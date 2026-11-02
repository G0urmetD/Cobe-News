// Browser check (0.1.42): the open tabs of one browser sign out together, and polls do not keep a session alive.
// One browser context, two tabs (A and B):
// - Sign-out in A → B on the sign-in at once with "Abgemeldet – in einem anderen Tab.", no story list left in the page,
//   an open drawer, "really?" question or re-confirmation gone; signed in again in A → B is in again by itself.
// - The idle timeout (set to its minimum, 5 minutes, for this run): the warning in both tabs, "Angemeldet bleiben" in A
//   extends it for both, closing the next warning in A closes it in B; left alone both tabs reach the sign-in within a
//   few seconds of each other – a visible idle tab is not kept alive: the polls carry X-Cobe-Background: 1 and leave
//   "zuletzt aktiv" (Meine Sitzungen) where it was; at the end one or two looks (GET /api/auth/session), not one per tab
//   and second.
// - An admin ends the account's sessions from another browser → the tab that is switched to signs out at once
//   (headless Chrome keeps every tab visible: the switch is a visibilitychange event).
// DE and EN, 1280 px and 375 px, light and dark for the sign-out round (no page error, no console error, no horizontal
// scroll on the sign-in page). The idle round and the revocation run once (DE, wide). About 12 minutes.
// Env: BASE_URL, CREDS ({user, password, totp, tabs_user, tabs_password, story142}), PLAYWRIGHT, SHOTS.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { BASE, COMBOS, H, SHOTS, check, creds, finish, freshCode, json, open, pw, scrollCheck, settle, signIn } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const USER = creds.tabs_user
const PASSWORD = creds.tabs_password
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
async function until(fn, ms = 8000, step = 250) {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn().catch(() => false)
    if (v || Date.now() > end) return v
    await sleep(step)
  }
}
const onSignIn = (page) => page.locator("#username").isVisible()
const inApp = (page) =>
  page
    .locator('[data-sidebar="trigger"]')
    .count()
    .then((n) => n > 0)
const toastText = (page) =>
  page
    .locator("[data-sonner-toast]")
    .allInnerTexts()
    .then((x) => x.join(" | "))

/** The page's errors – both tabs of a context. */
function watchErrors(page, errors, name) {
  page.on("pageerror", (e) => errors.push(`${name} pageerror: ${e.message}`))
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(`${name} console: ${m.text()}`)
  })
}

async function uiSignIn(page, t, user = USER, password = PASSWORD, code = false) {
  if (!(await onSignIn(page))) {
    await page.goto(`${BASE}/`)
    await page.locator("#username").waitFor({ timeout: 10000 })
  }
  // with Active Directory on, the form asks which account: these are local ones
  const local = page.getByRole("radio", { name: t("auth.local") })
  if (await local.count()) await local.click()
  await page.locator("#username").fill(user)
  await page.locator("#password").fill(password)
  await page.getByRole("button", { name: t("auth.continue") }).click()
  if (code) {
    await page.getByText(t("auth.mfaTitle")).waitFor({ timeout: 10000 })
    await page.keyboard.type(await freshCode())
  }
  await until(() => inApp(page), 15000)
}

async function uiSignOut(page, t, narrow) {
  if (narrow) await page.locator('[data-sidebar="trigger"]').first().click()
  await page.locator('[data-sidebar="footer"] button').first().click()
  await page.getByRole("menuitem", { name: t("shell.logout") }).click()
}

async function twoTabs(browser, combo) {
  const errors = []
  const r = await open(browser, combo)
  const A = r.page
  watchErrors(A, errors, "A") // open() collects for A too – these are the ones of both, named
  const B = await r.ctx.newPage()
  watchErrors(B, errors, "B")
  return { ctx: r.ctx, A, B, errors }
}

/** The admin's context, re-confirmed (sensitive settings and ending another account's sessions). */
async function admin(browser) {
  const a = await open(browser, COMBOS[0])
  await signIn(a.ctx, creds.user, creds.password, true)
  // the idle timeout of this run (5 minutes) ends the admin's session too while the tabs wait – signed in again then
  const alive = async () => {
    if ((await a.ctx.request.get(`${BASE}/api/me`)).status() === 401) await signIn(a.ctx, creds.user, creds.password, true)
  }
  const reauth = async () => {
    await alive()
    const r = await a.ctx.request.post(`${BASE}/api/auth/reauth`, { data: { password: creds.password, code: await freshCode() }, headers: await H(a.ctx) })
    if (!r.ok()) throw new Error(`reauth: ${r.status()}`)
  }
  const idle = async (min) => {
    await reauth()
    const cur = await json(a.ctx, "/api/admin/auth/sessions")
    const r = await a.ctx.request.put(`${BASE}/api/admin/auth/sessions`, { data: { idle_min: min, absolute_h: cur.absolute_h, rev: cur.rev }, headers: await H(a.ctx) })
    return r.ok()
  }
  return { ...a, alive, reauth, idle }
}

async function signOutRound(browser, combo, t, story) {
  const tag = `${combo.lang} ${combo.width}px ${combo.theme}`
  const narrow = combo.width < 768
  const { ctx, A, B, errors } = await twoTabs(browser, combo)
  await uiSignIn(A, t)
  await B.goto(`${BASE}/?story=${story}`)
  await settle(B)
  const drawer = (await B.locator("[data-slot=sheet-content]").count()) === 1 && (await B.locator("main article").count()) > 0
  await uiSignOut(A, t, narrow)
  const out = await until(() => onSignIn(B), 6000, 100)
  const msg = await until(async () => (await toastText(B)).includes(t("auth.signedOutElsewhere")), 4000)
  const left = { articles: await B.locator("main article").count(), sheet: await B.locator("[data-slot=sheet-content]").count(), story: new URL(B.url()).searchParams.has("story") }
  check(
    `${tag}: sign-out in tab A – tab B on the sign-in with "${t("auth.signedOutElsewhere")}", the drawer and the story list gone`,
    drawer && out && msg && left.articles === 0 && left.sheet === 0 && !left.story,
    { drawer, out, msg, ...left },
  )
  await scrollCheck(B, tag, "tab B signed out", SHOTS && `${combo.lang}-${combo.width}-${combo.theme}-signed_out_elsewhere`)
  // signed in again in A → B is in again by itself
  await uiSignIn(A, t)
  const back = await until(() => inApp(B), 8000, 100)
  check(`${tag}: signed in again in A – B is in again by itself`, back)
  check(`${tag}: no page or console errors (both tabs)`, errors.length === 0, errors.slice(0, 3))
  return { ctx, A, B, errors }
}

async function questionRounds(browser, combo, t) {
  const tag = `${combo.lang} questions`
  const { ctx, A, B, errors } = await twoTabs(browser, combo)
  await uiSignIn(A, t)
  // a "really?" question open in B (deleting a saved view)
  const h = await H(ctx)
  for (const v of (await json(ctx, "/api/me/views?page=news")).items) await ctx.request.delete(`${BASE}/api/me/views/${v.id}`, { headers: h })
  await ctx.request.post(`${BASE}/api/me/views`, { data: { page: "news", name: "E2E Tabs", query: "severity=critical" }, headers: h })
  await B.goto(`${BASE}/`)
  await settle(B)
  await B.getByRole("button", { name: t("reader.views.title") })
    .first()
    .click()
  await B.locator("[data-slot=popover-content]")
    .getByRole("button", { name: t("common.remove"), exact: true })
    .first()
    .click()
  const asked = await until(
    async () =>
      (await B.getByRole("dialog")
        .filter({ hasText: t("reader.views.deleteTitle") })
        .count()) === 1,
  )
  await uiSignOut(A, t, false)
  const out = await until(() => onSignIn(B), 6000, 100)
  const gone = (await B.getByRole("dialog").count()) === 0 && (await B.locator("[data-slot=popover-content]").count()) === 0
  check(`${tag}: an open "really?" question in B goes with the sign-out in A`, asked && out && gone, { asked, out, gone })
  await ctx.close()
  check(`${tag}: no page or console errors (both tabs)`, errors.length === 0, errors.slice(0, 3))
}

async function reauthRound(browser, combo, t) {
  const tag = `${combo.lang} re-confirmation`
  const { ctx, A, B, errors } = await twoTabs(browser, combo)
  await uiSignIn(A, t, creds.user, creds.password, true)
  await B.goto(`${BASE}/settings/auth`)
  await settle(B)
  // the server asks for the re-confirmation (as after its window) – the prompt stays open in B
  await B.route("**/api/admin/auth/mfa", (route) =>
    route.request().method() === "PUT" ? route.fulfill({ status: 403, json: { detail: { code: "reauth_required", via: "password", totp: true } } }) : route.fallback(),
  )
  const card = B.locator("main section").filter({ has: B.getByText(t("settings.mfa.title"), { exact: true }) })
  await card.scrollIntoViewIfNeeded()
  await card.getByRole("switch").first().click()
  await card.getByRole("button", { name: t("common.save"), exact: true }).click()
  const asked = await until(async () => (await B.locator("#reauth-pw").count()) === 1)
  await uiSignOut(A, t, false)
  const out = await until(() => onSignIn(B), 6000, 100)
  const gone = (await B.locator("#reauth-pw").count()) === 0 && (await B.getByRole("dialog").count()) === 0
  check(`${tag}: an open re-confirmation in B goes with the sign-out in A`, asked && out && gone, { asked, out, gone })
  await ctx.close()
  check(`${tag}: no page or console errors (both tabs)`, errors.length === 0, errors.slice(0, 3))
}

async function idleRound(browser, combo, t, adm) {
  const tag = `${combo.lang} idle`
  const { ctx, A, B, errors } = await twoTabs(browser, combo)
  const reqs = []
  for (const [name, p] of [
    ["A", A],
    ["B", B],
  ])
    p.on("request", (r) => {
      const u = new URL(r.url())
      if (u.pathname.startsWith("/api/")) reqs.push({ tab: name, at: Date.now(), method: r.method(), path: u.pathname, bg: r.headers()["x-cobe-background"] ?? null })
    })
  await uiSignIn(A, t)
  await B.goto(`${BASE}/`)
  await settle(B)
  await A.goto(`${BASE}/vendor`)
  await settle(A)
  // "zuletzt aktiv" as the sessions list says – asked as a background request itself (it must not move it either)
  const lastSeen = async () => {
    const r = await ctx.request.get(`${BASE}/api/me/sessions`, { headers: { "X-Cobe-Background": "1" } })
    return (await r.json()).find((s) => s.current)?.last_seen_at
  }
  const seen0 = await lastSeen()
  const t0 = Date.now()
  const warn = t("auth.sessionEnding")
  const warned = (p) => toastText(p).then((x) => x.includes(warn))
  // the warning two minutes before the end – in both tabs
  const w1 = await until(async () => (await warned(A)) && (await warned(B)), 4.5 * 60_000, 2000)
  const after = Math.round((Date.now() - t0) / 1000)
  const polls = reqs.filter((r) => r.at > t0 && r.method === "GET" && r.path !== "/api/auth/session")
  const seen1 = await lastSeen()
  check(`${tag}: the warning "${warn}" in both tabs (~3 min after the last activity)`, w1, { after })
  check(`${tag}: meanwhile only background requests (X-Cobe-Background: 1) – "zuletzt aktiv" unchanged`, polls.length > 0 && polls.every((r) => r.bg === "1") && seen1 === seen0, {
    polls: polls.length,
    paths: [...new Set(polls.map((r) => r.path))].slice(0, 6),
    notBg: polls
      .filter((r) => r.bg !== "1")
      .map((r) => r.path)
      .slice(0, 4),
    seen0,
    seen1,
  })
  await scrollCheck(B, `${combo.lang} ${combo.width}px ${combo.theme}`, "idle warning", SHOTS && `${combo.lang}-idle_warning`)
  // "Angemeldet bleiben" in A: the session goes on, the warning goes in both
  await A.locator("[data-sonner-toast]")
    .filter({ hasText: warn })
    .getByRole("button", { name: t("auth.staySignedIn") })
    .click()
  const goneBoth = await until(async () => !(await warned(A)) && !(await warned(B)), 8000)
  const left = (await (await ctx.request.get(`${BASE}/api/auth/session`)).json()).idle_left_s
  check(`${tag}: "${t("auth.staySignedIn")}" in A – the warning gone in both, the session extended`, goneBoth && left > 240, { goneBoth, left })
  // the next warning: closed in A, closed in B
  const t1 = Date.now()
  const w2 = await until(async () => (await warned(A)) && (await warned(B)), 4.5 * 60_000, 2000)
  await A.locator("[data-sonner-toast]").filter({ hasText: warn }).locator("[data-close-button]").click()
  const closedB = await until(async () => !(await warned(B)), 6000)
  check(`${tag}: the next warning closed in A – closed in B too`, w2 && closedB, { w2, closedB, after: Math.round((Date.now() - t1) / 1000) })
  // left alone: both tabs on the sign-in within a few seconds of each other; one or two looks
  const tEnd = Date.now()
  const at = {}
  await until(
    async () => {
      for (const [n, p] of [
        ["A", A],
        ["B", B],
      ])
        if (!at[n] && (await onSignIn(p))) at[n] = Date.now()
      return at.A && at.B
    },
    3 * 60_000,
    250,
  )
  const looks = reqs.filter((r) => r.at > tEnd && r.path === "/api/auth/session")
  const apart = at.A && at.B ? Math.abs(at.A - at.B) : null
  const expiredMsg = (await toastText(A)).includes(t("auth.sessionExpired")) || (await toastText(B)).includes(t("auth.sessionExpired"))
  check(`${tag}: left alone both tabs reach the sign-in (the idle timeout) within a few seconds of each other`, !!at.A && !!at.B && apart < 5000 && expiredMsg, {
    afterWarn: at.A ? Math.round((at.A - tEnd) / 1000) : null,
    apart,
    expiredMsg,
  })
  check(`${tag}: at the end at most two looks (GET /api/auth/session – none when a poll's 401 came first), not one per tab and second`, looks.length <= 2, {
    looks: looks.length,
    tabs: looks.map((l) => l.tab),
  })
  check(`${tag}: no page or console errors (both tabs)`, errors.length === 0, errors.slice(0, 3))
  // an admin ends the account's sessions – switching to a tab signs out at once
  await uiSignIn(A, t)
  await until(() => inApp(B), 8000)
  await sleep(31_000) // a tab shown again looks at most every 30 s (session-sync VISIBLE_MIN_MS)
  await adm.alive()
  const users = await json(adm.ctx, "/api/admin/users")
  const uid = users.find((u) => u.username === USER)?.id
  await adm.reauth()
  const ended = await adm.ctx.request.post(`${BASE}/api/admin/users/${uid}/sessions/end-all`, { headers: await H(adm.ctx) })
  const t2 = Date.now()
  await B.bringToFront()
  await B.evaluate(() => document.dispatchEvent(new Event("visibilitychange")))
  const outB = await until(() => onSignIn(B), 5000, 100)
  const secs = (Date.now() - t2) / 1000
  const outA = await until(() => onSignIn(A), 5000, 100)
  check(`${tag}: the admin ends the sessions – switching to tab B signs out at once (${secs.toFixed(1)} s), A follows`, ended.ok() && outB && secs < 4 && outA, {
    status: ended.status(),
    outB,
    outA,
  })
  await ctx.close()
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
let adm = null
try {
  adm = await admin(browser)
  check("the idle timeout set to its minimum (5 minutes) for this run", await adm.idle(5))
  const story = creds.story142 || (await json(adm.ctx, "/api/news?state=all&limit=1")).items[0]?.id
  for (const combo of COMBOS) {
    const t = texts(combo.lang)
    const r = await signOutRound(browser, combo, t, story)
    await r.ctx.close()
    if (combo.wide) await questionRounds(browser, combo, t)
    if (combo.wide && combo.lang === "de") await reauthRound(browser, combo, t)
  }
  await idleRound(browser, COMBOS[0], texts("de"), adm)
} finally {
  if (adm) check("the idle timeout back to 60 minutes", await adm.idle(60).catch(() => false))
  await browser.close()
}
finish()
