// Browser check (0.1.42): the sign-in hardening.
// - Anmeldung → Microsoft Entra ID: "MFA-Nachweis" (a select opening as a popper below its field), "Authentifizierungs-
//   kontext verlangen" shows the context field, the warning hint stays while no context is entered, saving that mode
//   without a context is refused (the button off; the API answers 400 auth_context_missing). No real Entra.
// - "Zweiter Faktor für alle" (re-confirmation): a local reader without a second factor gets the set-up step at the
//   next sign-in – "Stattdessen einen Passkey einrichten" (CDP virtual authenticator) or TOTP; removing the TOTP is
//   refused while it is required and no passkey takes its place; switched off again a reader signs in without it.
// - API tokens: no "Nie" among the validities, at most 365 days (the API refuses 366); a token made with "never"
//   before migration 0023 shows "Ablauf ergänzt" (seeded before the migration – skipped with a note without one).
// - The password history: one of the last five passwords is refused with its rule.
// - A lock survives a restart of the backend (RESTART_CMD) and an admin's "Sperre aufheben" clears it.
// DE and EN (the flows), 1280 px and 375 px, light and dark (the pages): no page error, no console error, no horizontal
// scroll. Env: BASE_URL, CREDS (+ mfa1…mfa4, history, locked accounts), PLAYWRIGHT, SHOTS, RESTART_CMD (restarts the
// throwaway backend and returns when it answers again; without it the lock check is skipped with a note).
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import { execSync } from "node:child_process"
import {
  BASE,
  COMBOS,
  H,
  SHOTS,
  check,
  creds,
  dismissToasts,
  finish,
  freshCode,
  json,
  open,
  pw,
  reauthOnce,
  scrollCheck,
  settle,
  signIn,
  toastAfter,
  toastCount,
  totp,
} from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const RESTART_CMD = process.env.RESTART_CMD || ""
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
async function until(fn, ms = 8000, step = 250) {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn().catch(() => false)
    if (v || Date.now() > end) return v
    await sleep(step)
  }
}
const inApp = (page) =>
  page
    .locator('[data-sidebar="trigger"]')
    .count()
    .then((n) => n > 0)
const card = (page, title) => page.locator("main section").filter({ has: page.getByText(title, { exact: true }) })
const strong = () => `Pw-${crypto.randomBytes(9).toString("base64url")}-9aA!`

async function adminCtx(browser, combo) {
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.user, creds.password, true)
  r.reauth = async () => {
    const x = await r.ctx.request.post(`${BASE}/api/auth/reauth`, { data: { password: creds.password, code: await freshCode() }, headers: await H(r.ctx) })
    if (!x.ok()) throw new Error(`reauth ${x.status()}`)
  }
  return r
}

/** The sign-in form: name and password; returns "app", "enroll" or "error". */
async function uiLogin(page, t, user, password) {
  await page.goto(`${BASE}/`)
  await page.locator("#username").waitFor({ timeout: 10000 })
  // with Active Directory on, the form asks which account: these are local ones
  const local = page.getByRole("radio", { name: t("auth.local") })
  if (await local.count()) await local.click()
  await page.locator("#username").fill(user)
  await page.locator("#password").fill(password)
  await page.getByRole("button", { name: t("auth.continue") }).click()
  return until(async () => ((await inApp(page)) ? "app" : (await page.getByText(t("auth.enrollTitle")).count()) ? "enroll" : null), 12000)
}

async function entraFlow(a, combo, t) {
  const tag = `${combo.lang} Entra`
  const p = a.page
  await p.goto(`${BASE}/settings/auth`)
  await settle(p)
  const c = card(p, t("settings.entra.title"))
  const sw = c.locator("[role=switch]").first()
  if ((await sw.getAttribute("aria-checked")) !== "true") await sw.click()
  const trigger = c.getByRole("combobox").first()
  await trigger.scrollIntoViewIfNeeded()
  const shownMode = (await trigger.innerText()).trim()
  const tb = await trigger.boundingBox() // before it opens: the open select hides the rest of the page from the tree
  await trigger.click()
  const listbox = p.getByRole("listbox")
  await listbox.waitFor({ timeout: 5000 })
  const opts = (await listbox.getByRole("option").allInnerTexts()).map((x) => x.trim())
  const lb = await listbox.boundingBox()
  // a popper sits right at its field – below, or above when there is no room below (not over the field, as "item-aligned")
  const gap = tb && lb ? Math.min(Math.abs(lb.y - (tb.y + tb.height)), Math.abs(tb.y - (lb.y + lb.height))) : 99
  const popper = (await p.locator("[data-radix-popper-content-wrapper]").count()) >= 1 && gap < 16
  check(`${tag}: "${t("signin.entra.mfa")}" – three modes, opens as a popper right at its field`, opts.length === 3 && opts.includes(t("signin.entra.mfa.context")) && popper, {
    shownMode,
    opts,
    gap: Math.round(gap),
  })
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "Entra MFA select", SHOTS && `${combo.lang}-entra_mfa_select`)
  await listbox.getByRole("option", { name: t("signin.entra.mfa.context") }).click()
  const ctxField = c.getByPlaceholder("C1")
  const fieldThere = (await ctxField.count()) === 1
  const warn = c.getByText(t("signin.entra.noContext"))
  const warned = (await warn.count()) === 1
  const save = c.getByRole("button", { name: t("common.save"), exact: true })
  const off = await save.isDisabled()
  await ctxField.fill("C7")
  const warnGone = await until(async () => (await warn.count()) === 0, 3000)
  check(
    `${tag}: "${t("signin.entra.mfa.context")}" – the context field, the warning while it is empty, saving off; "C7" – the warning goes`,
    fieldThere && warned && off && warnGone,
    {
      fieldThere,
      warned,
      off,
      warnGone,
    },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "Entra context", SHOTS && `${combo.lang}-entra_context`)
  // the API refuses the mode without its context
  await a.reauth()
  const cur = await json(a.ctx, "/api/admin/auth/entra")
  const r = await a.ctx.request.put(`${BASE}/api/admin/auth/entra`, {
    data: { enabled: false, tenant_id: cur.tenant_id ?? "", client_id: cur.client_id ?? "", client_secret: "", mfa_mode: "context", auth_context: "", rev: cur.rev },
    headers: await H(a.ctx),
  })
  const body = await r.json().catch(() => ({}))
  check(`${tag}: saving "context" without a context – the API answers 400 auth_context_missing`, r.status() === 400 && JSON.stringify(body).includes("auth_context_missing"), {
    status: r.status(),
  })
  await p.reload()
  await settle(p)
}

/** "Zweiter Faktor für alle" switched in the UI (with the re-confirmation). */
async function secondFactor(a, t, on) {
  const p = a.page
  await p.goto(`${BASE}/settings/auth`)
  await settle(p)
  const c = card(p, t("settings.mfa.title"))
  await c.scrollIntoViewIfNeeded()
  const sw = c.getByRole("switch").first()
  if (((await sw.getAttribute("aria-checked")) === "true") !== on) await sw.click()
  const asked = await reauthOnce(p, "**/api/admin/auth/mfa", () => c.getByRole("button", { name: t("common.save"), exact: true }).click())
  const state = await until(async () => (await json(a.ctx, "/api/admin/auth/mfa")).required_all === on)
  return asked && state
}

async function factorFlow(browser, a, combo, t, [pkUser, totpUser]) {
  const tag = `${combo.lang} second factor`
  const on = await secondFactor(a, t, true)
  check(`${tag}: "${t("signin.mfa.requiredAll")}" switched on (with the re-confirmation)`, on)
  await scrollCheck(a.page, `${combo.lang} ${combo.width}px ${combo.theme}`, "second factor card", SHOTS && `${combo.lang}-second_factor_card`)
  // a passkey instead
  const r1 = await open(browser, combo)
  const cdp = await r1.page.context().newCDPSession(r1.page)
  await cdp.send("WebAuthn.enable")
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  })
  const s1 = await uiLogin(r1.page, t, creds[`${pkUser}_user`], creds[`${pkUser}_password`])
  const text = s1 === "enroll" ? await r1.page.locator("main, body").first().innerText() : ""
  const pkBtn = r1.page.getByRole("button", { name: t("auth.enrollPasskey") })
  const offered = (await pkBtn.count()) === 1
  await scrollCheck(r1.page, `${combo.lang} ${combo.width}px ${combo.theme}`, "enroll step", SHOTS && `${combo.lang}-enroll_step`)
  if (offered) await pkBtn.click()
  const in1 = await until(() => inApp(r1.page), 12000)
  const pks = in1 ? ((await json(r1.ctx, "/api/me/passkeys")).length ?? (await json(r1.ctx, "/api/me/passkeys")).items?.length) : 0
  check(
    `${tag}: a reader without a second factor gets the set-up step ("${t("auth.enrollTextAll").slice(0, 40)}…"); "${t("auth.enrollPasskey")}" – in, with a passkey`,
    s1 === "enroll" && text.includes(t("auth.enrollTextAll")) && offered && in1 && pks >= 1,
    {
      s1,
      offered,
      in1,
      pks,
    },
  )
  check(`${tag}: passkey path – no page or console errors`, r1.errors.length === 0, r1.errors.slice(0, 3))
  await r1.ctx.close()
  // TOTP
  const r2 = await open(browser, combo)
  const s2 = await uiLogin(r2.page, t, creds[`${totpUser}_user`], creds[`${totpUser}_password`])
  const key = r2.page.locator("span.font-mono.tracking-wider")
  await key.waitFor({ timeout: 8000 }).catch(() => undefined)
  const secret = ((await key.innerText().catch(() => "")) || "").replace(/\s+/g, "")
  if (secret) {
    await r2.page.locator("[data-input-otp]").first().click()
    await r2.page.keyboard.type(totp(secret))
  }
  const in2 = await until(() => inApp(r2.page), 12000)
  const me = in2 ? await json(r2.ctx, "/api/me") : {}
  check(`${tag}: … or TOTP – the code of the shown key, in with TOTP`, s2 === "enroll" && !!secret && in2 && !!me.totp, { s2, secret: !!secret, in2, totp: !!me.totp })
  // removing the TOTP: refused while it is required and no passkey takes its place
  await r2.page.goto(`${BASE}/settings/profile?tab=security`)
  await settle(r2.page)
  await r2.page
    .getByRole("button", { name: t("account.totpRemove") })
    .first()
    .click()
  const dlg = r2.page.getByRole("dialog").filter({ hasText: t("account.totpRemoveTitle") })
  await dlg.waitFor({ timeout: 5000 })
  // the dialog asks for the current code (TOTP set up) – it sends itself once six digits are in – or for the password
  const b = await toastCount(r2.page)
  const pwField = dlg.locator("input[type=password]")
  if (await pwField.count()) {
    await pwField.fill(creds[`${totpUser}_password`])
    await dlg.getByRole("button", { name: t("account.totpRemove") }).click()
  } else {
    await dlg.locator("[data-input-otp]").first().click()
    await r2.page.keyboard.type(totp(secret, Date.now() + 30000))
  }
  const said = await until(async () => {
    const all = (await r2.page.locator("[data-sonner-toast]").allInnerTexts()).join(" ") + (await dlg.innerText().catch(() => ""))
    return all.includes(t("errors.totp_required"))
  }, 6000)
  const still = !!(await json(r2.ctx, "/api/me")).totp
  check(`${tag}: removing the TOTP refused – "${t("errors.totp_required").slice(0, 50)}…"`, said && still, { said, still, toasts: (await toastCount(r2.page)) - b })
  await r2.page.keyboard.press("Escape")
  check(`${tag}: TOTP path – no page or console errors`, r2.errors.length === 0, r2.errors.slice(0, 3))
  await r2.ctx.close()
  // off again: a reader without a second factor signs in straight away
  const off = await secondFactor(a, t, false)
  const r3 = await open(browser, combo)
  const s3 = await uiLogin(r3.page, t, creds.history_user, creds.history_password)
  check(`${tag}: switched off again – a reader without a second factor signs in without the set-up step`, off && s3 === "app", { off, s3 })
  await r3.ctx.close()
}

async function tokensFlow(a, combo, t) {
  const tag = `${combo.lang} API tokens`
  const p = a.page
  await p.goto(`${BASE}/settings/api`)
  await settle(p)
  await p
    .getByRole("button", { name: t("apiTokens.create") })
    .first()
    .click()
  const sheetEl = p.locator("[data-slot=sheet-content]")
  await sheetEl.waitFor({ timeout: 5000 })
  const expiry = sheetEl.getByRole("combobox").last()
  const shown = (await expiry.innerText()).trim()
  await expiry.click()
  const opts = (await p.getByRole("listbox").getByRole("option").allInnerTexts()).map((x) => x.trim())
  const want = [30, 90, 180, 365].map((d) => t("apiTokens.expiry.days", { count: d }))
  check(`${tag}: the validities ${want.join(", ")} – no "never", "${want[3]}" chosen`, JSON.stringify(opts) === JSON.stringify(want) && shown === want[3], { opts, shown })
  await p.keyboard.press("Escape")
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "token sheet", SHOTS && `${combo.lang}-token_create`)
  await p.keyboard.press("Escape")
  const r366 = await a.ctx.request.post(`${BASE}/api/admin/api-tokens`, { data: { name: "e2e-366", scopes: ["read"], expires_days: 366 }, headers: await H(a.ctx) })
  check(`${tag}: the API refuses 366 days (422)`, r366.status() === 422, { status: r366.status() })
  const list = await json(a.ctx, "/api/admin/api-tokens")
  const old = (list.items ?? list).find((x) => x.name === "E2E alt ohne Ablauf")
  if (!old) {
    console.log("note: no token made with “never” before migration 0023 – the “Ablauf ergänzt” check is skipped")
    return
  }
  await p.goto(`${BASE}/settings/api`)
  await settle(p)
  const row = p.locator("main li, main tr").filter({ hasText: "E2E alt ohne Ablauf" }).first()
  const rowText = (await row.innerText().catch(() => "")).replace(/\s+/g, " ")
  const days = old.expires_at ? Math.round((Date.parse(old.expires_at) - Date.now()) / 86400000) : null
  check(
    `${tag}: the token made with "never" before 0023 – "${t("apiTokens.expiryAdded")}", now ~365 days`,
    old.expiry_added === true && rowText.includes(t("apiTokens.expiryAdded")) && days >= 360 && days <= 366,
    {
      flag: old.expiry_added,
      days,
      row: rowText.slice(0, 120),
    },
  )
}

async function historyFlow(browser, combo, t) {
  const tag = `${combo.lang} password history`
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.history_user, creds.history_password)
  const p = r.page
  const change = async (from, to) => {
    await p.goto(`${BASE}/settings/profile`)
    await settle(p)
    await p
      .getByRole("button", { name: t("account.pwChange") })
      .first()
      .click()
    await p.locator("#cur-pw").fill(from)
    await p.locator("#new-pw").fill(to)
    await p.locator("#new-pw2").fill(to)
    const b = await toastCount(p)
    await p
      .getByRole("dialog")
      .getByRole("button", { name: t("common.save"), exact: true })
      .click()
    const toast = await toastAfter(p, b)
    await dismissToasts(p)
    await p.keyboard.press("Escape")
    return toast
  }
  const first = creds.history_password
  const next = strong()
  const ok = await change(first, next)
  const okDone = ok?.type === "success"
  if (okDone) creds.history_password = next
  const back = await change(okDone ? next : first, first)
  const refused = back?.type === "error" && back.text.includes(t("policy.reused"))
  // still the new one
  const login = await r.ctx.request.post(`${BASE}/api/auth/login`, { data: { username: creds.history_user, password: first }, headers: await H(r.ctx) })
  check(`${tag}: changed once, then the previous password refused – "${t("policy.reused")}"`, okDone && refused && login.status() >= 400, {
    okDone,
    back: back?.text,
    oldLogin: login.status(),
  })
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

async function lockFlow(browser, combo, t) {
  const tag = "lock"
  if (!RESTART_CMD) {
    console.log("note: RESTART_CMD not set – the lock over a restart is skipped")
    return
  }
  const r = await open(browser, combo)
  await r.ctx.request.get(`${BASE}/api/auth/config`)
  const h = await H(r.ctx)
  const tryLogin = (password) => r.ctx.request.post(`${BASE}/api/auth/login`, { data: { username: creds.locked_user, password }, headers: h })
  for (let i = 0; i < 5; i++) await tryLogin(`wrong-${i}-${crypto.randomBytes(3).toString("hex")}`)
  const locked0 = (await tryLogin(creds.locked_password)).status()
  execSync(RESTART_CMD, { stdio: "inherit", shell: "/bin/sh" })
  const locked1 = (await tryLogin(creds.locked_password)).status()
  check(`${tag}: five wrong passwords lock the account (${locked0}) – still locked after a restart of the backend (${locked1})`, locked0 === 423 && locked1 === 423, {
    locked0,
    locked1,
  })
  await r.ctx.close()
  // the admin's "Sperre aufheben"
  const a = await adminCtx(browser, combo)
  await a.page.goto(`${BASE}/settings/users`)
  await settle(a.page)
  const row = a.page.locator("main li, main tr").filter({ hasText: creds.locked_user }).first()
  const lockedShown = (await row.innerText()).includes(t("users.locked", { minutes: "§" }).split("§")[0].trim())
  const unlock = row.getByRole("button", { name: t("users.unlock") })
  let clicked = false
  if (await unlock.count()) {
    clicked = await reauthOnce(a.page, "**/api/admin/users/**", () => unlock.click()).then(() => true)
  } else {
    // in the account's menu
    await row.getByRole("button").last().click()
    const item = a.page.getByRole("menuitem", { name: t("users.unlock") })
    if (await item.count()) clicked = await reauthOnce(a.page, "**/api/admin/users/**", () => item.click()).then(() => true)
  }
  await sleep(800)
  const r2 = await open(browser, combo)
  await r2.ctx.request.get(`${BASE}/api/auth/config`)
  const after = (await r2.ctx.request.post(`${BASE}/api/auth/login`, { data: { username: creds.locked_user, password: creds.locked_password }, headers: await H(r2.ctx) })).status()
  check(`${tag}: the users list says locked; "${t("users.unlock")}" clears it – the right password works again`, lockedShown && clicked && after === 200, {
    lockedShown,
    clicked,
    after,
  })
  await scrollCheck(a.page, `${combo.lang} ${combo.width}px ${combo.theme}`, "users", SHOTS && `${combo.lang}-users_unlocked`)
  check(`${tag}: no page or console errors`, a.errors.length === 0 && r2.errors.length === 0, [...a.errors, ...r2.errors].slice(0, 3))
  await r2.ctx.close()
  await a.ctx.close()
}

async function pages(browser, combo) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme}`
  const a = await adminCtx(browser, combo)
  for (const [name, path] of [
    ["sign-in settings", "/settings/auth"],
    ["api tokens", "/settings/api"],
    ["profile", "/settings/profile"],
  ]) {
    await a.page.goto(`${BASE}${path}`)
    await settle(a.page)
    await scrollCheck(a.page, tag, name, SHOTS && `${lang}-${width}-${theme}-${name.replace(/ /g, "_")}`)
  }
  check(`${tag} pages: no page or console errors`, a.errors.length === 0, a.errors.slice(0, 3))
  await a.ctx.close()
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) {
    const t = texts(combo.lang)
    if (combo.wide) {
      const a = await adminCtx(browser, combo)
      await entraFlow(a, combo, t)
      await factorFlow(browser, a, combo, t, combo.lang === "de" ? ["mfa1", "mfa2"] : ["mfa3", "mfa4"])
      await tokensFlow(a, combo, t)
      check(`${combo.lang} admin: no page or console errors`, a.errors.length === 0, a.errors.slice(0, 3))
      await a.ctx.close()
      await historyFlow(browser, combo, t)
      if (combo.lang === "de") await lockFlow(browser, combo, t)
    } else await pages(browser, combo)
  }
} finally {
  await browser.close()
}
finish()
