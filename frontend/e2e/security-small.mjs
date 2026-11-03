// Browser check (0.1.47): the small security items – nothing fetched (seed147: tara.temp with a temporary password of
// yesterday, toni.temp with one of ten days ago, the audit entry of the emergency admin's exceeded failure budget).
// - Einstellungen → Anmeldung → Sitzungen: "Startpasswort gültig für" (1–30 days; 0 and 31 refused, 14 saved behind the
//   re-confirmation); the user list: "Startpasswort läuft ab am …" / "Startpasswort abgelaufen" (with its hint), as the
//   validity says; signing in with the expired one is refused with its message (the valid one goes on to the new
//   password).
// - Einstellungen → HTTPS: the emergency admin's "slowed" warning (21 failures), no short-key warning (the key file);
//   a second backend with a short SECRET_KEY (SHORT_BASE, SHORT_CREDS) shows that warning.
// - A request over 1 MiB: 413 body_too_large (API and the browser's own fetch); one below the limit is not.
// - The sign-in page: /?login_error=<code> shows the alert with the first paint of the form, and the parameter is gone
//   from the address; something not shaped like a code is no alert, an unknown code the generic text.
// - Benutzer → Rollen-Zuordnung: the group search keeps no stale answer when the directory is switched (the directory
//   answers stubbed in the page: AD slow, Entra quick – nothing is asked of a real directory).
// - 375 px: the sidebar is the mobile one from the first paint (the desktop one is never rendered).
// - Optional (NGINX_HTTPS_PORT, NGINX_HTTP_PORT, NGINX_CONTAINER, NGINX_WARN_CONTAINER): the bundled nginx template in
//   the pinned image – unknown Host: 421 plain text on https, nothing (444) on port 80 and for plain http on the https
//   port; known names (localhost, 127.0.0.1, BASE_URL's host, a TLS_NAMES entry) reach the app; plain http on the
//   https port is redirected; the start log warns about BIND=0.0.0.0 with BASE_URL on localhost (and only then).
// DE and EN (the flows, 1280 px light), 1280 px and 375 px, light and dark (the pages): no page error, no console error,
// no horizontal scroll. Env: BASE_URL, CREDS, PLAYWRIGHT, SHOTS, SHORT_BASE, SHORT_CREDS, NGINX_*.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { execSync } from "node:child_process"
import fs from "node:fs"
import http from "node:http"
import https from "node:https"
import { BASE, COMBOS, H, SHOTS, check, creds, finish, freshCode, json, open, pw, reauthOnce, scrollCheck, settle, signIn, totp } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const SHORT_BASE = (process.env.SHORT_BASE || "").replace(/\/$/, "")
const SHORT = process.env.SHORT_CREDS ? JSON.parse(fs.readFileSync(process.env.SHORT_CREDS, "utf8")) : null
const card = (page, title) => page.locator("main section").filter({ has: page.getByText(title, { exact: true }) })
const prefix = (s) => s.split("{{")[0].trim()
const until = async (fn, ms = 8000) => {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn()
    if (v || Date.now() > end) return v
    await new Promise((ok) => setTimeout(ok, 200))
  }
}
const reauth = async (ctx) => {
  const x = await ctx.request.post(`${BASE}/api/auth/reauth`, { data: { password: creds.password, code: await freshCode() }, headers: await H(ctx) })
  if (!x.ok()) throw new Error(`reauth ${x.status()}`)
}
const setTempDays = async (ctx, days) => {
  const cur = await json(ctx, "/api/admin/auth/sessions")
  if (cur.temp_password_days === days) return
  await reauth(ctx)
  const r = await ctx.request.put(`${BASE}/api/admin/auth/sessions`, {
    data: { idle_min: cur.idle_min, absolute_h: cur.absolute_h, temp_password_days: days, rev: cur.rev },
    headers: await H(ctx),
  })
  if (!r.ok()) throw new Error(`sessions ${r.status()}`)
}
const userRow = (page, username) => page.locator("li, tr").filter({ hasText: username }).last()

async function settingsFlow(browser, combo, t) {
  const tag = `${combo.lang} settings`
  const a = await open(browser, combo)
  await signIn(a.ctx, creds.user, creds.password, true)
  const p = a.page
  await setTempDays(a.ctx, 7)
  // the validity: 1–30 days
  await p.goto(`${BASE}/settings/auth`)
  await settle(p)
  const sessions = card(p, t("settings.tab.sessions"))
  const field = sessions.getByLabel(t("signin.sessions.tempDays"))
  const save = sessions.getByRole("button", { name: t("common.save") })
  const shown = await field.inputValue()
  const hint = (await sessions.innerText()).includes(t("signin.sessions.tempDaysHint"))
  const limits = {}
  for (const v of ["0", "31", ""]) {
    await field.fill(v)
    limits[v || "empty"] = { invalid: (await field.getAttribute("aria-invalid")) === "true", saveOff: await save.isDisabled() }
  }
  check(
    `${tag}: "${t("signin.sessions.tempDays")}" shows 7 days with its hint; 0, 31 and an empty field are marked and cannot be saved`,
    shown === "7" && hint && Object.values(limits).every((x) => x.invalid && x.saveOff),
    { shown, hint, limits },
  )
  await field.fill("14")
  const asked = await reauthOnce(p, "**/api/admin/auth/sessions", () => save.click())
  await settle(p)
  const stored = (await json(a.ctx, "/api/admin/auth/sessions")).temp_password_days
  check(`${tag}: 14 days saved behind the re-confirmation`, asked && stored === 14, { asked, stored })
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "sessions card", SHOTS && `${combo.lang}-temp_days`)
  // the user list follows the validity: at 14 days both are valid, at 7 days ten days ago is expired
  await p.goto(`${BASE}/settings/users`)
  await settle(p)
  const until14 = { tara: await userRow(p, creds.temp_ok_user).innerText(), toni: await userRow(p, creds.temp_old_user).innerText() }
  check(
    `${tag}: users at 14 days – both "${prefix(t("users.tempUntil"))} …"`,
    until14.tara.includes(prefix(t("users.tempUntil"))) && until14.toni.includes(prefix(t("users.tempUntil"))) && !until14.toni.includes(t("users.tempExpired")),
    until14,
  )
  await setTempDays(a.ctx, 7)
  await p.reload()
  await settle(p)
  const toni = userRow(p, creds.temp_old_user)
  const toniText = await toni.innerText()
  const taraText = await userRow(p, creds.temp_ok_user).innerText()
  const pillHint = await toni
    .getByText(t("users.tempExpired"), { exact: true })
    .getAttribute("title")
    .catch(() => null)
  check(
    `${tag}: users at 7 days – "${t("users.tempExpired")}" (hint: re-issue) for ten days ago, "${prefix(t("users.tempUntil"))} …" for yesterday`,
    toniText.includes(t("users.tempExpired")) && pillHint === t("users.tempExpiredHint") && taraText.includes(prefix(t("users.tempUntil"))),
    { toniText: toniText.replace(/\s+/g, " ").slice(0, 160), pillHint },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "user list", SHOTS && `${combo.lang}-users_temp`)
  // Einstellungen → HTTPS: the emergency admin's warning, no short-key warning (this instance has the 44-character file)
  await p.goto(`${BASE}/settings/https`)
  await settle(p)
  const main = (await p.locator("main").innerText()).replace(/\s+/g, " ")
  check(
    `${tag}: HTTPS – "${t("system.warning.emergencyFailures", { count: 21 }).slice(0, 50)}…" with its time, no short-key warning`,
    main.includes(t("system.warning.emergencyFailures", { count: 21 })) &&
      !main.includes(prefix(t("system.warning.secretKeyShort.file"))) &&
      !main.includes(prefix(t("system.warning.secretKeyShort.env"))),
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "https warnings", SHOTS && `${combo.lang}-https_emergency`)
  await mappingFlow(p, combo, t)
  // the body limit: 413 body_too_large – the API and the browser's own fetch, and one below the limit passes it
  const big = "x".repeat(1024 * 1024 + 2048)
  const r1 = await a.ctx.request.post(`${BASE}/api/auth/login`, { data: { username: "nobody", password: big }, headers: await H(a.ctx) })
  const b1 = await r1.json().catch(() => ({}))
  const r2 = await p.evaluate(
    async (body) => {
      const csrf =
        document.cookie
          .split("; ")
          .find((c) => c.includes("cobe_news_csrf="))
          ?.split("=")[1] ?? ""
      const r = await fetch("/api/me/desktop", { method: "PUT", body, headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf } })
      return { status: r.status, body: await r.json().catch(() => null) }
    },
    JSON.stringify({ enabled: false, pad: big }),
  )
  // (below the limit on an endpoint that counts no failed sign-in: the address must not be slowed down)
  const r3 = await a.ctx.request.put(`${BASE}/api/me/desktop`, { data: { enabled: false, pad: "x".repeat(900 * 1024) }, headers: await H(a.ctx) })
  check(
    `${tag}: over 1 MiB – 413 body_too_large (API and the page's fetch), 900 KiB is not stopped by the limit`,
    r1.status() === 413 && b1.detail?.code === "body_too_large" && r2.status === 413 && r2.body?.detail?.code === "body_too_large" && r3.status() !== 413,
    { api: r1.status(), fetch: r2.status, below: r3.status() },
  )
  check(`${tag}: no page or console errors`, a.errors.length === 0, a.errors.slice(0, 3))
  await a.ctx.close()
}

/** The group search: AD answers after 2.5 s, Entra at once (both stubbed) – a switch never shows the other's answer. */
async function mappingFlow(p, combo, t) {
  const tag = `${combo.lang} mappings`
  const usable = async (route) => {
    const r = await route.fetch()
    route.fulfill({ response: r, json: { ...(await r.json()), enabled: true, usable: true } })
  }
  const asked = []
  await p.route("**/api/admin/auth/ldap", usable)
  await p.route("**/api/admin/auth/entra", usable)
  await p.route("**/api/admin/auth/ldap/groups**", async (route) => {
    asked.push(`ldap ${new URL(route.request().url()).searchParams.get("q")}`)
    await new Promise((ok) => setTimeout(ok, 2500))
    await route.fulfill({ json: [{ id: "CN=Alt-LDAP,OU=Groups,DC=corp,DC=example", name: "Alt-LDAP-Gruppe", path: "corp.example/Groups" }] }).catch(() => {})
  })
  await p.route("**/api/admin/auth/entra/groups**", async (route) => {
    asked.push(`entra ${new URL(route.request().url()).searchParams.get("q")}`)
    await route.fulfill({ json: [{ id: "00000000-0000-0000-0000-0000000000e2", name: "Entra-Gruppe-E2E", description: "Entra" }] })
  })
  await p.goto(`${BASE}/settings/users?tab=mapping`)
  await settle(p)
  const list = p.getByRole("listbox", { name: t("signin.map.results") })
  const names = async () => ((await list.count()) ? (await list.getByRole("option").allInnerTexts()).join(" | ") : "")
  await until(async () => (await names()).includes("Alt-LDAP-Gruppe"), 6000)
  const search = p.getByPlaceholder(t("signin.map.searchPlaceholder"))
  // AD → Entra while AD is still searching: Entra's answer only, AD's late one never shows
  await search.fill("News")
  await p.waitForTimeout(700)
  const source = p.getByRole("combobox").filter({ hasText: "Active Directory" }).first()
  await source.click()
  await p.getByRole("option", { name: "Entra ID", exact: true }).click()
  const seen1 = new Set()
  for (let i = 0; i < 18; i++) {
    seen1.add(await names())
    await p.waitForTimeout(200)
  }
  const after1 = await names()
  check(
    `${tag}: AD → Entra while AD still searched – Entra's groups only, AD's late answer never shows`,
    after1.includes("Entra-Gruppe-E2E") && ![...seen1].some((s) => s.includes("Alt-LDAP")) && asked.includes("ldap News") && asked.includes("entra News"),
    { after1, asked },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "group search", SHOTS && `${combo.lang}-mapping_search`)
  // Entra → AD: until AD answers, nothing of Entra's list is left
  await p.getByRole("combobox").filter({ hasText: "Entra ID" }).first().click()
  await p.getByRole("option", { name: "Active Directory", exact: true }).click()
  const seen2 = new Set()
  for (let i = 0; i < 18; i++) {
    seen2.add(await names())
    await p.waitForTimeout(200)
  }
  const after2 = await names()
  check(
    `${tag}: Entra → AD – Entra's list gone at once, AD's answer when it comes`,
    after2.includes("Alt-LDAP-Gruppe") && ![...seen2].some((s) => s.includes("Entra-Gruppe-E2E")),
    { after2 },
  )
  await p.unrouteAll({ behavior: "ignoreErrors" })
}

async function loginFlow(browser, combo, t) {
  const tag = `${combo.lang} sign-in`
  // the alert with the first paint of the form: an observer from the document's start notes what is there when the
  // name field first appears
  const r = await open(browser, combo)
  await r.ctx.addInitScript(() => {
    const seen = { form: false, alertWithForm: null }
    window.__first = seen
    new MutationObserver(() => {
      if (seen.form || !document.getElementById("username")) return
      seen.form = true
      seen.alertWithForm = !!document.querySelector("[role=alert]")
    }).observe(document, { childList: true, subtree: true })
  })
  const p = r.page
  await p.goto(`${BASE}/?login_error=temp_password_expired`)
  await p.locator("#username").waitFor({ timeout: 10000 })
  await settle(p)
  const first = await p.evaluate(() => window.__first)
  const alert = (
    (await p
      .getByRole("alert")
      .first()
      .innerText()
      .catch(() => "")) || ""
  ).replace(/\s+/g, " ")
  check(
    `${tag}: /?login_error=temp_password_expired – the alert is there with the form's first paint, its text, the parameter gone`,
    first.alertWithForm === true && alert.includes(t("errors.temp_password_expired")) && !p.url().includes("login_error"),
    { first, alert, url: p.url() },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "login error", SHOTS && `${combo.lang}-login_error`)
  await p.goto(`${BASE}/?login_error=%3Cb%3Ex%3C%2Fb%3E`)
  await p.locator("#username").waitFor({ timeout: 10000 })
  await settle(p)
  const odd = await p.getByRole("alert").count()
  await p.goto(`${BASE}/?login_error=zzz_unknown`)
  await p.locator("#username").waitFor({ timeout: 10000 })
  await settle(p)
  const unknown = (
    (await p
      .getByRole("alert")
      .first()
      .innerText()
      .catch(() => "")) || ""
  ).replace(/\s+/g, " ")
  check(`${tag}: a parameter not shaped like a code – no alert; an unknown code – "${t("errors.generic")}"`, odd === 0 && unknown.includes(t("errors.generic")), { odd, unknown })
  // the expired temporary password: refused with its message (UI), the valid one goes on (API)
  await p.goto(`${BASE}/`)
  await p.locator("#username").waitFor({ timeout: 10000 })
  const local = p.getByRole("radio", { name: t("auth.local") })
  if (await local.count()) await local.click()
  await p.locator("#username").fill(creds.temp_old_user)
  await p.locator("#password").fill(creds.temp_old_password)
  await p.getByRole("button", { name: t("auth.continue") }).click()
  const refused = await until(async () =>
    (
      (await p
        .getByRole("alert")
        .first()
        .innerText()
        .catch(() => "")) || ""
    ).includes(t("errors.temp_password_expired")),
  )
  check(`${tag}: the expired temporary password – refused with "${t("errors.temp_password_expired")}"`, refused && (await p.locator("#username").count()) === 1)
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "temp expired", SHOTS && `${combo.lang}-temp_expired`)
  const c2 = await browser.newContext()
  await c2.request.get(`${BASE}/api/auth/config`)
  const ok = await c2.request.post(`${BASE}/api/auth/login`, { data: { username: creds.temp_ok_user, password: creds.temp_ok_password }, headers: await H(c2) })
  const next = (await ok.json().catch(() => ({}))).next
  check(`${tag}: yesterday's temporary password – accepted, on to the new password`, ok.status() === 200 && next === "password", { status: ok.status(), next })
  await c2.close()
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

async function shortKeyFlow(browser, combo, t) {
  const tag = `${combo.lang} short key`
  if (!SHORT_BASE || !SHORT) {
    check(`${tag}: SHORT_BASE / SHORT_CREDS given`, false)
    return
  }
  const r = await open(browser, combo)
  const req = r.ctx.request
  await req.get(`${SHORT_BASE}/api/auth/config`)
  const hs = async () => {
    const csrf = (await r.ctx.cookies(SHORT_BASE)).find((c) => c.name.endsWith("cobe_news_csrf"))?.value ?? ""
    return { "X-CSRF-Token": csrf }
  }
  const l = await req.post(`${SHORT_BASE}/api/auth/login`, { data: { username: SHORT.user, password: SHORT.password }, headers: await hs() })
  // one code per step: wait for a fresh one (the other flows used the main instance's admin)
  await new Promise((ok) => setTimeout(ok, 31000 - (Date.now() % 30000)))
  const m = await req.post(`${SHORT_BASE}/api/auth/mfa`, { data: { code: totp(SHORT.totp) }, headers: await hs() })
  if (!l.ok() || !m.ok()) {
    check(`${tag}: signed in on the short-key instance`, false, { login: l.status(), mfa: m.status() })
    return
  }
  const sys = (await (await req.get(`${SHORT_BASE}/api/admin/tls`)).json()).system ?? []
  const w = sys.find((x) => x.code === "secret_key_short")
  await r.page.goto(`${SHORT_BASE}/settings/https`)
  await settle(r.page)
  const main = (await r.page.locator("main").innerText()).replace(/\s+/g, " ")
  check(
    `${tag}: SECRET_KEY short – the API says "env", HTTPS shows "${t("system.warning.secretKeyShort.env", { min: w?.min }).slice(0, 60)}…"`,
    w?.source === "env" && main.includes(t("system.warning.secretKeyShort.env", { min: w.min })),
    { w },
  )
  await scrollCheck(r.page, `${combo.lang} ${combo.width}px ${combo.theme}`, "short key", SHOTS && `${combo.lang}-short_key`)
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

/** The sidebar at 375 px: the desktop one (sidebar-gap / sidebar-container) is never in the document. */
async function sidebarCheck(browser, combo, tag) {
  const r = await open(browser, combo)
  await r.ctx.addInitScript(() => {
    const seen = { desktop: false, at: null }
    window.__sidebar = seen
    new MutationObserver(() => {
      if (!seen.desktop && document.querySelector("[data-slot=sidebar-gap], [data-slot=sidebar-container]")) {
        seen.desktop = true
        seen.at = Math.round(performance.now())
      }
    }).observe(document, { childList: true, subtree: true })
  })
  await signIn(r.ctx, creds.layout_solo_user, creds.layout_solo_password)
  const out = []
  for (const path of ["/", "/settings/profile", "/vendor"]) {
    await r.page.goto(`${BASE}${path}`)
    await settle(r.page)
    out.push({ path, ...(await r.page.evaluate(() => window.__sidebar)), trigger: await r.page.locator("[data-slot=sidebar-trigger]").count() })
  }
  const mobile = combo.width < 768
  check(
    `${tag}: the sidebar is ${mobile ? "the mobile one from the first paint (the desktop one never rendered)" : "the desktop one"}`,
    out.every((x) => (mobile ? !x.desktop && x.trigger > 0 : x.desktop)),
    out,
  )
  check(`${tag} sidebar: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

async function pages(browser, combo) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme}`
  const t = texts(lang)
  await sidebarCheck(browser, combo, tag)
  const a = await open(browser, combo)
  await signIn(a.ctx, creds.user, creds.password, true)
  for (const [name, path, text] of [
    ["sessions", "/settings/auth", t("signin.sessions.tempDays")],
    ["users", "/settings/users", t("users.tempExpired")],
    ["https", "/settings/https", t("system.warning.emergencyFailures", { count: 21 })],
  ]) {
    await a.page.goto(`${BASE}${path}`)
    await settle(a.page)
    if (name === "sessions") await card(a.page, t("settings.tab.sessions")).scrollIntoViewIfNeeded()
    check(`${tag}: ${name} shows "${text.slice(0, 40)}"`, (await a.page.locator("main").innerText()).replace(/\s+/g, " ").includes(text))
    await scrollCheck(a.page, tag, name, SHOTS && `${lang}-${width}-${theme}-${name}`)
  }
  check(`${tag} pages: no page or console errors`, a.errors.length === 0, a.errors.slice(0, 3))
  await a.ctx.close()
  const r = await open(browser, combo)
  await r.page.goto(`${BASE}/?login_error=temp_password_expired`)
  await r.page.locator("#username").waitFor({ timeout: 10000 })
  await settle(r.page)
  check(`${tag}: the sign-in page with the alert`, (await r.page.getByRole("alert").count()) === 1 && !r.page.url().includes("login_error"))
  await scrollCheck(r.page, tag, "login error", SHOTS && `${lang}-${width}-${theme}-login_error`)
  check(`${tag} sign-in page: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

// ---------------------------------------------------------------- nginx (optional)
/** One request with its own Host header: { status, type, body, location } or { closed } when nginx closes (444). */
function ask(secure, port, host, path = "/") {
  return new Promise((ok) => {
    const lib = secure ? https : http
    const req = lib.request({ host: "127.0.0.1", port, path, method: "GET", headers: { Host: host }, rejectUnauthorized: false, timeout: 6000 }, (res) => {
      let body = ""
      res.setEncoding("utf8")
      res.on("data", (c) => (body += c))
      res.on("end", () => ok({ status: res.statusCode, type: res.headers["content-type"] ?? "", body, location: res.headers.location ?? "" }))
    })
    req.on("timeout", () => req.destroy(new Error("timeout")))
    req.on("error", (e) => ok({ closed: true, error: e.code || e.message }))
    req.end()
  })
}

async function nginxChecks() {
  const S = Number(process.env.NGINX_HTTPS_PORT)
  const P = Number(process.env.NGINX_HTTP_PORT)
  const known = (process.env.NGINX_KNOWN || "localhost,127.0.0.1").split(",")
  const tag = "nginx"
  const u = await ask(true, S, "unknown.example")
  check(
    `${tag}: https with an unknown Host – 421 plain text "Unbekannter Hostname …" / "Unknown host name …", no-store`,
    u.status === 421 && u.type.startsWith("text/plain") && u.body.includes("Unbekannter Hostname") && u.body.includes("Unknown host name") && !u.body.includes("<"),
    { status: u.status, type: u.type },
  )
  const reached = []
  for (const h of known) {
    const x = await ask(true, S, `${h}:${S}`, "/api/health")
    const y = await ask(true, S, `${h}:${S}`)
    reached.push({ h, health: x.status, page: y.status, app: (y.body ?? "").includes('id="root"') })
  }
  check(
    `${tag}: https with a known name (${known.join(", ")}) – the app answers`,
    reached.every((x) => x.health === 200 && x.page === 200 && x.app),
    reached,
  )
  const p80u = await ask(false, P, "unknown.example")
  const p80k = await ask(false, P, "localhost")
  check(
    `${tag}: port 80 – an unknown Host gets nothing (444), localhost a 301 to https`,
    p80u.closed === true && p80k.status === 301 && p80k.location === `https://localhost:${S}/`,
    { p80u, p80k: { status: p80k.status, location: p80k.location } },
  )
  const plainK = await ask(false, S, `localhost:${S}`, "/settings/profile?x=1")
  const plainU = await ask(false, S, "unknown.example")
  check(
    `${tag}: plain http on the https port – a known name redirected to https (path and query kept), an unknown one closed`,
    plainK.status === 301 && plainK.location === `https://localhost:${S}/settings/profile?x=1` && plainU.closed === true,
    { plainK: { status: plainK.status, location: plainK.location }, plainU },
  )
  const logs = (name) => execSync(`docker logs ${name} 2>&1`, { encoding: "utf8" })
  const quiet = logs(process.env.NGINX_CONTAINER)
  const loud = process.env.NGINX_WARN_CONTAINER ? logs(process.env.NGINX_WARN_CONTAINER) : ""
  const names = (quiet.match(/cobe-news: answering to (.*)/) ?? [])[1] ?? ""
  check(
    `${tag}: start log – the names answered to (${names}); BIND=0.0.0.0 with BASE_URL on localhost warns, BIND=127.0.0.1 does not`,
    known.every((h) => names.split(" ").includes(h)) &&
      !quiet.includes("WARNING") &&
      /WARNING – BIND=0\.0\.0\.0 publishes Cobe News to the network, but BASE_URL names localhost/.test(loud),
    { names, quietWarns: quiet.includes("WARNING"), loudWarns: loud.includes("WARNING") },
  )
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) {
    const t = texts(combo.lang)
    if (combo.wide) {
      await settingsFlow(browser, combo, t)
      await loginFlow(browser, combo, t)
      await shortKeyFlow(browser, combo, t)
      await sidebarCheck(browser, combo, `${combo.lang} ${combo.width}px ${combo.theme}`)
    } else await pages(browser, combo)
  }
  if (process.env.NGINX_HTTPS_PORT) await nginxChecks()
} finally {
  await browser.close()
}
finish()
