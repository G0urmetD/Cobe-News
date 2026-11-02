// Regression check (browser): Einstellungen → Anmeldung.
// 1. The re-confirmation (password + code, components/cobe/reauth.tsx) is always the topmost, usable layer: its own
//    level above drawers and dialogs, the first field focused, and drawn again as the last layer when a drawer mounts
//    after it (it lay behind the drawer, its fields could not be used).
// 2. "Verbindung testen" (AD/LDAP, Entra ID) answers with a toast – success, warning or the reason – besides the box
//    under the form; the button is busy meanwhile, "Speichern" waits.
//
// Only against a throwaway instance (temp DATA_DIR, never the live one) – how to run it: docs/BETRIEB.md, "Entwicklung / Tests".
// Env: BASE_URL (vite dev server, e.g. http://127.0.0.1:5611), CREDS (JSON file {user, password, totp} of an admin),
// PLAYWRIGHT (path to an existing playwright or playwright-core install: …/node_modules/playwright/index.mjs).
// Uses the installed Google Chrome (channel "chrome") – never downloads a browser. No directory, no tenant: the test
// endpoints are answered here, and so is the server's "confirm first" (a fresh sign-in counts as confirmed).
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import fs from "node:fs"

const BASE = (process.env.BASE_URL || "http://127.0.0.1:5611").replace(/\/$/, "")
const creds = JSON.parse(fs.readFileSync(process.env.CREDS || "", "utf8"))
const { chromium } = await import(process.env.PLAYWRIGHT || "playwright-core")

// RFC 6238 TOTP (SHA-1, 6 digits, 30 s) – the second factor of the throwaway admin
function totp(secret, at = Date.now()) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = ""
  for (const c of secret.replace(/=+$/, "").toUpperCase()) bits += alpha.indexOf(c).toString(2).padStart(5, "0")
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)))
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(Math.floor(at / 30000)))
  const h = crypto.createHmac("sha1", key).update(msg).digest()
  const o = h[h.length - 1] & 15
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0")
}

const results = []
const check = (name, ok, info) => {
  results.push(ok)
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${info ? `  (${JSON.stringify(info)})` : ""}`)
}

const browser = await chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  // no service worker, no notification permission; Notification and showNotification stubbed – nothing reaches the desktop
  const ctx = await browser.newContext({ serviceWorkers: "block", locale: "de-DE", viewport: { width: 1280, height: 860 } })
  await ctx.addInitScript(() => {
    window.__notifications = []
    class N {
      static permission = "denied"
      static requestPermission() {
        return Promise.resolve("denied")
      }
      constructor(title) {
        window.__notifications.push(title)
      }
      close() {}
      addEventListener() {}
    }
    window.Notification = N
    if (window.ServiceWorkerRegistration)
      window.ServiceWorkerRegistration.prototype.showNotification = function (title) {
        window.__notifications.push(title)
        return Promise.resolve()
      }
  })
  const page = await ctx.newPage()

  // sign in through the API (the session cookie lands in this browser context)
  const req = ctx.request
  const signIn = async () => {
    await req.get(`${BASE}/api/auth/config`)
    const csrf = (await ctx.cookies(BASE)).find((c) => c.name.endsWith("cobe_news_csrf"))?.value ?? ""
    const h = { "X-CSRF-Token": csrf }
    const r = await req.post(`${BASE}/api/auth/login`, { data: { username: creds.user, password: creds.password }, headers: h })
    if (!r.ok()) throw new Error(`login: ${r.status()}`)
    const left = 30000 - (Date.now() % 30000)
    if (left < 4000) await page.waitForTimeout(left + 500)
    return (await req.post(`${BASE}/api/auth/mfa`, { data: { code: totp(creds.totp) }, headers: h })).ok()
  }
  if (!(await signIn())) {
    await page.waitForTimeout(30000 - (Date.now() % 30000) + 500)
    if (!(await signIn())) throw new Error("sign-in failed")
  }

  // the server asks for a confirmation on the next save of the sign-in settings (once per arm()); the confirmation
  // itself is accepted here – the save after it goes to the real server
  let askNext = false
  const arm = () => (askNext = true)
  const reauthRequired = { status: 403, json: { detail: { code: "reauth_required", via: "password", totp: true } } }
  await page.route(/\/api\/admin\/auth\/(ldap|entra)$/, (route) => {
    if (route.request().method() === "PUT" && askNext) {
      askNext = false
      return route.fulfill(reauthRequired)
    }
    return route.fallback()
  })
  await page.route("**/api/auth/reauth", (route) => route.fulfill({ json: { ok: true } }))
  // "Verbindung testen": answered here (no directory, no tenant), a little late – the busy state can be seen
  let ldapAnswer = { ok: true }
  let entraAnswer = { ok: true, groups: "ok" }
  const late = (answer) => async (route) => {
    await new Promise((r) => setTimeout(r, 700))
    await route.fulfill({ json: answer() })
  }
  await page.route(
    "**/api/admin/auth/ldap/test",
    late(() => ldapAnswer),
  )
  await page.route(
    "**/api/admin/auth/entra/test",
    late(() => entraAnswer),
  )

  // is the re-confirmation the layer on top, where is the focus, does typing reach its field?
  const prompt = () =>
    page.evaluate(() => {
      const pw = document.getElementById("reauth-pw")
      if (!pw) return { open: false }
      const r = pw.getBoundingClientRect()
      const at = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2)
      return {
        open: true,
        onTop: at === pw,
        at: at?.closest("[data-slot]")?.getAttribute("data-slot") ?? at?.tagName,
        focus: document.activeElement?.id || document.activeElement?.getAttribute("data-slot"),
      }
    })
  const typeInto = async (text) => {
    await page.keyboard.type(text)
    return page.evaluate(() => document.getElementById("reauth-pw")?.value)
  }
  const toasts = () => page.locator("[data-sonner-toast]").evaluateAll((els) => els.map((e) => ({ type: e.getAttribute("data-type"), text: e.textContent?.trim() })))
  const dismissToasts = async () => {
    await page.evaluate(() => document.querySelectorAll("[data-sonner-toast] [data-close-button]").forEach((b) => b.click()))
    await page.waitForTimeout(500)
  }
  const ldapCard = page.locator("section").filter({ has: page.getByText("Anmeldung mit Active Directory", { exact: true }) })
  const entraCard = page.locator("section").filter({ has: page.getByText("Anmeldung mit Microsoft Entra ID", { exact: true }) })

  // ---------------------------------------------------------------- 1. re-confirmation
  const openLdap = async () => {
    await page.goto(`${BASE}/settings/auth`)
    await page.getByText("Anmeldung mit Active Directory", { exact: true }).waitFor()
    const on = ldapCard.locator("[role=switch]").first()
    if ((await on.getAttribute("aria-checked")) !== "true") await on.click()
  }
  const dc = () => `dc${crypto.randomInt(10, 99)}.corp.example` // every run something new to save
  await openLdap()
  await ldapCard.locator("textarea").first().fill(dc())
  await ldapCard.getByPlaceholder("DC=corp,DC=example", { exact: true }).fill("DC=corp,DC=example")
  arm()
  await ldapCard.getByRole("button", { name: "Speichern" }).click()
  await page.locator("#reauth-pw").waitFor()
  await page.waitForTimeout(300)
  let p = await prompt()
  check("LDAP saved the first time: the re-confirmation is on top, the password field has the focus", p.onTop && p.focus === "reauth-pw", p)
  check("… typing goes into it", (await typeInto("pw")) === "pw")

  // a drawer that mounts after the question (here: the address changes to the mail server drawer)
  await page.evaluate(() => {
    history.pushState({}, "", "/settings/rules?smtp=1")
    dispatchEvent(new PopStateEvent("popstate"))
  })
  await page.locator("[data-slot=sheet-content]").waitFor()
  await page.waitForTimeout(500)
  p = await prompt()
  const kids = await page.evaluate(() => [...document.body.children].map((c) => c.getAttribute("data-slot")).filter(Boolean))
  check("a drawer mounted after it: the re-confirmation is still the last layer and on top", p.onTop && kids.at(-1) === "dialog-content", { ...p, kids })
  check(
    "… what was typed is still there, the focus is in the form",
    (await page.evaluate(() => document.getElementById("reauth-pw")?.value)) === "pw" && p.focus === "reauth-pw",
    p,
  )
  await page
    .locator("#reauth-pw")
    .click({ timeout: 3000 })
    .catch(() => {}) // it lay behind the drawer: the click hit the drawer's overlay
  check("… a click into its field works and typing reaches it", (await typeInto("x")) === "pwx")
  await page.keyboard.press("Escape")
  await page.waitForTimeout(400)
  p = await prompt()
  const sheetOpen = (await page.locator("[data-slot=sheet-content]").count()) === 1
  check("Escape closes only the re-confirmation, the drawer stays", !p.open && sheetOpen, { ...p, sheetOpen })
  await page.keyboard.press("Escape")
  await page.waitForTimeout(400)
  await dismissToasts()

  // the confirmation itself: code + password, the save goes through
  await openLdap()
  await ldapCard.locator("textarea").first().fill(dc())
  await ldapCard.getByPlaceholder("DC=corp,DC=example", { exact: true }).fill("DC=corp,DC=example")
  arm()
  await ldapCard.getByRole("button", { name: "Speichern" }).click()
  await page.locator("#reauth-pw").waitFor()
  await page.waitForTimeout(300)
  await page.keyboard.type("anything")
  await page.locator("#reauth-code").fill("123456")
  await page.keyboard.press("Enter")
  await page
    .locator("#reauth-pw")
    .waitFor({ state: "detached", timeout: 5000 })
    .catch(() => {})
  await page
    .locator("[data-sonner-toast][data-type=success]")
    .first()
    .waitFor({ timeout: 5000 })
    .catch(() => {})
  await page.waitForTimeout(300)
  const saved = (await toasts()).some((x) => x.type === "success")
  const pe = await page.evaluate(() => document.body.style.pointerEvents || "")
  check("confirmed: the prompt closes, the save goes through, the page stays usable", !(await prompt()).open && saved && pe !== "none", { saved, pe })
  await dismissToasts()

  // ---------------------------------------------------------------- 2. "Verbindung testen"
  const testIn = (card) => card.getByRole("button", { name: "Verbindung testen" })
  const saveIn = (card) => card.getByRole("button", { name: "Speichern" })
  const runTest = async (card) => {
    await dismissToasts()
    await testIn(card).click()
    await page.waitForTimeout(250)
    const during = { test: await testIn(card).isDisabled(), spinner: (await testIn(card).locator(".animate-spin").count()) === 1, save: await saveIn(card).isDisabled() }
    await page
      .locator("[data-sonner-toast]")
      .first()
      .waitFor({ timeout: 5000 })
      .catch(() => {})
    await page.waitForTimeout(300)
    return { during, toasts: await toasts(), after: !(await testIn(card).isDisabled()) }
  }
  // the boxes of the card (the test's details; 0.1.42: also the MFA proof hint of Entra) – their text
  const box = (card) =>
    card
      .locator("p.rounded-lg.border")
      .allTextContents()
      .then((all) => all.join("\n"))
      .catch(() => "")

  await ldapCard
    .locator("textarea")
    .first()
    .fill(dc() + "\n" + dc()) // something to save: "Speichern" must still wait for the test
  ldapAnswer = { ok: true }
  let r = await runTest(ldapCard)
  check("LDAP test: busy while it runs (spinner, button off, Speichern waits)", r.during.test && r.during.spinner && r.during.save, r.during)
  check("LDAP test ok: one success toast", r.toasts.length === 1 && r.toasts[0].type === "success" && r.toasts[0].text.includes("Dienstkonto angemeldet"), r.toasts)
  check("… and the button is free again", r.after)

  ldapAnswer = { ok: false, error: "service_bind" }
  r = await runTest(ldapCard)
  const ldapBox = await box(ldapCard)
  check(
    "LDAP test failed: one error toast with the reason the box shows",
    r.toasts.length === 1 && r.toasts[0].type === "error" && r.toasts[0].text.includes("Dienstkonto wird abgelehnt") && ldapBox.includes("Dienstkonto wird abgelehnt"),
    { toasts: r.toasts, ldapBox },
  )

  // Entra: switch on, fill in, test – nothing is saved
  await page.getByText("Anmeldung mit Microsoft Entra ID", { exact: true }).scrollIntoViewIfNeeded()
  const entraSwitch = entraCard.locator("[role=switch]").first()
  if ((await entraSwitch.getAttribute("aria-checked")) !== "true") await entraSwitch.click()
  const guids = entraCard.getByPlaceholder("00000000-0000-0000-0000-000000000000")
  await guids.nth(0).fill("11111111-2222-3333-4444-555555555555")
  await guids.nth(1).fill("66666666-7777-8888-9999-000000000000")
  await entraCard.locator("input[type=password]").fill("example-secret")

  entraAnswer = { ok: true, groups: "ok" }
  r = await runTest(entraCard)
  check(
    "Entra test ok: one success toast, busy meanwhile",
    r.during.test && r.during.spinner && r.toasts.length === 1 && r.toasts[0].type === "success" && r.toasts[0].text.includes("Mandant, Client-ID"),
    r,
  )
  entraAnswer = { ok: true, groups: "forbidden" }
  r = await runTest(entraCard)
  check("Entra test ok, but no Graph permission for groups: a warning toast", r.toasts.length === 1 && r.toasts[0].type === "warning", r.toasts)
  entraAnswer = { ok: false, error: "auth" }
  r = await runTest(entraCard)
  const entraBox = await box(entraCard)
  check(
    "Entra test failed: one error toast with the reason the box shows",
    r.toasts.length === 1 &&
      r.toasts[0].type === "error" &&
      r.toasts[0].text.includes("Anmeldung der Anwendung abgelehnt") &&
      entraBox.includes("Anmeldung der Anwendung abgelehnt"),
    { toasts: r.toasts, entraBox },
  )

  const shown = await page.evaluate(() => window.__notifications.length)
  check("no notification shown (stubs)", shown === 0, { shown })
} finally {
  await browser.close()
}
const failed = results.filter((x) => !x).length
console.log(failed ? `\n${failed} of ${results.length} checks FAILED` : `\nall ${results.length} checks passed`)
process.exit(failed ? 1 : 0)
