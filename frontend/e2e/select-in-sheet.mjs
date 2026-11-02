// Regression check (browser): Radix layers nested in a Sheet. Two copies of @radix-ui/react-dismissable-layer (cmdk
// pulled its own @radix-ui/react-dialog) each kept their own layer stack – Escape in a Select inside a Sheet closed both
// and left body.style.pointerEvents = "none" (the app dead until reload), the Select was not usable by keyboard, Escape
// on a tooltip in the product drawer closed the drawer. The cheap guard is src/lib/radix-deps.test.ts (one version of
// every @radix-ui package in package-lock.json); this script checks the behaviour itself.
//
// Only against a throwaway instance (temp DATA_DIR, never the live one) – how to run it: docs/BETRIEB.md, "Entwicklung / Tests".
// Env: BASE_URL (vite dev server, e.g. http://127.0.0.1:5611), CREDS (JSON file {user, password, totp} of an admin),
// PLAYWRIGHT (path to an existing playwright or playwright-core install: …/node_modules/playwright/index.mjs).
// Uses the installed Google Chrome (channel "chrome") – never downloads a browser.
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
    // a code is accepted once: start in a fresh 30 s step
    const left = 30000 - (Date.now() % 30000)
    if (left < 4000) await page.waitForTimeout(left + 500)
    return (await req.post(`${BASE}/api/auth/mfa`, { data: { code: totp(creds.totp) }, headers: h })).ok()
  }
  if (!(await signIn())) {
    await page.waitForTimeout(30000 - (Date.now() % 30000) + 500)
    if (!(await signIn())) throw new Error("sign-in failed")
  }

  const state = () =>
    page.evaluate(() => ({
      sheet: document.querySelectorAll("[data-slot=sheet-content]").length,
      listbox: !!document.querySelector("[role=listbox]"),
      tooltip: !!document.querySelector("[data-slot=tooltip-content]"),
      bodyPE: document.body.style.pointerEvents || "",
    }))
  const openCustomSheet = async () => {
    await page.goto(`${BASE}/vendor?tab=catalog`)
    await page.getByRole("button", { name: /Nicht im Katalog|Not in the catalogue/ }).click()
    await page.locator("[data-slot=sheet-content]").waitFor()
    await page.waitForTimeout(400)
    return page.locator("[data-slot=sheet-content] [role=combobox]")
  }

  // 1. Select opened with the mouse, one Escape: only the Select closes
  let combo = await openCustomSheet()
  await combo.click()
  await page.locator("[role=listbox]").waitFor()
  await page.keyboard.press("Escape")
  await page.waitForTimeout(500)
  let s = await state()
  check("Escape in an open Select closes only the Select", !s.listbox && s.sheet === 1, s)
  // the open Sheet is modal (body pointer-events "none" is right while it is open) – its own fields must still work
  const field = page.locator("[data-slot=sheet-content] input").last()
  await field.click({ timeout: 3000 }).catch(() => {})
  await page.keyboard.type("x")
  check("… and the Sheet stays usable (click + type into a field)", (await field.count()) > 0 && (await field.inputValue()) === "x")
  await page.keyboard.press("Escape")
  await page.waitForTimeout(500)
  s = await state()
  check("a second Escape closes the Sheet, the page stays clickable", s.sheet === 0 && s.bodyPE !== "none", s)

  // 2. the Select by keyboard alone: focus, Enter opens, arrows move, Enter chooses
  combo = await openCustomSheet()
  const before = (await combo.textContent())?.trim()
  await combo.focus()
  await page.keyboard.press("Enter")
  await page.waitForTimeout(300)
  const opened = (await state()).listbox
  await page.keyboard.press("ArrowUp") // the preset category is the last entry
  await page.keyboard.press("ArrowUp")
  await page.keyboard.press("Enter")
  await page.waitForTimeout(500)
  s = await state()
  const after = (await combo.textContent())?.trim()
  check("Select opens with Enter", opened)
  check("Select: arrow keys + Enter choose another entry, the Sheet stays open", !s.listbox && s.sheet === 1 && !!after && after !== before, { before, after, ...s })
  await page.keyboard.press("Escape")
  await page.waitForTimeout(500)

  // 3. product drawer: Tab to the CPE term (its tooltip opens on focus), one Escape closes only the tooltip
  await page.goto(`${BASE}/vendor?tab=catalog&product=${encodeURIComponent(process.env.PRODUCT || "fortios")}`)
  await page.locator("[data-slot=sheet-content]").waitFor()
  await page.waitForTimeout(800)
  await page.keyboard.press("Tab")
  await page.waitForTimeout(800)
  const tipOpen = (await state()).tooltip
  const focused = await page.evaluate(() => document.activeElement?.textContent?.trim())
  await page.keyboard.press("Escape")
  await page.waitForTimeout(500)
  s = await state()
  check("Tab in the product drawer focuses the CPE term and opens its tooltip", tipOpen && focused === "CPE", { focused })
  check("Escape on the tooltip closes only the tooltip, the drawer stays open", !s.tooltip && s.sheet === 1, s)
  await page.keyboard.press("Escape")
  await page.waitForTimeout(500)
  s = await state()
  check("a second Escape closes the drawer", s.sheet === 0 && s.bodyPE !== "none", s)

  // 4. cmdk (source filter on the news page) still searches and chooses; Escape closes only its popover
  await page.goto(`${BASE}/news`)
  const trigger = page.getByRole("button", { name: /^Quelle|^Source/ })
  await trigger.click()
  const items = page.locator("[cmdk-item]")
  await items.first().waitFor()
  const n = await items.count()
  const second = (await items.nth(1).textContent())?.trim() ?? ""
  await page.keyboard.type(second)
  await page.waitForTimeout(300)
  const m = await items.count()
  await page.keyboard.press("Enter")
  await page.waitForTimeout(300)
  const chosen = (await trigger.textContent())?.trim()
  await page.keyboard.press("Escape")
  await page.waitForTimeout(400)
  const popoverGone = (await page.locator("[cmdk-root]").count()) === 0
  const pe = await page.evaluate(() => document.body.style.pointerEvents || "")
  check("cmdk list: search narrows the entries, Enter chooses one, Escape closes it", n > 1 && m < n && m >= 1 && /1$/.test(chosen ?? "") && popoverGone && pe !== "none", {
    n,
    m,
    chosen,
    popoverGone,
  })

  const shown = await page.evaluate(() => window.__notifications.length)
  check("no notification shown (stubs)", shown === 0, { shown })
} finally {
  await browser.close()
}
const failed = results.filter((x) => !x).length
console.log(failed ? `\n${failed} of ${results.length} checks FAILED` : `\nall ${results.length} checks passed`)
process.exit(failed ? 1 : 0)
