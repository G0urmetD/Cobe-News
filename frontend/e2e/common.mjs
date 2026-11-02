// Shared helpers of the 0.1.39 browser checks (audit, delivery-ops, catalog-care, passkeys-sessions): sign-in through
// the API (TOTP once per 30-second step), the notification stubs, checks that print PASS/FAIL, no horizontal scroll,
// tooltips, toasts and the re-confirmation. Only against a throwaway instance – docs/BETRIEB.md, "Entwicklung / Tests".
import crypto from "node:crypto"
import fs from "node:fs"

export const BASE = (process.env.BASE_URL || "http://localhost:5280").replace(/\/$/, "")
export const creds = JSON.parse(fs.readFileSync(process.env.CREDS || "", "utf8"))
export const SHOTS = process.env.SHOTS || ""
export const pw = await import(process.env.PLAYWRIGHT || "playwright-core")
export const COMBOS = []
for (const lang of ["de", "en"])
  for (const width of [1280, 375]) for (const theme of ["light", "dark"]) COMBOS.push({ lang, width, theme, wide: width === 1280 && theme === "light" })

export function totp(secret, at = Date.now()) {
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

// a TOTP code counts once: every use (sign-in, re-confirmation) in a step of its own
let lastStep = 0
export async function freshCode() {
  while (Math.floor(Date.now() / 30000) <= lastStep || 30000 - (Date.now() % 30000) < 3000) await new Promise((ok) => setTimeout(ok, 1000))
  lastStep = Math.floor(Date.now() / 30000)
  return totp(creds.totp)
}

export const results = []
export function check(name, ok, info) {
  results.push(!!ok)
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${info !== undefined ? `  (${JSON.stringify(info)})` : ""}`)
}
export function finish() {
  const failed = results.filter((x) => !x).length
  console.log(`\n${results.length - failed}/${results.length} passed`)
  process.exit(failed ? 1 : 0)
}

export async function stub(ctx, lang, theme) {
  await ctx.addInitScript(
    ([l, th]) => {
      localStorage.setItem("cobe-news.lang", l)
      localStorage.setItem("cobe-news.theme", th)
      class N {
        static permission = "denied"
        static requestPermission() {
          return Promise.resolve("denied")
        }
        close() {}
        addEventListener() {}
      }
      window.Notification = N
      if (window.ServiceWorkerRegistration) window.ServiceWorkerRegistration.prototype.showNotification = () => Promise.resolve()
    },
    [lang, theme],
  )
}

export const csrfOf = async (ctx, base = BASE) => (await ctx.cookies(base)).find((c) => c.name.endsWith("cobe_news_csrf"))?.value ?? ""
export const H = async (ctx) => ({ "X-CSRF-Token": await csrfOf(ctx) })

/** Signs a browser context in through the API – the admin with a TOTP code of a fresh step. */
export async function signIn(ctx, user, password, withTotp = false) {
  const req = ctx.request
  await req.get(`${BASE}/api/auth/config`)
  const r = await req.post(`${BASE}/api/auth/login`, { data: { username: user, password }, headers: await H(ctx) })
  if (!r.ok()) throw new Error(`login ${user}: ${r.status()}`)
  if ((await r.json()).next !== "mfa") return
  if (!withTotp) throw new Error(`login ${user}: a code is asked`)
  const m = await req.post(`${BASE}/api/auth/mfa`, { data: { code: await freshCode() }, headers: await H(ctx) })
  if (!m.ok()) throw new Error(`mfa: ${m.status()}`)
}

/** A browser context with the stubs, its page, the page's errors (no console error, no page error). */
export async function open(browser, { lang, width, theme }, extra = {}) {
  const ctx = await browser.newContext({ serviceWorkers: "block", locale: lang === "de" ? "de-DE" : "en-GB", viewport: { width, height: 860 }, colorScheme: theme, ...extra })
  await stub(ctx, lang, theme)
  const page = await ctx.newPage()
  const errors = []
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`))
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`)
  })
  return { ctx, page, errors }
}

export async function settle(page) {
  await page.waitForLoadState("networkidle").catch(() => undefined)
  await page.waitForTimeout(350)
}

/** No horizontal scroll: the page, an open drawer, an open dialog. */
export async function scrollCheck(page, tag, name, shot, mask = []) {
  const s = await page.evaluate(() => {
    const wide = (el) => !!el && el.scrollWidth > el.clientWidth + 1
    const d = document.documentElement
    const sheet = document.querySelector("[data-slot=sheet-content]")
    const dialog = [...document.querySelectorAll("[data-slot=dialog-content]")].some(wide)
    return { ok: !wide(d) && !wide(sheet) && !dialog, page: wide(d), sheet: wide(sheet), dialog }
  })
  check(`${tag} ${name}: no horizontal scroll`, s.ok, s.ok ? undefined : s)
  if (SHOTS && shot) await page.screenshot({ path: `${SHOTS}/${shot}.png`, mask })
}

export async function tooltipOf(page, el) {
  await el.hover()
  await el.focus().catch(() => {})
  const tip = page.locator("[data-slot=tooltip-content]").first()
  await tip.waitFor({ timeout: 3000 }).catch(() => {})
  const text = (await tip.count()) ? await tip.innerText() : ""
  await page.mouse.move(1, 1)
  await page.keyboard.press("Escape")
  await page.waitForTimeout(200)
  return text
}

/** The newest toast after `before` toasts: its type and text (null: none came). */
export async function toastAfter(page, before, ms = 8000) {
  const toasts = page.locator("[data-sonner-toast]")
  for (let i = 0; i * 150 < ms && (await toasts.count()) <= before; i++) await page.waitForTimeout(150)
  if ((await toasts.count()) <= before) return null
  const last = toasts.last()
  return { type: await last.getAttribute("data-type"), text: await last.innerText(), el: last }
}
export const toastCount = (page) => page.locator("[data-sonner-toast]").count()

export async function dismissToasts(page) {
  for (let i = 0; i < 20 && (await page.locator("[data-sonner-toast]").count()); i++) {
    const close = page.locator("[data-sonner-toast] [data-close-button]").first()
    if (await close.count()) await close.click({ timeout: 1000 }).catch(() => {})
    else await page.waitForTimeout(400)
  }
}

/** The server asks for the re-confirmation on the next POST/PUT/DELETE to `pattern` (as after its window): the prompt
 * is answered for real – the password (and a TOTP code of a fresh step when `code`). True: it asked and was answered. */
export async function reauthOnce(page, pattern, action, { password = creds.password, code = true, method = null } = {}) {
  let asked = false
  await page.route(pattern, (route) => {
    const m = route.request().method()
    if (!asked && m !== "GET" && (!method || m === method)) {
      asked = true
      return route.fulfill({ status: 403, json: { detail: { code: "reauth_required", via: "password", totp: code } } })
    }
    return route.fallback()
  })
  await action()
  const pwField = page.locator("#reauth-pw")
  await pwField.waitFor({ timeout: 6000 }).catch(() => {})
  const shown = (await pwField.count()) === 1
  if (shown) {
    await pwField.fill(password)
    if (code) await page.locator("#reauth-code").fill(await freshCode())
    await page.keyboard.press("Enter")
    await pwField.waitFor({ state: "detached", timeout: 8000 }).catch(() => {})
  }
  await page.unroute(pattern)
  return asked && shown
}

export const json = async (ctx, p) => (await ctx.request.get(`${BASE}${p}`)).json()
