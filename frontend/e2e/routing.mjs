// Browser check: per-person routing and the personal notifications (0.1.30) – the team drawer's *Produkte* ("Alle im
// Team", the member picker, the warning for an empty choice), who gets what under *Mitglieder*, the three admin switches
// under Teams → Einstellungen, and a reader's "Hersteller-News meiner Produkte" under Einstellungen → Benachrichtigungen
// (and its absence for someone in no team). DE and EN, 1280 px and 375 px, light and dark: no page error, no console
// error, no horizontal scroll.
//
// Only against a throwaway instance (own database and DATA_DIR, never the live one) – docs/BETRIEB.md, "Entwicklung / Tests".
// It expects: a team "Netzwerk" with panos and fortios for all members and cisco-asa for Rudi and Person 3, Teams on,
// e-mail and Microsoft Teams allowed, desktop not; Rudi with e-mail and a Teams URL on.
// Env: BASE_URL (vite dev server), CREDS (JSON {user, password, totp, reader, reader_password, reader2,
// reader2_password} – never printed), PLAYWRIGHT (path to an existing playwright install
// …/node_modules/playwright/index.mjs), SHOTS (optional folder for screenshots). Uses the installed Google Chrome
// (channel "chrome") – never downloads a browser. Notifications stubbed, never granted.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import fs from "node:fs"

const BASE = (process.env.BASE_URL || "http://127.0.0.1:5220").replace(/\/$/, "")
const creds = JSON.parse(fs.readFileSync(process.env.CREDS || "", "utf8"))
const SHOTS = process.env.SHOTS || ""
const { chromium } = await import(process.env.PLAYWRIGHT || "playwright-core")

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

async function stub(ctx, lang, theme) {
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

async function csrf(ctx) {
  return { "X-CSRF-Token": (await ctx.cookies(BASE)).find((c) => c.name.endsWith("cobe_news_csrf"))?.value ?? "" }
}

async function signIn(ctx, page, user, password, code) {
  const req = ctx.request
  await req.get(`${BASE}/api/auth/config`)
  const h = await csrf(ctx)
  const r = await req.post(`${BASE}/api/auth/login`, { data: { username: user, password }, headers: h })
  if (!r.ok()) throw new Error(`login: ${r.status()}`)
  if ((await r.json()).next !== "mfa") return
  const left = 30000 - (Date.now() % 30000)
  if (left < 4000) await page.waitForTimeout(left + 500)
  const m = await req.post(`${BASE}/api/auth/mfa`, { data: { code: totp(code) }, headers: h })
  if (!m.ok()) throw new Error(`mfa: ${m.status()}`)
}

async function settle(page) {
  await page.waitForLoadState("networkidle").catch(() => undefined)
  await page.waitForTimeout(350)
}

async function noScroll(page) {
  return page.evaluate(() => {
    const d = document.documentElement
    return { ok: d.scrollWidth <= d.clientWidth + 1, scroll: d.scrollWidth, client: d.clientWidth }
  })
}

function watch(page) {
  const errors = []
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`))
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`)
  })
  return errors
}

const T = {
  de: {
    all: "Alle im Team",
    add: "Person hinzufügen",
    nobody: "Niemand bekommt die News zu diesem Produkt.",
    gets: "Bekommt:",
    personal: "Persönliche Benachrichtigungen",
    title: "Hersteller-News meiner Produkte",
    adminOff: "Vom Admin ausgeschaltet",
    save: "Speichern",
    search: "Mitglieder durchsuchen",
  },
  en: {
    all: "Everyone in the team",
    add: "Add person",
    nobody: "Nobody gets the news of this product.",
    gets: "Gets:",
    personal: "Personal notifications",
    title: "Vendor news of my products",
    adminOff: "Switched off by the admin",
    save: "Save",
    search: "Search members",
  },
}

const browser = await chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
let teamId = null
const usedMfa = new Set()
try {
  for (const lang of ["de", "en"]) {
    const L = T[lang]
    for (const width of [1280, 375]) {
      for (const theme of ["light", "dark"]) {
        const tag = `${lang} ${width}px ${theme}`
        const opts = { serviceWorkers: "block", locale: lang === "de" ? "de-DE" : "en-GB", viewport: { width, height: 860 }, colorScheme: theme }
        // ---------------------------------------------------------------- the admin
        const ctx = await browser.newContext(opts)
        await stub(ctx, lang, theme)
        const page = await ctx.newPage()
        const errors = watch(page)
        const step = Math.floor(Date.now() / 30000)
        if (usedMfa.has(step)) await page.waitForTimeout(30000 - (Date.now() % 30000) + 500)
        await signIn(ctx, page, creds.user, creds.password, creds.totp)
        usedMfa.add(Math.floor(Date.now() / 30000))
        if (!teamId) teamId = (await (await ctx.request.get(`${BASE}/api/admin/teams`)).json()).find((t) => t.name === "Netzwerk").id
        for (const [name, path] of [
          ["products", `/settings/teams?team=${teamId}&part=products`],
          ["members", `/settings/teams?team=${teamId}&part=members`],
          ["switch", "/settings/teams?tab=settings"],
        ]) {
          await page.goto(`${BASE}${path}`)
          await settle(page)
          const s = await noScroll(page)
          check(`${tag} ${name}: no horizontal scroll`, s.ok, s.ok ? undefined : s)
          if (SHOTS) await page.screenshot({ path: `${SHOTS}/${lang}-${width}-${theme}-${name}.png` })
        }
        await page.goto(`${BASE}/settings/teams?tab=settings`)
        await settle(page)
        const sw = await page.locator("body").innerText()
        check(`${tag} switch: personal notifications with three ways`, sw.includes(L.personal) && sw.includes("Microsoft Teams") && sw.includes("Desktop"))

        await page.goto(`${BASE}/settings/teams?team=${teamId}&part=products`)
        await settle(page)
        const rows = page.locator("[data-routing]")
        // as many as the team has (the seed: panos, cisco-asa, fortios – later seeds may add more)
        const teamProducts = ((await (await ctx.request.get(`${BASE}/api/admin/teams`)).json()).find((t) => t.id === teamId)?.products ?? []).length
        check(`${tag} products: a routing row per product (${teamProducts})`, teamProducts >= 3 && (await rows.count()) === teamProducts)
        check(`${tag} products: "${L.all}" toggles`, (await page.getByText(L.all, { exact: true }).count()) === teamProducts)
        const cisco = page.locator('[data-routing="cisco-asa"]')
        check(`${tag} products: cisco for chosen people (chip)`, (await cisco.innerText()).includes("Rudi Reader"))
        // the picker: search, pick – a chip; the popover fits the screen
        await cisco.getByRole("button", { name: L.add }).click()
        await page.getByRole("textbox", { name: L.search }).fill("Person 5")
        await page.waitForTimeout(700)
        await settle(page)
        const option = page.getByRole("option", { name: /Person 5/ })
        check(`${tag} picker: finds a team member`, (await option.count()) === 1)
        const s1 = await noScroll(page)
        check(`${tag} picker open: no horizontal scroll`, s1.ok, s1.ok ? undefined : s1)
        if (SHOTS) await page.screenshot({ path: `${SHOTS}/${lang}-${width}-${theme}-picker.png` })
        await option.click()
        await page.keyboard.press("Escape")
        check(`${tag} picker: chip added`, (await cisco.innerText()).includes("Person 5"))
        // "Alle im Team" off with nobody chosen: the warning
        const forti = page.locator('[data-routing="fortios"]')
        await forti.getByRole("switch").click()
        check(`${tag} products: warning for an empty choice`, (await forti.getByRole("alert").innerText()).includes(L.nobody))
        const s2 = await noScroll(page)
        check(`${tag} products edited: no horizontal scroll`, s2.ok, s2.ok ? undefined : s2)
        if (width === 1280 && theme === "light") {
          // saved through the drawer's bar: the API says so; then back as it was
          await forti.getByRole("switch").click()
          await page.getByRole("button", { name: L.save }).click()
          await settle(page)
          let team = (await (await ctx.request.get(`${BASE}/api/admin/teams`)).json()).find((t) => t.id === teamId)
          const people = team.products.find((p) => p.key === "cisco-asa").people.map((p) => p.display_name)
          check(`${lang} products: saved – Person 5 gets cisco`, people.includes("Person 5") && people.includes("Rudi Reader"), people)
          await page.goto(`${BASE}/settings/teams?team=${teamId}&part=members`)
          await settle(page)
          const members = await page.locator("body").innerText()
          check(`${lang} members: who gets what`, members.includes(L.gets))
          const ids = team.products
            .find((p) => p.key === "cisco-asa")
            .people.filter((p) => p.display_name !== "Person 5")
            .map((p) => p.id)
          await ctx.request.put(`${BASE}/api/admin/teams/${teamId}/routing`, { data: { product: "cisco-asa", all_members: false, members: ids }, headers: await csrf(ctx) })
          team = (await (await ctx.request.get(`${BASE}/api/admin/teams`)).json()).find((t) => t.id === teamId)
          check(`${lang} products: restored`, team.products.find((p) => p.key === "cisco-asa").people.length === 2)
        }
        check(`${tag} admin: no page or console errors`, errors.length === 0, errors.slice(0, 3))
        await ctx.close()

        // ---------------------------------------------------------------- the reader in a team
        const rctx = await browser.newContext(opts)
        await stub(rctx, lang, theme)
        const rp = await rctx.newPage()
        const rerr = watch(rp)
        await signIn(rctx, rp, creds.reader, creds.reader_password, "")
        await rp.goto(`${BASE}/settings/notifications?tab=vendor`)
        await settle(rp)
        const body = await rp.locator("body").innerText()
        check(`${tag} reader: the section is there`, body.includes(L.title))
        check(`${tag} reader: own products shown`, body.includes("Cisco") && body.includes("PAN-OS"))
        check(`${tag} reader: own address read-only`, body.includes("rudi@corp.example"))
        check(`${tag} reader: desktop switched off by the admin`, body.includes(L.adminOff))
        const html = await rp.content()
        check(
          `${tag} reader: the Teams URL masked, never in clear`,
          html.includes("prod-12.westeurope.logic.azure.com/…") && !html.includes("sig=example") && !html.includes("/workflows/"),
        )
        const s3 = await noScroll(rp)
        check(`${tag} reader: no horizontal scroll`, s3.ok, s3.ok ? undefined : s3)
        if (SHOTS) await rp.screenshot({ path: `${SHOTS}/${lang}-${width}-${theme}-reader.png`, fullPage: true })
        await rp.goto(`${BASE}/settings/notifications`)
        await settle(rp)
        const s4 = await noScroll(rp)
        check(`${tag} reader desktop tab: no horizontal scroll`, s4.ok, s4.ok ? undefined : s4)
        check(`${tag} reader: no page or console errors`, rerr.length === 0, rerr.slice(0, 3))
        await rctx.close()

        // ---------------------------------------------------------------- a reader in no team: no section
        if (width === 1280 && theme === "light") {
          const nctx = await browser.newContext(opts)
          await stub(nctx, lang, theme)
          const np = await nctx.newPage()
          const nerr = watch(np)
          await signIn(nctx, np, creds.reader2, creds.reader2_password, "")
          await np.goto(`${BASE}/settings/notifications?tab=vendor`)
          await settle(np)
          check(`${lang} no team: no section`, !(await np.locator("body").innerText()).includes(L.title))
          check(`${lang} no team: no page or console errors`, nerr.length === 0, nerr.slice(0, 3))
          await nctx.close()
        }
      }
    }
  }
} finally {
  await browser.close()
}
const failed = results.filter((x) => !x).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed ? 1 : 0)
