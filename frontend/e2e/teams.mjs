// Browser check: the Teams screens – Einstellungen → Teams (list, drawer with its parts, the switch), the user list with
// teams and welcome state, the rule editor's team filter, and "Mein Team / Alle" in Vendor News for a reader. Under
// Gruppen → "Gruppe binden" the groups of the role mapping (mappedGroups below).
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll.
//
// Only against a throwaway instance (own database and DATA_DIR, never the live one) – docs/BETRIEB.md, "Entwicklung / Tests".
// Env: BASE_URL (vite dev server), CREDS (JSON {user, password, totp, reader, reader_password} – never printed),
// PLAYWRIGHT (path to an existing playwright install …/node_modules/playwright/index.mjs), SHOTS (optional folder for
// screenshots). Uses the installed Google Chrome (channel "chrome") – never downloads a browser. Notifications stubbed.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import fs from "node:fs"

const BASE = (process.env.BASE_URL || "http://127.0.0.1:5210").replace(/\/$/, "")
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

async function signIn(ctx, page, user, password, code) {
  const req = ctx.request
  await req.get(`${BASE}/api/auth/config`)
  const csrf = (await ctx.cookies(BASE)).find((c) => c.name.endsWith("cobe_news_csrf"))?.value ?? ""
  const h = { "X-CSRF-Token": csrf }
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

// "Gruppe binden" offers the groups of the role mapping (0.1.31): those of the chosen directory, not bound to the team
// yet, with their role, narrowed by the search text; a click picks one. Needs a usable directory (AD/LDAP with names
// under corp.example – the search in the directory itself may fail) and at least two AD mappings, one of them bound to
// "Netzwerk"; the bind itself is tried on "Server" (no group – its load touches no other group) and undone.
async function mappedGroups(ctx, page, lang, width, theme, tag) {
  const req = ctx.request
  const [settings, maps, teams] = await Promise.all(
    ["/api/admin/teams/settings", "/api/admin/auth/mappings", "/api/admin/teams"].map(async (p) => (await req.get(`${BASE}${p}`)).json()),
  )
  const source = settings.ldap_usable || !settings.entra_usable ? "ldap" : "entra"
  const net = teams.find((t) => t.name === "Netzwerk")
  const isBound = (t, m) => t.groups.some((g) => g.source === m.source && g.group_id.toLowerCase() === m.group_id.toLowerCase())
  const free = maps.filter((m) => m.source === source && !isBound(net, m))
  const taken = maps.filter((m) => m.source === source && isBound(net, m))
  const otherSource = maps.filter((m) => m.source !== source)
  check(`${tag} mapped groups: seed – directory usable, free and bound mappings`, (settings.ldap_usable || settings.entra_usable) && free.length >= 1 && taken.length >= 1, {
    usable: [settings.ldap_usable, settings.entra_usable],
    free: free.length,
    taken: taken.length,
  })
  if (!free.length) return
  const heading = lang === "de" ? "Aus der Rollen-Zuordnung" : "From the role mapping"
  const roleLabel = { admin: "Admin", reader: lang === "de" ? "Leser" : "Reader" }
  const nameOf = (m) => m.group_name || m.group_id
  const bindLabel = (m) => (lang === "de" ? `${nameOf(m)} binden` : `Bind ${nameOf(m)}`)
  const sheet = page.locator("[data-slot=sheet-content]")
  const list = sheet.getByRole("listbox", { name: heading })
  const search = sheet.getByPlaceholder(lang === "de" ? "Name der Gruppe …" : "Group name …")
  const optionTexts = async () =>
    (await list.getByRole("option").allInnerTexts()).map((x) =>
      x
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean),
    )

  await page.goto(`${BASE}/settings/teams?team=${net.id}&part=groups`)
  await settle(page)
  await list.waitFor({ timeout: 5000 }).catch(() => {})
  const shown = await optionTexts()
  const names = shown.map((o) => o[0])
  check(
    `${tag} mapped groups: heading shown, the free groups listed, the bound one and other directories not`,
    (await sheet.getByText(heading, { exact: true }).isVisible()) &&
      free.every((m) => names.includes(nameOf(m))) &&
      ![...taken, ...otherSource].some((m) => names.includes(nameOf(m))) &&
      names.length === free.length,
    { names },
  )
  check(
    `${tag} mapped groups: the role next to each group`,
    free.every((m) => shown.find((o) => o[0] === nameOf(m))?.at(-1) === roleLabel[m.role]),
    { shown },
  )
  await search.fill("zz-keine-solche-gruppe")
  await page.waitForTimeout(200)
  check(`${tag} mapped groups: a search without a match hides the list`, (await list.count()) === 0 && !(await sheet.getByText(heading, { exact: true }).isVisible()))
  const one = free[0]
  await search.fill(nameOf(one).slice(1, -1).toLowerCase())
  await page.waitForTimeout(200)
  const narrowed = (await optionTexts()).map((o) => o[0])
  check(`${tag} mapped groups: a matching search keeps that group`, narrowed.includes(nameOf(one)), { narrowed })
  await search.fill("")
  await page.waitForTimeout(200)
  const option = list.getByRole("option").filter({ hasText: nameOf(one) })
  await option.click()
  const bindButton = page.getByRole("button", { name: bindLabel(one), exact: true })
  check(
    `${tag} mapped groups: a click picks it, the button says "${bindLabel(one)}"`,
    (await option.getAttribute("aria-selected")) === "true" && (await bindButton.isVisible()) && (await bindButton.isEnabled()),
  )
  await page.waitForTimeout(400) // the button fades in from its disabled look
  const overflow = await page.evaluate(() => {
    const d = document.documentElement
    const wide = (el) => !!el && el.scrollWidth > el.clientWidth + 1
    return {
      page: d.scrollWidth > d.clientWidth + 1,
      sheet: wide(document.querySelector("[data-slot=sheet-content]")),
      list: [...document.querySelectorAll("[data-slot=sheet-content] [role=listbox]")].some(wide),
    }
  })
  check(`${tag} mapped groups: no horizontal scroll (page, drawer, list)`, !overflow.page && !overflow.sheet && !overflow.list, overflow)
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${lang}-${width}-${theme}-groups_from_mapping.png` })

  // the bind itself, once per language (a fresh sign-in counts as the confirmation)
  if (width !== 1280 || theme !== "light") return
  const server = teams.find((t) => t.name === "Server")
  const pickFor = server && maps.find((m) => m.source === source && !isBound(server, m))
  if (!pickFor) return check(`${lang} mapped groups bind: seed – team "Server" with a free mapping`, false)
  await page.goto(`${BASE}/settings/teams?team=${server.id}&part=groups`)
  await settle(page)
  await list
    .getByRole("option")
    .filter({ hasText: nameOf(pickFor) })
    .click()
  await page.getByRole("button", { name: bindLabel(pickFor), exact: true }).click()
  await sheet
    .getByRole("button", { name: lang === "de" ? "Gruppe lösen" : "Unbind group" })
    .first()
    .waitFor({ timeout: 8000 })
    .catch(() => {})
  await settle(page)
  const after = (await (await req.get(`${BASE}/api/admin/teams`)).json()).find((t) => t.id === server.id)
  const g = after.groups.find((x) => x.source === pickFor.source && x.group_id.toLowerCase() === pickFor.group_id.toLowerCase())
  const left = (await list.count()) === 0 || !(await optionTexts()).some((o) => o[0] === nameOf(pickFor))
  check(`${lang} mapped groups bind: the picked group is bound and leaves the list`, !!g && left, { bound: !!g, left })
  if (g) {
    const csrf = (await ctx.cookies(BASE)).find((c) => c.name.endsWith("cobe_news_csrf"))?.value ?? ""
    const r = await req.delete(`${BASE}/api/admin/teams/${server.id}/groups/${g.id}`, { headers: { "X-CSRF-Token": csrf } })
    check(`${lang} mapped groups bind: undone through the API`, r.ok(), r.ok() ? undefined : r.status())
  }
}

// Vendor News (0.1.32): "Mein Team / Alle" lives in the page – with "Mein Team" remembered, a load asks the overview
// once (scope=team) and never shows the full list first (cisco asa is not the reader's); the tab's number is the
// answer's `total` (all followed products) under either choice.
// 0.1.43: "Mein Team / Alle" sits in the tool row's "Filter" popover; the status row's "Alle" field counts the products
const filterBtn = (rp, lang) => rp.getByRole("button", { name: new RegExp(`^${lang === "de" ? "Filter" : "Filters"}(,|$)`) })
async function scopeRadio(rp, lang, which) {
  await filterBtn(rp, lang).click()
  const radio = rp.locator("[data-slot=popover-content]").getByRole("radio", { name: which, exact: true })
  await radio.waitFor({ timeout: 5000 }).catch(() => undefined)
  return radio
}
async function chooseScope(rp, lang, which) {
  await (await scopeRadio(rp, lang, which)).click()
  await rp.keyboard.press("Escape")
  await settle(rp)
}
async function scopeChecked(rp, lang, which) {
  const on = (await (await scopeRadio(rp, lang, which)).getAttribute("aria-checked")) === "true"
  await rp.keyboard.press("Escape")
  return on
}
async function allField(rp, lang) {
  const r = rp.getByRole("radio", { name: new RegExp(`^${lang === "de" ? "Alle" : "All"}: \\d+$`) })
  return (await r.count()) ? Number((await r.getAttribute("aria-label")).split(":")[1]) : -1
}

async function vendorLoad(rctx, rp, lang) {
  const asked = []
  rp.on("request", (r) => {
    if (r.url().includes("/api/vendor/overview")) asked.push(new URL(r.url()).search)
  })
  await rctx.addInitScript(() => {
    window.__sawAsa = false
    const look = () => {
      if (document.body && document.body.innerText.toLowerCase().includes("asa")) window.__sawAsa = true
    }
    new MutationObserver(look).observe(document, { childList: true, subtree: true, characterData: true })
  })
  await rp.reload()
  await settle(rp)
  const flashed = await rp.evaluate(() => window.__sawAsa)
  check(`${lang} vendor: Mein Team on load – one overview request (scope=team), the full list never shown`, asked.length === 1 && asked[0] === "?scope=team" && !flashed, {
    asked,
    flashed,
  })
  const api = async (q) => (await rctx.request.get(`${BASE}/api/vendor/overview${q}`)).json()
  const team = await api("?scope=team")
  await rp.getByRole("radio", { name: new RegExp(`^${lang === "de" ? "Alle" : "All"}: `) }).click() // the status row: every status
  await settle(rp)
  const mineAll = await allField(rp, lang)
  await chooseScope(rp, lang, lang === "de" ? "Alle" : "All")
  const all = await api("")
  const allAll = await allField(rp, lang)
  check(
    `${lang} vendor: the status row's "${lang === "de" ? "Alle" : "All"}" is the API's number of products (Mein Team and Alle)`,
    mineAll === team.items.length && allAll === all.items.length && all.total === all.items.length && team.items.length < all.items.length,
    {
      mineAll,
      allAll,
      total: [team.total, all.total],
      items: [team.items.length, all.items.length],
    },
  )
  await chooseScope(rp, lang, lang === "de" ? "Mein Team" : "My team")
}

const browser = await chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
let teamId = null
const usedMfa = new Set()
try {
  for (const lang of ["de", "en"]) {
    for (const width of [1280, 375]) {
      for (const theme of ["light", "dark"]) {
        const tag = `${lang} ${width}px ${theme}`
        const ctx = await browser.newContext({ serviceWorkers: "block", locale: lang === "de" ? "de-DE" : "en-GB", viewport: { width, height: 860 }, colorScheme: theme })
        await stub(ctx, lang, theme)
        const page = await ctx.newPage()
        const errors = []
        page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`))
        page.on("console", (m) => {
          if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`)
        })
        // a TOTP code is accepted once – wait for the next step when this one was used
        const step = Math.floor(Date.now() / 30000)
        if (usedMfa.has(step)) await page.waitForTimeout(30000 - (Date.now() % 30000) + 500)
        await signIn(ctx, page, creds.user, creds.password, creds.totp)
        usedMfa.add(Math.floor(Date.now() / 30000))
        if (!teamId) {
          const r = await ctx.request.get(`${BASE}/api/admin/teams`)
          teamId = (await r.json()).find((t) => t.name === "Netzwerk").id
        }
        const pages = [
          ["teams list", "/settings/teams"],
          ["teams switch", "/settings/teams?tab=settings"],
          ["drawer general", `/settings/teams?team=${teamId}&part=general`],
          ["drawer groups", `/settings/teams?team=${teamId}&part=groups`],
          ["drawer members", `/settings/teams?team=${teamId}&part=members`],
          ["drawer products", `/settings/teams?team=${teamId}&part=products`],
          ["new team", "/settings/teams?team=new"],
          ["users", "/settings/users"],
          ["rules", "/settings/rules?tab=rules"],
        ]
        for (const [name, path] of pages) {
          await page.goto(`${BASE}${path}`)
          await settle(page)
          const s = await noScroll(page)
          check(`${tag} ${name}: no horizontal scroll`, s.ok, s.ok ? undefined : s)
          if (SHOTS && theme === "light") await page.screenshot({ path: `${SHOTS}/${lang}-${width}-${name.replace(/ /g, "_")}.png`, fullPage: false })
        }
        await mappedGroups(ctx, page, lang, width, theme, tag)
        // content checks once per language (the wide light run)
        if (width === 1280 && theme === "light") {
          await page.goto(`${BASE}/settings/teams?team=${teamId}&part=groups`)
          await settle(page)
          const body = await page.locator("body").innerText()
          check(`${lang} groups: Graph 403 hint names GroupMember.Read.All`, body.includes("GroupMember.Read.All"))
          await page.goto(`${BASE}/settings/users`)
          await settle(page)
          const users = await page.locator("body").innerText()
          check(
            `${lang} users: never signed in + no e-mail marked`,
            users.includes(lang === "de" ? "Noch nie angemeldet" : "Never signed in") && users.includes(lang === "de" ? "Keine E-Mail" : "No e-mail"),
          )
          // the rule editor shows the team filter
          await page.goto(`${BASE}/settings/rules?tab=rules`)
          await settle(page)
          // the rule with the team (the seed's "Vendor kritisch – Netzwerk" – another rule may come first)
          await page
            .locator("main li")
            .filter({ hasText: "Netzwerk" })
            .getByRole("button", { name: lang === "de" ? "Bearbeiten" : "Edit" })
            .first()
            .click()
          await settle(page)
          const editor = await page.locator("body").innerText()
          check(`${lang} rule editor: team filter with Netzwerk`, editor.includes("Teams") && editor.includes("Netzwerk"))
          const s = await noScroll(page)
          check(`${lang} rule editor: no horizontal scroll`, s.ok, s.ok ? undefined : s)
          if (SHOTS) await page.screenshot({ path: `${SHOTS}/${lang}-${width}-rule_editor.png` })
        }
        check(`${tag} admin: no page or console errors`, errors.length === 0, errors.slice(0, 3))
        await ctx.close()

        // the reader: Vendor News with "Mein Team / Alle"
        const rctx = await browser.newContext({ serviceWorkers: "block", locale: lang === "de" ? "de-DE" : "en-GB", viewport: { width, height: 860 }, colorScheme: theme })
        await stub(rctx, lang, theme)
        const rp = await rctx.newPage()
        const rerr = []
        rp.on("pageerror", (e) => rerr.push(`pageerror: ${e.message}`))
        rp.on("console", (m) => {
          if (m.type() === "error" && !/Failed to load resource/.test(m.text())) rerr.push(`console: ${m.text()}`)
        })
        await signIn(rctx, rp, creds.reader, creds.reader_password, "")
        await rp.goto(`${BASE}/vendor`)
        await settle(rp)
        const teamName = lang === "de" ? "Mein Team" : "My team"
        const allName = lang === "de" ? "Alle" : "All"
        const shown = (await (await scopeRadio(rp, lang, teamName)).count()) === 1
        await rp.keyboard.press("Escape")
        check(`${tag} vendor: "Mein Team" switch shown (in the Filter popover)`, shown)
        const s = await noScroll(rp)
        check(`${tag} vendor: no horizontal scroll`, s.ok, s.ok ? undefined : s)
        if (width === 1280 && theme === "light") {
          const cards = async () => (await rp.locator("main").innerText()).toLowerCase()
          await chooseScope(rp, lang, teamName)
          const mine = await cards()
          await chooseScope(rp, lang, allName)
          const all = await cards()
          check(`${lang} vendor: Mein Team hides cisco asa, Alle shows it`, !mine.includes("asa") && all.includes("asa"))
          await rp.reload()
          await settle(rp)
          check(`${lang} vendor: the choice is remembered`, await scopeChecked(rp, lang, allName))
          await chooseScope(rp, lang, teamName)
          await vendorLoad(rctx, rp, lang)
        }
        if (SHOTS && theme === "light") await rp.screenshot({ path: `${SHOTS}/${lang}-${width}-vendor.png` })
        check(`${tag} reader: no page or console errors`, rerr.length === 0, rerr.slice(0, 3))
        await rctx.close()
      }
    }
  }
} finally {
  await browser.close()
}
const failed = results.filter((x) => !x).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed ? 1 : 0)
