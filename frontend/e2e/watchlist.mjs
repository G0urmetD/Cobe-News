// Browser check (0.1.38): "Beobachtete CVEs" as a watchlist (/watch).
// - Head: the tip line with the star; the CVE field, "Beobachten" and (?) – a popover that opens and closes (Escape too);
//   an invalid id, the limit of 500 and an id watched already answer; at 375 px the controls wrap below the title.
// - The notification line per reason: Teams off (answer of the list mocked – switching Teams off would deactivate
//   accounts and reload groups of the shared seed), no way allowed (switched off by the admin for a moment), no way on
//   with and without the personal delivery available; no line while a way is on.
// - Tiles (2×2 at 375 px): a click sets the filter (aria-pressed), the KEV tile red above 0, the counts as the API says.
// - Filter chips (arrow keys, counts), the sort a popper select; filter and sort in the address, kept over a reload.
// - Rows: severity, KEV (tooltip with ransomware), EPSS bar and tooltip, fix; a CVE no source knows; the copy button
//   does not open the row; a table from 1024 px, cards below. Opening by click and by Enter/Space on the chevron
//   (aria-expanded); the timeline with fix, KEV, EPSS, withdrawn and "Beobachtet" at the bottom – nothing from before
//   the person's own watch; another person's CVE: its events 404. "Meldungen (n)" → /?q=CVE with n as the API says;
//   "Advisory öffnen" only with an advisory (http(s), rel noopener); "Nicht mehr beobachten" → "Rückgängig" re-adds it.
// - "Neu": none on the first visit; after a new event the next visit marks it (kept while the list comes again during
//   that visit), the visit after that not any more.
// - /watch?cve=X opens that row in view – a filter that would hide it goes back to "Alle".
// - Empty: the invitation with the field.
// - Stars on a news card with one CVE, at a finding line of the overview and in a finding: a click opens neither card
//   nor drawer; tooltip and aria-label; the toast's "Zur Liste" opens /watch?cve=….
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll.
//
// Only against a throwaway instance (own database and DATA_DIR, never the live one) – docs/BETRIEB.md, "Entwicklung / Tests".
// It expects (cn-e2e seed): a reader `watcher` in a team with e-mail on, watching CVE-2026-1002 (critical, KEV with
// ransomware, EPSS 99.5th percentile, fixed; four watch events and one from before the watch), CVE-2026-1001 (a fix, a
// story), CVE-2026-1005 (known, no fix), CVE-2025-99991 (no source); `reader` watching CVE-2026-1003; `limited` at
// 500 (0.1.42; 200 before); `reader3` in a team, nothing watched, no way on; `reader2` in no team, nothing watched.
// Env: BASE_URL, CREDS (JSON {user, password, totp, watcher, watcher_password, limited, limited_password, reader2,
// reader2_password, reader3, reader3_password} – never printed), PLAYWRIGHT, SHOTS (optional), DB_CMD (optional: a
// command that runs SQL from stdin in the throwaway database, e.g. `docker exec -i <container> psql -U postgres -d
// <db> -q` – for "Neu": the watcher's last visit reset and one new event; without it those checks are skipped).
// Uses the installed Google Chrome (channel "chrome") – never downloads a browser. Notifications stubbed, never granted.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { execSync } from "node:child_process"
import crypto from "node:crypto"
import fs from "node:fs"

const BASE = (process.env.BASE_URL || "http://127.0.0.1:5270").replace(/\/$/, "")
const creds = JSON.parse(fs.readFileSync(process.env.CREDS || "", "utf8"))
const SHOTS = process.env.SHOTS || ""
const DB_CMD = process.env.DB_CMD || ""
const { chromium, request } = await import(process.env.PLAYWRIGHT || "playwright-core")

const KEV = "CVE-2026-1002"
const FIXED = "CVE-2026-1001"
const NOFIX = "CVE-2026-1005"
const UNKNOWN = "CVE-2025-99991"
const OTHERS = "CVE-2026-1003" // watched by another person
const FINDING = "CVE-2026-1004" // a finding of panos nobody here watches
const L = {
  de: {
    title: "Beobachtete CVEs",
    tip: ["Tipp: In jeder Meldung und jedem Befund mit", "merken."],
    add: "CVE hinzufügen",
    watchButton: "Beobachten",
    what: "Wann kommt eine Meldung?",
    invalid: "Keine CVE-ID – Format CVE-JJJJ-NNNN.",
    full: "Du beobachtest schon 500 CVEs – entferne zuerst eine.",
    already: (c) => `${c} beobachtest du schon.`,
    notifyOff: "Benachrichtigung aus – die Liste ist eine Merkliste.",
    reason: {
      teams_off: "Persönliche Wege gibt ein Admin unter Einstellungen → Teams frei.",
      no_way_allowed: "Ein Admin hat noch keinen persönlichen Weg freigegeben.",
      firstCve: "Sobald du eine CVE beobachtest, kannst du sie unter „Hersteller-News meiner Produkte“ einschalten.",
    },
    toWays: "Wege einschalten",
    tiles: "Übersicht",
    firstVisit: "erster Besuch",
    filter: { all: "Alle", kev: "KEV", nofix: "Ohne Fix", epss: "EPSS hoch", new: "Neu" },
    filterLabel: "Filter",
    sortLabel: "Sortieren",
    sortSeverity: "Schwere",
    critical: "Kritisch",
    noSource: "Noch keine Quelle kennt sie",
    kevSince: "In KEV seit",
    ransomware: "Laut CISA in Ransomware-Kampagnen genutzt.",
    copy: "Kopieren",
    toggle: (c) => `Verlauf zu ${c}`,
    tl: {
      fix: "Fix-Version erschienen",
      kev: "aufgenommen – aktiv ausgenutzt",
      epss: "im 99. Perzentil",
      withdrawn: "Advisory zurückgezogen: NVD-WITHDRAWN-E2E",
      since: "Beobachtet",
    },
    stories: (n) => (n === 1 ? "1 Meldung" : `${n} Meldungen`),
    advisory: "Advisory öffnen",
    unwatchButton: "Nicht mehr beobachten",
    undo: "Rückgängig",
    newPill: "Neu",
    emptyTitle: "Merk dir CVEs direkt in Meldungen und Befunden",
    watch: (c) => `${c} beobachten`,
    unwatch: (c) => `${c} nicht mehr beobachten`,
    toList: "Zur Liste",
  },
  en: {
    title: "Watched CVEs",
    tip: ["Tip: mark CVEs with", "in any story and any finding."],
    add: "Add a CVE",
    watchButton: "Watch",
    what: "When does a notice come?",
    invalid: "Not a CVE id – format CVE-YYYY-NNNN.",
    full: "You watch 500 CVEs already – remove one first.",
    already: (c) => `You watch ${c} already.`,
    notifyOff: "Notifications off – the list is a reminder list.",
    reason: {
      teams_off: "An admin allows personal ways under Settings → Teams.",
      no_way_allowed: "An admin has not allowed a personal way yet.",
      firstCve: "As soon as you watch a CVE, you can switch them on under “Vendor news of my products”.",
    },
    toWays: "Switch on a way",
    tiles: "Summary",
    firstVisit: "first visit",
    filter: { all: "All", kev: "KEV", nofix: "No fix", epss: "EPSS high", new: "New" },
    filterLabel: "Filter",
    sortLabel: "Sort",
    sortSeverity: "Severity",
    critical: "Critical",
    noSource: "No source knows it yet",
    kevSince: "In KEV since",
    ransomware: "Used in ransomware campaigns according to CISA.",
    copy: "Copy",
    toggle: (c) => `History of ${c}`,
    tl: { fix: "Fixed version appeared", kev: "– actively exploited", epss: "in percentile 99", withdrawn: "Advisory withdrawn: NVD-WITHDRAWN-E2E", since: "Watched" },
    stories: (n) => (n === 1 ? "1 story" : `${n} stories`),
    advisory: "Open advisory",
    unwatchButton: "Stop watching",
    undo: "Undo",
    newPill: "New",
    emptyTitle: "Keep CVEs right where you read them: in stories and findings",
    watch: (c) => `Watch ${c}`,
    unwatch: (c) => `Stop watching ${c}`,
    toList: "To the list",
  },
}

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

const sql = (text) => execSync(DB_CMD, { input: text, stdio: ["pipe", "ignore", "inherit"], shell: "/bin/sh" })

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

const csrfOf = async (ctx) => (await ctx.cookies(BASE)).find((c) => c.name.endsWith("cobe_news_csrf"))?.value ?? ""

async function signIn(req, cookies, user, password, code) {
  await req.get(`${BASE}/api/auth/config`)
  const h = { "X-CSRF-Token": await cookies() }
  const r = await req.post(`${BASE}/api/auth/login`, { data: { username: user, password }, headers: h })
  if (!r.ok()) throw new Error(`login: ${r.status()}`)
  if ((await r.json()).next !== "mfa") return
  const left = 30000 - (Date.now() % 30000)
  if (left < 4000) await new Promise((ok) => setTimeout(ok, left + 500))
  const m = await req.post(`${BASE}/api/auth/mfa`, { data: { code: totp(code) }, headers: h })
  if (!m.ok()) throw new Error(`mfa: ${m.status()}`)
}

async function settle(page) {
  await page.waitForLoadState("networkidle").catch(() => undefined)
  await page.waitForTimeout(350)
}

async function scrollCheck(page, tag, name, shot) {
  const s = await page.evaluate(() => {
    const wide = (el) => !!el && el.scrollWidth > el.clientWidth + 1
    const d = document.documentElement
    return { ok: !wide(d) && !wide(document.querySelector("[data-slot=sheet-content]")), page: wide(d) }
  })
  check(`${tag} ${name}: no horizontal scroll`, s.ok, s.ok ? undefined : s)
  if (SHOTS && shot) await page.screenshot({ path: `${SHOTS}/${shot}.png` })
}

async function tooltipOf(page, el) {
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

async function toastAfter(page, before) {
  const toasts = page.locator("[data-sonner-toast]")
  for (let i = 0; i < 40 && (await toasts.count()) <= before; i++) await page.waitForTimeout(150)
  return (await toasts.count()) > before ? toasts.last() : null
}

/** Toasts gone (on a phone they lie over the lower part of the page). */
async function dismissToasts(page) {
  for (let i = 0; i < 20 && (await page.locator("[data-sonner-toast]").count()); i++) {
    const close = page.locator("[data-sonner-toast] [data-close-button]").first()
    if (await close.count()) await close.click({ timeout: 1000 }).catch(() => {})
    else await page.waitForTimeout(500)
  }
}

async function context(browser, lang, width, theme, user, password) {
  const ctx = await browser.newContext({ serviceWorkers: "block", locale: lang === "de" ? "de-DE" : "en-GB", viewport: { width, height: 860 }, colorScheme: theme })
  await stub(ctx, lang, theme)
  const page = await ctx.newPage()
  const errors = []
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`))
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`)
  })
  await signIn(ctx.request, () => csrfOf(ctx), user, password, "")
  return { ctx, page, errors }
}

const json = async (ctx, path) => (await ctx.request.get(`${BASE}${path}`)).json()
const ids = async (ctx) => (await json(ctx, "/api/me/cve-watch/ids")).cves
const row = (page, cve) => page.locator(`#watch-${cve}`)
const chevron = (page, T, cve) => page.getByRole("button", { name: T.toggle(cve), exact: true })
const expanded = async (page, T, cve) => (await chevron(page, T, cve).getAttribute("aria-expanded")) === "true"
async function openRow(page, T, cve) {
  if (!(await expanded(page, T, cve))) await chevron(page, T, cve).click()
  await page.waitForTimeout(300)
}

/** The watcher's list as the seed made it (a run broken off half-way may have left a star on or off). */
async function seedList(ctx) {
  const h = { "X-CSRF-Token": await csrfOf(ctx) }
  const have = await ids(ctx)
  for (const c of [FINDING, OTHERS]) if (have.includes(c)) await ctx.request.delete(`${BASE}/api/me/cve-watch/${c}`, { headers: h })
  for (const c of [KEV, FIXED, NOFIX, UNKNOWN]) if (!have.includes(c)) await ctx.request.post(`${BASE}/api/me/cve-watch`, { data: { cve: c }, headers: h })
}

/** The counts the page must show – from the API's list (the "new" one is checked on its own). */
function counts(list) {
  const known = (w) => w.known
  return {
    all: list.items.length,
    kev: list.items.filter((w) => w.kev).length,
    nofix: list.items.filter((w) => known(w) && w.fixed_count === 0).length,
    epss: list.items.filter((w) => (w.epss?.percentile ?? 0) >= 0.9).length,
  }
}

// ---------------------------------------------------------------- "Neu" – once, before anything else changes the visit

async function newMarks(browser, T) {
  const tag = "de 1280px light new"
  const { ctx, page, errors } = await context(browser, "de", 1280, "light", creds.watcher, creds.watcher_password)
  await seedList(ctx)
  sql(`UPDATE person_notify SET watch_seen_at = NULL WHERE user_id = (SELECT id FROM users WHERE username = '${creds.watcher}');`)
  await page.goto(`${BASE}/watch`)
  await settle(page)
  const first = await page.getByText(T.newPill, { exact: true }).count()
  const tiles = await page.getByRole("region", { name: T.tiles }).innerText()
  check(`${tag}: the first visit marks nothing ("${T.firstVisit}")`, first === 0 && tiles.includes(T.firstVisit), { first })
  // something happens to CVE-2026-1001 after this visit – at this machine's time (the app's clock), not the database
  // server's: a container's clock can lag behind after the host slept
  const key = `watch:${FIXED}:fix:e2e-new-${crypto.randomBytes(3).toString("hex")}`
  const data = JSON.stringify({ cve: FIXED, what: "fix", title: "", fixed: ["PAN-OS 11.2: 11.2.4-h99"], more: 0, by: [] })
  await page.waitForTimeout(1500)
  sql(
    `INSERT INTO vendor_events (id, key, kind, product, severity, data, baseline, scope, created_at) VALUES (gen_random_uuid(), '${key}', 'watch', '', 'high', '${data}'::jsonb, false, 'watch:${FIXED}', '${new Date().toISOString()}');`,
  )
  await page.waitForTimeout(1500)
  await page.reload()
  await settle(page)
  const pill = row(page, FIXED).getByText(T.newPill, { exact: true })
  const tint = /bg-primary/.test((await row(page, FIXED).getAttribute("class")) ?? "")
  const second = (await pill.count()) === 1
  // the list comes again during this visit (a CVE added through the field): the marks stay
  await page.getByLabel(T.add, { exact: true }).fill(OTHERS)
  await page.getByRole("button", { name: T.watchButton, exact: true }).click()
  await page.waitForTimeout(1200)
  const kept = (await pill.count()) === 1
  check(`${tag}: after a new event the next visit marks it ("${T.newPill}" and the tint), kept when the list comes again`, second && tint && kept, { second, tint, kept })
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/de-1280-light-watch_new.png` })
  // "Nicht mehr beobachten" → "Rückgängig"
  await openRow(page, T, OTHERS)
  const before = await page.locator("[data-sonner-toast]").count()
  await row(page, OTHERS).getByRole("button", { name: T.unwatchButton, exact: true }).click()
  const toast = await toastAfter(page, before)
  const gone = !(await ids(ctx)).includes(OTHERS)
  if (toast) await toast.getByRole("button", { name: T.undo, exact: true }).click()
  await page.waitForTimeout(1000)
  const back = (await ids(ctx)).includes(OTHERS)
  check(`${tag}: "${T.unwatchButton}" → a toast with "${T.undo}" that watches it again`, gone && !!toast && back, { gone, toast: !!toast, back })
  await ctx.request.delete(`${BASE}/api/me/cve-watch/${OTHERS}`, { headers: { "X-CSRF-Token": await csrfOf(ctx) } })
  await page.reload()
  await settle(page)
  check(`${tag}: the visit after that marks nothing any more`, (await page.getByText(T.newPill, { exact: true }).count()) === 0)
  check(`${tag}: no page or console errors`, errors.length === 0, errors.slice(0, 3))
  await ctx.close()
}

// ---------------------------------------------------------------- the watcher's list

async function watcher(browser, lang, width, theme, admin) {
  const T = L[lang]
  const tag = `${lang} ${width}px ${theme}`
  const wide = width === 1280 && theme === "light"
  const shot = (n) => `${lang}-${width}-${theme}-${n}`
  const { ctx, page, errors } = await context(browser, lang, width, theme, creds.watcher, creds.watcher_password)
  const main = page.locator("main")
  await seedList(ctx)
  await page.goto(`${BASE}/watch`)
  await settle(page)

  // head
  const lead = main.locator("h1 + p")
  const tip = await lead.innerText()
  const star = await lead.locator("svg").count()
  const input = page.getByLabel(T.add, { exact: true })
  const button = page.getByRole("button", { name: T.watchButton, exact: true })
  const help = page.getByRole("button", { name: T.what, exact: true })
  check(
    `${tag} head: the tip line with the star; field, "${T.watchButton}", (?)`,
    tip.includes(T.tip[0]) && tip.includes(T.tip[1]) && star >= 1 && (await input.isVisible()) && (await button.isVisible()) && (await help.isVisible()),
  )
  const pop = page.locator("[data-slot=popover-content]")
  const tips = page.locator("[data-slot=tooltip-content]")
  await help.click()
  await page.waitForTimeout(400)
  const opened = await pop.isVisible().catch(() => false)
  const popText = opened ? await pop.innerText() : ""
  const tipOnOpen = await tips.count() // a tooltip that opened by itself (the focus landed on a term inside)
  await page.keyboard.press("Escape")
  await page.waitForTimeout(400)
  const escaped = !(await pop.isVisible().catch(() => false))
  if (!escaped) {
    await page.keyboard.press("Escape")
    await page.waitForTimeout(400)
  }
  await help.click()
  await page.waitForTimeout(300)
  const reopened = await pop.isVisible().catch(() => false)
  await help.click()
  await page.waitForTimeout(400)
  const toggled = !(await pop.isVisible().catch(() => false))
  check(`${tag} (?): opens "${T.what}", a second click closes it`, opened && popText.includes(T.what) && reopened && toggled, { opened, reopened, toggled })
  check(`${tag} (?): one Escape closes it (no tooltip opened by itself in front of it)`, escaped && tipOnOpen === 0, { escaped, tipOnOpen })
  if (width < 768) {
    const h1 = await main.locator("h1").boundingBox()
    const field = await input.boundingBox()
    check(`${tag} head (phone): the controls wrap below the title`, !!h1 && !!field && field.y >= h1.y + h1.height - 1, { h1: h1?.y, field: field?.y })
  }
  await input.fill("CVE-12")
  const alert = page.getByText(T.invalid, { exact: true })
  check(
    `${tag} an invalid id: the message (role alert), aria-invalid, the button off`,
    (await alert.isVisible()) && (await alert.getAttribute("role")) === "alert" && (await input.getAttribute("aria-invalid")) === "true" && (await button.isDisabled()),
  )
  await input.fill(KEV)
  const before = await page.locator("[data-sonner-toast]").count()
  await button.click()
  const t1 = await toastAfter(page, before)
  check(`${tag} an id watched already: "${T.already(KEV)}"`, !!t1 && (await t1.innerText()).includes(T.already(KEV)))
  await page.keyboard.press("Escape")

  // notification line: a way is on – none
  check(`${tag} a way is on: no notification line`, !(await main.innerText()).includes(T.notifyOff))

  // tiles
  const list = await json(ctx, "/api/me/cve-watch")
  const want = counts(list)
  const tiles = page.getByRole("region", { name: T.tiles }).getByRole("button")
  const values = await tiles.evaluateAll((els) => els.map((e) => Number(e.querySelector(".text-2xl")?.textContent)))
  const kevColor = await tiles.nth(1).evaluate((e) => e.querySelector(".text-2xl")?.getAttribute("style") ?? "")
  const boxes = await tiles.evaluateAll((els) => els.map((e) => Math.round(e.getBoundingClientRect().top)))
  const grid = width < 768 ? boxes[0] === boxes[1] && boxes[2] === boxes[3] && boxes[2] > boxes[0] : new Set(boxes).size === 1
  check(
    `${tag} tiles: counts as the API says, KEV red above 0, ${width < 768 ? "2×2" : "one row"}`,
    values[0] === want.all && values[1] === want.kev && values[2] === want.nofix && (want.kev === 0 || /--sev-critical/.test(kevColor)) && grid,
    {
      values,
      want,
      boxes,
    },
  )
  await tiles.nth(1).click()
  await settle(page)
  check(
    `${tag} the KEV tile sets the filter (aria-pressed, ?filter=kev, ${want.kev} row)`,
    (await tiles.nth(1).getAttribute("aria-pressed")) === "true" &&
      new URL(page.url()).searchParams.get("filter") === "kev" &&
      (await main.locator("li[id^=watch-]").count()) === want.kev,
  )

  // chips: counts, arrow keys; the sort; both in the address over a reload
  const chips = page.getByRole("radiogroup", { name: T.filterLabel }).getByRole("radio")
  const chipText = (await chips.allInnerTexts()).map((x) => x.replace(/\s+/g, " ").trim())
  const chipsOk = [`${T.filter.all} ${want.all}`, `${T.filter.kev} ${want.kev}`, `${T.filter.nofix} ${want.nofix}`, `${T.filter.epss} ${want.epss}`].every((x) =>
    chipText.includes(x),
  )
  await chips.filter({ hasText: T.filter.kev }).focus()
  await page.waitForTimeout(200)
  await page.keyboard.press("ArrowRight")
  await page.waitForTimeout(200)
  await page.keyboard.press("Space")
  await settle(page)
  const viaKeys = new URL(page.url()).searchParams.get("filter")
  check(`${tag} chips: counts; ArrowRight + Space choose "${T.filter.nofix}"`, chipsOk && viaKeys === "nofix", { chipText, viaKeys })
  const sort = page.getByRole("combobox", { name: T.sortLabel })
  await sort.click()
  const popper = await page.locator("[data-radix-popper-content-wrapper] [role=listbox]").isVisible()
  await page.getByRole("option", { name: T.sortSeverity, exact: true }).click()
  await settle(page)
  await page.reload()
  await settle(page)
  const u = new URL(page.url())
  const kept =
    u.searchParams.get("filter") === "nofix" &&
    u.searchParams.get("sort") === "severity" &&
    (await chips.filter({ hasText: T.filter.nofix }).getAttribute("aria-checked")) === "true" &&
    (await sort.innerText()).includes(T.sortSeverity)
  check(`${tag} sort: a popper select; filter and sort in the address, kept over a reload`, popper && kept, { popper, search: u.search })

  // rows
  await page.goto(`${BASE}/watch`)
  await settle(page)
  const kevRow = row(page, KEV)
  const kevText = await kevRow.innerText()
  const epssBar = await kevRow.locator("[title*='EPSS']").count()
  const epssTitle =
    (await kevRow
      .locator("[title*='EPSS']")
      .first()
      .getAttribute("title")
      .catch(() => "")) ?? ""
  check(
    `${tag} row ${KEV}: severity, KEV, EPSS bar with its tooltip, fix`,
    kevText.includes(T.critical) && kevText.includes("KEV ·") && epssBar === 1 && epssTitle.includes(KEV) && kevText.includes("11.2.4-h30"),
    { epssTitle },
  )
  const kevTip = await tooltipOf(page, kevRow.locator("span[tabindex]").filter({ hasText: "KEV ·" }).first())
  check(`${tag} KEV tooltip: since when, ransomware`, kevTip.includes(T.kevSince) && kevTip.includes(T.ransomware), { kevTip })
  check(`${tag} row ${UNKNOWN}: "${T.noSource}"`, (await row(page, UNKNOWN).innerText()).includes(T.noSource))
  await kevRow.getByRole("button", { name: T.copy, exact: true }).first().click()
  await page.waitForTimeout(300)
  check(`${tag} the copy button does not open the row`, !(await expanded(page, T, KEV)))
  const head = main.getByText(T.tiles).first() // (the tiles exist in both layouts)
  void head
  // the column header: the first row of the list's frame (0.1.46: above the product groups as well)
  const header = await page.evaluate(() => {
    const ul = document.querySelector("main ul[aria-label]")
    const h = ul?.closest(".rounded-xl")?.firstElementChild
    return h && !h.contains(ul) ? getComputedStyle(h).display : "none"
  })
  check(`${tag} layout: ${width >= 1024 ? "a table with its header" : "cards (no header)"}`, width >= 1024 ? header === "grid" : header === "none", { header })

  // open / close: click, Enter, Space on the chevron
  await kevRow.locator("p").first().click()
  const byClick = await expanded(page, T, KEV)
  await chevron(page, T, KEV).click()
  const closed = !(await expanded(page, T, KEV))
  await chevron(page, T, KEV).focus()
  await page.keyboard.press("Enter")
  const byEnter = await expanded(page, T, KEV)
  await page.keyboard.press("Space")
  const bySpace = !(await expanded(page, T, KEV))
  check(`${tag} a row opens by click and by Enter/Space on the chevron (aria-expanded)`, byClick && closed && byEnter && bySpace, { byClick, closed, byEnter, bySpace })
  await openRow(page, T, KEV)
  await kevRow
    .locator("ol li")
    .last()
    .waitFor({ timeout: 5000 })
    .catch(() => {})
  const entries = await kevRow.locator("ol > li").allInnerTexts()
  const all = entries.join("\n")
  const lastLi = entries.at(-1) ?? ""
  check(
    `${tag} timeline: fix, KEV, EPSS, withdrawn, "${T.tl.since}" at the bottom – nothing from before the watch`,
    all.includes(T.tl.fix) &&
      all.includes(T.tl.kev) &&
      all.includes(T.tl.epss) &&
      all.includes(T.tl.withdrawn) &&
      lastLi.startsWith(T.tl.since) &&
      !all.includes("SA-OLD-BEFORE-WATCH"),
    { entries: entries.length },
  )
  await scrollCheck(page, tag, "opened row", shot("watch_open"))
  const other = await ctx.request.get(`${BASE}/api/me/cve-watch/${OTHERS}/events`)
  check(`${tag} another person's CVE: its events 404`, other.status() === 404, { status: other.status() })

  // actions
  await openRow(page, T, FIXED)
  const ev = await json(ctx, `/api/me/cve-watch/${FIXED}/events`)
  const stories = row(page, FIXED).getByRole("link", { name: T.stories(ev.stories), exact: true })
  const storiesOk = (await stories.count()) === 1 && (await stories.getAttribute("href")) === `/?q=${FIXED}`
  const adv = row(page, FIXED).getByRole("link", { name: T.advisory, exact: true })
  const advOk = (await adv.count()) === 1 && /^https?:\/\//.test((await adv.getAttribute("href")) ?? "") && /noopener/.test((await adv.getAttribute("rel")) ?? "")
  await openRow(page, T, UNKNOWN)
  const noAdv = (await row(page, UNKNOWN).getByRole("link", { name: T.advisory, exact: true }).count()) === 0
  check(`${tag} actions: "${T.stories(ev.stories)}" → /?q=${FIXED}; "${T.advisory}" http(s) with noopener – not for an unknown CVE`, storiesOk && advOk && noAdv, {
    storiesOk,
    advOk,
    noAdv,
  })
  if (wide) {
    await stories.click()
    await settle(page)
    const u2 = new URL(page.url())
    check(`${lang} "${T.stories(ev.stories)}" opens the stories at q=${FIXED}`, u2.pathname === "/" && u2.searchParams.get("q") === FIXED)
  }

  // deep link: a filter that would hide it goes back to "Alle"
  await page.goto(`${BASE}/watch?filter=kev&cve=${FIXED}`)
  await settle(page)
  const box = await row(page, FIXED).boundingBox()
  const inView = !!box && box.y >= 0 && box.y < 860
  check(
    `${tag} /watch?filter=kev&cve=${FIXED}: the filter back to "${T.filter.all}", the row open and in view`,
    !new URL(page.url()).searchParams.get("filter") && (await expanded(page, T, FIXED)) && inView,
    {
      search: new URL(page.url()).search,
      inView,
    },
  )
  await scrollCheck(page, tag, "deep link", shot("watch_deeplink"))

  // notification lines that need a state of their own (wide light runs): no way allowed (for a moment), Teams off (mocked)
  if (wide && admin) {
    const st = await (await admin.get(`${BASE}/api/admin/teams/settings`)).json()
    const put = async (ways) =>
      admin.put(`${BASE}/api/admin/teams/settings`, {
        data: { enabled: st.enabled, welcome_mail: st.welcome_mail, ...ways, rev: (await (await admin.get(`${BASE}/api/admin/teams/settings`)).json()).rev },
        headers: { "X-CSRF-Token": admin.csrf },
      })
    await put({ personal_email: false, personal_desktop: false, personal_teams: false })
    await page.goto(`${BASE}/watch`)
    await settle(page)
    const off = await main.innerText()
    await put({ personal_email: st.personal_email, personal_desktop: st.personal_desktop, personal_teams: st.personal_teams })
    check(`${lang} no way allowed: the line "${T.notifyOff}" – ${T.reason.no_way_allowed}`, off.includes(T.notifyOff) && off.includes(T.reason.no_way_allowed))
    await page.route("**/api/me/cve-watch", async (route) => {
      if (route.request().method() !== "GET") return route.fallback()
      const r = await route.fetch()
      const body = await r.json()
      body.notify = { ...body.notify, reason: "teams_off" }
      return route.fulfill({ response: r, json: body })
    })
    await page.goto(`${BASE}/watch`)
    await settle(page)
    const tOff = await main.innerText()
    await page.unroute("**/api/me/cve-watch")
    check(`${lang} Teams off (the list's answer mocked): the line – ${T.reason.teams_off}`, tOff.includes(T.notifyOff) && tOff.includes(T.reason.teams_off))
  }

  await dismissToasts(page)
  // stars: a news card with one CVE, a finding line of the overview, a finding in the drawer
  await page.goto(`${BASE}/`)
  await settle(page)
  const cardStar = main.getByRole("button", { name: new RegExp(`^(${T.watch(FIXED)}|${T.unwatch(FIXED)})$`) }).first()
  // one list of every story (0.1.41) – the seed's story may be further down: the next pages load on scrolling
  for (let i = 0; i < 8 && !(await cardStar.count()); i++) {
    await main.locator("article").last().scrollIntoViewIfNeeded()
    await settle(page)
  }
  await cardStar.scrollIntoViewIfNeeded()
  const label0 = (await cardStar.count()) ? await cardStar.getAttribute("aria-label") : null
  const tipStar = label0 ? await tooltipOf(page, cardStar) : ""
  await cardStar.click()
  await page.waitForTimeout(700)
  const noStory = !new URL(page.url()).searchParams.get("story") && (await page.locator("[data-slot=sheet-content]").count()) === 0
  const off = (await cardStar.getAttribute("aria-pressed")) === "false" && !(await ids(ctx)).includes(FIXED)
  await dismissToasts(page)
  const before2 = await page.locator("[data-sonner-toast]").count()
  await cardStar.click()
  const t2 = await toastAfter(page, before2)
  const on = (await cardStar.getAttribute("aria-pressed")) === "true" && (await ids(ctx)).includes(FIXED)
  check(
    `${tag} star on a news card: no story opens, aria-pressed and the API follow, tooltip = aria-label`,
    label0 === T.unwatch(FIXED) && tipStar === label0 && noStory && off && on,
    {
      label0,
      tipStar,
      noStory,
      off,
      on,
    },
  )
  if (t2 && wide) {
    await t2.getByRole("button", { name: T.toList, exact: true }).click()
    await settle(page)
    const u3 = new URL(page.url())
    check(
      `${lang} the toast's "${T.toList}" opens /watch?cve=${FIXED} with its row open`,
      u3.pathname === "/watch" && u3.searchParams.get("cve") === FIXED && (await expanded(page, T, FIXED)),
    )
  }
  await page.goto(`${BASE}/vendor`)
  await settle(page)
  // a star at a finding line of a card: no drawer opens, the CVE is watched (and back). Which findings a card lists depends
  // on the seed – a person who watches none of them (reader2) toggles the first one, the watcher's list stays as it is
  {
    const o = await context(browser, lang, width, theme, creds.reader2, creds.reader2_password)
    await o.page.goto(`${BASE}/vendor?status=all`)
    await settle(o.page)
    const first = o.page.locator("main article button[aria-pressed=false]").first()
    if (await first.count()) {
      const cve = ((await first.getAttribute("aria-label")) ?? "").match(/CVE-\d{4}-\d+/)?.[0]
      // that star – by its CVE (its label changes when pressed)
      const lineStar = o.page
        .locator("main article")
        .getByRole("button", { name: new RegExp(`^(${T.watch(cve)}|${T.unwatch(cve)})$`) })
        .first()
      await lineStar.click()
      await o.page.waitForTimeout(700)
      const noDrawer = (await o.page.locator("[data-slot=sheet-content]").count()) === 0 && !new URL(o.page.url()).searchParams.get("product")
      const pressed = (await lineStar.getAttribute("aria-pressed")) === "true" && (await ids(o.ctx)).includes(cve)
      await dismissToasts(o.page)
      await lineStar.click()
      await o.page.waitForTimeout(700)
      check(`${tag} star at a finding line of the overview (${cve}): no drawer, watched (and back)`, noDrawer && pressed && !(await ids(o.ctx)).includes(cve), {
        noDrawer,
        pressed,
      })
    } else check(`${tag} star at a finding line of the overview: one shown`, false)
    await o.ctx.close()
  }
  await page.goto(`${BASE}/vendor?product=panos`)
  await settle(page)
  const sheet = page.locator("[data-slot=sheet-content]")
  const fStar = sheet.getByRole("button", { name: new RegExp(`^(${T.watch(FINDING)}|${T.unwatch(FINDING)})$`) }).first()
  await fStar.click()
  await page.waitForTimeout(700)
  const stays = (await sheet.count()) === 1 && (await fStar.getAttribute("aria-pressed")) === "true" && (await ids(ctx)).includes(FINDING)
  await dismissToasts(page)
  await fStar.click()
  await page.waitForTimeout(700)
  check(`${tag} star in a finding: watched, the drawer stays (and back)`, stays && !(await ids(ctx)).includes(FINDING), { stays })
  check(`${tag} watcher: no page or console errors`, errors.length === 0, errors.slice(0, 3))
  await ctx.close()
}

// ---------------------------------------------------------------- empty, without ways, at the limit

async function others(browser, lang, width, theme) {
  const T = L[lang]
  const tag = `${lang} ${width}px ${theme}`
  const wide = width === 1280 && theme === "light"
  // in a team, nothing watched, no way on: the line with the link; the invitation
  const a = await context(browser, lang, width, theme, creds.reader3, creds.reader3_password)
  for (const c of await ids(a.ctx)) await a.ctx.request.delete(`${BASE}/api/me/cve-watch/${c}`, { headers: { "X-CSRF-Token": await csrfOf(a.ctx) } })
  await a.page.goto(`${BASE}/watch`)
  await settle(a.page)
  const text = await a.page.locator("main").innerText()
  check(
    `${tag} empty (in a team, no way on): the invitation with the field; the line with "${T.toWays}"`,
    text.includes(T.emptyTitle) &&
      (await a.page.getByLabel(T.add, { exact: true }).isVisible()) &&
      text.includes(T.notifyOff) &&
      (await a.page.getByRole("link", { name: T.toWays, exact: true }).count()) === 1,
  )
  await scrollCheck(a.page, tag, "empty", `${lang}-${width}-${theme}-watch_empty`)
  check(`${tag} empty: no page or console errors`, a.errors.length === 0, a.errors.slice(0, 3))
  await a.ctx.close()
  // in no team, nothing watched: the ways open only with a CVE – no link, the hint
  const b = await context(browser, lang, width, theme, creds.reader2, creds.reader2_password)
  for (const c of await ids(b.ctx)) await b.ctx.request.delete(`${BASE}/api/me/cve-watch/${c}`, { headers: { "X-CSRF-Token": await csrfOf(b.ctx) } })
  await b.page.goto(`${BASE}/watch`)
  await settle(b.page)
  const t2 = await b.page.locator("main").innerText()
  check(
    `${tag} no way on, personal delivery not available: the line with "${T.reason.firstCve.slice(0, 28)}…", no link`,
    t2.includes(T.notifyOff) && t2.includes(T.reason.firstCve) && (await b.page.getByRole("link", { name: T.toWays, exact: true }).count()) === 0,
  )
  await b.ctx.close()
  // at the limit
  if (wide) {
    const c = await context(browser, lang, width, theme, creds.limited, creds.limited_password)
    await c.page.goto(`${BASE}/watch`)
    await settle(c.page)
    const r = await c.ctx.request.post(`${BASE}/api/me/cve-watch`, { data: { cve: "CVE-2026-9999" }, headers: { "X-CSRF-Token": await csrfOf(c.ctx) } })
    const code = (await r.json().catch(() => ({})))?.detail?.code
    check(
      `${lang} at the limit of 500: "${T.full}", the field off; the API 409 watch_limit`,
      (await c.page.getByText(T.full, { exact: true }).isVisible()) &&
        (await c.page.getByLabel(T.add, { exact: true }).isDisabled()) &&
        r.status() === 409 &&
        code === "watch_limit",
      { status: r.status(), code },
    )
    await c.ctx.close()
  }
}

const browser = await chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
let admin = null
try {
  admin = await request.newContext()
  await signIn(admin, async () => (await admin.storageState()).cookies.find((c) => c.name.endsWith("cobe_news_csrf"))?.value ?? "", creds.user, creds.password, creds.totp)
  admin.csrf = (await admin.storageState()).cookies.find((c) => c.name.endsWith("cobe_news_csrf"))?.value ?? ""
  if (DB_CMD) await newMarks(browser, L.de)
  else console.log('note: DB_CMD not set – the checks of "Neu" and of undo are skipped')
  for (const lang of ["de", "en"])
    for (const width of [1280, 375])
      for (const theme of ["light", "dark"]) {
        await watcher(browser, lang, width, theme, admin)
        await others(browser, lang, width, theme)
      }
} finally {
  await admin?.dispose()
  await browser.close()
}
const failed = results.filter((x) => !x).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed ? 1 : 0)
