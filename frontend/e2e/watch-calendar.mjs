// Browser check (0.1.34): "CVE beobachten" and the calendar feed.
// a) The star next to a CVE – at a finding (Vendor News drawer) and in a story – watches it and stops again (aria-pressed,
//    GET /api/me/cve-watch/ids agrees). "Beobachtete CVEs" (own page /watch, in the sidebar – on a phone through the
//    sidebar menu –, one head: title, the tip line with the star, help link): add by input (an invalid
//    id is refused with a message, the button stays off, the API answers 422 invalid_cve), a CVE not known yet is listed
//    as such, remove; the hint says where the notices go – for a reader in a team the ways switched on, for a reader in
//    no team the reminder-list hint: nothing watched – no link, the hint "Sobald du eine CVE beobachtest …"; the first CVE
//    (no reload) – the link "Wege einschalten" and the sub-tab appear, the link opens "Hersteller-News meiner Produkte";
//    the last one removed – no link again.
// b) "Kalender": create the address – shown once, with a copy button (copied as shown); the feed (GET /cal/<token>.ics,
//    straight to the backend: the vite dev server proxies /api only, and the address the app shows names BASE_URL of
//    the server, never this one) is text/calendar with one VEVENT per version entered with a known end of support,
//    VALARMs, no CVE id, Cache-Control no-store and Referrer-Policy no-referrer; "Neue Adresse erzeugen": the old
//    address 404, the new 200; "Adresse löschen": 404. The token never shows up in the page's console, never printed.
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll. The full feed
// and renew/delete round once per language (the wide light run: the feed's limits allow 20 unknown tokens in 10 min).
//
// Only against a throwaway instance (own database and DATA_DIR, never the live one) – docs/BETRIEB.md, "Entwicklung / Tests".
// It expects: Teams on, e-mail and Microsoft Teams allowed as personal ways; the reader in team "Netzwerk" with e-mail
// on, following panos 11.2.4-h23 (advisory paloalto:CVE-2026-1001 and a story of it) and fortios 7.4.8 (both with a
// known end of support) and cisco-asa 9.18.4 (none); reader2 in no team, no way on, nothing watched.
// Env: BASE_URL (vite dev server), API_URL (the backend itself, e.g. http://127.0.0.1:8634 – for /cal/), CREDS (JSON
// {reader, reader_password, reader2, reader2_password} – never printed), PLAYWRIGHT (path to an existing playwright
// install …/node_modules/playwright/index.mjs), SHOTS (optional folder for screenshots; the address is masked). Uses
// the installed Google Chrome (channel "chrome") – never downloads a browser. Notifications stubbed, never granted.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import fs from "node:fs"

const BASE = (process.env.BASE_URL || "http://127.0.0.1:5240").replace(/\/$/, "")
const API = (process.env.API_URL || "").replace(/\/$/, "")
const creds = JSON.parse(fs.readFileSync(process.env.CREDS || "", "utf8"))
const SHOTS = process.env.SHOTS || ""
const { chromium } = await import(process.env.PLAYWRIGHT || "playwright-core")
if (!API) throw new Error("API_URL (the backend of the throwaway instance) is needed for /cal/")

const CVE = "CVE-2026-1001"
const UNKNOWN = "CVE-2025-99991"
const FEED = /\/cal\/[A-Za-z0-9_-]{43}\.ics$/
const L = {
  de: {
    watch: `${CVE} beobachten`,
    unwatch: (c) => `${c} nicht mehr beobachten`,
    add: "CVE hinzufügen",
    watchButton: "Beobachten",
    invalid: "Keine CVE-ID – Format CVE-JJJJ-NNNN.",
    unknown: "Noch keine Quelle kennt sie",
    notifyOff: "Benachrichtigung aus – die Liste ist eine Merkliste.",
    toggle: (c) => `Verlauf zu ${c}`,
    unwatchButton: "Nicht mehr beobachten",
    toWays: "Wege einschalten",
    waysCard: "Hersteller-News meiner Produkte",
    title: "Beobachtete CVEs",
    tip: ["Tipp: In jeder Meldung und jedem Befund mit", "merken."],
    help: "Hilfe",
    docs: "Dokumentation",
    firstCve: "Sobald du eine CVE beobachtest, kannst du sie unter „Hersteller-News meiner Produkte“ einschalten.",
    make: "Kalender-Adresse erzeugen",
    renew: "Neue Adresse erzeugen",
    del: "Adresse löschen",
    url: "Kalender-Adresse",
    once: "Nur jetzt sichtbar.",
    copy: "Kopieren",
    none: "Noch keine Kalender-Adresse",
    active: "Adresse aktiv seit",
  },
  en: {
    watch: `Watch ${CVE}`,
    unwatch: (c) => `Stop watching ${c}`,
    add: "Add a CVE",
    watchButton: "Watch",
    invalid: "Not a CVE id – format CVE-YYYY-NNNN.",
    unknown: "No source knows it yet",
    notifyOff: "Notifications off – the list is a reminder list.",
    toggle: (c) => `History of ${c}`,
    unwatchButton: "Stop watching",
    toWays: "Switch on a way",
    waysCard: "Vendor news of my products",
    title: "Watched CVEs",
    tip: ["Tip: mark CVEs with", "in any story and any finding."],
    help: "Help",
    docs: "Documentation",
    firstCve: "As soon as you watch a CVE, you can switch them on under “Vendor news of my products”.",
    make: "Create a calendar address",
    renew: "Create a new address",
    del: "Delete the address",
    url: "Calendar address",
    once: "Shown only now.",
    copy: "Copy",
    none: "No calendar address yet",
    active: "Address active since",
  },
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

const csrfOf = async (ctx) => (await ctx.cookies(BASE)).find((c) => c.name.endsWith("cobe_news_csrf"))?.value ?? ""

async function signIn(ctx, user, password) {
  await ctx.request.get(`${BASE}/api/auth/config`)
  const r = await ctx.request.post(`${BASE}/api/auth/login`, { data: { username: user, password }, headers: { "X-CSRF-Token": await csrfOf(ctx) } })
  if (!r.ok()) throw new Error(`login: ${r.status()}`)
}

async function settle(page) {
  await page.waitForLoadState("networkidle").catch(() => undefined)
  await page.waitForTimeout(350)
}

async function scrollCheck(page, tag, name) {
  const s = await page.evaluate(() => {
    const d = document.documentElement
    const wide = (el) => !!el && el.scrollWidth > el.clientWidth + 1
    return { ok: !wide(d) && !wide(document.querySelector("[data-slot=sheet-content]")), scroll: d.scrollWidth, client: d.clientWidth }
  })
  check(`${tag} ${name}: no horizontal scroll`, s.ok, s.ok ? undefined : s)
}

const json = async (ctx, path) => (await ctx.request.get(`${BASE}${path}`)).json()
/** A story by its title among all of them, read or not (0.1.41: one list – its default is the unread ones), page by page. */
async function findStory(ctx, part) {
  for (let next = "", i = 0; i < 10; i++) {
    const news = await json(ctx, `/api/news?state=all&limit=120${next ? `&before=${encodeURIComponent(next)}` : ""}`)
    const hit = news.items.find((x) => x.title.includes(part))
    if (hit || !news.next) return hit ?? null
    next = news.next
  }
  return null
}
const watched = async (ctx) => (await json(ctx, "/api/me/cve-watch/ids")).cves

async function context(browser, lang, width, theme) {
  const ctx = await browser.newContext({ serviceWorkers: "block", locale: lang === "de" ? "de-DE" : "en-GB", viewport: { width, height: 860 }, colorScheme: theme })
  await stub(ctx, lang, theme)
  const page = await ctx.newPage()
  const errors = []
  const logs = [] // every console line – the token must be in none
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`))
  page.on("console", (m) => {
    logs.push(m.text())
    if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`)
  })
  return { ctx, page, errors, logs }
}

/** A star next to the CVE: on, then off – aria-pressed and the API agree each time. */
async function starRound(ctx, page, T, tag, where) {
  const star = () =>
    page
      .locator("[data-slot=sheet-content]")
      .getByRole("button", { name: new RegExp(`^(${T.watch}|${T.unwatch(CVE)})$`) })
      .first()
  const shown = (await star().count()) > 0
  const before = shown ? await star().getAttribute("aria-pressed") : null
  if (!shown) return check(`${tag} ${where}: the star next to ${CVE}`, false)
  await star().click()
  await page.waitForTimeout(600)
  const onPressed = await star().getAttribute("aria-pressed")
  const onApi = (await watched(ctx)).includes(CVE)
  await star().click()
  await page.waitForTimeout(600)
  const offPressed = await star().getAttribute("aria-pressed")
  const offApi = (await watched(ctx)).includes(CVE)
  check(`${tag} ${where}: the star watches ${CVE} and stops again (aria-pressed, API)`, before === "false" && onPressed === "true" && onApi && offPressed === "false" && !offApi, {
    before,
    onPressed,
    onApi,
    offPressed,
    offApi,
  })
}

/** "Beobachtete CVEs": invalid input refused, add (known and unknown CVE), remove – the API agrees. */
/** 0.1.38: a row is removed from its opened details ("Nicht mehr beobachten" next to the timeline). */
async function unwatchRow(page, T, cve) {
  const toggle = page.getByRole("button", { name: T.toggle(cve), exact: true })
  if ((await toggle.getAttribute("aria-expanded")) !== "true") await toggle.click()
  await page.locator(`#watch-${cve}`).getByRole("button", { name: T.unwatchButton, exact: true }).click()
  await page.waitForTimeout(700)
}

async function watchList(ctx, page, T, tag, shot) {
  await page.goto(`${BASE}/watch`)
  await settle(page)
  const input = page.getByLabel(T.add, { exact: true })
  const button = page.getByRole("button", { name: T.watchButton, exact: true })
  await input.fill("CVE-26-1")
  await page.waitForTimeout(150)
  check(
    `${tag} watch list: an invalid id – the message, the button off`,
    (await page.getByText(T.invalid, { exact: true }).isVisible()) && (await button.isDisabled()) && (await input.getAttribute("aria-invalid")) === "true",
  )
  for (const c of [CVE.toLowerCase(), UNKNOWN]) {
    await input.fill(c)
    await button.click()
    await page.waitForTimeout(700)
  }
  const ids = await watched(ctx)
  const body = await page.locator("main").innerText()
  check(
    `${tag} watch list: added by input (case does not matter), a CVE not known yet marked`,
    ids.includes(CVE) && ids.includes(UNKNOWN) && body.includes(CVE) && body.includes(T.unknown),
    {
      ids,
    },
  )
  await scrollCheck(page, tag, "watch list")
  if (SHOTS && shot) await page.screenshot({ path: `${SHOTS}/${shot}.png` })
  for (const c of [CVE, UNKNOWN]) await unwatchRow(page, T, c)
  const left = await watched(ctx)
  check(`${tag} watch list: removed again`, !left.includes(CVE) && !left.includes(UNKNOWN), { left })
}

// ---------------------------------------------------------------- the reader in a team

/** The sidebar entry "Beobachtete CVEs" opens /watch – on a phone (375 px) through the sidebar menu (its trigger). */
async function sidebarToWatch(page, T, tag, width) {
  await page.goto(`${BASE}/vendor`)
  await settle(page)
  const mobile = width < 768
  if (mobile) {
    // the user menu in the sidebar's foot: "Dokumentation" opens /docs and the sidebar menu closes as well
    await page.locator("[data-sidebar=trigger]").first().click()
    await page.waitForTimeout(400)
    await page.locator('[data-mobile="true"] [data-sidebar="footer"] [data-sidebar="menu-button"]').first().click()
    await page.getByRole("menuitem", { name: T.docs, exact: true }).click()
    await settle(page)
    const docsPath = new URL(page.url()).pathname
    const docsOpen = await page
      .locator('[data-mobile="true"]')
      .isVisible()
      .catch(() => false)
    check(`${tag} sidebar menu (phone): "${T.docs}" in the user menu opens the handbook (/docs…), the menu closes`, docsPath.startsWith("/docs") && !docsOpen, {
      path: docsPath,
      stayedOpen: docsOpen,
    })
    await page.goto(`${BASE}/vendor`)
    await settle(page)
    await page.locator("[data-sidebar=trigger]").first().click()
    await page.waitForTimeout(400)
  }
  const entry = page.locator(`${mobile ? '[data-mobile="true"] ' : ""}[data-sidebar="menu"] a[href="/watch"]`).first()
  const visible = (await entry.count()) > 0 && (await entry.isVisible())
  if (visible) await entry.click()
  await settle(page)
  // on a phone the menu closes with the tap (CloseOnNavigate / NavItem in app-shell.tsx)
  const stayed =
    mobile &&
    (await page
      .locator('[data-mobile="true"]')
      .isVisible()
      .catch(() => false))
  const closed =
    !mobile ||
    !(await page
      .locator('[data-mobile="true"]')
      .isVisible()
      .catch(() => false))
  check(`${tag} sidebar${mobile ? " menu (phone)" : ""}: "${T.title}" reachable, opens /watch`, visible && new URL(page.url()).pathname === "/watch" && closed, {
    visible,
    path: new URL(page.url()).pathname,
    ...(mobile ? { stayedOpen: stayed } : {}),
  })
}

/** /watch: one h1 with the title, the description, the help link – no second heading of the same name. */
async function pageHead(page, T, tag, shot) {
  const main = page.locator("main")
  await main
    .locator("h1")
    .first()
    .waitFor({ timeout: 5000 })
    .catch(() => {})
  const h1 = await main.locator("h1").allInnerTexts()
  const same = await main.getByText(T.title, { exact: true }).count()
  const lead = await main
    .locator("h1 + p")
    .innerText()
    .catch(() => "")
  const desc = lead.includes(T.tip[0]) && lead.includes(T.tip[1]) // the tip line with the star
  const help = await main.getByRole("link", { name: `${T.help}: ${T.title}`, exact: true }).isVisible()
  check(
    `${tag} /watch: a clean head – one h1 "${T.title}", the description, the help link, no second heading`,
    h1.length === 1 && h1[0] === T.title && same === 1 && desc && help,
    {
      h1,
      same,
      desc,
      help,
    },
  )
  await scrollCheck(page, tag, "/watch")
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${shot}.png` })
}

async function reader(browser, lang, width, theme) {
  const T = L[lang]
  const tag = `${lang} ${width}px ${theme}`
  const wide = width === 1280 && theme === "light"
  const shot = (n) => `${lang}-${width}-${theme}-${n}`
  const { ctx, page, errors, logs } = await context(browser, lang, width, theme)
  await signIn(ctx, creds.reader, creds.reader_password)
  if ((await watched(ctx)).length) for (const c of await watched(ctx)) await ctx.request.delete(`${BASE}/api/me/cve-watch/${c}`, { headers: { "X-CSRF-Token": await csrfOf(ctx) } })

  // a) the stars: a finding, a story
  await page.goto(`${BASE}/vendor?product=panos`)
  await settle(page)
  await starRound(ctx, page, T, tag, "finding")
  await scrollCheck(page, tag, "finding")
  const story = await findStory(ctx, CVE)
  if (story) {
    await page.goto(`${BASE}/?story=${story.id}`)
    await settle(page)
    await starRound(ctx, page, T, tag, "story")
    await scrollCheck(page, tag, "story")
  } else check(`${tag} story: seed – a story of ${CVE}`, false)

  // a) the page itself: reached from the sidebar (on a phone through the sidebar menu), one clean head
  await sidebarToWatch(page, T, tag, width)
  await pageHead(page, T, tag, shot("watch_page"))

  // a) the list, the hint for a person whose way is on
  await watchList(ctx, page, T, tag, shot("watch_list"))
  check(`${tag} watch list: a way is on – no notification line`, !(await page.locator("main").innerText()).includes(T.notifyOff))
  if (wide) {
    const r = await ctx.request.post(`${BASE}/api/me/cve-watch`, { data: { cve: "CVE-26-123456" }, headers: { "X-CSRF-Token": await csrfOf(ctx) } })
    const code = (await r.json().catch(() => ({})))?.detail?.code
    check(`${lang} watch API: an invalid id is refused (422 invalid_cve)`, r.status() === 422 && code === "invalid_cve", { status: r.status(), code })
  }

  // b) the calendar
  await page.goto(`${BASE}/settings/notifications?tab=calendar`)
  await settle(page)
  const field = page.getByLabel(T.url, { exact: true })
  const make = async (confirm) => {
    await page.getByRole("button", { name: confirm ? T.renew : T.make, exact: true }).click()
    if (confirm) await page.getByRole("dialog").last().getByRole("button", { name: T.renew, exact: true }).click()
    await field.waitFor({ timeout: 5000 }).catch(() => {})
    return (await field.count()) ? await field.inputValue() : ""
  }
  const none = await page.getByText(T.none, { exact: true }).isVisible()
  const url = await make(false)
  const tokens = [url.split("/cal/")[1] ?? ""]
  check(
    `${tag} calendar: the address is made and shown once, with a copy button`,
    none && FEED.test(url) && (await page.getByText(T.once).isVisible()) && (await page.getByRole("button", { name: T.copy, exact: true }).isVisible()),
    { none, format: FEED.test(url) },
  )
  await scrollCheck(page, tag, "calendar")
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${shot("calendar")}.png`, mask: [field] })
  const feed = async (u) => ctx.request.get(`${API}${new URL(u).pathname}`)
  if (wide) {
    await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: BASE })
    await page.getByRole("button", { name: T.copy, exact: true }).click()
    await page.waitForTimeout(300)
    check(`${lang} calendar: the copy button copies the address as shown`, (await page.evaluate(() => navigator.clipboard.readText())) === url)
    // the seed's two versions with an end of support – more when later seeds (0.1.40 review) added versions
    const want = (await json(ctx, "/api/me/calendar")).entries
    const r = await feed(url)
    const h = r.headers()
    const ics = await r.text()
    const events = (ics.match(/^BEGIN:VEVENT\r?$/gm) ?? []).length
    check(
      `${lang} calendar feed: text/calendar, VCALENDAR, one VEVENT per version with an end of support, VALARMs`,
      r.status() === 200 && /^text\/calendar/.test(h["content-type"] ?? "") && ics.startsWith("BEGIN:VCALENDAR") && events === want && want >= 2 && /BEGIN:VALARM/.test(ics),
      { status: r.status(), type: h["content-type"], events, want },
    )
    check(
      `${lang} calendar feed: no CVE id; Cache-Control no-store, Referrer-Policy no-referrer`,
      !/CVE-\d{4}-\d+/i.test(ics) && /no-store/.test(h["cache-control"] ?? "") && h["referrer-policy"] === "no-referrer",
      { cache: h["cache-control"], referrer: h["referrer-policy"] },
    )
    await page.reload()
    await settle(page)
    check(`${lang} calendar: after a reload the address is gone, "active since" instead`, (await field.count()) === 0 && (await page.getByText(T.active).isVisible()))
    const next = await make(true)
    tokens.push(next.split("/cal/")[1] ?? "")
    const [o, n] = [await feed(url), await feed(next)]
    check(`${lang} calendar renewed: the old address 404, the new one 200`, FEED.test(next) && next !== url && o.status() === 404 && n.status() === 200, {
      old: o.status(),
      new: n.status(),
    })
    await page.getByRole("button", { name: T.del, exact: true }).click()
    await page.getByRole("dialog").last().getByRole("button", { name: T.del, exact: true }).click()
    await settle(page)
    const gone = await feed(next)
    check(`${lang} calendar deleted: the address 404, the page says none`, gone.status() === 404 && (await page.getByText(T.none, { exact: true }).isVisible()), {
      status: gone.status(),
    })
  } else {
    await page.getByRole("button", { name: T.del, exact: true }).click()
    await page.getByRole("dialog").last().getByRole("button", { name: T.del, exact: true }).click()
    await settle(page)
    check(`${tag} calendar: deleted again`, !(await json(ctx, "/api/me/calendar")).active)
  }
  const leaked = logs.some((l) => tokens.some((t) => t && l.includes(t)))
  check(`${tag} calendar: the token is in no console line of the page`, !leaked, { lines: logs.length })
  check(`${tag} reader: no page or console errors`, errors.length === 0, errors.slice(0, 3))
  await ctx.close()
}

// ---------------------------------------------------------------- the reader in no team

async function noTeam(browser, lang, width, theme) {
  const T = L[lang]
  const tag = `${lang} ${width}px ${theme} no team`
  const { ctx, page, errors } = await context(browser, lang, width, theme)
  await signIn(ctx, creds.reader2, creds.reader2_password)
  for (const c of await watched(ctx)) await ctx.request.delete(`${BASE}/api/me/cve-watch/${c}`, { headers: { "X-CSRF-Token": await csrfOf(ctx) } })
  const link = page.getByRole("link", { name: T.toWays, exact: true })
  const tab = page.getByRole("link", { name: T.waysCard, exact: true }) // the sub-tab "Hersteller-News meiner Produkte" (settings)
  const state = async () => ({ hint: (await page.locator("main").innerText()).includes(T.firstCve), link: await link.count() })
  const available = async () => (await (await ctx.request.get(`${BASE}/api/me/vendor-notify`)).json()).available

  // the own page: in the sidebar, and the old settings address (links in sent messages) leads there
  if (width === 1280) {
    await page.goto(`${BASE}/settings/notifications?tab=watch&cve=${CVE}`)
    await settle(page)
    const u = new URL(page.url())
    check(`${tag} the old address /settings/notifications?tab=watch goes to /watch`, u.pathname === "/watch" && u.searchParams.get("cve") === CVE, {
      path: u.pathname,
      search: u.search,
    })
    check(`${tag} "${T.title}" is a sidebar entry`, (await page.locator('[data-sidebar="menu"] a[href="/watch"]').count()) === 1)
  }
  // nothing watched: the ways cannot be switched on yet – no link, the hint says when they can
  await page.goto(`${BASE}/watch`)
  await settle(page)
  const none = await state()
  check(
    `${tag} nothing watched: the reminder-list hint, "${T.firstCve.slice(0, 30)}…", no link, ways not available`,
    (await page.locator("main").innerText()).includes(T.notifyOff) && none.hint && !none.link && !(await available()),
    none,
  )
  if (SHOTS && width === 1280) await page.screenshot({ path: `${SHOTS}/${lang}-${width}-${theme}-watch_no_team_empty.png` })

  // the first CVE, no reload: the link and the sub-tab appear, the link opens the ways
  await page.getByLabel(T.add, { exact: true }).fill(CVE)
  await page.getByRole("button", { name: T.watchButton, exact: true }).click()
  await link.waitFor({ timeout: 5000 }).catch(() => {})
  const first = await state()
  check(`${tag} first CVE (no reload): the link "${T.toWays}" appears`, first.link === 1 && !first.hint && (await available()), first)
  if (first.link) {
    await link.click()
    await settle(page)
    const on = (await tab.getAttribute("aria-current").catch(() => null)) === "page"
    check(`${tag} first CVE: "${T.toWays}" opens "${T.waysCard}"`, on && new URL(page.url()).searchParams.get("tab") === "vendor", { on, url: new URL(page.url()).search })
    await scrollCheck(page, tag, "ways")
    await page.goBack() // back to the list – no reload
    await settle(page)
  }

  // the last CVE removed, no reload: no link, no sub-tab, the hint again
  await unwatchRow(page, T, CVE)
  await page
    .getByText(T.firstCve)
    .waitFor({ timeout: 5000 })
    .catch(() => {})
  const last = await state()
  check(`${tag} last CVE removed (no reload): no link, the hint again, ways not available`, !last.link && last.hint && !(await watched(ctx)).length && !(await available()), last)

  await watchList(ctx, page, T, tag, width === 1280 && `${lang}-${width}-${theme}-watch_list_no_team`)
  check(`${tag} reader: no page or console errors`, errors.length === 0, errors.slice(0, 3))
  await ctx.close()
}

const browser = await chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const lang of ["de", "en"]) {
    for (const width of [1280, 375]) {
      for (const theme of ["light", "dark"]) {
        await reader(browser, lang, width, theme)
        await noTeam(browser, lang, width, theme)
      }
    }
  }
} finally {
  await browser.close()
}
const failed = results.filter((x) => !x).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed ? 1 : 0)
