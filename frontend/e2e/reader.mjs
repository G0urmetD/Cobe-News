// Browser check (0.1.41): reading – read / unread with a watermark, muting for a while, saved views.
// - News: an unread story has the dot and bold; opening it marks it read where it stands; ✓ / ↺ with "Rückgängig";
//   "Nur ungelesene"; "Alle als gelesen" with a filter while a story arrives meanwhile (that one stays unread); the
//   sidebar badge follows (polling), "99+" from 100; a new account starts with nothing unread.
// - Mute: a CVE from a card's menu (the card goes; "Stummgeschaltete zeigen" shows it with "Stumm"), "Bis zu einem
//   Datum …"; Einstellungen → Benachrichtigungen → "Stummschaltungen" with the time left and "Aufheben"; only for that
//   person.
// - Vendor News: "N neu" on a card; the drawer shows "Neu" and marks read; a finding unread again; a product muted –
//   its KEV finding stays in sight ("KEV trotz Stumm"); "Alle als gelesen" with a status filter; ?filter=review keeps
//   the "Versionen prüfen" panel with "Nur ungelesene" and the views.
// - Ansichten: save, rename, default (applied when entering from the sidebar, not again after clearing the filters),
//   "Link kopieren" opened by another account, delete; crafted parameters break nothing; ?tab=suggestions stays with a
//   default view of Vendor News.
// - The watchlist row: "Stummschalten" in the opened row, then the "Stumm" pill; the audit log has none of it.
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll. The flows run
// once per language (the wide light run), the pages in every combination.
// It expects: News on (no fetching), two readers made after every story (reader6 in team Netzwerk, reader7), panos
// followed with findings CVE-2026-1002 (in the KEV catalogue) and CVE-2026-1004, versions due for review. DB_CMD (SQL
// from stdin into the throwaway database) adds stories as they would arrive. Env: BASE_URL, CREDS, PLAYWRIGHT, SHOTS,
// DB_CMD.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { execSync } from "node:child_process"
import crypto from "node:crypto"
import { BASE, COMBOS, H, SHOTS, check, creds, dismissToasts, finish, json, open, pw, scrollCheck, settle, signIn, toastAfter, toastCount } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const DB_CMD = process.env.DB_CMD || ""
if (!DB_CMD) throw new Error("DB_CMD (SQL into the throwaway database) is needed to add stories")
const sql = (text) => execSync(DB_CMD, { input: text, stdio: ["pipe", "ignore", "inherit"], shell: "/bin/sh" })
const esc = (s) => s.replace(/'/g, "''")
const INSERT =
  "INSERT INTO news_items (id, source_id, url, url_key, title, title_key, summary, content_html, published_at, fetched_at, severity, reasons, cves, also_in, backlog, search, seq)"
const SOURCE = "(SELECT id FROM news_sources WHERE enabled ORDER BY name LIMIT 1)"
const bump = (n) => `WITH c AS (INSERT INTO counters (name, value) VALUES ('news_seq', ${n}) ON CONFLICT (name) DO UPDATE SET value = counters.value + ${n} RETURNING value)`

/** A story arriving now (the next arrival number; the app's clock, not the database server's) – its id. */
function story(title, cves = [], severity = "high") {
  const id = crypto.randomUUID()
  const at = new Date().toISOString()
  const search = esc(`${title} ${cves.join(" ")} reader check.`.toLowerCase())
  sql(`${bump(1)} ${INSERT} SELECT '${id}', ${SOURCE}, 'https://news.example.com/reader/${id}', 'reader-${id}', '${esc(title)}', '${esc(title.toLowerCase())}',
'Reader check.', '', '${at}', '${at}', '${severity}', '[]', '${JSON.stringify(cves)}', '[]', false, '${search}', c.value FROM c;`)
  return id
}
/** `n` stories arriving now, dated two days back (below the check's own stories in the list, still unread). */
function bulk(n, tag) {
  const at = new Date().toISOString()
  const day = new Date(Date.now() - 2 * 86400000).toISOString()
  sql(`${bump(n)} ${INSERT} SELECT gen_random_uuid(), ${SOURCE}, 'https://news.example.com/bulk/${tag}/' || g, 'bulk-${tag}-' || g, 'E2E Bulk ${tag} ' || g, 'e2e bulk ${tag} ' || g,
'Bulk.', '', '${day}', '${at}', 'low', '[]', '[]', '[]', false, 'e2e bulk ${tag} ' || g, c.value - ${n} + g FROM c, generate_series(1, ${n}) g;`)
}

const counts = async (ctx) => json(ctx, "/api/reader/counts")
const item = async (ctx, id) => json(ctx, `/api/news/${id}`)
const card = (page, title) => page.locator("main article").filter({ hasText: title })
const isUnread = async (page, title) => (await card(page, title).first().getAttribute("data-unread")) !== null
const dialogOf = (page, title) => page.getByRole("dialog").filter({ hasText: title })
const newsBadge = (page) =>
  page
    .locator('[data-sidebar="menu-item"]')
    .filter({ has: page.locator('a[href="/"]') })
    .locator('[data-sidebar="menu-badge"]')
const badgeOf = async (page) => ((await newsBadge(page).count()) ? (await newsBadge(page).innerText()).trim() : "")
const mutesOf = async (ctx) => (await json(ctx, "/api/me/mutes")).items
async function until(fn, ms = 8000, step = 250) {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn().catch(() => false)
    if (v || Date.now() > end) return v
    await new Promise((r) => setTimeout(r, step))
  }
}
async function reader(browser, combo, who = "reader6") {
  const r = await open(browser, combo)
  // "Link kopieren" without a clipboard permission: what would be copied is kept on the page
  await r.ctx.addInitScript(() => {
    if (navigator.clipboard) navigator.clipboard.writeText = async (t) => void (window.__copied = t)
  })
  await signIn(r.ctx, creds[who], creds[`${who}_password`])
  return r
}

async function newsFlow(browser, combo, t) {
  const tag = `${combo.lang} news`
  const r = await reader(browser, combo)
  const p = r.page
  const sfx = `${combo.lang}${crypto.randomBytes(2).toString("hex")}`
  const A = `E2E Reader A ${sfx}`
  const B = `E2E Reader B ${sfx}`
  const C = `E2E Reader C ${sfx}`
  const n = Number.parseInt(crypto.randomBytes(2).toString("hex"), 16) % 4000
  const cveB = `CVE-2026-${50000 + n}`
  const cveC = `CVE-2026-${60000 + n}`
  const ids = { A: story(A, [], "high"), B: story(B, [cveB], "high"), C: story(C, [cveC], "critical") }
  await p.goto(`${BASE}/`)
  await settle(p)
  const h3 = card(p, A).first().locator("h3")
  const bold = /font-semibold/.test((await h3.getAttribute("class")) ?? "")
  const dot = (await h3.locator("span.rounded-full").count()) === 1
  check(`${tag}: an unread story has the dot and bold`, (await isUnread(p, A)) && bold && dot, { bold, dot })
  // opening marks it read – it stays where it is
  const order0 = await p.locator("main article h3").allInnerTexts()
  await card(p, A).first().locator("button[data-open]").click()
  await until(async () => !(await item(r.ctx, ids.A)).unread)
  await p.keyboard.press("Escape")
  await settle(p)
  const order1 = await p.locator("main article h3").allInnerTexts()
  const at0 = order0.findIndex((x) => x.includes(A))
  const at1 = order1.findIndex((x) => x.includes(A))
  check(`${tag}: opening marks read, the story stays in its place, dot and bold gone`, !(await item(r.ctx, ids.A)).unread && at0 >= 0 && at0 === at1 && !(await isUnread(p, A)), {
    at0,
    at1,
  })
  // ✓ with undo, ↺
  const before = await toastCount(p)
  await card(p, B)
    .first()
    .getByRole("button", { name: t("news.markRead"), exact: true })
    .click()
  const toast = await toastAfter(p, before)
  const readB = await until(async () => !(await item(r.ctx, ids.B)).unread)
  if (toast) await toast.el.getByRole("button", { name: t("news.undo") }).click()
  const undone = await until(async () => (await item(r.ctx, ids.B)).unread)
  await card(p, A)
    .first()
    .getByRole("button", { name: t("news.markUnread"), exact: true })
    .click()
  const again = await until(async () => (await item(r.ctx, ids.A)).unread)
  check(`${tag}: ✓ marks read, "${t("news.undo")}" undoes it, ↺ marks unread again`, readB && !!toast && undone && again, { readB, toast: !!toast, undone, again })
  await dismissToasts(p)
  // "Nur ungelesene"
  await p.getByRole("switch", { name: t("reader.onlyUnread") }).click()
  await settle(p)
  const only = await p.locator("main article").evaluateAll((els) => els.length > 0 && els.every((e) => e.hasAttribute("data-unread")))
  check(`${tag}: "${t("reader.onlyUnread")}" – ?unread=1, only unread cards`, new URL(p.url()).searchParams.get("unread") === "1" && only)
  // "Alle als gelesen" with a filter while a story arrives meanwhile
  await p.goto(`${BASE}/?severity=high`)
  await settle(p)
  const late = story(`E2E Reader late ${sfx}`, [], "high")
  await p.getByRole("button", { name: t("news.readAll") }).click()
  await dialogOf(p, t("news.readAllTitle"))
    .getByRole("button", { name: t("news.readAll") })
    .click()
  await until(async () => !(await item(r.ctx, ids.B)).unread)
  const lateUnread = (await item(r.ctx, late)).unread
  const cStill = (await item(r.ctx, ids.C)).unread // critical – outside the filter
  const aRead = !(await item(r.ctx, ids.A)).unread
  check(`${tag}: "${t("news.readAll")}" with a filter – the story that arrived meanwhile stays unread, another severity untouched`, lateUnread && cStill && aRead, {
    lateUnread,
    cStill,
    aRead,
  })
  await dismissToasts(p)
  // the sidebar badge follows (polled every minute); "99+"
  await p.goto(`${BASE}/watch`)
  await settle(p)
  const n0 = (await counts(r.ctx)).news
  const b0 = await badgeOf(p)
  story(`E2E Reader poll ${sfx}`)
  const b1 = await until(async () => (await badgeOf(p)) === String(n0 + 1) && (await badgeOf(p)), 75000, 1000)
  check(`${tag}: the sidebar badge follows within the polling (${b0} → ${n0 + 1})`, b0 === String(n0) && b1 === String(n0 + 1), { n0, b0, b1 })
  if (combo.lang === "de") {
    bulk(100, sfx)
    await p.reload()
    await settle(p)
    const b2 = await until(async () => (await badgeOf(p)) === "99+" && "99+", 8000)
    check(`${tag}: from 100 unread the badge says "99+"`, b2 === "99+", { b2, n: (await counts(r.ctx)).news })
    await r.ctx.request.post(`${BASE}/api/news/read-all`, { data: { severity: ["low"], q: `e2e bulk ${sfx}` }, headers: await H(r.ctx) })
  }

  // mute a CVE from the card's menu: the card goes, "Stummgeschaltete zeigen" shows it with "Stumm"
  await p.goto(`${BASE}/`)
  await settle(p)
  await card(p, C)
    .first()
    .getByRole("button", { name: t("reader.menu") })
    .click()
  await p.getByRole("menuitem", { name: t("reader.mute.days", { count: 7 }), exact: true }).click()
  const gone = await until(async () => (await card(p, C).count()) === 0)
  await p.getByRole("switch", { name: t("reader.showMuted") }).click()
  await settle(p)
  const shown = (await card(p, C).count()) === 1 && (await card(p, C).first().innerText()).includes(t("reader.mute.badge"))
  check(`${tag}: ${cveC} muted from the card – it goes; "${t("reader.showMuted")}" shows it with "${t("reader.mute.badge")}"`, gone && shown, { gone, shown })
  await dismissToasts(p)
  // until a day
  await card(p, B)
    .first()
    .getByRole("button", { name: t("reader.menu") })
    .click()
  await p.getByRole("menuitem", { name: t("reader.mute.untilDots") }).click()
  const d = new Date(Date.now() + 10 * 86400000)
  const day = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`
  await p.locator("#mute-until").fill(day)
  await scrollCheck(p, tag, "mute until dialog", SHOTS && `${combo.lang}-mute_until`)
  await dialogOf(p, t("reader.mute.untilLabel"))
    .getByRole("button", { name: t("reader.mute.action") })
    .click()
  const m = await until(async () => (await mutesOf(r.ctx)).find((x) => x.key === cveB))
  const local = m ? new Date(m.until) : null
  const sameDay = !!local && `${local.getFullYear()}-${String(local.getMonth() + 1).padStart(2, "0")}-${String(local.getDate()).padStart(2, "0")}` === day
  check(`${tag}: "${t("reader.mute.untilDots")}" – ${cveB} muted until the end of ${day}`, sameDay, { until: m?.until })
  await dismissToasts(p)
  // Einstellungen → Benachrichtigungen → Stummschaltungen: time left, Aufheben
  await p.goto(`${BASE}/settings/notifications`)
  await settle(p)
  await p
    .getByRole("link", { name: t("reader.mutes.tab") })
    .or(p.getByRole("tab", { name: t("reader.mutes.tab") }))
    .first()
    .click()
  await settle(p)
  const rowB = p.locator("main li").filter({ hasText: cveB })
  const rowC = p.locator("main li").filter({ hasText: cveC })
  const leftB = (await rowB.count()) ? await rowB.innerText() : ""
  const leftC = (await rowC.count()) ? await rowC.innerText() : ""
  const leftOk = leftC.includes(t("reader.mutes.left.days", { count: 7 })) || leftC.includes(t("reader.mutes.left.days", { count: 6 }))
  const leftOkB = leftB.includes(t("reader.mutes.left.days", { count: 10 })) || leftB.includes(t("reader.mutes.left.days", { count: 11 }))
  await scrollCheck(p, tag, "mutes tab", SHOTS && `${combo.lang}-mutes`)
  await rowB.getByRole("button", { name: t("reader.mutes.lift") }).click()
  const lifted = await until(async () => !(await mutesOf(r.ctx)).some((x) => x.key === cveB))
  const rowGone = await until(async () => (await rowB.count()) === 0)
  check(
    `${tag}: "${t("reader.mutes.tab")}" lists both with the time left; "${t("reader.mutes.lift")}" lifts one`,
    new URL(p.url()).searchParams.get("tab") === "mutes" && leftOk && leftOkB && lifted && rowGone,
    {
      leftC: leftC.replace(/\s+/g, " ").slice(0, 70),
      leftB: leftB.replace(/\s+/g, " ").slice(0, 70),
      lifted,
    },
  )
  // only for that person
  const o = await reader(browser, combo, "reader7")
  const other = await item(o.ctx, ids.C)
  const inList = ((await json(o.ctx, `/api/news?state=all&q=${encodeURIComponent(C)}`)).items ?? []).some((x) => x.id === ids.C && !x.muted)
  check(`${tag}: the mute is only the reader's – another reader sees the story unmuted`, other.muted === false && inList && (await item(r.ctx, ids.C)).muted === true)
  await o.ctx.close()
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

/** "Alle N als gelesen" (Vendor News, 0.1.43) – whatever N is. */
function readAllN(p, t) {
  const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  const one = esc(t("reader.vendorReadAllN", { count: 1 })).replace("1", "\\d+")
  const other = esc(t("reader.vendorReadAllN", { count: 987654 })).replace("987654", "\\d+")
  return p.getByRole("button", { name: new RegExp(`^(${one}|${other})$`) })
}

async function vendorFlow(browser, combo, t) {
  const tag = `${combo.lang} vendor`
  const r = await reader(browser, combo)
  const p = r.page
  const h = await H(r.ctx)
  for (const x of (await mutesOf(r.ctx)).filter((x) => x.key === "panos")) await r.ctx.request.delete(`${BASE}/api/me/mutes/${x.id}`, { headers: h })
  // two of panos' findings unread (made before this account: read for it until marked)
  for (const f of ["paloalto:CVE-2026-1002", "paloalto:CVE-2026-1004"])
    await r.ctx.request.post(`${BASE}/api/vendor/unread`, { data: { product: "panos", finding: f }, headers: h })
  await p.goto(`${BASE}/vendor`)
  await settle(p)
  const panos = p.locator("main article").filter({ hasText: "PAN-OS" }).first()
  const pill = await panos.innerText()
  check(`${tag}: "${t("reader.newCount", { count: 2 })}" on the card`, pill.includes(t("reader.newCount", { count: 2 })), { text: pill.replace(/\s+/g, " ").slice(0, 120) })
  const v0 = (await counts(r.ctx)).vendor
  // the drawer: "Neu", read when opened
  await p.goto(`${BASE}/vendor?product=panos`)
  await settle(p)
  const sheet = p.locator("[data-slot=sheet-content]")
  const pills = await sheet.getByText(t("reader.new"), { exact: true }).count()
  const v1 = await until(async () => {
    const c = (await counts(r.ctx)).vendor
    return c <= v0 - 2 ? c : false
  })
  check(`${tag}: the drawer shows "${t("reader.new")}" and marks its findings read`, pills >= 2 && v1 !== false, { pills, v0, v1 })
  await scrollCheck(p, tag, "drawer with Neu", SHOTS && `${combo.lang}-vendor_drawer_new`)
  const unreadBtn = sheet.getByRole("button", { name: t("news.markUnread") }).first()
  await unreadBtn.waitFor({ timeout: 8000 }).catch(() => undefined)
  await unreadBtn.click()
  const v2 = await until(async () => (await counts(r.ctx)).vendor === v1 + 1)
  check(`${tag}: a finding unread again ("${t("news.markUnread")}")`, v2, { v1 })
  await dismissToasts(p)
  await p.keyboard.press("Escape")
  await settle(p)
  // mute panos: the KEV finding stays in sight
  await p.goto(`${BASE}/vendor`)
  await settle(p)
  await panos.getByRole("button", { name: new RegExp(`^${t("reader.menuOf", { name: "§" }).split("§")[0]}`) }).click()
  await p.getByRole("menuitem", { name: t("reader.mute.days", { count: 30 }), exact: true }).click()
  const muted = await until(async () => (await mutesOf(r.ctx)).some((x) => x.key === "panos"))
  await settle(p)
  const kev = await until(async () => (await panos.count()) === 1 && (await panos.getByText(t("reader.mute.kev")).count()) === 1)
  check(`${tag}: panos muted – still listed with "${t("reader.mute.kev")}" (KEV finding)`, muted && kev, { muted, kev })
  await scrollCheck(p, tag, "muted product with KEV", SHOTS && `${combo.lang}-vendor_muted_kev`)
  for (const x of (await mutesOf(r.ctx)).filter((x) => x.key === "panos")) await r.ctx.request.delete(`${BASE}/api/me/mutes/${x.id}`, { headers: h })
  await dismissToasts(p)
  // "Alle N als gelesen" with a status filter (0.1.43: the button says how many)
  await p.goto(`${BASE}/vendor?status=action`)
  await settle(p)
  const readAll = readAllN(p, t)
  const can = (await readAll.count()) === 1
  const label = can ? (await readAll.innerText()).trim() : ""
  if (can) {
    await readAll.click()
    await dialogOf(p, t("reader.vendorReadAllTitle"))
      .getByRole("button", { name: t("news.readAll") })
      .click()
  }
  const zero = can && (await until(async () => (await counts(r.ctx)).vendor < v1 + 1))
  check(`${tag}: "${label || t("reader.vendorReadAllN", { count: 2 })}" with a status filter (?status=action)`, can && zero, { can, zero })
  await dismissToasts(p)
  // ?filter=review with "Nur ungelesene" (in the Filter popover since 0.1.43) and the views
  await r.ctx.request.post(`${BASE}/api/vendor/unread`, { data: { product: "panos", finding: "paloalto:CVE-2026-1004" }, headers: h })
  await p.goto(`${BASE}/vendor?filter=review&unread=1`)
  await settle(p)
  const main = p.locator("main")
  const panel = await main.getByText(t("review.title"), { exact: true }).count()
  const filters = p.getByRole("button", { name: new RegExp(`^${t("vendor.filters.button")}(,|$)`) })
  await filters.click()
  const unreadSw = p.locator("[data-slot=popover-content]").getByRole("switch", { name: new RegExp(`^${t("reader.onlyUnread")}`) })
  const sw = await unreadSw.getAttribute("aria-checked")
  // the switch, toggled on the page, keeps the review filter
  await unreadSw.click()
  await p.keyboard.press("Escape")
  await settle(p)
  const views = await p.getByRole("button", { name: new RegExp(t("reader.views.title")) }).count()
  const u = new URL(p.url()).searchParams
  const kept = u.get("filter") === "review" && !u.get("unread") && (await main.getByText(t("review.title"), { exact: true }).count()) >= 1
  check(
    `${tag}: ?filter=review&unread=1 – "${t("review.title")}" panel, "${t("reader.onlyUnread")}" on, "${t("reader.views.title")}"; switching keeps the panel`,
    panel >= 1 && sw === "true" && views >= 1 && kept,
    {
      panel,
      sw,
      views,
      kept,
    },
  )
  await scrollCheck(p, tag, "review + unread", SHOTS && `${combo.lang}-vendor_review_unread`)
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

async function viewsFlow(browser, combo, t) {
  const tag = `${combo.lang} views`
  const r = await reader(browser, combo)
  const p = r.page
  const h = await H(r.ctx)
  const drop = async (page) => {
    for (const v of (await json(r.ctx, `/api/me/views?page=${page}`)).items) await r.ctx.request.delete(`${BASE}/api/me/views/${v.id}`, { headers: h })
  }
  await drop("news")
  await p.goto(`${BASE}/?severity=critical&unread=1`)
  await settle(p)
  const menu = () => p.getByRole("button", { name: t("reader.views.title") }).first()
  const pop = () => p.locator("[data-slot=popover-content]")
  await menu().click()
  const name = `E2E Kritisch ${crypto.randomBytes(2).toString("hex")}`
  await pop()
    .getByRole("textbox", { name: t("reader.views.name") })
    .fill(name)
  await pop()
    .getByRole("button", { name: t("reader.views.save") })
    .last()
    .click()
  const saved = await until(async () => (await json(r.ctx, "/api/me/views?page=news")).items.find((v) => v.name === name))
  await scrollCheck(p, tag, "views menu", SHOTS && `${combo.lang}-views_menu`)
  // rename, default
  await pop()
    .getByRole("button", { name: t("reader.views.rename"), exact: true })
    .first()
    .click()
  const edit = pop()
    .getByRole("textbox", { name: t("reader.views.name") })
    .first()
  await edit.fill(`${name} neu`)
  await edit.press("Enter")
  const renamed = await until(async () => (await json(r.ctx, "/api/me/views?page=news")).items.find((v) => v.name === `${name} neu`))
  await pop()
    .getByRole("button", { name: t("reader.views.defaultSet"), exact: true })
    .first()
    .click()
  const def = await until(async () => (await json(r.ctx, "/api/me/views?page=news")).items.find((v) => v.default))
  check(`${tag}: saved with the filter, renamed, made the default`, !!saved && saved.query.includes("severity=critical") && !!renamed && def?.id === saved?.id, {
    query: saved?.query,
    renamed: !!renamed,
    def: !!def,
  })
  await p.keyboard.press("Escape")
  // entering from the sidebar applies the default; clearing the filters does not apply it again
  await p.goto(`${BASE}/watch`)
  await settle(p)
  await p.locator('[data-sidebar="menu-item"] a[href="/"]').first().click()
  await settle(p)
  const sp = new URL(p.url()).searchParams
  const applied = sp.get("severity") === "critical" && sp.get("unread") === "1"
  const label = (await menu().innerText()).trim()
  await p.getByRole("switch", { name: t("reader.onlyUnread") }).click()
  await settle(p)
  await p
    .locator("main")
    .getByRole("button", { name: t("news.resetFilter") })
    .click()
  await settle(p)
  await p.waitForTimeout(800)
  const cleared = [...new URL(p.url()).searchParams.keys()].length === 0
  check(`${tag}: entering from the sidebar applies the default ("${label}"); clearing the filters does not apply it again`, applied && label === `${name} neu` && cleared, {
    applied,
    label,
    url: p.url().replace(BASE, ""),
  })
  // "Link kopieren" opened by another account: the same filters
  await menu().click()
  await pop()
    .getByRole("button", { name: t("reader.views.copy"), exact: true })
    .first()
    .click()
  const link = await until(async () => p.evaluate(() => window.__copied ?? ""))
  await p.keyboard.press("Escape")
  const o = await reader(browser, combo, "reader7")
  if (link) await o.page.goto(link)
  await settle(o.page)
  const ou = new URL(o.page.url()).searchParams
  check(`${tag}: "${t("reader.views.copy")}" opened by another account – the same filters`, !!link && ou.get("severity") === "critical" && ou.get("unread") === "1", {
    link: link ? link.replace(BASE, "") : null,
  })
  check(`${tag}: the other account's page has no errors`, o.errors.length === 0, o.errors.slice(0, 2))
  await o.ctx.close()
  // delete
  await menu().click()
  await pop()
    .getByRole("button", { name: t("common.remove"), exact: true })
    .first()
    .click()
  await dialogOf(p, t("reader.views.deleteTitle"))
    .getByRole("button", { name: t("common.remove"), exact: true })
    .click()
  const deleted = await until(async () => (await json(r.ctx, "/api/me/views?page=news")).items.length === 0)
  check(`${tag}: deleted`, deleted)
  await p.keyboard.press("Escape")
  // crafted parameters
  const bad = [
    "/?severity=bogus&source=not-a-uuid&foo=bar&unread=maybe&muted=%00",
    "/?source=00000000-0000-0000-0000-000000000000&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&story=nope",
    "/vendor?filter=nonsense&status=nope&q=%3Cimg%20src%3Dx%3E&product=..%2F..&unread=2&zzz=1",
  ]
  const broke = []
  for (const u of bad) {
    const before = r.errors.length
    let dialogs = 0
    const onDialog = (d) => (dialogs++, d.dismiss().catch(() => {}))
    p.on("dialog", onDialog)
    await p.goto(`${BASE}${u}`)
    await settle(p)
    p.off("dialog", onDialog)
    const ok = (await p.locator("main h1").count()) >= 1 && r.errors.length === before && dialogs === 0
    if (!ok) broke.push({ u, errors: r.errors.slice(before, before + 2), dialogs })
  }
  check(`${tag}: crafted parameters (bad uuid, severity, unknown, markup) break nothing`, broke.length === 0, broke.length ? broke : undefined)
  // a default view of Vendor News: ?tab=suggestions stays; entering /vendor plainly applies it
  await drop("vendor")
  const made = await r.ctx.request.post(`${BASE}/api/me/views`, { data: { page: "vendor", name: "E2E Vendor default", query: "status=action", default: true }, headers: h })
  await p.goto(`${BASE}/watch`)
  await settle(p)
  await p.goto(`${BASE}/vendor?tab=suggestions`)
  await settle(p)
  const sTab = new URL(p.url()).searchParams
  await p.goto(`${BASE}/vendor`)
  await settle(p)
  const plain = new URL(p.url()).searchParams.get("status")
  check(
    `${tag}: with a default view of Vendor News ?tab=suggestions stays, a plain /vendor gets the default`,
    made.ok() && sTab.get("tab") === "suggestions" && plain === "action",
    {
      status: made.status(),
      tab: sTab.toString(),
      plain,
    },
  )
  await drop("vendor")
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

async function watchFlow(browser, combo, t) {
  const tag = `${combo.lang} watchlist`
  const r = await reader(browser, combo)
  const p = r.page
  const h = await H(r.ctx)
  const CVE = "CVE-2026-1001"
  for (const x of (await mutesOf(r.ctx)).filter((x) => x.key === CVE)) await r.ctx.request.delete(`${BASE}/api/me/mutes/${x.id}`, { headers: h })
  if (!(await json(r.ctx, "/api/me/cve-watch/ids")).cves.includes(CVE)) await r.ctx.request.post(`${BASE}/api/me/cve-watch`, { data: { cve: CVE }, headers: h })
  await p.goto(`${BASE}/watch?cve=${CVE}`)
  await settle(p)
  const row = p.locator(`#watch-${CVE}`)
  const btn = row.getByRole("button", { name: t("reader.mute.action"), exact: true })
  const hasBtn = (await btn.count()) === 1
  if (hasBtn) {
    await btn.click()
    await p.getByRole("menuitem", { name: t("reader.mute.days", { count: 7 }), exact: true }).click()
  }
  const muted = await until(async () => (await mutesOf(r.ctx)).some((x) => x.key === CVE))
  // the pill by its explanation (in English the pill and the button both say "Muted")
  const help = t("reader.mute.watchHelp", { date: "§" }).split("§")[0]
  const pill = await until(
    async () =>
      (await row
        .locator("span[title]")
        .filter({ hasText: t("reader.mute.badge") })
        .evaluateAll((els, h) => els.filter((e) => e.title.startsWith(h)).length, help)) === 1,
  )
  const nowBtn = row.getByRole("button", { name: t("reader.mute.muted"), exact: true })
  const now = await until(async () => (await nowBtn.count()) >= 1 && (await row.getByRole("button", { name: t("reader.mute.action"), exact: true }).count()) === 0)
  check(`${tag}: "${t("reader.mute.action")}" in the opened row – then the "${t("reader.mute.badge")}" pill and "${t("reader.mute.muted")}"`, hasBtn && muted && pill && now, {
    hasBtn,
    muted,
    pill,
    now,
  })
  await dismissToasts(p)
  await scrollCheck(p, tag, "muted row", SHOTS && `${combo.lang}-watch_muted`)
  for (const x of (await mutesOf(r.ctx)).filter((x) => x.key === CVE)) await r.ctx.request.delete(`${BASE}/api/me/mutes/${x.id}`, { headers: h })
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

async function auditFlow(browser, combo, since) {
  const a = await open(browser, combo)
  await signIn(a.ctx, creds.user, creds.password, true)
  const seen = []
  let cursor = ""
  for (let i = 0; i < 20; i++) {
    const page = await json(a.ctx, `/api/admin/audit?limit=200&since=${encodeURIComponent(since)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`)
    seen.push(...page.items)
    if (!page.next) break
    cursor = page.next
  }
  const readers = new Set([creds.reader6, creds.reader7])
  const theirs = seen.filter((e) => readers.has(e.actor?.name) && !e.action.startsWith("login."))
  const reading = seen.filter((e) => /read|mute|view|unread/i.test(e.action))
  check(`${combo.lang} audit log: no entry for reading, muting or views (${seen.length} entries since the start looked at)`, theirs.length === 0 && reading.length === 0, {
    theirs: theirs.map((e) => e.action).slice(0, 5),
    reading: reading.map((e) => e.action).slice(0, 5),
  })
  await a.ctx.close()
}

async function pages(browser, combo) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme}`
  const r = await reader(browser, combo)
  for (const [name, path] of [
    ["news", "/"],
    ["news unread+muted", "/?unread=1&muted=1"],
    ["vendor", "/vendor"],
    ["vendor drawer", "/vendor?product=panos"],
    ["mutes", "/settings/notifications?tab=mutes"],
    ["watchlist", "/watch"],
  ]) {
    await r.page.goto(`${BASE}${path}`)
    await settle(r.page)
    await scrollCheck(r.page, tag, name, SHOTS && `${lang}-${width}-${theme}-${name.replace(/[ +]/g, "_")}`)
  }
  check(`${tag} pages: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
const since = new Date(Date.now() - 1000).toISOString()
try {
  // a new account starts with nothing unread (reader7 has not been signed in before)
  {
    const s = await reader(browser, COMBOS[0], "reader7")
    const c = await counts(s.ctx)
    await s.page.goto(`${BASE}/`)
    await settle(s.page)
    const dots = await s.page.locator("main article[data-unread]").count()
    check("a new account starts with nothing unread (no badge, no unread card)", c.news === 0 && c.news_enabled === true && dots === 0 && (await badgeOf(s.page)) === "", {
      ...c,
      dots,
    })
    await s.ctx.close()
  }
  for (const combo of COMBOS) {
    const t = texts(combo.lang)
    if (combo.wide) {
      await newsFlow(browser, combo, t)
      await vendorFlow(browser, combo, t)
      await viewsFlow(browser, combo, t)
      await watchFlow(browser, combo, t)
      await auditFlow(browser, combo, since)
    }
    await pages(browser, combo)
  }
} finally {
  await browser.close()
}
finish()
