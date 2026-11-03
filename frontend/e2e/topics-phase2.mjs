// Browser check (0.1.47): topics, phase 2.
// - News: the topic "Exploit veröffentlicht" (filter row with the API's number, ?topic=poc); "Betrifft unsere Produkte"
//   with its number (shown while something is followed), the card badge "Unser Produkt: …" (+n, the names in its
//   tooltip); a team member: exactly one first /api/news request without `scope`, the chip's label and number do not
//   change after the first paint, with the chip on the list asks scope=team and only the team's products count (the
//   Cisco ASA story is left out, the badges name the team's products) – a reader in no team sees it; the drawer's
//   "Themen" names "CVE-… · nuclei-templates"; a story without CVEs of its own shows the details' CVEs labelled.
// - Kanäle & Regeln: the rule editor's topic picker, the Probelauf's "Thema …", the Zustellprotokoll's topics (a real
//   round to the local mock receiver: ROUND_CMD), the audit entry's "Themen"; desktop notifications' topic picker in the
//   account settings (switched on without any permission – the stub answers "denied").
// DE and EN (the flows, 1280 px light), 1280 px and 375 px, light and dark (the pages): no page error, no console error,
// no horizontal scroll. It expects seed147 (stories, exploit entries) and team Netzwerk (panos, fortios – not cisco-asa
// for layout_team). Env: BASE_URL, CREDS, PLAYWRIGHT, SHOTS, DB_CMD, ROUND_CMD, MOCK (the receiver, http://ip:port).
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import { execSync } from "node:child_process"
import { BASE, COMBOS, H, SHOTS, check, creds, dismissToasts, finish, freshCode, json, open, pw, scrollCheck, settle, signIn, tooltipOf } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const DB_CMD = process.env.DB_CMD || ""
const ROUND = process.env.ROUND_CMD || ""
const MOCK = process.env.MOCK || ""
if (!DB_CMD || !ROUND || !MOCK) throw new Error("DB_CMD, ROUND_CMD and MOCK are needed")
const sql = (text) => execSync(DB_CMD, { input: text, stdio: ["pipe", "ignore", "inherit"], shell: "/bin/sh" })
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
async function until(fn, ms = 8000, step = 250) {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn().catch(() => false)
    if (v || Date.now() > end) return v
    await sleep(step)
  }
}
const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
const P2 = "E2E Phase2:"
const card = (p, part) => p.locator("main article").filter({ hasText: part }).first()
const titles = async (p) =>
  (await p.locator("main article h3").allInnerTexts())
    .map((x) => x.trim())
    .filter((x) => x.includes(P2))
    .map((x) => x.slice(x.indexOf(P2)))
    .sort()
const oursChip = (p, t) => p.getByRole("button", { name: new RegExp(`^${esc(t("news.ours"))}`) })

async function newsFlow(browser, combo, t) {
  const tag = `${combo.lang} news`
  // the team member: one first request, the chip steady
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.layout_team_user, creds.layout_team_password)
  const p = r.page
  const asked = []
  p.on("request", (q) => {
    const u = new URL(q.url())
    if (u.pathname === "/api/news") asked.push(u.search)
  })
  await p.goto(`${BASE}/`)
  const chip = oursChip(p, t)
  await chip.waitFor({ timeout: 10000 })
  const first = (await chip.innerText()).replace(/\s+/g, " ").trim()
  await settle(p)
  await sleep(2000)
  const later = (await chip.innerText()).replace(/\s+/g, " ").trim()
  const all = await json(r.ctx, "/api/news?state=all&limit=120")
  check(
    `${tag}: a team member – one first /api/news request without "scope"; "${t("news.ours")}" ${all.counts?.ours} as the API counts, steady after the first paint`,
    asked.length === 1 && !asked[0].includes("scope") && first === later && first === `${t("news.ours")} ${all.counts?.ours}` && all.ours_on === true,
    { asked, first, later, api: all.counts?.ours },
  )
  // "Exploit veröffentlicht"
  await p.getByRole("button", { name: new RegExp(`^${esc(t("news.filterTopic"))}`) }).click()
  const pocRow = (await p.getByRole("option").allInnerTexts()).map((x) => x.replace(/\s+/g, " ").trim()).find((x) => x.startsWith(t("news.topic.poc")))
  await p.keyboard.press("Escape")
  const poc = await json(r.ctx, "/api/news?state=all&limit=120&topic=poc")
  await p.goto(`${BASE}/?topic=poc`)
  await settle(p)
  const shownPoc = await titles(p)
  const wantPoc = poc.items
    .filter((i) => i.title.includes(P2))
    .map((i) => i.title)
    .sort()
  check(
    `${tag}: "${t("news.topic.poc")}" – in the topic filter with the API's ${all.counts.topics.poc}, ?topic=poc lists its stories`,
    !!pocRow &&
      pocRow.endsWith(String(all.counts.topics.poc)) &&
      pocRow.includes(t("news.topicHint.poc").slice(0, 20)) &&
      JSON.stringify(shownPoc) === JSON.stringify(wantPoc) &&
      wantPoc.length >= 1,
    {
      pocRow,
      shownPoc,
    },
  )
  // the chip on: scope=team, the team's products only
  await p.goto(`${BASE}/`)
  await settle(p)
  asked.length = 0
  await oursChip(p, t).click()
  await settle(p)
  const scoped = asked.some((x) => /[?&]ours=(1|true)\b/.test(x) && x.includes("scope=team"))
  const label = (await oursChip(p, t).innerText()).replace(/\s+/g, " ").trim()
  const team = await json(r.ctx, "/api/news?state=all&limit=120&ours=1&scope=team")
  const shownTeam = await titles(p)
  const multi = card(p, "Sammelhinweis Palo Alto und Fortinet")
  const badge = multi
    .locator("span[tabindex]")
    .filter({ hasText: t("news.oursBadge", { name: "§" }).split("§")[0] })
    .first()
  const btext = ((await badge.innerText().catch(() => "")) || "").trim()
  const btip = (await badge.count()) ? await tooltipOf(p, badge) : ""
  check(
    `${tag}: "${t("news.oursTeam")}" on – the request asks scope=team, ${team.counts?.ours} stories (no Cisco ASA), the badge "${btext}" with all names in its tooltip`,
    scoped &&
      label.startsWith(t("news.oursTeam")) &&
      !shownTeam.some((x) => x.includes("Cisco ASA")) &&
      shownTeam.some((x) => x.includes("Sammelhinweis")) &&
      /\+1$/.test(btext) &&
      btip.includes("FortiOS") &&
      btip.includes("PAN-OS"),
    { scoped, label, shownTeam, btext, btip },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "ours on (team)", SHOTS && `${combo.lang}-ours_team`)
  // the drawer: "CVE-… · nuclei-templates"; the details' CVEs labelled
  const s1004 = all.items.find((i) => i.title.includes("CVE-2026-1004"))
  await p.goto(`${BASE}/?story=${s1004.id}`)
  await settle(p)
  const topicsText = (
    (await p
      .locator("[data-slot=sheet-content] section")
      .filter({ has: p.getByRole("heading", { name: t("news.topicsTitle") }) })
      .innerText()
      .catch(() => "")) || ""
  ).replace(/\s+/g, " ")
  check(
    `${tag}: the drawer's "${t("news.topicsTitle")}" – "${t("news.topic.poc")}" because of "CVE-2026-1004 · nuclei-templates"`,
    topicsText.includes(t("news.topic.poc")) && topicsText.includes("CVE-2026-1004") && topicsText.includes("nuclei-templates"),
    {
      topicsText: topicsText.slice(0, 200),
    },
  )
  const nocve = all.items.find((i) => i.title.includes("ohne eigene CVE"))
  await p.goto(`${BASE}/?story=${nocve.id}`)
  await settle(p)
  const sheetText = (await p.locator("[data-slot=sheet-content]").innerText()).replace(/\s+/g, " ")
  check(
    `${tag}: a story without CVEs of its own – "${t("news.cveOfDetails")}" CVE-2026-1001, CVE-2026-1002 (no empty list)`,
    sheetText.includes(t("news.cveOfDetails")) && sheetText.includes("CVE-2026-1001") && sheetText.includes("CVE-2026-1002") && nocve.cves.length === 0,
    {
      has: sheetText.includes(t("news.cveOfDetails")),
    },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "details CVEs", SHOTS && `${combo.lang}-details_cves`)
  check(`${tag}: team member – no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
  // a reader in no team: all followed products – the Cisco ASA story with its badge
  const s = await open(browser, combo)
  await signIn(s.ctx, creds.layout_solo_user, creds.layout_solo_password)
  await s.page.goto(`${BASE}/?ours=1`)
  await settle(s.page)
  const soloAsked = await json(s.ctx, "/api/news?state=all&limit=120&ours=1")
  const soloShown = await titles(s.page)
  const asa = card(s.page, "Cisco ASA Schwachstelle")
  const asaBadge = ((await asa.innerText().catch(() => "")) || "").includes(t("news.oursBadge", { name: "§" }).split("§")[0])
  check(
    `${tag}: a reader in no team – "${t("news.ours")}" ${soloAsked.counts?.ours}, the Cisco ASA story with its badge`,
    soloShown.some((x) => x.includes("Cisco ASA")) && asaBadge && (await oursChip(s.page, t).innerText()).startsWith(t("news.ours")),
    {
      soloShown,
    },
  )
  check(`${tag}: no-team reader – no page or console errors`, s.errors.length === 0, s.errors.slice(0, 3))
  await s.ctx.close()
}

async function rulesFlow(browser, combo, t) {
  const tag = `${combo.lang} rules`
  const a = await open(browser, combo)
  await signIn(a.ctx, creds.user, creds.password, true)
  const p = a.page
  const h = await H(a.ctx)
  const ch = await (
    await a.ctx.request.post(`${BASE}/api/admin/notify/channels`, {
      data: { name: `E2E Themen ${crypto.randomBytes(2).toString("hex")}`, type: "webhook", url: `${MOCK}/ok`, allow_http: true },
      headers: h,
    })
  ).json()
  const name = `E2E Themenregel ${crypto.randomBytes(2).toString("hex")}`
  const made = await a.ctx.request.post(`${BASE}/api/admin/notify/rules`, {
    data: { name, channels: [ch.id], severities: ["critical", "high", "medium", "low", "info"], kinds: ["news"], topics: ["exploited", "poc"], lang: combo.lang },
    headers: h,
  })
  const rule = await made.json()
  await p.goto(`${BASE}/settings/rules?tab=rules`)
  await settle(p)
  const row = p.locator("main li").filter({ hasText: name }).first()
  const rowText = (await row.innerText()).replace(/\s+/g, " ")
  check(
    `${tag}: the rule's line says "${t("notify.topicsList", { names: `${t("news.topic.exploited")}, ${t("news.topic.poc")}` })}"`,
    rowText.includes(t("notify.topicsList", { names: `${t("news.topic.exploited")}, ${t("news.topic.poc")}` })),
    { rowText: rowText.slice(0, 160) },
  )
  await row.getByRole("button", { name: t("common.edit"), exact: true }).click()
  const main = p.locator("main")
  await main.getByText(t("notify.topicsHint")).waitFor({ timeout: 6000 })
  const picker = main
    .locator("button")
    .filter({ hasText: t("news.topic.poc") })
    .first()
  const shownTopics = (await picker.innerText()).replace(/\s+/g, " ")
  check(
    `${tag}: the editor's topic picker shows "${t("news.topic.exploited")}" and "${t("news.topic.poc")}"`,
    shownTopics.includes(t("news.topic.exploited")) && shownTopics.includes(t("news.topic.poc")),
    { shownTopics },
  )
  // a story that arrives with "Aktiv ausgenutzt" (the seeded "poc" came by the backfill – quiet, news.loud_topic: no rule
  // takes it): the Probelauf's reason, then a real round to the mock receiver and the Zustellprotokoll's topics
  const tagS = crypto.randomBytes(3).toString("hex")
  const at = new Date().toISOString()
  sql(`WITH c AS (INSERT INTO counters (name, value) VALUES ('news_seq', 1) ON CONFLICT (name) DO UPDATE SET value = counters.value + 1 RETURNING value)
INSERT INTO news_items (id, source_id, url, url_key, title, title_key, summary, content_html, published_at, fetched_at, severity, reasons, cves, also_in, backlog, search, seq, topics)
SELECT gen_random_uuid(), (SELECT id FROM news_sources WHERE key = 'bleepingcomputer'), 'https://news.example.com/rule/${tagS}', 'rule-${tagS}', 'E2E Themenrunde ${tagS}', 'e2e themenrunde ${tagS}',
'Topic round.', '', '${at}', '${at}', 'high', '[]', '[]', '[]', false, 'e2e themenrunde ${tagS}', c.value, '["exploited"]' FROM c;`)
  // the Probelauf: "Thema …"
  await main.getByRole("combobox", { name: t("dlog.dry.window") }).click()
  await p.getByRole("option", { name: t("dlog.dry.days", { count: 30 }), exact: true }).click()
  await main.getByRole("button", { name: t("dlog.dry.run"), exact: true }).click()
  const dry = await until(async () => {
    const x = await main.innerText()
    return x.includes(t("dlog.dry.byTopic", { topics: "§" }).split("§")[0]) && x
  }, 10000)
  check(
    `${tag}: the Probelauf says why – "${t("dlog.dry.byTopic", { topics: t("news.topic.exploited") })}"`,
    !!dry && dry.includes(t("dlog.dry.byTopic", { topics: t("news.topic.exploited") }).slice(0, 12)),
    {
      found: !!dry,
    },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "rule editor topics", SHOTS && `${combo.lang}-rule_topics`)
  // remove "poc" in the picker and save: the audit entry names "Themen"
  await picker.click()
  await p.getByRole("option", { name: new RegExp(`^${esc(t("news.topic.poc"))}`) }).click()
  await p.keyboard.press("Escape")
  await main
    .getByRole("button", { name: t("common.save"), exact: true })
    .last()
    .click()
  const saved = await until(async () => {
    const x =
      (await json(a.ctx, "/api/admin/notify/rules")).find?.((y) => y.id === rule.id) ?? ((await json(a.ctx, "/api/admin/notify/rules")).items ?? []).find((y) => y.id === rule.id)
    return x && JSON.stringify(x.topics) === '["exploited"]' && x
  })
  await p.goto(`${BASE}/settings/audit`)
  await settle(p)
  await p.locator("main").getByRole("searchbox").first().fill(name)
  await p.waitForTimeout(800)
  await settle(p)
  const rows = p.locator("main ul > li > button[aria-expanded]")
  await rows.first().click()
  await p.waitForTimeout(300)
  const audit = (
    await p
      .locator("main [id^=audit-]")
      .first()
      .innerText()
      .catch(() => "")
  ).replace(/\s+/g, " ")
  check(`${tag}: saved with one topic less – the audit entry names "${t("audit.field.topics")}"`, !!saved && audit.includes(t("audit.field.topics")), {
    audit: audit.slice(0, 200),
  })
  execSync(ROUND, { stdio: "ignore", shell: "/bin/sh" })
  await p.goto(`${BASE}/settings/rules?tab=log`)
  await settle(p)
  const log = await until(async () => {
    const x = (await p.locator("main").innerText()).replace(/\s+/g, " ")
    return x.includes(`E2E Themenrunde ${tagS}`) && x
  }, 8000)
  // the delivery's details (opened): each story with its topics
  const entry = p
    .locator("main li")
    .filter({ hasText: `E2E Themenrunde ${tagS}` })
    .first()
  if (log)
    await entry
      .getByRole("button", { name: t("dlog.details") })
      .first()
      .click()
  await p.waitForTimeout(400)
  const opened = log ? (await entry.innerText()).replace(/\s+/g, " ") : ""
  const near = opened.slice(opened.lastIndexOf(`E2E Themenrunde ${tagS}`), opened.lastIndexOf(`E2E Themenrunde ${tagS}`) + 120)
  check(`${tag}: the Zustellprotokoll lists the delivered story with its topic "${t("news.topic.exploited")}"`, near.includes(t("news.topic.exploited")), { near })
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "delivery log", SHOTS && `${combo.lang}-dlog_topics`)
  await a.ctx.request.delete(`${BASE}/api/admin/notify/rules/${rule.id}`, { headers: h })
  await a.ctx.request.delete(`${BASE}/api/admin/notify/channels/${ch.id}`, { headers: h })
  void freshCode
  check(`${combo.lang} admin: no page or console errors`, a.errors.length === 0, a.errors.slice(0, 3))
  await a.ctx.close()
}

async function desktopFlow(browser, combo, t) {
  const tag = `${combo.lang} desktop`
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.layout_solo_user, creds.layout_solo_password)
  const p = r.page
  await p.goto(`${BASE}/settings/notifications`)
  await settle(p)
  const sw = p.locator("main").getByRole("switch").first()
  if ((await sw.getAttribute("aria-checked")) !== "true") await sw.click()
  const field = p.locator("main").getByText(t("desktop.topicsHint"))
  const hint = (await field.count()) === 1
  await p
    .locator("main")
    .locator("button")
    .filter({ hasText: t("notify.allTopics") })
    .first()
    .click()
  const opts = (await p.getByRole("option").allInnerTexts()).length
  await p.getByRole("option", { name: new RegExp(`^${esc(t("news.topic.poc"))}`) }).click()
  await p.keyboard.press("Escape")
  await p
    .locator("main")
    .getByRole("button", { name: t("common.save"), exact: true })
    .last()
    .click()
  const saved = await until(async () => (await json(r.ctx, "/api/me/desktop")).topics?.includes("poc"))
  check(`${tag}: account settings – the topic picker ("${t("desktop.topicsHint")}"), ${opts} topics, "${t("news.topic.poc")}" saved`, hint && opts === 9 && !!saved, {
    hint,
    opts,
    saved,
  })
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "desktop topics", SHOTS && `${combo.lang}-desktop_topics`)
  await r.ctx.request.put(`${BASE}/api/me/desktop`, { data: { ...(await json(r.ctx, "/api/me/desktop")), enabled: false, topics: [] }, headers: await H(r.ctx) })
  await dismissToasts(p)
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

async function pages(browser, combo) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme}`
  const t = texts(lang)
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.layout_team_user, creds.layout_team_password)
  await r.page.goto(`${BASE}/?ours=1`)
  await settle(r.page)
  await scrollCheck(r.page, tag, "news ours", SHOTS && `${lang}-${width}-${theme}-news_ours`)
  await r.page.goto(`${BASE}/?topic=poc`)
  await settle(r.page)
  await scrollCheck(r.page, tag, "news poc", false)
  check(`${tag}: the "${t("news.ours")}" chip shown`, (await oursChip(r.page, t).count()) === 1)
  check(`${tag} pages: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) {
    const t = texts(combo.lang)
    if (combo.wide) {
      await newsFlow(browser, combo, t)
      await rulesFlow(browser, combo, t)
      await desktopFlow(browser, combo, t)
    } else await pages(browser, combo)
  }
} finally {
  await browser.close()
}
finish()
