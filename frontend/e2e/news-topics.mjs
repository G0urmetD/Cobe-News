// Browser check (0.1.46): the topics of the news.
// - "Thema": the eight topics with their explanation and how many stories each would show (as the API counts them);
//   the quick chips Aktiv ausgenutzt / Zero-Day / Ohne Patch; topics OR among themselves, AND with the severity;
//   ?topic= in the address (an unknown value dropped).
// - Cards: at most two topic badges, "+n" with the rest (its label and tooltip), a badge's click opens no drawer; the
//   drawer's "Themen" with what each rests on; the "not exploited" story has no topic, the CRA press release (a duty to
//   report) is neither critical nor "Aktiv ausgenutzt".
// - "Quelle": grouped by kind, each group with "Alle: …".
// - A saved view keeps its topics; "Alle als gelesen" with only a topic marks only those stories; on Vendor News a
//   topic in the address is no filter ("Ansicht: Standard") and is not stored in a view.
// DE and EN (the flows, 1280 px light), 1280 px and 375 px, light and dark (the pages): no page error, no console error,
// no horizontal scroll. Env: BASE_URL, CREDS (topics_user: a reader made after the stories), PLAYWRIGHT, SHOTS.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import { BASE, COMBOS, H, SHOTS, check, creds, dismissToasts, finish, json, open, pw, scrollCheck, settle, signIn, toastAfter, toastCount, tooltipOf } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

// 0.1.47: "poc" (Exploit veröffentlicht) after "exploited"
const TOPICS = ["zeroday", "exploited", "poc", "ransomware", "nopatch", "breach", "supply", "phishing", "ot"]
const QUICK = ["exploited", "zeroday", "nopatch"]
const PREFIX = "E2E Thema:"
async function until(fn, ms = 8000, step = 250) {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn().catch(() => false)
    if (v || Date.now() > end) return v
    await new Promise((r) => setTimeout(r, step))
  }
}
const qs = (o) => {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(o)) for (const x of [v].flat()) if (x !== undefined) p.append(k, x)
  return p.toString()
}
const api = (ctx, o) => json(ctx, `/api/news?${qs({ state: "all", limit: 120, ...o })}`)
const ours = (items) =>
  items
    .filter((i) => i.title.startsWith(PREFIX))
    .map((i) => i.title)
    .sort()
// the card's title (an unread card's heading starts with the screen readers' "Ungelesen:")
const shownTitles = async (p) =>
  (await p.locator("main article h3").allInnerTexts())
    .map((x) => x.trim())
    .filter((x) => x.includes(PREFIX))
    .map((x) => x.slice(x.indexOf(PREFIX)))
    .sort()
const card = (p, part) => p.locator("main article").filter({ hasText: part }).first()

async function flows(browser, combo, t) {
  const tag = `${combo.lang} topics`
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.topics_user, creds.topics_password)
  const p = r.page
  const h = await H(r.ctx)
  const all = await api(r.ctx, {})
  const story = (part) => all.items.find((i) => i.title.includes(part))
  // the "Thema" filter: explanations and the API's numbers
  await p.goto(`${BASE}/`)
  await settle(p)
  await p.getByRole("button", { name: new RegExp(`^${t("news.filterTopic")}`) }).click()
  const opts = p.getByRole("option")
  await opts.first().waitFor({ timeout: 5000 })
  const rows = (await opts.allInnerTexts()).map((x) => x.replace(/\s+/g, " ").trim())
  const counts = all.counts.topics
  const ok = TOPICS.every((x) =>
    rows.some((row) => row.startsWith(t(`news.topic.${x}`)) && row.includes(t(`news.topicHint.${x}`).slice(0, 25)) && row.endsWith(String(counts[x] ?? 0))),
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "topic filter", SHOTS && `${combo.lang}-topic_filter`)
  await p.keyboard.press("Escape")
  check(`${tag}: "${t("news.filterTopic")}" – ${TOPICS.length} topics with their explanation and the API's numbers`, rows.length === TOPICS.length && ok, {
    rows: rows.map((x) => x.slice(0, 30) + "…" + x.slice(-4)),
    counts,
  })
  // quick chips: OR among topics, AND with the severity
  const quick = p.getByRole("toolbar", { name: t("news.quickTopics") })
  const chipNames = (await quick.getByRole("button").allInnerTexts()).map((x) => x.replace(/\s*\d+$/, "").trim())
  check(`${tag}: quick chips ${QUICK.map((x) => t(`news.topic.${x}`)).join(" / ")}`, JSON.stringify(chipNames) === JSON.stringify(QUICK.map((x) => t(`news.topic.${x}`))), {
    chipNames,
  })
  await quick.getByRole("button", { name: new RegExp(`^${t("news.topic.zeroday")}`) }).click()
  await settle(p)
  await quick.getByRole("button", { name: new RegExp(`^${t("news.topic.nopatch")}`) }).click()
  await settle(p)
  const u = new URL(p.url()).searchParams.getAll("topic").sort()
  const orWant = ours((await api(r.ctx, { topic: ["zeroday", "nopatch"] })).items)
  const orShown = await shownTitles(p)
  check(
    `${tag}: "${t("news.topic.zeroday")}" + "${t("news.topic.nopatch")}" – ?topic= both, the stories of either (${orWant.length})`,
    JSON.stringify(u) === '["nopatch","zeroday"]' && JSON.stringify(orShown) === JSON.stringify(orWant) && orWant.length === 3,
    {
      u,
      orShown,
    },
  )
  await p.goto(`${BASE}/?topic=zeroday&topic=nopatch&severity=critical`)
  await settle(p)
  const andWant = ours((await api(r.ctx, { topic: ["zeroday", "nopatch"], severity: "critical" })).items)
  const andShown = await shownTitles(p)
  check(`${tag}: … and severity "critical" – only the critical ones of them (${andWant.length})`, JSON.stringify(andShown) === JSON.stringify(andWant) && andWant.length === 2, {
    andShown,
  })
  // a bogus topic
  await p.goto(`${BASE}/?topic=zeroday&topic=bogus&topic=%3Cb%3E`)
  await settle(p)
  const bogus = await shownTitles(p)
  check(
    `${tag}: ?topic=bogus is dropped – the zero-days only, no error`,
    JSON.stringify(bogus) === JSON.stringify(ours((await api(r.ctx, { topic: "zeroday" })).items)) && r.errors.length === 0,
    { bogus },
  )
  // badges
  await p.goto(`${BASE}/`)
  await settle(p)
  const four = card(p, "Zero-day exploited by ransomware gang")
  const badges = (await four.locator("[data-slot=badge], span.inline-flex > span").allInnerTexts()).map((x) => x.trim()).filter((x) => x)
  const plus = four.locator("span[aria-label]").filter({ hasText: /^\+\d$/ })
  const plusLabel = (await plus.getAttribute("aria-label").catch(() => "")) ?? ""
  const tip = (await plus.count()) ? await tooltipOf(p, plus) : ""
  const want2 = [t("news.topic.zeroday"), t("news.topic.exploited")]
  const rest = `${t("news.topic.ransomware")}, ${t("news.topic.nopatch")}`
  const text4 = await four.innerText()
  check(
    `${tag}: a card with four topics – "${want2.join('", "')}" and "+2" (${rest})`,
    want2.every((x) => text4.includes(x)) && !text4.includes(t("news.topic.ransomware")) && plusLabel === rest && tip.includes(rest),
    {
      plusLabel,
      tip,
      badges: badges.slice(0, 6),
    },
  )
  await four.getByText(t("news.topic.zeroday"), { exact: true }).click()
  await p.waitForTimeout(600)
  check(`${tag}: a click on a badge opens no drawer`, !new URL(p.url()).searchParams.get("story") && (await p.locator("[data-slot=sheet-content]").count()) === 0)
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "cards with badges", SHOTS && `${combo.lang}-topic_badges`)
  // the drawer's "Themen"
  const s4 = story("Zero-day exploited by ransomware gang")
  await p.goto(`${BASE}/?story=${s4.id}`)
  await settle(p)
  const sheet = p.locator("[data-slot=sheet-content]")
  const block = sheet.locator("section").filter({ has: p.getByRole("heading", { name: t("news.topicsTitle") }) })
  const btext = ((await block.innerText().catch(() => "")) || "").replace(/\s+/g, " ")
  check(
    `${tag}: the drawer's "${t("news.topicsTitle")}" – four topics with what they rest on`,
    ["zeroday", "exploited", "ransomware", "nopatch"].every((x) => btext.includes(t(`news.topic.${x}`))) && btext.includes(t("news.topicWhy.title", { value: "§" }).split("§")[0]),
    {
      btext: btext.slice(0, 200),
    },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "drawer topics", SHOTS && `${combo.lang}-drawer_topics`)
  // not exploited, the CRA press release
  const notEx = story("Example Server flaw fixed")
  const cra = story("Cyber Resilience Act")
  await p.goto(`${BASE}/?story=${notEx.id}`)
  await settle(p)
  const noBlock =
    (await p
      .locator("[data-slot=sheet-content]")
      .getByRole("heading", { name: t("news.topicsTitle") })
      .count()) === 0
  check(
    `${tag}: "not known to be actively exploited" – no topic (no badge, no "${t("news.topicsTitle")}"); the CRA press release – ${cra?.severity}, not "${t("news.topic.exploited")}"`,
    notEx.topics?.length === 0 && noBlock && cra && cra.severity !== "critical" && !(cra.topics ?? []).includes("exploited"),
    { notEx: notEx.topics, cra: cra && [cra.severity, cra.topics] },
  )
  // "Quelle": grouped by kind with "Alle: …"
  await p.goto(`${BASE}/`)
  await settle(p)
  await p.getByRole("button", { name: new RegExp(`^${t("news.filterSource")}`) }).click()
  const heads = await p.locator("[cmdk-group-heading]").allInnerTexts()
  const alls = (await p.getByRole("option").allInnerTexts()).filter((x) => x.startsWith(t("news.allOfGroup", { group: "§" }).split("§")[0]))
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "source filter", SHOTS && `${combo.lang}-source_filter`)
  await p.keyboard.press("Escape")
  check(
    `${tag}: "${t("news.filterSource")}" grouped by kind (${heads.join(", ")}), each with "${t("news.allOfGroup", { group: "…" })}"`,
    heads.length >= 3 && alls.length >= 2 && heads.includes(t("settings.news.cat.press")),
    {
      heads,
      alls,
    },
  )
  // a saved view with topics
  for (const v of (await json(r.ctx, "/api/me/views?page=news")).items) await r.ctx.request.delete(`${BASE}/api/me/views/${v.id}`, { headers: h })
  await p.goto(`${BASE}/?topic=ransomware&topic=supply`)
  await settle(p)
  await p
    .getByRole("button", { name: t("reader.views.title") })
    .first()
    .click()
  const pop = p.locator("[data-slot=popover-content]")
  const vname = `E2E Themen ${crypto.randomBytes(2).toString("hex")}`
  await pop
    .getByRole("textbox", { name: t("reader.views.name") })
    .last()
    .fill(vname)
  await pop
    .getByRole("button", { name: t("reader.views.save") })
    .last()
    .click()
  const view = await until(async () => (await json(r.ctx, "/api/me/views?page=news")).items.find((v) => v.name === vname))
  await p.keyboard.press("Escape")
  check(`${tag}: a saved view keeps its topics`, !!view && view.query.includes("topic=ransomware") && view.query.includes("topic=supply"), { query: view?.query })
  for (const v of (await json(r.ctx, "/api/me/views?page=news")).items) await r.ctx.request.delete(`${BASE}/api/me/views/${v.id}`, { headers: h })
  // "Alle als gelesen" with only a topic
  const mine = all.items.filter((i) => i.title.startsWith(PREFIX))
  for (const i of mine) await r.ctx.request.delete(`${BASE}/api/news/${i.id}/read`, { headers: h })
  await p.goto(`${BASE}/?topic=phishing`)
  await settle(p)
  const b = await toastCount(p)
  await p.getByRole("button", { name: t("news.readAll") }).click()
  await p
    .getByRole("dialog")
    .filter({ hasText: t("news.readAllTitle") })
    .getByRole("button", { name: t("news.readAll") })
    .click()
  await toastAfter(p, b)
  await p.waitForTimeout(600)
  const after = await api(r.ctx, {})
  const unreadOurs = after.items.filter((i) => i.title.startsWith(PREFIX) && i.unread).map((i) => i.title)
  const phishing = after.items.find((i) => i.title.includes("Phishing campaign"))
  check(
    `${tag}: "${t("news.readAll")}" with only "${t("news.topic.phishing")}" – that story read, the other ${mine.length - 1} still unread`,
    phishing && !phishing.unread && unreadOurs.length === mine.length - 1,
    {
      unread: unreadOurs.length,
    },
  )
  await dismissToasts(p)
  // Vendor News: a topic is no filter there and not stored in a view
  await p.goto(`${BASE}/vendor?topic=exploited`)
  await settle(p)
  const vb = p.getByRole("button", { name: new RegExp(`^${t("reader.views.current")} `) })
  const label = (await vb.getAttribute("aria-label")) ?? ""
  for (const v of (await json(r.ctx, "/api/me/views?page=vendor")).items) await r.ctx.request.delete(`${BASE}/api/me/views/${v.id}`, { headers: h })
  await vb.click()
  const vname2 = `E2E Vendor ${crypto.randomBytes(2).toString("hex")}`
  await pop
    .getByRole("textbox", { name: t("reader.views.name") })
    .last()
    .fill(vname2)
  await pop
    .getByRole("button", { name: t("reader.views.save") })
    .last()
    .click()
  const vview = await until(async () => (await json(r.ctx, "/api/me/views?page=vendor")).items.find((v) => v.name === vname2))
  await p.keyboard.press("Escape")
  check(
    `${tag}: /vendor?topic=exploited – "${t("reader.views.current")} ${t("reader.views.standard")}", a view saved there has no topic`,
    label.includes(` ${t("reader.views.standard")} (`) && !!vview && !vview.query.includes("topic"),
    {
      label,
      query: vview?.query,
    },
  )
  for (const v of (await json(r.ctx, "/api/me/views?page=vendor")).items) await r.ctx.request.delete(`${BASE}/api/me/views/${v.id}`, { headers: h })
  check(`${combo.lang}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

async function pages(browser, combo) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme}`
  const t = texts(lang)
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.topics_user, creds.topics_password)
  await r.page.goto(`${BASE}/?topic=exploited`)
  await settle(r.page)
  await scrollCheck(r.page, tag, "news with a topic", SHOTS && `${lang}-${width}-${theme}-news_topic`)
  await r.page.getByRole("button", { name: new RegExp(`^${t("news.filterTopic")}`) }).click()
  await scrollCheck(r.page, tag, "topic filter open", false)
  await r.page.keyboard.press("Escape")
  check(`${tag} pages: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) {
    if (combo.wide) await flows(browser, combo, texts(combo.lang))
    else await pages(browser, combo)
  }
} finally {
  await browser.close()
}
finish()
