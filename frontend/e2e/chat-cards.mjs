// Browser check (0.1.46): the chat card of every channel type and of the team forward.
// Runs against a throwaway backend whose outgoing notification requests are answered by a local capture (the app's own
// test hook, notify.transport – CAPTURE_DIR holds one JSON file per request): no real Discord, Slack, Teams, Telegram,
// ntfy or Gotify is ever asked.
// - Test sends of Discord, Teams, Slack, Mattermost, Telegram, ntfy, Gotify and webhook: the newest story's card with
//   Produkt (its affected product), Quelle, Kategorie (severity and topics) and the short description in each platform's
//   form; the webhook's JSON carries `topics` and `product`.
// - A rule round (ROUND_CMD: one notify.dispatch with the capture) with more than three new stories: the compact list;
//   a Vendor News event of the old key cisco-sma: the card names "Cisco Secure Email Gateway (ESA)" (today's label).
// - Team forward of a story and a finding through Slack, Teams and Discord (UI: "Ans Team weiterleiten"): the card's
//   fields, the finding's Dringlichkeit and "Eure Versionen", the comment as a field of its own ("Kommentar") with its
//   link defused and no mention.
// DE and EN (1280 px light) – the forward dialog also at 375 px dark: no page error, no console error, no horizontal
// scroll. Env: BASE_URL, CREDS, PLAYWRIGHT, SHOTS, CAPTURE_DIR, ROUND_CMD, DB_CMD.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import { execSync } from "node:child_process"
import fs from "node:fs"
import path from "node:path"
import { BASE, COMBOS, H, SHOTS, check, creds, dismissToasts, finish, json, open, pw, scrollCheck, settle, signIn, toastAfter, toastCount } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const CAPTURE = process.env.CAPTURE_DIR || ""
const ROUND = process.env.ROUND_CMD || ""
const DB_CMD = process.env.DB_CMD || ""
if (!CAPTURE || !ROUND || !DB_CMD) throw new Error("CAPTURE_DIR, ROUND_CMD and DB_CMD are needed (a capture backend of the throwaway instance)")
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
/** The requests captured since `since` (ms) to `host` (and path part). */
function captured(since, host, part = "") {
  return fs
    .readdirSync(CAPTURE)
    .filter((f) => f.endsWith(".json"))
    .map((f) => JSON.parse(fs.readFileSync(path.join(CAPTURE, f), "utf8")))
    .filter((x) => x.at * 1000 >= since && x.host === host && x.path.includes(part))
    .sort((a, b) => a.at - b.at)
}
const LABELS = {
  de: {
    product: "Produkt",
    source: "Quelle",
    category: "Kategorie",
    comment: "Kommentar",
    urgency: "Dringlichkeit",
    versions: "Eure Versionen",
    many: (n) => `${n} neue Security-Meldungen`,
  },
  en: { product: "Product", source: "Source", category: "Category", comment: "Comment", urgency: "Urgency", versions: "Your versions", many: (n) => `${n} new security stories` },
}
const rand = () => crypto.randomBytes(3).toString("hex")
// who forwards (a member of team Netzwerk each – ten forwards an hour per person) and where in the stories to start
// (the same thing to the same team only once in ten minutes): de, en, de 375 px, en 375 px – a second run within the
// hour sets others (FORWARD_USERS, FORWARD_START)
const FWD = (process.env.FORWARD_USERS || "layout_team,reader6,watcher,reader").split(",")
const START = Number(process.env.FORWARD_START || 0)
const CHANNELS = [
  ["discord", { url: `https://discord.com/api/webhooks/123456789012/e2e_${rand()}` }, "discord.com"],
  ["teams", { url: `https://e2e.webhook.office.com/webhookb2/e2e-${rand()}` }, "e2e.webhook.office.com"],
  ["slack", { url: `https://hooks.slack.com/services/T0E2E/B0E2E/e2e${rand()}` }, "hooks.slack.com"],
  ["mattermost", { url: `https://mm.corp.example/hooks/e2e${rand()}abcdef` }, "mm.corp.example"],
  ["telegram", { bot_token: `123456789:${"E2E".repeat(11)}`, chat_id: "-1001234567890" }, "api.telegram.org"],
  ["ntfy", { server_url: "https://ntfy.corp.example", topic: `e2e-${rand()}` }, "ntfy.corp.example"],
  ["gotify", { server_url: "https://gotify.corp.example", token: `E2Etoken${rand()}` }, "gotify.corp.example"],
  ["webhook", { url: `https://hooks.corp.example/e2e-${rand()}` }, "hooks.corp.example"],
]

async function channels(a) {
  const h = await H(a.ctx)
  const made = {}
  for (const [type, cfg] of CHANNELS) {
    const r = await a.ctx.request.post(`${BASE}/api/admin/notify/channels`, { data: { name: `E2E Karte ${type} ${rand()}`, type, ...cfg }, headers: h })
    const body = await r.json().catch(() => ({}))
    made[type] = body.item?.id ?? body.id
    if (!r.ok()) console.log(`note: channel ${type}: ${r.status()} ${JSON.stringify(body).slice(0, 160)}`)
  }
  return made
}

async function testSends(a, combo, made, story) {
  const tag = `${combo.lang} test send`
  const L = LABELS[combo.lang]
  const h = await H(a.ctx)
  for (const [type, , host] of CHANNELS) {
    const since = Date.now() - 200
    const r = await a.ctx.request.post(`${BASE}/api/admin/notify/channels/${made[type]}/test`, { data: { lang: combo.lang }, headers: h })
    const ok = (await r.json().catch(() => ({}))).ok === true
    const got = await until(async () => captured(since, host).at(-1), 6000)
    const body = got?.body ?? ""
    // Discord's and Teams' markdown escapes ("PAN\\-OS") left out for the comparison
    const flat = body
      .replace(/\\u00a0/g, " ")
      .replace(/\\n/g, "\n")
      .replace(/\\/g, "")
    const has = (s) => flat.includes(s)
    let fields
    if (type === "webhook") {
      const j = JSON.parse(body || "{}")
      const s = j.stories?.[0] ?? j.items?.[0] ?? j
      fields = Array.isArray(s.topics) && s.topics.includes("nopatch") && typeof s.product === "string" && s.product.includes(story.product)
    } else fields = has(L.product) && has(story.product) && has(L.source) && has(L.category) && has(story.brief)
    check(
      `${tag}: ${type} – sent (captured), the card with ${L.product} "${story.product}", ${L.source}, ${L.category}${type === "webhook" ? " – the JSON with topics and product" : " and the short description"}`,
      ok && !!got && fields,
      {
        ok,
        got: !!got,
        sample: body.slice(0, 220),
      },
    )
  }
}

async function roundFlow(a, combo, made) {
  const tag = `${combo.lang} rule round`
  const L = LABELS[combo.lang]
  const h = await H(a.ctx)
  const rule = await a.ctx.request.post(`${BASE}/api/admin/notify/rules`, {
    data: { name: `E2E Karten ${rand()}`, channels: [made.slack], severities: ["critical", "high", "medium", "low", "info"], kinds: ["news", "vendor_vuln"], lang: combo.lang },
    headers: h,
  })
  const rid = (await rule.json()).id ?? (await rule.json()).item?.id
  await sleep(1200)
  // four stories arriving after the rule, and a Vendor News event of the old key cisco-sma
  const at = new Date().toISOString()
  const tagS = rand()
  sql(`WITH c AS (INSERT INTO counters (name, value) VALUES ('news_seq', 4) ON CONFLICT (name) DO UPDATE SET value = counters.value + 4 RETURNING value)
INSERT INTO news_items (id, source_id, url, url_key, title, title_key, summary, content_html, published_at, fetched_at, severity, reasons, cves, also_in, backlog, search, seq, topics)
SELECT gen_random_uuid(), (SELECT id FROM news_sources WHERE key = 'bleepingcomputer'), 'https://news.example.com/cards/${tagS}/' || g, 'cards-${tagS}-' || g, 'E2E Karte ${tagS} ' || g, 'e2e karte ${tagS} ' || g,
'Card check.', '', '${at}', '${at}', 'high', '[]', '[]', '[]', false, 'e2e karte ${tagS} ' || g, c.value - 4 + g, '["ransomware"]' FROM c, generate_series(1, 4) g;
INSERT INTO vendor_events (id, key, kind, product, severity, data, baseline, scope, created_at)
VALUES (gen_random_uuid(), 'vuln:cisco-sma:15.0.1:nvd:CVE-2026-7101:${tagS}', 'vuln', 'cisco-sma', 'high',
'{"product": "cisco-sma", "version": "15.0.1", "status": "affected", "ident": "CVE-2026-7101", "headline": "E2E Karte ${tagS}", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-7101", "cves": ["CVE-2026-7101"]}',
false, 'vuln:cisco-sma:15.0.1', '${at}');`)
  const since = Date.now() - 200
  execSync(ROUND, { stdio: "ignore", shell: "/bin/sh" })
  const sent = captured(since, "hooks.slack.com")
  const all = sent.map((x) => x.body).join("\n")
  // the four stories (and the event, when it comes in the same round) as one summary
  const many = (x) => [4, 5].some((n) => x.body.includes(L.many(n)))
  const list = sent.find(many)
  const compact = !!list && !JSON.parse(list.body).blocks?.some((b) => Array.isArray(b.fields))
  check(`${tag}: four new stories – one compact list ("${L.many(4)}" or five with the event, no card fields)`, compact, {
    n: sent.length,
    heads: sent.map((x) => (JSON.parse(x.body).text ?? "").slice(0, 60)),
  })
  check(
    `${tag}: a Vendor News event of the old key cisco-sma – the card says "Cisco Secure Email Gateway (ESA)"`,
    all.includes("Cisco Secure Email Gateway (ESA)") && all.includes("CVE-2026-7101"),
    {
      found: all.includes("CVE-2026-7101"),
    },
  )
  if (rid) await a.ctx.request.delete(`${BASE}/api/admin/notify/rules/${rid}`, { headers: h })
}

async function forwardFlow(browser, a, combo, made, t, who, start, only = null) {
  const tag = `${combo.lang} forward`
  const L = LABELS[combo.lang]
  const ah = await H(a.ctx)
  const teams = await json(a.ctx, "/api/admin/teams")
  const net = (teams.items ?? teams).find((x) => x.name === "Netzwerk")
  const r = await open(browser, combo)
  await signIn(r.ctx, creds[`${who}_user`] ?? creds[who], creds[`${who}_password`])
  const p = r.page
  const news = (await json(r.ctx, "/api/news?state=all&limit=120")).items.filter((i) => i.title.startsWith("E2E Thema:"))
  const findings = ((await json(r.ctx, "/api/vendor/products/panos?all=true&limit=50")).findings ?? []).filter((f) => f.cves?.length)
  const comment = `Bitte prüfen @everyone <@123> https://evil.example/x [klick](https://evil.example) **fett**`
  let n = start
  for (const [type, host] of [
    ["slack", "hooks.slack.com"],
    ["teams", "e2e.webhook.office.com"],
    ["discord", "discord.com"],
  ].filter(([type]) => !only || only.includes(type))) {
    const cur = await json(a.ctx, "/api/admin/teams")
    const team = (cur.items ?? cur).find((x) => x.id === net.id)
    await a.ctx.request.patch(`${BASE}/api/admin/teams/${net.id}`, { data: { forward_channel_id: made[type], version: team.version }, headers: ah })
    for (const what of only ? ["story"] : ["story", "finding"]) {
      const s = news[Math.floor(n / 2) % news.length]
      const f = findings[Math.floor(n / 2) % findings.length]
      n++
      await p.goto(what === "story" ? `${BASE}/?story=${s.id}` : `${BASE}/vendor?product=panos&finding=${encodeURIComponent(f.id)}`)
      await settle(p)
      const sheet = p.locator("[data-slot=sheet-content]")
      const btn =
        what === "story"
          ? sheet.getByRole("button", { name: t("forward.button") }).first()
          : sheet
              .locator(`li[data-finding="${f.id}"]`)
              .getByRole("button", { name: t("forward.button") })
              .first()
      await btn.click()
      const dlg = p.getByRole("dialog").filter({ hasText: t("forward.title") })
      await dlg.waitFor({ timeout: 6000 })
      await dlg.locator("textarea").fill(comment)
      if (combo.width < 768 || (type === "slack" && what === "story"))
        await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "forward dialog", SHOTS && `${combo.lang}-${combo.width}-${combo.theme}-forward_dialog`)
      const since = Date.now() - 200
      const b = await toastCount(p)
      await dlg.getByRole("button", { name: t("forward.send") }).click()
      const toast = await toastAfter(p, b)
      const got = await until(async () => captured(since, host).at(-1), 6000)
      const raw = got?.body ?? ""
      const body = raw.replace(/\\u00a0/g, " ").replace(/\\/g, "") // Discord's and Teams' markdown escapes left out
      const has = (x) => body.includes(x)
      const fields = has(L.source) && has(L.category) && (what === "story" || (has(L.urgency) && has(L.versions)))
      const noMention = type !== "discord" || JSON.parse(raw || "{}").allowed_mentions?.parse?.length === 0
      check(
        `${tag}: ${what} through ${type} – the card (${L.source}, ${L.category}${what === "finding" ? `, ${L.urgency}, ${L.versions}` : ""}), "${L.comment}" as its own field, the link defused, no mention`,
        !!toast && toast.type === "success" && !!got && fields && has(L.comment) && has("evil[.]example") && !has("https://evil.example") && !has("<@123>") && noMention,
        { toast: toast?.text, got: !!got, sample: body.slice(0, 260) },
      )
      await dismissToasts(p)
      await p.keyboard.press("Escape")
    }
  }
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) {
    if (!combo.wide && !(combo.width < 768 && combo.theme === "dark")) continue
    const t = texts(combo.lang)
    const a = await open(browser, combo)
    await signIn(a.ctx, creds.user, creds.password, true)
    if (combo.wide) {
      // the newest story: the PAN-OS story with its affected product (story details)
      sql(`UPDATE news_items SET published_at = now() + interval '1 minute', topics = '["nopatch"]' WHERE url_key = 'pan-1001-e2e';`)
      const d = await json(a.ctx, `/api/news?state=all&limit=1`)
      const top = d.items[0]
      const det = await json(a.ctx, `/api/news/${top.id}`)
      const product = (det.affects ?? [])[0]?.label ?? "PAN-OS"
      const brief = (top.summary ?? "").slice(0, 30)
      const made = await channels(a)
      await testSends(a, combo, made, { product, brief })
      await roundFlow(a, combo, made)
      await forwardFlow(browser, a, combo, made, t, FWD[combo.lang === "de" ? 0 : 1], START + (combo.lang === "de" ? 0 : 6))
      const h = await H(a.ctx)
      for (const id of Object.values(made)) if (id) await a.ctx.request.delete(`${BASE}/api/admin/notify/channels/${id}`, { headers: h })
    } else {
      const made = await channels(a)
      await forwardFlow(browser, a, combo, made, t, FWD[combo.lang === "de" ? 2 : 3], START + (combo.lang === "de" ? 12 : 14), ["slack"])
      const h = await H(a.ctx)
      for (const id of Object.values(made)) if (id) await a.ctx.request.delete(`${BASE}/api/admin/notify/channels/${id}`, { headers: h })
    }
    check(`${combo.lang} ${combo.width}px admin: no page or console errors`, a.errors.length === 0, a.errors.slice(0, 3))
    await a.ctx.close()
  }
} finally {
  await browser.close()
}
finish()
