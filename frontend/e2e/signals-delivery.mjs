// Browser check (0.1.36): Dringlichkeit, "An mein Team weiterleiten", Ruhezeiten, Abwesenheit mit Vertretung, Wochenrückblick.
// a) Dringlichkeit: the card's pill "N · Sofort/Bald/Beobachten" (N as the API says) with the breakdown in its tooltip;
//    the list's column, sortable; the filter "Sofort"; in the drawer the sort "Dringlichkeit" asks ?sort=score and shows
//    the findings in the API's order.
// b) Weiterleiten: a reader in a team with a forward channel – the button at a story and at a finding opens the dialog,
//    the comment's textarea grows with the text; sending answers with a toast (success to the check's own receiver,
//    when FORWARD_RECEIVER is set; an error for a channel to a refused target). Without a channel the button is off,
//    with a tooltip. The admin chooses the channel in the team drawer, "Allgemein".
// c) "Hersteller-News meiner Produkte": the sub-tabs; Ruhezeiten saved (the time zone a popper select); an absence with a
//    deputy – the team drawer's members say "Abwesend bis … – vertreten durch …", the deputy sees "Du vertrittst
//    gerade …"; the admin enters an absence for a member (calendar button) and switches the team's "Wochenrückblick" on
//    (weekday, time); without a mail server the hint.
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll (page, drawers,
// dialogs). What is changed is changed once per language (the wide light run) and set back at the end.
//
// Only against a throwaway instance (own database and DATA_DIR, never the live one) – docs/BETRIEB.md, "Entwicklung / Tests".
// It expects: Teams on, e-mail and Microsoft Teams allowed, no mail server; panos followed with 11.2.4-h23 and findings
// of different urgency (one "Sofort"), a story of CVE-2026-1001; team "Netzwerk" (the reader, the admin, Person 2, Person
// 4) with a webhook forward channel to FORWARD_RECEIVER, team "Server" (the reader) with one to a refused target
// (127.0.0.1), team "Labor" without a channel (reader3).
// Env: BASE_URL (vite dev server), CREDS (JSON {user, password, totp, reader, reader_password, reader3, reader3_password}
// – never printed), PLAYWRIGHT (…/node_modules/playwright/index.mjs), SHOTS (optional folder for screenshots),
// FORWARD_RECEIVER (optional host:port – a receiver started here, on an address the instance allows in
// WEBHOOK_PRIVATE_NETS; never loopback, the app refuses that). Uses the installed Google Chrome (channel "chrome") –
// never downloads a browser. Notifications stubbed, never granted. Nothing leaves the machine.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import fs from "node:fs"
import http from "node:http"

const BASE = (process.env.BASE_URL || "http://127.0.0.1:5250").replace(/\/$/, "")
const creds = JSON.parse(fs.readFileSync(process.env.CREDS || "", "utf8"))
const SHOTS = process.env.SHOTS || ""
const RECEIVER = process.env.FORWARD_RECEIVER || ""
const { chromium } = await import(process.env.PLAYWRIGHT || "playwright-core")

const L = {
  de: {
    level: { now: "Sofort", soon: "Bald", watch: "Beobachten" },
    scoreTitle: "Dringlichkeit",
    list: "Liste",
    toList: "Als Liste anzeigen",
    actionField: "Handlungsbedarf",
    sortScore: "Dringlichkeit – die dringendsten zuerst",
    forward: "Ans Team weiterleiten",
    forwardTitle: "An mein Team weiterleiten",
    send: "Weiterleiten",
    cancel: "Abbrechen",
    sent: (team) => `An „${team}“ weitergeleitet.`,
    noChannel: "Für deine Teams ist noch kein Weiterleitungs-Kanal festgelegt.",
    parts: ["Wege & Inhalte", "Ruhezeiten", "Abwesenheit", "Wochenrückblick"],
    quiet: "Ruhezeiten",
    save: "Speichern",
    pickDeputy: "Vertretung wählen",
    search: "Mitglieder durchsuchen",
    deputyLine: (who) => `vertreten durch ${who}`,
    covering: "Du vertrittst gerade",
    editFor: (name) => `Abwesenheit von ${name} eintragen`,
    noSmtp: "Es ist noch kein E-Mail-Server eingerichtet",
    teamWeekly: "Wochenrückblick verschicken",
    friday: "Freitag",
    general: "Allgemein",
    members: "Mitglieder",
    weekly: "Wochenrückblick",
    noForward: "Kein Kanal (Weiterleiten aus)",
  },
  en: {
    level: { now: "Now", soon: "Soon", watch: "Watch" },
    scoreTitle: "Urgency",
    list: "List",
    toList: "Show as a list",
    actionField: "Action needed",
    sortScore: "Urgency – most urgent first",
    forward: "Forward to team",
    forwardTitle: "Forward to my team",
    send: "Forward",
    cancel: "Cancel",
    sent: (team) => `Forwarded to “${team}”.`,
    noChannel: "None of your teams has a forward channel yet.",
    parts: ["Ways & content", "Quiet hours", "Absence", "Weekly review"],
    quiet: "Quiet hours",
    save: "Save",
    pickDeputy: "Choose deputy",
    search: "Search members",
    deputyLine: (who) => `deputy ${who}`,
    covering: "You are standing in for",
    editFor: (name) => `Enter an absence for ${name}`,
    noSmtp: "No mail server is set up yet",
    teamWeekly: "Send a weekly review",
    friday: "Friday",
    general: "General",
    members: "Members",
    weekly: "Weekly review",
    noForward: "No channel (forwarding off)",
  },
}
const ADMIN_NAME = "Anna Admin"
const READER_NAME = "Person 1"
const MEMBER = "Person 2"
const MEMBER_DEPUTY = "Person 4"

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

// the forward receiver: counts what arrives, never prints it
const received = []
let server = null
if (RECEIVER) {
  const [host, port] = RECEIVER.split(":")
  server = http.createServer((req, res) => {
    let body = ""
    req.on("data", (c) => (body += c))
    req.on("end", () => {
      received.push({ method: req.method, body })
      res.writeHead(200, { "content-type": "text/plain" })
      res.end("ok")
    })
  })
  await new Promise((ok) => server.listen(Number(port), host, ok))
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

async function signIn(ctx, page, user, password, code) {
  const req = ctx.request
  await req.get(`${BASE}/api/auth/config`)
  const h = { "X-CSRF-Token": await csrfOf(ctx) }
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

/** No horizontal scroll: the page, an open drawer, an open dialog. */
async function scrollCheck(page, tag, name, shot) {
  const s = await page.evaluate(() => {
    const wide = (el) => !!el && el.scrollWidth > el.clientWidth + 1
    const d = document.documentElement
    const sheet = document.querySelector("[data-slot=sheet-content]")
    const dialog = [...document.querySelectorAll("[data-slot=dialog-content]")].some(wide)
    return { ok: !wide(d) && !wide(sheet) && !dialog, page: wide(d), sheet: wide(sheet), dialog }
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

/** The newest toast: its type (success / error) and text – waits for one that was not there before. */
async function toastAfter(page, before) {
  const toasts = page.locator("[data-sonner-toast]")
  for (let i = 0; i < 40 && (await toasts.count()) <= before; i++) await page.waitForTimeout(250)
  const last = toasts.last()
  return (await toasts.count()) > before ? { type: await last.getAttribute("data-type"), text: await last.innerText() } : { type: null, text: "" }
}

function watchErrors(page) {
  const errors = []
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`))
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`)
  })
  return errors
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
const sendJson = async (ctx, method, path, data) => ctx.request.fetch(`${BASE}${path}`, { method, data, headers: { "X-CSRF-Token": await csrfOf(ctx) } })
const plusDays = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10)

// ---------------------------------------------------------------- a) Dringlichkeit

async function urgency(ctx, page, T, tag, width, shot) {
  const ov = await json(ctx, "/api/vendor/overview")
  const scored = ov.items.filter((i) => i.score)
  const top = scored.sort((a, b) => b.score.value - a.score.value)[0]
  if (!top) return check(`${tag} urgency: seed – a product with a score`, false)
  await page.goto(`${BASE}/vendor`)
  await settle(page)
  const pill = page.locator(`main [data-score]`).first()
  const value = Number(await pill.getAttribute("data-score"))
  const text = await pill.innerText()
  const tip = await tooltipOf(page, pill)
  const plus = (tip.match(/\+\d+/g) ?? []).length
  check(
    `${tag} card: "${top.score.value} · ${T.level[top.score.level]}" as the API says, the tooltip breaks it down`,
    value === top.score.value && text.includes(String(value)) && text.includes(T.level[top.score.level]) && tip.includes(`${T.scoreTitle} ${value}`) && plus >= 2,
    { value, api: top.score.value, plus },
  )
  await scrollCheck(page, tag, "overview", shot("overview"))

  // "Sofort" (0.1.43): the status row's "Handlungsbedarf" field says how many; the old link ?filter=now still filters (a chip)
  // over the products the page shows: "Mein Team" (its chip) for a team member
  const teamChip =
    (await page
      .locator("main ul li")
      .filter({ hasText: /^\s*(Mein Team|My team)\s*$/ })
      .count()) > 0
  const shownOv = teamChip ? await json(ctx, "/api/vendor/overview?scope=team") : ov
  const nowCount = shownOv.items.filter((i) => i.score?.level === "now").length
  const field = await page
    .getByRole("radio", { name: new RegExp(`^${T.actionField}: \\d+`) })
    .getAttribute("aria-label")
    .catch(() => "")
  const says = (field ?? "").endsWith(`, ${nowCount} ${T.level.now}`)
  await page.goto(`${BASE}/vendor?filter=now&status=all`)
  await settle(page)
  const filtered = await page.locator("main [data-score]").count()
  const chip =
    (await page
      .locator("main ul li")
      .filter({ hasText: new RegExp(`^\\s*${T.level.now}\\s*$`) })
      .count()) >= 1
  const others = await page
    .locator("main")
    .innerText()
    .then((b) => b.toLowerCase().includes("cisco asa"))
  check(
    `${tag} "${T.level.now}": the status row says ${nowCount}; ?filter=now – its chip, only the ${nowCount} product(s) with "now"`,
    says && chip && filtered === nowCount && !others,
    {
      field,
      chip,
      filtered,
      others,
    },
  )

  // the list: the column, sortable (wide only – a phone shows the score in the row)
  await page.goto(`${BASE}/vendor`)
  await settle(page)
  await page.getByRole("button", { name: T.toList, exact: true }).click()
  await settle(page)
  const rowScore = Number(await page.locator("main [role=table] [data-score]").first().getAttribute("data-score"))
  if (width >= 768) {
    const col = page.getByRole("columnheader", { name: new RegExp(T.scoreTitle) })
    await col.getByRole("button").click()
    await page.waitForTimeout(300)
    const sorted = await col.getAttribute("aria-sort")
    check(`${tag} list: the column "${T.scoreTitle}" sorts (most first), the row shows the score`, sorted === "descending" && rowScore === top.score.value, { sorted, rowScore })
  } else check(`${tag} list (phone): the row shows the score`, rowScore === top.score.value, { rowScore })
  await scrollCheck(page, tag, "list", false)

  // the drawer: "Dringlichkeit" asks the server with ?sort=score and keeps its order
  const api = await json(ctx, `/api/vendor/products/${top.product.key}?sort=score`)
  const want = api.findings.filter((f) => f.score && f.status !== "not_affected").map((f) => f.score.value)
  await page.goto(`${BASE}/vendor?product=${top.product.key}`)
  await settle(page)
  const sheet = page.locator("[data-slot=sheet-content]")
  const asked = []
  const onReq = (r) => r.url().includes(`/api/vendor/products/${top.product.key}`) && asked.push(new URL(r.url()).searchParams.get("sort"))
  page.on("request", onReq)
  await sheet.locator("#vendor-sort").click()
  await page.getByRole("option", { name: T.sortScore, exact: true }).click()
  await settle(page)
  page.off("request", onReq)
  const shown = (await sheet.locator("[data-score]").evaluateAll((els) => els.map((e) => Number(e.getAttribute("data-score"))))).slice(0, want.length)
  check(`${tag} drawer: "${T.sortScore}" asks ?sort=score, the findings in its order`, asked.includes("score") && JSON.stringify(shown) === JSON.stringify(want), {
    asked,
    shown,
    want,
  })
  await scrollCheck(page, tag, "drawer", shot("drawer_score"))
  return top.product.key
}

// ---------------------------------------------------------------- b) Weiterleiten

/** Opens the dialog from `button`, checks the textarea grows; with `team` it sends there and returns the toast. */
async function forwardDialog(page, T, tag, where, button, team) {
  await button.click()
  const dialog = page.getByRole("dialog", { name: T.forwardTitle })
  await dialog.waitFor({ timeout: 5000 }).catch(() => {})
  const open = (await dialog.count()) === 1
  const area = dialog.locator("textarea")
  const h0 = open ? ((await area.boundingBox())?.height ?? 0) : 0
  const marker = `e2e-${crypto.randomBytes(4).toString("hex")}`
  if (open) await area.fill(`${marker}\nZeile 2\nZeile 3\nZeile 4\nZeile 5\nZeile 6`)
  const h1 = open ? ((await area.boundingBox())?.height ?? 0) : 0
  check(`${tag} ${where}: "${T.forward}" opens the dialog, the comment's textarea grows with the text`, open && h1 > h0 + 20, { open, h0, h1 })
  await scrollCheck(page, tag, `${where} dialog`, false)
  if (!team) {
    await dialog.getByRole("button", { name: T.cancel, exact: true }).click()
    return null
  }
  const select = dialog.getByRole("combobox")
  if (await select.count()) {
    await select.click()
    await page.getByRole("option", { name: team, exact: true }).click()
  }
  const before = await page.locator("[data-sonner-toast]").count()
  await dialog.getByRole("button", { name: T.send, exact: true }).click()
  const toast = await toastAfter(page, before)
  await page.keyboard.press("Escape").catch(() => {})
  return { ...toast, marker }
}

async function forwarding(ctx, page, T, tag, lang, wide, productKey) {
  const story = await findStory(ctx, "CVE-2026-1001")
  // the finding (drawer) and the story: wide light runs send – one thing to the team with the receiver, the other to
  // the team with the refused target (de: the finding succeeds, en: the story – the same thing goes to a team only once
  // within ten minutes)
  const plan = wide ? (lang === "de" ? { finding: "Netzwerk", story: "Server" } : { finding: "Server", story: "Netzwerk" }) : {}
  for (const where of ["finding", "story"]) {
    await page.goto(where === "finding" ? `${BASE}/vendor?product=${productKey}` : `${BASE}/?story=${story?.id}`)
    await settle(page)
    const button = page.locator("[data-slot=sheet-content]").getByRole("button", { name: T.forward, exact: true }).first()
    if (!(await button.count())) {
      check(`${tag} ${where}: the button "${T.forward}"`, false)
      continue
    }
    const team = plan[where]
    const got = await forwardDialog(page, T, tag, where, button, team && (team !== "Netzwerk" || RECEIVER) ? team : null)
    if (!got) continue
    if (team === "Netzwerk") {
      await page.waitForTimeout(300)
      const arrived = received.some((r) => r.method === "POST" && r.body.includes(got.marker))
      check(`${lang} ${where} → Netzwerk: a success toast, the receiver got it (with the comment)`, got.type === "success" && got.text.includes(T.sent("Netzwerk")) && arrived, {
        type: got.type,
        arrived,
      })
    } else check(`${lang} ${where} → Server (refused target): an error toast`, got.type === "error" && got.text.length > 10, got)
  }
}

async function noChannel(browser, lang, width, theme) {
  const T = L[lang]
  const tag = `${lang} ${width}px ${theme} no channel`
  const ctx = await browser.newContext({ serviceWorkers: "block", locale: lang === "de" ? "de-DE" : "en-GB", viewport: { width, height: 860 }, colorScheme: theme })
  await stub(ctx, lang, theme)
  const page = await ctx.newPage()
  const errors = watchErrors(page)
  await signIn(ctx, page, creds.reader3, creds.reader3_password, "")
  const story = await findStory(ctx, "CVE-2026-1001")
  await page.goto(`${BASE}/?story=${story?.id}`)
  await settle(page)
  const button = page.locator("[data-slot=sheet-content]").getByRole("button", { name: T.forward, exact: true }).first()
  const off = (await button.count()) === 1 && (await button.isDisabled())
  const tip = off ? await tooltipOf(page, button.locator("xpath=..")) : ""
  check(`${tag}: "${T.forward}" off, the tooltip says why`, off && tip.includes(T.noChannel), { off, tip: tip.slice(0, 60) })
  check(`${tag}: no page or console errors`, errors.length === 0, errors.slice(0, 3))
  await ctx.close()
}

// ---------------------------------------------------------------- c) the reader's delivery settings

async function delivery(ctx, page, T, tag, wide, shot) {
  await page.goto(`${BASE}/settings/notifications?tab=vendor`)
  await settle(page)
  const card = page.locator("main")
  const tabs = []
  for (const [i, name] of T.parts.entries()) {
    const link = card.getByRole("link", { name, exact: true })
    if (!(await link.count())) {
      tabs.push(`${name}: missing`)
      continue
    }
    await link.click()
    await settle(page)
    const part = new URL(page.url()).searchParams.get("part")
    if ((await link.getAttribute("aria-current")) !== "page" || i > 0 !== !!part) tabs.push(`${name}: ${part}`)
    await scrollCheck(page, tag, `delivery ${name}`, i === 1 && shot("quiet"))
  }
  check(`${tag} "${T.parts.join(" / ")}": the sub-tabs work`, tabs.length === 0, tabs)

  // Ruhezeiten: window, a time zone from the popper list, saved
  await card.getByRole("link", { name: T.parts[1], exact: true }).click()
  await settle(page)
  const before = (await json(ctx, "/api/me/vendor-notify")).schedule
  const quiet = card.getByRole("switch", { name: T.quiet, exact: true })
  if ((await quiet.getAttribute("aria-checked")) !== "true") await quiet.click()
  const zone = card.getByRole("combobox").filter({ hasText: /\// }).first()
  await zone.click()
  const popper = await page.locator("[data-radix-popper-content-wrapper] [role=listbox]").isVisible()
  await page.getByRole("option", { name: "America/New York", exact: true }).click()
  if (wide) {
    const times = card.locator("input[type=time]")
    await times.nth(0).fill("21:30")
    await times.nth(1).fill("07:15")
    await card.getByRole("button", { name: T.save, exact: true }).click()
    await settle(page)
    const s = (await json(ctx, "/api/me/vendor-notify")).schedule
    check(
      `${tag} quiet hours: saved (21:30–07:15, America/New_York), the zone a popper select`,
      popper && s.quiet && s.from === "21:30" && s.to === "07:15" && s.tz === "America/New_York",
      {
        popper,
        saved: { quiet: s.quiet, from: s.from, to: s.to, tz: s.tz },
      },
    )
    await sendJson(ctx, "PUT", "/api/me/vendor-notify/schedule", before) // back as it was
  } else check(`${tag} quiet hours: the zone a popper select`, popper)

  // Abwesenheit with a deputy (the admin)
  await card.getByRole("link", { name: T.parts[2], exact: true }).click()
  await settle(page)
  if (wide) {
    const now = (await json(ctx, "/api/me/vendor-notify")).absence
    if (now) {
      await sendJson(ctx, "DELETE", "/api/me/vendor-notify/absence")
      await page.reload()
      await settle(page)
    }
    await card.locator("input[type=date]").nth(1).fill(plusDays(7))
    await card.getByRole("button", { name: T.pickDeputy, exact: true }).click()
    await page.getByLabel(T.search, { exact: true }).fill("Anna")
    await page.getByRole("option").filter({ hasText: ADMIN_NAME }).first().click()
    await card.getByRole("button", { name: T.save, exact: true }).click()
    await settle(page)
    const a = (await json(ctx, "/api/me/vendor-notify")).absence
    check(
      `${tag} absence: saved until ${plusDays(7)} with the deputy ${ADMIN_NAME}`,
      !!a && a.end === plusDays(7) && a.deputy?.display_name === ADMIN_NAME,
      a && { end: a.end, deputy: a.deputy?.display_name },
    )
  }
  await scrollCheck(page, tag, "absence", shot("absence"))

  // Wochenrückblick: no mail server – the hint
  await card.getByRole("link", { name: T.parts[3], exact: true }).click()
  await settle(page)
  check(`${tag} weekly review: the hint without a mail server`, (await card.innerText()).includes(T.noSmtp))
}

// ---------------------------------------------------------------- c) + b) the admin

async function admin(ctx, page, T, tag, wide, last, shot) {
  const teams = await json(ctx, "/api/admin/teams")
  const net = teams.find((t) => t.name === "Netzwerk")
  const labor = teams.find((t) => t.name === "Labor")
  const sheet = page.locator("[data-slot=sheet-content]")

  // the member list: the reader's absence – and the admin is the deputy
  await page.goto(`${BASE}/settings/teams?team=${net.id}&part=members`)
  await settle(page)
  const line = sheet.locator("li").filter({ hasText: READER_NAME }).locator("[data-member-absence]")
  const lineText = (await line.count()) ? await line.innerText() : ""
  check(`${tag} team members: "${READER_NAME}" away – "${T.deputyLine(ADMIN_NAME)}"`, lineText.includes(T.deputyLine(ADMIN_NAME)), { lineText })
  await scrollCheck(page, tag, "team members", shot("team_members"))

  // the admin enters an absence for a member (calendar button)
  if (wide) {
    const m = (await json(ctx, `/api/admin/teams/${net.id}/members?q=${encodeURIComponent(MEMBER)}&offset=0&limit=50`)).items.find((x) => x.display_name === MEMBER)
    if (m?.absence) await sendJson(ctx, "DELETE", `/api/admin/teams/${net.id}/members/${m.id}/absence`)
    await page.reload()
    await settle(page)
    await sheet.getByRole("button", { name: T.editFor(MEMBER), exact: true }).click()
    await settle(page)
    await sheet.locator("input[type=date]").nth(1).fill(plusDays(3))
    await sheet.getByRole("button", { name: T.pickDeputy, exact: true }).click()
    await page.getByLabel(T.search, { exact: true }).fill("Person 4")
    await page.getByRole("option").filter({ hasText: MEMBER_DEPUTY }).first().click()
    await sheet.getByRole("button", { name: T.save, exact: true }).click()
    await settle(page)
    const memberLine = sheet.locator("li").filter({ hasText: MEMBER }).locator("[data-member-absence]")
    const text = (await memberLine.count()) ? await memberLine.innerText() : ""
    check(`${tag} admin: an absence for "${MEMBER}" entered – "${T.deputyLine(MEMBER_DEPUTY)}"`, text.includes(T.deputyLine(MEMBER_DEPUTY)), { text })
  }

  // the deputy's view: "Du vertrittst gerade Person 1"
  await page.goto(`${BASE}/settings/notifications?tab=vendor&part=absence`)
  await settle(page)
  const body = await page.locator("main").innerText()
  check(`${tag} the deputy sees "${T.covering}" – ${READER_NAME}`, body.includes(T.covering) && body.includes(READER_NAME))

  // the team's weekly review: the hint, on with a weekday (popper) and a time
  await page.goto(`${BASE}/settings/teams?team=${net.id}&part=weekly`)
  await settle(page)
  const noSmtp = (await sheet.innerText()).includes(T.noSmtp)
  if (wide) {
    const before = net.weekly
    const on = sheet.getByRole("switch", { name: T.teamWeekly, exact: true })
    if ((await on.getAttribute("aria-checked")) !== "true") await on.click()
    await sheet.getByRole("combobox").first().click()
    const popper = await page.locator("[data-radix-popper-content-wrapper] [role=listbox]").isVisible()
    await page.getByRole("option", { name: T.friday, exact: true }).click()
    await sheet.locator("input[type=time]").fill("09:30")
    await sheet.getByRole("button", { name: T.save, exact: true }).click()
    await settle(page)
    const w = (await json(ctx, "/api/admin/teams")).find((t) => t.id === net.id).weekly
    check(
      `${tag} team weekly review: the hint without a mail server; on, Friday 09:30 saved (weekday a popper select)`,
      noSmtp && popper && w.enabled && w.weekday === 4 && w.at === "09:30",
      {
        noSmtp,
        popper,
        saved: { enabled: w.enabled, weekday: w.weekday, at: w.at },
      },
    )
    await sendJson(ctx, "PUT", `/api/admin/teams/${net.id}/weekly`, { enabled: before.enabled, weekday: before.weekday, at: before.at, tz: before.tz })
  } else check(`${tag} team weekly review: the hint without a mail server`, noSmtp)
  await scrollCheck(page, tag, "team weekly", shot("team_weekly"))

  // the forward channel, chosen in the team drawer under "Allgemein" (Labor: none → a channel → none again)
  await page.goto(`${BASE}/settings/teams?team=${labor.id}&part=general`)
  await settle(page)
  const select = sheet.getByRole("combobox").filter({ hasText: T.noForward })
  const shown = (await select.count()) === 1
  if (wide && shown) {
    await select.click()
    await page.getByRole("option", { name: /^Netzwerk-Weiterleitung/ }).click()
    await sheet.getByRole("button", { name: T.save, exact: true }).click()
    await settle(page)
    const set = (await json(ctx, "/api/admin/teams")).find((t) => t.id === labor.id).forward_channel_id
    await sheet
      .getByRole("combobox")
      .filter({ hasText: /^Netzwerk-Weiterleitung/ })
      .click()
    await page.getByRole("option", { name: T.noForward, exact: true }).click()
    await sheet.getByRole("button", { name: T.save, exact: true }).click()
    await settle(page)
    const back = (await json(ctx, "/api/admin/teams")).find((t) => t.id === labor.id).forward_channel_id
    check(`${tag} team "Allgemein": the forward channel chosen and saved, then none again`, !!set && back === null, { set: !!set, back })
  } else check(`${tag} team "Allgemein": the forward channel select`, shown)
  await scrollCheck(page, tag, "team general", false)

  // at the very end: the absences set back
  if (last) {
    for (const m of (await json(ctx, `/api/admin/teams/${net.id}/members?q=&offset=0&limit=50`)).items.filter((x) => x.absence))
      await sendJson(ctx, "DELETE", `/api/admin/teams/${net.id}/members/${m.id}/absence`)
  }
}

const browser = await chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
const usedMfa = new Set()
try {
  const runs = []
  for (const lang of ["de", "en"]) for (const width of [1280, 375]) for (const theme of ["light", "dark"]) runs.push([lang, width, theme])
  for (const [n, [lang, width, theme]] of runs.entries()) {
    const T = L[lang]
    const tag = `${lang} ${width}px ${theme}`
    const wide = width === 1280 && theme === "light"
    const shot = (name) => `${lang}-${width}-${theme}-${name}`
    const opts = { serviceWorkers: "block", locale: lang === "de" ? "de-DE" : "en-GB", viewport: { width, height: 860 }, colorScheme: theme }

    const rctx = await browser.newContext(opts)
    await stub(rctx, lang, theme)
    const rp = await rctx.newPage()
    const rerr = watchErrors(rp)
    await signIn(rctx, rp, creds.reader, creds.reader_password, "")
    const key = await urgency(rctx, rp, T, tag, width, shot)
    if (key) await forwarding(rctx, rp, T, tag, lang, wide, key)
    await delivery(rctx, rp, T, tag, wide, shot)
    check(`${tag} reader: no page or console errors`, rerr.length === 0, rerr.slice(0, 3))
    await rctx.close()

    await noChannel(browser, lang, width, theme)

    const ctx = await browser.newContext(opts)
    await stub(ctx, lang, theme)
    const page = await ctx.newPage()
    const errors = watchErrors(page)
    if (usedMfa.has(Math.floor(Date.now() / 30000))) await page.waitForTimeout(30000 - (Date.now() % 30000) + 500)
    await signIn(ctx, page, creds.user, creds.password, creds.totp)
    usedMfa.add(Math.floor(Date.now() / 30000))
    await admin(ctx, page, T, tag, wide, n === runs.length - 1, shot)
    check(`${tag} admin: no page or console errors`, errors.length === 0, errors.slice(0, 3))
    await ctx.close()
  }
} finally {
  await browser.close()
  server?.close()
}
if (!RECEIVER) console.log("note: FORWARD_RECEIVER not set – only the refused forward was sent")
const failed = results.filter((x) => !x).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed ? 1 : 0)
