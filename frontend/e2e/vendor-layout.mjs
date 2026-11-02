// Browser check (0.1.43): the Vendor News page without tabs.
// - The header line ("Nächstes Support-Ende … · abgerufen vor …"); the "⋯" menu ("Aktionen für Vendor News") per role
//   and by keyboard; the admins' "Vorschläge" button with its badge only while suggestions are open.
// - ONE status row (a radio group; its numbers as the overview API's products give them, computed as the page does;
//   click and arrow keys switch and write ?status=; 2×2 at 375 px).
// - ONE tool row: "Filter" (popover: Nur ungelesene, Stummgeschaltete zeigen, Versionen zu prüfen, Mein Team / Alle) with
//   the number on the button; removable chips; "Mein Team" as a chip by default for a team member; "Ansicht: Standard |
//   <name> | Angepasst"; the cards/list toggle kept over a reload.
// - "Alle N als gelesen": N is what is marked (the API before and after) – also with "Mein Team" (only the team's
//   products), with a muted product hidden (left unread) or shown (marked), and with a muted CVE in an unmuted product
//   hidden (its finding left unread) or shown (marked).
// - Old addresses: ?tab=catalog&product=…, ?tab=suggestions, ?filter=exploited; "← Zurück zur Übersicht" keeps the
//   overview's filters.
// Admin and reader, DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll.
// The flows run once per language (the wide light run).
// It expects (seed): layout_team (reader in team Netzwerk – panos and fortios are routed to it, cisco-asa not),
// layout_solo (reader in no team); panos with findings, cisco-asa with findings (seed143b). Env: BASE_URL, CREDS,
// PLAYWRIGHT, SHOTS.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import { BASE, COMBOS, H, SHOTS, check, creds, dismissToasts, finish, json, open, pw, scrollCheck, settle, signIn, toastAfter, toastCount } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

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

// ---------------------------------------------------------------- the page's own rules, from the API's products

const urgencyOf = (i) => {
  if (i.urgency) return i.urgency
  const c = i.counts
  if (c.exploited_affected ?? (c.affected ? c.exploited : 0)) return "exploited"
  if (c.critical_affected ?? (c.affected ? c.critical : 0)) return "critical"
  if (c.affected || i.releases.some((r) => r.eol_state === "past")) return "affected"
  if (c.possible || c.unversioned || i.releases.some((r) => r.eol_state === "soon")) return "possible"
  if (c.service) return "info"
  return "ok"
}
const statusOf = (i) => (i.counts.affected > 0 || i.releases.some((r) => r.eol_state === "past") ? "action" : urgencyOf(i) === "ok" ? "ok" : "check")
const visible = (items, f) =>
  items.filter((i) => {
    if (i.muted && !f.muted && !i.muted_kev) return false
    if (f.unread && !(i.unread ?? 0) && !(i.muted && i.muted_kev)) return false
    return true
  })
function rowCounts(items) {
  const out = { action: 0, check: 0, ok: 0, all: items.length, now: 0 }
  for (const i of items) {
    out[statusOf(i)]++
    if (statusOf(i) === "action" && i.score?.level === "now") out.now++
  }
  return out
}
const overview = (ctx, scope) => json(ctx, `/api/vendor/overview${scope === "team" ? "?scope=team" : ""}`)

// ---------------------------------------------------------------- the page

const STATUS = ["action", "check", "ok", "all"]
const statusName = (t, s) => t({ action: "vendor.show.action", check: "vendor.show.check", ok: "vendor.show.okShort", all: "vendor.show.all" }[s])
const statusRadio = (page, t, s) => page.getByRole("radiogroup", { name: t("vendor.show.label") }).getByRole("radio", { name: new RegExp(`^${esc(statusName(t, s))}: \\d+`) })
async function rowFromPage(page, t) {
  const out = {}
  for (const s of STATUS) {
    const label = (await statusRadio(page, t, s).getAttribute("aria-label")) ?? ""
    out[s] = Number(label.split(":")[1]?.split(",")[0])
    if (s === "action") out.now = Number((label.match(/,\s*(\d+)/) ?? [0, 0])[1])
  }
  return out
}
const filterButton = (page, t) => page.getByRole("button", { name: new RegExp(`^${esc(t("vendor.filters.button"))}(,|$)`) })
const popover = (page) => page.locator("[data-slot=popover-content]")
async function filterSwitch(page, t, label, on) {
  await filterButton(page, t).click()
  const sw = popover(page).getByRole("switch", { name: new RegExp(`^${esc(label)}`) })
  await sw.waitFor({ timeout: 5000 })
  if (((await sw.getAttribute("aria-checked")) === "true") !== on) await sw.click()
  await page.keyboard.press("Escape")
  await settle(page)
}
async function scopeTo(page, t, which) {
  await filterButton(page, t).click()
  await popover(page)
    .getByRole("radio", { name: t(which === "team" ? "vendor.scope.team" : "vendor.scope.all"), exact: true })
    .click()
  await page.keyboard.press("Escape")
  await settle(page)
}
const chips = (page, t) =>
  page
    .getByRole("list", { name: t("vendor.filters.active") })
    .locator("li")
    .allInnerTexts()
    .then((x) => x.map((s) => s.trim()))
    .catch(() => [])
function readAllN(page, t) {
  const one = esc(t("reader.vendorReadAllN", { count: 1 })).replace("1", "(\\d+)")
  const other = esc(t("reader.vendorReadAllN", { count: 987654 })).replace("987654", "(\\d+)")
  return page.getByRole("button", { name: new RegExp(`^(?:${one}|${other})$`) })
}
const nOf = async (btn) => ((await btn.count()) ? Number(((await btn.innerText()).match(/\d+/) ?? [NaN])[0]) : 0)
const viewButton = (page, t) => page.getByRole("button", { name: new RegExp(`^${esc(t("reader.views.current"))} .* \\(${esc(t("reader.views.title"))}\\)$`) })
const viewName = async (page, t) => {
  const l = (await viewButton(page, t).getAttribute("aria-label")) ?? ""
  return l.slice(t("reader.views.current").length + 1, l.lastIndexOf(" ("))
}

async function signedIn(browser, combo, who) {
  const r = await open(browser, combo)
  if (who === "admin") await signIn(r.ctx, creds.user, creds.password, true)
  else await signIn(r.ctx, creds[`${who}_user`], creds[`${who}_password`])
  return r
}

// ---------------------------------------------------------------- header, menu, badge

async function headerFlow(r, combo, t, role) {
  const tag = `${combo.lang} ${role} header`
  const p = r.page
  await p.goto(`${BASE}/vendor?status=all`)
  await settle(p)
  const line = (
    (await p
      .locator("[data-testid=vendor-headline]")
      .innerText()
      .catch(() => "")) || ""
  ).replace(/\s+/g, " ")
  // the scope the page shows: "Mein Team" (its chip) for a team member – the admin is one too
  const d = await overview(r.ctx, (await chips(p, t)).includes(t("vendor.scope.team")) ? "team" : "all")
  const day = new Date().toISOString().slice(0, 10)
  let next = null
  for (const i of visible(d.items, { unread: false, muted: false }))
    for (const x of i.releases) {
      const e = x.line?.eol_from
      if (e && e > day && x.eol_state !== "past" && (!next || e < next.date)) next = { label: i.product.label, date: e }
    }
  const nextOk = next
    ? line.includes(t("vendor.head.nextEnd", { product: next.label, when: "§" }).split("§")[0].trim())
    : !line.includes(t("vendor.head.nextEnd", { product: "§", when: "" }).split("§")[0])
  const fetched = d.status.fetched ? line.includes(t("vendor.head.fetched")) : line.includes(t("vendor.firstFetch").slice(0, 20))
  check(`${tag}: the line under the title – next end of support (${next?.label ?? "none"}) and when fetched`, nextOk && fetched, { line: line.slice(0, 160) })
  // the "⋯" menu by keyboard
  const more = p.getByRole("button", { name: new RegExp(`^${esc(t("vendor.head.more"))}`) })
  await more.focus()
  await p.keyboard.press("Enter")
  const menu = p.getByRole("menu")
  await menu.waitFor({ timeout: 5000 })
  const items = (await menu.getByRole("menuitem").allInnerTexts()).map((x) => x.replace(/\s*\d+$/, "").trim())
  const want =
    role === "admin"
      ? [t("vendor.head.add"), t("suggest.title"), t("suggest.tab"), t("settings.news.fetchNow"), t("vendor.settings")]
      : [t("vendor.head.browse"), t("suggest.title"), t("suggest.mine")]
  await p.keyboard.press("ArrowDown")
  const focused1 = await p.evaluate(() => document.activeElement?.getAttribute("role"))
  await p.keyboard.press("Escape")
  const back = await more.evaluate((el) => document.activeElement === el)
  check(
    `${tag}: "⋯" (${t("vendor.head.more")}) – Enter opens ${want.join(" / ")}, arrows move, Escape returns to the button`,
    JSON.stringify(items) === JSON.stringify(want) && focused1 === "menuitem" && back,
    {
      items,
      focused1,
      back,
    },
  )
  // the first entry by keyboard: the catalogue, and back
  await more.focus()
  await p.keyboard.press("Enter")
  await menu.waitFor({ timeout: 5000 })
  await p.keyboard.press("Enter") // the first entry has the focus
  await settle(p)
  const inCatalog = new URL(p.url()).searchParams.get("tab") === "catalog" && (await p.getByRole("heading", { name: t("vendor.tab.catalog") }).count()) === 1
  check(`${tag}: Enter on "${want[0]}" – the catalogue with "${t("vendor.head.back")}"`, inCatalog && (await p.getByRole("link", { name: t("vendor.head.back") }).count()) === 1)
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, `${role} catalogue`, SHOTS && `${combo.lang}-${role}-catalog`)
}

async function badgeFlow(admin, solo, combo, t) {
  const tag = `${combo.lang} admin "${t("suggest.tab")}" badge`
  const p = admin.page
  const ah = await H(admin.ctx)
  const rejectAll = async () => {
    for (const s of (await json(admin.ctx, "/api/admin/suggestions?state=open")).items)
      await admin.ctx.request.post(`${BASE}/api/admin/suggestions/${s.id}/reject`, { data: { answer: "E2E" }, headers: ah })
  }
  await rejectAll()
  await p.goto(`${BASE}/vendor`)
  await settle(p)
  const badge = (n) => p.getByRole("link", { name: t("vendor.head.suggestionsWaiting", { count: n }) })
  const none = (await p.getByRole("link", { name: new RegExp(`^${esc(t("suggest.tab"))} – `) }).count()) === 0
  const made = await solo.ctx.request.post(`${BASE}/api/vendor/suggestions`, {
    data: { vendor: "E2E Corp", product: `Layout Gateway ${crypto.randomBytes(2).toString("hex")}`, reason: "Browser check of the badge." },
    headers: await H(solo.ctx),
  })
  const open = (await json(admin.ctx, "/api/vendor/suggestions/count")).open
  await p.reload()
  await settle(p)
  const shown = await until(async () => (await badge(open).count()) === 1)
  const text = shown ? (await badge(open).innerText()).replace(/\s+/g, " ").trim() : ""
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "admin header with badge", SHOTS && `${combo.lang}-admin-badge`)
  await rejectAll()
  await p.reload()
  await settle(p)
  const gone = (await p.getByRole("link", { name: new RegExp(`^${esc(t("suggest.tab"))} – `) }).count()) === 0
  check(
    `${tag}: none without open suggestions; one open → "${t("vendor.head.suggestionsWaiting", { count: open })}" (the API's number); answered → gone`,
    none && made.ok() && open >= 1 && shown && text.endsWith(String(open)) && gone,
    {
      none,
      status: made.status(),
      open,
      text,
      gone,
    },
  )
}

// ---------------------------------------------------------------- status row, filters, chips, views, layout

async function rowFlow(r, combo, t, role) {
  const tag = `${combo.lang} ${role} status row`
  const p = r.page
  await p.goto(`${BASE}/vendor?status=action`)
  await settle(p)
  // the scope the page shows: "Mein Team" (its chip) for a team member – the admin is one too
  const team = (await chips(p, t)).includes(t("vendor.scope.team"))
  const d = await overview(r.ctx, team ? "team" : "all")
  const want = rowCounts(visible(d.items, { unread: false, muted: false }))
  const got = await rowFromPage(p, t)
  check(`${tag}: the four numbers as the API's products give them (${team ? "Mein Team" : "Alle"})`, STATUS.every((s) => got[s] === want[s]) && got.now === want.now, { got, want })
  // a click ("Alle" is the address without ?status=)
  await statusRadio(p, t, "all").click()
  await settle(p)
  const clicked = !new URL(p.url()).searchParams.get("status") && (await statusRadio(p, t, "all").getAttribute("aria-checked")) === "true"
  await statusRadio(p, t, "action").click()
  await settle(p)
  const clicked2 = new URL(p.url()).searchParams.get("status") === "action" && (await statusRadio(p, t, "action").getAttribute("aria-checked")) === "true"
  check(`${tag}: a click switches and writes the address ("${statusName(t, "action")}" → ?status=action, "${statusName(t, "all")}" → none)`, clicked && clicked2, {
    clicked,
    clicked2,
  })
  // the arrow keys (a radio group: the arrow moves to the next field – and should choose it)
  await statusRadio(p, t, "action").focus()
  await p.keyboard.press("ArrowRight")
  await settle(p)
  const focusOk = await statusRadio(p, t, "check").evaluate((el) => document.activeElement === el)
  const arrowUrl = new URL(p.url()).searchParams.get("status")
  const arrowChecked = (await statusRadio(p, t, "check").getAttribute("aria-checked")) === "true"
  check(`${tag}: ArrowRight moves to "${statusName(t, "check")}" and switches to it (?status=check)`, focusOk && arrowUrl === "check" && arrowChecked, {
    focusOk,
    arrowUrl,
    arrowChecked,
  })
  if (!arrowChecked) {
    await p.keyboard.press("Space")
    await settle(p)
    const spaceUrl = new URL(p.url()).searchParams.get("status")
    check(`${tag}: … Space on the focused field switches to it`, spaceUrl === "check" && (await statusRadio(p, t, "check").getAttribute("aria-checked")) === "true", { spaceUrl })
  }
  // 2×2 on a phone, four in a row on a wide screen
  const ys = await p
    .getByRole("radiogroup", { name: t("vendor.show.label") })
    .getByRole("radio")
    .evaluateAll((els) => [...new Set(els.map((e) => Math.round(e.getBoundingClientRect().top)))].length)
  check(`${tag}: ${combo.width < 768 ? "2×2" : "one row of four"}`, ys === (combo.width < 768 ? 2 : 1), { rows: ys })
}

async function filterFlow(r, combo, t, role) {
  const tag = `${combo.lang} ${role} filters`
  const p = r.page
  const team = role === "team"
  await p.goto(`${BASE}/vendor?status=all`)
  await settle(p)
  // a team member: "Mein Team" as a chip by default, the button says 1
  const c0 = await chips(p, t)
  const b0 = (await filterButton(p, t).getAttribute("aria-label")) ?? ""
  check(
    `${tag}: by default ${team ? `the chip "${t("vendor.scope.team")}", the button "${t("vendor.filters.buttonActive", { count: 1 })}"` : `no chip, the button "${t("vendor.filters.button")}"`}`,
    team ? c0.length === 1 && c0[0] === t("vendor.scope.team") && b0 === t("vendor.filters.buttonActive", { count: 1 }) : c0.length === 0 && b0 === t("vendor.filters.button"),
    { c0, b0 },
  )
  // the popover: its switches (and Mein Team / Alle only for a team member)
  await filterButton(p, t).click()
  const pop = popover(p)
  await pop.waitFor({ timeout: 5000 })
  const switches = (await pop.getByRole("switch").evaluateAll((els) => els.map((e) => document.querySelector(`label[for="${e.id}"]`)?.textContent ?? ""))).map((x) =>
    x.replace(/\d+$/, "").trim(),
  )
  const scope = (await pop.getByRole("radio").count()) === 2
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, `${role} filter popover`, SHOTS && `${combo.lang}-${role}-filter_popover`)
  await p.keyboard.press("Escape")
  check(
    `${tag}: the popover – ${t("reader.onlyUnread")}, ${t("reader.showMuted")}, ${t("review.filter")}${team ? `, ${t("vendor.scope.team")} / ${t("vendor.scope.all")}` : ""}`,
    switches.includes(t("reader.onlyUnread")) && switches.includes(t("reader.showMuted")) && switches.includes(t("review.filter")) && scope === team,
    { switches, scope },
  )
  // switched on: chips and the number; × removes
  await filterSwitch(p, t, t("reader.onlyUnread"), true)
  await filterSwitch(p, t, t("reader.showMuted"), true)
  const n = team ? 3 : 2
  const c1 = await chips(p, t)
  const b1 = (await filterButton(p, t).getAttribute("aria-label")) ?? ""
  const u1 = new URL(p.url()).searchParams
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, `${role} chips`, SHOTS && `${combo.lang}-${role}-chips`)
  await p.getByRole("button", { name: t("vendor.filters.remove", { name: t("reader.onlyUnread") }) }).click()
  await settle(p)
  const c2 = await chips(p, t)
  const u2 = new URL(p.url()).searchParams
  check(
    `${tag}: "${t("reader.onlyUnread")}" and "${t("reader.showMuted")}" on – ${n} chips, "${t("vendor.filters.buttonActive", { count: n })}"; × removes "${t("reader.onlyUnread")}" (and from the address)`,
    c1.length === n &&
      c1.includes(t("reader.onlyUnread")) &&
      c1.includes(t("vendor.filters.mutedChip")) &&
      b1 === t("vendor.filters.buttonActive", { count: n }) &&
      u1.get("unread") === "1" &&
      !c2.includes(t("reader.onlyUnread")) &&
      !u2.get("unread") &&
      c2.length === n - 1,
    { c1, b1, c2 },
  )
  await p.getByRole("button", { name: t("vendor.filters.remove", { name: t("vendor.filters.mutedChip") }) }).click()
  await settle(p)
  if (team) {
    // the team chip's ×: Alle (the popover says so too), and back
    await p.getByRole("button", { name: t("vendor.filters.remove", { name: t("vendor.scope.team") }) }).click()
    await settle(p)
    await filterButton(p, t).click()
    const allOn =
      (await popover(p)
        .getByRole("radio", { name: t("vendor.scope.all"), exact: true })
        .getAttribute("aria-checked")) === "true"
    await p.keyboard.press("Escape")
    const c3 = await chips(p, t)
    check(`${tag}: × on "${t("vendor.scope.team")}" – "${t("vendor.scope.all")}" chosen, no chip`, allOn && c3.length === 0, { allOn, c3 })
    await scopeTo(p, t, "team")
  }
  // "Versionen zu prüfen": its chip and the review panel
  await filterSwitch(p, t, t("review.filter"), true)
  const reviewChip = (await chips(p, t)).includes(t("review.filter")) && (await p.locator("main").getByText(t("review.title"), { exact: true }).count()) >= 1
  await p.getByRole("button", { name: t("vendor.filters.remove", { name: t("review.filter") }) }).click()
  await settle(p)
  check(
    `${tag}: "${t("review.filter")}" – its chip and the "${t("review.title")}" panel; × removes both`,
    reviewChip && (await p.locator("main").getByText(t("review.title"), { exact: true }).count()) === 0,
  )
}

async function viewFlow(r, combo, t, role) {
  const tag = `${combo.lang} ${role} views`
  const p = r.page
  const h = await H(r.ctx)
  for (const v of (await json(r.ctx, "/api/me/views?page=vendor")).items) await r.ctx.request.delete(`${BASE}/api/me/views/${v.id}`, { headers: h })
  await p.goto(`${BASE}/vendor`)
  await settle(p)
  const v0 = await viewName(p, t)
  await filterSwitch(p, t, t("reader.onlyUnread"), true)
  const v1 = await viewName(p, t)
  const name = `E2E Layout ${crypto.randomBytes(2).toString("hex")}`
  await viewButton(p, t).click()
  await popover(p)
    .getByRole("textbox", { name: t("reader.views.name") })
    .last()
    .fill(name)
  await popover(p)
    .getByRole("button", { name: t("reader.views.save") })
    .last()
    .click()
  const saved = await until(async () => (await viewName(p, t)) === name)
  await p.keyboard.press("Escape")
  check(
    `${tag}: "${t("reader.views.current")} ${t("reader.views.standard")}" without a filter, "${t("reader.views.custom")}" with one, the saved view's name once saved`,
    v0 === t("reader.views.standard") && v1 === t("reader.views.custom") && !!saved,
    {
      v0,
      v1,
      saved: await viewName(p, t),
    },
  )
  for (const v of (await json(r.ctx, "/api/me/views?page=vendor")).items) await r.ctx.request.delete(`${BASE}/api/me/views/${v.id}`, { headers: h })
  // cards / list – kept over a reload
  await p.goto(`${BASE}/vendor?status=all`)
  await settle(p)
  const toList = p.getByRole("button", { name: t("vendor.layout.toList") })
  const cards0 = await p.locator("main article").count()
  await toList.click()
  await settle(p)
  const listNow = (await p.getByRole("button", { name: t("vendor.layout.toCards") }).count()) === 1 && (await p.locator("main article").count()) === 0
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, `${role} list layout`, SHOTS && `${combo.lang}-${role}-list`)
  await p.reload()
  await settle(p)
  const kept = (await p.getByRole("button", { name: t("vendor.layout.toCards") }).count()) === 1
  await p.getByRole("button", { name: t("vendor.layout.toCards") }).click()
  await settle(p)
  check(
    `${tag}: one icon toggle – "${t("vendor.layout.toList")}" shows the list, kept over a reload, back to the cards`,
    cards0 > 0 && listNow && kept && (await p.locator("main article").count()) === cards0,
    {
      cards0,
      listNow,
      kept,
    },
  )
}

// ---------------------------------------------------------------- "Alle N als gelesen"

async function readAllFlow(r, combo, t) {
  const tag = `${combo.lang} read all`
  const p = r.page
  const h = await H(r.ctx)
  const KEYS = ["panos", "cisco-asa", "fortios"]
  const findings = async (key) => (await json(r.ctx, `/api/vendor/products/${key}?all=true&limit=100`)).findings ?? []
  // the unread findings of a product as its drawer has them – also while it is muted (the card's number then says 0)
  const unread = async () => Object.fromEntries(await Promise.all(KEYS.map(async (k) => [k, (await findings(k)).filter((f) => f.unread).length])))
  const unreadAll = async (keys) => {
    for (const key of keys) for (const f of await findings(key)) await r.ctx.request.post(`${BASE}/api/vendor/unread`, { data: { product: key, finding: f.id }, headers: h })
  }
  const mutes = async () => (await json(r.ctx, "/api/me/mutes")).items
  for (const m of await mutes()) await r.ctx.request.delete(`${BASE}/api/me/mutes/${m.id}`, { headers: h })
  const run = async (what, url, expect) => {
    await p.goto(`${BASE}/vendor?${url}`)
    await settle(p)
    const btn = readAllN(p, t)
    const n = await nOf(btn)
    const before = await unread()
    const b = await toastCount(p)
    if (n) {
      await btn.click()
      await p
        .getByRole("dialog")
        .filter({ hasText: t("reader.vendorReadAllTitle") })
        .getByRole("button", { name: t("news.readAll") })
        .click()
    }
    const toast = await toastAfter(p, b)
    await sleep(800)
    const after = await unread()
    const marked = KEYS.reduce((s, k) => s + before[k] - after[k], 0)
    const res = expect(before, after)
    check(
      `${tag} – ${what}: "${t("reader.vendorReadAllN", { count: n })}" marks exactly N; the toast says so`,
      n > 0 && marked === n && !!toast && toast.text.includes(t("reader.vendorReadAllDone", { count: n })) && res,
      {
        n,
        marked,
        toast: toast?.text,
        before,
        after,
      },
    )
    await dismissToasts(p)
  }
  // Mein Team: only the team's products (panos, fortios) – cisco-asa stays unread
  await unreadAll(["panos", "cisco-asa"])
  await run("Mein Team", "status=all", (b, a) => b.panos > 0 && a.panos === 0 && b["cisco-asa"] > 0 && a["cisco-asa"] === b["cisco-asa"])
  // Alle, panos muted and hidden: cisco-asa marked, panos left unread
  await unreadAll(["panos"])
  await r.ctx.request.post(`${BASE}/api/me/mutes`, { data: { kind: "product", key: "panos", days: 7 }, headers: h })
  await scopeTo(p, t, "all")
  await run("Alle, panos muted and hidden", "status=all", (b, a) => b.panos > 0 && a.panos === b.panos && a["cisco-asa"] === 0)
  // … "Stummgeschaltete zeigen": panos is shown – and marked; N must count it
  await unreadAll(["cisco-asa"])
  await run("Alle, muted panos shown", "status=all&muted=1", (b, a) => b.panos > 0 && a.panos === 0 && a["cisco-asa"] === 0)
  for (const m of await mutes()) await r.ctx.request.delete(`${BASE}/api/me/mutes/${m.id}`, { headers: h })
  // a muted CVE inside a product that is not muted (CVE-2026-6001 of cisco-asa): hidden – left unread; shown – marked
  const MUTED_CVE = "CVE-2026-6001"
  const stillUnread = async () => (await findings("cisco-asa")).some((f) => f.cves?.includes(MUTED_CVE) && f.unread)
  await r.ctx.request.post(`${BASE}/api/me/mutes`, { data: { kind: "cve", key: MUTED_CVE, days: 7 }, headers: h })
  await unreadAll(["cisco-asa"])
  await run(`Alle, ${MUTED_CVE} muted and hidden`, "status=all", (b, a) => b["cisco-asa"] === 2 && a["cisco-asa"] === 1)
  const left = await stillUnread()
  check(`${tag} – … the finding of the muted ${MUTED_CVE} stays unread`, left)
  await unreadAll(["cisco-asa"])
  await run(`Alle, ${MUTED_CVE} muted and shown`, "status=all&muted=1", (b, a) => b["cisco-asa"] === 2 && a["cisco-asa"] === 0)
  for (const m of await mutes()) await r.ctx.request.delete(`${BASE}/api/me/mutes/${m.id}`, { headers: h })
  await scopeTo(p, t, "team")
}

// ---------------------------------------------------------------- old addresses, the way back

async function placesFlow(r, combo, t, role) {
  const tag = `${combo.lang} ${role} addresses`
  const p = r.page
  await p.goto(`${BASE}/vendor?tab=catalog&product=panos`)
  await settle(p)
  const cat =
    (await p
      .locator("main h2")
      .filter({ hasText: t("vendor.tab.catalog") })
      .count()) === 1 && (await p.locator("[data-slot=sheet-content]").count()) === 1
  await p.keyboard.press("Escape")
  await p.goto(`${BASE}/vendor?tab=suggestions`)
  await settle(p)
  const sug = (await p.getByRole("heading", { name: t(role === "admin" ? "suggest.tab" : "suggest.mine") }).count()) === 1
  await p.goto(`${BASE}/vendor?filter=exploited`)
  await settle(p)
  const d = await overview(r.ctx, role === "team" ? "team" : "all")
  const exploited = d.items.filter((i) => (i.counts.exploited_affected ?? 0) > 0).map((i) => i.product.label)
  const exChip = (await chips(p, t)).includes(t("vendor.sum.filterExploited"))
  await statusRadio(p, t, "all").click()
  await settle(p)
  const shown = await p.locator("main article h3").allInnerTexts()
  check(
    `${tag}: ?tab=catalog&product=panos – the catalogue with the drawer; ?tab=suggestions – "${t(role === "admin" ? "suggest.tab" : "suggest.mine")}"; ?filter=exploited – its chip, only exploited products`,
    cat && sug && exChip && shown.length === exploited.length && exploited.every((l) => shown.some((s) => s.includes(l))),
    { cat, sug, exChip, shown, exploited },
  )
  // back keeps the filters
  await p.goto(`${BASE}/vendor?status=all&unread=1&q=pan`)
  await settle(p)
  await p.getByRole("button", { name: new RegExp(`^${esc(t("vendor.head.more"))}`) }).click()
  await p.getByRole("menuitem", { name: t(role === "admin" ? "vendor.head.add" : "vendor.head.browse") }).click()
  await settle(p)
  const inCat = new URL(p.url()).searchParams.get("tab") === "catalog"
  await p.getByRole("link", { name: t("vendor.head.back") }).click()
  await settle(p)
  const u = new URL(p.url()).searchParams
  check(
    `${tag}: "${t("vendor.head.back")}" from the catalogue keeps the overview's filters (status, unread, search)`,
    inCat && !u.get("tab") && u.get("status") === "all" && u.get("unread") === "1" && u.get("q") === "pan",
    {
      url: p.url().replace(BASE, ""),
    },
  )
}

async function pages(browser, combo, who) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme} ${who}`
  const t = texts(lang)
  const r = await signedIn(browser, combo, who)
  await r.page.goto(`${BASE}/vendor?status=all`)
  await settle(r.page)
  await scrollCheck(r.page, tag, "overview", SHOTS && `${lang}-${width}-${theme}-${who}-overview`)
  if (width < 768) await rowFlow(r, combo, t, who === "admin" ? "admin" : who === "layout_team" ? "team" : "solo")
  await r.page.getByRole("button", { name: new RegExp(`^${esc(t("vendor.head.more"))}`) }).click()
  await scrollCheck(r.page, tag, "⋯ menu", SHOTS && `${lang}-${width}-${theme}-${who}-menu`)
  await r.page.keyboard.press("Escape")
  await filterButton(r.page, t).click()
  await scrollCheck(r.page, tag, "filter popover", SHOTS && `${lang}-${width}-${theme}-${who}-filters`)
  await r.page.keyboard.press("Escape")
  await r.page.goto(`${BASE}/vendor?tab=catalog`)
  await settle(r.page)
  await scrollCheck(r.page, tag, "catalogue", SHOTS && `${lang}-${width}-${theme}-${who}-catalog`)
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) {
    const t = texts(combo.lang)
    if (combo.wide) {
      const team = await signedIn(browser, combo, "layout_team")
      const solo = await signedIn(browser, combo, "layout_solo")
      const admin = await signedIn(browser, combo, "admin")
      await headerFlow(team, combo, t, "team")
      await headerFlow(admin, combo, t, "admin")
      await badgeFlow(admin, solo, combo, t)
      await rowFlow(team, combo, t, "team")
      await rowFlow(solo, combo, t, "solo")
      await filterFlow(team, combo, t, "team")
      await filterFlow(solo, combo, t, "solo")
      await viewFlow(team, combo, t, "team")
      await readAllFlow(team, combo, t)
      await placesFlow(team, combo, t, "team")
      await placesFlow(admin, combo, t, "admin")
      for (const [name, r] of [
        ["team reader", team],
        ["solo reader", solo],
        ["admin", admin],
      ]) {
        check(`${combo.lang} ${name}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
        await r.ctx.close()
      }
    } else for (const who of ["layout_team", "admin"]) await pages(browser, combo, who)
  }
} finally {
  await browser.close()
}
finish()
