// Browser check (0.1.42, grouping by product 0.1.46): watching many CVEs at once and the list grouped by the product the
// CVEs concern (the default) or by where they were watched from.
// - A story drawer with more than 12 CVEs in its details: "+ N weitere CVEs" opens and closes (mouse and keyboard,
//   aria-expanded), the stars of the opened list watch with the story as origin; "Alle beobachten (N)" → the toast's
//   "Zur Liste" lands on /watch?group_by=origin&group=story:<id> with that group open and in view; "Alle nicht mehr
//   beobachten" with "Rückgängig"; a person with 495 watched CVEs gets the limit question ("Nur noch 5 frei …") –
//   cancelled nothing changes, confirmed the five likeliest (EPSS) are watched.
// - A Vendor News finding with several CVEs: its CVEs and "Alle beobachten".
// - /watch "Gruppieren nach: Produkt" without a parameter: every row in the group of its product as the list API names
//   it (product:<key> / name:<name> / none), a catalogue product's title opens it in Vendor News, "Gruppe nicht mehr
//   beobachten" of a product group with "Rückgängig" (each CVE back with its origin).
// - "Gruppieren nach: Herkunft" (?group_by=origin): kept over a reload (the address), a group's title opens the story or
//   the finding, a group closes and opens, "Gruppe nicht mehr beobachten" with "Rückgängig", a filter within the groups
//   ("3 von 21 CVEs"), ?group= of an origin group opens and scrolls to it also when the filter would hide it (and picks
//   the origin grouping by itself, as the old links do), the old ?groups=1&group=story:<id> lands on the same group, a
//   CVE typed on the page lands in "Einzeln hinzugefügt"; "Keine" (?group_by=none) shows one list.
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll. The flows run
// once per language (the wide light run) with a reader of their own.
// It expects (seed): the story `story142` with 21 CVEs in its details (CVE-2026-2001…2021, the first three in KEV, EPSS
// for 2006–2010), the PAN-OS finding paloalto:PAN-SA-2026-0042 with CVE-2026-3001…3004, readers groups_user /
// groups2_user (nothing watched) and near_user (495 watched). Env: BASE_URL, CREDS, PLAYWRIGHT, SHOTS.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { BASE, COMBOS, H, SHOTS, check, creds, dismissToasts, finish, json, open, pw, scrollCheck, settle, signIn, toastAfter, toastCount } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const STORY = creds.story142
const STORY_CVES = Array.from({ length: 21 }, (_, i) => `CVE-2026-${2001 + i}`)
const FINDING = "paloalto:PAN-SA-2026-0042"
const FINDING_CVES = ["CVE-2026-3001", "CVE-2026-3002", "CVE-2026-3003", "CVE-2026-3004"]
const MANUAL = "CVE-2026-4242"
const STORY_KEY = `story:${STORY}`
const FINDING_KEY = `finding:panos:${FINDING}`
if (!STORY) throw new Error("creds.story142 (the seeded story) is needed")

const ids = async (ctx) => (await json(ctx, "/api/me/cve-watch/ids")).cves
/** The key of a product group as the page makes it (src/lib/watch-api.ts productKey). */
const productKey = (pr) =>
  pr?.key ? `product:${pr.key}` : pr && pr.source !== "none" && pr.label.trim() ? `name:${pr.label.replace(/\s+/g, " ").trim().toLowerCase().replace(/ /g, "-")}` : "none"
/** "Gruppieren nach" set to one of its options (a Radix select). */
async function groupBy(page, t, by) {
  await page.getByRole("combobox", { name: t("watch.groupBy.label") }).click()
  await page.getByRole("option", { name: t(`watch.groupBy.${by}`), exact: true }).click()
  await settle(page)
}
const list = async (ctx) => (await json(ctx, "/api/me/cve-watch")).items
const sheet = (page) => page.locator("[data-slot=sheet-content]")
const group = (page, key) => page.locator(`[id="watch-group-${key}"]`)
const inView = (loc) =>
  loc.evaluate((el) => {
    const r = el.getBoundingClientRect()
    return r.top >= -2 && r.top < window.innerHeight - 40
  })
async function until(fn, ms = 8000, step = 250) {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn().catch(() => false)
    if (v || Date.now() > end) return v
    await new Promise((r) => setTimeout(r, step))
  }
}
/** A toast's action clicked with the mouse (at its place – over an open drawer too). Not clickable: a FAIL with what lies
 * on top of it, then – a diagnostic only, so the rest can still be checked – the action is triggered without the mouse.
 * An "undo" over an open drawer: the drawer stays open. */
async function toastAction(page, toast, name, tag, { keepsDrawer = false } = {}) {
  const btn = toast.el.getByRole("button", { name })
  const drawer = (await page.locator("[data-slot=sheet-content]").count()) > 0
  let clicked = true
  await btn.click({ timeout: 3000 }).catch(() => (clicked = false))
  check(`${tag}: the toast's "${name}" takes a mouse click${drawer ? " while the drawer is open" : ""}`, clicked, clicked ? undefined : { hit: await hitAt(page, btn) })
  if (!clicked) await btn.dispatchEvent("click") // diagnostic only (the FAIL above stands)
  if (drawer && keepsDrawer) {
    await page.waitForTimeout(800)
    check(`${tag}: … and the drawer stays open`, (await page.locator("[data-slot=sheet-content]").count()) === 1)
  }
}
const hitAt = (page, el) =>
  el.evaluate((b) => {
    const r = b.getBoundingClientRect()
    return document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2)?.getAttribute("data-slot") ?? "?"
  })
async function clear(ctx) {
  const have = await ids(ctx)
  if (have.length) await ctx.request.post(`${BASE}/api/me/cve-watch/bulk-remove`, { data: { cves: have }, headers: await H(ctx) })
}

async function storyFlow(browser, combo, t, user) {
  const tag = `${combo.lang} story`
  const r = await open(browser, combo)
  await signIn(r.ctx, creds[`${user}_user`], creds[`${user}_password`])
  await clear(r.ctx)
  const p = r.page
  await p.goto(`${BASE}/?story=${STORY}`)
  await settle(p)
  const s = sheet(p)
  const more = s.getByRole("button", { name: t("details.moreCves", { count: 9 }) })
  await more.waitFor({ timeout: 10000 }).catch(() => undefined)
  const chips = s.locator(`[id="${await more.getAttribute("aria-controls")}"]`)
  const shown0 = await chips.locator("li").count() // 12 and the button's
  const closed0 = (await more.getAttribute("aria-expanded")) === "false"
  // the keyboard: Enter opens, Space closes – the focus stays on the button
  await more.focus()
  await p.keyboard.press("Enter")
  const toggleBtn = chips.getByRole("button", { name: new RegExp(`^(${t("details.moreCves", { count: 9 }).replace("+", "\\+")}|${t("details.fewerCves")})$`) })
  const openKb =
    (await toggleBtn.getAttribute("aria-expanded")) === "true" && (await chips.locator("li").count()) === 22 && (await toggleBtn.innerText()).trim() === t("details.fewerCves")
  const focused = await toggleBtn.evaluate((el) => document.activeElement === el)
  await p.keyboard.press("Space")
  const closedKb = (await toggleBtn.getAttribute("aria-expanded")) === "false" && (await chips.locator("li").count()) === 13
  check(
    `${tag}: "${t("details.moreCves", { count: 9 })}" – 12 shown, Enter opens all 21 ("${t("details.fewerCves")}"), Space closes; aria-expanded follows`,
    shown0 === 13 && closed0 && openKb && focused && closedKb,
    {
      shown0,
      closed0,
      openKb,
      focused,
      closedKb,
    },
  )
  // a star of the opened list: watched with the story as origin
  await toggleBtn.click()
  const star = chips.getByRole("button", { name: t("watch.watch", { cve: STORY_CVES[14] }), exact: true })
  const starThere = (await star.count()) === 1
  if (starThere) await star.click()
  const watched = await until(async () => (await ids(r.ctx)).includes(STORY_CVES[14]))
  const origin = (await list(r.ctx)).find((w) => w.cve === STORY_CVES[14])?.origin
  const pressed = await until(
    async () => (await chips.getByRole("button", { name: t("watch.unwatch", { cve: STORY_CVES[14] }), exact: true }).getAttribute("aria-pressed")) === "true",
  )
  check(
    `${tag}: a star in the opened list watches ${STORY_CVES[14]} with the story as origin (aria-pressed)`,
    starThere && watched && origin?.kind === "story" && origin.id === STORY && pressed,
    { starThere, origin },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "story drawer, all CVEs", SHOTS && `${combo.lang}-story_all_cves`)
  // the star's toast, raised inside the drawer: "Zur Liste" with the mouse → the list at that CVE
  const starToast = p
    .locator("[data-sonner-toast]")
    .filter({ hasText: t("watch.added", { cve: STORY_CVES[14] }) })
    .last()
  const hasStarToast = await until(async () => (await starToast.count()) === 1, 5000)
  if (hasStarToast) await toastAction(p, { el: starToast }, t("watch.toList"), `${tag} star`)
  await p.waitForURL(/\/watch\?/, { timeout: 8000 }).catch(() => undefined)
  const su = new URL(p.url())
  check(
    `${tag} star: the toast "${t("watch.added", { cve: STORY_CVES[14] })}" – "${t("watch.toList")}" opens /watch?cve=${STORY_CVES[14]}`,
    hasStarToast && su.pathname === "/watch" && su.searchParams.get("cve") === STORY_CVES[14],
    {
      hasStarToast,
      url: `${su.pathname}${su.search}`,
    },
  )
  await p.goto(`${BASE}/?story=${STORY}`)
  await settle(p)
  await dismissToasts(p)
  // "Alle beobachten (20)" → "Zur Liste"
  const all = s.getByRole("button", { name: t("watch.all.watch", { count: 20 }) })
  const allThere = (await all.count()) === 1
  const before = await toastCount(p)
  if (allThere) await all.click()
  const toast = await toastAfter(p, before)
  const n = await until(async () => {
    const have = await ids(r.ctx)
    return STORY_CVES.every((c) => have.includes(c)) && have.length
  })
  check(
    `${tag}: "${t("watch.all.watch", { count: 20 })}" – all 21 watched, toast "${t("watch.all.added", { count: 20 })}"`,
    allThere && n === 21 && !!toast && toast.text.includes(t("watch.all.added", { count: 20 })),
    {
      allThere,
      n,
      toast: toast?.text,
    },
  )
  if (toast) await toastAction(p, toast, t("watch.toList"), tag)
  await p.waitForURL(/\/watch\?/, { timeout: 8000 }).catch(() => undefined)
  await settle(p)
  const u = new URL(p.url())
  const g = group(p, STORY_KEY)
  const openG = (await g.count()) === 1 && (await g.getByRole("button", { name: /./ }).first().getAttribute("aria-expanded")) === "true"
  const seen = openG && (await until(() => inView(g), 4000))
  check(
    `${tag}: "${t("watch.toList")}" → /watch?group_by=origin&group=story:<id>, the group open and in view`,
    u.pathname === "/watch" && u.searchParams.get("group_by") === "origin" && u.searchParams.get("group") === STORY_KEY && openG && seen,
    {
      url: `${u.pathname}${u.search}`.replace(STORY, "<id>"),
      openG,
      seen,
    },
  )
  // "Alle nicht mehr beobachten" with undo
  await p.goto(`${BASE}/?story=${STORY}`)
  await settle(p)
  await dismissToasts(p)
  const stop = sheet(p).getByRole("button", { name: t("watch.all.unwatch") })
  const b2 = await toastCount(p)
  if (await stop.count()) await stop.click()
  const t2 = await toastAfter(p, b2)
  const gone = await until(async () => (await ids(r.ctx)).length === 0)
  if (t2) await toastAction(p, t2, t("watch.undo"), tag, { keepsDrawer: true })
  const back = await until(async () => (await ids(r.ctx)).length === 21)
  const backOrigin = (await list(r.ctx)).every((w) => w.origin?.kind === "story" && w.origin.id === STORY)
  check(
    `${tag}: "${t("watch.all.unwatch")}" – all 21 gone; "${t("watch.undo")}" watches them again with their origin`,
    !!t2 && t2.text.includes(t("watch.all.removed", { count: 21 })) && gone && back && backOrigin,
    {
      toast: t2?.text,
      gone,
      back,
      backOrigin,
    },
  )
  await dismissToasts(p)

  // a Vendor News finding with several CVEs
  await p.goto(`${BASE}/vendor?product=panos`)
  await settle(p)
  const row = sheet(p)
    .locator("li")
    .filter({ hasText: "PAN-SA-2026-0042" })
    .filter({ has: p.getByRole("button", { name: t("watch.all.watch", { count: 4 }) }) })
    .first()
  const listed =
    (await row.count()) === 1 &&
    (await Promise.all(FINDING_CVES.map((c) => row.getByRole("button", { name: t("watch.watch", { cve: c }), exact: true }).count()))).every((x) => x === 1)
  if (listed) await row.getByRole("button", { name: t("watch.all.watch", { count: 4 }) }).click()
  const fw = await until(async () => {
    const items = await list(r.ctx)
    return FINDING_CVES.every((c) => items.some((w) => w.cve === c && w.origin?.kind === "finding" && w.origin.advisory === FINDING && w.origin.product === "panos"))
  })
  check(`${tag}: a finding with four CVEs – each with its star, "${t("watch.all.watch", { count: 4 })}" watches them with the finding as origin`, listed && fw, { listed, fw })
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "finding with CVEs", SHOTS && `${combo.lang}-finding_watch_all`)
  await dismissToasts(p)
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  return r
}

async function listFlow(r, combo, t) {
  const tag = `${combo.lang} groups`
  const p = r.page
  await p.goto(`${BASE}/watch`)
  await settle(p)
  // a CVE typed on the page: "Einzeln hinzugefügt"
  await p.getByLabel(t("watch.add"), { exact: true }).fill(MANUAL)
  await p.getByRole("button", { name: t("watch.watchButton"), exact: true }).click()
  await until(async () => (await ids(r.ctx)).includes(MANUAL))
  await dismissToasts(p)
  await productFlow(r, combo, t)
  // "Gruppieren nach: Herkunft" – in the address, kept over a reload
  await p.goto(`${BASE}/watch`)
  await settle(p)
  await groupBy(p, t, "origin")
  const on1 = new URL(p.url()).searchParams.get("group_by") === "origin"
  await p.reload()
  await settle(p)
  const on2 = (await p.getByRole("combobox", { name: t("watch.groupBy.label") }).innerText()).trim() === t("watch.groupBy.origin") && (await group(p, STORY_KEY).count()) === 1
  const manualG = group(p, "manual")
  const manualOk = (await manualG.count()) === 1 && (await manualG.innerText()).includes(t("watch.group.manual")) && (await manualG.innerText()).includes(MANUAL)
  check(
    `${tag}: "${t("watch.groupBy.label")}: ${t("watch.groupBy.origin")}" (?group_by=origin), kept over a reload; the typed CVE in "${t("watch.group.manual")}"`,
    on1 && on2 && manualOk,
    {
      on1,
      on2,
      manualOk,
    },
  )
  // the old link of "Zur Liste" (0.1.42–0.1.45): the same group, grouped by origin
  await p.goto(`${BASE}/watch?groups=1&group=${encodeURIComponent(STORY_KEY)}`)
  await settle(p)
  const oldG = group(p, STORY_KEY)
  const oldOk = (await oldG.count()) === 1 && (await until(() => inView(oldG), 4000))
  const oldSel = (await p.getByRole("combobox", { name: t("watch.groupBy.label") }).innerText()).trim() === t("watch.groupBy.origin")
  check(`${tag}: the old /watch?groups=1&group=story:<id> – grouped by origin, the story's group in view`, oldOk && oldSel, { oldOk, oldSel })
  // "Keine": one list, no groups
  await groupBy(p, t, "none")
  const flat =
    new URL(p.url()).searchParams.get("group_by") === "none" && (await p.locator("section[id^=watch-group-]").count()) === 0 && (await p.locator("li[id^=watch-CVE-]").count()) > 0
  check(`${tag}: "${t("watch.groupBy.none")}" (?group_by=none) – one list without groups`, flat)
  await groupBy(p, t, "origin")
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "watch grouped", SHOTS && `${combo.lang}-watch_grouped`)
  // the group's title opens the story / the finding
  const storyTitle = (await p.locator(`[id="watch-group-${STORY_KEY}-title"] a`).innerText()).trim()
  await p.locator(`[id="watch-group-${STORY_KEY}-title"] a`).click()
  await settle(p)
  const toStory = new URL(p.url()).searchParams.get("story") === STORY && (await sheet(p).count()) === 1
  await p.goBack()
  await settle(p)
  await p.locator(`[id="watch-group-${FINDING_KEY}-title"] a`).click()
  await settle(p)
  const fu = new URL(p.url())
  const toFinding = fu.pathname === "/vendor" && fu.searchParams.get("product") === "panos" && fu.searchParams.get("finding") === FINDING && (await sheet(p).count()) === 1
  await p.goBack()
  await settle(p)
  check(`${tag}: a group's title opens the story ("${storyTitle.slice(0, 40)}") and the finding in Vendor News`, toStory && toFinding, { toStory, toFinding })
  // collapse and open
  const sg = group(p, STORY_KEY)
  const collapse = sg.getByRole("button", { name: t("watch.group.collapse", { title: storyTitle }) })
  await collapse.click()
  const closed =
    (await sg.getByRole("button", { name: t("watch.group.expand", { title: storyTitle }) }).getAttribute("aria-expanded")) === "false" && (await sg.locator("ul").count()) === 0
  await sg.getByRole("button", { name: t("watch.group.expand", { title: storyTitle }) }).click()
  const reopened = (await sg.locator("ul > li").count()) === 21
  check(`${tag}: a group closes and opens again (aria-expanded, its rows)`, closed && reopened, { closed, reopened })
  // a filter within the groups: "3 von 21 CVEs"
  await p
    .getByRole("radiogroup", { name: t("watch.filter.label") })
    .getByRole("radio", { name: new RegExp(`^${t("watch.filter.kev")}`) })
    .click()
  await settle(p)
  const head = await p.locator(`[id="watch-group-${STORY_KEY}-title"]`).innerText()
  const fHidden = (await group(p, FINDING_KEY).count()) === 0
  check(
    `${tag}: filter "${t("watch.filter.kev")}" within the groups – "${t("watch.group.countOf", { shown: 3, count: 21 })}", the finding's group left out`,
    head.includes(t("watch.group.countOf", { shown: 3, count: 21 })) && fHidden,
    {
      head: head.slice(-40),
      fHidden,
    },
  )
  // ?group= also when the filter would hide it: the filter goes back to "Alle", the group in view
  for (const key of [FINDING_KEY, "manual"]) {
    await p.goto(`${BASE}/watch?filter=kev&group=${encodeURIComponent(key)}`)
    await settle(p)
    const gg = group(p, key)
    const there = (await gg.count()) === 1
    const view = there && (await until(() => inView(gg), 4000))
    const filterAll = (
      await p
        .getByRole("radiogroup", { name: t("watch.filter.label") })
        .getByRole("radio", { checked: true })
        .innerText()
    ).startsWith(t("watch.filter.all"))
    check(
      `${tag}: ?filter=kev&group=${key === "manual" ? "manual" : "finding:…"} – the group shown and in view, the filter back on "${t("watch.filter.all")}"`,
      there && view && filterAll,
      { there, view, filterAll },
    )
  }
  // "Gruppe nicht mehr beobachten" with undo
  await p.goto(`${BASE}/watch?group_by=origin`)
  await settle(p)
  await dismissToasts(p)
  const fg = group(p, FINDING_KEY)
  const fTitle = (await p.locator(`[id="watch-group-${FINDING_KEY}-title"] a`).innerText()).trim()
  const b = await toastCount(p)
  await fg.getByRole("button", { name: t("watch.group.remove") }).click()
  const toast = await toastAfter(p, b)
  const gone = await until(async () => (await ids(r.ctx)).filter((c) => FINDING_CVES.includes(c)).length === 0)
  const gGone = await until(async () => (await group(p, FINDING_KEY).count()) === 0)
  if (toast) await toastAction(p, toast, t("watch.undo"), tag)
  const back = await until(async () => {
    const items = await list(r.ctx)
    return FINDING_CVES.every((c) => items.some((w) => w.cve === c && w.origin?.kind === "finding" && w.origin.advisory === FINDING))
  })
  const gBack = await until(async () => (await group(p, FINDING_KEY).count()) === 1)
  check(
    `${tag}: "${t("watch.group.remove")}" – "${t("watch.group.removed", { count: 4, title: fTitle })}", "${t("watch.undo")}" brings the group back`,
    !!toast && toast.text.includes(t("watch.group.removed", { count: 4, title: fTitle })) && gone && gGone && back && gBack,
    {
      toast: toast?.text,
      gone,
      gGone,
      back,
      gBack,
    },
  )
  await dismissToasts(p)
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
}

/** The default grouping: by product, as the list API names each CVE's product. */
async function productFlow(r, combo, t) {
  const tag = `${combo.lang} by product`
  const p = r.page
  await p.goto(`${BASE}/watch`)
  await settle(p)
  const items = await list(r.ctx)
  const sel = (await p.getByRole("combobox", { name: t("watch.groupBy.label") }).innerText()).trim() === t("watch.groupBy.product")
  // every row in the group of its product (the rows inside the group's section)
  const misplaced = []
  for (const w of items) {
    const n = await group(p, productKey(w.product)).locator(`[id="watch-${w.cve}"]`).count()
    if (n !== 1) misplaced.push(`${w.cve} → ${productKey(w.product)}`)
  }
  const keys = [...new Set(items.map((w) => productKey(w.product)))]
  const sections = await p.locator("section[id^=watch-group-]").count()
  // "Ohne Produktzuordnung" – if there is one – is the last group
  const order = await p.locator("section[id^=watch-group-]").evaluateAll((els) => els.map((e) => e.id))
  const noneLast = !keys.includes("none") || order[order.length - 1] === "watch-group-none"
  check(
    `${tag}: no parameter – "${t("watch.groupBy.product")}"; each of ${items.length} CVEs in the group of its product (${keys.length} groups), "${t("watch.group.noProduct")}" last`,
    sel && misplaced.length === 0 && sections === keys.length && noneLast,
    { sel, misplaced: misplaced.slice(0, 5), sections, keys: keys.slice(0, 8), noneLast },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "watch by product", SHOTS && `${combo.lang}-watch_by_product`)
  // a catalogue product's title opens it in Vendor News
  const cat = keys.find((k) => k.startsWith("product:"))
  if (cat) {
    await p.locator(`[id="watch-group-${cat}-title"] a`).click()
    await settle(p)
    const vu = new URL(p.url())
    const toVendor = vu.pathname === "/vendor" && vu.searchParams.get("product") === cat.slice("product:".length) && (await sheet(p).count()) === 1
    await p.goBack()
    await settle(p)
    check(`${tag}: the title of ${cat} opens the product in Vendor News`, toVendor, { url: `${vu.pathname}${vu.search}` })
  } else check(`${tag}: a catalogue product among the groups (the seed links the finding's advisory to panos)`, false, { keys })
  // "Gruppe nicht mehr beobachten" of the finding's product group, with undo – each CVE back with its origin
  const fk = productKey(items.find((w) => w.cve === FINDING_CVES[0])?.product)
  const mine = items.filter((w) => productKey(w.product) === fk)
  const fg = group(p, fk)
  await dismissToasts(p)
  const b = await toastCount(p)
  await fg.getByRole("button", { name: t("watch.group.remove") }).click()
  const toast = await toastAfter(p, b)
  const gone = await until(async () => (await ids(r.ctx)).filter((c) => mine.some((w) => w.cve === c)).length === 0)
  if (toast) await toastAction(p, toast, t("watch.undo"), tag)
  const back = await until(async () => {
    const now = await list(r.ctx)
    return mine.every((w) => now.some((x) => x.cve === w.cve && JSON.stringify(x.origin) === JSON.stringify(w.origin)))
  })
  const gBack = await until(async () => (await group(p, fk).count()) === 1)
  check(`${tag}: "${t("watch.group.remove")}" of ${fk} – its ${mine.length} CVEs gone, "${t("watch.undo")}" brings them back with their origin`, !!toast && gone && back && gBack, {
    toast: toast?.text,
    gone,
    back,
    gBack,
  })
  await dismissToasts(p)
}

async function limitFlow(browser, combo, t) {
  const tag = `${combo.lang} limit`
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.near_user, creds.near_password)
  const h = await H(r.ctx)
  await r.ctx.request.post(`${BASE}/api/me/cve-watch/bulk-remove`, { data: { group: { kind: "story", id: STORY } }, headers: h })
  const n0 = (await ids(r.ctx)).length
  const p = r.page
  await p.goto(`${BASE}/?story=${STORY}`)
  await settle(p)
  const all = sheet(p).getByRole("button", { name: t("watch.all.watch", { count: 21 }) })
  await all.click()
  const dlg = p.getByRole("dialog").filter({ hasText: t("watch.all.limitTitle", { count: 5 }) })
  const asked = await until(async () => (await dlg.count()) === 1)
  const text = asked ? await dlg.innerText() : ""
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "limit question", SHOTS && `${combo.lang}-watch_limit`)
  if (asked) await dlg.getByRole("button", { name: t("common.cancel") }).click()
  await p.waitForTimeout(800)
  const n1 = (await ids(r.ctx)).length
  check(
    `${tag}: at ${n0} watched "${t("watch.all.watch", { count: 21 })}" asks "${t("watch.all.limitTitle", { count: 5 })}" – cancelled nothing changes`,
    n0 === 495 && asked && text.includes(t("watch.all.order.epss")) && n1 === 495,
    { n0, asked, n1 },
  )
  await all.click()
  await until(async () => (await dlg.count()) === 1)
  const before = await toastCount(p)
  await dlg.getByRole("button", { name: t("watch.all.limitConfirm", { count: 5 }) }).click()
  const toast = await toastAfter(p, before)
  const have = await until(async () => {
    const x = await ids(r.ctx)
    return x.length === 500 && x
  })
  const five = have ? STORY_CVES.slice(5, 10).every((c) => have.includes(c)) : false
  check(
    `${tag}: confirmed – the five likeliest (EPSS) watched, 500 in the list, the toast says 16 did not fit`,
    !!have && five && !!toast && toast.text.includes(t("watch.all.skipped", { count: 16 })),
    { n: have?.length, five, toast: toast?.text },
  )
  await r.ctx.request.post(`${BASE}/api/me/cve-watch/bulk-remove`, { data: { group: { kind: "story", id: STORY } }, headers: h })
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

async function pages(browser, combo, user) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme}`
  const r = await open(browser, combo)
  await signIn(r.ctx, creds[`${user}_user`], creds[`${user}_password`])
  const t = texts(lang)
  await r.page.goto(`${BASE}/?story=${STORY}`)
  await settle(r.page)
  const more = sheet(r.page).getByRole("button", { name: t("details.moreCves", { count: 9 }) })
  if (await more.count()) await more.click()
  await scrollCheck(r.page, tag, "story drawer opened list", SHOTS && `${lang}-${width}-${theme}-story_cves`)
  for (const [name, path] of [
    ["watch grouped", "/watch"],
    ["watch by origin", "/watch?group_by=origin"],
    ["watch old link", "/watch?groups=1"],
    ["watch group link", `/watch?group=${encodeURIComponent(FINDING_KEY)}`],
    ["finding drawer", `/vendor?product=panos&finding=${encodeURIComponent(FINDING)}`],
  ]) {
    await r.page.goto(`${BASE}${path}`)
    await settle(r.page)
    await scrollCheck(r.page, tag, name, SHOTS && `${lang}-${width}-${theme}-${name.replace(/ /g, "_")}`)
    if (name === "watch grouped" || name === "watch by origin") {
      // the group's title keeps a readable width next to "Gruppe nicht mehr beobachten" (at least half of its header row –
      // the button wraps below it on a phone) instead of a column of a few letters
      const titles = await r.page.locator("section[id^=watch-group-] h3").evaluateAll((els) =>
        els.map((e) => ({
          w: Math.round(e.getBoundingClientRect().width),
          row: Math.round(e.parentElement.getBoundingClientRect().width),
          lines: Math.round(e.getBoundingClientRect().height / parseFloat(getComputedStyle(e).lineHeight)),
        })),
      )
      check(
        `${tag} grouped: no group title squeezed beside the remove button (half its header wide, or at most two lines)`,
        titles.length > 0 && titles.every((x) => x.w >= x.row / 2 || x.lines <= 2),
        { titles },
      )
    }
  }
  check(`${tag} pages: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) {
    const t = texts(combo.lang)
    const user = combo.lang === "de" ? "groups" : "groups2"
    if (combo.wide) {
      const r = await storyFlow(browser, combo, t, user)
      await listFlow(r, combo, t)
      await r.ctx.close()
      await limitFlow(browser, combo, t)
    }
    await pages(browser, combo, user)
  }
} finally {
  await browser.close()
}
finish()
