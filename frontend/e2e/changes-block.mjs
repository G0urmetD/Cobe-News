// Browser check (0.1.33): advisory changes, the personal kind "Advisory geändert", the permanent block and the instant
// role revoke.
// a) Vendor News: "Geändert" on the finding (tooltip: the revision) and on the product card/row (tooltip), the drawer's
//    sub-tab "Änderungen" with the revision – the impact on a version entered as its first line –, the deep link
//    /vendor?product=<key>&view=changes, the rule kind "Advisory geändert" in the rule editor, a story's "Änderungen".
// b) Einstellungen → Benachrichtigungen → "Hersteller-News meiner Produkte" (a reader in a team): the toggle "Advisory
//    geändert", off by default; switched on and saved (and back off – the run can be repeated).
// c) Admin: "Dauerhaft sperren" for a directory account the sync switched off (sync:no_team) → "Vom Admin gesperrt",
//    "Dauerhafte Sperre aufheben" back; the dialog when removing a role mapping and when switching AD/LDAP off: the toggle
//    "Betroffene sofort abmelden" (on) and the number of accounts it concerns (as the server's /impact says). The
//    mapping "News-Kurzzeit" is removed once per language (checked through the API) and added again at the next start.
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll.
//
// Only against a throwaway instance (own database and DATA_DIR, never the live one) – docs/BETRIEB.md, "Entwicklung / Tests".
// It expects: Teams on, the reader in team "Netzwerk" following panos with the version 11.2.4-h23 entered; an advisory
// paloalto:CVE-2026-1001 stored twice (fixed version h10 → h30: 11.2.4-h23 now affected) and a story of it; AD/LDAP on
// and usable (names under corp.example); the role mapping "CN=News-Kurzzeit,OU=Groups,DC=corp,DC=example" (reader) and
// an AD account "Kai Kurzzeit" with that group stored and a session; an AD account "Dora Verzeichnis" switched off with
// sync:no_team; a rule.
// Env: BASE_URL (vite dev server), CREDS (JSON {user, password, totp, reader, reader_password} – never printed),
// PLAYWRIGHT (path to an existing playwright install …/node_modules/playwright/index.mjs), SHOTS (optional folder for
// screenshots). Uses the installed Google Chrome (channel "chrome") – never downloads a browser. Notifications stubbed,
// never granted.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import fs from "node:fs"

const BASE = (process.env.BASE_URL || "http://127.0.0.1:5230").replace(/\/$/, "")
const creds = JSON.parse(fs.readFileSync(process.env.CREDS || "", "utf8"))
const SHOTS = process.env.SHOTS || ""
const { chromium } = await import(process.env.PLAYWRIGHT || "playwright-core")

const TMP_GROUP = "CN=News-Kurzzeit,OU=Groups,DC=corp,DC=example"
const L = {
  de: {
    changed: /Geändert \S/,
    cardHelp: "Advisory zu diesem Produkt wurde in den letzten 30 Tagen geändert",
    title: "Änderungen",
    now: "jetzt",
    kind: "Advisory geändert",
    save: "Speichern",
    edit: "Bearbeiten",
    actions: "Weitere Aktionen",
    block: "Dauerhaft sperren",
    unblock: "Dauerhafte Sperre aufheben",
    offAdmin: "Vom Admin gesperrt",
    remove: "Entfernen",
    cancel: "Abbrechen",
    removeTitle: "Zuordnung entfernen?",
    endSessions: "Betroffene sofort abmelden",
    mapNone: "Nach den gespeicherten Gruppen verliert niemand seine Rolle.",
    mapLost: (n) => (n === 1 ? "1 Konto verliert den Zugang." : `${n} Konten verlieren den Zugang.`),
    ldapCard: "Anmeldung mit Active Directory",
    offTitle: "Active Directory ausschalten?",
    offNone: "Gerade ist niemand über Active Directory angemeldet.",
    offSome: (n) => (n === 1 ? "Gerade ist 1 Konto aus Active Directory angemeldet." : `Gerade sind ${n} Konten aus Active Directory angemeldet.`),
  },
  en: {
    changed: /Changed \S/,
    cardHelp: "advisory about this product changed within the last 30 days",
    title: "Changes",
    now: "now",
    kind: "Advisory changed",
    save: "Save",
    edit: "Edit",
    actions: "More actions",
    block: "Block permanently",
    unblock: "Lift the permanent block",
    offAdmin: "Blocked by an admin",
    remove: "Remove",
    cancel: "Cancel",
    removeTitle: "Remove the mapping?",
    endSessions: "Sign out those concerned at once",
    mapNone: "By the stored groups nobody loses their role.",
    mapLost: (n) => (n === 1 ? "1 account loses access." : `${n} accounts lose access.`),
    ldapCard: "Sign-in with Active Directory",
    offTitle: "Switch Active Directory off?",
    offNone: "Nobody is signed in through Active Directory right now.",
    offSome: (n) => (n === 1 ? "1 account from Active Directory is signed in right now." : `${n} accounts from Active Directory are signed in right now.`),
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

async function noScroll(page) {
  return page.evaluate(() => {
    const d = document.documentElement
    const wide = (el) => !!el && el.scrollWidth > el.clientWidth + 1
    const sheet = document.querySelector("[data-slot=sheet-content]")
    return { ok: !wide(d) && !wide(sheet), scroll: d.scrollWidth, client: d.clientWidth, sheet: wide(sheet) }
  })
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

/** The tooltip of an element: hovered (and focused, for the keyboard) – its text, or "" when none opened. */
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

function watch(page) {
  const errors = []
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`))
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`)
  })
  return errors
}

async function scrollCheck(page, tag, name, shot) {
  const s = await noScroll(page)
  check(`${tag} ${name}: no horizontal scroll`, s.ok, s.ok ? undefined : s)
  if (SHOTS && shot) await page.screenshot({ path: `${SHOTS}/${shot}.png` })
}

// ---------------------------------------------------------------- a) + b): the reader

async function reader(ctx, page, lang, width, theme, tag) {
  const T = L[lang]
  const shot = (name) => `${lang}-${width}-${theme}-${name}`
  const wide = width === 1280 && theme === "light"

  // the overview: the card (or row) of panos says "Geändert", its tooltip explains
  await page.goto(`${BASE}/vendor`)
  await settle(page)
  const hint = page.getByText(T.changed).first()
  const hintShown = (await hint.count()) > 0 && (await hint.isVisible())
  const hintTip = hintShown ? await tooltipOf(page, hint) : ""
  check(`${tag} overview: the product says "${T.changed.source.split(" ")[0]}", the tooltip explains`, hintShown && hintTip.includes(T.cardHelp), { hintShown, hintTip })
  await scrollCheck(page, tag, "overview", shot("vendor_overview"))

  // the drawer: the finding's badge with its revision in the tooltip, the sub-tab "Änderungen"
  await page.goto(`${BASE}/vendor?product=panos`)
  await settle(page)
  const sheet = page.locator("[data-slot=sheet-content]")
  const badge = sheet.getByText(T.changed).first()
  const badgeShown = (await badge.count()) > 0 && (await badge.isVisible())
  const badgeTip = badgeShown ? await tooltipOf(page, badge) : ""
  check(`${tag} drawer: the finding's badge, its tooltip names Revision 2`, badgeShown && badgeTip.includes("Revision 2"), { badgeShown, badgeTip })
  const tab = sheet.getByRole("link", { name: new RegExp(`^${T.title}`) })
  check(`${tag} drawer: the sub-tab "${T.title}" is there`, (await tab.count()) === 1)
  await scrollCheck(page, tag, "drawer findings", wide && shot("drawer_finding"))

  // the deep link opens the tab itself; the impact on the version entered first, in the "worse" tone
  await page.goto(`${BASE}/vendor?product=panos&view=changes`)
  await settle(page)
  const active = (await tab.getAttribute("aria-current").catch(() => null)) === "page"
  const rev = sheet.locator("ol > li").first()
  const revText = (await rev.count()) ? await rev.innerText() : ""
  const first = rev.locator("ul > li").first()
  const firstText = (await first.count()) ? await first.innerText() : ""
  const firstWorse = (await first.count()) ? /text-sev-critical/.test((await first.getAttribute("class")) ?? "") : false
  check(`${tag} deep link view=changes: the tab is active, Revision 2 listed`, active && revText.includes("Revision 2"), { active, revText: revText.slice(0, 160) })
  check(`${tag} changes: the impact on 11.2.4-h23 is the first line (red)`, firstText.includes("11.2.4-h23") && firstText.includes(T.now) && firstWorse, { firstText, firstWorse })
  await scrollCheck(page, tag, "drawer changes", shot("drawer_changes"))

  // a story of that advisory: its "Änderungen"
  const story = await findStory(ctx, "CVE-2026-1001")
  if (story) {
    await page.goto(`${BASE}/?story=${story.id}`)
    await settle(page)
    const sec = page
      .locator("[data-slot=sheet-content] section")
      .filter({ has: page.getByRole("heading", { name: T.title }) })
      .first()
    const secText = (await sec.count()) ? await sec.innerText() : ""
    check(`${tag} story: the section "${T.title}" with Revision 2`, secText.includes("Revision 2") && secText.includes("11.2.4-h30"), { secText: secText.slice(0, 160) })
    await scrollCheck(page, tag, "story", wide && shot("story_changes"))
  } else check(`${tag} story: seed – a story of CVE-2026-1001`, false)

  // b) the personal kind, off by default; on and saved, then off again
  const before = await json(ctx, "/api/me/vendor-notify")
  await page.goto(`${BASE}/settings/notifications?tab=vendor`)
  await settle(page)
  const sw = page.getByRole("switch", { name: T.kind, exact: true })
  const shown = (await sw.count()) === 1
  check(`${tag} personal: the toggle "${T.kind}", off by default`, shown && (await sw.getAttribute("aria-checked")) === "false" && !before.kinds.includes("vendor_change"), {
    shown,
    kinds: before.kinds,
  })
  await scrollCheck(page, tag, "personal", shot("personal_kind"))
  if (wide && shown) {
    const save = page.getByRole("button", { name: T.save, exact: true })
    await sw.click()
    await save.click()
    await settle(page)
    const on = await json(ctx, "/api/me/vendor-notify")
    const sw2 = page.getByRole("switch", { name: T.kind, exact: true })
    check(`${lang} personal: switched on and saved`, on.kinds.includes("vendor_change") && (await sw2.getAttribute("aria-checked")) === "true", { kinds: on.kinds })
    await sw2.click()
    await page.getByRole("button", { name: T.save, exact: true }).click()
    await settle(page)
    const off = await json(ctx, "/api/me/vendor-notify")
    check(`${lang} personal: switched off again and saved`, !off.kinds.includes("vendor_change"), { kinds: off.kinds })
  }
}

// ---------------------------------------------------------------- a) rule kind + c): the admin

async function admin(ctx, page, lang, width, theme, tag) {
  const T = L[lang]
  const shot = (name) => `${lang}-${width}-${theme}-${name}`
  const wide = width === 1280 && theme === "light"
  const h = { "X-CSRF-Token": await csrfOf(ctx) }
  const dialog = page.getByRole("dialog").last()

  // the rule editor offers the kind "Advisory geändert"
  await page.goto(`${BASE}/settings/rules?tab=rules`)
  await settle(page)
  await page.getByRole("button", { name: T.edit }).first().click()
  await settle(page)
  const kind = page.getByRole("switch", { name: T.kind, exact: true })
  check(`${tag} rule editor: the kind "${T.kind}" as a toggle`, (await kind.count()) === 1)
  await scrollCheck(page, tag, "rule editor", wide && shot("rule_kind"))

  // c) the permanent block of an account the sync switched off
  await page.goto(`${BASE}/settings/users`)
  await settle(page)
  const row = () => page.locator("li").filter({ hasText: "Dora Verzeichnis" }).first()
  const dora = async () => (await json(ctx, "/api/admin/users")).find((u) => u.username === "dora.dir")
  await row().getByRole("button", { name: T.actions }).click()
  const blockItem = page.getByRole("menuitem", { name: T.block })
  check(`${tag} users: "${T.block}" in "${T.actions}" for the account the sync switched off`, (await blockItem.count()) === 1 && (await blockItem.isEnabled()), {
    reason: (await dora())?.deactivated_reason,
  })
  if (SHOTS && wide) await page.screenshot({ path: `${SHOTS}/${shot("users_menu")}.png` })
  if (wide) {
    await blockItem.click()
    await dialog.getByRole("button", { name: T.block, exact: true }).click()
    await settle(page)
    const d1 = await dora()
    check(
      `${lang} users: blocked – the pill "${T.offAdmin}", the server says admin`,
      (await row().innerText()).includes(T.offAdmin) && !d1.is_active && d1.deactivated_reason === "admin",
      { reason: d1.deactivated_reason },
    )
    await row().getByRole("button", { name: T.actions }).click()
    await page.getByRole("menuitem", { name: T.unblock }).click()
    await dialog.getByRole("button", { name: T.unblock, exact: true }).click()
    await settle(page)
    const d2 = await dora()
    check(
      `${lang} users: block lifted – the pill gone, back to the sync`,
      !(await row().innerText()).includes(T.offAdmin) && !d2.is_active && d2.deactivated_reason?.startsWith("sync:"),
      { reason: d2.deactivated_reason },
    )
  } else await page.keyboard.press("Escape")
  await scrollCheck(page, tag, "users", false)

  // c) removing a role mapping: the toggle (on) and the number concerned
  let maps = await json(ctx, "/api/admin/auth/mappings")
  if (!maps.some((m) => m.group_id === TMP_GROUP)) {
    const r = await ctx.request.post(`${BASE}/api/admin/auth/mappings`, { data: { source: "ldap", group_id: TMP_GROUP, group_name: "News-Kurzzeit", role: "reader" }, headers: h })
    if (!r.ok()) check(`${tag} mapping: added again for the check`, false, r.status())
    maps = await json(ctx, "/api/admin/auth/mappings")
  }
  const m = maps.find((x) => x.group_id === TMP_GROUP)
  const impact = await json(ctx, `/api/admin/auth/mappings/${m.id}/impact`)
  await page.goto(`${BASE}/settings/users?tab=mapping`)
  await settle(page)
  await page.locator("li").filter({ hasText: "News-Kurzzeit" }).first().getByRole("button", { name: T.remove }).click()
  await dialog
    .getByText(T.removeTitle)
    .waitFor({ timeout: 5000 })
    .catch(() => {})
  await page.waitForTimeout(500)
  const end = dialog.getByRole("switch", { name: T.endSessions })
  const mapText = await dialog.innerText()
  const expect = impact.lost ? T.mapLost(impact.lost) : impact.demoted || impact.unknown ? null : T.mapNone
  check(
    `${tag} mapping removal: the toggle "${T.endSessions}" on, the number concerned`,
    (await end.count()) === 1 && (await end.getAttribute("aria-checked")) === "true" && (expect ? mapText.includes(expect) : /\d/.test(mapText)),
    { impact, expect },
  )
  await scrollCheck(page, tag, "mapping dialog", shot("mapping_dialog"))
  if (wide) {
    await dialog.getByRole("button", { name: T.remove, exact: true }).click()
    await settle(page)
    const gone = !(await json(ctx, "/api/admin/auth/mappings")).some((x) => x.id === m.id)
    const kai = (await json(ctx, "/api/admin/users")).find((u) => u.username === "kai.ldap")
    check(`${lang} mapping removal: the mapping is gone (API)`, gone, { kai: kai && { active: kai.is_active, reason: kai.deactivated_reason } })
  } else await dialog.getByRole("button", { name: T.cancel, exact: true }).click()

  // c) switching AD/LDAP off: the same question before saving – cancelled, nothing saved
  const off = await json(ctx, "/api/admin/auth/ldap/impact")
  await page.goto(`${BASE}/settings/auth`)
  await settle(page)
  const card = page.locator("section").filter({ has: page.getByText(T.ldapCard, { exact: true }) })
  const on = card.locator("[role=switch]").first()
  const wasOn = (await on.getAttribute("aria-checked")) === "true"
  if (wasOn) {
    await on.click()
    await card.getByRole("button", { name: T.save, exact: true }).click()
    await dialog
      .getByText(T.offTitle)
      .waitFor({ timeout: 5000 })
      .catch(() => {})
    await page.waitForTimeout(500)
    const offText = await dialog.innerText()
    const endOff = dialog.getByRole("switch", { name: T.endSessions })
    const want = off.accounts ? T.offSome(off.accounts) : T.offNone
    check(
      `${tag} AD off: the toggle "${T.endSessions}" on, the number signed in`,
      offText.includes(T.offTitle) && (await endOff.count()) === 1 && (await endOff.getAttribute("aria-checked")) === "true" && offText.includes(want),
      { accounts: off.accounts, want },
    )
    await scrollCheck(page, tag, "AD off dialog", shot("ldap_off_dialog"))
    await dialog.getByRole("button", { name: T.cancel, exact: true }).click()
    await page.waitForTimeout(300)
    await on.click() // back on: the form is clean again
    const still = await json(ctx, "/api/admin/auth/ldap")
    check(`${tag} AD off: cancelled – still on`, still.enabled === true)
  } else check(`${tag} AD off: seed – AD/LDAP is on`, false)
}

const browser = await chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
const usedMfa = new Set()
try {
  for (const lang of ["de", "en"]) {
    for (const width of [1280, 375]) {
      for (const theme of ["light", "dark"]) {
        const tag = `${lang} ${width}px ${theme}`
        const opts = { serviceWorkers: "block", locale: lang === "de" ? "de-DE" : "en-GB", viewport: { width, height: 860 }, colorScheme: theme }

        const rctx = await browser.newContext(opts)
        await stub(rctx, lang, theme)
        const rp = await rctx.newPage()
        const rerr = watch(rp)
        await signIn(rctx, rp, creds.reader, creds.reader_password, "")
        await reader(rctx, rp, lang, width, theme, tag)
        check(`${tag} reader: no page or console errors`, rerr.length === 0, rerr.slice(0, 3))
        await rctx.close()

        const ctx = await browser.newContext(opts)
        await stub(ctx, lang, theme)
        const page = await ctx.newPage()
        const errors = watch(page)
        // a TOTP code is accepted once – wait for the next step when this one was used
        if (usedMfa.has(Math.floor(Date.now() / 30000))) await page.waitForTimeout(30000 - (Date.now() % 30000) + 500)
        await signIn(ctx, page, creds.user, creds.password, creds.totp)
        usedMfa.add(Math.floor(Date.now() / 30000))
        await admin(ctx, page, lang, width, theme, tag)
        check(`${tag} admin: no page or console errors`, errors.length === 0, errors.slice(0, 3))
        await ctx.close()
      }
    }
  }
} finally {
  await browser.close()
}
const failed = results.filter((x) => !x).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed ? 1 : 0)
