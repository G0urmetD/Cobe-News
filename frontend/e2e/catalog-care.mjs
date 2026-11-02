// Browser check (0.1.39): Katalog-Pflege – versions to review and product suggestions.
// - Versions due: "Bitte prüfen" in the drawer's versions tab, "Bestätigen", "Alle N bestätigen" (asked first); the
//   overview's "N Versionen zu prüfen" → the review panel with Meine / Alle; a finding's "Version prüfen" with its
//   tooltip; the interval (Integrationen → Vendor News) a select.
// - "Produkt fehlt? Vorschlagen": "Meinst du …?" opens the product; hints for what is missing or wrong; the CPE term's
//   tooltip; a long address and reason wrap at 375 px. A reader's "Meine Vorschläge" and its count of unseen answers
//   (cleared when seen); the admins' queue: accept by CPE (the product sheet prefilled → accepted with that product),
//   the catalogue entry copied, duplicate (the picker), reject with a reason; a reader gets 403 from the admin API.
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll. The changes run
// once per language (the wide light run); DB_CMD (SQL from stdin into the throwaway database) puts the seed back first:
// versions unconfirmed for 200 days, no suggestions, no custom products of an earlier run.
// Env: BASE_URL, CREDS ({user, password, totp, reader, reader_password}), PLAYWRIGHT, SHOTS, DB_CMD.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { execSync } from "node:child_process"
import crypto from "node:crypto"
import { BASE, COMBOS, H, SHOTS, check, creds, dismissToasts, finish, json, open, pw, scrollCheck, settle, signIn, toastAfter, toastCount, tooltipOf } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const DB_CMD = process.env.DB_CMD || ""
const sql = (text) => execSync(DB_CMD, { input: text, stdio: ["pipe", "ignore", "inherit"], shell: "/bin/sh" })
const rand = () => crypto.randomBytes(3).toString("hex")

function resetSeed() {
  sql(`UPDATE vendor_versions SET confirmed_at = now() - interval '200 days', confirmed_by = NULL;
DELETE FROM product_suggestions;
DELETE FROM vendor_follows WHERE product LIKE 'custom-%';`)
}

async function versions(page, ctx, t, tag, wide) {
  await page.goto(`${BASE}/vendor?product=panos`)
  await settle(page)
  const sheet = page.locator("[data-slot=sheet-content]")
  // the finding: "Version prüfen" with its tooltip
  const pill = sheet
    .locator("span[tabindex]")
    .filter({ hasText: t("review.findingPill") })
    .first()
  const shownPill = (await pill.count()) > 0
  const tip = shownPill ? await tooltipOf(page, pill) : ""
  check(`${tag} finding: "${t("review.findingPill")}" with its tooltip`, shownPill && tip.includes("11.2.4-h23"), { tip: tip.slice(0, 60) })
  await page.goto(`${BASE}/vendor?product=panos&view=versions`)
  await settle(page)
  const due = sheet.getByText(t("review.due"), { exact: true })
  const n0 = await due.count()
  check(`${tag} versions tab: "${t("review.due")}" for each version due`, n0 >= 2, { due: n0 })
  await scrollCheck(page, tag, "versions due", SHOTS && `${tag.replace(/ /g, "-")}-versions_due`)
  if (!wide) return
  const before = await toastCount(page)
  await sheet
    .getByRole("button", { name: t("review.confirm"), exact: true })
    .first()
    .click()
  const one = await toastAfter(page, before)
  await page.waitForTimeout(500)
  const n1 = await due.count()
  await dismissToasts(page)
  await sheet.getByRole("button", { name: t("review.confirmAllN", { count: n1 }) }).click()
  const dialog = page.getByRole("dialog").last()
  const asked = (await dialog.innerText().catch(() => "")).includes(t("review.allTitle"))
  await dialog.getByRole("button", { name: t("review.confirmAll"), exact: true }).click()
  await page.waitForTimeout(800)
  check(
    `${tag} "${t("review.confirm")}" one, then "${t("review.confirmAllN", { count: n1 })}" (asked first) – none due`,
    one?.type === "success" && n1 === n0 - 1 && asked && (await due.count()) === 0,
    {
      one: one?.type,
      n1,
      asked,
      left: await due.count(),
    },
  )
}

async function overview(page, t, tag) {
  await page.goto(`${BASE}/vendor`)
  await settle(page)
  // 0.1.43: "Versionen zu prüfen" is a switch in the tool row's "Filter" popover (with its count)
  await page.getByRole("button", { name: new RegExp(`^${t("vendor.filters.button")}(,|$)`) }).click()
  const sum = page.locator("[data-slot=popover-content]").getByRole("switch", { name: new RegExp(`^${t("review.filter")}`) })
  const has = (await sum.count()) === 1
  if (has) await sum.click()
  await page.keyboard.press("Escape")
  await settle(page)
  const panel = page.locator("main").getByText(t("review.title"), { exact: true })
  const scope = page.getByRole("radiogroup", { name: t("review.scope") })
  const mine = scope.getByRole("radio", { name: t("review.scopeMine") })
  const all = scope.getByRole("radio", { name: t("review.scopeAll") })
  const hasScope = (await all.count()) === 1
  if (hasScope) await all.click()
  await page.waitForTimeout(400)
  check(
    `${tag} overview: Filter → "${t("review.filter")}" → the review panel, Meine / Alle`,
    has && (await panel.count()) >= 1 && hasScope && (await all.getAttribute("aria-checked")) === "true" && (await mine.count()) === 1,
  )
  await scrollCheck(page, tag, "review panel", SHOTS && `${tag.replace(/ /g, "-")}-review_panel`)
}

async function interval(page, t, tag) {
  await page.goto(`${BASE}/settings/integrations`)
  await settle(page)
  await page
    .locator("main article")
    .filter({ hasText: t("nav.vendor") })
    .getByRole("button", { name: t("settings.int.configure") })
    .click()
  const sheet = page.locator("[data-slot=sheet-content]")
  await sheet.waitFor({ timeout: 5000 }).catch(() => {})
  const select = sheet
    .getByRole("combobox")
    .filter({ hasText: t("review.every", { count: 90 }) })
    .first()
  const has = (await select.count()) === 1
  if (has) await select.click()
  const options = has ? await page.getByRole("option").allInnerTexts() : []
  await page.keyboard.press("Escape")
  await page.keyboard.press("Escape")
  check(
    `${tag} Integrationen: "${t("review.setting")}" – ${t("review.every", { count: 90 })}, the choices`,
    has && options.includes(t("review.every", { count: 30 })) && options.includes(t("review.off")),
    { options },
  )
}

async function suggestSheet(page, t, tag, width, send) {
  await page.goto(`${BASE}/vendor?tab=suggestions`)
  await settle(page)
  await page
    .locator("main")
    .getByRole("button", { name: t("suggest.title") })
    .first()
    .click()
  const sheet = page.locator("[data-slot=sheet-content]")
  await sheet.waitFor({ timeout: 5000 }).catch(() => {})
  // "Meinst du …?" opens the product
  await sheet.getByPlaceholder("Edge Gateway").fill("PAN-OS")
  await page.waitForTimeout(400)
  const similar = sheet.getByRole("status").filter({ hasText: t("suggest.similar") })
  const hasSimilar = (await similar.count()) === 1
  if (hasSimilar) await similar.getByRole("button").first().click()
  await settle(page)
  const opened = new URL(page.url()).searchParams.get("product")
  check(`${tag} "${t("suggest.similar")}" opens the product`, hasSimilar && !!opened, { opened })
  await page.keyboard.press("Escape")
  await page.goto(`${BASE}/vendor?tab=suggestions`)
  await settle(page)
  await page
    .locator("main")
    .getByRole("button", { name: t("suggest.title") })
    .first()
    .click()
  await sheet.waitFor({ timeout: 5000 }).catch(() => {})
  // what is missing or wrong
  await sheet.getByRole("button", { name: t("suggest.send"), exact: true }).click()
  await page.waitForTimeout(300)
  const missing = (await sheet.innerText()).includes(t("suggest.fix", { fields: "" }).trim().replace(/:$/, ""))
  await sheet.getByPlaceholder("https://www.example.com/security").fill("ftp://example.com")
  const urlBad = (await sheet.getByPlaceholder("https://www.example.com/security").getAttribute("aria-invalid")) === "true"
  const cpeTip = await tooltipOf(
    page,
    sheet
      .locator("label span[tabindex]")
      .filter({ hasText: t("suggest.cpe") })
      .first(),
  )
  check(`${tag} suggest: hints for what is missing, an ftp address refused, the CPE tooltip`, missing && urlBad && cpeTip.length > 10, {
    missing,
    urlBad,
    cpeTip: cpeTip.slice(0, 30),
  })
  // long address and reason wrap
  await sheet.getByPlaceholder("Example Corp").fill(`Example Corp ${rand()}`)
  await sheet.getByPlaceholder("Edge Gateway").fill(`E2E Edge Gateway ${rand()}`)
  await sheet.getByPlaceholder("https://www.example.com/security").fill(`https://www.example.com/${"very-long-path-segment-".repeat(14)}end`)
  await sheet.locator("textarea").fill(`Wir betreiben es im Rechenzentrum: ${"Begründungohneleerzeichen".repeat(12)} – bitte aufnehmen.`)
  await scrollCheck(page, tag, `suggest sheet (long text${width < 768 ? ", phone" : ""})`, SHOTS && `${tag.replace(/ /g, "-")}-suggest`)
  if (send) {
    const before = await toastCount(page)
    await sheet.getByRole("button", { name: t("suggest.send"), exact: true }).click()
    const toast = await toastAfter(page, before)
    check(`${tag} suggestion sent`, toast?.type === "success" && toast.text.includes(t("suggest.sent")))
  } else await page.keyboard.press("Escape")
}

async function queue(browser, combo, t, admin, reader) {
  const { lang } = combo
  const tag = `${lang} queue`
  // three suggestions of the reader (through the API) – accept by CPE, duplicate, reject
  const make = async (product, cpe) =>
    (
      await reader.ctx.request.post(`${BASE}/api/vendor/suggestions`, {
        data: { vendor: "E2E Vendor", product, cpe, reason: "Läuft bei uns im Labor.", url: null, team_id: null },
        headers: await H(reader.ctx),
      })
    ).json()
  const s1 = await make(`E2E Accept ${rand()}`, `a:e2e_vendor:e2e_accept_${rand()}`)
  const s2 = await make(`E2E Duplicate ${rand()}`, null)
  const s3 = await make(`E2E Reject ${rand()}`, null)
  const page = admin.page
  await admin.ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: new URL(BASE).origin })
  await page.goto(`${BASE}/vendor?tab=suggestions`)
  await settle(page)
  const card = (s) => page.locator("main li").filter({ hasText: s.product }).first()
  // accept: the catalogue entry copied, then by CPE – the product sheet prefilled
  await card(s1)
    .getByRole("button", { name: t("suggest.accept"), exact: true })
    .click()
  const decide = page.locator("[data-slot=sheet-content]").last()
  await decide.getByRole("button", { name: t("suggest.copySnippet") }).click()
  await page.waitForTimeout(300)
  const snippet = await page.evaluate(() => navigator.clipboard.readText()).catch(() => "")
  await decide.getByRole("button", { name: t("suggest.adoptCpeButton") }).click()
  await page.waitForTimeout(800)
  const custom = page.locator("[data-slot=sheet-content]").last()
  const cpeField = custom.getByPlaceholder("a:vendor:product")
  const prefilled = (await cpeField.inputValue().catch(() => "")) === s1.cpe_short || (await cpeField.inputValue().catch(() => "")).length > 5
  await custom.getByRole("button", { name: t("vendor.custom.add") }).click()
  await page.waitForTimeout(1500)
  const after = await json(admin.ctx, "/api/admin/suggestions?state=done")
  const got1 = (after.items ?? after).find?.((x) => x.id === s1.id)
  check(
    `${tag}: accepted by CPE (prefilled) → with its product; the catalogue entry copied`,
    prefilled && got1?.status === "accepted" && !!got1?.result?.key && snippet.includes(s1.product),
    {
      prefilled,
      status: got1?.status,
      product: !!got1?.result?.key,
      snippet: snippet.slice(0, 30),
    },
  )
  await page.keyboard.press("Escape")
  await page.goto(`${BASE}/vendor?tab=suggestions`)
  await settle(page)
  // duplicate: the picker
  await card(s2)
    .getByRole("button", { name: t("suggest.duplicate"), exact: true })
    .click()
  const dup = page.locator("[data-slot=sheet-content]").last()
  await dup.getByRole("textbox").first().fill("PAN")
  await page.waitForTimeout(500)
  await dup
    .getByRole("list", { name: t("suggest.existing") })
    .getByRole("button")
    .first()
    .click()
  await dup
    .getByRole("button", { name: t("suggest.duplicate"), exact: true })
    .last()
    .click()
  await page.waitForTimeout(800)
  // reject with a reason
  await page.goto(`${BASE}/vendor?tab=suggestions`)
  await settle(page)
  await card(s3)
    .getByRole("button", { name: t("suggest.reject"), exact: true })
    .click()
  const rej = page.locator("[data-slot=sheet-content]").last()
  await rej.locator("textarea").fill("Nicht im Einsatz.")
  await rej
    .getByRole("button", { name: t("suggest.reject"), exact: true })
    .last()
    .click()
  await page.waitForTimeout(800)
  const done = await json(admin.ctx, "/api/admin/suggestions?state=done")
  const list = done.items ?? done
  const st = (s) => list.find?.((x) => x.id === s.id)
  check(`${tag}: duplicate (picker) and rejected with its reason`, st(s2)?.status === "duplicate" && st(s3)?.status === "rejected" && st(s3)?.answer === "Nicht im Einsatz.", {
    dup: st(s2)?.status,
    rej: st(s3)?.status,
  })
  await scrollCheck(page, `${lang} admin`, "suggestions queue", SHOTS && `${lang}-suggestions_queue`)

  // the reader: the answers counted until seen
  const c0 = await json(reader.ctx, "/api/vendor/suggestions/count")
  await reader.page.goto(`${BASE}/vendor?tab=suggestions`)
  await settle(reader.page)
  await reader.page.waitForTimeout(800)
  const c1 = await json(reader.ctx, "/api/vendor/suggestions/count")
  const mine = await reader.page.locator("main").innerText()
  check(
    `${lang} reader "${t("suggest.mine")}": the answers; the unseen count clears when seen`,
    (c0.answered ?? 0) >= 3 && (c1.answered ?? 0) === 0 && mine.includes(t("suggest.status.rejected")),
    { before: c0, after: c1 },
  )
  const forbidden = (await reader.ctx.request.get(`${BASE}/api/admin/suggestions`)).status()
  check(`${lang} reader: the admin API 403`, forbidden === 403, { forbidden })
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) {
    const { lang, width, theme, wide } = combo
    const t = texts(lang)
    const tag = `${lang} ${width}px ${theme}`
    if (wide && DB_CMD) resetSeed()
    else if (DB_CMD) sql("UPDATE vendor_versions SET confirmed_at = now() - interval '200 days', confirmed_by = NULL;")
    const admin = await open(browser, combo)
    await signIn(admin.ctx, creds.user, creds.password, true)
    await overview(admin.page, t, tag)
    await versions(admin.page, admin.ctx, t, tag, wide && !!DB_CMD)
    await interval(admin.page, t, tag)
    const reader = await open(browser, combo)
    await signIn(reader.ctx, creds.reader, creds.reader_password)
    await suggestSheet(reader.page, t, tag, width, wide)
    if (wide) await queue(browser, combo, t, admin, reader)
    check(`${tag} admin: no page or console errors`, admin.errors.length === 0, admin.errors.slice(0, 3))
    check(`${tag} reader: no page or console errors`, reader.errors.length === 0, reader.errors.slice(0, 3))
    await admin.ctx.close()
    await reader.ctx.close()
  }
} finally {
  await browser.close()
}
finish()
