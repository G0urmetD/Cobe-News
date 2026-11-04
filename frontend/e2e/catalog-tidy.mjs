// Browser check (0.1.47): catalogue tidy-up and TLP:GREEN.
// - Versions: Firefox ESR refuses 134.0 with its release lines and takes 140.4.0esr; Exchange's ExSetup form
//   15.02.1748.024 shows "→ 15.2.1748.24" before saving; the catalogue says "Mozilla Firefox".
// - TLP:GREEN per CSAF provider (Integrationen → Vendor News → Weitere Quellen): a click on the ⓘ does not switch it, a
//   click on its label does; switched off again, saving asks first (its GREEN advisories go).
// - The TLP:GREEN pill (seed147: a GREEN advisory of PAN-OS): its explanation on hover, keyboard focus and touch on the
//   finding, on the overview card's line too; the new pills' text (TLP:GREEN, Exploit-Code öffentlich) readable in light
//   and dark (contrast at least 4.5:1).
// DE and EN (the flows, 1280 px light), 1280 px and 375 px, light and dark (the pages): no page error, no console error,
// no horizontal scroll. Env: BASE_URL, CREDS, PLAYWRIGHT, SHOTS.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { BASE, COMBOS, H, SHOTS, check, creds, dismissToasts, finish, json, open, pw, scrollCheck, settle, signIn } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

async function until(fn, ms = 8000, step = 250) {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn().catch(() => false)
    if (v || Date.now() > end) return v
    await new Promise((r) => setTimeout(r, step))
  }
}
const sheet = (p) => p.locator("[data-slot=sheet-content]")
async function form(p, key, t) {
  await p.goto(`${BASE}/vendor?product=${key}&view=versions`)
  await settle(p)
  const section = p.locator("section[aria-labelledby=vendor-add]")
  if (!(await section.count())) {
    const add = sheet(p).getByRole("button", { name: t("vendor.add.open") })
    if (await add.count()) await add.first().click()
  }
  const input = section.locator("input").first()
  await input.waitFor({ timeout: 8000 })
  return { section, input, hint: section.locator(`[id="${await input.getAttribute("aria-describedby")}"]`), submit: section.getByRole("button", { name: t("vendor.add.submit") }) }
}
async function enter(p, key, text, t, want) {
  const f = await form(p, key, t)
  await f.input.fill(text)
  const shown = await until(async () => {
    const h = (await f.hint.innerText()).replace(/\s+/g, " ").trim()
    return want(h) && h
  })
  return { ...f, shown, text: (await f.hint.innerText()).replace(/\s+/g, " ").trim() }
}
/** Contrast of an element's text against what is behind it (its own background blended over its ancestors'). */
const contrastOf = (loc) =>
  loc.evaluate((el) => {
    // any CSS colour (oklch, color-mix, rgb …) as sRGB 0–255 with alpha 0–1: painted on a 1×1 canvas and read back
    const cv = document.createElement("canvas")
    cv.width = cv.height = 1
    const cx = cv.getContext("2d", { willReadFrequently: true })
    const rgba = (s) => {
      cx.clearRect(0, 0, 1, 1)
      cx.fillStyle = "#000"
      cx.fillStyle = s
      cx.fillRect(0, 0, 1, 1)
      const [r, g, b, a] = cx.getImageData(0, 0, 1, 1).data
      return [r, g, b, a / 255]
    }
    const over = (top, under) => [0, 1, 2].map((i) => top[i] * top[3] + under[i] * (1 - top[3])).concat([1])
    const layers = []
    for (let x = el; x; x = x.parentElement) {
      const c = rgba(getComputedStyle(x).backgroundColor)
      if (c[3] > 0) layers.push(c)
      if (c[3] >= 1) break
    }
    let bg = [255, 255, 255, 1]
    for (const c of layers.reverse()) bg = over(c, bg)
    const fg = over(rgba(getComputedStyle(el).color), bg)
    const lum = (c) => {
      const [r, g, b] = c.slice(0, 3).map((v) => {
        v /= 255
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
      })
      return 0.2126 * r + 0.7152 * g + 0.0722 * b
    }
    const [a, b] = [lum(fg), lum(bg)].sort((x, y) => y - x)
    return Math.round(((a + 0.05) / (b + 0.05)) * 100) / 100
  })
async function tipOn(p, el, how) {
  // the previous tooltip away – no Escape (it would close the drawer the pill is in)
  await p.mouse.move(0, 0)
  await p.evaluate(() => document.activeElement instanceof HTMLElement && document.activeElement.blur())
  await p.waitForTimeout(400)
  if (how === "hover") await el.hover()
  else if (how === "focus") await el.focus()
  else await el.tap()
  const tip = p.locator("[data-slot=tooltip-content]").first()
  const ok = await until(async () => (await tip.count()) > 0 && (await tip.innerText()).includes("TLP"), 3000)
  return ok ? (await tip.innerText()).replace(/\s+/g, " ") : ""
}

async function versionsFlow(r, combo, t) {
  const tag = `${combo.lang} versions`
  const p = r.page
  const h = await H(r.ctx)
  for (const key of ["firefox-esr", "firefox", "msexchange"]) await r.ctx.request.put(`${BASE}/api/vendor/follows/${key}`, { data: { enabled: true }, headers: h })
  const v = await json(r.ctx, `/api/vendor/validate?product=firefox-esr&version=134.0`)
  const esr = await enter(p, "firefox-esr", "134.0", t, (x) => x.startsWith(t("vendor.invalid.implausible", { lines: (v.lines ?? []).join(", "), example: v.example })))
  check(
    `${tag}: Firefox ESR "134.0" refused – the release lines (${(v.lines ?? []).join(", ")}), saving off`,
    !!esr.shown && v.reason === "implausible" && (await esr.submit.isDisabled()),
    { hint: esr.text.slice(0, 160), reason: v.reason },
  )
  const ok = await enter(p, "firefox-esr", "140.4.0esr", t, (x) => x.includes(t("vendor.form.formatOk")) || x.startsWith("→"))
  check(`${tag}: Firefox ESR "140.4.0esr" taken`, !!ok.shown && (await ok.submit.isEnabled()), { hint: ok.text })
  const ex = await enter(p, "msexchange", "15.02.1748.024", t, (x) => x.includes(t("vendor.form.mapped", { version: "15.2.1748.24" })))
  check(`${tag}: Exchange "15.02.1748.024" – "→ 15.2.1748.24" before saving`, !!ex.shown, { hint: ex.text })
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "Exchange leading zeros", SHOTS && `${combo.lang}-exchange_zeros`)
  const cat = await json(r.ctx, "/api/vendor/catalog")
  const ff = cat.products.find((x) => x.key === "firefox")?.label
  await p.goto(`${BASE}/vendor?tab=catalog`)
  await settle(p)
  await p.getByPlaceholder(t("vendor.searchCatalog")).fill("firefox")
  await p.waitForTimeout(500)
  const labels = (await p.locator("main ul.divide-y > li button p.text-sm").allInnerTexts()).map((x) => x.split("\n")[0].trim())
  check(
    `${tag}: the catalogue says "Mozilla Firefox" (and "Mozilla Firefox ESR")`,
    ff === "Mozilla Firefox" && labels.includes("Mozilla Firefox") && labels.includes("Mozilla Firefox ESR"),
    { ff, labels: labels.slice(0, 4) },
  )
}

async function greenFlow(r, combo, t) {
  const tag = `${combo.lang} TLP:GREEN`
  const p = r.page
  await p.goto(`${BASE}/settings/integrations?vendor=sources`)
  await settle(p)
  const s = sheet(p)
  const sw = s.getByRole("switch", { name: new RegExp(`: ${t("vendor.src.allowGreen")}$`) }).first()
  await sw.waitFor({ timeout: 8000 })
  const id = await sw.getAttribute("id")
  const row = s.locator("li").filter({ has: p.locator(`[id="${id}"]`) })
  const provider = ((await sw.getAttribute("aria-label")) ?? "").split(":")[0]
  const before = await sw.getAttribute("aria-checked")
  await row.locator(`svg[aria-label="${t("vendor.tlpGreenHint")}"]`).click()
  await p.waitForTimeout(300)
  const afterInfo = await sw.getAttribute("aria-checked")
  await row.locator(`label[for="${id}"]`).click()
  await p.waitForTimeout(300)
  const afterLabel = await sw.getAttribute("aria-checked")
  check(
    `${tag}: ${provider} – a click on the ⓘ leaves the switch (${before}), a click on "${t("vendor.src.allowGreen")}" switches it`,
    before === afterInfo && afterLabel !== before,
    { before, afterInfo, afterLabel },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "TLP:GREEN switches", SHOTS && `${combo.lang}-green_switches`)
  // on and saved – then off: saving asks first
  if (afterLabel !== "true") await row.locator(`label[for="${id}"]`).click()
  await s
    .getByRole("button", { name: t("common.save"), exact: true })
    .last()
    .click()
  await until(async () => ((await json(r.ctx, "/api/admin/vendor")).settings?.csaf_green ?? []).length > 0, 6000)
  await dismissToasts(p)
  await row.locator(`label[for="${id}"]`).click()
  await s
    .getByRole("button", { name: t("common.save"), exact: true })
    .last()
    .click()
  const dlg = p.getByRole("dialog").filter({ hasText: t("vendor.src.greenOffTitle") })
  const asked = await until(async () => (await dlg.count()) === 1, 5000)
  const dtext = asked ? (await dlg.innerText()).replace(/\s+/g, " ") : ""
  if (asked) await dlg.getByRole("button", { name: t("vendor.src.greenOffConfirm") }).click()
  const off = await until(async () => ((await json(r.ctx, "/api/admin/vendor")).settings?.csaf_green ?? []).length === 0, 6000)
  check(`${tag}: switched off – saving asks "${t("vendor.src.greenOffTitle")}" naming ${provider}; confirmed, off`, asked && dtext.includes(provider) && !!off, { asked, off })
  await dismissToasts(p)
}

async function pillFlow(browser, combo, t, touch) {
  const tag = `${combo.lang} ${combo.width}px ${combo.theme} TLP pill`
  const r = await open(browser, combo, touch ? { hasTouch: true } : {})
  await signIn(r.ctx, creds.watcher, creds.watcher_password)
  const p = r.page
  await p.goto(`${BASE}/vendor?product=panos`)
  await settle(p)
  const finding = sheet(p).locator('li[data-finding="paloalto:PAN-SA-2026-0077"]')
  const pill = finding.getByText("TLP:GREEN", { exact: true }).first()
  const tips = {}
  for (const how of touch ? ["tap"] : ["hover", "focus"])
    tips[how] = await tipOn(p, how === "focus" ? finding.locator("[tabindex]").filter({ hasText: "TLP:GREEN" }).first() : pill, how)
  const want = t("glossary.tlp", { defaultValue: "TLP" })
  check(
    `${tag}: on the finding – its explanation by ${Object.keys(tips).join(" and ")}`,
    Object.values(tips).every((x) => x.includes(want) || x.includes("TLP:GREEN")),
    tips,
  )
  const contrast = { tlp: await contrastOf(pill) }
  const ex = sheet(p).getByText(t("exploit.pill"), { exact: true }).first()
  if (await ex.count()) contrast.exploit = await contrastOf(ex)
  check(
    `${tag}: readable – contrast TLP:GREEN ${contrast.tlp}:1, "${t("exploit.pill")}" ${contrast.exploit}:1 (≥ 4.5)`,
    contrast.tlp >= 4.5 && (contrast.exploit ?? 0) >= 4.5,
    contrast,
  )
  await scrollCheck(p, tag, "finding with TLP:GREEN", SHOTS && `${combo.lang}-${combo.width}-${combo.theme}-tlp_finding`)
  await p.keyboard.press("Escape")
  await p.goto(`${BASE}/vendor?status=all`)
  await settle(p)
  const line = p.locator("main article").filter({ hasText: "PAN-OS" }).first().getByText("TLP:GREEN", { exact: true }).first()
  const has = (await line.count()) === 1
  const lc = has ? await contrastOf(line) : 0
  if (!touch) {
    const lineTip = has ? await tipOn(p, line, "hover") : ""
    check(`${tag}: on the overview card's line – its explanation (hover), contrast ${lc}:1`, has && lineTip.includes("TLP") && lc >= 4.5, {
      has,
      lineTip: lineTip.slice(0, 80),
      lc,
    })
  } else {
    // the pill sits beside the line's button (0.1.48: a focus stop of its own) – a tap explains it, the finding stays shut
    const tip = has ? await tipOn(p, line, "tap") : ""
    const opened = (await sheet(p).locator('li[data-finding="paloalto:PAN-SA-2026-0077"]').count()) > 0
    check(`${tag}: on the overview card's line (touch) – a tap explains it, contrast ${lc}:1`, has && lc >= 4.5 && tip.includes("TLP") && !opened, {
      has,
      lc,
      opened,
      tip: tip.slice(0, 60),
    })
  }
  check(`${tag}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

/** The CSAF providers under Weitere Quellen (be56216): two columns – name and state left (they wrap there), the
 *  TLP:GREEN switch in one column on the right; no horizontal scroll. */
async function providerLayout(page, combo) {
  const tag = `${combo.lang} ${combo.width}px ${combo.theme} CSAF providers`
  await page.goto(`${BASE}/settings/integrations?vendor=sources`)
  await settle(page)
  await sheet(page).locator('[id^="green-"]').first().waitFor({ timeout: 8000 })
  const rows = await sheet(page)
    .locator("li")
    .filter({ has: page.locator('[id^="green-"]') })
    .evaluateAll((lis) =>
      lis.map((li) => {
        const r = (el) => el.getBoundingClientRect()
        const sw = li.querySelector('[id^="green-"]')
        const left = li.firstElementChild
        const name = left.firstElementChild
        const lh = parseFloat(getComputedStyle(name).lineHeight) || 16
        return {
          name: name.textContent.trim(),
          swLeft: Math.round(r(sw).left),
          swRight: Math.round(r(sw).right),
          leftRight: Math.round(r(left).right),
          liRight: Math.round(r(li).right),
          nameLines: Math.round(r(name).height / lh),
          swRowTop: Math.round(r(sw.parentElement).top),
          swRowH: Math.round(r(sw.parentElement).height),
        }
      }),
    )
  const xs = rows.map((x) => x.swLeft)
  const aligned = rows.length > 1 && Math.max(...xs) - Math.min(...xs) <= 1
  const apart = rows.every((x) => x.leftRight <= x.swLeft && x.swRight <= x.liRight + 0.5)
  const oneLine = rows.every((x) => x.swRowH <= 28)
  check(
    `${tag}: ${rows.length} rows – the switches in one column (x ${Math.min(...xs)}–${Math.max(...xs)}), name and state left of them, the switch's side one line (${rows.filter((x) => x.nameLines > 1).length} names wrap)`,
    aligned && apart && oneLine,
    rows.filter((x) => !(x.leftRight <= x.swLeft) || x.swRowH > 28 || Math.abs(x.swLeft - xs[0]) > 1).slice(0, 3),
  )
  await scrollCheck(page, `${combo.lang} ${combo.width}px ${combo.theme}`, "CSAF providers", SHOTS && `${combo.lang}-${combo.width}-${combo.theme}-csaf_providers`)
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) {
    const t = texts(combo.lang)
    if (combo.wide) {
      const r = await open(browser, combo)
      await signIn(r.ctx, creds.user, creds.password, true)
      await versionsFlow(r, combo, t)
      await greenFlow(r, combo, t)
      await providerLayout(r.page, combo)
      check(`${combo.lang} admin: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
      await r.ctx.close()
    } else {
      const r = await open(browser, combo)
      await signIn(r.ctx, creds.user, creds.password, true)
      await providerLayout(r.page, combo)
      check(`${combo.lang} ${combo.width}px ${combo.theme} admin: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
      await r.ctx.close()
    }
    await pillFlow(browser, combo, t, combo.width < 768)
  }
} finally {
  await browser.close()
}
finish()
