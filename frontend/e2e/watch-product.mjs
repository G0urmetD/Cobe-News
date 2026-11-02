// Browser check (0.1.46): watched CVEs grouped by the product they concern – the default of "Beobachtete CVEs".
// - Without a parameter "Gruppieren nach: Produkt": a catalogue product's group (its title opens it in Vendor News,
//   "Gefolgt" for a followed product), groups named by the CVE record only – "laut CNA" and "laut NVD-CPE", each term
//   explained in its tooltip –, "+ N weitere Produkte" with the others in its tooltip, "Ohne Produktzuordnung" last.
// - "Herkunft" and "Keine" (?group_by=), the old ?groups=1&group=finding:… link opens the origin grouping.
// - "Gruppe nicht mehr beobachten" of a product group with "Rückgängig".
// DE and EN (the flows, 1280 px light), 1280 px and 375 px, light and dark (the pages): no page error, no console error,
// no horizontal scroll. It expects (seed146): product_user watching CVE-2026-3001/3002 (PAN-OS, followed, via the
// PAN-SA-2026-0042 link), CVE-2026-8001 (a CVE record naming Acme Widget Server, Agent and Console), CVE-2026-8002 (an
// NVD record with the CPE acme:gadget_hub) and CVE-2025-99992 (nothing names a product). Env: BASE_URL, CREDS,
// PLAYWRIGHT, SHOTS.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { BASE, COMBOS, SHOTS, check, creds, dismissToasts, finish, json, open, pw, scrollCheck, settle, signIn, toastAfter, toastCount, tooltipOf } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const group = (page, key) => page.locator(`[id="watch-group-${key}"]`)
const title = (page, key) => page.locator(`[id="watch-group-${key}-title"]`)
const nameKey = (label) => `name:${label.replace(/\s+/g, " ").trim().toLowerCase().replace(/ /g, "-")}`
async function until(fn, ms = 8000, step = 250) {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn().catch(() => false)
    if (v || Date.now() > end) return v
    await new Promise((r) => setTimeout(r, step))
  }
}
async function groupBy(page, t, by) {
  await page.getByRole("combobox", { name: t("watch.groupBy.label") }).click()
  await page.getByRole("option", { name: t(`watch.groupBy.${by}`), exact: true }).click()
  await settle(page)
}
const ids = async (ctx) => (await json(ctx, "/api/me/cve-watch/ids")).cves

async function flows(browser, combo, t) {
  const tag = `${combo.lang} by product`
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.product_user, creds.product_password)
  const p = r.page
  const items = (await json(r.ctx, "/api/me/cve-watch")).items
  const prod = Object.fromEntries(items.map((w) => [w.cve, w.product]))
  await p.goto(`${BASE}/watch`)
  await settle(p)
  const sel = (await p.getByRole("combobox", { name: t("watch.groupBy.label") }).innerText()).trim()
  const order = await p.locator("section[id^=watch-group-]").evaluateAll((els) => els.map((e) => e.id.replace("watch-group-", "")))
  const cna = prod["CVE-2026-8001"]
  const nvdP = prod["CVE-2026-8002"]
  check(
    `${tag}: "${t("watch.groupBy.label")}: ${t("watch.groupBy.product")}" by default; the API names PAN-OS (catalogue, followed), "${cna?.label}" (CNA), "${nvdP?.label}" (NVD), none`,
    sel === t("watch.groupBy.product") &&
      prod["CVE-2026-3001"]?.key === "panos" &&
      prod["CVE-2026-3001"]?.source === "catalog" &&
      prod["CVE-2026-3001"]?.followed &&
      cna?.source === "cna" &&
      nvdP?.source === "nvd" &&
      prod["CVE-2025-99992"]?.source === "none",
    {
      sel,
      prod,
    },
  )
  check(
    `${tag}: the groups – PAN-OS, the two named ones, "${t("watch.group.noProduct")}" last`,
    order.length === 4 && order.includes("product:panos") && order.includes(nameKey(cna.label)) && order.includes(nameKey(nvdP.label)) && order.at(-1) === "none",
    { order },
  )
  // the catalogue product: its link and "Gefolgt"
  const pan = group(p, "product:panos")
  const link = title(p, "product:panos").locator("a")
  const href = await link.getAttribute("href")
  const followed = (await pan.getByText(t("watch.group.followed"), { exact: true }).count()) === 1
  check(
    `${tag}: PAN-OS – its title opens it in Vendor News (${href}), "${t("watch.group.followed")}", 2 CVEs`,
    href === "/vendor?product=panos" && followed && (await pan.locator("ul > li").count()) === 2,
    { href, followed },
  )
  // named by the CVE record: "laut CNA", "laut NVD-CPE" – each explained
  const cg = group(p, nameKey(cna.label))
  const cnaTerm = cg.getByText("CNA", { exact: true })
  const cnaTip = (await cnaTerm.count()) ? await tooltipOf(p, cnaTerm) : ""
  const ng = group(p, nameKey(nvdP.label))
  const cpeTerm = ng.getByText("CPE", { exact: true })
  const cpeTip = (await cpeTerm.count()) ? await tooltipOf(p, cpeTerm) : ""
  const cHead = (await cg.locator("div").first().innerText()).replace(/\s+/g, " ")
  const nHead = (await ng.locator("div").first().innerText()).replace(/\s+/g, " ")
  check(
    `${tag}: "${cna.label}" – "${t("watch.group.nameFrom")} CNA" (tooltip: ${t("glossary.cna")}); "${nvdP.label}" – "${t("watch.group.nameFrom")} NVD-CPE" (tooltip: CPE)`,
    cHead.includes(`${t("watch.group.nameFrom")} CNA`) &&
      cnaTip.includes(t("glossary.cna")) &&
      nHead.includes(`${t("watch.group.nameFrom")} NVD-CPE`) &&
      cpeTip.includes("CPE") &&
      cpeTip.length > 20,
    { cHead: cHead.slice(0, 90), nHead: nHead.slice(0, 90), cnaTip: cnaTip.slice(0, 60), cpeTip: cpeTip.slice(0, 60) },
  )
  // "+ N weitere Produkte"
  const more = cg.getByText(t("watch.product.more", { count: cna.others.length }), { exact: true })
  const moreTip = (await more.count()) ? await tooltipOf(p, more) : ""
  check(
    `${tag}: "${t("watch.product.more", { count: cna.others.length })}" – "${t("watch.product.alsoAffects")}" ${cna.others.join(", ")}`,
    cna.others.length === 2 && moreTip.includes(t("watch.product.alsoAffects")) && cna.others.every((o) => moreTip.includes(o)),
    {
      moreTip,
    },
  )
  const none = group(p, "none")
  check(
    `${tag}: "${t("watch.group.noProduct")}" holds CVE-2025-99992`,
    (await none.innerText()).includes(t("watch.group.noProduct")) && (await none.innerText()).includes("CVE-2025-99992"),
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "by product", SHOTS && `${combo.lang}-watch_by_product`)
  // the title opens Vendor News
  await link.click()
  await settle(p)
  check(
    `${tag}: a click on the PAN-OS title – Vendor News with its drawer`,
    new URL(p.url()).pathname === "/vendor" && new URL(p.url()).searchParams.get("product") === "panos" && (await p.locator("[data-slot=sheet-content]").count()) === 1,
  )
  // Herkunft, Keine, the old link
  await p.goto(`${BASE}/watch`)
  await settle(p)
  await groupBy(p, t, "origin")
  const o1 =
    new URL(p.url()).searchParams.get("group_by") === "origin" &&
    (await group(p, "finding:panos:paloalto:PAN-SA-2026-0042").count()) === 1 &&
    (await group(p, "manual").count()) === 1
  await groupBy(p, t, "none")
  const n1 =
    new URL(p.url()).searchParams.get("group_by") === "none" &&
    (await p.locator("section[id^=watch-group-]").count()) === 0 &&
    (await p.locator("li[id^=watch-CVE-]").count()) === 5
  await groupBy(p, t, "product")
  const back = !new URL(p.url()).searchParams.get("group_by") || new URL(p.url()).searchParams.get("group_by") === "product"
  await p.goto(`${BASE}/watch?groups=1&group=${encodeURIComponent("finding:panos:paloalto:PAN-SA-2026-0042")}`)
  await settle(p)
  const old =
    (await p.getByRole("combobox", { name: t("watch.groupBy.label") }).innerText()).trim() === t("watch.groupBy.origin") &&
    (await group(p, "finding:panos:paloalto:PAN-SA-2026-0042").count()) === 1
  check(
    `${tag}: "${t("watch.groupBy.origin")}" (?group_by=origin), "${t("watch.groupBy.none")}" (one list of 5), back to "${t("watch.groupBy.product")}"; the old ?groups=1&group=finding:… opens the origin grouping`,
    o1 && n1 && back && old,
    { o1, n1, back, old },
  )
  // a product group's "Gruppe nicht mehr beobachten" with undo
  await p.goto(`${BASE}/watch`)
  await settle(p)
  await dismissToasts(p)
  const b = await toastCount(p)
  await group(p, nameKey(cna.label))
    .getByRole("button", { name: t("watch.group.remove") })
    .click()
  const toast = await toastAfter(p, b)
  const gone = await until(async () => !(await ids(r.ctx)).includes("CVE-2026-8001"))
  if (toast) await toast.el.getByRole("button", { name: t("watch.undo") }).click()
  const backAgain = await until(async () => (await ids(r.ctx)).includes("CVE-2026-8001"))
  const sameOrigin = (await json(r.ctx, "/api/me/cve-watch")).items.find((w) => w.cve === "CVE-2026-8001")
  const gBack = await until(async () => (await group(p, nameKey(cna.label)).count()) === 1)
  check(
    `${tag}: "${t("watch.group.remove")}" of "${cna.label}" – "${t("watch.undo")}" brings it back (manual origin, the same group)`,
    !!toast && toast.text.includes(t("watch.group.removed", { count: 1, title: cna.label })) && gone && backAgain && gBack && (sameOrigin?.origin?.kind ?? "manual") === "manual",
    {
      toast: toast?.text,
      gone,
      backAgain,
      gBack,
    },
  )
  await dismissToasts(p)
  check(`${combo.lang}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

async function pages(browser, combo) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme}`
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.product_user, creds.product_password)
  await r.page.goto(`${BASE}/watch`)
  await settle(r.page)
  await scrollCheck(r.page, tag, "by product", SHOTS && `${lang}-${width}-${theme}-watch_by_product`)
  const titles = await r.page
    .locator("section[id^=watch-group-] h3")
    .evaluateAll((els) =>
      els.map((e) => ({
        w: Math.round(e.getBoundingClientRect().width),
        row: Math.round(e.parentElement.getBoundingClientRect().width),
        lines: Math.round(e.getBoundingClientRect().height / parseFloat(getComputedStyle(e).lineHeight)),
      })),
    )
  check(`${tag}: no group title squeezed (half its header wide, or at most two lines)`, titles.length === 4 && titles.every((x) => x.w >= x.row / 2 || x.lines <= 2), { titles })
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
