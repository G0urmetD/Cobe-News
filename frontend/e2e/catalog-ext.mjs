// Browser check (0.1.45): the extended catalogue and the merged duplicates.
// - The catalogue search finds new products and search names: VBR, SCCM, MECM, Lync, M365 Apps, Check_MK, NSX-T,
//   XenApp, WSUS, Domain Controller, PaperCut, 3CX, FRITZ!Box – each first hit names the term in its label or search
//   names; "über 900" products (the API, "Alle" in the categories, the handbook).
// - Merged duplicates once: IBM Db2, Omnissa Horizon, Junos, Harbor, Cisco ESA – the old keys are gone from the catalogue.
// - Old links: /vendor?product=db2 opens IBM Db2, /vendor?tab=catalog&product=cisco-sma opens Cisco ESA.
// - Followed under old keys before migration 0025 (seeded at 0023): moved with their versions, teams, the saved view,
//   the mute and the watched CVE's origin – seen in the drawers, "Stummschaltungen" and the API.
// DE and EN (the flows, 1280 px light), 1280 px and 375 px, light and dark (the pages): no page error, no console error,
// no horizontal scroll. Env: BASE_URL, CREDS (admin, layout_team = vera), PLAYWRIGHT, SHOTS.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { BASE, COMBOS, SHOTS, check, creds, finish, json, open, pw, scrollCheck, settle, signIn } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const TERMS = ["VBR", "SCCM", "MECM", "Lync", "M365 Apps", "Check_MK", "NSX-T", "XenApp", "WSUS", "Domain Controller", "PaperCut", "3CX", "FRITZ!Box"]
const MERGED = [
  ["db2", "ibm-db2", "Db2"],
  ["vmware-horizon", "horizon", "Horizon"],
  ["juniper-srx", "junos", "Junos"],
  ["vmware-harbor-registry", "harbor", "Harbor"],
  ["cisco-sma", "cisco-esa", "Secure Email Gateway"],
]
const fold = (s) =>
  String(s ?? "")
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9!]+/g, " ")
    .trim()

async function catalogSearch(p, t, q) {
  await p.goto(`${BASE}/vendor?tab=catalog`)
  await settle(p)
  await p.getByPlaceholder(t("vendor.searchCatalog")).fill(q)
  await p.waitForTimeout(500)
  return (await p.locator("main ul.divide-y > li button p.text-sm").allInnerTexts()).map((x) => x.split("\n")[0].trim())
}
const drawerTitle = async (p) =>
  (
    await p
      .locator("[data-slot=sheet-content] [data-slot=sheet-title]")
      .first()
      .innerText()
      .catch(() => "")
  ).trim()

async function flows(browser, combo, t) {
  const tag = `${combo.lang} catalogue`
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.user, creds.password, true)
  const p = r.page
  const cat = await json(r.ctx, "/api/vendor/catalog")
  const byKey = Object.fromEntries(cat.products.map((x) => [x.key, x]))
  // the search names
  for (const q of TERMS) {
    const labels = await catalogSearch(p, t, q)
    const first = cat.products.find((x) => x.label === labels[0])
    const names = first ? [first.label, ...(first.aliases ?? []), ...(first.kw ?? [])].map(fold) : []
    check(`${tag}: "${q}" – first hit "${labels[0] ?? "–"}" (named so in its label or search names)`, !!first && names.some((n) => n.includes(fold(q))), {
      first: labels.slice(0, 3),
      aliases: first?.aliases?.slice(0, 4),
    })
    if (q === "SCCM") await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "catalogue search", SHOTS && `${combo.lang}-catalog_sccm`)
  }
  // "über 900"
  await p.goto(`${BASE}/vendor?tab=catalog`)
  await settle(p)
  const allCat = await p.locator("main nav button").first().innerText()
  const allN = Number((allCat.match(/(\d+)\s*$/) ?? [0, 0])[1])
  await p.goto(`${BASE}/docs/vendor-news`)
  await settle(p)
  const doc = await p.locator("main").innerText()
  check(
    `${tag}: over 900 products – the API (${cat.products.length}), "Alle" in the categories (${allN}), the handbook says "über 900"`,
    cat.products.length > 900 && allN === cat.products.length && /über 900|more than 900|over 900/.test(doc),
    {
      api: cat.products.length,
      allN,
    },
  )
  // merged duplicates: once, the old keys gone
  for (const [old, kept, q] of MERGED) {
    const labels = await catalogSearch(p, t, q)
    const want = byKey[kept]?.label
    check(`${tag}: merged "${old}" → "${want}" – once in the catalogue, the old key gone`, !!want && labels.filter((l) => l === want).length === 1 && !byKey[old], {
      labels: labels.slice(0, 4),
    })
  }
  // old links
  await p.goto(`${BASE}/vendor?product=db2`)
  await settle(p)
  const t1 = await drawerTitle(p)
  await p.goto(`${BASE}/vendor?tab=catalog&product=cisco-sma`)
  await settle(p)
  const t2 = await drawerTitle(p)
  check(
    `${tag}: /vendor?product=db2 opens "${byKey["ibm-db2"]?.label}", ?tab=catalog&product=cisco-sma opens "${byKey["cisco-esa"]?.label}"`,
    t1.includes(byKey["ibm-db2"]?.label) && t2.includes(byKey["cisco-esa"]?.label),
    {
      t1,
      t2,
    },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "old link drawer", SHOTS && `${combo.lang}-old_link_cisco_sma`)
  // followed under the old keys: moved with versions and teams
  for (const [key, version] of [
    ["ibm-db2", "11.5.9"],
    ["horizon", "2312"],
    ["junos", "22.4R3"],
    ["cisco-esa", "15.0.1"],
  ]) {
    await p.goto(`${BASE}/vendor?product=${key}&view=versions`)
    await settle(p)
    const body = await p.locator("[data-slot=sheet-content]").innerText()
    check(`${tag}: followed before the merge – ${byKey[key]?.label} has its version ${version} (and its label "E2E …")`, body.includes(version) && body.includes("E2E"))
  }
  const teams = await json(r.ctx, "/api/admin/teams/products")
  const flat = JSON.stringify(teams)
  check(
    `${tag}: the team assignments moved (junos, cisco-esa – no old key left)`,
    flat.includes('"junos"') && flat.includes('"cisco-esa"') && !flat.includes('"juniper-srx"') && !flat.includes('"cisco-sma"'),
    {
      sample: flat.slice(0, 160),
    },
  )
  check(`${combo.lang} admin: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
  // the reader's own: the saved view, the mute, the watched CVE's origin
  const v = await open(browser, combo)
  await signIn(v.ctx, creds.layout_team_user, creds.layout_team_password)
  const views = (await json(v.ctx, "/api/me/views?page=vendor")).items
  const mutes = (await json(v.ctx, "/api/me/mutes")).items
  const watch = (await json(v.ctx, "/api/me/cve-watch")).items.find((w) => w.cve === "CVE-2026-7001")
  await v.page.goto(`${BASE}/settings/notifications?tab=mutes`)
  await settle(v.page)
  const mutesPage = await v.page.locator("main").innerText()
  check(
    `${combo.lang} reader: the saved view says product=ibm-db2, the mute is "${byKey.horizon?.label}" (shown so under "${t("reader.mutes.tab")}"), the watched CVE's origin product cisco-esa`,
    views.some((x) => x.query.includes("product=ibm-db2")) &&
      mutes.some((m) => m.kind === "product" && m.key === "horizon") &&
      mutesPage.includes(byKey.horizon?.label) &&
      watch?.origin?.product === "cisco-esa",
    { views: views.map((x) => x.query), mutes: mutes.map((m) => m.key), origin: watch?.origin },
  )
  await scrollCheck(v.page, `${combo.lang} ${combo.width}px ${combo.theme}`, "mutes moved", SHOTS && `${combo.lang}-mutes_moved`)
  check(`${combo.lang} reader: no page or console errors`, v.errors.length === 0, v.errors.slice(0, 3))
  await v.ctx.close()
}

async function pages(browser, combo) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme}`
  const t = texts(lang)
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.layout_team_user, creds.layout_team_password)
  await catalogSearch(r.page, t, "MECM")
  await scrollCheck(r.page, tag, "catalogue search", SHOTS && `${lang}-${width}-${theme}-catalog`)
  await r.page.goto(`${BASE}/vendor?product=db2`)
  await settle(r.page)
  await scrollCheck(r.page, tag, "old link drawer", false)
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
