// Browser check (0.1.42): vCenter and ESXi versions as admins see them, and "vSphere" finds them.
// - Katalog: "vsphere" and "VMware vSphere" list VMware vCenter Server and VMware ESXi as the first two (both have the
//   alias "vSphere" – a tie the page breaks by label; VMware vSphere Replication after them); "Produkt vorschlagen"
//   offers them so under "Meinst du …?".
// - Versions drawer of vCenter: the VAMI version 8.0.3.00400 shows "→ 8.0 U3d" before saving and is stored as 8.0 U3d,
//   the build 24322831 likewise; an unknown build gets the hint (DE/EN) and cannot be saved; the ESXi build 24022510
//   entered for vCenter is refused (hint, and the API answers 422). ESXi: build-24674464 → 8.0 U3e.
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll. The flows run
// once per language (the wide light run). Env: BASE_URL, CREDS, PLAYWRIGHT, SHOTS.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { BASE, COMBOS, H, SHOTS, check, dismissToasts, finish, creds, json, open, pw, scrollCheck, settle, signIn, toastAfter, toastCount } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const VCENTER = "VMware vCenter Server"
const ESXI = "VMware ESXi"
async function until(fn, ms = 8000, step = 250) {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn().catch(() => false)
    if (v || Date.now() > end) return v
    await new Promise((r) => setTimeout(r, step))
  }
}
const versionsOf = async (ctx, key) => {
  const d = await json(ctx, `/api/vendor/products/${key}`)
  return d.follow?.versions ?? d.versions ?? []
}
async function dropVersions(ctx, key) {
  for (const v of await versionsOf(ctx, key)) await ctx.request.delete(`${BASE}/api/vendor/versions/${v.id}`, { headers: await H(ctx) })
}

async function admin(browser, combo) {
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.user, creds.password, true)
  return r
}

async function catalog(p, t, tag) {
  const out = {}
  for (const q of ["vsphere", "VMware vSphere"]) {
    await p.goto(`${BASE}/vendor?tab=catalog`)
    await settle(p)
    await p.getByPlaceholder(t("vendor.searchCatalog")).fill(q)
    await p.waitForTimeout(600)
    const labels = (await p.locator("main ul.divide-y > li button p.text-sm").allInnerTexts()).map((x) => x.split("\n")[0].trim())
    out[q] = labels.slice(0, 3)
    // vCenter and ESXi both carry the alias "vSphere" (0.1.42): above VMware vSphere Replication, which only has the word
    check(`${tag}: catalogue search "${q}" – ${VCENTER} and ${ESXI} first`, topTwo(labels), {
      first: labels.slice(0, 3),
    })
  }
  // "Produkt vorschlagen": "Meinst du …?"
  await p
    .getByRole("button", { name: t("suggest.missing") })
    .first()
    .click()
  const dlg = p.getByRole("dialog").filter({ hasText: t("suggest.title") })
  await dlg.waitFor({ timeout: 6000 })
  await dlg.locator("input").nth(0).fill("VMware")
  await dlg.locator("input").nth(1).fill("vSphere")
  const box = dlg.getByRole("status").filter({ hasText: t("suggest.similar") })
  await until(async () => (await box.count()) === 1)
  const similar = (await box.getByRole("button").allInnerTexts()).map((x) => x.split("\n")[0].trim())
  check(`${tag}: "${t("suggest.title")}" – "${t("suggest.similar")}" offers ${VCENTER} and ${ESXI} first`, topTwo(similar), {
    similar: similar.slice(0, 3),
  })
  await scrollCheck(p, tag, "suggest – did you mean", SHOTS && `${tag.split(" ")[0]}-suggest_vsphere`)
  await p.keyboard.press("Escape")
}

/** vCenter and ESXi are the first two – in either order (equal score, the page breaks the tie by label). */
const topTwo = (labels) => {
  const two = labels.slice(0, 2)
  return two.some((x) => x?.startsWith(VCENTER)) && two.some((x) => x?.startsWith(ESXI))
}

/** The add form of a product's versions drawer: its field and its hint. */
async function form(p, key, t) {
  await p.goto(`${BASE}/vendor?product=${key}&view=versions`)
  await settle(p)
  const section = p.locator("section[aria-labelledby=vendor-add]")
  if (!(await section.count())) {
    const add = p.locator("[data-slot=sheet-content]").getByRole("button", { name: t("vendor.add.open") })
    if (await add.count()) await add.first().click()
  }
  const input = section.locator("input").first()
  await input.waitFor({ timeout: 8000 })
  const hint = section.locator(`[id="${await input.getAttribute("aria-describedby")}"]`)
  return { section, input, hint }
}

async function enter(p, key, text, t, want) {
  const f = await form(p, key, t)
  await f.input.fill(text)
  const shown = await until(async () => {
    const h = (await f.hint.innerText()).trim()
    return h.includes(want) && h
  }, 8000)
  return { ...f, shown }
}

async function versionsFlow(r, combo, t) {
  const tag = `${combo.lang} versions`
  const p = r.page
  const h = await H(r.ctx)
  for (const key of ["vcenter", "esxi"]) await r.ctx.request.put(`${BASE}/api/vendor/follows/${key}`, { data: { enabled: true }, headers: h })
  for (const [key, text, release] of [
    ["vcenter", "8.0.3.00400", "8.0 U3d"],
    ["vcenter", "24322831", "8.0 U3d"],
    ["esxi", "build-24674464", "8.0 U3e"],
  ]) {
    await dropVersions(r.ctx, key)
    const f = await enter(p, key, text, t, t("vendor.form.mapped", { version: release }))
    if (text === "8.0.3.00400") await scrollCheck(p, tag, "mapped hint", SHOTS && `${combo.lang}-vmware_mapped`)
    const before = await toastCount(p)
    await f.section.getByRole("button", { name: t("vendor.add.submit") }).click()
    const toast = await toastAfter(p, before)
    const stored = await until(async () => (await versionsOf(r.ctx, key)).map((v) => v.version).join(","))
    check(
      `${tag}: ${key} "${text}" – "${t("vendor.form.mapped", { version: release })}" before saving, stored as ${release}`,
      !!f.shown && stored === release && !!toast && toast.text.includes(release),
      {
        hint: f.shown ? undefined : (await f.hint.innerText()).slice(0, 80),
        stored,
        toast: toast?.text,
      },
    )
    await dismissToasts(p)
  }
  await dropVersions(r.ctx, "vcenter")
  await dropVersions(r.ctx, "esxi")
  // an unknown build: the hint, no saving
  const example = "8.0 U3d"
  for (const [text, what] of [
    ["8.0.3.99999", "an unknown four-part version"],
    ["24022510", "the ESXi build 24022510 for vCenter"],
  ]) {
    const f = await enter(p, "vcenter", text, t, t("vendor.invalid.unknown_build", { example }))
    const off = await f.section.getByRole("button", { name: t("vendor.add.submit") }).isDisabled()
    const api = await r.ctx.request.post(`${BASE}/api/vendor/follows/vcenter/versions`, { data: { version: text }, headers: h })
    const body = await api.json().catch(() => ({}))
    check(
      `${tag}: ${what} – the hint "${t("vendor.invalid.unknown_build", { example }).slice(0, 40)}…", no saving; the API answers 422`,
      !!f.shown && off && api.status() === 422 && JSON.stringify(body).includes("unknown_build"),
      {
        off,
        status: api.status(),
      },
    )
    if (text === "24022510") await scrollCheck(p, tag, "unknown build hint", SHOTS && `${combo.lang}-vmware_unknown`)
  }
  await dropVersions(r.ctx, "vcenter")
}

async function pages(browser, combo) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme}`
  const t = texts(lang)
  const r = await admin(browser, combo)
  await r.page.goto(`${BASE}/vendor?tab=catalog`)
  await settle(r.page)
  await r.page.getByPlaceholder(t("vendor.searchCatalog")).fill("VMware vSphere")
  await r.page.waitForTimeout(500)
  await scrollCheck(r.page, tag, "catalogue vSphere", SHOTS && `${lang}-${width}-${theme}-catalog_vsphere`)
  const f = await enter(r.page, "vcenter", "8.0.3.00400", t, t("vendor.form.mapped", { version: "8.0 U3d" }))
  check(`${tag}: the versions drawer shows "→ 8.0 U3d"`, !!f.shown)
  await scrollCheck(r.page, tag, "versions drawer", SHOTS && `${lang}-${width}-${theme}-vcenter_versions`)
  check(`${tag} pages: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) {
    const t = texts(combo.lang)
    if (combo.wide) {
      const r = await admin(browser, combo)
      await catalog(r.page, t, `${combo.lang} catalogue`)
      await versionsFlow(r, combo, t)
      check(`${combo.lang}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
      await r.ctx.close()
    } else await pages(browser, combo)
  }
} finally {
  await browser.close()
}
finish()
