// Browser check (0.1.44): versions as admins see them – normalised before saving, refused with the reason that helps.
// - "→ …" before saving (and stored so): vCenter 8.0.3.00400 → 8.0 U3d; Exchange "2019 CU15 Apr25HU" → 15.2.1748.24;
//   SQL Server a pasted SELECT @@VERSION line → its build; Java "Java 8 Update 441" → 8u441; Sophos "SFOS 21.0.1
//   MR-1-Build272" → 21.0.1.272; NetScaler "NS14.1: Build 29.72.nc" → 14.1-29.72. Exchange's ExSetup forms (15.2.1748.24,
//   15.02.1748.024) are taken.
// - Refused, saving off, with the reason: Exchange's AdminDisplayVersion ("Version 15.2 (Build 1748.24)") with the
//   ExSetup hint; a .NET SDK version with the runtime hint; an implausible version (PostgreSQL "2411") with the known
//   lines; a version of the other product of a split pair ("gehört zu …": nginx/NGINX Plus, pfSense CE/Plus,
//   Firefox/ESR, Jenkins LTS/weekly).
// - A stored version a rule refuses now (seeded): "Eintrag passt nicht mehr – bitte korrigieren" with its reason.
// - The split pairs are separate entries of the catalogue.
// DE and EN (the flows, 1280 px light), 1280 px and 375 px, light and dark (the pages): no page error, no console error,
// no horizontal scroll. Env: BASE_URL, CREDS, PLAYWRIGHT, SHOTS, DB_CMD (SQL into the throwaway database: the stored
// invalid version).
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { execSync } from "node:child_process"
import { BASE, COMBOS, H, SHOTS, check, creds, dismissToasts, finish, json, open, pw, scrollCheck, settle, signIn, toastAfter, toastCount } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const DB_CMD = process.env.DB_CMD || ""
const sql = (text) => execSync(DB_CMD, { input: text, stdio: ["pipe", "ignore", "inherit"], shell: "/bin/sh" })
const SQL_LINE = "Microsoft SQL Server 2022 (RTM-CU17) (KB5048038) - 16.0.4175.1 (X64)"
const MAPPED = [
  ["vcenter", "8.0.3.00400", "8.0 U3d", true],
  ["msexchange", "2019 CU15 Apr25HU", "15.2.1748.24", true],
  ["mssqlserver", SQL_LINE, "16.0.4175.1", true],
  ["oracle-jdk", "Java 8 Update 441", "8u441", false],
  ["sophos-firewall", "SFOS 21.0.1 MR-1-Build272", "21.0.1.272", false],
  ["netscaler-adc", "NS14.1: Build 29.72.nc", "14.1-29.72", false],
]
const TAKEN = [
  ["msexchange", "15.2.1748.24"],
  ["msexchange", "15.02.1748.024"],
]
const OTHER = [
  ["nginx", "R33", "nginx-plus"],
  ["nginx-plus", "1.27.4", "nginx"],
  ["pfsense", "24.11", "pfsense-plus"],
  ["pfsense-plus", "2.7.2", "pfsense"],
  ["firefox", "128.6.0esr", "firefox-esr"],
  ["jenkins", "2.495", "jenkins-weekly"],
  ["jenkins-weekly", "2.492.1", "jenkins"],
]
const SPLITS = [
  ["nginx", ["nginx", "nginx-plus"]],
  ["pfsense", ["pfsense", "pfsense-plus"]],
  ["firefox", ["firefox", "firefox-esr"]],
  ["jenkins", ["jenkins", "jenkins-weekly"]],
]
const KEYS = [...new Set([...MAPPED, ...TAKEN, ...OTHER].map((x) => x[0]).concat(["dotnet", "postgresql"]))]

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
  return { section, input, hint, submit: section.getByRole("button", { name: t("vendor.add.submit") }) }
}
async function enter(p, key, text, t, want) {
  const f = await form(p, key, t)
  await f.input.fill(text)
  const shown = await until(async () => {
    const h = (await f.hint.innerText()).replace(/\s+/g, " ").trim()
    return want(h) && h
  }, 8000)
  return { ...f, shown, text: (await f.hint.innerText()).replace(/\s+/g, " ").trim() }
}

async function flows(browser, combo, t) {
  const tag = `${combo.lang} versions`
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.user, creds.password, true)
  const p = r.page
  const h = await H(r.ctx)
  for (const key of KEYS) await r.ctx.request.put(`${BASE}/api/vendor/follows/${key}`, { data: { enabled: true }, headers: h })
  const cat = await json(r.ctx, "/api/vendor/catalog")
  const label = (key) => cat.products.find((x) => x.key === key)?.label ?? key
  // "→ …" before saving; some saved
  for (const [key, text, want, save] of MAPPED) {
    await dropVersions(r.ctx, key)
    const f = await enter(p, key, text, t, (h) => h.includes(t("vendor.form.mapped", { version: want })))
    let stored = null
    if (save) {
      const before = await toastCount(p)
      await f.submit.click()
      await toastAfter(p, before)
      stored = await until(async () => (await versionsOf(r.ctx, key)).map((v) => v.version).join(","))
      await dismissToasts(p)
    }
    check(
      `${tag}: ${label(key)} "${text.slice(0, 40)}${text.length > 40 ? "…" : ""}" – "→ ${want}" before saving${save ? `, stored as ${want}` : ""}`,
      !!f.shown && (!save || stored === want),
      {
        hint: f.shown ? undefined : f.text.slice(0, 120),
        stored,
      },
    )
    if (key === "msexchange") await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "Exchange mapped", SHOTS && `${combo.lang}-exchange_mapped`)
  }
  for (const [key, text] of TAKEN) {
    const f = await enter(p, key, text, t, (h) => h.includes(t("vendor.form.formatOk")) || h.startsWith("→"))
    check(`${tag}: ${label(key)} ExSetup form "${text}" taken`, !!f.shown && (await f.submit.isEnabled()), { hint: f.text.slice(0, 120) })
  }
  // refused, with the reason that helps
  const refused = async (key, text, what, want) => {
    const f = await enter(p, key, text, t, want)
    const off = await f.submit.isDisabled()
    check(`${tag}: ${label(key)} "${text}" refused – ${what}; saving off`, !!f.shown && off, { off, hint: f.text.slice(0, 200) })
    return f
  }
  await refused(
    "msexchange",
    "Version 15.2 (Build 1748.24)",
    "AdminDisplayVersion, the ExSetup hint",
    (h) => h.startsWith(t("vendor.invalid.unknown_name", { example: "15.2.1748.24" })) && h.includes("ExSetup"),
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "Exchange refused", SHOTS && `${combo.lang}-exchange_refused`)
  await refused(
    "dotnet",
    "8.0.404",
    "an SDK version, the runtime hint",
    (h) => h.startsWith(t("vendor.invalid.pattern", { example: "8.0.11" })) && /runtime/i.test(h) && h.includes("dotnet --list-runtimes"),
  )
  const pg = await json(r.ctx, `/api/vendor/validate?product=postgresql&version=2411`)
  await refused(
    "postgresql",
    "2411",
    `implausible – the known lines (${(pg.lines ?? []).join(", ")})`,
    (h) => (pg.lines ?? []).length > 0 && h.startsWith(t("vendor.invalid.implausible", { lines: pg.lines.join(", "), example: pg.example })),
  )
  for (const [key, text, to] of OTHER)
    await refused(key, text, `"${t("vendor.invalid.other_product", { product: label(to) })}"`, (h) => h.startsWith(t("vendor.invalid.other_product", { product: label(to) })))
  // a stored version a rule refuses now: "bitte korrigieren" with its reason
  await dropVersions(r.ctx, "postgresql")
  sql(
    `INSERT INTO vendor_versions (id, follow_id, version, label, created_at, updated_at, baseline_at) SELECT gen_random_uuid(), id, '2411', 'E2E alt', now() - interval '40 days', now() - interval '40 days', now() - interval '40 days' FROM vendor_follows WHERE product = 'postgresql';`,
  )
  await p.goto(`${BASE}/vendor?product=postgresql&view=versions`)
  await settle(p)
  const sheet = p.locator("[data-slot=sheet-content]")
  const body = (await sheet.innerText()).replace(/\s+/g, " ")
  const api = (await versionsOf(r.ctx, "postgresql")).find((v) => v.version === "2411")
  check(
    `${tag}: a stored "2411" a rule refuses now – "${t("review.invalid")}" and "${t("vendor.invalid.implausible", { lines: "…", example: "" }).slice(0, 30)}…"`,
    body.includes(t("review.invalid")) &&
      body.includes(t("vendor.invalid.implausible", { lines: (pg.lines ?? []).join(", "), example: pg.example })) &&
      api?.valid === false &&
      api?.invalid_reason === "implausible",
    { api: api && { valid: api.valid, reason: api.invalid_reason }, has: body.includes(t("review.invalid")) },
  )
  await scrollCheck(p, `${combo.lang} ${combo.width}px ${combo.theme}`, "stored invalid", SHOTS && `${combo.lang}-stored_invalid`)
  await dropVersions(r.ctx, "postgresql")
  // the split pairs in the catalogue
  for (const [q, keys] of SPLITS) {
    await p.goto(`${BASE}/vendor?tab=catalog`)
    await settle(p)
    await p.getByPlaceholder(t("vendor.searchCatalog")).fill(q)
    await p.waitForTimeout(500)
    const labels = (await p.locator("main ul.divide-y > li button p.text-sm").allInnerTexts()).map((x) => x.split("\n")[0].trim())
    const want = keys.map(label)
    check(
      `${tag}: catalogue "${q}" – ${want.join(" and ")} as separate entries`,
      want.every((w) => labels.filter((l) => l === w).length === 1),
      { labels: labels.slice(0, 5) },
    )
  }
  check(`${combo.lang}: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

async function pages(browser, combo) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme}`
  const t = texts(lang)
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.user, creds.password, true)
  const f = await enter(r.page, "msexchange", "Version 15.2 (Build 1748.24)", t, (h) => h.includes("ExSetup"))
  check(`${tag}: the Exchange hint shown`, !!f.shown)
  await scrollCheck(r.page, tag, "versions drawer with a long hint", SHOTS && `${lang}-${width}-${theme}-exchange_hint`)
  const g = await enter(r.page, "mssqlserver", SQL_LINE, t, (h) => h.includes(t("vendor.form.mapped", { version: "16.0.4175.1" })))
  check(`${tag}: the @@VERSION line mapped`, !!g.shown)
  await scrollCheck(r.page, tag, "versions drawer mapped", false)
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
