// Browser check (0.1.39): Einstellungen → Zugang & Sicherheit → Protokoll (the audit log).
// - What this run does appears there: a changed setting (the retention), a token made and revoked, a channel with
//   secrets – its secret fields only as "geändert" with the lock, the values nowhere in the page nor in any answer.
// - Filters (area, who, dates, search) and "Filter zurücksetzen"; "Ältere laden"; a row opened: before → after; the CSV
//   export (a cell starting with = + - @ is prefixed); Aufbewahrung: a shorter time asks for the re-confirmation.
// - A reader: no entry in the navigation, the API answers 403.
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll. The actions run
// once per language (the wide light run).
// Env: BASE_URL, CREDS ({user, password, totp, reader, reader_password}), PLAYWRIGHT, SHOTS, SECRET_HOST (optional: an
// address WEBHOOK_PRIVATE_NETS allows – the test channel is only saved, never sent to). Installed Chrome; stubs.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import fs from "node:fs"
import { BASE, COMBOS, H, SHOTS, check, creds, finish, json, open, pw, reauthOnce, scrollCheck, settle, signIn } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const HOST = process.env.SECRET_HOST || "10.20.0.15:18443"
const rand = () => crypto.randomBytes(6).toString("hex")

/** The admin's own actions of this run – through the API (they are what the log must show). */
async function act(ctx) {
  const h = await H(ctx)
  const s = await json(ctx, "/api/admin/audit/settings")
  // enough entries for a second page: the retention up and down (between 400 and 401 days – never shorter than now)
  const have = (await json(ctx, "/api/admin/audit?limit=200")).items.length
  let rev = s.rev
  for (let i = 0; have + i < 60; i++) {
    const r = await ctx.request.put(`${BASE}/api/admin/audit/settings`, { data: { keep_days: i % 2 ? 401 : 400, rev }, headers: h })
    rev = (await r.json()).rev
  }
  // always a real change last (the row "before → after" opens the newest settings entry – another script's switch, e.g.
  // passkeys on, may be newer than the loop's when the log was long enough already)
  const r0 = await ctx.request.put(`${BASE}/api/admin/audit/settings`, { data: { keep_days: 401, rev }, headers: h })
  rev = (await r0.json()).rev
  const r1 = await ctx.request.put(`${BASE}/api/admin/audit/settings`, { data: { keep_days: 400, rev }, headers: h })
  const token = `e2e-audit-token-${rand()}`
  const made = await (await ctx.request.post(`${BASE}/api/admin/api-tokens`, { data: { name: token, scopes: ["read"], expires_days: 30 }, headers: h })).json()
  await ctx.request.post(`${BASE}/api/admin/api-tokens/${made.item.id}/revoke`, { headers: h })
  const secrets = { path: `PATHSECRET${rand()}`, hmac: `HMACSECRET${rand()}${rand()}`, header: `HEADERSECRET${rand()}` }
  const channel = `=e2e-audit-channel-${rand()}`
  const c = await ctx.request.post(`${BASE}/api/admin/notify/channels`, {
    data: { name: channel, type: "webhook", url: `https://${HOST}/hook/${secrets.path}`, hmac_secret: secrets.hmac, header_name: "X-Api-Key", header_value: secrets.header },
    headers: h,
  })
  return { token, channel, secrets: [made.token, ...Object.values(secrets)], ok: r1.ok() && !!made.token && c.ok() }
}

async function run(browser, combo, state) {
  const { lang, width, theme, wide } = combo
  const t = texts(lang)
  const tag = `${lang} ${width}px ${theme}`
  const shot = (n) => SHOTS && `${lang}-${width}-${theme}-${n}`
  const { ctx, page, errors } = await open(browser, combo)
  await signIn(ctx, creds.user, creds.password, true)
  // every answer the page gets – no secret in any of them
  const bodies = []
  page.on("response", async (r) => {
    if (!r.url().includes("/api/")) return
    try {
      bodies.push(await r.text())
    } catch {
      // a body that is gone (redirect, aborted) holds nothing
    }
  })
  if (wide) {
    state.made = await act(ctx)
    check(`${lang} actions: a setting changed, a token made and revoked, a channel with secrets saved`, state.made.ok)
  }
  const { token, channel, secrets } = state.made
  await page.goto(`${BASE}/settings/audit`)
  await settle(page)
  const nav = page.locator('a[href="/settings/audit"]')
  const main = page.locator("main")
  const rows = main.locator("ul > li > button[aria-expanded]")
  check(`${tag} the navigation's "${t("settings.nav.audit")}" and entries`, (await nav.count()) >= 1 && (await rows.count()) > 0)
  await scrollCheck(page, tag, "audit log", shot("audit"))

  // search: the token – made and revoked
  const search = main.getByRole("searchbox", { name: t("audit.filter.search") })
  await search.fill(token)
  await page.waitForTimeout(700)
  await settle(page)
  const tokenRows = (await rows.allInnerTexts()).join("\n")
  check(
    `${tag} search "${token.slice(0, 16)}…": made and revoked`,
    (await rows.count()) >= 2 && tokenRows.includes(t("audit.action.token.created")) && tokenRows.includes(t("audit.action.token.revoked")),
    {
      rows: await rows.count(),
    },
  )
  // the channel: its secrets only as changed, with the lock
  await search.fill(channel)
  await page.waitForTimeout(700)
  await settle(page)
  await rows.first().click()
  await page.waitForTimeout(300)
  const details = main.locator("[id^=audit-]").first()
  const dText = await details.innerText().catch(() => "")
  const locks = await details.locator("dd svg").count()
  const html = await page.content()
  const leak = secrets.filter((s) => html.includes(s) || bodies.some((b) => b.includes(s)))
  check(
    `${tag} channel with secrets: "${t("audit.details.secret")}" with the lock, the values nowhere (page, answers)`,
    dText.includes(t("audit.details.secret")) && locks >= 1 && leak.length === 0,
    {
      locks,
      leak: leak.length,
    },
  )
  await scrollCheck(page, tag, "secret entry", shot("audit_secret"))
  // reset
  await main.getByRole("button", { name: t("audit.filter.reset") }).click()
  await settle(page)
  check(`${tag} "${t("audit.filter.reset")}": the search empty again`, (await search.inputValue()) === "" && (await rows.count()) > 2)

  // area: API tokens only
  await main.getByRole("combobox", { name: t("audit.filter.group") }).click()
  await page.getByRole("option", { name: t("audit.group.tokens"), exact: true }).click()
  await settle(page)
  const icons = await rows.locator("svg[aria-label]").evaluateAll((els) => els.map((e) => e.getAttribute("aria-label")))
  check(`${tag} area "${t("audit.group.tokens")}": only token entries`, icons.length > 0 && icons.every((x) => x === t("audit.group.tokens")), { n: icons.length })
  // who: the admin
  await main.getByRole("combobox", { name: t("audit.filter.actor") }).click()
  const actorOption = page.getByRole("option").filter({ hasText: "Anna Admin" }).first()
  const hasActor = (await actorOption.count()) === 1
  if (hasActor) await actorOption.click()
  await settle(page)
  check(`${tag} who "Anna Admin": entries`, hasActor && (await rows.count()) > 0)
  // dates: from tomorrow – none
  const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10)
  await main.getByLabel(t("audit.filter.from"), { exact: true }).fill(tomorrow)
  await settle(page)
  check(`${tag} from tomorrow: "${t("audit.empty.filtered")}"`, (await main.innerText()).includes(t("audit.empty.filtered")))
  await main.getByRole("button", { name: t("audit.filter.reset") }).click()
  await settle(page)

  // "Ältere laden"
  const more = main.getByRole("button", { name: t("audit.more") })
  const n0 = await rows.count()
  if (await more.count()) {
    await more.click()
    await settle(page)
  }
  check(`${tag} "${t("audit.more")}": more entries`, (await rows.count()) > n0, { before: n0, after: await rows.count() })

  // before → after: the retention's change
  await main.getByRole("combobox", { name: t("audit.filter.group") }).click()
  await page.getByRole("option", { name: t("audit.group.settings"), exact: true }).click()
  await settle(page)
  await rows.first().click()
  await page.waitForTimeout(300)
  const change = await main.locator("[id^=audit-] dd").allInnerTexts()
  check(`${tag} a row opened: before → after (the retention, days)`, change.length >= 2 && /\d{2,4}/.test(change[0]) && /\d{2,4}/.test(change[1]) && change[0] !== change[1], {
    change: change.slice(0, 4),
  })
  await main.getByRole("button", { name: t("audit.filter.reset") }).click()
  await settle(page)

  if (wide) {
    // the CSV export: the channel name starts with "=" – prefixed
    const [download] = await Promise.all([page.waitForEvent("download", { timeout: 10000 }).catch(() => null), main.getByRole("button", { name: t("audit.export") }).click()])
    const csv = download ? fs.readFileSync(await download.path(), "utf8") : ""
    const line = csv.split("\n").find((l) => l.includes(channel.slice(1))) ?? ""
    check(`${lang} CSV export: a cell starting with "=" comes prefixed ('=…), no secret in it`, line.includes(`'${channel}`) && !secrets.some((s) => csv.includes(s)), {
      found: !!line,
    })
    // Aufbewahrung: shorter asks for the re-confirmation
    await page.goto(`${BASE}/settings/audit?tab=retention`)
    await settle(page)
    const field = main.getByRole("spinbutton").first()
    await field.fill("300")
    const asked = await reauthOnce(page, "**/api/admin/audit/settings", () => main.getByRole("button", { name: t("common.save"), exact: true }).click())
    await page.waitForTimeout(800)
    const kept = (await json(ctx, "/api/admin/audit/settings")).keep_days
    check(`${lang} retention shorter: the re-confirmation asked, 300 days saved`, asked && kept === 300, { asked, kept })
    await scrollCheck(page, tag, "retention", shot("audit_retention"))
    const s = await json(ctx, "/api/admin/audit/settings")
    await ctx.request.put(`${BASE}/api/admin/audit/settings`, { data: { keep_days: 365, rev: s.rev }, headers: await H(ctx) })
  }
  check(`${tag} admin: no page or console errors`, errors.length === 0, errors.slice(0, 3))
  await ctx.close()

  // a reader: no navigation entry, 403
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.reader, creds.reader_password)
  await r.page.goto(`${BASE}/settings/profile`)
  await settle(r.page)
  const status = (await r.ctx.request.get(`${BASE}/api/admin/audit`)).status()
  check(`${tag} reader: no "${t("settings.nav.audit")}" in the navigation, the API 403`, (await r.page.locator('a[href="/settings/audit"]').count()) === 0 && status === 403, {
    status,
  })
  await r.ctx.close()
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
const state = {}
try {
  for (const combo of COMBOS) await run(browser, combo, state)
} finally {
  await browser.close()
}
finish()
