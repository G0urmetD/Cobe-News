// Browser check (0.1.39): Kanäle & Regeln – the new channel types, the Zustellprotokoll and the rule's Probelauf.
// - ntfy / Gotify / Mattermost: the forms (tooltips, https only), topic and token never shown again after saving
//   ("Gespeichert – leer lassen …"), another server asks for them again.
// - Test sends to a local mock receiver (MOCK, started outside: /ok 200, /fail 500, /slow too slow – reached through an
//   address the instance allows in WEBHOOK_PRIVATE_NETS): ok, failed, timeout; the TLS error of a push server with a
//   self-signed certificate. The Zustellprotokoll lists them, attempts open, "Erneut senden" of a failed rule
//   delivery (busy while it runs, a toast, a double click sends once), the health badge's colours.
// - The channel drawer "Einstellungen | Protokoll" keeps what was typed.
// - The rule editor's Probelauf: the days a popper select, the results, the flood warning, outdated after an edit.
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll. The sends and
// saves once per language (the wide light run).
// It expects (seed): webhook channels "E2E OK" (MOCK/ok), "E2E Fail" (MOCK/fail), "E2E Slow" (MOCK/slow), the rule
// "E2E Regel" (news, every severity) on "E2E Fail" with a failed rule delivery, 45 stories of today.
// Env: BASE_URL, CREDS, PLAYWRIGHT, SHOTS, MOCK (e.g. http://10.20.0.15:18091), MOCK_TLS (e.g. https://10.20.0.15:18443).
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import { BASE, COMBOS, H, SHOTS, check, creds, dismissToasts, finish, json, open, pw, scrollCheck, settle, signIn, toastAfter, toastCount, tooltipOf } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const MOCK = (process.env.MOCK || "").replace(/\/$/, "")
const MOCK_TLS = (process.env.MOCK_TLS || "").replace(/\/$/, "")
const rand = () => crypto.randomBytes(4).toString("hex")

const channels = async (ctx) => json(ctx, "/api/admin/notify/channels")
const logOf = async (ctx, q = "") => (await json(ctx, `/api/admin/notify/log?hours=168${q}`)).deliveries

async function openNew(page, t, type) {
  await page.getByRole("button", { name: t("channels.add") }).click()
  await page.getByRole("menuitem", { name: t(`notify.channel.${type}`), exact: true }).click()
  const sheet = page.locator("[data-slot=sheet-content]")
  await sheet.waitFor({ timeout: 5000 }).catch(() => {})
  return sheet
}

async function openEdit(page, t, name) {
  await page
    .locator("main li")
    .filter({ hasText: name })
    .first()
    .getByRole("button", { name: t("common.edit"), exact: true })
    .click()
  const sheet = page.locator("[data-slot=sheet-content]")
  await sheet.waitFor({ timeout: 5000 }).catch(() => {})
  return sheet
}

/** Push channels: forms, https only, secrets never back, another server asks for them again; the TLS error. */
async function pushForms(page, ctx, t, tag, wide) {
  const sheet = await openNew(page, t, "ntfy")
  const server = sheet.getByPlaceholder("https://ntfy.corp.example")
  await server.fill("http://ntfy.corp.example")
  const httpRefused = (await sheet.innerText()).includes(t("channels.check.server"))
  const tip = await tooltipOf(page, sheet.locator(`[aria-label="${t("channels.push.serverHint.ntfy").replace(/"/g, '\\"')}"]`).first())
  check(`${tag} ntfy form: https only (http refused), the server's tooltip`, httpRefused && tip.length > 20, { httpRefused, tip: tip.slice(0, 40) })
  await scrollCheck(page, tag, "ntfy form", SHOTS && `${tag.replace(/ /g, "-")}-ntfy`)
  if (!wide) {
    await page.keyboard.press("Escape")
    return
  }
  const name = `E2E ntfy ${rand()}`
  const topic = `e2e-topic-${rand()}`
  await sheet.getByPlaceholder(t(`channels.namePlaceholder.ntfy`)).fill(name)
  await server.fill(MOCK_TLS)
  await sheet.locator('input[type="password"]').first().fill(topic)
  await sheet.getByRole("button", { name: t("common.save"), exact: true }).click()
  await page.waitForTimeout(1000)
  await page.keyboard.press("Escape")
  await page.waitForTimeout(300)
  const edit = await openEdit(page, t, name)
  const topicField = edit.locator('input[type="password"]').first()
  const kept =
    (await topicField.inputValue()) === "" &&
    (await topicField.getAttribute("placeholder")) === t("channels.keepPlaceholder") &&
    (await edit.innerText()).includes(t("common.secretKept"))
  const html = await page.content()
  check(`${tag} ntfy saved: the topic not shown again ("${t("common.secretKept")}")`, kept && !html.includes(topic), { kept })
  await edit.getByPlaceholder("https://ntfy.corp.example").fill("https://ntfy-other.corp.example")
  check(`${tag} ntfy: another server asks for topic and token again`, (await edit.innerText()).includes(t("channels.push.secretsAgain")))
  await edit.getByPlaceholder("https://ntfy.corp.example").fill(MOCK_TLS)
  // the test send: a self-signed certificate – the TLS error
  await dismissToasts(page)
  const before = await toastCount(page)
  await edit.getByRole("button", { name: t("notify.test"), exact: true }).click()
  const toast = await toastAfter(page, before, 20000)
  check(`${tag} ntfy test against a self-signed server: an error toast (TLS)`, toast?.type === "error", toast && { text: toast.text.slice(0, 80) })
  await page.keyboard.press("Escape")
  await dismissToasts(page)
  // Gotify and Mattermost forms
  const g = await openNew(page, t, "gotify")
  const gText = await g.innerText()
  check(`${tag} Gotify form: server and "${t("channels.push.token.gotify")}"`, gText.includes(t("channels.push.server")) && gText.includes(t("channels.push.token.gotify")))
  await page.keyboard.press("Escape")
  const m = await openNew(page, t, "mattermost")
  await m.getByPlaceholder("https://chat.corp.example/hooks/…").fill("http://chat.corp.example/hooks/abc")
  check(`${tag} Mattermost form: https only`, (await m.innerText()).includes(t("channels.check.url.mattermost")))
  await page.keyboard.press("Escape")
  await page.waitForTimeout(300)
  const id = (await channels(ctx)).find((c) => c.name === name)?.id
  if (id) await ctx.request.delete(`${BASE}/api/admin/notify/channels/${id}`, { headers: await H(ctx) })
}

async function run(browser, combo) {
  const { lang, width, theme, wide } = combo
  const t = texts(lang)
  const tag = `${lang} ${width}px ${theme}`
  const shot = (n) => SHOTS && `${lang}-${width}-${theme}-${n}`
  const { ctx, page, errors } = await open(browser, combo)
  await signIn(ctx, creds.user, creds.password, true)
  await page.goto(`${BASE}/settings/rules`)
  await settle(page)
  await scrollCheck(page, tag, "channels", shot("channels"))

  if (wide) {
    // test sends: ok, failed (500), timeout
    const outcomes = {}
    for (const name of ["E2E OK", "E2E Fail", "E2E Slow"]) {
      const before = await toastCount(page)
      await page
        .locator("main li")
        .filter({ hasText: name })
        .first()
        .getByRole("button", { name: t("notify.test"), exact: true })
        .click()
      outcomes[name] = (await toastAfter(page, before, 40000))?.type ?? null
      await dismissToasts(page)
    }
    check(
      `${lang} test sends: "E2E OK" ok, "E2E Fail" and "E2E Slow" errors`,
      outcomes["E2E OK"] === "success" && outcomes["E2E Fail"] === "error" && outcomes["E2E Slow"] === "error",
      outcomes,
    )
    const tests = (await logOf(ctx, "&kind=test")).slice(0, 10)
    const by = (n) => tests.find((d) => d.channel_name === n)
    check(`${lang} log: ok, http and timeout recorded`, by("E2E OK")?.ok === true && by("E2E Fail")?.outcome === "http" && by("E2E Slow")?.outcome === "timeout", {
      ok: by("E2E OK")?.outcome,
      fail: by("E2E Fail")?.outcome,
      slow: by("E2E Slow")?.outcome,
    })
    await page.reload()
    await settle(page)
  }
  // the health badges: ok green, failing red
  const badge = async (name) =>
    page
      .locator("main li")
      .filter({ hasText: name })
      .first()
      .locator("[style*='--success'], [style*='--warning'], [style*='--destructive']")
      .last()
      .getAttribute("style")
      .catch(() => "")
  const okStyle = await badge("E2E OK")
  const failStyle = await badge("E2E Fail")
  check(
    `${tag} health badges: "E2E OK" green, "E2E Fail" red (amber once a resend went through)`,
    /--success/.test(okStyle ?? "") && /--destructive|--warning/.test(failStyle ?? ""),
    { okStyle, failStyle },
  )

  await pushForms(page, ctx, t, tag, wide)

  // the channel drawer: Einstellungen | Protokoll keeps what was typed
  await page.goto(`${BASE}/settings/rules`)
  await settle(page)
  const edit = await openEdit(page, t, "E2E Fail")
  const typed = `E2E Fail ${rand()}`
  await edit.getByRole("textbox").first().fill(typed)
  await edit.getByRole("tab", { name: t("dlog.tab.log"), exact: true }).click()
  await page.waitForTimeout(500)
  const logShown = (await edit.getByLabel(t("dlog.failed")).count()) > 0
  await edit.getByRole("tab", { name: t("dlog.tab.settings"), exact: true }).click()
  check(
    `${tag} channel drawer: "${t("dlog.tab.log")}" lists its deliveries, back the typed name is kept`,
    logShown && (await edit.getByRole("textbox").first().inputValue()) === typed,
  )
  await scrollCheck(page, tag, "channel drawer", false)
  await page.keyboard.press("Escape")
  await page.waitForTimeout(300)
  if (await page.getByRole("dialog").count()) await page.keyboard.press("Escape")

  // the Zustellprotokoll: rows, attempts, resend
  await page.goto(`${BASE}/settings/rules?tab=log`)
  await settle(page)
  const rows = page.locator("main ul > li")
  const failedRow = rows.filter({ has: page.getByLabel(t("dlog.failed")) }).first()
  await failedRow.getByRole("button", { name: t("dlog.details") }).click()
  await page.waitForTimeout(300)
  const attempts = await failedRow.locator("ul li").count()
  check(
    `${tag} Zustellprotokoll: ok and failed entries, a failed delivery's attempts open`,
    (await rows.filter({ has: page.getByLabel(t("dlog.outcome.ok")) }).count()) > 0 && attempts >= 1,
    { attempts },
  )
  await scrollCheck(page, tag, "delivery log", shot("delivery_log"))
  const ruleRow = rows.filter({ has: page.getByRole("button", { name: t("dlog.resend") }) }).first()
  if (wide) {
    const resend = ruleRow.getByRole("button", { name: t("dlog.resend") })
    const id = (await logOf(ctx, "&kind=rule")).find((d) => d.can_resend)?.id
    const manual0 = (await logOf(ctx, "&kind=rule")).flatMap((d) => d.attempts).filter((a) => a.manual).length
    if (lang === "en") {
      // the channel works again: the resend goes through
      const ch = (await channels(ctx)).find((c) => c.name === "E2E Fail")
      await ctx.request.put(`${BASE}/api/admin/notify/channels/${ch.id}`, {
        data: { name: ch.name, type: "webhook", url: `${MOCK}/ok`, allow_http: true, version: ch.version },
        headers: await H(ctx),
      })
    }
    const before = await toastCount(page)
    await resend.dblclick()
    const busy = await resend.isDisabled().catch(() => false)
    const toast = await toastAfter(page, before, 20000)
    await page.waitForTimeout(800)
    const manual1 = (await logOf(ctx, "&kind=rule")).flatMap((d) => d.attempts).filter((a) => a.manual).length
    const want = lang === "en" ? "success" : "error"
    check(`${lang} "${t("dlog.resend")}": busy while it runs, a ${want} toast, a double click sent once`, !!id && busy && toast?.type === want && manual1 - manual0 === 1, {
      busy,
      toast: toast?.type,
      manual: manual1 - manual0,
    })
    if (lang === "en") {
      const ch = (await channels(ctx)).find((c) => c.name === "E2E Fail")
      await ctx.request.put(`${BASE}/api/admin/notify/channels/${ch.id}`, {
        data: { name: ch.name, type: "webhook", url: `${MOCK}/fail`, allow_http: true, version: ch.version },
        headers: await H(ctx),
      })
    }
  }

  // the rule editor's Probelauf
  await page.goto(`${BASE}/settings/rules?tab=rules`)
  await settle(page)
  await page
    .locator("main li")
    .filter({ hasText: "E2E Regel" })
    .first()
    .getByRole("button", { name: t("common.edit"), exact: true })
    .click()
  const sheet = page.locator("main") // the rule editor takes the list's place
  await sheet
    .getByRole("combobox", { name: t("dlog.dry.window") })
    .waitFor({ timeout: 5000 })
    .catch(() => {})
  await sheet.getByRole("combobox", { name: t("dlog.dry.window") }).click()
  const popper = await page.locator("[data-radix-popper-content-wrapper] [role=listbox]").isVisible()
  await page.getByRole("option", { name: t("dlog.dry.days", { count: 30 }), exact: true }).click()
  await sheet.getByRole("button", { name: t("dlog.dry.run"), exact: true }).click()
  await page.waitForTimeout(2500)
  const text = await sheet.innerText()
  const flood = await sheet
    .getByRole("alert")
    .filter({ hasText: t("dlog.dry.flood") })
    .count()
  const results = await sheet.locator("section ul > li").count()
  check(`${tag} Probelauf: 30 days (popper), results, the flood warning`, popper && results > 0 && flood === 1, { popper, results, flood })
  await scrollCheck(page, tag, "dry run", shot("dry_run"))
  // an edit makes it outdated (one more kind)
  await sheet.getByRole("switch", { name: t("notify.kind.vendor_vuln"), exact: true }).click()
  await page.waitForTimeout(300)
  const outdated = (await sheet.innerText()).includes(t("dlog.dry.outdated")) && !text.includes(t("dlog.dry.outdated"))
  check(`${tag} Probelauf: outdated after an edit of the rule`, outdated)
  await sheet
    .getByRole("button", { name: t("common.cancel"), exact: true })
    .click()
    .catch(() => {})
  await page.waitForTimeout(300)
  if (await page.getByRole("dialog").count())
    await page
      .getByRole("dialog")
      .last()
      .getByRole("button")
      .last()
      .click()
      .catch(() => {})
  check(`${tag} admin: no page or console errors`, errors.length === 0, errors.slice(0, 3))
  await ctx.close()
}

if (!MOCK || !MOCK_TLS) throw new Error("MOCK and MOCK_TLS (the local mock receiver) are needed")
const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) await run(browser, combo)
} finally {
  await browser.close()
}
finish()
