// Browser check (0.1.37): API tokens, /api/v1, /metrics, the curated API reference and the restore test.
// a) Einstellungen → "API & Metriken", Tokens: a token made with name, scope (read / metrics) and expiry – the
//    re-confirmation asks (password + TOTP, for real); the token shown once with a copy button; after a reload only its
//    prefix and "zuletzt benutzt"; revoking asks again.
// b) Straight to the backend (API_URL – the vite dev server proxies /api only): a read token reads GET /api/v1/news
//    (200, JSON); POST with a token 403; token and session cookie together 400; a metrics token on /api/v1 403; /metrics
//    with it 200, Prometheus text with cobe_news_info and no e-mail address or name of a person; a revoked token 401;
//    the session cookie alone opens neither /api/v1 nor /metrics.
// c) "Referenz": the curated OpenAPI shown, its download works; /docs, /redoc and /openapi.json of the backend 404.
// d) Sicherung & Export → Rücksicherungs-Test: not set up – the hint, "Jetzt testen" off with the reason; set up (the
//    throwaway role and database of deploy/postgres/restore-role.sql, POSTGRES_RESTORE_PASSWORD) – a backup, "Jetzt
//    testen", "Bestanden" with its duration.
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll. Tokens are made
// and revoked once per language (the wide light run). No token is ever printed; screenshots mask it.
//
// Only against a throwaway instance (own database and DATA_DIR, never the live one) – docs/BETRIEB.md, "Entwicklung / Tests".
// It expects people of the seed under corp.example (their names and addresses must not be in /metrics).
// Env: BASE_URL (vite dev server), API_URL (the backend itself), CREDS (JSON {user, password, totp} – never printed),
// PLAYWRIGHT (…/node_modules/playwright/index.mjs), SHOTS (optional folder for screenshots). Uses the installed Google
// Chrome (channel "chrome") – never downloads a browser. Notifications stubbed, never granted.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import crypto from "node:crypto"
import fs from "node:fs"

const BASE = (process.env.BASE_URL || "http://127.0.0.1:5260").replace(/\/$/, "")
const API = (process.env.API_URL || "").replace(/\/$/, "")
const creds = JSON.parse(fs.readFileSync(process.env.CREDS || "", "utf8"))
const SHOTS = process.env.SHOTS || ""
const { chromium, request } = await import(process.env.PLAYWRIGHT || "playwright-core")
if (!API) throw new Error("API_URL (the backend of the throwaway instance) is needed")

// what /metrics must never contain: the people of the seed
const PEOPLE = ["@corp.example", "Anna Admin", "anna.admin", "Rudi Reader", "rudi.reader", "Nora", "Person 3 Beispiel", "Olga Labor", "Dora Verzeichnis", "Kai Kurzzeit"]
const TOKEN = /cnt_[A-Za-z0-9_-]{43}/
const L = {
  de: {
    create: "Token anlegen",
    createButton: "Anlegen",
    read: "Lesen",
    metrics: "Metriken",
    days30: "30 Tage",
    once: "Nur jetzt sichtbar.",
    copy: "Token kopieren",
    done: "Fertig",
    revoke: "Widerrufen",
    revokeName: (n) => `Token „${n}“ widerrufen`,
    lastUsed: "zuletzt benutzt",
    reference: "Referenz",
    refTitle: "API-Referenz",
    download: "OpenAPI herunterladen",
    restore: "Rücksicherungs-Test",
    off: "Nicht eingerichtet",
    notSetUp: "Die Wegwerf-Datenbank ist nicht eingerichtet.",
    nowOff: "Erst die Wegwerf-Datenbank einrichten.",
    now: "Jetzt testen",
    passed: "Bestanden",
    took: "Dauer ",
  },
  en: {
    create: "New token",
    createButton: "Create",
    read: "Read",
    metrics: "Metrics",
    days30: "30 days",
    once: "Visible only now.",
    copy: "Copy token",
    done: "Done",
    revoke: "Revoke",
    revokeName: (n) => `Revoke token “${n}”`,
    lastUsed: "last used",
    reference: "Reference",
    refTitle: "API reference",
    download: "Download OpenAPI",
    restore: "Restore test",
    off: "Not set up",
    notSetUp: "The throwaway database is not set up.",
    nowOff: "Set up the throwaway database first.",
    now: "Test now",
    passed: "Passed",
    took: "took ",
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

// a TOTP code counts once: every use (sign-in, re-confirmation) in a step of its own
let lastStep = 0
async function freshStep(page) {
  while (Math.floor(Date.now() / 30000) <= lastStep || 30000 - (Date.now() % 30000) < 3000) await page.waitForTimeout(1000)
  lastStep = Math.floor(Date.now() / 30000)
  return totp(creds.totp)
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

async function signIn(ctx, page) {
  const req = ctx.request
  await req.get(`${BASE}/api/auth/config`)
  const h = { "X-CSRF-Token": await csrfOf(ctx) }
  const r = await req.post(`${BASE}/api/auth/login`, { data: { username: creds.user, password: creds.password }, headers: h })
  if (!r.ok()) throw new Error(`login: ${r.status()}`)
  const m = await req.post(`${BASE}/api/auth/mfa`, { data: { code: await freshStep(page) }, headers: h })
  if (!m.ok()) throw new Error(`mfa: ${m.status()}`)
}

async function settle(page) {
  await page.waitForLoadState("networkidle").catch(() => undefined)
  await page.waitForTimeout(350)
}

async function scrollCheck(page, tag, name, shot, mask = []) {
  const s = await page.evaluate(() => {
    const wide = (el) => !!el && el.scrollWidth > el.clientWidth + 1
    const d = document.documentElement
    return { ok: !wide(d) && !wide(document.querySelector("[data-slot=sheet-content]")), page: wide(d) }
  })
  check(`${tag} ${name}: no horizontal scroll`, s.ok, s.ok ? undefined : s)
  if (SHOTS && shot) await page.screenshot({ path: `${SHOTS}/${shot}.png`, mask })
}

function watchErrors(page) {
  const errors = []
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`))
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`)
  })
  return errors
}

const json = async (ctx, path) => (await ctx.request.get(`${BASE}${path}`)).json()

/** The server asks for the re-confirmation on the next request to `pattern` (as after REAUTH_WINDOW): the prompt is
 * answered for real – password and a TOTP code of a fresh step. True when it asked and was answered. */
async function reauthOnce(page, pattern, action) {
  let asked = false
  await page.route(pattern, (route) => {
    if (route.request().method() === "POST" && !asked) {
      asked = true
      return route.fulfill({ status: 403, json: { detail: { code: "reauth_required", via: "password", totp: true } } })
    }
    return route.fallback()
  })
  await action()
  const pw = page.locator("#reauth-pw")
  await pw.waitFor({ timeout: 5000 }).catch(() => {})
  const shown = (await pw.count()) === 1
  if (shown) {
    await pw.fill(creds.password)
    await page.locator("#reauth-code").fill(await freshStep(page))
    await page.keyboard.press("Enter")
    await pw.waitFor({ state: "detached", timeout: 8000 }).catch(() => {})
  }
  await page.unroute(pattern)
  return asked && shown
}

/** Makes a token in the UI: name, scope, 30 days – returns its value (never printed). */
async function makeToken(page, T, name, scope, confirm) {
  await page.getByRole("button", { name: T.create, exact: true }).click()
  const sheet = page.locator("[data-slot=sheet-content]")
  await sheet.getByRole("textbox").first().fill(name)
  if (scope === "metrics") {
    await sheet.getByRole("switch", { name: T.read, exact: true }).click()
    await sheet.getByRole("switch", { name: T.metrics, exact: true }).click()
  }
  await sheet.getByRole("combobox").click()
  await page.getByRole("option", { name: T.days30, exact: true }).click()
  const submit = () => sheet.getByRole("button", { name: T.createButton, exact: true }).click()
  const asked = confirm ? await reauthOnce(page, "**/api/admin/api-tokens", submit) : (await submit(), null)
  const field = sheet.locator("input[readonly]")
  await field.waitFor({ timeout: 8000 }).catch(() => {})
  const value = (await field.count()) ? await field.inputValue() : ""
  return { value, asked }
}

async function apiChecks(lang, ctx, read, metrics) {
  const anon = await request.newContext() // no cookie at all
  const bearer = (t) => ({ Authorization: `Bearer ${t}` })
  const cookie = (await ctx.cookies(BASE)).map((c) => `${c.name}=${c.value}`).join("; ")
  const news = await anon.get(`${API}/api/v1/news`, { headers: bearer(read) })
  const body = await news.json().catch(() => null)
  check(
    `${lang} API: a read token – GET /api/v1/news 200, JSON`,
    news.status() === 200 && /json/.test(news.headers()["content-type"] ?? "") && !!body && Array.isArray(body.items),
    {
      status: news.status(),
    },
  )
  const post = await anon.post(`${API}/api/v1/news`, { headers: bearer(read), data: {} })
  check(`${lang} API: POST with a token 403`, post.status() === 403, { status: post.status() })
  const both = await anon.get(`${API}/api/v1/news`, { headers: { ...bearer(read), Cookie: cookie } })
  check(`${lang} API: token and session cookie together 400`, both.status() === 400, { status: both.status() })
  const scope = await anon.get(`${API}/api/v1/news`, { headers: bearer(metrics) })
  check(`${lang} API: a metrics token on /api/v1 403`, scope.status() === 403, { status: scope.status() })
  const m = await anon.get(`${API}/metrics`, { headers: bearer(metrics) })
  const text = await m.text()
  const leaks = PEOPLE.filter((p) => text.includes(p))
  check(
    `${lang} /metrics: 200, Prometheus text, cobe_news_info, no person`,
    m.status() === 200 && /^text\/plain/.test(m.headers()["content-type"] ?? "") && /^cobe_news_info\{/m.test(text) && leaks.length === 0,
    {
      status: m.status(),
      type: m.headers()["content-type"],
      leaks,
    },
  )
  const readOnMetrics = await anon.get(`${API}/metrics`, { headers: bearer(read) })
  check(`${lang} /metrics: a read token 403`, readOnMetrics.status() === 403, { status: readOnMetrics.status() })
  // the session cookie alone: through the dev server (its cookies) for /api/v1, with the cookie for /metrics
  const c1 = await ctx.request.get(`${BASE}/api/v1/news`)
  const c2 = await anon.get(`${API}/metrics`, { headers: { Cookie: cookie } })
  check(`${lang} the session cookie alone opens neither /api/v1 nor /metrics`, c1.status() === 401 && c2.status() === 401, { v1: c1.status(), metrics: c2.status() })
  // not FastAPI's own: 404 – or, where the backend serves the built UI too (STATIC_DIR), the UI's page (/docs is the
  // handbook there), never Swagger, ReDoc or the generated schema
  const hidden = []
  for (const p of ["/docs", "/redoc", "/openapi.json"]) {
    const r = await anon.get(`${API}${p}`)
    const body = await r.text()
    const ui = r.status() === 200 && /^text\/html/.test(r.headers()["content-type"] ?? "") && body.includes('id="root"')
    hidden.push([p, r.status(), r.status() === 404 || (ui && !/swagger|redoc|"openapi"\s*:/i.test(body))])
  }
  check(
    `${lang} backend: /docs, /redoc, /openapi.json not served (404, or the UI's own page)`,
    hidden.every(([, , ok]) => ok),
    hidden,
  )
  await anon.dispose()
}

async function run(browser, lang, width, theme) {
  const T = L[lang]
  const tag = `${lang} ${width}px ${theme}`
  const wide = width === 1280 && theme === "light"
  const shot = (n) => `${lang}-${width}-${theme}-${n}`
  const ctx = await browser.newContext({ serviceWorkers: "block", locale: lang === "de" ? "de-DE" : "en-GB", viewport: { width, height: 860 }, colorScheme: theme })
  await stub(ctx, lang, theme)
  const page = await ctx.newPage()
  const errors = watchErrors(page)
  const logs = []
  page.on("console", (m) => logs.push(m.text()))
  await signIn(ctx, page)

  // a) tokens
  await page.goto(`${BASE}/settings/api`)
  await settle(page)
  check(`${tag} "API & Metriken": the tokens and "${T.create}"`, (await page.getByRole("button", { name: T.create, exact: true }).count()) === 1)
  await scrollCheck(page, tag, "tokens", shot("tokens"))
  if (wide) {
    const sheet = page.locator("[data-slot=sheet-content]")
    const name = `e2e-read-${lang}-${crypto.randomBytes(2).toString("hex")}`
    const made = await makeToken(page, T, name, "read", true)
    const once = await sheet.getByText(T.once).isVisible()
    await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: new URL(BASE).origin })
    await sheet.getByRole("button", { name: T.copy, exact: true }).click()
    await page.waitForTimeout(300)
    const copied = made.value !== "" && (await page.evaluate(() => navigator.clipboard.readText())) === made.value
    check(`${lang} token "read": the re-confirmation asked (password + code), the token shown once, copied as shown`, made.asked && TOKEN.test(made.value) && once && copied, {
      asked: made.asked,
      format: TOKEN.test(made.value),
      once,
      copied,
    })
    await scrollCheck(page, tag, "token made", shot("token_made"), [sheet.locator("input, pre, code")])
    await sheet.getByRole("button", { name: T.done, exact: true }).click()
    const metricsName = `e2e-metrics-${lang}-${crypto.randomBytes(2).toString("hex")}`
    const m = await makeToken(page, T, metricsName, "metrics", false)
    await sheet.getByRole("button", { name: T.done, exact: true }).click()
    check(`${lang} token "metrics": made`, TOKEN.test(m.value))

    await apiChecks(lang, ctx, made.value, m.value)

    await page.reload()
    await settle(page)
    const row = page.locator("li").filter({ hasText: name }).first()
    const rowText = await row.innerText()
    const pageText = await page.locator("body").innerText()
    check(
      `${lang} after a reload: only the prefix and "${T.lastUsed}", the token nowhere`,
      rowText.includes(made.value.slice(0, 10)) && rowText.includes(T.lastUsed) && !pageText.includes(made.value),
      {
        prefix: rowText.includes(made.value.slice(0, 10)),
        lastUsed: rowText.includes(T.lastUsed),
      },
    )

    // revoke: the re-confirmation asks again
    const asked = await reauthOnce(page, "**/api/admin/api-tokens/*/revoke", async () => {
      await row.getByRole("button", { name: T.revokeName(name), exact: true }).click()
      await page.getByRole("dialog").last().getByRole("button", { name: T.revoke, exact: true }).click()
    })
    await settle(page)
    const anon = await request.newContext()
    const gone = await anon.get(`${API}/api/v1/news`, { headers: { Authorization: `Bearer ${made.value}` } })
    check(`${lang} revoked (the re-confirmation asked): the token 401`, asked && gone.status() === 401, { asked, status: gone.status() })
    await anon.dispose()
    const list = await json(ctx, "/api/admin/api-tokens")
    const mrow = list.items.find((x) => x.name === metricsName)
    if (mrow) await ctx.request.post(`${BASE}/api/admin/api-tokens/${mrow.id}/revoke`, { headers: { "X-CSRF-Token": await csrfOf(ctx) } })
    const leaked = logs.some((l) => l.includes(made.value) || l.includes(m.value))
    check(`${lang} the tokens are in no console line of the page`, !leaked)
  }

  // c) the reference
  await page.goto(`${BASE}/settings/api?tab=reference`)
  await settle(page)
  const ref = await page.locator("main").innerText()
  check(`${tag} "${T.reference}": the curated OpenAPI shown`, ref.includes(T.refTitle) && ref.includes("/api/v1/news") && ref.includes("/vendor/findings"))
  if (wide) {
    const [download] = await Promise.all([page.waitForEvent("download", { timeout: 8000 }).catch(() => null), page.getByRole("button", { name: T.download, exact: true }).click()])
    let ok = false
    if (download) {
      const file = await download.path()
      const doc = JSON.parse(fs.readFileSync(file, "utf8"))
      ok = download.suggestedFilename() === "cobe-news-openapi.json" && /^3\./.test(doc.openapi) && Object.keys(doc.paths).some((p) => p.endsWith("/news"))
    }
    check(`${lang} "${T.download}": cobe-news-openapi.json, an OpenAPI 3 document with the news`, ok)
  }
  await scrollCheck(page, tag, "reference", shot("reference"))

  // d) the restore test
  await page.goto(`${BASE}/settings/backup?tab=restore`)
  await settle(page)
  const status = await json(ctx, "/api/admin/restore-test")
  const main = page.locator("main")
  const now = page.getByRole("button", { name: T.now, exact: true })
  if (!status.configured) {
    const text = await main.innerText()
    check(
      `${tag} restore test not set up: the hint, "${T.now}" off with the reason`,
      text.includes(T.off) && text.includes(T.notSetUp) && text.includes(T.nowOff) && (await now.isDisabled()),
    )
  } else if (wide) {
    if (!status.newest) {
      await ctx.request.post(`${BASE}/api/admin/backup`, { headers: { "X-CSRF-Token": await csrfOf(ctx) } })
      for (let i = 0; i < 60 && (await json(ctx, "/api/admin/backup")).running; i++) await page.waitForTimeout(1000)
      await page.reload()
      await settle(page)
    }
    const before = status.last?.at ?? null
    await now.click()
    let last = null
    for (let i = 0; i < 120; i++) {
      await page.waitForTimeout(1000)
      const s = await json(ctx, "/api/admin/restore-test")
      if (!s.running && s.last && s.last.at !== before) {
        last = s.last
        break
      }
    }
    await page.reload()
    await settle(page)
    const text = await main.innerText()
    check(
      `${lang} restore test: "${T.now}" – "${T.passed}" with its duration`,
      !!last?.ok && text.includes(T.passed) && text.includes(T.took),
      last && { ok: last.ok, seconds: last.seconds, tables: last.tables },
    )
  } else check(`${tag} restore test set up: "${T.now}" offered`, await now.isEnabled())
  await scrollCheck(page, tag, "restore test", shot("restore_test"))

  check(`${tag} admin: no page or console errors`, errors.length === 0, errors.slice(0, 3))
  await ctx.close()
}

const browser = await chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const lang of ["de", "en"]) for (const width of [1280, 375]) for (const theme of ["light", "dark"]) await run(browser, lang, width, theme)
} finally {
  await browser.close()
}
const failed = results.filter((x) => !x).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed ? 1 : 0)
