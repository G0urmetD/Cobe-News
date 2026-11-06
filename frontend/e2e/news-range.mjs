// Browser check 0.1.51: News "Zeitraum" (presets, own range, time field, chip, URL share/reload, saved view, reset) and
// the ids link (/?ids=…, with ?story=). DE/EN, 1280/375, light/dark; no page error, console error, CSP violation or
// horizontal scroll. Against a throwaway instance only (docs/BETRIEB.md, "Entwicklung / Tests"). It expects: News on, a
// reader (CREDS: reader, reader_password) whose read watermark is 14 hours old, stories over the last weeks (some
// today, some after the watermark, some before), CREDS.ids: three story ids. Env: BASE_URL, CREDS, PLAYWRIGHT, SHOTS.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { BASE, COMBOS, SHOTS, check, creds, finish, open, pw, scrollCheck, settle, signIn } from "./common.mjs"

const browser = await pw.chromium.launch({ channel: "chrome", headless: true })
const L = {
  de: {
    range: "Zeitraum",
    today: "Heute",
    d7: "7 Tage",
    visit: "Seit meinem letzten Besuch",
    apply: "Zeitraum anwenden",
    reset: "Filter zurücksetzen",
    fetched: "Eingegangen",
    from: "Von",
    to: "Bis",
    order: "„Von“ liegt nach „Bis“.",
    ids: "Aus der Benachrichtigung",
    views: "Ansichten",
    save: "Speichern",
    chipToday: "heute, seit 00:00",
    chipVisit: "seit meinem letzten Besuch (vor 14 Stunden)",
    now: "jetzt",
    hits: "Treffer",
  },
  en: {
    range: "Time range",
    today: "Today",
    d7: "7 days",
    visit: "Since my last visit",
    apply: "Apply range",
    reset: "Reset filter",
    fetched: "Received",
    from: "From",
    to: "To",
    order: "“From” is after “To”.",
    ids: "From the notification",
    views: "Views",
    save: "Save",
    chipToday: "today, since 00:00",
    chipVisit: "since my last visit (14 hours ago)",
    now: "now",
    hits: "hit",
  },
}
const pad = (n) => String(n).padStart(2, "0")
const day = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`

for (const c of COMBOS) {
  const tag = `[${c.lang} ${c.width} ${c.theme}]`
  const t = L[c.lang]
  const { ctx, page, errors } = await open(browser, c, { timezoneId: "Europe/Berlin" })
  await signIn(ctx, creds.reader, creds.reader_password)
  const shot = (n) => (SHOTS ? page.screenshot({ path: `${SHOTS}/${c.lang}-${c.width}-${c.theme}-${n}.png` }) : null)
  const trigger = () => page.getByRole("button", { name: new RegExp(`^${t.range}`) }).first()
  const cards = () => page.locator("main article").count()

  await page.goto(`${BASE}/`)
  await settle(page)
  const all = await cards()
  check(`${tag} list shows stories`, all > 0, all)
  await trigger().click()
  await page.waitForTimeout(250)
  const pop = page.locator("[data-slot=popover-content]")
  check(`${tag} popover open with presets`, await pop.getByRole("button", { name: t.today, exact: true }).isVisible())
  check(`${tag} visit hint (14 h)`, /14/.test((await pop.getByRole("button", { name: new RegExp(t.visit) }).textContent()) ?? ""))
  await scrollCheck(page, tag, "popover", null)
  const box = await pop.boundingBox()
  check(`${tag} popover inside the viewport`, box && box.x >= 0 && box.x + box.width <= c.width + 0.5, box)
  await shot("1-popover")
  // the field toggle before a range: kept for the next pick
  await pop.getByRole("radio", { name: t.fetched }).click()
  await pop.getByRole("button", { name: t.today, exact: true }).click()
  await settle(page)
  check(`${tag} Heute in the URL as key, arrival`, page.url().includes("range=today") && page.url().includes("time=fetched"), page.url())
  check(`${tag} trigger shows the short label`, ((await trigger().textContent()) ?? "").includes(t.today))
  const chip = page.getByRole("group", { name: c.lang === "de" ? "Aktive Filter" : "Active filters" })
  const chipText = (await chip.textContent()) ?? ""
  check(`${tag} chip with text and hits`, chipText.includes(t.chipToday) && chipText.includes(t.hits), chipText)
  const todayCount = await cards()
  check(`${tag} fewer stories today`, todayCount > 0 && todayCount < all, { todayCount, all })
  await shot("2-today")
  // reload: the preset stays a preset
  await page.reload()
  await settle(page)
  check(`${tag} reload keeps Heute`, ((await trigger().textContent()) ?? "").includes(t.today) && (await cards()) === todayCount)

  // own range with validation
  await trigger().click()
  await page.waitForTimeout(200)
  const two = new Date(Date.now() - 2 * 86400000)
  await pop.getByLabel(t.from, { exact: true }).fill(day(new Date()))
  await pop.getByLabel(t.to, { exact: true }).fill(day(two))
  const err = pop.getByRole("alert")
  check(`${tag} inline error von > bis`, ((await err.textContent()) ?? "").includes(t.order) && (await pop.getByRole("button", { name: t.apply }).isDisabled()))
  await shot("3-error")
  await pop.getByLabel(t.from, { exact: true }).fill(day(two))
  await pop.getByLabel(c.lang === "de" ? "Von – Uhrzeit" : "From – time").fill("08:00")
  await pop.getByLabel(t.to, { exact: true }).fill("")
  await pop.getByRole("button", { name: t.apply }).click()
  await settle(page)
  const label = (await trigger().textContent()) ?? ""
  check(`${tag} own range label`, label.includes("08:00") && label.includes(t.now), label)
  check(`${tag} own range in the URL as UTC`, /since=\d{4}-\d\d-\d\dT0[67]%3A00%3A00\.000Z/.test(page.url()) && !page.url().includes("range="), page.url())
  await shot("4-custom")

  // since my last visit
  await trigger().click()
  await page.waitForTimeout(200)
  await pop.getByRole("button", { name: new RegExp(t.visit) }).click()
  await settle(page)
  const vt = (await chip.textContent()) ?? ""
  check(`${tag} visit chip`, vt.includes(t.chipVisit) && page.url().includes("range=visit") && !page.url().includes("time="), vt)
  const visitCount = await cards()
  check(`${tag} visit shows the stories after the watermark`, visitCount > 0 && visitCount < all, visitCount)
  await shot("5-visit")

  // reset removes the range
  await page.getByRole("button", { name: t.reset }).click()
  await settle(page)
  check(`${tag} reset clears the range`, !page.url().includes("range=") && !(await chip.isVisible().catch(() => false)) && (await cards()) === all)

  if (c.wide) {
    // a saved view carries the preset key
    await page.goto(`${BASE}/?range=7d`)
    await settle(page)
    await page.getByRole("button", { name: t.views }).click()
    await page.waitForTimeout(200)
    const vp = page.locator("[data-slot=popover-content]")
    await vp.getByRole("textbox").first().fill(`E2E 7d ${c.lang}`)
    await vp.getByRole("button", { name: t.save }).click()
    await page.waitForTimeout(600)
    const views = await (await ctx.request.get(`${BASE}/api/me/views?page=news`)).json()
    check(
      `${tag} saved view stores range=7d`,
      views.items.some((v) => v.query === "range=7d"),
      views.items.map((v) => v.query),
    )
    await page.keyboard.press("Escape")
    await page.goto(`${BASE}/`)
    await settle(page)
    await page.getByRole("button", { name: t.views }).click()
    await page.waitForTimeout(200)
    await page.locator("[data-slot=popover-content]").getByText(`E2E 7d ${c.lang}`).click()
    await settle(page)
    check(`${tag} applying the view brings 7 Tage back`, page.url().includes("range=7d") && ((await trigger().textContent()) ?? "").includes(t.d7))
    for (const v of (await (await ctx.request.get(`${BASE}/api/me/views?page=news`)).json()).items)
      await ctx.request.delete(`${BASE}/api/me/views/${v.id}`, {
        headers: { "X-CSRF-Token": (await ctx.cookies(BASE)).find((k) => k.name.endsWith("cobe_news_csrf"))?.value ?? "" },
      })
  }

  // the ids link with a story's drawer and a range present: exactly those stories, the drawer opens
  const ids = creds.ids
  await page.goto(`${BASE}/?ids=${ids.join(",")},not-a-uuid&story=${ids[0]}&range=today`)
  await settle(page)
  check(`${tag} drawer of ?story= open`, await page.getByRole("dialog").isVisible())
  await shot("6-ids-drawer")
  await page.keyboard.press("Escape")
  await settle(page)
  const idChip = (await chip.textContent()) ?? ""
  check(`${tag} ids chip`, idChip.includes(t.ids) && idChip.includes("3"), idChip)
  check(`${tag} exactly the three stories`, (await cards()) === 3, await cards())
  await scrollCheck(page, tag, "ids list", null)
  await shot("7-ids")
  await chip.getByRole("button").click()
  await settle(page)
  check(`${tag} chip × ends the ids list (range kept)`, !page.url().includes("ids=") && page.url().includes("range=today"), page.url())
  await page.goto(`${BASE}/`)
  await settle(page)
  await scrollCheck(page, tag, "list", null)
  check(`${tag} no page or console error`, errors.length === 0, errors.slice(0, 3))
  await ctx.close()
}
await browser.close()
const { violations } = await import("./csp-guard.mjs")
check("no CSP violation", violations.length === 0, violations.slice(0, 3))
finish()
