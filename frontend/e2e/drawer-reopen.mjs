// Regression check (0.1.56): a drawer opened again while it is still going out. Radix's Dialog.Portal gave the overlay
// and the content a portal each; the overlay (100 ms) was gone before the content (200 ms) had slid out, and opened
// again in that window the overlay came back AFTER the content in <body> – the dimming over the drawer, which took no
// click any more (reported: Vendor News at a product from a notification). components/ui/layer-portal.tsx puts both in
// one portal. Checked here: Escape and the product opened again after 30 … 400 ms – the overlay before the content, the
// drawer's middle is the drawer (not the overlay), a tab in it can be clicked; and a fresh load of a notification's
// link (?product=…&view=versions) shows the drawer at that tab, usable.
//
// Only against a throwaway instance (temp DATA_DIR, never the live one) – how to run it: docs/BETRIEB.md, "Entwicklung / Tests".
// Env: BASE_URL, CREDS (JSON {user, password, totp} of an admin), PLAYWRIGHT, PRODUCT (a catalogue key, default gitlab),
// SHOTS (optional: screenshots).
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { BASE, SHOTS, check, creds, finish, open, pw, settle, signIn } from "./common.mjs"

const PRODUCT = process.env.PRODUCT || "gitlab"
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** The drawer's layers: overlay before content, and what the middle of the drawer is. */
const layers = (page) =>
  page.evaluate(() => {
    const kids = [...document.body.children]
    const overlay = kids.findIndex((e) => e.getAttribute("data-slot") === "sheet-overlay")
    const content = kids.findIndex((e) => e.getAttribute("data-slot") === "sheet-content")
    const el = kids[content]
    const r = el?.getBoundingClientRect()
    const hit = r ? document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2) : null
    return { overlay, content, overlays: kids.filter((e) => e.getAttribute("data-slot") === "sheet-overlay").length, inDrawer: !!el && !!hit && el.contains(hit) }
  })

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  const { ctx, page, errors } = await open(browser, { lang: "de", width: 1280, theme: "light" })
  await signIn(ctx, creds.user, creds.password, true)

  // a notification's link, loaded fresh
  await page.goto(`${BASE}/vendor?product=${encodeURIComponent(PRODUCT)}&view=versions`)
  await page.locator("[data-slot=sheet-content]").waitFor()
  await settle(page)
  let l = await layers(page)
  check("fresh load: one overlay, before the drawer, the drawer on top", l.overlays === 1 && l.overlay < l.content && l.inDrawer, l)
  const current = await page
    .locator("[data-slot=sheet-content] [aria-current=page]")
    .first()
    .innerText()
    .catch(() => "")
  check("fresh load with view=versions: the Versionen tab", /Versionen/.test(current), current)
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/drawer-fresh.png` })

  for (const ms of [30, 120, 170, 400]) {
    await page.keyboard.press("Escape")
    await sleep(ms)
    // opened again in the page (as a card, a link or a notification does): the router reads the new address
    await page.evaluate((key) => {
      history.pushState(null, "", `/vendor?product=${encodeURIComponent(key)}`)
      dispatchEvent(new PopStateEvent("popstate"))
    }, PRODUCT)
    await page.locator("[data-slot=sheet-content][data-state=open]").waitFor()
    await settle(page)
    l = await layers(page)
    check(`opened again after ${ms} ms: the overlay before the drawer, the drawer on top`, l.overlays === 1 && l.overlay < l.content && l.inDrawer, l)
    // usable: a click on a tab inside the drawer switches it (the overlay would take the click)
    const tab = page.locator("[data-slot=sheet-content] a", { hasText: "Versionen" }).first()
    const clicked = await tab.click({ timeout: 3000 }).then(
      () => true,
      () => false,
    )
    await sleep(300)
    check(`opened again after ${ms} ms: a tab in the drawer takes the click`, clicked && new URL(page.url()).searchParams.get("view") === "versions", page.url())
    if (SHOTS && ms === 120) await page.screenshot({ path: `${SHOTS}/drawer-reopen-${ms}.png` })
  }
  check("no page error, no console error", errors.length === 0, errors.slice(0, 3))
  await ctx.close()
} finally {
  await browser.close()
}
finish()
