// Browser check (0.1.58): a link that brings a signed-out person into Cobe News – a notification (Web Push, the open
// tab's desktop notification), a mail (rule, personal, weekly summary), Teams, Slack, Discord, Telegram, a webhook, the
// calendar – survives the sign-in and opens what it points to, usable: the drawer on top of its dimming, not under it
// (reported: a story's drawer from a push, opened after the sign-in, lay under the dimming until one click).
//
// The link shapes (backend: notify._link and vendor_path, weekly.py, calendar_feed.py, webpush.py, lib/desktop.ts):
//   /?story=<id>                         one story – every channel, push and desktop notification
//   /?ids=<id>,<id>                      a message about several stories ("Cobe News öffnen")
//   /vendor?product=<key>                a product (weekly summary)
//   /vendor?product=<key>&view=versions  a new version or an end of support (mail, chat, push, calendar)
//   /vendor?product=<key>&view=changes   a revised advisory
//   /watch?cve=<CVE>                     a watched CVE
// Each one (1) signed out, signed in through the page with password and TOTP – the page swaps to the app without a
// reload – and (2) loaded fresh with a session (the way back from Microsoft, Entra ID: a full load of `next`). And the
// start of the Entra sign-in takes the longest of these links (it answered 422 beyond 300 characters).
//
// Checked: the address kept, exactly one dimming and it lies before the drawer in <body>, the middle of the drawer is the
// drawer (elementFromPoint), the drawer is opaque, a click in it leaves it open; a click on the dimming closes it.
//
// Only against a throwaway instance (temp DATA_DIR, never the live one) – how to run it: docs/BETRIEB.md, "Entwicklung / Tests".
// Env: BASE_URL, CREDS (JSON {user, password, totp} of an admin), PLAYWRIGHT, PRODUCT (a catalogue key, default gitlab),
// CVE (default CVE-2024-3094 – watched by the check), SHOTS (optional: screenshots). The news must be on with two stories.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { BASE, H, SHOTS, check, creds, finish, freshCode, json, open, pw, settle, signIn } from "./common.mjs"

const PRODUCT = process.env.PRODUCT || "gitlab"
const CVE = process.env.CVE || "CVE-2024-3094"
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** What lies in <body>: every dimming and drawer (order, state, opacity), and what the middle of the drawer is. */
const layers = (page) =>
  page.evaluate(() => {
    const kids = [...document.body.children]
    const of = (sel) => kids.map((e, i) => (e.matches(sel) ? i : -1)).filter((i) => i >= 0)
    const overlays = of("[data-slot$=overlay]")
    const contents = of("[data-slot=sheet-content],[data-slot=dialog-content]")
    const el = document.querySelector("[data-slot=sheet-content]")
    const r = el?.getBoundingClientRect()
    const hit = r ? document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2) : null
    return {
      overlays: overlays.length,
      contents: contents.length,
      below: overlays.length === 1 && contents.length === 1 && overlays[0] < contents[0],
      inDrawer: !!el && !!hit && el.contains(hit),
      opaque: !!el && getComputedStyle(el).opacity === "1",
      states: [...document.querySelectorAll("[data-slot$=overlay],[data-slot=sheet-content]")].map((e) => e.getAttribute("data-state")),
      visible: document.visibilityState,
    }
  })

/** The drawer is open and usable: on top of its dimming, opaque, a click in it keeps it open. */
async function drawerUsable(page, tag) {
  const drawer = page.locator("[data-slot=sheet-content][data-state=open]")
  const shown = await drawer.waitFor({ timeout: 15000 }).then(
    () => true,
    () => false,
  )
  if (!shown) return check(`${tag}: the drawer opened`, false)
  await settle(page)
  await page.waitForFunction(() => document.querySelector("[data-slot=sheet-content]")?.getAnimations().length === 0, null, { timeout: 5000 }).catch(() => {})
  const l = await layers(page)
  check(`${tag}: one dimming, below the drawer, the drawer on top and opaque`, l.overlays === 1 && l.below && l.inDrawer && l.opaque, l)
  const box = await drawer.boundingBox()
  await page.mouse.click(box.x + box.width / 2, box.y + box.height - 120)
  await sleep(400)
  check(`${tag}: a click in the drawer leaves it open`, (await drawer.count()) === 1, await layers(page))
}

/** Signed out at `link`, signed in through the page (password, then the TOTP code): the page swaps without a reload. */
async function viaSignInPage(browser, link, tag) {
  const { ctx, page, errors } = await open(browser, { lang: "de", width: 1280, theme: "light" })
  await page.goto(`${BASE}${link}`)
  await page.locator("#username").fill(creds.user)
  await page.locator("#password").fill(creds.password)
  await page.keyboard.press("Enter")
  const otp = page.locator("input[autocomplete=one-time-code]")
  await otp.waitFor()
  await otp.focus()
  await page.keyboard.type(await freshCode())
  await page.locator("#username").waitFor({ state: "detached", timeout: 10000 })
  const at = new URL(page.url())
  check(`${tag}: the address kept through the sign-in`, at.pathname + at.search === link, at.pathname + at.search)
  return { ctx, page, errors }
}

/** Loaded fresh with a session – as after the redirect back from Microsoft (Entra ID lands on `next` with a full load). */
async function viaFullLoad(browser, state, link) {
  const { ctx, page, errors } = await open(browser, { lang: "de", width: 1280, theme: "light" }, { storageState: state })
  await page.goto(`${BASE}${link}`)
  return { ctx, page, errors }
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  // a session for the preparation and the "full load" rounds
  const prep = await open(browser, { lang: "de", width: 1280, theme: "light" })
  await signIn(prep.ctx, creds.user, creds.password, true)
  const stories = (await json(prep.ctx, "/api/news?state=all&limit=2")).items ?? []
  check("two stories to open (the news switched on)", stories.length >= 2, stories.length)
  await prep.ctx.request.post(`${BASE}/api/me/cve-watch`, { data: { cve: CVE }, headers: await H(prep.ctx) })
  const state = await prep.ctx.storageState()
  await prep.ctx.close()
  if (stories.length < 2) finish()

  const links = [
    { kind: "story", link: `/?story=${stories[0].id}` },
    { kind: "stories", link: `/?ids=${stories[0].id},${stories[1].id}` },
    { kind: "product", link: `/vendor?product=${encodeURIComponent(PRODUCT)}` },
    { kind: "versions", link: `/vendor?product=${encodeURIComponent(PRODUCT)}&view=versions`, tab: /Versionen/ },
    { kind: "changes", link: `/vendor?product=${encodeURIComponent(PRODUCT)}&view=changes`, tab: /Änderungen/ },
    { kind: "watch", link: `/watch?cve=${CVE}` },
  ]

  for (const how of ["sign-in page", "full load"]) {
    for (const { kind, link, tab } of links) {
      const tag = `${how} ${kind}`
      const { ctx, page, errors } = how === "sign-in page" ? await viaSignInPage(browser, link, tag) : await viaFullLoad(browser, state, link)
      if (kind === "stories") {
        // the list of exactly these stories – no drawer
        const cards = page.locator("[data-open]")
        await page.waitForFunction(() => document.querySelectorAll("[data-open]").length === 2, null, { timeout: 15000 }).catch(() => {})
        check(`${tag}: the list shows exactly the two stories`, (await cards.count()) === 2, await cards.count())
      } else if (kind === "watch") {
        const row = page.locator(`#watch-${CVE}`)
        const there = await row.waitFor({ timeout: 15000 }).then(
          () => true,
          () => false,
        )
        check(`${tag}: the watched CVE's row is there`, there)
      } else {
        await drawerUsable(page, tag)
        if (tab) {
          const current = await page
            .locator("[data-slot=sheet-content] [aria-current=page]")
            .first()
            .innerText()
            .catch(() => "")
          check(`${tag}: the drawer at its tab`, tab.test(current), current)
        }
        if (kind === "story" && SHOTS) await page.screenshot({ path: `${SHOTS}/after-signin-${how.replace(" ", "-")}.png` })
      }
      const l = await layers(page)
      check(`${tag}: nothing dimmed without a drawer`, kind === "stories" || kind === "watch" ? l.overlays === 0 : l.overlays === 1, l)
      check(`${tag}: no page error, no console error`, errors.length === 0, errors.slice(0, 3))
      // a click on the dimming (outside the drawer) closes it – the dimming takes no click meant for the drawer
      if (kind === "story" && how === "full load") {
        await page.mouse.click(60, 400)
        await page
          .locator("[data-slot=sheet-content]")
          .waitFor({ state: "detached", timeout: 3000 })
          .catch(() => {})
        check(
          `${tag}: a click on the dimming closes the drawer`,
          (await page.locator("[data-slot=sheet-content]").count()) === 0 && !new URL(page.url()).searchParams.has("story"),
          page.url(),
        )
      }
      await ctx.close()
    }
  }

  // Entra ID: the start of the sign-in keeps the longest link of a message (the list of its stories, notify.LINK_MAX) as
  // `next` – it refused more than 300 characters with 422, the sign-in with Microsoft could not even begin
  const ids = Array.from({ length: 50 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`).join(",")
  const anon = await pw.request.newContext()
  const r = await anon.get(`${BASE}/api/auth/oidc/start?next=${encodeURIComponent(`/?ids=${ids}`)}`, { maxRedirects: 0 })
  check("Entra ID: the start takes a link of 1900 characters as next (a redirect, not 422)", r.status() === 302 || r.status() === 307, r.status())
  await anon.dispose()
} finally {
  await browser.close()
}
finish()
