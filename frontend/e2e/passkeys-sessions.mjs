// Browser check (0.1.39): passkeys and "Meine Sitzungen" – with Chrome's virtual WebAuthn authenticator (CDP: ctap2,
// resident key, user verification), at BASE_URL (its host must be the instance's BASE_URL host – `localhost` works).
// - A reader registers a passkey (Profil & Sicherheit → Anmeldung & Sicherheit; the re-confirmation of a fresh sign-in
//   counts), ES256; a second one on the same authenticator: "Dieses Gerät hat schon einen Passkey …" (excludeCredentials).
// - Sign-in without a user name from a fresh context; an authenticator without user verification is refused; a
//   cancelled browser dialog says so; no passkey button while an admin switched passkeys off, nor on another origin
//   (127.0.0.1 – the passkeys are bound to the host name).
// - Rename; Meine Sitzungen: "Diese Sitzung", the passkey session with its method, end it (it gets 401), "Alle anderen
//   abmelden"; removing the passkey ends the sessions signed in with it (401).
// - Admin: the user's "Sitzungen & Passkeys" – end all sessions, remove a passkey; the audit log has these entries.
// DE and EN, 1280 px and 375 px, light and dark: no page error, no console error, no horizontal scroll. The flows run
// once per language (the wide light run); every run checks the pages.
// Env: BASE_URL (the vite dev server at the instance's BASE_URL, e.g. http://localhost:5643), ALT_URL (the same server
// under another origin, e.g. http://127.0.0.1:5643), CREDS ({user, password, totp, reader, reader_password}), PLAYWRIGHT,
// SHOTS. Installed Google Chrome (channel "chrome"); notifications stubbed, never granted.
import "./csp-guard.mjs" // first: every browser context of this run fails on a CSP violation
import { BASE, COMBOS, H, SHOTS, check, creds, dismissToasts, finish, json, open, pw, scrollCheck, settle, signIn, toastAfter, toastCount } from "./common.mjs"
import { texts } from "./i18n-text.mjs"

const ALT = (process.env.ALT_URL || "").replace(/\/$/, "")

async function authenticator(page, { uv = true } = {}) {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send("WebAuthn.enable")
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: uv, automaticPresenceSimulation: true },
  })
  return { cdp, id: authenticatorId }
}

const me = async (ctx) => (await ctx.request.get(`${BASE}/api/me`)).status()

async function passkeyButton(page, t) {
  await page.goto(`${BASE}/`)
  await settle(page)
  return page.getByRole("button", { name: t("passkey.signIn"), exact: true })
}

/** Signs a fresh context in with the copied credential – true when the app is open afterwards. */
async function passkeySignIn(browser, combo, t, cred, uv = true) {
  const s = await open(browser, combo)
  const a = await authenticator(s.page, { uv })
  if (cred) await a.cdp.send("WebAuthn.addCredential", { authenticatorId: a.id, credential: cred })
  const button = await passkeyButton(s.page, t)
  if (await button.count()) await button.click()
  await s.page.waitForTimeout(2500)
  await settle(s.page)
  return { ...s, ok: (await me(s.ctx)) === 200 }
}

async function adminCtx(browser, combo) {
  const s = await open(browser, combo)
  await signIn(s.ctx, creds.user, creds.password, true)
  return s
}

async function setPasskeys(admin, enabled) {
  const cur = await json(admin.ctx, "/api/admin/auth/passkeys")
  const r = await admin.ctx.request.put(`${BASE}/api/admin/auth/passkeys`, { data: { enabled, rev: cur.rev }, headers: await H(admin.ctx) })
  return r.ok()
}

async function flows(browser, combo, t) {
  const { lang } = combo
  const tag = `${lang} flow`
  // the reader: a passkey, registered after the re-confirmation (a fresh sign-in counts)
  const a = await open(browser, combo)
  await signIn(a.ctx, creds.reader, creds.reader_password)
  const auth = await authenticator(a.page)
  for (const p of await json(a.ctx, "/api/me/passkeys")) await a.ctx.request.delete(`${BASE}/api/me/passkeys/${p.id}`, { headers: await H(a.ctx) })
  await a.page.goto(`${BASE}/settings/profile?tab=security`)
  await settle(a.page)
  const name = `E2E ${lang} ${Date.now() % 10000}`
  const add = async () => {
    await a.page.getByRole("button", { name: t("passkey.add"), exact: true }).click()
    const dialog = a.page.getByRole("dialog")
    await dialog.locator("#passkey-name").fill(name)
    const before = await toastCount(a.page)
    await dialog.getByRole("button", { name: t("passkey.addDo"), exact: true }).click()
    return { dialog, toast: await toastAfter(a.page, before, 6000) }
  }
  const first = await add()
  const keys = await json(a.ctx, "/api/me/passkeys")
  const creds1 = (await auth.cdp.send("WebAuthn.getCredentials", { authenticatorId: auth.id })).credentials
  check(
    `${tag}: a passkey registered (toast, listed, a resident credential on the authenticator)`,
    first.toast?.type === "success" && keys.some((k) => k.name === name) && creds1.length === 1 && creds1[0].isResidentCredential,
    { toast: first.toast?.type, keys: keys.length, creds: creds1.length },
  )
  const alg = keys.find((k) => k.name === name)?.alg ?? keys.find((k) => k.name === name)?.algorithm ?? null
  check(`${tag}: ES256 (the virtual authenticator's key)`, alg === null || /ES256|-7/.test(String(alg)), { alg })
  await dismissToasts(a.page)
  const second = await add()
  await a.page.waitForTimeout(1500)
  const msg = await second.dialog.innerText().catch(() => "")
  check(
    `${tag}: a second registration on the same device is refused (excludeCredentials)`,
    msg.includes(t("passkey.err.exists")) && (await json(a.ctx, "/api/me/passkeys")).length === 1,
    { msg: msg.slice(0, 120) },
  )
  await a.page.keyboard.press("Escape")
  const cred = creds1[0]

  // sign-in without a user name, from a fresh context
  const b = await passkeySignIn(browser, combo, t, cred)
  check(`${tag}: sign-in with the passkey from a fresh context`, b.ok)
  // without user verification: refused
  const c = await passkeySignIn(browser, combo, t, cred, false)
  const cText = await c.page.locator("body").innerText()
  check(
    `${tag}: an authenticator without user verification is refused (not signed in, the reason shown)`,
    !c.ok && (cText.includes(t("auth.failed")) || cText.includes(t("passkey.signInCancelled"))),
    { ok: c.ok, failed: cText.includes(t("auth.failed")), cancelled: cText.includes(t("passkey.signInCancelled")) },
  )
  await c.ctx.close()
  // the browser dialog cancelled
  const d = await open(browser, combo)
  await d.ctx.addInitScript(() => {
    navigator.credentials.get = () => Promise.reject(new DOMException("The operation either timed out or was not allowed.", "NotAllowedError"))
  })
  const dButton = await passkeyButton(d.page, t)
  await dButton.click()
  await d.page.waitForTimeout(800)
  const dText = await d.page.locator("body").innerText()
  check(`${tag}: a cancelled dialog: "${t("passkey.signInCancelled")}"`, dText.includes(t("passkey.signInCancelled")) && dText.includes(t("passkey.err.cancelled")))
  if (SHOTS) await d.page.screenshot({ path: `${SHOTS}/${lang}-passkey_cancelled.png` })
  await d.ctx.close()

  // rename
  await a.page.reload()
  await settle(a.page)
  await a.page
    .getByRole("button", { name: t("passkey.rename") })
    .first()
    .click()
  const renamed = `${name} ✓`
  await a.page.locator("#passkey-rename").fill(renamed)
  await a.page.locator("#passkey-rename").press("Enter")
  await a.page.waitForTimeout(800)
  check(
    `${tag}: renamed`,
    (await json(a.ctx, "/api/me/passkeys")).some((k) => k.name === renamed),
  )

  // Meine Sitzungen: this session, the passkey session; end it
  await a.page.goto(`${BASE}/settings/profile?tab=sessions`)
  await settle(a.page)
  const list = a.page.locator("main li")
  const current = list.filter({ hasText: t("security.thisSession") })
  const viaKey = list.filter({ hasText: t("security.method.passkeyNamed", { name: renamed }) })
  check(`${tag} sessions: "${t("security.thisSession")}" once, the passkey session with its method`, (await current.count()) === 1 && (await viaKey.count()) >= 1, {
    current: await current.count(),
    viaKey: await viaKey.count(),
  })
  await viaKey
    .first()
    .getByRole("button", { name: t("security.endOne") })
    .click()
  await a.page.waitForTimeout(800)
  check(`${tag} sessions: the passkey session ended – it gets 401`, (await me(b.ctx)) === 401)
  await b.ctx.close()
  // "Alle anderen abmelden"
  const e = await open(browser, combo)
  await signIn(e.ctx, creds.reader, creds.reader_password)
  await a.page.reload()
  await settle(a.page)
  await a.page.getByRole("button", { name: t("security.endOthers") }).click()
  const dialog = a.page.getByRole("dialog").last()
  if (await dialog.count())
    await dialog
      .getByRole("button", { name: t("security.endOthers") })
      .click()
      .catch(() => {})
  await a.page.waitForTimeout(800)
  check(`${tag} sessions: "${t("security.endOthers")}" – the other one 401, this one stays`, (await me(e.ctx)) === 401 && (await me(a.ctx)) === 200)
  await e.ctx.close()

  // removing the passkey ends the sessions signed in with it
  const f = await passkeySignIn(browser, combo, t, cred)
  await a.page.goto(`${BASE}/settings/profile?tab=security`)
  await settle(a.page)
  await a.page
    .getByRole("button", { name: t("common.remove") })
    .first()
    .click()
  const before = await toastCount(a.page)
  await a.page
    .getByRole("dialog")
    .last()
    .getByRole("button", { name: t("common.remove") })
    .click()
  const removedToast = await toastAfter(a.page, before)
  check(
    `${tag}: removed – "${t("passkey.removedSessions", { count: 1 })}", that session 401`,
    f.ok && removedToast?.text.includes(t("passkey.removedSessions", { count: 1 })) && (await me(f.ctx)) === 401,
    {
      signedIn: f.ok,
      toast: removedToast?.text,
    },
  )
  await f.ctx.close()

  // admin: the user's sessions & passkeys – a new passkey of the reader, end all sessions, remove the passkey
  await a.page.reload()
  await settle(a.page)
  await auth.cdp.send("WebAuthn.clearCredentials", { authenticatorId: auth.id })
  await add()
  await a.page.waitForTimeout(800)
  const adm = await adminCtx(browser, combo)
  const users = await json(adm.ctx, "/api/admin/users")
  const rudi = users.find((u) => u.username === creds.reader)
  await adm.page.goto(`${BASE}/settings/users`)
  await settle(adm.page)
  await adm.page
    .locator("main li")
    .filter({ hasText: rudi.display_name })
    .first()
    .getByRole("button", { name: t("users.actions") })
    .click()
  await adm.page.getByRole("menuitem", { name: t("users.security") }).click()
  const sheet = adm.page.locator("[data-slot=sheet-content]")
  await sheet.waitFor({ timeout: 5000 }).catch(() => {})
  // the sheet mounts before its lists have loaded – wait for the person's entry before reading
  await sheet
    .getByText(rudi.display_name)
    .first()
    .waitFor({ timeout: 5000 })
    .catch(() => {})
  const sheetText = await sheet.innerText()
  await scrollCheck(adm.page, `${lang} admin`, "user sessions & passkeys", SHOTS && `${lang}-admin_user_security`)
  await sheet.getByRole("button", { name: t("users.endAll") }).click()
  await adm.page
    .getByRole("dialog")
    .last()
    .getByRole("button", { name: t("users.endAll") })
    .click()
  await adm.page.waitForTimeout(1000)
  const endedAll = (await me(a.ctx)) === 401
  await sheet
    .getByRole("button", { name: t("common.remove") })
    .first()
    .click()
  await adm.page
    .getByRole("dialog")
    .last()
    .getByRole("button", { name: t("common.remove") })
    .click()
  await adm.page.waitForTimeout(1000)
  const left = (await json(adm.ctx, `/api/admin/users/${rudi.id}/passkeys`)).length
  check(
    `${lang} admin "${t("users.security")}": the reader's sessions and passkey listed; all ended (401), the passkey removed`,
    sheetText.includes(name) && endedAll && left === 0,
    {
      listed: sheetText.includes(name),
      endedAll,
      left,
    },
  )
  // the audit log has them
  const audit = await json(adm.ctx, `/api/admin/audit?limit=200&q=${encodeURIComponent(creds.reader)}`)
  const acts = new Set(audit.items.map((x) => x.action))
  check(
    `${lang} audit log: passkey added, renamed, removed, sessions ended`,
    ["passkey.added", "passkey.renamed", "passkey.removed", "sessions.revoked"].every((x) => acts.has(x)),
    [...acts],
  )
  // switched off: no passkey button; on again
  await setPasskeys(adm, false)
  const off = await open(browser, combo)
  const offButton = await passkeyButton(off.page, t)
  const hiddenOff = (await offButton.count()) === 0
  await off.ctx.close()
  await setPasskeys(adm, true)
  check(`${lang} passkeys switched off by the admin: no passkey button on the sign-in page`, hiddenOff)
  await resetRemovesPasskeys(browser, combo, t, adm, lang === "de" ? [creds.reader4, creds.reader4_password] : [creds.reader5, creds.reader5_password])
  await adm.ctx.close()
  await a.ctx.close()
}

/** 0.1.40: an admin's password reset removes the account's passkeys – the dialog says so, the list is empty, the audit
 * log has passkey.removed with "reset". A reader of its own per language (its password is gone after the reset). */
async function resetRemovesPasskeys(browser, combo, t, adm, [user, password]) {
  const tag = `${combo.lang} reset`
  if (!user) return check(`${tag}: seed – a reader for the reset (reader4 / reader5 in CREDS)`, false)
  const p = await open(browser, combo)
  await signIn(p.ctx, user, password)
  await authenticator(p.page)
  await p.page.goto(`${BASE}/settings/profile?tab=security`)
  await settle(p.page)
  await p.page.getByRole("button", { name: t("passkey.add"), exact: true }).click()
  await p.page
    .getByRole("dialog")
    .getByRole("button", { name: t("passkey.addDo"), exact: true })
    .click()
  await p.page.waitForTimeout(1500)
  const had = (await json(p.ctx, "/api/me/passkeys")).length
  const u = (await json(adm.ctx, "/api/admin/users")).find((x) => x.username === user)
  await adm.page.goto(`${BASE}/settings/users`)
  await settle(adm.page)
  await adm.page
    .locator("main li")
    .filter({ hasText: u.display_name })
    .first()
    .getByRole("button", { name: t("users.actions") })
    .click()
  await adm.page.getByRole("menuitem", { name: t("users.resetPw") }).click()
  const dialog = adm.page.getByRole("dialog").last()
  await dialog.waitFor({ timeout: 5000 }).catch(() => {})
  const text = await dialog.innerText()
  const says = text.includes(t("users.resetPwText", { name: u.display_name })) && /passkey/i.test(text)
  if (SHOTS) await adm.page.screenshot({ path: `${SHOTS}/${combo.lang}-reset_passkeys_dialog.png` })
  await dialog.getByRole("button", { name: t("users.resetPw"), exact: true }).click()
  await adm.page.waitForTimeout(1200)
  await adm.page.keyboard.press("Escape") // the temporary password's dialog (never read here)
  const left = (await json(adm.ctx, `/api/admin/users/${u.id}/passkeys`)).length
  const audit = await json(adm.ctx, `/api/admin/audit?limit=50&action=passkey.removed&q=${encodeURIComponent(user)}`)
  const entry = audit.items.find((x) => x.details?.reset === true)
  check(`${tag}: the dialog mentions the passkeys; after the reset the list is empty, passkey.removed with reset logged`, had === 1 && says && left === 0 && !!entry, {
    had,
    says,
    left,
    logged: !!entry,
  })
  await p.ctx.close()
}

async function pages(browser, combo, t) {
  const { lang, width, theme } = combo
  const tag = `${lang} ${width}px ${theme}`
  const shot = (n) => SHOTS && `${lang}-${width}-${theme}-${n}`
  // the sign-in page: the button at the passkeys' origin, none at another
  const s = await open(browser, combo)
  const button = await passkeyButton(s.page, t)
  const shown = (await button.count()) === 1
  await scrollCheck(s.page, tag, "sign-in", shot("signin_passkey"))
  let other = null
  if (ALT) {
    await s.page.goto(`${ALT}/`)
    await settle(s.page)
    other = await s.page.getByRole("button", { name: t("passkey.signIn"), exact: true }).count()
  }
  check(`${tag} sign-in: "${t("passkey.signIn")}" at ${BASE}${ALT ? `, none at ${ALT}` : ""}`, shown && (other === null || other === 0), { shown, other })
  check(`${tag} sign-in: no page or console errors`, s.errors.length === 0, s.errors.slice(0, 3))
  await s.ctx.close()
  // the reader's security and sessions pages
  const r = await open(browser, combo)
  await signIn(r.ctx, creds.reader, creds.reader_password)
  await r.page.goto(`${BASE}/settings/profile?tab=security`)
  await settle(r.page)
  check(`${tag} profile: the passkeys with "${t("passkey.add")}"`, (await r.page.getByRole("button", { name: t("passkey.add"), exact: true }).count()) === 1)
  await scrollCheck(r.page, tag, "profile security", shot("profile_security"))
  await r.page.goto(`${BASE}/settings/profile?tab=sessions`)
  await settle(r.page)
  check(`${tag} sessions: "${t("security.thisSession")}"`, (await r.page.locator("main").innerText()).includes(t("security.thisSession")))
  await scrollCheck(r.page, tag, "sessions", shot("sessions"))
  check(`${tag} reader: no page or console errors`, r.errors.length === 0, r.errors.slice(0, 3))
  await r.ctx.close()
}

const browser = await pw.chromium.launch({ channel: "chrome", headless: process.env.HEADED !== "1" })
try {
  for (const combo of COMBOS) {
    const t = texts(combo.lang)
    if (combo.wide) await flows(browser, combo, t)
    await pages(browser, combo, t)
  }
} finally {
  await browser.close()
}
finish()
