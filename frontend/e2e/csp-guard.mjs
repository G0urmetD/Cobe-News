// CSP guard for every browser check (0.1.42: `style-src 'self' 'sha256-…'; style-src-attr 'unsafe-inline'` – no inline
// <style> element any more). Imported first by each script: every context of every browser the script launches gets
// a `securitypolicyviolation` listener (reported to the console as "[csp] …"), and every page's console is watched for
// it and for the browser's own "Content Security Policy" messages. At the end a violation fails the run: a FAIL line
// with the first ones and exit code 1; without one the last line says "CSP: no violation".
// The CSP is sent by the backend – run the checks against the production build it serves (STATIC_DIR), not the dev
// server (npm run dev sends no CSP and injects its CSS as <style> elements).
const pw = await import(process.env.PLAYWRIGHT || "playwright-core")

export const violations = []

function listen() {
  document.addEventListener(
    "securitypolicyviolation",
    (e) =>
      console.error(`[csp] ${e.effectiveDirective} blocked ${e.blockedURI || "inline"} (${e.sourceFile || location.pathname}:${e.lineNumber}) ${(e.sample || "").slice(0, 60)}`),
    true,
  )
}

function watchPage(page) {
  page.on("console", (m) => {
    const text = m.text()
    if (/^\[csp\]|Content Security Policy/i.test(text)) violations.push(`${page.url()} – ${text.slice(0, 240)}`)
  })
}

async function watchContext(ctx) {
  await ctx.addInitScript(listen)
  ctx.on("page", watchPage)
  for (const p of ctx.pages()) watchPage(p)
  return ctx
}

const launch = pw.chromium.launch.bind(pw.chromium)
pw.chromium.launch = async (...args) => {
  const browser = await launch(...args)
  const newContext = browser.newContext.bind(browser)
  browser.newContext = async (...opts) => watchContext(await newContext(...opts))
  return browser
}

process.on("exit", () => {
  if (violations.length) {
    const seen = [...new Set(violations)]
    console.log(`FAIL  CSP: ${violations.length} violation(s)  (${JSON.stringify(seen.slice(0, 5))})`)
    process.exitCode = 1
  } else console.log("CSP: no violation")
})
