/** A path of this app from a message (a notification click relayed by the service worker) – or null. Only a path that
 * stays on `origin` once the browser has parsed it: "//evil.example", "/\evil.example" and "/\t/evil.example" (URL
 * parsing drops the tab and makes it "//evil.example") are refused, as is every control character.
 * public/sw.js has the same check (it is not bundled) – the test runs both. */
export function safePath(url: unknown, origin: string): string | null {
  // eslint-disable-next-line no-control-regex -- control characters are exactly what is refused here
  if (typeof url !== "string" || !url.startsWith("/") || /[\u0000-\u001f\u007f\\]/.test(url)) return null
  try {
    const u = new URL(url, origin)
    return u.origin === origin ? u.pathname + u.search + u.hash : null
  } catch {
    return null
  }
}
