/* Cobe News service worker – only for desktop notifications: Web Push with every tab closed, and the click on a
 * notification. It caches nothing and answers no requests (no "fetch" handler): the app always comes from the server. */

self.addEventListener("install", () => self.skipWaiting())
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()))

/** Only paths of this app ("/?story=…") – never another site, whatever a message says: no control characters (URL
 * parsing drops a tab – "/\t/evil.example" became "//evil.example"), no backslash, and the parsed URL must stay on this
 * origin. The same check as src/lib/safe-path.ts (tested there). */
function safePath(url) {
  // eslint-disable-next-line no-control-regex
  if (typeof url !== "string" || !url.startsWith("/") || /[\u0000-\u001f\u007f\\]/.test(url)) return "/"
  try {
    const u = new URL(url, self.location.origin)
    return u.origin === self.location.origin ? u.pathname + u.search + u.hash : "/"
  } catch {
    return "/"
  }
}

/** Tells the open pages what became of a push: shown (handed to the system) or refused by the browser, with its reason –
 * the test in the settings says so instead of leaving the person guessing. Only the kind, the tag and the error text. */
async function report(message) {
  try {
    if (typeof BroadcastChannel === "function") {
      const ch = new BroadcastChannel("cobe-news-notify")
      ch.postMessage(message)
      ch.close()
      return
    }
    const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true })
    for (const c of all) c.postMessage(message)
  } catch {
    /* nobody to tell */
  }
}

self.addEventListener("push", (event) => {
  let data = {}
  try {
    data = event.data ? event.data.json() : {}
  } catch {
    data = {}
  }
  const title = typeof data.title === "string" && data.title ? data.title.slice(0, 200) : "Cobe News"
  // one notification per story: a second message about it (another tab, a retry) replaces it silently
  const tag = typeof data.id === "string" && data.id ? data.id.slice(0, 100) : undefined
  const kind = typeof data.kind === "string" ? data.kind.slice(0, 20) : "story"
  event.waitUntil(
    self.registration
      .showNotification(title, {
        body: typeof data.body === "string" ? data.body.slice(0, 300) : "",
        tag,
        icon: "/icon-192.png",
        requireInteraction: data.severity === "critical",
        data: { url: safePath(data.url) },
      })
      .then(
        () => report({ type: "cobe-news-shown", kind, tag: tag || "", ok: true }),
        (e) => report({ type: "cobe-news-shown", kind, tag: tag || "", ok: false, error: String((e && (e.message || e.name)) || e).slice(0, 300) }),
      ),
  )
})

self.addEventListener("notificationclick", (event) => {
  event.notification.close()
  const path = safePath(event.notification.data && event.notification.data.url)
  event.waitUntil(
    (async () => {
      const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true })
      const mine = all.filter((c) => new URL(c.url).origin === self.location.origin)
      // the tab in front, else a visible one, else any – it opens the story itself (no reload, no lost state)
      const tab = mine.find((c) => c.focused) || mine.find((c) => c.visibilityState === "visible") || mine[0]
      if (tab) {
        await tab.focus()
        tab.postMessage({ type: "cobe-news-open", url: path })
        return
      }
      await self.clients.openWindow(new URL(path, self.location.origin).href)
    })(),
  )
})
