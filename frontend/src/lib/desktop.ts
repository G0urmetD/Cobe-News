import { useEffect, useRef, useState, useSyncExternalStore } from "react"
import i18n from "@/i18n"
import { api } from "@/lib/api"
import type { DesktopPrefs, NewsItem } from "@/lib/news-api"
import { pushActiveHere, syncPush } from "@/lib/push"

/**
 * Desktop notifications while Cobe News is open in a tab – also in a background tab, a minimised window or behind
 * another app (Notification API). With every tab closed: Web Push (push.ts, optional).
 *
 * Every open tab keeps its own timer; whichever tab's timer fires first after a minute asks /api/news/recent (a short
 * Web Lock around the request and the "shown" list, never held between rounds) – so a tab the browser froze or
 * discarded never blocks the others, and a hidden tab whose timers Chrome throttles to once a minute still asks.
 * Coming back (visible, focus, online, resumed from freezing or the back/forward cache) asks at once. The cursor is the
 * server's arrival number: nothing is lost, nothing shown twice, also across tabs, reloads and restored tabs.
 */

export const POLL_MS = 60_000
const CATCH_UP_MS = 10_000 // a "came back" round at most this often
const STALE_MS = 3 * POLL_MS // the lock held this long (a tab frozen mid-round): taken over
const SYNC_PUSH_MS = 10 * 60_000
const SEEN_MAX = 500

export const desktopSupported = () => typeof window !== "undefined" && "Notification" in window
export const desktopSecure = () => typeof window !== "undefined" && window.isSecureContext

const cursorKey = (userId: string) => `cobe-news.desktop.seq.${userId}`
const seenKey = (userId: string) => `cobe-news.desktop.seen.${userId}`
export const lastKey = (userId: string) => `cobe-news.desktop.last.${userId}`
const lockName = (userId: string) => `cobe-news-desktop-${userId}`

function read(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

function write(key: string, value: string) {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* private mode */
  }
}

/** The last round of any tab of this browser: when, and whether the server answered. */
export interface LastRound {
  at: number
  ok: boolean
}

export function readLast(userId: string): LastRound {
  try {
    const v = JSON.parse(read(lastKey(userId)) ?? "null") as LastRound | null
    return v && typeof v.at === "number" ? v : { at: 0, ok: true }
  } catch {
    return { at: 0, ok: true }
  }
}

/** Marks a story as shown – false when another tab showed it already. */
function claim(userId: string, id: string): boolean {
  let seen: string[] = []
  try {
    seen = JSON.parse(read(seenKey(userId)) ?? "[]") as string[]
  } catch {
    seen = []
  }
  if (seen.includes(id)) return false
  write(seenKey(userId), JSON.stringify([...seen, id].slice(-SEEN_MAX)))
  return true
}

/** What became of one notification: handed to the system, refused by the browser (with its reason), or no answer. */
export type ShowOutcome = { ok: true; via: "worker" | "page" } | { ok: false; error: string } | { ok: null }

const errText = (e: unknown) => (e instanceof Error ? e.message || e.name : String(e)).slice(0, 300)

/** Shows one notification – through the service worker when there is one (its click works with this tab gone, and on
 * Android the constructor is refused), else in the page. `path`: where a click leads. `track`: wait for the page's
 * notification to say shown or failed (the test in the settings) – real rounds do not wait for it. */
async function notify(title: string, options: { body: string; tag: string; critical: boolean; path: string }, onClick: () => void, track = false): Promise<ShowOutcome> {
  const opts: NotificationOptions = { body: options.body, tag: options.tag, icon: "/icon-192.png", requireInteraction: options.critical }
  let reg: ServiceWorkerRegistration | undefined
  try {
    reg = "serviceWorker" in navigator ? await navigator.serviceWorker.getRegistration("/") : undefined
  } catch {
    reg = undefined // no worker after all – in the page
  }
  if (reg?.active) {
    try {
      await reg.showNotification(title, { ...opts, data: { url: options.path } })
      return { ok: true, via: "worker" }
    } catch (e) {
      // refused by the worker's way – the page's own way is tried, the reason kept for when that fails too
      const first = errText(e)
      const second = await inPage(title, opts, onClick, track)
      return second.ok === false ? { ok: false, error: `${first} / ${second.error}` } : second
    }
  }
  return inPage(title, opts, onClick, track)
}

function inPage(title: string, opts: NotificationOptions, onClick: () => void, track: boolean): Promise<ShowOutcome> {
  let n: Notification
  try {
    n = new Notification(title, opts)
  } catch (e) {
    return Promise.resolve({ ok: false, error: errText(e) }) // not allowed here – the list shows it
  }
  n.onclick = () => {
    window.focus()
    onClick()
    n.close()
  }
  if (!track) return Promise.resolve({ ok: true, via: "page" })
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ ok: null }), TRACK_MS)
    n.onshow = () => {
      clearTimeout(timer)
      resolve({ ok: true, via: "page" })
    }
    n.onerror = () => {
      clearTimeout(timer)
      resolve({ ok: false, error: "error" })
    }
  })
}

/** How long the test waits for the browser to answer (the page's notification; a push: from the moment the server
 * handed it to the push service). */
export const TRACK_MS = 20_000

export function showStory(item: Pick<NewsItem, "id" | "title" | "severity" | "source">, open: (id: string) => void, track = false) {
  return notify(
    item.title,
    {
      body: `${i18n.t(`news.sev.${item.severity}`)} · ${item.source.name}`,
      tag: item.id, // the system shows one notification per story, even if two tabs fire
      critical: item.severity === "critical",
      path: `/?story=${encodeURIComponent(item.id)}`,
    },
    () => open(item.id),
    track,
  )
}

/** The service worker's word on a push (sw.js report()): shown, or refused with the browser's reason. */
export interface ShownMessage {
  type: "cobe-news-shown"
  kind: string
  tag: string
  ok: boolean
  error?: string
}

export function isShownMessage(d: unknown): d is ShownMessage {
  const m = d as Partial<ShownMessage> | null
  return !!m && m.type === "cobe-news-shown" && typeof m.kind === "string" && typeof m.ok === "boolean"
}

/**
 * Waits for the service worker to report a push of this kind (BroadcastChannel; the worker's postMessage where there is
 * none). Resolves with the report, or null after `ms`. `stop()` gives up early (the settings closed).
 */
export function waitForShown(kind: string, ms = TRACK_MS): { done: Promise<ShowOutcome>; stop: () => void } {
  let stop = () => undefined as void
  const done = new Promise<ShowOutcome>((resolve) => {
    const ch = typeof BroadcastChannel === "function" ? new BroadcastChannel("cobe-news-notify") : null
    const sw = typeof navigator !== "undefined" && "serviceWorker" in navigator ? navigator.serviceWorker : null
    const finish = (o: ShowOutcome) => {
      clearTimeout(timer)
      ch?.close()
      sw?.removeEventListener("message", onMessage)
      resolve(o)
    }
    const onMessage = (e: MessageEvent) => {
      if (isShownMessage(e.data) && e.data.kind === kind) finish(e.data.ok ? { ok: true, via: "worker" } : { ok: false, error: e.data.error || "error" })
    }
    const timer = setTimeout(() => finish({ ok: null }), ms)
    if (ch) ch.onmessage = onMessage
    sw?.addEventListener("message", onMessage)
    stop = () => finish({ ok: null })
  })
  return { done, stop: () => stop() }
}

/** Which system and browser this is – for the hint where to allow notifications (pure, tested). */
export function systemOf(ua: string, platform: string, brands: string[] = []): { os: "mac" | "windows" | "other"; browser: string } {
  const p = `${platform} ${ua}`
  const os = /mac|iphone|ipad/i.test(p) ? "mac" : /win/i.test(p) ? "windows" : "other"
  const brand = brands.find((b) => /edge/i.test(b)) ? "Microsoft Edge" : brands.find((b) => /google chrome/i.test(b)) ? "Google Chrome" : null
  const browser =
    brand ??
    (/Edg\//.test(ua)
      ? "Microsoft Edge"
      : /Firefox\//.test(ua)
        ? "Firefox"
        : /OPR\//.test(ua)
          ? "Opera"
          : /Chrome\//.test(ua)
            ? "Google Chrome"
            : /Safari\//.test(ua)
              ? "Safari"
              : "")
  return { os, browser }
}

export function currentSystem() {
  if (typeof navigator === "undefined") return systemOf("", "")
  const uad = (navigator as Navigator & { userAgentData?: { platform?: string; brands?: { brand: string }[] } }).userAgentData
  return systemOf(navigator.userAgent, uad?.platform || navigator.platform || "", uad?.brands?.map((b) => b.brand) ?? [])
}

/** At most this many single notifications per round – more become one summary ("N neue Meldungen"). */
export const DESKTOP_MAX = 3

/**
 * Which stories of one round get a notification of their own (oldest of them first), and how many more there are for
 * the summary. `claim` marks one as shown (false: another tab showed it already). Pure – desktop.test.ts checks it.
 */
export function planNotifications(items: NewsItem[], total: number, claim: (id: string) => boolean): { single: NewsItem[]; more: number } {
  const fresh = items.filter((i) => claim(i.id))
  const single = fresh.slice(0, DESKTOP_MAX).reverse()
  // the server counts everything that arrived (it lists only the newest few) – minus what another tab showed already
  const more = Math.max(0, total - (items.length - fresh.length) - single.length)
  return { single, more }
}

function showSummary(count: number, open: () => void) {
  return notify(i18n.t("desktop.summaryTitle", { count }), { body: i18n.t("desktop.summaryText"), tag: `cobe-news-summary-${Date.now()}`, critical: false, path: "/" }, open)
}

/** One round: what arrived since the cursor. With push working in this browser the push messages show it – the round
 * only moves the cursor (switching push off later brings no backlog). */
export async function poll(userId: string, open: (id: string | null) => void): Promise<void> {
  const raw = read(cursorKey(userId))
  const after = raw !== null && /^\d+$/.test(raw) ? raw : null
  // the person's choice (severities, sources) is applied by the server – the count then is exactly what is new for them
  // a background request: the rounds of an open tab do not keep the session alive (lib/poll.ts)
  const res = await api.get<{ items: NewsItem[]; total: number; cursor: number }>(`/api/news/recent?mine=true${after !== null ? `&after=${after}` : ""}`, {
    background: true,
  })
  write(cursorKey(userId), String(res.cursor))
  if (after === null || pushActiveHere(userId)) return
  const { single, more } = planNotifications(res.items, res.total ?? res.items.length, (id) => claim(userId, id))
  for (const item of single) await showStory(item, open)
  if (more > 0) await showSummary(more, () => open(null))
}

type Locks = { request: (name: string, options: { ifAvailable?: boolean; steal?: boolean }, cb: (lock: unknown) => Promise<void> | void) => Promise<void> }

/**
 * One tab's turn: only when no tab asked within the last minute (or, `catchUp`, the last 10 s). The lock makes reading
 * the cursor, asking and marking "shown" one step across tabs; a tab that would have to wait for it skips the round.
 */
export async function tick(userId: string, open: (id: string | null) => void, catchUp = false, now: () => number = Date.now): Promise<boolean> {
  const due = () => now() - readLast(userId).at >= (catchUp ? CATCH_UP_MS : POLL_MS - 2_000)
  if (!due()) return false
  const run = async () => {
    if (!due()) return false // another tab was faster
    write(lastKey(userId), JSON.stringify({ at: now(), ok: true }))
    try {
      await poll(userId, open)
    } catch {
      write(lastKey(userId), JSON.stringify({ at: now(), ok: false })) // offline or signed out – next round
    }
    return true
  }
  const locks = (typeof navigator !== "undefined" ? (navigator as Navigator & { locks?: Locks }).locks : undefined) ?? null
  if (!locks?.request) return run()
  let ran = false
  const stale = now() - readLast(userId).at > STALE_MS
  await locks.request(lockName(userId), stale ? { steal: true } : { ifAvailable: true }, async (lock) => {
    if (lock) ran = await run()
  })
  return ran
}

/**
 * Runs in every tab of a signed-in person. Its effect depends only on primitives (user, on/off and the chosen severities
 * and sources as a text) – the open() callback lives in a ref, so navigating never restarts the timer.
 */
export function useDesktopNotifications(userId: string | undefined, prefs: DesktopPrefs | undefined, open: (id: string | null) => void) {
  const permission = useNotificationPermission()
  const on = !!userId && !!prefs?.enabled && desktopSupported() && permission === "granted"
  const openRef = useRef(open)
  useEffect(() => {
    openRef.current = open
  }, [open])
  const choice = prefs ? `${prefs.severities.join(",")}|${prefs.sources.join(",")}` : ""
  useEffect(() => {
    if (!on || !userId) return
    let stopped = false
    let timer: ReturnType<typeof setTimeout> | undefined
    let lastSync = 0
    const go = (catchUp: boolean) => {
      if (stopped) return
      if (Date.now() - lastSync > SYNC_PUSH_MS) {
        lastSync = Date.now()
        void syncPush(userId, i18n.language)
      }
      void tick(userId, (id) => openRef.current(id), catchUp)
    }
    const loop = () => {
      go(false)
      // every half minute a look whether a round is due; a little spread, so tabs do not fire in the same millisecond
      timer = setTimeout(loop, POLL_MS / 2 + Math.random() * 2_000)
    }
    const back = () => go(true)
    const visible = () => document.visibilityState === "visible" && back()
    timer = setTimeout(loop, 1_000)
    document.addEventListener("visibilitychange", visible)
    document.addEventListener("resume", back) // Chrome: the tab was frozen
    window.addEventListener("focus", back)
    window.addEventListener("online", back)
    window.addEventListener("pageshow", back) // back/forward cache
    return () => {
      stopped = true
      clearTimeout(timer)
      document.removeEventListener("visibilitychange", visible)
      document.removeEventListener("resume", back)
      window.removeEventListener("focus", back)
      window.removeEventListener("online", back)
      window.removeEventListener("pageshow", back)
    }
  }, [on, userId, choice])
}

// ---------------------------------------------------------------- state for the settings

function currentPermission(): NotificationPermission | "unsupported" {
  return desktopSupported() ? Notification.permission : "unsupported"
}

/** The browser's permission, kept current: granted in the settings, in the address bar or in another tab. */
export function useNotificationPermission(): NotificationPermission | "unsupported" {
  const [perm, setPerm] = useState(currentPermission)
  useEffect(() => {
    const check = () => setPerm(currentPermission())
    let status: PermissionStatus | null = null
    navigator.permissions
      ?.query({ name: "notifications" })
      .then((s) => {
        status = s
        s.onchange = check
      })
      .catch(() => undefined)
    window.addEventListener("focus", check)
    document.addEventListener("visibilitychange", check)
    const id = setInterval(check, 5_000)
    return () => {
      if (status) status.onchange = null
      window.removeEventListener("focus", check)
      document.removeEventListener("visibilitychange", check)
      clearInterval(id)
    }
  }, [])
  return perm
}

function subscribeRounds(cb: () => void) {
  window.addEventListener("storage", cb)
  const id = setInterval(cb, 5_000)
  return () => {
    window.removeEventListener("storage", cb)
    clearInterval(id)
  }
}

/** The last round of any tab of this browser – updates when another tab writes it. */
export function useLastRound(userId: string | undefined): LastRound | null {
  const raw = useSyncExternalStore(subscribeRounds, () => (userId ? read(lastKey(userId)) : null))
  if (!userId || !raw) return null
  return readLast(userId)
}
