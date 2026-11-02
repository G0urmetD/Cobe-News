import { api } from "@/lib/api"

/**
 * Web Push: desktop notifications with every Cobe News tab closed (backend: webpush.py). Needs a secure context, a
 * service worker (/sw.js) the browser accepts – Chrome refuses it on a certificate the computer does not trust – and the
 * browser vendor's push service. Optional: without it, the open tab (also in the background) still notifies (desktop.ts).
 */

export type PushBlock = "insecure" | "unsupported" | "certificate" | "sw_failed" | "server_off" | "denied"
export type PushAvailability = { ok: true; reg: ServiceWorkerRegistration } | { ok: false; why: PushBlock; detail?: string }

const flagKey = (userId: string) => `cobe-news.push.active.${userId}`

/** This browser has a working push subscription of this person – the tab then leaves showing to push (no doubles). */
export function pushActiveHere(userId: string): boolean {
  try {
    return localStorage.getItem(flagKey(userId)) === "1"
  } catch {
    return false
  }
}

function setActive(userId: string, on: boolean) {
  try {
    if (on) localStorage.setItem(flagKey(userId), "1")
    else localStorage.removeItem(flagKey(userId))
  } catch {
    /* private mode: the tab shows them (doubles are replaced by the tag) */
  }
}

/** The browser's reason, from the error of register(): an untrusted certificate is the usual one. */
export function swErrorReason(e: unknown): PushBlock {
  const text = e instanceof Error ? `${e.name} ${e.message}` : String(e)
  return /ssl|certificate|cert/i.test(text) ? "certificate" : "sw_failed"
}

export function pushApiPresent(): boolean {
  return typeof window !== "undefined" && "serviceWorker" in navigator && "PushManager" in window && "Notification" in window
}

/** Registers /sw.js (it only handles push and clicks) – where that is not possible, why. */
export async function pushAvailability(): Promise<PushAvailability> {
  if (typeof window === "undefined" || !window.isSecureContext) return { ok: false, why: "insecure" }
  if (!pushApiPresent()) return { ok: false, why: "unsupported" }
  try {
    const reg = await navigator.serviceWorker.register("/sw.js", { scope: "/" })
    return { ok: true, reg }
  } catch (e) {
    return { ok: false, why: swErrorReason(e), detail: e instanceof Error ? e.message : String(e) }
  }
}

export interface PushInfo {
  enabled: boolean
  public_key: string | null
  devices: number
}

export interface PushState {
  registered: boolean
  ok?: boolean
  last_ok_at?: string | null
  last_error?: string | null
}

function keyBytes(b64url: string): Uint8Array<ArrayBuffer> {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4)
  const raw = atob((b64url + pad).replace(/-/g, "+").replace(/_/g, "/"))
  const out = new Uint8Array(new ArrayBuffer(raw.length))
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i)
  return out
}

function sameKey(sub: PushSubscription, key: Uint8Array): boolean {
  const have = sub.options?.applicationServerKey
  if (!have) return true // the browser does not tell – assume it is ours
  const a = new Uint8Array(have)
  return a.length === key.length && a.every((x, i) => x === key[i])
}

function body(sub: PushSubscription, lang: string) {
  const json = sub.toJSON()
  return { endpoint: json.endpoint ?? sub.endpoint, keys: { p256dh: json.keys?.p256dh ?? "", auth: json.keys?.auth ?? "" }, lang: lang.slice(0, 2) }
}

/** Switches push on for this browser: permission, subscription at the push service, handed to the server. */
export async function enablePush(userId: string, lang: string): Promise<PushAvailability> {
  const av = await pushAvailability()
  if (!av.ok) return av
  if (Notification.permission === "default") await Notification.requestPermission()
  if (Notification.permission !== "granted") return { ok: false, why: "denied" }
  const info = await api.get<PushInfo>("/api/me/push")
  if (!info.enabled || !info.public_key) return { ok: false, why: "server_off" }
  const key = keyBytes(info.public_key)
  let sub = await av.reg.pushManager.getSubscription()
  if (sub && !sameKey(sub, key)) {
    await sub.unsubscribe() // made for another server key (a restored or new installation)
    sub = null
  }
  sub ??= await av.reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key })
  await api.post("/api/me/push", body(sub, lang))
  setActive(userId, true)
  return av
}

/** Switches push off for this browser (also at sign-out: the next person at this computer gets nothing of mine). */
export async function disablePush(userId: string | undefined): Promise<void> {
  if (userId) setActive(userId, false)
  if (!pushApiPresent()) return
  const reg = await navigator.serviceWorker.getRegistration("/").catch(() => undefined)
  const sub = await reg?.pushManager.getSubscription().catch(() => null)
  if (!sub) return
  try {
    await api.post("/api/me/push/remove", { endpoint: sub.endpoint })
  } finally {
    await sub.unsubscribe().catch(() => false)
  }
}

/** This browser's subscription and what the server knows of it. `background`: the periodic check (syncPush) – not
 *  counted as activity (lib/poll.ts; the server reads this POST as reading, deps.READ_ONLY_POSTS). */
export async function pushHere(background = false): Promise<{ sub: PushSubscription | null; state: PushState }> {
  if (!pushApiPresent() || !window.isSecureContext) return { sub: null, state: { registered: false } }
  const reg = await navigator.serviceWorker.getRegistration("/").catch(() => undefined)
  const sub = (await reg?.pushManager.getSubscription().catch(() => null)) ?? null
  if (!sub) return { sub, state: { registered: false } }
  return { sub, state: await api.post<PushState>("/api/me/push/state", { endpoint: sub.endpoint }, { background }) }
}

/**
 * At start (and now and then): is push of this browser still working? A subscription the server forgot (removed after
 * an error, another person signed in here meanwhile) is handed over again; one that keeps failing leaves showing to
 * the tab again.
 */
export async function syncPush(userId: string, lang: string): Promise<boolean> {
  try {
    const { sub, state } = await pushHere(true)
    if (!sub) {
      setActive(userId, false)
      return false
    }
    if (!state.registered) {
      // ours (this person switched it on here) – or left over from someone else: only taken when this person had it on
      if (!pushActiveHere(userId)) return false
      const info = await api.get<PushInfo>("/api/me/push", { background: true })
      if (!info.enabled || !info.public_key) return false
      // made for an older server key (rotated, or SECRET_KEY changed): subscribed again with the current one
      if (!sameKey(sub, keyBytes(info.public_key))) return (await enablePush(userId, lang)).ok
      await api.post("/api/me/push", body(sub, lang))
      return true
    }
    setActive(userId, state.ok !== false)
    return state.ok !== false
  } catch {
    return pushActiveHere(userId)
  }
}

/** The push service of a subscription ("fcm.googleapis.com") – where the server has to reach out to. */
export function pushHost(endpoint: string): string | null {
  try {
    return new URL(endpoint).host
  } catch {
    return null
  }
}

/** A test message through the push service to this browser – the push service's host when the server handed it over. */
export async function testPush(): Promise<string | undefined> {
  const { sub } = await pushHere()
  if (!sub) throw new Error("no subscription")
  await api.post("/api/me/push/test", { endpoint: sub.endpoint })
  return pushHost(sub.endpoint) ?? undefined
}
