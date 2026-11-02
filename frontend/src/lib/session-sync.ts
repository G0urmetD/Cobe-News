/**
 * All open tabs of this browser sign out together (lib/auth.tsx holds one SessionSync, session-sync.test.ts checks it).
 *
 * - A message to the other tabs: signed out (a sign-out here, or the session found over), signed in, a request that
 *   moved "last active", the session's times, the warning closed. BroadcastChannel, else a localStorage key (its
 *   "storage" event) – only the event and times, never a token or anything about the person.
 * - The end without a request: the server tells the times left (GET /api/auth/session, /api/auth/state – seconds, so
 *   no clock of this computer is involved); every tab knows the requests of all of them and moves the idle end the way
 *   the server does (it writes "last active" at most every `touch_s`). Shortly after the end a tab looks – the look
 *   itself never extends the session – and once it is over every tab goes to the sign-in, its data dropped.
 * - Two minutes before the idle end: a warning with "stay signed in" (closed in one tab, closed in all).
 */

export type SignOutReason = "logout" | "expired"

/** What GET /api/auth/session (and /api/auth/state for an active session) answers. */
export interface SessionTimes {
  idle_left_s: number
  absolute_left_s: number
  idle_min: number
  touch_s: number
}

/** Times on this computer's clock (ms) – the same for all its tabs. */
interface Times {
  idleEnd: number
  absEnd: number
  idleMs: number
  touchMs: number
}

export type SyncMessage =
  | { type: "signed-out"; reason: SignOutReason; at: number }
  | { type: "signed-in"; at: number }
  | { type: "activity"; at: number }
  | ({ type: "status"; at: number } & Times)
  | { type: "warning-dismissed"; at: number }

export interface Transport {
  post: (m: SyncMessage) => void
  close: () => void
}

export const CHANNEL = "cobe-news-auth"
export const STORAGE_KEY = "cobe-news.auth-sync"

export const WARN_MS = 2 * 60_000 // the warning this long before the idle end
export const CHECK_AFTER_MS = 1500 // a look this long after the end (the server's own clock, a slow answer)
export const JITTER_MS = 2000 // … plus up to this (the warning too): one tab looks, the others hear its answer
export const FRESH_MS = 10_000 // times this recent are trusted without asking again
export const VISIBLE_MIN_MS = 30_000 // a tab shown again looks at most this often (it may have been revoked meanwhile)
export const RETRY_MS = 30_000 // no answer (offline, server busy): try again – never signed out for it
const MAX_DELAY_MS = 60 * 60_000 // setTimeout's limit is ~24 days; an absolute lifetime can be longer
const SAME_END_MS = 30_000 // two idle ends this close are the same period (a "last active" write moves it ≥ 1 min)

const num = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v)

/** A message from another tab – anything else (another version, a stray key) is ignored. */
export function parseMessage(x: unknown): SyncMessage | null {
  if (!x || typeof x !== "object") return null
  const m = x as Record<string, unknown>
  if (!num(m.at)) return null
  switch (m.type) {
    case "signed-out":
      return m.reason === "logout" || m.reason === "expired" ? { type: "signed-out", reason: m.reason, at: m.at } : null
    case "signed-in":
    case "activity":
    case "warning-dismissed":
      return { type: m.type, at: m.at }
    case "status":
      return num(m.idleEnd) && num(m.absEnd) && num(m.idleMs) && num(m.touchMs)
        ? { type: "status", at: m.at, idleEnd: m.idleEnd, absEnd: m.absEnd, idleMs: m.idleMs, touchMs: m.touchMs }
        : null
    default:
      return null
  }
}

type ChannelLike = { postMessage: (m: unknown) => void; close: () => void; onmessage: ((e: { data: unknown }) => void) | null }
type StorageLike = Pick<Storage, "setItem">
type EventTargetLike = { addEventListener: (t: "storage", l: (e: StorageEvent) => void) => void; removeEventListener: (t: "storage", l: (e: StorageEvent) => void) => void }

export interface TransportEnv {
  BroadcastChannel?: new (name: string) => ChannelLike
  storage?: StorageLike | null
  target?: EventTargetLike | null
}

function defaultEnv(): TransportEnv {
  let storage: StorageLike | null = null
  try {
    storage = typeof localStorage === "undefined" ? null : localStorage
  } catch {
    /* blocked */
  }
  return {
    BroadcastChannel: typeof BroadcastChannel === "undefined" ? undefined : (BroadcastChannel as unknown as TransportEnv["BroadcastChannel"]),
    storage,
    target: typeof window === "undefined" ? null : window,
  }
}

/** BroadcastChannel – or, in a browser without it, the "storage" event of one localStorage key (the other tabs get it). */
export function openTransport(onMessage: (m: SyncMessage) => void, env: TransportEnv = defaultEnv()): Transport {
  if (env.BroadcastChannel) {
    try {
      const ch = new env.BroadcastChannel(CHANNEL)
      ch.onmessage = (e) => {
        const m = parseMessage(e.data)
        if (m) onMessage(m)
      }
      return { post: (m) => ch.postMessage(m), close: () => ch.close() }
    } catch {
      /* falls back to the storage event */
    }
  }
  const { storage, target } = env
  const onStorage = (e: StorageEvent) => {
    if (e.key !== STORAGE_KEY || !e.newValue) return
    try {
      const m = parseMessage(JSON.parse(e.newValue))
      if (m) onMessage(m)
    } catch {
      /* not ours */
    }
  }
  target?.addEventListener("storage", onStorage)
  let n = 0
  return {
    post: (m) => {
      try {
        // the same value twice is no change (no event): a counter makes every message new
        storage?.setItem(STORAGE_KEY, JSON.stringify({ ...m, n: ++n }))
      } catch {
        /* private mode, full: the other tabs notice with their next request */
      }
    },
    close: () => target?.removeEventListener("storage", onStorage),
  }
}

export interface SyncDeps {
  /** GET /api/auth/session: the times, "ended" (401) or "unknown" (no answer – nothing is concluded from it) */
  peek: () => Promise<SessionTimes | "ended" | "unknown">
  /** this tab signs out – `elsewhere`: another tab said so (nothing to tell the server or the others) */
  onSignedOut: (reason: SignOutReason, elsewhere: boolean) => void
  /** another tab signed in: this one loads the sign-in state again (it shares the cookie) */
  onSignedIn: () => void
  /** the warning before the idle end: show it (with the end), or take it away */
  onWarning: (show: boolean, idleEnd: number) => void
  transport?: (onMessage: (m: SyncMessage) => void) => Transport
  now?: () => number
  random?: () => number
}

export class SessionSync {
  private readonly d: SyncDeps
  private readonly t: Transport
  private readonly now: () => number
  private readonly random: () => number
  private active = false
  private times: Times | null = null
  private statusAt = 0
  private timer: ReturnType<typeof setTimeout> | undefined
  private warned = false
  private dismissedEnd: number | null = null
  private peeking: Promise<void> | null = null

  constructor(d: SyncDeps) {
    this.d = d
    this.now = d.now ?? Date.now
    this.random = d.random ?? Math.random
    this.t = (d.transport ?? openTransport)((m) => this.receive(m))
  }

  get signedIn() {
    return this.active
  }

  /** The idle end, the absolute end – while signed in and known (for tests and the warning). */
  get ends(): { idleEnd: number; absEnd: number } | null {
    return this.times ? { idleEnd: this.times.idleEnd, absEnd: this.times.absEnd } : null
  }

  /** Signed in (the page loaded with a session, or a sign-in finished): with the times of /api/auth/state, else it asks. */
  start(times?: SessionTimes) {
    if (!this.active) {
      this.active = true
      this.post({ type: "signed-in", at: this.now() })
    }
    if (times) this.adopt(fromServer(times, this.now()), true)
    else void this.check()
  }

  /** This tab signed out (the menu) or found the session over (a 401): every other tab too. */
  signOut(reason: SignOutReason) {
    const was = this.active
    this.stop()
    this.post({ type: "signed-out", reason, at: this.now() })
    if (was) this.d.onSignedOut(reason, false)
  }

  /** A request of this tab reached the server (lib/api.ts) – sent at `at`. */
  activity(at: number) {
    if (this.touch(at)) {
      this.post({ type: "activity", at })
      this.schedule()
    }
  }

  /** The tab is shown again: timers may have slept (a closed laptop), the session may have been ended meanwhile. */
  visible() {
    if (!this.active) return
    if (this.now() - this.statusAt < VISIBLE_MIN_MS) this.schedule()
    else void this.check()
  }

  /** The warning closed here (its close button, "stay signed in") – closed in every tab, for this idle end. */
  dismissWarning() {
    if (!this.warned || !this.times) return
    this.warned = false
    this.dismissedEnd = this.times.idleEnd
    this.post({ type: "warning-dismissed", at: this.now() })
  }

  close() {
    this.stop()
    this.t.close()
  }

  // ---------------------------------------------------------------- inside

  private post(m: SyncMessage) {
    try {
      this.t.post(m)
    } catch {
      /* a closed channel */
    }
  }

  /** Signed out here without a word to the others (a state loaded anew without a session). */
  stop() {
    this.active = false
    this.times = null
    this.dismissedEnd = null
    clearTimeout(this.timer)
    this.timer = undefined
    this.hideWarning()
  }

  private hideWarning() {
    if (!this.warned) return
    this.warned = false
    this.d.onWarning(false, this.times?.idleEnd ?? 0)
  }

  private receive(m: SyncMessage) {
    switch (m.type) {
      case "signed-out":
        if (!this.active) return
        this.stop()
        this.d.onSignedOut(m.reason, true)
        return
      case "signed-in":
        if (!this.active) this.d.onSignedIn()
        return
      case "activity":
        if (this.active && this.touch(m.at)) this.schedule()
        return
      case "status":
        if (this.active && m.at > this.statusAt) this.adopt({ idleEnd: m.idleEnd, absEnd: m.absEnd, idleMs: m.idleMs, touchMs: m.touchMs }, false, m.at)
        return
      case "warning-dismissed":
        if (!this.active || !this.times) return
        this.dismissedEnd = this.times.idleEnd
        this.hideWarning()
        this.schedule()
        return
    }
  }

  /** What the server does with a request at `at`: "last active" written when the last write is older than touch_s. */
  private touch(at: number): boolean {
    const x = this.times
    if (!this.active || !x) return false
    if (at - (x.idleEnd - x.idleMs) <= x.touchMs) return false
    x.idleEnd = at + x.idleMs
    return true
  }

  private adopt(times: Times, tell: boolean, at = this.now()) {
    this.times = times
    this.statusAt = at
    if (tell) this.post({ type: "status", at, ...times })
    this.schedule()
  }

  private dismissed(x: Times) {
    return this.dismissedEnd !== null && Math.abs(x.idleEnd - this.dismissedEnd) < SAME_END_MS
  }

  /** One timer: the warning's moment or the look after the end, whichever comes first. */
  private schedule() {
    clearTimeout(this.timer)
    this.timer = undefined
    const x = this.times
    if (!this.active || !x) return
    const now = this.now()
    const warnAt = x.idleEnd - WARN_MS
    // only an idle end can be moved by a click – before the absolute end, a warning would offer nothing
    const warnable = x.idleEnd < x.absEnd && !this.dismissed(x)
    if (this.warned && (now < warnAt || !warnable)) this.hideWarning()
    // the warning's moment, and times just answered (here or in another tab): shown now
    if (warnable && !this.warned && now >= warnAt && now < x.idleEnd && now - this.statusAt < FRESH_MS) {
      this.warned = true
      this.d.onWarning(true, x.idleEnd)
    }
    // the tabs' timers apart by up to JITTER_MS: the first one asks, the others hear its answer
    const jitter = this.random() * JITTER_MS
    let next = Math.min(x.idleEnd, x.absEnd) + CHECK_AFTER_MS + jitter
    if (warnable && !this.warned) next = Math.min(next, warnAt + jitter)
    this.timer = setTimeout(() => this.tick(), Math.min(Math.max(0, next - now), MAX_DELAY_MS))
  }

  private tick() {
    this.timer = undefined
    const x = this.times
    if (!this.active || !x) return
    const now = this.now()
    // the end – or the warning's moment with times of a while ago (an estimate between two answers): asked once more
    const warnDue = x.idleEnd < x.absEnd && !this.dismissed(x) && !this.warned && now >= x.idleEnd - WARN_MS
    if (now >= Math.min(x.idleEnd, x.absEnd) || (warnDue && now - this.statusAt >= FRESH_MS)) return void this.check()
    this.schedule()
  }

  /** The look at the session – one at a time; it never extends it. */
  private check(): Promise<void> {
    if (this.peeking) return this.peeking
    this.peeking = (async () => {
      const r = await this.d.peek().catch(() => "unknown" as const)
      if (!this.active) return
      if (r === "ended") return this.signOut("expired")
      if (r === "unknown") {
        clearTimeout(this.timer)
        this.timer = setTimeout(() => void this.check(), RETRY_MS)
        // no answer: the warning all the same, by the times known
        const x = this.times
        if (x && !this.warned && x.idleEnd < x.absEnd && !this.dismissed(x) && this.now() >= x.idleEnd - WARN_MS && this.now() < x.idleEnd) {
          this.warned = true
          this.d.onWarning(true, x.idleEnd)
        }
        return
      }
      this.adopt(fromServer(r, this.now()), true)
    })().finally(() => {
      this.peeking = null
    })
    return this.peeking
  }
}

function fromServer(s: SessionTimes, now: number): Times {
  return { idleEnd: now + s.idle_left_s * 1000, absEnd: now + s.absolute_left_s * 1000, idleMs: s.idle_min * 60_000, touchMs: s.touch_s * 1000 }
}
