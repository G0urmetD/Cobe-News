import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import {
  CHECK_AFTER_MS,
  JITTER_MS,
  RETRY_MS,
  STORAGE_KEY,
  SessionSync,
  type SessionTimes,
  type SyncMessage,
  type TransportEnv,
  WARN_MS,
  openTransport,
  parseMessage,
} from "@/lib/session-sync"

const MIN = 60_000

/** The server's side of one session (app/auth/sessions.py): "last active" written at most every touch_s, idle and
 *  absolute end, a look (GET /api/auth/session) that never writes. */
class FakeServer {
  idleMin = 30
  absH = 12
  touchS = 300
  lastSeen = Date.now()
  created = Date.now()
  revoked = false
  peeks = 0
  over(t = Date.now()) {
    return this.revoked || t >= this.lastSeen + this.idleMin * MIN || t >= this.created + this.absH * 60 * MIN
  }
  times(): SessionTimes {
    const t = Date.now()
    return {
      idle_left_s: Math.floor((this.lastSeen + this.idleMin * MIN - t) / 1000),
      absolute_left_s: Math.floor((this.created + this.absH * 60 * MIN - t) / 1000),
      idle_min: this.idleMin,
      touch_s: this.touchS,
    }
  }
  /** a request of the app: true when it reached a live session (and maybe moved "last active") */
  request(t = Date.now()) {
    if (this.over(t)) return false
    if (t - this.lastSeen > this.touchS * 1000) this.lastSeen = t
    return true
  }
  peek = async (): Promise<SessionTimes | "ended" | "unknown"> => {
    this.peeks += 1
    return this.over() ? "ended" : this.times()
  }
}

/** BroadcastChannel between "tabs" of one test: every other channel of the same name gets the message. */
class FakeBus {
  channels = new Set<FakeChannel>()
  Channel = (() => {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const bus = this
    return class extends FakeChannel {
      constructor(name: string) {
        super(bus, name)
      }
    }
  })()
}
class FakeChannel {
  onmessage: ((e: { data: unknown }) => void) | null = null
  bus: FakeBus
  name: string
  constructor(bus: FakeBus, name: string) {
    this.bus = bus
    this.name = name
    bus.channels.add(this)
  }
  postMessage(m: unknown) {
    for (const c of this.bus.channels) if (c !== this && c.name === this.name) c.onmessage?.({ data: structuredClone(m) })
  }
  close() {
    this.bus.channels.delete(this)
  }
}

function tab(server: FakeServer, bus: FakeBus, random = 0) {
  const events = { out: [] as [string, boolean][], signedIn: 0, warnings: [] as boolean[] }
  const sync = new SessionSync({
    peek: () => server.peek(),
    onSignedOut: (reason, elsewhere) => events.out.push([reason, elsewhere]),
    onSignedIn: () => (events.signedIn += 1),
    onWarning: (show) => events.warnings.push(show),
    transport: (on) => openTransport(on, { BroadcastChannel: bus.Channel }),
    random: () => random,
  })
  return { sync, events, request: (t = Date.now()) => server.request(t) && sync.activity(t) }
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date("2026-11-02T08:00:00Z"))
})
afterEach(() => vi.useRealTimers())

describe("SessionSync: the end without a request", () => {
  it("a tab left alone warns two minutes before the idle end, then looks shortly after it and signs out", async () => {
    const server = new FakeServer()
    const a = tab(server, new FakeBus())
    a.sync.start(server.times())
    await vi.advanceTimersByTimeAsync(30 * MIN - WARN_MS - 1000)
    expect(a.events.warnings).toEqual([])
    await vi.advanceTimersByTimeAsync(1000)
    expect(server.peeks).toBe(1) // asked once more before warning
    expect(a.events.warnings).toEqual([true])
    expect(server.lastSeen).toBe(server.created) // looking never kept it alive
    await vi.advanceTimersByTimeAsync(WARN_MS + CHECK_AFTER_MS)
    expect(server.peeks).toBe(2)
    expect(a.events.out).toEqual([["expired", false]])
    expect(a.events.warnings).toEqual([true, false])
    expect(a.sync.signedIn).toBe(false)
    await vi.advanceTimersByTimeAsync(60 * MIN)
    expect(server.peeks).toBe(2) // signed out: no more looks
  })

  it("the absolute end: no warning (a click would not help), signed out shortly after it", async () => {
    const server = new FakeServer()
    server.absH = 1
    server.created = Date.now() - 50 * MIN
    const a = tab(server, new FakeBus())
    a.sync.start(server.times())
    for (let i = 0; i < 9; i++) {
      await vi.advanceTimersByTimeAsync(MIN)
      a.request() // busy all the time – the idle end keeps moving, the absolute one does not
    }
    expect(a.events.out).toEqual([])
    await vi.advanceTimersByTimeAsync(MIN + CHECK_AFTER_MS)
    expect(a.events.warnings).toEqual([])
    expect(a.events.out).toEqual([["expired", false]])
    expect(server.peeks).toBe(1)
  })

  it("a request moves the idle end like the server does (at most every touch_s) – no look needed", async () => {
    const server = new FakeServer()
    const a = tab(server, new FakeBus())
    a.sync.start(server.times())
    const end0 = a.sync.ends!.idleEnd
    await vi.advanceTimersByTimeAsync(2 * MIN)
    a.request() // within touch_s: the server keeps "last active", so does the tab
    expect(a.sync.ends!.idleEnd).toBe(end0)
    await vi.advanceTimersByTimeAsync(4 * MIN)
    a.request()
    expect(a.sync.ends!.idleEnd).toBe(Date.now() + 30 * MIN)
    expect(a.sync.ends!.idleEnd).toBe(server.lastSeen + 30 * MIN)
    await vi.advanceTimersByTimeAsync(25 * MIN) // past the first end: still signed in, nothing asked
    expect(a.events.out).toEqual([])
    expect(server.peeks).toBe(0)
  })

  it("no answer (offline): never signed out for it – asked again later", async () => {
    const server = new FakeServer()
    const a = tab(server, new FakeBus())
    a.sync.start(server.times())
    const peek = vi.spyOn(server, "peek").mockResolvedValue("unknown")
    await vi.advanceTimersByTimeAsync(30 * MIN + CHECK_AFTER_MS)
    expect(a.events.out).toEqual([])
    expect(a.events.warnings).toEqual([true]) // the warning all the same, by the times known
    peek.mockRestore()
    await vi.advanceTimersByTimeAsync(RETRY_MS)
    expect(a.events.out).toEqual([["expired", false]])
  })

  it("shown again: looks at once (revoked meanwhile), at most every 30 s", async () => {
    const server = new FakeServer()
    const a = tab(server, new FakeBus())
    a.sync.start(server.times())
    a.sync.visible()
    expect(server.peeks).toBe(0) // just answered
    await vi.advanceTimersByTimeAsync(5 * MIN)
    server.revoked = true
    a.sync.visible()
    await vi.advanceTimersByTimeAsync(0)
    expect(server.peeks).toBe(1)
    expect(a.events.out).toEqual([["expired", false]])
  })

  it("started without times (a sign-in just finished): it asks", async () => {
    const server = new FakeServer()
    const a = tab(server, new FakeBus())
    a.sync.start()
    await vi.advanceTimersByTimeAsync(0)
    expect(server.peeks).toBe(1)
    expect(a.sync.ends!.idleEnd).toBe(Date.now() + 30 * MIN)
  })
})

describe("SessionSync: all tabs together", () => {
  it("signed out in one tab (the menu): every other tab signs out too, without telling anybody again", () => {
    const server = new FakeServer()
    const bus = new FakeBus()
    const [a, b, c] = [tab(server, bus), tab(server, bus), tab(server, bus)]
    for (const x of [a, b, c]) x.sync.start(server.times())
    a.sync.signOut("logout")
    expect(a.events.out).toEqual([["logout", false]])
    expect(b.events.out).toEqual([["logout", true]])
    expect(c.events.out).toEqual([["logout", true]])
    expect([a, b, c].map((x) => x.sync.signedIn)).toEqual([false, false, false])
  })

  it("one tab finds the session over: the others go too – and only one of them asked", async () => {
    const server = new FakeServer()
    const bus = new FakeBus()
    const a = tab(server, bus, 0)
    const b = tab(server, bus, 1) // its look would come up to JITTER_MS later
    a.sync.start(server.times())
    b.sync.start(server.times())
    a.sync.dismissWarning()
    await vi.advanceTimersByTimeAsync(30 * MIN + CHECK_AFTER_MS + JITTER_MS)
    expect(a.events.out).toEqual([["expired", false]])
    expect(b.events.out).toEqual([["expired", true]])
    expect(server.peeks).toBe(2) // the warning's look (one tab, the other adopted its answer) and the end's
  })

  it("a request in another tab moves the end in every tab", async () => {
    const server = new FakeServer()
    const bus = new FakeBus()
    const a = tab(server, bus)
    const b = tab(server, bus)
    a.sync.start(server.times())
    b.sync.start(server.times())
    await vi.advanceTimersByTimeAsync(20 * MIN)
    a.request()
    expect(b.sync.ends!.idleEnd).toBe(Date.now() + 30 * MIN)
    await vi.advanceTimersByTimeAsync(20 * MIN) // past the old end
    expect(b.events.out).toEqual([])
    expect(server.peeks).toBe(0)
  })

  it("the warning: closed in one tab, closed in all; a request (stay signed in) takes it away everywhere", async () => {
    const server = new FakeServer()
    const bus = new FakeBus()
    const a = tab(server, bus)
    const b = tab(server, bus)
    a.sync.start(server.times())
    b.sync.start(server.times())
    await vi.advanceTimersByTimeAsync(30 * MIN - WARN_MS)
    expect(a.events.warnings).toEqual([true])
    expect(b.events.warnings).toEqual([true])
    b.sync.dismissWarning()
    expect(a.events.warnings).toEqual([true, false])
    await vi.advanceTimersByTimeAsync(30_000)
    expect(a.events.warnings).toEqual([true, false]) // not again for the same end
    // the next idle period warns again; "stay signed in" there (a request) ends it in both tabs
    a.request()
    await vi.advanceTimersByTimeAsync(30 * MIN - WARN_MS)
    expect(a.events.warnings).toEqual([true, false, true])
    expect(b.events.warnings).toEqual([true, true])
    a.request()
    expect(a.events.warnings).toEqual([true, false, true, false])
    expect(b.events.warnings).toEqual([true, true, false])
    expect(a.events.out).toEqual([])
  })

  it("signed in in one tab: a tab on the sign-in page loads its state again; a signed-in tab does nothing", () => {
    const server = new FakeServer()
    const bus = new FakeBus()
    const a = tab(server, bus)
    const b = tab(server, bus)
    const c = tab(server, bus)
    c.sync.start(server.times())
    expect(a.events.signedIn).toBe(1)
    a.sync.start(server.times())
    expect(b.events.signedIn).toBe(2)
    expect(c.events.signedIn).toBe(0)
  })

  it("a signed-out tab ignores the others' sign-out and times", () => {
    const server = new FakeServer()
    const bus = new FakeBus()
    const a = tab(server, bus)
    const b = tab(server, bus)
    a.sync.start(server.times())
    a.sync.signOut("expired")
    expect(b.events.out).toEqual([])
    expect(b.sync.ends).toBeNull()
  })
})

describe("transport", () => {
  it("without BroadcastChannel: one localStorage key and its storage event – the event and times only", () => {
    const listeners = new Map<string, Set<(e: StorageEvent) => void>>()
    const stored = new Map<string, string>()
    // two tabs: the storage event reaches every tab but the writing one
    const tabEnv = (name: string): TransportEnv => ({
      storage: {
        setItem: (k, v) => {
          stored.set(k, v)
          for (const [other, ls] of listeners) if (other !== name) for (const l of ls) l({ key: k, newValue: v } as StorageEvent)
        },
      },
      target: {
        addEventListener: (_t, l) => listeners.set(name, (listeners.get(name) ?? new Set()).add(l)),
        removeEventListener: (_t, l) => listeners.get(name)?.delete(l),
      },
    })
    const gotA: SyncMessage[] = []
    const gotB: SyncMessage[] = []
    const a = openTransport((m) => gotA.push(m), tabEnv("a"))
    const b = openTransport((m) => gotB.push(m), tabEnv("b"))
    a.post({ type: "signed-out", reason: "logout", at: 1 })
    a.post({ type: "signed-out", reason: "logout", at: 1 }) // the same twice: still an event
    expect(gotB).toEqual([
      { type: "signed-out", reason: "logout", at: 1 },
      { type: "signed-out", reason: "logout", at: 1 },
    ])
    expect(gotA).toEqual([])
    expect(Object.keys(JSON.parse(stored.get(STORAGE_KEY)!)).sort()).toEqual(["at", "n", "reason", "type"])
    // other keys and foreign values are not messages
    for (const l of listeners.get("b")!) {
      l({ key: "other", newValue: '{"type":"signed-out","reason":"logout","at":1}' } as StorageEvent)
      l({ key: STORAGE_KEY, newValue: "not json" } as StorageEvent)
      l({ key: STORAGE_KEY, newValue: null } as StorageEvent)
    }
    expect(gotB).toHaveLength(2)
    b.close()
    a.post({ type: "signed-in", at: 2 })
    expect(gotB).toHaveLength(2)
  })

  it("two tabs over the storage event sign out together", () => {
    const tabs: ((e: StorageEvent) => void)[] = []
    const env = (): TransportEnv => {
      const me: { l?: (e: StorageEvent) => void } = {}
      return {
        storage: { setItem: (k, v) => tabs.filter((l) => l !== me.l).forEach((l) => l({ key: k, newValue: v } as StorageEvent)) },
        target: { addEventListener: (_t, l) => tabs.push((me.l = l)), removeEventListener: () => undefined },
      }
    }
    const server = new FakeServer()
    const out: string[] = []
    const mk = (name: string) =>
      new SessionSync({
        peek: server.peek,
        onSignedOut: (r, e) => out.push(`${name}:${r}:${e}`),
        onSignedIn: () => undefined,
        onWarning: () => undefined,
        transport: (on) => openTransport(on, env()),
      })
    const a = mk("a")
    const b = mk("b")
    a.start(server.times())
    b.start(server.times())
    b.signOut("expired")
    expect(out.sort()).toEqual(["a:expired:true", "b:expired:false"])
  })

  it("parseMessage keeps only known messages", () => {
    expect(parseMessage({ type: "signed-out", reason: "logout", at: 5 })).toEqual({ type: "signed-out", reason: "logout", at: 5 })
    expect(parseMessage({ type: "signed-out", reason: "x", at: 5 })).toBeNull()
    expect(parseMessage({ type: "activity", at: "5" })).toBeNull()
    expect(parseMessage({ type: "status", at: 5, idleEnd: 1, absEnd: 2, idleMs: 3 })).toBeNull()
    expect(parseMessage({ type: "signed-in", at: 5, token: "secret" })).toEqual({ type: "signed-in", at: 5 }) // nothing else is carried
    expect(parseMessage(null)).toBeNull()
    expect(parseMessage("signed-out")).toBeNull()
  })
})
