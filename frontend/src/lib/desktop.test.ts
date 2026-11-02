import { describe, expect, it } from "vitest"
import { DESKTOP_MAX, isShownMessage, planNotifications, systemOf } from "@/lib/desktop"
import type { NewsItem } from "@/lib/news-api"

const item = (id: string): NewsItem => ({
  id,
  title: id,
  summary: "",
  url: "",
  source: { id: "s", key: "s", name: "S", logo: false },
  published_at: "2026-10-28T08:00:00Z",
  severity: "high",
  cves: [],
  also_in: [],
  read_at: null,
})

describe("desktop notifications", () => {
  it("shows a few on their own and sums up the rest – none lost", () => {
    // newest first, as the server lists them; 60 arrived, it lists 10
    const items = Array.from({ length: 10 }, (_, n) => item(`s${n}`))
    const { single, more } = planNotifications(items, 60, () => true)
    expect(single.map((i) => i.id)).toEqual(["s2", "s1", "s0"]) // the newest few, oldest of them first
    expect(single).toHaveLength(DESKTOP_MAX)
    expect(more).toBe(57)
  })

  it("leaves out what another tab showed already", () => {
    const shown = new Set(["s0"])
    const { single, more } = planNotifications([item("s0"), item("s1")], 2, (id) => !shown.has(id))
    expect(single.map((i) => i.id)).toEqual(["s1"])
    expect(more).toBe(0)
  })

  it("does nothing on a quiet round", () => {
    expect(planNotifications([], 0, () => true)).toEqual({ single: [], more: 0 })
  })
})

// ---------------------------------------------------------------- rounds across tabs (node: localStorage, Notification and locks as stand-ins)

import { afterEach, beforeEach, vi } from "vitest"
import { api } from "@/lib/api"
import { POLL_MS, lastKey, poll, tick } from "@/lib/desktop"
import { swErrorReason } from "@/lib/push"

const shown: string[] = []
let mem: Map<string, string>

beforeEach(() => {
  mem = new Map()
  shown.length = 0
  Object.defineProperty(globalThis, "localStorage", {
    value: { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v), removeItem: (k: string) => void mem.delete(k) },
    configurable: true,
    writable: true,
  })
  class FakeNotification {
    onclick: (() => void) | null = null
    constructor(title: string) {
      shown.push(title)
    }
    close() {}
  }
  vi.stubGlobal("Notification", FakeNotification)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function server(rounds: { items: NewsItem[]; total: number; cursor: number }[]) {
  const asked: string[] = []
  vi.spyOn(api, "get").mockImplementation(async (path: string) => {
    asked.push(path)
    return (rounds.shift() ?? { items: [], total: 0, cursor: 0 }) as never
  })
  return asked
}

describe("rounds", () => {
  it("a new browser starts at the cursor, then shows what arrived after it – once", async () => {
    const asked = server([
      { items: [], total: 0, cursor: 7 },
      { items: [item("b"), item("a")], total: 2, cursor: 9 },
    ])
    await poll("u", () => undefined)
    expect(shown).toEqual([]) // no backlog
    await poll("u", () => undefined)
    expect(asked[1]).toContain("after=7")
    expect(shown).toEqual(["a", "b"])
    expect(mem.get("cobe-news.desktop.seq.u")).toBe("9")
  })

  it("with push working in this browser the tab only moves the cursor", async () => {
    mem.set("cobe-news.desktop.seq.u", "3")
    mem.set("cobe-news.push.active.u", "1")
    server([{ items: [item("x")], total: 1, cursor: 4 }])
    await poll("u", () => undefined)
    expect(shown).toEqual([])
    expect(mem.get("cobe-news.desktop.seq.u")).toBe("4")
  })

  it("asks once a minute across tabs, sooner when a tab comes back", async () => {
    const asked = server([])
    let t = 1_000_000
    const now = () => t
    expect(await tick("u", () => undefined, false, now)).toBe(true)
    t += 30_000
    expect(await tick("u", () => undefined, false, now)).toBe(false) // another tab asked half a minute ago
    expect(await tick("u", () => undefined, true, now)).toBe(true) // came back: catch up
    t += 5_000
    expect(await tick("u", () => undefined, true, now)).toBe(false) // not more often than every 10 s
    t += POLL_MS
    expect(await tick("u", () => undefined, false, now)).toBe(true)
    expect(asked).toHaveLength(3)
  })

  it("a failed round is noted, the next one tries again", async () => {
    vi.spyOn(api, "get").mockRejectedValue(new Error("offline"))
    await tick(
      "u",
      () => undefined,
      false,
      () => 5_000_000,
    )
    expect(JSON.parse(mem.get(lastKey("u"))!)).toEqual({ at: 5_000_000, ok: false })
  })

  it("a tab holding the lock skips the others; a lock held too long (frozen tab) is taken over", async () => {
    const asked = server([])
    const calls: { ifAvailable?: boolean; steal?: boolean }[] = []
    let held = true
    vi.stubGlobal("navigator", {
      locks: {
        request: async (_n: string, o: { ifAvailable?: boolean; steal?: boolean }, cb: (l: unknown) => Promise<void>) => {
          calls.push(o)
          await cb(held && !o.steal ? null : {})
        },
      },
    })
    mem.set(lastKey("u"), JSON.stringify({ at: 1_000_000, ok: true }))
    expect(
      await tick(
        "u",
        () => undefined,
        false,
        () => 1_000_000 + POLL_MS,
      ),
    ).toBe(false) // the frozen tab has the lock
    expect(calls.at(-1)).toEqual({ ifAvailable: true })
    expect(
      await tick(
        "u",
        () => undefined,
        false,
        () => 1_000_000 + 4 * POLL_MS,
      ),
    ).toBe(true)
    expect(calls.at(-1)).toEqual({ steal: true })
    held = false
    expect(asked).toHaveLength(1)
  })
})

describe("push availability", () => {
  it("tells an untrusted certificate apart from other refusals", () => {
    expect(swErrorReason(new DOMException("Failed to register a ServiceWorker: An SSL certificate error occurred when fetching the script.", "SecurityError"))).toBe("certificate")
    expect(swErrorReason(new TypeError("Failed to register a ServiceWorker: A bad HTTP response code (404) was received"))).toBe("sw_failed")
  })
})

describe("test feedback", () => {
  it("names system and browser for the hint where to allow notifications", () => {
    const mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    expect(systemOf(mac, "MacIntel")).toEqual({ os: "mac", browser: "Google Chrome" })
    expect(systemOf(mac, "macOS", ["Chromium", "Google Chrome", "Not?A_Brand"])).toEqual({ os: "mac", browser: "Google Chrome" })
    const edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"
    expect(systemOf(edge, "Win32")).toEqual({ os: "windows", browser: "Microsoft Edge" })
    expect(systemOf(edge, "Windows", ["Chromium", "Microsoft Edge"])).toEqual({ os: "windows", browser: "Microsoft Edge" })
    expect(systemOf("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0", "Win32")).toEqual({ os: "windows", browser: "Firefox" })
    expect(systemOf("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0", "Linux x86_64")).toEqual({ os: "other", browser: "Firefox" })
  })

  it("takes only the service worker's own reports", () => {
    expect(isShownMessage({ type: "cobe-news-shown", kind: "test", tag: "t", ok: true })).toBe(true)
    expect(isShownMessage({ type: "cobe-news-open", url: "/" })).toBe(false)
    expect(isShownMessage({ type: "cobe-news-shown", kind: "test" })).toBe(false)
    expect(isShownMessage(null)).toBe(false)
  })
})
