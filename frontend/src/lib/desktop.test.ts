import { describe, expect, it } from "vitest"
import { DESKTOP_MAX, isShownMessage, planNotifications, storyBody, summaryBody, systemOf, watchPermission } from "@/lib/desktop"
import i18n from "@/i18n"
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
    expect(planNotifications([], 0, () => true)).toEqual({ single: [], more: 0, rest: [] })
  })

  it("takes the first few of the server's order – critical or exploited first, the most important shown last", () => {
    // as /news/recent lists them: the critical and the exploited one before the newer high ones
    const items = [item("crit-old"), item("exploited"), item("high-new"), item("high-2"), item("high-3")]
    const { single, more, rest } = planNotifications(items, 5, () => true)
    expect(single.map((i) => i.id)).toEqual(["high-new", "exploited", "crit-old"])
    expect(rest.map((i) => i.id)).toEqual(["high-2", "high-3"])
    expect(more).toBe(2)
  })
})

// ---------------------------------------------------------------- rounds across tabs (node: localStorage, Notification and locks as stand-ins)

import { afterEach, beforeEach, vi } from "vitest"
import { api } from "@/lib/api"
import { POLL_MS, lastKey, poll, tick } from "@/lib/desktop"
import { swErrorReason } from "@/lib/push"

const shown: string[] = []
const bodies: string[] = []
let mem: Map<string, string>

beforeEach(() => {
  mem = new Map()
  shown.length = 0
  bodies.length = 0
  Object.defineProperty(globalThis, "localStorage", {
    value: { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v), removeItem: (k: string) => void mem.delete(k) },
    configurable: true,
    writable: true,
  })
  class FakeNotification {
    onclick: (() => void) | null = null
    constructor(title: string, opts?: NotificationOptions) {
      shown.push(title)
      bodies.push(opts?.body ?? "")
    }
    close() {}
  }
  vi.stubGlobal("Notification", FakeNotification)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function server(rounds: { items: NewsItem[]; total: number; cursor: number; unlisted_top?: string | null }[]) {
  const asked: string[] = []
  vi.spyOn(api, "get").mockImplementation(async (path: string) => {
    asked.push(path)
    return (rounds.shift() ?? { items: [], total: 0, cursor: 0 }) as never
  })
  return asked
}

describe("what matched", () => {
  const t = (k: string, o?: Record<string, unknown>) => (o ? `${k}${JSON.stringify(o)}` : k)
  const item = { severity: "critical" as const, source: { id: "s", key: "s", name: "heise", logo: false } }
  it("says why it came when the person chose systems or words – at most three names, one line", () => {
    expect(storyBody(item, t)).toBe("news.sev.critical · heise")
    expect(storyBody({ ...item, hits: [] }, t)).toBe("news.sev.critical · heise")
    expect(storyBody({ ...item, hits: ["PAN-OS", "Palo\nAlto", "C", "D"] }, t)).toBe('news.sev.critical · desktop.hit{"names":"PAN-OS, Palo Alto, C +1"} · heise')
  })
  it("names the products, the CVSS and an exploitation – and no severity when the story has none", () => {
    const notice = { rated: true, cvss: "9.2", exploited: true, products: ["PAN-OS", "Prisma Cloud"] }
    expect(storyBody({ ...item, notice }, t)).toBe("news.sev.critical (CVSS 9.2) · desktop.exploited · PAN-OS, Prisma Cloud · heise")
    // what matched the person's choice stands for the products
    expect(storyBody({ ...item, notice, hits: ["PAN-OS"] }, t)).toBe('news.sev.critical (CVSS 9.2) · desktop.exploited · desktop.hit{"names":"PAN-OS"} · heise')
    expect(storyBody({ ...item, severity: "info", notice: { rated: false, cvss: null, exploited: false, products: [] } }, t)).toBe("heise")
  })
  it("the summary names the highest severity and the products of the rest", () => {
    const n = (products: string[], rated = true) => ({ rated, cvss: null, exploited: false, products })
    expect(
      summaryBody(
        [
          { severity: "high", notice: n(["FortiOS"]) },
          { severity: "critical", notice: n(["PAN-OS", "FortiOS"]) },
          { severity: "info", notice: n([], false) },
        ],
        t,
      ),
    ).toBe('desktop.summaryTop{"sev":"news.sev.critical"} · FortiOS, PAN-OS')
    expect(summaryBody([], t)).toBe("desktop.summaryText")
  })
  it("the summary's severity covers the rest the server did not list", () => {
    const n = (products: string[]) => ({ rated: true, cvss: null, exploited: false, products })
    const rest = [{ severity: "medium" as const, notice: n(["FortiOS"]) }]
    expect(summaryBody(rest, t, "critical")).toBe('desktop.summaryTop{"sev":"news.sev.critical"} · FortiOS')
    expect(summaryBody(rest, t, "low")).toBe('desktop.summaryTop{"sev":"news.sev.medium"} · FortiOS') // the listed one is higher
    expect(summaryBody([], t, "high")).toBe('desktop.summaryTop{"sev":"news.sev.high"}') // only unlisted ones
    expect(summaryBody(rest, t, null)).toBe('desktop.summaryTop{"sev":"news.sev.medium"} · FortiOS')
  })
})

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

  it("the summary names the highest severity of the stories the server did not list", async () => {
    mem.set("cobe-news.desktop.seq.u", "3")
    vi.spyOn(i18n, "t").mockImplementation(((k: string, o?: Record<string, unknown>) => (o ? `${k}${JSON.stringify(o)}` : k)) as never)
    const listed = Array.from({ length: 10 }, (_, n) => ({ ...item(`s${n}`), severity: "low" as const }))
    server([{ items: listed, total: 25, unlisted_top: "critical", cursor: 28 }])
    await poll("u", () => undefined)
    expect(shown.slice(0, 3)).toEqual(["s2", "s1", "s0"])
    expect(shown).toHaveLength(4) // three on their own, one summary for the other 22
    expect(bodies[3]).toBe('desktop.summaryTop{"sev":"news.sev.critical"}')
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

describe("notification permission", () => {
  it("a permission query answering after the page is gone attaches nothing", async () => {
    let answer: (s: { onchange: (() => void) | null }) => void = () => undefined
    const status = { onchange: null as (() => void) | null }
    const listeners = new Map<string, () => void>()
    vi.stubGlobal("navigator", { permissions: { query: () => new Promise((r) => (answer = r)) } })
    vi.stubGlobal("window", { addEventListener: (k: string, f: () => void) => listeners.set(k, f), removeEventListener: (k: string) => listeners.delete(k) })
    vi.stubGlobal("document", { ...document, addEventListener: (k: string, f: () => void) => listeners.set(k, f), removeEventListener: (k: string) => listeners.delete(k) })
    let calls = 0
    const stop = watchPermission(() => calls++)
    listeners.get("focus")?.()
    expect(calls).toBe(1)
    stop() // unmounted before the browser answered
    expect(listeners.size).toBe(0)
    answer(status)
    await new Promise((r) => setTimeout(r, 0))
    expect(status.onchange).toBeNull()
    expect(calls).toBe(1)
  })

  it("while mounted, the permission's change event checks again – and is detached on stop", async () => {
    const status = { onchange: null as (() => void) | null }
    vi.stubGlobal("navigator", { permissions: { query: async () => status } })
    vi.stubGlobal("window", { addEventListener: () => undefined, removeEventListener: () => undefined })
    vi.stubGlobal("document", { ...document, addEventListener: () => undefined, removeEventListener: () => undefined })
    let calls = 0
    const stop = watchPermission(() => calls++)
    await new Promise((r) => setTimeout(r, 0))
    status.onchange?.()
    expect(calls).toBe(1)
    stop()
    expect(status.onchange).toBeNull()
  })
})
