import { describe, expect, it } from "vitest"
import type { InfiniteData } from "@tanstack/react-query"
import {
  NEWS_TOPICS,
  askedFilter,
  cardTopics,
  findStory,
  loadNewsFilter,
  mergePages,
  newsQuery,
  readAllBody,
  saveNewsFilter,
  sourceGroups,
  type NewsItem,
  type NewsPage,
  withStory,
  withoutStory,
} from "@/lib/news-api"

const item = (id: string): NewsItem => ({
  id,
  title: id,
  summary: "",
  url: `https://n.example.com/${id}`,
  source: { id: "s", key: "s", name: "S", logo: false },
  published_at: "2026-10-28T08:00:00Z",
  severity: "low",
  cves: [],
  also_in: [],
  read_at: null,
})
const page = (ids: string[], extra: Partial<NewsPage> = {}): NewsPage => ({ items: ids.map(item), more: true, next: null, enabled: true, ...extra })

describe("paging", () => {
  it("lists a story once when it moved onto the next page", () => {
    expect(mergePages([page(["a", "b", "c"]), page(["c", "d"])]).map((i) => i.id)).toEqual(["a", "b", "c", "d"])
    expect(mergePages(undefined)).toEqual([])
  })

  it("asks the next page by cursor, the counts only once", () => {
    const f = { state: "new" as const, sources: ["x"], severities: ["critical" as const], q: " lücke " }
    const first = new URL(newsQuery(f, null), "https://n.example.com").searchParams
    expect(first.get("before")).toBeNull()
    expect(first.get("counts")).toBeNull()
    expect(first.get("q")).toBe("lücke")
    const next = new URL(newsQuery(f, { before: "2026-10-28T08:00:00+00:00|abc", asked: {} }), "https://n.example.com").searchParams
    expect(next.get("before")).toBe("2026-10-28T08:00:00+00:00|abc")
    expect(next.get("counts")).toBe("false")
    expect(next.getAll("source")).toEqual(["x"])
  })

  it("asks the scope only with Betrifft unsere Produkte on (one cache entry while it is off)", () => {
    const off = { state: "new" as const, sources: [], severities: [], scope: "team" as const }
    expect(askedFilter(off)).toEqual(askedFilter({ ...off, scope: "all" }))
    expect(JSON.stringify(askedFilter(off))).not.toContain("scope")
    expect(new URL(newsQuery(off, null), "https://n.example.com").searchParams.get("scope")).toBeNull()
    const on = { ...off, ours: true }
    expect(askedFilter(on)).toEqual(on)
    const q = new URL(newsQuery(on, null), "https://n.example.com").searchParams
    expect(q.get("ours")).toBe("true")
    expect(q.get("scope")).toBe("team")
  })

  it("caps the search at 100 characters", () => {
    const q = new URL(newsQuery({ state: "new", sources: [], severities: [], q: "x".repeat(150) }, null), "https://n.example.com").searchParams.get("q")
    expect(q).toHaveLength(100)
  })
})

describe("marking read", () => {
  const data: InfiniteData<NewsPage> = { pages: [page(["a", "b"], { counts: { new: 5, read: 1 } }), page(["c"])], pageParams: [null, "x"] }

  it("takes the story out of the list and moves the numbers", () => {
    const r = withoutStory(data, "c", true)
    expect(r.listed).toBe(true)
    expect(mergePages(r.data?.pages).map((i) => i.id)).toEqual(["a", "b"])
    expect(r.data?.pages[0].counts).toEqual({ new: 4, read: 2 })
  })

  it("leaves a list without that story alone (undo: reloaded instead)", () => {
    const r = withoutStory(data, "zz", false)
    expect(r.listed).toBe(false)
    expect(r.data).toBe(data)
  })

  it("an error puts the story back where it was, the numbers too", () => {
    const at = findStory(data, "b")!
    expect(at).toMatchObject({ page: 0, index: 1 })
    const gone = withoutStory(data, "b", true).data
    const back = withStory(gone, at, true)
    expect(back?.pages.map((p) => p.items.map((i) => i.id))).toEqual([["a", "b"], ["c"]])
    expect(back?.pages[0].counts).toEqual({ new: 5, read: 1 })
  })

  it("a rollback never lists a story twice and keeps what arrived meanwhile", () => {
    const at = findStory(data, "c")!
    const gone = withoutStory(data, "c", true).data!
    // meanwhile a refetch or the next page brought the story back (and a page more): nothing to restore
    const refetched: InfiniteData<NewsPage> = { ...gone, pages: [page(["a", "b"], { counts: { new: 5, read: 1 } }), page(["c"]), page(["d"])] }
    const back = withStory(refetched, at, true)
    expect(back).toBe(refetched)
    expect(mergePages(back?.pages).map((i) => i.id)).toEqual(["a", "b", "c", "d"])
    // two clicks, the first one failed: only that story comes back – the second one (marked fine) stays out
    const both = withoutStory(withoutStory(data, "a", true).data, "c", true).data
    const once = withStory(both, findStory(data, "a")!, true)
    expect(once?.pages.flatMap((p) => p.items.map((i) => i.id))).toEqual(["a", "b"])
    expect(once?.pages[0].counts).toEqual({ new: 4, read: 2 })
    // the same rollback twice (two lists, a retry) – still once
    expect(withStory(once, findStory(data, "a")!, true)).toBe(once)
  })
})

describe("all read", () => {
  it("marks only what had arrived when the list was loaded", () => {
    const f = { sources: ["x"], severities: ["critical"], q: "lücke" }
    expect(readAllBody(f, page(["a"], { upto: 130 }))).toEqual({ source: ["x"], severity: ["critical"], q: "lücke", upto: 130 })
    expect(readAllBody(f, page(["a"], { upto: 0 })).upto).toBe(0)
    // an older server without upto: the filter alone, as before
    expect(readAllBody(f, page(["a"]))).toEqual({ source: ["x"], severity: ["critical"], q: "lücke" })
    expect(readAllBody(f, undefined)).not.toHaveProperty("upto")
  })
})

describe("topics", () => {
  it("are asked as repeated parameters and sent with read-all", () => {
    const p = new URL(newsQuery({ state: "all", sources: [], severities: ["high"], topics: ["zeroday", "ot"] }, null), "https://n.example.com").searchParams
    expect(p.getAll("topic")).toEqual(["zeroday", "ot"])
    expect(readAllBody({ sources: [], severities: [], topics: ["exploited"], q: "" }, undefined)).toEqual({ source: [], severity: [], topic: ["exploited"], q: "" })
    // without topics nothing changes in the body
    expect(readAllBody({ sources: [], severities: [], topics: [], q: "" }, undefined)).toEqual({ source: [], severity: [], q: "" })
  })
  it("knows the topic Exploit veröffentlicht right after Aktiv ausgenutzt", () => {
    expect(NEWS_TOPICS.indexOf("poc")).toBe(NEWS_TOPICS.indexOf("exploited") + 1)
    expect(cardTopics(["poc", "ransomware", "exploited"])).toEqual({ shown: ["exploited", "poc"], more: 1 })
  })
  it("asks for our products in the scope and sends them with read-all", () => {
    const p = new URL(newsQuery({ state: "all", sources: [], severities: [], ours: true, scope: "team" }, null), "https://n.example.com").searchParams
    expect(p.get("ours")).toBe("true")
    expect(p.get("scope")).toBe("team")
    const plain = new URL(newsQuery({ state: "all", sources: [], severities: [] }, null), "https://n.example.com").searchParams
    expect(plain.has("ours")).toBe(false)
    expect(plain.has("scope")).toBe(false)
    expect(readAllBody({ sources: [], severities: [], q: "", ours: true, scope: "team" }, undefined)).toEqual({ source: [], severity: [], q: "", ours: true, scope: "team" })
    expect(readAllBody({ sources: [], severities: [], q: "", ours: false, scope: "team" }, undefined)).toEqual({ source: [], severity: [], q: "" })
  })
  it("a card shows two in badge order and counts the rest", () => {
    expect(cardTopics(["ot", "exploited", "zeroday", "breach"])).toEqual({ shown: ["zeroday", "exploited"], more: 2 })
    expect(cardTopics(["nopatch", "ransomware"])).toEqual({ shown: ["ransomware", "nopatch"], more: 0 })
    expect(cardTopics(["bogus"])).toEqual({ shown: [], more: 0 })
    expect(cardTopics(undefined)).toEqual({ shown: [], more: 0 })
  })
  it("the browser's fallback filter keeps known topics only", () => {
    const before = globalThis.localStorage
    const m = new Map<string, string>()
    globalThis.localStorage = { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) } as unknown as Storage
    saveNewsFilter("u1", { sources: [], severities: ["critical"], topics: ["nopatch"] })
    expect(loadNewsFilter("u1")).toEqual({ sources: [], severities: ["critical"], topics: ["nopatch"], ours: false })
    saveNewsFilter("u1", { sources: [], severities: [], topics: ["poc"], ours: true })
    expect(loadNewsFilter("u1")).toEqual({ sources: [], severities: [], topics: ["poc"], ours: true })
    localStorage.setItem("cobe-news.filter.u2", JSON.stringify({ sources: [], severities: [], topics: ["ot", "x", "ot"] }))
    expect(loadNewsFilter("u2").topics).toEqual(["ot"])
    // an older entry without topics
    localStorage.setItem("cobe-news.filter.u3", JSON.stringify({ sources: ["a"], severities: [] }))
    expect(loadNewsFilter("u3")).toEqual({ sources: ["a"], severities: [], topics: [], ours: false })
    globalThis.localStorage = before
  })
  it("the source filter is grouped by the kind of source, authorities first", () => {
    const g = sourceGroups([{ id: "1", category: "press" as const }, { id: "2", category: "authority" as const }, { id: "3" }, { id: "4", category: "authority" as const }])
    expect(g.map((x) => [x.category, x.sources.map((s) => s.id)])).toEqual([
      ["authority", ["2", "4"]],
      ["press", ["1"]],
      ["custom", ["3"]],
    ])
  })
})
