import { describe, expect, it } from "vitest"
import type { InfiniteData } from "@tanstack/react-query"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { listKeeps, type NewsItem, type NewsPage, withRead } from "@/lib/news-api"
import { NO_RANGE } from "@/lib/news-range"
import {
  applyView,
  badgeText,
  cleanViewName,
  fromOutside,
  hasFilter,
  IN_PAGE,
  readNewsFilter,
  readVendorFilter,
  readerVisible,
  remaining,
  untilEndOf,
  viewLink,
  viewQuery,
  writeNewsFilter,
  writeVendorFilter,
} from "@/lib/reader-api"

const SRC = "0b7e6a52-1d3c-4f5e-9a1b-2c3d4e5f6a7b"

describe("badge", () => {
  it("shows nothing for 0 and caps at 99+", () => {
    expect(badgeText(0)).toBeNull()
    expect(badgeText(undefined)).toBeNull()
    expect(badgeText(-3)).toBeNull()
    expect(badgeText(7)).toBe("7")
    expect(badgeText(99)).toBe("99")
    expect(badgeText(100)).toBe("99+")
    expect(badgeText(12345)).toBe("99+")
  })
})

describe("news filter in the address", () => {
  it("reads what is valid and drops the rest (a crafted link cannot break the page)", () => {
    const p = new URLSearchParams(`source=${SRC}&source=not-a-uuid&source=${SRC}&severity=critical&severity=bogus&q=${"x".repeat(300)}&unread=1&muted=yes&story=abc`)
    const f = readNewsFilter(p)
    expect(f.sources).toEqual([SRC])
    expect(f.severities).toEqual(["critical"])
    expect(f.q).toHaveLength(100)
    expect(f.unread).toBe(true)
    expect(f.muted).toBe(false)
  })
  it("caps the sources at 50", () => {
    const many = Array.from({ length: 70 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`)
    expect(readNewsFilter(new URLSearchParams(many.map((s) => ["source", s]))).sources).toHaveLength(50)
  })
  it("writes a round trip and keeps the drawer and unknown parameters", () => {
    const base = new URLSearchParams("story=abc&future=1&tab=read")
    const next = writeNewsFilter(base, { sources: [SRC], severities: ["high", "critical"], q: "  gitlab  ", unread: true, muted: false })
    expect(next.get("story")).toBe("abc")
    expect(next.get("future")).toBe("1")
    expect(next.has("tab")).toBe(false) // the old Neu | Gelesen tabs
    expect(readNewsFilter(next)).toEqual({
      sources: [SRC],
      severities: ["high", "critical"],
      topics: [],
      q: "gitlab",
      unread: true,
      muted: false,
      ours: false,
      range: NO_RANGE,
      ids: [],
      systems: [],
      without: [],
    })
    const cleared = writeNewsFilter(next, { sources: [], severities: [], q: "", unread: false })
    expect([...cleared.keys()].sort()).toEqual(["future", "story"])
    // "Betrifft unsere Produkte" in the address (saved views and shared links carry it)
    const ours = writeNewsFilter(cleared, { ours: true })
    expect(ours.get("ours")).toBe("1")
    expect(readNewsFilter(ours).ours).toBe(true)
    expect(writeNewsFilter(ours, { ours: false }).has("ours")).toBe(false)
  })
})

describe("topics in the address", () => {
  it("keeps only known topics, once each", () => {
    const f = readNewsFilter(new URLSearchParams("topic=zeroday&topic=bogus&topic=zeroday&topic=ot&topic=<script>"))
    expect(f.topics).toEqual(["zeroday", "ot"])
  })
  it("writes them as repeated parameters and clears them", () => {
    const next = writeNewsFilter(new URLSearchParams("story=abc&severity=high"), { topics: ["exploited", "nopatch"] })
    expect(next.getAll("topic")).toEqual(["exploited", "nopatch"])
    expect(next.get("severity")).toBe("high") // the other filters stay
    expect(readNewsFilter(next).topics).toEqual(["exploited", "nopatch"])
    const cleared = writeNewsFilter(next, { topics: [] })
    expect(cleared.has("topic")).toBe(false)
    expect(cleared.get("story")).toBe("abc")
  })
  it("a view's query carries the topics, the drawer's parameters not", () => {
    expect(viewQuery(new URLSearchParams("topic=ot&story=x"))).toBe("topic=ot")
    expect(viewQuery(new URLSearchParams("topic=ot&story=x"), "news")).toBe("topic=ot")
    expect(hasFilter(new URLSearchParams("topic=ot"))).toBe(true)
    expect(hasFilter(new URLSearchParams("topic=ot"), "news")).toBe(true)
  })
  it("on Vendor News a topic is no filter: not in a view, no reason to skip the default view, not read", () => {
    const here = new URLSearchParams("topic=exploited&status=action&product=panos&q=pan")
    expect(viewQuery(here, "vendor")).toBe("status=action&q=pan")
    expect(hasFilter(new URLSearchParams("topic=exploited&product=panos"), "vendor")).toBe(false)
    expect(hasFilter(new URLSearchParams("ours=1"), "vendor")).toBe(false)
    expect(hasFilter(new URLSearchParams("ours=1"), "news")).toBe(true)
    expect(hasFilter(new URLSearchParams("topic=exploited&status=ok"), "vendor")).toBe(true)
    expect(readVendorFilter(new URLSearchParams("topic=exploited"))).toEqual({ status: null, filter: null, q: "", unread: false, muted: false, confirmed: false })
    expect(writeVendorFilter(new URLSearchParams("topic=zeroday"), { status: "check" }).get("status")).toBe("check")
  })
})

describe("systems in the address", () => {
  it("keeps valid systems only, once each, at most 50 – a crafted link cannot break the page", () => {
    const p = new URLSearchParams()
    for (const v of ["v:Palo Alto Networks", "p:panos", "p:panos", "p:Bad Key", "x:y", "v:", "v:" + "a".repeat(121), "v:Evil\u2028Name", "panos"]) p.append("system", v)
    expect(readNewsFilter(p).systems).toEqual([{ vendor: "Palo Alto Networks" }, { product: "panos" }])
    const many = new URLSearchParams(Array.from({ length: 70 }, (_, i) => ["system", `p:k${i}`]))
    expect(readNewsFilter(many).systems).toHaveLength(50)
  })
  it("writes them as repeated parameters, keeps the rest, clears them – and a view carries them", () => {
    const next = writeNewsFilter(new URLSearchParams("story=abc&severity=critical"), { systems: [{ vendor: "Palo Alto Networks" }, { product: "panos" }] })
    expect(next.getAll("system")).toEqual(["v:Palo Alto Networks", "p:panos"])
    expect(next.get("severity")).toBe("critical")
    expect(readNewsFilter(next).systems).toEqual([{ vendor: "Palo Alto Networks" }, { product: "panos" }])
    expect(viewQuery(next, "news")).toBe("severity=critical&system=v%3APalo+Alto+Networks&system=p%3Apanos")
    expect(readNewsFilter(applyView(new URLSearchParams("story=x"), viewQuery(next, "news"))).systems).toHaveLength(2)
    expect(hasFilter(new URLSearchParams("system=p:panos"), "news")).toBe(true)
    // on Vendor News no filter: not stored in its views, no reason to skip its default view
    expect(hasFilter(new URLSearchParams("system=p:panos"), "vendor")).toBe(false)
    expect(viewQuery(new URLSearchParams("system=p:panos&q=x"), "vendor")).toBe("q=x")
    expect(writeNewsFilter(next, { systems: [] }).has("system")).toBe(false)
  })
})

describe("excluded words in the address", () => {
  it("keeps only words the server takes, once each, at most 30 – and a view carries them", () => {
    const p = new URLSearchParams()
    for (const w of ["Webinar", "webinar", "x", "(.*)+$", "a".repeat(61), " Citrix   Bleed "]) p.append("without", w)
    expect(readNewsFilter(p).without).toEqual(["Webinar", "Citrix Bleed"])
    expect(readNewsFilter(new URLSearchParams(Array.from({ length: 40 }, (_, i) => ["without", `wort${i}`]))).without).toHaveLength(30)
    const next = writeNewsFilter(new URLSearchParams("story=x"), { without: ["Webinar"] })
    expect(next.getAll("without")).toEqual(["Webinar"])
    expect(viewQuery(next, "news")).toBe("without=Webinar")
    expect(hasFilter(new URLSearchParams("without=Webinar"), "vendor")).toBe(false)
    expect(writeNewsFilter(next, { without: [] }).has("without")).toBe(false)
  })
})

describe("vendor filter in the address", () => {
  it("validates status and summary filter, keeps an older link's action", () => {
    expect(readVendorFilter(new URLSearchParams("status=check&filter=exploited&q=pan&unread=1"))).toEqual({
      status: "check",
      filter: "exploited",
      q: "pan",
      unread: true,
      muted: false,
      confirmed: false,
    })
    expect(readVendorFilter(new URLSearchParams("status=<script>&filter=nope"))).toEqual({ status: null, filter: null, q: "", unread: false, muted: false, confirmed: false })
    expect(readVendorFilter(new URLSearchParams("filter=action")).status).toBe("action")
    // "Versionen prüfen" (catalog care): its summary filter survives the address too
    expect(readVendorFilter(new URLSearchParams("filter=review")).filter).toBe("review")
  })
  it("writes only what changes and drops 'all'", () => {
    const next = writeVendorFilter(new URLSearchParams("product=panos&status=ok"), { status: "all", muted: true })
    expect(next.toString()).toBe("product=panos&muted=1")
  })
})

describe("views", () => {
  it("stores the address without the drawer's parameters and applies a view keeping the open drawer", () => {
    const here = new URLSearchParams(`story=abc&severity=high&source=${SRC}`)
    expect(viewQuery(here)).toBe(`severity=high&source=${SRC}`)
    expect(hasFilter(new URLSearchParams("story=abc&tab=catalog"))).toBe(false)
    expect(hasFilter(here)).toBe(true)
    const applied = applyView(here, "?severity=critical&story=other&zzz=1")
    expect(applied.get("story")).toBe("abc")
    expect(applied.getAll("severity")).toEqual(["critical"])
    expect(applied.get("zzz")).toBe("1") // unknown parameters of a view stay (tolerated, ignored by the page)
  })
  it("makes a shareable link per page", () => {
    expect(viewLink("https://news.corp.example", "news", "severity=high")).toBe("https://news.corp.example/?severity=high")
    expect(viewLink("https://news.corp.example", "vendor", "")).toBe("https://news.corp.example/vendor")
  })
  it("cleans names", () => {
    expect(cleanViewName("  Kritisch\u0007 & neu  ")).toBe("Kritisch & neu")
    expect(cleanViewName("x".repeat(80))).toHaveLength(60)
    expect(cleanViewName(" \n ")).toBe("")
  })
  it("tells in-page changes from arrivals", () => {
    expect(fromOutside(null)).toBe(true)
    expect(fromOutside({ other: 1 })).toBe(true)
    expect(fromOutside(IN_PAGE)).toBe(false)
  })
})

describe("mutes", () => {
  it("says what is left", () => {
    const now = Date.parse("2026-10-31T12:00:00Z")
    expect(remaining("2026-11-07T12:00:00Z", now)).toEqual({ unit: "days", count: 7 })
    expect(remaining("2026-11-01T12:00:00Z", now)).toEqual({ unit: "hours", count: 24 })
    expect(remaining("2026-10-31T12:30:00Z", now)).toEqual({ unit: "minutes", count: 30 })
    expect(remaining("2026-10-30T12:00:00Z", now)).toEqual({ unit: "minutes", count: 1 })
  })
  it("ends a day at its end, refuses garbage", () => {
    const iso = untilEndOf("2026-12-24")
    expect(iso).not.toBeNull()
    const d = new Date(iso as string)
    expect([d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMinutes()]).toEqual([2026, 11, 24, 23, 59])
    expect(untilEndOf("24.12.2026")).toBeNull()
    expect(untilEndOf("")).toBeNull()
  })
  it("hides muted products unless asked – never an exploited one", () => {
    const items = [
      { key: "a", unread: 2 },
      { key: "b", unread: 0 },
      { key: "c", unread: 3, muted: { until: "2026-11-07T00:00:00Z" } },
      { key: "d", unread: 0, muted: { until: "2026-11-07T00:00:00Z" }, muted_kev: true },
    ]
    expect(readerVisible(items, { unread: false, muted: false }).map((i) => i.key)).toEqual(["a", "b", "d"])
    expect(readerVisible(items, { unread: false, muted: true }).map((i) => i.key)).toEqual(["a", "b", "c", "d"])
    expect(readerVisible(items, { unread: true, muted: false }).map((i) => i.key)).toEqual(["a", "d"])
  })
})

const item = (id: string, unread: boolean): NewsItem => ({
  id,
  title: id,
  summary: "",
  url: `https://n.example.com/${id}`,
  source: { id: "s", key: "s", name: "S", logo: false },
  published_at: "2026-10-28T08:00:00Z",
  severity: "low",
  cves: [],
  also_in: [],
  read_at: unread ? null : "2026-10-29T08:00:00Z",
  unread,
})

describe("marking in a list that keeps the story", () => {
  const data = (): InfiniteData<NewsPage> => ({
    pages: [{ items: [item("a", true), item("b", false)], more: false, next: null, enabled: true, counts: { new: 1, read: 1 } }],
    pageParams: [null],
  })
  it("flips the flag and moves the numbers once", () => {
    const d = withRead(data(), "a", true)
    expect(d?.pages[0].items[0].unread).toBe(false)
    expect(d?.pages[0].counts).toEqual({ new: 0, read: 2 })
    // already read: nothing changes (no double counting)
    expect(withRead(d, "a", true)).toBe(d)
    const back = withRead(d, "b", false)
    expect(back?.pages[0].items[1].unread).toBe(true)
    expect(back?.pages[0].counts).toEqual({ new: 1, read: 1 })
  })
  it("knows which lists keep a story", () => {
    expect(listKeeps("all", true)).toBe(true)
    expect(listKeeps("new", true)).toBe(false)
    expect(listKeeps("new", false)).toBe(true)
    expect(listKeeps("read", false)).toBe(false)
  })
})

describe("i18n", () => {
  it("has every reading text in German and English", () => {
    const keys = (m: Record<string, string>) => Object.keys(m).filter((k) => k.startsWith("reader.") || k.startsWith("nav.badge."))
    expect(keys(de).sort()).toEqual(keys(en).sort())
    expect(keys(de).length).toBeGreaterThan(60)
  })
})
