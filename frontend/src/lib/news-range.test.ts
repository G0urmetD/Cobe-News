// local times below are those of Central Europe – the reader's zone is what Intl knows of this process
process.env.TZ = "Europe/Berlin"

import { afterEach, beforeAll, describe, expect, it } from "vitest"
import i18n from "@/i18n"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { NO_RANGE, draftOf, draftRange, fromLocal, isoTime, rangeChip, rangeLabel, readIds, readRange, resolveRange, writeRange, type NewsRange } from "@/lib/news-range"
import { readAllBody, newsQuery, type NewsPage } from "@/lib/news-api"
import { hasFilter, readNewsFilter, viewQuery, writeNewsFilter } from "@/lib/reader-api"

const t = ((k: string, o?: Record<string, unknown>) => i18n.t(k, o)) as unknown as Parameters<typeof rangeLabel>[0]
const A = "0b7e6a52-1d3c-4f5e-9a1b-2c3d4e5f6a7b"
const B = "1c8f7b63-2e4d-4a6f-8b2c-3d4e5f6a7b8c"
const NOW = new Date(2026, 10, 5, 13, 41, 20) // Thursday 5 November 2026, 13:41 local (MEZ, UTC+1)

beforeAll(async () => {
  await i18n.changeLanguage("de")
})
afterEach(async () => {
  await i18n.changeLanguage("de")
})

describe("the range in the address", () => {
  it("keeps a preset as its key – a shared link with “Heute” stays today", () => {
    const p = writeRange(new URLSearchParams("story=x"), { preset: "today", since: null, until: null, field: "published" })
    expect(p.toString()).toBe("story=x&range=today")
    expect(readRange(p)).toEqual({ preset: "today", since: null, until: null, field: "published" })
    const f = writeRange(p, { preset: "7d", since: null, until: null, field: "fetched" })
    expect(f.get("time")).toBe("fetched")
    expect(readRange(f).field).toBe("fetched")
    // "visit" is by arrival: no "time" written
    expect(writeRange(p, { preset: "visit", since: null, until: null, field: "fetched" }).has("time")).toBe(false)
    // off: every range parameter goes, the others stay
    expect(writeRange(f, NO_RANGE).toString()).toBe("story=x")
  })

  it("an own range as UTC times with a zone; malformed, zoneless, extreme or reversed ones are dropped", () => {
    expect(isoTime("2026-11-05T08:00:00+01:00")).toBe("2026-11-05T07:00:00.000Z")
    expect(isoTime("2026-11-05T07:00Z")).toBe("2026-11-05T07:00:00.000Z")
    expect(isoTime("2026-11-05T08:00:00")).toBeNull() // whose local time?
    expect(isoTime("9999-12-31T23:59:59-14:00")).toBeNull()
    expect(isoTime("1969-12-31T23:00:00Z")).toBeNull()
    expect(isoTime("gestern")).toBeNull()
    expect(isoTime("x".repeat(60) + "Z")).toBeNull()
    expect(readRange(new URLSearchParams("range=bogus&since=2026-11-05T07:00:00Z"))).toEqual({ preset: null, since: "2026-11-05T07:00:00.000Z", until: null, field: "published" })
    expect(readRange(new URLSearchParams("since=2026-11-05T09:00:00Z&until=2026-11-05T08:00:00Z"))).toEqual(NO_RANGE)
    expect(readRange(new URLSearchParams("time=<script>"))).toEqual(NO_RANGE)
  })
})

describe("a preset resolved when the list is asked", () => {
  const r = (preset: NewsRange["preset"], field: NewsRange["field"] = "published"): NewsRange => ({ preset, since: null, until: null, field })
  it("in the browser's zone", () => {
    expect(resolveRange(r("today"), NOW)).toEqual({ since: "2026-11-04T23:00:00.000Z" }) // local midnight
    expect(resolveRange(r("yesterday"), NOW)).toEqual({ since: "2026-11-03T23:00:00.000Z", until: "2026-11-04T23:00:00.000Z" })
    expect(resolveRange(r("1h"), NOW)).toEqual({ since: new Date(NOW.getTime() - 3_600_000).toISOString() })
    expect(resolveRange(r("7d", "fetched"), NOW)).toEqual({ since: new Date(NOW.getTime() - 7 * 86_400_000).toISOString(), time_field: "fetched" })
    expect(resolveRange(r("visit", "fetched"), NOW)).toEqual({ since_mark: true })
    expect(resolveRange(NO_RANGE, NOW)).toEqual({})
    expect(resolveRange({ preset: null, since: "2026-11-05T07:00:00.000Z", until: null, field: "published" }, NOW)).toEqual({ since: "2026-11-05T07:00:00.000Z" })
  })
  it("“Gestern” across a clock change is the calendar day", () => {
    const after = new Date(2026, 9, 26, 10, 0) // Monday after the 25-hour Sunday
    expect(resolveRange(r("yesterday"), after)).toEqual({ since: "2026-10-24T22:00:00.000Z", until: "2026-10-25T23:00:00.000Z" })
  })
  it("the list asks the times, the next page the same ones, „Alle als gelesen“ too", () => {
    const f = { state: "all" as const, sources: [], severities: [], q: "", range: r("today") }
    const first = new URL(newsQuery(f, null, resolveRange(f.range, NOW)), "https://n.example.com").searchParams
    expect(first.get("since")).toBe("2026-11-04T23:00:00.000Z")
    const asked = { since: "2026-11-04T23:00:00.000Z" }
    const next = new URL(newsQuery(f, { before: "c", asked }), "https://n.example.com").searchParams
    expect(next.get("since")).toBe("2026-11-04T23:00:00.000Z")
    const page: NewsPage = { items: [], more: false, next: null, enabled: true, upto: 7, asked: { since_mark: true } }
    expect(readAllBody({ sources: [], severities: [], q: "" }, page)).toEqual({ since_mark: true, source: [], severity: [], q: "", upto: 7 })
  })
})

describe("texts", () => {
  it("short label and chip", () => {
    expect(rangeLabel(t, { preset: "today", since: null, until: null, field: "published" }, NOW)).toBe("Heute")
    expect(rangeLabel(t, { preset: null, since: new Date(2026, 10, 5, 8, 0).toISOString(), until: null, field: "published" }, NOW)).toBe("05.11. 08:00 – jetzt")
    expect(rangeLabel(t, { preset: null, since: null, until: new Date(2025, 0, 2, 18, 30).toISOString(), field: "published" }, NOW)).toBe("… – 02.01.2025 18:30")
    expect(rangeChip(t, { preset: "today", since: null, until: null, field: "published" }, { now: NOW })).toBe("heute, seit 00:00")
    expect(rangeChip(t, { preset: "7d", since: null, until: null, field: "fetched" }, { now: NOW })).toBe("7 Tage, seit 29.10. 13:41 · nach Eingang")
    expect(rangeChip(t, { preset: "visit", since: null, until: null, field: "fetched" }, { now: NOW, markAt: new Date(NOW.getTime() - 14 * 3_600_000).toISOString() })).toBe(
      "seit meinem letzten Besuch (vor 14 Stunden)",
    )
  })
  it("every key in both languages", () => {
    const keys = (o: Record<string, string>) => Object.keys(o).filter((k) => k.startsWith("newsRange."))
    expect(keys(de).sort()).toEqual(keys(en).sort())
    expect(keys(de).length).toBeGreaterThan(40)
  })
})

describe("the own range's fields", () => {
  it("local date and time; a day without a time is the whole day", () => {
    expect(fromLocal("2026-11-05", "08:00")).toBe("2026-11-05T07:00:00.000Z")
    expect(fromLocal("2026-11-05", "")).toBe("2026-11-04T23:00:00.000Z")
    expect(fromLocal("2026-11-05", "", true)).toBe("2026-11-05T23:00:00.000Z")
    expect(fromLocal("", "")).toBeNull()
    expect(fromLocal("", "08:00")).toBeUndefined()
    expect(fromLocal("1960-01-01", "")).toBeUndefined()
  })
  it("checks the order and that anything is given", () => {
    expect(draftRange({ fromDate: "2026-11-05", fromTime: "10:00", toDate: "2026-11-05", toTime: "09:00" }).error).toBe("order")
    expect(draftRange({ fromDate: "", fromTime: "", toDate: "", toTime: "" }).error).toBe("empty")
    expect(draftRange({ fromDate: "2026-11-05", fromTime: "08:00", toDate: "", toTime: "" })).toEqual({ since: "2026-11-05T07:00:00.000Z", until: null, error: null })
    // the same day, from and to: that day
    expect(draftRange({ fromDate: "2026-11-05", fromTime: "", toDate: "2026-11-05", toTime: "" }).error).toBeNull()
  })
  it("shows an end at midnight as the day entered", () => {
    const d = draftRange({ fromDate: "2026-11-02", fromTime: "", toDate: "2026-11-05", toTime: "" })
    expect(draftOf({ preset: null, since: d.since, until: d.until, field: "published" })).toEqual({ fromDate: "2026-11-02", fromTime: "00:00", toDate: "2026-11-05", toTime: "" })
  })
})

describe("a notification's stories (?ids=)", () => {
  it("reads story ids only, once each, at most 50", () => {
    expect(readIds(new URLSearchParams(`ids=${A},bogus, ${B.toUpperCase()} ,${A}`))).toEqual([A, B])
    const many = Array.from({ length: 70 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`).join(",")
    expect(readIds(new URLSearchParams(`ids=${many}`))).toHaveLength(50)
    expect(readIds(new URLSearchParams("ids="))).toEqual([])
  })
  it("lives beside the story's drawer and the range, never in a view, and asks only the ids", () => {
    const p = new URLSearchParams(`ids=${A},${B}&story=${A}&range=today`)
    const f = readNewsFilter(p)
    expect(f.ids).toEqual([A, B])
    expect(f.range.preset).toBe("today")
    expect(hasFilter(new URLSearchParams(`ids=${A}`), "news")).toBe(true) // a mail's link: no default view over it
    expect(viewQuery(p, "news")).toBe("range=today")
    const cleared = writeNewsFilter(p, { ids: [] })
    expect(cleared.has("ids")).toBe(false)
    expect(cleared.get("story")).toBe(A)
    const q = new URL(
      newsQuery({ state: "all", sources: [], severities: [], q: "", muted: true, ids: [A, B], range: { preset: "today", since: null, until: null, field: "published" } }, null),
      "https://n.example.com",
    ).searchParams
    expect(q.get("ids")).toBe(`${A},${B}`)
    expect(q.get("since")).toBeNull()
    expect(q.get("muted")).toBe("true")
    expect(readAllBody({ sources: ["x"], severities: [], q: "a", ids: [A] }, undefined)).toEqual({ ids: [A], muted: true })
  })
})
