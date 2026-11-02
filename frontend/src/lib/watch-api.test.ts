import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { TERMS } from "@/components/cobe/glossary"
import {
  EPSS_HIGH,
  groupHref,
  groupWatch,
  isNewItem,
  originIn,
  originKey,
  originLink,
  isOriginKey,
  parseGroupBy,
  productKey,
  productLink,
  storyWatchCves,
  undoGroups,
  unwatched,
  withGroupBy,
  matchesWatchFilter,
  normalizeCve,
  parseWatchFilter,
  parseWatchSort,
  sortWatch,
  watchCounts,
  watchEpss,
  watchHintAction,
  watchHintKey,
  webcalUrl,
  withoutFix,
  type WatchItem,
  type WatchOrigin,
  type WatchProduct,
} from "@/lib/watch-api"

describe("normalizeCve", () => {
  it("takes CVE ids as the server keeps them", () => {
    expect(normalizeCve(" cve-2026-31337 ")).toBe("CVE-2026-31337")
    expect(normalizeCve("CVE-2024-3400")).toBe("CVE-2024-3400")
    expect(normalizeCve("CVE-2026-123456789012")).toBe("CVE-2026-123456789012")
  })

  it("refuses anything else", () => {
    for (const bad of ["", "CVE-26-1", "CVE-2026-123", "CVE-2026-1234567890123", "GHSA-abcd-efgh-ijkl", "CVE-2026-1234; x", "xCVE-2026-1234", "CVE-2026-12a4"]) {
      expect(normalizeCve(bad), bad).toBeNull()
    }
  })
})

describe("calendar address", () => {
  it("opens as webcal for calendar apps", () => {
    expect(webcalUrl("https://news.corp.example:8095/cal/abc.ics")).toBe("webcal://news.corp.example:8095/cal/abc.ics")
    expect(webcalUrl("HTTP://news.corp.example/cal/abc.ics")).toBe("webcal://news.corp.example/cal/abc.ics")
  })
})

describe("watched CVEs", () => {
  it("says why nothing comes – in both languages", () => {
    expect(watchHintKey(null)).toBeNull()
    for (const r of ["teams_off", "no_way_allowed", "no_way_on"] as const) {
      const k = watchHintKey(r)!
      expect(de[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
    }
  })

  it("shows its EPSS in the chip's shape", () => {
    const w = { cve: "CVE-2026-1", epss: { score: 0.4, percentile: 0.97, day: "2026-10-30" } } as WatchItem
    expect(watchEpss(w)).toEqual({ cve: "CVE-2026-1", score: 0.4, percentile: 0.97, date: "2026-10-30" })
    expect(watchEpss({ ...w, epss: null })).toBeNull()
  })

  it("has every text in German and English alike", () => {
    const mine = (o: Record<string, string>) =>
      Object.keys(o).filter((k) =>
        /^(watch\.|cal\.|personal\.(noTeamWatch|watchAlways)|errors\.(watch_limit|invalid_cve|origin_not_found|cve_not_in_origin|watch_rate_limited)|details\.(moreCves|fewerCves)|glossary\.ical)/.test(
          k,
        ),
      )
    expect(mine(de).sort()).toEqual(mine(en).sort())
    expect(mine(de).length).toBeGreaterThan(70)
    for (const k of ["watch.storiesN_one", "watch.storiesN_other", "watch.hint.short.teams_off", "watch.hint.short.no_way_allowed", "errors.not_watched", "cal.entries_other"]) {
      expect(de[k], k).toBeTruthy()
    }
  })

  it("explains iCal as a term", () => {
    expect(TERMS).toContain("ical")
    expect(de["glossary.icalText"] && en["glossary.icalText"]).toBeTruthy()
  })
})

const item = (over: Partial<WatchItem> = {}): WatchItem => ({
  cve: "CVE-2026-1000",
  since: "2026-10-01T10:00:00Z",
  known: true,
  title: "Example",
  severity: "high",
  kev: null,
  epss: null,
  fixed: [],
  fixed_count: 0,
  advisories: 1,
  advisory: null,
  last_event: null,
  origin: null,
  product: { key: null, label: "", source: "none", others: [], followed: false },
  ...over,
})

describe("the watch list", () => {
  const seen = "2026-10-20T12:00:00Z"

  it("marks as new only what happened after the previous visit", () => {
    const after = item({ last_event: { what: "kev", at: "2026-10-21T08:00:00Z" } })
    expect(isNewItem(after, seen)).toBe(true)
    expect(isNewItem(after, null)).toBe(false) // the first visit: nothing is new
    expect(isNewItem(item({ last_event: { what: "fix", at: "2026-10-19T08:00:00Z" } }), seen)).toBe(false)
    expect(isNewItem(item({ last_event: { what: "fix", at: seen } }), seen)).toBe(false) // strictly after
    // watched since the last visit, nothing happened: adding it yourself is no news
    expect(isNewItem(item({ since: "2026-10-25T00:00:00Z" }), seen)).toBe(false)
    // an event from before the watch began is never this person's news
    expect(isNewItem(item({ since: "2026-10-25T00:00:00Z", last_event: { what: "kev", at: "2026-10-22T00:00:00Z" } }), seen)).toBe(false)
  })

  it("filters: KEV, without a fix, EPSS high, new", () => {
    const kev = { added: "2026-10-01", due: "", ransomware: false, name: "x" }
    expect(matchesWatchFilter(item({ kev }), "kev", seen)).toBe(true)
    expect(matchesWatchFilter(item(), "kev", seen)).toBe(false)
    expect(withoutFix(item())).toBe(true)
    expect(withoutFix(item({ fixed: ["7.4.9"], fixed_count: 1 }))).toBe(false)
    expect(withoutFix(item({ known: false }))).toBe(false) // unknown is not "no fix"
    const epss = (percentile: number | null) => item({ epss: { score: 0.3, percentile, day: "2026-10-30" } })
    expect(EPSS_HIGH).toBe(0.9) // app/cve_watch.py EPSS_PCT
    expect(matchesWatchFilter(epss(0.9), "epss", seen)).toBe(true)
    expect(matchesWatchFilter(epss(0.89), "epss", seen)).toBe(false)
    expect(matchesWatchFilter(epss(null), "epss", seen)).toBe(false)
    expect(matchesWatchFilter(item(), "all", seen)).toBe(true)
  })

  it("counts every filter at once", () => {
    const items = [
      item({ cve: "CVE-2026-1", kev: { added: "2026-10-01", due: "", ransomware: true, name: "" }, last_event: { what: "kev", at: "2026-10-21T00:00:00Z" } }),
      item({ cve: "CVE-2026-2", fixed: ["1.2"], fixed_count: 1, epss: { score: 0.5, percentile: 0.97, day: "" } }),
      item({ cve: "CVE-2026-3", known: false, severity: "info" }),
    ]
    expect(watchCounts(items, seen)).toEqual({ all: 3, kev: 1, nofix: 1, epss: 1, new: 1 })
    expect(watchCounts(items, null).new).toBe(0)
    expect(watchCounts([], seen)).toEqual({ all: 0, kev: 0, nofix: 0, epss: 0, new: 0 })
  })

  it("sorts by the last change, severity, EPSS or CVE number", () => {
    const a = item({ cve: "CVE-2026-12345", severity: "medium", since: "2026-10-01T00:00:00Z", last_event: { what: "fix", at: "2026-10-28T00:00:00Z" } })
    const b = item({ cve: "CVE-2026-9999", severity: "critical", since: "2026-10-27T00:00:00Z", epss: { score: 0.2, percentile: 0.95, day: "" } })
    const c = item({ cve: "CVE-2025-1", known: false, severity: "info", since: "2026-10-29T00:00:00Z" })
    const d = item({ cve: "CVE-2026-1234", severity: "low", since: "2026-09-01T00:00:00Z", epss: { score: 0.6, percentile: 0.99, day: "" } })
    const ids = (xs: WatchItem[]) => xs.map((x) => x.cve)
    // the newest event, else when the watch began
    expect(ids(sortWatch([a, b, c, d], "last"))).toEqual(["CVE-2025-1", "CVE-2026-12345", "CVE-2026-9999", "CVE-2026-1234"])
    expect(ids(sortWatch([a, b, c, d], "severity"))).toEqual(["CVE-2026-9999", "CVE-2026-12345", "CVE-2026-1234", "CVE-2025-1"]) // unknown last
    expect(ids(sortWatch([a, b, c, d], "epss"))).toEqual(["CVE-2026-1234", "CVE-2026-9999", "CVE-2025-1", "CVE-2026-12345"]) // no EPSS: by last change
    expect(ids(sortWatch([a, b, c, d], "cve"))).toEqual(["CVE-2025-1", "CVE-2026-1234", "CVE-2026-9999", "CVE-2026-12345"]) // by number, not as text
    const input = [a, b]
    sortWatch(input, "cve")
    expect(input).toEqual([a, b]) // a new array – the query's data stays as it was
  })

  it("reads filter and order from the address – anything else is the default", () => {
    expect(parseWatchFilter("kev")).toBe("kev")
    expect(parseWatchFilter("bogus")).toBe("all")
    expect(parseWatchFilter(null)).toBe("all")
    expect(parseWatchSort("epss")).toBe("epss")
    expect(parseWatchSort("<script>")).toBe("last")
  })

  it("offers the way to the own ways only where there is one", () => {
    expect(watchHintAction(null, true)).toBeNull()
    expect(watchHintAction("no_way_on", true)).toBe("link")
    expect(watchHintAction("no_way_on", false)).toBe("firstCve")
    expect(watchHintAction("teams_off", true)).toBe("admin")
    expect(watchHintAction("no_way_allowed", true)).toBe("admin")
    for (const r of ["teams_off", "no_way_allowed"]) {
      expect(de[`watch.hint.short.${r}`] && en[`watch.hint.short.${r}`], r).toBeTruthy()
    }
  })
})

describe("origins and groups", () => {
  const story: WatchOrigin = { kind: "story", id: "7b0c", title: "GitLab Patch Release 18.5.2" }
  const finding: WatchOrigin = { kind: "finding", product: "typo3", advisory: "nvd:CVE-2026-50030", title: "TYPO3: CVE-2026-50030" }

  it("names an origin for a request without its title, and keys and links it", () => {
    expect(originIn(story)).toEqual({ kind: "story", id: "7b0c" })
    expect(originIn(finding)).toEqual({ kind: "finding", product: "typo3", advisory: "nvd:CVE-2026-50030" })
    expect(originIn(null)).toEqual({ kind: "manual" })
    expect(originKey(story)).toBe("story:7b0c")
    expect(originKey(originIn(finding))).toBe(originKey(finding))
    expect(originKey(null)).toBe("manual")
    expect(originKey({ kind: "manual" })).toBe("manual")
    expect(originLink(story)).toBe("/?story=7b0c")
    expect(originLink(finding)).toBe("/vendor?product=typo3&finding=nvd%3ACVE-2026-50030")
    expect(originLink(null)).toBeNull()
    expect(groupHref(originIn(story))).toBe("/watch?group_by=origin&group=story%3A7b0c")
  })

  it("keeps the grouping in the address – by product unless it says otherwise", () => {
    const by = (q: string) => parseGroupBy(new URLSearchParams(q))
    expect(by("")).toBe("product")
    expect(by("filter=kev&sort=epss")).toBe("product")
    expect(by("group_by=origin")).toBe("origin")
    expect(by("group_by=none")).toBe("none")
    expect(by("group_by=nonsense")).toBe("product")
    expect(by("group=product%3Agitlab")).toBe("product")
    expect(by("group=none")).toBe("product")
    // old links (0.1.42–0.1.45): ?groups=1, and the "Zur Liste" of "Alle beobachten" – the origin grouping, at its group
    expect(by("groups=1")).toBe("origin")
    expect(by("groups=1&group=story%3A7b0c")).toBe("origin")
    expect(by("group=story%3A7b0c")).toBe("origin")
    expect(by("filter=kev&group=finding%3Apanos%3Apaloalto%3APAN-SA-2026-0042")).toBe("origin")
    expect(by("group=manual")).toBe("origin")
    expect(by("groups=0")).toBe("product")
    expect(by("group_by=none&groups=1")).toBe("none") // the new parameter wins
    expect(isOriginKey("story:x") && isOriginKey("finding:a:b") && isOriginKey("manual")).toBe(true)
    expect(isOriginKey("product:gitlab") || isOriginKey("none") || isOriginKey("name:acme")).toBe(false)
    // switching: the old parameter and a group link go; product is the default and not written
    expect(withGroupBy(new URLSearchParams("filter=kev&sort=epss"), "origin").toString()).toBe("filter=kev&sort=epss&group_by=origin")
    expect(withGroupBy(new URLSearchParams("filter=kev&groups=1&group=manual"), "none").toString()).toBe("filter=kev&group_by=none")
    expect(withGroupBy(new URLSearchParams("filter=kev&group_by=origin&group=manual"), "product").toString()).toBe("filter=kev")
    // an old "Zur Liste" link lands on the same group as the new one
    const old = new URLSearchParams("groups=1&group=story%3A7b0c")
    const now = new URL(`https://x${groupHref(originIn(story))}`).searchParams
    expect([parseGroupBy(old), old.get("group")]).toEqual([parseGroupBy(now), now.get("group")])
  })

  it("keys and links a product", () => {
    const gitlab: WatchProduct = { key: "gitlab", label: "GitLab", source: "catalog", others: [], followed: true }
    expect(productKey(gitlab)).toBe("product:gitlab")
    expect(productKey({ ...gitlab, source: "cna" })).toBe("product:gitlab") // a CNA name that is the catalogue product
    expect(productKey({ key: null, label: "  Acme   Widget Server ", source: "cna", others: [], followed: false })).toBe("name:acme-widget-server")
    expect(productKey({ key: null, label: "ACME widget server", source: "nvd", others: [], followed: false })).toBe("name:acme-widget-server")
    expect(productKey({ key: null, label: "", source: "none", others: [], followed: false })).toBe("none")
    expect(productKey(undefined)).toBe("none")
    expect(productLink(gitlab)).toBe("/vendor?product=gitlab")
    expect(productLink({ ...gitlab, key: "custom-1 2" })).toBe("/vendor?product=custom-1%202")
    expect(productLink({ key: null, label: "Acme", source: "cna", others: [], followed: false })).toBeNull()
  })

  it("groups by product: KEV or new first, then by name, the ones without a product last", () => {
    const seen = "2026-10-20T12:00:00Z"
    const p = (key: string | null, label: string, source: WatchProduct["source"] = key ? "catalog" : "cna", followed = false): WatchProduct => ({
      key,
      label,
      source,
      others: [],
      followed,
    })
    const kev = { added: "2026-10-01", due: "", ransomware: false, name: "" }
    const all = [
      item({ cve: "CVE-2026-1", product: p("typo3", "TYPO3", "catalog", true), origin: story }),
      item({ cve: "CVE-2026-2", product: p(null, "", "none") }),
      item({ cve: "CVE-2026-3", product: p("gitlab", "GitLab"), origin: story }),
      item({ cve: "CVE-2026-4", product: p("gitlab", "GitLab", "cna"), origin: finding, fixed: ["1.0"], fixed_count: 1 }),
      item({ cve: "CVE-2026-5", product: p(null, "Acme Widget", "cna"), kev }),
      item({ cve: "CVE-2026-6", product: p(null, "acme  widget", "nvd") }),
      item({ cve: "CVE-2026-7", product: p("zabbix", "Zabbix"), last_event: { what: "fix", at: "2026-10-21T00:00:00Z" } }),
      item({ cve: "CVE-2026-8", product: p(null, "", "none"), kev }),
    ]
    const groups = groupWatch(all, all, seen, "product")
    // KEV / new first (Acme, Zabbix – by name), then the rest by name (GitLab, TYPO3); without a product last even with KEV
    expect(groups.map((g) => g.key)).toEqual(["name:acme-widget", "product:zabbix", "product:gitlab", "product:typo3", "none"])
    const gl = groups[2]
    expect([gl.by, gl.total, gl.cves, gl.counts]).toEqual(["product", 2, ["CVE-2026-3", "CVE-2026-4"], { kev: 0, nofix: 1, new: 0 }])
    expect(groups[0].product?.label).toBe("Acme Widget") // the newest watch's spelling
    expect(groups[3].product?.followed).toBe(true)
    expect(groups[4].cves).toEqual(["CVE-2026-2", "CVE-2026-8"])
    // a filter within the groups: the numbers stay those of the whole group
    const fixed = groupWatch(
      all.filter((w) => w.fixed_count > 0),
      all,
      seen,
      "product",
    )
    expect(fixed.map((g) => [g.key, g.items.length, g.total])).toEqual([["product:gitlab", 1, 2]])
    // the same rows by origin: the groups of before
    expect(groupWatch(all, all, seen, "origin").map((g) => g.key)).toEqual(["finding:typo3:nvd:CVE-2026-50030", "story:7b0c", "manual"])
  })

  it("groups the list: the filter within the groups, the numbers of the whole group, the manual ones last", () => {
    const seen = "2026-10-20T12:00:00Z"
    const all = [
      item({ cve: "CVE-2026-1", origin: story, since: "2026-10-10T00:00:00Z", kev: { added: "2026-10-01", due: "", ransomware: false, name: "" } }),
      item({ cve: "CVE-2026-2", origin: story, since: "2026-10-10T00:00:00Z", fixed: ["1.0"], fixed_count: 1 }),
      item({ cve: "CVE-2026-3", origin: null, since: "2026-10-30T00:00:00Z" }),
      item({ cve: "CVE-2026-4", origin: { kind: "manual" }, since: "2026-10-01T00:00:00Z", last_event: { what: "fix", at: "2026-10-21T00:00:00Z" } }),
      item({ cve: "CVE-2026-5", origin: finding, since: "2026-10-15T00:00:00Z" }),
    ]
    const groups = groupWatch(all, all, seen)
    expect(groups.map((g) => g.key)).toEqual(["finding:typo3:nvd:CVE-2026-50030", "story:7b0c", "manual"])
    const s = groups[1]
    expect(s.origin).toEqual(story)
    expect(s.total).toBe(2)
    expect(s.counts).toEqual({ kev: 1, nofix: 1, new: 0 })
    expect(groups[2].items.map((w) => w.cve)).toEqual(["CVE-2026-3", "CVE-2026-4"]) // unknown and manual together
    expect(groups[2].counts.new).toBe(1)
    // a filter: only KEV – the story's group with one of two, the others gone
    const kev = groupWatch(
      all.filter((w) => w.kev),
      all,
      seen,
    )
    expect(kev.map((g) => [g.key, g.items.length, g.total])).toEqual([["story:7b0c", 1, 2]])
  })

  it("collects a story's CVEs once, the likeliest first", () => {
    expect(storyWatchCves(["CVE-2026-1001", "cve-2026-1002", "nope"], ["CVE-2026-1002", "CVE-2026-1003"], [{ cve: "CVE-2026-1003", score: 0.5 }])).toEqual([
      "CVE-2026-1003",
      "CVE-2026-1001",
      "CVE-2026-1002",
    ])
    expect(storyWatchCves([], [])).toEqual([])
  })

  it("knows what is not watched yet", () => {
    expect(unwatched(["CVE-2026-1", "CVE-2026-2"], new Set(["CVE-2026-2"]))).toEqual(["CVE-2026-1"])
    expect(unwatched(["CVE-2026-1"], undefined)).toEqual(["CVE-2026-1"])
  })

  it("undoes per origin", () => {
    expect(
      undoGroups([
        { cve: "CVE-2026-1", origin: story },
        { cve: "CVE-2026-2", origin: null },
        { cve: "CVE-2026-3", origin: story },
        { cve: "CVE-2026-4", origin: { kind: "manual" } },
      ]),
    ).toEqual([
      { origin: { kind: "story", id: "7b0c" }, cves: ["CVE-2026-1", "CVE-2026-3"] },
      { origin: { kind: "manual" }, cves: ["CVE-2026-2", "CVE-2026-4"] },
    ])
  })

  it("has the new texts in both languages, with plurals", () => {
    for (const k of ["watch.all.added_one", "watch.all.added_other", "watch.all.limitTitle_other", "watch.group.count_other", "details.fewerCves", "errors.watch_rate_limited"]) {
      expect(de[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
    }
  })
})
