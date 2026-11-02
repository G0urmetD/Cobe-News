import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { applyView, readVendorFilter } from "@/lib/reader-api"
import type { OverviewItem } from "@/lib/vendor-api"
import { activeFilters, placeLink, placeOf, readAllCount, readAllProducts, statusRowCounts, withoutChip } from "@/lib/vendor-filters"

/** Just what the status row, the chips and "Alle als gelesen" look at. */
function item(
  key: string,
  o: { affected?: number; possible?: number; level?: "now" | "soon" | "plan"; ended?: boolean; unread?: number; unread_all?: number; muted?: boolean; kev?: boolean } = {},
): OverviewItem {
  return {
    product: { key, label: key },
    versions: [],
    summary: { worst: "none", per_version: {} },
    releases: o.ended ? [{ version_id: "v", eol_state: "past", line: null }] : [],
    counts: { affected: o.affected ?? 0, possible: o.possible ?? 0, service: 0, unversioned: 0, critical: 0, exploited: 0 },
    latest: [],
    score: o.level ? { level: o.level } : null,
    unread: o.unread ?? 0,
    unread_all: o.unread_all ?? o.unread ?? 0,
    muted: o.muted ? { until: "2099-01-01T00:00:00Z" } : null,
    muted_kev: o.kev ?? false,
  } as unknown as OverviewItem
}

describe("the parts of the page in the address", () => {
  it("old ?tab= links still lead to the catalogue and the suggestions, anything else is the overview", () => {
    expect(placeOf(new URLSearchParams("tab=catalog"))).toBe("catalog")
    expect(placeOf(new URLSearchParams("tab=suggestions&product=panos"))).toBe("suggestions")
    expect(placeOf(new URLSearchParams("tab=overview"))).toBe("overview")
    expect(placeOf(new URLSearchParams("tab=<script>"))).toBe("overview")
    expect(placeOf(new URLSearchParams(""))).toBe("overview")
  })
  it("going there keeps the overview's filters, closes the drawer; back drops the catalogue's category", () => {
    const here = new URLSearchParams("status=action&unread=1&product=panos&view=versions&finding=x")
    expect(placeLink(here, "catalog")).toBe("?status=action&unread=1&tab=catalog")
    expect(placeLink(new URLSearchParams("status=action&tab=catalog&cat=firewall"), "overview")).toBe("?status=action")
    expect(placeLink(new URLSearchParams("tab=suggestions"), "overview")).toBe("?")
    expect(placeLink(new URLSearchParams("tab=catalog&cat=os"), "suggestions")).toBe("?tab=suggestions")
  })
  it("an old saved view with tab= neither moves the page nor loses its filters", () => {
    const applied = applyView(new URLSearchParams("tab=catalog"), "tab=suggestions&status=check&muted=1")
    expect(placeOf(applied)).toBe("catalog")
    expect(readVendorFilter(applied)).toMatchObject({ status: "check", muted: true })
    expect(placeOf(applyView(new URLSearchParams(""), "tab=catalog&unread=1"))).toBe("overview")
  })
})

describe("the filters that are on", () => {
  const f = (q: string) => readVendorFilter(new URLSearchParams(q))
  it("counts the switches, the team and the old summary filters – status and search are not chips", () => {
    expect(activeFilters(f("status=action&q=pan"), { team: false })).toEqual([])
    expect(activeFilters(f("unread=1&muted=1&filter=review"), { team: true })).toEqual(["team", "unread", "muted", "review"])
    // an older link's "Sofort", "aktiv ausgenutzt", "Support endet": still applied, shown as a chip to remove
    expect(activeFilters(f("filter=now"), { team: false })).toEqual(["now"])
    expect(activeFilters(f("filter=exploited&unread=1"), { team: false })).toEqual(["unread", "exploited"])
    expect(activeFilters(f("filter=support"), { team: false })).toEqual(["support"])
    // "filter=action" of an older link is the status row's Handlungsbedarf, not a chip
    expect(activeFilters(f("filter=action"), { team: false })).toEqual([])
    expect(f("filter=action").status).toBe("action")
  })
  it("removing a chip changes just its own filter", () => {
    expect(withoutChip("team")).toEqual({ scope: "all" })
    expect(withoutChip("unread")).toEqual({ url: { unread: false } })
    expect(withoutChip("muted")).toEqual({ url: { muted: false } })
    for (const c of ["review", "now", "exploited", "support"] as const) expect(withoutChip(c)).toEqual({ url: { filter: null } })
  })
})

describe("the status row", () => {
  it("one field per product, Sofort counted inside Handlungsbedarf", () => {
    const c = statusRowCounts([
      item("a", { affected: 2, level: "now" }),
      item("b", { affected: 1, level: "soon" }),
      item("c", { ended: true, level: "now" }),
      item("d", { possible: 3, level: "now" }), // "Sofort" but only "möglicherweise": not in Handlungsbedarf's number
      item("e"),
    ])
    expect(c).toEqual({ action: 3, check: 1, ok: 1, all: 5, now: 2 })
    expect(statusRowCounts([])).toEqual({ action: 0, check: 0, ok: 0, all: 0, now: 0 })
  })
})

describe("Alle N als gelesen", () => {
  // the server reports a muted product's unread as 0 and its findings in unread_all; "a" has one muted CVE finding
  const shown = [item("a", { unread: 3, unread_all: 4 }), item("b", { unread: 0, unread_all: 2, muted: true, kev: true }), item("c")]
  it("counts what the server marks: muted findings only with 'Stummgeschaltete zeigen'", () => {
    expect(readAllCount(shown, false)).toBe(3)
    expect(readAllCount(shown, true)).toBe(6)
    expect(readAllCount([], true)).toBe(0)
  })
  it("names exactly the products shown when the list is narrowed, none (all followed) else", () => {
    expect(readAllProducts(shown, true)).toEqual(["a", "b", "c"])
    expect(readAllProducts(shown, false)).toBeUndefined()
  })
})

describe("i18n", () => {
  it("has the tool row's texts in German and English", () => {
    const keys = (m: Record<string, string>) => Object.keys(m).filter((k) => /^vendor\.(head|filters|layout)\.|^vendor\.show\.|^reader\.views\.|^reader\.vendorReadAllN/.test(k))
    expect(keys(de).sort()).toEqual(keys(en).sort())
    for (const k of ["vendor.head.nextEnd", "vendor.filters.button", "vendor.show.okShort", "reader.views.current", "reader.vendorReadAllN_other"]) expect(de[k]).toBeTruthy()
  })
})
