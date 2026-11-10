import type { VendorUrlFilter } from "@/lib/reader-api"
import type { VendorScope } from "@/lib/teams-api"
import { type OverviewItem, type StatusFilter, scoreLevelOf, statusCounts, statusOf } from "@/lib/vendor-api"

/*
 * The Vendor News page's tool row (pages/vendor-overview.tsx): which filters are on (the chips under the row and the
 * number on "Filter"), what "Alle N als gelesen" means, and where the page's parts live in the address.
 */

// ---------------------------------------------------------------- the parts of the page

/** The overview, the catalogue ("Produkt hinzufügen" / "Katalog ansehen") and the suggestions – no tabs any more. */
export type VendorPlace = "overview" | "catalog" | "suggestions"

/** The part an address shows: `tab=catalog` and `tab=suggestions` of older links and bookmarks still lead there. */
export function placeOf(p: URLSearchParams): VendorPlace {
  const t = p.get("tab")
  return t === "catalog" || t === "suggestions" ? t : "overview"
}

/**
 * The address of a part, from the current one: the filters of the overview stay (back from the catalogue, they are
 * still set), the drawer closes, the catalogue's category is the catalogue's alone.
 */
export function placeLink(current: URLSearchParams, place: VendorPlace): string {
  const next = new URLSearchParams(current)
  for (const k of ["tab", "cat", "product", "finding", "view"]) next.delete(k)
  if (place !== "overview") next.set("tab", place)
  const s = next.toString()
  return s ? `?${s}` : "?"
}

// ---------------------------------------------------------------- the filters that are on

/** One chip under the tool row. `now`, `exploited` and `support` are the old summary line's filters – an older link or
 *  view still sets them; they show as a chip (removable) but are no longer offered. */
export type FilterChip = "unread" | "muted" | "confirmed" | "review" | "team" | "now" | "exploited" | "support"

/** The filters that are on, in the order of the chips. `team`: "Mein Team" is chosen (and offered at all). */
export function activeFilters(f: Pick<VendorUrlFilter, "unread" | "muted" | "filter"> & { confirmed?: boolean }, o: { team: boolean }): FilterChip[] {
  const out: FilterChip[] = []
  if (o.team) out.push("team")
  if (f.unread) out.push("unread")
  if (f.muted) out.push("muted")
  if (f.confirmed) out.push("confirmed")
  if (f.filter === "review") out.push("review")
  else if (f.filter === "now" || f.filter === "exploited" || f.filter === "support") out.push(f.filter)
  return out
}

/** What removing a chip changes in the address (`scope`: back to "Alle"). */
export function withoutChip(chip: FilterChip): { url?: Partial<VendorUrlFilter>; scope?: VendorScope } {
  if (chip === "team") return { scope: "all" }
  if (chip === "unread") return { url: { unread: false } }
  if (chip === "muted") return { url: { muted: false } }
  if (chip === "confirmed") return { url: { confirmed: false } }
  return { url: { filter: null } }
}

// ---------------------------------------------------------------- the status row

export type StatusRowCounts = Record<StatusFilter, number> & {
  /** of the products with Handlungsbedarf: those whose most urgent finding says "Sofort" */
  now: number
}

/** The four fields' numbers – over what the search and the filters leave. */
export function statusRowCounts(items: OverviewItem[]): StatusRowCounts {
  return { ...statusCounts(items), now: items.filter((i) => statusOf(i) === "action" && scoreLevelOf(i) === "now").length }
}

// ---------------------------------------------------------------- "Alle N als gelesen"

/**
 * The unread findings "Alle N als gelesen" marks among the products shown: a muted product's only with "Stummgeschaltete
 * zeigen" – one shown anyway (KEV trotz Stumm) is left by the server too (backend app/reader_api.py vendor_read_all).
 */
export function readAllCount(shown: Pick<OverviewItem, "unread" | "unread_all" | "muted">[], muted: boolean): number {
  // muted ones shown: every unread finding, also a muted product's and a muted CVE's; hidden: what the cards count
  return shown.reduce((n, i) => n + (muted ? (i.unread_all ?? i.unread ?? 0) : i.muted ? 0 : (i.unread ?? 0)), 0)
}

/** The products the request names: exactly those shown when anything narrows the list, none (= all followed) else. */
export function readAllProducts(shown: Pick<OverviewItem, "product">[], narrowed: boolean): string[] | undefined {
  return narrowed ? shown.map((i) => i.product.key) : undefined
}
