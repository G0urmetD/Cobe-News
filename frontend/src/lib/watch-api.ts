import { useQuery } from "@tanstack/react-query"
import { ApiError, api } from "@/lib/api"
import type { Epss } from "@/lib/vendor-api"
import type { PersonalWay } from "@/lib/teams-api"

/** CVE beobachten (app/watch_api.py) and the calendar feed (app/calendar_feed.py) – the signed-in person's own. */

export const CVE_ID = /^CVE-\d{4}-\d{4,12}$/

/** The CVE id as the server keeps it (trimmed, upper case) – or null: not one. */
export function normalizeCve(value: string): string | null {
  const c = value.trim().toUpperCase()
  return CVE_ID.test(c) ? c : null
}

export interface WatchItem {
  cve: string
  since: string
  /** a source of Cobe News knows it (an advisory, KEV or EPSS) */
  known: boolean
  title: string
  severity: string
  kev: { added: string; due: string; ransomware: boolean; name: string } | null
  epss: { score: number; percentile: number | null; day: string } | null
  fixed: string[]
  fixed_count: number
  advisories: number
  /** the advisory to open (the vendor's own first) – a web address */
  advisory: { source: string; ident: string; url: string } | null
  /** the newest event since this person began watching */
  last_event: { what: WatchWhat; at: string } | null
  /** where it was watched from (the title as it was then); null: watched before 0.1.42 – counted with the manual ones */
  origin: WatchOrigin | null
  /** the product it concerns, worked out by the server on every read (app/watch_product.py) */
  product: WatchProduct
}

/** The product of a watched CVE: a catalogue product (`key` – the advisories are linked to it, or the CNA's / the NVD's
 * names are exactly its), else the name the CNA or the NVD's CPE gives (`key` null), else none. `others`: the further
 * products the same source names (labels). */
export interface WatchProduct {
  key: string | null
  label: string
  source: "catalog" | "cna" | "nvd" | "none"
  others: string[]
  /** a product this installation follows in Vendor News */
  followed: boolean
}

/** Where a watch comes from, as the server keeps it (app/cve_watch.py origin_out). */
export type WatchOrigin = { kind: "story"; id: string; title: string } | { kind: "finding"; product: string; advisory: string; title: string } | { kind: "manual" }

/** …and as a request names it: the server looks the title up itself (app/watch_api.py). */
export type WatchOriginIn = { kind: "story"; id: string } | { kind: "finding"; product: string; advisory: string } | { kind: "manual" }

export type WatchWhat = "kev" | "fix" | "epss" | "withdrawn"
export type WatchReason = "teams_off" | "no_way_allowed" | "no_way_on" | null

export interface WatchList {
  items: WatchItem[]
  limit: number
  notify: { teams_on: boolean; allowed: Record<PersonalWay, boolean>; ways: Record<PersonalWay, boolean>; reason: WatchReason }
  /** the person's previous visit of the list (null: never) – what happened after it is "new" */
  seen_before: string | null
}

/** One entry of a watched CVE's timeline (GET /api/me/cve-watch/{cve}/events). */
export type WatchEvent =
  | { what: "fix"; at: string; fixed: string[]; more: number; by: { source: string; ident: string }[] }
  | { what: "kev"; at: string; added: string; due: string; ransomware: boolean }
  | { what: "epss"; at: string; score: number | null; percentile: number | null; from: number | null; reasons: string[] }
  | { what: "withdrawn"; at: string; source: string; ident: string }

export interface WatchEvents {
  cve: string
  since: string
  /** newest first, since the watch began (at most 50) */
  events: WatchEvent[]
  /** stories the story list's search finds for it (/?q=<CVE>) */
  stories: number
}

export const WATCH_KEY = ["me", "cve-watch"] as const
export const WATCH_IDS_KEY = ["me", "cve-watch", "ids"] as const

export const useWatchList = () => useQuery({ queryKey: WATCH_KEY, queryFn: () => api.get<WatchList>("/api/me/cve-watch"), staleTime: 30_000 })

export const useWatchIds = () =>
  useQuery({ queryKey: WATCH_IDS_KEY, queryFn: () => api.get<{ cves: string[] }>("/api/me/cve-watch/ids"), staleTime: 60_000, select: (d) => new Set(d.cves) })

/** The timeline of one watched CVE – loaded when its row opens; under WATCH_KEY, so the list's invalidation reaches it. */
export const useWatchEvents = (cve: string, enabled: boolean) =>
  useQuery({
    queryKey: [...WATCH_KEY, "events", cve],
    queryFn: () => api.get<WatchEvents>(`/api/me/cve-watch/${encodeURIComponent(cve)}/events`),
    enabled,
    staleTime: 30_000,
  })

/** The person has seen the list now (once per visit). */
export const markWatchSeen = () => api.post<{ seen_at: string }>("/api/me/cve-watch/seen")

/** One CVE – with where it is watched from (a story's or a finding's star; typed on the list: manual). */
export const watchCve = (cve: string, origin?: WatchOriginIn) => api.post<{ cve: string; added: boolean }>("/api/me/cve-watch", origin ? { cve, origin } : { cve })
export const unwatchCve = (cve: string) => api.del<{ cve: string; removed: boolean }>(`/api/me/cve-watch/${encodeURIComponent(cve)}`)

/** The most CVEs one "Alle beobachten" sends (app/cve_watch.py BULK_MAX). */
export const BULK_MAX = 500

export interface BulkResult {
  added: string[]
  /** watched already – they keep their first origin */
  already: string[]
  /** did not fit any more (only with `partial`) */
  skipped: string[]
  limit: number
  count: number
}

/** "Alle beobachten": these CVEs with this origin. Without `partial` more than fit is refused (409 watch_limit with
 * `free` and `wanted`); with it the first that fit are watched, in the given order. */
export const watchCves = (cves: string[], origin: WatchOriginIn, partial = false) =>
  api.post<BulkResult>("/api/me/cve-watch/bulk", { cves: cves.slice(0, BULK_MAX), origin, partial })

export type Removed = { cve: string; origin: WatchOrigin | null }[]

/** "Alle nicht mehr beobachten" of a story – these CVEs, whatever their origin. */
export const unwatchCves = (cves: string[]) => api.post<{ removed: Removed }>("/api/me/cve-watch/bulk-remove", { cves })
/** "Gruppe nicht mehr beobachten": one group of the list. */
export const unwatchGroup = (group: WatchOriginIn) => api.post<{ removed: Removed }>("/api/me/cve-watch/bulk-remove", { group })

/** The EPSS of a watched CVE in the shape of the EPSS chip. */
export const watchEpss = (w: WatchItem): Epss | null => (w.epss ? { cve: w.cve, score: w.epss.score, percentile: w.epss.percentile, date: w.epss.day } : null)

/** Why nothing reaches the person – the text key of the hint (null: at least one way is on). */
export function watchHintKey(reason: WatchReason): string | null {
  return reason ? `watch.hint.${reason}` : null
}

// ---------------------------------------------------------------- the list: filters, order, "new"

/** The EPSS percentile from which the server notifies (app/cve_watch.py EPSS_PCT) – the filter "EPSS hoch". */
export const EPSS_HIGH = 0.9

export const WATCH_FILTERS = ["all", "kev", "nofix", "epss", "new"] as const
export type WatchFilter = (typeof WATCH_FILTERS)[number]
export const WATCH_SORTS = ["last", "severity", "epss", "cve"] as const
export type WatchSort = (typeof WATCH_SORTS)[number]

export const parseWatchFilter = (v: string | null): WatchFilter => ((WATCH_FILTERS as readonly string[]).includes(v ?? "") ? (v as WatchFilter) : "all")
export const parseWatchSort = (v: string | null): WatchSort => ((WATCH_SORTS as readonly string[]).includes(v ?? "") ? (v as WatchSort) : "last")

const time = (iso: string | null | undefined) => {
  const n = iso ? Date.parse(iso) : NaN
  return Number.isNaN(n) ? null : n
}

/** Something happened to it after the previous visit (`seenBefore`; null: the first visit – nothing is new). Starting to
 * watch it is not news: only an event counts, and only one since the watch began. */
export function isNewItem(w: WatchItem, seenBefore: string | null): boolean {
  const seen = time(seenBefore)
  const at = time(w.last_event?.at)
  const since = time(w.since)
  if (seen === null || at === null) return false
  return at > seen && (since === null || at >= since)
}

/** No fixed version known – for a CVE a source knows (an unknown one is no "Ohne Fix", it is not known at all). */
export const withoutFix = (w: WatchItem) => w.known && w.fixed_count === 0
export const epssHigh = (w: WatchItem) => w.epss?.percentile != null && w.epss.percentile >= EPSS_HIGH

export function matchesWatchFilter(w: WatchItem, f: WatchFilter, seenBefore: string | null): boolean {
  switch (f) {
    case "kev":
      return w.kev !== null
    case "nofix":
      return withoutFix(w)
    case "epss":
      return epssHigh(w)
    case "new":
      return isNewItem(w, seenBefore)
    default:
      return true
  }
}

export function watchCounts(items: WatchItem[], seenBefore: string | null): Record<WatchFilter, number> {
  const out: Record<WatchFilter, number> = { all: 0, kev: 0, nofix: 0, epss: 0, new: 0 }
  for (const w of items) for (const f of WATCH_FILTERS) if (matchesWatchFilter(w, f, seenBefore)) out[f]++
  return out
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

/** When it last changed for this person: its newest event, else when the watch began. */
export const lastChange = (w: WatchItem) => time(w.last_event?.at) ?? time(w.since) ?? 0

/** CVE-2026-1234 < CVE-2026-12345 < CVE-2027-1: by year, then by number. */
function cveOrder(a: string, b: string): number {
  const pa = /^CVE-(\d+)-(\d+)$/.exec(a)
  const pb = /^CVE-(\d+)-(\d+)$/.exec(b)
  if (!pa || !pb) return a.localeCompare(b)
  return Number(pa[1]) - Number(pb[1]) || Number(pa[2]) - Number(pb[2])
}

/** The list's order: the latest change first (default), the most severe, the highest EPSS, or by CVE number. Ties: the
 * latest change, then the CVE. A CVE no source knows has no severity and no EPSS – it goes last there. */
export function sortWatch(items: WatchItem[], sort: WatchSort): WatchItem[] {
  const byLast = (a: WatchItem, b: WatchItem) => lastChange(b) - lastChange(a) || cveOrder(a.cve, b.cve)
  const sev = (w: WatchItem) => (w.known ? (SEV_RANK[w.severity] ?? 0) : -1)
  const cmp: Record<WatchSort, (a: WatchItem, b: WatchItem) => number> = {
    last: byLast,
    severity: (a, b) => sev(b) - sev(a) || byLast(a, b),
    epss: (a, b) => (b.epss?.score ?? -1) - (a.epss?.score ?? -1) || byLast(a, b),
    cve: (a, b) => cveOrder(a.cve, b.cve),
  }
  return [...items].sort(cmp[sort])
}

/** What the notification hint offers: the way to the own ways ("link"), the note that they open with the first watched
 * CVE ("firstCve"), or only an admin can help ("admin"); null – a way is on, no hint. */
export function watchHintAction(reason: WatchReason, personalAvailable: boolean): "link" | "firstCve" | "admin" | null {
  if (!reason) return null
  if (reason === "no_way_on") return personalAvailable ? "link" : "firstCve"
  return "admin"
}

// ---------------------------------------------------------------- origins and groups

/** The origin as a request names it (no title); none – manual. */
export function originIn(o: WatchOrigin | WatchOriginIn | null | undefined): WatchOriginIn {
  if (o?.kind === "story") return { kind: "story", id: o.id }
  if (o?.kind === "finding") return { kind: "finding", product: o.product, advisory: o.advisory }
  return { kind: "manual" }
}

/** The key of a group of the list (and of ?group=): story:<id>, finding:<product>:<advisory>, manual. */
export function originKey(o: WatchOrigin | WatchOriginIn | null | undefined): string {
  if (o?.kind === "story") return `story:${o.id}`
  if (o?.kind === "finding") return `finding:${o.product}:${o.advisory}`
  return "manual"
}

/** Where the group header leads: the story's drawer, the finding in Vendor News – none for the manual ones. */
export function originLink(o: WatchOrigin | null | undefined): string | null {
  if (o?.kind === "story") return `/?story=${encodeURIComponent(o.id)}`
  if (o?.kind === "finding") return `/vendor?product=${encodeURIComponent(o.product)}&finding=${encodeURIComponent(o.advisory)}`
  return null
}

/** How the list is grouped: by the product the CVEs concern (the default), by where they were watched from, or not. */
export const WATCH_GROUP_BYS = ["none", "product", "origin"] as const
export type WatchGroupBy = (typeof WATCH_GROUP_BYS)[number]

/** A group key of the origin grouping (story:<id>, finding:<product>:<advisory>, manual). */
export const isOriginKey = (key: string) => key === "manual" || key.startsWith("story:") || key.startsWith("finding:")

/** The grouping in the address: ?group_by=product|origin|none (none given: product). Older links: ?groups=1 is the
 * origin grouping, and so is a ?group=<key> of an origin group (the "Zur Liste" of 0.1.42–0.1.45). */
export function parseGroupBy(params: URLSearchParams): WatchGroupBy {
  const v = params.get("group_by")
  if ((WATCH_GROUP_BYS as readonly string[]).includes(v ?? "")) return v as WatchGroupBy
  if (params.get("groups") === "1") return "origin"
  const g = params.get("group")
  if (g && isOriginKey(g)) return "origin"
  return "product"
}

/** The list's address for another grouping (other filters stay; the old ?groups= and a group link go). */
export function withGroupBy(params: URLSearchParams, by: WatchGroupBy): URLSearchParams {
  const next = new URLSearchParams(params)
  next.delete("groups")
  next.delete("group")
  if (by === "product") next.delete("group_by")
  else next.set("group_by", by)
  return next
}

/** "Zur Liste" after "Alle beobachten": the list grouped by origin, at that group. */
export const groupHref = (o: WatchOriginIn) => `/watch?group_by=origin&group=${encodeURIComponent(originKey(o))}`

/** A name as the server groups it (app/watch_product.py fold): trimmed, single spaces, case-insensitive. */
export const foldName = (s: string) => s.replace(/\s+/g, " ").trim().toLowerCase()

/** The key of a product group (and of ?group=): product:<catalogue key>, name:<the name, folded> (a CNA's or the
 * NVD's name), none. */
export function productKey(p: WatchProduct | null | undefined): string {
  if (p?.key) return `product:${p.key}`
  if (p && p.source !== "none" && p.label.trim()) return `name:${foldName(p.label).replace(/ /g, "-")}`
  return "none"
}

/** Where a product group's header leads: the product in Vendor News (a catalogue product) – none for a mere name. */
export const productLink = (p: WatchProduct | null | undefined) => (p?.key ? `/vendor?product=${encodeURIComponent(p.key)}` : null)

/** The group a row belongs to under a grouping. */
export const groupKeyOf = (w: WatchItem, by: Exclude<WatchGroupBy, "none">) => (by === "origin" ? originKey(w.origin) : productKey(w.product))

export interface WatchGroup {
  key: string
  by: Exclude<WatchGroupBy, "none">
  /** the origin of its first row (by origin – all rows share it; the manual one: null or manual) */
  origin: WatchOrigin | null
  /** the product of its first row (by product – all rows share its key; the label of the newest watch) */
  product: WatchProduct | null
  /** the rows the filter lets through, in the list's order */
  items: WatchItem[]
  /** all of the group's rows (the header's numbers) */
  total: number
  /** the CVEs of all its rows ("Gruppe nicht mehr beobachten" of a product group) */
  cves: string[]
  counts: { kev: number; nofix: number; new: number }
}

/** The list in groups: `shown` (filtered and sorted) within its group, the numbers of the whole group from `all`; a
 * group the filter empties is left out. By origin: the group watched last first, the manual ones at the end. By
 * product: the groups with KEV or something new first, then by name; "Ohne Produktzuordnung" at the end. */
export function groupWatch(shown: WatchItem[], all: WatchItem[], seenBefore: string | null, by: Exclude<WatchGroupBy, "none"> = "origin"): WatchGroup[] {
  const groups = new Map<string, WatchGroup & { latest: number }>()
  for (const w of all) {
    const key = groupKeyOf(w, by)
    let g = groups.get(key)
    if (!g) {
      g = { key, by, origin: w.origin, product: w.product ?? null, items: [], total: 0, cves: [], counts: { kev: 0, nofix: 0, new: 0 }, latest: 0 }
      groups.set(key, g)
    }
    g.total++
    g.cves.push(w.cve)
    if (w.kev) g.counts.kev++
    if (withoutFix(w)) g.counts.nofix++
    if (isNewItem(w, seenBefore)) g.counts.new++
    g.latest = Math.max(g.latest, time(w.since) ?? 0)
    if (!g.origin && w.origin) g.origin = w.origin
    // a product group: followed when its product is (any row says so – they share the key)
    if (g.product && w.product?.followed && !g.product.followed) g.product = { ...g.product, followed: true }
  }
  for (const w of shown) groups.get(groupKeyOf(w, by))?.items.push(w)
  const last = by === "origin" ? "manual" : "none"
  const hot = (g: WatchGroup) => Number(g.counts.kev > 0 || g.counts.new > 0)
  const name = (g: WatchGroup) => g.product?.label ?? ""
  return [...groups.values()]
    .filter((g) => g.items.length > 0)
    .sort(
      (a, b) =>
        Number(a.key === last) - Number(b.key === last) ||
        (by === "origin" ? b.latest - a.latest : hot(b) - hot(a) || name(a).localeCompare(name(b), undefined, { sensitivity: "base" })) ||
        a.key.localeCompare(b.key),
    )
    .map(({ latest: _latest, ...g }) => g)
}

/** The CVEs of a story for "Alle beobachten": its own and its details', once each, the likeliest (EPSS) first, the
 * others in their order. */
export function storyWatchCves(cves: string[], detailCves: string[] = [], epss: { cve: string; score: number }[] = []): string[] {
  const ids = [...new Set([...cves, ...detailCves].map((c) => normalizeCve(c)).filter((c): c is string => !!c))]
  const score = new Map(epss.map((e) => [e.cve.toUpperCase(), e.score]))
  return ids
    .map((c, i) => ({ c, i, s: score.get(c) ?? -1 }))
    .sort((a, b) => b.s - a.s || a.i - b.i)
    .map((x) => x.c)
}

/** What "Alle beobachten" would add (not watched yet, in order) – none: all are watched, the button stops instead. */
export const unwatched = (cves: string[], watched: Set<string> | undefined) => cves.filter((c) => !watched?.has(c))

/** The undo of a removal: per origin the CVEs to watch again (in the order they went). */
export function undoGroups(removed: Removed): { origin: WatchOriginIn; cves: string[] }[] {
  const out = new Map<string, { origin: WatchOriginIn; cves: string[] }>()
  for (const r of removed) {
    const key = originKey(r.origin)
    const g = out.get(key) ?? { origin: originIn(r.origin), cves: [] }
    g.cves.push(r.cve)
    out.set(key, g)
  }
  return [...out.values()]
}

/** Undo: watch what went again, each with its origin (from now on). A story or finding no longer there (or no longer
 * naming the CVE): watched as a manual one rather than not at all. Returns how many are watched again. */
export async function rewatch(removed: Removed): Promise<number> {
  let n = 0
  for (const g of undoGroups(removed)) {
    try {
      n += (await watchCves(g.cves, g.origin, true)).added.length
    } catch (e) {
      if (!(e instanceof ApiError && (e.code === "origin_not_found" || e.code === "cve_not_in_origin") && g.origin.kind !== "manual")) throw e
      n += (await watchCves(g.cves, { kind: "manual" }, true)).added.length
    }
  }
  return n
}

// ---------------------------------------------------------------- the calendar feed

export interface CalendarState {
  active: boolean
  created_at: string | null
  last_used_at: string | null
  /** an admin's feed: every followed product; a reader's: the products of their team routing */
  scope: "all" | "teams"
  teams_on: boolean
  /** versions with a known end of support in it now */
  entries: number
}

export const CALENDAR_KEY = ["me", "calendar"] as const
export const useCalendar = () => useQuery({ queryKey: CALENDAR_KEY, queryFn: () => api.get<CalendarState>("/api/me/calendar"), staleTime: 30_000 })
export const makeCalendar = () => api.post<{ url: string; created_at: string }>("/api/me/calendar")
export const deleteCalendar = () => api.del<{ removed: boolean }>("/api/me/calendar")

/** The same address for clients that open webcal:// (Apple Calendar, Outlook on the desktop). */
export function webcalUrl(url: string): string {
  return url.replace(/^https?:\/\//i, "webcal://")
}
