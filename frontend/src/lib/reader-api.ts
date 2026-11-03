import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { polled } from "@/lib/poll"
import { NEWS_SEVERITIES, type NewsSeverity, type NewsTopic, isTopic } from "@/lib/news-api"
import { STATUS_FILTERS, type OverviewFilter, type StatusFilter } from "@/lib/vendor-api"
import type { VendorScope } from "@/lib/teams-api"

// ---------------------------------------------------------------- the unread numbers (sidebar)

export interface ReaderCounts {
  news: number
  vendor: number
  news_enabled: boolean
}

export const COUNTS_KEY = ["reader", "counts"] as const

/** The sidebar's numbers: polled every minute, again when the window comes back into focus – cheap on the server. */
export const useReaderCounts = (scope: VendorScope) =>
  useQuery({
    queryKey: [...COUNTS_KEY, scope],
    queryFn: polled<ReaderCounts>((o) => api.get(`/api/reader/counts?scope=${scope}`, o)),
    staleTime: 60_000,
    refetchInterval: 60_000,
    refetchOnWindowFocus: true,
  })

/** A badge's text: nothing for 0, "99+" from 100 on. */
export function badgeText(n: number | null | undefined): string | null {
  if (!n || n < 0 || !Number.isFinite(n)) return null
  return n > 99 ? "99+" : String(Math.floor(n))
}

// ---------------------------------------------------------------- the URL's filters (validated – a crafted link cannot break the page)

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
/** Not a filter: the drawer and the page's sub-tab – never stored in a view, kept when a view is applied. */
export const DRAWER_PARAMS = ["story", "product", "finding", "view", "tab", "cat"] as const

export interface NewsUrlFilter {
  sources: string[]
  severities: NewsSeverity[]
  topics: NewsTopic[]
  q: string
  unread: boolean
  muted: boolean
  /** "Betrifft unsere Produkte" */
  ours: boolean
}

const on = (v: string | null) => v === "1" || v === "true"

/** The news filter of an address – unknown or malformed values are dropped (at most 50 sources, 100 characters, known topics only). */
export function readNewsFilter(p: URLSearchParams): NewsUrlFilter {
  const sources = [...new Set(p.getAll("source").filter((x) => UUID.test(x)))].slice(0, 50)
  const severities = [...new Set(p.getAll("severity"))].filter((x): x is NewsSeverity => NEWS_SEVERITIES.includes(x as NewsSeverity))
  const topics = [...new Set(p.getAll("topic"))].filter(isTopic)
  return { sources, severities, topics, q: (p.get("q") ?? "").slice(0, 100), unread: on(p.get("unread")), muted: on(p.get("muted")), ours: on(p.get("ours")) }
}

/** The filter written into an address – the other parameters (the drawer's, unknown ones) stay as they are. */
export function writeNewsFilter(p: URLSearchParams, f: Partial<NewsUrlFilter>): URLSearchParams {
  const next = new URLSearchParams(p)
  if (f.sources !== undefined) {
    next.delete("source")
    for (const s of f.sources) next.append("source", s)
  }
  if (f.severities !== undefined) {
    next.delete("severity")
    for (const s of f.severities) next.append("severity", s)
  }
  if (f.topics !== undefined) {
    next.delete("topic")
    for (const s of f.topics) next.append("topic", s)
  }
  if (f.q !== undefined) {
    if (f.q.trim()) next.set("q", f.q.trim().slice(0, 100))
    else next.delete("q")
  }
  for (const k of ["unread", "muted", "ours"] as const)
    if (f[k] !== undefined) {
      if (f[k]) next.set(k, "1")
      else next.delete(k)
    }
  next.delete("tab") // the old "Neu | Gelesen" tabs
  return next
}

export interface VendorUrlFilter {
  status: StatusFilter | null
  filter: OverviewFilter | null
  q: string
  unread: boolean
  muted: boolean
}

const SUMMARY: OverviewFilter[] = ["now", "exploited", "support", "review"]

export function readVendorFilter(p: URLSearchParams): VendorUrlFilter {
  const st = p.get("status")
  const f = p.get("filter")
  return {
    // "action" in `filter` is an older link's way of saying the status row's "Handlungsbedarf"
    status: STATUS_FILTERS.includes(st as StatusFilter) ? (st as StatusFilter) : f === "action" ? "action" : null,
    filter: SUMMARY.includes(f as OverviewFilter) ? (f as OverviewFilter) : null,
    q: (p.get("q") ?? "").slice(0, 80),
    unread: on(p.get("unread")),
    muted: on(p.get("muted")),
  }
}

export function writeVendorFilter(p: URLSearchParams, f: Partial<VendorUrlFilter>): URLSearchParams {
  const next = new URLSearchParams(p)
  const put = (k: string, v: string | null | undefined) => {
    if (v === undefined) return
    if (v) next.set(k, v)
    else next.delete(k)
  }
  put("status", f.status === undefined ? undefined : f.status && f.status !== "all" ? f.status : null)
  put("filter", f.filter === undefined ? undefined : f.filter)
  put("q", f.q === undefined ? undefined : f.q.trim().slice(0, 80))
  put("unread", f.unread === undefined ? undefined : f.unread ? "1" : null)
  put("muted", f.muted === undefined ? undefined : f.muted ? "1" : null)
  return next
}

/** Filters of the News page only: on Vendor News they are no filter (a `topic` or `ours` there is neither a view nor a
 *  reason to skip the default view – readVendorFilter ignores them as well). */
export const NEWS_ONLY_PARAMS = ["topic", "ours"] as const

const notAFilter = (k: string, page?: ViewPage) => (DRAWER_PARAMS as readonly string[]).includes(k) || (page === "vendor" && (NEWS_ONLY_PARAMS as readonly string[]).includes(k))

/** Whether an address carries any filter (what a default view replaces) – the drawer's parameters do not count, nor on
 *  Vendor News the News page's own filters. */
export function hasFilter(p: URLSearchParams, page?: ViewPage): boolean {
  return [...p.keys()].some((k) => !notAFilter(k, page))
}

/** The query a view stores: the address without the drawer's parameters (and without "?"); on Vendor News also without
 *  the News page's own filters. */
export function viewQuery(p: URLSearchParams, page?: ViewPage): string {
  const next = new URLSearchParams()
  for (const [k, v] of p) if (!notAFilter(k, page)) next.append(k, v)
  return next.toString()
}

/** A view applied: its filter, the drawer's parameters of the current address kept (an open story stays open). */
export function applyView(current: URLSearchParams, query: string): URLSearchParams {
  const next = new URLSearchParams(query.replace(/^\?/, ""))
  for (const k of DRAWER_PARAMS) {
    next.delete(k)
    for (const v of current.getAll(k)) next.append(k, v)
  }
  return next
}

/** The shareable address of a view: the page and its filter – the receiver just gets the same filters. */
export function viewLink(origin: string, page: ViewPage, query: string): string {
  const path = page === "news" ? "/" : "/vendor"
  const q = query.replace(/^\?/, "")
  return `${origin}${path}${q ? `?${q}` : ""}`
}

/** In-page changes of the address carry this state: a default view is applied only when one arrives from outside. */
export const IN_PAGE = { inPage: true } as const
export const fromOutside = (state: unknown) => !(state && typeof state === "object" && (state as { inPage?: unknown }).inPage)

// ---------------------------------------------------------------- saved views

export type ViewPage = "news" | "vendor"
export const VIEW_NAME_MAX = 60

export interface SavedView {
  id: string
  page: ViewPage
  name: string
  query: string
  default: boolean
  updated_at: string
}

export const viewsKey = (page: ViewPage) => ["me", "views", page] as const

export const useViews = (page: ViewPage) =>
  useQuery({ queryKey: viewsKey(page), queryFn: () => api.get<{ items: SavedView[]; max: number }>(`/api/me/views?page=${page}`), staleTime: 5 * 60_000 })

export function useViewMutations(page: ViewPage) {
  const qc = useQueryClient()
  const done = () => void qc.invalidateQueries({ queryKey: viewsKey(page) })
  return {
    add: useMutation({ mutationFn: (b: { name: string; query: string; default: boolean }) => api.post<SavedView>("/api/me/views", { page, ...b }), onSettled: done }),
    patch: useMutation({
      mutationFn: ({ id, ...b }: { id: string; name?: string; query?: string; default?: boolean }) => api.patch<SavedView>(`/api/me/views/${id}`, b),
      onSettled: done,
    }),
    remove: useMutation({ mutationFn: (id: string) => api.del(`/api/me/views/${id}`), onSettled: done }),
  }
}

/** A name as stored: trimmed, at most 60 characters, no control characters ("" when nothing is left). */
export function cleanViewName(v: string): string {
  const printable = [...v].filter((c) => c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) !== 0x7f).join("")
  return printable.trim().slice(0, VIEW_NAME_MAX)
}

// ---------------------------------------------------------------- mutes

export type MuteKind = "product" | "cve"

export interface Mute {
  id: string
  kind: MuteKind
  key: string
  label: string
  until: string
  created_at: string
}

export const MUTES_KEY = ["me", "mutes"] as const

export const useMutes = () => useQuery({ queryKey: MUTES_KEY, queryFn: () => api.get<{ items: Mute[]; max: number }>("/api/me/mutes"), staleTime: 60_000 })

/** After a mute changes: the lists that dim or hide what is muted, and the numbers. */
export function refreshMuted(qc: ReturnType<typeof useQueryClient>) {
  void qc.invalidateQueries({ queryKey: MUTES_KEY })
  void qc.invalidateQueries({ queryKey: COUNTS_KEY })
  void qc.invalidateQueries({ queryKey: ["news", "list"] })
  void qc.invalidateQueries({ queryKey: ["news", "detail"] })
  void qc.invalidateQueries({ queryKey: ["vendor", "overview"] })
  void qc.invalidateQueries({ queryKey: ["vendor", "product"] })
}

export function useMuteMutations() {
  const qc = useQueryClient()
  return {
    add: useMutation({
      mutationFn: (b: { kind: MuteKind; key: string; days?: number; until?: string }) => api.post<Mute>("/api/me/mutes", b),
      onSettled: () => refreshMuted(qc),
    }),
    remove: useMutation({ mutationFn: (id: string) => api.del(`/api/me/mutes/${id}`), onSettled: () => refreshMuted(qc) }),
  }
}

/** What is left of a mute: whole days, else hours, else minutes (never negative). */
export function remaining(until: string, now: number = Date.now()): { unit: "days" | "hours" | "minutes"; count: number } {
  const ms = Math.max(0, new Date(until).getTime() - now)
  const h = ms / 3_600_000
  if (h >= 48) return { unit: "days", count: Math.floor(h / 24) }
  if (h >= 1) return { unit: "hours", count: Math.floor(h) }
  return { unit: "minutes", count: Math.max(1, Math.ceil(ms / 60_000)) }
}

/** "bis zum" a day picked in a date field: the end of that day in the browser's time zone, as an ISO time. */
export function untilEndOf(day: string): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day)
  if (!m) return null
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 0)
  return Number.isNaN(d.getTime()) ? null : d.toISOString()
}

// ---------------------------------------------------------------- Vendor News read state

export const useVendorRead = () => {
  const qc = useQueryClient()
  const settle = () => {
    void qc.invalidateQueries({ queryKey: COUNTS_KEY })
    void qc.invalidateQueries({ queryKey: ["vendor", "overview"] })
  }
  return {
    read: useMutation({
      mutationFn: (b: { product: string; finding?: string; upto?: string }) => api.post<{ marked: number }>("/api/vendor/read", b),
      onSettled: settle,
    }),
    unread: useMutation({
      mutationFn: (b: { product: string; finding: string }) => api.post("/api/vendor/unread", b),
      onSettled: (_d, _e, b) => {
        settle()
        void qc.invalidateQueries({ queryKey: ["vendor", "product", b.product] })
      },
    }),
    readAll: useMutation({
      mutationFn: (b: { products?: string[]; upto?: string; muted?: boolean }) => api.post<{ marked: number }>("/api/vendor/read-all", b),
      onSettled: () => {
        settle()
        void qc.invalidateQueries({ queryKey: ["vendor", "product"] })
      },
    }),
  }
}

/**
 * The Vendor News products a person's read state and mutes leave in the list: muted ones only with "Stummgeschaltete
 * zeigen" – except one an exploited vulnerability affects (shown with its badge, never hidden); "Nur ungelesene": those
 * with unread findings (and that exploited muted one).
 */
export function readerVisible<T extends { unread?: number; muted?: { until: string } | null; muted_kev?: boolean }>(items: T[], f: { unread: boolean; muted: boolean }): T[] {
  return items.filter((i) => {
    if (i.muted && !f.muted && !i.muted_kev) return false
    if (f.unread && !(i.unread ?? 0) && !(i.muted && i.muted_kev)) return false
    return true
  })
}
