import { keepPreviousData, useQuery } from "@tanstack/react-query"
import type { TFunction } from "i18next"
import { api, DETAIL_TIMEOUT_MS, detailRetry } from "@/lib/api"
import { polled } from "@/lib/poll"

/** Quellen-Gesundheit – backend app/source_health.py (states and thresholds documented there and in docs/BETRIEB.md). */
export type HealthState = "healthy" | "slow" | "disturbed" | "dead" | "off" | "never"
/** news feeds | Vendor News families | the structured sources (CSAF providers, cvelistV5, EPSS, OSV) */
export type HealthKind = "news" | "vendor" | "structured"
export type ErrorCategory = "timeout" | "connection" | "tls" | "http_4xx" | "http_5xx" | "rate_limited" | "blocked" | "parse" | "too_large" | "other"

export interface HealthError {
  category: ErrorCategory
  status: number | null
  at: string | null
}

export interface HealthRow {
  kind: HealthKind
  key: string
  name: string
  /** news: the category (press, authority …); Vendor News: the family (nvd, paloalto …) */
  group: string
  host: string
  url: string
  enabled: boolean
  state: HealthState
  reasons: string[]
  /** since when it is in this state (null: not known yet) */
  since: string | null
  last_ok_at: string | null
  last_fetch_at: string | null
  next_fetch_at: string | null
  paused: boolean
  failures: number
  /** the current failure (null: the last fetch went fine) */
  error: HealthError | null
  /** the last failed fetch within 60 days */
  last_error: HealthError | null
  /** new items per week, oldest first – null: no fetch that week */
  weeks: (number | null)[]
  avg_ms: number | null
  avg_bytes: number | null
  fetches_7d: number
  timeouts_7d: number
  parse_errors_7d: number
  not_modified_7d: number
  conditional: boolean
  /** a Vendor News family: its queries */
  members: { total: number; active: number; problems: number } | null
}

export interface HealthOverview {
  at: string
  counts: Record<HealthState, number>
  items: HealthRow[]
}

export interface HealthFetch {
  key: string
  at: string
  ok: boolean
  status: number | null
  error: ErrorCategory | null
  duration_ms: number
  requests: number
  bytes: number
  items: number
  not_modified: boolean
  parse_errors: number
}

export interface HealthDetail {
  item: HealthRow
  fetches: HealthFetch[]
  errors: HealthFetch[]
  events: { at: string; state: HealthState; prev: HealthState | null; reasons: string[] }[]
  members: HealthRow[]
}

export const HEALTH_KEY = ["admin", "source-health"] as const

/** The table – and the number on "Integrationen" in the settings navigation (the same query, shared). */
export const useSourceHealth = (enabled = true) =>
  useQuery({ queryKey: HEALTH_KEY, queryFn: polled<HealthOverview>((o) => api.get("/api/admin/source-health", o)), enabled, staleTime: 60_000, refetchInterval: 5 * 60_000 })

export const useSourceHealthDetail = (kind: HealthKind | null, key: string | null) =>
  useQuery({
    queryKey: [...HEALTH_KEY, kind, key],
    queryFn: ({ signal }) => api.get<HealthDetail>(`/api/admin/source-health/${kind}/${encodeURIComponent(key ?? "")}`, { signal, timeoutMs: DETAIL_TIMEOUT_MS }),
    enabled: !!kind && !!key,
    retry: detailRetry,
    placeholderData: keepPreviousData,
  })

/** docs/UX.md colours: green nothing to do, blue a notice, amber act soon, red act now, grey information. */
export const STATE_COLOR: Record<HealthState, string> = {
  healthy: "--success",
  slow: "--primary",
  disturbed: "--warning",
  dead: "--sev-critical",
  off: "--muted-foreground",
  never: "--muted-foreground",
}

/** Worst first – the order of the table. */
export const STATE_ORDER: HealthState[] = ["dead", "disturbed", "slow", "healthy", "never", "off"]

export const isProblem = (s: HealthState) => s === "dead" || s === "disturbed"

/** Worst first, then by name – a switched-off source last. */
export function sortRows(rows: HealthRow[]): HealthRow[] {
  return [...rows].sort((a, b) => STATE_ORDER.indexOf(a.state) - STATE_ORDER.indexOf(b.state) || a.name.localeCompare(b.name))
}

/** "nur Probleme": disturbed and dead only. */
export const filterRows = (rows: HealthRow[], onlyProblems: boolean) => (onlyProblems ? rows.filter((r) => isProblem(r.state)) : rows)

/** "12, 8, –, 9 Meldungen je Woche (älteste zuerst)" – the sparkline for screen readers (and its tooltip). */
export function sparkLabel(weeks: (number | null)[], t: TFunction, lang: string): string {
  const nf = new Intl.NumberFormat(lang === "en" ? "en-GB" : "de-DE")
  const parts = weeks.map((n) => (n === null ? "–" : nf.format(n)))
  return t("health.sparkLabel", { values: parts.join(", ") })
}

/** Points of the sparkline in a width × height box (a week without a fetch: a gap, drawn at the bottom as a dot). */
export function sparkPoints(weeks: (number | null)[], width: number, height: number, pad = 2): { x: number; y: number; known: boolean }[] {
  const max = Math.max(1, ...weeks.map((n) => n ?? 0))
  const step = weeks.length > 1 ? (width - 2 * pad) / (weeks.length - 1) : 0
  return weeks.map((n, i) => ({ x: pad + i * step, y: height - pad - ((n ?? 0) / max) * (height - 2 * pad), known: n !== null }))
}

/** "1,2 s" / "340 ms" in the reader's language. */
export function fmtMs(ms: number | null, lang: string): string {
  if (ms === null) return "–"
  const locale = lang === "en" ? "en-GB" : "de-DE"
  if (ms < 1000) return `${new Intl.NumberFormat(locale).format(ms)} ms`
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: 1, minimumFractionDigits: 1 }).format(ms / 1000)} s`
}

const WITH_STATUS: ErrorCategory[] = ["http_4xx", "http_5xx", "blocked", "rate_limited"]

/** The error in words: "Abgelehnt (HTTP 403)", "Zeitüberschreitung". */
export function errorLabel(e: { category: ErrorCategory | null; status: number | null } | null, t: TFunction): string {
  if (!e?.category) return "–"
  const word = t(`health.err.${e.category}`, { defaultValue: e.category })
  // the status only where it tells something (not "Nicht lesbar (HTTP 200)")
  return e.status && WITH_STATUS.includes(e.category) ? `${word} (HTTP ${e.status})` : word
}

/** ?source=news:heise – the line a link (a notification, the badge) opens in the drawer. */
export function parseSourceParam(v: string | null): { kind: HealthKind; key: string } | null {
  if (!v) return null
  const at = v.indexOf(":")
  const kind = v.slice(0, at)
  const key = v.slice(at + 1)
  if (at < 1 || !key || (kind !== "news" && kind !== "vendor" && kind !== "structured")) return null
  return { kind, key }
}

/** The badge in the settings navigation: dead sources (null – nothing to show). */
export const deadCount = (o: HealthOverview | undefined) => (o && o.counts.dead > 0 ? o.counts.dead : null)
