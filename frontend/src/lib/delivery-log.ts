import { keepPreviousData, useInfiniteQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { polledPages } from "@/lib/poll"
import type { ChannelDelivery, ChannelType, RuleKind } from "@/lib/admin-api"
import type { NewsSeverity, NewsTopic } from "@/lib/news-api"
import { type RuleSystem, applicable } from "@/lib/rule-filters"

// The delivery log (Zustellprotokoll, backend app/delivery_log.py) and the rule's dry run (Probelauf) – types, queries
// and the pure helpers the pages use (tested in delivery-log.test.ts).

export type DeliveryKind = "rule" | "forward" | "weekly" | "test"
export type DeliveryOutcome = "ok" | "http" | "timeout" | "blocked" | "smtp" | "error"
export const DELIVERY_KINDS: DeliveryKind[] = ["rule", "forward", "weekly", "test"]
/** The outcome filter: "failed" is every failure, the others one class of it. */
export const OUTCOME_FILTERS = ["all", "failed", "ok", "http", "timeout", "blocked", "smtp", "error"] as const
export type OutcomeFilter = (typeof OUTCOME_FILTERS)[number]
export const WINDOWS = [24, 168, 720] as const
export type LogWindow = (typeof WINDOWS)[number]

export interface DeliveryItem {
  kind: string
  id: string
  title: string
  severity: string
  /** a news story's topics when it went out */
  topics?: NewsTopic[]
}

export interface DeliveryAttempt {
  id: string
  at: string
  channel_id: string | null
  channel_name: string
  channel_type: ChannelType | ""
  kind: DeliveryKind
  ref: string
  attempt: number
  manual: boolean
  items: DeliveryItem[]
  total: number
  rules: { id: string; name: string }[]
  team_name: string | null
  /** a weekly review's recipient (admins only) */
  person: string | null
  ok: boolean
  outcome: DeliveryOutcome
  error: string | null
  code: number | null
  detail: string | null
  duration_ms: number | null
}

/** A delivery: its latest attempt, with all attempts (the channel's automatic retries, a manual resend). */
export interface Delivery extends DeliveryAttempt {
  attempts: DeliveryAttempt[]
  can_resend: boolean
}

export interface DeliveryLogPage {
  deliveries: Delivery[]
  more: boolean
  since: string
  retention_days: number
  /** the personal deliveries, as counts only (they are not in the log) – only in the view of all channels */
  personal: { sent_24h: number; failed_24h: number; waiting: number } | null
}

export interface LogFilter {
  channel?: string
  outcome: OutcomeFilter
  kind: DeliveryKind | "all"
  hours: LogWindow
}

export function logQuery(f: LogFilter, before?: string): string {
  const p = new URLSearchParams({ hours: String(f.hours), limit: "50" })
  if (f.channel) p.set("channel", f.channel)
  if (f.outcome !== "all") p.set("outcome", f.outcome)
  if (f.kind !== "all") p.set("kind", f.kind)
  if (before) p.set("before", before)
  return `/api/admin/notify/log?${p.toString()}`
}

/** The deliveries page by page ("Ältere laden": the next page starts before the last delivery shown). */
export const useDeliveryLog = (f: LogFilter) =>
  useInfiniteQuery({
    queryKey: ["admin", "delivery-log", f],
    queryFn: polledPages<DeliveryLogPage, string>((o, pageParam) => api.get(logQuery(f, pageParam || undefined), o)),
    initialPageParam: "",
    getNextPageParam: (last) => nextBefore(last),
    placeholderData: keepPreviousData,
    refetchInterval: 60_000,
  })

/** Where the next page starts – none when this one was the last. */
export const nextBefore = (page: Pick<DeliveryLogPage, "deliveries" | "more">): string | undefined =>
  page.more && page.deliveries.length ? page.deliveries[page.deliveries.length - 1].at : undefined

// ---------------------------------------------------------------- the badge of a channel

export type Health = { tone: "ok" | "warn" | "bad" | "none"; key: string; at?: string; n?: number }

/**
 * The small badge in the channel list: failures of the last 24 hours ("3 Fehler in 24 Std."), else the last
 * successful delivery ("letzte Zustellung ok vor 3 Std."), else nothing logged yet.
 */
export function channelHealth(d: ChannelDelivery | undefined): Health {
  if (!d) return { tone: "none", key: "dlog.health.none" }
  if (d.failed_24h > 0) {
    // every attempt failed: nothing got through – worse than an occasional failure the retry fixed
    const allFailed = d.failed_24h >= d.attempts_24h && (!d.last_ok_at || (d.last_failed_at !== null && d.last_ok_at < d.last_failed_at))
    return { tone: allFailed ? "bad" : "warn", key: "dlog.health.failed", n: d.failed_24h }
  }
  if (d.last_ok_at) return { tone: "ok", key: "dlog.health.ok", at: d.last_ok_at }
  return { tone: "none", key: "dlog.health.none" }
}

// ---------------------------------------------------------------- texts of an attempt

type T = (key: string, opts?: Record<string, unknown>) => string

/** "HTTP 503", "SMTP 550", "Zeitüberschreitung", "Vom Egress-Schutz blockiert" … – the outcome in a few words. */
export function outcomeText(t: T, a: Pick<DeliveryAttempt, "ok" | "outcome" | "code" | "error">): string {
  if (a.ok) return t("dlog.outcome.ok")
  if (a.outcome === "http" && a.code) return `HTTP ${a.code}`
  if (a.outcome === "smtp" && a.code) return `SMTP ${a.code}`
  return t(`dlog.outcome.${a.outcome}`)
}

/** What was sent: the title of one story, or "<first title> + n weitere". */
export function itemsText(t: T, a: Pick<DeliveryAttempt, "items" | "total">): string {
  const first = a.items[0]?.title ?? "–"
  const more = Math.max(0, a.total - 1)
  return more ? t("dlog.itemsMore", { title: first, n: more }) : first
}

/** Which channel – or, for a weekly review (no channel), the way and the team. */
export function whereText(t: T, a: Pick<DeliveryAttempt, "kind" | "channel_name" | "team_name">): string {
  if (a.kind === "weekly") return t("dlog.weeklyWay", { team: a.team_name ?? "?" })
  return a.channel_name || "–"
}

// ---------------------------------------------------------------- the dry run of a rule

export const DRY_DAYS = [1, 7, 30] as const
export type DryDays = (typeof DRY_DAYS)[number]

export interface DryRunIn {
  severities: NewsSeverity[]
  sources: string[]
  topics: NewsTopic[]
  lang: "de" | "en"
  kinds: RuleKind[]
  teams: string[]
  systems: RuleSystem[]
  keywords: string[]
  exclude: string[]
  days: DryDays
}

export interface DryRunItem {
  kind: RuleKind
  id: string
  title: string
  severity: NewsSeverity
  at: string
  source: string
  /** a story: the rule's topics it has (what it matched by) */
  topics?: NewsTopic[]
  /** what it matched the rule's systems and words by ("PAN-OS", "Citrix Bleed") */
  hits?: string[]
  match: { kind: RuleKind; severity: boolean; source: boolean; topic?: boolean; teams: boolean; concern?: boolean }
}

export interface DryRunResult {
  days: number
  since: string
  count: number
  items: DryRunItem[]
  truncated: boolean
  per_day: { day: string; matches: number; messages: number }[]
  messages: number
  peak_per_day: number
  flood: boolean
  flood_limit: number
}

/** The body of the dry run: the form as it is now (not saved) – only what decides what the rule brings, and of that
 *  only what applies to its kinds (rule-filters.applicable – the same the rule is saved with). */
export function dryRunBody(
  v: {
    severities: NewsSeverity[]
    sources: string[]
    topics?: NewsTopic[]
    lang: "de" | "en"
    kinds: RuleKind[]
    teams: string[]
    systems?: RuleSystem[]
    keywords?: string[]
    exclude?: string[]
  },
  days: DryDays,
): DryRunIn {
  const x = applicable(v)
  return {
    severities: x.severities,
    sources: x.sources,
    topics: x.topics,
    lang: x.lang,
    kinds: x.kinds,
    teams: x.teams,
    systems: x.systems,
    keywords: x.keywords,
    exclude: x.exclude,
    days,
  }
}

/** Why an item matched, as short parts: its kind, and severity / source / team where the rule chose some. */
export function matchParts(t: T, x: DryRunItem): string[] {
  const out = [t(`notify.kind.${x.match.kind}`)]
  if (x.match.severity) out.push(t("dlog.dry.bySeverity", { sev: t(`news.sev.${x.severity}`) }))
  if (x.match.source) out.push(t("dlog.dry.bySource", { source: x.source }))
  if (x.match.topic && x.topics?.length) out.push(t("dlog.dry.byTopic", { topics: x.topics.map((k) => t(`news.topic.${k}`)).join(", ") }))
  if (x.match.teams) out.push(t("dlog.dry.byTeams"))
  if (x.match.concern && x.hits?.length) out.push(t("dlog.dry.byHits", { names: x.hits.join(", ") }))
  return out
}

/** The average of messages a day over the window (rounded to one decimal). */
export const perDay = (r: Pick<DryRunResult, "messages" | "days">) => Math.round((r.messages / Math.max(1, r.days)) * 10) / 10
