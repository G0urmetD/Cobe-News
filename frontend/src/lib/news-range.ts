import type { TFunction } from "i18next"
import { dateTimeFormat, fmtRelative } from "@/lib/format"

/**
 * The News list's "Zeitraum": a preset (kept as its key – a shared link or a saved view with "Heute" stays today) or an
 * own range (times with a zone, as UTC in the address), on the published date or the arrival time. "visit" ("Seit
 * meinem letzten Besuch"): what arrived after the person's read watermark – the server knows it (`mark_at`), the
 * address only says "visit". Resolved into times only when the list is asked (resolveRange).
 */
export const RANGE_PRESETS = ["1h", "today", "yesterday", "24h", "7d", "30d", "visit"] as const
export type RangePreset = (typeof RANGE_PRESETS)[number]
export type TimeField = "published" | "fetched"

export interface NewsRange {
  preset: RangePreset | null
  /** an own range: ISO times (UTC) – either end may be open */
  since: string | null
  until: string | null
  /** what the times are about: the story's date (default) or when it arrived here */
  field: TimeField
}

export const NO_RANGE: NewsRange = { preset: null, since: null, until: null, field: "published" }
export const isRangePreset = (x: unknown): x is RangePreset => RANGE_PRESETS.includes(x as RangePreset)
export const rangeActive = (r: NewsRange | undefined): boolean => !!r && !!(r.preset || r.since || r.until)
/** "visit" is by arrival: the date of the story plays no part there */
export const fieldApplies = (r: NewsRange): boolean => r.preset !== "visit"

const T_MIN = Date.UTC(1970, 0, 1)
const T_MAX = Date.UTC(2100, 0, 1)
const H = 3_600_000
const D = 24 * H
const ZONED = /(?:Z|[+-]\d{2}:?\d{2})$/i

/** A time of the address: only with a zone (without one it would be read in the receiver's zone), 1970–2099, as UTC. */
export function isoTime(v: string | null | undefined): string | null {
  if (!v || v.length > 40 || !ZONED.test(v)) return null
  const ms = Date.parse(v)
  if (!Number.isFinite(ms) || ms < T_MIN || ms >= T_MAX) return null
  return new Date(ms).toISOString()
}

const ms = (iso: string) => Date.parse(iso)

/** The range of an address – unknown presets and malformed or reversed times are dropped. */
export function readRange(p: URLSearchParams): NewsRange {
  const field: TimeField = p.get("time") === "fetched" ? "fetched" : "published"
  const preset = p.get("range")
  if (isRangePreset(preset)) return { preset, since: null, until: null, field }
  const since = isoTime(p.get("since"))
  const until = isoTime(p.get("until"))
  if (since && until && ms(since) > ms(until)) return { ...NO_RANGE, field }
  return { preset: null, since, until, field }
}

/** The range written into an address (the other parameters stay); "time" only while a range is on and it matters. */
export function writeRange(p: URLSearchParams, r: NewsRange): URLSearchParams {
  const next = new URLSearchParams(p)
  for (const k of ["range", "since", "until", "time"]) next.delete(k)
  if (r.preset) next.set("range", r.preset)
  else {
    if (r.since) next.set("since", r.since)
    if (r.until) next.set("until", r.until)
  }
  if (rangeActive(r) && fieldApplies(r) && r.field === "fetched") next.set("time", "fetched")
  return next
}

/** What the list asks the server (GET /api/news, "Alle als gelesen"): the preset as times of `now`, in the browser's zone. */
export interface AskedRange {
  since?: string
  until?: string
  time_field?: "fetched"
  since_mark?: true
}

export function resolveRange(r: NewsRange | undefined, now: Date = new Date()): AskedRange {
  if (!r || !rangeActive(r)) return {}
  if (r.preset === "visit") return { since_mark: true }
  const field = r.field === "fetched" ? { time_field: "fetched" as const } : {}
  const day = (n: number) => new Date(now.getFullYear(), now.getMonth(), now.getDate() + n).toISOString()
  const ago = (d: number) => new Date(now.getTime() - d).toISOString()
  switch (r.preset) {
    case "1h":
      return { since: ago(H), ...field }
    case "today":
      return { since: day(0), ...field }
    case "yesterday":
      return { since: day(-1), until: day(0), ...field }
    case "24h":
      return { since: ago(D), ...field }
    case "7d":
      return { since: ago(7 * D), ...field }
    case "30d":
      return { since: ago(30 * D), ...field }
    default:
      return { ...(r.since ? { since: r.since } : {}), ...(r.until ? { until: r.until } : {}), ...field }
  }
}

/** The query parameters of an asked range. */
export function rangeParams(a: AskedRange | undefined, p: URLSearchParams): void {
  if (a?.since) p.set("since", a.since)
  if (a?.until) p.set("until", a.until)
  if (a?.time_field) p.set("time_field", a.time_field)
  if (a?.since_mark) p.set("since_mark", "true")
}

// ---------------------------------------------------------------- texts

const time = (iso: string) => dateTimeFormat({ hour: "2-digit", minute: "2-digit" }).format(new Date(iso))
/** "05.11." (this year) / "05.11.2025" – the reader's format */
function dayText(iso: string, now: Date) {
  const d = new Date(iso)
  return dateTimeFormat(d.getFullYear() === now.getFullYear() ? { day: "2-digit", month: "2-digit" } : { day: "2-digit", month: "2-digit", year: "numeric" }).format(d)
}
/** "05.11. 08:00" */
export const shortTime = (iso: string, now: Date = new Date()) => `${dayText(iso, now)} ${time(iso)}`

/** The control's short label: "Heute", "7 Tage", "05.11. 08:00 – jetzt". */
export function rangeLabel(t: TFunction, r: NewsRange, now: Date = new Date()): string {
  if (r.preset) return t(`newsRange.short.${r.preset}`)
  if (!r.since && !r.until) return t("newsRange.title")
  return `${r.since ? shortTime(r.since, now) : "…"} – ${r.until ? shortTime(r.until, now) : t("newsRange.now")}`
}

/** The chip's text: "heute, seit 00:00", "7 Tage, seit 29.10. 13:41", "seit meinem letzten Besuch (vor 14 Stunden)" –
 *  "· nach Eingang" when the times are arrival times. */
export function rangeChip(t: TFunction, r: NewsRange, opts: { now?: Date; markAt?: string | null; asked?: AskedRange } = {}): string {
  const now = opts.now ?? new Date()
  // the times the list was asked with (a preset's "seit" as shown), else those of now
  const a = opts.asked?.since ? opts.asked : resolveRange(r, now)
  let text: string
  switch (r.preset) {
    case "visit":
      text = opts.markAt ? t("newsRange.chip.visitAgo", { ago: fmtRelative(opts.markAt, now.getTime()) }) : t("newsRange.chip.visit")
      break
    case "today":
    case "1h":
      text = t(`newsRange.chip.${r.preset}`, { from: time(a.since!) })
      break
    case "yesterday":
      text = t("newsRange.chip.yesterday", { day: dayText(a.since!, now) })
      break
    case "24h":
    case "7d":
    case "30d":
      text = t(`newsRange.chip.${r.preset}`, { from: shortTime(a.since!, now) })
      break
    default:
      text = rangeLabel(t, r, now)
  }
  return fieldApplies(r) && r.field === "fetched" ? `${text} · ${t("newsRange.chip.fetched")}` : text
}

// ---------------------------------------------------------------- the own range's fields (local date and time)

const pad = (n: number) => String(n).padStart(2, "0")

/** An ISO time as the values of a date and a time field in the browser's zone. */
export function localParts(iso: string | null): { date: string; time: string } {
  if (!iso) return { date: "", time: "" }
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return { date: "", time: "" }
  return { date: `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`, time: `${pad(d.getHours())}:${pad(d.getMinutes())}` }
}

/** Date and time fields (local) as an ISO time; `end`: a day without a time means the whole day (up to the next midnight).
 *  undefined: the fields are not a valid time; null: empty (an open end). */
export function fromLocal(date: string, timeOfDay: string, end = false): string | null | undefined {
  if (!date) return timeOfDay ? undefined : null
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date)
  const tm = timeOfDay ? /^(\d{2}):(\d{2})$/.exec(timeOfDay) : null
  if (!m || (timeOfDay && !tm)) return undefined
  const d = tm ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(tm[1]), Number(tm[2])) : new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]) + (end ? 1 : 0))
  if (Number.isNaN(d.getTime()) || d.getTime() < T_MIN || d.getTime() >= T_MAX) return undefined
  return d.toISOString()
}

export interface RangeDraft {
  fromDate: string
  fromTime: string
  toDate: string
  toTime: string
}

/** The own range from its four fields: the range, or why not ("invalid": a field is no time, "order": von after bis,
 *  "empty": neither end given). */
export function draftRange(d: RangeDraft): { since: string | null; until: string | null; error: null | "invalid" | "order" | "empty" } {
  const since = fromLocal(d.fromDate, d.fromTime)
  const until = fromLocal(d.toDate, d.toTime, true)
  if (since === undefined || until === undefined) return { since: null, until: null, error: "invalid" }
  if (!since && !until) return { since: null, until: null, error: "empty" }
  if (since && until && ms(since) > ms(until)) return { since, until, error: "order" }
  return { since, until, error: null }
}

/** The fields of a range shown again: an end at midnight is the whole day before ("bis 05.11." – as it was entered). */
export function draftOf(r: NewsRange): RangeDraft {
  const f = r.preset ? { date: "", time: "" } : localParts(r.since)
  let u = r.preset ? { date: "", time: "" } : localParts(r.until)
  if (u.date && u.time === "00:00") {
    const d = new Date(r.until!)
    u = { date: localParts(new Date(d.getFullYear(), d.getMonth(), d.getDate() - 1).toISOString()).date, time: "" }
  }
  return { fromDate: f.date, fromTime: f.time, toDate: u.date, toTime: u.time }
}

// ---------------------------------------------------------------- a notification's stories (`ids`)

export const IDS_MAX = 50
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** `ids=a,b,c` (also repeated): story ids only, each once, at most IDS_MAX – anything else is dropped. */
export function readIds(p: URLSearchParams): string[] {
  const all = p
    .getAll("ids")
    .flatMap((v) => v.split(","))
    .map((v) => v.trim().toLowerCase())
    .filter((v) => UUID.test(v))
  return [...new Set(all)].slice(0, IDS_MAX)
}
