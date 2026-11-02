import { useSyncExternalStore } from "react"
import i18n from "@/i18n"

const locale = () => (i18n.language === "en" ? "en-GB" : "de-DE")

// Intl formatters are expensive to make (a grid of 2,400 cards made one per card and render): made once per language
const cache = new Map<string, Intl.DateTimeFormat | Intl.RelativeTimeFormat>()
function dtf(options: Intl.DateTimeFormatOptions, lang = locale()): Intl.DateTimeFormat {
  const k = `d|${lang}|${JSON.stringify(options)}`
  let f = cache.get(k) as Intl.DateTimeFormat | undefined
  if (!f) cache.set(k, (f = new Intl.DateTimeFormat(lang, options)))
  return f
}
export const dateTimeFormat = dtf
function rtf(): Intl.RelativeTimeFormat {
  const k = `r|${locale()}`
  let f = cache.get(k) as Intl.RelativeTimeFormat | undefined
  if (!f) cache.set(k, (f = new Intl.RelativeTimeFormat(locale(), { numeric: "auto" })))
  return f
}

export function fmtDateTime(iso: string) {
  return dtf({ dateStyle: "medium", timeStyle: "short" }).format(new Date(iso))
}

/** The zone of a point in time in the reader's time zone, as Intl names it: MEZ/MESZ in German, CET/CEST in English (other
 *  zones: GMT-5 …) – a time in the hour a clock change repeats is only unambiguous with it. */
export function fmtZone(iso: string) {
  return (
    dtf({ hour: "numeric", timeZoneName: "short" })
      .formatToParts(new Date(iso))
      .find((p) => p.type === "timeZoneName")?.value ?? ""
  )
}

/** Date, time and zone ("28.10.2026, 02:30 MEZ") – where an exact time matters (the drawers). */
export function fmtDateTimeZone(iso: string) {
  const zone = fmtZone(iso)
  return zone ? `${fmtDateTime(iso)} ${zone}` : fmtDateTime(iso)
}

export function fmtDate(iso: string) {
  return dtf({ dateStyle: "medium" }).format(new Date(iso))
}

/**
 * A calendar day as sources give it ("2027-05-02", endoflife.date) in the reader's format – 02.05.2027 / 2 May 2027,
 * like fmtDate; read as a local day, never shifted by the time zone. Anything else comes back as it is.
 */
export function fmtDay(day: string) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(day)
  if (!m) return day
  return dtf({ dateStyle: "medium" }).format(new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])))
}

export function fmtRelative(iso: string, now = Date.now()) {
  const at = new Date(iso)
  const diff = (at.getTime() - now) / 1000
  const abs = Math.abs(diff)
  if (abs < 60) return rtf().format(Math.round(diff), "second")
  if (abs < 3600) return rtf().format(Math.round(diff / 60), "minute")
  if (abs < 86400) return rtf().format(Math.round(diff / 3600), "hour")
  if (abs < 86400 * 30) {
    // calendar days in local time, not blocks of 24 hours: Monday 23:00 seen on Wednesday 01:00 is "vorgestern", not
    // "gestern" (rounded: a day with a clock change has 23 or 25 hours)
    const midnight = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime()
    return rtf().format(Math.round((midnight(at) - midnight(new Date(now))) / 86_400_000), "day")
  }
  return fmtDate(iso)
}

/**
 * How far away a calendar day is ("2027-05-02" from endoflife.date), in words: "in 12 Tagen", "in 4 Monaten",
 * "in 2 Jahren" (or "vor …" when past) – days up to six weeks, months up to two years, then years.
 */
export function fmtDayFrom(day: string, today: Date = new Date()) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(day)
  if (!m) return day
  const at = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]))
  const from = new Date(today.getFullYear(), today.getMonth(), today.getDate())
  const days = Math.round((at.getTime() - from.getTime()) / 86_400_000)
  if (Math.abs(days) <= 42) return rtf().format(days, "day")
  const months = Math.round(days / 30.44)
  if (Math.abs(months) < 24) return rtf().format(months, "month")
  return rtf().format(Math.round(days / 365.25), "year")
}

// one clock for every relative time on the page ("vor 5 Minuten" moves on by itself), ticking once a minute
let minute = Math.floor(Date.now() / 60_000)
const ticking = new Set<() => void>()
let timer: ReturnType<typeof setInterval> | undefined
function subscribe(fn: () => void) {
  ticking.add(fn)
  timer ??= setInterval(() => {
    minute = Math.floor(Date.now() / 60_000)
    ticking.forEach((f) => f())
  }, 60_000)
  return () => {
    ticking.delete(fn)
    if (!ticking.size && timer) {
      clearInterval(timer)
      timer = undefined
    }
  }
}
/** The current minute – components using it render again when it changes. */
export function useMinute(): number {
  return useSyncExternalStore(subscribe, () => minute)
}

/** "Test Admin" → "TA" (avatars). */
export function initials(name: string) {
  const parts = name
    .replace(/^Dr\.\s*/, "")
    .split(/[\s.]+/)
    .filter(Boolean)
  return ((parts[0]?.[0] ?? "") + (parts[1]?.[0] ?? "")).toUpperCase() || "?"
}
