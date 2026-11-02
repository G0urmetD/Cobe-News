import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import type { PersonalWay } from "@/lib/teams-api"

// ---------------------------------------------------------------- quiet hours, absence, weekly review (0.1.35)
// backend: app/quiet.py, app/absence.py, app/weekly.py – the own ones under /api/me/vendor-notify, a team's under
// /api/admin/teams/{id}

export type UrgentKind = "critical" | "kev" | "affected" | "watch"
export const URGENT_KINDS: UrgentKind[] = ["critical", "kev", "affected", "watch"]

export interface Schedule {
  quiet: boolean
  from: string
  to: string
  weekends: boolean
  tz: string
  urgent: UrgentKind[]
  /** per way: null – at once; "HH:MM" – the normal messages collected and sent then */
  daily: Record<PersonalWay, string | null>
}

export interface PersonRefLite {
  id: string
  username: string
  display_name: string
}

export interface AbsenceView {
  /** local dates (the person's zone), the end inclusive */
  start: string
  end: string
  starts_at: string
  ends_at: string
  running: boolean
  also_me: boolean
  deputy: PersonRefLite & { active: boolean }
  /** the deputy is away then too – nothing is passed on, the person gets it */
  deputy_absent: boolean
}

export interface Covering {
  name: string
  start: string
  end: string
  running: boolean
}

export interface WeeklyMine {
  on: boolean
  teams: { team: string; weekday: number; at: string; tz: string }[]
  address_ok: boolean
  smtp_ready: boolean
}

export interface TeamWeekly {
  enabled: boolean
  weekday: number
  at: string
  tz: string
  last_week: string | null
  /** members who switched it on and can get it (active, with an address) */
  recipients: number
}

export interface Deputy extends PersonRefLite {
  teams: string[]
}

export const WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"] as const

/** The zones offered (any IANA zone the server knows is taken; one stored that is not listed is offered too). */
export const TIMEZONES = [
  "Europe/Berlin",
  "Europe/Vienna",
  "Europe/Zurich",
  "Europe/Amsterdam",
  "Europe/Brussels",
  "Europe/Paris",
  "Europe/Madrid",
  "Europe/Rome",
  "Europe/Warsaw",
  "Europe/Prague",
  "Europe/Stockholm",
  "Europe/Helsinki",
  "Europe/London",
  "Europe/Dublin",
  "Europe/Lisbon",
  "Europe/Istanbul",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "America/Sao_Paulo",
  "Asia/Dubai",
  "Asia/Kolkata",
  "Asia/Singapore",
  "Asia/Tokyo",
  "Australia/Sydney",
  "UTC",
]

export const zonesWith = (tz: string) => (TIMEZONES.includes(tz) ? TIMEZONES : [tz, ...TIMEZONES])

const HM = /^([01]\d|2[0-3]):[0-5]\d$/
export const validHm = (v: string) => HM.test(v)

/** A schedule the server takes: times as HH:MM, a quiet window that is not empty (or the weekends). */
export function scheduleValid(s: Schedule): boolean {
  if (!validHm(s.from) || !validHm(s.to)) return false
  if (s.quiet && s.from === s.to && !s.weekends) return false
  return Object.values(s.daily).every((v) => v === null || validHm(v))
}

/** Today in the browser's zone as YYYY-MM-DD (the default start of an absence). */
export function today(now = new Date()): string {
  const p = (n: number) => String(n).padStart(2, "0")
  return `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`
}

/** A YYYY-MM-DD date for the reader: 03.11.2026 / 2026-11-03 (no time zone shift – it is a local date already). */
export function showDate(iso: string, lang: string): string {
  const [y, m, d] = iso.split("-")
  if (!y || !m || !d) return iso
  return lang === "en" ? iso : `${d}.${m}.${y}`
}

/** An absence's range is fine to send: both dates, the end not before the start, not over a year. */
export function absenceValid(start: string, end: string, deputy: string): boolean {
  if (!start || !end || !deputy) return false
  const a = Date.parse(start)
  const b = Date.parse(end)
  return Number.isFinite(a) && Number.isFinite(b) && b >= a && (b - a) / 86_400_000 < 366
}

export const useDeputies = (url: string, q: string, enabled: boolean) =>
  useQuery({
    queryKey: ["deputies", url, q],
    queryFn: () => api.get<{ items: Deputy[] }>(`${url}?${new URLSearchParams({ q })}`),
    enabled,
    staleTime: 30_000,
  })
