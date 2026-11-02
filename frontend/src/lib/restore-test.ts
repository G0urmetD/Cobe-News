import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { polled } from "@/lib/poll"
import { dateTimeFormat } from "@/lib/format"

/** The outcome of the last restore test (also a failed one) – backend app/restore_test.py, settings "restore_test_last". */
export interface RestoreLast {
  ok: boolean
  trigger: "schedule" | "manual" | "cli"
  started_at: string
  at: string
  seconds: number
  /** the schema revision this version of the app knows */
  head: string
  name?: string
  encrypted?: boolean
  /** how the file was checked: decrypted with the passphrase, or the signature with this installation's key */
  auth?: "passphrase" | "signature"
  /** the backup's schema revision (its manifest) */
  revision?: string
  restored_revision?: string
  backup_version?: string
  backup_at?: string
  /** made with this installation's key */
  key_matches?: boolean
  tables?: number
  rows?: number
  /** what went wrong, for the text (restoreTest.err.<code>) */
  code?: string
  error?: string
}

export type RestoreMode = "app" | "host"

/** GET /api/admin/restore-test */
export interface RestoreStatus {
  /** the throwaway database is set up (POSTGRES_RESTORE_PASSWORD) */
  configured: boolean
  target: { database: string; user: string } | null
  enabled: boolean
  mode: RestoreMode
  every_days: number
  /** the hour (UTC) a scheduled test may start – within `window_h` hours after it */
  hour: number
  every_choices: number[]
  window_h: number
  timeout_s: number
  rev: number
  running: boolean
  running_since: string | null
  last: RestoreLast | null
  next_at: string | null
  overdue: boolean
  /** the app knows BACKUP_PASSPHRASE (it can decrypt an encrypted backup) */
  passphrase: boolean
  newest: { name: string; size: number; at: string; encrypted: boolean } | null
}

export type RestoreSettings = Pick<RestoreStatus, "enabled" | "mode" | "every_days" | "hour">

export const RESTORE_KEY = ["admin", "restore-test"] as const
/** While a test runs, asked every 2 s – "Jetzt testen" answers at once and the test goes on in the background. */
export const useRestoreTest = () =>
  useQuery({
    queryKey: RESTORE_KEY,
    queryFn: polled<RestoreStatus>((o) => api.get("/api/admin/restore-test", o)),
    refetchInterval: (q) => (q.state.data?.running ? 2000 : false),
  })

export type RestoreState = "off" | "never" | "failed" | "overdue" | "passed"

/** How the restore test stands: not set up / never run (grey), failed (red), overdue (amber – the schedule or the cron
 *  job does not run), passed (green). */
export function restoreState(s: Pick<RestoreStatus, "configured" | "last" | "overdue">): RestoreState {
  if (!s.configured) return "off"
  if (!s.last) return "never"
  if (!s.last.ok) return "failed"
  return s.overdue ? "overdue" : "passed"
}

/** UX.md colours: green in order, amber act soon, red act now, grey information. */
export const RESTORE_STATE_COLOR: Record<RestoreState, string> = {
  off: "--muted-foreground",
  never: "--muted-foreground",
  failed: "--sev-critical",
  overdue: "--warning",
  passed: "--success",
}

/** Needs a look on the Sicherung & Export page (a dot on its tab). */
export const restoreAlert = (state: RestoreState) => state === "failed" || state === "overdue"

/** Every reason a test can fail (restore_test.py) – each has restoreTest.err.<code>. */
export const RESTORE_ERROR_CODES = [
  "not_configured",
  "unsafe",
  "busy",
  "no_backup",
  "passphrase",
  "verify",
  "connect",
  "restore",
  "rows",
  "schema",
  "revision",
  "timeout",
  "failed",
]

export const restoreErrorKey = (last: Pick<RestoreLast, "code">) => `restoreTest.err.${last.code && RESTORE_ERROR_CODES.includes(last.code) ? last.code : "failed"}`

/** The backup's schema revision is older than the app's: a real restore migrates it (no fault – worth a word). */
export const revisionBehind = (last: RestoreLast) => !!last.revision && !!last.head && last.revision !== last.head

/** The newest backup is encrypted, the app has no passphrase and is to run the test itself: it would fail – the host's
 *  script (with a passphrase file) can. */
export const needsHost = (s: Pick<RestoreStatus, "newest" | "passphrase">, mode: RestoreMode) => mode === "app" && !!s.newest?.encrypted && !s.passphrase

export const HOST_COMMAND = "scripts/restore-test.sh --passphrase-file /pfad/zur/passphrase"

/** "03:00" UTC as the reader's local time on `day` (summer or winter time of that day) – "05:00" in Zurich in summer. */
export function localHour(hourUtc: number, day: Date = new Date(), timeZone?: string): string {
  const at = new Date(Date.UTC(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate(), hourUtc))
  return dateTimeFormat({ hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone }, "de-DE").format(at)
}

export const pad2 = (n: number) => String(n).padStart(2, "0")

/** Has the form something to save. */
export const settingsDirty = (a: RestoreSettings, b: RestoreSettings) => a.enabled !== b.enabled || a.mode !== b.mode || a.every_days !== b.every_days || a.hour !== b.hour

/** "42 s", "3 min 05 s", "1 h 02 min" – the same units in German and English. */
export function durationText(seconds: number): string {
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return `${s} s`
  if (s < 3600) return `${Math.floor(s / 60)} min ${pad2(s % 60)} s`
  return `${Math.floor(s / 3600)} h ${pad2(Math.floor((s % 3600) / 60))} min`
}
