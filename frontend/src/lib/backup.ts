import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { polled } from "@/lib/poll"

/** The outcome of the last backup (also a failed one) – backend app/backup.py, settings "backup_last". */
export interface BackupLast {
  ok: boolean
  at: string
  name?: string
  size?: number
  seconds?: number
  encrypted?: boolean
  rows?: number
  /** what went wrong, for the text (backup.err.<code>): busy, no_pg_dump, timeout, dump, passphrase, failed */
  code?: string
  error?: string
}

export interface BackupFile {
  name: string
  size: number
  at: string
  encrypted: boolean
}

/** Where the app's own passphrase comes from ("Jetzt sichern", the restore test) – never the passphrase itself. */
export interface BackupPassphrase {
  /** env: BACKUP_PASSPHRASE, file: BACKUP_PASSPHRASE_FILE, null: none (backups from the app are not encrypted) */
  source: "env" | "file" | null
  /** the file's path in the container */
  file: string | null
  /** both set: BACKUP_PASSPHRASE wins, the file is not read */
  file_ignored: boolean
  /** backups from the app are encrypted */
  ok: boolean
  /** why it cannot be used ("Jetzt sichern" fails until fixed): missing, unreadable, not_a_file, too_large, not_text, empty, short */
  error: string | null
  /** the server's own text for it (path and reason) */
  detail: string | null
}

/** GET /api/admin/backup */
export interface BackupStatus {
  /** a backup runs now ("Jetzt sichern" in the background, or the CLI / cron job) */
  running: boolean
  running_since: string | null
  keep: number
  keep_choices: number[]
  /** what a retention change is made on – an older state is refused (409 "stale") */
  rev: number
  dir: string
  /** the app has a usable passphrase: its backups are encrypted and carry the master key */
  with_key: boolean
  passphrase: BackupPassphrase
  last: BackupLast | null
  backups: BackupFile[]
}

export const BACKUP_KEY = ["admin", "backup"] as const
/** While a backup runs, asked every 2 s – "Jetzt sichern" answers at once and the backup goes on in the background. */
export const useBackup = () =>
  useQuery({
    queryKey: BACKUP_KEY,
    queryFn: polled<BackupStatus>((o) => api.get("/api/admin/backup", o)),
    refetchInterval: (q) => (q.state.data?.running ? 2000 : false),
  })

/** A file size in readable units ("2,4 MB" / "2.4 MB"), decimal like the file managers of macOS and Windows Explorer's
 *  "MB" on screen; bytes below 1 kB as they are. */
export function fmtBytes(bytes: number, lang: string): string {
  const locale = lang === "en" ? "en-GB" : "de-DE"
  const units = ["B", "kB", "MB", "GB", "TB"]
  let v = Math.max(0, bytes)
  let i = 0
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000
    i++
  }
  const digits = i === 0 || v >= 100 ? 0 : 1
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: digits, minimumFractionDigits: digits }).format(v)} ${units[i]}`
}

export type BackupState = "none" | "failed" | "stale" | "ok"

/** How the last backup stands: none yet (neutral), failed (red), older than `staleDays` (amber – act soon), ok (green). */
export function backupState(last: BackupLast | null, now = Date.now(), staleDays = 7): BackupState {
  if (!last) return "none"
  if (!last.ok) return "failed"
  return now - new Date(last.at).getTime() > staleDays * 86_400_000 ? "stale" : "ok"
}

/** UX.md colours: green in order, amber act soon, red act now, grey information. */
export const STATE_COLOR: Record<BackupState, string> = {
  none: "--muted-foreground",
  failed: "--sev-critical",
  stale: "--warning",
  ok: "--success",
}

/** How many backups a smaller retention removes right away (the server keeps only the newest `keep`). */
export const removedBy = (keep: number, count: number) => Math.max(0, count - Math.max(1, keep))

/** The restore commands for one file (CLI on the server, the app stopped first). An encrypted one (.tar.enc) needs the
 *  passphrase: read into the shell (not into the history or the .env) and handed to the container by name only. */
export function restoreCommand(name: string, dir = "/data/backups"): string {
  const file = `${dir.replace(/\/$/, "")}/${name}`
  if (name.endsWith(".enc")) {
    return [
      "read -rs BACKUP_PASSPHRASE && export BACKUP_PASSPHRASE",
      "docker compose stop app",
      `docker compose run --rm --no-deps -e BACKUP_PASSPHRASE app python -m app.cli restore ${file}`,
      "docker compose start app",
    ].join("\n")
  }
  return `docker compose stop app\ndocker compose run --rm --no-deps app python -m app.cli restore ${file}\ndocker compose start app`
}

/** The last outcome's error in the reader's language (the backend's own text stays available as detail). */
export const backupErrorKey = (last: BackupLast) => `backup.err.${last.code ?? "failed"}`

/** What the footer of "Jetzt sichern" says before a backup starts: encrypted, fails (the passphrase file), or plain –
 *  plain with encrypted ones in the list (from a command with a passphrase, e.g. cron): the difference named. */
export type NowNote = "encrypted" | "broken" | "plain" | "plainBesideEncrypted"

export function nowNote(s: Pick<BackupStatus, "with_key" | "passphrase" | "backups">): NowNote {
  if (s.with_key) return "encrypted"
  if (s.passphrase.error) return "broken"
  return s.backups.some((f) => f.encrypted) ? "plainBesideEncrypted" : "plain"
}
