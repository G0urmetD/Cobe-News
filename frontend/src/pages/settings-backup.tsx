import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link, useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import {
  AlertTriangle,
  ArrowRight,
  BookOpen,
  Copy,
  DatabaseBackup,
  Download,
  FileDown,
  FileJson,
  FileSpreadsheet,
  Info,
  KeyRound,
  Loader2,
  Lock,
  Server,
  ShieldCheck,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Pill } from "@/components/cobe/badges"
import { Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { confirmAction } from "@/components/cobe/confirm"
import { Explained } from "@/components/cobe/explained"
import { Field } from "@/components/cobe/form"
import { SubTabs } from "@/components/cobe/sub-tabs"
import { Ts } from "@/components/cobe/time"
import { api, ApiError, saveBlob } from "@/lib/api"
import {
  BACKUP_KEY,
  backupErrorKey,
  backupState,
  canDownload,
  downloadBackup,
  fmtBytes,
  nowNote,
  removedBy,
  restoreCommand,
  STATE_COLOR,
  useBackup,
  type BackupStatus,
} from "@/lib/backup"
import { copyWithToast } from "@/lib/clipboard"
import { docPath } from "@/lib/docs"
import { errorText, isStale } from "@/lib/errors"
import { withReauth } from "@/lib/reauth"
import { cn } from "@/lib/utils"
import { restoreAlert, restoreState, useRestoreTest } from "@/lib/restore-test"
import { RestoreTestPane } from "@/pages/settings-restore-test"
import { Loading, SaveBar } from "@/pages/settings-shared"

const SHOWN = 10

type BackupTab = "backup" | "restore" | "export"

/** Settings → Sicherung & Export (admins): backups of the database (pg_dump, app/backup.py) | the restore test (the newest
 *  backup restored into a throwaway database, app/restore_test.py) | an export without secrets (sub-tabs, `?tab=`).
 *  A real restore replaces everything – it is done on the server with the app stopped, never from the browser. */
export function BackupSettings() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const asked = params.get("tab")
  const tab: BackupTab = asked === "restore" || asked === "export" ? asked : "backup"
  // a failed or overdue restore test: a dot on its tab (the same query as the pane – one request for both)
  const restore = useRestoreTest().data
  const parts = [
    { key: "backup" as const, icon: DatabaseBackup, label: t("backup.title") },
    { key: "restore" as const, icon: ShieldCheck, label: t("restoreTest.title"), alert: !!restore && restoreAlert(restoreState(restore)) },
    { key: "export" as const, icon: FileDown, label: t("backup.export.title") },
  ]
  return (
    <>
      <SubTabs parts={parts} active={tab} to={(k) => (k === "backup" ? "?" : `?tab=${k}`)} label={t("settings.nav.backup")} />
      {tab === "restore" ? <RestoreTestPane /> : tab === "export" ? <ExportPane /> : <BackupPane restoreConfigured={restore?.configured} />}
    </>
  )
}

/** `restoreConfigured`: the throwaway database of the restore test is set up (undefined: not known yet). */
function BackupPane({ restoreConfigured }: { restoreConfigured?: boolean }) {
  const { t } = useTranslation()
  const q = useBackup()
  if (!q.data) {
    return (
      <Section title={t("backup.title")} description={t("backup.desc")}>
        <div className="p-5">
          <Loading error={q.error} onRetry={q.refetch} />
        </div>
      </Section>
    )
  }
  return <BackupCard s={q.data} restoreConfigured={restoreConfigured} />
}

function BackupCard({ s, restoreConfigured }: { s: BackupStatus; restoreConfigured?: boolean }) {
  const { t, i18n } = useTranslation()
  const qc = useQueryClient()
  const [posting, setPosting] = useState(false)
  const [showAll, setShowAll] = useState(false)
  // "Jetzt sichern" answers at once; the backup runs on the server and useBackup asks until it is done. Started here:
  // the outcome as a toast once "running" is over.
  const mine = useRef(false)
  const busy = posting || s.running
  const state = backupState(s.last)
  const last = s.last

  useEffect(() => {
    if (!mine.current || s.running) return
    mine.current = false
    if (s.last?.ok) toast.success(t("backup.done", { name: s.last.name ?? "" }))
    else if (s.last) toast.error(t(backupErrorKey(s.last)))
  }, [s.running, s.last, t])

  const backupNow = async () => {
    setPosting(true)
    try {
      const r = await api.post<{ started: boolean; status: BackupStatus }>("/api/admin/backup")
      mine.current = true
      qc.setQueryData(BACKUP_KEY, r.status)
      toast.info(t(r.status.with_key ? "backup.started" : "backup.startedPlain"))
    } catch (e) {
      const msg = e instanceof ApiError && typeof e.data.message === "string" ? `${errorText(t, e)} (${e.data.message})` : errorText(t, e)
      toast.error(msg)
      void qc.invalidateQueries({ queryKey: BACKUP_KEY })
    } finally {
      setPosting(false)
    }
  }

  const stateText = {
    none: t("backup.state.none"),
    failed: t("backup.state.failed"),
    stale: t("backup.state.stale"),
    ok: t("backup.state.ok"),
  }[state]
  const files = showAll ? s.backups : s.backups.slice(0, SHOWN)
  const command = restoreCommand(s.backups[0]?.name ?? t("backup.fileName"), s.dir)
  const note = nowNote(s)

  return (
    <Section
      title={t("backup.title")}
      description={t("backup.desc")}
      actions={
        <>
          <HelpLink chapter="sicherung" section="ueberblick" topic={t("backup.title")} />
          <Pill color={STATE_COLOR[state]} dot>
            {stateText}
          </Pill>
        </>
      }
    >
      <div className="space-y-5 p-5 text-sm">
        {/* 1. does it work: the last backup */}
        <div>
          <p className="text-xs text-muted-foreground">{t("backup.last")}</p>
          {!last ? (
            <p className="mt-1 text-muted-foreground">
              {t("backup.never")}{" "}
              <Link to={docPath("sicherung", "cron")} className="font-medium text-primary underline-offset-2 hover:underline">
                {t("backup.neverLink")}
              </Link>
              .
            </p>
          ) : last.ok ? (
            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1.5">
              <Ts at={last.at} className="font-medium" />
              <span className="text-xs text-muted-foreground">
                (<Ts at={last.at} rel />)
              </span>
              {last.size != null && <span className="text-xs text-muted-foreground tabular-nums">{fmtBytes(last.size, i18n.language)}</span>}
              {last.rows != null && (
                <span className="text-xs text-muted-foreground tabular-nums">{t("backup.rows", { count: last.rows, n: last.rows.toLocaleString(i18n.language) })}</span>
              )}
              <KeyPill encrypted={!!last.encrypted} />
            </div>
          ) : (
            <div role="alert" className="mt-1.5 flex gap-2 rounded-lg border border-sev-critical/40 bg-sev-critical/10 p-2.5 text-xs">
              <AlertTriangle className="size-4 shrink-0 text-sev-critical" />
              <span className="min-w-0 break-words">
                {t("backup.failedAt")} <Ts at={last.at} /> – {t(backupErrorKey(last))}
                {last.error && (
                  <span className="mt-1 block font-mono text-[11px] text-muted-foreground" title={t("backup.errDetail")}>
                    {last.error}
                  </span>
                )}
              </span>
            </div>
          )}
        </div>

        {/* 2. the key: what "Jetzt sichern" makes – encrypted with the key, failing (the passphrase file), or plain */}
        <KeyNote s={s} />

        {/* 3. what to change: retention */}
        <RetentionForm key={`${s.keep}|${s.rev}`} s={s} />

        {/* 4. background: the files and how to restore one */}
        <div className="@container space-y-2">
          <p className="text-xs text-muted-foreground">
            <Explained label={t("backup.files", { count: s.backups.length })} text={t("backup.filesHint", { dir: s.dir })} />
          </p>
          {s.backups.length === 0 ? (
            <p className="text-xs text-muted-foreground">{t("backup.filesEmpty")}</p>
          ) : (
            <ul className={cn("divide-y rounded-lg border", FILE_GRID)}>
              <li className={cn("hidden px-3 py-2 text-xs text-muted-foreground @2xl:grid", FILE_ROW)} aria-hidden>
                <span>{t("backup.col.name")}</span>
                <span>{t("backup.col.at")}</span>
                <span className="text-right">{t("backup.col.size")}</span>
                <span>{t("backup.col.key")}</span>
                <span className="text-right">{t("backup.col.download")}</span>
              </li>
              {files.map((f) => (
                <FileRow key={f.name} f={f} />
              ))}
            </ul>
          )}
          {s.backups.length > SHOWN && (
            <Button variant="ghost" size="sm" onClick={() => setShowAll(!showAll)}>
              {showAll ? t("common.less") : t("backup.showAll", { count: s.backups.length })}
            </Button>
          )}
        </div>

        {/* 5. download and restore: on the server only – and what the restore test is (a trial run, nothing changes) */}
        <div className="space-y-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
          <p className="flex items-center gap-1.5 font-medium text-foreground">
            <Server className="size-3.5 shrink-0" aria-hidden /> {t("backup.serverOnlyTitle")}
          </p>
          <p>{t("backup.serverOnly", { dir: s.dir })}</p>
          <p>
            <Link to={docPath("sicherung", "schritt-fuer-schritt")} className="inline-flex items-center gap-1 font-medium text-primary underline-offset-2 hover:underline">
              <BookOpen className="size-3.5 shrink-0" aria-hidden /> {t("backup.stepsLink")}
            </Link>
          </p>
          <p>{t("backup.restoreHint")}</p>
          {command.startsWith("read ") && <p>{t("backup.restoreEncHint")}</p>}
          <div className="flex items-start gap-2">
            <pre className="min-w-0 flex-1 overflow-x-auto rounded bg-background/70 p-2 font-mono text-[11px] whitespace-pre-wrap break-all text-foreground">{command}</pre>
            <Button variant="ghost" size="icon-sm" aria-label={t("backup.copyRestore")} title={t("backup.copyRestore")} onClick={() => void copyWithToast(command)}>
              <Copy />
            </Button>
          </div>
          <p className="flex gap-1.5 border-t border-border/60 pt-2">
            <ShieldCheck className="mt-px size-3.5 shrink-0" aria-hidden />
            <span>
              {t("backup.restoreTestNote")}
              {restoreConfigured === false && <> {t("backup.restoreTestOff")}</>}{" "}
              <Link to="?tab=restore" className="font-medium whitespace-nowrap text-primary underline-offset-2 hover:underline">
                {t("backup.restoreTestLink")}
              </Link>
            </span>
          </p>
        </div>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t px-5 py-3">
        <span className="min-w-0 flex-1 basis-64 text-xs text-muted-foreground">
          {s.running && s.running_since ? (
            <>
              {t("backup.runningSince")} <Ts at={s.running_since} rel />
            </>
          ) : (
            <span className="inline-flex gap-1.5">
              {note === "encrypted" ? (
                <Lock className="mt-px size-3.5 shrink-0" aria-hidden />
              ) : note === "broken" ? (
                <AlertTriangle className="mt-px size-3.5 shrink-0 text-sev-critical" aria-hidden />
              ) : (
                <Info className="mt-px size-3.5 shrink-0" aria-hidden />
              )}
              <span>{t(`backup.nowNote.${note}`)}</span>
            </span>
          )}
        </span>
        <Button onClick={() => void backupNow()} disabled={busy} title={busy ? t("backup.running") : undefined}>
          {busy ? <Loader2 className="animate-spin" /> : <DatabaseBackup />} {busy ? t("backup.running") : t("backup.now")}
        </Button>
      </div>
    </Section>
  )
}

/** Retention: chosen in the list, applied with "Speichern" – a smaller number deletes older backups at once, so it asks
 *  first (never from inside the open list: a dialog stacked on a closing Select left the page unclickable). */
function RetentionForm({ s }: { s: BackupStatus }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [keep, setKeep] = useState(s.keep)
  const [busy, setBusy] = useState(false)
  const save = async () => {
    const gone = removedBy(keep, s.backups.length)
    if (gone > 0 && !(await confirmAction({ title: t("backup.keepTitle"), text: t("backup.keepText", { count: gone, keep }), confirm: t("backup.keepConfirm") }))) return
    setBusy(true)
    try {
      // fewer kept deletes older backups at once: the server asks for a fresh confirmation first (withReauth)
      const r = await withReauth(() => api.put<BackupStatus>("/api/admin/backup", { keep, rev: s.rev }))
      qc.setQueryData(BACKUP_KEY, r)
      toast.success(t("backup.keepSaved", { count: keep }))
    } catch (e) {
      toast.error(isStale(e) ? t("errors.stale") : errorText(t, e))
      void qc.invalidateQueries({ queryKey: BACKUP_KEY })
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <Field label={<Explained label={t("backup.keep")} text={t("backup.keepHint")} />} className="w-full sm:max-w-xs">
        <Select value={String(keep)} onValueChange={(v) => setKeep(Number(v))} disabled={busy}>
          <SelectTrigger className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent position="popper">
            {s.keep_choices.map((n) => (
              <SelectItem key={n} value={String(n)}>
                {t("backup.keepN", { count: n })}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Field>
      <SaveBar busy={busy} dirty={keep !== s.keep} onSave={() => void save()} />
    </div>
  )
}

/** The list's columns: one grid for the head and every row (subgrid) – the widths come from the longest entry, never
 *  a fixed width a pill could stick out of; the file name keeps 12rem, a pill wraps instead. By the list's own width
 *  (a container query – the settings page is narrower than the window): below 42rem each row is a small block. */
const FILE_GRID = "@2xl:grid @2xl:grid-cols-[minmax(12rem,1fr)_auto_auto_minmax(0,auto)_auto]"
const FILE_ROW = "@2xl:col-span-full @2xl:grid-cols-subgrid @2xl:gap-x-4"

/** What the key column says, explained on hover, focus and tap (UX.md: jargon gets its explanation). */
function KeyNote({ s }: { s: BackupStatus }) {
  const { t } = useTranslation()
  const p = s.passphrase
  const masterKey = (
    <TapTip text={t("backup.masterKey")}>
      <span className="underline decoration-muted-foreground/60 decoration-dotted underline-offset-4">{t("backup.masterKeyQ")}</span>
    </TapTip>
  )
  if (s.with_key) {
    const source = p.source === "file" ? `BACKUP_PASSPHRASE_FILE: ${p.file ?? ""}` : "BACKUP_PASSPHRASE"
    return (
      <div className="flex gap-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
        <Lock className="mt-0.5 size-3.5 shrink-0" aria-hidden />
        <div className="min-w-0 space-y-1 break-words">
          <p>{t("backup.withKey", { source })}</p>
          {p.file_ignored && <p>{t("backup.withKeyIgnored")}</p>}
          <p>{masterKey}</p>
        </div>
      </div>
    )
  }
  if (p.error) {
    return (
      <div role="alert" className="flex gap-2 rounded-lg border border-sev-critical/40 bg-sev-critical/10 p-3 text-xs">
        <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-sev-critical" aria-hidden />
        <div className="min-w-0 space-y-1 break-words">
          <p className="font-medium">{t("backup.passFile.title")}</p>
          <p>{t(`backup.passFile.${p.error}`, { defaultValue: t("backup.err.passphrase_file") })}</p>
          {p.detail && p.detail !== s.last?.error && (
            <p className="font-mono text-[11px] text-muted-foreground" title={t("backup.errDetail")}>
              {p.detail}
            </p>
          )}
          <p>
            <Link to={docPath("sicherung", "passphrase-datei")} className="font-medium text-primary underline-offset-2 hover:underline">
              {t("backup.howToEncrypt")}
            </Link>
          </p>
        </div>
      </div>
    )
  }
  return (
    <div className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
      <KeyRound className="mt-0.5 size-3.5 shrink-0 text-warning" aria-hidden />
      <div className="min-w-0 space-y-1 break-words">
        <p>{t("backup.withoutKey")}</p>
        <p className="flex flex-wrap gap-x-4 gap-y-1">
          {masterKey}
          <Link to={docPath("sicherung", "passphrase-datei")} className="font-medium text-primary underline-offset-2 hover:underline">
            {t("backup.howToEncrypt")}
          </Link>
        </p>
      </div>
    </div>
  )
}

/** A tooltip that also opens on a tap: Radix opens one on hover and keyboard focus, but closes it on a click and never
 *  opens it from a touch – here a tap opens it, a tap elsewhere closes it (its content is a dismissable layer). */
function TapTip({ text, children, className }: { text: string; children: React.ReactNode; className?: string }) {
  const [open, setOpen] = useState(false)
  const touch = useRef(false)
  return (
    <Tooltip open={open} onOpenChange={setOpen}>
      <TooltipTrigger asChild>
        <button
          type="button"
          className={cn("inline-flex max-w-full cursor-help rounded-full text-left outline-none focus-visible:ring-2 focus-visible:ring-ring/50", className)}
          onPointerDown={(e) => {
            touch.current = e.pointerType !== "mouse"
          }}
          onClick={(e) => {
            if (!touch.current) return // a mouse click: Radix closes it, as everywhere else
            e.preventDefault() // keeps Radix from closing it again
            setOpen(true)
          }}
        >
          {children}
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs text-left leading-relaxed">
        <span className="block">{text}</span>
      </TooltipContent>
    </Tooltip>
  )
}

function KeyPill({ encrypted }: { encrypted: boolean }) {
  const { t } = useTranslation()
  // wraps onto a second line where the column is narrow (h-auto) – never wider than its cell
  const wrap = "h-auto min-h-5 max-w-full rounded-[10px] py-0.5 leading-tight whitespace-normal"
  return encrypted ? (
    <TapTip text={t("backup.encryptedHint")}>
      <Pill color="--success" fg="--success-fg" className={wrap}>
        <Lock /> {t("backup.encrypted")}
      </Pill>
    </TapTip>
  ) : (
    <TapTip text={t("backup.plainHint")}>
      <Pill color="--muted-foreground" className={wrap}>
        <KeyRound /> {t("backup.plain")}
      </Pill>
    </TapTip>
  )
}

function FileRow({ f }: { f: BackupStatus["backups"][number] }) {
  const { t, i18n } = useTranslation()
  return (
    <li className={cn("grid gap-1 px-3 py-2 text-xs @2xl:items-center", FILE_ROW)}>
      <span className="min-w-0 font-mono wrap-break-word">{f.name}</span>
      <span className="flex gap-1.5 whitespace-nowrap">
        <span className="text-muted-foreground @2xl:hidden">{t("backup.col.at")}:</span>
        <Ts at={f.at} />
      </span>
      <span className="flex gap-1.5 whitespace-nowrap tabular-nums @2xl:justify-end">
        <span className="text-muted-foreground @2xl:hidden">{t("backup.col.size")}:</span>
        {fmtBytes(f.size, i18n.language)}
      </span>
      <span className="min-w-0">
        <KeyPill encrypted={f.encrypted} />
      </span>
      <span className="flex @2xl:justify-end">{canDownload(f) ? <DownloadButton name={f.name} /> : <ServerOnly />}</span>
    </li>
  )
}

/** An encrypted backup to this computer: asked first (what the file is, that it needs the passphrase, keep it safe),
 *  then a fresh proof of identity (withReauth) – then the browser downloads it itself (straight to disk, its own
 *  progress); the server streams it, logs it and allows a few per hour. */
function DownloadButton({ name }: { name: string }) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const run = async () => {
    if (!(await confirmAction({ title: t("backup.dl.title"), text: t("backup.dl.text", { name }), confirm: t("backup.dl.confirm"), destructive: false }))) return
    setBusy(true)
    try {
      await withReauth(() => downloadBackup(name))
      toast.success(t("backup.dl.done", { name }))
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Button variant="outline" size="sm" className="h-7 px-2 text-xs" onClick={() => void run()} disabled={busy} aria-label={t("backup.dl.label", { name })}>
      {busy ? <Loader2 className="animate-spin" /> : <Download />} {busy ? t("backup.dl.running") : t("backup.dl.button")}
    </Button>
  )
}

/** A plain backup has no download – the row says why (on hover, focus and tap). */
function ServerOnly() {
  const { t } = useTranslation()
  return (
    <TapTip text={t("backup.dl.plainWhy")} className="rounded-sm">
      <span className="inline-flex items-center gap-1 text-muted-foreground">
        <Server className="size-3.5 shrink-0" aria-hidden /> {t("backup.dl.serverOnly")}
      </span>
    </TapTip>
  )
}

function ExportPane() {
  const { t } = useTranslation()
  const [busy, setBusy] = useState<"" | "json" | "csv">("")
  const run = async (format: "json" | "csv") => {
    setBusy(format)
    try {
      // every user's name and e-mail: a fresh confirmation first, as for the user administration
      const { blob, filename } = await withReauth(() => api.getFile(`/api/admin/export?format=${format}`))
      saveBlob(blob, filename)
      toast.success(t("backup.export.done", { name: filename }))
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy("")
    }
  }
  return (
    <Section title={t("backup.export.title")} description={t("backup.export.desc")} actions={<HelpLink chapter="sicherung" section="export" topic={t("backup.export.title")} />}>
      <div className="space-y-3 p-5 text-sm">
        <div className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warning" aria-hidden />
          <span className="min-w-0">
            {t("backup.export.notBackup")}{" "}
            <Link to="?" className="inline-flex items-center gap-0.5 font-medium whitespace-nowrap text-primary underline-offset-2 hover:underline">
              {t("backup.export.toBackup")} <ArrowRight className="size-3" aria-hidden />
            </Link>
          </span>
        </div>
        <p className="text-muted-foreground">{t("backup.export.what")}</p>
        <p className="flex gap-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
          <Lock className="mt-0.5 size-3.5 shrink-0" />
          <span>{t("backup.export.noSecrets")}</span>
        </p>
      </div>
      <div className="flex flex-wrap items-center justify-end gap-2 border-t px-5 py-3">
        <Button variant="outline" onClick={() => void run("json")} disabled={!!busy} title={busy ? t("backup.export.running") : undefined}>
          {busy === "json" ? <Loader2 className="animate-spin" /> : <FileJson />} {t("backup.export.json")}
        </Button>
        <Button variant="outline" onClick={() => void run("csv")} disabled={!!busy} title={busy ? t("backup.export.running") : undefined}>
          {busy === "csv" ? <Loader2 className="animate-spin" /> : <FileSpreadsheet />} {t("backup.export.csv")}
        </Button>
      </div>
    </Section>
  )
}
