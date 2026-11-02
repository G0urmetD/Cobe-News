import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link, useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import { AlertTriangle, Copy, DatabaseBackup, FileDown, FileJson, FileSpreadsheet, KeyRound, Loader2, Lock, ShieldCheck } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
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
import { BACKUP_KEY, backupErrorKey, backupState, fmtBytes, removedBy, restoreCommand, STATE_COLOR, useBackup, type BackupFile, type BackupStatus } from "@/lib/backup"
import { copyWithToast } from "@/lib/clipboard"
import { docPath } from "@/lib/docs"
import { errorText, isStale } from "@/lib/errors"
import { withReauth } from "@/lib/reauth"
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
      {tab === "restore" ? <RestoreTestPane /> : tab === "export" ? <ExportPane /> : <BackupPane />}
    </>
  )
}

function BackupPane() {
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
  return <BackupCard s={q.data} />
}

function BackupCard({ s }: { s: BackupStatus }) {
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
      toast.info(t("backup.started"))
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
              {last.rows != null && <span className="text-xs text-muted-foreground tabular-nums">{t("backup.rows", { count: last.rows })}</span>}
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

        {/* 2. the key: in the backups or kept apart */}
        {s.with_key ? (
          <p className="flex gap-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
            <Lock className="mt-0.5 size-3.5 shrink-0" />
            <span>{t("backup.withKey")}</span>
          </p>
        ) : (
          <p className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
            <KeyRound className="mt-0.5 size-3.5 shrink-0 text-warning" />
            <span>{t("backup.withoutKey")}</span>
          </p>
        )}

        {/* 3. what to change: retention */}
        <RetentionForm key={`${s.keep}|${s.rev}`} s={s} />

        {/* 4. background: the files and how to restore one */}
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">
            <Explained label={t("backup.files", { count: s.backups.length })} text={t("backup.filesHint", { dir: s.dir })} />
          </p>
          {s.backups.length === 0 ? (
            <p className="text-xs text-muted-foreground">{t("backup.filesEmpty")}</p>
          ) : (
            <ul className="divide-y rounded-lg border">
              <li className="hidden grid-cols-[minmax(0,1fr)_11rem_6rem_9rem] gap-3 px-3 py-2 text-xs text-muted-foreground sm:grid" aria-hidden>
                <span>{t("backup.col.name")}</span>
                <span>{t("backup.col.at")}</span>
                <span className="text-right">{t("backup.col.size")}</span>
                <span>{t("backup.col.key")}</span>
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

        <div className="space-y-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
          <p>{t("backup.restoreHint")}</p>
          {command.startsWith("read ") && <p>{t("backup.restoreEncHint")}</p>}
          <div className="flex items-start gap-2">
            <pre className="min-w-0 flex-1 overflow-x-auto rounded bg-background/70 p-2 font-mono text-[11px] whitespace-pre-wrap break-all text-foreground">{command}</pre>
            <Button variant="ghost" size="icon-sm" aria-label={t("backup.copyRestore")} title={t("backup.copyRestore")} onClick={() => void copyWithToast(command)}>
              <Copy />
            </Button>
          </div>
        </div>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t px-5 py-3">
        <span className="text-xs text-muted-foreground">
          {s.running && s.running_since ? (
            <>
              {t("backup.runningSince")} <Ts at={s.running_since} rel />
            </>
          ) : (
            t("backup.nowHint")
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

function KeyPill({ encrypted }: { encrypted: boolean }) {
  const { t } = useTranslation()
  return encrypted ? (
    <Pill color="--success" title={t("backup.encryptedHint")}>
      <Lock /> {t("backup.encrypted")}
    </Pill>
  ) : (
    <Pill color="--muted-foreground" title={t("backup.plainHint")}>
      {t("backup.plain")}
    </Pill>
  )
}

function FileRow({ f }: { f: BackupFile }) {
  const { t, i18n } = useTranslation()
  return (
    <li className="grid gap-1 px-3 py-2 text-xs sm:grid-cols-[minmax(0,1fr)_11rem_6rem_9rem] sm:items-center sm:gap-3">
      <span className="min-w-0 font-mono break-all">{f.name}</span>
      <span className="flex gap-1.5">
        <span className="text-muted-foreground sm:hidden">{t("backup.col.at")}:</span>
        <Ts at={f.at} />
      </span>
      <span className="flex gap-1.5 tabular-nums sm:justify-end">
        <span className="text-muted-foreground sm:hidden">{t("backup.col.size")}:</span>
        {fmtBytes(f.size, i18n.language)}
      </span>
      <span>
        <KeyPill encrypted={f.encrypted} />
      </span>
    </li>
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
