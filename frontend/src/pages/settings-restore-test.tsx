import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { useQueryClient } from "@tanstack/react-query"
import { AlertTriangle, CalendarClock, Copy, Database, Info, Loader2, ShieldCheck, Terminal } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Pill } from "@/components/cobe/badges"
import { Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Explained } from "@/components/cobe/explained"
import { Field, LockedFields, ToggleRow } from "@/components/cobe/form"
import { Ts } from "@/components/cobe/time"
import { api, ApiError } from "@/lib/api"
import { copyWithToast } from "@/lib/clipboard"
import { errorText, isStale } from "@/lib/errors"
import {
  durationText,
  HOST_COMMAND,
  localHour,
  needsHost,
  pad2,
  RESTORE_KEY,
  RESTORE_STATE_COLOR,
  restoreErrorKey,
  restoreState,
  revisionBehind,
  settingsDirty,
  useRestoreTest,
  type RestoreLast,
  type RestoreMode,
  type RestoreSettings,
  type RestoreStatus,
} from "@/lib/restore-test"
import { Loading, SaveBar } from "@/pages/settings-shared"

/** Settings → Sicherung & Export → Rücksicherungs-Test (admins): the newest backup really restored – into a throwaway
 *  database of its own, never into the real one (app/restore_test.py). */
export function RestoreTestPane() {
  const { t } = useTranslation()
  const q = useRestoreTest()
  if (!q.data) {
    return (
      <Section title={t("restoreTest.title")} description={t("restoreTest.desc")}>
        <div className="p-5">
          <Loading error={q.error} onRetry={q.refetch} />
        </div>
      </Section>
    )
  }
  return <RestoreTestCard s={q.data} />
}

function RestoreTestCard({ s }: { s: RestoreStatus }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [posting, setPosting] = useState(false)
  // "Jetzt testen" answers at once; the test runs on the server and useRestoreTest asks until it is done. Started here:
  // the outcome as a toast once "running" is over.
  const mine = useRef(false)
  const busy = posting || s.running
  const state = restoreState(s)

  useEffect(() => {
    if (!mine.current || s.running) return
    mine.current = false
    if (s.last?.ok) toast.success(t("restoreTest.done", { name: s.last.name ?? "" }))
    else if (s.last) toast.error(t(restoreErrorKey(s.last)))
  }, [s.running, s.last, t])

  const testNow = async () => {
    setPosting(true)
    try {
      const r = await api.post<{ started: boolean; status: RestoreStatus }>("/api/admin/restore-test")
      mine.current = true
      qc.setQueryData(RESTORE_KEY, r.status)
      toast.info(t("restoreTest.started"))
    } catch (e) {
      const msg = e instanceof ApiError && typeof e.data.message === "string" ? `${errorText(t, e)} (${e.data.message})` : errorText(t, e)
      toast.error(msg)
      void qc.invalidateQueries({ queryKey: RESTORE_KEY })
    } finally {
      setPosting(false)
    }
  }

  return (
    <Section
      title={t("restoreTest.title")}
      description={t("restoreTest.desc")}
      actions={
        <>
          <HelpLink chapter="sicherung" section="ruecksicherungs-test" topic={t("restoreTest.title")} />
          <Pill color={RESTORE_STATE_COLOR[state]} dot>
            {t(`restoreTest.state.${state}`)}
          </Pill>
        </>
      }
    >
      <div className="space-y-5 p-5 text-sm">
        <p className="text-xs text-muted-foreground">
          <Explained label={t("restoreTest.what")} text={t("restoreTest.whatText")} />
        </p>

        {!s.configured && (
          <div role="status" className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs leading-relaxed">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />
            <div className="min-w-0 space-y-1.5">
              <p className="font-medium">{t("restoreTest.notSetUp")}</p>
              <p>{t("restoreTest.notSetUpText")}</p>
              <pre className="overflow-x-auto rounded bg-background/70 p-2 font-mono text-[11px] whitespace-pre-wrap break-all">
                {"POSTGRES_RESTORE_PASSWORD=…\ndocker compose up -d"}
              </pre>
              <div className="-ml-1.5">
                <HelpLink chapter="sicherung" section="ruecksicherungs-test-einrichten" topic={t("restoreTest.setUpTopic")} />
              </div>
            </div>
          </div>
        )}

        {/* 1. does it work: the last test */}
        {(s.configured || s.last) && <LastTest last={s.last} />}
        {state === "overdue" && (
          <p role="status" className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
            <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warning" />
            <span>{s.mode === "host" ? t("restoreTest.overdueHost") : t("restoreTest.overdueApp")}</span>
          </p>
        )}

        {s.configured && (
          <>
            {s.target && (
              <p className="flex gap-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
                <Database className="mt-0.5 size-3.5 shrink-0" />
                <span>
                  {t("restoreTest.target", { database: s.target.database, user: s.target.user })}
                  {!s.newest && <> {t("restoreTest.noBackup")}</>}
                </span>
              </p>
            )}
            {/* 2. what to change: when and by whom */}
            <RestoreForm key={`${s.rev}|${s.enabled}|${s.mode}|${s.every_days}|${s.hour}`} s={s} />
            {s.next_at && (
              <p className="flex items-center gap-2 text-xs text-muted-foreground">
                <CalendarClock className="size-3.5 shrink-0" />
                <span>
                  {t("restoreTest.next")} <Ts at={s.next_at} className="font-medium text-foreground" /> (<Ts at={s.next_at} rel />)
                </span>
              </p>
            )}
          </>
        )}
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t px-5 py-3">
        <span className="text-xs text-muted-foreground">
          {s.running && s.running_since ? (
            <>
              {t("restoreTest.runningSince")} <Ts at={s.running_since} rel />
            </>
          ) : s.running ? (
            t("restoreTest.runningElsewhere")
          ) : s.configured ? (
            t("restoreTest.nowHint")
          ) : (
            t("restoreTest.nowOff")
          )}
        </span>
        <Button onClick={() => void testNow()} disabled={busy || !s.configured} title={busy ? t("restoreTest.running") : undefined}>
          {busy ? <Loader2 className="animate-spin" /> : <ShieldCheck />} {busy ? t("restoreTest.running") : t("restoreTest.now")}
        </Button>
      </div>
    </Section>
  )
}

function LastTest({ last }: { last: RestoreLast | null }) {
  const { t, i18n } = useTranslation()
  const num = (n: number) => n.toLocaleString(i18n.language === "en" ? "en-GB" : "de-DE")
  if (!last) {
    return (
      <div>
        <p className="text-xs text-muted-foreground">{t("restoreTest.last")}</p>
        <p className="mt-1 text-muted-foreground">{t("restoreTest.never")}</p>
      </div>
    )
  }
  const rows: [string, React.ReactNode][] = []
  if (last.name)
    rows.push([
      t("restoreTest.file"),
      <span key="file" className="font-mono break-all">
        {last.name}
      </span>,
    ])
  if (last.auth) rows.push([t("restoreTest.checked"), t(`restoreTest.auth.${last.auth}`)])
  if (last.tables != null) rows.push([t("restoreTest.content"), t("restoreTest.tablesRows", { count: last.tables, rows: num(last.rows ?? 0) })])
  if (last.revision)
    rows.push([
      t("restoreTest.revision"),
      <span key="revision" className="font-mono">
        {last.revision}
      </span>,
    ])
  rows.push([t("restoreTest.trigger"), t(`restoreTest.by.${last.trigger}`, { defaultValue: last.trigger })])
  return (
    <div className="space-y-2.5">
      <p className="text-xs text-muted-foreground">{t("restoreTest.last")}</p>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <Ts at={last.at} className="font-medium" />
        <span className="text-xs text-muted-foreground">
          (<Ts at={last.at} rel />)
        </span>
        <span className="text-xs text-muted-foreground tabular-nums">{t("restoreTest.took", { duration: durationText(last.seconds) })}</span>
      </div>
      {!last.ok && (
        <div role="alert" className="flex gap-2 rounded-lg border border-sev-critical/40 bg-sev-critical/10 p-2.5 text-xs">
          <AlertTriangle className="size-4 shrink-0 text-sev-critical" />
          <span className="min-w-0 break-words">
            {t("restoreTest.failed")} – {t(restoreErrorKey(last))}
            {last.error && (
              <span className="mt-1 block font-mono text-[11px] text-muted-foreground" title={t("backup.errDetail")}>
                {last.error}
              </span>
            )}
          </span>
        </div>
      )}
      <dl className="grid gap-x-4 gap-y-1.5 text-xs sm:grid-cols-[10rem_minmax(0,1fr)]">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted-foreground">{k}</dt>
            <dd className="min-w-0">{v}</dd>
          </div>
        ))}
      </dl>
      {revisionBehind(last) && (
        <p className="flex gap-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
          <Info className="mt-0.5 size-3.5 shrink-0" />
          <span>{t("restoreTest.revisionBehind", { revision: last.revision, head: last.head })}</span>
        </p>
      )}
      {last.key_matches === false && (
        <p className="flex gap-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
          <Info className="mt-0.5 size-3.5 shrink-0" />
          <span>{t("restoreTest.otherKey")}</span>
        </p>
      )}
    </div>
  )
}

const HOURS = Array.from({ length: 24 }, (_, h) => h)

/** When and by whom: saved with "Speichern" (409 "stale" when another admin changed it meanwhile). */
function RestoreForm({ s }: { s: RestoreStatus }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const initial: RestoreSettings = { enabled: s.enabled, mode: s.mode, every_days: s.every_days, hour: s.hour }
  const [v, setV] = useState<RestoreSettings>(initial)
  const [busy, setBusy] = useState(false)
  const set = (p: Partial<RestoreSettings>) => setV((cur) => ({ ...cur, ...p }))
  const dirty = settingsDirty(v, initial)
  const save = async () => {
    setBusy(true)
    try {
      const r = await api.put<RestoreStatus>("/api/admin/restore-test", { ...v, rev: s.rev })
      qc.setQueryData(RESTORE_KEY, r)
      toast.success(t("common.saved"))
    } catch (e) {
      toast.error(isStale(e) ? t("errors.stale") : errorText(t, e))
      void qc.invalidateQueries({ queryKey: RESTORE_KEY })
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="space-y-3">
      <ToggleRow
        label={t("restoreTest.enabled")}
        description={t("restoreTest.enabledHint")}
        checked={v.enabled}
        onCheckedChange={(enabled) => set({ enabled })}
        disabled={busy}
        className="py-0"
      />
      <LockedFields locked={!v.enabled || busy} className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label={t("restoreTest.mode")}>
            <Select value={v.mode} onValueChange={(mode) => set({ mode: mode as RestoreMode })} disabled={!v.enabled || busy}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value="app">{t("restoreTest.mode.app")}</SelectItem>
                <SelectItem value="host">{t("restoreTest.mode.host")}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field label={<Explained label={t("restoreTest.every")} text={v.mode === "host" ? t("restoreTest.everyHostHint") : t("restoreTest.everyHint")} />}>
            <Select value={String(v.every_days)} onValueChange={(d) => set({ every_days: Number(d) })} disabled={!v.enabled || busy}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                {s.every_choices.map((d) => (
                  <SelectItem key={d} value={String(d)}>
                    {t(`restoreTest.every.${d}`, { defaultValue: t("restoreTest.everyN", { count: d }) })}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          {v.mode === "app" && (
            <Field label={<Explained label={t("restoreTest.hour")} text={t("restoreTest.hourHint", { hours: s.window_h })} />}>
              <Select value={String(v.hour)} onValueChange={(h) => set({ hour: Number(h) })} disabled={!v.enabled || busy}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper" className="max-h-72">
                  {HOURS.map((h) => (
                    <SelectItem key={h} value={String(h)}>
                      {t("restoreTest.hourOption", { utc: `${pad2(h)}:00`, local: localHour(h) })}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          )}
        </div>
      </LockedFields>
      {v.mode === "host" && (
        <div className="space-y-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
          <p className="flex items-center gap-1.5">
            <Terminal className="size-3.5 shrink-0" /> {t("restoreTest.hostHint")}
          </p>
          <div className="flex items-start gap-2">
            <pre className="min-w-0 flex-1 overflow-x-auto rounded bg-background/70 p-2 font-mono text-[11px] whitespace-pre-wrap break-all text-foreground">{HOST_COMMAND}</pre>
            <Button variant="ghost" size="icon-sm" aria-label={t("restoreTest.copyCommand")} title={t("restoreTest.copyCommand")} onClick={() => void copyWithToast(HOST_COMMAND)}>
              <Copy />
            </Button>
          </div>
          <div className="-ml-1.5">
            <HelpLink chapter="sicherung" section="ruecksicherungs-test-host" topic={t("restoreTest.hostTopic")} />
          </div>
        </div>
      )}
      {needsHost(s, v.mode) && (
        <p role="status" className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warning" />
          <span>{t("restoreTest.needsHost")}</span>
        </p>
      )}
      <SaveBar busy={busy} dirty={dirty} onSave={() => void save()} />
    </div>
  )
}
