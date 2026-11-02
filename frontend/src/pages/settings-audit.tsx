import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import {
  Archive,
  BellRing,
  Boxes,
  ChevronDown,
  DatabaseBackup,
  FileSpreadsheet,
  KeyRound,
  Loader2,
  Lock,
  type LucideIcon,
  Plug,
  RotateCcw,
  ScrollText,
  Search,
  Settings2,
  ShieldQuestion,
  Users,
  UsersRound,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { EmptyState, Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Explained } from "@/components/cobe/explained"
import { SubTabs } from "@/components/cobe/sub-tabs"
import { Ts } from "@/components/cobe/time"
import { api, saveBlob } from "@/lib/api"
import {
  actionText,
  actorText,
  AUDIT_KEY,
  type AuditEntry,
  type AuditFilters,
  type AuditGroup,
  changeCount,
  detailRows,
  exportPath,
  fieldText,
  fmtValue,
  GROUP_KEYS,
  isFiltered,
  NO_FILTERS,
  targetText,
  useAuditActors,
  useAuditLog,
  useAuditSettings,
} from "@/lib/audit"
import { errorText, isStale } from "@/lib/errors"
import { withReauth } from "@/lib/reauth"
import { cn } from "@/lib/utils"
import { Loading, NumberField, SaveBar, StaleNotice } from "@/pages/settings-shared"

const GROUP_ICON: Record<AuditGroup, LucideIcon> = {
  accounts: Users,
  signin: KeyRound,
  tokens: Plug,
  notify: BellRing,
  teams: UsersRound,
  settings: Settings2,
  backup: DatabaseBackup,
  sources: Boxes,
  other: ShieldQuestion,
}

const ALL = "__all" // Radix Select needs a value for "no filter"

type AuditTab = "entries" | "retention"

/** Settings → Protokoll (admins): the audit log with filters and CSV export | how long it is kept (sub-tabs, `?tab=`). */
export function AuditSettings() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const tab: AuditTab = params.get("tab") === "retention" ? "retention" : "entries"
  const parts = [
    { key: "entries" as const, icon: ScrollText, label: t("audit.tab.entries") },
    { key: "retention" as const, icon: Archive, label: t("audit.tab.retention") },
  ]
  return (
    <>
      <SubTabs parts={parts} active={tab} to={(k) => (k === "entries" ? "?" : `?tab=${k}`)} label={t("settings.nav.audit")} />
      {tab === "retention" ? <RetentionPane /> : <EntriesPane />}
    </>
  )
}

// ---------------------------------------------------------------- entries

function EntriesPane() {
  const { t } = useTranslation()
  const [filters, setFilters] = useState<AuditFilters>(NO_FILTERS)
  const [typed, setTyped] = useState("")
  const [open, setOpen] = useState<Set<number>>(new Set())
  const [exporting, setExporting] = useState(false)
  // the search waits for a pause in typing – not a request per key
  useEffect(() => {
    const id = setTimeout(() => setFilters((f) => (f.q === typed ? f : { ...f, q: typed })), 300)
    return () => clearTimeout(id)
  }, [typed])
  const q = useAuditLog(filters)
  const actors = useAuditActors().data ?? []
  const items = q.data?.pages.flatMap((p) => p.items) ?? []
  const set = (patch: Partial<AuditFilters>) => setFilters((f) => ({ ...f, ...patch }))
  const toggle = (id: number) =>
    setOpen((s) => {
      const n = new Set(s)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  const runExport = async () => {
    setExporting(true)
    try {
      const { blob, filename } = await api.getFile(exportPath(filters))
      saveBlob(blob, filename)
      toast.success(t("audit.exportDone", { name: filename }))
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setExporting(false)
    }
  }
  const filtered = isFiltered({ ...filters, q: typed })

  return (
    <Section
      title={t("audit.title")}
      description={t("audit.desc")}
      actions={
        <>
          <Button variant="outline" size="sm" onClick={() => void runExport()} disabled={exporting} title={t("audit.exportHint")}>
            {exporting ? <Loader2 className="animate-spin" /> : <FileSpreadsheet />} {t("audit.export")}
          </Button>
          <HelpLink chapter="betrieb" section="protokoll" topic={t("audit.title")} />
        </>
      }
    >
      <div
        role="search"
        aria-label={t("audit.filter.label")}
        className="grid gap-2 border-b px-5 py-3 sm:grid-cols-2 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_9.5rem_9.5rem_minmax(0,1.3fr)_auto]"
      >
        <Select value={filters.group || ALL} onValueChange={(v) => set({ group: v === ALL ? "" : v })}>
          <SelectTrigger className="w-full" aria-label={t("audit.filter.group")}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent position="popper">
            <SelectItem value={ALL}>{t("audit.filter.allGroups")}</SelectItem>
            {GROUP_KEYS.map((g) => {
              const Icon = GROUP_ICON[g]
              return (
                <SelectItem key={g} value={g}>
                  <Icon className="size-4 text-muted-foreground" /> {t(`audit.group.${g}`)}
                </SelectItem>
              )
            })}
          </SelectContent>
        </Select>
        <Select value={filters.actor || ALL} onValueChange={(v) => set({ actor: v === ALL ? "" : v })}>
          <SelectTrigger className="w-full" aria-label={t("audit.filter.actor")}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent position="popper">
            <SelectItem value={ALL}>{t("audit.filter.allActors")}</SelectItem>
            {actors.map((a) => (
              <SelectItem key={a.id ?? a.kind} value={a.id ?? a.kind}>
                {actorText(t, a)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          type="date"
          value={filters.from}
          max={filters.to || undefined}
          onChange={(e) => set({ from: e.target.value })}
          aria-label={t("audit.filter.from")}
          title={t("audit.filter.from")}
          className="w-full"
        />
        <Input
          type="date"
          value={filters.to}
          min={filters.from || undefined}
          onChange={(e) => set({ to: e.target.value })}
          aria-label={t("audit.filter.to")}
          title={t("audit.filter.to")}
          className="w-full"
        />
        <div className="relative sm:col-span-2 lg:col-span-1">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            type="search"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={t("audit.filter.search")}
            aria-label={t("audit.filter.search")}
            maxLength={200}
            className="w-full pl-8"
          />
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="h-8 justify-self-start"
          disabled={!filtered}
          onClick={() => {
            setTyped("")
            setFilters(NO_FILTERS)
          }}
        >
          <RotateCcw /> {t("audit.filter.reset")}
        </Button>
      </div>

      {!q.data ? (
        <div className="p-5">
          <Loading error={q.error} onRetry={() => void q.refetch()} />
        </div>
      ) : items.length === 0 ? (
        <div className="p-5">
          <EmptyState
            icon={ScrollText}
            title={filtered ? t("audit.empty.filtered") : t("audit.empty.title")}
            text={filtered ? t("audit.empty.filteredText") : t("audit.empty.text")}
          />
        </div>
      ) : (
        <>
          <div
            aria-hidden
            className="hidden border-b px-5 py-2 text-xs font-medium text-muted-foreground md:grid md:grid-cols-[8.5rem_minmax(0,1.1fr)_minmax(0,1.4fr)_minmax(0,1.2fr)_7.5rem_1rem] md:gap-3"
          >
            <span>{t("audit.col.time")}</span>
            <span>{t("audit.col.actor")}</span>
            <span>{t("audit.col.action")}</span>
            <span>{t("audit.col.target")}</span>
            <span>
              <Explained label={t("audit.col.ip")} text={t("audit.ipTip")} />
            </span>
            <span />
          </div>
          <ul className={cn("divide-y", q.isPlaceholderData && "opacity-60")}>
            {items.map((e) => (
              <EntryRow key={e.id} e={e} open={open.has(e.id)} onToggle={() => toggle(e.id)} />
            ))}
          </ul>
          <div className="flex flex-wrap items-center justify-between gap-3 border-t px-5 py-3 text-xs text-muted-foreground">
            <span role="status">{t("audit.count", { count: items.length })}</span>
            {q.hasNextPage && (
              <Button variant="outline" size="sm" onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage}>
                {q.isFetchingNextPage && <Loader2 className="animate-spin" />} {t("audit.more")}
              </Button>
            )}
          </div>
        </>
      )}
    </Section>
  )
}

function EntryRow({ e, open, onToggle }: { e: AuditEntry; open: boolean; onToggle: () => void }) {
  const { t } = useTranslation()
  const Icon = GROUP_ICON[e.group] ?? ShieldQuestion
  const n = changeCount(e)
  const id = `audit-${e.id}`
  return (
    <li>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={id}
        className="grid w-full grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-1 px-5 py-3 text-left text-sm outline-none hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:ring-inset md:grid-cols-[8.5rem_minmax(0,1.1fr)_minmax(0,1.4fr)_minmax(0,1.2fr)_7.5rem_1rem] md:items-center"
      >
        {/* mobile: the action first, the time at the right; md+: one row per entry in the table's columns */}
        <span className="col-start-2 row-start-1 text-xs whitespace-nowrap text-muted-foreground md:col-start-1 md:text-sm">
          <Ts at={e.at} rel />
        </span>
        <span
          className="col-span-2 row-start-2 truncate text-muted-foreground md:col-span-1 md:col-start-2 md:row-start-1 md:text-foreground"
          title={e.actor.kind === "sync" ? t("audit.syncTip") : undefined}
        >
          {actorText(t, e.actor)}
        </span>
        <span className="col-start-1 row-start-1 flex min-w-0 items-center gap-2 font-medium md:col-start-3">
          <Icon className="size-4 shrink-0 text-muted-foreground" aria-label={t(`audit.group.${e.group}`)} />
          <span className="truncate">{actionText(t, e.action)}</span>
          {n > 0 && <span className="shrink-0 rounded-full bg-muted px-1.5 text-[11px] font-normal text-muted-foreground tabular-nums">{t("audit.changes", { count: n })}</span>}
        </span>
        <span className="col-span-2 row-start-3 truncate text-muted-foreground md:col-span-1 md:col-start-4 md:row-start-1">{targetText(t, e.target)}</span>
        <span className="col-span-2 row-start-4 font-mono text-xs text-muted-foreground md:col-span-1 md:col-start-5 md:row-start-1 md:truncate">{e.ip ?? "—"}</span>
        <ChevronDown className={cn("hidden size-4 text-muted-foreground transition-transform md:col-start-6 md:row-start-1 md:block", open && "rotate-180")} aria-hidden />
        <span className="sr-only">{t("audit.details.expand")}</span>
      </button>
      {open && <EntryDetails id={id} e={e} />}
    </li>
  )
}

function EntryDetails({ id, e }: { id: string; e: AuditEntry }) {
  const { t } = useTranslation()
  const { changes, info } = detailRows(e.details)
  return (
    <div id={id} className="space-y-3 border-t bg-muted/30 px-5 py-3 text-sm">
      {changes.length > 0 && (
        <div>
          <p className="mb-1.5 text-xs font-medium text-muted-foreground">{t("audit.details.changes")}</p>
          <div className="overflow-hidden rounded-lg border bg-background">
            <div aria-hidden className="hidden grid-cols-[minmax(0,12rem)_minmax(0,1fr)_minmax(0,1fr)] gap-3 border-b px-3 py-1.5 text-xs text-muted-foreground sm:grid">
              <span>{t("audit.details.field")}</span>
              <span>{t("audit.details.from")}</span>
              <span>{t("audit.details.to")}</span>
            </div>
            <dl className="divide-y">
              {changes.map((c) => (
                <div key={c.field} className="grid gap-x-3 gap-y-0.5 px-3 py-2 sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)_minmax(0,1fr)]">
                  <dt className="font-medium [overflow-wrap:anywhere]">{fieldText(t, c.field)}</dt>
                  {c.secret || c.changedOnly ? (
                    <dd className="flex items-center gap-1.5 text-muted-foreground sm:col-span-2">
                      {c.secret && <Lock className="size-3.5 shrink-0" aria-hidden />}
                      {c.secret ? t("audit.details.secret") : t("audit.details.changedOnly")}
                    </dd>
                  ) : (
                    <>
                      <dd className="text-muted-foreground line-through decoration-muted-foreground/40 [overflow-wrap:anywhere]">
                        <span className="sr-only">{t("audit.details.from")}: </span>
                        {fmtValue(t, c.from)}
                      </dd>
                      <dd className="[overflow-wrap:anywhere]">
                        <span className="sr-only">{t("audit.details.to")}: </span>
                        <span aria-hidden className="text-muted-foreground sm:hidden">
                          →{" "}
                        </span>
                        {fmtValue(t, c.to)}
                      </dd>
                    </>
                  )}
                </div>
              ))}
            </dl>
          </div>
        </div>
      )}
      {info.length > 0 && (
        <div>
          <p className="mb-1.5 text-xs font-medium text-muted-foreground">{t("audit.details.info")}</p>
          <dl className="grid gap-x-3 gap-y-1 sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)]">
            {info.map((r) => (
              <div key={r.field} className="contents">
                <dt className="text-muted-foreground [overflow-wrap:anywhere]">{fieldText(t, r.field)}</dt>
                <dd className="[overflow-wrap:anywhere]">{fmtValue(t, r.value)}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
      {changes.length === 0 && info.length === 0 && <p className="text-muted-foreground">{t("audit.details.none")}</p>}
      <p className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span>{t("audit.details.entry", { id: e.id })}</span>
        <Ts at={e.at} />
        {e.target?.id && (
          <span className="[overflow-wrap:anywhere]">
            {t("audit.details.target")}: <span className="font-mono">{e.target.id}</span>
          </span>
        )}
      </p>
    </div>
  )
}

// ---------------------------------------------------------------- retention

function RetentionPane() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useAuditSettings()
  const [days, setDays] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [stale, setStale] = useState(false)
  if (!q.data) {
    return (
      <Section title={t("audit.retention.title")} description={t("audit.retention.desc")}>
        <div className="p-5">
          <Loading error={q.error} onRetry={() => void q.refetch()} />
        </div>
      </Section>
    )
  }
  const s = q.data
  const value = days ?? s.keep_days
  const valid = Number.isInteger(value) && value >= s.keep_min && value <= s.keep_max
  const save = async () => {
    setBusy(true)
    try {
      // shorter: older entries go with the next prune – the server asks for a fresh confirmation first
      await withReauth(() => api.put("/api/admin/audit/settings", { keep_days: value, rev: s.rev }))
      await qc.invalidateQueries({ queryKey: AUDIT_KEY })
      setDays(null)
      setStale(false)
      toast.success(t("audit.retention.saved"))
    } catch (e) {
      if (isStale(e)) setStale(true)
      else toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Section
      title={t("audit.retention.title")}
      description={t("audit.retention.desc")}
      actions={<HelpLink chapter="betrieb" section="protokoll-aufbewahrung" topic={t("audit.retention.title")} />}
    >
      <div className="space-y-4 p-5">
        {stale && (
          <StaleNotice
            onReload={() => {
              setDays(null)
              setStale(false)
              void q.refetch()
            }}
          />
        )}
        <NumberField
          label={t("audit.retention.label")}
          hint={t("audit.retention.hint", { min: s.keep_min, max: s.keep_max, def: s.keep_default })}
          value={value}
          unit={t("audit.retention.unit")}
          min={s.keep_min}
          max={s.keep_max}
          onChange={setDays}
        />
        <p className="flex gap-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
          <DatabaseBackup className="mt-0.5 size-3.5 shrink-0" />
          <span>{t("audit.retention.backup")}</span>
        </p>
      </div>
      <div className="border-t px-5 py-3">
        <SaveBar onSave={() => void save()} busy={busy} disabled={!valid} dirty={days !== null && days !== s.keep_days} />
      </div>
    </Section>
  )
}
