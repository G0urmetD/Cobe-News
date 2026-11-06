import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link, useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import {
  Archive,
  ArrowUpRight,
  BellRing,
  Boxes,
  Braces,
  CalendarRange,
  ChevronDown,
  Copy,
  DatabaseBackup,
  FileSpreadsheet,
  KeyRound,
  Loader2,
  Lock,
  type LucideIcon,
  Plug,
  Plus,
  RotateCcw,
  ScrollText,
  Search,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  TriangleAlert,
  Users,
  UsersRound,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { EmptyState, Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Explained } from "@/components/cobe/explained"
import { FilterChip } from "@/components/cobe/filter-chip"
import { SubTabs } from "@/components/cobe/sub-tabs"
import { Ts } from "@/components/cobe/time"
import { api, saveBlob } from "@/lib/api"
import {
  actionText,
  actorText,
  AUDIT_KEY,
  type AuditChain,
  type AuditEntry,
  type AuditFilters,
  type AuditGroup,
  browserText,
  chainOf,
  chainText,
  changeCount,
  detailRows,
  entryJson,
  exportPath,
  fieldText,
  fmtField,
  fmtNumber,
  GROUP_KEYS,
  isFiltered,
  methodText,
  NO_FILTERS,
  type Range,
  RANGES,
  sessionText,
  settingsPath,
  targetLink,
  targetText,
  useAuditActors,
  useAuditChain,
  useAuditEntry,
  useAuditLog,
  useAuditSettings,
  valueChips,
  withoutChip,
} from "@/lib/audit"
import { copyWithToast } from "@/lib/clipboard"
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
type SetFilter = (patch: Partial<AuditFilters>) => void

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
  const { t, i18n } = useTranslation()
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
  const chain = useAuditChain().data
  const actors = useAuditActors().data ?? []
  const items = q.data?.pages.flatMap((p) => p.items) ?? []
  const first = q.data?.pages[0]
  const set: SetFilter = (patch) => setFilters((f) => ({ ...f, ...patch }))
  const toggle = (id: number) =>
    setOpen((s) => {
      const n = new Set(s)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  const reset = () => {
    setTyped("")
    setFilters(NO_FILTERS)
  }
  const runExport = async () => {
    setExporting(true)
    try {
      const { blob, filename, headers } = await api.getFile(exportPath({ ...filters, q: typed }, i18n.language))
      saveBlob(blob, filename)
      const cut = headers.get("X-Audit-Truncated")
      if (cut) toast.warning(t("audit.exportCut", { n: fmtNumber(Number(cut), i18n.language) }))
      else toast.success(t("audit.exportDone", { name: filename }))
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setExporting(false)
    }
  }
  const filtered = isFiltered({ ...filters, q: typed })
  const short = typed.trim().length > 0 && typed.trim().length < 3 // the trigram index needs 3 characters
  const chips = valueChips(t, filters)

  return (
    <Section
      title={t("audit.title")}
      description={t("audit.desc")}
      actions={
        <>
          <ChainBadge chain={chain} />
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
        className="grid gap-2 border-b px-5 py-3 sm:grid-cols-2 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.3fr)]"
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
        <Select
          value={filters.actor || ALL}
          onValueChange={(v) => {
            const a = actors.find((x) => (x.id ?? x.kind) === v)
            set({ actor: v === ALL ? "" : v, actorLabel: a ? actorText(t, a) : "" })
          }}
        >
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
        <RangeControl filters={filters} set={set} />
        <div className="relative sm:col-span-2 xl:col-span-1">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            type="search"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={t("audit.filter.search")}
            aria-label={t("audit.filter.search")}
            maxLength={200}
            className="w-full pl-8"
            aria-describedby={short ? "audit-search-short" : undefined}
          />
        </div>
        {short && (
          <p id="audit-search-short" className="text-xs text-muted-foreground sm:col-span-2 xl:col-span-4">
            {t("audit.filter.searchShort")}
          </p>
        )}
        <div className="flex flex-wrap items-center justify-between gap-2 sm:col-span-2 xl:col-span-4">
          <label className="flex h-8 items-center gap-2 text-sm whitespace-nowrap" title={t("audit.filter.notableHint")}>
            <Switch checked={filters.notable} onCheckedChange={(v) => set({ notable: v })} aria-describedby="audit-notable-hint" />
            <ShieldAlert className="size-4 text-amber-600 dark:text-amber-400" aria-hidden />
            {t("audit.filter.notable")}
            <span id="audit-notable-hint" className="sr-only">
              {t("audit.filter.notableHint")}
            </span>
          </label>
          <Button variant="ghost" size="sm" className="h-8" disabled={!filtered} onClick={reset}>
            <RotateCcw /> {t("audit.filter.reset")}
          </Button>
        </div>
      </div>

      {chips.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 border-b bg-muted/30 px-5 py-2 text-sm" aria-label={t("audit.chip.label")} role="group">
          {chips.map((c) => (
            <FilterChip
              key={c.key}
              label={c.label}
              value={c.value}
              removeLabel={t("audit.chip.remove", { label: `${c.label}: ${c.value}` })}
              onRemove={() => setFilters((f) => withoutChip(f, c.key))}
            />
          ))}
          {first?.total != null && (
            <span className="text-xs text-muted-foreground tabular-nums" role="status">
              {first.total_more ? t("audit.chip.hitsMore", { count: first.total }) : t("audit.chip.hits", { count: first.total })}
            </span>
          )}
          <Button variant="link" size="sm" className="h-auto px-1 py-0 text-xs" onClick={reset}>
            {t("audit.filter.reset")}
          </Button>
        </div>
      )}

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
              <EntryRow key={e.id} e={e} open={open.has(e.id)} onToggle={() => toggle(e.id)} chain={chain} set={set} />
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

/** "Zeitraum": the presets (24 hours … 90 days) and an own range of days – one control. */
function RangeControl({ filters, set }: { filters: AuditFilters; set: SetFilter }) {
  const { t, i18n } = useTranslation()
  const day = (d: string) => new Date(`${d}T00:00:00`).toLocaleDateString(i18n.language, { day: "numeric", month: "short", year: "numeric" })
  const label = filters.range
    ? t(`audit.range.${filters.range}`)
    : filters.from && filters.to
      ? t("audit.range.between", { from: day(filters.from), to: day(filters.to) })
      : filters.from
        ? t("audit.range.since", { from: day(filters.from) })
        : filters.to
          ? t("audit.range.until", { to: day(filters.to) })
          : t("audit.range.all")
  const pick = (r: "" | Range) => set({ range: r, from: "", to: "" })
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" className="w-full justify-start font-normal" aria-label={`${t("audit.filter.range")}: ${label}`}>
          <CalendarRange className="text-muted-foreground" aria-hidden />
          <span className="truncate">{label}</span>
          <ChevronDown className="ml-auto text-muted-foreground" aria-hidden />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64 space-y-3 p-3">
        <div role="group" aria-label={t("audit.filter.range")} className="grid gap-1">
          {(["", ...RANGES] as const).map((r) => {
            const on = filters.range === r && (r !== "" || (!filters.from && !filters.to))
            return (
              <button
                key={r || "all"}
                type="button"
                aria-pressed={on}
                onClick={() => pick(r)}
                className={cn("rounded-md px-2 py-1.5 text-left text-sm outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring/50", on && "bg-muted font-medium")}
              >
                {r ? t(`audit.range.${r}`) : t("audit.range.all")}
              </button>
            )
          })}
        </div>
        <div className="space-y-2 border-t pt-3">
          <p className="text-xs font-medium text-muted-foreground">{t("audit.range.custom")}</p>
          <label className="grid gap-1 text-xs text-muted-foreground">
            {t("audit.filter.from")}
            <Input type="date" value={filters.from} max={filters.to || undefined} onChange={(e) => set({ from: e.target.value, range: "" })} />
          </label>
          <label className="grid gap-1 text-xs text-muted-foreground">
            {t("audit.filter.to")}
            <Input type="date" value={filters.to} min={filters.from || undefined} onChange={(e) => set({ to: e.target.value, range: "" })} />
          </label>
        </div>
      </PopoverContent>
    </Popover>
  )
}

/** The chain's state in the header: intact, a problem (where), or not checkable. */
function ChainBadge({ chain }: { chain: AuditChain | undefined }) {
  const { t } = useTranslation()
  if (!chain || (chain.state === "empty" && !chain.rekeyed_at)) return null
  const ok = chain.state === "ok" || chain.state === "empty"
  const text = chain.state === "empty" ? t("audit.chain.state.empty") : chainText(t, chain)
  const tip = [chain.state === "ok" ? t("audit.chain.state.ok", { seq: chain.verified_seq ?? 0 }) : null, ok ? null : t("audit.chain.operatorTip"), t("audit.chain.tip")]
    .filter(Boolean)
    .join(" – ")
  const Icon = chain.busy ? Loader2 : ok ? ShieldCheck : ShieldAlert
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-0.5">
      <span
        className={cn(
          "inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs whitespace-nowrap",
          ok ? "text-emerald-700 dark:text-emerald-400" : "bg-destructive/10 font-medium text-destructive",
        )}
        role="status"
      >
        <Icon className={cn("size-3.5 shrink-0", chain.busy && "animate-spin")} aria-hidden />
        <Explained
          label={
            ok ? (
              <span className="max-sm:sr-only">{chain.busy ? t("audit.chain.state.busy") : text}</span>
            ) : (
              <>
                <span className="max-sm:hidden">{text}</span>
                <span className="sm:hidden">{t(chain.state === "other_key" ? "audit.chain.short.other_key" : "audit.chain.short.problem")}</span>
              </>
            )
          }
          text={tip}
        />
      </span>
      {chain.rekeyed_at && (
        <span className="text-xs whitespace-nowrap text-muted-foreground">
          {t("audit.chain.rekeyed")} <Ts at={chain.rekeyed_at} />
        </span>
      )}
    </span>
  )
}

function EntryRow({ e, open, onToggle, chain, set }: { e: AuditEntry; open: boolean; onToggle: () => void; chain: AuditChain | undefined; set: SetFilter }) {
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
          <bdi>{actorText(t, e.actor)}</bdi>
        </span>
        <span className="col-start-1 row-start-1 flex min-w-0 items-center gap-2 font-medium md:col-start-3">
          <Icon className="size-4 shrink-0 text-muted-foreground" aria-label={t(`audit.group.${e.group}`)} />
          <span className="truncate">{actionText(t, e.action)}</span>
          {e.notable && <TriangleAlert className="size-3.5 shrink-0 text-amber-600 dark:text-amber-400" aria-label={t("audit.notable")} />}
          {n > 0 && (
            // compact: the column is narrow – the number, the words for screen readers and on hover
            <span className="shrink-0 rounded-full bg-muted px-1.5 text-[11px] font-normal text-muted-foreground tabular-nums" title={t("audit.changes", { count: n })}>
              <span aria-hidden>±{n}</span>
              <span className="sr-only">{t("audit.changes", { count: n })}</span>
            </span>
          )}
        </span>
        <span className="col-span-2 row-start-3 truncate text-muted-foreground md:col-span-1 md:col-start-4 md:row-start-1">
          <bdi>{targetText(t, e.target)}</bdi>
        </span>
        <span className="col-span-2 row-start-4 font-mono text-xs text-muted-foreground md:col-span-1 md:col-start-5 md:row-start-1 md:truncate">{e.ip ?? "—"}</span>
        <ChevronDown className={cn("hidden size-4 text-muted-foreground transition-transform md:col-start-6 md:row-start-1 md:block", open && "rotate-180")} aria-hidden />
        <span className="sr-only">{t("audit.details.expand")}</span>
      </button>
      {open && <EntryDetails id={id} e={e} chain={chain} set={set} />}
    </li>
  )
}

// ---------------------------------------------------------------- the expanded entry

/** The small icons next to a value: filter by it, open it, copy it – shown on hover and focus, always on touch. */
function ValueActions({ value, onFilter, href, copy }: { value: string; onFilter?: () => void; href?: string | null; copy?: string | null }) {
  const { t } = useTranslation()
  const cls =
    "inline-flex size-6 shrink-0 items-center justify-center rounded text-muted-foreground outline-none hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
  return (
    <span className="inline-flex shrink-0 items-center opacity-0 transition-opacity group-focus-within/v:opacity-100 group-hover/v:opacity-100 [@media(hover:none)]:opacity-100">
      {onFilter && (
        <button type="button" className={cls} onClick={onFilter} aria-label={t("audit.act.filter", { value })} title={t("audit.act.filter", { value })}>
          <Plus className="size-3.5" />
        </button>
      )}
      {href && (
        <Link to={href} className={cls} aria-label={t("audit.act.open", { value })} title={t("audit.act.open", { value })}>
          <ArrowUpRight className="size-3.5" />
        </Link>
      )}
      {copy && (
        <button
          type="button"
          className={cls}
          onClick={() => void copyWithToast(copy, t("audit.copied"))}
          aria-label={t("audit.act.copy", { value })}
          title={t("audit.act.copy", { value })}
        >
          <Copy className="size-3.5" />
        </button>
      )}
    </span>
  )
}

/** A value with its icons. */
function Val({
  children,
  value,
  onFilter,
  href,
  copy,
  mono,
}: {
  children?: React.ReactNode
  value: string
  onFilter?: () => void
  href?: string | null
  copy?: string | null
  mono?: boolean
}) {
  return (
    <span className="group/v inline-flex max-w-full min-w-0 items-center gap-1 align-middle">
      <bdi className={cn("min-w-0 [overflow-wrap:anywhere]", mono && "font-mono text-xs")}>{children ?? value}</bdi>
      <ValueActions value={value} onFilter={onFilter} href={href} copy={copy} />
    </span>
  )
}

function Row({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="grid gap-x-3 py-1 sm:grid-cols-[9rem_minmax(0,1fr)]">
      <dt className="text-xs text-muted-foreground sm:text-sm">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  )
}

function Part({ title, children, className }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={cn("min-w-0 rounded-lg border bg-background px-3 py-2.5", className)} aria-label={title}>
      <h4 className="mb-1 text-xs font-semibold tracking-wide text-muted-foreground uppercase">{title}</h4>
      {children}
    </section>
  )
}

function EntryDetails({ id, e, chain, set }: { id: string; e: AuditEntry; chain: AuditChain | undefined; set: SetFilter }) {
  const { t, i18n } = useTranslation()
  const full = useAuditEntry(e.id)
  const ctx = full.data?.context
  const { changes, info } = detailRows(e.details)
  const isUser = e.actor.kind === "user"
  const actorValue = actorText(t, e.actor)
  const actorFilter = () => set({ actor: e.actor.id ?? e.actor.kind, actorLabel: actorValue })
  const path = settingsPath(t, e.target)
  const link = targetLink(e.target)
  const browser = browserText(e.browser)
  const state = chainOf(e, chain)
  const notRecorded = <span className="text-muted-foreground">{t("audit.who.notRecorded")}</span>
  return (
    <div id={id} className="space-y-3 border-t bg-muted/30 px-5 py-3 text-sm">
      <div className="grid gap-3 md:grid-cols-2">
        <Part title={t("audit.sec.who")}>
          <dl>
            <Row label={t("audit.who.account")}>
              <Val value={actorValue} onFilter={actorFilter} href={isUser ? "/settings/users" : null} copy={isUser ? e.actor.name : null} />
            </Row>
            {isUser && (
              <Row label={t("audit.who.role")}>
                {e.actor.role ? (
                  <span className="inline-flex flex-wrap items-center gap-1.5">
                    {t(`audit.role.${e.actor.role}`, { defaultValue: e.actor.role })}
                    {e.actor.emergency && (
                      <span className="rounded-full bg-amber-100 px-1.5 text-[11px] font-medium text-amber-900 dark:bg-amber-500/15 dark:text-amber-300">
                        {t("audit.who.emergency")}
                      </span>
                    )}
                  </span>
                ) : (
                  notRecorded
                )}
              </Row>
            )}
            {isUser && <Row label={t("audit.who.method")}>{e.session?.method ? methodText(t, e.session.method) : notRecorded}</Row>}
            {e.session?.ref && (
              <Row label={t("audit.who.session")}>
                <Val value={sessionText(e.session.ref)} mono onFilter={() => set({ session: e.session?.ref ?? "" })} copy={e.session.ref} />
                {ctx?.session && <div className="text-xs text-muted-foreground">{t("audit.who.sessionEntries", { count: ctx.session.entries })}</div>}
              </Row>
            )}
          </dl>
        </Part>

        <Part title={t("audit.sec.where")}>
          <dl>
            <Row label={t("audit.where.ip")}>
              {e.ip ? (
                <>
                  <Val value={e.ip} mono onFilter={() => set({ ip: e.ip ?? "" })} copy={e.ip} />
                  {e.ip_class && <div className="text-xs text-muted-foreground">{t(`audit.ipclass.${e.ip_class}`, { defaultValue: e.ip_class })}</div>}
                </>
              ) : (
                "—"
              )}
            </Row>
            {e.via && <Row label={t("audit.where.via")}>{t(`audit.via.${e.via}`, { defaultValue: e.via })}</Row>}
            {browser && <Row label={t("audit.where.browser")}>{browser}</Row>}
            {e.request?.method && (
              <Row label={t("audit.where.request")}>
                <span className="font-mono text-xs [overflow-wrap:anywhere]">
                  {e.request.method} {e.request.path}
                </span>
              </Row>
            )}
            {e.request?.id && (
              <Row label={<Explained label={t("audit.where.requestId")} text={t("audit.where.requestIdTip")} />}>
                <Val value={e.request.id} mono copy={e.request.id} />
              </Row>
            )}
          </dl>
        </Part>

        <Part title={t("audit.sec.what")} className="md:col-span-2">
          <dl>
            <Row label={t("audit.col.action")}>
              <Val value={actionText(t, e.action)} onFilter={() => set({ action: e.action })} />
            </Row>
            {e.target && (
              <Row label={t("audit.col.target")}>
                <Val
                  value={targetText(t, e.target)}
                  onFilter={() => set({ targetType: e.target?.type ?? "", targetId: e.target?.id ?? "", targetLabel: targetText(t, e.target) })}
                  href={link}
                  copy={e.target.id ?? e.target.label}
                />
              </Row>
            )}
            {path && (
              <Row label={t("audit.what.path")}>
                <Val value={path} href={link} />
              </Row>
            )}
          </dl>
          {changes.length > 0 && <Changes changes={changes} />}
          {info.length > 0 && (
            <dl className="mt-2 border-t pt-2">
              {info.map((r) => (
                <Row key={r.field} label={fieldText(t, r.field)}>
                  <bdi className="[overflow-wrap:anywhere]">{fmtField(t, r.field, r.value, i18n.language)}</bdi>
                </Row>
              ))}
            </dl>
          )}
          {e.target && (
            <div className="mt-2 border-t pt-2">
              <p className="mb-1 text-xs font-medium text-muted-foreground">{t("audit.what.history")}</p>
              {!ctx ? (
                <ContextState loading={full.isLoading} />
              ) : ctx.history.length === 0 ? (
                <p className="text-xs text-muted-foreground">{t("audit.what.historyNone")}</p>
              ) : (
                <ol className="space-y-0.5 text-xs">
                  {ctx.history.map((h) => (
                    <li key={h.id} className="flex flex-wrap gap-x-2">
                      <span className="text-muted-foreground">
                        <Ts at={h.at} />
                      </span>
                      <span className="font-medium">{actionText(t, h.action)}</span>
                      <bdi className="text-muted-foreground">{actorText(t, h.actor)}</bdi>
                    </li>
                  ))}
                </ol>
              )}
            </div>
          )}
        </Part>

        <Part title={t("audit.sec.context")} className="md:col-span-2">
          {!ctx ? (
            <ContextState loading={full.isLoading} />
          ) : (
            <dl>
              {ctx.session && (
                <Row label={t("audit.ctx.session")}>
                  <Val value={t("audit.who.sessionEntries", { count: ctx.session.entries })} onFilter={() => set({ session: ctx.session?.ref ?? "" })} />
                </Row>
              )}
              {ctx.ip_24h && (
                <Row label={t("audit.ctx.ip")}>
                  <Val value={t("audit.ctx.ipText", { count: ctx.ip_24h.entries, locks: ctx.ip_24h.locks })} onFilter={() => set({ ip: e.ip ?? "" })} />
                </Row>
              )}
              {isUser && (
                <Row label={t("audit.ctx.previous")}>
                  {ctx.previous_signin ? (
                    <span className="inline-flex flex-wrap items-center gap-x-2">
                      <Ts at={ctx.previous_signin.at} />
                      {ctx.previous_signin.ip && <span className="font-mono text-xs">{ctx.previous_signin.ip}</span>}
                      {browserText(ctx.previous_signin.browser) && <span className="text-muted-foreground">{browserText(ctx.previous_signin.browser)}</span>}
                      {ctx.previous_signin.method && <span className="text-muted-foreground">{methodText(t, ctx.previous_signin.method)}</span>}
                    </span>
                  ) : (
                    <span className="text-muted-foreground">{t("audit.ctx.previousNone")}</span>
                  )}
                </Row>
              )}
              <Row label={t("audit.ctx.anomalies")}>
                {e.anomalies && e.anomalies.length > 0 ? (
                  <ul className="space-y-0.5">
                    {e.anomalies.map((a) => (
                      <li key={a} className="flex items-start gap-1.5 text-amber-800 dark:text-amber-300">
                        <TriangleAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden />
                        {t(`audit.anomaly.${a}`, { defaultValue: a })}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="text-muted-foreground">{t("audit.ctx.none")}</span>
                )}
              </Row>
            </dl>
          )}
        </Part>
      </div>

      <p className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1">
          {t("audit.details.entry", { id: e.id })}
          <button
            type="button"
            className="inline-flex size-6 items-center justify-center rounded outline-none hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
            onClick={() => void copyWithToast(entryJson(full.data ?? e), t("audit.copied"))}
            aria-label={t("audit.act.json")}
            title={t("audit.act.json")}
          >
            <Braces className="size-3.5" />
          </button>
        </span>
        <Ts at={e.at} zone />
        {e.app_version && <span>{t("audit.foot.version", { version: e.app_version })}</span>}
        <span className={cn("inline-flex items-center gap-1", state === "ok" && "text-emerald-700 dark:text-emerald-400", state === "problem" && "font-medium text-destructive")}>
          {state === "ok" ? (
            <ShieldCheck className="size-3.5" aria-hidden />
          ) : state === "problem" ? (
            <ShieldAlert className="size-3.5" aria-hidden />
          ) : (
            <Lock className="size-3.5" aria-hidden />
          )}
          {t(`audit.chain.${state}`)}
        </span>
        {e.target?.id && (
          <span className="[overflow-wrap:anywhere]">
            {t("audit.details.target")}: <span className="font-mono">{e.target.id}</span>
          </span>
        )}
      </p>
    </div>
  )
}

function ContextState({ loading }: { loading: boolean }) {
  const { t } = useTranslation()
  return (
    <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
      {loading && <Loader2 className="size-3.5 animate-spin" aria-hidden />}
      {loading ? t("audit.ctx.loading") : t("audit.ctx.failed")}
    </p>
  )
}

/** Before and after – a secret only as "changed", a value coloured: the old one struck through, the new one green. */
function Changes({ changes }: { changes: ReturnType<typeof detailRows>["changes"] }) {
  const { t, i18n } = useTranslation()
  return (
    <div className="mt-2 overflow-hidden rounded-lg border">
      <div aria-hidden className="hidden grid-cols-[minmax(0,12rem)_minmax(0,1fr)_minmax(0,1fr)] gap-3 border-b bg-muted/40 px-3 py-1.5 text-xs text-muted-foreground sm:grid">
        <span>{t("audit.details.field")}</span>
        <span>{t("audit.details.from")}</span>
        <span>{t("audit.details.to")}</span>
      </div>
      <dl className="divide-y" data-audit-changes>
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
                <dd className="rounded bg-red-50 px-1.5 text-red-800 line-through decoration-red-800/40 [overflow-wrap:anywhere] dark:bg-red-500/10 dark:text-red-300 dark:decoration-red-300/40">
                  <span className="sr-only">{t("audit.details.from")}: </span>
                  <bdi>{fmtField(t, c.field, c.from, i18n.language)}</bdi>
                </dd>
                <dd className="rounded bg-emerald-50 px-1.5 text-emerald-900 [overflow-wrap:anywhere] dark:bg-emerald-500/10 dark:text-emerald-300">
                  <span className="sr-only">{t("audit.details.to")}: </span>
                  <span aria-hidden className="sm:hidden">
                    →{" "}
                  </span>
                  <bdi>{fmtField(t, c.field, c.to, i18n.language)}</bdi>
                </dd>
              </>
            )}
          </div>
        ))}
      </dl>
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
