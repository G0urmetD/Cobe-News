import { memo, useDeferredValue, useMemo, useState } from "react"
import { Link, useSearchParams } from "react-router"
import { useTranslation } from "react-i18next"
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpCircle,
  BellOff,
  Boxes,
  CalendarClock,
  CheckCheck,
  CheckCircle2,
  CircleAlert,
  CircleHelp,
  Clock,
  Cloud,
  Copy,
  LayoutGrid,
  Library,
  List,
  Loader2,
  MoreHorizontal,
  Search,
  ShieldAlert,
  SlidersHorizontal,
  TrendingUp,
  UsersRound,
  X,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill, TlpPill } from "@/components/cobe/badges"
import { confirmAction } from "@/components/cobe/confirm"
import { MuteItems, type MuteTarget, MuteUntilDialog } from "@/components/cobe/mute-menu"
import { ViewsMenu } from "@/components/cobe/views-menu"
import { EmptyState } from "@/components/cobe/common"
import { Explained } from "@/components/cobe/explained"
import { QueryError } from "@/components/cobe/query-state"
import { WatchStar } from "@/components/cobe/watch-star"
import { useAuth } from "@/lib/auth"
import { errorText } from "@/lib/errors"
import { fmtDate, fmtDay, fmtDayFrom } from "@/lib/format"
import { IN_PAGE, type VendorUrlFilter, readVendorFilter, readerVisible, useVendorRead, writeVendorFilter } from "@/lib/reader-api"
import { NEWS_SEV_COLOR } from "@/lib/news-api"
import { useCatalogTexts } from "@/lib/catalog-texts"
import { cn } from "@/lib/utils"
import { normalizeCve } from "@/lib/watch-api"
import { type FilterChip, type StatusRowCounts, activeFilters, placeLink, readAllCount, readAllProducts, statusRowCounts, withoutChip } from "@/lib/vendor-filters"
import {
  STATUS_COLOR,
  STATUS_FILTERS,
  type OverviewItem,
  type SortKey,
  type StatusFilter,
  type TargetGroup,
  type Urgency,
  byUrgency,
  matchScore,
  matchesFilter,
  matchesStatus,
  statusOf,
  sortItems,
  supportOf,
  targetGroups,
  urgencyOf,
  useVendorOverview,
} from "@/lib/vendor-api"
import { type VendorScope, type VendorScopeState } from "@/lib/teams-api"
import { ProductChangedHint } from "@/components/cobe/advisory-changes"
import { ScorePill } from "@/components/cobe/score"
import { useReview } from "@/lib/version-review"
import { ReviewPanel } from "@/pages/vendor-review"

type OnOpen = (key: string, finding?: string) => void
type Layout = "cards" | "list"

// the chosen view, per browser – a convenience: private windows or blocked storage simply start with the cards
const LAYOUT_KEY = "cobe-news.vendor.layout"
function readLayout(): Layout {
  try {
    return localStorage.getItem(LAYOUT_KEY) === "list" ? "list" : "cards"
  } catch {
    return "cards"
  }
}
function saveLayout(l: Layout) {
  try {
    localStorage.setItem(LAYOUT_KEY, l)
  } catch {
    // not remembered – nothing else depends on it
  }
}

// the status row's choice, per browser – like the layout a convenience (blocked storage: "Alle")
const STATUS_KEY = "cobe-news.vendor.status"
function readStatus(): StatusFilter {
  try {
    const v = localStorage.getItem(STATUS_KEY) as StatusFilter | null
    return v && STATUS_FILTERS.includes(v) ? v : "all"
  } catch {
    return "all"
  }
}
function saveStatus(s: StatusFilter) {
  try {
    localStorage.setItem(STATUS_KEY, s)
  } catch {
    // not remembered – nothing else depends on it
  }
}

// the chips' names; `now`, `exploited` and `support` come only from older links and views (the summary line is gone)
const CHIP_LABEL: Record<FilterChip, string> = {
  team: "vendor.scope.team",
  unread: "reader.onlyUnread",
  muted: "vendor.filters.mutedChip",
  review: "review.filter",
  now: "vendor.sum.filterNow",
  exploited: "vendor.sum.filterExploited",
  support: "vendor.sum.filterSupport",
}

/** The followed products: the status row (each a filter), the tool row, then the products by urgency – as cards or as a list. */
export function Overview({ onOpen, scope: sc, onSuggest }: { onOpen: OnOpen; scope: VendorScopeState; onSuggest?: () => void }) {
  const { t } = useTranslation()
  const { isAdmin } = useAuth()
  // "Mein Team / Alle" (useVendorScope, held by the page): only while Teams is on and the viewer is in a team –
  // remembered per person in this browser; null until the teams are known (no full list flashes up first)
  const { scope, setScope, hasTeam, teams } = sc
  const q = useVendorOverview(scope)
  const [params, setParams] = useSearchParams()
  // the filters live in the address (validated – saved views and shared links carry them); the status row falls back
  // to this browser's last choice when the address names none
  const uf = useMemo(() => readVendorFilter(params), [params])
  const change = (f: Partial<VendorUrlFilter>) => setParams((p) => writeVendorFilter(p, f), { replace: true, state: IN_PAGE })
  const filter = uf.filter
  const [fallbackStatus, setFallbackStatus] = useState<StatusFilter>(readStatus)
  const status: StatusFilter = uf.status ?? fallbackStatus
  const setStatus = (s: StatusFilter) => {
    change({ status: s })
    setFallbackStatus(s)
    saveStatus(s)
  }
  const [layout, setLayoutState] = useState<Layout>(readLayout)
  const setLayout = (l: Layout) => {
    setLayoutState(l)
    saveLayout(l)
  }
  const search = uf.q
  const setSearch = (v: string) => change({ q: v })
  const term = useDeferredValue(search)
  const loaded = q.data?.items
  const all = useMemo(() => (loaded ? readerVisible(loaded, uf) : undefined), [loaded, uf])
  const unreadTotal = useMemo(() => (loaded ?? []).reduce((n, i) => n + (i.muted ? 0 : (i.unread ?? 0)), 0), [loaded])
  const marks = useVendorRead()
  // search and the filters first – the status row counts what they leave, then chooses among it
  const base = useMemo(() => {
    const list = all ?? []
    const found = term.trim()
      ? list.filter((i) => matchScore(i.product, term) > 0 || i.versions.some((v) => `${v.version} ${v.label}`.toLowerCase().includes(term.toLowerCase())))
      : list
    return found.filter((i) => matchesFilter(i, filter))
  }, [all, term, filter])
  const counts = useMemo(() => statusRowCounts(base), [base])
  const items = useMemo(() => base.filter((i) => matchesStatus(i, status)).sort(byUrgency), [base, status])
  // Versionen prüfen: how many versions the viewer is responsible for confirming (their teams', an admin's of no team)
  const review = useReview("mine").data
  if (q.isError && !q.data) return <QueryError error={q.error} onRetry={() => void q.refetch()} />
  if (q.isLoading || scope === null)
    return (
      <p className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> {t("vendor.loading")}
      </p>
    )
  const st = q.data?.status
  if (st && !st.enabled)
    return (
      <EmptyState
        icon={ShieldAlert}
        title={t("vendor.offTitle")}
        text={t(isAdmin ? "vendor.offTextAdmin" : "vendor.offText")}
        action={
          isAdmin && (
            <Button size="sm" asChild>
              <Link to="/settings/integrations#vendor">{t("vendor.setUp")}</Link>
            </Button>
          )
        }
      />
    )
  if (!q.data?.items.length && scope === "team")
    return (
      <div className="space-y-4">
        <ScopeSwitch value={scope} onChange={setScope} teams={teams} />
        <EmptyState
          icon={Boxes}
          title={t("vendor.scope.emptyTitle")}
          text={t(isAdmin ? "vendor.scope.emptyTextAdmin" : "vendor.scope.emptyText")}
          action={
            <Button size="sm" variant="outline" onClick={() => setScope("all")}>
              {t("vendor.scope.showAll")}
            </Button>
          }
        />
      </div>
    )
  if (!q.data?.items.length)
    return (
      <EmptyState
        icon={Boxes}
        title={t("vendor.emptyTitle")}
        text={t(isAdmin ? "vendor.emptyTextAdmin" : "vendor.emptyText")}
        action={
          <Button size="sm" asChild>
            <Link to={placeLink(params, "catalog")} state={IN_PAGE}>
              <Library /> {t("vendor.openCatalog")}
            </Link>
          </Button>
        }
      />
    )
  const urgent = items.filter((i) => statusOf(i) !== "ok")
  const ok = items.filter((i) => statusOf(i) === "ok")
  const team = hasTeam && scope === "team"
  const chips = activeFilters(uf, { team })
  const removeChip = (c: FilterChip) => {
    const x = withoutChip(c)
    if (x.scope) setScope(x.scope)
    if (x.url) change(x.url)
  }
  // "Alle N als gelesen": exactly the products shown – named when anything narrows the list (the team's too)
  const narrowed = status !== "all" || !!filter || !!term.trim() || uf.unread || team
  const toRead = readAllCount(items, uf.muted)
  const readAll = async () => {
    const ok = await confirmAction({
      title: t("reader.vendorReadAllTitle"),
      text: t("reader.vendorReadAllText", { count: toRead }),
      confirm: t("news.readAll"),
      destructive: false,
    })
    if (!ok) return
    marks.readAll.mutate(
      { products: readAllProducts(items, narrowed), upto: q.data?.now, muted: uf.muted },
      { onSuccess: (r) => toast.success(t("reader.vendorReadAllDone", { count: r.marked })), onError: (e) => toast.error(errorText(t, e)) },
    )
  }
  return (
    <div className="space-y-4">
      <StatusRow value={status} counts={counts} onChange={setStatus} />
      {filter === "review" && <ReviewPanel onOpen={onOpen} />}
      <div className="flex flex-wrap items-center gap-2">
        <SearchField value={search} onChange={setSearch} placeholder={t("vendor.searchFollowed")} />
        <FilterMenu
          uf={uf}
          active={chips.length}
          onChange={change}
          unread={unreadTotal}
          review={review?.enabled ? review.count : null}
          scope={hasTeam ? { value: scope, onChange: setScope, teams } : null}
        />
        <ViewsMenu page="vendor" inline />
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="outline"
              size="icon"
              className="size-9"
              onClick={() => setLayout(layout === "list" ? "cards" : "list")}
              aria-label={t(layout === "list" ? "vendor.layout.toCards" : "vendor.layout.toList")}
            >
              {layout === "list" ? <LayoutGrid /> : <List />}
            </Button>
          </TooltipTrigger>
          <TooltipContent>{t(layout === "list" ? "vendor.layout.toCards" : "vendor.layout.toList")}</TooltipContent>
        </Tooltip>
      </div>
      {(chips.length > 0 || toRead > 0) && (
        <div className="flex flex-wrap items-center gap-2">
          {chips.length > 0 && (
            <ul className="flex flex-wrap items-center gap-1.5" aria-label={t("vendor.filters.active")}>
              {chips.map((c) => (
                <li key={c}>
                  <span className="inline-flex h-7 items-center gap-1 rounded-full border bg-muted/40 pr-1 pl-2.5 text-xs font-medium">
                    {c === "team" && <UsersRound className="size-3.5 text-muted-foreground" aria-hidden />}
                    {t(CHIP_LABEL[c])}
                    <button
                      type="button"
                      onClick={() => removeChip(c)}
                      aria-label={t("vendor.filters.remove", { name: t(CHIP_LABEL[c]) })}
                      title={t("vendor.filters.remove", { name: t(CHIP_LABEL[c]) })}
                      className="flex size-5 items-center justify-center rounded-full text-muted-foreground outline-none hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
                    >
                      <X className="size-3.5" />
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          )}
          {toRead > 0 && (
            <Button variant="ghost" size="sm" className="ml-auto" onClick={() => void readAll()} disabled={marks.readAll.isPending} title={t("reader.vendorUnreadHelp")}>
              <CheckCheck /> {t("reader.vendorReadAllN", { count: toRead })}
            </Button>
          )}
        </div>
      )}
      {items.length === 0 ? (
        <EmptyState
          icon={Search}
          title={t("common.noResults")}
          action={
            status !== "all" &&
            counts.all > 0 && (
              <Button size="sm" variant="outline" onClick={() => setStatus("all")}>
                {t("vendor.show.showAll", { count: counts.all })}
              </Button>
            )
          }
        />
      ) : layout === "list" ? (
        <ProductList items={items} onOpen={onOpen} />
      ) : (
        <>
          {urgent.length > 0 && (
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
              {urgent.map((i) => (
                <ProductCard key={i.product.key} item={i} onOpen={onOpen} />
              ))}
            </div>
          )}
          {ok.length > 0 && <OkCards items={ok} heading={urgent.length > 0} onOpen={onOpen} />}
        </>
      )}
      {onSuggest && (
        <p className="flex flex-wrap items-center gap-1 pt-2 text-xs text-muted-foreground">
          {t("suggest.overviewHint")}
          <Button variant="link" size="xs" className="h-auto px-0" onClick={onSuggest}>
            {t("suggest.missing")}
          </Button>
        </p>
      )}
    </div>
  )
}

/** "Mein Team | Alle" – the products of the viewer's teams, or every followed product. */
function ScopeSwitch({ value, onChange, teams }: { value: VendorScope; onChange: (s: VendorScope) => void; teams: { id: string; name: string }[] }) {
  const { t } = useTranslation()
  const names = teams.map((x) => x.name).join(", ")
  return (
    <ToggleGroup type="single" variant="outline" size="sm" spacing={0} value={value} onValueChange={(v) => v && onChange(v as VendorScope)} aria-label={t("vendor.scope.label")}>
      <ToggleGroupItem value="team" title={t("vendor.scope.teamHint", { names })}>
        <UsersRound /> {t("vendor.scope.team")}
      </ToggleGroupItem>
      <ToggleGroupItem value="all" title={t("vendor.scope.allHint")}>
        {t("vendor.scope.all")}
      </ToggleGroupItem>
    </ToggleGroup>
  )
}

const STATUS_HELP: Record<StatusFilter, string> = { action: "vendor.sum.actionHelp", check: "vendor.show.checkHelp", ok: "vendor.ok.help", all: "vendor.show.allHelp" }
const STATUS_TONE: Record<StatusFilter, string> = { action: "--warning", check: "--muted-foreground", ok: "--success", all: "--foreground" }
const STATUS_NAME: Record<StatusFilter, string> = { action: "vendor.show.action", check: "vendor.show.check", ok: "vendor.show.okShort", all: "vendor.show.all" }

/**
 * The status row: "Handlungsbedarf 4 · 2 Sofort | Möglicherweise 1 | Aktuell 1 | Alle 6" – one at a time (a radio
 * group: Tab reaches the chosen field, the arrow keys move and choose), four in a row, a 2×2 grid on phones.
 */
function StatusRow({ value, counts, onChange }: { value: StatusFilter; counts: StatusRowCounts; onChange: (s: StatusFilter) => void }) {
  const { t } = useTranslation()
  return (
    <ToggleGroup
      type="single"
      role="radiogroup"
      value={value}
      onValueChange={(v) => v && onChange(v as StatusFilter)}
      aria-label={t("vendor.show.label")}
      className="grid w-full grid-cols-2 gap-2 sm:grid-cols-4"
      data-testid="vendor-status-row"
    >
      {/* the explanation as a native title: a Radix tooltip around a toggle item would take over its data-state */}
      {STATUS_FILTERS.map((s) => {
        const warn = s === "action" && counts.action > 0
        return (
          <ToggleGroupItem
            key={s}
            value={s}
            // a radio group: the arrow keys move the focus – and the choice with it (Tab lands on the chosen one)
            onFocus={() => s !== value && onChange(s)}
            title={t(STATUS_HELP[s])}
            aria-label={`${t(STATUS_NAME[s])}: ${counts[s]}${s === "action" && counts.now > 0 ? `, ${t("vendor.sum.now", { count: counts.now })}` : ""}`}
            className={cn(
              "h-auto min-w-0 flex-col items-start justify-start gap-0.5 rounded-xl border bg-card px-3 py-2 text-left whitespace-normal hover:bg-muted/50",
              warn && "border-warning/40 bg-warning/5 dark:bg-warning/10",
              "data-[state=on]:border-primary data-[state=on]:bg-accent data-[state=on]:text-accent-foreground data-[state=on]:ring-1 data-[state=on]:ring-primary",
            )}
          >
            <span className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
              {s !== "all" && <span aria-hidden className="size-2 shrink-0 rounded-full" style={{ backgroundColor: `var(${STATUS_TONE[s]})` }} />}
              {t(STATUS_NAME[s])}
            </span>
            <span className="flex flex-wrap items-baseline gap-x-1.5">
              <span className={cn("text-xl leading-tight font-semibold tabular-nums", warn && "text-warning")}>{counts[s]}</span>
              {s === "action" && counts.now > 0 && <span className="text-xs font-medium text-sev-critical">· {t("vendor.sum.now", { count: counts.now })}</span>}
            </span>
          </ToggleGroupItem>
        )
      })}
    </ToggleGroup>
  )
}

function SearchField({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative min-w-0 flex-1 basis-full sm:basis-56">
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input type="search" value={value} onChange={(e) => onChange(e.target.value)} maxLength={80} placeholder={placeholder} aria-label={placeholder} className="h-9 w-full pl-8" />
    </div>
  )
}

/** "Filter": the switches that narrow the list, behind one button – its number says how many are on. */
function FilterMenu({
  uf,
  active,
  onChange,
  unread,
  review,
  scope,
}: {
  uf: VendorUrlFilter
  active: number
  onChange: (f: Partial<VendorUrlFilter>) => void
  /** unread findings of the products not muted */
  unread: number
  /** versions to confirm – null: the review is switched off */
  review: number | null
  scope: { value: VendorScope; onChange: (s: VendorScope) => void; teams: { id: string; name: string }[] } | null
}) {
  const { t } = useTranslation()
  const count = (n: number) => <span className="ml-auto rounded-full bg-muted px-1.5 text-[11px] text-muted-foreground tabular-nums">{n}</span>
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="h-9" aria-label={active ? t("vendor.filters.buttonActive", { count: active }) : t("vendor.filters.button")}>
          <SlidersHorizontal /> {t("vendor.filters.button")}
          {active > 0 && <span className="rounded-full bg-primary px-1.5 text-[11px] leading-4 font-medium text-primary-foreground tabular-nums">{active}</span>}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-[min(20rem,calc(100vw-2rem))] gap-3 p-3">
        <div className="flex items-center gap-2.5">
          <Switch id="vendor-unread" checked={uf.unread} onCheckedChange={(v) => onChange({ unread: v })} />
          <Label htmlFor="vendor-unread" className="flex-1 text-sm" title={t("reader.vendorUnreadHelp")}>
            {t("reader.onlyUnread")}
            {count(unread)}
          </Label>
        </div>
        <div className="flex items-center gap-2.5">
          <Switch id="vendor-muted" checked={uf.muted} onCheckedChange={(v) => onChange({ muted: v })} />
          <Label htmlFor="vendor-muted" className="flex-1 text-sm" title={t("reader.mute.onlyYou")}>
            {t("reader.showMuted")}
          </Label>
        </div>
        {(review !== null || uf.filter === "review") && (
          <div className="flex items-center gap-2.5">
            <Switch id="vendor-review" checked={uf.filter === "review"} onCheckedChange={(v) => onChange({ filter: v ? "review" : null })} />
            <Label htmlFor="vendor-review" className="flex-1 text-sm" title={t("review.sumHelp")}>
              {t("review.filter")}
              {count(review ?? 0)}
            </Label>
          </div>
        )}
        {scope && (
          <div className="space-y-1.5 border-t pt-3">
            <p className="text-xs font-medium text-muted-foreground">{t("vendor.scope.label")}</p>
            <ScopeSwitch value={scope.value} onChange={scope.onChange} teams={scope.teams} />
          </div>
        )}
      </PopoverContent>
    </Popover>
  )
}

// ---------------------------------------------------------------- the action line

/** One line: what to do for these versions ("Update auf 4.14.6 behebt alle 31 Lücken"). */
function actionText(t: (k: string, o?: Record<string, unknown>) => string, g: TargetGroup): string {
  const x = g.target
  // the target itself affected by holes the installed version does not have: said, never hidden
  const intro = x.introduces && x.to ? ` – ${t("vendor.action.introduces", { to: x.to, count: x.introduces })}` : ""
  if (x.kind === "update" && x.to) {
    const head = x.open === 0 ? t("vendor.action.updateAll", { to: x.to, count: x.total }) : t("vendor.action.updatePart", { to: x.to, fixes: x.fixes, total: x.total })
    if (x.open === 0) return head + intro
    const rest = x.newer ? t("vendor.action.openNewer", { count: x.newer.fixes, line: x.newer.line }) : t("vendor.action.openNoFix", { count: x.open })
    return `${head} – ${rest}${intro}`
  }
  if (x.kind === "newer_line" && x.line) {
    const detail = !x.to
      ? ""
      : ` – ${x.open === 0 ? t("vendor.action.newerLineAll", { to: x.to, count: x.total }) : t("vendor.action.newerLineTo", { to: x.to, fixes: x.fixes, total: x.total })}`
    return t("vendor.action.newerLine", { line: x.line }) + detail + intro
  }
  if (x.kind === "no_fix") return t("vendor.action.noFix", { count: x.total })
  return t("vendor.action.versionOk")
}

const TIER_TONE: Record<Urgency, string> = {
  exploited: "--sev-critical",
  critical: "--sev-critical",
  affected: "--warning",
  possible: "--muted-foreground",
  info: "--sev-low",
  ok: "--success",
}

/** What to do for the product, strongest signals beside it – the first thing a card says. */
function ActionBlock({ item }: { item: OverviewItem }) {
  const { t } = useTranslation()
  const tier = urgencyOf(item)
  const tone = TIER_TONE[tier]
  const c = item.counts
  const groups = targetGroups(item).filter((g) => g.target.total > 0)
  const support = supportOf(item)
  const newer = item.releases.find((r) => r.newer_line)?.newer_line
  let lines: { icon: React.ElementType; text: string; versions?: string[] }[] = []
  if (groups.length > 0) {
    const many = targetGroups(item).length > 1
    lines = groups.map((g) => ({
      icon: g.target.kind === "newer_line" ? ArrowUpCircle : g.target.kind === "no_fix" ? CircleAlert : TrendingUp,
      text: actionText(t, g),
      versions: many ? g.versions.map((v) => v.version) : undefined,
    }))
  } else if (item.product.cloud && c.service > 0) lines = [{ icon: Cloud, text: t("vendor.action.service") }]
  else if (item.versions.length === 0 && !item.product.cloud && c.unversioned > 0) lines = [{ icon: CircleHelp, text: t("vendor.action.unversioned") }]
  else if (support.state === "past") lines = [{ icon: CalendarClock, text: newer ? t("vendor.action.eolPastTo", { line: newer.label ?? newer.name }) : t("vendor.action.eolPast") }]
  else if (c.possible > 0) lines = [{ icon: CircleHelp, text: t("vendor.action.possible", { count: c.possible }) }]
  else if (support.state === "soon" && support.until) lines = [{ icon: CalendarClock, text: t("vendor.action.eolSoon", { when: fmtDayFrom(support.until) }) }]
  else lines = [{ icon: CheckCircle2, text: t("vendor.action.ok") }]
  const shown = lines.slice(0, 4)
  const exploited = c.exploited_affected ?? 0
  const critical = c.critical_affected ?? 0
  return (
    <div className="space-y-1.5">
      <ul className="space-y-1">
        {shown.map((l, n) => (
          <li key={n} className="flex items-start gap-2 text-sm leading-snug font-medium">
            <l.icon className="mt-0.5 size-4 shrink-0" style={{ color: `var(${tone})` }} />
            <span className="min-w-0">
              {l.versions && <span className="mr-1.5 font-mono text-xs text-muted-foreground">{l.versions.join(", ")}</span>}
              {l.text}
              {n === 0 && groups.length > 0 && (
                <span className="ml-1 inline-flex align-[-2px]">
                  <Explained label={<span className="sr-only">{t("vendor.col.target")}</span>} text={t("vendor.action.help")} />
                </span>
              )}
            </span>
          </li>
        ))}
        {lines.length > shown.length && <li className="pl-6 text-xs text-muted-foreground">{t("vendor.card.moreVersionsLines", { count: lines.length - shown.length })}</li>}
      </ul>
      {(exploited > 0 || critical > 0) && (
        <div className="flex flex-wrap items-center gap-1.5 pl-6">
          {exploited > 0 && (
            <Pill color="--sev-critical">
              <AlertTriangle /> {t("vendor.card.exploited", { count: exploited })}
            </Pill>
          )}
          {critical > 0 && <Pill color="--sev-critical">{t("vendor.card.critical", { count: critical })}</Pill>}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------- the card

// a version's dot on the card: affected amber (red is for exploited / critical – the card's accent and chips say that)
const VERSION_DOT = { affected: "--warning", possible: "--muted-foreground", not_affected: "--success" } as const

const CARD_TONE: Partial<Record<Urgency, string>> = { exploited: "--sev-critical", critical: "--sev-critical", affected: "--warning" }

/** One followed product: what to do, its versions with their support, the three worst findings. */
export const ProductCard = memo(function ProductCard({ item, onOpen }: { item: OverviewItem; onOpen: OnOpen }) {
  const { t } = useTranslation()
  const ct = useCatalogTexts()
  const { product: p, counts, versions, releases } = item
  const tier = urgencyOf(item)
  const accent = CARD_TONE[tier]
  const shownAffected = item.latest.filter((f) => f.status === "affected").length
  const shownPossible = item.latest.filter((f) => f.status === "possible").length
  const moreAffected = counts.affected - shownAffected
  const morePossible = counts.possible - shownPossible
  return (
    <article
      className={cn(
        "group relative flex min-h-44 flex-col gap-3 overflow-hidden rounded-xl border bg-card p-4 text-left transition-colors hover:bg-muted/30 has-[[data-open]:focus-visible]:ring-2 has-[[data-open]:focus-visible]:ring-ring",
        !accent && "hover:border-primary/40",
        item.muted && !item.muted_kev && "opacity-60",
      )}
      style={accent ? { borderColor: `color-mix(in oklch, var(${accent}) 45%, transparent)` } : undefined}
      data-urgency={tier}
    >
      {accent && <span aria-hidden className="absolute inset-y-0 left-0 w-1" style={{ backgroundColor: `var(${accent})` }} />}
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <p className="truncate text-xs text-muted-foreground">{p.vendor}</p>
          <h3 className="text-sm leading-snug font-semibold">
            <button type="button" data-open onClick={() => onOpen(p.key)} className="text-left outline-none after:absolute after:inset-0 after:rounded-xl after:content-['']">
              {p.label}
            </button>
          </h3>
          <SameData names={item.same_data} />
          <ProductChangedHint changed={item.changed} />
          <ReaderPills item={item} />
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <div className="flex items-center gap-1">
            <Pill color="--muted-foreground">{ct.cat(p.category)}</Pill>
            <ProductMenu item={item} />
          </div>
          {item.score && <ScorePill score={item.score} />}
        </div>
      </div>
      <ActionBlock item={item} />
      {versions.length > 0 ? (
        <ul className="space-y-1">
          {versions.slice(0, 4).map((v) => {
            const s = item.summary.per_version[v.id]
            const rel = releases.find((r) => r.version_id === v.id)
            const tone = s?.affected ? "affected" : s?.possible ? "possible" : "not_affected"
            return (
              <li key={v.id} className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
                <span className="size-1.5 shrink-0 rounded-full" style={{ backgroundColor: `var(${VERSION_DOT[tone]})` }} />
                <span className="font-mono font-medium">{v.version}</span>
                {v.short && <ShortPill version={v.version} />}
                {v.review?.due && <DuePill days={v.review.age_days} />}
                {(v.label || v.count) && (
                  <span className="min-w-0 truncate text-muted-foreground">
                    {v.label}
                    {v.label && v.count ? " · " : ""}
                    {v.count ? t("vendor.devices", { count: v.count }) : ""}
                  </span>
                )}
                <SupportPill state={rel?.eol_state} until={rel?.line?.eol_from ?? null} />
              </li>
            )
          })}
          {versions.length > 4 && <li className="text-xs text-muted-foreground">{t("vendor.card.moreVersions", { count: versions.length - 4 })}</li>}
        </ul>
      ) : (
        !p.cloud && counts.unversioned === 0 && <p className="text-xs text-muted-foreground">{t("vendor.giveVersion")}</p>
      )}
      {item.latest.length > 0 && (
        // the worst first, like the drawer – a click opens the drawer at that finding
        <div className="relative z-10 mt-auto space-y-0.5 border-t pt-2">
          <ul className="space-y-0.5">
            {item.latest.slice(0, 3).map((f) => (
              <li key={f.id}>
                <FindingLine
                  f={f}
                  productKey={p.key}
                  onOpen={onOpen}
                  prefix={tier === "affected" || tier === "critical" || tier === "exploited" ? f.status !== "affected" : f.status !== "possible"}
                />
              </li>
            ))}
          </ul>
          {(moreAffected > 0 || morePossible > 0) && (
            <button
              type="button"
              onClick={() => onOpen(p.key)}
              className="px-1 text-xs text-muted-foreground outline-none hover:text-foreground hover:underline focus-visible:ring-2 focus-visible:ring-ring/50"
            >
              {[moreAffected > 0 && t("vendor.card.moreAffected", { count: moreAffected }), morePossible > 0 && t("vendor.card.morePossible", { count: morePossible })]
                .filter(Boolean)
                .join(" · ")}
            </button>
          )}
        </div>
      )}
    </article>
  )
})

/** "gleiche Schwachstellendaten wie Wazuh Manager" – the NVD does not tell the products apart. */
function SameData({ names }: { names?: string[] }) {
  const { t } = useTranslation()
  if (!names?.length) return null
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className="relative z-10 mt-0.5 inline-flex cursor-help items-center gap-1 text-[11px] text-muted-foreground underline decoration-dotted underline-offset-2"
        >
          <Copy className="size-3 shrink-0" /> {t("vendor.card.sameData", { names: names.join(", ") })}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">{t("vendor.card.sameDataHelp")}</TooltipContent>
    </Tooltip>
  )
}

/** "ungenau": a short version ("7.4" for FortiOS 7.4.8) stands for several releases – as on the Versionen tab. */
/** "Bitte prüfen": the version was not confirmed for longer than the interval. */
export function DuePill({ days, compact = false }: { days: number; compact?: boolean }) {
  const { t } = useTranslation()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="relative z-10 cursor-help rounded-full font-sans outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          <Pill color="--warning">
            <Clock /> {compact ? <span className="sr-only">{t("review.due")}</span> : t("review.due")}
          </Pill>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">{t("review.dueHint", { count: days })}</TooltipContent>
    </Tooltip>
  )
}

function ShortPill({ version }: { version: string }) {
  const { t } = useTranslation()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="relative z-10 cursor-help rounded-full font-sans outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          <Pill color="--warning">
            <AlertTriangle /> {t("vendor.v.short")}
          </Pill>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">{t("vendor.v.shortHint", { version })}</TooltipContent>
    </Tooltip>
  )
}

function SupportPill({ state, until }: { state?: string; until: string | null }) {
  const { t } = useTranslation()
  if (state !== "past" && state !== "soon") return null
  const pill = (
    <Pill color={state === "past" ? "--sev-critical" : "--warning"}>
      <CalendarClock /> {t(state === "past" ? "vendor.v.supportEndedNoDate" : "vendor.card.eolSoon")}
    </Pill>
  )
  if (!until) return pill
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="relative z-10 cursor-help">
          {pill}
        </span>
      </TooltipTrigger>
      <TooltipContent>{state === "past" ? t("vendor.v.supportEnded", { date: fmtDay(until) }) : t("vendor.card.supportUntil", { date: fmtDay(until) })}</TooltipContent>
    </Tooltip>
  )
}

/** CVSS badge, CVE, readable title – the drawer opens at it. */
function FindingLine({ f, productKey, onOpen, prefix }: { f: OverviewItem["latest"][number]; productKey: string; onOpen: OnOpen; prefix: boolean }) {
  const { t } = useTranslation()
  const sev = NEWS_SEV_COLOR[f.severity]
  const cve = normalizeCve(f.ident)
  const line = (
    <button
      type="button"
      onClick={() => onOpen(productKey, f.id)}
      aria-label={t("vendor.card.openFinding", { ident: f.ident })}
      className="flex w-full min-w-0 items-center gap-1.5 rounded px-1 py-0.5 text-left text-xs outline-none hover:bg-muted/60 focus-visible:ring-2 focus-visible:ring-ring/50"
    >
      <span
        className="w-8 shrink-0 rounded px-1 py-px text-center font-mono text-[11px] font-semibold tabular-nums"
        style={{ color: `var(${sev})`, backgroundColor: `color-mix(in oklch, var(${sev}) 13%, transparent)` }}
        title={`CVSS ${f.cvss?.toFixed(1) ?? "–"}`}
      >
        {f.cvss !== null ? f.cvss.toFixed(1) : t("vendor.card.cvssNone")}
      </span>
      {prefix && (
        <span className="shrink-0 font-medium" style={{ color: `var(${STATUS_COLOR[f.status]})` }}>
          {t(`vendor.card.short.${f.status}`, { defaultValue: "" })}
        </span>
      )}
      <span className={cn("line-clamp-1 min-w-0 text-muted-foreground", f.muted && "opacity-60")}>
        {f.unread && <span aria-hidden className="mr-1 inline-block size-1.5 rounded-full bg-primary align-middle" />}
        {f.unread && <span className="sr-only">{t("reader.unread")}: </span>}
        <span className={cn("font-mono text-foreground/80", f.unread && "font-semibold text-foreground")}>{f.ident}</span> {f.headline || f.title}
      </span>
      {f.exploited && <AlertTriangle className="size-3 shrink-0 text-sev-critical" aria-label={t("vendor.exploited")} />}
    </button>
  )
  const tlp = f.tlp === "GREEN"
  if (!cve && !tlp) return line
  // beside the line, not inside its button: the star of a finding named by its CVE, and the TLP:GREEN pill – a focus
  // stop of its own, so a tap explains it (inside the button a tap only opened the finding)
  return (
    <span className="flex items-center gap-0.5">
      <span className="min-w-0 flex-1">{line}</span>
      {tlp && <TlpPill compact />}
      {cve && <WatchStar cve={cve} origin={{ kind: "finding", product: productKey, advisory: f.id }} />}
    </span>
  )
}

// ---------------------------------------------------------------- products with nothing to do

/** Products where all is well: compact green cards (after the others, or alone under "Alles aktuell"). */
function OkCards({ items, heading, onOpen }: { items: OverviewItem[]; heading: boolean; onOpen: OnOpen }) {
  const { t } = useTranslation()
  return (
    <section className="space-y-2" aria-labelledby="vendor-ok-title">
      <h3 id="vendor-ok-title" className={cn("flex items-center gap-1.5 pt-1 text-sm font-medium text-success", !heading && "sr-only")}>
        <CheckCircle2 className="size-4" />
        <Explained label={t("vendor.show.ok")} text={t("vendor.ok.help")} />
        <span className="text-xs font-normal text-muted-foreground tabular-nums">{items.length}</span>
      </h3>
      <ul className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        {items.map((i) => (
          <OkCard key={i.product.key} item={i} onOpen={onOpen} />
        ))}
      </ul>
    </section>
  )
}

const OkCard = memo(function OkCard({ item, onOpen }: { item: OverviewItem; onOpen: OnOpen }) {
  const { t } = useTranslation()
  const { product: p, versions } = item
  const shown = versions.map((v) => v.version).join(", ")
  const due = versions.filter((v) => v.review?.due)
  return (
    <li
      className="relative flex min-w-0 items-start gap-2.5 rounded-xl border border-success/30 bg-card px-3 py-2.5 transition-colors hover:bg-muted/30 has-[[data-open]:focus-visible]:ring-2 has-[[data-open]:focus-visible]:ring-ring"
      data-urgency="ok"
    >
      <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" aria-hidden />
      <div className="min-w-0 flex-1">
        <button
          type="button"
          data-open
          onClick={() => onOpen(p.key)}
          className="text-left text-sm leading-snug font-semibold outline-none after:absolute after:inset-0 after:rounded-xl after:content-['']"
        >
          {p.label}
        </button>
        {due.length > 0 && (
          <span className="ml-1.5">
            <DuePill days={Math.max(...due.map((v) => v.review?.age_days ?? 0))} compact />
          </span>
        )}
        <p className="truncate text-xs text-muted-foreground" title={shown || undefined}>
          {p.vendor}
          {shown ? (
            <>
              {" · "}
              <span className="font-mono">{shown}</span>
            </>
          ) : null}
        </p>
      </div>
      <span className="sr-only">{t("vendor.action.ok")}</span>
    </li>
  )
})

// ---------------------------------------------------------------- the list

const COLS: { key: SortKey; label: string; num?: boolean }[] = [
  { key: "product", label: "vendor.col.product" },
  { key: "score", label: "vendor.col.score", num: true },
  { key: "versions", label: "vendor.col.versions" },
  { key: "target", label: "vendor.col.target" },
  { key: "affected", label: "vendor.col.affected", num: true },
  { key: "critical", label: "vendor.col.critical", num: true },
  { key: "exploited", label: "vendor.col.exploited", num: true },
  { key: "support", label: "vendor.col.support" },
]
const GRID = "sm:grid sm:grid-cols-[minmax(0,2.2fr)_6.5rem_minmax(0,1.3fr)_minmax(0,1.3fr)_4.5rem_4.5rem_5rem_7rem] sm:items-center sm:gap-x-4"
// numbers sort the most first (also the Dringlichkeit)
const DESC_FIRST: string[] = ["score", "affected", "critical", "exploited", "versions"]

/** The products as a sortable table – at 375 px each row with its labels (docs/UX.md). */
function ProductList({ items, onOpen }: { items: OverviewItem[]; onOpen: OnOpen }) {
  const { t } = useTranslation()
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "urgency", desc: false })
  const rows = useMemo(() => sortItems(items, sort.key, sort.desc), [items, sort])
  const click = (key: SortKey) => setSort((s) => (s.key === key ? { key, desc: !s.desc } : { key, desc: DESC_FIRST.includes(key) }))
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 sm:hidden">
        <span className="text-xs text-muted-foreground">{t("vendor.col.sortBy")}</span>
        <Select value={sort.key} onValueChange={(v) => setSort({ key: v as SortKey, desc: DESC_FIRST.includes(v) })}>
          <SelectTrigger size="sm" className="w-48">
            <SelectValue />
          </SelectTrigger>
          <SelectContent position="popper">
            <SelectItem value="urgency">{t("vendor.col.urgency")}</SelectItem>
            {COLS.map((c) => (
              <SelectItem key={c.key} value={c.key}>
                {t(c.label)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="rounded-xl border bg-card" role="table" aria-label={t("vendor.tab.overview")}>
        <div role="row" className={cn("hidden border-b px-3 py-2 text-xs font-medium text-muted-foreground", GRID)}>
          {COLS.map((c) => (
            <span
              role="columnheader"
              key={c.key}
              aria-sort={sort.key === c.key ? (sort.desc ? "descending" : "ascending") : "none"}
              className={cn("min-w-0", c.num && "flex justify-end")}
            >
              {/* numbers: right-aligned like their cells, the sort arrow before the label so label and numbers line up */}
              <button
                type="button"
                onClick={() => click(c.key)}
                title={t("vendor.col.sort", { col: t(c.label) })}
                className={cn(
                  "inline-flex max-w-full items-center gap-1 rounded text-left outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50",
                  c.num && "flex-row-reverse text-right",
                )}
              >
                {c.key === "target" ? (
                  <Explained label={t(c.label)} text={t("vendor.action.help")} />
                ) : c.key === "score" ? (
                  <Explained label={t(c.label)} text={t("vendor.score.help")} />
                ) : (
                  t(c.label)
                )}
                {sort.key === c.key && (sort.desc ? <ArrowDown className="size-3" /> : <ArrowUp className="size-3" />)}
              </button>
            </span>
          ))}
        </div>
        <ul className="divide-y" role="rowgroup">
          {rows.map((i) => (
            <ListRow key={i.product.key} item={i} onOpen={onOpen} />
          ))}
        </ul>
      </div>
    </div>
  )
}

const ListRow = memo(function ListRow({ item, onOpen }: { item: OverviewItem; onOpen: OnOpen }) {
  const { t } = useTranslation()
  const { product: p, counts: c } = item
  const tier = urgencyOf(item)
  const accent = CARD_TONE[tier]
  const groups = targetGroups(item).filter((g) => g.target.total > 0)
  const first = groups[0]?.target
  const support = supportOf(item)
  const label = (k: string) => <span className="font-sans text-xs text-muted-foreground sm:hidden">{t(k)}: </span>
  const num = (n: number, tone?: string) => (
    <span className={cn("tabular-nums", !n && "text-muted-foreground")} style={n && tone ? { color: `var(${tone})` } : undefined}>
      {n}
    </span>
  )
  return (
    <li
      role="row"
      className={cn("relative grid grid-cols-2 gap-x-3 gap-y-1 px-3 py-2.5 text-sm hover:bg-muted/30", GRID, item.muted && !item.muted_kev && "opacity-60")}
      data-urgency={tier}
    >
      {accent && <span aria-hidden className="absolute inset-y-0 left-0 w-1" style={{ backgroundColor: `var(${accent})` }} />}
      <span role="cell" className="col-span-2 min-w-0 sm:col-span-1">
        <button type="button" onClick={() => onOpen(p.key)} className="text-left font-medium outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring/50">
          {p.label}
        </button>
        <span className="block truncate text-xs text-muted-foreground">{p.vendor}</span>
        <SameData names={item.same_data} />
        <ProductChangedHint changed={item.changed} />
        <ReaderPills item={item} />
      </span>
      <span role="cell" className="flex items-center gap-1 sm:block sm:text-right">
        {label("vendor.col.score")}
        {item.score ? <ScorePill score={item.score} compact /> : <span className="text-xs text-muted-foreground">–</span>}
      </span>
      <span role="cell" className="col-span-2 min-w-0 font-mono text-xs sm:col-span-1">
        {label("vendor.col.versions")}
        {item.versions.length ? (
          item.versions.map((v, n) => (
            <span key={v.id} className="inline-flex items-center gap-1">
              {v.version}
              {v.short && <ShortPill version={v.version} />}
              {v.review?.due && <DuePill days={v.review.age_days} compact />}
              {n < item.versions.length - 1 && <span className="-ml-0.5">,</span>}
            </span>
          ))
        ) : (
          <span className="font-sans text-muted-foreground">{t("vendor.noVersions")}</span>
        )}
      </span>
      <span role="cell" className="col-span-2 min-w-0 text-xs sm:col-span-1">
        {label("vendor.col.target")}
        {first?.to ? (
          <span className="font-mono font-medium" title={actionText(t, groups[0])}>
            {first.kind === "newer_line" && first.line ? t("vendor.col.newerLine", { line: first.line }) + " · " : ""}
            {first.to}
            {groups.length > 1 && <span className="ml-1 font-sans text-muted-foreground">+{groups.length - 1}</span>}
          </span>
        ) : first?.kind === "no_fix" ? (
          <span className="text-warning">{t("vendor.action.noFix", { count: first.total })}</span>
        ) : (
          <span className="text-muted-foreground">{t("vendor.col.noTarget")}</span>
        )}
      </span>
      <span role="cell" className="flex gap-1 sm:block sm:text-right">
        {label("vendor.col.affected")}
        {num(c.affected, "--warning")}
      </span>
      <span role="cell" className="flex gap-1 sm:block sm:text-right">
        {label("vendor.col.critical")}
        {num(c.critical_affected ?? 0, "--sev-critical")}
      </span>
      <span role="cell" className="flex gap-1 sm:block sm:text-right">
        {label("vendor.col.exploited")}
        {num(c.exploited_affected ?? 0, "--sev-critical")}
      </span>
      <span role="cell" className="text-xs tabular-nums">
        {label("vendor.col.support")}
        {support.until ? (
          <span style={support.state === "past" || support.state === "soon" ? { color: `var(${support.state === "past" ? "--sev-critical" : "--warning"})` } : undefined}>
            {fmtDay(support.until)}
          </span>
        ) : (
          <span className="text-muted-foreground">–</span>
        )}
      </span>
    </li>
  )
})

// ---------------------------------------------------------------- read state and mutes (app/reader.py)

/** "3 neu", "Stumm bis …", and "KEV trotz Stummschaltung" – an exploited vulnerability stays visible while muted. */
function ReaderPills({ item }: { item: OverviewItem }) {
  const { t } = useTranslation()
  const n = item.unread ?? 0
  if (!n && !item.muted) return null
  return (
    <span className="relative z-10 mt-1 flex flex-wrap items-center gap-1">
      {n > 0 && (
        <Pill color="--primary" dot>
          {t("reader.newCount", { count: n })}
        </Pill>
      )}
      {item.muted && (
        <span title={t("reader.mute.onlyYou")}>
          <Pill color="--muted-foreground">
            <BellOff /> {t("reader.mute.until", { date: fmtDate(item.muted.until) })}
          </Pill>
        </span>
      )}
      {item.muted && item.muted_kev && (
        <span title={t("reader.mute.kevHelp")}>
          <Pill color="--sev-critical">
            <AlertTriangle /> {t("reader.mute.kev")}
          </Pill>
        </span>
      )}
    </span>
  )
}

/** The card's menu: the product's findings read, and muting the product for a while (only for me). */
function ProductMenu({ item }: { item: OverviewItem }) {
  const { t } = useTranslation()
  const marks = useVendorRead()
  const [until, setUntil] = useState<MuteTarget | null>(null)
  const target: MuteTarget = { kind: "product", key: item.product.key, label: item.product.label }
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            aria-label={t("reader.menuOf", { name: item.product.label })}
            title={t("reader.menu")}
            className="relative z-10 flex size-6 items-center justify-center rounded-md text-muted-foreground outline-none hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
          >
            <MoreHorizontal className="size-4" />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          <DropdownMenuItem disabled={!item.unread} onSelect={() => marks.read.mutate({ product: item.product.key }, { onError: (e) => toast.error(errorText(t, e)) })}>
            <CheckCheck /> {t("reader.productRead")}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <MuteItems targets={[target]} onUntil={setUntil} />
        </DropdownMenuContent>
      </DropdownMenu>
      <MuteUntilDialog target={until} onClose={() => setUntil(null)} />
    </>
  )
}
