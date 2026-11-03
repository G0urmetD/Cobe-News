import { memo, useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from "react"
import { Link, useNavigate, useSearchParams } from "react-router"
import { useTranslation } from "react-i18next"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  CircleHelp,
  Clock,
  Cloud,
  ExternalLink,
  History,
  Library,
  Lightbulb,
  ListChecks,
  Loader2,
  MessageSquarePlus,
  MoreHorizontal,
  Newspaper,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Settings2,
  ShieldAlert,
  Stethoscope,
  Trash2,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill } from "@/components/cobe/badges"
import { EmptyState, MoreText, PageHeader } from "@/components/cobe/common"
import { Field } from "@/components/cobe/form"
import { Explained } from "@/components/cobe/explained"
import { Term } from "@/components/cobe/glossary"
import { EpssPill, SsvcPill } from "@/components/cobe/epss"
import { ExploitHints } from "@/components/cobe/exploit"
import { ScorePill } from "@/components/cobe/score"
import { ForwardButton } from "@/components/cobe/forward"
import { DrawerSkeleton, QueryError } from "@/components/cobe/query-state"
import { SubTabs } from "@/components/cobe/sub-tabs"
import { Ts } from "@/components/cobe/time"
import { confirmAction } from "@/components/cobe/confirm"
import { ChangedBadge, ProductChanges } from "@/components/cobe/advisory-changes"
import { CveChips, WatchAllButton } from "@/components/cobe/watch-all"
import { MuteButton } from "@/components/cobe/mute-menu"
import { useDefaultView } from "@/components/cobe/views-menu"
import { IN_PAGE, badgeText, readVendorFilter, readerVisible, useVendorRead } from "@/lib/reader-api"
import { type VendorPlace, placeLink, placeOf } from "@/lib/vendor-filters"
import { Versions } from "@/pages/vendor-versions"
import { Overview } from "@/pages/vendor-overview"
import { SuggestButton, SuggestSheet, SuggestionsTab } from "@/pages/vendor-suggestions"
import { SUGGESTIONS_KEY, type Suggestion, acceptWith, useSuggestionCount } from "@/lib/suggestions"
import { useSettled } from "@/hooks/use-settled"
import { ApiError, api } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { errorText } from "@/lib/errors"
import { restoreFocus } from "@/lib/focus"
import { fmtDay, fmtDayFrom } from "@/lib/format"
import { NEWS_SEV_COLOR, type NewsSeverity } from "@/lib/news-api"
import { careReason } from "@/lib/catalog-care"
import { CategoryIcon } from "@/lib/catalog-icons"
import { useCatalogTexts } from "@/lib/catalog-texts"
import { type VendorScope, useVendorScope } from "@/lib/teams-api"
import { cn } from "@/lib/utils"
import {
  ADVISORY_SOURCE_LABEL,
  STATUS_COLOR,
  type FindingSort,
  type FollowedVersion,
  type Finding,
  type CatalogCheckVerdict,
  type ProductDetail,
  type Status,
  type VendorCatalog,
  type VendorOverview,
  type VendorProduct,
  FINDINGS_PAGE,
  affectedVersions,
  findingCounts,
  matchScore,
  mergeFindingPages,
  productKeyOf,
  overviewStats,
  refreshVendor,
  useVendorCatalog,
  useVendorOverview,
  useVendorProduct,
  visibleFindings,
} from "@/lib/vendor-api"

/** Vendor News: the products this installation follows (cards), the catalogue to pick them from, a drawer per product. */
export function VendorPage() {
  const { t } = useTranslation()
  const { isAdmin, user } = useAuth()
  const [params, setParams] = useSearchParams()
  // reached without a filter (the sidebar, a link): the person's default view of Vendor News, if they set one
  useDefaultView("vendor")
  // no tabs: the overview, and the catalogue and the suggestions as parts of their own (?tab= as before – old links
  // and bookmarks still lead there)
  const place = placeOf(params)
  const qc = useQueryClient()
  // Produkt vorschlagen: the form (with what was searched), the admins' "Übernehmen" by CPE (the add form prefilled)
  const [suggest, setSuggest] = useState<{ n: number; term: string } | null>(null)
  const [adopt, setAdopt] = useState<Suggestion | null>(null)
  const openSuggest = useCallback((term = "") => setSuggest((x) => ({ n: (x?.n ?? 0) + 1, term })), [])
  const open = params.get("product")
  // "Mein Team / Alle" lives here: the header's line and the overview share one request
  const scope = useVendorScope(user?.id)
  // the drawer stays mounted while it slides out – with the product it showed
  const [shown, setShown] = useState<string | null>(open)
  if (open && open !== shown) setShown(open)
  // what opened the drawer (a card, a row, a finding line) gets the focus back when it closes
  const opener = useRef<Element | null>(null)
  const setOpen = useCallback(
    (key: string | null, finding?: string) => {
      if (key) opener.current = document.activeElement
      setParams(
        (p) => {
          const next = new URLSearchParams(p)
          next.delete("view")
          next.delete("finding")
          if (key) {
            next.set("product", key)
            if (finding) next.set("finding", finding) // the drawer scrolls to it and marks it
          } else next.delete("product")
          return next
        },
        { replace: !key, state: IN_PAGE },
      )
    },
    [setParams],
  )
  const closed = useCallback(() => {
    setShown(null)
    restoreFocus(opener.current)
    opener.current = null
  }, [])
  return (
    <div className="space-y-5">
      <PageHeader
        title={t("nav.vendor")}
        description={place === "overview" ? <HeadLine scope={scope.scope} /> : undefined}
        actions={<HeaderActions onSuggest={() => openSuggest()} />}
      />
      {place !== "overview" && <PlaceHead place={place} />}
      {place === "overview" ? (
        <Overview onOpen={setOpen} scope={scope} onSuggest={() => openSuggest()} />
      ) : place === "catalog" ? (
        <Catalog onOpen={setOpen} onSuggest={openSuggest} />
      ) : (
        <SuggestionsTab onOpen={setOpen} onSuggest={() => openSuggest()} onAdopt={setAdopt} />
      )}
      {suggest && <SuggestSheet key={suggest.n} open onClose={() => setSuggest(null)} initial={suggest.term} onOpen={setOpen} />}
      {isAdmin && adopt && (
        <CustomProduct
          key={adopt.id}
          open
          initial={{ q: adopt.cpe_short ? "" : `${adopt.vendor} ${adopt.product}`.slice(0, 60), cpe: adopt.cpe_short ?? "", label: adopt.product }}
          onClose={() => setAdopt(null)}
          onAdded={(key) => {
            // added (and followed): the suggestion is accepted with it
            void acceptWith(adopt, key).then(
              () => {
                toast.success(t("suggest.done.accept"))
                void qc.invalidateQueries({ queryKey: SUGGESTIONS_KEY })
              },
              (e) => toast.error(errorText(t, e)),
            )
            setOpen(key)
          }}
        />
      )}
      {/* one drawer per product: its switches, folded groups and loaded pages start afresh with another product */}
      {shown && <ProductDrawer key={shown} productKey={shown} open={!!open} onClose={() => setOpen(null)} onClosed={closed} />}
    </div>
  )
}

/** The one line under the title: the next end of support among the products shown, and when the sources last answered. */
function HeadLine({ scope }: { scope: VendorScope | null }) {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const d = useVendorOverview(scope).data
  const uf = useMemo(() => readVendorFilter(params), [params])
  const next = useMemo(() => (d ? overviewStats(readerVisible(d.items, uf)).next : null), [d, uf])
  const st = d?.status
  if (!st?.enabled) return null
  const parts: React.ReactNode[] = []
  if (next) parts.push(<span key="eol">{t("vendor.head.nextEnd", { product: next.item.product.label, when: fmtDayFrom(next.date) })}</span>)
  if (!st.fetched)
    parts.push(
      <span key="first">
        <Loader2 className="inline size-3 animate-spin align-[-2px]" aria-hidden /> {t("vendor.firstFetch")}
      </span>,
    )
  else if (st.last_ok_at)
    parts.push(
      <span key="fetched">
        {t("vendor.head.fetched")} <Ts at={st.last_ok_at} rel />
      </span>,
    )
  if (st.errors > 0)
    parts.push(
      <span key="errors" className="text-warning">
        {t("vendor.sourceErrors", { count: st.errors })}
      </span>,
    )
  if (!parts.length) return null
  return (
    <span className="block text-xs" data-testid="vendor-headline">
      {/* the dot stays with the part before it: a wrapped line never starts with one */}
      {parts.map((p, n) => (
        <span key={n}>
          {p}
          {n < parts.length - 1 && <span aria-hidden>{"\u00a0·"} </span>}
        </span>
      ))}
    </span>
  )
}

/** Right of the title: "Vorschläge" while some wait for an admin, and "⋯" with the rest – a reader sees no admin entry. */
function HeaderActions({ onSuggest }: { onSuggest: () => void }) {
  const { t } = useTranslation()
  const { isAdmin } = useAuth()
  const qc = useQueryClient()
  const [params] = useSearchParams()
  const sc = useSuggestionCount().data
  const waiting = isAdmin ? (sc?.open ?? 0) : 0
  const answered = sc?.answered ?? 0
  const [fetching, setFetching] = useState(false)
  const fetchNow = async () => {
    setFetching(true)
    try {
      await api.post("/api/admin/vendor/fetch")
      toast.success(t("settings.vendor.fetching"))
      void qc.invalidateQueries({ queryKey: ["vendor", "overview"] })
      setTimeout(() => void qc.invalidateQueries({ queryKey: ["vendor", "overview"] }), 20_000)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setFetching(false)
    }
  }
  const badge = (n: number, tone = "bg-primary text-primary-foreground") =>
    n > 0 && <span className={cn("ml-auto rounded-full px-1.5 text-[11px] leading-4 font-medium tabular-nums", tone)}>{badgeText(n)}</span>
  return (
    <>
      {waiting > 0 && (
        <Button variant="outline" size="sm" asChild>
          <Link to={placeLink(params, "suggestions")} state={IN_PAGE} aria-label={t("vendor.head.suggestionsWaiting", { count: waiting })}>
            <Lightbulb /> {t("suggest.tab")}
            <span className="rounded-full bg-primary px-1.5 text-[11px] leading-4 font-medium text-primary-foreground tabular-nums">{badgeText(waiting)}</span>
          </Link>
        </Button>
      )}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            size="icon-sm"
            className="relative"
            aria-label={answered > 0 ? t("vendor.head.moreAnswered", { count: answered }) : t("vendor.head.more")}
            title={t("vendor.head.more")}
          >
            <MoreHorizontal />
            {answered > 0 && <span aria-hidden className="absolute -top-0.5 -right-0.5 size-2 rounded-full bg-warning ring-2 ring-background" />}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-60">
          <DropdownMenuItem asChild>
            <Link to={placeLink(params, "catalog")} state={IN_PAGE}>
              {isAdmin ? <Plus /> : <Library />} {t(isAdmin ? "vendor.head.add" : "vendor.head.browse")}
            </Link>
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={onSuggest}>
            <MessageSquarePlus /> {t("suggest.title")}
          </DropdownMenuItem>
          <DropdownMenuItem asChild>
            <Link to={placeLink(params, "suggestions")} state={IN_PAGE}>
              <Lightbulb /> {t(isAdmin ? "suggest.tab" : "suggest.mine")}
              {badge(waiting || answered, waiting ? undefined : "bg-warning/25 text-foreground")}
            </Link>
          </DropdownMenuItem>
          {isAdmin && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem disabled={fetching} onSelect={() => void fetchNow()}>
                {fetching ? <Loader2 className="animate-spin" /> : <RefreshCw />} {t("settings.news.fetchNow")}
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link to="/settings/integrations#vendor">
                  <Settings2 /> {t("vendor.settings")}
                </Link>
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  )
}

/** Above the catalogue and the suggestions: the way back to the overview (its filters kept) and what this part is. */
function PlaceHead({ place }: { place: Exclude<VendorPlace, "overview"> }) {
  const { t } = useTranslation()
  const { isAdmin } = useAuth()
  const [params] = useSearchParams()
  const title = place === "catalog" ? t("vendor.tab.catalog") : t(isAdmin ? "suggest.tab" : "suggest.mine")
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      {/* no IN_PAGE state: back in an address without a filter, the default view applies as on arrival */}
      <Button variant="ghost" size="sm" className="-ml-2" asChild>
        <Link to={placeLink(params, "overview")}>
          <ArrowLeft /> {t("vendor.head.back")}
        </Link>
      </Button>
      <h2 className="flex items-center gap-2 text-lg font-semibold">
        {place === "catalog" ? <Library className="size-5 text-muted-foreground" /> : <Lightbulb className="size-5 text-muted-foreground" />}
        {title}
      </h2>
    </div>
  )
}

function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative">
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input value={value} onChange={(e) => onChange(e.target.value)} maxLength={80} placeholder={placeholder} aria-label={placeholder} className="h-9 w-72 max-w-full pl-8" />
    </div>
  )
}

export function StatusPill({ status, children }: { status: Status; children?: React.ReactNode }) {
  const { t } = useTranslation()
  return (
    <Pill color={STATUS_COLOR[status]} dot>
      {children ?? t(`vendor.status.${status}`)}
    </Pill>
  )
}

function SevPill({ s }: { s: NewsSeverity }) {
  const { t } = useTranslation()
  return (
    <Pill color={NEWS_SEV_COLOR[s]} dot>
      {t(`news.sev.${s}`)}
    </Pill>
  )
}

// ---------------------------------------------------------------- catalogue

const PAGE = 120

function Catalog({ onOpen, onSuggest }: { onOpen: (key: string) => void; onSuggest: (term?: string) => void }) {
  const { t } = useTranslation()
  const { isAdmin } = useAuth()
  const qc = useQueryClient()
  const q = useVendorCatalog()
  const ct = useCatalogTexts()
  const [params, setParams] = useSearchParams()
  const cat = params.get("cat") ?? "all"
  const [search, setSearch] = useState("")
  const term = useDeferredValue(search)
  // more rows on request – back to the first page when the category or the search changes
  const [paging, setPaging] = useState({ at: "", limit: PAGE })
  const limit = paging.at === `${cat}|${term}` ? paging.limit : PAGE
  const setLimit = (n: number) => setPaging({ at: `${cat}|${term}`, limit: n })
  // per row: the state a switch was set to, until the catalogue shows it (the switch never springs back meanwhile)
  const [pending, setPending] = useState<Record<string, boolean>>({})
  const [custom, setCustom] = useState(false)
  // a fresh form each time it opens
  const [customKey, setCustomKey] = useState(0)
  const data = q.data
  // the chosen category stays in sight inside its list (a row of chips on phones, a column with its own scroll on
  // desktop) – only the list scrolls, never the page
  const navRef = useRef<HTMLElement>(null)
  const loaded = !!data
  useEffect(() => {
    const nav = navRef.current
    const btn = nav?.querySelector<HTMLElement>("[aria-current]")
    if (!nav || !btn) return
    const n = nav.getBoundingClientRect()
    const b = btn.getBoundingClientRect()
    if (b.left < n.left || b.right > n.right) nav.scrollLeft += b.left - n.left - (n.width - b.width) / 2
    if (b.top < n.top || b.bottom > n.bottom) nav.scrollTop += b.top - n.top - (n.height - b.height) / 2
  }, [cat, loaded])
  const list = useMemo(() => {
    if (!data) return []
    const rows = data.products
      .filter((p) => (cat === "all" ? true : cat === "followed" ? data.followed[p.key]?.enabled : p.category === cat))
      .map((p) => ({ p, s: matchScore(p, term) }))
      .filter((x) => x.s > 0)
    rows.sort((a, b) => b.s - a.s || Number(!!data.followed[b.p.key]?.enabled) - Number(!!data.followed[a.p.key]?.enabled) || a.p.label.localeCompare(b.p.label))
    return rows.map((x) => x.p)
  }, [data, cat, term])
  if (q.isError && !data) return <QueryError error={q.error} onRetry={() => void q.refetch()} />
  if (!data)
    return (
      <p className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> {t("vendor.loading")}
      </p>
    )
  const follow = async (p: VendorProduct, on: boolean) => {
    setPending((x) => ({ ...x, [p.key]: on }))
    try {
      await api.put(`/api/vendor/follows/${encodeURIComponent(p.key)}`, { enabled: on })
      toast.success(t(on ? "vendor.followed" : "vendor.unfollowed", { name: p.label }))
      await refreshVendor(qc, ["vendor", "catalog"])
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setPending(({ [p.key]: _done, ...rest }) => rest)
    }
  }
  const followedCount = Object.values(data.followed).filter((f) => f.enabled).length
  const chooseCat = (c: string) =>
    setParams(
      (p) => {
        const next = new URLSearchParams(p)
        if (c === "all") next.delete("cat")
        else next.set("cat", c)
        return next
      },
      { replace: true, state: IN_PAGE },
    )
  // the categories in the order of the catalogue data (the server lists them in that order)
  const cats: { key: string; label: string; icon?: string; total: number; followed: number }[] = [
    { key: "all", label: t("vendor.cat.all"), total: data.products.length, followed: followedCount },
    { key: "followed", label: t("vendor.cat.followed"), total: followedCount, followed: followedCount },
    ...Object.keys(data.categories)
      .filter((c) => data.categories[c]?.total)
      .map((c) => ({
        key: c,
        label: ct.cat(c),
        icon: ct.icon(c),
        total: data.categories[c].total,
        followed: data.categories[c].followed,
      })),
  ]
  return (
    <div className="grid gap-6 lg:grid-cols-[250px_minmax(0,1fr)]">
      {/* long names wrap to two lines (cut with a tooltip beyond that) – the count keeps its own column, nothing spills over */}
      <nav
        ref={navRef}
        className="flex min-w-0 gap-1 overflow-x-auto pb-1 lg:sticky lg:top-20 lg:max-h-[calc(100svh-6rem)] lg:flex-col lg:self-start lg:overflow-y-auto lg:overscroll-contain"
        aria-label={t("vendor.categories")}
      >
        {cats.map((c) => (
          <button
            key={c.key}
            type="button"
            onClick={() => chooseCat(c.key)}
            aria-current={cat === c.key ? "true" : undefined}
            title={c.label}
            className={cn(
              "flex shrink-0 items-start gap-2 rounded-lg px-2.5 py-1.5 text-left text-sm font-medium whitespace-nowrap transition-colors lg:w-full lg:whitespace-normal",
              cat === c.key ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:bg-muted hover:text-foreground",
            )}
          >
            {c.icon && <CategoryIcon icon={c.icon} className="mt-0.5 hidden size-4 shrink-0 opacity-70 lg:block" />}
            <span className="min-w-0 flex-1 leading-snug lg:line-clamp-2 lg:break-words">{c.label}</span>
            <span className="shrink-0 pt-px text-right text-xs leading-snug font-normal whitespace-nowrap tabular-nums">
              {c.key !== "all" && c.key !== "followed" && c.followed > 0 && <span className="font-semibold text-primary">{c.followed} / </span>}
              {c.total}
            </span>
          </button>
        ))}
      </nav>
      <div className="min-w-0 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder={t("vendor.searchCatalog")} />
          <span className="text-xs text-muted-foreground">{t("vendor.hits", { count: list.length })}</span>
          <SuggestButton variant="ghost" className="ml-auto" onClick={() => onSuggest(search.trim())} />
          {isAdmin && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setCustomKey((k) => k + 1)
                setCustom(true)
              }}
            >
              <Plus /> {t("vendor.custom.open")}
            </Button>
          )}
        </div>
        {list.length === 0 ? (
          <EmptyState
            icon={Search}
            title={t("common.noResults")}
            text={isAdmin ? t("vendor.custom.notFound") : t("suggest.notFound")}
            action={<SuggestButton onClick={() => onSuggest(search.trim())} />}
          />
        ) : (
          <ul className="divide-y rounded-xl border bg-card">
            {list.slice(0, limit).map((p) => (
              <CatalogRow key={p.key} p={p} state={data.followed[p.key]} pending={pending[p.key]} canEdit={isAdmin} onToggle={follow} onOpen={onOpen} />
            ))}
          </ul>
        )}
        {list.length > limit && (
          <div className="text-center">
            <Button variant="outline" size="sm" onClick={() => setLimit(limit + PAGE)}>
              {t("vendor.more", { count: list.length - limit })}
            </Button>
          </div>
        )}
        {data.catalog_version && (
          <p className="flex flex-wrap items-center gap-1 pt-1 text-xs text-muted-foreground">
            <Explained label={t("vendor.catalogVersion")} text={t("vendor.catalogVersionHint")} />
            <span className="font-mono tabular-nums">{data.catalog_version}</span>
          </p>
        )}
      </div>
      {isAdmin && <CustomProduct key={customKey} open={custom} onClose={() => setCustom(false)} onAdded={(key) => onOpen(key)} />}
    </div>
  )
}

const CatalogRow = memo(function CatalogRow({
  p,
  state,
  pending,
  canEdit,
  onToggle,
  onOpen,
}: {
  p: VendorProduct
  state: { enabled: boolean; versions: number } | undefined
  /** switched, not yet in the catalogue: shown in its new state, locked until then */
  pending: boolean | undefined
  canEdit: boolean
  onToggle: (p: VendorProduct, on: boolean) => void
  onOpen: (key: string) => void
}) {
  const { t } = useTranslation()
  const ct = useCatalogTexts()
  const busy = pending !== undefined
  const on = pending ?? !!state?.enabled
  const toggle = (
    // locked while saving, but not disabled: a disabled control loses the keyboard focus
    <Switch
      checked={on}
      disabled={!canEdit}
      aria-busy={busy || undefined}
      className={cn(busy && "opacity-60")}
      onCheckedChange={(x) => !busy && onToggle(p, x)}
      aria-label={t("vendor.followToggle", { name: p.label })}
    />
  )
  return (
    <li className="flex items-center gap-3 px-3 py-2.5">
      <button type="button" onClick={() => onOpen(p.key)} className="min-w-0 flex-1 text-left outline-none focus-visible:rounded focus-visible:ring-2 focus-visible:ring-ring/50">
        <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
          {p.label}
          {p.advisory && <Pill color="--primary">{t("vendor.badge.advisory")}</Pill>}
          {p.cloud && (
            <Pill color="--sev-low">
              <Cloud /> {t("vendor.badge.cloud")}
            </Pill>
          )}
          {p.custom && <Pill color="--muted-foreground">{t("vendor.badge.custom")}</Pill>}
        </p>
        <p className="truncate text-xs text-muted-foreground">
          {p.vendor} · {ct.cat(p.category)}
          {p.cpes.length > 0 ? ` · ${t("vendor.badge.cpe")}` : ` · ${t("vendor.badge.noCpe")}`}
          {p.eol && ` · ${t("vendor.badge.eol")}`}
          {on && state && ` · ${state.versions ? t("vendor.versionsCount", { count: state.versions }) : t("vendor.noVersions")}`}
        </p>
      </button>
      <span className="hidden text-xs text-muted-foreground sm:inline">{on ? t("vendor.following") : t("vendor.follow")}</span>
      {canEdit ? (
        toggle
      ) : (
        <Tooltip>
          <TooltipTrigger asChild>
            <span>{toggle}</span>
          </TooltipTrigger>
          <TooltipContent>{t("vendor.adminOnly")}</TooltipContent>
        </Tooltip>
      )}
    </li>
  )
})

type CpeHit = { cpe: string; title: string; vendor: string; product: string }

/** The NVD CPE dictionary search: one query per settled term (an older one is cancelled), a "slow down" waits and retries. */
function useCpeSearch(term: string) {
  return useQuery({
    queryKey: ["vendor-cpe", term.toLowerCase()],
    queryFn: ({ signal }) => api.get<{ items: CpeHit[]; error?: string }>(`/api/vendor/cpe-search?q=${encodeURIComponent(term)}`, { signal }),
    enabled: term.length >= 3,
    staleTime: 60 * 60_000,
    retry: (n, e) => e instanceof ApiError && e.status === 429 && n < 3,
    retryDelay: 7_500,
  })
}

/** A product the catalogue does not know: its CPE from the NVD dictionary (search, cached on the server). */
function CustomProduct({
  open,
  onClose,
  onAdded,
  initial,
}: {
  open: boolean
  onClose: () => void
  onAdded: (key: string) => void
  /** prefilled – a suggestion taken over ("Übernehmen") */
  initial?: { q: string; cpe: string; label: string }
}) {
  const { t } = useTranslation()
  const ct = useCatalogTexts()
  const qc = useQueryClient()
  const [q, setQ] = useState(initial?.q ?? "")
  const typed = q.trim().replace(/\s+/g, " ")
  const term = useSettled(typed, 600)
  const search = useCpeSearch(term)
  // results only for what is typed now – never those of an earlier term that answered late
  const current = typed === term && term.length >= 3
  const items = current ? (search.data?.items ?? []) : []
  // the server asks the NVD at most every 7 seconds: a search in that gap waits and runs again by itself
  const throttled = search.isFetching && search.failureReason instanceof ApiError && search.failureReason.status === 429
  const searching = typed.length >= 3 && (!current || search.isFetching)
  const failed = current && search.isError ? search.error : null
  const [cpe, setCpe] = useState(initial?.cpe ?? "")
  const [label, setLabel] = useState(initial?.label ?? "")
  const [category, setCategory] = useState<string>("other")
  const [busy, setBusy] = useState(false)
  const valid = /^(cpe:2\.3:)?[aoh]:[^:\s]+:[^:\s]+$/.test(cpe.trim()) && label.trim().length >= 2
  const add = async () => {
    setBusy(true)
    try {
      const r = await api.post<{ key: string }>("/api/vendor/custom", { cpe: cpe.trim(), label: label.trim(), category })
      toast.success(t("vendor.followed", { name: label.trim() }))
      void qc.invalidateQueries({ queryKey: ["vendor"] })
      onClose()
      onAdded(r.key)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-lg">
        <SheetHeader className="border-b">
          <SheetTitle className="flex items-center gap-2">
            <Plus className="size-4" /> {t("vendor.custom.title")}
          </SheetTitle>
          <SheetDescription>{t("vendor.custom.desc")}</SheetDescription>
        </SheetHeader>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
          <Field label={<Term k="cpe">{t("vendor.custom.search")}</Term>} hint={t("vendor.custom.searchHint")}>
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="netscaler, zyxel usg, sap gui …" maxLength={60} />
          </Field>
          {searching && (
            <p className="flex items-center gap-2 text-xs text-muted-foreground" role="status">
              <Loader2 className="size-3.5 animate-spin" /> {t(throttled ? "vendor.custom.throttled" : "vendor.custom.searching")}
            </p>
          )}
          {failed && (
            <p className="flex flex-wrap items-center gap-x-2 text-xs text-warning">
              {failed instanceof ApiError && failed.status === 429 ? t("vendor.err.rate_limited") : errorText(t, failed)}
              <Button variant="link" size="xs" className="h-auto px-0" onClick={() => void search.refetch()}>
                {t("errors.retry")}
              </Button>
            </p>
          )}
          {current && !search.isFetching && search.data?.error && (
            <p className="text-xs text-warning">{t(`vendor.err.${search.data.error}`, { defaultValue: search.data.error })}</p>
          )}
          {current && !search.isFetching && search.data && !search.data.error && items.length === 0 && <p className="text-xs text-muted-foreground">{t("vendor.custom.noHits")}</p>}
          {items.length > 0 && (
            <ul className="max-h-64 divide-y overflow-y-auto rounded-lg border">
              {items.map((i) => (
                <li key={i.cpe}>
                  <button
                    type="button"
                    onClick={() => {
                      setCpe(i.cpe)
                      if (!label) setLabel(i.title || `${i.vendor} ${i.product}`)
                    }}
                    className={cn("flex w-full flex-col items-start px-3 py-2 text-left hover:bg-muted/50", cpe === i.cpe && "bg-accent")}
                  >
                    <span className="text-sm font-medium">{i.title || i.product}</span>
                    <span className="font-mono text-[11px] text-muted-foreground">{i.cpe}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          <Field label="CPE" hint={t("vendor.custom.cpeHint")}>
            <Input value={cpe} onChange={(e) => setCpe(e.target.value)} placeholder="a:vendor:product" className="font-mono" aria-invalid={!!cpe && !valid && label.length > 1} />
          </Field>
          <Field label={t("vendor.custom.label")}>
            <Input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={120} />
          </Field>
          <Field label={t("vendor.custom.category")}>
            <Select value={category} onValueChange={setCategory}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                {ct.categories.map((c) => (
                  <SelectItem key={c.key} value={c.key}>
                    {c.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        </div>
        <SheetFooter className="flex-row flex-wrap items-center justify-end gap-2 border-t bg-popover">
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button disabled={!valid || busy} onClick={() => void add()}>
            {busy ? <Loader2 className="animate-spin" /> : <Plus />} {t("vendor.custom.add")}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

// ---------------------------------------------------------------- the drawer of one product

type View = "vulns" | "versions" | "news" | "changes"
const VIEWS: View[] = ["vulns", "versions", "news", "changes"]

function ProductDrawer({ productKey, open, onClose, onClosed }: { productKey: string; open: boolean; onClose: () => void; onClosed: () => void }) {
  const { t } = useTranslation()
  const ct = useCatalogTexts()
  const { isAdmin } = useAuth()
  const qc = useQueryClient()
  const [params] = useSearchParams()
  const view: View = VIEWS.find((v) => v === params.get("view")) ?? "vulns"
  const [all, setAll] = useState(false)
  const [sort, setSortState] = useState<FindingSort>("relevance")
  const q = useVendorProduct(productKey, all, sort)
  const merged = useMemo(() => mergeFindingPages(q.data), [q.data])
  const { hasNextPage, isFetching, isPlaceholderData, fetchNextPage } = q
  const pages = q.data?.pages.length ?? 0
  // "auch nicht betroffene" switched: as many pages as were shown before, not back to the first one – the list shown
  // stays until they are all there (it never shrinks and grows again meanwhile)
  const [want, setWant] = useState(1)
  const filling = !isPlaceholderData && pages < want && hasNextPage
  const [steady, setSteady] = useState(merged)
  if (!filling && steady !== merged) setSteady(merged)
  const d = filling ? steady : merged
  // the header at once from the card or catalogue row that opened it – the details follow
  const head = d?.product ?? cachedProduct(qc, productKey)
  // the follow switch shows what was chosen until the drawer has reloaded with it (it never springs back meanwhile)
  const [pending, setPending] = useState<boolean | null>(null)
  const followed = pending ?? !!d?.follow?.enabled
  // a tab stays mounted once shown: switching back is instant, a long list of findings is not built again
  const [seen, setSeen] = useState<View[]>([view])
  if (!seen.includes(view)) setSeen([...seen, view])
  const focus = params.get("finding")
  // opened at a finding (a card's line): it is among the first – if not, the next pages are loaded until it is there
  const focusMissing = !!focus && !!d && !d.findings.some((f) => f.id === focus)
  const showAll = useCallback(
    (v: boolean) => {
      setWant(pages)
      setAll(v)
    },
    [pages, setWant, setAll],
  )
  const setSort = useCallback(
    (v: FindingSort) => {
      setWant(pages)
      setSortState(v)
    },
    [pages, setWant, setSortState],
  )
  useEffect(() => {
    if (!hasNextPage || isFetching || isPlaceholderData) return
    if ((focusMissing && pages < 6) || pages < want) void fetchNextPage()
  }, [focusMissing, hasNextPage, isFetching, isPlaceholderData, pages, want, fetchNextPage])
  const more = useCallback(() => void fetchNextPage({ cancelRefetch: false }), [fetchNextPage])
  const viewLink = (k: View) => {
    const next = new URLSearchParams(params)
    next.delete("finding")
    if (k === "vulns") next.delete("view")
    else next.set("view", k)
    return `?${next.toString()}`
  }
  const follow = async (on: boolean) => {
    if (!d || pending !== null) return
    setPending(on)
    try {
      // only the switch: note and tags stay as they are (the server changes what is sent)
      await api.put(`/api/vendor/follows/${encodeURIComponent(d.product.key)}`, { enabled: on })
      await refreshVendor(qc, productKeyOf(d.product.key))
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setPending(null)
    }
  }
  const remove = async () => {
    if (!d) return
    if (!(await confirmAction({ title: t("vendor.removeTitle"), text: t("vendor.removeText", { name: d.product.label }), confirm: t("common.remove") }))) return
    try {
      await api.del(`/api/vendor/follows/${encodeURIComponent(d.product.key)}`)
      void refreshVendor(qc)
      onClose()
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  const visible = d ? visibleFindings(d) : 0
  // opening the drawer reads the product's findings (what had arrived when it loaded) – the ones that were unread keep
  // their "Neu" here until the drawer closes
  const reading = useVendorRead()
  const [fresh, setFresh] = useState<Set<string>>(() => new Set())
  const newly = (d?.findings ?? []).filter((f) => f.unread && !fresh.has(f.id))
  if (newly.length) setFresh(new Set([...fresh, ...newly.map((f) => f.id)]))
  const markedAt = useRef<string | null>(null)
  const readMutate = reading.read.mutate
  useEffect(() => {
    if (!open || !d?.follow || !d.unread || markedAt.current) return
    markedAt.current = d.now ?? new Date().toISOString()
    readMutate({ product: d.product.key, upto: d.now })
  }, [open, d, readMutate])
  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent
        className="w-full gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-3xl"
        onCloseAutoFocus={(e) => {
          // the page puts the focus back on what opened the drawer (Radix would not know it: no trigger)
          e.preventDefault()
          onClosed()
        }}
      >
        <SheetHeader className="border-b">
          {head ? (
            <>
              <div className="flex flex-wrap items-center gap-2 pr-8 text-xs text-muted-foreground">
                <span className="font-medium text-foreground/80">{head.vendor}</span>
                <span>·</span>
                <span>{ct.cat(head.category)}</span>
                {head.cpes.length > 0 && (
                  <>
                    <span>·</span>
                    <Term k="cpe">CPE</Term>
                    <span className="font-mono">{head.cpes.slice(0, 2).join(", ")}</span>
                  </>
                )}
              </div>
              <SheetTitle className="text-lg leading-snug">{head.label}</SheetTitle>
              <SheetDescription className="sr-only">{t("vendor.description")}</SheetDescription>
            </>
          ) : (
            <SheetTitle className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" /> {t("vendor.loading")}
            </SheetTitle>
          )}
          {d && (
            <>
              <SubTabs
                parts={[
                  { key: "vulns" as const, icon: ShieldAlert, label: t("vendor.view.vulns"), count: visible },
                  {
                    key: "versions" as const,
                    icon: ListChecks,
                    label: t("vendor.view.versions"),
                    count: d.versions.length,
                    alert: d.versions.some((v) => v.release?.eol_state === "past" || v.review?.due),
                  },
                  { key: "news" as const, icon: Newspaper, label: t("vendor.view.news"), count: d.news.length },
                  { key: "changes" as const, icon: History, label: t("changes.title"), alert: d.findings.some((f) => f.changed?.impact.length) },
                ]}
                active={view}
                to={viewLink}
                label={d.product.label}
              />
            </>
          )}
        </SheetHeader>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-5">
          {q.isError && !d && <QueryError error={q.error} onRetry={() => void q.refetch()} />}
          {!d && !q.isError && <DrawerSkeleton label={t("vendor.loading")} />}
          {d && <ProductHint p={d.product} />}
          {d?.catalog_check && <CatalogCareHint c={d.catalog_check} isAdmin={isAdmin} />}
          {d && !d.follow && <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t(isAdmin ? "vendor.notFollowedAdmin" : "vendor.notFollowed")}</p>}
          {d && seen.includes("vulns") && (
            <div hidden={view !== "vulns"}>
              <Vulns
                d={d}
                fresh={fresh}
                all={all}
                onAll={showAll}
                sort={sort}
                onSort={setSort}
                switching={isPlaceholderData || !!filling}
                focus={view === "vulns" ? focus : null}
                onMore={more}
                loadingMore={q.isFetchingNextPage}
                moreError={q.isFetchNextPageError ? q.error : null}
              />
            </div>
          )}
          {d && seen.includes("versions") && (
            <div hidden={view !== "versions"}>
              <Versions d={d} canEdit={isAdmin && !!d.follow} canConfirm={!!d.follow && (d.can_confirm ?? isAdmin)} vulnsHref={viewLink("vulns")} />
            </div>
          )}
          {d && seen.includes("news") && (
            <div hidden={view !== "news"}>
              <RelatedNews d={d} />
            </div>
          )}
          {d && seen.includes("changes") && (
            <div hidden={view !== "changes"}>
              <ProductChanges productKey={d.product.key} />
            </div>
          )}
        </div>
        <SheetFooter className="flex-row flex-wrap items-center gap-2 border-t bg-popover">
          {d && isAdmin && (
            <div className="mr-auto flex flex-wrap items-center gap-2">
              <Switch
                id="vendor-follow"
                checked={followed}
                aria-busy={pending !== null || undefined}
                className={cn(pending !== null && "opacity-60")}
                onCheckedChange={(x) => void follow(x)}
              />
              <Label htmlFor="vendor-follow" className="text-sm">
                {followed ? t("vendor.following") : t("vendor.follow")}
              </Label>
              {d.follow && (
                <Button variant="ghost" size="sm" onClick={() => void remove()}>
                  <Trash2 /> {t("vendor.remove")}
                </Button>
              )}
            </div>
          )}
          {d?.follow && <MuteButton targets={[{ kind: "product", key: d.product.key, label: d.product.label }]} />}
          <Button variant="ghost" onClick={onClose} className={cn(!isAdmin && !d?.follow && "ml-auto")}>
            {t("common.close")}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

/** What the overview or the catalogue already loaded about a product (for the drawer's header while it loads). */
function cachedProduct(qc: ReturnType<typeof useQueryClient>, key: string): VendorProduct | undefined {
  return (
    qc.getQueryData<VendorOverview>(["vendor", "overview"])?.items.find((i) => i.product.key === key)?.product ??
    qc.getQueryData<VendorOverview>(["vendor", "overview", "team"])?.items.find((i) => i.product.key === key)?.product ??
    qc.getQueryData<VendorCatalog>(["vendor", "catalog"])?.products.find((p) => p.key === key)
  )
}

function ProductHint({ p }: { p: VendorProduct }) {
  const ct = useCatalogTexts()
  const text = ct.hint(p.cloud ? "cloud" : p.hint)
  if (!text) return null
  return (
    <p className="flex gap-2 rounded-lg border border-primary/30 bg-primary/5 p-3 text-xs leading-relaxed">
      <CircleHelp className="mt-0.5 size-4 shrink-0 text-primary" />
      <span>
        <MoreText>{text}</MoreText>
      </span>
    </p>
  )
}

/** Katalog-Pflege found something about this followed product's catalogue entry (a CPE missing in the NVD …): a small
 *  note – the findings may be incomplete until the entry is fixed. */
function CatalogCareHint({ c, isAdmin }: { c: CatalogCheckVerdict; isAdmin: boolean }) {
  const { t } = useTranslation()
  return (
    <div className="flex gap-2 rounded-lg border border-warning/40 bg-warning/5 p-3 text-xs leading-relaxed" data-testid="catalog-care-hint">
      <Stethoscope className="mt-0.5 size-4 shrink-0 text-warning" />
      <div className="min-w-0 space-y-1">
        <p className="font-medium">{t("vendor.care.drawerTitle")}</p>
        <ul className="space-y-0.5">
          {c.reasons.map((r, n) => (
            <li key={n} className="break-words">
              {careReason(t, r)}
            </li>
          ))}
        </ul>
        {isAdmin && (
          <Link to="/settings/integrations?vendor=care" className="inline-block font-medium text-primary hover:underline">
            {t("vendor.care.drawerLink")}
          </Link>
        )}
      </div>
    </div>
  )
}

const GROUPS: Status[] = ["affected", "possible", "service", "unversioned", "stale", "not_affected"]

/** The findings in groups (affected first), page by page: the group heads count all of a kind, also those not loaded yet. */
const Vulns = memo(function Vulns({
  d,
  fresh,
  all,
  onAll,
  sort,
  onSort,
  switching,
  focus,
  onMore,
  loadingMore,
  moreError,
}: {
  d: ProductDetail
  /** the findings that were unread when the drawer opened ("Neu") */
  fresh: Set<string>
  all: boolean
  onAll: (v: boolean) => void
  /** within each group: the drawer's order, or the likeliest to be exploited first (EPSS) */
  sort: FindingSort
  onSort: (v: FindingSort) => void
  /** the other list ("auch nicht betroffene") is loading – this one stays until it is there */
  switching: boolean
  focus: string | null
  onMore: () => void
  loadingMore: boolean
  moreError: unknown
}) {
  const { t } = useTranslation()
  const versions = d.versions
  const counts = findingCounts(d)
  const [showStale, setShowStale] = useState(false)
  const shown = d.findings
  const rest = d.shown !== undefined ? Math.max(0, d.shown - shown.length) : 0
  // what is left are only "unklare Altdaten" (folded): "Weitere anzeigen" waits behind their fold
  const loadedVisible = shown.filter((f) => f.status !== "stale" && f.status !== "not_affected").length
  const onlyStaleLeft = !all && rest > 0 && loadedVisible >= visibleFindings(d)
  const groups = GROUPS.map((g) => ({ g, items: shown.filter((f) => f.status === g) })).filter((x) => x.items.length > 0 || (x.g === "stale" && onlyStaleLeft && counts.stale > 0))
  // opened from a card: scroll to that finding (once it is rendered)
  const found = !!focus && shown.some((f) => f.id === focus)
  useEffect(() => {
    if (!found || !focus) return
    const el = document.querySelector(`[data-finding="${CSS.escape(focus)}"]`)
    el?.scrollIntoView({ block: "center" })
  }, [found, focus])
  const staleOpen = showStale || shown.some((f) => f.status === "stale" && f.id === focus)
  return (
    <div className="space-y-4">
      {d.follow && versions.length === 0 && !d.product.cloud && (
        <p className="flex items-center gap-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
          <CircleHelp className="size-4 shrink-0" /> {t("vendor.giveVersionLong")}
        </p>
      )}
      {versions.length > 0 && d.summary && (
        <ul className="flex flex-wrap gap-2">
          {versions.map((v) => {
            const s = d.summary?.per_version[v.id]
            return (
              <li key={v.id} className="flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs">
                <span className="font-mono font-medium">{v.version}</span>
                {v.label && <span className="text-muted-foreground">{v.label}</span>}
                {s?.affected ? <StatusPill status="affected">{s.affected}</StatusPill> : null}
                {s?.possible ? <StatusPill status="possible">{s.possible}</StatusPill> : null}
                {!s?.affected && !s?.possible && <CheckCircle2 className="size-3.5 text-success" />}
              </li>
            )
          })}
        </ul>
      )}
      {d.follow && (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">{t("vendor.findingsCount", { count: visibleFindings(d) })}</p>
          {visibleFindings(d) > 1 && (
            <div className="flex items-center gap-2">
              <Label htmlFor="vendor-sort" className="text-xs text-muted-foreground">
                {t("vendor.sort.label")}
              </Label>
              <Select value={sort} onValueChange={(v) => onSort(v as FindingSort)}>
                <SelectTrigger id="vendor-sort" size="sm" className="text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper">
                  <SelectItem value="relevance">{t("vendor.sort.relevance")}</SelectItem>
                  <SelectItem value="epss">{t("vendor.sort.epss")}</SelectItem>
                  <SelectItem value="score">{t("vendor.sort.score")}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}
          {counts.not_affected > 0 && (
            <div className="flex items-center gap-2">
              {switching && <Loader2 className="size-3.5 animate-spin text-muted-foreground" aria-hidden />}
              <Switch id="vendor-all" checked={all} onCheckedChange={onAll} aria-busy={switching || undefined} />
              <Label htmlFor="vendor-all" className="text-xs">
                {t("vendor.showNotAffected", { count: counts.not_affected })}
              </Label>
            </div>
          )}
        </div>
      )}
      {d.follow && shown.length === 0 && rest === 0 && <EmptyState icon={ShieldAlert} title={t("vendor.noFindings")} text={t("vendor.noFindingsText")} />}
      {groups.map(({ g, items }) =>
        // "unklare Altdaten": folded – open by itself only when the card pointed at one of them
        g === "stale" && !staleOpen ? (
          <section key={g} className="flex flex-wrap items-center gap-2 rounded-lg border border-dashed px-3 py-2" aria-labelledby="vendor-group-stale">
            <span id="vendor-group-stale" className="text-xs text-muted-foreground">
              <Explained label={t("vendor.group.stale")} text={t("vendor.group.staleHelp")} />
            </span>
            <Button variant="link" size="xs" className="h-auto px-0" onClick={() => setShowStale(true)}>
              {t("vendor.group.staleShow", { count: counts.stale })}
            </Button>
          </section>
        ) : (
          <section key={g} className="space-y-2.5" aria-labelledby={`vendor-group-${g}`}>
            <h3 id={`vendor-group-${g}`} className="flex items-center gap-2 pt-1 text-sm font-semibold">
              <span className="size-2 shrink-0 rounded-full" style={{ backgroundColor: `var(${STATUS_COLOR[g]})` }} />
              <Explained label={t(`vendor.group.${g}`)} text={t(`vendor.group.${g}Help`)} />
              <span className="rounded-full bg-muted px-1.5 text-[11px] font-normal text-muted-foreground tabular">{counts[g] || items.length}</span>
            </h3>
            <ul className="space-y-3">
              {items.map((f) => (
                <FindingRow key={f.id} f={f} versions={versions} marked={f.id === focus} productKey={d.follow ? d.product.key : null} fresh={fresh.has(f.id)} />
              ))}
            </ul>
            {g === "stale" && (
              <Button variant="link" size="xs" className="h-auto px-0" onClick={() => setShowStale(false)}>
                {t("vendor.group.staleHide")}
              </Button>
            )}
          </section>
        ),
      )}
      {rest > 0 && (!onlyStaleLeft || staleOpen) && (
        <div className="flex flex-col items-center gap-2 pt-1">
          {moreError ? <QueryError error={moreError} onRetry={onMore} compact /> : null}
          <Button variant="outline" size="sm" onClick={onMore} disabled={loadingMore || switching}>
            {loadingMore && <Loader2 className="animate-spin" />}
            {t("vendor.moreFindings", { count: Math.min(FINDINGS_PAGE, rest), rest })}
          </Button>
        </div>
      )}
    </div>
  )
})

const SOURCE_LABEL = ADVISORY_SOURCE_LABEL

function reasonText(t: (k: string, o?: Record<string, unknown>) => string, r: Finding["versions"][number]) {
  const base = t(`vendor.reason.${r.reason}`, { defaultValue: r.reason, line: r.detail.line ?? "", released: r.detail.released ? fmtDay(r.detail.released) : "" })
  const extra = [r.detail.platform && t("vendor.reason.platform", { value: r.detail.platform }), r.detail.after && t("vendor.reason.after", { value: r.detail.after })].filter(
    Boolean,
  )
  return [base, ...extra].join(" · ")
}

const FindingRow = memo(function FindingRow({
  f,
  versions,
  marked = false,
  productKey = null,
  fresh = false,
}: {
  f: Finding
  versions: FollowedVersion[]
  marked?: boolean
  /** unread when the drawer opened: "Neu" */
  fresh?: boolean
  /** the followed product – "An mein Team weiterleiten" needs it (none: not followed, nothing to forward) */
  productKey?: string | null
}) {
  const { t } = useTranslation()
  const counts = affectedVersions(f)
  const labelOf = (id: string | null) => versions.find((v) => v.id === id)?.label
  // Versionen prüfen: the verdict holds for the version entered – one not confirmed for long gets a hint (the score
  // itself never changes because of it)
  const dueOf = (id: string | null) => versions.find((v) => v.id === id)?.review
  const unconfirmed = f.versions.filter((v) => (v.status === "affected" || v.status === "possible") && dueOf(v.id)?.due)
  return (
    <li
      data-finding={f.id}
      className={cn(
        "scroll-mt-4 space-y-2 rounded-xl border p-3.5",
        f.exploited && f.status === "affected" && "border-sev-critical/40",
        marked && "ring-2 ring-primary/60",
        f.muted && !f.exploited && "opacity-60",
      )}
    >
      <div className="flex flex-wrap items-center gap-1.5">
        {(fresh || f.unread) && (
          <Pill color="--primary" dot>
            {t("reader.new")}
          </Pill>
        )}
        {f.muted && <Pill color="--muted-foreground">{t("reader.mute.badge")}</Pill>}
        {f.score && f.status !== "not_affected" && <ScorePill score={f.score} />}
        {unconfirmed.length > 0 && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={0} className="cursor-help rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
                <Pill color="--warning">
                  <Clock /> {t("review.findingPill")}
                </Pill>
              </span>
            </TooltipTrigger>
            <TooltipContent className="max-w-xs leading-relaxed">
              {t("review.findingHint", { versions: unconfirmed.map((v) => v.version).join(", "), count: Math.max(...unconfirmed.map((v) => dueOf(v.id)?.age_days ?? 0)) })}
            </TooltipContent>
          </Tooltip>
        )}
        <SevPill s={f.severity} />
        {f.cvss !== null && (
          <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">
            <Term k="cvss">CVSS</Term> {f.cvss.toFixed(1)}
          </span>
        )}
        {f.kev && (
          <Pill color="--sev-critical">
            <AlertTriangle /> <Term k="kev">KEV</Term>
            {f.kev.ransomware ? ` · ${t("vendor.ransomware")}` : ""}
          </Pill>
        )}
        {!f.kev && f.exploited && !(f.ssvc?.exploitation === "active") && (
          <Pill color="--sev-critical">
            <AlertTriangle /> {f.euvd ? <Term k="euvd">{t("vendor.exploited")}</Term> : t("vendor.exploited")}
          </Pill>
        )}
        {f.epss && <EpssPill e={f.epss} />}
        {f.ssvc && <SsvcPill s={f.ssvc} />}
        {f.exploit && f.exploit.length > 0 && <ExploitHints hints={f.exploit} />}
        {f.quiet && (
          <span title={t("vendor.quietHint")}>
            <Pill color="--muted-foreground">{t("vendor.quiet")}</Pill>
          </span>
        )}
        {f.changed && <ChangedBadge c={f.changed} />}
        <span className="ml-auto text-[11px] text-muted-foreground">
          {SOURCE_LABEL[f.source]}
          {f.also.length > 0 && ` + ${f.also.map((a) => SOURCE_LABEL[a.source] ?? a.source).join(", ")}`}
          {f.published_at && (
            <>
              {" · "}
              <Ts at={f.published_at} rel />
            </>
          )}
        </span>
      </div>
      <p className="text-sm leading-snug font-medium">
        <span className="font-mono text-[12.5px] text-muted-foreground">{f.ident}</span> {f.headline || f.title}
      </p>
      {f.summary && f.summary !== (f.headline || f.title) && (
        <p className="text-xs leading-relaxed text-muted-foreground">
          <MoreText>{f.summary}</MoreText>
        </p>
      )}
      {counts.total > 1 && (counts.affected > 0 || counts.possible > 0) && (
        <p className="text-xs font-medium">
          {counts.affected > 0 && t("vendor.affectsOf", { count: counts.affected, total: counts.total })}
          {counts.affected > 0 && counts.possible > 0 && " · "}
          {counts.possible > 0 && t("vendor.possibleOf", { count: counts.possible, total: counts.total })}
        </p>
      )}
      <ul className="divide-y rounded-lg border bg-muted/20">
        {f.versions.map((v) => (
          <li key={v.id ?? "none"} className="flex flex-wrap items-center gap-2 px-3 py-2 text-xs">
            {v.version ? (
              <span className="font-mono font-medium">
                {v.version}
                {labelOf(v.id) && <span className="ml-1.5 font-sans font-normal text-muted-foreground">{labelOf(v.id)}</span>}
              </span>
            ) : (
              <span className="text-muted-foreground">{t("vendor.allVersions")}</span>
            )}
            <StatusPill status={v.status} />
            {dueOf(v.id)?.due && (
              <span className="inline-flex items-center gap-1 text-warning">
                <Clock className="size-3" /> {t("review.since", { count: dueOf(v.id)?.age_days ?? 0 })}
              </span>
            )}
            {v.fixed && (
              <span>
                {t("vendor.fixIn")} <span className="font-mono font-semibold">{v.fixed}</span>
              </span>
            )}
            <span className="text-muted-foreground">{reasonText(t, v)}</span>
            {v.detail.lines && (
              <ul className="w-full space-y-0.5 pt-1 text-muted-foreground">
                {v.detail.lines.map((l) => (
                  <li key={l.line} className="font-mono text-[11px]">
                    {l.line}: {l.affected} → {l.fixed}
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap items-center gap-2">
        <CveChips cves={f.cves} shown={6} origin={productKey ? { kind: "finding", product: productKey, advisory: f.id } : undefined} />
        {productKey && <WatchAllButton cves={f.cves} origin={{ kind: "finding", product: productKey, advisory: f.id }} order="list" />}
        <span className="ml-auto flex flex-wrap items-center gap-3">
          {productKey && !f.unread && <FindingUnread product={productKey} finding={f.id} />}
          {f.cves.length > 0 && <MuteButton targets={f.cves.slice(0, 6).map((c) => ({ kind: "cve" as const, key: c, label: c }))} size="xs" variant="link" />}
          {productKey && <ForwardButton thing={{ product: productKey, finding: f.id }} title={`${f.ident} ${f.headline || f.title}`} size="xs" variant="link" />}
          <Button variant="link" size="xs" className="h-auto px-0" asChild>
            <a href={f.url} target="_blank" rel="noopener noreferrer">
              <ExternalLink /> {t("vendor.openAdvisory")}
            </a>
          </Button>
        </span>
      </div>
    </li>
  )
})

/** "Als ungelesen markieren" for one finding (it counts again in the numbers). */
function FindingUnread({ product, finding }: { product: string; finding: string }) {
  const { t } = useTranslation()
  const { unread } = useVendorRead()
  return (
    <Button
      variant="link"
      size="xs"
      className="h-auto px-0"
      disabled={unread.isPending}
      onClick={() => unread.mutate({ product, finding }, { onSuccess: () => toast.success(t("news.markedUnread")), onError: (e) => toast.error(errorText(t, e)) })}
    >
      <RotateCcw /> {t("news.markUnread")}
    </Button>
  )
}

// ---------------------------------------------------------------- related stories

function RelatedNews({ d }: { d: ProductDetail }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  if (!d.news.length) return <EmptyState icon={Newspaper} title={t("vendor.noNews")} text={t("vendor.noNewsText")} />
  return (
    <ul className="divide-y rounded-xl border">
      {d.news.map((n) => (
        <li key={n.id}>
          <button
            type="button"
            onClick={() => navigate(`/?story=${encodeURIComponent(n.id)}`)}
            className="flex w-full flex-col items-start gap-1 px-3.5 py-3 text-left hover:bg-muted/40"
          >
            <span className="flex w-full flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
              <SevPill s={n.severity} />
              <span className="font-medium text-foreground/80">{n.source.name}</span>
              <span>·</span>
              <Ts at={n.published_at} rel />
              <span className="ml-auto">{n.by === "cve" ? t("vendor.newsByCve", { cves: n.cves.join(", ") }) : t("vendor.newsByName")}</span>
            </span>
            <span className="text-sm leading-snug font-medium">{n.title}</span>
            {n.summary && <span className="line-clamp-2 text-xs text-muted-foreground">{n.summary}</span>}
          </button>
        </li>
      ))}
    </ul>
  )
}
