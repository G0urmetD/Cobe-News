import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Link, useNavigate, useSearchParams } from "react-router"
import { useTranslation } from "react-i18next"
import { Check, CheckCheck, ExternalLink, Loader2, MoreHorizontal, Newspaper, Package, RotateCcw, Search, Settings2 } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Toggle } from "@/components/ui/toggle"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { MultiSelect } from "@/components/cobe/multi-select"
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Pill } from "@/components/cobe/badges"
import { EmptyState, PageHeader } from "@/components/cobe/common"
import { DrawerSkeleton, QueryError } from "@/components/cobe/query-state"
import { Ts } from "@/components/cobe/time"
import { WatchStar } from "@/components/cobe/watch-star"
import { confirmAction } from "@/components/cobe/confirm"
import { MuteButton, MuteItems, type MuteTarget, MuteUntilDialog } from "@/components/cobe/mute-menu"
import { ViewsMenu, useDefaultView } from "@/components/cobe/views-menu"
import { IN_PAGE, type NewsUrlFilter, readNewsFilter, writeNewsFilter } from "@/lib/reader-api"
import { ApiError, api } from "@/lib/api"
import { errorText } from "@/lib/errors"
import { restoreFocus } from "@/lib/focus"
import {
  NEWS_SEVERITIES,
  NEWS_SEV_COLOR,
  NEWS_TOPICS,
  NEWS_TOPIC_COLOR,
  QUICK_TOPICS,
  type NewsDetail,
  type NewsItem,
  type NewsSeverity,
  type NewsSourceRef,
  type NewsTopic,
  type TopicReason,
  cardTopics,
  loadNewsFilter,
  mergePages,
  readAllBody,
  saveNewsFilter,
  sourceGroups,
  useMarkRead,
  useNews,
  useNewsDetail,
  useNewsSources,
} from "@/lib/news-api"
import { useAuth } from "@/lib/auth"
import { useVendorScope } from "@/lib/teams-api"
import { cn } from "@/lib/utils"
import { AffectsYou, DetailHint, StoryCves, StoryDetailsBlock } from "@/pages/news-details"
import { StoryChanges } from "@/components/cobe/advisory-changes"
import { ForwardButton } from "@/components/cobe/forward"
import { useQueryClient } from "@tanstack/react-query"

export function NewsPage() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { user, isAdmin } = useAuth()
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  // the filter lives in the address (validated – a crafted link cannot break the page): saved views and shared links
  // carry it; the sources and severities are also remembered for this person in this browser (the fallback when the
  // page is reached without a filter and without a default view)
  const filter = useMemo(() => readNewsFilter(params), [params])
  const state = filter.unread ? "new" : "all"
  const fallback = useCallback(
    (p: URLSearchParams) => {
      const f = loadNewsFilter(user?.id)
      return f.sources.length || f.severities.length || f.topics.length || f.ours ? writeNewsFilter(p, f) : null
    },
    [user?.id],
  )
  const deciding = useDefaultView("news", fallback).pending
  const choose = useCallback(
    (next: Partial<NewsUrlFilter>) => {
      setParams((p) => writeNewsFilter(p, next), { replace: true, state: IN_PAGE })
      if (next.sources !== undefined || next.severities !== undefined || next.topics !== undefined || next.ours !== undefined) {
        const cur = readNewsFilter(new URLSearchParams(window.location.search))
        saveNewsFilter(user?.id, {
          sources: next.sources ?? cur.sources,
          severities: next.severities ?? cur.severities,
          topics: next.topics ?? cur.topics,
          ours: next.ours ?? cur.ours,
        })
      }
    },
    [setParams, user?.id],
  )
  const q = filter.q
  const setQ = useCallback((v: string) => choose({ q: v }), [choose])
  // typed but not applied yet (the search follows 300 ms after the last key): "Alle als gelesen" would mark the stories
  // of the previous search
  const [typing, setTyping] = useState(false)
  const sourcesQ = useNewsSources()
  const sources = useMemo(() => sourcesQ.data ?? [], [sourcesQ.data])
  // a source switched off or removed meanwhile: its filter would stay active, but invisible – it counts no more
  const activeSources = useMemo(() => (sourcesQ.data ? filter.sources.filter((id) => sourcesQ.data.some((x) => x.id === id)) : filter.sources), [sourcesQ.data, filter.sources])

  // the open story lives in the address (?story=…): a desktop notification or a link from a mail opens it directly.
  // Opened here it is one history step – closing goes that step back instead of adding another one.
  const open = params.get("story")
  const pushed = useRef(false)
  const opener = useRef<HTMLElement | null>(null)
  const openStory = useCallback(
    (id: string) => {
      opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
      pushed.current = true
      setParams(
        (p) => {
          const next = new URLSearchParams(p)
          next.set("story", id)
          return next
        },
        { replace: false, state: IN_PAGE },
      )
    },
    [setParams],
  )
  const closeStory = useCallback(() => {
    if (pushed.current) {
      pushed.current = false
      navigate(-1)
    } else
      setParams(
        (p) => {
          const next = new URLSearchParams(p)
          next.delete("story")
          return next
        },
        { replace: true, state: IN_PAGE },
      )
  }, [navigate, setParams])
  // a link to a story that is gone (removed after its retention time, or by an admin): said once, the address cleaned
  const gone = useCallback(() => {
    toast.info(t("news.gone"), { id: "news-gone" })
    closeStory()
  }, [closeStory, t])
  // the drawer stays mounted while it slides out – with the story it showed
  const [shown, setShown] = useState<string | null>(open)
  if (open && open !== shown) setShown(open)

  // "Betrifft unsere Produkte" in Vendor News' scope: under "Mein Team" the products of my teams – the teams asked only
  // while the filter is on, and the list then waits for them (the full list would flash first otherwise); off, the
  // scope is not part of the request (one first load, the chip's label and number do not change on their own)
  const vscope = useVendorScope(user?.id, filter.ours)
  const scope = filter.ours && vscope.scope === "team" ? "team" : "all"
  const waitScope = filter.ours && vscope.scope === null
  const list = useNews(
    { state, sources: activeSources, severities: filter.severities, topics: filter.topics, q, muted: filter.muted, ours: filter.ours, scope },
    !deciding && !waitScope,
  )
  const mark = useMarkRead()
  const items = useMemo(() => mergePages(list.data?.pages), [list.data])
  const first = list.data?.pages[0]
  const counts = first?.counts ?? { new: 0, read: 0 }
  const topicCounts = first?.counts?.topics
  const topicOptions = useMemo(
    () =>
      NEWS_TOPICS.map((x) => ({
        value: x,
        label: t(`news.topic.${x}`),
        description: t(`news.topicHint.${x}`),
        hint: topicCounts ? String(topicCounts[x] ?? 0) : undefined,
      })),
    [t, topicCounts],
  )
  const sourceOptions = useMemo(() => sources.map((x) => ({ value: x.id, label: x.name, group: x.category ?? "custom" })), [sources])
  const sourceGroupsOf = useMemo(
    () =>
      sourceGroups(sources).map((g) => ({
        key: g.category,
        label: t(`settings.news.cat.${g.category}`),
        all: t("news.allOfGroup", { group: t(`settings.news.cat.${g.category}`) }),
      })),
    [sources, t],
  )
  const quick = filter.topics.filter((x) => QUICK_TOPICS.includes(x))
  const anyFilter = activeSources.length > 0 || filter.severities.length > 0 || filter.topics.length > 0 || filter.ours
  const showOurs = !!first?.ours_on || filter.ours

  const markRef = useRef(mark.mutate)
  useEffect(() => {
    markRef.current = mark.mutate
  }, [mark.mutate])
  const toggle = useCallback(
    (item: NewsItem, read: boolean) => {
      markRef.current(
        { id: item.id, read },
        {
          onError: (e) => toast.error(errorText(t, e)),
          // a click too many is undone right there
          onSuccess: () =>
            toast.success(t(read ? "news.markedRead" : "news.markedUnread"), {
              id: "news-mark",
              action: { label: t("news.undo"), onClick: () => markRef.current({ id: item.id, read: !read }) },
            }),
        },
      )
    },
    [t],
  )
  const readAll = async () => {
    if (typing) return
    const ok = await confirmAction({
      title: t("news.readAllTitle"),
      text: t("news.readAllText", { count: counts.new }),
      confirm: t("news.readAll"),
      destructive: false,
    })
    if (!ok) return
    try {
      const body = readAllBody({ sources: activeSources, severities: filter.severities, topics: filter.topics, q, muted: filter.muted, ours: filter.ours, scope }, first)
      const r = await api.post<{ marked: number }>("/api/news/read-all", body)
      toast.success(t("news.readAllDone", { count: r.marked }))
      // the lists and the number – not the sources or every story's details
      void qc.invalidateQueries({ queryKey: ["news", "list"] })
      void qc.invalidateQueries({ queryKey: ["reader", "counts"] })
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }

  const header = (
    <PageHeader
      title={t("nav.news")}
      description={t("news.description")}
      actions={
        isAdmin && (
          <Button variant="outline" size="sm" asChild>
            <Link to="/settings/integrations#news">
              <Settings2 /> {t("news.sources")}
            </Link>
          </Button>
        )
      }
    />
  )
  // news switched off: only the note – no filters, nothing they could act on
  if (first && !first.enabled)
    return (
      <div className="space-y-5">
        {header}
        <EmptyState
          icon={Newspaper}
          title={t("news.offTitle")}
          text={t(isAdmin ? "news.offTextAdmin" : "news.offText")}
          action={
            isAdmin && (
              <Button size="sm" asChild>
                <Link to="/settings/integrations#news">{t("news.setUp")}</Link>
              </Button>
            )
          }
        />
      </div>
    )

  return (
    <div className="space-y-5">
      {header}
      <div className="flex flex-wrap items-center gap-2">
        <SearchBox applied={q} onSearch={setQ} onPending={setTyping} />
        <MultiSelect
          label={t("news.filterSource")}
          options={sourceOptions}
          groups={sourceGroupsOf}
          value={activeSources}
          onChange={(v) => choose({ sources: v })}
          className="h-9"
        />
        <MultiSelect
          label={t("news.filterSeverity")}
          options={NEWS_SEVERITIES.map((x) => ({ value: x, label: t(`news.sev.${x}`) }))}
          value={filter.severities}
          onChange={(v) => choose({ severities: v as NewsSeverity[] })}
          searchable={false}
          className="h-9"
        />
        <MultiSelect
          label={t("news.filterTopic")}
          options={topicOptions}
          value={filter.topics}
          onChange={(v) => choose({ topics: NEWS_TOPICS.filter((x) => v.includes(x)) })}
          searchable={false}
          className="h-9"
          contentClassName="w-80"
        />
        <ViewsMenu page="news" />
        {anyFilter && (
          <Button variant="ghost" size="sm" onClick={() => choose({ sources: [], severities: [], topics: [], ours: false })}>
            {t("news.resetFilter")}
          </Button>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {/* one click for the topics asked most – the same filter as "Thema" (OR with the topics chosen there) */}
        <ToggleGroup
          type="multiple"
          variant="outline"
          size="sm"
          value={quick}
          onValueChange={(v) => choose({ topics: NEWS_TOPICS.filter((x) => (QUICK_TOPICS.includes(x) ? v.includes(x) : filter.topics.includes(x))) })}
          className="flex-wrap"
          aria-label={t("news.quickTopics")}
        >
          {QUICK_TOPICS.map((x) => (
            <ToggleGroupItem key={x} value={x} title={t(`news.topicHint.${x}`)} className="h-8 rounded-full! px-3 text-xs">
              {t(`news.topic.${x}`)}
              {topicCounts && <span className="text-muted-foreground tabular-nums">{topicCounts[x] ?? 0}</span>}
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
        {/* "Betrifft unsere Produkte": AND with the other filters – only while something is followed (or it is on) */}
        {showOurs && (
          <Toggle
            variant="outline"
            size="sm"
            pressed={filter.ours}
            onPressedChange={(v) => choose({ ours: v })}
            title={t(scope === "team" ? "news.oursHintTeam" : "news.oursHint")}
            className="h-8 rounded-full! px-3 text-xs"
          >
            <Package className="size-3.5" />
            {t(scope === "team" ? "news.oursTeam" : "news.ours")}
            {first?.counts?.ours !== undefined && <span className="text-muted-foreground tabular-nums">{first.counts.ours}</span>}
          </Toggle>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
        <div className="flex items-center gap-2">
          <Switch id="news-unread" checked={filter.unread} onCheckedChange={(v) => choose({ unread: v })} />
          <Label htmlFor="news-unread" className="text-sm">
            {t("reader.onlyUnread")}
          </Label>
        </div>
        <div className="flex items-center gap-2">
          <Switch id="news-muted" checked={filter.muted} onCheckedChange={(v) => choose({ muted: v })} />
          <Label htmlFor="news-muted" className="text-sm" title={t("reader.mute.onlyYou")}>
            {t("reader.showMuted")}
          </Label>
        </div>
        {first?.counts && (
          <span className="text-xs text-muted-foreground tabular-nums" aria-live="polite">
            {t("reader.unreadCount", { count: counts.new })}
          </span>
        )}
        {counts.new > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="ml-auto"
            onClick={() => void readAll()}
            disabled={typing || list.isPlaceholderData}
            title={typing || list.isPlaceholderData ? t("news.readAllWait") : undefined}
          >
            <CheckCheck /> {t("news.readAll")}
          </Button>
        )}
      </div>

      {/* a failed refresh: the stories already shown stay, the error is said above them (a failed next page: at the end) */}
      {list.isError && list.data && !list.isFetchNextPageError && <QueryError error={list.error} onRetry={() => void list.refetch()} compact />}
      {list.isError && !list.data ? (
        <QueryError error={list.error} onRetry={() => void list.refetch()} />
      ) : list.isLoading ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin" /> {t("news.loading")}
        </p>
      ) : items.length === 0 ? (
        first?.enabled && (
          <EmptyState icon={Newspaper} title={t(state === "new" ? "news.emptyNew" : "reader.emptyAll")} text={t(state === "new" ? "news.emptyNewText" : "reader.emptyAllText")} />
        )
      ) : (
        <div
          className={cn("grid grid-cols-1 gap-4 transition-opacity sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-6", list.isPlaceholderData && "opacity-60")}
          aria-busy={list.isPlaceholderData || undefined}
        >
          {items.map((n) => (
            <NewsCard key={n.id} n={n} onOpen={openStory} onToggle={toggle} />
          ))}
        </div>
      )}
      {/* a failed next page: said where the person is (the end of the list), with "try again" – no automatic retries,
          each would fail again while the end stays in sight */}
      {list.isFetchNextPageError && !list.isFetchingNextPage ? (
        <QueryError error={list.error} onRetry={() => list.fetchNextPage({ cancelRefetch: false })} compact />
      ) : (
        list.hasNextPage && !list.isPlaceholderData && <MoreBelow busy={list.isFetchingNextPage} onMore={() => void list.fetchNextPage({ cancelRefetch: false })} />
      )}
      {shown && (
        <NewsDrawer
          id={shown}
          card={items.find((n) => n.id === shown)}
          open={!!open}
          onClose={closeStory}
          onGone={gone}
          onClosed={() => {
            setShown(null)
            // back where the person was: the card (or whatever opened it), not the top of the page
            restoreFocus(opener.current)
            opener.current = null
          }}
          onToggle={(item, read) => {
            toggle(item, read)
            if (read && state === "new") closeStory()
          }}
          onSeen={(item) => mark.mutate({ id: item.id, read: true, keep: true })}
        />
      )}
    </div>
  )
}

/** Typing re-renders only this box – the grid follows 300 ms after the last key. `onPending`: typed ≠ applied (the page
 *  renders again only when that flips, not per key). */
function SearchBox({ applied, onSearch, onPending }: { applied: string; onSearch: (q: string) => void; onPending: (p: boolean) => void }) {
  const { t } = useTranslation()
  const [input, setInput] = useState(applied)
  // the address changed from elsewhere (a view applied, back in the history): the box follows – not when it is only
  // the search this box sent arriving
  const [sent, setSent] = useState(applied)
  const norm = (v: string) => v.trim().slice(0, 100)
  if (applied !== norm(sent)) {
    setSent(applied)
    if (applied !== norm(input)) setInput(applied)
  }
  useEffect(() => {
    if (input === sent) return
    const id = setTimeout(() => {
      setSent(input)
      onSearch(input)
    }, 300)
    return () => clearTimeout(id)
  }, [input, sent, onSearch])
  useEffect(() => onPending(input.trim().slice(0, 100) !== applied), [input, applied, onPending])
  return (
    <div className="relative">
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input value={input} onChange={(e) => setInput(e.target.value)} maxLength={100} placeholder={t("news.search")} className="h-9 w-56 pl-8" aria-label={t("news.search")} />
    </div>
  )
}

/**
 * The next page when the end of the list comes into sight (400 px ahead), and as a button (keyboard, screen readers). The
 * cards already shown stay – keyboard focus and scroll position too; the browser skips drawing those out of sight
 * (content-visibility on the cards), so a list scrolled to thousands of stories stays light.
 */
function MoreBelow({ busy, onMore }: { busy: boolean; onMore: () => void }) {
  const { t } = useTranslation()
  const ref = useRef<HTMLDivElement>(null)
  const more = useRef(onMore)
  useEffect(() => {
    more.current = onMore
  }, [onMore])
  useEffect(() => {
    const el = ref.current
    if (!el || busy || typeof IntersectionObserver === "undefined") return
    // a new observer per finished page: still in sight after it (a short page, a tall screen) → the next one, once
    const io = new IntersectionObserver((entries) => entries.some((e) => e.isIntersecting) && more.current(), { rootMargin: "400px 0px" })
    io.observe(el)
    return () => io.disconnect()
  }, [busy])
  return (
    <div ref={ref} className="text-center">
      <Button variant="outline" size="sm" onClick={onMore} disabled={busy}>
        {busy && <Loader2 className="animate-spin" />} {t("news.more")}
      </Button>
    </div>
  )
}

export function SourceLogo({ s, className }: { s: NewsSourceRef; className?: string }) {
  const [failed, setFailed] = useState(false)
  if (!s.logo || failed)
    return (
      <span className={cn("flex size-5 shrink-0 items-center justify-center rounded bg-muted text-[10px] font-semibold text-muted-foreground uppercase", className)}>
        {s.name.slice(0, 1)}
      </span>
    )
  return <img src={`/api/news/sources/${s.id}/logo`} alt="" className={cn("size-5 shrink-0 rounded object-contain", className)} onError={() => setFailed(true)} />
}

/** The first two topics of a card (Zero-Day > Aktiv ausgenutzt > Ransomware > Ohne Patch > the rest), "+n" for the
 *  others – each with its explanation on hover. */
function TopicBadges({ topics }: { topics?: NewsTopic[] }) {
  const { t } = useTranslation()
  const { shown, more } = cardTopics(topics)
  if (!shown.length) return null
  const rest = NEWS_TOPICS.filter((x) => topics?.includes(x) && !shown.includes(x))
  return (
    <>
      {shown.map((x) => (
        <Tooltip key={x}>
          <TooltipTrigger asChild>
            <span className="relative z-10 inline-flex" tabIndex={0}>
              <Pill color={NEWS_TOPIC_COLOR[x]}>{t(`news.topic.${x}`)}</Pill>
            </span>
          </TooltipTrigger>
          <TooltipContent className="max-w-xs leading-relaxed">{t(`news.topicHint.${x}`)}</TooltipContent>
        </Tooltip>
      ))}
      {more > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="relative z-10 inline-flex" tabIndex={0} aria-label={rest.map((x) => t(`news.topic.${x}`)).join(", ")}>
              <Pill color="--muted-foreground">+{more}</Pill>
            </span>
          </TooltipTrigger>
          <TooltipContent className="max-w-xs leading-relaxed">{rest.map((x) => t(`news.topic.${x}`)).join(", ")}</TooltipContent>
        </Tooltip>
      )}
    </>
  )
}

/** "Unser Produkt: PAN-OS" – the first followed product the story's details concern, "+n" for more (all on hover). */
function OursBadge({ products }: { products?: { key: string; label: string }[] }) {
  const { t } = useTranslation()
  if (!products?.length) return null
  const names = products.map((p) => p.label).join(", ")
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="relative z-10 inline-flex max-w-full min-w-0" tabIndex={0}>
          <Pill color="--primary" className="max-w-full min-w-0 shrink">
            <span className="truncate">
              {t("news.oursBadge", { name: products[0].label })}
              {products.length > 1 && ` +${products.length - 1}`}
            </span>
          </Pill>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">{t("news.oursBadgeHint", { names })}</TooltipContent>
    </Tooltip>
  )
}

/** The drawer's "Themen": each topic with what it rests on (computed by the server on request). */
function TopicsBlock({ reasons }: { reasons: TopicReason[] }) {
  const { t } = useTranslation()
  return (
    <section className="space-y-1.5 rounded-lg border p-3">
      <h3 className="text-xs font-semibold text-muted-foreground">{t("news.topicsTitle")}</h3>
      <ul className="space-y-1 text-xs">
        {reasons.map((r) => (
          <li key={r.topic} className="flex flex-wrap items-center gap-2">
            <Pill color={NEWS_TOPIC_COLOR[r.topic]}>{t(`news.topic.${r.topic}`)}</Pill>
            <span className="text-muted-foreground">{t(`news.topicWhy.${r.kind}`, { value: r.value })}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

function SeverityTag({ s }: { s: NewsSeverity }) {
  const { t } = useTranslation()
  return (
    <Pill color={NEWS_SEV_COLOR[s]} dot>
      {t(`news.sev.${s}`)}
    </Pill>
  )
}

/** One story. The title is the button that opens it (a real one – keyboard and screen readers); the whole card is its
 *  click area. The read button above it toggles on its own, the menu beside it mutes. Unread: a dot and a bold title;
 *  muted (shown with "Stummgeschaltete zeigen"): dimmed. Memoised: marking one card re-renders only that one. */
const NewsCard = memo(function NewsCard({ n, onOpen, onToggle }: { n: NewsItem; onOpen: (id: string) => void; onToggle: (n: NewsItem, read: boolean) => void }) {
  const { t } = useTranslation()
  const unread = !!n.unread
  return (
    <article
      className={cn(
        // not drawn while far out of sight (the browser keeps its place by the size it had) – thousands of cards stay light
        "group relative flex min-h-52 flex-col gap-2 rounded-xl border bg-card p-4 text-left transition-colors [contain-intrinsic-size:auto_13rem] [content-visibility:auto] hover:border-primary/40 hover:bg-muted/30 has-[[data-open]:focus-visible]:ring-2 has-[[data-open]:focus-visible]:ring-ring",
        n.severity === "critical" && "border-sev-critical/40",
        n.muted && "opacity-55",
      )}
      data-unread={unread || undefined}
    >
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <SourceLogo s={n.source} />
        <span className="min-w-0 flex-1 truncate font-medium text-foreground/80">{n.source.name}</span>
        {n.muted && <Pill color="--muted-foreground">{t("reader.mute.badge")}</Pill>}
        <button
          type="button"
          onClick={() => onToggle(n, unread)}
          title={unread ? t("news.markRead") : t("news.markUnread")}
          aria-label={unread ? t("news.markRead") : t("news.markUnread")}
          className="relative z-10 flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground opacity-60 transition group-hover:opacity-100 hover:bg-muted hover:text-foreground focus-visible:opacity-100"
        >
          {unread ? <Check className="size-4" /> : <RotateCcw className="size-4" />}
        </button>
        <StoryMenu n={n} onToggle={onToggle} />
      </div>
      <h3 className={cn("line-clamp-3 text-sm leading-snug", unread ? "font-semibold" : "font-normal text-foreground/85")}>
        {unread && <span aria-hidden className="mr-1.5 inline-block size-2 rounded-full bg-primary align-middle" />}
        <button type="button" data-open onClick={() => onOpen(n.id)} className="text-left outline-none after:absolute after:inset-0 after:rounded-xl after:content-['']">
          {unread && <span className="sr-only">{t("reader.unread")}: </span>}
          {n.title}
        </button>
      </h3>
      <p className="line-clamp-3 text-xs leading-relaxed text-muted-foreground">{n.summary}</p>
      <DetailHint n={n} />
      <div className="mt-auto flex flex-wrap items-center gap-1.5 pt-1">
        <SeverityTag s={n.severity} />
        <OursBadge products={n.products} />
        <TopicBadges topics={n.topics} />
        {n.cves.length > 0 && (
          <span className="inline-flex items-center gap-0.5">
            <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]">{n.cves.length === 1 ? n.cves[0] : t("news.cves", { count: n.cves.length })}</span>
            {/* one CVE: the star right here (above the card's click area); several: in the story's drawer, one per CVE */}
            {n.cves.length === 1 && <WatchStar cve={n.cves[0]} origin={{ kind: "story", id: n.id }} />}
          </span>
        )}
        <Ts at={n.published_at} rel className="relative z-10 ml-auto text-[11px] text-muted-foreground" />
      </div>
    </article>
  )
})

/** The card's menu: read / unread, and muting the story's CVEs (each on its own – a story counts as muted when all are). */
function StoryMenu({ n, onToggle }: { n: NewsItem; onToggle: (n: NewsItem, read: boolean) => void }) {
  const { t } = useTranslation()
  const [until, setUntil] = useState<MuteTarget | null>(null)
  const targets: MuteTarget[] = n.cves.map((c) => ({ kind: "cve", key: c, label: c }))
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            aria-label={t("reader.menu")}
            title={t("reader.menu")}
            className="relative z-10 flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground opacity-60 transition group-hover:opacity-100 hover:bg-muted hover:text-foreground focus-visible:opacity-100 data-[state=open]:opacity-100"
          >
            <MoreHorizontal className="size-4" />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          <DropdownMenuItem onSelect={() => onToggle(n, !!n.unread)}>
            {n.unread ? <Check /> : <RotateCcw />} {n.unread ? t("news.markRead") : t("news.markUnread")}
          </DropdownMenuItem>
          {targets.length > 0 && (
            <>
              <DropdownMenuSeparator />
              <MuteItems targets={targets} onUntil={setUntil} />
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
      <MuteUntilDialog target={until} onClose={() => setUntil(null)} />
    </>
  )
}

function reasonText(t: (k: string, o?: Record<string, unknown>) => string, r: { kind: string; value: string; in_text?: boolean }) {
  const base =
    r.kind === "vendor"
      ? t("news.reason.vendor", { value: t(`news.sev.${r.value}`) })
      : (r.kind === "kev" || r.kind === "euvd") && !r.value
        ? t(`news.reason.${r.kind}Plain`)
        : t(`news.reason.${r.kind}`, { value: r.value })
  return r.in_text ? `${base} ${t("news.reason.inText")}` : base
}

function NewsDrawer({
  id,
  card,
  open,
  onClose,
  onClosed,
  onGone,
  onToggle,
  onSeen,
}: {
  id: string
  /** the card that opened it: title, source and teaser at once, the details follow */
  card?: NewsItem
  open: boolean
  onClose: () => void
  /** after the slide-out: focus goes back to what opened it */
  onClosed: () => void
  /** the story does not exist (any more) */
  onGone: () => void
  onToggle: (n: NewsItem, read: boolean) => void
  /** opened while unread: marked read once (the story stays where it is in the list) */
  onSeen: (n: NewsItem) => void
}) {
  const { t } = useTranslation()
  const q = useNewsDetail(id)
  const d = q.data
  const seen = useRef<string | null>(null)
  const seenRef = useRef(onSeen)
  useEffect(() => {
    seenRef.current = onSeen
  }, [onSeen])
  useEffect(() => {
    if (!open || !d || seen.current === d.id) return
    seen.current = d.id
    if (d.unread) seenRef.current(d)
  }, [open, d])
  const head = d ?? card
  const missing = q.error instanceof ApiError && q.error.status === 404
  const goneRef = useRef(onGone)
  useEffect(() => {
    goneRef.current = onGone
  }, [onGone])
  useEffect(() => {
    if (missing && open) goneRef.current()
  }, [missing, open])
  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent
        className="w-full gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-2xl"
        onCloseAutoFocus={(e) => {
          e.preventDefault()
          onClosed()
        }}
      >
        <SheetHeader className="border-b">
          {head ? (
            <>
              <div className="flex flex-wrap items-center gap-2 pr-8 text-xs text-muted-foreground">
                <SourceLogo s={head.source} />
                <span className="font-medium text-foreground/80">{head.source.name}</span>
                <span>·</span>
                <Ts at={head.published_at} zone />
                {head.also_in.length > 0 && <span>· {t("news.alsoIn", { list: head.also_in.join(", ") })}</span>}
              </div>
              <SheetTitle className="text-lg leading-snug">{head.title}</SheetTitle>
              <SheetDescription className="sr-only">{head.summary}</SheetDescription>
            </>
          ) : q.isError ? (
            <SheetTitle className="text-sm text-muted-foreground">{t(missing ? "news.gone" : "errors.loadFailed")}</SheetTitle>
          ) : (
            <SheetTitle className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" /> {t("news.loading")}
            </SheetTitle>
          )}
        </SheetHeader>
        <div className="min-h-0 flex-1 space-y-5 overflow-y-auto p-5">
          {q.isError && !missing && <QueryError error={q.error} onRetry={() => q.refetch()} />}
          {!d && !q.isError && <DrawerSkeleton label={t("news.loading")} />}
          {d && (
            <>
              <section className="space-y-1.5 rounded-lg border p-3">
                <div className="flex items-center gap-2">
                  <SeverityTag s={d.severity} />
                  <span className="text-xs text-muted-foreground">{t("news.ratedBy")}</span>
                </div>
                {d.reasons.length > 0 ? (
                  <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted-foreground">
                    {d.reasons.map((r, i) => (
                      <li key={i}>{reasonText(t, r)}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-muted-foreground">{t("news.reason.none")}</p>
                )}
              </section>
              {!!d.topic_reasons?.length && <TopicsBlock reasons={d.topic_reasons} />}
              <AffectsYou d={d} />
              {d.details && <StoryDetailsBlock details={d.details} story={d} />}
              {!!d.changes?.length && <StoryChanges changes={d.changes} />}
              {d.summary && <p className="text-sm leading-relaxed font-medium">{d.summary}</p>}
              {d.content_html && (
                <div
                  className="space-y-3 text-sm leading-relaxed text-foreground/90 [&_a]:text-primary [&_a]:underline [&_blockquote]:border-l-2 [&_blockquote]:pl-3 [&_h2]:font-semibold [&_h3]:font-semibold [&_li]:ml-5 [&_ol]:list-decimal [&_pre]:overflow-x-auto [&_pre]:rounded [&_pre]:bg-muted [&_pre]:p-2 [&_ul]:list-disc"
                  // sanitised on the server (nh3: structure and links only, no images, no scripts)
                  dangerouslySetInnerHTML={{ __html: d.content_html }}
                />
              )}
              {(d.cves.length > 0 || (d.exploits?.length ?? 0) > 0) && <StoryCves d={d} />}
            </>
          )}
        </div>
        <SheetFooter className="flex-row flex-wrap items-center justify-end gap-2 border-t bg-popover">
          {d && (
            <>
              <span className="mr-auto">
                <ForwardButton thing={{ story_id: d.id }} title={d.title} />
              </span>
              <MuteButton targets={storyTargets(d)} />
              <Button variant="outline" onClick={() => onToggle(d, !!d.unread)}>
                {d.unread ? <Check /> : <RotateCcw />} {d.unread ? t("news.markRead") : t("news.markUnread")}
              </Button>
              <Button asChild>
                <a href={d.url} target="_blank" rel="noopener noreferrer">
                  <ExternalLink /> {t("news.openArticle")}
                </a>
              </Button>
            </>
          )}
          <Button variant="ghost" onClick={onClose}>
            {t("common.close")}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

/** What a story's drawer can mute: its CVEs and the followed products it affects. */
function storyTargets(d: NewsDetail): MuteTarget[] {
  const products = d.affects.filter((a) => a.versions.some((v) => v.status !== "not_affected")).map((a) => ({ kind: "product" as const, key: a.product, label: a.label }))
  return [...products, ...d.cves.slice(0, 10).map((c) => ({ kind: "cve" as const, key: c, label: c }))]
}
