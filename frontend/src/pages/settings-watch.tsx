import { useEffect, useMemo, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link, useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import {
  Ban,
  BellOff,
  CalendarDays,
  CalendarPlus,
  ChevronDown,
  CircleHelp,
  Copy,
  Eye,
  ExternalLink,
  Flame,
  Keyboard,
  Loader2,
  Newspaper,
  Package,
  PackageX,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Skull,
  Star,
  Tag,
  Trash2,
  TrendingUp,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill } from "@/components/cobe/badges"
import { EmptyState, Mono, PageHeader } from "@/components/cobe/common"
import { confirmAction } from "@/components/cobe/confirm"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Field } from "@/components/cobe/form"
import { Term } from "@/components/cobe/glossary"
import { Ts } from "@/components/cobe/time"
import { MuteButton, useMuteOf } from "@/components/cobe/mute-menu"
import { copyWithToast } from "@/lib/clipboard"
import { epssPercent, epssTone } from "@/lib/epss"
import { errorText } from "@/lib/errors"
import { fmtDate, fmtDay, fmtDayFrom } from "@/lib/format"
import { NEWS_SEV_COLOR, type NewsSeverity } from "@/lib/news-api"
import { PERSONAL_KEY, usePersonalNotify } from "@/lib/teams-api"
import { cn } from "@/lib/utils"
import { ADVISORY_SOURCE_LABEL } from "@/lib/vendor-api"
import {
  CALENDAR_KEY,
  WATCH_FILTERS,
  WATCH_GROUP_BYS,
  WATCH_KEY,
  WATCH_SORTS,
  type WatchEvent,
  type WatchFilter,
  type WatchGroup,
  type WatchGroupBy,
  type WatchItem,
  type WatchList,
  deleteCalendar,
  groupKeyOf,
  groupWatch,
  isNewItem,
  makeCalendar,
  markWatchSeen,
  matchesWatchFilter,
  normalizeCve,
  originIn,
  originLink,
  parseGroupBy,
  parseWatchFilter,
  parseWatchSort,
  rewatch,
  sortWatch,
  productLink,
  unwatchCve,
  unwatchCves,
  unwatchGroup,
  useCalendar,
  useWatchEvents,
  useWatchList,
  watchCounts,
  watchCve,
  watchHintAction,
  watchHintKey,
  webcalUrl,
  withGroupBy,
} from "@/lib/watch-api"
import { PlainCard, SettingsCard, SheetActions, SheetBody, SheetLoading } from "@/pages/settings-shared"

// ---------------------------------------------------------------- Beobachtete CVEs

/** "Beobachtete CVEs" (its own page in the sidebar, /watch): a watchlist – the CVEs the person follows, what is known of
 * each now and what happened to it since (fix, KEV, EPSS, withdrawn – app/cve_watch.py). Works without a team; without a
 * way it is a reminder list. Filter, order and the grouping live in the address (?filter=, ?sort=, ?group_by= – by
 * product unless it says origin or none; the older ?groups=1 is by origin); ?cve= opens that row, ?group=<key> shows that
 * group. */
export function WatchPage() {
  const { t } = useTranslation()
  const q = useWatchList()
  const qc = useQueryClient()
  // the previous visit as it was when the page opened: the marks stay for this visit, also after the list comes again
  const [seenBefore, setSeenBefore] = useState<string | null | undefined>(undefined)
  const marked = useRef(false)
  useEffect(() => {
    if (!q.data || marked.current) return
    marked.current = true
    setSeenBefore(q.data.seen_before)
    void markWatchSeen().catch(() => undefined) // a lost mark only means the same "new" marks next time
  }, [q.data])
  // until the effect ran: the first answer's visit (it is the one kept)
  const before = seenBefore !== undefined ? seenBefore : (q.data?.seen_before ?? null)
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: WATCH_KEY })
    void qc.invalidateQueries({ queryKey: PERSONAL_KEY }) // the first watched CVE can open the personal ways
  }
  const empty = q.data?.items.length === 0
  return (
    <>
      <PageHeader
        title={t("watch.title")}
        description={
          <span className="inline-flex flex-wrap items-center gap-1">
            {t("watch.tipBefore")} <Star className="inline size-3.5 text-warning" aria-hidden />
            <span className="sr-only">☆</span> {t("watch.tipAfter")}
          </span>
        }
        actions={
          <>
            {q.data && !empty && <AddCve data={q.data} onAdded={refresh} compact />}
            <HelpLink chapter="benachrichtigungen" section="cves-beobachten" topic={t("watch.title")} />
          </>
        }
      />
      {!q.data ? (
        <PlainCard>
          <SheetLoading error={q.error} onRetry={() => void q.refetch()} />
        </PlainCard>
      ) : (
        <WatchBody data={q.data} seenBefore={before} onChanged={refresh} />
      )}
    </>
  )
}

/** "CVE-2026-12345 [Beobachten] (?)" – the header's add control (and the empty state's). */
function AddCve({ data, onAdded, compact = false }: { data: WatchList; onAdded: () => void; compact?: boolean }) {
  const { t } = useTranslation()
  const [text, setText] = useState("")
  const [busy, setBusy] = useState(false)
  const id = normalizeCve(text)
  const full = data.items.length >= data.limit
  const invalid = text.trim() !== "" && !id
  const add = async () => {
    if (!id) return
    setBusy(true)
    try {
      const r = await watchCve(id, { kind: "manual" })
      toast.success(r.added ? t("watch.added", { cve: id }) : t("watch.already", { cve: id }))
      setText("")
      onAdded()
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const msg = full ? t("watch.full", { limit: data.limit }) : invalid ? t("watch.invalid") : null
  return (
    <form
      className={cn("flex flex-col gap-1", !compact && "w-full max-w-md")}
      onSubmit={(e) => {
        e.preventDefault()
        void add()
      }}
    >
      <div className="flex items-center gap-2">
        <Input
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="CVE-2026-12345"
          spellCheck={false}
          autoComplete="off"
          className={cn("min-w-0 font-mono", compact ? "w-40 sm:w-48" : "flex-1")}
          aria-invalid={invalid ? true : undefined}
          aria-label={t("watch.add")}
          aria-describedby={msg ? "watch-add-msg" : undefined}
          disabled={full}
        />
        <Button type="submit" disabled={!id || busy || full}>
          {busy ? <Loader2 className="animate-spin" /> : <Star />} {t("watch.watchButton")}
        </Button>
        <WhatHelp />
      </div>
      {msg && (
        <p id="watch-add-msg" className={cn("text-xs", full ? "text-muted-foreground" : "text-destructive")} role={invalid ? "alert" : undefined}>
          {msg}
        </p>
      )}
    </form>
  )
}

/** (?) – "Wann kommt eine Meldung?" in a small popover instead of a long text on the page. */
function WhatHelp() {
  const { t } = useTranslation()
  const box = useRef<HTMLDivElement>(null)
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button type="button" variant="ghost" size="icon" aria-label={t("watch.what")} title={t("watch.what")}>
          <CircleHelp />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        ref={box}
        tabIndex={-1}
        align="end"
        className="w-80 max-w-[calc(100vw-2rem)] text-xs leading-relaxed"
        // focus the box itself, not its first term: that would open the term's tooltip at once and catch the first Escape
        onOpenAutoFocus={(e) => {
          e.preventDefault()
          box.current?.focus()
        }}
      >
        <p className="text-sm font-medium">{t("watch.what")}</p>
        <ul className="list-disc space-y-0.5 pl-5 text-muted-foreground">
          <li>{t("watch.what.fix")}</li>
          <li>
            <Term k="kev">KEV</Term>: {t("watch.what.kev")}
          </li>
          <li>
            <Term k="epss">EPSS</Term>: {t("watch.what.epss")}
          </li>
          <li>{t("watch.what.withdrawn")}</li>
        </ul>
        <p className="text-muted-foreground">{t("watch.onlyNew")}</p>
        <p className="text-muted-foreground">{t("watch.footer")}</p>
      </PopoverContent>
    </Popover>
  )
}

/** One thin line when nothing can reach the person: why, and the way to the own ways where there is one. */
function NotifyHint({ data }: { data: WatchList }) {
  const { t } = useTranslation()
  // the first watched CVE can open the personal ways to someone without a team – only then is there a link
  const personal = usePersonalNotify()
  const key = watchHintKey(data.notify.reason)
  const action = watchHintAction(data.notify.reason, personal.data?.available ?? false)
  if (!key || !action) return null
  return (
    <p className="flex flex-wrap items-center gap-x-2 gap-y-0.5 rounded-lg border border-warning/30 bg-warning/10 px-3 py-1.5 text-xs" role="status" title={t(key)}>
      <BellOff className="size-3.5 shrink-0 text-warning" aria-hidden />
      <span className="font-medium">{t("watch.notifyOff")}</span>
      {action === "link" ? (
        <Link to="/settings/notifications?tab=vendor" className="font-medium text-primary underline-offset-2 hover:underline">
          {t("watch.hint.toWays")}
        </Link>
      ) : (
        <span className="text-muted-foreground">{action === "firstCve" ? t("watch.hint.firstCve") : t(`watch.hint.short.${data.notify.reason}`)}</span>
      )}
    </p>
  )
}

function WatchBody({ data, seenBefore, onChanged }: { data: WatchList; seenBefore: string | null; onChanged: () => void }) {
  const { t } = useTranslation()
  const [params, setParams] = useSearchParams()
  const focus = normalizeCve(params.get("cve") ?? "")
  const filter = parseWatchFilter(params.get("filter"))
  const sort = parseWatchSort(params.get("sort"))
  const setParam = (key: "filter" | "sort", value: string, fallback: string) =>
    setParams(
      (p) => {
        const next = new URLSearchParams(p)
        if (value === fallback) next.delete(key)
        else next.set(key, value)
        return next
      },
      { replace: true },
    )
  const setFilter = (f: WatchFilter) => setParam("filter", f, "all")
  const counts = useMemo(() => watchCounts(data.items, seenBefore), [data.items, seenBefore])
  const rows = useMemo(
    () =>
      sortWatch(
        data.items.filter((w) => matchesWatchFilter(w, filter, seenBefore)),
        sort,
      ),
    [data.items, filter, sort, seenBefore],
  )
  const groupBy = parseGroupBy(params)
  const groupFocus = groupBy === "none" ? null : params.get("group")
  const groups = useMemo(() => (groupBy !== "none" ? groupWatch(rows, data.items, seenBefore, groupBy) : []), [groupBy, rows, data.items, seenBefore])
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set())
  const setGroupBy = (by: WatchGroupBy) => setParams((p) => withGroupBy(p, by), { replace: true })
  // ?group=…: that group open and in view, once per link – also when the filter would hide all of it
  const handledGroup = useRef<string | null>(null)
  const scrollTo = useRef<string | null>(null)
  useEffect(() => {
    if (!groupFocus || groupBy === "none" || handledGroup.current === groupFocus) return
    const mine = data.items.filter((w) => groupKeyOf(w, groupBy) === groupFocus)
    if (!mine.length) return // not (yet) in the list
    handledGroup.current = groupFocus
    scrollTo.current = `group-${groupFocus}`
    setCollapsed((c) => {
      if (!c.has(groupFocus)) return c
      const next = new Set(c)
      next.delete(groupFocus)
      return next
    })
    if (!mine.some((w) => matchesWatchFilter(w, filter, seenBefore))) setFilter("all")
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only when the link (or its group) arrives
  }, [groupFocus, groupBy, data.items])
  const toggleGroup = (key: string) =>
    setCollapsed((c) => {
      const next = new Set(c)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  const [open, setOpen] = useState<Set<string>>(() => new Set(focus ? [focus] : []))
  // ?cve=…: that row open and in view, once per link – also when a filter would hide it (the link wants that CVE);
  // a filter chosen afterwards is the person's again
  const handled = useRef<string | null>(null)
  useEffect(() => {
    if (!focus || handled.current === focus) return
    const w = data.items.find((x) => x.cve === focus)
    if (!w) return // not (yet) in the list
    handled.current = focus
    scrollTo.current = focus
    setOpen((o) => (o.has(focus) ? o : new Set([...o, focus])))
    if (!matchesWatchFilter(w, filter, seenBefore)) setFilter("all")
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only when the link (or its row) arrives
  }, [focus, data.items])
  // after the render that shows the row
  useEffect(() => {
    if (!scrollTo.current) return
    const el = document.getElementById(`watch-${scrollTo.current}`)
    if (!el) return
    const isGroup = scrollTo.current.startsWith("group-")
    scrollTo.current = null
    el.scrollIntoView({ block: isGroup ? "start" : "center" })
  })
  const toggle = (cve: string) =>
    setOpen((o) => {
      const next = new Set(o)
      if (next.has(cve)) next.delete(cve)
      else next.add(cve)
      return next
    })
  if (data.items.length === 0)
    return (
      <div className="space-y-4">
        <NotifyHint data={data} />
        <WatchEmpty data={data} onAdded={onChanged} />
      </div>
    )
  return (
    <div className="space-y-4">
      <NotifyHint data={data} />
      <WatchTiles counts={counts} limit={data.limit} filter={filter} firstVisit={seenBefore === null} onFilter={setFilter} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <ToggleGroup
          type="single"
          variant="outline"
          size="sm"
          spacing={1}
          value={filter}
          onValueChange={(v) => v && setFilter(v as WatchFilter)}
          aria-label={t("watch.filter.label")}
          className="flex-wrap"
        >
          {WATCH_FILTERS.map((f) => (
            <ToggleGroupItem
              key={f}
              value={f}
              title={f === "epss" ? t("watch.filter.epssHint") : undefined}
              className="h-8 gap-1.5 rounded-full px-3 data-[state=on]:border-primary/50 data-[state=on]:bg-accent data-[state=on]:text-accent-foreground"
            >
              {t(`watch.filter.${f}`)}
              <span className="text-xs font-normal text-muted-foreground tabular-nums">{counts[f]}</span>
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex items-center gap-2" title={t(`watch.groupBy.hint.${groupBy}`)}>
            <span id="watch-group-by-label" className="text-xs text-muted-foreground">
              {t("watch.groupBy.label")}
            </span>
            <Select value={groupBy} onValueChange={(v) => setGroupBy(v as WatchGroupBy)}>
              <SelectTrigger size="sm" className="w-32" aria-labelledby="watch-group-by-label">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper" align="end">
                {WATCH_GROUP_BYS.map((b) => (
                  <SelectItem key={b} value={b}>
                    {t(`watch.groupBy.${b}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <span id="watch-sort-label" className="text-xs text-muted-foreground">
              {t("watch.sort.label")}
            </span>
            <Select value={sort} onValueChange={(v) => setParam("sort", v, "last")}>
              <SelectTrigger size="sm" className="w-40" aria-labelledby="watch-sort-label">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper" align="end">
                {WATCH_SORTS.map((s) => (
                  <SelectItem key={s} value={s}>
                    {t(`watch.sort.${s}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>
      {rows.length === 0 ? (
        <EmptyState
          icon={Star}
          title={t("watch.filter.none")}
          action={
            <Button size="sm" variant="outline" onClick={() => setFilter("all")}>
              {t("watch.filter.showAll")}
            </Button>
          }
        />
      ) : (
        <div className="overflow-hidden rounded-xl border bg-card">
          <div className={cn("hidden border-b px-3 py-2 text-xs font-medium text-muted-foreground", GRID)}>
            <span>{t("watch.col.cve")}</span>
            <span>{t("watch.col.severity")}</span>
            <span>
              <Term k="kev">KEV</Term>
            </span>
            <span>
              <Term k="epss">EPSS</Term>
            </span>
            <span>{t("watch.col.fix")}</span>
            <span />
          </div>
          {groupBy !== "none" ? (
            <div className="divide-y">
              {groups.map((g) => (
                <WatchGroupSection key={g.key} g={g} collapsed={collapsed.has(g.key)} focus={g.key === groupFocus} onCollapse={toggleGroup} onChanged={onChanged}>
                  {g.items.map((w) => (
                    <WatchRow
                      key={w.cve}
                      w={w}
                      groupBy={groupBy}
                      isNew={isNewItem(w, seenBefore)}
                      open={open.has(w.cve)}
                      focus={w.cve === focus}
                      onToggle={toggle}
                      onChanged={onChanged}
                    />
                  ))}
                </WatchGroupSection>
              ))}
            </div>
          ) : (
            <ul className="divide-y" aria-label={t("watch.title")}>
              {rows.map((w) => (
                <WatchRow
                  key={w.cve}
                  w={w}
                  groupBy={groupBy}
                  isNew={isNewItem(w, seenBefore)}
                  open={open.has(w.cve)}
                  focus={w.cve === focus}
                  onToggle={toggle}
                  onChanged={onChanged}
                />
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}

// the desktop columns: CVE (title under it) · Schwere · KEV · EPSS · Fix · chevron; below lg each row is a compact card
const GRID = "lg:grid lg:grid-cols-[minmax(0,1fr)_6rem_9.5rem_8.5rem_10rem_2rem] lg:items-center lg:gap-x-4"

/** One group of the list: the product its CVEs concern (by product – a catalogue product links to Vendor News, a name
 * says where it comes from, "Ohne Produktzuordnung") or where they were watched from (by origin – a story, a finding or
 * "Einzeln hinzugefügt"); how many, its KEV / ohne Fix / neu, collapse, and "Gruppe nicht mehr beobachten" (with undo,
 * as for one CVE – each CVE watched again with its origin). */
function WatchGroupSection({
  g,
  collapsed,
  focus,
  onCollapse,
  onChanged,
  children,
}: {
  g: WatchGroup
  collapsed: boolean
  focus: boolean
  onCollapse: (key: string) => void
  onChanged: () => void
  children: React.ReactNode
}) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const o = g.origin
  const pr = g.product
  const byProduct = g.by === "product"
  // by product: product (a catalogue one), name (a CNA's or the NVD's), none; by origin: story, finding, manual
  const kind = byProduct ? (pr?.key ? "product" : pr && pr.source !== "none" ? "name" : "none") : o?.kind === "story" || o?.kind === "finding" ? o.kind : "manual"
  const title = byProduct
    ? kind === "none"
      ? t("watch.group.noProduct")
      : pr!.label
    : o?.kind === "story" || o?.kind === "finding"
      ? o.title || t(`watch.group.untitled.${o.kind}`)
      : t("watch.group.manual")
  const link = byProduct ? productLink(pr) : originLink(o)
  const Icon = { story: Newspaper, finding: ShieldAlert, manual: Keyboard, product: Package, name: Tag, none: PackageX }[kind]
  const hint = kind === "manual" ? t("watch.group.manualHint") : kind === "none" ? t("watch.group.noProductHint") : undefined
  const id = `watch-group-${g.key}`
  const panel = `${id}-rows`
  const remove = async () => {
    setBusy(true)
    try {
      // a product group is the CVEs it holds now; an origin group is named as such (the server finds its rows)
      const r = byProduct ? await unwatchCves(g.cves) : await unwatchGroup(originIn(o))
      toast.success(t("watch.group.removed", { count: r.removed.length, title }), {
        action: {
          label: t("watch.undo"),
          onClick: () =>
            void rewatch(r.removed).then(
              (n) => {
                toast.success(t("watch.all.undone", { count: n }))
                onChanged()
              },
              (e: unknown) => toast.error(errorText(t, e)),
            ),
        },
      })
      onChanged()
    } catch (e) {
      toast.error(errorText(t, e))
      setBusy(false)
    }
  }
  return (
    <section id={id} aria-labelledby={`${id}-title`} className={cn(focus && "bg-primary/[0.03]")}>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 bg-muted/40 px-3 py-2">
        <button
          type="button"
          onClick={() => onCollapse(g.key)}
          aria-expanded={!collapsed}
          aria-controls={panel}
          aria-label={t(collapsed ? "watch.group.expand" : "watch.group.collapse", { title })}
          className="flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground outline-none hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          <ChevronDown className={cn("size-4 transition-transform", collapsed && "-rotate-90")} />
        </button>
        <Icon className="size-3.5 shrink-0 text-muted-foreground" aria-label={t(`watch.group.kind.${kind}`)} />
        <h3 id={`${id}-title`} className="min-w-[12rem] flex-1 text-sm font-medium [overflow-wrap:anywhere] sm:min-w-0 sm:flex-none" title={hint}>
          {link ? (
            <Link to={link} className="underline-offset-2 hover:underline" title={t(`watch.group.open.${kind}`)}>
              {title}
            </Link>
          ) : (
            title
          )}
          <span className="font-normal text-muted-foreground">
            {" – "}
            {g.items.length < g.total ? t("watch.group.countOf", { shown: g.items.length, count: g.total }) : t("watch.group.count", { count: g.total })}
          </span>
        </h3>
        <span className="flex flex-wrap items-center gap-1">
          {kind === "name" && pr && <NameSource source={pr.source} />}
          {kind === "product" && pr?.followed && (
            <span title={t("watch.group.followedHint")}>
              <Pill color="--success">{t("watch.group.followed")}</Pill>
            </span>
          )}
          {g.counts.kev > 0 && (
            <span title={t("watch.tile.kev")}>
              <Pill color="--sev-critical">
                <Flame /> KEV {g.counts.kev}
              </Pill>
            </span>
          )}
          {g.counts.nofix > 0 && (
            <Pill color="--muted-foreground">
              {t("watch.tile.nofix")} {g.counts.nofix}
            </Pill>
          )}
          {g.counts.new > 0 && (
            <span title={t("watch.newHint")}>
              <Pill color="--primary">
                {t("watch.new")} {g.counts.new}
              </Pill>
            </span>
          )}
        </span>
        <Button variant="ghost" size="xs" className="ml-auto text-destructive" disabled={busy} onClick={() => void remove()}>
          {busy ? <Loader2 className="animate-spin" /> : <Trash2 />} {t("watch.group.remove")}
        </Button>
      </div>
      {!collapsed && (
        <ul id={panel} className="divide-y border-t" aria-label={title}>
          {children}
        </ul>
      )}
    </section>
  )
}

/** Where a product group's name comes from when it is no catalogue product: "laut CNA" / "laut NVD-CPE" (explained). */
function NameSource({ source }: { source: "catalog" | "cna" | "nvd" | "none" }) {
  const { t } = useTranslation()
  return (
    <span className="text-xs text-muted-foreground">
      {t("watch.group.nameFrom")}{" "}
      {source === "nvd" ? (
        <>
          NVD-<Term k="cpe">CPE</Term>
        </>
      ) : (
        <Term k="cna">CNA</Term>
      )}
    </span>
  )
}

/** "+ 2 weitere Produkte" – the other products the CVE concerns, named in its tooltip (the group or the row names the
 * first). Outside the product grouping the first comes with it ("GitLab + 2"). */
function OtherProducts({ w, withLabel }: { w: WatchItem; withLabel: boolean }) {
  const { t } = useTranslation()
  const p = w.product
  if (!p || p.source === "none" || (!withLabel && p.others.length === 0)) return null
  const more = p.others.length > 0 ? t("watch.product.more", { count: p.others.length }) : null
  if (!more)
    return (
      <span className="min-w-0 truncate text-xs text-muted-foreground" title={t("watch.product.label")}>
        {p.label}
      </span>
    )
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className="min-w-0 cursor-help truncate rounded-sm text-xs text-muted-foreground underline decoration-muted-foreground/60 decoration-dotted underline-offset-4 outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          {withLabel ? `${p.label} ${more}` : more}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">
        <span className="block font-semibold">{t("watch.product.alsoAffects")}</span>
        <span className="block">{p.others.join(", ")}</span>
      </TooltipContent>
    </Tooltip>
  )
}

function WatchTiles({
  counts,
  limit,
  filter,
  firstVisit,
  onFilter,
}: {
  counts: Record<WatchFilter, number>
  limit: number
  filter: WatchFilter
  firstVisit: boolean
  onFilter: (f: WatchFilter) => void
}) {
  const { t } = useTranslation()
  const tile = (f: WatchFilter, label: React.ReactNode, value: number, tone: string | null, extra?: React.ReactNode) => (
    <button
      type="button"
      onClick={() => onFilter(f)}
      aria-pressed={filter === f}
      className={cn(
        "flex min-w-0 flex-col items-start gap-1 rounded-xl border bg-card px-3.5 py-3 text-left outline-none transition-colors hover:bg-muted/40 focus-visible:ring-2 focus-visible:ring-ring/50",
        filter === f && "border-primary/50 bg-accent/60",
      )}
    >
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="flex items-baseline gap-1.5">
        <span className="text-2xl font-semibold tabular-nums" style={tone ? { color: `var(${tone})` } : undefined}>
          {value}
        </span>
        {extra && <span className="text-xs text-muted-foreground">{extra}</span>}
      </span>
    </button>
  )
  return (
    <section aria-label={t("watch.tiles")} className="grid grid-cols-2 gap-2 sm:gap-3 lg:grid-cols-4">
      {tile("all", t("watch.tile.all"), counts.all, null, t("watch.tile.of", { limit }))}
      {tile("kev", t("watch.tile.kev"), counts.kev, counts.kev > 0 ? "--sev-critical" : null)}
      {tile("nofix", t("watch.tile.nofix"), counts.nofix, null)}
      {tile("new", t("watch.tile.new"), counts.new, counts.new > 0 ? "--primary" : null, firstVisit ? t("watch.tile.firstVisit") : undefined)}
    </section>
  )
}

function SevCell({ s }: { s: string }) {
  const { t } = useTranslation()
  const sev = (s in NEWS_SEV_COLOR ? s : "info") as NewsSeverity
  return (
    <Pill color={NEWS_SEV_COLOR[sev]} dot>
      {t(`news.sev.${sev}`)}
    </Pill>
  )
}

function KevCell({ kev }: { kev: NonNullable<WatchItem["kev"]> }) {
  const { t } = useTranslation()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex max-w-full cursor-help rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          <Pill color="--sev-critical" className="max-w-full">
            <Flame /> <span className="truncate">KEV · {fmtDayFrom(kev.added)}</span>
            {kev.ransomware && <Skull aria-label={t("vendor.ransomware")} />}
          </Pill>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">
        <span className="block">
          <span className="font-semibold">{t("glossary.kev")}</span> – {t("watch.kevSince", { date: fmtDay(kev.added) })}
          {kev.ransomware && <span className="block">{t("watch.ransomware")}</span>}
        </span>
      </TooltipContent>
    </Tooltip>
  )
}

function EpssCell({ w }: { w: WatchItem }) {
  const { t, i18n } = useTranslation()
  const e = w.epss!
  const tone = epssTone(e.score)
  const pct = e.percentile
  return (
    <span
      className="inline-flex min-w-0 items-center gap-2"
      title={t("vendor.epssTitle", {
        score: epssPercent(e.score, i18n.language),
        cve: w.cve,
        pct: pct !== null ? (pct * 100).toLocaleString(i18n.language, { maximumFractionDigits: 1 }) : "–",
        date: e.day ? fmtDay(e.day) : "–",
      })}
    >
      <span className="lg:hidden text-xs text-muted-foreground">EPSS</span>
      <span aria-hidden className="h-1.5 w-10 shrink-0 overflow-hidden rounded-full bg-muted">
        <span className="block h-full rounded-full" style={{ width: `${Math.round((pct ?? e.score) * 100)}%`, backgroundColor: `var(${tone})` }} />
      </span>
      <span className="font-mono text-[11px] whitespace-nowrap" style={{ color: `var(${tone})` }}>
        {pct !== null ? t("watch.epssPct", { pct: Math.floor(pct * 100) }) : `${epssPercent(e.score, i18n.language)} %`}
      </span>
      {pct !== null && <span className="hidden text-[11px] text-muted-foreground xl:inline">{epssPercent(e.score, i18n.language)} %</span>}
    </span>
  )
}

function FixCell({ w }: { w: WatchItem }) {
  const { t } = useTranslation()
  if (w.fixed_count === 0) return <Pill color="--muted-foreground">{t("watch.noFix")}</Pill>
  return (
    <Pill color="--success" title={w.fixed.join("\n")} className="max-w-full">
      <ShieldCheck /> <span className="truncate font-mono text-[11px]">{w.fixed[0]}</span>
      {w.fixed_count > 1 && <span className="shrink-0">+{w.fixed_count - 1}</span>}
    </Pill>
  )
}

const Dash = () => (
  <span aria-hidden className="hidden text-muted-foreground lg:inline">
    –
  </span>
)

function WatchRow({
  w,
  groupBy,
  isNew,
  open,
  focus,
  onToggle,
  onChanged,
}: {
  w: WatchItem
  groupBy: WatchGroupBy
  isNew: boolean
  open: boolean
  focus: boolean
  onToggle: (cve: string) => void
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const muted = useMuteOf()("cve", w.cve)
  const panel = `watch-panel-${w.cve}`
  return (
    <li id={`watch-${w.cve}`} className={cn(isNew && "bg-primary/[0.04]", focus && "bg-primary/5")}>
      {/* the row is its click area; the chevron is the real control (keyboard, screen readers) – copy and tooltips inside stay their own */}
      <div
        className={cn("relative flex cursor-pointer flex-wrap items-center gap-x-2 gap-y-1.5 py-2.5 pr-11 pl-3 hover:bg-muted/30 lg:pr-3", GRID)}
        onClick={(e) => {
          // a control inside the row (copy, a tooltip's term) is its own – only those within this row count
          const hit = (e.target as HTMLElement).closest("button, a, [tabindex]")
          if (hit && hit !== e.currentTarget && e.currentTarget.contains(hit)) return
          onToggle(w.cve)
        }}
      >
        <div className="w-full min-w-0 space-y-0.5 lg:w-auto">
          <div className="flex min-w-0 items-center gap-1.5">
            <Mono value={w.cve} className="font-medium" />
            {isNew && (
              <span title={t("watch.newHint")}>
                <Pill color="--primary">{t("watch.new")}</Pill>
              </span>
            )}
            {muted && (
              <span title={t("reader.mute.watchHelp", { date: fmtDate(muted.until) })}>
                <Pill color="--muted-foreground">
                  <BellOff /> {t("reader.mute.badge")}
                </Pill>
              </span>
            )}
            <OtherProducts w={w} withLabel={groupBy !== "product"} />
          </div>
          <p className="truncate text-xs text-muted-foreground" title={w.known ? w.title : undefined}>
            {w.known ? w.title || "\u00a0" : t("watch.noSource")}
          </p>
        </div>
        {w.known ? (
          <>
            <div className="min-w-0">
              <SevCell s={w.severity} />
            </div>
            <div className="min-w-0">{w.kev ? <KevCell kev={w.kev} /> : <Dash />}</div>
            <div className="min-w-0">{w.epss ? <EpssCell w={w} /> : <Dash />}</div>
            <div className="min-w-0">
              <FixCell w={w} />
            </div>
          </>
        ) : (
          <>
            <Dash />
            <Dash />
            <Dash />
            <Dash />
          </>
        )}
        <button
          type="button"
          data-row-toggle
          onClick={(e) => {
            e.stopPropagation()
            onToggle(w.cve)
          }}
          aria-expanded={open}
          aria-controls={panel}
          aria-label={t("watch.toggle", { cve: w.cve })}
          className="absolute top-2 right-2 flex size-8 items-center justify-center rounded-md text-muted-foreground outline-none hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 lg:static lg:size-7"
        >
          <ChevronDown className={cn("size-4 transition-transform", open && "rotate-180")} />
        </button>
      </div>
      {open && (
        <div id={panel} className="border-t bg-muted/20 px-3 py-3 lg:px-4">
          <WatchDetails w={w} onChanged={onChanged} />
        </div>
      )}
    </li>
  )
}

/** The opened row: what happened since the watch began (newest first, "Beobachtet" at the bottom), then the actions. */
function WatchDetails({ w, onChanged }: { w: WatchItem; onChanged: () => void }) {
  const { t } = useTranslation()
  const q = useWatchEvents(w.cve, true)
  const [busy, setBusy] = useState(false)
  const remove = async () => {
    setBusy(true)
    try {
      await unwatchCve(w.cve)
      toast.success(t("watch.removed", { cve: w.cve }), {
        action: {
          label: t("watch.undo"),
          onClick: () =>
            void watchCve(w.cve).then(
              () => {
                toast.success(t("watch.undone", { cve: w.cve }))
                onChanged()
              },
              (e: unknown) => toast.error(errorText(t, e)),
            ),
        },
      })
      onChanged()
    } catch (e) {
      toast.error(errorText(t, e))
      setBusy(false)
    }
  }
  return (
    <div className="space-y-3">
      <section aria-label={t("watch.tl.label")}>
        {q.isPending ? (
          <div className="space-y-2" aria-busy="true">
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-4 w-1/2" />
          </div>
        ) : q.isError ? (
          <p className="text-xs text-destructive">
            {errorText(t, q.error)}{" "}
            <button type="button" onClick={() => void q.refetch()} className="font-medium underline underline-offset-2">
              {t("errors.retry")}
            </button>
          </p>
        ) : (
          <ol className="relative space-y-3 border-l pl-4">
            {q.data.events.map((e, i) => (
              <TimelineEntry key={`${e.what}-${e.at}-${i}`} e={e} />
            ))}
            {q.data.events.length === 0 && <li className="text-xs text-muted-foreground">{t("watch.tl.empty")}</li>}
            <li className="relative text-xs">
              <Dot icon={Eye} tone="--muted-foreground" />
              <span className="font-medium">{t("watch.tl.since")}</span> · <Ts at={q.data.since} rel className="text-muted-foreground" />
            </li>
          </ol>
        )}
      </section>
      <div className="flex flex-wrap items-center gap-2 border-t pt-3">
        <Button variant="outline" size="sm" asChild>
          <Link to={`/?q=${encodeURIComponent(w.cve)}`}>
            <Newspaper /> {q.data ? t("watch.storiesN", { count: q.data.stories }) : t("watch.storiesPlain")}
          </Link>
        </Button>
        {w.advisory && (
          <Button variant="outline" size="sm" asChild>
            <a href={w.advisory.url} target="_blank" rel="noopener noreferrer" title={`${ADVISORY_SOURCE_LABEL[w.advisory.source] ?? w.advisory.source} · ${w.advisory.ident}`}>
              <ExternalLink /> {t("watch.openAdvisory")}
            </a>
          </Button>
        )}
        <MuteButton targets={[{ kind: "cve", key: w.cve, label: w.cve }]} size="sm" />
        <Button variant="ghost" size="sm" className="ml-auto text-destructive" disabled={busy} onClick={() => void remove()}>
          {busy ? <Loader2 className="animate-spin" /> : <Trash2 />} {t("watch.unwatchButton")}
        </Button>
      </div>
    </div>
  )
}

function Dot({ icon: Icon, tone }: { icon: React.ElementType; tone: string }) {
  return (
    <span
      aria-hidden
      className="absolute top-0 -left-[1.6rem] flex size-5 items-center justify-center rounded-full border bg-card"
      style={{ color: `var(${tone})`, borderColor: `color-mix(in oklch, var(${tone}) 35%, transparent)` }}
    >
      <Icon className="size-3" />
    </span>
  )
}

function TimelineEntry({ e }: { e: WatchEvent }) {
  const { t, i18n } = useTranslation()
  const pct = (v: number | null | undefined) => (v === null || v === undefined ? "–" : `${epssPercent(v, i18n.language)} %`)
  let icon: React.ElementType = ShieldCheck
  let tone = "--success"
  let text: React.ReactNode
  let sub: React.ReactNode = null
  if (e.what === "fix") {
    text = t("watch.tl.fix", { fixed: e.fixed.join(", ") }) + (e.more > 0 ? ` ${t("watch.tl.fixMore", { count: e.more })}` : "")
    if (e.by.length) sub = t("watch.tl.fixBy", { by: e.by.map((b) => `${ADVISORY_SOURCE_LABEL[b.source] ?? b.source} ${b.ident}`).join(", ") })
  } else if (e.what === "kev") {
    icon = Flame
    tone = "--sev-critical"
    text = (
      <>
        {t("watch.tl.kevBefore")} <Term k="kev">CISA KEV</Term> {t("watch.tl.kevAfter")}
      </>
    )
    sub = [e.due && t("watch.tl.kevDue", { date: fmtDay(e.due) }), e.ransomware && t("watch.ransomware")].filter(Boolean).join(" · ") || null
  } else if (e.what === "epss") {
    icon = TrendingUp
    tone = e.score !== null ? epssTone(e.score) : "--sev-high"
    const high = e.reasons.includes("high")
    text = (
      <>
        <Term k="epss">EPSS</Term> {high ? t("watch.tl.epssHigh", { pct: e.percentile !== null ? Math.floor(e.percentile * 100) : "–" }) : t("watch.tl.epssRose")}
      </>
    )
    sub = e.from !== null ? t("watch.tl.epssFrom", { from: pct(e.from), score: pct(e.score) }) : t("watch.tl.epssNow", { score: pct(e.score) })
  } else {
    icon = Ban
    tone = "--warning"
    text = t("watch.tl.withdrawn", { ident: e.ident || "?" })
    sub = e.source ? (ADVISORY_SOURCE_LABEL[e.source] ?? e.source) : null
  }
  return (
    <li className="relative text-xs">
      <Dot icon={icon} tone={tone} />
      <p className="leading-snug">
        <span className="font-medium [overflow-wrap:anywhere]">{text}</span> · <Ts at={e.at} rel className="text-muted-foreground" />
      </p>
      {sub && <p className="mt-0.5 text-muted-foreground [overflow-wrap:anywhere]">{sub}</p>}
    </li>
  )
}

/** No CVE yet: an invitation – what the star does, and the field right here. */
function WatchEmpty({ data, onAdded }: { data: WatchList; onAdded: () => void }) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-col items-center gap-4 rounded-xl border border-dashed px-6 py-12 text-center">
      <span aria-hidden className="inline-flex items-center gap-1.5 rounded-lg border bg-card px-2.5 py-1.5 font-mono text-[12.5px] shadow-xs">
        CVE-2026-12345
        <span className="rounded bg-warning/15 p-0.5 text-warning">
          <Star className="size-3.5 fill-current" />
        </span>
      </span>
      <div className="max-w-md space-y-1">
        <p className="font-medium">{t("watch.emptyTitle")}</p>
        <p className="text-sm text-muted-foreground">{t("watch.emptyLead")}</p>
      </div>
      <AddCve data={data} onAdded={onAdded} />
    </div>
  )
}

// ---------------------------------------------------------------- Kalender (iCal)

/** Settings → Benachrichtigungen → "Kalender": a secret address for Outlook & Co. – the end of support of the versions
 * of the person's products as all-day events, reminders 90 and 30 days before (app/calendar_feed.py). */
export function CalendarCard() {
  const { t } = useTranslation()
  const q = useCalendar()
  return (
    <SettingsCard
      title={t("cal.title")}
      description={
        <>
          {t("cal.descBefore")} <Term k="ical">iCal</Term>
          {t("cal.descAfter")}
        </>
      }
      actions={<HelpLink chapter="benachrichtigungen" section="kalender-ical" topic={t("cal.title")} />}
    >
      {!q.data ? <SheetLoading error={q.error} onRetry={() => void q.refetch()} /> : <CalendarBody />}
    </SettingsCard>
  )
}

function CalendarBody() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const d = useCalendar().data!
  const [url, setUrl] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const make = async () => {
    if (d.active && !(await confirmAction({ title: t("cal.renewAsk"), text: t("cal.renewText"), confirm: t("cal.renew"), destructive: false }))) return
    setBusy(true)
    try {
      const r = await makeCalendar()
      setUrl(r.url)
      void qc.invalidateQueries({ queryKey: CALENDAR_KEY })
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const remove = async () => {
    if (!(await confirmAction({ title: t("cal.deleteAsk"), text: t("cal.deleteText"), confirm: t("cal.delete") }))) return
    setBusy(true)
    try {
      await deleteCalendar()
      setUrl(null)
      toast.success(t("cal.deleted"))
      void qc.invalidateQueries({ queryKey: CALENDAR_KEY })
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const scope = d.scope === "all" ? t("cal.scopeAll") : d.teams_on ? t("cal.scopeTeams") : t("cal.scopeTeamsOff")
  return (
    <>
      <SheetBody>
        <p className="flex items-start gap-2 rounded-lg bg-muted/60 p-3 text-xs leading-relaxed text-muted-foreground">
          <CalendarDays className="mt-0.5 size-4 shrink-0" />
          <span>
            {scope} {t("cal.entries", { count: d.entries })} {t("cal.content")}
          </span>
        </p>
        {url ? (
          <div className="space-y-2 rounded-lg border border-warning/40 bg-warning/10 p-3" role="status">
            <Field label={t("cal.url")} hint={t("cal.onceHint")}>
              <div className="flex gap-2">
                <Input value={url} readOnly onFocus={(e) => e.currentTarget.select()} className="font-mono text-xs" aria-label={t("cal.url")} />
                <Button variant="outline" size="icon" onClick={() => void copyWithToast(url)} aria-label={t("common.copy")} title={t("common.copy")}>
                  <Copy />
                </Button>
              </div>
            </Field>
            <p className="text-xs">
              <a href={webcalUrl(url)} className="underline underline-offset-2">
                {t("cal.openWebcal")}
              </a>
            </p>
          </div>
        ) : d.active ? (
          <p className="text-xs text-muted-foreground">
            {t("cal.activeSince")} <Ts at={d.created_at!} rel />
            {" · "}
            {d.last_used_at ? (
              <>
                {t("cal.lastUsed")} <Ts at={d.last_used_at} rel />
              </>
            ) : (
              t("cal.neverUsed")
            )}
          </p>
        ) : (
          <EmptyState icon={CalendarPlus} title={t("cal.none")} text={t("cal.noneText")} />
        )}
        <section aria-labelledby="cal-outlook" className="space-y-1 text-xs leading-relaxed text-muted-foreground">
          <p id="cal-outlook" className="text-sm font-medium text-foreground">
            {t("cal.outlook")}
          </p>
          <ol className="list-decimal space-y-0.5 pl-5">
            <li>{t("cal.outlook1")}</li>
            <li>{t("cal.outlook2")}</li>
            <li>{t("cal.outlook3")}</li>
          </ol>
          <p>{t("cal.secret")}</p>
        </section>
      </SheetBody>
      <SheetActions>
        {d.active ? (
          <Button variant="ghost" className="text-destructive" disabled={busy} onClick={() => void remove()}>
            <Trash2 /> {t("cal.delete")}
          </Button>
        ) : (
          <span />
        )}
        <Button onClick={() => void make()} disabled={busy}>
          {busy ? <Loader2 className="animate-spin" /> : d.active ? <RefreshCw /> : <CalendarPlus />} {d.active ? t("cal.renew") : t("cal.make")}
        </Button>
      </SheetActions>
    </>
  )
}
