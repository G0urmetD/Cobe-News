import { useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link, useSearchParams } from "react-router"
import { Activity, Loader2, Plug, Settings2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Sheet, SheetClose, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill } from "@/components/cobe/badges"
import { Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Explained } from "@/components/cobe/explained"
import { DrawerSkeleton, QueryError } from "@/components/cobe/query-state"
import { SubTabs } from "@/components/cobe/sub-tabs"
import { Ts } from "@/components/cobe/time"
import { fmtBytes } from "@/lib/backup"
import { restoreFocus } from "@/lib/focus"
import { useMinute } from "@/lib/format"
import {
  errorLabel,
  filterRows,
  fmtMs,
  type HealthDetail,
  type HealthFetch,
  type HealthKind,
  type HealthRow,
  type HealthState,
  isProblem,
  parseSourceParam,
  sortRows,
  sparkLabel,
  sparkPoints,
  STATE_COLOR,
  STATE_ORDER,
  useSourceHealth,
  useSourceHealthDetail,
} from "@/lib/source-health"
import { cn } from "@/lib/utils"
import { NewsCard } from "@/pages/settings-news"
import { Loading } from "@/pages/settings-shared"
import { VendorCard } from "@/pages/settings-vendor"

/** Settings → Integrationen: the sources (tiles of news and Vendor News) | their health – sub-tabs, `?view=health`. */
export function IntegrationsSettings() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const view = params.get("view") === "health" ? "health" : "sources"
  const health = useSourceHealth()
  const problems = health.data ? health.data.counts.dead + health.data.counts.disturbed : 0
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SubTabs
          parts={[
            { key: "sources" as const, icon: Plug, label: t("health.tab.sources") },
            { key: "health" as const, icon: Activity, label: t("health.tab.health"), alert: problems > 0 },
          ]}
          active={view}
          to={(k) => (k === "health" ? "/settings/integrations?view=health" : "/settings/integrations")}
          label={t("settings.nav.integrations")}
        />
        <HelpLink
          chapter="integrationen"
          section={view === "health" ? "gesundheit" : "ueberblick"}
          topic={view === "health" ? t("health.tab.health") : t("settings.nav.integrations")}
        />
      </div>
      {view === "health" ? (
        <HealthPane />
      ) : (
        // tiles as on the integrations page – the news and Vendor News
        <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
          <NewsCard />
          <VendorCard />
        </div>
      )}
    </div>
  )
}

// "nur Probleme", per browser – a convenience (blocked storage: everything is shown)
const ONLY_KEY = "cobe-news.health.only"
function readOnly(): boolean {
  try {
    return localStorage.getItem(ONLY_KEY) === "1"
  } catch {
    return false
  }
}
function saveOnly(v: boolean) {
  try {
    localStorage.setItem(ONLY_KEY, v ? "1" : "0")
  } catch {
    // not remembered – nothing else depends on it
  }
}

// the table's columns from lg on; below, every line is a card with labelled values
const COLS = "lg:grid-cols-[minmax(0,1.3fr)_10rem_7rem_minmax(0,1fr)_6.5rem_5.5rem]"

function HealthPane() {
  const { t } = useTranslation()
  const q = useSourceHealth()
  const [params, setParams] = useSearchParams()
  const [only, setOnly] = useState(readOnly)
  const [showOff, setShowOff] = useState(false)
  // the line that opened the drawer: the focus goes back to it when the drawer closes (no Radix trigger knows it)
  const opener = useRef<Element | null>(null)
  const sel = parseSourceParam(params.get("source"))
  const openRow = (r: HealthRow, el: Element | null) => {
    opener.current = el
    setParams((p) => {
      const n = new URLSearchParams(p)
      n.set("source", `${r.kind}:${r.key}`)
      return n
    })
  }
  const close = () =>
    setParams(
      (p) => {
        const n = new URLSearchParams(p)
        n.delete("source")
        return n
      },
      { replace: true },
    )
  const toggle = (
    <div className="flex items-center gap-2">
      <Switch
        id="health-only"
        checked={only}
        onCheckedChange={(v) => {
          setOnly(v)
          saveOnly(v)
        }}
        aria-describedby="health-only-hint"
      />
      <Label htmlFor="health-only" className="text-sm">
        {t("health.onlyProblems")}
      </Label>
      <span id="health-only-hint" className="sr-only">
        {t("health.onlyProblemsHint")}
      </span>
    </div>
  )
  const all = q.data ? sortRows(q.data.items) : []
  const listed = filterRows(all, only)
  // switched-off sources say little – folded, unless asked for (about 40 built-in feeds are off by default)
  const offCount = listed.filter((r) => r.state === "off").length
  const rows = showOff ? listed : listed.filter((r) => r.state !== "off")
  const anyOn = all.some((r) => r.enabled)
  return (
    <>
      <Section title={t("health.title")} description={t("health.desc")} actions={toggle}>
        {!q.data ? (
          <div className="p-5">
            <Loading error={q.error} onRetry={q.refetch} />
          </div>
        ) : (
          <>
            <Summary counts={q.data.counts} />
            {!anyOn ? (
              <p className="px-5 py-6 text-sm text-muted-foreground">{t("health.empty")}</p>
            ) : listed.length === 0 ? (
              <p className="px-5 py-6 text-sm text-muted-foreground">{t("health.emptyProblems")}</p>
            ) : (
              <ul className="divide-y border-t">
                <li className={cn("hidden gap-3 px-4 py-2 text-xs text-muted-foreground lg:grid", COLS)}>
                  <span>{t("health.col.source")}</span>
                  <span>
                    <Explained label={t("health.col.state")} text={t("health.statesHint")} />
                  </span>
                  <span>{t("health.col.lastOk")}</span>
                  <span>{t("health.col.lastError")}</span>
                  <span>
                    <Explained label={t("health.col.weeks")} text={t("health.colHint.weeks")} />
                  </span>
                  <span className="text-right">
                    <Explained label={t("health.col.avgMs")} text={t("health.colHint.avgMs")} />
                  </span>
                </li>
                {rows.map((r) => (
                  <HealthLine key={`${r.kind}:${r.key}`} r={r} onOpen={(el) => openRow(r, el)} />
                ))}
              </ul>
            )}
            {anyOn && offCount > 0 && (
              <div className="border-t px-3 py-2">
                <Button variant="ghost" size="sm" onClick={() => setShowOff(!showOff)}>
                  {showOff ? t("health.hideOff") : t("health.showOff", { count: offCount })}
                </Button>
              </div>
            )}
          </>
        )}
      </Section>
      <HealthDrawer
        sel={sel}
        onClose={close}
        onClosed={() => {
          restoreFocus(opener.current)
          opener.current = null
        }}
      />
    </>
  )
}

/** "1 tot · 2 gestört · 3 langsam · 20 gesund" – each with its meaning on hover and focus. */
function Summary({ counts }: { counts: Record<HealthState, number> }) {
  const { t } = useTranslation()
  const shown = STATE_ORDER.filter((s) => counts[s] > 0)
  if (shown.length === 0) return null
  return (
    <div className="flex flex-wrap gap-1.5 px-5 py-3">
      {shown.map((s) => (
        <StatePill key={s} state={s} tip>
          <span className="tabular-nums">{counts[s]}</span> {t(`health.state.${s}`)}
        </StatePill>
      ))}
    </div>
  )
}

/** A state as a chip (words, never colour alone); `tip`: its meaning as a tooltip on hover and keyboard focus. */
function StatePill({ state, tip = false, children }: { state: HealthState; tip?: boolean; children?: React.ReactNode }) {
  const { t } = useTranslation()
  const pill = (
    <Pill color={STATE_COLOR[state]} dot title={tip ? undefined : t(`health.stateHint.${state}`)}>
      {children ?? t(`health.state.${state}`)}
    </Pill>
  )
  if (!tip) return pill
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="cursor-help rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          {pill}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">{t(`health.stateHint.${state}`)}</TooltipContent>
    </Tooltip>
  )
}

/** Where a line belongs: the news category, or Vendor News with its number of queries. */
function subLine(r: HealthRow, t: (k: string, o?: Record<string, unknown>) => string): string {
  if (r.kind === "vendor" || r.kind === "structured") {
    const m = r.members
    const queries = !m ? "" : m.problems ? t("health.membersProblems", { problems: m.problems, total: m.active }) : t("health.members", { count: m.active || m.total })
    return [t(r.kind === "vendor" ? "health.vendor" : "health.structured"), queries].filter(Boolean).join(" · ")
  }
  return [t(`settings.news.cat.${r.group}`, { defaultValue: r.group }), r.host].filter(Boolean).join(" · ")
}

function Cell({ label, className, children }: { label: string; className?: string; children: React.ReactNode }) {
  return (
    <span className={cn("flex min-w-0 flex-col gap-0.5 lg:block", className)}>
      <span className="text-xs text-muted-foreground lg:hidden">{label}</span>
      <span className="block min-w-0 truncate">{children}</span>
    </span>
  )
}

function HealthLine({ r, onOpen }: { r: HealthRow; onOpen: (el: Element) => void }) {
  const { t, i18n } = useTranslation()
  const last = r.weeks[r.weeks.length - 1]
  const err = r.error ?? r.last_error
  return (
    <li>
      <button
        type="button"
        onClick={(e) => onOpen(e.currentTarget)}
        className={cn(
          "grid w-full gap-x-3 gap-y-2 px-4 py-3 text-left text-sm outline-none hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:ring-inset lg:items-center",
          COLS,
          !r.enabled && "text-muted-foreground",
        )}
      >
        {/* name and state side by side on a phone; two cells of the table from lg on */}
        <span className="flex min-w-0 items-start justify-between gap-2 lg:contents">
          <span className="min-w-0">
            <span className="block truncate font-medium">{r.name}</span>
            <span className="block truncate text-xs text-muted-foreground">{subLine(r, t)}</span>
          </span>
          <span className="flex shrink-0 flex-col items-end gap-0.5 lg:items-start">
            <StatePill state={r.state} />
          </span>
        </span>
        <span className="grid grid-cols-2 gap-x-3 gap-y-2 sm:grid-cols-4 lg:contents">
          <Cell label={t("health.col.lastOk")}>{r.last_ok_at ? <Ts at={r.last_ok_at} rel /> : <span className="text-muted-foreground">{t("health.noSuccess")}</span>}</Cell>
          <Cell label={t("health.col.lastError")}>
            {err ? (
              <>
                <span className={cn("block truncate", r.error ? "text-warning" : "text-muted-foreground")}>{errorLabel(err, t)}</span>
                {err.at && (
                  <span className="block truncate text-xs text-muted-foreground">
                    <Ts at={err.at} rel />
                  </span>
                )}
              </>
            ) : (
              <span className="text-muted-foreground">{t("health.noError")}</span>
            )}
          </Cell>
          <Cell label={t("health.col.weeks")}>
            <span className="inline-flex items-center gap-2">
              <Sparkline weeks={r.weeks} />
              <span className="text-xs tabular-nums">{last ?? "–"}</span>
            </span>
          </Cell>
          <Cell label={t("health.col.avgMs")} className="lg:text-right">
            <span className="tabular-nums">{fmtMs(r.avg_ms, i18n.language)}</span>
          </Cell>
        </span>
      </button>
    </li>
  )
}

/** Items per week as a small line (tokens only); a week without a fetch is a hollow dot, not a 0. */
export function Sparkline({ weeks, width = 56, height = 18, className }: { weeks: (number | null)[]; width?: number; height?: number; className?: string }) {
  const { t, i18n } = useTranslation()
  const pts = sparkPoints(weeks, width, height)
  const label = sparkLabel(weeks, t, i18n.language)
  const segments: string[] = []
  let run: string[] = []
  for (const p of pts) {
    if (p.known) run.push(`${p.x},${p.y}`)
    else {
      if (run.length > 1) segments.push(run.join(" "))
      run = []
    }
  }
  if (run.length > 1) segments.push(run.join(" "))
  return (
    <svg role="img" aria-label={label} viewBox={`0 0 ${width} ${height}`} width={width} height={height} className={cn("shrink-0 overflow-visible text-primary", className)}>
      <title>{label}</title>
      {segments.map((s) => (
        <polyline key={s} points={s} fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
      ))}
      {pts.map((p, i) =>
        p.known ? (
          <circle key={i} cx={p.x} cy={p.y} r={1.75} fill="currentColor" />
        ) : (
          <circle key={i} cx={p.x} cy={height - 2} r={1.5} fill="none" stroke="var(--muted-foreground)" strokeWidth={1} />
        ),
      )}
    </svg>
  )
}

// ---------------------------------------------------------------- the drawer

function HealthDrawer({ sel, onClose, onClosed }: { sel: { kind: HealthKind; key: string } | null; onClose: () => void; onClosed: () => void }) {
  const { t } = useTranslation()
  // what it shows stays while it slides out
  const [shown, setShown] = useState(sel)
  if (sel && (sel.kind !== shown?.kind || sel.key !== shown?.key)) setShown(sel)
  const q = useSourceHealthDetail(shown?.kind ?? null, shown?.key ?? null)
  const d = q.data && q.data.item.kind === shown?.kind && q.data.item.key === shown?.key ? q.data : undefined
  return (
    <Sheet open={!!sel} onOpenChange={(o) => !o && onClose()}>
      <SheetContent
        className="w-full gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-2xl"
        onCloseAutoFocus={(e) => {
          e.preventDefault()
          onClosed()
        }}
      >
        <SheetHeader className="border-b">
          {d ? (
            <>
              <p className="pr-8 text-xs text-muted-foreground">{subLine(d.item, t)}</p>
              <SheetTitle className="text-lg leading-snug">{d.item.name}</SheetTitle>
              <SheetDescription className={cn("font-mono text-[11px] break-all", !d.item.url && "sr-only")}>{d.item.url || t("health.title")}</SheetDescription>
              <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-muted-foreground">
                <StatePill state={d.item.state} tip />
                {d.item.since && (
                  <span>
                    {t("health.sinceWord")} <Ts at={d.item.since} rel />
                  </span>
                )}
              </div>
            </>
          ) : (
            <SheetTitle className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" /> {t("health.loading")}
            </SheetTitle>
          )}
        </SheetHeader>
        <div className="min-h-0 flex-1 space-y-5 overflow-y-auto p-5 text-sm">
          {q.isError && !d && <QueryError error={q.error} onRetry={() => void q.refetch()} />}
          {!d && !q.isError && <DrawerSkeleton label={t("health.loading")} />}
          {d && <DrawerBody d={d} />}
        </div>
        <SheetFooter className="flex-row flex-wrap items-center justify-between gap-2 border-t bg-popover">
          {d ? (
            <Button variant="outline" asChild>
              <Link to={d.item.kind === "structured" ? "/settings/integrations?vendor=sources#vendor" : `/settings/integrations#${d.item.kind === "vendor" ? "vendor" : "news"}`}>
                <Settings2 /> {t("health.d.setup")}
              </Link>
            </Button>
          ) : (
            <span />
          )}
          <SheetClose asChild>
            <Button variant="ghost">{t("health.d.close")}</Button>
          </SheetClose>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

function Fact({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 min-w-0 break-words">{children}</dd>
    </div>
  )
}

function DrawerBody({ d }: { d: HealthDetail }) {
  const { t, i18n } = useTranslation()
  const minute = useMinute()
  const r = d.item
  const lang = i18n.language
  const nextAhead = r.next_fetch_at && new Date(r.next_fetch_at).getTime() > minute * 60_000
  const vendor = r.kind === "vendor" || r.kind === "structured"
  const recentKeys = new Set(d.fetches.map((f) => `${f.key}|${f.at}`))
  const olderErrors = d.errors.filter((e) => !recentKeys.has(`${e.key}|${e.at}`))
  return (
    <>
      {/* 1. why it is in this state */}
      {r.reasons.length > 0 && (
        <div
          className={cn(
            "rounded-lg border p-3 text-xs",
            r.state === "dead" ? "border-sev-critical/40 bg-sev-critical/10" : r.state === "disturbed" ? "border-warning/40 bg-warning/10" : "bg-muted/60",
          )}
        >
          <p className="font-medium">{t("health.d.why")}</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-4">
            {r.reasons.map((x) => (
              <li key={x}>{t(`health.reason.${x}`, { defaultValue: x })}</li>
            ))}
          </ul>
        </div>
      )}

      {/* 2. the facts */}
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3">
        <Fact label={t("health.d.lastOk")}>{r.last_ok_at ? <Ts at={r.last_ok_at} zone /> : t("health.noSuccess")}</Fact>
        <Fact label={t(r.error ? "health.d.currentError" : "health.d.lastError")}>
          {r.error || r.last_error ? (
            <span className={cn(r.error && "text-warning")}>
              {errorLabel(r.error ?? r.last_error, t)}
              {(r.error ?? r.last_error)?.at && (
                <span className="text-muted-foreground">
                  {" · "}
                  <Ts at={(r.error ?? r.last_error)!.at!} rel />
                </span>
              )}
            </span>
          ) : (
            t("health.noError")
          )}
        </Fact>
        {r.failures > 0 && (
          <Fact label={t("health.d.failures")}>
            <span className="tabular-nums">{r.failures}</span>
          </Fact>
        )}
        {nextAhead && (
          <Fact label={t("health.d.nextTry")}>
            <Ts at={r.next_fetch_at!} rel />
            {r.paused && <span className="text-muted-foreground"> · {t("health.d.paused")}</span>}
          </Fact>
        )}
        <Fact label={<Explained label={t("health.d.conditional")} text={t("health.d.conditionalHint")} />}>
          {r.conditional ? (r.not_modified_7d > 0 ? t("health.d.conditionalYesN", { count: r.not_modified_7d }) : t("health.d.conditionalYes")) : t("health.d.conditionalNo")}
        </Fact>
        <Fact label={t("health.d.avgMs")}>
          <span className="tabular-nums">{fmtMs(r.avg_ms, lang)}</span>
        </Fact>
        <Fact label={t("health.d.avgBytes")}>
          <span className="tabular-nums">{r.avg_bytes === null ? "–" : fmtBytes(r.avg_bytes, lang)}</span>
        </Fact>
        <Fact label={t("health.d.fetches")}>
          <span className="tabular-nums">{r.fetches_7d}</span>
        </Fact>
        <Fact label={t("health.d.timeouts")}>
          <span className="tabular-nums">{r.timeouts_7d}</span>
        </Fact>
        <Fact label={<Explained label={t("health.d.parseErrors")} text={t("health.d.parseErrorsHint")} />}>
          <span className="tabular-nums">{r.parse_errors_7d}</span>
        </Fact>
      </dl>

      {/* 3. new items per week */}
      <section className="space-y-2">
        <h3 className="text-xs font-medium text-muted-foreground">
          <Explained label={t("health.d.weeks")} text={t("health.colHint.weeks")} />
        </h3>
        <div className="flex flex-wrap items-end gap-4">
          <Sparkline weeks={r.weeks} width={120} height={32} />
          <ol className="grid flex-1 grid-cols-4 gap-2 text-center">
            {r.weeks.map((n, i) => (
              <li key={i} className="rounded-md bg-muted/50 px-1 py-1.5">
                <span className="block text-sm font-medium tabular-nums">{n ?? "–"}</span>
                <span className="block text-[10px] text-muted-foreground">
                  {i === r.weeks.length - 1 ? t("health.d.thisWeek") : t("health.d.weekN", { count: r.weeks.length - 1 - i })}
                </span>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* 4. a Vendor News family: its queries */}
      {vendor && d.members.length > 0 && <Members members={d.members} />}

      {/* 5. the history */}
      <section className="space-y-2">
        <h3 className="text-xs font-medium text-muted-foreground">{t("health.d.recent")}</h3>
        {d.fetches.length === 0 ? <p className="text-xs text-muted-foreground">{t("health.d.noFetches")}</p> : <FetchList rows={d.fetches} vendor={vendor} />}
      </section>
      {olderErrors.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-xs font-medium text-muted-foreground">{t("health.d.errors")}</h3>
          <FetchList rows={olderErrors} vendor={vendor} />
        </section>
      )}
      {d.events.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-xs font-medium text-muted-foreground">{t("health.d.events")}</h3>
          <ul className="space-y-1.5 text-xs">
            {d.events.map((e) => (
              <li key={e.at + e.state} className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <Ts at={e.at} className="text-muted-foreground tabular-nums" />
                {e.prev ? (
                  <>
                    <StatePill state={e.prev} />
                    <span aria-hidden>→</span>
                  </>
                ) : (
                  <span className="text-muted-foreground">{t("health.d.eventFirst")}:</span>
                )}
                <StatePill state={e.state} />
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  )
}

const FETCH_COLS = "sm:grid-cols-[9.5rem_minmax(0,1fr)_4.5rem_4.5rem_3rem]"
const FETCH_COLS_VENDOR = "sm:grid-cols-[9.5rem_minmax(0,1fr)_4.5rem_4.5rem_3rem_minmax(0,1fr)]"

function FetchList({ rows, vendor }: { rows: HealthFetch[]; vendor: boolean }) {
  const { t, i18n } = useTranslation()
  const cols = vendor ? FETCH_COLS_VENDOR : FETCH_COLS
  return (
    <ul className="divide-y rounded-lg border text-xs">
      <li className={cn("hidden gap-3 px-3 py-2 text-muted-foreground sm:grid", cols)} aria-hidden>
        <span>{t("health.d.col.at")}</span>
        <span>{t("health.d.col.status")}</span>
        <span className="text-right">{t("health.d.col.duration")}</span>
        <span className="text-right">{t("health.d.col.size")}</span>
        <span className="text-right">{t("health.d.col.items")}</span>
        {vendor && <span>{t("health.d.col.query")}</span>}
      </li>
      {rows.map((f, i) => (
        <li key={`${f.key}|${f.at}|${i}`} className={cn("grid grid-cols-2 gap-x-3 gap-y-1 px-3 py-2 sm:items-center", cols)}>
          <span className="col-span-2 tabular-nums sm:col-span-1">
            <Ts at={f.at} />
          </span>
          <span className={cn("col-span-2 min-w-0 sm:col-span-1", f.ok ? "text-success" : "text-warning")}>
            {f.ok
              ? f.not_modified
                ? t("health.d.notModified")
                : `${t("health.d.ok")}${f.status ? ` (${f.status})` : ""}`
              : errorLabel({ category: f.error, status: f.status }, t)}
          </span>
          <span className="flex gap-1.5 tabular-nums sm:justify-end">
            <span className="text-muted-foreground sm:hidden">{t("health.d.col.duration")}:</span>
            {fmtMs(f.duration_ms, i18n.language)}
          </span>
          <span className="flex gap-1.5 tabular-nums sm:justify-end">
            <span className="text-muted-foreground sm:hidden">{t("health.d.col.size")}:</span>
            {f.not_modified || !f.ok ? "–" : fmtBytes(f.bytes, i18n.language)}
          </span>
          <span className="flex gap-1.5 tabular-nums sm:justify-end">
            <span className="text-muted-foreground sm:hidden">{t("health.d.col.items")}:</span>
            {f.items}
          </span>
          {vendor && (
            <span className="col-span-2 min-w-0 truncate font-mono text-[11px] text-muted-foreground sm:col-span-1" title={f.key}>
              {f.key}
            </span>
          )}
        </li>
      ))}
    </ul>
  )
}

const MEMBERS_SHOWN = 8

/** A family's queries one by one – problems always shown, the healthy rest folded. */
function Members({ members }: { members: HealthRow[] }) {
  const { t } = useTranslation()
  const [all, setAll] = useState(false)
  const on = members.filter((m) => m.enabled)
  const off = members.length - on.length
  const bad = on.filter((m) => isProblem(m.state) || m.state === "slow")
  const rest = on.filter((m) => !bad.includes(m))
  const visible = all ? [...bad, ...rest] : [...bad, ...rest.slice(0, Math.max(0, MEMBERS_SHOWN - bad.length))]
  const hidden = bad.length + rest.length - visible.length
  return (
    <section className="space-y-2">
      <h3 className="text-xs font-medium text-muted-foreground">
        <Explained label={`${t("health.d.members")} (${on.length})`} text={t("health.d.membersHint")} />
      </h3>
      <ul className="divide-y rounded-lg border text-xs">
        {visible.map((m) => (
          <li key={m.key} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
            <span className="min-w-0 flex-1 truncate font-mono text-[11px]" title={m.key}>
              {m.key}
            </span>
            <StatePill state={m.state} />
            <span className="text-muted-foreground">{m.error ? errorLabel(m.error, t) : m.last_ok_at ? <Ts at={m.last_ok_at} rel /> : t("health.noSuccess")}</span>
          </li>
        ))}
      </ul>
      {hidden > 0 && (
        <Button variant="ghost" size="sm" onClick={() => setAll(true)}>
          {t("health.d.showHealthy", { count: hidden })}
        </Button>
      )}
      {off > 0 && (
        <p className="text-xs text-muted-foreground">
          <span className="tabular-nums">{off}</span> {t("health.state.off")}
        </p>
      )}
    </section>
  )
}
