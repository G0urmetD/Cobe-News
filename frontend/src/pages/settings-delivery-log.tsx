import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useQueryClient } from "@tanstack/react-query"
import { CheckCircle2, ChevronDown, History, Loader2, RotateCcw, ScrollText, UserRound, XCircle } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Pill } from "@/components/cobe/badges"
import { EmptyState, Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Explained } from "@/components/cobe/explained"
import { Ts } from "@/components/cobe/time"
import { api } from "@/lib/api"
import { type NotifyChannel, type SendResult, useChannels } from "@/lib/admin-api"
import { sendError } from "@/lib/channels"
import {
  DELIVERY_KINDS,
  type Delivery,
  type DeliveryAttempt,
  type DeliveryKind,
  type LogFilter,
  type LogWindow,
  OUTCOME_FILTERS,
  type OutcomeFilter,
  WINDOWS,
  channelHealth,
  itemsText,
  outcomeText,
  useDeliveryLog,
  whereText,
} from "@/lib/delivery-log"
import { errorText } from "@/lib/errors"
import { cn } from "@/lib/utils"
import { Loading } from "@/pages/settings-shared"

const TONE: Record<string, string> = { ok: "--success", warn: "--warning", bad: "--destructive", none: "--muted-foreground" }

/** The badge of a channel in the list: "Letzte Zustellung ok vor 3 Std." / "3 Fehler in 24 Std." */
export function HealthBadge({ c }: { c: NotifyChannel }) {
  const { t } = useTranslation()
  const h = channelHealth(c.delivery)
  if (h.tone === "none") return null
  return (
    <Pill color={TONE[h.tone]} dot title={t("dlog.health.title")}>
      {h.at ? (
        <>
          {t(h.key)} <Ts at={h.at} rel />
        </>
      ) : (
        t(h.key, { count: h.n })
      )}
    </Pill>
  )
}

// ---------------------------------------------------------------- the list

function Attempt({ a }: { a: DeliveryAttempt }) {
  const { t } = useTranslation()
  return (
    <li className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs">
      <span className="tabular text-muted-foreground">{t("dlog.attemptN", { n: a.attempt })}</span>
      <Ts at={a.at} className="tabular" />
      <span className={a.ok ? "text-success" : "text-destructive"}>{outcomeText(t, a)}</span>
      {a.manual && <Pill color="--primary">{t("dlog.manual")}</Pill>}
      {a.error && !a.ok && <span className="text-muted-foreground">{t(`notify.err.${a.error}`, { defaultValue: a.error })}</span>}
      {a.detail && <span className="font-mono [overflow-wrap:anywhere] text-muted-foreground">{a.detail}</span>}
      {a.duration_ms !== null && <span className="tabular text-muted-foreground">{t("dlog.ms", { n: a.duration_ms })}</span>}
    </li>
  )
}

function DeliveryRow({ d, showChannel }: { d: Delivery; showChannel: boolean }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const resend = async () => {
    if (busy) return // a double click sends once (the server refuses a second one as well)
    setBusy(true)
    try {
      const r = await api.post<SendResult>(`/api/admin/notify/log/${d.id}/resend`, {})
      if (r.ok) toast.success(t("dlog.resent", { name: d.channel_name }))
      else toast.error(sendError(t, r))
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
      void qc.invalidateQueries({ queryKey: ["admin", "delivery-log"] })
      void qc.invalidateQueries({ queryKey: ["admin", "channels"] })
    }
  }
  const Icon = d.ok ? CheckCircle2 : XCircle
  return (
    <li className="px-5 py-3">
      <div className="flex items-start gap-3">
        <Icon className={cn("mt-0.5 size-4 shrink-0", d.ok ? "text-success" : "text-destructive")} aria-label={d.ok ? t("dlog.outcome.ok") : t("dlog.failed")} />
        <div className="min-w-0 flex-1 space-y-1">
          <p className="text-sm font-medium [overflow-wrap:anywhere]">{itemsText(t, d)}</p>
          <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
            <Pill color="--muted-foreground">{t(`dlog.kind.${d.kind}`)}</Pill>
            {showChannel && <span className="font-medium text-foreground">{whereText(t, d)}</span>}
            <Ts at={d.at} rel />
            <span className={d.ok ? "text-success" : "text-destructive"}>{outcomeText(t, d)}</span>
            {d.attempts.length > 1 && <span>{t("dlog.attempts", { count: d.attempts.length })}</span>}
            {d.rules.length > 0 && <span>{t("dlog.byRules", { names: d.rules.map((r) => r.name).join(", ") })}</span>}
            {d.kind === "forward" && d.team_name && <span>{t("dlog.toTeam", { team: d.team_name })}</span>}
            {d.person && (
              <span className="inline-flex items-center gap-1">
                <UserRound className="size-3" />
                {d.person}
              </span>
            )}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {d.can_resend && (
            <Button variant="outline" size="sm" disabled={busy} onClick={() => void resend()} title={t("dlog.resendHint")}>
              {busy ? <Loader2 className="animate-spin" /> : <RotateCcw />} <span className="max-sm:sr-only">{t("dlog.resend")}</span>
            </Button>
          )}
          <Button variant="ghost" size="icon-sm" aria-expanded={open} aria-label={t("dlog.details")} title={t("dlog.details")} onClick={() => setOpen(!open)}>
            <ChevronDown className={open ? "rotate-180 transition-transform" : "transition-transform"} />
          </Button>
        </div>
      </div>
      {open && (
        <div className="mt-2 ml-7 space-y-2 rounded-lg border bg-muted/30 p-3">
          {d.items.length > 0 && (
            <ul className="space-y-0.5 text-xs">
              {d.items.map((x) => (
                <li key={`${x.kind}:${x.id}`} className="[overflow-wrap:anywhere]">
                  {x.severity && <span className="text-muted-foreground">[{t(`news.sev.${x.severity}`, { defaultValue: x.severity })}] </span>}
                  {x.title}
                  {!!x.topics?.length && <span className="text-muted-foreground"> · {x.topics.map((k) => t(`news.topic.${k}`, { defaultValue: k })).join(", ")}</span>}
                </li>
              ))}
              {d.total > d.items.length && <li className="text-muted-foreground">{t("dlog.moreItems", { count: d.total - d.items.length })}</li>}
            </ul>
          )}
          <ul className="space-y-1 border-t pt-2">
            {d.attempts.map((a) => (
              <Attempt key={a.id} a={a} />
            ))}
          </ul>
        </div>
      )}
    </li>
  )
}

function DeliveryList({ filter, showChannel }: { filter: LogFilter; showChannel: boolean }) {
  const { t } = useTranslation()
  const q = useDeliveryLog(filter)
  if (!q.data) return <Loading error={q.error} onRetry={() => void q.refetch()} />
  const rows = q.data.pages.flatMap((p) => p.deliveries)
  const personal = q.data.pages[0]?.personal
  return (
    <>
      {rows.length === 0 ? (
        <div className="p-5">
          <EmptyState icon={ScrollText} title={t("dlog.emptyTitle")} text={t("dlog.emptyText", { days: q.data.pages[0]?.retention_days ?? 30 })} />
        </div>
      ) : (
        <ul className={cn("divide-y", q.isPlaceholderData && "opacity-60")}>
          {rows.map((d) => (
            <DeliveryRow key={d.id} d={d} showChannel={showChannel} />
          ))}
        </ul>
      )}
      {q.hasNextPage && (
        <div className="border-t px-5 py-3">
          <Button variant="outline" size="sm" disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
            {q.isFetchingNextPage ? <Loader2 className="animate-spin" /> : <History />} {t("dlog.older")}
          </Button>
        </div>
      )}
      {personal && (
        <p className="border-t px-5 py-3 text-xs text-muted-foreground">
          <Explained label={t("dlog.personal", personal)} text={t("dlog.personalHint")} />
        </p>
      )}
    </>
  )
}

function FilterSelect<V extends string>({ value, onChange, options, label }: { value: V; onChange: (v: V) => void; options: { value: V; label: string }[]; label: string }) {
  return (
    <Select value={value} onValueChange={(x) => onChange(x as V)}>
      <SelectTrigger className="w-full" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent position="popper">
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

function Filters({ f, set, channels }: { f: LogFilter; set: (f: LogFilter) => void; channels?: NotifyChannel[] }) {
  const { t } = useTranslation()
  return (
    <div className={cn("grid grid-cols-2 gap-2 border-b px-5 py-3", channels ? "sm:grid-cols-4" : "sm:grid-cols-3")}>
      {channels && (
        <FilterSelect
          label={t("dlog.filter.channel")}
          value={f.channel ?? "all"}
          onChange={(v) => set({ ...f, channel: v === "all" ? undefined : v })}
          options={[{ value: "all", label: t("dlog.filter.allChannels") }, ...channels.map((c) => ({ value: c.id, label: c.name }))]}
        />
      )}
      <FilterSelect<OutcomeFilter>
        label={t("dlog.filter.outcome")}
        value={f.outcome}
        onChange={(v) => set({ ...f, outcome: v })}
        options={OUTCOME_FILTERS.map((o) => ({ value: o, label: t(`dlog.filter.o.${o}`) }))}
      />
      <FilterSelect<DeliveryKind | "all">
        label={t("dlog.filter.kind")}
        value={f.kind}
        onChange={(v) => set({ ...f, kind: v })}
        options={[{ value: "all" as const, label: t("dlog.filter.allKinds") }, ...DELIVERY_KINDS.map((k) => ({ value: k, label: t(`dlog.kind.${k}`) }))]}
      />
      <FilterSelect<string>
        label={t("dlog.filter.window")}
        value={String(f.hours)}
        onChange={(v) => set({ ...f, hours: Number(v) as LogWindow })}
        options={WINDOWS.map((h) => ({ value: String(h), label: t(`dlog.filter.w.${h}`) }))}
      />
    </div>
  )
}

/** Settings → Kanäle & Regeln → Zustellprotokoll: the deliveries of every channel, filtered. */
export function DeliveryLogPane() {
  const { t } = useTranslation()
  const channels = useChannels().data
  const [f, setF] = useState<LogFilter>({ outcome: "all", kind: "all", hours: 168 })
  return (
    <Section title={t("dlog.title")} description={t("dlog.hint")} actions={<HelpLink chapter="benachrichtigungen" section="zustellprotokoll" topic={t("dlog.title")} />}>
      <Filters f={f} set={setF} channels={channels ?? []} />
      <DeliveryList filter={f} showChannel />
    </Section>
  )
}

/** The log of one channel – the "Protokoll" tab of its drawer. */
export function ChannelLog({ channel }: { channel: NotifyChannel }) {
  const [f, setF] = useState<LogFilter>({ channel: channel.id, outcome: "all", kind: "all", hours: 168 })
  return (
    <div className="overflow-hidden rounded-lg border">
      <Filters f={f} set={setF} />
      <DeliveryList filter={f} showChannel={false} />
    </div>
  )
}
