import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { useQueryClient } from "@tanstack/react-query"
import { AlertTriangle, CalendarClock, Loader2, Search, UserRound, X } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Explained } from "@/components/cobe/explained"
import { Field, ToggleRow } from "@/components/cobe/form"
import { Term } from "@/components/cobe/glossary"
import { api } from "@/lib/api"
import {
  type AbsenceView,
  type Deputy,
  type PersonRefLite,
  type Schedule,
  URGENT_KINDS,
  type UrgentKind,
  WEEKDAYS,
  absenceValid,
  scheduleValid,
  showDate,
  today,
  useDeputies,
  validHm,
  zonesWith,
} from "@/lib/delivery-api"
import { errorText } from "@/lib/errors"
import { PERSONAL_KEY, PERSONAL_WAYS, type PersonalNotify, type PersonalWay, type Team, type TeamsSettings } from "@/lib/teams-api"
import { SaveBar, SheetActions, SheetBody } from "@/pages/settings-shared"
import { isoList } from "@/lib/bidi"

const refresh = (qc: ReturnType<typeof useQueryClient>) => void qc.invalidateQueries({ queryKey: PERSONAL_KEY })

/** A time zone from the offered list (the stored one too, when it is not among them). */
export function ZoneSelect({ value, onChange, id }: { value: string; onChange: (v: string) => void; id?: string }) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className="w-full sm:w-64" id={id}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent position="popper" className="max-h-72">
        {zonesWith(value).map((z) => (
          <SelectItem key={z} value={z}>
            {z.replace(/_/g, " ")}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

// ---------------------------------------------------------------- quiet hours, urgent, per way

/** "Ruhezeiten": a window (and the weekends) in the own zone, what passes at once, per way at once or collected. */
export function QuietPart({ initial }: { initial: PersonalNotify }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const first = initial.schedule
  const [v, setV] = useState<Schedule>(first)
  const [busy, setBusy] = useState(false)
  const dirty = JSON.stringify(v) !== JSON.stringify(first)
  const valid = scheduleValid(v)
  const save = async () => {
    setBusy(true)
    try {
      await api.put("/api/me/vendor-notify/schedule", v)
      toast.success(t("common.saved"))
      refresh(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const urgent = (k: UrgentKind, on: boolean) => setV({ ...v, urgent: URGENT_KINDS.filter((x) => (x === k ? on : v.urgent.includes(x))) })
  const daily = (w: PersonalWay, at: string | null) => setV({ ...v, daily: { ...v.daily, [w]: at } })
  const urgentLabel = (k: UrgentKind) =>
    k === "kev" ? (
      <>
        {t("delivery.urgent.kevBefore")} <Term k="kev">CISA KEV</Term>
      </>
    ) : k === "affected" ? (
      <Explained label={t("delivery.urgent.affected")} text={t("delivery.urgent.affectedExplain")} />
    ) : (
      t(`delivery.urgent.${k}`)
    )
  return (
    <>
      <SheetBody>
        <section className="rounded-lg border px-3" aria-label={t("delivery.quiet.title")}>
          <ToggleRow label={t("delivery.quiet.title")} description={t("delivery.quiet.hint")} checked={v.quiet} onCheckedChange={(x) => setV({ ...v, quiet: x })}>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={t("delivery.quiet.from")}>
                <Input type="time" step={60} value={v.from} onChange={(e) => setV({ ...v, from: e.target.value })} className="w-full sm:w-36" />
              </Field>
              <Field label={t("delivery.quiet.to")}>
                <Input type="time" step={60} value={v.to} onChange={(e) => setV({ ...v, to: e.target.value })} className="w-full sm:w-36" />
              </Field>
            </div>
            <ToggleRow
              label={t("delivery.quiet.weekends")}
              description={t("delivery.quiet.weekendsHint")}
              checked={v.weekends}
              onCheckedChange={(x) => setV({ ...v, weekends: x })}
              className="pb-0"
            />
            {v.quiet && v.from === v.to && !v.weekends && <p className="text-xs text-destructive">{t("errors.quiet_empty")}</p>}
          </ToggleRow>
          <div className="pb-3.5">
            <Field label={t("delivery.tz")} hint={t("delivery.tzHint")}>
              <ZoneSelect value={v.tz} onChange={(x) => setV({ ...v, tz: x })} />
            </Field>
          </div>
        </section>

        <section className="rounded-lg border px-3" aria-labelledby="delivery-urgent">
          <p id="delivery-urgent" className="pt-3 text-sm font-medium">
            <Explained label={t("delivery.urgent.title")} text={t("delivery.urgent.explain")} />
          </p>
          <div className="divide-y">
            {URGENT_KINDS.map((k) => (
              <ToggleRow key={k} label={urgentLabel(k)} description={t(`delivery.urgent.${k}Hint`)} checked={v.urgent.includes(k)} onCheckedChange={(x) => urgent(k, x)} />
            ))}
          </div>
        </section>

        <section className="rounded-lg border px-3" aria-labelledby="delivery-ways">
          <p id="delivery-ways" className="pt-3 text-sm font-medium">
            <Explained label={t("delivery.mode.title")} text={t("delivery.mode.explain")} />
          </p>
          <div className="divide-y">
            {PERSONAL_WAYS.map((w) => (
              <div key={w} className="flex flex-wrap items-end justify-between gap-3 py-3">
                <span className="text-sm">{t(`personal.${w}.title`)}</span>
                <span className="flex flex-wrap items-center gap-2">
                  <Select value={v.daily[w] ? "daily" : "now"} onValueChange={(x) => daily(w, x === "daily" ? (v.daily[w] ?? "08:00") : null)}>
                    <SelectTrigger className="w-44" aria-label={t(`personal.${w}.title`)}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent position="popper">
                      <SelectItem value="now">{t("delivery.mode.now")}</SelectItem>
                      <SelectItem value="daily">{t("delivery.mode.daily")}</SelectItem>
                    </SelectContent>
                  </Select>
                  {v.daily[w] !== null && (
                    <Input type="time" step={60} value={v.daily[w] ?? ""} onChange={(e) => daily(w, e.target.value)} className="w-28" aria-label={t("delivery.mode.at")} />
                  )}
                </span>
              </div>
            ))}
          </div>
          {!initial.allowed.desktop && !initial.allowed.email && !initial.allowed.teams && <p className="pb-3 text-xs text-muted-foreground">{t("delivery.mode.noWay")}</p>}
        </section>
      </SheetBody>
      <SheetActions>
        <span className="text-xs text-muted-foreground">{t("delivery.quiet.footer")}</span>
        <SaveBar busy={busy} dirty={dirty} disabled={!valid} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}

// ---------------------------------------------------------------- absence with a deputy

/** Pick one person from a server-side search (the server offers only who may stand in). */
export function DeputyPicker({ url, value, onChange }: { url: string; value: PersonRefLite | null; onChange: (v: PersonRefLite | null) => void }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState("")
  const [term, setTerm] = useState("")
  useEffect(() => {
    const id = setTimeout(() => setTerm(q.trim()), 250)
    return () => clearTimeout(id)
  }, [q])
  const found = useDeputies(url, term, open)
  const options = (found.data?.items ?? []).filter((d: Deputy) => d.id !== value?.id)
  return (
    <div className="flex flex-wrap items-center gap-2">
      {value ? (
        <span className="inline-flex max-w-full items-center gap-1 rounded-md bg-secondary py-0.5 pr-0.5 pl-2 text-sm font-medium">
          <UserRound className="size-3.5 text-muted-foreground" />
          <span className="min-w-0 truncate" title={value.username}>
            {value.display_name}
          </span>
          <Button variant="ghost" size="icon-xs" aria-label={t("delivery.absence.clearDeputy")} onClick={() => onChange(null)}>
            <X />
          </Button>
        </span>
      ) : (
        <span className="text-xs text-muted-foreground">{t("delivery.absence.noDeputy")}</span>
      )}
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button variant="outline" size="sm">
            <Search /> {value ? t("delivery.absence.otherDeputy") : t("delivery.absence.pickDeputy")}
          </Button>
        </PopoverTrigger>
        <PopoverContent align="start" collisionPadding={12} className="w-[min(22rem,calc(100vw-2rem))] p-2">
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("teams.members.search")} aria-label={t("teams.members.search")} className="pl-8" autoFocus />
          </div>
          {!found.data ? (
            <Loader2 className="mx-auto my-2 size-4 animate-spin text-muted-foreground" />
          ) : options.length === 0 ? (
            <p className="px-1 py-2 text-xs text-muted-foreground">{t("delivery.absence.noCandidates")}</p>
          ) : (
            <ul className="mt-2 max-h-64 divide-y overflow-y-auto rounded-md border" role="listbox" aria-label={t("delivery.absence.pickDeputy")}>
              {options.map((d) => (
                <li key={d.id}>
                  <button
                    type="button"
                    role="option"
                    aria-selected={false}
                    onClick={() => {
                      onChange({ id: d.id, username: d.username, display_name: d.display_name })
                      setOpen(false)
                    }}
                    className="w-full px-2.5 py-1.5 text-left hover:bg-muted/60 focus-visible:bg-muted/60 focus-visible:outline-none"
                  >
                    <span className="block truncate text-sm">{d.display_name}</span>
                    <span className="block truncate text-[11px] text-muted-foreground">
                      <span className="font-mono">{d.username}</span>
                      {d.teams.length > 0 && ` · ${isoList(d.teams)}`}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </PopoverContent>
      </Popover>
    </div>
  )
}

/** "abwesend bis … – vertreten durch …" (and the hint when the deputy is away then too). */
export function AbsenceLine({ a, name }: { a: AbsenceView; name?: string }) {
  const { t, i18n } = useTranslation()
  const lang = i18n.language
  const text = a.running
    ? t("delivery.absence.lineRunning", { end: showDate(a.end, lang), deputy: a.deputy.display_name })
    : t("delivery.absence.linePlanned", { start: showDate(a.start, lang), end: showDate(a.end, lang), deputy: a.deputy.display_name })
  return (
    <span className="block">
      <span className="inline-flex items-center gap-1">
        <CalendarClock className="size-3.5 shrink-0" /> {text}
        {a.also_me && ` · ${t("delivery.absence.alsoMeShort")}`}
      </span>
      {(a.deputy_absent || !a.deputy.active) && (
        <span className="mt-0.5 flex items-center gap-1 text-warning" role="status">
          <AlertTriangle className="size-3.5 shrink-0" /> {t("delivery.absence.deputyAway", { name: name ?? t("delivery.absence.you") })}
        </span>
      )}
    </span>
  )
}

type AbsenceForm = { start: string; end: string; deputy: PersonRefLite | null; also_me: boolean }

/** The form of an absence – the person's own or a member's (an admin in the team drawer): its save and end URLs. */
export function AbsenceEditor({
  current,
  deputiesUrl,
  absenceUrl,
  onSaved,
  onCancel,
  intro,
  alsoMeLabel,
}: {
  current: AbsenceView | null
  deputiesUrl: string
  absenceUrl: string
  onSaved: () => void
  onCancel?: () => void
  intro?: React.ReactNode
  /** an admin sets it for a member: "also to <name>" instead of "also to me" */
  alsoMeLabel?: string
}) {
  const { t } = useTranslation()
  const first: AbsenceForm = current
    ? { start: current.start, end: current.end, deputy: current.deputy, also_me: current.also_me }
    : { start: today(), end: today(), deputy: null, also_me: false }
  const [v, setV] = useState<AbsenceForm>(first)
  const [busy, setBusy] = useState(false)
  const dirty = JSON.stringify(v) !== JSON.stringify(first)
  const valid = absenceValid(v.start, v.end, v.deputy?.id ?? "")
  const save = async () => {
    if (!v.deputy) return
    setBusy(true)
    try {
      await api.put(absenceUrl, { start: v.start, end: v.end, deputy_id: v.deputy.id, also_me: v.also_me })
      toast.success(t("common.saved"))
      onSaved()
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const end = async () => {
    setBusy(true)
    try {
      await api.del(absenceUrl)
      toast.success(current?.running ? t("delivery.absence.ended") : t("delivery.absence.removed"))
      onSaved()
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <SheetBody>
        {intro}
        {current && (
          <div className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
            <AbsenceLine a={current} />
          </div>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t("delivery.absence.start")} hint={current?.running ? t("delivery.absence.startRunning") : undefined}>
            <Input type="date" value={v.start} disabled={!!current?.running} onChange={(e) => setV({ ...v, start: e.target.value })} className="w-full sm:w-44" />
          </Field>
          <Field label={t("delivery.absence.end")}>
            <Input type="date" value={v.end} min={v.start} onChange={(e) => setV({ ...v, end: e.target.value })} className="w-full sm:w-44" />
          </Field>
        </div>
        {v.start && v.end && v.end < v.start && <p className="text-xs text-destructive">{t("errors.absence_range")}</p>}
        <Field label={<Explained label={t("delivery.absence.deputy")} text={t("delivery.absence.deputyExplain")} />}>
          <DeputyPicker url={deputiesUrl} value={v.deputy} onChange={(d) => setV({ ...v, deputy: d })} />
        </Field>
        <div className="rounded-lg border px-3">
          <ToggleRow
            label={alsoMeLabel ?? t("delivery.absence.alsoMe")}
            description={t("delivery.absence.alsoMeHint")}
            checked={v.also_me}
            onCheckedChange={(x) => setV({ ...v, also_me: x })}
          />
        </div>
        <p className="rounded-lg bg-muted/60 p-3 text-xs leading-relaxed text-muted-foreground">{t("delivery.absence.rules")}</p>
      </SheetBody>
      <SheetActions>
        <span className="flex flex-wrap gap-2">
          {onCancel && (
            <Button variant="ghost" onClick={onCancel} disabled={busy}>
              {t("common.cancel")}
            </Button>
          )}
          {current && (
            <Button variant="ghost" className="text-destructive" disabled={busy} onClick={() => void end()}>
              {current.running ? t("delivery.absence.end_now") : t("delivery.absence.remove")}
            </Button>
          )}
        </span>
        <SaveBar busy={busy} dirty={dirty} disabled={!valid} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}

/** "Abwesenheit": the own absence and deputy – and for whom the person stands in now. */
export function AbsencePart({ initial }: { initial: PersonalNotify }) {
  const { t, i18n } = useTranslation()
  const qc = useQueryClient()
  const intro = (
    <>
      <p className="text-xs leading-relaxed text-muted-foreground">{t("delivery.absence.hint")}</p>
      {initial.covering.length > 0 && (
        <div className="rounded-lg border border-primary/30 bg-primary/5 p-3 text-xs" role="status">
          <p className="font-medium">{t("delivery.absence.coveringTitle")}</p>
          <ul className="mt-1 space-y-0.5">
            {initial.covering.map((c) => (
              <li key={`${c.name}-${c.start}`}>
                {c.running
                  ? t("delivery.absence.coveringNow", { name: c.name, end: showDate(c.end, i18n.language) })
                  : t("delivery.absence.coveringLater", { name: c.name, start: showDate(c.start, i18n.language), end: showDate(c.end, i18n.language) })}
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  )
  return (
    <AbsenceEditor
      key={JSON.stringify(initial.absence)}
      current={initial.absence}
      deputiesUrl="/api/me/vendor-notify/deputies"
      absenceUrl="/api/me/vendor-notify/absence"
      onSaved={() => refresh(qc)}
      intro={intro}
    />
  )
}

// ---------------------------------------------------------------- weekly review

/** "Wochenrückblick": the review of the own teams by e-mail, for me (off by default). */
export function WeeklyPart({ initial }: { initial: PersonalNotify }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const w = initial.weekly
  const [on, setOn] = useState(w.on)
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true)
    try {
      await api.put("/api/me/vendor-notify/weekly", { on })
      toast.success(t("common.saved"))
      refresh(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <SheetBody>
        <p className="text-xs leading-relaxed text-muted-foreground">{t("delivery.weekly.hint")}</p>
        {w.teams.length === 0 ? (
          <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("delivery.weekly.noTeam")}</p>
        ) : (
          <ul className="space-y-1 rounded-lg border p-3 text-sm">
            {w.teams.map((x) => (
              <li key={x.team}>
                <span className="font-medium">{x.team}</span>{" "}
                <span className="text-muted-foreground">
                  {t("delivery.weekly.when", { day: t(`delivery.day.${WEEKDAYS[x.weekday] ?? "monday"}`), at: x.at, tz: x.tz.replace(/_/g, " ") })}
                </span>
              </li>
            ))}
          </ul>
        )}
        {!w.smtp_ready && <p className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">{t("delivery.weekly.noSmtp")}</p>}
        <div className="rounded-lg border px-3">
          <ToggleRow
            label={t("delivery.weekly.toggle")}
            description={w.address_ok ? t("delivery.weekly.toggleHint") : t("personal.email.noAddress")}
            checked={on}
            disabled={!w.address_ok && !on}
            onCheckedChange={setOn}
          />
        </div>
      </SheetBody>
      <SheetActions>
        <span className="text-xs text-muted-foreground">{t("delivery.weekly.footer")}</span>
        <SaveBar busy={busy} dirty={on !== w.on} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}

// ---------------------------------------------------------------- a team's weekly review (admin, team drawer)

/** The team's weekly review by e-mail: on/off (off by default), weekday, time, zone. Who gets it, each member chooses. */
export function TeamWeeklyPart({ team, settings }: { team: Team; settings: TeamsSettings }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const w = team.weekly
  const first = { enabled: w.enabled, weekday: w.weekday, at: w.at, tz: w.tz }
  const [v, setV] = useState(first)
  const [busy, setBusy] = useState(false)
  const dirty = JSON.stringify(v) !== JSON.stringify(first)
  const save = async () => {
    setBusy(true)
    try {
      await api.put(`/api/admin/teams/${team.id}/weekly`, v)
      toast.success(t("common.saved"))
      void qc.invalidateQueries({ queryKey: ["admin", "teams"] })
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <SheetBody>
        <p className="text-xs leading-relaxed text-muted-foreground">{t("delivery.teamWeekly.hint")}</p>
        {!settings.smtp_ready && <p className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">{t("delivery.weekly.noSmtp")}</p>}
        <div className="rounded-lg border px-3">
          <ToggleRow
            label={t("delivery.teamWeekly.toggle")}
            description={t("delivery.teamWeekly.toggleHint")}
            checked={v.enabled}
            onCheckedChange={(x) => setV({ ...v, enabled: x })}
          />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t("delivery.teamWeekly.day")}>
            <Select value={String(v.weekday)} onValueChange={(x) => setV({ ...v, weekday: Number(x) })}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                {WEEKDAYS.map((d, i) => (
                  <SelectItem key={d} value={String(i)}>
                    {t(`delivery.dayName.${d}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label={t("delivery.teamWeekly.at")}>
            <Input type="time" step={60} value={v.at} onChange={(e) => setV({ ...v, at: e.target.value })} className="w-full sm:w-36" />
          </Field>
        </div>
        <Field label={t("delivery.tz")}>
          <ZoneSelect value={v.tz} onChange={(x) => setV({ ...v, tz: x })} />
        </Field>
        <p className="rounded-lg bg-muted/60 p-3 text-xs leading-relaxed text-muted-foreground">
          {t("delivery.teamWeekly.recipients", { count: w.recipients })}
          {w.last_week && ` ${t("delivery.teamWeekly.last", { week: w.last_week })}`}
        </p>
        <p className="text-xs leading-relaxed text-muted-foreground">{t("delivery.teamWeekly.content")}</p>
      </SheetBody>
      <SheetActions>
        <span className="text-xs text-muted-foreground">{t("delivery.teamWeekly.once")}</span>
        <SaveBar busy={busy} dirty={dirty} disabled={!validHm(v.at)} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}
