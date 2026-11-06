import { useId, useState } from "react"
import { useTranslation } from "react-i18next"
import { CalendarRange, ChevronDown } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { fmtRelative, fmtZone, useMinute } from "@/lib/format"
import { NO_RANGE, type NewsRange, type RangeDraft, type TimeField, RANGE_PRESETS, draftOf, draftRange, fieldApplies, rangeActive, rangeLabel } from "@/lib/news-range"
import { cn } from "@/lib/utils"

/**
 * "Zeitraum" in the News filter bar: one button (the short label of the active range, highlighted), its popover the
 * presets, an own range (date and time in the browser's zone, either end open) and what the times are about (the
 * story's date or its arrival). `markAt`: the time of the read watermark – "Seit meinem letzten Besuch" shows how long ago.
 */
export function NewsRangeControl({ value, onChange, markAt }: { value: NewsRange; onChange: (r: NewsRange) => void; markAt?: string | null }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState<RangeDraft>(() => draftOf(value))
  const [tried, setTried] = useState(false)
  // the field chosen before a range is on: used by the next preset or own range
  const [field, setField] = useState<TimeField>(value.field)
  const id = useId()
  const minute = useMinute()
  const active = rangeActive(value)
  const label = rangeLabel(t, value, new Date(minute * 60_000))
  const own = draftRange(draft)
  const zone = fmtZone(new Date(minute * 60_000).toISOString())
  const errorText =
    own.error === "order" ? t("newsRange.errOrder") : own.error === "invalid" ? t("newsRange.errInvalid") : own.error === "empty" && tried ? t("newsRange.errEmpty") : null
  const curField = active ? value.field : field

  const openChange = (o: boolean) => {
    if (o) {
      setDraft(draftOf(value))
      setField(value.field)
      setTried(false)
    }
    setOpen(o)
  }
  const pick = (preset: NewsRange["preset"]) => {
    onChange({ preset, since: null, until: null, field: curField })
    setOpen(false)
  }
  const applyOwn = (e: React.FormEvent) => {
    e.preventDefault()
    setTried(true)
    if (own.error) return
    onChange({ preset: null, since: own.since, until: own.until, field: curField })
    setOpen(false)
  }
  const setTimeField = (v: string) => {
    if (v !== "published" && v !== "fetched") return // a click on the pressed one: it stays
    setField(v)
    if (active) onChange({ ...value, field: v })
  }
  const set = (k: keyof RangeDraft) => (e: React.ChangeEvent<HTMLInputElement>) => setDraft((d) => ({ ...d, [k]: e.target.value }))

  return (
    <Popover open={open} onOpenChange={openChange}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          className={cn("h-9 max-w-full border-dashed", active && "border-solid")}
          aria-label={active ? `${t("newsRange.title")}: ${label}` : t("newsRange.title")}
        >
          <CalendarRange className="text-muted-foreground" aria-hidden />
          {active ? <span className="min-w-0 truncate rounded-md bg-primary/10 px-1.5 text-xs font-semibold text-primary">{label}</span> : t("newsRange.title")}
          <ChevronDown className="text-muted-foreground" aria-hidden />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="max-h-(--radix-popover-content-available-height) w-[min(21rem,calc(100vw-1.5rem))] gap-3 overflow-y-auto p-3">
        <div role="group" aria-labelledby={`${id}-presets`} className="grid grid-cols-2 gap-1">
          <p id={`${id}-presets`} className="col-span-2 text-xs font-medium text-muted-foreground">
            {t("newsRange.presets")}
          </p>
          {RANGE_PRESETS.map((p) => {
            const on = value.preset === p
            return (
              <button
                key={p}
                type="button"
                aria-pressed={on}
                onClick={() => pick(p)}
                className={cn(
                  "rounded-md px-2 py-1.5 text-left text-sm outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring/50",
                  on && "bg-primary/10 font-medium text-primary",
                  p === "visit" && "col-span-2",
                )}
              >
                {t(`newsRange.preset.${p}`)}
                {p === "visit" && markAt && <span className="ml-1 text-xs font-normal text-muted-foreground">({fmtRelative(markAt)})</span>}
              </button>
            )
          })}
          <p className="col-span-2 px-2 text-xs leading-snug text-muted-foreground">{t("newsRange.visitHint")}</p>
        </div>

        <form className="space-y-2 border-t pt-3" onSubmit={applyOwn} noValidate aria-labelledby={`${id}-own`}>
          <p id={`${id}-own`} className="text-xs font-medium text-muted-foreground">
            {t("newsRange.custom")}
          </p>
          {(["from", "to"] as const).map((end) => (
            <div key={end} className="grid gap-1">
              <Label htmlFor={`${id}-${end}-date`} className="text-xs text-muted-foreground">
                {t(`newsRange.${end}`)}
              </Label>
              <div className="flex gap-1.5">
                <Input
                  id={`${id}-${end}-date`}
                  type="date"
                  min="1970-01-01"
                  max="2099-12-31"
                  value={end === "from" ? draft.fromDate : draft.toDate}
                  onChange={set(end === "from" ? "fromDate" : "toDate")}
                  aria-invalid={!!errorText || undefined}
                  aria-describedby={errorText ? `${id}-err` : `${id}-zone`}
                  className="h-9 min-w-0 flex-1"
                />
                <Input
                  type="time"
                  step={60}
                  value={end === "from" ? draft.fromTime : draft.toTime}
                  onChange={set(end === "from" ? "fromTime" : "toTime")}
                  aria-label={t(`newsRange.${end}Time`)}
                  aria-invalid={!!errorText || undefined}
                  aria-describedby={errorText ? `${id}-err` : `${id}-zone`}
                  className="h-9 w-[6.5rem] shrink-0"
                />
              </div>
            </div>
          ))}
          <p id={`${id}-zone`} className="text-xs text-muted-foreground">
            {zone ? t("newsRange.zone", { zone }) : t("newsRange.zoneLocal")} · {t("newsRange.openEnd")}
          </p>
          {errorText && (
            <p id={`${id}-err`} role="alert" className="text-xs font-medium text-destructive">
              {errorText}
            </p>
          )}
          <Button type="submit" size="sm" className="w-full" disabled={own.error === "order" || own.error === "invalid"}>
            {t("newsRange.apply")}
          </Button>
        </form>

        <div className="space-y-1.5 border-t pt-3">
          <p id={`${id}-field`} className="text-xs font-medium text-muted-foreground">
            {t("newsRange.field")}
          </p>
          <ToggleGroup
            type="single"
            variant="outline"
            size="sm"
            value={curField}
            onValueChange={setTimeField}
            aria-labelledby={`${id}-field`}
            disabled={active && !fieldApplies(value)}
            className="w-full"
          >
            <ToggleGroupItem value="published" className="flex-1">
              {t("newsRange.published")}
            </ToggleGroupItem>
            <ToggleGroupItem value="fetched" className="flex-1">
              {t("newsRange.fetched")}
            </ToggleGroupItem>
          </ToggleGroup>
          <p className="text-xs leading-snug text-muted-foreground">{t(active && !fieldApplies(value) ? "newsRange.fieldVisit" : "newsRange.fieldHint")}</p>
        </div>

        {active && (
          <Button
            variant="ghost"
            size="sm"
            className="w-full"
            onClick={() => {
              onChange({ ...NO_RANGE, field: curField })
              setOpen(false)
            }}
          >
            {t("newsRange.clear")}
          </Button>
        )}
      </PopoverContent>
    </Popover>
  )
}
