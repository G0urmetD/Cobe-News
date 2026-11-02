import { useLayoutEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { Check, Copy } from "lucide-react"
import { toast } from "sonner"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { copyText } from "@/lib/clipboard"
import { dateTimeFormat, fmtDateTime, fmtDateTimeZone, fmtRelative, useMinute } from "@/lib/format"
import { cn } from "@/lib/utils"

const pad = (n: number) => String(n).padStart(2, "0")

/** "2026-09-28 20:13:05 UTC" – what logs, MDR notes and authorities work with. */
export function utcText(iso: string) {
  const d = new Date(iso)
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`
}

const isoOf = (at: string) => new Date(at).toISOString().replace(".000Z", "Z")

// dateStyle/timeStyle cannot be combined with timeZoneName – spelled out instead
const LOCAL = { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", timeZoneName: "short" } as const

function localText(iso: string, lang: string) {
  return dateTimeFormat(LOCAL, lang === "en" ? "en-GB" : "de-DE").format(new Date(iso))
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const { t } = useTranslation()
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={(e) => {
        e.stopPropagation() // the tooltip is portaled, but React still bubbles the click to e.g. a clickable table row
        e.preventDefault()
        copyText(value)
          .then(() => {
            setDone(true)
            setTimeout(() => setDone(false), 1200)
          })
          .catch(() => toast.error(t("time.copyFailed")))
      }}
      className="rounded p-0.5 text-background/70 outline-none hover:bg-background/15 hover:text-background focus-visible:ring-2 focus-visible:ring-background/40"
    >
      {done ? <Check className="size-3" /> : <Copy className="size-3" />}
    </button>
  )
}

/**
 * A point in time as the app shows it everywhere (relative or date + time); hovering it shows the exact local time with
 * seconds and zone, and UTC – each copyable. `zone`: the zone right in the text (MEZ/MESZ) – in drawers, where the hour a
 * clock change repeats would otherwise be ambiguous.
 */
export function Ts({ at, rel = false, zone = false, className, children }: { at: string; rel?: boolean; zone?: boolean; className?: string; children?: React.ReactNode }) {
  const { t, i18n } = useTranslation()
  useMinute() // relative times move on: rendered again every minute
  const ref = useRef<HTMLTimeElement>(null)
  // inside a button, link or keyboard row the surrounding element is the stop – no second focusable inside it
  useLayoutEffect(() => {
    const el = ref.current
    if (el?.parentElement?.closest('button, a[href], [role=button], [role=link], [role=option], [tabindex]:not([tabindex="-1"])')) el.tabIndex = -1
  }, [])
  if (!at || Number.isNaN(Date.parse(at))) return <span className={className}>{children ?? "—"}</span>
  const shown = children ?? (rel ? fmtRelative(at) : zone ? fmtDateTimeZone(at) : fmtDateTime(at))
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* keyboard: Tab focuses (the tooltip opens), ⌘/Strg+C copies the UTC time stamp; screen readers hear both times */}
        <time
          ref={ref}
          dateTime={at}
          tabIndex={0}
          aria-label={`${typeof shown === "string" ? `${shown} – ` : ""}${localText(at, i18n.language)} · ${utcText(at)}`}
          onKeyDown={(e) => {
            if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "c" && !window.getSelection()?.toString()) {
              e.preventDefault()
              e.stopPropagation()
              copyText(isoOf(at)).then(
                () => toast.success(t("time.copiedUtc")),
                () => toast.error(t("time.copyFailed")),
              )
            }
          }}
          className={cn(
            "cursor-default rounded-sm underline-offset-[3px] outline-none hover:underline hover:decoration-dotted focus-visible:ring-2 focus-visible:ring-ring/50",
            className,
          )}
        >
          {shown}
        </time>
      </TooltipTrigger>
      <TooltipContent side="top" className="block max-w-none px-3 py-2">
        <TsDetails at={at} rel={rel} />
      </TooltipContent>
    </Tooltip>
  )
}

/** Only rendered while the tooltip is open – a long timeline has hundreds of times. */
function TsDetails({ at, rel }: { at: string; rel: boolean }) {
  const { t, i18n } = useTranslation()
  const local = localText(at, i18n.language)
  const iso = isoOf(at)
  return (
    <dl className="grid grid-cols-[auto_auto_auto] items-center gap-x-3 gap-y-1 text-xs">
      <dt className="text-background/60">{t("time.local")}</dt>
      <dd className="tabular">{local}</dd>
      <dd>
        <CopyButton value={local} label={t("time.copyLocal")} />
      </dd>
      <dt className="text-background/60">UTC</dt>
      <dd className="font-mono text-[11px]">{utcText(at)}</dd>
      <dd>
        <CopyButton value={iso} label={t("time.copyUtc")} />
      </dd>
      {!rel && (
        <>
          <dt className="text-background/60">{t("time.ago")}</dt>
          <dd className="col-span-2">{fmtRelative(at)}</dd>
        </>
      )}
      <dd className="col-span-3 pt-1 text-[10px] text-background/60">{t("time.keyHint")}</dd>
    </dl>
  )
}
