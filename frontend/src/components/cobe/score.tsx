import { useTranslation } from "react-i18next"
import { Gauge } from "lucide-react"
import { Pill } from "@/components/cobe/badges"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { SCORE_TONE, type Score, type ScoreBrief, scorePartText } from "@/lib/vendor-api"
import { cn } from "@/lib/utils"

/**
 * Dringlichkeit as one number: "87 · Sofort" in the level's colour. With a breakdown (`score.parts`) the tooltip says how
 * it came about ("KEV +30, EPSS-Perzentil 97 % +20, eure Version betroffen +25 …"); a brief one only explains the term.
 */
export function ScorePill({ score, className, compact = false }: { score: Score | ScoreBrief; className?: string; compact?: boolean }) {
  const { t, i18n } = useTranslation()
  const tone = SCORE_TONE[score.level]
  const parts = "parts" in score ? score.parts : null
  const label = t(`vendor.score.level.${score.level}`)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          data-score={score.value}
          aria-label={t("vendor.score.aria", { value: score.value, level: label })}
          className={cn("relative z-10 inline-flex cursor-help rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50", className)}
        >
          <Pill color={tone}>
            <Gauge /> <span className="font-mono tabular-nums">{score.value}</span>
            {!compact && <span>· {label}</span>}
          </Pill>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs text-left leading-relaxed">
        {/* one block: the tooltip lays out its children side by side */}
        <span className="block space-y-1">
          <span className="block font-semibold">
            {t("vendor.score.title")} {score.value} · {label}
          </span>
          {parts ? (
            <>
              {"ident" in score && score.ident && <span className="block text-muted-foreground">{t("vendor.score.from", { ident: score.ident })}</span>}
              {"version" in score && score.version && !("ident" in score && score.ident) && (
                <span className="block text-muted-foreground">{t("vendor.score.version", { version: score.version })}</span>
              )}
              <span className="block">{parts.map((p) => scorePartText(t, p, i18n.language)).join(", ")}</span>
              {"raw" in score && score.raw !== score.value && <span className="block text-muted-foreground">{t("vendor.score.clamped", { raw: score.raw })}</span>}
            </>
          ) : null}
          <span className="block text-muted-foreground">{t("vendor.score.help")}</span>
        </span>
      </TooltipContent>
    </Tooltip>
  )
}
