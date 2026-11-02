import { useTranslation } from "react-i18next"
import { ArrowDownRight, ArrowUpRight, ExternalLink, History } from "lucide-react"
import { Pill } from "@/components/cobe/badges"
import { EmptyState } from "@/components/cobe/common"
import { Term } from "@/components/cobe/glossary"
import { DrawerSkeleton, QueryError } from "@/components/cobe/query-state"
import { Ts } from "@/components/cobe/time"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { type AdvisoryChange, type ChangeLine, changeLines, hasWorse, useLineText, useProductChanges } from "@/lib/advisory-changes"
import { fmtDay } from "@/lib/format"
import { cn } from "@/lib/utils"

const TONE: Record<ChangeLine["tone"], string> = {
  worse: "font-medium text-sev-critical",
  better: "font-medium text-success",
  important: "font-medium",
  normal: "text-muted-foreground",
}

/** "Geändert" with the day of the newest revision – the tooltip says what changed (the lists: findings, cards). */
export function ChangedBadge({ c }: { c: AdvisoryChange }) {
  const { t } = useTranslation()
  const text = useLineText()
  const lines = changeLines(c)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          <Pill color={hasWorse(c) ? "--sev-critical" : "--warning"}>
            <History /> {t("changes.badge", { date: fmtDay(c.at) })}
          </Pill>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-sm text-left leading-relaxed">
        <span className="block font-semibold">{t("changes.revision", { n: c.revision })}</span>
        {lines.slice(0, 5).map((l, i) => (
          <span key={i} className="block">
            {text(l)}
          </span>
        ))}
        {lines.length > 5 && <span className="block">{t("changes.moreLines", { count: lines.length - 5 })}</span>}
      </TooltipContent>
    </Tooltip>
  )
}

/** The revisions, newest first: per revision when, which advisory, and what changed – the impact on the versions
 * entered first. */
export function ChangeList({ changes, showAdvisory = true }: { changes: AdvisoryChange[]; showAdvisory?: boolean }) {
  const { t } = useTranslation()
  const text = useLineText()
  return (
    <ol className="space-y-2">
      {changes.map((c) => {
        const lines = changeLines(c)
        return (
          <li key={`${c.advisory}:${c.revision}`} className={cn("space-y-1.5 rounded-xl border p-3.5", hasWorse(c) && "border-sev-critical/40")}>
            <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
              <span className="font-medium text-foreground/80">
                <Term k="revision">{t("changes.revision", { n: c.revision })}</Term>
              </span>
              {c.doc_rev && <span>· {t("changes.docRev", { rev: c.doc_rev })}</span>}
              <span>·</span>
              <Ts at={c.at} rel />
              {showAdvisory && c.url && (
                <a href={c.url} target="_blank" rel="noopener noreferrer" className="ml-auto inline-flex items-center gap-1 text-primary hover:underline">
                  <ExternalLink className="size-3" /> {t("vendor.openAdvisory")}
                </a>
              )}
            </div>
            {showAdvisory && (
              <p className="text-sm leading-snug font-medium">
                <span className="font-mono text-[12.5px] text-muted-foreground">{c.ident}</span> {c.title}
              </p>
            )}
            <ul className="space-y-0.5 text-xs">
              {lines.map((l, i) => (
                <li key={i} className={cn("flex gap-1.5", TONE[l.tone])}>
                  {l.tone === "worse" ? (
                    <ArrowUpRight className="mt-0.5 size-3.5 shrink-0" />
                  ) : l.tone === "better" ? (
                    <ArrowDownRight className="mt-0.5 size-3.5 shrink-0" />
                  ) : (
                    <span className="mt-1.5 size-1 shrink-0 rounded-full bg-current" />
                  )}
                  <span>{text(l)}</span>
                </li>
              ))}
            </ul>
          </li>
        )
      })}
    </ol>
  )
}

/** The drawer's "Änderungen": the revisions of the product's advisories (only those that concern it). */
export function ProductChanges({ productKey }: { productKey: string }) {
  const { t } = useTranslation()
  const q = useProductChanges(productKey)
  if (q.isError) return <QueryError error={q.error} onRetry={() => void q.refetch()} />
  if (!q.data) return <DrawerSkeleton label={t("vendor.loading")} />
  const shown = q.data.changes
  if (!shown.length) return <EmptyState icon={History} title={t("changes.none")} text={t("changes.noneText")} />
  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">{t("changes.intro")}</p>
      <ChangeList changes={shown} />
    </div>
  )
}

/** A story's "Änderungen": the revisions of the advisory behind it (as Vendor News keeps them). */
export function StoryChanges({ changes }: { changes: AdvisoryChange[] }) {
  const { t } = useTranslation()
  if (!changes.length) return null
  return (
    <section className="space-y-2">
      <h3 className="flex items-center gap-1.5 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
        <History className="size-3.5" /> {t("changes.title")}
      </h3>
      <ChangeList changes={changes} showAdvisory={false} />
    </section>
  )
}

/** A card's (and a row's) "Geändert": advisories of the product revised within the last 30 days – red when one changed
 * the verdict of a version entered. */
export function ProductChangedHint({ changed }: { changed?: { count: number; at: string; impact: boolean } | null }) {
  const { t } = useTranslation()
  if (!changed?.count) return null
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className={cn(
            "relative z-10 mt-0.5 inline-flex cursor-help items-center gap-1 text-[11px] underline decoration-dotted underline-offset-2",
            changed.impact ? "font-medium text-sev-critical" : "text-muted-foreground",
          )}
        >
          <History className="size-3 shrink-0" /> {t("changes.badge", { date: fmtDay(changed.at) })}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">
        {t("changes.cardHelp", { count: changed.count })}
        {changed.impact && ` ${t("changes.cardImpact")}`}
      </TooltipContent>
    </Tooltip>
  )
}
