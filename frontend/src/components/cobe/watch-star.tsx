import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import { Star } from "lucide-react"
import { toast } from "sonner"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { errorText } from "@/lib/errors"
import { PERSONAL_KEY } from "@/lib/teams-api"
import { cn } from "@/lib/utils"
import { WATCH_IDS_KEY, WATCH_KEY, type WatchOriginIn, normalizeCve, unwatchCve, useWatchIds, watchCve } from "@/lib/watch-api"

/** The star next to a CVE (a story, a finding): watch it ("CVE beobachten") or stop. What comes of it and whether a way
 * is on is said on the page "Beobachtete CVEs" (/watch – the toast's "Zur Liste" opens it at the CVE). A click never
 * reaches the card or row around it (its navigation, its drawer). `origin`: the story or finding it sits in – kept with
 * the watch (the list's groups); a CVE watched already keeps its first origin. */
export function WatchStar({ cve, origin, className }: { cve: string; origin?: WatchOriginIn; className?: string }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const ids = useWatchIds()
  const [busy, setBusy] = useState(false)
  const id = normalizeCve(cve)
  if (!id) return null
  const on = ids.data?.has(id) ?? false
  const toggle = async (e: React.MouseEvent) => {
    e.stopPropagation()
    e.preventDefault()
    setBusy(true)
    try {
      if (on) {
        await unwatchCve(id)
        toast.success(t("watch.removed", { cve: id }))
      } else {
        await watchCve(id, origin)
        toast.success(t("watch.added", { cve: id }), {
          action: { label: t("watch.toList"), onClick: () => navigate(`/watch?cve=${encodeURIComponent(id)}`) },
        })
      }
      void qc.invalidateQueries({ queryKey: WATCH_IDS_KEY })
      void qc.invalidateQueries({ queryKey: WATCH_KEY, exact: true })
      void qc.invalidateQueries({ queryKey: PERSONAL_KEY }) // the first watched CVE can open the personal ways
    } catch (err) {
      toast.error(errorText(t, err))
    } finally {
      setBusy(false)
    }
  }
  const label = on ? t("watch.unwatch", { cve: id }) : t("watch.watch", { cve: id })
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={(e) => void toggle(e)}
          onKeyDown={(e) => e.stopPropagation()} // Enter/Space on the star are the star's, not a keyboard row's
          disabled={busy || ids.isPending}
          aria-pressed={on}
          aria-label={label}
          className={cn(
            "relative z-10 shrink-0 rounded p-0.5 transition-colors hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none disabled:opacity-50",
            on ? "text-warning" : "text-muted-foreground opacity-60 hover:text-foreground hover:opacity-100",
            className,
          )}
        >
          <Star className={cn("size-3.5", on && "fill-current")} />
        </button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}
