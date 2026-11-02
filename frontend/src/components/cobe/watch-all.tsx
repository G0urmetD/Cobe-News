import { useId, useState } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import { Loader2, Star, StarOff } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Mono } from "@/components/cobe/common"
import { confirmAction } from "@/components/cobe/confirm"
import { WatchStar } from "@/components/cobe/watch-star"
import { ApiError } from "@/lib/api"
import { errorText } from "@/lib/errors"
import { PERSONAL_KEY } from "@/lib/teams-api"
import { cn } from "@/lib/utils"
import { WATCH_IDS_KEY, WATCH_KEY, type WatchOriginIn, groupHref, rewatch, unwatchCves, unwatched, useWatchIds, watchCves } from "@/lib/watch-api"

/** CVEs as chips (copy, star) – the first `shown`, the rest behind "+ N weitere CVEs" (and back with "weniger"). */
export function CveChips({ cves, shown, origin, className }: { cves: string[]; shown: number; origin?: WatchOriginIn; className?: string }) {
  const { t } = useTranslation()
  const [all, setAll] = useState(false)
  const id = useId()
  const more = cves.length - shown
  const list = all || more <= 0 ? cves : cves.slice(0, shown)
  return (
    <ul id={id} className={cn("flex flex-wrap items-center gap-x-3 gap-y-1", className)}>
      {list.map((c) => (
        <li key={c} className="inline-flex items-center gap-0.5">
          <Mono value={c} />
          <WatchStar cve={c} origin={origin} />
        </li>
      ))}
      {more > 0 && (
        <li>
          <button
            type="button"
            aria-expanded={all}
            aria-controls={id}
            onClick={(e) => {
              e.stopPropagation()
              setAll((v) => !v)
            }}
            className="rounded text-xs font-medium text-primary outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring/50"
          >
            {all ? t("details.fewerCves") : t("details.moreCves", { count: more })}
          </button>
        </li>
      )}
    </ul>
  )
}

/** "Alle beobachten (N)" – the CVEs of a story or a finding in one request, each with that origin; when all are
 * watched: "Alle nicht mehr beobachten" (with undo). More than fit into the list: the server says how many places are
 * left and the person decides whether the first ones (in `cves`' order – `order` says which that is) should be watched. */
export function WatchAllButton({ cves, origin, order, className }: { cves: string[]; origin: WatchOriginIn; order: "epss" | "list"; className?: string }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const ids = useWatchIds()
  const [busy, setBusy] = useState(false)
  if (cves.length < 2) return null
  const missing = unwatched(cves, ids.data)
  const allOn = missing.length === 0
  const changed = () => {
    void qc.invalidateQueries({ queryKey: WATCH_IDS_KEY })
    void qc.invalidateQueries({ queryKey: WATCH_KEY, exact: true })
    void qc.invalidateQueries({ queryKey: PERSONAL_KEY }) // the first watched CVE can open the personal ways
  }
  const watch = async (partial: boolean): Promise<void> => {
    try {
      const r = await watchCves(cves, origin, partial)
      changed()
      const text = r.added.length ? t("watch.all.added", { count: r.added.length }) : t("watch.all.nothingNew")
      toast.success(r.skipped.length ? `${text} ${t("watch.all.skipped", { count: r.skipped.length })}` : text, {
        action: { label: t("watch.toList"), onClick: () => navigate(groupHref(origin)) },
      })
    } catch (e) {
      if (!partial && e instanceof ApiError && e.code === "watch_limit" && typeof e.data.free === "number") {
        const free = e.data.free
        const limit = Number(e.data.limit ?? 0)
        if (free <= 0) {
          toast.error(t("watch.all.full", { limit }))
          return
        }
        const ok = await confirmAction({
          title: t("watch.all.limitTitle", { count: free }),
          text: `${t("watch.all.limitText", { limit, wanted: Number(e.data.wanted ?? missing.length), free })} ${t(`watch.all.order.${order}`)}`,
          confirm: t("watch.all.limitConfirm", { count: free }),
          destructive: false,
        })
        if (ok) await watch(true)
        return
      }
      toast.error(errorText(t, e))
    }
  }
  const unwatch = async () => {
    try {
      const r = await unwatchCves(cves.filter((c) => ids.data?.has(c)))
      changed()
      toast.success(t("watch.all.removed", { count: r.removed.length }), {
        action: {
          label: t("watch.undo"),
          onClick: () =>
            void rewatch(r.removed).then(
              (n) => {
                toast.success(t("watch.all.undone", { count: n }))
                changed()
              },
              (err: unknown) => toast.error(errorText(t, err)),
            ),
        },
      })
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  const run = async (e: React.MouseEvent) => {
    e.stopPropagation()
    setBusy(true)
    try {
      await (allOn ? unwatch() : watch(false))
    } finally {
      setBusy(false)
    }
  }
  const hint = allOn
    ? t("watch.all.hintAll", { count: cves.length })
    : missing.length === cves.length
      ? t("watch.all.hintNone", { count: cves.length })
      : t("watch.all.hintSome", { count: cves.length, watched: cves.length - missing.length })
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button type="button" variant="outline" size="xs" className={className} disabled={busy || ids.isPending} onClick={(e) => void run(e)}>
          {busy ? <Loader2 className="animate-spin" /> : allOn ? <StarOff /> : <Star />}
          {allOn ? t("watch.all.unwatch") : t("watch.all.watch", { count: missing.length })}
        </Button>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">{hint}</TooltipContent>
    </Tooltip>
  )
}
