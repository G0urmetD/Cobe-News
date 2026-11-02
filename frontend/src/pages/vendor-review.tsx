import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useQueryClient } from "@tanstack/react-query"
import { Check, CheckCheck, Clock, Loader2, UsersRound } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { confirmAction } from "@/components/cobe/confirm"
import { EmptyState, MoreText } from "@/components/cobe/common"
import { QueryError } from "@/components/cobe/query-state"
import { useAuth } from "@/lib/auth"
import { errorText } from "@/lib/errors"
import { type ReviewItem, confirmAll, confirmVersion, groupByTeam, refreshReview, useReview } from "@/lib/version-review"

/**
 * "Versionen prüfen" above the overview (filter "zu prüfen"): the versions not confirmed within the interval that the
 * viewer is responsible for – by team – each with "Bestätigen", a team or product at once with "Alle bestätigen".
 */
export function ReviewPanel({ onOpen }: { onOpen: (key: string) => void }) {
  const { t } = useTranslation()
  const { isAdmin } = useAuth()
  const [scope, setScope] = useState<"mine" | "all">("mine")
  const q = useReview(isAdmin ? scope : "mine")
  const qc = useQueryClient()
  const [busy, setBusy] = useState<string | null>(null)
  const d = q.data
  if (q.isError && !d) return <QueryError error={q.error} onRetry={() => void q.refetch()} />
  if (!d) return null
  const run = async (key: string, what: () => Promise<number>) => {
    setBusy(key)
    try {
      const n = await what()
      toast.success(t("review.confirmedN", { count: n }))
      await refreshReview(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
    }
  }
  const all = async (label: string, n: number, target: { product: string } | { team_id: string }, key: string) => {
    if (!(await confirmAction({ title: t("review.allTitle"), text: t("review.allText", { count: n, product: label }), confirm: t("review.confirmAll"), destructive: false })))
      return
    await run(key, async () => (await confirmAll(target)).confirmed)
  }
  const groups = groupByTeam(d.items)
  return (
    <section aria-labelledby="review-title" className="space-y-3 rounded-xl border border-warning/40 bg-warning/5 p-3.5 sm:p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 id="review-title" className="flex items-center gap-2 text-sm font-semibold">
          <Clock className="size-4 text-warning" /> {t("review.title")}
        </h2>
        {isAdmin && (
          <ToggleGroup
            type="single"
            variant="outline"
            size="sm"
            spacing={0}
            value={scope}
            onValueChange={(v) => v && setScope(v as "mine" | "all")}
            aria-label={t("review.scope")}
            className="ml-auto"
          >
            <ToggleGroupItem value="mine" title={t("review.scopeMineHint")}>
              {t("review.scopeMine")}
            </ToggleGroupItem>
            <ToggleGroupItem value="all">{t("review.scopeAll")}</ToggleGroupItem>
          </ToggleGroup>
        )}
      </div>
      <p className="text-xs leading-relaxed text-muted-foreground">
        <MoreText>{d.enabled ? t("review.intro", { days: d.days }) : t("review.offText")}</MoreText>
      </p>
      {d.enabled && d.items.length === 0 && <EmptyState icon={CheckCheck} title={t("review.empty")} />}
      {groups.map((g) => {
        const mayTeam = !!g.team && g.items.every((i) => i.can_confirm)
        const gkey = `team:${g.team?.id ?? "none"}`
        return (
          <div key={gkey} className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground uppercase">
                {g.team ? (
                  <>
                    <UsersRound className="size-3.5" /> {g.team.name}
                  </>
                ) : (
                  t("review.noTeam")
                )}
                <span className="font-normal normal-case tabular-nums">· {t("review.versionsN", { count: g.versions })}</span>
              </h3>
              {mayTeam && g.versions > 1 && g.team && (
                <Button variant="outline" size="xs" className="ml-auto" disabled={!!busy} onClick={() => void all(g.team!.name, g.versions, { team_id: g.team!.id }, gkey)}>
                  {busy === gkey ? <Loader2 className="animate-spin" /> : <CheckCheck />} {t("review.confirmAllN", { count: g.versions })}
                </Button>
              )}
            </div>
            <ul className="divide-y rounded-lg border bg-card">
              {g.items.map((i) => (
                <Row
                  key={i.product.key}
                  i={i}
                  busy={busy}
                  onOpen={onOpen}
                  onOne={(id) => void run(`v:${id}`, async () => (await confirmVersion(id), 1))}
                  onAll={() => void all(i.product.label, i.versions.length, { product: i.product.key }, `p:${i.product.key}`)}
                />
              ))}
            </ul>
          </div>
        )
      })}
    </section>
  )
}

function Row({ i, busy, onOpen, onOne, onAll }: { i: ReviewItem; busy: string | null; onOpen: (key: string) => void; onOne: (id: string) => void; onAll: () => void }) {
  const { t } = useTranslation()
  return (
    <li className="space-y-1.5 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => onOpen(i.product.key)}
          className="min-w-0 text-left text-sm font-medium outline-none hover:underline focus-visible:rounded focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          {i.product.label}
        </button>
        <span className="text-xs text-muted-foreground">{i.product.vendor}</span>
        {i.can_confirm && i.versions.length > 1 && (
          <Button variant="ghost" size="xs" className="ml-auto" disabled={!!busy} onClick={onAll}>
            {busy === `p:${i.product.key}` ? <Loader2 className="animate-spin" /> : <CheckCheck />} {t("review.confirmAllN", { count: i.versions.length })}
          </Button>
        )}
      </div>
      <ul className="space-y-1">
        {i.versions.map((v) => (
          <li key={v.id} className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
            <span className="font-mono font-medium break-all">{v.version}</span>
            {v.label && <span className="text-muted-foreground">{v.label}</span>}
            <span className="text-warning">{t("review.since", { count: v.age_days })}</span>
            {v.confirmed_by && <span className="text-muted-foreground">· {t("review.by", { name: v.confirmed_by })}</span>}
            {i.can_confirm && (
              <Button variant="outline" size="xs" className="ml-auto" disabled={!!busy} onClick={() => onOne(v.id)} title={t("review.confirmHint")}>
                {busy === `v:${v.id}` ? <Loader2 className="animate-spin" /> : <Check />} {t("review.confirm")}
              </Button>
            )}
          </li>
        ))}
      </ul>
    </li>
  )
}
