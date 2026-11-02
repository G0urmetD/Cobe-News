import { useState } from "react"
import { useTranslation } from "react-i18next"
import { AlertTriangle, FlaskConical, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Pill } from "@/components/cobe/badges"
import { Explained } from "@/components/cobe/explained"
import { Ts } from "@/components/cobe/time"
import { api } from "@/lib/api"
import type { RuleIn } from "@/lib/admin-api"
import { DRY_DAYS, type DryDays, type DryRunResult, dryRunBody, matchParts, perDay } from "@/lib/delivery-log"
import { errorText } from "@/lib/errors"
import { NEWS_SEV_COLOR } from "@/lib/news-api"

/**
 * "Was hätte diese Regel ausgelöst?" – the rule as it is in the form (not saved) against what is stored of the last
 * 1 / 7 / 30 days. Nothing is sent and nothing is written (backend notify.dry_run).
 */
export function DryRunPanel({ rule }: { rule: Pick<RuleIn, "severities" | "sources" | "lang" | "kinds" | "teams"> }) {
  const { t } = useTranslation()
  const [days, setDays] = useState<DryDays>(7)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<{ r: DryRunResult; body: string } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const body = dryRunBody(rule, days)
  const key = JSON.stringify(body)
  const outdated = !!result && result.body !== key
  const run = async () => {
    setBusy(true)
    setError(null)
    try {
      const r = await api.post<DryRunResult>("/api/admin/notify/rules/dry-run", body)
      setResult({ r, body: key })
    } catch (e) {
      setError(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const r = result?.r
  return (
    <section className="space-y-3 rounded-lg border border-dashed p-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-auto text-sm font-medium">
          <Explained label={t("dlog.dry.title")} text={t("dlog.dry.explain")} />
        </p>
        <Select value={String(days)} onValueChange={(x) => setDays(Number(x) as DryDays)}>
          <SelectTrigger className="w-40" aria-label={t("dlog.dry.window")}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent position="popper">
            {DRY_DAYS.map((d) => (
              <SelectItem key={d} value={String(d)}>
                {t("dlog.dry.days", { count: d })}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" disabled={busy || rule.kinds.length === 0} onClick={() => void run()}>
          {busy ? <Loader2 className="animate-spin" /> : <FlaskConical />} {t("dlog.dry.run")}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">{t("dlog.dry.hint")}</p>
      {error && <p className="text-xs text-destructive">{error}</p>}
      {r && (
        <div className={outdated ? "space-y-3 opacity-60" : "space-y-3"}>
          {outdated && <p className="text-xs text-warning">{t("dlog.dry.outdated")}</p>}
          <p className="text-sm">
            {t("dlog.dry.count", { count: r.count, days: r.days })}{" "}
            {r.count > 0 && <span className="text-muted-foreground">{t("dlog.dry.messages", { count: r.messages, avg: perDay(r), peak: r.peak_per_day })}</span>}
          </p>
          {r.flood && (
            <p role="alert" className="flex items-start gap-2 rounded-lg border border-destructive/40 bg-destructive/10 p-2.5 text-xs">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-destructive" />
              <span>
                <span className="font-medium">{t("dlog.dry.flood")}</span> {t("dlog.dry.floodText", { peak: r.peak_per_day, limit: r.flood_limit })}
              </span>
            </p>
          )}
          {r.items.length > 0 && (
            <ul className="max-h-80 divide-y overflow-y-auto rounded-lg border">
              {r.items.map((x) => (
                <li key={`${x.kind}:${x.id}`} className="space-y-1 px-3 py-2">
                  <p className="text-sm [overflow-wrap:anywhere]">{x.title}</p>
                  <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                    <Pill color={NEWS_SEV_COLOR[x.severity] ?? "--muted-foreground"}>{t(`news.sev.${x.severity}`, { defaultValue: x.severity })}</Pill>
                    <Ts at={x.at} />
                    <span>{t("dlog.dry.because", { parts: matchParts(t, x).join(" · ") })}</span>
                  </p>
                </li>
              ))}
            </ul>
          )}
          {r.truncated && <p className="text-xs text-muted-foreground">{t("dlog.dry.truncated", { shown: r.items.length, count: r.count })}</p>}
        </div>
      )}
    </section>
  )
}
