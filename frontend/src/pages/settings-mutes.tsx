import { useTranslation } from "react-i18next"
import { Link } from "react-router"
import { BellOff, BellRing, Boxes, Loader2, ShieldAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { EmptyState, Mono } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { QueryError } from "@/components/cobe/query-state"
import { useMuteActions } from "@/components/cobe/mute-menu"
import { fmtDateTime } from "@/lib/format"
import { remaining, useMutes } from "@/lib/reader-api"
import { SettingsCard } from "@/pages/settings-shared"

/** Settings → Benachrichtigungen → Stummschaltungen: the person's running mutes, what is left of each, "Aufheben". */
export function MutesCard() {
  const { t } = useTranslation()
  const q = useMutes()
  const { unmute, busy } = useMuteActions()
  const items = q.data?.items ?? []
  return (
    <SettingsCard
      title={t("reader.mutes.title")}
      description={t("reader.mutes.desc")}
      actions={<HelpLink chapter="benachrichtigungen" section="stummschalten" topic={t("reader.mutes.title")} />}
    >
      {q.isError ? (
        <QueryError error={q.error} onRetry={() => void q.refetch()} />
      ) : q.isLoading ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin" /> {t("reader.loading")}
        </p>
      ) : items.length === 0 ? (
        <EmptyState icon={BellOff} title={t("reader.mutes.none")} text={t("reader.mutes.noneText")} />
      ) : (
        <ul className="divide-y rounded-lg border">
          {items.map((m) => {
            const left = remaining(m.until)
            return (
              <li key={m.id} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3 py-2.5 text-sm">
                {m.kind === "product" ? <Boxes className="size-4 shrink-0 text-muted-foreground" /> : <ShieldAlert className="size-4 shrink-0 text-muted-foreground" />}
                <span className="min-w-0 flex-1">
                  {m.kind === "product" ? (
                    <Link to={`/vendor?product=${encodeURIComponent(m.key)}`} className="font-medium hover:underline">
                      {m.label}
                    </Link>
                  ) : (
                    <Mono value={m.key} className="font-medium" />
                  )}
                  <span className="block text-xs text-muted-foreground">{t(`reader.mutes.kind.${m.kind}`)}</span>
                </span>
                <span className="text-xs text-muted-foreground tabular-nums" title={fmtDateTime(m.until)}>
                  {t(`reader.mutes.left.${left.unit}`, { count: left.count })}
                </span>
                <Button variant="outline" size="sm" disabled={busy} onClick={() => unmute(m)}>
                  <BellRing /> {t("reader.mutes.lift")}
                </Button>
              </li>
            )
          })}
        </ul>
      )}
      <p className="mt-3 text-xs text-muted-foreground">{t("reader.mute.onlyYou")}</p>
    </SettingsCard>
  )
}
