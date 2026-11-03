import { useTranslation } from "react-i18next"
import { AlertTriangle, Copy, Download, Lock } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Pill } from "@/components/cobe/badges"
import { Explained } from "@/components/cobe/explained"
import { Ts } from "@/components/cobe/time"
import { copyWithToast } from "@/lib/clipboard"
import { api, saveBlob } from "@/lib/api"
import { useTls } from "@/lib/admin-api"
import { errorText } from "@/lib/errors"
import { Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Loading } from "@/pages/settings-shared"

const SERIOUS = new Set(["missing", "expired", "name_mismatch"])

/** HTTPS of the bundled nginx: which certificate is served, until when, and
 *  what needs a look. The mode is set in .env (TLS_MODE) – here it is only shown, with the certificate to hand out. */
export function TlsPane() {
  const { t } = useTranslation()
  const q = useTls()
  const s = q.data
  if (!s) return <Loading error={q.error} onRetry={q.refetch} />
  const hasCert = !!s.not_after
  const pill =
    s.mode === "external"
      ? { color: "--muted-foreground", text: t("tls.mode.external") }
      : s.problems.some((p) => SERIOUS.has(p))
        ? { color: "--destructive", text: t("tls.state.broken") }
        : s.ours
          ? { color: "--success", text: t("tls.mode.selfsigned") }
          : { color: "--success", text: t("tls.mode.own") }
  const download = async () => {
    try {
      const { blob, filename } = await api.getFile("/api/admin/tls/cobe.crt")
      saveBlob(blob, filename)
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  return (
    <Section
      title={t("tls.title")}
      description={t("tls.hint")}
      actions={
        <>
          <HelpLink chapter="betrieb" section="https" topic={t("tls.title")} />
          <Pill color={pill.color} dot>
            {pill.text}
          </Pill>
        </>
      }
    >
      <div className="space-y-4 p-5 text-sm">
        {(s.system ?? []).length > 0 && (
          <ul className="space-y-1.5">
            {(s.system ?? []).map((w) => (
              <li key={w.code} className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs">
                <AlertTriangle className="size-4 shrink-0 text-warning" />
                {w.code === "secret_key_short" ? (
                  <span>{t(`system.warning.secretKeyShort.${w.source}`, { min: w.min })}</span>
                ) : (
                  <span>
                    {t("system.warning.emergencyFailures", { count: w.failures })} <Ts at={w.at} rel />
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
        {s.problems.length > 0 && (
          <ul className="space-y-1.5">
            {s.problems.map((p) => (
              <li
                key={p}
                className={
                  SERIOUS.has(p)
                    ? "flex gap-2 rounded-lg border border-destructive/40 bg-destructive/10 p-2.5 text-xs"
                    : "flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs"
                }
              >
                <AlertTriangle className={SERIOUS.has(p) ? "size-4 shrink-0 text-destructive" : "size-4 shrink-0 text-warning"} />
                <span>{t(`tls.problem.${p}`, { host: s.hostname, defaultValue: p })}</span>
              </li>
            ))}
          </ul>
        )}
        {s.mode === "external" ? (
          <p className="text-muted-foreground">{t("tls.externalText")}</p>
        ) : (
          hasCert && (
            <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
              <div>
                <dt className="text-xs text-muted-foreground">{t("tls.modeLabel")}</dt>
                <dd>
                  <code className="font-mono text-xs">TLS_MODE={s.mode}</code>
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">{t("tls.validUntil")}</dt>
                <dd className="flex flex-wrap items-center gap-2">
                  <Ts at={s.not_after!} />
                  <Pill color={(s.days_left ?? 0) <= 30 ? "--warning" : "--muted-foreground"}>{t("tls.daysLeft", { count: s.days_left ?? 0 })}</Pill>
                </dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-xs text-muted-foreground">{t("tls.renewal")}</dt>
                <dd>
                  {s.renews_at ? (
                    <span>
                      {t("tls.renewsAuto")} <Ts at={s.renews_at} />
                    </span>
                  ) : (
                    <span>{t("tls.renewsOwn")}</span>
                  )}
                </dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-xs text-muted-foreground">
                  <Explained label={t("tls.names")} text={t("tls.namesHint")} />
                </dt>
                <dd className="mt-1 flex flex-wrap gap-1.5">
                  {(s.names ?? []).map((n) => (
                    <code key={n} className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                      {n}
                    </code>
                  ))}
                </dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-xs text-muted-foreground">{t("tls.issuer")}</dt>
                <dd className="font-mono text-xs break-all">{s.self_signed ? t("tls.issuerSelf") : s.issuer}</dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-xs text-muted-foreground">
                  <Explained label={t("tls.fingerprint")} text={t("tls.fingerprintHint")} />
                </dt>
                <dd className="flex items-start gap-2">
                  <code className="min-w-0 flex-1 font-mono text-[11px] break-all">{s.fingerprint}</code>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={t("common.copy")}
                    onClick={() => {
                      void copyWithToast(s.fingerprint ?? "")
                    }}
                  >
                    <Copy />
                  </Button>
                </dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-xs text-muted-foreground">
                  <Explained label="HSTS" text={t("tls.hstsHint")} />
                </dt>
                <dd className="text-xs">{s.hsts ? t("tls.hstsOn") : t("tls.hstsOff")}</dd>
              </div>
            </dl>
          )
        )}
        {s.mode !== "external" && (
          <div className="flex flex-col gap-3 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
            <p className="flex gap-2">
              <Lock className="mt-0.5 size-3.5 shrink-0" />
              <span>{s.ours ? t("tls.selfsignedText") : t("tls.ownText")}</span>
            </p>
            {hasCert && (
              <Button variant="outline" size="sm" onClick={() => void download()} className="shrink-0">
                <Download /> {t("tls.download")}
              </Button>
            )}
          </div>
        )}
      </div>
    </Section>
  )
}
