import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useQueryClient } from "@tanstack/react-query"
import { Mail, MessageSquare, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Field, ToggleRow } from "@/components/cobe/form"
import { api } from "@/lib/api"
import { errorText } from "@/lib/errors"
import { PERSONAL_NEWS_KEY, type PersonalNews, personalNewsBody, usePersonalNews } from "@/lib/personal-news"
import { NewsChoiceFields } from "@/pages/settings-notify"
import { StateLine, WayLabel } from "@/pages/settings-personal"
import { SaveBar, SettingsCard, SheetActions, SheetBody, SheetLoading } from "@/pages/settings-shared"

/** Settings → Benachrichtigungen → "Security-Meldungen": a person's own security stories by e-mail or their Teams
 * Workflows webhook, chosen as a channel rule (app/personal_news_api.py) – only while an admin allows it. */
export function PersonalNewsCard() {
  const { t } = useTranslation()
  const q = usePersonalNews()
  return (
    <SettingsCard
      title={t("personalNews.title")}
      description={t("personalNews.desc")}
      actions={<HelpLink chapter="benachrichtigungen" section="security-meldungen" topic={t("personalNews.title")} />}
    >
      {!q.data ? <SheetLoading error={q.error} onRetry={() => void q.refetch()} /> : <PersonalNewsForm key={JSON.stringify(q.data)} initial={q.data} />}
    </SettingsCard>
  )
}

type Form = Pick<PersonalNews, "severities" | "sources" | "topics" | "systems" | "keywords" | "exclude"> & { email_on: boolean; teams_on: boolean }

function PersonalNewsForm({ initial }: { initial: PersonalNews }) {
  const { t, i18n } = useTranslation()
  const qc = useQueryClient()
  const first: Form = {
    email_on: initial.email.on,
    teams_on: initial.teams.on,
    severities: initial.severities,
    sources: initial.sources,
    topics: initial.topics,
    systems: initial.systems,
    keywords: initial.keywords,
    exclude: initial.exclude,
  }
  const [v, setV] = useState<Form>(first)
  const [url, setUrl] = useState("")
  const [busy, setBusy] = useState(false)
  const dirty = JSON.stringify(v) !== JSON.stringify(first) || url.trim() !== ""
  const needsUrl = v.teams_on && !initial.teams.url_set && !url.trim()
  const save = async (extra: Record<string, unknown> = {}) => {
    setBusy(true)
    try {
      await api.put("/api/me/news-notify", { ...personalNewsBody(v, i18n.language, url), ...extra })
      toast.success(t("common.saved"))
      setUrl("")
      void qc.invalidateQueries({ queryKey: PERSONAL_NEWS_KEY })
      void qc.invalidateQueries({ queryKey: ["me", "vendor-notify"] }) // the Teams URL is the same one
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <SheetBody>
        {!initial.available && <p className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">{t("personalNews.adminOff")}</p>}
        <section aria-label={t("personal.ways")} className="divide-y rounded-lg border px-3">
          {/* a way the admin does not allow (any more): shown only while it is on – to switch it off */}
          {(initial.allowed.email || initial.email.on) && (
            <div>
              <ToggleRow
                label={<WayLabel icon={Mail} text={t("personal.email.title")} />}
                description={initial.email.address_ok ? t("personal.email.to", { address: initial.email.address }) : t("personal.email.noAddress")}
                checked={v.email_on}
                disabled={(!initial.email.address_ok || !initial.allowed.email) && !v.email_on}
                onCheckedChange={(x) => setV({ ...v, email_on: x })}
              />
              {initial.email.on && <StateLine state={initial.email.state} />}
            </div>
          )}
          {(initial.allowed.teams || initial.teams.on) && (
            <div>
              <ToggleRow
                label={<WayLabel icon={MessageSquare} text={t("personal.teams.title")} />}
                description={t("personalNews.teamsHint")}
                checked={v.teams_on}
                disabled={!initial.allowed.teams && !v.teams_on}
                onCheckedChange={(x) => setV({ ...v, teams_on: x })}
              />
              {(v.teams_on || initial.teams.url_set) && (
                <div className="pb-3.5">
                  <Field label={t("personal.teams.url")} hint={t("personalNews.urlHint")}>
                    <Input
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder={initial.teams.url_hint ? t("personal.teams.urlSaved", { hint: initial.teams.url_hint }) : "https://….logic.azure.com/workflows/…"}
                      autoComplete="off"
                      spellCheck={false}
                      inputMode="url"
                      className="font-mono text-xs"
                    />
                  </Field>
                  {needsUrl && <p className="mt-1 text-xs text-destructive">{t("personal.teams.urlMissing")}</p>}
                  {initial.teams.url_set && (
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      <Button size="sm" variant="ghost" className="text-destructive" disabled={busy} onClick={() => void save({ teams_on: false, teams_url: "" })}>
                        <Trash2 /> {t("personal.teams.remove")}
                      </Button>
                      <span className="text-xs text-muted-foreground">{t("personalNews.urlShared")}</span>
                    </div>
                  )}
                </div>
              )}
              {initial.teams.on && <StateLine state={initial.teams.state} />}
            </div>
          )}
        </section>
        <div className="grid gap-4 sm:grid-cols-2">
          <NewsChoiceFields value={v} onChange={(x) => setV({ ...v, ...x })} laterHint="personalNews" />
        </div>
        <p className="rounded-lg bg-muted/60 p-3 text-xs leading-relaxed text-muted-foreground">{t("personalNews.about")}</p>
      </SheetBody>
      <SheetActions>
        <SaveBar busy={busy} dirty={dirty} disabled={needsUrl} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}
