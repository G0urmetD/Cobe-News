import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import { BellRing, Boxes, CalendarClock, Loader2, Mail, MessageSquare, MonitorSmartphone, MoonStar, Newspaper, Send, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Pill } from "@/components/cobe/badges"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Explained } from "@/components/cobe/explained"
import { Field, ToggleRow } from "@/components/cobe/form"
import { Term } from "@/components/cobe/glossary"
import { SubTabs } from "@/components/cobe/sub-tabs"
import { Ts } from "@/components/cobe/time"
import { api } from "@/lib/api"
import { errorCategoryText } from "@/lib/channels"
import { errorText } from "@/lib/errors"
import { PERSONAL_KINDS, type PersonalKind, type PersonalNotify, type WayState, upcoming, usePersonalNotify, wayState } from "@/lib/teams-api"
import { SaveBar, SettingsCard, SheetActions, SheetBody, SheetLoading } from "@/pages/settings-shared"
import { AbsencePart, QuietPart, WeeklyPart } from "@/pages/settings-delivery"
import { isoList } from "@/lib/bidi"
import { type RuleSystem, useCatalogVendors, vendorsOf } from "@/lib/rule-filters"
import { SystemsPicker } from "@/components/cobe/systems-picker"

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const

/** Settings → Benachrichtigungen → "Hersteller-News meiner Produkte": the Vendor News of the products a person's team
 * gives them, by e-mail, desktop push and their own Microsoft Teams Workflows webhook (app/personal_api.py). */
export function PersonalVendorCard() {
  const { t } = useTranslation()
  const q = usePersonalNotify()
  const [params] = useSearchParams()
  const d = q.data
  // sub-tabs instead of one long page: the ways and what | quiet hours | absence | weekly review (`?part=`) – the last
  // two need a team (a person who only watches CVEs has neither)
  const parts = [
    { key: "ways" as const, icon: BellRing, label: t("delivery.part.ways") },
    { key: "quiet" as const, icon: MoonStar, label: t("delivery.part.quiet") },
    ...(d?.in_team
      ? [
          { key: "absence" as const, icon: CalendarClock, label: t("delivery.part.absence"), alert: !!d.absence?.deputy_absent || d.covering.length > 0 },
          { key: "weekly" as const, icon: Newspaper, label: t("delivery.part.weekly") },
        ]
      : []),
  ]
  type Part = (typeof parts)[number]["key"]
  const asked = params.get("part")
  const part: Part = parts.some((p) => p.key === asked) ? (asked as Part) : "ways"
  const to = (k: Part) => {
    const next = new URLSearchParams(params)
    if (k === "ways") next.delete("part")
    else next.set("part", k)
    return `?${next.toString()}`
  }
  const helpSection = part === "quiet" ? "ruhezeiten" : part === "absence" ? "abwesenheit" : part === "weekly" ? "wochenrueckblick" : "meine-produkte"
  return (
    <SettingsCard
      title={t("personal.title")}
      description={t("personal.desc")}
      actions={<HelpLink chapter="benachrichtigungen" section={helpSection} topic={t("personal.title")} />}
    >
      {!d ? (
        <SheetLoading error={q.error} onRetry={() => void q.refetch()} />
      ) : (
        <>
          <div className="border-b px-5 py-2">
            <SubTabs parts={parts} active={part} to={to} label={t("personal.title")} />
          </div>
          {part === "quiet" ? (
            <QuietPart key={JSON.stringify(d.schedule)} initial={d} />
          ) : part === "absence" ? (
            <AbsencePart initial={d} />
          ) : part === "weekly" ? (
            <WeeklyPart key={JSON.stringify(d.weekly)} initial={d} />
          ) : (
            <PersonalForm key={JSON.stringify(d)} initial={d} />
          )}
        </>
      )}
    </SettingsCard>
  )
}

type Form = { email_on: boolean; desktop_on: boolean; teams_on: boolean; kinds: PersonalKind[]; min_severity: PersonalNotify["min_severity"]; systems: RuleSystem[] }

function PersonalForm({ initial }: { initial: PersonalNotify }) {
  const { t, i18n } = useTranslation()
  const qc = useQueryClient()
  const first: Form = {
    email_on: initial.email.on,
    desktop_on: initial.desktop.on,
    teams_on: initial.teams.on,
    kinds: initial.kinds,
    min_severity: initial.min_severity,
    systems: initial.systems ?? [],
  }
  // "Nur diese Systeme": the vendors and products among my own (a vendor also covers its products assigned later)
  const allVendors = useCatalogVendors(initial.products.length > 0 || (initial.systems ?? []).length > 0)
  const vendors = useMemo(
    () =>
      vendorsOf(
        allVendors,
        initial.products.map((p) => p.key),
      ),
    [allVendors, initial.products],
  )
  const [v, setV] = useState<Form>(first)
  const [url, setUrl] = useState("")
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState(false)
  const lang = i18n.language === "en" ? "en" : "de"
  // the messages' language: the one of the page when saved (no change of its own – switching the page's language alone
  // does not make the form unsaved)
  const dirty = JSON.stringify(v) !== JSON.stringify(first) || url.trim() !== ""
  const needsUrl = v.teams_on && !initial.teams.url_set && !url.trim()
  const valid = v.kinds.length > 0 && !needsUrl
  const allowed = initial.allowed

  const put = async (extra: Record<string, unknown> = {}) => {
    setBusy(true)
    try {
      await api.put("/api/me/vendor-notify", { ...v, lang, ...(url.trim() ? { teams_url: url.trim() } : {}), ...extra })
      toast.success(t("common.saved"))
      setUrl("")
      void qc.invalidateQueries({ queryKey: ["me", "vendor-notify"] })
      void qc.invalidateQueries({ queryKey: ["me", "news-notify"] }) // the one Teams URL: removed, Teams is off there too
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const test = async () => {
    setTesting(true)
    try {
      const r = await api.post<{ ok: boolean; error?: string }>("/api/me/vendor-notify/teams/test")
      if (r.ok) toast.success(t("personal.teams.testSent"))
      else toast.error(t("personal.teams.testFailed"), { description: errorCategoryText(t, r.error ?? "") })
      void qc.invalidateQueries({ queryKey: ["me", "vendor-notify"] })
    } catch (e) {
      toast.error(t("personal.teams.testFailed"), { description: errorText(t, e) })
    } finally {
      setTesting(false)
    }
  }
  const kind = (k: PersonalKind, on: boolean) => setV({ ...v, kinds: PERSONAL_KINDS.filter((x) => (x === k ? on : v.kinds.includes(x))) })

  return (
    <>
      <SheetBody>
        <section aria-labelledby="personal-products" className="space-y-2">
          <p id="personal-products" className="text-sm font-medium">
            <Explained label={t("personal.products")} text={t("personal.productsExplain")} />
          </p>
          {initial.products.length === 0 ? (
            <p className="flex items-center gap-2 rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
              <Boxes className="size-4 shrink-0" /> {initial.in_team === false ? t("personal.noTeamWatch") : t("personal.noProducts")}
            </p>
          ) : (
            <ul className="flex flex-wrap gap-1.5">
              {initial.products.map((p) => (
                <li key={p.key}>
                  <Pill color="--primary" title={t("personal.fromTeams", { teams: isoList(p.teams) })} className="h-auto max-w-full py-0.5 whitespace-normal">
                    <span className="[overflow-wrap:anywhere]">{p.label}</span>
                  </Pill>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section aria-label={t("personal.ways")} className="divide-y rounded-lg border px-3">
          <Way icon={Mail} title={t("personal.email.title")} allowed={allowed.email} state={initial.email.state} on={initial.email.on}>
            <ToggleRow
              label={<WayLabel icon={Mail} text={t("personal.email.title")} />}
              description={initial.email.address_ok ? t("personal.email.to", { address: initial.email.address }) : t("personal.email.noAddress")}
              checked={v.email_on}
              disabled={!initial.email.address_ok && !v.email_on}
              onCheckedChange={(x) => setV({ ...v, email_on: x })}
            />
          </Way>
          <Way
            icon={MonitorSmartphone}
            title={t("personal.desktop.title")}
            allowed={allowed.desktop}
            offText={initial.web_push ? undefined : t("personal.desktop.noPush")}
            state={initial.desktop.state}
            on={initial.desktop.on}
          >
            <ToggleRow
              label={<WayLabel icon={MonitorSmartphone} text={t("personal.desktop.title")} />}
              description={initial.desktop.devices > 0 ? t("personal.desktop.devices", { count: initial.desktop.devices }) : t("personal.desktop.noDevice")}
              checked={v.desktop_on}
              onCheckedChange={(x) => setV({ ...v, desktop_on: x })}
            />
          </Way>
          <Way icon={MessageSquare} title={t("personal.teams.title")} allowed={allowed.teams} state={initial.teams.state} on={initial.teams.on}>
            <ToggleRow
              label={<WayLabel icon={MessageSquare} text={t("personal.teams.title")} />}
              description={
                <>
                  {t("personal.teams.hintBefore")} <Term k="webhook">{t("personal.teams.webhook")}</Term> {t("personal.teams.hintAfter")}
                </>
              }
              checked={v.teams_on}
              onCheckedChange={(x) => setV({ ...v, teams_on: x })}
            />
            {(v.teams_on || initial.teams.url_set) && (
              <div className="space-y-2 pb-3.5">
                <Field label={t("personal.teams.url")} hint={t("personal.teams.urlHint")}>
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
                {needsUrl && <p className="text-xs text-destructive">{t("personal.teams.urlMissing")}</p>}
                {initial.teams.url_set && (
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" variant="outline" disabled={testing || busy || dirty} onClick={() => void test()} title={dirty ? t("personal.teams.saveFirst") : undefined}>
                      {testing ? <Loader2 className="animate-spin" /> : <Send />} {t("personal.teams.test")}
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="text-destructive"
                      disabled={busy}
                      title={t("personal.teams.removeShared")}
                      onClick={() => void put({ teams_on: false, teams_url: "" })}
                    >
                      <Trash2 /> {t("personal.teams.remove")}
                    </Button>
                  </div>
                )}
              </div>
            )}
          </Way>
        </section>

        <section aria-labelledby="personal-what" className="rounded-lg border px-3">
          <p id="personal-what" className="pt-3 text-sm font-medium">
            {t("personal.what")}
          </p>
          <div className="divide-y">
            <ToggleRow
              label={t("personal.kind.vendor_vuln")}
              description={t("notify.kind.vendor_vulnHint")}
              checked={v.kinds.includes("vendor_vuln")}
              onCheckedChange={(x) => kind("vendor_vuln", x)}
            />
            <ToggleRow
              label={t("personal.kind.vendor_version")}
              description={t("notify.kind.vendor_versionHint")}
              checked={v.kinds.includes("vendor_version")}
              onCheckedChange={(x) => kind("vendor_version", x)}
            />
            <ToggleRow
              label={t("personal.kind.vendor_change")}
              description={t("notify.kind.vendor_changeHint")}
              checked={v.kinds.includes("vendor_change")}
              onCheckedChange={(x) => kind("vendor_change", x)}
            />
          </div>
          {v.kinds.length === 0 && <p className="pb-3 text-xs text-destructive">{t("notify.kindsMissing")}</p>}
          <p className="pb-2 text-xs text-muted-foreground">{t("personal.watchAlways")}</p>
          <div className="pb-3.5">
            <Field label={t("personal.minSeverity")} hint={t("personal.minSeverityHint")}>
              <Select value={v.min_severity} onValueChange={(x) => setV({ ...v, min_severity: x as Form["min_severity"] })}>
                <SelectTrigger className="w-full sm:w-64">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper">
                  {SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s === "info" ? t("personal.allSeverities") : t("personal.fromSeverity", { sev: t(`news.sev.${s}`) })}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          </div>
          {(initial.products.length > 0 || v.systems.length > 0) && (
            <div className="pb-3.5">
              <Field label={<Explained label={t("personal.systems")} text={t("personal.systemsExplain")} />} hint={t("personal.systemsHint")}>
                <SystemsPicker
                  value={v.systems}
                  onChange={(x) => setV({ ...v, systems: x })}
                  vendors={vendors}
                  label={vendors ? t("personal.allSystems") : undefined}
                  goneLabel={t("personal.systemGone")}
                  goneName={(name) => t("personal.systemGoneName", { name })}
                />
              </Field>
            </div>
          )}
        </section>
        <p className="rounded-lg bg-muted/60 p-3 text-xs leading-relaxed text-muted-foreground">{t("personal.onlyNew")}</p>
      </SheetBody>
      <SheetActions>
        <span className="text-xs text-muted-foreground">{t("personal.digest")}</span>
        <SaveBar busy={busy} dirty={dirty} disabled={!valid} onSave={() => void put()} />
      </SheetActions>
    </>
  )
}

export function WayLabel({ icon: Icon, text }: { icon: React.ElementType; text: string }) {
  return (
    <span className="flex items-center gap-2">
      <Icon className="size-4 text-muted-foreground" /> {text}
    </span>
  )
}

/** One way: its toggle (and fields) – or "vom Admin ausgeschaltet" – and what its last delivery came to. */
function Way({
  icon: Icon,
  title,
  allowed,
  offText,
  state,
  on,
  children,
}: {
  icon: React.ElementType
  title: string
  allowed: boolean
  offText?: string
  state: WayState
  on: boolean
  children: React.ReactNode
}) {
  const { t } = useTranslation()
  if (!allowed)
    return (
      <div className="flex flex-wrap items-start justify-between gap-2 py-3.5" data-way-off>
        <span className="text-sm font-medium">
          <WayLabel icon={Icon} text={title} />
        </span>
        <span className="flex min-w-0 flex-col items-end gap-1 text-right">
          <Pill color="--muted-foreground">{t("personal.adminOff")}</Pill>
          <span className="text-xs text-muted-foreground">{offText ?? t("personal.adminOffHint")}</span>
        </span>
      </div>
    )
  return (
    <div>
      {children}
      {on && <StateLine state={state} />}
    </div>
  )
}

export function StateLine({ state }: { state: WayState }) {
  const { t } = useTranslation()
  const s = wayState(state)
  if (s.tone === "none") return <p className="-mt-1.5 pb-3 text-xs text-muted-foreground">{t("personal.state.none")}</p>
  if (s.tone === "ok")
    return (
      <p className="-mt-1.5 pb-3 text-xs text-success">
        {t("personal.state.ok")} <Ts at={s.at!} rel />
      </p>
    )
  return (
    <p role="status" className="-mt-1.5 pb-3 text-xs text-warning">
      {t("personal.state.error", { error: errorCategoryText(t, s.error ?? "") })}
      {state.next_try_at && upcoming(state.next_try_at) && (
        <>
          {" "}
          {t("personal.state.next")} <Ts at={state.next_try_at} rel />
        </>
      )}
    </p>
  )
}
