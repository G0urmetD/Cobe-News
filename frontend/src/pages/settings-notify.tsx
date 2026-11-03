import { useCallback, useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { useSearchParams } from "react-router"
import { type QueryClient, useQueryClient } from "@tanstack/react-query"
import { BellRing, Loader2, Pencil, Plus, RadioTower, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Pill } from "@/components/cobe/badges"
import { confirmAction } from "@/components/cobe/confirm"
import { EmptyState, Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Explained } from "@/components/cobe/explained"
import { EnableCard, Field, LockedFields, ToggleRow } from "@/components/cobe/form"
import { MultiSelect } from "@/components/cobe/multi-select"
import { api } from "@/lib/api"
import { type NotifyChannel, type NotifyRule, RULE_KINDS, type RuleIn, type RuleKind, useChannels, useRules, useSmtp } from "@/lib/admin-api"
import { errorCategoryText, mailServerMissing, uiLang } from "@/lib/channels"
import { type ShowOutcome, TRACK_MS, currentSystem, desktopSecure, desktopSupported, showStory, useLastRound, useNotificationPermission, waitForShown } from "@/lib/desktop"
import { type PushBlock, type PushInfo, disablePush, enablePush, pushActiveHere, pushAvailability, pushHere, pushHost, testPush } from "@/lib/push"
import { useAuth } from "@/lib/auth"
import { useTeams, useTeamsSettings } from "@/lib/teams-api"
import { errorText, isStale } from "@/lib/errors"
import { cn } from "@/lib/utils"
import { confirmDiscard } from "@/lib/unsaved"
import { NEWS_SEVERITIES, NEWS_TOPICS, type DesktopPrefs, type NewsSeverity, type NewsTopic, useAdminNews, useDesktopPrefs, useNewsSources } from "@/lib/news-api"
import { ChannelIcon, ChannelsPane } from "@/pages/settings-channels"
import { DeliveryLogPane } from "@/pages/settings-delivery-log"
import { DryRunPanel } from "@/pages/settings-dry-run"
import { Loading, SaveBar, SettingsCard, SheetActions, SheetBody, SheetLoading, StaleNotice } from "@/pages/settings-shared"

function SeverityPicker({ value, onChange }: { value: NewsSeverity[]; onChange: (v: NewsSeverity[]) => void }) {
  const { t } = useTranslation()
  return (
    <MultiSelect
      variant="field"
      label={t("notify.allSeverities")}
      options={NEWS_SEVERITIES.map((x) => ({ value: x, label: t(`news.sev.${x}`) }))}
      value={value}
      onChange={(v) => onChange(NEWS_SEVERITIES.filter((x) => v.includes(x)))}
      searchable={false}
    />
  )
}

/** Topics of a story (OR) – none chosen: every story, whatever its topics. Each with its explanation. */
function TopicPicker({ value, onChange }: { value: NewsTopic[]; onChange: (v: NewsTopic[]) => void }) {
  const { t } = useTranslation()
  return (
    <MultiSelect
      variant="field"
      label={t("notify.allTopics")}
      options={NEWS_TOPICS.map((x) => ({ value: x, label: t(`news.topic.${x}`), description: t(`news.topicHint.${x}`) }))}
      value={value}
      onChange={(v) => onChange(NEWS_TOPICS.filter((x) => v.includes(x)))}
      searchable={false}
      contentClassName="w-80"
    />
  )
}

function SourcePicker({ value, onChange, options }: { value: string[]; onChange: (v: string[]) => void; options: { id: string; name: string }[] }) {
  const { t } = useTranslation()
  return (
    <MultiSelect
      variant="field"
      label={t("notify.allSources")}
      options={options.map((s) => ({ value: s.id, label: s.name }))}
      value={value.filter((id) => options.some((s) => s.id === id))}
      onChange={onChange}
    />
  )
}

// ---------------------------------------------------------------- channels | rules

/** Settings → Channels & rules: where to (channels) and what (rules) – sub-tabs, `?tab=rules`. */
export function NotifySettings() {
  const { t } = useTranslation()
  const [params, setParams] = useSearchParams()
  const asked = params.get("tab")
  const tab = asked === "rules" || asked === "log" ? asked : "channels"
  const switchTab = async (v: string) => {
    if (await confirmDiscard()) setParams(v === "channels" ? {} : { tab: v }, { replace: true })
  }
  return (
    <Tabs value={tab} onValueChange={(v) => void switchTab(v)} className="gap-6">
      <TabsList>
        <TabsTrigger value="channels">{t("settings.tab.channels")}</TabsTrigger>
        <TabsTrigger value="rules">{t("settings.tab.rules")}</TabsTrigger>
        <TabsTrigger value="log">{t("dlog.title")}</TabsTrigger>
      </TabsList>
      <TabsContent value="channels">
        <ChannelsPane />
      </TabsContent>
      <TabsContent value="rules">
        <RulesPane onChannels={() => void switchTab("channels")} />
      </TabsContent>
      <TabsContent value="log">
        <DeliveryLogPane />
      </TabsContent>
    </Tabs>
  )
}

// ---------------------------------------------------------------- rules

const toBody = (r: NotifyRule, patch: Partial<RuleIn> = {}): RuleIn => ({
  name: r.name,
  enabled: r.enabled,
  channels: r.channels,
  severities: r.severities,
  sources: r.sources,
  topics: r.topics ?? [],
  lang: r.lang,
  kinds: r.kinds,
  teams: r.teams ?? [],
  ...patch,
})

const refreshNotify = (qc: QueryClient) => {
  void qc.invalidateQueries({ queryKey: ["admin", "rules"] })
  void qc.invalidateQueries({ queryKey: ["admin", "channels"] })
}

/** The rules: the list, or one rule in the editor (list ↔ editor in the same tab). */
function RulesPane({ onChannels }: { onChannels: () => void }) {
  const qc = useQueryClient()
  const rules = useRules().data
  // the rule being edited by id (its stored state from the list); `key`: a fresh form after "load the current state"
  const [editing, setEditing] = useState<{ id: string | "new"; key: number } | null>(null)
  const rule = editing && editing.id !== "new" ? (rules?.find((r) => r.id === editing.id) ?? null) : null
  // removed by another admin meanwhile: back to the list
  if (editing && editing.id !== "new" && rules && !rule) setEditing(null)
  if (editing) {
    if (editing.id !== "new" && !rule) return <Loading />
    return (
      <RuleEditor
        key={editing.key}
        rule={rule}
        onDone={() => setEditing(null)}
        onChannels={onChannels}
        onStale={() => refreshNotify(qc)}
        onReload={() =>
          // the form is rebuilt from the list: first the list as it is stored now (not the cached state that was refused)
          void qc.refetchQueries({ queryKey: ["admin", "rules"] }).then(() => setEditing((e) => e && { ...e, key: e.key + 1 }))
        }
      />
    )
  }
  return <RuleList onEdit={(r) => setEditing({ id: r === "new" ? "new" : r.id, key: 0 })} onChannels={onChannels} />
}

/** A channel of a rule: icon and name – in warning colour while it cannot send (no mail server) or its last send failed. */
function ChannelChip({ c }: { c: NotifyChannel }) {
  const { t } = useTranslation()
  const noServer = mailServerMissing(c, useSmtp().data)
  const problem = noServer ? t("channels.mailMissing") : c.last_error ? errorCategoryText(t, c.last_error) : null
  return (
    <Pill color={problem ? "--warning" : "--muted-foreground"} title={problem ?? t(`notify.channel.${c.type}`)}>
      <ChannelIcon type={c.type} /> {c.name}
    </Pill>
  )
}

function RuleList({ onEdit, onChannels }: { onEdit: (r: NotifyRule | "new") => void; onChannels: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useRules()
  const ch = useChannels()
  const sources = useAdminNews().data?.sources ?? []
  const teamList = useTeams().data ?? []
  const ruleTeams = (r: NotifyRule) => (r.teams ?? []).map((id) => teamList.find((x) => x.id === id)?.name ?? "?")
  // a switch being saved stays disabled until the list holds the rule's new version – a second click before that
  // would be sent with the old version and refused as "changed by someone else"
  const [pending, setPending] = useState<ReadonlySet<string>>(new Set())
  const toggle = async (r: NotifyRule, enabled: boolean) => {
    setPending((p) => new Set(p).add(r.id))
    try {
      await api.put(`/api/admin/notify/rules/${r.id}`, { ...toBody(r, { enabled }), version: r.version })
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      // the list as it is now (also after a refusal: another admin changed the rule meanwhile)
      await Promise.all([qc.refetchQueries({ queryKey: ["admin", "rules"] }), qc.invalidateQueries({ queryKey: ["admin", "channels"] })])
      setPending((p) => {
        const n = new Set(p)
        n.delete(r.id)
        return n
      })
    }
  }
  const remove = async (r: NotifyRule) => {
    if (!(await confirmAction({ title: t("notify.removeTitle"), text: t("notify.removeText", { name: r.name }), confirm: t("common.remove") }))) return
    try {
      await api.del(`/api/admin/notify/rules/${r.id}`)
      refreshNotify(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  if (!q.data || !ch.data) return <Loading error={q.error ?? ch.error} onRetry={() => void (q.refetch(), ch.refetch())} />
  const channels = ch.data
  const none = channels.length === 0
  return (
    <Section
      title={t("settings.tab.rules")}
      description={t("notify.rulesHint")}
      actions={
        <>
          <HelpLink chapter="benachrichtigungen" section="regeln" topic={t("settings.tab.rules")} />
          <Button size="sm" disabled={none} title={none ? t("notify.channelFirstTitle") : undefined} onClick={() => onEdit("new")}>
            <Plus /> {t("notify.newRule")}
          </Button>
        </>
      }
    >
      {none && (
        <div className="p-5">
          <EmptyState
            icon={RadioTower}
            title={t("notify.channelFirstTitle")}
            text={t("notify.channelFirstText")}
            action={
              <Button size="sm" variant="outline" onClick={onChannels}>
                <RadioTower /> {t("notify.toChannels")}
              </Button>
            }
          />
        </div>
      )}
      {q.data.length === 0 && !none ? (
        <div className="p-5">
          <EmptyState icon={BellRing} title={t("notify.emptyTitle")} text={t("notify.emptyText")} />
        </div>
      ) : (
        q.data.length > 0 && (
          <ul className={none ? "divide-y border-t" : "divide-y"}>
            {q.data.map((r) => {
              const names = r.sources.map((id) => sources.find((s) => s.id === id)?.name).filter(Boolean)
              const used = r.channels.map((id) => channels.find((c) => c.id === id)).filter((c): c is NotifyChannel => !!c)
              return (
                <li key={r.id} className="flex items-start gap-3 px-5 py-3">
                  <span className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted">
                    <BellRing className="size-4" />
                  </span>
                  <div className="min-w-0 flex-1 space-y-1.5">
                    <p className="text-sm font-medium">{r.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {r.kinds.map((k) => t(`notify.kind.${k}`)).join(", ") +
                        " · " +
                        (r.severities.length ? r.severities.map((s) => t(`news.sev.${s}`)).join(", ") : t("notify.allSeverities")) +
                        " · " +
                        (names.length ? names.join(", ") : t("notify.allSources")) +
                        (r.topics?.length && r.kinds.includes("news") ? " · " + t("notify.topicsList", { names: r.topics.map((x) => t(`news.topic.${x}`)).join(", ") }) : "") +
                        (ruleTeams(r).length ? " · " + t("notify.teamsList", { names: ruleTeams(r).join(", ") }) : "") +
                        " · " +
                        (r.lang === "en" ? "English" : "Deutsch")}
                    </p>
                    <div className="flex flex-wrap gap-1">
                      {used.length ? used.map((c) => <ChannelChip key={c.id} c={c} />) : <Pill color="--warning">{t("notify.noChannel")}</Pill>}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <Button variant="ghost" size="icon-sm" aria-label={t("common.edit")} title={t("common.edit")} onClick={() => onEdit(r)}>
                      <Pencil />
                    </Button>
                    <Button variant="ghost" size="icon-sm" aria-label={t("common.remove")} title={t("common.remove")} onClick={() => void remove(r)}>
                      <Trash2 />
                    </Button>
                    <Switch
                      checked={r.enabled}
                      disabled={pending.has(r.id)}
                      onCheckedChange={(x) => void toggle(r, x)}
                      aria-label={t("notify.toggle", { name: r.name })}
                      className="ml-1"
                    />
                  </div>
                </li>
              )
            })}
          </ul>
        )
      )}
    </Section>
  )
}

function RuleEditor({
  rule,
  onDone,
  onChannels,
  onStale,
  onReload,
}: {
  rule: NotifyRule | null
  onDone: () => void
  onChannels: () => void
  /** the save was refused as stale: the list loads the current state */
  onStale: () => void
  /** a fresh form on the rule as it is stored now */
  onReload: () => void
}) {
  const { t, i18n } = useTranslation()
  const qc = useQueryClient()
  const sources = useAdminNews().data?.sources ?? []
  const channels = useChannels().data ?? []
  // a channel deleted in the meantime is no longer offered (nor kept)
  const [initial] = useState<RuleIn>(() =>
    rule
      ? toBody(rule, { channels: rule.channels.filter((id) => channels.some((c) => c.id === id)) })
      : {
          name: "",
          enabled: true,
          channels: channels.length === 1 ? [channels[0].id] : [],
          severities: ["critical", "high"],
          sources: [],
          topics: [],
          lang: uiLang(i18n.language),
          kinds: ["news"],
          teams: [],
        },
  )
  const [v, setV] = useState<RuleIn>(initial)
  // the stored state this edit is made on – another admin's save in between makes the server refuse it (409 stale)
  const [version] = useState(rule?.version)
  const [stale, setStale] = useState(false)
  const [busy, setBusy] = useState(false)
  const teamsOn = !!useTeamsSettings().data?.enabled
  const teamList = useTeams().data ?? []
  const vendorKinds = v.kinds.some((k) => k === "vendor_vuln" || k === "vendor_version" || k === "vendor_change")
  const valid = v.name.trim().length >= 2 && v.channels.length > 0 && v.kinds.length > 0
  const kind = (k: RuleKind, on: boolean) => setV({ ...v, kinds: on ? RULE_KINDS.filter((x) => x === k || v.kinds.includes(x)) : v.kinds.filter((x) => x !== k) })
  const body = { ...v, name: v.name.trim() }
  const dirty = JSON.stringify(body) !== JSON.stringify(initial)
  const save = async () => {
    setBusy(true)
    try {
      if (rule) await api.put(`/api/admin/notify/rules/${rule.id}`, { ...body, version })
      else await api.post("/api/admin/notify/rules", body)
      toast.success(t("common.saved"))
      refreshNotify(qc)
      onDone()
    } catch (e) {
      toast.error(errorText(t, e))
      if (isStale(e)) {
        setStale(true)
        onStale()
      }
    } finally {
      setBusy(false)
    }
  }
  return (
    <SettingsCard title={rule ? t("notify.editTitle") : t("notify.newRule")} description={t("notify.rulesHint")}>
      <SheetBody>
        {stale && <StaleNotice onReload={onReload} />}
        <ToggleRow label={t("notify.enabled")} description={t("notify.enabledHint")} checked={v.enabled} onCheckedChange={(x) => setV({ ...v, enabled: x })} className="py-0" />
        <div className="grid gap-4 sm:grid-cols-[2fr_1fr]">
          <Field label={t("notify.name")}>
            <Input value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} placeholder={t("notify.namePlaceholder")} maxLength={100} />
          </Field>
          <Field label={t("notify.lang")}>
            <Select value={v.lang} onValueChange={(x) => setV({ ...v, lang: x as "de" | "en" })}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value="de">Deutsch</SelectItem>
                <SelectItem value="en">English</SelectItem>
              </SelectContent>
            </Select>
          </Field>
        </div>
        <Field label={t("notify.channels")} hint={t("notify.channelsHint")}>
          <MultiSelect
            variant="field"
            label={t("notify.channelsPick")}
            options={channels.map((c) => ({ value: c.id, label: c.name, hint: t(`notify.channel.${c.type}`), icon: <ChannelIcon type={c.type} className="size-4" /> }))}
            value={v.channels}
            onChange={(x) => setV({ ...v, channels: x })}
            searchable={channels.length > 6}
          />
        </Field>
        <div className="-mt-2">
          <Button variant="link" size="xs" className="h-auto px-0" onClick={onChannels}>
            <Plus /> {t("notify.newChannel")}
          </Button>
        </div>
        <section className="rounded-lg border px-3">
          <p className="pt-3 text-sm font-medium">{t("notify.kinds")}</p>
          <div className="divide-y">
            {RULE_KINDS.map((k) => (
              <ToggleRow key={k} label={t(`notify.kind.${k}`)} description={t(`notify.kind.${k}Hint`)} checked={v.kinds.includes(k)} onCheckedChange={(x) => kind(k, x)} />
            ))}
          </div>
          {v.kinds.length === 0 && <p className="pb-3 text-xs text-destructive">{t("notify.kindsMissing")}</p>}
        </section>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            label={t("notify.severities")}
            hint={t(v.kinds.includes("vendor_vuln") || v.kinds.includes("vendor_change") ? "notify.severitiesHintVendor" : "notify.severitiesHint")}
          >
            <SeverityPicker value={v.severities} onChange={(x) => setV({ ...v, severities: x })} />
          </Field>
          {v.kinds.includes("news") && (
            <Field label={t("notify.sources")} hint={t("notify.sourcesHint")}>
              <SourcePicker value={v.sources} onChange={(x) => setV({ ...v, sources: x })} options={sources} />
            </Field>
          )}
          {v.kinds.includes("news") && (
            <Field label={<Explained label={t("notify.topics")} text={t("notify.topicsExplain")} />} hint={t("notify.topicsHint")} className="sm:col-span-2">
              <TopicPicker value={v.topics} onChange={(x) => setV({ ...v, topics: x })} />
            </Field>
          )}
        </div>
        {(teamsOn || v.teams.length > 0) && (
          <Field label={<Explained label={t("notify.teams")} text={t("notify.teamsExplain")} />} hint={t(vendorKinds ? "notify.teamsHint" : "notify.teamsHintNoVendor")}>
            <MultiSelect
              variant="field"
              label={t("notify.allTeams")}
              options={teamList.map((x) => ({ value: x.id, label: x.name }))}
              value={v.teams.filter((id) => teamList.some((x) => x.id === id))}
              onChange={(x) => setV({ ...v, teams: x })}
              searchable={teamList.length > 6}
            />
          </Field>
        )}
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("notify.onlyNew")}</p>
        {vendorKinds && <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("notify.vendorOnce")}</p>}
        {v.kinds.includes("vendor_change") && <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("notify.vendorChangeOnly")}</p>}
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("notify.batching")}</p>
        <DryRunPanel rule={v} />
      </SheetBody>
      <SheetActions>
        <Button variant="ghost" onClick={() => void confirmDiscard().then((ok) => ok && onDone())}>
          {t("common.cancel")}
        </Button>
        <SaveBar busy={busy} dirty={dirty} disabled={!valid || stale} onSave={() => void save()} />
      </SheetActions>
    </SettingsCard>
  )
}

// ---------------------------------------------------------------- desktop (per person)

/** Desktop notifications of the signed-in person – in the admin settings and under "Mein Konto". */
export function DesktopPane() {
  const q = useDesktopPrefs()
  if (!q.data) return <SheetLoading error={q.error} onRetry={q.refetch} />
  return <DesktopForm key={JSON.stringify(q.data)} initial={q.data} />
}

function DesktopForm({ initial }: { initial: DesktopPrefs }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const sources = useNewsSources().data ?? []
  const [v, setV] = useState(initial)
  const perm = useNotificationPermission()
  const [busy, setBusy] = useState(false)
  const dirty = JSON.stringify(v) !== JSON.stringify(initial)
  const supported = desktopSupported() && desktopSecure()
  const [test, setTest] = useState<TestState | null>(null)
  const save = async (next = v) => {
    setBusy(true)
    try {
      await api.put("/api/me/desktop", next)
      toast.success(t("common.saved"))
      void qc.invalidateQueries({ queryKey: ["me", "desktop"] })
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const enable = async (on: boolean) => {
    if (on && supported && Notification.permission === "default") await Notification.requestPermission()
    setV({ ...v, enabled: on })
  }
  return (
    <>
      <SheetBody>
        <EnableCard label={t("desktop.enabled")} description={t("desktop.enabledHint")} checked={v.enabled} onCheckedChange={(x) => void enable(x)} />
        {!supported && <p className="rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs">{desktopSupported() ? t("desktop.insecure") : t("desktop.unsupported")}</p>}
        {supported && <DesktopStatus perm={perm} saved={initial.enabled} wanted={v.enabled} />}
        {test && <TestOutcome test={test} />}
        <LockedFields locked={!v.enabled} className="grid gap-4 sm:grid-cols-2">
          <Field label={t("notify.severities")} hint={t("notify.severitiesHint")}>
            <SeverityPicker value={v.severities} onChange={(x) => setV({ ...v, severities: x })} />
          </Field>
          <Field label={t("notify.sources")} hint={t("notify.sourcesHint")}>
            <SourcePicker value={v.sources} onChange={(x) => setV({ ...v, sources: x })} options={sources} />
          </Field>
          <Field label={<Explained label={t("notify.topics")} text={t("desktop.topicsExplain")} />} hint={t("desktop.topicsHint")} className="sm:col-span-2">
            <TopicPicker value={v.topics ?? []} onChange={(x) => setV({ ...v, topics: x })} />
          </Field>
        </LockedFields>
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("desktop.about")}</p>
      </SheetBody>
      <SheetActions>
        <TestButton disabled={!supported || perm !== "granted"} onState={setTest} />
        <SaveBar busy={busy} dirty={dirty} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}

const TEST_DELAY_S = 5

/** Seconds left, every quarter second – the button counts down. */
function countdown(seconds: number, onLeft: (s: number) => void) {
  const started = Date.now()
  return setInterval(() => onLeft(Math.max(0, seconds - Math.floor((Date.now() - started) / 1000))), 250)
}

/** The test's way and what came of it: waiting for the browser, shown, refused (with the reason) or no answer. */
type TestState = { via: "push" | "tab"; host?: string; outcome: ShowOutcome | "waiting" }

/**
 * A test notification after 5 s – time to switch to another tab or app and see it arrive in the background. It takes
 * the way the real ones take in this browser: push when push works here, else the tab. Then it says what became of it:
 * the service worker (push) or the notification itself (tab) reports shown or refused; nothing within 20 s is said too.
 */
function TestButton({ disabled, onState }: { disabled: boolean; onState: (s: TestState | null) => void }) {
  const { t } = useTranslation()
  const { user } = useAuth()
  const [left, setLeft] = useState(0)
  const stopRef = useRef<(() => void) | null>(null)
  useEffect(() => () => stopRef.current?.(), [])
  const start = () => {
    const viaPush = !!user && pushActiveHere(user.id)
    toast.info(t("desktop.testSoon", { s: TEST_DELAY_S }), { description: t(viaPush ? "desktop.testViaPush" : "desktop.testViaTab") })
    onState(null)
    setLeft(TEST_DELAY_S)
    const id = countdown(TEST_DELAY_S, setLeft)
    setTimeout(() => {
      clearInterval(id)
      setLeft(0)
      if (viaPush) void runPush()
      else {
        onState({ via: "tab", outcome: "waiting" })
        void showStory(
          { id: `test-${Date.now()}`, title: t("desktop.testTitle"), severity: "high", source: { id: "", key: "", name: "Cobe News", logo: false } },
          () => undefined,
          true,
        ).then((outcome) => onState({ via: "tab", outcome }))
      }
    }, TEST_DELAY_S * 1000)
  }
  const runPush = async () => {
    // listening before the server sends: the worker can answer within milliseconds; the 20 s count from the moment the
    // server handed the test to the push service (the request itself may take a while)
    const wait = waitForShown("test", 3 * TRACK_MS)
    stopRef.current = wait.stop
    let host: string | undefined
    try {
      host = await testPush()
    } catch (e) {
      wait.stop()
      onState(null)
      toast.error(t("desktop.testPushFailed"), { description: errorText(t, e) })
      return
    }
    onState({ via: "push", host, outcome: "waiting" })
    const timer = setTimeout(wait.stop, TRACK_MS)
    const outcome = await wait.done
    clearTimeout(timer)
    onState({ via: "push", host, outcome })
  }
  return (
    <Button variant="outline" disabled={disabled || left > 0} onClick={start}>
      <BellRing /> {left > 0 ? t("desktop.testIn", { s: left }) : t("desktop.test")}
    </Button>
  )
}

/** What the test came to – with where to look when the browser handed it over but nothing appeared. */
function TestOutcome({ test }: { test: TestState }) {
  const { t } = useTranslation()
  const sys = currentSystem()
  const browser = sys.browser || t("desktop.result.theBrowser")
  const o = test.outcome
  const tone = o === "waiting" ? "border-border bg-muted/40" : o.ok === true ? "border-success/40 bg-success/5" : "border-warning/40 bg-warning/10"
  return (
    <div role="status" aria-live="polite" className={cn("space-y-1.5 rounded-lg border p-3 text-xs leading-relaxed", tone)}>
      {o === "waiting" ? (
        <p className="flex items-center gap-2">
          <Loader2 className="size-3.5 animate-spin" /> {t(test.via === "push" ? "desktop.result.waitingPush" : "desktop.result.waitingTab")}
        </p>
      ) : o.ok === true ? (
        <>
          <p className="font-medium">{t("desktop.result.shown", { browser })}</p>
          <p className="text-muted-foreground">
            {t("desktop.result.nothing")} {t(`desktop.result.hint.${sys.os}`, { browser })}
          </p>
        </>
      ) : o.ok === false ? (
        <>
          <p className="font-medium">{t("desktop.result.refused", { error: o.error === "error" ? t("desktop.result.noReason") : o.error })}</p>
          <p className="text-muted-foreground">
            {t("desktop.denied")} {t(`desktop.result.hint.${sys.os}`, { browser })}
          </p>
        </>
      ) : test.via === "push" ? (
        <p>{t("desktop.result.timeoutPush", { s: TRACK_MS / 1000, host: test.host || t("desktop.result.pushService") })}</p>
      ) : (
        <p>{t("desktop.result.timeoutTab", { s: TRACK_MS / 1000 })}</p>
      )}
    </div>
  )
}

function StatusRow({ label, help, children }: { label: string; help: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1.5 py-2.5 first:pt-0 last:pb-0">
      <span className="text-sm font-medium">
        <Explained label={label} text={help} />
      </span>
      <div className="flex min-w-0 flex-col items-end gap-1 text-right">{children}</div>
    </div>
  )
}

/** What works in this browser right now: permission, the background tab, push with the tab closed. */
function DesktopStatus({ perm, saved, wanted }: { perm: NotificationPermission | "unsupported"; saved: boolean; wanted: boolean }) {
  const { t, i18n } = useTranslation()
  const { user } = useAuth()
  const last = useLastRound(user?.id)
  const [now, setNow] = useState(() => Date.now())
  const [push, setPush] = useState<{ loading: boolean; on: boolean; block?: PushBlock; detail?: string; error?: string | null; host?: string | null }>({
    loading: true,
    on: false,
  })
  const [pushBusy, setPushBusy] = useState(false)
  const uid = user?.id

  const refreshPush = useCallback(async () => {
    const av = await pushAvailability()
    if (!av.ok) return setPush({ loading: false, on: false, block: av.why, detail: av.detail })
    try {
      const info = await api.get<PushInfo>("/api/me/push")
      if (!info.enabled) return setPush({ loading: false, on: false, block: "server_off" })
      const { sub, state } = await pushHere()
      const on = !!sub && state.registered && !!uid && pushActiveHere(uid)
      // the stored error is "<category>[: detail]": shown as the category's text, never the raw code
      setPush({
        loading: false,
        on,
        error: on && state.ok === false && state.last_error ? errorCategoryText(t, state.last_error) : null,
        host: sub ? pushHost(sub.endpoint) : null,
      })
    } catch (e) {
      setPush({ loading: false, on: false, error: errorText(t, e) })
    }
  }, [t, uid])

  useEffect(() => {
    void Promise.resolve().then(refreshPush) // registers the service worker: asynchronous anyway
    const id = setInterval(() => setNow(Date.now()), 5_000) // "checked 20 s ago" stays current
    return () => clearInterval(id)
  }, [refreshPush])

  const togglePush = async (on: boolean) => {
    if (!uid) return
    setPushBusy(true)
    try {
      if (on) {
        const r = await enablePush(uid, i18n.language)
        if (!r.ok) toast.error(t(`desktop.pushBlock.${r.why}`, { detail: r.detail ?? "" }))
        else toast.success(t("desktop.pushOn"))
      } else {
        await disablePush(uid)
        toast.success(t("desktop.pushOff"))
      }
    } catch (e) {
      toast.error(t("desktop.pushFailed"), { description: errorText(t, e) })
    } finally {
      setPushBusy(false)
      await refreshPush()
    }
  }

  const ago = last ? Math.max(0, Math.round((Math.max(now, last.at) - last.at) / 1000)) : null
  const permPill =
    perm === "granted" ? (
      <Pill color="--success" dot>
        {t("desktop.perm.granted")}
      </Pill>
    ) : perm === "denied" ? (
      <Pill color="--warning" dot>
        {t("desktop.perm.denied")}
      </Pill>
    ) : (
      <Pill color="--muted-foreground" dot>
        {t("desktop.perm.default")}
      </Pill>
    )
  const tab = !saved ? (
    <Pill color="--muted-foreground" dot>
      {wanted ? t("desktop.tab.unsaved") : t("desktop.tab.off")}
    </Pill>
  ) : perm !== "granted" ? (
    <Pill color="--warning" dot>
      {t("desktop.tab.waiting")}
    </Pill>
  ) : last && !last.ok ? (
    <Pill color="--warning" dot>
      {t("desktop.tab.error")}
    </Pill>
  ) : (
    <Pill color="--success" dot>
      {t("desktop.tab.active")}
    </Pill>
  )
  return (
    <div className="rounded-xl border p-3.5">
      <p className="mb-2.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">{t("desktop.stateTitle")}</p>
      <div className="divide-y">
        <StatusRow label={t("desktop.perm.label")} help={t("desktop.perm.help")}>
          {permPill}
          {perm === "denied" && <span className="max-w-xs text-xs text-muted-foreground">{t("desktop.denied")}</span>}
          {perm === "default" && (
            <Button size="sm" variant="outline" onClick={() => void Notification.requestPermission()}>
              <BellRing /> {t("desktop.askPermission")}
            </Button>
          )}
        </StatusRow>
        <StatusRow label={t("desktop.tab.label")} help={t("desktop.tab.help")}>
          {tab}
          {saved && perm === "granted" && ago !== null && <span className="text-xs text-muted-foreground">{t("desktop.tab.checked", { s: ago })}</span>}
        </StatusRow>
        <StatusRow label={t("desktop.push.label")} help={t("desktop.push.help")}>
          <div className="flex items-center gap-2">
            {push.loading ? (
              <Loader2 className="size-4 animate-spin text-muted-foreground" />
            ) : push.block ? (
              <Pill color="--muted-foreground" dot>
                {t("desktop.push.unavailable")}
              </Pill>
            ) : push.error ? (
              <Pill color="--warning" dot>
                {t("desktop.push.failing")}
              </Pill>
            ) : (
              <Pill color={push.on ? "--success" : "--muted-foreground"} dot>
                {push.on ? t("desktop.push.active") : t("desktop.push.off")}
              </Pill>
            )}
            <Switch
              aria-label={t("desktop.push.label")}
              checked={push.on}
              disabled={push.loading || pushBusy || !!push.block || !saved || perm === "denied"}
              onCheckedChange={(x) => void togglePush(x)}
            />
          </div>
          {push.block && (
            <span className="max-w-sm text-xs text-muted-foreground">
              {t(`desktop.pushBlock.${push.block}`, { detail: push.detail ?? "" })} {t("desktop.push.tabStillWorks")}
            </span>
          )}
          {!push.block && !push.loading && (
            <span className="max-w-sm text-xs text-muted-foreground">{push.host ? t("desktop.push.sub", { host: push.host }) : t("desktop.push.noSub")}</span>
          )}
          {!push.block && push.error && <span className="max-w-sm text-xs text-muted-foreground">{t("desktop.push.lastError", { error: push.error })}</span>}
          {!push.block && !saved && <span className="max-w-sm text-xs text-muted-foreground">{t("desktop.push.saveFirst")}</span>}
        </StatusRow>
      </div>
    </div>
  )
}
