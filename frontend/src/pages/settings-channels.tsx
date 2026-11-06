import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import {
  Bell,
  ChevronDown,
  Copy,
  FlaskConical,
  Hash,
  KeyRound,
  Loader2,
  Mail,
  MessageCircle,
  MessageSquareText,
  MessagesSquare,
  Pencil,
  Plus,
  RadioTower,
  Send,
  Smartphone,
  Trash2,
  Webhook,
  XCircle,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet } from "@/components/ui/sheet"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Pill } from "@/components/cobe/badges"
import { confirmAction } from "@/components/cobe/confirm"
import { EmptyState, Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Explained } from "@/components/cobe/explained"
import { Field, ToggleRow } from "@/components/cobe/form"
import { Ts } from "@/components/cobe/time"
import { ApiError, api } from "@/lib/api"
import { CHANNEL_TYPES, type ChannelType, type NotifyChannel, type SendResult, type SmtpSettings, useChannels, useSmtp } from "@/lib/admin-api"
import {
  type ChannelField,
  type ChannelForm,
  MAX_RECIPIENTS,
  badRecipients,
  channelProblems,
  errorCategoryText,
  NTFY_TAGS_MAX,
  hasServer,
  hasUrl,
  initialForm,
  mailServerMissing,
  needsSecretsAgain,
  parseRecipients,
  randomSecret,
  sendError,
  smtpReady,
  smtpTarget,
  targetSummary,
  toChannelIn,
  uiLang,
  upcomingTry,
} from "@/lib/channels"
import { copyWithToast } from "@/lib/clipboard"
import { errorText, isStale } from "@/lib/errors"
import { confirmDiscard } from "@/lib/unsaved"
import { ChannelLog, HealthBadge } from "@/pages/settings-delivery-log"
import { IntegrationSheetContent, Loading, SaveBar, SheetActions, SheetBody, SheetLoading, StaleNotice } from "@/pages/settings-shared"
import { iso } from "@/lib/bidi"

const ICON: Record<ChannelType, React.ElementType> = {
  email: Mail,
  teams: MessagesSquare,
  slack: Hash,
  discord: MessageCircle,
  telegram: Send,
  webhook: Webhook,
  ntfy: Bell,
  gotify: Smartphone,
  mattermost: MessageSquareText,
}
// the section of the handbook (/docs/benachrichtigungen#…) that explains a channel type
const CHANNEL_HELP: Record<ChannelType, string> = {
  email: "e-mail",
  teams: "teams",
  slack: "slack",
  discord: "discord",
  telegram: "telegram",
  webhook: "webhook",
  ntfy: "ntfy",
  gotify: "gotify",
  mattermost: "mattermost",
}

export function ChannelIcon({ type, className }: { type: ChannelType; className?: string }) {
  const Icon = ICON[type]
  return <Icon className={className} />
}

const URL_PLACEHOLDER: Partial<Record<ChannelType, string>> = {
  teams: "https://…/workflows/…",
  slack: "https://hooks.slack.com/services/…",
  discord: "https://discord.com/api/webhooks/…",
  webhook: "https://n8n.corp.example/webhook/…",
  mattermost: "https://chat.corp.example/hooks/…",
}

// What a webhook channel posts – shown in the drawer, it documents the format (version 1).
const EXAMPLE_PAYLOAD = JSON.stringify(
  {
    version: 1,
    type: "news.stories",
    id: "5b0c…",
    sent_at: "2026-10-28T12:00:00Z",
    app: "cobe-news",
    app_url: "https://news.corp.example:8095/",
    channel: "n8n SOC",
    rules: ["Kritisch an SOC"],
    lang: "de",
    total: 1,
    more: 0,
    stories: [
      {
        id: "…",
        title: "…",
        summary: "…",
        url: "https://news.example.com/…",
        link: "https://news.corp.example:8095/?story=…",
        severity: "critical",
        source: "Example Feed",
        published_at: "2026-10-28T11:58:00Z",
        cves: ["CVE-2026-0001"],
      },
    ],
  },
  null,
  2,
)

/**
 * Last error (with the next try, while it lies ahead) or when something went out last – in the list and in the drawer.
 * An e-mail channel without a mail server says that instead: it cannot send at all.
 */
function SendStatus({ c }: { c: NotifyChannel }) {
  const { t } = useTranslation()
  const smtp = useSmtp().data
  // one flowing line: on a phone it wraps like text instead of leaving the icon on a line of its own
  const icon = <XCircle className="mr-1 inline size-3.5 align-[-3px]" />
  if (mailServerMissing(c, smtp))
    return (
      <p className="text-xs text-warning">
        {icon}
        {t("channels.mailMissing")}
      </p>
    )
  const next = upcomingTry(c)
  if (c.last_error)
    return (
      <p className="text-xs text-warning">
        {icon}
        {errorCategoryText(t, c.last_error)}
        {c.last_error_at && (
          <>
            {" "}
            <Ts at={c.last_error_at} rel className="text-muted-foreground" />
          </>
        )}
        {next && (
          <span className="text-muted-foreground">
            {" "}
            · {t("notify.nextTry")} <Ts at={next} rel />
          </span>
        )}
      </p>
    )
  return (
    <p className="text-xs text-muted-foreground">
      {c.last_sent_at ? (
        <>
          {t("notify.lastSent")} <Ts at={c.last_sent_at} rel />
        </>
      ) : (
        t("notify.neverSent")
      )}
    </p>
  )
}

function UsedBy({ c }: { c: NotifyChannel }) {
  const { t } = useTranslation()
  if (!c.rules.length) return <p className="text-xs text-muted-foreground italic">{t("channels.unused")}</p>
  return (
    <p className="text-xs">
      <span className="text-muted-foreground">{t("channels.usedBy")}</span>{" "}
      {c.rules.map((r, i) => (
        <span key={r.id}>
          {i > 0 && ", "}
          <bdi>{r.name}</bdi>
          {!r.enabled && ` (${t("channels.ruleOff")})`}
        </span>
      ))}
    </p>
  )
}

/** Sends a test message over the stored channel. */
function TestChannelButton({ channel, iconOnly = false, disabled = false }: { channel: NotifyChannel; iconOnly?: boolean; disabled?: boolean }) {
  const { t, i18n } = useTranslation()
  const qc = useQueryClient()
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    try {
      const r = await api.post<SendResult>(`/api/admin/notify/channels/${channel.id}/test`, { lang: uiLang(i18n.language) })
      if (r.ok) toast.success(t("notify.testSent", { name: channel.name }))
      else toast.error(sendError(t, r))
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
      void qc.invalidateQueries({ queryKey: ["admin", "channels"] })
    }
  }
  const noServer = mailServerMissing(channel, useSmtp().data)
  const title = noServer ? t("channels.mailMissing") : disabled ? t("notify.testSavedOnly") : t("notify.test")
  return iconOnly ? (
    <Button variant="ghost" size="icon-sm" disabled={busy || disabled || noServer} aria-label={t("notify.test")} title={title} onClick={() => void run()}>
      {busy ? <Loader2 className="animate-spin" /> : <FlaskConical />}
    </Button>
  ) : (
    <Button variant="outline" disabled={busy || disabled || noServer} onClick={() => void run()} title={disabled || noServer ? title : undefined}>
      {busy ? <Loader2 className="animate-spin" /> : <FlaskConical />} {t("notify.test")}
    </Button>
  )
}

// ---------------------------------------------------------------- the list

type SheetState = { open: boolean; type: ChannelType; id: string | null; key: number }

const opensMailServer = (p: URLSearchParams) => p.get("smtp") === "1" || ["smtp", "mail"].includes(p.get("tab") ?? "")

/** Settings → Channels & rules → Channels: where notifications go – and the mail server of the e-mail channels. */
export function ChannelsPane() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useChannels()
  const smtp = useSmtp()
  const [sheet, setSheet] = useState<SheetState>({ open: false, type: "email", id: null, key: 0 })
  // the mail server's drawer – `?smtp=1` (where the old page "E-Mail-Versand" leads) or `?tab=smtp` opens it right away
  const [params, setParams] = useSearchParams()
  const [smtpOpen, setSmtpOpen] = useState(() => opensMailServer(params))
  const closeSmtp = () => {
    setSmtpOpen(false)
    if (opensMailServer(params)) setParams({}, { replace: true })
  }
  const openSmtp = () => {
    // from a channel's drawer: that one closes first (asking when something is not saved)
    if (!sheet.open) return setSmtpOpen(true)
    void confirmDiscard().then((ok) => ok && (setSheet((s) => ({ ...s, open: false })), setSmtpOpen(true)))
  }
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["admin", "channels"] })
    void qc.invalidateQueries({ queryKey: ["admin", "rules"] })
  }
  const openNew = (type: ChannelType) => setSheet((s) => ({ open: true, type, id: null, key: s.key + 1 }))
  const openEdit = (c: NotifyChannel) => setSheet((s) => ({ open: true, type: c.type, id: c.id, key: s.key + 1 }))
  const saved = (c: NotifyChannel) => {
    // the drawer stays open on the stored channel (now with "Testen"); the list has it at once
    qc.setQueryData<NotifyChannel[]>(["admin", "channels"], (old) => (old ? [...old.filter((x) => x.id !== c.id), c].sort((a, b) => a.name.localeCompare(b.name)) : old))
    setSheet((s) => ({ ...s, id: c.id, key: s.key + 1 }))
    refresh()
  }
  const remove = async (c: NotifyChannel) => {
    const text = c.rules.length
      ? t("channels.removeTextUsed", { name: iso(c.name), rules: c.rules.map((r) => `„${iso(r.name)}“`).join(", ") })
      : t("channels.removeText", { name: iso(c.name) })
    if (!(await confirmAction({ title: t("channels.removeTitle"), text, confirm: t("common.remove") }))) return
    try {
      await api.del(`/api/admin/notify/channels/${c.id}`)
      refresh()
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  if (!q.data) return <Loading error={q.error} onRetry={q.refetch} />
  const channel = sheet.id ? (q.data.find((c) => c.id === sheet.id) ?? null) : null
  // a new e-mail channel while no mail server is set up: the server first, in the same drawer
  const serverFirst = sheet.type === "email" && !channel && !!smtp.data && !smtpReady(smtp.data)
  return (
    <>
      <Section
        title={t("channels.title")}
        description={t("channels.hint")}
        actions={
          <>
            <HelpLink chapter="benachrichtigungen" section="kanaele" topic={t("channels.title")} />
            <DropdownMenu modal={false}>
              <DropdownMenuTrigger asChild>
                <Button size="sm">
                  <Plus /> {t("channels.add")} <ChevronDown />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-52">
                {CHANNEL_TYPES.map((type) => (
                  <DropdownMenuItem key={type} onSelect={() => openNew(type)}>
                    <ChannelIcon type={type} /> {t(`notify.channel.${type}`)}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        }
      >
        {smtp.data ? (
          <MailServerLine smtp={smtp.data} needed={q.data.some((c) => c.type === "email")} onEdit={openSmtp} />
        ) : (
          smtp.error && (
            <p className="border-b px-5 py-3 text-xs text-destructive">
              {t("channels.mailServer")}: {errorText(t, smtp.error)}
            </p>
          )
        )}
        {q.data.length === 0 ? (
          <div className="p-5">
            <EmptyState icon={RadioTower} title={t("channels.emptyTitle")} text={t("channels.emptyText")} />
          </div>
        ) : (
          <ul className="divide-y">
            {q.data.map((c) => (
              <li key={c.id} className="flex items-start gap-3 px-5 py-3">
                <span className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted">
                  <ChannelIcon type={c.type} className="size-4" />
                </span>
                <div className="min-w-0 flex-1 space-y-1">
                  <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                    {c.name}
                    <Pill color="--muted-foreground">{t(`notify.channel.${c.type}`)}</Pill>
                  </p>
                  <p className="truncate font-mono text-xs text-muted-foreground" title={targetSummary(c)}>
                    {targetSummary(c)}
                  </p>
                  <UsedBy c={c} />
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <SendStatus c={c} />
                    <HealthBadge c={c} />
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <TestChannelButton channel={c} iconOnly />
                  <Button variant="ghost" size="icon-sm" aria-label={t("common.edit")} title={t("common.edit")} onClick={() => openEdit(c)}>
                    <Pencil />
                  </Button>
                  <Button variant="ghost" size="icon-sm" aria-label={t("common.remove")} title={t("common.remove")} onClick={() => void remove(c)}>
                    <Trash2 />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>
      {/* mounted while it slides out; closing with changes not saved asks first */}
      <Sheet open={sheet.open} onOpenChange={(o) => !o && void confirmDiscard().then((ok) => ok && setSheet((s) => ({ ...s, open: false })))}>
        <IntegrationSheetContent
          icon={ICON[sheet.type]}
          title={t(`channels.sheetTitle.${sheet.type}`)}
          description={t("channels.sheetDesc")}
          help={{ chapter: "benachrichtigungen", section: CHANNEL_HELP[sheet.type] }}
        >
          {(sheet.id && !channel) || (sheet.type === "email" && !smtp.data) ? (
            <SheetLoading error={sheet.type === "email" ? smtp.error : undefined} onRetry={() => void smtp.refetch()} />
          ) : serverFirst ? (
            <SmtpPane intro={<p className="rounded-lg border border-primary/30 bg-primary/5 p-3 text-xs leading-relaxed">{t("channels.mailFirst")}</p>} />
          ) : (
            <ChannelEditor
              key={sheet.key}
              type={sheet.type}
              channel={channel}
              onSaved={saved}
              onReload={() =>
                // rebuilt from the list: first the channel as it is stored now (not the cached state that was refused)
                void qc.refetchQueries({ queryKey: ["admin", "channels"] }).then(() => setSheet((s) => ({ ...s, key: s.key + 1 })))
              }
              onStale={refresh}
              onSmtp={openSmtp}
              onCancel={() => void confirmDiscard().then((ok) => ok && setSheet((s) => ({ ...s, open: false })))}
            />
          )}
        </IntegrationSheetContent>
      </Sheet>
      <Sheet open={smtpOpen} onOpenChange={(o) => !o && void confirmDiscard().then((ok) => ok && closeSmtp())}>
        <IntegrationSheetContent icon={Mail} title={t("settings.tab.smtp")} description={t("notify.smtpHint")} help={{ chapter: "benachrichtigungen", section: "e-mail" }}>
          <SmtpPane />
        </IntegrationSheetContent>
      </Sheet>
    </>
  )
}

/** "Mail server: mail.corp.example:587 · set up [Edit]" – one line above the channels, the form in a drawer. */
function MailServerLine({ smtp, needed, onEdit }: { smtp: SmtpSettings; needed: boolean; onEdit: () => void }) {
  const { t } = useTranslation()
  const ready = smtpReady(smtp)
  return (
    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-2 border-b px-5 py-3">
      <Mail className="size-4 shrink-0 text-muted-foreground" />
      <span className="text-sm font-medium">{t("channels.mailServer")}</span>
      {smtp.host && <span className="min-w-0 font-mono text-xs [overflow-wrap:anywhere] text-muted-foreground">{smtpTarget(smtp)}</span>}
      <Pill color={ready ? "--success" : needed ? "--warning" : "--muted-foreground"} dot title={ready ? undefined : t("channels.mailNotReadyHint")}>
        {ready ? t("channels.mailReady") : t("channels.mailNotReady")}
      </Pill>
      <Button variant="outline" size="sm" className="ml-auto" onClick={onEdit}>
        <Pencil /> {ready ? t("common.edit") : t("settings.int.configure")}
      </Button>
    </div>
  )
}

// ---------------------------------------------------------------- the drawer

function ChannelEditor({
  type,
  channel,
  onSaved,
  onSmtp,
  onCancel,
  onReload,
  onStale,
}: {
  type: ChannelType
  channel: NotifyChannel | null
  onSaved: (c: NotifyChannel) => void
  onSmtp: () => void
  onCancel: () => void
  /** a fresh form on the channel as it is stored now */
  onReload: () => void
  /** the save was refused as stale: the list loads the current state */
  onStale: () => void
}) {
  const { t } = useTranslation()
  const [f, setF] = useState<ChannelForm>(() => initialForm(channel))
  const [start] = useState(() => JSON.stringify(toChannelIn(type, initialForm(channel), channel)))
  // the stored state this edit is made on – another admin's save in between makes the server refuse it (409 stale)
  const [version] = useState(channel?.version)
  const [stale, setStale] = useState(false)
  const [busy, setBusy] = useState(false)
  const set = (patch: Partial<ChannelForm>) => setF((x) => ({ ...x, ...patch }))
  const body = toChannelIn(type, f, channel)
  const dirty = JSON.stringify(body) !== start
  const problems = channelProblems(type, f, channel)
  const valid = Object.keys(problems).length === 0
  // a field says what is wrong once something is typed into it – an untouched form is not red all over
  const shown = (field: ChannelField, typed: string) => {
    const key = problems[field]
    return typed.trim() && key ? <span className="text-destructive">{t(key)}</span> : undefined
  }
  const save = async () => {
    setBusy(true)
    try {
      const saved = channel
        ? await api.put<NotifyChannel>(`/api/admin/notify/channels/${channel.id}`, { ...body, version })
        : await api.post<NotifyChannel>("/api/admin/notify/channels", body)
      toast.success(t("common.saved"))
      onSaved(saved)
    } catch (e) {
      // the generic text of this code is about the mail server
      toast.error(e instanceof ApiError && e.code === "secret_required" ? t("channels.secretRequired") : errorText(t, e))
      if (isStale(e)) {
        setStale(true)
        onStale()
      }
    } finally {
      setBusy(false)
    }
  }
  // a stored channel: its settings | its delivery log (the form stays mounted – a switch loses nothing typed)
  const [view, setView] = useState<"edit" | "log">("edit")
  return (
    <>
      <SheetBody>
        {channel && (
          <Tabs value={view} onValueChange={(x) => setView(x as "edit" | "log")}>
            <TabsList>
              <TabsTrigger value="edit">{t("dlog.tab.settings")}</TabsTrigger>
              <TabsTrigger value="log">{t("dlog.tab.log")}</TabsTrigger>
            </TabsList>
          </Tabs>
        )}
        {channel && view === "log" && <ChannelLog channel={channel} />}
        <div className={view === "log" ? "hidden" : "space-y-4"}>
          {stale && <StaleNotice onReload={onReload} />}
          <SetupHint type={type} onSmtp={onSmtp} />
          <Field label={t("notify.name")} hint={shown("name", f.name)}>
            <Input value={f.name} onChange={(e) => set({ name: e.target.value })} placeholder={t(`channels.namePlaceholder.${type}`)} maxLength={100} />
          </Field>
          {type === "email" && <EmailFields f={f} set={set} />}
          {hasUrl(type) && <UrlField type={type} f={f} set={set} channel={channel} error={shown("url", f.url)} />}
          {type === "telegram" && <TelegramFields f={f} set={set} channel={channel} shown={shown} />}
          {type === "webhook" && <WebhookFields f={f} set={set} channel={channel} problems={problems} />}
          {hasServer(type) && <PushFields type={type} f={f} set={set} channel={channel} shown={shown} />}
          {channel && (
            <div className="space-y-1 rounded-lg border p-3">
              <p className="text-xs font-medium">{t("channels.status")}</p>
              <SendStatus c={channel} />
              <HealthBadge c={channel} />
              <UsedBy c={channel} />
            </div>
          )}
        </div>
      </SheetBody>
      <SheetActions>
        <Button variant="ghost" onClick={onCancel}>
          {t("common.cancel")}
        </Button>
        <div className="flex flex-wrap items-center justify-end gap-2">
          {channel && <TestChannelButton channel={channel} disabled={dirty} />}
          <SaveBar busy={busy} dirty={dirty} disabled={!valid || stale} onSave={() => void save()} />
        </div>
      </SheetActions>
    </>
  )
}

function SetupHint({ type, onSmtp }: { type: ChannelType; onSmtp: () => void }) {
  const { t } = useTranslation()
  const smtp = useSmtp().data
  const missing = type === "email" && !!smtp && !smtpReady(smtp)
  return (
    <>
      {missing && (
        <div className="space-y-1.5 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
          <p className="font-medium">{t("channels.mailMissing")}</p>
          <p className="leading-relaxed">{t("channels.mailNotReadyHint")}</p>
          <Button variant="outline" size="sm" onClick={onSmtp}>
            <Mail /> {t("channels.toMailServer")}
          </Button>
        </div>
      )}
      <div className="space-y-1.5 rounded-lg bg-muted/60 p-3 text-xs">
        <p className="font-medium">{t("channels.setupTitle")}</p>
        <p className="leading-relaxed whitespace-pre-line text-muted-foreground [overflow-wrap:anywhere]">{t(`channels.setup.${type}`)}</p>
        {type === "email" && smtp && !missing && (
          <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="text-muted-foreground">
              {t("channels.mailServer")}: <span className="font-mono [overflow-wrap:anywhere]">{smtpTarget(smtp)}</span>
            </span>
            <Button variant="link" size="xs" className="h-auto px-0" onClick={onSmtp}>
              {t("common.edit")}
            </Button>
          </p>
        )}
      </div>
    </>
  )
}

type Part = { f: ChannelForm; set: (patch: Partial<ChannelForm>) => void }

function EmailFields({ f, set }: Part) {
  const { t } = useTranslation()
  const list = parseRecipients(f.recipients)
  const bad = badRecipients(list)
  const hint = bad.length ? (
    <span className="text-destructive">{t("notify.badRecipients", { list: bad.join(", ") })}</span>
  ) : list.length > MAX_RECIPIENTS ? (
    <span className="text-destructive">{t("channels.check.tooManyRecipients")}</span>
  ) : (
    t("notify.recipientsHint")
  )
  return (
    <Field label={t("notify.recipients")} hint={hint}>
      <Textarea
        value={f.recipients}
        onChange={(e) => set({ recipients: e.target.value })}
        placeholder={"soc@corp.example\nit-security@corp.example"}
        aria-invalid={bad.length > 0 || list.length > MAX_RECIPIENTS}
        className="font-mono text-xs"
      />
    </Field>
  )
}

function UrlField({ type, f, set, channel, error }: Part & { type: ChannelType; channel: NotifyChannel | null; error?: React.ReactNode }) {
  const { t } = useTranslation()
  const kept = !!channel?.url_set
  return (
    <Field
      label={<Explained label={t(`channels.url.${type}`)} text={t(`channels.urlHint.${type}`)} />}
      hint={error ?? (kept ? t("channels.urlKept", { host: channel?.host ?? "?" }) : t("channels.urlSecret"))}
    >
      <Input
        type="password"
        autoComplete="off"
        value={f.url}
        onChange={(e) => set({ url: e.target.value })}
        placeholder={kept ? t("channels.keepPlaceholder") : URL_PLACEHOLDER[type]}
        aria-invalid={!!error}
        className="font-mono text-xs"
      />
    </Field>
  )
}

function TelegramFields({ f, set, channel, shown }: Part & { channel: NotifyChannel | null; shown: (field: ChannelField, typed: string) => React.ReactNode | undefined }) {
  const { t } = useTranslation()
  const tokenError = shown("bot_token", f.bot_token)
  const chatError = shown("chat_id", f.chat_id)
  return (
    <>
      <Field
        label={<Explained label={t("channels.botToken")} text={t("channels.botTokenHint")} />}
        hint={tokenError ?? (channel?.token_set ? t("common.secretKept") : t("channels.tokenSecret"))}
      >
        <Input
          type="password"
          autoComplete="off"
          value={f.bot_token}
          onChange={(e) => set({ bot_token: e.target.value })}
          placeholder={channel?.token_set ? t("channels.keepPlaceholder") : "123456789:AA…"}
          aria-invalid={!!tokenError}
          className="font-mono text-xs"
        />
      </Field>
      <Field label={<Explained label={t("channels.chatId")} text={t("channels.chatIdHint")} />} hint={chatError ?? t("channels.chatIdFormat")}>
        <Input
          value={f.chat_id}
          onChange={(e) => set({ chat_id: e.target.value.trim() })}
          placeholder="-1001234567890"
          autoComplete="off"
          aria-invalid={!!chatError}
          className="font-mono text-xs"
        />
      </Field>
    </>
  )
}

/** ntfy and Gotify: the server (no secret), the topic (ntfy – a secret: on a public server the only protection) and the token. */
function PushFields({
  type,
  f,
  set,
  channel,
  shown,
}: Part & { type: ChannelType; channel: NotifyChannel | null; shown: (field: ChannelField, typed: string) => React.ReactNode | undefined }) {
  const { t } = useTranslation()
  const ntfy = type === "ntfy"
  const serverError = shown("server_url", f.server_url)
  const topicError = shown("topic", f.topic)
  const tokenError = shown("token", f.token)
  const tagsError = shown("tags", f.tags)
  const tokenField = (
    <Field
      label={<Explained label={t(`channels.push.token.${type}`)} text={t(`channels.push.tokenHint.${type}`)} />}
      hint={tokenError ?? (channel?.token_set ? t("common.secretKept") : t("channels.tokenSecret"))}
    >
      <Input
        type="password"
        autoComplete="off"
        value={f.token}
        onChange={(e) => set({ token: e.target.value })}
        placeholder={channel?.token_set ? t("channels.keepPlaceholder") : ntfy ? "tk_…" : "A…"}
        aria-invalid={!!tokenError}
        className="font-mono text-xs"
      />
    </Field>
  )
  return (
    <>
      {needsSecretsAgain(f, channel) && <p className="rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs">{t("channels.push.secretsAgain")}</p>}
      <Field label={<Explained label={t("channels.push.server")} text={t(`channels.push.serverHint.${type}`)} />} hint={serverError ?? t("channels.push.serverFormat")}>
        <Input
          value={f.server_url}
          onChange={(e) => set({ server_url: e.target.value.trim() })}
          placeholder={ntfy ? "https://ntfy.corp.example" : "https://gotify.corp.example"}
          autoComplete="off"
          aria-invalid={!!serverError}
          className="font-mono text-xs"
        />
      </Field>
      {ntfy && (
        <Field
          label={<Explained label={t("channels.push.topic")} text={t("channels.push.topicHint")} />}
          hint={topicError ?? (channel?.topic_set ? t("common.secretKept") : t("channels.push.topicSecret"))}
        >
          <Input
            type="password"
            autoComplete="off"
            value={f.topic}
            onChange={(e) => set({ topic: e.target.value.trim() })}
            placeholder={channel?.topic_set ? t("channels.keepPlaceholder") : "cobe-soc-…"}
            aria-invalid={!!topicError}
            className="font-mono text-xs"
          />
        </Field>
      )}
      {ntfy ? (
        <ToggleRow
          label={t("channels.push.tokenOn")}
          description={t("channels.push.tokenOnHint")}
          checked={f.token_on}
          onCheckedChange={(x) => set({ token_on: x, token: "" })}
          className="py-0"
        >
          {tokenField}
        </ToggleRow>
      ) : (
        tokenField
      )}
      {ntfy && (
        <Field label={<Explained label={t("channels.push.tags")} text={t("channels.push.tagsHint")} />} hint={tagsError ?? t("channels.push.tagsFormat", { max: NTFY_TAGS_MAX })}>
          <Input
            value={f.tags}
            onChange={(e) => set({ tags: e.target.value })}
            placeholder="soc, cobe"
            autoComplete="off"
            aria-invalid={!!tagsError}
            className="font-mono text-xs"
          />
        </Field>
      )}
      <p className="rounded-lg bg-muted/60 p-3 text-xs leading-relaxed text-muted-foreground">{t(`channels.push.priority.${type}`)}</p>
    </>
  )
}

function WebhookFields({ f, set, channel, problems }: Part & { channel: NotifyChannel | null; problems: Partial<Record<ChannelField, string>> }) {
  const { t } = useTranslation()
  const [revealed, setRevealed] = useState(false) // a generated secret is shown so it can be copied
  const [example, setExample] = useState(false)
  const err = (field: ChannelField) => {
    const key = problems[field]
    return key ? <span className="text-destructive">{t(key)}</span> : undefined
  }
  const generate = () => {
    set({ hmac_secret: randomSecret() })
    setRevealed(true)
  }
  return (
    <>
      {needsSecretsAgain(f, channel) && <p className="rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs">{t("channels.secretRequired")}</p>}
      <ToggleRow
        label={t("channels.allowHttp")}
        description={t("channels.allowHttpHint")}
        checked={f.allow_http}
        onCheckedChange={(x) => set({ allow_http: x })}
        className="py-0"
      />
      {f.allow_http && <p className="rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs">{t("channels.allowHttpWarn")}</p>}
      <ToggleRow
        label={<Explained label={t("channels.useProxy")} text={t("channels.useProxyExplained")} />}
        description={t("channels.useProxyHint")}
        checked={f.use_proxy}
        onCheckedChange={(x) => set({ use_proxy: x })}
        className="py-0"
      />
      <ToggleRow
        label={<Explained label={t("channels.hmac")} text={t("channels.hmacExplained")} />}
        description={t("channels.hmacHint")}
        checked={f.hmac_on}
        onCheckedChange={(x) => set({ hmac_on: x, hmac_secret: "" })}
        className="py-0"
      >
        <Field
          label={t("channels.hmacSecret")}
          hint={err("hmac_secret") ?? (f.hmac_secret ? t("channels.hmacCopyNow") : channel?.hmac_set ? t("common.secretKept") : t("channels.hmacSecretHint", { min: 16 }))}
        >
          <div className="flex gap-2">
            <Input
              type={revealed ? "text" : "password"}
              autoComplete="off"
              value={f.hmac_secret}
              onChange={(e) => set({ hmac_secret: e.target.value })}
              placeholder={channel?.hmac_set ? t("channels.keepPlaceholder") : ""}
              aria-invalid={!!err("hmac_secret")}
              className="min-w-0 flex-1 font-mono text-xs"
            />
            {revealed && f.hmac_secret && (
              <Button variant="outline" size="icon" aria-label={t("common.copy")} title={t("common.copy")} onClick={() => void copyWithToast(f.hmac_secret)}>
                <Copy />
              </Button>
            )}
            <Button variant="outline" onClick={generate}>
              <KeyRound /> {t("channels.generate")}
            </Button>
          </div>
        </Field>
      </ToggleRow>
      <ToggleRow
        label={t("channels.header")}
        description={t("channels.headerHint")}
        checked={f.header_on}
        onCheckedChange={(x) => set({ header_on: x, header_value: "", header_name: f.header_name || "Authorization" })}
        className="py-0"
      >
        <div className="grid gap-3 sm:grid-cols-[2fr_3fr]">
          <Field label={t("channels.headerName")} hint={f.header_name ? err("header_name") : undefined}>
            <Input
              value={f.header_name}
              onChange={(e) => set({ header_name: e.target.value.trim() })}
              placeholder="Authorization"
              autoComplete="off"
              className="font-mono text-xs"
            />
          </Field>
          <Field label={t("channels.headerValue")} hint={err("header_value") ?? (channel?.header_set ? t("common.secretKept") : t("channels.headerValueHint"))}>
            <Input
              type="password"
              autoComplete="off"
              value={f.header_value}
              onChange={(e) => set({ header_value: e.target.value })}
              placeholder={channel?.header_set ? t("channels.keepPlaceholder") : "Bearer …"}
              className="font-mono text-xs"
            />
          </Field>
        </div>
      </ToggleRow>
      <div className="space-y-2">
        <Button variant="ghost" size="sm" onClick={() => setExample(!example)} aria-expanded={example}>
          <ChevronDown className={example ? "rotate-180 transition-transform" : "transition-transform"} /> {example ? t("channels.exampleHide") : t("channels.exampleShow")}
        </Button>
        {example && (
          <div className="space-y-1.5">
            <p className="text-xs text-muted-foreground">{t("channels.exampleHint")}</p>
            <pre className="max-h-64 overflow-auto rounded-lg border bg-muted/40 p-3 font-mono text-[11px] leading-relaxed">{EXAMPLE_PAYLOAD}</pre>
          </div>
        )}
      </div>
    </>
  )
}

// ---------------------------------------------------------------- the mail server

/** The mail server of all e-mail channels (drawer of the status line, or the first step of a new e-mail channel). */
export function SmtpPane({ intro }: { intro?: React.ReactNode }) {
  const q = useSmtp()
  const [reloads, setReloads] = useState(0)
  if (!q.data) return <SheetLoading error={q.error} onRetry={q.refetch} />
  // a fresh form on what is stored now – after a save, or "load the current state" after another admin's save
  const reload = () => void q.refetch().then(() => setReloads((n) => n + 1))
  return <SmtpForm key={`${reloads}:${JSON.stringify(q.data)}`} initial={q.data} intro={intro} onReload={reload} />
}

function SmtpForm({ initial, intro, onReload }: { initial: SmtpSettings; intro?: React.ReactNode; onReload: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { password_set, ...rest } = initial
  const [v, setV] = useState({ ...rest, password: "", clear_password: false })
  const [to, setTo] = useState("")
  const [busy, setBusy] = useState<"save" | "test" | null>(null)
  // another admin saved the mail server meanwhile: the save is refused (409) – saving again would be refused, too
  const [stale, setStale] = useState(false)
  const dirty =
    JSON.stringify({ ...v, password: "", clear_password: false }) !== JSON.stringify({ ...rest, password: "", clear_password: false }) || !!v.password || v.clear_password
  const fromOk = !v.from_addr || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.from_addr)
  const valid = fromOk && v.port >= 1 && v.port <= 65535
  const save = async () => {
    setBusy("save")
    try {
      await api.put("/api/admin/notify/smtp", v)
      setV((x) => ({ ...x, password: "", clear_password: false })) // stored (encrypted) – the field empties, the form is clean
      toast.success(t("common.saved"))
      void qc.invalidateQueries({ queryKey: ["admin", "smtp"] })
      void qc.invalidateQueries({ queryKey: ["admin", "channels"] }) // the e-mail channels start afresh with it
    } catch (e) {
      toast.error(errorText(t, e))
      if (isStale(e)) setStale(true) // the form stays (the typed values); "load the current state" starts afresh
    } finally {
      setBusy(null)
    }
  }
  const test = async () => {
    setBusy("test")
    try {
      const r = await api.post<SendResult>("/api/admin/notify/smtp/test", { ...v, to })
      if (r.ok) toast.success(t("notify.smtpTestSent", { to }))
      else toast.error(sendError(t, r))
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
    }
  }
  return (
    <>
      <SheetBody>
        {stale && <StaleNotice onReload={onReload} />}
        {intro}
        <div className="grid gap-4 sm:grid-cols-[2fr_1fr_1fr]">
          <Field label={t("notify.smtpHost")}>
            <Input value={v.host} onChange={(e) => setV({ ...v, host: e.target.value.trim() })} placeholder="mail.corp.example" />
          </Field>
          <Field label={t("notify.smtpPort")}>
            <Input type="number" min={1} max={65535} value={v.port} onChange={(e) => setV({ ...v, port: Number(e.target.value) })} className="tabular" />
          </Field>
          <Field label={<Explained label={t("notify.smtpEnc")} text={t("notify.smtpEncHint")} />}>
            <Select
              value={v.encryption}
              onValueChange={(x) => {
                const enc = x as SmtpSettings["encryption"]
                setV({ ...v, encryption: enc, port: v.port === 587 || v.port === 465 || v.port === 25 ? (enc === "tls" ? 465 : enc === "starttls" ? 587 : 25) : v.port })
              }}
            >
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value="starttls">STARTTLS</SelectItem>
                <SelectItem value="tls">SSL/TLS</SelectItem>
                <SelectItem value="none">{t("notify.smtpNone")}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
        </div>
        {v.encryption === "none" && <p className="rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs">{t("notify.smtpPlainWarn")}</p>}
        {v.encryption !== "none" && (
          <ToggleRow
            label={t("notify.smtpVerify")}
            description={t("notify.smtpVerifyHint")}
            checked={v.verify_cert}
            onCheckedChange={(x) => setV({ ...v, verify_cert: x })}
            className="py-0"
          />
        )}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("notify.smtpUser")} hint={t("notify.smtpUserHint")}>
            <Input value={v.username} onChange={(e) => setV({ ...v, username: e.target.value })} autoComplete="off" />
          </Field>
          <Field label={t("notify.smtpPassword")} hint={password_set && !v.clear_password ? t("common.secretKept") : undefined}>
            <Input
              type="password"
              autoComplete="new-password"
              value={v.password}
              onChange={(e) => setV({ ...v, password: e.target.value, clear_password: false })}
              placeholder={password_set && !v.clear_password ? "••••••••" : ""}
            />
          </Field>
        </div>
        {password_set && (
          <ToggleRow label={t("notify.smtpClearPassword")} checked={v.clear_password} onCheckedChange={(x) => setV({ ...v, clear_password: x, password: "" })} className="py-0" />
        )}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("notify.smtpFrom")}>
            <Input value={v.from_addr} onChange={(e) => setV({ ...v, from_addr: e.target.value.trim() })} placeholder="cobe-news@corp.example" aria-invalid={!fromOk} />
          </Field>
          <Field label={t("notify.smtpFromName")}>
            <Input value={v.from_name} onChange={(e) => setV({ ...v, from_name: e.target.value })} maxLength={100} />
          </Field>
        </div>
        <div className="space-y-2 rounded-lg border border-dashed p-3">
          <Field label={t("notify.smtpTestTo")} hint={t("notify.smtpTestHint")}>
            <Input value={to} onChange={(e) => setTo(e.target.value.trim())} placeholder="du@corp.example" />
          </Field>
        </div>
      </SheetBody>
      <SheetActions>
        <Button variant="outline" disabled={busy !== null || !v.host || !v.from_addr || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)} onClick={() => void test()}>
          {busy === "test" ? <Loader2 className="animate-spin" /> : <FlaskConical />} {t("notify.smtpTest")}
        </Button>
        <SaveBar busy={busy === "save"} dirty={dirty} disabled={!valid || stale} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}
