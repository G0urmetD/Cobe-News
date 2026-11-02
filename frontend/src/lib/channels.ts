import type { ChannelIn, ChannelType, NotifyChannel, SendResult, SmtpSettings } from "@/lib/admin-api"

// Pure helpers of the channel editor (settings → Channels & rules): what the form checks before it saves. The server
// checks everything again – these only spare a round trip and say which field is wrong.

export const MAX_RECIPIENTS = 20
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/

/** Types whose target is a secret URL (stored encrypted, only its host is shown again). */
export const URL_TYPES: ChannelType[] = ["teams", "slack", "discord", "webhook", "mattermost"]
export const hasUrl = (type: ChannelType) => URL_TYPES.includes(type)

/** Types with a server address (no secret) and a token / topic (secrets bound to that server). */
export const PUSH_TYPES: ChannelType[] = ["ntfy", "gotify"]
export const hasServer = (type: ChannelType) => PUSH_TYPES.includes(type)

/** An ntfy / Gotify server: https, a host, maybe a path – no query, no fragment (the topic and token are not in it). */
export function serverOk(url: string): boolean {
  const u = url.trim()
  if (!/^https:\/\/[^\s/?#]+(\/[^\s?#]*)?$/.test(u)) return false
  try {
    new URL(u)
    return true
  } catch {
    return false
  }
}

/** An ntfy topic name (ntfy's own rule). */
export const topicOk = (topic: string) => /^[A-Za-z0-9_-]{1,64}$/.test(topic.trim())
/** An ntfy access token or a Gotify application token: no blank, no line break (it goes into a header). */
export const pushTokenOk = (token: string) => /^[A-Za-z0-9_.~+/=-]{8,200}$/.test(token.trim())
export const NTFY_TAGS_MAX = 5
/** "soc, cobe" → ["soc", "cobe"] – commas and blanks separate. */
export const parseTags = (text: string) => [
  ...new Set(
    text
      .split(/[\s,;]+/)
      .map((x) => x.trim())
      .filter(Boolean),
  ),
]
export const tagsOk = (tags: string[]) => tags.length <= NTFY_TAGS_MAX && tags.every((x) => /^[A-Za-z0-9_+-]{1,40}$/.test(x))

/** One address per line – commas, semicolons and blanks separate as well (pasted from a mail client). */
export function parseRecipients(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((x) => x.trim())
    .filter(Boolean)
}

export const badRecipients = (list: string[]) => list.filter((x) => !EMAIL.test(x))

/** The URL check per type: https only (a webhook may allow http on purpose); Discord only its own webhook path. */
export function urlOk(type: ChannelType, url: string, allowHttp = false): boolean {
  const u = url.trim()
  if (/\s/.test(u)) return false
  switch (type) {
    case "teams":
    case "slack":
      return /^https:\/\/\S+$/.test(u)
    case "discord":
      return /^https:\/\/(discord\.com|discordapp\.com)\/api\/webhooks\/\S+$/.test(u)
    case "webhook":
      return /^https:\/\/\S+$/.test(u) || (allowHttp && /^http:\/\/\S+$/.test(u))
    case "mattermost":
      return /^https:\/\/[^\s?#]+\/hooks\/[A-Za-z0-9]{8,64}\/?$/.test(u)
    default:
      return false
  }
}

/** A bot token from @BotFather: "<bot id>:<secret>". */
export const telegramTokenOk = (token: string) => /^\d{5,12}:[A-Za-z0-9_-]{30,50}$/.test(token.trim())

/** A numeric chat id (groups start with "-", channels with "-100") or the @name of a public channel. */
export const chatIdOk = (id: string) => /^-?\d{1,20}$|^@[A-Za-z][A-Za-z0-9_]{4,31}$/.test(id.trim())

/** Headers the server sets itself or that change how the request is read – never a custom auth header (as in backend notify.RESERVED_HEADERS). */
export const RESERVED_HEADERS = new Set(["host", "content-length", "content-type", "transfer-encoding", "connection", "user-agent", "te", "trailer", "upgrade", "expect", "cookie"])

/** A custom header name – the server's rule: letters, digits and "-" (not first), up to 64; no reserved name, no X-Cobe-…. */
export const headerNameOk = (name: string) => {
  const n = name.trim()
  const lower = n.toLowerCase()
  return /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/.test(n) && !RESERVED_HEADERS.has(lower) && !lower.startsWith("x-cobe-")
}

export const HMAC_MIN = 16

/** A random secret for the HMAC signature: 32 bytes, base64url without padding (43 characters). */
export function randomSecret(bytes = 32): string {
  const buf = new Uint8Array(bytes)
  crypto.getRandomValues(buf)
  let bin = ""
  for (const b of buf) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/** Host of a typed URL – with and without port ([] when it is none). */
export function hostsOf(url: string): string[] {
  try {
    const u = new URL(url.trim())
    return [u.host.toLowerCase(), u.hostname.toLowerCase()]
  } catch {
    return []
  }
}

/** The target in one line of the channel list. */
export function targetSummary(c: Pick<NotifyChannel, "type" | "recipients" | "host" | "chat_id" | "server">): string {
  if (c.type === "email") return c.recipients.join(", ") || "–"
  if (c.type === "telegram") return c.chat_id ? `Chat ${c.chat_id}` : "–"
  if (c.type === "ntfy" || c.type === "gotify") return c.server || c.host || "–"
  return c.host || "–"
}

// ---------------------------------------------------------------- the form

export interface ChannelForm {
  name: string
  /** email: the textarea as typed */
  recipients: string
  url: string
  bot_token: string
  chat_id: string
  allow_http: boolean
  use_proxy: boolean
  hmac_on: boolean
  hmac_secret: string
  header_on: boolean
  header_name: string
  header_value: string
  /** ntfy / gotify */
  server_url: string
  topic: string
  token: string
  /** ntfy: with an access token (a protected topic) */
  token_on: boolean
  /** ntfy: the tags as typed */
  tags: string
}

/** What the editor starts with: the stored channel (secrets empty = keep), or an empty one. */
export function initialForm(c?: NotifyChannel | null): ChannelForm {
  return {
    name: c?.name ?? "",
    recipients: c?.recipients.join("\n") ?? "",
    url: "",
    bot_token: "",
    chat_id: c?.chat_id ?? "",
    allow_http: c?.allow_http ?? false,
    use_proxy: c?.use_proxy ?? false,
    hmac_on: c?.hmac_set ?? false,
    hmac_secret: "",
    header_on: c?.header_set ?? false,
    header_name: c?.header_name ?? "",
    header_value: "",
    server_url: c?.server ?? "",
    topic: "",
    token: "",
    token_on: c?.type === "ntfy" ? !!c.token_set : false,
    tags: (c?.tags ?? []).join(", "),
  }
}

/** The request body – fields of other types empty, a switched-off signature/header of a stored channel cleared. */
export function toChannelIn(type: ChannelType, f: ChannelForm, c?: NotifyChannel | null): ChannelIn {
  const hook = type === "webhook"
  return {
    name: f.name.trim(),
    type,
    recipients: type === "email" ? parseRecipients(f.recipients) : [],
    url: hasUrl(type) ? f.url.trim() : "",
    bot_token: type === "telegram" ? f.bot_token.trim() : "",
    chat_id: type === "telegram" ? f.chat_id.trim() : "",
    allow_http: hook && f.allow_http,
    use_proxy: hook && f.use_proxy,
    hmac_secret: hook && f.hmac_on ? f.hmac_secret.trim() : "",
    clear_hmac: hook && !f.hmac_on && !!c?.hmac_set,
    header_name: hook && f.header_on ? f.header_name.trim() : "",
    header_value: hook && f.header_on ? f.header_value.trim() : "",
    clear_header: hook && !f.header_on && !!c?.header_set,
    server_url: hasServer(type) ? f.server_url.trim().replace(/\/+$/, "") : "",
    topic: type === "ntfy" ? f.topic.trim() : "",
    token: type === "gotify" || (type === "ntfy" && f.token_on) ? f.token.trim() : "",
    clear_token: type === "ntfy" && !f.token_on && !!c?.token_set,
    tags: type === "ntfy" ? parseTags(f.tags) : [],
  }
}

export type ChannelField = "name" | "recipients" | "url" | "bot_token" | "chat_id" | "hmac_secret" | "header_name" | "header_value" | "server_url" | "topic" | "token" | "tags"

/**
 * Problems per field as i18n keys (empty object = can be saved). A secret left empty is fine when one is stored –
 * it is kept.
 */
export function channelProblems(type: ChannelType, f: ChannelForm, c?: NotifyChannel | null): Partial<Record<ChannelField, string>> {
  const p: Partial<Record<ChannelField, string>> = {}
  if (f.name.trim().length < 2) p.name = "channels.check.name"
  if (type === "email") {
    const list = parseRecipients(f.recipients)
    if (list.length === 0) p.recipients = "errors.recipients_missing"
    else if (badRecipients(list).length) p.recipients = "channels.check.recipients"
    else if (list.length > MAX_RECIPIENTS) p.recipients = "channels.check.tooManyRecipients"
  }
  if (hasUrl(type)) {
    if (f.url.trim()) {
      if (!urlOk(type, f.url, f.allow_http)) p.url = `channels.check.url.${type}`
    } else if (!c?.url_set) p.url = "errors.url_missing"
  }
  if (type === "telegram") {
    if (f.bot_token.trim()) {
      if (!telegramTokenOk(f.bot_token)) p.bot_token = "errors.token_invalid"
    } else if (!c?.token_set) p.bot_token = "errors.token_missing"
    if (!chatIdOk(f.chat_id)) p.chat_id = "errors.chat_id_invalid"
  }
  if (hasServer(type)) {
    if (!f.server_url.trim()) p.server_url = "errors.url_missing"
    else if (!serverOk(f.server_url)) p.server_url = "channels.check.server"
    const needToken = type === "gotify" || f.token_on
    if (f.token.trim()) {
      if (!pushTokenOk(f.token)) p.token = "errors.push_token_invalid"
    } else if (needToken && !c?.token_set) p.token = "errors.push_token_missing"
  }
  if (type === "ntfy") {
    if (f.topic.trim()) {
      if (!topicOk(f.topic)) p.topic = "errors.topic_invalid"
    } else if (!c?.topic_set) p.topic = "errors.topic_missing"
    if (!tagsOk(parseTags(f.tags))) p.tags = "errors.tags_invalid"
  }
  if (type === "webhook") {
    if (f.hmac_on) {
      if (f.hmac_secret.trim()) {
        if (f.hmac_secret.trim().length < HMAC_MIN) p.hmac_secret = "errors.hmac_too_short"
      } else if (!c?.hmac_set) p.hmac_secret = "channels.check.hmacMissing"
    }
    if (f.header_on) {
      if (!headerNameOk(f.header_name)) p.header_name = "errors.header_name_invalid"
      if (!f.header_value.trim() && !c?.header_set) p.header_value = "channels.check.headerValueMissing"
    }
  }
  return p
}

/**
 * A new URL with another host while a signature secret or header value is stored and not typed again: the server
 * refuses that (secret_required) – a stored secret never goes to a new target unasked.
 */
export function needsSecretsAgain(f: ChannelForm, c?: NotifyChannel | null): boolean {
  if (c && hasServer(c.type)) {
    // another ntfy / Gotify server: the stored topic and token are not sent there unasked
    const now = hostsOf(f.server_url)
    if (!now.length || now.includes((c.host ?? "").toLowerCase())) return false
    return (c.type === "ntfy" && !!c.topic_set && !f.topic.trim()) || (!!c.token_set && (c.type === "gotify" || f.token_on) && !f.token.trim())
  }
  if (!c || c.type !== "webhook" || !f.url.trim()) return false
  const hosts = hostsOf(f.url)
  if (!hosts.length || hosts.includes((c.host ?? "").toLowerCase())) return false
  return (f.hmac_on && c.hmac_set && !f.hmac_secret.trim()) || (f.header_on && c.header_set && !f.header_value.trim())
}

// ---------------------------------------------------------------- mail server and channel state

/** E-mails can go out: a server and a sender are set (port and encryption have defaults). */
export const smtpReady = (s?: Pick<SmtpSettings, "host" | "from_addr"> | null) => !!(s?.host.trim() && s?.from_addr.trim())

/** "mail.corp.example:587" – the mail server in the status line of the channels ("" when none is set). */
export function smtpTarget(s?: Pick<SmtpSettings, "host" | "port"> | null): string {
  if (!s?.host) return ""
  const host = s.host.includes(":") && !s.host.startsWith("[") ? `[${s.host}]` : s.host // an IPv6 address
  return `${host}:${s.port}`
}

/** An e-mail channel while no mail server is set up: it cannot send – said instead of an old send error. */
export const mailServerMissing = (c: Pick<NotifyChannel, "type">, smtp?: Pick<SmtpSettings, "host" | "from_addr"> | null) => c.type === "email" && !!smtp && !smtpReady(smtp)

/** The next try after an error – only while it lies ahead (a past one is no information, the round comes anyway). */
export const upcomingTry = (c: Pick<NotifyChannel, "next_try_at">, now = Date.now()) => (c.next_try_at && Date.parse(c.next_try_at) > now ? c.next_try_at : null)

// ---------------------------------------------------------------- send results

type T = (key: string, opts?: Record<string, unknown>) => string

/** "rate_limited: 429" → the text of the category (the stored error is "<category>[: detail]"). */
export const errorCategoryText = (t: T, error: string) => t(`notify.err.${error.split(":")[0]}`, { defaultValue: error })

/** The text of a failed test send. */
export function sendError(t: T, r: SendResult): string {
  if (r.ok) return ""
  const base = t(`notify.err.${r.error}`, { defaultValue: r.error })
  return r.detail ? `${base} (${r.detail})` : base
}

/** The UI language as the server takes it for texts ("de" | "en"). */
export const uiLang = (language: string | undefined): "de" | "en" => (language?.startsWith("en") ? "en" : "de")
