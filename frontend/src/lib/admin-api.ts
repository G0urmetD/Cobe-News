import { useQuery } from "@tanstack/react-query"
import { api, type ApiUser, type Role } from "@/lib/api"
import type { NewsSeverity } from "@/lib/news-api"

// ---------------------------------------------------------------- notifications

export type ChannelType = "email" | "teams" | "slack" | "discord" | "telegram" | "webhook" | "ntfy" | "gotify" | "mattermost"
export const CHANNEL_TYPES: ChannelType[] = ["email", "teams", "slack", "discord", "telegram", "mattermost", "ntfy", "gotify", "webhook"]

/** The delivery log of a channel's last 24 hours (the badge in the list) – tests not counted. */
export interface ChannelDelivery {
  last_ok_at: string | null
  last_failed_at: string | null
  attempts_24h: number
  failed_24h: number
}

/** Where notifications go (a mailbox, a chat, an own endpoint) – rules point to one or several of them. */
export interface NotifyChannel {
  id: string
  name: string
  type: ChannelType
  /** email */
  recipients: string[]
  /** telegram ("" otherwise) */
  chat_id: string
  /** teams/slack/discord/webhook: the URL is a secret – only whether one is stored and its host */
  url_set: boolean
  host: string | null
  /** telegram */
  token_set: boolean
  /** webhook */
  allow_http: boolean
  use_proxy: boolean
  hmac_set: boolean
  header_name: string
  header_set: boolean
  /** ntfy / gotify: the server's address (no secret) */
  server?: string
  /** ntfy: whether a topic is stored (the topic itself is a secret) */
  topic_set?: boolean
  /** ntfy: extra tags */
  tags?: string[]
  delivery?: ChannelDelivery
  rules: { id: string; name: string; enabled: boolean }[]
  created_at: string
  last_sent_at: string | null
  last_error: string | null
  last_error_at: string | null
  failures: number
  next_try_at: string | null
  /** what an edit is made on – an edit of an older state is refused (409 "stale") */
  version?: number
}

/** Body of POST/PUT /channels – secrets left "" keep the stored one. */
export interface ChannelIn {
  name: string
  type: ChannelType
  recipients: string[]
  url: string
  bot_token: string
  chat_id: string
  allow_http: boolean
  use_proxy: boolean
  hmac_secret: string
  clear_hmac: boolean
  header_name: string
  header_value: string
  clear_header: boolean
  /** ntfy / gotify */
  server_url: string
  /** ntfy – "" keeps the stored one */
  topic: string
  /** ntfy access token (optional) / Gotify application token – "" keeps the stored one */
  token: string
  clear_token: boolean
  tags: string[]
}

export interface NotifyRule {
  id: string
  name: string
  enabled: boolean
  channels: string[]
  severities: NewsSeverity[]
  sources: string[]
  lang: "de" | "en"
  /** what it sends: stories, Vendor News vulnerabilities of followed products, newer versions / EOL */
  kinds: RuleKind[]
  /** Teams: Vendor News events of these teams' products only ([] = every product) */
  teams: string[]
  created_at: string
  active_since: string
  /** what an edit is made on – an edit of an older state is refused (409 "stale") */
  version?: number
}

/** vendor_change: an advisory of a followed product was revised (backend app/advisory_changes.py) – chosen per rule */
export type RuleKind = "news" | "vendor_vuln" | "vendor_version" | "vendor_change" | "source_health"
export const RULE_KINDS: RuleKind[] = ["news", "vendor_vuln", "vendor_version", "vendor_change", "source_health"]

export interface RuleIn {
  name: string
  enabled: boolean
  channels: string[]
  severities: NewsSeverity[]
  sources: string[]
  lang: "de" | "en"
  kinds: RuleKind[]
  teams: string[]
}

export interface SmtpSettings {
  host: string
  port: number
  encryption: "starttls" | "tls" | "none"
  verify_cert: boolean
  username: string
  password_set: boolean
  from_addr: string
  from_name: string
  /** the saved state the form was loaded with (409 "stale" when another admin saved in between) */
  rev?: number
}

export type SendResult = { ok: true } | { ok: false; error: string; detail?: string }

export const useChannels = () => useQuery({ queryKey: ["admin", "channels"], queryFn: () => api.get<NotifyChannel[]>("/api/admin/notify/channels") })
export const useRules = () => useQuery({ queryKey: ["admin", "rules"], queryFn: () => api.get<NotifyRule[]>("/api/admin/notify/rules") })
export const useSmtp = () => useQuery({ queryKey: ["admin", "smtp"], queryFn: () => api.get<SmtpSettings>("/api/admin/notify/smtp") })

// ---------------------------------------------------------------- users and sign-in

const OFF_KEYS: Record<string, string> = {
  admin: "users.offAdmin",
  "sync:no_team": "users.offNoTeam",
  "sync:teams_off": "users.offTeamsOff",
  "sync:no_role": "users.offNoRole",
  "sync:disabled": "users.offDisabled",
  "sync:gone": "users.offGone",
  "sync:unblocked": "users.offUnblocked",
}

/**
 * The i18n keys (label, hint) for why an account is switched off: an admin's lasting block ("admin") against the
 * reasons of the sync and of Teams ("sync:…"), which switch the account on again by themselves.
 */
export function offKeys(reason: string | null): [string, string | undefined] {
  const key = reason ? OFF_KEYS[reason] : undefined
  if (key) return [key, `${key}Hint`]
  return reason?.startsWith("sync:") ? ["users.offSync", "users.offSyncHint"] : ["users.off", undefined]
}

/** The lasting block of an admin – lifted only by an admin (the switch is off already for a "sync:…" account). */
export const isBlocked = (u: { is_active: boolean; deactivated_reason: string | null }) => !u.is_active && u.deactivated_reason === "admin"

/** Before removing a role mapping: whom it concerns (GET /api/admin/auth/mappings/{id}/impact). */
export interface MappingImpact {
  /** no role left: switched off and signed out */
  lost: number
  /** admin → reader: signed out */
  demoted: number
  /** groups not known yet (signed in before they were kept): signed out to be safe */
  unknown: number
  affected: number
  /** the admin's own access hangs on this group – refused */
  self: boolean
}

/** Before switching AD/LDAP or Entra ID off (GET /api/admin/auth/{source}/impact). */
export interface SourceImpact {
  /** accounts of the source signed in now */
  accounts: number
  /** the admin is an account of this source – refused */
  self: boolean
}

export interface UserRow extends ApiUser {
  is_active: boolean
  deactivated_reason: string | null
  must_change_password: boolean
  /** when the temporary password stops being accepted (null: none) – set up by an admin or the CLI reset */
  temp_password_expires_at?: string | null
  /** … and whether that time has passed: a sign-in with it is refused, a new one has to be issued */
  temp_password_expired?: boolean
  locked_for: number
  created_at: string
  last_login_at: string | null
  /** what an edit is made on – an edit of an older state is refused (409 "stale") */
  version: number
  /** Teams: the teams of the account */
  teams?: string[]
  /** Teams: the welcome e-mail of a loaded account (null: none planned) */
  welcome?: "pending" | "sending" | "sent" | "no_address" | "failed" | null
  /** registered passkeys (local accounts) */
  passkeys?: number
}

export interface LdapSettings {
  enabled: boolean
  servers: string[]
  encryption: "ldaps" | "starttls" | "none"
  allow_plain: boolean
  verify_cert: boolean
  ca_cert: string
  base_dn: string
  bind_dn: string
  bind_password_set: boolean
  user_filter: string
  nested_groups: boolean
  timeout: number
  usable: boolean
  /** the saved state the form was loaded with (409 "stale" when another admin saved in between) */
  rev?: number
}

/** "MFA-Nachweis" (backend app/auth/entra.py): trust Conditional Access | the authentication context must be in the
 *  token | a proof in the token or Cobe News' own TOTP */
export type EntraMfaMode = "entra" | "context" | "require"

export interface EntraSettings {
  enabled: boolean
  tenant_id: string
  client_id: string
  client_secret_set: boolean
  redirect_uri: string
  usable: boolean
  mfa_mode: EntraMfaMode
  /** c1 … c99 – "" when none is configured */
  auth_context: string
  rev?: number
}

/** "Zweiter Faktor für alle" (GET/PUT /api/admin/auth/mfa) */
export interface MfaSettings {
  required_all: boolean
  rev: number
}

/** An authentication context id as Entra names them: C1 … C99 (case does not matter). */
export const AUTH_CONTEXT = /^[cC]([1-9]|[1-9][0-9])$/

export interface GroupMapping {
  id: string
  source: "ldap" | "entra"
  group_id: string
  group_name: string
  role: Role
}

export interface DirectoryGroup {
  id: string
  name: string
  description: string
  path: string
}

export interface SessionSettings {
  idle_min: number
  absolute_h: number
  /** how many days a temporary password is valid (1–30, default 7) */
  temp_password_days: number
  rev?: number
}

export const useUsers = () => useQuery({ queryKey: ["admin", "users"], queryFn: () => api.get<UserRow[]>("/api/admin/users") })
export const useLdap = () => useQuery({ queryKey: ["admin", "ldap"], queryFn: () => api.get<LdapSettings>("/api/admin/auth/ldap") })
export const useEntra = () => useQuery({ queryKey: ["admin", "entra"], queryFn: () => api.get<EntraSettings>("/api/admin/auth/entra") })
export const useMappings = () => useQuery({ queryKey: ["admin", "mappings"], queryFn: () => api.get<GroupMapping[]>("/api/admin/auth/mappings") })
export const useSessionSettings = () => useQuery({ queryKey: ["admin", "sessions"], queryFn: () => api.get<SessionSettings>("/api/admin/auth/sessions") })
export const useMfaSettings = () => useQuery({ queryKey: ["admin", "mfa"], queryFn: () => api.get<MfaSettings>("/api/admin/auth/mfa") })

// ---------------------------------------------------------------- HTTPS

export interface TlsStatus {
  mode: "selfsigned" | "own" | "external"
  base_url: string
  hostname: string
  problems: string[]
  hsts?: boolean
  subject?: string
  issuer?: string
  self_signed?: boolean
  ours?: boolean
  names?: string[]
  not_before?: string
  not_after?: string
  days_left?: number
  fingerprint?: string
  renews_at?: string | null
  /** what needs a look besides the certificate: a short master key, the emergency admin's failure budget exceeded */
  system?: SystemWarning[]
}

export type SystemWarning = { code: "secret_key_short"; source: "env" | "file"; min: number } | { code: "emergency_failures"; at: string; failures: number }

export const useTls = () => useQuery({ queryKey: ["admin", "tls"], queryFn: () => api.get<TlsStatus>("/api/admin/tls"), staleTime: 60_000 })
