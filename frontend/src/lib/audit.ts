import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query"
import type { TFunction } from "i18next"
import { api, DETAIL_TIMEOUT_MS, detailRetry } from "@/lib/api"
import { fmtBytes } from "@/lib/backup"

// ---------------------------------------------------------------- the audit log (backend app/audit.py, app/audit_api.py)

/** action → group, as the server's audit.GROUPS (the server sends its list with every page – this one is the fallback
 *  and what the texts are checked against: every action has a text in both languages, audit.test.ts). */
export const AUDIT_GROUPS = {
  accounts: [
    "user.created",
    "user.changed",
    "user.deleted",
    "user.activated",
    "user.deactivated",
    "user.blocked",
    "user.unblocked",
    "user.reset",
    "user.unlocked",
    "role.changed",
    "account.password_changed",
    "account.totp_enabled",
    "account.totp_removed",
    "passkey.added",
    "passkey.renamed",
    "passkey.removed",
    "passkey.sign_count_warning",
    "sessions.revoked",
  ],
  signin: [
    "signin.config_changed",
    "role_mapping.created",
    "role_mapping.deleted",
    "login.success",
    "login.locked",
    "login.locked_unknown",
    "login.ip_blocked",
    "login.emergency_slowed",
    "setup.completed",
    "setup.token_issued",
  ],
  tokens: ["token.created", "token.revoked"],
  notify: ["channel.created", "channel.changed", "channel.deleted", "rule.created", "rule.changed", "rule.deleted", "delivery.resent"],
  teams: [
    "team.created",
    "team.changed",
    "team.deleted",
    "team.group_added",
    "team.group_removed",
    "team.member_added",
    "team.member_removed",
    "team.products_changed",
    "team.routing_changed",
    "team.weekly_changed",
    "team.absence_set",
    "team.absence_ended",
    "team.sync_started",
    "team.synced",
  ],
  settings: ["settings.changed"],
  backup: [
    "backup.created",
    "backup.restored",
    "backup.deleted",
    "backup.imported",
    "restore_test.run",
    "restore_test.done",
    "export.downloaded",
    "audit.exported",
    "audit.chain_problem",
    "audit.chain_rekeyed",
    "audit.pruned",
  ],
  sources: [
    "source.created",
    "source.changed",
    "source.deleted",
    "catalog.followed",
    "catalog.unfollowed",
    "catalog.follow_changed",
    "catalog.custom_added",
    "catalog.version_added",
    "catalog.version_changed",
    "catalog.version_deleted",
    "catalog.version_confirmed",
    "catalog.versions_confirmed",
    "catalog.refreshed",
    "suggestion.accepted",
    "suggestion.rejected",
    "suggestion.duplicate",
  ],
} as const satisfies Record<string, readonly string[]>

export type AuditGroup = keyof typeof AUDIT_GROUPS | "other"
export const GROUP_KEYS = Object.keys(AUDIT_GROUPS) as (keyof typeof AUDIT_GROUPS)[]
export const ALL_ACTIONS: string[] = GROUP_KEYS.flatMap((g) => [...AUDIT_GROUPS[g]])
/** The reasons an entry is marked (backend audit.ANOMALIES) – each has a text in both languages. */
export const ANOMALIES = ["emergency_off_hours", "new_address", "failures_before", "role_admin", "retention_lowered", "audit_export", "late_entry", "future_entry"] as const

export type ActorKind = "user" | "system" | "sync" | "cli"

export interface AuditActor {
  kind: ActorKind
  id: string | null
  name: string
  display: string
  /** the account's role and whether it was the emergency account – entries before 0.1.50 have neither */
  role?: string | null
  emergency?: boolean | null
}

export interface AuditBrowser {
  family: string | null
  version: string | null
  os: string | null
}

export interface AuditEntry {
  id: number
  at: string
  actor: AuditActor
  action: string
  group: AuditGroup
  target: { type: string; id: string | null; label: string | null } | null
  ip: string | null
  /** loopback | gateway | shared | internal | external */
  ip_class?: string | null
  /** direct | bundled | proxy | bundled_proxy */
  via?: string | null
  browser?: AuditBrowser | null
  session?: { ref: string | null; method: string | null } | null
  request?: { method: string | null; path: string | null; id: string | null } | null
  app_version?: string | null
  notable?: boolean
  anomalies?: string[]
  /** the position in the integrity chain (null: not sealed yet) */
  seq?: number | null
  details: Record<string, unknown>
}

export interface AuditBrief {
  id: number
  at: string
  action: string
  actor: { kind: ActorKind; name: string; display: string }
  ip: string | null
}

export interface AuditContext {
  history: AuditBrief[]
  session: { ref: string; entries: number; first: string | null; last: string | null } | null
  ip_24h: { entries: number; locks: number } | null
  previous_signin: { id: number; at: string; ip: string | null; ip_class: string | null; method: string | null; browser: AuditBrowser | null } | null
}

export interface AuditPage {
  items: AuditEntry[]
  next: string | null
  groups: Record<string, string[]>
  total?: number
  total_more?: boolean
}

export interface AuditChain {
  state: "ok" | "problem" | "other_key" | "empty"
  sealed_seq: number | null
  verified_seq: number | null
  verified_at: string | null
  full_at: string | null
  anchor_seq: number
  unsealed: number
  problems: { id: number | null; seq: number; kind: string; count?: number }[]
  /** problems found earlier (audit.chain_problem entries) that an operator has not acknowledged yet */
  logged_problems?: number
  /** when an operator last anchored the chain anew (shown for good) */
  rekeyed_at: string | null
  /** another check (the hourly one) is running – this is the state as it is */
  busy?: boolean
}

/** The chain's state in words for the badge. */
export function chainText(t: TFunction, chain: AuditChain): string {
  if (chain.state === "ok") return t("audit.chain.ok")
  if (chain.state === "other_key") return t("audit.chain.state.other_key")
  const p = chain.problems[0]
  if (p?.kind === "state") return t("audit.chain.state.stateChanged")
  if (p?.kind === "tail") return t("audit.chain.state.tail", { count: p.count ?? 1, id: p.id ?? p.seq })
  if (p) return t("audit.chain.state.problem", { id: p.id ?? p.seq })
  return t("audit.chain.state.logged", { count: chain.logged_problems ?? 0 })
}

export interface AuditSettings {
  keep_days: number
  keep_min: number
  keep_max: number
  keep_default: number
  rev: number
}

export const RANGES = ["24h", "7d", "30d", "90d"] as const
export type Range = (typeof RANGES)[number]
const RANGE_MS: Record<Range, number> = { "24h": 864e5, "7d": 7 * 864e5, "30d": 30 * 864e5, "90d": 90 * 864e5 }

export interface AuditFilters {
  group: string
  actor: string
  /** a preset time range (the last 24 hours …) – else `from`/`to` */
  range: "" | Range
  /** calendar days in the reader's time zone ("2026-10-31"); `to` counts as a whole day */
  from: string
  to: string
  q: string
  /** "Nur Auffälliges": anomalies and the security-relevant actions */
  notable: boolean
  // value filters (the "+" next to a value; shown as chips)
  ip: string
  session: string
  action: string
  targetType: string
  targetId: string
  /** how the target chip names it (not sent) */
  targetLabel: string
  /** how the account chip names it (not sent) */
  actorLabel: string
}

export const NO_FILTERS: AuditFilters = {
  group: "",
  actor: "",
  range: "",
  from: "",
  to: "",
  q: "",
  notable: false,
  ip: "",
  session: "",
  action: "",
  targetType: "",
  targetId: "",
  targetLabel: "",
  actorLabel: "",
}

const VALUE_KEYS = ["actor", "ip", "session", "action", "targetType"] as const

export const isFiltered = (f: AuditFilters) => f.notable || !!f.range || [f.group, f.actor, f.from, f.to, f.q, f.ip, f.session, f.action, f.targetType].some((v) => v.trim() !== "")

/** Value filters are set (the chip row shows them and the hit count). */
export const hasValueFilters = (f: AuditFilters) => VALUE_KEYS.some((k) => f[k] !== "")

export interface Chip {
  key: "actor" | "ip" | "session" | "action" | "target"
  label: string
  value: string
}

/** The chips of the value filters, in a fixed order. */
export function valueChips(t: TFunction, f: AuditFilters): Chip[] {
  const out: Chip[] = []
  if (f.actor)
    out.push({ key: "actor", label: t("audit.chip.actor"), value: f.actorLabel || (["system", "sync", "cli"].includes(f.actor) ? t(`audit.actor.${f.actor}`) : f.actor) })
  if (f.ip) out.push({ key: "ip", label: t("audit.chip.ip"), value: f.ip })
  if (f.session) out.push({ key: "session", label: t("audit.chip.session"), value: sessionText(f.session) })
  if (f.action) out.push({ key: "action", label: t("audit.chip.action"), value: actionText(t, f.action) })
  if (f.targetType)
    out.push({ key: "target", label: t("audit.chip.target"), value: f.targetLabel || f.targetId || t(`audit.target.${f.targetType}`, { defaultValue: f.targetType }) })
  return out
}

/** A chip removed: its filter (and its label) cleared. */
export function withoutChip(f: AuditFilters, key: Chip["key"]): AuditFilters {
  if (key === "target") return { ...f, targetType: "", targetId: "", targetLabel: "" }
  if (key === "actor") return { ...f, actor: "", actorLabel: "" }
  return { ...f, [key]: "" }
}

/** The group of an action (the server's word first). */
export function groupOf(action: string): AuditGroup {
  for (const g of GROUP_KEYS) if ((AUDIT_GROUPS[g] as readonly string[]).includes(action)) return g
  return "other"
}

/** Local midnight of a calendar day as an ISO time with zone – what the server's since/until want. */
function dayStart(day: string, plusDays = 0): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day)
  if (!m) return null
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]) + plusDays)
  return Number.isNaN(d.getTime()) ? null : d.toISOString()
}

/** The filters as query parameters (empty ones left out; the "to" day included as a whole; a preset range from now). */
export function filterParams(f: AuditFilters, now: number = Date.now()): URLSearchParams {
  const p = new URLSearchParams()
  if (f.group) p.set("group", f.group)
  if (f.actor) p.set("actor", f.actor)
  if (f.range) {
    p.set("since", new Date(now - RANGE_MS[f.range]).toISOString())
  } else {
    const since = f.from ? dayStart(f.from) : null
    const until = f.to ? dayStart(f.to, 1) : null
    if (since) p.set("since", since)
    if (until) p.set("until", until)
  }
  if (f.notable) p.set("notable", "1")
  if (f.ip) p.set("ip", f.ip)
  if (f.session) p.set("session", f.session)
  if (f.action) p.set("action", f.action)
  if (f.targetType) p.set("target_type", f.targetType)
  if (f.targetId) p.set("target_id", f.targetId)
  if (f.q.trim()) p.set("q", f.q.trim())
  return p
}

export const AUDIT_KEY = ["admin", "audit"] as const
export const AUDIT_PAGE = 50

export const useAuditLog = (f: AuditFilters) =>
  useInfiniteQuery({
    queryKey: [...AUDIT_KEY, "entries", f],
    queryFn: ({ signal, pageParam }) => {
      const p = filterParams(f)
      p.set("limit", String(AUDIT_PAGE))
      if (pageParam) p.set("cursor", pageParam)
      else if (hasValueFilters(f)) p.set("total", "1") // the chips show the hit count
      return api.get<AuditPage>(`/api/admin/audit?${p.toString()}`, { signal, timeoutMs: DETAIL_TIMEOUT_MS })
    },
    initialPageParam: "",
    getNextPageParam: (last: AuditPage) => last.next ?? undefined,
    retry: detailRetry,
    retryDelay: 1000,
    placeholderData: keepPreviousData,
  })

export const useAuditActors = () => useQuery({ queryKey: [...AUDIT_KEY, "actors"], queryFn: () => api.get<AuditActor[]>("/api/admin/audit/actors"), staleTime: 60_000 })

export const useAuditSettings = () => useQuery({ queryKey: [...AUDIT_KEY, "settings"], queryFn: () => api.get<AuditSettings>("/api/admin/audit/settings") })

/** One entry with its surroundings – fetched when it is opened. */
export const useAuditEntry = (id: number) =>
  useQuery({
    queryKey: [...AUDIT_KEY, "entry", id],
    queryFn: ({ signal }) => api.get<AuditEntry & { context: AuditContext }>(`/api/admin/audit/${id}`, { signal, timeoutMs: DETAIL_TIMEOUT_MS }),
    retry: detailRetry,
    staleTime: 30_000,
  })

/** The integrity chain: the new entries sealed and checked (incrementally) whenever the page is opened. */
export const useAuditChain = () =>
  useQuery({
    queryKey: [...AUDIT_KEY, "chain"],
    queryFn: () => api.get<AuditChain>("/api/admin/audit/chain", { timeoutMs: 30_000 }),
    staleTime: 30_000,
    // while the hourly check runs, the answer is the state before it: asked again until it is done
    refetchInterval: (q) => (q.state.data?.busy ? 3000 : false),
  })

/** The export's address: the filters, and the delimiter of the reader's language (German Excel splits on ";"). */
export const exportPath = (f: AuditFilters, lang = "en") => {
  const p = filterParams(f)
  if (lang.startsWith("de")) p.set("delimiter", "semicolon")
  const q = p.toString()
  return `/api/admin/audit/export${q ? `?${q}` : ""}`
}

// ---------------------------------------------------------------- texts

/** The action in words ("Rolle geändert"); an action this version has no text for: its key. */
export const actionText = (t: TFunction, action: string) => t(`audit.action.${action}`, { defaultValue: action })

/** Who: the account's display name (and its sign-in name when it differs), or the system, the directory sync, the CLI. */
export function actorText(t: TFunction, a: { kind: ActorKind; name: string; display: string; id?: string | null }): string {
  if (a.kind !== "user") return t(`audit.actor.${a.kind}`)
  if (a.display && a.display !== a.name) return `${a.display} (${a.name})`
  return a.name || a.display || "—"
}

/** On what: its name then, else its kind ("Einstellungen · smtp"). */
export function targetText(t: TFunction, target: AuditEntry["target"]): string {
  if (!target) return "—"
  const kind = t(`audit.target.${target.type}`, { defaultValue: target.type })
  const label = target.label ?? target.id
  return label ? `${kind} · ${label}` : kind
}

/** A session's reference, short ("3f9a1c…"). */
export const sessionText = (ref: string) => (ref.length > 6 ? `${ref.slice(0, 6)}…` : ref)

/** How a session was signed in, in words: "Passwort + TOTP · lokal". */
export function methodText(t: TFunction, method: string | null | undefined): string {
  if (!method) return "—"
  const [way, second] = method.split("_")
  const where = way === "ldap" ? "ldap" : way === "entra" ? "entra" : "local"
  const how = t(`audit.method.${way}`, { defaultValue: way }) + (second === "totp" ? ` + ${t("audit.method.totp")}` : "")
  return `${how} · ${t(`audit.source.${where}`)}`
}

/** "Firefox 144 · macOS" – what is known of the browser (only family, major version and system are stored). */
export function browserText(b: AuditBrowser | null | undefined): string | null {
  if (!b) return null
  const name = [b.family === "other" ? null : b.family, b.version].filter(Boolean).join(" ")
  return [name, b.os].filter(Boolean).join(" · ") || null
}

/** The page of the app a target is on – null when there is none. */
export function targetLink(target: AuditEntry["target"]): string | null {
  if (!target) return null
  const id = target.id ? encodeURIComponent(target.id) : ""
  switch (target.type) {
    case "user":
      return "/settings/users"
    case "team":
      return id ? `/settings/teams?team=${id}` : "/settings/teams"
    case "teams":
      return "/settings/teams"
    case "channel":
    case "rule":
      return "/settings/rules"
    case "news_source":
    case "catalog":
      return "/settings/integrations"
    case "product":
      return id ? `/vendor?product=${id}` : "/vendor"
    case "api_token":
      return "/settings/api"
    case "role_mapping":
      return "/settings/users?tab=mapping"
    case "signin":
      return "/settings/auth"
    case "backup":
      return "/settings/backup"
    case "restore_test":
      return "/settings/backup?tab=restore"
    case "settings":
      return SETTINGS_LINK[target.id ?? ""] ?? null
    default:
      return null
  }
}

/** Where a settings section lives in the app (the path's words are audit.path.<section>). */
const SETTINGS_LINK: Record<string, string> = {
  news: "/settings/integrations",
  vendor: "/settings/integrations",
  smtp: "/settings/rules?smtp=1",
  backup: "/settings/backup",
  restore_test: "/settings/backup?tab=restore",
  updates: "/about",
  teams: "/settings/teams?tab=settings",
  passkeys: "/settings/auth",
  audit: "/settings/audit?tab=retention",
}
export const SETTINGS_SECTIONS = [...Object.keys(SETTINGS_LINK), "webpush"]
export const SIGNIN_SECTIONS = ["sessions", "mfa", "ldap", "entra"]

/** The path in the app of a changed setting ("Einstellungen › Über Cobe News › Neue Versionen"), or null. */
export function settingsPath(t: TFunction, target: AuditEntry["target"]): string | null {
  if (!target?.id) return null
  if (target.type === "settings" || target.type === "signin") {
    const key = `audit.path.${target.type === "signin" ? "signin." : ""}${target.id}`
    const text = t(key, { defaultValue: "" })
    return text || null
  }
  return null
}

/** How far the chain vouches for an entry: ok (checked), pending (not sealed yet), problem, unchecked (sealed, not
 *  checked yet – the next check does), unknown (no answer yet, or sealed with another key). */
export function chainOf(e: Pick<AuditEntry, "id" | "seq">, chain: AuditChain | undefined): "ok" | "pending" | "problem" | "unchecked" | "unknown" {
  if (!chain) return "unknown"
  if (e.seq == null) return "pending"
  if (chain.problems.some((p) => p.id === e.id)) return "problem"
  if (chain.state === "other_key") return "unknown"
  return chain.verified_seq != null && e.seq <= chain.verified_seq ? "ok" : "unchecked"
}

// ---------------------------------------------------------------- details: before / after

export interface ChangeRow {
  field: string
  from: unknown
  to: unknown
  /** a secret field: only that it changed – the server never stores a value */
  secret: boolean
  /** changed, no values logged (a URL with another path, the same host) */
  changedOnly: boolean
}

export interface InfoRow {
  field: string
  value: unknown
}

const isMark = (v: unknown): boolean => !!v && typeof v === "object" && !Array.isArray(v) && (v as Record<string, unknown>).secret === true

/** `details.changes` as rows (sorted by field), the other details as information rows. */
export function detailRows(details: Record<string, unknown> | null | undefined): { changes: ChangeRow[]; info: InfoRow[] } {
  const d = details ?? {}
  const raw = d.changes && typeof d.changes === "object" && !Array.isArray(d.changes) ? (d.changes as Record<string, unknown>) : {}
  const changes = Object.entries(raw)
    .map(([field, v]): ChangeRow => {
      if (isMark(v)) return { field, from: null, to: null, secret: true, changedOnly: false }
      const o = (v && typeof v === "object" ? v : {}) as Record<string, unknown>
      if (!("from" in o) && !("to" in o)) return { field, from: null, to: null, secret: false, changedOnly: true }
      return { field, from: o.from ?? null, to: o.to ?? null, secret: false, changedOnly: false }
    })
    .sort((a, b) => a.field.localeCompare(b.field))
  const info = Object.entries(d)
    .filter(([k]) => k !== "changes" && k !== "anomalies")
    .map(([field, value]) => ({ field, value }))
  return { changes, info }
}

/** A logged value as text: — for nothing, yes/no, lists joined, a secret as •••, objects as compact JSON. */
export function fmtValue(t: TFunction, v: unknown): string {
  if (v === null || v === undefined || v === "") return "—"
  if (typeof v === "boolean") return v ? t("audit.value.yes") : t("audit.value.no")
  if (isMark(v)) return "•••"
  if (Array.isArray(v)) return v.length ? v.map((x) => fmtValue(t, x)).join(", ") : "—"
  if (typeof v === "object") return JSON.stringify(v)
  return String(v)
}

/** A whole number grouped the reader's way ("88.508", "88,508"). */
export const fmtNumber = (n: number, lang: string) => new Intl.NumberFormat(lang.startsWith("en") ? "en-GB" : "de-DE").format(n)

/** Seconds as a short duration ("15 min", "2 Std."). */
export function fmtSeconds(t: TFunction, s: number, lang: string): string {
  if (s < 120) return t("audit.unit.s", { value: fmtNumber(Math.round(s), lang) })
  if (s < 7200) return t("audit.unit.min", { value: fmtNumber(Math.round(s / 60), lang) })
  return t("audit.unit.h", { value: new Intl.NumberFormat(lang.startsWith("en") ? "en-GB" : "de-DE", { maximumFractionDigits: 1 }).format(s / 3600) })
}

/** A logged value in words for its field: sizes, durations and numbers the reader's way, known values (reasons,
 *  triggers, steps …: audit.val.<field>.<value>) in words, the rest as fmtValue. */
export function fmtField(t: TFunction, field: string, v: unknown, lang = "de"): string {
  if (typeof v === "number") {
    if (field === "size") return fmtBytes(v, lang)
    if (field.endsWith("_s")) return fmtSeconds(t, v, lang)
    return fmtNumber(v, lang)
  }
  if (typeof v === "string" && v) return t(`audit.val.${field}.${v}`, { defaultValue: v })
  if (Array.isArray(v) && v.every((x) => typeof x === "string")) return v.length ? v.map((x) => fmtField(t, field, x, lang)).join(", ") : "—"
  return fmtValue(t, v)
}

/** A field's name in words where the UI knows it ("bind_password" → "Bind-Passwort"), else as stored. */
export const fieldText = (t: TFunction, field: string) => t(`audit.field.${field}`, { defaultValue: field })

/** How many changes an entry carries (the row shows it as a hint before it is opened). */
export const changeCount = (e: AuditEntry) => detailRows(e.details).changes.length

/** The entry as JSON (the footer's copy) – what the server sent, without the expanded view's surroundings. */
export function entryJson(e: AuditEntry): string {
  const { ...plain } = e as AuditEntry & { context?: unknown }
  delete (plain as { context?: unknown }).context
  return JSON.stringify(plain, null, 2)
}
