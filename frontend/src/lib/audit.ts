import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query"
import type { TFunction } from "i18next"
import { api, DETAIL_TIMEOUT_MS, detailRetry } from "@/lib/api"

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
    "login.ip_blocked",
    "login.emergency_slowed",
    "setup.completed",
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
    "team.synced",
  ],
  settings: ["settings.changed"],
  backup: ["backup.created", "backup.restored", "backup.deleted", "restore_test.run", "export.downloaded", "audit.exported"],
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

export type ActorKind = "user" | "system" | "sync" | "cli"

export interface AuditActor {
  kind: ActorKind
  id: string | null
  name: string
  display: string
}

export interface AuditEntry {
  id: number
  at: string
  actor: AuditActor
  action: string
  group: AuditGroup
  target: { type: string; id: string | null; label: string | null } | null
  ip: string | null
  details: Record<string, unknown>
}

export interface AuditPage {
  items: AuditEntry[]
  next: string | null
  groups: Record<string, string[]>
}

export interface AuditSettings {
  keep_days: number
  keep_min: number
  keep_max: number
  keep_default: number
  rev: number
}

export interface AuditFilters {
  group: string
  actor: string
  /** calendar days in the reader's time zone ("2026-10-31"); `to` counts as a whole day */
  from: string
  to: string
  q: string
}

export const NO_FILTERS: AuditFilters = { group: "", actor: "", from: "", to: "", q: "" }

export const isFiltered = (f: AuditFilters) => Object.values(f).some((v) => v.trim() !== "")

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

/** The filters as query parameters (empty ones left out; the "to" day included as a whole). */
export function filterParams(f: AuditFilters): URLSearchParams {
  const p = new URLSearchParams()
  if (f.group) p.set("group", f.group)
  if (f.actor) p.set("actor", f.actor)
  const since = f.from ? dayStart(f.from) : null
  const until = f.to ? dayStart(f.to, 1) : null
  if (since) p.set("since", since)
  if (until) p.set("until", until)
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

export const exportPath = (f: AuditFilters) => {
  const q = filterParams(f).toString()
  return `/api/admin/audit/export${q ? `?${q}` : ""}`
}

// ---------------------------------------------------------------- texts

/** The action in words ("Rolle geändert"); an action this version has no text for: its key. */
export const actionText = (t: TFunction, action: string) => t(`audit.action.${action}`, { defaultValue: action })

/** Who: the account's display name (and its sign-in name when it differs), or the system, the directory sync, the CLI. */
export function actorText(t: TFunction, a: AuditActor): string {
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
    .filter(([k]) => k !== "changes")
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

/** A field's name in words where the UI knows it ("bind_password" → "Bind-Passwort"), else as stored. */
export const fieldText = (t: TFunction, field: string) => t(`audit.field.${field}`, { defaultValue: field })

/** How many changes an entry carries (the row shows it as a hint before it is opened). */
export const changeCount = (e: AuditEntry) => detailRows(e.details).changes.length
