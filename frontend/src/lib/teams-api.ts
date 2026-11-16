import { type QueryClient, useQuery } from "@tanstack/react-query"
import { useState } from "react"
import type { RuleSystem } from "@/lib/rule-filters"
import { api } from "@/lib/api"
import { polled } from "@/lib/poll"
import type { AbsenceView, Covering, Schedule, TeamWeekly, WeeklyMine } from "@/lib/delivery-api"

// ---------------------------------------------------------------- Teams (backend: app/teams.py, app/teams_api.py)

export interface TeamsSettings {
  enabled: boolean
  welcome_mail: boolean
  /** the ways of the personal notifications an admin allows (app/personal.py) – each off by default */
  personal_email: boolean
  personal_desktop: boolean
  personal_teams: boolean
  /** a person's own security stories by e-mail / their Teams webhook (app/personal_news.py) – off by default; older answers lack it */
  personal_news?: boolean
  /** Web Push on the server (WEB_PUSH) – desktop needs it */
  web_push: boolean
  rev: number
  /** an SMTP server with sender is set (Kanäle & Regeln → E-Mail-Server) – the welcome e-mail needs it */
  smtp_ready: boolean
  ldap_usable: boolean
  entra_usable: boolean
  base_url: string
}

export type GroupState = "loading" | "waiting" | "ok" | "error"

export interface TeamGroup {
  id: string
  source: "ldap" | "entra"
  group_id: string
  group_name: string
  state: GroupState
  /** the category of the last failed load (forbidden, user_read, connection …) */
  error: string | null
  members: number
  synced_at: string | null
}

export interface TeamProductRef {
  key: string
  label: string
  enabled: boolean
}

export interface PersonRef {
  id: string
  username: string
  display_name: string
}

/** A product of a team with its routing: for all members, or for the chosen ones (`people`). */
export interface TeamProduct extends TeamProductRef {
  all_members: boolean
  people: PersonRef[]
}

export interface Team {
  id: string
  name: string
  description: string
  version: number
  created_at: string
  groups: TeamGroup[]
  members: { group: number; manual: number }
  products: TeamProduct[]
  /** names of the rules limited to this team (it cannot be deleted while there are any) */
  rules: string[]
  /** "An mein Team weiterleiten": the notification channel a member's forward goes to (null: forwarding off) */
  forward_channel_id?: string | null
  /** the weekly review by e-mail (app/weekly.py) */
  weekly: TeamWeekly
}

export type WelcomeState = "pending" | "sending" | "sent" | "no_address" | "failed"

export interface TeamMemberRow {
  id: string
  username: string
  display_name: string
  email: string | null
  auth_source: "local" | "ldap" | "entra"
  origin: "group" | "manual"
  is_active: boolean
  deactivated_reason: string | null
  last_login_at: string | null
  welcome: WelcomeState | null
  /** the team's products this person gets (routing) */
  products: string[]
  /** a running or planned absence (app/absence.py) */
  absence: AbsenceView | null
}

export interface TeamMembers {
  total: number
  offset: number
  items: TeamMemberRow[]
}

export interface MyTeams {
  enabled: boolean
  /** `forward`: the team has a forward channel (which one is the admin's business) */
  teams: { id: string; name: string; forward?: boolean }[]
}

export const MEMBER_PAGE = 50

export const useTeamsSettings = (enabled = true) =>
  useQuery({ queryKey: ["admin", "teams", "settings"], queryFn: () => api.get<TeamsSettings>("/api/admin/teams/settings"), enabled })
/** While a group loads, the list asks again every few seconds – then it stops. */
export const useTeams = (enabled = true) =>
  useQuery({
    queryKey: ["admin", "teams", "list"],
    queryFn: polled<Team[]>((o) => api.get("/api/admin/teams", o)),
    enabled,
    refetchInterval: (q) => (q.state.data?.some((t) => t.groups.some((g) => g.state === "loading")) ? 3000 : false),
  })
export const useTeamProducts = (enabled = true) =>
  useQuery({ queryKey: ["admin", "teams", "products"], queryFn: () => api.get<TeamProductRef[]>("/api/admin/teams/products"), enabled })
export const useTeamMembers = (teamId: string, q: string, offset: number, loading: boolean, enabled = true) =>
  useQuery({
    queryKey: ["admin", "teams", "members", teamId, q, offset],
    queryFn: polled<TeamMembers>((o) => api.get(`/api/admin/teams/${teamId}/members?${new URLSearchParams({ q, offset: String(offset), limit: String(MEMBER_PAGE) })}`, o)),
    refetchInterval: loading ? 3000 : false,
    enabled,
  })
export const useMyTeams = (enabled = true) => useQuery({ queryKey: ["me", "teams"], queryFn: () => api.get<MyTeams>("/api/me/teams"), staleTime: 60_000, enabled })

/**
 * After a change of the teams (the switch, a team, its members or products): every view that depends on them is asked
 * again – the admin lists, the viewer's own teams and their "Mein Team" overview, and the personal notifications
 * ("Meine Produkte": available or not, which products), which otherwise stayed up to 30 s on what was before.
 */
export function refreshTeams(qc: QueryClient) {
  void qc.invalidateQueries({ queryKey: ["admin", "teams"] })
  void qc.invalidateQueries({ queryKey: ["admin", "users"] })
  void qc.invalidateQueries({ queryKey: ["me", "teams"] })
  void qc.invalidateQueries({ queryKey: PERSONAL_KEY })
  void qc.invalidateQueries({ queryKey: ["vendor", "overview", "team"] })
}

/**
 * What the team sheet shows for `?team=`: the form for a new one, the team, a short wait while the list is being asked
 * (`waiting`: no answer since the sheet was opened – a link to a team the cached list does not know yet), or "Team
 * nicht gefunden" (deleted, or a stale link) – never a spinner without end.
 */
export type TeamSheet = { kind: "none" } | { kind: "new" } | { kind: "team"; team: Team } | { kind: "loading" } | { kind: "missing" }
export function teamSheet(open: string | null, teams: Team[], waiting: boolean): TeamSheet {
  if (!open) return { kind: "none" }
  if (open === "new") return { kind: "new" }
  const team = teams.find((x) => x.id === open)
  if (team) return { kind: "team", team }
  return waiting ? { kind: "loading" } : { kind: "missing" }
}

/** One product's routing in the products part: for all members, or for the chosen ones. */
export type Routing = { all: boolean; people: PersonRef[] }
export const routingOf = (p: TeamProduct): Routing => ({ all: p.all_members, people: p.people })
const ALL: Routing = { all: true, people: [] }
const sameRouting = (a: Routing, b: Routing) => a.all === b.all && (a.all || JSON.stringify(a.people.map((x) => x.id).sort()) === JSON.stringify(b.people.map((x) => x.id).sort()))

/**
 * The one request of the products part (PUT …/products): the products and the routings that differ from what is
 * stored – a new product's too. The server applies all of it in one transaction (all or nothing).
 */
export function productsSave(chosen: string[], routing: Record<string, Routing>, stored: TeamProduct[]) {
  const saved = Object.fromEntries(stored.map((p) => [p.key, routingOf(p)])) as Record<string, Routing>
  const changed = chosen.filter((k) => !sameRouting(routing[k] ?? ALL, saved[k] ?? ALL))
  const productsChanged = JSON.stringify([...chosen].sort()) !== JSON.stringify(stored.map((p) => p.key).sort())
  return {
    dirty: productsChanged || changed.length > 0,
    body: {
      products: chosen,
      routing: changed.map((k) => {
        const r = routing[k] ?? ALL
        return { product: k, all_members: r.all, members: r.all ? [] : r.people.map((x) => x.id) }
      }),
    },
  }
}

/** The i18n key of a group's state line: what the last load said, with the permission it lacks when Graph refused. */
export function groupStateKey(g: Pick<TeamGroup, "state" | "error" | "source">): string {
  if (g.state !== "error") return `teams.group.state.${g.state}`
  switch (g.error) {
    case "forbidden":
      return g.source === "entra" ? "teams.group.err.graphGroupMember" : "teams.group.err.forbidden"
    case "user_read":
      return "teams.group.err.graphUserRead"
    case "not_configured":
    case "too_many":
    case "not_found":
      return `teams.group.err.${g.error}`
    default:
      return "teams.group.err.other"
  }
}

// ---------------------------------------------------------------- "Mein Team / Alle" in Vendor News, per person and browser

export type VendorScope = "team" | "all"
const scopeKey = (userId: string) => `cobe-news.vendor.scope.${userId}`

/** The remembered choice of this person in this browser – none yet: "Mein Team" (what a team is for). */
export function readScope(userId: string | undefined): VendorScope {
  if (!userId) return "all"
  try {
    return localStorage.getItem(scopeKey(userId)) === "all" ? "all" : "team"
  } catch {
    return "team"
  }
}

export function saveScope(userId: string | undefined, scope: VendorScope) {
  if (!userId) return
  try {
    localStorage.setItem(scopeKey(userId), scope)
  } catch {
    // not remembered – nothing else depends on it
  }
}

/**
 * The scope the overview loads: `null` while the viewer's teams are not known yet (nothing is loaded, nothing shown –
 * otherwise the full list would flash before "Mein Team"), "all" without Teams, without a team or when the teams could
 * not be read, else the remembered choice.
 */
export function resolveScope(teams: MyTeams | undefined, pending: boolean, choice: VendorScope): VendorScope | null {
  if (pending) return null
  return teams?.enabled && teams.teams.length > 0 ? choice : "all"
}

/** "Mein Team / Alle" of the vendor page – one state for the tab's number and the overview (one request, not two).
 *  `needed` false: the teams are not asked (the scope stays `null` – News while "Betrifft unsere Produkte" is off). */
export function useVendorScope(userId: string | undefined, needed = true) {
  const mine = useMyTeams(needed)
  const [choice, setChoice] = useState<VendorScope>(() => readScope(userId))
  const scope = resolveScope(mine.data, mine.isPending, choice)
  const setScope = (s: VendorScope) => {
    setChoice(s)
    saveScope(userId, s)
  }
  return { scope, setScope, hasTeam: scope !== null && !!mine.data?.enabled && mine.data.teams.length > 0, teams: mine.data?.teams ?? [] }
}
export type VendorScopeState = ReturnType<typeof useVendorScope>

// ---------------------------------------------------------------- "Hersteller-News meiner Produkte" (app/personal_api.py)

export type PersonalWay = "email" | "desktop" | "teams"
export const PERSONAL_WAYS: PersonalWay[] = ["email", "desktop", "teams"]
export type PersonalKind = "vendor_vuln" | "vendor_version" | "vendor_change"
export const PERSONAL_KINDS: PersonalKind[] = ["vendor_vuln", "vendor_version", "vendor_change"]

export interface WayState {
  last_ok_at: string | null
  /** "<category>[: detail]" as for the channels – or no_address / no_device */
  last_error: string | null
  last_error_at: string | null
  next_try_at: string | null
  failures: number
}

export interface PersonalNotify {
  available: boolean
  reason: "teams_off" | "no_team" | null
  /** false: available only because the person watches a CVE (no team – only those notices come) */
  in_team: boolean
  allowed: Record<PersonalWay, boolean>
  web_push: boolean
  products: { key: string; label: string; enabled: boolean; teams: string[] }[]
  lang: "de" | "en"
  kinds: PersonalKind[]
  min_severity: "critical" | "high" | "medium" | "low" | "info"
  /** only the Vendor News of these systems ([] = every product of my teams; older answers lack it) */
  systems?: RuleSystem[]
  email: { on: boolean; address: string | null; address_ok: boolean; state: WayState }
  desktop: { on: boolean; devices: number; state: WayState }
  teams: { on: boolean; url_set: boolean; url_hint: string | null; state: WayState }
  /** quiet hours, urgent, collected per way; the absence and whom the person stands in for; the weekly review */
  schedule: Schedule
  absence: AbsenceView | null
  covering: Covering[]
  weekly: WeeklyMine
}

export const PERSONAL_KEY = ["me", "vendor-notify"] as const

export const usePersonalNotify = (enabled = true) =>
  useQuery({ queryKey: PERSONAL_KEY, queryFn: () => api.get<PersonalNotify>("/api/me/vendor-notify"), enabled, staleTime: 30_000 })

/** What a way's state line says: "ok" (last delivery at), "error" (its category), or nothing yet. */
export function wayState(s: WayState): { tone: "ok" | "error" | "none"; at: string | null; error: string | null } {
  const okAt = s.last_ok_at ? Date.parse(s.last_ok_at) : 0
  const errAt = s.last_error_at ? Date.parse(s.last_error_at) : 0
  if (s.last_error && errAt >= okAt) return { tone: "error", at: s.last_error_at, error: s.last_error }
  if (s.last_ok_at) return { tone: "ok", at: s.last_ok_at, error: null }
  return { tone: "none", at: null, error: null }
}

/** A next try still ahead (one in the past waits for the next round – nothing worth a time). */
export const upcoming = (iso: string | null, now = Date.now()) => !!iso && Date.parse(iso) > now
