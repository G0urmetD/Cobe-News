import { useQuery } from "@tanstack/react-query"
import type { TFunction } from "i18next"
import { api } from "@/lib/api"
import { polled } from "@/lib/poll"
import type { ActorKind } from "@/lib/audit"
import { targetLink } from "@/lib/audit"

// ---------------------------------------------------------------- "Meldungen" in the sidebar (backend app/activity_api.py, admins only)

/** The audit actions the box shows (backend activity_api.ACTIONS) – each has a text in both languages
 *  (activity.text.<action>, activity.test.ts). The approval ones come with the approval of new accounts and roles. */
export const ACTIVITY_ACTIONS = [
  "user.approval_pending",
  "role.approval_pending",
  "user.approved",
  "user.declined",
  "role.approved",
  "role.declined",
  "user.created",
  "user.deactivated",
  "role.changed",
  "catalog.followed",
  "catalog.custom_added",
  "backup.restored",
] as const
/** The sign-ins (from the accounts – no audit action). */
export const SIGNIN = "signin"
/** They need an admin's step: they stand out (and give the collapsed sidebar's bell its dot). */
export const PENDING_ACTIONS: readonly string[] = ["user.approval_pending", "role.approval_pending"]
/** Where a pending approval is dealt with. */
export const PENDING_LINK = "/settings/users?waiting=1"
export const ACTIVITY_LIMIT = 3

export interface ActivityItem {
  /** stable per line: a<entry id> or s<account id> */
  id: string
  /** the audit entry (null for the sign-ins) */
  entry: number | null
  action: string
  at: string
  actor: { kind: ActorKind; id: string | null; name: string; display: string; role?: string }
  target: { type: string; id: string | null; label: string | null; display?: string | null } | null
  /** what of the entry the texts use: role (also the new one of a change), why */
  details: { role?: string; why?: string }
  /** sign-ins: how many others signed in right before (one line), and whether there were even more */
  others?: number
  others_more?: boolean
  names?: string[]
  /** a "… wartet auf Freigabe" line: whether it still waits (approved, declined or gone: false) */
  open?: boolean
}

export interface Activity {
  items: ActivityItem[]
  /** accounts and raises to admin waiting now – also those whose line is not among the newest */
  pending?: number
}

export const ACTIVITY_KEY = ["admin", "activity"] as const

/** The newest lines – polled every minute while the tab is visible (TanStack Query does not poll a hidden tab), sent
 *  as background requests (a session is not kept alive by it), again when the window comes back. */
export const useActivity = (enabled: boolean) =>
  useQuery({
    queryKey: [...ACTIVITY_KEY, ACTIVITY_LIMIT],
    queryFn: polled<Activity>((o) => api.get(`/api/admin/activity?limit=${ACTIVITY_LIMIT}`, o)),
    enabled,
    staleTime: 30_000,
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
  })

export type ActivityIcon = "signin" | "pending" | "approved" | "declined" | "role" | "created" | "deactivated" | "followed" | "product" | "restored" | "other"

export interface ActivityView {
  text: string
  icon: ActivityIcon
  /** the place in the app it leads to */
  to: string
  /** needs an admin's step */
  urgent: boolean
  /** a tooltip: the names of a joined sign-in line */
  title?: string
}

const ICON: Record<string, ActivityIcon> = {
  signin: "signin",
  "user.approval_pending": "pending",
  "role.approval_pending": "pending",
  "user.approved": "approved",
  "user.declined": "declined",
  "role.approved": "role",
  "role.declined": "declined",
  "role.changed": "role",
  "user.created": "created",
  "user.deactivated": "deactivated",
  "catalog.followed": "followed",
  "catalog.custom_added": "product",
  "backup.restored": "restored",
}

/** Who did it: the display name (else the sign-in name); the system, the directory sync, the command line by kind. */
function who(t: TFunction, a: ActivityItem["actor"]): string {
  if (a.kind !== "user") return t(`audit.actor.${a.kind}`)
  return a.display || a.name || "—"
}

/** What it is about: an account by its current name, else the name the log kept. */
function what(target: ActivityItem["target"]): string {
  if (!target) return "—"
  return target.display || target.label || target.id || "—"
}

/** The Protokoll filtered to the entry's action and target, the entry opened. */
export function auditLink(item: ActivityItem): string {
  const p = new URLSearchParams()
  if (item.action === SIGNIN) {
    p.set("action", "login.success")
    if (item.actor.id) p.set("actor", item.actor.id)
    const label = item.actor.display || item.actor.name
    if (label) p.set("who", label)
  } else {
    p.set("action", item.action)
    if (item.target?.type) {
      p.set("target_type", item.target.type)
      if (item.target.id) p.set("target_id", item.target.id)
      const label = item.target.display || item.target.label
      if (label) p.set("what", label)
    }
    if (item.entry) p.set("open", String(item.entry))
  }
  return `/settings/audit?${p.toString()}`
}

/** A waiting line that still waits (an older server without `open`: as before). */
export const stillWaits = (item: ActivityItem) => PENDING_ACTIONS.includes(item.action) && item.open !== false

/** The collapsed sidebar's bell has its dot: something waits now – whether or not its line is among the newest. */
export const anyWaiting = (a: Activity, waits: (i: ActivityItem) => boolean = stillWaits) => (a.pending !== undefined ? a.pending > 0 : a.items.some(waits))

function linkOf(item: ActivityItem): string {
  if (stillWaits(item)) return PENDING_LINK
  if (item.action === SIGNIN) {
    // the Protokoll has the admins' sign-ins only; a reader's – and a joined line – are on the accounts page
    return item.actor.role === "admin" && !item.others ? auditLink(item) : "/settings/users"
  }
  if (item.action === "catalog.followed" || item.action === "catalog.custom_added") return targetLink(item.target) ?? auditLink(item)
  return auditLink(item)
}

/** The role in words, for the texts that name it ("als Admin"). */
const isAdmin = (d: ActivityItem["details"]) => d.role === "admin"

/** One line as the box shows it: its text in the reader's language, its icon, where it leads, whether it stands out. */
export function activityView(t: TFunction, item: ActivityItem): ActivityView {
  const name = who(t, item.actor)
  const target = what(item.target)
  const auto = item.actor.kind !== "user" // the directory sync, the system, the command line: said without a name
  const d = item.details ?? {}
  let text: string
  switch (item.action) {
    case SIGNIN: {
      const others = item.others ?? 0
      text = !others ? t("activity.text.signin", { name }) : t(item.others_more ? "activity.text.signinMore" : "activity.text.signinOthers", { name, count: others })
      break
    }
    case "user.approval_pending":
      text = t(stillWaits(item) ? "activity.text.user.approval_pending" : "activity.text.user.approval_pending.done", { target })
      break
    case "role.approval_pending": {
      const key = isAdmin(d) ? "activity.text.role.approval_pending.admin" : "activity.text.role.approval_pending"
      text = t(stillWaits(item) ? key : `${key}.done`, { target })
      break
    }
    case "role.approved":
      text = t(isAdmin(d) ? "activity.text.role.approved.admin" : "activity.text.role.approved", { name, target })
      break
    case "role.changed": {
      const role = d.role === "admin" || d.role === "reader" ? d.role : null
      const key = role ? `activity.text.role.changed.${role}` : "activity.text.role.changed"
      text = t(auto ? `${key}.auto` : key, { name, target })
      break
    }
    case "user.created":
      text = t(auto ? (d.why === "signin" ? "activity.text.user.created.signin" : "activity.text.user.created.auto") : "activity.text.user.created", { name, target })
      break
    case "user.deactivated":
      text = t(auto ? "activity.text.user.deactivated.auto" : "activity.text.user.deactivated", { name, target })
      break
    default:
      // an action this version has no text for: its name in the Protokoll's words, and who
      text = t(`activity.text.${item.action}`, { name, target, defaultValue: "" }) || `${name}: ${t(`audit.action.${item.action}`, { defaultValue: item.action })}`
  }
  const names = item.action === SIGNIN && item.others && item.names?.length ? item.names.join(", ") + (item.names.length <= item.others || item.others_more ? " …" : "") : undefined
  return { text, icon: ICON[item.action] ?? "other", to: linkOf(item), urgent: stillWaits(item), title: names }
}
