import { useQuery, type QueryClient } from "@tanstack/react-query"
import { api } from "@/lib/api"
import type { FollowedVersion } from "@/lib/vendor-api"

/*
 * "Versionen prüfen" (backend app/catalog_care.py): an entered version not confirmed for longer than the interval is
 * "bitte prüfen". Entering or changing it confirms it, "Bestätigen" confirms it unchanged – nothing is evaluated anew.
 */

/** The intervals an admin can choose (days; 0: off) – the same as the server's REVIEW_CHOICES. */
export const REVIEW_CHOICES = [30, 60, 90, 180, 365, 0] as const

export interface ReviewVersion {
  id: string
  version: string
  label: string
  confirmed_at: string | null
  confirmed_by: string | null
  age_days: number
  due: boolean
}

export interface ReviewItem {
  product: { key: string; label: string; vendor: string }
  teams: { id: string; name: string }[]
  versions: ReviewVersion[]
  can_confirm: boolean
}

/** GET /api/vendor/review – the versions to confirm the viewer is responsible for (`all`: every one, admins). */
export interface ReviewList {
  days: number
  enabled: boolean
  count: number
  items: ReviewItem[]
}

export const REVIEW_KEY = ["vendor", "review"] as const

export const useReview = (scope: "mine" | "all" = "mine", enabled = true) =>
  useQuery({ queryKey: [...REVIEW_KEY, scope], queryFn: () => api.get<ReviewList>(`/api/vendor/review?scope=${scope}`), enabled, staleTime: 60_000 })

/** After a confirmation: the review list and the vendor views (the badges) are read again. */
export async function refreshReview(qc: QueryClient): Promise<void> {
  await qc.invalidateQueries({ queryKey: ["vendor"] })
}

export const confirmVersion = (id: string) => api.post<ReviewVersion>(`/api/vendor/versions/${encodeURIComponent(id)}/confirm`)

export const confirmAll = (target: { product: string } | { team_id: string }, dueOnly = true) =>
  api.post<{ confirmed: number }>("/api/vendor/review/confirm", { ...target, due_only: dueOnly })

/** The versions of a product that need confirming. */
export function dueVersions(versions: Pick<FollowedVersion, "review">[]): number {
  return versions.filter((v) => v.review?.due).length
}

/** Per team (and "no team") the products to review – the order of the list: teams by name, "no team" last. */
export function groupByTeam(items: ReviewItem[]): { team: { id: string; name: string } | null; items: ReviewItem[]; versions: number }[] {
  const groups = new Map<string, { team: { id: string; name: string } | null; items: ReviewItem[]; versions: number }>()
  for (const i of items) {
    const ts = i.teams.length ? i.teams : [null]
    for (const team of ts) {
      const k = team?.id ?? ""
      const g = groups.get(k) ?? { team, items: [], versions: 0 }
      g.items.push(i)
      g.versions += i.versions.length
      groups.set(k, g)
    }
  }
  return [...groups.values()].sort((a, b) => (a.team ? (b.team ? a.team.name.localeCompare(b.team.name) : -1) : b.team ? 1 : 0))
}
