import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"

/** The update notice for admins (server: app/update_check.py) – GitHub's latest release against this version. */
export interface UpdateStatus {
  /** the check is switched on (settings "updates") */
  enabled: boolean
  current: string
  /** the newest final release GitHub names (null: not checked yet, none, or switched off) */
  latest: string | null
  /** latest is newer than current */
  available: boolean
  /** this admin closed the notice for `latest` */
  dismissed: boolean
  /** the release on GitHub (made by the server from the tag) */
  url: string | null
  published_at: string | null
  checked_at: string | null
  error: string | null
  rev: number
}

export const UPDATE_KEY = ["admin", "update"] as const

/** Admins only – readers get 403, so nothing is asked for them. */
export const useUpdateStatus = (isAdmin: boolean) =>
  useQuery({ queryKey: UPDATE_KEY, queryFn: () => api.get<UpdateStatus>("/api/admin/update"), enabled: isAdmin, staleTime: 60 * 60_000, refetchOnWindowFocus: false, retry: false })

export const dismissUpdate = (version: string) => api.post<UpdateStatus>("/api/admin/update/dismiss", { version })
export const saveUpdateCheck = (check: boolean, rev: number) => api.put<UpdateStatus>("/api/admin/update/settings", { check, rev })

/** The release link, only when it is an https address – otherwise none (shell notice and About page alike). */
export function releaseLink(s: Pick<UpdateStatus, "url"> | undefined): string | null {
  return s && typeof s.url === "string" && s.url.startsWith("https://") ? s.url : null
}

/** Whether the shell shows the notice: a newer release, not closed, with its link (an https address). */
export function showUpdateNotice(s: UpdateStatus | undefined): s is UpdateStatus & { latest: string; url: string } {
  return !!s && s.enabled && s.available && !s.dismissed && !!s.latest && releaseLink(s) !== null
}
