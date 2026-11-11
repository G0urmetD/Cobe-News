import { useQuery } from "@tanstack/react-query"
import type { TFunction } from "i18next"
import { api } from "@/lib/api"
import { fmtDay } from "@/lib/format"
import type { CareReason } from "@/lib/vendor-api"

export type CareStatus = "error" | "warn" | "ok" | "unchecked"

/** Katalog-Pflege (GET /api/admin/vendor/catalog-check): the entries that need care and the state of the self-test. */
export interface CatalogCare {
  catalog_version: string
  eol_generated_at: string | null
  counts: Record<CareStatus, number>
  followed_counts: Record<CareStatus, number>
  cpes: { total: number; checked: number }
  items: {
    product: string
    label: string
    vendor: string
    category: string
    cpes: string[]
    status: "error" | "warn"
    followed: boolean
    reasons: CareReason[]
    checked_at: string | null
    in_catalog: boolean
  }[]
  last_run_at: string | null
  last_asked_at: string | null
  last_manual_at: string | null
  /** why the last step asked no further: budget | paused | off | nothing_followed | vendor_busy | null (done) */
  last_stop: string | null
  running: boolean
  budget_per_hour: number
  followed_every_days: number
  all_every_days: number
}

export const useCatalogCare = (enabled = true) =>
  useQuery({ queryKey: ["vendor", "catalog-care"], queryFn: () => api.get<CatalogCare>("/api/admin/vendor/catalog-check"), enabled, staleTime: 30_000 })

export const CARE_COLOR: Record<CareStatus, string> = { error: "--sev-critical", warn: "--warning", ok: "--success", unchecked: "--muted-foreground" }

const SOURCE: Record<string, string> = { paloalto: "Palo Alto Networks", fortinet: "Fortinet", veeam: "Veeam" }

/** One reason in words ("CPE a:veeam:veeam_one existiert nicht in der NVD"). */
export function careReason(t: TFunction, r: CareReason): string {
  const day = (d?: string) => (d ? fmtDay(d) : "")
  return t(`vendor.care.reason.${r.code}`, {
    cpe: r.cpe ?? "",
    by: r.by ?? "",
    key: r.key ?? "",
    theirs: r.theirs ?? "",
    months: r.months ?? 0,
    cve: r.cve ?? "",
    day: day(r.newest ?? r.last),
    source: SOURCE[r.source ?? ""] ?? r.source ?? "",
    error: r.error ?? "",
    defaultValue: r.code,
  })
}

/** Only the items the filter keeps: followed ones, or all. */
export function careItems(data: CatalogCare | undefined, onlyFollowed: boolean): CatalogCare["items"] {
  return (data?.items ?? []).filter((i) => !onlyFollowed || i.followed)
}
