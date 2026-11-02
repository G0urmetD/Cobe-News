import { useQuery } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { api } from "@/lib/api"

/** Advisory changes – backend app/advisory_changes.py: a stored advisory came again with other content (a revision). */

export type ChangeField = "fixed" | "affected" | "products" | "cves" | "severity" | "cvss" | "kev" | "withdrawn"

export type ChangeEntry =
  | { f: "fixed" | "affected" | "products" | "cves"; add: string[]; del: string[]; more?: number }
  | { f: "severity"; from: string; to: string; cvss_from: number | null; cvss_to: number | null }
  | { f: "cvss"; from: number | null; to: number }
  | { f: "kev"; cve: string; added: string; ransomware: boolean }
  | { f: "withdrawn" }

/** What the change means for one version entered (status before → after, the fixed version before → after) */
export interface ChangeImpact {
  product: string
  label: string
  version: string | null
  vlabel: string
  from: string | null
  to: string | null
  fixed_from: string | null
  fixed_to: string | null
}

export interface AdvisoryChange {
  advisory: string
  source: string
  ident: string
  title: string
  url: string
  revision: number
  /** the vendor's own version of the document, if it names one */
  doc_rev: string | null
  at: string
  diff: ChangeEntry[]
  impact: ChangeImpact[]
  severity?: string
}

/** One line of a revision: an i18n key with its values (`refs`: values that are i18n keys themselves – a status, a
 * severity); `tone` says how it is shown (worse first and red). */
export interface ChangeLine {
  key: string
  values: Record<string, string | number>
  refs?: Record<string, string>
  tone: "worse" | "better" | "important" | "normal"
}

const SHOWN = 3
const RANK: Record<string, number> = { affected: 3, possible: 2, service: 1, unversioned: 1 }

/** Whether a version is concerned now that was not, or "possibly" became "affected" (the backend's advisory_changes.worse). */
export function isWorse(i: ChangeImpact): boolean {
  return (RANK[i.to ?? ""] ?? 0) > (RANK[i.from ?? ""] ?? 0)
}

const statusKey = (s: string | null) => `vendor.status.${s && s !== "stale" ? s : "not_affected"}`

function list(xs: string[], more = 0): { items: string; more: string } {
  const left = xs.length - SHOWN + more
  return { items: xs.slice(0, SHOWN).join(", "), more: left > 0 ? ` (+${left})` : "" }
}

/** A revision in lines – the impact on the versions entered first, then what the advisory changed. */
export function changeLines(c: Pick<AdvisoryChange, "diff" | "impact">): ChangeLine[] {
  const out: ChangeLine[] = []
  for (const i of c.impact) {
    const where = [i.label || i.product, i.version].filter(Boolean).join(" ")
    const was = i.from === "not_affected" ? null : i.from
    const now = i.to === "not_affected" ? null : i.to
    if (was !== now) {
      out.push({
        key: i.fixed_to && now ? "changes.impact.nowFix" : "changes.impact.now",
        values: { where, fixed: i.fixed_to ?? "" },
        refs: { to: statusKey(i.to), from: statusKey(i.from) },
        tone: isWorse(i) ? "worse" : "better",
      })
    } else if (i.fixed_to) {
      out.push({ key: "changes.impact.fix", values: { where, fixed: i.fixed_to }, tone: "important" })
    }
  }
  for (const d of c.diff) {
    if (d.f === "fixed" || d.f === "affected" || d.f === "products" || d.f === "cves") {
      const important = d.f === "fixed"
      if (d.add.length) {
        const l = list(d.add, d.del.length ? 0 : (d.more ?? 0))
        out.push({ key: `changes.${d.f}.add`, values: l, tone: important ? "important" : "normal" })
      }
      if (d.del.length) out.push({ key: `changes.${d.f}.del`, values: list(d.del), tone: "normal" })
    } else if (d.f === "severity") {
      const fresh = d.from === "info" && d.cvss_from === null
      const cvss = d.cvss_from !== null && d.cvss_to !== null && d.cvss_from !== d.cvss_to ? `${d.cvss_from.toFixed(1)} → ${d.cvss_to.toFixed(1)}` : ""
      out.push({
        key: fresh ? "changes.severity.new" : cvss ? "changes.severity.withCvss" : "changes.severity.changed",
        values: { cvss },
        refs: { from: `news.sev.${d.from}`, to: `news.sev.${d.to}` },
        tone: "important",
      })
    } else if (d.f === "cvss") {
      out.push(
        d.from === null
          ? { key: "changes.cvss.new", values: { to: d.to.toFixed(1) }, tone: "normal" }
          : { key: "changes.cvss.changed", values: { from: d.from.toFixed(1), to: d.to.toFixed(1) }, tone: "normal" },
      )
    } else if (d.f === "kev") {
      out.push({ key: d.ransomware ? "changes.kev.ransomware" : "changes.kev.added", values: { cve: d.cve, date: d.added }, tone: "important" })
    } else if (d.f === "withdrawn") {
      out.push({ key: "changes.withdrawn", values: {}, tone: "important" })
    }
  }
  return out
}

/** Whether a revision changed the verdict of a version entered for the worse – shown first and in red. */
export function hasWorse(c: Pick<AdvisoryChange, "impact">): boolean {
  return c.impact.some(isWorse)
}

export const useProductChanges = (key: string, enabled = true) =>
  useQuery({
    queryKey: ["vendor", "product", key, "changes"],
    queryFn: () => api.get<{ changes: AdvisoryChange[] }>(`/api/vendor/products/${encodeURIComponent(key)}/changes`),
    enabled,
    staleTime: 30_000,
  })

/** A line's text: its values, the ones that are i18n keys themselves (status, severity) translated first. */
export function useLineText(): (l: ChangeLine) => string {
  const { t } = useTranslation()
  return (l) => t(l.key, { ...l.values, ...Object.fromEntries(Object.entries(l.refs ?? {}).map(([k, v]) => [k, t(v)])) })
}
