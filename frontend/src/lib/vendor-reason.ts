/** The text of a verdict's reason in the drawer (vendor.reason.<key>) – with the source it came from (detail.by). */
import { fmtDay } from "@/lib/format"
import type { VersionVerdict } from "@/lib/vendor-api"

/** Reasons whose text names a source ("vom Hersteller", "laut Hinweis"): another source than the vendor has its own
 *  wording (`<reason>_by`: "laut NVD …"); the others get "Quelle: …" appended. */
export const SOURCE_WORDED = new Set(["in_list", "line_none", "default_affected", "all_listed"])
/** Reasons that name their sources themselves */
const SOURCE_NAMED = new Set(["all_listed_disputed", "vendor_unaffected", "older_untested", "cloud"])

/** The source of a verdict as the drawer names it: "Hersteller", "NVD" … – a CNA that is not the vendor with its name
 *  ("GitHub (nicht der Hersteller)"; one known only by its UUID as "CNA"). */
export function sourceName(t: (k: string, o?: Record<string, unknown>) => string, detail: Pick<VersionVerdict["detail"], "by" | "cna">): string {
  const by = detail.by
  if (!by) return ""
  if (by === "cna") return t("vendor.by.cna", { name: detail.cna || t("vendor.by.cna_unnamed") })
  return t(`vendor.by.${by}`, { defaultValue: by })
}

export function reasonText(t: (k: string, o?: Record<string, unknown>) => string, r: Pick<VersionVerdict, "reason" | "detail">): string {
  const by = r.detail.by
  const src = sourceName(t, r.detail)
  const worded = SOURCE_WORDED.has(r.reason)
  const key = by && by !== "vendor" && worded ? `vendor.reason.${r.reason}_by` : `vendor.reason.${r.reason}`
  const base = t(key, { defaultValue: r.reason, line: r.detail.line ?? "", released: r.detail.released ? fmtDay(r.detail.released) : "", src })
  const extra = [
    r.detail.platform && t("vendor.reason.platform", { value: r.detail.platform }),
    r.detail.after && t("vendor.reason.after", { value: r.detail.after }),
    by && !worded && !SOURCE_NAMED.has(r.reason) && t("vendor.reason.source", { src }),
  ].filter(Boolean)
  return [base, ...extra].join(" · ")
}
