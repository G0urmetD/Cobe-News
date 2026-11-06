import { describe, expect, it } from "vitest"
import vendorDe from "@/i18n/vendor.de"
import vendorEn from "@/i18n/vendor.en"
import { SOURCE_WORDED, reasonText } from "@/lib/vendor-reason"
import vendorMatchPy from "../../../backend/app/vendor_match.py?raw"

// i18next's interpolation, enough for these texts
const tr =
  (dict: Record<string, string>) =>
  (k: string, o: Record<string, unknown> = {}): string =>
    (dict[k] ?? String(o.defaultValue ?? k)).replace(/\{\{(\w+)\}\}/g, (_, n: string) => String(o[n] ?? ""))
const t = tr(vendorDe as Record<string, string>)

describe("the reason of a verdict names its source", () => {
  it('says "Hersteller" only for the vendor\'s own word', () => {
    expect(reasonText(t, { reason: "default_affected", detail: { by: "vendor" } })).toBe("laut Hersteller alle anderen Versionen betroffen")
    expect(reasonText(t, { reason: "default_affected", detail: { by: "adp" } })).toBe("laut CISA (ADP) alle anderen Versionen betroffen")
    expect(reasonText(t, { reason: "in_list", detail: { by: "nvd" } })).toBe("Version laut NVD als betroffen gelistet")
    expect(reasonText(t, { reason: "in_list", detail: { by: "vendor" } })).toBe("Version vom Hersteller als betroffen gelistet")
    expect(reasonText(t, { reason: "all_listed", detail: { by: "bsi" } })).toBe("laut BSI alle Versionen betroffen")
    expect(reasonText(t, { reason: "line_none", detail: { by: "osv" } })).toBe("Linie laut OSV nicht betroffen")
  })

  it("adds the source to the other reasons, and to none that names it already", () => {
    expect(reasonText(t, { reason: "in_range", detail: { by: "nvd", after: "1.2" } })).toBe("im betroffenen Versionsbereich · betroffen bis einschließlich 1.2 · Quelle: NVD")
    expect(reasonText(t, { reason: "fixed", detail: { by: "vendor" } })).toBe("Version enthält den Fix · Quelle: Hersteller")
    expect(reasonText(t, { reason: "all_listed_disputed", detail: { by: "bsi" } })).toContain("laut BSI alle Versionen betroffen")
    expect(reasonText(t, { reason: "all_listed_disputed", detail: { by: "bsi" } })).not.toContain("Quelle")
    expect(reasonText(t, { reason: "vendor_unaffected", detail: { by: "nvd" } })).not.toContain("Quelle")
    // a verdict of before (no origin): as it was
    expect(reasonText(t, { reason: "in_range", detail: {} })).toBe("im betroffenen Versionsbereich")
  })

  it("has every source and every sourced wording in German and English", () => {
    const sources = new Set([...vendorMatchPy.matchAll(/^#\s+(\w+)\s{2,}/gm)].map((m) => m[1]))
    expect([...sources].sort()).toEqual(["adp", "bsi", "csaf", "nvd", "osv", "vendor"])
    for (const s of sources) {
      expect(vendorDe[`vendor.by.${s}` as keyof typeof vendorDe], s).toBeTruthy()
      expect(vendorEn[`vendor.by.${s}` as keyof typeof vendorEn], s).toBeTruthy()
    }
    for (const r of SOURCE_WORDED) {
      expect(vendorDe[`vendor.reason.${r}_by` as keyof typeof vendorDe], r).toContain("{{src}}")
      expect(vendorEn[`vendor.reason.${r}_by` as keyof typeof vendorEn], r).toContain("{{src}}")
    }
  })
})
