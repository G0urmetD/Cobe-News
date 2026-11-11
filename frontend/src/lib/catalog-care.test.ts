import { describe, expect, it } from "vitest"
import i18n from "i18next"
import { careItems, careReason, type CatalogCare } from "@/lib/catalog-care"
import de from "@/i18n/vendor.de"
import en from "@/i18n/vendor.en"

const t = (lng: "de" | "en") => {
  const inst = i18n.createInstance()
  void inst.init({ lng, resources: { [lng]: { translation: lng === "de" ? de : en } }, keySeparator: false, nsSeparator: false, interpolation: { escapeValue: false } })
  return inst.t
}

describe("careReason", () => {
  it("words every reason code in both languages", () => {
    for (const code of [
      "cpe_missing",
      "cpe_deprecated",
      "no_cves",
      "stale_cves",
      "eol_missing",
      "eol_mismatch",
      "adv_stale",
      "nocpe_followed",
      "releases_failed",
      "releases_none",
      "releases_stale",
    ]) {
      expect(de[`vendor.care.reason.${code}`], code).toBeTruthy()
      expect(en[`vendor.care.reason.${code}`], code).toBeTruthy()
    }
    expect(careReason(t("de"), { code: "cpe_missing", level: "error", cpe: "a:veeam:veeam_one" })).toBe("CPE a:veeam:veeam_one existiert nicht in der NVD")
    expect(careReason(t("en"), { code: "eol_missing", level: "error", key: "wildfly" })).toBe("endoflife.date no longer knows the key “wildfly”")
    const stale = careReason(t("de"), { code: "stale_cves", level: "warn", months: 39, cve: "CVE-2023-1", newest: "2023-07-02" })
    expect(stale).toContain("Seit 39 Monaten")
    expect(stale).toContain("CVE-2023-1")
    expect(stale).not.toContain("2023-07-02") // a calendar day is shown formatted, never in ISO form
    expect(careReason(t("en"), { code: "adv_stale", level: "warn", source: "paloalto", months: 30, last: "2024-04-01" })).toContain("Palo Alto Networks")
  })

  it("words the release source reasons with their source and day", () => {
    const stale = careReason(t("de"), { code: "releases_stale", level: "warn", source: "GitHub portainer/portainer", months: 20, last: "2025-03-01" })
    expect(stale).toContain("GitHub portainer/portainer")
    expect(stale).toContain("seit 20 Monaten")
    expect(stale).not.toContain("2025-03-01")
    expect(careReason(t("en"), { code: "releases_failed", level: "warn", source: "passwork.pro", error: "http: HTTP 404" })).toBe(
      "Release source passwork.pro cannot be fetched (http: HTTP 404)",
    )
  })

  it("an unknown code shows the code, not an empty line", () => {
    expect(careReason(t("de"), { code: "something_new", level: "warn" })).toBe("something_new")
  })
})

describe("careItems", () => {
  const item = (product: string, followed: boolean) => ({
    product,
    label: product,
    vendor: "",
    category: "other",
    cpes: [],
    status: "warn" as const,
    followed,
    reasons: [],
    checked_at: null,
    in_catalog: true,
  })
  const data = { items: [item("a", true), item("b", false)] } as unknown as CatalogCare
  it("filters the followed ones", () => {
    expect(careItems(data, true).map((i) => i.product)).toEqual(["a"])
    expect(careItems(data, false).map((i) => i.product)).toEqual(["a", "b"])
    expect(careItems(undefined, true)).toEqual([])
  })
})
