import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { type AdvisoryChange, changeLines, hasWorse, isWorse } from "@/lib/advisory-changes"
import { TERMS } from "@/components/cobe/glossary"

const base: AdvisoryChange = {
  advisory: "paloalto:CVE-2026-1001",
  source: "paloalto",
  ident: "CVE-2026-1001",
  title: "PAN-OS: Example",
  url: "https://security.paloaltonetworks.com/CVE-2026-1001",
  revision: 3,
  doc_rev: null,
  at: "2026-10-30T08:00:00Z",
  diff: [],
  impact: [],
}

describe("advisory changes", () => {
  it("puts the impact on a version entered first, worse in red", () => {
    const c: AdvisoryChange = {
      ...base,
      diff: [
        { f: "fixed", add: ["PAN-OS 11.2: 11.2.4-h30"], del: ["PAN-OS 11.2: 11.2.4-h10"] },
        { f: "severity", from: "high", to: "critical", cvss_from: 7.5, cvss_to: 9.3 },
      ],
      impact: [{ product: "panos", label: "PAN-OS", version: "11.2.4-h23", vlabel: "", from: "not_affected", to: "affected", fixed_from: null, fixed_to: "11.2.4-h30" }],
    }
    const lines = changeLines(c)
    expect(lines[0]).toEqual({
      key: "changes.impact.nowFix",
      values: { where: "PAN-OS 11.2.4-h23", fixed: "11.2.4-h30" },
      refs: { to: "vendor.status.affected", from: "vendor.status.not_affected" },
      tone: "worse",
    })
    expect(lines.map((l) => l.key)).toEqual(["changes.impact.nowFix", "changes.fixed.add", "changes.fixed.del", "changes.severity.withCvss"])
    expect(lines[3].values.cvss).toBe("7.5 → 9.3")
    expect(lines[3].refs).toEqual({ from: "news.sev.high", to: "news.sev.critical" })
    expect(hasWorse(c)).toBe(true)
  })

  it("says better and fixed-only changes apart", () => {
    const better = { product: "panos", label: "PAN-OS", version: "10.2.1", vlabel: "", from: "affected", to: "not_affected", fixed_from: "10.2.5", fixed_to: null }
    const fix = { product: "panos", label: "PAN-OS", version: "10.2.1", vlabel: "", from: "affected", to: "affected", fixed_from: null, fixed_to: "10.2.5" }
    expect(isWorse(better)).toBe(false)
    expect(changeLines({ diff: [], impact: [better] })[0]).toMatchObject({ key: "changes.impact.now", tone: "better" })
    expect(changeLines({ diff: [], impact: [fix] })[0]).toMatchObject({ key: "changes.impact.fix", values: { fixed: "10.2.5" }, tone: "important" })
    expect(isWorse({ ...fix, from: "possible" })).toBe(true)
  })

  it("shortens long lists and names KEV, withdrawn and new ratings", () => {
    const lines = changeLines({
      diff: [
        { f: "affected", add: ["a", "b", "c", "d", "e"], del: [], more: 7 },
        { f: "severity", from: "info", to: "critical", cvss_from: null, cvss_to: 9.8 },
        { f: "cvss", from: null, to: 5.3 },
        { f: "kev", cve: "CVE-2026-1001", added: "2026-10-29", ransomware: true },
        { f: "withdrawn" },
      ],
      impact: [],
    })
    expect(lines[0].values).toEqual({ items: "a, b, c", more: " (+9)" })
    expect(lines.slice(1).map((l) => l.key)).toEqual(["changes.severity.new", "changes.cvss.new", "changes.kev.ransomware", "changes.withdrawn"])
  })

  it("has every text in German and English", () => {
    const keys = (m: Record<string, string>) => Object.keys(m).filter((k) => k.startsWith("changes.") || k.includes("vendor_change") || k === "notify.vendorChangeOnly")
    expect(keys(de).sort()).toEqual(keys(en).sort())
    const wanted = new Set<string>()
    const sample: AdvisoryChange = {
      ...base,
      diff: [
        ...(["fixed", "affected", "products", "cves"] as const).map((f) => ({ f, add: ["x"], del: ["y"] })),
        { f: "severity", from: "high", to: "critical", cvss_from: null, cvss_to: null },
        { f: "severity", from: "high", to: "critical", cvss_from: 7, cvss_to: 9 },
        { f: "severity", from: "info", to: "critical", cvss_from: null, cvss_to: null },
        { f: "cvss", from: 5, to: 6 },
        { f: "cvss", from: null, to: 6 },
        { f: "kev", cve: "CVE-1", added: "", ransomware: false },
        { f: "kev", cve: "CVE-1", added: "", ransomware: true },
        { f: "withdrawn" },
      ],
      impact: [
        { product: "p", label: "P", version: "1", vlabel: "", from: null, to: "affected", fixed_from: null, fixed_to: null },
        { product: "p", label: "P", version: "1", vlabel: "", from: null, to: "affected", fixed_from: null, fixed_to: "2" },
        { product: "p", label: "P", version: "1", vlabel: "", from: "affected", to: "affected", fixed_from: null, fixed_to: "2" },
      ],
    }
    for (const l of changeLines(sample)) {
      wanted.add(l.key)
      for (const r of Object.values(l.refs ?? {})) wanted.add(r)
    }
    for (const k of wanted) {
      expect(de[k as keyof typeof de], k).toBeTruthy()
      expect(en[k as keyof typeof en], k).toBeTruthy()
    }
    expect(TERMS).toContain("revision")
    expect(de["glossary.revisionText"] && en["glossary.revisionText"]).toBeTruthy()
  })
})
