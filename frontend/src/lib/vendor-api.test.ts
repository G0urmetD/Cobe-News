import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import vendorDe from "@/i18n/vendor.de"
import vendorEn from "@/i18n/vendor.en"
import { fmtDay } from "@/lib/format"
import { SUPPORT_SOON_DAYS, fold, invalidText, looksLikeBuild, matchScore, supportState, versionProblem, worse, type VendorProduct } from "@/lib/vendor-api"
// the server's threshold for the cards and the notifications – the same number as the drawer's
import vendorPy from "../../../backend/app/vendor.py?raw"
import vendorMatchPy from "../../../backend/app/vendor_match.py?raw"
import vendorSourcesPy from "../../../backend/app/vendor_sources.py?raw"
import newsPy from "../../../backend/app/news.py?raw"
import virtualizationYaml from "../../../backend/app/catalog/products/virtualization.yaml?raw"

const prod = (label: string, extra: Partial<VendorProduct> = {}): VendorProduct => ({
  key: label.toLowerCase(),
  label,
  vendor: "",
  category: "other",
  scheme: "generic",
  example: "",
  cloud: false,
  cpes: [],
  advisory: null,
  eol: false,
  aliases: [],
  hint: null,
  version_cmd: null,
  version_where: null,
  custom: false,
  ...extra,
})

describe("catalogue search", () => {
  const panos = prod("PAN-OS (Firewalls)", { vendor: "Palo Alto Networks", cpes: ["o:paloaltonetworks:pan-os"], aliases: ["Palo Alto Firewall"] })
  const fortios = prod("FortiOS (FortiGate)", { vendor: "Fortinet", aliases: ["FortiGate"] })
  it("finds by label, vendor, alias and CPE, case and punctuation ignored", () => {
    expect(matchScore(panos, "pan os")).toBeGreaterThan(0)
    expect(matchScore(panos, "palo alto")).toBeGreaterThan(0)
    expect(matchScore(panos, "paloaltonetworks")).toBeGreaterThan(0)
    expect(matchScore(fortios, "fortigate")).toBeGreaterThan(0)
  })
  it("needs every word and forgives one typo in long words", () => {
    expect(matchScore(panos, "palo cisco")).toBe(0)
    expect(matchScore(fortios, "fortigte")).toBeGreaterThan(0)
    expect(matchScore(prod("PHP"), "phx")).toBe(0)
  })
  it("ranks a label hit above a vendor hit", () => {
    expect(matchScore(prod("Fortinet Thing"), "fortinet")).toBeGreaterThan(matchScore(prod("Thing", { vendor: "Fortinet" }), "fortinet"))
  })
  it("folds accents", () => expect(fold("Lücke-Ä")).toBe("lucke a"))
  // the catalogue's entries (backend/app/catalog/products/virtualization.yaml): "vSphere" is vCenter's alias
  const vmware = { vendor: "Broadcom (VMware)" }
  const vcenter = prod("VMware vCenter Server", { ...vmware, key: "vcenter", aliases: ["vSphere", "vSphere Client", "VCSA", "vCenter Server Appliance"] })
  const esxi = prod("VMware ESXi", { ...vmware, key: "esxi", aliases: ["vSphere", "vSphere Hypervisor", "vSphere ESXi"] })
  const replication = prod("VMware vSphere Replication", { ...vmware, key: "vsphere-replication", cpes: ["a:vmware:vsphere_replication"] })
  const rank = (q: string) =>
    [vcenter, esxi, replication]
      .map((p) => ({ p, s: matchScore(p, q) }))
      .filter((x) => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .map((x) => x.p.key)
  it("ranks a whole alias above a label that only contains the words", () => {
    expect(rank("vsphere")).toEqual(["vcenter", "esxi", "vsphere-replication"]) // vSphere = vCenter + ESXi
    expect(rank("VMware vSphere")[0]).toBe("vcenter")
    expect(rank("Broadcom vSphere")[0]).toBe("vcenter")
    expect(rank("vSphere Hypervisor")[0]).toBe("esxi")
    expect(rank("vSphere Replication")[0]).toBe("vsphere-replication")
    expect(rank("VCSA")).toEqual(["vcenter"])
    // a product's exact name stays above another's alias; a part of an alias is no whole match
    expect(matchScore(prod("vSphere"), "vsphere")).toBeGreaterThan(matchScore(vcenter, "vsphere"))
    expect(matchScore(vcenter, "vsphere client")).toBeGreaterThan(matchScore(vcenter, "vsphere"))
    expect(matchScore(prod("Veeam Agent", { vendor: "Veeam", aliases: ["Veeam Agent for Windows"] }), "agent")).toBe(6)
  })
  it("has the aliases in the catalogue data", () => {
    const entry = (key: string) => virtualizationYaml.split(/^- key: /m).find((e) => e.startsWith(`${key}\n`)) ?? ""
    expect(entry("vcenter")).toContain("aliases: [vSphere, vSphere Client, VCSA, vCenter Server Appliance]")
    expect(entry("esxi")).toContain("aliases: [vSphere, vSphere Hypervisor, vSphere ESXi]")
  })
})

describe("version hints while typing", () => {
  it("knows the PAN-OS hotfix format", () => {
    expect(versionProblem("panos", "11.2.4-h23")).toBeNull()
    expect(versionProblem("panos", "11.2")).toBe("format")
  })
  it("refuses KB numbers for Windows and versions for cloud services", () => {
    expect(versionProblem("windows", "KB5044281")).toBe("kb")
    expect(versionProblem("windows", "10.0.20348.2762")).toBeNull()
    expect(versionProblem("cloud", "1.0")).toBe("cloud")
  })
  it("takes other schemes", () => {
    expect(versionProblem("vmware", "8.0 U3c")).toBeNull()
    expect(versionProblem("ivanti", "22.7R2.3")).toBeNull()
    expect(versionProblem("generic", "9.8p1")).toBeNull()
    // Veeam: the build (or a short version), never a patch number – the same as the server's scheme
    expect(versionProblem("veeam", "12.3.2.4934")).toBeNull()
    expect(versionProblem("veeam", "12.3.1")).toBeNull()
    expect(versionProblem("veeam", "13.1.2 (build 13.1.2.57)")).toBeNull()
    expect(versionProblem("veeam", "11.0.1.1261 P20240304")).toBeNull()
    expect(versionProblem("veeam", "12.3.2 P4")).toBe("format")
    expect(versionProblem("veeam", "13")).toBe("format")
    expect(versionProblem("generic", "")).toBe("empty")
  })
  it("takes the GA line's patches and vSphere 9 like the server, not vCenter's four-part version", () => {
    for (const ok of ["8.0c", "7.0.0d", "7.0b", "8.0 U3d", "8.0 Update 3d", "9.0.2.0100", "9.1.1.0"]) expect(versionProblem("vmware", ok)).toBeNull()
    for (const bad of ["8.0a U1", "8.0.3a", "8.0.3.00400", "24322831"]) expect(versionProblem("vmware", bad)).toBe("format")
  })
  it("knows what the server looks up for vCenter and ESXi", () => {
    for (const b of [
      "8.0.3.00400",
      "8.0.3.400",
      "24322831",
      "build-24322831",
      "8.0.3-24022510",
      "8.0.3, 24022510",
      "VMware ESXi 8.0.3 build-24022510",
      "Version 8.0.3.00400 Build 24322831",
      "8.0 Update 3 (build 24022515)",
    ])
      expect(looksLikeBuild(b), b).toBe(true)
    for (const v of ["8.0 U3d", "8.0", "8.0c", "9.0.2.0100", "12345", "8.0.3.00400.1", ""]) expect(looksLikeBuild(v), v).toBe(false)
  })
})

describe("states", () => {
  it("takes the worse one", () => {
    expect(worse("possible", "affected")).toBe("affected")
    expect(worse("none", "not_affected")).toBe("not_affected")
    expect(worse("unversioned", "possible")).toBe("possible")
  })
})

describe("strings", () => {
  it("has every Vendor News key in German and English", () => {
    expect(Object.keys(vendorEn).sort()).toEqual(Object.keys(vendorDe).sort())
  })
  // the drawer shows vendor.reason.<reason> of every verdict, the CPE search vendor.err.<category> – a new one on the
  // server without a text showed the bare key ("all_listed", "short_version", "too_large")
  it("has a text for every reason and fetch error the server can send", () => {
    const reasons = new Set([...(vendorPy + vendorMatchPy).matchAll(/Verdict\("[a-z_]+", "([a-z_]+)"/g)].map((m) => m[1]))
    const errors = new Set([...(newsPy + vendorPy + vendorSourcesPy).matchAll(/NewsError\("([a-z_]+)"/g)].map((m) => m[1]))
    expect(reasons.size).toBeGreaterThan(20)
    expect(errors).toContain("blocked")
    expect([...reasons].filter((r) => !vendorDe[`vendor.reason.${r}`])).toEqual([])
    expect([...errors].filter((e) => !vendorDe[`vendor.err.${e}`])).toEqual([])
    // the settings show the same categories of a source's last fetch
    expect([...errors].filter((e) => !de[`settings.news.err.${e}`])).toEqual([])
  })
})

describe("support of a release line", () => {
  const today = new Date(2026, 9, 29)
  it("past, soon (under half a year), ok, unknown", () => {
    expect(supportState("2026-10-29", false, today)).toBe("past")
    expect(supportState("2025-05-02", true, today)).toBe("past")
    expect(supportState("2027-03-01", false, today)).toBe("soon")
    expect(supportState("2027-05-02", false, today)).toBe("ok")
    expect(supportState(null, true, today)).toBe("past")
    expect(supportState(null, false, today)).toBe("ok") // no end announced
    expect(supportState(undefined, undefined, today)).toBe("unknown")
  })
  it("ends soon below the same half year as on the server (cards, notifications)", () => {
    expect(SUPPORT_SOON_DAYS).toBe(183)
    expect(/^EOL_SOON_DAYS = (\d+)$/m.exec(vendorPy)?.[1]).toBe(String(SUPPORT_SOON_DAYS))
    // 2027-05-02: 183 days left on 31 Oct 2026 – not yet; 182 on 1 Nov – soon (the server: release_info, same days)
    expect(supportState("2027-05-02", false, new Date(2026, 9, 31))).toBe("ok")
    expect(supportState("2027-05-02", false, new Date(2026, 10, 1))).toBe("soon")
  })
  it("days in the reader's format, never shifted by the time zone", () => {
    expect(fmtDay("2027-05-02")).toBe("02.05.2027")
    expect(fmtDay("2027-05-02T00:00:00Z")).toBe("02.05.2027")
    expect(fmtDay("nicht bekannt")).toBe("nicht bekannt")
  })
})

describe("refused versions (app/version_input.py)", () => {
  const t = (key: string, o?: Record<string, unknown>) => {
    const text = (vendorDe as Record<string, string>)[key] ?? key
    return text.replace(/\{\{(\w+)\}\}/g, (_, k: string) => String(o?.[k] ?? ""))
  }
  it("has a text for every reason the server gives, in German and English", () => {
    for (const r of ["unknown_name", "other_product", "pattern", "implausible", "unknown_build", "build_mismatch"]) {
      expect((vendorDe as Record<string, string>)[`vendor.invalid.${r}`]).toBeTruthy()
      expect((vendorEn as Record<string, string>)[`vendor.invalid.${r}`]).toBeTruthy()
    }
    expect((vendorDe as Record<string, string>)["vendor.v.effective"]).toContain("{{version}}")
  })
  it("names the product a form belongs to and adds the catalogue's hint in the language", () => {
    expect(invalidText(t, "de", "other_product", { example: "2.8.0", toLabel: "pfSense Plus" })).toContain("pfSense Plus")
    const hint = { de: "ExSetup.exe nehmen.", en: "Use ExSetup.exe." }
    expect(invalidText(t, "de", "unknown_name", { example: "15.2.1748.24", hint })).toMatch(/15\.2\.1748\.24.*ExSetup\.exe nehmen\./)
    expect(invalidText(t, "en", "unknown_name", { example: "x", hint })).toContain("Use ExSetup.exe.")
    expect(invalidText(t, "de", "implausible", { example: "1.27.2", lines: ["1.31", "1.30"] })).toContain("1.31, 1.30")
    // vCenter's reasons have their own text – the server's hint is not repeated
    expect(invalidText(t, "de", "unknown_build", { example: "8.0 U3d", hint })).not.toContain("ExSetup")
  })
  it("takes a pasted line up to 200 characters (SELECT @@VERSION) – the server takes the version out of it", () => {
    expect(versionProblem("generic", "Microsoft SQL Server 2022 (RTM-CU20) (KB5059390) - 16.0.4205.1 (X64) Jul 1 2025")).toBeNull()
    expect(versionProblem("generic", "1".repeat(201))).toBe("too_long")
  })
})
