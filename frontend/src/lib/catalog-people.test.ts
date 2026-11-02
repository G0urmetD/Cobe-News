import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import careDe from "@/i18n/care.de"
import careEn from "@/i18n/care.en"
import { safeHttpUrl, similarProducts, suggestProblems, yamlSnippet, type SuggestionIn } from "@/lib/suggestions"
import { matchesFilter, type OverviewItem, type VendorProduct } from "@/lib/vendor-api"
import { REVIEW_CHOICES, dueVersions, groupByTeam, type ReviewItem } from "@/lib/version-review"

const prod = (label: string, extra: Partial<VendorProduct> = {}): VendorProduct => ({
  key: label.toLowerCase().replace(/\W+/g, "-"),
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

const good: SuggestionIn = { vendor: "Example Corp", product: "Edge Gateway", url: "https://www.example.com/security", cpe: "a:example:edge_gateway", reason: "Läuft bei uns." }

describe("suggestion form", () => {
  it("takes a good one and names what is wrong", () => {
    expect(suggestProblems(good)).toEqual([])
    expect(suggestProblems({ ...good, url: "", cpe: "" })).toEqual([])
    expect(suggestProblems({ ...good, vendor: "x", reason: " " })).toEqual(["vendor", "reason"])
    expect(suggestProblems({ ...good, url: "javascript:alert(1)" })).toEqual(["url"])
    expect(suggestProblems({ ...good, cpe: "edge gateway" })).toEqual(["cpe"])
    expect(suggestProblems({ ...good, product: "p".repeat(121) })).toEqual(["product"])
  })

  it("links only http(s) addresses without credentials", () => {
    expect(safeHttpUrl("https://www.example.com/a?b=1")).toBe("https://www.example.com/a?b=1")
    for (const bad of ["javascript:alert(1)", "data:text/html,<b>x</b>", "https://user:pw@example.com/", "ftp://example.com/", "not a url", "", null])
      expect(safeHttpUrl(bad)).toBeNull()
  })

  it("offers similar catalogue products before a duplicate is sent", () => {
    const ps = [prod("PAN-OS (Firewalls)", { vendor: "Palo Alto Networks" }), prod("FortiOS (FortiGate)", { vendor: "Fortinet", aliases: ["FortiGate"] }), prod("nginx")]
    expect(similarProducts(ps, "Fortinet", "Fortigate").map((p) => p.label)).toEqual(["FortiOS (FortiGate)"])
    expect(similarProducts(ps, "", "pan os").map((p) => p.label)).toEqual(["PAN-OS (Firewalls)"])
    expect(similarProducts(ps, "Example", "x")).toEqual([])
    expect(similarProducts(ps, "Example", "Edge Gateway")).toEqual([])
  })

  it("„Meinst du …?“ offers vCenter for vSphere, above vSphere Replication", () => {
    const vmware = { vendor: "Broadcom (VMware)" }
    const ps = [
      prod("VMware vSphere Replication", { ...vmware, cpes: ["a:vmware:vsphere_replication"] }),
      prod("VMware ESXi", { ...vmware, aliases: ["vSphere Hypervisor", "vSphere ESXi"] }),
      prod("VMware vCenter Server", { ...vmware, aliases: ["vSphere", "vSphere Client", "VCSA", "vCenter Server Appliance"] }),
    ]
    for (const [vendor, product] of [
      ["VMware", "vSphere"],
      ["Broadcom", "vSphere"],
      ["", "VMware vSphere"],
      ["VMware", "VMware vSphere"],
    ])
      expect(similarProducts(ps, vendor, product)[0]?.label, `${vendor} ${product}`).toBe("VMware vCenter Server")
    expect(similarProducts(ps, "VMware", "vSphere").map((p) => p.label)).toContain("VMware vSphere Replication")
  })

  it("gives the bundled catalogue a starting entry", () => {
    expect(yamlSnippet({ vendor: "Example Corp", product: "Edge Gateway", cpe_short: "a:example:edge_gateway" })).toBe(
      "- key: example-corp-edge-gateway\n  label: Edge Gateway\n  vendor: Example Corp\n  cpes: [a:example:edge_gateway]",
    )
    expect(yamlSnippet({ vendor: "Ä: B", product: "#x", cpe_short: null })).toContain('label: "#x"')
  })
})

describe("version review", () => {
  it("counts the due versions and filters the overview by them", () => {
    const v = (due: boolean) => ({ review: { confirmed_at: null, confirmed_by: null, age_days: due ? 120 : 1, due } })
    expect(dueVersions([v(true), v(false), {}])).toBe(1)
    const item = { versions: [v(false), v(true)] } as unknown as OverviewItem
    expect(matchesFilter(item, "review")).toBe(true)
    expect(matchesFilter({ versions: [v(false)] } as unknown as OverviewItem, "review")).toBe(false)
    expect(REVIEW_CHOICES).toContain(90)
    expect(REVIEW_CHOICES).toContain(0)
  })

  it("groups by team, products of no team last, a product of two teams in both", () => {
    const it_ = (key: string, teams: string[], n = 1): ReviewItem => ({
      product: { key, label: key, vendor: "" },
      teams: teams.map((x) => ({ id: x, name: x })),
      versions: Array.from({ length: n }, (_, i) => ({ id: `${key}${i}`, version: "1", label: "", confirmed_at: null, confirmed_by: null, age_days: 100, due: true })),
      can_confirm: true,
    })
    const g = groupByTeam([it_("a", []), it_("b", ["Server", "Netzwerk"], 2), it_("c", ["Netzwerk"])])
    expect(g.map((x) => [x.team?.name ?? null, x.items.map((i) => i.product.key), x.versions])).toEqual([
      ["Netzwerk", ["b", "c"], 3],
      ["Server", ["b"], 2],
      [null, ["a"], 1],
    ])
  })
})

describe("catalog care strings", () => {
  it("are in German and English alike and merged into both bundles", () => {
    expect(Object.keys(careDe).sort()).toEqual(Object.keys(careEn).sort())
    for (const k of Object.keys(careDe)) {
      expect(de[k], k).toBe(careDe[k])
      expect(en[k], k).toBe(careEn[k])
    }
  })
})
