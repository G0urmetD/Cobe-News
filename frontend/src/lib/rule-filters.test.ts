import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { type DryRunItem, dryRunBody, matchParts } from "@/lib/delivery-log"
import {
  OURS,
  applicable,
  catalogVendors,
  fold,
  normalizeWord,
  offSources,
  readSystems,
  ruleSummary,
  splitWords,
  systemName,
  systemOf,
  systemParam,
  systemRef,
  systemValue,
  vendorId,
  vendorOf,
  vendorsOf,
  wordProblem,
} from "@/lib/rule-filters"

// a stand-in for i18next: the key and its options, so the tests see what was asked for
const t = (key: string, opts?: Record<string, unknown>) => (opts ? `${key}${JSON.stringify(opts)}` : key)

const products = [
  { key: "panos", label: "PAN-OS (Firewalls)", vendor: "Palo Alto Networks", custom: false },
  { key: "expedition", label: "Expedition", vendor: "Palo Alto Networks", custom: false },
  { key: "rhel", label: "Red Hat Enterprise Linux", vendor: "Redhat", custom: false },
  { key: "rhv", label: "Red Hat Virtualization", vendor: "Red Hat", custom: false },
  { key: "satellite", label: "Red Hat Satellite", vendor: "Red Hat", custom: false },
  { key: "mine", label: "Own gateway", vendor: "Palo Alto Networks", custom: true },
]

describe("the catalogue by vendor", () => {
  const vendors = catalogVendors(products)
  it("one vendor for its spellings, the most used one shown; custom products left out", () => {
    expect(vendors.map((v) => [v.id, v.name, v.products.map((p) => p.key)])).toEqual([
      ["paloaltonetworks", "Palo Alto Networks", ["expedition", "panos"]],
      ["redhat", "Red Hat", ["rhel", "satellite", "rhv"]],
    ])
    expect(vendorId("Red Hat")).toBe(vendorId("Redhat"))
  })
  it("names systems – a vendor with all of its products, null for one the catalogue no longer knows", () => {
    expect(systemName(t, { product: "panos" }, vendors)).toBe("PAN-OS (Firewalls)")
    expect(systemName(t, { vendor: "Redhat" }, vendors)).toBe('notify.systemsVendorChip{"vendor":"Red Hat"}')
    expect(systemName(t, { product: "gone" }, vendors)).toBeNull()
    expect(systemOf(systemValue({ vendor: "Palo Alto Networks" }))).toEqual({ vendor: "Palo Alto Networks" })
    expect(systemOf(systemValue({ product: "panos" }))).toEqual({ product: "panos" })
    expect(systemOf("x:y")).toBeNull()
  })
})

describe("one vendor under several spellings (the server's vendor_group)", () => {
  const group = { vendor_group: "broadcomvmware", vendor_group_name: "Broadcom (VMware)", custom: false }
  const vendors = catalogVendors([
    { key: "photon", label: "Photon OS", vendor: "VMware", ...group },
    { key: "srm", label: "VMware SRM", vendor: "VMware", ...group },
    { key: "esxi", label: "ESXi", vendor: "Broadcom (VMware)", ...group },
    { key: "httpd", label: "Apache HTTP Server", vendor: "Apache", vendor_group: "apache", vendor_group_name: "Apache", custom: false },
    { key: "tomcat", label: "Apache Tomcat", vendor: "Apache Software Foundation", vendor_group: "apache", vendor_group_name: "Apache", custom: false },
    { key: "own", label: "Own ESXi", vendor: "VMware", custom: true },
  ])
  it("one group with all of its products, the server's name, every spelling as alias and search word", () => {
    expect(vendors.map((v) => [v.id, v.name, v.products.map((p) => p.key)])).toEqual([
      ["apache", "Apache", ["httpd", "tomcat"]],
      ["broadcomvmware", "Broadcom (VMware)", ["esxi", "photon", "srm"]],
    ])
    expect(vendors[1].aliases).toEqual(["broadcomvmware", "vmware"])
    expect(vendors[1].names).toEqual(["Broadcom (VMware)", "VMware"])
    expect(vendors[0].aliases).toEqual(["apache", "apachesoftwarefoundation"])
  })
  it("a stored rule names it by any spelling", () => {
    for (const name of ["VMware", "vmware", "Broadcom (VMware)", "BroadcomVMware"]) {
      expect(vendorOf(vendors, name)?.id).toBe("broadcomvmware")
      expect(systemName(t, { vendor: name }, vendors)).toBe('notify.systemsVendorChip{"vendor":"Broadcom (VMware)"}')
    }
    expect(systemName(t, { vendor: "Apache Software Foundation" }, vendors)).toBe('notify.systemsVendorChip{"vendor":"Apache"}')
    expect(vendorOf(vendors, "Citrix")).toBeUndefined()
    expect(vendorOf(vendors, "–")).toBeUndefined()
  })
})

describe("folding as the server does (casefold, NFKD, no marks)", () => {
  it("ß and its capital are ss, final sigma and long s their letters, accents dropped", () => {
    expect(fold("Straße")).toBe("strasse")
    expect(fold("STRASSE")).toBe(fold("Straße"))
    expect(fold("GROẞ")).toBe("gross")
    expect(fold("ΟΔΟΣ")).toBe(fold("οδος"))
    expect(fold("ὁδός")).toBe("οδοσ")
    expect(fold("Waſſer")).toBe("wasser")
    expect(fold("ᾳ")).toBe("αι")
    expect(fold("Lücke Café ﬁx")).toBe("lucke cafe fix")
    expect(vendorId("Weiß GmbH")).toBe("weissgmbh")
  })
  it("chips refuse the same word under another case", () => {
    expect(wordProblem("STRASSE", ["Straße"])).toBe("notify.wordTwice")
    expect(wordProblem("Straße", ["strasse"])).toBe("notify.wordTwice")
  })
})

describe("only what applies to the kinds", () => {
  const form = {
    name: "r",
    severities: ["critical" as const],
    sources: ["s1"],
    topics: ["poc" as const],
    lang: "de" as const,
    teams: ["t1"],
    systems: [{ product: "panos" }],
    keywords: ["Bleed"],
    exclude: ["Webinar"],
  }
  it("news keeps everything", () => {
    expect(applicable({ ...form, kinds: ["news"] })).toEqual({ ...form, kinds: ["news"] })
  })
  it("Vendor News: no sources, topics or words – severities only for vulnerabilities and revised advisories", () => {
    expect(applicable({ ...form, kinds: ["vendor_vuln"] })).toEqual({ ...form, kinds: ["vendor_vuln"], sources: [], topics: [], keywords: [], exclude: [] })
    expect(applicable({ ...form, kinds: ["vendor_version"] })).toMatchObject({ severities: [], systems: [{ product: "panos" }], teams: ["t1"] })
    expect(applicable({ ...form, kinds: ["vendor_change", "vendor_version"] }).severities).toEqual(["critical"])
  })
  it("source health alone: none of the filters", () => {
    expect(applicable({ ...form, kinds: ["source_health"] })).toEqual({
      ...form,
      kinds: ["source_health"],
      severities: [],
      sources: [],
      topics: [],
      systems: [],
      keywords: [],
      exclude: [],
    })
  })
  it("the dry run tries what is saved", () => {
    for (const kinds of [["news"], ["vendor_version"], ["vendor_vuln", "source_health"], ["source_health"]] as const) {
      const { name: _, ...saved } = applicable({ ...form, kinds: [...kinds] })
      expect(dryRunBody({ ...form, kinds: [...kinds] }, 7)).toEqual({ ...saved, days: 7 })
    }
  })
})

describe("words as chips", () => {
  it("as the server takes them", () => {
    expect(normalizeWord("  Palo   Alto ")).toBe("Palo Alto")
    expect(splitWords("Citrix Bleed, ransomware,, ")).toEqual(["Citrix Bleed", "ransomware"])
    expect(wordProblem("x", [])).toBe("notify.wordLength")
    expect(wordProblem("a".repeat(61), [])).toBe("notify.wordLength")
    expect(wordProblem("<script>", [])).toBe("notify.wordChars")
    expect(wordProblem("--", [])).toBe("notify.wordChars")
    expect(wordProblem("Lücke", ["lucke"])).toBe("notify.wordTwice")
    expect(wordProblem("C++", [])).toBeNull()
    expect(
      wordProblem(
        "one more",
        Array.from({ length: 30 }, (_, n) => `w${n}`),
      ),
    ).toBe("notify.wordsMax")
  })
})

describe("the rules list's line", () => {
  const vendors = catalogVendors(products)
  const ctx = { sourceName: (id: string) => ({ s1: "heise", s2: "BSI" })[id], teamNames: [], vendors }
  const rule = { kinds: ["news" as const], severities: ["critical" as const], sources: ["s1"], topics: [], lang: "de" as const, systems: [], keywords: [], exclude: [] }
  it('names "Unsere Produkte" as such', () => {
    expect(ruleSummary(t, { ...rule, systems: [OURS] }, ctx)).toContain('notify.concernsList{"names":"⁨notify.systemsOursChip⁩"}')
  })
  it("a news rule: severity, sources, what it concerns and keeps away", () => {
    const line = ruleSummary(t, { ...rule, systems: [{ vendor: "Palo Alto Networks" }, { product: "gone" }], keywords: ["Bleed"], exclude: ["Webinar"] }, ctx)
    expect(line).toBe(
      [
        "notify.kind.news",
        "news.sev.critical",
        "⁨heise⁩",
        'notify.concernsList{"names":"⁨notify.systemsVendorChip{\\"vendor\\":\\"Palo Alto Networks\\"}⁩, ⁨notify.systemGone⁩, notify.quoted{\\"word\\":\\"Bleed\\"}"}',
        'notify.excludeList{"names":"notify.quoted{\\"word\\":\\"Webinar\\"}"}',
        "Deutsch",
      ].join(" · "),
    )
  })
  it("no sources or words where they do not apply, no severity for versions and source health", () => {
    const line = ruleSummary(t, { ...rule, kinds: ["vendor_version", "source_health"], keywords: ["Bleed"], exclude: ["x"], systems: [{ product: "panos" }] }, ctx)
    expect(line).toBe(["notify.kind.vendor_version, notify.kind.source_health", 'notify.concernsList{"names":"⁨PAN-OS (Firewalls)⁩"}', "Deutsch"].join(" · "))
    expect(ruleSummary(t, { ...rule, kinds: ["vendor_change"], severities: [] }, ctx)).toBe("notify.kind.vendor_change · notify.allSeverities · Deutsch")
    expect(ruleSummary(t, { ...rule, kinds: ["source_health"], systems: [{ product: "panos" }] }, ctx)).toBe("notify.kind.source_health · Deutsch")
  })
})

describe("switched-off sources", () => {
  const sources = [
    { id: "a", enabled: true },
    { id: "b", enabled: false },
    { id: "c", enabled: false },
  ]
  it("which are off, and whether the rule names only those", () => {
    expect(offSources(["a", "b"], sources)).toEqual({ off: ["b"], onlyOff: false })
    expect(offSources(["b", "c", "gone"], sources)).toEqual({ off: ["b", "c"], onlyOff: true })
    expect(offSources([], sources)).toEqual({ off: [], onlyOff: false })
  })
})

describe("the dry run with systems and words", () => {
  const form = { severities: [], sources: [], lang: "de" as const, teams: [], systems: [{ product: "panos" }], keywords: ["Bleed"], exclude: ["Webinar"] }
  it("sends systems where they apply, words with news only", () => {
    expect(dryRunBody({ ...form, kinds: ["vendor_vuln"] }, 7)).toMatchObject({ systems: [{ product: "panos" }], keywords: [], exclude: [] })
    expect(dryRunBody({ ...form, kinds: ["source_health"] }, 7)).toMatchObject({ systems: [], keywords: [], exclude: [] })
    expect(dryRunBody({ ...form, kinds: ["news"] }, 7)).toMatchObject({ systems: [{ product: "panos" }], keywords: ["Bleed"], exclude: ["Webinar"] })
  })
  it("says what it matched by", () => {
    const x: DryRunItem = {
      kind: "news",
      id: "1",
      title: "x",
      severity: "high",
      at: "",
      source: "Feed",
      hits: ["PAN-OS", "Bleed"],
      match: { kind: "news", severity: false, source: false, teams: false, concern: true },
    }
    expect(matchParts(t, x)).toEqual(["notify.kind.news", 'dlog.dry.byHits{"names":"PAN-OS, Bleed"}'])
  })
})

describe("systems beyond the rules (News filter, own notifications)", () => {
  it("an address's system is a catalogue key or a vendor's name – anything else is dropped", () => {
    expect(systemParam("p:panos")).toEqual({ product: "panos" })
    expect(systemParam(" v:Palo Alto Networks ")).toEqual({ vendor: "Palo Alto Networks" })
    for (const bad of ["p:PAN OS", "p:-x", "p:", "v:", "v: ", "x:panos", "panos", "v:a\u0000b", "v:" + "x".repeat(121)]) expect(systemParam(bad), bad).toBeNull()
    expect(readSystems(["p:panos", "p:panos", "v:Fortinet", "bad"])).toEqual([{ product: "panos" }, { vendor: "Fortinet" }])
  })
  it('"Unsere Produkte" is its own system – `system=ours`, named without the catalogue', () => {
    expect(systemValue(OURS)).toBe("ours")
    expect(systemOf("ours")).toEqual({ ours: true })
    expect(systemParam(" ours ")).toEqual({ ours: true })
    for (const bad of ["OURS", "ours:x", "o:ours", "p:ours "]) expect(systemParam(bad), bad).not.toEqual({ ours: true })
    expect(readSystems(["ours", "p:panos", "ours"])).toEqual([{ ours: true }, { product: "panos" }])
    expect(systemName(t, OURS, undefined)).toBe("notify.systemsOursChip")
    expect(systemName(t, OURS, catalogVendors(products))).toBe("notify.systemsOursChip")
    expect(systemRef(OURS)).toBe("ours")
    expect(systemRef({ vendor: "Fortinet" })).toBe("Fortinet")
  })
  it("its texts in both languages", () => {
    expect(de["notify.systemsOursChip"]).toBe("Unsere Produkte")
    expect(de["notify.systemsOurs"]).toBe("Unsere Produkte (aus Vendor News)")
    expect(en["notify.systemsOurs"]).toBe("Our products (from Vendor News)")
    expect(de["notify.systemsOursHint"]).toContain("auch später hinzugefügte")
    expect(de["notify.sourcesHint"]).toBe("Leer = alle eingeschalteten Quellen.")
    expect(en["notify.sourcesHint"]).toBe("Empty = all switched-on sources.")
  })
  it("a person's picker offers only the vendors and products among their own", () => {
    const mine = vendorsOf(catalogVendors(products), ["panos", "rhel"])!
    expect(mine.map((v) => [v.name, v.products.map((p) => p.key)])).toEqual([
      ["Palo Alto Networks", ["panos"]],
      ["Red Hat", ["rhel"]],
    ])
    expect(vendorsOf(catalogVendors(products), [])).toEqual([])
    expect(vendorsOf(undefined, ["panos"])).toBeUndefined()
  })
})

describe("texts", () => {
  it("the texts of the News filter and the own notifications in both languages", () => {
    const keys = Object.keys(de).filter((k) =>
      /^(news\.(filterSystems|systemRemove|filterWithout|without)|desktop\.(systems|exclude|hit)|personal\.(systems|allSystems|systemGone))/.test(k),
    )
    expect(keys.length).toBe(17)
    for (const k of keys) expect(en, k).toHaveProperty([k])
  })
  it("every new key in both languages", () => {
    const keys = Object.keys(de).filter((k) => /^notify\.(systems?|allSystems|keywords|exclude|word|concerns|quoted|sourceOff|sourcesOnlyOff|sourcesSomeOff)/.test(k))
    expect(keys.length).toBeGreaterThan(20)
    for (const k of keys) expect(en, k).toHaveProperty([k])
  })
})
