process.env.TZ = "Europe/Berlin"

import { beforeAll, describe, expect, it } from "vitest"
import i18n from "@/i18n"
import { fmtDayFrom } from "@/lib/format"
import {
  type OverviewItem,
  type VersionTarget,
  byUrgency,
  matchesFilter,
  matchesStatus,
  overviewStats,
  sortItems,
  statusCounts,
  statusOf,
  supportOf,
  targetGroups,
  urgencyOf,
  worse,
} from "@/lib/vendor-api"

beforeAll(async () => {
  await i18n.changeLanguage("de")
})

const target = (t: Partial<VersionTarget> = {}): VersionTarget => ({ kind: "none", to: null, line: null, fixes: 0, total: 0, open: 0, possible: 0, newer: null, ...t })

function item(
  label: string,
  o: { counts?: Partial<OverviewItem["counts"]>; urgency?: OverviewItem["urgency"]; versions?: [string, VersionTarget?][]; eol?: [string, string][] } = {},
): OverviewItem {
  const versions = (o.versions ?? []).map(([v], n) => ({ id: `${label}-${n}`, version: v, label: "", count: null, valid: true, invalid_reason: null, updated_at: null }))
  return {
    product: {
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
      custom: false,
    },
    follow: { enabled: true, note: "", tags: [], created_at: null },
    versions,
    summary: {
      worst: "none",
      per_version: Object.fromEntries(
        versions.map((v, n) => [v.id, { affected: 0, possible: 0, critical: 0, exploited: 0, service: 0, unversioned: 0, target: o.versions?.[n]?.[1] }]),
      ),
    },
    releases: (o.eol ?? []).map(([state, date], n) => ({
      version_id: versions[n]?.id ?? `x${n}`,
      eol_state: state as "ok",
      line: { name: "1", label: null, latest: null, latest_date: null, eol_from: date, eoas_from: null, lts: null },
    })),
    counts: { affected: 0, possible: 0, service: 0, unversioned: 0, critical: 0, exploited: 0, ...o.counts },
    urgency: o.urgency,
    latest: [],
  }
}

describe("overview order", () => {
  it("exploited → critical → affected → possibly → info → ok, from the server or from the counts", () => {
    const items = [
      item("Ok"),
      item("Possible", { counts: { possible: 3, exploited: 1 } }), // exploited, but only "possibly": not at the top
      item("Exploited", { counts: { affected: 1, exploited_affected: 1 } }),
      item("Cloud", { counts: { service: 2 } }),
      item("Critical", { counts: { affected: 2, critical_affected: 1 } }),
      item("Affected", { counts: { affected: 5 } }),
      item("Ended", { eol: [["past", "2025-01-01"]] }),
    ]
    expect([...items].sort(byUrgency).map((i) => i.product.label)).toEqual(["Exploited", "Critical", "Affected", "Ended", "Possible", "Cloud", "Ok"])
    expect(urgencyOf(item("Server", { urgency: "critical" }))).toBe("critical")
    expect(urgencyOf(item("Old", { counts: { stale: 4 } }))).toBe("ok") // unclear old data never make it urgent
  })

  it("unclear old data rank below everything that counts", () => {
    expect(worse("stale", "possible")).toBe("possible")
    expect(worse("stale", "not_affected")).toBe("stale")
  })
})

describe("targets per version", () => {
  it("versions with the same target share one line, the most open first", () => {
    const up = target({ kind: "update", to: "4.14.6", line: "4.14", fixes: 31, total: 31 })
    const i = item("Wazuh", {
      versions: [
        ["4.14.4", up],
        ["4.14.3", up],
        ["4.13.2", target({ kind: "newer_line", to: "4.14.6", line: "4.14", fixes: 40, total: 42, open: 2 })],
        ["4.14.6", target()],
      ],
    })
    const g = targetGroups(i)
    expect(g.map((x) => x.versions.map((v) => v.version))).toEqual([["4.13.2"], ["4.14.4", "4.14.3"], ["4.14.6"]])
  })
})

describe("summary bar", () => {
  const today = new Date(2026, 9, 29)
  const items = [
    item("PAN-OS", { counts: { affected: 3, exploited_affected: 1 }, eol: [["soon", "2027-03-01"]] }),
    item("TYPO3", { counts: { possible: 1 }, eol: [["ok", "2027-12-31"]] }),
    item("Old NAS", { eol: [["past", "2026-01-31"]] }),
    item("Clean", { eol: [["ok", "2029-06-30"]] }),
  ]
  it("counts products that need action, exploited ones and the next end of support", () => {
    const s = overviewStats(items, today)
    expect(s.action).toBe(2) // affected, or no support any more – "possibly" is not action
    expect(s.exploited).toBe(1)
    expect(s.ended).toBe(1)
    expect(s.next?.item.product.label).toBe("PAN-OS")
    expect(s.next?.date).toBe("2027-03-01")
  })
  it("each part filters the products", () => {
    expect(items.filter((i) => matchesFilter(i, "action")).map((i) => i.product.label)).toEqual(["PAN-OS", "Old NAS"])
    expect(items.filter((i) => matchesFilter(i, "exploited")).map((i) => i.product.label)).toEqual(["PAN-OS"])
    expect(items.filter((i) => matchesFilter(i, "support")).map((i) => i.product.label)).toEqual(["PAN-OS", "Old NAS"])
    expect(items.filter((i) => matchesFilter(i, null))).toHaveLength(4)
  })
  it("support of a product: the worst state and the earliest end", () => {
    const i = item("Two lines", {
      versions: [["1"], ["2"]],
      eol: [
        ["ok", "2028-01-01"],
        ["soon", "2027-02-01"],
      ],
    })
    expect(supportOf(i)).toEqual({ state: "soon", until: "2027-02-01" })
    expect(supportOf(item("Unknown"))).toEqual({ state: "unknown", until: null })
  })
  it("the time to an end of support in words", async () => {
    expect(fmtDayFrom("2027-03-01", today)).toBe("in 4 Monaten")
    expect(fmtDayFrom("2026-11-10", today)).toBe("in 12 Tagen")
    expect(fmtDayFrom("2029-06-30", today)).toBe("in 3 Jahren")
    await i18n.changeLanguage("en")
    expect(fmtDayFrom("2027-03-01", today)).toBe("in 4 months")
    await i18n.changeLanguage("de")
  })
})

describe("list view", () => {
  const items = [
    item("Bravo", { counts: { affected: 2 }, eol: [["ok", "2028-01-01"]] }),
    item("alpha", { counts: { affected: 9, critical_affected: 1 } }),
    item("Charlie", { eol: [["soon", "2027-01-01"]] }),
  ]
  it("sorts by any column, ties by urgency", () => {
    expect(sortItems(items, "product", false).map((i) => i.product.label)).toEqual(["alpha", "Bravo", "Charlie"])
    expect(sortItems(items, "affected", true).map((i) => i.product.label)).toEqual(["alpha", "Bravo", "Charlie"])
    expect(sortItems(items, "support", false).map((i) => i.product.label)).toEqual(["Charlie", "Bravo", "alpha"]) // no date last
    expect(sortItems(items, "urgency", false).map((i) => i.product.label)).toEqual(["alpha", "Bravo", "Charlie"])
  })
})

describe("status row", () => {
  const items = [
    item("PAN-OS", { counts: { affected: 3, exploited_affected: 1 } }),
    item("Old NAS", { versions: [["4.1"]], eol: [["past", "2024-01-31"]] }), // no support any more: action as well
    item("nginx", { counts: { possible: 2 } }),
    item("Wiki", { counts: { unversioned: 4 } }), // no version given: to check
    item("M365", { counts: { service: 1 } }), // a cloud service with notes: to check, not "all well"
    item("Soon", { versions: [["2.0"]], eol: [["soon", "2027-01-31"]] }),
    item("GitLab", { versions: [["17.2.1"]], counts: { stale: 3 } }), // only "unklare Altdaten": all well
    item("Redis", { versions: [["7.2.5"]] }),
  ]

  it("puts every product into exactly one group – Handlungsbedarf as in the summary bar", () => {
    expect(items.map((i) => [i.product.label, statusOf(i)])).toEqual([
      ["PAN-OS", "action"],
      ["Old NAS", "action"],
      ["nginx", "check"],
      ["Wiki", "check"],
      ["M365", "check"],
      ["Soon", "check"],
      ["GitLab", "ok"],
      ["Redis", "ok"],
    ])
    const c = statusCounts(items)
    expect(c).toEqual({ action: 2, check: 4, ok: 2, all: 8 })
    expect(c.action + c.check + c.ok).toBe(c.all)
    expect(c.action).toBe(overviewStats(items).action)
    expect(overviewStats(items).ok).toBe(2)
  })

  it("filters together with the summary filters and the search (counted over what those leave)", () => {
    const supportOnly = items.filter((i) => matchesFilter(i, "support"))
    expect(statusCounts(supportOnly)).toEqual({ action: 1, check: 1, ok: 0, all: 2 })
    expect(items.filter((i) => matchesStatus(i, "ok")).map((i) => i.product.label)).toEqual(["GitLab", "Redis"])
    expect(items.filter((i) => matchesStatus(i, "all"))).toHaveLength(8)
  })
})
