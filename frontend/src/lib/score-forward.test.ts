import { beforeAll, describe, expect, it } from "vitest"
import i18n from "@/i18n"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { forwardState } from "@/lib/forward-api"
import { type OverviewItem, type Score, type ScorePart, SCORE_TONE, byUrgency, matchesFilter, overviewStats, scorePartText, sortItems } from "@/lib/vendor-api"

beforeAll(async () => {
  await i18n.changeLanguage("de")
})

const t = (k: string, o?: Record<string, unknown>) => i18n.t(k, o)

function item(label: string, score: Score | null, counts: Partial<OverviewItem["counts"]> = {}): OverviewItem {
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
    versions: [],
    summary: { worst: "none", per_version: {} },
    releases: [],
    counts: { affected: 0, possible: 0, service: 0, unversioned: 0, critical: 0, exploited: 0, ...counts },
    score,
    latest: [],
  }
}

const score = (value: number, level: Score["level"]): Score => ({ value, level, raw: value, parts: [] })

describe("Dringlichkeit", () => {
  it("says each factor of the breakdown with its points", () => {
    const parts: ScorePart[] = [
      { factor: "kev", points: 30 },
      { factor: "epss", points: 20, percentile: 0.973 },
      { factor: "version", points: 25, status: "affected" },
      { factor: "severity", points: 35, band: "critical", cvss: 9.8 },
      { factor: "severity", points: 25, band: "high", cvss: null },
      { factor: "version", points: -70, status: "not_affected" },
      { factor: "version", points: 0, status: "service" },
      { factor: "no_fix", points: 5 },
      { factor: "age", points: 10, days: 1 },
      { factor: "age", points: 5, days: 12 },
      { factor: "exploited", points: 25 },
    ]
    expect(parts.map((p) => scorePartText(t, p, "de"))).toEqual([
      "KEV +30",
      "EPSS-Perzentil 97 % +20",
      "eure Version betroffen +25",
      "CVSS 9,8 (Kritisch) +35",
      "Schwere Hoch +25",
      "eure Version nicht betroffen −70",
      "Cloud-Dienst (behebt der Hersteller) ±0",
      "kein Fix bekannt +5",
      "seit 1 Tag bekannt +10",
      "seit 12 Tagen bekannt +5",
      "ausgenutzt +25",
    ])
  })

  it("has every text in both languages", () => {
    const keys = [
      ...["now", "soon", "watch"].map((l) => `vendor.score.level.${l}`),
      ...["affected", "possible", "unversioned", "service", "stale", "not_affected"].map((s) => `vendor.score.part.version.${s}`),
      ...["cvss", "severity", "epss", "kev", "exploited", "no_fix", "age_one", "age_other", "public_exploit"].map((f) => `vendor.score.part.${f}`),
      "vendor.score.help",
      "vendor.sort.score",
      "vendor.col.score",
      "vendor.sum.nowHelp",
    ]
    for (const k of keys) {
      expect(de[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
    }
    expect(Object.keys(SCORE_TONE)).toEqual(["now", "soon", "watch"])
  })

  it("sorts, filters and counts by the number – the tiers stay first", () => {
    const a = item("A", score(50, "soon"), { affected: 1 })
    const b = item("B", score(80, "now"), { affected: 1 })
    const c = item("C", score(90, "now"), { possible: 1 }) // a higher number, but only "possibly": the tier decides first
    const d = item("D", null)
    expect([a, b, c, d].sort(byUrgency).map((i) => i.product.label)).toEqual(["B", "A", "C", "D"])
    expect(sortItems([a, b, c, d], "score", true).map((i) => i.product.label)).toEqual(["C", "B", "A", "D"])
    expect(sortItems([a, b, c, d], "score", false).map((i) => i.product.label)).toEqual(["D", "A", "B", "C"])
    expect([a, b, c, d].filter((i) => matchesFilter(i, "now")).map((i) => i.product.label)).toEqual(["B", "C"])
    expect(overviewStats([a, b, c, d]).now).toBe(2)
  })
})

describe("An mein Team weiterleiten", () => {
  it("hidden without teams, off without a channel, ready with the teams that have one", () => {
    expect(forwardState(undefined)).toEqual({ state: "hidden" })
    expect(forwardState({ enabled: false, teams: [] })).toEqual({ state: "hidden" })
    expect(forwardState({ enabled: true, teams: [] })).toEqual({ state: "hidden" })
    expect(forwardState({ enabled: true, teams: [{ id: "1", name: "SOC", forward: false }] })).toEqual({ state: "off" })
    expect(forwardState({ enabled: true, teams: [{ id: "1", name: "SOC" }] })).toEqual({ state: "off" }) // an older server
    expect(
      forwardState({
        enabled: true,
        teams: [
          { id: "1", name: "SOC", forward: true },
          { id: "2", name: "NOC", forward: false },
        ],
      }),
    ).toEqual({ state: "ready", teams: [{ id: "1", name: "SOC", forward: true }] })
  })

  it("has every text in both languages", () => {
    const keys = Object.keys(de).filter((k) => k.startsWith("forward.") || k.startsWith("errors.forward_") || k.startsWith("teams.forward"))
    expect(keys.length).toBeGreaterThan(20)
    for (const k of keys) expect(en[k], k).toBeTruthy()
    for (const k of ["timeout", "rejected", "auth", "http", "rate_limited", "not_configured", "connection", "dns", "refused", "tls", "forbidden_target", "host_not_allowed"])
      expect(de[`forward.err.${k}`], k).toBeTruthy()
  })
})
