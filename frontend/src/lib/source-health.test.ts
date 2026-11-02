import { describe, expect, it } from "vitest"
import i18next from "i18next"
import de from "@/i18n/de"
import en from "@/i18n/en"
import healthDe from "@/i18n/health.de"
import healthEn from "@/i18n/health.en"
import {
  deadCount,
  errorLabel,
  filterRows,
  fmtMs,
  type HealthOverview,
  type HealthRow,
  type HealthState,
  isProblem,
  parseSourceParam,
  sortRows,
  sparkLabel,
  sparkPoints,
  STATE_COLOR,
  STATE_ORDER,
} from "@/lib/source-health"

const row = (name: string, state: HealthState): HealthRow => ({
  kind: "news",
  key: name,
  name,
  group: "press",
  host: "",
  url: "",
  enabled: state !== "off",
  state,
  reasons: [],
  since: null,
  last_ok_at: null,
  last_fetch_at: null,
  next_fetch_at: null,
  paused: false,
  failures: 0,
  error: null,
  last_error: null,
  weeks: [null, null, null, null],
  avg_ms: null,
  avg_bytes: null,
  fetches_7d: 0,
  timeouts_7d: 0,
  parse_errors_7d: 0,
  not_modified_7d: 0,
  conditional: false,
  members: null,
})

async function translator(lang: "de" | "en") {
  const i = i18next.createInstance()
  await i.init({ lng: lang, resources: { [lang]: { translation: lang === "de" ? de : en } }, keySeparator: false, nsSeparator: false, interpolation: { escapeValue: false } })
  return i.t
}

describe("state → chip", () => {
  it("colours by UX.md: red only for dead, amber disturbed, blue slow, green healthy, grey off and never", () => {
    expect(STATE_COLOR).toEqual({
      dead: "--sev-critical",
      disturbed: "--warning",
      slow: "--primary",
      healthy: "--success",
      off: "--muted-foreground",
      never: "--muted-foreground",
    })
  })
  it("has a word and an explanation for every state in both languages", () => {
    for (const s of STATE_ORDER) {
      for (const m of [healthDe, healthEn]) {
        expect(m[`health.state.${s}`]).toBeTruthy()
        expect(m[`health.stateHint.${s}`]).toBeTruthy()
      }
    }
  })
  it("counts only disturbed and dead as problems", () => {
    expect(STATE_ORDER.filter(isProblem)).toEqual(["dead", "disturbed"])
  })
})

describe("table", () => {
  it("sorts worst first, then by name, and filters problems", () => {
    const rows = [row("b", "healthy"), row("a", "healthy"), row("z", "dead"), row("x", "off"), row("y", "slow"), row("w", "disturbed")]
    expect(sortRows(rows).map((r) => r.name)).toEqual(["z", "w", "y", "a", "b", "x"])
    expect(filterRows(sortRows(rows), true).map((r) => r.name)).toEqual(["z", "w"])
    expect(filterRows(rows, false)).toHaveLength(6)
  })
  it("shows the nav badge only for dead sources", () => {
    const o = (dead: number, disturbed = 0): HealthOverview => ({ at: "", items: [], counts: { dead, disturbed, slow: 0, healthy: 3, off: 0, never: 0 } })
    expect(deadCount(o(2))).toBe(2)
    expect(deadCount(o(0, 4))).toBeNull()
    expect(deadCount(undefined)).toBeNull()
  })
  it("reads the source of a link", () => {
    expect(parseSourceParam("news:heise")).toEqual({ kind: "news", key: "heise" })
    expect(parseSourceParam("vendor:nvd")).toEqual({ kind: "vendor", key: "nvd" })
    expect(parseSourceParam("structured:cvelist")).toEqual({ kind: "structured", key: "cvelist" })
    expect(parseSourceParam("news:custom-1:x")).toEqual({ kind: "news", key: "custom-1:x" })
    expect(parseSourceParam("other:x")).toBeNull()
    expect(parseSourceParam("news:")).toBeNull()
    expect(parseSourceParam(null)).toBeNull()
  })
})

describe("sparkline", () => {
  it("has a label with every week, a gap as a dash", async () => {
    const t = await translator("de")
    expect(sparkLabel([12, 8, null, 1234], t, "de")).toBe("12, 8, –, 1.234 neue Einträge je Woche, älteste zuerst")
    const te = await translator("en")
    expect(sparkLabel([0, 0, 3, 9], te, "en")).toBe("0, 0, 3, 9 new items per week, oldest first")
  })
  it("scales into the box, the highest week on top, unknown weeks marked", () => {
    const p = sparkPoints([0, 5, null, 10], 56, 18)
    expect(p.map((x) => x.x)).toEqual([2, 19.333333333333332, 36.666666666666664, 54])
    expect(p[0].y).toBe(16)
    expect(p[3].y).toBe(2)
    expect(p[1].y).toBe(9)
    expect(p.map((x) => x.known)).toEqual([true, true, false, true])
    expect(sparkPoints([null, null, null, null], 56, 18).every((x) => x.y === 16)).toBe(true) // no division by zero
  })
})

describe("numbers and errors", () => {
  it("formats response times", () => {
    expect(fmtMs(340, "de")).toBe("340 ms")
    expect(fmtMs(1234, "de")).toBe("1,2 s")
    expect(fmtMs(1234, "en")).toBe("1.2 s")
    expect(fmtMs(null, "en")).toBe("–")
  })
  it("names the error, with the status where it says something", async () => {
    const t = await translator("de")
    expect(errorLabel({ category: "blocked", status: 403 }, t)).toBe("Abgelehnt (HTTP 403)")
    expect(errorLabel({ category: "http_4xx", status: 404 }, t)).toBe("Fehlerantwort (HTTP 404)")
    expect(errorLabel({ category: "timeout", status: null }, t)).toBe("Zeitüberschreitung")
    expect(errorLabel({ category: "parse", status: 200 }, t)).toBe("Nicht lesbar")
    expect(errorLabel(null, t)).toBe("–")
  })
})

describe("i18n", () => {
  it("has the same keys in German and English", () => {
    expect(Object.keys(healthEn).sort()).toEqual(Object.keys(healthDe).sort())
  })
  it("names every error category and reason", () => {
    for (const c of ["timeout", "connection", "tls", "http_4xx", "http_5xx", "rate_limited", "blocked", "parse", "too_large", "other"])
      expect(healthDe[`health.err.${c}`]).toBeTruthy()
    for (const r of ["blocked", "not_found", "no_success", "stale", "failing", "error", "parse", "slow", "timeouts", "retrying"])
      expect(healthEn[`health.reason.${r}`]).toBeTruthy()
    expect(de["notify.kind.source_health"]).toBeTruthy()
    expect(en["notify.kind.source_healthHint"]).toBeTruthy()
  })
})
