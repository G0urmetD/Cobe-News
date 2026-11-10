import { describe, expect, it } from "vitest"
import { CONFIRM_STATUSES, NOTE_MAX, NOTE_REQUIRED, cardLines, cleanNote, confirmProblem } from "@/lib/finding-confirm"
import { activeFilters, withoutChip } from "@/lib/vendor-filters"
import { readVendorFilter, writeVendorFilter } from "@/lib/reader-api"
import confirmPy from "../../../backend/app/finding_confirm.py?raw"
import de from "@/i18n/vendor.de"
import en from "@/i18n/vendor.en"

describe("Treffer bestätigen", () => {
  it("knows the server's statuses, limit and which need a reason", () => {
    expect(/^STATUSES = \(([^)]*)\)$/m.exec(confirmPy)?.[1]).toBe(CONFIRM_STATUSES.map((s) => `"${s}"`).join(", "))
    expect(/^NOTE_MAX = (\d+)$/m.exec(confirmPy)?.[1]).toBe(String(NOTE_MAX))
    expect(/^NOTE_REQUIRED = frozenset\(\{([^}]*)\}\)/m.exec(confirmPy)?.[1]).toBe(NOTE_REQUIRED.map((s) => `"${s}"`).join(", "))
  })

  it("saves only with a status – and a reason for an accepted risk", () => {
    expect(confirmProblem("", "Brotli nicht aktiviert")).toBe("status")
    expect(confirmProblem("not_affected", "")).toBeNull()
    expect(confirmProblem("mitigated", "")).toBeNull()
    expect(confirmProblem("accepted", "   ")).toBe("note_required")
    expect(confirmProblem("accepted", "Ersatz bestellt")).toBeNull()
    expect(confirmProblem("not_affected", "x".repeat(NOTE_MAX + 1))).toBe("too_long")
    expect(cleanNote("  Brotli\n nicht   aktiviert ")).toBe("Brotli nicht aktiviert")
  })

  it("has a text for every status and every reason, in both languages", () => {
    for (const lang of [de, en]) {
      for (const s of CONFIRM_STATUSES) {
        expect(lang[`confirm.status.${s}`]).toBeTruthy()
        expect(lang[`confirm.statusHint.${s}`]).toBeTruthy()
      }
      for (const r of ["exploited", "severity", "cves", "verdict", "withdrawn"]) expect(lang[`confirm.reason.${r}`]).toBeTruthy()
    }
  })

  it("lists confirmed findings on a card only with „Mit Bestätigten“, after the open ones", () => {
    const open = [{ id: "a" }, { id: "b" }, { id: "c" }, { id: "d" }]
    const done = [{ id: "x" }]
    expect(cardLines(open, done, false).map((l) => l.line.id)).toEqual(["a", "b", "c"])
    expect(cardLines(open, done, true).map((l) => [l.line.id, l.confirmed])).toEqual([
      ["a", false],
      ["b", false],
      ["c", false],
      ["x", true],
    ])
    expect(cardLines([], undefined, true)).toEqual([])
  })

  it("is a filter of the address with a chip of its own", () => {
    const f = readVendorFilter(new URLSearchParams("confirmed=1&muted=1"))
    expect(f.confirmed).toBe(true)
    expect(activeFilters(f, { team: false })).toEqual(["muted", "confirmed"])
    expect(withoutChip("confirmed")).toEqual({ url: { confirmed: false } })
    expect(writeVendorFilter(new URLSearchParams("confirmed=1&q=pan"), { confirmed: false }).toString()).toBe("q=pan")
    expect(writeVendorFilter(new URLSearchParams(), { confirmed: true }).toString()).toBe("confirmed=1")
  })
})
