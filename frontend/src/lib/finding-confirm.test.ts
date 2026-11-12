import { describe, expect, it } from "vitest"
import { CONFIRM_STATUSES, NOTE_MAX, NOTE_REQUIRED, cardLines, cleanNote, confirmProblem, confirmTouches, withConfirmation } from "@/lib/finding-confirm"
import type { ProductDetail } from "@/lib/vendor-api"
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
      for (const r of ["exploited", "severity", "cves", "verdict", "withdrawn", "regrouped"]) expect(lang[`confirm.reason.${r}`]).toBeTruthy()
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

  it("reads again what a confirmation changes – the drawer, overview, badge and unread numbers, not every Vendor News query", () => {
    const yes = [
      ["vendor", "product", "panos", false, "relevance"],
      ["vendor", "overview", "all"],
      ["vendor", "badge"],
      ["reader", "counts", "all"],
    ]
    const no = [["vendor", "product", "panos", "changes"], ["vendor", "product", "fortios", false, "relevance"], ["vendor", "catalog"], ["vendor", "review", "mine"], ["news"]]
    for (const k of yes) expect(confirmTouches("panos", k), k.join("/")).toBe(true)
    for (const k of no) expect(confirmTouches("panos", k), k.join("/")).toBe(false)
  })

  it("shows the answer in the drawer at once", () => {
    const page = (ids: string[]) => ({ findings: ids.map((id) => ({ id, confirmed: null, confirm_lapsed: { reason: "exploited" } })) }) as unknown as ProductDetail
    const data = { pages: [page(["a", "b"]), page(["c"])], pageParams: [0, 100] }
    const c = { status: "not_affected" as const, note: "Brotli aus", by: "Anna", at: "2026-11-11T08:00:00Z" }
    const got = withConfirmation(data, "c", c)!
    expect(got.pages[1].findings[0].confirmed).toEqual(c)
    expect(got.pages[1].findings[0].confirm_lapsed).toBeNull()
    expect(got.pages[0].findings[0].confirmed).toBeNull()
    expect(data.pages[1].findings[0].confirmed).toBeNull() // a copy
    expect(withConfirmation(undefined, "c", c)).toBeUndefined()
  })
})
