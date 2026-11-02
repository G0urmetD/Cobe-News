import { describe, expect, it } from "vitest"
import { epssPercent, epssTone } from "@/lib/epss"

describe("EPSS", () => {
  it("shows small probabilities with a decimal, large ones whole", () => {
    expect(epssPercent(0.00423, "de")).toBe("0,4")
    expect(epssPercent(0.0423, "en")).toBe("4.2")
    expect(epssPercent(0.97123, "de")).toBe("97")
    expect(epssPercent(0.99999, "en")).toBe("100")
  })
  it("colours by likelihood", () => {
    expect(epssTone(0.6)).toBe("--sev-critical")
    expect(epssTone(0.2)).toBe("--sev-high")
    expect(epssTone(0.02)).toBe("--sev-medium")
    expect(epssTone(0.001)).toBe("--muted-foreground")
  })
})
