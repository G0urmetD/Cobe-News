import { describe, expect, it } from "vitest"
import { iso, isoList } from "@/lib/bidi"

describe("bidi isolation", () => {
  it("wraps each name in FSI … PDI", () => {
    expect(iso("قاعدة")).toBe("⁨قاعدة⁩")
    expect(iso("")).toBe("")
    expect(iso(null)).toBe("")
    expect(isoList(["Regel 15 قاعدة", "Regel 24", null])).toBe("⁨Regel 15 قاعدة⁩, ⁨Regel 24⁩")
    expect(isoList(["a", "b"], " · ")).toBe("⁨a⁩ · ⁨b⁩")
  })
})
