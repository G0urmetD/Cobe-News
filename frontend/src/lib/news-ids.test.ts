import { describe, expect, it } from "vitest"
import { isShortSearch, isStoryId, reasonText } from "@/lib/news-api"
import de from "@/i18n/de"

describe("story ids in the address (0.1.51)", () => {
  it("only a UUID is a story – ?story=not-a-uuid is handled as a story that is gone, never asked", () => {
    expect(isStoryId("d2d61018-135e-41ee-8284-430cfe890618")).toBe(true)
    expect(isStoryId("D2D61018-135E-41EE-8284-430CFE890618")).toBe(true)
    for (const bad of ["not-a-uuid", "", null, undefined, "d2d61018-135e-41ee-8284-430cfe89061", "../../x"]) expect(isStoryId(bad)).toBe(false)
  })
})

describe("short search terms (0.1.51)", () => {
  it("1–2 characters are short, as for the audit log", () => {
    expect(isShortSearch("")).toBe(false)
    expect(isShortSearch("  ")).toBe(false)
    expect(isShortSearch("z")).toBe(true)
    expect(isShortSearch(" zz ")).toBe(true)
    expect(isShortSearch("zzz")).toBe(false)
    expect(isShortSearch("%")).toBe(false) // no term at all once % drops out – a search like an empty one
    expect(isShortSearch("a%")).toBe(true)
  })
})

const t = (key: string, opts?: Record<string, unknown>): string => {
  const text = (de as Record<string, string>)[key] ?? (opts?.defaultValue as string | undefined) ?? key
  return text.replace(/\{\{(\w+)\}\}/g, (_, k: string) => String(opts?.[k] ?? ""))
}

describe("the reasons of a rating", () => {
  it("an unknown kind is a sentence, never the raw key", () => {
    const text = reasonText(t, { kind: "cve", value: "CVE-2026-1" })
    expect(text).not.toContain("news.reason")
    expect(text).toBe(de["news.reason.other"].replace("{{value}}", "CVE-2026-1"))
    expect(reasonText(t, { kind: "whatever", value: "" })).toBe(de["news.reason.otherPlain"])
  })
  it("known kinds keep their sentence; a vendor's own word stays readable", () => {
    expect(reasonText(t, { kind: "bsi", value: "hoch" })).toBe(de["news.reason.bsi"].replace("{{value}}", "hoch"))
    expect(reasonText(t, { kind: "vendor", value: "Microsoft Patchday" })).toContain("Microsoft Patchday")
    expect(reasonText(t, { kind: "vendor", value: "Microsoft Patchday" })).not.toContain("news.sev")
  })
})
