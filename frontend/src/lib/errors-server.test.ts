import type { TFunction } from "i18next"
import { describe, expect, it, vi } from "vitest"
import { ApiError } from "@/lib/api"
import { errorText } from "@/lib/errors"
import de from "@/i18n/de"
import en from "@/i18n/en"

const tOf =
  (texts: Record<string, string>) =>
  (key: string, opts?: Record<string, unknown>): string => {
    const text = texts[key] ?? (opts?.defaultValue as string | undefined) ?? key
    return text.replace(/\{\{(\w+)\}\}/g, (_, k: string) => String(opts?.[k] ?? ""))
  }

describe("errorText for server errors and no answer (0.1.51)", () => {
  it.each([de, en])("says the database is gone, a server error and no connection in words", (texts) => {
    const t = tOf(texts) as unknown as TFunction
    expect(errorText(t, new ApiError(503, { code: "unavailable" }))).toBe(texts["errors.unavailable"])
    // a 500 or a proxy's 502 without a code of its own: not "Fehler: http_500"
    expect(errorText(t, new ApiError(500, { code: "http_500" }))).toBe(texts["errors.server"].replace("{{status}}", "500"))
    expect(errorText(t, new ApiError(502, { code: "http_502" }))).toContain("502")
    // a 4xx without a text keeps the code
    expect(errorText(t, new ApiError(418, { code: "http_418" }))).toBe(texts["errors.generic_code"].replace("{{code}}", "http_418"))
    expect(errorText(t, new TypeError("Failed to fetch"))).toBe(texts["errors.network"])
  })

  it("names an offline browser as such", () => {
    vi.stubGlobal("navigator", { onLine: false })
    try {
      expect(errorText(tOf(de) as unknown as TFunction, new TypeError("Failed to fetch"))).toBe(de["offline.text"])
    } finally {
      vi.unstubAllGlobals()
    }
  })
})
