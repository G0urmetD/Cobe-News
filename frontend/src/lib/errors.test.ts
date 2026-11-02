import type { TFunction } from "i18next"
import { describe, expect, it } from "vitest"
import { ApiError } from "@/lib/api"
import { errorText } from "@/lib/errors"
import de from "@/i18n/de"
import en from "@/i18n/en"

/** A t() over the real German texts ({{x}} filled in), returning the key when it is missing – like i18next. */
const tOf =
  (texts: Record<string, string>) =>
  (key: string, opts?: Record<string, unknown>): string => {
    const text = texts[key] ?? (opts?.defaultValue as string | undefined) ?? key
    return text.replace(/\{\{(\w+)\}\}/g, (_, k: string) => String(opts?.[k] ?? ""))
  }

describe("errorText for Web Push", () => {
  // codes the server answers when a browser subscribes or a test push fails (push_api.py, webpush.PushError)
  const codes = ["push_failed", "push_disabled", "endpoint_not_allowed", "endpoint_too_long", "invalid_keys", "payload_too_large"]

  it.each(codes)("%s has a text of its own in German and English", (code) => {
    for (const texts of [de, en]) {
      const text = errorText(tOf(texts) as unknown as TFunction, new ApiError(422, { code }))
      expect(text).not.toContain(code)
      expect(text).toBe(texts[`errors.${code}`])
    }
  })

  it("names the reason a push failed", () => {
    const t = tOf(de) as unknown as TFunction
    expect(errorText(t, new ApiError(502, { code: "push_failed", detail: "timeout" }))).toBe(de["errors.push_failed_reason"].replace("{{reason}}", de["notify.err.timeout"]))
    expect(errorText(t, new ApiError(502, { code: "push_failed", detail: "gone" }))).toContain(de["errors.push_gone"])
  })
})
