import type { TFunction } from "i18next"
import { describe, expect, it } from "vitest"
import { directoryTestError, directoryTestToast } from "@/lib/directory-test"
import de from "@/i18n/de"
import en from "@/i18n/en"

/** A t() over the real texts, returning the default value or the key when one is missing – like i18next. */
const tOf = (texts: Record<string, string>) =>
  ((key: string, opts?: Record<string, unknown>) => texts[key] ?? (opts?.defaultValue as string | undefined) ?? key) as unknown as TFunction

describe("Verbindung testen (AD/LDAP, Entra ID): a toast for every result", () => {
  it.each([de, en])("success: a short confirmation of what was checked", (texts) => {
    const t = tOf(texts)
    expect(directoryTestToast(t, "ldap", { ok: true })).toEqual({ level: "success", text: texts["signin.ldap.testOk"] })
    expect(directoryTestToast(t, "entra", { ok: true, groups: "ok" })).toEqual({ level: "success", text: texts["signin.entra.testOk"] })
  })

  it.each([de, en])("Entra without the Graph permission for groups: a warning, not a plain success", (texts) => {
    const r = directoryTestToast(tOf(texts), "entra", { ok: true, groups: "forbidden" })
    expect(r.level).toBe("warning")
    expect(r.text).toBe(texts["signin.entra.testOkLimited"])
    expect(r.text).toBeTruthy()
  })

  it.each(["ldap", "entra"] as const)("%s failed: the toast says what the box under the form says", (kind) => {
    for (const texts of [de, en]) {
      const t = tOf(texts)
      for (const error of ["connection", "tls", "service_bind", "search", "auth", "forbidden_target"]) {
        const r = directoryTestToast(t, kind, { ok: false, error })
        expect(r).toEqual({ level: "error", text: directoryTestError(t, error) })
        expect(r.text).toBe(texts[`dir.err.${error}`])
      }
    }
  })

  it("an unknown reason is shown as it came, never an empty toast", () => {
    expect(directoryTestToast(tOf(de), "ldap", { ok: false, error: "something_new" })).toEqual({ level: "error", text: "something_new" })
  })
})
