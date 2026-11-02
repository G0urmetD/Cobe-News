import type { TFunction } from "i18next"

/** "Verbindung testen" of AD/LDAP and Entra ID (POST /api/admin/auth/{ldap,entra}/test): the answer of the server. */
export type DirectoryTestResult = { ok: true; groups?: string; redirect_uri?: string } | { ok: false; error: string }
export type DirectoryKind = "ldap" | "entra"

/** The text of a failed test – the same in the toast and in the box under the form. */
export function directoryTestError(t: TFunction, error: string): string {
  return t(`dir.err.${error}`, { defaultValue: error })
}

/**
 * The toast after a test – the result used to stand only in the box under the form, often out of sight, and the
 * button gave no answer of its own. Entra with a missing Graph permission for groups: sign-in works, the group search
 * does not – a warning, the box says what to grant.
 */
export function directoryTestToast(t: TFunction, kind: DirectoryKind, r: DirectoryTestResult): { level: "success" | "warning" | "error"; text: string } {
  if (!r.ok) return { level: "error", text: directoryTestError(t, r.error) }
  if (kind === "entra" && r.groups === "forbidden") return { level: "warning", text: t("signin.entra.testOkLimited") }
  return { level: "success", text: t(`signin.${kind}.testOk`) }
}
