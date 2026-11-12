/** "Zweiten Faktor auf dem Gerät merken" (app/auth/devices.py) at the TOTP step – pure, remember-device.test.ts checks it. */

/** What GET /api/auth/state says in stage "mfa" – absent while the admin switch is off (or the rule leaves the account
 *  out: admins unless included, the emergency account). */
export interface RememberInfo {
  offer: boolean
  /** until when a device remembered now would count */
  until: string | null
  /** this browser is a remembered device already (an Entra sign-in comes back without the cookie: the page asks) */
  device: boolean
}

/** The state's `remember`, only when it is shaped as expected – anything else: no switch. */
export function rememberInfo(state: unknown): RememberInfo | null {
  const r = (state as { remember?: unknown } | null)?.remember as Partial<RememberInfo> | undefined
  if (!r || r.offer !== true) return null
  return { offer: true, until: typeof r.until === "string" ? r.until : null, device: r.device === true }
}

/** The body of POST /api/auth/mfa – `remember` only when offered and switched on (never sent otherwise). */
export function mfaBody(code: string, remember: boolean, info: RememberInfo | null): { code: string; remember?: true } {
  return info?.offer && remember ? { code, remember: true } : { code }
}

/** The choices of the admin's duration (0: the maximum session lifetime). */
export const REMEMBER_DAYS = [0, 1, 7, 30] as const
export type RememberDays = (typeof REMEMBER_DAYS)[number]
