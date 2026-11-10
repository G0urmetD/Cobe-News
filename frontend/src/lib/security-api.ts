import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { createPasskey, getPasskey, type CreationOptionsJSON, type RequestOptionsJSON } from "@/lib/webauthn"
import type { LoginStep } from "@/lib/api"

/** Passkeys and sessions (app/passkeys_api.py, app/sessions_api.py): the own ones and the admins' view of an account. */

export interface Passkey {
  id: string
  name: string
  created_at: string
  last_used_at: string | null
  transports: string[]
  /** the signature counter went back – possibly a cloned authenticator */
  sign_count_warning_at: string | null
}

/** …_device: the TOTP step skipped on a remembered device */
export type SignInMethod = "password" | "password_totp" | "ldap" | "ldap_totp" | "passkey" | "entra" | "entra_totp" | "password_device" | "ldap_device" | "entra_device"

/** A remembered device ("Zweiten Faktor auf dem Gerät merken", app/auth/devices.py) – it skips the TOTP step. */
export interface RememberedDevice {
  id: string
  /** this browser */
  current: boolean
  created_at: string
  expires_at: string
  last_used_at: string | null
  ip: string | null
  user_agent: string
}

export interface SessionRow {
  id: string
  current: boolean
  /** "active", or a sign-in still under way (mfa | password | enroll) */
  stage: string
  method: SignInMethod | null
  passkey: string | null
  created_at: string
  last_seen_at: string
  expires_at: string
  ip: string | null
  user_agent: string
}

export interface PasskeySettings {
  enabled: boolean
  rev: number
  available: boolean
  reason: string | null
  rp_id: string | null
  origin: string | null
}

export const useMyPasskeys = (enabled = true) => useQuery({ queryKey: ["me", "passkeys"], queryFn: () => api.get<Passkey[]>("/api/me/passkeys"), enabled })
export const useMySessions = () => useQuery({ queryKey: ["me", "sessions"], queryFn: () => api.get<SessionRow[]>("/api/me/sessions") })
export const useUserPasskeys = (uid: string) => useQuery({ queryKey: ["admin", "users", uid, "passkeys"], queryFn: () => api.get<Passkey[]>(`/api/admin/users/${uid}/passkeys`) })
export const useUserSessions = (uid: string) =>
  useQuery({ queryKey: ["admin", "users", uid, "sessions"], queryFn: () => api.get<SessionRow[]>(`/api/admin/users/${uid}/sessions`) })
// the own list under /api/auth: the device cookie (Path=/api/auth) comes along there – "dieses Gerät"
export const useMyDevices = () => useQuery({ queryKey: ["me", "devices"], queryFn: () => api.get<RememberedDevice[]>("/api/auth/devices") })
export const useUserDevices = (uid: string) =>
  useQuery({ queryKey: ["admin", "users", uid, "devices"], queryFn: () => api.get<RememberedDevice[]>(`/api/admin/users/${uid}/devices`) })
export const usePasskeySettings = () => useQuery({ queryKey: ["admin", "passkeys"], queryFn: () => api.get<PasskeySettings>("/api/admin/auth/passkeys") })

/** Registers a passkey of this device: the options (needs a fresh re-confirmation – call inside withReauth), the
 *  browser's dialog, the answer checked by the server. */
export async function registerPasskey(name: string): Promise<Passkey> {
  const options = await api.post<CreationOptionsJSON>("/api/me/passkeys/options")
  const answer = await createPasskey(options)
  return api.post<Passkey>("/api/me/passkeys", { name, ...answer })
}

/** The set-up step of a sign-in ("Zweiter Faktor für alle", a local reader): a passkey of this device instead of TOTP –
 *  the password just checked is the proof of identity; the answer ends the sign-in. */
export async function enrollPasskey(name: string): Promise<LoginStep> {
  const options = await api.post<CreationOptionsJSON>("/api/auth/enroll/passkey/options")
  const answer = await createPasskey(options)
  return api.post<LoginStep>("/api/auth/enroll/passkey", { name, ...answer })
}

/** What the set-up step offers (GET /api/auth/state in stage "enroll"). */
export interface EnrollInfo {
  /** admin: admins always need TOTP | required: "Zweiter Faktor für alle" (or Entra without a proof) */
  reason: "admin" | "required"
  /** a passkey instead of TOTP (local readers, passkeys on and possible) */
  passkey: boolean
  /** the account has a passkey already – a sign-in with it needs nothing more */
  has_passkey: boolean
}

/** The sign-in without a user name: any passkey of this site the browser offers. */
export async function signInWithPasskey(): Promise<LoginStep> {
  const options = await api.post<RequestOptionsJSON>("/api/auth/passkey/options")
  const answer = await getPasskey(options)
  return api.post<LoginStep>("/api/auth/passkey/login", answer)
}
