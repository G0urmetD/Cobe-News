/**
 * Passkeys in the browser (WebAuthn, no library): the server's JSON options → navigator.credentials.create/get → the
 * answer as base64url JSON for the server (app/passkeys_api.py). Errors become a `PasskeyError` with a code the page
 * can explain: cancelled (or timed out), exists (this device has one already), insecure (no secure context),
 * unsupported (no WebAuthn), origin (opened at another address than the configured one), failed.
 */

export type PasskeyErrorCode = "cancelled" | "exists" | "insecure" | "unsupported" | "origin" | "failed"

export class PasskeyError extends Error {
  code: PasskeyErrorCode
  constructor(code: PasskeyErrorCode, message?: string) {
    super(message ?? code)
    this.code = code
  }
}

/** base64url without padding (RFC 4648 §5) – what WebAuthn and the server use. */
export function toBase64url(data: ArrayBuffer | ArrayBufferView): string {
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
  let bin = ""
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/** Strict: only the base64url alphabet, no padding, no length no encoding has – anything else throws. */
export function fromBase64url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) throw new PasskeyError("failed", "not base64url")
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** Can this page use passkeys at all, and at this address? `origin`: the one the server's passkeys are bound to. */
export function passkeySupport(
  origin: string | null | undefined,
  win: Pick<Window, "isSecureContext" | "location"> & { PublicKeyCredential?: unknown } = window,
): "ok" | PasskeyErrorCode {
  if (!win.isSecureContext) return "insecure"
  if (typeof win.PublicKeyCredential === "undefined" || typeof navigator === "undefined" || !navigator.credentials) return "unsupported"
  if (origin && win.location.origin !== origin) return "origin"
  return "ok"
}

function mapError(e: unknown): PasskeyError {
  if (e instanceof PasskeyError) return e
  const name = e instanceof Error || (typeof e === "object" && e && "name" in e) ? String((e as { name: string }).name) : ""
  // NotAllowedError: the person cancelled, or the time ran out – the browser does not tell which (on purpose)
  if (name === "NotAllowedError" || name === "AbortError") return new PasskeyError("cancelled")
  if (name === "InvalidStateError") return new PasskeyError("exists")
  if (name === "SecurityError") return new PasskeyError("origin")
  if (name === "NotSupportedError") return new PasskeyError("unsupported")
  return new PasskeyError("failed", e instanceof Error ? e.message : undefined)
}

type Descriptor = { type: "public-key"; id: string; transports?: string[] }

export interface CreationOptionsJSON {
  rp: { id: string; name: string }
  user: { id: string; name: string; displayName: string }
  challenge: string
  pubKeyCredParams: { type: "public-key"; alg: number }[]
  timeout: number
  attestation: AttestationConveyancePreference
  authenticatorSelection: AuthenticatorSelectionCriteria
  excludeCredentials: Descriptor[]
}

export interface RequestOptionsJSON {
  challenge: string
  rpId: string
  timeout: number
  userVerification: UserVerificationRequirement
  allowCredentials: Descriptor[]
}

const descriptor = (d: Descriptor): PublicKeyCredentialDescriptor => ({
  type: "public-key",
  id: fromBase64url(d.id),
  transports: d.transports as AuthenticatorTransport[] | undefined,
})

export interface RegistrationJSON {
  id: string
  raw_id: string
  type: "public-key"
  client_data_json: string
  attestation_object: string
  transports: string[]
}

export interface AssertionJSON {
  id: string
  raw_id: string
  type: "public-key"
  client_data_json: string
  authenticator_data: string
  signature: string
  user_handle: string | null
}

export async function createPasskey(o: CreationOptionsJSON, creds: CredentialsContainer = navigator.credentials): Promise<RegistrationJSON> {
  let cred: Credential | null
  try {
    cred = await creds.create({
      publicKey: {
        rp: o.rp,
        user: { id: fromBase64url(o.user.id), name: o.user.name, displayName: o.user.displayName },
        challenge: fromBase64url(o.challenge),
        pubKeyCredParams: o.pubKeyCredParams,
        timeout: o.timeout,
        attestation: o.attestation,
        authenticatorSelection: o.authenticatorSelection,
        excludeCredentials: o.excludeCredentials.map(descriptor),
      },
    })
  } catch (e) {
    throw mapError(e)
  }
  const pk = cred as PublicKeyCredential | null
  if (!pk || pk.type !== "public-key") throw new PasskeyError("failed")
  const res = pk.response as AuthenticatorAttestationResponse
  return {
    id: pk.id,
    raw_id: toBase64url(pk.rawId),
    type: "public-key",
    client_data_json: toBase64url(res.clientDataJSON),
    attestation_object: toBase64url(res.attestationObject),
    transports: typeof res.getTransports === "function" ? res.getTransports() : [],
  }
}

export async function getPasskey(o: RequestOptionsJSON, creds: CredentialsContainer = navigator.credentials): Promise<AssertionJSON> {
  let cred: Credential | null
  try {
    cred = await creds.get({
      publicKey: {
        challenge: fromBase64url(o.challenge),
        rpId: o.rpId,
        timeout: o.timeout,
        userVerification: o.userVerification,
        allowCredentials: o.allowCredentials.map(descriptor),
      },
    })
  } catch (e) {
    throw mapError(e)
  }
  const pk = cred as PublicKeyCredential | null
  if (!pk || pk.type !== "public-key") throw new PasskeyError("failed")
  const res = pk.response as AuthenticatorAssertionResponse
  return {
    id: pk.id,
    raw_id: toBase64url(pk.rawId),
    type: "public-key",
    client_data_json: toBase64url(res.clientDataJSON),
    authenticator_data: toBase64url(res.authenticatorData),
    signature: toBase64url(res.signature),
    user_handle: res.userHandle ? toBase64url(res.userHandle) : null,
  }
}
