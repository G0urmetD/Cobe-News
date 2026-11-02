import { describe, expect, it } from "vitest"
import { PasskeyError, createPasskey, fromBase64url, getPasskey, passkeySupport, toBase64url } from "@/lib/webauthn"

const bytes = (...b: number[]) => new Uint8Array(b)

describe("base64url", () => {
  it("round-trips without padding and with the URL alphabet", () => {
    for (let n = 0; n < 40; n++) {
      const b = new Uint8Array(n).map((_, i) => (i * 37 + n) & 0xff)
      const s = toBase64url(b)
      expect(s).toMatch(/^[A-Za-z0-9_-]*$/)
      expect(Array.from(fromBase64url(s))).toEqual(Array.from(b))
    }
    expect(toBase64url(bytes(0xfb, 0xff, 0xbf))).toBe("-_-_")
    expect(toBase64url(bytes(0))).toBe("AA")
    expect(toBase64url(bytes(1, 2, 3, 4).buffer)).toBe("AQIDBA")
    expect(toBase64url(new Uint8Array([9, 1, 2, 3]).subarray(1))).toBe("AQID") // a view: only its own bytes
  })

  it("refuses anything that is not base64url", () => {
    for (const bad of ["AA==", "A", "a+b/", "AA AA", "ä"]) expect(() => fromBase64url(bad)).toThrow(PasskeyError)
  })
})

describe("passkeySupport", () => {
  const win = (over: Partial<{ isSecureContext: boolean; origin: string; pkc: unknown }> = {}) => ({
    isSecureContext: over.isSecureContext ?? true,
    location: { origin: over.origin ?? "https://news.corp.example" } as Location,
    PublicKeyCredential: "pkc" in over ? over.pkc : function PublicKeyCredential() {},
  })
  it("needs a secure context, WebAuthn and the configured address", () => {
    Object.defineProperty(navigator, "credentials", { value: {}, configurable: true })
    expect(passkeySupport("https://news.corp.example", win())).toBe("ok")
    expect(passkeySupport("https://news.corp.example", win({ isSecureContext: false }))).toBe("insecure")
    expect(passkeySupport("https://news.corp.example", win({ pkc: undefined }))).toBe("unsupported")
    expect(passkeySupport("https://news.corp.example", win({ origin: "https://192.0.2.10" }))).toBe("origin")
  })
})

function fakeCreds(result: unknown, fail?: string): CredentialsContainer & { seen: unknown[] } {
  const seen: unknown[] = []
  const answer = async (o: unknown) => {
    seen.push(o)
    if (fail) throw Object.assign(new Error(fail), { name: fail })
    return result
  }
  return { create: answer, get: answer, seen } as unknown as CredentialsContainer & { seen: unknown[] }
}

describe("create and get", () => {
  const creation = {
    rp: { id: "news.corp.example", name: "Cobe News" },
    user: { id: "AQID", name: "rudi", displayName: "Rudi" },
    challenge: "BAUG",
    pubKeyCredParams: [{ type: "public-key" as const, alg: -7 }],
    timeout: 120000,
    attestation: "none" as const,
    authenticatorSelection: { residentKey: "required" as const, requireResidentKey: true, userVerification: "required" as const },
    excludeCredentials: [{ type: "public-key" as const, id: "CQo", transports: ["internal"] }],
  }

  it("turns the options into bytes and the answer into base64url", async () => {
    const creds = fakeCreds({
      id: "Bwg",
      type: "public-key",
      rawId: bytes(7, 8).buffer,
      response: { clientDataJSON: bytes(1).buffer, attestationObject: bytes(2).buffer, getTransports: () => ["internal"] },
    })
    const out = await createPasskey(creation, creds)
    expect(out).toEqual({ id: "Bwg", raw_id: "Bwg", type: "public-key", client_data_json: "AQ", attestation_object: "Ag", transports: ["internal"] })
    const asked = (creds.seen[0] as { publicKey: PublicKeyCredentialCreationOptions }).publicKey
    expect(Array.from(asked.challenge as Uint8Array)).toEqual([4, 5, 6])
    expect(Array.from(asked.user.id as Uint8Array)).toEqual([1, 2, 3])
    expect(Array.from(asked.excludeCredentials![0].id as Uint8Array)).toEqual([9, 10])

    const got = fakeCreds({
      id: "Bwg",
      type: "public-key",
      rawId: bytes(7, 8).buffer,
      response: { clientDataJSON: bytes(1).buffer, authenticatorData: bytes(2).buffer, signature: bytes(3).buffer, userHandle: null },
    })
    const a = await getPasskey({ challenge: "BAUG", rpId: "news.corp.example", timeout: 1, userVerification: "required", allowCredentials: [] }, got)
    expect(a).toEqual({ id: "Bwg", raw_id: "Bwg", type: "public-key", client_data_json: "AQ", authenticator_data: "Ag", signature: "Aw", user_handle: null })
  })

  it("explains the browser's refusals", async () => {
    const codes: Record<string, string> = {
      NotAllowedError: "cancelled",
      AbortError: "cancelled",
      InvalidStateError: "exists",
      SecurityError: "origin",
      NotSupportedError: "unsupported",
      TypeError: "failed",
    }
    for (const [name, code] of Object.entries(codes)) {
      await expect(createPasskey(creation, fakeCreds(null, name))).rejects.toMatchObject({ code })
    }
    await expect(createPasskey(creation, fakeCreds(null))).rejects.toMatchObject({ code: "failed" })
  })
})
