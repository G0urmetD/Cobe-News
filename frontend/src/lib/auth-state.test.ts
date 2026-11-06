import { describe, expect, it } from "vitest"
import type { ApiUser, AuthConfig } from "@/lib/api"
import { authReducer, clearUserStorage, initialAuth, userStorageKeys } from "@/lib/auth-state"

const config: AuthConfig = { setup_required: false, ldap_enabled: false, entra_enabled: false }
const user = { id: "u1", username: "anna", display_name: "Anna", email: null, role: "reader", auth_source: "local", totp: true, is_emergency: false } as ApiUser

describe("sign-in state", () => {
  it("resumes an interrupted step after a reload", () => {
    const s = authReducer(initialAuth, { type: "loaded", config, stage: "mfa" })
    expect(s).toMatchObject({ loading: false, failed: false, stage: "mfa", user: null })
  })

  it("forgets the resumed step once signed in, signed out or expired", () => {
    const mfa = authReducer(initialAuth, { type: "loaded", config, stage: "enroll" })
    const inside = authReducer(mfa, { type: "user", user })
    expect(inside).toMatchObject({ user, stage: null })
    expect(authReducer(mfa, { type: "signedOut" })).toMatchObject({ user: null, stage: null })
  })

  it("an unreachable server is an error, not the sign-in form", () => {
    expect(authReducer(initialAuth, { type: "failed" })).toMatchObject({ loading: false, failed: true })
    // the reason stays for the page to say (0.1.51: "the server cannot reach its database" instead of "failed")
    const why = new Error("503")
    expect(authReducer(initialAuth, { type: "failed", error: why }).error).toBe(why)
  })

  it("only an active session counts as signed in", () => {
    expect(authReducer(initialAuth, { type: "loaded", config, stage: "active", user }).user).toEqual(user)
    expect(authReducer(initialAuth, { type: "loaded", config, stage: "bogus", user }).stage).toBeNull()
  })

  it("clears this person's keys at sign-out", () => {
    const removed: string[] = []
    clearUserStorage("u1", { removeItem: (k: string) => void removed.push(k) })
    expect(removed).toEqual(userStorageKeys("u1"))
    clearUserStorage(undefined, { removeItem: () => removed.push("x") })
    expect(removed).not.toContain("x")
  })
})
