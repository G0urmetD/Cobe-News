import { describe, expect, it } from "vitest"
import { REMEMBER_DAYS, mfaBody, rememberInfo } from "@/lib/remember-device"

describe("remember the second factor on this device", () => {
  it("offers the switch only when the server says so", () => {
    expect(rememberInfo({ stage: "mfa" })).toBeNull() // the admin switch off: no "remember" in the state
    expect(rememberInfo(null)).toBeNull()
    expect(rememberInfo({ stage: "mfa", remember: { offer: false, until: null, device: false } })).toBeNull()
    expect(rememberInfo({ stage: "mfa", remember: { offer: true, until: "2026-11-11T08:00:00+00:00", device: false } })).toEqual({
      offer: true,
      until: "2026-11-11T08:00:00+00:00",
      device: false,
    })
    expect(rememberInfo({ remember: { offer: true, until: 5, device: "yes" } })).toEqual({ offer: true, until: null, device: false })
  })

  it("sends remember only when offered and switched on", () => {
    const info = { offer: true, until: null, device: false }
    expect(mfaBody("123456", true, info)).toEqual({ code: "123456", remember: true })
    expect(mfaBody("123456", false, info)).toEqual({ code: "123456" })
    expect(mfaBody("123456", true, null)).toEqual({ code: "123456" })
  })

  it("keeps the durations bounded (at most 30 days)", () => {
    expect([...REMEMBER_DAYS]).toEqual([0, 1, 7, 30])
    expect(Math.max(...REMEMBER_DAYS)).toBeLessThanOrEqual(30)
  })
})
