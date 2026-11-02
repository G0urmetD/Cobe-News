import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { isBlocked, offKeys } from "@/lib/admin-api"

const REASONS = ["admin", "sync:no_team", "sync:teams_off", "sync:no_role", "sync:disabled", "sync:gone", "sync:unblocked", "sync:later", null]

describe("offKeys", () => {
  it("tells an admin's lasting block from the sync's reasons", () => {
    expect(offKeys("admin")).toEqual(["users.offAdmin", "users.offAdminHint"])
    expect(offKeys("sync:no_team")).toEqual(["users.offNoTeam", "users.offNoTeamHint"])
    expect(offKeys("sync:no_role")).toEqual(["users.offNoRole", "users.offNoRoleHint"])
    expect(offKeys("sync:unblocked")).toEqual(["users.offUnblocked", "users.offUnblockedHint"])
    expect(offKeys("sync:something_new")).toEqual(["users.offSync", "users.offSyncHint"])
    expect(offKeys(null)).toEqual(["users.off", undefined])
  })

  it("has every label and hint in German and English", () => {
    for (const r of REASONS) {
      for (const key of offKeys(r).filter((k): k is string => !!k)) {
        expect(de[key], key).toBeTruthy()
        expect(en[key], key).toBeTruthy()
      }
    }
  })
})

describe("isBlocked", () => {
  it("is the admin's block only, not the sync's off", () => {
    expect(isBlocked({ is_active: false, deactivated_reason: "admin" })).toBe(true)
    expect(isBlocked({ is_active: false, deactivated_reason: "sync:no_team" })).toBe(false)
    expect(isBlocked({ is_active: true, deactivated_reason: null })).toBe(false)
  })
})

describe("i18n", () => {
  it("has the block, re-check and switch-off texts in both languages", () => {
    const keys = (m: Record<string, string>) =>
      Object.keys(m).filter((k) => /^(users\.(off|block|unblock)|signin\.(map\.(impact|endHint|selfBlocked|removed)|off\.|endSessions|impact)|errors\.(own_|not_blocked))/.test(k))
    expect(keys(de).sort()).toEqual(keys(en).sort())
    expect(keys(de).length).toBeGreaterThan(40)
  })
})
