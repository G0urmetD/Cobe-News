import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { approvalBody, isBlocked, isPending, offKeys, pendingTotal } from "@/lib/admin-api"

const REASONS = ["admin", "pending", "sync:no_team", "sync:teams_off", "sync:no_role", "sync:disabled", "sync:gone", "sync:unblocked", "sync:later", null]

describe("offKeys", () => {
  it("tells an admin's lasting block from the sync's reasons", () => {
    expect(offKeys("admin")).toEqual(["users.offAdmin", "users.offAdminHint"])
    expect(offKeys("sync:no_team")).toEqual(["users.offNoTeam", "users.offNoTeamHint"])
    expect(offKeys("sync:no_role")).toEqual(["users.offNoRole", "users.offNoRoleHint"])
    expect(offKeys("sync:unblocked")).toEqual(["users.offUnblocked", "users.offUnblockedHint"])
    expect(offKeys("pending")).toEqual(["users.offPending", "users.offPendingHint"])
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

describe("approval", () => {
  it("is waiting only while off for that reason – never an admin's block or the sync's off", () => {
    expect(isPending({ is_active: false, deactivated_reason: "pending" })).toBe(true)
    expect(isPending({ is_active: true, deactivated_reason: "pending" })).toBe(false)
    expect(isPending({ is_active: false, deactivated_reason: "admin" })).toBe(false)
    expect(isPending({ is_active: false, deactivated_reason: "sync:no_role" })).toBe(false)
    expect(isBlocked({ is_active: false, deactivated_reason: "pending" })).toBe(false)
  })
  it("counts accounts and raises on the badge", () => {
    expect(pendingTotal(undefined)).toBe(0)
    expect(pendingTotal({ accounts: 2, accounts_admin: 1, raises: 3 })).toBe(5)
  })
  it('sends the numbers the dialog showed with "approve all" – and only then', () => {
    const shown = { auto_signin: false, rev: 4, active_directory: 9, accounts: 2, accounts_admin: 1, raises: 3 }
    expect(approvalBody(shown, true, true)).toEqual({ auto_signin: true, approve_pending: true, expect: { accounts: 2, accounts_admin: 1, raises: 3 }, rev: 4 })
    expect(approvalBody(shown, true, false)).toEqual({ auto_signin: true, approve_pending: false, rev: 4 })
    expect(de["signin.approval.staleCounts"]).toBeTruthy()
    expect(en["signin.approval.staleCounts"]).toBeTruthy()
    expect(de["errors.approve_needs_counts"]).toBeTruthy()
    expect(en["errors.approve_needs_counts"]).toBeTruthy()
  })
  it("has the approval texts in German and English", () => {
    const keys = [
      "users.pendingBadge_one",
      "users.pendingBadge_other",
      "users.approve",
      "users.decline",
      "users.raisePending",
      "users.keepReader",
      "users.filterWaiting",
      "errors.approval_pending",
      "errors.directory_pending",
      "signin.approval.auto",
      "signin.approval.approveAll",
    ]
    for (const k of keys) {
      expect(de[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
    }
    expect(de["errors.approval_pending"]).toBe("Konto wartet auf Freigabe durch einen Admin.")
    expect(en["signin.approval.auto"]).toBe("Allow automatic sign-in via AD/Entra ID")
  })
})
