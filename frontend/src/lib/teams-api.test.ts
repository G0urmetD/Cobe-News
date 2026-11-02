import { afterEach, beforeEach, describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { PERSONAL_KINDS, groupStateKey, readScope, resolveScope, saveScope, upcoming, wayState } from "@/lib/teams-api"
import { followedCount, overviewKey, type VendorOverview } from "@/lib/vendor-api"

describe("groupStateKey", () => {
  it("names the missing Graph permission", () => {
    expect(groupStateKey({ state: "error", error: "forbidden", source: "entra" })).toBe("teams.group.err.graphGroupMember")
    expect(groupStateKey({ state: "error", error: "user_read", source: "entra" })).toBe("teams.group.err.graphUserRead")
    expect(groupStateKey({ state: "error", error: "forbidden", source: "ldap" })).toBe("teams.group.err.forbidden")
    expect(groupStateKey({ state: "error", error: "connection", source: "ldap" })).toBe("teams.group.err.other")
    expect(groupStateKey({ state: "ok", error: null, source: "ldap" })).toBe("teams.group.state.ok")
  })

  it("has a text in both languages for every state", () => {
    const keys = [
      groupStateKey({ state: "loading", error: null, source: "ldap" }),
      groupStateKey({ state: "waiting", error: null, source: "ldap" }),
      ...["forbidden", "user_read", "not_configured", "too_many", "not_found", "http"].map((e) => groupStateKey({ state: "error", error: e, source: "entra" })),
      "teams.group.err.forbidden",
    ]
    for (const k of keys) {
      expect(de[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
    }
    expect(de["teams.group.state.ok_other"] && en["teams.group.state.ok_one"]).toBeTruthy()
  })
})

describe("Teams strings", () => {
  it("are in German and English alike", () => {
    const mine = (o: Record<string, string>) => Object.keys(o).filter((k) => /^(teams\.|vendor\.scope\.|notify\.teams|users\.welcome)/.test(k))
    expect(mine(de).sort()).toEqual(mine(en).sort())
    expect(mine(de).length).toBeGreaterThan(50)
  })
})

describe("Mein Team / Alle", () => {
  // a real store for these tests (test-setup's stand-in remembers nothing)
  const real = globalThis.localStorage
  beforeEach(() => {
    const m = new Map<string, string>()
    Object.defineProperty(globalThis, "localStorage", {
      value: { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) },
      configurable: true,
      writable: true,
    })
  })
  afterEach(() => Object.defineProperty(globalThis, "localStorage", { value: real, configurable: true, writable: true }))

  it("is remembered per person in this browser – Mein Team until chosen otherwise", () => {
    expect(readScope("u1")).toBe("team")
    saveScope("u1", "all")
    expect(readScope("u1")).toBe("all")
    expect(readScope("u2")).toBe("team")
    expect(readScope(undefined)).toBe("all")
  })

  it("is not known while the teams load – so the full list never flashes up before Mein Team", () => {
    const team = { enabled: true, teams: [{ id: "t1", name: "Network" }] }
    expect(resolveScope(undefined, true, "team")).toBeNull()
    expect(resolveScope(undefined, true, "all")).toBeNull()
    expect(resolveScope(team, false, "team")).toBe("team")
    expect(resolveScope(team, false, "all")).toBe("all")
    expect(resolveScope({ enabled: true, teams: [] }, false, "team")).toBe("all") // in no team
    expect(resolveScope({ enabled: false, teams: team.teams }, false, "team")).toBe("all") // Teams off
    expect(resolveScope(undefined, false, "team")).toBe("all") // the teams could not be read
    // nothing is asked while unknown – and never under the key of the full list (a cached one would flash up)
    expect(overviewKey(null)).not.toEqual(overviewKey("all"))
    expect(overviewKey(null)).not.toEqual(overviewKey("team"))
  })

  it("takes the tab's number from the Mein-Team answer – no second request for the full list", () => {
    const answer = (items: number, more: Partial<VendorOverview>) =>
      ({ status: { enabled: true, last_ok_at: null, errors: 0, fetched: true }, items: Array(items).fill({}), ...more }) as VendorOverview
    expect(followedCount(answer(1, { team_scope: true, total: 7 }))).toBe(7)
    expect(followedCount(answer(7, { team_scope: false, total: 7 }))).toBe(7)
    expect(followedCount(answer(3, {}))).toBe(3) // an older server without `total`
    expect(followedCount(answer(1, { team_scope: true }))).toBeUndefined() // the team's list is not the number of all
    expect(followedCount(undefined)).toBeUndefined()
  })
})

describe("Hersteller-News meiner Produkte", () => {
  const none = { last_ok_at: null, last_error: null, last_error_at: null, next_try_at: null, failures: 0 }

  it("says the last outcome of a way: the newer of ok and error", () => {
    expect(wayState(none).tone).toBe("none")
    expect(wayState({ ...none, last_ok_at: "2026-10-30T10:00:00Z" })).toEqual({ tone: "ok", at: "2026-10-30T10:00:00Z", error: null })
    const failed = { ...none, last_ok_at: "2026-10-30T10:00:00Z", last_error: "refused", last_error_at: "2026-10-30T11:00:00Z", failures: 1 }
    expect(wayState(failed)).toEqual({ tone: "error", at: "2026-10-30T11:00:00Z", error: "refused" })
    // delivered again after the error: ok
    expect(wayState({ ...failed, last_ok_at: "2026-10-30T12:00:00Z", last_error: null }).tone).toBe("ok")
  })

  it("shows a next try only while it is ahead", () => {
    const now = Date.parse("2026-10-30T12:00:00Z")
    expect(upcoming("2026-10-30T12:05:00Z", now)).toBe(true)
    expect(upcoming("2026-10-30T11:55:00Z", now)).toBe(false)
    expect(upcoming(null, now)).toBe(false)
  })

  it("has every string in German and English, with the error texts the state can show", () => {
    const mine = (o: Record<string, string>) => Object.keys(o).filter((k) => /^(personal\.|teams\.personal\.|teams\.routing\.|teams\.members\.gets)/.test(k))
    expect(mine(de).sort()).toEqual(mine(en).sort())
    for (const k of [
      "notify.err.no_address",
      "notify.err.no_device",
      "notify.err.interrupted",
      "glossary.webhook",
      "glossary.webhookText",
      "errors.not_member",
      "errors.way_off",
      "errors.teams_url_host_not_allowed",
      "errors.teams_url_forbidden_target",
      "errors.teams_url_invalid_url",
      "errors.teams_url_required",
      ...PERSONAL_KINDS.map((x) => `personal.kind.${x}`),
    ]) {
      expect(de[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
    }
    // plain words: the warning for an empty choice says what happens
    expect(de["teams.routing.nobody"]).toBe("Niemand bekommt die News zu diesem Produkt.")
  })
})
