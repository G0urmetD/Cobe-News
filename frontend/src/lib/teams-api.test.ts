import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { QueryClient } from "@tanstack/react-query"
import de from "@/i18n/de"
import en from "@/i18n/en"
import {
  PERSONAL_KEY,
  PERSONAL_KINDS,
  type Team,
  type TeamProduct,
  groupStateKey,
  productsSave,
  readScope,
  refreshTeams,
  resolveScope,
  saveScope,
  teamSheet,
  upcoming,
  wayState,
} from "@/lib/teams-api"
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

describe("after a change of the teams", () => {
  it("asks the personal notifications and Mein Team again – not 30 s on what was before", () => {
    const qc = new QueryClient()
    const keys = [PERSONAL_KEY, ["me", "teams"], ["admin", "teams", "list"], ["vendor", "overview", "team"]] as const
    for (const k of keys) qc.setQueryData([...k], {})
    qc.setQueryData(["vendor", "overview"], {})
    refreshTeams(qc)
    for (const k of keys) expect(qc.getQueryState([...k])?.isInvalidated, k.join("/")).toBe(true)
    // the full list does not depend on the teams
    expect(qc.getQueryState(["vendor", "overview"])?.isInvalidated).toBe(false)
  })
})

describe("the team sheet for ?team=", () => {
  const team = { id: "t1", name: "Net" } as Team
  it("shows the team, the form for a new one, or nothing", () => {
    expect(teamSheet(null, [team], false)).toEqual({ kind: "none" })
    expect(teamSheet("new", [], false)).toEqual({ kind: "new" })
    expect(teamSheet("t1", [team], true)).toEqual({ kind: "team", team })
  })
  it("says 'nicht gefunden' for a deleted team once the list is fresh – no spinner without end", () => {
    expect(teamSheet("gone", [team], false)).toEqual({ kind: "missing" })
    // the list is being asked again (a team just created): a short wait, not "nicht gefunden"
    expect(teamSheet("gone", [team], true)).toEqual({ kind: "loading" })
    for (const k of ["teams.notFoundTitle", "teams.notFoundText", "teams.backToList", "teams.routing.loadFailed", "errors.retry"]) {
      expect(de[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
    }
  })
})

describe("saving the products part", () => {
  const anja = { id: "u1", username: "anja", display_name: "Anja" }
  const stored = [{ key: "panos", label: "PAN-OS", enabled: true, all_members: true, people: [] }] as TeamProduct[]
  it("is one request: the products with every changed routing, a new product's too", () => {
    const x = productsSave(["panos", "fortios"], { panos: { all: false, people: [anja] }, fortios: { all: false, people: [anja] } }, stored)
    expect(x.dirty).toBe(true)
    expect(x.body).toEqual({
      products: ["panos", "fortios"],
      routing: [
        { product: "panos", all_members: false, members: ["u1"] },
        { product: "fortios", all_members: false, members: ["u1"] },
      ],
    })
  })
  it("sends no routing that did not change, and is not dirty without a change", () => {
    expect(productsSave(["panos"], { panos: { all: true, people: [] } }, stored)).toEqual({ dirty: false, body: { products: ["panos"], routing: [] } })
    // a new product for all members: only the product
    expect(productsSave(["panos", "fortios"], {}, stored)).toEqual({ dirty: true, body: { products: ["panos", "fortios"], routing: [] } })
    // a removed product's routing is not sent
    expect(productsSave([], { panos: { all: false, people: [anja] } }, stored).body).toEqual({ products: [], routing: [] })
  })
})
