import { describe, expect, it } from "vitest"
import type { TFunction } from "i18next"
import de from "@/i18n/de"
import en from "@/i18n/en"
import activityPy from "../../../backend/app/activity_api.py?raw"
import { ACTIVITY_ACTIONS, activityView, anyWaiting, auditLink, PENDING_LINK, SIGNIN, type ActivityItem } from "@/lib/activity"
import { linkFilters, NO_FILTERS } from "@/lib/audit"

// a t() over one bundle, with i18next's defaultValue, plural (_one/_other) and {{x}} interpolation
const tOf =
  (bundle: Record<string, string>) =>
  (key: string, opts?: Record<string, unknown>): string => {
    const plural = typeof opts?.count === "number" ? bundle[`${key}_${opts.count === 1 ? "one" : "other"}`] : undefined
    const raw = bundle[key] ?? plural ?? (opts?.defaultValue as string | undefined) ?? key
    return raw.replace(/\{\{(\w+)\}\}/g, (_, k: string) => String(opts?.[k] ?? ""))
  }
const t = tOf(de) as unknown as TFunction
const tEn = tOf(en) as unknown as TFunction

const ben = { kind: "user" as const, id: "11111111-1111-4111-8111-111111111111", name: "ben", display: "Ben Bauer" }
const carla = { type: "user", id: "22222222-2222-4222-8222-222222222222", label: "carla", display: "Carla Clausen" }
const item = (o: Partial<ActivityItem>): ActivityItem => ({
  id: "a1",
  entry: 1,
  action: "catalog.followed",
  at: "2026-11-06T08:00:00+00:00",
  actor: ben,
  target: null,
  details: {},
  ...o,
})

describe("texts", () => {
  it("knows the server's actions", () => {
    const m = /ACTIONS: tuple\[str, \.\.\.\] = \(([\s\S]*?)\n\)/.exec(activityPy)
    expect(m, "activity_api.ACTIONS").toBeTruthy()
    const server = [...m![1].matchAll(/"([a-z_.]+)"/g)].map((x) => x[1])
    expect([...ACTIVITY_ACTIONS].sort()).toEqual(server.sort())
  })
  it("has the same activity keys in German and English, and a text for every action", () => {
    const of = (b: Record<string, string>) =>
      Object.keys(b)
        .filter((k) => k.startsWith("activity."))
        .sort()
    expect(of(en)).toEqual(of(de))
    for (const a of ACTIVITY_ACTIONS) {
      expect(de[`activity.text.${a}`], `de ${a}`).toBeTruthy()
      expect(en[`activity.text.${a}`], `en ${a}`).toBeTruthy()
    }
  })
})

describe("activityView", () => {
  it("says who signed in, a joined line with how many others", () => {
    const one = item({ id: "s1", entry: null, action: SIGNIN, actor: { ...ben, role: "reader" }, others: 0, names: ["Ben Bauer"] })
    expect(activityView(t, one)).toMatchObject({ text: "Ben Bauer hat sich angemeldet", icon: "signin", to: "/settings/users", urgent: false })
    expect(activityView(tEn, one).text).toBe("Ben Bauer signed in")
    const run = { ...one, others: 2, names: ["Ben Bauer", "Ali", "Bea"] }
    expect(activityView(t, run)).toMatchObject({ text: "Ben Bauer und 2 weitere haben sich angemeldet", title: "Ben Bauer, Ali, Bea" })
    expect(activityView(t, { ...run, others: 1, names: ["Ben Bauer", "Ali"] }).text).toBe("Ben Bauer und eine weitere Person haben sich angemeldet")
    expect(activityView(t, { ...run, others: 24, others_more: true }).text).toBe("Ben Bauer und mehr als 24 weitere haben sich angemeldet")
    expect(activityView(t, { ...run, others: 24, others_more: true }).title).toBe("Ben Bauer, Ali, Bea …")
    // an admin's single sign-in is in the Protokoll
    expect(activityView(t, { ...one, actor: { ...ben, role: "admin" } }).to).toBe(`/settings/audit?action=login.success&actor=${ben.id}&who=Ben+Bauer`)
  })
  it("names the product followed or added and leads to it", () => {
    const f = item({ target: { type: "product", id: "fortinet-fortios", label: "Fortinet FortiOS" } })
    expect(activityView(t, f)).toMatchObject({ text: "Ben Bauer folgt jetzt Fortinet FortiOS", icon: "followed", to: "/vendor?product=fortinet-fortios" })
    expect(activityView(tEn, f).text).toBe("Ben Bauer now follows Fortinet FortiOS")
    const c = item({ action: "catalog.custom_added", target: { type: "product", id: "custom-1", label: "Acme Gateway" } })
    expect(activityView(t, c)).toMatchObject({ text: "Ben Bauer hat Acme Gateway zu Vendor News hinzugefügt", icon: "product" })
  })
  it("lets a pending approval stand out and leads to the accounts", () => {
    const p = item({ action: "user.approval_pending", actor: { kind: "user", id: carla.id, name: "carla", display: "Carla Clausen" }, target: carla })
    expect(activityView(t, p)).toMatchObject({ text: "Carla Clausen wartet auf Freigabe", icon: "pending", urgent: true, to: PENDING_LINK })
    expect(activityView(tEn, p).text).toBe("Carla Clausen is waiting for approval")
    const r = item({ action: "role.approval_pending", actor: { kind: "sync", id: null, name: "directory-sync", display: "" }, target: carla, details: { role: "admin" } })
    expect(activityView(t, r)).toMatchObject({ text: "Carla Clausen wartet auf Freigabe als Admin", urgent: true })
    expect(activityView(t, { ...r, details: {} }).text).toBe("Carla Clausen wartet auf Freigabe einer Rolle")
  })
  it("no longer stands out once the approval is dealt with – the bell follows what waits now", () => {
    const p = item({ entry: 7, action: "user.approval_pending", target: carla, open: false })
    expect(activityView(t, p)).toMatchObject({ text: "Carla Clausen wartete auf Freigabe (erledigt)", urgent: false })
    expect(activityView(t, p).to).toBe(`/settings/audit?action=user.approval_pending&target_type=user&target_id=${carla.id}&what=Carla+Clausen&open=7`)
    expect(activityView(tEn, p).text).toBe("Carla Clausen waited for approval (dealt with)")
    const r = item({ action: "role.approval_pending", target: carla, details: { role: "admin" }, open: false })
    expect(activityView(t, r)).toMatchObject({ text: "Carla Clausen wartete auf Freigabe als Admin (erledigt)", urgent: false })
    // the dot: what waits now, also when its line is pushed out of the newest three – and not for a line dealt with
    expect(anyWaiting({ items: [p], pending: 0 })).toBe(false)
    expect(anyWaiting({ items: [item({})], pending: 2 })).toBe(true)
    // an older server without the count: the lines as before
    expect(anyWaiting({ items: [{ ...p, open: undefined }] })).toBe(true)
  })
  it("renders the decisions on approvals", () => {
    const base = { target: carla }
    expect(activityView(t, item({ ...base, action: "user.approved" }))).toMatchObject({ text: "Ben Bauer hat Carla Clausen freigegeben", icon: "approved", urgent: false })
    expect(activityView(t, item({ ...base, action: "user.declined" })).text).toBe("Ben Bauer hat Carla Clausen abgelehnt")
    expect(activityView(t, item({ ...base, action: "role.approved", details: { role: "admin" } })).text).toBe("Ben Bauer hat Carla Clausen als Admin freigegeben")
    expect(activityView(tEn, item({ ...base, action: "role.approved" })).text).toBe("Ben Bauer approved the role of Carla Clausen")
    expect(activityView(t, item({ ...base, action: "role.declined" })).text).toBe("Ben Bauer hat den Aufstieg von Carla Clausen abgelehnt")
    expect(activityView(tEn, item({ ...base, action: "role.declined" })).text).toBe("Ben Bauer declined the raise of Carla Clausen")
    expect(activityView(t, item({ ...base, action: "role.declined" })).icon).toBe("declined")
  })
  it("says the directory's doings without a name", () => {
    const sync = { kind: "sync" as const, id: null, name: "directory-sync", display: "" }
    expect(activityView(t, item({ action: "user.created", actor: sync, target: carla, details: { why: "signin" } })).text).toBe("Carla Clausen ist neu (erste Anmeldung)")
    expect(activityView(t, item({ action: "user.created", target: carla })).text).toBe("Ben Bauer hat Carla Clausen angelegt")
    expect(activityView(t, item({ action: "user.deactivated", actor: sync, target: carla })).text).toBe("Carla Clausen wurde deaktiviert (Verzeichnis)")
    expect(activityView(t, item({ action: "role.changed", target: carla, details: { role: "admin" } })).text).toBe("Ben Bauer hat Carla Clausen zum Admin gemacht")
    expect(activityView(t, item({ action: "role.changed", actor: sync, target: carla, details: { role: "reader" } })).text).toBe("Carla Clausen ist jetzt Leser (Verzeichnis)")
    expect(
      activityView(t, item({ action: "backup.restored", actor: { kind: "cli", id: null, name: "cli", display: "" }, target: { type: "backup", id: "b.tar", label: "b.tar" } }))
        .text,
    ).toBe("Sicherung b.tar wiederhergestellt")
  })
  it("shows an action it has no text for by the Protokoll's word", () => {
    expect(activityView(t, item({ action: "token.created" })).text).toBe("Ben Bauer: API-Token erstellt")
    expect(activityView(t, item({ action: "future.thing" }))).toMatchObject({ text: "Ben Bauer: future.thing", icon: "other" })
  })
})

describe("links into the Protokoll", () => {
  it("filters to the entry's action and target and opens it – and reads back", () => {
    const e = item({ entry: 42, action: "user.approved", target: carla })
    const to = auditLink(e)
    expect(to).toBe(`/settings/audit?action=user.approved&target_type=user&target_id=${carla.id}&what=Carla+Clausen&open=42`)
    const back = linkFilters(new URLSearchParams(to.split("?")[1]), ACTIVITY_ACTIONS)
    expect(back.open).toBe(42)
    expect(back.filters).toEqual({ ...NO_FILTERS, action: "user.approved", targetType: "user", targetId: carla.id, targetLabel: "Carla Clausen" })
  })
  it("takes nothing a crafted link gets wrong", () => {
    const got = linkFilters(new URLSearchParams("action=drop.table&actor=nobody&target_type=Robert');&open=-3"))
    expect(got).toEqual({ filters: NO_FILTERS, open: null })
    expect(linkFilters(new URLSearchParams("actor=sync&open=7")).filters.actor).toBe("sync")
    expect(linkFilters(new URLSearchParams(`action=${"a".repeat(100)}`)).filters.action).toBe("")
  })
})
