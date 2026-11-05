import { describe, expect, it } from "vitest"
import type { TFunction } from "i18next"
import de from "@/i18n/de"
import en from "@/i18n/en"
import {
  actionText,
  actorText,
  ALL_ACTIONS,
  ANOMALIES,
  AUDIT_GROUPS,
  browserText,
  chainOf,
  chainText,
  detailRows,
  entryJson,
  exportPath,
  fieldText,
  filterParams,
  fmtField,
  fmtValue,
  GROUP_KEYS,
  groupOf,
  hasValueFilters,
  isFiltered,
  methodText,
  NO_FILTERS,
  SETTINGS_SECTIONS,
  settingsPath,
  SIGNIN_SECTIONS,
  targetLink,
  targetText,
  valueChips,
  withoutChip,
} from "@/lib/audit"

// a t() over one bundle, with i18next's defaultValue and {{x}} interpolation
const tOf =
  (bundle: Record<string, string>) =>
  (key: string, opts?: Record<string, unknown>): string => {
    const plural = typeof opts?.count === "number" ? bundle[`${key}_${opts.count === 1 ? "one" : "other"}`] : undefined
    const raw = bundle[key] ?? plural ?? (opts?.defaultValue as string | undefined) ?? key
    return raw.replace(/\{\{(\w+)\}\}/g, (_, k: string) => String(opts?.[k] ?? ""))
  }
const t = tOf(de) as unknown as TFunction
const tEn = tOf(en) as unknown as TFunction

describe("texts", () => {
  it("has a text for every action, group, actor kind and the nav entry in both languages", () => {
    const keys = [
      "settings.nav.audit",
      ...ALL_ACTIONS.map((a) => `audit.action.${a}`),
      ...[...GROUP_KEYS, "other"].map((g) => `audit.group.${g}`),
      ...["user", "system", "sync", "cli"].map((k) => `audit.actor.${k}`),
    ]
    for (const k of keys) {
      expect(de[k], `de: ${k}`).toBeTruthy()
      expect(en[k], `en: ${k}`).toBeTruthy()
    }
  })
  it("has the same audit keys in German and English", () => {
    const of = (b: Record<string, string>) =>
      Object.keys(b)
        .filter((k) => k.startsWith("audit."))
        .sort()
    expect(of(en)).toEqual(of(de))
  })
  it("names each action once", () => {
    expect(new Set(ALL_ACTIONS).size).toBe(ALL_ACTIONS.length)
  })
  it("shows an unknown action by its key", () => {
    expect(actionText(t, "role.changed")).toBe("Rolle geändert")
    expect(actionText(tEn, "role.changed")).toBe("Role changed")
    expect(actionText(t, "future.thing")).toBe("future.thing")
  })
})

describe("groupOf", () => {
  it("finds the group, other for an unknown action", () => {
    expect(groupOf("token.revoked")).toBe("tokens")
    expect(groupOf("login.locked")).toBe("signin")
    expect(groupOf("nope")).toBe("other")
    for (const g of GROUP_KEYS) for (const a of AUDIT_GROUPS[g]) expect(groupOf(a)).toBe(g)
  })
})

describe("actor and target", () => {
  it("names accounts by display name and login, the others by their kind", () => {
    expect(actorText(t, { kind: "user", id: "1", name: "anna", display: "Anna Admin" })).toBe("Anna Admin (anna)")
    expect(actorText(t, { kind: "user", id: "1", name: "anna", display: "anna" })).toBe("anna")
    expect(actorText(t, { kind: "sync", id: null, name: "directory-sync", display: "" })).toBe("Verzeichnis-Sync")
    expect(actorText(tEn, { kind: "cli", id: null, name: "cli", display: "" })).toBe("Command line")
  })
  it("shows the target's kind and its name then", () => {
    expect(targetText(t, null)).toBe("—")
    expect(targetText(t, { type: "channel", id: "x", label: "SOC Slack" })).toBe("Kanal · SOC Slack")
    expect(targetText(t, { type: "backup", id: null, label: null })).toBe("Sicherung")
    expect(targetText(t, { type: "settings", id: "smtp", label: null })).toBe("Einstellungen · smtp")
  })
})

describe("detailRows", () => {
  it("turns before/after into rows, a secret into a changed-only row", () => {
    const { changes, info } = detailRows({
      changes: { host: { from: "", to: "mail.corp.example" }, password: { secret: true, changed: true }, url: { changed: true } },
      sessions_ended: true,
    })
    expect(changes).toEqual([
      { field: "host", from: "", to: "mail.corp.example", secret: false, changedOnly: false },
      { field: "password", from: null, to: null, secret: true, changedOnly: false },
      { field: "url", from: null, to: null, secret: false, changedOnly: true },
    ])
    expect(info).toEqual([{ field: "sessions_ended", value: true }])
  })
  it("copes with no or odd details", () => {
    expect(detailRows(undefined)).toEqual({ changes: [], info: [] })
    expect(detailRows({ changes: ["x"] }).changes).toEqual([])
  })
})

describe("fmtValue", () => {
  it("formats nothing, flags, lists, secrets and objects", () => {
    expect(fmtValue(t, null)).toBe("—")
    expect(fmtValue(t, "")).toBe("—")
    expect(fmtValue(t, true)).toBe("ja")
    expect(fmtValue(tEn, false)).toBe("no")
    expect(fmtValue(t, ["critical", "high"])).toBe("critical, high")
    expect(fmtValue(t, [])).toBe("—")
    expect(fmtValue(t, { secret: true, changed: true })).toBe("•••")
    expect(fmtValue(t, { a: 1 })).toBe('{"a":1}')
    expect(fmtValue(t, 365)).toBe("365")
  })
  it("names known fields, others as stored", () => {
    expect(fieldText(t, "bind_password")).toBe("Bind-Passwort")
    expect(fieldText(tEn, "secret.url")).toBe("Webhook address")
    expect(fieldText(t, "config.header_name")).toBe("Header-Name")
    expect(fieldText(t, "config.future_field")).toBe("config.future_field")
  })
  it("formats sizes, durations, numbers and known values for their field", () => {
    expect(fmtField(t, "size", 35942400, "de")).toBe("35,9 MB")
    expect(fmtField(t, "was_locked_s", 900, "de")).toBe("15 min")
    expect(fmtField(tEn, "blocked_for_s", 7200, "en")).toBe("2 h")
    expect(fmtField(t, "rows", 477188, "de")).toBe("477.188")
    expect(fmtField(tEn, "rows", 477188, "en")).toBe("477,188")
    expect(fmtField(t, "reason", "manual")).toBe("von Hand")
    expect(fmtField(t, "trigger", "cli")).toBe("Kommandozeile")
    expect(fmtField(t, "outcome", "failed")).toBe("fehlgeschlagen")
    expect(fmtField(t, "reason", "something-new")).toBe("something-new")
    expect(fmtField(t, "scopes", ["read", "metrics"])).toBe("read, metrics")
    expect(fmtField(t, "encrypted", true)).toBe("ja")
  })
})

describe("filters", () => {
  it("leaves empty filters out and takes the 'to' day whole, in local time", () => {
    expect(isFiltered(NO_FILTERS)).toBe(false)
    expect(filterParams(NO_FILTERS).toString()).toBe("")
    const p = filterParams({ ...NO_FILTERS, group: "tokens", actor: "sync", from: "2026-10-01", to: "2026-10-31", q: "  anna " })
    expect(p.get("group")).toBe("tokens")
    expect(p.get("actor")).toBe("sync")
    expect(p.get("q")).toBe("anna")
    expect(new Date(p.get("since")!).getTime()).toBe(new Date(2026, 9, 1).getTime())
    expect(new Date(p.get("until")!).getTime()).toBe(new Date(2026, 10, 1).getTime())
    expect(filterParams({ ...NO_FILTERS, from: "kaputt" }).has("since")).toBe(false)
    expect(isFiltered({ ...NO_FILTERS, q: "x" })).toBe(true)
  })
  it("builds the export address with the same filters – and the delimiter of the reader's language", () => {
    expect(exportPath(NO_FILTERS)).toBe("/api/admin/audit/export")
    expect(exportPath({ ...NO_FILTERS, group: "backup" })).toBe("/api/admin/audit/export?group=backup")
    expect(exportPath({ ...NO_FILTERS, group: "backup" }, "de")).toBe("/api/admin/audit/export?group=backup&delimiter=semicolon")
    expect(exportPath(NO_FILTERS, "en-GB")).toBe("/api/admin/audit/export")
  })
  it("turns a preset range into a time from now and drops the days then", () => {
    const now = Date.UTC(2026, 10, 4, 12, 0, 0)
    const p = filterParams({ ...NO_FILTERS, range: "7d", from: "2026-01-01", to: "2026-01-02" }, now)
    expect(p.get("since")).toBe(new Date(now - 7 * 864e5).toISOString())
    expect(p.has("until")).toBe(false)
    expect(isFiltered({ ...NO_FILTERS, range: "24h" })).toBe(true)
  })
  it("sends the value filters and the notable switch", () => {
    const p = filterParams({ ...NO_FILTERS, notable: true, ip: "192.0.2.1", session: "abc", action: "role.changed", targetType: "team", targetId: "t1", targetLabel: "Netz" })
    expect(p.toString()).toBe("notable=1&ip=192.0.2.1&session=abc&action=role.changed&target_type=team&target_id=t1")
    expect(hasValueFilters(NO_FILTERS)).toBe(false)
    expect(hasValueFilters({ ...NO_FILTERS, notable: true })).toBe(false)
    expect(hasValueFilters({ ...NO_FILTERS, ip: "x" })).toBe(true)
  })
})

describe("chips", () => {
  it("names each value filter and removes it with its label", () => {
    const f = {
      ...NO_FILTERS,
      actor: "u1",
      actorLabel: "Anna Admin (anna)",
      ip: "192.0.2.1",
      session: "3f9a1c2b7d4e",
      targetType: "team",
      targetId: "t1",
      targetLabel: "Team · Netz",
    }
    const chips = valueChips(t, f)
    expect(chips.map((c) => `${c.label}: ${c.value}`)).toEqual(["Konto: Anna Admin (anna)", "IP: 192.0.2.1", "Sitzung: 3f9a1c…", "Ziel: Team · Netz"])
    expect(withoutChip(f, "target")).toMatchObject({ targetType: "", targetId: "", targetLabel: "" })
    expect(withoutChip(f, "actor")).toMatchObject({ actor: "", actorLabel: "" })
    expect(valueChips(t, { ...NO_FILTERS, actor: "sync" })[0].value).toBe("Verzeichnis-Sync")
  })
})

describe("who and from where in words", () => {
  it("names the sign-in method with its source", () => {
    expect(methodText(t, "password_totp")).toBe("Passwort + TOTP · lokal")
    expect(methodText(t, "ldap_totp")).toBe("AD-Passwort + TOTP · AD/LDAP")
    expect(methodText(tEn, "entra")).toBe("Entra ID · Microsoft Entra")
    expect(methodText(t, "passkey")).toBe("Passkey · lokal")
    expect(methodText(t, null)).toBe("—")
  })
  it("names the browser coarse", () => {
    expect(browserText({ family: "Firefox", version: "144", os: "macOS" })).toBe("Firefox 144 · macOS")
    expect(browserText({ family: "other", version: null, os: "Linux" })).toBe("Linux")
    expect(browserText({ family: null, version: null, os: null })).toBe(null)
    expect(browserText(null)).toBe(null)
  })
  it("finds the page of a target and the path of a setting", () => {
    expect(targetLink({ type: "team", id: "t 1", label: "Netz" })).toBe("/settings/teams?team=t%201")
    expect(targetLink({ type: "settings", id: "updates", label: "updates" })).toBe("/about")
    expect(targetLink({ type: "ip", id: "1.2.3.4", label: null })).toBe(null)
    expect(settingsPath(t, { type: "settings", id: "updates", label: "updates" })).toBe("Über Cobe News › Neue Versionen")
    expect(settingsPath(tEn, { type: "signin", id: "mfa", label: "mfa" })).toBe("Settings › Sign-in › Second factor for everyone")
    expect(settingsPath(t, { type: "settings", id: "unknown", label: null })).toBe(null)
    expect(settingsPath(t, { type: "team", id: "x", label: null })).toBe(null)
  })
  it("has a path for every settings section and a text for every anomaly, address class and route", () => {
    for (const k of [...SETTINGS_SECTIONS.map((s) => `audit.path.${s}`), ...SIGNIN_SECTIONS.map((s) => `audit.path.signin.${s}`)]) {
      expect(de[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
    }
    for (const a of ANOMALIES) expect(de[`audit.anomaly.${a}`], a).toBeTruthy()
    for (const c of ["loopback", "internal", "gateway", "shared", "external"]) expect(en[`audit.ipclass.${c}`], c).toBeTruthy()
    for (const v of ["direct", "bundled", "proxy", "bundled_proxy"]) expect(de[`audit.via.${v}`], v).toBeTruthy()
  })
})

describe("chain", () => {
  const chain = {
    state: "ok",
    sealed_seq: 10,
    verified_seq: 8,
    verified_at: null,
    full_at: null,
    anchor_seq: 0,
    unsealed: 0,
    problems: [{ id: 7, seq: 7, kind: "changed" }],
    rekeyed_at: null,
  } as const
  it("says how far the chain vouches for an entry", () => {
    expect(chainOf({ id: 1, seq: 1 }, { ...chain, problems: [] })).toBe("ok")
    expect(chainOf({ id: 7, seq: 7 }, { ...chain, problems: [...chain.problems] })).toBe("problem")
    expect(chainOf({ id: 9, seq: 9 }, { ...chain, problems: [] })).toBe("unchecked")
    expect(chainOf({ id: 11, seq: null }, { ...chain, problems: [] })).toBe("pending")
    expect(chainOf({ id: 1, seq: 1 }, undefined)).toBe("unknown")
    expect(chainOf({ id: 1, seq: 1 }, { ...chain, state: "other_key", problems: [] })).toBe("unknown")
  })
  it("names the chain's state – a changed state and unacknowledged findings as problems", () => {
    expect(chainText(t, { ...chain, problems: [] })).toBe("Kette lückenlos")
    expect(chainText(t, { ...chain, state: "problem", problems: [{ id: null, seq: 9, kind: "state" }] })).toBe("Zustand der Kette verändert – prüfen")
    expect(chainText(t, { ...chain, state: "problem", problems: [{ id: 7, seq: 7, kind: "changed" }] })).toBe("Lücke oder Änderung bei Eintrag #7")
    expect(chainText(t, { ...chain, state: "problem", problems: [], logged_problems: 2 })).toBe("2 gefundene Probleme nicht bestätigt")
    expect(chainText(tEn, { ...chain, state: "other_key", problems: [] })).toBe("Sealed with another key – cannot be checked")
  })
  it("copies an entry as JSON without its surroundings", () => {
    const e = {
      id: 1,
      at: "2026-11-04T10:00:00Z",
      actor: { kind: "system", id: null, name: "system", display: "" },
      action: "x",
      group: "other",
      target: null,
      ip: null,
      details: {},
      context: { history: [] },
    }
    expect(JSON.parse(entryJson(e as never))).not.toHaveProperty("context")
    expect(JSON.parse(entryJson(e as never)).id).toBe(1)
  })
})
