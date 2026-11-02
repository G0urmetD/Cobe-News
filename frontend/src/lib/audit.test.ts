import { describe, expect, it } from "vitest"
import type { TFunction } from "i18next"
import de from "@/i18n/de"
import en from "@/i18n/en"
import {
  actionText,
  actorText,
  ALL_ACTIONS,
  AUDIT_GROUPS,
  detailRows,
  exportPath,
  fieldText,
  filterParams,
  fmtValue,
  GROUP_KEYS,
  groupOf,
  isFiltered,
  NO_FILTERS,
  targetText,
} from "@/lib/audit"

// a t() over one bundle, with i18next's defaultValue and {{x}} interpolation
const tOf =
  (bundle: Record<string, string>) =>
  (key: string, opts?: Record<string, unknown>): string => {
    const raw = bundle[key] ?? (opts?.defaultValue as string | undefined) ?? key
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
    expect(fieldText(t, "config.header_name")).toBe("config.header_name")
  })
})

describe("filters", () => {
  it("leaves empty filters out and takes the 'to' day whole, in local time", () => {
    expect(isFiltered(NO_FILTERS)).toBe(false)
    expect(filterParams(NO_FILTERS).toString()).toBe("")
    const p = filterParams({ group: "tokens", actor: "sync", from: "2026-10-01", to: "2026-10-31", q: "  anna " })
    expect(p.get("group")).toBe("tokens")
    expect(p.get("actor")).toBe("sync")
    expect(p.get("q")).toBe("anna")
    expect(new Date(p.get("since")!).getTime()).toBe(new Date(2026, 9, 1).getTime())
    expect(new Date(p.get("until")!).getTime()).toBe(new Date(2026, 10, 1).getTime())
    expect(filterParams({ ...NO_FILTERS, from: "kaputt" }).has("since")).toBe(false)
    expect(isFiltered({ ...NO_FILTERS, q: "x" })).toBe(true)
  })
  it("builds the export address with the same filters", () => {
    expect(exportPath(NO_FILTERS)).toBe("/api/admin/audit/export")
    expect(exportPath({ ...NO_FILTERS, group: "backup" })).toBe("/api/admin/audit/export?group=backup")
  })
})
