import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import {
  durationText,
  HOST_COMMAND,
  localHour,
  needsHost,
  RESTORE_ERROR_CODES,
  RESTORE_STATE_COLOR,
  restoreAlert,
  restoreErrorKey,
  restoreState,
  revisionBehind,
  settingsDirty,
  type RestoreLast,
} from "@/lib/restore-test"

const last = (over: Partial<RestoreLast> = {}): RestoreLast => ({
  ok: true,
  trigger: "schedule",
  started_at: "2026-10-29T03:00:00Z",
  at: "2026-10-29T03:01:00Z",
  seconds: 42.5,
  head: "0013",
  ...over,
})

describe("restoreState", () => {
  it("tells not set up, never, failed, overdue and passed apart", () => {
    expect(restoreState({ configured: false, last: last(), overdue: false })).toBe("off")
    expect(restoreState({ configured: true, last: null, overdue: false })).toBe("never")
    expect(restoreState({ configured: true, last: last({ ok: false, code: "rows" }), overdue: true })).toBe("failed")
    expect(restoreState({ configured: true, last: last(), overdue: true })).toBe("overdue")
    expect(restoreState({ configured: true, last: last(), overdue: false })).toBe("passed")
  })
  it("colours by UX.md and marks only what needs a look", () => {
    expect(RESTORE_STATE_COLOR.failed).toBe("--sev-critical")
    expect(RESTORE_STATE_COLOR.overdue).toBe("--warning")
    expect(RESTORE_STATE_COLOR.passed).toBe("--success")
    expect(RESTORE_STATE_COLOR.never).toBe("--muted-foreground")
    expect(restoreAlert("failed") && restoreAlert("overdue")).toBe(true)
    expect(restoreAlert("never") || restoreAlert("off") || restoreAlert("passed")).toBe(false)
  })
})

describe("the outcome", () => {
  it("has a text in both languages for every reason a test fails", () => {
    for (const code of RESTORE_ERROR_CODES) {
      const key = restoreErrorKey({ code })
      expect(key).toBe(`restoreTest.err.${code}`)
      expect(de[key], key).toBeTruthy()
      expect(en[key], key).toBeTruthy()
    }
    expect(restoreErrorKey({})).toBe("restoreTest.err.failed")
    expect(restoreErrorKey({ code: "something_new" })).toBe("restoreTest.err.failed")
  })
  it("writes the duration short", () => {
    expect(durationText(42.4)).toBe("42 s")
    expect(durationText(185)).toBe("3 min 05 s")
    expect(durationText(3720)).toBe("1 h 02 min")
    expect(durationText(-1)).toBe("0 s")
  })
  it("notes an older schema revision (a real restore migrates it)", () => {
    expect(revisionBehind(last({ revision: "0012" }))).toBe(true)
    expect(revisionBehind(last({ revision: "0013" }))).toBe(false)
    expect(revisionBehind(last())).toBe(false)
  })
})

describe("settings", () => {
  it("points to the host script when the app cannot decrypt the newest backup", () => {
    const newest = { name: "cobe-news-20261029-030000.tar.enc", size: 1, at: "", encrypted: true }
    expect(needsHost({ newest, passphrase: false }, "app")).toBe(true)
    expect(needsHost({ newest, passphrase: false }, "host")).toBe(false)
    expect(needsHost({ newest, passphrase: true }, "app")).toBe(false)
    expect(needsHost({ newest: { ...newest, encrypted: false }, passphrase: false }, "app")).toBe(false)
    expect(needsHost({ newest: null, passphrase: false }, "app")).toBe(false)
    expect(HOST_COMMAND).toBe("scripts/restore-test.sh --passphrase-file /pfad/zur/passphrase")
  })
  it("shows the UTC hour in local time of that day", () => {
    expect(localHour(3, new Date("2026-07-01T12:00:00Z"), "Europe/Zurich")).toBe("05:00")
    expect(localHour(3, new Date("2026-12-01T12:00:00Z"), "Europe/Zurich")).toBe("04:00")
    expect(localHour(23, new Date("2026-12-01T12:00:00Z"), "Europe/Zurich")).toBe("00:00")
    expect(localHour(0, new Date("2026-12-01T12:00:00Z"), "UTC")).toBe("00:00")
  })
  it("knows when there is something to save", () => {
    const a = { enabled: true, mode: "app" as const, every_days: 7, hour: 3 }
    expect(settingsDirty(a, { ...a })).toBe(false)
    expect(settingsDirty(a, { ...a, hour: 4 })).toBe(true)
    expect(settingsDirty(a, { ...a, mode: "host" })).toBe(true)
  })
})

describe("i18n", () => {
  it("has every restore-test text in German and English", () => {
    const keys = (m: Record<string, string>) => Object.keys(m).filter((k) => k.startsWith("restoreTest."))
    expect(keys(de).sort()).toEqual(keys(en).sort())
    expect(keys(de).length).toBeGreaterThan(40)
  })
})
