import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { type Schedule, TIMEZONES, URGENT_KINDS, WEEKDAYS, absenceValid, scheduleValid, showDate, today, validHm, zonesWith } from "@/lib/delivery-api"

const base: Schedule = {
  quiet: true,
  from: "18:00",
  to: "08:00",
  weekends: false,
  tz: "Europe/Berlin",
  urgent: [...URGENT_KINDS],
  daily: { email: null, desktop: null, teams: null },
}

describe("schedule", () => {
  it("takes HH:MM only and no empty window", () => {
    expect(validHm("08:00") && validHm("23:59")).toBe(true)
    expect(validHm("8:00") || validHm("24:00") || validHm("12:60")).toBe(false)
    expect(scheduleValid(base)).toBe(true)
    expect(scheduleValid({ ...base, from: "08:00", to: "08:00" })).toBe(false)
    expect(scheduleValid({ ...base, from: "08:00", to: "08:00", weekends: true })).toBe(true) // the weekends alone
    expect(scheduleValid({ ...base, quiet: false, from: "08:00", to: "08:00" })).toBe(true)
    expect(scheduleValid({ ...base, daily: { ...base.daily, email: "7:00" } })).toBe(false)
  })

  it("offers a stored zone that is not in the list", () => {
    expect(zonesWith("Europe/Berlin")).toBe(TIMEZONES)
    expect(zonesWith("Pacific/Auckland")[0]).toBe("Pacific/Auckland")
  })
})

describe("absence", () => {
  it("needs both dates, the end not before the start, a deputy", () => {
    expect(absenceValid("2026-11-02", "2026-11-06", "id")).toBe(true)
    expect(absenceValid("2026-11-02", "2026-11-02", "id")).toBe(true)
    expect(absenceValid("2026-11-06", "2026-11-02", "id")).toBe(false)
    expect(absenceValid("2026-11-02", "2026-11-06", "")).toBe(false)
    expect(absenceValid("2026-01-01", "2027-06-01", "id")).toBe(false)
  })

  it("shows local dates without shifting them", () => {
    expect(showDate("2026-11-03", "de")).toBe("03.11.2026")
    expect(showDate("2026-11-03", "en")).toBe("2026-11-03")
    expect(today(new Date(2026, 10, 3, 23, 30))).toBe("2026-11-03")
  })
})

describe("delivery strings", () => {
  it("are in German and English alike", () => {
    const mine = (o: Record<string, string>) => Object.keys(o).filter((k) => k.startsWith("delivery."))
    expect(mine(de).sort()).toEqual(mine(en).sort())
    const used = [
      ...URGENT_KINDS.flatMap((k) => [`delivery.urgent.${k}Hint`]),
      ...WEEKDAYS.flatMap((d) => [`delivery.day.${d}`, `delivery.dayName.${d}`]),
      ...["quiet_empty", "invalid_tz", "absence_range", "absence_past", "deputy_not_in_team"].map((c) => `errors.${c}`),
    ]
    for (const k of used) {
      expect(de[k], k).toBeTruthy()
      expect(en[k], k).toBeTruthy()
    }
  })
})
