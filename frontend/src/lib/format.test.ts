// the zone abbreviations below are those of Central Europe – the reader's zone is what Intl knows of this process
process.env.TZ = "Europe/Berlin"

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest"
import i18n from "@/i18n"
import { fmtDateTimeZone, fmtRelative, fmtZone } from "@/lib/format"

beforeAll(async () => {
  await i18n.changeLanguage("de")
})

afterEach(async () => {
  vi.useRealTimers()
  await i18n.changeLanguage("de")
})

describe("format", () => {
  it("relative days are calendar days in local time, not blocks of 24 hours", async () => {
    const now = new Date(2026, 9, 28, 1, 0).getTime() // Wednesday 01:00, local time
    expect(fmtRelative(new Date(2026, 9, 26, 23, 0).toISOString(), now)).toBe("vorgestern") // 26 hours, but two calendar days
    expect(fmtRelative(new Date(2026, 9, 27, 0, 30).toISOString(), now)).toBe("gestern") // 24.5 hours
    expect(fmtRelative(new Date(2026, 9, 27, 23, 0).toISOString(), now)).toBe("vor 2 Stunden")
    await i18n.changeLanguage("en")
    expect(fmtRelative(new Date(2026, 9, 26, 23, 0).toISOString(), now)).toBe("2 days ago")
    expect(fmtRelative(new Date(2026, 9, 27, 0, 30).toISOString(), now)).toBe("yesterday")
  })

  it("a day with a clock change still counts as one day", () => {
    // 25 October 2026: 25 hours long in Central Europe
    const now = new Date(2026, 9, 26, 12, 0).getTime()
    expect(fmtRelative(new Date(2026, 9, 24, 12, 0).toISOString(), now)).toBe("vorgestern")
    expect(fmtRelative(new Date(2026, 9, 25, 0, 30).toISOString(), now)).toBe("gestern")
  })

  it("the zone of a point in time from the reader's time zone (MEZ/MESZ, CET/CEST)", async () => {
    // 25 October 2026, 02:30 happens twice in Berlin – once in summer time, once in winter time
    const summer = "2026-10-25T00:30:00Z"
    const winter = "2026-10-25T01:30:00Z"
    expect(fmtZone(summer)).toBe("MESZ")
    expect(fmtZone(winter)).toBe("MEZ")
    expect(fmtDateTimeZone(summer)).toMatch(/02:30 MESZ$/)
    expect(fmtDateTimeZone(winter)).toMatch(/02:30 MEZ$/)
    await i18n.changeLanguage("en")
    expect(fmtZone(summer)).toBe("CEST")
    expect(fmtZone(winter)).toBe("CET")
  })
})
