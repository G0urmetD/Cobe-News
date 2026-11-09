import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { personalNewsBody } from "@/lib/personal-news"

const choice = { severities: ["critical" as const], sources: [], topics: [], systems: [{ vendor: "Palo Alto Networks" }], keywords: ["Bleed"], exclude: ["Webinar"] }

describe("security stories by e-mail or Teams", () => {
  it("sends the choice and the ways, a Teams URL only when one was typed", () => {
    const b = personalNewsBody({ ...choice, email_on: true, teams_on: false }, "de-CH", "  ")
    expect(b).toEqual({
      email_on: true,
      teams_on: false,
      severities: ["critical"],
      sources: [],
      topics: [],
      systems: [{ vendor: "Palo Alto Networks" }],
      keywords: ["Bleed"],
      exclude: ["Webinar"],
      lang: "de",
    })
    expect(personalNewsBody({ ...choice, email_on: false, teams_on: true }, "en", " https://x.logic.azure.com/w ")).toMatchObject({
      teams_url: "https://x.logic.azure.com/w",
      lang: "en",
    })
  })
  it("has its texts and the admin switch in both languages", () => {
    const keys = Object.keys(de).filter((k) => k.startsWith("personalNews.") || k.startsWith("teams.personal.news"))
    expect(keys.length).toBe(14)
    for (const k of keys) expect(en, k).toHaveProperty([k])
  })
})
