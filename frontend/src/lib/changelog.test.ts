import { describe, expect, it } from "vitest"
import aboutDe from "@/i18n/about.de"
import aboutEn from "@/i18n/about.en"
import { CHANGE_KINDS, type ChangelogEntry, entryGroups, inlineTokens, kindCounts, splitChangelog } from "./changelog"

describe("inlineTokens", () => {
  it("keeps plain text as one token", () => {
    expect(inlineTokens("Neuer Seitenpunkt „Folgen“ (CPE)")).toEqual([{ kind: "text", text: "Neuer Seitenpunkt „Folgen“ (CPE)", bold: false }])
  })

  it("marks **bold** and `code`", () => {
    expect(inlineTokens("Neu: **Vendor News** mit `nvd:<cpe>` und mehr")).toEqual([
      { kind: "text", text: "Neu: ", bold: false },
      { kind: "text", text: "Vendor News", bold: true },
      { kind: "text", text: " mit ", bold: false },
      { kind: "code", text: "nvd:<cpe>", bold: false },
      { kind: "text", text: " und mehr", bold: false },
    ])
  })

  it("keeps code inside bold, and ** inside code literal", () => {
    expect(inlineTokens("**a `b` c**")).toEqual([
      { kind: "text", text: "a ", bold: true },
      { kind: "code", text: "b", bold: true },
      { kind: "text", text: " c", bold: true },
    ])
    expect(inlineTokens("`**x**`")).toEqual([{ kind: "code", text: "**x**", bold: false }])
  })

  it("shows unclosed markers as they are", () => {
    expect(inlineTokens("2 ** 3 und ` allein")).toEqual([{ kind: "text", text: "2 ** 3 und ` allein", bold: false }])
    expect(inlineTokens("****")).toEqual([{ kind: "text", text: "****", bold: false }])
  })

  it("never produces markup – HTML stays text", () => {
    const html = '<img src=x onerror="alert(1)"> **<b>x</b>**'
    const tokens = inlineTokens(html)
    expect(tokens.map((t) => t.text).join("")).toBe('<img src=x onerror="alert(1)"> <b>x</b>')
    expect(tokens.every((t) => t.kind === "text")).toBe(true)
  })
})

describe("splitChangelog", () => {
  const entries = [
    { version: "0.1.2", title: "B", items: ["x"] },
    { version: "0.1.1", title: "A", items: ["y"] },
  ]
  it("puts the running version first", () => {
    expect(splitChangelog({ version: "0.1.1", entries })).toEqual({ current: entries[1], older: [entries[0]] })
  })
  it("has no current section for a version without notes", () => {
    expect(splitChangelog({ version: "0.1.3", entries })).toEqual({ current: null, older: entries })
  })
})

describe("entryGroups", () => {
  it("keeps the server's groups, without empty ones", () => {
    const entry: ChangelogEntry = {
      version: "0.1.4",
      title: "x",
      groups: [
        { kind: "neu", heading: "Neu", items: ["a"] },
        { kind: "other", heading: "Leer", items: [] },
        { kind: "fixes", heading: "Fixes", items: ["b", "c"] },
      ],
      items: ["a", "b", "c"],
    }
    expect(entryGroups(entry).map((g) => g.heading)).toEqual(["Neu", "Fixes"])
  })

  it("falls back to one unnamed group for an entry without groups", () => {
    expect(entryGroups({ version: "0.1.0", title: "", items: ["a", "b"] })).toEqual([{ kind: "other", heading: "", items: ["a", "b"] }])
    expect(entryGroups({ version: "0.1.0", title: "", groups: [], items: [] })).toEqual([])
  })
})

describe("kindCounts", () => {
  it("counts per kind in changelog order, other headings summed up at the end", () => {
    const entry: ChangelogEntry = {
      version: "0.1.8",
      title: "x",
      groups: [
        { kind: "other", heading: "", items: ["o1"] },
        { kind: "fixes", heading: "Fixes", items: ["f1", "f2", "f3"] },
        { kind: "neu", heading: "Neu", items: ["n1"] },
        { kind: "other", heading: "Hinweis", items: ["o2"] },
        { kind: "betrieb", heading: "Betrieb", items: ["b1", "b2"] },
      ],
      items: [],
    }
    expect(kindCounts(entry)).toEqual([
      { kind: "neu", count: 1 },
      { kind: "fixes", count: 3 },
      { kind: "betrieb", count: 2 },
      { kind: "other", count: 2 },
    ])
  })

  it("knows the same kinds as the server, in the same order", () => {
    expect(CHANGE_KINDS).toEqual(["neu", "verbessert", "fixes", "sicherheit", "entfernt", "betrieb"])
  })
})

describe("strings", () => {
  it("has every Version & Changelog key in German and English", () => {
    expect(Object.keys(aboutEn).sort()).toEqual(Object.keys(aboutDe).sort())
  })

  it("has a label and a count for every kind", () => {
    for (const kind of CHANGE_KINDS) {
      expect(aboutDe[`about.kind.${kind}`]).toBeTruthy()
      expect(aboutDe[`about.count.${kind}_one`]).toBeTruthy()
      expect(aboutDe[`about.count.${kind}_other`]).toBeTruthy()
    }
    expect(aboutDe["about.count.other_other"]).toBeTruthy()
  })
})
