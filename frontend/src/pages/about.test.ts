import { createElement } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import i18n from "i18next"
import { I18nextProvider, initReactI18next } from "react-i18next"
import { describe, expect, it, vi } from "vitest"
import { TooltipProvider } from "@/components/ui/tooltip"
import aboutDe from "@/i18n/about.de"
import type { Changelog } from "@/lib/changelog"
import { UPDATE_KEY, type UpdateStatus } from "@/lib/update-api"
import { AboutPage } from "./about"

// sonner (pulled in by the shared helpers) injects its CSS on import – not in node
vi.mock("sonner", () => ({ toast: Object.assign(() => undefined, { error: () => undefined, success: () => undefined }) }))
// the update check is for admins only (app/update_check.py) – a reader by default, an admin where a test says so
const auth = vi.hoisted(() => ({ isAdmin: false }))
vi.mock("@/lib/auth", () => ({ useAuth: () => auth }))

const t = i18n.createInstance()
void t.use(initReactI18next).init({ lng: "de", resources: { de: { translation: aboutDe } }, keySeparator: false, nsSeparator: false, interpolation: { escapeValue: false } })

function render(data: Changelog, update?: UpdateStatus): string {
  const qc = new QueryClient()
  qc.setQueryData(["changelog"], data)
  if (update) qc.setQueryData(UPDATE_KEY, update)
  return renderToStaticMarkup(
    createElement(I18nextProvider, { i18n: t }, createElement(QueryClientProvider, { client: qc }, createElement(TooltipProvider, null, createElement(AboutPage)))),
  )
}

describe("AboutPage", () => {
  it("shows the running version's notes first, with bold and code, and the earlier versions folded", () => {
    const html = render({
      version: "0.1.1",
      entries: [
        { version: "0.1.1", title: "Vendor News", items: ["Neuer Punkt **Vendor News** mit `cpe:2.3`"] },
        { version: "0.1.0", title: "Erste Version", items: ["Älteres"] },
      ],
    })
    expect(html).toContain("Neu in 0.1.1")
    expect(html).toContain('<strong class="font-semibold">Vendor News</strong>')
    expect(html).toContain("cpe:2.3</code>")
    expect(html).toContain("Frühere Versionen")
    expect(html).toContain("Erste Version")
    expect(html).not.toContain("Älteres") // folded: the notes appear on click
  })

  it("shows the running version's notes under their headings, with a badge per kind", () => {
    const html = render({
      version: "0.1.4",
      entries: [
        {
          version: "0.1.4",
          title: "Versionen-Tab und Fixes",
          groups: [
            { kind: "neu", heading: "Neu", items: ["Reiter **Versionen**"] },
            { kind: "fixes", heading: "Fixes", items: ["PAN-OS: zweite CVE"] },
            { kind: "other", heading: "Hinweis", items: ["Ein Absatz"] },
          ],
          items: ["Reiter **Versionen**", "PAN-OS: zweite CVE", "Ein Absatz"],
        },
      ],
    })
    const neu = html.indexOf(">Neu</span>")
    const fixes = html.indexOf(">Fixes</span>")
    expect(neu).toBeGreaterThan(-1)
    expect(fixes).toBeGreaterThan(neu)
    expect(html).toContain("var(--primary)") // the badge colour, a token
    expect(html).toContain("var(--warning)")
    expect(html.indexOf("PAN-OS: zweite CVE")).toBeGreaterThan(fixes)
    expect(html).toContain(">Hinweis</h3>") // a heading the changelog does not define keeps its text
    expect(html).toContain('<strong class="font-semibold">Versionen</strong>')
  })

  it("counts the kinds in the folded header of an earlier version", () => {
    const html = render({
      version: "0.1.5",
      entries: [
        { version: "0.1.5", title: "x", groups: [{ kind: "neu", heading: "Neu", items: ["a"] }], items: ["a"] },
        {
          version: "0.1.4",
          title: "Ältere",
          groups: [
            { kind: "neu", heading: "Neu", items: ["n1", "n2", "n3"] },
            { kind: "fixes", heading: "Fixes", items: ["f1", "f2", "f3", "f4", "f5"] },
            { kind: "sicherheit", heading: "Sicherheit", items: ["s1"] },
          ],
          items: ["n1", "n2", "n3", "f1", "f2", "f3", "f4", "f5", "s1"],
        },
        { version: "0.1.0", title: "Ohne Überschriften", items: ["a", "b"] },
      ],
    })
    const text = html.replace(/<[^>]+>/g, "")
    expect(text).toContain("3 neu·5 Fixes·1 Sicherheit")
    expect(text).toContain("2 Änderungen") // no headings: the plain count, as before
    expect(text).not.toContain("f1") // folded: the notes appear on click
  })

  it("escapes markup in the notes – text, never HTML", () => {
    const html = render({ version: "0.1.1", entries: [{ version: "0.1.1", title: "x", items: ['<img src=x onerror="alert(1)">'] }] })
    expect(html).not.toContain("<img src=x")
    expect(html).toContain("&lt;img src=x")
  })

  it("has a friendly hint when the running version has no notes", () => {
    const html = render({ version: "0.1.2", entries: [{ version: "0.1.1", title: "x", items: ["y"] }] })
    expect(html).toContain("Für 0.1.2 gibt es noch keine Notizen")
    expect(html).toContain("0.1.1")
  })

  it("shows admins the switch of the update check and what it found – readers nothing", () => {
    const data = { version: "0.1.46", entries: [] }
    const update: UpdateStatus = {
      enabled: true,
      current: "0.1.46",
      latest: "0.1.48",
      available: true,
      dismissed: false,
      url: "https://github.com/G0urmetD/Cobe-News/releases/tag/v0.1.48",
      published_at: null,
      checked_at: null, // a time (Ts) needs the browser's clock – not in a server render
      error: null,
      rev: 1,
    }
    expect(render(data, update)).not.toContain("Nach neuen Versionen suchen")
    auth.isAdmin = true
    try {
      const html = render(data, update)
      expect(html).toContain("Nach neuen Versionen suchen")
      expect(html).toContain("0.1.48 verfügbar")
      expect(html).toContain('href="https://github.com/G0urmetD/Cobe-News/releases/tag/v0.1.48"')
      expect(html).toContain('rel="noopener noreferrer"')
      // the release link only as an https address – as the shell's notice (no link otherwise)
      const bad = render(data, { ...update, url: "javascript:alert(1)" })
      expect(bad).not.toContain("javascript:")
      expect(bad).not.toContain("0.1.48 verfügbar</a>")
    } finally {
      auth.isAdmin = false
    }
  })
})
