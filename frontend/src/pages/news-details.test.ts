import { createElement, type ReactElement } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import i18n from "i18next"
import { I18nextProvider, initReactI18next } from "react-i18next"
import { describe, expect, it, vi } from "vitest"
import { TlpPill } from "@/components/cobe/badges"
import { ExploitHints } from "@/components/cobe/exploit"
import { TooltipProvider } from "@/components/ui/tooltip"
import de from "@/i18n/de"
import type { NewsDetail } from "@/lib/news-api"
import { StoryCves } from "./news-details"

// sonner (pulled in by the shared helpers) injects its CSS on import – not in node
vi.mock("sonner", () => ({ toast: Object.assign(() => undefined, { error: () => undefined, success: () => undefined }) }))

const t = i18n.createInstance()
void t.use(initReactI18next).init({ lng: "de", resources: { de: { translation: de } }, keySeparator: false, nsSeparator: false, interpolation: { escapeValue: false } })

function render(node: ReactElement): string {
  return renderToStaticMarkup(
    createElement(
      I18nextProvider,
      { i18n: t },
      createElement(QueryClientProvider, { client: new QueryClient() }, createElement(MemoryRouter, null, createElement(TooltipProvider, null, node))),
    ),
  )
}

const story = (extra: Partial<NewsDetail>): NewsDetail =>
  ({
    id: "s1",
    title: "x",
    summary: "",
    url: "https://n.example.com/x",
    source: { id: "s", key: "s", name: "S", logo: false },
    published_at: "2026-11-01T08:00:00Z",
    severity: "high",
    cves: [],
    also_in: [],
    read_at: null,
    content_html: "",
    reasons: [],
    details: null,
    details_state: "ok",
    affects: [],
    ...extra,
  }) as NewsDetail

describe("the story's CVEs", () => {
  it("without CVEs of its own: no empty list – the details' CVEs with their exploits, labelled", () => {
    const html = render(createElement(StoryCves, { d: story({ exploits: [{ cve: "CVE-2026-1111", source: "nuclei", url: "https://github.com/x" }] }) }))
    expect(html.match(/<ul/g)).toHaveLength(1)
    expect(html).toContain("CVEs aus „Betroffene Versionen“:")
    expect(html).toContain("CVE-2026-1111")
    expect(html).toContain("Exploit-Code öffentlich")
  })
  it("with CVEs of its own and none only the details name: one list, no label", () => {
    const html = render(
      createElement(StoryCves, { d: story({ cves: ["CVE-2026-2222"], exploits: [{ cve: "CVE-2026-2222", source: "metasploit", url: "https://github.com/y" }] }) }),
    )
    expect(html.match(/<ul/g)).toHaveLength(1)
    expect(html).not.toContain("Betroffene Versionen")
  })
})

describe("exploit and TLP pills", () => {
  it("a link without a CVE has a title without one", () => {
    const html = render(createElement(ExploitHints, { hints: [{ source: "exploitdb", url: "https://www.exploit-db.com/exploits/1" }] }))
    expect(html).toContain('title="Exploit-DB-Eintrag öffnen"')
    expect(html).not.toContain("zu  öffnen")
  })
  it("TLP:GREEN explains itself through the glossary (focusable – a tap opens it on touch), compact as well", () => {
    const own = render(createElement(TlpPill))
    expect(own).toContain("TLP:GREEN")
    expect(own).toContain('tabindex="0"')
    expect(own).toContain("var(--success-fg)") // the darker text tone (AA on the tint)
    const compact = render(createElement(TlpPill, { compact: true }))
    expect(compact).toContain("TLP:GREEN")
    expect(compact).toContain('tabindex="0"') // the overview's line: beside its button, a focus stop of its own
  })
})
