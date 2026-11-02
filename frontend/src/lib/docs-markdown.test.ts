import { readFileSync, readdirSync } from "node:fs"
import { join } from "node:path"
import { createElement } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router"
import i18n from "i18next"
import { I18nextProvider, initReactI18next } from "react-i18next"
import { describe, expect, it, vi } from "vitest"
import { TooltipProvider } from "@/components/ui/tooltip"
import { DocBlocks } from "@/components/cobe/doc-markdown"
import de from "@/i18n/de"
import en from "@/i18n/en"
import docsDe from "@/i18n/docs.de"
import docsEn from "@/i18n/docs.en"
import { type Block, type Inline, fillLive, highlightParts, linkKind, parseInline, parseMarkdown, searchSections, sectionTexts } from "./docs-markdown"

// sonner (pulled in by the copy helper) injects its CSS on import – not in node
vi.mock("sonner", () => ({ toast: Object.assign(() => undefined, { error: () => undefined, success: () => undefined }) }))

const t = i18n.createInstance()
void t.use(initReactI18next).init({ lng: "de", resources: { de: { translation: de } }, keySeparator: false, nsSeparator: false, interpolation: { escapeValue: false } })

function render(md: string, live: Record<string, string> = {}): string {
  return renderToStaticMarkup(
    createElement(
      I18nextProvider,
      { i18n: t },
      createElement(MemoryRouter, null, createElement(TooltipProvider, null, createElement(DocBlocks, { blocks: parseMarkdown(md), chapter: "test", live }))),
    ),
  )
}

/** Every inline token of a block tree, depth first. */
function inlines(blocks: Block[]): Inline[] {
  const out: Inline[] = []
  const walk = (c: Inline[]) => {
    for (const x of c) {
      out.push(x)
      if ("c" in x) walk(x.c)
    }
  }
  for (const b of blocks) {
    if (b.t === "para" || b.t === "subheading") walk(b.c)
    else if (b.t === "heading") walk(parseInline(b.text))
    else if (b.t === "list") b.items.forEach((it) => out.push(...inlines(it)))
    else if (b.t === "callout") out.push(...inlines(b.blocks))
    else if (b.t === "table") [b.head, ...b.rows].forEach((r) => r.forEach(walk))
  }
  return out
}

describe("links", () => {
  it("allows only http(s), paths of this app, anchors and term:", () => {
    expect(linkKind("https://learn.example.com/a?b=c#d")).toBe("external")
    expect(linkKind("http://example.com")).toBe("external")
    expect(linkKind("/settings/auth")).toBe("app")
    expect(linkKind("/settings/integrations?vendor=care")).toBe("app")
    expect(linkKind("/docs/anmeldung#entra-fehler")).toBe("doc")
    expect(linkKind("#abschnitt")).toBe("anchor")
    expect(linkKind("term:cvss")).toBe("term")
    for (const bad of [
      "javascript:alert(1)",
      "JavaScript:alert(1)",
      " javascript:alert(1)",
      "java\tscript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "vbscript:msgbox",
      "mailto:a@example.com",
      "file:///etc/passwd",
      "//evil.example",
      "/\\evil.example",
      "https://user:pw@example.com/",
      "https://exa mple.com",
      "ftp://example.com",
      "term:Bad-Term",
      "",
    ])
      expect(linkKind(bad), bad).toBeNull()
  })

  it("renders a forbidden link as its text only, an external one with noopener in a new tab", () => {
    const html = render("[klick](javascript:alert(1)) und [Seite](https://example.com/x) und [intern](/settings/auth) und [Abschnitt](#a)")
    expect(html).not.toContain("javascript:")
    expect(html).toContain("klick")
    expect(html).toContain('href="https://example.com/x" target="_blank" rel="noopener noreferrer"')
    expect(html).toContain('href="/settings/auth"')
    expect(html).toContain('href="/#a"')
  })
})

describe("no raw HTML", () => {
  it("shows tags in the text as text – never as markup", () => {
    const md = [
      "Hallo <script>alert(1)</script> <b>fett</b> <img src=x onerror=alert(1)>",
      "",
      "- <iframe src=https://example.com></iframe>",
      "",
      "| a | b |",
      "|---|---|",
      "| <svg onload=alert(1)> | `<b>` |",
      "",
      "> [!WARNING]",
      "> <style>body{}</style>",
      "",
      "```html",
      "<script>alert(2)</script>",
      "```",
      "",
      "## <em>Titel</em> {#titel}",
    ].join("\n")
    const html = render(md)
    for (const tag of ["<script", "<b>", "<img", "<iframe", "<style", "<em>"]) expect(html, tag).not.toContain(tag)
    // the only <svg> elements are the page's own icons (lucide), never one from the text
    expect(html.match(/<svg(?![^>]*class="lucide)/g)).toBeNull()
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;")
    expect(html).toContain("&lt;script&gt;alert(2)&lt;/script&gt;")
    expect(html).toContain("&lt;svg onload=alert(1)&gt;")
    // the only <script>-free way to get markup would be an innerHTML prop – the renderer has none
    expect(readFileSync(join(import.meta.dirname, "../components/cobe/doc-markdown.tsx"), "utf8")).not.toContain("dangerouslySetInnerHTML")
  })

  it("has no image syntax", () => {
    const html = render("![bild](https://example.com/x.png)")
    expect(html).not.toContain("<img")
  })
})

describe("blocks", () => {
  it("parses headings with ids and the admin marker, lists, code, tables and callouts", () => {
    const blocks = parseMarkdown(
      [
        "## Einrichten {#einrichten .admin}",
        "",
        "1. Erster Schritt",
        "   mit Fortsetzung",
        "2. Zweiter Schritt",
        "   - verschachtelt",
        "",
        "3. Dritter",
        "",
        "```bash",
        "echo {{base_url}}",
        "```",
        "",
        "| Name | Wert |",
        "|---|:-:|",
        "| `a\\|b` | **x** |",
        "",
        "> [!TIP]",
        "> Ein Tipp.",
      ].join("\n"),
    )
    expect(blocks.map((b) => b.t)).toEqual(["heading", "list", "code", "table", "callout"])
    expect(blocks[0]).toMatchObject({ level: 2, id: "einrichten", admin: true, text: "Einrichten" })
    const list = blocks[1] as Extract<Block, { t: "list" }>
    expect(list.ordered).toBe(true)
    expect(list.items).toHaveLength(3) // the blank line before "3." does not end the list
    expect(list.items[0]).toEqual([{ t: "para", c: [{ t: "text", v: "Erster Schritt mit Fortsetzung" }] }])
    expect(list.items[1].map((b) => b.t)).toEqual(["para", "list"])
    expect(blocks[2]).toEqual({ t: "code", lang: "bash", text: "echo {{base_url}}" })
    const table = blocks[3] as Extract<Block, { t: "table" }>
    expect(table.align).toEqual(["left", "center"])
    expect(table.rows[0][0]).toEqual([{ t: "code", v: "a|b" }])
    expect(blocks[4]).toMatchObject({ t: "callout", kind: "tip" })
  })

  it("fills the installation's values – unknown names stay as written", () => {
    expect(parseInline("URI: {{redirect_uri}} und {{nope}}")).toEqual([
      { t: "text", v: "URI: " },
      { t: "live", name: "redirect_uri" },
      { t: "text", v: " und " },
      { t: "live", name: "nope" },
    ])
    expect(fillLive("a {{base_url}} {{x}}", { base_url: "https://news.corp.example:8095" })).toBe("a https://news.corp.example:8095 {{x}}")
    const html = render("Eintragen: {{redirect_uri}} – {{secret}}\n\n```text\n{{redirect_uri}}\n```", {
      redirect_uri: "https://news.corp.example:8095/api/auth/oidc/callback",
    })
    expect(html.match(/news\.corp\.example:8095\/api\/auth\/oidc\/callback/g)).toHaveLength(2)
    expect(html).toContain("{{secret}}")
  })

  it("renders a code block with a copy button and terms with their explanation", () => {
    const html = render("Ein [CVSS-Wert](term:cvss) und [Redirect](term:redirecturi) und [x](term:unbekannt)\n\n```bash\nls\n```")
    expect(html).toContain('aria-label="Code kopieren"')
    expect(html).toContain("CVSS-Wert")
    expect(html).toContain("cursor-help")
    expect(html).toContain("und x</p>") // an unknown term: the word alone
  })
})

describe("search", () => {
  const blocks = parseMarkdown("Einleitung.\n\n## Redirect-URI {#redirect}\n\nDie Adresse `{{redirect_uri}}` muss passen.\n\n## Übersicht {#ueberblick}\n\nAlles über Größen.")
  const sections = sectionTexts(blocks, { redirect_uri: "https://news.corp.example/api/auth/oidc/callback" })

  it("finds sections by all words, title hits first, accent-insensitive", () => {
    const chapters = [{ id: "anmeldung", title: "Anmeldung", sections }]
    expect(searchSections(chapters, "redirect").map((h) => h.section)).toEqual(["redirect"])
    expect(searchSections(chapters, "callback adresse").map((h) => h.section)).toEqual(["redirect"])
    expect(searchSections(chapters, "uebersicht")).toEqual([])
    expect(searchSections(chapters, "ubersicht").map((h) => h.section)).toEqual(["ueberblick"])
    expect(searchSections(chapters, "a")).toEqual([]) // too short
  })

  it("highlights as text parts – also next to characters that NFKD would expand (…, ß)", () => {
    expect(highlightParts("… HMAC signature …", "signature")).toEqual([
      { text: "… HMAC ", hit: false },
      { text: "signature", hit: true },
      { text: " …", hit: false },
    ])
    expect(highlightParts("Die Übersicht", "uber")).toEqual([
      { text: "Die ", hit: false },
      { text: "Über", hit: true },
      { text: "sicht", hit: false },
    ])
  })
})

describe("the handbook files", () => {
  const root = join(import.meta.dirname, "../../../docs/handbuch")
  const files = (lang: string) =>
    readdirSync(join(root, lang))
      .filter((f) => /^\d{2}-[a-z0-9-]+\.md$/.test(f))
      .map((f) => ({ name: `${lang}/${f}`, text: readFileSync(join(root, lang, f), "utf8") }))
  const all = [...files("de"), ...files("en")]
  const bodyOf = (text: string) => text.replace(/^---\n[\s\S]*?\n---\n/, "")

  it("exist in both languages", () => {
    expect(files("de").length).toBeGreaterThanOrEqual(9)
    expect(files("en").map((f) => f.name.slice(3))).toEqual(files("de").map((f) => f.name.slice(3)))
  })

  it("use only links the renderer allows, known terms and known live values", () => {
    for (const f of all) {
      const tokens = inlines(parseMarkdown(bodyOf(f.text)))
      for (const x of tokens) {
        if (x.t === "text") {
          expect(x.v, `${f.name}: a link the renderer refused`).not.toMatch(/\]\(/)
          expect(x.v, `${f.name}: raw HTML`).not.toMatch(/<[A-Za-z/!]/)
        }
        if (x.t === "term") expect(t.exists(`glossary.${x.k}`) || t.exists(`docs.term.${x.k}`), `${f.name}: term ${x.k}`).toBe(true)
        if (x.t === "live") expect(["base_url", "redirect_uri", "version"], `${f.name}: live ${x.name}`).toContain(x.name)
      }
    }
  })

  it("have their texts in German and English", () => {
    expect(Object.keys(docsEn).sort()).toEqual(Object.keys(docsDe).sort())
    for (const k of Object.keys(docsDe)) {
      expect(de[k], k).toBe(docsDe[k])
      expect(en[k], k).toBe(docsEn[k])
    }
  })
})
