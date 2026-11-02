import { readFileSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"
import { STYLE_PATCHES, noInlineStyles, patchInlineStyles } from "@/lib/no-inline-styles"
import mainPy from "../../../backend/app/main.py?raw"

/** The installed files the build changes (src/lib/no-inline-styles.ts) – a new version must still have the places. */
const pkgDir = (name: string) => join(import.meta.dirname, "../../node_modules", name)
const FILES = {
  sonner: join(pkgDir("sonner"), "dist/index.mjs"),
  singleton: join(pkgDir("react-style-singleton"), "dist/es2015/singleton.js"),
  select: join(pkgDir("@radix-ui/react-select"), "dist/index.mjs"),
}

describe("no inline <style> elements (CSP style-src 'self')", () => {
  it("the server's CSP allows no inline style element, only style attributes", () => {
    const csp = /CSP = \(\n([\s\S]*?)\n\)/.exec(mainPy)?.[1] ?? ""
    // stylesheets of this origin and an empty <style> (input-otp fills its one through the CSS object model)
    expect(csp).toContain("style-src 'self' {STYLE_EMPTY};")
    expect(mainPy).toContain(`STYLE_EMPTY = "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"`) // sha256 of ""
    expect(csp).toContain("style-src-attr 'unsafe-inline'")
    expect(csp).not.toMatch(/style-src 'self'[^;]*'unsafe-inline'/)
  })

  it("finds and changes each place in the installed libraries", () => {
    for (const [name, file] of Object.entries(FILES)) {
      const code = readFileSync(file, "utf8")
      const r = patchInlineStyles(code, file)
      expect(r, name).not.toBeNull()
      expect(r!.code, name).not.toBe(code)
    }
    expect(STYLE_PATCHES).toHaveLength(Object.keys(FILES).length)
  })

  it("sonner injects nothing – its CSS file is imported instead", () => {
    const out = patchInlineStyles(readFileSync(FILES.sonner, "utf8"), FILES.sonner)!.code
    expect(out).toMatch(/function __insertCSS\(code\) \{\n\s*return/)
    expect(readFileSync(join(pkgDir("sonner"), "dist/styles.css"), "utf8")).toContain("[data-sonner-toaster]")
    expect(readFileSync(join(import.meta.dirname, "../components/ui/sonner.tsx"), "utf8")).toContain('import "sonner/dist/styles.css"')
  })

  it("the scroll lock uses a constructed stylesheet, no <style> element", () => {
    const out = patchInlineStyles(readFileSync(FILES.singleton, "utf8"), FILES.singleton)!.code
    expect(out).not.toContain("createElement")
    expect(out).toContain("adoptedStyleSheets")
    expect(out).toContain("export var stylesheetSingleton")
  })

  it("Radix Select renders no <style>; its rule is in index.css", () => {
    const out = patchInlineStyles(readFileSync(FILES.select, "utf8"), FILES.select)!.code
    expect(out).not.toContain("dangerouslySetInnerHTML")
    const css = readFileSync(join(import.meta.dirname, "../index.css"), "utf8")
    expect(css).toContain("[data-radix-select-viewport]::-webkit-scrollbar")
    expect(css).toContain("scrollbar-width: none")
  })

  it("leaves other files alone and fails loudly when a place is gone", () => {
    expect(patchInlineStyles("const x = 1", "/x/node_modules/other/index.mjs")).toBeNull()
    expect(() => patchInlineStyles("export const nothing = 1", "/x/node_modules/sonner/dist/index.mjs")).toThrow(/not found/)
    const plugin = noInlineStyles()
    plugin.buildStart()
    expect(() => plugin.buildEnd()).toThrow(/not applied/)
  })

  it("the theme switch needs no <style> element either", () => {
    const theme = readFileSync(join(import.meta.dirname, "theme.tsx"), "utf8")
    expect(theme).not.toContain('createElement("style")')
    expect(readFileSync(join(import.meta.dirname, "../index.css"), "utf8")).toContain(".theme-switching *")
  })
})
