/**
 * The Content-Security-Policy allows no inline <style> elements (backend app/main.py: `style-src 'self';
 * style-src-attr 'unsafe-inline'` – style attributes stay allowed, Radix positions its popovers with them). Three
 * libraries put CSS into <style> elements at runtime; the build changes exactly those places (vite.config.ts), and fails
 * when one of them is not found any more (a new version of the library – look again, tests: no-inline-styles.test.ts):
 *
 * - sonner (the toasts) injects its whole stylesheet: switched off, the same CSS comes from `sonner/dist/styles.css`
 *   (imported in components/ui/sonner.tsx – a file of this origin).
 * - react-style-singleton (react-remove-scroll-bar: an open dialog, drawer or menu locks the page's scrolling, with the
 *   width of the scrollbar computed then): a constructed stylesheet (document.adoptedStyleSheets) instead – the CSS
 *   object model is not what CSP restricts.
 * - Radix Select renders a <style> with its viewport's scrollbar rule: left out, the rule is in index.css.
 *
 * input-otp creates an empty <style> and fills it through the CSS object model (insertRule) – allowed as it is.
 * Only the production build is changed: the dev server (npm run dev) sends no CSP.
 */

export interface StylePatch {
  what: string
  file: RegExp
  apply: (code: string) => string | null
}

const SINGLETON = `// Cobe News (src/lib/no-inline-styles.ts): a constructed stylesheet instead of a <style> element – no inline style for CSP
export var stylesheetSingleton = function () {
  var counter = 0;
  var sheet = null;
  return {
    add: function (style) {
      if (counter == 0 && typeof document !== "undefined" && typeof CSSStyleSheet === "function" && "adoptedStyleSheets" in document) {
        sheet = new CSSStyleSheet();
        sheet.replaceSync(style);
        document.adoptedStyleSheets = document.adoptedStyleSheets.concat([sheet]);
      }
      counter++;
    },
    remove: function () {
      counter--;
      if (!counter && sheet) {
        var gone = sheet;
        document.adoptedStyleSheets = document.adoptedStyleSheets.filter(function (s) { return s !== gone; });
        sheet = null;
      }
    },
  };
};
`

const RADIX_SELECT_STYLE = /\/\* @__PURE__ \*\/ jsx\(\s*"style",\s*\{\s*dangerouslySetInnerHTML:\s*\{\s*__html:\s*`\[data-radix-select-viewport\][^`]*`\s*\},\s*nonce\s*\}\s*\)/

export const STYLE_PATCHES: StylePatch[] = [
  {
    what: "sonner: no injected stylesheet (sonner/dist/styles.css instead)",
    file: /[\\/]node_modules[\\/]sonner[\\/]dist[\\/]index\.mjs$/,
    apply: (code) =>
      code.includes("function __insertCSS(code) {")
        ? code.replace("function __insertCSS(code) {", "function __insertCSS(code) {\n  return // Cobe News: CSP – the CSS comes from sonner/dist/styles.css\n")
        : null,
  },
  {
    what: "react-style-singleton: a constructed stylesheet instead of a <style> element",
    file: /[\\/]node_modules[\\/]react-style-singleton[\\/]dist[\\/]es2015[\\/]singleton\.js$/,
    apply: (code) => (code.includes("export var stylesheetSingleton") && code.includes("document.createElement('style')") ? SINGLETON : null),
  },
  {
    what: "Radix Select: no <style> in the viewport (the rule is in index.css)",
    file: /[\\/]node_modules[\\/]@radix-ui[\\/]react-select[\\/]dist[\\/]index\.mjs$/,
    apply: (code) => (RADIX_SELECT_STYLE.test(code) ? code.replace(RADIX_SELECT_STYLE, "null") : null),
  },
]

/** The patched module – null when `id` is none of the files; throws when it is one but the place is not found. */
export function patchInlineStyles(code: string, id: string): { code: string; patch: StylePatch } | null {
  const patch = STYLE_PATCHES.find((p) => p.file.test(id.split("?")[0]))
  if (!patch) return null
  const out = patch.apply(code)
  if (out === null) throw new Error(`no-inline-styles: ${patch.what} – the place to change was not found in ${id} (a new version?)`)
  return { code: out, patch }
}

/** A Vite plugin (build only): applies the patches and fails the build when one of them was never applied. */
export function noInlineStyles() {
  const applied = new Set<StylePatch>()
  return {
    name: "cobe-news-no-inline-styles",
    apply: "build" as const,
    enforce: "pre" as const,
    buildStart() {
      applied.clear()
    },
    transform(code: string, id: string) {
      const r = patchInlineStyles(code, id)
      if (!r) return null
      applied.add(r.patch)
      return { code: r.code, map: null }
    },
    buildEnd(error?: Error) {
      if (error) return
      const missing = STYLE_PATCHES.filter((p) => !applied.has(p))
      if (missing.length) throw new Error(`no-inline-styles: not applied – ${missing.map((p) => p.what).join("; ")}`)
    },
  }
}
