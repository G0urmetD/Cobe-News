// The app's own texts for the browser checks: read from src/i18n (de.ts / en.ts and the *.de.ts / *.en.ts parts mixed
// into them), so a check finds a button by the text the page shows – and a changed wording changes the check with it.
// Plain "key": "value" pairs only (what the files hold); {{name}} is filled in, _one / _other chosen by `count`.
import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "i18n")
const PAIR = /"([A-Za-z0-9_.-]+)":\s*\n?\s*"((?:[^"\\]|\\.)*)"/g

function load(lang) {
  const out = {}
  const files = fs.readdirSync(DIR).filter((f) => f === `${lang}.ts` || f.endsWith(`.${lang}.ts`))
  // the base file first, the parts after it (as the app mixes them in)
  files.sort((a, b) => (a === `${lang}.ts` ? -1 : b === `${lang}.ts` ? 1 : a.localeCompare(b)))
  for (const f of files) {
    const text = fs.readFileSync(path.join(DIR, f), "utf8")
    for (const m of text.matchAll(PAIR)) out[m[1]] = JSON.parse(`"${m[2]}"`)
  }
  return out
}

const cache = {}

/** t("de", "audit.title"), t("en", "audit.count", { count: 3 }) – throws for a key the app does not have. */
export function t(lang, key, vars = {}) {
  const dict = (cache[lang] ??= load(lang))
  let s = dict[key]
  if (s === undefined && "count" in vars) s = dict[`${key}_${vars.count === 1 ? "one" : "other"}`]
  if (s === undefined) throw new Error(`no text ${lang}:${key}`)
  return s.replace(/\{\{(\w+)\}\}/g, (_, k) => (k in vars ? String(vars[k]) : `{{${k}}}`))
}

/** A function bound to one language. */
export const texts = (lang) => (key, vars) => t(lang, key, vars)
