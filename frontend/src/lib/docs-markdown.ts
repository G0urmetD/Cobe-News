/**
 * The handbook's Markdown (docs/handbuch/README.md) → a small tree the page renders as React elements. Deliberately
 * small and strict: no HTML (a tag in the text stays text – React escapes it), no images, links only http(s), paths of
 * this app, #anchors and term: tooltips – anything else is shown as plain text. Never rendered via innerHTML.
 */

export type Inline =
  | { t: "text"; v: string }
  | { t: "strong"; c: Inline[] }
  | { t: "em"; c: Inline[] }
  | { t: "code"; v: string }
  | { t: "link"; kind: LinkKind; href: string; c: Inline[] }
  | { t: "term"; k: string; c: Inline[] }
  | { t: "live"; name: string }

export type CalloutKind = "note" | "tip" | "warning"

export type Block =
  | { t: "heading"; level: 2 | 3; id: string; text: string; admin: boolean }
  | { t: "subheading"; c: Inline[] }
  | { t: "para"; c: Inline[] }
  | { t: "list"; ordered: boolean; start: number; items: Block[][] }
  | { t: "code"; lang: string; text: string }
  | { t: "table"; head: Inline[][]; rows: Inline[][][]; align: ("left" | "center" | "right")[] }
  | { t: "callout"; kind: CalloutKind; blocks: Block[] }

export type LinkKind = "external" | "app" | "doc" | "anchor" | "term"

const HEADING = /^(#{2,3})\s+(.+?)\s*\{#([a-z0-9][a-z0-9-]*)((?:\s+\.[a-z]+)*)\}\s*$/
const ANY_HEADING = /^(#{1,6})\s+(.*?)\s*(?:\{#[^}]*\})?\s*$/
const FENCE = /^(\s*)(```|~~~)\s*([A-Za-z0-9_+-]*)\s*$/
const MARKER = /^(\s*)([-*+]|\d{1,3}[.)])\s+(.*)$/
const TABLE_SEP = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/
const CALLOUT = /^\[!(NOTE|TIP|WARNING|IMPORTANT|CAUTION)\]\s*$/i

/** What a link target is – or null: not allowed (shown as text). */
export function linkKind(href: string): LinkKind | null {
  const h = href.trim()
  if (/^term:[a-z]+$/.test(h)) return "term"
  if (/^#[a-z0-9-]+$/.test(h)) return "anchor"
  if (/^\/docs(\/[a-z0-9-]*)?(#[a-z0-9-]+)?$/.test(h)) return "doc"
  // an app path: one leading slash (not //host), no backslash, no control characters or spaces
  if (/^\/(?![/\\])[A-Za-z0-9\-._~/?=&%#]*$/.test(h)) return "app"
  if (/^https?:\/\//i.test(h) && !/[\s\\<>"']/.test(h)) {
    try {
      const u = new URL(h)
      if ((u.protocol === "https:" || u.protocol === "http:") && u.hostname && !u.username && !u.password) return "external"
    } catch {
      return null
    }
  }
  return null
}

const indentOf = (line: string) => line.length - line.trimStart().length

/** Markdown text → blocks. */
export function parseMarkdown(text: string): Block[] {
  return parseBlocks(text.replace(/\r\n?/g, "\n").replace(/\t/g, "    ").split("\n"))
}

function startsBlock(line: string, next: string | undefined): boolean {
  return (
    FENCE.test(line) ||
    ANY_HEADING.test(line.trim()) ||
    MARKER.test(line) ||
    line.trimStart().startsWith(">") ||
    (line.trimStart().startsWith("|") && next !== undefined && TABLE_SEP.test(next))
  )
}

function parseBlocks(lines: string[]): Block[] {
  const out: Block[] = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    if (!line.trim()) {
      i += 1
      continue
    }
    // fenced code: the text as it is (dedented by the fence's indent); an unclosed fence runs to the end
    const fence = FENCE.exec(line)
    if (fence) {
      const ind = fence[1].length
      const body: string[] = []
      i += 1
      while (i < lines.length && !(lines[i].trim().startsWith(fence[2]) && lines[i].trim().replace(/[`~]/g, "") === "")) {
        body.push(lines[i].slice(Math.min(ind, indentOf(lines[i]))))
        i += 1
      }
      i += 1
      out.push({ t: "code", lang: fence[3].toLowerCase(), text: body.join("\n") })
      continue
    }
    const trimmed = line.trim()
    const h = HEADING.exec(trimmed)
    if (h) {
      out.push({ t: "heading", level: h[1].length as 2 | 3, id: h[3], text: h[2], admin: h[4].split(/\s+/).includes(".admin") })
      i += 1
      continue
    }
    const any = ANY_HEADING.exec(trimmed)
    if (any) {
      out.push({ t: "subheading", c: parseInline(any[2]) })
      i += 1
      continue
    }
    // callout / quote
    if (trimmed.startsWith(">")) {
      const inner: string[] = []
      while (i < lines.length && lines[i].trim().startsWith(">")) {
        inner.push(lines[i].trim().replace(/^>\s?/, ""))
        i += 1
      }
      let kind: CalloutKind = "note"
      const m = inner.length ? CALLOUT.exec(inner[0].trim()) : null
      if (m) {
        const k = m[1].toUpperCase()
        kind = k === "TIP" ? "tip" : k === "WARNING" || k === "CAUTION" || k === "IMPORTANT" ? "warning" : "note"
        inner.shift()
      }
      out.push({ t: "callout", kind, blocks: parseBlocks(inner) })
      continue
    }
    // table: a row of cells followed by the |---| line
    if (trimmed.startsWith("|") && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1])) {
      const head = splitRow(trimmed)
      const align = splitRow(lines[i + 1].trim()).map((c) => (c.startsWith(":") && c.endsWith(":") ? "center" : c.endsWith(":") ? "right" : "left") as "left" | "center" | "right")
      i += 2
      const rows: Inline[][][] = []
      while (i < lines.length && lines[i].trim().startsWith("|")) {
        const cells = splitRow(lines[i].trim())
        rows.push(head.map((_, n) => parseInline(cells[n] ?? "")))
        i += 1
      }
      out.push({ t: "table", head: head.map((c) => parseInline(c)), rows, align: head.map((_, n) => align[n] ?? "left") })
      continue
    }
    // list: items at this indent; everything indented deeper (or a lazy continuation line) belongs to the item above
    const marker = MARKER.exec(line)
    if (marker) {
      const base = marker[1].length
      const ordered = /\d/.test(marker[2])
      const items: Block[][] = []
      const start = ordered ? parseInt(marker[2], 10) : 1
      while (i < lines.length) {
        // blank lines between two items of the same list (a "loose" list) do not end it
        let j = i
        while (j < lines.length && !lines[j].trim()) j += 1
        const next = j < lines.length ? MARKER.exec(lines[j]) : null
        if (j > i && next && next[1].length === base && /\d/.test(next[2]) === ordered) i = j
        const m = MARKER.exec(lines[i] ?? "")
        if (!m || m[1].length !== base || /\d/.test(m[2]) !== ordered) break
        const content = base + m[2].length + 1
        const itemLines = [m[3]]
        i += 1
        while (i < lines.length) {
          const l = lines[i]
          if (!l.trim()) {
            // a blank line: the item goes on only if something indented follows
            let j = i + 1
            while (j < lines.length && !lines[j].trim()) j += 1
            if (j < lines.length && indentOf(lines[j]) > base) {
              for (; i < j; i += 1) itemLines.push("")
              continue
            }
            break
          }
          const ind = indentOf(l)
          if (ind <= base) {
            // lazy continuation of the item's paragraph (not a new block)
            if (ind === base || startsBlock(l, lines[i + 1]) || !itemLines[itemLines.length - 1].trim()) break
          }
          itemLines.push(l.slice(Math.min(ind, content)))
          i += 1
        }
        items.push(parseBlocks(itemLines))
      }
      out.push({ t: "list", ordered, start, items })
      continue
    }
    // paragraph: up to a blank line or the start of another block
    const para: string[] = [trimmed]
    i += 1
    while (i < lines.length && lines[i].trim() && !startsBlock(lines[i], lines[i + 1])) {
      para.push(lines[i].trim())
      i += 1
    }
    out.push({ t: "para", c: parseInline(para.join(" ")) })
  }
  return out
}

/** "| a | `b|c` | d \| e |" → cells; a | inside `code` or escaped as \| stays in the cell. */
function splitRow(row: string): string[] {
  const s = row.replace(/^\|/, "").replace(/\|\s*$/, "")
  const cells: string[] = []
  let cur = ""
  let code = false
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i]
    if (ch === "\\" && s[i + 1] === "|") {
      cur += "|"
      i += 1
    } else if (ch === "`") {
      code = !code
      cur += ch
    } else if (ch === "|" && !code) {
      cells.push(cur.trim())
      cur = ""
    } else cur += ch
  }
  cells.push(cur.trim())
  return cells
}

/** Inline Markdown → tokens: **bold**, *italic*, `code`, [text](target), {{live}}, \-escapes; the rest is text. */
export function parseInline(src: string, inLink = false): Inline[] {
  const out: Inline[] = []
  let buf = ""
  const flush = () => {
    if (buf) out.push({ t: "text", v: buf })
    buf = ""
  }
  let i = 0
  while (i < src.length) {
    const ch = src[i]
    if (ch === "\\" && i + 1 < src.length && /[\\`*_[\]{}()#+\-.!|>~]/.test(src[i + 1])) {
      buf += src[i + 1]
      i += 2
      continue
    }
    if (ch === "`") {
      // a run of n backticks closes at the next run of n
      let n = 1
      while (src[i + n] === "`") n += 1
      const fence = "`".repeat(n)
      const end = src.indexOf(fence, i + n)
      if (end > i + n - 1 && end !== -1) {
        flush()
        out.push({ t: "code", v: src.slice(i + n, end).replace(/^ (.*) $/, "$1") })
        i = end + n
        continue
      }
      buf += fence
      i += n
      continue
    }
    if (src.startsWith("{{", i)) {
      const end = src.indexOf("}}", i + 2)
      const name = end > 0 ? src.slice(i + 2, end).trim() : ""
      if (/^[a-z_]{1,40}$/.test(name)) {
        flush()
        out.push({ t: "live", name })
        i = end + 2
        continue
      }
    }
    if (src.startsWith("**", i)) {
      const end = findClose(src, "**", i + 2)
      if (end > i + 2) {
        flush()
        out.push({ t: "strong", c: parseInline(src.slice(i + 2, end), inLink) })
        i = end + 2
        continue
      }
    } else if (ch === "*" && src[i + 1] && src[i + 1] !== " ") {
      const end = findClose(src, "*", i + 1)
      if (end > i + 1 && src[end - 1] !== " ") {
        flush()
        out.push({ t: "em", c: parseInline(src.slice(i + 1, end), inLink) })
        i = end + 1
        continue
      }
    }
    if (ch === "[" && !inLink) {
      const close = findBracket(src, i)
      if (close > i && src[close + 1] === "(") {
        const end = src.indexOf(")", close + 2)
        if (end > close) {
          const href = src.slice(close + 2, end).trim()
          const label = parseInline(src.slice(i + 1, close), true)
          const kind = linkKind(href)
          flush()
          if (kind === "term") out.push({ t: "term", k: href.slice(5), c: label })
          else if (kind) out.push({ t: "link", kind, href, c: label })
          else out.push(...label) // not an allowed target: the text alone
          i = end + 1
          continue
        }
      }
    }
    buf += ch
    i += 1
  }
  flush()
  return out
}

/** The closing marker – not inside `code`. */
function findClose(src: string, marker: string, from: number): number {
  let i = from
  while (i < src.length) {
    if (src[i] === "`") {
      const end = src.indexOf("`", i + 1)
      if (end > i) {
        i = end + 1
        continue
      }
    }
    if (src.startsWith(marker, i) && (marker !== "*" || src[i + 1] !== "*")) return i
    if (marker === "*" && src.startsWith("**", i)) {
      const end = src.indexOf("**", i + 2)
      if (end > i) {
        i = end + 2
        continue
      }
    }
    i += 1
  }
  return -1
}

function findBracket(src: string, open: number): number {
  let depth = 0
  for (let i = open; i < src.length; i += 1) {
    if (src[i] === "\\") {
      i += 1
      continue
    }
    if (src[i] === "`") {
      const end = src.indexOf("`", i + 1)
      if (end > i) {
        i = end
        continue
      }
    }
    if (src[i] === "[") depth += 1
    else if (src[i] === "]") {
      depth -= 1
      if (depth === 0) return i
    }
  }
  return -1
}

/** {{name}} in a code block → the installation's value; an unknown name stays as written. */
export function fillLive(text: string, live: Record<string, string>): string {
  return text.replace(/\{\{\s*([a-z_]{1,40})\s*\}\}/g, (all, name: string) => (Object.hasOwn(live, name) ? live[name] : all))
}

// ---------------------------------------------------------------- search

export function inlineText(c: Inline[], live: Record<string, string> = {}): string {
  return c
    .map((x) => {
      if (x.t === "text") return x.v
      if (x.t === "code") return fillLive(x.v, live)
      if (x.t === "live") return live[x.name] ?? `{{${x.name}}}`
      return inlineText(x.c, live)
    })
    .join("")
}

function blockText(b: Block, live: Record<string, string>): string {
  switch (b.t) {
    case "heading":
      return ""
    case "subheading":
    case "para":
      return inlineText(b.c, live)
    case "list":
      return b.items.map((it) => it.map((x) => blockText(x, live)).join(" ")).join(" ")
    case "code":
      return fillLive(b.text, live)
    case "table":
      return [b.head, ...b.rows].map((r) => r.map((c) => inlineText(c, live)).join(" ")).join(" ")
    case "callout":
      return b.blocks.map((x) => blockText(x, live)).join(" ")
  }
}

/** A chapter cut at its ## / ### headings – the units the search finds ("" = the text before the first heading). */
export type SectionText = { id: string; title: string; text: string }

export function sectionTexts(blocks: Block[], live: Record<string, string> = {}): SectionText[] {
  const out: SectionText[] = [{ id: "", title: "", text: "" }]
  for (const b of blocks) {
    if (b.t === "heading") out.push({ id: b.id, title: b.text, text: "" })
    else {
      const cur = out[out.length - 1]
      cur.text = `${cur.text} ${blockText(b, live)}`.trim()
    }
  }
  return out.filter((s) => s.id || s.text)
}

/** Case- and accent-insensitive form for matching ("Überblick" finds "uberblick") – character by character, so the
 * folded text has the same length as the original (the highlighting relies on it). */
export function fold(s: string): string {
  let out = ""
  for (const ch of s) {
    const lower = ch.toLowerCase()
    const base = lower.normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
    out += base.length === lower.length && base.length === ch.length ? base : lower.length === ch.length ? lower : ch
  }
  return out
}

export type SearchHit = { chapter: string; section: string; title: string; snippet: string; score: number }

/** Every section in which all words of the query occur (title hits first); snippet: the text around the first word. */
export function searchSections(chapters: { id: string; title: string; sections: SectionText[] }[], query: string, limit = 40): SearchHit[] {
  const words = fold(query)
    .split(/\s+/)
    .filter((w) => w.length >= 2)
  if (words.length === 0) return []
  const hits: SearchHit[] = []
  for (const ch of chapters) {
    for (const s of ch.sections) {
      const title = s.title || ch.title
      const hay = fold(`${title} ${s.text}`)
      if (!words.every((w) => hay.includes(w))) continue
      const inTitle = words.filter((w) => fold(title).includes(w)).length
      hits.push({ chapter: ch.id, section: s.id, title, snippet: snippet(s.text, words[0]), score: inTitle * 10 + (s.id ? 0 : -1) })
    }
  }
  return hits.sort((a, b) => b.score - a.score).slice(0, limit)
}

function snippet(text: string, word: string, size = 160): string {
  const at = fold(text).indexOf(word)
  if (at < 0) return text.length > size ? `${text.slice(0, size).replace(/\s+\S*$/, "")} …` : text
  const from = Math.max(0, at - 50)
  const cut = text.slice(from, from + size)
  return `${from > 0 ? "… " : ""}${cut}${from + size < text.length ? " …" : ""}`
}

/** A text split at the query's words – for highlighting with <mark> (as React text, never markup). */
export function highlightParts(text: string, query: string): { text: string; hit: boolean }[] {
  const words = fold(query)
    .split(/\s+/)
    .filter((w) => w.length >= 2)
  if (!words.length) return [{ text, hit: false }]
  const folded = fold(text)
  const marks = new Array<boolean>(text.length).fill(false)
  for (const w of words) {
    let at = folded.indexOf(w)
    while (at >= 0) {
      for (let k = at; k < at + w.length; k += 1) marks[k] = true
      at = folded.indexOf(w, at + w.length)
    }
  }
  const parts: { text: string; hit: boolean }[] = []
  for (let k = 0; k < text.length; k += 1) {
    const last = parts[parts.length - 1]
    if (last && last.hit === marks[k]) last.text += text[k]
    else parts.push({ text: text[k], hit: marks[k] })
  }
  return parts
}
