import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"

/** The small headings a version's notes sit under, in the order the changelog uses them (app/changelog.py KINDS). */
export const CHANGE_KINDS = ["neu", "verbessert", "fixes", "sicherheit", "entfernt", "betrieb"] as const
export type ChangeKind = (typeof CHANGE_KINDS)[number]

/** One heading of a version with its items – "other": a heading the changelog does not define (its text is shown), or
 * the unnamed group of items before the first heading (heading ""). */
export type ChangelogGroup = { kind: ChangeKind | "other"; heading: string; items: string[] }

/** One version's notes from CHANGELOG.md (parsed on the server, app/changelog.py); items: all of them, without
 * headings. */
export type ChangelogEntry = { version: string; title: string; groups?: ChangelogGroup[]; items: string[] }
/** catalog_version: the Vendor News catalogue data (backend/app/catalog) – versioned on its own */
export type Changelog = { version: string; catalog_version?: string; entries: ChangelogEntry[] }

/** The groups to render – a server without groups (or an entry without headings): all items as one unnamed group. */
export function entryGroups(entry: ChangelogEntry): ChangelogGroup[] {
  const groups = (entry.groups ?? []).filter((g) => g.items.length > 0)
  if (groups.length > 0) return groups
  return entry.items.length > 0 ? [{ kind: "other", heading: "", items: entry.items }] : []
}

export type KindCount = { kind: ChangeKind | "other"; count: number }

/** How many changes of each kind – for the folded header ("3 neu · 5 Fixes"): the known kinds in changelog order, the
 * rest summed up as "other" at the end. */
export function kindCounts(entry: ChangelogEntry): KindCount[] {
  const counts = new Map<ChangeKind | "other", number>()
  for (const g of entryGroups(entry)) {
    const kind = (CHANGE_KINDS as readonly string[]).includes(g.kind) ? g.kind : "other"
    counts.set(kind, (counts.get(kind) ?? 0) + g.items.length)
  }
  return [...CHANGE_KINDS, "other" as const].filter((k) => counts.has(k)).map((kind) => ({ kind, count: counts.get(kind) ?? 0 }))
}

/** The running version and the changelog bundled with it – they do not change while the build runs. */
export function useChangelog() {
  return useQuery({ queryKey: ["changelog"], queryFn: () => api.get<Changelog>("/api/changelog"), staleTime: Infinity })
}

/** The running version's notes first, the others below (in file order: newest first). */
export function splitChangelog(data: Changelog): { current: ChangelogEntry | null; older: ChangelogEntry[] } {
  const current = data.entries.find((e) => e.version === data.version) ?? null
  return { current, older: data.entries.filter((e) => e !== current) }
}

export type InlineToken = { kind: "text" | "code"; text: string; bold: boolean }

/**
 * The little markdown a changelog line uses – **bold** and `code` – as tokens; everything else stays plain text (no
 * HTML, no links: rendered as React text, never as markup). An unclosed ** or ` is shown as it is. Code inside bold
 * stays code; ** inside code is literal.
 */
export function inlineTokens(line: string): InlineToken[] {
  const out: InlineToken[] = []
  const push = (kind: InlineToken["kind"], text: string, bold: boolean) => {
    if (!text) return
    const last = out[out.length - 1]
    if (last && last.kind === "text" && kind === "text" && last.bold === bold) last.text += text
    else out.push({ kind, text, bold })
  }
  let bold = false
  let i = 0
  let plain = ""
  const flush = () => {
    push("text", plain, bold)
    plain = ""
  }
  while (i < line.length) {
    if (line[i] === "`") {
      const end = line.indexOf("`", i + 1)
      if (end > i + 1) {
        flush()
        push("code", line.slice(i + 1, end), bold)
        i = end + 1
        continue
      }
    } else if (line.startsWith("**", i)) {
      // opens only when a closing ** follows (outside code); closes what is open
      if (bold || hasClosingBold(line, i + 2)) {
        flush()
        bold = !bold
        i += 2
        continue
      }
    }
    plain += line[i]
    i += 1
  }
  flush()
  return out
}

function hasClosingBold(line: string, from: number): boolean {
  let i = from
  while (i < line.length) {
    if (line[i] === "`") {
      const end = line.indexOf("`", i + 1)
      if (end > i + 1) {
        i = end + 1
        continue
      }
    }
    if (line.startsWith("**", i)) return i > from
    i += 1
  }
  return false
}
