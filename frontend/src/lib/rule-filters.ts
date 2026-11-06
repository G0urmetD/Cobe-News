import type { NotifyRule, RuleKind } from "@/lib/admin-api"
import { isoList } from "@/lib/bidi"
import type { NewsSeverity, NewsTopic } from "@/lib/news-api"
import type { VendorProduct } from "@/lib/vendor-api"

// The rules' "Betrifft" (systems of the catalogue and own words) and "Nicht senden, wenn enthalten" – the pure helpers
// of the rule editor and the rules list (backend app/systems.py, app/keywords.py; tested in rule-filters.test.ts).

/** A system of a rule: a catalogue vendor (all of its products, also those added later) or one product. */
export type RuleSystem = { vendor: string } | { product: string }

/** The kinds a rule's severities apply to (versions, EOL and source health have their own). */
export const SEVERITY_KINDS: RuleKind[] = ["news", "vendor_vuln", "vendor_change"]
/** The kinds the systems apply to (news by their details or names, Vendor News events by their product). */
export const SYSTEM_KINDS: RuleKind[] = ["news", "vendor_vuln", "vendor_version", "vendor_change"]

export const WORDS_MAX = 30
export const WORD_MIN = 2
export const WORD_MAX = 60
export const SYSTEMS_MAX = 50
// as the server takes them (app/keywords.py ALLOWED): letters, digits, blanks and . + # & / : ' @ ! -
const ALLOWED = /^[\p{L}\p{N}_ .+#&/:'@!-]+$/u
const ALNUM = /[\p{L}\p{N}]/u

// what Python's str.casefold() folds beyond toLowerCase: "ß" (and "ẞ", lowered to it) → "ss", the final "ς" → "σ", the
// long "ſ" → "s"; the iota subscript (also out of "ᾳ" by NFKD) → "ι" – a letter there, not a mark that is dropped
const CASEFOLD: Record<string, string> = { ß: "ss", ς: "σ", ſ: "s", "\u0345": "ι" }

/** Case and accents ignored – as the server folds (db.fold: casefold, then NFKD, combining marks dropped). */
export const fold = (s: string) =>
  s
    .toLowerCase()
    .replace(/[ßςſ]/g, (c) => CASEFOLD[c])
    .normalize("NFKD")
    .replace(/\u0345/g, CASEFOLD["\u0345"])
    .replace(/\p{M}/gu, "")

/** A vendor as the server compares it ("Red Hat" and "Redhat" are one): folded, letters and digits only. */
export const vendorId = (name: string) => fold(name).replace(/[^a-z0-9]/g, "")

/** The value of a system in the picker – "v:<vendor>" or "p:<key>". */
export const systemValue = (s: RuleSystem) => ("vendor" in s ? `v:${s.vendor}` : `p:${s.product}`)

export function systemOf(value: string): RuleSystem | null {
  if (value.startsWith("v:") && value.length > 2) return { vendor: value.slice(2) }
  if (value.startsWith("p:") && value.length > 2) return { product: value.slice(2) }
  return null
}

export interface CatalogVendor {
  /** the server's vendor identity (vendor_group) – else vendorId() of its spelling */
  id: string
  /** the name shown: the server's (vendor_group_name), else the spelling most of its products have */
  name: string
  /** vendorId() of every spelling of its products, and its id – a stored rule may name it by any of them */
  aliases: string[]
  /** every spelling of its products (searched by them too) */
  names: string[]
  products: { key: string; label: string }[]
}

/**
 * The catalogue by vendor (custom products left out – they are no catalogue products), each vendor's products by label.
 * One vendor under several spellings ("VMware" and "Broadcom (VMware)") is one: the server says which (vendor_group).
 */
export function catalogVendors(products: Pick<VendorProduct, "key" | "label" | "vendor" | "custom" | "vendor_group" | "vendor_group_name">[]): CatalogVendor[] {
  const by = new Map<string, { group?: string; names: Map<string, number>; products: { key: string; label: string }[] }>()
  for (const p of products) {
    if (p.custom || !p.vendor) continue
    const id = p.vendor_group || vendorId(p.vendor)
    if (!id) continue
    const v = by.get(id) ?? { names: new Map<string, number>(), products: [] as { key: string; label: string }[] }
    v.group ||= p.vendor_group_name || undefined
    v.names.set(p.vendor, (v.names.get(p.vendor) ?? 0) + 1)
    v.products.push({ key: p.key, label: p.label })
    by.set(id, v)
  }
  return [...by.entries()]
    .map(([id, v]) => {
      const names = [...v.names.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([n]) => n)
      const name = v.group ?? names[0]
      return {
        id,
        name,
        aliases: [...new Set([id, ...[name, ...names].map(vendorId)])],
        names: [...new Set([name, ...names])],
        products: v.products.sort((a, b) => a.label.localeCompare(b.label)),
      }
    })
    .sort((a, b) => a.name.localeCompare(b.name))
}

/** The catalogue vendor a stored rule's vendor stands for – under any of its spellings; undefined: no longer known. */
export const vendorOf = (vendors: CatalogVendor[], name: string) => {
  const id = vendorId(name)
  return id ? vendors.find((v) => v.aliases.includes(id)) : undefined
}

type T = (key: string, opts?: Record<string, unknown>) => string

/** A system by its name: the product's label, a vendor "(alle)" – null: the catalogue no longer knows it. */
export function systemName(t: T, s: RuleSystem, vendors: CatalogVendor[] | undefined): string | null {
  if (!vendors) return "vendor" in s ? s.vendor : s.product
  if ("vendor" in s) {
    const v = vendorOf(vendors, s.vendor)
    return v ? t("notify.systemsVendorChip", { vendor: v.name }) : null
  }
  for (const v of vendors) {
    const p = v.products.find((x) => x.key === s.product)
    if (p) return p.label
  }
  return null
}

/** The words as the server keeps them: trimmed, single blanks, each once (case and accents ignored). */
export const normalizeWord = (w: string) => w.split(/\s+/).filter(Boolean).join(" ")

/** Why a word cannot be added (an i18n key) – null: it can. */
export function wordProblem(word: string, list: string[]): string | null {
  const w = normalizeWord(word)
  if (w.length < WORD_MIN || w.length > WORD_MAX) return "notify.wordLength"
  if (!ALLOWED.test(w) || !ALNUM.test(w)) return "notify.wordChars"
  if (list.some((x) => fold(x) === fold(w))) return "notify.wordTwice"
  if (list.length >= WORDS_MAX) return "notify.wordsMax"
  return null
}

/** The words typed into a chip field: a comma ends one ("Bleed, Ransomware" → two). */
export const splitWords = (text: string) => text.split(",").map(normalizeWord).filter(Boolean)

interface Applicable {
  severities: NewsSeverity[]
  sources: string[]
  topics?: NewsTopic[]
  kinds: RuleKind[]
  systems?: RuleSystem[]
  keywords?: string[]
  exclude?: string[]
}

/**
 * A rule with only what applies to its kinds – what the editor shows: severities with news, vulnerabilities and revised
 * advisories; sources, topics, words and exclusions with news; systems with news and Vendor News. The rest empty (the
 * server: no restriction), so a field hidden for the chosen kinds is neither saved nor tried in the dry run.
 */
export function applicable<R extends Applicable>(r: R): R & Required<Applicable> {
  const news = r.kinds.includes("news")
  return {
    ...r,
    severities: r.kinds.some((k) => SEVERITY_KINDS.includes(k)) ? r.severities : [],
    sources: news ? r.sources : [],
    topics: news ? (r.topics ?? []) : [],
    systems: r.kinds.some((k) => SYSTEM_KINDS.includes(k)) ? (r.systems ?? []) : [],
    keywords: news ? (r.keywords ?? []) : [],
    exclude: news ? (r.exclude ?? []) : [],
  }
}

export interface SummaryContext {
  sourceName: (id: string) => string | undefined
  teamNames: string[]
  vendors: CatalogVendor[] | undefined
}

/**
 * The rules list's line of a rule: its kinds, then only what applies to them – severities (news, vulnerabilities,
 * revised advisories), sources and topics (news), systems and words, teams – and its language.
 */
export function ruleSummary(t: T, r: Pick<NotifyRule, "kinds" | "severities" | "sources" | "topics" | "lang" | "systems" | "keywords" | "exclude">, ctx: SummaryContext): string {
  const news = r.kinds.includes("news")
  const parts = [r.kinds.map((k) => t(`notify.kind.${k}`)).join(", ")]
  if (r.kinds.some((k) => SEVERITY_KINDS.includes(k))) parts.push(r.severities.length ? r.severities.map((s) => t(`news.sev.${s}`)).join(", ") : t("notify.allSeverities"))
  if (news) {
    const names = r.sources.map(ctx.sourceName).filter((x): x is string => !!x)
    parts.push(names.length ? isoList(names) : t("notify.allSources"))
    if (r.topics?.length) parts.push(t("notify.topicsList", { names: r.topics.map((x) => t(`news.topic.${x}`)).join(", ") }))
  }
  const systems = r.kinds.some((k) => SYSTEM_KINDS.includes(k)) ? (r.systems ?? []).map((s) => systemName(t, s, ctx.vendors) ?? t("notify.systemGone")) : []
  const words = news ? (r.keywords ?? []) : []
  const quoted = (w: string) => t("notify.quoted", { word: w })
  if (systems.length || words.length) parts.push(t("notify.concernsList", { names: [isoList(systems), ...words.map(quoted)].filter(Boolean).join(", ") }))
  if (news && r.exclude?.length) parts.push(t("notify.excludeList", { names: r.exclude.map(quoted).join(", ") }))
  if (ctx.teamNames.length) parts.push(t("notify.teamsList", { names: isoList(ctx.teamNames) }))
  parts.push(r.lang === "en" ? "English" : "Deutsch")
  return parts.join(" · ")
}

/** The rule's sources that are switched off – a rule naming only those brings no story. */
export function offSources(chosen: string[], sources: { id: string; enabled: boolean }[]): { off: string[]; onlyOff: boolean } {
  const known = chosen.filter((id) => sources.some((s) => s.id === id))
  const off = known.filter((id) => !sources.find((s) => s.id === id)?.enabled)
  return { off, onlyOff: known.length > 0 && off.length === known.length }
}
