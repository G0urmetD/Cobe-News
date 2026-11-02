import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { polled } from "@/lib/poll"
import { matchScore, type VendorProduct } from "@/lib/vendor-api"

/*
 * "Produkt vorschlagen" (backend app/catalog_care.py): a reader suggests a product the catalogue lacks; admins answer
 * (Übernehmen, Ablehnen, Doppelt). Everything is plain text – an address is a link only when it is http(s).
 */

export type SuggestionStatus = "open" | "accepted" | "rejected" | "duplicate"

export interface Suggestion {
  id: string
  vendor: string
  product: string
  url: string | null
  cpe: string | null
  /** "a:vendor:product" of the CPE – what "add by CPE" takes */
  cpe_short: string | null
  reason: string
  team: { id: string; name: string } | null
  status: SuggestionStatus
  answer: string
  /** accepted: the product added (null: for the bundled catalogue) · duplicate: the existing product */
  result: { key: string; label: string } | null
  created_at: string | null
  decided_at: string | null
  seen: boolean
  /** the admins' list only */
  by?: string | null
  decided_by?: string | null
}

export interface SuggestionIn {
  vendor: string
  product: string
  url?: string | null
  cpe?: string | null
  reason: string
  team_id?: string | null
}

export const SUGGEST_LIMITS = { vendor: 80, product: 120, url: 500, cpe: 200, reason: 1000 } as const

export const SUGGESTIONS_KEY = ["vendor", "suggestions"] as const

export const useMySuggestions = (enabled = true) =>
  useQuery({
    queryKey: [...SUGGESTIONS_KEY, "mine"],
    queryFn: () => api.get<{ items: Suggestion[]; per_day: number }>("/api/vendor/suggestions/mine"),
    enabled,
    staleTime: 30_000,
  })

export const useSuggestionQueue = (state: "open" | "done", enabled = true) =>
  useQuery({
    queryKey: [...SUGGESTIONS_KEY, "queue", state],
    queryFn: () => api.get<{ items: Suggestion[] }>(`/api/admin/suggestions?state=${state}`),
    enabled,
    staleTime: 30_000,
  })

/** The numbers on the tab: answers not seen yet, and for admins the open queue (null for readers). */
export const useSuggestionCount = () =>
  useQuery({
    queryKey: [...SUGGESTIONS_KEY, "count"],
    queryFn: polled<{ answered: number; open: number | null }>((o) => api.get("/api/vendor/suggestions/count", o)),
    staleTime: 60_000,
    refetchInterval: 5 * 60_000,
  })

/** The address as a link target – only http(s) with a host (anything else is shown as text, never as a link). */
export function safeHttpUrl(url: string | null | undefined): string | null {
  if (!url) return null
  try {
    const u = new URL(url)
    if ((u.protocol !== "http:" && u.protocol !== "https:") || !u.hostname || u.username || u.password) return null
    return u.href
  } catch {
    return null
  }
}

const CPE = /^(?:cpe:2\.3:)?[aoh]:[^:\s]+:[^:\s]+(?::[^:\s]*){0,10}$/i

export type SuggestProblem = "vendor" | "product" | "url" | "cpe" | "reason"

/** What the form must fix before it can be sent (the server checks the same). */
export function suggestProblems(s: SuggestionIn): SuggestProblem[] {
  const out: SuggestProblem[] = []
  const v = s.vendor.trim()
  const p = s.product.trim()
  const r = s.reason.trim()
  if (v.length < 2 || v.length > SUGGEST_LIMITS.vendor) out.push("vendor")
  if (p.length < 2 || p.length > SUGGEST_LIMITS.product) out.push("product")
  const url = (s.url ?? "").trim()
  if (url && (url.length > SUGGEST_LIMITS.url || !safeHttpUrl(url) || /\s/.test(url))) out.push("url")
  const cpe = (s.cpe ?? "").trim()
  if (cpe && (cpe.length > SUGGEST_LIMITS.cpe || !CPE.test(cpe))) out.push("cpe")
  if (r.length < 3 || r.length > SUGGEST_LIMITS.reason) out.push("reason")
  return out
}

/** "Meinst du …?": catalogue products like the one typed – by name, then by vendor and name together. */
export function similarProducts(products: VendorProduct[], vendor: string, product: string, limit = 5): VendorProduct[] {
  const name = product.trim()
  if (name.length < 2) return []
  const both = `${vendor.trim()} ${name}`.trim()
  const scored = products
    .map((p) => ({ p, s: Math.max(matchScore(p, name), matchScore(p, both) * 1.2) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s || a.p.label.localeCompare(b.p.label))
  return scored.slice(0, limit).map((x) => x.p)
}

/** An entry for the bundled catalogue data (backend/app/catalog/products/<category>.yaml) – a starting point. */
export function yamlSnippet(s: Pick<Suggestion, "vendor" | "product" | "cpe_short">): string {
  const key =
    `${s.vendor} ${s.product}`
      .normalize("NFKD")
      .replace(/[̀-ͯ]/g, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 64) || "product"
  const q = (x: string) => (/^[\w .()&+-]+$/.test(x) && !/^[\s&*!|>'"%@`#,[\]{}?:-]/.test(x) ? x : JSON.stringify(x))
  return [`- key: ${key}`, `  label: ${q(s.product)}`, `  vendor: ${q(s.vendor)}`, `  cpes: [${s.cpe_short ?? ""}]`].join("\n")
}

/** After "Als Produkt per CPE anlegen" added it: the suggestion is accepted with that product. */
export async function acceptWith(s: Pick<Suggestion, "id">, key: string): Promise<void> {
  await api.post(`/api/admin/suggestions/${encodeURIComponent(s.id)}/accept`, { product_key: key })
}
