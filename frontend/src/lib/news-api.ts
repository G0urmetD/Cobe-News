import { useInfiniteQuery, useMutation, useQuery, useQueryClient, type InfiniteData, type QueryKey } from "@tanstack/react-query"
import { api, DETAIL_TIMEOUT_MS, detailRetry } from "@/lib/api"
import { polledPages } from "@/lib/poll"
import type { Epss, ExploitHint, Ssvc } from "@/lib/vendor-api"
import type { AdvisoryChange } from "@/lib/advisory-changes"

export type NewsSeverity = "critical" | "high" | "medium" | "low" | "info"
export const NEWS_SEVERITIES: NewsSeverity[] = ["critical", "high", "medium", "low", "info"]
export const NEWS_SEV_COLOR: Record<NewsSeverity, string> = {
  critical: "--sev-critical",
  high: "--sev-high",
  medium: "--sev-medium",
  low: "--sev-low",
  info: "--muted-foreground",
}

/** The topics of a story (backend news.TOPICS – detected in title and teaser and from structured data). The order is
 *  the order of a card's badges: the first two are shown. */
export type NewsTopic = "zeroday" | "exploited" | "poc" | "ransomware" | "nopatch" | "breach" | "supply" | "phishing" | "ot"
export const NEWS_TOPICS: NewsTopic[] = ["zeroday", "exploited", "poc", "ransomware", "nopatch", "breach", "supply", "phishing", "ot"]
/** The quick filters above the list (one click, also on a phone). */
export const QUICK_TOPICS: NewsTopic[] = ["exploited", "zeroday", "nopatch"]
export const NEWS_TOPIC_COLOR: Record<NewsTopic, string> = {
  zeroday: "--sev-critical",
  exploited: "--sev-critical",
  poc: "--sev-high",
  ransomware: "--sev-high",
  nopatch: "--sev-high",
  breach: "--sev-medium",
  supply: "--sev-medium",
  phishing: "--sev-low",
  ot: "--sev-low",
}
export const isTopic = (x: unknown): x is NewsTopic => NEWS_TOPICS.includes(x as NewsTopic)

/** A story's topics as a card shows them: in badge order, at most `max`, and how many more there are. */
export function cardTopics(topics: readonly string[] | undefined, max = 2): { shown: NewsTopic[]; more: number } {
  const all = NEWS_TOPICS.filter((t) => (topics ?? []).includes(t))
  return { shown: all.slice(0, max), more: Math.max(0, all.length - max) }
}

export interface NewsSourceRef {
  id: string
  key: string
  name: string
  /** the server holds an icon of the site (it fetched it once – the browser loads nothing from the news site) */
  logo: boolean
  /** the kind of source (only in /api/news/sources): the groups of the source filter */
  category?: NewsCategory
}

export interface NewsItem {
  id: string
  title: string
  summary: string
  url: string
  source: NewsSourceRef
  published_at: string
  severity: NewsSeverity
  cves: string[]
  /** further sources with the same story (it is shown once) */
  also_in: string[]
  /** the story's topics (NEWS_TOPICS order) */
  topics?: NewsTopic[]
  /** the followed products the story's details concern ("Unser Produkt: PAN-OS") – lists and the drawer */
  products?: { key: string; label: string }[]
  read_at: string | null
  /** unread for me (app/reader.py: the watermark, my marks, the age) – absent where it is not asked (/news/recent) */
  unread?: boolean | null
  /** all of its CVEs are muted by me (listed only with "Stummgeschaltete zeigen") */
  muted?: boolean
  /** from the story's details (CSAF / NVD): CVSS, the first affected product with its range, a followed product affected */
  hint?: { cvss: number | null; product: string | null; exploited: boolean; affects?: boolean } | null
}

export interface NewsReason {
  /** kev / euvd: in the catalog of exploited vulnerabilities (value: due date / exploited since), vendor: the PSIRT's rating */
  kind: "cvss" | "bsi" | "vendor" | "kev" | "euvd" | "ransomware" | "exploited" | "impact" | "vulnerability" | "topic"
  value: string
  /** found only in the article text, not in title or teaser – counted one level lower */
  in_text?: boolean
}

export interface DetailRange {
  text: string
  from?: string
  to?: string
  exact?: string
  line?: string
  all?: boolean
}

export interface DetailProduct {
  vendor: string
  name: string
  cpe: string
  affected: DetailRange[]
  fixed: string[]
  not_affected: string[]
}

/** Details aus der Quelle: the structured advisory behind a story (BSI/Siemens/Cisco/Fortinet CSAF, Palo Alto, NVD). */
export interface StoryDetails {
  kind: "bsi" | "siemens" | "cisco" | "fortinet" | "paloalto" | "veeam" | "kev" | "euvd" | "nvd"
  publisher: string
  /** CVSS, ranges and fixes come from the NVD (no structured advisory of the publisher) */
  via_nvd?: boolean
  /** … and, for CVEs the NVD has not analysed yet, from the CVE records of cvelistV5 (the CNA, CISA's ADP) */
  via_cvelist?: boolean
  ssvc?: Ssvc | null
  id: string
  title: string
  severity_text: string
  summary: string
  products: DetailProduct[]
  more_products: number
  cves: string[]
  cvss: { score: number; temporal: number | null; vector: string; version: string; cve?: string; nvd?: boolean }[]
  exploited: boolean
  remote: boolean | null
  mitigation: boolean | null
  remediations: { category: string; text: string; url: string }[]
  revision: { current: string; initial: string; version: string; summary: string; count: number }
  kev?: { added: string; due: string; ransomware: boolean } | null
}

export interface StoryAffects {
  product: string
  label: string
  versions: {
    id: string | null
    version: string | null
    label: string
    status: "affected" | "possible" | "not_affected" | "unversioned" | "service"
    fixed: string | null
    reason: string
  }[]
}

/** Why a story has a topic: catalog (CISA KEV / ENISA EUVD), kev (the KEV lists a CVE of it), details (Details aus der
 *  Quelle say exploited), csaf (no fix available), source (an OT source), title / teaser (the words found), zeroday,
 *  kev_flag (CISA: ransomware campaigns) */
export interface TopicReason {
  topic: NewsTopic
  kind: "catalog" | "kev" | "details" | "csaf" | "source" | "title" | "teaser" | "zeroday" | "kev_flag" | "exploit" | "ssvc"
  value: string
}

export interface NewsDetail extends NewsItem {
  content_html: string
  reasons: NewsReason[]
  topic_reasons?: TopicReason[]
  details: StoryDetails | null
  details_state: "pending" | "ok" | "none" | "error"
  affects: StoryAffects[]
  /** FIRST EPSS of the story's CVEs (those asked so far), the likeliest first */
  epss?: Epss[]
  /** the revisions of the advisory behind the story (Vendor News keeps them), newest first */
  changes?: AdvisoryChange[]
  /** public exploits for the story's CVEs (switched-on exploit lists – app/exploits.py) */
  exploits?: ExploitHint[]
}

export interface NewsPage {
  items: NewsItem[]
  more: boolean
  /** cursor of the next page (time and id of this page's last story) */
  next: string | null
  /** only on the first page; `topics`: stories per topic with every other filter (not the topic filter itself);
   *  `ours`: the stories about our products with every other filter */
  counts?: { new: number; read: number; topics?: Partial<Record<NewsTopic, number>>; ours?: number }
  /** anything followed (in the scope asked) – "Betrifft unsere Produkte" has something to show */
  ours_on?: boolean
  enabled: boolean
  /** the arrival number of the newest story stored when this page was read – "all read" marks up to it */
  upto?: number
}

/** The body of "Alle als gelesen": the list's filter, and only what had arrived when its first page was loaded (a
 *  story arriving meanwhile was not counted in the dialog and was never seen – it stays new). */
export function readAllBody(
  f: { sources: string[]; severities: string[]; topics?: string[]; q: string; muted?: boolean; ours?: boolean; scope?: "all" | "team" },
  first: NewsPage | undefined,
) {
  return {
    source: f.sources,
    severity: f.severities,
    ...(f.topics?.length ? { topic: f.topics } : {}),
    ...(f.ours ? { ours: true, scope: f.scope ?? "all" } : {}),
    q: f.q,
    ...(f.muted ? { muted: true } : {}),
    ...(first?.upto !== undefined ? { upto: first.upto } : {}),
  }
}

export interface NewsFilter {
  /** all stories, only the unread ones ("Nur ungelesene"), only the read ones */
  state: "all" | "new" | "read"
  sources: string[]
  severities: NewsSeverity[]
  /** one of these topics (OR) */
  topics?: NewsTopic[]
  q?: string
  /** also the stories whose CVEs I all muted (dimmed) */
  muted?: boolean
  /** "Betrifft unsere Produkte": only stories about a followed product – of my teams under "Mein Team" */
  ours?: boolean
  scope?: "all" | "team"
}

const PAGE = 60

export function newsQuery(f: NewsFilter, before: string | null) {
  const p = new URLSearchParams({ state: f.state, limit: String(PAGE) })
  // the next pages by cursor: stories arriving or read meanwhile neither repeat nor skip one; counts only once
  if (before) {
    p.set("before", before)
    p.set("counts", "false")
  }
  for (const s of f.sources) p.append("source", s)
  for (const s of f.severities) p.append("severity", s)
  for (const s of f.topics ?? []) p.append("topic", s)
  if (f.q?.trim()) p.set("q", f.q.trim().slice(0, 100))
  if (f.muted) p.set("muted", "true")
  if (f.ours) p.set("ours", "true")
  // the scope counts for "Betrifft unsere Produkte" (the filter and its number on the chip)
  if (f.scope === "team") p.set("scope", "team")
  return `/api/news?${p.toString()}`
}

/** All loaded pages as one list – a story is listed once, even if it moved from one page onto the next. */
export function mergePages(pages: NewsPage[] | undefined): NewsItem[] {
  const seen = new Set<string>()
  const out: NewsItem[] = []
  for (const p of pages ?? [])
    for (const i of p.items)
      if (!seen.has(i.id)) {
        seen.add(i.id)
        out.push(i)
      }
  return out
}

export const useNews = (f: NewsFilter, enabled = true) =>
  useInfiniteQuery({
    queryKey: ["news", "list", f],
    enabled,
    queryFn: polledPages<NewsPage, string | null>((o, pageParam) => api.get(newsQuery(f, pageParam), o)),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => (last.more ? last.next : undefined),
    // another search or filter: the stories shown stay (dimmed) until the new ones are there – no flash of "Lädt …" per
    // keystroke. Not across the tabs: "Gelesen" showing the new stories for a moment would be wrong.
    placeholderData: (prev, prevQuery) => ((prevQuery?.queryKey[2] as NewsFilter | undefined)?.state === f.state ? prev : undefined),
    staleTime: 30_000,
    // new stories arrive in the background – asked again while only the first page is loaded (a refetch would load
    // every page that was scrolled to, one after the other)
    refetchInterval: (q) => ((q.state.data?.pages.length ?? 0) > 1 ? false : 5 * 60_000),
  })

export const useNewsDetail = (id: string | null) =>
  useQuery({
    queryKey: ["news", "detail", id],
    queryFn: ({ signal }) => api.get<NewsDetail>(`/api/news/${id}`, { signal, timeoutMs: DETAIL_TIMEOUT_MS }),
    enabled: !!id,
    retry: detailRetry,
    retryDelay: 1000,
  })

export const useNewsSources = () => useQuery({ queryKey: ["news", "sources"], queryFn: () => api.get<NewsSourceRef[]>("/api/news/sources"), staleTime: 300_000 })

/** The open list after marking one story: it leaves the list, the numbers of the first page follow (pure, tested). */
export function withoutStory(d: InfiniteData<NewsPage> | undefined, id: string, read: boolean): { data: InfiniteData<NewsPage> | undefined; listed: boolean } {
  if (!d?.pages?.[0]?.items) return { data: d, listed: false }
  const listed = d.pages.some((p) => p.items.some((i) => i.id === id))
  if (!listed) return { data: d, listed }
  return {
    listed,
    data: {
      ...d,
      pages: d.pages.map((p, n) => ({
        ...p,
        items: p.items.filter((i) => i.id !== id),
        counts: n === 0 && p.counts ? { new: p.counts.new + (read ? -1 : 1), read: p.counts.read + (read ? 1 : -1) } : p.counts,
      })),
    },
  }
}

/** Whether a list of this filter keeps a story of this read state (else it leaves the list when marked). */
export function listKeeps(state: NewsFilter["state"] | undefined, read: boolean): boolean {
  return state === "all" || state === undefined || (state === "new" ? !read : read)
}

/** One story marked in a loaded list that keeps it: its flag flips, the numbers follow – only when it changes (pure, tested). */
export function withRead(d: InfiniteData<NewsPage> | undefined, id: string, read: boolean): InfiniteData<NewsPage> | undefined {
  const at = findStory(d, id)
  if (!d || !at || !at.item.unread === read) return d
  const stamp = read ? new Date().toISOString() : null
  return {
    ...d,
    pages: d.pages.map((p, n) => ({
      ...p,
      items: p.items.map((i) => (i.id === id ? { ...i, unread: !read, read_at: stamp } : i)),
      counts: n === 0 && p.counts ? { new: Math.max(0, p.counts.new + (read ? -1 : 1)), read: Math.max(0, p.counts.read + (read ? 1 : -1)) } : p.counts,
    })),
  }
}

/** Where a story sits in a loaded list (page and position) – what an undo after an error needs. */
export interface StoryAt {
  page: number
  index: number
  item: NewsItem
}

export function findStory(d: InfiniteData<NewsPage> | undefined, id: string): StoryAt | null {
  for (const [page, p] of (d?.pages ?? []).entries()) {
    const index = p.items.findIndex((i) => i.id === id)
    if (index >= 0) return { page, index, item: p.items[index] }
  }
  return null
}

/**
 * Marking failed: the story comes back where it was and the numbers move back – only this story and only when it is
 * not listed again already (a refetch, another tab's change or a second click in between). Restoring a whole snapshot
 * instead brought back stories marked meanwhile and, with pages loaded since, listed stories twice (pure, tested).
 */
export function withStory(d: InfiniteData<NewsPage> | undefined, at: StoryAt, read: boolean): InfiniteData<NewsPage> | undefined {
  if (!d?.pages?.length || findStory(d, at.item.id)) return d
  const page = Math.min(at.page, d.pages.length - 1)
  return {
    ...d,
    pages: d.pages.map((p, n) => {
      const items = n === page ? [...p.items.slice(0, at.index), at.item, ...p.items.slice(at.index)] : p.items
      const counts = n === 0 && p.counts ? { new: p.counts.new + (read ? 1 : -1), read: p.counts.read + (read ? -1 : 1) } : p.counts
      return n === page || n === 0 ? { ...p, items, counts } : p
    }),
  }
}

/**
 * Read / unread: the story leaves the open list at once, the numbers follow. Nothing is reloaded but the numbers and
 * the story itself – ten clicks used to reload every loaded page ten times. Undo (the story is not listed any more)
 * and errors bring the list back from the server; an error first puts just that story back where it was.
 */
export function useMarkRead() {
  const qc = useQueryClient()
  return useMutation({
    // `keep`: opening a story marks it read – it stays where it is (also in "Nur ungelesene"), only its flag flips
    mutationFn: ({ id, read }: { id: string; read: boolean; keep?: boolean }) => (read ? api.post(`/api/news/${id}/read`) : api.del(`/api/news/${id}/read`)),
    onMutate: async ({ id, read, keep }) => {
      // a refetch still under way would put the story back
      await qc.cancelQueries({ queryKey: ["news", "list"] })
      const removed: { key: QueryKey; at: StoryAt }[] = []
      const flipped: QueryKey[] = []
      for (const [key, d] of qc.getQueriesData<InfiniteData<NewsPage>>({ queryKey: ["news", "list"] })) {
        const at = findStory(d, id)
        if (!at) continue
        const state = (key[2] as NewsFilter | undefined)?.state
        if (keep || listKeeps(state, read)) {
          flipped.push(key)
          qc.setQueryData(key, withRead(d, id, read))
        } else {
          removed.push({ key, at })
          qc.setQueryData(key, withoutStory(d, id, read).data)
        }
      }
      return { removed, flipped, listed: removed.length + flipped.length > 0 }
    },
    onError: (_e, { id, read }, ctx) => {
      for (const { key, at } of ctx?.removed ?? []) qc.setQueryData<InfiniteData<NewsPage>>(key, (d) => withStory(d, at, read))
      for (const key of ctx?.flipped ?? []) qc.setQueryData<InfiniteData<NewsPage>>(key, (d) => withRead(d, id, !read))
    },
    onSettled: (_d, err, { id }, ctx) => {
      // one count request for a burst of clicks: a refetch already under way is not started again
      void qc.invalidateQueries({ queryKey: ["reader", "counts"] }, { cancelRefetch: false })
      void qc.invalidateQueries({ queryKey: ["news", "detail", id] })
      // the other tab (Neu / Gelesen) is out of date: loaded again when shown, not now
      void qc.invalidateQueries({ queryKey: ["news", "list"], refetchType: err || !ctx?.listed ? "active" : "none" }, { cancelRefetch: false })
    },
  })
}

/** The groups of the source list in the settings – "custom": a feed an admin added. */
export type NewsCategory = "authority" | "vendor" | "research" | "press" | "catalog" | "custom"
export const NEWS_CATEGORIES: NewsCategory[] = ["authority", "catalog", "vendor", "research", "press", "custom"]

export interface AdminNewsSource extends NewsSourceRef {
  url: string
  site: string
  builtin: boolean
  enabled: boolean
  category: NewsCategory
  /** language of the texts of a built-in source (an own feed: unknown) */
  lang: "de" | "en" | "fr" | null
  items: number
  last_fetch_at: string | null
  last_ok_at: string | null
  next_fetch_at: string | null
  error: string | null
}

export interface NewsSettings {
  enabled: boolean
  every_min: number
  keep_days: number
  /** Details aus der Quelle (CSAF, NVD) per story */
  details: boolean
  /** the saved state the form was loaded with (409 "stale" when another admin saved in between) */
  rev?: number
}

export const useAdminNews = () => useQuery({ queryKey: ["admin-news"], queryFn: () => api.get<{ settings: NewsSettings; sources: AdminNewsSource[] }>("/api/admin/news") })

const filterKey = (userId: string) => `cobe-news.filter.${userId}`

/** The filter a person chose (sources, severities, topics, "Betrifft unsere Produkte") – kept in this browser for that
 *  person, not asked again each time. */
export function loadNewsFilter(userId: string | undefined): { sources: string[]; severities: NewsSeverity[]; topics: NewsTopic[]; ours: boolean } {
  try {
    const raw = userId ? localStorage.getItem(filterKey(userId)) : null
    const v = raw ? (JSON.parse(raw) as { sources?: unknown; severities?: unknown; topics?: unknown; ours?: unknown }) : {}
    return {
      sources: Array.isArray(v.sources) ? v.sources.filter((x): x is string => typeof x === "string") : [],
      severities: Array.isArray(v.severities) ? v.severities.filter((x): x is NewsSeverity => NEWS_SEVERITIES.includes(x as NewsSeverity)) : [],
      topics: Array.isArray(v.topics) ? [...new Set(v.topics.filter(isTopic))] : [],
      ours: v.ours === true,
    }
  } catch {
    return { sources: [], severities: [], topics: [], ours: false }
  }
}

export function saveNewsFilter(userId: string | undefined, f: { sources: string[]; severities: NewsSeverity[]; topics?: NewsTopic[]; ours?: boolean }) {
  if (!userId) return
  try {
    localStorage.setItem(filterKey(userId), JSON.stringify({ sources: f.sources, severities: f.severities, topics: f.topics ?? [], ours: !!f.ours }))
  } catch {
    /* private window: the filter just is not kept */
  }
}

/** The source filter's options grouped by the kind of source (authorities first – "Behörden-Warnung" is a group of
 *  sources, not a topic); a kind without a source is left out. */
export function sourceGroups<T extends { category?: NewsCategory }>(sources: T[]): { category: NewsCategory; sources: T[] }[] {
  return NEWS_CATEGORIES.map((category) => ({ category, sources: sources.filter((s) => (s.category ?? "custom") === category) })).filter((g) => g.sources.length > 0)
}

/** Desktop notifications of the signed-in person (kept on the server, per user). */
export interface DesktopPrefs {
  enabled: boolean
  severities: NewsSeverity[]
  sources: string[]
  /** only stories with one of these topics ([] = every story); older answers lack it */
  topics?: NewsTopic[]
}

export const useDesktopPrefs = (enabled = true) => useQuery({ queryKey: ["me", "desktop"], queryFn: () => api.get<DesktopPrefs>("/api/me/desktop"), enabled, staleTime: 60_000 })
