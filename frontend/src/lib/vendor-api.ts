import { type InfiniteData, type QueryClient, keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { api, DETAIL_TIMEOUT_MS, detailRetry } from "@/lib/api"
import { polled } from "@/lib/poll"
import type { AdvisoryChange } from "@/lib/advisory-changes"
import type { NewsSeverity } from "@/lib/news-api"

/** A category key of the catalogue data (backend/app/catalog/categories.yaml) – labels and order: useCatalogTexts */
export type VendorCategory = string

export type VersionScheme = "panos" | "fortios" | "cisco" | "windows" | "vmware" | "ivanti" | "veeam" | "sfos" | "java" | "sap" | "distro" | "cloud" | "generic"

export interface VendorProduct {
  key: string
  label: string
  vendor: string
  category: VendorCategory
  scheme: VersionScheme
  example: string
  cloud: boolean
  cpes: string[]
  /** the vendor's own structured advisories */
  advisory: "paloalto" | "fortinet" | "veeam" | null
  /** endoflife.date knows its release lines */
  eol: boolean
  aliases: string[]
  hint: string | null
  version_cmd: string | null
  /** eol: the command comes from endoflife.date (shown as such) · catalog: from the curated catalogue */
  version_cmd_from?: "eol" | "catalog"
  /** where the version is read, for products without a command (vendor.where.<key>) */
  version_where?: string | null
  /** vCenter, ESXi: the four-part version (8.0.3.00400) and build numbers are taken too – looked up on the server */
  builds?: boolean
  custom: boolean
}

export interface VendorCatalog {
  generated_at: string
  /** the version of the curated catalogue data (e.g. 2026.10.29-1) – separate from the app version */
  catalog_version: string
  categories: Record<string, { total: number; followed: number }>
  products: VendorProduct[]
  followed: Record<string, { enabled: boolean; versions: number }>
}

/** stale: "unklare Altdaten" – unclear data, published long before the installed release line (folded, never counted) */
export type Status = "affected" | "possible" | "not_affected" | "service" | "unversioned" | "stale"

/** Dringlichkeit (server: app/vendor_score.py): now "Sofort" · soon "Bald" · watch "Beobachten" */
export type ScoreLevel = "now" | "soon" | "watch"

/** One factor of the number and what it was computed from (the tooltip says it: "KEV +30"). */
export interface ScorePart {
  factor: "severity" | "epss" | "kev" | "exploited" | "version" | "no_fix" | "age" | "public_exploit"
  points: number
  band?: NewsSeverity
  cvss?: number | null
  percentile?: number | null
  status?: Status
  days?: number | null
}

export interface ScoreBrief {
  value: number
  level: ScoreLevel
}

/** The number 0–100 with its breakdown – of a finding (its most urgent version), or of a card (its most urgent finding). */
export interface Score extends ScoreBrief {
  /** the sum before it was kept between 0 and 100 */
  raw: number
  parts: ScorePart[]
  /** the version the number is about (a finding) */
  version?: string | null
  /** the finding the card's number comes from */
  finding?: string
  ident?: string
}

export interface VersionVerdict {
  id: string | null
  version: string | null
  status: Status
  /** why (vendor.reason.<key>) */
  reason: string
  fixed: string | null
  /** by: where the verdict comes from (vendor, nvd, adp, bsi, csaf, osv – backend vendor_match.BY_VENDOR …) */
  detail: { platform?: string; after?: string; lines?: { line: string; affected: string; fixed: string }[]; line?: string; released?: string; by?: string }
  /** Dringlichkeit of this version (the value alone) */
  score?: number
}

/** FIRST EPSS of a finding's CVE most likely to be exploited (0–1, as of `date`) */
export interface Epss {
  cve: string
  score: number
  percentile: number | null
  date: string
}

/** The exploit lists (server: app/exploits.py) – public exploit code or a ready-made exploit check for a CVE */
export const EXPLOIT_SOURCES = ["metasploit", "exploitdb", "nuclei"] as const
export type ExploitSource = (typeof EXPLOIT_SOURCES)[number]

/** One list naming a CVE: the entry's address and when Cobe News first saw it there */
export interface ExploitHint {
  cve?: string
  source: ExploitSource
  url: string
  first_seen?: string | null
}

/** CISA's SSVC decision points (cvelistV5, ADP container) */
export interface Ssvc {
  exploitation: "none" | "poc" | "active" | string
  automatable: string
  technical_impact: string
}

export interface Finding {
  id: string
  /** unread for me / all of its CVEs (or its product) muted by me – app/reader.py */
  unread?: boolean
  muted?: boolean
  source: "paloalto" | "fortinet" | "veeam" | "nvd" | "csaf" | "cvelist" | "osv"
  ident: string
  title: string
  /** a readable title: the vendor's, else the NVD description without its boilerplate, else the weakness (CWE) */
  headline: string
  summary: string
  url: string
  also: { source: string; ident: string; url: string }[]
  cves: string[]
  cvss: number | null
  severity: NewsSeverity
  exploited: boolean
  kev: { added: string; due: string; ransomware: boolean } | null
  euvd: boolean
  epss?: Epss | null
  ssvc?: Ssvc | null
  /** public exploits for its CVEs (switched-on exploit lists) */
  exploit?: ExploitHint[]
  /** brought by a CSAF provider's first fill: shown, never notified */
  quiet?: boolean
  /** "GREEN": from a CSAF provider's TLP:GREEN document (allowed by an admin) – share internally only */
  tlp?: "GREEN" | null
  /** the newest revision of the advisory (or one of its CVE records) within the last 30 days – "Geändert" */
  changed?: AdvisoryChange | null
  published_at: string | null
  status: Status
  versions: VersionVerdict[]
  score?: Score | null
}

export interface ReleaseLine {
  name: string
  label: string | null
  latest: string | null
  latestDate?: string | null
  releaseDate?: string | null
  eolFrom?: string | null
  eoasFrom?: string | null
  isEol?: boolean
  isLts?: boolean
  isMaintained?: boolean
  eol_state: EolState
}

export type EolState = "ok" | "soon" | "past" | "unknown"

export interface ReleaseInfo {
  lines?: ReleaseLine[]
  line?: {
    name: string
    label: string | null
    latest: string | null
    latest_date: string | null
    release_date?: string | null
    eol_from: string | null
    eoas_from: string | null
    lts: boolean | null
  } | null
  update_available?: boolean
  /** a short version (Veeam "12.3.2" without its build, nginx "1.27"): whether the latest release is installed is not known */
  update_unknown?: boolean
  eol_state?: EolState
  newer_line?: { name: string; label: string | null; latest: string | null } | null
}

export interface FollowedVersion {
  id: string
  version: string
  label: string
  count: number | null
  valid: boolean
  invalid_reason: string | null
  /** why it is refused, from the catalogue (de/en) – e.g. where Exchange's build is read */
  invalid_hint?: { de: string; en: string } | null
  /** other_product: the product this form belongs to (pfSense Plus for "24.11" under pfSense CE) */
  invalid_to?: string | null
  invalid_to_label?: string | null
  /** implausible: the release lines the product has */
  invalid_lines?: string[]
  /** stored before a rule existed ("2019 CU15"): what it is compared as (15.2.1748) */
  effective?: string | null
  /** accepted, but fewer parts than the product's releases ("7.4" for FortiOS 7.4.8): stands for several releases */
  short?: boolean
  updated_at: string | null
  release?: ReleaseInfo | null
  /** Versionen prüfen: when somebody last said it still runs (entered, changed or "Bestätigen"), by whom, due */
  review?: VersionReview
}

export interface VersionReview {
  confirmed_at: string | null
  confirmed_by: string | null
  age_days: number
  due: boolean
  /** due because the stored text is no valid version of the product any more (a rule came after it was entered) */
  invalid?: boolean
}

/** The version to go to (computed by the server per installed version, app/vendor.py target_versions). */
export interface VersionTarget {
  /** none: nothing affects it · update: `to` in its own line · newer_line: only a newer line fixes · no_fix */
  kind: "none" | "update" | "newer_line" | "no_fix"
  to: string | null
  line: string | null
  /** of `total` vulnerabilities affecting the version, `fixes` are fixed by `to`, `open` remain */
  fixes: number
  total: number
  open: number
  possible: number
  /** a newer line that fixes some of the open ones */
  newer: { to: string; line: string; fixes: number } | null
  /** `to` itself is affected by this many vulnerabilities the installed version is not (no release of its line avoids them yet) */
  introduces?: number
}

export interface VersionSummary {
  affected: number
  possible: number
  critical: number
  exploited: number
  service: number
  unversioned: number
  stale?: number
  target?: VersionTarget
}

/** How urgent a followed product is (server: app/vendor.py urgency) – the order of the overview. */
export type Urgency = "exploited" | "critical" | "affected" | "possible" | "info" | "ok"
export const URGENCY_ORDER: Urgency[] = ["exploited", "critical", "affected", "possible", "info", "ok"]

export interface OverviewItem {
  product: VendorProduct
  follow: { enabled: boolean; note: string; tags: string[]; created_at: string | null }
  versions: FollowedVersion[]
  /** the viewer may confirm its versions (admins; readers of a team the product belongs to) */
  can_confirm?: boolean
  summary: { per_version: Record<string, VersionSummary>; worst: Status | "none" }
  releases: ({ version_id: string } & ReleaseInfo)[]
  counts: {
    affected: number
    possible: number
    service: number
    unversioned: number
    critical: number
    exploited: number
    stale?: number
    /** critical / exploited vulnerabilities that affect a version (not "possibly") – what makes a card red */
    critical_affected?: number
    exploited_affected?: number
  }
  urgency?: Urgency
  /** Dringlichkeit: the number of the product's most urgent finding, with its breakdown (null: no finding) */
  score?: Score | null
  /** other followed products the NVD lists under the same CPE – their CVEs appear on both cards */
  same_data?: string[]
  /** revised advisories of the product within the last 30 days; `impact`: one changed the verdict of a version entered */
  changed?: { count: number; at: string; impact: boolean } | null
  latest: (Pick<Finding, "id" | "ident" | "title" | "severity" | "exploited" | "status" | "published_at" | "cvss" | "tlp"> & {
    headline?: string
    score?: ScoreBrief | null
    unread?: boolean
    muted?: boolean
  })[]
  /** my read state and mutes (app/reader.py): unread findings, muted until, an exploited one while muted */
  unread?: number
  /** unread findings including the muted ones (what "Alle N als gelesen" marks while muted ones are shown) */
  unread_all?: number
  muted?: { until: string } | null
  muted_kev?: boolean
}

export interface VendorOverview {
  /** failed: nothing has answered yet and every source asked failed */
  status: { enabled: boolean; last_ok_at: string | null; errors: number; fetched: boolean; failed?: boolean }
  items: OverviewItem[]
  /** the answer is limited to the viewer's teams ("Mein Team") */
  team_scope?: boolean
  /** how many products are followed in all – the number on the tab, also with "Mein Team" */
  total?: number
  /** Versionen prüfen: the interval in days (0: off) */
  review_days?: number
  /** the load time – "Alle gelesen" marks what had arrived up to it */
  now?: string
}

export interface RelatedStory {
  id: string
  title: string
  summary: string
  url: string
  source: { id: string; name: string; logo: boolean }
  published_at: string
  severity: NewsSeverity
  cves: string[]
  by: "cve" | "name"
}

export interface ProductDetail {
  product: VendorProduct
  follow: OverviewItem["follow"] | null
  versions: FollowedVersion[]
  releases: ReleaseInfo | null
  summary?: OverviewItem["summary"]
  /** one page of the findings in the drawer's order (affected, possibly, …, unklare Altdaten, not affected) */
  findings: Finding[]
  offset?: number
  limit?: number
  /** how many the whole (filtered) list has – `findings` is the page from `offset` */
  shown?: number
  /** how many of each kind over all findings (also those not on this page, also the not affected ones) */
  by_status?: Partial<Record<Status, number>>
  not_affected?: number
  total?: number
  /** the related stories – with the first page only */
  news: RelatedStory[]
  /** Katalog-Pflege: the catalogue entry needs care (first page only, null when it is fine) */
  catalog_check?: CatalogCheckVerdict | null
  /** Versionen prüfen: the interval in days (0: off), and whether the viewer may confirm the versions */
  review_days?: number
  can_confirm?: boolean
  /** my unread findings of the product, my mute of it, the load time (app/reader.py) */
  unread?: number
  muted?: { until: string } | null
  now?: string
}

/** A reason of the catalogue self-test (backend app/catalog_check.py) – worded by lib/catalog-care.ts */
export interface CareReason {
  code: string
  level: "error" | "warn" | "info"
  cpe?: string
  by?: string
  key?: string
  theirs?: string
  months?: number
  newest?: string
  cve?: string
  source?: string
  last?: string
}

export interface CatalogCheckVerdict {
  status: "error" | "warn"
  reasons: CareReason[]
  checked_at: string | null
}

/** The structured sources, each switched on its own (Integrationen → Vendor News → Weitere Quellen). */
export const STRUCTURED_SOURCES = ["csaf", "cvelist", "epss", "osv"] as const
export type StructuredSource = (typeof STRUCTURED_SOURCES)[number]

/** The settings switch of an exploit list: exploit_<source> */
export const exploitSwitch = (s: ExploitSource) => `exploit_${s}` as const
export type ExploitSwitch = ReturnType<typeof exploitSwitch>

export interface VendorSettings extends Record<StructuredSource, boolean>, Partial<Record<ExploitSwitch, boolean>> {
  enabled: boolean
  every_h: number
  eol_every_h: number
  nvd_key_set: boolean
  /** Versionen prüfen: days after which an entered version is "bitte prüfen" (0: off) */
  review_days?: number
  /** CSAF providers whose TLP:GREEN documents are read (default none: only TLP:CLEAR/WHITE) */
  csaf_green?: string[]
  /** the saved state the form was loaded with (409 "stale" when another admin saved in between) */
  rev?: number
}

export interface VendorAdmin {
  settings: VendorSettings
  structured?: {
    csaf_providers: { key: string; name: string; domain: string; vendors: string[]; needed: boolean; green?: boolean }[]
    osv_products: number
    exploit_sources?: { key: ExploitSource; name: string; url: string; licence: string; default: boolean }[]
  }
  catalog: { generated_at: string; eol_generated_at: string | null; products: number; counts: Record<string, number> }
  sources: { key: string; last_ok_at: string | null; last_fetch_at: string | null; next_fetch_at: string | null; error: string | null; items: number }[]
}

export const useVendorCatalog = () => useQuery({ queryKey: ["vendor", "catalog"], queryFn: () => api.get<VendorCatalog>("/api/vendor/catalog"), staleTime: 60_000 })
/**
 * `team`: "Mein Team" – only the products of the viewer's teams (Teams on); its own cache entry below the usual one.
 * `null`: not known yet (the viewer's teams are loading) – nothing is asked until it is.
 */
export const useVendorOverview = (scope: "all" | "team" | null = "all") =>
  useQuery({
    queryKey: overviewKey(scope),
    queryFn: polled<VendorOverview>((o) => api.get(scope === "team" ? "/api/vendor/overview?scope=team" : "/api/vendor/overview", o)),
    enabled: scope !== null,
    refetchInterval: 5 * 60_000,
    staleTime: 20_000,
  })
export const overviewKey = (scope: "all" | "team" | null) =>
  scope === "team" ? ["vendor", "overview", "team"] : scope === "all" ? ["vendor", "overview"] : ["vendor", "overview", "pending"]
/** Every followed product ("Alle"), whichever scope the overview shows (the answer carries the full count). */
export const followedCount = (d: VendorOverview | undefined): number | undefined => (d ? (d.total ?? (d.team_scope ? undefined : d.items.length)) : undefined)
/** Findings per page in the drawer – the server sends at most 500, the drawer loads more on request. */
export const FINDINGS_PAGE = 100

/**
 * One product for the drawer, its findings page by page (`?offset=&limit=`): the first page brings the product, its
 * versions and the related stories; "Weitere anzeigen" loads the next. Switching "auch nicht betroffene" keeps the
 * shown list until the other one is there (no skeleton, the switch keeps the focus).
 */
export type FindingSort = "relevance" | "epss" | "score"

export const useVendorProduct = (key: string | null, all = false, sort: FindingSort = "relevance") =>
  useInfiniteQuery({
    queryKey: ["vendor", "product", key, all, sort],
    queryFn: ({ signal, pageParam }) =>
      api.get<ProductDetail>(
        `/api/vendor/products/${encodeURIComponent(key ?? "")}?${new URLSearchParams({ ...(all ? { all: "true" } : {}), ...(sort !== "relevance" ? { sort } : {}), offset: String(pageParam), limit: String(FINDINGS_PAGE) }).toString()}`,
        { signal, timeoutMs: DETAIL_TIMEOUT_MS },
      ),
    initialPageParam: 0,
    getNextPageParam: nextFindingsOffset,
    enabled: !!key,
    retry: detailRetry,
    retryDelay: 1000,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  })

/** Where the next page starts – none when the server sent everything (or is older and does not page). */
export function nextFindingsOffset(last: ProductDetail): number | undefined {
  if (last.shown === undefined) return undefined
  const next = (last.offset ?? 0) + last.findings.length
  return last.findings.length > 0 && next < last.shown ? next : undefined
}

/** The pages as one product: the first page's head, the findings of all loaded pages (each once). */
export function mergeFindingPages(data: InfiniteData<ProductDetail> | undefined): ProductDetail | undefined {
  const first = data?.pages[0]
  if (!data || !first) return undefined
  if (data.pages.length === 1) return first
  const seen = new Set<string>()
  const findings: Finding[] = []
  for (const pg of data.pages)
    for (const f of pg.findings)
      if (!seen.has(f.id)) {
        seen.add(f.id)
        findings.push(f)
      }
  return { ...first, findings }
}

/** How many findings of each kind – from the server (all pages), or counted in what is loaded (an older server). */
export function findingCounts(d: ProductDetail): Record<Status, number> {
  const out: Record<Status, number> = { affected: 0, possible: 0, service: 0, unversioned: 0, stale: 0, not_affected: 0 }
  if (d.by_status) for (const [k, n] of Object.entries(d.by_status)) out[k as Status] = n ?? 0
  else for (const f of d.findings) out[f.status]++
  return out
}

/** The number on "Schwachstellen": everything but "not affected" and "unklare Altdaten" (folded, never counted). */
export function visibleFindings(d: ProductDetail): number {
  const c = findingCounts(d)
  return c.affected + c.possible + c.service + c.unversioned
}

/** The query key of one product's drawer (both lists: with and without the not affected ones). */
export const productKeyOf = (key: string) => ["vendor", "product", key] as const

/**
 * After a change of Vendor News data: every vendor view is refetched; the promise ends when the views under `wait` have
 * their fresh data (a switch or a form stays busy until it shows what was saved – the heavy overview does not hold it up).
 */
export async function refreshVendor(qc: QueryClient, wait?: readonly unknown[]): Promise<void> {
  const waited = (k: readonly unknown[]) => !!wait && wait.every((x, i) => k[i] === x)
  void qc.invalidateQueries({ queryKey: ["vendor"], predicate: (q) => !waited(q.queryKey) })
  if (wait) await qc.invalidateQueries({ queryKey: [...wait] })
}

/** The server's check of a typed version (GET /api/vendor/validate) – `short`: accepted, but less precise than the releases. */
export interface VersionCheck {
  ok: boolean
  normalized: string
  reason: string | null
  short: boolean
  /** looked up or normalised – `normalized` is what is stored (vCenter 8.0.3.00400 → 8.0 U3d, Exchange 2019 CU15 → 15.2.1748) */
  mapped?: boolean
  example: string
  /** refused: the catalogue's explanation (de/en), the product the form belongs to, the known release lines */
  hint?: { de: string; en: string } | null
  to?: string | null
  to_label?: string | null
  lines?: string[]
}
export const useVersionCheck = (product: string, version: string, enabled: boolean) =>
  useQuery({
    queryKey: ["vendor-validate", product, version],
    queryFn: ({ signal }) => api.get<VersionCheck>(`/api/vendor/validate?${new URLSearchParams({ product, version }).toString()}`, { signal }),
    enabled,
    staleTime: Infinity,
    retry: false,
  })
export const useVendorAdmin = (enabled = true) => useQuery({ queryKey: ["vendor", "admin"], queryFn: () => api.get<VendorAdmin>("/api/admin/vendor"), enabled })

// ---------------------------------------------------------------- pure helpers (tested)

const RANK: Record<Status, number> = { affected: 5, possible: 4, service: 3, unversioned: 2, stale: 1, not_affected: 0 }

/** The worse of two states (affected > possibly affected > cloud service > no version > unclear old data > not affected). */
export function worse(a: Status | "none", b: Status | "none"): Status | "none" {
  if (a === "none") return b
  if (b === "none") return a
  return RANK[a] >= RANK[b] ? a : b
}

/** Lower case without accents and punctuation – "FortiGate" finds "fortigate", "Pan os" finds "PAN-OS". */
export function fold(s: string): string {
  return s
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
}

/**
 * Fuzzy score of a product for a search: every word of the query must occur (in label, vendor, aliases or CPE) – a
 * word at the start of a word counts more, the label more than the rest; a typo of one letter is forgiven in words of
 * five letters or more. 0: no match.
 */
export function matchScore(p: Pick<VendorProduct, "label" | "vendor" | "aliases" | "cpes" | "key">, query: string): number {
  const words = fold(query).split(" ").filter(Boolean)
  if (!words.length) return 1
  const label = fold(p.label)
  const rest = fold([p.vendor, ...p.aliases, ...p.cpes.map((c) => c.split(":").slice(1).join(" ")), p.key].join(" "))
  let score = 0
  for (const w of words) {
    const s = wordScore(label, w) * 2 || wordScore(rest, w)
    if (!s) return 0
    score += s
  }
  // the whole query is the product's name or one of its aliases, also with the vendor's name before it ("VMware vSphere"
  // → vCenter's alias "vSphere"): above a product that only has the words in its label ("VMware vSphere Replication")
  const q = words.join(" ")
  const vendorWords = new Set(fold(p.vendor).split(" "))
  const bare = words.filter((w) => !vendorWords.has(w)).join(" ")
  const whole = (name: string) => {
    const n = fold(name)
    return n === q || (bare !== "" && n === bare)
  }
  if (whole(p.label)) return Math.max(score, words.length * 6 + 2)
  if (p.aliases.some(whole)) return Math.max(score, words.length * 6 + 1)
  return score
}

function wordScore(hay: string, w: string): number {
  if (!hay) return 0
  if (` ${hay}`.includes(` ${w}`)) return 3
  if (hay.includes(w)) return 2
  if (w.length >= 5) for (const token of hay.split(" ")) if (token.length >= w.length - 1 && near(token.slice(0, w.length + 1), w)) return 1
  return 0
}

/** Edit distance ≤ 1 (one letter wrong, missing or too many). */
function near(a: string, b: string): boolean {
  if (Math.abs(a.length - b.length) > 1) return false
  let i = 0
  let j = 0
  let edits = 0
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      i++
      j++
      continue
    }
    if (++edits > 1) return false
    if (a.length > b.length) i++
    else if (a.length < b.length) j++
    else {
      i++
      j++
    }
  }
  return edits + (a.length - i) + (b.length - j) <= 1
}

/** Version formats per scheme – the same rules as the server (app/vendor_versions.py), for a hint while typing. */
const FORMATS: Partial<Record<VersionScheme, RegExp>> = {
  panos: /^\d{1,2}\.\d{1,2}\.\d{1,3}(?:[-.]?h\d{1,3})?$/i,
  fortios: /^v?\d+\.\d+(?:\.\d+)?(?:[ ,]*build\s*\d+)?$/i,
  windows: /^(?:10\.0\.)?\d{5}\.\d{1,6}$/,
  ivanti: /^\d+\.\d+\s*r\d+(?:\.\d+){0,2}(?:\s*(?:build\s*)?\d+)?$/i,
  // 8.0 U3c, 8.0.3, 8.0 Update 3c, a patch of the GA release 8.0c / 7.0.0d, from 9.0 on the four-part 9.0.2.0100
  vmware: /^(?:\d+\.\d+(?:\.\d+)?(?:\s*(?:u|update)\s*\d+\s*[a-z]?)?(?:\s*(?:p|patch)\s*\d+)?|\d+\.\d+(?:\.0)?[a-z]|(?:9|[1-9]\d)\.\d{1,2}\.\d{1,2}\.\d{1,5})$/i,
  // a build 12.3.2.4934 (or a short 12.3.2), 11.0.1.1261 P20240304, "13.1.2 (build 13.1.2.57)" – not "12.3.2 P4"
  veeam: /^(?:\d{1,3}(?:\.\d{1,6}){1,4}|\d{1,3}(?:\.\d{1,6}){3}\s*(?:p|patch)\s*\d{8}|.*\bbuild\s*\d{1,3}(?:\.\d{1,6}){3,4}\s*\)?)$/i,
}

export type VersionProblem = "empty" | "too_long" | "kb" | "format" | "cloud" | null

/** The text of a refused version: the reason (with example, product, lines), then the catalogue's hint in the language. */
export function invalidText(
  t: (key: string, o?: Record<string, unknown>) => string,
  lang: string,
  reason: string,
  o: { example: string; hint?: { de: string; en: string } | null; toLabel?: string | null; lines?: string[] | null },
): string {
  const base = t(`vendor.invalid.${reason}`, { example: o.example, product: o.toLabel ?? "", lines: (o.lines ?? []).join(", ") })
  // vCenter/ESXi's reasons have their own full text; the others add the catalogue's explanation
  const own = reason === "unknown_build" || reason === "build_mismatch"
  const hint = o.hint && !own ? (lang.startsWith("en") ? o.hint.en : o.hint.de) || o.hint.de : ""
  return hint ? `${base} ${hint}` : base
}

/**
 * vCenter / ESXi: a four-part version before 9.0 (8.0.3.00400) or a text with a build number (24322831, 8.0.3-24022510,
 * "VMware ESXi 8.0.3 build-24022510") – which release it is, only the server's tables know (app/vmware_builds.py): the
 * form asks the server and shows "→ 8.0 U3d" instead of checking the format itself.
 */
export function looksLikeBuild(text: string): boolean {
  const t = text.trim().replace(/\s+/g, " ")
  if (t.length > 64) return false
  const four = /(?:^|\s)(\d{1,2})\.\d{1,2}\.\d{1,2}\.\d{1,5}$/.exec(t)
  if (four && Number(four[1]) < 9) return true
  return /(?:^|[\s,:(-])(?:build[\s:#-]*)?\d{6,9}\)?$/i.test(t)
}

export function versionProblem(scheme: VersionScheme, text: string): VersionProblem {
  const t = text.trim().replace(/\s+/g, " ")
  if (!t) return "empty"
  // a pasted line (SELECT @@VERSION) may be longer – the server takes the version out of it (at most 64 are stored)
  if (t.length > 200) return "too_long"
  if (scheme === "cloud") return "cloud"
  if (scheme === "windows" && /^kb\s?\d{6,8}$/i.test(t)) return "kb"
  const rx = FORMATS[scheme]
  if (rx) return rx.test(t) ? null : "format"
  return /\d/.test(t) ? null : "format"
}

/** The worst state over a product's versions for its card – and how many of its versions a finding affects. */
export function affectedVersions(f: Finding): { affected: number; possible: number; total: number } {
  const total = f.versions.length
  return {
    affected: f.versions.filter((v) => v.status === "affected").length,
    possible: f.versions.filter((v) => v.status === "possible").length,
    total,
  }
}

export const STATUS_COLOR: Record<Status, string> = {
  affected: "--sev-critical",
  possible: "--warning",
  service: "--sev-low",
  unversioned: "--muted-foreground",
  stale: "--muted-foreground",
  not_affected: "--success",
}

/** Support of a release line: "soon" with less than half a year left – what an upgrade needs to be planned. The server
 * uses the same number for the cards and the notifications (backend app/vendor.py EOL_SOON_DAYS – pinned by a test). */
export type Support = "ok" | "soon" | "past" | "unknown"
export const SUPPORT_SOON_DAYS = 183

/**
 * The support state of a release line from its EOL date (endoflife.date: "2027-05-02", or `isEol` without a date):
 * past – no security updates any more; soon – ends within half a year; ok – supported (also: no end announced).
 */
export function supportState(eolFrom: string | null | undefined, isEol: boolean | null | undefined, today: Date = new Date()): Support {
  const m = eolFrom ? /^(\d{4})-(\d{2})-(\d{2})/.exec(eolFrom) : null
  if (m) {
    const end = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]))
    const day = new Date(today.getFullYear(), today.getMonth(), today.getDate())
    const days = Math.round((end.getTime() - day.getTime()) / 86_400_000)
    return days <= 0 ? "past" : days < SUPPORT_SOON_DAYS ? "soon" : "ok"
  }
  if (isEol === true) return "past"
  if (isEol === false) return "ok"
  return "unknown"
}

export const SUPPORT_COLOR: Record<Support, string> = { ok: "--success", soon: "--warning", past: "--sev-critical", unknown: "--muted-foreground" }

// ---------------------------------------------------------------- the overview (cards and list)

const URGENCY_RANK = Object.fromEntries(URGENCY_ORDER.map((u, i) => [u, i])) as Record<Urgency, number>

/** The urgency of a card – from the server, or (an older server) from its counts. */
export function urgencyOf(i: OverviewItem): Urgency {
  if (i.urgency) return i.urgency
  const c = i.counts
  if (c.exploited_affected ?? (c.affected ? c.exploited : 0)) return "exploited"
  if (c.critical_affected ?? (c.affected ? c.critical : 0)) return "critical"
  if (c.affected || i.releases.some((r) => r.eol_state === "past")) return "affected"
  if (c.possible || c.unversioned || i.releases.some((r) => r.eol_state === "soon")) return "possible"
  if (c.service) return "info"
  return "ok"
}

/**
 * Most urgent first: exploited → critical → affected → possibly → info → ok; within a tier the higher Dringlichkeit
 * (the number of the most urgent finding), then more affected first.
 */
export function byUrgency(a: OverviewItem, b: OverviewItem): number {
  return (
    URGENCY_RANK[urgencyOf(a)] - URGENCY_RANK[urgencyOf(b)] ||
    (b.score?.value ?? -1) - (a.score?.value ?? -1) ||
    (b.counts.exploited_affected ?? 0) - (a.counts.exploited_affected ?? 0) ||
    (b.counts.critical_affected ?? 0) - (a.counts.critical_affected ?? 0) ||
    b.counts.affected - a.counts.affected ||
    b.counts.possible - a.counts.possible ||
    a.product.label.localeCompare(b.product.label)
  )
}

/** The support of a product's versions: the worst state, and the earliest end date (endoflife.date) of their lines. */
export function supportOf(i: OverviewItem): { state: Support; until: string | null } {
  const order: Support[] = ["past", "soon", "ok", "unknown"]
  let state: Support = "unknown"
  let until: string | null = null
  for (const r of i.releases) {
    const s = (r.eol_state ?? "unknown") as Support
    if (order.indexOf(s) < order.indexOf(state)) state = s
    const d = r.line?.eol_from
    if (d && (!until || d < until)) until = d
  }
  return { state, until }
}

export interface TargetGroup {
  target: VersionTarget
  versions: FollowedVersion[]
}

/** Versions with the same target together (one action line each): the most open first. */
export function targetGroups(i: OverviewItem): TargetGroup[] {
  const out = new Map<string, TargetGroup>()
  for (const v of i.versions) {
    const t: VersionTarget = i.summary.per_version[v.id]?.target ?? { kind: "none", to: null, line: null, fixes: 0, total: 0, open: 0, possible: 0, newer: null }
    const k = JSON.stringify(t)
    const g = out.get(k)
    if (g) g.versions.push(v)
    else out.set(k, { target: t, versions: [v] })
  }
  const weight = (t: VersionTarget) => (t.kind === "none" ? -1 : t.total * 2 + t.open)
  return [...out.values()].sort((a, b) => weight(b.target) - weight(a.target))
}

/**
 * The status row above the overview: Handlungsbedarf (a version is affected or without support) · Möglicherweise
 * (possibly affected, no version given, support ends soon, a cloud service with notes) · Alles aktuell · Alle.
 */
export type StatusFilter = "action" | "check" | "ok" | "all"
export const STATUS_FILTERS: StatusFilter[] = ["action", "check", "ok", "all"]

/** Which of the status row's groups a product belongs to (every product to exactly one). */
export function statusOf(i: OverviewItem): Exclude<StatusFilter, "all"> {
  if (needsAction(i)) return "action"
  return urgencyOf(i) === "ok" ? "ok" : "check"
}

export function matchesStatus(i: OverviewItem, s: StatusFilter): boolean {
  return s === "all" || statusOf(i) === s
}

/** The numbers on the status row – over what the search and the summary filters leave. */
export function statusCounts(items: OverviewItem[]): Record<StatusFilter, number> {
  const out: Record<StatusFilter, number> = { action: 0, check: 0, ok: 0, all: items.length }
  for (const i of items) out[statusOf(i)]++
  return out
}

export type OverviewFilter = "action" | "exploited" | "support" | "now" | "review"

/** Handlungsbedarf: a vulnerability affects a version, or a version's line has no support any more. */
export function needsAction(i: OverviewItem): boolean {
  return i.counts.affected > 0 || i.releases.some((r) => r.eol_state === "past")
}

export function matchesFilter(i: OverviewItem, f: OverviewFilter | null): boolean {
  if (!f) return true
  if (f === "action") return needsAction(i)
  if (f === "exploited") return (i.counts.exploited_affected ?? 0) > 0
  if (f === "now") return scoreLevelOf(i) === "now"
  if (f === "review") return i.versions.some((v) => v.review?.due)
  const s = supportOf(i).state
  return s === "past" || s === "soon"
}

/** The summary bar: products that need action, those with an exploited vulnerability, the next end of support. */
export function overviewStats(items: OverviewItem[], today: Date = new Date()) {
  const day = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, "0")}-${String(today.getDate()).padStart(2, "0")}`
  let next: { item: OverviewItem; date: string } | null = null
  let ended = 0
  for (const i of items) {
    if (i.releases.some((r) => r.eol_state === "past")) ended++
    for (const r of i.releases) {
      const d = r.line?.eol_from
      if (d && d > day && r.eol_state !== "past" && (!next || d < next.date)) next = { item: i, date: d }
    }
  }
  return {
    action: items.filter(needsAction).length,
    ok: items.filter((i) => statusOf(i) === "ok").length,
    exploited: items.filter((i) => (i.counts.exploited_affected ?? 0) > 0).length,
    /** products whose most urgent finding says "Sofort" */
    now: items.filter((i) => scoreLevelOf(i) === "now").length,
    ended,
    next,
  }
}

export type SortKey = "urgency" | "score" | "product" | "versions" | "target" | "affected" | "critical" | "exploited" | "support"

/** The list view's order; ties by urgency. */
export function sortItems(items: OverviewItem[], key: SortKey, desc: boolean): OverviewItem[] {
  const val = (i: OverviewItem): number | string => {
    switch (key) {
      case "product":
        return i.product.label.toLowerCase()
      case "versions":
        return i.versions.length
      case "target":
        return targetGroups(i).find((g) => g.target.to)?.target.to ?? ""
      case "affected":
        return i.counts.affected
      case "critical":
        return i.counts.critical_affected ?? 0
      case "exploited":
        return i.counts.exploited_affected ?? 0
      case "support":
        return supportOf(i).until ?? "9999"
      case "score":
        return i.score?.value ?? -1
      default:
        return 0
    }
  }
  return [...items].sort((a, b) => {
    if (key === "urgency") return desc ? byUrgency(b, a) : byUrgency(a, b)
    const x = val(a)
    const y = val(b)
    const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true })
    return (desc ? -c : c) || byUrgency(a, b)
  })
}

// ---------------------------------------------------------------- Dringlichkeit (server: app/vendor_score.py)

/** The level's colour – the overview's colour rule: red for "Sofort" (as exploited / critical cards), amber for "Bald". */
export const SCORE_TONE: Record<ScoreLevel, string> = { now: "--sev-critical", soon: "--warning", watch: "--muted-foreground" }

/** A card's level – none when the product has no finding (or an older server sends no number). */
export const scoreLevelOf = (i: Pick<OverviewItem, "score">): ScoreLevel | null => i.score?.level ?? null

type Tr = (k: string, o?: Record<string, unknown>) => string

/** One line of the breakdown: "KEV +30", "EPSS-Perzentil 97 % +20", "eure Version betroffen +25". */
export function scorePartText(t: Tr, p: ScorePart, lang = "de"): string {
  const pts = p.points > 0 ? `+${p.points}` : p.points < 0 ? `−${Math.abs(p.points)}` : "±0"
  const pct = (x: number) => Math.floor(x * 100).toLocaleString(lang)
  let what: string
  switch (p.factor) {
    case "severity":
      what =
        p.cvss !== null && p.cvss !== undefined
          ? t("vendor.score.part.cvss", { cvss: p.cvss.toLocaleString(lang, { minimumFractionDigits: 1, maximumFractionDigits: 1 }), band: t(`news.sev.${p.band ?? "info"}`) })
          : t("vendor.score.part.severity", { band: t(`news.sev.${p.band ?? "info"}`) })
      break
    case "epss":
      what = t("vendor.score.part.epss", { pct: p.percentile !== null && p.percentile !== undefined ? pct(p.percentile) : "–" })
      break
    case "version":
      what = t(`vendor.score.part.version.${p.status ?? "not_affected"}`)
      break
    case "age":
      what = t("vendor.score.part.age", { count: p.days ?? 0 })
      break
    default:
      what = t(`vendor.score.part.${p.factor}`)
  }
  return `${what} ${pts}`
}

/** The advisory sources by name (a finding's source, a watched CVE's advisory). */
export const ADVISORY_SOURCE_LABEL: Record<string, string> = {
  paloalto: "Palo Alto PSIRT",
  fortinet: "Fortinet PSIRT",
  veeam: "Veeam KB",
  nvd: "NVD",
  csaf: "CSAF (BSI, Siemens, Cisco, Schneider, Open-Xchange)",
  cvelist: "cvelistV5",
  osv: "OSV",
}
