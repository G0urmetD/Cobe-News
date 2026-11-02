import { describe, expect, it } from "vitest"
import { QueryClient, QueryObserver } from "@tanstack/react-query"
import { findingCounts, mergeFindingPages, nextFindingsOffset, refreshVendor, visibleFindings, type Finding, type ProductDetail, type Status } from "@/lib/vendor-api"

const f = (id: string, status: Status): Finding =>
  ({
    id,
    status,
    source: "nvd",
    ident: id,
    title: "",
    headline: "",
    summary: "",
    url: "",
    also: [],
    cves: [],
    cvss: null,
    severity: "high",
    exploited: false,
    kev: null,
    euvd: false,
    published_at: null,
    versions: [],
  }) as Finding

const page = (offset: number, findings: Finding[], extra: Partial<ProductDetail> = {}): ProductDetail =>
  ({
    product: { key: "panos" },
    follow: null,
    versions: [],
    releases: null,
    findings,
    offset,
    limit: 100,
    shown: 230,
    news: offset ? [] : [{ id: "s1" }],
    ...extra,
  }) as ProductDetail

const many = (from: number, n: number, status: Status = "affected") => Array.from({ length: n }, (_, i) => f(`f${from + i}`, status))

describe("drawer findings page by page", () => {
  it("asks for the next page until the whole list is there – no silent cap", () => {
    expect(nextFindingsOffset(page(0, many(0, 100)))).toBe(100)
    expect(nextFindingsOffset(page(200, many(200, 30)))).toBeUndefined()
    // an older server sends everything at once (no `shown`), an empty page ends it too
    expect(nextFindingsOffset({ ...page(0, many(0, 100)), shown: undefined })).toBeUndefined()
    expect(nextFindingsOffset(page(100, []))).toBeUndefined()
  })

  it("merges the loaded pages into one list, each finding once, with the first page's head and stories", () => {
    const d = mergeFindingPages({ pages: [page(0, many(0, 100)), page(100, [...many(99, 101)])], pageParams: [0, 100] })
    expect(d?.findings).toHaveLength(200)
    expect(new Set(d?.findings.map((x) => x.id)).size).toBe(200)
    expect(d?.news).toEqual([{ id: "s1" }])
    expect(mergeFindingPages(undefined)).toBeUndefined()
  })

  it("counts every kind from the server, not from the loaded slice", () => {
    const d = page(0, many(0, 100), { by_status: { affected: 180, possible: 30, stale: 12, not_affected: 400, unversioned: 8 } })
    expect(findingCounts(d)).toEqual({ affected: 180, possible: 30, service: 0, unversioned: 8, stale: 12, not_affected: 400 })
    // "N Schwachstellen": neither the not affected ones nor "unklare Altdaten"
    expect(visibleFindings(d)).toBe(218)
    // an older server: counted in what is there
    expect(visibleFindings({ ...page(0, [...many(0, 3), f("s", "stale"), f("n", "not_affected")]), by_status: undefined })).toBe(3)
  })
})

describe("refresh after a change", () => {
  it("waits for the drawer's product only – the other vendor views are refetched without holding up the form", async () => {
    const qc = new QueryClient()
    const calls: string[] = []
    let slowNow = false
    let release = () => {}
    const slow = new Promise<void>((r) => (release = r))
    const unsub: (() => void)[] = []
    for (const key of [
      ["vendor", "product", "panos", false],
      ["vendor", "overview"],
    ]) {
      const o = new QueryObserver(qc, {
        queryKey: key,
        queryFn: async () => {
          calls.push(key.join("/"))
          if (slowNow && key[1] === "overview") await slow
          return calls.length
        },
      })
      unsub.push(o.subscribe(() => {}))
    }
    await new Promise((r) => setTimeout(r, 10))
    calls.length = 0
    slowNow = true
    let done = false
    const p = refreshVendor(qc, ["vendor", "product", "panos"]).then(() => (done = true))
    await new Promise((r) => setTimeout(r, 20))
    expect(done).toBe(true) // the overview is still loading
    expect(calls.sort()).toEqual(["vendor/overview", "vendor/product/panos/false"]) // each once
    release()
    await p
    unsub.forEach((u) => u())
  })
})
