import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

// TanStack Query polls only in a browser (no refetchInterval where `window` is missing – a server render)
vi.hoisted(() => {
  Object.defineProperty(globalThis, "window", { value: { addEventListener: () => undefined, removeEventListener: () => undefined }, configurable: true, writable: true })
})
import { InfiniteQueryObserver, QueryClient, QueryObserver } from "@tanstack/react-query"
import { api, setActivityListener } from "@/lib/api"
import { polled, polledPages } from "@/lib/poll"

/** Every request's path and whether it went as a background request (X-Cobe-Background: 1). */
let sent: { path: string; background: boolean }[] = []

beforeEach(() => {
  sent = []
  vi.stubGlobal("fetch", async (path: string, init: RequestInit) => {
    sent.push({ path, background: (init.headers as Record<string, string>)["X-Cobe-Background"] === "1" })
    return new Response(JSON.stringify({ more: true, next: path.endsWith("after=") ? "p1" : "p2" }), { status: 200 })
  })
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
  setActivityListener(null)
})

describe("polled queries", () => {
  it("the first load is an ordinary request, the interval's polls are background requests – and no activity", async () => {
    vi.useFakeTimers()
    const seen: number[] = []
    setActivityListener((at) => seen.push(at))
    const client = new QueryClient()
    const obs = new QueryObserver(client, { queryKey: ["counts"], queryFn: polled((o) => api.get("/api/reader/counts", o)), refetchInterval: 60_000 })
    const off = obs.subscribe(() => undefined)
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(60_000)
    await vi.advanceTimersByTimeAsync(60_000)
    off()
    expect(sent).toEqual([
      { path: "/api/reader/counts", background: false },
      { path: "/api/reader/counts", background: true },
      { path: "/api/reader/counts", background: true },
    ])
    expect(seen).toHaveLength(1) // only the first load counts as activity
    client.clear()
  })

  it("a refetch (focus, reconnect, invalidation) of a polled query is a background request too", async () => {
    const client = new QueryClient()
    const opts = { queryKey: ["badge"], queryFn: polled((o) => api.get("/api/vendor/badge", o)) }
    await client.fetchQuery(opts)
    await client.refetchQueries({ queryKey: ["badge"] })
    expect(sent.map((s) => s.background)).toEqual([false, true])
    const obs = new QueryObserver(client, opts)
    const off = obs.subscribe(() => undefined)
    await obs.refetch()
    off()
    // mounted again on cached data (staleTime 0: refetched at once), then refetched: both on the page's own account
    expect(sent.map((s) => s.background)).toEqual([false, true, true, true])
  })

  it("a paged list: the next page (a scroll) counts, a poll of the first page does not", async () => {
    const client = new QueryClient()
    const obs = new InfiniteQueryObserver(client, {
      queryKey: ["news", "list"],
      queryFn: polledPages<{ more: boolean; next: string }, string | null>((o, page) => api.get(`/api/news?after=${page ?? ""}`, o)),
      initialPageParam: null as string | null,
      getNextPageParam: (last: { more: boolean; next: string }) => (last.more ? last.next : undefined),
    })
    const off = obs.subscribe(() => undefined)
    await vi.waitFor(() => expect(obs.getCurrentResult().data?.pages).toHaveLength(1))
    await obs.fetchNextPage()
    await obs.refetch()
    off()
    expect(sent).toEqual([
      { path: "/api/news?after=", background: false },
      { path: "/api/news?after=p1", background: false },
      { path: "/api/news?after=", background: true },
      { path: "/api/news?after=p1", background: true },
    ])
  })

  it("an ordinary query sends no header", async () => {
    const client = new QueryClient()
    await client.fetchQuery({ queryKey: ["me"], queryFn: () => api.get("/api/me") })
    await client.fetchQuery({ queryKey: ["me"], queryFn: () => api.get("/api/me"), staleTime: 0 })
    expect(sent.map((s) => s.background)).toEqual([false, false])
  })
})
