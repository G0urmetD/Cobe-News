import type { QueryFunction, QueryFunctionContext, QueryKey } from "@tanstack/react-query"
import type { RequestOpts } from "@/lib/api"

/**
 * Requests the page makes on its own must not keep a session alive: a tab left open on the screen polls the counters
 * every minute – the idle timeout would never come. A query TanStack polls (refetchInterval, refetch on focus or
 * reconnect) has its query function wrapped in `polled`: its first load is an ordinary request; every later fetch of
 * the same entry while it already has data – the poll, a refetch – is sent as a background request (X-Cobe-Background,
 * not counted as activity by the server or the tabs). Loading the next page of a list (a scroll, "load more") is the
 * person's doing and counts.
 */
export function isBackgroundFetch(ctx: Pick<QueryFunctionContext, "client" | "queryKey">): boolean {
  const state = ctx.client.getQueryCache().find({ queryKey: ctx.queryKey, exact: true })?.state
  if (!state || state.data === undefined) return false // the first load
  return !(state.fetchMeta as { fetchMore?: unknown } | null | undefined)?.fetchMore // fetchNextPage/fetchPreviousPage
}

/** The query function of a polled query: `fn` gets the request options to pass on. */
export function polled<T>(fn: (opts: RequestOpts) => Promise<T>): QueryFunction<T, QueryKey> {
  return (ctx) => fn({ background: isBackgroundFetch(ctx) })
}

/** The same for a paged list (useInfiniteQuery): `fn` also gets the page. */
export function polledPages<T, P>(fn: (opts: RequestOpts, pageParam: P) => Promise<T>): QueryFunction<T, QueryKey, P> {
  return (ctx) => fn({ background: isBackgroundFetch(ctx) }, ctx.pageParam as P)
}
