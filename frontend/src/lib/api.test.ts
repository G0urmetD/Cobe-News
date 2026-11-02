import { afterEach, describe, expect, it, vi } from "vitest"
import { api, ApiError, detailRetry, setActivityListener, setSessionExpiredHandler } from "@/lib/api"

describe("detailRetry", () => {
  it("tries a server error or a lost connection once more, then shows the error", () => {
    expect(detailRetry(0, new ApiError(500, { code: "http_500" }))).toBe(true)
    expect(detailRetry(0, new TypeError("Failed to fetch"))).toBe(true)
    expect(detailRetry(1, new ApiError(500, { code: "http_500" }))).toBe(false)
  })
  it("never retries a refusal or a timeout", () => {
    expect(detailRetry(0, new ApiError(404, { code: "not_found" }))).toBe(false)
    expect(detailRetry(0, new ApiError(504, { code: "timeout" }))).toBe(false)
  })
})

describe("request timeout", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("no answer in time: ApiError 504 timeout", async () => {
    vi.stubGlobal(
      "fetch",
      (_url: string, init: RequestInit) => new Promise((_, reject) => init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))),
    )
    const err = await api.get("/api/slow", { timeoutMs: 20 }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).code).toBe("timeout")
  })

  it("a dropped query stays an abort, not a timeout", async () => {
    vi.stubGlobal(
      "fetch",
      (_url: string, init: RequestInit) => new Promise((_, reject) => init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))),
    )
    const ctl = new AbortController()
    const p = api.get("/api/slow", { signal: ctl.signal, timeoutMs: 5000 }).catch((e: unknown) => e)
    ctl.abort()
    const err = await p
    expect(err).not.toBeInstanceOf(ApiError)
  })
})

describe("session: activity and its end", () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    setActivityListener(null)
    setSessionExpiredHandler(null)
  })
  const answer = (status: number, body: unknown = {}) => vi.stubGlobal("fetch", async () => new Response(JSON.stringify(body), { status }))

  it("a request that reached the server is activity – not the look at the session, the config or the sign-out", async () => {
    const seen: number[] = []
    setActivityListener((at) => seen.push(at))
    answer(200)
    await api.get("/api/news")
    await api.get("/api/auth/state")
    await api.get("/api/auth/session")
    await api.get("/api/auth/config")
    await api.post("/api/auth/logout")
    expect(seen).toHaveLength(2)
    answer(404, { detail: { code: "not_found" } })
    await api.get("/api/news/x").catch(() => undefined) // a refusal is an answer: the session was there
    expect(seen).toHaveLength(3)
    answer(401, { detail: { code: "not_authenticated" } })
    await api.get("/api/news").catch(() => undefined)
    expect(seen).toHaveLength(3)
    answer(200)
    await api.get("/api/reader/counts", { background: true }) // the page asked on its own: keeps nothing alive
    expect(seen).toHaveLength(3)
  })

  it("a background request carries X-Cobe-Background, an ordinary one does not", async () => {
    const headers: Record<string, string>[] = []
    vi.stubGlobal("fetch", async (_p: string, init: RequestInit) => (headers.push(init.headers as Record<string, string>), new Response("{}", { status: 200 })))
    await api.get("/api/reader/counts", { background: true })
    await api.get("/api/reader/counts")
    expect(headers.map((h) => h["X-Cobe-Background"])).toEqual(["1", undefined])
  })

  it("a 401 ends the session for the app's requests and the re-confirmation – not for the steps of a sign-in", async () => {
    let ended = 0
    setSessionExpiredHandler(() => (ended += 1))
    answer(401, { detail: { code: "not_authenticated" } })
    document.cookie = "cobe_news_csrf=t"
    await api.get("/api/news").catch(() => undefined)
    await api.post("/api/auth/reauth", { password: "x" }).catch(() => undefined)
    expect(ended).toBe(2)
    await api.post("/api/auth/login", {}).catch(() => undefined)
    await api.post("/api/auth/mfa", {}).catch(() => undefined)
    await api.get("/api/auth/session").catch(() => undefined)
    expect(ended).toBe(2)
    document.cookie = ""
  })
})
