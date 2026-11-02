/** Thin fetch wrapper: typed errors, the CSRF token on every write, session expiry. */

export class ApiError extends Error {
  status: number
  code: string
  data: Record<string, unknown>
  constructor(status: number, data: Record<string, unknown>) {
    super(String(data.code ?? `http_${status}`))
    this.status = status
    this.code = String(data.code ?? `http_${status}`)
    this.data = data
  }
}

/**
 * Double submit: the server sets __Host-cobe_news_csrf (readable; without the prefix on plain-http development), every
 * write sends it back as X-CSRF-Token. The prefixed one first – an unprefixed one of an older version may still be there.
 */
export function csrfToken(cookie: string = document.cookie): string {
  const m = cookie.match(/(?:^|;\s*)__Host-cobe_news_csrf=([^;]+)/) ?? cookie.match(/(?:^|;\s*)cobe_news_csrf=([^;]+)/)
  return m ? decodeURIComponent(m[1]) : ""
}

let expiredHandler: (() => void) | null = null
/** Registered by <AuthProvider/>: the session ended on the server – back to the sign-in. */
export function setSessionExpiredHandler(h: (() => void) | null) {
  expiredHandler = h
}

let activityListener: ((at: number) => void) | null = null
/**
 * Registered by <AuthProvider/> (lib/session-sync.ts): a request reached the server with this browser's session – it
 * may have moved "last active" there. `at`: when it was sent. Not for the look at the session itself (it never extends
 * it), the sign-in page's config, the health check or the sign-out.
 */
export function setActivityListener(l: ((at: number) => void) | null) {
  activityListener = l
}
const NO_ACTIVITY = new Set(["/api/auth/session", "/api/auth/config", "/api/auth/logout", "/api/health"])
function activity(path: string, at: number) {
  if (!NO_ACTIVITY.has(path.split("?")[0])) activityListener?.(at)
}

/** A 401 that means the session is over: any request of the signed-in app, and the re-confirmation of who is at the
 *  keyboard (reauth dialog) – not the steps of a sign-in, whose 401 is about that sign-in. */
const endsSession = (path: string) => !path.startsWith("/api/auth/") || path === "/api/auth/reauth"

function errorOf(status: number, data: unknown): ApiError {
  const detail = (data as { detail?: unknown })?.detail
  return new ApiError(status, typeof detail === "object" && detail ? (detail as Record<string, unknown>) : { code: `http_${status}` })
}

/**
 * `signal`: TanStack Query's (the query was dropped); `timeoutMs`: no answer by then → ApiError 504 "timeout";
 * `background`: the page asks on its own (a poll, a refetch – lib/poll.ts) – X-Cobe-Background: 1, the server answers
 * but does not count it as activity (deps.background), and neither do the tabs (lib/session-sync.ts).
 */
export interface RequestOpts {
  signal?: AbortSignal
  timeoutMs?: number
  background?: boolean
}

export const BACKGROUND_HEADER = "X-Cobe-Background"

async function raw<T>(method: string, path: string, body?: unknown, opts: RequestOpts = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" }
  if (body !== undefined) headers["Content-Type"] = "application/json"
  if (!["GET", "HEAD"].includes(method)) headers["X-CSRF-Token"] = csrfToken()
  if (opts.background) headers[BACKGROUND_HEADER] = "1"
  const ctl = new AbortController()
  let timedOut = false
  const timer = opts.timeoutMs ? setTimeout(() => ((timedOut = true), ctl.abort()), opts.timeoutMs) : undefined
  const cancel = () => ctl.abort()
  if (opts.signal?.aborted) ctl.abort()
  opts.signal?.addEventListener("abort", cancel)
  let res: Response
  let text: string
  try {
    res = await fetch(path, { method, headers, credentials: "same-origin", body: body === undefined ? undefined : JSON.stringify(body), signal: ctl.signal })
    text = await res.text()
  } catch (e) {
    if (timedOut) throw new ApiError(504, { code: "timeout" })
    throw e
  } finally {
    clearTimeout(timer)
    opts.signal?.removeEventListener("abort", cancel)
  }
  let data: unknown = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = { code: `http_${res.status}` }
  }
  if (!res.ok) throw errorOf(res.status, data)
  return data as T
}

async function request<T>(method: string, path: string, body?: unknown, opts?: RequestOpts): Promise<T> {
  // the CSRF cookie comes with the first API answer – before the first write, ask once
  if (!["GET", "HEAD"].includes(method) && !csrfToken()) await raw("GET", "/api/auth/config")
  const at = Date.now()
  const counts = !opts?.background // a background request keeps nothing alive – on the server neither
  try {
    const out = await raw<T>(method, path, body, opts)
    if (counts) activity(path, at)
    return out
  } catch (e) {
    // an answer all the same: the session was there (not: refused before it was looked at, or no answer in time)
    if (counts && e instanceof ApiError && e.status !== 401 && e.code !== "csrf_failed" && e.code !== "timeout") activity(path, at)
    if (e instanceof ApiError && e.status === 401 && e.code === "not_authenticated" && endsSession(path)) expiredHandler?.()
    throw e
  }
}

/** A file from a GET endpoint – errors as ApiError (a plain link would save the error JSON as the file). */
async function getFile(path: string): Promise<{ blob: Blob; filename: string }> {
  const at = Date.now()
  const res = await fetch(path, { credentials: "same-origin" })
  if (res.status !== 401) activity(path, at)
  if (!res.ok) throw errorOf(res.status, await res.json().catch(() => null))
  const filename = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") ?? "")?.[1] ?? "download"
  return { blob: await res.blob(), filename }
}

export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 5000)
}

/** A drawer's details: no answer within this → the error with "try again" instead of an endless spinner. */
export const DETAIL_TIMEOUT_MS = 10_000

/**
 * Retries of a drawer's query: one quick retry after a server error or a lost connection, then the error with "try
 * again" – never a minute of silent retries. A timeout is not tried again on its own; a refusal (4xx) is an answer.
 */
export function detailRetry(count: number, err: unknown): boolean {
  if (count >= 1) return false
  if (err instanceof ApiError) return (err.status >= 500 || err.status === 429) && err.code !== "timeout"
  return true
}

export const api = {
  get: <T>(path: string, opts?: RequestOpts) => request<T>("GET", path, undefined, opts),
  post: <T>(path: string, body?: unknown, opts?: RequestOpts) => request<T>("POST", path, body ?? {}, opts),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body ?? {}),
  del: <T>(path: string) => request<T>("DELETE", path),
  getFile,
}

// ---------------------------------------------------------------- shared types

export type Role = "admin" | "reader"

export interface ApiUser {
  id: string
  username: string
  display_name: string
  email: string | null
  role: Role
  auth_source: "local" | "ldap" | "entra"
  totp: boolean
  is_emergency: boolean
}

export interface AuthConfig {
  setup_required: boolean
  ldap_enabled: boolean
  entra_enabled: boolean
  /** passkeys: switched on, possible at BASE_URL (`reason` otherwise: ip_host | not_https …), bound to `origin` */
  passkeys?: { enabled: boolean; available: boolean; reason: string | null; origin: string | null }
}

export type LoginNext = "mfa" | "password" | "enroll" | "done"

export interface LoginStep {
  next: LoginNext
  user?: ApiUser
}
