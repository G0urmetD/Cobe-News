import type { ApiUser, AuthConfig } from "@/lib/api"

/** Where a sign-in stands (pure – lib/auth.tsx holds it, auth-state.test.ts checks it). */
export interface AuthData {
  loading: boolean
  /** /api/auth/config or /api/auth/state could not be read – an error with "try again", not the sign-in form */
  failed: boolean
  /** why (0.1.51): the page says it – "the server cannot reach its database", "not reachable" – not only "failed" */
  error?: unknown
  config: AuthConfig | null
  user: ApiUser | null
  /** a sign-in in progress (after a reload): mfa | password | enroll */
  stage: "mfa" | "password" | "enroll" | null
}

export type AuthAction =
  | { type: "loaded"; config: AuthConfig; stage: string | null; user?: ApiUser | null }
  | { type: "failed"; error?: unknown }
  | { type: "user"; user: ApiUser | null }
  | { type: "signedOut" }

export const initialAuth: AuthData = { loading: true, failed: false, config: null, user: null, stage: null }

const STAGES = ["mfa", "password", "enroll"] as const

export function authReducer(s: AuthData, a: AuthAction): AuthData {
  switch (a.type) {
    case "loaded":
      return {
        loading: false,
        failed: false,
        error: undefined,
        config: a.config,
        user: a.stage === "active" && a.user ? a.user : null,
        stage: (STAGES as readonly string[]).includes(a.stage ?? "") ? (a.stage as AuthData["stage"]) : null,
      }
    case "failed":
      return { ...s, loading: false, failed: true, error: a.error }
    // a finished sign-in, or one ended: a resumed step (mfa, enroll) never outlives it
    case "user":
      return { ...s, user: a.user, stage: null }
    case "signedOut":
      return { ...s, user: null, stage: null }
  }
}

/** What this browser keeps per person – gone at sign-out (a shared computer must not keep another's filters). */
export const userStorageKeys = (userId: string) => [
  `cobe-news.filter.${userId}`,
  `cobe-news.desktop.cursor.${userId}`, // before the arrival numbers: a time
  `cobe-news.desktop.seq.${userId}`,
  `cobe-news.desktop.seen.${userId}`,
  `cobe-news.desktop.last.${userId}`,
  `cobe-news.push.active.${userId}`,
]

export function clearUserStorage(userId: string | undefined, storage: Pick<Storage, "removeItem"> | null = typeof localStorage === "undefined" ? null : localStorage) {
  if (!userId || !storage) return
  for (const k of userStorageKeys(userId)) {
    try {
      storage.removeItem(k)
    } catch {
      /* private mode */
    }
  }
}
