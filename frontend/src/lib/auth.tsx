import { createContext, useCallback, useContext, useEffect, useMemo, useReducer, useRef } from "react"
import { useTranslation } from "react-i18next"
import { useNavigate } from "react-router"
import { Loader2 } from "lucide-react"
import { useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { ApiError, api, setActivityListener, setSessionExpiredHandler, type ApiUser, type AuthConfig } from "@/lib/api"
import { disablePush } from "@/lib/push"
import { type AuthData, authReducer, clearUserStorage, initialAuth } from "@/lib/auth-state"
import { errorText } from "@/lib/errors"
import { closeReauth } from "@/lib/reauth"
import { SessionSync, type SessionTimes, type SignOutReason } from "@/lib/session-sync"
import { closeConfirm } from "@/components/cobe/confirm"
import { clearDirty } from "@/lib/unsaved"

/** Who is signed in (two roles only): config of the sign-in page, the user, logout. */
interface AuthState extends AuthData {
  isAdmin: boolean
  refresh: () => Promise<void>
  setUser: (u: ApiUser | null) => void
  /** false when the server could not be told (the session would stay alive there) – the person stays signed in */
  logout: () => Promise<boolean>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const { i18n, t } = useTranslation()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [s, dispatch] = useReducer(authReducer, initialAuth)
  const times = useRef<SessionTimes | undefined>(undefined) // of the last /api/auth/state – the sync starts with them
  const sync = useRef<SessionSync | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [config, state] = await Promise.all([
        api.get<AuthConfig>("/api/auth/config"),
        api.get<{ stage: string | null; user?: ApiUser; session?: SessionTimes }>("/api/auth/state"),
      ])
      times.current = state.session
      dispatch({ type: "loaded", config, stage: state.stage, user: state.user })
    } catch (e) {
      dispatch({ type: "failed", error: e })
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const setUser = useCallback((u: ApiUser | null) => dispatch({ type: "user", user: u }), [])

  const userId = s.user?.id
  const signedIn = useRef(false)
  const userRef = useRef(userId)
  useEffect(() => {
    userRef.current = userId
  }, [userId])

  /**
   * This tab goes to the sign-in: no data of the account stays on screen (the query cache, toasts), no question stays
   * open (re-confirmation, "really?"), nothing of a drawer or dialog in the address. `elsewhere`: another tab said so.
   */
  const endHere = useCallback(
    (reason: SignOutReason, elsewhere: boolean) => {
      signedIn.current = false
      if (reason === "logout") clearUserStorage(userRef.current) // the sign-out tab did it too – this tab may have written since
      closeReauth(false)
      closeConfirm()
      clearDirty() // open forms are gone either way – no question on the way to the sign-in page
      toast.dismiss() // the warning, and whatever a toast said about the account's data
      qc.clear()
      dispatch({ type: "signedOut" })
      if (elsewhere || reason === "expired") navigate("/", { replace: true })
      if (reason === "expired") toast.info(i18n.t("auth.sessionExpired"))
      else if (elsewhere) toast.info(i18n.t("auth.signedOutElsewhere"))
    },
    [qc, i18n, navigate],
  )
  const endRef = useRef(endHere)
  useEffect(() => {
    endRef.current = endHere
  }, [endHere])
  const refreshRef = useRef(refresh)
  useEffect(() => {
    refreshRef.current = refresh
  }, [refresh])

  // every tab of this browser together (lib/session-sync.ts): signed out in one, signed out in all – also when the
  // session simply ran out while nobody clicked
  useEffect(() => {
    let warning: string | number | undefined // the warning toast shown – a fresh one each time
    const sy = new SessionSync({
      peek: async () => {
        try {
          return await api.get<SessionTimes>("/api/auth/session", { timeoutMs: 10_000 })
        } catch (e) {
          return e instanceof ApiError && e.status === 401 ? "ended" : "unknown"
        }
      },
      onSignedOut: (reason, elsewhere) => endRef.current(reason, elsewhere),
      onSignedIn: () => void refreshRef.current(),
      onWarning: (show, idleEnd) => {
        const old = warning
        warning = undefined
        if (old !== undefined) toast.dismiss(old)
        if (!show) return
        const time = new Date(idleEnd).toLocaleTimeString(i18n.language, { hour: "2-digit", minute: "2-digit" })
        const id = toast.warning(i18n.t("auth.sessionEnding"), {
          description: i18n.t("auth.sessionEndingText", { time }),
          duration: Infinity,
          // any request of the signed-in app moves "last active" – then the warning goes in every tab
          action: { label: i18n.t("auth.staySignedIn"), onClick: () => void api.get("/api/me").catch(() => undefined) },
          // closed by hand (sonner calls this for a dismissal of ours too – then it is no longer the current one)
          onDismiss: () => {
            if (warning !== id) return
            warning = undefined
            sy.dismissWarning()
          },
        })
        warning = id
      },
    })
    sync.current = sy
    setActivityListener((at) => sy.activity(at))
    const onVisible = () => document.visibilityState === "visible" && sy.visible()
    document.addEventListener("visibilitychange", onVisible)
    return () => {
      document.removeEventListener("visibilitychange", onVisible)
      setActivityListener(null)
      sy.close()
      sync.current = null
    }
  }, [i18n])

  // signed in (on load, after a sign-in of any kind) → the sync runs and tells the other tabs; signed out → it stops
  useEffect(() => {
    signedIn.current = !!userId
    const sy = sync.current
    if (!sy) return
    if (userId && !sy.signedIn) {
      sy.start(times.current)
      times.current = undefined
    } else if (!userId && sy.signedIn) sy.stop()
  }, [userId])

  const logout = useCallback(async () => {
    // this browser gets no push of mine any more – the next person at this computer signs in to their own
    await disablePush(userId).catch(() => undefined)
    try {
      await api.post("/api/auth/logout")
    } catch (e) {
      // already gone on the server (401): signed out all the same; anything else: say so and stay
      if (!(e instanceof ApiError && e.status === 401)) {
        toast.error(t("auth.logoutFailed"), { description: errorText(t, e) })
        return false
      }
    }
    if (sync.current?.signedIn)
      sync.current.signOut("logout") // every tab, this one included (endHere)
    else endHere("logout", false)
    return true
  }, [t, userId, endHere])

  // the session ended on the server while the tab was open (idle timeout, disabled, role changed): to the sign-in –
  // every tab of this browser
  useEffect(() => {
    setSessionExpiredHandler(() => {
      if (!signedIn.current) return
      if (sync.current?.signedIn) sync.current.signOut("expired")
      else endRef.current("expired", false)
    })
    return () => setSessionExpiredHandler(null)
  }, [])

  const value = useMemo(() => ({ ...s, isAdmin: s.user?.role === "admin", refresh, setUser, logout }), [s, refresh, setUser, logout])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth outside AuthProvider")
  return ctx
}

export function FullPageSpinner() {
  return (
    <div className="flex min-h-svh items-center justify-center">
      <Loader2 className="size-6 animate-spin text-muted-foreground" />
    </div>
  )
}
