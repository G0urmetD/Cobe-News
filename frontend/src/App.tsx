import { Suspense, lazy, useCallback, useEffect } from "react"
import { Navigate, Route, Routes, useNavigate } from "react-router"
import { Loader2 } from "lucide-react"
import { AppShell } from "@/components/cobe/app-shell"
import { QueryError } from "@/components/cobe/query-state"
import { FullPageSpinner, useAuth } from "@/lib/auth"
import { useDesktopNotifications } from "@/lib/desktop"
import { useDesktopPrefs } from "@/lib/news-api"
import { safePath } from "@/lib/safe-path"
import { NewsPage } from "@/pages/news"

// loaded when needed: the sign-in and setup pages (QR code, code input) and the settings are separate chunks
const LoginPage = lazy(() => import("@/pages/login").then((m) => ({ default: m.LoginPage })))
const SetupPage = lazy(() => import("@/pages/setup").then((m) => ({ default: m.SetupPage })))
const SettingsPage = lazy(() => import("@/pages/settings").then((m) => ({ default: m.SettingsPage })))
const VendorPage = lazy(() => import("@/pages/vendor").then((m) => ({ default: m.VendorPage })))
const WatchPage = lazy(() => import("@/pages/settings-watch").then((m) => ({ default: m.WatchPage })))
const AboutPage = lazy(() => import("@/pages/about").then((m) => ({ default: m.AboutPage })))
const DocsPage = lazy(() => import("@/pages/docs").then((m) => ({ default: m.DocsPage })))

/** First start → setup wizard; not signed in → sign-in; then the app's frame with the news and the settings. */
export default function App() {
  const auth = useAuth()
  if (auth.loading) return <FullPageSpinner />
  // the server did not answer: an error with "try again" – not a sign-in form that cannot work
  if (auth.failed)
    return (
      <div className="flex min-h-svh items-center justify-center p-4">
        <QueryError error={auth.error ?? new Error("load")} onRetry={() => void auth.refresh()} className="w-full max-w-md" />
      </div>
    )
  return (
    <Suspense fallback={<FullPageSpinner />}>
      {auth.config?.setup_required ? <SetupPage /> : !auth.user ? <LoginPage key={auth.stage ?? "start"} resume={auth.stage ?? undefined} /> : <SignedIn />}
    </Suspense>
  )
}

function SignedIn() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const prefs = useDesktopPrefs(!!user).data
  // a desktop notification opens its story on the news page – from wherever the person is
  const openStory = useCallback((id: string | null) => navigate(id ? `/?story=${encodeURIComponent(id)}` : "/"), [navigate])
  useDesktopNotifications(user?.id, prefs, openStory)
  // a click on a notification the service worker showed (push with the tab closed, or a tab's own): it focuses this
  // tab and says which story – only paths of this app
  useEffect(() => {
    const sw = "serviceWorker" in navigator ? navigator.serviceWorker : null
    if (!sw) return
    const onMessage = (e: MessageEvent) => {
      const d = e.data as { type?: string; url?: unknown } | null
      const path = d?.type === "cobe-news-open" ? safePath(d.url, window.location.origin) : null
      if (path) navigate(path)
    }
    sw.addEventListener("message", onMessage)
    return () => sw.removeEventListener("message", onMessage)
  }, [navigate])
  return (
    <AppShell>
      <Routes>
        <Route index element={<NewsPage />} />
        <Route path="vendor" element={<Lazy page={<VendorPage />} />} />
        <Route path="watch" element={<Lazy page={<WatchPage />} />} />
        <Route path="settings" element={<Lazy page={<SettingsPage />} />} />
        <Route path="settings/:section" element={<Lazy page={<SettingsPage />} />} />
        <Route path="about" element={<Lazy page={<AboutPage />} />} />
        <Route path="docs" element={<Lazy page={<DocsPage />} />} />
        <Route path="docs/:chapter" element={<Lazy page={<DocsPage />} />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  )
}

function Lazy({ page }: { page: React.ReactNode }) {
  return (
    <Suspense
      fallback={
        <div className="flex justify-center py-16">
          <Loader2 className="size-5 animate-spin text-muted-foreground" />
        </div>
      }
    >
      {page}
    </Suspense>
  )
}
