import { Component, type ErrorInfo, type ReactNode, useState } from "react"
import { useTranslation } from "react-i18next"
import { AlertTriangle, ChevronDown, ChevronRight, Home, Loader2, RotateCw, WifiOff } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError } from "@/lib/api"
import { errorText } from "@/lib/errors"
import { cn } from "@/lib/utils"

/** No answer at all, or the server failed – worth trying again (a 4xx is an answer). */
export function retryable(err: unknown): boolean {
  return !(err instanceof ApiError) || err.status >= 500 || err.status === 429
}

/**
 * A list or page that could not be loaded – never shown as "nothing there": during an incident an empty list after a
 * network hiccup would tell the analyst there are no cases, IOCs or tasks.
 */
export function QueryError({ error, onRetry, compact = false, className }: { error: unknown; onRetry?: () => void; compact?: boolean; className?: string }) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const offline = error instanceof TypeError
  const Icon = offline ? WifiOff : AlertTriangle
  const retry = onRetry
    ? async () => {
        setBusy(true)
        try {
          await onRetry()
        } finally {
          setBusy(false)
        }
      }
    : undefined
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-sev-critical/40 bg-sev-critical/5 text-center",
        compact ? "px-4 py-6" : "px-6 py-14",
        className,
      )}
    >
      <div className="flex size-10 items-center justify-center rounded-full bg-sev-critical/10 text-sev-critical">
        <Icon className="size-5" />
      </div>
      <div className="space-y-1">
        <p className="font-medium">{offline ? t("errors.loadOffline") : t("errors.loadFailed")}</p>
        <p className="max-w-md text-sm text-muted-foreground">{offline ? t("errors.loadOfflineText") : errorText(t, error)}</p>
      </div>
      {retry && (
        <Button variant="outline" size="sm" onClick={() => void retry()} disabled={busy}>
          {busy ? <Loader2 className="animate-spin" /> : <RotateCw />} {t("errors.retry")}
        </Button>
      )}
    </div>
  )
}

/** Loading spinner – or the error with "try again" once the query failed. */
export function Pending({ error, onRetry, className }: { error?: unknown; onRetry?: () => void; className?: string }) {
  if (error) return <QueryError error={error} onRetry={onRetry} className={className} />
  return (
    <div className={cn("flex justify-center py-16", className)}>
      <Loader2 className="size-5 animate-spin text-muted-foreground" aria-label="…" />
    </div>
  )
}

/** A drawer's body while its details load: the shape of what comes, not an empty sheet with a spinner. */
export function DrawerSkeleton({ label }: { label: string }) {
  return (
    <div role="status" aria-live="polite" className="space-y-3">
      <span className="sr-only">{label}</span>
      <Skeleton className="h-16 w-full rounded-lg" />
      <Skeleton className="h-4 w-2/3" />
      <Skeleton className="h-4 w-1/2" />
      <Skeleton className="h-24 w-full rounded-lg" />
      <Skeleton className="h-24 w-full rounded-lg" />
    </div>
  )
}

/**
 * A page that crashed while rendering shows this instead of a white screen – the sidebar, the other pages and the
 * open case stay usable. Reset when the address changes.
 */
export class PageErrorBoundary extends Component<{ children: ReactNode; resetKey: string; full?: boolean }, { error: Error | null; resetKey: string }> {
  state = { error: null as Error | null, resetKey: this.props.resetKey }
  static getDerivedStateFromError(error: Error) {
    return { error }
  }
  // another address: the crash notice goes before that render (not in a second one after it)
  static getDerivedStateFromProps(props: { resetKey: string }, state: { error: Error | null; resetKey: string }) {
    return props.resetKey !== state.resetKey ? { error: null, resetKey: props.resetKey } : null
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("page crashed", error, info.componentStack)
  }
  render() {
    if (!this.state.error) return this.props.children
    return <CrashNotice error={this.state.error} full={this.props.full} onRetry={() => this.setState({ error: null })} />
  }
}

function CrashNotice({ error, full, onRetry }: { error: Error; full?: boolean; onRetry: () => void }) {
  const { t } = useTranslation()
  const [details, setDetails] = useState(false)
  return (
    <div className={cn("flex justify-center", full ? "min-h-svh items-center p-6" : "py-16")}>
      <div role="alert" className="w-full max-w-lg space-y-4 rounded-xl border bg-card p-6 text-center shadow-sm">
        <div className="mx-auto flex size-11 items-center justify-center rounded-full bg-sev-critical/10 text-sev-critical">
          <AlertTriangle className="size-5" />
        </div>
        <div className="space-y-1">
          <p className="text-lg font-semibold">{t("errors.crashTitle")}</p>
          <p className="text-sm text-muted-foreground">{full ? t("errors.crashTextFull") : t("errors.crashText")}</p>
        </div>
        <div className="flex flex-wrap justify-center gap-2">
          <Button onClick={full ? () => window.location.reload() : onRetry}>
            <RotateCw /> {full ? t("errors.reload") : t("errors.retry")}
          </Button>
          {!full && (
            <Button variant="outline" onClick={() => (window.location.href = "/")}>
              <Home /> {t("errors.toStart")}
            </Button>
          )}
        </div>
        <button type="button" onClick={() => setDetails(!details)} className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
          {details ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />} {t("errors.crashDetails")}
        </button>
        {details && <pre className="max-h-40 overflow-auto rounded-lg bg-muted p-2 text-left text-xs whitespace-pre-wrap">{String(error.message || error)}</pre>}
      </div>
    </div>
  )
}
