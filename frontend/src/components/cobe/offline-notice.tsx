import { useSyncExternalStore } from "react"
import { useTranslation } from "react-i18next"
import { WifiOff } from "lucide-react"

function subscribe(cb: () => void) {
  window.addEventListener("online", cb)
  window.addEventListener("offline", cb)
  return () => {
    window.removeEventListener("online", cb)
    window.removeEventListener("offline", cb)
  }
}

/** Whether the browser says it has a network – true where it cannot tell. */
export const useOnline = () =>
  useSyncExternalStore(
    subscribe,
    () => navigator.onLine,
    () => true,
  )

/**
 * The browser is offline: said once, at the top, on every page (0.1.51). Without it a page waited with "Wird geladen …"
 * for as long as the network was gone – the queries pause while offline (TanStack Query) and go on by themselves once
 * it is back, so this notice is all that is needed.
 */
export function OfflineNotice() {
  const { t } = useTranslation()
  const online = useOnline()
  if (online) return null
  return (
    <div role="status" aria-live="polite" className="pointer-events-none fixed inset-x-0 top-3 z-[60] flex justify-center px-3">
      <div className="pointer-events-auto flex max-w-lg items-start gap-2 rounded-lg border border-warning/40 bg-background px-3 py-2 text-sm shadow-md">
        <WifiOff className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden />
        <div>
          <p className="font-medium">{t("offline.title")}</p>
          <p className="text-muted-foreground">{t("offline.text")}</p>
        </div>
      </div>
    </div>
  )
}
