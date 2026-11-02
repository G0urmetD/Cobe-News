import { useSyncExternalStore } from "react"
import { useTranslation } from "react-i18next"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"

/**
 * One rule for removing things (see docs/UX.md):
 * - entries of a working list (IOCs, entities, tasks): removed at once, with "undo" for a few seconds (lib/undo.ts)
 * - evidence, compliance records and security settings: asked first, here – one click must not lose them
 */
type Ask = { title: string; text?: string; confirm?: string; cancel?: string; destructive?: boolean; resolve: (ok: boolean) => void }

let current: Ask | null = null
const listeners = new Set<() => void>()
const emit = () => listeners.forEach((l) => l())

/** Asks before an action that cannot be undone; resolves true once confirmed. */
export function confirmAction(opts: Omit<Ask, "resolve">): Promise<boolean> {
  current?.resolve(false)
  return new Promise((resolve) => {
    current = { destructive: true, ...opts, resolve }
    emit()
  })
}

function close(ok: boolean) {
  current?.resolve(ok)
  current = null
  emit()
}

/** An open question is answered "no" – the session ended (lib/auth.tsx): nothing is done after the sign-in page. */
export function closeConfirm() {
  if (current) close(false)
}

/** Mounted once next to the app. */
export function ConfirmHost() {
  const { t } = useTranslation()
  const ask = useSyncExternalStore(
    (l) => (listeners.add(l), () => listeners.delete(l)),
    () => current,
  )
  return (
    <Dialog open={!!ask} onOpenChange={(o) => !o && close(false)}>
      {ask && (
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{ask.title}</DialogTitle>
            {ask.text && <DialogDescription className="whitespace-pre-line [overflow-wrap:anywhere]">{ask.text}</DialogDescription>}
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => close(false)}>
              {ask.cancel ?? t("common.cancel")}
            </Button>
            <Button variant={ask.destructive ? "destructive" : "default"} onClick={() => close(true)} autoFocus>
              {ask.confirm ?? t("common.remove")}
            </Button>
          </DialogFooter>
        </DialogContent>
      )}
    </Dialog>
  )
}
