import { useEffect, useRef, useSyncExternalStore } from "react"
import { useBlocker } from "react-router"
import { useTranslation } from "react-i18next"
import { confirmAction } from "@/components/cobe/confirm"
import i18n from "@/i18n"

// Forms with changes not saved yet. One guard for all of them (a router supports a single blocker, and a settings page
// can hold four forms).
const dirty = new Set<symbol>()
const listeners = new Set<() => void>()
const emit = () => listeners.forEach((l) => l())
const anyDirty = () => dirty.size > 0

/**
 * Marks the calling form as having unsaved changes while `isDirty` is true. Returns `release`: call it right before
 * navigating away on purpose after saving or deleting (the state update would come too late for that navigation).
 */
export function useDirty(isDirty: boolean) {
  const id = useRef(Symbol("form"))
  useEffect(() => {
    const key = id.current
    if (isDirty) dirty.add(key)
    else dirty.delete(key)
    emit()
    return () => {
      dirty.delete(key)
      emit()
    }
  }, [isDirty])
  return () => {
    dirty.delete(id.current)
    emit()
  }
}

/** Before switching away within a page (a tab, another record) – asks if a form has unsaved changes. */
export async function confirmDiscard(text?: string): Promise<boolean> {
  if (!anyDirty()) return true
  const ok = await confirmAction({ title: i18n.t("unsaved.title"), text: text ?? i18n.t("unsaved.text"), confirm: i18n.t("unsaved.discard") })
  if (ok) clearDirty()
  return ok
}

/** Forget all unsaved marks – before signing out (the changes are gone anyway). */
export function clearDirty() {
  dirty.clear()
  emit()
}

/** Mounted once in the app frame: asks before leaving a page with unsaved changes – in the app and when closing the tab. */
export function UnsavedGuard() {
  const { t } = useTranslation()
  const any = useSyncExternalStore((l) => (listeners.add(l), () => listeners.delete(l)), anyDirty)
  // only another page – switching a filter or tab within the same page keeps the form
  // read at the moment of navigating (a form released just before is not asked about)
  const blocker = useBlocker(({ currentLocation, nextLocation }) => anyDirty() && currentLocation.pathname !== nextLocation.pathname)
  useEffect(() => {
    if (blocker.state !== "blocked") return
    void confirmAction({ title: t("unsaved.title"), text: t("unsaved.text"), confirm: t("unsaved.leave") }).then((ok) => {
      if (ok) {
        dirty.clear()
        emit()
        blocker.proceed()
      } else blocker.reset()
    })
  }, [blocker, t])
  useEffect(() => {
    if (!any) return
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      e.returnValue = "" // the browser shows its own question
    }
    window.addEventListener("beforeunload", warn)
    return () => window.removeEventListener("beforeunload", warn)
  }, [any])
  return null
}
