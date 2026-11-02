import { ApiError } from "@/lib/api"

/**
 * Sensitive admin actions (sign-in settings, group mappings, admins, resets, deletions) need a proof of identity of the
 * last minutes – the server answers 403 "reauth_required" otherwise (deps.require_reauth). `withReauth` asks for it
 * (<ReauthHost/>, components/cobe/reauth.tsx) and repeats the action once confirmed: local and AD accounts with their
 * password and the current TOTP code, Entra accounts at Microsoft (the page leaves for the sign-in and comes back – the
 * action is then done again by hand).
 */
export type ReauthAsk = { id: number; via: "password" | "entra"; totp: boolean; resolve: (ok: boolean) => void }

let current: ReauthAsk | null = null
let asked = 0
const listeners = new Set<() => void>()
const emit = () => listeners.forEach((l) => l())

export const reauthStore = {
  subscribe(l: () => void) {
    listeners.add(l)
    return () => {
      listeners.delete(l)
    }
  },
  get: () => current,
}

function ask(via: ReauthAsk["via"], totp: boolean): Promise<boolean> {
  current?.resolve(false)
  return new Promise((resolve) => {
    current = { id: ++asked, via, totp, resolve } // every question a fresh dialog: nothing typed is carried over
    emit()
  })
}

export function closeReauth(ok: boolean) {
  current?.resolve(ok)
  current = null
  emit()
}

export function isReauthRequired(e: unknown): e is ApiError {
  return e instanceof ApiError && e.status === 403 && e.code === "reauth_required"
}

/** Runs `fn`; when the server asks for a fresh proof of identity: asks for it, then runs `fn` once more. */
export async function withReauth<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    if (!isReauthRequired(e)) throw e
    const ok = await ask(e.data.via === "entra" ? "entra" : "password", e.data.totp === true)
    if (!ok) throw new ApiError(400, { code: "reauth_cancelled" })
    return await fn()
  }
}

/** Where an Entra account confirms itself: Microsoft's sign-in, then back to `here` (a path of this app). */
export function entraReauthUrl(here: string): string {
  return `/api/auth/oidc/start?reauth=1&next=${encodeURIComponent(here)}`
}

/**
 * The question has to be answered before anything else, so it stays the topmost layer wherever it opens. Radix stacks
 * its layers (drawers, dialogs, menus) in the order they mount – the order on <body>, its layer stack (which layer gets
 * pointer events) and its focus-scope stack (which one keeps the focus) – and all of them sit at z-50: a drawer or a
 * dialog that mounts after the question (one opened from the address, one whose content is drawn anew) lay on top of
 * it and kept the focus, the fields could not be used. True when `node`, just added to <body>, is such a layer after
 * `prompt` – <ReauthHost/> then mounts the question again, as the last layer.
 */
export function coversPrompt(prompt: Element, node: Node): boolean {
  if (node === prompt || node.nodeType !== 1) return false
  if (!(prompt.compareDocumentPosition(node) & 4)) return false // Node.DOCUMENT_POSITION_FOLLOWING
  const el = node as Element
  return el.matches(MODAL_LAYER) || !!el.querySelector(MODAL_LAYER)
}

const MODAL_LAYER = "[role=dialog], [role=alertdialog]"
