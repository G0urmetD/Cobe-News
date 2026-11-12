import { type InfiniteData, useMutation, useQueryClient } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { type ProductDetail, productKeyOf } from "@/lib/vendor-api"

/*
 * "Treffer bestätigen" (backend app/finding_confirm.py): a finding of a followed product assessed once for everybody –
 * not affected, mitigated or the risk accepted. It counts as handled (not in the numbers that mean "needs attention")
 * and is not notified, until somebody undoes it or the finding changes materially (then it lapses by itself). Muting
 * (lib/reader-api.ts) is a person's own and temporary; this is shared and lasting. Admins and the members of a team the
 * product belongs to may confirm (`can_confirm` of the product), everybody else sees it.
 */

export const CONFIRM_STATUSES = ["not_affected", "mitigated", "accepted"] as const
export type ConfirmStatus = (typeof CONFIRM_STATUSES)[number]

/** The note's limit – the server's NOTE_MAX. */
export const NOTE_MAX = 500
/** The statuses that need a reason – the server's NOTE_REQUIRED. */
export const NOTE_REQUIRED: readonly ConfirmStatus[] = ["accepted"]

/** Why the confirmation lapsed by itself (the server's REASONS without "undone"). */
export type LapseReason = "exploited" | "severity" | "cves" | "verdict" | "withdrawn" | "regrouped"

/** A confirmation that stands: what, why, who, when. */
export interface Confirmation {
  status: ConfirmStatus
  note: string
  by: string
  at: string
}

/** A confirmation that lapsed lately because the finding changed. */
export interface ConfirmLapse {
  status: ConfirmStatus
  reason: LapseReason
  at: string
  by: string
}

/** What keeps the dialog from saving – null: it may be saved. */
export function confirmProblem(status: ConfirmStatus | "", note: string): "status" | "note_required" | "too_long" | null {
  if (!status) return "status"
  if (note.length > NOTE_MAX) return "too_long"
  if (NOTE_REQUIRED.includes(status) && !note.trim()) return "note_required"
  return null
}

/** The note as the server stores it: one line, single spaces. */
export const cleanNote = (note: string) => note.split(/\s+/).filter(Boolean).join(" ")

export const confirmFinding = (b: { product: string; finding: string; status: ConfirmStatus; note: string }) =>
  api.post<{ product: string; finding: string; confirmed: Confirmation }>("/api/vendor/findings/confirm", { ...b, note: cleanNote(b.note) })

export const unconfirmFinding = (b: { product: string; finding: string }) => api.post<{ product: string; finding: string; confirmed: null }>("/api/vendor/findings/unconfirm", b)

/** The drawer's loaded pages with one finding's confirmation set from the server's answer (a copy – null: undone). */
export function withConfirmation(data: InfiniteData<ProductDetail> | undefined, finding: string, confirmed: Confirmation | null): InfiniteData<ProductDetail> | undefined {
  if (!data) return data
  return { ...data, pages: data.pages.map((pg) => ({ ...pg, findings: pg.findings.map((f) => (f.id === finding ? { ...f, confirmed, confirm_lapsed: null } : f)) })) }
}

/** The queries a confirmation changes: the product's drawer (not its revisions), the overview, the badge, the unread numbers. */
export function confirmTouches(product: string, key: readonly unknown[]): boolean {
  if (key[0] === "reader") return key[1] === "counts"
  if (key[0] !== "vendor") return false
  if (key[1] === "overview" || key[1] === "badge") return true
  return key[1] === "product" && key[2] === product && key[3] !== "changes"
}

/**
 * Confirm / undo: the drawer shows the answer at once (its loaded pages patched), then the views it changes are read
 * again in the background – the product's drawer, the overview, the badge and the unread numbers in the sidebar; not
 * every Vendor News query (the catalogue, the revisions), and the button does not wait for them.
 */
export function useFindingConfirm(product: string) {
  const qc = useQueryClient()
  const done = (finding: string, confirmed: Confirmation | null) => {
    qc.setQueriesData<InfiniteData<ProductDetail>>({ queryKey: productKeyOf(product), predicate: (q) => q.queryKey[3] !== "changes" }, (d) =>
      withConfirmation(d, finding, confirmed),
    )
    void qc.invalidateQueries({ predicate: (q) => confirmTouches(product, q.queryKey) })
  }
  const confirm = useMutation({
    mutationFn: (b: { finding: string; status: ConfirmStatus; note: string }) => confirmFinding({ product, ...b }),
    onSuccess: (r) => done(r.finding, r.confirmed),
  })
  const undo = useMutation({ mutationFn: (finding: string) => unconfirmFinding({ product, finding }), onSuccess: (r) => done(r.finding, null) })
  return { confirm, undo, busy: confirm.isPending || undo.isPending }
}

/** The lines a card shows: the open ones – with "Mit Bestätigten" also the confirmed ones, after them. */
export function cardLines<T extends { id: string }>(open: T[], confirmed: T[] | undefined, show: boolean, max = 3): { line: T; confirmed: boolean }[] {
  const out = open.slice(0, max).map((line) => ({ line, confirmed: false }))
  if (show) for (const line of (confirmed ?? []).slice(0, max)) out.push({ line, confirmed: true })
  return out
}
