/**
 * Where the focus goes when a drawer or dialog opens (see docs/UX.md, "Fokus in Schubladen und Dialogen").
 *
 * Radix focuses the first focusable element inside on open – in a drawer header that is often a term with an
 * explanation (CPE) or a time stamp, whose tooltip then pops up by itself, unasked. Instead the drawer itself takes the
 * focus: screen readers announce it with its title, Tab goes on to the first control (where the tooltip opens, because
 * somebody asked for it), Escape still closes. An element inside with `autoFocus` keeps the focus (Radix does not ask
 * then), and a handler of the page's own runs first and may decide otherwise (preventDefault and focus something).
 */
export function focusContentOnOpen(own?: (e: Event) => void): (e: Event) => void {
  return (e) => {
    own?.(e)
    if (e.defaultPrevented) return
    e.preventDefault()
    const el = e.target as HTMLElement | null
    el?.focus?.({ preventScroll: true })
  }
}

/**
 * Where the focus goes when a small form dialog opens (the re-confirmation): into the field that had it when the dialog
 * was drawn anew (`keep`, an id), else into the first empty field, else the last one. Through Radix' own "focus on
 * open", not React's autoFocus: autoFocus fires while the dialog is being inserted, before Radix has paused the focus
 * trap of a drawer or dialog underneath – that trap pulled the focus straight back, and typing went nowhere.
 */
export function focusFieldOnOpen(e: Event, keep?: string | null): void {
  const fields = [...((e.target as HTMLElement | null)?.querySelectorAll?.<HTMLInputElement>("input:not([disabled])") ?? [])]
  const field = fields.find((f) => !!keep && f.id === keep) ?? fields.find((f) => !f.value) ?? fields.at(-1)
  if (!field) return // nothing to type in (Entra: a button) – the dialog itself takes the focus (focusContentOnOpen)
  e.preventDefault()
  field.focus({ preventScroll: true })
}

/**
 * Where the focus goes when a drawer closes: back to what opened it (the card, the row, the button) – keyboard users go
 * on where they were. Not when that element is gone (unfollowed, filtered away) – and never onto the trigger of a
 * tooltip: focus opens a tooltip, and one must not pop up by itself (its focusable parent takes the focus instead).
 */
export function restoreFocus(el: Element | null | undefined): boolean {
  const usable = (x: Element | null | undefined): x is HTMLElement => !!x && x.isConnected && x.tagName !== "BODY" && typeof (x as HTMLElement).focus === "function"
  let target: HTMLElement | null = usable(el) ? el : null
  while (target?.matches("[data-slot=tooltip-trigger]")) {
    const up = target.parentElement?.closest("button, a[href], [tabindex]")
    target = usable(up) ? up : null
  }
  if (!target) return false
  target.focus({ preventScroll: true })
  return true
}
