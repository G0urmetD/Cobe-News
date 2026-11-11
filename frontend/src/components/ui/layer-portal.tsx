import type * as React from "react"
import { createPortal } from "react-dom"

/**
 * The overlay and the content of a drawer or dialog in ONE portal (into <body>), in this order.
 *
 * Radix's Dialog.Portal gives each of its children a portal of its own, and a portal's element is appended to <body>
 * when it mounts. Closed and opened again while it was still going out – the overlay (100 ms) already gone, the content
 * (200 ms in a drawer) still sliding out – the overlay came back AFTER the content: both z-50, so the later one won and
 * the dimming lay over the drawer, which took no click any more (Vendor News, a product's drawer opened again at once).
 * In one portal React puts the overlay back before the content, wherever it is. Browser check: e2e/drawer-reopen.mjs.
 */
export function LayerPortal({ children }: { children: React.ReactNode }) {
  return typeof document === "undefined" ? null : createPortal(children, document.body)
}
