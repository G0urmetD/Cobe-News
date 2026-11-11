import { readFileSync } from "node:fs"
import { describe, expect, it } from "vitest"

// A drawer opened again while it was still going out had its dimming ON TOP of it (Vendor News at a product from a
// notification): Radix's Dialog.Portal gives the overlay and the content a portal each, and the overlay (gone first)
// came back after the content in <body>. components/ui/layer-portal.tsx puts both in one portal – this guard fails when
// an update of the shadcn files brings the per-child Radix portal back. The browser check: e2e/drawer-reopen.mjs.
const ui = (name: string) => readFileSync(`${import.meta.dirname}/../components/ui/${name}`, "utf8")

describe("overlay and content of a drawer or dialog share one portal", () => {
  for (const [file, overlay, content] of [
    ["sheet.tsx", "<SheetOverlay />", "<SheetPrimitive.Content"],
    ["dialog.tsx", "<DialogOverlay className={overlayClassName} />", "<DialogPrimitive.Content"],
  ] as const) {
    it(file, () => {
      const src = ui(file)
      const body = /<LayerPortal>([\s\S]*?)<\/LayerPortal>/.exec(src)?.[1] ?? ""
      expect(body.indexOf(overlay)).toBeGreaterThanOrEqual(0)
      expect(body.indexOf(content)).toBeGreaterThan(body.indexOf(overlay))
      expect(src).not.toMatch(/<(Sheet|Dialog)Portal>\s*<(Sheet|Dialog)Overlay/)
    })
  }

  it("is one React portal into <body>", () => {
    expect(ui("layer-portal.tsx")).toContain("createPortal(children, document.body)")
  })
})
