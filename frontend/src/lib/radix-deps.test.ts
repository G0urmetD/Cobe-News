import { readFileSync } from "node:fs"
import { describe, expect, it } from "vitest"

// Two copies of a Radix package are two module instances with their own state: cmdk pulled a newer
// @radix-ui/react-dialog (with its own react-dismissable-layer/focus-scope) – then every Radix layer kept its own layer
// stack, Escape in a Select inside a Sheet closed both and left body.style.pointerEvents = "none". The "overrides" in
// package.json pin cmdk's Radix packages to the versions of radix-ui; this guard fails when an update brings a second
// copy back (a nested node_modules path counts too – same version, still a separate instance). The browser check:
// e2e/select-in-sheet.mjs.
describe("package-lock.json", () => {
  it("has exactly one copy of every @radix-ui package", () => {
    const lock = JSON.parse(readFileSync(`${import.meta.dirname}/../../package-lock.json`, "utf8")) as { packages: Record<string, { version?: string }> }
    const copies = new Map<string, string[]>()
    for (const [path, pkg] of Object.entries(lock.packages)) {
      const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length)
      if (path.includes("node_modules/") && name.startsWith("@radix-ui/")) copies.set(name, [...(copies.get(name) ?? []), `${path}@${pkg.version}`])
    }
    expect(copies.size).toBeGreaterThan(10)
    expect([...copies.values()].filter((c) => c.length > 1)).toEqual([])
  })
})
