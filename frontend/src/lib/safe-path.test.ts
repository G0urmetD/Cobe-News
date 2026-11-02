import { readFileSync } from "node:fs"
import { describe, expect, it } from "vitest"
import { safePath } from "@/lib/safe-path"

const ORIGIN = "https://news.corp.example:8095"

/** public/sw.js's own safePath (the worker is not bundled): taken from the file and run with `self.location` set. */
function swSafePath(): (url: unknown) => string {
  const src = readFileSync(new URL("../../public/sw.js", import.meta.url), "utf8")
  const fn = src.slice(src.indexOf("function safePath"), src.indexOf("\n}\n", src.indexOf("function safePath")) + 2)
  return new Function("self", `${fn}; return safePath`)({ location: { origin: ORIGIN } }) as (url: unknown) => string
}

// security review 0.1.16 L10: "/\t/evil.example" passed the old check – URL parsing drops the tab: "//evil.example"
const BAD = ["/\t/evil.example", "/\n/evil.example", "//evil.example", "/\\evil.example", "/\\/evil.example", "/\u0000x", "https://evil.example/", "evil", "", 42, null]
const GOOD = ["/", "/?story=5b0c6f0e-1111-4222-8333-444455556666", "/vendor?view=all#x"]

describe("safePath", () => {
  it.each(BAD.map((x) => [x]))("refuses %j", (url) => {
    expect(safePath(url, ORIGIN)).toBeNull()
    expect(swSafePath()(url)).toBe("/")
  })
  it.each(GOOD.map((x) => [x]))("keeps %j", (url) => {
    expect(safePath(url, ORIGIN)).toBe(url)
    expect(swSafePath()(url)).toBe(url)
  })
})
