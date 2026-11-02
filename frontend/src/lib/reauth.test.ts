import { describe, expect, it } from "vitest"
import { ApiError, csrfToken } from "@/lib/api"
import { closeReauth, coversPrompt, entraReauthUrl, reauthStore, withReauth } from "@/lib/reauth"

const required = (via = "password", totp = true) => new ApiError(403, { code: "reauth_required", via, totp })

describe("withReauth", () => {
  it("asks once the server wants a fresh confirmation, then repeats the action", async () => {
    let calls = 0
    const run = withReauth(async () => {
      calls += 1
      if (calls === 1) throw required()
      return "saved"
    })
    await new Promise((r) => setTimeout(r, 0))
    expect(reauthStore.get()).toMatchObject({ via: "password", totp: true })
    closeReauth(true)
    await expect(run).resolves.toBe("saved")
    expect(calls).toBe(2)
    expect(reauthStore.get()).toBeNull()
  })

  it("cancelled: nothing is repeated, the caller hears reauth_cancelled", async () => {
    let calls = 0
    const run = withReauth(async () => {
      calls += 1
      throw required("entra", false)
    })
    await new Promise((r) => setTimeout(r, 0))
    expect(reauthStore.get()?.via).toBe("entra")
    closeReauth(false)
    await expect(run).rejects.toMatchObject({ code: "reauth_cancelled" })
    expect(calls).toBe(1)
  })

  it("other errors pass through without asking", async () => {
    await expect(withReauth(async () => Promise.reject(new ApiError(409, { code: "stale" })))).rejects.toMatchObject({ code: "stale" })
    expect(reauthStore.get()).toBeNull()
  })

  it("every question is a fresh one (its own id – a new dialog, nothing typed carried over)", async () => {
    const first = withReauth(async () => Promise.reject(required())).catch((e: unknown) => e)
    await new Promise((r) => setTimeout(r, 0))
    const a = reauthStore.get()?.id
    const second = withReauth(async () => Promise.reject(required()))
    await new Promise((r) => setTimeout(r, 0))
    const b = reauthStore.get()?.id
    expect(a).toBeTypeOf("number")
    expect(b).not.toBe(a)
    expect(await first).toMatchObject({ code: "reauth_cancelled" }) // the newer question replaced it
    closeReauth(false)
    await expect(second).rejects.toMatchObject({ code: "reauth_cancelled" })
  })

  it("Entra: back to this page after Microsoft's sign-in", () => {
    expect(entraReauthUrl("/settings?tab=users")).toBe("/api/auth/oidc/start?reauth=1&next=%2Fsettings%3Ftab%3Dusers")
  })
})

describe("csrfToken", () => {
  it("prefers the __Host- cookie over an unprefixed one an older version left", () => {
    expect(csrfToken("cobe_news_csrf=old; __Host-cobe_news_csrf=new")).toBe("new")
    expect(csrfToken("__Host-cobe_news_csrf=new; cobe_news_csrf=old")).toBe("new")
    expect(csrfToken("other=1; cobe_news_csrf=plain")).toBe("plain")
    expect(csrfToken("x__Host-cobe_news_csrf=evil")).toBe("")
  })
})

// Stand-ins for nodes on <body>: where they are relative to the question, what they are.
const FOLLOWING = 4
const PRECEDING = 2
function node(opts: { after: boolean; role?: string; inner?: string; text?: boolean }) {
  return {
    nodeType: opts.text ? 3 : 1,
    pos: opts.after ? FOLLOWING : PRECEDING,
    matches: (sel: string) => !!opts.role && sel.includes(`[role=${opts.role}]`),
    querySelector: (sel: string) => (opts.inner && sel.includes(`[role=${opts.inner}]`) ? {} : null),
  }
}
const prompt = { compareDocumentPosition: (n: { pos: number }) => n.pos } as unknown as Element
const covers = (n: ReturnType<typeof node>) => coversPrompt(prompt, n as unknown as Node)

describe("the re-confirmation stays the topmost layer", () => {
  it("a drawer or dialog mounted after it covers it (all Radix layers sit at z-50, the later one wins)", () => {
    expect(covers(node({ after: true, role: "dialog" }))).toBe(true) // sheet-content, dialog-content
    expect(covers(node({ after: true, role: "alertdialog" }))).toBe(true)
    expect(covers(node({ after: true, inner: "dialog" }))).toBe(true) // a wrapper around one
  })

  it("not: layers from before, its own node, overlays, focus guards, tooltips, text", () => {
    expect(covers(node({ after: false, role: "dialog" }))).toBe(false)
    expect(coversPrompt(prompt, prompt as unknown as Node)).toBe(false)
    expect(covers(node({ after: true }))).toBe(false) // an overlay or the focus-guard <span> – they come with the drawer
    expect(covers(node({ after: true, role: "tooltip" }))).toBe(false)
    expect(covers(node({ after: true, text: true }))).toBe(false)
  })
})
