import { describe, expect, it, vi } from "vitest"
import { focusContentOnOpen, focusFieldOnOpen, restoreFocus } from "@/lib/focus"

// Radix fires its "focus on open" event at the drawer element; without our handler it would focus the first
// focusable element inside – the CPE term of the Vendor News drawer, whose tooltip then opened by itself.
function openEvent() {
  const target = { focus: vi.fn() }
  let prevented = false
  const e = {
    target,
    get defaultPrevented() {
      return prevented
    },
    preventDefault: () => {
      prevented = true
    },
  } as unknown as Event
  return { e, target }
}

describe("focus when a drawer opens", () => {
  it("goes to the drawer itself, not to its first element", () => {
    const { e, target } = openEvent()
    focusContentOnOpen()(e)
    expect(e.defaultPrevented).toBe(true)
    expect(target.focus).toHaveBeenCalledWith({ preventScroll: true })
  })

  it("leaves it to a page that decides itself", () => {
    const { e, target } = openEvent()
    const own = vi.fn((ev: Event) => ev.preventDefault())
    focusContentOnOpen(own)(e)
    expect(own).toHaveBeenCalledOnce()
    expect(target.focus).not.toHaveBeenCalled()
  })
})

// a stand-in element: connected or not, a tooltip trigger or not, with a parent to climb to
function el(opts: { tag?: string; connected?: boolean; tooltip?: boolean; parent?: unknown } = {}) {
  return {
    tagName: opts.tag ?? "BUTTON",
    isConnected: opts.connected ?? true,
    focus: vi.fn(),
    matches: (sel: string) => sel.includes("tooltip-trigger") && !!opts.tooltip,
    parentElement: opts.parent ? { closest: () => opts.parent } : null,
  } as unknown as HTMLElement & { focus: ReturnType<typeof vi.fn> }
}

describe("focus when a drawer closes", () => {
  it("goes back to what opened it", () => {
    const card = el()
    expect(restoreFocus(card)).toBe(true)
    expect(card.focus).toHaveBeenCalledWith({ preventScroll: true })
  })

  it("does nothing when the opener is gone or was the page itself", () => {
    expect(restoreFocus(el({ connected: false }))).toBe(false)
    expect(restoreFocus(el({ tag: "BODY" }))).toBe(false)
    expect(restoreFocus(null)).toBe(false)
  })

  it("never focuses a tooltip trigger – its tooltip would open by itself – but its focusable parent", () => {
    const row = el()
    const trigger = el({ tooltip: true, parent: row })
    expect(restoreFocus(trigger)).toBe(true)
    expect(trigger.focus).not.toHaveBeenCalled()
    expect(row.focus).toHaveBeenCalled()
    expect(restoreFocus(el({ tooltip: true }))).toBe(false)
  })
})

describe("focus when the re-confirmation opens", () => {
  // the dialog with its fields (stand-ins: a value and focus()); Radix fires the event at the dialog element
  function dialogWith(values: string[]) {
    const fields = values.map((value, i) => ({ id: `f${i}`, value, focus: vi.fn() }))
    let prevented = false
    const e = {
      target: { querySelectorAll: () => fields },
      get defaultPrevented() {
        return prevented
      },
      preventDefault: () => {
        prevented = true
      },
    } as unknown as Event
    return { e, fields }
  }

  it("goes into the first empty field – through Radix' event, after the drawer's focus trap below is paused", () => {
    const { e, fields } = dialogWith(["", ""])
    focusFieldOnOpen(e)
    expect(e.defaultPrevented).toBe(true)
    expect(fields[0].focus).toHaveBeenCalledWith({ preventScroll: true })
    expect(fields[1].focus).not.toHaveBeenCalled()
  })

  it("the field still empty (the code after the password), else the last one", () => {
    const half = dialogWith(["secret", ""])
    focusFieldOnOpen(half.e)
    expect(half.fields[1].focus).toHaveBeenCalled()
    const full = dialogWith(["secret", "123456"])
    focusFieldOnOpen(full.e)
    expect(full.fields[1].focus).toHaveBeenCalled()
    expect(full.fields[0].focus).not.toHaveBeenCalled()
  })

  it("drawn anew: back into the field that had the focus, even when it is not empty", () => {
    const { e, fields } = dialogWith(["sec", ""])
    focusFieldOnOpen(e, "f0")
    expect(fields[0].focus).toHaveBeenCalled()
    expect(fields[1].focus).not.toHaveBeenCalled()
  })

  it("no field (Entra: a button) – leaves it to the dialog's own focus", () => {
    const { e } = dialogWith([])
    focusFieldOnOpen(e)
    expect(e.defaultPrevented).toBe(false)
  })
})
