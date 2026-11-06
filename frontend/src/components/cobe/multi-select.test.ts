import { describe, expect, it } from "vitest"

import { containsAll } from "./multi-select"

describe("containsAll", () => {
  it("finds what contains every typed word, in label or keywords", () => {
    expect(containsAll("VMware ESXi", "vmware")).toBe(1)
    expect(containsAll("VMware ESXi", "esxi vmw")).toBe(1)
    expect(containsAll("ESXi", "broadcom", ["Broadcom (VMware)"])).toBe(1)
  })

  it("has no fuzzy match: letters in order are not enough", () => {
    expect(containsAll("Apache ActiveMQ Classic", "vmware")).toBe(0)
    expect(containsAll("Alle Produkte von TeamViewer", "vmware")).toBe(0)
  })
})
