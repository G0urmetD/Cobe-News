import { describe, expect, it } from "vitest"
import { catalogTexts, type CatalogMeta } from "@/lib/catalog-texts"

const meta: CatalogMeta = {
  catalog_version: "2026.10.29-1",
  categories: [
    { key: "firewall", icon: "brick-wall", label: { de: "Firewalls & VPN", en: "Firewalls & VPN" } },
    { key: "network", icon: "network", label: { de: "Switches, Router & WLAN", en: "Switches, routers & WLAN" } },
  ],
  texts: { hints: { nocpe: { de: "Keine CPE", en: "No CPE" } }, where: { veeam_br: { de: "Konsole", en: "Console" } } },
}

describe("catalogTexts", () => {
  it("picks the UI language", () => {
    const de = catalogTexts(meta, "de")
    expect(de.cat("network")).toBe("Switches, Router & WLAN")
    expect(de.hint("nocpe")).toBe("Keine CPE")
    expect(catalogTexts(meta, "en").where("veeam_br")).toBe("Console")
    expect(catalogTexts(meta, "en-GB").cat("network")).toBe("Switches, routers & WLAN")
    expect(de.categories.map((c) => c.key)).toEqual(["firewall", "network"])
    expect(de.icon("firewall")).toBe("brick-wall")
    expect(de.version).toBe("2026.10.29-1")
  })

  it("falls back while loading or for unknown keys", () => {
    const empty = catalogTexts(undefined, "de")
    expect(empty.cat("firewall")).toBe("firewall")
    expect(empty.hint("nocpe")).toBe("")
    expect(empty.version).toBeNull()
    expect(catalogTexts(meta, "de").hint(null)).toBe("")
    expect(catalogTexts(meta, "de").where("nope")).toBe("")
  })
})
