import { useTranslation } from "react-i18next"
import { MultiSelect, type Option, type OptionGroup } from "@/components/cobe/multi-select"
import { type CatalogVendor, OURS, type RuleSystem, SYSTEMS_MAX, systemOf, systemRef, systemValue, vendorOf } from "@/lib/rule-filters"

/**
 * "Systeme": the catalogue by vendor – first "Alle Produkte von <Hersteller>" (also those added later), then its
 * products; searched by product and vendor (any of its spellings). A system no longer among the options stays as a chip
 * until removed (`goneLabel`: what it is called then – "Nicht mehr im Katalog"). At the top "Unsere Produkte (aus Vendor
 * News)": the products followed when a story is judged, also those followed later (`ours={false}`: not offered – the
 * Vendor News of a person's own products are of followed products anyway). One picker for the channel rules, the News
 * page's filter (`variant="filter"`), the desktop notifications, "Security-Meldungen" and "Hersteller-News meiner
 * Produkte".
 */
export function SystemsPicker({
  value,
  onChange,
  vendors,
  variant = "field",
  label,
  goneLabel,
  goneName,
  ours = true,
  className,
}: {
  value: RuleSystem[]
  onChange: (v: RuleSystem[]) => void
  /** undefined while the catalogue loads */
  vendors: CatalogVendor[] | undefined
  variant?: "field" | "filter"
  /** the trigger's text (default: "Alle Systeme" / "Lädt …") */
  label?: string
  goneLabel?: string
  goneName?: (name: string) => string
  /** offer "Unsere Produkte (aus Vendor News)" (default) */
  ours?: boolean
  className?: string
}) {
  const { t } = useTranslation()
  const groups: OptionGroup[] = []
  const options: Option[] = []
  for (const v of vendors ?? []) {
    groups.push({ key: v.id, label: v.name })
    options.push({
      value: systemValue({ vendor: v.name }),
      label: t("notify.systemsAllOf", { vendor: v.name }),
      chip: t("notify.systemsVendorChip", { vendor: v.name }),
      group: v.id,
      keywords: v.names,
    })
    for (const p of v.products) options.push({ value: systemValue({ product: p.key }), label: p.label, group: v.id, keywords: v.names })
  }
  // "Unsere Produkte": its own choice, not a vendor's product – also while the catalogue loads (it needs none); shown
  // where it is chosen already, also where it is not offered
  const withOurs = ours || value.some((s) => "ours" in s)
  if (withOurs)
    options.unshift({
      value: systemValue(OURS),
      label: t("notify.systemsOurs"),
      chip: t("notify.systemsOursChip"),
      description: t("notify.systemsOursHint"),
      group: "ours",
      keywords: [t("notify.systemsOursChip"), "Vendor News"],
    })
  // a vendor chosen under another of its spellings ("VMware" for "Broadcom (VMware)") is its one option; one no longer
  // among the options is shown (and removable) as it is
  const shown = [
    ...new Set(
      value.map((s) => {
        const v = "vendor" in s && vendors ? vendorOf(vendors, s.vendor) : undefined
        return v ? systemValue({ vendor: v.name }) : systemValue(s)
      }),
    ),
  ]
  if (vendors) {
    for (const c of shown) {
      if (options.some((o) => o.value === c)) continue
      const s = systemOf(c)
      if (!s) continue
      const name = systemRef(s)
      options.push({ value: c, label: goneName ? goneName(name) : t("notify.systemGoneName", { name }), group: "gone" })
    }
    if (options.some((o) => o.group === "gone")) groups.unshift({ key: "gone", label: goneLabel ?? t("notify.systemGone") })
  }
  if (withOurs) groups.unshift({ key: "ours", label: t("notify.systemsOursGroup") })
  return (
    <MultiSelect
      variant={variant}
      label={label ?? (vendors ? t("notify.allSystems") : t("news.loading"))}
      options={options}
      groups={groups}
      value={shown}
      onChange={(x) =>
        onChange(
          x
            .slice(0, SYSTEMS_MAX)
            .map(systemOf)
            .filter((y): y is NonNullable<typeof y> => !!y),
        )
      }
      className={className}
      contentClassName="w-80"
    />
  )
}
