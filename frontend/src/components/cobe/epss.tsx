import { useTranslation } from "react-i18next"
import { Pill } from "@/components/cobe/badges"
import { Term } from "@/components/cobe/glossary"
import { fmtDay } from "@/lib/format"
import type { Epss, Ssvc } from "@/lib/vendor-api"
import { epssPercent, epssTone } from "@/lib/epss"

/** The EPSS chip: the probability, its percentile and date on hover. */
export function EpssPill({ e }: { e: Epss }) {
  const { t, i18n } = useTranslation()
  return (
    <span
      className="rounded px-1.5 py-0.5 font-mono text-[11px]"
      style={{ color: `var(${epssTone(e.score)})`, backgroundColor: `color-mix(in oklch, var(${epssTone(e.score)}) 11%, transparent)` }}
      title={t("vendor.epssTitle", {
        score: epssPercent(e.score, i18n.language),
        cve: e.cve,
        pct: e.percentile !== null ? (e.percentile * 100).toLocaleString(i18n.language, { maximumFractionDigits: 1 }) : "–",
        date: e.date ? fmtDay(e.date) : "–",
      })}
    >
      <Term k="epss">EPSS</Term> {t("vendor.epssPill", { score: epssPercent(e.score, i18n.language) })}
    </span>
  )
}

/** CISA's SSVC "exploitation" (and "automatable"), where it says more than nothing. */
export function SsvcPill({ s }: { s: Ssvc }) {
  const { t } = useTranslation()
  if (!["active", "poc"].includes(s.exploitation)) return null
  return (
    <Pill color={s.exploitation === "active" ? "--sev-critical" : "--sev-high"}>
      <Term k="ssvc">{t(`vendor.ssvc.${s.exploitation}`)}</Term>
      {s.automatable === "yes" ? ` · ${t("vendor.ssvc.automatable")}` : ""}
    </Pill>
  )
}
