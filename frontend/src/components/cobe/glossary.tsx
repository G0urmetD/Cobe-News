import { useTranslation } from "react-i18next"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

/** Security terms in plain words (from Cobe's glossary) – the ones Cobe News uses (and the Teams "Workflows-Webhook"): glossary.<key> / glossary.<key>Text. */
export const TERMS = [
  "kev",
  "euvd",
  "psirt",
  "cpe",
  "cna",
  "cvss",
  "eol",
  "hotfix",
  "lts",
  "epss",
  "csaf",
  "tlp",
  "ssvc",
  "osv",
  "webhook",
  "revision",
  "ical",
  "bearer",
  "scope",
  "prometheus",
  "openapi",
  "passkey",
  "webauthn",
] as const
export type TermKey = (typeof TERMS)[number]

/** A term with its explanation on hover or focus – dotted underline, like an abbreviation. */
export function Term({ k, children }: { k: TermKey; children: React.ReactNode }) {
  const { t } = useTranslation()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className="cursor-help underline decoration-muted-foreground/60 decoration-dotted underline-offset-4 outline-none focus-visible:rounded-sm focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs text-left leading-relaxed">
        {/* one block: the tooltip lays out its children side by side */}
        <span className="block">
          <span className="font-semibold">{t(`glossary.${k}`)}</span> – {t(`glossary.${k}Text`)}
        </span>
      </TooltipContent>
    </Tooltip>
  )
}
