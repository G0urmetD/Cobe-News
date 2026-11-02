import { useTranslation } from "react-i18next"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill } from "@/components/cobe/badges"
import { offKeys } from "@/lib/admin-api"

/** "Deaktiviert" and why – the Teams reasons ("Kein Team mehr", "Teams ausgeschaltet") explain themselves on hover. */
export function OffPill({ reason }: { reason: string | null }) {
  const { t } = useTranslation()
  const [label, hint] = offKeys(reason)
  const pill = <Pill color="--muted-foreground">{t(label)}</Pill>
  if (!hint) return pill
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex">
          {pill}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">{t(hint)}</TooltipContent>
    </Tooltip>
  )
}
