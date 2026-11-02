import { Info } from "lucide-react"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

/** A word with its explanation on hover – for jargon (as in pages/settings-tls.tsx). */
export function Explained({ label, text }: { label: React.ReactNode; text: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      {label}
      <Tooltip>
        <TooltipTrigger asChild>
          <Info className="size-3.5 cursor-help text-muted-foreground" tabIndex={0} aria-label={text} />
        </TooltipTrigger>
        <TooltipContent className="max-w-xs leading-relaxed">{text}</TooltipContent>
      </Tooltip>
    </span>
  )
}
