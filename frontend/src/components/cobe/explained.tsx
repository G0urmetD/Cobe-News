import { useLayoutEffect } from "react"
import { Info } from "lucide-react"
import { useFieldLabelText } from "@/components/ui/field-context"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

/** A word with its explanation on hover – for jargon (as in pages/settings-tls.tsx). */
export function Explained({ label, text }: { label: React.ReactNode; text: string }) {
  // in a <Field/>'s label: the word is the label's text (a MultiSelect inside is named by it, not by the explanation)
  const field = useFieldLabelText()
  useLayoutEffect(() => {
    if (!field) return
    field.use(true)
    return () => field.use(false)
  }, [field])
  return (
    <span className="inline-flex items-center gap-1">
      <span id={field?.id}>{label}</span>
      <Tooltip>
        <TooltipTrigger asChild>
          <Info className="size-3.5 cursor-help text-muted-foreground" tabIndex={0} aria-label={text} />
        </TooltipTrigger>
        <TooltipContent className="max-w-xs leading-relaxed">{text}</TooltipContent>
      </Tooltip>
    </span>
  )
}
