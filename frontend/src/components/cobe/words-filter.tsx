import { ChevronDown } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { ChipInput } from "@/components/cobe/chip-input"
import { Field } from "@/components/cobe/form"
import { cn } from "@/lib/utils"

/**
 * A filter of own words in the filter bar – one compact button ("Ohne …" with the number chosen) that opens the chip
 * field (Enter or a comma adds a word, checked as the server checks it). The words chosen show as chips in the row
 * of active filters, not here.
 */
export function WordsFilter({
  label,
  title,
  hint,
  placeholder,
  value,
  onChange,
  className,
}: {
  label: string
  /** the field's label in the popover */
  title: string
  hint: string
  placeholder: string
  value: string[]
  onChange: (v: string[]) => void
  className?: string
}) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" className={cn("border-dashed", value.length && "border-solid", className)}>
          {label}
          {value.length > 0 && <span className="ml-0.5 rounded-md bg-primary/10 px-1.5 text-xs font-semibold text-primary tabular">{value.length}</span>}
          <ChevronDown className="text-muted-foreground" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80 p-3" align="start">
        <Field label={title} hint={hint}>
          <ChipInput value={value} onChange={onChange} placeholder={placeholder} />
        </Field>
      </PopoverContent>
    </Popover>
  )
}
