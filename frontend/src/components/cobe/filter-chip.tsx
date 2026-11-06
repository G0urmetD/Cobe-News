import { X } from "lucide-react"

/** One active filter as a chip ("Zeitraum: heute, seit 00:00 ×") – the label muted, the value, a button removing it. */
export function FilterChip({ label, value, onRemove, removeLabel }: { label: string; value: string; onRemove: () => void; removeLabel: string }) {
  return (
    <span className="inline-flex max-w-full items-center gap-1 rounded-full border bg-background py-0.5 pr-1 pl-2.5 text-xs">
      <span className="shrink-0 text-muted-foreground">{label}:</span>
      <bdi className="truncate font-medium">{value}</bdi>
      <button
        type="button"
        className="ml-0.5 shrink-0 rounded-full p-0.5 text-muted-foreground outline-none hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
        aria-label={removeLabel}
        onClick={onRemove}
      >
        <X className="size-3.5" />
      </button>
    </span>
  )
}
