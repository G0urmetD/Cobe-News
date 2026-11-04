import { Term } from "@/components/cobe/glossary"
import { cn } from "@/lib/utils"

// Soft, token-driven pill used by all semantic badges. `fg`: a darker text tone where the colour's own is too light on
// its tint (--sev-high-fg, --success-fg – AA in light mode).
export function Pill({
  color,
  fg,
  children,
  className,
  dot = false,
  title,
}: {
  color: string
  fg?: string
  children: React.ReactNode
  className?: string
  dot?: boolean
  title?: string
}) {
  return (
    <span
      title={title}
      className={cn("inline-flex h-5 shrink-0 items-center gap-1.5 rounded-full border px-2 text-xs font-medium whitespace-nowrap [&>svg]:size-3", className)}
      style={{
        color: `var(${fg ?? color})`,
        backgroundColor: `color-mix(in oklch, var(${color}) 11%, transparent)`,
        borderColor: `color-mix(in oklch, var(${color}) 24%, transparent)`,
      }}
    >
      {dot && <span className="size-1.5 rounded-full" style={{ backgroundColor: `var(${color})` }} />}
      {children}
    </span>
  )
}

/** A finding from a CSAF provider's TLP:GREEN document (an admin allowed it): share within the organisation /
 *  community only – the badge says it, the glossary's tooltip explains it (hover, focus – a tap focuses it on touch).
 *  One component for the finding and the overview's line (`compact`, beside the line's button, never inside it). */
export function TlpPill({ compact = false }: { compact?: boolean }) {
  const pill = compact ? (
    <span className="rounded border border-success/40 px-1 font-mono text-[10px] font-semibold text-success-fg">TLP:GREEN</span>
  ) : (
    <Pill color="--success" fg="--success-fg">
      TLP:GREEN
    </Pill>
  )
  return (
    <Term k="tlp" className="shrink-0 no-underline">
      {pill}
    </Term>
  )
}
