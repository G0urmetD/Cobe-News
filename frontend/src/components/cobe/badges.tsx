import { cn } from "@/lib/utils"

// Soft, token-driven pill used by all semantic badges.
export function Pill({ color, children, className, dot = false, title }: { color: string; children: React.ReactNode; className?: string; dot?: boolean; title?: string }) {
  return (
    <span
      title={title}
      className={cn("inline-flex h-5 shrink-0 items-center gap-1.5 rounded-full border px-2 text-xs font-medium whitespace-nowrap [&>svg]:size-3", className)}
      style={{
        color: `var(${color})`,
        backgroundColor: `color-mix(in oklch, var(${color}) 11%, transparent)`,
        borderColor: `color-mix(in oklch, var(${color}) 24%, transparent)`,
      }}
    >
      {dot && <span className="size-1.5 rounded-full" style={{ backgroundColor: `var(${color})` }} />}
      {children}
    </span>
  )
}
