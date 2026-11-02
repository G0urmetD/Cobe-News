import { Link } from "react-router"
import { cn } from "@/lib/utils"

export type SubTab<K extends string> = {
  key: K
  icon: React.ElementType
  label: string
  count?: number
  /** needs attention (an overdue duty, an approval waiting) – a dot */
  alert?: boolean
}

/**
 * The second level inside a case tab (IOCs | entities, tasks | playbooks …): each part gets the full width instead of
 * long lists stacked on top of each other. `to` builds the address of a part – a path or `?view=`.
 */
export function SubTabs<K extends string>({ parts, active, to, label }: { parts: SubTab<K>[]; active: K; to: (key: K) => string; label: string }) {
  return (
    <nav className="inline-flex max-w-full flex-wrap rounded-lg border bg-muted/40 p-0.5" aria-label={label}>
      {parts.map((p) => (
        <Link
          key={p.key}
          to={to(p.key)}
          aria-current={active === p.key ? "page" : undefined}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium whitespace-nowrap transition-colors",
            active === p.key ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
          )}
        >
          <p.icon className="size-4" /> {p.label}
          {!!p.count && <span className="rounded-full bg-muted px-1.5 text-[11px] text-muted-foreground tabular">{p.count}</span>}
          {p.alert && <span className="size-1.5 rounded-full bg-warning" />}
        </Link>
      ))}
    </nav>
  )
}
