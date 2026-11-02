import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Check, Copy } from "lucide-react"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { initials } from "@/lib/format"
import { copyWithToast } from "@/lib/clipboard"
import { cn } from "@/lib/utils"

/** A value in monospace with copy on hover (CVE ids in the drawer). */
export function Mono({ value, className }: { value: string; className?: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const onCopy = (e: React.MouseEvent) => {
    e.stopPropagation()
    void copyWithToast(value).then((ok) => {
      if (!ok) return
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    })
  }
  return (
    <span className={cn("group/mono inline-flex min-w-0 items-center gap-1 font-mono text-[12.5px]", className)}>
      <span className="truncate" title={value}>
        {value}
      </span>
      <button
        type="button"
        onClick={onCopy}
        aria-label={t("common.copy")}
        title={t("common.copy")}
        className="shrink-0 rounded p-0.5 text-muted-foreground opacity-40 transition-opacity group-hover/mono:opacity-100 hover:bg-muted hover:text-foreground focus-visible:opacity-100"
      >
        {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
      </button>
    </span>
  )
}

export function PageHeader({
  title,
  description,
  actions,
  children,
}: {
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  children?: React.ReactNode
}) {
  return (
    <div className="flex flex-col gap-4 pb-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1 basis-80 space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          {description && <p className="text-sm text-muted-foreground">{description}</p>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </div>
  )
}

export function EmptyState({ icon: Icon, title, text, action }: { icon: React.ElementType; title: string; text?: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed px-6 py-14 text-center">
      <div className="flex size-11 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <Icon className="size-5" />
      </div>
      <div className="space-y-1">
        <p className="font-medium">{title}</p>
        {text && (
          <p className="max-w-sm text-sm text-muted-foreground">
            <MoreText>{text}</MoreText>
          </p>
        )}
      </div>
      {action}
    </div>
  )
}

export function Logo({ className, withText = true }: { className?: string; withText?: boolean }) {
  return (
    <span className={cn("inline-flex min-w-0 items-center gap-2", className)}>
      {/* the Cobe News mark: the logo's two cards without the lettering, which would be unreadable at this size */}
      <img src="/favicon.svg" alt="" aria-hidden className="size-8 shrink-0" />
      {/* one line, never wrapped; in the collapsed (icon-only) sidebar only the mark – the name would spill out of the rail */}
      {withText && <span className="truncate text-[15px] font-semibold tracking-tight whitespace-nowrap group-data-[collapsible=icon]:hidden">Cobe News</span>}
    </span>
  )
}

const LONG = 220
const ABBREV = /(\b(z|B|d|h|u|a|o|i|v|bzw|ggf|ca|evtl|inkl|usw|vgl|Nr|Abs|Art|e\.g|i\.e|etc|vs)\.)$/

/**
 * A long explanation shows its first sentence and "more" – under stress the important part is read, the details stay
 * one click away. Short texts and non-text (links, formatting) are shown as they are.
 */
export function MoreText({ children, className }: { children: React.ReactNode; className?: string }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  if (typeof children !== "string" || children.length <= LONG) return <>{children}</>
  // the first sentence – a full stop that ends one: not after an abbreviation ("z. B.", "bzw.", "e.g."), not before a
  // lowercase word; otherwise the first ~160 characters at a word boundary
  const ends = [...children.matchAll(/[.!?](?=\s+\S)/g)].map((x) => x.index! + 1)
  const cut = ends.find((i) => i >= 40 && i <= 220 && !ABBREV.test(children.slice(Math.max(0, i - 6), i)) && !/^\s+[a-zäöü]/.test(children.slice(i)))
  const head = cut ? children.slice(0, cut) : `${children.slice(0, 160).replace(/\s+\S*$/, "")} …`
  if (head.length >= children.length - 20) return <>{children}</>
  return (
    <span className={className}>
      {open ? children : head}{" "}
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} className="font-medium whitespace-nowrap text-primary hover:underline">
        {open ? t("common.less") : t("common.moreInfo")}
      </button>
    </span>
  )
}

/** A card with a title row (settings and detail pages); the content brings its own padding. */
export function Section({
  title,
  description,
  actions,
  children,
  className,
}: {
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <section className={cn("flex flex-col rounded-xl border bg-card", className)}>
      <header className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3.5">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold">{title}</h2>
          {description && (
            <p className="mt-0.5 text-xs text-muted-foreground">
              <MoreText>{description}</MoreText>
            </p>
          )}
        </div>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </header>
      <div className="min-h-0">{children}</div>
    </section>
  )
}

const avatarHues = [264, 190, 25, 150, 300, 60, 220, 330]

function hueFor(id: string) {
  let h = 0
  for (const ch of id) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  return avatarHues[h % avatarHues.length]
}

/** Avatar with the initials (as in the user menu). */
export function PersonAvatar({ user, size = "md", className }: { user: { id: string; display_name: string } | null | undefined; size?: "sm" | "md" | "lg"; className?: string }) {
  const name = user?.display_name ?? "?"
  const hue = user?.id ? hueFor(user.id) : 260
  const sz = { sm: "size-6 text-[10px]", md: "size-7 text-[11px]", lg: "size-9 text-sm" }[size]
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={cn("inline-flex shrink-0 items-center justify-center rounded-full font-semibold ring-2 ring-background select-none", sz, className)}
          style={{ backgroundColor: `oklch(0.9 0.05 ${hue})`, color: `oklch(0.35 0.12 ${hue})` }}
        >
          {initials(name)}
        </span>
      </TooltipTrigger>
      <TooltipContent>{name}</TooltipContent>
    </Tooltip>
  )
}
