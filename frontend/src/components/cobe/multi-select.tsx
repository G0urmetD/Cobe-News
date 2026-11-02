import { useRef } from "react"
import { useTranslation } from "react-i18next"
import { ChevronDown, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { useFieldId } from "@/components/ui/field-context"
import { cn } from "@/lib/utils"

export interface Option {
  value: string
  label: string
  /** short text at the right (a count) */
  hint?: string
  /** a second line under the label (what the option means) */
  description?: string
  icon?: React.ReactNode
  /** options with a group are listed under its heading (`groups`), in the order the groups first appear */
  group?: string
}

/** The headings of grouped options; `all`: the label of a row choosing every option of the group at once. */
export interface OptionGroup {
  key: string
  label: string
  all?: string
}

/** Filter/multi-select dropdown with search: "filter" for the news filters, "field" (chips) in forms. */
export function MultiSelect({
  label,
  options,
  value,
  onChange,
  searchable = true,
  className,
  variant = "filter",
  groups,
  contentClassName,
}: {
  label: string
  options: Option[]
  value: string[]
  onChange: (v: string[]) => void
  searchable?: boolean
  className?: string
  variant?: "filter" | "field"
  groups?: OptionGroup[]
  /** the dropdown's own classes (a wider one for options with a description) */
  contentClassName?: string
}) {
  const { t } = useTranslation()
  const fieldId = useFieldId() // inside a <Field/>: its label names this button
  const toggle = (v: string) => onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v])
  const selected = options.filter((o) => value.includes(o.value))
  // without a search field nothing in the list could take the focus: the list itself does (arrow keys move, Enter or
  // Space choose – the highlighted row shows where), otherwise the keyboard ended on the popover and chose nothing
  const listRef = useRef<HTMLDivElement>(null)
  const listKeys = (e: React.KeyboardEvent) => {
    if (e.key !== " ") return
    e.preventDefault()
    listRef.current?.querySelector<HTMLElement>("[cmdk-item][data-selected=true]")?.click()
  }
  return (
    <Popover>
      <PopoverTrigger asChild>
        {variant === "filter" ? (
          <Button variant="outline" className={cn("border-dashed", value.length && "border-solid", className)}>
            {label}
            {value.length > 0 && <span className="ml-0.5 rounded-md bg-primary/10 px-1.5 text-xs font-semibold text-primary tabular">{value.length}</span>}
            <ChevronDown className="text-muted-foreground" />
          </Button>
        ) : (
          <button
            type="button"
            id={fieldId}
            className={cn(
              "flex min-h-9 w-full flex-wrap items-center gap-1 rounded-lg border border-input bg-transparent px-2 py-1 text-left text-sm transition-colors outline-none hover:bg-muted/40 focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30",
              className,
            )}
          >
            {selected.length === 0 && <span className="px-1 text-muted-foreground">{label}</span>}
            {selected.map((o) => (
              <span key={o.value} className="inline-flex items-center gap-1 rounded-md bg-secondary px-1.5 py-0.5 text-xs font-medium">
                {o.label}
                <span
                  role="button"
                  tabIndex={-1}
                  onClick={(e) => {
                    e.stopPropagation()
                    toggle(o.value)
                  }}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <X className="size-3" />
                </span>
              </span>
            ))}
            <ChevronDown className="ml-auto size-4 text-muted-foreground" />
          </button>
        )}
      </PopoverTrigger>
      <PopoverContent
        className={cn("w-64 p-0", contentClassName)}
        align="start"
        onOpenAutoFocus={
          searchable
            ? undefined
            : (e) => {
                e.preventDefault()
                listRef.current?.focus()
              }
        }
      >
        <Command ref={listRef} {...(searchable ? {} : { tabIndex: -1, "aria-label": label, onKeyDown: listKeys, className: "outline-none" })}>
          {searchable && <CommandInput placeholder={t("common.search")} />}
          <CommandList className="scroll-shadow max-h-[min(32rem,max(9rem,calc(var(--radix-popover-content-available-height)_-_6rem)))] [scrollbar-width:thin]!">
            <CommandEmpty>{t("common.noResults")}</CommandEmpty>
            {(groups?.length ? groups.filter((g) => options.some((o) => o.group === g.key)) : [null]).map((g) => {
              const opts = g ? options.filter((o) => o.group === g.key) : options
              const all = opts.length > 1 && opts.every((o) => value.includes(o.value))
              return (
                <CommandGroup key={g?.key ?? ""} heading={g?.label}>
                  {g?.all && opts.length > 1 && (
                    <CommandItem
                      value={`${g.label} ${g.all}`}
                      onSelect={() => onChange(all ? value.filter((v) => !opts.some((o) => o.value === v)) : [...new Set([...value, ...opts.map((o) => o.value)])])}
                      data-checked={all}
                      className="gap-2 text-muted-foreground"
                    >
                      <span className={cn("flex-1 truncate", all && "font-medium text-foreground")}>{g.all}</span>
                    </CommandItem>
                  )}
                  {opts.map((o) => {
                    const active = value.includes(o.value)
                    return (
                      <CommandItem key={o.value} value={o.label} onSelect={() => toggle(o.value)} data-checked={active} className="gap-2">
                        {o.icon}
                        <span className="flex min-w-0 flex-1 flex-col">
                          <span className={cn("truncate", active && "font-medium")}>{o.label}</span>
                          {o.description && <span className="text-xs leading-snug whitespace-normal text-muted-foreground">{o.description}</span>}
                        </span>
                        {o.hint && <span className="self-start text-xs text-muted-foreground tabular-nums">{o.hint}</span>}
                      </CommandItem>
                    )
                  })}
                </CommandGroup>
              )
            })}
          </CommandList>
          {value.length > 0 && (
            <div className="border-t p-1">
              <Button variant="ghost" size="sm" className="w-full" onClick={() => onChange([])}>
                {t("common.clearSelection")}
              </Button>
            </div>
          )}
        </Command>
      </PopoverContent>
    </Popover>
  )
}
