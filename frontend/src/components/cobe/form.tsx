import { useId, useState } from "react"
import { useTranslation } from "react-i18next"
import { Lock } from "lucide-react"
import { MoreText } from "@/components/cobe/common"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { FieldIdContext } from "@/components/ui/field-context"
import { cn } from "@/lib/utils"

/** A labelled toggle row – the standard replacement for checkboxes throughout the app. */
export function ToggleRow({
  label,
  description,
  defaultChecked = false,
  checked,
  onCheckedChange,
  disabled,
  className,
  children,
}: {
  label: React.ReactNode
  description?: React.ReactNode
  defaultChecked?: boolean
  checked?: boolean
  onCheckedChange?: (v: boolean) => void
  disabled?: boolean
  className?: string
  children?: React.ReactNode
}) {
  const id = useId()
  const [inner, setInner] = useState(defaultChecked)
  const value = checked ?? inner
  return (
    <div className={cn("flex flex-col gap-3 py-3.5", className)}>
      <div className="flex items-start justify-between gap-6">
        <div className="min-w-0 space-y-0.5">
          <Label htmlFor={id} className="text-sm font-medium">
            {label}
          </Label>
          {description && <p className="text-xs leading-relaxed text-muted-foreground">{description}</p>}
        </div>
        <Switch
          id={id}
          checked={value}
          disabled={disabled}
          onCheckedChange={(v) => {
            setInner(v)
            onCheckedChange?.(v)
          }}
          className="mt-0.5"
        />
      </div>
      {children && value && <div className="rounded-lg bg-muted/50 p-3">{children}</div>}
    </div>
  )
}

export function Field({
  label,
  hint,
  children,
  className,
  htmlFor,
}: {
  label: React.ReactNode
  hint?: React.ReactNode
  children: React.ReactNode
  className?: string
  htmlFor?: string
}) {
  // the label points at the control: its own id (htmlFor) or one given to the first Input/Select/Textarea inside
  const auto = useId()
  const id = htmlFor ?? auto
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <Label htmlFor={id} className="text-[13px] font-medium">
        {label}
      </Label>
      <FieldIdContext.Provider value={htmlFor ? undefined : auto}>{children}</FieldIdContext.Provider>
      {hint && (
        <p className="text-xs text-muted-foreground">
          <MoreText>{hint}</MoreText>
        </p>
      )}
    </div>
  )
}

/**
 * The main on/off switch of an integration – visually prominent, because everything below it stays locked
 * (see <LockedFields/>) until it is switched on.
 */
export function EnableCard({
  label,
  description,
  checked,
  onCheckedChange,
}: {
  label: React.ReactNode
  description?: React.ReactNode
  checked: boolean
  onCheckedChange: (v: boolean) => void
}) {
  const { t } = useTranslation()
  const id = useId()
  return (
    <div
      className={cn(
        "flex items-start justify-between gap-6 rounded-lg border p-3.5 transition-colors",
        checked ? "border-success/40 bg-success/5" : "border-primary/40 bg-primary/5",
      )}
    >
      <div className="min-w-0 space-y-1">
        <Label htmlFor={id} className="text-sm font-semibold">
          {label}
        </Label>
        {description && <p className="text-xs leading-relaxed text-muted-foreground">{description}</p>}
        {!checked && (
          <p className="flex items-center gap-1.5 text-xs font-medium text-primary">
            <Lock className="size-3" /> {t("form.enableFirst")}
          </p>
        )}
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} className="mt-0.5" />
    </div>
  )
}

/** Disables every input, select, toggle and button inside while `locked` (native <fieldset disabled>). */
export function LockedFields({ locked, className, children }: { locked: boolean; className?: string; children: React.ReactNode }) {
  return (
    <fieldset disabled={locked} className={cn("min-w-0 transition-opacity", locked && "[&_label]:opacity-60 [&_p]:opacity-60", className)}>
      {children}
    </fieldset>
  )
}
