import { createContext, useContext, useState } from "react"
import { useTranslation } from "react-i18next"
import { Loader2, RefreshCw, Settings2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Field } from "@/components/cobe/form"
import { Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Pending } from "@/components/cobe/query-state"
import { useDirty } from "@/lib/unsaved"

/**
 * Save button of a settings form. With `dirty`: says "unsaved changes", is only active with changes, and leaving the
 * page with changes asks first (lib/unsaved).
 */
export function SaveBar({ onSave, busy, disabled, dirty }: { onSave: () => void; busy?: boolean; disabled?: boolean; dirty?: boolean }) {
  const { t } = useTranslation()
  useDirty(!!dirty && !busy)
  return (
    <div className="flex items-center justify-end gap-3">
      {dirty && (
        <span className="inline-flex items-center gap-1.5 text-xs text-warning" role="status">
          <span className="size-1.5 rounded-full bg-warning" /> {t("unsaved.badge")}
        </span>
      )}
      <Button onClick={onSave} disabled={busy || disabled || dirty === false}>
        {busy && <Loader2 className="animate-spin" />} {t("common.save")}
      </Button>
    </div>
  )
}

/** Loading – or, once the request failed, the error with "try again" (never an endless spinner). */
export function Loading({ error, onRetry }: { error?: unknown; onRetry?: () => void }) {
  return <Pending error={error} onRetry={onRetry} />
}

export function NumberField({
  label,
  hint,
  value,
  unit,
  onChange,
  min,
  max,
  disabled,
}: {
  label: string
  hint?: string
  value: number
  unit: string
  onChange?: (v: number) => void
  min?: number
  max?: number
  disabled?: boolean
}) {
  // the typed text is kept as it is: an emptied field stays empty (it used to jump to 0) and counts as invalid
  const [text, setText] = useState(String(value))
  const [seen, setSeen] = useState(value)
  if (!Object.is(value, seen)) {
    // changed from outside (another value loaded) – NaN is what an emptied field reports, never shown as "NaN"
    setSeen(value)
    if (!Number.isNaN(value) && Number(text) !== value) setText(String(value))
  }
  return (
    <Field label={label} hint={hint}>
      <div className="flex items-center gap-2">
        <Input
          type="number"
          inputMode="numeric"
          min={min}
          max={max}
          value={text}
          disabled={disabled}
          aria-invalid={text.trim() === "" || (min !== undefined && Number(text) < min) || (max !== undefined && Number(text) > max) || undefined}
          onChange={(e) => {
            setText(e.target.value)
            onChange?.(e.target.value.trim() === "" ? Number.NaN : Number(e.target.value))
          }}
          className="w-24 tabular"
        />
        <span className="text-sm text-muted-foreground">{unit}</span>
      </div>
    </Field>
  )
}

// ---------------------------------------------------------------- integration drawers
// Same layout everywhere: header on top, scrolling body, action bar pinned to the bottom edge.

export function IntegrationSheetContent({
  icon: Icon,
  title,
  description,
  help,
  children,
}: {
  icon: React.ElementType
  title: string
  description: string
  /** the matching section of the handbook ("Hilfe") */
  help?: { chapter: string; section?: string }
  children: React.ReactNode
}) {
  return (
    <SheetContent className="w-full gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-lg">
      <SheetHeader className="border-b">
        <SheetTitle className="flex items-center gap-2">
          <Icon className="size-4" /> {title}
        </SheetTitle>
        <SheetDescription>{description}</SheetDescription>
        {help && (
          <div className="-ml-1.5">
            <HelpLink chapter={help.chapter} section={help.section} topic={title} />
          </div>
        )}
      </SheetHeader>
      {children}
    </SheetContent>
  )
}

/** "Einrichten" on an integration tile. */
export function ConfigureLabel() {
  const { t } = useTranslation()
  return (
    <>
      <Settings2 /> {t("settings.int.configure")}
    </>
  )
}

// The same form parts sit in a drawer (the news sheet) or in a card of a settings page – the card brings body padding
// and a footer row with a line above instead of the pinned sheet footer.
const InCard = createContext(false)

/** A settings card (like Section) whose SheetBody / SheetActions render as card body and card footer. */
export function SettingsCard({
  title,
  description,
  actions,
  children,
}: {
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <Section title={title} description={description} actions={actions}>
      <InCard.Provider value={true}>{children}</InCard.Provider>
    </Section>
  )
}

/** A settings card without its own header – for a page whose PageHeader already names it (the watched CVEs). */
export function PlainCard({ children }: { children: React.ReactNode }) {
  return (
    <section className="flex flex-col rounded-xl border bg-card">
      <InCard.Provider value={true}>{children}</InCard.Provider>
    </section>
  )
}

export function SheetBody({ children }: { children: React.ReactNode }) {
  if (useContext(InCard)) return <div className="space-y-4 p-5">{children}</div>
  return <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">{children}</div>
}

export function SheetActions({ children }: { children: React.ReactNode }) {
  if (useContext(InCard)) return <div className="flex flex-wrap items-center justify-between gap-3 border-t px-5 py-3">{children}</div>
  return <SheetFooter className="flex-row items-center justify-between border-t bg-popover">{children}</SheetFooter>
}

export function SheetLoading({ error, onRetry }: { error?: unknown; onRetry?: () => void }) {
  return (
    <div className={useContext(InCard) ? "p-5" : "flex-1 p-4"}>
      <Loading error={error} onRetry={onRetry} />
    </div>
  )
}

/**
 * In a form whose save was refused as "stale": the input stays (nothing is lost by surprise) – a button loads the
 * current state into the form, then the change can be made again on it.
 */
export function StaleNotice({ onReload }: { onReload: () => void }) {
  const { t } = useTranslation()
  return (
    <div role="alert" className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
      <span className="min-w-0 flex-1 leading-relaxed">{t("stale.notice")}</span>
      <Button variant="outline" size="sm" onClick={onReload}>
        <RefreshCw /> {t("stale.reload")}
      </Button>
    </div>
  )
}
