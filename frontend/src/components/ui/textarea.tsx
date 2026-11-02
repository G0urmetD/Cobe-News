import * as React from "react"
import { cn } from "cn"
import { useFieldId } from "@/components/ui/field-context"

// Local change: text areas grow with their content instead of having a drag handle. Browsers with CSS `field-sizing`
// do it natively; for the others (older Safari/Firefox) the height is adjusted on every change.
const nativeAutosize = typeof CSS !== "undefined" && CSS.supports?.("field-sizing", "content")

function Textarea({ className, ref, onInput, id, ...props }: React.ComponentProps<"textarea">) {
  const fieldId = useFieldId()
  const inner = React.useRef<HTMLTextAreaElement | null>(null)
  const fit = React.useCallback(() => {
    const el = inner.current
    if (nativeAutosize || !el) return
    el.style.height = "auto"
    el.style.height = `${el.scrollHeight + (el.offsetHeight - el.clientHeight)}px`
  }, [])
  React.useLayoutEffect(fit, [fit, props.value])
  return (
    <textarea
      ref={(el) => {
        inner.current = el
        if (typeof ref === "function") ref(el)
        else if (ref) ref.current = el
      }}
      data-slot="textarea"
      id={id ?? fieldId}
      onInput={(e) => {
        fit()
        onInput?.(e)
      }}
      className={cn(
        "flex field-sizing-content max-h-[60vh] min-h-16 w-full resize-none overflow-y-auto rounded-lg border border-input bg-transparent px-2.5 py-2 text-base transition-colors outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:bg-input/50 disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 md:text-sm dark:bg-input/30 dark:disabled:bg-input/80 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40",
        className,
      )}
      {...props}
    />
  )
}

export { Textarea }
