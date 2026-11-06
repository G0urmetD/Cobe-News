import { useId, useState } from "react"
import { useTranslation } from "react-i18next"
import { X } from "lucide-react"
import { useFieldId } from "@/components/ui/field-context"
import { normalizeWord, splitWords, wordProblem } from "@/lib/rule-filters"
import { cn } from "@/lib/utils"

/**
 * Words as chips (a rule's "Schlagwörter", "Nicht senden, wenn enthalten"): Enter or a comma adds what was typed,
 * Backspace in the empty field takes the last one back, × removes one. A word the server would refuse (length, signs,
 * twice, too many) is not added – the reason shows under the field, tied to it (aria-describedby) and read out.
 */
export function ChipInput({ value, onChange, placeholder, className }: { value: string[]; onChange: (v: string[]) => void; placeholder: string; className?: string }) {
  const { t } = useTranslation()
  const fieldId = useFieldId()
  const problemId = useId()
  const [text, setText] = useState("")
  const [problem, setProblem] = useState<string | null>(null)
  const add = (raw: string) => {
    let next = value
    for (const w of splitWords(raw)) {
      const why = wordProblem(w, next)
      if (why) {
        setProblem(t(why, { word: w }))
        return false
      }
      next = [...next, normalizeWord(w)]
    }
    setProblem(null)
    if (next !== value) onChange(next)
    return true
  }
  const keys = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault()
      if (text.trim() && add(text)) setText("")
    } else if (e.key === "Backspace" && !text && value.length) {
      onChange(value.slice(0, -1))
    }
  }
  return (
    <div className="space-y-1">
      <div
        className={cn(
          "flex min-h-9 w-full flex-wrap items-center gap-1 rounded-lg border border-input bg-transparent px-2 py-1 text-sm transition-colors focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/50 dark:bg-input/30",
          problem && "border-destructive",
          className,
        )}
      >
        {value.map((w) => (
          <span key={w} className="inline-flex items-center gap-1 rounded-md bg-secondary px-1.5 py-0.5 text-xs font-medium">
            <bdi>{w}</bdi>
            <button
              type="button"
              aria-label={t("notify.wordRemove", { word: w })}
              onClick={() => onChange(value.filter((x) => x !== w))}
              className="text-muted-foreground hover:text-foreground"
            >
              <X className="size-3" />
            </button>
          </span>
        ))}
        <input
          id={fieldId}
          value={text}
          onChange={(e) => {
            setText(e.target.value)
            setProblem(null)
          }}
          onKeyDown={keys}
          onBlur={() => text.trim() && add(text) && setText("")}
          aria-invalid={problem ? true : undefined}
          aria-describedby={problem ? problemId : undefined}
          placeholder={value.length ? "" : placeholder}
          maxLength={200}
          className="min-w-24 flex-1 bg-transparent px-1 py-0.5 outline-none placeholder:text-muted-foreground"
        />
      </div>
      {problem && (
        <p id={problemId} role="alert" className="text-xs text-destructive">
          {problem}
        </p>
      )}
    </div>
  )
}
