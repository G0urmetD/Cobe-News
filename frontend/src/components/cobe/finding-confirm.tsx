import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Loader2, ShieldCheck, ShieldOff, Undo2 } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill } from "@/components/cobe/badges"
import { Field } from "@/components/cobe/form"
import { errorText } from "@/lib/errors"
import { fmtDate } from "@/lib/format"
import { CONFIRM_STATUSES, type ConfirmLapse, type ConfirmStatus, type Confirmation, NOTE_MAX, NOTE_REQUIRED, confirmProblem, useFindingConfirm } from "@/lib/finding-confirm"

/** "Bestätigt · Nicht betroffen" – who, when and why on hover (and focus). */
export function ConfirmedPill({ c, compact = false }: { c: Confirmation; compact?: boolean }) {
  const { t } = useTranslation()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="relative z-10 cursor-help rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          <Pill color="--success" fg="--success-fg">
            <ShieldCheck /> {compact ? t(`confirm.status.${c.status}`) : t("confirm.badge", { status: t(`confirm.status.${c.status}`) })}
          </Pill>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">
        <p>{t("confirm.byAt", { by: c.by || t("confirm.someone"), date: fmtDate(c.at) })}</p>
        {c.note && <p className="font-medium">{c.note}</p>}
        <p className="opacity-80">{t("confirm.forAll")}</p>
      </TooltipContent>
    </Tooltip>
  )
}

/** "Bestätigung aufgehoben: jetzt ausgenutzt" – the finding changed, it counts and notifies again. */
export function LapsedPill({ l }: { l: ConfirmLapse }) {
  const { t } = useTranslation()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="cursor-help rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          <Pill color="--warning">
            <ShieldOff /> {t("confirm.lapsed", { why: t(`confirm.reason.${l.reason}`) })}
          </Pill>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">
        {t("confirm.lapsedHint", { status: t(`confirm.status.${l.status}`), by: l.by || t("confirm.someone"), date: fmtDate(l.at) })}
      </TooltipContent>
    </Tooltip>
  )
}

/**
 * The finding's own actions in the drawer: "Bestätigen…" (a dialog) or, when it is confirmed, "Bestätigung aufheben" –
 * only for those who may (an admin, a member of a team the product belongs to). Everybody else sees the badge only.
 */
export function ConfirmActions({
  product,
  finding,
  title,
  confirmed,
  may,
}: {
  product: string
  finding: string
  title: string
  confirmed: Confirmation | null | undefined
  may: boolean
}) {
  const { t } = useTranslation()
  const { undo, busy } = useFindingConfirm(product)
  const [open, setOpen] = useState(false)
  if (!may) return null
  if (confirmed)
    return (
      <Button
        variant="link"
        size="xs"
        className="h-auto px-0"
        disabled={busy}
        onClick={() => undo.mutate(finding, { onSuccess: () => toast.success(t("confirm.undone")), onError: (e) => toast.error(errorText(t, e)) })}
        title={t("confirm.undoHint")}
      >
        <Undo2 /> {t("confirm.undo")}
      </Button>
    )
  return (
    <>
      <Button variant="link" size="xs" className="h-auto px-0" onClick={() => setOpen(true)} title={t("confirm.forAll")}>
        <ShieldCheck /> {t("confirm.action")}
      </Button>
      {open && <ConfirmDialog product={product} finding={finding} title={title} onClose={() => setOpen(false)} />}
    </>
  )
}

function ConfirmDialog({ product, finding, title, onClose }: { product: string; finding: string; title: string; onClose: () => void }) {
  const { t } = useTranslation()
  const { confirm } = useFindingConfirm(product)
  const [status, setStatus] = useState<ConfirmStatus | "">("")
  const [note, setNote] = useState("")
  const problem = confirmProblem(status, note)
  const busy = confirm.isPending
  const save = () => {
    if (problem || !status || busy) return
    confirm.mutate(
      { finding, status, note },
      {
        onSuccess: () => {
          toast.success(t("confirm.done", { status: t(`confirm.status.${status}`) }))
          onClose()
        },
        onError: (e) => toast.error(errorText(t, e)),
      },
    )
  }
  const required = !!status && NOTE_REQUIRED.includes(status)
  return (
    <Dialog open onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("confirm.title")}</DialogTitle>
          <DialogDescription className="line-clamp-2">{title}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">{t("confirm.lead")}</p>
          <Field label={t("confirm.statusLabel")} hint={status ? t(`confirm.statusHint.${status}`) : undefined}>
            <Select value={status} onValueChange={(v) => setStatus(v as ConfirmStatus)}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder={t("confirm.choose")} />
              </SelectTrigger>
              <SelectContent position="popper">
                {CONFIRM_STATUSES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {t(`confirm.status.${s}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label={t(required ? "confirm.noteRequired" : "confirm.note")} hint={t("confirm.noteHint", { count: NOTE_MAX - note.length })}>
            <Textarea value={note} onChange={(e) => setNote(e.target.value.slice(0, NOTE_MAX))} maxLength={NOTE_MAX} rows={2} placeholder={t("confirm.notePlaceholder")} />
          </Field>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button onClick={save} disabled={busy || !!problem}>
            {busy ? <Loader2 className="animate-spin" /> : <ShieldCheck />} {t("confirm.save")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
