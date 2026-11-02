import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Forward, Loader2, Send } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Field } from "@/components/cobe/form"
import { uiLang } from "@/lib/channels"
import { errorText } from "@/lib/errors"
import { COMMENT_MAX, type ForwardThing, forwardState, forwardTo } from "@/lib/forward-api"
import { useMyTeams } from "@/lib/teams-api"

/**
 * "An mein Team weiterleiten": a story or a finding with a short comment to one of the own teams – to the channel an admin
 * chose for that team (the reader never chooses a target). Hidden while Teams is off or the person is in no team; off,
 * with the reason on hover, while none of their teams has a channel.
 */
export function ForwardButton({
  thing,
  title,
  size = "default",
  variant = "outline",
}: {
  thing: ForwardThing
  title: string
  size?: "default" | "sm" | "xs"
  variant?: "outline" | "ghost" | "link"
}) {
  const { t } = useTranslation()
  const mine = useMyTeams()
  const [open, setOpen] = useState(false)
  const st = forwardState(mine.data)
  if (st.state === "hidden") return null
  const button = (
    <Button variant={variant} size={size} disabled={st.state === "off"} onClick={() => setOpen(true)} className={variant === "link" ? "h-auto px-0" : undefined}>
      <Forward /> {t("forward.button")}
    </Button>
  )
  if (st.state === "off")
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          {/* a disabled button gets no pointer events: the wrapper carries the tooltip (and the focus) */}
          <span tabIndex={0} className="inline-flex cursor-not-allowed rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
            {button}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs leading-relaxed">{t("forward.noChannel")}</TooltipContent>
      </Tooltip>
    )
  return (
    <>
      {button}
      {open && <ForwardDialog thing={thing} title={title} teams={st.teams} onClose={() => setOpen(false)} />}
    </>
  )
}

function ForwardDialog({ thing, title, teams, onClose }: { thing: ForwardThing; title: string; teams: { id: string; name: string }[]; onClose: () => void }) {
  const { t, i18n } = useTranslation()
  const [team, setTeam] = useState(teams[0]?.id ?? "")
  const [comment, setComment] = useState("")
  const [busy, setBusy] = useState(false)
  const name = teams.find((x) => x.id === team)?.name ?? ""
  const send = async () => {
    if (!team || busy) return
    setBusy(true)
    try {
      const r = await forwardTo({ ...thing, team_id: team, comment: comment.trim(), lang: uiLang(i18n.language) })
      toast.success(t("forward.sent", { team: r.team }))
      onClose()
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("forward.title")}</DialogTitle>
          <DialogDescription className="line-clamp-2">{title}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          {teams.length > 1 ? (
            <Field label={t("forward.team")}>
              <Select value={team} onValueChange={setTeam}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper">
                  {teams.map((x) => (
                    <SelectItem key={x.id} value={x.id}>
                      {x.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          ) : (
            <p className="text-sm text-muted-foreground">{t("forward.toTeam", { team: name })}</p>
          )}
          <Field label={t("forward.comment")} hint={t("forward.commentHint", { count: COMMENT_MAX - comment.length })}>
            <Textarea
              value={comment}
              onChange={(e) => setComment(e.target.value.slice(0, COMMENT_MAX))}
              maxLength={COMMENT_MAX}
              rows={3}
              placeholder={t("forward.commentPlaceholder")}
              autoFocus
            />
          </Field>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button onClick={() => void send()} disabled={busy || !team}>
            {busy ? <Loader2 className="animate-spin" /> : <Send />} {t("forward.send")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
