import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Link } from "react-router"
import { BellOff, BellRing } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { errorText } from "@/lib/errors"
import { fmtDate } from "@/lib/format"
import { type Mute, type MuteKind, untilEndOf, useMuteMutations, useMutes } from "@/lib/reader-api"

export interface MuteTarget {
  kind: MuteKind
  key: string
  label: string
}

/** The running mute of a target (none: not muted). */
export function useMuteOf() {
  const mutes = useMutes().data?.items
  return (kind: MuteKind, key: string): Mute | undefined => mutes?.find((m) => m.kind === kind && m.key === key)
}

/** Mute / unmute with a toast – the same everywhere (menus, drawers, the watchlist, "Meine Stummschaltungen"). */
export function useMuteActions() {
  const { t } = useTranslation()
  const m = useMuteMutations()
  const mute = (target: MuteTarget, when: { days: number } | { until: string }) =>
    m.add.mutate(
      { kind: target.kind, key: target.key, ...when },
      {
        onSuccess: (r) => toast.success(t("reader.mute.done", { name: target.label, date: fmtDate(r.until) })),
        onError: (e) => toast.error(errorText(t, e)),
      },
    )
  const unmute = (mute: Mute) =>
    m.remove.mutate(mute.id, {
      onSuccess: () => toast.success(t("reader.mute.lifted", { name: mute.label })),
      onError: (e) => toast.error(errorText(t, e)),
    })
  return { mute, unmute, busy: m.add.isPending || m.remove.isPending }
}

/**
 * The menu entries for muting one or more targets (inside an open DropdownMenuContent): 7 days, 30 days, until a day –
 * or "aufheben" for one that is muted. Several targets: one submenu each. `onUntil` opens the date dialog.
 */
export function MuteItems({ targets, onUntil }: { targets: MuteTarget[]; onUntil: (t: MuteTarget) => void }) {
  const { t } = useTranslation()
  const of = useMuteOf()
  const { mute, unmute } = useMuteActions()
  if (!targets.length) return null
  const entries = (x: MuteTarget) => {
    const running = of(x.kind, x.key)
    return running ? (
      <DropdownMenuItem onSelect={() => unmute(running)}>
        <BellRing /> {t("reader.mute.lift", { date: fmtDate(running.until) })}
      </DropdownMenuItem>
    ) : (
      <>
        <DropdownMenuItem onSelect={() => mute(x, { days: 7 })}>{t("reader.mute.days", { count: 7 })}</DropdownMenuItem>
        <DropdownMenuItem onSelect={() => mute(x, { days: 30 })}>{t("reader.mute.days", { count: 30 })}</DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onUntil(x)}>{t("reader.mute.untilDots")}</DropdownMenuItem>
      </>
    )
  }
  return (
    <>
      <DropdownMenuLabel className="max-w-64 text-xs font-normal whitespace-normal text-muted-foreground">{t("reader.mute.onlyYou")}</DropdownMenuLabel>
      {targets.length === 1 ? (
        <>
          <DropdownMenuLabel className="text-xs">{t(`reader.mute.title.${targets[0].kind}`, { name: targets[0].label })}</DropdownMenuLabel>
          {entries(targets[0])}
        </>
      ) : (
        targets.map((x) => (
          <DropdownMenuSub key={`${x.kind}:${x.key}`}>
            <DropdownMenuSubTrigger>
              <BellOff /> <span className="truncate">{x.label}</span>
              {of(x.kind, x.key) && <span className="ml-auto pl-2 text-[11px] text-muted-foreground">{t("reader.mute.badge")}</span>}
            </DropdownMenuSubTrigger>
            <DropdownMenuSubContent>{entries(x)}</DropdownMenuSubContent>
          </DropdownMenuSub>
        ))
      )}
    </>
  )
}

/** "Stummschalten bis …": a day in the future (at most a year), the end of that day. */
export function MuteUntilDialog({ target, onClose }: { target: MuteTarget | null; onClose: () => void }) {
  const { t } = useTranslation()
  const { mute } = useMuteActions()
  const [day, setDay] = useState("")
  const [today] = useState(() => new Date())
  const iso = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`
  const min = iso(today)
  const max = iso(new Date(today.getTime() + 365 * 86_400_000))
  const until = untilEndOf(day)
  const ok = !!until && day >= min && day <= max
  return (
    <Dialog open={!!target} onOpenChange={(o) => !o && (setDay(""), onClose())}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{target ? t(`reader.mute.title.${target.kind}`, { name: target.label }) : ""}</DialogTitle>
          <DialogDescription>{t("reader.mute.onlyYou")}</DialogDescription>
        </DialogHeader>
        <div className="space-y-1.5">
          <Label htmlFor="mute-until">{t("reader.mute.untilLabel")}</Label>
          <Input id="mute-until" type="date" value={day} min={min} max={max} onChange={(e) => setDay(e.target.value)} />
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => (setDay(""), onClose())}>
            {t("common.cancel")}
          </Button>
          <Button
            disabled={!ok}
            onClick={() => {
              if (!target || !until) return
              mute(target, { until })
              setDay("")
              onClose()
            }}
          >
            <BellOff /> {t("reader.mute.action")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** A button with its own menu ("Stummschalten") – drawers' footers and the watchlist's rows. */
export function MuteButton({
  targets,
  size = "default",
  variant = "outline",
  iconOnly = false,
}: {
  targets: MuteTarget[]
  size?: "default" | "sm" | "xs" | "icon"
  variant?: "outline" | "ghost" | "link"
  iconOnly?: boolean
}) {
  const { t } = useTranslation()
  const of = useMuteOf()
  const [until, setUntil] = useState<MuteTarget | null>(null)
  if (!targets.length) return null
  const muted = targets.some((x) => of(x.kind, x.key))
  const label = muted ? t("reader.mute.muted") : t("reader.mute.action")
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant={variant} size={iconOnly ? "icon-sm" : size} aria-label={label} title={t("reader.mute.onlyYou")}>
            <BellOff className={muted ? "text-warning" : undefined} />
            {!iconOnly && label}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          <MuteItems targets={targets} onUntil={setUntil} />
          <DropdownMenuSeparator />
          <DropdownMenuItem asChild>
            <Link to="/settings/notifications?tab=mutes">{t("reader.mute.mine")}</Link>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <MuteUntilDialog target={until} onClose={() => setUntil(null)} />
    </>
  )
}
