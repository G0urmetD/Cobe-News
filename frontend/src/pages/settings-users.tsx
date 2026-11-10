import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import {
  Ban,
  Check,
  Copy,
  Fingerprint,
  KeyRound,
  Loader2,
  LockOpen,
  LogOut,
  MailX,
  MonitorSmartphone,
  MoreHorizontal,
  Plus,
  ShieldCheck,
  ShieldOff,
  Siren,
  Trash2,
  Undo2,
  UserCheck,
  X,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill } from "@/components/cobe/badges"
import { OffPill } from "@/components/cobe/off-pill"
import { confirmAction } from "@/components/cobe/confirm"
import { Field } from "@/components/cobe/form"
import { Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Ts } from "@/components/cobe/time"
import { copyWithToast } from "@/lib/clipboard"
import { ApiError, api, type Role } from "@/lib/api"
import { type UserRow, isBlocked, isPending, useUsers } from "@/lib/admin-api"
import { withReauth } from "@/lib/reauth"
import { useAuth } from "@/lib/auth"
import { errorText } from "@/lib/errors"
import { fmtDate, fmtDateTime, initials } from "@/lib/format"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { DeviceList, PasskeyList, SessionList } from "@/components/cobe/security"
import { type Passkey, type SessionRow, useUserDevices, useUserPasskeys, useUserSessions } from "@/lib/security-api"
import { Loading, SheetActions, SheetBody } from "@/pages/settings-shared"
import { isoList } from "@/lib/bidi"

/** Wraps a control that is off for a reason – the reason on hover (a disabled button gets no pointer events). */
function Why({ why, children, className = "inline-flex" }: { why?: string; children: React.ReactNode; className?: string }) {
  if (!why) return <>{children}</>
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className={className}>
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">{why}</TooltipContent>
    </Tooltip>
  )
}

function TempPassword({ value, onClose, title }: { value: string; onClose: () => void; title: string }) {
  const { t } = useTranslation()
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{t("users.tempText")}</DialogDescription>
        </DialogHeader>
        <div className="flex items-center gap-2 rounded-lg bg-muted px-3 py-2">
          <code className="flex-1 font-mono text-sm tracking-wide break-all">{value}</code>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label={t("common.copy")}
            onClick={() => {
              void copyWithToast(value)
            }}
          >
            <Copy />
          </Button>
        </div>
        <DialogFooter>
          <Button onClick={onClose}>{t("users.tempDone")}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function UsersPane() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { user: me } = useAuth()
  const q = useUsers()
  const [creating, setCreating] = useState(false)
  const [temp, setTemp] = useState<{ title: string; value: string } | null>(null)
  const [security, setSecurity] = useState<UserRow | null>(null)
  // "Wartet auf Freigabe": only the accounts and raises waiting for an admin (shown while there are any)
  // ?waiting=1 (the sidebar notice "… wartet auf Freigabe") opens the list filtered – also when it is already open
  const [params] = useSearchParams()
  const waitingLink = params.get("waiting") === "1"
  const [onlyWaiting, setOnlyWaiting] = useState(waitingLink)
  const [seenLink, setSeenLink] = useState(waitingLink)
  if (waitingLink !== seenLink) {
    setSeenLink(waitingLink)
    if (waitingLink) setOnlyWaiting(true)
  }
  // the sidebar's notices with it: a "… wartet auf Freigabe" line dealt with no longer stands out
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["admin", "users"] })
    void qc.invalidateQueries({ queryKey: ["admin", "activity"] })
  }
  // sensitive changes ask who is at the keyboard first (withReauth); an edit of an older state (another admin was
  // quicker) is refused – the list shows the current one again
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await withReauth(fn)
      refresh()
    } catch (e) {
      toast.error(errorText(t, e))
      if (e instanceof ApiError && e.code === "stale") refresh()
    }
  }
  if (!q.data) return <Loading error={q.error} onRetry={q.refetch} />
  const waits = (u: UserRow) => isPending(u) || u.pending_role === "admin"
  const waiting = q.data.filter(waits).length
  const rows = onlyWaiting && waiting ? q.data.filter(waits) : q.data
  // approval: a waiting account switched on (as admin: re-confirmed, asked first), or declined (stays off – asked)
  const approve = async (u: UserRow) => {
    if (
      u.role === "admin" &&
      !(await confirmAction({ title: t("users.approveAdminTitle"), text: t("users.approveAdminText", { name: u.display_name }), confirm: t("users.approve"), destructive: false }))
    )
      return
    await act(async () => {
      await api.post(`/api/admin/users/${u.id}/approve`, { version: u.version })
      toast.success(t("users.approveDone", { name: u.display_name }))
    })
  }
  const decline = async (u: UserRow) => {
    if (!(await confirmAction({ title: t("users.declineTitle"), text: t("users.declineText", { name: u.display_name }), confirm: t("users.decline") }))) return
    await act(() => api.post(`/api/admin/users/${u.id}/decline`, { version: u.version }))
  }
  const raise = async (u: UserRow, yes: boolean) => {
    if (
      !(await confirmAction({
        title: t(yes ? "users.raiseTitle" : "users.keepReaderTitle"),
        text: t(yes ? "users.raiseText" : "users.keepReaderText", { name: u.display_name }),
        confirm: t(yes ? "users.raiseApprove" : "users.keepReader"),
        destructive: false,
      }))
    )
      return
    await act(() => api.post(`/api/admin/users/${u.id}/${yes ? "approve-role" : "decline-role"}`, { version: u.version }))
  }
  return (
    <>
      <Section
        title={t("settings.tab.users")}
        description={t("users.hint")}
        actions={
          <>
            <HelpLink chapter="anmeldung" section="lokale-benutzer" topic={t("settings.tab.users")} />
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus /> {t("users.create")}
            </Button>
          </>
        }
      >
        {waiting > 0 && (
          <div className="flex flex-wrap items-center gap-2 border-b px-5 py-2.5" role="group" aria-label={t("users.filter")}>
            {[false, true].map((only) => (
              <Button key={String(only)} size="sm" variant={onlyWaiting === only ? "secondary" : "ghost"} aria-pressed={onlyWaiting === only} onClick={() => setOnlyWaiting(only)}>
                {only ? (
                  <>
                    <UserCheck /> {t("users.filterWaiting")}
                    <Pill color="--warning" className="px-1.5 tabular-nums">
                      {waiting}
                    </Pill>
                  </>
                ) : (
                  t("users.filterAll")
                )}
              </Button>
            ))}
          </div>
        )}
        <ul className="divide-y">
          {rows.map((u) => {
            const self = u.id === me?.id
            const protectedWhy = u.is_emergency ? t("users.protectedEmergency") : self ? t("users.protectedSelf") : undefined
            const roleWhy = protectedWhy ?? (u.auth_source !== "local" ? t("users.directoryRole") : undefined)
            return (
              <li key={u.id} className="flex flex-wrap items-center gap-3 px-5 py-3">
                <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-primary/10 text-[11px] font-semibold text-primary">
                  {initials(u.display_name)}
                </span>
                {/* on a phone the name with its chips takes the line, the controls wrap below – chips wrap, never overlap */}
                <div className="min-w-0 flex-1 basis-[calc(100%-3.5rem)] sm:basis-0">
                  <p className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-sm font-medium">
                    <span className="min-w-0 [overflow-wrap:anywhere]">{u.display_name}</span>
                    {self && <Pill color="--primary">{t("users.you")}</Pill>}
                    {u.is_emergency && (
                      <Pill color="--sev-critical" title={t("users.emergencyHint")}>
                        <Siren /> {t("users.emergency")}
                      </Pill>
                    )}
                    {!u.is_active && <OffPill reason={u.deactivated_reason} />}
                    {u.pending_role === "admin" && (
                      <Pill color="--warning" title={t("users.raisePendingHint")}>
                        {t("users.raisePending")}
                      </Pill>
                    )}
                    {u.pending_role === "declined" && (
                      <Pill color="--muted-foreground" title={t("users.raiseDeclinedHint")}>
                        {t("users.raiseDeclined")}
                      </Pill>
                    )}
                    {u.must_change_password &&
                      (u.temp_password_expired ? (
                        <Pill color="--sev-critical" title={t("users.tempExpiredHint")}>
                          {t("users.tempExpired")}
                        </Pill>
                      ) : (
                        <Pill color="--warning" title={u.temp_password_expires_at ? fmtDateTime(u.temp_password_expires_at) : undefined}>
                          {u.temp_password_expires_at ? t("users.tempUntil", { date: fmtDate(u.temp_password_expires_at) }) : t("users.tempPending")}
                        </Pill>
                      ))}
                    {u.locked_for > 0 && <Pill color="--sev-critical">{t("users.locked", { minutes: Math.ceil(u.locked_for / 60) })}</Pill>}
                    {u.welcome === "no_address" && (
                      <Pill color="--warning" title={t("users.welcomeNoAddressHint")}>
                        <MailX /> {t("users.welcomeNoAddress")}
                      </Pill>
                    )}
                    {u.welcome === "failed" && (
                      <Pill color="--warning" title={t("users.welcomeFailedHint")}>
                        <MailX /> {t("users.welcomeFailed")}
                      </Pill>
                    )}
                  </p>
                  {/* on a phone the details wrap (name, mail and last sign-in all readable); from sm on one line */}
                  <p className="text-xs text-muted-foreground [overflow-wrap:anywhere] sm:truncate">
                    <span className="font-mono">{u.username}</span>
                    {u.email && ` · ${u.email}`} ·{" "}
                    {u.last_login_at ? (
                      <>
                        {t("users.lastLogin")} <Ts at={u.last_login_at} rel />
                      </>
                    ) : (
                      t("users.neverLoggedIn")
                    )}
                    {!!u.teams?.length && ` · ${t("users.teams", { names: isoList(u.teams) })}`}
                  </p>
                  {/* waiting for an admin: the decision right in the row */}
                  {(isPending(u) || u.pending_role === "admin") && (
                    <div className="mt-1.5 flex flex-wrap gap-2">
                      <Button size="xs" onClick={() => void (isPending(u) ? approve(u) : raise(u, true))}>
                        <Check /> {isPending(u) ? (u.role === "admin" ? t("users.approveAsAdmin") : t("users.approve")) : t("users.raiseApprove")}
                      </Button>
                      <Button size="xs" variant="outline" onClick={() => void (isPending(u) ? decline(u) : raise(u, false))}>
                        <X /> {isPending(u) ? t("users.decline") : t("users.keepReader")}
                      </Button>
                    </div>
                  )}
                </div>
                {/* phone: two rows of their own below the name, indented to it – origin and TOTP, then the controls (role
                    filling the row, the switch with its label, the menu at the end); from sm on all in the one row */}
                <div className="flex basis-full items-center gap-2 pl-11 sm:basis-auto sm:pl-0">
                  <Pill color="--muted-foreground">{t(`users.source.${u.auth_source}`)}</Pill>
                  {u.auth_source !== "entra" &&
                    (u.totp ? (
                      <span className="flex items-center gap-1 text-xs text-success">
                        <ShieldCheck className="size-3.5" /> TOTP
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-xs text-warning">
                        <ShieldOff className="size-3.5" /> {t("users.noTotp")}
                      </span>
                    ))}
                  {!!u.passkeys && (
                    <span className="flex items-center gap-1 text-xs text-success" title={t("users.passkeysHint", { count: u.passkeys })}>
                      <Fingerprint className="size-3.5" /> {u.passkeys}
                    </span>
                  )}
                </div>
                <div className="flex basis-full items-center gap-3 pl-11 sm:basis-auto sm:pl-0">
                  <div className="min-w-0 flex-1 sm:flex-none">
                    <Why why={roleWhy} className="flex w-full sm:inline-flex sm:w-auto">
                      <Select
                        value={u.role}
                        disabled={!!roleWhy}
                        onValueChange={(r) => void act(() => api.patch(`/api/admin/users/${u.id}`, { role: r as Role, version: u.version }))}
                      >
                        <SelectTrigger size="sm" className="w-full sm:w-32" aria-label={t("users.role")}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent position="popper">
                          <SelectItem value="admin">{t("role.admin")}</SelectItem>
                          <SelectItem value="reader">{t("role.reader")}</SelectItem>
                        </SelectContent>
                      </Select>
                    </Why>
                  </div>
                  <label className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground">
                    <span className="sm:hidden">{t("users.active")}</span>
                    <Why why={protectedWhy}>
                      <Switch
                        checked={u.is_active}
                        disabled={!!protectedWhy}
                        aria-label={t("users.active")}
                        title={protectedWhy ? undefined : t("users.active")}
                        onCheckedChange={(x) => (x && isPending(u) ? void approve(u) : void act(() => api.patch(`/api/admin/users/${u.id}`, { is_active: x, version: u.version })))}
                      />
                    </Why>
                  </label>
                  <UserMenu u={u} self={self} onTemp={(title, value) => setTemp({ title, value })} act={act} onSecurity={() => setSecurity(u)} />
                </div>
              </li>
            )
          })}
        </ul>
      </Section>
      {creating && (
        <CreateUser
          onClose={() => setCreating(false)}
          onCreated={(name, pw) => {
            setCreating(false)
            refresh()
            setTemp({ title: t("users.createdTitle", { name }), value: pw })
          }}
        />
      )}
      {temp && <TempPassword title={temp.title} value={temp.value} onClose={() => setTemp(null)} />}
      <Sheet open={!!security} onOpenChange={(o) => !o && setSecurity(null)}>
        {security && <UserSecuritySheet u={security} onChanged={refresh} />}
      </Sheet>
    </>
  )
}

function UserMenu({
  u,
  self,
  onTemp,
  act,
  onSecurity,
}: {
  u: UserRow
  self: boolean
  onTemp: (title: string, pw: string) => void
  act: (fn: () => Promise<unknown>) => Promise<void>
  onSecurity: () => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const reset = async (what: { password: boolean; totp: boolean }) => {
    setOpen(false)
    const key = what.password ? "users.resetPw" : "users.resetTotp"
    if (!(await confirmAction({ title: t(`${key}Title`), text: t(`${key}Text`, { name: u.display_name }), confirm: t(key), destructive: false }))) return
    await act(async () => {
      const r = await api.post<UserRow & { temp_password?: string }>(`/api/admin/users/${u.id}/reset`, { ...what, version: u.version })
      if (r.temp_password) onTemp(t("users.resetDoneTitle", { name: u.display_name }), r.temp_password)
      else toast.success(t("users.totpReset"))
    })
  }
  // the lasting block – also for an account the sync switched off (its switch is off already); lifted, the sync decides
  const block = async (blocked: boolean) => {
    setOpen(false)
    const text = blocked ? "users.blockText" : u.auth_source === "local" ? "users.unblockTextLocal" : "users.unblockText"
    const title = blocked ? "users.blockTitle" : "users.unblockTitle"
    if (!(await confirmAction({ title: t(title), text: t(text, { name: u.display_name }), confirm: t(blocked ? "users.block" : "users.unblock"), destructive: blocked }))) return
    await act(async () => {
      await api.post(`/api/admin/users/${u.id}/block`, { blocked, version: u.version })
      toast.success(t(blocked ? "users.blockDone" : "users.unblockDone", { name: u.display_name }))
    })
  }
  const remove = async () => {
    setOpen(false)
    if (!(await confirmAction({ title: t("users.deleteTitle"), text: t("users.deleteText", { name: u.display_name }), confirm: t("common.remove") }))) return
    await act(() => api.del(`/api/admin/users/${u.id}`))
  }
  const local = u.auth_source === "local"
  const emergencyOther = u.is_emergency && !self
  const items: { key: string; icon: React.ElementType; label: string; onClick: () => void; why?: string; danger?: boolean }[] = [
    { key: "security", icon: MonitorSmartphone, label: t("users.security"), onClick: () => (setOpen(false), onSecurity()) },
    {
      key: "pw",
      icon: KeyRound,
      label: t("users.resetPw"),
      onClick: () => void reset({ password: true, totp: false }),
      why: !local ? t("users.directoryPw") : self ? t("users.useAccount") : emergencyOther ? t("users.emergencyCli") : undefined,
    },
    {
      key: "totp",
      icon: ShieldOff,
      label: t("users.resetTotp"),
      onClick: () => void reset({ password: false, totp: true }),
      why: u.auth_source === "entra" ? t("users.entraMfa") : !u.totp ? t("users.noTotp") : self ? t("users.useAccount") : emergencyOther ? t("users.emergencyCli") : undefined,
    },
    {
      key: "unlock",
      icon: LockOpen,
      label: t("users.unlock"),
      onClick: () => (setOpen(false), void act(() => api.post(`/api/admin/users/${u.id}/unlock`))),
      why: u.locked_for > 0 ? undefined : t("users.notLocked"),
    },
    isBlocked(u)
      ? { key: "unblock", icon: Undo2, label: t("users.unblock"), onClick: () => void block(false) }
      : {
          key: "block",
          icon: Ban,
          label: t("users.block"),
          onClick: () => void block(true),
          why: u.is_emergency ? t("users.protectedEmergency") : self ? t("users.protectedSelf") : undefined,
          danger: true,
        },
    {
      key: "del",
      icon: Trash2,
      label: t("users.delete"),
      onClick: () => void remove(),
      why: u.is_emergency ? t("users.protectedEmergency") : self ? t("users.protectedSelf") : undefined,
      danger: true,
    },
  ]
  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label={t("users.actions")}>
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        {items.map((i) => (
          <DropdownMenuItem key={i.key} disabled={!!i.why} variant={i.danger ? "destructive" : "default"} onSelect={i.onClick} title={i.why}>
            <i.icon /> {i.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function CreateUser({ onClose, onCreated }: { onClose: () => void; onCreated: (name: string, pw: string) => void }) {
  const { t } = useTranslation()
  const [v, setV] = useState({ username: "", display_name: "", email: "", role: "reader" as Role })
  const [busy, setBusy] = useState(false)
  const nameOk = /^[A-Za-z0-9._@-]{3,64}$/.test(v.username)
  const mailOk = !v.email || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.email)
  const create = async () => {
    setBusy(true)
    try {
      const r = await withReauth(() => api.post<UserRow & { temp_password: string }>("/api/admin/users", { ...v, email: v.email || null }))
      onCreated(r.display_name, r.temp_password)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("users.create")}</DialogTitle>
          <DialogDescription>{t("users.createText")}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <Field label={t("users.username")}>
            <Input value={v.username} onChange={(e) => setV({ ...v, username: e.target.value.trim() })} aria-invalid={!!v.username && !nameOk} autoFocus />
          </Field>
          <Field label={t("users.displayName")}>
            <Input value={v.display_name} onChange={(e) => setV({ ...v, display_name: e.target.value })} />
          </Field>
          <Field label={t("users.email")}>
            <Input value={v.email} onChange={(e) => setV({ ...v, email: e.target.value.trim() })} placeholder="name@corp.example" aria-invalid={!mailOk} />
          </Field>
          <Field label={t("users.role")} hint={t(`role.${v.role}Hint`)}>
            <Select value={v.role} onValueChange={(r) => setV({ ...v, role: r as Role })}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value="reader">{t("role.reader")}</SelectItem>
                <SelectItem value="admin">{t("role.admin")}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button disabled={busy || !nameOk || !mailOk} onClick={() => void create()}>
            {busy && <Loader2 className="animate-spin" />} {t("users.createDo")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** A person's sessions and passkeys (admins): end one or all sessions, remove a passkey – each re-confirmed. */
function UserSecuritySheet({ u, onChanged }: { u: UserRow; onChanged: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const sq = useUserSessions(u.id)
  const pq = useUserPasskeys(u.id)
  const dq = useUserDevices(u.id)
  const [busy, setBusy] = useState<string | null>(null)
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["admin", "users", u.id] })
    onChanged()
  }
  const run = async (key: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(key)
    try {
      await withReauth(fn)
      toast.success(done)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
      refresh()
    }
  }
  const endOne = (s: SessionRow) => void run(s.id, () => api.del(`/api/admin/users/${u.id}/sessions/${s.id}`), t("security.ended"))
  const endAll = async () => {
    if (!(await confirmAction({ title: t("users.endAllTitle"), text: t("users.endAllText", { name: u.display_name }), confirm: t("users.endAll") }))) return
    await run("all", () => api.post(`/api/admin/users/${u.id}/sessions/end-all`), t("users.endAllDone", { name: u.display_name }))
  }
  const removeKey = async (p: Passkey) => {
    if (!(await confirmAction({ title: t("passkey.removeTitle"), text: t("users.passkeyRemoveText", { name: p.name, user: u.display_name }), confirm: t("common.remove") }))) return
    await run(p.id, () => api.del(`/api/admin/users/${u.id}/passkeys/${p.id}`), t("passkey.removed"))
  }
  const forgetDevices = async () => {
    if (!(await confirmAction({ title: t("users.forgetDevicesTitle"), text: t("users.forgetDevicesText", { name: u.display_name }), confirm: t("users.forgetDevices") }))) return
    await run("devices", () => api.post(`/api/admin/users/${u.id}/devices/forget-all`), t("users.forgetDevicesDone", { name: u.display_name }))
  }
  const others = (sq.data ?? []).filter((s) => !s.current).length
  return (
    <SheetContent className="w-full gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-lg">
      <SheetHeader className="border-b">
        <SheetTitle className="flex items-center gap-2">
          <MonitorSmartphone className="size-4" /> {t("users.securityTitle", { name: u.display_name })}
        </SheetTitle>
        <SheetDescription>{t("users.securityText")}</SheetDescription>
      </SheetHeader>
      <SheetBody>
        <section className="rounded-xl border">
          <h3 className="border-b px-5 py-2.5 text-sm font-semibold">{t("security.sessions")}</h3>
          {sq.data ? (
            sq.data.length ? (
              <SessionList rows={sq.data} onEnd={endOne} busy={busy} />
            ) : (
              <p className="px-5 py-4 text-sm text-muted-foreground">{t("users.noSessions")}</p>
            )
          ) : (
            <div className="p-4">
              <Loading error={sq.error} onRetry={sq.refetch} />
            </div>
          )}
        </section>
        {!!dq.data?.length && (
          <section className="rounded-xl border">
            <h3 className="border-b px-5 py-2.5 text-sm font-semibold">{t("security.devices")}</h3>
            <DeviceList rows={dq.data} />
            <div className="flex justify-end border-t px-5 py-2.5">
              <Button variant="outline" size="sm" disabled={busy === "devices"} onClick={() => void forgetDevices()}>
                {busy === "devices" ? <Loader2 className="animate-spin" /> : <ShieldOff />} {t("users.forgetDevices")}
              </Button>
            </div>
          </section>
        )}
        {u.auth_source === "local" && (
          <section className="rounded-xl border">
            <h3 className="border-b px-5 py-2.5 text-sm font-semibold">{t("passkey.title")}</h3>
            {pq.data ? (
              <PasskeyList items={pq.data} onRemove={(p) => void removeKey(p)} empty={t("users.noPasskeys")} />
            ) : (
              <div className="p-4">
                <Loading error={pq.error} onRetry={pq.refetch} />
              </div>
            )}
          </section>
        )}
      </SheetBody>
      <SheetActions>
        <span className="text-xs text-muted-foreground">{t("users.securityReauth")}</span>
        <Button variant="destructive" size="sm" disabled={!others || busy === "all"} onClick={() => void endAll()}>
          {busy === "all" ? <Loader2 className="animate-spin" /> : <LogOut />} {t("users.endAll")}
        </Button>
      </SheetActions>
    </SheetContent>
  )
}
