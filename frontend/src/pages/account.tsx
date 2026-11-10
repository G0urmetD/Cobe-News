import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import { Fingerprint, KeyRound, Loader2, LogOut, MonitorSmartphone, Plus, ShieldCheck, ShieldOff, Smartphone, UserRound } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Section } from "@/components/cobe/common"
import { confirmAction } from "@/components/cobe/confirm"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Field } from "@/components/cobe/form"
import { Term } from "@/components/cobe/glossary"
import { CodeInput, NewPasswordFields, TotpEnroll } from "@/components/cobe/mfa"
import { DeviceList, PasskeyList, SessionList, passkeyErrorText, suggestedPasskeyName } from "@/components/cobe/security"
import { SubTabs } from "@/components/cobe/sub-tabs"
import { api, type ApiUser } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { errorText } from "@/lib/errors"
import { withReauth } from "@/lib/reauth"
import { type Passkey, type RememberedDevice, type SessionRow, registerPasskey, useMyDevices, useMyPasskeys, useMySessions } from "@/lib/security-api"
import { useTheme } from "@/lib/theme"
import { passkeySupport } from "@/lib/webauthn"
import { Loading } from "@/pages/settings-shared"

type ProfileTab = "profile" | "security" | "sessions"

/** Settings → "Profil & Sicherheit" (the profile page), in sub-tabs (`?tab=`): name, language, appearance and the
 *  password | the second factor and passkeys | the own sessions. */
export function ProfileSettings() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const asked = params.get("tab")
  const tab: ProfileTab = asked === "security" || asked === "sessions" ? asked : "profile"
  const parts = [
    { key: "profile" as const, icon: UserRound, label: t("settings.profile.title") },
    { key: "security" as const, icon: ShieldCheck, label: t("security.tab") },
    { key: "sessions" as const, icon: MonitorSmartphone, label: t("security.sessions") },
  ]
  return (
    <>
      <SubTabs parts={parts} active={tab} to={(k) => (k === "profile" ? "?" : `?tab=${k}`)} label={t("settings.nav.profile")} />
      {tab === "security" ? (
        <SecurityPane />
      ) : tab === "sessions" ? (
        <>
          <MySessions />
          <MyDevices />
        </>
      ) : (
        <ProfilePane />
      )}
    </>
  )
}

function ProfilePane() {
  const { t, i18n } = useTranslation()
  const { theme, setTheme } = useTheme()
  const auth = useAuth()
  const user = auth.user
  const [pwOpen, setPwOpen] = useState(false)
  if (!user) return null
  const local = user.auth_source === "local"
  return (
    <>
      <Section title={t("settings.profile.title")}>
        <div className="grid gap-4 p-5 sm:grid-cols-2">
          <Field label={t("settings.profile.name")}>
            <Input value={user.display_name} disabled />
          </Field>
          <Field label={t("auth.username")}>
            <Input value={user.username} disabled className="font-mono" />
          </Field>
          <Field label={t("shell.language")}>
            <ToggleGroup type="single" variant="outline" value={i18n.language === "en" ? "en" : "de"} onValueChange={(v) => v && void i18n.changeLanguage(v)} className="w-full">
              <ToggleGroupItem value="de" className="flex-1">
                Deutsch
              </ToggleGroupItem>
              <ToggleGroupItem value="en" className="flex-1">
                English
              </ToggleGroupItem>
            </ToggleGroup>
          </Field>
          <Field label={t("shell.theme")}>
            <ToggleGroup type="single" variant="outline" value={theme} onValueChange={(v) => v && setTheme(v)} className="w-full">
              <ToggleGroupItem value="light" className="flex-1">
                {t("shell.themeLight")}
              </ToggleGroupItem>
              <ToggleGroupItem value="dark" className="flex-1">
                {t("shell.themeDark")}
              </ToggleGroupItem>
              <ToggleGroupItem value="system" className="flex-1">
                {t("shell.themeSystem")}
              </ToggleGroupItem>
            </ToggleGroup>
          </Field>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t px-5 py-3">
          <p className="text-xs text-muted-foreground">
            {local ? t("settings.profile.sourceLocal") : t(`account.pwDirectory.${user.auth_source}`)} · {t(`role.${user.role}`)}
          </p>
          {local && (
            <Button size="sm" variant="outline" onClick={() => setPwOpen(true)}>
              <KeyRound /> {t("account.pwChange")}
            </Button>
          )}
        </div>
      </Section>
      <ChangePasswordDialog open={pwOpen} onOpenChange={setPwOpen} />
    </>
  )
}

/** The second factor (TOTP) and – for local accounts – the passkeys. */
function SecurityPane() {
  const { t } = useTranslation()
  const auth = useAuth()
  const qc = useQueryClient()
  const user = auth.user
  const [enrolling, setEnrolling] = useState(false)
  const [removing, setRemoving] = useState(false)
  if (!user) return null
  return (
    <>
      <Section
        title={t("settings.profile.mfa")}
        description={user.auth_source === "entra" ? (user.totp ? t("account.totpEntraOwn") : t("account.totpEntra")) : t("settings.profile.mfaHint")}
        actions={
          user.auth_source !== "entra" &&
          !user.totp && (
            <Button size="sm" variant="outline" onClick={() => setEnrolling(true)}>
              <Smartphone /> {t("mfa.authenticator")}
            </Button>
          )
        }
      >
        {user.auth_source !== "entra" && (
          <ul className="divide-y">
            <li className="flex flex-wrap items-center gap-3 px-5 py-3">
              <Smartphone className="size-4 text-muted-foreground" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{t("mfa.authenticator")}</p>
                <p className="text-xs text-muted-foreground">
                  {user.totp ? (user.role === "admin" ? t("account.totpRequired") : t("account.totpActive")) : t("account.totpOptional")}
                </p>
              </div>
              {user.totp ? (
                <>
                  <span className="flex items-center gap-1 text-xs text-success">
                    <ShieldCheck className="size-3.5" /> TOTP
                  </span>
                  <Button variant="outline" size="sm" onClick={() => setEnrolling(true)}>
                    <KeyRound /> {t("account.totpRenew")}
                  </Button>
                  {user.role !== "admin" && (
                    <Button variant="ghost" size="sm" onClick={() => setRemoving(true)}>
                      <ShieldOff /> {t("account.totpRemove")}
                    </Button>
                  )}
                </>
              ) : (
                <span className="flex items-center gap-1 text-xs text-warning">
                  <ShieldOff className="size-3.5" /> {t("users.noTotp")}
                </span>
              )}
            </li>
          </ul>
        )}
      </Section>

      <Dialog open={enrolling} onOpenChange={setEnrolling}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>{t("mfa.addAuthenticator")}</DialogTitle>
            <DialogDescription>{t("mfa.addText")}</DialogDescription>
          </DialogHeader>
          {enrolling && (
            <Reauth<{ secret: string; uri: string }> user={user} url="/api/me/totp/start" action={t("common.next")}>
              {(started) => (
                <TotpEnroll<ApiUser>
                  startUrl="/api/me/totp/start"
                  confirmUrl="/api/me/totp/confirm"
                  started={started}
                  onDone={(u) => {
                    auth.setUser(u)
                    setEnrolling(false)
                    toast.success(t("account.totpOn"))
                  }}
                />
              )}
            </Reauth>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={removing} onOpenChange={setRemoving}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t("account.totpRemoveTitle")}</DialogTitle>
            <DialogDescription>{t("account.totpRemoveText")}</DialogDescription>
          </DialogHeader>
          {removing && (
            <Reauth<ApiUser>
              user={user}
              url="/api/me/totp/remove"
              action={t("account.totpRemove")}
              destructive
              onDone={(u) => {
                auth.setUser(u)
                setRemoving(false)
                void qc.invalidateQueries({ queryKey: ["admin", "users"] })
              }}
            />
          )}
        </DialogContent>
      </Dialog>

      {user.auth_source === "local" && <PasskeysSection />}
    </>
  )
}

/** Own passkeys: add (the browser's dialog, after re-confirming), rename, remove (re-confirmed; ends the sessions
 *  signed in with it). Not offered while switched off, without HTTPS host name or at another address. */
function PasskeysSection() {
  const { t } = useTranslation()
  const auth = useAuth()
  const qc = useQueryClient()
  const q = useMyPasskeys()
  const [adding, setAdding] = useState(false)
  const [renaming, setRenaming] = useState<Passkey | null>(null)
  const cfg = auth.config?.passkeys
  const support = passkeySupport(cfg?.origin)
  // why a new one cannot be added here (existing ones stay listed and removable)
  const why = !cfg?.enabled
    ? t("passkey.disabled")
    : !cfg.available
      ? t(`passkey.unavailable.${cfg.reason ?? "bad_host"}`, { defaultValue: t("errors.passkey_unavailable") })
      : support !== "ok"
        ? t(`passkey.err.${support}`, { origin: cfg.origin })
        : null
  const refresh = () => void qc.invalidateQueries({ queryKey: ["me", "passkeys"] })
  const remove = async (p: Passkey) => {
    if (!(await confirmAction({ title: t("passkey.removeTitle"), text: t("passkey.removeText", { name: p.name }), confirm: t("common.remove") }))) return
    try {
      const r = await withReauth(() => api.del<{ sessions_ended: number }>(`/api/me/passkeys/${p.id}`))
      toast.success(r.sessions_ended ? t("passkey.removedSessions", { count: r.sessions_ended }) : t("passkey.removed"))
      refresh()
      void qc.invalidateQueries({ queryKey: ["me", "sessions"] })
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  return (
    <>
      <Section
        title={
          <span className="inline-flex items-center gap-1.5">
            <Fingerprint className="size-4" /> <Term k="passkey">{t("passkey.title")}</Term>
          </span>
        }
        description={t("passkey.hint")}
        actions={
          <>
            <HelpLink chapter="erste-schritte" section="passkeys" topic={t("passkey.title")} />
            <Button size="sm" variant="outline" disabled={!!why} title={why ?? undefined} onClick={() => setAdding(true)}>
              <Plus /> {t("passkey.add")}
            </Button>
          </>
        }
      >
        {why && <p className="border-b bg-muted/40 px-5 py-2.5 text-xs text-muted-foreground">{why}</p>}
        {q.data ? (
          <PasskeyList items={q.data} onRename={setRenaming} onRemove={(p) => void remove(p)} empty={t("passkey.none")} />
        ) : (
          <Loading error={q.error} onRetry={q.refetch} />
        )}
      </Section>
      {adding && (
        <AddPasskeyDialog
          onClose={() => setAdding(false)}
          onAdded={() => {
            setAdding(false)
            refresh()
          }}
        />
      )}
      {renaming && <RenamePasskeyDialog passkey={renaming} onClose={() => setRenaming(null)} onDone={refresh} />}
    </>
  )
}

function AddPasskeyDialog({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const { t } = useTranslation()
  const [name, setName] = useState(() => suggestedPasskeyName(t))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const add = async () => {
    setBusy(true)
    setError(null)
    try {
      await withReauth(() => registerPasskey(name.trim()))
      toast.success(t("passkey.added"))
      onAdded()
    } catch (e) {
      setError(passkeyErrorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("passkey.addTitle")}</DialogTitle>
          <DialogDescription>{t("passkey.addText")}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void add()
          }}
        >
          <Field label={t("passkey.name")} hint={t("passkey.nameHint")} htmlFor="passkey-name">
            <Input id="passkey-name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} autoFocus />
          </Field>
          {error && <p className="text-sm text-destructive">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose} disabled={busy}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={busy || !name.trim()}>
              {busy ? <Loader2 className="animate-spin" /> : <Fingerprint />} {t("passkey.addDo")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function RenamePasskeyDialog({ passkey, onClose, onDone }: { passkey: Passkey; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation()
  const [name, setName] = useState(passkey.name)
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true)
    try {
      await api.patch(`/api/me/passkeys/${passkey.id}`, { name: name.trim() })
      onDone()
      onClose()
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
          <DialogTitle>{t("passkey.renameTitle")}</DialogTitle>
          <DialogDescription>{t("passkey.nameHint")}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void save()
          }}
        >
          <Field label={t("passkey.name")} htmlFor="passkey-rename">
            <Input id="passkey-rename" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} autoFocus />
          </Field>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={busy || !name.trim() || name.trim() === passkey.name}>
              {busy && <Loader2 className="animate-spin" />} {t("common.save")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Meine Sitzungen: every running session of the own account – end one, or all others. */
function MySessions() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useMySessions()
  const [busy, setBusy] = useState<string | null>(null)
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["me", "sessions"] })
    void qc.invalidateQueries({ queryKey: ["me", "devices"] }) // "alle anderen abmelden" forgets them too
  }
  const endOne = async (s: SessionRow) => {
    setBusy(s.id)
    try {
      await api.del(`/api/me/sessions/${s.id}`)
      toast.success(t("security.ended"))
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
      refresh()
    }
  }
  const endOthers = async () => {
    if (!(await confirmAction({ title: t("security.endOthersTitle"), text: t("security.endOthersText"), confirm: t("security.endOthers") }))) return
    setBusy("others")
    try {
      const r = await api.post<{ ended: number }>("/api/me/sessions/end-others")
      toast.success(t("security.endedCount", { count: r.ended }))
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
      refresh()
    }
  }
  const others = (q.data ?? []).filter((s) => !s.current).length
  return (
    <Section
      title={t("security.sessions")}
      description={t("security.sessionsHint")}
      actions={<HelpLink chapter="erste-schritte" section="abmelden" topic={t("security.sessions")} />}
    >
      {q.data ? <SessionList rows={q.data} onEnd={(s) => void endOne(s)} busy={busy} /> : <Loading error={q.error} onRetry={q.refetch} />}
      <div className="flex flex-wrap items-center justify-between gap-3 border-t px-5 py-3">
        <p className="text-xs text-muted-foreground">{t("security.sessionsFoot")}</p>
        <Button size="sm" variant="outline" disabled={!others || busy === "others"} onClick={() => void endOthers()}>
          {busy === "others" ? <Loader2 className="animate-spin" /> : <LogOut />} {t("security.endOthers")}
        </Button>
      </div>
    </Section>
  )
}

/** Gemerkte Geräte: where the sign-in skips the TOTP step ("Zweiten Faktor auf dem Gerät merken") – forget one or all.
 *  Shown only when there is one. */
function MyDevices() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useMyDevices()
  const [busy, setBusy] = useState<string | null>(null)
  const run = async (key: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(key)
    try {
      await fn()
      toast.success(done)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
      void qc.invalidateQueries({ queryKey: ["me", "devices"] })
    }
  }
  const forgetOne = (d: RememberedDevice) => void run(d.id, () => api.del(`/api/auth/devices/${d.id}`), t("security.forgotten"))
  const forgetAll = async () => {
    if (!(await confirmAction({ title: t("security.forgetAllTitle"), text: t("security.forgetAllText"), confirm: t("security.forgetAll") }))) return
    await run("all", () => api.post("/api/auth/devices/forget-all"), t("security.forgottenAll"))
  }
  if (!q.data?.length) return null
  return (
    <Section title={t("security.devices")} description={t("security.devicesHint")}>
      <DeviceList rows={q.data} onForget={forgetOne} busy={busy} />
      <div className="flex flex-wrap items-center justify-end gap-3 border-t px-5 py-3">
        <Button size="sm" variant="outline" disabled={busy === "all"} onClick={() => void forgetAll()}>
          {busy === "all" ? <Loader2 className="animate-spin" /> : <ShieldOff />} {t("security.forgetAll")}
        </Button>
      </div>
    </Section>
  )
}

function ChangePasswordDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation()
  const [current, setCurrent] = useState("")
  const [next, setNext] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const change = async () => {
    setBusy(true)
    try {
      await api.post("/api/me/password", { current_password: current, new_password: next })
      toast.success(t("account.pwChanged"))
      setCurrent("")
      onOpenChange(false)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        {open && (
          <>
            <DialogHeader>
              <DialogTitle>{t("account.pwChange")}</DialogTitle>
              <DialogDescription>{t("account.pwOthersOut")}</DialogDescription>
            </DialogHeader>
            <Field label={t("account.currentPassword")} htmlFor="cur-pw">
              <Input id="cur-pw" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
            </Field>
            <NewPasswordFields onValid={setNext} autoFocus={false} />
            <DialogFooter>
              <Button variant="ghost" onClick={() => onOpenChange(false)}>
                {t("common.cancel")}
              </Button>
              <Button disabled={!current || !next || busy} onClick={() => void change()}>
                {busy && <Loader2 className="animate-spin" />} {t("common.save")}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

/**
 * Replacing or removing the second factor asks first who is at the keyboard: the current code from the app (or, without
 * one, the password). A session left open is not enough to take the account over.
 */
function Reauth<T>({
  user,
  url,
  action,
  destructive = false,
  onDone,
  children,
}: {
  user: ApiUser
  url: string
  action: string
  destructive?: boolean
  onDone?: (res: T) => void
  children?: (res: T) => React.ReactNode
}) {
  const { t } = useTranslation()
  const [value, setValue] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<T | null>(null)
  const byCode = user.totp
  if (done !== null && children) return <>{children(done)}</>
  const send = async (v = value) => {
    setBusy(true)
    setError(null)
    try {
      const r = await api.post<T>(url, byCode ? { code: v } : { password: v })
      setDone(r)
      onDone?.(r)
    } catch (e) {
      setError(errorText(t, e))
      setValue("")
    } finally {
      setBusy(false)
    }
  }
  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault()
        void send()
      }}
    >
      {byCode ? (
        <Field label={t("account.reauthCode")} hint={t("account.reauthCodeHint")}>
          <CodeInput value={value} onChange={setValue} onComplete={(v) => void send(v)} />
        </Field>
      ) : (
        <Field label={t("account.currentPassword")} hint={t("account.reauthPasswordHint")}>
          <Input type="password" autoComplete="current-password" value={value} onChange={(e) => setValue(e.target.value)} autoFocus />
        </Field>
      )}
      {error && <p className="text-sm text-destructive">{error}</p>}
      <DialogFooter>
        <Button type="submit" variant={destructive ? "destructive" : "default"} disabled={busy || (byCode ? value.length < 6 : !value)}>
          {busy && <Loader2 className="animate-spin" />} {action}
        </Button>
      </DialogFooter>
    </form>
  )
}
