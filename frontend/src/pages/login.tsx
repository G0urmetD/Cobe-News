import { useCallback, useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { AlertTriangle, ArrowLeft, Fingerprint, KeyRound, Loader2, Lock, ShieldCheck, ShieldX, Smartphone } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Field } from "@/components/cobe/form"
import { CodeInput, NewPasswordFields, TotpEnroll } from "@/components/cobe/mfa"
import { AuthLayout } from "@/pages/auth-layout"
import { ApiError, api, type LoginStep } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { errorText } from "@/lib/errors"
import { passkeyErrorText, suggestedPasskeyName } from "@/components/cobe/security"
import { type EnrollInfo, enrollPasskey, signInWithPasskey } from "@/lib/security-api"
import { PasskeyError, passkeySupport } from "@/lib/webauthn"

type Step = "credentials" | "mfa" | "password" | "enroll"

function MicrosoftIcon() {
  return (
    <svg viewBox="0 0 21 21" className="size-4" aria-hidden>
      <rect x="1" y="1" width="9" height="9" fill="#f25022" />
      <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
      <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
      <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
    </svg>
  )
}

function StepHeader({ icon: Icon, title, text }: { icon?: React.ElementType; title: string; text: string }) {
  return (
    <div className="space-y-1.5">
      {Icon && (
        <div className="mb-4 flex size-11 items-center justify-center rounded-xl bg-primary/10 text-primary">
          <Icon className="size-5" />
        </div>
      )}
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="text-sm text-muted-foreground">{text}</p>
    </div>
  )
}

/** Sign-in: local or AD in one form, "Mit Microsoft anmelden" when Entra is on, then the
 *  code, a new password (temporary one) or the TOTP set-up (admins). */
export function LoginPage({ resume }: { resume?: Step }) {
  const { t } = useTranslation()
  const auth = useAuth()
  const [step, setStep] = useState<Step>(resume ?? "credentials")
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState<{ title: string; text: string; blocked?: boolean } | null>(null)
  const [loading, setLoading] = useState(false)
  const [otp, setOtp] = useState("")
  const [newPassword, setNewPassword] = useState<string | null>(null)
  const ldap = !!auth.config?.ldap_enabled
  const [source, setSource] = useState<"ldap" | "local">(() => {
    if (!ldap) return "local"
    try {
      return localStorage.getItem("cobe-news.loginSource") === "local" ? "local" : "ldap"
    } catch {
      return "ldap"
    }
  })
  const chooseSource = (v: "ldap" | "local") => {
    setSource(v)
    try {
      localStorage.setItem("cobe-news.loginSource", v)
    } catch {
      /* private mode – only a convenience */
    }
  }

  // errors handed over by the Entra redirect (/?login_error=…) – only known codes, then gone from the address
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get("login_error")
    if (code && /^[a-z_]{3,40}$/.test(code)) {
      setError({ title: t("auth.failed"), text: t(`errors.${code}`, { defaultValue: t("errors.generic") }) })
      params.delete("login_error")
      const q = params.toString()
      window.history.replaceState(null, "", window.location.pathname + (q ? `?${q}` : ""))
    }
  }, [t])

  const handle = useCallback(
    (res: LoginStep) => {
      setError(null)
      setOtp("")
      if (res.next === "done" && res.user) {
        auth.setUser(res.user)
        return
      }
      setStep(res.next as Step)
    },
    [auth],
  )

  // passkeys: switched on, possible at the configured address – and this page opened at exactly that address in a
  // browser that can (otherwise the button is not shown: the passkeys of this site are bound to that address)
  const pk = auth.config?.passkeys
  const passkeyOk = !!pk?.enabled && pk.available && passkeySupport(pk.origin) === "ok"
  const [pkBusy, setPkBusy] = useState(false)
  const withPasskey = async () => {
    setPkBusy(true)
    setError(null)
    try {
      handle(await signInWithPasskey())
    } catch (e) {
      // cancelled in the browser's own dialog: nothing to report
      if (e instanceof PasskeyError && e.code === "cancelled") setError({ title: t("passkey.signInCancelled"), text: t("passkey.err.cancelled") })
      else if (e instanceof ApiError && e.code === "ip_blocked") setError({ title: t("auth.failed"), text: errorText(t, e), blocked: true })
      else setError({ title: t("auth.failed"), text: passkeyErrorText(t, e) })
    } finally {
      setPkBusy(false)
    }
  }

  const fail = (e: unknown) => {
    if (e instanceof ApiError && (e.code === "ip_blocked" || e.code === "account_locked")) setError({ title: t("auth.failed"), text: errorText(t, e), blocked: true })
    else if (e instanceof ApiError && e.code === "session_revoked") {
      setStep("credentials")
      setError({ title: t("auth.failed"), text: errorText(t, e) })
    } else setError({ title: t("auth.failed"), text: errorText(t, e) })
  }

  const run = async (fn: () => Promise<LoginStep>) => {
    setLoading(true)
    try {
      handle(await fn())
    } catch (e) {
      fail(e)
      setOtp("")
    } finally {
      setLoading(false)
    }
  }

  const back = (
    <button
      type="button"
      onClick={async () => {
        await api.post("/api/auth/logout").catch(() => undefined)
        setStep("credentials")
        setError(null)
      }}
      className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft className="size-4" /> {t("common.back")}
    </button>
  )

  const errorBox = error && (
    <Alert variant="destructive">
      {error.blocked ? <ShieldX /> : <AlertTriangle />}
      <AlertTitle>{error.title}</AlertTitle>
      <AlertDescription>{error.text}</AlertDescription>
    </Alert>
  )

  return (
    <AuthLayout wide={step === "enroll"}>
      {step === "credentials" && (
        <div className="space-y-6">
          <StepHeader title={t("auth.signIn")} text={t("auth.signInText")} />
          {passkeyOk && (
            <Button size="lg" variant="outline" className="h-10 w-full" disabled={pkBusy || loading} onClick={() => void withPasskey()}>
              {pkBusy ? <Loader2 className="animate-spin" /> : <Fingerprint />} {t("passkey.signIn")}
            </Button>
          )}
          {auth.config?.entra_enabled && (
            <>
              <Button
                size="lg"
                variant="outline"
                className="h-10 w-full"
                onClick={() => window.location.assign(`/api/auth/oidc/start?next=${encodeURIComponent(window.location.pathname + window.location.search)}`)}
              >
                <MicrosoftIcon /> {t("auth.withEntra")}
              </Button>
            </>
          )}
          {(passkeyOk || auth.config?.entra_enabled) && (
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <span className="h-px flex-1 bg-border" />
              {t("auth.orAccount")}
              <span className="h-px flex-1 bg-border" />
            </div>
          )}
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void run(() => api.post<LoginStep>("/api/auth/login", { username, password, source: ldap ? source : "local" }))
            }}
            className="space-y-4"
          >
            {ldap && (
              <ToggleGroup type="single" variant="outline" value={source} onValueChange={(v) => v && chooseSource(v as "ldap" | "local")} className="w-full">
                <ToggleGroupItem value="ldap" className="flex-1">
                  {t("auth.ad")}
                </ToggleGroupItem>
                <ToggleGroupItem value="local" className="flex-1">
                  {t("auth.local")}
                </ToggleGroupItem>
              </ToggleGroup>
            )}
            <Field label={ldap && source === "ldap" ? t("auth.usernameAd") : t("auth.username")} htmlFor="username">
              <Input id="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} className="h-10" autoFocus />
            </Field>
            <Field label={t("auth.password")} htmlFor="password">
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="h-10"
                aria-invalid={!!error}
              />
            </Field>
            {errorBox}
            <Button type="submit" size="lg" className="h-10 w-full" disabled={loading || !username || !password}>
              {loading ? <Loader2 className="animate-spin" /> : <Lock />} {t("auth.continue")}
            </Button>
          </form>
        </div>
      )}

      {step === "mfa" && (
        <div className="space-y-6">
          {back}
          <StepHeader icon={ShieldCheck} title={t("auth.mfaTitle")} text={t("auth.mfaText")} />
          <div className="flex justify-center">
            <CodeInput size="lg" value={otp} onChange={setOtp} onComplete={(v) => void run(() => api.post<LoginStep>("/api/auth/mfa", { code: v }))} />
          </div>
          {errorBox}
          <Button size="lg" className="h-10 w-full" disabled={otp.length < 6 || loading} onClick={() => void run(() => api.post<LoginStep>("/api/auth/mfa", { code: otp }))}>
            {loading && <Loader2 className="animate-spin" />} {t("auth.verify")}
          </Button>
          <p className="text-center text-xs text-muted-foreground">{t("auth.mfaLost")}</p>
        </div>
      )}

      {step === "password" && (
        <div className="space-y-6">
          {back}
          <StepHeader icon={KeyRound} title={t("auth.changePwTitle")} text={t("auth.changePwText")} />
          <NewPasswordFields onValid={setNewPassword} />
          {errorBox}
          <Button
            size="lg"
            className="h-10 w-full"
            disabled={!newPassword || loading}
            onClick={() => void run(() => api.post<LoginStep>("/api/auth/password", { new_password: newPassword }))}
          >
            {loading && <Loader2 className="animate-spin" />} {t("auth.changePwSave")}
          </Button>
        </div>
      )}

      {step === "enroll" && <EnrollStep back={back} onDone={handle} />}
    </AuthLayout>
  )
}

/**
 * The set-up of the second factor within the sign-in: TOTP always – and, for a local reader while "Zweiter Faktor für
 * alle" is on, a passkey of this device instead (when passkeys are on and this page is at their address). What it
 * offers comes from GET /api/auth/state (`enroll`).
 */
function EnrollStep({ back, onDone }: { back: React.ReactNode; onDone: (res: LoginStep) => void }) {
  const { t } = useTranslation()
  const auth = useAuth()
  const [info, setInfo] = useState<EnrollInfo | null>(null)
  useEffect(() => {
    let alive = true
    api.get<{ stage: string | null; enroll?: EnrollInfo }>("/api/auth/state").then(
      (r) => alive && setInfo(r.enroll ?? null),
      () => undefined, // only what is offered besides TOTP – the TOTP set-up works without it
    )
    return () => {
      alive = false
    }
  }, [])
  const pk = auth.config?.passkeys
  const passkeyOk = !!info?.passkey && !!pk?.enabled && pk.available && passkeySupport(pk.origin) === "ok"
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const withPasskey = async () => {
    setBusy(true)
    setError(null)
    try {
      onDone(await enrollPasskey(suggestedPasskeyName(t)))
    } catch (e) {
      if (!(e instanceof PasskeyError && e.code === "cancelled")) setError(passkeyErrorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="space-y-6">
      {back}
      <StepHeader icon={Smartphone} title={t("auth.enrollTitle")} text={info?.reason === "admin" ? t("auth.enrollText") : t("auth.enrollTextAll")} />
      {info?.has_passkey && (
        <Alert>
          <Fingerprint />
          <AlertDescription>{t("auth.enrollHasPasskey")}</AlertDescription>
        </Alert>
      )}
      <div className="rounded-2xl border bg-card p-6">
        <TotpEnroll<LoginStep> startUrl="/api/auth/enroll/start" confirmUrl="/api/auth/enroll/confirm" onDone={onDone} />
      </div>
      {passkeyOk && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <span className="h-px flex-1 bg-border" />
            {t("auth.orInstead")}
            <span className="h-px flex-1 bg-border" />
          </div>
          <p className="text-sm text-muted-foreground">{t("auth.enrollPasskeyText")}</p>
          <Button size="lg" variant="outline" className="h-10 w-full" disabled={busy} onClick={() => void withPasskey()}>
            {busy ? <Loader2 className="animate-spin" /> : <Fingerprint />} {t("auth.enrollPasskey")}
          </Button>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
      )}
    </div>
  )
}
