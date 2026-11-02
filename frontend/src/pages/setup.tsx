import { useState } from "react"
import { useTranslation } from "react-i18next"
import { ArrowLeft, ArrowRight, Check, Loader2, Newspaper, PartyPopper, Terminal } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Field } from "@/components/cobe/form"
import { NewPasswordFields, TotpEnroll } from "@/components/cobe/mfa"
import { AuthLayout } from "@/pages/auth-layout"
import { ApiError, api } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { errorText } from "@/lib/errors"
import { cn } from "@/lib/utils"

const STEPS = ["token", "account", "mfa", "done"] as const
type Step = (typeof STEPS)[number]
const VISIBLE = STEPS.filter((s) => s !== "done")

/**
 * First start, as a wizard: the one-time token from the container log, then the first local admin (the emergency
 * account), then its TOTP – mandatory for admins. The token is checked when the admin is created (one request).
 */
export function SetupPage() {
  const { t } = useTranslation()
  const auth = useAuth()
  const [step, setStep] = useState<Step>("token")
  const [token, setToken] = useState("")
  const [username, setUsername] = useState("")
  const [displayName, setDisplayName] = useState("")
  const [password, setPassword] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const idx = STEPS.indexOf(step)
  const nameOk = /^[A-Za-z0-9._-]{3,64}$/.test(username)

  const create = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.post("/api/setup", { token, username, display_name: displayName, password })
      setStep("mfa") // the session is now in the "enroll" stage – the TOTP set-up follows right here
    } catch (e) {
      setError(errorText(t, e))
      if (e instanceof ApiError && e.code === "invalid_token") setStep("token")
    } finally {
      setBusy(false)
    }
  }
  const canNext = { token: token.replace(/\W/g, "").length >= 8, account: nameOk && !!password, mfa: false, done: true }[step]

  return (
    <AuthLayout wide>
      <div className="space-y-8">
        <div className="space-y-4">
          <p className="text-xs font-medium tracking-wider text-primary uppercase">{t("setup.eyebrow")}</p>
          <ol className="flex items-center gap-2">
            {VISIBLE.map((s, i) => (
              <li key={s} className="flex min-w-0 flex-1 items-center gap-2" aria-current={i === idx ? "step" : undefined}>
                <span
                  className={cn(
                    "flex size-7 shrink-0 items-center justify-center rounded-full border text-xs font-semibold transition-colors",
                    i < idx && "border-primary bg-primary text-primary-foreground",
                    i === idx && "border-primary text-primary ring-4 ring-primary/15",
                    i > idx && "text-muted-foreground",
                  )}
                >
                  {i < idx ? <Check className="size-3.5" /> : i + 1}
                </span>
                <span className={cn("hidden min-w-0 truncate text-xs font-medium lg:block", i === idx ? "text-foreground" : "text-muted-foreground")}>{t(`setup.step.${s}`)}</span>
                {i < VISIBLE.length - 1 && <span className={cn("h-px min-w-3 flex-1", i < idx ? "bg-primary" : "bg-border")} />}
              </li>
            ))}
          </ol>
        </div>

        <div className="rounded-2xl border bg-card p-6 shadow-sm sm:p-8">
          {step === "token" && (
            <div className="space-y-6">
              <Header title={t("setup.tokenTitle")} text={t("setup.tokenText")} />
              <div className="rounded-lg border bg-muted/50 p-4 font-mono text-xs leading-relaxed">
                <div className="mb-2 flex items-center gap-2 font-sans text-xs font-medium text-muted-foreground">
                  <Terminal className="size-3.5" /> {t("setup.tokenWhere")}
                </div>
                docker compose logs app | grep -A1 "Setup token"
              </div>
              <Field label={t("setup.token")} htmlFor="setup-token" hint={t("setup.tokenHint")}>
                <Input
                  id="setup-token"
                  value={token}
                  onChange={(e) => setToken(e.target.value.toUpperCase())}
                  placeholder="XXXX-XXXX-XXXX-XXXX"
                  className="h-11 font-mono tracking-widest"
                  autoFocus
                />
              </Field>
            </div>
          )}

          {step === "account" && (
            <div className="space-y-6">
              <Header title={t("setup.accountTitle")} text={t("setup.text")} />
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label={t("setup.username")} htmlFor="setup-user" hint={t("setup.usernameHint")}>
                  <Input
                    id="setup-user"
                    autoComplete="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="h-10 font-mono"
                    aria-invalid={!!username && !nameOk}
                    autoFocus
                  />
                </Field>
                <Field label={t("setup.displayName")} htmlFor="setup-name">
                  <Input id="setup-name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} className="h-10" />
                </Field>
              </div>
              <NewPasswordFields onValid={setPassword} autoFocus={false} />
              <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("setup.emergencyHint")}</p>
            </div>
          )}

          {step === "mfa" && (
            <div className="space-y-6">
              <Header title={t("setup.mfaTitle")} text={t("setup.mfaText")} />
              <TotpEnroll startUrl="/api/auth/enroll/start" confirmUrl="/api/auth/enroll/confirm" onDone={() => setStep("done")} />
            </div>
          )}

          {step === "done" && (
            <div className="flex flex-col items-center gap-4 py-6 text-center">
              <div className="flex size-14 items-center justify-center rounded-full bg-success/15 text-success">
                <PartyPopper className="size-6" />
              </div>
              <h2 className="text-xl font-semibold">{t("setup.doneTitle")}</h2>
              <p className="max-w-md text-sm text-muted-foreground">{t("setup.doneText")}</p>
              <Button size="lg" className="mt-2" onClick={() => void auth.refresh()}>
                <Newspaper /> {t("setup.toNews")}
              </Button>
            </div>
          )}

          {error && <p className="mt-6 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>}

          {(step === "token" || step === "account") && (
            <div className="mt-8 flex items-center justify-between border-t pt-6">
              <Button variant="ghost" onClick={() => (setStep("token"), setError(null))} disabled={step === "token"}>
                <ArrowLeft /> {t("common.back")}
              </Button>
              <Button onClick={() => (step === "token" ? (setStep("account"), setError(null)) : void create())} disabled={!canNext || busy}>
                {busy && <Loader2 className="animate-spin" />}
                {step === "account" ? t("setup.create") : t("common.next")} <ArrowRight />
              </Button>
            </div>
          )}
        </div>
      </div>
    </AuthLayout>
  )
}

function Header({ title, text }: { title: string; text: string }) {
  return (
    <div className="space-y-1.5">
      <h2 className="text-xl font-semibold tracking-tight">{title}</h2>
      <p className="text-sm leading-relaxed text-muted-foreground">{text}</p>
    </div>
  )
}
