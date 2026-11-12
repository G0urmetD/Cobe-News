import { useEffect, useMemo, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import QRCode from "react-qr-code"
import { CircleCheck, CircleDashed, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from "@/components/ui/input-otp"
import { Field } from "@/components/cobe/form"
import { api } from "@/lib/api"
import { errorText } from "@/lib/errors"
import { cn } from "@/lib/utils"

/** Password rules (at least 12 characters, no common password – the
 *  server checks that list), the 6-digit code input and the TOTP enrolment with QR code. */

export const MIN_PASSWORD = 12

export function passwordRules(pw: string, confirm: string) {
  return [
    { key: "setup.pwLength", ok: pw.length >= MIN_PASSWORD, n: MIN_PASSWORD },
    { key: "setup.pwMatch", ok: pw.length > 0 && pw === confirm, n: 0 },
  ]
}

export function PasswordChecklist({ rules }: { rules: { key: string; ok: boolean; n: number }[] }) {
  const { t } = useTranslation()
  const score = rules.filter((r) => r.ok).length
  return (
    <div className="space-y-3">
      <div className="flex gap-1">
        {rules.map((_, i) => (
          <span key={i} className={cn("h-1.5 flex-1 rounded-full transition-colors", i < score ? (score === rules.length ? "bg-success" : "bg-warning") : "bg-muted")} />
        ))}
      </div>
      <ul className="grid gap-1.5 text-[13px] sm:grid-cols-2">
        {rules.map((r) => (
          <li key={r.key} className={cn("flex items-center gap-2", r.ok ? "text-foreground" : "text-muted-foreground")}>
            {r.ok ? <CircleCheck className="size-4 text-success" /> : <CircleDashed className="size-4" />}
            {t(r.key, { n: r.n })}
          </li>
        ))}
      </ul>
      <p className="text-xs text-muted-foreground">{t("setup.pwServerCheck")}</p>
    </div>
  )
}

export function NewPasswordFields({ onValid, autoFocus = true }: { onValid: (pw: string | null) => void; autoFocus?: boolean }) {
  const { t } = useTranslation()
  const [pw, setPw] = useState("")
  const [pw2, setPw2] = useState("")
  const rules = useMemo(() => passwordRules(pw, pw2), [pw, pw2])
  const valid = rules.every((r) => r.ok)
  useEffect(() => onValid(valid ? pw : null), [valid, pw, onValid])
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("setup.newPassword")} htmlFor="new-pw">
          <Input id="new-pw" type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} className="h-10" autoFocus={autoFocus} />
        </Field>
        <Field label={t("setup.confirmPassword")} htmlFor="new-pw2">
          <Input id="new-pw2" type="password" autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} className="h-10" />
        </Field>
      </div>
      <PasswordChecklist rules={rules} />
    </div>
  )
}

export function CodeInput({
  value,
  onChange,
  onComplete,
  size = "md",
  autoFocus = true,
}: {
  value: string
  onChange: (v: string) => void
  onComplete?: (v: string) => void
  size?: "md" | "lg"
  /** false where the code is not the first field (the password change: the current password comes first) */
  autoFocus?: boolean
}) {
  const cls = size === "lg" ? "size-11 text-base" : "size-10"
  return (
    <InputOTP
      maxLength={6}
      value={value}
      onChange={(v) => {
        onChange(v)
        if (v.length === 6) onComplete?.(v)
      }}
      autoFocus={autoFocus}
    >
      <InputOTPGroup>
        {[0, 1, 2].map((i) => (
          <InputOTPSlot key={i} index={i} className={cls} />
        ))}
      </InputOTPGroup>
      <InputOTPSeparator />
      <InputOTPGroup>
        {[3, 4, 5].map((i) => (
          <InputOTPSlot key={i} index={i} className={cls} />
        ))}
      </InputOTPGroup>
    </InputOTP>
  )
}

export function TotpEnroll<T>({
  startUrl,
  confirmUrl,
  onDone,
  started: given,
}: {
  startUrl: string
  confirmUrl: string
  onDone: (res: T) => void
  /** already started by the caller (e.g. after asking for the password) – not started again here */
  started?: { secret: string; uri: string }
}) {
  const { t } = useTranslation()
  const [data, setData] = useState<{ secret: string; uri: string } | null>(given ?? null)
  const [code, setCode] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const started = useRef(false)

  useEffect(() => {
    if (started.current || given) return // StrictMode runs effects twice; one pending secret per enrolment
    started.current = true
    api.post<{ secret: string; uri: string }>(startUrl).then(setData, (e) => setError(errorText(t, e)))
  }, [startUrl, t, given])

  const confirm = async (c = code) => {
    setBusy(true)
    setError(null)
    try {
      onDone(await api.post<T>(confirmUrl, { code: c }))
    } catch (e) {
      setError(errorText(t, e))
      setCode("")
    } finally {
      setBusy(false)
    }
  }

  if (!data) return error ? <p className="text-sm text-destructive">{error}</p> : <Loader2 className="size-5 animate-spin text-muted-foreground" />
  return (
    <div className="grid items-center gap-8 sm:grid-cols-[auto_1fr]">
      <div className="mx-auto rounded-xl border bg-white p-3">
        <QRCode value={data.uri} size={156} />
      </div>
      <div className="space-y-4">
        <ol className="list-decimal space-y-1.5 pl-4 text-sm text-muted-foreground">
          <li>{t("setup.mfaStep1")}</li>
          <li>{t("setup.mfaStep2")}</li>
          <li>{t("setup.mfaStep3")}</li>
        </ol>
        <div className="rounded-lg bg-muted/60 px-3 py-2 text-xs">
          <span className="text-muted-foreground">{t("setup.manualKey")}: </span>
          <span className="font-mono tracking-wider break-all">{data.secret.replace(/(.{4})/g, "$1 ").trim()}</span>
        </div>
        <CodeInput value={code} onChange={setCode} onComplete={(v) => void confirm(v)} />
        {error && <p className="text-sm text-destructive">{error}</p>}
        <Button onClick={() => void confirm()} disabled={code.length < 6 || busy}>
          {busy && <Loader2 className="animate-spin" />} {t("auth.verify")}
        </Button>
      </div>
    </div>
  )
}
