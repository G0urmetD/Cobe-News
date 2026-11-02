import { useEffect, useRef, useState, useSyncExternalStore } from "react"
import { useTranslation } from "react-i18next"
import { useLocation, useNavigate } from "react-router"
import { Loader2, ShieldCheck } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Field } from "@/components/cobe/form"
import { api } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { errorText } from "@/lib/errors"
import { focusFieldOnOpen } from "@/lib/focus"
import { type ReauthAsk, closeReauth as close, coversPrompt, entraReauthUrl, reauthStore } from "@/lib/reauth"

/** The question of lib/reauth.ts withReauth: who is at the keyboard (password + code, or Microsoft's sign-in). Mounted
 *  once next to the app. */
export function ReauthHost() {
  const req = useSyncExternalStore(reauthStore.subscribe, reauthStore.get)
  useReturnedError()
  return req ? <ReauthPrompt key={req.id} req={req} /> : null
}

/**
 * A failed confirmation at Microsoft comes back as /?login_error=… (like a failed sign-in). Signed out, the sign-in page
 * shows it; signed in – an Entra admin's re-confirmation – it is shown here as a toast, then gone from the address.
 */
function useReturnedError() {
  const { t } = useTranslation()
  const signedIn = !!useAuth().user
  const { pathname, search, hash } = useLocation()
  const navigate = useNavigate()
  useEffect(() => {
    if (!signedIn) return
    const params = new URLSearchParams(search)
    const code = params.get("login_error")
    if (code === null) return
    params.delete("login_error")
    const q = params.toString()
    navigate({ pathname, search: q ? `?${q}` : "", hash }, { replace: true })
    // the user comes from /api/auth/state after the first draw – the toaster is there by then
    if (/^[a-z_]{3,40}$/.test(code)) toast.error(t("reauth.failed"), { description: t(`errors.${code}`, { defaultValue: t("errors.generic") }), duration: 30_000 })
  }, [signedIn, pathname, search, hash, navigate, t])
}

type FormState = { password: string; code: string; busy: boolean; error: string | null }

/**
 * One question. It is always the topmost layer: its own level above the drawers and dialogs (z-60/61 – Radix places
 * everything else at z-50, in the order it mounts), and when a drawer or dialog still mounts after it, it is drawn
 * again as the last layer (coversPrompt) – what was typed stays, it lives here, outside the dialog.
 */
function ReauthPrompt({ req }: { req: ReauthAsk }) {
  const [form, setForm] = useState<FormState>({ password: "", code: "", busy: false, error: null })
  const [round, setRound] = useState(0)
  const lastField = useRef<string | null>(null) // drawn anew: the focus goes back where it was
  useEffect(() => {
    let raised = 0
    const watch = new MutationObserver((records) => {
      const prompt = document.querySelector("[data-reauth-prompt]")
      if (!prompt || raised >= 10) return // 10: never a loop with something that always mounts again
      if (records.some((r) => [...r.addedNodes].some((n) => coversPrompt(prompt, n)))) {
        raised += 1
        setRound((x) => x + 1)
      }
    })
    watch.observe(document.body, { childList: true })
    return () => watch.disconnect()
  }, [])
  return (
    <Dialog key={round} open onOpenChange={(o) => !o && close(false)}>
      <DialogContent data-reauth-prompt="" className="z-[61] sm:max-w-md" overlayClassName="z-[60]" onOpenAutoFocus={(e) => focusFieldOnOpen(e, lastField.current)}>
        <ReauthForm req={req} form={form} setForm={setForm} onFieldFocus={(id) => (lastField.current = id)} />
      </DialogContent>
    </Dialog>
  )
}

function ReauthForm({
  req,
  form,
  setForm,
  onFieldFocus,
}: {
  req: ReauthAsk
  form: FormState
  setForm: React.Dispatch<React.SetStateAction<FormState>>
  onFieldFocus: (id: string) => void
}) {
  const { t } = useTranslation()
  const { password, code, busy, error } = form
  const patch = (p: Partial<FormState>) => setForm((f) => ({ ...f, ...p }))
  if (req.via === "entra") {
    const toMicrosoft = () => window.location.assign(entraReauthUrl(window.location.pathname + window.location.search))
    // with the own TOTP set up: its code first (noted on the session for a few minutes), then Microsoft – the token
    // alone proves no second factor unless Entra says so (MFA-Nachweis)
    const sendCode = async () => {
      patch({ busy: true, error: null })
      try {
        await api.post("/api/auth/reauth", { code })
        toMicrosoft()
      } catch (e) {
        patch({ error: errorText(t, e), code: "", busy: false })
      }
    }
    return (
      <form
        className="space-y-4"
        onFocus={(e) => e.target instanceof HTMLInputElement && onFieldFocus(e.target.id)}
        onSubmit={(e) => {
          e.preventDefault()
          if (busy) return
          if (!req.totp) toMicrosoft()
          else if (/^\d{6}$/.test(code)) void sendCode()
        }}
      >
        <DialogHeader>
          <DialogTitle>{t("reauth.title")}</DialogTitle>
          <DialogDescription>{req.totp ? t("reauth.entraCodeText") : t("reauth.entraText")}</DialogDescription>
        </DialogHeader>
        {req.totp && (
          <Field label={t("account.reauthCode")} htmlFor="reauth-code">
            <Input
              id="reauth-code"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              value={code}
              onChange={(e) => patch({ code: e.target.value.replace(/\D/g, "").slice(0, 6) })}
              className="font-mono tracking-widest"
            />
          </Field>
        )}
        {error && <p className="text-sm text-destructive">{error}</p>}
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => close(false)}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" disabled={busy || (req.totp && !/^\d{6}$/.test(code))}>
            {busy ? <Loader2 className="animate-spin" /> : <ShieldCheck />} {t("reauth.entraDo")}
          </Button>
        </DialogFooter>
      </form>
    )
  }
  const ready = !!password && (!req.totp || /^\d{6}$/.test(code))
  const send = async () => {
    patch({ busy: true, error: null })
    try {
      await api.post("/api/auth/reauth", req.totp ? { password, code } : { password })
      close(true)
    } catch (e) {
      patch({ error: errorText(t, e), code: "" })
    } finally {
      patch({ busy: false })
    }
  }
  return (
    <form
      className="space-y-4"
      onFocus={(e) => e.target instanceof HTMLInputElement && onFieldFocus(e.target.id)}
      onSubmit={(e) => {
        e.preventDefault()
        if (ready && !busy) void send()
      }}
    >
      <DialogHeader>
        <DialogTitle>{t("reauth.title")}</DialogTitle>
        <DialogDescription>{t("reauth.text")}</DialogDescription>
      </DialogHeader>
      <Field label={t("account.currentPassword")} htmlFor="reauth-pw">
        <Input id="reauth-pw" type="password" autoComplete="current-password" value={password} onChange={(e) => patch({ password: e.target.value })} />
      </Field>
      {req.totp && (
        <Field label={t("account.reauthCode")} htmlFor="reauth-code">
          <Input
            id="reauth-code"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            value={code}
            onChange={(e) => patch({ code: e.target.value.replace(/\D/g, "").slice(0, 6) })}
            className="font-mono tracking-widest"
          />
        </Field>
      )}
      {error && <p className="text-sm text-destructive">{error}</p>}
      <DialogFooter>
        <Button type="button" variant="ghost" onClick={() => close(false)}>
          {t("common.cancel")}
        </Button>
        <Button type="submit" disabled={!ready || busy}>
          {busy && <Loader2 className="animate-spin" />} {t("reauth.confirm")}
        </Button>
      </DialogFooter>
    </form>
  )
}
