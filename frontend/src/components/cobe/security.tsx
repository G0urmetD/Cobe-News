import type { TFunction } from "i18next"
import { useTranslation } from "react-i18next"
import { AlertTriangle, Fingerprint, KeyRound, LogOut, Monitor, Pencil, Smartphone, Trash2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill } from "@/components/cobe/badges"
import { Ts } from "@/components/cobe/time"
import { ApiError } from "@/lib/api"
import { errorText } from "@/lib/errors"
import type { Passkey, SessionRow } from "@/lib/security-api"
import { parseUserAgent } from "@/lib/user-agent"
import { PasskeyError } from "@/lib/webauthn"

/** "Chrome auf Windows" – or "Unbekanntes Gerät" when the User-Agent says nothing clear. */
export function deviceLabel(t: TFunction, ua: string | null | undefined): string {
  const d = parseUserAgent(ua)
  if (d.browser && d.os) return t("security.device", { browser: d.browser, os: d.os })
  return d.browser ?? d.os ?? t("security.unknownDevice")
}

/** A first name for a new passkey: the device it is made on. */
export function suggestedPasskeyName(t: TFunction): string {
  const d = parseUserAgent(typeof navigator !== "undefined" ? navigator.userAgent : "")
  return d.browser && d.os ? t("security.device", { browser: d.browser, os: d.os }) : t("passkey.defaultName")
}

/** Errors of a passkey ceremony – the browser's (cancelled, exists …) and the server's. */
export function passkeyErrorText(t: TFunction, e: unknown): string {
  if (e instanceof PasskeyError) return t(`passkey.err.${e.code}`)
  if (e instanceof ApiError && e.code === "passkey_invalid") return t("errors.passkey_invalid")
  if (e instanceof ApiError && e.code === "passkey_unavailable")
    return t(`passkey.unavailable.${String(e.data.reason ?? "bad_host")}`, { defaultValue: t("errors.passkey_unavailable") })
  if (e instanceof ApiError && e.code === "too_many_attempts") return t("passkey.err.tooMany")
  return errorText(t, e)
}

export function PasskeyList({ items, onRename, onRemove, empty }: { items: Passkey[]; onRename?: (p: Passkey) => void; onRemove: (p: Passkey) => void; empty: string }) {
  const { t } = useTranslation()
  if (!items.length) return <p className="px-5 py-4 text-sm text-muted-foreground">{empty}</p>
  return (
    <ul className="divide-y">
      {items.map((p) => (
        <li key={p.id} className="flex flex-wrap items-center gap-3 px-5 py-3">
          <Fingerprint className="size-4 shrink-0 text-muted-foreground" />
          <div className="min-w-0 flex-1 basis-[calc(100%-3rem)] sm:basis-0">
            <p className="flex flex-wrap items-center gap-1.5 text-sm font-medium">
              <span className="min-w-0 [overflow-wrap:anywhere]">{p.name}</span>
              {p.sign_count_warning_at && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span tabIndex={0} className="inline-flex">
                      <Pill color="--warning">
                        <AlertTriangle /> {t("passkey.cloneWarning")}
                      </Pill>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs leading-relaxed">{t("passkey.cloneWarningText")}</TooltipContent>
                </Tooltip>
              )}
            </p>
            <p className="text-xs text-muted-foreground [overflow-wrap:anywhere]">
              {t("passkey.created")} <Ts at={p.created_at} rel /> ·{" "}
              {p.last_used_at ? (
                <>
                  {t("passkey.lastUsed")} <Ts at={p.last_used_at} rel />
                </>
              ) : (
                t("passkey.neverUsed")
              )}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-1 pl-7 sm:pl-0">
            {onRename && (
              <Button variant="ghost" size="sm" onClick={() => onRename(p)}>
                <Pencil /> {t("passkey.rename")}
              </Button>
            )}
            <Button variant="ghost" size="sm" onClick={() => onRemove(p)}>
              <Trash2 /> {t("common.remove")}
            </Button>
          </div>
        </li>
      ))}
    </ul>
  )
}

function methodText(t: TFunction, s: SessionRow): string {
  if (!s.method) return t("security.method.unknown")
  if (s.method === "passkey" && s.passkey) return t("security.method.passkeyNamed", { name: s.passkey })
  return t(`security.method.${s.method}`)
}

export function SessionList({ rows, onEnd, busy }: { rows: SessionRow[]; onEnd: (s: SessionRow) => void; busy?: string | null }) {
  const { t } = useTranslation()
  return (
    <ul className="divide-y">
      {rows.map((s) => {
        const d = parseUserAgent(s.user_agent)
        const Icon = d.mobile ? Smartphone : Monitor
        return (
          <li key={s.id} className="flex flex-wrap items-center gap-3 px-5 py-3">
            <Icon className="size-4 shrink-0 text-muted-foreground" />
            <div className="min-w-0 flex-1 basis-[calc(100%-3rem)] sm:basis-0">
              <p className="flex flex-wrap items-center gap-1.5 text-sm font-medium">
                <span className="min-w-0 [overflow-wrap:anywhere]">{deviceLabel(t, s.user_agent)}</span>
                {s.current && <Pill color="--primary">{t("security.thisSession")}</Pill>}
                {s.stage !== "active" && (
                  <Pill color="--warning" title={t("security.pendingHint")}>
                    {t("security.pending")}
                  </Pill>
                )}
              </p>
              <p className="text-xs text-muted-foreground [overflow-wrap:anywhere]">
                <span className="inline-flex items-center gap-1">
                  <KeyRound className="size-3" /> {methodText(t, s)}
                </span>
                {s.ip && (
                  <>
                    {" · "}
                    <span className="font-mono">{s.ip}</span>
                  </>
                )}
              </p>
              <p className="text-xs text-muted-foreground">
                {t("security.signedIn")} <Ts at={s.created_at} rel /> · {t("security.lastActive")} <Ts at={s.last_seen_at} rel />
              </p>
            </div>
            {!s.current && (
              <div className="shrink-0 pl-7 sm:pl-0">
                <Button variant="ghost" size="sm" disabled={busy === s.id} onClick={() => onEnd(s)}>
                  <LogOut /> {t("security.endOne")}
                </Button>
              </div>
            )}
          </li>
        )
      })}
    </ul>
  )
}
