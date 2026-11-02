import type { TFunction } from "i18next"
import { ApiError } from "@/lib/api"

/** Maps backend error codes to user-facing text. Unknown codes fall back to a generic message. */
export function errorText(t: TFunction, err: unknown): string {
  if (!(err instanceof ApiError)) return t("errors.generic")
  const d = err.data
  switch (err.code) {
    case "invalid_credentials":
      return typeof d.attempts_left === "number" && d.attempts_left > 0 ? t("auth.attemptsLeft", { count: d.attempts_left }) : t("errors.invalid_credentials")
    case "account_locked":
      return t("errors.account_locked", { minutes: Math.max(1, Math.ceil(Number(d.retry_after ?? 60) / 60)) })
    case "password_policy":
      return t("errors.password_policy", { rules: ((d.rules as string[]) ?? []).map((r) => t(`policy.${r}`, { defaultValue: r })).join(", ") })
    case "push_failed": {
      // the reason the server sends along: a category as for the channels ("timeout", "http" …), or "gone"
      const r = d.detail ? String(d.detail) : ""
      if (!r) return t("errors.push_failed")
      return t("errors.push_failed_reason", { reason: r === "gone" ? t("errors.push_gone") : t(`notify.err.${r}`, { defaultValue: r }) })
    }
    case "forward_failed": {
      // the team's channel did not take it: the category as for the channels ("timeout", "rejected" …)
      const r = d.detail ? String(d.detail) : ""
      return r ? t("errors.forward_failed_reason", { reason: t(`forward.err.${r}`, { defaultValue: t(`notify.err.${r}`, { defaultValue: r }) }) }) : t("errors.forward_failed")
    }
    case "forward_rate_limited":
    case "forward_duplicate":
    case "watch_rate_limited":
      return t(`errors.${err.code}`, { minutes: Math.max(1, Math.ceil(Number(d.retry_after ?? 60) / 60)) })
    case "directory_unavailable":
      return d.reason ? `${t("errors.directory_unavailable")} (${t(`dir.err.${String(d.reason)}`, { defaultValue: String(d.reason) })})` : t("errors.directory_unavailable")
    default: {
      const key = `errors.${err.code}`
      const text = t(key)
      return text === key ? t("errors.generic_code", { code: err.code }) : text
    }
  }
}

/** A save refused because another admin changed the same thing meanwhile (409 "stale"). */
export const isStale = (e: unknown) => e instanceof ApiError && e.code === "stale"
