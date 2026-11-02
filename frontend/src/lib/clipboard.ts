import { toast } from "sonner"
import i18n from "@/i18n"

/** No Clipboard API (plain HTTP) or a refusal is a failure too, not a silent success. */
export function copyText(value: string): Promise<void> {
  return navigator.clipboard ? navigator.clipboard.writeText(value) : Promise.reject(new Error("no clipboard"))
}

/** Copies and says how it went – "copied" only when it really was. */
export async function copyWithToast(value: string, success = i18n.t("common.copied")): Promise<boolean> {
  try {
    await copyText(value)
    toast.success(success)
    return true
  } catch {
    toast.error(i18n.t("time.copyFailed"))
    return false
  }
}
