import { useTranslation } from "react-i18next"
import { Languages, Moon, Sun } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Logo } from "@/components/cobe/common"
import { useTheme } from "@/lib/theme"

const BRAND = "#4a6fa5"

/**
 * Sign-in frame: a plain brand panel with only the mark on the left (wide screens), the form on the right. No claims,
 * no decoration – the page has one job. Buttons and focus rings take the brand colour here.
 */
export function AuthLayout({ children, wide = false }: { children: React.ReactNode; wide?: boolean }) {
  const { t, i18n } = useTranslation()
  const { resolvedTheme, setTheme } = useTheme()
  return (
    <div className="grid min-h-svh lg:grid-cols-[minmax(320px,38%)_minmax(0,1fr)]">
      <aside className="hidden items-center justify-center bg-[#dae8fc] lg:flex dark:bg-[#1b2a40]">
        <img src="/mark-large.svg" alt="Cobe News" className="size-44 select-none" draggable={false} />
      </aside>
      <div className="flex flex-col" style={{ "--primary": BRAND, "--primary-foreground": "#fff", "--ring": BRAND } as React.CSSProperties}>
        <div className="flex items-center justify-between p-4 lg:justify-end">
          <Logo className="lg:hidden" />
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="sm" onClick={() => void i18n.changeLanguage(i18n.language === "de" ? "en" : "de")}>
              <Languages /> {i18n.language === "de" ? "English" : "Deutsch"}
            </Button>
            <Button variant="ghost" size="icon" aria-label={t("shell.theme")} onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}>
              {resolvedTheme === "dark" ? <Sun /> : <Moon />}
            </Button>
          </div>
        </div>
        <div className="flex flex-1 items-center justify-center px-4 pb-16">
          <div className={wide ? "w-full max-w-2xl" : "w-full max-w-sm"}>{children}</div>
        </div>
      </div>
    </div>
  )
}
