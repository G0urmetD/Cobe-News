import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react"

/**
 * Light / dark / system theme – a few lines instead of next-themes, which renders an inline <script> meant for server
 * rendering (React warns about it in this client-only app, and the CSP would block it anyway). The class on <html>
 * is set before the first render, so there is no flash of the wrong theme.
 */

export type Theme = "light" | "dark" | "system"
type Resolved = "light" | "dark"

const KEY = "cobe-news.theme"
const media = () => (typeof window !== "undefined" && window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null)

function stored(): Theme {
  try {
    const v = localStorage.getItem(KEY)
    return v === "dark" || v === "light" || v === "system" ? v : "light"
  } catch {
    return "light" // private mode, blocked storage
  }
}

const resolve = (t: Theme): Resolved => (t === "system" ? (media()?.matches ? "dark" : "light") : t)

function apply(r: Resolved) {
  const root = document.documentElement
  // no colour transitions while switching: everything changes at once (index.css: .theme-switching – a class, no
  // <style> element: the CSP allows none)
  root.classList.add("theme-switching")
  root.classList.remove("light", "dark")
  root.classList.add(r)
  root.style.colorScheme = r
  void window.getComputedStyle(document.body).opacity // force the style recalculation before re-enabling transitions
  setTimeout(() => root.classList.remove("theme-switching"), 1)
}

if (typeof document !== "undefined") apply(resolve(stored()))

interface ThemeState {
  theme: Theme
  resolvedTheme: Resolved
  setTheme: (t: string) => void
}

const Ctx = createContext<ThemeState>({ theme: "light", resolvedTheme: "light", setTheme: () => {} })

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(stored)
  const [systemDark, setSystemDark] = useState(() => !!media()?.matches)
  const resolvedTheme: Resolved = theme === "system" ? (systemDark ? "dark" : "light") : theme

  useEffect(() => {
    const m = media()
    if (!m) return
    const on = (e: MediaQueryListEvent) => setSystemDark(e.matches)
    m.addEventListener("change", on)
    return () => m.removeEventListener("change", on)
  }, [])

  useEffect(() => apply(resolvedTheme), [resolvedTheme])

  // another tab changed it
  useEffect(() => {
    const on = (e: StorageEvent) => e.key === KEY && setThemeState(stored())
    window.addEventListener("storage", on)
    return () => window.removeEventListener("storage", on)
  }, [])

  const setTheme = useCallback((t: string) => {
    if (t !== "light" && t !== "dark" && t !== "system") return
    setThemeState(t)
    try {
      localStorage.setItem(KEY, t)
    } catch {
      /* private mode */
    }
  }, [])

  const value = useMemo(() => ({ theme, resolvedTheme, setTheme }), [theme, resolvedTheme, setTheme])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export const useTheme = () => useContext(Ctx)
