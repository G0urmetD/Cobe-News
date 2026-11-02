import i18n, { type BackendModule } from "i18next"
import { initReactI18next } from "react-i18next"

const stored = (() => {
  try {
    return localStorage.getItem("cobe-news.lang")
  } catch {
    return null
  }
})()

// Each language is its own chunk: only the one in use is loaded (the other when somebody switches – i18next waits for it).
const bundles: Record<string, () => Promise<{ default: Record<string, string> }>> = { de: () => import("./de"), en: () => import("./en") }
const lazyBundles: BackendModule = {
  type: "backend",
  init: () => undefined,
  read: (lng, _ns, done) => {
    const load = bundles[lng]
    if (!load) return done(null, {})
    load().then(
      (m) => done(null, m.default),
      (e: Error) => done(e, null),
    )
  },
}

export const i18nReady = i18n
  .use(lazyBundles)
  .use(initReactI18next)
  .init({
    lng: stored === "en" ? "en" : "de",
    supportedLngs: ["de", "en"],
    fallbackLng: false,
    load: "languageOnly",
    interpolation: { escapeValue: false },
    keySeparator: false,
    nsSeparator: false,
    react: { useSuspense: false },
  })

if (typeof document !== "undefined") document.documentElement.lang = i18n.language
i18n.on("languageChanged", (lng) => {
  if (typeof document !== "undefined") document.documentElement.lang = lng
  try {
    localStorage.setItem("cobe-news.lang", lng)
  } catch {
    /* ignore */
  }
})

export default i18n
