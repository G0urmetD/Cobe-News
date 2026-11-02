import { useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { api } from "@/lib/api"

type I18nText = { de: string; en: string }

/** What the catalogue data says beyond the products (GET /api/vendor/catalog/meta): its version, the categories in
 *  display order and the texts products refer to. They come with the catalogue (backend/app/catalog), not with the UI. */
export interface CatalogMeta {
  catalog_version: string
  categories: { key: string; icon: string; label: I18nText }[]
  texts: { hints: Record<string, I18nText>; where: Record<string, I18nText> }
}

export interface CatalogTexts {
  version: string | null
  categories: { key: string; icon: string; label: string }[]
  /** a category's label (its key until the data is there) */
  cat: (key: string) => string
  icon: (key: string) => string | undefined
  /** a hint shown with a product ("" when unknown or not loaded yet) */
  hint: (key: string | null | undefined) => string
  /** where the version of a product is read ("" when unknown) */
  where: (key: string | null | undefined) => string
}

export function catalogTexts(meta: CatalogMeta | undefined, language: string): CatalogTexts {
  const lang: keyof I18nText = language.startsWith("en") ? "en" : "de"
  const cats = new Map((meta?.categories ?? []).map((c) => [c.key, c]))
  const pick = (x: I18nText | undefined) => (x ? x[lang] || x.de : "")
  return {
    version: meta?.catalog_version ?? null,
    categories: (meta?.categories ?? []).map((c) => ({ key: c.key, icon: c.icon, label: pick(c.label) })),
    cat: (key) => pick(cats.get(key)?.label) || key,
    icon: (key) => cats.get(key)?.icon,
    hint: (key) => (key ? pick(meta?.texts.hints[key]) : ""),
    where: (key) => (key ? pick(meta?.texts.where[key]) : ""),
  }
}

/** The catalogue data changes only with the image: fetched once per page load. */
export const useCatalogMeta = () =>
  useQuery({ queryKey: ["vendor", "catalog-meta"], queryFn: () => api.get<CatalogMeta>("/api/vendor/catalog/meta"), staleTime: Infinity, gcTime: Infinity })

export function useCatalogTexts(): CatalogTexts {
  const { i18n } = useTranslation()
  const q = useCatalogMeta()
  return useMemo(() => catalogTexts(q.data, i18n.language), [q.data, i18n.language])
}
