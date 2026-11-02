import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"

/** A ## / ### heading of a chapter – admin: only admins get it (readers never receive it from the server). */
export type DocSection = { id: string; title: string; level: number; admin: boolean }

/** One chapter of the handbook as this person may read it (backend/app/docs.py) – lang: the language it is written in
 * (German when it is missing in the asked one). */
export type DocChapter = { id: string; title: string; summary: string; audience: "all" | "admin"; lang: string; sections: DocSection[]; markdown: string }

/** live: values of this installation the text may show ({{base_url}} …) – never secrets. */
export type Docs = { lang: string; chapters: DocChapter[]; live: Record<string, string> }

export const docsLang = (language: string | undefined) => (language === "en" ? "en" : "de")

/** Every chapter this person may read, in the UI language – the build's handbook does not change while it runs. */
export function useDocs(lang: string) {
  return useQuery({ queryKey: ["docs", lang], queryFn: () => api.get<Docs>(`/api/docs?lang=${encodeURIComponent(lang)}`), staleTime: Infinity })
}

/** The address of a section of the handbook – for the "Hilfe" links of the settings. */
export function docPath(chapter: string, section?: string): string {
  return `/docs/${chapter}${section ? `#${section}` : ""}`
}

/** The DOM id of a section heading – prefixed, so a section id never collides with another element of the app. */
export const sectionDomId = (id: string) => `doc-${id}`
