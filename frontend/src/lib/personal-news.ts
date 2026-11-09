import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import type { NewsSeverity, NewsTopic } from "@/lib/news-api"
import type { RuleSystem } from "@/lib/rule-filters"
import type { WayState } from "@/lib/teams-api"

// ---------------------------------------------------------------- "Security-Meldungen per E-Mail/Teams" (app/personal_news_api.py)

export interface PersonalNews {
  available: boolean
  /** why not: Teams off, or an admin has not allowed it (or neither of its ways) */
  reason: "teams_off" | "news_off" | null
  allowed: { email: boolean; teams: boolean }
  lang: "de" | "en"
  severities: NewsSeverity[]
  sources: string[]
  topics: NewsTopic[]
  systems: RuleSystem[]
  keywords: string[]
  exclude: string[]
  email: { on: boolean; address: string | null; address_ok: boolean; state: WayState }
  teams: { on: boolean; url_set: boolean; url_hint: string | null; state: WayState }
}

export const PERSONAL_NEWS_KEY = ["me", "news-notify"] as const

export const usePersonalNews = (enabled = true) =>
  useQuery({ queryKey: PERSONAL_NEWS_KEY, queryFn: () => api.get<PersonalNews>("/api/me/news-notify"), enabled, staleTime: 30_000 })

/** What the form sends: the choice and the ways (the Teams URL only when a new one was typed). */
export function personalNewsBody(
  v: Pick<PersonalNews, "severities" | "sources" | "topics" | "systems" | "keywords" | "exclude"> & { email_on: boolean; teams_on: boolean },
  lang: string,
  url: string,
) {
  const out: Record<string, unknown> = {
    email_on: v.email_on,
    teams_on: v.teams_on,
    severities: v.severities,
    sources: v.sources,
    topics: v.topics,
    systems: v.systems,
    keywords: v.keywords,
    exclude: v.exclude,
    lang: lang === "en" ? "en" : "de",
  }
  if (url.trim()) out.teams_url = url.trim()
  return out
}
