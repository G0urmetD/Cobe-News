import { api } from "@/lib/api"
import type { MyTeams } from "@/lib/teams-api"

// ---------------------------------------------------------------- An mein Team weiterleiten (backend: app/forward.py)

/** The comment's limit – the server refuses more (and counts after trimming). */
export const COMMENT_MAX = 1000

/** A story, or a finding of a followed product – never a target: where it goes is the team's channel (an admin's choice). */
export type ForwardThing = { story_id: string } | { product: string; finding: string }

export interface ForwardIn {
  team_id: string
  comment: string
  lang: "de" | "en"
}

export const forwardTo = (body: ForwardIn & ForwardThing) => api.post<{ ok: boolean; team: string }>("/api/forward", body)

/**
 * What the button shows: hidden (Teams off, or in no team – nowhere to forward to), off (no team of the person has a
 * channel – the tooltip says why), or ready with the teams that can receive (the select only with more than one).
 */
export type ForwardState = { state: "hidden" } | { state: "off" } | { state: "ready"; teams: { id: string; name: string }[] }

export function forwardState(mine: MyTeams | undefined): ForwardState {
  if (!mine?.enabled || mine.teams.length === 0) return { state: "hidden" }
  const teams = mine.teams.filter((t) => t.forward)
  return teams.length ? { state: "ready", teams } : { state: "off" }
}
