import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import { Boxes, CalendarClock, FolderTree, Loader2, Newspaper, Plus, RefreshCw, Search, Settings2, Trash2, UserPlus, UsersRound, X } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Sheet } from "@/components/ui/sheet"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Pill } from "@/components/cobe/badges"
import { OffPill } from "@/components/cobe/off-pill"
import { confirmAction } from "@/components/cobe/confirm"
import { EmptyState, Section } from "@/components/cobe/common"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { Explained } from "@/components/cobe/explained"
import { EnableCard, Field, LockedFields, ToggleRow } from "@/components/cobe/form"
import { MultiSelect } from "@/components/cobe/multi-select"
import { SubTabs } from "@/components/cobe/sub-tabs"
import { Ts } from "@/components/cobe/time"
import { ApiError, api } from "@/lib/api"
import { type DirectoryGroup, useChannels, useMappings, useUsers } from "@/lib/admin-api"
import { errorText, isStale } from "@/lib/errors"
import { withReauth } from "@/lib/reauth"
import { confirmDiscard } from "@/lib/unsaved"
import {
  MEMBER_PAGE,
  type PersonRef,
  type Team,
  type TeamGroup,
  type TeamMemberRow,
  type TeamProduct,
  type TeamsSettings,
  groupStateKey,
  useTeamMembers,
  useTeamProducts,
  useTeams,
  useTeamsSettings,
} from "@/lib/teams-api"
import { IntegrationSheetContent, Loading, SaveBar, SettingsCard, SheetActions, SheetBody, SheetLoading } from "@/pages/settings-shared"
import { AbsenceEditor, AbsenceLine, TeamWeeklyPart } from "@/pages/settings-delivery"
import { isoList } from "@/lib/bidi"

type Part = "general" | "groups" | "members" | "products" | "weekly"
const PARTS: Part[] = ["general", "groups", "members", "products", "weekly"]

const refreshTeams = (qc: ReturnType<typeof useQueryClient>) => {
  void qc.invalidateQueries({ queryKey: ["admin", "teams"] })
  void qc.invalidateQueries({ queryKey: ["admin", "users"] })
  void qc.invalidateQueries({ queryKey: ["me", "teams"] })
}

/** Settings → Teams: the teams | the switch (sub-tabs, `?tab=settings`). */
export function TeamsSettingsPage() {
  const { t } = useTranslation()
  const [params, setParams] = useSearchParams()
  const tab = params.get("tab") === "settings" ? "settings" : "teams"
  return (
    <div className="space-y-6">
      <SubTabs
        parts={[
          { key: "teams" as const, icon: UsersRound, label: t("teams.tab.teams") },
          { key: "settings" as const, icon: Settings2, label: t("teams.tab.settings") },
        ]}
        active={tab}
        to={(k) => (k === "teams" ? "?" : "?tab=settings")}
        label={t("settings.nav.teams")}
      />
      {tab === "settings" ? <TeamsSwitch /> : <TeamsList onSettings={() => setParams({ tab: "settings" }, { replace: true })} />}
    </div>
  )
}

// ---------------------------------------------------------------- the switch

function TeamsSwitch() {
  const q = useTeamsSettings()
  if (!q.data) return <Loading error={q.error} onRetry={q.refetch} />
  return <TeamsSwitchForm key={JSON.stringify(q.data)} initial={q.data} />
}

function TeamsSwitchForm({ initial }: { initial: TeamsSettings }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [v, setV] = useState({
    enabled: initial.enabled,
    welcome_mail: initial.welcome_mail,
    personal_email: initial.personal_email,
    personal_desktop: initial.personal_desktop,
    personal_teams: initial.personal_teams,
  })
  const [busy, setBusy] = useState(false)
  const dirty = (Object.keys(v) as (keyof typeof v)[]).some((k) => v[k] !== initial[k])
  const save = async () => {
    setBusy(true)
    try {
      await withReauth(() => api.put("/api/admin/teams/settings", { ...v, rev: initial.rev }))
      toast.success(v.enabled && !initial.enabled ? t("teams.switch.onToast") : t("common.saved"))
      refreshTeams(qc)
    } catch (e) {
      toast.error(errorText(t, e))
      if (isStale(e)) refreshTeams(qc)
    } finally {
      setBusy(false)
    }
  }
  return (
    <SettingsCard title={t("teams.switch.title")} description={t("teams.switch.desc")} actions={<HelpLink chapter="anmeldung" section="teams" topic={t("settings.nav.teams")} />}>
      <SheetBody>
        <EnableCard label={t("teams.switch.enable")} description={t("teams.switch.enableHint")} checked={v.enabled} onCheckedChange={(x) => setV({ ...v, enabled: x })} />
        <LockedFields locked={!v.enabled}>
          <ToggleRow
            label={t("teams.switch.welcome")}
            description={t("teams.switch.welcomeHint", { url: initial.base_url })}
            checked={v.welcome_mail}
            onCheckedChange={(x) => setV({ ...v, welcome_mail: x })}
          />
          {v.welcome_mail && !initial.smtp_ready && <p className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">{t("teams.switch.noSmtp")}</p>}
          <section className="mt-2 rounded-lg border px-3" aria-labelledby="teams-personal">
            <div className="flex items-start justify-between gap-3 pt-3">
              <div className="min-w-0 space-y-0.5">
                <p id="teams-personal" className="text-sm font-medium">
                  {t("teams.personal.title")}
                </p>
                <p className="text-xs leading-relaxed text-muted-foreground">{t("teams.personal.desc")}</p>
              </div>
              <HelpLink chapter="anmeldung" section="teams-persoenlich" topic={t("teams.personal.title")} />
            </div>
            <div className="divide-y">
              <ToggleRow
                label={t("teams.personal.email")}
                description={t("teams.personal.emailHint")}
                checked={v.personal_email}
                onCheckedChange={(x) => setV({ ...v, personal_email: x })}
              />
              <ToggleRow
                label={t("teams.personal.desktop")}
                description={initial.web_push ? t("teams.personal.desktopHint") : t("teams.personal.desktopNoPush")}
                checked={v.personal_desktop}
                onCheckedChange={(x) => setV({ ...v, personal_desktop: x })}
              />
              <ToggleRow
                label={t("teams.personal.teams")}
                description={t("teams.personal.teamsHint")}
                checked={v.personal_teams}
                onCheckedChange={(x) => setV({ ...v, personal_teams: x })}
              />
            </div>
            {v.personal_email && !initial.smtp_ready && <p className="mb-3 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">{t("teams.personal.noSmtp")}</p>}
          </section>
        </LockedFields>
        <div className="space-y-1.5 rounded-lg bg-muted/60 p-3 text-xs leading-relaxed text-muted-foreground">
          <p>{t("teams.switch.role")}</p>
          <p>{t("teams.switch.entraPerm")}</p>
          {!initial.ldap_usable && !initial.entra_usable && <p className="text-warning">{t("teams.switch.noDirectory")}</p>}
        </div>
      </SheetBody>
      <SheetActions>
        <span className="text-xs text-muted-foreground">{v.enabled !== initial.enabled ? t("teams.switch.reauth") : ""}</span>
        <SaveBar busy={busy} dirty={dirty} onSave={() => void save()} />
      </SheetActions>
    </SettingsCard>
  )
}

// ---------------------------------------------------------------- the list

function TeamsList({ onSettings }: { onSettings: () => void }) {
  const { t } = useTranslation()
  const settings = useTeamsSettings()
  const q = useTeams()
  const [params, setParams] = useSearchParams()
  const open = params.get("team")
  const part = (PARTS as string[]).includes(params.get("part") ?? "") ? (params.get("part") as Part) : "general"
  const openTeam = (id: string | null, p: Part = "general") =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        if (id) {
          next.set("team", id)
          next.set("part", p)
        } else {
          next.delete("team")
          next.delete("part")
        }
        return next
      },
      { replace: !id },
    )
  if (!q.data || !settings.data) return <Loading error={q.error ?? settings.error} onRetry={() => void Promise.all([q.refetch(), settings.refetch()])} />
  const team = open && open !== "new" ? (q.data.find((x) => x.id === open) ?? null) : null
  return (
    <>
      {!settings.data.enabled && (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-primary/40 bg-primary/5 p-3 text-sm">
          <span className="min-w-0 flex-1">{t("teams.offNotice")}</span>
          <Button size="sm" variant="outline" onClick={onSettings}>
            <Settings2 /> {t("teams.toSettings")}
          </Button>
        </div>
      )}
      <Section
        title={t("teams.title")}
        description={t("teams.hint")}
        actions={
          <>
            <HelpLink chapter="anmeldung" section="teams" topic={t("teams.title")} />
            <Button size="sm" onClick={() => openTeam("new")}>
              <Plus /> {t("teams.create")}
            </Button>
          </>
        }
      >
        {q.data.length === 0 ? (
          <div className="p-5">
            <EmptyState icon={UsersRound} title={t("teams.emptyTitle")} text={t("teams.emptyText")} />
          </div>
        ) : (
          <ul className="divide-y">
            {q.data.map((x) => (
              <li key={x.id}>
                <button type="button" onClick={() => openTeam(x.id)} className="flex w-full items-start gap-3 px-5 py-3 text-left hover:bg-muted/40">
                  <span className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <UsersRound className="size-4" />
                  </span>
                  <span className="min-w-0 flex-1 space-y-1">
                    <span className="block text-sm font-medium [overflow-wrap:anywhere]">{x.name}</span>
                    {x.description && <span className="block text-xs text-muted-foreground [overflow-wrap:anywhere]">{x.description}</span>}
                    <span className="flex flex-wrap gap-1">
                      <Pill color="--muted-foreground">{t("teams.count.groups", { count: x.groups.length })}</Pill>
                      <Pill color="--muted-foreground">{t("teams.count.members", { count: x.members.group + x.members.manual })}</Pill>
                      <Pill color="--muted-foreground">{t("teams.count.products", { count: x.products.length })}</Pill>
                      {x.groups.some((g) => g.state === "loading") && (
                        <Pill color="--primary">
                          <Loader2 className="animate-spin" /> {t("teams.group.state.loading")}
                        </Pill>
                      )}
                      {x.groups.some((g) => g.state === "error") && <Pill color="--warning">{t("teams.groupError")}</Pill>}
                    </span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Sheet open={!!open} onOpenChange={(o) => !o && void confirmDiscard().then((ok) => ok && openTeam(null))}>
        <IntegrationSheetContent
          icon={UsersRound}
          title={team ? team.name : t("teams.create")}
          description={t("teams.sheetDesc")}
          help={{ chapter: "anmeldung", section: "teams" }}
        >
          {open === "new" ? (
            <GeneralPart team={null} onDone={(id) => (id ? openTeam(id, "groups") : openTeam(null))} />
          ) : !team ? (
            <SheetLoading />
          ) : (
            <TeamParts team={team} part={part} settings={settings.data} onPart={(p) => openTeam(team.id, p)} onClose={() => openTeam(null)} />
          )}
        </IntegrationSheetContent>
      </Sheet>
    </>
  )
}

function TeamParts({ team, part, settings, onPart, onClose }: { team: Team; part: Part; settings: TeamsSettings; onPart: (p: Part) => void; onClose: () => void }) {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const to = (k: Part) => {
    const next = new URLSearchParams(params)
    next.set("part", k)
    return `?${next.toString()}`
  }
  return (
    <>
      <div className="border-b px-4 py-2">
        <SubTabs
          parts={[
            { key: "general" as const, icon: Settings2, label: t("teams.part.general") },
            { key: "groups" as const, icon: FolderTree, label: t("teams.part.groups"), count: team.groups.length, alert: team.groups.some((g) => g.state === "error") },
            { key: "members" as const, icon: UsersRound, label: t("teams.part.members"), count: team.members.group + team.members.manual },
            { key: "products" as const, icon: Boxes, label: t("teams.part.products"), count: team.products.length },
            { key: "weekly" as const, icon: Newspaper, label: t("delivery.part.weekly") },
          ]}
          active={part}
          to={to}
          label={t("teams.parts")}
        />
      </div>
      {part === "groups" ? (
        <GroupsPart team={team} settings={settings} onMembers={() => onPart("members")} />
      ) : part === "members" ? (
        <MembersPart team={team} settings={settings} />
      ) : part === "weekly" ? (
        <TeamWeeklyPart key={JSON.stringify(team.weekly)} team={team} settings={settings} />
      ) : part === "products" ? (
        <ProductsPart key={team.products.map((p) => `${p.key}:${p.all_members}:${p.people.map((x) => x.id).join(",")}`).join("|")} team={team} />
      ) : (
        <GeneralPart key={team.version} team={team} onDone={(id) => (id ? undefined : onClose())} />
      )}
    </>
  )
}

// ---------------------------------------------------------------- general: name, description, forward channel, delete

const NO_CHANNEL = "none"

function GeneralPart({ team, onDone }: { team: Team | null; onDone: (id: string | null) => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const channels = useChannels()
  const [v, setV] = useState({ name: team?.name ?? "", description: team?.description ?? "", forward: team?.forward_channel_id ?? NO_CHANNEL })
  const [busy, setBusy] = useState(false)
  const valid = v.name.trim().length >= 2
  const dirty = v.name !== (team?.name ?? "") || v.description !== (team?.description ?? "") || v.forward !== (team?.forward_channel_id ?? NO_CHANNEL)
  const save = async () => {
    setBusy(true)
    try {
      const body = { name: v.name.trim(), description: v.description.trim() }
      if (team) {
        const forward = v.forward === NO_CHANNEL ? null : v.forward
        await api.patch(`/api/admin/teams/${team.id}`, { ...body, forward_channel_id: forward, version: team.version })
        toast.success(t("common.saved"))
      } else {
        const r = await api.post<Team>("/api/admin/teams", body)
        toast.success(t("teams.created", { name: r.name }))
        refreshTeams(qc)
        onDone(r.id)
        return
      }
      refreshTeams(qc)
    } catch (e) {
      toast.error(errorText(t, e))
      if (isStale(e)) refreshTeams(qc)
    } finally {
      setBusy(false)
    }
  }
  const remove = async () => {
    if (!team) return
    if (team.rules.length) {
      toast.error(t("errors.team_in_rules_named", { rules: isoList(team.rules) }))
      return
    }
    if (!(await confirmAction({ title: t("teams.deleteTitle"), text: t("teams.deleteText", { name: team.name }), confirm: t("common.remove") }))) return
    try {
      await withReauth(() => api.del(`/api/admin/teams/${team.id}`))
      refreshTeams(qc)
      onDone(null)
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  return (
    <>
      <SheetBody>
        <Field label={t("teams.name")}>
          <Input value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} placeholder={t("teams.namePlaceholder")} maxLength={80} autoFocus={!team} />
        </Field>
        <Field label={t("teams.description")} hint={t("teams.descriptionHint")}>
          <Textarea value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} maxLength={500} rows={2} />
        </Field>
        {team && (
          // "An mein Team weiterleiten": where a member's forward goes – one of the existing channels, chosen here only
          <Field label={<Explained label={t("teams.forward")} text={t("teams.forwardHelp")} />} hint={t("teams.forwardHint")}>
            <Select value={v.forward} onValueChange={(x) => setV({ ...v, forward: x })}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value={NO_CHANNEL}>{t("teams.forwardNone")}</SelectItem>
                {(channels.data ?? []).map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.name} · {t(`notify.channel.${c.type}`, { defaultValue: c.type })}
                  </SelectItem>
                ))}
                {/* a channel the list does not have (yet): still shown as chosen */}
                {v.forward !== NO_CHANNEL && channels.data && !channels.data.some((c) => c.id === v.forward) && (
                  <SelectItem value={v.forward}>{t("teams.forwardUnknown")}</SelectItem>
                )}
              </SelectContent>
            </Select>
          </Field>
        )}
        {!team && <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("teams.createNext")}</p>}
        {team && team.rules.length > 0 && <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("teams.usedByRules", { rules: isoList(team.rules) })}</p>}
      </SheetBody>
      <SheetActions>
        {team ? (
          <Button variant="ghost" className="text-destructive" onClick={() => void remove()}>
            <Trash2 /> {t("teams.delete")}
          </Button>
        ) : (
          <span />
        )}
        <SaveBar busy={busy} dirty={dirty} disabled={!valid} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}

// ---------------------------------------------------------------- groups: bind (search in the directory), unbind

function GroupState({ g }: { g: TeamGroup }) {
  const { t } = useTranslation()
  const key = groupStateKey(g)
  if (g.state === "loading")
    return (
      <span className="flex items-center gap-1 text-xs text-muted-foreground">
        <Loader2 className="size-3 animate-spin" /> {t(key)}
      </span>
    )
  if (g.state === "error") return <span className="block text-xs text-destructive">{t(key, { category: g.error ?? "" })}</span>
  if (g.state === "waiting") return <span className="block text-xs text-muted-foreground">{t(key)}</span>
  return (
    <span className="block text-xs text-muted-foreground">
      {t(key, { count: g.members })}
      {g.synced_at && (
        <>
          {" · "}
          <Ts at={g.synced_at} rel />
        </>
      )}
    </span>
  )
}

function GroupsPart({ team, settings, onMembers }: { team: Team; settings: TeamsSettings; onMembers: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [source, setSource] = useState<"ldap" | "entra">(settings.ldap_usable || !settings.entra_usable ? "ldap" : "entra")
  const [query, setQuery] = useState("")
  const [groups, setGroups] = useState<DirectoryGroup[] | null>(null)
  const [searching, setSearching] = useState(false)
  const [searchError, setSearchError] = useState<string | null>(null)
  const [picked, setPicked] = useState<DirectoryGroup | null>(null)
  const [busy, setBusy] = useState(false)
  const usable = source === "ldap" ? settings.ldap_usable : settings.entra_usable
  const mappings = useMappings()
  // groups of the role mapping (same ids: AD by DN, Entra by object id) – offered first, unless bound already
  const bound = new Set(team.groups.filter((g) => g.source === source).map((g) => g.group_id.toLowerCase()))
  const needle = query.trim().toLowerCase()
  const mapped = (mappings.data ?? [])
    .filter((m) => m.source === source && !bound.has(m.group_id.toLowerCase()))
    .filter((m) => !needle || `${m.group_name} ${m.group_id}`.toLowerCase().includes(needle))
  const mappedIds = new Set(mapped.map((m) => m.group_id.toLowerCase()))
  const found = groups?.filter((g) => !mappedIds.has(g.id.toLowerCase()) && !bound.has(g.id.toLowerCase())) ?? null
  const pick = (g: DirectoryGroup) => setPicked(g)
  const isPicked = (id: string) => picked?.id.toLowerCase() === id.toLowerCase()

  // live search in the directory itself, debounced (as the role mapping)
  useEffect(() => {
    if (!usable) return
    let alive = true
    const id = setTimeout(async () => {
      setGroups(null)
      setSearchError(null)
      setSearching(true)
      try {
        const r = await api.get<DirectoryGroup[]>(`/api/admin/auth/${source}/groups?q=${encodeURIComponent(query)}`)
        if (alive) setGroups(r)
      } catch (e) {
        if (alive) setSearchError(errorText(t, e))
      } finally {
        if (alive) setSearching(false)
      }
    }, 350)
    return () => {
      alive = false
      clearTimeout(id)
    }
  }, [query, source, usable, t])

  const bind = async () => {
    if (!picked) return
    setBusy(true)
    try {
      await withReauth(() => api.post(`/api/admin/teams/${team.id}/groups`, { source, group_id: picked.id, group_name: picked.name }))
      toast.success(settings.enabled ? t("teams.group.boundLoading", { name: picked.name }) : t("teams.group.bound", { name: picked.name }))
      setPicked(null)
      refreshTeams(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const unbind = async (g: TeamGroup) => {
    if (!(await confirmAction({ title: t("teams.group.unbindTitle"), text: t("teams.group.unbindText", { name: g.group_name || g.group_id }), confirm: t("teams.group.unbind") })))
      return
    try {
      await withReauth(() => api.del(`/api/admin/teams/${team.id}/groups/${g.id}`))
      refreshTeams(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  return (
    <>
      <SheetBody>
        {team.groups.length === 0 ? (
          <EmptyState icon={FolderTree} title={t("teams.group.emptyTitle")} text={t("teams.group.emptyText")} />
        ) : (
          <ul className="divide-y rounded-lg border">
            {team.groups.map((g) => (
              <li key={g.id} className="flex items-start gap-3 px-3 py-2.5">
                <Pill color="--muted-foreground" className="mt-0.5">
                  {g.source === "ldap" ? "AD" : "Entra"}
                </Pill>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium [overflow-wrap:anywhere]">{g.group_name || g.group_id}</p>
                  <p className="truncate font-mono text-[11px] text-muted-foreground" title={g.group_id}>
                    {g.group_id}
                  </p>
                  <GroupState g={g} />
                </div>
                <Button variant="ghost" size="icon-sm" aria-label={t("teams.group.unbind")} title={t("teams.group.unbind")} onClick={() => void unbind(g)}>
                  <Trash2 />
                </Button>
              </li>
            ))}
          </ul>
        )}
        <div className="space-y-3 rounded-lg border border-dashed p-3">
          <p className="text-sm font-medium">{t("teams.group.addTitle")}</p>
          <div className="grid gap-3 sm:grid-cols-[1fr_2fr]">
            <Field label={t("signin.map.source")}>
              <Select value={source} onValueChange={(x) => (setSource(x as "ldap" | "entra"), setPicked(null), setGroups(null), setSearchError(null))}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper">
                  <SelectItem value="ldap">Active Directory</SelectItem>
                  <SelectItem value="entra">Entra ID</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label={t("signin.map.search")}>
              <div className="relative">
                <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("signin.map.searchPlaceholder")} className="pl-8" disabled={!usable} />
              </div>
            </Field>
          </div>
          {usable && mapped.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-muted-foreground">
                <Explained label={t("teams.group.fromMappings")} text={t("teams.group.fromMappingsHint")} />
              </p>
              <ul className="max-h-56 divide-y overflow-y-auto rounded-lg border" role="listbox" aria-label={t("teams.group.fromMappings")}>
                {mapped.map((m) => (
                  <li key={m.id}>
                    <button
                      type="button"
                      role="option"
                      aria-selected={isPicked(m.group_id)}
                      onClick={() => pick({ id: m.group_id, name: m.group_name || m.group_id, description: "", path: "" })}
                      className={
                        "flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-muted/50 " + (isPicked(m.group_id) ? "bg-primary/5 ring-1 ring-primary ring-inset" : "")
                      }
                    >
                      <span className="min-w-0 flex-1">
                        <span className="block text-sm font-medium [overflow-wrap:anywhere]">{m.group_name || m.group_id}</span>
                        <span className="block truncate font-mono text-[11px] text-muted-foreground" title={m.group_id}>
                          {m.group_id}
                        </span>
                      </span>
                      <Pill color={m.role === "admin" ? "--sev-high" : "--primary"}>{t(`role.${m.role}`)}</Pill>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {!usable ? (
            <p className="text-xs text-muted-foreground">{t(`signin.map.notConfigured.${source}`)}</p>
          ) : searchError ? (
            <p className="text-xs text-destructive">{searchError}</p>
          ) : searching && !groups ? (
            <Loader2 className="size-4 animate-spin text-muted-foreground" />
          ) : found && found.length === 0 ? (
            mapped.length === 0 && <p className="text-xs text-muted-foreground">{t("common.noResults")}</p>
          ) : (
            found && (
              <div className="space-y-1.5">
                {mapped.length > 0 && <p className="text-xs font-medium text-muted-foreground">{t("teams.group.fromDirectory")}</p>}
                <ul className="max-h-56 divide-y overflow-y-auto rounded-lg border" role="listbox" aria-label={t("signin.map.results")}>
                  {found.map((g) => (
                    <li key={g.id}>
                      <button
                        type="button"
                        role="option"
                        aria-selected={isPicked(g.id)}
                        onClick={() => pick(g)}
                        className={"w-full px-3 py-2 text-left hover:bg-muted/50 " + (isPicked(g.id) ? "bg-primary/5 ring-1 ring-primary ring-inset" : "")}
                      >
                        <span className="block text-sm font-medium">{g.name}</span>
                        <span className="block truncate text-[11px] text-muted-foreground">{g.path || g.description || g.id}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )
          )}
          <p className="text-xs text-muted-foreground">
            <Explained label={t("teams.group.nested")} text={t("teams.group.nestedExplain")} />
          </p>
        </div>
      </SheetBody>
      <SheetActions>
        <Button variant="ghost" onClick={onMembers}>
          <UsersRound /> {t("teams.part.members")}
        </Button>
        <Button disabled={!picked || busy} onClick={() => void bind()}>
          {busy ? <Loader2 className="animate-spin" /> : <Plus />} {picked ? t("teams.group.bindPicked", { name: picked.name }) : t("teams.group.bind")}
        </Button>
      </SheetActions>
    </>
  )
}

// ---------------------------------------------------------------- members: page by page; local accounts by hand

function MembersPart({ team, settings }: { team: Team; settings: TeamsSettings }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [q, setQ] = useState("")
  const [term, setTerm] = useState("")
  const [offset, setOffset] = useState(0)
  const loading = team.groups.some((g) => g.state === "loading")
  const members = useTeamMembers(team.id, term, offset, loading)
  const users = useUsers()
  const [pick, setPick] = useState("")
  const [busy, setBusy] = useState(false)
  const [away, setAway] = useState<TeamMemberRow | null>(null)
  useEffect(() => {
    const id = setTimeout(() => {
      setTerm(q.trim())
      setOffset(0)
    }, 300)
    return () => clearTimeout(id)
  }, [q])
  // a load just ended: the members once more (the list polls only while loading – its last answer may be from before)
  const wasLoading = useRef(loading)
  useEffect(() => {
    if (wasLoading.current && !loading) void qc.invalidateQueries({ queryKey: ["admin", "teams", "members", team.id] })
    wasLoading.current = loading
  }, [loading, qc, team.id])
  // the page lies behind the end now (members removed, a smaller group): back to the last page there is (set while
  // rendering – the next render asks for that page)
  const d = members.data
  if (d && d.offset === offset && offset > 0 && offset >= d.total) setOffset(Math.max(0, Math.floor((d.total - 1) / MEMBER_PAGE) * MEMBER_PAGE))
  const locals = (users.data ?? []).filter((u) => u.auth_source === "local" && !u.teams?.includes(team.name))
  const add = async () => {
    if (!pick) return
    setBusy(true)
    try {
      await api.put(`/api/admin/teams/${team.id}/members/${pick}`)
      setPick("")
      refreshTeams(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const remove = async (id: string) => {
    try {
      await api.del(`/api/admin/teams/${team.id}/members/${id}`)
      refreshTeams(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  const loadNow = async () => {
    try {
      await api.post(`/api/admin/teams/${team.id}/sync`)
      toast.success(t("teams.members.loading"))
      refreshTeams(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  if (away)
    // a member's absence, set by an admin: the deputy from this team (app/absence.py) – its own form, actions below
    return (
      <AbsenceEditor
        key={away.id}
        current={away.absence}
        deputiesUrl={`/api/admin/teams/${team.id}/members/${away.id}/deputies`}
        absenceUrl={`/api/admin/teams/${team.id}/members/${away.id}/absence`}
        intro={<p className="text-sm font-medium">{t("delivery.absence.forMember", { name: away.display_name })}</p>}
        alsoMeLabel={t("delivery.absence.alsoTo", { name: away.display_name })}
        onCancel={() => setAway(null)}
        onSaved={() => {
          setAway(null)
          void qc.invalidateQueries({ queryKey: ["admin", "teams", "members", team.id] })
        }}
      />
    )
  return (
    <>
      <SheetBody>
        <p className="text-xs leading-relaxed text-muted-foreground">{t("teams.members.hint")}</p>
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("teams.members.search")} className="pl-8" aria-label={t("teams.members.search")} />
        </div>
        {!d ? (
          <Loading error={members.error} onRetry={() => void members.refetch()} />
        ) : d.items.length === 0 ? (
          <EmptyState icon={UsersRound} title={term ? t("common.noResults") : t("teams.members.emptyTitle")} text={term ? undefined : t("teams.members.emptyText")} />
        ) : (
          <ul className="divide-y rounded-lg border">
            {d.items.map((m) => (
              <li key={m.id} className="flex items-start gap-3 px-3 py-2.5">
                <div className="min-w-0 flex-1">
                  <p className="flex flex-wrap items-center gap-1.5 text-sm font-medium">
                    <span className="min-w-0 [overflow-wrap:anywhere]">{m.display_name}</span>
                    <Pill color="--muted-foreground">{t(`users.source.${m.auth_source}`)}</Pill>
                    {m.origin === "manual" && <Pill color="--primary">{t("teams.members.manual")}</Pill>}
                    {!m.is_active &&
                      (m.deactivated_reason === "admin" ? <Pill color="--muted-foreground">{t("teams.members.blocked")}</Pill> : <OffPill reason={m.deactivated_reason} />)}
                    {m.welcome === "no_address" && <Pill color="--warning">{t("users.welcomeNoAddress")}</Pill>}
                  </p>
                  <p className="text-xs text-muted-foreground [overflow-wrap:anywhere]">
                    {team.products.length > 0 && (
                      <span className="block" data-member-products>
                        {m.products.length ? t("teams.members.gets", { products: isoList(m.products) }) : t("teams.members.getsNone")}
                      </span>
                    )}
                    {m.absence && (
                      <span className="block" data-member-absence>
                        <AbsenceLine a={m.absence} name={m.display_name} />
                      </span>
                    )}
                    <span className="font-mono">{m.username}</span>
                    {m.email && ` · ${m.email}`} ·{" "}
                    {m.last_login_at ? (
                      <>
                        {t("users.lastLogin")} <Ts at={m.last_login_at} rel />
                      </>
                    ) : (
                      t("users.neverLoggedIn")
                    )}
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={t("delivery.absence.editFor", { name: m.display_name })}
                  title={t("delivery.absence.editFor", { name: m.display_name })}
                  onClick={() => setAway(m)}
                >
                  <CalendarClock />
                </Button>
                {m.origin === "manual" && (
                  <Button variant="ghost" size="icon-sm" aria-label={t("teams.members.remove")} title={t("teams.members.remove")} onClick={() => void remove(m.id)}>
                    <X />
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
        {d && d.total > MEMBER_PAGE && (
          <div className="flex items-center justify-between gap-3 text-xs text-muted-foreground">
            <span>{t("teams.members.range", { from: d.offset + 1, to: Math.min(d.offset + MEMBER_PAGE, d.total), total: d.total })}</span>
            <span className="flex gap-2">
              <Button size="sm" variant="outline" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - MEMBER_PAGE))}>
                {t("common.back")}
              </Button>
              <Button size="sm" variant="outline" disabled={offset + MEMBER_PAGE >= d.total} onClick={() => setOffset(offset + MEMBER_PAGE)}>
                {t("common.next")}
              </Button>
            </span>
          </div>
        )}
        <div className="space-y-2 rounded-lg border border-dashed p-3">
          <Field label={t("teams.members.addLocal")} hint={t("teams.members.addLocalHint")}>
            <Select value={pick} onValueChange={setPick} disabled={locals.length === 0}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder={locals.length ? t("teams.members.pickLocal") : t("teams.members.noLocal")} />
              </SelectTrigger>
              <SelectContent position="popper">
                {locals.map((u) => (
                  <SelectItem key={u.id} value={u.id}>
                    {u.display_name} ({u.username})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <div className="flex justify-end">
            <Button size="sm" variant="outline" disabled={!pick || busy} onClick={() => void add()}>
              <UserPlus /> {t("teams.members.add")}
            </Button>
          </div>
        </div>
      </SheetBody>
      <SheetActions>
        <span className="text-xs text-muted-foreground">{loading ? t("teams.group.state.loading") : ""}</span>
        <Button
          variant="outline"
          disabled={!settings.enabled || team.groups.length === 0 || loading}
          onClick={() => void loadNow()}
          title={!settings.enabled ? t("teams.offShort") : undefined}
        >
          <RefreshCw /> {t("teams.members.loadNow")}
        </Button>
      </SheetActions>
    </>
  )
}

// ---------------------------------------------------------------- products and who of the team gets them

type Routing = { all: boolean; people: PersonRef[] }
const routingOf = (p: TeamProduct): Routing => ({ all: p.all_members, people: p.people })
const sameRouting = (a: Routing, b: Routing) => a.all === b.all && (a.all || JSON.stringify(a.people.map((x) => x.id).sort()) === JSON.stringify(b.people.map((x) => x.id).sort()))

function ProductsPart({ team }: { team: Team }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const products = useTeamProducts()
  const initial = team.products.map((p) => p.key)
  const saved = Object.fromEntries(team.products.map((p) => [p.key, routingOf(p)])) as Record<string, Routing>
  const [v, setV] = useState<string[]>(initial)
  const [routing, setRouting] = useState<Record<string, Routing>>(saved)
  const [busy, setBusy] = useState(false)
  const route = (key: string): Routing => routing[key] ?? { all: true, people: [] }
  const changed = v.filter((k) => !sameRouting(route(k), saved[k] ?? { all: true, people: [] }))
  const dirty = JSON.stringify([...v].sort()) !== JSON.stringify([...initial].sort()) || changed.length > 0
  const save = async () => {
    setBusy(true)
    try {
      if (JSON.stringify([...v].sort()) !== JSON.stringify([...initial].sort())) await api.put(`/api/admin/teams/${team.id}/products`, { products: v })
      for (const key of changed) {
        const r = route(key)
        await api.put(`/api/admin/teams/${team.id}/routing`, { product: key, all_members: r.all, members: r.all ? [] : r.people.map((x) => x.id) })
      }
      toast.success(t("common.saved"))
      refreshTeams(qc)
      void qc.invalidateQueries({ queryKey: ["vendor", "overview", "team"] })
      void qc.invalidateQueries({ queryKey: ["me", "vendor-notify"] })
    } catch (e) {
      toast.error(e instanceof ApiError ? errorText(t, e) : t("errors.generic"))
      refreshTeams(qc)
    } finally {
      setBusy(false)
    }
  }
  if (!products.data) return <SheetLoading error={products.error} onRetry={() => void products.refetch()} />
  const label = (key: string) => products.data.find((p) => p.key === key)?.label ?? team.products.find((p) => p.key === key)?.label ?? key
  const chosen = [...v].sort((a, b) => label(a).localeCompare(label(b)))
  return (
    <>
      <SheetBody>
        <p className="text-xs leading-relaxed text-muted-foreground">{t("teams.products.hint")}</p>
        {products.data.length === 0 ? (
          <EmptyState icon={Boxes} title={t("teams.products.noneTitle")} text={t("teams.products.noneText")} />
        ) : (
          <Field label={t("teams.part.products")}>
            <MultiSelect
              variant="field"
              label={t("teams.products.pick")}
              options={products.data.map((p) => ({ value: p.key, label: p.label, hint: p.enabled ? undefined : t("teams.products.off") }))}
              value={v}
              onChange={setV}
            />
          </Field>
        )}
        {chosen.length > 0 && (
          <section className="space-y-2" aria-labelledby="teams-routing">
            <div className="flex items-center justify-between gap-2">
              <p id="teams-routing" className="text-sm font-medium">
                <Explained label={t("teams.routing.title")} text={t("teams.routing.explain")} />
              </p>
              <HelpLink chapter="anmeldung" section="teams-zuteilung" topic={t("teams.routing.title")} />
            </div>
            <ul className="divide-y rounded-lg border">
              {chosen.map((key) => {
                const r = route(key)
                return (
                  <li key={key} className="px-3 pt-2.5" data-routing={key}>
                    <p className="text-sm font-medium [overflow-wrap:anywhere]">{label(key)}</p>
                    <ToggleRow
                      label={t("teams.routing.all")}
                      description={r.all ? t("teams.routing.allHint") : t("teams.routing.someHint")}
                      checked={r.all}
                      onCheckedChange={(x) => setRouting({ ...routing, [key]: { all: x, people: x ? [] : r.people } })}
                      className="py-2"
                    />
                    {!r.all && (
                      <div className="space-y-2 pb-3">
                        <MemberPicker teamId={team.id} value={r.people} onChange={(people) => setRouting({ ...routing, [key]: { all: false, people } })} />
                        {r.people.length === 0 && (
                          <p role="alert" className="rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs">
                            {t("teams.routing.nobody")}
                          </p>
                        )}
                      </div>
                    )}
                  </li>
                )
              })}
            </ul>
          </section>
        )}
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("teams.products.rules")}</p>
      </SheetBody>
      <SheetActions>
        <span />
        <SaveBar busy={busy} dirty={dirty} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}

/** The chosen members of a product: removable chips, more added from a search in the team's members (server-side –
 * a team can have thousands). Only members of the team can be found here, and the server checks it again. */
function MemberPicker({ teamId, value, onChange }: { teamId: string; value: PersonRef[]; onChange: (v: PersonRef[]) => void }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState("")
  const [term, setTerm] = useState("")
  useEffect(() => {
    const id = setTimeout(() => setTerm(q.trim()), 250)
    return () => clearTimeout(id)
  }, [q])
  const found = useTeamMembers(teamId, term, 0, false, open)
  const picked = new Set(value.map((x) => x.id))
  const options = (found.data?.items ?? []).filter((m) => !picked.has(m.id))
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {value.map((p) => (
        <span key={p.id} className="inline-flex max-w-full items-center gap-1 rounded-md bg-secondary py-0.5 pr-0.5 pl-2 text-xs font-medium">
          <span className="min-w-0 truncate" title={p.username}>
            {p.display_name}
          </span>
          <Button
            variant="ghost"
            size="icon-xs"
            aria-label={t("teams.routing.removePerson", { name: p.display_name })}
            onClick={() => onChange(value.filter((x) => x.id !== p.id))}
          >
            <X />
          </Button>
        </span>
      ))}
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button variant="outline" size="xs">
            <UserPlus /> {t("teams.routing.addPerson")}
          </Button>
        </PopoverTrigger>
        <PopoverContent align="start" collisionPadding={12} className="w-[min(20rem,calc(100vw-2rem))] p-2">
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("teams.members.search")} aria-label={t("teams.members.search")} className="pl-8" autoFocus />
          </div>
          {!found.data ? (
            <Loader2 className="mx-auto my-2 size-4 animate-spin text-muted-foreground" />
          ) : options.length === 0 ? (
            <p className="px-1 py-2 text-xs text-muted-foreground">{t("common.noResults")}</p>
          ) : (
            <ul className="max-h-64 divide-y overflow-y-auto rounded-md border" role="listbox" aria-label={t("teams.routing.addPerson")}>
              {options.map((m) => (
                <li key={m.id}>
                  <button
                    type="button"
                    role="option"
                    aria-selected={false}
                    onClick={() => onChange([...value, { id: m.id, username: m.username, display_name: m.display_name }])}
                    className="w-full px-2.5 py-1.5 text-left hover:bg-muted/60 focus-visible:bg-muted/60 focus-visible:outline-none"
                  >
                    <span className="block truncate text-sm">{m.display_name}</span>
                    <span className="block truncate font-mono text-[11px] text-muted-foreground">{m.username}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </PopoverContent>
      </Popover>
    </div>
  )
}
