import { useEffect } from "react"
import { useTranslation } from "react-i18next"
import { Link, Navigate, useLocation, useParams, useSearchParams } from "react-router"
import {
  Bell,
  BellOff,
  BellRing,
  Blocks,
  Boxes,
  CalendarDays,
  DatabaseBackup,
  KeyRound,
  Lock,
  MonitorSmartphone,
  Plug,
  ScrollText,
  UserRound,
  Users,
  UsersRound,
} from "lucide-react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Pill } from "@/components/cobe/badges"
import { PageHeader } from "@/components/cobe/common"
import { SubTabs } from "@/components/cobe/sub-tabs"
import { HelpLink } from "@/components/cobe/doc-markdown"
import { pendingTotal, usePendingCounts } from "@/lib/admin-api"
import { useAuth } from "@/lib/auth"
import { deadCount, useSourceHealth } from "@/lib/source-health"
import { usePersonalNotify } from "@/lib/teams-api"
import { confirmDiscard } from "@/lib/unsaved"
import { cn } from "@/lib/utils"
import { ProfileSettings } from "@/pages/account"
import { ApiSettings } from "@/pages/settings-api"
import { AuditSettings } from "@/pages/settings-audit"
import { BackupSettings } from "@/pages/settings-backup"
import { IntegrationsSettings } from "@/pages/settings-health"
import { DesktopPane, NotifySettings } from "@/pages/settings-notify"
import { PersonalVendorCard } from "@/pages/settings-personal"
import { CalendarCard } from "@/pages/settings-watch"
import { MutesCard } from "@/pages/settings-mutes"
import { SettingsCard } from "@/pages/settings-shared"
import { ApprovalPane, EntraPane, LdapPane, MappingsPane, PasskeysPane, SecondFactorPane, SessionsPane } from "@/pages/settings-signin"
import { TeamsSettingsPage } from "@/pages/settings-teams"
import { TlsPane } from "@/pages/settings-tls"
import { UsersPane } from "@/pages/settings-users"

type NavEntry = { key: string; icon: React.ElementType; admin?: boolean }

// The settings page: personal pages for everybody, the system ones grouped by what an admin is looking for
const PERSONAL: NavEntry[] = [
  { key: "profile", icon: UserRound },
  { key: "notifications", icon: Bell },
]
const GROUPS: { label: string; items: NavEntry[] }[] = [
  {
    label: "settings.group.organisation",
    items: [
      { key: "users", icon: Users, admin: true },
      { key: "teams", icon: UsersRound, admin: true },
    ],
  },
  {
    label: "settings.group.access",
    items: [
      { key: "auth", icon: KeyRound, admin: true },
      { key: "https", icon: Lock, admin: true },
      { key: "audit", icon: ScrollText, admin: true },
    ],
  },
  {
    label: "settings.group.connections",
    items: [
      { key: "integrations", icon: Blocks, admin: true },
      { key: "rules", icon: BellRing, admin: true },
    ],
  },
  {
    label: "settings.group.operations",
    items: [
      { key: "backup", icon: DatabaseBackup, admin: true },
      { key: "api", icon: Plug, admin: true },
    ],
  },
]
const SYSTEM = GROUPS.flatMap((g) => g.items)
const MAIL_SERVER_PAGES = ["mail", "smtp"]

export function SettingsPage() {
  const { t } = useTranslation()
  const { section } = useParams()
  const { hash } = useLocation()
  const { isAdmin } = useAuth()
  // dead sources: a number on "Integrationen" (the health page's own query – one request for both)
  const dead = deadCount(useSourceHealth(isAdmin).data)
  // accounts and raises to admin waiting for approval: a number on "Benutzer"
  const waiting = pendingTotal(usePendingCounts(isAdmin).data)
  // a part of a page (#news): scrolled to once it is drawn
  useEffect(() => {
    if (!hash) return
    const id = setTimeout(() => document.getElementById(hash.slice(1))?.scrollIntoView({ block: "start" }), 0)
    return () => clearTimeout(id)
  }, [hash, section])
  const allowed = (e: NavEntry) => !e.admin || isAdmin
  // "E-Mail-Versand" is part of Kanäle now (the status line above the channels): old links and bookmarks open its drawer
  if (section && MAIL_SERVER_PAGES.includes(section)) return <Navigate to={isAdmin ? "/settings/rules?smtp=1" : "/settings/profile"} replace />
  const active = section ?? (isAdmin ? SYSTEM[0].key : "profile")
  const entry = [...PERSONAL, ...SYSTEM].find((e) => e.key === active)
  if (!entry || !allowed(entry)) return <Navigate to="/settings/profile" replace />
  if (!section) return <Navigate to={`/settings/${active}`} replace />

  const content: Record<string, React.ReactNode> = {
    profile: <ProfileSettings />,
    notifications: <NotificationsPage />,
    users: <UsersSettings />,
    teams: <TeamsSettingsPage />,
    auth: (
      <>
        <SettingsCard
          title={t("settings.approval.title")}
          description={t("settings.approval.desc")}
          actions={<HelpLink chapter="anmeldung" section="freigabe" topic={t("settings.approval.title")} />}
        >
          <ApprovalPane />
        </SettingsCard>
        <SettingsCard
          title={t("settings.ldap.title")}
          description={t("settings.ldap.desc")}
          actions={<HelpLink chapter="anmeldung" section="ad-ldap" topic={t("settings.ldap.title")} />}
        >
          <LdapPane />
        </SettingsCard>
        <SettingsCard
          title={t("settings.entra.title")}
          description={t("settings.entra.desc")}
          actions={<HelpLink chapter="anmeldung" section="entra-app-registrierung" topic={t("settings.entra.title")} />}
        >
          <EntraPane />
        </SettingsCard>
        <SettingsCard
          title={t("settings.mfa.title")}
          description={t("settings.mfa.desc")}
          actions={<HelpLink chapter="anmeldung" section="zweiter-faktor-alle" topic={t("settings.mfa.title")} />}
        >
          <SecondFactorPane />
        </SettingsCard>
        <SettingsCard title={t("passkey.title")} description={t("signin.passkeys.desc")} actions={<HelpLink chapter="anmeldung" section="passkeys" topic={t("passkey.title")} />}>
          <PasskeysPane />
        </SettingsCard>
        <SettingsCard
          title={t("settings.tab.sessions")}
          description={t("settings.sessions.desc")}
          actions={<HelpLink chapter="anmeldung" section="sitzungen" topic={t("settings.tab.sessions")} />}
        >
          <SessionsPane />
        </SettingsCard>
      </>
    ),
    https: <TlsPane />,
    audit: <AuditSettings />,
    // the tiles of news and Vendor News | the sources' health (sub-tabs)
    integrations: <IntegrationsSettings />,
    rules: <NotifySettings />,
    backup: <BackupSettings />,
    api: <ApiSettings />,
  }

  return (
    <>
      <PageHeader title={t("nav.settings")} description={t("settings.description")} />
      <div className="grid gap-8 lg:grid-cols-[220px_minmax(0,1fr)]">
        <nav className="space-y-6 lg:sticky lg:top-20 lg:self-start" aria-label={t("nav.settings")}>
          <NavGroup label={t("settings.personal")} items={PERSONAL} active={active} />
          {GROUPS.map((g) => {
            const items = g.items.filter(allowed)
            return (
              items.length > 0 && (
                <NavGroup
                  key={g.label}
                  label={t(g.label)}
                  items={items}
                  active={active}
                  badges={{ integrations: dead, users: waiting }}
                  badgeTitles={{ integrations: "health.navBadge", users: "users.pendingBadge" }}
                />
              )
            )
          })}
        </nav>
        <div key={active} className={cn("min-w-0 animate-in space-y-6 duration-200 fade-in-0", active === "integrations" ? "max-w-[100rem]" : "max-w-5xl")}>
          {content[active]}
        </div>
      </div>
    </>
  )
}

function NavGroup({
  label,
  items,
  active,
  badges,
  badgeTitles,
}: {
  label: string
  items: NavEntry[]
  active: string
  badges?: Record<string, number | null>
  /** the i18n key of each badge's text (with {{count}}) */
  badgeTitles?: Record<string, string>
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1">
      <p className="px-2 pb-1 text-xs font-medium text-muted-foreground">{label}</p>
      {items.map(({ key, icon: Icon }) => (
        <Link
          key={key}
          to={`/settings/${key}`}
          aria-current={active === key ? "page" : undefined}
          className={cn(
            "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm font-medium transition-colors",
            active === key ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:bg-muted hover:text-foreground",
          )}
        >
          <Icon className="size-4" />
          {t(`settings.nav.${key}`)}
          {!!badges?.[key] && (
            <Pill color={key === "users" ? "--warning" : "--sev-critical"} className="ml-auto px-1.5" title={t(badgeTitles?.[key] ?? "health.navBadge", { count: badges[key]! })}>
              <span className="tabular-nums" aria-hidden>
                {badges[key]}
              </span>
              <span className="sr-only">{t(badgeTitles?.[key] ?? "health.navBadge", { count: badges[key]! })}</span>
            </Pill>
          )}
        </Link>
      ))}
    </div>
  )
}

/** Users | role mapping – sub-tabs instead of two growing lists on top of each other. */
function UsersSettings() {
  const { t } = useTranslation()
  const [params, setParams] = useSearchParams()
  const tab = params.get("tab") === "mapping" ? "mapping" : "users"
  const switchTab = async (v: string) => {
    if (await confirmDiscard()) setParams(v === "users" ? {} : { tab: v }, { replace: true })
  }
  return (
    <Tabs value={tab} onValueChange={(v) => void switchTab(v)} className="gap-6">
      <TabsList>
        <TabsTrigger value="users">{t("settings.tab.users")}</TabsTrigger>
        <TabsTrigger value="mapping">{t("settings.tab.mappings")}</TabsTrigger>
      </TabsList>
      <TabsContent value="users">
        <UsersPane />
      </TabsContent>
      <TabsContent value="mapping">
        <SettingsCard
          title={t("settings.tab.mappings")}
          description={t("signin.map.hint")}
          actions={<HelpLink chapter="anmeldung" section="gruppen-rollen" topic={t("settings.tab.mappings")} />}
        >
          <MappingsPane />
        </SettingsCard>
      </TabsContent>
    </Tabs>
  )
}

type NotifyTab = "desktop" | "vendor" | "calendar" | "mutes"

/** Settings → Benachrichtigungen (everybody): desktop notifications of this browser | the Vendor News of the own
 * products (only while Teams is on and the person is in a team or watches a CVE) | the calendar
 * address (sub-tabs, `?tab=`). */
function NotificationsPage() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const personal = usePersonalNotify().data
  const asked = params.get("tab")
  const tab: NotifyTab = asked === "vendor" && personal?.available ? "vendor" : asked === "calendar" || asked === "mutes" ? asked : "desktop"
  const parts = [
    { key: "desktop" as const, icon: MonitorSmartphone, label: t("personal.tab.desktop") },
    ...(personal?.available ? [{ key: "vendor" as const, icon: Boxes, label: t("personal.title") }] : []),
    { key: "calendar" as const, icon: CalendarDays, label: t("cal.title") },
    { key: "mutes" as const, icon: BellOff, label: t("reader.mutes.tab") },
  ]
  // the watched CVEs have their own page now – an older link (also in sent messages) goes there
  if (asked === "watch") return <Navigate to={`/watch${params.get("cve") ? `?cve=${encodeURIComponent(params.get("cve") ?? "")}` : ""}`} replace />
  return (
    <>
      <SubTabs parts={parts} active={tab} to={(k) => (k === "desktop" ? "?" : `?tab=${k}`)} label={t("settings.nav.notifications")} />
      {tab === "vendor" ? (
        <PersonalVendorCard />
      ) : tab === "mutes" ? (
        <MutesCard />
      ) : tab === "calendar" ? (
        <CalendarCard />
      ) : (
        <SettingsCard
          title={t("settings.desktop.title")}
          description={t("settings.desktop.desc")}
          actions={<HelpLink chapter="benachrichtigungen" section="desktop" topic={t("settings.desktop.title")} />}
        >
          <DesktopPane />
        </SettingsCard>
      )}
    </>
  )
}
