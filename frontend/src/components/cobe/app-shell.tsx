import { useEffect } from "react"
import { Link, useLocation, useMatch, useNavigate } from "react-router"
import { useTranslation } from "react-i18next"
import { useQuery } from "@tanstack/react-query"
import { BookOpen, ChevronsUpDown, Info, Languages, LogOut, Monitor, Moon, Newspaper, Settings, ShieldAlert, Star, Sun, UserRound } from "lucide-react"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Logo, PersonAvatar } from "@/components/cobe/common"
import { PageErrorBoundary } from "@/components/cobe/query-state"
import { api } from "@/lib/api"
import { polled } from "@/lib/poll"
import { useAuth } from "@/lib/auth"
import { badgeText, useReaderCounts } from "@/lib/reader-api"
import { readScope } from "@/lib/teams-api"
import { useTheme } from "@/lib/theme"
import { UnsavedGuard, clearDirty } from "@/lib/unsaved"

/** The user menu in the sidebar footer: profile, language, appearance, the handbook, the running version (→ changelog),
 * sign-out. */
function UserMenu() {
  const { t, i18n } = useTranslation()
  const { theme, setTheme } = useTheme()
  const navigate = useNavigate()
  const { user, logout } = useAuth()
  const name = user?.display_name ?? ""
  const version = useQuery({ queryKey: ["version"], queryFn: () => api.get<{ version: string }>("/api/health"), staleTime: Infinity }).data?.version
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent">
          <PersonAvatar user={user} />
          <div className="grid min-w-0 flex-1 text-left leading-tight">
            <span className="truncate text-sm font-medium">{name}</span>
            <span className="truncate text-xs text-muted-foreground">{t(`role.${user?.role ?? "reader"}`)}</span>
          </div>
          <ChevronsUpDown className="ml-auto size-4 text-muted-foreground" />
        </SidebarMenuButton>
      </DropdownMenuTrigger>
      <DropdownMenuContent side="top" align="start" className="w-64">
        <DropdownMenuLabel className="font-normal">
          <p className="text-sm font-medium">{name}</p>
          <p className="text-xs text-muted-foreground">{user?.email || user?.username}</p>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => navigate("/settings/profile")}>
          <UserRound /> {t("shell.profile")}
        </DropdownMenuItem>
        <DropdownMenuSub>
          <DropdownMenuSubTrigger>
            <Languages /> {t("shell.language")}
          </DropdownMenuSubTrigger>
          <DropdownMenuSubContent>
            <DropdownMenuRadioGroup value={i18n.language === "en" ? "en" : "de"} onValueChange={(v) => void i18n.changeLanguage(v)}>
              <DropdownMenuRadioItem value="de">Deutsch</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="en">English</DropdownMenuRadioItem>
            </DropdownMenuRadioGroup>
          </DropdownMenuSubContent>
        </DropdownMenuSub>
        <DropdownMenuSub>
          <DropdownMenuSubTrigger>
            {theme === "dark" ? <Moon /> : theme === "light" ? <Sun /> : <Monitor />} {t("shell.theme")}
          </DropdownMenuSubTrigger>
          <DropdownMenuSubContent>
            <DropdownMenuRadioGroup value={theme} onValueChange={setTheme}>
              <DropdownMenuRadioItem value="light">{t("shell.themeLight")}</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="dark">{t("shell.themeDark")}</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="system">{t("shell.themeSystem")}</DropdownMenuRadioItem>
            </DropdownMenuRadioGroup>
          </DropdownMenuSubContent>
        </DropdownMenuSub>
        {/* the handbook: how to set things up and use them (chapters for the role, /docs) */}
        <DropdownMenuItem onSelect={() => navigate("/docs")}>
          <BookOpen /> {t("docs.menu")}
        </DropdownMenuItem>
        {/* which build is running – asked for first when something behaves differently after an update – and what
            changed with it */}
        <DropdownMenuItem onSelect={() => navigate("/about")}>
          <Info /> {t("about.menu")}
          {version && <span className="ml-auto pl-2 text-xs text-muted-foreground tabular">{version}</span>}
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onSelect={() => {
            clearDirty() // signing out: open forms are gone either way – no question on the way to the sign-in page
            void logout().then((ok) => ok && navigate("/", { replace: true }))
          }}
        >
          <LogOut /> {t("shell.logout")}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

type NavBadge = { value: number | string; tone: string; title: string }

/** On a phone the sidebar is a sheet over the page: a new page closes it (an entry, the user menu, a link elsewhere). */
function CloseOnNavigate() {
  const { pathname } = useLocation()
  const { setOpenMobile } = useSidebar()
  useEffect(() => setOpenMobile(false), [pathname, setOpenMobile])
  return null
}

function NavItem({ to, end = false, icon: Icon, label, badge }: { to: string; end?: boolean; icon: React.ElementType; label: string; badge?: NavBadge }) {
  const active = useMatch({ path: to, end })
  const { setOpenMobile } = useSidebar()
  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild isActive={!!active} tooltip={label}>
        {/* the page shown already: the path does not change – the tap still closes the phone's menu */}
        <Link to={to} onClick={() => setOpenMobile(false)}>
          <Icon />
          <span>{label}</span>
        </Link>
      </SidebarMenuButton>
      {badge && (
        <SidebarMenuBadge
          className="gap-0.5 rounded-full px-1.5 font-semibold tabular"
          style={{ color: `var(${badge.tone})`, backgroundColor: `color-mix(in oklch, var(${badge.tone}) 14%, transparent)` }}
          title={badge.title}
          aria-label={badge.title}
        >
          {badge.value}
        </SidebarMenuBadge>
      )}
    </SidebarMenuItem>
  )
}

/** The frame of the signed-in app: a collapsible sidebar (news, settings, user menu) and a slim top bar. */
export function AppShell({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation()
  const { pathname } = useLocation()
  const { isAdmin, user } = useAuth()
  // not read by this person yet – the numbers on "News" and "Vendor News" (app/reader.py: muted things left out). One
  // small request for both, polled every minute and again when the window comes back; Vendor News in the scope the
  // person chose there ("Mein Team / Alle", remembered in this browser)
  const counts = useReaderCounts(readScope(user?.id)).data
  const n = counts?.news_enabled ? counts.news : 0
  const nv = counts?.vendor ?? 0
  // followed products a vulnerability affects – the tone of the "Vendor News" badge (and a dot when nothing is
  // unread): red only when an exploited vulnerability affects a version – not for a "possibly" one (as the cards)
  const vendor = useQuery({
    queryKey: ["vendor", "badge"],
    queryFn: polled<{ affected: number; exploited: boolean }>((o) => api.get("/api/vendor/badge", o)),
    refetchInterval: 5 * 60_000,
    staleTime: 60_000,
  }).data
  const hit = vendor?.affected ?? 0
  const exploited = vendor?.exploited ?? false
  const vendorTone = exploited ? "--sev-critical" : hit ? "--warning" : "--primary"
  const vendorBadge: NavBadge | undefined = nv
    ? {
        value: badgeText(nv) ?? "",
        tone: vendorTone,
        title: [t("nav.badge.vendorUnread", { count: nv }), hit ? t("nav.badge.vendor", { count: hit }) : ""].filter(Boolean).join(" · "),
      }
    : hit
      ? { value: "●", tone: vendorTone, title: t("nav.badge.vendor", { count: hit }) }
      : undefined
  return (
    <SidebarProvider>
      <CloseOnNavigate />
      <Sidebar collapsible="icon">
        {/* collapsed: the 3rem rail with the mark centred above the menu icons (same 0.5rem inset as SidebarMenuButton) */}
        <SidebarHeader className="px-3 pt-3 group-data-[collapsible=icon]:px-2">
          <Link to="/" aria-label="Cobe News" className="flex h-9 min-w-0 items-center px-1 group-data-[collapsible=icon]:px-0">
            <Logo withText />
          </Link>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>{t("nav.intel")}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <NavItem
                  to="/"
                  end
                  icon={Newspaper}
                  label={t("nav.news")}
                  badge={n ? { value: badgeText(n) ?? "", tone: "--primary", title: t("nav.badge.news", { count: n }) } : undefined}
                />
                <NavItem to="/vendor" icon={ShieldAlert} label={t("nav.vendor")} badge={vendorBadge} />
                <NavItem to="/watch" icon={Star} label={t("watch.title")} />
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
          {isAdmin && (
            <SidebarGroup className="mt-auto">
              <SidebarGroupContent>
                <SidebarMenu>
                  <NavItem to="/settings" icon={Settings} label={t("nav.settings")} />
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          )}
        </SidebarContent>
        <SidebarFooter>
          <SidebarMenu>
            <SidebarMenuItem>
              <UserMenu />
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-20 flex h-14 items-center gap-2 border-b bg-background/85 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/70">
          <SidebarTrigger className="-ml-1" />
          <Link to="/" className="md:hidden">
            <Logo />
          </Link>
        </header>
        <main className="mx-auto w-full max-w-[1920px] flex-1 px-4 py-6 md:px-8 md:py-8">
          {/* a page that crashes shows a notice here – sidebar and the other pages keep working */}
          <PageErrorBoundary resetKey={pathname}>{children}</PageErrorBoundary>
          <UnsavedGuard />
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}
