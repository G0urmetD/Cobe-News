import { useState } from "react"
import { Link } from "react-router"
import { useTranslation } from "react-i18next"
import {
  ArchiveRestore,
  Bell,
  BellDot,
  ChevronRight,
  Hourglass,
  LogIn,
  PackageCheck,
  PackagePlus,
  ScrollText,
  ShieldUser,
  UserRoundCheck,
  UserRoundMinus,
  UserRoundPlus,
  UserRoundX,
  type LucideIcon,
} from "lucide-react"
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar } from "@/components/ui/sidebar"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Ts } from "@/components/cobe/time"
import { useAuth } from "@/lib/auth"
import { activityView, anyWaiting, useActivity, type ActivityIcon, type ActivityItem } from "@/lib/activity"
import { cn } from "@/lib/utils"

const ICONS: Record<ActivityIcon, LucideIcon> = {
  signin: LogIn,
  pending: Hourglass,
  approved: UserRoundCheck,
  declined: UserRoundX,
  role: ShieldUser,
  created: UserRoundPlus,
  deactivated: UserRoundMinus,
  followed: PackageCheck,
  product: PackagePlus,
  restored: ArchiveRestore,
  other: ScrollText,
}

/** The lines and the way to the whole Protokoll – in the sidebar's box and in the collapsed sidebar's popover. */
function ActivityList({ items, onPick }: { items: ActivityItem[]; onPick?: () => void }) {
  const { t } = useTranslation()
  const { setOpenMobile } = useSidebar()
  const pick = () => {
    setOpenMobile(false) // a phone: the page shown already does not close the menu by navigating
    onPick?.()
  }
  return (
    <>
      {items.length === 0 ? (
        <p className="px-1.5 py-1 text-muted-foreground">{t("activity.empty")}</p>
      ) : (
        <ul role="list" className="flex flex-col gap-0.5">
          {items.map((item) => {
            const v = activityView(t, item)
            const Icon = ICONS[v.icon]
            return (
              <li key={item.id}>
                <Link
                  to={v.to}
                  onClick={pick}
                  title={v.title ? `${v.text}: ${v.title}` : v.text}
                  className={cn(
                    "flex min-w-0 items-start gap-2 rounded-md px-1.5 py-1 text-sidebar-foreground ring-sidebar-ring outline-hidden hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:ring-2",
                    v.urgent && "bg-warning/12 ring-1 ring-warning/35 hover:bg-warning/20",
                  )}
                >
                  <Icon className={cn("mt-px size-3.5 shrink-0", v.urgent ? "text-warning" : "text-muted-foreground")} aria-hidden />
                  <span className="grid min-w-0 flex-1 gap-0.5">
                    <span className="line-clamp-2 leading-snug break-words">
                      {v.text}
                      {v.urgent && <span className="sr-only"> – {t("activity.pending")}</span>}
                    </span>
                    <Ts at={item.at} rel className="text-[11px] leading-none text-muted-foreground" />
                  </span>
                </Link>
              </li>
            )
          })}
        </ul>
      )}
      <Link
        to="/settings/audit"
        onClick={pick}
        className="mt-1 inline-flex items-center gap-0.5 self-start rounded-sm px-1.5 py-0.5 text-[11px] text-muted-foreground ring-sidebar-ring outline-hidden hover:text-sidebar-foreground focus-visible:ring-2"
      >
        {t("activity.all")} <ChevronRight className="size-3" aria-hidden />
      </Link>
    </>
  )
}

/**
 * Admins only: the newest three things that happened in the app (not news) – who signed in, who follows a product now,
 * who waits for approval … (backend app/activity_api.py), above "Einstellungen". Collapsed to the icon rail: a bell (with
 * a dot while an approval waits) that opens the same list. A phone shows the sidebar as a sheet: the box as it is.
 */
export function ActivityBox() {
  const { t } = useTranslation()
  const { isAdmin } = useAuth()
  const { state, isMobile } = useSidebar()
  const q = useActivity(isAdmin)
  const [open, setOpen] = useState(false)
  const items = q.data?.items
  if (!isAdmin || !q.data || !items) return null // loading or failed: nothing rather than a box that jumps
  // the bell's dot: something waits now – also when its line is no longer among the newest three
  const urgent = anyWaiting(q.data)

  if (state === "collapsed" && !isMobile) {
    const label = urgent ? t("activity.openPending") : t("activity.open")
    return (
      <SidebarMenu>
        <SidebarMenuItem>
          <Popover open={open} onOpenChange={setOpen}>
            <PopoverTrigger asChild>
              <SidebarMenuButton tooltip={t("activity.title")} aria-label={label}>
                {urgent ? <BellDot className="text-warning" /> : <Bell />}
                <span>{t("activity.title")}</span>
              </SidebarMenuButton>
            </PopoverTrigger>
            <PopoverContent side="right" align="end" className="w-64 gap-1 p-2 text-xs">
              <section aria-labelledby="activity-title-popover" className="flex flex-col">
                <h2 id="activity-title-popover" className="px-1.5 pb-1 text-[11px] font-medium text-muted-foreground">
                  {t("activity.title")}
                </h2>
                <ActivityList items={items} onPick={() => setOpen(false)} />
              </section>
            </PopoverContent>
          </Popover>
        </SidebarMenuItem>
      </SidebarMenu>
    )
  }

  return (
    <section aria-labelledby="activity-title" className="mx-0.5 mb-1 flex flex-col rounded-lg border border-sidebar-border bg-sidebar-accent/30 p-1 text-xs">
      <h2 id="activity-title" className="flex items-center gap-1.5 px-1.5 pt-0.5 pb-1 text-[11px] font-medium text-sidebar-foreground/70">
        <Bell className="size-3" aria-hidden /> {t("activity.title")}
      </h2>
      <ActivityList items={items} />
    </section>
  )
}
