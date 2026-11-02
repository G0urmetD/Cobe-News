import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { useLocation, useNavigate, useSearchParams } from "react-router"
import { Bookmark, Check, ChevronDown, Link2, Loader2, Pencil, Plus, Star, Trash2, X } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Switch } from "@/components/ui/switch"
import { confirmAction } from "@/components/cobe/confirm"
import { copyWithToast } from "@/lib/clipboard"
import { errorText } from "@/lib/errors"
import {
  IN_PAGE,
  VIEW_NAME_MAX,
  type SavedView,
  type ViewPage,
  applyView,
  cleanViewName,
  fromOutside,
  hasFilter,
  useViewMutations,
  useViews,
  viewLink,
  viewQuery,
} from "@/lib/reader-api"
import { cn } from "@/lib/utils"

/**
 * "Ansichten" next to a page's filters: the person's saved filters of this page (apply, rename, delete, one as the
 * default), the current filter saved under a name, and "Link kopieren" – the address with the filter (whoever opens it
 * gets the same filters; nothing is shared on the server). `inline`: the trigger says which view is on ("Ansicht:
 * Standard ▾") – Vendor News' tool row.
 */
export function ViewsMenu({ page, inline = false }: { page: ViewPage; inline?: boolean }) {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const q = useViews(page)
  const m = useViewMutations(page)
  const [open, setOpen] = useState(false)
  const [name, setName] = useState("")
  const [asDefault, setAsDefault] = useState(false)
  const [editing, setEditing] = useState<string | null>(null)
  const [draft, setDraft] = useState("")
  const items = q.data?.items ?? []
  const max = q.data?.max ?? 30
  const current = viewQuery(params, page)
  const active = items.find((v) => v.query === current)
  const shownName = active ? active.name : hasFilter(params, page) ? t("reader.views.custom") : t("reader.views.standard")
  const path = page === "news" ? "/" : "/vendor"
  const apply = (v: SavedView) => {
    navigate(`${path}?${applyView(params, v.query).toString()}`, { replace: true, state: IN_PAGE })
    setOpen(false)
  }
  const fail = (e: unknown) => toast.error(errorText(t, e))
  const save = () => {
    const n = cleanViewName(name)
    if (!n) return
    m.add.mutate(
      { name: n, query: current, default: asDefault },
      {
        onSuccess: () => {
          toast.success(t("reader.views.saved", { name: n }))
          setName("")
          setAsDefault(false)
        },
        onError: fail,
      },
    )
  }
  const rename = (v: SavedView) => {
    const n = cleanViewName(draft)
    if (!n || n === v.name) return setEditing(null)
    m.patch.mutate({ id: v.id, name: n }, { onSuccess: () => setEditing(null), onError: fail })
  }
  const remove = async (v: SavedView) => {
    if (!(await confirmAction({ title: t("reader.views.deleteTitle"), text: t("reader.views.deleteText", { name: v.name }), confirm: t("common.remove") }))) return
    m.remove.mutate(v.id, { onError: fail })
  }
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        {inline ? (
          // the name says what is shown ("Ansicht: Standard") and what the button is ("Ansichten")
          <Button
            variant="outline"
            size="sm"
            className="h-9 min-w-0"
            title={t("reader.views.title")}
            aria-label={`${t("reader.views.current")} ${shownName} (${t("reader.views.title")})`}
          >
            <Bookmark className={cn(active && "fill-current text-primary")} />
            <span className="text-muted-foreground">{t("reader.views.current")}</span>
            <span className="max-w-32 truncate">{shownName}</span>
            <ChevronDown className="text-muted-foreground" />
          </Button>
        ) : (
          <Button variant="outline" size="sm" className="h-9" aria-label={t("reader.views.title")}>
            <Bookmark className={cn(active && "fill-current text-primary")} />
            <span className="max-w-40 truncate">{active ? active.name : t("reader.views.title")}</span>
          </Button>
        )}
      </PopoverTrigger>
      <PopoverContent align="start" className="w-[min(22rem,calc(100vw-2rem))] gap-2">
        <p className="text-xs font-medium text-muted-foreground">{t("reader.views.mine")}</p>
        {q.isLoading ? (
          <p className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="size-3.5 animate-spin" /> {t("reader.loading")}
          </p>
        ) : items.length === 0 ? (
          <p className="text-xs text-muted-foreground">{t("reader.views.none")}</p>
        ) : (
          <ul className="max-h-64 space-y-0.5 overflow-y-auto">
            {items.map((v) => (
              <li key={v.id} className={cn("flex items-center gap-1 rounded-md px-1 py-0.5", v === active && "bg-accent")}>
                {editing === v.id ? (
                  <form
                    className="flex min-w-0 flex-1 items-center gap-1"
                    onSubmit={(e) => {
                      e.preventDefault()
                      rename(v)
                    }}
                  >
                    <Input
                      value={draft}
                      onChange={(e) => setDraft(e.target.value)}
                      maxLength={VIEW_NAME_MAX}
                      className="h-7 text-sm"
                      autoFocus
                      aria-label={t("reader.views.name")}
                    />
                    <Button type="submit" variant="ghost" size="icon-xs" aria-label={t("common.save")}>
                      <Check />
                    </Button>
                    <Button type="button" variant="ghost" size="icon-xs" onClick={() => setEditing(null)} aria-label={t("common.cancel")}>
                      <X />
                    </Button>
                  </form>
                ) : (
                  <>
                    <button
                      type="button"
                      onClick={() => apply(v)}
                      className="min-w-0 flex-1 truncate rounded px-1 py-1 text-left text-sm outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring/50"
                    >
                      {v.name}
                    </button>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-pressed={v.default}
                      title={v.default ? t("reader.views.defaultOn") : t("reader.views.defaultSet")}
                      aria-label={v.default ? t("reader.views.defaultOn") : t("reader.views.defaultSet")}
                      onClick={() => m.patch.mutate({ id: v.id, default: !v.default }, { onError: fail })}
                    >
                      <Star className={cn(v.default && "fill-current text-warning")} />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label={t("reader.views.copy")}
                      title={t("reader.views.copy")}
                      onClick={() => void copyWithToast(viewLink(window.location.origin, page, v.query), t("reader.views.copied"))}
                    >
                      <Link2 />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label={t("reader.views.rename")}
                      title={t("reader.views.rename")}
                      onClick={() => {
                        setEditing(v.id)
                        setDraft(v.name)
                      }}
                    >
                      <Pencil />
                    </Button>
                    <Button variant="ghost" size="icon-xs" aria-label={t("common.remove")} title={t("common.remove")} onClick={() => void remove(v)}>
                      <Trash2 />
                    </Button>
                  </>
                )}
              </li>
            ))}
          </ul>
        )}
        <div className="space-y-2 border-t pt-2">
          <form
            className="flex items-center gap-1.5"
            onSubmit={(e) => {
              e.preventDefault()
              save()
            }}
          >
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={VIEW_NAME_MAX}
              placeholder={t("reader.views.namePlaceholder")}
              aria-label={t("reader.views.name")}
              className="h-8 text-sm"
              disabled={items.length >= max}
            />
            <Button type="submit" size="sm" disabled={!cleanViewName(name) || m.add.isPending || items.length >= max}>
              {m.add.isPending ? <Loader2 className="animate-spin" /> : <Plus />} {t("reader.views.save")}
            </Button>
          </form>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Switch id={`view-default-${page}`} checked={asDefault} onCheckedChange={setAsDefault} disabled={items.length >= max} />
              <Label htmlFor={`view-default-${page}`} className="text-xs" title={t("reader.views.defaultHelp")}>
                {t("reader.views.asDefault")}
              </Label>
            </div>
            <Button variant="link" size="xs" className="h-auto px-0" onClick={() => void copyWithToast(viewLink(window.location.origin, page, current), t("reader.views.copied"))}>
              <Link2 /> {t("reader.views.copyCurrent")}
            </Button>
          </div>
          {items.length >= max && <p className="text-xs text-warning">{t("reader.views.full", { count: max })}</p>}
        </div>
      </PopoverContent>
    </Popover>
  )
}

/**
 * The page's default view: applied when the page is reached from outside (the sidebar, a link) without any filter in
 * the address – not when the person clears the filters on the page (those changes carry IN_PAGE). Without a default:
 * `fallback` (e.g. the filter this browser remembered before views existed). `pending`: still deciding – the page may
 * wait with its list meanwhile (no flash of the unfiltered list).
 */
export function useDefaultView(page: ViewPage, fallback?: (params: URLSearchParams) => URLSearchParams | null): { pending: boolean } {
  const [params, setParams] = useSearchParams()
  const location = useLocation()
  const views = useViews(page)
  const wants = !hasFilter(params, page) && fromOutside(location.state)
  const settled = !!views.data || views.isError
  const def = views.data?.items.find((v) => v.default)
  const target = wants && def ? applyView(params, def.query) : null
  const fb = useRef(fallback)
  useEffect(() => {
    fb.current = fallback
  }, [fallback])
  useEffect(() => {
    if (!wants || !settled) return
    const next = target ?? fb.current?.(params) ?? null
    // only a real change: the address then carries a filter, `wants` ends – no loop
    if (next && next.toString() !== params.toString()) setParams(next, { replace: true, state: IN_PAGE })
  }, [wants, settled, target, params, setParams])
  return { pending: wants && (!settled || (!!target && target.toString() !== params.toString())) }
}
