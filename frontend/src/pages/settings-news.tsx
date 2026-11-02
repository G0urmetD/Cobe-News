import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useQueryClient } from "@tanstack/react-query"
import { CheckCircle2, ChevronRight, Loader2, Newspaper, Plus, RefreshCw, Trash2, XCircle } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Input } from "@/components/ui/input"
import { Sheet } from "@/components/ui/sheet"
import { Switch } from "@/components/ui/switch"
import { EnableCard, Field, LockedFields, ToggleRow } from "@/components/cobe/form"
import { Term, type TermKey } from "@/components/cobe/glossary"
import { Ts } from "@/components/cobe/time"
import { confirmAction } from "@/components/cobe/confirm"
import { api } from "@/lib/api"
import { errorText } from "@/lib/errors"
import { useMinute } from "@/lib/format"
import { confirmDiscard } from "@/lib/unsaved"
import { type AdminNewsSource, NEWS_CATEGORIES, type NewsCategory, type NewsSettings, useAdminNews } from "@/lib/news-api"
import { cn } from "@/lib/utils"
import { useSection } from "@/lib/settings-api"
import { Pill } from "@/components/cobe/badges"
import { SourceLogo } from "@/pages/news"
import { ConfigureLabel, IntegrationSheetContent, NumberField, SaveBar, SheetActions, SheetBody, SheetLoading } from "@/pages/settings-shared"

/** The tile under Settings → Integrations: news on or off, how many sources, and the sheet to set them up. */
export function NewsCard() {
  const { t } = useTranslation()
  // opened right away when the news page sent an admin here
  const [open, setOpen] = useState(() => typeof window !== "undefined" && window.location.hash === "#news")
  const { data } = useAdminNews()
  const on = data?.sources.filter((s) => s.enabled) ?? []
  const broken = on.filter((s) => s.error).length
  return (
    <>
      <article id="news" className="flex scroll-mt-24 flex-col gap-4 rounded-xl border bg-card p-5">
        <div className="flex items-start gap-3">
          <span className="flex size-10 items-center justify-center rounded-lg bg-muted">
            <Newspaper className="size-5" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="font-semibold">{t("nav.news")}</p>
            <p className="text-xs text-muted-foreground">{t("settings.news.desc")}</p>
          </div>
        </div>
        <div className="mt-auto flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap gap-1.5">
            <Pill color={data?.settings.enabled ? "--success" : "--muted-foreground"} dot>
              {data?.settings.enabled ? t("settings.news.on") : t("settings.news.off")}
            </Pill>
            {data?.settings.enabled && <Pill color="--muted-foreground">{t("settings.news.sourcesOn", { count: on.length })}</Pill>}
            {data?.settings.enabled && broken > 0 && <Pill color="--warning">{t("settings.news.broken", { count: broken })}</Pill>}
          </div>
          <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
            <ConfigureLabel />
          </Button>
        </div>
      </article>
      {/* mounted while it slides out; focus goes back to "Einrichten" (Radix: the element focused before) */}
      <NewsSheet open={open} onClose={() => setOpen(false)} />
    </>
  )
}

function NewsSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data, save, error, refetch } = useSection<NewsSettings>("news")
  return (
    // closing with changes not saved asks first (the form would be gone)
    <Sheet open={open} onOpenChange={(o) => !o && void confirmDiscard().then((ok) => ok && onClose())}>
      <IntegrationSheetContent icon={Newspaper} title={t("nav.news")} description={t("settings.news.desc")} help={{ chapter: "integrationen", section: "news" }}>
        {!data ? (
          <SheetLoading error={error} onRetry={refetch} />
        ) : (
          <NewsForm
            key={JSON.stringify(data)}
            initial={data}
            busy={save.isPending}
            onSave={(v) =>
              save.mutate(v, {
                onSuccess: () => {
                  void qc.invalidateQueries({ queryKey: ["admin-news"] })
                  void qc.invalidateQueries({ queryKey: ["news"] })
                },
              })
            }
          />
        )}
      </IntegrationSheetContent>
    </Sheet>
  )
}

function NewsForm({ initial, busy, onSave }: { initial: NewsSettings; busy: boolean; onSave: (v: NewsSettings) => void }) {
  const { t } = useTranslation()
  const [v, setV] = useState(initial)
  const changed = JSON.stringify(v) !== JSON.stringify(initial)
  const valid = v.every_min >= 15 && v.every_min <= 1440 && v.keep_days >= 7 && v.keep_days <= 365
  return (
    <>
      <SheetBody>
        <EnableCard label={t("settings.news.enabled")} description={t("settings.news.enabledHint")} checked={v.enabled} onCheckedChange={(x) => setV({ ...v, enabled: x })} />
        <LockedFields locked={!v.enabled}>
          <NumberField
            label={t("settings.news.every")}
            hint={t("settings.news.everyHint")}
            value={v.every_min}
            unit={t("settings.news.minutes")}
            min={15}
            max={1440}
            onChange={(x) => setV({ ...v, every_min: x })}
          />
          <NumberField
            label={t("settings.news.keep")}
            hint={t("settings.news.keepHint")}
            value={v.keep_days}
            unit={t("settings.news.days")}
            min={7}
            max={365}
            onChange={(x) => setV({ ...v, keep_days: x })}
          />
          <ToggleRow
            label={t("settings.news.details")}
            description={t("settings.news.detailsHint")}
            checked={v.details ?? true}
            onCheckedChange={(x) => setV({ ...v, details: x })}
          />
        </LockedFields>
        <Sources enabled={initial.enabled} />
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("settings.news.about")}</p>
      </SheetBody>
      <SheetActions>
        <FetchNow enabled={initial.enabled} />
        <SaveBar busy={busy} dirty={changed} disabled={!valid} onSave={() => onSave(v)} />
      </SheetActions>
    </>
  )
}

function FetchNow({ enabled }: { enabled: boolean }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [busy, setBusy] = useState(false)
  if (!enabled) return <span />
  return (
    <Button
      variant="outline"
      disabled={busy}
      onClick={async () => {
        setBusy(true)
        try {
          await api.post("/api/admin/news/fetch")
          toast.success(t("settings.news.fetching"))
          setTimeout(() => void qc.invalidateQueries({ queryKey: ["admin-news"] }), 15_000)
        } catch (e) {
          toast.error(errorText(t, e))
        } finally {
          setBusy(false)
        }
      }}
    >
      {busy ? <Loader2 className="animate-spin" /> : <RefreshCw />} {t("settings.news.fetchNow")}
    </Button>
  )
}

function Sources({ enabled }: { enabled: boolean }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data } = useAdminNews()
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["admin-news"] })
    void qc.invalidateQueries({ queryKey: ["news"] })
  }
  const patch = async (s: AdminNewsSource, enabled: boolean) => {
    try {
      await api.patch(`/api/admin/news/sources/${s.id}`, { enabled })
      refresh()
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  const remove = async (s: AdminNewsSource) => {
    if (!(await confirmAction({ title: t("settings.news.removeTitle"), text: t("settings.news.removeText", { name: s.name, count: s.items }), confirm: t("common.remove") })))
      return
    try {
      await api.del(`/api/admin/news/sources/${s.id}`)
      refresh()
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  if (!data) return null
  // about 35 sources: in groups, each folded away unless one of its sources is switched on
  const groups = NEWS_CATEGORIES.map((c) => ({ c, sources: data.sources.filter((s) => s.category === c) })).filter((g) => g.sources.length > 0)
  return (
    <section className="space-y-3">
      <h3 className="text-sm font-semibold">{t("settings.news.sourcesTitle")}</h3>
      {groups.map(({ c, sources }) => (
        <SourceGroup key={c} category={c} sources={sources}>
          {sources.map((s) => (
            <li key={s.id} className="flex items-start gap-3 px-3 py-2.5">
              <SourceLogo s={s} className="mt-0.5" />
              <div className="min-w-0 flex-1">
                <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                  <SourceName s={s} />
                  {s.lang && (
                    <Pill color="--muted-foreground" title={t(`settings.news.lang.${s.lang}`)}>
                      {s.lang.toUpperCase()}
                    </Pill>
                  )}
                  {!s.builtin && <Pill color="--muted-foreground">{t("settings.news.own")}</Pill>}
                </p>
                <p className="truncate font-mono text-[11px] text-muted-foreground" title={s.url}>
                  {s.url}
                </p>
                {enabled && s.enabled && <SourceState s={s} />}
              </div>
              <Switch checked={s.enabled} onCheckedChange={(x) => void patch(s, x)} aria-label={t("settings.news.toggle", { name: s.name })} />
              {!s.builtin && (
                <Button variant="ghost" size="icon-sm" onClick={() => void remove(s)} aria-label={t("common.remove")}>
                  <Trash2 />
                </Button>
              )}
            </li>
          ))}
        </SourceGroup>
      ))}
      <AddSource onAdded={refresh} />
    </section>
  )
}

/** The jargon in a source's name explained on hover (KEV, EUVD, PSIRT). */
const NAME_TERMS: [RegExp, TermKey][] = [
  [/\bKEV\b/, "kev"],
  [/\bEUVD\b/, "euvd"],
  [/\bPSIRT\b/, "psirt"],
]

function SourceName({ s }: { s: AdminNewsSource }) {
  const hit = s.builtin ? NAME_TERMS.map(([rx, k]) => ({ m: rx.exec(s.name), k })).find((x) => x.m) : undefined
  if (!hit?.m) return <>{s.name}</>
  const at = hit.m.index
  return (
    <span>
      {s.name.slice(0, at)}
      <Term k={hit.k}>{hit.m[0]}</Term>
      {s.name.slice(at + hit.m[0].length)}
    </span>
  )
}

/** One group of sources (authorities, catalogs, vendors …): folded away unless one of its sources is switched on. */
function SourceGroup({ category, sources, children }: { category: NewsCategory; sources: AdminNewsSource[]; children: React.ReactNode }) {
  const { t } = useTranslation()
  const on = sources.filter((s) => s.enabled).length
  const [open, setOpen] = useState(on > 0 || category === "custom")
  const hint = category === "catalog" || category === "vendor" ? t(`settings.news.catHint.${category}`) : null
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="rounded-lg border">
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm font-medium outline-none hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          <ChevronRight className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")} />
          <span className="flex-1">{t(`settings.news.cat.${category}`)}</span>
          <span className="text-xs font-normal text-muted-foreground">{t("settings.news.groupOn", { on, total: sources.length })}</span>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        {hint && (
          <p className="border-t px-3 py-2 text-xs text-muted-foreground">
            {category === "vendor" && (
              <>
                <Term k="psirt">PSIRT</Term> ·{" "}
              </>
            )}
            {hint}
          </p>
        )}
        <ul className="divide-y border-t">{children}</ul>
      </CollapsibleContent>
    </Collapsible>
  )
}

function SourceState({ s }: { s: AdminNewsSource }) {
  const { t } = useTranslation()
  const minute = useMinute() // the page's one clock: a retry time that passes disappears by itself
  if (s.error)
    return (
      // one flowing text: a long reason (403) wraps under itself, the next try follows it instead of a squeezed column
      <p className="mt-0.5 flex items-start gap-1 text-xs text-warning">
        <XCircle className="mt-px size-3.5 shrink-0" />
        <span>
          {t(`settings.news.err.${s.error.split(":")[0]}`, { defaultValue: s.error })}
          {/* a retry time already past (the round has not come yet) is no information – only one still ahead is shown */}
          {s.next_fetch_at && new Date(s.next_fetch_at).getTime() > minute * 60_000 && (
            <span className="text-muted-foreground">
              {" "}
              · {t("settings.news.nextTry")} <Ts at={s.next_fetch_at} rel />
            </span>
          )}
        </span>
      </p>
    )
  if (!s.last_ok_at) return <p className="mt-0.5 text-xs text-muted-foreground">{t("settings.news.never")}</p>
  return (
    <p className="mt-0.5 flex items-center gap-1 text-xs text-muted-foreground">
      <CheckCircle2 className="size-3.5 text-success" /> {t("settings.news.ok", { count: s.items })} · <Ts at={s.last_ok_at} rel />
    </p>
  )
}

function AddSource({ onAdded }: { onAdded: () => void }) {
  const { t } = useTranslation()
  const [name, setName] = useState("")
  const [url, setUrl] = useState("")
  const [busy, setBusy] = useState<"test" | "add" | null>(null)
  const [result, setResult] = useState<{ ok: boolean; entries?: number; newest?: string | null; error?: string | null; detail?: string } | null>(null)
  const urlOk = /^https:\/\/[^\s]+$/.test(url.trim())
  const test = async () => {
    setBusy("test")
    try {
      setResult(await api.post("/api/admin/news/test", { url: url.trim() }))
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
    }
  }
  const add = async () => {
    setBusy("add")
    try {
      await api.post("/api/admin/news/sources", { name: name.trim(), url: url.trim() })
      toast.success(t("settings.news.added"))
      setName("")
      setUrl("")
      setResult(null)
      onAdded()
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
    }
  }
  return (
    <div className="space-y-3 rounded-lg border border-dashed p-3">
      <p className="text-sm font-medium">{t("settings.news.addTitle")}</p>
      <div className="grid gap-3 sm:grid-cols-[1fr_2fr]">
        <Field label={t("settings.news.name")}>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="CERT Blog" maxLength={100} />
        </Field>
        <Field label={t("settings.news.url")} hint={t("settings.news.urlHint")}>
          <Input
            value={url}
            onChange={(e) => {
              setUrl(e.target.value)
              setResult(null)
            }}
            placeholder="https://example.org/feed.xml"
            aria-invalid={!!url && !urlOk}
          />
        </Field>
      </div>
      {result && (
        <p className={result.ok ? "text-xs text-success" : "text-xs text-destructive"}>
          {result.ok
            ? t("settings.news.testOk", { count: result.entries, newest: result.newest })
            : t(`settings.news.err.${result.error}`, { defaultValue: `${result.error}${result.detail ? `: ${result.detail}` : ""}` })}
        </p>
      )}
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="outline" size="sm" disabled={!urlOk || busy !== null} onClick={() => void test()}>
          {busy === "test" && <Loader2 className="animate-spin" />} {t("settings.news.test")}
        </Button>
        <Button size="sm" disabled={!urlOk || name.trim().length < 2 || busy !== null} onClick={() => void add()}>
          {busy === "add" ? <Loader2 className="animate-spin" /> : <Plus />} {t("settings.news.add")}
        </Button>
      </div>
    </div>
  )
}
