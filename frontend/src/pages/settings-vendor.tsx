import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link, useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import { Activity, CheckCircle2, ClipboardCheck, Layers, Library, Loader2, RefreshCw, Settings2, ShieldAlert, Stethoscope, XCircle } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet } from "@/components/ui/sheet"
import { Pill } from "@/components/cobe/badges"
import { EnableCard, Field, LockedFields, ToggleRow } from "@/components/cobe/form"
import { Explained } from "@/components/cobe/explained"
import { Term, type TermKey } from "@/components/cobe/glossary"
import { EmptyState, MoreText } from "@/components/cobe/common"
import { SubTabs } from "@/components/cobe/sub-tabs"
import { Ts } from "@/components/cobe/time"
import { api } from "@/lib/api"
import { CARE_COLOR, type CareStatus, careItems, careReason, useCatalogCare } from "@/lib/catalog-care"
import { docPath } from "@/lib/docs"
import { errorText } from "@/lib/errors"
import { HEALTH_KEY } from "@/lib/source-health"
import { confirmDiscard } from "@/lib/unsaved"
import { cn } from "@/lib/utils"
import { STRUCTURED_SOURCES, type StructuredSource, type VendorAdmin, type VendorSettings, useVendorAdmin } from "@/lib/vendor-api"
import { REVIEW_CHOICES } from "@/lib/version-review"
import { ConfigureLabel, IntegrationSheetContent, NumberField, SaveBar, SheetActions, SheetBody, SheetLoading } from "@/pages/settings-shared"

/** The tile under Settings → Integrations: Vendor News on or off, the sources' state, the sheet to set it up. */
export function VendorCard() {
  const { t } = useTranslation()
  const [params, setParams] = useSearchParams()
  const [open, setOpen] = useState(() => (typeof window !== "undefined" && window.location.hash === "#vendor") || params.has("vendor"))
  const { data } = useVendorAdmin()
  const care = useCatalogCare()
  const broken = data?.sources.filter((s) => s.error).length ?? 0
  const needCare = care.data ? care.data.followed_counts.error + care.data.followed_counts.warn : 0
  const close = () => {
    setOpen(false)
    if (params.has("vendor"))
      setParams(
        (p) => {
          const next = new URLSearchParams(p)
          next.delete("vendor")
          return next
        },
        { replace: true },
      )
  }
  return (
    <>
      <article id="vendor" className="flex scroll-mt-24 flex-col gap-4 rounded-xl border bg-card p-5">
        <div className="flex items-start gap-3">
          <span className="flex size-10 items-center justify-center rounded-lg bg-muted">
            <ShieldAlert className="size-5" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="font-semibold">{t("nav.vendor")}</p>
            <p className="text-xs text-muted-foreground">{t("settings.vendor.desc")}</p>
          </div>
        </div>
        <div className="mt-auto flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap gap-1.5">
            <Pill color={data?.settings.enabled ? "--success" : "--muted-foreground"} dot>
              {data?.settings.enabled ? t("settings.news.on") : t("settings.news.off")}
            </Pill>
            {data && <Pill color="--muted-foreground">{t("settings.vendor.products", { count: data.catalog.products })}</Pill>}
            {data?.settings.nvd_key_set && <Pill color="--muted-foreground">{t("settings.vendor.keySet")}</Pill>}
            {broken > 0 && <Pill color="--warning">{t("settings.news.broken", { count: broken })}</Pill>}
            {needCare > 0 && (
              <Link to="?vendor=care" onClick={() => setOpen(true)} className="rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
                <Pill color="--warning">{t("vendor.care.badge", { count: needCare })}</Pill>
              </Link>
            )}
          </div>
          <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
            <ConfigureLabel />
          </Button>
        </div>
      </article>
      <VendorSheet open={open} onClose={close} />
    </>
  )
}

function VendorSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const q = useVendorAdmin(open)
  const care = useCatalogCare(open)
  const [params] = useSearchParams()
  // three parts: the settings | the structured sources (?vendor=sources – the health page links there) | Katalog-Pflege
  // (?vendor=care – a link from a product's drawer opens it directly)
  const view = params.get("vendor") === "care" ? "care" : params.get("vendor") === "sources" ? "sources" : "settings"
  const needCare = care.data ? care.data.followed_counts.error + care.data.followed_counts.warn : 0
  const to = (k: "settings" | "sources" | "care") => {
    const next = new URLSearchParams(params)
    next.set("vendor", k)
    return `?${next.toString()}`
  }
  return (
    <Sheet open={open} onOpenChange={(o) => !o && void confirmDiscard().then((ok) => ok && onClose())}>
      <IntegrationSheetContent
        icon={ShieldAlert}
        title={t("nav.vendor")}
        description={t("settings.vendor.desc")}
        help={
          view === "care"
            ? { chapter: "vendor-news", section: "katalog-pflege" }
            : view === "sources"
              ? { chapter: "integrationen", section: "weitere-quellen" }
              : { chapter: "integrationen", section: "vendor-news" }
        }
      >
        <div className="border-b px-4 py-2">
          <SubTabs
            parts={[
              { key: "settings" as const, icon: Settings2, label: t("vendor.care.tabSettings") },
              { key: "sources" as const, icon: Layers, label: t("vendor.src.tab") },
              { key: "care" as const, icon: Stethoscope, label: t("vendor.care.tab"), count: needCare || undefined },
            ]}
            active={view}
            to={to}
            label={t("vendor.care.tabs")}
          />
        </div>
        {view === "care" ? (
          <CatalogCarePane enabled={!!q.data?.settings.enabled} />
        ) : view === "sources" ? (
          !q.data ? (
            <SheetLoading error={q.error} onRetry={() => void q.refetch()} />
          ) : (
            <SourcesForm key={JSON.stringify(q.data.settings)} data={q.data} />
          )
        ) : !q.data ? (
          <SheetLoading error={q.error} onRetry={() => void q.refetch()} />
        ) : (
          <VendorForm key={JSON.stringify(q.data.settings)} data={q.data} />
        )}
      </IntegrationSheetContent>
    </Sheet>
  )
}

// "nur gefolgte", per browser – a convenience (blocked storage: the followed ones)
const CARE_ALL_KEY = "cobe-news.care.all"
function readAll(): boolean {
  try {
    return localStorage.getItem(CARE_ALL_KEY) === "1"
  } catch {
    return false
  }
}

/** Katalog-Pflege: the catalogue entries that need care, with the reasons; the state of the self-test; "Jetzt prüfen". */
function CatalogCarePane({ enabled }: { enabled: boolean }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useCatalogCare()
  const [all, setAll] = useState(readAll)
  const [busy, setBusy] = useState(false)
  const later = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(
    () => () => {
      if (later.current) clearTimeout(later.current)
    },
    [],
  )
  if (!q.data) return <SheetLoading error={q.error} onRetry={() => void q.refetch()} />
  const d = q.data
  const items = careItems(d, !all)
  const counts = all ? d.counts : d.followed_counts
  const check = async () => {
    setBusy(true)
    try {
      await api.post("/api/admin/vendor/catalog-check")
      toast.success(t("vendor.care.checking"))
      if (later.current) clearTimeout(later.current)
      later.current = setTimeout(() => void qc.invalidateQueries({ queryKey: ["vendor"] }), 15_000)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const order: CareStatus[] = ["error", "warn", "ok", "unchecked"]
  return (
    <>
      <SheetBody>
        <section className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <ClipboardCheck className="size-4 text-primary" /> {t("vendor.care.title")}
          </h3>
          <p className="text-xs text-muted-foreground">
            <MoreText>{t("vendor.care.intro", { budget: d.budget_per_hour })}</MoreText>
          </p>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
            <dt className="text-muted-foreground">{t("vendor.care.lastRun")}</dt>
            <dd>{d.last_run_at ? <Ts at={d.last_run_at} rel /> : t("vendor.care.never")}</dd>
            <dt className="text-muted-foreground">
              <Explained label={t("vendor.catalogVersion")} text={t("vendor.catalogVersionHint")} />
            </dt>
            <dd className="font-mono tabular-nums">{d.catalog_version}</dd>
          </dl>
          <p className="text-xs text-muted-foreground tabular-nums">{t("vendor.care.progress", { checked: d.cpes.checked, total: d.cpes.total })}</p>
          {d.last_stop && <p className="text-xs text-muted-foreground">{t(`vendor.care.stop.${d.last_stop}`, { defaultValue: "" })}</p>}
        </section>
        <div className="flex flex-wrap gap-1.5">
          {order.map((s) => (
            <span key={s} title={t(`vendor.care.statusHelp.${s}`)}>
              <Pill color={CARE_COLOR[s]} dot>
                <span className="tabular-nums">{counts[s] ?? 0}</span> {t(`vendor.care.status.${s}`)}
              </Pill>
            </span>
          ))}
        </div>
        <ToggleRow
          className="border-y py-2.5"
          label={t("vendor.care.onlyFollowed")}
          checked={!all}
          onCheckedChange={(v) => {
            setAll(!v)
            try {
              localStorage.setItem(CARE_ALL_KEY, v ? "0" : "1")
            } catch {
              /* ignore */
            }
          }}
        />
        {items.length === 0 ? (
          <EmptyState icon={CheckCircle2} title={all ? t("vendor.care.empty") : t("vendor.care.emptyFollowed")} />
        ) : (
          <ul className="divide-y rounded-lg border" aria-label={t("vendor.care.title")}>
            {items.map((i) => (
              <li key={i.product} className="space-y-1.5 px-3 py-2.5">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  {i.in_catalog ? (
                    <Link to={`/vendor?tab=catalog&product=${encodeURIComponent(i.product)}`} className="min-w-0 text-sm font-medium break-words hover:underline">
                      {i.label}
                    </Link>
                  ) : (
                    <span className="min-w-0 text-sm font-medium break-words">{i.label}</span>
                  )}
                  <span title={t(`vendor.care.statusHelp.${i.status}`)}>
                    <Pill color={CARE_COLOR[i.status]} dot>
                      {t(`vendor.care.status.${i.status}`)}
                    </Pill>
                  </span>
                  {i.followed && <Pill color="--primary">{t("vendor.care.followed")}</Pill>}
                  {!i.in_catalog && <Pill color="--muted-foreground">{t("vendor.care.notInCatalog")}</Pill>}
                </div>
                <p className="truncate font-mono text-[11px] text-muted-foreground" title={i.product}>
                  {i.vendor ? `${i.vendor} · ` : ""}
                  {i.product}
                </p>
                <ul className="space-y-0.5 text-xs">
                  {i.reasons.map((r, n) => (
                    <li key={n} className={cn("flex gap-1.5 break-words", r.level === "error" ? "text-sev-critical" : "text-foreground/90")}>
                      <XCircle className={cn("mt-0.5 size-3.5 shrink-0", r.level === "error" ? "text-sev-critical" : "text-warning")} />
                      <span className="min-w-0">{careReason(t, r)}</span>
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        )}
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">
          {t("vendor.care.howToFix")}{" "}
          <Link to={docPath("vendor-news", "eintrag-korrigieren")} className="font-medium text-primary underline-offset-2 hover:underline">
            {t("vendor.care.howToFixLink")}
          </Link>
          .
        </p>
      </SheetBody>
      <SheetActions>
        <span />
        <Button variant="outline" disabled={!enabled || busy || d.running} title={!enabled ? t("vendor.care.checkOff") : t("vendor.care.checkHint")} onClick={() => void check()}>
          {busy || d.running ? <Loader2 className="animate-spin" /> : <RefreshCw />} {t("vendor.care.check")}
        </Button>
      </SheetActions>
    </>
  )
}

type Form = VendorSettings & { nvd_key: string; clear_nvd_key: boolean }

function VendorForm({ data }: { data: VendorAdmin }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const initial: Form = { ...data.settings, nvd_key: "", clear_nvd_key: false }
  const [v, setV] = useState<Form>(initial)
  const [busy, setBusy] = useState<"save" | "fetch" | "catalog" | null>(null)
  const dirty = JSON.stringify(v) !== JSON.stringify(initial)
  // the structured sources' queries are listed in their own tab
  const own = data.sources.filter((s) => !isStructured(s.key))
  const valid = v.every_h >= 1 && v.every_h <= 48 && v.eol_every_h >= 6 && v.eol_every_h <= 168 && /^[A-Za-z0-9-]*$/.test(v.nvd_key)
  const refresh = () => void qc.invalidateQueries({ queryKey: ["vendor"] })
  // a second look after the server's background work – dropped when the drawer closes before
  const later = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(
    () => () => {
      if (later.current) clearTimeout(later.current)
    },
    [],
  )
  const run = async (what: "save" | "fetch" | "catalog") => {
    setBusy(what)
    try {
      if (what === "save") {
        await api.put("/api/admin/vendor", {
          enabled: v.enabled,
          every_h: v.every_h,
          eol_every_h: v.eol_every_h,
          nvd_key: v.nvd_key,
          clear_nvd_key: v.clear_nvd_key,
          review_days: v.review_days,
          rev: v.rev,
        })
        toast.success(t("common.saved"))
      } else if (what === "fetch") {
        await api.post("/api/admin/vendor/fetch")
        toast.success(t("settings.vendor.fetching"))
      } else {
        await api.post("/api/admin/vendor/catalog")
        toast.success(t("settings.vendor.catalogRefreshing"))
      }
      refresh()
      if (later.current) clearTimeout(later.current)
      later.current = setTimeout(refresh, 20_000)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
    }
  }
  return (
    <>
      <SheetBody>
        <EnableCard label={t("settings.vendor.enabled")} description={t("settings.vendor.enabledHint")} checked={v.enabled} onCheckedChange={(x) => setV({ ...v, enabled: x })} />
        <LockedFields locked={!v.enabled} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <NumberField
              label={t("settings.vendor.every")}
              hint={t("settings.vendor.everyHint")}
              value={v.every_h}
              unit={t("settings.vendor.hours")}
              min={1}
              max={48}
              onChange={(x) => setV({ ...v, every_h: x })}
            />
            <NumberField
              label={t("settings.vendor.eolEvery")}
              hint={t("settings.vendor.eolEveryHint")}
              value={v.eol_every_h}
              unit={t("settings.vendor.hours")}
              min={6}
              max={168}
              onChange={(x) => setV({ ...v, eol_every_h: x })}
            />
          </div>
          <Field label={t("settings.vendor.nvdKey")} hint={t(data.settings.nvd_key_set ? "settings.vendor.nvdKeySet" : "settings.vendor.nvdKeyHint")}>
            <div className="flex gap-2">
              <Input
                type="password"
                autoComplete="off"
                value={v.nvd_key}
                onChange={(e) => setV({ ...v, nvd_key: e.target.value.trim(), clear_nvd_key: false })}
                placeholder={data.settings.nvd_key_set ? "••••••••" : "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}
                aria-invalid={!/^[A-Za-z0-9-]*$/.test(v.nvd_key) || undefined}
              />
              {data.settings.nvd_key_set && (
                <Button variant="outline" onClick={() => setV({ ...v, nvd_key: "", clear_nvd_key: !v.clear_nvd_key })}>
                  {v.clear_nvd_key ? t("settings.vendor.keepKey") : t("common.remove")}
                </Button>
              )}
            </div>
          </Field>
          {/* Versionen prüfen: entries not confirmed for longer are shown as "bitte prüfen" (app/catalog_care.py) */}
          <Field label={t("review.setting")} hint={t("review.settingHint")}>
            <Select value={String(v.review_days ?? 90)} onValueChange={(x) => setV({ ...v, review_days: Number(x) })}>
              <SelectTrigger className="w-full sm:w-64">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                {REVIEW_CHOICES.map((d) => (
                  <SelectItem key={d} value={String(d)}>
                    {d ? t("review.every", { count: d }) : t("review.off")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        </LockedFields>
        <section className="space-y-2">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-sm font-semibold">{t("settings.vendor.catalog")}</h3>
            <Button variant="outline" size="sm" disabled={!data.settings.enabled || busy !== null} onClick={() => void run("catalog")}>
              {busy === "catalog" ? <Loader2 className="animate-spin" /> : <Library />} {t("settings.vendor.catalogRefresh")}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            {t("settings.vendor.catalogState", { count: data.catalog.products })} <Ts at={data.catalog.generated_at} />
          </p>
        </section>
        <section className="space-y-2">
          <h3 className="text-sm font-semibold">{t("settings.vendor.sources")}</h3>
          {own.length === 0 ? (
            <p className="text-xs text-muted-foreground">{t("settings.vendor.noSources")}</p>
          ) : (
            <ul className="divide-y rounded-lg border">
              {own.map((s) => (
                <li key={s.key} className="px-3 py-2">
                  <p className="truncate font-mono text-[11px]" title={s.key}>
                    {s.key}
                  </p>
                  {s.error ? (
                    <p className="mt-0.5 flex items-center gap-1 text-xs text-warning">
                      <XCircle className="size-3.5" /> {t(`settings.news.err.${s.error.split(":")[0]}`, { defaultValue: s.error })}
                      {s.next_fetch_at && (
                        <span className="text-muted-foreground">
                          · {t("settings.news.nextTry")} <Ts at={s.next_fetch_at} rel />
                        </span>
                      )}
                    </p>
                  ) : s.last_ok_at ? (
                    <p className="mt-0.5 flex items-center gap-1 text-xs text-muted-foreground">
                      <CheckCircle2 className="size-3.5 text-success" /> <Ts at={s.last_ok_at} rel />
                      {s.next_fetch_at && (
                        <>
                          · {t("settings.vendor.next")} <Ts at={s.next_fetch_at} rel />
                        </>
                      )}
                    </p>
                  ) : (
                    <p className="mt-0.5 text-xs text-muted-foreground">{t("settings.news.never")}</p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("settings.vendor.about")}</p>
      </SheetBody>
      <SheetActions>
        <Button variant="outline" disabled={!data.settings.enabled || busy !== null} onClick={() => void run("fetch")}>
          {busy === "fetch" ? <Loader2 className="animate-spin" /> : <RefreshCw />} {t("settings.news.fetchNow")}
        </Button>
        <SaveBar busy={busy === "save"} dirty={dirty} disabled={!valid} onSave={() => void run("save")} />
      </SheetActions>
    </>
  )
}

const STRUCTURED_PREFIX: Record<StructuredSource, string> = { csaf: "csaf:", cvelist: "cvelist:", epss: "epss:", osv: "osv:" }
const STRUCTURED_TERM: Partial<Record<StructuredSource, [TermKey, string]>> = { csaf: ["csaf", "CSAF"], epss: ["epss", "EPSS"], osv: ["osv", "OSV"] }
const isStructured = (key: string) => Object.values(STRUCTURED_PREFIX).some((p) => key.startsWith(p))

/** One query's state, as in the settings tab: the error with the next try, else the last success. */
function QueryState({ s }: { s: VendorAdmin["sources"][number] }) {
  const { t } = useTranslation()
  if (s.error)
    return (
      <p className="flex flex-wrap items-center gap-1 text-xs text-warning">
        <XCircle className="size-3.5" /> {t(`settings.news.err.${s.error.split(":")[0]}`, { defaultValue: s.error })}
        {s.next_fetch_at && (
          <span className="text-muted-foreground">
            · {t("settings.news.nextTry")} <Ts at={s.next_fetch_at} rel />
          </span>
        )}
      </p>
    )
  if (s.last_ok_at)
    return (
      <p className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
        <CheckCircle2 className="size-3.5 text-success" /> <Ts at={s.last_ok_at} rel />
        {s.next_fetch_at && (
          <>
            · {t("settings.vendor.next")} <Ts at={s.next_fetch_at} rel />
          </>
        )}
      </p>
    )
  return <p className="text-xs text-muted-foreground">{t("settings.news.never")}</p>
}

/** Weitere Quellen: the structured sources (CSAF providers, cvelistV5, EPSS, OSV), each on or off, what leaves the
 *  machine, the state of their queries. Saved with the same settings (and their `rev`) as the main tab. */
function SourcesForm({ data }: { data: VendorAdmin }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const initial = Object.fromEntries(STRUCTURED_SOURCES.map((k) => [k, data.settings[k] ?? true])) as Record<StructuredSource, boolean>
  const [v, setV] = useState(initial)
  const [busy, setBusy] = useState(false)
  const dirty = JSON.stringify(v) !== JSON.stringify(initial)
  const save = async () => {
    setBusy(true)
    try {
      const st = data.settings
      await api.put("/api/admin/vendor", { enabled: st.enabled, every_h: st.every_h, eol_every_h: st.eol_every_h, ...v, rev: st.rev })
      toast.success(t("common.saved"))
      void qc.invalidateQueries({ queryKey: ["vendor"] })
      void qc.invalidateQueries({ queryKey: HEALTH_KEY })
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const providers = data.structured?.csaf_providers ?? []
  return (
    <>
      <SheetBody>
        <section className="space-y-1">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Layers className="size-4 text-primary" /> {t("vendor.src.title")}
          </h3>
          <p className="text-xs text-muted-foreground">
            <MoreText>{t("vendor.src.intro")}</MoreText>
          </p>
        </section>
        {!data.settings.enabled && <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("vendor.src.offVendor")}</p>}
        <LockedFields locked={!data.settings.enabled} className="divide-y rounded-lg border px-3.5">
          {STRUCTURED_SOURCES.map((k) => {
            const queries = data.sources.filter((s) => s.key.startsWith(STRUCTURED_PREFIX[k]))
            return (
              <ToggleRow
                key={k}
                label={t(`vendor.src.${k}`)}
                description={
                  <>
                    {STRUCTURED_TERM[k] && (
                      <>
                        <Term k={STRUCTURED_TERM[k][0]}>{STRUCTURED_TERM[k][1]}</Term>
                        {" – "}
                      </>
                    )}
                    {t(`vendor.src.${k}Hint`)}
                    <span className="mt-1 block text-foreground/80">{t("vendor.src.leaves", { what: t(`vendor.src.leaves.${k}`) })}</span>
                  </>
                }
                checked={v[k]}
                onCheckedChange={(x) => setV({ ...v, [k]: x })}
              >
                {k === "csaf" && providers.length > 0 && (
                  <div className="space-y-1">
                    <p className="text-xs font-medium">
                      <Explained label={t("vendor.src.providers")} text={t("glossary.tlpText")} />
                    </p>
                    <ul className="space-y-1">
                      {providers.map((p) => (
                        <li key={p.key} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs" title={`${p.domain} · ${p.vendors.join(", ")}`}>
                          <span className="min-w-0 break-words">{p.name}</span>
                          <Pill color={p.needed && v.csaf ? "--success" : "--muted-foreground"} dot>
                            {p.needed ? t("vendor.src.providerActive") : t("vendor.src.providerIdle")}
                          </Pill>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {k === "osv" && data.structured && <p className="text-xs text-muted-foreground">{t("vendor.src.osvProducts", { count: data.structured.osv_products })}</p>}
                {queries.length > 0 && (
                  <ul className="divide-y rounded-lg border" aria-label={t("vendor.src.queries")}>
                    {queries.map((s) => (
                      <li key={s.key} className="px-3 py-2">
                        <p className="truncate font-mono text-[11px]" title={s.key}>
                          {s.key}
                        </p>
                        <QueryState s={s} />
                      </li>
                    ))}
                  </ul>
                )}
              </ToggleRow>
            )
          })}
        </LockedFields>
        <Link
          to={`/settings/integrations?view=health&source=${encodeURIComponent("structured:cvelist")}`}
          className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline"
        >
          <Activity className="size-3.5" /> {t("vendor.src.health")}
        </Link>
      </SheetBody>
      <SheetActions>
        <span />
        <SaveBar busy={busy} dirty={dirty} disabled={!data.settings.enabled} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}
