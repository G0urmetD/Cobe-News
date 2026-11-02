import { useEffect, useMemo, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { useQueryClient } from "@tanstack/react-query"
import { Ban, Check, Copy, CopyCheck, ExternalLink, Inbox, Lightbulb, Loader2, MessageSquarePlus, PackagePlus, Search, Send, UsersRound } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Textarea } from "@/components/ui/textarea"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Pill } from "@/components/cobe/badges"
import { EmptyState } from "@/components/cobe/common"
import { Field } from "@/components/cobe/form"
import { Term } from "@/components/cobe/glossary"
import { QueryError } from "@/components/cobe/query-state"
import { Ts } from "@/components/cobe/time"
import { api } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { copyWithToast } from "@/lib/clipboard"
import { errorText } from "@/lib/errors"
import {
  SUGGESTIONS_KEY,
  SUGGEST_LIMITS,
  type Suggestion,
  type SuggestionIn,
  type SuggestionStatus,
  safeHttpUrl,
  similarProducts,
  suggestProblems,
  useMySuggestions,
  useSuggestionQueue,
  yamlSnippet,
} from "@/lib/suggestions"
import { useMyTeams } from "@/lib/teams-api"
import { matchScore, useVendorCatalog, type VendorProduct } from "@/lib/vendor-api"
import { cn } from "@/lib/utils"

const STATUS_TONE: Record<SuggestionStatus, string> = { open: "--primary", accepted: "--success", rejected: "--muted-foreground", duplicate: "--warning" }

/** "Produkt fehlt? Vorschlagen" – the button where somebody notices a missing product. */
export function SuggestButton({ onClick, className, variant = "outline" }: { onClick: () => void; className?: string; variant?: "outline" | "ghost" | "link" }) {
  const { t } = useTranslation()
  return (
    <Button variant={variant} size="sm" className={className} onClick={onClick}>
      <Lightbulb /> {t("suggest.missing")}
    </Button>
  )
}

// ---------------------------------------------------------------- the form

const NO_TEAM = "none"

/** Suggest a product: vendor, name, an optional address and CPE, why, an optional team – with "Meinst du …?" first. */
export function SuggestSheet({ open, onClose, initial, onOpen }: { open: boolean; onClose: () => void; initial?: string; onOpen: (key: string) => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const cat = useVendorCatalog()
  const teams = useMyTeams()
  const myTeams = teams.data?.enabled ? teams.data.teams : []
  const [v, setV] = useState<SuggestionIn>({ vendor: "", product: initial ?? "", url: "", cpe: "", reason: "", team_id: null })
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const problems = suggestProblems(v)
  const similar = useMemo(() => similarProducts(cat.data?.products ?? [], v.vendor, v.product), [cat.data, v.vendor, v.product])
  const bad = (k: (typeof problems)[number]) => (touched || !!(v[k] ?? "").toString().trim()) && problems.includes(k)
  const send = async () => {
    setTouched(true)
    if (problems.length) return
    setBusy(true)
    try {
      await api.post("/api/vendor/suggestions", { ...v, url: v.url?.trim() || null, cpe: v.cpe?.trim() || null, team_id: v.team_id || null })
      toast.success(t("suggest.sent"))
      void qc.invalidateQueries({ queryKey: SUGGESTIONS_KEY })
      onClose()
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-lg">
        <SheetHeader className="border-b">
          <SheetTitle className="flex items-center gap-2">
            <MessageSquarePlus className="size-4" /> {t("suggest.title")}
          </SheetTitle>
          <SheetDescription>{t("suggest.desc")}</SheetDescription>
        </SheetHeader>
        <form
          id="suggest-form"
          className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4"
          onSubmit={(e) => {
            e.preventDefault()
            void send()
          }}
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("suggest.vendor")}>
              <Input
                value={v.vendor}
                onChange={(e) => setV({ ...v, vendor: e.target.value })}
                maxLength={SUGGEST_LIMITS.vendor}
                placeholder="Example Corp"
                aria-invalid={bad("vendor") || undefined}
              />
            </Field>
            <Field label={t("suggest.product")}>
              <Input
                value={v.product}
                onChange={(e) => setV({ ...v, product: e.target.value })}
                maxLength={SUGGEST_LIMITS.product}
                placeholder="Edge Gateway"
                aria-invalid={bad("product") || undefined}
              />
            </Field>
          </div>
          {similar.length > 0 && (
            <div className="space-y-1.5 rounded-lg border border-primary/30 bg-primary/5 p-3" role="status">
              <p className="text-xs font-medium">{t("suggest.similar")}</p>
              <ul className="space-y-1">
                {similar.map((p) => (
                  <li key={p.key}>
                    <button
                      type="button"
                      onClick={() => {
                        onClose()
                        onOpen(p.key)
                      }}
                      className="flex w-full min-w-0 items-baseline gap-2 rounded px-1 py-0.5 text-left text-sm outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring/50"
                    >
                      <span className="truncate font-medium">{p.label}</span>
                      <span className="truncate text-xs text-muted-foreground">{p.vendor}</span>
                    </button>
                  </li>
                ))}
              </ul>
              <p className="text-[11px] text-muted-foreground">{t("suggest.similarHint")}</p>
            </div>
          )}
          <Field label={t("suggest.url")} hint={t("suggest.urlHint")}>
            <Input
              type="url"
              inputMode="url"
              value={v.url ?? ""}
              onChange={(e) => setV({ ...v, url: e.target.value })}
              maxLength={SUGGEST_LIMITS.url}
              placeholder="https://www.example.com/security"
              aria-invalid={bad("url") || undefined}
            />
          </Field>
          <Field label={<Term k="cpe">{t("suggest.cpe")}</Term>} hint={t("suggest.cpeHint")}>
            <Input
              value={v.cpe ?? ""}
              onChange={(e) => setV({ ...v, cpe: e.target.value })}
              maxLength={SUGGEST_LIMITS.cpe}
              placeholder="a:vendor:product"
              className="font-mono"
              aria-invalid={bad("cpe") || undefined}
            />
          </Field>
          <Field label={t("suggest.reason")} hint={t("suggest.reasonHint", { max: SUGGEST_LIMITS.reason })}>
            <Textarea
              value={v.reason}
              onChange={(e) => setV({ ...v, reason: e.target.value })}
              maxLength={SUGGEST_LIMITS.reason}
              rows={3}
              aria-invalid={bad("reason") || undefined}
            />
          </Field>
          {myTeams.length > 0 && (
            <Field label={t("suggest.team")} hint={t("suggest.teamHint")}>
              <Select value={v.team_id ?? NO_TEAM} onValueChange={(x) => setV({ ...v, team_id: x === NO_TEAM ? null : x })}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper">
                  <SelectItem value={NO_TEAM}>{t("suggest.noTeam")}</SelectItem>
                  {myTeams.map((x) => (
                    <SelectItem key={x.id} value={x.id}>
                      {x.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          )}
          {touched && problems.length > 0 && <p className="text-xs text-destructive">{t("suggest.fix", { fields: problems.map((p) => t(`suggest.${p}`)).join(", ") })}</p>}
        </form>
        <SheetFooter className="flex-row flex-wrap items-center justify-end gap-2 border-t bg-popover">
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" form="suggest-form" disabled={busy}>
            {busy ? <Loader2 className="animate-spin" /> : <Send />} {t("suggest.send")}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

// ---------------------------------------------------------------- the tab: own suggestions, the admins' queue

type Part = "open" | "done" | "mine"

/** "Vorschläge": the own suggestions with their answers – and for admins the queue (open, answered). */
export function SuggestionsTab({ onOpen, onSuggest, onAdopt }: { onOpen: (key: string) => void; onSuggest: () => void; onAdopt: (s: Suggestion) => void }) {
  const { t } = useTranslation()
  const { isAdmin } = useAuth()
  const [part, setPart] = useState<Part>(isAdmin ? "open" : "mine")
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {isAdmin && (
          <ToggleGroup type="single" variant="outline" size="sm" spacing={0} value={part} onValueChange={(v) => v && setPart(v as Part)} aria-label={t("suggest.tab")}>
            <ToggleGroupItem value="open">{t("suggest.queueOpen")}</ToggleGroupItem>
            <ToggleGroupItem value="done">{t("suggest.queueDone")}</ToggleGroupItem>
            <ToggleGroupItem value="mine">{t("suggest.mine")}</ToggleGroupItem>
          </ToggleGroup>
        )}
        <Button size="sm" className="ml-auto" onClick={onSuggest}>
          <MessageSquarePlus /> {t("suggest.title")}
        </Button>
      </div>
      {part === "mine" ? <Mine onOpen={onOpen} /> : <Queue state={part} onOpen={onOpen} onAdopt={onAdopt} />}
    </div>
  )
}

function Mine({ onOpen }: { onOpen: (key: string) => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useMySuggestions()
  const items = q.data?.items
  // the answers were seen: the number on the tab goes (once per load with unseen ones)
  const marked = useRef(false)
  useEffect(() => {
    if (marked.current || !items?.some((s) => s.status !== "open" && !s.seen)) return
    marked.current = true
    void api.post("/api/vendor/suggestions/seen").then(
      () => qc.invalidateQueries({ queryKey: [...SUGGESTIONS_KEY, "count"] }),
      () => undefined,
    )
  }, [items, qc])
  if (q.isError && !q.data) return <QueryError error={q.error} onRetry={() => void q.refetch()} />
  if (!items)
    return (
      <p className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> {t("vendor.loading")}
      </p>
    )
  if (!items.length) return <EmptyState icon={Lightbulb} title={t("suggest.mineEmpty")} text={t("suggest.mineEmptyText", { count: q.data?.per_day ?? 10 })} />
  return (
    <ul className="space-y-3" aria-label={t("suggest.mine")}>
      {items.map((s) => (
        <SuggestionCard key={s.id} s={s} onOpen={onOpen} fresh={s.status !== "open" && !s.seen} />
      ))}
    </ul>
  )
}

function Queue({ state, onOpen, onAdopt }: { state: "open" | "done"; onOpen: (key: string) => void; onAdopt: (s: Suggestion) => void }) {
  const { t } = useTranslation()
  const q = useSuggestionQueue(state)
  const [deciding, setDeciding] = useState<{ s: Suggestion; mode: Mode } | null>(null)
  if (q.isError && !q.data) return <QueryError error={q.error} onRetry={() => void q.refetch()} />
  if (!q.data)
    return (
      <p className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> {t("vendor.loading")}
      </p>
    )
  if (!q.data.items.length) return <EmptyState icon={Inbox} title={t(state === "open" ? "suggest.queueEmpty" : "suggest.doneEmpty")} />
  return (
    <>
      <ul className="space-y-3" aria-label={t(state === "open" ? "suggest.queueOpen" : "suggest.queueDone")}>
        {q.data.items.map((s) => (
          <SuggestionCard
            key={s.id}
            s={s}
            onOpen={onOpen}
            admin
            actions={
              s.status === "open" && (
                <>
                  <Button size="sm" onClick={() => setDeciding({ s, mode: "accept" })}>
                    <PackagePlus /> {t("suggest.accept")}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => setDeciding({ s, mode: "duplicate" })}>
                    <CopyCheck /> {t("suggest.duplicate")}
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setDeciding({ s, mode: "reject" })}>
                    <Ban /> {t("suggest.reject")}
                  </Button>
                </>
              )
            }
          />
        ))}
      </ul>
      {deciding && (
        <DecideSheet
          key={deciding.s.id + deciding.mode}
          s={deciding.s}
          mode={deciding.mode}
          onClose={() => setDeciding(null)}
          onAdopt={(s) => {
            setDeciding(null)
            onAdopt(s)
          }}
        />
      )}
    </>
  )
}

function SuggestionCard({
  s,
  onOpen,
  admin = false,
  fresh = false,
  actions,
}: {
  s: Suggestion
  onOpen: (key: string) => void
  admin?: boolean
  fresh?: boolean
  actions?: React.ReactNode
}) {
  const { t } = useTranslation()
  const href = safeHttpUrl(s.url)
  return (
    <li className={cn("space-y-2 rounded-xl border bg-card p-3.5", fresh && "border-primary/50 ring-1 ring-primary/30")}>
      <div className="flex flex-wrap items-start gap-2">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold [overflow-wrap:anywhere]">
            {s.vendor} · {s.product}
          </p>
          <p className="flex flex-wrap items-center gap-x-1.5 text-xs text-muted-foreground">
            {s.created_at && <Ts at={s.created_at} rel />}
            {admin && s.by && <span>· {t("suggest.byName", { name: s.by })}</span>}
            {s.team && (
              <span className="inline-flex items-center gap-1">
                · <UsersRound className="size-3" /> {s.team.name}
              </span>
            )}
          </p>
        </div>
        <Pill color={STATUS_TONE[s.status]} dot>
          {t(`suggest.status.${s.status}`)}
        </Pill>
        {fresh && <Pill color="--primary">{t("suggest.new")}</Pill>}
      </div>
      {/* plain text – never markup; an address is a link only when it is http(s) */}
      <p className="text-sm leading-relaxed whitespace-pre-line [overflow-wrap:anywhere]">{s.reason}</p>
      {(s.url || s.cpe) && (
        <dl className="grid gap-x-3 gap-y-1 text-xs sm:grid-cols-[auto_minmax(0,1fr)]">
          {s.url && (
            <>
              <dt className="text-muted-foreground">{t("suggest.url")}</dt>
              <dd className="min-w-0 break-all">
                {href ? (
                  <a href={href} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-primary underline-offset-2 hover:underline">
                    {s.url} <ExternalLink className="size-3 shrink-0" />
                  </a>
                ) : (
                  s.url
                )}
              </dd>
            </>
          )}
          {s.cpe && (
            <>
              <dt className="text-muted-foreground">
                <Term k="cpe">CPE</Term>
              </dt>
              <dd className="min-w-0 font-mono break-all">{s.cpe}</dd>
            </>
          )}
        </dl>
      )}
      {s.status !== "open" && (
        <div className="space-y-1 rounded-lg bg-muted/60 p-2.5 text-xs">
          <p>
            {t(`suggest.answer.${s.status}${s.status === "accepted" && !s.result ? "Catalog" : ""}`)}
            {s.result && (
              <>
                {" "}
                <button type="button" onClick={() => onOpen(s.result!.key)} className="font-medium text-primary underline-offset-2 hover:underline">
                  {s.result.label}
                </button>
              </>
            )}
            {s.decided_at && (
              <span className="text-muted-foreground">
                {" · "}
                <Ts at={s.decided_at} rel />
                {admin && s.decided_by && ` · ${s.decided_by}`}
              </span>
            )}
          </p>
          {s.answer && <p className="whitespace-pre-line text-muted-foreground [overflow-wrap:anywhere]">{s.answer}</p>}
        </div>
      )}
      {actions && <div className="flex flex-wrap items-center gap-2 pt-1">{actions}</div>}
    </li>
  )
}

// ---------------------------------------------------------------- the admins' answer

type Mode = "accept" | "duplicate" | "reject"

function DecideSheet({ s, mode, onClose, onAdopt }: { s: Suggestion; mode: Mode; onClose: () => void; onAdopt: (s: Suggestion) => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const cat = useVendorCatalog()
  const [answer, setAnswer] = useState("")
  const [busy, setBusy] = useState(false)
  const [search, setSearch] = useState(s.product)
  const [pick, setPick] = useState<VendorProduct | null>(null)
  const hits = useMemo(() => {
    const ps = cat.data?.products ?? []
    if (!search.trim()) return similarProducts(ps, s.vendor, s.product, 8)
    return ps
      .map((p) => ({ p, sc: matchScore(p, search) }))
      .filter((x) => x.sc > 0)
      .sort((a, b) => b.sc - a.sc)
      .slice(0, 8)
      .map((x) => x.p)
  }, [cat.data, search, s.vendor, s.product])
  const snippet = yamlSnippet(s)
  const decide = async (path: "accept" | "reject" | "duplicate", body: Record<string, unknown>) => {
    setBusy(true)
    try {
      await api.post(`/api/admin/suggestions/${encodeURIComponent(s.id)}/${path}`, body)
      toast.success(t(`suggest.done.${path}`))
      void qc.invalidateQueries({ queryKey: SUGGESTIONS_KEY })
      onClose()
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  const answerField = (
    <Field label={t(mode === "reject" ? "suggest.rejectReason" : "suggest.answerOptional")} hint={t("suggest.answerHint")}>
      <Textarea value={answer} onChange={(e) => setAnswer(e.target.value)} maxLength={500} rows={2} />
    </Field>
  )
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-lg">
        <SheetHeader className="border-b">
          <SheetTitle>{t(`suggest.decide.${mode}`)}</SheetTitle>
          <SheetDescription className="[overflow-wrap:anywhere]">
            {s.vendor} · {s.product}
          </SheetDescription>
        </SheetHeader>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
          {mode === "accept" && (
            <>
              <section className="space-y-2 rounded-lg border p-3">
                <h3 className="text-sm font-semibold">{t("suggest.adoptCpe")}</h3>
                <p className="text-xs leading-relaxed text-muted-foreground">{t("suggest.adoptCpeText")}</p>
                <Button size="sm" onClick={() => onAdopt(s)}>
                  <PackagePlus /> {t("suggest.adoptCpeButton")}
                </Button>
              </section>
              <section className="space-y-2 rounded-lg border p-3">
                <h3 className="text-sm font-semibold">{t("suggest.adoptCatalog")}</h3>
                <p className="text-xs leading-relaxed text-muted-foreground">{t("suggest.adoptCatalogText")}</p>
                <pre className="overflow-x-auto rounded-md bg-muted p-2.5 font-mono text-[11px] leading-relaxed">{snippet}</pre>
                <Button size="sm" variant="outline" onClick={() => void copyWithToast(snippet)}>
                  <Copy /> {t("suggest.copySnippet")}
                </Button>
              </section>
              {answerField}
            </>
          )}
          {mode === "duplicate" && (
            <>
              <Field label={t("suggest.existing")}>
                <div className="relative">
                  <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
                  <Input value={search} onChange={(e) => setSearch(e.target.value)} maxLength={80} className="pl-8" />
                </div>
              </Field>
              <ul className="max-h-64 divide-y overflow-y-auto rounded-lg border" aria-label={t("suggest.existing")}>
                {hits.map((p) => (
                  <li key={p.key}>
                    <button
                      type="button"
                      aria-pressed={pick?.key === p.key}
                      onClick={() => setPick(p)}
                      className={cn("flex w-full min-w-0 items-baseline gap-2 px-3 py-2 text-left hover:bg-muted/50", pick?.key === p.key && "bg-accent")}
                    >
                      {pick?.key === p.key && <Check className="size-3.5 shrink-0 text-primary" />}
                      <span className="truncate text-sm font-medium">{p.label}</span>
                      <span className="truncate text-xs text-muted-foreground">{p.vendor}</span>
                    </button>
                  </li>
                ))}
                {hits.length === 0 && <li className="px-3 py-2 text-xs text-muted-foreground">{t("common.noResults")}</li>}
              </ul>
              {answerField}
            </>
          )}
          {mode === "reject" && answerField}
        </div>
        <SheetFooter className="flex-row flex-wrap items-center justify-end gap-2 border-t bg-popover">
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          {mode === "accept" && (
            <Button variant="outline" disabled={busy} onClick={() => void decide("accept", { answer })}>
              {busy ? <Loader2 className="animate-spin" /> : <Check />} {t("suggest.markAccepted")}
            </Button>
          )}
          {mode === "duplicate" && (
            <Button disabled={busy || !pick} onClick={() => pick && void decide("duplicate", { product_key: pick.key, answer })}>
              {busy ? <Loader2 className="animate-spin" /> : <CopyCheck />} {t("suggest.duplicate")}
            </Button>
          )}
          {mode === "reject" && (
            <Button variant="destructive" disabled={busy} onClick={() => void decide("reject", { answer })}>
              {busy ? <Loader2 className="animate-spin" /> : <Ban />} {t("suggest.reject")}
            </Button>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}
