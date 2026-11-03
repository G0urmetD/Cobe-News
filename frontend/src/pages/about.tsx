import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { ChevronRight, CircleMinus, FileQuestion, type LucideIcon, Server, ShieldCheck, Sparkles, TrendingUp, Wrench } from "lucide-react"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { EmptyState, PageHeader, Section } from "@/components/cobe/common"
import { Pill } from "@/components/cobe/badges"
import { Explained } from "@/components/cobe/explained"
import { Pending } from "@/components/cobe/query-state"
import { ToggleRow } from "@/components/cobe/form"
import { Ts } from "@/components/cobe/time"
import { useAuth } from "@/lib/auth"
import { errorText } from "@/lib/errors"
import { UPDATE_KEY, releaseLink, saveUpdateCheck, useUpdateStatus } from "@/lib/update-api"
import { type ChangeKind, type ChangelogEntry, entryGroups, inlineTokens, kindCounts, splitChangelog, useChangelog } from "@/lib/changelog"
import { cn } from "@/lib/utils"

/** "Version & Changelog": the running version, its notes open at the top, the earlier versions folded below. */
export function AboutPage() {
  const { t, i18n } = useTranslation()
  const q = useChangelog()
  if (!q.data) return <Pending error={q.error} onRetry={() => void q.refetch()} />
  const { version, entries } = q.data
  const { current, older } = splitChangelog(q.data)
  return (
    <div className="mx-auto w-full max-w-3xl">
      <PageHeader title={t("about.title")} description={t("about.description")} />

      {/* the product and the build: the version is what support asks for first */}
      <div className="mb-6 flex flex-col gap-4 rounded-xl border bg-card p-5 sm:flex-row sm:items-center sm:gap-5">
        <div className="flex min-w-0 flex-1 items-center gap-4">
          <img src="/mark-large.svg" alt="" aria-hidden className="size-14 shrink-0 select-none" draggable={false} />
          <div className="min-w-0">
            <p className="text-lg font-semibold tracking-tight">Cobe News</p>
            <p className="text-sm text-muted-foreground">{t("about.product")}</p>
          </div>
        </div>
        <div className="border-t pt-4 sm:border-t-0 sm:border-l sm:pt-0 sm:pl-5 sm:text-right">
          <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
            <Explained label={t("about.version")} text={t("about.versionHint")} />
          </p>
          <p className="font-mono text-3xl font-semibold tracking-tight tabular" data-testid="about-version">
            {version}
          </p>
          {q.data.catalog_version && (
            <p className="mt-1 text-xs text-muted-foreground">
              <Explained label={t("about.catalogVersion")} text={t("about.catalogVersionHint")} />{" "}
              <span className="font-mono text-foreground/80 tabular-nums" data-testid="about-catalog-version">
                {q.data.catalog_version}
              </span>
            </p>
          )}
        </div>
      </div>

      <UpdateCheck />

      {i18n.language === "en" && entries.length > 0 && <p className="mb-3 text-xs text-muted-foreground">{t("about.notesLanguage")}</p>}

      {current ? (
        <Section
          className="mb-8"
          title={
            <span className="flex flex-wrap items-center gap-2">
              <Sparkles className="size-4 text-primary" />
              {t("about.current", { version })}
              <span className="rounded-full bg-primary/10 px-2 py-0.5 text-[11px] font-medium text-primary">{t("about.running")}</span>
            </span>
          }
          description={current.title || undefined}
        >
          <Groups entry={current} className="px-5 py-4" />
        </Section>
      ) : (
        <div className="mb-8">
          <EmptyState
            icon={FileQuestion}
            title={entries.length ? t("about.noNotes", { version }) : t("about.noChangelog")}
            text={entries.length ? t("about.noNotesText") : t("about.noChangelogText")}
          />
        </div>
      )}

      {older.length > 0 && (
        <section aria-labelledby="about-older" className="space-y-2">
          <h2 id="about-older" className="flex items-center gap-1 pb-1 text-sm font-semibold">
            <Explained label={t("about.older")} text={t("about.changelogHint")} />
          </h2>
          {older.map((e) => (
            <OlderVersion key={e.version} entry={e} />
          ))}
        </section>
      )}
    </div>
  )
}

/** Admins only: the switch of the update notice (app/update_check.py) and what the last check found. */
function UpdateCheck() {
  const { t } = useTranslation()
  const { isAdmin } = useAuth()
  const qc = useQueryClient()
  const q = useUpdateStatus(isAdmin)
  const [busy, setBusy] = useState(false)
  if (!isAdmin || !q.data) return null
  const s = q.data
  const toggle = async (check: boolean) => {
    setBusy(true)
    try {
      qc.setQueryData(UPDATE_KEY, await saveUpdateCheck(check, s.rev))
      toast.success(t("common.saved"))
    } catch (e) {
      toast.error(errorText(t, e))
      void qc.invalidateQueries({ queryKey: UPDATE_KEY })
    } finally {
      setBusy(false)
    }
  }
  const link = releaseLink(s) // an https address only, as the shell's notice
  return (
    <div className="mb-6 rounded-xl border bg-card px-5 py-1">
      <ToggleRow label={t("update.check")} description={t("update.checkHint")} checked={s.enabled} disabled={busy} onCheckedChange={(v) => void toggle(v)}>
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-xs">
          <dt className="text-muted-foreground">{t("update.latest")}</dt>
          <dd className="min-w-0">
            {s.latest ? (
              <span className="font-mono tabular-nums">
                {s.latest}{" "}
                {s.available && link ? (
                  <a href={link} target="_blank" rel="noopener noreferrer" className="font-sans text-primary hover:underline">
                    {t("update.available", { version: s.latest })}
                  </a>
                ) : (
                  <span className="font-sans text-muted-foreground">· {t(s.ahead ? "update.ahead" : "update.upToDate", { version: s.current })}</span>
                )}
              </span>
            ) : (
              <span className="text-muted-foreground">{t("update.none")}</span>
            )}
          </dd>
          <dt className="text-muted-foreground">{t("update.checked")}</dt>
          <dd className="min-w-0">{s.checked_at ? <Ts at={s.checked_at} rel /> : <span className="text-muted-foreground">–</span>}</dd>
          {s.error && <dd className="col-span-2 text-warning [overflow-wrap:anywhere]">{t("update.error", { error: s.error })}</dd>}
        </dl>
      </ToggleRow>
    </div>
  )
}

/** One earlier version, folded: number, title and how many changes of each kind – the notes on click. */
function OlderVersion({ entry }: { entry: ChangelogEntry }) {
  const [open, setOpen] = useState(false)
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="rounded-xl border bg-card">
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className="flex w-full items-start gap-2 rounded-xl px-4 py-3 text-left text-sm outline-none hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          <ChevronRight className={cn("mt-0.5 size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")} />
          <span className="shrink-0 font-mono font-semibold tabular">{entry.version}</span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-muted-foreground">{entry.title}</span>
            <KindSummary entry={entry} />
          </span>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <Groups entry={entry} className="border-t px-4 py-3" />
      </CollapsibleContent>
    </Collapsible>
  )
}

/** Colour and symbol of each kind of change – tokens only, so light and dark both work (docs/UX.md). */
const KIND_STYLE: Record<ChangeKind, { color: string; icon: LucideIcon }> = {
  neu: { color: "--primary", icon: Sparkles },
  verbessert: { color: "--success", icon: TrendingUp },
  fixes: { color: "--warning", icon: Wrench },
  sicherheit: { color: "--sev-critical", icon: ShieldCheck },
  entfernt: { color: "--muted-foreground", icon: CircleMinus },
  betrieb: { color: "--chart-2", icon: Server },
}

function KindBadge({ kind }: { kind: ChangeKind }) {
  const { t } = useTranslation()
  const { color, icon: Icon } = KIND_STYLE[kind]
  return (
    <Pill color={color}>
      <Icon aria-hidden />
      {t(`about.kind.${kind}`)}
    </Pill>
  )
}

/** "3 neu · 5 Fixes" – a coloured dot per kind (the word says it too); only headings the changelog does not define:
 * "N Änderungen". */
function KindSummary({ entry }: { entry: ChangelogEntry }) {
  const { t } = useTranslation()
  const counts = kindCounts(entry)
  if (counts.length === 0) return null
  if (counts.length === 1 && counts[0].kind === "other") {
    return <span className="mt-0.5 block text-xs text-muted-foreground">{t("about.items", { count: counts[0].count })}</span>
  }
  return (
    <span className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-xs text-muted-foreground" data-testid="about-kind-summary">
      {counts.map(({ kind, count }, i) => (
        <span key={kind} className="inline-flex items-center gap-1.5 whitespace-nowrap">
          {i > 0 && (
            <span aria-hidden className="text-muted-foreground/60">
              ·
            </span>
          )}
          {kind !== "other" && <span aria-hidden className="size-1.5 rounded-full" style={{ backgroundColor: `var(${KIND_STYLE[kind].color})` }} />}
          {t(`about.count.${kind}`, { count })}
        </span>
      ))}
    </span>
  )
}

/** A version's notes under their headings (Neu, Verbessert, Fixes …) – a heading the changelog does not define shows its
 * own text, items before the first heading none. */
function Groups({ entry, className }: { entry: ChangelogEntry; className?: string }) {
  return (
    <div className={cn("space-y-4", className)}>
      {entryGroups(entry).map((g, i) => (
        <div key={i}>
          {g.kind !== "other" ? (
            <h3 className="mb-2">
              <KindBadge kind={g.kind} />
            </h3>
          ) : (
            g.heading && <h3 className="mb-2 text-xs font-semibold text-muted-foreground">{g.heading}</h3>
          )}
          <Items items={g.items} />
        </div>
      ))}
    </div>
  )
}

function Items({ items }: { items: string[] }) {
  return (
    <ul className="list-disc space-y-2 pl-5 text-sm leading-relaxed marker:text-muted-foreground">
      {items.map((item, i) => (
        <li key={i} className="pl-1 break-words">
          <Inline text={item} />
        </li>
      ))}
    </ul>
  )
}

/** **bold** and `code` of a changelog line – as React elements; everything else is text, never markup. */
function Inline({ text }: { text: string }) {
  return (
    <>
      {inlineTokens(text).map((tok, i) => {
        const inner = tok.kind === "code" ? <code className="rounded bg-muted px-1 py-0.5 font-mono text-[12.5px] break-all">{tok.text}</code> : tok.text
        return tok.bold ? (
          <strong key={i} className="font-semibold">
            {inner}
          </strong>
        ) : (
          <span key={i}>{inner}</span>
        )
      })}
    </>
  )
}
