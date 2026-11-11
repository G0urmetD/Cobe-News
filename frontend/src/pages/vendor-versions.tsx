import { useId, useState } from "react"
import { Link } from "react-router"
import { useTranslation } from "react-i18next"
import { useQueryClient } from "@tanstack/react-query"
import {
  AlertTriangle,
  CalendarClock,
  Check,
  CheckCheck,
  Clock,
  CheckCircle2,
  ChevronDown,
  Copy,
  Info,
  ListChecks,
  Loader2,
  Pencil,
  Plus,
  ShieldAlert,
  StickyNote,
  Trash2,
  TrendingUp,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill } from "@/components/cobe/badges"
import { Explained } from "@/components/cobe/explained"
import { Field } from "@/components/cobe/form"
import { Term } from "@/components/cobe/glossary"
import { confirmAction } from "@/components/cobe/confirm"
import { Ts } from "@/components/cobe/time"
import { useSettled } from "@/hooks/use-settled"
import { ApiError, api } from "@/lib/api"
import { copyWithToast } from "@/lib/clipboard"
import { errorText } from "@/lib/errors"
import { fmtDay } from "@/lib/format"
import { useCatalogTexts } from "@/lib/catalog-texts"
import { cn } from "@/lib/utils"
import { confirmAll, confirmVersion, dueVersions, refreshReview } from "@/lib/version-review"
import { iso } from "@/lib/bidi"
import {
  STATUS_COLOR,
  SUPPORT_COLOR,
  invalidText,
  looksLikeBuild,
  supportState,
  useVersionCheck,
  versionProblem,
  type FollowedVersion,
  type ProductDetail,
  type ReleaseLine,
  type ReleaseSource,
  type Support,
  type VendorProduct,
  type VersionTarget,
  productKeyOf,
  refreshVendor,
} from "@/lib/vendor-api"

/*
 * The "Versionen" tab of a product (docs/UX.md): what is set is shown read-only, edited on demand (pencil); a new
 * version is entered in a labelled form of its own; release lines below, explained; notes last.
 */

export function Versions({ d, canEdit, canConfirm = canEdit, vulnsHref }: { d: ProductDetail; canEdit: boolean; canConfirm?: boolean; vulnsHref: string }) {
  const ct = useCatalogTexts()
  const lines = d.releases?.lines ?? []
  const source = d.releases?.source ?? null
  const yours = new Set(d.versions.map((v) => v.release?.line?.name).filter((x): x is string => !!x))
  return (
    <div className="space-y-7">
      {d.product.cloud ? (
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{ct.hint("cloud")}</p>
      ) : (
        d.follow && (
          <>
            <Installed d={d} lines={lines} canEdit={canEdit} canConfirm={canConfirm} vulnsHref={vulnsHref} />
            {canEdit && <AddVersion key={d.versions.length} p={d.product} lines={lines} startOpen={d.versions.length === 0} />}
          </>
        )
      )}
      {lines.length > 0 ? <ReleaseLines lines={lines} yours={yours} source={source} /> : source && source.kind !== "eol" && <SourceNote source={source} />}
      {d.follow && <Notes d={d} canEdit={canEdit} />}
    </div>
  )
}

function SectionTitle({ children, count, aside }: { children: React.ReactNode; count?: number; aside?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <h3 className="flex items-center gap-2 text-sm font-semibold">
        {children}
        {!!count && <span className="rounded-full bg-muted px-1.5 text-[11px] font-normal text-muted-foreground tabular">{count}</span>}
      </h3>
      {aside && <div className="ml-auto">{aside}</div>}
    </div>
  )
}

// ---------------------------------------------------------------- installed: read-only cards, edit on demand

function Installed({ d, lines, canEdit, canConfirm, vulnsHref }: { d: ProductDetail; lines: ReleaseLine[]; canEdit: boolean; canConfirm: boolean; vulnsHref: string }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const due = dueVersions(d.versions)
  const [busy, setBusy] = useState(false)
  // "Alle bestätigen": asked first – it says for every version due at once that it still runs as entered
  const all = async () => {
    if (
      !(await confirmAction({
        title: t("review.allTitle"),
        text: t("review.allText", { count: due, product: d.product.label }),
        confirm: t("review.confirmAll"),
        destructive: false,
      }))
    )
      return
    setBusy(true)
    try {
      const r = await confirmAll({ product: d.product.key })
      toast.success(t("review.confirmedN", { count: r.confirmed }))
      await refreshReview(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className="space-y-3" aria-labelledby="vendor-installed">
      <div className="space-y-0.5">
        <SectionTitle
          count={d.versions.length}
          aside={
            canConfirm &&
            due > 1 && (
              <Button variant="outline" size="xs" disabled={busy} onClick={() => void all()}>
                {busy ? <Loader2 className="animate-spin" /> : <CheckCheck />} {t("review.confirmAllN", { count: due })}
              </Button>
            )
          }
        >
          <ListChecks className="size-4 text-muted-foreground" />
          <span id="vendor-installed">{t("vendor.installed")}</span>
        </SectionTitle>
        {d.versions.length > 0 && <p className="text-xs text-muted-foreground">{t("vendor.installedHint")}</p>}
      </div>
      {d.versions.length === 0 ? (
        <div className="flex gap-3 rounded-xl border border-dashed p-4">
          <div className="flex size-9 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground">
            <ListChecks className="size-4" />
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium">{t("vendor.noVersionsTitle")}</p>
            <p className="text-xs leading-relaxed text-muted-foreground">
              {t("vendor.noVersionsText")}
              {!canEdit && ` ${t("vendor.noVersionsReader")}`}
            </p>
          </div>
        </div>
      ) : (
        <ul className="space-y-2.5">
          {d.versions.map((v) => (
            <InstalledVersion key={v.id + v.updated_at} v={v} d={d} lines={lines} canEdit={canEdit} canConfirm={canConfirm} vulnsHref={vulnsHref} />
          ))}
        </ul>
      )}
    </section>
  )
}

function InstalledVersion({
  v,
  d,
  lines,
  canEdit,
  canConfirm,
  vulnsHref,
}: {
  v: FollowedVersion
  d: ProductDetail
  lines: ReleaseLine[]
  canEdit: boolean
  canConfirm: boolean
  vulnsHref: string
}) {
  const { t, i18n } = useTranslation()
  const qc = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const confirm = async () => {
    setConfirming(true)
    try {
      await confirmVersion(v.id)
      toast.success(t("review.confirmed", { version: v.version }))
      await refreshReview(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setConfirming(false)
    }
  }
  const name = v.label ? `${v.version} (${iso(v.label)})` : v.version
  const remove = async () => {
    if (!(await confirmAction({ title: t("vendor.v.removeTitle"), text: t("vendor.v.removeText", { version: name }), confirm: t("common.remove") }))) return
    try {
      await api.del(`/api/vendor/versions/${v.id}`)
      toast.success(t("vendor.v.removed", { version: v.version }))
      void refreshVendor(qc)
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  if (editing)
    return (
      <li className="rounded-xl border border-primary/40 bg-card p-3.5">
        <VersionForm p={d.product} lines={lines} v={v} onDone={() => setEditing(false)} />
      </li>
    )
  const s = d.summary?.per_version[v.id]
  return (
    <li className="space-y-2.5 rounded-xl border bg-card p-3.5">
      <div className="flex items-start gap-2">
        <p className="flex min-w-0 flex-1 flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="font-mono text-base font-semibold break-all">{v.version}</span>
          {v.label && <bdi className="text-sm text-muted-foreground">{v.label}</bdi>}
          {v.count && <span className="text-xs text-muted-foreground">· {t("vendor.devices", { count: v.count })}</span>}
          {v.short && (
            <Hint text={t("vendor.v.shortHint", { version: v.version })}>
              <Pill color="--warning">
                <AlertTriangle /> {t("vendor.v.short")}
              </Pill>
            </Hint>
          )}
        </p>
        {canEdit && (
          <div className="-mt-1 -mr-1 flex shrink-0 items-center">
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={() => setEditing(true)}
              aria-label={t("vendor.v.edit", { version: v.version })}
              title={t("vendor.v.edit", { version: v.version })}
            >
              <Pencil />
            </Button>
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={() => void remove()}
              aria-label={t("vendor.v.remove", { version: v.version })}
              title={t("vendor.v.remove", { version: v.version })}
            >
              <Trash2 />
            </Button>
          </div>
        )}
      </div>
      {v.invalid_reason && (
        <p className="text-xs text-warning">
          {invalidText(t, i18n.language, v.invalid_reason, { example: d.product.example, hint: v.invalid_hint, toLabel: v.invalid_to_label, lines: v.invalid_lines })}
        </p>
      )}
      {v.effective && !v.invalid_reason && <p className="text-xs text-muted-foreground">{t("vendor.v.effective", { version: v.effective })}</p>}
      {v.review && <ReviewLine v={v} canConfirm={canConfirm} busy={confirming} onConfirm={() => void confirm()} />}
      <div className="flex flex-wrap items-center gap-1.5">
        {s &&
          (s.affected || s.possible ? (
            <>
              {s.affected > 0 && (
                <ChipLink to={vulnsHref} color={STATUS_COLOR.affected} label={t("vendor.v.toVulns")}>
                  <ShieldAlert /> {t("vendor.v.affects", { count: s.affected })}
                </ChipLink>
              )}
              {s.possible > 0 && (
                <ChipLink to={vulnsHref} color={STATUS_COLOR.possible} label={t("vendor.v.toVulns")}>
                  {t("vendor.v.possible", { count: s.possible })}
                </ChipLink>
              )}
            </>
          ) : (
            <Pill color="--success">
              <CheckCircle2 /> {t("vendor.v.clean")}
            </Pill>
          ))}
        <ReleaseChips v={v} lines={lines} veeam={d.product.scheme === "veeam"} affected={s?.affected ?? 0} target={s?.target} />
      </div>
    </li>
  )
}

/** When the version was last confirmed, "bitte prüfen" when that is longer ago than the interval, and "Bestätigen". */
function ReviewLine({ v, canConfirm, busy, onConfirm }: { v: FollowedVersion; canConfirm: boolean; busy: boolean; onConfirm: () => void }) {
  const { t } = useTranslation()
  const r = v.review
  if (!r) return null
  return (
    <div className={cn("flex flex-wrap items-center gap-x-2 gap-y-1 text-xs", r.due ? "rounded-lg bg-warning/10 px-2.5 py-1.5" : "text-muted-foreground")}>
      {r.due && (
        <Hint text={r.invalid ? t("review.invalidHint") : t("review.dueHint", { count: r.age_days })}>
          <Pill color="--warning">
            <Clock /> {t("review.due")}
          </Pill>
        </Hint>
      )}
      <span className={cn(r.due && "text-foreground/80")}>
        {r.invalid ? t("review.invalid") : r.due ? t("review.since", { count: r.age_days }) : t("review.confirmedAt")}
        {!r.due && r.confirmed_at && (
          <>
            {" "}
            <Ts at={r.confirmed_at} rel />
          </>
        )}
        {r.confirmed_by && ` · ${t("review.by", { name: iso(r.confirmed_by) })}`}
      </span>
      {canConfirm && (
        <Button variant={r.due ? "outline" : "ghost"} size="xs" className="ml-auto" disabled={busy} onClick={onConfirm} title={t("review.confirmHint")}>
          {busy ? <Loader2 className="animate-spin" /> : <Check />} {t("review.confirm")}
        </Button>
      )}
    </div>
  )
}

/** A status chip that leads somewhere (the vulnerabilities of this version). */
function ChipLink({ to, color, label, children }: { to: string; color: string; label: string; children: React.ReactNode }) {
  return (
    <Link to={to} title={label} className="rounded-full outline-none hover:opacity-80 focus-visible:ring-2 focus-visible:ring-ring/50">
      <Pill color={color}>{children}</Pill>
    </Link>
  )
}

/** Hover or keyboard focus explains a chip. */
function Hint({ text, children }: { text: string; children: React.ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="cursor-help rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">{text}</TooltipContent>
    </Tooltip>
  )
}

function ReleaseChips({ v, lines, veeam, affected, target }: { v: FollowedVersion; lines: ReleaseLine[]; veeam: boolean; affected: number; target?: VersionTarget }) {
  const { t } = useTranslation()
  const r = v.release
  if (!r) return <span className="text-xs text-muted-foreground">{t("vendor.lines.noData")}</span>
  const own = !!r.source && r.source.kind !== "eol" // a release source: lines and newest versions, no support dates
  if (!r.line) return <span className="text-xs text-muted-foreground">{t(own ? "vendor.lines.noLineSource" : "vendor.lines.noLine")}</span>
  const lineName = r.line.label || r.line.name
  const row = lines.find((l) => l.name === r.line?.name)
  const support = supportState(r.line.eol_from ?? row?.eolFrom, row?.isEol ?? (r.eol_state === "past" ? true : undefined))
  const newer = r.newer_line
  return (
    <>
      {r.update_unknown && r.line.latest ? (
        // Veeam: the build is missing ("12.3.2"); any other product: a short version ("1.27" for nginx 1.27.3)
        <Hint text={t(veeam ? "vendor.v.buildUnknownHint" : "vendor.v.versionUnknownHint", { latest: r.line.latest, version: v.version })}>
          <Pill color="--muted-foreground">
            <Info /> {t(veeam ? "vendor.v.buildUnknown" : "vendor.v.versionUnknown")}
          </Pill>
        </Hint>
      ) : r.update_available && r.line.latest ? (
        <Hint text={t("vendor.v.updateHint", { line: lineName, latest: r.line.latest })}>
          <Pill color="--primary">
            <TrendingUp /> {t("vendor.v.update", { latest: r.line.latest })}
          </Pill>
        </Hint>
      ) : r.line.latest && affected > 0 && target?.kind === "update" && target.to && target.to !== r.line.latest ? (
        // the advisories name a fix in the line that endoflife.date does not list yet (its newest is older): the newer
        // known fix counts – as the card's "Update auf … behebt …"
        <Hint text={t("vendor.v.updateFixHint", { line: lineName, to: target.to, latest: r.line.latest })}>
          <Pill color="--primary">
            <TrendingUp /> {t("vendor.v.update", { latest: target.to })}
          </Pill>
        </Hint>
      ) : r.line.latest && affected > 0 ? (
        // the newest release of the line, but a vulnerability affects it (endoflife.date may not know the fix yet):
        // never a green "Aktuell" next to "1 betrifft diese Version"
        <Hint text={t("vendor.v.latestAffectedHint", { line: lineName, count: affected })}>
          <Pill color="--muted-foreground">
            <Info /> {t("vendor.v.latestAffected")}
          </Pill>
        </Hint>
      ) : (
        r.line.latest && (
          <Hint text={t("vendor.v.currentHint", { line: lineName })}>
            <Pill color="--success">
              <Check /> {t("vendor.v.current")}
            </Pill>
          </Hint>
        )
      )}
      {own ? (
        <Pill color="--muted-foreground">
          <CalendarClock /> {t("vendor.lines.eolUnknown")}
        </Pill>
      ) : (
        <SupportChip support={support} eolFrom={r.line.eol_from ?? row?.eolFrom ?? null} />
      )}
      {/* where the version stands: its line, and a newer one as a muted hint – an upgrade, not an urgent update */}
      <p className="flex w-full flex-wrap items-center gap-x-1.5 pt-0.5 text-xs text-muted-foreground">
        <span>{t("vendor.v.line", { line: lineName })}</span>
        {newer && (
          <>
            <span aria-hidden>·</span>
            <Hint
              text={t("vendor.v.newerLineHint", {
                line: newer.label || newer.name,
                latest: newer.latest ? t("vendor.v.newerLineLatest", { latest: newer.latest }) : "",
              })}
            >
              <span className="inline-flex items-center gap-1">
                {t("vendor.v.newerLine", { line: newer.label || newer.name })}
                <Info className="size-3" />
              </span>
            </Hint>
          </>
        )}
      </p>
    </>
  )
}

function SupportChip({ support, eolFrom }: { support: Support; eolFrom: string | null }) {
  const { t } = useTranslation()
  if (support === "unknown") return null
  const text =
    support === "past"
      ? eolFrom
        ? t("vendor.v.supportEnded", { date: fmtDay(eolFrom) })
        : t("vendor.v.supportEndedNoDate")
      : eolFrom
        ? t("vendor.v.supportUntil", { date: fmtDay(eolFrom) })
        : t("vendor.v.supportOpen")
  return (
    <Pill color={support === "ok" ? "--muted-foreground" : SUPPORT_COLOR[support]}>
      <CalendarClock /> {text}
    </Pill>
  )
}

// ---------------------------------------------------------------- entering a version: a labelled form of its own

function AddVersion({ p, lines, startOpen }: { p: VendorProduct; lines: ReleaseLine[]; startOpen: boolean }) {
  const { t } = useTranslation()
  const ct = useCatalogTexts()
  const [open, setOpen] = useState(startOpen)
  if (!open)
    return (
      <Button variant="outline" className="w-full border-dashed" onClick={() => setOpen(true)}>
        <Plus /> {t("vendor.add.open")}
      </Button>
    )
  return (
    <section className="space-y-3 rounded-xl border border-primary/30 bg-primary/[0.03] p-4" aria-labelledby="vendor-add">
      <div className="space-y-0.5">
        <h3 id="vendor-add" className="flex items-center gap-2 text-sm font-semibold">
          <Plus className="size-4 text-primary" /> {t("vendor.add.title")}
        </h3>
        <p className="text-xs text-muted-foreground">{t("vendor.add.intro")}</p>
      </div>
      {p.version_cmd && <VersionCommand cmd={p.version_cmd} fromEol={p.version_cmd_from === "eol"} />}
      {p.version_where && ct.where(p.version_where) && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">{t("vendor.add.where")}</p>
          <p className="flex gap-2 rounded-lg bg-muted/70 px-2.5 py-2 text-xs leading-relaxed">
            <Info className="mt-0.5 size-3.5 shrink-0 text-primary" />
            <span>{ct.where(p.version_where)}</span>
          </p>
        </div>
      )}
      <VersionForm p={p} lines={lines} onDone={startOpen ? undefined : () => setOpen(false)} />
    </section>
  )
}

function VersionCommand({ cmd, fromEol }: { cmd: string; fromEol: boolean }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1">
      {/* third-party data: said where it comes from – read it before running it */}
      <p className="text-xs text-muted-foreground">{t(fromEol ? "vendor.add.cmdFromEol" : "vendor.add.cmd")}</p>
      <div className="flex items-center gap-1 rounded-lg bg-muted/70 py-1 pr-1 pl-2.5">
        <code className="min-w-0 flex-1 font-mono text-xs break-all">{cmd}</code>
        <Button variant="ghost" size="icon-xs" onClick={() => void copyWithToast(cmd)} aria-label={t("vendor.add.copyCmd")} title={t("vendor.add.copyCmd")}>
          <Copy />
        </Button>
      </div>
    </div>
  )
}

/** The fields of a version, labelled above – for a new one (no `v`) or one being edited. */
function VersionForm({ p, lines, v, onDone }: { p: VendorProduct; lines: ReleaseLine[]; v?: FollowedVersion; onDone?: () => void }) {
  const { t, i18n } = useTranslation()
  const qc = useQueryClient()
  const ids = useId()
  const [version, setVersion] = useState(v?.version ?? "")
  const [label, setLabel] = useState(v?.label ?? "")
  const [count, setCount] = useState(v?.count ? String(v.count) : "")
  const [busy, setBusy] = useState(false)
  const example = p.example || "8.3.14"
  // vCenter, ESXi: a four-part version (8.0.3.00400) or a build is looked up on the server – no format check here, the
  // hint shows the release it is ("→ 8.0 U3d") before it is saved
  const lookup = !!p.builds && looksLikeBuild(version)
  const problem = lookup ? null : versionProblem(p.scheme, version)
  // accepted, but shorter than the product's releases ("7.4" for FortiOS 7.4.8): saving stays allowed, the hint asks
  // for the whole version – the server knows how long a complete version of this product is
  const settled = useSettled(version.trim())
  const check = useVersionCheck(p.key, settled, settled !== "" && ((!!p.builds && looksLikeBuild(settled)) || !versionProblem(p.scheme, settled)))
  const current = settled === version.trim() && !!check.data
  const short = !problem && current && !!check.data?.ok && check.data.short
  const lookupOk = lookup && current && !!check.data?.ok
  // the server knows more than the format (app/version_input.py): build tables, the product's own forms, other
  // products' forms, its release lines – what it refuses is shown with its reason, what it maps with "→ …"
  const serverProblem = !problem && current && !check.data?.ok ? (check.data?.reason ?? "format") : null
  const mapped = current && check.data?.ok && check.data.mapped ? check.data.normalized : null
  const lookupProblem = serverProblem
  const problemText = (reason: string) => invalidText(t, i18n.language, reason, { example, hint: check.data?.hint, toLabel: check.data?.to_label, lines: check.data?.lines })
  const fuller = lines.find((l) => l.latest?.startsWith(`${settled}.`))?.latest ?? (example.startsWith(`${settled}.`) ? example : `${settled}.x`)
  const countOk = count.trim() === "" || (/^\d+$/.test(count.trim()) && Number(count) >= 1 && Number(count) <= 100000)
  const dirty = !v || version.trim() !== v.version || label.trim() !== v.label || (count.trim() || null) !== (v.count ? String(v.count) : null)
  // the server decides – when it could not be asked, saving is allowed and it answers then
  const valid = !problem && !serverProblem && countOk && (!lookup || lookupOk || check.isError)
  const save = async () => {
    if (!valid || !dirty) return
    setBusy(true)
    try {
      const body = { version: version.trim(), label: label.trim(), count: count.trim() ? Number(count) : null }
      if (v) {
        await api.put(`/api/vendor/versions/${v.id}`, body)
        toast.success(t("common.saved"))
      } else {
        // what is stored: vCenter's 8.0.3.00400 is saved as 8.0 U3d
        const saved = await api.post<FollowedVersion>(`/api/vendor/follows/${encodeURIComponent(p.key)}/versions`, body)
        toast.success(t("vendor.v.added", { version: saved?.version || body.version }))
      }
      // the form stays (busy) until the drawer shows what was saved – no flash of the old version in between
      await refreshVendor(qc, productKeyOf(p.key))
      if (!v) {
        setVersion("")
        setLabel("")
        setCount("")
      }
      onDone?.()
    } catch (e) {
      const reason = e instanceof ApiError && e.code === "version_invalid" ? String(e.data.reason ?? "") : ""
      toast.error(
        reason && reason !== "format"
          ? invalidText(t, i18n.language, reason, {
              example,
              hint: (e as ApiError).data.hint as { de: string; en: string } | undefined,
              toLabel: (e as ApiError).data.to_label as string | undefined,
              lines: (e as ApiError).data.lines as string[] | undefined,
            })
          : errorText(t, e),
      )
    } finally {
      setBusy(false)
    }
  }
  const typed = version.trim() !== ""
  const bad = typed && (!!problem || !!lookupProblem)
  const placeholder = "placeholder:text-muted-foreground/60"
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault()
        void save()
      }}
    >
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1.2fr)_minmax(0,1.4fr)_7rem]">
        <Field label={t("vendor.form.version")} htmlFor={`${ids}-v`}>
          <Input
            id={`${ids}-v`}
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            placeholder={
              p.builds ? t(`vendor.form.buildsPh.${p.key}`, { example, defaultValue: t("vendor.form.versionPh", { example }) }) : t("vendor.form.versionPh", { example })
            }
            aria-invalid={bad || undefined}
            aria-describedby={`${ids}-vh`}
            className={cn("font-mono", placeholder)}
            maxLength={200}
            autoComplete="off"
            spellCheck={false}
          />
          <p
            id={`${ids}-vh`}
            className={cn("text-xs", bad ? "text-destructive" : short ? "text-warning" : typed && (!lookup || lookupOk) ? "text-success" : "text-muted-foreground")}
            aria-live="polite"
          >
            {typed && problem ? (
              t(`vendor.invalid.${problem}`, { example })
            ) : lookupProblem ? (
              problemText(lookupProblem)
            ) : mapped && !lookup ? (
              <span className="inline-flex items-center gap-1">
                <Check className="size-3" /> {t("vendor.form.mapped", { version: mapped })}
              </span>
            ) : lookup && !check.isError ? (
              lookupOk ? (
                <span className="inline-flex items-center gap-1">
                  <Check className="size-3" /> {mapped ? t("vendor.form.mapped", { version: mapped }) : t("vendor.form.formatOk")}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1">
                  <Loader2 className="size-3 animate-spin" /> {t("vendor.form.lookingUp")}
                </span>
              )
            ) : short ? (
              <span className="inline-flex items-start gap-1">
                <AlertTriangle className="mt-px size-3 shrink-0" /> {t("vendor.form.short", { version: settled, example: fuller })}
              </span>
            ) : typed ? (
              <span className="inline-flex items-center gap-1">
                <Check className="size-3" /> {t("vendor.form.formatOk")}
              </span>
            ) : (
              <>
                {p.builds ? t(`vendor.form.buildsHint.${p.key}`, { example, defaultValue: t("vendor.form.formatHint", { example }) }) : t("vendor.form.formatHint", { example })}
                {p.scheme === "panos" && (
                  <>
                    {" "}
                    <Term k="hotfix">{t("glossary.hotfix")}</Term>
                  </>
                )}
              </>
            )}
          </p>
        </Field>
        <Field label={t("vendor.form.label")} htmlFor={`${ids}-l`}>
          <Input id={`${ids}-l`} value={label} onChange={(e) => setLabel(e.target.value)} placeholder={t("vendor.form.labelPh")} className={placeholder} maxLength={100} />
        </Field>
        <Field label={t("vendor.form.count")} htmlFor={`${ids}-c`}>
          <Input
            id={`${ids}-c`}
            value={count}
            onChange={(e) => setCount(e.target.value)}
            placeholder={t("vendor.form.countPh")}
            className={placeholder}
            inputMode="numeric"
            aria-invalid={!countOk || undefined}
            aria-describedby={!countOk ? `${ids}-ch` : undefined}
          />
          {!countOk && (
            <p id={`${ids}-ch`} className="text-xs text-destructive">
              {t("vendor.form.countInvalid")}
            </p>
          )}
        </Field>
      </div>
      <div className="flex flex-wrap items-center justify-end gap-2">
        {onDone && (
          <Button type="button" variant="ghost" onClick={onDone}>
            {t("common.cancel")}
          </Button>
        )}
        <Button type="submit" disabled={!valid || !dirty || busy}>
          {busy ? <Loader2 className="animate-spin" /> : v ? <Check /> : <Plus />} {v ? t("common.save") : t("vendor.add.submit")}
        </Button>
      </div>
    </form>
  )
}

// ---------------------------------------------------------------- release lines, explained

/** Where the lines come from: endoflife.date, or a release source of the catalogue with its last fetch. */
function SourceLine({ source }: { source: ReleaseSource | null }) {
  const { t } = useTranslation()
  if (!source || source.kind === "eol") return <p className="text-[11px] text-muted-foreground">{t("vendor.lines.source")}</p>
  return (
    <p className="text-[11px] text-muted-foreground">
      {t(source.kind === "github" ? "vendor.lines.sourceGithub" : "vendor.lines.sourcePage")}{" "}
      <a href={source.url} target="_blank" rel="noopener noreferrer" className="underline-offset-2 hover:underline">
        {source.ref}
      </a>
      {source.fetched_at ? (
        <>
          {", "}
          {t("vendor.lines.fetched")} <Ts at={source.fetched_at} rel />
        </>
      ) : (
        <> – {t("vendor.lines.notFetched")}</>
      )}
      {" · "}
      {t("vendor.lines.noSupportData")}
    </p>
  )
}

/** A product with a release source that has no lines yet (not fetched, or nothing found). */
function SourceNote({ source }: { source: ReleaseSource }) {
  const { t } = useTranslation()
  return (
    <section className="space-y-1.5" aria-labelledby="vendor-lines">
      <SectionTitle>
        <span id="vendor-lines">{t("vendor.lines.title")}</span>
      </SectionTitle>
      <p className="text-xs text-muted-foreground">{t("vendor.lines.sourceEmpty")}</p>
      <SourceLine source={source} />
    </section>
  )
}

function ReleaseLines({ lines, yours, source }: { lines: ReleaseLine[]; yours: Set<string>; source: ReleaseSource | null }) {
  const { t } = useTranslation()
  const own = !!source && source.kind !== "eol"
  const [showOld, setShowOld] = useState(false)
  const rows = lines.map((l) => ({ l, s: supportState(l.eolFrom, l.isEol), mine: yours.has(l.name) }))
  const current = rows.filter((r) => r.s !== "past" || r.mine)
  const old = rows.filter((r) => r.s === "past" && !r.mine)
  const shown = showOld ? rows : current
  const grid = "sm:grid sm:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)_6.5rem_6.5rem_8.5rem] sm:items-center sm:gap-3"
  return (
    <section className="space-y-2.5" aria-labelledby="vendor-lines">
      <SectionTitle>
        <span id="vendor-lines">
          <Explained label={t("vendor.lines.title")} text={t("vendor.lines.help")} />
        </span>
      </SectionTitle>
      <div className="overflow-hidden rounded-xl border">
        <div className={cn("hidden border-b bg-muted/40 px-3 py-2 text-xs font-medium text-muted-foreground", grid)}>
          <span>{t("vendor.lines.colLine")}</span>
          <Explained label={t("vendor.lines.colLatest")} text={t("vendor.lines.colLatestHelp")} />
          <Explained label={t("vendor.lines.colReleased")} text={t("vendor.lines.colReleasedHelp")} />
          <span>
            <Term k="eol">{t("vendor.lines.colEol")}</Term>
          </span>
          <Explained label={t("vendor.lines.colStatus")} text={t("vendor.lines.colStatusHelp")} />
        </div>
        <ul className="divide-y">
          {shown.map(({ l, s, mine }) => (
            <li key={l.name} className={cn("flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-xs", grid, mine && "bg-primary/5")}>
              <span className="flex min-w-0 flex-wrap items-center gap-1.5 font-medium">
                <span className="text-sm">{l.label || l.name}</span>
                {l.isLts && (
                  <Pill color="--muted-foreground">
                    <Term k="lts">LTS</Term>
                  </Pill>
                )}
                {mine && <Pill color="--primary">{t("vendor.lines.yours")}</Pill>}
              </span>
              <span className="min-w-0 font-mono break-all">
                <span className="font-sans text-muted-foreground sm:hidden">{t("vendor.lines.colLatest")}: </span>
                {l.latest || "–"}
              </span>
              <span className="tabular">
                <span className="text-muted-foreground sm:hidden">{t("vendor.lines.colReleased")}: </span>
                {l.releaseDate ? fmtDay(l.releaseDate) : "–"}
              </span>
              <span className="tabular" style={s === "past" || s === "soon" ? { color: `var(${SUPPORT_COLOR[s]})` } : undefined}>
                <span className="text-muted-foreground sm:hidden">{t("vendor.lines.colEol")}: </span>
                {l.eolFrom ? fmtDay(l.eolFrom) : l.isEol ? "–" : t(own ? "vendor.lines.eolUnknown" : "vendor.lines.noEnd")}
              </span>
              <span className="w-full sm:w-auto">
                <Pill color={SUPPORT_COLOR[s]} dot>
                  {t(`vendor.lines.${s}`)}
                </Pill>
              </span>
            </li>
          ))}
        </ul>
        {old.length > 0 && (
          <button
            type="button"
            onClick={() => setShowOld(!showOld)}
            aria-expanded={showOld}
            className="flex w-full items-center justify-center gap-1.5 border-t px-3 py-2 text-xs font-medium text-muted-foreground outline-none hover:bg-muted/40 hover:text-foreground focus-visible:bg-muted/40"
          >
            <ChevronDown className={cn("size-3.5 transition-transform", showOld && "rotate-180")} />
            {showOld ? t("vendor.lines.hideOld") : t("vendor.lines.showOld", { count: old.length })}
          </button>
        )}
      </div>
      <SourceLine source={source} />
    </section>
  )
}

// ---------------------------------------------------------------- notes: secondary, last

function Notes({ d, canEdit }: { d: ProductDetail; canEdit: boolean }) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState(false)
  const note = d.follow?.note ?? ""
  const tags = d.follow?.tags ?? []
  const empty = !note && !tags.length
  if (!canEdit && empty) return null
  return (
    <section className="space-y-2 border-t pt-5" aria-labelledby="vendor-notes">
      <SectionTitle
        aside={
          canEdit &&
          !editing &&
          !empty && (
            <Button variant="ghost" size="icon-sm" onClick={() => setEditing(true)} aria-label={t("vendor.notes.edit")} title={t("vendor.notes.edit")}>
              <Pencil />
            </Button>
          )
        }
      >
        <StickyNote className="size-4 text-muted-foreground" />
        <span id="vendor-notes">{t("vendor.notes.title")}</span>
      </SectionTitle>
      {editing ? (
        <NoteForm d={d} onDone={() => setEditing(false)} />
      ) : empty ? (
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-xs text-muted-foreground">{t("vendor.notes.empty")}</p>
          <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
            <Plus /> {t("vendor.notes.add")}
          </Button>
        </div>
      ) : (
        <div className="space-y-2 text-sm">
          {note && <p className="leading-relaxed whitespace-pre-line [overflow-wrap:anywhere]">{note}</p>}
          {tags.length > 0 && (
            <p className="flex flex-wrap gap-1">
              {tags.map((x) => (
                <Pill key={x} color="--muted-foreground">
                  {x}
                </Pill>
              ))}
            </p>
          )}
        </div>
      )}
    </section>
  )
}

function NoteForm({ d, onDone }: { d: ProductDetail; onDone: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [note, setNote] = useState(d.follow?.note ?? "")
  const [tags, setTags] = useState((d.follow?.tags ?? []).join(", "))
  const [busy, setBusy] = useState(false)
  const parsed = tags
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
  const dirty = note.trim() !== (d.follow?.note ?? "") || parsed.join(",") !== (d.follow?.tags ?? []).join(",")
  const save = async () => {
    setBusy(true)
    try {
      await api.put(`/api/vendor/follows/${encodeURIComponent(d.product.key)}`, { enabled: !!d.follow?.enabled, note: note.trim(), tags: parsed.slice(0, 10) })
      toast.success(t("common.saved"))
      await refreshVendor(qc, productKeyOf(d.product.key))
      onDone()
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault()
        void save()
      }}
    >
      <Field label={t("vendor.note")}>
        <Textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder={t("vendor.notePlaceholder")}
          className="placeholder:text-muted-foreground/60"
          maxLength={500}
        />
      </Field>
      <Field label={t("vendor.notes.tags")}>
        <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder={t("vendor.tagsPlaceholder")} className="placeholder:text-muted-foreground/60" maxLength={300} />
      </Field>
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onDone}>
          {t("common.cancel")}
        </Button>
        <Button type="submit" disabled={!dirty || busy}>
          {busy ? <Loader2 className="animate-spin" /> : <Check />} {t("common.save")}
        </Button>
      </div>
    </form>
  )
}
