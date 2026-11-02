import { useState } from "react"
import { Link } from "react-router"
import { useTranslation } from "react-i18next"
import { AlertTriangle, Globe, History, ShieldAlert, ShieldCheck, Wrench } from "lucide-react"
import { Pill } from "@/components/cobe/badges"
import { Mono } from "@/components/cobe/common"
import { EpssPill, SsvcPill } from "@/components/cobe/epss"
import { Term } from "@/components/cobe/glossary"
import { Ts } from "@/components/cobe/time"
import { CveChips, WatchAllButton } from "@/components/cobe/watch-all"
import { WatchStar } from "@/components/cobe/watch-star"
import { fmtDay } from "@/lib/format"
import type { NewsDetail, NewsItem, StoryDetails } from "@/lib/news-api"
import { STATUS_COLOR, type Status } from "@/lib/vendor-api"
import { cn } from "@/lib/utils"
import { storyWatchCves } from "@/lib/watch-api"

const SHOWN_PRODUCTS = 6
const SHOWN_RANGES = 8
const SHOWN_CVES = 12

/** The story's CVEs for "Alle beobachten": its own and its details', the likeliest first (EPSS). */
const watchAllOf = (d: NewsDetail) => storyWatchCves(d.cves, d.details?.cves ?? [], d.epss ?? [])

function cvssTone(score: number): string {
  return score >= 9 ? "--sev-critical" : score >= 7 ? "--sev-high" : score >= 4 ? "--sev-medium" : "--sev-low"
}

/** "betrifft deine Systeme": the followed products (Vendor News) this story's details concern, per version entry. */
export function AffectsYou({ d }: { d: NewsDetail }) {
  const { t } = useTranslation()
  const rows = d.affects.filter((a) => a.versions.some((v) => v.status !== "not_affected"))
  if (!rows.length) return null
  return (
    <section className="space-y-2 rounded-lg border border-sev-critical/40 bg-sev-critical/5 p-3">
      <p className="flex items-center gap-2 text-sm font-semibold">
        <ShieldAlert className="size-4 text-sev-critical" /> {t("details.affectsYou")}
      </p>
      <ul className="space-y-1.5">
        {rows.map((a) => (
          <li key={a.product} className="space-y-1 text-xs">
            <Link to={`/vendor?product=${encodeURIComponent(a.product)}`} className="font-medium text-primary hover:underline">
              {a.label}
            </Link>
            <ul className="flex flex-wrap gap-1.5">
              {a.versions.map((v) => (
                <li key={v.id ?? "none"} className="flex items-center gap-1.5 rounded-md border bg-background px-2 py-1">
                  {v.version ? <span className="font-mono">{v.version}</span> : <span className="text-muted-foreground">{t("vendor.allVersions")}</span>}
                  {v.label && <span className="text-muted-foreground">{v.label}</span>}
                  <Pill color={STATUS_COLOR[v.status as Status]} dot>
                    {t(`vendor.status.${v.status}`)}
                  </Pill>
                  {v.fixed && (
                    <span>
                      {t("vendor.fixIn")} <span className="font-mono font-semibold">{v.fixed}</span>
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </section>
  )
}

/** "Betroffene Versionen": the structured advisory behind the story, compact, above its text. With the story (`story`):
 * its stars keep it as their origin, and "Alle beobachten" sits above its CVEs. */
export function StoryDetailsBlock({ details, story }: { details: StoryDetails; story?: NewsDetail }) {
  const { t } = useTranslation()
  const [allProducts, setAllProducts] = useState(false)
  const products = details.products.filter((p) => p.affected.length > 0)
  const shown = allProducts ? products : products.slice(0, SHOWN_PRODUCTS)
  const cvss = details.cvss[0]
  const updated =
    details.revision.count > 1 || (details.revision.current && details.revision.initial && details.revision.current.slice(0, 10) !== details.revision.initial.slice(0, 10))
  return (
    <section className="space-y-3 rounded-lg border p-3">
      <div className="flex flex-wrap items-center gap-1.5">
        <h3 className="mr-auto text-xs font-semibold tracking-wide text-muted-foreground uppercase">{t("details.title")}</h3>
        {cvss && (
          <Pill color={cvssTone(cvss.score)} title={cvss.vector || undefined}>
            <Term k="cvss">CVSS</Term> {cvss.score.toFixed(1)}
            {cvss.temporal !== null && cvss.temporal !== cvss.score && ` · ${t("details.temporal")} ${cvss.temporal.toFixed(1)}`}
            {cvss.nvd && ` · NVD`}
          </Pill>
        )}
        {details.severity_text && <Pill color="--muted-foreground">{details.severity_text}</Pill>}
        {details.exploited && (
          <Pill color="--sev-critical">
            <AlertTriangle /> {t("vendor.exploited")}
          </Pill>
        )}
        {details.remote && (
          <Pill color="--sev-high">
            <Globe /> {t("details.remote")}
          </Pill>
        )}
        {details.mitigation && (
          <Pill color="--success">
            <ShieldCheck /> {t("details.mitigation")}
          </Pill>
        )}
        {details.ssvc && <SsvcPill s={details.ssvc} />}
      </div>
      {shown.length > 0 ? (
        <ul className="space-y-1.5 text-xs">
          {shown.map((p) => (
            <li key={`${p.vendor}|${p.name}`} className="leading-relaxed">
              <span className="font-medium">{p.name}</span>
              {p.vendor && p.vendor !== "Open Source" && !p.name.startsWith(p.vendor) && <span className="text-muted-foreground"> · {p.vendor}</span>}
              {": "}
              <span className="font-mono">
                {p.affected
                  .slice(0, SHOWN_RANGES)
                  .map((r) => (r.all ? t("details.allVersions") : r.text))
                  .join(", ")}
              </span>
              {p.affected.length > SHOWN_RANGES && <span className="text-muted-foreground"> {t("details.moreRanges", { count: p.affected.length - SHOWN_RANGES })}</span>}
              {p.fixed.length > 0 && (
                <span className="text-muted-foreground">
                  {" "}
                  · {t("details.fixed")} <span className="font-mono text-foreground">{p.fixed.slice(0, SHOWN_RANGES).join(", ")}</span>
                </span>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-muted-foreground">{t("details.noProducts")}</p>
      )}
      {(products.length > SHOWN_PRODUCTS || details.more_products > 0) && !allProducts && (
        <button type="button" className="text-xs font-medium text-primary hover:underline" onClick={() => setAllProducts(true)}>
          {t("details.moreProducts", { count: products.length - SHOWN_PRODUCTS + details.more_products })}
        </button>
      )}
      {details.remediations.filter((r) => r.category !== "vendor_fix").length > 0 && (
        <ul className="space-y-1 text-xs">
          {details.remediations
            .filter((r) => r.category !== "vendor_fix")
            .slice(0, 2)
            .map((r, i) => (
              <li key={i} className="flex gap-1.5">
                <Wrench className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
                <span className="line-clamp-3 whitespace-pre-line">
                  <span className="font-medium">{t(`details.rem.${r.category}`, { defaultValue: r.category })}:</span> {r.text}
                </span>
              </li>
            ))}
        </ul>
      )}
      {details.kev && (
        <p className="text-xs text-muted-foreground">
          <Term k="kev">KEV</Term>
          {details.kev.due && ` · ${t("details.kevDue", { date: details.kev.due })}`}
          {details.kev.ransomware && ` · ${t("vendor.ransomware")}`}
        </p>
      )}
      {details.cves.length > 0 && (
        <div className="space-y-1.5">
          {story && (
            <div className="flex justify-end">
              <WatchAllButton cves={watchAllOf(story)} origin={{ kind: "story", id: story.id }} order="epss" />
            </div>
          )}
          <CveChips cves={details.cves} shown={SHOWN_CVES} origin={story ? { kind: "story", id: story.id } : undefined} />
        </div>
      )}
      <p className="flex flex-wrap items-center gap-1.5 border-t pt-2 text-[11px] text-muted-foreground">
        <History className="size-3.5" />
        {details.revision.current && (
          <span>
            {updated ? t("details.updated") : t("details.published")} {/* a source that dates by day only (Veeam's KB): the day, not midnight UTC as a time */}
            {/^\d{4}-\d{2}-\d{2}$/.test(details.revision.current) ? fmtDay(details.revision.current) : <Ts at={details.revision.current} zone />}
            {details.revision.summary && updated && ` – ${details.revision.summary}`}
          </span>
        )}
        <span className="ml-auto">
          {t("details.from", { source: details.publisher })}
          {details.via_nvd && ` · ${t("details.viaNvd")}`}
          {details.via_cvelist && ` · ${t("details.viaCvelist")}`}
          {details.id && <span className="font-mono"> · {details.id}</span>}
        </span>
      </p>
    </section>
  )
}

/** The card's line under the teaser: CVSS and "betrifft GitLab <19.5.1" – red when a followed product is concerned. */
export function DetailHint({ n }: { n: NewsItem }) {
  const { t } = useTranslation()
  const h = n.hint
  if (!h || (!h.cvss && !h.product)) return null
  return (
    <p className={cn("flex min-w-0 items-center gap-1.5 text-[11px]", h.affects ? "font-medium text-sev-critical" : "text-muted-foreground")}>
      {h.cvss !== null && (
        <span
          className="shrink-0 rounded px-1 font-mono"
          style={{ color: `var(${cvssTone(h.cvss)})`, backgroundColor: `color-mix(in oklch, var(${cvssTone(h.cvss)}) 11%, transparent)` }}
        >
          {h.cvss.toFixed(1)}
        </span>
      )}
      {h.affects && <ShieldAlert className="size-3.5 shrink-0" />}
      {h.product && <span className="truncate">{h.affects ? t("details.hintAffects", { product: h.product }) : t("details.hint", { product: h.product })}</span>}
    </p>
  )
}

/** The story's CVEs with their EPSS (as far as FIRST was asked): the likeliest to be exploited first. */
export function StoryCves({ d }: { d: NewsDetail }) {
  const { t } = useTranslation()
  const scores = new Map((d.epss ?? []).map((e) => [e.cve, e]))
  const cves = [...d.cves].sort((a, b) => (scores.get(b)?.score ?? -1) - (scores.get(a)?.score ?? -1))
  const origin = { kind: "story", id: d.id } as const
  return (
    <section className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{t("news.cveTitle")}</h3>
        {/* "Alle beobachten" once per drawer: above the details' CVEs when there are some, else here */}
        {!d.details?.cves.length && <WatchAllButton cves={watchAllOf(d)} origin={origin} order="epss" />}
      </div>
      <ul className="flex flex-wrap gap-2">
        {cves.map((c) => {
          const e = scores.get(c)
          return (
            <li key={c} className="flex items-center gap-1.5">
              <Mono value={c} />
              <WatchStar cve={c} origin={origin} />
              {e && <EpssPill e={e} />}
            </li>
          )
        })}
      </ul>
      {scores.size > 0 && <p className="text-[11px] text-muted-foreground">{t("details.epss")}</p>}
    </section>
  )
}
