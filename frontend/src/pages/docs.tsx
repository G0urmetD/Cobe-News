import { useEffect, useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link, Navigate, useLocation, useNavigate, useParams } from "react-router"
import { BookOpen, ChevronLeft, ChevronRight, FileQuestion, Search, SearchX, ShieldCheck, X } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { EmptyState, PageHeader } from "@/components/cobe/common"
import { AdminPill, DocBlocks } from "@/components/cobe/doc-markdown"
import { Pending } from "@/components/cobe/query-state"
import { type Block, type SearchHit, highlightParts, parseMarkdown, searchSections, sectionTexts } from "@/lib/docs-markdown"
import { type DocChapter, docPath, docsLang, sectionDomId, useDocs } from "@/lib/docs"
import { cn } from "@/lib/utils"

/** "Dokumentation": the handbook – chapters in a sidebar (a select on small screens), search across all of them, deep
 * links /docs/<chapter>#<section>. What a reader may not see never reaches the browser (backend/app/docs.py). */
export function DocsPage() {
  const { t, i18n } = useTranslation()
  const { chapter: chapterId } = useParams()
  const { hash } = useLocation()
  const q = useDocs(docsLang(i18n.language))
  const [query, setQuery] = useState("")

  const parsed = useMemo(() => {
    const live = q.data?.live ?? {}
    return (q.data?.chapters ?? []).map((c) => {
      const blocks = parseMarkdown(c.markdown)
      return { chapter: c, blocks, texts: sectionTexts(blocks, live) }
    })
  }, [q.data])
  const hits = useMemo(
    () =>
      query.trim().length >= 2
        ? searchSections(
            parsed.map((p) => ({ id: p.chapter.id, title: p.chapter.title, sections: p.texts })),
            query,
          )
        : [],
    [parsed, query],
  )
  const index = parsed.findIndex((p) => p.chapter.id === chapterId)

  // a deep link (#section) or a click in the sidebar: to that heading once the chapter is drawn; a new chapter: to the top
  useEffect(() => {
    if (index < 0 || query.trim()) return
    const id = setTimeout(() => {
      const el = hash ? document.getElementById(sectionDomId(decodeURIComponent(hash.slice(1)))) : null
      if (el) el.scrollIntoView({ block: "start" })
      else if (!hash) window.scrollTo({ top: 0 })
    }, 0)
    return () => clearTimeout(id)
  }, [hash, index, query])

  if (!q.data) return <Pending error={q.error} onRetry={() => void q.refetch()} />
  if (parsed.length === 0) return <EmptyState icon={BookOpen} title={t("docs.empty")} text={t("docs.emptyText")} />
  if (!chapterId) return <Navigate to={`${docPath(parsed[0].chapter.id)}${hash}`} replace />
  const current = index >= 0 ? parsed[index] : null

  return (
    <div className="mx-auto w-full max-w-6xl">
      <PageHeader title={t("docs.title")} description={t("docs.description")}>
        <SearchBox value={query} onChange={setQuery} />
      </PageHeader>
      <div className="grid gap-8 lg:grid-cols-[240px_minmax(0,1fr)]">
        <ChapterNav chapters={parsed.map((p) => p.chapter)} active={current?.chapter.id} hash={hash} />
        <div className="min-w-0">
          {query.trim() ? (
            <Results hits={hits} query={query} chapters={parsed.map((p) => p.chapter)} onOpen={() => setQuery("")} />
          ) : current ? (
            <>
              <MobileNav chapters={parsed.map((p) => p.chapter)} current={current.chapter} />
              <Chapter
                chapter={current.chapter}
                blocks={current.blocks}
                number={index + 1}
                live={q.data.live}
                prev={parsed[index - 1]?.chapter}
                next={parsed[index + 1]?.chapter}
                fallback={docsLang(i18n.language) !== current.chapter.lang}
              />
            </>
          ) : (
            <EmptyState
              icon={FileQuestion}
              title={t("docs.notFound")}
              text={t("docs.notFoundText")}
              action={
                <Link to={docPath(parsed[0].chapter.id)} className="text-sm font-medium text-primary hover:underline">
                  {t("docs.toOverview")}
                </Link>
              }
            />
          )}
        </div>
      </div>
    </div>
  )
}

function SearchBox({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation()
  return (
    <div className="relative w-full max-w-md">
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
      <Input
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => e.key === "Escape" && value && (e.preventDefault(), onChange(""))}
        maxLength={100}
        placeholder={t("docs.searchPlaceholder")}
        aria-label={t("docs.search")}
        className="h-9 pr-9 pl-8 placeholder:text-muted-foreground/60 [&::-webkit-search-cancel-button]:hidden"
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange("")}
          aria-label={t("docs.clearSearch")}
          title={t("docs.clearSearch")}
          className="absolute top-1/2 right-1.5 -translate-y-1/2 rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          <X className="size-3.5" />
        </button>
      )}
    </div>
  )
}

/** The chapters (lg and up): the open one lists its sections. */
function ChapterNav({ chapters, active, hash }: { chapters: DocChapter[]; active?: string; hash: string }) {
  const { t } = useTranslation()
  return (
    <nav aria-label={t("docs.chapters")} className="hidden lg:sticky lg:top-20 lg:block lg:max-h-[calc(100svh-6rem)] lg:self-start lg:overflow-y-auto lg:pr-1">
      <p className="px-2 pb-2 text-xs font-medium text-muted-foreground">{t("docs.chapters")}</p>
      <ol className="space-y-0.5">
        {chapters.map((c, i) => {
          const open = c.id === active
          return (
            <li key={c.id}>
              <Link
                to={docPath(c.id)}
                aria-current={open && !hash ? "page" : undefined}
                className={cn(
                  "flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm font-medium transition-colors",
                  open ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
              >
                <span className="w-4 shrink-0 text-right text-xs tabular-nums opacity-70">{i + 1}</span>
                <span className="min-w-0 flex-1">{c.title}</span>
                {c.audience === "admin" && <AdminMark />}
              </Link>
              {open && (
                <ul className="my-1 ml-[1.15rem] space-y-0.5 border-l pl-2">
                  {c.sections
                    .filter((s) => s.level === 2)
                    .map((s) => (
                      <li key={s.id}>
                        <Link
                          to={docPath(c.id, s.id)}
                          aria-current={hash === `#${s.id}` ? "location" : undefined}
                          className={cn(
                            "flex items-center gap-1.5 rounded-md px-2 py-1 text-[13px] transition-colors",
                            hash === `#${s.id}` ? "font-medium text-foreground" : "text-muted-foreground hover:text-foreground",
                          )}
                        >
                          <span className="min-w-0 flex-1">{s.title}</span>
                          {s.admin && <AdminMark />}
                        </Link>
                      </li>
                    ))}
                </ul>
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}

/** A small shield: only admins get this chapter/section (shown to admins – readers never receive it). */
function AdminMark() {
  const { t } = useTranslation()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <ShieldCheck className="size-3.5 shrink-0 text-chart-2" aria-label={t("docs.adminOnly")} />
      </TooltipTrigger>
      <TooltipContent>{t("docs.adminOnly")}</TooltipContent>
    </Tooltip>
  )
}

/** Below lg: the chapter and the section as two selects (popper – they open below, docs/UX.md). */
function MobileNav({ chapters, current }: { chapters: DocChapter[]; current: DocChapter }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { hash } = useLocation()
  const START = "__start"
  return (
    <div className="mb-6 grid gap-2 sm:grid-cols-2 lg:hidden">
      <Select value={current.id} onValueChange={(v) => navigate(docPath(v))}>
        <SelectTrigger className="w-full" aria-label={t("docs.chapter")}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent position="popper">
          {chapters.map((c, i) => (
            <SelectItem key={c.id} value={c.id}>
              {i + 1}. {c.title}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {current.sections.length > 0 && (
        <Select value={hash ? hash.slice(1) : START} onValueChange={(v) => navigate(v === START ? docPath(current.id) : docPath(current.id, v))}>
          <SelectTrigger className="w-full" aria-label={t("docs.jumpTo")}>
            <SelectValue placeholder={t("docs.jumpTo")} />
          </SelectTrigger>
          <SelectContent position="popper" className="max-h-80">
            <SelectItem value={START}>{t("docs.chapterStart")}</SelectItem>
            {current.sections.map((s) => (
              <SelectItem key={s.id} value={s.id} className={s.level === 3 ? "pl-6 text-muted-foreground" : undefined}>
                {s.title}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
    </div>
  )
}

function Chapter({
  chapter,
  blocks,
  number,
  live,
  prev,
  next,
  fallback,
}: {
  chapter: DocChapter
  blocks: Block[]
  number: number
  live: Record<string, string>
  prev?: DocChapter
  next?: DocChapter
  fallback: boolean
}) {
  const { t } = useTranslation()
  return (
    <article aria-labelledby="doc-chapter-title" className="min-w-0" data-testid="doc-chapter">
      <header className="mb-6 space-y-2 border-b pb-5">
        <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          {t("docs.chapter")} {number}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <h2 id="doc-chapter-title" className="text-xl font-semibold tracking-tight">
            {chapter.title}
          </h2>
          {chapter.audience === "admin" && <AdminPill />}
        </div>
        {chapter.summary && <p className="text-sm text-muted-foreground">{chapter.summary}</p>}
        {fallback && <p className="text-xs text-muted-foreground">{t("docs.fallback")}</p>}
      </header>
      <DocBlocks blocks={blocks} chapter={chapter.id} live={live} />
      <nav aria-label={t("docs.chapters")} className="mt-10 grid gap-3 border-t pt-5 sm:grid-cols-2">
        {prev ? <PrevNext chapter={prev} dir="prev" /> : <span />}
        {next && <PrevNext chapter={next} dir="next" />}
      </nav>
    </article>
  )
}

function PrevNext({ chapter, dir }: { chapter: DocChapter; dir: "prev" | "next" }) {
  const { t } = useTranslation()
  const Icon = dir === "prev" ? ChevronLeft : ChevronRight
  return (
    <Link
      to={docPath(chapter.id)}
      className={cn(
        "flex items-center gap-2 rounded-lg border p-3 text-sm transition-colors hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
        dir === "next" && "justify-end text-right sm:col-start-2",
      )}
    >
      {dir === "prev" && <Icon className="size-4 shrink-0 text-muted-foreground" />}
      <span className="min-w-0">
        <span className="block text-xs text-muted-foreground">{t(dir === "prev" ? "docs.prev" : "docs.next")}</span>
        <span className="block font-medium">{chapter.title}</span>
      </span>
      {dir === "next" && <Icon className="size-4 shrink-0 text-muted-foreground" />}
    </Link>
  )
}

function Results({ hits, query, chapters, onOpen }: { hits: SearchHit[]; query: string; chapters: DocChapter[]; onOpen: () => void }) {
  const { t } = useTranslation()
  if (query.trim().length < 2) return <p className="text-sm text-muted-foreground">{t("docs.searchShort")}</p>
  if (hits.length === 0) return <EmptyState icon={SearchX} title={t("docs.noResults")} text={t("docs.noResultsText")} />
  const titleOf = (id: string) => chapters.find((c) => c.id === id)?.title ?? id
  return (
    <section aria-label={t("docs.search")}>
      <p className="mb-3 text-xs text-muted-foreground" role="status">
        {t("docs.results", { count: hits.length })}
      </p>
      <ul className="space-y-2" data-testid="doc-results">
        {hits.map((h) => (
          <li key={`${h.chapter}#${h.section}`}>
            <Link
              to={docPath(h.chapter, h.section || undefined)}
              onClick={onOpen}
              className="block rounded-lg border p-3 transition-colors hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
            >
              <span className="block text-xs text-muted-foreground">{titleOf(h.chapter)}</span>
              <span className="block text-sm font-medium">
                <Marked text={h.title} query={query} />
              </span>
              {h.snippet && (
                <span className="mt-1 block text-xs leading-relaxed break-words text-muted-foreground">
                  <Marked text={h.snippet} query={query} />
                </span>
              )}
            </Link>
          </li>
        ))}
      </ul>
    </section>
  )
}

/** The search words highlighted – as React text in <mark>, never as markup. */
function Marked({ text, query }: { text: string; query: string }) {
  return (
    <>
      {highlightParts(text, query).map((p, i) =>
        p.hit ? (
          <mark key={i} className="rounded-sm bg-warning/25 px-0.5 text-foreground">
            {p.text}
          </mark>
        ) : (
          <span key={i}>{p.text}</span>
        ),
      )}
    </>
  )
}
