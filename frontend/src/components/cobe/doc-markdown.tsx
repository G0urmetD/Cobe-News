import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Link } from "react-router"
import { BookOpen, Check, Copy, ExternalLink, Info, Lightbulb, Link2, ShieldCheck, TriangleAlert } from "lucide-react"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill } from "@/components/cobe/badges"
import { copyWithToast } from "@/lib/clipboard"
import { type Block, type CalloutKind, type Inline, fillLive, parseInline } from "@/lib/docs-markdown"
import { docPath, sectionDomId } from "@/lib/docs"
import { cn } from "@/lib/utils"

/**
 * The handbook's blocks as React elements (lib/docs-markdown.ts parses them). Everything from the files ends up as React
 * text – a tag in a file shows as text, never as markup; links only to the targets the parser allowed.
 */
export function DocBlocks({ blocks, chapter, live }: { blocks: Block[]; chapter: string; live: Record<string, string> }) {
  return (
    <div className="space-y-4 text-sm leading-relaxed">
      {blocks.map((b, i) => (
        <DocBlock key={i} block={b} chapter={chapter} live={live} />
      ))}
    </div>
  )
}

function DocBlock({ block: b, chapter, live }: { block: Block; chapter: string; live: Record<string, string> }) {
  switch (b.t) {
    case "heading":
      return <SectionHeading level={b.level} id={b.id} text={b.text} admin={b.admin} chapter={chapter} live={live} />
    case "subheading":
      return (
        <h5 className="pt-1 text-sm font-semibold">
          <Inlines c={b.c} live={live} />
        </h5>
      )
    case "para":
      return (
        <p className="break-words">
          <Inlines c={b.c} live={live} />
        </p>
      )
    case "list":
      return <DocList block={b} chapter={chapter} live={live} />
    case "code":
      return <CodeBlock lang={b.lang} text={fillLive(b.text, live)} />
    case "table":
      return <DocTable block={b} live={live} />
    case "callout":
      return <Callout kind={b.kind} blocks={b.blocks} chapter={chapter} live={live} />
  }
}

function SectionHeading({ level, id, text, admin, chapter, live }: { level: 2 | 3; id: string; text: string; admin: boolean; chapter: string; live: Record<string, string> }) {
  const { t } = useTranslation()
  // the page has the h1 (Dokumentation) and the chapter title (h2): ## → h3, ### → h4
  const H = level === 2 ? "h3" : "h4"
  const copyLink = () => void copyWithToast(`${window.location.origin}${docPath(chapter, id)}`, t("docs.linkCopied"))
  return (
    <H
      id={sectionDomId(id)}
      className={cn(
        "group/h flex scroll-mt-20 flex-wrap items-center gap-x-2 gap-y-1 font-semibold tracking-tight",
        level === 2 ? "border-t pt-6 text-lg first:border-t-0 first:pt-0" : "pt-2 text-base",
      )}
    >
      <span className="min-w-0 break-words">
        <Inlines c={parseInline(text)} live={live} />
      </span>
      {admin && <AdminPill />}
      <button
        type="button"
        onClick={copyLink}
        aria-label={t("docs.copyLink")}
        title={t("docs.copyLink")}
        className="rounded p-1 text-muted-foreground opacity-40 transition-opacity group-hover/h:opacity-100 hover:bg-muted hover:text-foreground focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
      >
        <Link2 className="size-3.5" />
      </button>
    </H>
  )
}

export function AdminPill() {
  const { t } = useTranslation()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          <Pill color="--chart-2">
            <ShieldCheck aria-hidden /> {t("docs.adminOnly")}
          </Pill>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">{t("docs.adminOnlyHint")}</TooltipContent>
    </Tooltip>
  )
}

function DocList({ block, chapter, live }: { block: Extract<Block, { t: "list" }>; chapter: string; live: Record<string, string> }) {
  const items = block.items.map((item, i) => {
    // a one-paragraph item: its text directly (tight list); otherwise its blocks
    const only = item.length === 1 && item[0].t === "para" ? item[0] : null
    return (
      <li key={i} className="pl-1 break-words">
        {only ? (
          <Inlines c={only.c} live={live} />
        ) : (
          <div className="space-y-2">
            {item.map((b, k) => (
              <DocBlock key={k} block={b} chapter={chapter} live={live} />
            ))}
          </div>
        )}
      </li>
    )
  })
  return block.ordered ? (
    <ol start={block.start} className="list-decimal space-y-1.5 pl-6 marker:text-muted-foreground">
      {items}
    </ol>
  ) : (
    <ul className="list-disc space-y-1.5 pl-5 marker:text-muted-foreground">{items}</ul>
  )
}

export function CodeBlock({ lang, text }: { lang: string; text: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const copy = () =>
    void copyWithToast(text).then((ok) => {
      if (!ok) return
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    })
  return (
    <div className="min-w-0 overflow-hidden rounded-lg border bg-muted/40">
      <div className="flex items-center justify-between gap-2 border-b bg-muted/50 py-1 pr-1 pl-3">
        <span className="font-mono text-[11px] text-muted-foreground uppercase">{lang || "text"}</span>
        <button
          type="button"
          onClick={copy}
          aria-label={t("docs.copyCode")}
          title={t("docs.copyCode")}
          className="inline-flex items-center gap-1 rounded px-1.5 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
          <span>{t("common.copy")}</span>
        </button>
      </div>
      <pre className="overflow-x-auto p-3 font-mono text-[12.5px] leading-relaxed">
        <code>{text}</code>
      </pre>
    </div>
  )
}

/** A table – on narrow screens each row becomes a small card with the column names as labels (375 px, docs/UX.md). */
function DocTable({ block, live }: { block: Extract<Block, { t: "table" }>; live: Record<string, string> }) {
  const align = (n: number) => (block.align[n] === "right" ? "text-right" : block.align[n] === "center" ? "text-center" : "text-left")
  return (
    <>
      <div className="hidden overflow-x-auto rounded-lg border sm:block">
        <table className="w-full border-collapse text-sm">
          <thead className="bg-muted/50">
            <tr>
              {block.head.map((c, n) => (
                <th key={n} scope="col" className={cn("border-b px-3 py-2 align-bottom text-xs font-semibold", align(n))}>
                  <Inlines c={c} live={live} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {block.rows.map((row, r) => (
              <tr key={r} className="border-b last:border-b-0">
                {row.map((c, n) => (
                  <td key={n} className={cn("px-3 py-2 align-top break-words", align(n))}>
                    <Inlines c={c} live={live} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="space-y-2 sm:hidden">
        {block.rows.map((row, r) => (
          <dl key={r} className="space-y-1.5 rounded-lg border p-3">
            {row.map((c, n) => (
              <div key={n} className="min-w-0">
                <dt className="text-[11px] font-medium text-muted-foreground uppercase">
                  <Inlines c={block.head[n]} live={live} />
                </dt>
                <dd className="break-words">
                  <Inlines c={c} live={live} />
                </dd>
              </div>
            ))}
          </dl>
        ))}
      </div>
    </>
  )
}

const CALLOUT: Record<CalloutKind, { color: string; icon: React.ElementType }> = {
  note: { color: "--primary", icon: Info },
  tip: { color: "--success", icon: Lightbulb },
  warning: { color: "--warning", icon: TriangleAlert },
}

function Callout({ kind, blocks, chapter, live }: { kind: CalloutKind; blocks: Block[]; chapter: string; live: Record<string, string> }) {
  const { t } = useTranslation()
  const { color, icon: Icon } = CALLOUT[kind]
  return (
    <div
      role="note"
      className="rounded-lg border border-l-4 p-3"
      style={{ borderLeftColor: `var(${color})`, backgroundColor: `color-mix(in oklch, var(${color}) 6%, transparent)` }}
    >
      <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold" style={{ color: `var(${color})` }}>
        <Icon className="size-3.5" aria-hidden /> {t(`docs.callout.${kind}`)}
      </p>
      <DocBlocks blocks={blocks} chapter={chapter} live={live} />
    </div>
  )
}

/** Inline tokens as React elements. */
export function Inlines({ c, live }: { c: Inline[]; live: Record<string, string> }) {
  return (
    <>
      {c.map((x, i) => (
        <InlineNode key={i} x={x} live={live} />
      ))}
    </>
  )
}

function InlineNode({ x, live }: { x: Inline; live: Record<string, string> }) {
  const { t } = useTranslation()
  switch (x.t) {
    case "text":
      return <>{x.v}</>
    case "strong":
      return (
        <strong className="font-semibold">
          <Inlines c={x.c} live={live} />
        </strong>
      )
    case "em":
      return (
        <em>
          <Inlines c={x.c} live={live} />
        </em>
      )
    case "code":
      // {{name}} in `code` is the installation's value too (as in code blocks)
      return <code className="rounded bg-muted px-1 py-0.5 font-mono text-[0.86em] break-words">{fillLive(x.v, live)}</code>
    case "live":
      return Object.hasOwn(live, x.name) ? <LiveValue value={live[x.name]} /> : <>{`{{${x.name}}}`}</>
    case "term":
      return <DocTerm k={x.k} label={<Inlines c={x.c} live={live} />} />
    case "link":
      if (x.kind === "external")
        return (
          <a href={x.href} target="_blank" rel="noopener noreferrer" className="font-medium text-primary underline-offset-4 hover:underline">
            <Inlines c={x.c} live={live} />
            <ExternalLink className="ml-0.5 inline size-3 align-[-1px]" aria-hidden />
            <span className="sr-only"> ({t("docs.external")})</span>
          </a>
        )
      return (
        <Link to={x.href} className="font-medium text-primary underline-offset-4 hover:underline">
          <Inlines c={x.c} live={live} />
        </Link>
      )
  }
}

/** A term with its explanation on hover or focus: the app's glossary (glossary.*) or the handbook's own (docs.term.*). */
function DocTerm({ k, label }: { k: string; label: React.ReactNode }) {
  const { t, i18n } = useTranslation()
  const base = i18n.exists(`glossary.${k}`) ? `glossary.${k}` : i18n.exists(`docs.term.${k}`) ? `docs.term.${k}` : null
  if (!base) return <>{label}</>
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className="cursor-help underline decoration-muted-foreground/60 decoration-dotted underline-offset-4 outline-none focus-visible:rounded-sm focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          {label}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs text-left leading-relaxed">
        <span className="block">
          <span className="font-semibold">{t(base)}</span> – {t(`${base}Text`)}
        </span>
      </TooltipContent>
    </Tooltip>
  )
}

/** A value of this installation (the Entra redirect URI …) – highlighted, with copy. */
function LiveValue({ value }: { value: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const copy = () =>
    void copyWithToast(value).then((ok) => {
      if (!ok) return
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    })
  return (
    <span className="inline-flex max-w-full items-center gap-1 rounded-md border border-primary/30 bg-primary/5 py-0.5 pr-0.5 pl-1.5 align-middle font-mono text-[0.86em]">
      <Tooltip>
        <TooltipTrigger asChild>
          <span tabIndex={0} className="min-w-0 break-all outline-none focus-visible:ring-2 focus-visible:ring-ring/50" data-testid="doc-live">
            {value}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs leading-relaxed">
          <span className="block">
            <span className="font-semibold">{t("docs.liveValue")}</span> – {t("docs.liveValueHint")}
          </span>
        </TooltipContent>
      </Tooltip>
      <button
        type="button"
        onClick={copy}
        aria-label={t("common.copy")}
        title={t("common.copy")}
        className="shrink-0 rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
      >
        {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
      </button>
    </span>
  )
}

/** "Hilfe" – a small link from a settings card to the matching section of the handbook. */
export function HelpLink({ chapter, section, topic }: { chapter: string; section?: string; topic?: string }) {
  const { t } = useTranslation()
  const label = topic ? t("docs.helpFor", { topic }) : t("docs.help")
  return (
    <Link
      to={docPath(chapter, section)}
      aria-label={label}
      title={label}
      className="inline-flex shrink-0 items-center gap-1 rounded-md px-1.5 py-1 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
    >
      <BookOpen className="size-3.5" aria-hidden /> {t("docs.help")}
    </Link>
  )
}
