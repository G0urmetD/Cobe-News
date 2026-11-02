import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import { AlertTriangle, BookOpenText, ChevronRight, Copy, Download, Info, KeyRound, Loader2, Lock, Plus, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet } from "@/components/ui/sheet"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill } from "@/components/cobe/badges"
import { EmptyState } from "@/components/cobe/common"
import { Explained } from "@/components/cobe/explained"
import { confirmAction } from "@/components/cobe/confirm"
import { CodeBlock, HelpLink } from "@/components/cobe/doc-markdown"
import { Field, ToggleRow } from "@/components/cobe/form"
import { Term } from "@/components/cobe/glossary"
import { SubTabs } from "@/components/cobe/sub-tabs"
import { Ts } from "@/components/cobe/time"
import { api, saveBlob } from "@/lib/api"
import {
  type ApiOperation,
  type ApiToken,
  type OpenApiDoc,
  type SchemaField,
  type TokenList,
  type TokenMade,
  type TokenScope,
  codeSpans,
  curlExample,
  DEFAULT_EXPIRY,
  describeType,
  expiryChoices,
  fmtDefault,
  groupOperations,
  isEnded,
  isLive,
  mainResponse,
  OPENAPI_FILE,
  otherResponses,
  powershellExample,
  prometheusExample,
  PROMETHEUS_TOKEN_FILE,
  schemaFields,
  sortTokens,
  TOKEN_STATE_COLOR,
  TOKENS_KEY,
  useApiTokens,
  useOpenApi,
  validName,
} from "@/lib/api-tokens"
import { copyWithToast } from "@/lib/clipboard"
import { errorText } from "@/lib/errors"
import { withReauth } from "@/lib/reauth"
import { cn } from "@/lib/utils"
import { IntegrationSheetContent, SettingsCard, SheetActions, SheetBody, SheetLoading } from "@/pages/settings-shared"

type ApiTab = "tokens" | "reference"

/** Settings → API & Metriken (admins): read-only API tokens for scripts, a SIEM or Prometheus (app/api_tokens.py) | the
 *  reference of what a token reaches – the curated OpenAPI of /api/v1 and /metrics, drawn here as text (sub-tabs, `?tab=`). */
export function ApiSettings() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const tab: ApiTab = params.get("tab") === "reference" ? "reference" : "tokens"
  const parts = [
    { key: "tokens" as const, icon: KeyRound, label: t("apiTokens.tab.tokens") },
    { key: "reference" as const, icon: BookOpenText, label: t("apiTokens.tab.reference") },
  ]
  return (
    <>
      <SubTabs parts={parts} active={tab} to={(k) => (k === "tokens" ? "?" : `?tab=${k}`)} label={t("settings.nav.api")} />
      {tab === "reference" ? <ReferenceCard /> : <TokensCard />}
    </>
  )
}

// ---------------------------------------------------------------- tokens

/** A scope as a pill with its meaning on hover or focus. */
function ScopePill({ scope, plain = false }: { scope: string; plain?: boolean }) {
  const { t } = useTranslation()
  // inside a button (the folded operation): the meaning as a title, no second focus stop
  if (plain)
    return (
      <Pill color="--primary" title={t(`apiTokens.scope.${scope}Hint`, { defaultValue: scope })}>
        {t(`apiTokens.scope.${scope}`, { defaultValue: scope })}
      </Pill>
    )
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex cursor-help rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          <Pill color="--primary">{t(`apiTokens.scope.${scope}`, { defaultValue: scope })}</Pill>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">{t(`apiTokens.scope.${scope}Hint`, { defaultValue: scope })}</TooltipContent>
    </Tooltip>
  )
}

function StatePill({ token }: { token: ApiToken }) {
  const { t } = useTranslation()
  const pill = (
    <Pill color={TOKEN_STATE_COLOR[token.state]} dot>
      {t(`apiTokens.state.${token.state}`)}
    </Pill>
  )
  if (token.state !== "orphaned") return pill
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex cursor-help rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          {pill}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs leading-relaxed">{t("apiTokens.state.orphanedHint")}</TooltipContent>
    </Tooltip>
  )
}

function TokensCard() {
  const { t } = useTranslation()
  const q = useApiTokens()
  const [open, setOpen] = useState(false)
  // every opening a fresh form: a token shown once is gone with the closed drawer
  const [session, setSession] = useState(0)
  return (
    <>
      <SettingsCard title={t("apiTokens.title")} description={t("apiTokens.desc")} actions={<HelpLink chapter="api" section="tokens" topic={t("apiTokens.title")} />}>
        {!q.data ? (
          <SheetLoading error={q.error} onRetry={() => void q.refetch()} />
        ) : (
          <TokensBody
            data={q.data}
            onCreate={() => {
              setSession((n) => n + 1)
              setOpen(true)
            }}
          />
        )}
      </SettingsCard>
      {q.data && (
        <Sheet open={open} onOpenChange={(o) => !o && setOpen(false)}>
          <IntegrationSheetContent icon={KeyRound} title={t("apiTokens.create")} description={t("apiTokens.createDesc")} help={{ chapter: "api", section: "tokens" }}>
            <CreateTokenForm key={session} data={q.data} onClose={() => setOpen(false)} />
          </IntegrationSheetContent>
        </Sheet>
      )}
    </>
  )
}

function TokensBody({ data, onCreate }: { data: TokenList; onCreate: () => void }) {
  const { t } = useTranslation()
  const live = data.items.filter(isLive).length
  const full = live >= data.max_active
  return (
    <>
      <SheetBody>
        <section aria-labelledby="api-what" className="space-y-1.5 rounded-lg bg-muted/60 p-3 text-xs leading-relaxed text-muted-foreground">
          <p id="api-what" className="flex items-center gap-2 font-medium text-foreground">
            <Info className="size-4 shrink-0" /> {t("apiTokens.what")}
          </p>
          <ul className="list-disc space-y-0.5 pl-5">
            <li>
              {t("apiTokens.what.use")} <Term k="prometheus">Prometheus</Term>.
            </li>
            <li>{t("apiTokens.what.readOnly")}</li>
            <li>
              {t("apiTokens.what.howBefore")} <Term k="bearer">{t("apiTokens.what.bearer")}</Term> {t("apiTokens.what.howAfter")}
            </li>
            <li>{t("apiTokens.what.once")}</li>
            <li>{t("apiTokens.what.owner")}</li>
          </ul>
        </section>
        {data.items.length === 0 ? (
          <EmptyState icon={KeyRound} title={t("apiTokens.empty")} text={t("apiTokens.emptyText")} />
        ) : (
          <ul className="divide-y rounded-lg border">
            {sortTokens(data.items).map((tok) => (
              <TokenRow key={tok.id} token={tok} />
            ))}
          </ul>
        )}
      </SheetBody>
      <SheetActions>
        <span className="text-xs text-muted-foreground tabular">
          {full ? t("apiTokens.full", { max: data.max_active }) : t("apiTokens.count", { count: live, max: data.max_active })}
        </span>
        <Button onClick={onCreate} disabled={full}>
          <Plus /> {t("apiTokens.create")}
        </Button>
      </SheetActions>
    </>
  )
}

function TokenRow({ token }: { token: ApiToken }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [busy, setBusy] = useState(false)
  const ended = isEnded(token)
  const revoke = async () => {
    const ok = await confirmAction({
      title: t("apiTokens.revokeAsk", { name: token.name }),
      text: t("apiTokens.revokeText", { prefix: token.prefix }),
      confirm: t("apiTokens.revoke"),
    })
    if (!ok) return
    setBusy(true)
    try {
      const r = await withReauth(() => api.post<TokenList>(`/api/admin/api-tokens/${encodeURIComponent(token.id)}/revoke`))
      qc.setQueryData(TOKENS_KEY, r)
      toast.success(t("apiTokens.revoked", { name: token.name }))
    } catch (e) {
      toast.error(errorText(t, e))
      void qc.invalidateQueries({ queryKey: TOKENS_KEY })
    } finally {
      setBusy(false)
    }
  }
  const by = token.created_by ? token.created_by.display_name || token.created_by.username : null
  return (
    <li className={cn("flex flex-wrap items-start gap-x-3 gap-y-1.5 px-3 py-2.5", ended && "opacity-60")}>
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-medium [overflow-wrap:anywhere]">{token.name}</span>
          <span className="font-mono text-xs text-muted-foreground" title={t("apiTokens.prefixHint")}>
            {token.prefix}…
          </span>
          {token.scopes.map((s) => (
            <ScopePill key={s} scope={s} />
          ))}
          <StatePill token={token} />
        </div>
        <p className="text-[11px] leading-relaxed text-muted-foreground">
          {t("apiTokens.created")} <Ts at={token.created_at} />
          {by && <> {t("apiTokens.by", { name: by })}</>}
          {" · "}
          {token.revoked_at ? (
            <>
              {t("apiTokens.revokedAt")} <Ts at={token.revoked_at} />
            </>
          ) : token.expires_at ? (
            <>
              {token.state === "expired" ? t("apiTokens.expiredAt") : t("apiTokens.expires")} <Ts at={token.expires_at} />
            </>
          ) : (
            t("apiTokens.expiresNever")
          )}
          {token.expiry_added && !ended && (
            <>
              {" · "}
              <Explained label={t("apiTokens.expiryAdded")} text={t("apiTokens.expiryAddedHint")} />
            </>
          )}
          {" · "}
          {token.last_used_at ? (
            <>
              {t("apiTokens.lastUsed")} <Ts at={token.last_used_at} rel />
            </>
          ) : (
            t("apiTokens.neverUsed")
          )}
        </p>
      </div>
      {!ended && (
        <Button variant="ghost" size="sm" className="text-destructive" disabled={busy} onClick={() => void revoke()} aria-label={t("apiTokens.revokeName", { name: token.name })}>
          {busy ? <Loader2 className="animate-spin" /> : <Trash2 />} {t("apiTokens.revoke")}
        </Button>
      )}
    </li>
  )
}

function CreateTokenForm({ data, onClose }: { data: TokenList; onClose: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [name, setName] = useState("")
  const [scopes, setScopes] = useState<TokenScope[]>(["read"])
  const choices = expiryChoices(data.max_days)
  const [expiry, setExpiry] = useState(String(choices.includes(DEFAULT_EXPIRY) ? DEFAULT_EXPIRY : (choices.at(-1) ?? data.max_days)))
  const [busy, setBusy] = useState(false)
  // the new token: in this component's state only – gone once the drawer is closed
  const [made, setMade] = useState<TokenMade | null>(null)
  const nameOk = validName(name)
  const valid = nameOk && scopes.length > 0

  const toggle = (s: TokenScope, on: boolean) => setScopes((cur) => (on ? data.scopes.filter((x) => x === s || cur.includes(x)) : cur.filter((x) => x !== s)))

  const create = async () => {
    if (!valid) return
    setBusy(true)
    try {
      const body = { name: name.trim(), scopes, expires_days: Number(expiry) }
      const r = await withReauth(() => api.post<TokenMade>("/api/admin/api-tokens", body))
      setMade(r)
      toast.success(t("apiTokens.made", { name: r.item.name }))
      void qc.invalidateQueries({ queryKey: TOKENS_KEY })
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }

  if (made) return <MadeToken made={made} onClose={onClose} />

  return (
    <>
      <SheetBody>
        <form
          id="api-token-form"
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void create()
          }}
        >
          <Field label={t("apiTokens.name")} hint={t("apiTokens.nameHint")}>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={80}
              autoFocus
              autoComplete="off"
              placeholder={t("apiTokens.namePlaceholder")}
              aria-invalid={name !== "" && !nameOk ? true : undefined}
              disabled={busy}
            />
          </Field>
          <div>
            <p className="text-[13px] font-medium">
              {t("apiTokens.scopes")} (<Term k="scope">Scopes</Term>)
            </p>
            <div className="divide-y">
              {data.scopes.map((s) => (
                <ToggleRow
                  key={s}
                  label={t(`apiTokens.scope.${s}`, { defaultValue: s })}
                  description={t(`apiTokens.scope.${s}Hint`, { defaultValue: s })}
                  checked={scopes.includes(s)}
                  onCheckedChange={(on) => toggle(s, on)}
                  disabled={busy}
                />
              ))}
            </div>
            {scopes.length === 0 ? (
              <p className="text-xs text-destructive" role="alert">
                {t("apiTokens.scopesNone")}
              </p>
            ) : (
              <p className="text-xs text-muted-foreground">{t("apiTokens.scopesHint")}</p>
            )}
          </div>
          <Field label={t("apiTokens.expiry")} hint={t("apiTokens.expiryHint")}>
            <Select value={expiry} onValueChange={setExpiry} disabled={busy}>
              <SelectTrigger className="w-full sm:max-w-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                {choices.map((d) => (
                  <SelectItem key={d} value={String(d)}>
                    {t("apiTokens.expiry.days", { count: d })}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        </form>
      </SheetBody>
      <SheetActions>
        <Button variant="ghost" onClick={onClose} disabled={busy}>
          {t("common.cancel")}
        </Button>
        <Button type="submit" form="api-token-form" disabled={!valid || busy}>
          {busy ? <Loader2 className="animate-spin" /> : <KeyRound />} {t("apiTokens.createButton")}
        </Button>
      </SheetActions>
    </>
  )
}

function MadeToken({ made, onClose }: { made: TokenMade; onClose: () => void }) {
  const { t } = useTranslation()
  const origin = window.location.origin
  const { token, item } = made
  return (
    <>
      <SheetBody>
        <div className="space-y-2 rounded-lg border border-warning/40 bg-warning/10 p-3" role="status">
          <p className="flex items-start gap-2 text-xs font-medium">
            <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warning" /> {t("apiTokens.onceTitle")}
          </p>
          <Field label={t("apiTokens.token", { name: item.name })} hint={t("apiTokens.onceHint")}>
            <div className="flex gap-2">
              <Input value={token} readOnly onFocus={(e) => e.currentTarget.select()} className="font-mono text-xs" spellCheck={false} />
              <Button variant="outline" size="icon" onClick={() => void copyWithToast(token)} aria-label={t("apiTokens.copyToken")} title={t("apiTokens.copyToken")}>
                <Copy />
              </Button>
            </div>
          </Field>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
          {item.scopes.map((s) => (
            <ScopePill key={s} scope={s} />
          ))}
          <span>·</span>
          {item.expires_at ? (
            <span>
              {t("apiTokens.expires")} <Ts at={item.expires_at} />
            </span>
          ) : (
            <span>{t("apiTokens.expiresNever")}</span>
          )}
        </div>
        {item.scopes.includes("read") && (
          <section aria-labelledby="api-try" className="space-y-2">
            <p id="api-try" className="text-sm font-medium">
              {t("apiTokens.try")}
            </p>
            <CodeBlock lang="bash" text={curlExample(origin, token)} />
            <CodeBlock lang="powershell" text={powershellExample(origin, token)} />
          </section>
        )}
        {item.scopes.includes("metrics") && (
          <section aria-labelledby="api-prom" className="space-y-2">
            <p id="api-prom" className="text-sm font-medium">
              <Term k="prometheus">Prometheus</Term> (prometheus.yml)
            </p>
            <p className="text-xs leading-relaxed text-muted-foreground">{t("apiTokens.promHint", { file: PROMETHEUS_TOKEN_FILE })}</p>
            <CodeBlock lang="yaml" text={prometheusExample(origin)} />
          </section>
        )}
      </SheetBody>
      <SheetActions>
        <span className="text-xs text-muted-foreground">{t("apiTokens.closeHint")}</span>
        <Button onClick={onClose}>{t("apiTokens.done")}</Button>
      </SheetActions>
    </>
  )
}

// ---------------------------------------------------------------- reference

function ReferenceCard() {
  const { t } = useTranslation()
  const q = useOpenApi()
  return (
    <SettingsCard title={t("apiRef.title")} description={t("apiRef.desc")} actions={<HelpLink chapter="api" section="endpunkte" topic={t("apiRef.title")} />}>
      {!q.data ? <SheetLoading error={q.error} onRetry={() => void q.refetch()} /> : <ReferenceBody doc={q.data} />}
    </SettingsCard>
  )
}

/** Text of the spec – `code` as code, everything else as text (never HTML). */
function SpecText({ text, className }: { text: string; className?: string }) {
  return (
    <span className={className}>
      {codeSpans(text).map((p, i) =>
        p.code ? (
          <code key={i} className="rounded bg-muted px-1 font-mono text-[0.92em]">
            {p.text}
          </code>
        ) : (
          <span key={i}>{p.text}</span>
        ),
      )}
    </span>
  )
}

function ReferenceBody({ doc }: { doc: OpenApiDoc }) {
  const { t } = useTranslation()
  const groups = groupOperations(doc)
  const origin = window.location.origin
  const download = () => {
    saveBlob(new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" }), OPENAPI_FILE)
    toast.success(t("apiRef.downloaded", { name: OPENAPI_FILE }))
  }
  return (
    <>
      <SheetBody>
        <div className="space-y-1.5 rounded-lg bg-muted/60 p-3 text-xs leading-relaxed text-muted-foreground">
          <p className="flex items-center gap-2 font-medium text-foreground">
            <Lock className="size-3.5 shrink-0" /> {t("apiRef.auth")}
          </p>
          <p>
            <code className="rounded bg-background/70 px-1.5 py-0.5 font-mono text-[11px] text-foreground">Authorization: Bearer cnt_…</code>
          </p>
          <p>
            {t("apiRef.authRules")} <Term k="openapi">{t("apiRef.openapiFile")}</Term> {t("apiRef.authFile")}
          </p>
          <p>
            {t("apiRef.base")} <code className="font-mono text-[11px] text-foreground">{origin}</code>
          </p>
        </div>
        {groups.map((g) => (
          <section key={g.tag} aria-labelledby={`api-tag-${g.tag}`} className="space-y-2">
            <h3 id={`api-tag-${g.tag}`} className="text-sm font-semibold">
              {g.tag}
            </h3>
            <div className="space-y-2">
              {g.ops.map((o) => (
                <OperationItem key={`${o.method} ${o.path}`} doc={doc} o={o} />
              ))}
            </div>
          </section>
        ))}
      </SheetBody>
      <SheetActions>
        <span className="text-xs text-muted-foreground">{t("apiRef.version", { openapi: doc.openapi, version: doc.info?.version ?? "" })}</span>
        <Button variant="outline" onClick={download}>
          <Download /> {t("apiRef.download")}
        </Button>
      </SheetActions>
    </>
  )
}

function OperationItem({ doc, o }: { doc: OpenApiDoc; o: ApiOperation }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const main = mainResponse(o.op)
  const others = otherResponses(o.op, main?.status)
  const body = main?.schema ? schemaFields(doc, main.schema) : null
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="rounded-lg border">
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className="flex w-full flex-wrap items-center gap-x-2.5 gap-y-1 rounded-lg px-3 py-2.5 text-left text-sm outline-none hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          <ChevronRight className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")} />
          <span className="rounded border border-success/40 bg-success/10 px-1.5 font-mono text-[11px] font-semibold text-success">{o.method}</span>
          <span className="min-w-0 font-mono text-[12.5px] break-all">{o.path}</span>
          <span className="min-w-0 flex-1 text-xs text-muted-foreground">{o.summary}</span>
          {o.scope && <ScopePill scope={o.scope} plain />}
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="space-y-4 border-t px-3 py-3 text-xs">
          {o.description && (
            <p className="leading-relaxed whitespace-pre-line text-muted-foreground">
              <SpecText text={o.description} />
            </p>
          )}
          {o.scope && (
            <p className="text-muted-foreground">
              {t("apiRef.needs")} <ScopePill scope={o.scope} />
            </p>
          )}
          <div className="space-y-1.5">
            <p className="font-medium">{t("apiRef.params")}</p>
            {o.parameters.length === 0 ? <p className="text-muted-foreground">{t("apiRef.noParams")}</p> : <ParamTable o={o} />}
          </div>
          {main && (
            <div className="space-y-1.5">
              <p className="font-medium">
                {t("apiRef.response", { status: main.status })}
                {main.mediaType && <span className="ml-1.5 font-mono font-normal text-muted-foreground">{main.mediaType}</span>}
                {body && <span className="ml-1.5 font-mono font-normal text-primary">{body.type}</span>}
              </p>
              {main.description && main.description !== "Successful Response" && <p className="text-muted-foreground">{main.description}</p>}
              {body && body.fields.length > 0 && <FieldList fields={body.fields} />}
            </div>
          )}
          {others.length > 0 && (
            <div className="space-y-1">
              <p className="font-medium">{t("apiRef.otherResponses")}</p>
              <ul className="space-y-0.5 text-muted-foreground">
                {others.map((r) => (
                  <li key={r.code}>
                    <span className="font-mono text-foreground">{r.code}</span> {r.description && <>– {r.description}</>}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </CollapsibleContent>
    </Collapsible>
  )
}

function ParamTable({ o }: { o: ApiOperation }) {
  const { t } = useTranslation()
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full min-w-[36rem] text-left">
        <thead className="bg-muted/50 text-muted-foreground">
          <tr>
            <th className="px-2 py-1.5 font-medium">{t("apiRef.col.name")}</th>
            <th className="px-2 py-1.5 font-medium">{t("apiRef.col.in")}</th>
            <th className="px-2 py-1.5 font-medium">{t("apiRef.col.type")}</th>
            <th className="px-2 py-1.5 font-medium">{t("apiRef.col.required")}</th>
            <th className="px-2 py-1.5 font-medium">{t("apiRef.col.description")}</th>
          </tr>
        </thead>
        <tbody className="divide-y">
          {o.parameters.map((p) => {
            const def = fmtDefault(p.schema?.default)
            const text = p.description ?? p.schema?.description ?? ""
            return (
              <tr key={`${p.in}:${p.name}`} className="align-top">
                <td className="px-2 py-1.5 font-mono">{p.name}</td>
                <td className="px-2 py-1.5">{t(`apiRef.in.${p.in}`, { defaultValue: p.in })}</td>
                <td className="px-2 py-1.5 font-mono [overflow-wrap:anywhere] text-primary">{describeType(p.schema)}</td>
                <td className="px-2 py-1.5">{p.required ? t("apiRef.yes") : "–"}</td>
                <td className="px-2 py-1.5 text-muted-foreground">
                  {text && <SpecText text={text} />}
                  {def && (
                    <span className="block">
                      {t("apiRef.default")} <code className="font-mono text-foreground">{def}</code>
                    </span>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function FieldList({ fields, nested = false }: { fields: SchemaField[]; nested?: boolean }) {
  const { t } = useTranslation()
  return (
    <ul className={cn("space-y-1", nested ? "mt-1 border-l pl-3" : "rounded-md border p-2")}>
      {fields.map((f) => (
        <li key={f.name}>
          <span className="font-mono text-foreground">{f.name}</span>
          <span className="ml-1.5 font-mono [overflow-wrap:anywhere] text-primary">{f.type}</span>
          {f.required && <span className="ml-1.5 text-[10px] tracking-wide text-muted-foreground uppercase">{t("apiRef.required")}</span>}
          {f.description && (
            <span className="block text-muted-foreground">
              <SpecText text={f.description} />
            </span>
          )}
          {f.children && f.children.length > 0 && <FieldList fields={f.children} nested />}
        </li>
      ))}
    </ul>
  )
}
