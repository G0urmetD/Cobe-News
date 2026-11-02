import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"

// ---------------------------------------------------------------- tokens (backend app/api_tokens.py)

export type TokenScope = "read" | "metrics"
export type TokenState = "active" | "revoked" | "expired" | "orphaned"

export interface ApiToken {
  id: string
  name: string
  /** "cnt_" and the first characters – to tell tokens apart, never the token itself */
  prefix: string
  scopes: TokenScope[]
  created_at: string
  created_by: { username: string; display_name: string } | null
  /** always set since 0.1.42 (at most a year) – null only on a revoked token of an older version */
  expires_at: string | null
  last_used_at: string | null
  revoked_at: string | null
  /** made with "never" before 0.1.42: the update gave it an expiry (migration time + 365 days) – "Ablauf ergänzt" */
  expiry_added: boolean
  /** orphaned: the admin who made it is no active admin any more – it does not work (until they are again) */
  state: TokenState
}

/** GET /api/admin/api-tokens (also the answer of a revoke) */
export interface TokenList {
  items: ApiToken[]
  scopes: TokenScope[]
  max_active: number
  /** 365 – there is no "never" */
  max_days: number
  default_days: number
}

/** POST /api/admin/api-tokens → 201: the token is in this answer only */
export interface TokenMade {
  token: string
  item: ApiToken
}

export const TOKENS_KEY = ["admin", "api-tokens"] as const
export const OPENAPI_KEY = ["admin", "api-tokens", "openapi"] as const

export const useApiTokens = () => useQuery({ queryKey: TOKENS_KEY, queryFn: () => api.get<TokenList>("/api/admin/api-tokens") })

/** The curated description – it changes only with a new version of the app. */
export const useOpenApi = (enabled = true) =>
  useQuery({ queryKey: OPENAPI_KEY, queryFn: () => api.get<OpenApiDoc>("/api/admin/api-tokens/openapi.json"), staleTime: Infinity, enabled })

/** The validity choices of a new token in days – the server allows up to `max_days` (365); there is no "never". */
export const EXPIRY_CHOICES: number[] = [30, 90, 180, 365]
export const DEFAULT_EXPIRY = 365

export const expiryChoices = (maxDays: number) => EXPIRY_CHOICES.filter((d) => d <= maxDays)

/** UX.md colours: green in order, amber act soon, grey information. */
export const TOKEN_STATE_COLOR: Record<TokenState, string> = {
  active: "--success",
  expired: "--warning",
  orphaned: "--warning",
  revoked: "--muted-foreground",
}

/** Revoked or expired: over for good (shown dimmed, gone from the list 30 days later). */
export const isEnded = (t: ApiToken) => t.state === "revoked" || t.state === "expired"

/** Still counts towards the limit and can be revoked: active, or orphaned (works again once its admin is one again). */
export const isLive = (t: ApiToken) => !isEnded(t)

/** The ones still in force first, each part as the server sends it (newest first). */
export const sortTokens = (items: ApiToken[]) => [...items.filter(isLive), ...items.filter(isEnded)]

/** A name the server takes: 1–80 characters of one line (trimmed). */
export function validName(name: string): boolean {
  const n = name.trim()
  return n.length >= 1 && n.length <= 80 && !/[\r\n\t]/.test(n)
}

// ---------------------------------------------------------------- examples for the new token

/** host:port of an address – with the scheme's default port spelled out (Prometheus' targets want one). */
export function hostPort(origin: string): string {
  const u = new URL(origin)
  return `${u.hostname}:${u.port || (u.protocol === "http:" ? "80" : "443")}` // an IPv6 hostname comes in brackets already
}

const base = (origin: string) => origin.replace(/\/+$/, "")

export function curlExample(origin: string, token: string): string {
  return `curl -H "Authorization: Bearer ${token}" "${base(origin)}/api/v1/news?limit=5"`
}

export function powershellExample(origin: string, token: string): string {
  return `Invoke-RestMethod -Uri "${base(origin)}/api/v1/news?limit=5" -Headers @{ Authorization = "Bearer ${token}" }`
}

export const PROMETHEUS_TOKEN_FILE = "/etc/prometheus/cobe-news.token"

/** A scrape job for prometheus.yml – the token in a file of its own, never in the configuration. */
export function prometheusExample(origin: string): string {
  const scheme = new URL(origin).protocol === "http:" ? "http" : "https"
  return [
    "scrape_configs:",
    "  - job_name: cobe-news",
    `    scheme: ${scheme}`,
    "    metrics_path: /metrics",
    "    authorization:",
    "      type: Bearer",
    `      credentials_file: ${PROMETHEUS_TOKEN_FILE}`,
    "    static_configs:",
    `      - targets: ["${hostPort(origin)}"]`,
  ].join("\n")
}

// ---------------------------------------------------------------- the API reference (OpenAPI 3.1, app/api_v1.py)

export interface Schema {
  $ref?: string
  type?: string | string[]
  format?: string
  enum?: unknown[]
  const?: unknown
  items?: Schema
  anyOf?: Schema[]
  oneOf?: Schema[]
  allOf?: Schema[]
  properties?: Record<string, Schema>
  required?: string[]
  additionalProperties?: boolean | Schema
  description?: string
  title?: string
  default?: unknown
}

export interface Parameter {
  name: string
  in: string
  required?: boolean
  description?: string
  schema?: Schema
}

export interface ResponseObj {
  description?: string
  content?: Record<string, { schema?: Schema }>
}

export interface Operation {
  tags?: string[]
  summary?: string
  description?: string
  operationId?: string
  parameters?: Parameter[]
  responses?: Record<string, ResponseObj>
  "x-scope"?: string
}

export interface OpenApiDoc {
  openapi: string
  info: { title: string; version: string; description?: string }
  servers?: { url: string }[]
  paths: Record<string, Record<string, Operation>>
  components?: { schemas?: Record<string, Schema> }
}

const SCHEMA_REF = "#/components/schemas/"

/** "#/components/schemas/Story" → "Story"; anything else (a remote reference) as it is. */
export const refName = (ref: string) => (ref.startsWith(SCHEMA_REF) ? ref.slice(SCHEMA_REF.length) : ref)

/** The schema a $ref points to (only into components.schemas – never a remote one); the schema itself without a $ref. */
export function resolveRef(doc: OpenApiDoc, s: Schema | undefined): Schema | undefined {
  let cur = s
  for (let i = 0; i < 10 && cur?.$ref; i++) {
    if (!cur.$ref.startsWith(SCHEMA_REF)) return undefined
    const name = refName(cur.$ref)
    cur = Object.hasOwn(doc.components?.schemas ?? {}, name) ? doc.components!.schemas![name] : undefined
  }
  return cur
}

const isNull = (s: Schema) => s.type === "null"

const literal = (v: unknown) => (typeof v === "string" ? `"${v}"` : String(v))

/** A schema's type as short text, TypeScript-like: `string (uuid)`, `Story[]`, `"low" | "high"`, `number | null`,
 *  `Record<string, integer>` – a $ref by its name, never resolved here (the field list shows its fields). */
export function describeType(s: Schema | undefined, depth = 0): string {
  if (!s || depth > 6) return "any"
  if (s.$ref) return refName(s.$ref)
  const union = s.anyOf ?? s.oneOf
  if (union?.length) return [...new Set(union.map((x) => describeType(x, depth + 1)))].join(" | ")
  if (s.allOf?.length) return s.allOf.map((x) => describeType(x, depth + 1)).join(" & ")
  if (s.enum?.length) return s.enum.map(literal).join(" | ")
  if (s.const !== undefined) return literal(s.const)
  if (Array.isArray(s.type)) return s.type.map((t) => describeType({ ...s, type: t }, depth + 1)).join(" | ")
  switch (s.type) {
    case "array": {
      const inner = describeType(s.items, depth + 1)
      return inner.includes(" ") ? `(${inner})[]` : `${inner}[]`
    }
    case "object":
      if (s.additionalProperties && typeof s.additionalProperties === "object") return `Record<string, ${describeType(s.additionalProperties, depth + 1)}>`
      return s.title && !s.properties ? s.title : "object"
    case undefined:
      return "any"
    default:
      return s.format ? `${s.type} (${s.format})` : s.type
  }
}

/** The object schema behind a field, if any: a $ref, an array of one, or one of them "or null" – for one level of fields. */
export function objectOf(doc: OpenApiDoc, s: Schema | undefined): Schema | undefined {
  if (!s) return undefined
  const union = (s.anyOf ?? s.oneOf)?.filter((x) => !isNull(x))
  if (union?.length === 1) return objectOf(doc, union[0])
  if (s.type === "array") return objectOf(doc, s.items)
  if (s.allOf?.length === 1) return objectOf(doc, s.allOf[0])
  const r = resolveRef(doc, s)
  return r?.properties ? r : undefined
}

export interface SchemaField {
  name: string
  type: string
  required: boolean
  description?: string
  /** the fields of an object (or of the items of an array of objects) – one level deep */
  children?: SchemaField[]
}

function fieldsOfObject(doc: OpenApiDoc, s: Schema, nest: number): SchemaField[] {
  const req = new Set(s.required ?? [])
  return Object.entries(s.properties ?? {}).map(([name, p]) => {
    const inner = nest > 0 ? objectOf(doc, p) : undefined
    return {
      name,
      type: describeType(p),
      required: req.has(name),
      description: p.description ?? resolveRef(doc, p)?.description,
      ...(inner ? { children: fieldsOfObject(doc, inner, nest - 1) } : {}),
    }
  })
}

/** A response schema for the reference: its type and its fields (the items' fields for a list), nested objects one level deep. */
export function schemaFields(doc: OpenApiDoc, s: Schema | undefined, nest = 1): { type: string; fields: SchemaField[] } {
  const obj = objectOf(doc, s)
  return { type: describeType(s), fields: obj ? fieldsOfObject(doc, obj, nest) : [] }
}

/** The success answer of an operation: 200 (or the first 2xx), JSON before anything else. */
export function mainResponse(op: Operation): { status: string; mediaType: string | null; schema?: Schema; description?: string } | null {
  const codes = Object.keys(op.responses ?? {})
  const status = codes.includes("200") ? "200" : codes.find((c) => /^2\d\d$/.test(c))
  if (!status) return null
  const r = op.responses![status]
  const types = Object.keys(r.content ?? {})
  const mediaType = types.includes("application/json") ? "application/json" : (types[0] ?? null)
  return { status, mediaType, schema: mediaType ? r.content![mediaType].schema : undefined, description: r.description }
}

/** The other answers (errors) of an operation, by status code. */
export const otherResponses = (op: Operation, main: string | undefined) =>
  Object.entries(op.responses ?? {})
    .filter(([code]) => code !== main)
    .map(([code, r]) => ({ code, description: r.description ?? "" }))
    .sort((a, b) => a.code.localeCompare(b.code))

export interface ApiOperation {
  method: string
  path: string
  tag: string
  summary: string
  description: string
  scope: string | null
  parameters: Parameter[]
  op: Operation
}

const METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"]
/** The order of the parts on the page; any other tag after them. */
export const TAG_ORDER = ["News", "Vendor News", "Metrics"]

/** The operations by their (first) tag, in the order of TAG_ORDER, then as the document lists them. */
export function groupOperations(doc: OpenApiDoc): { tag: string; ops: ApiOperation[] }[] {
  const groups = new Map<string, ApiOperation[]>()
  for (const [path, item] of Object.entries(doc.paths ?? {})) {
    for (const method of METHODS) {
      const op = item?.[method]
      if (!op || typeof op !== "object") continue
      const tag = op.tags?.[0] ?? "API"
      const entry: ApiOperation = {
        method: method.toUpperCase(),
        path,
        tag,
        summary: op.summary ?? "",
        description: op.description ?? "",
        scope: typeof op["x-scope"] === "string" ? op["x-scope"] : null,
        parameters: Array.isArray(op.parameters) ? op.parameters : [],
        op,
      }
      groups.set(tag, [...(groups.get(tag) ?? []), entry])
    }
  }
  const rank = (t: string) => (TAG_ORDER.includes(t) ? TAG_ORDER.indexOf(t) : TAG_ORDER.length)
  return [...groups.entries()].sort((a, b) => rank(a[0]) - rank(b[0])).map(([tag, ops]) => ({ tag, ops }))
}

/** A default worth showing ("50", "false") – none for an empty list or text. */
export function fmtDefault(v: unknown): string | null {
  if (v === undefined || v === null || v === "") return null
  if (Array.isArray(v)) return v.length ? v.map(String).join(", ") : null
  return typeof v === "object" ? JSON.stringify(v) : String(v)
}

/** Text with `code` in backticks (the spec's descriptions) as parts – rendered as text, never as HTML. */
export function codeSpans(text: string): { code: boolean; text: string }[] {
  return text
    .split("`")
    .map((part, i) => ({ code: i % 2 === 1, text: part }))
    .filter((p) => p.text !== "")
}

export const OPENAPI_FILE = "cobe-news-openapi.json"
