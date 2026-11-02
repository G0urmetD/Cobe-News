import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { TERMS } from "@/components/cobe/glossary"
import {
  type ApiToken,
  type OpenApiDoc,
  codeSpans,
  curlExample,
  describeType,
  expiryChoices,
  fmtDefault,
  groupOperations,
  hostPort,
  isEnded,
  mainResponse,
  otherResponses,
  powershellExample,
  prometheusExample,
  resolveRef,
  schemaFields,
  sortTokens,
  TOKEN_STATE_COLOR,
  validName,
} from "@/lib/api-tokens"

// A trimmed copy of what app/api_v1.openapi() makes (FastAPI, Pydantic 2: anyOf with null, $refs into components)
const DOC: OpenApiDoc = {
  openapi: "3.1.0",
  info: { title: "Cobe News API", version: "0.1.0" },
  paths: {
    "/metrics": {
      get: {
        tags: ["Metrics"],
        summary: "Prometheus metrics",
        responses: { "200": { description: "Prometheus text format 0.0.4", content: { "text/plain": { schema: { type: "string" } } } }, "401": { description: "No token" } },
        "x-scope": "metrics",
      },
    },
    "/api/v1/vendor/findings": {
      get: {
        tags: ["Vendor News"],
        summary: "Findings across all followed products",
        parameters: [
          {
            name: "status",
            in: "query",
            required: false,
            schema: { type: "array", items: { enum: ["affected", "possible"], type: "string" }, default: [] },
          },
          { name: "exploited", in: "query", required: false, schema: { anyOf: [{ type: "boolean" }, { type: "null" }] } },
          { name: "limit", in: "query", required: false, schema: { type: "integer", default: 50 } },
        ],
        responses: { "200": { description: "Successful Response", content: { "application/json": { schema: { $ref: "#/components/schemas/FindingPage" } } } } },
        "x-scope": "read",
      },
    },
    "/api/v1/news": {
      get: {
        tags: ["News"],
        summary: "Stories, newest first",
        responses: {
          "200": { description: "Successful Response", content: { "application/json": { schema: { $ref: "#/components/schemas/StoryPage" } } } },
          "429": { description: "Too many requests" },
          "401": { description: "No token" },
        },
        "x-scope": "read",
      },
    },
    "/api/v1/news/sources": {
      get: {
        tags: ["News"],
        summary: "The switched-on news sources",
        responses: { "200": { content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/SourceRef" } } } } } },
        "x-scope": "read",
      },
    },
  },
  components: {
    schemas: {
      SourceRef: { type: "object", properties: { key: { type: "string", description: "Stable key" }, name: { type: "string" } }, required: ["key", "name"] },
      Story: {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          source: { $ref: "#/components/schemas/SourceRef" },
          severity: { type: "string", enum: ["critical", "high"] },
          cves: { type: "array", items: { type: "string" } },
        },
        required: ["id", "source"],
      },
      StoryPage: {
        type: "object",
        properties: {
          items: { type: "array", items: { $ref: "#/components/schemas/Story" } },
          next: { anyOf: [{ type: "string" }, { type: "null" }], description: "Pass as `before`" },
        },
        required: ["items", "next"],
      },
      Kev: { type: "object", properties: { added: { anyOf: [{ type: "string" }, { type: "null" }] } } },
      Finding: {
        type: "object",
        properties: {
          kev: { anyOf: [{ $ref: "#/components/schemas/Kev" }, { type: "null" }] },
          by_status: { type: "object", additionalProperties: { type: "integer" } },
        },
      },
      FindingPage: { type: "object", properties: { items: { type: "array", items: { $ref: "#/components/schemas/Finding" } }, total: { type: "integer" } }, required: ["items"] },
    },
  },
}

describe("describeType", () => {
  it("writes a schema's type as short text", () => {
    expect(describeType({ type: "string", format: "uuid" })).toBe("string (uuid)")
    expect(describeType({ $ref: "#/components/schemas/Story" })).toBe("Story")
    expect(describeType({ type: "array", items: { $ref: "#/components/schemas/Story" } })).toBe("Story[]")
    expect(describeType({ type: "array", items: { type: "string", enum: ["a", "b"] } })).toBe('("a" | "b")[]')
    expect(describeType({ anyOf: [{ type: "number" }, { type: "null" }] })).toBe("number | null")
    expect(describeType({ anyOf: [{ $ref: "#/components/schemas/Kev" }, { type: "null" }] })).toBe("Kev | null")
    expect(describeType({ type: "object", additionalProperties: { type: "integer" } })).toBe("Record<string, integer>")
    expect(describeType({ type: ["string", "null"] })).toBe("string | null")
    expect(describeType({ enum: [1, 7] })).toBe("1 | 7")
    expect(describeType(undefined)).toBe("any")
    expect(describeType({})).toBe("any")
  })
})

describe("resolveRef", () => {
  it("follows a $ref into components.schemas only", () => {
    expect(resolveRef(DOC, { $ref: "#/components/schemas/SourceRef" })?.required).toEqual(["key", "name"])
    expect(resolveRef(DOC, { $ref: "#/components/schemas/Nope" })).toBeUndefined()
    expect(resolveRef(DOC, { $ref: "https://evil.example/schema.json" })).toBeUndefined()
    expect(resolveRef(DOC, { $ref: "#/components/schemas/__proto__" })).toBeUndefined()
    expect(resolveRef(DOC, { type: "string" })).toEqual({ type: "string" })
  })
})

describe("schemaFields", () => {
  it("lists the fields of a response, nested objects one level deep", () => {
    const r = schemaFields(DOC, { $ref: "#/components/schemas/StoryPage" })
    expect(r.type).toBe("StoryPage")
    expect(r.fields.map((f) => [f.name, f.type, f.required])).toEqual([
      ["items", "Story[]", true],
      ["next", "string | null", true],
    ])
    expect(r.fields[1].description).toBe("Pass as `before`")
    const items = r.fields[0].children!
    expect(items.map((f) => f.name)).toEqual(["id", "source", "severity", "cves"])
    expect(items[2].type).toBe('"critical" | "high"')
    expect(items[1].children).toBeUndefined() // one level is enough
  })
  it("shows the item fields of a list and the fields behind 'or null'", () => {
    const list = schemaFields(DOC, { type: "array", items: { $ref: "#/components/schemas/SourceRef" } })
    expect(list.type).toBe("SourceRef[]")
    expect(list.fields.map((f) => f.name)).toEqual(["key", "name"])
    const page = schemaFields(DOC, { $ref: "#/components/schemas/FindingPage" })
    const kev = page.fields[0].children!.find((f) => f.name === "kev")!
    expect(kev.type).toBe("Kev | null")
    expect(page.fields[0].children!.find((f) => f.name === "by_status")!.type).toBe("Record<string, integer>")
  })
  it("has no fields for plain text", () => {
    expect(schemaFields(DOC, { type: "string" })).toEqual({ type: "string", fields: [] })
  })
})

describe("groupOperations", () => {
  it("groups by tag in the page's order: News, Vendor News, Metrics", () => {
    const g = groupOperations(DOC)
    expect(g.map((x) => x.tag)).toEqual(["News", "Vendor News", "Metrics"])
    expect(g[0].ops.map((o) => `${o.method} ${o.path}`)).toEqual(["GET /api/v1/news", "GET /api/v1/news/sources"])
    expect(g[2].ops[0].scope).toBe("metrics")
    expect(g[1].ops[0].parameters.map((p) => describeType(p.schema))).toEqual(['("affected" | "possible")[]', "boolean | null", "integer"])
  })
  it("finds the success answer and the others", () => {
    const news = DOC.paths["/api/v1/news"].get
    expect(mainResponse(news)).toMatchObject({ status: "200", mediaType: "application/json" })
    expect(otherResponses(news, "200").map((r) => r.code)).toEqual(["401", "429"])
    expect(mainResponse(DOC.paths["/metrics"].get)).toMatchObject({ mediaType: "text/plain", schema: { type: "string" } })
    expect(mainResponse({ responses: { "404": {} } })).toBeNull()
  })
  it("shows defaults worth showing and code in backticks as text parts", () => {
    expect(fmtDefault(50)).toBe("50")
    expect(fmtDefault(false)).toBe("false")
    expect(fmtDefault([])).toBeNull()
    expect(fmtDefault("")).toBeNull()
    expect(codeSpans("Pass as `before` for the next page")).toEqual([
      { code: false, text: "Pass as " },
      { code: true, text: "before" },
      { code: false, text: " for the next page" },
    ])
    expect(codeSpans("<b>no html</b>")).toEqual([{ code: false, text: "<b>no html</b>" }])
  })
})

describe("examples for a new token", () => {
  const token = "cnt_" + "A".repeat(43)
  it("builds curl and PowerShell from the page's own address", () => {
    expect(curlExample("https://news.example.com", token)).toBe(`curl -H "Authorization: Bearer ${token}" "https://news.example.com/api/v1/news?limit=5"`)
    expect(powershellExample("https://news.example.com:8443/", token)).toBe(
      `Invoke-RestMethod -Uri "https://news.example.com:8443/api/v1/news?limit=5" -Headers @{ Authorization = "Bearer ${token}" }`,
    )
  })
  it("gives Prometheus a target with a port and the token as a file, never inline", () => {
    expect(hostPort("https://news.example.com")).toBe("news.example.com:443")
    expect(hostPort("http://10.0.0.5")).toBe("10.0.0.5:80")
    expect(hostPort("https://[::1]:8443")).toBe("[::1]:8443")
    const y = prometheusExample("https://news.example.com:8443")
    expect(y).toContain("metrics_path: /metrics")
    expect(y).toContain("scheme: https")
    expect(y).toContain("credentials_file: /etc/prometheus/cobe-news.token")
    expect(y).toContain('targets: ["news.example.com:8443"]')
    expect(y).not.toContain("cnt_")
  })
})

describe("tokens", () => {
  const tok = (state: ApiToken["state"], id: string): ApiToken => ({
    id,
    name: id,
    prefix: "cnt_AbC123",
    scopes: ["read"],
    created_at: "",
    created_by: null,
    expires_at: null,
    last_used_at: null,
    revoked_at: null,
    expiry_added: false,
    state,
  })
  it("puts the ones in force first and dims the ended ones", () => {
    const sorted = sortTokens([tok("revoked", "a"), tok("active", "b"), tok("expired", "c"), tok("orphaned", "d")])
    expect(sorted.map((x) => x.id)).toEqual(["b", "d", "a", "c"])
    expect(isEnded(tok("orphaned", "x"))).toBe(false)
    expect(TOKEN_STATE_COLOR.active).toBe("--success")
    expect(TOKEN_STATE_COLOR.revoked).toBe("--muted-foreground")
  })
  it("checks the name like the server and offers only allowed validities", () => {
    expect(validName("Prometheus")).toBe(true)
    expect(validName("   ")).toBe(false)
    expect(validName("x".repeat(81))).toBe(false)
    expect(validName("a\tb")).toBe(false)
    expect(expiryChoices(365)).toEqual([30, 90, 180, 365]) // no "never" (0.1.42)
    expect(expiryChoices(730)).toEqual([30, 90, 180, 365])
    expect(expiryChoices(100)).toEqual([30, 90])
  })
})

describe("i18n", () => {
  const ours = (m: Record<string, string>) => Object.keys(m).filter((k) => /^(apiTokens\.|apiRef\.|settings\.nav\.api$|glossary\.(bearer|scope|prometheus|openapi))/.test(k))
  it("has every API text in German and English", () => {
    expect(ours(de).sort()).toEqual(ours(en).sort())
    expect(ours(de).length).toBeGreaterThan(50)
    for (const k of ours(de)) expect(de[k] && en[k], k).toBeTruthy()
  })
  it("explains the terms the handbook links (term:bearer …)", () => {
    for (const k of ["bearer", "scope", "prometheus", "openapi"] as const) {
      expect(TERMS).toContain(k)
      expect(de[`glossary.${k}Text`] && en[`glossary.${k}Text`]).toBeTruthy()
    }
  })
  it("has a text for every refusal of a token", () => {
    for (const code of [
      "too_many_tokens",
      "bearer_with_cookie",
      "token_read_only",
      "token_not_allowed",
      "invalid_token",
      "insufficient_scope",
      "restore_test_busy",
      "restore_test_not_configured",
    ]) {
      expect(de[`errors.${code}`], code).toBeTruthy()
      expect(en[`errors.${code}`], code).toBeTruthy()
    }
  })
})
