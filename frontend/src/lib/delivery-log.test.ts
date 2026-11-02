import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import deOps from "@/i18n/delivery-ops.de"
import en from "@/i18n/en"
import enOps from "@/i18n/delivery-ops.en"
import { CHANNEL_TYPES, type NotifyChannel } from "@/lib/admin-api"
import {
  NTFY_TAGS_MAX,
  channelProblems,
  initialForm,
  needsSecretsAgain,
  parseTags,
  pushTokenOk,
  serverOk,
  tagsOk,
  targetSummary,
  toChannelIn,
  topicOk,
  urlOk,
} from "@/lib/channels"
import {
  DELIVERY_KINDS,
  type DryRunItem,
  OUTCOME_FILTERS,
  WINDOWS,
  channelHealth,
  dryRunBody,
  itemsText,
  logQuery,
  matchParts,
  nextBefore,
  outcomeText,
  perDay,
  whereText,
} from "@/lib/delivery-log"

// a stand-in for i18next: the key and its options, so the tests see what was asked for
const t = (key: string, opts?: Record<string, unknown>) => (opts ? `${key}${JSON.stringify(opts)}` : key)

describe("the badge of a channel", () => {
  it("nothing logged: no badge", () => {
    expect(channelHealth(undefined).tone).toBe("none")
    expect(channelHealth({ last_ok_at: null, last_failed_at: null, attempts_24h: 0, failed_24h: 0 }).tone).toBe("none")
  })
  it("the last delivery ok", () => {
    const h = channelHealth({ last_ok_at: "2026-10-31T09:00:00Z", last_failed_at: null, attempts_24h: 4, failed_24h: 0 })
    expect(h).toEqual({ tone: "ok", key: "dlog.health.ok", at: "2026-10-31T09:00:00Z" })
  })
  it("failures: a warning while some got through, red when nothing did", () => {
    expect(channelHealth({ last_ok_at: "2026-10-31T10:00:00Z", last_failed_at: "2026-10-31T09:00:00Z", attempts_24h: 5, failed_24h: 3 })).toEqual({
      tone: "warn",
      key: "dlog.health.failed",
      n: 3,
    })
    expect(channelHealth({ last_ok_at: "2026-10-20T10:00:00Z", last_failed_at: "2026-10-31T09:00:00Z", attempts_24h: 3, failed_24h: 3 }).tone).toBe("bad")
    expect(channelHealth({ last_ok_at: null, last_failed_at: "2026-10-31T09:00:00Z", attempts_24h: 1, failed_24h: 1 }).tone).toBe("bad")
  })
})

describe("texts of an attempt", () => {
  it("the outcome in a few words", () => {
    expect(outcomeText(t, { ok: true, outcome: "ok", code: null, error: null })).toBe("dlog.outcome.ok")
    expect(outcomeText(t, { ok: false, outcome: "http", code: 503, error: "http" })).toBe("HTTP 503")
    expect(outcomeText(t, { ok: false, outcome: "smtp", code: 550, error: "rejected" })).toBe("SMTP 550")
    expect(outcomeText(t, { ok: false, outcome: "smtp", code: null, error: "auth" })).toBe("dlog.outcome.smtp")
    expect(outcomeText(t, { ok: false, outcome: "blocked", code: null, error: "forbidden_target" })).toBe("dlog.outcome.blocked")
  })
  it("what was sent and where", () => {
    expect(itemsText(t, { items: [{ kind: "news", id: "1", title: "Lücke", severity: "high" }], total: 1 })).toBe("Lücke")
    expect(itemsText(t, { items: [{ kind: "news", id: "1", title: "Lücke", severity: "high" }], total: 12 })).toBe('dlog.itemsMore{"title":"Lücke","n":11}')
    expect(itemsText(t, { items: [], total: 0 })).toBe("–")
    expect(whereText(t, { kind: "weekly", channel_name: "", team_name: "SOC" })).toBe('dlog.weeklyWay{"team":"SOC"}')
    expect(whereText(t, { kind: "rule", channel_name: "Slack", team_name: null })).toBe("Slack")
  })
})

describe("the log's query", () => {
  it("only the filters that are set", () => {
    expect(logQuery({ outcome: "all", kind: "all", hours: 168 })).toBe("/api/admin/notify/log?hours=168&limit=50")
    expect(logQuery({ channel: "c1", outcome: "failed", kind: "rule", hours: 24 }, "2026-10-31T09:00:00+00:00")).toBe(
      "/api/admin/notify/log?hours=24&limit=50&channel=c1&outcome=failed&kind=rule&before=2026-10-31T09%3A00%3A00%2B00%3A00",
    )
  })
  it("the next page starts before the last delivery shown", () => {
    const d = (at: string) => ({ at }) as never
    expect(nextBefore({ more: true, deliveries: [d("b"), d("a")] })).toBe("a")
    expect(nextBefore({ more: false, deliveries: [d("b")] })).toBeUndefined()
    expect(nextBefore({ more: true, deliveries: [] })).toBeUndefined()
  })
})

describe("the dry run", () => {
  const form = { severities: ["critical" as const], sources: ["s1"], lang: "de" as const, kinds: ["vendor_vuln" as const], teams: ["t1"] }
  it("sends only what decides the matches – sources only with news", () => {
    expect(dryRunBody(form, 7)).toEqual({ severities: ["critical"], sources: [], lang: "de", kinds: ["vendor_vuln"], teams: ["t1"], days: 7 })
    expect(dryRunBody({ ...form, kinds: ["news"] }, 1).sources).toEqual(["s1"])
  })
  it("says why an item matched", () => {
    const x: DryRunItem = { kind: "news", id: "1", title: "x", severity: "high", at: "", source: "Feed", match: { kind: "news", severity: true, source: true, teams: false } }
    expect(matchParts(t, x)).toEqual(["notify.kind.news", 'dlog.dry.bySeverity{"sev":"news.sev.high"}', 'dlog.dry.bySource{"source":"Feed"}'])
    expect(matchParts(t, { ...x, match: { kind: "vendor_vuln", severity: false, source: false, teams: true } })).toEqual(["notify.kind.vendor_vuln", "dlog.dry.byTeams"])
  })
  it("messages a day on average", () => {
    expect(perDay({ messages: 31, days: 7 })).toBe(4.4)
    expect(perDay({ messages: 0, days: 1 })).toBe(0)
  })
})

const channel = (patch: Partial<NotifyChannel>): NotifyChannel => ({
  id: "c1",
  name: "ntfy",
  type: "ntfy",
  recipients: [],
  chat_id: "",
  url_set: false,
  host: "ntfy.corp.example",
  token_set: true,
  allow_http: false,
  use_proxy: false,
  hmac_set: false,
  header_name: "",
  header_set: false,
  server: "https://ntfy.corp.example",
  topic_set: true,
  tags: ["soc"],
  rules: [],
  created_at: "2026-10-31T08:00:00Z",
  last_sent_at: null,
  last_error: null,
  last_error_at: null,
  failures: 0,
  next_try_at: null,
  ...patch,
})

describe("ntfy, Gotify, Mattermost in the editor", () => {
  it("checks the server, topic, token and tags as the server does", () => {
    expect(serverOk("https://ntfy.corp.example")).toBe(true)
    expect(serverOk("https://corp.example/gotify/")).toBe(true)
    expect(serverOk("http://ntfy.corp.example")).toBe(false)
    expect(serverOk("https://ntfy.corp.example/?topic=x")).toBe(false)
    expect(topicOk("cobe-soc_1")).toBe(true)
    expect(topicOk("a/b")).toBe(false)
    expect(pushTokenOk("tk_abcdefgh12345678")).toBe(true)
    expect(pushTokenOk("tk_abc\r\nX: 1")).toBe(false)
    expect(parseTags("soc, cobe  soc;x")).toEqual(["soc", "cobe", "x"])
    expect(tagsOk(["warning", "soc"])).toBe(true)
    expect(tagsOk(["a b"])).toBe(false)
    expect(tagsOk(Array.from({ length: NTFY_TAGS_MAX + 1 }, (_, i) => `t${i}`))).toBe(false)
    expect(urlOk("mattermost", "https://chat.corp.example/hooks/abcdefghij123")).toBe(true)
    expect(urlOk("mattermost", "https://chat.corp.example/api/v4/posts")).toBe(false)
    expect(urlOk("mattermost", "http://chat.corp.example/hooks/abcdefghij123")).toBe(false)
  })
  it("a new ntfy channel needs server and topic; the token only when switched on", () => {
    const f = { ...initialForm(null), name: "ntfy SOC", server_url: "https://ntfy.corp.example" }
    expect(channelProblems("ntfy", f)).toEqual({ topic: "errors.topic_missing" })
    expect(channelProblems("ntfy", { ...f, topic: "soc" })).toEqual({})
    expect(channelProblems("ntfy", { ...f, topic: "soc", token_on: true })).toEqual({ token: "errors.push_token_missing" })
    expect(channelProblems("gotify", { ...f })).toEqual({ token: "errors.push_token_missing" })
    expect(channelProblems("gotify", { ...f, server_url: "", token: "AbCdEfGh123" })).toEqual({ server_url: "errors.url_missing" })
  })
  it("a stored channel keeps its secrets; the body says what to keep and clear", () => {
    const c = channel({})
    const f = initialForm(c)
    expect(f.token_on).toBe(true)
    expect(f.tags).toBe("soc")
    expect(channelProblems("ntfy", f, c)).toEqual({})
    const body = toChannelIn("ntfy", { ...f, token_on: false, server_url: "https://ntfy.corp.example/" }, c)
    expect(body).toMatchObject({ server_url: "https://ntfy.corp.example", topic: "", token: "", clear_token: true, tags: ["soc"], url: "" })
    expect(toChannelIn("slack", { ...f, url: "https://hooks.slack.com/x" }, null)).toMatchObject({ server_url: "", topic: "", token: "", tags: [] })
  })
  it("another server asks for topic and token again", () => {
    const c = channel({})
    expect(needsSecretsAgain({ ...initialForm(c), server_url: "https://ntfy.example.com" }, c)).toBe(true)
    expect(needsSecretsAgain({ ...initialForm(c), server_url: "https://ntfy.example.com", topic: "x", token: "tk_abcdefgh123" }, c)).toBe(false)
    expect(needsSecretsAgain(initialForm(c), c)).toBe(false)
  })
  it("the list shows the server", () => {
    expect(targetSummary(channel({}))).toBe("https://ntfy.corp.example")
    expect(targetSummary(channel({ type: "mattermost", server: "", host: "chat.corp.example" }))).toBe("chat.corp.example")
  })
})

describe("texts in both languages", () => {
  it("the new keys exist in German and English", () => {
    expect(Object.keys(deOps).sort()).toEqual(Object.keys(enOps).sort())
    for (const k of Object.keys(deOps)) {
      expect(de[k], k).toBe(deOps[k])
      expect(en[k], k).toBe(enOps[k])
    }
  })
  it("every channel type, kind, outcome filter and window has its text", () => {
    for (const lang of [de, en]) {
      for (const c of CHANNEL_TYPES) {
        for (const k of [`notify.channel.${c}`, `channels.sheetTitle.${c}`, `channels.namePlaceholder.${c}`, `channels.setup.${c}`]) expect(lang[k], k).toBeTruthy()
      }
      for (const k of DELIVERY_KINDS) expect(lang[`dlog.kind.${k}`]).toBeTruthy()
      for (const o of OUTCOME_FILTERS) expect(lang[`dlog.filter.o.${o}`]).toBeTruthy()
      for (const o of ["ok", "http", "timeout", "blocked", "smtp", "error"]) expect(lang[`dlog.outcome.${o}`]).toBeTruthy()
      for (const w of WINDOWS) expect(lang[`dlog.filter.w.${w}`]).toBeTruthy()
      for (const k of [
        "already_delivered",
        "gone",
        "resend_running",
        "not_resendable",
        "dry_run_timeout",
        "topic_invalid",
        "topic_missing",
        "push_token_invalid",
        "push_token_missing",
        "tags_invalid",
      ])
        expect(lang[`errors.${k}`], k).toBeTruthy()
    }
  })
})
