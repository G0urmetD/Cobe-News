import { describe, expect, it } from "vitest"
import type { NotifyChannel } from "@/lib/admin-api"
import {
  badRecipients,
  channelProblems,
  chatIdOk,
  headerNameOk,
  initialForm,
  mailServerMissing,
  needsSecretsAgain,
  parseRecipients,
  randomSecret,
  smtpReady,
  smtpTarget,
  targetSummary,
  telegramTokenOk,
  toChannelIn,
  upcomingTry,
  urlOk,
} from "@/lib/channels"

const channel = (patch: Partial<NotifyChannel> = {}): NotifyChannel => ({
  id: "c1",
  name: "n8n SOC",
  type: "webhook",
  recipients: [],
  chat_id: "",
  url_set: true,
  host: "n8n.corp.example",
  token_set: false,
  allow_http: false,
  use_proxy: false,
  hmac_set: true,
  header_name: "Authorization",
  header_set: true,
  rules: [],
  created_at: "2026-10-28T08:00:00Z",
  last_sent_at: null,
  last_error: null,
  last_error_at: null,
  failures: 0,
  next_try_at: null,
  ...patch,
})

// a bot token's shape, put together here (a literal one would look like a leaked secret to scanners)
const SECRET_PART = "x".repeat(35)
const TOKEN = `123456789:${SECRET_PART}`

describe("recipients", () => {
  it("splits lines, commas, semicolons and blanks", () => {
    expect(parseRecipients(" soc@corp.example\nit@corp.example, a@b.example; \n\n")).toEqual(["soc@corp.example", "it@corp.example", "a@b.example"])
  })
  it("names the addresses that are none", () => {
    expect(badRecipients(["soc@corp.example", "soc", "a@b", "x@y.example"])).toEqual(["soc", "a@b"])
  })
})

describe("URLs per type", () => {
  it("teams and slack: https only", () => {
    expect(urlOk("teams", "https://prod.example.com/workflows/abc")).toBe(true)
    expect(urlOk("slack", "https://hooks.slack.com/services/T/B/x")).toBe(true)
    expect(urlOk("slack", "http://hooks.slack.com/services/T/B/x")).toBe(false)
    expect(urlOk("teams", "https://a.example.com/with space")).toBe(false)
  })
  it("discord: only its own webhook path", () => {
    expect(urlOk("discord", "https://discord.com/api/webhooks/1/abc")).toBe(true)
    expect(urlOk("discord", "https://discordapp.com/api/webhooks/1/abc")).toBe(true)
    expect(urlOk("discord", "https://discord.com/channels/1")).toBe(false)
    expect(urlOk("discord", "https://evil.example.com/api/webhooks/1/abc")).toBe(false)
    expect(urlOk("discord", "https://discord.com.evil.example/api/webhooks/1")).toBe(false)
  })
  it("webhook: http only when allowed", () => {
    expect(urlOk("webhook", "https://n8n.corp.example/webhook/x")).toBe(true)
    expect(urlOk("webhook", "http://n8n.corp.example/webhook/x")).toBe(false)
    expect(urlOk("webhook", "http://n8n.corp.example/webhook/x", true)).toBe(true)
    expect(urlOk("webhook", "ftp://n8n.corp.example/x", true)).toBe(false)
  })
  it("email and telegram have no URL", () => {
    expect(urlOk("email", "https://a.example.com")).toBe(false)
    expect(urlOk("telegram", "https://a.example.com")).toBe(false)
  })
})

describe("telegram", () => {
  it("bot token", () => {
    expect(telegramTokenOk(TOKEN)).toBe(true)
    expect(telegramTokenOk(` ${TOKEN} `)).toBe(true)
    expect(telegramTokenOk(`1234:${SECRET_PART}`)).toBe(false) // id too short
    expect(telegramTokenOk("123456789:short")).toBe(false)
    expect(telegramTokenOk(`123456789${SECRET_PART}`)).toBe(false)
  })
  it("chat id: numbers (groups -, channels -100) or @name", () => {
    for (const ok of ["123456", "-4012345678", "-1001234567890", "@soc_alerts"]) expect(chatIdOk(ok)).toBe(true)
    for (const bad of ["", "abc", "@abc", "@1channel", "--1", "12 34", `-${"1".repeat(21)}`]) expect(chatIdOk(bad)).toBe(false)
  })
})

describe("header and secret", () => {
  it("header name follows the server's rule", () => {
    expect(headerNameOk("Authorization")).toBe(true)
    expect(headerNameOk("X-Api-Key")).toBe(true)
    expect(headerNameOk("x-api-key2")).toBe(true)
    expect(headerNameOk("A".repeat(64))).toBe(true)
    expect(headerNameOk("A".repeat(65))).toBe(false)
    expect(headerNameOk("X Api")).toBe(false)
    expect(headerNameOk("X:Api")).toBe(false)
    expect(headerNameOk("")).toBe(false)
    // RFC token characters the server refuses
    for (const n of ["X_Api", "X.Api", "X!Api", "X~Api", "-X-Api"]) expect(headerNameOk(n)).toBe(false)
    // reserved names and the own prefix, in any case
    for (const n of ["Host", "content-type", "Cookie", "TE", "X-Cobe-Signature", "x-cobe-delivery"]) expect(headerNameOk(n)).toBe(false)
    expect(headerNameOk("X-Cobe")).toBe(true)
  })
  it("random secret: 32 bytes base64url, every time another", () => {
    const a = randomSecret()
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(randomSecret()).not.toBe(a)
    expect(randomSecret(16)).toMatch(/^[A-Za-z0-9_-]{22}$/)
  })
})

describe("target summary", () => {
  it("per type", () => {
    expect(targetSummary(channel({ type: "email", recipients: ["a@corp.example", "b@corp.example"] }))).toBe("a@corp.example, b@corp.example")
    expect(targetSummary(channel({ type: "telegram", chat_id: "-100123" }))).toBe("Chat -100123")
    expect(targetSummary(channel({ type: "slack", host: "hooks.slack.com" }))).toBe("hooks.slack.com")
    expect(targetSummary(channel({ type: "discord", host: null }))).toBe("–")
  })
})

describe("channel form", () => {
  it("a new channel needs its target", () => {
    const f = { ...initialForm(), name: "SOC" }
    expect(channelProblems("email", f)).toEqual({ recipients: "errors.recipients_missing" })
    expect(channelProblems("slack", f)).toEqual({ url: "errors.url_missing" })
    expect(channelProblems("telegram", f)).toEqual({ bot_token: "errors.token_missing", chat_id: "errors.chat_id_invalid" })
    expect(channelProblems("telegram", { ...f, bot_token: TOKEN, chat_id: "-100123" })).toEqual({})
    expect(channelProblems("discord", { ...f, url: "https://discord.com/api/webhooks/1/x" })).toEqual({})
    expect(channelProblems("email", { ...f, name: "x", recipients: "a@corp.example" })).toEqual({ name: "channels.check.name" })
  })
  it("at most 20 recipients, all valid", () => {
    const f = { ...initialForm(), name: "SOC" }
    expect(channelProblems("email", { ...f, recipients: "a@corp.example\nnope" }).recipients).toBe("channels.check.recipients")
    const many = Array.from({ length: 21 }, (_, n) => `u${n}@corp.example`).join("\n")
    expect(channelProblems("email", { ...f, recipients: many }).recipients).toBe("channels.check.tooManyRecipients")
  })
  it("stored secrets are kept when left empty", () => {
    const c = channel()
    expect(channelProblems("webhook", initialForm(c), c)).toEqual({})
    const body = toChannelIn("webhook", initialForm(c), c)
    expect(body).toMatchObject({ url: "", hmac_secret: "", clear_hmac: false, header_name: "Authorization", header_value: "", clear_header: false })
  })
  it("switching signature or header off clears the stored one", () => {
    const c = channel()
    const body = toChannelIn("webhook", { ...initialForm(c), hmac_on: false, header_on: false }, c)
    expect(body).toMatchObject({ clear_hmac: true, hmac_secret: "", clear_header: true, header_name: "", header_value: "" })
  })
  it("a new signature or header needs its secret", () => {
    const f = { ...initialForm(), name: "Hook", url: "https://n8n.corp.example/x", hmac_on: true, header_on: true }
    expect(channelProblems("webhook", f)).toEqual({
      hmac_secret: "channels.check.hmacMissing",
      header_name: "errors.header_name_invalid",
      header_value: "channels.check.headerValueMissing",
    })
    expect(channelProblems("webhook", { ...f, hmac_secret: "short", header_name: "X-Key", header_value: "v" })).toEqual({ hmac_secret: "errors.hmac_too_short" })
    expect(channelProblems("webhook", { ...f, hmac_secret: randomSecret(), header_name: "X-Key", header_value: "v" })).toEqual({})
  })
  it("fields of other types stay out of the body", () => {
    const f = {
      ...initialForm(),
      name: " Mail ",
      recipients: "a@corp.example",
      url: "https://x.example.com",
      bot_token: TOKEN,
      chat_id: "1",
      hmac_on: true,
      hmac_secret: "x",
      server_url: "https://ntfy.corp.example",
      topic: "t",
      token: "tk_abcdefgh",
      tags: "soc",
    }
    expect(toChannelIn("email", f)).toEqual({
      name: "Mail",
      type: "email",
      recipients: ["a@corp.example"],
      url: "",
      bot_token: "",
      chat_id: "",
      allow_http: false,
      use_proxy: false,
      hmac_secret: "",
      clear_hmac: false,
      header_name: "",
      header_value: "",
      clear_header: false,
      server_url: "",
      topic: "",
      token: "",
      clear_token: false,
      tags: [],
    })
  })
  it("a new host needs the stored secrets typed again", () => {
    const c = channel()
    const f = initialForm(c)
    expect(needsSecretsAgain(f, c)).toBe(false)
    expect(needsSecretsAgain({ ...f, url: "https://n8n.corp.example/other" }, c)).toBe(false)
    expect(needsSecretsAgain({ ...f, url: "https://other.corp.example/x" }, c)).toBe(true)
    expect(needsSecretsAgain({ ...f, url: "https://other.corp.example/x", hmac_secret: randomSecret(), header_value: "v" }, c)).toBe(false)
    expect(needsSecretsAgain({ ...f, url: "https://other.corp.example/x", hmac_on: false, header_on: false }, c)).toBe(false)
  })
})

describe("mail server and channel state", () => {
  const smtp = { host: "mail.corp.example", port: 587, from_addr: "news@corp.example" }
  it("is ready with a server and a sender", () => {
    expect(smtpReady(smtp)).toBe(true)
    expect(smtpReady({ ...smtp, host: " " })).toBe(false)
    expect(smtpReady({ ...smtp, from_addr: "" })).toBe(false)
    expect(smtpReady(undefined)).toBe(false)
  })
  it("names the server with its port, IPv6 in brackets", () => {
    expect(smtpTarget(smtp)).toBe("mail.corp.example:587")
    expect(smtpTarget({ host: "2001:db8::25", port: 25 })).toBe("[2001:db8::25]:25")
    expect(smtpTarget({ host: "[2001:db8::25]", port: 25 })).toBe("[2001:db8::25]:25")
    expect(smtpTarget({ host: "", port: 587 })).toBe("")
  })
  it("says the mail server is missing only for e-mail channels, once it is known", () => {
    expect(mailServerMissing({ type: "email" }, { host: "", from_addr: "" })).toBe(true)
    expect(mailServerMissing({ type: "email" }, smtp)).toBe(false)
    expect(mailServerMissing({ type: "slack" }, { host: "", from_addr: "" })).toBe(false)
    expect(mailServerMissing({ type: "email" }, undefined)).toBe(false) // still loading: no false alarm
  })
  it("shows a next try only while it lies ahead", () => {
    const now = Date.parse("2026-10-29T12:00:00Z")
    expect(upcomingTry({ next_try_at: "2026-10-29T12:05:00Z" }, now)).toBe("2026-10-29T12:05:00Z")
    expect(upcomingTry({ next_try_at: "2026-10-29T11:55:00Z" }, now)).toBeNull()
    expect(upcomingTry({ next_try_at: null }, now)).toBeNull()
  })
})
