---
title: API & metrics
summary: Make API tokens, read the news and Vendor News by script (curl, PowerShell) and watch the state of the installation with Prometheus.
audience: admin
---

## Overview {#ueberblick}

Cobe News has a small, documented **read-only API** – for scripts, a SIEM, a ticket system or
[Prometheus](term:prometheus). Access is an **API token** that an admin makes. The page for it:
*Settings → API & metrics* ([open directly](/settings/api)).

| What | Address | Token needs |
|---|---|---|
| News, sources, followed products, findings | `/api/v1/…` | scope `read` |
| State of the installation for Prometheus | `/metrics` | scope `metrics` |

- **Read** only: a token cannot change, create or delete anything.
- Only these two areas: a token never reaches the endpoints of the user interface or the admin pages.
- Nothing personal: no read marks, no notes, no user names.
- The exact description of every field is in the **"Reference"** tab as an [OpenAPI](term:openapi) file to download.
  There is no public `/docs` or `/openapi.json` page.

## API tokens {#tokens}

A token looks like this: `cnt_` and 43 more characters (256 random bits). The fixed prefix `cnt_` helps secret
scanners find a token in code or tickets – e.g. a custom pattern in GitHub:

```text
cnt_[A-Za-z0-9_-]{43}
```

Cobe News does **not** store the token itself, only a keyed hash of it ([HMAC](term:hmac) with the
[master key](term:masterkey)). Whoever reads the database or a backup cannot make a token from it.

### Making a token {#token-anlegen}

1. Open *Settings → API & metrics*, tab **"Tokens"**.
2. Enter a **name** that says what the token is for (e.g. "Prometheus" or "SIEM export").
3. Choose the **[scopes](term:scope)** (see [Scopes](#scopes)).
4. Choose the **expiry**: 30, 90, 180 or 365 days. Every token expires after **a year at most** – there is no "never"
   since 0.1.42 (see [Revoking and expiry](#token-widerrufen)).
5. Create it and [confirm your identity again](/docs/anmeldung#erneut-bestaetigen) with password and TOTP (Entra accounts: at Microsoft).
6. **Copy the token at once** and store it safely (password manager, the script's secret store).

> [!WARNING]
> The token is shown **only once**. After that nobody can show it again – no admin either. If it is lost: make a new
> one and revoke the old one.

The list shows for each token:

| Column | Content |
|---|---|
| Name | the name given when it was made |
| Token | only the first characters, e.g. `cnt_AbC123` – to tell tokens apart |
| Scopes | `read`, `metrics` or both |
| Created | by whom and when |
| Expires | date; "Expiry added" on a token made without expiry before 0.1.42 |
| Last used | updated at most every 5 minutes |
| State | active, expired, revoked or orphaned |

There are at most **50 active** tokens.

### Scopes {#scopes}

| Scope | Allows |
|---|---|
| `read` | everything under `/api/v1/` – news, sources, followed products of Vendor News and their findings |
| `metrics` | `/metrics` only |

There is no scope for writing and no admin scope.

> [!TIP]
> For Prometheus, make a **separate token with `metrics` only**. If it falls into the wrong hands, it shows only
> operating figures, no news and no findings.

### Revoking and expiry {#token-widerrufen}

- **Revoke:** in the list, choose "Revoke" at the token and confirm again. The token stops working **at once**.
- **Expiry:** an expired token no longer works. It cannot be extended – make a new one in time, swap it in the script
  and revoke the old one. A token lives 365 days at most; through the API (`POST /api/admin/api-tokens`)
  `expires_days` 1 to 365 is allowed, 365 when left out – `null` ("never") is refused.
- **Tokens without expiry from older versions:** the update to 0.1.42 gave every token still valid that was made with
  "never" an expiry date: **time of the update + 365 days**. The list shows "Expiry added" at it. Make a new token
  before that date and swap it – otherwise the script (or Prometheus, see [Metrics](#metriken)) gets 401 from then on.
- Revoked and expired tokens stay in the list for **30 days**, then they disappear.

**Orphaned:** a token only works while the admin who made it is an **active admin**. If their account is switched off,
deleted or made a reader, the token is "orphaned" and every request gets 401.

> [!NOTE]
> When an admin leaves the team, another admin makes a new token for each of theirs, puts it into the script and
> revokes the old one. If an account becomes admin again later, its orphaned tokens work again – so better revoke old
> tokens.

## Usage {#nutzung}

The token goes along with every request in the header ([Bearer](term:bearer) scheme):

```text
Authorization: Bearer cnt_…
```

The rules:

- Only `GET`, only `/api/v1/…` and `/metrics`.
- **Never** together with a browser sign-in (session cookie) – that gets 400 `bearer_with_cookie`.
- No CSRF token needed.
- **Never put the token into a URL.** Cobe News only reads it from the header.
- The address is the same as in the browser, e.g. `https://news.corp.example:8095`.

### curl {#curl}

Read the token into an environment variable – it appears neither on the screen nor in the shell history:

```bash
read -rs COBE_TOKEN && export COBE_TOKEN
```

The newest critical stories:

```bash
curl -fsS --cacert cobe-news.crt \
  -H "Authorization: Bearer $COBE_TOKEN" \
  "https://news.corp.example:8095/api/v1/news?severity=critical&limit=20"
```

You need `--cacert` with the self-signed certificate: the file from *Settings → HTTPS & certificate* ("Download
certificate", see [Distributing the certificate](/docs/betrieb#zertifikat-verteilen)). If the machine already trusts the
certificate, or you have a certificate of your own CA, leave `--cacert` out.

The answer (shortened):

```json
{
  "items": [
    {
      "id": "00000000-0000-4000-8000-000000000001",
      "title": "Critical flaw in an example product",
      "url": "https://example.com/advisory/1",
      "source": { "key": "cisa-kev", "name": "CISA KEV" },
      "published_at": "2026-10-30T02:30:00+00:00",
      "severity": "critical",
      "cves": ["CVE-2026-0001"],
      "also_in": []
    }
  ],
  "next": "2026-10-30T02:30:00+00:00|00000000-0000-4000-8000-000000000001"
}
```

**Fetching all pages:** pass `next` of the answer as `before` of the next request until `next` is empty (`null`).
`next` contains `+` and `|` – so always pass it encoded (`--data-urlencode`). Example with `jq`:

```bash
before=""
while :; do
  page=$(curl -fsSG --cacert cobe-news.crt -H "Authorization: Bearer $COBE_TOKEN" \
    --data-urlencode "severity=critical" --data-urlencode "limit=200" --data-urlencode "before=$before" \
    "https://news.corp.example:8095/api/v1/news")
  printf '%s\n' "$page" | jq -c '.items[]'
  before=$(printf '%s\n' "$page" | jq -r '.next // empty')
  [ -n "$before" ] || break
done
```

> [!NOTE]
> On a machine several people work on, someone else can briefly see curl's command line with the token. There, read
> the header from a file only you may read: `curl -H @auth-header.txt …` (one line `Authorization: Bearer cnt_…`).

### PowerShell {#powershell}

With PowerShell 7 – the token is typed hidden and stays a SecureString:

```powershell
$token = Read-Host -AsSecureString "Cobe News token"
Invoke-RestMethod -Uri "https://news.corp.example:8095/api/v1/news?severity=critical&limit=20" `
  -Authentication Bearer -Token $token
```

With Windows PowerShell 5.1 (or when the token is already in an environment variable):

```powershell
Invoke-RestMethod -Uri "https://news.corp.example:8095/api/v1/vendor/findings?exploited=true" `
  -Headers @{ Authorization = "Bearer $env:COBE_TOKEN" }
```

Fetching all pages – encode `next` with `[uri]::EscapeDataString`:

```powershell
$base = "https://news.corp.example:8095/api/v1/news?severity=critical&limit=200"
$uri = $base
$all = @()
do {
  $page = Invoke-RestMethod -Uri $uri -Authentication Bearer -Token $token
  $all += $page.items
  $uri = if ($page.next) { "$base&before=" + [uri]::EscapeDataString($page.next) } else { $null }
} while ($uri)
$all.Count
```

PowerShell needs a certificate Windows trusts – so distribute the self-signed one first
([Distributing the certificate](/docs/betrieb#zertifikat-verteilen)). Use `-SkipCertificateCheck` only for a quick
try, never in a script that sends a token.

## Endpoints {#endpunkte}

All endpoints are `GET`, the answers JSON. The OpenAPI file in the **"Reference"** tab describes the fields in detail.

| Endpoint | Content | Parameters |
|---|---|---|
| `/api/v1/news` | stories of the switched-on sources, newest first; answer `{items, next}` | `severity` (repeatable: `critical`, `high`, `medium`, `low`, `info`), `source` (key of the source, repeatable), `topic` (repeatable, any one matches: `zeroday`, `exploited`, `poc`, `ransomware`, `nopatch`, `breach`, `supply`, `phishing`, `ot` – see [Topics](/docs/news-quellen#themen)), `q` (words in title, summary, CVE), `since` (time in ISO 8601), `limit` (1–200, default 50), `before` (`next` of the previous page). Every story carries `topics`. |
| `/api/v1/news/sources` | the switched-on sources with key and name | – |
| `/api/v1/news/{id}` | one story, with the [EPSS](term:epss) of its CVEs and the [public exploits](/docs/vendor-news#oeffentlicher-exploit) (`exploits`) | – |
| `/api/v1/vendor/products` | the followed products with versions, number of findings of each kind and urgency | – |
| `/api/v1/vendor/products/{key}` | one followed product with its findings | `status` (repeatable; default: all but `not_affected`), `offset`, `limit` (1–500, default 100) |
| `/api/v1/vendor/findings` | findings across all followed products, the most relevant first | `status` (repeatable; default: `affected` and `possible`), `severity` (repeatable), `exploited=true`, `offset`, `limit` (1–500, default 100) |

Notes:

- Best write `since` with `Z` (`since=2026-10-01T00:00:00Z`). A time with `+01:00` must be encoded, otherwise `+`
  becomes a space.
- The values of `status`: `affected`, `possible` (possibly affected), `service` (cloud service affected),
  `unversioned` (product followed without a version), `stale` (unclear old data), `not_affected` – see
  [Verdicts](/docs/vendor-news#bewertung).
- A token sees the same as every signed-in reader on the shared pages – in Vendor News the "All" view.

## Errors and limits {#fehler}

An error comes as JSON with a code, e.g. `{"detail": {"code": "invalid_token"}}`.

| Status | Code | Meaning |
|---|---|---|
| 400 | `bearer_with_cookie` | token and session cookie in the same request – never mix both |
| 401 | `invalid_token` | no token, or an unknown, malformed, revoked, expired or orphaned one – always the same answer, with `WWW-Authenticate: Bearer` |
| 403 | `insufficient_scope` | the token lacks the scope (e.g. a `metrics` token at `/api/v1/news`) |
| 403 | `token_read_only` | another method than `GET` |
| 403 | `token_not_allowed` | another path than `/api/v1/…` or `/metrics` |
| 404 | `not_found` | no such story, or no followed product with this key |
| 422 | `invalid`, `invalid_cursor` | a parameter does not fit, or `before` is not a valid `next` |
| 429 | `rate_limited` | too many requests – `Retry-After` says how many seconds to wait |

The 401 deliberately does not say **why** a token is refused. The token list shows the reason (state).

**Limits:**

- At most **600 requests in 10 minutes** per token (one per second on average).
- **Wrong tokens** count per client address – together with wrong calendar addresses
  ([Calendar](/docs/benachrichtigungen#kalender-ical)): after **20 in 10 minutes** this address gets 429 for the rest
  of the 10 minutes, even with a valid token.
- The counters live in the app's memory; a restart resets them.

## Metrics for Prometheus {#metriken}

`GET /metrics` returns the state of the installation in Prometheus' text format (version 0.0.4). It needs a token with
the scope `metrics`.

- The answer is cached for **30 seconds**, costly parts (what channels still have to send, the database size) for
  **5 minutes**. Asking more often brings nothing.
- No personal data and no story titles. Sources appear with key and name, channels only with id and type (a channel
  may be named after a person).

> [!NOTE]
> Prometheus' token expires too (after a year at most). Make a new one in time and swap it in `credentials_file` – an
> expired token makes the scrape fail with 401 (`up == 0`).

### prometheus.yml {#prometheus-konfiguration}

1. Make a token with `metrics` only ([Making a token](#token-anlegen)).
2. Put the token on the Prometheus server into a file only Prometheus may read, e.g. `/etc/prometheus/cobe-news.token`
   (`chmod 600`, owned by Prometheus' user).
3. With the self-signed certificate, put the file from *Settings → HTTPS & certificate* at
   `/etc/prometheus/cobe-news-ca.crt`.
4. Add the job to `prometheus.yml` and reload Prometheus:

```yaml
scrape_configs:
  - job_name: cobe-news
    scheme: https
    metrics_path: /metrics
    scrape_interval: 60s
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/cobe-news.token
    tls_config:
      ca_file: /etc/prometheus/cobe-news-ca.crt
    static_configs:
      - targets: ["news.corp.example:8095"]
```

With a certificate of your own CA, `ca_file` points to that CA (or is left out when the system trusts it). The
self-signed certificate renews about every five months – then replace the file.

**Prometheus on the same server:** without TLS through the app port, which is bound to `127.0.0.1` only (`APP_PORT`,
default `8096`, see [.env reference](/docs/betrieb#env-adresse)):

```yaml
    scheme: http
    static_configs:
      - targets: ["127.0.0.1:8096"]
```

This only works when Prometheus runs directly on the host (not in a container of its own without the host network).
The token is still needed.

### The metrics {#metriken-liste}

All metrics are of type `gauge`. Times are Unix seconds. `NaN` means "nothing yet", e.g. before the first backup.

| Metric | Labels | Meaning |
|---|---|---|
| `cobe_news_info` | `version` | always 1; the version is in the label |
| `cobe_news_source_state` | `kind`, `source`, `name`, `state` | 1 for the current state of a source: `healthy`, `slow`, `disturbed`, `dead`, `off`, `never` |
| `cobe_news_source_enabled` | `kind`, `source`, `name` | 1 when the source is switched on and needed |
| `cobe_news_source_last_success_timestamp_seconds` | `kind`, `source`, `name` | time of the last successful fetch |
| `cobe_news_source_last_fetch_timestamp_seconds` | `kind`, `source`, `name` | time of the last fetch, successful or not |
| `cobe_news_source_consecutive_failures` | `kind`, `source`, `name` | failures in a row |
| `cobe_news_source_fetches_7d` | `kind`, `source`, `name` | fetches in the last 7 days |
| `cobe_news_source_timeouts_7d` | `kind`, `source`, `name` | timeouts in the last 7 days |
| `cobe_news_source_parse_errors_7d` | `kind`, `source`, `name` | unreadable answers in the last 7 days |
| `cobe_news_sources` | `state` | number of sources per state |
| `cobe_news_channel_consecutive_failures` | `channel_id`, `type` | failed sends of a channel in a row |
| `cobe_news_channel_backoff` | `channel_id`, `type` | 1 while a channel pauses after a failure |
| `cobe_news_channel_last_success_timestamp_seconds` | `channel_id`, `type` | time of the last delivered message |
| `cobe_news_channel_pending_items` | `channel_id`, `type` | what a channel still has to send (computed at most every 5 minutes) |
| `cobe_news_channel_delivery_attempts_24h` | `channel_id`, `type` | delivery attempts of a channel within the last 24 hours ([delivery log](/docs/benachrichtigungen#zustellprotokoll), tests not counted) |
| `cobe_news_channel_delivery_failures_24h` | `channel_id`, `type` | of them failed |
| `cobe_news_delivery_attempts_total` | `kind`, `type`, `outcome` | counter since the start: attempts by kind (`rule`, `forward`, `weekly`, `test`, `personal`), channel type or personal way, and outcome (`ok`, `http`, `timeout`, `blocked`, `smtp`, `error`) |
| `cobe_news_personal_deliveries` | `status`, `way` | personal Vendor News deliveries by state (`pending`, `sending`, `failed`) and way (`email`, `desktop`, `teams`) |
| `cobe_news_personal_backlog` | – | 1 when the last round of personal deliveries had to stop with messages left |
| `cobe_news_backup_last_ok` | – | 1: last backup attempt worked, 0: failed |
| `cobe_news_backup_last_attempt_timestamp_seconds` | – | time of the last backup attempt |
| `cobe_news_backup_newest_timestamp_seconds` | – | time of the newest backup file |
| `cobe_news_backup_age_seconds` | – | age of the newest backup file |
| `cobe_news_backup_files` | – | number of backup files on the server |
| `cobe_news_restore_test_configured` | – | 1 when the throwaway database for the [restore test](/docs/sicherung#ruecksicherungs-test) is set up |
| `cobe_news_restore_test_enabled` | – | 1 when the restore test is switched on |
| `cobe_news_restore_test_running` | – | 1 while a test runs |
| `cobe_news_restore_test_last_ok` | – | 1: last test passed, 0: failed |
| `cobe_news_restore_test_last_timestamp_seconds` | – | time the last test ended |
| `cobe_news_restore_test_age_seconds` | – | age of the last test |
| `cobe_news_restore_test_duration_seconds` | – | how long the last test took |
| `cobe_news_update_available` | – | 1: a newer Cobe News version is published, 0: not; `NaN` while the [update notice](/docs/betrieb#update-hinweis) is off or has no answer yet |
| `cobe_news_audit_entries` | `group` | entries in the [audit log](/docs/betrieb#protokoll) per area – counts only, no names |
| `cobe_news_audit_newest_timestamp_seconds` | – | time of the newest audit log entry |
| `cobe_news_database_size_bytes` | – | size of the database on disk (computed at most every 5 minutes) |
| `cobe_news_metrics_generated_timestamp_seconds` | – | when this answer was computed |

`kind` is `news`, `vendor` or `structured` (the [more sources](/docs/integrationen#weitere-quellen)). The states of the
sources are explained under [Health](/docs/integrationen#gesundheit).

### Alerts {#alarme}

Example rules for Prometheus (a file under `rule_files`):

```yaml
groups:
  - name: cobe-news
    rules:
      - alert: CobeNewsDown
        expr: up{job="cobe-news"} == 0
        for: 10m
      - alert: CobeNewsBackupTooOld
        expr: cobe_news_backup_age_seconds > 26 * 3600
        for: 15m
      - alert: CobeNewsBackupFailed
        expr: cobe_news_backup_last_ok == 0
      - alert: CobeNewsRestoreTestFailed
        expr: cobe_news_restore_test_last_ok == 0
      - alert: CobeNewsRestoreTestTooOld
        expr: cobe_news_restore_test_age_seconds > 8 * 86400
      - alert: CobeNewsSourceDead
        expr: cobe_news_source_state{state="dead"} == 1
        for: 30m
      - alert: CobeNewsChannelBackoff
        expr: cobe_news_channel_backoff == 1
        for: 1h
      - alert: CobeNewsPersonalDeliveriesFailing
        expr: delta(cobe_news_personal_deliveries{status="failed"}[1h]) > 0
```

- `up == 0` also reports an invalid token (401) – then check the token list first.
- A comparison with `NaN` is never true: before the first backup or the first restore test, their alerts do not fire.
  So after setting up, back up once and choose "Test now" once.
- `26 * 3600` fits a daily backup by [cron](/docs/sicherung#cron); `8 * 86400` a weekly restore test.

## Security {#sicherheit}

**A token is stolen.** This is the main danger. What keeps the damage small:

- Only a keyed hash ([HMAC](term:hmac)) is stored; the token itself is shown only once.
- The prefix `cnt_` lets secret scanners find a token in code, tickets or chats.
- Every token expires (a year at most); revoke tokens no longer needed at once.
- A token only works while its admin is an active admin.
- Read only, only `/api/v1/…` and `/metrics`; no admin and no user-interface endpoints.
- Limits per token and per address (see [Errors and limits](#fehler)).

**CSRF** does not apply: a token only comes in the header, no browser sends it by itself, only `GET` works, and token
and session cookie are never mixed.

**Metrics** contain no personal data and no story content. Still, they tell something about your operations (sources,
channels, state of the backups) – hence a separate token with `metrics` only.

Recommendations:

- Always over HTTPS, best through the bundled proxy. Use the app port `8096` only on the same host.
- One token per purpose and system, with a telling name – then one can be revoked on its own.
- **Never** put a token into a URL, a wiki, a ticket, a chat or a repository. Scripts read it from a secret store, an
  environment variable or a file only they may read.
- If a token shows up somewhere it does not belong: revoke it at once, make a new one.
