---
title: API & Metriken
summary: API-Tokens anlegen, die Nachrichten und Vendor News per Skript lesen (curl, PowerShell) und den Zustand der Installation mit Prometheus überwachen.
audience: admin
---

## Überblick {#ueberblick}

Cobe News hat eine kleine, dokumentierte **API nur zum Lesen** – für Skripte, ein SIEM, ein Ticketsystem oder
[Prometheus](term:prometheus). Der Zugang ist ein **API-Token**, das ein Admin anlegt. Die Seite dazu:
*Einstellungen → API & Metriken* ([direkt öffnen](/settings/api)).

| Was | Adresse | Token braucht |
|---|---|---|
| Nachrichten, Quellen, gefolgte Produkte, Befunde | `/api/v1/…` | Scope `read` |
| Zustand der Installation für Prometheus | `/metrics` | Scope `metrics` |

- Nur **lesen**: Ein Token kann nichts ändern, nichts anlegen und nichts löschen.
- Nur diese zwei Bereiche: Die Endpunkte der Oberfläche und der Admin-Seiten erreicht ein Token nie.
- Nichts Persönliches: keine Gelesen-Markierungen, keine Notizen, keine Benutzernamen.
- Die genaue Beschreibung aller Felder steht im Reiter **„Referenz“** als [OpenAPI](term:openapi)-Datei zum
  Herunterladen. Eine öffentliche Seite `/docs` oder `/openapi.json` gibt es nicht.

## API-Tokens {#tokens}

Ein Token sieht so aus: `cnt_` und 43 weitere Zeichen (256 zufällige Bits). Das feste Präfix `cnt_` hilft
Secret-Scannern, ein Token in Code oder Tickets zu finden – z. B. ein eigenes Muster in GitHub:

```text
cnt_[A-Za-z0-9_-]{43}
```

Cobe News speichert das Token **nicht** selbst, nur einen Schlüssel-Hash davon ([HMAC](term:hmac) mit dem
[Hauptschlüssel](term:masterkey)). Wer die Datenbank oder eine Sicherung liest, kann daraus kein Token machen.

### Token anlegen {#token-anlegen}

1. *Einstellungen → API & Metriken* öffnen, Reiter **„Tokens“**.
2. Einen **Namen** eingeben, der sagt, wofür das Token ist (z. B. „Prometheus“ oder „SIEM-Export“).
3. Den oder die **[Scopes](term:scope)** wählen (siehe [Scopes](#scopes)).
4. Den **Ablauf** wählen: 30, 90, 180 oder 365 Tage. Jedes Token läuft nach **höchstens einem Jahr** ab – „nie“ gibt es
   seit 0.1.42 nicht mehr (siehe [Widerrufen und Ablauf](#token-widerrufen)).
5. Anlegen und die [erneute Bestätigung](/docs/anmeldung#erneut-bestaetigen) mit Passwort und TOTP ausführen (Entra-Konten: bei Microsoft).
6. Das Token **sofort kopieren** und sicher ablegen (Passwort-Manager, Secret-Store des Skripts).

> [!WARNING]
> Das Token erscheint **nur einmal**. Danach kann es niemand mehr anzeigen – auch kein Admin. Ist es verloren: ein
> neues anlegen, das alte widerrufen.

Die Liste zeigt je Token:

| Spalte | Inhalt |
|---|---|
| Name | der Name beim Anlegen |
| Token | nur die ersten Zeichen, z. B. `cnt_AbC123` – damit ihr Tokens auseinanderhaltet |
| Scopes | `read`, `metrics` oder beide |
| Erstellt | von wem und wann |
| Läuft ab | Datum; „Ablauf ergänzt“ bei einem Token, das vor 0.1.42 ohne Ablauf angelegt wurde |
| Zuletzt benutzt | höchstens alle 5 Minuten aktualisiert |
| Zustand | aktiv, abgelaufen, widerrufen oder verwaist |

Es gibt höchstens **50 aktive** Tokens.

### Scopes {#scopes}

| Scope | Erlaubt |
|---|---|
| `read` | alles unter `/api/v1/` – Nachrichten, Quellen, gefolgte Produkte von Vendor News und ihre Befunde |
| `metrics` | nur `/metrics` |

Es gibt keinen Scope zum Schreiben und keinen Admin-Scope.

> [!TIP]
> Für Prometheus ein **eigenes Token nur mit `metrics`** anlegen. Gerät es in falsche Hände, sieht man damit nur
> Zahlen zum Betrieb, aber keine Nachrichten und keine Befunde.

### Widerrufen und Ablauf {#token-widerrufen}

- **Widerrufen:** In der Liste beim Token „Widerrufen“ wählen und erneut bestätigen. Das Token gilt **sofort** nicht
  mehr.
- **Ablauf:** Ein abgelaufenes Token gilt nicht mehr. Verlängern geht nicht – rechtzeitig ein neues anlegen, im Skript
  austauschen und das alte widerrufen. Ein Token gilt höchstens 365 Tage; über die API (`POST /api/admin/api-tokens`)
  sind `expires_days` 1 bis 365 erlaubt, ohne Angabe 365 – `null` („nie“) wird abgelehnt.
- **Tokens ohne Ablauf aus älteren Versionen:** Das Update auf 0.1.42 hat jedem noch gültigen Token, das mit „nie“
  angelegt war, ein Ablaufdatum gegeben: **Zeitpunkt des Updates + 365 Tage**. Die Liste zeigt bei ihm „Ablauf ergänzt“.
  Vor diesem Datum ein neues Token anlegen und tauschen – sonst bekommt das Skript (oder Prometheus, siehe
  [Metriken](#metriken)) ab dann 401.
- Widerrufene und abgelaufene Tokens bleiben **30 Tage** in der Liste, dann verschwinden sie.

**Verwaist:** Ein Token gilt nur, solange der Admin, der es angelegt hat, ein **aktiver Admin** ist. Wird sein Konto
abgeschaltet, gelöscht oder zum Leser, ist das Token „verwaist“ und jede Anfrage bekommt 401.

> [!NOTE]
> Verlässt ein Admin das Team, legt ein anderer Admin für jedes seiner Tokens ein neues an, trägt es im Skript ein und
> widerruft das alte. Wird ein Konto später wieder Admin, gelten seine verwaisten Tokens wieder – deshalb alte Tokens
> lieber widerrufen.

## Nutzung {#nutzung}

Das Token geht in jeder Anfrage im Header mit (Schema [Bearer](term:bearer)):

```text
Authorization: Bearer cnt_…
```

Die Regeln:

- Nur `GET`, nur `/api/v1/…` und `/metrics`.
- **Nie** zusammen mit einer Anmeldung im Browser (Sitzungs-Cookie) – dann kommt 400 `bearer_with_cookie`.
- Kein CSRF-Token nötig.
- Das Token **nie in die URL** schreiben. Cobe News liest es nur aus dem Header.
- Die Adresse ist dieselbe wie im Browser, z. B. `https://news.corp.example:8095`.

### curl {#curl}

Das Token in eine Umgebungsvariable einlesen – es erscheint nicht auf dem Bildschirm und nicht in der Shell-History:

```bash
read -rs COBE_TOKEN && export COBE_TOKEN
```

Die neuesten kritischen Meldungen:

```bash
curl -fsS --cacert cobe-news.crt \
  -H "Authorization: Bearer $COBE_TOKEN" \
  "https://news.corp.example:8095/api/v1/news?severity=critical&limit=20"
```

`--cacert` braucht ihr beim selbstsignierten Zertifikat: die Datei aus *Einstellungen → HTTPS & Zertifikat*
(„Zertifikat herunterladen“, siehe [Zertifikat verteilen](/docs/betrieb#zertifikat-verteilen)). Vertraut der Rechner dem
Zertifikat schon, oder habt ihr ein Zertifikat eurer eigenen CA, fällt `--cacert` weg.

Die Antwort (gekürzt):

```json
{
  "items": [
    {
      "id": "00000000-0000-4000-8000-000000000001",
      "title": "Kritische Lücke in einem Beispielprodukt",
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

**Alle Seiten abholen:** `next` der Antwort als `before` der nächsten Anfrage mitgeben, bis `next` leer (`null`) ist.
`next` enthält `+` und `|` – deshalb immer kodiert übergeben (`--data-urlencode`). Beispiel mit `jq`:

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
> Auf einem Rechner, an dem mehrere Personen arbeiten, kann jemand anderes die Befehlszeile von curl samt Token kurz
> sehen. Dort den Header aus einer Datei lesen, die nur ihr lesen dürft: `curl -H @auth-header.txt …` (eine Zeile
> `Authorization: Bearer cnt_…`).

### PowerShell {#powershell}

Mit PowerShell 7 – das Token wird verdeckt eingegeben und bleibt ein SecureString:

```powershell
$token = Read-Host -AsSecureString "Cobe News Token"
Invoke-RestMethod -Uri "https://news.corp.example:8095/api/v1/news?severity=critical&limit=20" `
  -Authentication Bearer -Token $token
```

Mit Windows PowerShell 5.1 (oder wenn das Token schon in einer Umgebungsvariablen steht):

```powershell
Invoke-RestMethod -Uri "https://news.corp.example:8095/api/v1/vendor/findings?exploited=true" `
  -Headers @{ Authorization = "Bearer $env:COBE_TOKEN" }
```

Alle Seiten abholen – `next` mit `[uri]::EscapeDataString` kodieren:

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

PowerShell braucht ein Zertifikat, dem Windows vertraut – das selbstsignierte also vorher verteilen
([Zertifikat verteilen](/docs/betrieb#zertifikat-verteilen)). `-SkipCertificateCheck` nur zum kurzen Ausprobieren,
nie in einem Skript, das ein Token sendet.

## Endpunkte {#endpunkte}

Alle Endpunkte sind `GET`, die Antworten JSON. Die Felder im Einzelnen beschreibt die OpenAPI-Datei im Reiter
**„Referenz“**.

| Endpunkt | Inhalt | Parameter |
|---|---|---|
| `/api/v1/news` | Meldungen der eingeschalteten Quellen, neueste zuerst; Antwort `{items, next}` | `severity` (mehrfach: `critical`, `high`, `medium`, `low`, `info`), `source` (Schlüssel der Quelle, mehrfach), `topic` (mehrfach, eines genügt: `zeroday`, `exploited`, `poc`, `ransomware`, `nopatch`, `breach`, `supply`, `phishing`, `ot` – siehe [Themen](/docs/news-quellen#themen)), `q` (Wörter in Titel, Zusammenfassung, CVE), `since` (Zeit nach ISO 8601), `limit` (1–200, Standard 50), `before` (`next` der vorigen Seite). Jede Meldung trägt `topics`. |
| `/api/v1/news/sources` | die eingeschalteten Quellen mit Schlüssel und Name | – |
| `/api/v1/news/{id}` | eine Meldung, dazu [EPSS](term:epss) ihrer CVEs und die [öffentlichen Exploits](/docs/vendor-news#oeffentlicher-exploit) (`exploits`) | – |
| `/api/v1/vendor/products` | die gefolgten Produkte mit Versionen, Anzahl der Befunde je Art und Dringlichkeit | – |
| `/api/v1/vendor/products/{key}` | ein gefolgtes Produkt mit seinen Befunden | `status` (mehrfach; Standard: alle außer `not_affected`), `offset`, `limit` (1–500, Standard 100) |
| `/api/v1/vendor/findings` | Befunde über alle gefolgten Produkte, die wichtigsten zuerst | `status` (mehrfach; Standard: `affected` und `possible`), `severity` (mehrfach), `exploited=true`, `confirmed` (`false`: ohne die bestätigten, `true`: nur sie; Standard: alle), `offset`, `limit` (1–500, Standard 100) |

Hinweise:

- `since` am besten mit `Z` schreiben (`since=2026-10-01T00:00:00Z`). Eine Zeit mit `+01:00` muss kodiert werden, sonst
  wird aus `+` ein Leerzeichen.
- Die Werte für `status`: `affected` (betroffen), `possible` (möglicherweise betroffen), `service` (Cloud-Dienst
  betroffen), `unversioned` (Produkt ohne Version gefolgt), `stale` (unklare Altdaten), `not_affected` (nicht
  betroffen) – siehe [Bewertung](/docs/vendor-news#bewertung).
- Ein Token sieht dasselbe wie jeder angemeldete Leser auf den gemeinsamen Seiten – bei Vendor News die Ansicht „Alle“.
- Ein [bestätigter Treffer](/docs/vendor-news#treffer-bestaetigen) trägt `confirmed` (`status`, `note`, `by`, `at`) und
  zählt in den Zahlen von `/api/v1/vendor/products` nicht mit.

## Fehler und Grenzen {#fehler}

Ein Fehler kommt als JSON mit einem Code, z. B. `{"detail": {"code": "invalid_token"}}`.

| Status | Code | Bedeutung |
|---|---|---|
| 400 | `bearer_with_cookie` | Token und Sitzungs-Cookie in derselben Anfrage – nie beides mischen |
| 401 | `invalid_token` | kein Token, oder unbekannt, falsch geformt, widerrufen, abgelaufen oder verwaist – immer dieselbe Antwort, mit `WWW-Authenticate: Bearer` |
| 403 | `insufficient_scope` | dem Token fehlt der Scope (z. B. ein `metrics`-Token an `/api/v1/news`) |
| 403 | `token_read_only` | eine andere Methode als `GET` |
| 403 | `token_not_allowed` | ein anderer Pfad als `/api/v1/…` oder `/metrics` |
| 404 | `not_found` | keine solche Meldung bzw. kein gefolgtes Produkt mit diesem Schlüssel |
| 422 | `invalid`, `invalid_cursor` | ein Parameter passt nicht, oder `before` ist kein gültiges `next` |
| 429 | `rate_limited` | zu viele Anfragen – `Retry-After` sagt, wie viele Sekunden zu warten sind |

Die 401 sagt absichtlich nicht, **warum** ein Token nicht gilt. Den Grund zeigt die Liste der Tokens (Zustand).

**Grenzen:**

- Je Token höchstens **600 Anfragen in 10 Minuten** (im Mittel eine pro Sekunde).
- **Falsche Tokens** zählen je Client-Adresse – zusammen mit falschen Kalender-Adressen
  ([Kalender](/docs/benachrichtigungen#kalender-ical)): nach **20 in 10 Minuten** bekommt diese Adresse für den Rest der
  10 Minuten 429, auch mit einem gültigen Token.
- Die Zähler leben im Speicher der App; ein Neustart setzt sie zurück.

## Metriken für Prometheus {#metriken}

`GET /metrics` liefert den Zustand der Installation im Textformat von Prometheus (Version 0.0.4). Nötig ist ein Token
mit dem Scope `metrics`.

- Die Antwort wird **30 Sekunden** zwischengespeichert, teure Teile (was Kanäle noch senden müssen, Größe der
  Datenbank) **5 Minuten**. Häufiger abfragen bringt nichts.
- Keine personenbezogenen Daten und keine Titel von Meldungen. Quellen erscheinen mit Schlüssel und Name, Kanäle nur
  mit ID und Typ (ein Kanal kann nach einer Person benannt sein).

> [!NOTE]
> Auch das Token von Prometheus läuft ab (höchstens nach einem Jahr). Rechtzeitig ein neues anlegen und in
> `credentials_file` tauschen – ein abgelaufenes Token lässt den Scrape mit 401 scheitern (`up == 0`).

### prometheus.yml {#prometheus-konfiguration}

1. Ein Token nur mit `metrics` anlegen ([Token anlegen](#token-anlegen)).
2. Das Token auf dem Prometheus-Server in eine Datei legen, die nur Prometheus lesen darf, z. B.
   `/etc/prometheus/cobe-news.token` (`chmod 600`, Besitzer der Benutzer von Prometheus).
3. Beim selbstsignierten Zertifikat die Datei aus *Einstellungen → HTTPS & Zertifikat* nach
   `/etc/prometheus/cobe-news-ca.crt` legen.
4. Den Job in `prometheus.yml` eintragen und Prometheus neu laden:

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

Mit einem Zertifikat eurer eigenen CA zeigt `ca_file` auf diese CA (oder fällt weg, wenn das System ihr vertraut). Das
selbstsignierte Zertifikat erneuert sich etwa alle fünf Monate – dann die Datei austauschen.

**Prometheus auf demselben Server:** Ohne TLS über den App-Port, der nur an `127.0.0.1` gebunden ist (`APP_PORT`,
Standard `8096`, siehe [Referenz der .env](/docs/betrieb#env-adresse)):

```yaml
    scheme: http
    static_configs:
      - targets: ["127.0.0.1:8096"]
```

Das geht nur, wenn Prometheus direkt auf dem Host läuft (nicht in einem eigenen Container ohne Host-Netz). Das Token
ist trotzdem nötig.

### Die Metriken {#metriken-liste}

Alle Metriken sind vom Typ `gauge`. Zeiten sind Unix-Sekunden. `NaN` heißt „noch nichts da“, z. B. vor der ersten
Sicherung.

| Metrik | Labels | Bedeutung |
|---|---|---|
| `cobe_news_info` | `version` | immer 1; die Version steht im Label |
| `cobe_news_source_state` | `kind`, `source`, `name`, `state` | 1 für den aktuellen Zustand einer Quelle: `healthy`, `slow`, `disturbed`, `dead`, `off`, `never` |
| `cobe_news_source_enabled` | `kind`, `source`, `name` | 1, wenn die Quelle eingeschaltet ist und gebraucht wird |
| `cobe_news_source_last_success_timestamp_seconds` | `kind`, `source`, `name` | Zeit des letzten erfolgreichen Abrufs |
| `cobe_news_source_last_fetch_timestamp_seconds` | `kind`, `source`, `name` | Zeit des letzten Abrufs, erfolgreich oder nicht |
| `cobe_news_source_consecutive_failures` | `kind`, `source`, `name` | Fehlschläge in Folge |
| `cobe_news_source_fetches_7d` | `kind`, `source`, `name` | Abrufe der letzten 7 Tage |
| `cobe_news_source_timeouts_7d` | `kind`, `source`, `name` | Zeitüberschreitungen der letzten 7 Tage |
| `cobe_news_source_parse_errors_7d` | `kind`, `source`, `name` | unlesbare Antworten der letzten 7 Tage |
| `cobe_news_sources` | `state` | Anzahl der Quellen je Zustand |
| `cobe_news_channel_consecutive_failures` | `channel_id`, `type` | fehlgeschlagene Sendungen eines Kanals in Folge |
| `cobe_news_channel_backoff` | `channel_id`, `type` | 1, solange ein Kanal nach einem Fehler pausiert |
| `cobe_news_channel_last_success_timestamp_seconds` | `channel_id`, `type` | Zeit der letzten zugestellten Nachricht |
| `cobe_news_channel_pending_items` | `channel_id`, `type` | was ein Kanal noch senden muss (höchstens alle 5 Minuten berechnet) |
| `cobe_news_channel_delivery_attempts_24h` | `channel_id`, `type` | Zustellversuche eines Kanals in den letzten 24 Stunden ([Zustellprotokoll](/docs/benachrichtigungen#zustellprotokoll), ohne Tests) |
| `cobe_news_channel_delivery_failures_24h` | `channel_id`, `type` | davon fehlgeschlagen |
| `cobe_news_delivery_attempts_total` | `kind`, `type`, `outcome` | Zähler seit dem Start: Versuche nach Art (`rule`, `forward`, `weekly`, `test`, `personal`), Kanaltyp bzw. persönlichem Weg und Ergebnis (`ok`, `http`, `timeout`, `blocked`, `smtp`, `error`) |
| `cobe_news_personal_deliveries` | `status`, `way` | persönliche Zustellungen von Vendor News nach Zustand (`pending`, `sending`, `failed`) und Weg (`email`, `desktop`, `teams`) |
| `cobe_news_personal_backlog` | – | 1, wenn die letzte Runde persönlicher Zustellungen mit Rest aufhören musste |
| `cobe_news_backup_last_ok` | – | 1: letzter Sicherungsversuch geklappt, 0: fehlgeschlagen |
| `cobe_news_backup_last_attempt_timestamp_seconds` | – | Zeit des letzten Sicherungsversuchs |
| `cobe_news_backup_newest_timestamp_seconds` | – | Zeit der neuesten Sicherungsdatei |
| `cobe_news_backup_age_seconds` | – | Alter der neuesten Sicherungsdatei |
| `cobe_news_backup_files` | – | Anzahl der Sicherungsdateien auf dem Server |
| `cobe_news_restore_test_configured` | – | 1, wenn die Wegwerf-Datenbank für den [Rücksicherungs-Test](/docs/sicherung#ruecksicherungs-test) eingerichtet ist |
| `cobe_news_restore_test_enabled` | – | 1, wenn der Rücksicherungs-Test eingeschaltet ist |
| `cobe_news_restore_test_running` | – | 1, solange ein Test läuft |
| `cobe_news_restore_test_last_ok` | – | 1: letzter Test bestanden, 0: fehlgeschlagen |
| `cobe_news_restore_test_last_timestamp_seconds` | – | Zeit, zu der der letzte Test endete |
| `cobe_news_restore_test_age_seconds` | – | Alter des letzten Tests |
| `cobe_news_restore_test_duration_seconds` | – | Dauer des letzten Tests |
| `cobe_news_update_available` | – | 1: eine neuere Version von Cobe News ist veröffentlicht, 0: nicht; `NaN`, solange der [Update-Hinweis](/docs/betrieb#update-hinweis) aus ist oder noch keine Antwort hat |
| `cobe_news_audit_entries` | `group` | Einträge im [Protokoll](/docs/betrieb#protokoll) je Bereich – nur Zahlen, keine Namen |
| `cobe_news_audit_newest_timestamp_seconds` | – | Zeit des neuesten Protokoll-Eintrags |
| `cobe_news_database_size_bytes` | – | Größe der Datenbank auf der Platte (höchstens alle 5 Minuten berechnet) |
| `cobe_news_metrics_generated_timestamp_seconds` | – | wann diese Antwort berechnet wurde |

`kind` ist `news`, `vendor` oder `structured` (die [weiteren Quellen](/docs/integrationen#weitere-quellen)). Die
Zustände der Quellen erklärt [Gesundheit](/docs/integrationen#gesundheit).

### Alarme {#alarme}

Beispiele für Regeln in Prometheus (Datei unter `rule_files`):

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

- `up == 0` meldet auch ein ungültiges Token (401) – dann zuerst die Liste der Tokens prüfen.
- Ein Vergleich mit `NaN` ist nie wahr: Vor der ersten Sicherung bzw. dem ersten Rücksicherungs-Test schlagen die
  Alarme dazu nicht an. Nach dem Einrichten deshalb einmal sichern und einmal „Jetzt testen“.
- `26 * 3600` passt zu einer täglichen Sicherung per [cron](/docs/sicherung#cron); `8 * 86400` zu einem wöchentlichen
  Rücksicherungs-Test.

## Sicherheit {#sicherheit}

**Ein Token wird gestohlen.** Das ist die wichtigste Gefahr. Was den Schaden klein hält:

- Gespeichert ist nur ein Schlüssel-Hash ([HMAC](term:hmac)); das Token selbst erscheint nur einmal.
- Das Präfix `cnt_` lässt Secret-Scanner ein Token in Code, Tickets oder Chats finden.
- Jedes Token läuft ab (höchstens ein Jahr); nicht mehr gebrauchte Tokens sofort widerrufen.
- Ein Token gilt nur, solange sein Admin ein aktiver Admin ist.
- Nur lesen, nur `/api/v1/…` und `/metrics`; keine Admin- und keine Oberflächen-Endpunkte.
- Grenzen je Token und je Adresse (siehe [Fehler und Grenzen](#fehler)).

**CSRF** spielt keine Rolle: Ein Token kommt nur im Header, kein Browser schickt es von selbst mit, es geht nur `GET`,
und Token und Sitzungs-Cookie werden nie gemischt.

**Metriken** enthalten keine personenbezogenen Daten und keine Inhalte von Meldungen. Trotzdem verraten sie etwas über
euren Betrieb (Quellen, Kanäle, Stand der Sicherungen) – deshalb ein eigenes Token nur mit `metrics`.

Empfehlungen:

- Immer über HTTPS, am besten über den mitgelieferten Proxy. Den App-Port `8096` nur auf demselben Host nutzen.
- Ein Token je Zweck und System, mit sprechendem Namen – dann lässt sich eines gezielt widerrufen.
- Ein Token **nie** in eine URL, ein Wiki, ein Ticket, einen Chat oder ein Repository schreiben. Skripte lesen es aus
  einem Secret-Store, einer Umgebungsvariablen oder einer Datei, die nur sie lesen dürfen.
- Taucht ein Token irgendwo auf, wo es nicht hingehört: sofort widerrufen, ein neues anlegen.
