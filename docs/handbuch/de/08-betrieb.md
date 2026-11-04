---
title: Betrieb
summary: Einstellungen in der .env, Start und Stopp, Updates, HTTPS, eigener Reverse Proxy, Adresse im Netz, Logs, Befehle auf dem Server und die Datenbank.
audience: admin
---

## Referenz der .env {#env-referenz}

Alles, was die Installation selbst betrifft (Adresse, Zertifikat, Netz, Datenbank), steht in der
[.env](term:envfile) im Installationsordner. Alles andere stellt ihr in der Oberfläche ein; es liegt in der Datenbank.

- Vorlage ist `.env.example`; `scripts/setup-env.sh` legt daraus einmal die `.env` an (nur für den Besitzer lesbar).
- Eine Zeile mit `#` am Anfang ist aus – es gilt dann der Standard aus der Tabelle.
- Nach jeder Änderung `docker compose up -d` ausführen. Das legt die betroffenen Container mit den neuen Werten neu an.
  `docker compose restart` reicht **nicht**: dabei behalten die Container ihre alten Werte.
- Die `.env` enthält Passwörter. Nie weitergeben, nie ins Repository einchecken (Git ignoriert sie).

### Adresse und Port {#env-adresse}

| Variable | Bedeutung | Standard |
|---|---|---|
| `PORT` | https-Port auf dem Host (der mitgelieferte nginx) | `8095` |
| `BIND` | auf welcher Adresse des Hosts der Port lauscht. `0.0.0.0` öffnet ihn ins Netz ([Adresse für Kollegen](#adresse)) | `127.0.0.1` (nur dieser Rechner) |
| `BASE_URL` | die Adresse, die man im Browser eintippt – für Links in Benachrichtigungen, die Entra-Umleitungs-URI, die Push-Kontaktadresse und die Namen im Zertifikat | `https://localhost:8095` |
| `NEWS_HOSTNAME` | [FQDN](term:fqdn) für das selbstsignierte Zertifikat (neben `localhost` und `127.0.0.1`) | leer |
| `TLS_NAMES` | weitere Namen oder IP-Adressen für das selbstsignierte Zertifikat, durch Komma getrennt. nginx antwortet nur auf die Namen aus `BASE_URL`, `NEWS_HOSTNAME`, `TLS_NAMES` und `localhost` ([Nur bekannte Namen](#host-namen)) | leer |
| `APP_PORT` | http-Port der App, fest an `127.0.0.1` gebunden: für den Health-Check, Prometheus auf demselben Host ([Metriken](/docs/api#prometheus-konfiguration)) und einen eigenen Reverse Proxy auf demselben Host | `8096` |
| `COMPOSE_FILE` | `docker-compose.yml:docker-compose.http.yml` schaltet die Umleitung von http auf https ein ([HTTPS](#http-umleitung)) | nicht gesetzt |
| `HTTP_PORT` | http-Port, der nur auf https umleitet (nur mit `COMPOSE_FILE` wie oben) | `8094` |
| `COBE_NEWS_IMAGE` | das veröffentlichte, signierte Image statt des lokalen Builds, z. B. `ghcr.io/g0urmetd/cobe-news:0.1.46` – nur mit `COMPOSE_FILE=docker-compose.yml:docker-compose.image.yml`; Signatur vorher mit cosign prüfen (docs/BETRIEB.md) | nicht gesetzt (lokaler Build) |

### Zertifikat {#env-zertifikat}

| Variable | Bedeutung | Standard |
|---|---|---|
| `TLS_MODE` | `selfsigned` (die App erstellt und erneuert das Zertifikat), `own` (euer Zertifikat), `external` (TLS endet an eurem eigenen Proxy) | `selfsigned` |
| `TLS_SOURCE` | mit `own`: Ordner mit `cobe.crt` und `cobe.key`, z. B. `./deploy/certs` | das Docker-Volume `tls` |
| `HSTS` | `1` sendet [HSTS](term:hsts) auch mit dem selbstsignierten Zertifikat. Bei `own` und `external` wird HSTS immer gesendet – nur an Hostnamen, nie an `localhost` oder IP-Adressen ([HSTS](#hsts)) | `0` |

### Eigener Proxy und Client-Adressen {#env-proxy}

| Variable | Bedeutung | Standard |
|---|---|---|
| `PROXY_ENABLED` | `0`: der mitgelieferte nginx startet nicht – für einen eigenen [Reverse Proxy](term:reverseproxy) davor | `1` |
| `TRUSTED_PROXIES` | Adressen oder Netze ([CIDR](term:cidr)), deren `X-Forwarded-For` die App glaubt – nur die Adresse eures eigenen Proxys, z. B. `172.31.250.1/32` für einen Proxy auf dem Host ([welche Adresse?](#trusted-proxies)) | leer |
| `SHARED_ADDRESSES` | Adressen oder Netze, die sich viele Personen teilen (z. B. das NAT eines Büros): werden nie gesperrt, Fehlversuche darüber nur gebremst | leer |
| `COOKIE_SECURE` | Cookies nur über https. Nicht ändern – `0` ist nur für Entwicklung ohne https gedacht | `1` |

### Geheimnisse und ausgehende Verbindungen {#env-ausgehend}

| Variable | Bedeutung | Standard |
|---|---|---|
| `SECRET_KEY` | [Hauptschlüssel](term:masterkey) für gespeicherte Geheimnisse (Webhook-URLs, SMTP-, LDAP-Passwort, Entra-Geheimnis, TOTP lokaler Konten). Mindestens 32 zufällige Zeichen, z. B. aus `openssl rand -base64 32` – ein kürzerer (oder einer aus nur wenigen verschiedenen Zeichen) startet, gibt aber beim Start eine Warnung aus und steht als Hinweis unter *Einstellungen → HTTPS & Zertifikat*. Nicht mehr ändern, wenn Geheimnisse gespeichert sind | leer: Schlüsseldatei `./data/secret.key` |
| `WEBHOOK_HOSTS` | weitere erlaubte Hosts für Teams- und Slack-Kanäle (neben den Microsoft- und Slack-Hosts), z. B. `chat.corp.example` | leer |
| `WEBHOOK_PRIVATE_NETS` | private Adressen oder Netze, an die Benachrichtigungskanäle senden dürfen (z. B. ein n8n im Firmennetz), z. B. `10.20.0.0/16,192.168.10.5`; auch die eigenen Docker-Netze und der Docker-Host über seine Adresse. Loopback, Link-Local (`169.254.169.254`), „any“ und Multicast bleiben immer gesperrt ([Erlaubte Ziele](/docs/benachrichtigungen#webhook-ziele)) | leer: nur öffentliche Ziele |
| `SMTP_ALLOW_INTERNAL` | Adresse eines [SMTP](term:smtp)-Relays, das sonst als intern abgelehnt würde (z. B. auf dem Docker-Host hinter dem Gateway `172.31.250.1`; dann auch per Name wie `host.docker.internal`). Loopback, Link-Local, „any“ und Multicast bleiben immer gesperrt | leer |
| `HTTPS_PROXY` | Proxy für alle ausgehenden Anfragen, z. B. `http://proxy.corp.example:3128` | leer |
| `CA_FILE` | Pfad **im Container** zu einem eigenen CA-Bündel (PEM), z. B. für einen Proxy, der TLS aufbricht. Der Ordner `./data` ist als `/data` eingehängt: Datei z. B. als `./data/ca.pem` ablegen und `CA_FILE=/data/ca.pem` setzen | leer |
| `ALLOW_PRIVATE_FEEDS` | `1` erlaubt eigene Feeds unter privaten Adressen (Firmennetz) | `0` |

### Web Push {#env-push}

| Variable | Bedeutung | Standard |
|---|---|---|
| `WEB_PUSH` | `0` schaltet Desktop-Benachrichtigungen bei geschlossenem Tab für alle ab – dann geht keine Anfrage an die Push-Dienste der Browser. Der offene Tab benachrichtigt weiter | `1` |
| `PUSH_CONTACT` | Kontaktadresse für die Push-Dienste (`mailto:` oder `https:`), z. B. `mailto:secops@corp.example` | leer: `BASE_URL` |

Mehr dazu: [Web Push](/docs/integrationen#web-push), Schlüssel [VAPID](term:vapid).

### Datenbank und Sicherungen {#env-datenbank}

| Variable | Bedeutung | Standard |
|---|---|---|
| `POSTGRES_PASSWORD` | Passwort des Datenbank-Superusers `cobe_news` (nur `db-init` nutzt es). **Nie ändern** ([Datenbank](#datenbank)) | von `setup-env.sh` erzeugt |
| `POSTGRES_APP_PASSWORD` | Passwort der App-Rolle `cobe_news_app`, mindestens 16 Zeichen. Darf sich ändern – `db-init` setzt es bei jedem Start | von `setup-env.sh` erzeugt |
| `POSTGRES_RESTORE_PASSWORD` | Passwort der Rolle `cobe_news_restore` für den [Rücksicherungs-Test](/docs/sicherung#ruecksicherungs-test), mindestens 16 Zeichen. Darf sich ändern – `db-init` setzt es bei jedem Start. Leer: kein Rücksicherungs-Test | von `setup-env.sh` erzeugt |
| `DB_MEM` | Speichergrenze des Datenbank-Containers | `512m` |
| `BACKUP_PASSPHRASE` | Sicherungen verschlüsselt und mit dem Schlüssel, mindestens 12 Zeichen. Besser nur dem [cron](term:cron)-Job mitgeben ([Verschlüsselung](/docs/sicherung#verschluesselung)) | leer: unverschlüsselt, ohne Schlüssel |
| `SQLITE_IMPORT` | `0`: eine alte SQLite-Datei (`data/news.db`, bis Version 0.1.15) beim Start nicht in eine leere Datenbank übernehmen ([Datenbank](#datenbank)) | `1`: Übernahme an |

### Ressourcen und Netze {#env-ressourcen}

| Variable | Bedeutung | Standard |
|---|---|---|
| `APP_MEM` | Speichergrenze des App-Containers | `512m` |
| `EDGE_SUBNET` | Subnetz des Docker-Netzes `edge` zwischen nginx und App – nur ändern, wenn es mit einem eurer Netze kollidiert | `172.31.250.0/24` |
| `EDGE_RANGE` | Bereich darin für dynamische Adressen (die feste Adresse des Proxys liegt außerhalb) | `172.31.250.128/25` |
| `PROXY_IP` | feste Adresse des mitgelieferten nginx im Netz `edge`; nur von ihr (und aus `TRUSTED_PROXIES`) übernimmt die App die Client-Adresse. Muss in `EDGE_SUBNET` und außerhalb von `EDGE_RANGE` liegen | `172.31.250.10` |
| `MAX_BODY_BYTES` | größte Anfrage, die die App selbst annimmt, in Bytes (16 KiB bis 64 MiB) – hinter nginx, das schon bei 1 MB ablehnt; größere bekommen `413` (`body_too_large`). Nur nötig für einen eigenen Proxy, der mehr durchlässt; kein Endpunkt braucht mehr | `1048576` (1 MiB) |

Fest in `docker-compose.yml` und nicht über die `.env` einstellbar: `TLS_PATH`, `POSTGRES_HOST` und `POSTGRES_USER` der
App. Weitere Variablen, die der Code kennt (z. B. `BACKUP_DIR`, `DATABASE_URL`), reicht `docker-compose.yml` nicht an
den Container weiter – in der `.env` wirken sie nicht.

## Start und Stopp {#start-stopp}

Cobe News besteht aus vier Containern:

| Container | Aufgabe | Port |
|---|---|---|
| `cobe-news-proxy` | nginx: HTTPS, leitet an die App weiter | `PORT` (8095), https |
| `cobe-news-app` | Oberfläche, API und Hintergrundaufgaben (Abrufe, Benachrichtigungen, Zertifikat, Verzeichnisabgleich) | `127.0.0.1:8096`, http, nur Health-Check |
| `cobe-news-db` | PostgreSQL 18 mit allen Daten | keiner (internes Netz) |
| `cobe-news-db-init` | läuft bei jedem Start kurz vor der App und richtet deren Datenbank-Rolle ein | keiner |

### Erster Start {#erster-start}

```bash
cd /opt/cobe-news
scripts/setup-env.sh
docker compose up -d --build
docker compose logs app | grep -A1 "Setup token"
```

1. Das Repository nach `/opt/cobe-news` holen und hineinwechseln.
2. `scripts/setup-env.sh` ausführen. Es legt die `.env` an und erzeugt die beiden Datenbank-Passwörter. Ein zweiter
   Aufruf schadet nicht – er ändert nichts, was schon gesetzt ist.
3. Die `.env` anpassen, falls nötig. `BIND` bleibt zunächst auf `127.0.0.1`.
4. Mit `docker compose up -d --build` bauen und starten.
5. Das **Setup-Token** aus dem Log kopieren (letzte Zeile oben). Es gilt 60 Minuten und nur einmal. Bis das Setup
   abgeschlossen ist, schreibt jeder Neustart ein neues ins Log; von Hand gibt es eines mit
   `docker compose exec app python -m app.cli new-setup-token`.
6. `https://localhost:8095` auf dem Server öffnen. Ohne Browser auf dem Server: einen SSH-Tunnel nutzen, z. B.
   `ssh -L 8095:127.0.0.1:8095 admin@news.corp.example`, dann `https://localhost:8095` auf dem eigenen Rechner.
7. Der Browser warnt vor dem selbstsignierten Zertifikat – das ist beim ersten Start normal ([HTTPS](#https)).
8. Der Assistent fragt nach dem Token, legt das erste Konto an (Passwort mindestens 12 Zeichen) und richtet
   [TOTP](term:totp) ein. Dieses Konto ist der [Notfall-Admin](/docs/anmeldung#notfall-admin).

Erst danach die Adresse für Kollegen öffnen ([Adresse für Kollegen](#adresse)).

### Starten, stoppen, Zustand {#starten-stoppen}

| Befehl | Wirkung |
|---|---|
| `docker compose up -d` | starten bzw. Änderungen an der `.env` übernehmen |
| `docker compose up -d --build` | neu bauen und starten (nach einem Update) |
| `docker compose stop` | anhalten, Container bleiben stehen |
| `docker compose start` | angehaltene Container wieder starten |
| `docker compose restart app` | nur die App neu starten (übernimmt **keine** Änderungen an der `.env`) |
| `docker compose down` | anhalten und Container entfernen – die Daten bleiben |
| `docker compose ps -a` | Zustand aller Container |

Alle Befehle im Installationsordner ausführen (`cd /opt/cobe-news`). Die Container starten nach einem Neustart des
Servers von selbst wieder, solange sie nicht von Hand angehalten wurden.

In `docker compose ps -a` steht die App als `healthy`, wenn sie läuft und die Datenbank erreicht. `cobe-news-db-init`
steht als beendet mit `Exited (0)` da – das ist richtig, er läuft nur kurz beim Start.

> [!WARNING]
> `docker compose down -v` löscht auch die Volumes – also die ganze Datenbank und das Zertifikat. Nur verwenden, wenn
> ihr wirklich von vorn beginnen wollt, und nur mit einer [Sicherung](/docs/sicherung#jetzt-sichern).

### Wo die Daten liegen {#daten-ablage}

| Ort | Inhalt |
|---|---|
| Volume `cobe-news_db18` | die Datenbank: Meldungen, Quellen, Benutzer, Sitzungen, Kanäle, Regeln, Vendor News, Einstellungen |
| `./data/secret.key` | Schlüssel für gespeicherte Geheimnisse (wenn `SECRET_KEY` leer ist) |
| `./data/backups/` | die Sicherungen ([Sicherung](/docs/sicherung#ueberblick)) |
| `./data/vendor_catalog.json` | der zuletzt neu gebaute Vendor-News-Katalog |
| Volume `cobe-news_tls` | das selbstsignierte Zertifikat (bei `TLS_MODE=own` stattdessen der Ordner aus `TLS_SOURCE`) |
| `.env` | die Einstellungen dieser Installation mit den Datenbank-Passwörtern |

`./data` und alle Dateien darin kann nur der Prozess der App lesen.

### Mit Portainer {#portainer}

Wer Docker mit Portainer verwaltet, braucht keinen Checkout: Die Datei `docker-compose.portainer.yml` aus dem
Repository kommt als Ganzes in Portainers Web-Editor (*Stacks → Add stack → Web editor*), die Werte der `.env` als
*Environment variables* des Stacks – Pflicht sind `POSTGRES_PASSWORD` und `POSTGRES_APP_PASSWORD`. Sie nimmt das
veröffentlichte Image ab Version 0.1.48 und ist genauso gehärtet wie die normale Installation. Die Container heißen
nach dem Stack (z. B. `news-app-1`), die Daten liegen in benannten Volumes (`news_data`, `news_db18`, `news_tls`). Ein
Update: `COBE_NEWS_IMAGE` auf die neue Version setzen und *Update the stack*. Sicherung, Rücksicherungs-Test und
Wiederherstellung laufen dort mit `docker exec` bzw. einem Wegwerf-Container statt mit `docker compose` – alle
Schritte, Variablen und Grenzen: docs/BETRIEB.md, Abschnitt „Portainer (Stack-Editor)“.

## Update {#update}

Cobe News wird mit Git und Docker Compose aktualisiert. Die Datenbank bringt die App beim Start selbst auf den Stand
der neuen Version (Migrationen) – dafür ist nichts von Hand zu tun.

### Update in Schritten {#update-schritte}

1. **Sicherung anlegen** – in *Einstellungen → Sicherung & Export* mit „Jetzt sichern“ oder per Befehl (unten). Ist die
   Passphrase nicht in der `.env`, sie wie beim [cron-Job](/docs/sicherung#cron) mitgeben.
2. **Das laufende Image behalten** – damit gibt es einen schnellen Weg zurück.
3. **Neue Version holen** und in `CHANGELOG.md` die Abschnitte „Betrieb“ der neuen Versionen lesen: dort steht, was
   beim Update zu beachten ist.
4. **`scripts/setup-env.sh`** erneut ausführen. Es ergänzt Werte, die eine neue Version braucht, und lässt alles
   Bestehende unverändert.
5. **Bauen und starten.**
6. **Prüfen**: Zustand der Container, Log der App, und im Benutzermenü unter *Version & Changelog* die neue Nummer.

```bash
cd /opt/cobe-news
docker compose exec -T app python -m app.cli backup
docker tag cobe-news:latest cobe-news:before-update
git pull
scripts/setup-env.sh
docker compose up -d --build
docker compose ps -a
docker compose logs --tail 50 app
```

Die erste Zeile nach dem Start nennt Version und Adresse: `Cobe News 0.1.x – data in /data, https://…`. Kommt die
App nicht hoch, steht der Grund im Log von `app` oder `db-init` ([Logs](#logs)).

### Update-Hinweis {#update-hinweis}

Admins sehen oben in der Leiste einen kleinen Hinweis, sobald eine neuere Version veröffentlicht ist: **„Version
0.1.48 verfügbar – Changelog“**. Der Link öffnet die Release-Seite auf GitHub; das **×** schließt den Hinweis für dich
und diese Version – erscheint eine noch neuere, kommt er wieder. Leser sehen nichts.

- **Woher:** die öffentliche Release-Schnittstelle von GitHub (`api.github.com/repos/G0urmetD/Cobe-News/releases/latest`),
  ohne Anmeldung, höchstens alle 12 Stunden – auch nach einem Fehler –, bedingt (`ETag`: unverändert zählt nicht gegen
  GitHubs Grenze von 60 Anfragen pro Stunde), mit kurzer Wartezeit und Größenlimit, über dieselbe Härtung wie jeder
  Abruf. Gesendet wird nur die Anfrage selbst mit der Kennung `Cobe/<Version>` – nichts über eure Installation.
- **Was zählt:** nur eine fertige Version `x.y.z`, die höher ist als die laufende. Entwürfe, Vorabversionen
  (`0.1.48-rc1`) und andere Tags werden übergangen.
- **Abschalten:** im Benutzermenü *Version & Changelog*, Schalter **„Nach neuen Versionen suchen“** (ab Werk an). Aus:
  keine Anfrage, kein Hinweis. Dort stehen auch die neueste bekannte Version, wann zuletzt geprüft wurde und ein Fehler.
- **Überwachung:** `/metrics` meldet `cobe_news_update_available` ([Metriken](/docs/api#metriken)).

Der Hinweis ersetzt das Update nicht – das bleibt ein Schritt von euch ([Update in Schritten](#update-schritte)).

### Zurück zur alten Version {#update-zurueck}

```bash
cd /opt/cobe-news
git log --oneline
git checkout <commit-der-alten-version>
docker tag cobe-news:before-update cobe-news:latest
docker compose up -d --no-build
```

1. Im Git-Verlauf den Stand der alten Version suchen: `git log --oneline` zeigt jede Version als „Version 0.1.x: …“.
2. Diesen Stand auschecken, das behaltene Image zurück auf `latest` setzen und ohne Neubau starten (Befehle oben).
3. Hat das Update die Datenbank migriert, passt die alte Version nicht zum neuen Schema. Dann die Sicherung aus
   Schritt 1 mit der alten Version zurückspielen: App anhalten, wiederherstellen, App starten
   ([Wiederherstellung](/docs/sicherung#wiederherstellung)).
4. Später wieder vorwärts: `git checkout main`, dann wie oben.

## HTTPS und Zertifikat {#https}

Cobe News läuft immer über HTTPS. Welches Zertifikat der mitgelieferte nginx ausliefert, legt `TLS_MODE` in der
`.env` fest. Den Zustand zeigt *Einstellungen → HTTPS & Zertifikat*: Modus, „Gültig bis“, „Gilt für“ (die Namen im
Zertifikat), Aussteller, Fingerabdruck (SHA-256) und ob HSTS gesendet wird. Probleme stehen dort als Hinweis, z. B.
wenn das Zertifikat nicht für den Namen aus `BASE_URL` gilt oder bald abläuft.

nginx bemerkt neue Zertifikatsdateien innerhalb einer Minute und lädt sie ohne Unterbrechung. Eine kaputte Datei lädt er
nicht – das laufende Zertifikat bleibt.

### Selbstsigniert (Standard) {#tls-selbstsigniert}

Mit `TLS_MODE=selfsigned` erstellt die App beim Start ein Zertifikat (180 Tage gültig) für `NEWS_HOSTNAME`, den Namen
aus `BASE_URL`, `localhost`, `127.0.0.1` und die Einträge aus `TLS_NAMES`. Sie erneuert es 30 Tage vor Ablauf von
selbst und sofort, wenn sich die Namen ändern. Ein Zertifikat, das sie nicht selbst erstellt hat, überschreibt sie nie.

Browser warnen vor diesem Zertifikat, bis der Computer ihm vertraut. Desktop-Benachrichtigungen bei geschlossenem Tab
gehen erst dann ([Desktop](/docs/benachrichtigungen#desktop)).

### Selbstsigniertes Zertifikat verteilen {#zertifikat-verteilen}

1. *Einstellungen → HTTPS & Zertifikat* öffnen und „Zertifikat herunterladen“ wählen. Die Datei enthält nur den
   öffentlichen Teil.
2. Das Zertifikat auf den Computern als vertrauenswürdig hinterlegen – im Unternehmen am einfachsten per
   Gruppenrichtlinie unter „Vertrauenswürdige Stammzertifizierungsstellen“.
3. **Nach jeder Erneuerung wiederholen** – also etwa alle fünf Monate und immer, wenn sich `NEWS_HOSTNAME`,
   `TLS_NAMES` oder `BASE_URL` ändern.

Ohne Verteilung: den Fingerabdruck in der Warnung des Browsers mit dem in den Einstellungen vergleichen, bevor ihr
fortfahrt. Für den Dauerbetrieb ist ein Zertifikat eurer eigenen CA bequemer.

### Eigenes Zertifikat {#eigenes-zertifikat}

Für den Betrieb unter z. B. `news.corp.example` mit einem Zertifikat eurer internen CA:

1. Zertifikat für den FQDN ausstellen lassen (Serverauthentifizierung, der FQDN als Subject Alternative Name, [SAN](term:san); ein
   Wildcard-Zertifikat wie `*.corp.example` geht auch).
2. Die Dateien in `deploy/certs/` ablegen (Git ignoriert den Ordner):
   - `cobe.crt` – PEM, zuerst das Serverzertifikat, dahinter die Zwischenzertifikate (nicht die Root)
   - `cobe.key` – PEM, ohne Passwort, nur für den Besitzer lesbar: `chmod 600 deploy/certs/cobe.key`
3. In der `.env` die Werte aus dem Beispiel unten setzen.
4. `docker compose up -d`.

```
TLS_MODE=own
TLS_SOURCE=./deploy/certs
NEWS_HOSTNAME=news.corp.example
BASE_URL=https://news.corp.example:8095
```

Die App schreibt nie in diesen Ordner. Sie zeigt nur die Restlaufzeit und warnt 30 Tage vor Ablauf. Zum Tausch die
beiden Dateien ersetzen – nginx lädt sie innerhalb einer Minute.

### Aus einer PFX-Datei {#pfx-umwandeln}

Liefert eure CA eine [PFX- bzw. PKCS#12-Datei](term:pfx), wandelt ihr sie so um (das Passwort der PFX wird abgefragt):

```bash
cd /opt/cobe-news
openssl pkcs12 -in news.pfx -clcerts -nokeys -out deploy/certs/cobe.crt
openssl pkcs12 -in news.pfx -cacerts -nokeys >> deploy/certs/cobe.crt
openssl pkcs12 -in news.pfx -nocerts -nodes -out deploy/certs/cobe.key
chmod 600 deploy/certs/cobe.key
```

### HSTS {#hsts}

[HSTS](term:hsts) sagt dem Browser, die Seite ein Jahr lang nur noch über HTTPS zu öffnen und Zertifikatsfehler nicht
mehr übergehen zu lassen.

- Bei `TLS_MODE=own` und `TLS_MODE=external` sendet Cobe News HSTS immer – bei `external` auf jede Anfrage, die über
  HTTPS kam: Der eigene Proxy muss in `TRUSTED_PROXIES` stehen und `X-Forwarded-Proto https` mitschicken (siehe
  [Beispiel](#proxy-nginx-beispiel)). Euer Proxy darf den Header zusätzlich selbst setzen.
- Beim selbstsignierten Zertifikat nicht – sonst könnte niemand mehr „trotzdem fortfahren“. Und nach jeder Erneuerung
  (etwa alle 150 Tage, ein neues Zertifikat) kämen Computer, die dem alten vertraut haben, gar nicht mehr hinein. Erst
  wenn es auf allen Computern vertraut ist und nach jeder Erneuerung neu verteilt wird, `HSTS=1` setzen.
- Nur an einen Hostnamen (z. B. `news.corp.example`), nie an `localhost`, `*.localhost` oder eine IP-Adresse. HSTS gilt
  für einen Host über alle Ports: Ein HSTS für `localhost` würde den Notzugang `http://localhost:8096` ein Jahr lang auf
  https umbiegen, wo dort niemand antwortet. Für IP-Adressen ignorieren Browser HSTS ohnehin.
- Ohne `includeSubDomains` und ohne `preload`: Es betrifft nur den Namen von Cobe News, keine anderen Dienste der Domain.
- Mit HSTS öffnet der Browser auch `http://news.corp.example:8094` (die [Umleitung](#http-umleitung)) gleich per https
  auf demselben Port – dort antwortet nur http. Nutzt die https-Adresse mit Port (Lesezeichen).

### Umleitung von http auf https {#http-umleitung}

Ab Werk gibt es keinen http-Port. Soll `http://…` auf die https-Adresse umleiten, in der `.env`:

```
COMPOSE_FILE=docker-compose.yml:docker-compose.http.yml
HTTP_PORT=8094
```

Dann `docker compose up -d`. Der Port leitet nur weiter, Inhalte liefert er nicht aus. Er lauscht auf derselben
Adresse wie `BIND`.

Auch ohne diesen Port: Wer `http://…` an den https-Port schickt (z. B. `http://news.corp.example:8095`), wird auf
`https://` umgeleitet statt nginx' Fehlerseite „plain HTTP request was sent to HTTPS port“ zu sehen.

### Nur bekannte Namen {#host-namen}

Der mitgelieferte nginx liefert Cobe News nur unter den Namen aus, die zur Installation gehören:

- dem Namen aus `BASE_URL`,
- `NEWS_HOSTNAME` und allen Einträgen aus `TLS_NAMES` (Namen und IP-Adressen),
- `localhost`, `127.0.0.1` und `[::1]` – der Zugang auf dem Server selbst geht immer.

Eine Anfrage mit einem anderen Namen im `Host`-Header – jemand, der Adressbereiche absucht, oder ein fremder DNS-Name,
der auf euren Server zeigt – bekommt keine Seite: über https nur die Zeile „Unbekannter Hostname – in .env BASE_URL
oder TLS_NAMES eintragen.“ (HTTP 421), über http nichts (nginx schließt die Verbindung, Code 444 im Log des Proxys).
Öffnet jemand die Seite über einen weiteren Namen oder eine IP-Adresse, diesen in `TLS_NAMES` eintragen und
`docker compose up -d` – beim selbstsignierten Zertifikat kommt er damit auch ins Zertifikat. Welche Namen gelten,
steht beim Start im Log: `docker compose logs proxy | grep "answering to"`. Ist Cobe News ins Netz geöffnet
(`BIND=0.0.0.0`), `BASE_URL` aber noch `localhost`, steht dort zusätzlich eine Warnung.

> **Beim Update auf 0.1.47:** Frühere Versionen haben auf jeden Namen geantwortet. Öffnet ihr Cobe News über eine
> IP-Adresse oder einen Namen, der nicht in `BASE_URL`, `NEWS_HOSTNAME` oder `TLS_NAMES` steht, zeigt der Browser nach
> dem Update „Unbekannter Hostname“. Vorher die Adresse aus der Adresszeile in `TLS_NAMES` eintragen (oder `BASE_URL`
> richtig setzen), dann `docker compose up -d`. Namen mit Umlauten in der
`xn--`-Schreibweise eintragen; ein Eintrag mit anderen Zeichen als Buchstaben, Ziffern, `.`, `-`, `:`, `[`, `]` (und
`*.` am Anfang) wird übergangen und im Log genannt.

## Eigener Reverse Proxy {#reverse-proxy}

Läuft auf dem Server schon ein nginx, Traefik o. Ä. mit Zertifikat, kann er Cobe News ausliefern. Der mitgelieferte
nginx bleibt dann aus.

### Einstellungen {#proxy-einstellungen}

```
PROXY_ENABLED=0
TLS_MODE=external
BASE_URL=https://news.corp.example
TRUSTED_PROXIES=172.31.250.1/32
```

1. Die Werte oben in die `.env` eintragen.
2. `docker compose up -d`. Der Container `cobe-news-proxy` startet nicht mehr.
3. Euren Proxy auf `http://127.0.0.1:8096` zeigen lassen (`APP_PORT`). Dieser Port ist fest an `127.0.0.1` gebunden –
   der eigene Proxy muss also auf demselben Host laufen.
4. Prüfen, mit welcher Adresse die Anfragen ankommen, und genau diese in `TRUSTED_PROXIES` eintragen ([unten](#trusted-proxies)).

Das Zertifikat pflegt ihr an eurem Proxy. *Einstellungen → HTTPS & Zertifikat* zeigt dann „Externer Reverse Proxy“.

### Beispiel für nginx {#proxy-nginx-beispiel}

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name news.corp.example;
    ssl_certificate     /etc/ssl/news/fullchain.pem;
    ssl_certificate_key /etc/ssl/news/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8096;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Wichtig ist `X-Forwarded-For $remote_addr`: der Proxy setzt die echte Adresse des Clients und **ersetzt** eine, die der
Client selbst mitschickt. Nicht `$proxy_add_x_forwarded_for` verwenden – damit könnte jeder seine Adresse selbst wählen.

### Welche Adresse in TRUSTED_PROXIES? {#trusted-proxies}

Die App glaubt `X-Forwarded-For` nur von Adressen aus `TRUSTED_PROXIES`. Ohne passenden Eintrag sehen alle Anfragen aus,
als kämen sie vom Proxy – dann teilen sich alle Personen eine Adresse für Sperren und Bremsen.

1. Die Seite einmal über den eigenen Proxy öffnen.
2. `docker compose logs --tail 20 app` ausführen. Die Zugriffszeilen beginnen mit der Adresse, von der die Anfrage kam.
   Bei einem Proxy auf demselben Host ist das meist das Gateway des Docker-Netzes `edge`, ab Werk `172.31.250.1`.
3. Genau diese Adresse mit `/32` eintragen und `docker compose up -d`.

Gut zu wissen:

- Die App hängt im Docker-Netz `edge` (`172.31.250.0/24`), nicht im Standard-Netz von Docker. `172.17.0.1` (das
  Gateway des Standard-Netzes) ist deshalb **nicht** die richtige Adresse.
- Läuft euer Proxy selbst als Container im Netz `edge`, gebt ihm dort eine feste Adresse unterhalb von `.128` – also
  außerhalb von `EDGE_RANGE`, z. B. `172.31.250.20` – und tragt genau diese ein: `TRUSTED_PROXIES=172.31.250.20/32`.
  Eine dynamische Adresse kann nach einem Neustart ein anderer Container bekommen. Von außen heißt das Netz
  `cobe-news_edge`; der Proxy erreicht die App dort unter `http://cobe-news-app:8000`.

> [!WARNING]
> Mit dem **mitgelieferten** nginx (`PROXY_ENABLED=1`) nie das Docker-Gateway in `TRUSTED_PROXIES` eintragen. Unter
> Docker Desktop kommen dort alle Clients an – jeder könnte dann seine Adresse per `X-Forwarded-For` selbst wählen und
> Sperren umgehen. Beim eigenen Proxy ist das Gateway nur deshalb in Ordnung, weil der App-Port allein auf dem Server
> selbst (`127.0.0.1`) erreichbar ist.

## Adresse für Kollegen {#adresse}

Ab Werk ist Cobe News nur auf dem Server selbst erreichbar (`BIND=127.0.0.1`). So hängt eine neue Installation nicht
im Netz, bevor sie abgesichert ist.

### Für Kollegen im Netz freigeben {#fuer-kollegen}

Vorher erledigt sein muss:

- der erste Admin ist angelegt (Setup-Token) und hat TOTP eingerichtet,
- ein vertrauenswürdiges Zertifikat ist hinterlegt – ein eigenes oder das selbstsignierte, verteilt auf alle Computer.

Dann:

```
BIND=0.0.0.0
BASE_URL=https://news.corp.example:8095
NEWS_HOSTNAME=news.corp.example
TLS_NAMES=10.0.0.5
```

1. Einen DNS-Eintrag, z. B. `news.corp.example`, auf die Adresse des Servers anlegen.
2. Die Werte oben in die `.env` eintragen. `TLS_NAMES` nur, wenn jemand die Seite auch über die IP-Adresse öffnet –
   dann aber nötig: nginx antwortet nur auf bekannte Namen ([Nur bekannte Namen](#host-namen)).
   Soll in der Adresse kein Port stehen: `PORT=443` und `BASE_URL=https://news.corp.example`.
3. In der Firewall des Servers den Port aus `PORT` (ab Werk 8095, TCP) für das Firmennetz öffnen – mit Umleitung von
   http auch `HTTP_PORT`.
4. `docker compose up -d`.
5. *Einstellungen → HTTPS & Zertifikat* prüfen: kein Hinweis, dass das Zertifikat nicht für den Namen gilt. Beim
   selbstsignierten Zertifikat hat sich mit den Namen das Zertifikat geändert – neu verteilen.
6. Wird Entra ID genutzt: die Umleitungs-URI in der App-Registrierung anpassen ([unten](#was-base-url-steuert)).

### Was BASE_URL steuert {#was-base-url-steuert}

Die aktuelle Adresse dieser Installation: {{base_url}}

| Wo | Wirkung |
|---|---|
| Benachrichtigungen | Links in E-Mail, Teams, Slack, Discord, Telegram und Webhook zeigen auf diese Adresse |
| Entra ID | die [Umleitungs-URI](term:redirecturi) ist `BASE_URL` plus `/api/auth/oidc/callback` |
| Web Push | Kontaktadresse für die Push-Dienste, solange `PUSH_CONTACT` leer ist |
| Selbstsigniertes Zertifikat | der Name aus `BASE_URL` steht immer darin |
| *HTTPS & Zertifikat* | warnt, wenn das Zertifikat nicht für diesen Namen gilt oder die Adresse mit `http://` beginnt |

Die Umleitungs-URI dieser Installation, wie sie in Entra eingetragen sein muss – exakt, ohne Schrägstrich am Ende:

```
{{redirect_uri}}
```

Ändert sich `BASE_URL`, ändert sich die Umleitungs-URI mit. Ohne Anpassung in Entra scheitert die Anmeldung mit
Microsoft ([Umleitungs-URI](/docs/anmeldung#entra-redirect-uri)).

### Docker Desktop (Mac, Windows) {#docker-desktop}

Unter Docker Desktop (und Colima) gehen die echten Client-Adressen schon in Dockers Port-Weiterleitung verloren. Alle
Anfragen kommen vom Docker-Gateway, z. B. `172.31.250.1`.

- **Was ihr seht:** im Log der App und unter *Benutzer & Rollen* („letzte Anmeldung“) steht für alle dieselbe Adresse.
- **Was Cobe News tut:** das Gateway gilt als geteilte Adresse. Es wird nie gesperrt, Fehlversuche darüber werden nur
  gebremst; die Sperren einzelner Konten wirken weiter. Das Limit für Anmeldestarts mit Microsoft gilt dort für alle
  zusammen.
- **Was zu tun ist:** für den Echtbetrieb einen Linux-Server mit Docker nehmen – dort sieht nginx die echten Adressen.
  Ein Gateway, das Cobe News nicht selbst erkennt, in `SHARED_ADDRESSES` eintragen. **Nie** in `TRUSTED_PROXIES`.

Mehr zu Sperren und geteilten Adressen: [Sitzungen](/docs/anmeldung#sitzungen).

## Logs {#logs}

Jeder Container schreibt sein eigenes Log. Docker behält davon je Container bis zu 3 Dateien à 20 MB.

### Logs lesen {#logs-lesen}

```bash
cd /opt/cobe-news
docker compose logs -f app
docker compose logs --since 1h app
docker compose logs db-init
docker compose logs proxy
docker compose logs db
```

| Container | Wann hineinschauen |
|---|---|
| `app` | fast immer: Start (Version, Adresse), Zertifikat (`tls:`), Abrufe (`news:`), Benachrichtigungen (`notify:`, `push:`), Quellen-Gesundheit, Verzeichnisabgleich, Zugriffe (Adresse, Methode, Pfad, Status, Dauer); Warnungen zu Auffälligem: `SECRET_KEY is short` (beim Start), `csrf check failed` (höchstens eine Zeile pro Adresse und Minute), `emergency admin: … failed sign-in checks` (höchstens eine pro Stunde) |
| `db-init` | wenn die App nicht startet – meist ein Problem mit den Datenbank-Passwörtern |
| `proxy` | Zertifikat neu geladen („certificate changed – nginx reloaded“), die Namen, auf die nginx antwortet („answering to …“), oder nginx startet nicht |
| `db` | Fehler der Datenbank selbst, z. B. zu wenig Speicher |

`-f` folgt dem Log fortlaufend (beenden mit Strg+C), `--since 1h` zeigt nur die letzte Stunde, `--tail 100` die letzten
100 Zeilen. Vor dem Weitergeben eines Logs Setup-Tokens und temporäre Passwörter entfernen.

### Health-Check {#health}

Die App beantwortet auf dem Server selbst eine einfache Abfrage, ob sie läuft und die Datenbank erreicht:

```bash
curl -s http://127.0.0.1:8096/api/health
```

Antwort im Normalfall: `{"ok":true,"version":"{{version}}"}`. Docker nutzt dieselbe Abfrage für den Zustand `healthy`
in `docker compose ps`; erst dann startet der Proxy. Diese Abfrage erscheint nicht im Zugriffslog.

Mehr als „läuft“ – Zustand der Quellen, offene Zustellungen, Alter der letzten Sicherung, Ergebnis des
Rücksicherungs-Tests – liefert `/metrics` für Prometheus, mit einem eigenen Token: [Metriken](/docs/api#metriken).

## Befehle auf dem Server {#cli}

Einige Aufgaben gehen nur auf dem Server, mit dem Befehl `python -m app.cli` im Container der App:

```bash
cd /opt/cobe-news
docker compose exec app python -m app.cli reset-emergency
```

Für Skripte und cron `exec -T` verwenden (ohne Terminal). Ohne oder mit unbekanntem Befehl zeigt `app.cli` seine Hilfe.

| Befehl | Wirkung |
|---|---|
| `reset-emergency` | neues temporäres Passwort für den Notfall-Admin; sein TOTP und seine Passkeys werden entfernt, seine Sitzungen enden, eine Sperre wird aufgehoben |
| `new-setup-token` | ein neues Setup-Token – nur solange es noch keinen Notfall-Admin gibt |
| `rotate-vapid` | ein neues Schlüsselpaar für Web Push (z. B. nach einem Leck); die Browser melden sich beim nächsten Besuch selbst neu an |
| `migrate` | das Datenbankschema auf den Stand dieser Version bringen (macht die App bei jedem Start auch selbst) |
| `migrate-sqlite FILE` | eine SQLite-Datei von Version 0.1.15 (`/data/news.db`) in die leere Datenbank übernehmen; die Datei bleibt unverändert |
| `backup` | jetzt eine Sicherung anlegen – mit `BACKUP_PASSPHRASE` verschlüsselt und mit dem Schlüssel |
| `restore FILE` | eine Sicherung zurückspielen, nur mit angehaltener App ([Wiederherstellung](/docs/sicherung#wiederherstellung)); Optionen `--yes`, `--use-backup-key`, `--ignore-key`, `--allow-unsigned` |
| `restore-test` | die neueste Sicherung zur Probe in die Wegwerf-Datenbank einspielen und prüfen – nie in die Datenbank der App ([Rücksicherungs-Test](/docs/sicherung#ruecksicherungs-test)); Exit-Code 0 bestanden, 1 fehlgeschlagen. Vom Host: `scripts/restore-test.sh` |
| `export` | Regeln, Kanäle, Quellen, gefolgte Produkte und Benutzer ohne Geheimnisse; `--format json` oder `csv`, `--out FILE` (ohne: JSON auf die Ausgabe) |

Bei `backup`, `restore` und `restore-test` liest `--passphrase-file F` die Passphrase aus einer Datei statt aus
`BACKUP_PASSPHRASE`; `--passphrase-file -` liest sie von der Standardeingabe (so macht es `scripts/restore-test.sh`).
Pfade wie `FILE` sind Pfade **im Container** – `./data` auf dem Host ist dort `/data`.

Die Wiederherstellung läuft mit angehaltener App in einem eigenen Container:

```bash
cd /opt/cobe-news
docker compose stop app
docker compose run --rm --no-deps app python -m app.cli restore /data/backups/<datei>
docker compose start app
```

## Datenbank {#datenbank}

Alle Daten liegen in PostgreSQL 18 im Container `cobe-news-db`. Er hängt nur im internen Netz mit der App: kein Port
nach außen, keine Verbindung ins Internet. Die Daten liegen im Volume `cobe-news_db18`.

### Rollen und Passwörter {#db-rollen}

| Rolle | Wofür | Passwort |
|---|---|---|
| `cobe_news_app` | die App, Sicherung und Wiederherstellung – Besitzer der Datenbank, aber ohne Superuser-Rechte | `POSTGRES_APP_PASSWORD` |
| `cobe_news_restore` | nur der [Rücksicherungs-Test](/docs/sicherung#ruecksicherungs-test) – Besitzer der Wegwerf-Datenbank `cobe_news_restore_test`, kein Superuser, darf keine Datenbanken oder Rollen anlegen und sich nicht mit der Datenbank der App verbinden | `POSTGRES_RESTORE_PASSWORD` |
| `cobe_news` | Superuser des Containers – nur der kurze Dienst `db-init` nutzt ihn | `POSTGRES_PASSWORD` |

- `POSTGRES_PASSWORD` **nie ändern**: die Datenbank wurde damit angelegt. Ein anderes Passwort in der `.env` sperrt
  `db-init` aus, und die App startet nicht. Dann das alte Passwort zurück in die `.env` setzen.
- `POSTGRES_APP_PASSWORD` darf sich ändern (mindestens 16 Zeichen): `db-init` setzt es bei jedem Start neu.
- `POSTGRES_RESTORE_PASSWORD` ebenso. Ist es gesetzt, legt `db-init` bei jedem Start auch die Rolle `cobe_news_restore`
  und die Wegwerf-Datenbank an bzw. prüft ihre Rechte (Log: `cobe_news_restore ready`).
- Scheitert `db-init`, startet die App nicht – der Grund steht in `docker compose logs db-init`.

Das Schema kommt aus Migrationen und wird bei jedem Start der App auf den Stand ihrer Version gebracht. Die
Speichergrenze des Containers setzt `DB_MEM` (ab Werk `512m`); bei sehr vielen Meldungen und Vendor-News-Daten hilft mehr.

### Ein Blick hinein {#db-zugriff}

```bash
cd /opt/cobe-news
docker compose exec db psql -U cobe_news cobe_news
```

Das öffnet `psql` als Superuser. Nur lesen (z. B. `\dt` für die Tabellen, `\q` zum Beenden) – Änderungen von Hand
umgehen die Prüfungen der App. Für Sicherungen immer die eingebauten nehmen ([Sicherung](/docs/sicherung#ueberblick)),
nicht ein eigenes `pg_dump`. Den Umstieg von älteren Versionen (SQLite bis 0.1.15, Rollen ab 0.1.22) beschreibt die
Betriebs-Referenz des Repositorys (`docs/BETRIEB.md`) im Abschnitt „PostgreSQL“.

## Protokoll {#protokoll}

Unter **Einstellungen → Protokoll** (nur Admins) steht, wer wann was an Cobe News geändert hat: wer (das Konto mit dem
Namen von damals – oder System, Verzeichnis-Sync, Kommandozeile), was, wann, von welcher Adresse und woran. Ein Klick
auf einen Eintrag zeigt die geänderten Felder mit Vorher und Nachher. Filtern lässt sich nach Bereich, Person, Zeitraum
und Freitext (Name, Ziel, Adresse).

Ein Eintrag wird in derselben Transaktion geschrieben wie die Änderung selbst: wird sie abgelehnt (etwa weil ein anderer
Admin zwischendurch gespeichert hat), entsteht auch kein Eintrag. Einträge lassen sich weder bearbeiten noch einzeln
löschen – auch nicht von Admins.

### Was protokolliert wird {#protokoll-inhalt}

- **Konten & Rollen:** Konto angelegt, geändert, gelöscht, ein- und ausgeschaltet, gesperrt und entsperrt, Passwort
  oder TOTP zurückgesetzt, Anmeldesperre aufgehoben, Rolle geändert; das eigene Passwort und TOTP;
  [Passkeys](/docs/anmeldung#passkeys) eingerichtet, umbenannt und entfernt (selbst oder durch einen Admin, mit Name des
  Passkeys und der Zahl der damit beendeten Sitzungen) und ein Passkey, dessen Zähler zurückging (möglicher Klon,
  [Was geprüft wird](/docs/anmeldung#passkeys-pruefung)); beendete Sitzungen – auch unter
  [Meine Sitzungen](/docs/anmeldung#meine-sitzungen) und durch einen Admin, mit Umfang (eine, alle anderen, alle) und
  Anzahl.
- **Anmeldung:** Änderungen an AD/LDAP, Entra ID (auch [MFA-Nachweis](/docs/anmeldung#entra-mfa-nachweis) und
  Authentifizierungskontext), [Zweiter Faktor für alle](/docs/anmeldung#zweiter-faktor-alle) und den
  Sitzungs-Zeitlimits, Gruppenzuordnungen, die Einrichtung,
  Anmeldungen von **Admins** mit der Anmeldeart (Passwort, Passwort und TOTP, AD/LDAP, Passkey, Entra ID, Entra ID und TOTP),
  Kontosperren und Adresssperren nach Fehlversuchen – auch nach abgelehnten Passkey-Anmeldungen –, und wenn die
  Fehlversuche beim [Notfall-Admin](/docs/anmeldung#notfall-admin) das Stunden-Budget überschreiten.
- **API-Tokens:** erstellt und widerrufen (Name, Rechte, Gültigkeit).
- **Kanäle & Regeln, Teams, Quellen & Produkte:** angelegt, geändert, gelöscht; bei Teams auch Gruppen, Mitglieder,
  Produkte, Zuteilung, Wochenrückblick und Abwesenheiten. Bei Kanälen auch ntfy, Gotify und Mattermost (Topic und
  Tokens nur als „geändert“) und jedes [Erneut senden](/docs/benachrichtigungen#erneut-senden) aus dem
  Zustellprotokoll (Kanal, Zustellung, ob es geklappt hat).
- **Versionen und Vorschläge:** [Versionen bestätigt](/docs/vendor-news#versionen-pruefen) – einzeln oder alle eines
  Produkts oder Teams (mit Anzahl), von Admins wie von Lesern im Team des Produkts; Antworten auf
  [Produktvorschläge](/docs/vendor-news#vorschlaege-beantworten): übernommen, abgelehnt, doppelt (mit Produkt und der
  Antwort, gekürzt auf 200 Zeichen).
- **Einstellungen:** Nachrichten, Vendor News (auch das Intervall von „Versionen prüfen“), E-Mail-Versand, Teams,
  Passkeys ein/aus, Sicherung, Rücksicherungs-Test, Protokoll.
- **Sicherung & Export:** Sicherung erstellt, alte Sicherungen entfernt, Sicherung zurückgespielt (Kommandozeile),
  Rücksicherungs-Test gestartet, Export heruntergeladen, Protokoll exportiert.
- **Verzeichnis-Sync:** was AD oder Entra ID am Zugang ändern – Konten aus- oder wieder eingeschaltet, Rollen aus der
  Gruppenzuordnung, ein Team-Abgleich (eine Zusammenfassung pro Lauf).

Nicht einzeln protokolliert werden fehlgeschlagene Anmeldungen – mit Passwort wie mit Passkey: die kann jeder von außen
schicken, und ein ins Namensfeld getipptes Passwort würde sonst im Protokoll landen. Stattdessen steht die Sperre darin,
die sie auslösen ([Fehlversuche und Sperren](/docs/anmeldung#sperren)). Anmeldungen von Lesern stehen nur als „zuletzt
angemeldet“ am Konto. Ebenfalls nicht protokolliert: der Probelauf einer Regel (er ändert nichts), ein neuer
Produktvorschlag eines Lesers (erst die Antwort darauf) und das Lesen des Protokolls selbst – sein Export schon.

### Was nie darin steht {#protokoll-geheimnisse}

Kein geheimer Wert – nur, dass er geändert wurde: Passwörter (lokal, Bind-Passwort, SMTP), das Client-Secret von Entra
ID, Webhook-Adressen (dort steckt das Token im Pfad), Bot-Tokens, ntfy-Topics und -Tokens, Gotify-Tokens,
HMAC-Secrets und Header-Werte, der NVD-API-Schlüssel,
TOTP-Schlüssel, API-Tokens (auch nicht ihr Anfang), die Hashes früherer Passwörter
([Passwort-Regeln](/docs/anmeldung#benutzer-anlegen)) und die Passphrase der Sicherung. Adressen erscheinen nur als
Schema und Host (`https://hooks.example.com/…`), überlange Texte gekürzt. Eine zentrale Prüfung im Server entscheidet
das für jedes Feld; ein Test schlägt fehl, sobald ein neues Feld nach Geheimnis aussieht und nicht geschwärzt würde.

### Aufbewahrung {#protokoll-aufbewahrung}

Ab Werk bleiben Einträge **365 Tage**, einstellbar von 90 bis 3650 Tagen unter **Protokoll → Aufbewahrung**. Ältere
Einträge löscht die App stündlich. Eine kürzere Frist verlangt eine erneute Bestätigung – ältere Einträge gehen dann
mit dem nächsten Aufräumen. Das Protokoll ist Teil jeder [Sicherung](/docs/sicherung#ueberblick); eine zurückgespielte
Sicherung bringt ihr Protokoll mit (Einträge nach ihrem Zeitpunkt fehlen dann), die Wiederherstellung selbst wird
danach als neuer Eintrag festgehalten.

### Export {#protokoll-export}

**CSV exportieren** lädt die Einträge mit den gewählten Filtern herunter (UTF-8, die neuesten zuerst, höchstens
100 000 Zeilen – für Älteres den Zeitraum eingrenzen). Zellen, die mit `=`, `+`, `-` oder `@` beginnen, bekommen ein
Hochkomma davor, damit eine Tabellenkalkulation sie nicht als Formel ausführt. Die Einzelheiten stehen als JSON in der
letzten Spalte. Für Zählungen ohne Namen liefert `/metrics` die Zahl der Einträge pro Bereich
([Metriken](/docs/api#metriken)).
