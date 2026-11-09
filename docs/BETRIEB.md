# Cobe News – Betrieb

Betriebs-Referenz (Deutsch): Installation, Konfiguration, Anmeldung, HTTPS, Quellen, Vendor News, Benachrichtigungen,
PostgreSQL, Sicherung und Entwicklung. Überblick und Schnellstart: [README](../README.md). Befunde von Image-Scannern:
[`SICHERHEIT-SCANS.md`](SICHERHEIT-SCANS.md).

Cobe News sammelt Security-Nachrichten aus öffentlichen RSS-/Atom-Feeds von Presse, Behörden/CERTs, Herstellern (PSIRT)
und Research sowie aus den Katalogen ausgenutzter Schwachstellen (CISA KEV, ENISA EUVD, Microsoft Patchday) – 46
eingebaute Quellen, siehe [Quellen](#quellen) – mit Anmeldung (lokal, Active Directory, Entra ID), HTTPS und
Push-Benachrichtigungen (E-Mail, Teams, Slack, Discord, Telegram, eigener Webhook, Desktop).

- Kacheln mit Quelle, Schwere-Einstufung (Regeln: CVSS-Wert, Einstufung von BSI/Hersteller, „aktiv ausgenutzt“, Ransomware …), CVEs
- Drawer mit Artikeltext (serverseitig bereinigt, keine Bilder), Begründung der Einstufung, Link zum Artikel
- Reiter **Neu / Gelesen** (pro Person), Suche, Mehrfachfilter nach Quelle und Schwere, „Alle als gelesen“
- jede Meldung nur einmal (gleiche URL ohne Tracking-Parameter oder gleicher Titel innerhalb von 3 Tagen; zwischen KEV, EUVD
  und BSI-Warnungen auch dieselbe CVE innerhalb von 30 Tagen)
- **Vendor News**: die eingesetzten Produkte und Versionen (z. B. PAN-OS 11.2.4-h23 und 10.2.13-h5, Panorama 11.2.4-h23)
  – welche Schwachstellen genau diese Versionen betreffen (mit Fix-Version), ob eine neue Version oder das Support-Ende
  kommt, passende News; siehe [Vendor News](#vendor-news)
- Deutsch / Englisch, Hell / Dunkel / Wie System

**Handbuch in der App:** Benutzermenü unten links → *Dokumentation* (`/docs`) – Einrichtung und Bedienung Schritt für
Schritt (Anmeldung mit Entra ID/AD, Kanäle und Webhooks, Regeln, Sicherung, Betrieb, FAQ), Deutsch und Englisch, mit
Suche und Links direkt aus den Einstellungen („Hilfe“). Leser sehen nur ihre Kapitel; die Admin-Kapitel liefert der
Server nur an Admins aus. Die Texte liegen als Markdown in [`docs/handbuch/`](handbuch/README.md) (Format und
Regeln dort) und kommen mit dem Image.

## Start / Stopp

```bash
cd cobe-news
scripts/setup-env.sh             # einmal: .env anlegen, Datenbank-Passwort erzeugen (schadet auch später nicht)
docker compose up -d --build     # bauen und starten (App + PostgreSQL + nginx)
docker compose logs -f app       # Logs der App (dort steht beim ersten Start das Setup-Token)
docker compose down              # stoppen (Daten bleiben im Volume db18 und in ./data, das Zertifikat im Volume tls)
```

Dann **<https://localhost:8095>** öffnen. Beim ersten Aufruf warnt der Browser vor dem selbstsignierten
Zertifikat (siehe [HTTPS](#https)).

| Container | Aufgabe | Port |
|---|---|---|
| `cobe-news-proxy` | nginx 1.30: TLS, leitet an die App weiter (Image `cobe-news-proxy`, aus `deploy/nginx`) | **8095** (https, Host) |
| `cobe-news-app` | FastAPI + Web-UI + Hintergrundjobs (Feeds, Benachrichtigungen, Zertifikat, Verzeichnisabgleich) | `127.0.0.1:8096` (http, nur Health/Notfall) |
| `cobe-news-db` | PostgreSQL 18 – alle Daten; richtet bei jedem Start die Rolle der App ein (Image `cobe-news-db`, aus `deploy/postgres`; siehe [PostgreSQL](#postgresql)) | keiner (internes Netz, nur die App) |

Drei Images, alle drei baut `docker compose up -d --build`; nichts aus `deploy/` wird eingehängt, und es gibt keinen
kurzen Dienst mehr, der beim Start „Exited (0)“ zurücklässt (bis 0.1.48: `cobe-news-db-init`).

**Update** einer lokalen Installation: `git pull`, `scripts/setup-env.sh`, `docker compose up -d --build --remove-orphans`
(Sicherung vorher, Handbuch *Betrieb → Update*). Beim Update von **0.1.48 oder älter** entfernt `--remove-orphans` den
alten Container `cobe-news-db-init` (ohne den Schalter bleibt er als „Exited“ stehen und Compose warnt „Found orphan
containers“ – harmlos, `docker rm cobe-news-db-init` geht auch). Volumes (`cobe-news_db18`, `cobe-news_tls`), `./data`
und das Netz `cobe-news_edge` bleiben, wie sie sind; nichts muss von Hand umgezogen werden. Mit eigenem Reverse Proxy:
steht in der `.env` noch `TRUSTED_PROXIES=172.31.250.1/32` (der falsche Rat bis 0.1.48), diese Zeile **entfernen** (oder
leer setzen) – sonst sieht die App weiter jede Anfrage vom Gateway `172.31.250.128`; das Log warnt beim Start
(`proxy: TRUSTED_PROXIES=… lies in the network edge … but not on its gateway`). Details: [HTTPS](#https), 3.

**Zurück auf 0.1.48**: `docker compose up -d --build` hat `cobe-news:latest` mit der neuen App überschrieben – das alte
Image muss vorher behalten worden sein (`docker tag cobe-news:latest cobe-news:before-update` vor dem Update, Handbuch
*Betrieb → Update*). Dann: `git checkout <Stand von 0.1.48>`, `docker tag cobe-news:before-update cobe-news:latest`,
`docker compose up -d --no-build --remove-orphans` – das legt `db-init` wieder an (Datenbank und Proxy wieder direkt aus
den Basis-Images), dieselben Volumes. Brachte das Update eine Migration mit, vorher die Sicherung mit der alten Version
zurückspielen. Ohne behaltenes Image: `git checkout <Stand von 0.1.48>` und `docker compose up -d --build` baut sie neu.

### Veröffentlichtes Image statt lokalem Build

Standard ist der lokale Build (`docker compose up -d --build`, Images `cobe-news:latest`, `cobe-news-db:latest`,
`cobe-news-proxy:latest`) – daran ändert sich nichts. Wer stattdessen die veröffentlichten, signierten Images einer
Version betreiben will (`ghcr.io/g0urmetd/cobe-news`, `…/cobe-news-db`, `…/cobe-news-proxy`, je `:<version>`, gebaut von
der Release-Pipeline, siehe [Release](#release)), schaltet die Datei `docker-compose.image.yml` zu – in `.env`:

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.image.yml   # mit http-Umleitung: …:docker-compose.http.yml:docker-compose.image.yml
COBE_NEWS_VERSION=0.1.55                                   # eine Version, nicht latest – gilt für alle drei Images
```

Die Datei ersetzt bei `app`, `db` und `proxy` nur das Image (der `build`-Teil fällt weg); alles andere – Volumes, Netze,
`.env` – bleibt, wie es ist. Ohne `COBE_NEWS_VERSION` bricht `docker compose` mit einem Hinweis ab, statt still etwas
anderes zu starten. Einzelne Images lassen sich per Digest festnageln: `COBE_NEWS_IMAGE`, `COBE_NEWS_DB_IMAGE`,
`COBE_NEWS_PROXY_IMAGE` (z. B. `ghcr.io/g0urmetd/cobe-news-db:0.1.55@sha256:<digest>`) gehen `COBE_NEWS_VERSION` vor.
**Bis 0.1.48** nahm die Datei nur `COBE_NEWS_IMAGE` (die App) – wer sie so nutzt, setzt jetzt `COBE_NEWS_VERSION` und
nimmt `COBE_NEWS_IMAGE` heraus (sonst bliebe die App auf der alten Version). Vor dem Start die Signaturen prüfen
(cosign ≥ 2, keyless – die Identität ist der Release-Workflow dieses Repositorys):

```bash
for i in cobe-news cobe-news-db cobe-news-proxy; do
  cosign verify ghcr.io/g0urmetd/$i:0.1.55 \
    --certificate-identity-regexp '^https://github\.com/G0urmetD/Cobe-News/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
done
docker compose pull                     # holt die drei Images (pull_policy: missing – vorhandene werden nicht neu geholt)
docker compose up -d --remove-orphans   # ohne --build
docker compose config --images          # zeigt, welche Images Compose nimmt
```

`cosign verify` gibt den Digest aus, den die Signatur abdeckt; wer ihn übernimmt (`…:0.1.55@sha256:<digest>` in der
jeweiligen Image-Variable), startet genau das geprüfte Image, auch wenn der Tag später anders zeigen sollte. Ein Update:
`COBE_NEWS_VERSION` auf die neue Version setzen, Signaturen prüfen, `docker compose pull && docker compose up -d
--remove-orphans` (die Migrationen laufen beim Start wie beim lokalen Build). Zurück zum lokalen Build: die beiden Zeilen
aus `.env` nehmen und `docker compose up -d --build`.

### Portainer (Stack-Editor)

Ohne Checkout und ohne Dateien auf dem Host: [`docker-compose.portainer.yml`](../docker-compose.portainer.yml) ist eine
eigenständige Compose-Datei (kein Zusatz zu `docker-compose.yml`) für Portainers Web-Editor. Sie startet die drei
veröffentlichten Images der Version, aus der sie stammt (`ghcr.io/g0urmetd/cobe-news`, `-db`, `-proxy`) mit derselben
Härtung wie `docker-compose.yml` – drei Container, die alle laufen bleiben: `app`, `db`, `proxy`. Das Datenbank-Image
richtet bei jedem Start die Rolle der App ein und meldet sich erst danach „healthy“, das Proxy-Image bringt die
nginx-Konfiguration mit; es gibt keinen kurzen Dienst und keine Volumes für Dateien mehr (bis 0.1.48: `assets` und
`db-init`, die Portainer als rot „exited – code 0“ zeigte).

Nur für Portainer-Umgebungen vom Typ **Docker Standalone**, nicht Swarm: `docker stack deploy` übergeht die Bedingungen
von `depends_on`, `security_opt`, `mem_limit`, `scale` und `ipv4_address`.

1. *Stacks → Add stack → Web editor*: den Inhalt von `docker-compose.portainer.yml` einfügen. Stack-Name z. B. `news` –
   **nicht** `cobe-news`, wenn auf demselben Host eine lokale Installation läuft (das ist deren Projektname: der Stack
   nähme ihre Volumes und Netze). Die Container heißen nach dem Stack (`news-app-1`, `news-db-1`, `news-proxy-1`, kein
   `container_name`), die Volumes `news_data`, `news_db18`, `news_tls` – Namen und Volumes von Stack und lokaler
   Installation kommen sich nie in die Quere. Ports und Netz aber schon: die Standardwerte sind dieselben wie die der
   lokalen Installation. Neben ihr daher `PORT`, `APP_PORT`, `EDGE_SUBNET`, `EDGE_RANGE` und `PROXY_IP` auf andere
   Werte setzen (z. B. `8195`, `8196`, `172.31.251.0/24`, `172.31.251.128/25`, `172.31.251.10`) – sonst scheitert das
   Deployment am belegten Port bzw. mit „Pool overlaps“.
2. Unter *Environment variables* (*Advanced mode*: als Text einfügen) **einen** der beiden Blöcke aus dem Kopf der Datei
   eintragen und ausfüllen – Portainer füllt damit die `${…}` der Datei; eine `.env` gibt es nicht:

   **A) hinter dem eigenen Reverse Proxy** auf diesem Host (nginx, Traefik … mit eurem Zertifikat):
   ```
   POSTGRES_PASSWORD=<zufällig – behalten>
   POSTGRES_APP_PASSWORD=<zufällig, mindestens 16 Zeichen>
   BASE_URL=https://news.corp.example
   PROXY_ENABLED=0
   ```
   Der eigene Proxy zeigt auf `http://127.0.0.1:8096` (`APP_PORT`); `PROXY_ENABLED=0` ist der einzige Schalter – kein
   `TLS_MODE`, kein `TRUSTED_PROXIES` ([HTTPS](#https), 3.).

   **B) ohne** – das HTTPS von Cobe News (nginx, selbstsigniertes Zertifikat der App), Port 8095:
   ```
   POSTGRES_PASSWORD=<zufällig – behalten>
   POSTGRES_APP_PASSWORD=<zufällig, mindestens 16 Zeichen>
   BASE_URL=https://news.corp.example:8095
   BIND=0.0.0.0
   ```
   `BIND=0.0.0.0` öffnet den Port ins Netz – weglassen, solange der erste Admin TOTP noch nicht eingerichtet hat
   ([Netz](#netz-nur-lokal-oder-im-lan)); nginx antwortet nur auf die Namen aus `BASE_URL`, `NEWS_HOSTNAME`, `TLS_NAMES`.

   Weitere Variablen nach Bedarf:

   | Variable | Bedeutung |
   |---|---|
   | `POSTGRES_PASSWORD` | **Pflicht** – Superuser der Datenbank (nur der Datenbank-Container kennt ihn). Einmal erzeugen und **behalten**: das Volume wird damit angelegt |
   | `POSTGRES_APP_PASSWORD` | **Pflicht** – die Rolle der App `cobe_news_app`, mindestens 16 Zeichen; darf sich ändern (*Update the stack*) |
   | `POSTGRES_RESTORE_PASSWORD` | empfohlen – Rolle des [Rücksicherungs-Tests](#rücksicherungs-test); leer: kein Test |
   | `COBE_NEWS_VERSION` | die Version aller drei Images; Standard: die Version, aus der die Datei stammt |
   | `COBE_NEWS_IMAGE`, `COBE_NEWS_DB_IMAGE`, `COBE_NEWS_PROXY_IMAGE` | ein Image einzeln, z. B. per Digest (`…@sha256:<digest>`) – gehen `COBE_NEWS_VERSION` vor; sonst leer lassen |
   | `BASE_URL`, `NEWS_HOSTNAME`, `TLS_NAMES` | Adresse und Namen wie in der `.env` ([HTTPS](#https), Host-Namen) |
   | `BIND`, `PORT` | Standard `127.0.0.1` und `8095` (nur Variante B) – auf einem Server meist `BIND=0.0.0.0`, dann `BASE_URL` auf den Namen, den die Browser benutzen (sonst warnt der Proxy im Log und antwortet mit 421) |
   | `APP_PORT` | http-Port der App, fest an `127.0.0.1` (Health-Check, Notzugang, Ziel des eigenen Proxys), Standard `8096` – neben einer lokalen Installation ändern |
   | `SECRET_KEY` | leer: Schlüsseldatei `secret.key` im Volume `data`; besser setzen und getrennt aufbewahren ([Daten](#daten)) |
   | `BACKUP_PASSPHRASE` | Sicherungen verschlüsselt – hier für jeden sichtbar, der den Stack bearbeiten darf: besser die Datei (nächste Zeilen) oder nur dem cron-Job mitgeben (unten) |
   | `BACKUP_SECRET_DIR`, `BACKUP_PASSPHRASE_FILE` | die Passphrase aus einer Datei: ein **absoluter** Ordner auf dem Host (lesbar für UID 10001), eingehängt unter `/run/backup-secret`, und der Pfad der Datei darin, z. B. `/run/backup-secret/backup-pass` – dann ist auch „Jetzt sichern“ verschlüsselt ([Sicherung](#sicherung-wiederherstellung-export)). Leer: ein leeres eigenes Volume `backup-secret`, keine Datei |
   | `EDGE_SUBNET`, `EDGE_RANGE`, `PROXY_IP` | Standard `172.31.250.0/24`, `172.31.250.128/25`, `172.31.250.10` – neben einer lokalen Installation (oder einem zweiten Stack) ändern |

   Passwörter nur aus Buchstaben und Ziffern (nichts zu quoten), z. B. `openssl rand -hex 24`. Ohne die beiden
   Pflicht-Passwörter bricht das Deployment mit einer Meldung ab. Alle anderen Variablen aus `.env.example` wirken
   genauso. Portainer zeigt die Werte jedem, der den Stack bearbeiten darf.
3. *Deploy the stack*. Danach laufen drei Container, alle grün: `db` „healthy“ (erst nach der Rolle der App), `app`
   „healthy“, `proxy` „running“ (mit `PROXY_ENABLED=0` gibt es ihn nicht). Das Setup-Token steht im Log von
   `news-app-1` (Portainer: Container → Logs, oder `docker logs news-app-1 2>&1 | grep -A1 "Setup token"`); weiter wie
   beim [ersten Start](#erster-start-setup-token-und-notfall-admin). Die Rolle: Log von `news-db-1`, Zeilen `db-init: …`.
   Welche Namen nginx bedient: Log von `news-proxy-1`, Zeile `answering to …`. Wem die App die Client-Adresse glaubt:
   Log von `news-app-1`, Zeile `proxy: …`. Der Text der 421-Seite nennt `.env` – hier sind das die Environment
   variables des Stacks.

**Update:** Signaturen der neuen Version prüfen ([cosign](#veröffentlichtes-image-statt-lokalem-build)), die neue
`docker-compose.portainer.yml` in den Editor einfügen (oder nur `COBE_NEWS_VERSION` auf die neue Version setzen, wenn
sich die Datei nicht geändert hat), *Update the stack* mit *Re-pull image*. Die Migrationen laufen beim Start der App.
Zurück: die alte Version eintragen und wieder *Update the stack* (brachte das Update eine Migration mit, vorher die
Sicherung zurückspielen).

**Update von der Datei aus 0.1.48** (mit `assets` und `db-init`): die neue Datei einfügen, in den Environment variables
`COBE_NEWS_IMAGE` **löschen** (sonst bliebe die App auf 0.1.48 – die Version kommt jetzt aus `COBE_NEWS_VERSION` bzw. der
Datei), *Update the stack* – mit **Prune services**, wo Portainer den Schalter anbietet (entfernt die beiden beendeten
Container `assets` und `db-init`); sonst bleiben sie als „exited“ stehen und lassen sich unter *Containers* löschen.
Mit eigenem Reverse Proxy: `TRUSTED_PROXIES=172.31.250.1/32` (der falsche Rat bis 0.1.48) **entfernen** oder leer setzen –
sonst bleibt jede Anfrage beim Gateway `….128` (das Log der App warnt); ein gesetztes `TRUSTED_PROXIES=<Gateway>/32` darf
heraus, `PROXY_ENABLED=0` genügt ([HTTPS](#https), 3.); `TLS_MODE=external` behalten, wer HSTS will. **Die Images ab
0.1.49 brauchen die Stack-Datei ab 0.1.49**: nur `COBE_NEWS_IMAGE` auf 0.1.49 zu stellen und die alte Datei zu behalten,
scheitert – deren Dienst `assets` sucht `/srv/deploy` im App-Image und meldet irreführend „COBE_NEWS_IMAGE must be Cobe
News 0.1.48 or newer“. Die Volumes `news_data`, `news_db18`, `news_tls` und das Netz bleiben; die Volumes
`news_deploy-postgres` und `news_deploy-nginx` braucht nichts mehr (nur kopierte Dateien, keine Daten) – unter
*Volumes* löschen.

**Eigener Reverse Proxy** als Container statt auf dem Host ([HTTPS](#https), 3.): die Namen dort heißen hier nach dem
Stack – das Netz `news_edge` statt `cobe-news_edge`, das Ziel `http://news-app-1:8000` statt `http://cobe-news-app:8000`.

**Eigenes Zertifikat** (`TLS_MODE=own`): `TLS_SOURCE` auf einen **absoluten** Ordner auf dem Host setzen, z. B.
`/opt/cobe-news/certs` mit `cobe.crt` und `cobe.key` ([HTTPS](#https)) – relative Pfade gibt es im Web-Editor nicht, ein
anderes benanntes Volume als `tls` ebenso wenig (die Datei kennt nur ihre eigenen).

**Sicherung:** „Jetzt sichern“ in der Oberfläche wie immer; die Dateien liegen im Volume `news_data` unter `backups/`.
Die Befehle oben (`docker compose exec … app`) brauchen den Checkout – mit Portainer dasselbe direkt am Container, z. B.
per cron auf dem Host; die Passphrase über die Standardeingabe (`--passphrase-file -`), nie als `-e` auf der
Befehlszeile (dort sieht sie jeder in `ps`):

```
30 2 * * * root docker exec -i news-app-1 python -m app.cli backup --passphrase-file - < /root/.cobe-news-backup-pass >>/var/log/cobe-news-backup.log 2>&1 && mkdir -p /srv/cobe-news-backups && docker exec news-app-1 tar -C /data/backups -cf - --exclude='./.*' --exclude='*.partial' . | tar -C /srv/cobe-news-backups -xf -
```

Das `tar` lässt wie das `rsync` oben Halbfertiges und versteckte Dateien weg; `docker cp news-app-1:/data/backups/. …`
geht auch, kopiert aber alles (ohne solche Ausnahmen).

Rücksicherungs-Test vom Host (statt `scripts/restore-test.sh`):
`docker exec -i news-app-1 python -m app.cli restore-test --passphrase-file - < /root/.cobe-news-backup-pass`.
Wiederherstellen: die App anhalten und die Wiederherstellung in einem Wegwerf-Container mit demselben Image, dem
Datenbank-Netz und dem Volume `data` laufen lassen – das Passwort der App aus der Shell, nicht von der Befehlszeile (mit
`SECRET_KEY` im Stack ebenso `-e SECRET_KEY`):

```bash
IMG=$(docker inspect -f '{{.Config.Image}}' news-app-1)   # genau das Image des Stacks
docker stop news-app-1
read -rs POSTGRES_PASSWORD; export POSTGRES_PASSWORD      # der Wert von POSTGRES_APP_PASSWORD
docker run --rm -it --network news_db -v news_data:/data --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true -e POSTGRES_HOST=db -e POSTGRES_USER=cobe_news_app -e POSTGRES_PASSWORD \
  "$IMG" python -m app.cli restore /data/backups/cobe-news-<Zeit>.tar   # .tar.enc: -e BACKUP_PASSPHRASE
docker start news-app-1
```

Eine Sicherung von einem anderen System zurück ins Volume (z. B. auf einem neuen Server, als Benutzer der App):
`docker exec -i news-app-1 sh -c 'umask 077; mkdir -p /data/backups && cat > /data/backups/<Datei>' < <Datei>`. Bei einer
`.tar.enc` auf einem neuen Server `--use-backup-key` an den `restore` hängen; bei einer `.tar` vorher (App angehalten) den
aufbewahrten Schlüssel ins Volume schreiben – geprüft (nicht leer, mindestens 16 Byte), erst als neue Datei, dann
ausgetauscht, der bisherige bleibt als `secret.key.before-restore-<Zeit>` (nichts wird überschrieben, auch nicht bei einem
zweiten Lauf):

```bash
test -s cobe-news-secret.key && docker run --rm -i -v news_data:/data --network none "$IMG" sh -ec '
  umask 077; cat > /data/secret.key.new
  [ "$(wc -c < /data/secret.key.new)" -ge 16 ] || { rm -f /data/secret.key.new; echo "key empty or cut off - nothing changed" >&2; exit 1; }
  [ ! -e /data/secret.key ] || cp -p /data/secret.key "/data/secret.key.before-restore-$(date -u +%Y%m%d-%H%M%S)"
  mv /data/secret.key.new /data/secret.key' < cobe-news-secret.key
```

Alles Schritt für
Schritt (sichern, herunterladen, einspielen, was man dafür braucht): Handbuch *Sicherung → Schritt für Schritt*.

Eine Datei ins Volume `data` (z. B. für `CA_FILE=/data/ca.pem`): `docker cp ca.pem news-app-1:/data/ca.pem`.

**Grenzen:** Die Zusatzdateien (`docker-compose.http.yml`, `docker-compose.image.yml`) gibt es hier nicht – die
http-Umleitung: beim Dienst `proxy` unter `ports` die Zeile `- "${BIND:-127.0.0.1}:${HTTP_PORT:-8094}:80"` ergänzen.
`scripts/setup-env.sh` und `scripts/restore-test.sh` brauchen den Checkout (Ersatz oben). Änderungen an den Variablen
immer mit *Update the stack* übernehmen – ein bloßer Neustart der Container behält die alten Werte. Die Images
`cobe-news-db` und `cobe-news-proxy` gibt es ab 0.1.49; ältere Versionen lassen sich mit dieser Datei nicht starten
(dafür die Datei jener Version nehmen).

## Erster Start: Setup-Token und Notfall-Admin

Beim ersten Start schreibt die App ein **einmaliges Setup-Token** ins Log (60 Minuten gültig, bei jedem Neustart bis
zum Abschluss ein neues):

```bash
docker compose logs app | grep -A1 "Setup token"
```

Im Browser führt ein Assistent in drei Schritten: Token eingeben, Benutzername,
Anzeigename und Passwort (mind. 12 Zeichen, kein bekanntes Passwort) wählen, danach die Authenticator-App (TOTP)
einrichten. Ein falsches Token führt zurück zum ersten Schritt; geprüft und verbraucht wird es erst beim Anlegen – in
derselben Transaktion, die das Konto und seine Sitzung anlegt: Scheitert dabei etwas, bleibt das Token gültig (statt eines
„abgeschlossenen“ Setups ohne Admin). Ist das Setup als erledigt markiert, aber kein Notfall-Admin da (eine ältere
Version konnte auf halbem Weg stehen bleiben), gibt es beim nächsten Start bzw. mit
`docker compose exec app python -m app.cli new-setup-token` wieder ein Token. Dieses erste Konto ist der **Notfall-Admin**:

- lokal, nie vom Verzeichnisabgleich betroffen, kann von keinem anderen Admin deaktiviert, herabgestuft oder gelöscht werden,
- wird durch Fehlversuche nie gesperrt, und sein **richtiges** Passwort (mit TOTP) wird auch von einer geblockten Adresse
  angenommen – hinter NAT oder dem Docker-Gateway teilen sich oft alle Clients eine Adresse; Fehlversuche warten und zählen trotzdem.
  Dafür eine Bremse: nach 20 Fehlversuchen in einer Stunde (von irgendwo) wartet jede Prüfung des Notfall-Admins
  – auch die richtige – erst 3 Sekunden, und es läuft nur eine gleichzeitig, über alle Adressen (parallele Versuche
  bekommen sofort „zu viele Versuche“). Raten von vielen Adressen aus schafft so höchstens einen Versuch alle paar Sekunden, der Besitzer kommt (etwas
  langsamer) immer hinein,
- meldet sich, wenn jemand rät: Überschreiten die Fehlversuche das Budget, schreibt die App eine Warnung ins Log
  (`emergency admin: N failed sign-in checks in the last hour …`, mit der letzten Adresse bzw. ihrem /64), einen
  Protokolleintrag `login.emergency_slowed` und zeigt 24 Stunden lang einen Hinweis unter *Einstellungen → HTTPS &
  Zertifikat* – höchstens einmal pro Stunde (wer weiter rät, flutet weder Log noch Protokoll),
- Passwort/TOTP verloren: auf dem Server zurücksetzen –
  `docker compose exec app python -m app.cli reset-emergency` (gibt ein temporäres Passwort aus, TOTP wird neu eingerichtet;
  das Passwort gilt wie jedes temporäre 7 Tage, siehe [Lokale Konten](#lokale-konten)).

Zugangsdaten des Notfall-Admins offline aufbewahren (Passwort-Tresor).

## Anmeldung und Rollen

Zwei Rollen:

| Rolle | darf |
|---|---|
| **admin** | alles: News-Einstellungen und Quellen, Benachrichtigungskanäle und -regeln, SMTP, Benutzer, Anmeldung (AD/Entra/Zuordnungen), HTTPS-Status |
| **reader** | News lesen, gelesen/ungelesen markieren, eigene Desktop-Benachrichtigungen, eigenes Passwort/TOTP |

Sitzungen liegen serverseitig in der Datenbank (Cookie HttpOnly, Secure, SameSite=Lax); Leerlauf-Timeout 60 Minuten,
absolutes Timeout 12 Stunden (änderbar unter *Einstellungen → Anmeldung*, Karte *Sitzungen*). Schreibende Aufrufe brauchen
ein CSRF-Token (Double Submit). Fehlversuche: 5 pro Konto in 15 Minuten sperren das Konto 15 Minuten (bei Wiederholung
länger; AD-Konten zählen pro Konto, egal ob als Name, UPN oder in anderer Schreibweise getippt). Jeder Fehlversuch
verzögert die nächste Prüfung (pro Konto und pro Adresse + Name). Eine **Adresse** wird erst geblockt (30 Minuten), wenn
von ihr 30 Fehlversuche über mindestens 5 verschiedene Namen kommen (Password Spraying) – Tippfehler einer Person
sperren nur deren Konto, nie alle, die sich eine Adresse teilen. Die Adresse kommt nur vom mitgelieferten nginx
(`X-Forwarded-For` von anderen wird ignoriert); läuft ein eigener Proxy davor, muss er die echte Client-Adresse
weitergeben, sonst teilen sich alle die Adresse des Proxys. Eine **geteilte Adresse** – das Docker-Gateway (unter
Docker Desktop kommen alle von dort, siehe [Netz](#netz-nur-lokal-oder-im-lan)), der Proxy selbst oder eine Adresse aus
`SHARED_ADDRESSES` (z. B. das NAT eines Büros, kommagetrennt, auch Netze) – wird nie geblockt: Spraying über sie wird
stattdessen gebremst (3 Sekunden je Fehlversuch), die einzelnen Konten sperren wie immer. Fehlversuche zählen je
Herkunft getrennt: ein lokales Konto unter seinem Namen, ein AD-/Entra-Konto unter seiner Verzeichnis-ID – eine
abgelehnte AD-Anmeldung sperrt nie das gleichnamige lokale Konto. AD-Sperren sieht und löst ein Admin wie jede andere
(*Benutzer & Rollen*, „Entsperren“); ein gesperrtes AD-Konto wird gar nicht erst am Domänencontroller geprüft.
Laufende Konto-Sperren und Adress-Sperren überstehen einen Neustart (Tabelle `auth_locks`); die Zähler bis dahin nicht.
Optional **„Zweiter Faktor für alle Pflicht“** (aus ab Werk): dann richten auch Leser bei der nächsten Anmeldung TOTP
(lokal wahlweise einen Passkey) ein. Ein neues Passwort darf keines der letzten fünf sein (nur lokale Konten).
Sitzungs- und CSRF-Cookie heißen mit HTTPS `__Host-cobe_news_session` / `__Host-cobe_news_csrf` (nur diese Origin, nur
über HTTPS – keine Subdomain und keine http-Seite kann sie setzen). Ein kürzeres absolutes Timeout gilt sofort auch für
laufende Sitzungen. Zweiten Faktor ersetzen oder entfernen verlangt den aktuellen Code (ohne TOTP: das Passwort).
Ein schreibender Aufruf ohne oder mit falschem CSRF-Token wird mit 403 `csrf_failed` abgelehnt und als Warnung geloggt
(`cobe_news.security: csrf check failed: <Methode> <Pfad> from <Adresse bzw. /64> (<was fehlte>)` – nie Token oder
Cookie); höchstens eine Zeile pro Herkunft und Minute und 30 pro Minute insgesamt, die zurückgehaltenen zählt die
nächste Zeile mit. Kein Protokolleintrag (niemand angemeldet, keine Aktion an etwas).

**Erneut bestätigen** – heikle Änderungen verlangen, dass sich der Admin in den letzten 10 Minuten ausgewiesen hat (die
Anmeldung selbst zählt): Anmelde-Einstellungen (AD, Entra, Sitzungen), Rollen-Zuordnungen, einen Admin anlegen, eine
Rolle ändern, Passwort/TOTP eines anderen zurücksetzen, ein Konto löschen. Sonst fragt ein Dialog nach dem Passwort und
dem aktuellen TOTP-Code (AD-Konten: AD-Passwort + Code) und führt die Änderung danach aus; Entra-Konten bestätigen bei
Microsoft (erneute Anmeldung erzwungen, die Antwort muss für dasselbe Konto und frisch sein) und machen die Änderung
danach noch einmal. Fünf falsche Bestätigungen beenden die Sitzung (das Konto selbst wird dadurch nicht gesperrt).

**Gleichzeitige Änderungen**: Ändern zwei Admins dasselbe Konto, dieselben Anmelde-Einstellungen, den E-Mail-Server
oder die Einstellungen von News bzw. Vendor News, gewinnt nicht stillschweigend der Letzte – wer auf einem veralteten
Stand speichert, bekommt „Inzwischen von jemand anderem geändert“ und lädt neu (Skripte: das Feld `rev` aus dem GET
mitschicken; ohne `rev` wird nicht geprüft). Trifft das Speichern eines Kanals oder einer Regel auf eine gleichzeitige
Änderung (z. B. ein Kanal, der gerade gelöscht wurde), kommt dieselbe Meldung statt eines Serverfehlers.

### Lokale Konten

*Einstellungen → Benutzer & Rollen → Lokalen Benutzer anlegen*: Name, Rolle → ein **temporäres Passwort** erscheint einmal und muss bei der
ersten Anmeldung ersetzt werden. Es gilt `temp_password_days` Tage ab Vergabe (*Einstellungen → Anmeldung → Sitzungen*,
„Startpasswort gültig für“, 1–30, Standard 7) – ebenso eines aus „Passwort zurücksetzen“ und aus `reset-emergency`;
gespeichert ist die Vergabezeit (`users.temp_password_at`, Migration 0029 – Konten, die beim Update noch auf ihre erste
Passwortänderung warten, zählen ab dem Update). Danach lehnt die Anmeldung das richtige temporäre Passwort mit
`temp_password_expired` ab („Startpasswort abgelaufen – Admin um ein neues bitten“, keine Sitzung, kein Fehlversuch);
die Benutzerliste zeigt „Startpasswort läuft ab am …“ bzw. „Startpasswort abgelaufen“. Die Einstellung gilt für schon
vergebene Passwörter mit (gerechnet ab ihrer Vergabe); ihre Änderung steht im Protokoll (`signin.config_changed`). Admins müssen TOTP einrichten, für Reader ist es freiwillig (*Profil & Sicherheit* im Benutzermenü unten links).
Admins können Konten deaktivieren, die Rolle ändern, Passwort und/oder TOTP zurücksetzen, entsperren und löschen.

### Active Directory (LDAP)

*Einstellungen → Anmeldung*, Karte *Active Directory / LDAP*:

1. Domänencontroller (bis zu 4, der erste ist der primäre), Verschlüsselung **LDAPS** (636) oder **StartTLS** (389).
   Unverschlüsselt nur mit dem ausdrücklichen Schalter „Unsicher zulassen“ – dann gehen alle Passwörter lesbar über das Netz.
2. Zertifikat prüfen (Standard) – bei einer internen CA deren Zertifikat (PEM) eintragen.
3. Basis-DN (z. B. `DC=corp,DC=example`, wird aus dem DC-Namen vorgeschlagen), Dienstkonto (Bind-DN, z. B.
   `CN=svc-news,OU=Service,DC=corp,DC=example`) und dessen Passwort – verschlüsselt gespeichert, nie wieder angezeigt.
4. **Testen**, speichern, „AD-Anmeldung“ einschalten.

Die Domänencontroller dürfen im Firmennetz liegen, aber nie auf Loopback, Link-Local, in den eigenen Docker-Netzen oder
auf dem Docker-Host (`host.docker.internal`, Docker Desktops `192.168.65.0/24`) – „Testen“ meldet dann „Ziel nicht
erlaubt“ und zeigt bei Fehlern nur deren Art, nie Antworten des Servers.

Anmeldung mit `sAMAccountName` (`a.weber`) oder UPN (`a.weber@corp.example`) im Reiter „Active Directory“ der Anmeldeseite.
Admins aus dem AD richten beim ersten Anmelden ebenfalls TOTP ein.

### Entra ID (OIDC)

App-Registrierung im Entra Admin Center (*Identität → Anwendungen → App-Registrierungen → Neue Registrierung*):

1. Name z. B. „Cobe News“, Kontotyp „Nur Konten in diesem Organisationsverzeichnis“.
2. **Umleitungs-URI** (Plattform *Web*): `https://news.corp.example:8095/api/auth/oidc/callback` – exakt die Adresse aus
   `BASE_URL` plus `/api/auth/oidc/callback` (sie steht auch in *Einstellungen → Anmeldung*, Karte *Microsoft Entra ID*, zum Kopieren).
3. *Zertifikate & Geheimnisse → Neuer geheimer Clientschlüssel* – den **Wert** kopieren und das **Ablaufdatum**
   notieren (Kalender, mit Vorlauf; höchstens 24 Monate).
4. *Tokenkonfiguration → Gruppenanspruch hinzufügen* → **Sicherheitsgruppen**, Typ „Gruppen-ID“ (für ID-Token).
5. Optional, empfohlen: *API-Berechtigungen → Microsoft Graph → Anwendungsberechtigungen* `GroupMember.Read.All` und
   `User.Read.All` mit Administratorzustimmung – für die Gruppensuche in den Einstellungen, für Benutzer mit mehr als
   200 Gruppen und für den stündlichen Abgleich (deaktivierte Konten verlieren den Zugang).
6. In Cobe News: Mandanten-ID, Client-ID und Geheimnis eintragen, **Testen**, speichern, einschalten.

Die Anmeldeseite zeigt dann **„Mit Microsoft anmelden“** (Authorization Code Flow mit PKCE; ID-Token wird vollständig
geprüft). MFA verlangt Microsoft (Conditional Access); was das Token davon nachweist, prüft Cobe News (Einstellung
**MFA-Nachweis**: Entra vertrauen – Leser wie bisher, Admins nur mit Nachweis –, Authentifizierungskontext C1–C99 als
`acrs`-Claim verlangen, oder Nachweis verlangen). Ohne Nachweis, wo einer nötig ist: der eigene TOTP von Cobe News
(Handbuch: *Anmeldung → MFA-Nachweis*).

**Clientgeheimnis abgelaufen:** Dann scheitert jede Anmeldung mit Microsoft (AADSTS7000222; ein falsches Geheimnis:
AADSTS7000215), und Cobe News meldet „Microsoft lehnt das Clientgeheimnis von Cobe News ab – es ist abgelaufen oder
falsch …“. Ein über Entra angemeldeter Admin kann das neue Geheimnis **nicht** speichern: Die Änderung verlangt eine
erneute Bestätigung, und die läuft über Microsoft, die mit dem alten Geheimnis scheitert. Ein **lokaler Administrator**
oder das **Notfallkonto** (der Notfall-Admin) meldet sich an und trägt das neue unter *Einstellungen → Anmeldung →
Microsoft Entra ID* ein. Deshalb immer ein lokales Admin-Konto bzw. die Zugangsdaten des Notfall-Admins bereithalten und
das Geheimnis rechtzeitig vor Ablauf wechseln (neues anlegen, eintragen, speichern, das alte in Entra löschen).

### Gruppen → Rollen

*Einstellungen → Benutzer & Rollen → Rollen-Zuordnung*: Gruppe live im AD (voller DN) oder in Entra (Objekt-ID) suchen,
Rolle wählen. **Ohne passende Gruppe kein Zugang** (die Anmeldung scheitert wie mit falschem Passwort). Passen mehrere,
gewinnt `admin`. Die Rolle wird bei jeder Anmeldung und stündlich neu bestimmt; wer aus der Gruppe fällt oder im
Verzeichnis deaktiviert wird, verliert den Zugang (Sitzungen enden). Ist das Verzeichnis nicht erreichbar, ändert der
Abgleich nichts. Ein Verzeichniskonto übernimmt nie ein gleichnamiges lokales Konto. Ändert sich die Rolle bei der
Anmeldung oder im Abgleich, enden alle älteren Sitzungen des Kontos (eine Reader-Sitzung wird nie still zur
Admin-Sitzung ohne TOTP). Verzeichniskonten werden über ihre ID erkannt: wird ein Konto umbenannt (AD: neuer
`sAMAccountName`; Entra: neuer UPN), folgt der Name bei der nächsten Anmeldung (AD auch im stündlichen Abgleich). Der
Name eines Kontos, das im Verzeichnis gelöscht wurde („Abgleich: nicht mehr vorhanden“), wird frei (`name~1a2b3c4d`) –
ein neu angelegtes Konto gleichen Namens (Entra: neue Objekt-ID) kann sich dann anmelden (bei ausgeschalteter
automatischer Anmeldung: nach der Freigabe). Die Mitglieder der zugeordneten Gruppen stehen schon vor der ersten
Anmeldung unter *Benutzer* (siehe nächster Abschnitt).

### Automatische Anmeldung, Freigabe und Vorab-Laden

*Einstellungen → Anmeldung*, ganz oben: **„Automatische Anmeldung über AD/Entra ID zulassen“** (Einstellungsabschnitt
`directory`, Schlüssel `auto_signin`, Standard **an** – nach dem Update verhält sich alles wie bisher). Ändern nur als
Admin mit erneuter Bestätigung; protokolliert als `signin.config_changed` (Ziel `signin`/`directory`).

- **Aus = Freigabe nötig.** Neue Verzeichniskonten – vorab geladen, bei der Anmeldung entstanden oder von einem Team
  geladen – starten als *Wartet auf Freigabe* (`is_active=false`, `deactivated_reason="pending"`). Nur ein Admin schaltet
  sie ein („Freigeben“ bzw. der Schalter *Aktiv*; als Admin mit erneuter Bestätigung), nie der Abgleich, ein Team oder
  eine Anmeldung – auch nicht, wenn der Schalter später wieder an ist. „Ablehnen“ setzt `deactivated_reason="admin"`
  (wie die dauerhafte Sperre). Ein **Aufstieg zum Admin** wartet ebenso (`users.pending_role="admin"`, das Konto bleibt
  Leser; „Bleibt Leser“: `"declined"`, bis es die Admin-Gruppe verlässt). **Absenken und Ausschalten** (gelöscht,
  deaktiviert, keine Gruppe) bleiben automatisch und sofort.
- Die Freigabe hängt an der **Verzeichnis-ID** (`objectGUID` bzw. Entra-Objekt-ID), nie am Namen: ein im Verzeichnis neu
  angelegtes Konto gleichen Namens wartet wieder. Ein Konto, das nie angemeldet war, vom Abgleich ausgeschaltet wurde
  und zurückkommt, wartet ebenfalls.
- Anmeldung eines wartenden Kontos: erst **nach** richtigem AD-Passwort bzw. erfolgreichem Microsoft-Login kommt
  `approval_pending` (AD, HTTP 403) bzw. `/?login_error=directory_pending` (Entra) – „Konto wartet auf Freigabe durch
  einen Admin“; kein Fehlversuch, keine Sitzung, Protokoll `login.pending_refused`. Mit falschem Passwort sieht es aus wie
  immer. Wer noch kein Konto hat, bekommt eines (wartend), damit Admins es sehen.
- **An → Aus**: aktive Verzeichniskonten bleiben aktiv. **Aus → An**: Wartendes bleibt wartend, außer „Auch alle
  wartenden freigeben“ (`approve_pending`, jede Freigabe einzeln protokolliert). Dabei gehen die Zahlen mit, die der
  Dialog gezeigt hat (`expect`); wartet inzwischen anderes (ein neues Konto, eine Ablehnung dazwischen), lehnt der
  Server ab (409 `stale`, nichts freigegeben, nichts umgestellt) und der Dialog fragt mit den neuen Zahlen noch einmal. Der Notfall-Admin und lokale Konten
  sind nie betroffen.
- Protokoll: `user.approval_pending` (Details `source`, `why`: preload | signin | team | sync), `user.approved`,
  `user.declined`, `role.approval_pending` (`from`, `to`), `role.approved`, `role.declined` – die wartenden und die
  Freigaben sind auffällig markiert.

**Vorab-Laden** (unabhängig vom Schalter): Die Mitglieder **jeder zugeordneten Gruppe** (Leser und Admin, AD/LDAP und
Entra ID; verschachtelte Gruppen wie bei der Anmeldung – bei AD nur mit *Verschachtelte Gruppen*) bekommen ein Verzeichniskonto ohne Passwort und ohne Sitzung („Noch nie
angemeldet“) – beim Hinzufügen oder Entfernen einer Zuordnung (im Hintergrund) und stündlich vor dem Konten-Abgleich
(`app/preload.py`). Das Verzeichnis wird ohne offene Transaktion gefragt, geschrieben wird in Paketen zu 500 Konten (je
eine kurze Transaktion); eine Gruppe hat höchstens 50 000 Mitglieder (`MEMBERS_MAX`). 5000 Mitglieder: 10 Seiten zu
500 (LDAP, ein Bind) bzw. 6 Graph-Seiten zu 999 pro Gruppe, 10 kurze Schreib-Transaktionen, im Test wenige Sekunden. **Datensparsam:** ein Konto,
das **nie angemeldet** war und in keiner zugeordneten Gruppe und keinem Team mehr ist, wird **gelöscht** – nur wenn alle
zugeordneten Gruppen seines Verzeichnisses gelesen werden konnten, nie ein vom Admin gesperrtes/abgelehntes, nie eines
mit laufender Anmeldung (Sitzung) oder das während des Ladens entstand. Das Protokoll behält es (`user.deleted`, Akteur
`directory-sync`, `why: unused`; das Protokoll hat keinen Fremdschlüssel auf Konten). Pro Lauf, der etwas ändert, ein
Eintrag `directory.preloaded` mit den Zahlen; nicht lesbare Gruppen (`failed_groups`) allein nur, wenn es andere sind
als beim letzten Lauf oder der letzte Eintrag dazu einen Tag alt ist (Stand in der Einstellung `preload_state`) – ohne
Graph-Berechtigungen also einer am Tag statt stündlich; Einzeleinträge höchstens 200 pro Lauf, der Rest gezählt (`not_listed`). Entra
braucht dafür `GroupMember.Read.All` und `User.Read.All` (Anwendung) – dieselben wie Teams; ohne sie bleibt die Gruppe
ungelesen und es ändert sich nichts. Konten, die sich je angemeldet haben, werden wie bisher nur ausgeschaltet.

Migration `0037_directory_approval`: neue Spalte `users.pending_role` (leer). Nach einem Downgrade bleiben wartende
Konten aus (`pending` ist kein `sync:`-Grund), ein wartender Aufstieg ist vergessen.

### Teams

*Einstellungen → Teams* (standardmäßig **aus** – solange aus, ändert sich nichts): Ein Team ist an AD- oder
Entra-Gruppen gebunden; deren Mitglieder (auch verschachtelte – AD `LDAP_MATCHING_RULE_IN_CHAIN`, Entra
`transitiveMembers`) werden beim Binden sofort geladen und stündlich abgeglichen und erscheinen unter *Benutzer* als
„Noch nie angemeldet“. Eine Team-Gruppe gibt **Leser** (Admin-Gruppe der Rollen-Zuordnung gewinnt); ein von einem Admin
deaktiviertes Konto bleibt aus. Lokale Konten kommen von Hand dazu. Gefolgte Produkte gehören zu Teams („Mein Team“ in
Vendor News), Regeln lassen sich auf Teams beschränken. Optional eine Willkommens-Mail (aus; genau einmal pro Person,
ohne Passwort). Entra braucht dafür `GroupMember.Read.All` **und** `User.Read.All` (Anwendung) – keine neue
Berechtigung. Handbuch: *Anmeldung & Benutzer → Teams*.

## HTTPS

Welches Zertifikat nginx ausliefert, legt `TLS_MODE` in `.env` fest. Den Zustand zeigt *Einstellungen → HTTPS & Zertifikat*
(Gültigkeit, Restlaufzeit, Namen, Aussteller, SHA-256-Fingerabdruck, Download nur des öffentlichen Teils). nginx
bemerkt neue Zertifikatsdateien innerhalb einer Minute und lädt sie ohne Unterbrechung (eine kaputte Datei lädt er
nicht – `nginx -t` vorher, das laufende Zertifikat bleibt).

**1. Selbstsigniert (Standard, `TLS_MODE=selfsigned`).** Die App erstellt beim Start ein Zertifikat (EC P-256,
180 Tage) für `NEWS_HOSTNAME`, den Namen aus `BASE_URL`, `localhost`, `127.0.0.1` und `TLS_NAMES` und erneuert es
30 Tage vor Ablauf (Prüfung beim Start und täglich) – sofort, wenn sich die Namen ändern. Ein Zertifikat, das die App
nicht selbst erstellt hat, überschreibt sie nie (Markerdatei mit dem Fingerabdruck). Browser warnen, bis sie ihm
vertrauen: in den Einstellungen herunterladen und verteilen (z. B. per GPO unter „Vertrauenswürdige
Stammzertifizierungsstellen“) – nach jeder Erneuerung erneut. Ohne Verteilung den Fingerabdruck aus der Browser-Warnung
mit dem in den Einstellungen vergleichen. HSTS wird in diesem Modus **nicht** gesendet (`HSTS=1` schaltet es ein,
sobald das Zertifikat überall vertraut ist).

**2. Eigenes Zertifikat und eigener FQDN (`TLS_MODE=own`).** Für den Betrieb unter z. B. `news.corp.example` mit einem
Zertifikat der internen CA:

1. Zertifikat für den FQDN ausstellen lassen (Serverauthentifizierung, FQDN als Subject Alternative Name; Wildcard
   `*.corp.example` geht auch).
2. Dateien in `deploy/certs/` legen (von Git ignoriert):
   - `cobe.crt` – PEM: zuerst das Serverzertifikat, dahinter die Zwischenzertifikate (nicht die Root)
   - `cobe.key` – PEM, ohne Passwort: `chmod 600 deploy/certs/cobe.key`
   - aus einer PFX-Datei:
     ```bash
     openssl pkcs12 -in news.pfx -clcerts -nokeys -out deploy/certs/cobe.crt
     openssl pkcs12 -in news.pfx -cacerts -nokeys >> deploy/certs/cobe.crt
     openssl pkcs12 -in news.pfx -nocerts -nodes -out deploy/certs/cobe.key
     ```
3. In `.env`:
   ```
   TLS_MODE=own
   TLS_SOURCE=./deploy/certs
   NEWS_HOSTNAME=news.corp.example
   BASE_URL=https://news.corp.example:8095
   BIND=0.0.0.0
   ```
4. DNS-Eintrag `news.corp.example` auf den Server, Firewall für Port 8095 öffnen, `docker compose up -d`.

Die App schreibt nie in diesen Ordner und zeigt nur die Restlaufzeit (Warnung 30 Tage vorher). Zum Tausch die beiden
Dateien ersetzen. In diesem Modus sendet die App HSTS (ebenso mit `TLS_MODE=external`, siehe unten) – nur an einen
Hostnamen, nie an `localhost` oder eine IP-Adresse, damit der Notzugang `http://localhost:8096` nutzbar bleibt.

**3. Eigener Reverse Proxy davor – ein Schalter: `PROXY_ENABLED=0`.** Wenn auf dem Host schon ein nginx/Traefik mit
Zertifikat läuft: in `.env` (bzw. den Environment variables des Stacks) `PROXY_ENABLED=0` und `BASE_URL=https://<FQDN>`,
den eigenen Proxy auf `http://127.0.0.1:8096` (`APP_PORT`) zeigen lassen – fertig. `PROXY_ENABLED=0` bewirkt:

- der mitgelieferte nginx startet nicht (`scale: 0`),
- `TLS_MODE` gilt als `external` (TLS endet am eigenen Proxy; ein ausdrücklich gesetztes `TLS_MODE` geht vor). HSTS
  sendet die App dabei **nicht** – bis 0.1.48 lief eine solche Installation als `selfsigned` ohne HSTS, und ein Jahr
  HSTS ließe sich nicht zurücknehmen. HSTS gibt es mit ausdrücklichem `TLS_MODE=external` (oder `HSTS=1`, das HSTS in
  jedem Modus einschaltet). **Vorher die Zertifikatskette prüfen**: Liefert der eigene Proxy nur das Server-Zertifikat
  ohne Zwischenzertifikat (`openssl s_client -connect <FQDN>:443 -servername <FQDN> -showcerts` zeigt nur `0 s:`), lädt
  mancher Browser die Kette selbst nach, mancher nicht – mit HSTS gibt es dann kein „Trotzdem fortfahren“ mehr
  (`NET::ERR_CERT_AUTHORITY_INVALID`, die Seite ist gesperrt). Abhilfe: Zertifikat und Zwischenzertifikat in einer Datei
  (`ssl_certificate …-fullchain.crt`); bis dahin `TLS_MODE` weglassen und im Browser unter
  `chrome://net-internals/#hsts` den Namen löschen. Bis 0.1.48 kam HSTS hinter einem eigenen Proxy nie an (die App
  vertraute dem Proxy nicht – falsches Gateway), seit 0.1.49 schon,
- die App glaubt `X-Forwarded-For` und `X-Forwarded-Proto` von ihrem **Docker-Gateway** – das ist der Host selbst. Die
  App-Zeile im Log beim Start sagt es: `proxy: PROXY_ENABLED=0 – X-Forwarded-For trusted from 172.31.250.128 (the Docker
  gateway: a reverse proxy on this host)`; im Zugriffslog stehen danach die echten Client-Adressen.

**Welche Adresse hat das Gateway?** Das Netz `edge` hat ein `ip_range` (`EDGE_RANGE`, `172.31.250.128/25`); ohne
ausdrückliches Gateway nimmt Docker dafür die **erste Adresse dieses Bereichs**: `172.31.250.128` – nicht `.1`, wie es
hier bis 0.1.48 fälschlich stand (mit dem Gateway `.1` in `TRUSTED_PROXIES` sah die App alle Anfragen von `.128`). Die App
liest das Gateway selbst aus ihrer Routing-Tabelle (`/proc/net/route`), es muss nirgends eingetragen werden.
`EDGE_GATEWAY` legt eine andere Adresse fest – nur für ein Netz, das neu angelegt wird; ein bestehendes behält seine
(leer, der Standard, ändert an ihm nichts – eine geänderte Netz-Konfiguration ließe Compose das Netz neu anlegen, und das
scheitert, solange ein eigener Container daran hängt).

**Warum das Gateway sicher ist – und wann nicht.** Beide Compose-Dateien veröffentlichen den App-Port nur auf
`127.0.0.1` des Hosts. Unter Linux (Docker Engine) kommt vom Gateway nur, was auf dem Host selbst läuft: Dockers
Weiterleitung des `127.0.0.1`-Ports (`docker-proxy` bzw. DNAT mit Masquerade – beides mit dem Gateway als Absender) oder
ein Prozess des Hosts, der die Container-Adresse direkt anspricht. Ein anderer Container im Netz `edge` kommt mit seiner
eigenen Adresse (sein `X-Forwarded-For` zählt nicht), einer in einem anderen Netz erreicht den `127.0.0.1`-Port gar nicht
(auch nicht über sein Gateway oder `host.docker.internal:host-gateway`), ein anderer Rechner nie über das Gateway.
Geprüft mit Docker Engine 29 unter Linux. Wer auf dem Host Code ausführen kann, kann seine Adresse
damit selbst wählen – dieselbe Grenze wie bisher mit `TRUSTED_PROXIES=<Gateway>`. Daraus folgt:

- **Docker Desktop, OrbStack, Colima/Lima, Podman Machine, WSL2:** dort erreicht *jeder* Container die `127.0.0.1`-Ports
  des Rechners über `host.docker.internal` oder die Host-Adresse der VM (`192.168.65.254`) – und kommt ebenfalls vom
  Gateway. Die App glaubt dem Gateway deshalb nur, wenn sie **sicher** ist, auf einer Linux Docker Engine zu laufen: der
  Kernel ist keiner dieser VMs (`linuxkit`, `orbstack`, `microsoft-standard-WSL2` in `uname -r`), und keiner der Namen
  `host.docker.internal`, `gateway.docker.internal`, `host.orb.internal`, `host.lima.internal`,
  `host.containers.internal` existiert – weder in `/etc/hosts` des Containers (dort trägt Podman Machine seinen Namen
  ein) noch im DNS, wo der Resolver ausdrücklich „gibt es nicht“ sagen muss. Steht einer da oder löst auf, glaubt sie
  **niemandem**; antwortet der Resolver nicht klar (kein DNS, Zeitüberschreitung – höchstens 3 Sekunden beim Start),
  ebenso nicht, und sie fragt im Hintergrund jede Minute neu. Das Log sagt es (`… a desktop Docker …` bzw. `… cannot
  tell …, trusted from nobody`). Wer es trotzdem will (eigener Rechner, keine fremden Container):
  `TRUSTED_PROXIES=<Gateway>/32` ausdrücklich setzen. Dasselbe gilt auf einer Linux Docker Engine, die dem App-Container
  `extra_hosts: host.docker.internal:host-gateway` mitgibt (die Compose-Dateien tun das nicht), und auf einem Server
  **ohne erreichbares DNS** (abgeschottet, der Upstream antwortet dauerhaft SERVFAIL): dort bleibt es bei „trusted from
  nobody“ – `TRUSTED_PROXIES=<Gateway>/32` setzen. Das Gateway nennt die Startzeile der App (`… through the gateway
  172.31.250.128 …`) oder `docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' <Projekt>_edge`
  (`cobe-news_edge`, beim Stack `news_edge`).
- **Nur ein Gateway im Netz `edge`:** die App vergleicht es mit `EDGE_SUBNET` (beide Compose-Dateien geben es ihr mit).
  Liegt das Default-Gateway nicht darin – etwa mit `network_mode: host`, wo es der Router des LANs wäre –, glaubt sie
  niemandem.
- **Den App-Port nie auf eine andere Adresse als `127.0.0.1` legen**, solange das Gateway vertraut wird (die
  Compose-Dateien tun das nicht; wer sie ändert, setzt `TRUSTED_PROXIES=none`).
- **Nie mit dem mitgelieferten nginx** (`PROXY_ENABLED=1`): dann gilt nur dessen feste Adresse (`PROXY_IP`), nie das
  Gateway.

`TRUSTED_PROXIES` ersetzt das Gateway (Adressen oder Netze, Komma-getrennt); `TRUSTED_PROXIES=none` glaubt niemandem.
Ein **Proxy-Container** im Netz `edge` (von außen `cobe-news_edge`, Ziel `http://cobe-news-app:8000`) bekommt dort eine
feste Adresse unterhalb von `.128`, also außerhalb von `EDGE_RANGE` (z. B. `172.31.250.20`), und genau diese steht in
`TRUSTED_PROXIES` – eine dynamische Adresse könnte nach einem Neustart ein anderer Container bekommen. HSTS sendet die
App mit ausdrücklichem `TLS_MODE=external` (siehe oben) – auf Anfragen, die über HTTPS kamen, also von einer vertrauten Adresse mit
`X-Forwarded-Proto: https`; der eigene Proxy darf den Header zusätzlich selbst setzen. Bis 0.1.48 gesetzte Werte:
`TRUSTED_PROXIES=172.31.250.1/32` (der falsche Rat von damals) **entfernen** oder leer setzen – ein gesetztes
`TRUSTED_PROXIES` ersetzt das Gateway, die App sähe weiter jede Anfrage von `172.31.250.128`; sie warnt beim Start
(`proxy: TRUSTED_PROXIES=172.31.250.1/32 lies in the network edge … but not on its gateway`). `TRUSTED_PROXIES=172.31.250.128/32`
stört nicht (unter Linux dieselbe Wirkung), kann weg; `TLS_MODE=external` behalten, wer HSTS will. Beispiel:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name news.corp.example;
    ssl_certificate     /etc/ssl/news/fullchain.pem;   # Serverzertifikat + Zwischenzertifikate
    ssl_certificate_key /etc/ssl/news/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8096;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $remote_addr;   # die echte Adresse – nie die vom Client mitgeschickte
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

**http → https:** standardmäßig gibt es keinen http-Port. Mit `COMPOSE_FILE=docker-compose.yml:docker-compose.http.yml`
in `.env` leitet zusätzlich `HTTP_PORT` (Standard 8094) auf https um. Plain http an den https-Port (`http://name:8095`)
leitet nginx ebenfalls auf https um (`error_page 497`) statt der Fehlerseite „plain HTTP request was sent to HTTPS port“.

**Host-Namen:** nginx liefert Cobe News nur unter den Namen der Installation aus – dem Host aus `BASE_URL`,
`NEWS_HOSTNAME`, den Einträgen aus `TLS_NAMES` sowie `localhost`, `127.0.0.1` und `[::1]` (lokaler Zugang,
selbstsigniert, Health-Checks auf dem Server). `deploy/nginx/16-server-names.envsh` bildet daraus beim Start des
Proxys `NEWS_SERVER_NAMES` (`server_name` im Template; nur Zeichen `a-z 0-9 . - : [ ]` und ein führendes `*.` – alles
andere wird übergangen und geloggt, ein Wert mit Zeilenumbruch ganz; es kommt nichts anderes in die Konfiguration;
IPv6 in eckigen Klammern). Für jeden anderen `Host` antwortet der `default_server` auf 443 mit `421 Misdirected
Request` und einer kurzen Textzeile („Unbekannter Hostname – in .env BASE_URL oder TLS_NAMES eintragen.“, kein Name der
Installation, nie die App), Port 80 und Klartext an den https-Port mit `444` (Verbindung zu). Wer die Seite über eine IP
oder einen weiteren Namen öffnet, trägt ihn in `TLS_NAMES` ein. Welche Namen gelten:
`docker compose logs proxy | grep "answering to"`. Steht `BIND` nicht auf dieser Maschine (`0.0.0.0` o. Ä.), `BASE_URL`
aber noch auf `localhost`, warnt der Proxy beim Start (`WARNING – BIND=… publishes Cobe News to the network`), ebenso
bei einer festen `BIND`-Adresse, die unter den Namen fehlt (`NEWS_BIND` in `docker-compose.yml`, nur dafür).

**Upgrade auf 0.1.47 (Host-Namen):** Ältere Versionen haben jeden `Host` ausgeliefert. Wer Cobe News bisher über eine IP
oder einen Namen öffnet, der weder in `BASE_URL` noch in `NEWS_HOSTNAME` oder `TLS_NAMES` steht, sieht nach dem Update
„Unbekannter Hostname“ (HTTP 421). Vor dem Update prüfen: Steht die Adresse aus der Adresszeile des Browsers in `.env`?
Sonst in `TLS_NAMES` ergänzen (z. B. `TLS_NAMES=10.0.0.5,news.intern`) bzw. `BASE_URL` auf den richtigen Namen setzen
und `docker compose up -d`. Mit `TLS_MODE=external` (eigener Proxy) gilt das für den eigenen
Proxy nicht – dort selbst ein `server_name` und einen Default-Server setzen.

**Größe der Anfragen:** nginx nimmt höchstens 1 MB (`client_max_body_size 1m`), die App selbst ebenso
(`MAX_BODY_BYTES`, Standard 1 MiB, 16 KiB bis 64 MiB; reine ASGI-Middleware `app/bodylimit.py`): `Content-Length`
darüber → sofort `413 body_too_large`; ohne `Content-Length` (chunked) wird mitgezählt und beim Überschreiten
abgebrochen – mit denselben Sicherheits-Headern wie jede Antwort. Kein Endpunkt braucht mehr (es gibt keinen Upload:
Sicherungen entstehen und werden eingespielt auf dem Server).

Der mitgelieferte nginx (`nginx:1.30-alpine`) läuft schreibgeschützt mit `tmpfs`, ohne Capabilities außer den für
Zertifikat und Port nötigen, TLS 1.2/1.3 mit Forward Secrecy, HTTP/2; ein vom Client mitgeschicktes `X-Forwarded-For`
ersetzt er. Er hat im Netz `edge` die feste Adresse `172.31.250.10` (Subnetz `172.31.250.0/24`); nur von dort (und aus `TRUSTED_PROXIES`) übernimmt die App die Client-Adresse.
Seine Konfiguration (`deploy/nginx`: Vorlage, `16-server-names.envsh`, `40-cert-watch.sh`) steckt im Image
`cobe-news-proxy` – nichts davon wird eingehängt; eine Änderung dort wirkt nach `docker compose up -d --build`.
Der Zertifikatswächter lädt nginx neu, sobald sich Zertifikat oder Schlüssel ändern; schlägt die Prüfung oder das
Neuladen fehl (halb geschriebene Dateien, Schlüssel passt noch nicht), versucht er es in der nächsten Runde wieder.

## Netz: nur lokal oder im LAN?

Standard ist `BIND=127.0.0.1` – erreichbar nur von diesem Rechner. Seit es eine Anmeldung gibt, darf
`BIND=0.0.0.0` den Port ins Netz öffnen. Die Voreinstellung bleibt trotzdem lokal: Ein Dienst, der neu aufgesetzt wird,
soll nicht schon im Netz hängen, bevor der erste Admin (Setup-Token) angelegt, TOTP eingerichtet und ein vertrauenswürdiges
Zertifikat hinterlegt ist. Danach `BIND=0.0.0.0` und `BASE_URL`/`NEWS_HOSTNAME` passend setzen – und jeden weiteren
Namen bzw. jede IP, über die die Seite geöffnet wird, in `TLS_NAMES`: nginx antwortet nur auf bekannte Namen
([HTTPS](#https), Host-Namen).

**Docker Desktop / Colima (Mac, Windows)**: Dort gehen die echten Client-Adressen schon bei Dockers Port-Weiterleitung
verloren – nginx sieht jede Anfrage vom Docker-Gateway (z. B. `172.31.250.128`). Was man dann sieht: im Access-Log der App
und unter *Benutzer & Rollen* („letzte Anmeldung“) steht für alle dieselbe Adresse. Was Cobe News daraus macht: das
Gateway gilt als **geteilte Adresse** und wird nie geblockt (sonst sperrte ein Spraying-Versuch alle aus), Fehlversuche
darüber werden gebremst, die Konto-Sperren wirken weiter; das Limit für Entra-Anmeldestarts gilt dort für alle zusammen
(300 statt 30 je 10 Minuten). Was zu tun ist: für den Echtbetrieb einen Linux-Docker-Host nehmen (dort sieht nginx die
echten Adressen); ein Gateway, das Cobe News nicht selbst erkennt (anderer Weg als die Standard-Route des Containers),
in `SHARED_ADDRESSES` eintragen. **Nicht** das Gateway in `TRUSTED_PROXIES` eintragen: dann könnte jeder, der den
App-Port erreicht, seine Adresse per `X-Forwarded-For` selbst wählen (mit `PROXY_ENABLED=0` vertraut die App dem Gateway
hier deshalb auch nicht von selbst, siehe [HTTPS](#https), 3.).

## Einstellungen (Admins)

*Einstellungen* unten in der Seitenleiste (links die Bereiche, rechts Karten mit Speichern unten):

- **Integrationen → News** (Kachel, „Einrichten“ öffnet die Schublade; der Knopf „Quellen“ auf der News-Seite führt
  direkt dorthin) – Hauptschalter (**ab Werk aus**: solange er aus ist, geht keine Anfrage nach außen), Abrufintervall
  (15–1440 Min.), Aufbewahrung (7–365 Tage), Quellen ein/aus, eigene Feeds (nur `https://`, vorher testen), „Jetzt abrufen“.
- **Integrationen → Vendor News** – an/aus, Abrufintervalle, optionaler NVD-API-Schlüssel, „Jetzt abrufen“,
  „Katalog aktualisieren“, Zustand jeder Abfrage; Unter-Reiter **Weitere Quellen** (CSAF-Anbieter, cvelistV5, EPSS,
  OSV – je ein Schalter) und **Katalog-Pflege** – siehe [Vendor News](#vendor-news), [Weitere Quellen](#weitere-quellen-csaf-anbieter-cvelistv5-epss-osv)
  und [Katalog pflegen](#katalog-pflegen).
- **Integrationen → Gesundheit** (Unter-Reiter, `?view=health`) – wie gut jede Quelle abgerufen wird, siehe
  [Quellen-Gesundheit](#quellen-gesundheit). Ist eine Quelle tot, zeigt *Integrationen* in der Navigation die Anzahl.
- **Kanäle & Regeln** (mit dem E-Mail-Server oben in *Kanäle*) – siehe unten.
- **Benutzer & Rollen** (mit Rollen-Zuordnung), **Anmeldung** – siehe oben.
- **HTTPS & Zertifikat** – Zertifikat.
- **API & Metriken** (`/settings/api`) – API-Tokens für die Lese-API und `/metrics`, siehe
  [API-Tokens und Metriken](#api-tokens-und-metriken).
- Für alle: **Profil & Sicherheit** (Sprache, Darstellung, Passwort, TOTP) und **Benachrichtigungen** (Desktop).

### Quellen

In der News-Schublade stehen die Quellen in Gruppen mit Sprache (DE/EN/FR); eine Gruppe ist aufgeklappt, sobald eine
ihrer Quellen an ist. Neue eingebaute Quellen erscheinen nach einem Update mit ihrem Standard – was ein Admin an- oder
ausgeschaltet hat, bleibt so. Ändert sich der Standard einer eingebauten Quelle, folgt ihm nur eine Quelle, die nie ein
Admin geschaltet hat; seit 0.1.7 merkt sich Cobe News jedes Schalten. Eine Quelle, die Cobe News nicht mehr mitbringt,
verschwindet beim nächsten Start wie eine gelöschte eigene: Regeln und Desktop-Auswahl lassen sie los, Meldungen, die
auch eine andere Quelle bringt, bleiben.

| Gruppe | Eingeschaltet (Standard) | Wählbar |
|---|---|---|
| Behörden & CERTs | BSI Cyber-Sicherheitswarnungen, CERT-EU Security Advisories, CERT.at Warnungen | BSI CERT-Bund (WID), BSI Presse, NCSC UK, Canadian Centre for Cyber Security, CERT-FR Alertes (FR) |
| Schwachstellen-Kataloge | CISA KEV (JSON) | ENISA EUVD – ausgenutzte Schwachstellen (JSON), Microsoft Patchday (MSRC, JSON) |
| Hersteller-Hinweise (PSIRT) | CERT@VDE (OT-Hersteller), Veeam Security | Fortinet PSIRT, Palo Alto Networks PSIRT, Cisco PSIRT, Ivanti, Siemens ProductCERT, Oracle Security Alerts |
| Research | Microsoft Threat Intelligence, Cisco Talos | Unit 42, Google Threat Intelligence (Mandiant), Kaspersky Securelist, ESET WeLiveSecurity, Check Point Research, Zero Day Initiative, SANS ISC, watchTowr Labs, Huntress |
| Presse | heise online, heise Security, The Hacker News, golem.de Security, BleepingComputer, SecurityWeek ICS/OT | SecurityWeek, Krebs on Security, Dark Reading, The Record, Borns IT-Blog, Security-Insider, t3n Security, Risky Bulletin |

- **CISA KEV und ENISA EUVD** sind JSON-Kataloge aktiv ausgenutzter Schwachstellen (am Inhalt erkannt, nicht am
  Content-Type): jeder Eintrag eine Meldung („CVE · Hersteller Produkt: Name“, Link zur NVD bzw. zum EUVD-Eintrag),
  Schwere **hoch**, **kritisch** bei bekannter Ransomware-Nutzung (KEV) bzw. ab CVSS 9 (EUVD). Je Abruf die neuesten 200
  Einträge, ältere als die Aufbewahrung nicht. Eigene Quellen dürfen auch ein JSON-Katalog in diesem Format sein.
- **Microsoft Patchday (MSRC)** liest den CVRF-Index (`api.msrc.microsoft.com/cvrf/v3.0/updates`): je Release eine
  Meldung („Microsoft: October 2026 Security Updates“, Link zu den Release Notes im Update Guide), Schwere **hoch** –
  der ruhige Weg, Microsoft zu folgen (der Update-Guide-Feed hat je CVE einen Eintrag, Hunderte im Monat).
- **CISA Alerts und Rockwell Automation** gibt es seit 0.1.49 nicht mehr: `www.cisa.gov` und `www.rockwellautomation.com`
  lehnen automatische Abrufe aus den meisten Netzen ab (403, Bot-Schutz) – sie lieferten nie. Cobe News umgeht so etwas
  nicht (kein anderer User-Agent, keine Browser-Header) und zeigt bei 403 „Die Quelle lehnt automatische Abrufe ab“. Wer
  eine davon erreicht, trägt ihre Adresse als eigene Quelle ein. CISAs KEV-Katalog bleibt; OT-Meldungen kommen über
  CERT@VDE, Siemens ProductCERT und SecurityWeek ICS/OT.
- **Eine Meldung je CVE:** zwischen KEV, EUVD und den BSI-Warnungen ist dieselbe CVE innerhalb von 30 Tagen dieselbe
  Meldung („auch bei …“, die höhere Schwere mit Begründung), wenn eine Seite genau diese eine CVE betrifft. Ein
  Presseartikel über dieselbe CVE bleibt eine eigene Meldung.
- **Rückstand:** der erste KEV-Abruf bringt rund 100 Meldungen der letzten 90 Tage auf einmal. Weder Regeln noch
  Desktop-Benachrichtigungen noch Web Push schicken davon etwas – nur Meldungen, die beim Abruf höchstens einen Tag alt
  waren; ein Datum ohne Uhrzeit (KEV, EUVD) zählt bis zum Ende dieses Tages. Meldungen ohne eigenes Datum sind im
  ersten Abruf einer Quelle Rückstand, danach neu. Das wird einmal beim Speichern entschieden und gilt überall gleich.
- **Mehrere Quellen, eine Meldung:** eine Meldung, die auch andere Quellen bringen („auch bei …“), zählt für jede davon –
  im Quellenfilter, in Regeln, Desktop-Benachrichtigungen und in der Anzahl je Quelle; sie bleibt sichtbar, solange
  eine dieser Quellen eingeschaltet ist. Innerhalb einer Quelle ist ein gleicher Titel unter anderer Adresse eine eigene
  Meldung (CISA „Adds Two Known Exploited Vulnerabilities …“); eine geänderte Meldung („[UPDATE] …“) wird übernommen,
  ihre Schwere steigt nur, ihre CVEs werden ergänzt.
- **Reihenfolge:** jeder Feed wird vor dem Kürzen auf 200 Einträge nach Datum sortiert (Siemens liefert seine ganze
  Historie, die ältesten zuletzt).
- **Schwere:** die Einstufung des Herausgebers gilt (BSI „[hoch]“, Palo Alto „(Severity: HIGH)“, Cisco „Security Impact
  Rating“) – nur ein CVSS-Wert oder „aktiv ausgenutzt“ heben sie an; Verneinungen wie „not known to be actively
  exploited“, „bislang nicht aktiv ausgenutzt“, „Kein Zero-Day“ oder „keine aktive Ausnutzung“ zählen nicht als
  Ausnutzung, ebenso wenig die Zero-Day-Initiative, ein „Out-of-Band-Management-Interface“ oder Malware „in the wild“
  (nur eine *Ausnutzung* in freier Wildbahn zählt). CVSS-Werte auch in deutscher Form („CVSS-Score von 9.8“,
  „CVSS-Basiswert 9,8“); eine Versionsangabe („CVSS:3.1/AV:N…“, „CVSS 3.1“) gilt nie als Wert.
- **Ausgehende Hosts** (nur eingeschaltete Quellen, je Host höchstens eine Anfrage pro Minute): Standard `www.heise.de`,
  `feeds.feedburner.com`, `rss.golem.de`, `www.bleepingcomputer.com`, `www.cisa.gov` (KEV),
  `www.bsi.bund.de`, `cert.europa.eu`, `www.microsoft.com`, `blog.talosintelligence.com`, `www.cert.at`, `certvde.com`,
  `www.securityweek.com`, `www.veeam.com`; wählbar `wid.cert-bund.de`, `www.ncsc.gov.uk`,
  `euvdservices.enisa.europa.eu`, `filestore.fortinet.com`, `security.paloaltonetworks.com`, `sec.cloudapps.cisco.com`,
  `www.ivanti.com`, `cert-portal.siemens.com`, `unit42.paloaltonetworks.com`, `cloudblog.withgoogle.com`,
  `securelist.com`, `research.checkpoint.com`, `www.zerodayinitiative.com`, `isc.sans.edu`, `www.securityweek.com`,
  `krebsonsecurity.com`, `www.darkreading.com`, `therecord.media`, `www.borncity.com`, `www.security-insider.de`,
  `t3n.de`, `www.cyber.gc.ca`, `cert.cyber.gouv.fr`, `labs.watchtowr.com`, `www.huntress.com`,
  `www.oracle.com`, `news.risky.biz`, `api.msrc.microsoft.com`; dazu die Startseiten für
  die Logos (z. B. `risky.biz`, `msrc.microsoft.com`).

Abruf: höchstens eine Anfrage pro Website und Minute, `ETag`/`If-Modified-Since`, nach 429/503 Pause wie
per `Retry-After` verlangt (mind. 1 h), sonst wachsende Pause (bis 24 h); nur https, keine internen Ziele (Loopback,
Link-Local/Metadaten, ohne `ALLOW_PRIVATE_FEEDS` auch keine privaten Netze; DNS einmal aufgelöst und genau diese Adresse
verbunden), max. 5 MB / 30 s je Feed, XML mit DTD/Entities abgelehnt, Logos nur als Bitmap und vom Server geholt.
Mit `HTTPS_PROXY` löst der Proxy die Namen auf: geprüft werden dann nur Adressen, die als IP in der URL stehen – das
Sperren interner Ziele über Namen muss der Proxy selbst übernehmen. XML wird vom Parser selbst auf DTD/Entities
geprüft (in jeder Kodierung, an jeder Stelle); Datumsangaben außerhalb 1990–2100 gelten als „kein Datum“. Ein Feed,
der einen Fehler auslöst, pausiert nur selbst – die Runde geht mit den anderen weiter. Meldungen älter als die
Aufbewahrung werden nicht (wieder) übernommen – auch nicht nach einem späteren Erhöhen der Aufbewahrung; Meldungen
ohne eigenes Datum bleiben, solange ihr Feed sie noch listet (siehe [Aufbewahrung](#aufbewahrung)).
Benachrichtigungsregeln schicken keinen Rückstand (Meldungen, die beim Abruf schon älter als ein Tag waren, etwa beim
ersten Abruf einer neu eingeschalteten Quelle – oder ohne eigenes Datum beim ersten Abruf nach dem Wiedereinschalten
von News). Verbindungsfehler und Timeouts pausieren eine Quelle höchstens eine Stunde (oder ein Abrufintervall, wenn es länger
ist). Den Platz gelöschter Meldungen nutzt PostgreSQL wieder (autovacuum).

### Quellen-Gesundheit

*Einstellungen → Integrationen → Gesundheit* zeigt für jede News-Quelle, jede Quellen-Familie von Vendor News
(NVD, Palo Alto Networks, Fortinet PSIRT, Veeam KB, CISA KEV, endoflife.date – die vielen NVD-Abfragen je CPE stehen in
einer Zeile, die Schublade listet sie einzeln) und jede der [weiteren Quellen](#weitere-quellen-csaf-anbieter-cvelistv5-epss-osv)
als eigene Art „Weitere Quelle“ (CSAF-Anbieter – je Anbieter und die Liste des BSI eine Abfrage –, cvelistV5, FIRST
EPSS, OSV.dev) den Zustand, den letzten Erfolg, den letzten Fehler, neue Einträge je
Woche der letzten 4 Wochen und die mittlere Antwortzeit. „Nur Probleme“ blendet alles aus, was nicht gestört oder tot
ist. Ein Klick öffnet die Schublade mit den letzten 50 Abrufen (Zeit, Status, Dauer, Größe, neue Einträge, Fehler),
den letzten Fehlern, den Zustandswechseln, ob die Quelle bedingte Abrufe kann (`ETag`/`Last-Modified` → 304) und der
Pause bis zum nächsten Versuch.

| Zustand | Wann (Reihenfolge: der erste passende gilt) |
|---|---|
| aus | Quelle oder News ausgeschaltet; bei Vendor News: ausgeschaltet oder kein gefolgtes Produkt braucht die Abfrage |
| noch nicht abgerufen | eingeschaltet, aber noch nie gefragt |
| **tot** (rot) | HTTP 401/403/410 zweimal in Folge, HTTP 404 dreimal in Folge; seit **14 Tagen** kein erfolgreicher Abruf (gezählt ab dem letzten Erfolg bzw. dem Einschalten); nur News: seit **60 Tagen** keine neue Meldung, obwohl der Abruf klappt – erst bewertet, wenn Meldungen und Statistik die 60 Tage abdecken |
| **gestört** (bernstein) | 3 Fehlschläge in Folge; ein aktueller Fehler, der nicht nur vorübergehend ist (alles außer Zeitüberschreitung, Verbindungsfehler, HTTP 5xx, „zu viele Anfragen“) – die Quelle pausiert bis zum nächsten Versuch; eine unlesbare Antwort in den letzten 24 Stunden |
| **langsam** (blau – ein Hinweis, nichts zu tun) | im Mittel der letzten 7 Tage über 5 s je Anfrage (mind. 3 Anfragen; Downloads über 1 MB je Anfrage zählen nicht), mind. 3 Zeitüberschreitungen und mind. ein Viertel der Abrufe, oder ein vorübergehender Fehler, der gleich wiederholt wird |
| **gesund** (grün) | alles andere |

- **Gespeichert** wird je Abruf eine Zeile (`source_fetch_stats`): Zeit, Erfolg, HTTP-Status, Fehlerart (Zeitüberschreitung,
  Verbindung, TLS, HTTP 4xx, HTTP 5xx, zu viele Anfragen, abgelehnt/403, unlesbar, zu groß, sonstiges), Dauer und Zahl
  der Anfragen, Bytes, neue Einträge, 304 ja/nein, unlesbare Einträge. Aufbewahrung **60 Tage**, stündlich in kleinen
  Portionen gelöscht. Ein Abruf, der gar nicht fragt (Host pausiert), zählt nicht.
- **Neue Einträge**: bei News die neu gespeicherten Meldungen, bei Vendor News neue oder geänderte Hinweise (KEV und
  endoflife.date: neue Einträge im Katalog). Eine Woche ohne Abruf steht als „–“, nicht als 0.
- **Mittlere Antwortzeit und Größe** nur aus erfolgreichen Abrufen; eine 304-Antwort hat keinen Inhalt und zählt als Erfolg.
- **Benachrichtigung** (optional): Regel-Art *„Quelle gestört oder tot“* unter *Kanäle & Regeln*. Gesendet wird **einmal
  je Zustandswechsel** (in gestört oder tot, von gestört nach tot, und zurück zu gesund/langsam), nie jede Runde; ein
  Ausschalten oder der erste Zustand einer Quelle nach dem Update schickt nichts. Die Zustände werden alle 5 Minuten
  verglichen und gespeichert (`source_health_events`) – auch ein Neustart schickt nichts doppelt. Bei Vendor News kommt
  eine Nachricht je Familie (NVD ausgefallen = eine Nachricht, nicht eine je CPE).
- API (nur Admins): `GET /api/admin/source-health` (Zeilen und Anzahl je Zustand), `GET /api/admin/source-health/{news|vendor|structured}/{key}`
  (Verlauf einer Quelle bzw. Familie).

## Vendor News

Seitenpunkt **Vendor News**: zu den Produkten und Versionen, die ihr einsetzt, die Schwachstellen, die **genau diese
Versionen** betreffen, neue Versionen, Support-Ende und passende News.

- **Katalog** (⋯ → „Produkt hinzufügen“): rund 830 Produkte in Kategorien (Firewalls & VPN, Switches/Router/WLAN,
  Betriebssysteme, Virtualisierung, Storage & Backup, Microsoft-Server, ERP, Collaboration, Web-/App-Server &
  Laufzeiten, Datenbanken, Security/Endpoint, Passwortmanager & Zugangsverwaltung, Fernzugriff/IT-Management,
  Browser & Clients, Cloud-Dienste …) mit
  Suche (unscharf: Hersteller, Produkt, Alias, CPE; ein Tippfehler wird verziehen) und Zählern „gefolgt / gesamt“ je
  Kategorie. Pro Produkt ein Schalter **„Folgen“** (Admins; alle anderen sehen dieselbe Liste). Fehlt etwas:
  „Nicht im Katalog?“ – Hersteller/Produkt im CPE-Verzeichnis der NVD suchen und als eigenen Eintrag folgen.
- **Ohne Version gefolgt**: alle Schwachstellen und News zum Produkt („betrifft das Produkt – Version angeben für
  genaue Prüfung“) – z. B. „PHP“ oder „Node.js“, damit die aktuelle große Lücke erscheint.
- **Mit Versionen**: beliebig viele pro Produkt (je Standort eine Zeile, optional Bezeichnung wie „RZ Nord“,
  „HA-Paar“ und Anzahl), im Reiter „Versionen“ der Schublade: eingetragene Versionen als Karten mit Status
  (Schwachstellen, „Aktuell“ / „Update verfügbar“, Support bis …), Bearbeiten per Stift, neue Versionen im Formular
  „Neue Version eintragen“. Jede Version wird einzeln
  geprüft: **betroffen** (mit Fix-Version / Upgrade-Ziel), **möglicherweise betroffen – Version nicht eindeutig** oder
  **nicht betroffen**. Eine Schwachstelle zeigt „betrifft 2 von 3 Versionen“, die Karte den schlimmsten Stand.
  Das Format wird je Hersteller geprüft (PAN-OS `11.2.4-h23`, FortiOS `7.4.8`, Cisco `9.18(4)22` / `17.9.4a`,
  Windows-Build `10.0.20348.2762` – keine KB-Nummer, VMware `8.0 U3c`, Ivanti `22.7R2.3`).
- **Übersicht**: eine Statuszeile (Handlungsbedarf · Möglicherweise · Aktuell · Alle), Suche, Filter, Ansichten;
  je Produkt eine Karte – betroffene / mögliche Schwachstellen, davon kritisch und
  aktiv ausgenutzt (KEV/EUVD), „Update verfügbar“, Warnung bei nahem (unter 6 Monaten) oder erreichtem Support-Ende – dieselbe Schwelle in Karte, Schublade und
  Benachrichtigung. Die
  Zahl am Seitenpunkt: Produkte, die eine Schwachstelle betrifft (rot, wenn eine davon ausgenutzt wird).
- **Schublade** je Produkt mit den Reitern Schwachstellen (gruppiert: betrifft eure Versionen / möglicherweise
  betroffen – Daten nicht eindeutig / …) / Versionen / News; Release-Linien mit aktuellster Version, Support-Ende und
  Status je Linie („eure Linie“ markiert, Linien ohne Support eingeklappt); Notizen und Tags zuletzt. Ein Klick auf
  einen Eintrag der Karte öffnet die Schublade bei diesem Befund.

**Woher die Daten kommen**

| Quelle | Wofür | Abruf |
|---|---|---|
| Palo Alto Networks (`security.paloaltonetworks.com/json/`) | PAN-OS, Panorama, GlobalProtect, Prisma Access/SD-WAN/Cloud, Cortex XDR/XSOAR/XSIAM, Expedition, Strata Cloud Manager, Cloud NGFW: je Linie betroffene und behobene Versionen (Hotfix-genau) und die Liste aller betroffenen Versionen | je Produktname, neueste zuerst, bis zum Stand des letzten Abrufs; `ETag` |
| Fortinet (`filestore.fortinet.com`) | PSIRT-RSS (die neuesten 50) und pro Hinweis die CSAF-Datei: betroffene / nicht betroffene Bereiche je Produkt, Fix je Linie | RSS bedingt, je Hinweis einmal |
| Veeam (`www.veeam.com/services/open/kb/security-feed`) | Security-KB-Feed (Atom, die neuesten ~20 KB-Artikel): je Artikel alle CVEs, CVSS, je CVE und Produkt die betroffenen Builds je Release-Linie („13.1.1.18 and all earlier version 13.1 builds“), die Fix-Builds („13.1.2 (build 13.1.2.57)“) und die Hinweise zu anderen Linien („Older versions … are not affected“, „Version 13 is not affected“). Backup & Replication (mit Enterprise Manager), Agent für Windows und für Linux, ONE, Service Provider Console, Recovery Orchestrator, Backup for Microsoft 365, Kasten. Die laufenden Listen „List of Security Fixes and Improvements“ sind keine Hinweise und werden übergangen | nur mit gefolgtem Veeam-Produkt; eine Anfrage je Runde (alle 6 Stunden), bedingt, wenn der Server `ETag`/`Last-Modified` schickt; höchstens eine Anfrage pro Minute an `www.veeam.com` (zusammen mit der News-Quelle) |
| NVD API 2.0 (`services.nvd.nist.gov`) | alle Produkte mit CPE: CVEs mit CPE-Versionsbereichen und den Angaben des CNA (Microsoft: Build-Bereiche bis zum Security Update), CVSS, „von CISA als ausgenutzt gelistet“; neue, noch nicht analysierte CVEs per Stichwortsuche der letzten 30 Tage | je CPE die neuesten 2000 CVEs, danach nur Geänderte (`lastModStartDate`); ohne Schlüssel höchstens 5 Anfragen / 30 s |
| CISA KEV (`www.cisa.gov`) | ganzer Katalog ausgenutzter Schwachstellen | täglich, bedingt |
| endoflife.date (`/api/v1/products/full`) | Katalog, Release-Linien, aktuellste Version je Linie, Support- und EOL-Daten | täglich, eine Anfrage, bedingt |
| ENISA EUVD | „aktiv ausgenutzt“ – aus den News (wenn die Quelle eingeschaltet ist) | – |
| CSAF-Anbieter (Siemens, Cisco, Schneider Electric, Open-Xchange) | die CSAF-Hinweise des Herstellers: Produkte mit Bereichen und Fix-Versionen | nur mit gefolgtem Produkt des Herstellers; alle 6 Stunden, Liste bedingt, je Runde höchstens 25 Dokumente – [Weitere Quellen](#weitere-quellen-csaf-anbieter-cvelistv5-epss-osv) |
| cvelistV5 (GitHub) | CVE-Einträge, wie der Hersteller (CNA) sie meldet, und die Einstufung der CISA (CVSS, SSVC, KEV) – vor allem für CVEs, die die NVD noch nicht analysiert hat | dreimal am Tag die Änderungen des Tages, einmal der Tagesabschluss des Vortags; einzelne ältere Einträge bei Bedarf |
| FIRST EPSS | Wahrscheinlichkeit der Ausnutzung in 30 Tagen | je CVE eines Befunds oder einer Meldung höchstens täglich |
| OSV.dev | betroffene und behobene Versionen von Open-Source-Paketen (Tomcat, Jenkins, Django …) | nur mit der CVE-Nummer, je CVE täglich bis wöchentlich |

Microsofts eigene CVRF-Dokumente (ca. 30 MB pro Monat) werden nicht geladen – dieselben Build-Grenzen stehen in den
CNA-Daten der NVD. Cisco openVuln braucht Zugangsdaten und ist nicht eingebaut; Cisco-CVEs kommen über die NVD.

**Wie verglichen wird** (`backend/app/vendor_versions.py`, `vendor_match.py`): Versionen werden je Schema zerlegt
(PAN-OS-Hotfix `11.2.4-h23` > `11.2.4-h4` > `11.2.4`, Cisco-Klammern, IOS-XE-Buchstaben, Windows-Builds, VMware
Updates, Ivanti R-Releases, Veeam-Builds, sonst Zahlen und Buchstaben mit Vorabversionen). Veeam: am besten den ganzen
Build eintragen (`12.3.2.4934`, auch `13.1.2 (build 13.1.2.57)`), zu finden in der Konsole unter Help → About (der
Hinweis steht im Formular „Neue Version eintragen“). Eine kurze Angabe wie `12.3.2` gilt für jeden Build von 12.3.2:
entschieden wird nur, was für alle gilt (`12.3.1` ist von „12.3.2.4854 and all earlier version 12 builds“ betroffen,
`12.3.2` nur „möglicherweise“). `12.3.2 P4` lässt sich nicht vergleichen – welcher Build ein Patch ist, sagt der
KB-Artikel. Der Veeam Agent hat je Betriebssystem einen Katalog-Eintrag (Windows und Linux haben eigene Builds). „Nicht betroffen“ nur, wenn die Daten es
entscheiden (Version ab dem Fix, Linie ausdrücklich nicht betroffen, neuer als alles Genannte). Sonst
**„möglicherweise betroffen“**: unbekanntes Format, eine Quelle ohne Hotfix-/Update-Stand, eine Linie, die der Hinweis
nicht nennt, „alle Versionen“ ohne Grenze, ein PAN-OS-Hinweis ohne Angabe zu Panorama. **Reihenfolge**: der Hersteller
(eigene Hinweise, CSAF) entscheidet vor allem anderen; danach je CVE die NVD, wo sie die CVE analysiert hat (CPE-
Konfigurationen); wo sie das nicht hat (noch kein Eintrag, „Awaiting Analysis“), der aktuelle CVE-Eintrag aus cvelistV5
– zuerst die Angaben des Herstellers (CNA), nur wenn die das Produkt nicht nennen die der CISA (ADP, CPE-Namen) –,
zuletzt die Kopie dieser Angaben in der NVD. OSV kommt danach: es entscheidet ein „möglicherweise betroffen“ und nennt
eine fehlende Fix-Version, ändert aber kein eindeutiges Urteil. Kurze Versionen (`7.4`) werden bei allen Quellen gleich
behandelt („möglicherweise – Version zu ungenau“). Linux-Distributionen: nur Release-Linie und Support-Ende – ob eine Lücke geschlossen ist, sagt nur das
Advisory der Distribution.

**Benachrichtigungen:** Regeln haben drei Arten – Security-Meldungen, „Schwachstelle betrifft eines unserer Systeme“,
„Neue Version / EOL naht“ – und nutzen dieselben Kanäle. Jede Schwachstelle kommt **einmal pro Produkt und Version**
(auch wenn Hersteller und NVD sie melden). Was beim ersten Prüfen eines neu gefolgten Produkts oder einer neuen /
geänderten Version schon bekannt ist, steht auf der Seite, wird aber nicht verschickt; ebenso Hinweise, die älter als
30 Tage sind (außer frisch im KEV). Wird eine schon gemeldete Schwachstelle später aktiv ausgenutzt (neu im KEV), kommt
einmal „Jetzt aktiv ausgenutzt: …“. Im Webhook-JSON haben diese Einträge `"kind": "vendor.vuln"` / `"vendor.version"` /
`"vendor.eol"` und `link` auf die Produktseite.

**An oder aus:** ab Werk **an** – Anfragen gehen aber erst raus, wenn jemand einem Produkt folgt, und nur für die
gefolgten Produkte (ohne gefolgtes Produkt: keine einzige Anfrage). Abschalten unter *Einstellungen → Integrationen →
Vendor News*. Der Abruf läuft in einem eigenen Hintergrundtask (eine langsame NVD-Runde hält die News nicht auf):
Hinweise und NVD alle 6 Stunden, endoflife.date und KEV alle 24 Stunden (änderbar), dieselbe Härtung wie die Feeds
(nur https, keine internen Ziele, DNS gepinnt, Größen- und Zeitlimits, keine XML-DTDs), je Host ein Mindestabstand,
nach Fehlern wachsende Pausen, `Retry-After` (mindestens 1 h nach 429/503). Lehnt die NVD ab (429), pausiert sie für
alle Abfragen – die übrigen CPEs der Runde, die Details der News und die CPE-Suche fragen erst danach wieder. Je CPE
kommen erst die neuesten 2000 CVEs, danach alles, was die NVD seit dem letzten Abruf geändert hat (alle Seiten), und
einmal pro Woche wieder die neuesten 2000: was die NVD für die CPE nicht mehr listet (zurückgezogen, CPE entfernt),
verliert dann die Zuordnung. Eine geänderte Version wird sofort neu bewertet – ohne neuen Abruf. Ereignisse entfernter
Versionen und nicht mehr gefolgter Produkte werden gelöscht.

**Ausgehende Hosts** (nur bei gefolgten Produkten): `services.nvd.nist.gov`, `endoflife.date`, `www.cisa.gov`;
mit Palo-Alto-Produkten `security.paloaltonetworks.com`, mit Fortinet-Produkten `filestore.fortinet.com`, mit
Veeam-Produkten `www.veeam.com`; dazu die [weiteren Quellen](#weitere-quellen-csaf-anbieter-cvelistv5-epss-osv).

### Weitere Quellen (CSAF-Anbieter, cvelistV5, EPSS, OSV)

Vier strukturierte Quellen ergänzen die Hinweise der Hersteller und die NVD. Jede hat ihren Schalter unter
*Einstellungen → Integrationen → Vendor News → Weitere Quellen* und ist **ab Werk an**: Keine fragt etwas, solange
nichts gefolgt wird (EPSS: auch keine Meldung mit CVE da ist), jede fragt nur, was gefolgte Produkte brauchen, und es
geht nie etwas über eure Installation hinaus (keine Produkte, Versionen, Inventar, Hostnamen) – nur Anfragen an die
öffentlichen Adressen dieser Dienste und CVE- bzw. Schwachstellen-Nummern. Ist Vendor News aus, fragt keine. Der
Zustand jeder Quelle steht dort und unter *Gesundheit* (Art „Weitere Quelle“, intern `structured`). Ausführlich für
Admins: Handbuch, Kapitel *Integrationen → Weitere Quellen* (`/docs/integrationen#weitere-quellen`); für Leser EPSS,
SSVC und „Erstabruf“ unter *Vendor News & Katalog* (`/docs/vendor-news#epss-ssvc`).

| Quelle | Was sie bringt | Wann, wie viel | Was nach außen geht |
|---|---|---|---|
| **CSAF-Anbieter** der Hersteller (`backend/app/csaf_providers.py`) | die CSAF-2.0-Hinweise von Siemens, Cisco, Schneider Electric, Open-Xchange (Liste in `catalog/csaf.yaml`) als Hinweise in Vendor News: Produkte mit Bereichen, Fix-Versionen, CVEs, CVSS | nur mit gefolgtem Produkt des Herstellers; mit der Vendor-News-Runde (alle 6 Stunden); die Liste der Dokumente (ROLIE-Feed oder `changes.csv`) bedingt; je Runde höchstens 25 Dokumente, ein Rest 20 Minuten später; der erste Abruf reicht 90 Tage zurück („Erstabruf“, unten) | Abrufe der öffentlichen CSAF-Adressen des Herstellers (`cert-portal.siemens.com`, `www.cisco.com`, `www.se.com`, `www.open-xchange.com` und `documentation.open-xchange.com`) und täglich die Anbieter-Liste des BSI (`wid.cert-bund.de`) |
| **cvelistV5** (`backend/app/cvelist.py`) | die CVE-Einträge, wie der Hersteller (CNA) sie meldet – betroffene Versionen mit `lessThan`/`lessThanOrEqual`/Hotfix-Änderungen – und die Einstufung der CISA (ADP: CVSS, SSVC, KEV, CPEs) | dreimal am Tag die ZIP-Datei „alles seit Mitternacht (UTC) geändert“ (einige hundert KB bis wenige MB; nie die ganze Liste mit ~650 MB), einmal am Tag der Tagesabschluss des Vortags – zusammen etwa 9–11 MB am Tag (Zeitplan unten); einzelne ältere Einträge, wenn ein Befund oder eine Meldung sie braucht (höchstens 20 bzw. 15 je Runde, je CVE höchstens wöchentlich) | Abrufe öffentlicher Dateien bei `api.github.com`, `github.com`, `raw.githubusercontent.com` (ohne Anmeldung) |
| **FIRST EPSS** (`backend/app/epss.py`) | Wahrscheinlichkeit der Ausnutzung in den nächsten 30 Tagen und Perzentil – bei Befunden (mit Sortierung in der Schublade) und in der Meldung | für die CVEs der Befunde gefolgter Produkte und der Meldungen der letzten 30 Tage (wenn „Details aus der Quelle“ an ist); je CVE höchstens einmal am Tag; bis 100 CVEs je Anfrage, höchstens 20 Anfragen je Runde | nur CVE-Nummern (`api.first.org`) |
| **OSV.dev** (`backend/app/osv.py`) | betroffene und behobene Versionen von Open-Source-Paketen (ECOSYSTEM/SEMVER-Bereiche; GIT-Bereiche mit Commits werden verworfen) | für die CVEs der Befunde gefolgter Produkte, deren Pakete der Katalog nennt (`osv` – Tomcat, Jenkins, Grafana, Keycloak, Kubernetes, Django, Spring …); je CVE täglich, solange sie jünger als 30 Tage ist, sonst wöchentlich; höchstens 25 CVEs je Runde und je CVE bis 3 Aliasse (GHSA zuerst; GO-, PYSEC-, RUSTSEC-); zurückgezogene OSV-Einträge (withdrawn) werden nicht beachtet | nur CVE- und Advisory-Nummern im Pfad (`api.osv.dev/v1/vulns/<id>`) – nie ein Produkt oder eine Version (keine Abfrage `/v1/query`) |

- **CSAF-Anbieter finden**: zuerst die Anbieter-Liste des BSI (`https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json`)
  – ein Eintrag, dessen Adresse auf dem Host des Anbieters liegt –, sonst `https://<domain>/.well-known/csaf/provider-metadata.json`.
  Gelesen werden nur ROLIE-Feeds mit TLP:WHITE/CLEAR und Verzeichnisse (`changes.csv`); Adressen außerhalb der Domain
  des Herstellers werden abgelehnt.
- **Nur öffentlich**: Ein Dokument mit TLP-Kennzeichnung muss TLP:WHITE oder TLP:CLEAR sein; eines ohne Kennzeichnung
  (Cisco kennzeichnet nicht) nur aus einer nicht anders gekennzeichneten Verteilung. GREEN, AMBER, RED: übergangen.
- **Unverfälscht**: Die Prüfsumme (`.sha512`, sonst `.sha256`) jedes Dokuments muss stimmen, wo der Hersteller eine
  anbietet – sonst wird das Dokument übergangen (zählt unter *Gesundheit* als unlesbar). Nennt der Feed eine Prüfsumme,
  die sich gerade nicht abrufen lässt, wird das Dokument in dieser Runde nicht übernommen (später erneut versucht);
  geratene Prüfsummen-Dateien, die es nicht gibt, fragt Cobe News erst nach einer Weile wieder. Die OpenPGP-Signatur (`.asc`)
  wird **nicht** geprüft: Der Schlüssel liegt auf demselben Server wie das Dokument (mehr als TLS und Prüfsumme brächte
  das nur mit einem unabhängig hinterlegten Schlüssel), und es bräuchte eine eigene OpenPGP-Implementierung.
- **Stand je Anbieter**: eine Marke (Zeit und Adresse des zuletzt gelesenen Dokuments); jede Runde liest nur, was
  danach geändert wurde, das älteste zuerst. Ein Dokument, das vorübergehend scheitert (5xx, Zeitüberschreitung), wird
  in späteren Runden erneut versucht und nach 5 Versuchen oder 24 Stunden aufgegeben – die übrigen Dokumente laufen
  weiter; ein fehlendes, unlesbares oder nicht öffentliches Dokument wird übersprungen. Zeitangaben mehr als einen Tag
  in der Zukunft werden nicht beachtet.
- **Nur für die eigenen Produkte**: Ein Dokument eines Anbieters zählt nur für Produkte, deren Katalog-Hersteller einer
  seiner `vendors` (`csaf.yaml`) ist, und der Hersteller-Zweig im Dokument muss zum Hersteller des Produkts passen. Der
  Namespace des Herausgebers im Dokument muss auf der Domain des Anbieters liegen; Weiterleitungen und der Link auf den
  Hinweis müssen dort bleiben (sonst wird die Adresse des Dokuments selbst verlinkt).
- **Nicht doppelt, nichts überschreiben**: Ein Dokument ersetzt nie den Hinweis eines anderen Herausgebers (etwa einen
  Hinweis des BSI, WID-SEC, oder dieselbe Kennung von einem anderen Anbieter). Siemens- und Cisco-Dokumente teilen sich
  einen Datensatz mit den Siemens- bzw. Cisco-Hinweisen, die über Meldungen kommen – ein Hinweis, ein Befund, eine
  Benachrichtigung.
- **Erstabruf**: Der erste Abruf eines Anbieters reicht 90 Tage zurück. Dokumente, die dabei älter als 7 Tage sind,
  tragen „Erstabruf“ – sie stehen auf der Seite, werden aber nie verschickt; jüngere werden normal gemeldet.
- **cvelistV5 – Zeitplan** (sparsam mit der Bandbreite): Cobe News schaut nur dann nach dem neuesten Release
  (`api.github.com`, eine kleine JSON-Antwort), wenn etwas fällig ist. Die kumulative ZIP-Datei („alles seit
  Mitternacht UTC“) lädt es dreimal am Tag – sobald das Release von 05:00, 11:00 bzw. 17:00 UTC erschienen ist (GitHub
  veröffentlicht jedes stündliche Release etwa 20–40 Minuten nach der Stunde) –, dazu einmal nach dem Tageswechsel den
  Tagesabschluss des Vortags (erscheint gegen 00:30–00:40 UTC; bis 06:00 UTC wird auf einen fehlenden gewartet, damit
  die letzten Stunden des Tages nicht verloren gehen). Etwa 9–11 MB am Tag (Beispiel 29.10.2026: 0,4 + 0,7 + 4,3 +
  5,3 MB) statt ~50 MB bei stündlichem Download; eine Änderung ist nach höchstens etwa 7,5 Stunden da. Rechner im
  Ruhezustand oder App gestoppt: ein verpasster Termin kommt mit dem nächsten oder dem Tagesabschluss, verpasste Tage
  (höchstens 3) über ihre Tagesabschlüsse. Eine unlesbare oder zu große ZIP-Datei eines Tages wird übersprungen (Fehler
  unter *Gesundheit*), die anderen werden gelesen. Einzelabrufe (`raw.githubusercontent.com`): eine gescheiterte Anfrage
  wird in der nächsten Runde wiederholt; als gefragt gilt eine CVE erst nach Erfolg, 404 oder unlesbarem Eintrag.
- **cvelistV5 – was bleibt**: nur Einträge, die ein gefolgtes Produkt betreffen (der Hersteller nennt es, oder die CISA
  nennt eine seiner CPEs), und Einträge, die schon gespeichert sind (eine Änderung); ein zurückgezogener Eintrag wird
  entfernt. Die NVD bleibt für den CPE-Abgleich zuständig.
- **Abschalten**: Ein ausgeschalteter Schalter beendet die Anfragen sofort. Gespeichertes bleibt gespeichert, zählt
  aber nicht mehr bei der Bewertung (EPSS wird nicht mehr angezeigt); wieder eingeschaltet zählt es sofort wieder. Der
  Hinweis auf eine neue Lücke kann ohne cvelistV5 erst über die NVD kommen.

### Exploit-Hinweise (Metasploit, Exploit-DB, nuclei)

`backend/app/exploits.py`: ob es für eine CVE öffentlichen Exploit-Code oder eine fertige Prüfung gibt – als „Exploit
öffentlich“ an Befunden (Dringlichkeit +10, nur wenn nicht schon als ausgenutzt bekannt), in den Details einer Meldung,
bei beobachteten CVEs (Ereignis „Exploit veröffentlicht“, je CVE einmal) und für die Themen der Meldungen (Tabelle
`exploit_refs`: CVE, Quelle, Link, `first_seen`, `baseline` – nie Code). Schalter je Liste unter *Weitere Quellen*
(`exploit_metasploit`, `exploit_exploitdb`, `exploit_nuclei` im Abschnitt `vendor`).

| Liste | Datei | Größe | Lizenz | ab Werk |
|---|---|---|---|---|
| Metasploit (Rapid7) | `raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json` – nur Module vom Typ `exploit` | ~11 MB (gzip ~1,4 MB) | BSD-3-Clause | an |
| nuclei-templates (ProjectDiscovery) | `raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json` (eine JSON-Zeile je Vorlage) | ~2,3 MB (gzip ~0,5 MB) | MIT | an |
| Exploit-DB (OffSec) | `gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` (Spalte `codes`) | ~10 MB, GitLab komprimiert nicht | GPL-2.0 (Repository) | aus |

- Je Liste höchstens einmal am Tag (`vendor_fetch` `exploit:<liste>`), bedingt (ETag/If-Modified-Since), Größenlimit
  24 MB (nuclei 8 MB), über `vendor.get` (Egress-Wächter, Abstand je Host, Pause nach 429/503); nach Fehlern 6 Stunden
  wachsend, höchstens ein Tag. Nur solange gebraucht: wie der KEV (gefolgtes Produkt oder News an) oder eine CVE
  beobachtet wird. Nach außen geht nichts über die Installation – dieselbe öffentliche Datei für alle.
- Metasploit wird Modul für Modul gelesen (nie die 11 MB als ein Python-Objekt). Je CVE ein Link je Liste (der erste
  Eintrag nach Pfad/Name bzw. die kleinste EDB-ID).
- Erstes Laden einer Liste – oder das erste, nachdem sie aus war oder nicht gebraucht wurde (Marker `{"baseline": true}`
  im `cursor` ihres `vendor_fetch`-Eintrags, gesetzt von der Runde; Fehlversuche setzen ihn nicht): `baseline` –
  gezeigt, nie gemeldet. Führt eine Liste eine CVE nicht mehr, geht die Zeile; bringt eine Antwort weniger als die
  Hälfte der gespeicherten CVEs, gilt sie als kaputt (Fehler „list shrank … (n of 3)“, nichts gelöscht, die alten
  Validatoren bleiben) – kommt **dieselbe** Antwort dreimal in Folge, wird sie übernommen (Warnung im Log).
- Download je Liste mit eigener Frist (Metasploit, Exploit-DB 120 s, nuclei 60 s), Weiterleitungen nur auf dem Host der
  Liste (`raw.githubusercontent.com`, `gitlab.com`).
- Thema „Exploit veröffentlicht“ der News: Erstes Laden oder mehr als 2000 geänderte CVEs → alle Themen neu
  (`counters` `news_topics_ask`/`news_topics_done`, Hintergrundjob in Blöcken; was eine Meldung dabei bekommt, steht in
  `news_items.quiet_topics` und löst keine Regel aus). Sonst die geänderten CVEs in `settings` `exploit_retopic`, mit
  der Liste in einer Transaktion gespeichert und direkt danach abgearbeitet (nach einem Absturz in der nächsten Runde).
- Ausgeschaltet: keine Anfrage; Gespeichertes bleibt, wird aber weder gezeigt noch gezählt.
- Verworfen: inoffizielle PoC-Sammlungen (Trickest/cve, PoC-in-GitHub – ungeprüft, teils Schadcode), GitHub Security
  Advisories (keine Exploit-Angaben), Dienste mit Schlüssel und eigenen Bedingungen.
- Gesundheit: Familie `exploit` („Exploit-Hinweise“, Art `structured`).

### Katalog pflegen

Der kuratierte Teil des Katalogs (Anzeigename, Hersteller, CPEs, Versionsschema, Herstellerquelle, Namen in Hinweisen
und CVE-Daten, Suchwörter, Hinweise) sind **Daten, kein Code** – in `backend/app/catalog/`:

```
catalog.yaml              catalog_version (z. B. 2026.10.29-1) und Format – bei jeder Änderung hochzählen
categories.yaml           Kategorien in Anzeigereihenfolge: Schlüssel, Symbol (lucide), Name deutsch und englisch
texts.yaml                Hinweise zu Produkten (hints) und „Wo steht die Version?“ (where), deutsch und englisch
products/<kategorie>.yaml die Produkte einer Kategorie (Dateiname = Kategorie), Reihenfolge und Kommentare bleiben
csaf.yaml                 die CSAF-Anbieter und für welche Hersteller (vendor der Produkte) sie sprechen
cnas.yaml                 CNAs (wer einen CVE-Eintrag schreibt) und welche Hersteller sie sind
build_maps/<name>.yaml    Build-Tabellen: was Admins sehen → was Hinweise vergleichen (app/build_maps.py), je Datei mit
                          Quelle und Abrufdatum: vmware.yaml (vCenter/ESXi, Broadcom KB 326316 / 316595), exchange.yaml
                          (CU/SU → Build), sqlserver.yaml (CU/GDR/KB → Build), vmware_tools.yaml (Code → Version),
                          globalprotect.yaml (Build → Hotfix)
schema/*.schema.json      JSON Schema für Editoren (aus app/catalog_data.py erzeugt, nicht von Hand ändern)
```

**CSAF-Anbieter** – ein Eintrag in `csaf.yaml`:

```yaml
- key: example                     # kurz, eindeutig (unter Gesundheit: csaf:example)
  name: Example Corp PSIRT
  domain: psirt.example.com        # provider-metadata.json: in der Liste des BSI, sonst /.well-known/csaf/
  vendors: [Example Corp]          # Hersteller wie im Feld vendor der Produkte (geprüft)
  # metadata: https://psirt.example.com/csaf/provider-metadata.json   # nur wenn sie anderswo liegt
  # hosts: [example.com]           # erlaubte Hosts der Feeds und Dokumente (Standard: die letzten zwei Teile der domain)
```

Eingetragen: Siemens, Cisco, Schneider Electric, Open-Xchange (0.1.45; seit Katalog 2026.11.03-1 auch für Dovecot –
Hersteller `Dovecot (Open-Xchange)`: die Dokumente `oxdc-adv-…` führen „OX Dovecot CE“ und „OX Dovecot Pro“ im Zweig
„Open-Xchange GmbH“ mit der CPE `a:open-xchange:dovecot`; der Katalog-Eintrag ist Dovecot CE, „OX Dovecot Pro“ zählt
nicht, `excluded_names`). Open-Xchange kennzeichnet seine CSAF-Dokumente (App Suite und Dovecot, geprüft 03.11.2026)
mit **TLP:GREEN** (Weitergabe nur innerhalb der Organisation/Community, nicht öffentlich). Ab Werk wird nur
TLP:WHITE/CLEAR gelesen, solche Dokumente werden abgelehnt (Quellen-Gesundheit: „blocked“); Dovecots Befunde kommen
dann aus den CVE-Einträgen (CNA „OX“: „Open-Xchange GmbH / OX Dovecot CE“) und der NVD.

**TLP:GREEN je Anbieter** – *Integrationen → Vendor News → Weitere Quellen*, Schalter „TLP:GREEN zulassen“ je
Anbieter (Einstellung `vendor.csaf_green`, Liste der Anbieter-Schlüssel, ab Werk leer; Audit: `settings.changed`).
Eingeschaltet liest der Anbieter auch TLP:GREEN-Feeds und -Dokumente (seine Liste wird dafür einmal von vorn gelesen,
Älteres als 7 Tage still wie beim ersten Abruf); jeder solche Hinweis trägt `data.tlp = "GREEN"`, der Befund `tlp`,
und jede Ausgabe kennzeichnet ihn: Karte und Schublade (Zeichen „TLP:GREEN“), Mail/Chat/ntfy/Gotify/Mattermost (Feld
„TLP“, `[TLP:GREEN]` vor dem Titel, auch Web Push), Weiterleiten an Teams, Wochenbericht, Webhook (`tlp`, in
`news.stories` und `news.forward`) und `/api/v1` (`tlp`). AMBER, AMBER+STRICT und RED werden nie gelesen. Öffentliche
Wege gibt es nicht; der Kalender-Feed enthält keine Hinweise (nur Support-Enden). Die Details zu News-Meldungen nehmen
nur öffentliche Dokumente (ein Dokument mit anderem TLP als CLEAR/WHITE wird dort nicht verwendet). Wieder
ausgeschaltet: die gespeicherten TLP:GREEN-Hinweise des Anbieters werden sofort entfernt (und in jeder Runde erneut
geprüft, `csaf_providers.purge_green`), ohne Revision und ohne „zurückgezogen“; noch nicht verschickte Ereignisse
daraus werden still (baseline), verschickte bleiben in der Historie mit Kennzeichnung. Entfernt statt versteckt: wer
TLP:GREEN abschaltet, will solche Inhalte nicht halten – versteckt stünden sie weiter in Datenbank, Sicherung und
Export, und jeder Ausgabeweg bräuchte einen eigenen Filter. Citrix/NetScaler hat keinen CSAF-Anbieter und
keinen Feed der Security Bulletins (geprüft 02.11.2026: BSI-Liste, `/.well-known/csaf/` von citrix.com, netscaler.com,
cloud.com, support.citrix.com; der alte RSS-Feed liefert nur die Webseite) – Citrix-Produkte laufen über die CNA-Daten
der CVE-Liste und NVD, die Webseiten werden nicht ausgelesen.
Nicht eingetragen (bewusst): Red Hat und SUSE (Pakete der Distribution – Vendor News bewertet Distributionen nur nach
Linie und Support), Microsoft (VEX-Dokumente je CVE für alle Produkte – die Build-Grenzen stehen schon in den CNA-Daten
der NVD), Fortinet und Palo Alto Networks (eigene Quellen).

**CNAs** – wer einen CVE-Eintrag geschrieben hat: cvelistV5 nennt die CNA mit Kurznamen (`assignerShortName`, z. B.
`palo_alto`, `GitHub_M`), die NVD mit `sourceIdentifier` (Adresse wie `psirt@fortinet.com` oder die UUID der CNA);
gespeichert als `data.assigner` des Hinweises. Die betroffenen Versionen des Eintrags gelten nur als Wort des
Herstellers („laut Hersteller“, mit Gewicht gegen die NVD-Analyse), wenn die CNA der Hersteller des Produkts ist –
sonst „laut <CNA> (nicht der Hersteller)“, ohne dieses Gewicht. Ohne Eintrag in `cnas.yaml` gilt eine CNA als
Hersteller, wenn ihr Kurzname oder die Domain ihrer Adresse der Name des Herstellers ist: gleich; oder der Name des
Herstellers in ganzen Wörtern, danach nur eine Rechtsform oder Ähnliches (`palo_alto` – Palo Alto Networks, `juniper.net`
– Juniper Networks; Liste `_VENDOR_TAIL` in `app/vendor_match.py`); oder der Name des Herstellers mit einem Anhang der
CNA (`GitHub_P`, `qnapsecurity.com.tw`). Der kürzere Teil hat mindestens 4 Zeichen und ist kein allgemeines Wort
(`cert`, `micro`, `open`, `cloud`, `data`, `net`, `tech`, `systems` … – `_CNA_STOP`): `cert.at` ist nicht cert-manager,
Phoenix Technologies (`phoenix.com`) nicht Phoenix Contact. Sonst gilt sie als Dritter (die sichere Seite). CERT@VDE
und HackerOne schreiben oft für einen Hersteller – der CVE-Eintrag sagt das aber in keinem Feld (nur im Titel und in
`affected[].vendor`), sie bleiben Dritte. Eingetragen werden Dritte, die über fremde Produkte schreiben (GitHub, VulDB, MITRE, HackerOne,
Wordfence, Patchstack, CERTs …), und Hersteller, die die Regel nicht erkennt (die NVD nennt viele CNAs nur mit ihrer
UUID – Werte aus `services.nvd.nist.gov/rest/json/source/2.0`):

```yaml
- key: example                     # kurz, eindeutig
  name: Example Corp               # angezeigt: „laut Example Corp (nicht der Hersteller)“
  ids: [example_psirt, psirt@example.com, 0f0e0d0c-1111-2222-3333-444455556666]   # Kurzname, Adresse, UUID; "*@example.com" = jede Adresse dort
  vendors: [Example Corp]          # Hersteller wie im Feld vendor der Produkte; leer: für kein Produkt der Hersteller
```

Hinweise, die vor 0.1.52 gespeichert wurden, haben bei der NVD noch keine CNA und gelten wie bisher als Wort des
Herstellers; Migration 0036 lässt jede NVD-CPE-Abfrage beim nächsten Lauf einmal vollständig abrufen, dabei bekommen sie
die CNA (cvelistV5-Einträge haben sie schon).

Ein Produkt hinzufügen – in der Datei seiner Kategorie, z. B. `products/firewall.yaml`:

```yaml
- key: example-fw                  # eindeutig, klein, a-z 0-9 . _ -; für ein endoflife.date-Produkt dessen Schlüssel
  label: Example Firewall OS       # Anzeigename
  vendor: Example Corp
  cpes: [o:example:firewall_os]    # NVD-CPE part:vendor:product (ohne Version, ohne *)
  scheme: generic                  # Versionsschema: panos fortios cisco windows vmware ivanti veeam sfos java sap distro cloud generic
  kw: [Example Firewall]           # Wörter, die passende News finden
  example: "7.2.1"                 # Beispielversion; Zahlen wie 8.0 in Anführungszeichen (sonst liest YAML eine Zahl)
  hint: nocpe                      # optional: Hinweis aus texts.yaml
```

Weitere Felder: `eol` (endoflife.date-Schlüssel, wenn er anders heißt), `adv` (`paloalto`, `fortinet`, `veeam` – die
Hinweise des Herstellers), `names` (Produktnamen in diesen Hinweisen), `cna` (`[Hersteller, Produkt]` in den CNA-Daten
der CVE-Einträge), `osv` (`[Ökosystem, Paket]` in OSV, z. B. `[[Maven, org.apache.tomcat:tomcat-catalina]]` – nur
Open-Source-Produkte; Ökosysteme: Go, Maven, npm, NuGet, Packagist, PyPI, RubyGems, crates.io, Hex, Pub, Bitnami), `aliases`, `version_cmd`, `where` (Text aus texts.yaml), `cloud: true` (Dienst ohne eigene Version,
dann `scheme: cloud`), `filter` (ein Wort, das eine CVE nennen muss; mehrere Alternativen mit `|`, z. B. beim Domain
Controller `Active Directory Domain Services|Kerberos|Netlogon|…`), `replaces` (Schlüssel, die in diesem Produkt
aufgegangen sind – ein endoflife.date-Produkt dieses Schlüssels fällt weg, sein Name bleibt als Suchname; die Daten
zieht eine Migration um, z. B. 0025: `db2` → `ibm-db2`; ein Test prüft, dass Katalog und Migration dasselbe sagen),
`depth` (aus wie vielen Teilen eine vollständige
Version besteht, wenn endoflife.date es nicht oder falsch zeigt – weniger Teile gelten als „ungenau“; ohne Release-Daten
und ohne `depth` ist keine Version ungenau). Regeln für eingetragene Versionen (`app/version_input.py`): `pattern`
(regulärer Ausdruck, dem eine Version genügen muss, z. B. nur Builds) mit `pattern_hint` (Text aus texts.yaml),
`normalize` (Anzeigeformen übersetzen: `two_digit_year`, `netscaler`, `ise_patch`, `office_build`, `nginx_plus`,
`checkpoint`, `horizon_yymm`, `leading_zeros` – Exchange `15.02.1748.024` → `15.2.1748.24`, `ipfire_core` – IPFire `2.27 - Core Update 174` → `2.27 Core 174`), `lines_only` (`lts`: nur
die Linien, die endoflife.date als LTS führt, sind die des Produkts – Firefox ESR, Jenkins LTS; `all`: jede gelistete
Linie; eine Version dazwischen auf keiner davon wird abgelehnt, ältere und neuere als die bekannten nicht), `belongs` (`[{pattern, to}]` – Formen eines abgetrennten Produkts, z. B. pfSense Plus bei pfSense CE),
`editions` (Editionen mit gleichen Versionsnummern und ihren Build-Bereichen, z. B. SharePoint 2016/2019/SE),
`line_depth` (Teile, die eine Linie mit eigenen Zeilen in CVE-Einträgen bilden, Exchange: 3) und `cpe_editions`
(`[cpe, sw_edition]` – nur diese Editionen einer CPE zählen, Firefox `esr`, Jenkins `lts`), `excluded_names`
(Produktnamen in CSAF-Dokumenten und CNA-Zeilen, die trotz passender CPE ein anderes Produkt sind – Dovecot:
`OX Dovecot Pro`). Gegen die Release-Linien
von endoflife.date wird jede Version auf Plausibilität geprüft. Eine Build-Tabelle (`kind: names`) nennt `products`,
`sources`, `fetched`, optional `strip`, `extract`, `claims`, `hint` und `rows: [{value, names}]` – ein Name, den die
Tabelle zweimal vergibt, stoppt den Start. Ein Eintrag ohne `label` verschiebt nur ein
endoflife.date-Produkt in diese Kategorie (erlaubt dann nur `vendor`, `cpes`, `scheme`, `hint`, `osv`, `aliases`, `replaces` und
die Versionsregeln `pattern`, `pattern_hint`, `normalize`, `belongs`, `cpe_editions`, `lines_only`). Ein Produkt ohne CPE in der NVD
bekommt `cpes: []` und `hint: nocpe`.

**Hersteller** – endoflife.date nennt keinen; ohne `vendor` nimmt der Katalog das erste Wort des Namens („Red Hat
Satellite“ → „Red“) oder den Hersteller der CPE („a:djangoproject:django“ → „Djangoproject“). Deshalb trägt ein Eintrag
ohne `label` den Hersteller, wo das falsch wäre (seit Katalog 2026.11.06-3 für alle so entstandenen). Jeder Hersteller hat
**eine** Schreibweise – die offizielle („IBM“, „Red Hat“, „SUSE“, „Grafana Labs“, „Apache Software Foundation“), in allen
Dateien gleich (auch `csaf.yaml`, `cnas.yaml`). Eine Marke mit eigenem Namen, die einem anderen gehört, heißt „Eigentümer
(Marke)“ bzw. „Marke (Eigentümer)“ – „Broadcom (VMware)“, „Broadcom (Symantec)“, „Splunk (Cisco)“, „Datto (Kaseya)“ – und
ist ein eigener Hersteller („VMware (alle Produkte)“ umfasst kein Symantec); ein bloßes Produkt eines Herstellers hat
keine Klammer (Dockge ist „Louis Lam“, Velociraptor „Rapid7“, PingCastle „Netwrix“). Ein Hersteller, der nur ein
gewöhnliches Wort ist, nennt in Meldungen niemanden („Linux“ – der Kernel ist „Linux Kernel Organization“). Wird eine
Schreibweise geändert, zieht eine Migration die Regeln mit (0041 für Katalog 2026.11.06-3, ein Test vergleicht sie mit
dem Katalog).

**CPE prüfen** – gibt es sie im CPE-Verzeichnis der NVD? Im Katalog „Nicht im Katalog?“ suchen (dieselbe Abfrage) oder
`https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:o:example:firewall_os` (ohne Schlüssel
höchstens 5 Anfragen in 30 s). Ob es CVEs dazu gibt: `…/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:example:firewall_os&resultsPerPage=1`.

**Prüfen und testen** – danach `catalog_version` in `catalog.yaml` hochzählen und einen Eintrag im CHANGELOG:

```bash
cd backend
uv run python -m app.catalog_data                  # prüft alle Dateien – Fehler nennen Datei und Produkt
uv run python -m app.catalog_data --write-schema   # nur nach Änderungen an app/catalog_data.py (Schema neu erzeugen)
uv run pytest -q tests/test_catalog_data.py tests/test_vendor_catalog.py tests/test_catalog_accuracy.py
```

Geprüft werden (beim Start der App und in den Tests): Schema jeder Datei (unbekannte Felder, `8.0` statt `"8.0"`),
eindeutige Schlüssel über alle Dateien, bekannte Kategorien, CPE-Form, bekannte Schemata und Herstellerquellen,
Hinweise, „where“-Texte und Kategorien in Deutsch und Englisch, die Build-Tabellen (jeder Wert eine Version des
Produkts, kein Name doppelt), die Versionsregeln (reguläre Ausdrücke, Zielprodukte, Editionen); in den Tests außerdem,
dass jedes Beispiel vom eigenen Produkt angenommen wird, jedes Produkt mit eigenem Schema ein Beispiel hat und keine CPE
in zwei Produkten steht, ohne dass eines sie per `filter`/`cpe_editions` eingrenzt oder das Paar im Test begründet ist
(`tests/test_catalog_ext.py`). Ein Fehler stoppt den Start mit Datei und Produkt –
der Katalog kommt mit dem Image, die Tests fangen das vor einem Release.

**Katalog-Pflege (Selbsttest)** – *Einstellungen → Integrationen → Vendor News → Katalog-Pflege* zeigt, welche
Einträge Pflege brauchen, mit Grund („CPE a:example:fw existiert nicht in der NVD“, „seit 40 Monaten keine CVE-Daten“,
„endoflife.date kennt den Schlüssel nicht mehr“), Filter gefolgte/alle, letzte Prüfung und „Jetzt prüfen“. Gefolgte
Produkte mit einem Problem zeigen es zusätzlich in ihrer Schublade. Geprüft wird (`backend/app/catalog_check.py`):

| Prüfung | Woher | Ergebnis |
|---|---|---|
| CPE im CPE-Verzeichnis der NVD (`cpeMatchString`) | NVD, eine Anfrage je CPE | fehlt: **Fehler**; nur veraltete Einträge: Warnung mit Nachfolger |
| CVEs zur CPE in den letzten 3 Jahren | gefolgte Produkte: die schon geholten NVD-Daten; sonst NVD (Anzahl und neueste CVE, zwei Anfragen) | keine oder älter: Warnung (nicht bei Cloud-Diensten) |
| endoflife.date-Schlüssel | die zuletzt geholte endoflife.date-Liste (keine eigene Anfrage) | unbekannt: **Fehler**; anderer Hersteller in den CPEs: Warnung |
| letzter Hinweis des Herstellers (Palo Alto, Fortinet, Veeam) | gespeicherte Hinweise gefolgter Produkte | älter als 2 Jahre: Warnung |
| gefolgt, aber ohne CPE | Katalog | Warnung (nur Hinweise und News) |

Anfragen an die NVD laufen über dieselbe Bremse wie Vendor News (6,5 s Abstand ohne Schlüssel, gemeinsame Pause nach
429) und nur, wenn Vendor News an ist, einem Produkt gefolgt wird und die Vendor-News-Runde gerade nicht läuft:
gefolgte Produkte **wöchentlich**, der ganze Katalog **monatlich**, höchstens **20 Anfragen pro Stunde** – über die
Stunde verteilt (alle 10 Minuten höchstens 4) und auch über einen Neustart hinweg gezählt (in der Datenbank). Rechnung:
rund 770 CPEs × höchstens 3 Anfragen ≈ 2 300 Anfragen im Monat (im Mittel gut 3 pro Stunde); mit der Grenze von 20 pro
Stunde (rund 3 % dessen, was die NVD ohne Schlüssel erlaubt: 5 in 30 s) dauert der erste ganze Durchlauf etwa fünf
Tage, danach kommt jede CPE 30 Tage nach ihrer letzten Prüfung wieder dran. „Jetzt prüfen“ (höchstens alle 10 Minuten)
fragt die CPEs der gefolgten Produkte sofort (höchstens 60 Anfragen). Ein Fehler wird korrigiert, indem man den Eintrag
in `backend/app/catalog/` ändert (oben) – er kommt mit dem nächsten Update.

Die **Katalogversion** steht unten im Katalog und auf „Version & Changelog“ und zählt getrennt von der App. Ein mit
endoflife.date neu gebauter Katalog (`data/vendor_catalog.json`) merkt sich den Fingerabdruck der Katalogdaten; ändern
sich die Daten mit einem Update, werden sie beim Laden neu angewandt – ohne auf die nächste Aktualisierung zu warten.

**Neu verknüpfen nach einer Katalogänderung** – neue Namen oder CPEs eines Produkts (z. B. CNA-Namen wie „Exchange
Server Subscription Edition“) verknüpfen von sich aus nur neue oder geänderte Hinweise. Deshalb verknüpft die
Vendor-News-Runde einmal je `catalog_version` die gespeicherten Hinweise neu mit den gefolgten Produkten
(`vendor.relink_catalog`): zehn Produkte je Runde, der Stand steht in der Einstellung `catalog_relink` (Version,
erledigte Produkte) – ein Neustart macht weiter, nichts doppelt. So gefundene Verknüpfungen sind **still**
(`vendor_advisory_products.quiet`, Migration 0028): ein Befund, den es nur durch sie gibt, erscheint in der Ansicht,
wird aber nicht gemeldet (wie die Grundlinie eines neu gefolgten Produkts) – eine Katalogänderung ist keine Neuigkeit,
und die Hinweise sind alt. Wird ein Hinweis später neu gespeichert (die Quelle ändert ihn), gilt seine Verknüpfung
wieder normal. Dasselbe gilt für neue CPEs aus der täglichen endoflife.date-Aktualisierung.

**Signierte Katalog-Updates (geplant, nicht gebaut)** – heute kommen Katalog-Änderungen mit dem Image. Später soll ein
Katalog auch ohne neues Image kommen können:

- Ein Bundle (`cobe-news-catalog-<catalog_version>.tar`) enthält genau dieses Verzeichnis und ein Manifest
  (`catalog_version`, `format`, die kleinste App-Version, SHA-256 jeder Datei), signiert mit Ed25519. Der öffentliche
  Schlüssel steht fest im Image; ohne gültige Signatur, mit anderem `format` oder älterer `catalog_version` als der
  mitgelieferten wird nichts übernommen.
- Abruf nur auf Wunsch (Einstellung, aus ab Werk) von einer festen https-Adresse, mit denselben Grenzen wie die Feeds
  (Größe, Zeit, keine internen Ziele); das Bundle wird mit derselben Prüfung wie beim Start (`catalog_data.load(Verzeichnis)`)
  geprüft, bevor es nach `data/catalog/<catalog_version>/` gelegt und atomar aktiv geschaltet wird. Die vorige Version
  bleibt liegen (zurück per Knopf), die mitgelieferte gilt immer als Rückfall.
- Texte (Kategorien, Hinweise) kommen mit den Daten – deshalb liefert die Oberfläche sie aus `/api/vendor/catalog/meta`
  statt aus ihren eigenen Übersetzungen.

### Details aus der Quelle

Zu jeder Meldung holt Cobe News das strukturierte Advisory dahinter und zeigt es in der Schublade über dem Text als
**„Betroffene Versionen“** – je Produkt die betroffenen Bereiche und die Fix-Versionen, CVSS, die CVEs (kopierbar),
„Remote angreifbar“, „Workaround/Mitigation vorhanden“, „Stand: Update vom …“ und die Herkunft. Die Kachel zeigt CVSS
und „betrifft GitLab <19.5.1“. Folgt ihr dem Produkt in Vendor News, steht dort **„Betrifft deine Systeme“** mit den
betroffenen Versionseinträgen; BSI-, Siemens- und Cisco-Advisories werden auch zu Befunden in Vendor News (und lösen
die Regel-Art „Schwachstelle betrifft eines unserer Systeme“ aus).

| Quelle der Meldung | Woher die Details | Was es gibt | Was nicht |
|---|---|---|---|
| BSI CERT-Bund (WID) | CSAF 2.0: `wid.cert-bund.de/.well-known/csaf/white/<Jahr>/wid-sec-w-<Jahr>-<Nr>.json` | Produkte mit Bereichen („<19.5.1“), Fix-Versionen (mit CPE), CVEs, Einstufung (hoch …), Revisionen („Neue Updates von Red Hat aufgenommen“) | CVSS und „Remote“ stehen nicht im CSAF (CVSS kommt aus der NVD der ersten CVEs; „Remote“ aus dem Text „entfernter Angreifer“); TLP:GREEN-Advisories sind nicht öffentlich |
| Siemens ProductCERT | CSAF 2.0: `cert-portal.siemens.com/productcert/csaf/ssa-<Nr>.json` | Produkte und Bereiche, CVSS mit Vektor, Remediations, Revisionen | – |
| Cisco PSIRT | CSAF 2.0: `sec.cloudapps.cisco.com/…/CiscoSecurityAdvisory/<id>/csaf/<id>.json` | betroffene Versionen einzeln (Service Packs), CVSS, Revisionen | Cisco nennt die Fix-Versionen nur über den Software Checker |
| Fortinet PSIRT | CSAF 2.0 (Adresse aus dem PSIRT-RSS, nur die neuesten 50) | Bereiche je Produkt, nicht betroffene Linien, Fix je Linie, Workarounds/IPS-Signaturen | ältere Advisories: dann NVD |
| Palo Alto Networks | CVE-5-JSON: `security.paloaltonetworks.com/json/<id>` | Bereiche mit Hotfix-Ständen, CVSS 4.0, Lösung, Workaround, Ausnutzung | – |
| Veeam Security (KB) | der Text der Meldung selbst (der KB-Artikel aus dem Feed) – keine Anfrage, derselbe Parser wie Vendor News | betroffene Builds je Produkt und Linie, Fix-Builds, CVEs, CVSS 4.0/3.1 mit Vektor, „Mitigation vorhanden“ | „List of Security Fixes and Improvements“ (keine Hinweise) |
| CISA KEV, ENISA EUVD | die Meldung selbst + NVD | ausgenutzt, Frist, Ransomware, CVSS/EPSS, Bereiche aus der NVD | – |
| alle anderen mit CVE | NVD API (bis 3 CVEs je Meldung), **„aus NVD“** | CVSS, CPE-Bereiche, Fix-Version (Ende des Bereichs), „von CISA als ausgenutzt gelistet“ | Text-Meldungen ohne CVE (keine Details); NVD hängt oft Tage hinterher |

Hat die NVD eine CVE der Meldung noch nicht analysiert (kein Eintrag oder keine CPE-Konfiguration), kommen Bereiche,
CVSS, SSVC und KEV aus dem CVE-Eintrag von cvelistV5 („ergänzt aus der CVE-Liste“, höchstens 15 Einträge je Runde, wenn
die Quelle an ist). Zu jeder CVE der Meldung steht ihr EPSS, sobald FIRST gefragt wurde.

Abruf im Hintergrundtask von Vendor News (gleiche Härtung, je Host Mindestabstand, NVD höchstens 5 Anfragen / 30 s
ohne Schlüssel): je Runde bis 25 Advisory-Dokumente und 8 NVD-Abfragen (40 mit Schlüssel), neueste Meldungen zuerst.
Je Advisory eine Anfrage; Meldungen jünger als 30 Tage werden täglich neu geprüft, eine Meldung, deren Titel sich
ändert („[UPDATE] …“), sofort. Eine unbekannte CVE fragt die NVD höchstens einmal pro Woche. Abschalten:
*Einstellungen → Integrationen → News*, Schalter „Details aus der Quelle“ (ab Werk an). **Ausgehend** zusätzlich zu den
Feeds: `services.nvd.nist.gov` (für Meldungen mit CVE), sonst dieselben Hosts wie die eingeschalteten Quellen
(`wid.cert-bund.de`, `cert-portal.siemens.com`, `sec.cloudapps.cisco.com`, `filestore.fortinet.com`,
`security.paloaltonetworks.com`).

**Gefolgte Produkte einer Meldung** (`news_items.products`, Filter „Betrifft unsere Produkte“): berechnet, sobald die
Details einer Meldung ankommen (dieselbe Prüfung wie „Betrifft deine Systeme“), und im selben Hintergrundtask nach jeder
Details-Runde für die Produkte, deren Folgen oder Versionen sich geändert haben – erkannt an einem Fingerabdruck je
Produkt in der Einstellungszeile `news_products`. Entfolgte Produkte gehen per SQL aus allen Listen, geänderte werden in
Blöcken von 500 Meldungen neu bewertet (abseits der Ereignisschleife). Nach dem Update auf die Version mit Migration 0026
läuft das einmal für alle gespeicherten Meldungen. Kein zusätzlicher Abruf. Neu berechnen erzwingen:
`DELETE FROM settings WHERE key = 'news_products';` – die nächste Runde rechnet alles neu.

**Systeme einer Meldung** (`news_items.systems`, für die Regel-Filter „Systeme“, `app/systems.py`): Katalogschlüssel
der Produkte, die ihre Details betreffen (derselbe Abgleich wie oben, gegen den **ganzen** Katalog, ohne Versionen –
erst die Wörter der Details wählen Kandidaten, dann entscheidet der Abgleich), dazu `m:<Schlüssel>` / `v:<Hersteller>`
für das, was Titel oder Teaser nennen (ganze Wörter; Namen aus gewöhnlichen Wörtern nur mit dem Hersteller, einige
bekannte auch im Zusammenhang einer Sicherheitsmeldung – `systems.CONTEXT`). Hersteller sind Identitäten: die
Schreibweisen einer Marke („VMware“ / „Broadcom (VMware)“, „Apache“ / „Apache Software Foundation“, „LANCOM“ / „LANCOM
Systems“ …) sind ein Hersteller (`v:<Gruppe>`, `GET /api/vendor/catalog` liefert je Produkt `vendor_group`); Regeln mit
jeder Schreibweise gelten weiter. Berechnet
beim Speichern und bei geändertem Titel/Teaser (Nennungen), beim Eintreffen der Details (Schlüssel) – und im
Hintergrund (Schritt „systems“ der News-Runde) einmal nach dem Update auf Migration 0039 für alle Meldungen, danach nur
für Katalogprodukte und Hersteller, deren Katalog-Eintrag sich geändert hat (Fingerabdruck je Produkt über die Felder,
die der Abgleich liest – nicht Beispiel, Versionsbefehl oder Hinweis –, in der Einstellungszeile `news_systems`), in
Blöcken von 500; eine neue Abgleich-Version (`SYSTEMS_V`) rechnet alle Meldungen neu. Was so dazukommt, ist **leise** (`news_items.quiet_systems`):
Regeln verschicken deshalb keine ältere Meldung; der Probelauf zählt sie mit (er zeigt, was eine Regel abdeckt). Neu berechnen erzwingen:
`DELETE FROM settings WHERE key = 'news_systems';`. Migration 0039 fügt nur Spalten mit festem Standardwert und einen
GIN-Index hinzu (`notify_rules.systems|keywords|exclude`, `news_items.systems|quiet_systems`); der Downgrade entfernt sie
und die Einstellungszeile.

Dieselben Filter gibt es außerhalb der Regeln – eine Umsetzung (`app/concerns.py`, Prüfung der Eingaben und SQL):
der Filter „Systeme“ der News-Liste (`GET /api/news?system=v:<Hersteller>&system=p:<Schlüssel>`, höchstens 50, auch
`POST /api/news/read-all`; zählt auch leise Systeme, über den GIN-Index `ix_news_items_systems`), die eigene Wahl
der Desktop-Benachrichtigungen (`users.desktop` – `systems`, `keywords`, `exclude`; gefiltert auf dem Server für
`/api/news/recent?mine=true` und Web Push, nur laute Systeme, mit `hits` für „Treffer“) und „Hersteller-News meiner
Produkte“ (`person_notify.systems`, Migration 0040 – eine Spalte mit festem Standardwert `'[]'`, der Downgrade entfernt
sie; nur das Produkt des Ereignisses, beobachtete CVEs nie). Die News-Liste nimmt dazu `without=<Wort>` („Ohne …“,
höchstens 30 Wörter, geprüft wie bei den Regeln, auch `POST /api/news/read-all`): ein regulärer Ausdruck je Zeile, den
kein Index trägt – die Liste selbst liest über den Datums-Index nur bis zur vollen Seite (rund 1 ms), die Zahlen der
ersten Seite lesen jede passende Zeile. Gemessen bei 30 000 Meldungen ohne weitere Filter: ohne „Ohne“ rund 36 ms für
die erste Seite mit allen Zahlen, mit einem Wort rund 105 ms, mit drei Wörtern rund 180 ms (die Themen-Zahlen prüfen das
Wort nur bei Meldungen mit Thema).

**Security-Meldungen per E-Mail oder Teams** (`app/personal_news.py`, Tabellen `person_news` und `person_news_sent`,
Migration 0042 – zwei neue Tabellen, der Downgrade entfernt sie): je Person die Auswahl wie bei einer Regel (derselbe
Abgleich `notify.news_filter`), je Weg (E-Mail, eigener Teams-Webhook aus `person_notify`) ab welcher Ankunftsnummer
(`<weg>_on_seq`, beim Einschalten die neueste). Fällig ist eine Meldung, die danach eintraf, höchstens eine Woche alt
ist, auf diesem Weg noch nicht gesendet wurde (`person_news_sent`) und jetzt passt – wie bei einer Regel auch, wenn sie
erst später passt (laute Änderung: Schwere, Titel/Teaser, Thema, System in `news_items.changes`, frische weitere Quelle
`news_item_sources.carried_at`). Nach dem Erweitern der Auswahl (`filter_seq`/`filter_at`) zählt eine ältere Meldung
nur durch eine Änderung danach. Eine Runde (Schritt „personal news“ nach den persönlichen Benachrichtigungen) schreibt
die Meldungen einer Nachricht als gesendet und markiert die Inanspruchnahme (`<weg>_claim_at`) in einem Commit vor dem
Senden: nie doppelt; ein Fehler, bei dem sicher nichts ankam, nimmt sie zurück (wachsende Pause `<weg>_next_at`,
höchstens 12 Versuche), eine nach einer Stunde verwaiste Inanspruchnahme wird aufgegeben, ihre Meldungen bleiben
gesendet. Höchstens eine Nachricht je 15 Minuten und Weg (`<weg>_sent_at`), bis zu drei Meldungen einzeln, mehr als eine
Sammelnachricht (zehn gelistet, höchstens 200 je Nachricht). Fällig (an, erlaubt, keine Pause, außerhalb der 15 Minuten)
entscheidet SQL; je Runde höchstens 500 Person-Wege und 30 Sekunden, die am längsten nicht angesehenen zuerst
(`<weg>_seen_at` – auch wer gerade Ruhezeit hat, wird markiert und hält niemanden auf). Gleich weiter (ohne Pause der
Hintergrundrunde) nur, solange ein fälliger Person-Weg in diesem Durchgang noch nicht angesehen wurde. Neu beurteilt wird
je Runde nur, was seit der letzten Beurteilung dieses Wegs eintraf oder sich änderte (`<weg>_checked_seq` / `_at`, mit
zehn Minuten Rückblick für spät festgeschriebene Änderungen) – gemessen bei 30 000 Meldungen in der Woche rund 10 ms je
Person-Weg (die erste Beurteilung nach dem Einschalten liest, was seitdem eintraf). `person_news_sent`
wird nach acht Tagen aufgeräumt (stündlich, „personal news“). Admin-Schalter: Einstellung `teams.personal_news` (ab
Werk aus) plus die Wege `personal_email` / `personal_teams`; solange ein Weg nicht erlaubt, die Person abwesend oder
ein Konto aus ist, rückt `<weg>_on_seq` mit (kein Nachschub beim Einschalten). API: `GET`/`PUT /api/me/news-notify`
(nur die eigenen Einstellungen; ausschalten und die Auswahl ändern auch, solange der Admin es aus hat).

**Themen** (`news_items.topics`): Das Thema „Exploit veröffentlicht“ (`poc`) kommt aus der SSVC-Einstufung der CISA in
den gespeicherten cvelistV5-Einträgen (und dem Wortlaut); ändert sich die Einstufung beim Speichern eines Eintrags,
werden die Meldungen zu dieser CVE neu berechnet. Dazu kommen die eingeschalteten Exploit-Sammlungen (`exploit_refs`,
aus dem Speicher): Neue oder gestrichene CVEs einer Sammlung berechnen die Meldungen zu diesen CVEs sofort neu (bis
2000 CVEs auf einmal); das erste Laden einer Sammlung, mehr Änderungen auf einmal und das Ein- oder Ausschalten einer
Sammlung setzen `news_topics_v` zurück – der Themen-Job rechnet dann alle Meldungen in Blöcken neu. Mit der neuen
Regel-Version (`news_topics_v` 2) berechnet der Themen-Job alle gespeicherten Meldungen einmal neu.

## Benachrichtigungen

*Einstellungen → Kanäle & Regeln* hat zwei Reiter:

- **Kanäle** – *wohin*: Art, Ziel und Geheimnis, eigener „Testen“-Knopf, eigener letzter Fehler und eigene Pause nach
  Fehlern. Ganz oben die Zeile **E-Mail-Server** (Server:Port · eingerichtet / nicht eingerichtet, „Bearbeiten“ öffnet
  die Schublade mit den SMTP-Einstellungen und der Testmail). Ein neuer E-Mail-Kanal ohne eingerichteten Server fragt in
  seiner Schublade zuerst nach dem Server; E-Mail-Kanäle ohne Server zeigen „E-Mail-Server fehlt“.
- **Regeln** – *was*: Name, an/aus, Schweregrade (z. B. nur Kritisch + Hoch), Quellen (leer = alle), bei News Themen
  (`notify_rules.topics`, eines genügt, leer = jede Meldung), „Betrifft“: Systeme aus dem Katalog
  (`notify_rules.systems`, Hersteller oder Produkt – auch für Vendor News) oder Schlagwörter (`notify_rules.keywords`),
  „Nicht senden, wenn enthalten“ (`notify_rules.exclude`, nur News), Sprache und
  **ein oder mehrere Kanäle**. Arten: News, Vendor News (Schwachstellen; neue Versionen und Support-Ende) und
  *Quelle gestört oder tot* ([Quellen-Gesundheit](#quellen-gesundheit) – Schweregrade und Quellen gelten dafür nicht).

| Kanal | Ziel | Format |
|---|---|---|
| E-Mail | Empfänger (eine Adresse pro Zeile, max. 20), Server in der Zeile *E-Mail-Server* über den Kanälen | HTML + Text |
| Microsoft Teams | Workflows-URL („Bei Empfang einer Webhookanfrage in einem Kanal posten“) oder Incoming Webhook | Adaptive Card |
| Slack | Incoming-Webhook-URL (`https://hooks.slack.com/services/…`) | Block Kit |
| Discord | Webhook-URL (`https://discord.com/api/webhooks/…`, auch `discordapp.com`) | Embeds, `allowed_mentions: {parse: []}` |
| Telegram | Bot-Token (@BotFather) + Chat-ID (`-100…` für Kanäle/Supergruppen, `-…` für Gruppen oder `@name`) | `sendMessage`, `parse_mode` HTML |
| Webhook | eigene URL (z. B. n8n), optional HMAC-Signatur und eigener Auth-Header | JSON, Version 1 (unten) |

- Nach jeder Abrufrunde: jede Meldung **höchstens einmal pro Kanal** – auch wenn zwei Regeln sie an denselben Kanal
  schicken. Eine neue (oder wieder eingeschaltete) Regel und ein Kanal, der einer Regel später hinzugefügt wird, gelten
  nur für Meldungen, die **danach** eintreffen – kein Schwall alter Meldungen. Ebenso eine Regel, deren Filter erweitert
  wird (mehr Schweregrade, Quellen, Themen oder Arten): was erst dadurch passt, kommt ab der Änderung (Eingangsnummer der
  Meldung, bei Vendor News der Zeitpunkt); was schon vorher passte und noch offen ist, kommt weiterhin. Ändert sich eine
  ältere Meldung danach laut, wird je Merkmal geprüft (`news_items.changes`: Anstieg der Schwere mit der Schwere davor,
  frühere Suchtexte bei geändertem Titel/Teaser, Zeit je laut gewonnenem Thema und System;
  `news_item_sources.carried_at`: Zeit eines frischen Mitführens): sie kommt nur, wenn sie in jedem Merkmal, das der
  Filter davor einschränkte, zu ihm passt – oder in diesem Merkmal zum Zeitpunkt der Erweiterung noch nicht zum
  erweiterten Filter passte und erst die Änderung danach sie passend machte. Eine Änderung eines anderen Merkmals
  (frisch mitgeführt, Details eingetroffen, wenn nur Schweregrade erweitert wurden) bringt keine alte Meldung. „Ab jetzt“ zählt bei News nach der Eingangsnummer
  (`notify_rules.active_seq`, `notify_rule_channels.added_seq` – Regeln und Verknüpfungen von vor 0.1.53: der
  Zeitpunkt): eine Meldung aus einem Abruf, der beim Speichern lief, kommt mit. Vendor-News-Ereignisse tragen die Zeit,
  zu der ihr Produkt geschrieben wird (nicht den Beginn der Runde).
- Eine weitere Quelle, die eine Meldung nur mitführt („auch in“, `news_item_sources`), zählt für eine Regel nur, wenn
  sie sie **frisch** brachte (`fresh`: nach derselben Regel wie `backlog`) – eine spät eingeschaltete Quelle bringt keine
  Sammelnachricht alter Meldungen anderer Quellen, und ihre Einstufung hebt sie nicht an. Migration
  `0038_rule_delivery_fixes`: bestehende Verknüpfungen gelten als frisch nur bei Meldungen des letzten Tages (was eine
  Runde noch offen haben kann), alle anderen als nicht frisch; die neuen Spalten sind leer.
- Vendor News: Wird ein bekannter Befund später höher eingestuft (NVD bewertet eine CVE erst nach Tagen), kommt ein
  Ereignis „Jetzt höher eingestuft“ (`rated:<Schwere>:<Scope>:<Befund>`) – nur nach oben, je Stufe einmal, still wie
  ein neues (Erstabruf, älter als 30 Tage, Erstbefüllung). Die erste Prüfung nach dem Update auf 0.1.53 merkt sich die
  Einstufungen nur, ohne zu senden – je Produkt bei dessen erster Prüfung (Zähler `vendor_rated_primed:<Produkt>`; ein
Produkt, dessen Quellen noch nicht geantwortet haben, wird erst dann vorbereitet). Eine Regel, die beide Stufen abdeckt,
bekommt so eine zweite Nachricht zum selben Befund.
- Jede Runde schaut nur nach, wenn sich etwas getan hat: eine neue Meldung oder ein neues Vendor-News-Ereignis, ein
  geänderter Kanal, eine geänderte Regel oder der E-Mail-Server, geänderte Themen einer Meldung (eine Regel mit Themen
  verschickt eine Meldung, die ihr Thema erst später bekommt, dann – einmal), oder die Pause eines Kanals ist um. Sonst kostet sie
  zwei kleine Abfragen statt eines Durchgangs durch alle Regeln (bei großen Datenbanken bis zu einer Sekunde). Alle
  10 Minuten wird trotzdem alles angesehen – eine Meldung, die inzwischen höher eingestuft ist oder von einer weiteren
  Quelle kommt, folgt damit spätestens dann.
- Bis zu 3 Treffer einer Runde kommen einzeln, mehr als **eine Sammelnachricht** (die 10 wichtigsten, Rest gezählt).
- Die Kanäle werden nebeneinander beliefert, jeder mit eigener Frist (Timeouts überall, nichts blockiert die App): ein
  langsamer oder kaputter Kanal hält die anderen nie auf. Fehlschlag: die Meldungen bleiben für diesen Kanal offen,
  neuer Versuch nach wachsender Pause (2 Min. … 6 Std.); verlangt der Dienst mit HTTP 429 eine Wartezeit (Discord
  `retry_after`, Telegram `parameters.retry_after`, sonst `Retry-After`), wartet Cobe News mindestens so lange – bis
  5 Sekunden direkt, sonst bis zur nächsten Runde. „Testen“ schickt sofort eine Testnachricht und markiert nichts als
  verschickt; kommt sie an, verschwinden der alte Fehler und die Pause (was auf den neuen Versuch wartet, geht in der
  nächsten Runde raus). Ein „nächster Versuch“ wird nur angezeigt, solange er in der Zukunft liegt. Speichern des
  E-Mail-Servers startet die E-Mail-Kanäle ohne Pause und ohne alten Fehler neu.
- **Mindestens einmal**: Jede Nachricht wird direkt nach dem Versand in einer eigenen kurzen Transaktion als verschickt
  vermerkt, jeder Kanal für sich. Eine Meldung, eine Regel oder ein Kanal, die währenddessen gelöscht werden, oder ein
  Schreibfehler bei einem Kanal machen nichts bei den anderen rückgängig. Stirbt der Prozess oder scheitert die
  Datenbank genau zwischen Versand und Vermerk, kommt die Nachricht beim nächsten Mal noch einmal – der Webhook behält
  dafür dieselbe `id` (unten).
- **Geheimnisse** – Webhook-URLs, das Telegram-Bot-Token, HMAC-Geheimnis und Wert des Auth-Headers, das SMTP-Passwort:
  verschlüsselt gespeichert (Schlüssel `SECRET_KEY` oder `./data/secret.key`, 0600), nie an den Browser zurückgegeben
  (er sieht nur „gesetzt“ und den Host); leeres Feld beim Speichern behält den alten Wert. Zeigt ein Webhook auf einen
  **anderen Host** (oder wechselt https → http), müssen HMAC-Geheimnis und Header-Wert neu eingegeben werden. Das
  Telegram-Token steht im Pfad der API-URL – das Anfrage-Log von httpx ist deshalb abgeschaltet (und filtert URLs).
- **Text aus den Feeds** (Titel, Zusammenfassung, Link) wird je Format entschärft: kein `<!channel>` in Slack, kein
  `@everyone` / `<@id>` in Discord, keine eigenen Markdown-Links in Teams, HTML-Escaping für Telegram und Mail; Links
  nur `http(s)`, Sonderzeichen darin prozentkodiert.
- **Ziele:** Teams/Slack nur per https an `hooks.slack.com`, `*.webhook.office.com`, `*.logic.azure.com`,
  `*.powerplatform.com` (eigene Hosts: `WEBHOOK_HOSTS`); Discord nur `discord.com`/`discordapp.com` mit Pfad
  `/api/webhooks/…`; Telegram nur `api.telegram.org`. Alle Kanäle (auch der **Webhook**) gehen ab Werk nur an
  **öffentliche** Adressen. `WEBHOOK_PRIVATE_NETS` (kommagetrennt, Adressen oder Netze, z. B.
  `10.20.0.0/16,192.168.10.5`) erlaubt zusätzlich: private Adressen (RFC 1918, IPv6-ULA …, z. B. n8n nebenan), die
  eigenen Docker-Netze (aus `/proc/net/route`; z. B. ein Empfänger im Netz `edge`: `WEBHOOK_PRIVATE_NETS=172.31.250.50`)
  und den **Docker-Host** über seine Adresse – das Gateway des Containers oder Docker Desktops Host-Netz
  `192.168.65.0/24` (dahinter erreicht man Dienste, die auf dem Rechner nur an 127.0.0.1 lauschen, und sie sähen die
  Anfrage als „localhost“ – darum nur ausdrücklich). **Immer** gesperrt, auch wenn sie in `WEBHOOK_PRIVATE_NETS` oder
  `SMTP_ALLOW_INTERNAL` stehen: Loopback (`127.0.0.0/8`, `::1`), Link-Local (`169.254.0.0/16` samt Cloud-Metadaten
  `169.254.169.254`, `fe80::/10`, AWS' IPv6-Metadaten `fd00:ec2::254`), „dieses Netz“/„any“ (`0.0.0.0/8`, `::`) und
  Multicast – auch versteckt in IPv4-mapped-, NAT64-, 6to4-, IPv4-compatible/-translated-Adressen. Namen des
  Docker-Hosts (`host.docker.internal`, `gateway.docker.internal`, `host.lima.internal` …) lehnt ein Webhook immer ab.
  Ein Dienst auf dem Host-eigenen 127.0.0.1 ist also über die Adresse des Docker-Hosts zu erreichen (Gateway bzw. die
  Adresse hinter `host.docker.internal`, in `WEBHOOK_PRIVATE_NETS`), nie über 127.0.0.1 (das wäre der Container). Der Name wird
  einmal aufgelöst, geprüft und genau diese Adresse verbunden (kein DNS-Rebinding); Weiterleitungen werden nicht
  verfolgt. http nur mit dem Schalter „Unverschlüsselt (http) erlauben“. Mit `HTTPS_PROXY` entscheidet der Schalter
  „Über den Proxy“ je Webhook: aus (Standard für neue Webhooks – in der Oberfläche wie über die API; vorher gespeicherte
  Kanäle behalten ihre Einstellung) verbindet direkt mit Adressprüfung, an schickt über den Proxy, der dann die Namen
  auflöst.
- **Update auf 0.1.22 – Kanäle ins Firmennetz:** Bis 0.1.21 durften Webhooks ohne Weiteres an private Adressen. Zeigt
  ein Kanal auf eine interne Adresse (z. B. n8n unter `10.…`, `172.16–31.…`, `192.168.…` oder einen internen Namen,
  der dorthin auflöst), meldet er danach „Ziel nicht erlaubt“ – dessen Adresse oder Netz in `WEBHOOK_PRIVATE_NETS` in
  der `.env` eintragen und `docker compose up -d` (die Schublade des Kanals zeigt den Fehler, „Testen“ prüft es).
- **SMTP-Server** (*Kanäle → E-Mail-Server*): ein Relay im Firmennetz ist in Ordnung, aber nie Loopback,
  Link-Local/Cloud-Metadaten, „any“, Multicast (das auch nicht mit `SMTP_ALLOW_INTERNAL`), die eigenen Docker-Netze oder
  der Docker-Host; der Name wird einmal aufgelöst, geprüft und genau diese Adresse verbunden (TLS prüft weiter den
  Namen). Ausnahme für ein Relay in den eigenen Docker-Netzen oder auf dem Docker-Host (Gateway des Containers, Docker
  Desktops `192.168.65.x`): seine Adresse in `SMTP_ALLOW_INTERNAL` (kommagetrennt, auch Netze; dann auch per Name wie
  `host.docker.internal`). Ein Relay, das auf dem Host nur an 127.0.0.1 lauscht, über diese Adresse ansprechen – nicht
  über 127.0.0.1. „Testmail senden“ zeigt nur die Art eines Fehlers
  (abgelehnt, keine Verbindung, TLS …), nie den Text des Servers.

### Generischer Webhook (JSON, Version 1)

`POST` mit `Content-Type: application/json`, keine Weiterleitungen, Antwort 2xx = zugestellt:

```json
{
  "version": 1,
  "type": "news.stories",
  "id": "5b0c6f0e-…",
  "sent_at": "2026-10-28T12:00:00Z",
  "app": "cobe-news",
  "app_url": "https://news.corp.example:8095/",
  "channel": "n8n SOC",
  "rules": ["Kritisch an SOC"],
  "lang": "de",
  "total": 14,
  "more": 4,
  "stories": [
    {
      "id": "…", "title": "…", "summary": "…",
      "url": "https://news.example.com/…",
      "link": "https://news.corp.example:8095/?story=…",
      "severity": "critical", "source": "Example Feed",
      "published_at": "2026-10-28T11:58:00Z", "cves": ["CVE-2026-0001"]
    }
  ]
}
```

- `type`: `news.stories` oder `news.test` (Knopf „Testen“); `total` Meldungen insgesamt, `stories` höchstens 10,
  `more` der Rest. Neue Felder können hinzukommen; eine inkompatible Änderung erhöht `version`.
- `id` (= Header `X-Cobe-Delivery`) hängt am Kanal und an den Meldungen der Nachricht: dieselbe Nachricht, noch einmal
  geschickt (neuer Versuch nach einem Fehler, Antwort unterwegs verloren), hat dieselbe `id` – ein Empfänger, der sich
  die `id` merkt, verwirft die zweite. Testnachrichten bekommen jedes Mal eine neue.
- Header: `X-Cobe-Event` (= `type`), `X-Cobe-Delivery` (= `id`), mit Signatur zusätzlich `X-Cobe-Timestamp` (Unix-Sekunden) und
  `X-Cobe-Signature: sha256=<hex>` = HMAC-SHA256(Geheimnis, `"<X-Cobe-Timestamp>.<Body>"`).
  Empfänger: Signatur über die **rohen** Body-Bytes prüfen, Zeitstempel nicht älter als ein paar Minuten
  annehmen, `id` gegen doppelte Zustellung merken.
- Optional ein eigener Header (z. B. `Authorization: Bearer …` oder `X-Api-Key`), Wert verschlüsselt gespeichert.
- Die Felder der Meldungen sind Text aus fremden Feeds – der Empfänger muss sie als nicht vertrauenswürdig behandeln.

**Umstieg von früher:** Regeln aus der Zeit vor den Kanälen (ein Kanal pro Regel) hat 0.1.15 beim ersten Start zu einer
Regel plus einem gleichnamigen Kanal gemacht. Wer von einer so alten Version kommt, startet zuerst einmal 0.1.15 – erst
danach zieht 0.1.16 die Daten nach PostgreSQL um.

**E-Mail-Server** (*Einstellungen → Kanäle & Regeln → Kanäle*, Zeile „E-Mail-Server“ über der Liste, „Bearbeiten“
öffnet die Schublade): Host, Port, STARTTLS / SSL/TLS / keine, Zertifikat prüfen, optional Benutzer + Passwort,
Absender; mit Testmail. Gilt für alle E-Mail-Kanäle. Die frühere Seite *E-Mail-Versand* gibt es nicht mehr – alte Links
(`/settings/mail`) führen dorthin und öffnen die Schublade; die API (`/api/admin/notify/smtp`) bleibt gleich.

**Desktop** (*Einstellungen → Benachrichtigungen*, pro Person): Browser-Benachrichtigungen für gewählte
Schweregrade/Quellen; jede Meldung nur einmal (auch bei mehreren Tabs), ein Klick öffnet sie.
Die Karte zeigt den Zustand in diesem Browser – Berechtigung, „Hintergrund-Tab: aktiv“ (mit der letzten Abfrage),
„Push bei geschlossenem Tab: aktiv / nicht verfügbar, weil …“ – und hat eine **Test-Benachrichtigung**, die nach
5 Sekunden kommt (Zeit, in einen anderen Tab oder eine andere App zu wechseln). Höchstens drei Meldungen einzeln pro
Runde, mehr als eine Zusammenfassung; „Kritisch“ bleibt stehen, bis man sie wegklickt.

- **Offener Tab, auch im Hintergrund** (immer): jeder offene Tab hat einen eigenen Takt; wessen Takt zuerst fällig ist,
  fragt `/api/news/recent` (etwa einmal pro Minute – so oft weckt Chrome auch einen Tab, der seit über fünf Minuten im
  Hintergrund liegt). Eine kurze Web-Sperre gilt nur für die eine Abfrage: friert der Browser einen Tab ein
  (Energiesparen/Speicher sparen) oder verwirft ihn, übernimmt ein anderer; beim Zurückkommen (Tab wieder sichtbar,
  Fokus, wieder online, aus dem Einfrieren) wird sofort nachgeholt. Der Cursor ist die **Eingangsnummer** der Meldung
  auf dem Server (nicht eine Uhrzeit): nichts geht verloren, nichts kommt doppelt – auch nach einem Neuladen.
- **Push bei geschlossenem Tab** (Web Push, optional, pro Browser einschaltbar): der Server schickt nach jeder Runde
  über den Push-Dienst des Browser-Herstellers, was für die Person neu ist – auch ohne offenen Tab, solange der Browser
  läuft. Inhalt: Titel, Schwere, Quelle, Link (Ende-zu-Ende verschlüsselt nach RFC 8291; der Push-Dienst sieht nur die
  Größe), signiert mit dem VAPID-Schlüssel des Servers (beim ersten Gebrauch erzeugt, verschlüsselt in der Datenbank).
  Abgemeldete oder abgelaufene Browser (404/410 vom Push-Dienst) werden gelöscht; bei anderen Fehlern wartet der Server
  länger (bis 6 h) und der offene Tab zeigt die Meldungen so lange selbst; nach 12 Fehlschlägen in Folge (etwa zwei
  Tage) wird das Abo gelöscht (der Browser meldet es beim nächsten Besuch neu an, wenn Push dort noch an ist). Ein
  Browser kann die anderen nicht aufhalten: höchstens 10 Browser pro Person, jeder Browser hat je Runde 30 Sekunden,
  die ganze Runde 2 Minuten – was dann nicht fertig ist, zählt als Zeitüberschreitung für diesen Browser.
  **Wer bekommt Push?** Abmelden schaltet Push für diesen Browser ab (er wird beim Server abgemeldet). Ein deaktiviertes
  Konto bekommt nichts, und wird es wieder aktiviert, kommt nur, was danach eintrifft (kein Schwall). Eine bloß
  **abgelaufene Sitzung** beendet Push dagegen nicht: Push ist genau für die Zeit ohne offenen Tab gedacht, die Inhalte
  sind öffentliche Schlagzeilen, und das Konto ist weiter aktiv – sonst endete Push still nach spätestens 12 Stunden.
  **VAPID-Schlüssel**: Lässt er sich nicht mehr lesen (`SECRET_KEY` bzw. `secret.key` geändert, Eintrag beschädigt),
  erzeugt der Server ein neues Paar und löscht die Abos des alten (die Push-Dienste würden sie ohnehin ablehnen); die
  Browser melden sich beim nächsten Besuch mit dem neuen Schlüssel an. Neuer Schlüssel mit Absicht (z. B. nach einem
  Leck): `docker compose exec app python -m app.cli rotate-vapid` – wirkt sofort, ohne Neustart.
  Voraussetzungen:
  - **Ein Zertifikat, dem der Computer vertraut.** Bei einer Zertifikatswarnung verweigert Chrome den Service Worker
    (`/sw.js`) – Push ist dann „nicht verfügbar“ (die Karte sagt warum), der offene Tab benachrichtigt weiter. Also das
    selbstsignierte Zertifikat verteilen (siehe [HTTPS](#https)) oder eines der eigenen CA verwenden.
  - **Ausgehend zu den Push-Diensten** (https, Port 443, über `HTTPS_PROXY`, wenn gesetzt): `fcm.googleapis.com`
    (Chrome, Edge auf Android, …), `*.push.services.mozilla.com` (Firefox), `*.push.apple.com` (Safari),
    `*.notify.windows.com` (Edge unter Windows). Andere Ziele nimmt der Server nicht an (ein Abo ist Browser-Eingabe).
  - Ausschalten für alle: `WEB_PUSH=0` in der `.env` (dann geht keine Anfrage an die Push-Dienste).
    `PUSH_CONTACT` (`mailto:` oder `https:`) ist die Kontaktadresse für die Push-Dienste; leer: `BASE_URL`.
  - Grenzen: der Browser muss laufen (Chrome/Edge im Hintergrund, Firefox offen); Safari erst ab macOS 13; die
    System-Einstellungen (Mitteilungen für den Browser, Fokus/Nicht stören) entscheiden, ob und wie sie erscheinen.

## Daten

- **PostgreSQL 18** (Container `cobe-news-db`, Volume `cobe-news_db18`): Quellen, Meldungen, Benutzer, Sitzungen,
  Gelesen-Status, Kanäle, Regeln, Vendor News, Einstellungen, die Abruf-Statistik der Quellen (60 Tage) – siehe
  [PostgreSQL](#postgresql)
- **`./data/backups/`**: die Sicherungen (siehe [Sicherung](#sicherung-wiederherstellung-export))
- **`./data/vendor_catalog.json`**: der zuletzt von endoflife.date neu gebaute Vendor-News-Katalog (fehlt er, gilt
  der mitgelieferte `backend/app/data/vendor_catalog.json`)
- **`./data/secret.key`**: Schlüssel für gespeicherte Geheimnisse (fehlt er, müssen Webhook-URLs, SMTP-/Bind-Passwort
  und Entra-Geheimnis neu eingegeben werden). Besser: `SECRET_KEY` in der `.env` setzen und **getrennt** von der
  Datensicherung aufbewahren – eine Sicherung ohne Passphrase enthält dann keine lesbaren Geheimnisse. `SECRET_KEY`:
  mindestens 32 zufällige Zeichen (`openssl rand -base64 32`). Ein kürzerer Schlüssel (oder einer aus weniger als
  8 verschiedenen Zeichen, ebenso eine `secret.key` unter 32 Bytes) wird nicht abgelehnt – bestehende Installationen
  laufen weiter –, aber beim Start als Warnung geloggt (`SECRET_KEY is short …`, nie der Schlüssel selbst) und unter
  *Einstellungen → HTTPS & Zertifikat* angezeigt. Wechseln heißt: die gespeicherten Geheimnisse neu eingeben.
- **`./data/news.db`**: die SQLite-Datei bis 0.1.15 – seit dem Umzug unverändert, der Weg zurück (siehe unten)
- `./data` und alle Dateien darin sind nur für den App-Prozess lesbar (Verzeichnis 0700, Dateien 0600).
- **Volume `cobe-news_tls`**: das selbstsignierte Zertifikat (bei `TLS_MODE=own` stattdessen `TLS_SOURCE`)

### Aufbewahrung

Die App räumt selbst auf: stündlich in der News-Runde (`main.FetchLoop._prune`), einmal am Tag in der
Vendor-News-Runde (`vendor.daily_prunes` – auch bei ausgeschalteter Vendor News). Jeder Schritt läuft für sich:
scheitert einer (Deadlock, Zeitlimit von 30 s je Anweisung), steht `prune <Schritt> failed` bzw. `vendor: pruning the
… failed` im Log, die übrigen laufen weiter, und er wird in der nächsten Stunde wieder versucht. Gelöscht wird in kurzen
Transaktionen (höchstens 5000 Zeilen, Meldungen 500); eine Zeile, die gerade eine andere Transaktion ändert, bleibt bis
zum nächsten Lauf (`FOR UPDATE SKIP LOCKED` – kein Warten, kein Deadlock). Den Platz nutzt PostgreSQL wieder (autovacuum).

| Daten (Tabelle) | Regel | Ab Werk / Bereich | Wo einstellen |
|---|---|---|---|
| Meldungen (`news_items`) mit weiteren Quellen, Gelesen-Markierungen, Details, Versandmarken (ON DELETE CASCADE) | älter als die Aufbewahrung (Veröffentlichung); eine Meldung ohne eigenes Datum erst, wenn ihr Feed – und jede weitere Quelle, die sie führt – seit ihrer letzten Sichtung gelesen wurde (HTTP 200) und sie nicht mehr listete: ein Feed, der lange „304“ antwortet, ausfällt, oder ausgeschaltete News löschen nichts. Als Sichtung zählt nur, dass ihr Feed oder ein anderer Feed **dieselbe Adresse** listet – eine weitere Quelle, die sie nur über Titel oder CVE führt, hält sie nicht. Was gelöscht wurde, wird nie wieder übernommen | 90 Tage, 7–365 | *Integrationen → News* (eine kürzere Frist nennt vorher die Zahl) |
| Gelesen-Markierungen (`news_reads`, `vendor_reads`) | Meldungen und Befunde älter als 30 Tage zählen ohnehin als gelesen, ebenso alles unter der „Alle gelesen“-Marke; „ungelesen“ bleibt mit der Meldung bzw. solange dem Produkt gefolgt wird | 30 Tage | fest |
| Stummschaltungen (`person_mutes`) | nach Ablauf | – | – |
| Abruf-Statistik der Quellen (`source_fetch_stats`) | 60 Tage | fest | – |
| Zustandswechsel der Quellen (`source_health_events`) | 60 Tage, der letzte je Quelle bleibt | fest | – |
| Zustellprotokoll (`delivery_log`) | 30 Tage, höchstens 200 000 Einträge | fest | – |
| Protokoll (`audit_log`) mit Adresse, Browser/System grob und Sitzungskennung | älter als die Aufbewahrung, täglich, in der Reihenfolge der Integritätskette (der neue Anfang wird als Eintrag `audit.pruned` in der Kette festgehalten, siehe [Protokoll](#protokoll-audit-log)) | 365 Tage, 90–3650 | *Protokoll → Aufbewahrung* |
| Persönliche Zustellungen (`person_deliveries`) | entschiedene (gesendet, fehlgeschlagen, übersprungen) nach 90 Tagen; Abwesenheiten 8 Tage nach ihrem Ende | 90 Tage | fest |
| Wochenrückblick-Versand (`team_weekly_sends`) | entschiedene nach 90 Tagen | 90 Tage | fest |
| CVE beobachten: Ereignisse (`vendor_events`, Art `watch`) | 90 Tage; der Zustand einer CVE, sobald niemand sie mehr beobachtet | 90 Tage | fest |
| Vendor-News-Ereignisse (Befunde, neue Version, Support-Ende) mit Versandmarken | solange das Produkt gefolgt und die Version eingetragen ist (eine geänderte Version ist eine neue) – sie sorgen dafür, dass jeder Befund nur einmal gemeldet wird | – | – |
| Revisionen der Hinweise (`vendor_advisory_changes`) und Änderungs-Ereignisse | die letzten 20 je Hinweis, keine älter als ein Jahr (täglich) | 1 Jahr | fest |
| Einzelabfragen je CVE (`vendor_fetch` `nvdcve:`, `cvelistcve:`, `osvcve:`) | 30 Tage (täglich) | 30 Tage | fest |
| EPSS-Werte (`epss_scores`) | 30 Tage nicht mehr gefragt (täglich) | 30 Tage | fest |
| Hinweise (`vendor_advisories` mit Produkt-Zuordnung und Stand) | ein Jahr nach dem letzten Speichern (täglich, `advisory_cleanup`), wenn **alles** zutrifft: kein gefolgtes und eingeschaltetes Produkt verweist darauf, keine seiner CVEs wird beobachtet, keine gespeicherte Meldung nennt eine davon und keine Meldungs-Details zeigen auf ihn, keine Revision im letzten Jahr, und keine noch gestellte Abfrage würde ihn liefern (ein NVD-Eintrag mit einer CPE, die ein gefolgtes Produkt abfragt – etwa die gemeinsame CPE der Windows-Server-Rollen; Palo-Alto- bzw. Veeam-Einträge, solange eine Palo-Alto- bzw. die Veeam-Abfrage läuft). NVD- und cvelistV5-Einträge ganz ohne CPE bleiben, solange sie ein Katalogprodukt nennen (nur die Stichwortsuche der letzten Tage brachte sie). **Nie** gelöscht: CSAF-Dokumente (ein Wasserzeichen je Anbieter, der Erstabruf reicht nur 90 Tage zurück – ein gelöschtes älteres Dokument käme nie wieder) und Fortinet (der PSIRT-Feed listet nur die neuesten). Nach einer Löschung beginnen alle Abfragen, die kein eingeschaltetes Produkt mehr stellt (`nvd:`, `nvdkw:`, `paloalto:`, `veeam:`), von vorn; ebenso die eines Produkts, dem wieder gefolgt wird: der nächste Abruf holt alles neu, die Auswertung wartet darauf (auch auf die Stichwortsuche `nvdkw:`) – der Ausgangsstand entsteht mit den Hinweisen, nichts Altes wird gemeldet | 1 Jahr | fest |
| API-Tokens | 30 Tage nach Widerruf oder Ablauf | fest | – |
| Sitzungen | nach Ablauf (stündlich; vorher schon beim nächsten Aufruf) | – | Zeitlimits der Sitzungen (Handbuch, Anmeldung) |
| Anmeldesperren (`auth_locks`), Passkey-Challenges, Zähler im Speicher | nach Ablauf (stündlich) | – | – |
| Sicherungen (`data/backups`) | die letzten N; eine Sicherung vor einer Wiederherstellung 30 Tage | 7: 3/7/14/30/90 | *Einstellungen → Sicherung* |
| Container-Logs | `json-file`, 3 × 20 MB je Container | – | `docker-compose.yml` (`x-logging`) |

Zurücksetzen = `docker compose down -v` (löscht auch die Datenbank!), `data/secret.key` löschen, neu starten (neues
Setup-Token im Log). Liegt dann noch eine `data/news.db` mit Daten da, wird sie beim Start wieder umgezogen – vorher
wegräumen oder `SQLITE_IMPORT=0` setzen.

## PostgreSQL

- Ein eigener Container `cobe-news-db` (Image `cobe-news-db`: `postgres:18-alpine` plus `deploy/postgres`), nur im internen Netz `db` mit der App – kein Port nach
  außen, keine Verbindung ins Internet. Daten im Volume `cobe-news_db18`, eingehängt auf `/var/lib/postgresql` (ab
  PostgreSQL 18 liegt das Datenverzeichnis darunter in `18/docker`, nicht mehr in `/var/lib/postgresql/data`).
- Datenbank `cobe_news`, zwei Rollen (siehe [Rollen](#rollen)): `cobe_news` ist der Superuser des Containers (Passwort
  `POSTGRES_PASSWORD`), die App arbeitet als **`cobe_news_app`** ohne Superuser-Rechte (Passwort `POSTGRES_APP_PASSWORD`).
  Dazu `cobe_news_audit` ohne Anmeldung – Besitzer des Protokolls ([Datenbank-Sperre](#datenbank-sperre)).
  Dazu die Wegwerf-Datenbank `cobe_news_restore_test` mit ihrer eigenen Rolle `cobe_news_restore` (Passwort
  `POSTGRES_RESTORE_PASSWORD`, siehe [Rücksicherungs-Test](#rücksicherungs-test)).
  Alle Passwörter stehen in der `.env` (von `scripts/setup-env.sh` erzeugt, nie im Repository). `POSTGRES_PASSWORD` **nicht
  ändern**: das Volume wurde damit angelegt (das Image nimmt es nur beim ersten Start; die Einrichtung der Rolle läuft
  über den lokalen Socket und hängt nicht davon ab – für alles andere bleibt das alte gültig: das alte zurück in die
  `.env` oder `ALTER USER cobe_news PASSWORD …` im Container). `POSTGRES_APP_PASSWORD` darf sich ändern: der
  Datenbank-Container setzt es bei jedem Start (`docker compose up -d` legt ihn und die App dafür neu an).
- Sortierung byteweise (`--locale-provider=builtin --locale=C.UTF-8`) – wie zuvor SQLite, unabhängig von der
  C-Bibliothek des Images (kein Neuaufbau der Indizes nach einem Image-Update).
- Das Schema kommt aus Alembic-Migrationen (`backend/app/migrations`); die App bringt es bei jedem Start auf den Stand
  ihrer Version (`python -m app.cli migrate` geht auch von Hand). Jede Verbindung hat ein Statement-Timeout (30 s) und
  ein Timeout für vergessene offene Transaktionen (5 min); die App hält höchstens 15 Verbindungen.
- Speichergrenze des Containers: `DB_MEM` (Standard 512m). Ein Blick hinein:
  `docker compose exec db psql -U cobe_news cobe_news`.
- Speichergrenze der App: `APP_MEM` (Standard 512m). Die App hält die ausgewerteten Befunde der gefolgten Produkte im
  Speicher. Gemessen (0.1.50, Lasttest mit 20 Nutzern): 10 Produkte / 5 000 Hinweise um 200 MiB, 48 Produkte /
  50 000 Hinweise / 30 000 Meldungen 430 MiB. Ab etwa 30 Produkten oder 20 000 Hinweisen `APP_MEM=768m`, ab 100
  Produkten `1g`; der Standard bleibt 512m (reicht für die übliche Installation, ein höherer Wert reserviert nichts,
  begrenzt nur). An der Grenze beendet Docker die App und startet sie neu (`OOMKilled` in `docker inspect`).

### Rollen

Bis 0.1.21 arbeitete die App als Superuser `cobe_news` – damit hätte jede eingeschleuste SQL-Anweisung (etwa aus einer
präparierten Sicherung) auch Programme im Datenbank-Container starten können (`COPY … TO PROGRAM`). Seit 0.1.22:

- **`cobe_news_app`** – die App, die Sicherung und die Wiederherstellung. Besitzer der Datenbank und aller Tabellen
  (darf also das Schema migrieren, sichern und wiederherstellen), aber `NOSUPERUSER NOCREATEDB NOCREATEROLE`: keine
  Programme auf dem Server, keine Dateien des Servers, keine nicht vertrauenswürdigen Erweiterungen, keine anderen Rollen.
  Ausnahme seit 0.1.52: das Protokoll `audit_log` und das Schema `public` gehören `cobe_news_audit` – die App darf in
  `public` anlegen (`CREATE`) und ihre eigenen Tabellen ändern und löschen, das Protokoll nur lesen und ergänzen.
  Seit 0.1.52 verbindet sie sich auch mit keiner anderen Datenbank mehr: `app-role.sql` nimmt `PUBLIC` das `CONNECT`
  auf `postgres` und `template1` (so legt PostgreSQL sie an; nur der Superuser braucht sie, und der braucht kein Recht) –
  `DROP DATABASE` braucht eine Verbindung zu einer anderen Datenbank, die eigene lässt sich nicht löschen. Steht eine
  andere Datenbank der App offen, sagt es die Zeile `db-init: WARNING – cobe_news_app may connect to …`.
  Als Besitzerin der Datenbank darf die App Einstellungen für sie setzen (`ALTER DATABASE … SET`) – auch einen
  `search_path`, der eigene Funktionen vor `pg_catalog` stellt. Damit davon nichts als Superuser läuft: `db-init` und
  seine drei SQL-Dateien arbeiten nur mit `search_path = pg_catalog, pg_temp`, und für Sitzungen des Superusers in
  dieser Datenbank (`docker compose exec db psql -U cobe_news cobe_news`) setzt `app-role.sql` bei jedem Start
  `ALTER ROLE cobe_news IN DATABASE cobe_news SET search_path = pg_catalog, public` – das geht der Einstellung der
  Datenbank vor, und nur ein Superuser kann es ändern.
- **`cobe_news_audit`** (ab 0.1.52) – `NOLOGIN`, niemand ist Mitglied, niemand meldet sich damit an. Besitzer von
  `audit_log`, dem Schema `public` und dem Schema `cobe_news_audit` (Sperr-Funktionen, beiseitegelegte Einträge).
  Angelegt von `deploy/postgres/audit-lock.sql` bei jedem Start der Datenbank, nach `app-role.sql` – siehe
  [Datenbank-Sperre](#datenbank-sperre).
- **`cobe_news`** – der Superuser, den das PostgreSQL-Image beim ersten Start anlegt. Nur der Datenbank-Container kennt
  sein Passwort, die App nie. Sein Einstiegspunkt (`deploy/postgres/cobe-news-db.sh`) startet PostgreSQL über den
  offiziellen Einstiegspunkt, wartet, bis der Server Verbindungen annimmt, und führt dann bei **jedem Start**
  `db-init.sh` (`app-role.sql`, dann `audit-lock.sql`) aus: legt `cobe_news_app` an, falls sie fehlt, setzt ihr
  Passwort und überträgt die Datenbank und alles, was der Superuser bisher angelegt hat (Tabellen mit Indizes und
  Sequenzen), an sie – außer dem gesperrten Protokoll; dann die Sperre des Protokolls – mehrfach ausgeführt ändert er
  nichts. Erst danach schreibt er eine Markierung (`/var/run/postgresql/.cobe-news-ready`, auf
  tmpfs – bei jedem Start weg), und erst mit ihr meldet der Healthcheck „healthy“ (`pg_isready` **und** Markierung) – die
  App startet also nie gegen eine Datenbank ohne ihre Rolle. Scheitert die Einrichtung, hält er PostgreSQL an und endet
  mit Exit 1; die Restart-Policy versucht es erneut (`docker compose logs db`, Zeilen `db-init: …`). `docker stop`
  (SIGINT) bzw. SIGTERM reicht er als *fast shutdown* an PostgreSQL weiter: offene Transaktionen zurückgerollt,
  Checkpoint, Exit 0. Bis 0.1.48 erledigte das der kurze Dienst `db-init` (danach „Exited (0)“).
- **`cobe_news_restore`** – nur der [Rücksicherungs-Test](#rücksicherungs-test) (`deploy/postgres/restore-role.sql`).
  Besitzer der Wegwerf-Datenbank `cobe_news_restore_test` und sonst von nichts: `NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS`, kein Mitglied von `cobe_news_app`, ohne `CONNECT` auf die Datenbank der App. Der Datenbank-Container legt
  sie bei jedem Start an bzw. prüft sie – nur wenn `POSTGRES_RESTORE_PASSWORD` gesetzt ist (mindestens 16 Zeichen;
  leer: kein Rücksicherungs-Test). `cobe_news_app` bekommt dafür kein zusätzliches Recht.

**Umstellung einer bestehenden Installation** (einmal, beim Update auf 0.1.22):

```bash
cd cobe-news
docker compose exec -T app python -m app.cli backup   # Sicherung vorher (der Weg zurück, siehe unten)
docker tag cobe-news:latest cobe-news:before-roles     # das alte Image behalten
scripts/setup-env.sh                                   # ergänzt POSTGRES_APP_PASSWORD in der .env
docker compose up -d --build --remove-orphans          # die Datenbank stellt um, dann startet die App als cobe_news_app
docker compose logs db | grep db-init                  # "… object(s) handed over to cobe_news_app", "superuser: false"
docker compose exec db psql -U cobe_news cobe_news -c "SELECT tableowner, count(*) FROM pg_tables WHERE schemaname='public' GROUP BY 1"
```

**Der Weg zurück**: Der Superuser darf weiterhin alles – die alte Version läuft mit der alten Compose-Datei unverändert
(`git checkout <alte Version> -- docker-compose.yml`, `docker tag cobe-news:before-roles cobe-news:latest`,
`docker compose up -d --no-build`; brachte das Update eine neue Migration mit, vorher die Sicherung von eben mit der
alten Version zurückspielen). Die Eigentümer zurück an den Superuser geben ist nicht nötig; wer es will:
`docker compose exec db psql -U cobe_news cobe_news -c "REASSIGN OWNED BY cobe_news_app TO cobe_news"` und
`ALTER DATABASE cobe_news OWNER TO cobe_news`.

### Umstieg von SQLite (0.1.15) und zurück

**Umstieg** – wie ein normales Update, plus einmal `scripts/setup-env.sh` und eine Kopie der SQLite-Datei (sqlite3-Backup-API, mit Integritätsprüfung):

```bash
cd cobe-news
scripts/setup-env.sh                             # zuerst: .env mit POSTGRES_PASSWORD (die neue Compose-Datei braucht es schon für exec)
docker tag cobe-news:latest cobe-news:0.1.15     # das alte Image behalten (der Weg zurück)
docker compose exec -T app python -c "import sqlite3,time; d=sqlite3.connect(f'/data/news.db.pre-pg-{time.strftime(\"%Y%m%d-%H%M%S\")}.bak'); sqlite3.connect('file:/data/news.db?mode=ro', uri=True).backup(d); print(d.execute('PRAGMA integrity_check').fetchone())"
docker compose up -d --build
docker compose logs app | grep "database:"       # Umzug: Zeilen je Tabelle, Dauer
```

Beim ersten Start ist PostgreSQL leer und `data/news.db` enthält Daten: die App zieht sie **einmal** um, bevor sie
irgendetwas anderes tut – in einer einzigen Transaktion, Tabelle für Tabelle, und vergleicht danach Zeilenzahl je
Tabelle und bis zu 25 Zeilen je Tabelle Wert für Wert (mit allen JSON-Feldern). Erst dann wird gespeichert, mit einer
Markierung (Einstellung `sqlite_import`), und die App beginnt zu arbeiten. Scheitert etwas, bleibt PostgreSQL leer,
die App startet **nicht** (Log: „import … refused“) und versucht es beim nächsten Start neu – sie arbeitet nie mit einer
leeren oder halb gefüllten Datenbank, während die Datei die Daten hat. Die Datei selbst wird nur gelesen (read-only,
auch ein liegengebliebenes `news.db-wal` wird mitgelesen) und bleibt unverändert; daneben liegt danach
`news.db.imported-to-postgresql.txt`. Von Hand (z. B. mit `SQLITE_IMPORT=0`):
`docker compose exec app python -m app.cli migrate-sqlite /data/news.db` – verweigert eine Datenbank, die schon Daten hat;
was der Start der App von selbst anlegt (die eingebauten Quellen ohne Meldungen, das offene Setup ohne Konto), zählt
nicht und macht den Daten der Datei Platz. Ein Wert mit Steuerzeichen (z. B. NUL, das SQLite speichern konnte,
PostgreSQL nicht) wird ohne diese Zeichen übernommen; die Ausgabe nennt, wie viele Werte je Tabelle das betraf.

**Zurück zu 0.1.15** – mit dem Stand der SQLite-Datei vom Umzug (was seitdem dazukam, fehlt):

```bash
docker compose down                              # die Datenbank bleibt im Volume db18
git checkout aad77ed -- docker-compose.yml   # die Compose-Datei von 0.1.15 (ohne den Dienst db)
docker tag cobe-news:0.1.15 cobe-news:latest
docker compose up -d --no-build
```

Später wieder vorwärts: entweder mit den PostgreSQL-Daten weiter (der Stand vom Zurückgehen, `docker compose up -d
--build` – kein neuer Umzug, die Markierung ist da), oder die inzwischen gewachsene SQLite-Datei erneut umziehen:
`docker compose down`, `docker volume rm cobe-news_db18`, `docker compose up -d --build`.

## Sicherung, Wiederherstellung, Export

**Sicherung** (*Einstellungen → Betrieb → Sicherung & Export*, „Jetzt sichern“, oder per Befehl) – eine Datei in
`data/backups/` (0600): `pg_dump` im Custom-Format, ein Manifest (Version, Schema-Stand, Zeilen je Tabelle, Prüfsummen,
Fingerabdruck des Schlüssels) – Zählung und Dump aus demselben Snapshot. Es läuft immer nur eine Sicherung; die
Aufbewahrung (die letzten 3, 7, 14, 30 oder 90) gilt für alle, auch die per cron. Die Einstellungen zeigen die letzte
Sicherung (auch eine gescheiterte, mit Grund) und ob gerade eine läuft. „Jetzt sichern“ startet sie im Hintergrund –
die Seite fragt alle 2 Sekunden nach, bis sie fertig ist (eine große Datenbank braucht länger, als der Proxy auf eine
Antwort wartet). Weniger Sicherungen aufbewahren (löscht ältere sofort) und der Export (Namen und E-Mail-Adressen aller
Benutzer) brauchen die erneute Bestätigung wie die Benutzerverwaltung.

- **Ohne Passphrase** (`cobe-news-<Zeit>.tar`): **ohne** den Schlüssel – die Geheimnisse darin (Webhook-URLs,
  SMTP-/LDAP-Passwort, Entra-Geheimnis, TOTP lokaler Konten) bleiben mit `SECRET_KEY` bzw. `data/secret.key`
  verschlüsselt. Den Schlüssel getrennt aufbewahren. Seit 0.1.22 **signiert** (`manifest.sig`, HMAC-SHA256 mit einem aus
  dem Schlüssel abgeleiteten Schlüssel): die Wiederherstellung erkennt, dass die Datei von dieser Installation stammt und
  danach nicht verändert wurde – die Prüfsummen im Manifest allein beweisen das nicht, sie stehen in derselben Datei.
- **Mit `BACKUP_PASSPHRASE`** (`cobe-news-<Zeit>.tar.enc`, mindestens 12 Zeichen): die ganze Datei verschlüsselt
  (scrypt mit N=2^17 + AES-256-GCM in Blöcken – verändert, vertauscht oder abgeschnitten fällt beim Entschlüsseln auf;
  Dateien bis 0.1.23 mit N=2^15 lassen sich weiter öffnen) und **mit** dem Schlüssel. Für einen
  neuen Server reichen dann Datei und Passphrase. Die Passphrase gehört nicht in die `.env` – nur dem cron-Job
  mitgeben (unten) oder der App als Datei (nächster Absatz).

**Passphrase-Datei** (`BACKUP_PASSPHRASE_FILE`, ab 0.1.50): damit auch „Jetzt sichern“ und der Rücksicherungs-Test der
App verschlüsseln bzw. entschlüsseln, ohne dass die Passphrase in der Umgebung steht. Beide Compose-Dateien hängen
`${BACKUP_SECRET_DIR:-backup-secret}` schreibgeschützt unter `/run/backup-secret` ein – ein Bind-Mount mit leerer Quelle
bricht einen Stack (`:/run/…` ist ungültig), deshalb ist der Standard ein leeres eigenes Volume; gesetzt ein Ordner des
Hosts (absolut, außerhalb von `data/`, lesbar für UID 10001, z. B. `/etc/cobe-news-secret` mit `backup-pass` 0400).
Dazu `BACKUP_PASSPHRASE_FILE=/run/backup-secret/backup-pass` (`.env` bzw. Variablen des Stacks). Regeln:
`BACKUP_PASSPHRASE` geht vor, wenn beide gesetzt sind (die Seite sagt, dass die Datei dann nicht gelesen wird); `--passphrase-file` der CLI geht beiden vor. Die Datei wird bei jedem
Gebrauch gelesen (eine geänderte gilt sofort), Leerraum am Anfang und Ende zählt nicht (wie bei `--passphrase-file`),
höchstens 4 KiB, UTF-8, mindestens 12 Zeichen. Fehlt sie oder ist sie nicht lesbar: keine Sicherung – nie eine
unverschlüsselte an ihrer Stelle –, letzter Ausgang mit Code `passphrase_file`, die Seite nennt den Grund (`missing`,
`unreadable`, `not_a_file`, `too_large`, `not_text`, `empty`, `short`); die App läuft weiter. Ins Log und auf die Seite
kommt nur der Pfad, nie der Inhalt. `restore` und `restore-test` der CLI lesen die Datei ebenso.

Täglich per cron, z. B. `/etc/cron.d/cobe-news-backup` (die Datei mit der Passphrase: `chmod 600`, root):

```
30 2 * * * root cd /opt/cobe-news && docker compose exec -T app python -m app.cli backup --passphrase-file - < /root/.cobe-news-backup-pass >>/var/log/cobe-news-backup.log 2>&1 && rsync -a --exclude='.*' --exclude='*.partial' data/backups/ backup-host.corp.example:/srv/cobe-news/
```

Die Passphrase über die Standardeingabe, nie als `-e BACKUP_PASSPHRASE="$(cat …)"` (das stünde in der Befehlszeile von `docker`,
also in `ps` auf dem Host); mit [Passphrase-Datei](#sicherung-wiederherstellung-export) der App genügt der Befehl ohne Option.
Ohne Passphrase: `--passphrase-file - < …` weglassen. Exit-Code 0 = gesichert; die Sicherungen zusätzlich auf ein anderes System kopieren.
Während einer Sicherung oder Wiederherstellung liegen Dump und (verschlüsselt) Schlüssel kurz im Klartext in
`data/.backup-work/` – **neben** `data/backups/`, nicht darin. Was ein abgebrochener Lauf dort (oder bis 0.1.21 als
`.partial-…`/`.restore-…` in `data/backups/`) liegen ließ, räumt die nächste Sicherung, Wiederherstellung oder der
nächste Start der App weg, sobald es älter als 6 Stunden ist; `--exclude` hält Halbfertiges ohnehin vom Kopieren fern.

**Herunterladen in der App** (ab 0.1.51, ab 0.1.52 als Download des Browsers): nur **verschlüsselte** Sicherungen
(`.tar.enc`), Knopf „Herunterladen“ in der Liste; eine unverschlüsselte zeigt „Nur auf dem Server“ und wird abgelehnt
(403 `backup_not_encrypted`) – sie enthält die ganze Datenbank lesbar und bleibt beim Kopieren per
`docker cp`/`docker compose cp`. Die Seite fragt zuerst (die Datei braucht zum Einspielen die Passphrase, sicher
aufbewahren), dann zwei Schritte:

1. `POST /api/admin/backup/files/<Name>/ticket` – ein Schreibzugriff, also mit dem CSRF-Token (ein Formular oder Skript
   einer fremden Seite bekommt nichts), mit erneuter Bestätigung (`reauth_required`) und allen Prüfungen des Downloads
   selbst (Name, verschlüsselt, belegt, Grenze je Stunde – die Seite zeigt den Grund). Die Antwort ist die Adresse
   `/api/admin/backup/download/<Ticket>`: 256 Bit Zufall, auf dem Server nur als SHA-256 gehalten, 60 Sekunden gültig,
   einmal verwendbar, gebunden an Admin, Sitzung und Datei; ein neues ersetzt das ältere desselben Admins. Gezählt
   und belegt wird noch nichts.
2. Die Seite lässt den Browser diese Adresse selbst laden (ein verstecktes `<a download>`): er speichert die Datei direkt
   auf die Festplatte, mit seiner eigenen Fortschrittsanzeige, ohne neuen Tab – nie ganz im Arbeitsspeicher der Seite,
   bei jeder Größe. Das Ticket ist beim ersten Aufruf verbraucht, was auch folgt; eine andere Sitzung (auch desselben
   Admins), ein anderer Admin, ein abgelaufenes oder benutztes Ticket: 403 `backup_ticket_invalid` (für alle Gründe
   dieselbe Antwort). Das Ticket ersetzt hier das CSRF-Token – nur die Seite, die es geholt hat, kennt es.

Nur Namen aus der Liste und dem Namensmuster (kein Pfad, keine versteckten oder halbfertigen Dateien), geöffnet mit
`O_NOFOLLOW` als normale Datei, beim Start noch einmal geprüft und beim Senden noch einmal (dieselbe Datei: Gerät und
Inode). Gestreamt in Stücken von 1 MiB, nie ganz im Speicher, mit `Content-Length`, `Content-Disposition: attachment`,
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff` und `Referrer-Policy: no-referrer`; höchstens 6 je Stunde
(`backup_download_rate_limited`, 429) und einer zur Zeit (`backup_download_busy`, 409) je Admin – der Platz wird beim
Start des Downloads belegt (mit einem Token je Download) und nur von diesem Download wieder freigegeben: am Ende, bei
einem Fehler oder Abbruch, oder wenn die Antwort nie gesendet wird; nach 6 Stunden gilt ein Platz als verwaist. Tickets,
Plätze und Zähler liegen im Speicher des einen App-Prozesses (`--workers 1`); ein Neustart verwirft nur Tickets der
letzten Minute. Protokoll: `backup.downloaded` mit Datei und Größe, als auffällig markiert, wenn der Download beginnt.
Das Ticket steht in keinem Log: Das Zugriffsprotokoll der App und das „Woher“ im Protokoll zeigen nur
`/api/admin/backup/download/…`. Das mitgelieferte nginx reicht die Route ungepuffert durch
(`location ^~ /api/admin/backup/download/` mit `proxy_buffering off`, `proxy_max_temp_file_size 0`, `access_log off`):
sonst legte es eine große Datei in seinen Zwischenordner – ein tmpfs, also in die 128 MB Speicher des Proxys;
`proxy_read_timeout` und `send_timeout` dort 300 s (Zeit zwischen zwei Lese- bzw. Schreibvorgängen – ein kurz stockender
Client bricht einen langen Download nicht ab). Ein eigener Reverse Proxy: für diesen Pfad ebenso nicht puffern und
nicht protokollieren (bis 0.1.51 war es `/api/admin/backup/files/`).

**Wiederherstellung** – nur auf dem Server, mit angehaltener App:

```bash
docker compose stop app
docker compose run --rm --no-deps app python -m app.cli restore /data/backups/cobe-news-<Zeit>.tar   # .tar.enc: vorher read -rs BACKUP_PASSPHRASE; export BACKUP_PASSPHRASE, dann -e BACKUP_PASSPHRASE (nur der Name)
docker compose start app
```

Ablauf:

1. **Echtheit**: Eine verschlüsselte Sicherung beweist sie mit der Passphrase (verändert lässt sie sich nicht
   entschlüsseln), eine unverschlüsselte mit ihrer Signatur und dem Schlüssel dieser Installation. Eine Signatur, die
   nicht passt: Abbruch, immer. Eine unverschlüsselte Sicherung **ohne** Signatur (bis 0.1.21) oder mit dem Schlüssel
   einer anderen Installation: Abbruch, außer mit `--allow-unsigned` – nur für eine Datei, von der man sicher weiß,
   dass sie die eigene ist (eine präparierte Sicherung kann beliebige Daten und Konten mitbringen).
2. **Inhalt**: nur die erwarteten Dateien (Manifest, Signatur, Dump, Schlüssel), jede einmal, als normale Datei, in
   ihrer Größe; Prüfsummen; Schema-Stand (eine Sicherung einer neueren Version wird abgelehnt); Fingerabdruck des
   Schlüssels. Das Inhaltsverzeichnis des Dumps darf nur enthalten, was Cobe News anlegt (Tabellen, Daten, Sequenzen,
   Indizes, Constraints, die Erweiterung `pg_trgm`) – eine Funktion, ein Trigger, eine Sicht, ein anderes Schema: Abbruch,
   bevor etwas geändert ist (die zwei Trigger der [Datenbank-Sperre](#datenbank-sperre) auf `audit_log` werden nur
   übergangen, nie eingespielt). Läuft noch eine App auf der Datenbank: Abbruch.
3. Bestätigung („RESTORE“ tippen oder `--yes`), dann eine Sicherung des aktuellen Stands (`…-pre-restore.tar`, der Weg
   zurück – mit derselben Passphrase wie die Wiederherstellung; sie zählt nicht zur Aufbewahrung und bleibt 30 Tage).
4. **Eine** Transaktion als `cobe_news_app` (kein Superuser): `DROP SCHEMA public`, der Dump Stück für Stück von
   `pg_restore` in `psql` (nie ganz im Speicher), dann zwei Prüfungen: die Zeilen je Tabelle wie im Manifest, und das
   Schema **genau** so, wie es die Migrationen für den Schema-Stand der Sicherung anlegen (Spalten, Vorgaben,
   Constraints, Indizes, keine Funktionen, Trigger, Regeln, Rechte, Einstellungen der Datenbank oder Rolle, anderen
   Schemas). Weicht etwas ab oder bricht etwas ab, wird alles zurückgerollt – die Datenbank bleibt, wie sie war.
   Mit der [Datenbank-Sperre](#datenbank-sperre) des Protokolls (die App darf `public` und `audit_log` nicht löschen)
   statt `DROP SCHEMA public`: zuerst `cobe_news_audit.set_aside()` – die bisherigen Einträge wandern nach
   `cobe_news_audit.audit_log_replaced`, gelöscht wird keiner –, dann alles andere in `public` gelöscht (jede Tabelle,
   Sicht, Sequenz, Funktion und jeder Typ mit `CASCADE`; die Erweiterung `pg_trgm` bleibt), der Dump **ohne** die
   Definition von `audit_log` (Tabelle, Indizes, Constraints, Sequenz bleiben die gesperrten), nur mit seinen Zeilen
   (`COPY` – Einfügen darf die App), danach `cobe_news_audit.restored()` (die Sequenz hinter die höchste ID) und die
   beiden Prüfungen; die Vergleichsbasis entsteht ebenso neben der gesperrten Tabelle. Alles in derselben Transaktion:
   scheitert etwas, stehen auch die Einträge wieder, wo sie waren. Danach ist die Sperre weiter aktiv; die Ausgabe nennt
   die beiseitegelegten Einträge, `backup.restored` trägt ihre Zahl (`set_aside`).
5. Das Schema auf den Stand dieser Version bringen. Anmeldungen, die es zur Zeit der Sicherung gab, gelten wieder;
   spätere nicht.

Anderer Schlüssel: Abbruch mit Erklärung – `--use-backup-key` übernimmt den Schlüssel aus einer verschlüsselten
Sicherung nach `data/secret.key` (der alte bleibt daneben; mit `SECRET_KEY` in der `.env` dort eintragen),
`--ignore-key` stellt trotzdem her (gespeicherte Geheimnisse sind dann neu einzugeben).

**Neuer Server** (Katastrophenfall: nur die Sicherungsdatei, bei `.tar.enc` dazu die Passphrase, bei `.tar` dazu der
alte `SECRET_KEY` bzw. `data/secret.key`):

```bash
git clone … && cd cobe-news && scripts/setup-env.sh          # neue .env (bei .tar: den alten SECRET_KEY eintragen)
mkdir -p data/backups && cp /pfad/cobe-news-<Zeit>.tar.enc data/backups/
docker compose build && docker compose up -d --wait db       # nur die Datenbank (leer) mit der Rolle der App
docker compose run --rm --no-deps -e BACKUP_PASSPHRASE app python -m app.cli restore /data/backups/cobe-news-<Zeit>.tar.enc --use-backup-key
docker compose up -d
```

`BACKUP_PASSPHRASE` vorher in der Shell setzen (`read -rs BACKUP_PASSPHRASE; export BACKUP_PASSPHRASE`) – sie steht dann
weder in der `.env` noch in der Shell-History. In die leere Datenbank wird ohne Rückfrage-Sicherung eingespielt.

**Export** (*Sicherung & Export*, oder `docker compose exec -T app python -m app.cli export --format csv --out
/data/export.zip`): Regeln, Kanäle, Quellen, gefolgte Produkte mit Versionen und Benutzer als JSON oder CSV (ZIP, eine
Datei je Bereich) – **ohne Geheimnisse**: bei Kanälen nur, welche gesetzt sind; bei Benutzern Name, Rolle, Herkunft,
ob TOTP eingerichtet ist, letzte Anmeldung. Zum Nachlesen und Übertragen in andere Werkzeuge (JSON für Skripte, CSV für
Excel) – keine Sicherung, und Cobe News kann ihn nicht wieder einlesen.

Schritt für Schritt (sichern, herunterladen, einspielen – lokal und mit Portainer, was man dafür braucht): Handbuch
*Sicherung & Wiederherstellung → Schritt für Schritt*.

## Rücksicherungs-Test

Eine Sicherung zählt erst, wenn sie sich zurückspielen lässt. Der Rücksicherungs-Test spielt die **neueste**
Sicherung regelmäßig wirklich ein – in die Wegwerf-Datenbank `cobe_news_restore_test` mit der eigenen Rolle
`cobe_news_restore` (siehe [Rollen](#rollen)), **nie** in die Datenbank der App – und leert sie danach wieder (auch nach
einem Fehler). Einstellungen und Ergebnis: *Sicherung & Export → Rücksicherungs-Test* (an/aus, wer startet – die App
oder der Host –, alle 1/7/14/30 Tage, Stunde in UTC; ab Werk an, alle 7 Tage ab 03:00 UTC, Start innerhalb von 3
Stunden), „Jetzt testen“; dazu `/metrics`. Keine Nachricht über Kanäle – dafür ein Prometheus-Alarm.

Geprüft wird wie bei einer echten Wiederherstellung: Echtheit (Passphrase bzw. Signatur), nur die erwarteten Dateien,
Prüfsummen, Inhaltsverzeichnis des Dumps, bekannter Schema-Stand; `pg_restore` → `psql` in einer Transaktion ohne
Fehler (die [Datenbank-Sperre](#datenbank-sperre) gibt es dort nicht: Sicherungen tragen sie nie); Zeilen je Tabelle genau wie im Manifest; Schema genau wie eine frisch migrierte Datenbank desselben Stands;
danach `alembic_version` wie in der Sicherung. Niedrige CPU-Priorität (nice 19), nur einer zur Zeit, die App startet
keinen während einer Sicherung, Abbruch nach 1 Stunde. Vor jedem Test fragt die App den Server, ob die Rolle des Tests
wirklich keine Rechte auf die Datenbank der App hat – sonst Abbruch (`unsafe`). Kosten: Platz für eine zweite Kopie der
Daten (Platte und WAL) während des Tests; die Kopie enthält dieselben Daten wie die Sicherung, bis sie geleert ist.

**Einrichten in einer bestehenden Installation** (neue Installationen haben es schon):

```bash
git pull                          # wie bei jedem Update
scripts/setup-env.sh              # ergänzt POSTGRES_RESTORE_PASSWORD in der .env (alles andere bleibt)
docker compose up -d --build      # die Datenbank legt Rolle und Wegwerf-Datenbank an
docker compose logs db | grep db-init   # "cobe_news_restore ready"
```

Dann *Sicherung & Export → Rücksicherungs-Test* → „Jetzt testen“. Nicht gewünscht: `POSTGRES_RESTORE_PASSWORD=` leer in
der `.env` lassen (Zeile behalten) – dann legt die Datenbank nichts an und der Reiter sagt „nicht eingerichtet“.

**Verschlüsselte Sicherungen, deren Passphrase die App nicht kennt** (`BACKUP_PASSPHRASE` nur im cron-Job): „Wer startet
den Test“ auf „Der Host (Cron-Skript)“ stellen und auf dem Host per cron `scripts/restore-test.sh` laufen lassen – das
Skript liest die Passphrase-Datei auf dem Host und gibt sie dem Container über die Standardeingabe (nie auf einer
Befehlszeile oder in einem Log). Z. B. `/etc/cron.d/cobe-news-restore-test`, sonntags nach der täglichen Sicherung:

```
30 4 * * 0 root /opt/cobe-news/scripts/restore-test.sh --passphrase-file /root/.cobe-news-backup-pass >>/var/log/cobe-news-restore-test.log 2>&1
```

Exit-Code 0 = bestanden, 1 = fehlgeschlagen. Darunter: `docker compose exec -T app python -m app.cli restore-test
[--passphrase-file -]`. Die Fehlercodes erklärt das Handbuch (*Sicherung → Rücksicherungs-Test*).

## Protokoll (Audit-Log)

Code: `backend/app/audit.py` (Schreiben, Schwärzen, Kette, Aufräumen, Lesen, CSV), `audit_api.py` (nur Admins),
Tabelle `audit_log` (Migrationen 0017, 0032, 0033), Datenbank-Sperre: `audit_lock.py`, `deploy/postgres/audit-lock.sql`.
Handbuch: *Betrieb → Protokoll*.

- **Schreiben:** `audit.record()` in der Transaktion der Änderung; eine abgelehnte Änderung hinterlässt keinen Eintrag.
  Der Kontext der Anfrage kommt aus der Middleware (`main._guard`: Client-Adresse, Weg `direct`/`bundled`/`proxy`/
  `bundled_proxy`, Methode, Pfad ohne Query, Request-ID, Browser-Familie/Hauptversion/System – nie der ganze
  User-Agent), die Sitzung aus `deps._session` (HMAC-Kurzkennung der Sitzungs-ID, Anmeldeart). Jede API-Antwort trägt
  `X-Request-ID`; dieselbe ID steht in der Zugriffs-Log-Zeile (`rid=…`) und im Eintrag.
- **Nie ein Geheimnis:** `audit.scrub` – geheim benannte Felder nur als „geändert“, Adressen jedes Schemas nur als
  Origin (auch in Freitext, Zugangsdaten fallen weg), JWT/bekannte Token-Formen/lange zufällige Zeichenketten als
  geheim, Steuer- und Richtungszeichen entfernt.
- **Auffälliges** (`notable`, Gründe in `details.anomalies`, beim Schreiben bestimmt): Notfall-Konto außerhalb 07–19 Uhr
  oder am Wochenende (Ortszeit `TZ`, sonst Europe/Berlin), Admin-Anmeldung von neuer Adresse (90 Tage), ≥ 3 Fehlversuche
  vor der Anmeldung, Rolle → Admin, Aufbewahrung verkürzt, Protokoll exportiert; dazu die sicherheitsrelevanten Aktionen
  (`audit.NOTABLE_ACTIONS`). Filter `notable=1`.
- **Sperren begrenzt:** Kontosperre nur für bestehende Konten (`login.locked`, mit `stage`); ein unbekannter Name wird nie
  geschrieben – je Adresse und Stunde ein Eintrag `login.locked_unknown` (höchstens 20/h), der Rest und Adresssperren
  über 20/h in einer Zusammenfassung je Stunde. Eine Sitzung, die nach 5 falschen Codes (zweiter Faktor, erneute
  Bestätigung, Passwortwechsel) endet: `sessions.revoked` mit `why: failures`.
- **Integritätskette:** jeder Eintrag bekommt `seq`, `prev_hash` und `hash` = HMAC-SHA-256 (Schlüssel aus dem
  Hauptschlüssel abgeleitet) über die kanonische Form. Versiegelt wird in jeder Runde der Hintergrundschleife (etwa
  minütlich, `audit.seal`, Advisory-Lock, eigene Sitzung – nie die einer Anfrage), beim Öffnen des Protokolls, beim
  Export und im stündlichen Aufräumen. Der Zustand (`settings` → `audit_chain`: Anker, Kopf, geprüft bis, Funde) trägt
  selbst ein HMAC; ein Zustand, dessen MAC nicht passt oder der fehlt, ist ein Fund – nie ein Anlass, neu zu verankern.
  Geprüft wird inkrementell ab der letzten Prüfung (`GET /api/admin/audit/chain`; läuft die stündliche Prüfung, kommt
  sofort der letzte Stand mit `busy`) und stündlich die ganze Kette in Teilen (`audit.sweep`, 200 000 je Stunde). Funde
  werden einmal als `audit.chain_problem` protokolliert und bleiben „Problem“, bis ein Operator sie bestätigt.
- **Was sie beweist:** „seit dem Versiegeln unverändert, nichts gelöscht oder eingeschoben“ – gegenüber jemandem ohne
  Hauptschlüssel. Nicht: dass ein Eintrag von der App stammt (ein vor dem Versiegeln eingefügter Eintrag wird
  mitversiegelt; liegt seine Zeit mehr als 15 min vor der des vorigen, wird er als `late_entry` markiert), die neuesten
  noch nicht versiegelten Einträge (bis etwa eine Minute), und nichts, was ein Inhaber des Hauptschlüssels tut.
  **Zeuge:** stündlich die Log-Zeile `audit chain head: seq=… hash=… key=… anchor=…` (Logger `cobe_news.audit`) – in
  ein externes Log-System schicken, dann ist auch ein Zurücksetzen des Endes belegbar.
- **Neuer Schlüssel / Operator-Schritt:** passt der Schlüssel nicht (neuer `SECRET_KEY`, geändertes Schlüsselfeld),
  zeigt die Seite `other_key` und versiegelt nichts mehr, bis `python -m app.cli verify-audit --accept-new-key` (oder
  eine Wiederherstellung mit `--ignore-key`) die Kette ab ihrem neuesten Eintrag neu verankert – protokolliert als
  `audit.chain_rekeyed` (auffällig), `rekeyed_at` steht dauerhaft auf der Seite. Damit werden auch geprüfte Funde
  bestätigt.
- **Datenbank-Sperre** (ab 0.1.52, siehe [unten](#datenbank-sperre)): PostgreSQL selbst lässt die App Einträge nur
  hinzufügen, lesen und versiegeln – ändern, löschen, leeren lehnt die Datenbank ab.
- **Aufräumen:** in Kettenreihenfolge bis zum ersten Eintrag innerhalb der Aufbewahrung, sobald der älteste einen Tag
  darüber liegt (also täglich). Zuerst ein `audit.pruned`-Eintrag mit dem neuen Anker (Position, Hash), versiegelt;
  dann Pakete zu 20 000 in eigenen Transaktionen. Ein Anker jenseits des zuletzt erklärten ist ein Fund (`anchor`). Ein
  Eintrag mehr als einen Tag in der Zukunft wird als `future_entry` markiert und hält das Aufräumen nicht auf.
- **Export:** `GET /api/admin/audit/export` nur mit dem CSRF-Token im Header `X-CSRF-Token` (gilt auch für
  `/api/admin/export`); Trennzeichen `delimiter=semicolon` (deutsche Oberfläche) oder Komma; höchstens 100 000 Zeilen,
  sonst Kopfzeile `X-Audit-Truncated` und eine letzte Zeile `# truncated …`; Formelschutz am Zellanfang und nach `,`/`;`
  (im JSON der Einzelheiten als `\u003d` usw.).
- **Kommandozeile:** `export`, `new-setup-token`, `migrate-sqlite`, `restore-test`, `backup`, `restore`,
  `reset-emergency`, `rotate-vapid` werden mit dem Akteur `cli` protokolliert.
- **Leistung** (gemessen mit 2 Mio. Einträgen über 3 Jahre, PostgreSQL 18 lokal): Seiten, alle Filter (Konto, Art,
  Adresse, Sitzung, Ziel, Aktion, Bereich, Auffälliges, Zeitraum), Trefferzahl, die Umgebung eines Eintrags und die
  Akteurliste unter 25 ms; die Freitextsuche über einen Ausdruck mit Trigramm-Index (`ix_audit_log_search`,
  Migration 0033; der Ausdruck in `audit.SEARCH_TEXT` muss genau dem des Index entsprechen): ab 3 Zeichen bei 450 000
  Einträgen ohne Treffer < 1 ms, selten ~10 ms (Index 50 MB); kürzere Begriffe lesen die Tabelle (~60 ms). Versiegeln
  ~16 000 Einträge/s: nach dem Update auf 0.1.50 versiegelt das erste stündliche Aufräumen die vorhandenen Einträge
  (50 000 in ~4 s, 2 Mio. in ~2,5 min, in Paketen). Jedes Versiegeln schreibt die Zeile neu – die Tabelle wird etwa
  doppelt so groß; `VACUUM` gibt den Platz nur zur Wiederverwendung frei, schrumpfen lässt sie `VACUUM FULL audit_log`
  (exklusive Sperre, ~4 s je 450 000 Einträge; Aktionen, die einen Eintrag schreiben, warten so lange);
  Prüfen ~25 000 Einträge/s (beim Öffnen höchstens 50 000, stündlich 200 000 neue und 200 000 der Gesamtprüfung).
  Aufräumen von 1,3 Mio. Einträgen auf einmal (Aufbewahrung stark verkürzt) ~70 s in Paketen, ohne lange
  Sperren; im Normalfall einmal am Tag einen Tag Einträge.

### Datenbank-Sperre

Die Kette deckt eine Änderung **danach** auf; die Sperre (ab 0.1.52) verhindert sie: PostgreSQL selbst lehnt ab, dass
die App einen Eintrag ändert oder löscht. Bis 0.1.51 gehörte `audit_log` wie jede Tabelle der App – ein Besitzer darf
alles (löschen, leeren, Trigger abschalten, die Tabelle löschen); ein einfacher Trigger hätte das nicht verhindert und
die Wiederherstellung blockiert (deshalb in 0.1.50 verworfen).

**Wie** (`deploy/postgres/audit-lock.sql`, von `db-init.sh` als Superuser bei jedem Start der Datenbank nach
`app-role.sql`, mehrfach ausgeführt ändert es nichts):

- `audit_log` (mit Indizes und Sequenz) und das Schema `public` gehören der Rolle **`cobe_news_audit`** (`NOLOGIN`,
  kein Mitglied). Das Schema gehört mit, weil der Besitzer eines Schemas jede Tabelle darin löschen darf
  (`DROP TABLE`, `DROP SCHEMA … CASCADE`); die App behält `USAGE, CREATE` darauf, legt also weiter ihre Tabellen an
  und löscht oder ändert sie als deren Besitzer.
- `cobe_news_app` bekommt auf `audit_log` nur `SELECT, INSERT` und `UPDATE` auf die Spalten der Kette (`seq`,
  `prev_hash`, `hash`, `details`, `notable`). Ein Trigger (`cobe_news_audit_lock`, `ENABLE ALWAYS`) lässt davon nur das
  **Versiegeln** durch: ein noch nicht versiegelter Eintrag bekommt Position, Hashes und höchstens eine Markierung
  dazu (`details.anomalies`, `notable` nur von falsch auf wahr) – sonst ändert sich nichts. Jedes andere UPDATE,
  DELETE und TRUNCATE (`cobe_news_audit_lock_truncate`) lehnt er ab, auch für den Besitzer.
- Gelöscht wird nur über zwei Funktionen von `cobe_news_audit` im Schema `cobe_news_audit` (`SECURITY DEFINER`, fester
  `search_path`, nur für `cobe_news_app` ausführbar):
  - `prune(bis_position, aufbewahrung_tage)` – das stündliche Aufräumen (`audit.prune`): Einträge in Kettenreihenfolge
    bis zur Position, aber nur, wenn **keiner** davon jünger ist als die Aufbewahrung – und die zählt nie weniger als
    **90 Tage**, egal was die App übergibt (die Grenze gilt in der Datenbank, die Einstellung „Aufbewahrung“ kann die App
    selbst ändern). Der Eintrag „Alte Einträge aufgeräumt“ mit dem Anker wird wie bisher vorher geschrieben.
  - `set_aside()` – nur die Wiederherstellung: verschiebt alle Einträge nach `cobe_news_audit.audit_log_replaced`
    (Zeitpunkt, ID, Zeit, der ganze Eintrag als JSON) – **gelöscht wird nichts**. Die App darf diese Tabelle nur lesen;
    das Aufräumen löscht dort, was älter als die Aufbewahrung ist (dieselbe Untergrenze). Die Seite zeigt die Zahl
    („· n beiseitegelegt“) – auch eine, die nicht von einer Wiederherstellung stammt. Ansehen:
    `docker compose exec db psql -U cobe_news cobe_news -c "SELECT replaced_at, id, at, entry->>'action' FROM cobe_news_audit.audit_log_replaced ORDER BY replaced_at, id"`.
    Beiseitegelegtes ist **nicht** in den Sicherungen (`pg_dump --exclude-schema=cobe_news_audit`).
  - dazu `restored()`: setzt nach einer Wiederherstellung die Sequenz hinter die höchste ID (das darf die App nicht).
- Sicherungen tragen die Sperre nie: `pg_dump` lässt das Schema `cobe_news_audit` weg, die Wiederherstellung die zwei
  Trigger. Eine Sicherung mit Sperre lässt sich deshalb überall einspielen (Rücksicherungs-Test, neuer Server, eigenes
  PostgreSQL), und eine ohne in eine gesperrte Datenbank ([Wiederherstellung](#sicherung-wiederherstellung-export),
  Schritt 4). Danach ist die Sperre weiter aktiv – sie hängt an der Datenbank, nicht an der Sicherung.

**Anzeige und Log:** *Protokoll* zeigt neben der Kette „Datenbank-Sperre: aktiv“ bzw. „nicht aktiv (Grund)“, der
Hinweis erklärt es (`GET /api/admin/audit/chain` → `lock`). Beim Start schreibt die App eine Zeile `audit log: database
lock active …` bzw. `… NOT active: …`. Gründe: `no_lock` – ohne das Datenbank-Image (eigenes PostgreSQL, Entwicklung,
Tests): nichts ändert sich, die App arbeitet wie bisher; `pending` – eingerichtet, aber die Tabelle gab es beim Start der
Datenbank noch nicht (eine **neue Installation**: die App legt sie erst bei ihrem ersten Start an). Dann sieht der
Datenbank-Container alle 10 Sekunden nach (bis zu 30 Minuten, im Hintergrund, als derselbe Benutzer ohne Rechte dazu),
und sobald die Migration der App fertig ist – sie läuft in einer Transaktion, die Tabelle gibt es erst mit ihrem
Abschluss – führt er `audit-lock.sql` einmal aus (`db-init: audit_log is there now … – locking it`, dann `audit log
locked`; bekommt er die Tabelle nicht binnen 5 Sekunden, versucht er es 10 Sekunden später noch einmal). Neue
Installationen sind also wenige Sekunden nach dem ersten Start der App gesperrt; kam die App in den 30 Minuten nicht,
folgt die Sperre beim nächsten Start des Datenbank-Containers (`docker compose restart db`). `pending` gilt auch, wenn
`audit-lock.sql` die Übernahme abgelehnt hat (ein fremder Trigger, eine Regel oder Zeilensicherheit auf `audit_log` –
Zeile `db-init: WARNING – audit log NOT locked …` im Log der Datenbank); `superuser` – die App verbindet sich als
Superuser, den hält keine Sperre auf; `incomplete` – ein Teil fehlt oder die App hat ein Recht zu viel (Log prüfen,
Datenbank neu starten).

**Bestehende Installation** (Update auf 0.1.52): nichts zu tun. Das Update legt den Datenbank-Container mit dem neuen
Image neu an, sein `db-init` sperrt die vorhandene Tabelle, dann startet die App (`docker compose logs db | grep
"audit log locked"`).

**Aufheben** (Superuser; z. B. vor dem Weg zurück zu 0.1.51 – deren Aufräumen scheiterte am Trigger, und eine Sicherung
mit den Triggern spielt sie nicht ein, ihr Inhaltsverzeichnis-Check lehnt Trigger ab):

```bash
docker compose exec db psql -U cobe_news cobe_news -c "ALTER TABLE public.audit_log OWNER TO cobe_news_app; ALTER SCHEMA public OWNER TO pg_database_owner; DROP SCHEMA cobe_news_audit CASCADE"
```

`DROP SCHEMA … CASCADE` nimmt die Funktionen, die beiden Trigger und die beiseitegelegten Einträge mit (vorher ansehen,
s. o.). Mit dem 0.1.52-Image sperrt der nächste Start der Datenbank wieder.

**Wogegen sie schützt – und wogegen nicht:** gegen eine kompromittierte App, ein gestohlenes Passwort von
`cobe_news_app` und eine SQL-Injection: wer nur so weit kommt, kann Einträge hinzufügen (die Kette markiert
nachträgliche), aber keinen bestehenden ändern, löschen oder jünger als 90 Tage aufräumen. **Nicht** gegen den
Superuser `cobe_news` oder jemanden mit Zugriff auf Docker auf dem Host (`docker compose exec db psql -U cobe_news`
hebt alles auf) – dagegen hilft nur die Zeile `audit chain head` in einem Log-System außerhalb. Die ganze Datenbank
löschen (`DROP DATABASE`) kann das App-Passwort seit dem Datenbank-Image von 0.1.52 nicht mehr (keine Verbindung zu
`postgres`/`template1`, siehe [Rollen](#rollen)); die Datenbank gehört aber weiter der App: sie kann ihre eigenen
Tabellen löschen (laut, nicht leise – der Weg zurück ist die Sicherung) und Einstellungen der Datenbank setzen, die nur
ihre eigenen Sitzungen treffen. Eine Datenbank, die dem Superuser gehört, schlösse auch das – das bräuchte eine andere
Wiederherstellung (sie legt das Schema `public` neu an) und steht unter *Offene Punkte*.

**Grenzen im Einzelnen** (Durchsicht 0.1.52): Die App besitzt die Erweiterung `pg_trgm` (Migration 0002) und kann sie
löschen (`DROP EXTENSION pg_trgm CASCADE`) – mit ihr geht der Suchindex des Protokolls (`ix_audit_log_search`), keine
Zeile (und der Suchindex der Meldungen); die Suche wird langsamer. Zurück: `CREATE EXTENSION pg_trgm` in der Datenbank
(als App oder Superuser), dann legt der nächste Start der Datenbank den Index des Protokolls wieder an (`audit-lock.sql`). `INSERT` darf schon versiegelte Zeilen schreiben (`seq`, `hash` gesetzt) – das
braucht das `COPY` der Wiederherstellung; eine so eingeschleuste, gefälschte Zeile hält die Datenbank nicht auf, nur die
Prüfung der Kette (sie passt in keine Kette, deren Kopf außerhalb protokolliert ist). `set_aside()` kann die App
jederzeit aufrufen, nicht nur bei einer Wiederherstellung: die Einträge sind dann nicht gelöscht, sondern beiseitegelegt
(die Seite zeigt „· n beiseitegelegt“), und PostgreSQL schreibt eine Warnung ins Log der Datenbank (`set_aside() moved
n audit log entries …`) – kam sie ohne Wiederherstellung, hat jemand das Passwort der App benutzt.

**Wartung:** `VACUUM FULL audit_log` darf die App als Besitzerin der Datenbank weiterhin (es ändert keine Zeile);
alles, was die Tabelle ändert (Spalten, Indizes, Besitz), nur noch der Superuser.

## API-Tokens und Metriken

*Einstellungen → API & Metriken* (`/settings/api`, nur Admins): benannte **API-Tokens nur zum Lesen** für Skripte, ein
SIEM oder Prometheus. Anlegen und Widerrufen brauchen die erneute Bestätigung (Passwort + TOTP); Ablauf 30/90/180/365
Tage – höchstens ein Jahr, „nie“ gibt es seit 0.1.42 nicht mehr (ältere Tokens ohne Ablauf bekamen beim Update
Update-Zeitpunkt + 365 Tage, „Ablauf ergänzt“); höchstens 50 aktive. Das Token (`cnt_` + 43 Zeichen, 256 Bit; Muster für Secret-Scanner
`cnt_[A-Za-z0-9_-]{43}`) erscheint **einmal**; gespeichert wird nur sein HMAC mit dem Hauptschlüssel und die ersten
Zeichen für die Liste. Ein Token gilt nur, solange der Admin, der es angelegt hat, aktiver Admin ist (sonst „verwaist“).
Widerrufene und abgelaufene bleiben 30 Tage in der Liste.

- **Scopes:** `read` = alles unter `/api/v1/` (Nachrichten, Quellen, gefolgte Produkte, Befunde – nichts
  Persönliches); `metrics` = nur `/metrics`. Kein Scope zum Schreiben, kein Admin-Scope. Für Prometheus ein eigenes
  Token nur mit `metrics`.
- **Nutzung:** `Authorization: Bearer cnt_…`, nur `GET`, nur `/api/v1/…` und `/metrics`; anderes → 403
  (`token_read_only`, `token_not_allowed`), zusammen mit einem Sitzungs-Cookie → 400 (`bearer_with_cookie`). Kein CSRF.
  Unbekannt, widerrufen, abgelaufen oder verwaist → immer 401 `invalid_token`; fehlender Scope → 403
  `insufficient_scope`. Grenzen: 600 Anfragen je Token in 10 Minuten; falsche Tokens zählen je Adresse zusammen mit
  falschen Kalender-Adressen (20 in 10 Minuten, dann 429 mit `Retry-After`).
- **Endpunkte:** `/api/v1/news` (Cursor `next` → `before`), `/api/v1/news/sources`, `/api/v1/news/{id}`,
  `/api/v1/vendor/products`, `/api/v1/vendor/products/{key}`, `/api/v1/vendor/findings`. Die OpenAPI-Beschreibung gibt
  es im Reiter „Referenz“ (nur Admins); ein öffentliches `/docs` oder `/openapi.json` gibt es nicht.
- **`/metrics`:** Prometheus-Textformat 0.0.4, 30 s zwischengespeichert: Zustand der Quellen, Kanäle (nur ID und Typ),
  persönliche Zustellungen, Sicherung, Rücksicherungs-Test, Größe der Datenbank, `cobe_news_update_available` – keine
  personenbezogenen Daten.

## Update-Hinweis

`backend/app/update_check.py`: Admins sehen „Version x.y.z verfügbar – Changelog“, wenn GitHub ein neueres Release
nennt (`https://api.github.com/repos/G0urmetD/Cobe-News/releases/latest`, ohne Anmeldung, höchstens alle 12 Stunden,
auch nach Fehlern; ETag; 10 s Zeitlimit, 256 KB; über `news.download` mit Egress-Wächter, Weiterleitungen nur auf
`api.github.com`). Nur fertige `x.y.z` höher als `app.__version__` zählen (Entwürfe, Vorabversionen, andere Tags nicht);
der Link wird aus dem geprüften Tag gebaut, nie aus der Antwort übernommen. Schließen gilt je Admin und Version
(`update_dismissals`). Schalter: Abschnitt `updates` `{"check": true}` (ab Werk an), im Benutzermenü *Version &
Changelog*; aus: keine Anfrage, kein Hinweis. Zustand der letzten Prüfung in `settings` `updates_state`. Leser sehen
nichts (die API `/api/admin/update` nur für Admins). `/metrics`: `cobe_news_update_available` (1/0, NaN aus oder ohne
Antwort).
  `prometheus.yml`: `scheme: https`, `authorization: {type: Bearer, credentials_file: …}`, `tls_config: {ca_file: …}`
  beim selbstsignierten Zertifikat; auf demselben Host auch `http://127.0.0.1:8096`.

Beispiele (curl, PowerShell, Paging), alle Metriken und Alarm-Regeln: Handbuch, Kapitel *API & Metriken*.

## Entwicklung / Tests

```bash
# ein Wegwerf-PostgreSQL 18 für die Tests (Daten im RAM; das Passwort nur lokal, nie ins Repository):
docker run -d --name cobe-news-testdb -p 127.0.0.1:55433:5432 -e POSTGRES_PASSWORD="$PW" --tmpfs /var/lib/postgresql postgres:18-alpine
export TEST_DATABASE_URL="postgresql://postgres:$PW@127.0.0.1:55433/postgres"   # jeder Lauf: eigene Datenbank cn_test_…, danach gelöscht
cd backend && uv sync && uv run pytest -q   # kein echter Feed, kein Microsoft/Slack/Discord/Telegram/Mailserver – alles gemockt
cd frontend && npm install && npm run dev   # UI mit Hot Reload (/api → NEWS_API, Standard http://127.0.0.1:8095)
cd frontend && npm test && npm run lint && npm run format:check && npm run build   # vitest, oxlint, prettier, tsc + vite
```

Browser-Checks `frontend/e2e/select-in-sheet.mjs` (Escape/Tastatur bei Select und Tooltip in einer Schublade, cmdk-Liste)
und `frontend/e2e/signin-settings.mjs` (Bestätigung mit Passwort/Code immer obenauf und bedienbar, auch wenn danach eine
Schublade einhängt; Toast bei „Verbindung testen“ für AD/LDAP und Entra ID – die Test-Antworten kommen aus dem Skript) –
nur gegen eine Wegwerf-Instanz (eigenes `DATA_DIR`, nie die echte), mit dem installierten Google Chrome und einem schon
vorhandenen Playwright (steht bewusst nicht in `package.json`, lädt keinen Browser herunter):

```bash
cd backend && DATABASE_URL=postgresql://…/cn_e2e DATA_DIR=/tmp/cn-e2e NEWS_LOOP=0 COOKIE_SECURE=0 uv run uvicorn app.main:app --port 8611   # Admin per Setup-Token anlegen
cd frontend && NEWS_API=http://127.0.0.1:8611 npx vite --port 5611
cd frontend && BASE_URL=http://localhost:5611 CREDS=/tmp/cn-e2e/creds.json \
  PLAYWRIGHT=/pfad/zu/node_modules/playwright/index.mjs node e2e/select-in-sheet.mjs   # creds.json: {"user","password","totp"}
# ebenso: node e2e/signin-settings.mjs (speichert AD/LDAP der Wegwerf-Instanz mit Namen unter corp.example)
```

**Basis-Images** sind mit ihrem Digest festgeschrieben (`Dockerfile`: `node:24-slim@sha256:…`, `python:3.13-slim@sha256:…`;
`deploy/postgres/Dockerfile`: `postgres:18-alpine@sha256:…`; `deploy/nginx/Dockerfile`: `nginx:1.30-alpine@sha256:…`;
die Release-Pipeline baut daraus auch die Images `cobe-news-db` und `cobe-news-proxy`) – ein Build nimmt genau
diese Images, auch wenn unter dem Tag inzwischen ein anderes liegt. Aktualisieren – **zu jedem Release**, dazwischen
nach einer Sicherheitsmeldung: `docker buildx imagetools inspect <image:tag>` zeigt den aktuellen Digest („Digest:“ des
Index, nicht der einer Plattform), ihn an allen Stellen eintragen (Tag bleibt, Kommentare bleiben), bauen, Tests und ein
Wegwerf-Stack wie bei jedem Update, dann `scripts/scan-images.sh <die drei Wegwerf-Images>` (siehe [Release](#release)).
Was Debian bzw. Alpine nach dem Basis-Image korrigiert hat, holt der Build ohnehin: `apt-get upgrade` im App-Image,
`apk upgrade` in Datenbank und Proxy – der Digest bestimmt nur den Ausgangspunkt. Das App-Image enthält kein pip
(nach dem Installieren der Abhängigkeiten entfernt, ebenso das Wheel von `ensurepip`); das Datenbank-Image wechselt zum
Benutzer `postgres` mit `su-exec` aus Alpine statt mit dem `gosu` des Basis-Images (mit einer alten Go-Version gebaut).
Warum ein Scan trotzdem Befunde zeigt: [`SICHERHEIT-SCANS.md`](SICHERHEIT-SCANS.md). Beim nginx
zählt auch der Zweig: nur der aktuelle *stable*-Zweig (gerade Minor-Nummer, jedes Frühjahr ein neuer – 1.30 seit April 2026)
bekommt Sicherheitskorrekturen, der vorige keine mehr; dann den Tag wechseln (`nginx:1.30-alpine` → `nginx:1.32-alpine`).
Der Datenbank-Container läuft schreibgeschützt (nur sein Volume und tmpfs), ohne Capabilities außer denen, mit denen
der Einstiegspunkt den Datenordner dem Benutzer `postgres` gibt und zu ihm wechselt.

Aufbau:

```
backend/app/db.py             PostgreSQL (asyncpg): Verbindungen, Timeouts, Migrationen (backend/app/migrations, Alembic)
backend/app/sqlite_import.py  einmaliger Umzug einer 0.1.15-SQLite-Datei nach PostgreSQL
backend/app/backup.py         Sicherung (pg_dump), Wiederherstellung, Export ohne Geheimnisse
backend/app/news.py           Abruf, Parsing, Dedupe, Schwere-Regeln, Backoff, Logos
backend/app/api.py            News-API
backend/app/auth_api.py       Setup, Anmeldung, TOTP, Entra-OIDC, eigenes Konto
backend/app/auth/             Passwörter, TOTP, Sitzungen, Sperren, AD/LDAP, Entra, Abgleich
backend/app/admin_api.py      Benutzer, Anmeldung, Gruppen → Rollen, HTTPS-Status
backend/app/teams*.py         Teams: Gruppen laden (AD/Entra, verschachtelt), Mitglieder, Produkte, Willkommens-Mail
backend/app/notify*.py        Kanäle, Regeln, Versand: Mail/Teams/Slack/Discord/Telegram/Webhook
backend/app/vendor*.py        Vendor News: Katalog, Versionsvergleich, Abgleich, Quellen, Abruf, API
backend/app/docs.py           Handbuch (/api/docs): Kapitel aus docs/handbuch/<sprache>/, Admin-Teile nur für Admins
backend/app/catalog/          Katalogdaten (YAML je Kategorie, Kategorien, Texte, Schema) – geprüft von app/catalog_data.py
backend/app/story_details.py  Details aus der Quelle: CSAF (BSI, Siemens, Cisco, Fortinet), Palo Alto CVE 5, NVD je Meldung
backend/app/csaf_providers.py CSAF-Anbieter der Hersteller (Liste des BSI, ROLIE/changes.csv, Prüfsumme, TLP, Marke)
backend/app/cvelist.py        cvelistV5: Änderungen dreimal am Tag und Tagesabschluss, einzelne Einträge bei Bedarf
backend/app/epss.py           FIRST EPSS je CVE (Befunde, Meldungen)
backend/app/osv.py            OSV.dev: Bereiche von Open-Source-Paketen, nur nach CVE-/Advisory-Nummer
backend/app/exploits.py       Exploit-Hinweise: Metasploit, Exploit-DB, nuclei-templates – je CVE Liste und Link, täglich
backend/app/update_check.py   Update-Hinweis für Admins: GitHubs neuestes Release, höchstens alle 12 Stunden
backend/app/data/             mitgelieferter Katalog (python -m app.vendor_catalog <endoflife-dump.json> baut ihn neu)
backend/app/webpush.py        Web Push: Verschlüsselung (RFC 8291), VAPID (RFC 8292), Versand nach jeder Runde
frontend/public/sw.js         Service Worker – nur Push und Klick auf eine Benachrichtigung, kein Cache
backend/app/netaddr.py        Ziel-Prüfung (SSRF), DNS-Pinning
backend/app/tls.py            Zertifikat
deploy/nginx/                 Proxy-Image: nginx-Vorlage, Namen, Zertifikatswächter (Dockerfile)
deploy/postgres/              Datenbank-Image: Einstiegspunkt mit der Rolle der App und der Sperre des Protokolls bei jedem Start (Dockerfile)
frontend/src/pages/           Oberfläche
```

**Migrationen am Protokoll** (seit der [Datenbank-Sperre](#datenbank-sperre), 0.1.52): Mit Sperre darf die App
`audit_log` nicht ändern. Eine Migration, die die Tabelle anfasst, prüft deshalb zuerst
`app.audit_lock.ddl_skipped(op.get_bind(), revision)` – gesperrt lässt sie den Teil aus (eine Log-Zeile sagt es), ohne
Sperre (Entwicklung, eigenes PostgreSQL) macht sie ihn selbst. Dieselbe Änderung kommt **idempotent** in
`deploy/postgres/audit-lock.sql` (z. B. `ALTER TABLE public.audit_log ADD COLUMN IF NOT EXISTS …`, ein neuer Index mit
`CREATE INDEX IF NOT EXISTS` und dem Namen `ix_audit_log_…`), vor die Übergabe an `cobe_news_audit`: Beim Update startet
zuerst die Datenbank mit dem neuen Image (Superuser, vor der App), dann migriert die App. So machen es 0017, 0032 und
0033 – auch die Vergleichsbasis einer Wiederherstellung migriert von vorn neben der gesperrten Tabelle. Eine neue
Spalte ist für die App automatisch unveränderlich (der Trigger vergleicht alle Spalten außer denen der Kette);
`tests/test_audit_lock.py` richtet die Sperre mit den echten SQL-Dateien ein.

Regeln für neue Masken (was gesetzt ist vs. Eingabe, Reihenfolge, Tooltips, Leerzustände, Status-Farben, Datumsformat,
Löschen, Fokus in Schubladen, 375 px, Hell/Dunkel): [`docs/UX.md`](UX.md).

## Versionierung

0.1.x – jedes Release erhöht die letzte Stelle; Änderungen werden dafür gesammelt. Was sich geändert hat: [`CHANGELOG.md`](../CHANGELOG.md).

## Release

Gearbeitet wird nie direkt auf `main` (geschützt), sondern in eigenen Branches mit Pull Requests – dabei läuft keine
Pipeline. Ein Release startet nur mit einem Tag:

```bash
git tag v0.1.51 && git push origin v0.1.51   # die Version aus backend/app/__init__.py
```

Die einzige Pipeline, [`.github/workflows/release.yml`](../.github/workflows/release.yml), prüft dann, dass der Tag zu
allen Versionsangaben passt (`backend/app/__init__.py`, `backend/pyproject.toml`, `backend/uv.lock`,
`frontend/package.json`, `frontend/package-lock.json`) und `CHANGELOG.md` einen Abschnitt `## <Version> – …` hat, lässt die
Backend-Tests (mit PostgreSQL 18), die Frontend-Prüfungen, Tests und den Build laufen und prüft die Abhängigkeiten auf
bekannte Schwachstellen. Erst wenn alles grün ist, baut sie die drei Images für amd64 und arm64 – die App (`Dockerfile`),
die Datenbank (`deploy/postgres`) und den Proxy (`deploy/nginx`) – mit Provenance und SBOM und legt sie **nur unter ihrem
Digest** ab, ohne Tag; dann scannt sie die drei Digests (Trivy, siehe unten – ein behebbarer hoher oder kritischer
Befund stoppt hier) und signiert sie erst danach (cosign, ohne gespeicherten Schlüssel). Erst wenn alle drei gebaut,
gescannt und signiert sind, prüft der Job `publish` Signaturen und Attestierungen und setzt die Tags auf genau diese
Digests – ohne Neubau: `ghcr.io/g0urmetd/cobe-news:<Version>`, `ghcr.io/g0urmetd/cobe-news-db:<Version>`,
`ghcr.io/g0urmetd/cobe-news-proxy:<Version>`, und `:latest` nur, wenn der Tag das höchste Release ist (ein Backport auf
eine ältere Linie schiebt `latest` nie zurück; nie zwei Releases gleichzeitig). Scheitert vorher etwas, bleibt kein Tag
zurück – nur Digests ohne Tag –, `latest` zeigt weiter auf das vorige vollständige Release. Weil die Signatur den Digest
abdeckt, gilt sie für jeden Tag darauf. Zuletzt schreibt sie den GitHub-Release mit dem Text aus dem Changelog, den
drei Digests und den Berichten des Scans. Neue Pakete auf ghcr.io sind zuerst privat: nach dem ersten Release mit
`cobe-news-db` und `cobe-news-proxy` beide unter *Packages → Package settings* auf *Public* stellen (wie `cobe-news`),
sonst scheitert das Holen ohne Anmeldung (Portainer: „unauthorized“).

Prüfen der Signaturen (die Images `-db` und `-proxy` gibt es ab 0.1.49):

```bash
v=0.1.51
for i in cobe-news cobe-news-db cobe-news-proxy; do
  cosign verify ghcr.io/g0urmetd/$i:$v \
    --certificate-identity-regexp '^https://github\.com/G0urmetD/Cobe-News/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
done
```

**Scan vor dem Signieren**: Nach dem Build und vor dem Signieren scannt der Job `image` die drei Digests – genau so,
wie sie in der Registry liegen, für amd64 und arm64 – mit Trivy ([`scripts/scan-images.sh`](../scripts/scan-images.sh),
`--severity HIGH,CRITICAL --ignore-unfixed --exit-code 1`). Ein hoher oder kritischer Befund, für den es eine
korrigierte Version gibt, lässt den Schritt scheitern: nichts wird signiert, kein Tag, `latest` bleibt (wie bei jedem
Fehler bleiben nur Digests ohne Tag). Befunde ohne Korrektur stoppen den Release nicht. Die vollständigen Berichte – alle
Schweregrade, auch ohne Korrektur, je Image und Plattform als Tabelle (`trivy-<image-referenz>-<plattform>.txt`) und JSON – hebt
die Pipeline auch bei einem Fehlschlag als Artefakt `trivy-reports` des Workflow-Laufs auf (Actions → der Lauf → Artifacts); in den
GitHub-Release kommen sie nicht. Was der Release damit zusichert und warum Befunde ohne Korrektur bleiben:
[`SICHERHEIT-SCANS.md`](SICHERHEIT-SCANS.md). Die Pipeline nimmt Trivy ohne fremde Action: das Archiv einer festen
Version (`TRIVY_VERSION`) von Trivys GitHub-Release, geprüft mit seiner Prüfsumme (`TRIVY_SHA256`). Eine neue Version
eintragen: die Prüfsummenliste des Releases und ihre Signatur holen und prüfen, dann beide Werte und im Skript das Image
`TRIVY_IMAGE` (dieselbe Version, Digest des Index) ändern:

```bash
t=0.76.2
gh release download v$t -R aquasecurity/trivy -p "trivy_${t}_checksums.txt*"
cosign verify-blob trivy_${t}_checksums.txt --bundle trivy_${t}_checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v$t" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
grep "_Linux-64bit.tar.gz$" trivy_${t}_checksums.txt   # → TRIVY_SHA256 in release.yml
docker buildx imagetools inspect aquasec/trivy:$t       # „Digest:“ → TRIVY_IMAGE in scripts/scan-images.sh
```

**Derselbe Scan lokal**, vor einem Release auf den Wegwerf-Build oder jederzeit auf eine Installation:

```bash
scripts/scan-images.sh                    # der lokale Build: cobe-news:latest, cobe-news-db:latest, cobe-news-proxy:latest
scripts/scan-images.sh 0.1.55             # die veröffentlichten Images einer Version (von ghcr.io, ohne docker pull)
scripts/scan-images.sh img/app:test img/db:test img/proxy:test   # beliebige Images, z. B. ein Wegwerf-Build
PLATFORMS="linux/amd64 linux/arm64" scripts/scan-images.sh 0.1.55   # jede Plattform einzeln
```

Die geprüften Images werden nur gelesen – nie nach Docker geholt, nie getaggt; kein Compose, kein Container der App.
Ohne installiertes Trivy holt das Skript Trivys offizielles Image (`aquasec/trivy`, dieselbe Version, per Digest
festgeschrieben; `TRIVY=docker` erzwingt das) und legt für dessen Schwachstellen-Datenbank das Volume
`cobe-news-trivy-cache` an (`TRIVY_CACHE_VOLUME`); für lokale Images bekommt der Container den Docker-Socket. Die
Prüfung gehört dem Skript allein: `--config "" --ignorefile ""` (keine `trivy.yaml`, keine `.trivyignore`), und von
`TRIVY_*` aus der Umgebung gelten nur `TRIVY_IMAGE_SRC`, `TRIVY_DB_REPOSITORY`, `TRIVY_CACHE_DIR`. Hat das gelesene Image
nicht die verlangte Plattform, gilt der Scan als gescheitert; ebenso, wenn die Prüfung „bestanden“ sagt, der volle
Bericht aber einen behebbaren hohen oder kritischen Befund enthält. Berichte in `trivy-reports/<Zeit>/` (in
`.gitignore`; anderer Ordner: `OUT=…`): `summary.md` und je Image und Plattform `.txt` und `.json`, benannt nach der
ganzen Image-Referenz (ein Digest auf 12 Stellen gekürzt). Exit-Code 0: bestanden, 1: behebbarer hoher oder kritischer
Befund (aufgelistet), 2: falscher Aufruf oder Scan gescheitert.

Die Images statt eines lokalen Builds betreiben: [Veröffentlichtes Image statt lokalem Build](#veröffentlichtes-image-statt-lokalem-build).

## Offene Punkte

- Keine Wiederherstellungscodes für den zweiten Faktor (der Notfall-Admin wird über `app.cli` zurückgesetzt).
- Ein App-Prozess: Fehlversuch-Zähler, Rate-Limits und der Hintergrundjob leben im Speicher (ein Neustart setzt die
  Zähler zurück – laufende Konto- und Adress-Sperren bleiben, Tabelle `auth_locks`).
- AD/LDAP: der Servername wird vor der Verbindung geprüft (`netaddr.check_host`), aber nicht auf die geprüfte Adresse
  festgenagelt (kein DNS-Pinning wie bei den Kanälen) – ein DNS, das zwischen Prüfung und Verbindung die Antwort
  wechselt, könnte die Bind-Anfrage umlenken; LDAPS mit Zertifikatsprüfung schützt das Bind-Passwort trotzdem.
- Datenbank-Image: die Datenbank `cobe_news` gehört der App (`cobe_news_app`). Sie kann deshalb Einstellungen der
  Datenbank setzen (`ALTER DATABASE … SET`, auch `ALLOW_CONNECTIONS false` – ein Start der Datenbank scheitert dann,
  bis der Superuser es über `postgres` zurücknimmt) und `VACUUM FULL` jeder Tabelle. Superuser als Besitzer und für
  die App nur `CONNECT, CREATE, TEMP` schlösse das; die Wiederherstellung ohne Sperre legt dafür aber das Schema
  `public` neu an (`DROP SCHEMA public … AUTHORIZATION pg_database_owner`), das ginge dann nicht mehr. Bis dahin:
  kein `DROP DATABASE` (Rollen), kein Code der App als Superuser (fester `search_path`).
- Vendor News: Cisco openVuln (mit Zugangsdaten) und Microsofts CVRF nicht eingebaut.
- Katalog: Build-Tabellen fehlen noch für SEP (RU ↔ Build), Skype for Business (CU ↔ Build), LANCOM (SU/RU), Acronis
  (Build) und ManageEngine (nur Build-Nummern) – es gibt dafür keine offizielle Tabelle, die sich übernehmen ließe.
  Citrix hat keine maschinenlesbare Bulletin-Quelle (nur CVE-Daten). Ohne CPE in der NVD (nur News und
  Herstellerdaten): Matrix42 Empirum, Aagon ACMP, Datto RMM, Swyx, d.velop, ELO, DocuWare, ESET PROTECT, G DATA, NCP VPN
  Server, SAProuter, INSYS icom, Fujitsu iRMC, HPE iLO 7, Drucker/MFP (Dell iDRAC10 hat seit Katalog 2026.11.03-1 die
  CPE `o:dell:idrac10_firmware`). Dovecot ist an den CSAF-Anbieter Open-Xchange angebunden, dessen Dokumente
  TLP:GREEN tragen – gelesen nur, wenn ein Admin TLP:GREEN für Open-Xchange zulässt (siehe „CSAF-Anbieter“). Dells CVE-Einträge für iDRAC9 nennen
  14G und 15G/16G in einer Zeile „iDRAC9“ mit je eigener Grenze – ein 14G-Build über 7.00.00.18x gilt dort als betroffen
  bis zur 15G/16G-Grenze (eine Generation steht nicht in der Version).
- Weitere Quellen: OpenPGP-Signaturen der CSAF-Dokumente werden nicht geprüft (nur die Prüfsumme); Microsofts CSAF/VEX
  nicht eingetragen; gespeicherte Einträge von cvelistV5 und OSV werden (wie die der NVD) nicht aufgeräumt, wenn einem
  Produkt nicht mehr gefolgt wird; fehlen der App mehr als 3 Tage, holt cvelistV5 die Tage davor nicht nach (die NVD
  bringt sie).
