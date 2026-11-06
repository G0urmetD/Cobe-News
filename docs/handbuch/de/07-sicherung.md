---
title: Sicherung & Wiederherstellung
summary: Die Datenbank sichern, verschlüsseln, täglich per cron wegkopieren, die Sicherung automatisch zur Probe zurückspielen, wiederherstellen – auch auf einem neuen Server – und die Einstellungen ohne Geheimnisse exportieren.
audience: admin
---

## Überblick {#ueberblick}

Eine Sicherung ist **eine Datei** mit der ganzen Datenbank: Quellen, Meldungen, Benutzer, Kanäle, Regeln, Vendor
News, Einstellungen. Sie entsteht über „Jetzt sichern“ in der App oder per Befehl (z. B. täglich per
[cron](term:cron)). Die Seite dazu: *Einstellungen → Sicherung & Export* (Bereich „Betrieb“,
[direkt öffnen](/settings/backup)).

### Was in einer Sicherung steckt {#inhalt}

- `db.dump` – die Datenbank als `pg_dump` im Custom-Format,
- `manifest.json` – App-Version, Schema-Stand, Zeilen je Tabelle, Prüfsummen und der Fingerabdruck des Schlüssels.
  Zählung und Dump stammen aus demselben Stand der Datenbank,
- `manifest.sig` – die Signatur (siehe [Signatur](#signatur)),
- nur bei verschlüsselten Sicherungen: der [Hauptschlüssel](term:masterkey) (siehe [Verschlüsselung](#verschluesselung)).

| Datei | Wann |
|---|---|
| `cobe-news-JJJJMMTT-HHMMSS.tar` | ohne Passphrase – nicht verschlüsselt, **ohne** Schlüssel |
| `cobe-news-JJJJMMTT-HHMMSS.tar.enc` | mit einer Passphrase – verschlüsselt, **mit** Schlüssel |
| `…-pre-restore.tar` bzw. `.tar.enc` | automatisch direkt vor einer Wiederherstellung |

Die Zeit im Namen ist UTC.

**Wo:** im Container unter `/data/backups`, auf dem Server im Installationsordner unter `data/backups/`, also
`/opt/cobe-news/data/backups/`. Die Dateien sind nur für den App-Prozess lesbar (Ordner 0700, Dateien 0600).

### Aufbewahrung {#aufbewahrung}

Unter **„Aufbewahrung“** wird festgelegt, wie viele Sicherungen auf dem Server bleiben: die letzten 3, 7, 14, 30 oder 90
(Standard: 7). Ist eine neue Sicherung fertig, werden die ältesten darüber hinaus gelöscht – **auch die per cron
angelegten**.

- Weniger aufbewahren löscht ältere Sicherungen **sofort**. Vorher fragt die Seite („Ältere Sicherungen löschen?“ –
  „Löschen und speichern“) und verlangt die [erneute Bestätigung](/docs/anmeldung#erneut-bestaetigen) eurer Identität.
- Sicherungen vor einer Wiederherstellung (`…-pre-restore…`) zählen nicht mit; sie bleiben 30 Tage.

> [!WARNING]
> Eine Sicherung auf demselben Server hilft nicht, wenn der Server ausfällt. Die Dateien zusätzlich auf ein anderes
> System kopieren – siehe [cron](#cron).

## Schritt für Schritt: sichern, herunterladen, einspielen {#schritt-fuer-schritt}

Die Sicherungen liegen **nur auf dem Server**. Einen Download oder ein Einspielen im Browser gibt es bewusst nicht –
eine Sicherung enthält alle Daten. Herunterladen (auf ein anderes System kopieren) und Einspielen geschehen per Befehl
auf dem Server. Der [Rücksicherungs-Test](#ruecksicherungs-test) ist dagegen nur eine Probe: Er spielt die neueste
Sicherung in eine Wegwerf-Datenbank und ändert an euren Daten nichts.

Die Beispiele nehmen die Datei `cobe-news-20261104-123000.tar.enc`; die Ausgabe der Sicherung und die Liste auf der
Seite nennen den echten Namen.

### Was ihr dafür braucht {#was-man-braucht}

| Was | Wofür |
|---|---|
| die Sicherungsdatei | Schritt 2 unten – eine Kopie außerhalb des Servers |
| bei `.tar.enc`: die **Passphrase** | entschlüsselt die Datei; der Hauptschlüssel steckt darin. Aufbewahren im Passwort-Manager, nicht auf demselben Server |
| bei `.tar`: eine Kopie des **Hauptschlüssels** | nur auf einem **neuen** Server – auf demselben Server ist er schon da. Ohne ihn ist alles da, nur die gespeicherten Geheimnisse (Webhook-URLs, SMTP-/LDAP-Passwörter, Entra-Geheimnis, TOTP) sind neu einzugeben |
| das Passwort der Datenbankrolle | lokal steht es in der `.env`; bei Portainer braucht der Wegwerf-Container `POSTGRES_APP_PASSWORD` aus den Variablen des Stacks |
| dieselbe oder eine neuere Cobe News | eine ältere Sicherung wird auf den Stand der Version gebracht, die einer **neueren** Version abgelehnt. Die Version steht in der Ausgabe (`Backup of … – Cobe News 0.1.50 …`) |

Der [Hauptschlüssel](term:masterkey) entsteht beim ersten Start als `secret.key` im Datenordner (oder kommt aus
`SECRET_KEY`). Lesen lässt er sich nur auf dem Server – einmal kopieren und offline aufbewahren (Passwort-Manager,
verschlüsselter Stick), nie in Tickets oder Chats:

```bash
umask 077
docker exec cobe-news-app cat /data/secret.key > cobe-news-secret.key   # Portainer: news-app-1 statt cobe-news-app
```

Steht `SECRET_KEY` in der `.env` bzw. in den Variablen des Stacks, ist das der Schlüssel – dann diesen Wert aufbewahren.

### Lokale Installation (docker compose) {#schritte-lokal}

Im Installationsordner, z. B. `/opt/cobe-news`; die Container heißen `cobe-news-app` und `cobe-news-db`, die Dateien
liegen auf dem Host unter `data/backups/`.

**1. Sichern** – in der App „Jetzt sichern“ oder per Befehl:

```bash
cd /opt/cobe-news
docker compose exec -T app python -m app.cli backup
docker compose exec -T app python -m app.cli backup --passphrase-file - < /root/.cobe-news-backup-pass
```

Die erste Zeile verschlüsselt mit der Passphrase der App ([Passphrase-Datei](#passphrase-datei)) oder, ohne sie,
gar nicht. Die zweite gibt die Passphrase über die Standardeingabe mit – sie steht in keiner Befehlszeile.

**2. Herunterladen** – `docker compose cp` schreibt die Kopie mit eurem Benutzer (die Dateien in `data/backups/` darf
nur der Container lesen), `scp` bringt sie auf ein anderes System:

```bash
docker compose cp app:/data/backups/cobe-news-20261104-123000.tar.enc .
scp cobe-news-20261104-123000.tar.enc backup-host.corp.example:/srv/cobe-news/
```

Alle auf einmal, ohne halbfertige und versteckte Dateien, wie im [cron-Beispiel](#cron):
`sudo rsync -a --exclude='.*' --exclude='*.partial' data/backups/ backup-host.corp.example:/srv/cobe-news/`.

**3. Einspielen** – auf demselben Server, die Datei liegt noch in `data/backups/`:

```bash
cd /opt/cobe-news
docker compose stop app
docker compose run --rm --no-deps app python -m app.cli restore /data/backups/cobe-news-20261104-123000.tar.enc
docker compose start app
```

Zum Bestätigen `RESTORE` tippen; vorher wird der aktuelle Stand gesichert. Eine `.tar.enc` öffnet der Befehl mit der
Passphrase-Datei der App; ohne sie die Passphrase vorher einlesen und mitgeben:
`read -rs BACKUP_PASSPHRASE && export BACKUP_PASSPHRASE`, dann `docker compose run --rm --no-deps -e BACKUP_PASSPHRASE app …`
(siehe [Wiederherstellung](#wiederherstellung)).

**Auf einem neuen Server** – Cobe News installieren (noch nicht starten), dann:

```bash
cd /opt/cobe-news
sudo mkdir -p data/backups
sudo cp /pfad/zur/cobe-news-20261104-123000.tar.enc data/backups/
sudo cp /pfad/zum/cobe-news-secret.key data/secret.key   # nur bei einer .tar
sudo chown -R 10001 data && sudo chmod 600 data/secret.key
docker compose build && docker compose up -d --wait db
docker compose run --rm --no-deps -e BACKUP_PASSPHRASE app python -m app.cli restore /data/backups/cobe-news-20261104-123000.tar.enc --use-backup-key
docker compose up -d
```

Bei `.tar.enc` vorher `read -rs BACKUP_PASSPHRASE && export BACKUP_PASSPHRASE`; `--use-backup-key` übernimmt den
Schlüssel aus der Sicherung. Bei `.tar` ohne `-e BACKUP_PASSPHRASE` und ohne `--use-backup-key` – der Schlüssel liegt
schon in `data/`. Mehr: [Neuer Server](#neuer-server).

### Portainer-Stack {#schritte-portainer}

Ohne Checkout auf dem Host: die Container heißen nach dem Stack, hier `news` – `news-app-1`, `news-db-1`, die Volumes
`news_data` (darin `backups/` und `secret.key`) und `news_db18`. Die Befehle laufen auf dem Docker-Host (SSH),
nicht in Portainer.

**1. Sichern** – in der App „Jetzt sichern“ oder per Befehl:

```bash
docker exec news-app-1 python -m app.cli backup
docker exec -i news-app-1 python -m app.cli backup --passphrase-file - < /root/.cobe-news-backup-pass
```

**2. Herunterladen** – eine Datei mit `docker cp`, alle auf einmal mit `tar` aus dem Container (ohne halbfertige und
versteckte Dateien), dann mit `scp` weg:

```bash
docker cp news-app-1:/data/backups/cobe-news-20261104-123000.tar.enc .
mkdir -p /srv/cobe-news-backups && docker exec news-app-1 tar -C /data/backups -cf - --exclude='./.*' --exclude='*.partial' . | tar -C /srv/cobe-news-backups -xf -
scp cobe-news-20261104-123000.tar.enc backup-host.corp.example:/srv/cobe-news/
```

**3. Einspielen** – liegt die Datei nicht mehr im Volume (z. B. auf einem neuen Server), sie erst hineinlegen, als
Benutzer der App:

```bash
docker exec -i news-app-1 sh -c 'umask 077; mkdir -p /data/backups && cat > /data/backups/cobe-news-20261104-123000.tar.enc' < cobe-news-20261104-123000.tar.enc
```

Dann die App anhalten, die Sicherung in einem Wegwerf-Container mit demselben Image, dem Datenbank-Netz und dem Volume
`data` einspielen, die App starten. Passwort und Passphrase kommen aus der Shell, nicht von der Befehlszeile:

```bash
IMG=$(docker inspect -f '{{.Config.Image}}' news-app-1)
docker stop news-app-1
read -rs POSTGRES_PASSWORD && export POSTGRES_PASSWORD   # der Wert von POSTGRES_APP_PASSWORD aus dem Stack
read -rs BACKUP_PASSPHRASE && export BACKUP_PASSPHRASE   # nur bei .tar.enc
docker run --rm -it --network news_db -v news_data:/data --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true -e POSTGRES_HOST=db -e POSTGRES_USER=cobe_news_app -e POSTGRES_PASSWORD \
  -e BACKUP_PASSPHRASE "$IMG" python -m app.cli restore /data/backups/cobe-news-20261104-123000.tar.enc
unset POSTGRES_PASSWORD BACKUP_PASSPHRASE
docker start news-app-1
```

Zum Bestätigen `RESTORE` tippen. Steht `SECRET_KEY` in den Variablen des Stacks, zusätzlich `-e SECRET_KEY` (vorher
ebenso mit `read -rs` setzen).

**Auf einem neuen Server** – den Stack wie gewohnt anlegen (er startet leer und legt einen eigenen Schlüssel an),
die Datei wie oben ins Volume legen, dann:

- bei `.tar.enc`: an den `restore`-Befehl `--use-backup-key` anhängen – der Schlüssel der Sicherung ersetzt den neuen
  (der bleibt als `secret.key.before-restore-…` daneben).
- bei `.tar`: nach `docker stop` und vor dem `restore` den aufbewahrten Schlüssel ins Volume schreiben. Der Befehl
  prüft, dass die Datei nicht leer ist, schreibt erst eine neue Datei und tauscht sie dann aus; der bisherige Schlüssel
  bleibt als `secret.key.before-restore-<Zeit>` daneben (auch bei einem zweiten Lauf wird nichts überschrieben):

```bash
test -s cobe-news-secret.key && docker run --rm -i -v news_data:/data --network none "$IMG" sh -ec '
  umask 077; cat > /data/secret.key.new
  [ "$(wc -c < /data/secret.key.new)" -ge 16 ] || { rm -f /data/secret.key.new; echo "key empty or cut off - nothing changed" >&2; exit 1; }
  [ ! -e /data/secret.key ] || cp -p /data/secret.key "/data/secret.key.before-restore-$(date -u +%Y%m%d-%H%M%S)"
  mv /data/secret.key.new /data/secret.key' < cobe-news-secret.key
```

## Jetzt sichern {#jetzt-sichern}

1. *Einstellungen → Sicherung & Export* öffnen.
2. **„Jetzt sichern“** klicken.

Die Sicherung läuft im Hintergrund weiter, auch bei einer großen Datenbank. Die Seite zeigt „Sicherung läuft …“, der
Knopf heißt so lange „Sichert …“ mit „Läuft seit …“, und die Seite fragt alle 2 Sekunden nach. Ist sie fertig,
erscheint „Sicherung … angelegt“ oder eine Fehlermeldung. Es läuft immer nur **eine** Sicherung – auch eine per cron
oder Befehl gestartete sperrt den Knopf.

Der Kopf des Abschnitts zeigt den Stand:

| Anzeige | Bedeutung |
|---|---|
| Gesichert | letzte Sicherung erfolgreich, jünger als 7 Tage |
| Älter als 7 Tage | letzte erfolgreiche Sicherung ist älter – bald sichern |
| Letzte Sicherung fehlgeschlagen | der letzte Versuch ist gescheitert |
| Noch keine Sicherung | es gab noch keine |

**„Letzte Sicherung“** nennt Datei, Zeit, Größe und Zeilen – oder bei einem Fehler „Fehlgeschlagen am …“ mit dem Grund
und der technischen Meldung. Häufige Gründe:

| Meldung | Abhilfe |
|---|---|
| Die Passphrase ist zu kurz | mindestens 12 Zeichen verwenden |
| pg_dump hat nicht rechtzeitig geantwortet | Datenbank und Speicher prüfen, erneut versuchen |
| pg_dump ist fehlgeschlagen | technische Meldung und `docker compose logs app` lesen |

| Die Passphrase-Datei (BACKUP_PASSPHRASE_FILE) ließ sich nicht lesen | der Kasten über der Liste nennt den Grund – [Passphrase-Datei](#passphrase-datei) |

Darunter steht die Liste der Sicherungen auf dem Server (Datei, Erstellt, Größe, Verschlüsselung), die neuesten 10, mit
„Alle anzeigen“ alle:

| Anzeige | Bedeutung |
|---|---|
| Verschlüsselt · Schlüssel enthalten | `.tar.enc`: zum Einspielen – auch auf einem neuen Server – genügen Datei und Passphrase |
| Unverschlüsselt · Schlüssel getrennt aufbewahren | `.tar`: vollständig, auf diesem Server ohne Weiteres einzuspielen; auf einem neuen Server braucht es dazu eine Kopie des Hauptschlüssels ([Was ihr dafür braucht](#was-man-braucht)) |

Hover, Tastaturfokus oder Antippen zeigt dieselbe Erklärung an der Anzeige. Eine unverschlüsselte Sicherung ist also
nicht wertlos – ihr fehlt nur der Schlüssel für die gespeicherten Geheimnisse.

Neben dem Knopf steht, was „Jetzt sichern“ anlegen wird: „Verschlüsselt, mit Hauptschlüssel“, wenn die App eine
Passphrase hat, sonst „Wird unverschlüsselt angelegt – die App selbst kennt keine Passphrase“. Stehen daneben
verschlüsselte Sicherungen in der Liste, kommen die von einem Befehl mit Passphrase (z. B. dem cron-Job) – deshalb
können beide Arten nebeneinander stehen.

Darunter: wo die Sicherungen liegen und dass Herunterladen und Einspielen nur auf dem Server gehen (mit dem Link zu
[Schritt für Schritt](#schritt-fuer-schritt)), die Befehle zum Wiederherstellen der neuesten Sicherung mit dem Knopf
„Befehle zum Wiederherstellen kopieren“ und ein Hinweis auf den [Rücksicherungs-Test](#ruecksicherungs-test).

Per Befehl auf dem Server (gleiches Ergebnis, gleiche Aufbewahrung):

```bash
cd /opt/cobe-news
docker compose exec -T app python -m app.cli backup
```

Die Ausgabe nennt Datei, Größe, Zeilen, Dauer und ob verschlüsselt. Exit-Code 0 heißt gesichert.

## Verschlüsselung und Schlüssel {#verschluesselung}

Cobe News speichert Geheimnisse (Webhook-URLs, SMTP- und LDAP-Passwort, Entra-Geheimnis, NVD-Schlüssel, TOTP lokaler
Konten) verschlüsselt in der Datenbank. Der **Hauptschlüssel** dafür ist `SECRET_KEY` in der
[.env](term:envfile) oder, wenn der leer ist, die Datei `data/secret.key`.

| | ohne Passphrase (`.tar`) | mit Passphrase (`.tar.enc`) |
|---|---|---|
| Datei verschlüsselt | nein | ja, die ganze Datei |
| Hauptschlüssel enthalten | nein – Geheimnisse bleiben damit verschlüsselt | ja |
| Zum Wiederherstellen nötig | Datei **und** der Hauptschlüssel dieser Installation | Datei **und** Passphrase |
| Echtheit | Signatur | Passphrase (verändert lässt sie sich nicht entschlüsseln) |

**Passphrase:** mindestens 12 Zeichen, sonst wird nichts gesichert. Verschlüsselt wird mit scrypt und AES-256-GCM in
Blöcken – eine veränderte, vertauschte oder abgeschnittene Datei fällt beim Entschlüsseln auf.

Woher die Passphrase kommt – sie wird nie angezeigt und nie geloggt:

- **Nur der cron-Job** gibt sie mit (siehe [cron](#cron)): die cron-Sicherungen sind verschlüsselt, „Jetzt sichern“
  legt eine unverschlüsselte an. So entstehen beide Arten nebeneinander.
- **Die App hat sie als Datei** (`BACKUP_PASSPHRASE_FILE`, siehe [Passphrase-Datei](#passphrase-datei)): alle
  Sicherungen sind verschlüsselt, auch „Jetzt sichern“, ohne dass die Passphrase in der `.env` oder in Portainers
  Variablen steht. Die Seite sagt dann „„Jetzt sichern“ verschlüsselt mit der Passphrase der App …“.
- **`BACKUP_PASSPHRASE` in der `.env`**: wirkt wie die Datei, steht aber im Klartext in der `.env` (bzw. bei Portainer
  für jeden sichtbar, der den Stack bearbeiten darf). Die Datei ist besser.
- Die Passphrase getrennt vom Server aufbewahren, z. B. im Passwort-Manager. Ohne sie lässt sich eine `.tar.enc` nicht
  öffnen.

**Den Hauptschlüssel getrennt aufbewahren:** `SECRET_KEY` (bzw. eine Kopie von `data/secret.key`) gehört nicht zu den
Sicherungen, sondern an einen anderen sicheren Ort. Ohne ihn lassen sich die Geheimnisse einer `.tar`-Sicherung nicht
lesen – Webhook-URLs, Passwörter, das Entra-Geheimnis und TOTP müssen dann neu eingerichtet werden.

### Passphrase für die App als Datei {#passphrase-datei}

Damit auch „Jetzt sichern“ und der Rücksicherungs-Test der App verschlüsselte Sicherungen anlegen bzw. öffnen, liest
die App die Passphrase aus einer Datei. Ein Ordner des Hosts wird dazu schreibgeschützt nach `/run/backup-secret`
eingehängt.

**1. Datei anlegen** – nicht unter `data/` (der Ordner wird mit den Sicherungen kopiert), lesbar für den Benutzer des
Containers (UID 10001):

```bash
sudo mkdir -p /etc/cobe-news-secret
sudo bash -c 'umask 077; read -rsp "Passphrase: " P; echo; printf "%s\n" "$P" > /etc/cobe-news-secret/backup-pass'
sudo chown -R 10001 /etc/cobe-news-secret
sudo chmod 700 /etc/cobe-news-secret && sudo chmod 400 /etc/cobe-news-secret/backup-pass
```

**2. Zwei Einstellungen** – lokal in der `.env`, bei Portainer unter *Environment variables*:

```
BACKUP_SECRET_DIR=/etc/cobe-news-secret
BACKUP_PASSPHRASE_FILE=/run/backup-secret/backup-pass
```

**3. Übernehmen** – lokal `docker compose up -d`, bei Portainer *Update the stack*. Die Seite zeigt danach „„Jetzt
sichern“ verschlüsselt mit der Passphrase der App (BACKUP_PASSPHRASE_FILE: /run/backup-secret/backup-pass)“.

Regeln:

- Sind `BACKUP_PASSPHRASE` und `BACKUP_PASSPHRASE_FILE` gesetzt, gilt `BACKUP_PASSPHRASE` – die Datei wird dann nicht
  gelesen (die Seite sagt es). Ein Befehl mit `--passphrase-file` geht beiden vor; ohne Passphrase-Option nimmt er
  die Datei.
- Die Datei wird bei jeder Sicherung gelesen; eine geänderte gilt sofort. Leerraum am Anfang und Ende (der
  Zeilenumbruch) zählt nicht, mindestens 12 Zeichen.
- Fehlt die Datei oder ist sie nicht lesbar, legt „Jetzt sichern“ **keine** Sicherung an – auch keine unverschlüsselte.
  Die Seite nennt den Grund (fehlt, nicht lesbar, leer, zu kurz …), die App läuft weiter.
- Der Befehl `restore` (`docker compose run … app python -m app.cli restore …`) liest die Datei ebenso – kein
  `read -rs BACKUP_PASSPHRASE` nötig.
- Ohne die beiden Einstellungen hängt Compose ein leeres eigenes Volume (`backup-secret`) ein – nichts ändert sich.
- Die Passphrase liegt damit auf dem Server, wie der Hauptschlüssel. Sie schützt die Kopien, die den Server verlassen;
  aufbewahren müsst ihr sie trotzdem getrennt (Passwort-Manager) – ohne sie lässt sich keine `.tar.enc` öffnen.

> [!NOTE]
> Während einer Sicherung oder Wiederherstellung liegen Dump und (bei Verschlüsselung) Schlüssel kurz unverschlüsselt in
> `data/.backup-work/` – neben `data/backups/`, nicht darin. Reste eines abgebrochenen Laufs räumt die nächste
> Sicherung, Wiederherstellung oder der nächste Start weg, sobald sie älter als 6 Stunden sind.

### Signatur {#signatur}

Jede Sicherung ist signiert (`manifest.sig`, [HMAC](term:hmac)-SHA256 mit einem aus dem Hauptschlüssel abgeleiteten
Schlüssel). Damit erkennt die Wiederherstellung, dass eine unverschlüsselte Datei von **dieser** Installation stammt und
danach nicht verändert wurde. Die Prüfsummen im Manifest allein beweisen das nicht – sie stehen in derselben Datei.

## Tägliche Sicherung per cron {#cron}

Beispiel: jede Nacht um 2:30 eine verschlüsselte Sicherung, danach auf ein anderes System kopieren.

**1. Passphrase erzeugen** – mindestens 12 Zeichen, im Passwort-Manager ablegen.

**2. Passphrase auf dem Server ablegen** – in einer Datei, die nur root lesen darf, ohne sie anzuzeigen und ohne
Shell-History:

```bash
sudo bash -c 'umask 077; read -rsp "Passphrase: " P; echo; printf "%s\n" "$P" > /root/.cobe-news-backup-pass'
sudo chown root:root /root/.cobe-news-backup-pass
sudo chmod 600 /root/.cobe-news-backup-pass
```

**3. cron-Datei anlegen** – `/etc/cron.d/cobe-news-backup` mit einer Zeile:

```
30 2 * * * root cd /opt/cobe-news && docker compose exec -T app python -m app.cli backup --passphrase-file - < /root/.cobe-news-backup-pass >>/var/log/cobe-news-backup.log 2>&1 && rsync -a --exclude='.*' --exclude='*.partial' data/backups/ backup-host.corp.example:/srv/cobe-news/
```

**4. Testen** – den Befehl einmal von Hand als root ausführen und `/var/log/cobe-news-backup.log` prüfen. Danach zeigt
die Seite „Gesichert“, und die Datei steht mit „Verschlüsselt · Schlüssel enthalten“ in der Liste.

Hinweise:

- Die Passphrase geht über die Standardeingabe (`--passphrase-file -`), nie als `-e BACKUP_PASSPHRASE="$(cat …)"`:
  so stünde sie in der Befehlszeile von `docker`, und die zeigt jede Prozessliste des Hosts (`ps`).
- Hat die App eine [Passphrase-Datei](#passphrase-datei), genügt `… app python -m app.cli backup` ohne Option.
- Ohne Passphrase: `--passphrase-file - < …` weglassen – dann den Hauptschlüssel unbedingt getrennt aufbewahren.
- `rsync` braucht einen SSH-Zugang von root auf das Zielsystem (`backup-host.corp.example` ist ein Beispiel).
  Kopiert wird nur, wenn die Sicherung geklappt hat (`&&`). `--exclude` hält halbfertige Dateien vom Kopieren fern.
- Die Passphrase nie ins Log, in die `.env`, in Tickets oder Chats schreiben.
- Die Aufbewahrung in der App gilt nur für den Server; wie lange das Zielsystem die Kopien behält, regelt ihr dort.

## Wiederherstellung {#wiederherstellung}

Eine Wiederherstellung **ersetzt die ganze Datenbank** durch den Stand der Sicherung. Sie geht nur auf dem Server, per
Befehl, mit angehaltener App – nie aus dem Browser.

**1. App anhalten** – im Installationsordner; die Datenbank läuft weiter:

```bash
cd /opt/cobe-news
docker compose stop app
```

**2. Sicherung einspielen** – eine unverschlüsselte:

```bash
docker compose run --rm --no-deps app python -m app.cli restore /data/backups/cobe-news-20261030-023000.tar
```

Eine verschlüsselte: erst die Passphrase einlesen (sie erscheint weder auf dem Bildschirm noch in der History), dann
einspielen:

```bash
read -rs BACKUP_PASSPHRASE && export BACKUP_PASSPHRASE
docker compose run --rm --no-deps -e BACKUP_PASSPHRASE app python -m app.cli restore /data/backups/cobe-news-20261030-023000.tar.enc
unset BACKUP_PASSPHRASE
```

Hat die App eine [Passphrase-Datei](#passphrase-datei), genügt für beide der erste Befehl – sie liest die Datei selbst.

**3. Bestätigen** – der Befehl zeigt, was er einspielt (Datum, Version, Schema, Zeilen) und ob die Datei echt ist
(`Genuine: encrypted with the passphrase.` bzw. `Genuine: signed with this installation's key.`). Zum Bestätigen
`RESTORE` tippen. Vorher sichert er den aktuellen Stand (`Current state saved first: …-pre-restore…`) – das ist der
Weg zurück, verschlüsselt mit derselben Passphrase wie die Wiederherstellung. Am Ende steht
`Restored: … rows, schema now …`.

**4. App starten:**

```bash
docker compose start app
```

**5. Prüfen** – anmelden, *Version & Changelog* ansehen, unter *Einstellungen → Sicherung & Export* steht die
Pre-Restore-Sicherung als letzte Sicherung, einen Kanal testen.

Wer sich erst nach dem Zeitpunkt der Sicherung angemeldet hat, meldet sich neu an; Anmeldungen, die es zur Zeit der
Sicherung gab, gelten wieder. Eine Sicherung einer älteren Version wird auf den Stand dieser Version gebracht; die einer
**neueren** Version wird abgelehnt.

Die Befehle für die neueste Sicherung stehen auch in der App: „Befehle zum Wiederherstellen kopieren“.

### Was geprüft wird {#wiederherstellung-pruefungen}

Bevor etwas geändert wird:

- **Echtheit:** Passphrase (verschlüsselt) oder Signatur mit dem Schlüssel dieser Installation (unverschlüsselt). Eine
  Signatur, die nicht passt, bricht immer ab.
- **Inhalt:** nur die erwarteten Dateien, Prüfsummen, Schema-Stand, Fingerabdruck des Schlüssels. Der Dump darf nur
  enthalten, was Cobe News selbst anlegt – sonst Abbruch.
- **Keine laufende App:** Ist noch etwas mit der Datenbank verbunden, bricht der Befehl ab („stop the app first“).

Eingespielt wird in **einer** Transaktion mit der eigenen Datenbankrolle der App (kein Superuser). Danach werden die
Zeilen je Tabelle und das Schema mit der Sicherung verglichen. Weicht etwas ab oder bricht etwas ab, wird alles
zurückgerollt – die Datenbank bleibt, wie sie war.

### Anderer Schlüssel, alte Sicherung {#wiederherstellung-optionen}

| Option | Wirkung |
|---|---|
| `--yes` | ohne Rückfrage „RESTORE“ – nötig, wenn kein Terminal da ist (Skript) |
| `--use-backup-key` | übernimmt den Hauptschlüssel aus einer **verschlüsselten** Sicherung nach `data/secret.key`; der alte bleibt daneben liegen |
| `--ignore-key` | stellt trotz anderem Schlüssel her – gespeicherte Geheimnisse sind danach unlesbar und neu einzugeben |
| `--allow-unsigned` | stellt eine unverschlüsselte Sicherung **ohne** Signatur (vor Version 0.1.22) oder mit dem Schlüssel einer anderen Installation her |
| `--passphrase-file DATEI` | Passphrase aus einer Datei (Pfad im Container) statt aus `BACKUP_PASSPHRASE` |

Wurde die Sicherung mit einem anderen Hauptschlüssel erstellt, bricht der Befehl mit Erklärung ab. Dann entweder
`--use-backup-key` (nur bei `.tar.enc`) oder `--ignore-key` wählen, nicht beides. Steht `SECRET_KEY` in der `.env`,
weigert sich `--use-backup-key`: `SECRET_KEY` aus der `.env` entfernen (oder dort den Schlüssel der Sicherung
eintragen) und den Befehl wiederholen.

> [!WARNING]
> `--allow-unsigned` nur für eine Datei, von der ihr sicher wisst, dass sie eure eigene ist. Eine präparierte Sicherung
> kann beliebige Daten und Admin-Konten mitbringen. Der Befehl warnt dann ausdrücklich (`WARNING: … not checked`).

## Rücksicherungs-Test {#ruecksicherungs-test}

Eine Sicherung ist erst dann etwas wert, wenn sie sich auch zurückspielen lässt. Der Rücksicherungs-Test prüft genau
das – regelmäßig und von selbst: Er spielt die **neueste** Sicherung wirklich ein, aber in eine eigene
**Wegwerf-Datenbank** (`cobe_news_restore_test`), **nie** in die echte. Danach leert er sie wieder.

Die Seite dazu: *Einstellungen → Sicherung & Export*, Reiter **„Rücksicherungs-Test“**. Dort stehen:

- ein Schalter (ab Werk an),
- **„Wer startet den Test“**: die App nach Zeitplan oder „Der Host (Cron-Skript)“ (siehe
  [Per Host-Cron](#ruecksicherungs-test-host)),
- wie oft (alle 1, 7, 14 oder 30 Tage, Standard 7) und ab welcher Stunde (UTC, Standard 03:00),
- der letzte Test (Zeit, Datei, Dauer, Tabellen und Zeilen – oder der Fehler mit Code), der nächste geplante Test und
  ein Hinweis, wenn der letzte Test mehr als einen Tag überfällig ist,
- **„Jetzt testen“** startet einen Test sofort.

Die App startet ihren Test innerhalb von 3 Stunden ab der eingestellten Stunde – so läuft er auch nach einem Neustart
um 03:10 noch. Er läuft mit niedriger CPU-Priorität, immer nur einer zur Zeit, nie während einer Sicherung, und bricht
nach **1 Stunde** ab. Das Ergebnis steht auf der Seite und in den [Metriken](/docs/api#metriken). Eine Nachricht über
die Kanäle gibt es nicht – dafür einen [Alarm in Prometheus](/docs/api#alarme) anlegen.

**Warum eine eigene Rolle:** Die Rolle der App (`cobe_news_app`) bekommt für den Test **kein** zusätzliches Recht. Der
Test arbeitet als eigene Rolle `cobe_news_restore`: kein Superuser, darf keine Datenbanken und keine Rollen anlegen,
besitzt nur die Wegwerf-Datenbank und darf sich mit der Datenbank der App nicht einmal verbinden. Vor jedem Test fragt
die App den Datenbank-Server, ob das so ist – sonst bricht sie ab (Code `unsafe`). Selbst ein Fehler im Programm kann
also nie in die echten Daten zurückspielen: Der Datenbank-Server ließe es nicht zu.

Was das kostet:

- **Platz:** Während des Tests liegt eine zweite Kopie der Daten in der Datenbank (Platte und WAL), dazu kurz der
  entpackte Dump in `data/.backup-work/`. Genug freien Platz einplanen – mindestens so viel, wie die Datenbank groß ist.
- **Daten:** Die Kopie enthält dasselbe wie die Sicherung, auch personenbezogene Daten (gespeicherte Geheimnisse
  bleiben verschlüsselt). Sie bleibt nur bis zum Ende des Tests – auch nach einem Fehler wird die Wegwerf-Datenbank
  geleert. Wurde ein Test hart abgebrochen (z. B. durch einen Neustart), leert der nächste sie zuerst.

### Einrichten {#ruecksicherungs-test-einrichten}

Bei einer **neuen** Installation ist alles schon da: `scripts/setup-env.sh` erzeugt das Passwort, der Datenbank-Container legt
Rolle und Datenbank an. Eine **bestehende** Installation richtet ihr einmal so ein:

**1. Code aktualisieren** – wie bei jedem [Update](/docs/betrieb#update-schritte) (`git pull`).

**2. Passwort ergänzen** – das trägt `POSTGRES_RESTORE_PASSWORD` in die `.env` ein; alles andere darin bleibt, wie es
ist:

```bash
cd /opt/cobe-news
scripts/setup-env.sh
```

**3. Neu starten** – der Datenbank-Container legt die Rolle und die Wegwerf-Datenbank bei jedem Start an bzw. prüft sie.
Im Log steht danach `cobe_news_restore ready`:

```bash
docker compose up -d --build
docker compose logs db | grep db-init
```

**4. Ausprobieren** – *Einstellungen → Sicherung & Export → Rücksicherungs-Test*, „Jetzt testen“. Gibt es noch keine
Sicherung, vorher „Jetzt sichern“.

> [!WARNING]
> Ist die neueste Sicherung mit einer Passphrase verschlüsselt, die die App **nicht** kennt (empfohlen:
> `BACKUP_PASSPHRASE` nur im cron-Job, siehe [cron](#cron)), schlägt der Test der App mit dem Code `passphrase` fehl.
> Dann den Test vom Host starten lassen: [Per Host-Cron](#ruecksicherungs-test-host) – oder der App die Passphrase als
> Datei geben: [Passphrase-Datei](#passphrase-datei).

`POSTGRES_RESTORE_PASSWORD` muss mindestens 16 Zeichen lang sein. Ist es kürzer, bricht die Einrichtung der Datenbank ab
und die App startet nicht – `setup-env.sh` erzeugt 40 Zeichen.

**Nicht gewünscht?** In der `.env` `POSTGRES_RESTORE_PASSWORD=` leer lassen (die Zeile behalten, sonst ergänzt
`setup-env.sh` sie wieder) und `docker compose up -d` ausführen. Dann legt die Datenbank nichts an, und der Reiter sagt
„nicht eingerichtet“. Eine schon angelegte Rolle und Datenbank bleiben dabei bestehen. Wer sie entfernen will:

```bash
cd /opt/cobe-news
docker compose exec db psql -U cobe_news cobe_news -c "DROP DATABASE cobe_news_restore_test" -c "DROP ROLE cobe_news_restore"
```

### Per Host-Cron {#ruecksicherungs-test-host}

Für Sicherungen, deren Passphrase nur der cron-Job kennt:

**1. Umstellen** – unter *Rücksicherungs-Test* bei „Wer startet den Test“ **„Der Host (Cron-Skript)“** wählen und
speichern. Die App startet dann selbst keinen Test mehr.

**2. Passphrase-Datei** – sie liegt schon in einer Datei, die nur root lesen darf (siehe [cron](#cron), Schritt 2).

**3. cron-Datei anlegen** – z. B. `/etc/cron.d/cobe-news-restore-test`, hier jeden Sonntag um 04:30, also nach der
täglichen Sicherung:

```
30 4 * * 0 root /opt/cobe-news/scripts/restore-test.sh --passphrase-file /root/.cobe-news-backup-pass >>/var/log/cobe-news-restore-test.log 2>&1
```

**4. Testen** – den Befehl einmal von Hand als root ausführen und `/var/log/cobe-news-restore-test.log` prüfen.

Das Skript liest die Datei auf dem Host und gibt die Passphrase über die Standardeingabe an den Container. Sie steht nie
in einer Befehlszeile, im Container oder in einem Log. Ist die Datei für andere lesbar, warnt das Skript (`chmod 600`).
Exit-Code 0 heißt bestanden, 1 fehlgeschlagen, 2 falsch aufgerufen. Das Ergebnis erscheint wie bei der App auf der
Seite und in den Metriken.

Ohne Passphrase (unverschlüsselte Sicherung oder `BACKUP_PASSPHRASE` in der `.env`): `scripts/restore-test.sh` ohne
Option. Darunter liegt dieser Befehl:

```bash
cd /opt/cobe-news
docker compose exec -T app python -m app.cli restore-test
docker compose exec -T app python -m app.cli restore-test --passphrase-file - < /root/.cobe-news-backup-pass
```

> [!NOTE]
> Der Test von der Kommandozeile prüft nicht, ob gerade eine Sicherung läuft. Die cron-Zeile deshalb nicht in die
> Minuten der täglichen Sicherung legen.

### Was geprüft wird {#ruecksicherungs-test-pruefungen}

Dieselben Prüfungen wie bei einer echten [Wiederherstellung](#wiederherstellung-pruefungen):

1. **Die Datei:** entschlüsselt mit der Passphrase (verschlüsselt) bzw. die Signatur mit dem Schlüssel dieser
   Installation (unverschlüsselt); nur die erwarteten Dateien; Prüfsummen; das Inhaltsverzeichnis des Dumps; ein
   Schema-Stand, den diese Version kennt.
2. **Das Einspielen:** `pg_restore` → `psql` in die Wegwerf-Datenbank, in **einer** Transaktion, ohne Fehler.
3. **Der Inhalt:** die Zeilen je Tabelle **genau** wie im Manifest der Sicherung, und das Schema **genau** wie das
   einer frisch migrierten Datenbank desselben Stands.
4. **Der Stand:** danach ist der Schema-Stand (`alembic_version`) der wiederhergestellten Datenbank der der Sicherung.

Zum Schluss wird die Wegwerf-Datenbank geleert (Schema gelöscht und neu angelegt).

Schlägt ein Test fehl, nennt die Seite einen Code:

| Code | Bedeutung | Was tun |
|---|---|---|
| `not_configured` | keine Wegwerf-Datenbank eingerichtet | [Einrichten](#ruecksicherungs-test-einrichten) |
| `unsafe` | das Ziel ist die Datenbank oder die Rolle der App, oder die Rolle des Tests hat zu viele Rechte (Superuser, darf Datenbanken oder Rollen anlegen, darf sich mit der Datenbank der App verbinden, ist Mitglied der Rolle der App, besitzt die Wegwerf-Datenbank nicht) | `docker compose up -d` (die Datenbank setzt die Rechte bei jedem Start neu), `docker compose logs db` lesen; nie Rechte von Hand vergeben |
| `busy` | ein anderer Test läuft gerade (wird nicht als Ergebnis gespeichert) | warten |
| `no_backup` | es gibt keine Sicherung | „Jetzt sichern“ |
| `passphrase` | die neueste Sicherung ist verschlüsselt, die App kennt die Passphrase nicht (oder ihre Passphrase-Datei ist nicht lesbar – die Meldung nennt den Grund) | [Per Host-Cron](#ruecksicherungs-test-host) oder [Passphrase-Datei](#passphrase-datei) |
| `verify` | die Datei hat eine Prüfung nicht bestanden: falsche Passphrase, Signatur eines anderen Schlüssels oder keine, fehlende oder fremde Dateien, Prüfsumme, Inhaltsverzeichnis, Schema einer neueren Version | die Meldung lesen – so ließe sich die Sicherung auch nicht wiederherstellen |
| `connect` | die Wegwerf-Datenbank ist nicht erreichbar (falsches Passwort, Rolle oder Datenbank fehlt) | `docker compose up -d`, `docker compose logs db` |
| `restore` | `pg_restore` oder `psql` haben einen Fehler gemeldet | die Meldung und `docker compose logs app` lesen |
| `rows` | die Zeilen je Tabelle weichen vom Manifest ab | neu sichern und erneut testen |
| `schema` | das Schema weicht von dem einer frisch migrierten Datenbank ab | die Meldung lesen; die Sicherung enthält etwas, das Cobe News nicht selbst anlegt |
| `revision` | nach dem Einspielen ein anderer Schema-Stand als in der Sicherung | die Meldung lesen, erneut testen |
| `timeout` | nicht fertig innerhalb von 1 Stunde | Platz und Last des Servers prüfen; den Test in ruhigere Stunden legen |
| `failed` | ein unerwarteter Fehler | `docker compose logs app` lesen |

## Neuer Server {#neuer-server}

Für den Katastrophenfall braucht ihr nur:

- die Sicherungsdatei, und
- bei `.tar.enc` die Passphrase, bei `.tar` den alten `SECRET_KEY` bzw. die alte Datei `data/secret.key`.

**1. Installieren** – Cobe News auf dem neuen Server nach `/opt/cobe-news` holen und `scripts/setup-env.sh` ausführen
(siehe [Start und Stopp](/docs/betrieb#start-stopp)). Einstellungen wie `BASE_URL` aus der alten `.env` übernehmen.

- Bei `.tar`: den alten `SECRET_KEY` in die `.env` eintragen – oder die alte `secret.key` nach `data/` legen.
- Bei `.tar.enc`: **kein** `SECRET_KEY` in die `.env` – der Schlüssel kommt aus der Sicherung.

**2. Sicherung ablegen** – nach `data/backups/` kopieren und dem Benutzer des Containers (UID 10001) geben:

```bash
cd /opt/cobe-news
sudo mkdir -p data/backups
sudo cp /pfad/zur/cobe-news-20261030-023000.tar.enc data/backups/
sudo chown -R 10001 data
```

**3. Datenbank starten** – Image bauen und nur die (leere) Datenbank mit der Rolle der App anlegen:

```bash
docker compose build && docker compose up -d --wait db
```

**4. Einspielen** – mit `--use-backup-key`, damit der Schlüssel aus der Sicherung übernommen wird:

```bash
read -rs BACKUP_PASSPHRASE && export BACKUP_PASSPHRASE
docker compose run --rm --no-deps -e BACKUP_PASSPHRASE app python -m app.cli restore /data/backups/cobe-news-20261030-023000.tar.enc --use-backup-key
unset BACKUP_PASSPHRASE
```

Bei einer `.tar` ohne `-e BACKUP_PASSPHRASE` und ohne `--use-backup-key`. In eine leere Datenbank wird ohne
Pre-Restore-Sicherung eingespielt; `RESTORE` wird trotzdem abgefragt.

**5. Starten und prüfen** – wie bei der [Wiederherstellung](#wiederherstellung):

```bash
docker compose up -d
```

Ändert sich mit dem Umzug die Adresse (`BASE_URL`), ändert sich auch die Redirect-URI für Entra ID – siehe
[Adresse](/docs/betrieb#adresse).

## Export {#export}

Der Export enthält die Einstellungen zum Nachlesen oder Übertragen in andere Werkzeuge – JSON für Skripte und Tools,
CSV für Excel. Er ist **keine Sicherung** und lässt sich **nicht wieder einlesen**: Cobe News hat keinen Import, und
der Export enthält weder Meldungen noch Geheimnisse. Gesichert wird mit einer [Sicherung](#schritt-fuer-schritt).

In *Einstellungen → Sicherung & Export*, Abschnitt „Export“:

- **„JSON herunterladen“** – eine JSON-Datei,
- **„CSV (ZIP) herunterladen“** – eine CSV-Datei je Bereich in einem ZIP (UTF-8, öffnet sich richtig in Excel).

Der Export enthält Namen und E-Mail-Adressen aller Benutzer und verlangt deshalb die
[erneute Bestätigung](/docs/anmeldung#erneut-bestaetigen).

| Bereich | Inhalt |
|---|---|
| Regeln | Name, an/aus, Arten, Schweregrade, Quellen, Sprache, Kanäle |
| Kanäle | Name, Typ, Einstellungen ohne Geheimnis, **welche** Geheimnisse gesetzt sind, letzter Fehler |
| Quellen | Name, Adresse, eingebaut oder eigen, an/aus, letzter Abruf, Fehler |
| Gefolgte Produkte | Produkt, Notiz, Tags, CPE, Versionen mit Bezeichnung und Anzahl |
| Benutzer | Name, Anzeigename, E-Mail, Rolle, Herkunft, aktiv, ob TOTP eingerichtet ist, letzte Anmeldung |

Nicht enthalten: Webhook-URLs, Tokens, Passwörter, Passwort-Hashes, TOTP-Geheimnisse.

Per Befehl auf dem Server (ohne erneute Bestätigung – wer auf den Server kommt, darf das ohnehin):

```bash
cd /opt/cobe-news
docker compose exec -T app python -m app.cli export --format csv --out /data/export.zip
docker compose exec -T app python -m app.cli export > export.json
```

Ohne `--out` geht JSON auf die Standardausgabe. Die Datei enthält personenbezogene Daten – nach Gebrauch löschen.
