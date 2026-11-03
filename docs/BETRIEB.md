# Cobe News – Betrieb

Betriebs-Referenz (Deutsch): Installation, Konfiguration, Anmeldung, HTTPS, Quellen, Vendor News, Benachrichtigungen,
PostgreSQL, Sicherung und Entwicklung. Überblick und Schnellstart: [README](../README.md).

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
| `cobe-news-proxy` | nginx 1.30: TLS, leitet an die App weiter | **8095** (https, Host) |
| `cobe-news-app` | FastAPI + Web-UI + Hintergrundjobs (Feeds, Benachrichtigungen, Zertifikat, Verzeichnisabgleich) | `127.0.0.1:8096` (http, nur Health/Notfall) |
| `cobe-news-db` | PostgreSQL 18 – alle Daten (siehe [PostgreSQL](#postgresql)) | keiner (internes Netz, nur die App) |

### Veröffentlichtes Image statt lokalem Build

Standard ist der lokale Build (`docker compose up -d --build`, Image `cobe-news:latest`) – daran ändert sich nichts.
Wer stattdessen das veröffentlichte, signierte Image einer Version betreiben will
(`ghcr.io/g0urmetd/cobe-news:<version>`, gebaut von der Release-Pipeline, siehe [Release](#release)), schaltet die
Datei `docker-compose.image.yml` zu – in `.env`:

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.image.yml   # mit http-Umleitung: …:docker-compose.http.yml:docker-compose.image.yml
COBE_NEWS_IMAGE=ghcr.io/g0urmetd/cobe-news:0.1.46          # eine Version, nicht latest (oder …:0.1.46@sha256:<digest>)
```

Die Datei ersetzt beim Dienst `app` nur das Image (`image: ${COBE_NEWS_IMAGE}`, der `build`-Teil fällt weg); alles
andere – Datenbank, Proxy, Volumes, `.env` – bleibt, wie es ist. Ohne `COBE_NEWS_IMAGE` bricht `docker compose` mit
einem Hinweis ab, statt still etwas anderes zu starten. Vor dem Start die Signatur prüfen (cosign ≥ 2, keyless – die
Identität ist der Release-Workflow dieses Repositorys):

```bash
cosign verify ghcr.io/g0urmetd/cobe-news:0.1.46 \
  --certificate-identity-regexp '^https://github\.com/G0urmetD/Cobe-News/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker compose pull app          # holt das Image (pull_policy: missing – ein vorhandenes wird nicht neu geholt)
docker compose up -d             # ohne --build
docker compose config app | grep image:   # zeigt, welches Image Compose nimmt
```

`cosign verify` gibt den Digest aus, den die Signatur abdeckt; wer ihn in `COBE_NEWS_IMAGE` übernimmt
(`…:0.1.46@sha256:<digest>`), startet genau das geprüfte Image, auch wenn der Tag später anders zeigen sollte. Ein Update:
`COBE_NEWS_IMAGE` auf die neue Version setzen, Signatur prüfen, `docker compose pull app && docker compose up -d` (die
Migrationen laufen beim Start wie beim lokalen Build). Zurück zum lokalen Build: die beiden Zeilen aus `.env` nehmen und
`docker compose up -d --build`.

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
ein neu angelegtes Konto gleichen Namens (Entra: neue Objekt-ID) kann sich dann anmelden.

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

**3. Eigener Reverse Proxy davor (`TLS_MODE=external`).** Wenn auf dem Host schon ein nginx/Traefik mit Zertifikat
läuft: `PROXY_ENABLED=0` (der mitgelieferte nginx startet nicht), `TLS_MODE=external`, `BASE_URL=https://<FQDN>`,
und in `TRUSTED_PROXIES` die Adresse, von der die Anfragen des eigenen Proxys bei der App ankommen. Die App hängt im
Docker-Netz `edge` (`172.31.250.0/24`), nicht im Standard-Netz von Docker: Ein Proxy auf dem Host, der den
veröffentlichten App-Port erreicht, kommt vom Gateway dieses Netzes, also `TRUSTED_PROXIES=172.31.250.1/32` (nicht
`172.17.0.1` – das ist das Standard-Netz, in dem die App nicht hängt; im Zweifel zeigt `docker compose logs app` die
Adresse in den Zugriffszeilen). Das Gateway nur eintragen, wenn der App-Port ausschließlich vom Proxy erreichbar ist
(Standard `127.0.0.1:8096`) – und **nie**, solange der mitgelieferte nginx läuft (`PROXY_ENABLED=1`). Ein
Proxy-Container im Netz `edge` (von außen `cobe-news_edge`, Ziel `http://cobe-news-app:8000`) bekommt dort eine feste
Adresse unterhalb von `.128`, also außerhalb von `EDGE_RANGE` (z. B. `172.31.250.20`), und genau diese steht in
`TRUSTED_PROXIES`. HSTS sendet die App auch in diesem Modus – auf Anfragen, die über HTTPS kamen, also von einer
Adresse aus `TRUSTED_PROXIES` mit `X-Forwarded-Proto: https`; der eigene Proxy darf den Header zusätzlich selbst setzen.
Beispiel:

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
andere wird übergangen und geloggt, es kommt nichts anderes in die Konfiguration; IPv6 in eckigen Klammern). Für jeden
anderen `Host` antworten die `default_server`-Blöcke (80 und 443) mit `444` (Verbindung zu). Wer die Seite über eine IP
oder einen weiteren Namen öffnet, trägt ihn in `TLS_NAMES` ein. Welche Namen gelten:
`docker compose logs proxy | grep "answering to"`. Mit `TLS_MODE=external` (eigener Proxy) gilt das für den eigenen
Proxy nicht – dort selbst ein `server_name` und einen Default-Server setzen.

**Größe der Anfragen:** nginx nimmt höchstens 1 MB (`client_max_body_size 1m`), die App selbst ebenso
(`MAX_BODY_BYTES`, Standard 1 MiB, 16 KiB bis 64 MiB; reine ASGI-Middleware `app/bodylimit.py`): `Content-Length`
darüber → sofort `413 body_too_large`; ohne `Content-Length` (chunked) wird mitgezählt und beim Überschreiten
abgebrochen – mit denselben Sicherheits-Headern wie jede Antwort. Kein Endpunkt braucht mehr (es gibt keinen Upload:
Sicherungen entstehen und werden eingespielt auf dem Server).

Der mitgelieferte nginx (`nginx:1.30-alpine`) läuft schreibgeschützt mit `tmpfs`, ohne Capabilities außer den für
Zertifikat und Port nötigen, TLS 1.2/1.3 mit Forward Secrecy, HTTP/2; ein vom Client mitgeschicktes `X-Forwarded-For`
ersetzt er. Er hat im Netz `edge` die feste Adresse `172.31.250.10` (Subnetz `172.31.250.0/24`); nur von dort (und aus `TRUSTED_PROXIES`) übernimmt die App die Client-Adresse.
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
verloren – nginx sieht jede Anfrage vom Docker-Gateway (z. B. `172.31.250.1`). Was man dann sieht: im Access-Log der App
und unter *Benutzer & Rollen* („letzte Anmeldung“) steht für alle dieselbe Adresse. Was Cobe News daraus macht: das
Gateway gilt als **geteilte Adresse** und wird nie geblockt (sonst sperrte ein Spraying-Versuch alle aus), Fehlversuche
darüber werden gebremst, die Konto-Sperren wirken weiter; das Limit für Entra-Anmeldestarts gilt dort für alle zusammen
(300 statt 30 je 10 Minuten). Was zu tun ist: für den Echtbetrieb einen Linux-Docker-Host nehmen (dort sieht nginx die
echten Adressen); ein Gateway, das Cobe News nicht selbst erkennt (anderer Weg als die Standard-Route des Containers),
in `SHARED_ADDRESSES` eintragen. **Nicht** das Gateway in `TRUSTED_PROXIES` eintragen: dann könnte jeder, der den
App-Port erreicht, seine Adresse per `X-Forwarded-For` selbst wählen.

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
ausgeschaltet hat, bleibt so. Ändert sich der Standard einer eingebauten Quelle (CISA Alerts ab 0.1.7: aus), folgt ihm
nur eine Quelle, die nie ein Admin geschaltet hat; seit 0.1.7 merkt sich Cobe News jedes Schalten.

| Gruppe | Eingeschaltet (Standard) | Wählbar |
|---|---|---|
| Behörden & CERTs | BSI Cyber-Sicherheitswarnungen, CERT-EU Security Advisories, CERT.at Warnungen | CISA Alerts, BSI CERT-Bund (WID), BSI Presse, NCSC UK, Canadian Centre for Cyber Security, CERT-FR Alertes (FR) |
| Schwachstellen-Kataloge | CISA KEV (JSON) | ENISA EUVD – ausgenutzte Schwachstellen (JSON), Microsoft Patchday (MSRC, JSON) |
| Hersteller-Hinweise (PSIRT) | CERT@VDE (OT-Hersteller), Veeam Security | Fortinet PSIRT, Palo Alto Networks PSIRT, Cisco PSIRT, Ivanti, Siemens ProductCERT, Rockwell Automation, Oracle Security Alerts |
| Research | Microsoft Threat Intelligence, Cisco Talos | Unit 42, Google Threat Intelligence (Mandiant), Kaspersky Securelist, ESET WeLiveSecurity, Check Point Research, Zero Day Initiative, SANS ISC, watchTowr Labs, Huntress |
| Presse | heise online, heise Security, The Hacker News, golem.de Security, BleepingComputer, SecurityWeek ICS/OT | SecurityWeek, Krebs on Security, Dark Reading, The Record, Borns IT-Blog, Security-Insider, t3n Security, Risky Bulletin |

- **CISA KEV und ENISA EUVD** sind JSON-Kataloge aktiv ausgenutzter Schwachstellen (am Inhalt erkannt, nicht am
  Content-Type): jeder Eintrag eine Meldung („CVE · Hersteller Produkt: Name“, Link zur NVD bzw. zum EUVD-Eintrag),
  Schwere **hoch**, **kritisch** bei bekannter Ransomware-Nutzung (KEV) bzw. ab CVSS 9 (EUVD). Je Abruf die neuesten 200
  Einträge, ältere als die Aufbewahrung nicht. Eigene Quellen dürfen auch ein JSON-Katalog in diesem Format sein.
- **Microsoft Patchday (MSRC)** liest den CVRF-Index (`api.msrc.microsoft.com/cvrf/v3.0/updates`): je Release eine
  Meldung („Microsoft: October 2026 Security Updates“, Link zu den Release Notes im Update Guide), Schwere **hoch** –
  der ruhige Weg, Microsoft zu folgen (der Update-Guide-Feed hat je CVE einen Eintrag, Hunderte im Monat).
- **CISA Alerts** ist ab 0.1.7 aus: `www.cisa.gov` lehnt automatische Abrufe aus vielen Netzen ab (403, Bot-Schutz).
  Cobe News umgeht das nicht (kein anderer User-Agent, keine Browser-Header) und zeigt bei 403 „Die Quelle lehnt
  automatische Abrufe ab“. Wer die Quelle einschaltet und sie erreicht, behält sie.
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
  `feeds.feedburner.com`, `rss.golem.de`, `www.bleepingcomputer.com`, `www.cisa.gov` (KEV; Alerts wählbar),
  `www.bsi.bund.de`, `cert.europa.eu`, `www.microsoft.com`, `blog.talosintelligence.com`, `www.cert.at`, `certvde.com`,
  `www.securityweek.com`, `www.veeam.com`; wählbar `wid.cert-bund.de`, `www.ncsc.gov.uk`,
  `euvdservices.enisa.europa.eu`, `filestore.fortinet.com`, `security.paloaltonetworks.com`, `sec.cloudapps.cisco.com`,
  `www.ivanti.com`, `cert-portal.siemens.com`, `unit42.paloaltonetworks.com`, `cloudblog.withgoogle.com`,
  `securelist.com`, `research.checkpoint.com`, `www.zerodayinitiative.com`, `isc.sans.edu`, `www.securityweek.com`,
  `krebsonsecurity.com`, `www.darkreading.com`, `therecord.media`, `www.borncity.com`, `www.security-insider.de`,
  `t3n.de`, `www.cyber.gc.ca`, `cert.cyber.gouv.fr`, `labs.watchtowr.com`, `www.huntress.com`,
  `www.rockwellautomation.com`, `www.oracle.com`, `news.risky.biz`, `api.msrc.microsoft.com`; dazu die Startseiten für
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
ohne eigenes Datum bleiben, solange ihr Feed sie noch listet. Benachrichtigungsregeln schicken keinen Rückstand
(Meldungen, die beim Abruf schon älter als ein Tag waren, etwa beim ersten Abruf einer neu eingeschalteten Quelle).
Verbindungsfehler und Timeouts pausieren eine Quelle höchstens eine Stunde (oder ein Abrufintervall, wenn es länger
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
| **langsam** (blau – ein Hinweis, nichts zu tun) | im Mittel der letzten 7 Tage über 5 s je Anfrage (mind. 3 Anfragen), mind. 3 Zeitüberschreitungen und mind. ein Viertel der Abrufe, oder ein vorübergehender Fehler, der gleich wiederholt wird |
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
`checkpoint`, `horizon_yymm`, `leading_zeros` – Exchange `15.02.1748.024` → `15.2.1748.24`), `lines_only` (`lts`: nur
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
endoflife.date-Produkt in diese Kategorie (erlaubt dann nur `cpes`, `scheme`, `hint`, `osv`, `aliases`, `replaces` und
die Versionsregeln `pattern`, `pattern_hint`, `normalize`, `belongs`, `cpe_editions`, `lines_only`). Ein Produkt ohne CPE in der NVD
bekommt `cpes: []` und `hint: nocpe`.

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
  (`notify_rules.topics`, eines genügt, leer = jede Meldung), Sprache und
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
  Meldung, bei Vendor News der Zeitpunkt); was schon vorher passte und noch offen ist, kommt weiterhin.
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

Zurücksetzen = `docker compose down -v` (löscht auch die Datenbank!), `data/secret.key` löschen, neu starten (neues
Setup-Token im Log). Liegt dann noch eine `data/news.db` mit Daten da, wird sie beim Start wieder umgezogen – vorher
wegräumen oder `SQLITE_IMPORT=0` setzen.

## PostgreSQL

- Ein eigener Container `cobe-news-db` (`postgres:18-alpine`), nur im internen Netz `db` mit der App – kein Port nach
  außen, keine Verbindung ins Internet. Daten im Volume `cobe-news_db18`, eingehängt auf `/var/lib/postgresql` (ab
  PostgreSQL 18 liegt das Datenverzeichnis darunter in `18/docker`, nicht mehr in `/var/lib/postgresql/data`).
- Datenbank `cobe_news`, zwei Rollen (siehe [Rollen](#rollen)): `cobe_news` ist der Superuser des Containers (Passwort
  `POSTGRES_PASSWORD`), die App arbeitet als **`cobe_news_app`** ohne Superuser-Rechte (Passwort `POSTGRES_APP_PASSWORD`).
  Dazu die Wegwerf-Datenbank `cobe_news_restore_test` mit ihrer eigenen Rolle `cobe_news_restore` (Passwort
  `POSTGRES_RESTORE_PASSWORD`, siehe [Rücksicherungs-Test](#rücksicherungs-test)).
  Alle Passwörter stehen in der `.env` (von `scripts/setup-env.sh` erzeugt, nie im Repository). `POSTGRES_PASSWORD` **nicht
  ändern**: das Volume wurde damit angelegt – ein anderes in der `.env` sperrt `db-init` aus (dann `ALTER USER cobe_news
  PASSWORD …` im Container oder das alte zurück). `POSTGRES_APP_PASSWORD` darf sich ändern: `db-init` setzt es bei jedem Start.
- Sortierung byteweise (`--locale-provider=builtin --locale=C.UTF-8`) – wie zuvor SQLite, unabhängig von der
  C-Bibliothek des Images (kein Neuaufbau der Indizes nach einem Image-Update).
- Das Schema kommt aus Alembic-Migrationen (`backend/app/migrations`); die App bringt es bei jedem Start auf den Stand
  ihrer Version (`python -m app.cli migrate` geht auch von Hand). Jede Verbindung hat ein Statement-Timeout (30 s) und
  ein Timeout für vergessene offene Transaktionen (5 min); die App hält höchstens 15 Verbindungen.
- Speichergrenze des Containers: `DB_MEM` (Standard 512m). Ein Blick hinein:
  `docker compose exec db psql -U cobe_news cobe_news`.

### Rollen

Bis 0.1.21 arbeitete die App als Superuser `cobe_news` – damit hätte jede eingeschleuste SQL-Anweisung (etwa aus einer
präparierten Sicherung) auch Programme im Datenbank-Container starten können (`COPY … TO PROGRAM`). Seit 0.1.22:

- **`cobe_news_app`** – die App, die Sicherung und die Wiederherstellung. Besitzer der Datenbank und aller Tabellen
  (darf also das Schema migrieren, sichern und wiederherstellen), aber `NOSUPERUSER NOCREATEDB NOCREATEROLE`: keine
  Programme auf dem Server, keine Dateien des Servers, keine nicht vertrauenswürdigen Erweiterungen, keine anderen Rollen.
- **`cobe_news`** – der Superuser, den das PostgreSQL-Image beim ersten Start anlegt. Nur der kurze Dienst **`db-init`**
  (`deploy/postgres/db-init.sh`, `app-role.sql`) kennt sein Passwort: er läuft bei jedem `docker compose up` vor der App,
  legt `cobe_news_app` an, falls sie fehlt, setzt ihr Passwort und überträgt die Datenbank und alles, was der Superuser
  bisher angelegt hat (Tabellen mit Indizes und Sequenzen), an sie – mehrfach ausgeführt ändert er nichts.
  `docker compose ps -a` zeigt ihn danach als beendet (Exit 0); scheitert er, startet die App nicht (`docker compose logs db-init`).
- **`cobe_news_restore`** – nur der [Rücksicherungs-Test](#rücksicherungs-test) (`deploy/postgres/restore-role.sql`).
  Besitzer der Wegwerf-Datenbank `cobe_news_restore_test` und sonst von nichts: `NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS`, kein Mitglied von `cobe_news_app`, ohne `CONNECT` auf die Datenbank der App. `db-init` legt
  sie bei jedem Start an bzw. prüft sie – nur wenn `POSTGRES_RESTORE_PASSWORD` gesetzt ist (mindestens 16 Zeichen;
  leer: kein Rücksicherungs-Test). `cobe_news_app` bekommt dafür kein zusätzliches Recht.

**Umstellung einer bestehenden Installation** (einmal, beim Update auf 0.1.22):

```bash
cd cobe-news
docker compose exec -T app python -m app.cli backup   # Sicherung vorher (der Weg zurück, siehe unten)
docker tag cobe-news:latest cobe-news:before-roles     # das alte Image behalten
scripts/setup-env.sh                                   # ergänzt POSTGRES_APP_PASSWORD in der .env
docker compose up -d --build                           # db-init stellt um, dann startet die App als cobe_news_app
docker compose logs db-init                            # "… object(s) handed over to cobe_news_app", "superuser: false"
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
  neuen Server reichen dann Datei und Passphrase. Die Passphrase gehört nicht auf denselben Server – am besten nur dem
  cron-Job mitgeben (unten), nicht in die `.env`.

Täglich per cron, z. B. `/etc/cron.d/cobe-news-backup` (die Datei mit der Passphrase: `chmod 600`, root):

```
30 2 * * * root cd /opt/cobe-news && docker compose exec -T -e BACKUP_PASSPHRASE="$(cat /root/.cobe-news-backup-pass)" app python -m app.cli backup >>/var/log/cobe-news-backup.log 2>&1 && rsync -a --exclude='.*' --exclude='*.partial' data/backups/ backup-host.corp.example:/srv/cobe-news/
```

Ohne Passphrase: `-e …` weglassen. Exit-Code 0 = gesichert; die Sicherungen zusätzlich auf ein anderes System kopieren.
Während einer Sicherung oder Wiederherstellung liegen Dump und (verschlüsselt) Schlüssel kurz im Klartext in
`data/.backup-work/` – **neben** `data/backups/`, nicht darin. Was ein abgebrochener Lauf dort (oder bis 0.1.21 als
`.partial-…`/`.restore-…` in `data/backups/`) liegen ließ, räumt die nächste Sicherung, Wiederherstellung oder der
nächste Start der App weg, sobald es älter als 6 Stunden ist; `--exclude` hält Halbfertiges ohnehin vom Kopieren fern.

**Wiederherstellung** – nur auf dem Server, mit angehaltener App:

```bash
docker compose stop app
docker compose run --rm --no-deps app python -m app.cli restore /data/backups/cobe-news-<Zeit>.tar   # .tar.enc: -e BACKUP_PASSPHRASE=…
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
   bevor etwas geändert ist. Läuft noch eine App auf der Datenbank: Abbruch.
3. Bestätigung („RESTORE“ tippen oder `--yes`), dann eine Sicherung des aktuellen Stands (`…-pre-restore.tar`, der Weg
   zurück – mit derselben Passphrase wie die Wiederherstellung; sie zählt nicht zur Aufbewahrung und bleibt 30 Tage).
4. **Eine** Transaktion als `cobe_news_app` (kein Superuser): `DROP SCHEMA public`, der Dump Stück für Stück von
   `pg_restore` in `psql` (nie ganz im Speicher), dann zwei Prüfungen: die Zeilen je Tabelle wie im Manifest, und das
   Schema **genau** so, wie es die Migrationen für den Schema-Stand der Sicherung anlegen (Spalten, Vorgaben,
   Constraints, Indizes, keine Funktionen, Trigger, Regeln, Rechte, Einstellungen der Datenbank oder Rolle, anderen
   Schemas). Weicht etwas ab oder bricht etwas ab, wird alles zurückgerollt – die Datenbank bleibt, wie sie war.
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
docker compose build && docker compose up -d db-init          # nur die Datenbank (leer) und die Rolle der App
docker compose run --rm --no-deps -e BACKUP_PASSPHRASE app python -m app.cli restore /data/backups/cobe-news-<Zeit>.tar.enc --use-backup-key
docker compose up -d
```

`BACKUP_PASSPHRASE` vorher in der Shell setzen (`read -rs BACKUP_PASSPHRASE; export BACKUP_PASSPHRASE`) – sie steht dann
weder in der `.env` noch in der Shell-History. In die leere Datenbank wird ohne Rückfrage-Sicherung eingespielt.

**Export** (*Sicherung & Export*, oder `docker compose exec -T app python -m app.cli export --format csv --out
/data/export.zip`): Regeln, Kanäle, Quellen, gefolgte Produkte mit Versionen und Benutzer als JSON oder CSV (ZIP, eine
Datei je Bereich) – **ohne Geheimnisse**: bei Kanälen nur, welche gesetzt sind; bei Benutzern Name, Rolle, Herkunft,
ob TOTP eingerichtet ist, letzte Anmeldung. Zum Nachlesen und Übertragen, keine Sicherung.

## Rücksicherungs-Test

Eine Sicherung zählt erst, wenn sie sich zurückspielen lässt. Der Rücksicherungs-Test spielt die **neueste**
Sicherung regelmäßig wirklich ein – in die Wegwerf-Datenbank `cobe_news_restore_test` mit der eigenen Rolle
`cobe_news_restore` (siehe [Rollen](#rollen)), **nie** in die Datenbank der App – und leert sie danach wieder (auch nach
einem Fehler). Einstellungen und Ergebnis: *Sicherung & Export → Rücksicherungs-Test* (an/aus, wer startet – die App
oder der Host –, alle 1/7/14/30 Tage, Stunde in UTC; ab Werk an, alle 7 Tage ab 03:00 UTC, Start innerhalb von 3
Stunden), „Jetzt testen“; dazu `/metrics`. Keine Nachricht über Kanäle – dafür ein Prometheus-Alarm.

Geprüft wird wie bei einer echten Wiederherstellung: Echtheit (Passphrase bzw. Signatur), nur die erwarteten Dateien,
Prüfsummen, Inhaltsverzeichnis des Dumps, bekannter Schema-Stand; `pg_restore` → `psql` in einer Transaktion ohne
Fehler; Zeilen je Tabelle genau wie im Manifest; Schema genau wie eine frisch migrierte Datenbank desselben Stands;
danach `alembic_version` wie in der Sicherung. Niedrige CPU-Priorität (nice 19), nur einer zur Zeit, die App startet
keinen während einer Sicherung, Abbruch nach 1 Stunde. Vor jedem Test fragt die App den Server, ob die Rolle des Tests
wirklich keine Rechte auf die Datenbank der App hat – sonst Abbruch (`unsafe`). Kosten: Platz für eine zweite Kopie der
Daten (Platte und WAL) während des Tests; die Kopie enthält dieselben Daten wie die Sicherung, bis sie geleert ist.

**Einrichten in einer bestehenden Installation** (neue Installationen haben es schon):

```bash
git pull                          # wie bei jedem Update
scripts/setup-env.sh              # ergänzt POSTGRES_RESTORE_PASSWORD in der .env (alles andere bleibt)
docker compose up -d --build      # db-init legt Rolle und Wegwerf-Datenbank an
docker compose logs db-init       # "cobe_news_restore ready"
```

Dann *Sicherung & Export → Rücksicherungs-Test* → „Jetzt testen“. Nicht gewünscht: `POSTGRES_RESTORE_PASSWORD=` leer in
der `.env` lassen (Zeile behalten) – dann legt `db-init` nichts an und der Reiter sagt „nicht eingerichtet“.

**Verschlüsselte Sicherungen, deren Passphrase die App nicht kennt** (`BACKUP_PASSPHRASE` nur im cron-Job): „Wer startet
den Test“ auf „Der Host (Cron-Skript)“ stellen und auf dem Host per cron `scripts/restore-test.sh` laufen lassen – das
Skript liest die Passphrase-Datei auf dem Host und gibt sie dem Container über die Standardeingabe (nie auf einer
Befehlszeile oder in einem Log). Z. B. `/etc/cron.d/cobe-news-restore-test`, sonntags nach der täglichen Sicherung:

```
30 4 * * 0 root /opt/cobe-news/scripts/restore-test.sh --passphrase-file /root/.cobe-news-backup-pass >>/var/log/cobe-news-restore-test.log 2>&1
```

Exit-Code 0 = bestanden, 1 = fehlgeschlagen. Darunter: `docker compose exec -T app python -m app.cli restore-test
[--passphrase-file -]`. Die Fehlercodes erklärt das Handbuch (*Sicherung → Rücksicherungs-Test*).

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
`docker-compose.yml`: `postgres:18-alpine@sha256:…`, `nginx:1.30-alpine@sha256:…`) – ein Build oder Start nimmt genau
diese Images, auch wenn unter dem Tag inzwischen ein anderes liegt. Aktualisieren (z. B. monatlich oder nach einer
Sicherheitsmeldung): `docker buildx imagetools inspect <image:tag>` zeigt den aktuellen Digest („Digest:“ des Index), ihn
an allen Stellen eintragen, bauen, Tests und ein Wegwerf-Stack wie bei jedem Update. Beim nginx
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
deploy/nginx/                 nginx-Vorlage und Zertifikatswächter
frontend/src/pages/           Oberfläche
```

Regeln für neue Masken (was gesetzt ist vs. Eingabe, Reihenfolge, Tooltips, Leerzustände, Status-Farben, Datumsformat,
Löschen, Fokus in Schubladen, 375 px, Hell/Dunkel): [`docs/UX.md`](UX.md).

## Versionierung

0.1.x – jedes Release erhöht die letzte Stelle; Änderungen werden dafür gesammelt. Was sich geändert hat: [`CHANGELOG.md`](../CHANGELOG.md).

## Release

Gearbeitet wird nie direkt auf `main` (geschützt), sondern in eigenen Branches mit Pull Requests – dabei läuft keine
Pipeline. Ein Release startet nur mit einem Tag:

```bash
git tag v0.1.47 && git push origin v0.1.47
```

Die einzige Pipeline, [`.github/workflows/release.yml`](../.github/workflows/release.yml), prüft dann, dass der Tag zu
allen Versionsangaben passt (`backend/app/__init__.py`, `backend/pyproject.toml`, `backend/uv.lock`,
`frontend/package.json`, `frontend/package-lock.json`) und `CHANGELOG.md` einen Abschnitt `## 0.1.47 – …` hat, lässt die
Backend-Tests (mit PostgreSQL 18), die Frontend-Prüfungen, Tests und den Build laufen und prüft die Abhängigkeiten auf
bekannte Schwachstellen. Erst wenn alles grün ist, baut sie das Image für amd64 und arm64, legt es als
`ghcr.io/g0urmetd/cobe-news:0.1.47` und `:latest` ab, signiert es (cosign, ohne gespeicherten Schlüssel) und schreibt den
GitHub-Release mit dem Text aus dem Changelog.

Prüfen der Signatur:

```bash
cosign verify ghcr.io/g0urmetd/cobe-news:0.1.47 \
  --certificate-identity-regexp '^https://github\.com/G0urmetD/Cobe-News/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Das Image statt eines lokalen Builds betreiben: [Veröffentlichtes Image statt lokalem Build](#veröffentlichtes-image-statt-lokalem-build).

## Offene Punkte

- Keine Wiederherstellungscodes für den zweiten Faktor (der Notfall-Admin wird über `app.cli` zurückgesetzt).
- Ein App-Prozess: Fehlversuch-Zähler, Rate-Limits und der Hintergrundjob leben im Speicher (ein Neustart setzt die
  Zähler zurück – laufende Konto- und Adress-Sperren bleiben, Tabelle `auth_locks`).
- AD/LDAP: der Servername wird vor der Verbindung geprüft (`netaddr.check_host`), aber nicht auf die geprüfte Adresse
  festgenagelt (kein DNS-Pinning wie bei den Kanälen) – ein DNS, das zwischen Prüfung und Verbindung die Antwort
  wechselt, könnte die Bind-Anfrage umlenken; LDAPS mit Zertifikatsprüfung schützt das Bind-Passwort trotzdem.
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
