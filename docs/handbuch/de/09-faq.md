---
title: Fehlerbehebung & FAQ
summary: Antworten auf häufige Fragen – was zu tun ist, wenn News fehlen, Benachrichtigungen nicht ankommen, die Anmeldung scheitert oder der Server Probleme macht.
audience: all
---

## Fragen von Lesern {#leser}

### Ich sehe gar keine News {#keine-news}

- Steht auf der Seite „News sind ausgeschaltet“, hat noch niemand die News eingeschaltet. Das kann nur ein Admin –
  sprecht ihn an. Ab Werk sind die News aus, damit der Server nichts abruft, bevor jemand die Quellen gewählt hat.
- Steht dort „Nichts Neues“, habt ihr alles gelesen. Gelesene Meldungen stehen im Reiter „Gelesen“.
- Ist ein Filter oder eine Suche aktiv, zeigt die Seite nur passende Meldungen. „Filter zurücksetzen“ zeigt wieder alle.
- Direkt nach dem Einschalten dauert es bis zur ersten Abrufrunde, bis Meldungen erscheinen.

Mehr dazu: [News lesen](/docs/news-quellen#news-lesen) und [Neu und Gelesen](/docs/erste-schritte#gelesen).

### Warum ist eine Meldung „Hoch“ oder „Kritisch“? {#warum-hoch}

Cobe News stuft jede Meldung nach festen Regeln ein – nach dem [CVSS](term:cvss)-Wert, der Einstufung von Behörde oder
Hersteller, Hinweisen auf aktive Ausnutzung (z. B. im [KEV](term:kev)-Katalog) oder auf Ransomware. Öffnet die Meldung:
im Abschnitt „Einschätzung nach Regeln“ steht, welche Regel gegriffen hat. Die Einstufung ist ein Hinweis für die
Reihenfolge, keine eigene Bewertung eures Risikos.

Mehr dazu: [Schwere](/docs/news-quellen#schwere).

### Warum erscheint eine Meldung doppelt – oder „auch bei“? {#doppelt}

Cobe News zeigt jede Meldung nur einmal, wenn sie dieselbe Adresse (ohne Tracking-Zusätze) oder innerhalb von 3 Tagen
denselben Titel hat. Dieselbe CVE aus CISA KEV, ENISA EUVD und den BSI-Warnungen erscheint innerhalb von 30 Tagen nur
einmal; die anderen Quellen stehen dann als „auch bei …“ an der Meldung.

Berichten zwei Medien mit verschiedenen Titeln über dasselbe Ereignis, sind das zwei Meldungen – Cobe News erkennt
nicht, dass es inhaltlich um dasselbe geht.

### Desktop-Benachrichtigungen erscheinen nicht {#desktop-kommt-nicht}

Der Reihe nach prüfen:

1. *Einstellungen → Benachrichtigungen*: ist „Desktop-Benachrichtigungen“ eingeschaltet und gespeichert?
2. Steht bei „Berechtigung“ „Blockiert“, hat der Browser Benachrichtigungen für diese Seite gesperrt. In den
   Website-Einstellungen des Browsers erlauben, dann die Seite neu laden.
3. „Test-Benachrichtigung“ wählen. Kommt sie nicht, liegt es am Betriebssystem: Mitteilungen für den Browser in den
   Systemeinstellungen erlauben, Fokus bzw. „Nicht stören“ ausschalten.
4. Bei geschlossenem Tab helfen nur „Push bei geschlossenem Tab“ und ein Zertifikat, dem euer Computer vertraut. Steht
   dort „Nicht verfügbar“, nennt die Karte den Grund – meist das Zertifikat. Dann bitte einen Admin, es zu verteilen.
   Der offene Tab benachrichtigt trotzdem.
5. Benachrichtigungen gehen nur über die https-Adresse.

Mehr dazu: [Desktop-Benachrichtigungen](/docs/benachrichtigungen#desktop).

### Auf dem Mac sehe ich die Benachrichtigungen nicht {#macos-hauptdisplay}

macOS zeigt Mitteilungen nur auf dem Hauptdisplay. Arbeitet ihr mit mehreren Bildschirmen, erscheinen sie
möglicherweise auf einem, auf den ihr gerade nicht schaut. Den gewünschten Bildschirm zum Hauptdisplay machen:
*Systemeinstellungen → Displays*, Bildschirm wählen, „Verwenden als: Hauptdisplay“.

### Vendor News sagt „Möglicherweise betroffen“ – was heißt das? {#moeglicherweise-betroffen}

Die Daten zu dieser Schwachstelle reichen nicht für eine sichere Aussage. Typische Gründe:

- Der Hersteller oder die NVD nennt die betroffenen Versionen nicht eindeutig.
- Die eingetragene Version ist zu grob, z. B. `11.2` statt der genauen Version. Sie umfasst dann mehrere Releases,
  die unterschiedlich betroffen sind. Mit der genauen Version wird die Aussage sicher.

Mehr dazu: [Bewertung](/docs/vendor-news#bewertung) und [Versionen eintragen](/docs/vendor-news#versionen).

### Was heißt „Bitte prüfen“ an einer Version? {#bitte-pruefen}

Die Version hat länger als die eingestellte Frist (Standard 90 Tage) niemand bestätigt oder geändert. Cobe News weiß
nicht, ob sie noch läuft – nur ihr wisst das. Läuft sie noch so: „Bestätigen“. Sonst die Version ändern. Bestätigen
dürfen die Mitglieder der Teams des Produkts und die Admins. Mehr: [Versionen prüfen](/docs/vendor-news#versionen-pruefen).

### Ein Produkt fehlt im Katalog {#produkt-fehlt}

*Vendor News* → **⋯ → Produkt vorschlagen** (oder „Produkt fehlt? Vorschlagen“ im Katalog) – ein Admin nimmt es auf. Mehr:
[Produkt vorschlagen](/docs/vendor-news#produkt-vorschlagen).

„VMware vSphere“ steht als zwei Produkte im Katalog: **VMware vCenter Server** und **VMware ESXi** – die Version
aus der VAMI (`8.0.3.00400`) oder der Build wird genommen. Mehr:
[VMware vSphere](/docs/vendor-news#vmware-vsphere).

Ein Produkt, das bisher zweimal im Katalog stand (z. B. IBM Db2, Omnissa Horizon, Juniper SRX), gibt es seit 0.1.45
einmal – gefolgte Produkte sind mit umgezogen. Mehr:
[Zusammengelegte Produkte](/docs/vendor-news#zusammengelegte-produkte). Citrix-Bulletins kommen über die CVE-Daten,
nicht als eigene Quelle: [Citrix und NetScaler](/docs/vendor-news#citrix).

### Warum bin ich plötzlich abgemeldet? {#abgemeldet}

Eine Sitzung endet nach einer Zeit ohne Aktivität und spätestens nach einer festen Höchstdauer – ab Werk nach 60 Minuten
Leerlauf bzw. 12 Stunden. Ein Admin kann beides ändern. Auch wenn ein Admin euer Passwort oder TOTP zurücksetzt oder
sich eure Rolle ändert, endet die Sitzung. Einfach neu anmelden.

### Passwort vergessen oder TOTP verloren {#passwort-vergessen}

Eine Selbstbedienung gibt es nicht. Wendet euch an einen Admin:

- **Lokales Konto:** der Admin setzt Passwort und/oder TOTP zurück. Ihr bekommt ein temporäres Passwort und wählt bei
  der nächsten Anmeldung ein eigenes.
- **Active-Directory- oder Microsoft-Konto:** das Passwort gehört eurem Verzeichnis – wendet euch an eure IT. Bei
  Microsoft-Konten fragt Microsoft selbst nach dem zweiten Faktor.

Mehr dazu: [Eigenes Konto](/docs/erste-schritte#eigenes-konto).

### Ich bekomme keine Hersteller-News meiner Produkte {#keine-hersteller-news}

Der Reihe nach prüfen, unter *Einstellungen → Benachrichtigungen*:

1. **Kein Reiter *Hersteller-News meiner Produkte*?** Dann ist *Teams* ausgeschaltet oder ihr seid in keinem Team (und
   beobachtet keine CVE). Das ändert nur ein Admin.
2. **„Dir ist noch kein Produkt zugeteilt.“** Ein Admin legt im Team fest, wer welches Produkt bekommt.
3. **„Vom Admin ausgeschaltet“** an einem Weg: Diesen Weg hat ein Admin nicht freigegeben.
4. **Weg eingeschaltet und gespeichert?** E-Mail braucht eine Adresse im Konto. Desktop braucht in mindestens einem
   Browser „Push bei geschlossenem Tab“ (Reiter *Neue Meldungen*). Teams braucht eine Workflow-URL – „Test senden“
   zeigt, ob sie stimmt.
5. **Nur Neues:** Ältere Meldungen, das erste Prüfen eines Produkts und alles, was euer Filter (Art, Schwere)
   ausgelassen hat, kommen nie.
6. **Ruhezeiten oder „Gesammelt um …“:** Normales wartet bis zum Ende der Ruhezeit bzw. bis zur Uhrzeit.
7. **Abwesenheit:** In der Zeit geht alles an die Vertretung – außer mit „Trotzdem auch an mich“.

Unter jedem Weg steht, wann zuletzt etwas zugestellt wurde, oder der letzte Fehler mit dem nächsten Versuch.

Mehr dazu: [Hersteller-News meiner Produkte](/docs/benachrichtigungen#meine-produkte).

### „Ans Team weiterleiten“ fehlt oder ist ausgegraut {#weiterleiten-geht-nicht}

- **Der Knopf fehlt:** *Teams* ist ausgeschaltet oder ihr seid in keinem Team.
- **Der Knopf ist ausgegraut:** Für keines eurer Teams hat ein Admin einen Weiterleitungs-Kanal festgelegt – der Tooltip
  sagt das. Einen Kanal wählt nur ein Admin, im Team unter *Allgemein*.
- **Eine Meldung sagt, wann es wieder geht:** Höchstens 10 Weiterleitungen pro Stunde und Person, dieselbe Meldung an
  dasselbe Team nur einmal in 10 Minuten.
- **Der Kanal hat die Nachricht abgelehnt:** Dann sollte ein Admin den Kanal prüfen.

Mehr dazu: [An mein Team weiterleiten](/docs/benachrichtigungen#weiterleiten).

### Warum steht ein Befund auf „Sofort“? {#warum-sofort}

Die [Dringlichkeit](/docs/vendor-news#dringlichkeit) ist eine Zahl von 0 bis 100 aus festen Punkten: Schwere, EPSS,
KEV bzw. aktiv ausgenutzt, eure Version, ob es einen Fix gibt, und das Alter. Ab 60 heißt sie *Sofort*, ab 35 *Bald*.
Fahrt mit der Maus über die Zahl – der Tooltip zeigt jeden Faktor mit seinen Punkten. Eine kritische Lücke, die eure
Version betrifft, ist immer *Sofort*; eine nicht betroffene Version bleibt immer unter 35.

Mehr dazu: [So wird gerechnet](/docs/vendor-news#dringlichkeit-formel).

### Unter „Mein Team“ fehlt ein Produkt {#mein-team-fehlt}

„Mein Team“ zeigt nur die Produkte, die ihr über eure Teams bekommt. Fehlt eines, ist es eurem Team nicht zugeordnet,
oder es bekommen im Team nur ausgewählte Personen, und ihr seid nicht dabei. Beides ändert ein Admin im Team unter
*Produkte*. Mit *Alle* seht ihr bis dahin alle gefolgten Produkte.

Mehr dazu: [Mein Team](/docs/vendor-news#mein-team).

## Fragen von Admins {#admin .admin}

### Der Browser warnt vor dem Zertifikat {#zertifikatswarnung}

Ab Werk nutzt Cobe News ein selbstsigniertes Zertifikat. Browser warnen, bis der Computer ihm vertraut.

- Zertifikat in *Einstellungen → HTTPS & Zertifikat* herunterladen und auf allen Computern als vertrauenswürdig
  hinterlegen – nach jeder Erneuerung erneut ([verteilen](/docs/betrieb#zertifikat-verteilen)).
- Oder ein Zertifikat eurer eigenen CA einsetzen ([eigenes Zertifikat](/docs/betrieb#eigenes-zertifikat)).
- Warnt der Browser trotz vertrautem Zertifikat: passt der Name in der Adresszeile zu „Gilt für“? Die Seite
  *HTTPS & Zertifikat* zeigt einen Hinweis, wenn das Zertifikat nicht für den Namen aus `BASE_URL` gilt oder abgelaufen ist.

### Kollegen erreichen die Seite nicht {#kollegen-erreichen-nicht}

- `BIND` ist ab Werk `127.0.0.1` – dann ist die Seite nur auf dem Server erreichbar. `BIND=0.0.0.0` setzen.
- Die Firewall des Servers muss den Port aus `PORT` (ab Werk 8095) für das Firmennetz öffnen.
- Der DNS-Name muss auf den Server zeigen, und `BASE_URL` muss genau diese Adresse sein.
- Nach Änderungen an der `.env` `docker compose up -d` ausführen – ein `restart` übernimmt sie nicht.

Schritt für Schritt: [Adresse für Kollegen](/docs/betrieb#fuer-kollegen).

### Ein Kanal meldet „Ziel nicht erlaubt“ {#ziel-nicht-erlaubt}

Benachrichtigungskanäle (auch der generische [Webhook](term:webhook)) senden ab Werk nur an öffentliche Adressen. Seit
Version 0.1.22 gilt das auch für Ziele im Firmennetz, z. B. ein n8n unter einer `10.…`-Adresse.

1. Die Adresse oder das Netz des Ziels in der `.env` eintragen, z. B. `WEBHOOK_PRIVATE_NETS=10.20.0.5/32`.
2. `docker compose up -d`.
3. Im Kanal „Testen“ wählen.

Mit Eintrag gehen private Adressen, die eigenen Docker-Netze und der Docker-Host – dieser nur über seine Adresse, nie
über einen Namen wie `host.docker.internal`. Immer gesperrt, auch mit Eintrag, sind Loopback (`127.0.0.1`, `::1`),
Link-Local samt Cloud-Metadaten (`169.254.169.254`), „any“ (`0.0.0.0`) und Multicast. Ein Dienst, der auf dem Server
nur an `127.0.0.1` lauscht, ist über die Adresse des Docker-Hosts erreichbar, nicht über `127.0.0.1`. Mehr dazu:
[Ziele](/docs/benachrichtigungen#webhook-ziele).

### Die Anmeldung mit Microsoft zeigt einen AADSTS-Fehler {#entra-aadsts}

Die Nummer nach „AADSTS“ sagt, was in Entra nicht passt. Die häufigsten mit ihrer Lösung:
[Entra-Fehler](/docs/anmeldung#entra-fehler).

### Nach dem Ändern von BASE_URL klappt die Anmeldung mit Microsoft nicht mehr {#base-url-entra}

Die Umleitungs-URI hängt an `BASE_URL`. Microsoft meldet dann meist AADSTS50011. In der App-Registrierung in Entra
unter *Authentifizierung* die Umleitungs-URI auf diesen Wert ändern – exakt, ohne Schrägstrich am Ende:

```
{{redirect_uri}}
```

Mehr dazu: [Umleitungs-URI](/docs/anmeldung#entra-redirect-uri).

### Eine Quelle ist „tot“ oder „gestört“ {#quelle-tot}

- **gestört:** 3 Fehlschläge in Folge, ein Fehler, der nicht nur vorübergehend ist (Adresse falsch, Antwort unlesbar,
  Zertifikat), oder eine unlesbare Antwort in den letzten 24 Stunden. Die Quelle pausiert bis zum nächsten Versuch.
- **tot:** die Quelle lehnt Abrufe ab (401, 403 oder 410 zweimal in Folge), ihre Adresse gibt es nicht mehr (404
  dreimal), seit 14 Tagen klappte kein Abruf oder – bei News – seit 60 Tagen kam keine neue Meldung.

In *Einstellungen → Integrationen → Gesundheit* zeigt ein Klick auf die Quelle den Verlauf und den letzten Fehler.
Betrifft es viele Quellen gleichzeitig, liegt es meist am ausgehenden Netz (Proxy, Firewall, DNS) – siehe
[ausgehende Daten](/docs/integrationen#ausgehende-daten). Eine einzelne tote Quelle hat oft ihre Adresse geändert:
eine eigene Quelle anpassen oder ausschalten.

Mehr dazu: [Quellen-Gesundheit](/docs/news-quellen#quellen-gesundheit).

### Die Sicherung ist fehlgeschlagen {#sicherung-fehlgeschlagen}

*Einstellungen → Sicherung & Export* zeigt bei „Letzte Sicherung“ den Grund und darunter die technische Meldung.

| Meldung | Was tun |
|---|---|
| Es lief schon eine Sicherung. | Kein Fehler – warten, bis sie fertig ist. |
| Die Passphrase ist zu kurz | `BACKUP_PASSPHRASE` mit mindestens 12 Zeichen setzen. |
| pg_dump hat nicht rechtzeitig geantwortet / ist fehlgeschlagen | Läuft die Datenbank (`docker compose ps -a`)? Ist genug Platz auf dem Datenträger? Log der App lesen. |

Läuft die Sicherung per cron, steht das Ergebnis in dessen Logdatei; ein Exit-Code ungleich 0 heißt „nicht gesichert“.
Mehr dazu: [Sicherung](/docs/sicherung#jetzt-sichern) und [cron](/docs/sicherung#cron).

### Ich bin ausgesperrt {#ausgesperrt}

- **Ein Konto ist gesperrt** (5 Fehlversuche in 15 Minuten): die Sperre endet nach 15 Minuten von selbst. Ein anderer
  Admin kann sie unter *Einstellungen → Benutzer & Rollen* mit „Sperre aufheben“ sofort lösen.
- **Kein Admin kommt mehr hinein:** mit dem Notfall-Admin anmelden. Er wird durch Fehlversuche nie gesperrt, und er hängt
  nicht am Active Directory oder an Entra.
- **Auch das Passwort des Notfall-Admins ist weg:** auf dem Server zurücksetzen ([nächste Frage](#notfall-totp-verloren)).

Mehr dazu: [Notfall-Admin](/docs/anmeldung#notfall-admin).

### Das TOTP oder Passwort des Notfall-Admins ist verloren {#notfall-totp-verloren}

Auf dem Server:

```bash
cd /opt/cobe-news
docker compose exec app python -m app.cli reset-emergency
```

Der Befehl gibt ein temporäres Passwort aus, entfernt das TOTP, beendet alle Sitzungen des Notfall-Admins und hebt eine
Sperre auf. Mit dem temporären Passwort anmelden, ein neues Passwort wählen und TOTP neu einrichten. Die neuen
Zugangsdaten offline aufbewahren, z. B. in einem Passwort-Tresor.

### E-Mails kommen nicht an {#mails-kommen-nicht}

1. *Einstellungen → Kanäle & Regeln*, Reiter *Kanäle*, Zeile *E-Mail-Server*: „Bearbeiten“, dann „Test-Mail senden“.
   Die Meldung nennt die Art des Fehlers (abgelehnt, keine Verbindung, TLS …).
2. Kommt die Test-Mail an, aber keine Meldung: passt eine Regel? Schweregrade, Quellen und Sprache prüfen. Eine neue
   Regel gilt nur für Meldungen, die danach eintreffen ([Regeln](/docs/benachrichtigungen#regeln)).
3. Zeigt der Kanal einen Fehler und einen nächsten Versuch, pausiert er nach Fehlschlägen. „Testen“ prüft ihn sofort.
4. Liegt das [SMTP](term:smtp)-Relay auf dem Docker-Host selbst, lehnt Cobe News es als internes Ziel ab. Seine
   Adresse (das Gateway des Containers, z. B. `172.31.250.128`, oder bei Docker Desktop die Adresse hinter
   `host.docker.internal`) in `SMTP_ALLOW_INTERNAL` eintragen, dann `docker compose up -d`. `127.0.0.1` geht nie –
   das wäre der Container selbst.
5. Den Spam-Ordner der Empfänger prüfen.

### Vendor News zeigt nichts {#vendor-news-leer}

- Ohne gefolgtes Produkt fragt Vendor News nichts ab. Zuerst unter *Vendor News* Produkte aus dem Katalog folgen
  ([Produkten folgen](/docs/vendor-news#produkten-folgen)).
- Der erste Abruf dauert. Ohne NVD-API-Schlüssel erlaubt die [NVD](term:nvd) nur wenige Anfragen; ein kostenloser
  Schlüssel beschleunigt das ([Vendor News einrichten](/docs/integrationen#vendor-news)).
- In *Einstellungen → Integrationen → Gesundheit* nachsehen, ob die Abfragen von Vendor News klappen.

### Ich habe die .env geändert, aber nichts passiert {#env-wirkt-nicht}

Änderungen an der `.env` wirken erst, wenn die Container neu angelegt werden: `docker compose up -d` im
Installationsordner. `docker compose restart` behält die alten Werte.

### Die App startet nicht {#app-startet-nicht}

1. `docker compose ps -a` zeigt, welcher Container fehlt oder neu startet.
2. `docker compose logs db` – die Zeilen `db-init: …` zeigen, ob die Datenbank die Rolle der App eingerichtet hat;
   scheitert das, startet die App nicht. Häufigster Grund: `POSTGRES_APP_PASSWORD` fehlt oder ist kürzer als 16
   Zeichen ([Datenbank](/docs/betrieb#db-rollen)).
3. `docker compose logs --tail 100 app` – nach einem Update steht dort z. B. ein Fehler bei der Migration.

### Wo finde ich die Logs? {#wo-logs}

```bash
cd /opt/cobe-news
docker compose logs -f app
```

Welcher Container wofür: [Logs](/docs/betrieb#logs).

### Eine Team-Gruppe zeigt „Gruppe nicht lesbar“ {#team-gruppe-fehler}

Die Gruppe nennt den Grund; das Team bleibt so lange, wie es ist – ein Ausfall leert kein Team.

| Grund | Was tun |
|---|---|
| Das Verzeichnis verweigert die Suche | Rechte des Dienstkontos von AD/LDAP prüfen |
| Microsoft Graph verweigert den Zugriff (403) | der App-Registrierung `GroupMember.Read.All` als Anwendungsberechtigung geben, mit Administratorzustimmung ([Schritt 5](/docs/anmeldung#entra-api-berechtigungen)) |
| Graph liefert nur IDs ohne Namen | ebenso `User.Read.All` |
| Das Verzeichnis ist nicht eingerichtet oder ausgeschaltet | AD/LDAP bzw. Entra ID unter *Einstellungen → Anmeldung* einrichten und einschalten |
| Die Gruppe hat mehr als 50 000 Mitglieder | eine kleinere Gruppe binden |
| Die Gruppe wurde nicht gefunden | die Gruppe wurde im Verzeichnis gelöscht – lösen und die richtige binden |

Danach unter *Mitglieder* „Jetzt laden“. Mehr dazu: [Team anlegen und Gruppen binden](/docs/anmeldung#teams-gruppen).

### Der Rücksicherungs-Test ist fehlgeschlagen {#ruecksicherungs-test-fehlgeschlagen}

*Einstellungen → Sicherung & Export*, Reiter *Rücksicherungs-Test*, nennt einen Code. Die häufigsten:

- `not_configured` – `POSTGRES_RESTORE_PASSWORD` fehlt in der `.env`: `scripts/setup-env.sh`, dann
  `docker compose up -d`.
- `passphrase` – die Sicherung ist mit einer Passphrase verschlüsselt, die nur der cron-Job kennt: den Test vom Host
  starten lassen ([Per Host-Cron](/docs/sicherung#ruecksicherungs-test-host)).
- `no_backup` – es gibt noch keine Sicherung: „Jetzt sichern“.

Alle Codes mit Abhilfe: [Was geprüft wird](/docs/sicherung#ruecksicherungs-test-pruefungen).

### Ein Skript bekommt 401 mit seinem API-Token {#token-401}

Die 401 (`invalid_token`) sagt absichtlich nicht, warum. Den Grund zeigt *Einstellungen → API & Metriken*, Reiter
*Tokens*, in der Spalte *Zustand*: abgelaufen, widerrufen oder verwaist (der Admin, der es angelegt hat, ist kein
aktiver Admin mehr). In jedem Fall ein neues Token anlegen und das alte widerrufen. Steht es auf aktiv, kommt das Token
nicht richtig an: genau `Authorization: Bearer cnt_…`, ohne Sitzungs-Cookie und nie in der URL.

Mehr dazu: [Fehler und Grenzen](/docs/api#fehler).

### Wie melde ich ein Problem? {#problem-melden}

Diese Angaben helfen bei der Suche:

- die Version aus dem Benutzermenü, *Version & Changelog* (hier: {{version}}),
- was ihr getan habt und was ihr erwartet habt,
- Uhrzeit und Text der Fehlermeldung,
- die passenden Zeilen aus `docker compose logs --since 1h app`.

Vor dem Weitergeben Setup-Tokens, temporäre Passwörter, Webhook-URLs und andere Geheimnisse aus Logs und Screenshots
entfernen. Die `.env` nie mitschicken.
