# Changelog

Versionierung: 0.1.x – jede Änderung erhöht die letzte Stelle.

## 0.1.47 – Exploit-Hinweise, Themen in Regeln, Update-Hinweis und Härtung

### Neu
- **Exploit-Hinweise**: Plakette „Exploit-Code öffentlich“ mit Links an Befunden, Meldungen und beobachteten CVEs – aus den Listen von Metasploit und nuclei-templates (an) und Exploit-DB (aus, zuschaltbar); einmal täglich, nur CVE und Link, nie Exploit-Code.
- **Neues Thema „Exploit veröffentlicht“** in News, aus CISA-Einstufung und den Exploit-Listen; beobachtete CVEs melden sich, wenn ein Exploit erscheint.
- **Themen in Benachrichtigungsregeln** sowie für Desktop- und Push-Benachrichtigungen.
- **„Betrifft unsere Produkte“** als Schnellfilter in News mit Anzahl und Plakette „Unser Produkt: …“ auf den Karten.
- **Update-Hinweis für Admins**, wenn auf GitHub eine neuere Version erschienen ist (abschaltbar). Nur ein Hinweis – aktualisiert wird nichts von selbst. Läuft eine Version, die noch nicht veröffentlicht ist, steht das unter *Über Cobe News* so da.
- **TLP:GREEN je CSAF-Quelle zulassen** (aus ab Werk); solche Inhalte sind überall als „TLP:GREEN – nur intern weitergeben“ gekennzeichnet.
- **Katalog 2026.11.03-2 – 14 neue Produkte**: BookStack, BloodHound (Community Edition), Velociraptor, DFIR-IRIS, NetBox, Oxidized (Weboberfläche oxidized-web), Semaphore UI, Dockge, Wiki.js, Apache Guacamole sowie PingCastle, Purple Knight, GPOZaurr und ScubaGear (ohne CVE-Daten, nur News). Greenbone/OpenVAS deckt jetzt auch die Teile der Community Edition ab (gvmd, openvas-scanner).
- **Fertiges Image nutzen**: optional `docker-compose.image.yml` mit dem signierten Image von ghcr.io statt lokalem Bauen.

### Verbessert
- **Dringlichkeit**: ein öffentlicher Exploit zählt +10, nicht zusätzlich zu „aktiv ausgenutzt“.
- **Versionsprüfung**: Firefox ESR und Jenkins LTS nehmen nur Versionen ihrer eigenen Linien an; Exchange-Versionen mit führenden Nullen werden vereinheitlicht; „Mozilla Firefox“ einheitlich benannt.
- **Katalog-Änderungen verknüpfen gespeicherte Advisories neu** – angezeigt, aber nicht gemeldet.
- **Dovecot** über die Open-Xchange-Angaben, **iDRAC10** mit CPE, Dells „… or later“-Angaben werden verstanden.
- **Anmeldeseite und mobile Seitenleiste** ohne kurzes Flackern beim ersten Laden.

### Fixes
- **CPEs mit Doppelpunkt im Namen** (z. B. mailcow) werden beim Abgleich richtig erkannt.
- **Meldungsdetails** nutzen nur noch frei weitergebbare Dokumente.
- **Falsches „betroffen“ durch CISAs Ergänzung**: NVD liefert neben den Angaben des Herstellers auch CISAs Ergänzung (ADP) mit. Beide standen bisher ununterscheidbar nebeneinander, und CISAs Vorgabe „alle anderen Versionen betroffen“ galt als Aussage des Herstellers (GitLab 19.5.3 bei CVE-2024-4835). Jetzt entscheidet der Hersteller; CISAs Angaben zählen nur, wo er das Produkt nicht nennt. Die gespeicherten NVD-Einträge werden beim nächsten fälligen Abruf je Produkt vollständig neu geholt.
- **Bereiche im Versionsfeld**: Viele Hersteller (und GitHubs Hinweise) schreiben den Bereich ins Versionsfeld („>= 3.2.0, < 4.7.1“, „< 25.7.0“). Das wurde als eine einzige Version gelesen: Die Version mit dem Fix galt als „vom Hersteller als betroffen gelistet“, Versionen mitten im Bereich als „neuer als gelistet“. Betraf u. a. GitLab, TYPO3, Wazuh, LibreNMS, Squid, Redis.
- **CISAs Ergänzung (ADP) nie über der NVD-Analyse**: Sie zählt nur noch, wo weder die NVD-Analyse noch der Hersteller das Produkt nennt, und ihre Vorgabe „alle anderen Versionen betroffen“ gilt nie (VMware Cloud Foundation CVE-2022-22948 zeigte sonst „betroffen“ für 4.5.2). Schon gespeicherte NVD-Einträge werden sofort richtig gelesen, nicht erst nach dem nächsten Abruf.
- **„Möglicherweise betroffen“ trotz NVD-Analyse**: Schreibt der Hersteller die betroffenen Versionen nur als Text („versions prior to v22.09“), entscheidet jetzt die Analyse der NVD statt eines offenen „möglicherweise“ (BookStack CVE-2022-40690).
- **„Langsam“ in der Quellen-Gesundheit** kam auch von einem einzelnen großen Download, etwa dem ersten vollständigen NVD-Abruf eines neu verfolgten Produkts (GitLab: 6 MB in 4 Seiten). Downloads über 1 MB je Anfrage zählen dafür nicht mehr; die angezeigte mittlere Antwortzeit enthält sie weiter.

### Sicherheit
- **Startpasswörter laufen nach 7 Tagen ab** (einstellbar 1–30).
- **Größenlimit für Anfragen auch in der App** (1 MiB, `MAX_BODY_BYTES`).
- **Warnung bei kurzem `SECRET_KEY`** im Log und unter Einstellungen → HTTPS.
- **Verdächtiges im Log**: CSRF-Fehler gedrosselt protokolliert; zu viele Fehlversuche am Notfall-Konto erzeugen Warnung, Protokolleintrag und Hinweis für Admins.
- **Unsichtbare Richtungs- und Steuerzeichen** werden aus allen Benachrichtigungen entfernt.

### Betrieb
- **Bekannte Hostnamen**: Der Proxy antwortet nur noch auf die Namen aus `BASE_URL`, `NEWS_HOSTNAME`, `TLS_NAMES` sowie localhost; andere bekommen „Unbekannter Hostname“ (421). Wer Cobe News über eine weitere IP oder einen weiteren Namen aufruft, trägt sie in `TLS_NAMES` ein. Unverschlüsseltes http auf dem https-Port wird umgeleitet.
- **Neue Variable `NEWS_BIND`** in der Compose-Datei (aus `BIND`) für die Warnung beim Start des Proxys.
- **Neue ausgehende Verbindungen**: raw.githubusercontent.com (Exploit-Listen), gitlab.com (Exploit-DB, nur wenn an), api.github.com (Update-Hinweis).
- **Migrationen 0026 bis 0029**.

## 0.1.46 – Themen-Filter, neues Nachrichtenformat und CVEs nach Produkt

### Neu
- **Themen-Filter in News**: Aktiv ausgenutzt, Zero-Day, Ransomware, Ohne Patch, Vorfall/Datenleck, Lieferkette, Phishing und OT/ICS – mit Anzahl je Thema, Schnellfiltern, Plaketten auf den Karten und der Begründung in der Schublade.
- **Quellen nach Art gruppiert**: im Quellenfilter etwa „Alle: Behörden & CERTs“.
- **Nachrichten als Karte in allen Chat-Kanälen**: Discord, Teams, Slack, Mattermost und Telegram zeigen Produkt, Quelle, Kategorie und eine Kurzbeschreibung statt eines langen Textes; ntfy und Gotify dasselbe als Text; bei vielen Meldungen eine kompakte Liste.
- **Beobachtete CVEs nach Produkt gruppiert**: „Gruppieren nach“ Produkt (neu, Standard), Herkunft oder Keine – CVEs zu GitLab landen in der Gruppe GitLab, egal wie sie hinzugefügt wurden.

### Verbessert
- **„An mein Team weiterleiten“** im selben Kartenformat, der Kommentar als eigenes Feld.
- **Aktuelle Produktnamen in Benachrichtigungen**, auch für umbenannte und zusammengelegte Produkte.
- **KEV nur noch einmal geladen** und täglich auch ohne gefolgte Produkte; bei einer Sperre durch www.cisa.gov kommt er vom offiziellen Spiegel auf GitHub.

### Fixes
- **Pressemeldungen über eine Meldepflicht** („aktiv ausgenutzte Schwachstellen müssen gemeldet werden“) gelten nicht mehr als kritischer Angriff.

### Betrieb
- **Migration 0024**: Themen je Meldung; ältere Meldungen werden im Hintergrund nachberechnet.

## 0.1.45 – Katalog-Erweiterung

### Neu
- **Rund 95 neue Produkte**, darunter die Windows-Server-Rollen (WSUS, Domain Controller, RDS, NPS, RRAS, DHCP), Trellix ePO, BeyondTrust, PaperCut, 3CX, FRITZ!Box, DrayTek, NCP, baramundi, RMM-Werkzeuge, Mail-Systeme, TK-Anlagen, OT-Fernzugänge, Speicher und Druckerfirmware – der Katalog hat jetzt über 900 Produkte.
- **Open-Xchange als CSAF-Quelle.**
- **Viele Alternativnamen** in der Suche, etwa VBR, SCCM/MECM, Lync, M365 Apps, Check_MK, NSX-T oder XenApp.

### Verbessert
- **Doppelte Produkte zusammengelegt** (DB2, Horizon, SRX, Harbor, Stormshield); gefolgte Produkte, Versionen, Teams, Ansichten und Stummschaltungen ziehen mit um, ohne erneute Benachrichtigung.
- **Cisco SMA heißt richtig Cisco ESA**, Zyxel-Firewalls haben echte CPEs, viele Kategorien korrigiert.

### Betrieb
- **Migration 0025**: zusammengelegte Produkte.
- **Citrix**: Es gibt keine maschinenlesbare Bulletin-Quelle; Citrix-Lücken kommen weiter über die CVE-Liste und NVD.

## 0.1.44 – Katalog-Genauigkeit

### Verbessert
- **Versionen wie angezeigt eintragen**: Build-Tabellen für Exchange, SQL Server, VMware Tools und GlobalProtect; Anzeigeformen von NetScaler, FortiOS, Cisco ISE/FTD, Windows, Office und Check Point werden übersetzt; vor dem Speichern „→ so wird es gewertet“.
- **Plausibilitätsprüfung**: eine Version auf keiner bekannten Linie wird mit Hinweis abgelehnt; gespeicherte, nicht mehr passende Versionen erscheinen als „Bitte prüfen“.
- **Produkte getrennt**: pfSense CE/Plus, Firefox/Firefox ESR, Jenkins LTS/Weekly, nginx/NGINX Plus.
- **„Wo steht die Version?“** für rund 20 weitere Produkte.

### Fixes
- **Falsches „nicht betroffen“ behoben** bei Exchange (CU/SU), SQL Server („2022 CU16“), SharePoint (2016/2019/SE), Java 8 („8 Update 441“), VMware Tools, GlobalProtect, HPE iLO, Acrobat, Sophos (MR), nginx/NGINX Plus und SAP.
- **Falsches „betroffen“ behoben** bei gepatchtem SharePoint 2016, NetScaler 14.1, Jenkins LTS, Firefox ESR, pfSense CE und Sophos.

## 0.1.43 – Vendor News aufgeräumt

### Verbessert
- **Eine Statuszeile statt zwei**: Handlungsbedarf (mit „Sofort“), Möglicherweise, Aktuell und Alle als vier klickbare Felder – vorher standen dieselben Zahlen in einer Zusammenfassung und in Chips.
- **Eine Werkzeugzeile**: Suche, ein „Filter“-Menü (Nur ungelesene, Stummgeschaltete zeigen, Versionen zu prüfen, Mein Team/Alle) mit Anzahl aktiver Filter, „Ansicht: …“ und ein Knopf für Kacheln oder Liste.
- **Aktive Filter als Chips** mit × zum Entfernen und „Alle N als gelesen“ für genau das, was angezeigt wird.
- **Keine Reiter mehr**: Katalog und Vorschläge über das ⋯-Menü und den Knopf „Vorschläge“ (nur bei offenen Vorschlägen); Einstellungen und „Jetzt abrufen“ für Admins im ⋯-Menü; alte Links mit `?tab=` funktionieren weiter.
- **Eine Zeile unter dem Titel** mit nächstem Support-Ende und letztem Abruf.

### Fixes
- **„Alle als gelesen“ mit „Mein Team“** markiert nur noch die Produkte des Teams statt aller gefolgten.
- **Anzahl und Wirkung von „Alle N als gelesen“ stimmen überein**, auch mit stummgeschalteten Produkten und CVEs.

## 0.1.42 – Alle CVEs beobachten, Abmelden in allen Tabs, VMware-Versionen und MFA-Nachweis

### Neu
- **Alle CVEs einer Meldung beobachten**: „Alle beobachten (N)“ in der Meldung und im Befund, „+ N weitere CVEs“ klappt die ganze Liste auf; passt nicht alles ins Limit, fragt die App, ob die ersten freien Plätze genutzt werden sollen.
- **Beobachtete CVEs nach Herkunft gruppieren**: eine Gruppe je Meldung oder Befund mit eigenen Zahlen und „Gruppe nicht mehr beobachten“; Einzelne stehen unter „Einzeln hinzugefügt“.
- **Abmelden in allen Tabs**: Abmelden, Ablauf oder Widerruf beendet die Sitzung in allen offenen Tabs, eine Warnung kurz vor dem Ablauf mit „Angemeldet bleiben“, und erneutes Anmelden nimmt die anderen Tabs mit.
- **MFA-Nachweis bei Entra**: wahlweise Conditional Access vertrauen, einen Authentication Context verlangen oder einen Nachweis im Token fordern – sonst verlangt Cobe News den eigenen zweiten Faktor.
- **Zweiter Faktor für alle**: optionaler Schalter (aus ab Werk); Leser richten dann TOTP oder einen Passkey ein.
- **VMware-Versionen wie angezeigt**: vCenter nimmt `8.0.3.00400` und Build-Nummern an, ESXi Build-Nummern, beide zeigen vor dem Speichern „→ 8.0 U3d“; „vSphere“ findet vCenter Server und ESXi.

### Verbessert
- **Bis zu 500 beobachtete CVEs** pro Person statt 200.
- **Strengere Content Security Policy**: keine eingebetteten `<style>`-Blöcke mehr.

### Fixes
- **Hintergrund-Abfragen halten die Sitzung nicht mehr offen**: Ein offener, unbenutzter Tab läuft jetzt in die Leerlauf-Abmeldung.
- **Toast-Buttons über einer offenen Schublade** („Rückgängig“, „Zur Liste“) lassen sich wieder anklicken.

### Sicherheit
- **Sperren überstehen einen Neustart**: Konto- und Adress-Sperren werden gespeichert.
- **API-Tokens höchstens ein Jahr gültig**: bestehende Tokens ohne Ablauf bekommen ein Ablaufdatum in einem Jahr („Ablauf ergänzt“).
- **Passwort-Historie**: die letzten 5 Passwörter können nicht wieder verwendet werden.

### Betrieb
- **Migrationen 0022 und 0023**: Herkunft beobachteter CVEs; Sperren, Passwort-Historie und Ablauf der API-Tokens.
- **Hinweis für Entra-Admins**: Ohne MFA-Nachweis im Token fragt Cobe News bei der nächsten Anmeldung nach dem eigenen zweiten Faktor.

## 0.1.41 – Gelesen, Stummschalten und Ansichten

### Neu
- **Gelesen und ungelesen**: Ungelesene Meldungen und Befunde haben einen Punkt und einen fetten Titel; „Nur ungelesene“, „Alle als gelesen“ (nach dem aktuellen Filter) und „Als ungelesen markieren“; Zähler an News und Vendor News in der Seitenleiste.
- **Befund wieder ungelesen bei Wichtigem**: Wird ein Befund zum Beispiel aktiv ausgenutzt, ist er wieder ungelesen.
- **Stummschalten**: Ein Produkt oder eine CVE für 7 oder 30 Tage oder bis zu einem Datum stumm schalten – nur für die eigenen persönlichen Benachrichtigungen; Team-Kanäle, Admin-Regeln und andere Personen bleiben unberührt. Übersicht und „Aufheben“ unter Benachrichtigungen → Stummschaltungen.
- **KEV trotz Stumm**: Ein aktiv ausgenutzter Befund an einem stummen Produkt bleibt sichtbar, nur die Benachrichtigung entfällt.
- **Ansichten**: Filter in News und Vendor News unter einem Namen speichern, eine als Standard setzen und per „Link kopieren“ teilen.

### Verbessert
- **News als eine Liste**: Statt der Reiter „Neu“ und „Gelesen“ gibt es eine Liste mit Ungelesen-Markierung; eine geöffnete Meldung bleibt an ihrem Platz.
- **Filter von Vendor News in der Adresse**: Status, Zusammenfassung, Suche, Ungelesen und Stumm stehen in der URL und lassen sich teilen.

### Fixes
- **Neue Konten ohne Altlasten**: Wer neu dazukommt, sieht nichts Älteres als ungelesen – auch wenn Meldungen ihre Ankunftsnummer nicht in Abrufreihenfolge bekommen haben.

### Betrieb
- **Migration 0021**: Lesestand, Stummschaltungen und Ansichten.

## 0.1.40 – Protokoll, Zustellung, Versionen prüfen und Passkeys

### Neu
- **Protokoll (Audit-Log)**: Einstellungen → Zugang & Sicherheit → Protokoll zeigt, wer wann was geändert hat – Konten, Rollen, Anmeldung, Tokens, Kanäle und Regeln, Teams, Einstellungen, Sicherungen, Katalog, Passkeys und Sitzungen –, mit Vorher/Nachher, Filtern und CSV-Export; Änderungen durch den Verzeichnis-Sync und die Kommandozeile stehen mit drin.
- **Zustellprotokoll je Kanal**: Jeder Versuch mit Ergebnis und kurzem Fehlertext, automatische Wiederholungen als Versuche einer Zustellung, „Erneut senden“ für Regel-Meldungen und eine Gesundheits-Anzeige in der Kanalliste.
- **Probelauf für Regeln**: Im Regel-Editor zeigt er vor dem Speichern, was die Regel in den letzten 1, 7 oder 30 Tagen ausgelöst hätte, und warnt, wenn ein Kanal geflutet würde.
- **ntfy, Gotify und Mattermost**: neue Kanaltypen für Regel- und Team-Kanäle.
- **Versionen prüfen**: Eingetragene Versionen, die länger als die eingestellte Frist (Standard 90 Tage) nicht bestätigt wurden, sind als „Bitte prüfen“ markiert; bestätigen einzeln oder gesammelt, Erinnerung im Wochenrückblick.
- **Produkt vorschlagen**: Leser schlagen fehlende Produkte vor, Admins übernehmen, lehnen ab oder markieren als doppelt.
- **Passkeys**: Lokale Konten melden sich mit einem Passkey an – ohne Passwort und TOTP, nur über HTTPS mit Host-Namen.
- **Meine Sitzungen**: Unter Profil & Sicherheit die eigenen Sitzungen sehen und andere Geräte abmelden; Admins können das für jedes Konto.

### Sicherheit
- **Passwort-Reset entfernt Passkeys**: Ein Reset durch einen Admin und der Notfall-Reset über die Kommandozeile entfernen auch die Passkeys des Kontos.
- **Passkey-Prüfung streng begrenzt**: Nur gängige Schlüsseltypen, Benutzer-Verifikation Pflicht, Einmal-Challenges, Grenzen pro Adresse und pro IPv6-/48-Netz.
- **Keine Geheimnisse im Protokoll**: Passwörter, Schlüssel und Tokens erscheinen nur als „geändert“, ein Test schlägt an, wenn ein neues Feld nach Geheimnis aussieht und nicht geschwärzt wird.

### Betrieb
- **Migrationen 0017 bis 0020**: Protokoll, Zustellprotokoll, Versionsprüfung und Produktvorschläge, Passkeys und Sitzungsdaten.

## 0.1.39 – Sicherheitsprüfung

### Fixes
- **Feed-Inhalt konnte die App blockieren**: Ein präparierter Feed-Eintrag brachte die Erkennung „wird ausgenutzt“ auf über eine Minute Rechenzeit pro Abruf; jetzt Bruchteile einer Sekunde.
- **Anmelde-Flut auf ein gesperrtes Konto bremste alle**: Versuche auf ein gesperrtes Konto landeten in einem gemeinsamen Zähler, der mit jeder Anfrage teurer wurde; jetzt zählen sie nur an der Adresse, und jeder Zähler ist begrenzt.
- **Zu tief verschachtelte Anfragen**: Ein Text aus tausenden öffnenden Klammern führte vor der Anmeldung zu einem Serverfehler statt zu einer Ablehnung.
- **„Alle gelesen“ mit zu großer Zahl**: führt jetzt zu einer Ablehnung statt zu einem Serverfehler.
- **Nullbyte in der Adresse**: am internen http-Port eine Ablehnung statt eines Serverfehlers.
- **Fehlende Dateien wurden ein Jahr lang zwischengespeichert**: Der Proxy markiert nur noch gefundene Dateien als dauerhaft cachebar.

### Sicherheit
- **Proxy auf nginx 1.30**: Die bisherige Reihe 1.28 bekommt keine Sicherheitskorrekturen mehr; das Image ist auf einen festen Stand gepinnt.
- **E-Mail nur an genau eine Adresse**: Eine Adresse mit Komma (etwa aus dem Verzeichnis) konnte eine Mail zusätzlich an einen zweiten Empfänger schicken; jetzt wird so eine Adresse abgelehnt.
- **Leere Schlüsseldatei wird nicht mehr benutzt**: Ist `data/secret.key` leer oder abgeschnitten, startet die App nicht, statt Geheimnisse mit einem leeren Schlüssel zu verschlüsseln.
- **Sicherheits-Header auf jeder Antwort**: auch auf Ablehnungen (fehlendes CSRF-Token, falsches API-Token); neu sind Permissions-Policy und Cross-Origin-Opener-Policy.
- **TOTP-Codes in konstanter Zeit verglichen.**
- **Geheimnisse nicht in der Konfigurations-Darstellung**: SECRET_KEY und Passwörter in Verbindungs-Adressen erscheinen nie in einer Ausgabe der Konfiguration.
- **Entwicklungswerkzeuge aktualisiert**: vite und vitest ohne bekannte Schwachstellen (nur für den Build, nicht in der App).

### Betrieb
- **Test für alle Routen**: Jede der 160 Routen wird mit ihrer Absicherung geprüft – anonym abgewiesen, Leser von Admin-Routen ferngehalten.
- **Proxy neu starten**: Für nginx 1.30 einmal `docker compose up -d proxy`.

## 0.1.38 – Beobachtete CVEs als Merkliste

### Neu
- **Beobachtete CVEs als Merkliste**: Die Seite zeigt oben Kacheln (beobachtet, aktiv ausgenutzt, ohne Fix, neu seit dem letzten Besuch), darunter Filter, Sortierung und je CVE eine Zeile mit Schwere, KEV, EPSS und Fix-Version.
- **Verlauf je CVE**: Eine aufgeklappte Zeile zeigt, was seit dem Beobachten passiert ist – Fix, KEV, EPSS-Sprung, zurückgezogenes Advisory – und darunter „Meldungen“, „Advisory öffnen“ und „Nicht mehr beobachten“ mit Rückgängig.
- **Neu seit dem letzten Besuch**: CVEs, bei denen sich seit deinem letzten Besuch etwas getan hat, sind markiert.
- **Stern an mehr Stellen**: Auch auf Meldungskarten mit einer CVE und in den Befunden der Vendor-Übersicht; nach dem Merken führt „Zur Liste“ direkt zur Zeile.
- **Handbuch „Was ist neu“**: Eine Übersicht der Funktionen seit 0.1.26 mit Links, mit einem eigenen Teil für Admins.

### Verbessert
- **Erklärung im (?)**: „Wann kommt eine Meldung?“ steht jetzt in einem kleinen Fenster statt als langer Text auf der Seite, der Hinweis zu den Benachrichtigungswegen ist eine schmale Zeile.
- **Handbuch auf dem Stand von 0.1.37**: Fehlende Abschnitte ergänzt, neue FAQ-Einträge, die Liste der Aktionen mit erneuter Bestätigung vervollständigt.

### Fixes
- **„Mein Team“ richtig beschrieben**: Hinweis und Handbuch sagen jetzt, dass der Filter die Produkte zeigt, die deine Teams an dich leiten – nicht alle Produkte deiner Teams.
- **Verlauf nur ab dem eigenen Beobachten**: Die letzte Änderung einer CVE zählt nur, was nach deinem Beobachtungsbeginn geschah.

## 0.1.37 – API-Tokens, Metriken und Rücksicherungs-Test

### Neu
- **API-Tokens**: Admins legen benannte Tokens nur zum Lesen an, mit Ablaufdatum und Widerruf, und rufen damit News, Vendor News, Produkte und Befunde per `Authorization: Bearer` ab.
- **API-Referenz**: Unter Einstellungen → API & Metriken stehen alle Token-Endpunkte als OpenAPI zum Lesen und Herunterladen bereit.
- **Metriken für Prometheus**: `/metrics` zeigt die Gesundheit der Quellen, Warteschlangen, fehlgeschlagene Zustellungen, das Alter der letzten Sicherung und das Ergebnis des Rücksicherungs-Tests.
- **Rücksicherungs-Test**: Einmal pro Woche wird die neueste Sicherung wirklich in eine eigene Wegwerf-Datenbank zurückgespielt und geprüft, das Ergebnis steht unter Sicherung & Export.

### Fixes
- **Zwei Sicherungen in einer Sekunde**: Die neuere steht jetzt auch dann oben, wenn zwei Sicherungen in derselben Sekunde entstehen, sodass das Aufräumen nie die neuere löscht.

### Sicherheit
- **Tokens nur lesend und streng begrenzt**: Ein Token darf nur GET auf die freigegebenen Endpunkte, nie zusammen mit einem Anmelde-Cookie, und gilt nur, solange sein Admin aktiv ist.
- **Test-Datenbank ohne Zugriff auf echte Daten**: Die Rolle des Rücksicherungs-Tests kann die echte Datenbank nicht einmal öffnen, und die App prüft das vor jedem Lauf.
- **Falsche Tokens pro Netz gebremst**: Falsche API-Tokens und Kalender-Adressen zählen bei IPv6 pro /64-Netz, wie die Anmeldung.

### Betrieb
- **Neue Variable POSTGRES_RESTORE_PASSWORD**: `scripts/setup-env.sh` ergänzt sie, und db-init legt damit Rolle und Datenbank für den Rücksicherungs-Test an; ohne sie bleibt der Test aus.
- **Host-Skript für den Test**: `scripts/restore-test.sh` startet den Rücksicherungs-Test per Cron und gibt die Passphrase aus einer Datei über die Standardeingabe weiter.
- **Handbuch-Kapitel API & Metriken**: Es enthält Beispiele für curl, PowerShell und `prometheus.yml` sowie fertige Alarm-Regeln.

## 0.1.36 – Dringlichkeit, Weiterleiten, Ruhezeiten, Vertretung und Wochenrückblick

### Neu
- **Dringlichkeit als Zahl**: Jeder Befund in Vendor News bekommt eine Zahl von 0 bis 100 mit Stufe (Sofort, Bald, Beobachten), die aus Schwere, EPSS, KEV, eurer Version, Fix und Alter nachvollziehbar berechnet und beim Darüberfahren aufgeschlüsselt wird.
- **Nach Dringlichkeit sortieren und filtern**: Die Übersicht zeigt die Zahl auf jeder Karte, sortiert die Liste danach, filtert mit „Sofort“ und sortiert in der Schublade die dringendsten Befunde zuerst.
- **An mein Team weiterleiten**: Leser schicken eine Meldung oder einen Befund mit kurzem Kommentar an ihr Team, und zwar in den Kanal, den ein Admin für das Team festgelegt hat.
- **Weiterleitungs-Kanal im Team**: Admins wählen im Team unter „Allgemein“ einen der bestehenden Kanäle; ohne Kanal ist Weiterleiten für das Team aus.
- **Ruhezeiten**: Jede Person kann Ruhezeiten mit Zeitzone festlegen; normale Hersteller-News werden dann gesammelt und am Ende als eine Nachricht zugestellt.
- **Dringend trotz Ruhezeit**: Kritische Meldungen, CISA-KEV-Aufnahmen, jetzt betroffene eigene Versionen und beobachtete CVEs kommen auf Wunsch trotzdem sofort.
- **Gesammelt um eine Uhrzeit**: Pro Weg lässt sich wählen, ob Meldungen sofort oder einmal täglich zu einer festen Uhrzeit kommen.
- **Abwesenheit mit Vertretung**: Wer abwesend ist, kann eine Vertretung aus dem eigenen Team wählen, die in der Zeit die Hersteller-News der eigenen Produkte bekommt.
- **Wochenrückblick per E-Mail**: Admins können pro Team eine kurze wöchentliche E-Mail einschalten, die Mitglieder für sich selbst zuschalten.

### Verbessert
- **Hersteller-News meiner Produkte**: Die Seite ist in Unterreiter aufgeteilt (Wege & Inhalte, Ruhezeiten, Abwesenheit, Wochenrückblick) und bleibt dadurch übersichtlich.
- **Team-Mitglieder**: Die Mitgliederliste zeigt, wer abwesend ist und wer vertritt, und Admins können Abwesenheiten dort eintragen.

### Sicherheit
- **Weiterleiten ohne eigenes Ziel**: Leser können nie selbst eine Adresse oder einen Kanal angeben, der Kommentar bleibt in jedem Kanal reiner Text ohne aktive Links oder Erwähnungen, und pro Person gehen höchstens 10 Weiterleitungen pro Stunde raus.

## 0.1.35 – Beobachtete CVEs in der Seitenleiste

### Verbessert
- **Beobachtete CVEs als eigene Seite**: Die Liste steht jetzt als eigener Punkt in der Seitenleiste unter News und Vendor News statt versteckt in den Einstellungen; alte Links, auch aus verschickten Benachrichtigungen, führen dorthin.

### Fixes
- **Menü auf dem Handy**: Das Seitenleisten-Menü schließt sich jetzt, wenn man einen Eintrag antippt oder die Seite wechselt, statt die neue Seite zu verdecken.

## 0.1.34 – CVE beobachten, EOL-Vorwarnung und Kalender-Feed

### Neu
- **CVE beobachten**: Einzelnen CVEs per Stern oder unter Einstellungen → Benachrichtigungen folgen und per E-Mail, Desktop oder Teams hören, wenn ein Fix erscheint, die CVE in CISA KEV landet, ihr EPSS deutlich steigt oder ein Advisory zurückgezogen wird.
- **EOL-Vorwarnung**: Für jede eingetragene Version kommt 90 und 30 Tage vor dem Support-Ende und beim Ablauf je eine Meldung, über Regeln mit „Versionen & EOL“ und die persönlichen Wege.
- **Kalender-Feed (iCal)**: Das Support-Ende eurer Versionen lässt sich mit einer geheimen Adresse in Outlook & Co. abonnieren, mit Erinnerung 90 und 30 Tage vorher.

### Verbessert
- **Persönliche Wege ohne Team**: Wer eine CVE beobachtet, kann seine persönlichen Wege auch ohne Team einschalten.
- **Schnellere CVE-Suche**: Ein neuer Index findet die Advisories zu einer CVE, ohne alle Datensätze zu lesen.

### Sicherheit
- **Kalender-Adresse geschützt**: Die Adresse wird nur einmal angezeigt, nur als Hash gespeichert, ist widerrufbar, gilt nur für aktive Konten, ist begrenzt abrufbar und steht in keinem Protokoll.

## 0.1.33 – Advisory-Änderungen, dauerhaft sperren und Rolle sofort entziehen

### Neu
- **Advisory-Änderungen**: Ändert ein Hersteller ein Advisory nachträglich (neue Fix-Version, andere Schwere, größerer Bereich, KEV, zurückgezogen), zeigt Vendor News das als Revision mit einer kurzen Liste, was sich geändert hat.
- **Wirkung auf eure Versionen**: Ändert eine Revision die Bewertung einer eingetragenen Version, zum Beispiel von „nicht betroffen“ auf „betroffen“, steht das ganz oben und rot.
- **Reiter „Änderungen“**: Im Produkt stehen alle Revisionen seiner Advisories, neueste zuerst, und am Befund und auf der Kachel ein Hinweis „Geändert“ mit Datum.
- **Regelart „Advisory geändert“**: Regeln können Änderungen an Advisories an Mail, Teams, Slack, Discord und Telegram melden; bestehende Regeln bekommen sie nicht automatisch.
- **Advisory geändert auch persönlich**: Unter „Hersteller-News meiner Produkte“ lässt sich „Advisory geändert“ zuschalten; ab Werk ist es aus, der Schwere-Filter gilt auch dafür.
- **Dauerhaft sperren**: Admins können auch ein Konto dauerhaft sperren, das der Abgleich oder Teams schon ausgeschaltet hat, und die Sperre wieder aufheben – danach entscheidet wieder der Abgleich.
- **Klare Gründe in der Benutzerliste**: Die Markierung zeigt, ob ein Admin das Konto gesperrt hat oder ob es automatisch aus ist (z. B. „Kein Team mehr“, „Keine Rollen-Gruppe mehr“).

### Verbessert
- **Meldungen mit Details**: Unter einer Meldung steht jetzt, wie sich das Advisory dahinter verändert hat.

### Sicherheit
- **Rolle sofort entziehen**: Beim Entfernen einer Rollen-Zuordnung werden die Betroffenen sofort neu bewertet; wer seine Rolle verliert oder zum Leser wird, wird gleich abgemeldet statt erst beim nächsten Abgleich.
- **Anmeldeart ausschalten beendet Sitzungen**: Wer AD/LDAP oder Entra ID ausschaltet, beendet auf Wunsch (Standard: an) sofort alle Sitzungen dieser Konten; das eigene Konto kann sich dabei nicht aussperren.

## 0.1.32 – Große Teams, IPv6-Sperre pro Netz, HSTS und Vendor-Übersicht

### Verbessert
- **Persönliche Benachrichtigungen für große Teams**: Bei sehr vielen Empfängern verteilt Cobe News den Versand auf mehrere kurze Runden (höchstens 2000 Nachrichten und etwa 30 Sekunden je Runde), wer am längsten wartet, kommt zuerst dran.
- **Hintergrundrunde bleibt schnell**: Der Versand der persönlichen Benachrichtigungen prüft und schreibt jetzt viele Personen auf einmal und hält die Datenbank nur noch kurz fest, sodass News, Vendor News und Push nicht mehr minutenlang warten.
- **Vendor-Übersicht lädt einmal**: Mit „Mein Team“ lädt die Seite die Gesamtliste nicht mehr nur für die Zahl im Tab und zeigt sie beim Öffnen auch nicht mehr kurz an.

### Sicherheit
- **IPv6-Sperre pro Netz**: Fehlversuche von IPv6-Adressen zählen und sperren jetzt pro /64-Netz, damit ein Angreifer nicht einfach die Adresse wechseln kann.
- **HSTS nur für Hostnamen**: HSTS wird nicht mehr an localhost oder IP-Adressen gesendet, damit der Notzugang über http://localhost:8096 nicht dauerhaft auf https umgeleitet wird.

## 0.1.31 – Gruppen aus der Rollen-Zuordnung, Prüfung auf Fehler und Sicherheit

### Verbessert
- **Gruppen aus der Rollen-Zuordnung**: Beim Binden einer Gruppe an ein Team stehen die Gruppen aus *Benutzer & Rollen → Rollen-Zuordnung* schon oben zur Auswahl, mit ihrer Rolle daneben. Gruppen, die schon am Team hängen, fehlen dort.
- **Suche filtert mit**: Der Suchtext filtert auch diese Gruppen; die Treffer aus dem Verzeichnis stehen darunter, ohne Doppelte.
- **Teams-Liste erneut laden**: „Erneut laden“ lädt jetzt auch die Teams-Einstellungen nach, wenn sie nicht geladen werden konnten.

### Fixes
- **CSAF-Bereiche mit mehreren Intervallen**: Ein Versionsbereich mit mehreren Intervallen, Linien oder Versionen zählt jetzt ganz, vorher nur sein letzter Teil, sodass betroffene Versionen als „nicht betroffen“ galten.
- **CVE-Status „unknown“**: Eine Version, die der Hersteller mit unbekanntem Status nennt, gilt jetzt als „möglich“ statt als „nicht betroffen“.
- **Maven-Milestones**: Versionen wie 7.0.0-M1 gelten jetzt als Vorabversion vor 7.0.0, sodass OSV-Bereiche ab einem Milestone die Release-Version nicht mehr auslassen.
- **cvelist-Nachladen**: CVEs mit vorhandenem cvelist-Datensatz verdrängen ältere, noch ungefragte CVEs nicht mehr dauerhaft.
- **OSV-Advisory ohne Paketbereich**: Liefert OSV keinen Paketbereich mehr, entfällt der gespeicherte Advisory, statt mit alten Bereichen weiter zu entscheiden.
- **Teams während des Ladens ausgeschaltet**: Ein laufender Gruppen-Ladevorgang schaltet die gerade deaktivierten Konten nicht mehr wieder ein.
- **Team während des Ladens gelöscht**: Ein gelöschtes Team bricht den Ladevorgang der anderen Teams nicht mehr ab.
- **Mitgliederliste nach dem Laden**: Die Mitglieder eines Teams erscheinen jetzt sofort, wenn eine Gruppe fertig geladen ist.
- **Mitglieder-Seite hinter dem Ende**: Werden Mitglieder entfernt, springt die Liste auf die letzte vorhandene Seite statt leer zu bleiben.
- **Test-Knopf für Teams-Benachrichtigungen**: Der Test verwirft keine ungespeicherten Änderungen mehr, er wartet aufs Speichern.
- **Quelle entfernen**: Die Rückfrage nennt eine einzelne Nachricht jetzt in der Einzahl.

### Sicherheit
- **Adressen in Zahlenform**: Ziele wie `2852039166`, `0x7f000001`, `127.1` oder `localhost` werden jetzt auch mit Proxy als gesperrte Adresse erkannt, auch bei Weiterleitungen von Feeds.
- **Desktop-Auswahl begrenzt**: Jeder Quelleneintrag der Desktop-Benachrichtigungen darf höchstens 64 Zeichen lang sein.

## 0.1.30 – Wer bekommt was: Produkte pro Person und persönliche Benachrichtigungen

### Neu
- **Wer bekommt was**: Im Team legt ein Admin pro Produkt fest, ob alle Mitglieder seine Vendor News bekommen oder nur ausgewählte Personen – etwa „Anna und Ben bekommen Palo Alto, Anna und Cem bekommen Cisco“.
- **Auswahl aus dem Team**: Ausgewählte Personen stehen als Chips am Produkt und kommen über eine Suche in den Mitgliedern dazu. Wählbar sind nur Mitglieder; ist niemand gewählt, warnt die Seite.
- **Unter Mitglieder sichtbar**: Bei jeder Person im Team steht, welche Produkte sie bekommt.
- **Hersteller-News meiner Produkte**: Unter *Einstellungen → Benachrichtigungen* lässt sich jede Person die Vendor News ihrer Produkte selbst schicken – per E-Mail an die eigene Adresse, als Desktop-Push an die eigenen Browser oder in Microsoft Teams.
- **Eigener Teams-Webhook**: Für Microsoft Teams legt die Person in Teams einen Workflows-Webhook an, fügt die URL ein und schickt eine Testkarte.
- **Filter pro Person**: Schwachstellen und/oder Versionen & EOL, Schwachstellen ab einer Schwere – mit denselben Stufen wie bei den Regeln.
- **Zustand pro Weg**: Unter jedem Weg steht, wann zuletzt etwas zugestellt wurde, oder der letzte Fehler mit dem nächsten Versuch.
- **Freigabe durch den Admin**: Unter *Einstellungen → Teams → Einstellungen* gibt ein Admin E-Mail, Desktop und Microsoft Teams einzeln frei. Jeder Weg ist standardmäßig aus.

### Verbessert
- **Nur Neues, genau einmal**: Persönliche Benachrichtigungen bringen nur, was nach dem Einschalten und nach der Zuteilung des Produkts dazukommt, nie die erste Prüfung eines Produkts. Jede Meldung kommt pro Weg höchstens einmal, auch nach einem Neustart.
- **Gesammelt statt einzeln**: Mehrere Meldungen einer Runde kommen als eine Mail, eine Teams-Karte oder ein Push; höchstens 100 pro Person und Runde.
- **Wiederholung wie bei Kanälen**: Lehnt der Empfänger ab, versucht Cobe News es mit wachsender Pause erneut; nach einem Fehler, bei dem die Nachricht angekommen sein könnte, nicht.
- **Austritt räumt auf**: Wer ein Team verlässt, verliert dort auch seine Produkt-Auswahl.

### Sicherheit
- **Nur Microsoft-Adressen**: Ein persönlicher Teams-Webhook muss https auf `*.logic.azure.com`, `*.powerplatform.com` oder `*.webhook.office.com` sein und eine öffentliche Adresse haben; `WEBHOOK_PRIVATE_NETS` gilt dafür nie.
- **URL verschlüsselt**: Die Webhook-URL wird verschlüsselt gespeichert und nie zurückgegeben – die Seite zeigt nur den Host.
- **Nur die eigenen Einstellungen**: Jede Person ändert nur ihre eigenen Benachrichtigungen; wer was bekommt, legen nur Admins fest.

### Betrieb
- **Datenbank**: Die Migration 0008 legt nur neue Tabellen an und ist auf jeder Datenbankgröße sofort fertig. Sicherung und Wiederherstellung nehmen sie mit.

## 0.1.29 – Konten nach dem Team-Austritt deaktiviert

### Verbessert
- **Kein Team mehr, kein aktives Konto**: Wer über ein Team geladen wurde, sich nie angemeldet hat und in keiner Team-Gruppe mehr ist, wird automatisch deaktiviert. Unter *Benutzer* steht dann „Kein Team mehr“.
- **Teams ausschalten deaktiviert geladene Konten**: Schaltet ein Admin Teams aus, werden geladene Konten, die sich nie angemeldet haben, sofort deaktiviert („Teams ausgeschaltet“).
- **Wieder dabei, wieder aktiv**: Kommt die Person zurück in eine Team-Gruppe oder wird Teams wieder eingeschaltet, ist das Konto nach dem nächsten Laden wieder aktiv. Eine Sperre durch einen Admin bleibt bestehen.
- **Keine Begrüßung nach dem Austritt**: Ist ein Konto deaktiviert, bevor die Begrüßungs-E-Mail verschickt wurde, geht sie nicht mehr raus.

## 0.1.28 – Teams

### Neu
- **Teams**: Unter *Einstellungen → Teams* fasst ihr Personen zu Teams zusammen. Teams ist standardmäßig aus – solange es aus ist, ändert sich für niemanden etwas.
- **Gruppen binden**: Ein Team hängt an einer oder mehreren Gruppen aus AD/LDAP oder Entra ID. Binden und Lösen einer Gruppe und das Ein- und Ausschalten von Teams verlangen eine erneute Bestätigung.
- **Mitglieder sofort da**: Beim Binden werden die Mitglieder der Gruppe sofort geladen, auch die aus verschachtelten Gruppen. Der stündliche Abgleich hält sie aktuell; wer aus der Gruppe fällt, verlässt das Team.
- **Unter Benutzer sichtbar**: Geladene Personen stehen gleich in der Benutzerliste, als „Noch nie angemeldet“, bis sie sich zum ersten Mal anmelden. Dort steht auch, in welchen Teams jemand ist.
- **Leser über ein Team**: Eine Team-Gruppe gibt die Rolle Leser. Ist jemand auch in einer Admin-Gruppe, bleibt er Admin.
- **Sperren bleibt**: Ein Konto, das ein Admin ausschaltet – auch eines, das sich nie angemeldet hat –, schaltet weder das Laden noch der Abgleich wieder ein.
- **Lokale Konten im Team**: Lokale Konten fügt ein Admin von Hand zu einem Team hinzu.
- **Produkte je Team**: Gefolgte Produkte lassen sich einem oder mehreren Teams zuordnen.
- **Regeln für ein Team**: Eine Benachrichtigungsregel lässt sich auf die Produkte von Teams beschränken. Ein neu zugeordnetes Produkt meldet sie ab dann, nicht seine älteren Ereignisse.
- **„Mein Team / Alle“ in Vendor News**: Wer in einem Team ist, sieht in der Übersicht wahlweise nur die Produkte seiner Teams. Die Wahl merkt sich der Browser pro Person.
- **Willkommens-Mail**: Auf Wunsch (standardmäßig aus) bekommt jede neu geladene Person genau eine E-Mail mit der Adresse von Cobe News, nie ein Passwort. Wer keine E-Mail-Adresse hat, wird übersprungen und in der Benutzerliste markiert.

### Betrieb
- **Entra-Berechtigungen**: Für Entra-Gruppen braucht Teams `GroupMember.Read.All` und `User.Read.All` als Anwendungsberechtigungen – dieselben wie für den stündlichen Abgleich, keine neue. Fehlt eine, sagt die Gruppe welche.
- **Große Gruppen**: Mitglieder werden seitenweise gelesen und in Paketen von 500 geschrieben; auch 5000 Mitglieder halten weder Datenbank noch Server lange auf.
- **Datenbank**: Die Migration 0007 legt nur neue Tabellen an und ist auf jeder Datenbankgröße sofort fertig.

## 0.1.27 – Cisco-Hinweise auch für Duo und Splunk

### Verbessert
- **Cisco-Hinweise auch für Duo und Splunk**: Die CSAF-Hinweise von Cisco bewerten jetzt auch die Produkte „Cisco Duo“ und Splunk – egal, ob Cisco sie im Hinweis unter Cisco oder unter Splunk führt. Folgt ihr nur einem Duo- oder Splunk-Produkt, liest Cobe News die Cisco-Hinweise ebenfalls.

## 0.1.26 – Weitere Quellen, Dokumentation und sichere Webhook-Ziele

### Neu
- **Hinweise direkt von Siemens, Cisco und Schneider Electric**: Folgt ihr einem Produkt dieser Hersteller, liest Cobe News deren CSAF-Hinweise selbst – nicht mehr nur die, auf die eine Meldung zeigt. Gefunden wird der Anbieter über die Liste des BSI oder die Standard-Adresse des Herstellers.
- **Nur öffentliche Hinweise**: Gelesen werden nur Hinweise mit TLP:CLEAR bzw. TLP:WHITE; die Prüfsumme jedes Dokuments wird verglichen, wo der Hersteller eine anbietet.
- **Neue CVEs schneller**: Dreimal am Tag und einmal nach Tageswechsel kommen die geänderten Einträge der offiziellen CVE-Liste (cvelistV5) – nur die Änderungsdatei, nie die ganze Liste. Damit stehen neue Lücken eurer Produkte da, bevor die NVD sie analysiert hat.
- **Betroffene Versionen, wo die NVD noch nichts sagt**: Für Befunde und Meldungen, deren CVE die NVD noch nicht analysiert hat, holt Cobe News den CVE-Eintrag einzeln und nutzt die Angaben des Herstellers und die Einstufung der CISA (CVSS, SSVC, KEV).
- **EPSS**: Bei Befunden und in der Meldung steht, wie wahrscheinlich eine Lücke in den nächsten 30 Tagen ausgenutzt wird. Die Schublade eines Produkts kann die Befunde danach sortieren.
- **Fix-Versionen aus OSV**: Für Open-Source-Produkte wie Tomcat, Jenkins, Django oder Kubernetes ergänzt OSV die betroffenen und behobenen Versionen und klärt manches „möglicherweise betroffen“.
- **Unter-Reiter „Weitere Quellen“**: In *Integrationen → Vendor News* lässt sich jede dieser Quellen einzeln abschalten. Dort steht auch, was dabei nach außen geht – nur öffentliche Adressen bzw. CVE-Nummern.
- **Gesundheit**: Die neuen Quellen stehen unter *Integrationen → Gesundheit* als eigene Art „Weitere Quelle“, jeder CSAF-Anbieter mit eigener Zeile in der Schublade.
- **Dokumentation**: Im Benutzermenü steht jetzt „Dokumentation“ – ein Handbuch auf Deutsch und Englisch zu allen Bereichen, von den News bis zur Sicherung.
- **„Hilfe“-Links**: Die Einstellungen verweisen an den passenden Stellen direkt auf den Abschnitt im Handbuch.
- **Erklärungen**: EPSS, CSAF, TLP, SSVC und OSV haben einen Tooltip.
- **Mehr Fachbegriffe im Handbuch**: PKCE, UPN, Bedingter Zugriff, Gruppen-Überlauf, Release-Linie, Hauptschlüssel, SSRF, SAN und PFX werden beim Darüberfahren erklärt.

### Verbessert
- **Keine doppelten Hinweise**: Kommt derselbe Hinweis aus einer Meldung und vom Hersteller, steht er nur einmal da und wird nur einmal gemeldet.
- **Kein Schwall beim Update**: Was ein Hersteller beim ersten Abruf mitbringt und älter als 7 Tage ist, steht auf der Seite, wird aber nicht verschickt. Jüngere Hinweise werden wie immer gemeldet.
- **Cisco ASA und FTD**: Hinweise mit den neuen Produktnamen „Cisco Secure Firewall …“ werden erkannt.
- **Abgeschaltete Quelle zählt nicht mehr**: Schaltet ihr eine der weiteren Quellen ab, fließen ihre gespeicherten Einträge nicht mehr in die Bewertung ein. Wieder eingeschaltet, zählen sie sofort wieder.
- **Ein hängender Hinweis hält nichts auf**: Antwortet ein einzelnes Dokument eines Herstellers gerade nicht, versucht Cobe News es später erneut und liest die übrigen trotzdem.
- **Keine CVE-Änderungen verloren**: Fehlt die Tagesdatei der CVE-Liste kurz nach Mitternacht noch, wartet Cobe News bis zum Morgen auf sie, statt die letzte Stunde des Tages auszulassen.
- **Eine kaputte Tagesdatei blockiert nicht**: Ist eine Datei der CVE-Liste zu groß oder beschädigt, wird nur sie übersprungen; die übrigen kommen weiter.
- **Neue Webhooks ohne Proxy**: „Über den Proxy“ ist bei neuen Webhooks aus – im Formular wie über die API. Bestehende Kanäle behalten ihre Einstellung.
- **Header-Name wie auf dem Server geprüft**: Das Formular lehnt dieselben Header-Namen ab wie der Server und sagt, welche Zeichen erlaubt sind.
- **Abgelaufenes Entra-Clientgeheimnis**: Lehnt Microsoft das Geheimnis ab, sagt Cobe News das jetzt – und dass ein lokaler Administrator oder das Notfallkonto das neue eintragen muss.
- **Hinweise in den Einstellungen stimmen**: Wo man das eigene Konto findet, wo die Rollen-Zuordnung steht und was der Export enthält, ist jetzt richtig beschrieben.
- **Verweise aufs Handbuch**: Wo Texte bisher auf die README verwiesen (cron-Sicherung, Katalog-Korrektur), führt jetzt ein Link zum Abschnitt im Handbuch.

### Fixes
- **Bestätigung mit Passwort und Code immer obenauf**: Die Abfrage liegt jetzt immer über einer offenen Schublade oder einem Dialog und ist sofort bedienbar.
- **„Verbindung testen“ meldet sich**: Bei AD/LDAP und Entra ID zeigt der Test sein Ergebnis jetzt als Meldung an.
- **Fehlgeschlagene CVE-Abfrage nicht für eine Woche gemerkt**: War GitHub kurz nicht erreichbar, fragt Cobe News den CVE-Eintrag in der nächsten Runde erneut.
- **Zurückgezogene OSV-Einträge**: Einträge, die OSV zurückgezogen hat, werden nicht mehr verwendet.
- **Merkwürdige Zeitstempel**: Ein Hinweis mit einem Datum weit in der Zukunft hält das Lesen eines Herstellers nicht mehr an.
- **Beschädigte Einträge sind ein Lesefehler**: Ein kaputter Eintrag in einer CVE-Datei oder einer Liste eines Herstellers wird übersprungen, statt die ganze Runde scheitern zu lassen.

### Sicherheit
- **Hersteller sprechen nur für die eigenen Produkte**: Ein CSAF-Hinweis von Siemens, Cisco oder Schneider Electric bewertet nur Produkte dieses Herstellers – nie die eines anderen.
- **Kein Hinweis überschreibt einen fremden**: Ein Hersteller kann keinen Hinweis eines anderen Herstellers oder des BSI ersetzen; Dokumente, die nicht vom Hersteller selbst stammen, werden abgelehnt.
- **Prüfsumme wird nicht übersprungen**: Nennt ein Hersteller eine Prüfsumme, die gerade nicht abrufbar ist, wird das Dokument erst übernommen, wenn sie geprüft ist.
- **Umleitungen und Links bleiben beim Hersteller**: Weiterleitungen auf fremde Adressen werden nicht befolgt, und der Link zum Hinweis zeigt nur auf eine Adresse des Herstellers.
- **Große CVE-Dateien sprengen den Speicher nicht**: Cobe News behält beim Lesen nur, was eure Produkte betrifft, und prüft die Größe einer Datei, bevor es sie öffnet.
- **Sichere Webhook- und SMTP-Ziele**: Loopback (127.0.0.1), Link-Local mit der Metadaten-Adresse von Cloud-Anbietern (169.254.169.254), „jede Adresse“ (0.0.0.0) und Multicast sind jetzt immer gesperrt – auch wenn sie in `WEBHOOK_PRIVATE_NETS` oder `SMTP_ALLOW_INTERNAL` stehen. Private Adressen, das eigene Docker-Netz und der Docker-Host lassen sich dort weiter freigeben.
- **Handbuch nach Rolle**: Die Kapitel für Administratoren sieht nur, wer Administrator ist.
- **Handbuch ohne HTML**: Die Texte werden von einem eigenen, strengen Markdown-Leser dargestellt – HTML darin wird nie ausgeführt.

### Betrieb
- **Neue ausgehende Hosts**: `wid.cert-bund.de`, `cert-portal.siemens.com`, `www.cisco.com` und `www.se.com` (nur mit gefolgtem Produkt des Herstellers), `api.github.com`, `github.com` und `raw.githubusercontent.com` (CVE-Liste), `api.first.org` (EPSS) und `api.osv.dev` (OSV).
- **Wenig Datenverkehr für die CVE-Liste**: Etwa 10 MB am Tag statt rund 50 MB, eine Änderung kommt spätestens nach etwa 7,5 Stunden an.
- **Datenbank**: Eine neue Tabelle für EPSS; das Update legt sie von selbst an. Alte Einträge einzelner CVE-Abfragen werden nach 30 Tagen aufgeräumt.
- **Handbuch im Repository**: Die Texte liegen in `docs/handbuch` und werden im Image unter `/srv/handbuch` mitgeliefert.
- **`SQLITE_IMPORT` wirkt**: `docker-compose.yml` reicht die Einstellung jetzt an die App weiter.
- **Beispiel für `CA_FILE` korrigiert**: Die Datei liegt unter `./data/ca.pem`, eingetragen wird `/data/ca.pem`.
- **Beispiel für `TRUSTED_PROXIES` korrigiert**: Für einen eigenen Proxy auf dem Host ist es das Gateway des Netzes `edge` (`172.31.250.1`), nicht `172.17.0.1`.
- **HSTS richtig beschrieben**: Die README sagt jetzt, dass HSTS auch mit `TLS_MODE=external` gesendet wird.

## 0.1.25 – Richtiger Hinweis zu internen Webhook-Zielen

### Fixes
- **Hinweis im Webhook-Kanal korrigiert**: Der Kasten „So richtest du ihn ein“ sagte noch, interne Ziele im Firmennetz seien erlaubt. Seit 0.1.22 gehen interne Adressen nur, wenn sie in `WEBHOOK_PRIVATE_NETS` in der `.env` stehen – das steht jetzt dort.
- **Fehlermeldung beim Speichern eines Kanals vollständig**: Ist das Ziel gesperrt, nennt die Meldung jetzt auch den Docker-Host und dass private Adressen über `WEBHOOK_PRIVATE_NETS` freigegeben werden.

## 0.1.24 – Sicherung im Hintergrund, stärkere Passphrase, gehärteter Datenbank-Container

### Verbessert
- **„Jetzt sichern“ läuft im Hintergrund**: Die Seite zeigt „Sichert …“ und seit wann, fragt nach, bis die Sicherung fertig ist, und meldet dann das Ergebnis. Bisher kam bei großen Datenbanken „Fehler: http_504“, obwohl die Sicherung weiterlief.
- **Laufende Sicherung sichtbar**: Läuft gerade eine Sicherung per Befehl oder cron, zeigt die Seite das ebenfalls an.
- **Fehler der Sicherung auf Deutsch und Englisch**: Eine gescheiterte Sicherung nennt den Grund in der eingestellten Sprache, die technische Meldung steht klein darunter.
- **Befehl zum Wiederherstellen einer verschlüsselten Sicherung**: Für eine `.tar.enc` fragt der angezeigte Befehl die Passphrase ab, ohne sie anzuzeigen.

### Fixes
- **Abgelehnte zweite Sicherung ist kein Fehlschlag**: Wurde „Jetzt sichern“ abgelehnt, weil schon eine Sicherung lief, stand die Sicherung als „Fehlgeschlagen“ da.
- **„Letzte Sicherung“ nach einer Wiederherstellung**: Sie zeigt jetzt die Sicherung, die direkt vor der Wiederherstellung angelegt wurde, nicht mehr den alten Stand aus der eingespielten Datei.

### Sicherheit
- **Weniger Sicherungen aufbewahren und Export nur nach erneuter Bestätigung**: Beides braucht jetzt die Bestätigung mit Passwort und Code wie die Benutzerverwaltung.
- **Stärkere Ableitung des Schlüssels aus der Passphrase**: Neue verschlüsselte Sicherungen nutzen einen deutlich aufwendigeren Schlüssel. Ältere Sicherungen lassen sich weiter öffnen. Eine Passphrase muss mindestens 12 Zeichen haben.
- **Feste Basis-Images**: Die verwendeten Images sind mit ihrem Digest festgeschrieben.
- **Gehärteter Datenbank-Container**: Er läuft schreibgeschützt und ohne zusätzliche Rechte.

### Entfernt
- **Einstellung `ADMIN_PASSWORD`**: Sie wurde gelesen, aber nie verwendet.

### Betrieb
- **Datenbank-Container startet beim Update neu**: Wegen der Härtung wird er einmal neu erstellt; die Daten bleiben im Volume.

## 0.1.23 – Viele Fehler behoben: Vendor News, Benachrichtigungen, News und Bedienung

### Verbessert
- **Vendor News: Folgen geht schneller**: Beim Folgen eines Produkts liest Cobe News nur noch die Hinweise, die es betreffen können (bei 60 000 NVD-Einträgen 0,1–0,2 s statt rund 1 s).
- **Passende News**: Meldungen mit einer CVE des Produkts erscheinen immer, auch wenn viele Meldungen den Namen nur als Wortteil enthalten („Git“ in „Digital“). Namen zählen nur noch als ganzes Wort.
- **Zielversion**: Die empfohlene Version wird gegen alle bekannten Lücken des Produkts geprüft. Ist sie selbst betroffen, nimmt Cobe News eine spätere Version derselben Linie oder sagt es dazu.
- **Katalog-Pflege**: Die höchstens 20 NVD-Anfragen pro Stunde verteilen sich über die Stunde und zählen auch über einen Neustart hinweg.
- **Beispielversionen**: Kein Beispiel im Katalog gilt mehr als „ungenau“. Echte Builds für Veeam Backup for Microsoft Azure, for Google Cloud und das Management Pack, mit Hinweis auf den Appliance-Build.
- **„Schwere“-Filter mit der Tastatur**: In der Auswahl der Schweregrade auf der News-Seite wandern die Pfeiltasten durch die Liste, Enter oder Leertaste wählen, Escape schließt sie wieder.
- **Umzug von SQLite von Hand**: `migrate-sqlite` klappt jetzt auch, wenn die App schon einmal gestartet ist. Was der Start von selbst anlegt (eingebaute Quellen, offenes Setup), macht den Daten der Datei Platz.
- **Benutzer & Rollen auf dem Handy**: Name, Mail und letzte Anmeldung stehen vollständig da, Rolle, Aktiv-Schalter und Menü in einer eigenen Zeile.

### Fixes
- **Eine Quelle je Adresse**: Wird dieselbe Feed-Adresse gleichzeitig mehrfach hinzugefügt, entsteht nur noch eine Quelle; die anderen Versuche bekommen „gibt es schon“. Schon doppelt angelegte Quellen werden beim Update zusammengeführt, mit ihren Meldungen, Regeln und Desktop-Einstellungen.
- **„Alle als gelesen“ nur für das Angezeigte**: Eine Meldung, die nach dem Laden der Liste eintrifft, bleibt neu, statt ungesehen mit als gelesen markiert zu werden.
- **Ungültige Zeitangaben in Anfragen**: Ein Blätter-Zeiger oder Zeitpunkt weit außerhalb des Kalenders gibt jetzt eine klare Ablehnung statt eines Serverfehlers.
- **Umzug von SQLite mit Steuerzeichen**: Werte mit Zeichen, die PostgreSQL nicht speichern kann, werden ohne diese Zeichen übernommen; die Ausgabe nennt, wie viele es je Tabelle waren.
- **Vendor News: Änderung während der Auswertung**: Eine Version, die während einer Runde korrigiert wird, bleibt ein stiller Ausgangspunkt (bisher kamen alle ihre Lücken als Benachrichtigung). Eine gelöschte Version beendet die Runde nicht mehr.
- **Fortinet-Hinweise nicht mehr verloren**: Brach ein Abruf mittendrin ab oder wurde die Obergrenze erreicht, wurden die restlichen Hinweise erst nach einer Änderung des Feeds geholt. Jetzt kommen sie beim nächsten Lauf.
- **NVD-Änderungen an älteren CVEs**: Bei Produkten mit sehr vielen CVEs gingen Änderungen an älteren Einträgen beim wöchentlichen Komplettabruf verloren.
- **„Update verfügbar“ bei SQL Server und Co.**: Auch wenn die neueste Version einen Zusatz trägt (z. B. „CU27+GDR“), wird ein Update erkannt.
- **Hinweis „betrifft deine Systeme“** an einer Meldung bewertet kurze Versionen wie „7.4“ wie Vendor News.
- **„Quellen mit Fehlern“** zählt keine Fehler von Produkten mehr, denen nicht mehr gefolgt wird.
- **Eigenes Produkt**: Wird ein eigenes Produkt während einer Abrufrunde hinzugefügt, behält es seine gefundenen Hinweise.
- **Hinweise ohne CVE** können jetzt auch als „jetzt aktiv ausgenutzt“ gemeldet werden.
- **Versionskarte**: Neben „1 betrifft diese Version“ steht nicht mehr das grüne „Aktuell“, sondern „Neuester Stand der Linie“ mit Erklärung.
- **Web Push: kein doppelter Push mehr**: Meldete sich ein Browser während einer Runde ab, bekamen alle anderen Browser dieselben Meldungen in der nächsten Runde noch einmal. Jetzt wird jeder Browser für sich gespeichert.
- **Zwei Tabs, ein Browser**: Schalten zwei Tabs gleichzeitig Desktop-Benachrichtigungen ein, gibt es keinen Fehler 500 mehr.
- **Kanal repariert, während eine Runde läuft**: Speichert ein Admin eine neue Adresse, während die Runde noch an die alte sendet, überschreibt deren Fehler die Korrektur nicht mehr (keine lange Pause, kein alter Fehler).
- **Zeilenumbruch im Namen**: Regel- und Kanalnamen dürfen keine Zeilenumbrüche mehr enthalten. Ein Umbruch aus einem Produkt- oder Versionsnamen wird im Betreff zum Leerzeichen. Bisher scheiterte jede Mail des Kanals und wurde endlos wiederholt.
- **Fremde Sperre blockiert nicht mehr den Besitzer**: Hat jemand anderes ein Konto durch Fehlversuche gesperrt, kann die angemeldete Person ihr Passwort und TOTP trotzdem ändern.
- **Regel-Schalter**: Ein zweiter Klick, bevor der erste gespeichert ist, meldet nicht mehr fälschlich „Inzwischen von jemand anderem geändert“.
- **„Aktuellen Stand laden“** baut Regel und Kanal jetzt aus dem wirklich neuen Stand – vorher wurde danach erneut abgelehnt.
- **E-Mail-Server**: Hat ein anderer Admin den Server inzwischen gespeichert, zeigt die Schublade den Hinweis mit „Aktuellen Stand laden“ (wie bei Kanälen und Regeln), statt jedes weitere Speichern abzulehnen.
- **Web Push: verständliche Fehler** statt Codes wie `push_failed` oder `invalid_keys`, mit Grund.
- **Barrierefreiheit**: nur noch ein Hauptbereich (`main`) je Seite.

### Sicherheit
- **AD-Sperre vor der Anmeldung am DC**: Ein in Cobe News gesperrtes AD-Konto wird nicht mehr am Domänencontroller geprüft, egal in welcher Schreibweise der Name eingegeben wird.
- **Admin-Konten ein- oder ausschalten und deren E-Mail ändern** braucht jetzt die erneute Bestätigung (wie die Rolle).
- **Klick auf eine Benachrichtigung** öffnet nur Seiten von Cobe News, auch bei ungewöhnlich geschriebenen Pfaden.
- **Robustere Auswertung von Herstellerdaten**: Unerwartet aufgebaute Einträge legen keine Quelle mehr lahm.
- **NVD-API-Schlüssel** wird nie an eine Weiterleitung mitgeschickt.
- **Daten von endoflife.date** werden strenger geprüft, und der dort genannte Befehl zur Versionsanzeige ist als solcher gekennzeichnet.
- **Zwischenspeicher der „Passenden News“** lässt sich nicht mehr gezielt leeren.
- **Abgeschnittene komprimierte Antworten**: Eine unvollständig übertragene gzip- oder deflate-Antwort wird abgelehnt, statt als ganze Antwort zu gelten.

### Betrieb
- **Datenbank-Migration 0005**: Führt doppelte Quellen mit derselben Adresse zusammen und legt einen eindeutigen Index auf die Adresse der selbst hinzugefügten Quellen an.
- **Katalogversion 2026.10.29-4**, mit dem neuen optionalen Katalogfeld `depth` (README „Katalog pflegen“).

## 0.1.22 – Sicherheit: eigene Datenbankrolle, signierte Sicherungen, keine Ziele auf dem Docker-Host

### Fixes
- **Keine liegengebliebenen Klartext-Dateien bei den Sicherungen**: Wurde eine Sicherung oder Wiederherstellung abgebrochen, blieben Dump und Schlüssel unverschlüsselt in `data/backups/` liegen – und wurden mit den Sicherungen kopiert. Arbeitsdateien liegen jetzt daneben in `data/.backup-work/` und werden beim nächsten Lauf oder Start weggeräumt.
- **Wiederherstellung löscht nicht mehr die eigene Sicherung**: Die Sicherung vor einer Wiederherstellung konnte die älteste aufbewahrte Sicherung löschen – genau die, die gerade eingespielt wurde. Sie zählt jetzt nicht zur Aufbewahrung und bleibt 30 Tage.
- **Sicherung vor der Wiederherstellung mit derselben Passphrase**: Sie nutzt jetzt auch eine mit `--passphrase-file` angegebene Passphrase und ist damit verschlüsselt.

### Sicherheit
- **Eigene Datenbankrolle ohne Superuser-Rechte**: Die App arbeitet jetzt als `cobe_news_app`. Diese Rolle besitzt die Datenbank, kann aber keine Programme auf dem Datenbankserver starten und keine seiner Dateien lesen.
- **Sicherungen werden auf Echtheit geprüft**: Unverschlüsselte Sicherungen sind jetzt mit dem Schlüssel der Installation signiert. Eine Wiederherstellung lehnt eine veränderte Sicherung immer ab, eine unsignierte oder fremde nur mit `--allow-unsigned`.
- **Wiederherstellung nimmt nur, was Cobe News selbst anlegt**: Funktionen, Trigger, andere Schemas oder ein verändertes Schema in einer Sicherung führen zum Abbruch. Dabei wird nichts geändert.
- **Sicherungsdateien werden strenger gelesen**: Nur die erwarteten Dateien, jede einmal und in vernünftiger Größe.
- **Keine Ziele auf dem Docker-Host**: Webhooks, SMTP-Server, AD-Server und Feeds erreichen das Gateway des Containers, das Host-Netz von Docker Desktop und Namen wie `host.docker.internal` nicht mehr.
- **Kanäle ins Firmennetz nur nach Freigabe**: Benachrichtigungskanäle gehen ab Werk nur an öffentliche Adressen. Interne Ziele (z. B. n8n) gehen nur, wenn ihre Adresse oder ihr Netz in `WEBHOOK_PRIVATE_NETS` steht.
- **Weitere versteckte interne Adressen** in IPv6-Schreibweisen werden erkannt und abgelehnt.
- **Testmail und AD-Test** zeigen bei Fehlern nur noch die Art des Fehlers, keine Antworten des Servers.
- **Steuerzeichen aus Quellen und Eingaben**: Nicht darstellbare Steuerzeichen werden beim Einlesen entfernt, Anfragen mit einem Null-Zeichen werden abgelehnt. Bisher konnte ein einziger solcher Eintrag die Meldungen einer Quelle oder eines Herstellers unbemerkt blockieren.
- **Ein abgelehnter Eintrag kostet nur sich selbst**: News und Vendor News speichern jeden Eintrag für sich. Scheitert das Speichern, zeigt die Quelle den Fehler, statt gesund auszusehen.
- **Artikeltext ohne Rechenfalle**: Extrem tief verschachteltes HTML kostet keine Minuten Rechenzeit mehr. Solcher Text erscheint als einfacher Text, und das Bereinigen endet nie mitten in einem Tag.
- **Keine Werte im Fehlerprotokoll**: Scheitert eine Datenbankanweisung, stehen ihre Werte (z. B. Passwort-Hashes, E-Mail-Adressen) nicht mehr im Log.

### Betrieb
- **Vor dem Update einmal `scripts/setup-env.sh`**: Es ergänzt das Passwort `POSTGRES_APP_PASSWORD` für die neue Rolle in der `.env`. Ohne dieses Passwort startet `docker compose` nicht.
- **Neuer kurzer Dienst `db-init`**: Er läuft bei jedem Start vor der App, legt die Rolle an und überträgt ihr die Datenbank (README: PostgreSQL – Rollen, mit dem Weg zurück).
- **Neue Einstellung `WEBHOOK_PRIVATE_NETS`**: Wer Webhooks an interne Adressen schickt (z. B. n8n im LAN), trägt deren Adresse oder Netz vor dem Update in die `.env` ein (README: Benachrichtigungen → Ziele).
- **Sicherungen kopieren ohne Halbfertiges**: Der rsync-Befehl im README schließt jetzt Arbeits- und halbfertige Dateien aus.
- **Wiederherstellung auf einem neuen Server** ist im README Schritt für Schritt beschrieben.

## 0.1.21 – Wiederherstellung auch großer Datenbanken und auf einem neuen Server

### Fixes
- **Wiederherstellung großer Datenbanken**: Die Sicherung wird jetzt Stück für Stück eingespielt, statt sie ganz in den Speicher zu laden. Bisher brach die Wiederherstellung einer großen Datenbank im App-Container (512 MB) ab.
- **Wiederherstellung auf einem neuen Server**: In eine leere, frische Datenbank (App nie gestartet) lässt sich eine Sicherung jetzt direkt einspielen. Bisher brach der Befehl mit einer Fehlermeldung über eine fehlende Tabelle ab.
- **Wiederherstellung ganz oder gar nicht**: Die Zeilen je Tabelle werden noch vor dem Abschluss mit der Sicherung verglichen. Stimmen sie nicht, bleibt die Datenbank, wie sie war.
- **Vendor News: keine doppelten Benachrichtigungen nach Aus- und wieder Einschalten**: Wer einem Produkt nicht mehr folgt und es später wieder einschaltet, bekam bereits gemeldete Schwachstellen ein zweites Mal. Jetzt gilt nach dem Einschalten der aktuelle Stand als Ausgangspunkt, für alle eingetragenen Versionen.
- **Eigenes Passwort ändern verlängert die Sitzung nicht mehr**: Die Gesamtdauer einer Sitzung beginnt nach einer Passwortänderung nicht mehr von vorn.

### Sicherheit
- **Erneute Bestätigung nur mit zweitem Faktor**: Das Ändern des eigenen Passworts zählte bisher als frische Bestätigung für heikle Admin-Aktionen, ohne dass der TOTP-Code abgefragt wurde. Jetzt braucht die Bestätigung wieder den TOTP-Code.

## 0.1.20 – Katalog-Pflege: kein Fehlalarm bei veralteter CPE mit Nachfolger

### Fixes
- **Veraltete CPE mit Nachfolger**: Führt ein Produkt eine von der NVD als veraltet markierte CPE und ihren Nachfolger schon beide (z. B. 1Password), meldet die Katalog-Pflege keine Warnung mehr – die alte CPE bleibt für ältere CVEs nötig.

## 0.1.19 – Katalog-Pflege: der Vendor-News-Katalog prüft sich selbst

### Neu
- **Katalog-Pflege**: Unter *Einstellungen → Integrationen → Vendor News → Katalog-Pflege* steht, welche Katalogeinträge Pflege brauchen – mit Grund, z. B. „CPE … existiert nicht in der NVD“, „seit 40 Monaten keine CVE-Daten“ oder „endoflife.date kennt den Schlüssel nicht mehr“. Dazu Filter gefolgte/alle, letzte Prüfung, Fortschritt und „Jetzt prüfen“.
- **Automatische Prüfung**: Gefolgte Produkte werden wöchentlich geprüft, der ganze Katalog monatlich – ob jede CPE in der NVD existiert, ob es CVEs der letzten drei Jahre gibt, ob endoflife.date den Schlüssel noch kennt und wann der letzte Hinweis von Palo Alto, Fortinet oder Veeam kam.
- **Hinweis in der Schublade**: Hat ein gefolgtes Produkt ein Problem im Katalog, steht es oben in seiner Schublade, für Admins mit Link zur Katalog-Pflege.
- **Zahl an der Vendor-News-Kachel**: „2 Einträge brauchen Pflege“, wenn gefolgte Produkte betroffen sind.

### Fixes
- **Check Point Quantum / Gaia**: Eine der beiden CPEs gab es in der NVD nicht; jetzt `o:checkpoint:quantum_security_gateway_firmware` – damit erscheinen z. B. CVE-2024-24919 und weitere Lücken der Quantum-Gateways.
- **WildFly fehlte im Katalog**: endoflife.date führt WildFly nicht mehr, der Eintrag verschwand still. WildFly ist jetzt ein eigenes Produkt (Web-/App-Server) mit seiner CPE.

### Betrieb
- **Wenige, verteilte Anfragen an die NVD**: höchstens 20 pro Stunde, mit demselben Abstand und derselben Pause nach „zu viele Anfragen“ wie Vendor News, nur wenn Vendor News an ist, einem Produkt gefolgt wird und die Vendor-News-Runde gerade nicht läuft. Der ganze Katalog braucht etwa 2 300 Anfragen im Monat; der erste Durchlauf dauert rund fünf Tage. endoflife.date wird dafür nicht eigens gefragt.
- **Datenbank-Migration 0004**: zwei neue Tabellen für die Prüfergebnisse.
- **Katalogversion 2026.10.29-2**.

## 0.1.18 – Quellen-Gesundheit

### Neu
- **Quellen-Gesundheit**: Unter *Einstellungen → Integrationen → Gesundheit* steht für jede News-Quelle und jede Vendor-News-Quelle, ob sie **gesund**, **langsam**, **gestört** oder **tot** ist – mit letztem Erfolg, letztem Fehler, neuen Einträgen je Woche der letzten 4 Wochen (kleine Verlaufslinie) und mittlerer Antwortzeit. „Nur Probleme“ blendet den Rest aus; ausgeschaltete Quellen sind eingeklappt.
- **Verlauf je Quelle**: Ein Klick öffnet die Schublade mit dem Grund für den Zustand, den letzten 50 Abrufen (Zeit, Status, Dauer, Größe, neue Einträge, Fehler), den letzten Fehlern, den Zustandswechseln, der Pause bis zum nächsten Versuch und ob die Quelle bedingte Abrufe (ETag/304) kann. Bei Vendor News stehen die vielen NVD-Abfragen in einer Zeile, die Schublade listet sie einzeln.
- **Tote Quellen in der Navigation**: Ist eine Quelle tot, zeigt *Integrationen* die Anzahl in Rot.
- **Benachrichtigung „Quelle gestört oder tot“**: Neue Art für Regeln unter *Kanäle & Regeln*. Sie kommt einmal je Zustandswechsel – wenn eine Quelle gestört oder tot wird und wenn sie wieder in Ordnung ist –, nie jede Runde und auch nach einem Neustart nicht doppelt. Fällt die NVD aus, kommt eine Nachricht, nicht eine je Produkt.

### Verbessert
- **Klare Fehlerarten**: Fehler beim Abruf heißen jetzt einheitlich (Zeitüberschreitung, keine Verbindung, Zertifikat/TLS, Fehlerantwort, Serverfehler, zu viele Anfragen, abgelehnt, nicht lesbar, zu groß) – mit HTTP-Status, wo er etwas sagt.

### Betrieb
- **Abruf-Statistik in der Datenbank**: Je Abruf eine kleine Zeile (Datenbank-Migration 0003, neue Tabellen). Sie wird 60 Tage aufbewahrt und stündlich in kleinen Portionen gelöscht. Die Sicherung enthält sie, der einmalige Umzug aus SQLite (0.1.15) braucht sie nicht.
- **Nach dem Update** zeigt die Verlaufslinie zunächst „–“ für Wochen ohne Messung; sie füllt sich in den folgenden vier Wochen.

## 0.1.17 – Vendor-News-Katalog als Daten mit eigener Version

### Neu
- **Katalogversion**: Der Vendor-News-Katalog hat eine eigene Version (z. B. 2026.10.29-1), getrennt von der App. Sie steht im Reiter „Katalog“ und auf „Version & Changelog“.
- **Symbole für die Kategorien** in der Kategorieliste des Katalogs (am Desktop).

### Verbessert
- **Katalog als Daten statt Code**: Die rund 490 gepflegten Produkte liegen jetzt als YAML-Dateien, eine je Kategorie (`backend/app/catalog/`), mit Kategorien, Hinweisen und Schema daneben. Inhalt und Ergebnis sind unverändert – alle Produkte, CPEs und Hinweise sind dieselben wie in 0.1.16.
- **Katalog wird beim Start geprüft**: Schema, doppelte Schlüssel, Kategorien, CPE-Form, Versionsschemata, Herstellerquellen und deutsche und englische Texte. Ein Fehler nennt Datei und Produkt.
- **Kategorienamen und Produkthinweise kommen mit dem Katalog**, nicht mehr aus der Oberfläche – ein späterer Katalog bringt seine Texte selbst mit.

### Betrieb
- **„Katalog pflegen“ im README**: wie man ein Produkt hinzufügt, seine CPE prüft und den Katalog mit `python -m app.catalog_data` und den Tests prüft; dazu der Plan für signierte Katalog-Updates ohne neues Image (noch nicht gebaut).
- Neue Abhängigkeit PyYAML (zum Lesen der Katalogdateien).

## 0.1.16 – PostgreSQL 18 statt SQLite, Sicherung und Export

### Neu
- **Datenbank PostgreSQL 18**: Die Daten liegen jetzt in einer eigenen Datenbank (Container `cobe-news-db`, Volume `db18`) statt in der Datei `data/news.db`. Sie ist nur für die App erreichbar und hat keinen Port nach außen.
- **Umzug beim ersten Start**: Ist die neue Datenbank leer und liegt noch eine `data/news.db` von 0.1.15 da, zieht die App alles einmal um, prüft Zeilen und Inhalte und startet erst danach. Die Datei selbst bleibt unverändert – der Weg zurück zu 0.1.15.
- **Sicherung & Export in den Einstellungen** (neuer Bereich „Betrieb“): Hier stehen die letzte Sicherung mit Zeit, Größe und ob der Schlüssel enthalten ist, der Knopf „Jetzt sichern“ und die Aufbewahrung (die letzten 3–90 Sicherungen). Darunter die Liste der Sicherungen auf dem Server samt Befehlen zum Wiederherstellen.
- **Sicherung per Befehl und Zeitplan**: `python -m app.cli backup` sichert die ganze Datenbank, z. B. täglich per cron (README). Mit `BACKUP_PASSPHRASE` ist die Sicherung verschlüsselt und enthält den Schlüssel für die gespeicherten Geheimnisse.
- **Wiederherstellen mit Prüfungen**: `python -m app.cli restore` prüft Prüfsummen, Version und Schlüssel, sichert vorher den aktuellen Stand und spielt die Sicherung in einem Schritt ein – scheitert etwas, bleibt alles, wie es war.
- **Export ohne Geheimnisse** als JSON oder CSV (ZIP): Regeln, Kanäle, Quellen, gefolgte Produkte mit Versionen und Benutzer – ohne Webhook-URLs, Tokens, Passwörter oder TOTP.

### Verbessert
- **Suche schneller**: Die Suche in den News und die „Passenden News“ eines Produkts nutzen einen eigenen Index (bei 40 000 Meldungen 8 ms statt 38 ms) und finden weiter auch Wortteile wie bisher.
- **Vendor News im Hintergrund noch leichter**: Eine ruhige Runde braucht 12 ms statt 42 ms, die Prüfung auf neue Ereignisse 3 ms statt 10 ms.
- **Kein gegenseitiges Warten mehr beim Schreiben**: Viele Änderungen laufen jetzt gleichzeitig. Während Vendor News 120 000 Ereignisse schreibt, wartet eine andere Änderung höchstens 0,08 s statt 0,5 s.

### Entfernt
- **SQLite-Sonderwege**: Das schrittweise Freigeben von Speicherplatz (SQLite-VACUUM) und die Umstellungen alter Datenbanken von vor 0.1.15 gibt es nicht mehr. Wer von einer älteren Version kommt, startet zuerst einmal 0.1.15.

### Betrieb
- **Vor dem ersten Start einmal `scripts/setup-env.sh`**: Das Skript legt die `.env` an, falls sie fehlt, und erzeugt dort das Datenbank-Passwort `POSTGRES_PASSWORD`. Ohne dieses Passwort startet `docker compose` nicht.
- **Zurück zu 0.1.15**: Das Image `cobe-news:0.1.15` und die unveränderte `data/news.db` genügen (README: PostgreSQL – Umstieg und zurück). Was seit dem Umzug dazukam, fehlt dann.
- **Image mit PostgreSQL-18-Werkzeugen** (`pg_dump`, `pg_restore`, `psql`) aus dem Paketarchiv des PostgreSQL-Projekts; der Signierschlüssel ist im Dockerfile fest hinterlegt.
- **Tests laufen gegen PostgreSQL 18**: `TEST_DATABASE_URL` zeigt auf einen Server, jeder Lauf bekommt eine eigene Datenbank (README: Entwicklung / Tests).

## 0.1.15 – Vendor News: Statuszeile, Schublade in Seiten, Kanäle und Regeln sicher bearbeiten

### Neu
- **Statuszeile in „Unsere Systeme“**: Direkt unter der Zusammenfassung stehen „Handlungsbedarf · Möglicherweise · Alles aktuell · Alle“ mit Anzahl. Die Auswahl wirkt zusammen mit Suche, „aktiv ausgenutzt“ und „Support endet“, ist per Tastatur bedienbar und bleibt im Browser gemerkt.
- **„N aktuell“ in der Zusammenfassung** ist anklickbar und zeigt genau die Produkte, bei denen alles in Ordnung ist.
- **Ungenaue Versionen** (z. B. „7.4“ statt „7.4.8“) sind jetzt auch auf den Kacheln und in der Liste mit „ungenau“ markiert.

### Verbessert
- **„Alles aktuell“ nicht mehr am Ende versteckt**: Statt des grünen Streifens unter allen Kacheln erscheinen diese Produkte als kompakte grüne Kacheln – über „Alles aktuell“ auch für sich allein.
- **Schublade schneller**: Schwachstellen kommen in Seiten zu 100 („Weitere 100 anzeigen (noch 160)“); der Wechsel zwischen Schwachstellen, Versionen und News baut nichts neu auf.
- **„Auch nicht betroffene anzeigen“** lässt die Liste stehen, bis die neue da ist – kein Flackern, der Schalter behält den Fokus.
- **Fokus nach dem Schließen**: Wer die Schublade mit Escape oder „Schließen“ zumacht, landet wieder auf der Kachel, Zeile oder Schwachstelle, mit der sie geöffnet wurde.
- **CPE-Suche („Nicht im Katalog?“)**: Wenn die NVD bremst, wartet die Suche kurz und läuft dann von selbst weiter, statt einen Fehler zu zeigen; „Nichts gefunden“ wird eigens gesagt.
- **Versionen und Notizen**: Das Formular bleibt nach dem Speichern sichtbar (gesperrt), bis die Schublade den neuen Stand zeigt.
- **Zahl an „Vendor News“ in der Seitenleiste** kommt aus einer eigenen, kleinen Abfrage statt aus der kompletten Übersicht.

### Fixes
- **Keine stille Grenze mehr in der Schublade**: Bisher wurden höchstens 300 Schwachstellen gezeigt, während die Zahl 500 sagte. Jetzt lassen sich alle laden, und die Zahlen je Gruppe stimmen.
- **Folgen-Schalter sprang zurück**: Im Katalog und in der Schublade sprang der Schalter nach dem Umlegen gut eine Sekunde lang zurück. Er bleibt jetzt in der gewählten Stellung, und jede Katalogzeile hat ihren eigenen Ladezustand.
- **CPE-Suche zeigte alte Treffer**: Eine langsame Antwort zu einem früheren Suchbegriff konnte die Treffer des aktuellen überschreiben.
- **„Eigenes Produkt hinzufügen“** startet beim erneuten Öffnen leer.
- **Kanäle und Regeln gleichzeitig bearbeitet**: Hat ein anderer Admin inzwischen gespeichert, wird nichts mehr überschrieben. Die Eingaben bleiben stehen, ein Hinweis erklärt es, und „Aktuellen Stand laden“ holt den gespeicherten Stand. Auch der Regel-Schalter in der Liste speichert nicht mehr über eine fremde Änderung hinweg.
- **Listenansicht**: Die Zahlen unter „betroffen“, „kritisch“ und „ausgenutzt“ stehen rechtsbündig unter ihren Überschriften, „Support bis“ linksbündig wie seine Überschrift.
- **Benutzerliste auf dem Handy**: Der Chip „Temporäres Passwort“ (oder „Notfallkonto“) überlappt nicht mehr „Lokal“ – die Zeile bricht sauber um.
- **Veeam-Versionen finden**: Für Veeam Agent for Linux steht jetzt `veeamconfig version` bzw. die Paketversion von `veeam` oder `veeam-nosnap`; bei Veeam Backup & Replication der Hinweis, den Build nicht aus der Systemsteuerung abzulesen (sie zeigt nach Updates teils den alten).

## 0.1.14 – Vendor News: richtige Urteile, keine doppelten Meldungen, deutlich schneller

### Neu
- **„Jetzt aktiv ausgenutzt“**: Wird eine Schwachstelle, die schon gemeldet wurde, später aktiv ausgenutzt (neu im KEV), kommt einmal eine eigene Benachrichtigung „Jetzt aktiv ausgenutzt: …“ – bei Ransomware mit Hinweis.
- **Weitere Veeam-Produkte im Katalog**: Veeam Backup for Microsoft Azure, Veeam Backup for Google Cloud und Veeam Management Pack for System Center.

### Verbessert
- **Benachrichtigungen mit lesbarem Titel**: Meldungen zu Schwachstellen nennen denselben kurzen Titel wie die Seite (z. B. „Command Injection in the GlobalProtect feature“) statt des langen NVD-Textes.
- **Vendor News im Hintergrund fast ohne Last**: Die Runde jede Minute sieht nur noch Produkte an, bei denen sich etwas geändert hat. Mit vielen Daten (30 Produkte, 60 000 NVD-Einträge, 40 000 Meldungen) braucht eine ruhige Runde 0,04 s statt 1,4 s, und die App bleibt dabei bedienbar (Verzögerung anderer Anfragen unter 1 ms statt 0,7 s).
- **Übersicht „Unsere Systeme“ schneller**: nach neuen Daten 11 s statt 82 s, sonst 7 ms statt 91 ms; die Schublade eines Produkts mit vielen Lücken 5 ms statt 356 ms.
- **Neu ankommende Daten** berechnen nur das betroffene Produkt neu, nicht alle; gleichzeitige Aufrufe warten auf dieselbe Berechnung.
- **Weniger Speicher**: höchstens rund 470 MB statt rund 1,2 GB (Spitze); wichtig bei der Speichergrenze des Containers.
- **Einem Produkt folgen** geht schneller (0,6 s statt 2 s) und hält die anderen Anfragen nicht mehr auf.
- **News-Liste**: Die Hinweise „betrifft deine Systeme“ werden außerhalb der Hauptschleife berechnet und gemerkt (10 ms statt 67 ms je Seite); „Passende News“ in der Schublade kommen aus einem Zwischenspeicher.
- **Alte Ereignisse aufgeräumt**: Ereignisse entfernter Versionen und nicht mehr gefolgter Produkte werden gelöscht – die Tabelle wächst nicht mehr mit jeder Änderung.
- **NVD sagt „zu viel“ (429)**: Dann pausieren alle NVD-Abfragen gemeinsam – die übrigen Produkte der Runde, die Details der News und die CPE-Suche fragen erst nach der Pause wieder, statt weiter abgelehnt zu werden.
- **Ungenaue Versionen**: Wer z. B. „7.4“ statt „7.4.8“ einträgt, sieht unter dem Feld einen gelben Hinweis mit Beispiel; die Karte der Version zeigt „ungenau“. Speichern geht weiterhin.
- **„Genaue Version angeben“** statt „Update verfügbar“, wenn sich mit einer ungenauen Version nicht sagen lässt, ob schon die neueste installiert ist (bei Veeam weiter „Build angeben“).

### Fixes
- **Doppelte Benachrichtigung**: Meldete erst die NVD eine Lücke und später der Hersteller dieselbe CVE, kam eine zweite Benachrichtigung. Jetzt bleibt es bei einer pro Produkt, Version und CVE.
- **Falsches „nicht betroffen“ bei kurzen Versionen**: „7.4“ bei FortiOS oder „1.25“ bei nginx galt als 7.4.0 bzw. 1.25.0 – eine Lücke in 7.4.5 bis 7.4.8 erschien als „nicht betroffen“. Jetzt heißt es „möglicherweise betroffen – Version zu ungenau“, wo sich die Releases unterscheiden.
- **Folgen-Schalter löschte Notiz und Tags**: Aus- und wieder Einschalten im Katalog leerte Notiz und Tags. Jetzt bleiben sie erhalten.
- **Auswahllisten in Schubladen**: Escape in einer geöffneten Auswahlliste schloss die ganze Schublade und ließ die Seite bis zum Neuladen unbedienbar. Jetzt schließt Escape nur die Liste, und die Liste ist wieder per Tastatur bedienbar.
- **Tooltip in der Produkt-Schublade**: Escape auf einem Fachbegriff (z. B. CPE) schließt nur den Tooltip, nicht mehr die Schublade.
- **Lücken beim NVD-Abruf**: Hatte die NVD seit dem letzten Abruf mehr als 2000 Einträge einer CPE geändert, gingen Einträge verloren. Jetzt kommen alle Seiten.
- **Von der NVD zurückgezogene CVEs** verschwinden; einmal pro Woche werden je CPE die neuesten Einträge neu geholt, und was die NVD für das Produkt nicht mehr listet, verliert die Zuordnung.
- **Eigene Produkte (per CPE)** bekamen CVEs nicht, die zuerst über die Details einer News gespeichert wurden.
- **Katalog aktualisieren** funktioniert auch bei ausgeschaltetem Vendor News; bekommt ein gefolgtes Produkt durch die Aktualisierung neue CPEs, werden die schon gespeicherten CVEs zugeordnet.
- **Eine Quelle, die immer ablehnt** (z. B. HTTP 403), hält die Benachrichtigungen der anderen Quellen eines Produkts nicht mehr auf.
- **Reihenfolge der Schwachstellen**: Bei gleichem Status und CVSS stehen jetzt die neuesten oben.
- **Versionsangaben**: „1:2.3“ (Debian-Epoch) wird nicht mehr als 1.2.3 gelesen, „7.0(3)I7(9)“ bei Cisco nicht mehr falsch verglichen; GitLab-Versionen mit „-ee“/„-ce“ werden einheitlich angenommen.
- **Veeam-Katalog**: Veeam ONE nutzt die CPEs, die es in der NVD wirklich gibt (a:veeam:one, a:veeam:one_reporter); Veeam Agent for Linux hat keine CPE in der NVD und wird über die Veeam-KB und den Namen erkannt; Veeam Backup & Replication bekommt zusätzlich a:veeam:backup_and_replication.
- **Fehlende Texte**: „laut Hinweis alle Versionen betroffen“ und Fehlermeldungen der CPE-Suche erscheinen als Text statt als interner Schlüssel.

### Betrieb
- Beim ersten Start werden die Vendor-News-Ereignisse einmal um ihre Produkt-Version ergänzt (Spalte `scope`); danach holt jede CPE einmal die neuesten NVD-Einträge neu.

## 0.1.13 – Vendor News: Übersicht „Unsere Systeme“ neu gestaltet

### Neu
- **Zielversion auf jeder Karte**: „Update auf 4.14.6 behebt alle 31 Lücken“ – die kleinste Version eurer Release-Linie, die die meisten Lücken schließt; sonst „behebt 18 von 21 – für 3 gibt es noch keinen Fix“, „Neuere Linie nötig: …“ oder bei Cloud-Diensten „Vom Hersteller behoben“.
- Bei mehreren eingetragenen Versionen mit unterschiedlichem Ziel steht eine Zeile je Version.
- **Zusammenfassung oben**: Produkte mit Handlungsbedarf, aktiv ausgenutzt, nächstes Support-Ende – jeder Teil filtert die Übersicht.
- **Listenansicht**: Kacheln oder sortierbare Liste (Produkt, Versionen, Zielversion, betroffen, kritisch, ausgenutzt, Support bis); der Browser merkt sich die Wahl.
- **Hinweis bei gleichen Daten**: Produkte, die die NVD nicht unterscheidet (z. B. Wazuh Agent und Wazuh Manager), sagen das auf der Karte.

### Verbessert
- **Übersicht nach Dringlichkeit**: aktiv ausgenutzt vor kritisch vor betroffen vor möglicherweise; Produkte ohne Befund stehen kompakt am Ende („Alles aktuell: …“).
- **Farben mit Bedeutung**: Rot nur noch bei aktiv ausgenutzten oder kritischen Lücken, Bernstein bei betroffen, neutral bei nur „möglicherweise“ – nicht mehr jede betroffene Karte ist rot.
- **Lesbare Titel**: Schwachstellen zeigen den Titel des Herstellers oder eine kurze Beschreibung statt des Werbesatzes aus der NVD; ohne beides die Art der Lücke („SQL Injection“) mit der betroffenen Komponente.
- **Karten aufgeräumt**: Support-Stand je Version („Support endet bald“, „Kein Support mehr“) auf der Karte, die drei wichtigsten Schwachstellen mit CVSS, kein wiederholtes „betrifft euch“.

### Fixes
- **Uralte CVEs nicht mehr „möglicherweise“**: Einträge mit unklaren Daten, die mindestens ein Jahr vor eurer Release-Linie erschienen sind (z. B. CVE-2009-3631 bei TYPO3 13.4.37), stehen gefaltet als „Unklare Altdaten“ und zählen nicht mehr mit – weder in Zahlen noch in Benachrichtigungen. Aktiv ausgenutzte bleiben immer sichtbar.
- **Rote Zahl in der Seitenleiste** nur noch, wenn eine aktiv ausgenutzte Lücke eine eurer Versionen wirklich betrifft.

## 0.1.12 – Changelog neu gegliedert

### Verbessert
- Der Changelog ist neu gegliedert: Jede Version listet ihre Änderungen unter „Neu“, „Verbessert“, „Fixes“, „Sicherheit“, „Entfernt“ und „Betrieb“ – kurz, eine Änderung pro Punkt.
- Die Seite „Version & Changelog“ zeigt diese Gruppen mit farbigen Kennzeichen; eingeklappte ältere Versionen nennen die Zahl je Gruppe (z. B. „9 verbessert · 5 Fixes“), auch auf dem Handy.

## 0.1.11 – Veeam in Vendor News

### Neu
- **Veeam in Vendor News**: Der Security-KB-Feed von Veeam ist jetzt eine Hersteller-Quelle wie Palo Alto und Fortinet.
- Je KB-Artikel kommen alle CVEs (aus Titel und Text), CVSS, der Link und das Datum.
- Je CVE und Produkt stehen die betroffenen Builds je Release-Linie („13.1.1.18 and all earlier version 13.1 builds“) und die Builds mit dem Fix („13.1.2 (build 13.1.2.57)“).
- Hinweise zu anderen Linien werden mitgelesen: „Older versions are not affected“, „Version 13 is not affected“, „nicht getestet, als betroffen zu betrachten“.
- Gilt für Veeam Backup & Replication (mit Enterprise Manager), Veeam ONE, Backup for Microsoft 365, Service Provider Console, Recovery Orchestrator, Kasten und die Agents.
- Das Urteil von Veeam entscheidet vor der NVD – für alle CVEs des Artikels.
- Die laufenden Listen „List of Security Fixes and Improvements“ sind keine Sicherheitshinweise und werden übergangen.
- **Veeam Agent for Linux** ist ein eigenes Produkt, denn Windows- und Linux-Agent haben eigene Build-Nummern.
- **Details aus der Quelle für Veeam-Meldungen**: Meldungen der Quelle „Veeam Security“ zeigen „Betroffene Versionen“ je Produkt mit Fix-Build, CVSS, CVEs und „Betrifft deine Systeme“ – gelesen aus der Meldung selbst, ohne zusätzliche Anfrage.

### Verbessert
- **Veeam-Versionen**: Am besten den ganzen Build eintragen (z. B. 12.3.2.4934, auch „13.1.2 (build 13.1.2.57)“). Das Formular „Neue Version eintragen“ sagt, wo er steht: Konsole → Help → About, Control Panel des Agents, Paketversion unter Linux, Helm bei Kasten.
- Mit einer kurzen Angabe wie 12.3.2 entscheidet Cobe News nur, was für jeden Build von 12.3.2 gilt. Sonst steht „möglicherweise betroffen – ohne Build-Nummer nicht entscheidbar“ und statt „Aktuell“ der Hinweis „Build angeben“ – nie ein falsches „nicht betroffen“.
- Eine Angabe wie „12.3.2 P4“ lässt sich nicht vergleichen und wird abgelehnt.
- „Veeam Agent for Windows / Linux“ heißt jetzt „Veeam Agent for Microsoft Windows“. Wer bisher einen Linux-Agent eingetragen hat, folgt bitte dem neuen Eintrag „Veeam Agent for Linux“.
- Das Datum („Stand“) einer Veeam-Meldung erscheint als Tag statt als „01:00 MEZ“.

### Fixes
- **News auf dem Handy**: Eine lange Zeile „betrifft deine Systeme: …“ machte eine Kachel breiter als den Bildschirm, sodass die Liste bei 375 px seitlich scrollte. Jetzt wird die Zeile gekürzt.

### Betrieb
- Veeam wird nur abgerufen, wenn einem Veeam-Produkt gefolgt wird: eine Anfrage je Runde (alle 6 Stunden, als bedingte Anfrage mit ETag/Last-Modified, sobald Veeam sie sendet), höchstens eine pro Minute an www.veeam.com.

## 0.1.10 – E-Mail-Server unter „Kanäle“, Benachrichtigungen robuster und schneller

### Verbessert
- **E-Mail-Server unter „Kanäle“**: Oben in „Einstellungen → Kanäle & Regeln → Kanäle“ steht „E-Mail-Server: Server:Port · eingerichtet / nicht eingerichtet“ mit „Bearbeiten“ – eine Schublade mit allen SMTP-Einstellungen und der Testmail.
- Ein neuer E-Mail-Kanal ohne Server fragt in seiner Schublade zuerst nach dem Server; er gilt für alle E-Mail-Kanäle.
- E-Mail-Kanäle ohne Server zeigen „E-Mail-Server fehlt“, sonst ihren letzten Fehler.
- Speichern des E-Mail-Servers startet die E-Mail-Kanäle neu – ohne Pause und ohne alten Fehler.
- Alte Links (/settings/mail, /settings/smtp) führen zur neuen Stelle; die API bleibt gleich.
- **Schnellere Benachrichtigungsrunde**: Sie sah bisher jede Minute alle Regeln durch – bei großen Datenbanken bis zu einer Sekunde, auch ohne etwas zu verschicken. Jetzt nur noch, wenn eine Meldung oder ein Vendor-News-Ereignis eingetroffen ist, sich Kanäle, Regeln oder der E-Mail-Server geändert haben oder ein neuer Versuch fällig ist – dazu alle 10 Minuten ein voller Durchgang, etwa für eine inzwischen höher eingestufte Meldung.
- **Webhook – gleiche Nachricht, gleiche ID**: `X-Cobe-Delivery` bzw. `id` war bei jedem Versuch neu. Jetzt behält dieselbe Nachricht bei einem neuen Versuch nach einem Fehler ihre ID, und der Empfänger kann Doppelte verwerfen. Zugestellt wird „mindestens einmal“ (siehe README).
- **Kanal-Status**: Ein erfolgreicher „Testen“ löscht den alten Fehler und beendet die Pause.
- „Nächster Versuch“ erscheint bei einem Kanal nur noch, wenn er in der Zukunft liegt.

### Fixes
- **Löschen während des Versands**: Wurde eine Meldung (Aufbewahrung) oder ein Kanal gelöscht, während eine Benachrichtigungsrunde lief, wurde die ganze Runde zurückgenommen – alle Kanäle bekamen dieselben Nachrichten noch einmal. Jetzt wird jede Nachricht direkt nach dem Versand als verschickt vermerkt, jeder Kanal für sich; was inzwischen fehlt, wird einfach nicht vermerkt.
- Ein Fehler bei einem Kanal ändert nichts mehr bei den anderen Kanälen derselben Runde.
- **Erweiterte Regel schickte Altes**: Bekam eine Regel weitere Schweregrade, Quellen oder Arten (z. B. „Hoch“ zusätzlich zu „Kritisch“), schickte sie alles, was seit ihrem Anlegen eingetroffen war und erst jetzt passte. Jetzt gilt Neues ab der Änderung; was schon vorher passte und noch offen war, kommt weiterhin.
- **Gleichzeitige Änderungen**: Speicherten zwei Admins gleichzeitig den E-Mail-Server oder die Einstellungen von News bzw. Vendor News, überschrieb der Zweite still den Ersten. Jetzt erscheint „Inzwischen von jemand anderem geändert“.
- Eine Regel, deren Kanal gerade gelöscht wurde, sowie eine gleichzeitig gelöschte Regel oder ein gelöschter Kanal führen zu derselben Meldung statt zu einem Serverfehler.

### Entfernt
- Die eigene Seite „E-Mail-Versand“ – der E-Mail-Server steht jetzt unter „Kanäle“.

## 0.1.9 – News-Liste, Test-Benachrichtigung mit Rückmeldung, „Support endet bald“ einheitlich

### Neu
- **Test-Benachrichtigung mit Rückmeldung**: Der Test sagt jetzt, was passiert ist – „Test zugestellt – Chrome hat die Meldung an das System übergeben“, „Der Browser hat die Anzeige verweigert: …“ oder nach 20 Sekunden, dass der Push nicht ankam, mit dem Push-Dienst, den der Server erreichen muss.
- Bei „zugestellt“ steht dabei, wo man Mitteilungen im System erlaubt – macOS: Systemeinstellungen → Mitteilungen → Google Chrome erlauben; Windows: Einstellungen → System → Benachrichtigungen; jeweils Fokus bzw. „Nicht stören“ aus.
- Der Hintergrunddienst des Browsers (Service Worker) meldet dafür an die Seite zurück, ob er die Benachrichtigung anzeigen konnte; im offenen Tab zählt die Rückmeldung des Browsers, ob sie angezeigt wurde oder scheiterte.
- Die Karte zeigt außerdem die Berechtigung und ob dieser Browser ein Push-Abo hat und bei welchem Push-Dienst.
- **News-Liste lädt beim Scrollen nach**: Die nächste Seite kommt automatisch, sobald das Ende der Liste in Sicht ist; „Weitere laden“ bleibt als Knopf.

### Verbessert
- **„Support endet bald“ einheitlich unter 6 Monaten**: Karte und Benachrichtigung warnten erst unter 90 Tagen, die Schublade schon unter 6 Monaten. Jetzt gilt überall dieselbe Schwelle von 183 Tagen, und ein Test hält alle Stellen gleich.
- Release-Linien mit 3–6 Monaten Restlaufzeit melden sich dadurch einmalig neu („EOL naht“).
- Karten außerhalb des Bildschirms zeichnet der Browser nicht – auch tausende Meldungen bleiben flüssig.
- Schlägt das Laden einer Seite fehl, steht der Fehler am Listenende mit „Erneut versuchen“, statt dass die App es endlos wieder probiert.
- Markieren lädt nicht mehr bei jedem Klick die ganze Liste neu.
- **Suchen ohne Flackern**: Eine neue Suche oder ein anderer Filter zeigt die bisherigen Meldungen abgeblendet weiter, bis die neuen da sind – kein „Lädt …“ mehr bei jedem Tastendruck.
- **Uhrzeiten mit Zeitzone**: In der Meldungs-Schublade steht die Zone dabei (MEZ/MESZ, englisch CET/CEST) – die doppelte Stunde bei der Zeitumstellung ist eindeutig.

### Fixes
- **„Alle als gelesen“ passend zur Suche**: Direkt nach dem Tippen konnte der Knopf noch die Treffer der vorigen Suche markieren. Er wartet jetzt, bis die Suche angewendet ist.
- **Markieren nach einem Fehler**: Schlug „gelesen/ungelesen“ fehl, kamen auch zwischenzeitlich markierte Meldungen zurück, und nachgeladene Seiten verschwanden. Jetzt kommt nur diese eine Meldung an ihren Platz zurück, nie doppelt.
- **Link auf eine gelöschte Meldung**: Statt eines endlos drehenden Ladekreises heißt es „Meldung nicht mehr vorhanden“, und der Link wird aus der Adresse entfernt.
- **„Gestern“ heißt gestern**: Relative Angaben zählen Kalendertage in deiner Zeitzone statt 24-Stunden-Blöcken – Montag 23 Uhr ist am Mittwoch 1 Uhr „vorgestern“.
- **Schubladen auf dem Handy**: Die Knöpfe unten in der News-Schublade wurden bei 375 px abgeschnitten. Sie brechen jetzt um, ebenso in der Vendor-Schublade.
- Die Karte „Keine bekannte Schwachstelle betrifft eure Versionen“ macht die Seite auf dem Handy nicht mehr breiter.

## 0.1.8 – News-Logik: Einstufung, Zusammenführen, Rückstand, neue Quellen

### Neu
- **Neue Quellen, ab Werk an**: CERT.at Warnungen, CERT@VDE (OT-Hersteller), SecurityWeek ICS/OT und Veeam Security.
- **Neue Quellen zum Einschalten**: Canadian Centre for Cyber Security, CERT-FR Alertes (Französisch), watchTowr Labs, Huntress, Rockwell Automation, Oracle Security Alerts, Risky Bulletin und Microsoft Patchday (MSRC).
- Microsoft Patchday bringt eine Meldung je Patchday-Release aus Microsofts Verzeichnis der Releases (CVRF-Index), mit Link zu den Release Notes.
- Neue Quellen erscheinen nach dem Update mit ihrem Standard; was ein Admin geschaltet hat, bleibt so.

### Verbessert
- **Geänderte Meldungen**: Ändert eine Quelle eine Meldung („[UPDATE] … wird aktiv ausgenutzt“), werden Titel und Text übernommen, die Schwere steigt (sinkt aber nie), und die CVEs werden ergänzt.
- **„Auch bei …“ zählt mit**: Eine Meldung, die mehrere Quellen bringen, erscheint jetzt im Quellenfilter jeder dieser Quellen, in deren Regeln und Desktop-Auswahl und in der Anzahl je Quelle – und bleibt sichtbar, solange eine davon eingeschaltet ist.
- **Kurze Pause bei Verbindungsfehlern**: Timeouts und Verbindungsfehler (DNS, TLS, Proxy) ließen eine Quelle bis zu 16 Stunden pausieren; jetzt höchstens eine Stunde oder ein Abrufintervall, wenn es länger ist.
- Eine Zeitüberschreitung beim Lesen heißt jetzt „Keine Antwort in 30 Sekunden“ statt „Keine Verbindung“.
- **CISA Alerts ab Werk aus**: www.cisa.gov lehnt automatische Abrufe aus vielen Netzen ab (403). Cobe News umgeht das nicht (keine Browser-Kennung, keine falschen Header) und zeigt jetzt „Die Quelle lehnt automatische Abrufe ab (403). Cobe News umgeht das nicht – Quelle ausschalten oder später erneut versuchen.“ Neue Installationen haben die Quelle aus; der CISA-KEV-Katalog bleibt an.
- Cobe News merkt sich jetzt jedes Schalten einer Quelle – wer CISA Alerts einschaltet, behält sie.
- Meldungen ohne eigenes Datum bleiben bei der Aufbewahrung, solange ihr Feed sie noch listet.
- Ein kürzeres Abrufintervall einer Quelle gilt sofort.
- Eine wieder eingeschaltete Quelle startet ohne alten Fehler und ohne alte Pause.
- **Schneller**: Die Zähler der News-Liste brauchen bei 50 000 Meldungen 27 statt 66 ms.

### Fixes
- **„Aktiv ausgenutzt“ trotz Verneinung**: Meldungen mit „nicht aktiv ausgenutzt“, „has not been exploited in the wild“, „no known exploit in the wild“, „keine aktive Ausnutzung“ oder „Kein Zero-Day“ wurden als kritisch eingestuft. Jetzt zählt eine Verneinung direkt davor.
- Ebenso fälschlich kritisch waren die Zero-Day-Initiative (auch mit Bindestrich), ein „Out-of-Band-Management-Interface“ und Malware, die „in the wild“ gesichtet wurde. „In the wild“ bzw. „in freier Wildbahn“ zählt jetzt nur, wenn es um eine Ausnutzung geht.
- Auch der Exploit-Status in CSAF-Advisories erkennt jetzt „nicht“ und „kein“.
- **CVSS-Werte**: „CVSS-Score von 9.8“ und „CVSS-Basiswert 9,8“ werden jetzt gelesen. „CVSS:3.1/AV:N…“ oder „CVSS 3.1“ gelten nicht mehr als Wert 3.1.
- **Datumsangaben**: Feeds mit deutschen Wochentagen und Monaten („Di, 27 Okt 2026“) und mit Zonen wie MEZ, MESZ oder CEST bekommen die richtige Uhrzeit, statt als UTC gelesen zu werden oder ganz ohne Datum zu bleiben. „CST“ bleibt wie im Standard (RFC 822) US-Zentralzeit.
- CVE-Nummern mit typografischen Bindestrichen (z. B. aus Word) werden erkannt.
- **Benachrichtigungen bei CISA KEV und ENISA EUVD**: Einträge mit reinem Datum (ohne Uhrzeit) galten als „Mitternacht UTC“ und wurden schon wenige Stunden nach dem Abruf als Rückstand behandelt – nie an Regeln, Desktop oder Web Push gemeldet. Jetzt zählt so ein Datum bis zum Ende des Tages.
- Ob eine Meldung Rückstand ist, wird einmal beim Speichern entschieden und gilt für Regeln, Desktop-Benachrichtigungen und Web Push gleich. Meldungen ohne eigenes Datum sind nur im ersten Abruf einer Quelle Rückstand; was vor dem Update zurückgehalten wurde, bleibt zurückgehalten.
- **Gleicher Titel, andere Meldung**: Eine Quelle, die denselben Titel ein paar Tage später unter neuer Adresse bringt (CISA „Adds Two Known Exploited Vulnerabilities …“, CERT-Bund „[hoch] Linux Kernel …“), verlor die zweite Meldung. Jetzt werden Titel nur noch über Quellen hinweg zusammengeführt.
- Titel in kyrillischer oder chinesischer Schrift fallen nicht mehr zu einer Meldung zusammen.
- Ein „Retry-After“ mit einem Datum in der Vergangenheit führt nicht mehr zu einer negativen Pause.
- Nach dem Erhöhen der Aufbewahrung kommen bereits gelöschte Meldungen nicht mehr als ungelesen zurück.
- „Nächster Versuch“ erscheint bei einer Quelle nur noch, wenn er in der Zukunft liegt.
- Eine eingebaute Quelle mit neuer Adresse vergisst ETag, Pause und Fehler der alten.
- Zweimal gleichzeitig dieselbe Adresse hinzufügen ergibt eine Quelle und einen Hinweis statt eines Fehlers 500.
- **Quelle löschen räumt auf**: Meldungen, die auch andere Quellen bringen, bleiben – die nächste Quelle übernimmt sie. Regeln und Desktop-Auswahl nennen die gelöschte Quelle nicht mehr; nannten sie nur diese, sendet die Regel keine News mehr bzw. die Desktop-Benachrichtigung wird ausgeschaltet, statt plötzlich für „alle Quellen“ zu gelten.

### Sicherheit
- Ein Feed mit einem präparierten Titel (Hunderttausende „<“) konnte die Verarbeitung minutenlang blockieren. Titel und Versionsangaben aus Advisories werden jetzt vor der Auswertung gekürzt.

### Betrieb
- Bestehende Installationen, in denen CISA Alerts nie jemand geschaltet hat, schalten die Quelle beim Update einmal aus. Bis 0.1.6 wurde nicht festgehalten, ob ein Admin eine Quelle geschaltet hat – wer sie bewusst angelassen hat, schaltet sie wieder ein.
- Die neuen ausgehenden Hosts der neuen Quellen stehen in der README.
- Gelöschte Meldungen geben ihren Speicherplatz in kleinen Schritten frei. Dafür wird die Datenbank beim ersten Start einmal umgestellt (bei 50 000 Meldungen etwa eine Sekunde).

## 0.1.7 – Sicherheit: Web Push, Downloads, Anmeldung und Verzeichniskonten

### Fixes
- **Kein Schwall nach dem Wiedereinschalten**: Wird ein deaktiviertes Konto wieder aktiviert, kommen per Push nur noch Meldungen, die danach eintreffen – nicht alles aus der Zwischenzeit.
- Nach dem Abmelden bekommt dieser Browser keine Pushes mehr; eine nur abgelaufene Sitzung beendet Push nicht (siehe README).
- **Push-Schlüssel (VAPID)**: Ließ sich der gespeicherte Schlüssel nicht mehr lesen (`SECRET_KEY` geändert, Eintrag beschädigt), scheiterte Push dauerhaft. Jetzt entsteht ein neuer Schlüssel, die alten Abos werden gelöscht, und die Browser melden sich mit dem neuen an.
- **Gleichzeitige Änderungen**: Speicherten zwei Admins dasselbe Konto oder dieselben Anmelde-Einstellungen (AD, Entra, Sitzungen), überschrieb der Zweite still den Ersten. Jetzt erscheint „Inzwischen von jemand anderem geändert“.
- Gleichzeitiges Anlegen desselben Namens gibt eine klare Meldung statt eines Serverfehlers.
- **AD-Sperren**: Gesperrte AD-Konten waren in der Benutzerliste nicht zu sehen und ließen sich nicht entsperren. Jetzt sieht und löst ein Admin sie.
- Abgelehnte AD-Anmeldungen sperrten ein gleichnamiges lokales Konto. Sperren zählen jetzt je Herkunft getrennt.
- Ein gesperrtes AD-Konto wird gar nicht erst am Domänencontroller geprüft.
- **Umbenennungen im Verzeichnis**: Wurde ein AD- oder Entra-Konto umbenannt, blieb der alte Name. Jetzt folgt der Name dem Konto.
- Der Name eines im Verzeichnis gelöschten Kontos wird für ein neues Konto frei.
- **Einrichtung**: Brach die Ersteinrichtung auf halbem Weg ab, war sie als erledigt markiert, aber ohne Admin – und ließ sich nicht wiederholen. Jetzt gilt alles oder nichts; ein solcher Zustand bekommt beim nächsten Start ein neues Setup-Token.
- **Sitzungsdauer**: Ein kürzeres absolutes Timeout galt nur für neue Sitzungen, jetzt sofort für alle.
- Zwei Datenbank-Sicherungen in derselben Sekunde verhindern den Start nicht mehr.
- Der Zertifikatswächter versucht ein gescheitertes Neuladen von nginx in der nächsten Runde erneut.
- Eine Datenbank der allerersten Version lässt sich jetzt aktualisieren.

### Sicherheit
- **Downloads mit fester Obergrenze, auch komprimiert**: Ein Feed, Logo, Katalog (KEV, EUVD, endoflife.date), CSAF- oder NVD-Abruf oder die Antwort eines Webhooks bzw. von Telegram konnte als gzip-„Bombe“ aus wenigen KB im Speicher Hunderte MB werden. Jetzt entpackt Cobe News selbst, mit Obergrenze; angenommen wird nur unkomprimiert oder eine Schicht gzip/deflate (`Accept-Encoding: gzip, deflate`).
- **Web Push lässt sich nicht mehr lahmlegen**: Ein Browser, dessen Push-Dienst langsam antwortet oder dauernd Fehler liefert, hielt die Runde für alle auf. Jetzt hat jeder Browser je Runde 30 Sekunden, die ganze Runde 2 Minuten, und mehr Browser werden gleichzeitig beliefert.
- Ein Push-Abo, das 12-mal in Folge scheitert, wird gelöscht; der Browser meldet sich beim nächsten Besuch neu an.
- Push-Ziele bleiben auf die Push-Dienste der Browserhersteller beschränkt, höchstens 10 Browser je Person.
- **Docker Desktop: keine Sperre für alle**: Unter Docker Desktop kommen alle Anfragen von derselben Gateway-Adresse – ein Spraying-Versuch konnte damit alle aussperren. Das Gateway, der Proxy selbst und Adressen aus `SHARED_ADDRESSES` werden nie geblockt, Fehlversuche darüber nur gebremst; die Kontosperren gelten weiter.
- `X-Forwarded-For` gilt weiterhin nur vom mitgelieferten nginx bzw. von Adressen aus `TRUSTED_PROXIES`.
- **SMTP-Server**: Als SMTP-Server ließen sich interne Ziele eintragen (Loopback, Cloud-Metadaten, eigene Docker-Netze). Jetzt gilt dieselbe Regel wie beim Webhook: Firmennetz ja, interne Ziele nein. Der Name wird einmal aufgelöst und genau diese Adresse verbunden.
- **Notfall-Admin gebremst**: Das nie gesperrte Notfallkonto ließ sich von vielen Adressen gleichzeitig raten. Nach 20 Fehlversuchen pro Stunde wartet jede Prüfung 3 Sekunden, und es läuft nur eine gleichzeitig – der Besitzer kommt weiter hinein.
- **Erneut bestätigen**: Anmelde-Einstellungen, Rollen-Zuordnungen, Admins anlegen, Rollen ändern, Passwort/TOTP anderer zurücksetzen und Konten löschen verlangen eine Bestätigung der letzten 10 Minuten – Passwort und TOTP-Code (AD-Konten: AD-Passwort und Code), Entra-Konten bei Microsoft. Ein Dialog fragt danach und führt die Änderung dann aus.
- **AD-Konto zum Admin befördert**: Eine ältere Reader-Sitzung arbeitete nach der Beförderung als Admin weiter – ohne TOTP. Jetzt enden bei jeder Rollenänderung alle älteren Sitzungen des Kontos.
- **Cookies**: Auch das CSRF-Cookie heißt mit HTTPS `__Host-cobe_news_csrf` und lässt sich so von keiner Subdomain und keiner http-Seite setzen.

### Betrieb
- Neuer Befehl `python -m app.cli rotate-vapid`: erneuert den Push-Schlüssel mit Absicht, ohne Neustart.
- Die README erklärt, was man unter Docker Desktop bei den Anmeldesperren sieht und was zu tun ist.
- Ein SMTP-Relay auf dem Docker-Host oder einer anderen internen Adresse erlaubt `SMTP_ALLOW_INTERNAL` in der `.env`.
- Skripte, die die nun bestätigungspflichtigen Aufrufe nutzen, bestätigen vorher über `/api/auth/reauth`.

## 0.1.6 – Katalog: neue Kategorien und 169 Produkte

### Neu
- **Neue Kategorien** (Sicherheitsthemen stehen zusammen): Load Balancer & Reverse Proxy, DNS, DHCP & IPAM, Container & Kubernetes, Backup & Wiederherstellung, Mail & Mail-Security, ITSM & Ticketing, Monitoring & Observability, SIEM & Logging, Schwachstellen-Scanner, Identität & Zugriff (IAM/SSO), PKI & Zertifikate, OT/ICS (Industrie).
- **169 neue Produkte**, je mit in der NVD geprüften CPE-Kennungen (ohne CPE: Suche über Namen, CNA-Daten und News), Cloud-Dienste als „Cloud-Dienst“, mit Suchwörtern, Beispielversion, Aliasen und – wo es das gibt – Release-Linien von endoflife.date.
- **Neu in Firewalls & VPN**: Arista NG Firewall (Untangle); Check Point Remote Access VPN Client; Check Point Security Management / Smart-1; Clavister NetShield / cOS; Endian Firewall; Forcepoint NGFW; genua genucenter; genua genugate; Hillstone Networks (StoneOS); Huawei USG / HiSecEngine; IPFire; Juniper Secure Connect; Kerio Control; LANCOM R&S Unified Firewalls (LCOS FX); Securepoint UTM (NextGen Firewall); Securepoint VPN Client; Sophos Connect (VPN-Client); Sophos UTM (SG); Sophos ZTNA; WatchGuard Mobile VPN with SSL / IKEv2.
- **Neu in Switches, Router & WLAN**: Allied Telesis AlliedWare Plus; Arista CloudVision (CVP, CVaaS); Arista EOS; Cisco Business / Small Business Switches (CBS, SG); Cisco Catalyst Center (DNA Center); D-Link Business Switches (DGS, DXS); Dell SmartFabric OS10 (PowerSwitch); ExtremeCloud IQ (Cloud); H3C Comware; HPE Aruba AOS-S (ArubaOS-Switch, ProVision); HPE Aruba EdgeConnect SD-WAN (Silver Peak); HPE Aruba Instant On; HPE Aruba Networking Central (Cloud); HPE OfficeConnect Switches; Huawei VRP (Switches, Router); LANCOM Switches (LCOS SX); MikroTik SwOS; NETGEAR Managed Switches (ProSAFE, Insight); NVIDIA Cumulus Linux / Onyx (Mellanox); RUCKUS ICX (FastIron); RUCKUS SmartZone / Unleashed; TP-Link Omada (Controller, Switches); Ubiquiti EdgeRouter (EdgeOS); Ubiquiti UISP / airMAX (airOS); Ubiquiti UniFi Access; Ubiquiti UniFi Access Points (Firmware); Ubiquiti UniFi Protect; Ubiquiti UniFi Switch (USW, Firmware); Ubiquiti UniFi Talk; VyOS; Zyxel Switches (Nebula).
- **Neu in Load Balancer & Reverse Proxy**: Progress Kemp LoadMaster.
- **Neu in DNS, DHCP & IPAM**: Infoblox NIOS; ISC Kea DHCP; Unbound; Windows DNS Server.
- **Neu in Virtualisierung & Hypervisor**: Azure Local (Azure Stack HCI); KVM (Linux kernel); libvirt; Microsoft Hyper-V Server 2019 (standalone); Nutanix AHV; OpenStack (Nova, Neutron, Keystone …); Parallels Desktop; Parallels RAS; QEMU; Red Hat OpenShift Virtualization (KubeVirt); Red Hat Virtualization; SUSE Harvester (HCI); System Center Virtual Machine Manager (SCVMM); VMware vSAN; VMware vSphere Replication; Windows Admin Center; Xen Orchestra; Xen Project Hypervisor.
- **Neu in Container & Kubernetes**: Helm; K3s; Portainer.
- **Neu in Backup & Wiederherstellung**: Acronis Cyber Protect (Agent, Management Server); Arcserve UDP; Bacula / Bareos; Barracuda Backup; Cohesity DataProtect; Datto (SIRIS, ALTO, BCDR); Dell Avamar; Dell NetWorker; Dell PowerProtect Data Manager; Dell PowerProtect DD (Data Domain OS); Druva (inSync, Phoenix) (Cloud); Hornetsecurity VM Backup (Altaro); HYCU; IBM Storage Protect (Spectrum Protect, TSM); NAKIVO Backup & Replication; Redstor Backup (Cloud); Rubrik (Security Cloud, CDM); SEP sesam; Synology Active Backup for Business; Veeam Agent for Windows / Linux; Veeam Kasten (K10); Veeam Recovery Orchestrator; Veeam Service Provider Console; Veritas Backup Exec.
- **Neu in Mail & Mail-Security**: Hornetsecurity 365 Total Protection (Cloud); Mimecast Email Security (Cloud); NoSpamProxy; Proofpoint Email Protection (Cloud); Rspamd; SEPPmail Secure E-Mail Gateway; Trend Micro Email Security (Cloud).
- **Neu in ITSM & Ticketing**: GLPI; ServiceNow (Cloud); TOPdesk; Zammad; Znuny / OTRS.
- **Neu in Monitoring & Observability**: Datadog Agent; Nagios Core; Uptime Kuma.
- **Neu in Security & Endpoint**: Check Point Harmony Endpoint; FortiEDR.
- **Neu in SIEM & Logging**: Elastic Agent & Fleet Server (Elastic Security); Exabeam (New-Scale SIEM, Advanced Analytics); Fluentd; IBM QRadar SIEM; LogRhythm SIEM; Microsoft Sentinel (Cloud); Microsoft Sysmon; OpenText ArcSight (ESM, Logger); Rapid7 Insight Agent; Rapid7 InsightIDR (Cloud); Security Onion; Securonix Unified Defense SIEM (Cloud); Splunk SOAR; Splunk Universal Forwarder; Sumo Logic (Cloud); Trend Vision One (platform) (Cloud); Wazuh Agent; Wazuh Manager (Server).
- **Neu in Schwachstellen-Scanner**: Greenbone / OpenVAS; Qualys Cloud Agent; Tenable Nessus; Tenable Nessus Agent.
- **Neu in Identität & Zugriff (IAM/SSO)**: Active Directory Federation Services (AD FS); Cisco Duo (Authentication Proxy, Windows Logon); FortiAuthenticator; FreeIPA; Okta (Workforce Identity) (Cloud); Okta Verify (App); PingFederate; privacyIDEA; WatchGuard AuthPoint.
- **Neu in PKI & Zertifikate**: Active Directory Certificate Services (AD CS); Keyfactor EJBCA.
- **Neu in OT/ICS (Industrie)**: Beckhoff TwinCAT; Belden Hirschmann (HiOS, Classic); CODESYS Control (Runtime); Moxa (NPort, EDS, MXview); Phoenix Contact PLCnext; Rockwell ControlLogix / GuardLogix (Firmware); Rockwell FactoryTalk (View, Linx, AssetCentre); Schneider Electric EcoStruxure (Control Expert, Machine Expert); Schneider Electric Modicon (M340, M580); Siemens SCALANCE (Switches, Router, WLAN); Siemens SIMATIC S7-1200 (CPU-Firmware); Siemens SIMATIC S7-1500 (CPU-Firmware); Siemens SIMATIC WinCC; Siemens SINEC NMS; Siemens TIA Portal; WAGO PFC100 / PFC200.
- **Neu in Cloud-Dienste**: Securepoint Unified Security Cloud (Cloud); Sophos Central (Cloud).
- **Hyper-V-Hinweis**: Die Build-Nummer des Hosts angeben (z. B. 10.0.20348.2762 bei Server 2022), nicht die Integrationsdienste oder eine KB; gezeigt werden CVEs, die Hyper-V nennen.
- Neue Hinweise auch für Windows-Rollen (AD FS, AD CS, Windows-DNS), OT-Firmware und Cisco Meraki.

### Verbessert
- **Aufgeteilt**: „Storage & Backup“ in Storage & NAS und Backup & Wiederherstellung.
- **Aufgeteilt**: „Virtualisierung & Container“ in Virtualisierung & Hypervisor (inkl. VDI) und Container & Kubernetes.
- **Umsortiert nach Switches, Router & WLAN**: Cisco Meraki (MS, MR, MX) aus Cloud-Dienste.
- **Umsortiert nach Load Balancer & Reverse Proxy**: F5 BIG-IP und NetScaler ADC (Citrix ADC) aus Firewalls & VPN; FortiADC aus Switches, Router & WLAN; Envoy aus Weitere Server-Software; HAProxy, Traefik und nginx / NGINX Plus aus Web-/App-Server & Laufzeiten.
- **Umsortiert nach DNS, DHCP & IPAM**: BIND 9 und ISC DHCP aus Weitere Server-Software.
- **Umsortiert nach Virtualisierung & Hypervisor**: oVirt aus Weitere Server-Software.
- **Umsortiert nach Container & Kubernetes**: Argo CD, Argo Workflows und Istio aus Weitere Server-Software; Contour, DaoCloud Enterprise, Docker Engine, ExternalDNS, HAProxy Ingress, Harbor, Karpenter, Kubernetes, Kubernetes CSI Node Driver Registrar, Kubernetes Node Feature Discovery, Kyverno, MetalLB, Podman, Rancher, Red Hat OpenShift und containerd aus Virtualisierung & Hypervisor.
- **Umsortiert nach Backup & Wiederherstellung**: Commvault, HPE Zerto, NetBackup Appliance OS, Proxmox Backup Server, Veeam Backup & Replication, Veeam Backup for Microsoft 365, Veeam ONE und Veritas NetBackup aus Storage & NAS.
- **Umsortiert nach Mail & Mail-Security**: Roundcube Webmail und Zimbra Collaboration aus Collaboration & DevOps; Dovecot, Exim, Pigeonhole und Postfix aus Weitere Server-Software; Cisco Secure Email Gateway (ESA) und FortiMail aus Security & Endpoint; Proxmox Mail Gateway aus Virtualisierung & Hypervisor.
- **Umsortiert nach ITSM & Ticketing**: Atlassian Jira Service Management aus Collaboration & DevOps; ManageEngine ServiceDesk Plus und SolarWinds Web Help Desk aus Fernzugriff & IT-Management.
- **Umsortiert nach Monitoring & Observability**: Grafana, Icinga Web und Prometheus aus Weitere Server-Software; Checkmk, Icinga, Nagios XI, Paessler PRTG Network Monitor, SolarWinds Platform (Orion) und Zabbix aus Fernzugriff & IT-Management.
- **Umsortiert nach SIEM & Logging**: Cortex XSIAM aus Cloud-Dienste; Elasticsearch und OpenSearch aus Datenbanken; Elastic Beats, Fluent Bit, Grafana Loki, Graylog, Kibana, Logstash und Splunk Enterprise aus Weitere Server-Software; Cortex XSOAR und FortiSIEM aus Security & Endpoint.
- **Umsortiert nach Identität & Zugriff (IAM/SSO)**: Microsoft Entra Connect / Cloud Sync aus Microsoft-Server; authentik aus Weitere Server-Software; ManageEngine ADSelfService Plus aus Fernzugriff & IT-Management; Keycloak aus Security & Endpoint.
- **Besser auffindbar**: Hyper-V auch als „HyperV“/„Hyper V“, Sophos Firewall als „XG“, „XGS“, „SFOS“, Aruba-Switches als „ProCurve“/„ProVision“, UniFi als „UniFi Switch“/„Ubiquiti“, Proxmox VE als „PVE“.
- Stormshield heißt jetzt „Stormshield Network Security (SNS)“.
- LANCOM-Switches (LCOS SX) sind ein eigenes Produkt.
- **Katalog jetzt 828 Produkte** (vorher 659).
- **Produkte je Kategorie**: Firewalls & VPN 45, Switches, Router & WLAN 54, Load Balancer & Reverse Proxy 8, DNS, DHCP & IPAM 6, Betriebssysteme 54, Virtualisierung & Hypervisor 38, Container & Kubernetes 22, Storage & NAS 7, Backup & Wiederherstellung 32, Microsoft-Server 7, Mail & Mail-Security 16, Collaboration & DevOps 13, ITSM & Ticketing 8, ERP & Business 15, Web-/App-Server & Laufzeiten 53, Datenbanken 38, Monitoring & Observability 12, Security & Endpoint 25, SIEM & Logging 30, Schwachstellen-Scanner 4, Identität & Zugriff (IAM/SSO) 13, PKI & Zertifikate 2, Passwortmanager & Zugangsverwaltung 31, OT/ICS (Industrie) 16, Fernzugriff & IT-Management 12, Browser & Client-Software 58, Geräte & Firmware 23, Cloud-Dienste 19, Frameworks & Entwicklung 68, Weitere Server-Software 99.
- Automatische Prüfungen für den Katalog: eindeutige Schlüssel, gültige Kategorien und CPE-Formate, Beschriftung jeder Kategorie und jedes Hinweises auf Deutsch und Englisch, gleiche Reihenfolge der Kategorien in Server und Oberfläche, Suche nach den Aliasen.
- Geprüft, noch nicht eingebaut: Veeam veröffentlicht einen eigenen Sicherheits-Feed (Atom, je Hinweis Produkt, CVEs, betroffene und behobene Builds) – eine mögliche Hersteller-Quelle für genaue Versionsvergleiche.

### Fixes
- **Kategorie-Liste im Katalog**: Lange Namen („Passwortmanager & Zugangsverwaltung“, „Web-/App-Server & Laufzeiten“) liefen in ihre Zahl und über die Spalte hinaus in die Produktliste. Jetzt bricht der Name auf höchstens zwei Zeilen um (darüber gekürzt, voller Name als Tooltip).
- Die Zahl steht rechts in eigener Spalte mit gleich breiten Ziffern; der gefolgte Teil („1 /“) wie bisher in der Primärfarbe. Geprüft für alle Kategorien, Deutsch und Englisch, Desktop und 375 px, hell und dunkel.

## 0.1.5 – Schublade sofort da: keine Datenbank-Sperre mehr durch Hintergrundabrufe

### Verbessert
- **Schubladen**: Titel und Hersteller bzw. Quelle stehen sofort da (aus der Karte), darunter Platzhalter, bis die Details geladen sind.
- Bei einem Serverfehler versucht die Schublade es einmal nach 1 s erneut; ohne Antwort nach 10 s erscheint der Fehler mit „Erneut versuchen“ – kein minutenlanges stilles Wiederholen mehr.
- **Gemessen** (Wegwerf-Instanz, Vendor-News- und Details-Runde mit 3 s langsamen Hersteller-Antworten, 4 parallele Anfragen): vorher p50 7 ms, p95 10 380 ms, max 10 459 ms, 12 × HTTP 500; nachher p50 11 ms, p95 19 ms, max 59 ms, keine Fehler.

### Fixes
- **Schublade brauchte fast eine Minute**: Ein Klick auf eine Karte in Vendor News (oder auf eine Story) zeigte lange nichts, manchmal „database is locked“ (HTTP 500). Die Hintergrundrunden („Details aus der Quelle“, Vendor-News-Abrufe von NVD, Palo Alto, Fortinet, KEV, endoflife.date, Web Push) sperrten die Datenbank, während sie auf langsame Hersteller-Server und die NVD-Pausen (6,5 s) warteten. Jede Anfrage, die schreiben musste – schon das Vermerken „zuletzt aktiv“ der Sitzung –, wartete bis zu 10 s und brach dann ab; die Oberfläche versuchte es still erneut.
- Jetzt wird vor jedem Abruf gespeichert und die Sperre freigegeben; das Ergebnis wird danach in einem kurzen Schritt geschrieben.
- Große NVD-Abgleiche werden in Paketen zu 500 Einträgen geschrieben; das Zuordnen zu den Produkten läuft vorher und außerhalb der Sperre.
- Neu bewertete Ereignisse, der Web-Push-Stand, Logos und das Aufräumen alter Stories (in Paketen) halten die Datenbank ebenfalls nur kurz.
- **Sitzung**: „Zuletzt aktiv“ wird höchstens alle 5 Minuten (bzw. jedes Fünftel der Leerlaufzeit) gespeichert und wartet höchstens 1 s; ist die Datenbank gerade belegt, wird es übersprungen – eine Anfrage scheitert nie daran.

### Betrieb
- **SQLite**: Write-Ahead-Log mit `synchronous=NORMAL`, überall dieselbe Wartezeit von 10 s.
- **Wächter im Log**: Eine Schreib-Sperre, die länger als 2 s offen ist, erscheint als Warnung „slow write transaction“ mit der Stelle im Code, die sie begonnen hat.

## 0.1.4 – Versionen übersichtlich, PAN-OS-Befunde korrigiert, Passwortmanager

### Neu
- **Neue Kategorie „Passwortmanager & Zugangsverwaltung“** im Katalog: Passwork, Bitwarden (Server und Clients), Bitwarden Secrets Manager, Vaultwarden, 1Password, KeePass (aus „Clients“ verschoben), KeePassXC, LastPass, Keeper, Dashlane, Proton Pass, NordPass, Psono, Passbolt, Passwordstate, Netwrix Password Secure, Devolutions Server und Remote Desktop Manager, Delinea Secret Server, CyberArk PAM und Privilege Cloud, ManageEngine Password Manager Pro und PAM360, Pleasant Password Server, TeamPass, Enpass, RoboForm, Zoho Vault; HashiCorp Vault und FortiPAM ebenfalls dort.
- **Formular „Neue Version eintragen“**: mit Beschriftungen, „z. B.“-Platzhaltern, Formatprüfung beim Tippen und dem Befehl, der die Version zeigt (zum Kopieren).
- Ohne eingetragene Version erklärt ein Hinweis, warum sie sich lohnt.
- Tooltip „Was ist eine Release-Linie?“.

### Verbessert
- **Reiter „Versionen“ neu geordnet**: eingetragene Versionen als Karten (Version groß, Bezeichnung, Anzahl Geräte).
- Klare Status-Chips je Version: „1 betrifft diese Version“ (führt zu den Schwachstellen), „Aktuell“ oder „Update verfügbar → 11.2.16“, „Support bis 02.05.2027“ (gelb unter 6 Monaten, rot „Kein Support mehr seit …“), „Neuere Linie“ als Hinweis mit Erklärung.
- Bearbeiten per Stift, Entfernen mit Rückfrage.
- **Release-Linien erklärt**: Spalten mit Erklärung, Status „Unterstützt / Support endet bald / Kein Support“, „eure Linie“ markiert, Linien ohne Support eingeklappt, Daten als 02.05.2027, Quelle endoflife.date.
- Notiz und Tags stehen zuletzt und werden ebenfalls erst per Stift bearbeitet.
- **Schwachstellen gruppiert**: „Betrifft eure Versionen“ und „Möglicherweise betroffen – Daten nicht eindeutig“ getrennt, je mit Erklärung; der Grund steht bei jeder Version.
- Die Kurzliste der Karte zeigt den Status jedes Eintrags („betrifft euch“ / „möglicherweise“) in der Reihenfolge der Schublade; ein Klick öffnet die Schublade bei genau diesem Befund.

### Fixes
- **Falsches „möglicherweise betroffen“ bei PAN-OS**: Ein Palo-Alto-Hinweis zu zwei CVEs (PHP, CVE-2026-109618 und CVE-2026-109619) kannte nur die erste; die zweite wurde allein nach NVD-Daten bewertet. Jetzt gehören alle CVEs aus Kennung, Titel und Text zum Hinweis, und das Urteil des Herstellers entscheidet (11.2.4-h23: nicht betroffen, 11.2.4-h20: betroffen).
- Gespeicherte Hersteller-Hinweise werden beim Start einmal korrigiert.
- Ein NVD-Eintrag „pan-os:-“ (Produkt ohne Version) zählt nicht mehr als „alle Versionen betroffen“.
- Palo-Alto-Linien mit einer einzelnen betroffenen Version („11.2.2“, Fix „>= 11.2.3“) werden verglichen statt als „nicht vergleichbar“ gemeldet.
- **Tooltip öffnete sich von selbst**: Beim Öffnen einer Schublade (Vendor News, News) oder eines Dialogs bekam das erste Element den Fokus – z. B. der Begriff „CPE“, dessen Erklärung dann aufsprang. Jetzt bekommt die Schublade selbst den Fokus; Tab führt weiter, Escape schließt.
- **Neuer Katalog erst nach dem nächsten Abgleich**: Ein aktualisierter Katalog im Datenordner, der mit älteren kuratierten Einträgen gebaut wurde, verdeckte nach einem Update die neuen. Der Katalog merkt sich jetzt, mit welchem Stand er gebaut wurde, und bekommt beim Laden den aktuellen.

### Betrieb
- Bedienregeln für künftige Masken als eigenes Dokument (docs/UX.md, verlinkt im README).

## 0.1.3 – Version & Changelog

### Neu
- **Seite „Version & Changelog“** (Benutzermenü in der Seitenleiste → „Version & Changelog“): die laufende Version, darunter „Neu in“ dieser Version, ältere Versionen zum Aufklappen.

### Betrieb
- Die Texte kommen aus dieser Datei, die jetzt mit im Image liegt – Version und Notizen passen immer zusammen.

## 0.1.2 – Details aus der Quelle

### Neu
- **Details aus der Quelle**: Zu jeder Meldung das strukturierte Advisory dahinter. In der Schublade „Betroffene Versionen“ (je Produkt Bereich und Fix-Version), CVSS, CVEs zum Kopieren, „Remote angreifbar“, „Workaround/Mitigation vorhanden“, „Stand: Update vom …“ und woher die Details kommen.
- Auf der Kachel stehen CVSS und z. B. „betrifft GitLab <19.5.1“.
- **Quellen der Details**: BSI CERT-Bund (WID) als CSAF 2.0, Siemens ProductCERT CSAF, Cisco CSAF, Fortinet CSAF, Palo Alto (CVE-5-JSON); CISA KEV und ENISA EUVD aus der Meldung; sonst die NVD zu den CVEs (gekennzeichnet „aus NVD“, mit Rate-Limit).
- **Verknüpft mit Vendor News**: „Betrifft deine Systeme“ mit den betroffenen Versionseinträgen; BSI-, Siemens- und Cisco-Advisories werden Befunde der gefolgten Produkte – samt Benachrichtigung.
- Einstellungen → News: Schalter „Details aus der Quelle“ (ab Werk an).

### Verbessert
- Ändert sich der Titel einer Meldung („[UPDATE]“), werden ihre Details sofort neu geholt, und der Titel folgt jetzt auch.

### Betrieb
- Je Advisory eine Anfrage; Details frischer Meldungen werden täglich neu geholt.

## 0.1.1 – Vendor News

### Neu
- **Seitenpunkt „Vendor News“**: Katalog mit rund 630 Produkten (aus endoflife.date gebaut, kuratiert ergänzt um Palo Alto, Fortinet, Cisco, Check Point, Ivanti, NetScaler, SAP, Microsoft-Server u. v. m.), mit Suche, Kategorien und Schalter „Folgen“.
- Eigene Produkte per CPE.
- Mehrere Versionen pro Produkt (mit Bezeichnung und Anzahl), direkt in der Zeile bearbeitet; das Versionsformat wird je Hersteller geprüft.
- **Schwachstellen genau für die eingetragenen Versionen**: aus Palo-Alto-Advisory-JSON, Fortinet-CSAF und der NVD (CPE-Bereiche und CNA-Daten); CISA KEV und ENISA EUVD für „aktiv ausgenutzt“.
- Versionsvergleich je Schema (PAN-OS-Hotfixes, FortiOS, Cisco, Windows-Builds, VMware, Ivanti, allgemein). Nie fälschlich „nicht betroffen“ – sonst „möglicherweise betroffen“.
- Release-Linien, aktuellste Version und Support-/EOL-Daten von endoflife.date; Update- und EOL-Hinweise.
- Passende News je Produkt (gleiche CVE oder Produktname).
- **Neue Regel-Arten**: „Schwachstelle betrifft eines unserer Systeme“ und „Neue Version / EOL naht“ über die bestehenden Kanäle – einmal pro Produkt und Version, ohne Rückstand.
- **Einstellungen → Integrationen → Vendor News**: an/aus, Intervalle, NVD-API-Schlüssel (verschlüsselt gespeichert), „Jetzt abrufen“, „Katalog aktualisieren“ und der Zustand jeder Abfrage.

## 0.1.0 – erste Version

### Neu
- **News**: RSS-/Atom-Feeds von Presse, Behörden/CERTs, Herstellern und Research, dazu die JSON-Kataloge CISA KEV und ENISA EUVD.
- Schwere-Regeln, eine Meldung je URL, Titel oder CVE, Neu/Gelesen pro Person, Suche und Filter.
- **Anmeldung**: lokale Konten mit TOTP, Active Directory (LDAP), Entra ID (OIDC), Rollen admin/reader, Gruppen-Zuordnung, Notfall-Admin.
- **HTTPS** über den mitgelieferten nginx: selbstsigniert (automatisch erneuert), eigenes Zertifikat oder eigener Proxy davor.
- **Kanäle & Regeln**: E-Mail, Teams, Slack, Discord, Telegram, eigener Webhook (HMAC); jede Meldung einmal pro Kanal.
- **Desktop-Benachrichtigungen** im Hintergrund-Tab und **Web Push** bei geschlossenem Tab.
- Eigenes **Logo**, Anmeldeseite und Oberfläche (Seitenleiste, Einstellungen, Einrichtungsassistent).

### Sicherheit
- Schutz gegen Raten von Passwörtern und Password Spraying.
- Abruf der Feeds mit Schutz vor Zugriffen ins interne Netz (SSRF), Größen- und Zeitlimits.

### Betrieb
- Abruf mit bedingten Anfragen und Pausen.
