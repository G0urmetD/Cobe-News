---
title: Erste Schritte
summary: Was Cobe News macht, woher die Meldungen kommen, wer was darf und wie du dich in der Oberfläche zurechtfindest.
audience: all
---

## Was ist Cobe News? {#was-ist-cobe-news}

Cobe News sammelt Security-Nachrichten an einem Ort. Der Server ruft regelmäßig öffentliche Quellen ab, bewertet jede
Meldung und zeigt sie dir als Kachel – jede Meldung nur einmal, auch wenn mehrere Quellen sie bringen.

Die Meldungen kommen aus diesen Arten von Quellen:

| Art | Beispiele |
|---|---|
| Behörden & CERTs | BSI, CERT-EU, CERT.at, NCSC UK |
| Schwachstellen-Kataloge | [CISA KEV](term:kev), [ENISA EUVD](term:euvd), Microsoft Patchday |
| Hersteller-Hinweise ([PSIRT](term:psirt)) | Fortinet, Palo Alto Networks, Cisco, Siemens, Veeam |
| Research | Cisco Talos, Microsoft Threat Intelligence, Unit 42 |
| Presse | heise, golem.de, BleepingComputer, The Hacker News |

Welche Quellen eingeschaltet sind, legt ein Admin fest. Die vollständige Liste steht unter
[Eingebaute Quellen](/docs/news-quellen#eingebaute-quellen).

Was Cobe News für dich tut:

- **Schwere einschätzen** – jede Meldung bekommt eine Stufe von *Info* bis *Kritisch*, mit Begründung
  ([wie bewertet wird](/docs/news-quellen#schwere)).
- **Doppelte zusammenfassen** – dieselbe Meldung aus mehreren Quellen erscheint einmal, mit „auch bei …“.
- **Merken, was du gelesen hast** – pro Person, siehe [Neu und Gelesen](#gelesen).
- **Benachrichtigen** – als Desktop-Benachrichtigung im Browser oder (von Admins eingerichtet) per E-Mail, Teams,
  Slack, Discord, Telegram oder Webhook, siehe [Benachrichtigungen](/docs/benachrichtigungen#ueberblick). Bist du in
  einem Team, auch persönlich mit den Hersteller-News deiner Produkte.
- **Eure Systeme prüfen** – in [Vendor News](/docs/vendor-news#ueberblick) die Schwachstellen, die genau eure
  eingesetzten Produkte und Versionen betreffen.

> [!NOTE]
> Cobe News liest nur öffentliche Quellen. Es fragt keine eurer Systeme ab – welche Produkte und Versionen ihr einsetzt,
> tragen Admins in Vendor News selbst ein.

## News und Vendor News {#news-und-vendor-news}

In der Seitenleiste stehen unter *Analyse & Wissen* die beiden Hauptseiten:

| | News | Vendor News |
|---|---|---|
| Frage | Was passiert gerade in der Security-Welt? | Betrifft eine Schwachstelle unsere Systeme? |
| Inhalt | Meldungen aller eingeschalteten Quellen | Schwachstellen, neue Versionen und Support-Ende zu den Produkten, denen ihr folgt |
| Grundlage | Feeds und Kataloge | Hersteller-Hinweise, [NVD](term:nvd), CISA KEV, endoflife.date |
| Zahl in der Seitenleiste | ungelesene Meldungen (deine eigenen) | Produkte, die eine Schwachstelle betrifft (rot: eine davon wird aktiv ausgenutzt) |
| Gelesen-Status | pro Person | – |

**News** ist der breite Überblick: alles, was die Quellen veröffentlichen. **Vendor News** ist die gezielte Sicht auf
eure eigene Umgebung: Ein Admin wählt im Katalog die eingesetzten Produkte und trägt die Versionen ein, Cobe News
prüft dann jede Version einzeln – *betroffen*, *möglicherweise betroffen* oder *nicht betroffen*.

Beide Seiten hängen zusammen: Folgt ihr einem Produkt, zeigt eine passende News-Meldung „Betrifft deine Systeme“.
Mehr dazu im Kapitel [Vendor News & Katalog](/docs/vendor-news#ueberblick).

Darunter steht als dritter Punkt [*Beobachtete CVEs*](/watch): deine persönliche Liste einzelner CVEs, denen du folgst –
auch ohne Team und ohne gefolgtes Produkt ([CVEs beobachten](/docs/benachrichtigungen#cves-beobachten)).

## Rollen {#rollen}

Es gibt zwei Rollen. Welche du hast, steht unten in der Seitenleiste unter deinem Namen.

| Rolle | darf |
|---|---|
| **Leser** | News und Vendor News lesen, Meldungen als gelesen/ungelesen markieren, eigene Desktop-Benachrichtigungen einstellen, CVEs beobachten, das Support-Ende als Kalender abonnieren, eigenes Passwort und eigenen zweiten Faktor verwalten. In einem Team zusätzlich: die Hersteller-News der eigenen Produkte bekommen (mit Ruhezeiten, Abwesenheit und Wochenrückblick) und Meldungen ans Team weiterleiten |
| **Admin** | zusätzlich alles in den *Einstellungen*: Quellen und Integrationen, Produkte in Vendor News folgen und Versionen eintragen, Benachrichtigungskanäle und -regeln, Benutzer und Rollen, Teams, Anmeldung (AD, Entra ID), HTTPS, Sicherung, API-Tokens und Metriken |

- Für Admins ist ein zweiter Faktor ([TOTP](term:totp)) Pflicht, für Leser freiwillig, aber empfohlen.
- Leser sehen in der Seitenleiste keinen Punkt *Einstellungen*. Ihre persönlichen Seiten erreichen sie über das
  Benutzermenü: *Profil & Sicherheit* öffnet die Einstellungen, links unter *Persönlich* steht daneben
  *Benachrichtigungen*.
- Was du über ein Team bekommst, gibt es nur, wenn ein Admin *Teams* eingeschaltet und dich einem Team zugeordnet hat
  (meist über eine Gruppe im Verzeichnis).
- Meldet ihr euch mit Active Directory oder Entra ID an, entscheidet die Gruppe im Verzeichnis über die Rolle
  ([Gruppen und Rollen](/docs/anmeldung#gruppen-rollen)).

## Gelesen und ungelesen {#gelesen}

Ob du eine Meldung gelesen hast, gilt **pro Person** – was du liest, bleibt für deine Kolleginnen und Kollegen
ungelesen. Das gilt für die Meldungen unter *News* und für die Befunde unter *Vendor News*
([Vendor News: gelesen, stumm, Ansichten](/docs/vendor-news#vendor-lesen)).

- **Ungelesen** erkennst du an einem Punkt vor dem Titel und an der fetten Schrift.
- **Öffnen markiert als gelesen.** Die Meldung bleibt dabei in der Liste stehen, nur der Punkt verschwindet.
- Der Haken oben rechts auf der Kachel (oder „Als gelesen markieren“ in der Meldung) markiert, ohne zu öffnen. Ist sie
  schon gelesen, setzt derselbe Knopf (der Pfeil) sie mit **„Als ungelesen markieren“** zurück. Ein Hinweis unten bietet
  „Rückgängig“ an.
- Der Schalter **„Nur ungelesene“** blendet alles Gelesene aus – so arbeitest du die Liste ab wie einen Posteingang.

**Alles auf einmal:** „Alle als gelesen“ markiert alle ungelesenen Meldungen, die gerade zu Suche und Filtern passen.
Vorher fragt ein Dialog nach, wie viele es sind. Was erst danach eintrifft, bleibt ungelesen.

**Von selbst gelesen:** Was vor mehr als **30 Tagen** eingetroffen ist, zählt als gelesen. Ein neues Konto beginnt mit
allem gelesen – niemand startet mit tausenden ungelesenen Meldungen. Nur was du ausdrücklich „Als ungelesen markieren“
gewählt hast, bleibt ungelesen, auch wenn es älter ist.

> [!TIP]
> Erst nach Schwere filtern (z. B. *Info* und *Niedrig*), dann „Alle als gelesen“ – so räumst du Unwichtiges weg und
> die wichtigen Meldungen bleiben stehen.

Die Zahlen neben *News* und *Vendor News* in der Seitenleiste zeigen deine ungelesenen Meldungen und Befunde (ab 100 als
„99+“). Was du [stummgeschaltet](/docs/benachrichtigungen#stummschalten) hast, zählt dort nicht mit.

## Oberfläche {#oberflaeche}

### Seitenleiste {#seitenleiste}

- **News**, **Vendor News** und **Beobachtete CVEs** oben, **Einstellungen** unten (nur Admins), ganz unten dein
  **Benutzermenü**.
- Der Knopf links oben in der Kopfzeile klappt die Seitenleiste ein und aus (Tastatur: Strg+B bzw. ⌘+B). Eingeklappt
  bleiben nur die Symbole.

### Meldungen {#meldungen .admin}

Über *Einstellungen* zeigt ein Kasten **Meldungen** die drei neuesten Ereignisse der App selbst (keine News): wer sich
angemeldet hat, wer einem Produkt folgt oder eins zu Vendor News hinzugefügt hat, wer auf Freigabe wartet, wer ein Konto
angelegt, freigegeben, abgelehnt, deaktiviert oder zum Admin gemacht hat, eine zurückgespielte Sicherung. Deine eigenen
Aktionen stehen nicht darin; Anmeldungen kurz hintereinander werden zu einer Zeile („Anna und 2 weitere haben sich
angemeldet“). Wer auf Freigabe wartet, ist farbig hervorgehoben. Ein Klick führt an die passende Stelle – zum Produkt,
zu *Benutzer & Rollen* oder ins [Protokoll](/docs/betrieb#protokoll), gefiltert auf den Eintrag; **Alle im Protokoll**
öffnet das ganze. Der Kasten fragt jede Minute nach, solange der Tab sichtbar ist. Eingeklappt bleibt eine Glocke (mit
Punkt, solange jemand auf Freigabe wartet), die die Liste öffnet. Nur Admins sehen ihn.

### Benutzermenü {#benutzermenue}

Ein Klick auf deinen Namen unten in der Seitenleiste öffnet:

| Eintrag | Wozu |
|---|---|
| *Profil & Sicherheit* | Name, Passwort, zweiter Faktor – siehe [Eigenes Konto](#eigenes-konto) |
| *Sprache* | Deutsch oder English |
| *Darstellung* | Hell, Dunkel oder System (folgt der Einstellung des Betriebssystems) |
| *Dokumentation* | dieses Handbuch – Kapitel und Abschnitte für Admins sehen nur Admins |
| *Version & Changelog* | welche Version läuft und was sich geändert hat |
| *Abmelden* | beendet die Sitzung in diesem Browser |

Sprache und Darstellung merkt sich der **Browser**, nicht dein Konto. Auf einem anderen Rechner wählst du sie neu.
Die Texte der Meldungen selbst übersetzt Cobe News nicht – sie erscheinen in der Sprache der Quelle.

> [!TIP]
> Nenne die Nummer aus *Version & Changelog*, wenn sich nach einem Update etwas anders verhält. Diese Installation
> läuft gerade mit Version {{version}}.

### Suche und Filter {#suche-filter}

Über den Kacheln der News-Seite:

- **Suchfeld** („Titel, Text, CVE …“) – sucht in Titel, Zusammenfassung und CVE-Nummern; Groß-/Kleinschreibung und
  Akzente spielen keine Rolle.
- **Quelle** und **Schwere** – Mehrfachauswahl, z. B. nur *Kritisch* und *Hoch* aus zwei bestimmten Quellen.
  „Filter zurücksetzen“ hebt beides auf.
- **Nur ungelesene** und **Stummgeschaltete zeigen** – zwei Schalter darunter.
- Die Filter stehen in der Adresse der Seite: ein Lesezeichen oder ein geteilter Link öffnet genau diese Auswahl.

Einzelheiten zu Kacheln und Meldungen: [News lesen](/docs/news-quellen#news-lesen).

### Ansichten {#ansichten}

Eine Filterwahl, die du oft brauchst, speicherst du als **Ansicht** – auf *News* und auf *Vendor News*, je Seite bis zu
30, Namen bis 60 Zeichen. Der Knopf **Ansichten** neben den Filtern öffnet die Liste:

| Aktion | Wirkung |
|---|---|
| Name eingeben, *Speichern* | die aktuellen Filter unter diesem Namen |
| Klick auf den Namen | die Filter der Ansicht anwenden |
| Stern | **Standard** dieser Seite: öffnet sich, wenn du die Seite ohne Filter aufrufst (z. B. über die Seitenleiste) |
| Stift, Papierkorb | umbenennen, löschen |
| *Link kopieren* | die Adresse mit den Filtern – wer sie öffnet, sieht dieselben Filter |

Ansichten gehören deinem Konto und gelten auf jedem Rechner. Ein geteilter Link überträgt nur die Filter, nicht die
Ansicht selbst; was die Empfängerin sieht, hängt von ihrem eigenen Gelesen-Stand ab.

### Zeitangaben {#zeitangaben}

Zeiten stehen relativ da („vor 5 Minuten“). Fährst du mit der Maus darüber, siehst du Ortszeit und UTC – mit einem
Knopf, der den UTC-Zeitstempel kopiert (praktisch für Tickets und Berichte).

### Links auf eine Meldung {#links}

Eine geöffnete Meldung steht in der Adresse des Browsers. Diese Adresse kannst du kopieren und weitergeben – wer sie
öffnet (und angemeldet ist), sieht dieselbe Meldung. Desktop-Benachrichtigungen und Links in E-Mails öffnen eine
Meldung genauso.

## Eigenes Konto {#eigenes-konto}

Unter *Profil & Sicherheit* (Benutzermenü oder [direkt](/settings/profile)) verwaltest du dein Konto.

### Passwort ändern {#passwort}

Nur für lokale Konten. Meldest du dich mit Active Directory an, änderst du das Passwort dort; mit Microsoft (Entra ID)
verwaltet Microsoft es.

1. *Profil & Sicherheit* öffnen und „Passwort ändern“ wählen.
2. Aktuelles Passwort und das neue Passwort eingeben, „Speichern“.
3. Andere Browser, in denen du angemeldet bist, werden abgemeldet.

Regeln für das neue Passwort: mindestens 12 Zeichen, nicht zu häufig, nicht der Benutzername und nicht das bisherige
Passwort.

### Zweiter Faktor (TOTP) {#totp}

Der zweite Faktor ist ein 6-stelliger Code aus einer Authenticator-App (z. B. Microsoft Authenticator). Für Admins
ist er Pflicht, für Leser freiwillig.

1. *Profil & Sicherheit* öffnen, Reiter *Anmeldung & Sicherheit*, bei *Zweiter Faktor* auf „Authenticator-App“ klicken.
2. Mit deinem Passwort bestätigen, dass du es bist.
3. In der App den QR-Code scannen (oder den Schlüssel abtippen).
4. Den angezeigten Code eingeben.

Mit „Neu einrichten“ wechselst du auf ein neues Telefon; der alte Schlüssel gilt, bis du den ersten neuen Code
bestätigt hast. Leser können den zweiten Faktor mit „Entfernen“ wieder abschalten. Bei Anmeldung mit Microsoft
verlangt Microsoft selbst den zweiten Faktor – dann gibt es hier nichts einzurichten.

> [!WARNING]
> Telefon verloren? Ein Admin kann deinen zweiten Faktor zurücksetzen
> ([Lokale Benutzer](/docs/anmeldung#lokale-benutzer)).

### Passkeys {#passkeys}

Mit einem [Passkey](term:passkey) meldest du dich ohne Passwort an: Dein Gerät (Laptop, Handy oder
Sicherheitsschlüssel) fragt nach Fingerabdruck, Gesicht oder PIN, und du bist drin. Das zählt als zwei Faktoren –
Passwort und TOTP-Code entfallen. Nur für lokale Konten; mit Active Directory oder Microsoft meldest du dich weiter dort
an.

1. *Profil & Sicherheit* öffnen, Reiter *Anmeldung & Sicherheit*, bei *Passkeys* auf „Passkey hinzufügen“ klicken.
2. Einen Namen vergeben (z. B. „Laptop“) und „Passkey erstellen“ wählen. Hast du dich nicht gerade erst angemeldet,
   bestätigst du vorher mit Passwort (und Code), dass du es bist.
3. Der Browser fragt nach Fingerabdruck, Gesicht oder PIN – oder nach einem Sicherheitsschlüssel oder dem Handy.

Danach auf der Anmeldeseite „Mit Passkey anmelden“ wählen – ein Benutzername ist nicht nötig. Bis zu 10 Passkeys je
Konto; „Umbenennen“ und „Entfernen“ stehen in der Liste. Entfernen fragt erneut, ob du es bist, und meldet alle
Sitzungen ab, die mit diesem Passkey angemeldet sind. Auf dem Gerät selbst bleibt der Passkey gespeichert, bis du ihn
dort löschst.

- Passkeys gehen nur unter der eingerichteten Adresse ({{base_url}}) und nur über HTTPS. Unter einer anderen Adresse
  (z. B. der IP-Adresse des Servers) erscheint der Knopf nicht.
- Zeigt ein Passkey *Prüfen*, ist sein Zähler zurückgegangen – vielleicht wurde er kopiert. Entferne ihn und richte
  einen neuen ein.
- Gerät verloren? Melde dich mit Passwort an und entferne den Passkey – oder bitte einen Admin darum.

### Abmelden und Sitzungen {#abmelden}

- *Abmelden* im Benutzermenü beendet die Sitzung in diesem Browser. Hast du dort „Push bei geschlossenem Tab“
  eingeschaltet, endet auch das für diesen Browser.
- Eine Sitzung läuft ab, wenn du eine Weile nichts tust (ab Werk nach 60 Minuten), und spätestens nach einer festen
  Zeit (ab Werk 12 Stunden). Danach meldest du dich neu an. Die Zeiten legt ein Admin fest
  ([Sitzungen](/docs/anmeldung#sitzungen)).
- Alle Tabs gemeinsam: Meldest du dich in einem Tab ab oder ist die Sitzung abgelaufen, gehen alle Tabs dieses Browsers
  zur Anmeldung – auch einer, in dem du gerade nichts tust; was er zeigte, ist weg. Zwei Minuten vor dem Ablauf wegen
  Inaktivität erscheint „Deine Sitzung läuft bald ab“, *Angemeldet bleiben* verlängert sie. Meldest du dich in einem Tab
  wieder an, sind die anderen auch wieder drin ([Alle Tabs gemeinsam](/docs/anmeldung#sitzungen-tabs)).
- Nach mehreren falschen Passwörtern wird das Konto für einige Minuten gesperrt. Die Meldung beim Anmelden sagt, wie
  viele Versuche bleiben.
- **Meine Sitzungen** (*Profil & Sicherheit*, Reiter *Meine Sitzungen*) zeigt, wo dein Konto gerade angemeldet ist:
  Browser und System (grob aus dem Browser gelesen, sonst *Unbekanntes Gerät*), die Anmeldeart (Passwort, Passwort +
  TOTP, Passkey, Active Directory, Microsoft), seit wann, zuletzt aktiv (nur alle paar Minuten aktualisiert) und die
  volle IP-Adresse. *Diese Sitzung* ist die, in der du gerade bist. „Abmelden“ beendet eine andere Sitzung sofort,
  „Alle anderen abmelden“ alle außer dieser. *Anmeldung nicht abgeschlossen* heißt: Dort wurde dein Passwort eingegeben,
  der Code fehlt noch – warst du das nicht, ändere dein Passwort.

### Desktop-Benachrichtigungen {#desktop-kurz}

Unter [*Einstellungen → Benachrichtigungen*](/settings/notifications) stellst du ein, was dich erreicht – das gilt nur
für dich. Die Seite hat bis zu drei Reiter:

| Reiter | Wozu |
|---|---|
| *Neue Meldungen* | ob und für welche Meldungen dein Browser dich benachrichtigt – [Desktop-Benachrichtigungen](/docs/benachrichtigungen#desktop) |
| *Hersteller-News meiner Produkte* | nur in einem Team (oder mit einer beobachteten CVE): Vendor News deiner Produkte per E-Mail, Desktop-Push oder Microsoft Teams, mit Ruhezeiten, Abwesenheit und Wochenrückblick – [mehr](/docs/benachrichtigungen#meine-produkte) |
| *Kalender* | das Support-Ende eurer Versionen als Kalender-Abo – [Kalender (iCal)](/docs/benachrichtigungen#kalender-ical) |

## Was ist neu {#was-ist-neu}

Die wichtigsten Funktionen der letzten Versionen auf einen Blick, jeweils mit dem Abschnitt, der sie erklärt. Alle
Einzelheiten zu jeder Version stehen im Benutzermenü unter *Version & Changelog*.

| Seit | Funktion | Wo | Mehr |
|---|---|---|---|
| 0.1.26 | **EPSS und SSVC** – wie wahrscheinlich eine Lücke ausgenutzt wird, Einstufung der CISA | Befunde in Vendor News, Details einer Meldung | [EPSS und SSVC](/docs/vendor-news#epss-ssvc) |
| 0.1.28 | **Mein Team / Alle** – nur die Produkte, die du über dein Team bekommst | Vendor News, über der Übersicht | [Mein Team](/docs/vendor-news#mein-team) |
| 0.1.30 | **Hersteller-News meiner Produkte** – per E-Mail, Desktop-Push oder eigenem Teams-Webhook | *Einstellungen → Benachrichtigungen* | [Hersteller-News meiner Produkte](/docs/benachrichtigungen#meine-produkte) |
| 0.1.33 | **Advisory-Änderungen** – was ein Hersteller nachträglich geändert hat, mit Wirkung auf eure Versionen | Vendor News, Reiter *Änderungen* im Produkt | [Änderungen an Advisories](/docs/vendor-news#aenderungen) |
| 0.1.34 | **CVEs beobachten** – einzelnen CVEs folgen, auch ohne Team | Stern an der CVE, Seitenleiste *Beobachtete CVEs* | [CVEs beobachten](/docs/benachrichtigungen#cves-beobachten) |
| 0.1.34 | **Vorwarnung vor dem Support-Ende** – 90 und 30 Tage vorher | Regeln und persönliche Wege mit *Versionen & EOL* | [Vorwarnung](/docs/vendor-news#eol-vorwarnung) |
| 0.1.34 | **Kalender (iCal)** – Support-Ende in Outlook & Co. abonnieren | *Einstellungen → Benachrichtigungen → Kalender* | [Kalender (iCal)](/docs/benachrichtigungen#kalender-ical) |
| 0.1.36 | **Dringlichkeit** – eine Zahl von 0 bis 100 mit Stufe *Sofort*, *Bald*, *Beobachten* | Karten, Liste und Schublade in Vendor News | [Dringlichkeit](/docs/vendor-news#dringlichkeit) |
| 0.1.36 | **An mein Team weiterleiten** – eine Meldung oder einen Befund mit Kommentar | „Ans Team weiterleiten“ in Meldung und Befund | [Weiterleiten](/docs/benachrichtigungen#weiterleiten) |
| 0.1.36 | **Ruhezeiten**, **Abwesenheit mit Vertretung**, **Wochenrückblick** | *Hersteller-News meiner Produkte*, eigene Reiter | [Ruhezeiten](/docs/benachrichtigungen#ruhezeiten), [Abwesenheit](/docs/benachrichtigungen#abwesenheit), [Wochenrückblick](/docs/benachrichtigungen#wochenrueckblick) |

### Neu für Admins {#was-ist-neu-admin .admin}

| Seit | Funktion | Wo | Mehr |
|---|---|---|---|
| 0.1.26 | **Weitere Quellen**: CSAF-Hinweise von Siemens, Cisco und Schneider Electric, cvelistV5, EPSS, OSV | *Integrationen → Vendor News → Weitere Quellen* | [Weitere Quellen](/docs/integrationen#weitere-quellen) |
| 0.1.26 | **Sichere Webhook- und SMTP-Ziele** – Loopback, Metadaten-Adresse und Multicast immer gesperrt | Kanäle | [Erlaubte Ziele](/docs/benachrichtigungen#webhook-ziele) |
| 0.1.28 | **Teams** – Gruppen aus AD/Entra binden, Mitglieder sofort laden, Produkte je Team, Regeln auf Teams beschränken | *Einstellungen → Teams* | [Teams](/docs/anmeldung#teams) |
| 0.1.30 | **Wer bekommt was** – Produkte pro Person; persönliche Wege freigeben | Team → *Produkte*; *Teams → Einstellungen* | [Wer bekommt was?](/docs/anmeldung#teams-zuteilung), [Persönliche Benachrichtigungen](/docs/anmeldung#teams-persoenlich) |
| 0.1.33 | **Regelart „Advisory geändert“** | *Kanäle & Regeln → Regeln* | [Arten](/docs/benachrichtigungen#regel-arten) |
| 0.1.33 | **Dauerhaft sperren** und **Rolle sofort entziehen** | *Benutzer & Rollen* | [Verwalten](/docs/anmeldung#benutzer-verwalten), [Zuordnung entfernen](/docs/anmeldung#gruppen-entfernen) |
| 0.1.36 | **Weiterleitungs-Kanal** und **Wochenrückblick** je Team, Abwesenheiten der Mitglieder | Team → *Allgemein*, *Wochenrückblick*, *Mitglieder* | [Weiterleitungs-Kanal](/docs/anmeldung#teams-weiterleiten), [Wochenrückblick](/docs/anmeldung#teams-wochenrueckblick) |
| 0.1.37 | **API-Tokens**, **API-Referenz** und **Metriken für Prometheus** | *Einstellungen → API & Metriken* | [API & Metriken](/docs/api#ueberblick) |
| 0.1.37 | **Rücksicherungs-Test** – die neueste Sicherung wöchentlich zur Probe zurückspielen | *Sicherung & Export → Rücksicherungs-Test* | [Rücksicherungs-Test](/docs/sicherung#ruecksicherungs-test) |
