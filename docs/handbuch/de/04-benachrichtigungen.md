---
title: Benachrichtigungen
summary: Desktop-Benachrichtigungen im Browser für jede Person, dazu Kanäle (Teams, Slack, Discord, Telegram, Mattermost, ntfy, Gotify, E-Mail, Webhook), Regeln und das Zustellprotokoll für Admins.
audience: all
---

## Überblick {#ueberblick}

Cobe News meldet neue Meldungen auf zwei Wegen:

| | Desktop-Benachrichtigungen | Kanäle & Regeln |
|---|---|---|
| Für wen | jede Person für sich (Leser und Admins) | das Team – eingerichtet von Admins |
| Wo einstellen | *Einstellungen → Benachrichtigungen* | *Einstellungen → Kanäle & Regeln* |
| Wohin | Systembenachrichtigung dieses Browsers | Teams, Slack, Discord, Telegram, Mattermost, ntfy, Gotify, E-Mail oder ein eigener Webhook |
| Was | neue Security-Meldungen aus dem News-Feed | Security-Meldungen, Vendor News und Zustand der Quellen |

- **Desktop:** Du wählst Schweregrade, Quellen, Themen und auf Wunsch Systeme und Schlagwörter – „nur Palo Alto, nur
  Kritisch“ geht auch ohne Admin. Der Browser zeigt neue Meldungen als Systembenachrichtigung – im offenen Tab und auf
  Wunsch auch bei geschlossenem Tab (Web Push).
- **Kanäle** sagen, *wohin* eine Nachricht geht. **Regeln** sagen, *was* an welche Kanäle geht. Eine Regel kann an
  mehrere Kanäle schicken, ein Kanal kann von mehreren Regeln genutzt werden.

Beide Wege sind unabhängig voneinander: Eine Regel ändert nichts an deinen Desktop-Benachrichtigungen und umgekehrt.

Dazu kommen Wege, die nur dich betreffen:

| Was | Für wen | Wo | Mehr |
|---|---|---|---|
| Hersteller-News deiner Produkte – per E-Mail, Desktop-Push oder Microsoft Teams, mit Ruhezeiten, Abwesenheit und Wochenrückblick | Mitglieder eines Teams, wenn ein Admin die Wege freigegeben hat | *Einstellungen → Benachrichtigungen*, Reiter *Hersteller-News meiner Produkte* | [Hersteller-News meiner Produkte](#meine-produkte) |
| Security-Meldungen nach eigener Auswahl – per E-Mail oder Microsoft Teams | jede Person, wenn ein Admin es erlaubt hat | *Einstellungen → Benachrichtigungen*, Reiter *Security-Meldungen* | [Security-Meldungen per E-Mail oder Teams](#security-meldungen) |
| Neues zu einzelnen CVEs (Fix, KEV, EPSS, zurückgezogen) | jede Person | Stern an einer CVE, Seitenleiste *Beobachtete CVEs* | [CVEs beobachten](#cves-beobachten) |
| Support-Ende als Kalender-Abo | jede Person (Leser: die Produkte aus dem Team) | *Einstellungen → Benachrichtigungen*, Reiter *Kalender* | [Kalender (iCal)](#kalender-ical) |
| Eine Meldung mit Kommentar an dein Team schicken | Mitglieder eines Teams mit Weiterleitungs-Kanal | „Ans Team weiterleiten“ in Meldung und Befund | [An mein Team weiterleiten](#weiterleiten) |

## Desktop-Benachrichtigungen {#desktop}

Die Einstellungen gelten für dein Konto. Der Zustand (Berechtigung, Push) gilt für den Browser, in dem du gerade bist.

### Einschalten {#desktop-einschalten}

1. Öffne Cobe News über die https-Adresse, z. B. {{base_url}}.
2. Gehe zu [*Einstellungen → Benachrichtigungen*](/settings/notifications).
3. Schalte „Desktop-Benachrichtigungen“ ein. Der Browser fragt nach der Erlaubnis – stimme zu.
4. Wähle die **Schweregrade** (ab Werk Kritisch und Hoch), die **Quellen** und die **Themen**. Leer heißt: alle.
5. Klicke „Speichern“.

**Themen** ([was sie bedeuten](/docs/news-quellen#themen)): Eines der gewählten genügt, zusammen mit Schwere und
Quelle – „Aktiv ausgenutzt, Exploit veröffentlicht“ mit allen Schweregraden meldet jede Meldung mit einem der beiden
Themen. Es zählt das Thema, das die Meldung **beim Eintreffen** hat (aus Titel, Anrisstext, Quelle und dem
KEV-Katalog). Ein Thema, das erst später dazukommt – etwa aus den Details aus der Quelle –, löst keine
Desktop-Benachrichtigung mehr aus; dafür gibt es [Regeln](#regel-themen), die so eine Meldung dann nachreichen. Der
offene Tab und Push bei geschlossenem Tab filtern gleich.

**Was die Benachrichtigung zeigt**: Unter dem Titel stehen die Schwere (mit CVSS, wenn die Meldung einen nennt),
„ausgenutzt“, wenn die Lücke angegriffen wird, die Produkte, um die es geht, und die Quelle – etwa „Kritisch (CVSS 9.2)
· ausgenutzt · PAN-OS, Prisma Cloud · BSI“. Hat die Meldung keine eigene Schwere, fehlt sie. Kommen mehr Meldungen auf
einmal, nennt die Sammel-Benachrichtigung die höchste Schwere und die Produkte.

**Systeme, Schlagwörter und „Nicht anzeigen, wenn enthalten“** – wie bei den [Regeln](#regel-systeme), nur für dich:

- **Systeme**: Hersteller („Alle Produkte von Palo Alto Networks“) oder einzelne Produkte aus dem ganzen Katalog – oder
  ganz oben [Unsere Produkte (aus Vendor News)](#regel-systeme): alle gefolgten Produkte, auch später hinzugefügte.
- **Schlagwörter**: eigene Wörter als Chips (Enter oder Komma), ganze Wörter in Titel oder Teaser, Groß-/Kleinschreibung
  egal, reiner Text (höchstens 30, je 2–60 Zeichen).
- Systeme **oder** Schlagwörter – eines genügt, zusammen mit Schwere, Quelle und Thema.
- **Nicht anzeigen, wenn enthalten**: Steht ein solches Wort in Titel oder Teaser, kommt keine Benachrichtigung.
- Die Benachrichtigung sagt dann, warum sie kommt: „Kritisch · Treffer: PAN-OS · heise online“.
- Es zählt, was die Meldung **beim Eintreffen** hat – vor allem, was Titel und Teaser nennen. Ein System, das erst
  später aus den Details aus der Quelle dazukommt, löst keine Desktop-Benachrichtigung mehr aus (wie ein Thema); eine
  [Regel](#regel-systeme) reicht so eine Meldung nach.
- Gefiltert wird auf dem Server: der offene Tab und Push bei geschlossenem Tab bekommen nur, was passt.

Darunter zeigt die Karte „Zustand in diesem Browser“:

| Zeile | Bedeutung |
|---|---|
| Berechtigung | „Erteilt“, „Blockiert“ oder „Noch nicht gefragt“ (dann mit dem Knopf „Im Browser erlauben“). |
| Hintergrund-Tab | „Hintergrund-Tab: aktiv“ mit der Zeit der letzten Abfrage – oder warum nicht (z. B. „Erst speichern“). |
| Push bei geschlossenem Tab | Schalter für Web Push in diesem Browser: „Aktiv“, „Aus“, „Nicht verfügbar“ (mit Grund) oder „Zustellung gestört“. |

Hat der Browser Benachrichtigungen blockiert, erlaubst du sie in den Website-Einstellungen des Browsers (Schloss-Symbol
in der Adressleiste).

### Offener Tab und Push bei geschlossenem Tab {#desktop-push}

**Offener Tab (immer):** Solange Cobe News in einem Tab offen ist – auch im Hintergrund, im minimierten Fenster oder
hinter einer anderen App –, fragt einer der Tabs etwa einmal pro Minute nach neuen Meldungen. Jede Meldung erscheint
nur einmal, auch bei mehreren Tabs. Ein Klick öffnet sie. Friert der Browser einen Tab ein, übernimmt ein anderer;
kommst du zurück, wird sofort nachgeholt. Nichts geht verloren, nichts kommt doppelt – auch nach einem Neuladen.

**Push bei geschlossenem Tab (optional, pro Browser):** Mit dem Schalter „Push bei geschlossenem Tab“ schickt der Server
neue Meldungen über den Push-Dienst des Browser-Herstellers (Google, Mozilla, Apple, Microsoft). Sie kommen dann auch,
wenn kein Tab offen ist – solange der Browser läuft.

- Der Inhalt (Titel, Schwere, Quelle, Link) ist Ende-zu-Ende verschlüsselt. Der Push-Dienst sieht nur die Größe.
- Der Schalter geht erst, wenn Desktop-Benachrichtigungen eingeschaltet und gespeichert sind und der Browser sie nicht
  blockiert.
- Ist Push in diesem Browser aktiv, zeigt der offene Tab keine eigenen Benachrichtigungen – es gibt keine doppelten.
- Höchstens 10 Browser pro Person; ein elfter ersetzt den ältesten.
- Abmelden schaltet Push für diesen Browser ab. Ein deaktiviertes Konto bekommt nichts. Eine bloß abgelaufene Sitzung
  beendet Push nicht.

Für beide Wege gilt: Bis zu drei Meldungen einer Runde kommen einzeln, mehr als eine Zusammenfassung
(„N weitere neue Meldungen“). „Kritisch“ bleibt stehen, bis du sie wegklickst. Desktop-Benachrichtigungen zeigen nur
Security-Meldungen aus dem News-Feed; Vendor News und den Zustand der Quellen gibt es über Kanäle und Regeln – die
Vendor News deiner eigenen Produkte auch über [Hersteller-News meiner Produkte](#meine-produkte).

### Test-Benachrichtigung {#desktop-test}

1. Klicke „Test-Benachrichtigung“ (geht erst, wenn die Berechtigung erteilt ist).
2. Wechsle in einen anderen Tab oder eine andere App. Die Benachrichtigung kommt nach **5 Sekunden**.
3. Lies das Ergebnis auf der Karte.

Der Test nimmt denselben Weg wie die echten Meldungen: über Web Push, wenn Push in diesem Browser aktiv ist, sonst über
den Tab. Die Karte sagt danach:

- „Test zugestellt“ – der Browser hat die Meldung an das System übergeben. Siehst du trotzdem nichts, liegt es an den
  Systemeinstellungen (siehe unten).
- „Der Browser hat die Anzeige verweigert“ – mit dem Grund des Browsers.
- Keine Rückmeldung nach 20 Sekunden – bei Push erreicht der Server den Push-Dienst vermutlich nicht (ausgehender
  Zugriff, Proxy, Firewall), oder der Browser ist offline.

Die Systemeinstellungen entscheiden, ob und wie Benachrichtigungen erscheinen:

- macOS: *Systemeinstellungen → Mitteilungen →* den Browser erlauben, Fokus bzw. „Nicht stören“ aus.
- Windows: *Einstellungen → System → Benachrichtigungen →* den Browser einschalten, „Nicht stören“ aus.

### Voraussetzungen {#desktop-voraussetzungen}

- **HTTPS.** Benachrichtigungen gehen nur über https (oder localhost).
- **Ein Zertifikat, dem dein Computer vertraut** – nur für Push nötig. Zeigt der Browser eine Zertifikatswarnung,
  verweigert er den Service Worker. Push ist dann „Nicht verfügbar“; der offene Tab benachrichtigt trotzdem. Abhilfe:
  das Zertifikat als vertrauenswürdig hinterlegen oder eines der eigenen CA verwenden
  (siehe [HTTPS](/docs/betrieb#https)).
- **Der Server erreicht die Push-Dienste** (ausgehend https). Das richtet ein Admin ein, siehe
  [Web Push](/docs/integrationen#web-push). Ist Web Push auf dem Server aus (`WEB_PUSH=0`), steht das als Grund da.
- **Der Browser läuft.** Chrome und Edge laufen meist im Hintergrund weiter, Firefox muss offen sein. Safari kann
  Web Push ab macOS 13.

### Tipp für macOS: Benachrichtigungen auf dem Hauptdisplay {#desktop-macos}

macOS zeigt Mitteilungen nur auf dem **Hauptdisplay**. Arbeitest du mit mehreren Bildschirmen und siehst nichts, schau
auf den anderen Bildschirm – oder lege den Bildschirm, auf den du schaust, als Hauptdisplay fest:

1. *Systemeinstellungen → Displays* öffnen.
2. Den gewünschten Bildschirm wählen.
3. Bei „Verwenden als“ die Option „Hauptdisplay“ wählen.

## Hersteller-News meiner Produkte {#meine-produkte}

Bist du in einem [Team](/docs/anmeldung#teams) und sind dir Produkte zugeteilt, kannst du dir deren Vendor News selbst
schicken lassen: per **E-Mail**, als **Desktop-Push** oder in **Microsoft Teams**. Den Bereich gibt es nur, solange Teams
eingeschaltet ist und du in einem Team bist – oder eine [CVE beobachtest](#cves-beobachten).

### Einschalten {#meine-produkte-einschalten}

1. Gehe zu [*Einstellungen → Benachrichtigungen*](/settings/notifications?tab=vendor), Reiter *Hersteller-News meiner
   Produkte*.
2. Oben stehen **Meine Produkte** – welche das sind, legt ein Admin im Team fest.
3. Schalte die gewünschten Wege ein:
   - **E-Mail** geht an die Adresse deines Kontos (sie steht dabei). Hat dein Konto keine, lässt sich der Schalter
     nicht einschalten.
   - **Desktop** nutzt deine Browser mit „Push bei geschlossenem Tab“ ([oben](#desktop-push)). Schalte das dort zuerst
     ein.
   - **Microsoft Teams** braucht deinen eigenen Workflows-Webhook ([unten](#meine-produkte-teams)).
4. Wähle, **was** kommt: *Schwachstellen*, *Versionen & EOL* und/oder *[Advisory geändert](/docs/vendor-news#aenderungen)*,
   und ab welcher **Schwere** Schwachstellen und Advisory-Änderungen kommen. Ab Werk sind *Schwachstellen* und
   *Versionen & EOL* an, *Advisory geändert* ist aus, und es kommen alle Schweregrade.
5. Klicke „Speichern“.

Steht bei einem Weg „Vom Admin ausgeschaltet“, hat ein Admin ihn nicht freigegeben. Unter jedem eingeschalteten Weg
steht, wann zuletzt etwas zugestellt wurde – oder der letzte Fehler und wann es erneut versucht wird.

### Eigenen Teams-Webhook anlegen {#meine-produkte-teams}

Teams nimmt die Nachrichten über einen **Workflow** an, den du selbst anlegst. Er schreibt in einen Chat.

1. Öffne in Teams die App **Workflows** (links in der Leiste, sonst über „…“ → *Workflows*).
2. Wähle die Vorlage **„Send webhook alerts to a chat“** oder **„Post to a chat when a webhook request is received“**
   (in deutschem Teams sinngemäß übersetzt, z. B. „Webhookwarnungen an einen Chat senden“).
3. Gib einen Namen ein (z. B. „Cobe News“), bestätige die Verbindung mit deinem Konto und klicke „Weiter“.
4. Wähle den Chat, in dem die Karten erscheinen sollen – zum Beispiel den Chat mit dem Workflows-Bot –, und klicke
   „Workflow hinzufügen“.
5. Kopiere die angezeigte URL.
6. In Cobe News: **Microsoft Teams** einschalten, die URL bei *Workflow-URL* einfügen, „Speichern“, dann
   **„Test senden“**. Eine Testkarte erscheint im Chat.

> [!NOTE]
> Es werden nur Adressen von Microsoft angenommen: `*.logic.azure.com`, `*.powerplatform.com` und
> `*.webhook.office.com`, nur über https (Port 443) und nur öffentliche Ziele. Andere Adressen lehnt Cobe News ab.

- Die URL ist ein Geheimnis: Wer sie kennt, kann in deinen Chat schreiben. Cobe News speichert sie verschlüsselt und
  zeigt danach nur noch den Host. Zum Ändern fügst du eine neue URL ein; „URL entfernen“ löscht sie.
- Der Workflow läuft unter deinem Konto. Wird es deaktiviert oder löschst du den Workflow, kommt nichts mehr an – der
  Bereich zeigt dann den Fehler.
- „Test senden“ geht höchstens alle 10 Sekunden.

### Was kommt und wann {#meine-produkte-was}

- **Nur Neues.** Du bekommst, was nach dem Einschalten eines Wegs und nach der Zuteilung des Produkts dazukommt. Ältere
  Meldungen und alles aus dem ersten Prüfen eines Produkts kommen nicht.
- **Nur diese Systeme.** Unter der Schwere wählst du auf Wunsch Hersteller oder Produkte aus deinen Produkten – dann
  kommen nur deren Hersteller-News („Alle Produkte von Palo Alto Networks“ umfasst auch Produkte, die dir später
  zugeordnet werden). Leer heißt: alle deine Produkte. Wie bei den Systemen einer Regel für Vendor News zählt das
  Produkt der Meldung – es steht ohnehin in jeder Nachricht. Schlagwörter gibt es hier nicht; sie gelten für
  Security-Meldungen ([Desktop-Benachrichtigungen](#desktop-einschalten)). „Unsere Produkte“ gibt es hier nicht – es gibt
  Hersteller-News nur zu gefolgten Produkten, das wäre dasselbe wie leer. Beobachtete CVEs kommen immer.
- **Filter.** Was dein Filter (Art, Schwere, Systeme) einmal ausgelassen hat, kommt auch nach einer Änderung des Filters
  nicht nach.
- **Stumm.** Was du [stummgeschaltet](#stummschalten) hast, kommt nicht – auch nicht, wenn die Stummschaltung endet.
- **Gesammelt.** Mehrere Meldungen einer Runde kommen zusammen: eine Mail, eine Karte, ein Push mit „N neue
  Hersteller-News“. Höchstens 100 pro Runde, die schwersten zuerst; der Rest kommt in der nächsten Runde.
- **Große Teams.** Bei sehr vielen Empfängern verteilt Cobe News den Versand auf mehrere Runden: höchstens 2000
  Nachrichten und etwa 30 Sekunden pro Runde. Wer am längsten wartet, kommt zuerst dran. Die nächste Runde folgt
  sofort, und die übrigen Aufgaben (News, Vendor News, Push) laufen dazwischen weiter.
- **Genau einmal.** Jede Meldung kommt pro Weg höchstens einmal – auch nach einem Neustart. Lehnt der Server ab (z. B.
  E-Mail-Server nicht erreichbar), versucht Cobe News es später mit wachsender Pause erneut. Nach einem Fehler, bei dem die
  Nachricht angekommen sein könnte (z. B. Zeitüberschreitung), nicht.
- Ein Klick in der Nachricht öffnet die Meldung in [Vendor News](/docs/vendor-news).
- **Support-Ende.** Mit *Versionen & EOL* kommen auch die [Vorwarnungen](/docs/vendor-news#eol-vorwarnung) 90 und 30
  Tage vor dem Support-Ende jeder eingetragenen Version deiner Produkte.

### Ruhezeiten und Dringendes {#ruhezeiten}

Unter [*Hersteller-News meiner Produkte*](/settings/notifications?tab=vendor&part=quiet), Reiter **Ruhezeiten**, legst du
fest, wann dich Normales nicht stören soll. Ab Werk ist alles aus – dann kommt alles sofort, wie bisher.

- **Ruhezeiten**: ein Zeitfenster, z. B. 18:00–08:00 (über Mitternacht), und auf Wunsch **das ganze Wochenende**.
  In dieser Zeit wird Normales gesammelt. Am Ende der Ruhezeit kommt es als **eine** Sammelnachricht pro Weg.
- **Zeitzone**: ab Werk *Europe/Berlin*. Die Uhrzeiten gelten in dieser Zone – auch über die Umstellung auf Sommer- und
  Winterzeit hinweg (08:00 bleibt 08:00 Ortszeit).
- **Dringend kommt trotzdem sofort.** Was dringend ist, wählst du; ab Werk alle vier:
  - Schwere **kritisch**,
  - Aufnahme in **[CISA KEV](term:kev)** bzw. aktiv ausgenutzt,
  - eine **eigene Version ist jetzt betroffen** (eine [Advisory-Änderung](/docs/vendor-news#aenderungen) mit Wirkung),
  - eine **[beobachtete CVE](#cves-beobachten)**.
- **Desktop-Push** kommt in der Ruhezeit nur für Dringendes.
- **Zustellung pro Weg**: *Sofort* (ab Werk) oder **Gesammelt um HH:MM**. Dann wartet Normales auf diesem Weg bis zur
  Uhrzeit und kommt einmal am Tag zusammen. Gibt es die Uhrzeit an einem Tag nicht (Umstellung auf Sommerzeit, z. B.
  02:30), kommt die Sammlung direkt nach der Lücke; gibt es sie doppelt, nur beim ersten Mal.

Auch hier gilt: jede Meldung pro Weg genau einmal, und was wartet, zählt nicht gegen die Grenzen einer Runde.

### Abwesenheit und Vertretung {#abwesenheit}

Bist du nicht da, gehen die Hersteller-News deiner Produkte an eine **Vertretung** – über deren eigene Wege. Eintragen
unter [*Hersteller-News meiner Produkte*](/settings/notifications?tab=vendor&part=absence), Reiter **Abwesenheit** (den
Reiter gibt es, wie den *Wochenrückblick*, nur, wenn du in einem Team bist):

1. **Von** und **Bis** (ganze Tage, das Ende eingeschlossen, in deiner Zeitzone; höchstens ein Jahr). Ein Beginn in der
   Vergangenheit gilt ab jetzt.
2. **Vertretung** wählen. Wählbar ist, wer aktiv in einem deiner Teams ist, das dir Produkte gibt. Sie bekommt nur die
   Produkte von Teams, in denen sie selbst Mitglied ist; den Rest bekommst du weiter selbst.
3. Optional **Trotzdem auch an mich**. Sonst bekommst du in der Zeit nichts davon.
4. „Speichern“.

- **Genau einmal.** Jede Meldung kommt pro Empfänger und Weg genau einmal – auch wenn die Vertretung das Produkt
  ohnehin bekommt.
- **Keine Ketten.** Ist die Vertretung selbst abwesend (oder ausgeschaltet, ohne eingeschalteten Weg), wird nichts
  weitergeleitet. Die Meldungen kommen dann an dich, und der Reiter zeigt einen Hinweis.
- **Privat.** [Beobachtete CVEs](#cves-beobachten) gehen nie an die Vertretung, sondern weiter an dich.
- **Ende.** Mit dem Ende der Abwesenheit kommt wieder alles an dich. „Jetzt beenden“ beendet eine laufende Abwesenheit
  sofort; was in der Zeit an die Vertretung ging, kommt danach nicht noch einmal an dich.
- Die Vertretung sieht im selben Reiter, für wen sie gerade vertritt. Ein Admin kann die Abwesenheit auch im
  [Team](/docs/anmeldung#teams-abwesenheit) eintragen.

### Wochenrückblick {#wochenrueckblick}

Schaltet ein Admin für dein Team den Wochenrückblick ein, kannst du ihn unter
[*Hersteller-News meiner Produkte*](/settings/notifications?tab=vendor&part=weekly), Reiter **Wochenrückblick**, für
dich einschalten (ab Werk aus). Er kommt einmal pro Woche per E-Mail an die Adresse deines Kontos – ab der nächsten
Woche – und fasst die letzten 7 Tage der Produkte des Teams zusammen:

- neue Schwachstellen nach Schwere, die schwersten aufgelistet,
- eigene Versionen, die gerade betroffen sind,
- [Advisory-Änderungen](/docs/vendor-news#aenderungen) mit Wirkung auf eure Versionen,
- [Support-Ende](term:eol) in den nächsten 90 Tagen,
- neue Versionen,
- jeweils mit Link nach Cobe News.

Pro Team und Woche kommt er genau einmal, auch nach einem Neustart. Nach einem Ausfall kommt höchstens die letzte
verpasste Woche, nie mehrere alte. Ohne eingerichteten E-Mail-Server wird nichts versucht.

## Security-Meldungen per E-Mail oder Teams {#security-meldungen}

Security-Meldungen nach **deiner eigenen Auswahl** an deine E-Mail-Adresse oder deinen eigenen Teams-Webhook – wie eine
[Regel](#regel-systeme), nur für dich, ohne Admin. Den Reiter *Security-Meldungen* unter
[*Einstellungen → Benachrichtigungen*](/settings/notifications?tab=news) gibt es, sobald ein Admin es erlaubt
([Einstellungen → Teams](/docs/anmeldung#teams-persoenlich), ab Werk aus) – für jede Person, auch ohne Team.

1. Schalte **E-Mail** (an die Adresse aus deinem Konto) und/oder **Microsoft Teams** ein. Für Teams trägst du die
   Adresse deines [Workflows-Webhooks](#meine-produkte-teams) ein – dieselbe wie bei Hersteller-News meiner Produkte.
2. Wähle wie bei den [Desktop-Benachrichtigungen](#desktop-einschalten) **Schweregrade**, **Quellen**, **Themen**,
   **Systeme**, **Schlagwörter** und **Nicht anzeigen, wenn enthalten**. Leer heißt: alle. „Nur Palo Alto, nur Kritisch“:
   Schwere *Kritisch*, System „Alle Produkte von Palo Alto Networks“.
3. Klicke „Speichern“.

- **Wie eine Regel**: Systeme oder Schlagwörter – eines genügt –, zusammen mit Schwere, Quelle und Thema; ein
  Ausschluss-Wort verhindert die Meldung. Der Rückstand einer später eingeschalteten Quelle kommt nie, ebenso wenig, was
  eine Meldung erst durch eine Neuberechnung bekommt.
- **Auch später, wie eine Regel**: Passt eine Meldung erst später – sie wird höher eingestuft, ihre Details aus der
  Quelle nennen PAN-OS, sie bekommt das Thema „Aktiv ausgenutzt“, ein neuer Titel, eine weitere Quelle bringt sie frisch –,
  kommt sie dann; höchstens eine Woche nach ihrem Eintreffen. Was eine Meldung nur durch eine Neuberechnung bekommt
  (etwa nach einem Katalog-Update), bringt sie nicht.
- **Nur Neues, jede Meldung einmal**: Es kommt, was nach dem Einschalten eines Wegs eintrifft – pro Weg höchstens einmal,
  auch nach einem Neustart. **Erweiterst du die Auswahl** (eine weitere Schwere, Quelle, ein Thema, System oder Wort, ein
  Ausschluss-Wort weniger), kommt Älteres nur durch eine eigene Änderung danach – kein Schwall alter Meldungen.
- **Kein Schwall**: Höchstens eine Nachricht alle 15 Minuten pro Weg. Bis zu drei Meldungen kommen einzeln, mehr als
  eine Sammelnachricht („12 neue Security-Meldungen“) mit den zehn dringendsten (aktiv ausgenutzt oder kritisch zuerst).
- **Warum**: Mit Systemen oder Schlagwörtern sagt die Nachricht „Treffer: PAN-OS“.
- **Ruhezeiten und Sammelzeit** aus [Hersteller-News meiner Produkte](#ruhezeiten) gelten auch hier: In der Ruhezeit
  wartet die Nachricht und kommt danach gesammelt; mit „gesammelt um HH:MM“ kommt, was bis dahin eintraf. Eine
  Ausnahme für Dringendes gibt es hier nicht – dafür sind die Desktop-Benachrichtigungen da.
- **Abwesenheit**: Bist du [abwesend](#abwesenheit) (ohne „Trotzdem auch an mich“), kommt nichts, und nichts wartet auf
  deine Rückkehr – die News-Liste hat alles. Eine Vertretung gibt es hier nicht.
- **Stummgeschaltet**: Meldungen, deren CVEs du alle [stummgeschaltet](#stummschalten) hast, kommen nicht.
- **Fehler**: Lehnt der E-Mail-Server oder Teams ab, versucht Cobe News es später mit wachsender Pause erneut; nach einem
  Fehler, bei dem die Nachricht angekommen sein könnte (z. B. Zeitüberschreitung), nicht. Unter dem Weg steht die
  letzte Zustellung oder der letzte Fehler.
- Schaltet ein Admin den Weg aus oder wird dein Konto deaktiviert, kommt in dieser Zeit nichts – auch nicht später. Den
  Reiter siehst du dann weiter, solange ein Weg von dir an ist: ausschalten und die Auswahl ändern geht immer, einschalten
  erst wieder, wenn der Admin es erlaubt.
- **Die Teams-Adresse** ist eine für beide – Security-Meldungen und Hersteller-News meiner Produkte. Entfernst du sie in
  einem der beiden, ist Teams in beiden aus.

## CVEs beobachten {#cves-beobachten}

Einer einzelnen CVE folgen – unabhängig von Teams und gefolgten Produkten. Klicke den **Stern** neben einer CVE: auf
einer Meldungskarte (wenn sie genau eine CVE nennt), in einer geöffneten Meldung und ihren Details aus der Quelle, bei
einem Befund in Vendor News oder auf einer Produktkarte der Übersicht. Oder trage die CVE-ID oben rechts unter
[*Beobachtete CVEs*](/watch) in der Seitenleiste ein. Nach dem Stern führt „Zur Liste“ in der Bestätigung direkt zur
CVE in der Liste.

### Alle CVEs einer Meldung {#cves-alle}

Nennt eine Meldung viele CVEs (etwa ein GitLab-Patch-Release), zeigt die geöffnete Meldung zuerst zwölf davon;
**„+ N weitere CVEs“** klappt die ganze Liste auf (jede mit Kopieren und Stern), **„weniger“** wieder zu. Bei einem
Befund in Vendor News sind es sechs.

- **„Alle beobachten (N)“** über der CVE-Liste beobachtet alle CVEs der Meldung auf einmal – N sind die, die du noch
  nicht beobachtest. Bei einem Befund in Vendor News mit mehreren CVEs gibt es denselben Knopf.
- Beobachtest du schon alle, heißt der Knopf **„Alle nicht mehr beobachten“**: Er beendet das für alle CVEs der Meldung
  (auch für die, die du von woanders beobachtest) – mit „Rückgängig“ in der Bestätigung. Rückgängig beobachtet sie ab
  diesem Moment neu, jede mit ihrer bisherigen Herkunft.
- **Nicht genug Platz:** Passen nicht mehr alle neuen in deine Liste, fragt Cobe News vorher: „Nur noch K frei – die
  ersten K beobachten?“ Bei einer Meldung kommen die mit der höchsten [EPSS](term:epss) zuerst, bei einem Befund zählt
  seine Reihenfolge. Ist die Liste voll, kommt nur der Hinweis, zuerst welche zu entfernen.
- „Zur Liste“ in der Bestätigung öffnet die Liste nach Herkunft gruppiert, bei dieser Meldung.

**Herkunft:** Jede beobachtete CVE merkt sich, woher du sie beobachtest – eine Meldung (mit ihrem Titel von damals),
ein Befund (Produkt, Advisory, Titel) oder „einzeln hinzugefügt“ (auf der Seite eingetragen). Beobachtest du dieselbe
CVE später noch von woanders, bleibt die **erste Herkunft** (und der Beginn) – es ändert sich nichts. CVEs, die du schon
vor Version 0.1.42 beobachtet hast, haben keine Herkunft und stehen bei „Einzeln hinzugefügt“.

### Die Merkliste {#cves-liste}

[*Beobachtete CVEs*](/watch) ist eine Merkliste mit dem, was Cobe News gerade über jede CVE weiß:

- **Kacheln** oben: *Beobachtet* (von höchstens 500), *Aktiv ausgenutzt* (in [KEV](term:kev)), *Ohne Fix* (eine Quelle
  kennt die CVE, nennt aber noch keine Fix-Version) und *Neu seit letztem Besuch*. Ein Klick auf eine Kachel filtert.
- **Filter** *Alle · KEV · Ohne Fix · EPSS hoch · Neu* und **Sortierung** *Letzte Änderung* (Standard), *Schwere*,
  *EPSS* oder *CVE-Nummer*. „EPSS hoch“ heißt: Perzentil ab 0,9 – dieselbe Schwelle, ab der eine Meldung kommt. Filter
  und Sortierung stehen in der Adresse; ein Lesezeichen behält sie.
- **Gruppieren nach** (neben der Sortierung, ebenfalls in der Adresse): **Produkt** (Standard), **Herkunft** oder
  *Keine*. Jede Gruppe zeigt oben ihren Titel, die Zahl der CVEs („3 von 21 CVEs“, wenn ein Filter einige ausblendet)
  und kurz *KEV*, *Ohne Fix* und *Neu*. Der Pfeil klappt eine Gruppe zu und auf. Filter und Sortierung gelten innerhalb
  der Gruppen. **„Gruppe nicht mehr beobachten“** beendet das für alle CVEs der Gruppe – auch für die, die ein Filter
  gerade ausblendet – und lässt sich wie bei einer einzelnen CVE mit „Rückgängig“ zurücknehmen (jede CVE wieder mit
  ihrer Herkunft).
  - **Produkt:** die CVEs nach dem Produkt, das sie betreffen – egal, ob du sie per Stern, mit „Alle beobachten“ oder
    von Hand hinzugefügt hast. Beobachtest du fünf CVEs, die alle GitLab betreffen, stehen sie unter *GitLab*. Wie das
    Produkt bestimmt wird, steht [unten](#cves-produkt). Gruppen mit KEV oder Neuem stehen oben, dann nach Namen;
    *Ohne Produktzuordnung* am Ende.
  - **Herkunft:** die CVEs nach der Meldung oder dem Befund, aus dem du sie beobachtest ([Herkunft](#cves-alle)). Ein
    Klick auf den Titel öffnet die Meldung bzw. den Befund. Die zuletzt beobachtete Gruppe steht oben, *Einzeln
    hinzugefügt* am Ende. Ältere Links mit `?groups=1` öffnen diese Gruppierung.
- **Zeilen:** CVE-ID (kopierbar) mit Titel, Schwere, KEV (seit wann; Ransomware im Tooltip), [EPSS](term:epss)
  (Perzentil als Balken) und die erste Fix-Version („+2“: zwei weitere). „Exploit-Code öffentlich“ neben der CVE-ID: eine
  Sammlung führt einen Exploit ([Öffentlicher Exploit](/docs/vendor-news#oeffentlicher-exploit)); die Links stehen in
  der aufgeklappten Zeile. Eine CVE, die noch keine Quelle kennt, steht mit
  „Noch keine Quelle kennt sie“ da.
- **Aufklappen** (Klick auf die Zeile oder den Pfeil): der **Verlauf** seit du die CVE beobachtest, das Neueste oben –
  Fix-Version erschienen (in welchem Advisory), in KEV aufgenommen, EPSS gestiegen, Exploit veröffentlicht, Advisory
  zurückgezogen; ganz unten,
  seit wann du sie beobachtest. Darunter *Meldungen (n)* (die Meldungsliste mit der CVE als Suche), *Advisory öffnen*
  (die Seite des Herstellers, sonst CSAF oder NVD) und *Nicht mehr beobachten*. Das lässt sich in der Bestätigung mit
  „Rückgängig“ zurücknehmen – die CVE wird dann ab diesem Moment neu beobachtet.
- **Neu seit letztem Besuch:** Cobe News merkt sich, wann du die Liste zuletzt geöffnet hast. Was danach bei einer CVE
  passiert ist, trägt „Neu“. Die Markierungen bleiben bis zum nächsten Öffnen der Seite stehen. Beim allerersten Besuch
  ist nichts neu, und eine CVE selbst hinzuzufügen ist keine Neuigkeit.
- **Benachrichtigung aus:** Ist kein persönlicher Weg eingeschaltet, sagt eine schmale Zeile oben, dass die Liste nur
  eine Merkliste ist, und führt – wo das möglich ist – zu *Wege einschalten*.

### Gruppen nach Produkt {#cves-produkt}

Welches Produkt eine CVE betrifft, ermittelt Cobe News bei jedem Öffnen der Liste neu aus dem, was gerade gespeichert
ist – in dieser Reihenfolge:

1. **Produkte des Katalogs**, mit denen Vendor News die Advisories der CVE verknüpft hat. Ein gefolgtes Produkt geht vor
   (die Gruppe trägt „Gefolgt“), dann das mit den meisten Advisories, dann der Name. Es zählt der Name des Katalogs von
   heute – auch für ein [zusammengelegtes oder umbenanntes Produkt](/docs/vendor-news#zusammengelegte-produkte); ein
   [Produkt außerhalb des Katalogs](/docs/vendor-news#eigene-produkte) heißt, wie es angelegt wurde. Der Titel der Gruppe
   öffnet das Produkt in Vendor News.
2. Sonst Hersteller und Produkt, die die [CNA](term:cna) im CVE-Eintrag als betroffen nennt (aus cvelistV5, sonst aus
   der Kopie der NVD) – so wie sie dort stehen, Groß- und Kleinschreibung zählt nicht; „GitLab / GitLab“ wird zu
   „GitLab“. Die Gruppe trägt „laut CNA“. Ist der Name genau der eines Katalogprodukts, ist es dieses Produkt.
3. Sonst Hersteller und Produkt der [CPE](term:cpe) der NVD, lesbar gemacht (`a:gitlab:gitlab` ist das Katalogprodukt
   GitLab, sonst etwa „Microsoft Windows Server 2022“). Die Gruppe trägt „laut NVD-CPE“.
4. Sonst **Ohne Produktzuordnung** – noch keine Quelle nennt ein Produkt (etwa bei einer CVE, die noch niemand kennt).

Betrifft eine CVE mehrere Produkte, steht sie beim ersten; „+ N weitere Produkte“ in ihrer Zeile nennt die anderen im
Tooltip. Gespeichert wird nichts: Verknüpft Vendor News ein Advisory erst Stunden nach dem Beobachten, steht die CVE beim
nächsten Öffnen von selbst in der richtigen Gruppe. Ohne Gruppierung oder nach Herkunft steht das Produkt klein neben
der CVE-ID.

### Wann eine Meldung kommt {#cves-meldungen}

Das Fragezeichen neben „Beobachten“ fasst es kurz zusammen.

Eine Meldung kommt, wenn bei der CVE etwas Wichtiges passiert:

| Ereignis | Wann |
|---|---|
| Fix verfügbar | ein Advisory (Hersteller, NVD, cvelistV5, OSV, CSAF) nennt eine neue Fix-Version – auch durch eine Änderung |
| CISA KEV | die CVE wird in den Katalog der aktiv ausgenutzten Schwachstellen aufgenommen |
| EPSS | das Perzentil erreicht **0,9** (unter den 10 % wahrscheinlichsten) oder der Wert steigt um **0,1** (10 Prozentpunkte) seit der letzten Meldung; höchstens eine Meldung am Tag |
| Zurückgezogen | ein Advisory zur CVE wird zurückgezogen (z. B. NVD lehnt die CVE ab) |
| Exploit veröffentlicht | eine eingeschaltete Sammlung (Metasploit, Exploit-DB, nuclei) führt zum ersten Mal einen Exploit für die CVE ([Öffentlicher Exploit](/docs/vendor-news#oeffentlicher-exploit)); je CVE **einmal** |

„Exploit veröffentlicht“ kommt nur für Einträge, die nach dem ersten Laden einer Sammlung erscheinen: Was eine
Sammlung beim ersten Mal mitbringt (oder nachdem sie ausgeschaltet war oder nicht gebraucht wurde), steht in der Liste,
wird aber nicht gemeldet. Ein Ausfall des Downloads zählt nicht dazu: Was danach neu ist, wird gemeldet.
Schwere der Meldung: die der CVE, mindestens *hoch*.

Beim EPSS gilt eine kleine Spanne: Ist das Perzentil einmal über 0,9 gemeldet, kommt die nächste Meldung dazu erst,
nachdem es unter 0,85 gefallen ist – Schwanken um 0,9 erzeugt keine Meldungsserie. Der Anstieg um 0,1 zählt vom
letzten gemeldeten Wert (oder dem tiefsten Wert seither).

- **Wege.** Die Meldungen kommen über deine [persönlichen Wege](#meine-produkte-einschalten) – E-Mail, Desktop, Teams –,
  mit denselben Regeln: nur Neues, genau einmal, gesammelt pro Runde, begrenzte Runden. Die Filter *Art* und *Schwere*
  gelten für beobachtete CVEs nicht – du hast die CVE ja selbst gewählt.
- **Ohne Team.** Beobachten geht für jede Person. Wer in keinem Team ist, aber eine CVE beobachtet, sieht den Reiter
  *Hersteller-News meiner Produkte* trotzdem und kann dort seine Wege einschalten. Die Wege selbst gibt ein Admin unter
  *Einstellungen → Teams* frei; solange Teams aus ist, gibt es keine persönlichen Wege – die Liste ist dann eine
  Merkliste, und die Seite sagt das.
- **Nur Neues.** Was bei der CVE schon galt, als du sie zu beobachten begonnen hast (schon in KEV, schon gepatcht),
  wird nicht gemeldet.
- **Grenzen.** Höchstens 500 CVEs pro Person, nur gültige CVE-IDs (`CVE-JJJJ-NNNN`). Jede Person sieht und ändert nur
  ihre eigene Liste. „Alle beobachten“ geht höchstens 20-mal in fünf Minuten; die Herkunft prüft Cobe News selbst
  (die Meldung muss in den Listen sichtbar sein, die CVE muss in ihr vorkommen).
- **Keine Extra-Abfragen.** Für beobachtete CVEs fragt Cobe News keinen Dienst zusätzlich ab. Was die Quellen ohnehin
  holen, zählt. Eine CVE, die Cobe News noch nicht kennt, bleibt in der Liste („Noch keine Quelle kennt sie“) und zählt,
  sobald eine Quelle sie bringt. EPSS gibt es nur für CVEs aus Befunden und aus Meldungen der letzten 30 Tage.

## Stummschalten {#stummschalten}

Ein Produkt oder eine CVE nervt gerade (ein Patch ist eingeplant, ein Fehlalarm ist geklärt)? Schalte es **für eine
Weile** stumm: für **7 Tage**, **30 Tage** oder **bis zu einem Datum** (höchstens ein Jahr).

**Wo:** im Menü **⋯** einer Meldung oder einer Produktkachel, unten in der Meldung bzw. Produkt-Schublade, an einem
Befund und in der Merkliste der [beobachteten CVEs](#cves-liste) (aufgeklappte Zeile).

**Bestätigen statt stummschalten?** Ist ein Befund für alle erledigt (z. B. die betroffene Funktion ist nicht im
Einsatz), [bestätige](/docs/vendor-news#treffer-bestaetigen) ihn – das gilt für alle und bleibt.

**Was es bewirkt – nur für dich:**

- **Keine persönlichen Benachrichtigungen** dafür auf deinen Wegen (E-Mail, Desktop-Push, eigener Teams-Webhook):
  Vendor News eines stummen Produkts, Befunde, deren CVEs alle stumm sind, und die Meldungen einer stummen
  **beobachteten CVE** – auch die beobachtete CVE war deine Wahl, die neuere gilt bis zu ihrem Ende. Was in der Zeit
  ausfällt, kommt später nicht nach.
- **In deinen Listen** blass oder ausgeblendet („Stummgeschaltete zeigen“) und **nicht in deinen Zahlen** in der
  Seitenleiste. Eine Meldung gilt als stumm, wenn **alle** ihre CVEs stumm sind – eine Meldung zu fünf CVEs bleibt, wenn
  du eine davon stummschaltest.
- **Aktiv ausgenutzt bleibt sichtbar:** Kommt ein stummes Produkt in den KEV-Katalog, bekommst du (deine Wahl) keine
  Benachrichtigung, die Kachel bleibt aber mit „KEV trotz Stumm“ in der Liste.

**Was es nicht berührt:** andere Personen, die Kanäle eines Teams, die Regeln der Admins, den
[Wochenrückblick](#wochenrueckblick) und die [Vertretung](#abwesenheit) – wer dich vertritt, entscheidet über die
eigenen Stummschaltungen. Die [Desktop-Benachrichtigungen für News](#desktop) richten sich weiter nach Schwere und
Quelle.

**Meine Stummschaltungen** (*Einstellungen → Benachrichtigungen → Stummschaltungen*) listet alle laufenden mit der
verbleibenden Zeit; *Aufheben* beendet eine sofort. Abgelaufene verschwinden von selbst.

## Kalender (iCal) {#kalender-ical}

Das Support-Ende eurer eingetragenen Versionen als Kalender zum Abonnieren ([iCal](term:ical)): ein ganztägiger
Termin pro Version am Tag des Support-Endes, mit Erinnerung **90** und **30 Tage** vorher. Im Termin stehen Produkt,
Version, Release-Linie, Datum und ein Link nach Cobe News – keine CVE-Details und keine Namen (auch nicht die
Bezeichnung einer Version).

**Was drinsteht:** Als Admin alle gefolgten Produkte. Als Leser die Produkte, die dir dein Team zuteilt (nur solange
Teams eingeschaltet ist). Das wird bei jedem Abruf neu geprüft: Kommt ein Produkt dazu oder ändert sich deine Rolle,
stimmt der Kalender beim nächsten Abruf.

### Adresse erzeugen {#kalender-adresse}

1. Gehe zu [*Einstellungen → Benachrichtigungen → Kalender*](/settings/notifications?tab=calendar).
2. Klicke „Kalender-Adresse erzeugen“. Die Adresse erscheint **nur jetzt** – kopiere sie.
3. „Neue Adresse erzeugen“ macht die alte sofort ungültig; „Adresse löschen“ beendet sie.

### In Outlook abonnieren {#kalender-outlook}

1. **Outlook im Web / neues Outlook:** Kalender öffnen → *Kalender hinzufügen* → *Aus dem Internet abonnieren*.
   **Klassisches Outlook:** Kalender → *Kalender hinzufügen* → *Aus dem Internet …*.
2. Die Adresse einfügen, einen Namen vergeben (z. B. „Support-Ende“) und *Importieren* bzw. *OK* klicken.
3. Outlook holt die Termine dann selbst, meist alle paar Stunden. Geänderte Daten kommen beim nächsten Abruf an.

Apple Kalender und andere Programme öffnen die Adresse auch über den Link „Im Kalender-Programm öffnen (webcal)“.

> [!WARNING]
> Die Adresse ist ein Geheimnis wie ein Passwort: Wer sie kennt, sieht die Termine – ohne Anmeldung. Gib sie nicht
> weiter. Ist sie in falsche Hände geraten, erzeuge eine neue.

- Cobe News speichert nur einen Fingerabdruck der Adresse, nicht sie selbst, und schreibt sie in kein Protokoll.
- Wird dein Konto deaktiviert, endet die Adresse für immer – nach einer Reaktivierung erzeugst du eine neue.
- Ein Kalender darf die Adresse höchstens 30-mal in 10 Minuten abrufen; mehr wird kurz abgewiesen.

## An mein Team weiterleiten {#weiterleiten}

Eine Meldung oder einen Befund in Vendor News schickst du mit einem kurzen Kommentar an dein Team – etwa „Betrifft
unsere Firewalls, bitte heute patchen“.

1. Meldung öffnen (News) oder in der Schublade eines Produkts beim Befund (Vendor News) auf **„Ans Team weiterleiten“**.
2. Bist du in mehreren Teams, wählst du das Team. Zur Auswahl stehen nur Teams, für die ein Admin einen
   Weiterleitungs-Kanal festgelegt hat.
3. Optional einen **Kommentar** schreiben (höchstens 1000 Zeichen), **Weiterleiten**.

Die Nachricht geht in den **Kanal des Teams** (Teams, Slack, Discord, Telegram, Mattermost, ntfy, Gotify, E-Mail oder
Webhook) und enthält: wer weiterleitet, den Titel, einen Link nach Cobe News und – bei einem Befund – die
[Dringlichkeit](/docs/vendor-news#dringlichkeit) und eure Versionen. Bei einer Meldung stehen eure Versionen dabei,
wenn ihre Details ein gefolgtes Produkt betreffen. In den Chat-Kanälen ist sie dieselbe **Karte** wie eine
Benachrichtigung ([So sieht eine Nachricht aus](#nachrichten-format)): Produkt (nur wenn sicher bekannt), Quelle,
Kategorie, bei einem Befund Dringlichkeit und eure Versionen, dein Kommentar als eigenes Feld **„Kommentar“** und die
Kurzbeschreibung. Die E-Mail bleibt, wie sie ist.

Gut zu wissen:

- **Wohin, bestimmt ein Admin** – im Team unter [Einstellungen → Teams](/docs/anmeldung#teams-weiterleiten). Du wählst
  nie selbst eine Adresse oder einen Kanal. Ohne Kanal ist der Knopf aus; der Tooltip sagt warum.
- Der Kommentar ist **nur Text**: Links werden entschärft (`example[.]com`, `https[:]//…`) und nicht anklickbar, `@`
  erwähnt niemanden, Formatierungen werden als Zeichen gezeigt.
- **Grenzen:** höchstens 10 Weiterleitungen pro Stunde und Person; dieselbe Meldung an dasselbe Team nur einmal in
  10 Minuten (egal von wem). Die Meldung sagt, wann es wieder geht.
- Klappt der Versand nicht, steht der Grund im Hinweis (z. B. „der Kanal hat die Nachricht abgelehnt“) – dann sollte
  ein Admin den Kanal prüfen. Du kannst es danach sofort noch einmal versuchen.
- Cobe News speichert nicht, wer was weitergeleitet hat.
- Ist *Teams* aus oder bist du in keinem Team, gibt es den Knopf nicht.

## Kanäle {#kanaele .admin}

Ein Kanal ist ein Ziel: ein Postfach, ein Teams-, Slack-, Discord- oder Telegram-Chat oder ein eigener
[Webhook](term:webhook). Du findest die Kanäle unter [*Einstellungen → Kanäle & Regeln*](/settings/rules), Reiter
„Kanäle“.

| Kanal | Ziel | Format |
|---|---|---|
| E-Mail | Empfänger (eine Adresse pro Zeile, höchstens 20); Server in der Zeile „E-Mail-Server“ | HTML und Text |
| Microsoft Teams | Workflow-URL (oder URL eines klassischen „Incoming Webhook“) | Adaptive Card |
| Slack | Incoming-Webhook-URL `https://hooks.slack.com/services/…` | Block Kit |
| Discord | Webhook-URL `https://discord.com/api/webhooks/…` (auch `discordapp.com`) | Embeds |
| Telegram | Bot-Token und Chat-ID | Text-Nachricht |
| Mattermost | Incoming-Webhook-URL `https://…/hooks/…` | Markdown (entschärft), Farbe nach Schwere |
| ntfy | Server, Thema, optional Zugriffs-Token | reiner Text, Priorität nach Schwere |
| Gotify | Server und Anwendungs-Token | reiner Text, Priorität nach Schwere |
| Webhook | eigene URL, z. B. ein n8n-Workflow | JSON, Version 1 (siehe [Webhook](#webhook)) |

Text aus den Feeds wird für jedes Format entschärft: kein `@everyone` in Discord, kein `<!channel>` in Slack, keine
eigenen Links in Teams, kein `@channel` und kein Markdown in Mattermost; Links nur `http(s)`.

### So sieht eine Nachricht aus {#nachrichten-format}

In Teams, Slack, Discord, Mattermost und Telegram ist jede Meldung eine **Karte** mit beschrifteten Feldern; ntfy und
Gotify bekommen denselben Inhalt als knappen Text. Die Farbe richtet sich nach der Schwere.

| Feld | Inhalt |
|---|---|
| Titel | der Titel der Meldung, als Link zum Originalartikel – ohne die Kennzeichen, die das BSI (WID/CERT-Bund) voranstellt („[NEU]“, „[UPDATE]“, „[UNGEPATCHT]“, „[kritisch]“ … „[niedrig]“): Schwere und Thema stehen ohnehin dabei. Andere Klammern und alles im Titel bleiben; der [Webhook](#webhook) bekommt den Titel unverändert |
| **Produkt** | nur wenn sicher bekannt: bei Vendor News das Produkt mit eurer Version und dem Fix („PAN-OS 11.1.2 → 11.1.6-h3“); bei Meldungen ein gefolgtes Produkt, das die [Details aus der Quelle](/docs/news-quellen#details-aus-der-quelle) betreffen (ebenso mit Version und Fix), sonst das erste betroffene Produkt der Details („GitLab < 19.5.1“). Ist nichts sicher bekannt, fehlt das Feld – geraten wird nicht. Ein gefolgtes Produkt heißt, wie der Katalog es heute nennt – auch nach einer Umbenennung, Aufteilung oder [Zusammenlegung](/docs/vendor-news#zusammengelegte-produkte). |
| **Quelle** | der Name der Quelle |
| **Kategorie** | die [Themen](/docs/news-quellen#themen) der Meldung (höchstens drei) und die Schwere, z. B. „Zero-Day · Aktiv ausgenutzt · Kritisch“; ohne Thema die Schwere und die Art der Quelle („Hoch · Behörde“) |
| **Kurzbeschreibung** | die ersten ein bis zwei Sätze der Zusammenfassung, höchstens rund 200 Zeichen – am Satzende abgeschnitten, ein zu langer erster Satz am letzten Wortende mit „…“ |
| Fuß | Datum in Ortszeit mit Zone (Europe/Berlin, z. B. „02.11.2026 09:00 MEZ“) und „In Cobe News öffnen“ |

Beispiel (Telegram):

```text
Neue Security-Meldung · Kritisch an SOC

Chrome-Zero-Day: Google schließt aktiv ausgenutzte Lücke
Produkt: Chrome < 142.0.7444.59
Quelle: heise online
Kategorie: Zero-Day · Aktiv ausgenutzt · Kritisch
Google hat ein Notfall-Update für Chrome veröffentlicht. Die Lücke CVE-2026-1234 wird bereits ausgenutzt.
02.11.2026 09:00 MEZ · In Cobe News öffnen
```

Kommen **mehr als 3** Meldungen auf einmal (eine [Sammelnachricht](#einmal-pro-kanal)), wird daraus eine **kompakte
Liste**: eine Zeile je Meldung – „Titel · Produkt · Kategorie“, der Titel öffnet die Meldung in Cobe News – und
„… und N weitere in Cobe News“. So bleibt jede Nachricht unter den Grenzen der Dienste (Discord: ein Embed, Slack:
höchstens 50 Blöcke, Telegram: unter 4096 Zeichen). Die Sprache der Beschriftungen ist die der Regel. Wie die
E-Mail aussieht, steht unter [So sieht die E-Mail aus](#mail-format). Der Knopf „Testen“ schickt die neueste Meldung
(mit ihrem Produkt, wenn bekannt) oder ein Beispiel in genau diesem Aussehen.

### So sieht die E-Mail aus {#mail-format}

Eine E-Mail kommt als HTML mit einem gleichwertigen Textteil (für Programme, die nur Text zeigen). Sie lädt nichts
nach – keine Bilder, keine Zählpixel.

- **Betreff.** Eine Meldung: Schwere und Titel („[Cobe News] Hoch: Emerson Ovation: Mehrere Schwachstellen“). Mehrere:
  wie viele und worum es geht, in der Reihenfolge der Mail – je Meldung das betroffene eigene Produkt, sonst was der
  Titel vor dem Doppelpunkt nennt, sonst der gekürzte Titel; höchstens rund 150 Zeichen, der Rest als „+N“
  („[Cobe News] 5 neue Meldungen: Emerson Ovation, SolarWinds Dameware +3“). Ist eine TLP:GREEN-Meldung dabei, steht
  „[TLP:GREEN]“ vorn.
- **Kopf.** Die Überschrift („5 neue Security-Meldungen“, bei einer Meldung ihr Titel) und darunter eine Zeile mit dem
  Wichtigsten: „Höchste Schwere: Hoch · 1 betrifft eure Produkte · 1 aktiv ausgenutzt“ – Teile mit null fallen weg.
- **Reihenfolge.** Zuerst das Dringende – **aktiv ausgenutzt** oder **kritisch** –, dann, was **eure Produkte**
  betrifft, dann nach **Schwere**, zuletzt die **neueste** zuerst. Nach derselben Reihenfolge wählt eine
  [Sammelnachricht](#einmal-pro-kanal) ihre zehn aus – ein niedriger Befund eines eigenen Produkts verdrängt nie eine
  ausgenutzte oder kritische Meldung.
- **Je Meldung** (bis 5 Meldungen): Schwere, Quelle und Zeit; „Betrifft eure Produkte: …“ – hervorgehoben – wenn die
  [Details aus der Quelle](/docs/news-quellen#details-aus-der-quelle) ein in Vendor News gefolgtes Produkt betreffen
  (wie der Filter „Betrifft unsere Produkte“ auf der News-Seite) oder ein Vendor-News-Befund es tut. Ist die Regel
  auf Teams beschränkt, zählen nur die Produkte dieser Teams (brachten mehrere Regeln die Meldung, alles, was eine von
  ihnen abdeckt); der Titel (ohne die
  BSI-Kennzeichen, siehe oben); eine Zeile mit **Produkt** (wenn sicher bekannt), den ersten drei **CVEs** („+N“ für
  weitere) und den **Themen** („Aktiv ausgenutzt“, „Zero-Day“, „Exploit veröffentlicht“ …); die Zusammenfassung;
  „Artikel öffnen“ und „In Cobe News öffnen“.
- **Ab 6 Meldungen** eine kompakte Liste: eine Zeile je Meldung – Schwere, Produkt, der Titel als Link in Cobe News –
  ohne Zusammenfassungen.
- **Knopf „Cobe News öffnen“.** Bei einer Meldung öffnet er genau diese. Bei mehreren öffnet er die News-Liste, gefiltert
  auf genau die Meldungen der Nachricht – auch die unter „… und N weitere“ (Chip „Aus der Benachrichtigung (N)“, bis
  50 Meldungen; mehr: die ganze Liste). Vendor-News-Befunde eines Produkts öffnen dieses Produkt, mehrere Produkte
  Vendor News. Dasselbe gilt für den Knopf in Slack und Teams, den Klick auf ntfy-, Gotify- und Desktop-Push-Nachrichten
  und die persönlichen Nachrichten; eine weitergeleitete Meldung öffnet sich selbst.
- **Zeit.** In Ortszeit mit Zonenkürzel, damit sie eindeutig ist: „04.11.2026 11:19 MEZ“ (Sommer: MESZ; englisch
  „CET“/„CEST“) – ebenso in den Chat-Karten, Push-Texten und Weiterleitungen. Kanäle nehmen Europe/Berlin; die [persönlichen Nachrichten](#meine-produkte) die Zeitzone der Person
  (aus ihren [Ruhezeiten](#ruhezeiten), sonst ebenfalls Europe/Berlin).
- **Hell und dunkel.** Die Mail hat ein helles und ein dunkles Farbschema; Programme mit Dunkelmodus (Apple Mail, iOS,
  Outlook für Mac und Outlook.com, Thunderbird) zeigen das dunkle, die Schwere bleibt in beiden gut lesbar.
- **Fuß.** Warum die Mail kommt: „Regel „Kritisch“ · Regel bearbeiten“ – der Link öffnet die Regel unter
  *Einstellungen → Kanäle & Regeln* (bei mehreren Regeln die Liste; nur für Admins). Persönliche Nachrichten sagen statt
  dessen, für welche Produkte und CVEs sie kommen und wo man sie abschaltet.

### Kanal anlegen {#kanal-anlegen}

1. *Einstellungen → Kanäle & Regeln*, Reiter „Kanäle“.
2. „Kanal hinzufügen“ klicken und die Art wählen.
3. In der Schublade einen **Namen** vergeben (mindestens 2 Zeichen, z. B. „Teams SOC“). Der Kasten „So richtest du
   ihn ein“ fasst die Schritte zusammen.
4. Ziel eintragen (URL, Token oder Empfänger – siehe unten).
5. Speichern.
6. In der Liste beim Kanal „Testen“ klicken.
7. Unter dem Reiter „Regeln“ festlegen, was an den Kanal geht (siehe [Regeln](#regeln)).

Die Liste zeigt je Kanal das Ziel (nur den Host, die Empfänger oder die Chat-ID), welche Regeln ihn nutzen („von keiner
Regel genutzt“, wenn keine) und den Zustand: „Zuletzt verschickt …“, „Noch nichts verschickt“ oder den letzten Fehler.
Die Art eines Kanals lässt sich nicht ändern – für einen anderen Dienst legst du einen neuen Kanal an.

### Microsoft Teams (Workflows) {#teams}

Teams nimmt Nachrichten über einen **Workflow** an. Die Vorlage dafür heißt „Bei Empfang einer Webhookanfrage in einem
Kanal posten“.

1. In Teams beim gewünschten Kanal auf „…“ (Weitere Optionen) klicken und „Workflows“ wählen.
2. Die Vorlage „Bei Empfang einer Webhookanfrage in einem Kanal posten“ wählen.
3. Einen Namen vergeben (z. B. „Cobe News“), die Verbindung mit deinem Konto bestätigen und „Weiter“ klicken.
4. Team und Kanal prüfen und „Workflow hinzufügen“ klicken.
5. Die angezeigte URL kopieren. Sie liegt auf `*.logic.azure.com` oder `*.powerplatform.com`.
6. In Cobe News einen Kanal „Microsoft Teams“ anlegen, die URL bei „Workflow-URL“ einfügen, speichern und testen.

> [!NOTE]
> Der Workflow läuft unter dem Konto, das ihn angelegt hat. Wird dieses Konto deaktiviert, kommen keine Nachrichten
> mehr an. Lege ihn mit einem Konto an, das bleibt, und notiere, wem er gehört.

Die URL eines klassischen „Incoming Webhook“ (`*.webhook.office.com`) geht ebenfalls. Microsoft stellt diese Connectors
aber nach und nach ein – nimm für neue Kanäle Workflows. Liegt die URL auf einem anderen Host (z. B. einer eigenen
Cloud-Umgebung), muss ein Admin ihn in `WEBHOOK_HOSTS` eintragen (siehe [Erlaubte Ziele](#webhook-ziele)).

### Slack {#slack}

Slack nimmt Nachrichten über einen **Incoming Webhook** an: eine Slack-App, die alles, was an ihre URL geht, in einen
festen Kanal postet.

1. Auf [api.slack.com/apps](https://api.slack.com/apps) „Create New App“ → „From scratch“ wählen, Namen und Workspace
   angeben.
2. In der App „Incoming Webhooks“ öffnen und einschalten.
3. „Add New Webhook to Workspace“ klicken, den Slack-Kanal wählen und erlauben.
4. Die URL `https://hooks.slack.com/services/…` kopieren.
5. In Cobe News einen Kanal „Slack“ anlegen, die URL bei „Webhook-URL“ einfügen, speichern und testen.

Gibt es in eurem Workspace schon die App „Incoming Webhooks“ aus dem Slack-Verzeichnis, geht auch deren URL.

### Discord {#discord}

1. In Discord *Servereinstellungen → Integrationen → Webhooks* öffnen (dafür brauchst du das Recht, Webhooks zu
   verwalten).
2. „Neuer Webhook“ klicken, Namen und Kanal wählen.
3. „Webhook-URL kopieren“ klicken.
4. In Cobe News einen Kanal „Discord“ anlegen, die URL bei „Webhook-URL“ einfügen, speichern und testen.

Cobe News nimmt nur URLs auf `discord.com` oder `discordapp.com` mit dem Pfad `/api/webhooks/…` an. Nachrichten lösen
keine Erwähnungen aus.

### Telegram {#telegram}

Telegram braucht einen **Bot** und die **Chat-ID** des Chats, in den er schreibt.

1. In Telegram den Bot @BotFather öffnen, `/newbot` senden, Namen und Benutzernamen (endet auf `bot`) vergeben.
2. Das Token kopieren (Form `123456789:AA…`). Wer es kennt, kann im Namen des Bots schreiben.
3. Den Bot in die Gruppe aufnehmen – in einen Kanal als Admin mit dem Recht zu posten.
4. Im Chat eine Nachricht schreiben, z. B. `/start`.
5. Im eigenen Browser `https://api.telegram.org/bot<TOKEN>/getUpdates` öffnen (`<TOKEN>` ersetzen) und den Wert
   `chat.id` ablesen.
6. In Cobe News einen Kanal „Telegram“ anlegen, „Bot-Token“ und „Chat-ID“ eintragen, speichern und testen.

Chat-IDs: Gruppen beginnen mit `-`, Kanäle und Supergruppen mit `-100`, öffentliche Kanäle gehen auch als `@name`.

### E-Mail {#e-mail}

E-Mails gehen über einen [SMTP](term:smtp)-Server, der für alle E-Mail-Kanäle gilt. Er steht in der Zeile
**„E-Mail-Server“** über der Liste der Kanäle: Server und Port, dazu „eingerichtet“ oder „nicht eingerichtet“.

1. In der Zeile „E-Mail-Server“ auf „Einrichten“ bzw. „Bearbeiten“ klicken.
2. Eintragen:
   - „Server“ und „Port“,
   - „Verschlüsselung“: [STARTTLS](term:starttls) (meist Port 587), SSL/TLS (Port 465) oder „Keine (nur internes
     Relay)“,
   - „Zertifikat prüfen“ – eingeschaltet lassen,
   - „Benutzer“ und „Passwort“ – leer für ein Relay ohne Anmeldung,
   - „Absender-Adresse“ (Pflicht) und „Absender-Name“.
3. Bei „Test-Mail an“ eine Adresse eintragen und „Test-Mail senden“ klicken. Der Test nimmt die Werte im Formular, auch
   ungespeichert.
4. Speichern.
5. „Kanal hinzufügen“ → „E-Mail“, die Empfänger eintragen (eine Adresse pro Zeile, höchstens 20), speichern und
   testen.

Gut zu wissen:

- Ein neuer E-Mail-Kanal ohne eingerichteten Server fragt zuerst nach dem Server. Kanäle ohne Server zeigen
  „E-Mail-Server fehlt“.
- Speichern des Servers startet alle E-Mail-Kanäle neu – ohne Pause und ohne alten Fehler.
- Ändern sich Server, Port, Verschlüsselung, „Zertifikat prüfen“ oder Benutzer, musst du das Passwort neu eingeben.
- Ein Relay im Firmennetz ist in Ordnung. Die eigenen Docker-Netze und der Docker-Host (Gateway des Containers,
  `host.docker.internal`) gehen nur, wenn ihre Adresse in `SMTP_ALLOW_INTERNAL` steht (siehe
  [Betrieb](/docs/betrieb#env-referenz)) – dann auch über den Namen. Loopback (`127.0.0.1`), Link-Local samt
  Cloud-Metadaten, „any“ und Multicast sind immer gesperrt, auch mit Eintrag. Ein Relay, das auf dem Server nur an
  `127.0.0.1` lauscht, erreichst du über die Adresse des Docker-Hosts, nicht über `127.0.0.1`.
- Fehler zeigen nur die Art (abgelehnt, keine Verbindung, TLS …), nie den Text des Servers.

### Mattermost {#mattermost}

Mattermost nimmt Nachrichten über einen **Incoming Webhook** an – wie Slack, aber auf eurem eigenen Server.

1. In Mattermost *Hauptmenü → Integrationen → Incoming Webhooks* öffnen (die Integrationen muss ein Systemadmin
   erlaubt haben).
2. „Incoming Webhook hinzufügen“ klicken, Titel und Kanal wählen, speichern.
3. Die URL `https://chat.corp.example/hooks/…` kopieren. Wer sie kennt, kann in den Kanal posten.
4. In Cobe News einen Kanal „Mattermost“ anlegen, die URL bei „Webhook-URL“ einfügen, speichern und testen.

Jede Meldung kommt als Anhang mit einem Farbbalken nach Schwere (Kritisch rot, Hoch orange …), darin Titel als Link,
die Felder Produkt, Quelle und Kategorie, die Kurzbeschreibung, Datum und ein Link nach Cobe News
([So sieht eine Nachricht aus](#nachrichten-format)). Text aus den Feeds wird entschärft: Markdown-Zeichen werden
maskiert (keine eigenen Links, Hervorhebungen oder Emojis), `@channel`, `@all`, `@here` und `@name` lösen keine
Erwähnung aus, `~kanal` wird kein Kanal-Link. Nur `https://`. Der Server ist meist intern – seine Adresse muss dann in
`WEBHOOK_PRIVATE_NETS` stehen (siehe [Erlaubte Ziele](#webhook-ziele)).

### ntfy {#ntfy}

ntfy ist ein einfacher Push-Dienst: Was an ein **Thema** (Topic) geht, erscheint auf jedem Handy
und Browser, der das Thema abonniert hat – über die ntfy-App, ohne eigenes Konto. Ihr könnt den öffentlichen Server
ntfy.sh nehmen oder einen eigenen betreiben.

1. Ein Thema ausdenken. Auf einem öffentlichen Server kann jeder mitlesen und -schreiben, der den Namen kennt – nimm
   einen langen, zufälligen Namen (Buchstaben, Ziffern, `-` und `_`, höchstens 64 Zeichen).
2. Geschütztes Thema (empfohlen, auf eigenem Server mit Zugriffskontrolle): einen Benutzer mit Schreibrecht auf das
   Thema anlegen und für ihn einen **Zugriffs-Token** erzeugen (`ntfy token add <benutzer>` – er beginnt mit `tk_`).
3. In Cobe News einen Kanal „ntfy“ anlegen:
   - **Server**, z. B. `https://ntfy.corp.example` (auch mit Pfad hinter einem Reverse Proxy, ohne `?` und `#`),
   - **Thema**,
   - bei einem geschützten Thema „Zugriffs-Token“ einschalten und den Token eintragen,
   - optional **Tags** (mit Komma getrennt, höchstens 5) – ein Tag, das ein Emoji benennt (`warning`), zeigt ntfy als
     Emoji vor dem Titel.
4. Speichern und testen. In der ntfy-App das Thema auf demselben Server abonnieren.

| Schwere | Priorität | Tag (Emoji) |
|---|---|---|
| Kritisch | 5 (dringend) | `rotating_light` |
| Hoch | 4 | `warning` |
| Mittel | 3 | `large_orange_diamond` |
| Niedrig | 2 | `small_blue_diamond` |
| Info | 1 | `information_source` |

Ein Tippen auf die Benachrichtigung öffnet die Meldung in Cobe News (bei einer Sammelnachricht die Startseite). Cobe
News schickt alles als JSON im Body an die Wurzel des Servers – Titel und Text stehen nie in einem Header; sie sind
reiner Text (ntfys Markdown bleibt aus), Zeilenumbrüche und Steuerzeichen werden entfernt. Der Token geht nur im
Header `Authorization: Bearer …` mit.

### Gotify {#gotify}

Gotify ist ein selbst betriebener Push-Server mit eigener Android-App und Weboberfläche.

1. In Gotify unter *Apps* „Create Application“ klicken, Namen vergeben (z. B. „Cobe News“), speichern.
2. Das **Token** der Anwendung kopieren.
3. In Cobe News einen Kanal „Gotify“ anlegen: **Server** (z. B. `https://gotify.corp.example`, auch mit Pfad) und
   **Anwendungs-Token** eintragen, speichern und testen.

Priorität nach Schwere: Kritisch 10, Hoch 8, Mittel 5, Niedrig 2, Info 1 – in der App lässt sich einstellen, ab welcher
Priorität es klingelt. Der Text ist reiner Text (`text/plain`), ein Tippen öffnet die Meldung in Cobe News. Das Token
geht nur im Header `X-Gotify-Key` mit, nie in der URL.

> [!NOTE]
> Mattermost, ntfy und Gotify gehen nur über `https://` und durch dieselbe Egress-Prüfung wie alle Webhooks: öffentliche
> Adressen, interne nur über `WEBHOOK_PRIVATE_NETS`, Loopback, Link-Local, die eigenen Docker-Netze und der Docker-Host
> nie. Als **persönliche Wege** (Hersteller-News meiner Produkte) gibt es sie bisher nicht – nur als Kanäle für Regeln
> und Team-Weiterleitungen.

### Testen, Fehler und Pause {#kanal-testen}

„Testen“ schickt sofort eine Testnachricht mit der neuesten Meldung (oder einer Beispielmeldung). Sie ist als Test
markiert und gilt nicht als verschickt. Getestet wird der **gespeicherte** Kanal – also erst speichern. Zwischen zwei
Tests desselben Kanals liegen mindestens 3 Sekunden.

Scheitert der Versand, bleibt die Meldung für diesen Kanal offen. Cobe News versucht es mit wachsender Pause erneut:
2, 4, 8 … Minuten bis höchstens 6 Stunden. Verlangt der Dienst eine Wartezeit (HTTP 429), wartet Cobe News mindestens
so lange. Ein kaputter Kanal hält die anderen nie auf. Kommt ein Test an, verschwinden Fehler und Pause; was auf den
neuen Versuch wartet, geht in der nächsten Runde raus. Ändern des Ziels setzt Fehler und Pause ebenfalls zurück.

| Fehler | Was tun |
|---|---|
| Ziel nicht erlaubt | Die Adresse ist intern. Siehe [Erlaubte Ziele](#webhook-ziele). |
| Dieser Host ist nicht erlaubt | Teams/Slack: Host in `WEBHOOK_HOSTS`; Discord: nur `discord.com`. |
| Anmeldung abgelehnt | HTTP 401/403 oder SMTP-Anmeldung: Token, Passwort oder Auth-Header prüfen. |
| Vom Empfänger abgelehnt | HTTP 404/410 (URL gelöscht, z. B. Workflow entfernt) oder Empfänger abgelehnt: URL bzw. Adressen prüfen. |
| Vom Dienst gebremst | zu viele Nachrichten; Cobe News wartet und versucht es erneut. |
| Keine Antwort | Zeitüberschreitung: Netz, Proxy und Firewall prüfen. |
| TLS-Fehler | Zertifikat des Ziels prüfen; eine eigene CA kommt über `CA_FILE`. |
| Gespeichertes Geheimnis nicht lesbar | Der Schlüssel hat sich geändert: URL, Token bzw. Geheimnis neu eingeben. |

Jeder Versuch – auch jeder Test – steht im [Zustellprotokoll](#zustellprotokoll), mit HTTP-Status bzw. SMTP-Code.

### Geheimnisse {#geheimnisse}

Webhook-URLs (auch die von Mattermost), das Telegram-Bot-Token, Thema und Token von ntfy, das Gotify-Token, das
HMAC-Geheimnis, der Wert des Auth-Headers und das SMTP-Passwort werden verschlüsselt gespeichert ([Hauptschlüssel](term:masterkey) `SECRET_KEY` oder die Datei `data/secret.key`). Der
Browser bekommt sie nie zurück – er sieht nur „gespeichert“ und den Host. Ein leeres Feld beim Speichern behält den
alten Wert. Thema und Token von ntfy und das Gotify-Token gehören zu ihrem Server: Wer den Server ändert, muss sie neu
eingeben – sie gehen nie ungefragt an ein neues Ziel. Die Server-Adresse selbst ist kein Geheimnis und wird angezeigt.

## Generischer Webhook {#webhook .admin}

Der Kanal „Webhook“ schickt jede Benachrichtigung per `POST` als JSON an eine eigene URL – z. B. an n8n, Node-RED oder
einen eigenen Dienst. Optional mit [HMAC](term:hmac)-Signatur und eigenem Auth-Header. In der Schublade zeigt
„Beispiel anzeigen“ das Format.

### Inhalt (JSON, Version 1) {#webhook-payload}

So sieht eine Nachricht aus (hier lesbar formatiert – der echte Body ist kompaktes JSON in UTF-8, ohne Leerzeichen und
mit Umlauten im Klartext):

```json
{
  "version": 1,
  "type": "news.stories",
  "id": "00000000-0000-4000-8000-000000000001",
  "sent_at": "2026-10-28T12:00:03Z",
  "app": "cobe-news",
  "app_url": "https://news.corp.example:8095/",
  "channel": "n8n SOC",
  "rules": ["Kritisch an SOC"],
  "lang": "de",
  "total": 1,
  "more": 0,
  "stories": [
    {
      "id": "00000000-0000-4000-8000-000000000002",
      "title": "Kritische Lücke in Example Gateway (CVE-2026-0001)",
      "summary": "Angreifer können ohne Anmeldung Code ausführen …",
      "url": "https://news.example.com/advisory/2026-0001",
      "link": "https://news.corp.example:8095/?story=00000000-0000-4000-8000-000000000002",
      "severity": "critical",
      "source": "Example Feed",
      "published_at": "2026-10-28T11:58:00Z",
      "cves": ["CVE-2026-0001"],
      "kind": "news",
      "topics": ["exploited"],
      "product": "Example Gateway < 2.4.1"
    }
  ]
}
```

| Feld | Bedeutung |
|---|---|
| `version` | Format-Version, zurzeit `1`. Neue Felder können dazukommen; eine inkompatible Änderung erhöht die Version. |
| `type` | `news.stories` oder `news.test` (Knopf „Testen“). |
| `id` | Kennung der Nachricht, gleich dem Header `X-Cobe-Delivery`. Dieselbe Nachricht hat beim erneuten Versand dieselbe `id`; ein Test bekommt jedes Mal eine neue. |
| `sent_at` | Zeitpunkt des Versands (UTC). |
| `app_url` | Adresse dieser Installation (`BASE_URL`). |
| `channel`, `rules` | Name des Kanals und der Regeln, die die Meldungen gebracht haben (beim Test leer). |
| `lang` | Sprache der Regel: `de` oder `en`. |
| `total`, `more` | Meldungen insgesamt; `stories` enthält höchstens 10, `more` zählt den Rest. |

Felder einer Meldung in `stories`:

| Feld | Bedeutung |
|---|---|
| `id` | Kennung der Meldung bzw. des Ereignisses. |
| `title`, `summary` | Titel und Zusammenfassung. |
| `url` | Original-Link (leer, wenn er nicht mit `http(s)` beginnt). |
| `link` | öffnet die Meldung in Cobe News. |
| `severity` | `critical`, `high`, `medium`, `low` oder `info`. |
| `source` | Name der Quelle. |
| `published_at` | Veröffentlichung (bei Vendor News und Quellen-Ereignissen: Zeitpunkt des Ereignisses). |
| `cves` | CVE-Nummern, falls bekannt. |
| `kind` | `news`, `vendor.vuln`, `vendor.version`, `vendor.eol`, `vendor.change` oder `source.health`. |
| `topics` | die [Themen](/docs/news-quellen#themen) der Meldung: `zeroday`, `exploited`, `poc` (Exploit veröffentlicht), `ransomware`, `nopatch`, `breach`, `supply`, `phishing`, `ot` (seit 0.1.46; bei Vendor News `exploited`, wenn aktiv ausgenutzt). |
| `product` | das Produkt, wenn sicher bekannt (wie das Feld „Produkt“ der [Karten](#nachrichten-format)), sonst leer (seit 0.1.46). |
| `match` | warum die Regel die Meldung bringt: die Namen ihrer Systeme und Schlagwörter, die passten (z. B. `["PAN-OS"]`), sonst leer (seit 0.1.53). |

Bei `vendor.*` öffnet `link` das Produkt auf der Seite Vendor News; `source` ist „Vendor News“. Bei `source.health`
führen `url` und `link` zur Seite *Integrationen → Gesundheit*; die Schwere ist `high` (tot), `medium` (gestört) oder
`info` (wieder in Ordnung).

> [!WARNING]
> Titel, Zusammenfassung und Links stammen aus fremden Feeds. Behandle sie beim Empfänger als nicht vertrauenswürdig –
> nicht als Befehl ausführen, nicht ungeprüft als HTML anzeigen.

### Weitergeleitete Meldungen {#webhook-weiterleiten}

Ist ein Webhook-Kanal der [Weiterleitungs-Kanal eines Teams](/docs/anmeldung#teams-weiterleiten), kommt eine
weitergeleitete Meldung mit `"type": "news.forward"` (Header `X-Cobe-Event: news.forward`, signiert wie sonst). Statt
`stories` steht ein Objekt `forward` darin: `by` (Anzeigename), `team`, `comment` (entschärft, Zeilenumbrüche
bleiben), `kind` (`story` oder `finding`), `title`, `summary`, `url`, `link`, `severity`, `source`, `published_at`,
`cves`, `score` (`value`, `level` – nur bei Befunden), `versions` und seit 0.1.46 wie bei `stories` `topics` und
`product` (leer, wenn nicht sicher bekannt). Auch Name und Kommentar sind beim Empfänger als
nicht vertrauenswürdig zu behandeln.

### Header und Antwort {#webhook-header}

| Header | Inhalt |
|---|---|
| `Content-Type` | `application/json` |
| `User-Agent` | `Cobe-News-Webhook/1` |
| `X-Cobe-Event` | wie `type`: `news.stories` oder `news.test` |
| `X-Cobe-Delivery` | wie `id` |
| `X-Cobe-Timestamp` | Unix-Zeit in Sekunden – nur mit Signatur |
| `X-Cobe-Signature` | `sha256=` und die HMAC als Hex – nur mit Signatur |
| eigener Header | z. B. `Authorization` – nur mit „Eigener Auth-Header“ |

Antwort des Empfängers:

- **2xx** heißt zugestellt.
- Weiterleitungen (3xx) folgt Cobe News nicht – sie zählen als Fehler.
- 401/403 zeigt „Anmeldung abgelehnt“, 404/410 „Vom Empfänger abgelehnt“, 429 „Vom Dienst gebremst“ (ein
  `Retry-After` wird beachtet), alles andere „Die Gegenstelle hat den Aufruf abgelehnt“.
- Der Empfänger hat 10 Sekunden für den Verbindungsaufbau und insgesamt höchstens 25 Sekunden pro Aufruf. Antworte
  schnell und verarbeite lange Aufgaben danach.

Cobe News liefert **mindestens einmal**: Fällt die Antwort unterwegs aus, kommt dieselbe Nachricht noch einmal – mit
derselben `id`.

### Signatur (HMAC) {#webhook-signatur}

Mit „Signieren (HMAC-SHA256)“ prüft der Empfänger, dass der Aufruf von Cobe News kommt und unverändert ist. Empfohlen –
vor allem ohne eigenen Auth-Header.

1. In der Schublade „Signieren (HMAC-SHA256)“ einschalten.
2. „Erzeugen“ klicken (oder ein eigenes Geheimnis mit mindestens 16 Zeichen eintragen).
3. Das Geheimnis kopieren und beim Empfänger eintragen – nach dem Speichern wird es nie wieder angezeigt.
4. Speichern.

So rechnet Cobe News:

1. `ts` = aktuelle Unix-Zeit in Sekunden als Text, z. B. `1793102403`. Sie steht in `X-Cobe-Timestamp`.
2. Nachricht = `ts`, ein Punkt, dann die **rohen Bytes** des Bodys: `"<X-Cobe-Timestamp>.<Body>"`.
3. HMAC-SHA256 über diese Nachricht mit dem Geheimnis (UTF-8) als Schlüssel, als Hex in Kleinbuchstaben.
4. `X-Cobe-Signature: sha256=<hex>`.

Jeder Versuch wird neu signiert (neuer Zeitstempel); die `id` bleibt gleich.

Der Empfänger sollte:

- die Signatur über die **rohen Body-Bytes** prüfen – nicht über JSON, das er geparst und wieder serialisiert hat
  (andere Leerzeichen oder `ü` statt „ü“ ergeben eine andere Signatur),
- in **konstanter Zeit** vergleichen,
- nur Zeitstempel annehmen, die höchstens ein paar Minuten (z. B. 5) abweichen – so lassen sich alte Aufrufe nicht
  wiederholen; die Uhren beider Seiten per NTP stellen,
- sich `id` bzw. `X-Cobe-Delivery` merken und eine zweite Zustellung verwerfen.

### Signatur prüfen: Beispiele {#signatur-pruefen}

**Python** (nur Standardbibliothek). `body` sind die rohen Bytes, z. B. `request.get_data()` in Flask,
`await request.body()` in FastAPI oder `request.body` in Django. Die Header müssen ohne Rücksicht auf
Groß-/Kleinschreibung lesbar sein – das sind sie in diesen Frameworks.

```python
import hashlib
import hmac
import time

SECRET = b"das-geheimnis-aus-cobe-news"
TOLERANCE = 300  # Sekunden


def verify(headers, body: bytes) -> bool:
    ts = headers.get("X-Cobe-Timestamp", "")
    sig = headers.get("X-Cobe-Signature", "")
    if not (ts.isascii() and ts.isdigit()) or abs(time.time() - int(ts)) > TOLERANCE:
        return False
    mac = hmac.new(SECRET, ts.encode() + b"." + body, hashlib.sha256)
    return hmac.compare_digest(("sha256=" + mac.hexdigest()).encode(), sig.encode())
```

**Node.js** (ohne Pakete) – ein kleiner Empfänger auf Port 8081. Mit Express statt `JSON` die rohen Bytes nehmen:
`express.raw({ type: "application/json" })`.

```js
const crypto = require("node:crypto");
const http = require("node:http");

const SECRET = process.env.COBE_SECRET ?? "";
const TOLERANCE = 300; // Sekunden
const seen = new Map(); // X-Cobe-Delivery -> Zeitpunkt

function verify(headers, rawBody) {
  const ts = headers["x-cobe-timestamp"] ?? "";
  const sig = headers["x-cobe-signature"] ?? "";
  if (!/^\d+$/.test(ts) || Math.abs(Date.now() / 1000 - Number(ts)) > TOLERANCE) return false;
  const expected = "sha256=" + crypto.createHmac("sha256", SECRET).update(ts + ".").update(rawBody).digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(sig);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const raw = Buffer.concat(chunks); // die rohen Bytes
    if (!verify(req.headers, raw)) {
      res.writeHead(401).end();
      return;
    }
    const id = req.headers["x-cobe-delivery"];
    if (!seen.has(id)) {
      seen.set(id, Date.now());
      const msg = JSON.parse(raw);
      console.log(msg.type, msg.total, msg.stories.map((s) => s.title));
    }
    res.writeHead(204).end();
  });
}).listen(8081);
```

**PowerShell** (Windows PowerShell 5.1 und PowerShell 7) – die Prüfung als Funktion, darunter ein kleiner Empfänger mit
`HttpListener` auf Port 8082 (unter Windows als Administrator starten).

```powershell
function Test-CobeSignature {
    param(
        [string] $Secret,
        [string] $Timestamp,
        [string] $Signature,
        [byte[]] $Body,
        [int] $ToleranceSeconds = 300
    )
    [long] $ts = 0
    if ($Timestamp -notmatch '^[0-9]+$' -or -not [long]::TryParse($Timestamp, [ref] $ts)) { return $false }
    if ([math]::Abs([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $ts) -gt $ToleranceSeconds) { return $false }

    $data = [byte[]]([Text.Encoding]::UTF8.GetBytes("$Timestamp.") + $Body)
    $hmac = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($Secret))
    try { $hash = $hmac.ComputeHash($data) } finally { $hmac.Dispose() }
    $expected = [Text.Encoding]::ASCII.GetBytes('sha256=' + (-join ($hash | ForEach-Object { $_.ToString('x2') })))
    $given = [Text.Encoding]::ASCII.GetBytes($Signature)

    # Vergleich in konstanter Zeit
    if ($expected.Length -ne $given.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $expected.Length; $i++) { $diff = $diff -bor ($expected[$i] -bxor $given[$i]) }
    return $diff -eq 0
}

$secret = $env:COBE_SECRET
$seen = @{}
$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add('http://+:8082/')
$listener.Start()
while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    $ms = [IO.MemoryStream]::new()
    $ctx.Request.InputStream.CopyTo($ms)
    $body = $ms.ToArray()   # die rohen Bytes
    $h = $ctx.Request.Headers
    if (-not (Test-CobeSignature -Secret $secret -Timestamp $h['X-Cobe-Timestamp'] -Signature $h['X-Cobe-Signature'] -Body $body)) {
        $ctx.Response.StatusCode = 401
    } else {
        $id = $h['X-Cobe-Delivery']
        if (-not $seen.ContainsKey($id)) {
            $seen[$id] = Get-Date
            $msg = [Text.Encoding]::UTF8.GetString($body) | ConvertFrom-Json
            Write-Host $msg.type $msg.total
        }
        $ctx.Response.StatusCode = 204
    }
    $ctx.Response.Close()
}
```

In allen drei Beispielen merkt sich der Empfänger die `id` nur im Speicher. Im Betrieb gehört sie in eine Datenbank
oder einen Cache mit Ablaufzeit (z. B. ein Tag).

### Eigener Auth-Header {#webhook-auth-header}

Verlangt der Empfänger eine Anmeldung (z. B. n8n mit „Header Auth“), schickt Cobe News bei jedem Aufruf einen festen
Header mit.

1. „Eigener Auth-Header“ einschalten.
2. „Header-Name“ eintragen – vorbelegt ist `Authorization`, üblich ist auch `X-Api-Key`.
3. „Wert“ eintragen, z. B. `Bearer …`. Er wird verschlüsselt gespeichert und nie wieder angezeigt.
4. Speichern.

Der Name besteht aus Buchstaben, Ziffern und Bindestrichen (höchstens 64 Zeichen). Nicht erlaubt sind Header, die
Cobe News selbst setzt oder die die Anfrage verändern (z. B. `Host`, `Content-Type`, `Content-Length`, `User-Agent`,
`Cookie`) und alles, was mit `X-Cobe-` beginnt.

Wechselt die URL auf einen anderen Host, Port oder von https auf http, musst du HMAC-Geheimnis und Header-Wert neu
eingeben. Ein gespeichertes Geheimnis geht nie ungefragt an ein neues Ziel.

### Optionen: http und Proxy {#webhook-optionen}

**„Unverschlüsselt (http) erlauben“** – ab Werk aus; dann nimmt Cobe News nur `https://`-URLs an. Einschalten nur für
ein Ziel im eigenen, vertrauenswürdigen Netz: Über http gehen Meldungen, Signatur und Auth-Header im Klartext durchs
Netz.

**„Über den Proxy (HTTPS_PROXY)“** – nur von Bedeutung, wenn auf dem Server `HTTPS_PROXY` gesetzt ist. Bei einem neuen
Webhook ist der Schalter aus – im Formular wie über die API (ein Aufruf ohne `use_proxy`). Kanäle, die schon vorher
gespeichert waren, behalten ihre Einstellung.

- **Aus:** Cobe News verbindet sich direkt. Der Name wird einmal aufgelöst, die Adresse geprüft (siehe
  [Erlaubte Ziele](#webhook-ziele)) und genau diese Adresse verbunden. Richtig für interne Ziele wie n8n.
- **Ein:** Der Aufruf geht über den Proxy, und der Proxy löst den Namen auf. Cobe News prüft dann nur Adressen, die
  direkt in der URL stehen. Richtig für Dienste im Internet, wenn euer Netz nur über den Proxy hinausgeht.

Teams, Slack, Discord und Telegram gehen immer über den Proxy, wenn einer gesetzt ist.

### Erlaubte Ziele {#webhook-ziele}

**Teams und Slack** nehmen ab Werk nur URLs auf `hooks.slack.com`, `*.webhook.office.com`, `*.logic.azure.com` und
`*.powerplatform.com`. Weitere Hosts trägt ein Admin in `WEBHOOK_HOSTS` in der [.env](term:envfile) ein
(kommagetrennt, genau oder mit `*.` für alle Namen darunter). Discord und Telegram haben feste Hosts; der generische
Webhook hat keine Host-Liste.

**Interne Adressen** sind für alle Kanäle ab Werk gesperrt – auch für den Webhook. Erlaubt sind nur öffentliche
Adressen.

Warum? Eine Webhook-URL lässt den Server Anfragen an ein beliebiges Ziel schicken. Ohne Sperre könnte jemand mit
Admin-Zugang (oder einer gestohlenen Admin-Sitzung) so Dienste im Firmennetz erreichen, die von außen nicht erreichbar
sind ([SSRF](term:ssrf), Server-Side Request Forgery). Besonders heikel ist der Docker-Host: Dahinter lauschen oft
Dienste nur auf `127.0.0.1` und halten eine Anfrage von dort für „lokal“ und damit vertrauenswürdig.

Ein internes Ziel – z. B. n8n im Firmennetz – erlaubst du gezielt mit `WEBHOOK_PRIVATE_NETS`: eine Liste von
Adressen oder Netzen in [CIDR](term:cidr)-Schreibweise. Um genau eine Adresse zu erlauben, öffnest du auf dem Server
`/opt/cobe-news/.env` und trägst diese Zeile ein:

```bash
WEBHOOK_PRIVATE_NETS=10.20.0.15/32
```

Danach startest du die App mit der neuen Einstellung und prüfst den Kanal mit „Testen“:

```bash
cd /opt/cobe-news
docker compose up -d
```

Mehrere Einträge trennst du mit Kommas, z. B. `10.20.0.15/32,10.20.5.0/28`. Eine Adresse ohne `/` gilt als genau
diese eine. Ungültige Einträge werden still übergangen – prüfe daher nach dem Neustart mit „Testen“.

**Gesperrt, solange die Adresse nicht in der Liste steht** – ein Eintrag in `WEBHOOK_PRIVATE_NETS` erlaubt sie:

- private Adressen (`10.…`, `172.16–31.…`, `192.168.…`, IPv6-ULA und andere nicht öffentliche Bereiche),
- die eigenen Docker-Netze von Cobe News, z. B. ein Empfänger im Netz `edge`: `WEBHOOK_PRIVATE_NETS=172.31.250.50`,
- der Docker-Host: das Gateway des Containers (ab Werk `172.31.250.128`), bei Docker Desktop `192.168.65.0/24`.

**Immer gesperrt**, auch wenn die Adresse in der Liste steht:

- Loopback (`127.0.0.0/8`, `::1`),
- Link-Local (`169.254.0.0/16` samt der Cloud-Metadaten-Adresse `169.254.169.254`, `fe80::/10`) und die
  Metadaten-Adresse von AWS für IPv6 (`fd00:ec2::254`),
- „dieses Netz“ bzw. „any“ (`0.0.0.0/8`, `::`) und Multicast,
- dieselben Adressen versteckt in IPv6-Schreibweisen (IPv4-mapped, NAT64, 6to4 …),
- Namen, die für den Docker-Host stehen, z. B. `host.docker.internal`, `gateway.docker.internal` oder
  `host.lima.internal`. Ein Ziel auf dem Docker-Host geht nur über seine Adresse.

`127.0.0.1` in einer Webhook-URL wäre der Container von Cobe News selbst, nicht euer Server. Einen Dienst auf dem
Server erreichst du über die Adresse des Docker-Hosts (siehe [unten](#webhook-testen)).

> [!WARNING]
> Eine Adresse in `WEBHOOK_PRIVATE_NETS` gilt ohne weitere Prüfung. Trage nur genau die Ziele ein, die du brauchst
> (am besten `/32`), keine großen Bereiche wie `10.0.0.0/8` oder `0.0.0.0/0`.

Der Name einer URL wird einmal aufgelöst, geprüft und genau diese Adresse verbunden. Ein Name, der später auf eine
andere Adresse zeigt, kann die Prüfung so nicht umgehen (DNS-Rebinding). Steht eine gesperrte Adresse direkt in der
URL, lehnt schon das Speichern ab; zeigt ein Name auf eine gesperrte Adresse, meldet der Versand „Ziel nicht erlaubt“.

### Webhook testen {#webhook-testen}

Bevor der echte Empfänger fertig ist, kannst du mit einem kleinen Test-Empfänger sehen, was ankommt.

**Möglichkeit 1: öffentlicher Request-Bin-Dienst.** Solche Dienste geben dir eine https-URL und zeigen jeden Aufruf mit
Headern und Body an. Das geht ohne Änderung an der `.env`, weil das Ziel öffentlich ist. Der Dienst sieht dabei den
Inhalt – Testnachrichten enthalten die neueste Meldung, Kanal- und Regelnamen und die Adresse eurer Installation.
Verwende dort ein Test-Geheimnis und lösche den Kanal danach.

**Möglichkeit 2: eigener Empfänger auf einem Rechner im LAN.** Dieses Python-Skript (nur Standardbibliothek) nimmt
Aufrufe auf Port 8080 an, prüft die Signatur, wenn `COBE_SECRET` gesetzt ist, verwirft Doppelte und gibt jede Nachricht
aus. Speichere es als `receiver.py`:

```python
import hashlib
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ.get("COBE_SECRET", "").encode()  # leer: Kanal ohne Signatur
PORT = int(os.environ.get("PORT", "8080"))
TOLERANCE = 300  # Sekunden
seen = set()  # schon verarbeitete X-Cobe-Delivery


def verify(headers, body: bytes) -> bool:
    ts = headers.get("X-Cobe-Timestamp", "")
    sig = headers.get("X-Cobe-Signature", "")
    if not (ts.isascii() and ts.isdigit()) or abs(time.time() - int(ts)) > TOLERANCE:
        return False
    mac = hmac.new(SECRET, ts.encode() + b"." + body, hashlib.sha256)
    return hmac.compare_digest(("sha256=" + mac.hexdigest()).encode(), sig.encode())


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if SECRET and not verify(self.headers, body):
            print("Signatur falsch oder zu alt")
            self.send_response(401)
            self.end_headers()
            return
        delivery = self.headers.get("X-Cobe-Delivery", "")
        if delivery in seen:
            print("doppelt, verworfen:", delivery)
        else:
            seen.add(delivery)
            msg = json.loads(body)
            print(msg["type"], msg["total"], [s["title"] for s in msg["stories"]])
        self.send_response(204)
        self.end_headers()


HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
```

Starten (das Geheimnis aus der Schublade des Kanals; ohne Signatur `COBE_SECRET` weglassen):

```bash
COBE_SECRET='das-geheimnis-aus-cobe-news' python3 receiver.py
```

Dann in Cobe News – angenommen, der Rechner hat die Adresse `10.20.0.15`:

1. `WEBHOOK_PRIVATE_NETS=10.20.0.15/32` in die `.env` eintragen und `docker compose up -d` (siehe
   [Erlaubte Ziele](#webhook-ziele)).
2. Einen Kanal „Webhook“ anlegen, „Ziel-URL“ `http://10.20.0.15:8080/`.
3. „Unverschlüsselt (http) erlauben“ einschalten, „Über den Proxy“ aus lassen.
4. Optional „Signieren (HMAC-SHA256)“ mit demselben Geheimnis wie beim Start des Skripts.
5. Speichern und „Testen“ klicken. Im Terminal erscheint eine Zeile mit `news.test`.

Kommt nichts an: Lässt die Firewall des Rechners Port 8080 zu? Zeigt der Kanal „Ziel nicht erlaubt“, stimmt der Eintrag
in `WEBHOOK_PRIVATE_NETS` nicht oder die App wurde nicht neu gestartet.

**Empfänger auf dem Docker-Host selbst:** `127.0.0.1` geht nicht – das wäre der Container von Cobe News, und Loopback
ist immer gesperrt. Stattdessen:

- **Linux:** Das Skript lauscht auf `0.0.0.0` (wie oben). Als Ziel nimmst du die LAN-Adresse des Rechners oder das
  Gateway des Containers (ab Werk `172.31.250.128`) und trägst genau diese Adresse in `WEBHOOK_PRIVATE_NETS` ein.
- **Docker Desktop:** Dienste, die auf dem Rechner nur an `127.0.0.1` lauschen, erreicht der Container über die
  Adresse hinter `host.docker.internal`, meist `192.168.65.254`. Diese Adresse in der URL verwenden und in
  `WEBHOOK_PRIVATE_NETS` eintragen – den Namen `host.docker.internal` selbst lehnt Cobe News immer ab.

Nach dem Test: den Kanal löschen und den Eintrag aus `WEBHOOK_PRIVATE_NETS` wieder entfernen (danach erneut
`docker compose up -d`).

## Regeln {#regeln .admin}

Regeln legen fest, *was* an welche Kanäle geht. Du findest sie unter [*Einstellungen → Kanäle & Regeln*](/settings/rules),
Reiter „Regeln“. Lege zuerst mindestens einen Kanal an.

### Regel anlegen {#regel-anlegen}

1. Reiter „Regeln“ → „Neue Regel“.
2. „Regel aktiv“ eingeschaltet lassen.
3. **Name** vergeben, z. B. „Kritisch an SOC“.
4. **Sprache** wählen (Deutsch oder English) – in dieser Sprache kommen die Nachrichten.
5. **Kanäle** wählen – mindestens einer, mehrere sind möglich. „Neuen Kanal anlegen“ führt zu den Kanälen.
6. Bei „Was wird gesendet?“ eine oder mehrere Arten einschalten (siehe unten).
7. **Schweregrade** wählen (ab Werk Kritisch und Hoch; leer = alle) und bei Security-Meldungen die **Quellen**
   (leer = alle) und die **Themen** (leer = jede Meldung, siehe [Themen in Regeln](#regel-themen)) – und bei Bedarf
   **Systeme**, **Schlagwörter** und **Nicht senden, wenn enthalten** (siehe [Systeme, Schlagwörter und Ausschluss](#regel-systeme)).
8. Speichern.

In der Liste schaltest du eine Regel mit dem Schalter rechts ein und aus; der Stift öffnet sie, der Papierkorb löscht
sie. Eine Regel ohne Kanal verschickt nichts.

### Arten {#regel-arten}

| Art (im Code) | In der Oberfläche | Was kommt | Schweregrade / Quellen |
|---|---|---|---|
| `news` | „Security-Meldungen“ | neue Meldungen aus dem News-Feed | beide gelten |
| `vendor_vuln` | „Schwachstelle betrifft eines unserer Systeme“ | eine neue Schwachstelle betrifft eine eingetragene Version oder ein gefolgtes Produkt ohne Version | Schweregrade gelten |
| `vendor_version` | „Neue Version / EOL naht“ | neuere Version in der [Release-Linie](term:releaseline), Support-Ende in weniger als 6 Monaten, [Vorwarnung](/docs/vendor-news#eol-vorwarnung) 90 und 30 Tage vor dem Support-Ende jeder eingetragenen Version, Support-Ende erreicht | gelten nicht |
| `vendor_change` | „Advisory geändert“ | ein Hersteller hat ein Advisory zu einem gefolgten Produkt nachträglich geändert: neue Fix-Version, andere Schwere, Bereich, KEV, zurückgezogen ([mehr](/docs/vendor-news#aenderungen)) | Schweregrade gelten |
| `source_health` | „Quelle gestört oder tot“ | eine Quelle wird gestört oder tot – und wieder in Ordnung; einmal je Zustandswechsel | gelten nicht |

„Advisory geändert“ ist neu und muss in einer Regel **ausdrücklich** eingeschaltet werden – bestehende Regeln bekommen
die Art nicht dazu. Gemeldet wird nur, wenn das Advisory eure eingetragenen Versionen betrifft oder betraf (ohne Version:
jede Änderung). Die Nachricht sagt kurz, was sich geändert hat, die Wirkung auf eure Versionen zuerst, z. B. „Revision 2:
PAN-OS 11.2.4-h23: jetzt betroffen (vorher nicht betroffen) – Fix 11.2.4-h30“. Eine Revision kommt einmal pro Kanal.
Die Vorwarnungen vor dem Support-Ende (90 und 30 Tage) sind Teil von „Neue Version / EOL naht“: Bestehende Regeln mit
dieser Art bekommen sie ohne Änderung. Meldungen zu [beobachteten CVEs](#cves-beobachten) gehen nie über Regeln und
Kanäle, nur an die Person, die beobachtet.

Vendor News meldet jede Schwachstelle einmal pro Produkt und Version. Was beim ersten Prüfen einer neu eingetragenen
Version schon bekannt ist, steht auf der Seite, wird aber nicht verschickt. Mehr dazu in
[Vendor News](/docs/vendor-news#ueberblick) und [Quellen-Gesundheit](/docs/news-quellen#quellen-gesundheit).

### Probelauf {#probelauf}

Bevor du eine Regel speicherst oder erweiterst: **„Probelauf“** unten im Regel-Editor zeigt, was sie ausgelöst hätte.

1. Den Zeitraum wählen: letzter Tag, letzte 7 oder letzte 30 Tage.
2. „Probelauf“ klicken.

Geprüft wird die Regel **so, wie sie gerade im Formular steht** – auch ungespeichert – gegen die gespeicherten
Meldungen, Vendor-News-Ereignisse und Zustandswechsel der Quellen, mit derselben Logik wie beim echten Versand (so, als
wäre ein Kanal die ganze Zeit verbunden gewesen). Das Ergebnis:

- die Zahl der Treffer und eine Liste der neuesten (Titel, Zeit, Schwere und warum sie passt: Art, Schwere, Quelle,
  Thema, Team, Treffer bei Systemen und Schlagwörtern),
- wie viele **Nachrichten** daraus geworden wären – was in derselben Minute eintrifft, kommt in einer Runde, ab 4
  Meldungen als eine [Sammelnachricht](#einmal-pro-kanal) –, im Schnitt pro Tag und am stärksten Tag,
- die Warnung **„Dieser Kanal würde geflutet“**, wenn es an einem Tag mehr als 20 Nachrichten gewesen wären.

Der Probelauf zeigt, was die Regel **abdeckt**: Er zählt auch ältere Meldungen, die ein System oder Thema erst
nachträglich und still bekommen haben – etwa beim ersten Abgleich nach einem Update oder einer Katalog-Änderung. Solche
Meldungen verschickt die Regel nicht; neue schon.

Der Probelauf sendet nichts und schreibt nichts: keine Markierung „verschickt“, keine Änderung an Regel oder Kanal. Er
läuft lesend und mit Zeitlimit; dauert er zu lange, wähle einen kürzeren Zeitraum. Ändert sich das Formular danach,
wird das Ergebnis blass – einfach erneut starten. Nur Admins.

### Themen in Regeln {#regel-themen}

Bei Security-Meldungen kann eine Regel zusätzlich **Themen** verlangen ([was sie bedeuten](/docs/news-quellen#themen)),
z. B. „Kritisch an SOC“ nur für *Aktiv ausgenutzt* und *Exploit veröffentlicht*.

- **Eines genügt:** Die Meldung braucht eines der gewählten Themen – **und** passt außerdem zu Schweregraden und
  Quellen. Leer heißt: jede Meldung, wie bisher. Bestehende Regeln haben keine Themen und verhalten sich unverändert.
- **Thema kommt später:** Viele Themen stehen erst nach dem Eintreffen fest – die CVE kommt in den KEV-Katalog, die
  [Details aus der Quelle](/docs/news-quellen#details-aus-der-quelle) sagen „ausgenutzt“ oder „kein Fix“, die CISA
  stuft auf „poc“. Eine Meldung, die nach dem Speichern der Regel eintraf und ein verlangtes Thema erst danach bekommt,
  wird **dann** verschickt – mit der nächsten Runde, **einmal** pro Kanal, nie doppelt (auch nicht, wenn später ein
  weiteres Thema dazukommt). Ältere Meldungen bleiben, wie unter [Nur Neues](#nur-neues) beschrieben, außen vor.
- **Kein Schwall durch Neuberechnung:** Bekommen viele Meldungen ein Thema auf einmal, weil alle Themen neu berechnet
  werden – eine Exploit-Sammlung wird eingeschaltet oder zum ersten Mal geladen, ein Update ändert die Themenregeln –,
  zeigt Cobe News das Thema an diesen Meldungen (Filter, Badge), verschickt sie dafür aber **nicht**. Das gilt auch für
  „Exploit veröffentlicht“, das nur auf dem Grundbestand einer Sammlung beruht. Ein Thema durch ein eigenes Ereignis
  (neuer KEV-Eintrag, neuer Eintrag einer Sammlung, eingetroffene Details) kommt weiter einmal.
- **Nur Security-Meldungen:** Für Vendor-News-Ereignisse und Quellen-Gesundheit gelten die Themen nicht.
- **Erweitern:** Themen entfernen oder weitere wählen ist ein [erweiterter Filter](#nur-neues) – was erst dadurch
  passt, kommt ab der Änderung.
- Der [Probelauf](#probelauf) prüft die Themen mit und nennt bei jedem Treffer das Thema, über das er passt; das
  [Zustellprotokoll](#protokoll-inhalt) zeigt die Themen jeder verschickten Meldung, das
  [Protokoll](/docs/betrieb#protokoll) jede Änderung der Themen einer Regel.

### Systeme, Schlagwörter und Ausschluss {#regel-systeme}

Mit **Systeme** und **Schlagwörter** („Betrifft“) und **Nicht senden, wenn enthalten** wird aus „alles Kritische“
eine Regel für genau das, was euch angeht. Beispiel „nur Palo Alto, nur Kritisch“:

1. Neue Regel, Art „Security-Meldungen“ (und, wenn gewünscht, „Schwachstelle betrifft eines unserer Systeme“).
2. **Schweregrade:** nur *Kritisch*.
3. **Systeme:** „Alle Produkte von Palo Alto Networks“ – oder einzelne Produkte wie *PAN-OS*.
4. Optional **Nicht senden, wenn enthalten:** *Webinar*.
5. [Probelauf](#probelauf) starten, speichern.

- **Systeme** kommen aus dem **ganzen Katalog**, nicht nur aus den gefolgten Produkten. Ein Hersteller umfasst alle
  seine Produkte – auch solche, die der Katalog später dazubekommt. Eine Meldung passt, wenn
  - ihre [Details aus der Quelle](/docs/news-quellen#details-aus-der-quelle) das Produkt betreffen (CSAF, NVD-CPE,
    CVE-Eintrag; „nicht betroffen“ zählt nicht), oder
  - Titel oder Teaser das Produkt oder den Hersteller nennen (ganze Wörter, „PAN-OS“ auch als „PAN OS“, ein Produkt
    auch ohne den Hersteller davor: „Chrome“ für *Google Chrome*). Namen aus gewöhnlichen Wörtern – *Exchange*,
    *Panorama*, *Expedition*, *Teams* – zählen nur, wenn auch der Hersteller genannt ist („Microsoft Exchange“), damit
    „Die Expedition ins Darknet“ nicht als Palo-Alto-Meldung kommt. Einige bekannte (Exchange, Outlook, Teams, Edge,
    Windows, Zoom, Spring Framework …) zählen auch im Zusammenhang einer Sicherheitsmeldung: „Exchange-Lücke“, „Kritische
    Lücke in Exchange“, „Zoom fixes flaws“, „Windows 11“, „Edge-Browser“. Ein Herstellername als Ort oder Begriff zählt
    nicht („Palo Alto city hall“, „PALO ALTO, Calif.“, „Threat Intel“).
  - Nennt eine Meldung **nur den Hersteller** („Zyxel warnt vor Angriffen“), passt sie auf „Alle Produkte von Zyxel“,
    nicht auf ein einzelnes Zyxel-Produkt. Ein Name, den mehrere Produkte eines Herstellers teilen, zählt für das
    Produkt, dessen Name es ist: „PAN-OS“ ist PAN-OS, nicht Panorama; der längere Name gewinnt („NGINX Plus“ ist nicht
    auch nginx).
- **Unsere Produkte (aus Vendor News)** steht ganz oben in der Auswahl: alle Produkte, denen Cobe News in
  [Vendor News](/docs/vendor-news) folgt – so, als wäre jedes einzeln gewählt (Details oder Titel/Teaser), dazu per CPE
  angelegte eigene Produkte über ihre Details. Es gilt die Liste von jetzt: Ein später gefolgtes Produkt zählt für
  Meldungen, die **ab dann** eintreffen (oder es ab dann bekommen, etwa durch nachgelieferte Details) – ältere Meldungen
  zu ihm kommen nicht nachträglich. Ein Produkt, dem ihr nicht mehr folgt (ausgeschaltet oder entfernt), zählt nicht
  mehr. Folgt ihr keinem Produkt, passt nichts. „Treffer“ nennt das Produkt („Treffer: PAN-OS“).
- Ein **Hersteller ist einer**, auch wenn der Katalog ihn verschieden schreibt: „VMware“ und „Broadcom (VMware)“, „Apache“
  und „Apache Software Foundation“, „LANCOM“ und „LANCOM Systems“ erscheinen als eine Gruppe, „Alle Produkte“ umfasst
  alle. Ein Eigentümer in Klammern macht keinen: „CyberArk (Palo Alto Networks)“ gehört nicht zu Palo Alto Networks.
- **Schlagwörter:** eigene Wörter, Enter oder Komma fügt eines hinzu (höchstens 30, je 2–60 Zeichen). Eines genügt,
  als ganzes Wort in Titel oder Teaser, Groß-/Kleinschreibung und Akzente egal; Leerzeichen und Bindestrich sind
  gleich („Citrix Bleed“ findet „Citrix-Bleed“). Reiner Text, keine Muster.
- **Systeme oder Schlagwörter:** eines von beiden genügt – **und** dazu passen Schweregrade, Quellen, Themen und Teams.
  Beides leer heißt: keine Einschränkung, wie bisher.
- **Nicht senden, wenn enthalten:** Steht eines dieser Wörter in Titel oder Teaser, kommt die Meldung über diese Regel
  nie – egal, was sonst passt.
- **Vendor News:** Systeme gelten auch für Schwachstellen, neue Versionen und geänderte Advisories (über deren Produkt;
  „Unsere Produkte“: jedes gefolgte Produkt). Schlagwörter und Ausschluss gelten nur für Security-Meldungen, Quellen-Gesundheit kennt keines davon.
- **Details kommen später:** Eine Meldung, die erst durch nachgelieferte Details passt, kommt dann – einmal. Lernt
  dagegen der **Katalog** ein Produkt oder einen Namen dazu (Katalog-Update), werden ältere Meldungen dadurch nicht
  verschickt.
- Ein Produkt, das der Katalog nicht mehr kennt, steht in der Regel als „nicht mehr im Katalog“ und passt auf nichts –
  nie auf „alles“. Entferne es.
- Die Nachricht sagt, warum sie kommt: **„Treffer: PAN-OS“** (bzw. das Schlagwort) in der Mail und in den Karten; der
  Webhook bekommt das Feld `match`.
- **Auch ohne Admin:** Dieselben Systeme gibt es als Filter der [News-Liste](/docs/news-quellen#suchen-filtern), in den
  eigenen [Desktop-Benachrichtigungen](#desktop-einschalten) (mit Schlagwörtern und Ausschluss) und in
  [Hersteller-News meiner Produkte](#meine-produkte-was) – für jede Person selbst.

### Auf Teams beschränken {#regel-teams}

Ist [Teams](/docs/anmeldung#teams) eingeschaltet, hat die Regel ein Feld **Teams**. Leer heißt: alle Produkte. Mit
Teams meldet die Regel Vendor-News-Ereignisse (`vendor_vuln`, `vendor_version`, `vendor_change`) nur für die Produkte dieser Teams.
Security-Meldungen und Quellen-Gesundheit haben kein Produkt – für sie gilt das Feld nicht. Wird einem Team ein Produkt
neu zugeordnet, kommen seine Ereignisse ab dann, nicht die älteren; wird der Team-Filter entfernt, gilt das Gleiche wie
beim [Erweitern einer Regel](#nur-neues).

### Nur Neues – kein Schwall alter Meldungen {#nur-neues}

Eine Regel verschickt nur, was **nach** dem Speichern bzw. Einschalten eintrifft. Ältere Meldungen werden nie
nachgeschickt.

- **Neue oder wieder eingeschaltete Regel:** zählt ab diesem Moment. Was eintraf, während sie aus war, kommt nicht.
  Maßgeblich ist die Reihenfolge des Eintreffens: Eine Meldung aus einem Abruf, der gerade lief, als du gespeichert
  hast, kommt mit.
- **Kanal, der einer Regel später hinzugefügt wird:** bekommt nur, was danach eintrifft.
- **Erweiterter Filter** (mehr Schweregrade, Quellen, Themen, Arten, Systeme oder Schlagwörter, ein Ausschluss-Wort
  weniger): Was erst dadurch passt, kommt ab der Änderung. Was schon vorher passte und noch offen ist, kommt weiterhin.
  Ändert sich eine ältere Meldung **nach** der Änderung genau in dem, was erweitert wurde, sodass sie erst dadurch
  passt – sie wird in eine neue Schwere hochgestuft, eine neu gewählte Quelle bringt sie frisch, sie bekommt ein neu
  gewähltes Thema oder System durch ein eigenes Ereignis, ihr Titel nennt jetzt ein neues Schlagwort –, kommt sie. Eine
  Änderung von etwas anderem bringt keine alte Meldung: Hast du *Hoch* dazugenommen, kommt eine schon vorher hohe
  Meldung nicht, nur weil eine weitere Quelle sie bringt oder ihre Details eintreffen.
- **Neu eingeschaltete Quelle:** Die älteren Meldungen, die sie beim ersten Abruf mitbringt, werden nicht verschickt –
  nur, was danach frisch dazukommt. Das gilt auch für Meldungen, die andere Quellen schon gespeichert haben und die sie
  nur mitführt („auch in“): In der Liste stehen sie unter ihrem Namen, eine Regel nur für diese Quelle bekommt sie nicht,
  und ihre Einstufung hebt sie nicht an.
- **Höher eingestuft durch eine weitere Quelle:** Bringt eine weitere Quelle dieselbe Meldung (gleiche Adresse oder
  gleicher Titel) frisch und stuft sie höher ein, übernimmt die Meldung die höhere Schwere – nur nach oben, wie bei
  einem Update der eigenen Quelle.
- **Vendor News höher eingestuft:** Wird ein Befund später höher eingestuft, kommt „Jetzt höher eingestuft: …“ (siehe
  [Vendor News](/docs/vendor-news)) – eine Regel, die beide Stufen abdeckt, bekommt so eine zweite Nachricht zum selben
  Befund.

### Einmal pro Kanal, Sammelnachricht und Wiederholung {#einmal-pro-kanal}

- Nach jeder Abrufrunde schaut Cobe News, was neu ist. Alle 10 Minuten wird zusätzlich alles geprüft – so folgt auch
  eine Meldung, die inzwischen höher eingestuft ist.
- Jede Meldung geht **höchstens einmal pro Kanal** raus – auch wenn mehrere Regeln sie an denselben Kanal schicken.
- **Bis zu 3** Meldungen einer Runde kommen einzeln (die älteste zuerst). **Mehr** kommen als **eine
  Sammelnachricht**: die 10 wichtigsten, der Rest gezählt – zuerst aktiv ausgenutzte und kritische, dann, was eure
  Produkte betrifft, dann nach Schwere und die neueste zuerst. Regeln mit verschiedener Sprache bekommen getrennte
  Nachrichten.
- Die Kanäle werden nebeneinander beliefert. Scheitert ein Kanal, bleiben seine Meldungen offen und kommen beim nächsten
  Versuch – nach 2, 4, 8 … Minuten, höchstens 6 Stunden (siehe [Testen, Fehler und Pause](#kanal-testen)).
- Jede Nachricht wird direkt nach dem Versand als verschickt vermerkt. Stirbt der Prozess genau dazwischen, kommt sie
  noch einmal; ein Webhook erkennt das an derselben `id`.

## Zustellprotokoll {#zustellprotokoll .admin}

Das Zustellprotokoll zeigt **jeden Zustellversuch** an einen Kanal mit seinem Ergebnis. Du findest es unter
[*Einstellungen → Kanäle & Regeln*](/settings/rules?tab=log), Reiter „Zustellprotokoll“ (alle Kanäle), und in der
Schublade eines Kanals, Reiter „Protokoll“ (nur dieser Kanal).

In der Kanalliste zeigt ein kleines Abzeichen den Stand der letzten 24 Stunden: „Letzte Zustellung ok vor 3 Std.“ (grün)
oder „3 Fehler in 24 Std.“ (gelb, wenn danach etwas durchging; rot, wenn nichts durchging). Tests zählen dafür nicht.

### Was drinsteht {#protokoll-inhalt}

| Art | Wann |
|---|---|
| Regel | eine Nachricht einer Regel an einen Kanal – jede automatische Wiederholung und jedes „Erneut senden“ als weiterer Versuch derselben Zustellung |
| Weiterleitung | eine [Team-Weiterleitung](#weiterleiten) |
| Wochenrückblick | eine Mail des [Wochenrückblicks](#wochenrueckblick) an eine Person |
| Test | „Testen“ eines Kanals |

Pro Zustellung: Kanal (mit dem Namen, den er damals hatte – auch nach dem Löschen), was verschickt wurde (Meldung,
Ereignis oder Befund mit Titel, bei Meldungen mit ihren Themen; bei einer Sammelnachricht die aufgeführten und wie viele
insgesamt), die Regeln, Zeit, Versuch und Ergebnis:

| Ergebnis | Bedeutung |
|---|---|
| Zugestellt | angenommen (HTTP 2xx bzw. vom Mail-Server angenommen) |
| HTTP 4xx/5xx | die Gegenstelle hat abgelehnt – der Status steht dabei |
| Zeitüberschreitung | keine Antwort in der Frist |
| Vom Egress-Schutz blockiert | das Ziel ist nicht erlaubt (siehe [Erlaubte Ziele](#webhook-ziele)) – nichts wurde gesendet |
| SMTP-Fehler | der Mail-Server hat abgelehnt – mit Antwort-Code (z. B. 550), wenn er einen nannte |
| Fehler | DNS, TLS, Verbindung, Geheimnis nicht lesbar … |

Filtern lässt sich nach Kanal, Ergebnis („Nur Fehler“ oder eine Fehlerart), Art und Zeitraum (24 Stunden, 7 oder 30
Tage). Der Pfeil rechts klappt alle Versuche einer Zustellung auf, mit kurzem Fehlertext und Dauer.

**Nie im Protokoll:** der Inhalt einer Nachricht, Webhook-URLs (auch nicht ihr Pfad), Tokens, Thema von ntfy,
HMAC-Geheimnis, Auth-Header, SMTP-Zugangsdaten und Antworten der Gegenstelle. Der Fehlertext wird zusätzlich bereinigt:
Adressen nur mit Host, alles, was nach Token oder E-Mail-Adresse aussieht, ersetzt. Bei einer **Weiterleitung** stehen
weder Absender noch Kommentar drin – nur Team und Meldung. Beim **Wochenrückblick** steht die empfangende Person dabei
(nur Admins sehen das Protokoll), nie die Mail. **Persönliche Wege** (Hersteller-News meiner Produkte) gehören der
jeweiligen Person und stehen nicht im Protokoll – unten im Reiter stehen nur ihre Zahlen der letzten 24 Stunden.

### Erneut senden {#erneut-senden}

Bei einer fehlgeschlagenen Zustellung einer Regel steht **„Erneut senden“**. Es schickt dieselben Meldungen jetzt noch
einmal an denselben Kanal – über denselben Weg mit Egress-Prüfung; ein generischer Webhook bekommt dieselbe `id`, wenn
es dieselbe Nachricht ist.

- **Sofort:** Die Pause des Kanals nach Fehlern gilt nicht – du fragst ihn ja ausdrücklich. Ruhezeiten gibt es nur für
  persönliche Wege, nie für Kanäle.
- **Kommt sie an,** gilt sie als verschickt (die nächste Runde schickt sie nicht noch einmal), und Fehler und Pause des
  Kanals enden wie nach einem erfolgreichen Test. **Scheitert sie,** bleibt alles, wie die Runde es hinterlassen hat –
  sie wird weiter automatisch versucht.
- **Nur einmal:** Ist die Zustellung inzwischen angekommen (auch durch eine automatische Wiederholung), sendet ein
  weiterer Klick nichts. Was der Kanal inzwischen bekommen hat, geht nicht noch einmal mit; sind die Meldungen
  inzwischen gelöscht, gibt es nichts zu senden.
- **Gebremst:** derselbe Kanal höchstens alle 5 Sekunden, höchstens 20 Mal in 10 Minuten pro Admin.

Tests, Weiterleitungen und Wochenrückblicke lassen sich nicht erneut senden: Den Test wiederholst du mit „Testen“, eine
Weiterleitung schickt die Person selbst noch einmal (ihr Kommentar wird nicht gespeichert), der Wochenrückblick
versucht es selbst erneut.

### Aufbewahrung {#protokoll-aufbewahrung}

Einträge bleiben **30 Tage** und werden stündlich aufgeräumt (höchstens 200 000 Einträge, die ältesten zuerst). Das
Protokoll ist Teil der [Sicherung](/docs/sicherung#ueberblick) – es enthält keine Geheimnisse und ist klein. Für die
Überwachung zählt `/metrics` die Versuche nach Art, Kanaltyp und Ergebnis (`cobe_news_delivery_attempts_total`) und die
Fehler der letzten 24 Stunden je Kanal (`cobe_news_channel_delivery_failures_24h`) – ohne Namen und Adressen (siehe
[API](/docs/api#metriken-liste)).
