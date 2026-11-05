---
title: News & Quellen
summary: Meldungen lesen, verstehen, wie die Schwere entsteht, welche Quellen eingebaut sind – und wie Admins eigene Feeds hinzufügen und ihre Gesundheit im Blick behalten.
audience: all
---

## News lesen {#news-lesen}

Die Seite *News* zeigt die Meldungen aller eingeschalteten Quellen als Kacheln, die neuesten zuerst. Weiter unten
lädt „Weitere laden“ ältere nach.

### Die Kachel {#kachel}

Jede Kachel zeigt:

- oben Logo und Name der Quelle, rechts den Haken zum Als-gelesen-Markieren (gelesen: der Pfeil zurück auf ungelesen)
  und das Menü **⋯** (gelesen/ungelesen, die CVEs der Meldung [stummschalten](/docs/benachrichtigungen#stummschalten)),
- den Titel und den Anfang der Zusammenfassung,
- falls bekannt, das betroffene Produkt („betrifft GitLab …“ bzw. „betrifft deine Systeme: …“),
- unten die **Schwere**, „Unser Produkt: …“ (wenn die Meldung ein gefolgtes Produkt betrifft, siehe
  [Betrifft unsere Produkte](#unsere-produkte)), die [Themen](#themen), die genannte CVE (oder „3 CVEs“) und das Alter
  der Meldung.

Kritische Meldungen haben einen roten Rand. Ungelesene haben einen Punkt vor dem fett gesetzten Titel; stummgeschaltete
(nur mit „Stummgeschaltete zeigen“ zu sehen) sind blass und tragen „Stumm“.

### Die Meldung öffnen {#schublade}

Ein Klick auf die Kachel öffnet die Meldung rechts in einer Schublade:

| Teil | Inhalt |
|---|---|
| Kopf | Quelle, Zeitpunkt, „auch bei …“ (weitere Quellen mit derselben Meldung), Titel |
| Einschätzung | die Schwere und „Einschätzung nach Regeln“ – die Gründe dafür, siehe [Schwere](#schwere) |
| Betrifft deine Systeme | nur wenn ihr dem Produkt in Vendor News folgt und eine eingetragene Version betroffen ist |
| Betroffene Versionen | Details aus dem Advisory, siehe [Details aus der Quelle](#details-aus-der-quelle) |
| Änderungen | nur wenn sich das Advisory dahinter nachträglich geändert hat – was sich geändert hat, siehe [Änderungen an Advisories](/docs/vendor-news#aenderungen) |
| Text | Zusammenfassung und Artikeltext, vom Server bereinigt (Struktur und Links, keine Bilder, keine Skripte) |
| Genannte CVEs | jede CVE zum Kopieren, mit Stern zum [Beobachten](/docs/benachrichtigungen#cves-beobachten) |

Das Öffnen markiert die Meldung als gelesen ([Gelesen und ungelesen](/docs/erste-schritte#gelesen)). Unten: „Ans
Team weiterleiten“ (nur in einem Team, siehe [Weiterleiten](/docs/benachrichtigungen#weiterleiten)), „Stummschalten“
(die CVEs der Meldung und die betroffenen Produkte, für 7 oder 30 Tage oder bis zu einem Datum), „Als ungelesen
markieren“, „Artikel öffnen“ (der Originalartikel in einem neuen Tab) und „Schließen“.

### Suchen und filtern {#suchen-filtern}

- **Suche** („Titel, Text, CVE …“): durchsucht Titel, Zusammenfassung und CVE-Nummern, z. B. `CVE-2026-1234`,
  `FortiOS` oder `Ransomware`. Groß-/Kleinschreibung und Akzente sind egal; höchstens 100 Zeichen.
- **Quelle**, **Schwere** und **Thema**: mehrere Werte gleichzeitig wählbar. Innerhalb eines Filters reicht einer der
  gewählten Werte, die Filter zusammen müssen alle passen – „Thema: Zero-Day, Lieferkette“ und „Schwere: Kritisch“ zeigt
  kritische Meldungen, die Zero-Day **oder** Lieferkette sind. Was die [Themen](#themen) bedeuten, steht im Filter unter
  jedem Thema, daneben die Zahl der Meldungen, die es bei den übrigen Filtern hätte.
- Die **Quellen** sind nach ihrer Art gruppiert (Behörden & CERTs, Schwachstellen-Kataloge, Hersteller-Hinweise,
  Research, Presse, eigene Quellen). „Alle: Behörden & CERTs“ wählt eine ganze Gruppe – etwa für die Warnungen der
  Behörden.
- **Schnellfilter** unter der Filterzeile: „Aktiv ausgenutzt“, „Zero-Day“ und „Ohne Patch“ mit einem Klick – derselbe
  Filter wie *Thema*, mit der Zahl der Meldungen. Daneben **„Betrifft unsere Produkte“**, sobald ihr in Vendor News
  einem Produkt folgt ([mehr](#unsere-produkte)) – er gilt zusätzlich zu allen anderen Filtern.
- Quelle, Schwere, Thema und „Betrifft unsere Produkte“ merkt sich zusätzlich der Browser für dein Konto (wenn du keine
  Standard-Ansicht hast).
- „Filter zurücksetzen“ hebt Quelle, Schwere, Thema und „Betrifft unsere Produkte“ auf.
- **Nur ungelesene**: blendet Gelesenes aus. **Stummgeschaltete zeigen**: zeigt auch die Meldungen, deren CVEs du alle
  stummgeschaltet hast (blass) – sonst fehlen sie.
- **Ansichten**: die Filter unter einem Namen speichern, als Standard setzen, als Link teilen
  ([Ansichten](/docs/erste-schritte#ansichten)).
- „Alle als gelesen“ wirkt genau auf die ungelesenen Meldungen, die gerade zu Suche und Filtern passen
  ([Gelesen und ungelesen](/docs/erste-schritte#gelesen)).

### Jede Meldung nur einmal {#doppelte}

Bringen mehrere Quellen dieselbe Meldung, siehst du sie einmal – mit „auch bei …“ im Kopf. Als dieselbe Meldung gilt:

- dieselbe Adresse (ohne Tracking-Zusätze wie `utm_…`),
- derselbe Titel innerhalb von 3 Tagen aus einer anderen Quelle,
- zwischen CISA KEV, ENISA EUVD und den BSI-Cyber-Sicherheitswarnungen: dieselbe CVE innerhalb von 30 Tagen, wenn die
  Meldung genau diese eine CVE betrifft. Es gilt die höhere Schwere.

Ein Presseartikel über dieselbe CVE bleibt eine eigene Meldung. Eine Meldung, die auch andere Quellen bringen, zählt
für jede davon – im Quellenfilter und in Benachrichtigungen. Aktualisiert eine Quelle ihre Meldung (etwa „[UPDATE] …“),
übernimmt Cobe News die neue Fassung; die Schwere steigt dabei höchstens, neue CVEs kommen dazu.

### Wenn nichts erscheint {#keine-news}

- „News sind ausgeschaltet“: Ein Admin muss die News erst einschalten ([News einrichten](/docs/integrationen#news)).
- „Nichts Neues“ im Reiter **Neu**: Alles ist gelesen – oder ein Filter blendet die Meldungen aus.
- Meldungen verschwinden nach der Aufbewahrungszeit (ab Werk 90 Tage), gelesene wie ungelesene.

## Schwere {#schwere}

Jede Meldung bekommt eine von fünf Stufen:

| Stufe | Bedeutet typischerweise |
|---|---|
| **Kritisch** | wird bereits ausgenutzt, Zero-Day, Notfall-Patch, [CVSS](term:cvss) ab 9 |
| **Hoch** | schwere Folgen möglich (Remote Code Execution, Ransomware, Datenleck, Backdoor, Umgehen der Anmeldung), CVSS ab 7, jeder Eintrag in CISA KEV |
| **Mittel** | eine Sicherheitslücke oder ein Patch, Phishing, Malware, CVSS ab 4 |
| **Niedrig** | ein Security-Thema ohne konkrete Lücke |
| **Info** | kein Hinweis auf eine Schwachstelle oder einen Angriff |

Die Gründe stehen in der geöffneten Meldung unter „Einschätzung nach Regeln“. Eine Einschätzung durch Regeln ersetzt
nicht dein eigenes Urteil – sie hilft beim Sortieren.

### Wie bewertet wird {#bewertung-regeln}

1. **CVSS-Wert im Text** – auch in deutscher Form („CVSS-Basiswert 9,8“). Eine reine Versionsangabe wie `CVSS:3.1/AV:N…`
   oder „CVSS 3.1“ gilt nicht als Wert.
2. **Einstufung des Herausgebers** – BSI „[hoch]“ im Titel, Palo Alto „(Severity: HIGH)“, Cisco „Security Impact
   Rating“. Sie gilt; nur ein höherer CVSS-Wert oder „aktiv ausgenutzt“ heben sie noch an.
3. **Stichwörter** in Titel und Zusammenfassung – „actively exploited“, „Zero-Day“, „Notfall-Patch“ → kritisch;
   „Ransomware“, „Remote Code Execution“, „Datenleck“ → hoch; „Sicherheitslücke“, „Patch“, „Phishing“ → mittel.
4. Steht ein Stichwort **nur im Artikeltext** (nicht in Titel oder Zusammenfassung), zählt es eine Stufe niedriger –
   ein langer Bericht erwähnt „Zero-Day“ oft nur am Rande.

Die höchste zutreffende Stufe gilt.

### Was nicht als Ausnutzung zählt {#verneinungen}

Hersteller schreiben oft unter ihre Hinweise, dass eine Lücke *nicht* ausgenutzt wird. Solche Verneinungen erkennt
Cobe News, zum Beispiel:

- „not known to be actively exploited“, „no evidence … exploited in the wild“,
- „bislang nicht aktiv ausgenutzt“, „keine aktive Ausnutzung“, „Kein Zero-Day“.

Ebenso wenig zählen die Zero Day Initiative (ein Programm), ein „Out-of-Band-Management-Interface“ (Hardware) oder
Malware, die „in the wild“ gesehen wurde – nur eine *Ausnutzung* in freier Wildbahn zählt.

Auch eine **Pflicht, Ausnutzungen zu melden**, ist keine Ausnutzung: „Hersteller müssen aktiv ausgenutzte
Schwachstellen binnen 24 Stunden melden“ (der Cyber Resilience Act) nennt eine Art von Lücken in einer Regel – es wird
nichts angegriffen. Steht im selben Satz eine Meldepflicht („müssen … melden“, „Meldepflicht“, „must report“,
„reporting obligation“) oder geht es schon im Titel um sie („Meldepflicht“, „Cyber Resilience Act“, „CRA“), zählt
„aktiv ausgenutzt“ dort nicht. „Microsoft meldet aktiv ausgenutzte Lücke“ bleibt eine Ausnutzung.

### Kataloge ausgenutzter Schwachstellen {#schwere-kataloge}

Für Einträge aus Katalogen gelten die Textregeln nicht – jeder Eintrag bringt seine Einstufung mit:

| Quelle | Schwere |
|---|---|
| [CISA KEV](term:kev) | **hoch**; **kritisch**, wenn CISA bekannte Ransomware-Nutzung meldet |
| [ENISA EUVD](term:euvd) | **hoch**; **kritisch** ab CVSS 9 |
| Microsoft Patchday | **hoch** |

## Themen {#themen}

Neben der Schwere bekommt jede Meldung ihre **Themen** – null, eines oder mehrere. Sie stehen als farbige Marke neben
der Schwere auf der Kachel (die ersten zwei, „+n“ für weitere; der Mauszeiger erklärt sie), in der geöffneten Meldung
unter „Themen“ mit dem Grund („CISA KEV listet CVE-…“, „im Titel: ‚actively exploited‘“) und im Filter *Thema*.

| Thema | Woran Cobe News es erkennt |
|---|---|
| **Zero-Day** | „Zero-Day“, „0-day“ in Titel oder Anrisstext (nicht die Zero Day Initiative, nicht „Kein Zero-Day“). Eine Zero-Day-Meldung ist auch *aktiv ausgenutzt*. |
| **Aktiv ausgenutzt** | ein Eintrag der Kataloge [CISA KEV](term:kev) oder [ENISA EUVD](term:euvd); eine CVE der Meldung steht im KEV (siehe unten); die [Details aus der Quelle](#details-aus-der-quelle) sagen „ausgenutzt“; Wörter wie „actively exploited“, „exploited in the wild“, „aktiv ausgenutzt“, „wird bereits ausgenutzt“ – nicht verneint, nicht als Meldepflicht ([Verneinungen](#verneinungen)) |
| **Exploit veröffentlicht** | ein öffentlicher Exploit oder Proof of Concept ist bekannt: die CISA stuft eine CVE der Meldung in [SSVC](term:ssvc) mit „Exploitation: poc“ ein (aus der CVE-Liste, siehe unten); eine eingeschaltete Exploit-Sammlung (Metasploit, Exploit-DB, nuclei – [Öffentlicher Exploit](/docs/vendor-news#oeffentlicher-exploit)) führt eine CVE der Meldung; Wörter wie „PoC exploit“, „proof-of-concept exploit released“, „Exploit-Code veröffentlicht“, „öffentlicher Exploit“ – nicht verneint („kein öffentlicher Exploit“, „ein Exploit ist nicht bekannt“). Noch kein Beleg für Angriffe – das ist *Aktiv ausgenutzt*. |
| **Ransomware** | „Ransomware“, „Erpressertrojaner“, bekannte Gruppen (LockBit, Akira, Qilin, Black Basta, Cl0p); bei KEV-Einträgen der Hinweis der CISA auf Ransomware-Kampagnen |
| **Ohne Patch** | „[UNGEPATCHT]“ im Titel einer BSI-Warnung; ein CSAF-Advisory mit „kein Fix verfügbar“ oder „kein Fix geplant“ und ohne Hersteller-Fix; wenige eindeutige Wendungen („no patch yet“, „noch kein Update“, „unpatched flaw“) |
| **Vorfall/Datenleck** | „data breach“, „Datenleck“, „Datenpanne“, „Kundendaten“, „Cyberangriff auf …“, gestohlene oder offengelegte Daten |
| **Lieferkette** | „supply chain“, „Lieferkette“, schädliche npm-/PyPI-Pakete oder Erweiterungen, Typosquatting, „dependency confusion“ |
| **Phishing/Social Engineering** | „Phishing“, „Vishing“, „Smishing“, „ClickFix“, „AitM“, „Social Engineering“, gefälschte Anmeldeseiten – nicht schon „Kampagne“ oder „Angreifergruppe“ |
| **OT/ICS** | die OT-Quellen Siemens ProductCERT, CERT@VDE und SecurityWeek ICS/OT; Begriffe wie SIMATIC, CODESYS, SPS/PLC, SCADA, ICS, OT-Sicherheit |

Eine **Behörden-Warnung** ist kein Thema, sondern eine Art von Quelle: Im Quellenfilter wählt „Alle: Behörden & CERTs“
alle Behörden auf einmal.

### Wie Themen erkannt werden {#themen-erkennung}

- **Nur Titel und Anrisstext** zählen, nie der ganze Artikel – ein langer Bericht erwähnt „Phishing“ oder „Zero-Day“
  oft nur am Rande. Deutsch und Englisch werden erkannt.
- **Kataloge** (CISA KEV, ENISA EUVD) bekommen ihre Themen aus den Daten, nicht aus dem Text: ihr Standardtext („Known
  ransomware campaign use: Unknown“) zählt nicht.
- **CISA KEV über die CVE:** Steht eine CVE einer Meldung im KEV-Katalog, ist die Meldung *aktiv ausgenutzt* – wenn
  ihr Titel oder Anrisstext diese CVE nennt oder sie höchstens drei CVEs nennt. Ein Patchday-Sammelartikel mit 80 CVEs
  wird nicht „aktiv ausgenutzt“, nur weil eine davon im KEV steht. Den Ransomware-Hinweis der CISA bekommt nur der
  KEV-Eintrag selbst, nicht jede Meldung zur selben CVE.
- **Exploit veröffentlicht über die CVE:** Cobe News liest die SSVC-Einstufung der CISA aus den gespeicherten Einträgen
  der CVE-Liste (cvelistV5 – Vendor News hält sie für die gefolgten Produkte und für die CVEs, die es für Meldungen und
  Befunde nachschlägt). „poc“ macht die Meldung zu *Exploit veröffentlicht* – nach derselben Sammelartikel-Regel wie
  beim KEV. „active“ (aktive Ausnutzung) ist kein PoC: Diese Meldung ist *Aktiv ausgenutzt*. Ändert die CISA ihre
  Einstufung, folgen die Meldungen zu dieser CVE.
- **Exploit veröffentlicht über die Exploit-Sammlungen:** Führt eine eingeschaltete Sammlung (Metasploit, Exploit-DB,
  nuclei) eine CVE der Meldung, ist sie ebenfalls *Exploit veröffentlicht* (gleiche Sammelartikel-Regel); im Drawer
  steht die Sammlung als Grund. Nimmt eine Sammlung eine CVE neu auf oder streicht sie, folgen die Meldungen zu dieser
  CVE sofort; beim ersten Laden einer Sammlung, bei sehr vielen Änderungen auf einmal und beim Ein- oder Ausschalten
  einer Sammlung rechnet Cobe News alle Meldungen im Hintergrund neu.
- **Anzeigen** („heise-Angebot“, „Anzeige“, „Webinar:“, „(g+)“) bekommen keine Themen aus ihren Wörtern.
- **Neu berechnet** wird, sobald sich etwas ändert: die Meldung wird aktualisiert, die Details aus der Quelle kommen
  an, eine CVE kommt neu in den KEV-Katalog oder eine KEV-Meldung zur selben CVE erscheint. Nach einem Update oder einer
  Änderung der Regeln berechnet Cobe News alle gespeicherten Meldungen im Hintergrund neu (in Blöcken von 500).
- Damit *Aktiv ausgenutzt* auch ohne gefolgte Produkte stimmt, holt Cobe News den KEV-Katalog einmal am Tag, solange
  die News eingeschaltet sind ([Besonderheiten](#quellen-besonderheiten)).

### Grenzen {#themen-grenzen}

- Themen sind **Regeln über Wörter und Daten**, kein Verständnis des Textes. Ein Titel wie „Was tun gegen Ransomware?“
  bekommt *Ransomware*; ein Vorfall, der seine Art nur im Artikeltext nennt, bekommt kein Thema.
- *Ohne Patch* erkennt nur ausdrücklich gesagte Fälle. Fehlt der Hinweis, heißt das nicht, dass es einen Patch gibt.
- *Aktiv ausgenutzt* über den KEV setzt voraus, dass die Meldung die CVE nennt; Meldungen ohne CVE erkennt nur ihr
  Wortlaut.
- *Exploit veröffentlicht* kennt nur, was die CISA in SSVC einstuft, was eine eingeschaltete Exploit-Sammlung führt
  und was Titel und Anrisstext sagen. Sind alle Sammlungen aus, zählen nur SSVC und der Wortlaut.
- Die Themen gelten auch für [Benachrichtigungsregeln](/docs/benachrichtigungen#regel-themen) und für
  [Desktop-Benachrichtigungen und Web Push](/docs/benachrichtigungen#desktop-einschalten).

## Betrifft unsere Produkte {#unsere-produkte}

Der Schnellfilter **„Betrifft unsere Produkte“** zeigt nur die Meldungen, die ein Produkt betreffen, dem ihr in
[Vendor News](/docs/vendor-news#ueberblick) folgt. Auf der Kachel steht dann **„Unser Produkt: PAN-OS“** (bei mehreren
„+n“, der Mauszeiger nennt alle). Die Zahl am Schalter sagt, wie viele Meldungen es bei den übrigen Filtern sind.

- **Woher Cobe News das weiß:** aus den [Details aus der Quelle](#details-aus-der-quelle) – dem CSAF-Produktbaum, den
  CPE-Angaben der NVD, den betroffenen Produkten der CVE-Liste –, beurteilt wie in Vendor News. Es ist dieselbe
  Entscheidung wie „Betrifft deine Systeme“ in der geöffneten Meldung. **Nie aus Wörtern:** Ein Titel, der „Exchange“
  nennt, macht eine Meldung nicht zu eurer.
- **Versionen zählen:** Habt ihr Versionen eingetragen und ist keine davon betroffen, zählt die Meldung nicht. Ohne
  eingetragene Version zählt jede Meldung zum Produkt.
- **Mein Team:** Steht Vendor News bei dir auf [„Mein Team“](/docs/vendor-news#mein-team), zeigt der Filter nur die
  Produkte deiner Teams („Betrifft unsere Produkte (Mein Team)“). Mit „Alle“ gelten alle gefolgten Produkte.
- **Wann es sich ändert:** sobald die Details einer Meldung ankommen, und wenn ihr einem Produkt folgt, es entfolgt oder
  seine Versionen ändert – Cobe News rechnet dann die gespeicherten Meldungen für dieses Produkt im Hintergrund neu
  (in Blöcken von 500, meist innerhalb einer Minute). Nach dem Update auf diese Version geschieht das einmal für alle.
- **Grenzen:** Meldungen ohne Details (ohne CVE, Presseartikel ohne Advisory) betreffen für den Filter kein Produkt –
  auch wenn der Text es nennt. Der Schalter erscheint erst, wenn ihr mindestens einem Produkt folgt.

## Eingebaute Quellen {#eingebaute-quellen}

Cobe News bringt 46 Quellen mit, in fünf Gruppen. Ab Werk sind 14 davon eingeschaltet; Admins schalten weitere ein
oder aus ([Integrationen → News](/docs/integrationen#news)). Die Sprache steht als DE, EN oder FR neben der Quelle.

| Gruppe | Ab Werk an | Wählbar |
|---|---|---|
| Behörden & CERTs | BSI Cyber-Sicherheitswarnungen, CERT-EU Security Advisories, CERT.at Warnungen | BSI CERT-Bund (WID), BSI Presse, NCSC UK, Canadian Centre for Cyber Security, CERT-FR Alertes (FR) |
| Schwachstellen-Kataloge | CISA KEV | ENISA EUVD, Microsoft Patchday (MSRC) |
| Hersteller-Hinweise | CERT@VDE (OT-Hersteller), Veeam Security | Fortinet PSIRT, Palo Alto Networks PSIRT, Cisco PSIRT, Ivanti Security Advisories, Siemens ProductCERT, Oracle Security Alerts |
| Research | Microsoft Threat Intelligence, Cisco Talos | Unit 42, Google Threat Intelligence (Mandiant), Kaspersky Securelist, ESET WeLiveSecurity, Check Point Research, Zero Day Initiative (ZDI), SANS Internet Storm Center, watchTowr Labs, Huntress |
| Presse | heise online, heise Security, The Hacker News, golem.de Security, BleepingComputer, SecurityWeek ICS/OT | SecurityWeek, Krebs on Security, Dark Reading, The Record, Borns IT- und Windows-Blog, Security-Insider, t3n Security, Risky Bulletin |

### Besonderheiten {#quellen-besonderheiten}

- **CISA KEV und ENISA EUVD** sind keine Feeds, sondern Kataloge aktiv ausgenutzter Schwachstellen. Jeder Eintrag wird
  eine Meldung („CVE · Hersteller Produkt: Name“), mit Link zur NVD bzw. zum EUVD-Eintrag. Bei KEV steht die Frist
  dabei, bis wann US-Behörden patchen müssen.
- **Den KEV-Katalog lädt Cobe News einmal für alles:** Derselbe Abruf bringt die KEV-Meldungen und den ganzen Katalog
  für Vendor News und die [Themen](#themen). Ist die Quelle CISA KEV aus oder gestört, holt Vendor News den Katalog
  selbst – einmal am Tag, auch ohne gefolgtes Produkt, solange die News eingeschaltet sind. Lehnt `www.cisa.gov` den
  Abruf ab (HTTP 403, Schutz vor Bots), lädt Cobe News dieselbe Datei vom offiziellen Spiegel der CISA auf GitHub
  (`raw.githubusercontent.com/cisagov/kev-data`). Bei 429/503 gilt die Pause der Quelle, kein Ausweichen.
- **Microsoft Patchday (MSRC)** bringt eine Meldung je Patchday-Release („Microsoft: October 2026 Security Updates“)
  mit Link zu den Release Notes – statt Hunderter Einzelmeldungen je CVE.
- **Hersteller-Hinweise** sind genau, betreffen aber nur die Produkte des Herstellers. Die Schwere übernimmt Cobe News
  vom Hersteller.
- **CISA Alerts und Rockwell Automation** sind seit 0.1.49 keine eingebauten Quellen mehr: beide lehnen automatische
  Abrufe aus den meisten Netzen ab (HTTP 403). Cobe News umgeht das nicht und zeigt bei einer solchen Quelle „Die Quelle
  lehnt automatische Abrufe ab“. CISAs KEV-Katalog bleibt.
- **BSI CERT-Bund (WID)** bringt viele Hinweise am Tag – daher ab Werk aus.

### Neue Quellen und der Rückstand {#rueckstand}

Schaltet ein Admin eine Quelle ein, bringt ihr erster Abruf oft viele ältere Meldungen auf einmal – beim ersten
KEV-Abruf rund 100 Einträge der letzten 90 Tage. Dieser **Rückstand** steht auf der Seite, löst aber **keine**
Benachrichtigung aus: Benachrichtigt wird nur über Meldungen, die beim Abruf höchstens einen Tag alt waren.

Meldungen, die älter als die Aufbewahrungszeit sind, übernimmt Cobe News gar nicht. Je Abruf liest es höchstens die
neuesten 200 Einträge einer Quelle.

## Details aus der Quelle {#details-aus-der-quelle}

Zu vielen Meldungen holt Cobe News das strukturierte Advisory dahinter. Die geöffnete Meldung zeigt es oben als
**„Betroffene Versionen“**:

- je Produkt die betroffenen Versionsbereiche (z. B. `<19.5.1`) und die Fix-Versionen („Fix: …“),
- den CVSS-Wert, die CVEs, „Remote angreifbar“ und „Workaround/Mitigation vorhanden“,
- „Stand: Update vom …“ und die Herkunft („Details: …“).

Die Kachel zeigt davon CVSS und das betroffene Produkt.

| Quelle der Meldung | Woher die Details |
|---|---|
| BSI CERT-Bund (WID), Siemens ProductCERT, Cisco PSIRT, Fortinet PSIRT | das [CSAF](term:csaf)-Dokument des Herausgebers |
| Palo Alto Networks PSIRT | das Advisory als JSON des Herstellers |
| Veeam Security | der Text der Meldung selbst (der KB-Artikel) |
| CISA KEV, ENISA EUVD | die Meldung selbst und die [NVD](term:nvd) |
| andere Meldungen mit CVE | die NVD (für die ersten drei CVEs), markiert mit „aus NVD“ |

Gut zu wissen:

- Meldungen **ohne CVE** aus anderen Quellen haben keine Details.
- Die NVD hängt bei neuen CVEs oft einige Tage hinterher – die Details erscheinen dann später. Bis dahin ergänzt
  Cobe News die Angaben aus der CVE-Liste (cvelistV5), wenn ein Admin diese Quelle nicht abgeschaltet hat – markiert
  mit „ergänzt aus der CVE-Liste (cvelistV5)“.
- Zu jeder CVE der Meldung steht ihr [EPSS](term:epss)-Wert („Ausnutzung in 30 Tagen“), dazu die Einstufung
  [SSVC](term:ssvc) der CISA, wo sie mehr sagt als „nichts bekannt“ – siehe
  [EPSS und SSVC](/docs/vendor-news#epss-ssvc).
- Cisco nennt in seinen Advisories keine Fix-Versionen (nur über den eigenen Software Checker).
- Meldungen jünger als 30 Tage prüft Cobe News täglich neu; eine Meldung, deren Titel sich ändert („[UPDATE] …“), sofort.
- **„Betrifft deine Systeme“**: Folgt ihr dem Produkt in Vendor News, gleicht Cobe News die Bereiche mit euren
  eingetragenen Versionen ab. Advisories von BSI, Siemens und Cisco werden dabei auch zu Befunden in
  [Vendor News](/docs/vendor-news#bewertung).

Admins schalten die Details unter *Einstellungen → Integrationen → News* mit „Details aus der Quelle“ ab
([Einstellungen](/docs/integrationen#news)).

## Eigene Quellen {#eigene-quellen .admin}

Neben den eingebauten Quellen kann ein Admin eigene Feeds eintragen – etwa den Blog eines Herstellers oder das CERT
einer Branche.

### Was funktioniert {#eigene-formate}

| Format | Hinweis |
|---|---|
| [RSS](term:rss) 2.0, RSS 1.0 (RDF), Atom | der Normalfall |
| JSON im Format der CISA KEV (`{"vulnerabilities": […]}`) | jeder Eintrag eine Meldung |
| JSON im Format der ENISA EUVD (Liste oder `{"items": […]}`) | jeder Eintrag eine Meldung |
| JSON im Format des Microsoft-CVRF-Index (`{"value": […]}`) | je Release eine Meldung |

Anderes JSON (z. B. „JSON Feed“) und HTML-Seiten gehen nicht. Erkannt wird am Inhalt, nicht am Content-Type.

### Eine Quelle hinzufügen {#eigene-hinzufuegen}

1. *Einstellungen → Integrationen*, bei *News* auf „Einrichten“ klicken.
2. Ganz unten bei **Eigene Quelle** einen **Namen** (2–100 Zeichen) und die **Feed-Adresse** eintragen.
3. „Prüfen“ klicken: Cobe News lädt den Feed einmal und meldet, wie viele Einträge es gelesen hat und wie der neueste
   heißt – oder warum es nicht klappt.
4. „Hinzufügen“ klicken. Die Quelle steht dann in der Gruppe **Eigene Quellen**, ist eingeschaltet und wird mit der
   nächsten Runde abgerufen.

Eine eigene Quelle entfernst du mit dem Papierkorb neben ihrem Schalter. Ihre Meldungen gehen dabei mit – außer denen,
die auch eine andere Quelle bringt. Regeln und Desktop-Einstellungen, die nur diese Quelle gewählt hatten, schicken
danach keine News mehr. Eingebaute Quellen lassen sich nur ein- und ausschalten, nicht entfernen.

### Regeln und Grenzen {#eigene-grenzen}

- **Nur `https://`.** Auch Weiterleitungen (höchstens 3) müssen auf https bleiben.
- **Keine internen Ziele:** nie Loopback, Link-Local oder Cloud-Metadaten. Private Netze (`10.…`, `172.16–31.…`,
  `192.168.…`) nur, wenn in der [.env](term:envfile) `ALLOW_PRIVATE_FEEDS=1` steht. Der Name wird einmal aufgelöst,
  geprüft und genau diese Adresse verbunden.
- **Größe und Zeit:** höchstens 5 MB und 30 Sekunden je Abruf.
- **XML mit DTD oder Entities** wird abgelehnt.
- **Höchstens eine Anfrage pro Website und Minute;** unveränderte Feeds (`ETag`/`Last-Modified`) kosten nur eine kurze
  Nachfrage. Nach HTTP 429/503 wartet Cobe News so lange wie verlangt (mindestens eine Stunde), sonst mit wachsender
  Pause bis 24 Stunden.
- Datumsangaben außerhalb 1990–2100 gelten als „kein Datum“.

> [!NOTE]
> Mit `HTTPS_PROXY` löst der Proxy die Namen auf. Cobe News prüft dann nur Adressen, die als IP in der URL stehen –
> interne Ziele über Namen muss der Proxy selbst sperren
> ([Ausgehende Daten](/docs/integrationen#ausgehende-daten)).

### Abrufintervall, Aufbewahrung, Hauptschalter {#eigene-einstellungen}

Diese Einstellungen gelten für alle Quellen, eigene wie eingebaute – siehe [Integrationen → News](/docs/integrationen#news):
Hauptschalter „News abrufen“ (ab Werk aus), Abrufintervall je Quelle (15–1440 Minuten) und Aufbewahrung (7–365 Tage).

### Fehlermeldungen beim Prüfen {#eigene-fehler}

| Meldung | Ursache |
|---|---|
| Kein lesbarer Feed (RSS, Atom oder JSON-Katalog) | HTML-Seite, unbekanntes JSON oder kaputtes XML |
| Feed ohne verwertbare Einträge | Einträge ohne Titel oder Link |
| Feed zu groß (mehr als 5 MB) | Feed liefert seine ganze Historie |
| Keine Antwort in 30 Sekunden | Server zu langsam oder Firewall verwirft |
| Keine Verbindung (Netz, Proxy oder DNS?) | Name nicht auflösbar, Proxy fehlt, Ziel gesperrt |
| Die Quelle lehnt automatische Abrufe ab (403) | Bot-Schutz der Website – Cobe News umgeht ihn nicht |
| Die Seite bittet um Pause (zu viele Anfragen) | HTTP 429 – später erneut |

## Quellen-Gesundheit {#quellen-gesundheit .admin}

Cobe News beobachtet, wie gut jede Quelle abgerufen wird – damit eine ausgefallene Quelle auffällt, bevor Meldungen
fehlen. Zu sehen unter *Einstellungen → Integrationen → Gesundheit*
([Die Gesundheits-Ansicht](/docs/integrationen#gesundheit)). Ist eine Quelle tot, zeigt *Integrationen* in der
Navigation die Anzahl.

Jede News-Quelle, jede Quellen-Familie von Vendor News und jede der [weiteren Quellen](/docs/integrationen#weitere-quellen)
(CSAF-Anbieter, cvelistV5, EPSS, OSV) bekommt einen Zustand. Es gilt der erste, der passt:

| Zustand | Wann |
|---|---|
| **aus** | die Quelle oder die News sind ausgeschaltet; bei Vendor News: ausgeschaltet, oder kein gefolgtes Produkt braucht diese Abfrage |
| **noch nicht abgerufen** | eingeschaltet, aber noch nie gefragt – passiert mit der nächsten Runde |
| **tot** (rot) | HTTP 401/403/410 zweimal in Folge; HTTP 404 dreimal in Folge; seit **14 Tagen** kein erfolgreicher Abruf; nur News: seit **60 Tagen** keine neue Meldung, obwohl der Abruf klappt |
| **gestört** (bernstein) | 3 Fehlschläge in Folge; ein aktueller Fehler, der nicht nur vorübergehend ist (z. B. falsche Adresse, Zertifikat, unlesbare Antwort) – die Quelle pausiert bis zum nächsten Versuch; eine unlesbare Antwort in den letzten 24 Stunden |
| **langsam** (blau) | im Mittel der letzten 7 Tage über 5 Sekunden je Anfrage (große Downloads über 1 MB je Anfrage zählen hier nicht – etwa der erste vollständige NVD-Abruf eines neu verfolgten Produkts); häufige Zeitüberschreitungen (mindestens 3 und mindestens ein Viertel der Abrufe); oder ein vorübergehender Fehler, der gleich wiederholt wird |
| **gesund** (grün) | alles andere |

Vorübergehend sind Zeitüberschreitungen, Verbindungsfehler, HTTP 5xx und „zu viele Anfragen“. Sie pausieren eine
Quelle höchstens eine Stunde (oder ein Abrufintervall, wenn es länger ist).

Was zu tun ist:

- **langsam** – nichts; die Meldungen kommen trotzdem.
- **gestört** – bald nachsehen: Adresse noch richtig? Zertifikat? Proxy?
- **tot** – die Quelle prüfen oder ausschalten. Eine Quelle, die nach 60 Tagen nichts Neues bringt, ist oft
  umgezogen.

Einmal je Zustandswechsel kann Cobe News eine Benachrichtigung schicken – Regel-Art „Quelle gestört oder tot“
([Regeln](/docs/benachrichtigungen#regeln)).
