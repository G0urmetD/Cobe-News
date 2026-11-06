---
title: Integrationen & Quellen-Gesundheit
summary: News und Vendor News einrichten, Web Push steuern, verstehen, welche Daten den Server verlassen, und die Gesundheit der Quellen überwachen.
audience: admin
---

## Überblick {#ueberblick}

*Einstellungen → Integrationen* ([öffnen](/settings/integrations)) ist der Ort für alles, was Cobe News von außen
holt. Die Seite hat zwei Unter-Reiter:

| Reiter | Inhalt |
|---|---|
| **Quellen** | zwei Kacheln: **News** und **Vendor News** – je Zustand, Kennzahlen und „Einrichten“ |
| **Gesundheit** | wie gut jede Quelle abgerufen wird, siehe [Gesundheit](#gesundheit) |

Die Kachel zeigt auf einen Blick, ob die Integration eingeschaltet ist, wie viele Quellen laufen, wie viele ein
Problem haben („N mit Problem“) und – bei Vendor News – ob ein NVD-Schlüssel gesetzt ist und ob Katalogeinträge Pflege
brauchen. „Einrichten“ öffnet rechts die Schublade mit allen Einstellungen. Gespeichert wird mit „Speichern“ unten in
der Schublade.

- Der Knopf „Quellen“ oben auf der News-Seite führt direkt hierher.
- Ist eine Quelle tot, zeigt *Integrationen* in der Navigation die Anzahl in Rot.
- Speichern zwei Admins gleichzeitig, gewinnt nicht stillschweigend der Letzte: Wer auf einem veralteten Stand
  speichert, sieht „Inzwischen von jemand anderem geändert“ und lädt den aktuellen Stand.

## News {#news}

*Integrationen → News → „Einrichten“*

| Einstellung | Ab Werk | Bereich | Bedeutung |
|---|---|---|---|
| **News abrufen** | aus | an/aus | Hauptschalter. Aus: keine einzige Anfrage nach außen, die News-Seite zeigt „News sind ausgeschaltet“. |
| **Abrufintervall je Quelle** | 30 Minuten | 15–1440 Minuten | Wie oft jede Quelle gefragt wird. Unveränderte Feeds kosten nur eine kurze Nachfrage. |
| **Aufbewahrung** | 90 Tage | 7–365 Tage | Ältere Meldungen werden gelöscht, gelesene wie ungelesene. Eine Meldung ohne eigenes Datum bleibt, solange ihr Feed sie noch listet (oder ein anderer Feed dieselbe Adresse). Eine kürzere Frist nennt vor dem Speichern, wie viele Meldungen gehen – endgültig, sie werden auch später nicht wieder abgerufen. |
| **Details aus der Quelle** | an | an/aus | Holt zu jeder Meldung das Advisory dahinter ([Details aus der Quelle](/docs/news-quellen#details-aus-der-quelle)). |

Die Felder lassen sich erst bearbeiten, wenn der Hauptschalter an ist.

### Erste Einrichtung {#news-einrichten}

1. *Einstellungen → Integrationen* öffnen, bei **News** „Einrichten“ klicken.
2. „News abrufen“ einschalten.
3. Abrufintervall und Aufbewahrung prüfen, „Speichern“.
4. Unter **Quellen** die gewünschten Quellen einschalten. Jede Gruppe klappt auf; „3 von 9 an“ zeigt, wie viele laufen.
5. „Jetzt abrufen“ klicken – die Quellen werden nacheinander gefragt, die ersten Meldungen erscheinen nach wenigen
   Minuten.

### Quellen {#news-quellen}

- Die Quellen stehen in Gruppen (Behörden & CERTs, Schwachstellen-Kataloge, Hersteller-Hinweise, Research, Presse,
  Eigene Quellen) mit Sprache (DE/EN/FR) und Feed-Adresse. Welche es gibt:
  [Eingebaute Quellen](/docs/news-quellen#eingebaute-quellen).
- Ein Schalter je Quelle wirkt sofort, ohne „Speichern“. Eine wieder eingeschaltete Quelle wird mit der nächsten Runde
  gefragt, ohne alte Pause oder alten Fehler.
- Unter jeder eingeschalteten Quelle steht ihr Zustand: Zahl der Meldungen und letzter Erfolg, „Noch nicht abgerufen“
  oder der Fehler mit „nächster Versuch“.
- Was ein Admin schaltet, bleibt so – auch wenn ein Update den Standard einer eingebauten Quelle ändert. Neue
  eingebaute Quellen kommen nach einem Update mit ihrem Standard dazu.
- Eigene Feeds: ganz unten „Eigene Quelle“, siehe [Eigene Quellen](/docs/news-quellen#eigene-quellen).

### Jetzt abrufen {#news-jetzt-abrufen}

„Jetzt abrufen“ startet sofort eine Runde, statt auf das Intervall zu warten – höchstens einmal pro Minute. Auch dann
gilt: je Website höchstens eine Anfrage pro Minute, und Quellen, die nach einer Ablehnung (429/503) pausieren, bleiben
in der Pause.

> [!TIP]
> Ein kurzes Intervall bringt Meldungen kaum schneller: Die meisten Quellen veröffentlichen nur wenige Male am Tag.
> 30 Minuten sind ein guter Wert.

## Vendor News {#vendor-news}

*Integrationen → Vendor News → „Einrichten“*. Die Schublade hat drei Reiter: **Einstellungen**, **Weitere Quellen**
([Weitere Quellen](#weitere-quellen)) und **Katalog-Pflege**.

| Einstellung | Ab Werk | Bereich | Bedeutung |
|---|---|---|---|
| **Vendor News** | an | an/aus | Hauptschalter |
| **Hinweise & NVD alle** | 6 Stunden | 1–48 Stunden | Hersteller-Hinweise (Palo Alto, Fortinet, Veeam, CSAF-Anbieter) und CVEs der [NVD](term:nvd); danach nur, was sich geändert hat |
| **Versionen & KEV alle** | 24 Stunden | 6–168 Stunden | [Release-Linien](term:releaseline) von endoflife.date und der KEV-Katalog der CISA (den KEV auch ohne gefolgtes Produkt, solange die News an sind – für die [Themen](/docs/news-quellen#themen); bringt ihn schon die News-Quelle CISA KEV, wird er nicht ein zweites Mal geladen) |
| **NVD-API-Schlüssel (optional)** | leer | – | schnellere NVD-Abfragen, siehe unten |

> [!NOTE]
> Vendor News ist ab Werk **an** – trotzdem geht keine einzige Anfrage nach außen, solange niemand einem Produkt
> folgt. Danach nur für die gefolgten Produkte.

### NVD-API-Schlüssel {#nvd-schluessel}

Ohne Schlüssel erlaubt die NVD 5 Anfragen pro 30 Sekunden; Cobe News hält das ein. Der erste Abruf vieler Produkte
dauert dann einige Minuten, und die [Details aus der Quelle](/docs/news-quellen#details-aus-der-quelle) fragen je
Runde nur 8 statt 40 CVEs bei der NVD nach.

1. Den kostenlosen Schlüssel unter
   [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) anfordern.
2. In das Feld **NVD-API-Schlüssel** einfügen, „Speichern“.
3. Die Kachel zeigt danach „NVD-Schlüssel gesetzt“.

Der Schlüssel wird verschlüsselt gespeichert und nie wieder angezeigt. Leer lassen behält ihn; „Entfernen“ (danach
„Speichern“) löscht ihn.

### Katalog und Abfragen {#vendor-katalog}

- **Katalog aktualisieren** baut den Produktkatalog im Hintergrund neu aus endoflife.date auf. Daneben steht, wie viele
  Produkte er hat und von wann er ist. Höchstens alle 10 Minuten; normalerweise nicht nötig – der tägliche Abruf hält ihn aktuell.
- **Abfragen** listet jede laufende Abfrage (je gefolgtem Produkt, NVD je CPE …) mit letztem Erfolg, Fehler und
  nächstem Termin. „Noch keine“ heißt: noch keinem Produkt gefolgt.
- **Jetzt abrufen** startet eine Runde sofort. Je nach Rate-Limit der NVD dauert sie einige Minuten.

### Katalog-Pflege {#vendor-katalog-pflege}

Der Reiter **Katalog-Pflege** zeigt Katalogeinträge, die vermutlich veraltet oder falsch sind (CPE gibt es nicht
mehr, lange keine CVE …). „Jetzt prüfen“ prüft die gefolgten Produkte sofort. Einzelheiten:
[Katalog-Pflege](/docs/vendor-news#katalog-pflege). Wie man Produkten folgt und Versionen einträgt:
[Produkten folgen](/docs/vendor-news#produkten-folgen).

## Weitere Quellen {#weitere-quellen}

Vier strukturierte Quellen ergänzen die Hinweise der Hersteller und die [NVD](term:nvd): die
[CSAF](term:csaf)-Anbieter der Hersteller, die CVE-Liste [cvelistV5](term:cvelist), [EPSS](term:epss) von FIRST und
[OSV](term:osv). Dazu kommen drei Sammlungen öffentlicher Exploits ([Exploit-Hinweise](#exploit-hinweise)). Sie stehen in *Integrationen → Vendor News → „Einrichten“*, Unter-Reiter **Weitere Quellen**
([direkt öffnen](/settings/integrations?vendor=sources)).

- Jede Quelle hat ihren eigenen Schalter und ist **ab Werk an** – außer Exploit-DB. Gespeichert wird mit „Speichern“
  unten in der Schublade.
- Jede fragt nur, was die gefolgten Produkte brauchen (EPSS auch für die CVEs der Meldungen). Solange niemand einem
  Produkt folgt, fragt keine etwas. Ist Vendor News aus, fragt keine.
- Unter jedem Schalter steht, was nach außen geht, und der Zustand ihrer Abfragen. „Verlauf unter Gesundheit“ führt
  zur [Gesundheit](#gesundheit).

| Quelle | Was sie bringt | Wann |
|---|---|---|
| **CSAF-Anbieter** | die Sicherheitshinweise von Siemens, Cisco, Schneider Electric und Open-Xchange direkt vom Hersteller: betroffene Produkte mit Versionsbereichen, Fix-Versionen, CVEs, CVSS | mit der Vendor-News-Runde („Hinweise & NVD alle“, ab Werk alle 6 Stunden), nur mit gefolgtem Produkt des Herstellers |
| **cvelistV5** | CVE-Einträge, wie der Hersteller (CNA) sie meldet, und die Einstufung der CISA (CVSS, [SSVC](term:ssvc), KEV) – vor allem für CVEs, die die NVD noch nicht analysiert hat | dreimal am Tag die Änderungen des Tages, einmal am Tag der Tagesabschluss; einzelne Einträge bei Bedarf |
| **EPSS** | Wahrscheinlichkeit, dass eine CVE in den nächsten 30 Tagen ausgenutzt wird, mit Perzentil | je CVE höchstens einmal am Tag |
| **OSV** | betroffene und behobene Versionen von Open-Source-Paketen (Tomcat, Jenkins, Django …) | je CVE täglich, solange sie jünger als 30 Tage ist, sonst wöchentlich |
| **Exploit-Hinweise** (Metasploit, Exploit-DB, nuclei) | ob öffentlicher Exploit-Code oder eine fertige Prüfung für eine CVE existiert | je Sammlung höchstens einmal am Tag, bedingt (unverändert: keine Daten) |

### CSAF-Anbieter {#csaf-anbieter}

Welche Anbieter Cobe News kennt und für welche Hersteller sie sprechen, steht im Katalog (`csaf.yaml`):

| Anbieter | Domain | spricht für Produkte des Herstellers |
|---|---|---|
| Siemens ProductCERT | `cert-portal.siemens.com` | Siemens |
| Cisco PSIRT | `www.cisco.com` | Cisco, Cisco (Duo), Splunk (Cisco) |
| Schneider Electric CPCERT | `www.se.com` | Schneider Electric |
| Open-Xchange GmbH (ab 0.1.45) | `www.open-xchange.com` | Open-Xchange (OX App Suite) |

Ein Anbieter wird nur gefragt, wenn ihr einem Produkt seines Herstellers folgt (Feld „Hersteller“ im Katalog). Die
Liste unter *Weitere Quellen* zeigt je Anbieter „wird abgerufen“ oder „kein gefolgtes Produkt“. Einen weiteren
Anbieter einzutragen ist Katalogpflege: ein Eintrag in `backend/app/catalog/csaf.yaml` (beschrieben in `docs/BETRIEB.md` unter
„Katalog pflegen“ → „CSAF-Anbieter“), wirksam mit dem nächsten Update:

```yaml
- key: example                     # kurz, eindeutig (unter Gesundheit: csaf:example)
  name: Example Corp PSIRT
  domain: psirt.example.com
  vendors: [Example Corp]          # Hersteller wie im Feld vendor der Produkte
```

**So findet und liest Cobe News die Hinweise:**

1. **Anbieter finden:** zuerst in der Anbieter-Liste des BSI (CSAF-Aggregator auf `wid.cert-bund.de`, einmal am Tag
   gelesen) ein Eintrag auf der Domain des Anbieters, sonst
   `https://<domain>/.well-known/csaf/provider-metadata.json`.
2. **Liste der Dokumente:** ein ROLIE-Feed oder die Datei `changes.csv` eines Verzeichnisses – bedingt abgerufen,
   unverändert kostet sie nur eine kurze Nachfrage.
3. **Öffentliche Dokumente – TLP:GREEN nur auf Wunsch:** gelesen werden Feeds und Dokumente mit
   [TLP](term:tlp):WHITE oder TLP:CLEAR. Ein Dokument ohne Kennzeichnung nur aus einer Verteilung, die nicht anders
   gekennzeichnet ist. TLP:GREEN nur, wenn ein Admin es für diesen Anbieter zulässt ([unten](#tlp-green)); AMBER,
   AMBER+STRICT und RED werden nie gelesen.
4. **Prüfsumme:** Bietet der Anbieter eine Prüfsumme an (`.sha512` oder `.sha256`), muss sie stimmen – sonst wird das
   Dokument übergangen (unter *Gesundheit* als unlesbar gezählt). Nennt der Feed eine Prüfsumme, die sich gerade nicht
   abrufen lässt, wird das Dokument in dieser Runde nicht übernommen und später erneut versucht. Hat ein Anbieter gar
   keine Prüfsummen-Dateien, merkt sich Cobe News das und fragt erst nach einer Weile wieder danach.
5. **Stand je Anbieter:** Cobe News merkt sich Zeit und Adresse des zuletzt gelesenen Dokuments und liest danach nur,
   was später geändert wurde – das älteste zuerst, höchstens **25 Dokumente je Runde**. Ein Rest folgt 20 Minuten
   später.
6. **Vorübergehende Fehler:** Scheitert ein Dokument vorübergehend (Serverfehler 5xx, Zeitüberschreitung), wird es in
   den nächsten Runden erneut versucht – nach 5 Versuchen oder 24 Stunden gibt Cobe News es auf. Die übrigen Dokumente
   laufen weiter.
7. **Zeitangaben in der Zukunft** (mehr als einen Tag) werden nicht beachtet – ein Dokument mit falschem Datum kann den
   Stand nicht vorschieben.

**Keine Prüfung der OpenPGP-Signatur.** Die Anbieter signieren ihre Dokumente zusätzlich (`.asc`). Cobe News prüft
diese Signatur nicht: Der Schlüssel dafür liegt auf demselben Server wie das Dokument. Wer dort ein Dokument ändern
könnte, könnte auch den Schlüssel tauschen – mehr Schutz als TLS und Prüfsumme brächte die Signatur nur mit einem
Schlüssel, der unabhängig davon hinterlegt ist.

### TLP:GREEN je Anbieter zulassen {#tlp-green}

**TLP:GREEN** heißt: Weitergabe nur innerhalb eurer Organisation bzw. Community, nicht öffentlich. Manche Anbieter
kennzeichnen so auch Hinweise, die sie frei abrufbar ins Netz stellen – bekannt ist **Open-Xchange** (OX App Suite
und Dovecot, alle Dokumente TLP:GREEN). Ab Werk liest Cobe News solche Dokumente nicht.

Unter *Einstellungen → Integrationen → Vendor News → Weitere Quellen* hat jeder CSAF-Anbieter den Schalter
**TLP:GREEN zulassen** (aus ab Werk). Eingeschaltet:

- Die TLP:GREEN-Dokumente dieses Anbieters werden gelesen; seine Liste wird dafür einmal von vorn gelesen. Was älter als
  7 Tage ist, erscheint wie beim ersten Abruf auf der Seite, wird aber nicht gemeldet.
- Jeder Befund daraus trägt das Zeichen **TLP:GREEN** (mit Erklärung beim Darüberfahren) – auf der Produktkarte, in
  der Schublade, in E-Mails und Chat-Nachrichten (Feld „TLP: TLP:GREEN – nur intern weitergeben“, `[TLP:GREEN]` vor dem
  Titel), beim Weiterleiten an ein Team, im Wochenbericht, im Webhook (`"tlp": "GREEN"`) und in der API
  (`/api/v1`, Feld `tlp`). Wohin eure Kanäle gehen, entscheidet ihr – ein Kanal nach außen sollte solche Meldungen
  nicht bekommen.
- AMBER, AMBER+STRICT und RED bleiben immer abgelehnt.

Wieder ausgeschaltet, entfernt Cobe News die gespeicherten TLP:GREEN-Hinweise dieses Anbieters sofort (und jede Runde
noch einmal) – ohne Meldung „zurückgezogen“; noch nicht verschickte Meldungen daraus gehen nicht mehr hinaus. Entfernt
statt nur ausgeblendet, weil ihr damit entschieden habt, solche Inhalte nicht zu halten: sie stünden sonst weiter in
der Datenbank, in Sicherungen und Exporten. Jede Änderung des Schalters steht im Audit-Log
(„Einstellungen geändert“, Feld `csaf_green`).

Hinweise zu Meldungen aus News (BSI, Siemens, Cisco) werden nur aus öffentlichen Dokumenten (TLP:CLEAR/WHITE)
angezeigt – ein TLP:GREEN-Dokument dort wird nicht verwendet.

### Regeln für CSAF-Dokumente {#csaf-regeln}

Damit ein Anbieter nur für seine eigenen Produkte sprechen kann, gelten diese Regeln:

- **Nur die eigenen Hersteller:** Ein Dokument zählt nur für Produkte, deren Hersteller im Katalog einer der
  Hersteller des Anbieters ist (`vendors` in `csaf.yaml`). Zusätzlich muss der Hersteller im Dokument selbst (der
  Zweig „vendor“ des Produktbaums) zum Hersteller des Produkts passen. Ein Siemens-Dokument kann also nie ein
  Cisco-Produkt als betroffen melden.
- **Herausgeber auf der eigenen Domain:** Der Herausgeber (Namespace des Publishers) im Dokument muss auf der Domain
  des Anbieters liegen.
- **Adressen bleiben beim Anbieter:** Weiterleitungen werden nur innerhalb der Domain des Anbieters verfolgt. Zeigt
  der Link auf den Hinweis woandershin, verlinkt Cobe News stattdessen die Adresse des Dokuments selbst.
- **Nichts überschreiben:** Ein Dokument ersetzt nie den Hinweis eines anderen Herausgebers – weder einen Hinweis des
  BSI (WID-SEC) noch einen gleichnamigen Hinweis eines anderen Anbieters.
- **Ein Hinweis, ein Befund:** Hinweise von Siemens und Cisco, die zusätzlich über eine Meldung in den News kommen
  ([Details aus der Quelle](/docs/news-quellen#details-aus-der-quelle)), teilen sich einen Datensatz mit dem Dokument
  des Anbieters – ein Hinweis, ein Befund, eine Benachrichtigung.

### Erstabruf {#erstabruf}

Der erste Abruf eines Anbieters reicht **90 Tage** zurück. Damit dabei keine Flut von Benachrichtigungen entsteht:

- Dokumente, die beim Erstabruf **älter als 7 Tage** sind, tragen in der Schublade des Produkts die Markierung
  **„Erstabruf“**. Sie stehen auf der Seite und zählen wie jeder andere Befund – sie werden aber **nie verschickt**.
- Jüngere Dokumente aus dem Erstabruf werden ganz normal gemeldet.
- Alles, was nach dem Erstabruf kommt, wird ganz normal gemeldet.

Wie die Markierung für Leser aussieht: [Erstabruf](/docs/vendor-news#erstabruf).

### cvelistV5 {#cvelist}

cvelistV5 ist die offizielle CVE-Liste auf GitHub (Projekt CVEProject/cvelistV5): jeder CVE-Eintrag so, wie der
Hersteller oder eine andere vergebende Stelle (CNA) ihn veröffentlicht, ergänzt um die Einstufung der CISA (ADP).
Cobe News lädt **nie die ganze Liste** (rund 650 MB), sondern nur Änderungen:

- **Wann:** Cobe News schaut nur dann nach dem neuesten Release bei GitHub (eine kleine JSON-Antwort von
  `api.github.com`), wenn etwas fällig ist. Die ZIP-Datei „alles, was seit Mitternacht (UTC) geändert wurde“ lädt es
  **dreimal am Tag**, sobald das Release von 05:00, 11:00 bzw. 17:00 UTC erschienen ist – GitHub veröffentlicht jedes
  stündliche Release etwa 20 bis 40 Minuten nach der vollen Stunde.
- **Tagesabschluss:** Einmal nach dem Tageswechsel kommt die ZIP-Datei mit allen Änderungen des Vortags (erscheint
  gegen 00:30–00:40 UTC). Fehlt sie noch, wartet Cobe News bis 06:00 UTC darauf – so gehen die letzten Stunden des
  Tages nicht verloren.
- **Datenmenge:** etwa 9 bis 11 MB am Tag (Beispiel 29.10.2026: 0,4 + 0,7 + 4,3 + 5,3 MB) statt rund 50 MB bei einem
  Download pro Stunde. Eine Änderung ist nach höchstens etwa 7,5 Stunden in Cobe News.
- **Rechner im Ruhezustand, App gestoppt:** Ein verpasster Termin wird mit dem nächsten Termin oder dem
  Tagesabschluss nachgeholt, verpasste Tage (höchstens 3) über ihre Tagesabschlüsse.
- **Defekte Datei:** Eine ZIP-Datei, die sich nicht lesen lässt oder zu groß ist, wird übersprungen und erscheint
  als Fehler unter *Gesundheit*; die übrigen Dateien des Tages werden trotzdem gelesen.
- **Was bleibt:** nur Einträge, die ein gefolgtes Produkt betreffen (der Hersteller nennt es, oder die CISA nennt eine
  seiner [CPE](term:cpe)s), und Einträge, die schon gespeichert sind (eine Änderung). Ein zurückgezogener Eintrag
  („rejected“) wird entfernt.
- **Einzelne Einträge bei Bedarf:** Für CVEs von Befunden, die die NVD noch nicht analysiert hat, und von Meldungen,
  die die NVD nicht beschreiben kann, holt Cobe News den einzelnen Eintrag von `raw.githubusercontent.com` – je CVE
  höchstens einmal pro Woche, höchstens 20 je Runde. Scheitert die Anfrage, wird sie in der nächsten Runde wiederholt;
  als „gefragt“ gilt eine CVE erst nach einer Antwort, nach „nicht gefunden“ (404) oder einem unlesbaren Eintrag.
- **Was genutzt wird:** die betroffenen Versionen des Herstellers (CNA) und die Angaben der CISA (ADP): CVSS, SSVC
  und KEV.

### EPSS {#epss}

[EPSS](term:epss) (Exploit Prediction Scoring System, von FIRST) schätzt, wie wahrscheinlich eine CVE in den nächsten
30 Tagen ausgenutzt wird, und gibt das Perzentil unter allen CVEs an. Leser sehen den Wert an jedem Befund und in der
Meldung ([EPSS und SSVC](/docs/vendor-news#epss-ssvc)).

- Gefragt wird für die CVEs der Befunde gefolgter Produkte und die CVEs der Meldungen der letzten 30 Tage.
- Je CVE höchstens einmal am Tag (FIRST rechnet täglich neu), bis zu 100 CVEs in einer Anfrage an `api.first.org`.
- Nach außen gehen nur CVE-Nummern.

### OSV {#osv}

[OSV](term:osv) (osv.dev) kennt betroffene und behobene Versionen von Open-Source-Paketen. Cobe News fragt OSV nur mit
Nummern:

- nur mit der CVE und ihren Aliassen (`GHSA-…`, `GO-…`, `PYSEC-…`, `RUSTSEC-…`) – nie mit Produktnamen oder
  Versionen,
- nur für Produkte, deren Katalogeintrag das Feld `osv` hat: eine Liste aus Ökosystem und Paket, z. B.
  `[Maven, org.apache.tomcat:tomcat-catalina]`. Die Liste unter *Weitere Quellen* zeigt, wie viele gefolgte Produkte
  OSV-Pakete haben,
- Versionsbereiche der Art ECOSYSTEM und SEMVER werden übernommen, GIT-Bereiche (Commits) verworfen – sie sagen
  nichts über eine installierte Version,
- zurückgezogene OSV-Einträge (withdrawn) werden nicht beachtet,
- je CVE einmal am Tag, solange sie jünger als 30 Tage ist, danach einmal pro Woche.

### Exploit-Hinweise {#exploit-hinweise}

Drei öffentliche Sammlungen sagen, ob es für eine CVE **öffentlichen Exploit-Code** oder eine **fertige Prüfung** gibt,
die die Lücke ausnutzt. Leser sehen das als „Exploit-Code öffentlich“ an Befunden, in Meldungen und bei beobachteten CVEs
([Öffentlicher Exploit](/docs/vendor-news#oeffentlicher-exploit)); in der [Dringlichkeit](/docs/vendor-news#dringlichkeit-formel)
zählt es +10, solange die Lücke nicht schon als ausgenutzt bekannt ist.

| Sammlung | Datei | Größe am Tag | Lizenz | ab Werk |
|---|---|---|---|---|
| **Metasploit** (Rapid7) | `db/modules_metadata_base.json` von `raw.githubusercontent.com` – es zählen nur Module vom Typ „exploit“ | ~11 MB, komprimiert übertragen ~1,4 MB | BSD-3-Clause | **an** |
| **nuclei-templates** (ProjectDiscovery) | `cves.json` von `raw.githubusercontent.com` | ~2,3 MB, komprimiert ~0,5 MB | MIT | **an** |
| **Exploit-DB** (OffSec, GitLab-Spiegel) | `files_exploits.csv` von `gitlab.com` | ~10 MB, unkomprimiert | GPL-2.0 (Repository) | **aus** |

- **Dieselbe Datei für alle:** Jede Sammlung ist eine öffentliche Datei – Cobe News lädt sie ganz und sucht lokal. Nach
  außen geht keine CVE-Nummer, kein Produkt, nichts über eure Installation.
- **Höchstens einmal am Tag**, bedingt (`ETag`/`If-Modified-Since`): Hat sich die Datei nicht geändert, kommt nur
  „unverändert“ zurück. Größenlimit je Datei (Metasploit und Exploit-DB 24 MB, nuclei 8 MB), dieselbe Härtung wie
  jeder Abruf ([Ausgehende Daten](#ausgehende-daten)).
- **Nur wenn gebraucht:** wie der KEV-Katalog – mit gefolgtem Produkt (Vendor News an) oder bei eingeschalteten News,
  dazu, solange jemand eine CVE beobachtet.
- **Gespeichert** wird je CVE und Sammlung nur der Link zum Eintrag und wann Cobe News ihn zuerst gesehen hat – nie
  der Exploit selbst. Führt eine Sammlung eine CVE nicht mehr, verschwindet der Hinweis mit dem nächsten Laden. Bringt
  eine Antwort weniger als die Hälfte der bisherigen Einträge, gilt sie als kaputt: Fehler, nichts wird gelöscht.
- **Erstes Laden** (oder nach mehr als drei Tagen ohne Abruf, etwa weil die Sammlung aus war): Was dabei kommt, wird
  gezeigt, aber nicht als „Exploit veröffentlicht“ gemeldet.
- **Exploit-DB ist ab Werk aus:** die größte Datei, unkomprimiert, und ihre täglichen Änderungen sind meist
  nachbearbeitete alte Einträge. Wer sie will, schaltet sie ein.
- **Nicht genutzt** werden inoffizielle Sammlungen von PoC-Repositories (etwa Listen, die GitHub nach „CVE-…“
  durchsuchen): ungeprüft, teils mit Schadcode, ohne stabile Lizenz. Die GitHub Security Advisories sagen nichts über
  Exploits.

Unter *Gesundheit* stehen die drei als Familie **„Exploit-Hinweise“** (Art „Weitere Quelle“), je Sammlung eine Abfrage
`exploit:<sammlung>`.

### Was den Server verlässt {#weitere-quellen-daten}

Nur Anfragen an die öffentlichen Adressen dieser Dienste und CVE- bzw. Schwachstellen-Nummern – **nie**
Produktnamen, Versionen, euer Inventar oder Hostnamen.

| Quelle | Ziele | Was gesendet wird |
|---|---|---|
| CSAF-Anbieter | `wid.cert-bund.de` (Anbieter-Liste des BSI), `cert-portal.siemens.com`, `www.cisco.com`, `www.se.com` | Abrufe der öffentlichen CSAF-Adressen |
| cvelistV5 | `api.github.com`, `github.com` (und die Download-Server von GitHub), `raw.githubusercontent.com` | Abrufe öffentlicher Dateien ohne Anmeldung; bei Einzelabrufen die CVE-Nummer im Pfad |
| EPSS | `api.first.org` | CVE-Nummern |
| OSV | `api.osv.dev` | CVE- und Advisory-Nummern im Pfad |
| Exploit-Hinweise | `raw.githubusercontent.com` (Metasploit, nuclei), `gitlab.com` (Exploit-DB, wenn eingeschaltet) | nichts – Abruf derselben öffentlichen Datei für alle |

### Welche Quelle entscheidet {#urteil-reihenfolge}

Nennen mehrere Quellen dieselbe Schwachstelle, entscheidet je Version diese Reihenfolge:

1. der eigene Hinweis des Herstellers (Palo Alto, Fortinet, Veeam, CSAF-Anbieter),
2. die NVD, wo sie die CVE analysiert hat (CPE-Konfiguration),
3. cvelistV5 – die Angaben des Herstellers (CNA), nur wenn die das Produkt nicht nennen die der CISA (ADP),
4. die Kopie der Herstellerangaben in der NVD – auch hier die der CISA (ADP) nur, wenn der Hersteller das Produkt nicht nennt,
5. OSV zuletzt: es entscheidet nur ein „möglicherweise betroffen“ und ergänzt eine fehlende Fix-Version, ändert aber
   kein eindeutiges Urteil.

Dabei gilt:

- Ein CSAF-Dokument des BSI (WID) ist kein Herstellerhinweis: es fasst mehrere CVEs und die Angaben der Hersteller
  zusammen. Neben den CVE-Einträgen seiner CVEs entscheidet es nur, wo diese nichts entscheiden. Nennt es ein Produkt
  ohne Version („alle Versionen“) und sagen die CVE-Einträge „nicht betroffen“, steht „möglicherweise betroffen“; sein
  „nicht betroffen“ (etwa aus Grenzen je Linie, die zwei CVEs zusammenlegen) zählt nie gegen ein „betroffen“ der
  CVE-Einträge.
- Nennt der Hersteller im CVE-Eintrag seine betroffenen Bereiche und eure Version ausdrücklich nicht (alle anderen
  „nicht betroffen“, oder der Fix eurer Linie), die NVD-Analyse aber einen Bereich, der sie einschließt, steht
  „möglicherweise betroffen“ – nicht „betroffen“.
- Ein Release über dem Ende eines betroffenen Bereichs derselben Linie gilt als behoben (GitLab `>=12.8, <12.9.8`:
  12.9.8 enthält den Fix).

### Eine Quelle abschalten {#weitere-quellen-aus}

Schalter aus und „Speichern“:

- Die Quelle stellt sofort alle Anfragen ein.
- Was sie schon geholt hat, bleibt gespeichert, zählt aber nicht mehr bei der Bewertung (EPSS wird nicht mehr
  angezeigt).
- Wieder eingeschaltet, zählen die gespeicherten Einträge sofort wieder – ohne neuen Abruf.

Ohne cvelistV5 kommt der Hinweis auf eine neue Lücke nur noch über die NVD und die Hinweise der Hersteller. Unter
*Gesundheit* stehen die Quellen als Art **„Weitere Quelle (Vendor News)“** (intern `structured`): die CSAF-Anbieter je
Anbieter und die Anbieter-Liste des BSI, cvelistV5, EPSS, OSV und die Exploit-Hinweise.

## Web Push {#web-push}

Web Push bringt Desktop-Benachrichtigungen auch dann, wenn **kein Tab** von Cobe News offen ist – solange der Browser
läuft. Jede Person schaltet es für ihren Browser selbst ein
([Desktop-Benachrichtigungen](/docs/benachrichtigungen#desktop)). Als Admin steuerst du nur den Server.

So funktioniert es:

- Nach jeder Abrufrunde schickt der Server neue Meldungen über den Push-Dienst des Browser-Herstellers.
- Inhalt: Titel, Schwere und Quelle der Meldung, Ende-zu-Ende verschlüsselt – der Push-Dienst sieht nur die Größe.
- Signiert mit dem [VAPID](term:vapid)-Schlüssel des Servers; er entsteht beim ersten Gebrauch und liegt verschlüsselt
  in der Datenbank.

### Einstellungen in der .env {#web-push-env}

| Variable | Ab Werk | Bedeutung |
|---|---|---|
| `WEB_PUSH` | `1` | `0` schaltet Web Push für alle ab – dann geht keine Anfrage an die Push-Dienste. Benachrichtigungen im offenen Tab funktionieren weiter. |
| `PUSH_CONTACT` | leer | Kontaktadresse für die Push-Dienste, `mailto:` oder `https:`, z. B. `mailto:secops@corp.example`. Leer: `BASE_URL` (hier {{base_url}}). Die Push-Dienste sehen diese Adresse. |

Änderungen in der [.env](term:envfile) wirken nach einem Neustart:

```bash
cd /opt/cobe-news
docker compose up -d
```

Mit `WEB_PUSH=0` zeigt die Karte unter *Benachrichtigungen* „Nicht verfügbar, weil Web Push auf dem Server
ausgeschaltet ist (WEB_PUSH=0)“.

### Voraussetzungen {#web-push-voraussetzungen}

- **Ein Zertifikat, dem die Rechner vertrauen.** Bei einer Zertifikatswarnung verweigert der Browser den Service
  Worker – Push ist dann „nicht verfügbar“, der offene Tab benachrichtigt weiter
  ([HTTPS](/docs/betrieb#https)).
- **Ausgehend https (Port 443) zu den Push-Diensten**, über `HTTPS_PROXY`, wenn gesetzt:

| Browser | Push-Dienst |
|---|---|
| Chrome, Edge auf Android … | `fcm.googleapis.com` |
| Firefox | `*.push.services.mozilla.com` |
| Safari | `*.push.apple.com` |
| Edge unter Windows | `*.notify.windows.com` |

Andere Ziele nimmt der Server nicht an.

### VAPID-Schlüssel erneuern {#web-push-vapid}

Nach einem Verdacht auf ein Leck erzeugt dieser Befehl ein neues Schlüsselpaar – sofort wirksam, ohne Neustart:

```bash
cd /opt/cobe-news
docker compose exec app python -m app.cli rotate-vapid
```

Die bisherigen Push-Abos werden gelöscht; die Browser melden sich beim nächsten Besuch mit dem neuen Schlüssel an.
Dasselbe passiert automatisch, wenn sich der Schlüssel nicht mehr lesen lässt (etwa nach geändertem
[Hauptschlüssel](term:masterkey) `SECRET_KEY`).

## Ausgehende Daten {#ausgehende-daten}

Cobe News holt nur Daten – es meldet keine Nutzungsdaten irgendwohin. Was trotzdem den Server verlässt:

| Integration | Ziele | Was gesendet wird |
|---|---|---|
| **News** (nur eingeschaltete Quellen) | die Hosts der Feeds, z. B. `www.heise.de`, `www.bsi.bund.de`, `www.cisa.gov`; für Logos einmal die Startseiten; lehnt `www.cisa.gov` den KEV-Abruf ab (HTTP 403), der offizielle Spiegel `raw.githubusercontent.com/cisagov/kev-data` | einfache Abrufe mit der Kennung `Cobe/…` und Angaben für bedingte Abrufe (`ETag`/`If-Modified-Since`). Keine Benutzerdaten. Logos holt der Server – der Browser lädt nichts von den Nachrichtenseiten. |
| **Details aus der Quelle** | `services.nvd.nist.gov` und die Hosts der Advisories (`wid.cert-bund.de`, `cert-portal.siemens.com`, `sec.cloudapps.cisco.com`, `filestore.fortinet.com`, `security.paloaltonetworks.com`) | Kennungen der Advisories und CVE-Nummern aus öffentlichen Meldungen |
| **Vendor News** (nur mit gefolgtem Produkt; den KEV-Katalog von `www.cisa.gov` bzw. dem Spiegel auch ohne, solange die News an sind) | `services.nvd.nist.gov`, `endoflife.date`, `www.cisa.gov`; mit Produkten dieser Hersteller auch `security.paloaltonetworks.com`, `filestore.fortinet.com`, `www.veeam.com` | die CPE-Namen und Produktnamen der **gefolgten** Produkte (die NVD erfährt so, welche Produkte ihr beobachtet), der NVD-Schlüssel als Header. Eure **Versionen** bleiben auf dem Server – verglichen wird lokal. Die CPE-Suche bei „Nicht im Katalog?“ schickt den Suchbegriff an die NVD. |
| **Katalog-Pflege** | `services.nvd.nist.gov` | CPE-Namen des Katalogs, höchstens 20 Anfragen pro Stunde – nur bei eingeschalteter Vendor News mit gefolgtem Produkt |
| **Weitere Quellen** (CSAF-Anbieter, cvelistV5, EPSS, OSV) | `wid.cert-bund.de`, `cert-portal.siemens.com`, `www.cisco.com`, `www.se.com`, `api.github.com`, `github.com`, `raw.githubusercontent.com`, `api.first.org`, `api.osv.dev` | nur Abrufe öffentlicher Adressen und CVE- bzw. Schwachstellen-Nummern – nie Produkte, Versionen oder Hostnamen ([Was den Server verlässt](#weitere-quellen-daten)) |
| **Exploit-Hinweise** (Metasploit und nuclei ab Werk an, Exploit-DB aus) | `raw.githubusercontent.com`, `gitlab.com` (nur Exploit-DB) | nichts – höchstens einmal am Tag derselbe Abruf einer öffentlichen Datei für alle, bedingt ([Exploit-Hinweise](#exploit-hinweise)) |
| **Update-Hinweis** (ab Werk **an**, abschaltbar unter *Version & Changelog*) | `api.github.com` (`/repos/G0urmetD/Cobe-News/releases/latest`) | ein Abruf ohne Anmeldung höchstens alle 12 Stunden, bedingt (`ETag`), mit der Kennung `Cobe/<Version>` – sonst nichts über eure Installation ([Update-Hinweis](/docs/betrieb#update-hinweis)) |
| **Benachrichtigungskanäle** | der jeweilige Dienst (Teams, Slack, Discord, Telegram, euer Mailserver, eigener Webhook) | Titel, Zusammenfassung, Schwere, Quelle, CVEs und Links der Meldungen, Name von Kanal und Regel; bei Vendor-News-Regeln auch **Produkt und Version** eurer Systeme ([Kanäle](/docs/benachrichtigungen#kanaele)) |
| **Persönliche Benachrichtigungen** (nur wenn ein Admin die Wege freigibt) | euer Mailserver; für den eigenen Teams-Webhook einer Person `*.logic.azure.com`, `*.powerplatform.com` oder `*.webhook.office.com`; Desktop über Web Push | die Vendor-News-Meldungen der Produkte dieser Person, wie bei den Vendor-News-Regeln mit **Produkt und Version**; dazu Wochenrückblick und Willkommens-Mail per E-Mail ([Persönliche Benachrichtigungen](/docs/anmeldung#teams-persoenlich)) |
| **Weiterleiten ans Team** | der Weiterleitungs-Kanal des Teams | wer weiterleitet, der Kommentar, Titel und Link, bei einem Befund Dringlichkeit und eure Versionen ([Weiterleiten](/docs/benachrichtigungen#weiterleiten)) |
| **Web Push** | die Push-Dienste der Browser | Titel, Schwere und Quelle – Ende-zu-Ende verschlüsselt; `PUSH_CONTACT` |
| **Anmeldung** | eure Domänencontroller bzw. `login.microsoftonline.com` und `graph.microsoft.com` | nur wenn eingerichtet ([Anmeldung](/docs/anmeldung#ueberblick)) |

Für alle Abrufe gilt dieselbe Härtung: nur https, keine internen Ziele, Größen- und Zeitlimits, je Website höchstens
eine Anfrage pro Minute, Pausen nach Fehlern.

### Proxy (HTTPS_PROXY) {#proxy}

Muss der Server über einen Proxy ins Internet, setze in der `.env`:

```bash
HTTPS_PROXY=http://proxy.corp.example:3128
```

- Darüber laufen die Abrufe von News, Details und Vendor News, die Benachrichtigungskanäle, Web Push und die Anmeldung
  mit Microsoft. E-Mail (SMTP) und Active Directory gehen direkt.
- Mit Proxy löst der **Proxy** die Namen auf. Cobe News prüft dann nur Adressen, die als IP in der URL stehen – interne
  Ziele hinter Namen muss der Proxy selbst sperren.
- Ein Webhook ins eigene Netz (z. B. n8n) kann den Proxy umgehen: Schalter „Über den Proxy (HTTPS_PROXY)“ im Kanal
  ausschalten ([Webhook-Optionen](/docs/benachrichtigungen#webhook-optionen)).

### Eigene CA (CA_FILE) {#ca-file}

Bricht der Proxy TLS auf (TLS-Inspektion) oder nutzt ein Ziel ein Zertifikat eurer internen CA, braucht Cobe News
deren Zertifikat:

1. Das CA-Zertifikat (PEM) in den Ordner `data` der Installation legen, z. B. `/opt/cobe-news/data/ca.pem`.
2. In der `.env` den Pfad **im Container** eintragen: `CA_FILE=/data/ca.pem`.
3. `docker compose up -d`.

Die CA gilt zusätzlich zu den Zertifikaten des Systems – für Feeds, Details, Vendor News und Benachrichtigungskanäle.
TLS wird immer geprüft; abschalten lässt es sich nicht.

> [!WARNING]
> `ALLOW_PRIVATE_FEEDS=1` erlaubt Feeds aus privaten Netzen. Nur setzen, wenn ihr wirklich einen internen Feed abrufen
> wollt – sonst kann ein Admin-Konto damit interne Dienste ansprechen. Loopback und Cloud-Metadaten bleiben in jedem
> Fall gesperrt.

Alle Variablen mit Standardwerten: [Betrieb → Umgebungsvariablen](/docs/betrieb#env-referenz).

## Gesundheit {#gesundheit}

*Integrationen → Gesundheit* ([öffnen](/settings/integrations?view=health)) zeigt, wie gut jede Quelle abgerufen wird:
jede News-Quelle, jede Quellen-Familie von Vendor News (NVD, Palo Alto Networks, Fortinet PSIRT, Veeam KB, CISA KEV,
endoflife.date) und als Art „Weitere Quelle (Vendor News)“ jede der [weiteren Quellen](#weitere-quellen). Die Regeln
für die Zustände: [Quellen-Gesundheit](/docs/news-quellen#quellen-gesundheit). Gibt es gestörte oder tote Quellen,
trägt der Reiter **Gesundheit** eine Markierung.

### Die Tabelle {#gesundheit-tabelle}

| Spalte | Inhalt |
|---|---|
| **Quelle** | Name; bei Vendor News die Familie mit der Zahl ihrer Abfragen |
| **Zustand** | tot, gestört, langsam, gesund, aus, noch nicht abgerufen – die Bedeutung beim Darüberfahren |
| **Letzter Erfolg** | wann der letzte Abruf geklappt hat |
| **Letzter Fehler** | Art und Zeit des letzten Fehlers |
| **Neu je Woche** | neue Einträge je Woche der letzten 4 Wochen, älteste links; „–“ = in der Woche kein Abruf |
| **Antwortzeit** | mittlere Dauer einer Anfrage der letzten 7 Tage, nur erfolgreiche Abrufe |

Die schlimmsten stehen oben. **„Nur Probleme“** blendet alles aus, was nicht gestört oder tot ist (der Browser merkt
sich die Wahl). Ausgeschaltete Quellen sind eingeklappt und lassen sich einblenden.

### Die Schublade {#gesundheit-schublade}

Ein Klick auf eine Zeile öffnet den Verlauf:

- **Warum** der Zustand so ist, letzter Erfolg und Fehler, Fehlschläge in Folge, nächster Versuch bzw. Pause,
- **Bedingte Abrufe** – ob die Quelle `ETag`/`Last-Modified` kann (dann antwortet sie bei nichts Neuem nur mit 304),
- Mittelwerte der letzten 7 Tage: Antwortzeit, Größe, Zahl der Abrufe, Zeitüberschreitungen, unlesbare Einträge,
- bei Vendor News die einzelnen **Abfragen** (z. B. eine je CPE),
- **Letzte Abrufe** (Zeit, Status, Dauer, Größe, neue Einträge), **Letzte Fehler** und **Zustandswechsel**,
- „Quelle einrichten“ führt zurück zur Kachel der Integration (News bzw. Vendor News).

Die Statistik reicht 60 Tage zurück. Ein Abruf, der gar nicht gefragt hat (Quelle pausiert), zählt nicht.

### Benachrichtigung bei Ausfall {#gesundheit-benachrichtigung}

Damit du einen Ausfall nicht erst in der Tabelle bemerkst:

1. *Einstellungen → Kanäle & Regeln*, Reiter **Regeln**, eine Regel anlegen.
2. Unter „Was wird gesendet?“ **„Quelle gestört oder tot“** wählen, dazu einen oder mehrere Kanäle.
3. „Speichern“.

Gesendet wird **einmal je Zustandswechsel**: in gestört oder tot, von gestört nach tot und zurück zu gesund oder
langsam – nie jede Runde. Schweregrade und Quellen der Regel gelten dafür nicht. Das Ausschalten einer Quelle und der
erste Zustand nach einem Update schicken nichts. Die Zustände werden alle 5 Minuten verglichen; auch ein Neustart
schickt nichts doppelt. Bei Vendor News kommt eine Nachricht je Familie (fällt die NVD aus: eine Nachricht, nicht eine
je CPE). Mehr zu Regeln: [Regeln](/docs/benachrichtigungen#regeln).
