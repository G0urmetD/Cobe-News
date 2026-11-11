---
title: Vendor News & Katalog
summary: Produkten und Versionen folgen, die ihr einsetzt – und sehen, welche Schwachstellen genau eure Versionen betreffen, welches Update hilft und wann der Support endet.
audience: all
---

## Überblick {#ueberblick}

Der Seitenpunkt **Vendor News** zeigt zu den Produkten und Versionen, die ihr einsetzt, die Schwachstellen, die
**genau diese Versionen** betreffen, neue Versionen derselben [Release-Linie](term:releaseline), das Support-Ende und passende News.

Die Seite zeigt die gefolgten Produkte mit ihrem Stand. Von oben nach unten:

- **Kopf:** unter dem Titel eine Zeile wie „Nächstes Support-Ende: PAN-OS in 6 Monaten · abgerufen vor 2 Minuten“
  (beides nur, wenn bekannt). Rechts das Menü **⋯** mit „Produkt hinzufügen“ (Admins; Leser: „Katalog ansehen“),
  „Produkt vorschlagen“, „Vorschläge“ bzw. „Meine Vorschläge“ und für Admins „Jetzt abrufen“ und „Einstellungen“.
  Warten Vorschläge auf einen Admin, steht daneben der Knopf **Vorschläge** mit ihrer Zahl.
- **Statuszeile** mit vier Feldern und ihren Zahlen: **Handlungsbedarf** (darin „· 2 Sofort“, siehe
  [Dringlichkeit](#dringlichkeit)), **Möglicherweise**, **Aktuell** und **Alle**. Ein Klick zeigt nur diese Produkte,
  das gewählte Feld ist hervorgehoben. Mit der Tastatur: Tab erreicht das gewählte Feld, die Pfeiltasten wechseln.
- **Werkzeugzeile:** die Suche, **Filter** (mit der Zahl der eingeschalteten), **Ansicht** (deine
  [gespeicherten Ansichten](#vendor-lesen), „Standard“ ohne) und ein Knopf, der zwischen Kacheln und **Liste** wechselt
  (Spalten Produkt, Versionen, Zielversion, betroffen, kritisch, ausgenutzt, Support bis, Dringlichkeit – jede Spalte
  sortierbar).
- **Aktive Filter** als Chips darunter – ein Klick auf × entfernt einen. Rechts daneben **„Alle N als gelesen“** für
  genau die angezeigten Produkte (siehe [Gelesen, stumm und Ansichten](#vendor-lesen)).

Unter **Filter** stehen die Schalter „Nur ungelesene“ (mit der Zahl der ungelesenen Befunde), „Stummgeschaltete
zeigen“, „Bestätigte zeigen“ ([Treffer bestätigen](#treffer-bestaetigen)), „Versionen zu prüfen“ (mit ihrer Zahl, wenn [Versionen prüfen](#versionen-pruefen) eingeschaltet ist) und
„Mein Team | Alle“ (siehe [Mein Team](#mein-team)).

Der **Katalog** – alle Produkte, denen man folgen kann (über 900, in Kategorien) – öffnet sich über **⋯ → Produkt
hinzufügen** (Leser: „Katalog ansehen“), die **Vorschläge** über ⋯ oder den Knopf. Beide haben oben „Zurück zur
Übersicht“; Suche und Filter der Übersicht bleiben dabei erhalten.

Jede **Karte** zeigt für ein Produkt:

- wie viele Schwachstellen eure Versionen betreffen („3 betreffen euch“), wie viele vielleicht („2 möglicherweise“),
  davon kritisch und aktiv ausgenutzt,
- die Zielversion (siehe [Zielversion](#zielversion)), „Update verfügbar“, „Support endet bald“ oder
  „Support beendet“,
- die wichtigsten Schwachstellen – ein Klick öffnet die Schublade genau bei diesem Eintrag.

Ein Klick auf die Karte öffnet die **Schublade** des Produkts mit den Reitern „Schwachstellen“, „Versionen“ und
„News“, dazu die Release-Linien, Notizen und Tags.

**Die Zahl am Seitenpunkt** „Vendor News“ zählt die Produkte, bei denen mindestens eine Schwachstelle eine
eingetragene Version **betrifft** (nicht „möglicherweise“). Sie ist orange, und rot, sobald eine davon aktiv
ausgenutzt wird.

> [!NOTE]
> Steht auf der Seite „Vendor News ist ausgeschaltet“, hat ein Admin die Funktion unter *Einstellungen →
> Integrationen* abgeschaltet. Solange geht keine Anfrage an Hersteller, NVD oder endoflife.date.

## Produkten folgen {#produkten-folgen}

Im **Katalog** (⋯ → „Produkt hinzufügen“, für Leser „Katalog ansehen“) stehen die Produkte nach Kategorien (Firewalls & VPN, Betriebssysteme, Virtualisierung,
Storage & Backup, Datenbanken …). Links stehen die Kategorien mit Zählern „gefolgt / gesamt“, dazu „Alle“ und
„Gefolgt“.

- Die **Suche** („Produkt, Hersteller oder CPE suchen …“) ist unscharf: sie findet Hersteller, Produktnamen,
  andere Schreibweisen und [CPE](term:cpe) und verzeiht einen Tippfehler.
- Jede Zeile zeigt Hersteller, Kategorie und ob das Produkt eine CPE hat („CPE“ oder „ohne CPE – nur News“),
  „Versionen & EOL“ (Release-Daten vorhanden), „Hersteller-Hinweise“ oder „Cloud-Dienst“.
- Ein Klick auf eine Zeile öffnet die Schublade des Produkts – auch für nicht gefolgte Produkte (dann mit
  Release-Linien und News).

**Folgen** (nur Admins):

1. Über **⋯ → Produkt hinzufügen** den Katalog öffnen und das Produkt suchen.
2. Den Schalter **„Folgen“** rechts in der Zeile einschalten.
3. In der Schublade unter „Versionen“ die eingesetzten Versionen eintragen (siehe [Versionen](#versionen)).

Leser sehen dieselbe Liste, können den Schalter aber nicht bedienen („Nur Admins legen fest, welchen Produkten
gefolgt wird.“).

Zum Pausieren reicht es, „Folgen“ auszuschalten – Versionen und Notizen bleiben. „Entfernen“ in der Schublade
löscht das Produkt mit allen Versionen und Notizen.

### Ohne Version oder mit Versionen {#ohne-oder-mit-version}

| | Ohne Version | Mit Versionen |
|---|---|---|
| Was erscheint | alle Schwachstellen und News zum Produkt | nur, was eure Versionen betrifft |
| Bewertung | „Betrifft das Produkt – Version angeben für genaue Prüfung“ | betroffen / möglicherweise / nicht betroffen, mit Fix-Version |
| Update und Support-Ende | nein | ja, je Version |
| Sinnvoll für | Bibliotheken und Laufzeiten wie PHP oder Node.js, bei denen ihr die große aktuelle Lücke sehen wollt | alles, dessen Version ihr kennt |

## Versionen eintragen {#versionen}

In der Schublade eines gefolgten Produkts, Reiter **„Versionen“**:

1. „Version hinzufügen“ klicken – das Formular „Neue Version eintragen“ öffnet sich.
2. **Version** eintragen. Das Feld prüft sie sofort („Format passt.“ oder der Grund, z. B. „Unbekanntes Format –
   erwartet z. B. …“). Wird eine Anzeigeform übersetzt, zeigt es vor dem Speichern, was gespeichert und verglichen wird
   („→ 15.2.1748.24“) – mehr unter [Versionsformate je Hersteller](#versionsformate).
3. Optional **Bezeichnung** (z. B. „RZ Nord“, „HA-Paar“) und **Anzahl** (Geräte mit dieser Version, 1 bis 100 000).
4. „Version eintragen“.

Mehrere Versionen pro Produkt sind normal, zum Beispiel eine je Standort oder Cluster – höchstens 30 pro Produkt.
Jede Version wird einzeln geprüft. Eine Schwachstelle zeigt dann „betrifft 2 von 3 Versionen“, die Karte den
schlimmsten Stand.

Eingetragene Versionen erscheinen als Karten mit ihrem Stand: Zahl der Schwachstellen, „Aktuell“ oder
„Update verfügbar → …“, „Support bis …“. Mit dem Stift wird eine Version geändert, über „… entfernen“ gelöscht. Eine
geänderte Version wird sofort neu bewertet, ohne neuen Abruf.

> [!TIP]
> Eine zu kurze Angabe wie `7.4` bei FortiOS umfasst mehrere Releases. Sie wird angenommen, aber als „ungenau“
> markiert – wo die Releases unterschiedlich betroffen sind, steht dann „möglicherweise betroffen“. Die genaue
> Version eintragen.

### Versionsschemata {#versionsschemata}

Das Format wird je Hersteller geprüft, damit Versionen richtig verglichen werden:

| Produkt | Format | Beispiel |
|---|---|---|
| PAN-OS, Panorama | Version mit [Hotfix](term:hotfix) `-h` | `11.2.4-h23` (neuer als `11.2.4-h4` und `11.2.4`) |
| FortiOS und andere Fortinet-Produkte | drei Zahlen, Build optional, auch die GUI-/CLI-Zeile | `7.4.8`, `v7.4.3 build2573 (GA.F)`, `FortiGate-60F v7.4.3,build2573,240201 (GA.F)` |
| Cisco ASA, NX-OS | Klammerschreibweise | `9.18(4)22`, `10.2(5)` |
| Cisco IOS XE, FTD | Buchstabe als weiterer Teil, Zahlen; „(build …)“ wird ignoriert | `17.9.4a`, `7.2.5.1`, `7.2.5 (build 208)` |
| Cisco IOS (klassisch) | Release mit Zug – verglichen nur innerhalb des Zugs | `15.9(3)M9` |
| Windows, Windows-Server-Rollen | Build-Nummer, **keine KB-Nummer**; auch „OS Build …“ aus winver | `10.0.20348.2762`, `OS Build 26100.2605` |
| Sophos Firewall (SFOS) | MR = dritter Teil, Build = vierter | `21.0.1.272`, `SFOS 21.0.1 MR-1-Build272`, `21.0 MR1` |
| Oracle Java SE | Java 8 in jeder Schreibweise, gespeichert als `8u…` | `8u411`, `1.8.0_411`, `Java 8 Update 411`, `21.0.5` |
| SAP (S/4HANA, NetWeaver) | Komponenten-Release wie in SAPs Hinweisen | `S4CORE 108`, `SAP_BASIS 758`, `7.58` |
| VMware ESXi, vCenter | Version mit Update, auch Version aus der VAMI und Build ([mehr](#vmware-vsphere)) | `8.0 U3c`, `8.0 Update 3c`, `8.0c`, `8.0.3.00400`, `24322831` |
| Ivanti | R-Releases | `22.7R2.3` |
| Veeam | ganzer Build | `12.3.2.4934`, `13.1.2 (build 13.1.2.57)` |
| WAGO PFC100/PFC200 | Firmware mit Index in Klammern – der Index zählt | `04.06.03(28)`, `FW28` |
| Zoho ManageEngine (ServiceDesk Plus, ADSelfService Plus, Password Manager Pro, PAM360, OpManager) | Version mit Build-Nummer – die Build-Nummer zählt | `14.6 Build 14600`, `14600`, `12.8.329` (OpManager) |
| Linux-Distributionen | Release | `12`, `9.4`, `24.04` |
| alles andere | Zahlen und Buchstaben | `8.3.14`, `1.0.2u`, `9.8p1` |

Besonderheiten:

- **Windows:** Eine KB-Nummer lässt sich nicht vergleichen und wird abgelehnt. Welche KB welchem Build entspricht,
  steht im Update-Verlauf von Microsoft.
- **Veeam:** Am besten den ganzen Build eintragen. Eine kurze Angabe wie `12.3.2` gilt für jeden Build von 12.3.2 –
  entschieden wird nur, was für alle gilt, sonst steht „möglicherweise betroffen“. `12.3.2 P4` lässt sich nicht
  vergleichen; welcher Build zu einem Patch gehört, steht im KB-Artikel. Der Veeam Agent hat je Betriebssystem einen
  eigenen Katalog-Eintrag.
- **Zoho ManageEngine:** Die Produkte zählen nach Build-Nummer (Hilfe → Info: „14.6 Build 14600“). Verglichen wird der
  Build – mit den Build-Grenzen der Hinweise („vor 10509“) und mit NVD-Grenzen als Versionslinie („< 14.9“ = vor jedem
  Build von 14.9). Eine Angabe ohne Build (`14.6`) gilt für jeden Build von 14.6; entschieden wird nur, was für alle
  gilt. Fix und Zielversion stehen als Build da („14.9 Build 14920“).
- **Linux-Distributionen:** Vendor News zeigt Release-Linie und Support-Ende. Ob eine Lücke geschlossen ist, hängt am
  Paketstand – das sagt nur das Advisory der Distribution.
- **Cloud-Dienste** haben keine Version auf eurer Seite; Hinweise erscheinen als „Cloud-Dienst betroffen“.

Für jede eingetragene Version gilt außerdem: Ein Wort, das allein vor einer Zahl steht, muss ein Trennwort sein
(`Update`, `build`, `Patch`, `SP`, `CU`, `RU`, `Take` …). „iLO 6 v1.62“ wäre sonst die Version 6.1.62 – der Name des
Produkts wird deshalb vorher entfernt (eingetragen wird 1.62), ein unbekanntes Wort abgelehnt. Plattform-Angaben wie
`x64` oder `amd64` hinter der Version werden ignoriert.

### Versionsformate je Hersteller {#versionsformate}

Viele Hersteller zeigen ihre Version anders an, als ihre Hinweise sie nennen. Vendor News nimmt die Anzeigeform und
speichert, was die Hinweise vergleichen – das Formular zeigt es vorher („→ …“):

| Produkt | Was ihr seht | gespeichert als |
|---|---|---|
| Microsoft Exchange Server | `15.02.1748.037` (ExSetup), `2019 CU15 Apr25HU`, `SE RTM Oct26SU` | der Build, z. B. `15.2.1748.24` |
| Microsoft Exchange Server | `2019 CU15` (ohne Update) | `15.2.1748` – steht für jeden Build von CU15 („ungenau“) |
| Microsoft SQL Server | `2022 CU16`, `2022 CU16 GDR`, `KB5048033`, die ganze Zeile von `SELECT @@VERSION` | der Build, z. B. `16.0.4165.4` |
| VMware Tools | Code im vSphere Client `12416` | `12.4.0` |
| GlobalProtect App | Build `6.2.8-c948` | Hotfix `6.2.8-h10` |
| VMware vCenter, ESXi | `8.0.3.00400`, Build `24322831` ([mehr](#vmware-vsphere)) | `8.0 U3d` |
| HPE iLO | `iLO 6 v1.62` | `1.62` |
| Adobe Acrobat/Reader | `2024.005.20320` | `24.005.20320` |
| Microsoft Office / 365 Apps | `Version 2411 (Build 18227.20162 Klick-und-Ausführen)` | `16.0.18227.20162` |
| NetScaler ADC/Gateway | `NS14.1: Build 29.72.nc` | `14.1-29.72` (FIPS-Builds: `14.1-29.72 FIPS`) |
| Cisco ISE | `3.2.0.542 Patch 5` | `3.2 Patch 5` |
| Check Point | `R81.20 JHF Take 99`, `R81.20 - Build 012` | `R81.20 Take 99`, `R81.20` |
| NGINX Plus | `nginx/1.27.2 (nginx-plus-r33)` | `R33` |
| Sophos Firewall | `SFOS 21.0.1 MR-1-Build272` | `21.0.1.272` |
| Oracle Java SE | `1.8.0_411`, `Java 8 Update 411` | `8u411` |

Die Tabellen dafür kommen mit dem Katalog und nennen ihre Quelle und das Abrufdatum (Microsoft Learn für Exchange und
SQL Server, VMwares Versionstabelle für die Tools, die Release Notes von Palo Alto Networks, Broadcoms KB-Artikel für
vSphere). Was eine Tabelle nicht kennt, wird **abgelehnt statt geraten** – dann den Build eintragen. Ein Name, den
Microsoft mehreren Builds gibt (`2022 GDR`), geht nicht; ebenso nicht die AdminDisplayVersion von Exchange
(„Version 15.2 (Build 1748.10)“): sie zeigt keine Security Updates.

Was bewusst abgelehnt wird, mit Hinweis im Formular:

- **.NET:** die SDK-Version aus `dotnet --version` (`8.0.403`) – die Hinweise nennen die Runtime (`dotnet --list-runtimes`,
  z. B. `8.0.11`).
- **SAP S/4HANA:** der Produkt-Release (`2023`) – SAPs Hinweise nennen die Komponente (`S4CORE 108`).
- **Office:** die Versionsnummer allein (`2411`).
- **GlobalProtect:** ein Build, den die Release Notes keinem Hotfix zuordnen (z. B. `6.3.3-c1199`) – dann den Hotfix
  (`6.3.3-hN`) eintragen.

### Plausibilitätsprüfung {#plausibilitaet}

Eine Version muss zu den Release-Linien des Produkts passen (endoflife.date, mit dem Katalog geliefert und täglich
aktualisiert). Liegt die Hauptversion weit über allen bekannten Linien – mehr als das Anderthalbfache der höchsten und
mehr als zehn darüber –, ist es fast sicher ein Jahr, eine Marketing-Nummer oder ein interner Code: `2411` bei
Firefox, `2019` bei nginx. Das Formular lehnt sie ab und nennt die bekannten Linien und ein Beispiel. Neuere Linien als
die bekannten und ältere gehen. Produkte ohne Release-Linien prüft Vendor News darauf nicht; manche haben stattdessen
ein festes Muster (Exchange und SQL Server: Build-Nummern, VMware Tools: `12.4.0`).

Manche Produkte haben nur einen Teil der Linien: **Mozilla Firefox ESR** nur die ESR-Linien (115, 128, 140, 153 …),
**Jenkins LTS** nur die LTS-Linien (2.555, 2.568 …). Eine Version dazwischen, die auf keiner davon liegt – `134.0` bei
Firefox ESR, `2.500.1` bei Jenkins LTS –, lehnt das Formular ab und nennt die Linien; meist ist es das andere Produkt
(Mozilla Firefox, Jenkins weekly). Eine Linie, die neuer ist als alle bekannten, geht auch hier.

### Getrennte Produkte {#getrennte-produkte}

Produkte mit zwei Versionslinien unter einem Namen sind getrennt, weil ihre Hinweise getrennt rechnen:

| Produkt | getrennt in |
|---|---|
| pfSense | **pfSense CE** (`2.8.0`) und **pfSense Plus** (`24.11`) |
| Firefox | **Mozilla Firefox** und **Mozilla Firefox ESR** (`140.4.0esr`) – die NVD trennt sie über die Edition `esr` |
| Jenkins | **Jenkins LTS** (`2.492.2`) und **Jenkins Weekly** (`2.499`) – die NVD trennt sie über die Edition `lts` |
| nginx | **nginx (Open Source)** (`1.27.2`) und **NGINX Plus** (`R33`) |

Wer dem bisherigen Produkt schon folgt, folgt ihm weiter. Eine Version, die zum anderen Produkt gehört (`24.11` bei
pfSense CE, `128.5.1esr` bei Firefox), bleibt eingetragen, steht aber auf [„Bitte prüfen“](#versionen-pruefen) mit dem
Hinweis, welchem Produkt sie gehört – bis dahin wird sie nur als „möglicherweise betroffen“ gewertet. Dem anderen
Produkt folgen, die Version dort eintragen und hier entfernen.

Ähnlich bei Produkten, deren Editionen dieselben Versionsnummern haben: **SharePoint** 2016, 2019 und Subscription
Edition (alle 16.0.x) erkennt Vendor News am Build, **SQL Server** GDR- und CU-Zweig ebenso, und bei **Exchange** zählt
für einen Build nur die Zeile seines Cumulative Updates – eine Zeile für eine andere Edition oder ein anderes CU
spricht nicht über eure Version.

### Zusammengelegte Produkte {#zusammengelegte-produkte}

Einige Produkte standen bis 0.1.44 zweimal im Katalog. Seit 0.1.45 gibt es sie einmal:

| bisher auch | jetzt |
|---|---|
| IBM Db2 (`db2`) | **IBM Db2** (`ibm-db2`, der Schlüssel von endoflife.date) |
| Omnissa Horizon (`vmware-horizon`) | **Omnissa Horizon (VMware Horizon)** (`horizon`) – „2412“ wird als `8.2412` gespeichert, wie endoflife.date die Linien schreibt |
| Juniper SRX (`juniper-srx`) | **Juniper Junos OS** (`junos`) – SRX läuft mit Junos OS, eine Schwachstelle gilt für beide |
| VMware Harbor Registry | **Harbor** (`harbor`) |
| Stormshield Firewall (Gerätemodelle) | **Stormshield Network Security (SNS)** (`sns-firmware`) – verglichen wird die Firmware |
| Cisco Secure Email Gateway (`cisco-sma`) | **Cisco Secure Email Gateway (ESA)** (`cisco-esa`); die Management-Appliance (SMA) ist jetzt **Cisco Secure Email and Web Manager** (`cisco-sewm`) |

Beim Update zieht alles mit um: gefolgte Produkte mit ihren Versionen, Notizen und Tags, die Zuordnung zu Teams mit
den gewählten Personen, die Befunde mit ihrem „schon gemeldet“, Gelesen-Markierungen, Stummschaltungen, beobachtete
CVEs und gespeicherte Ansichten. Wer beiden Einträgen gefolgt ist, hat danach einen – mit den Versionen beider (eine
Version, die beide hatten, einmal). Alte Links (`/vendor?product=db2`) öffnen das neue Produkt; der alte Name findet
es in der Katalogsuche weiter.

### Windows-Server-Rollen {#windows-rollen}

WSUS, AD DS (Domain Controller), Remote Desktop Services/RD Gateway, NPS, RRAS, DHCP, DNS, AD FS und AD CS sind eigene
Einträge, haben aber keine eigene Version: eingetragen wird der **Build des Servers** mit der Rolle (`winver` oder
`[Environment]::OSVersion`, z. B. `10.0.20348.2762`). Sie teilen die CPEs von Windows Server; gezeigt werden nur die
CVEs, deren Beschreibung die Rolle nennt (beim Domain Controller auch Kerberos, Netlogon und LDAP). Geschlossen werden
sie mit dem kumulativen Windows-Update – deshalb zusätzlich **Microsoft Windows Server** folgen.

### Wo steht die Version? {#wo-steht-die-version}

Das Formular „Neue Version eintragen“ hilft beim Finden:

- **„So findest du die Version:“** – ein Befehl mit Kopieren-Knopf, z. B. `show version`. Stammt der Befehl von
  endoflife.date, steht dabei „laut endoflife.date – vor dem Ausführen lesen“.
- **„Wo steht die Version?“** – ein Text für Produkte ohne einfachen Befehl, z. B. bei Veeam Backup & Replication:
  Konsole → Hauptmenü → Help → About.
- Hinweise zum Produkt, z. B. für Windows: `winver` oder `[Environment]::OSVersion` zeigt den Build.

Produkte, die die NVD nur je Gerätemodell kennt (DrayTek, Zyxel, Teltonika, mGuard, RUGGEDCOM, StoreOnce …), nennen
die verbreiteten Modelle; Drucker und Multifunktionsgeräte (HP, Canon, Kyocera, Konica Minolta) und Produkte ohne CPE
(z. B. Matrix42 Empirum, Aagon ACMP, Swyx, d.velop, ELO, ESET PROTECT, iRMC, iLO 7, iDRAC10) haben einen Hinweis
dazu: dort erscheinen News und die CVEs, deren Herstellerdaten das Produkt nennen – eine Version wird nicht
verglichen.

**Suchnamen:** die Katalogsuche findet Produkte auch unter alten und kurzen Namen – VBR, SCCM/MECM/ConfigMgr, Lync,
M365 Apps/Office 365, MDE, SEP, OfficeScan, KES, ConnectWise Control, Check_MK, NSX-T, vROps, VCF, XenApp/XenDesktop,
Domain Controller, WS2022, SRX, IronPort, Bomgar, AirWatch, vManage …

### VMware vSphere: vCenter Server und ESXi {#vmware-vsphere}

„VMware vSphere“ sind im Katalog zwei Produkte – die Suche nach „vSphere“ findet beide:

- **VMware vCenter Server** für das vCenter (die Appliance, VCSA). Die Version steht in der VAMI unter
  `https://<vcenter>:5480` → **Übersicht** oder im vSphere Client unter Hilfe → Info zu VMware vSphere.
- **VMware ESXi** für die Hosts. Die Version zeigt `vmware -v` auf dem Host (`VMware ESXi 8.0.3 build-24022510`) oder der
  Host Client unter Hilfe → Info.

Eingetragen werden kann die Version so, wie sie dort steht:

| Eingabe | Beispiel | gespeichert als |
|---|---|---|
| Release | `8.0 U3d`, `8.0 Update 3d`, `8.0c` (Patch der GA-Version), `8.0` (GA) | wie eingegeben |
| vierteilige vCenter-Version (VAMI) | `8.0.3.00400` | `8.0 U3d` |
| Build, allein oder mit Version | `24322831`, `build-24022510`, `8.0.3-24022510`, `VMware ESXi 8.0.3 build-24022510` | `8.0 U3d` bzw. `8.0 U3` |

Das Formular zeigt vor dem Speichern, welcher Release es ist („→ 8.0 U3d“). Vierteilige Versionen und Builds werden in
Broadcoms Tabellen nachgeschlagen (KB 326316 für vCenter, KB 316595 für ESXi) – vCenter und ESXi haben eigene
Build-Nummern, ein ESXi-Build beim vCenter wird nicht erkannt. Ein unbekannter Build wird abgelehnt statt geraten:
dann den Release wie `8.0 U3d` eintragen. `vmware -l` nennt den Patch-Buchstaben nicht (`8.0 Update 3` auch bei 3e) –
besser den Build aus `vmware -v` nehmen. Ab vSphere 9 ist die vierteilige Version selbst der Release (`9.0.2.0100`).

Hinweise nennen die Releases, mit denen verglichen wird: `8.0 U3c` < `8.0 U3d`, und die Patches der GA-Version liegen
davor (`8.0` < `8.0a` < `8.0c` < `8.0 U1`). Fehlt ein Produkt aus der vSphere-Familie, lässt es sich
[vorschlagen](#produkt-vorschlagen).

## Versionen prüfen {#versionen-pruefen}

Cobe News fragt nie ein System ab – die Versionen tragt ihr von Hand ein. Mit der Zeit veralten sie, und dann ist
„betroffen“ oder „nicht betroffen“ unsicher. Darum merkt sich jede eingetragene Version, **wann jemand zuletzt gesagt
hat, dass sie noch so läuft**, und wer:

- **Eintragen oder Ändern** einer Version bestätigt sie.
- **„Bestätigen“** („läuft noch so“) bestätigt sie, ohne etwas zu ändern. Nichts wird neu bewertet, die
  [Dringlichkeit](#dringlichkeit) bleibt, wie sie ist.
- **„Alle bestätigen“** bestätigt alle fälligen Versionen eines Produkts oder eines Teams auf einmal – nach einer
  Rückfrage. Vorher wirklich nachsehen: Eine falsche Version macht die Bewertung unzuverlässig.

Ist eine Version länger als die eingestellte Frist nicht bestätigt (Standard 90 Tage), steht an ihr **„Bitte prüfen“** –
auf der Karte, in der Liste, im Reiter „Versionen“ der Schublade („seit 120 Tagen nicht bestätigt“) und bei den
Schwachstellen, deren Bewertung an dieser Version hängt („Version prüfen“). Unter **Filter** steht der Schalter
**„Versionen zu prüfen“** mit ihrer Zahl; eingeschaltet zeigt er sie über der Übersicht – nach Team gruppiert, jede mit
„Bestätigen“.

**Nicht mehr gültige Einträge:** Passt eine eingetragene Version nach einem Update des Katalogs nicht mehr zum
Produkt – sie gehört zu einem [getrennten Produkt](#getrennte-produkte), eine Tabelle kennt sie nicht, sie ist
[unplausibel](#plausibilitaet) –, steht sie ebenfalls auf „Bitte prüfen“, egal wie alt die Bestätigung ist, mit dem
Grund an der Karte („Eintrag passt nicht mehr – bitte korrigieren“). Sie wird weiter geprüft, aber nur als
„möglicherweise betroffen“; „Bestätigen“ ändert daran nichts, nur Korrigieren. Ein Eintrag aus der Zeit vor einer
Tabelle, den sie übersetzen kann (`2019 CU15` bei Exchange), wird gleich richtig verglichen – die Karte zeigt
„gewertet als 15.2.1748“.

**Wer zuständig ist:** Ist *Teams* eingeschaltet und gehört ein Produkt zu Teams, sehen und bestätigen dessen
Teammitglieder seine Versionen. Für alle anderen Produkte – und für alle, solange Teams aus ist – sind die Admins
zuständig. Admins können jede Version bestätigen; Leser ohne Team sehen die Hinweise, bestätigen aber nichts.

**Erinnerung per Mail:** Wer den [Wochenrückblick](/docs/benachrichtigungen#wochenrueckblick) seines Teams bekommt,
findet darin den Abschnitt „Versionen zu prüfen“ – höchstens einmal pro Woche, gesammelt, ohne eigene Einstellung.

> [!NOTE]
> Admins stellen die Frist unter *Einstellungen › Integrationen › Vendor News* ein: 30, 60, 90, 180 oder 365 Tage
> oder aus. Nach dem Update auf diese Version gilt für schon eingetragene Versionen ihr letzter Änderungszeitpunkt als
> Bestätigung – fällig sind nur die, die seit über der Frist niemand angefasst hat.

## Zielversion, Update und Support-Ende {#zielversion}

Für jede eingetragene Version rechnet Vendor News aus, was zu tun ist:

- **Zielversion** – die kleinste Version **eurer** Release-Linie, die die meisten der Lücken schließt, die diese
  Version betreffen. Jeder Kandidat wird mit denselben Daten geprüft wie eure Version (Hotfix-Stände, Builds). Die
  Karte zeigt dann „Update auf … behebt alle 3 Lücken“ oder „Update auf … behebt 2 von 3“.
- Gibt es in eurer Linie keinen Fix, steht „Neuere Linie nötig: …“. Gibt es noch gar keinen, steht „Noch kein Fix
  für …“.
- Ist die Zielversion selbst von einer anderen Lücke betroffen, steht das dabei.

**Update verfügbar** heißt: In eurer Release-Linie gibt es einen neueren Patch (laut endoflife.date) – ein Update
innerhalb der Linie, kein Linienwechsel. „Aktuell“ heißt: ihr habt den neuesten Patch der Linie.

**Support-Ende** ([EOL](term:eol)) kommt von endoflife.date:

| Anzeige | Bedeutung |
|---|---|
| „Support bis …“ / „Unterstützt“ | Support läuft noch mindestens 6 Monate |
| „Support endet bald“ | Ende in weniger als 6 Monaten |
| „Kein Support mehr seit …“ / „Kein Support“ | EOL erreicht, keine Sicherheitsupdates mehr – Wechsel der Linie planen |

Dieselbe Schwelle von 6 Monaten gilt in Karte, Schublade und Benachrichtigung.

### Vorwarnung vor dem Support-Ende {#eol-vorwarnung}

Für **jede eingetragene Version** kommt zusätzlich je eine Vorwarnung **90 Tage** und **30 Tage** vor ihrem
Support-Ende und eine, wenn der Support **abgelaufen** ist – jede Stufe pro Version genau einmal. Die Meldungen gehören
zur Art „Versionen & EOL“: Regeln mit dieser Art und die persönlichen Benachrichtigungen mit „Versionen & EOL“
bekommen sie, ein Team-Filter der Regel gilt wie sonst.

- **Datum verschoben.** Verschiebt der Hersteller das Support-Ende, zählt das neue Datum. Gemeldet wird nur, was
  dringender ist als das zuletzt Gesagte: Hieß es „noch 30 Tage“ und das Ende rückt auf in 80 Tagen, kommt keine
  zweite 90-Tage-Meldung – die 30 Tage des neuen Datums kommen, wenn es so weit ist.
- **Kein Nachholen.** Nach dem Update auf diese Version gilt nur der Stand von jetzt: Endet der Support in 20 Tagen,
  kommt eine 30-Tage-Meldung, keine 90-Tage-Meldung davor. Ein Support-Ende, das schon gemeldet wurde oder länger als
  30 Tage zurückliegt, kommt nicht noch einmal.
- Eine neu eingetragene Version beginnt wie immer still (Erstabruf).

Die Termine lassen sich auch als Kalender abonnieren: [Kalender (iCal)](/docs/benachrichtigungen#kalender-ical). Die Schublade zeigt die
**Release-Linien** des Produkts mit aktuellster Version, Erscheinungsdatum, Support-Ende und Status; „eure Linie“ ist
markiert, ältere Linien ohne Support sind eingeklappt. Eine Linie mit besonders langem Support heißt
[LTS](term:lts).

## Betroffen, möglicherweise, nicht betroffen {#bewertung}

Jede Schwachstelle wird für jede eingetragene Version einzeln bewertet. Die Schublade gruppiert danach:

| Bewertung | Wann |
|---|---|
| **Betroffen** („Betrifft eure Versionen“) | Die Quelle nennt eure Version ausdrücklich als betroffen, oder sie liegt im betroffenen Versionsbereich. Die Fix-Version steht dabei. |
| **Möglicherweise betroffen** („Daten nicht eindeutig“) | Die Daten reichen nicht für eine sichere Aussage – der Grund steht bei jeder Version. |
| **Nicht betroffen** | Nur, wenn die Daten es entscheiden: eure Version enthält den Fix, die Linie ist laut Hersteller nicht betroffen, oder eure Version ist neuer als alles, was der Hinweis nennt. |
| Betrifft das Produkt | Produkt ohne Version gefolgt. |
| Cloud-Dienst betroffen | Ein Dienst des Herstellers – er behebt es selbst; ob ihr etwas tun müsst, steht im Hinweis. |

Typische Gründe für **„möglicherweise“**:

- die eingetragene Version hat ein Format, das sich nicht vergleichen lässt, oder ist zu ungenau (`7.4` statt `7.4.8`),
- die Quelle nennt die Version ohne Hotfix- oder Update-Stand,
- der Hinweis nennt eure Release-Linie nicht,
- die NVD nennt „alle Versionen“ ohne Grenze,
- nur einzelne Hotfix-Stände sind betroffen, eurer wird nicht genannt,
- ein PAN-OS-Hinweis ohne Angabe zu Panorama,
- die Quellen widersprechen sich: laut Hersteller nicht betroffen, laut NVD im betroffenen Bereich – oder laut BSI
  „alle Versionen“ ohne Versionsangabe, laut den CVE-Daten nicht betroffen.

Jeder Grund nennt seine Quelle: „laut Hersteller“ steht nur, wo das Urteil vom Hersteller selbst kommt (sein Hinweis
oder seine Angaben im CVE-Eintrag); sonst „laut NVD“, „laut CISA (ADP)“, „laut BSI“, „laut OSV“ oder „Quelle: …“.
Ein CVE-Eintrag zählt nur als Wort des Herstellers, wenn der Hersteller ihn selbst geschrieben hat (er ist die CNA des
Eintrags). Schreibt ihn jemand anderes – etwa GitHubs Advisory-Datenbank für ein Open-Source-Projekt, VulDB, MITRE oder
HackerOne –, steht „laut GitHub (nicht der Hersteller)“, „laut VulDB (nicht der Hersteller)“ …; eine CNA, die die NVD
nur mit einer Kennung nennt, erscheint als „CNA (nicht der Hersteller)“. Solche Angaben wiegen nie schwerer als die
Analyse der NVD: sagt die NVD „betroffen“, bleibt es dabei.

Nennen mehrere Quellen dieselbe Schwachstelle, entscheidet der Hinweis des Herstellers vor der [NVD](term:nvd), die
NVD vor der CVE-Liste ([cvelistV5](term:cvelist)) und OSV zuletzt – Einzelheiten:
[Welche Quelle entscheidet](/docs/integrationen#urteil-reihenfolge). Nicht betroffene Schwachstellen sind eingeklappt
(„auch … nicht betroffene zeigen“). Im Zweifel „Hinweis öffnen“ und dort nachlesen.

### Unklare Altdaten {#unklare-altdaten}

Alte CVEs mit unklaren Daten, die mindestens ein Jahr vor dem Erscheinen eurer Release-Linie veröffentlicht wurden,
landen unter **„Unklare Altdaten“**: sie zählen nicht als „möglicherweise“, erscheinen nicht in Zahlen und
Benachrichtigungen und sind eingeklappt – nur zur Kontrolle. Aktiv ausgenutzte CVEs landen nie dort.

### Erstabruf {#erstabruf}

Manche Hinweise tragen die graue Markierung **„Erstabruf“**. Sie kamen mit dem ersten Abruf eines
[CSAF](term:csaf)-Anbieters (Siemens, Cisco, Schneider Electric, Open-Xchange), sobald ihr einem Produkt dieses Herstellers folgt.
Dieser erste Abruf reicht 90 Tage zurück; was dabei älter als 7 Tage ist, wird markiert.

- Der Hinweis **steht auf der Seite** und zählt wie jeder andere Befund (betroffen, möglicherweise …).
- Er wird **nicht verschickt** – keine Benachrichtigung, damit ein neuer Anbieter keine Flut alter Hinweise auslöst.
- Neuere Hinweise desselben Anbieters werden ganz normal gemeldet.

Wie der Abruf funktioniert: [CSAF-Anbieter](/docs/integrationen#erstabruf) (Admins).

## Aktiv ausgenutzt {#aktiv-ausgenutzt}

Eine Schwachstelle gilt als **aktiv ausgenutzt**, wenn sie im [KEV](term:kev)-Katalog der CISA steht, in der
[EUVD](term:euvd) als ausgenutzt gemeldet ist (aus den News, wenn diese Quelle eingeschaltet ist) oder der Hersteller
es in seinem Hinweis sagt. Sie trägt dann „aktiv ausgenutzt“, gilt mindestens als hoch, und bei einem KEV-Eintrag
mit Ransomware-Bezug steht „Ransomware“ dabei.

Aktiv ausgenutzte Lücken, die eure Versionen betreffen, stellen die Karte nach vorn (roter Rand, „… aktiv
ausgenutzt“) und färben die Zahl am Seitenpunkt rot – diese zuerst updaten.

**Benachrichtigung:** Die Regelart „Schwachstelle betrifft eines unserer Systeme“ meldet jede Schwachstelle **einmal
pro Produkt und Version**. Wird eine schon bekannte Schwachstelle später aktiv ausgenutzt (z. B. neu im KEV), kommt
genau einmal **„Jetzt aktiv ausgenutzt: …“**. Wird sie später **höher eingestuft** – NVD hatte sie noch nicht
bewertet („Awaiting Analysis“, gespeichert als Info) und gibt ihr Tage danach 9,8, oder der Hersteller stuft höher ein
als NVD –, kommt **„Jetzt höher eingestuft: Kritisch (vorher Info): …“** mit der neuen Schwere; eine Regel nur für
„Kritisch“ und „Hoch“ bekommt sie so auch dann, wenn die erste Meldung nicht zu ihr passte. Das geschieht nur nach oben
und je Stufe höchstens einmal; eine Regel, die beide Stufen abdeckt (etwa alle Schweregrade), bekommt so eine zweite
Nachricht zum selben Befund. Nicht verschickt wird, was beim ersten Prüfen eines neu gefolgten
Produkts oder einer neuen bzw. geänderten Version schon bekannt ist (es steht auf der Seite), und Hinweise, die älter
als 30 Tage sind – außer frisch im KEV. Regeln richten Admins ein, siehe
[Benachrichtigungen](/docs/benachrichtigungen#regeln).

## Änderungen an Advisories {#aenderungen}

Hersteller ändern Advisories oft nachträglich: eine neue Fix-Version, eine andere Schwere, ein größerer betroffener
Bereich, ein zurückgezogenes Advisory, eine Aufnahme in den [KEV](term:kev). Vendor News merkt sich, was ein Advisory
zuletzt gesagt hat, und legt bei jeder **inhaltlichen** Änderung eine neue [Revision](term:revision) an – zum Beispiel
„Revision 3: Neue Fix-Version 11.1.6, Schwere von Hoch auf Kritisch“.

**Was zählt:**

- Fix-Versionen (neu oder entfernt)
- betroffene Bereiche und Produkte (erweitert oder verkleinert)
- Schwere und [CVSS](term:cvss)
- weitere oder entfernte CVEs
- Aufnahme in den KEV
- zurückgezogen (die Quelle hat das Advisory zurückgenommen)

**Was nicht zählt:** Leerzeichen, Groß-/Kleinschreibung, Reihenfolge, Zeitstempel, ein anders formulierter
Beschreibungstext und die Versionsnummer des Dokuments allein. Fehlt einer Quelle ein Wert plötzlich (kein CVSS mehr,
keine Fix-Version), ist das eine Lücke der Quelle und keine Änderung – der letzte bekannte Wert bleibt.

**Kein Rauschen:** Beim ersten Speichern eines Advisorys und beim ersten Abruf einer Quelle gibt es nichts zu
vergleichen. Ändert ein Update von Cobe News, wie eine Quelle gelesen wird, wird der Stand still neu gesetzt. Ändert eine
Quelle fast alle bekannten Advisories auf einmal, gilt das als Umformatierung und wird ebenfalls still übernommen.

**Wirkung auf eure Versionen:** Ändert sich durch die Revision die Bewertung einer eingetragenen Version – etwa „nicht
betroffen“ → „betroffen“ oder es gibt jetzt eine Fix-Version –, steht das ganz oben und rot. Die Bewertung ist die der
geänderten Quelle; die Befundliste zeigt weiter die Gesamtbewertung aller Quellen.

**Wo du es siehst:**

- Am Befund steht **„Geändert“** mit Datum, wenn sich das Advisory in den letzten 30 Tagen geändert hat. Der Tooltip
  zeigt, was sich geändert hat.
- Im Produkt gibt es den Reiter **Änderungen** mit allen Revisionen, neueste zuerst.
- Die Kachel eines Produkts zeigt „Geändert“, rot, wenn eine Änderung eure Versionen betrifft.
- Bei einer Meldung mit Details aus der Quelle steht unter „Änderungen“, wie sich das Advisory dahinter verändert hat.

Pro Advisory bleiben die letzten 20 Revisionen, höchstens ein Jahr lang. **Benachrichtigung:** mit der Regelart
„Advisory geändert“ ([Regeln](/docs/benachrichtigungen#regel-arten)). Bestehende Regeln bekommen sie nicht automatisch.

## EPSS und SSVC {#epss-ssvc}

Neben der Schwere und dem [CVSS](term:cvss)-Wert zeigen Befunde zwei Hinweise darauf, **wie dringend** eine Lücke ist.
Sie ergänzen „aktiv ausgenutzt“ – sie ersetzen es nicht.

### EPSS {#epss}

[EPSS](term:epss) ist die Wahrscheinlichkeit, dass eine Schwachstelle in den **nächsten 30 Tagen** ausgenutzt wird.
FIRST berechnet sie täglich für jede CVE. Der Befund zeigt sie als Prozentwert, z. B. **„EPSS 0,4 %“** oder
**„EPSS 97 %“**. Hat ein Befund mehrere CVEs, steht der höchste Wert da.

Beim Darüberfahren steht mehr, z. B. „EPSS 97 % für CVE-2026-1234 (Perzentil 99,9), Stand …“:

- **Prozentwert:** die geschätzte Wahrscheinlichkeit einer Ausnutzung.
- **Perzentil:** wie viele CVEs niedriger liegen – 99 heißt: höher als 99 % aller CVEs.
- **Stand:** der Tag, an dem FIRST den Wert berechnet hat.

| Farbe | EPSS | Lesart |
|---|---|---|
| rot | ab 50 % | sehr wahrscheinlich ausgenutzt – sofort handeln |
| orange | ab 10 % | deutlich erhöht – bald patchen |
| gelb | ab 1 % | erhöht |
| grau | unter 1 % | die große Mehrheit der CVEs |

Gut zu wissen:

- EPSS ist eine **Vorhersage**, keine Beobachtung. Eine Lücke im [KEV](term:kev)-Katalog wird bereits ausgenutzt –
  „aktiv ausgenutzt“ zählt immer mehr als ein EPSS-Wert.
- Ein niedriger Wert heißt nicht „harmlos“: Neue CVEs haben oft erst nach einigen Tagen einen aussagekräftigen Wert.
- Fehlt die Angabe, kennt FIRST die CVE noch nicht oder ein Admin hat EPSS abgeschaltet.
- Auch in den Details einer Meldung steht bei jeder CVE ihr EPSS-Wert
  ([Details aus der Quelle](/docs/news-quellen#details-aus-der-quelle)).

### SSVC {#ssvc}

[SSVC](term:ssvc) ist die Einstufung der US-Behörde CISA zu einer CVE (aus der CVE-Liste cvelistV5). Cobe News zeigt
sie nur, wenn sie mehr sagt als „nichts bekannt“:

| Anzeige | Bedeutung |
|---|---|
| **„SSVC: aktiv ausgenutzt“** (rot) | Die CISA weiß von Angriffen, die die Lücke ausnutzen. |
| **„SSVC: Exploit-Code öffentlich“** (orange) | Es gibt öffentlich Code oder eine Anleitung zum Ausnutzen – Angriffe sind jederzeit möglich. |
| Zusatz **„· automatisierbar“** | Ein Angreifer kann die Ausnutzung automatisieren, etwa für Massen-Scans im Internet. Das erhöht die Dringlichkeit deutlich. |

Steht schon „SSVC: aktiv ausgenutzt“ da, fehlt die eigene Markierung „aktiv ausgenutzt“ (dieselbe Aussage); ein
KEV-Eintrag wird trotzdem als **KEV** gezeigt.

### Öffentlicher Exploit {#oeffentlicher-exploit}

**„Exploit-Code öffentlich“** (orange) heißt: Eine öffentliche Sammlung führt Code, der die Lücke ausnutzt, oder eine fertige
Prüfung, die sie ausnutzt. Daneben steht je Sammlung ein Link zu ihrem Eintrag:

| Sammlung | Was sie führt |
|---|---|
| **Metasploit** | ein Exploit-Modul des Metasploit Framework (nur Module vom Typ „exploit“, keine reinen Scanner) |
| **Exploit-DB** | einen Eintrag in der Exploit-Datenbank von OffSec (Proof of Concept, Exploit-Code) |
| **nuclei** | eine Vorlage der nuclei-templates von ProjectDiscovery – eine fertige Prüfung, die die Lücke im Netz findet |

Gut zu wissen:

- Das ist **keine Aussage über Angriffe**: Ein öffentlicher Exploit macht Angriffe leicht, „aktiv ausgenutzt“ heißt,
  sie finden statt. Steht beides da, zählt „aktiv ausgenutzt“ (auch in der [Dringlichkeit](#dringlichkeit-formel)).
- Cobe News speichert nur die CVE, die Sammlung, den Link und wann es den Eintrag zuerst gesehen hat – **nie den Code**.
- Die Sammlungen werden höchstens einmal am Tag geladen; ein neuer Eintrag erscheint also spätestens am nächsten Tag.
  Welche Sammlungen geladen werden, legt ein Admin fest
  ([Exploit-Hinweise](/docs/integrationen#exploit-hinweise)) – ab Werk Metasploit und nuclei, Exploit-DB nicht.
- Fehlt der Hinweis, heißt das nur: Keine der eingeschalteten Sammlungen führt die CVE. Exploits kursieren auch
  anderswo.
- Derselbe Hinweis steht in den Details einer Meldung bei ihren CVEs und in der Liste der
  [beobachteten CVEs](/docs/benachrichtigungen#cves-liste); taucht für eine beobachtete CVE ein Exploit auf, kommt
  einmal die Meldung **„Exploit veröffentlicht“** ([Wann eine Meldung kommt](/docs/benachrichtigungen#cves-meldungen)).

### Nach EPSS sortieren {#nach-epss-sortieren}

In der Schublade eines Produkts, Reiter „Schwachstellen“, steht bei mehr als einer Schwachstelle die Auswahl
**„Sortierung“**:

- **„Relevanz“** (Standard) – betroffen vor möglicherweise, aktiv ausgenutzt zuerst, dann nach CVSS.
- **„EPSS – Ausnutzung am wahrscheinlichsten“** – innerhalb jeder Gruppe (betroffen, möglicherweise …) die Lücke mit
  dem höchsten EPSS-Wert zuerst; Befunde ohne Wert stehen am Ende.

Die Gruppen selbst bleiben in derselben Reihenfolge – eine Lücke, die euch betrifft, steht nie unter einer, die euch
nur möglicherweise betrifft.

## Dringlichkeit {#dringlichkeit}

Jeder Befund bekommt eine **Zahl von 0 bis 100**: Wie dringend ist diese Lücke *für eure Version*? Die Zahl steht mit
ihrer **Stufe** da, z. B. **„77 · Sofort“**. Beim Darüberfahren zeigt sie, wie sie zustande kommt – etwa „CVSS 9,8
(Kritisch) +35, KEV +30, eure Version betroffen +25, seit 3 Tagen bekannt +10“.

| Stufe | Zahl | Farbe | Lesart |
|---|---|---|---|
| **Sofort** | ab 60 | rot | heute handeln |
| **Bald** | 35 bis 59 | orange | im nächsten Wartungsfenster |
| **Beobachten** | unter 35 | grau | im Blick behalten |

Die Zahl ersetzt nichts: Die Bewertung (betroffen, möglicherweise …), „aktiv ausgenutzt“ und die Zielversion bleiben,
wie sie sind. Sie fasst sie nur zu **einer** Reihenfolge zusammen.

### So wird gerechnet {#dringlichkeit-formel}

Kein Modell, kein Lernen – feste Punkte, zusammengezählt und auf 0 bis 100 begrenzt:

| Faktor | Punkte |
|---|---|
| Schwere aus dem [CVSS](term:cvss)-Wert (ohne CVSS: die angegebene Schwere) | kritisch (ab 9,0) +35 · hoch (ab 7,0) +25 · mittel (ab 4,0) +12 · niedrig +4 |
| [EPSS](term:epss)-Perzentil | ab 95 % +20 · ab 80 % +10 · ab 50 % +5 |
| Im [KEV](term:kev)-Katalog | +30 |
| Sonst bekannt als ausgenutzt (Hersteller, [EUVD](term:euvd)) | +25 |
| [Öffentlicher Exploit](#oeffentlicher-exploit) (Metasploit, Exploit-DB, nuclei) – nur, wenn die Lücke nicht schon als ausgenutzt bekannt ist | +10 |
| Eure Version | betroffen +25 · möglicherweise betroffen oder ohne Version +5 · Cloud-Dienst 0 · unklare Altdaten −50 · nicht betroffen −70 |
| Kein Fix bekannt (bei betroffen oder möglicherweise) | +5 |
| Alter | in den letzten 7 Tagen veröffentlicht +10 · in den letzten 30 Tagen +5 |

Gut zu wissen:

- **„Nicht betroffen“ drückt stark:** Auch eine kritische, ausgenutzte Lücke mit hohem EPSS bleibt für eine nicht
  betroffene Version unter 35 – also bei *Beobachten*.
- Hat ein Befund **mehrere eurer Versionen**, zählt die dringendste; der Tooltip nennt sie.
- **Kritisch und betroffen** ergibt mindestens 60 (*Sofort*), **hoch und betroffen** 50 (*Bald*) – passend zur roten
  bzw. orangen Karte der Übersicht.
- **Öffentlicher Exploit +10** liegt bewusst zwischen „nichts bekannt“ (0) und „ausgenutzt“ (+25/+30) – wie bei
  [SSVC](term:ssvc) „Exploit-Code öffentlich“ zwischen „keine“ und „aktiv“. Ist die Lücke schon als ausgenutzt bekannt,
  zählt nur das; beides zusammen gibt es nicht. So wird **hoch und betroffen** mit öffentlichem Exploit 60 (*Sofort*)
  statt 50 – Befunde ohne Exploit behalten ihre Zahl.
- Die Zahl rechnet der Server aus den Daten, die Cobe News ohnehin hat – keine zusätzliche Abfrage. Das Alter rückt
  täglich weiter, deshalb kann eine Zahl über Nacht sinken.

### Wo sie steht {#dringlichkeit-anzeige}

- **Karte eines Produkts:** die Zahl seines dringendsten Befunds, oben rechts.
- **Liste:** die Spalte *Dringlichkeit* – ein Klick sortiert danach (die dringendsten zuerst).
- **Statuszeile über der Übersicht:** im Feld „Handlungsbedarf“ „· N Sofort“ – wie viele der Produkte mit
  Handlungsbedarf einen Befund mit „Sofort“ haben.
- **Reihenfolge der Karten:** wie bisher nach Handlungsbedarf (ausgenutzt → kritisch → betroffen …); innerhalb einer
  Gruppe steht die höhere Zahl zuerst.
- **Schublade eines Produkts:** an jedem Befund; unter *Sortierung* sortiert **„Dringlichkeit – die dringendsten
  zuerst“** innerhalb jeder Gruppe danach.

## Gelesen, stumm und Ansichten {#vendor-lesen}

Auch in Vendor News merkt sich Cobe News **pro Person**, was du gesehen hast – Einheit ist der **Befund**: eine
Schwachstelle eines gefolgten Produkts (dieselbe CVE bei zwei Produkten sind zwei Befunde, denn du prüfst sie je
Produkt).

- **Neu** ist ein Befund, der als Neuigkeit gemeldet wurde – oder erneut, z. B. weil er jetzt aktiv ausgenutzt oder höher eingestuft wird – und
  den du seitdem nicht geöffnet hast. Was beim ersten Abruf eines Produkts schon da war ([Erstabruf](#erstabruf)), ist
  nicht neu; was vor mehr als 30 Tagen kam, zählt als gelesen.
- Die Kachel zeigt „3 neu“, die Zeilen der schlimmsten Befunde einen Punkt. **Öffnen** der Schublade markiert die Befunde
  des Produkts als gelesen; dort tragen die zuvor ungelesenen bis zum Schließen „Neu“. Am Befund setzt „Als ungelesen
  markieren“ ihn zurück.
- **Nur ungelesene** (unter *Filter*, mit der Zahl der ungelesenen Befunde) zeigt nur Produkte mit neuen Befunden.
  **„Alle N als gelesen“** neben den Filter-Chips markiert die ungelesenen Befunde genau der angezeigten Produkte – N
  ist ihre Zahl (die eines stummgeschalteten Produkts nur mit „Stummgeschaltete zeigen“). Es erscheint, sobald N
  größer als 0 ist.
- Das Menü **⋯** der Kachel: „Alle Befunde als gelesen markieren“ und das Produkt
  [stummschalten](/docs/benachrichtigungen#stummschalten). Am Befund schaltet „Stummschalten“ seine CVEs stumm.
- Stummgeschaltete Produkte fehlen, bis du unter *Filter* **Stummgeschaltete zeigen** einschaltest (dann blass mit „Stumm bis …“).
  **Ausnahme:** Betrifft ein aktiv ausgenutzter Befund das Produkt, bleibt die Kachel sichtbar und trägt
  „KEV trotz Stumm“ – eine Benachrichtigung dazu bekommst du trotzdem nicht.
- Status, Suche und Filter stehen in der Adresse – als [Ansicht](/docs/erste-schritte#ansichten) speicher- und
  teilbar. **Ansicht: …** in der Werkzeugzeile nennt die gewählte („Standard“ ohne Filter, „Angepasst“ bei Filtern, die
  keine gespeicherte Ansicht sind). Ältere Links und Ansichten gelten weiter: „Sofort“, „aktiv ausgenutzt“ und „Support
  endet / beendet“ der früheren Zusammenfassung erscheinen als Chip, `?tab=catalog` und `?tab=suggestions` öffnen
  Katalog und Vorschläge.

## Treffer bestätigen {#treffer-bestaetigen}

Manche Treffer betreffen die eigene Installation nicht, obwohl die Version im betroffenen Bereich liegt – etwa ein
PAN-OS-Advisory, das nur zählt, wenn eine bestimmte Funktion (z. B. Brotli) eingeschaltet ist. Dafür gibt es am Befund in
der Schublade **Bestätigen …**: eine Bewertung für **alle**, mit Begründung.

- **Bewertungen:** *Nicht betroffen* (Funktion oder Konfiguration nicht im Einsatz), *Maßnahme umgesetzt* (Workaround
  oder Gegenmaßnahme) und *Risiko akzeptiert* – diese nur mit Begründung. Die Begründung ist kurz (bis 500 Zeichen).
- **Wirkung:** Ein bestätigter Treffer zählt als erledigt – nicht in den Zahlen der Kachel, ihrem Zustand, der Zahl an
  „Vendor News“, den ungelesenen, dem [Wochenrückblick](/docs/benachrichtigungen#wochenrueckblick) und den Zahlen der
  [API](/docs/api) – und meldet sich nicht mehr: weder über die Regeln noch über die persönlichen Wege, auch keine
  Änderung an einem seiner Einträge (Herstellerhinweis, NVD, cvelistV5, OSV). Was in der Zeit entsteht, kommt auch
  später nicht nach, wenn jemand die Bestätigung aufhebt. Eine CVE, die du selbst
  [beobachtest](/docs/benachrichtigungen#cves-liste), meldet sich bei dir weiter – das ist deine eigene Wahl.
- **Sichtbar bleibt er:** in der Schublade blass mit „Bestätigt · Nicht betroffen“, wer, wann und warum stehen darunter
  und beim Darüberfahren. Die Kachel nennt „2 bestätigt“; unter *Filter* zeigt **Bestätigte zeigen** (Chip „Mit
  Bestätigten“) sie auch in den Zeilen der Kachel.
- **Von selbst aufgehoben** wird die Bestätigung, wenn sich der Treffer wesentlich ändert: jetzt aktiv ausgenutzt,
  höher eingestuft, neue CVEs, eine eingetragene Version jetzt (sicherer) betroffen – auch eine später eingetragene –
  oder das Advisory zurückgezogen. Dann zählt und meldet er sich wieder; die Meldung sagt „Bestätigung aufgehoben: jetzt
  ausgenutzt“, die Schublade ebenso. Was in den 24 Stunden davor entstand (etwa die Advisory-Änderung, die es
  auslöste), geht dann doch noch hinaus – bei einer Bestätigung, die jünger als 24 Stunden ist, also alles, was sie
  zurückhielt. Eine neue Fix-Version allein hebt sie nicht auf.
- **Wer darf:** Admins immer, bei eingeschalteten Teams auch die Mitglieder eines Teams, dem das Produkt zugeordnet ist
  (dieselben, die seine [Versionen prüfen](#versionen-pruefen)). Alle anderen sehen die Bestätigung nur.
  **Bestätigung aufheben** macht sie rückgängig. Bestätigen, Aufheben und das Aufheben von selbst stehen im Protokoll.

**Bestätigen oder stummschalten?** [Stummschalten](/docs/benachrichtigungen#stummschalten) ist deins und auf Zeit: nur
deine Meldungen und Zahlen, bis zu einem Datum. Bestätigen gilt für alle und bleibt, bis jemand es aufhebt oder der
Treffer sich ändert – es ist die Bewertung der Installation.

## Mein Team {#mein-team}

Hat ein Admin *Teams* eingeschaltet und gehörst du zu einem Team, steht unter **Filter** die Wahl
**Mein Team | Alle**; „Mein Team“ zeigt sich dann als Chip unter der Werkzeugzeile (× schaltet auf *Alle*):

- **Mein Team** zeigt nur die Produkte, die du über deine Teams bekommst: die Produkte eines Teams mit „Alle im Team“
  und die, bei denen ein Admin dich persönlich ausgewählt hat. Dieselbe Auswahl entscheidet über die
  [Hersteller-News meiner Produkte](/docs/benachrichtigungen#meine-produkte).
- **Alle** zeigt alle gefolgten Produkte.

Deine Wahl merkt sich dieser Browser für dich. Zuerst steht er auf *Mein Team*. Ist deinem Team noch kein Produkt
zugeordnet, ist die Liste leer – mit *Alle zeigen* geht es zurück. Die Zahl an „Vendor News“ in der Seitenleiste zählt
deine ungelesenen Befunde in derselben Wahl; ihre Farbe (oder ein Punkt, wenn nichts ungelesen ist) zeigt, ob ein
gefolgtes Produkt betroffen ist (rot: aktiv ausgenutzt).

## Produkte außerhalb des Katalogs {#eigene-produkte}

Fehlt ein Produkt im Katalog, kann ein Admin es über seine [CPE](term:cpe) hinzufügen:

1. Im Katalog (⋯ → „Produkt hinzufügen“) auf **„Nicht im Katalog?“** klicken – „Produkt per CPE hinzufügen“ öffnet sich.
2. Unter „Im CPE-Verzeichnis suchen“ Hersteller oder Produkt eingeben (mindestens 3 Zeichen). Die Suche fragt das
   CPE-Verzeichnis der NVD – höchstens alle 7 Sekunden, Ergebnisse werden eine Stunde gemerkt.
3. Einen Treffer übernehmen oder die CPE selbst eintragen, Form `Teil:Hersteller:Produkt`, z. B.
   `a:zyxel:usg_flex_100_firmware`.
4. **Anzeigename** und **Kategorie** wählen, „Hinzufügen und folgen“.

Der Eintrag trägt „Eigener Eintrag“ und verhält sich wie ein Katalogprodukt mit CVEs aus der NVD – ohne
Hersteller-Hinweise und ohne Release-Daten. Findet die Suche nichts: anders schreiben oder nur den Hersteller suchen.

## Produkt vorschlagen {#produkt-vorschlagen}

Fehlt ein Produkt, das ihr einsetzt, kann jeder Angemeldete es vorschlagen: **⋯ → Produkt vorschlagen**, **„Produkt
fehlt? Vorschlagen“** im Katalog (auch wenn die Suche nichts findet) und unter der Übersicht.

1. **Hersteller** und **Produkt** eintragen. Darunter erscheinen ähnliche Produkte aus dem Katalog („Meinst du …?“) –
   ein Klick öffnet sie. Passt keins, weiter.
2. Optional die **Website oder Advisory-Seite** (nur `http`/`https`; Cobe News ruft sie nicht ab) und die
   [CPE](term:cpe), falls bekannt.
3. **Warum** – wo es läuft, wofür ihr es braucht. Optional ein **Team**.
4. „Vorschlagen“.

Höchstens 10 Vorschläge pro Tag und Person. Den Stand siehst du unter **⋯ → Meine Vorschläge**: offen, übernommen,
abgelehnt (mit Begründung) oder doppelt (mit dem vorhandenen Produkt). Eine neue Antwort zeigt einen Punkt am ⋯ und
eine Zahl am Eintrag.
Die Vorschläge anderer sieht nur ein Admin.

### Vorschläge beantworten {#vorschlaege-beantworten .admin}

Admins öffnen die Vorschläge mit dem Knopf **„Vorschläge“** neben dem Titel (er erscheint mit der Zahl, solange
welche offen sind) oder über **⋯ → Vorschläge** – dort die offenen und die beantworteten:

- **Übernehmen** – entweder *per CPE anlegen*: „Produkt per CPE hinzufügen“ öffnet sich vorausgefüllt
  ([Produkte außerhalb des Katalogs](#eigene-produkte)); ist es angelegt, gilt der Vorschlag als übernommen. Oder *in
  den mitgelieferten Katalog*: Der kuratierte Katalog liegt im Repository (`backend/app/catalog/products/`); der Dialog
  zeigt einen Eintrag zum Kopieren, „Als übernommen markieren“ beantwortet den Vorschlag.
- **Doppelt** – das vorhandene Produkt wählen.
- **Ablehnen** – mit optionaler Begründung.

Ein Vorschlag wird genau einmal beantwortet. Adressen werden nur als Text und Link gezeigt, nie vom Server abgerufen.

## Datenquellen und Abruf {#datenquellen}

| Quelle | Wofür |
|---|---|
| Palo Alto Networks ([PSIRT](term:psirt)) | PAN-OS, Panorama, GlobalProtect, Prisma, Cortex u. a.: betroffene und behobene Versionen je Linie, Hotfix-genau |
| Fortinet (PSIRT-RSS und je Hinweis die [CSAF](term:csaf)-Datei) | betroffene und nicht betroffene Bereiche je Produkt, Fix je Linie |
| Veeam (Security-KB-Feed) | betroffene Builds und Fix-Builds je Release-Linie |
| [NVD](term:nvd) | alle Produkte mit CPE: CVEs mit Versionsbereichen und den Angaben des Herstellers (Microsoft: Build-Bereiche), [CVSS](term:cvss); neue, noch nicht analysierte CVEs per Stichwortsuche der letzten 30 Tage |
| CISA [KEV](term:kev) | „aktiv ausgenutzt“ |
| endoflife.date | Release-Linien, aktuellste Version je Linie, Support-Ende |
| ENISA [EUVD](term:euvd) | „aktiv ausgenutzt“ – aus den News, wenn die Quelle eingeschaltet ist |
| CSAF-Anbieter (Siemens, Cisco, Schneider Electric, Open-Xchange) | die [CSAF](term:csaf)-Hinweise direkt vom Hersteller: betroffene Bereiche und Fix-Versionen je Produkt |
| CVE-Liste (cvelistV5) | die Angaben des Herstellers zu einer CVE und die Einstufung der CISA ([SSVC](term:ssvc)) – vor allem, solange die NVD eine CVE noch nicht analysiert hat |
| FIRST [EPSS](term:epss) | Wahrscheinlichkeit der Ausnutzung in 30 Tagen |
| [OSV](term:osv) | Fix-Versionen von Open-Source-Paketen (Tomcat, Jenkins, Django …) |
| Metasploit, Exploit-DB, nuclei-templates | „Exploit-Code öffentlich“ ([Öffentlicher Exploit](#oeffentlicher-exploit)) |

Hersteller-Hinweise werden nur geholt, wenn einem Produkt dieses Herstellers gefolgt wird. Die letzten sieben Quellen
schaltet ein Admin einzeln ab ([Weitere Quellen](/docs/integrationen#weitere-quellen)); nach außen gehen dabei nur
CVE-Nummern und öffentliche Adressen, nie eure Produkte oder Versionen.

**Abruf:** Vendor News ist ab Werk an – Anfragen gehen aber erst raus, wenn jemand einem Produkt folgt, und nur für
die gefolgten Produkte. Der Abruf läuft im Hintergrund, unabhängig von den News:

| Was | Standard | einstellbar |
|---|---|---|
| Hersteller-Hinweise und NVD („Hinweise & NVD alle“) | 6 Stunden | 1 bis 48 Stunden |
| endoflife.date und KEV („Versionen & KEV alle“) | 24 Stunden | 6 bis 168 Stunden |

Je CPE holt Vendor News zuerst die neuesten 2000 CVEs, danach nur, was die NVD seit dem letzten Abruf geändert hat.
Nach Fehlern wird mit wachsenden Pausen erneut gefragt; lehnt die NVD ab („zu viele Anfragen“), pausieren alle
NVD-Abfragen gemeinsam. Admins finden die Einstellungen unter *Einstellungen → Integrationen → Vendor News*, siehe
[Integrationen](/docs/integrationen#vendor-news).

### Citrix und NetScaler {#citrix}

Citrix (Cloud Software Group) veröffentlicht seine Security Bulletins (CTX…) nur als Webseite auf
`support.citrix.com` – ohne [CSAF](term:csaf)-Anbieter (weder in der Liste des BSI noch unter
`/.well-known/csaf/` von citrix.com, netscaler.com oder cloud.com) und ohne RSS- oder JSON-Feed (geprüft am
02.11.2026; der frühere RSS-Feed liefert nur noch die Webseite). Vendor News liest die Webseiten nicht aus.

**Citrix: über CVE-Liste und NVD.** Citrix ist CNA und trägt seine Bulletins mit betroffenen und behobenen Builds in
die CVE-Daten ein – NetScaler ADC/Gateway, Virtual Apps and Desktops, Workspace app, StoreFront und Hypervisor werden
darüber bewertet (NetScaler-Builds wie `14.1-29.72`, auch FIPS/NDcPP getrennt). Zu Citrix-Lücken bringen die
[CSAF](term:csaf)-Warnungen des BSI (WID) in den News die „Details aus der Quelle“. Den Workaround oder die Mitigation
(z. B. Sitzungen beenden nach dem Update) nennt das Bulletin – der Link steht beim Befund.

### NVD-API-Schlüssel {#nvd-api-schluessel}

Ohne Schlüssel erlaubt die NVD 5 Anfragen pro 30 Sekunden. Cobe News hält das ein – der erste Abruf vieler Produkte
dauert dann einige Minuten („Erster Abruf läuft …“). Mit Schlüssel geht es deutlich schneller.

1. Einen kostenlosen Schlüssel bei der NVD beantragen:
   [nvd.nist.gov – Request an API Key](https://nvd.nist.gov/developers/request-an-api-key).
2. Unter *Einstellungen → Integrationen → Vendor News*, Reiter „Einstellungen“, in **„NVD-API-Schlüssel
   (optional)“** eintragen und speichern.

Der Schlüssel wird verschlüsselt gespeichert und nicht wieder angezeigt („Gespeichert (verschlüsselt) – leer lassen,
um ihn zu behalten.“).

## Katalog-Pflege {#katalog-pflege .admin}

Cobe News prüft seinen Katalog selbst. *Einstellungen → Integrationen → Vendor News*, Reiter **„Katalog-Pflege“**
([direkt öffnen](/settings/integrations?vendor=care)), zeigt unter „Pflege nötig“, welche Einträge Pflege brauchen –
mit Grund, zum Beispiel „CPE … existiert nicht in der NVD“, „Seit 40 Monaten keine CVE-Daten“ oder „endoflife.date
kennt den Schlüssel … nicht mehr“. Gefolgte Produkte mit einem Problem zeigen es zusätzlich in ihrer Schublade
(„Katalogeintrag braucht Pflege“, mit „Zur Katalog-Pflege“).

| Status | Bedeutung |
|---|---|
| Fehler | Der Eintrag ist falsch – ohne Korrektur fehlen Schwachstellen oder Support-Daten. |
| Prüfen | Vermutlich veraltet – lohnt einen Blick. |
| In Ordnung | Alle Prüfungen bestanden. |
| Noch nicht geprüft | Die NVD wurde zu diesem Eintrag noch nicht gefragt. |

Der Schalter „Nur gefolgte Produkte“ beschränkt die Liste auf eure Produkte; ausgeschaltet zeigt er den ganzen
Katalog. Oben stehen „Letzte Prüfung“, die Katalogversion und wie viele CPEs schon geprüft sind.

### Was geprüft wird {#was-geprueft-wird}

| Prüfung | Ergebnis |
|---|---|
| Gibt es die CPE im CPE-Verzeichnis der NVD? | fehlt: **Fehler**; nur als veraltet geführt: Warnung mit Nachfolger |
| CVEs zur CPE in den letzten 3 Jahren? | keine oder nur ältere: Warnung (nicht bei Cloud-Diensten) |
| Kennt endoflife.date den Schlüssel noch? | unbekannt: **Fehler**; anderer Hersteller: Warnung |
| Letzter Hinweis des Herstellers (Palo Alto, Fortinet, Veeam) | älter als 2 Jahre: Warnung |
| Gefolgt, aber ohne CPE | Warnung – Schwachstellen kommen nur aus Hersteller-Hinweisen und News |

**Grenzen:** Gefragt wird nur die NVD, über dieselbe Bremse wie der Vendor-News-Abruf, und nur, wenn Vendor News an ist,
einem Produkt gefolgt wird und gerade keine Vendor-News-Runde läuft. Gefolgte Produkte werden **wöchentlich** geprüft,
der ganze Katalog **monatlich**, mit höchstens **20 Anfragen pro Stunde**, über die Stunde verteilt und auch über einen
Neustart hinweg gezählt. Der erste ganze Durchlauf dauert deshalb etwa fünf Tage. Warum die Prüfung gerade wartet, steht
unter der Liste (z. B. „Stundenbudget erreicht – es geht in der nächsten Stunde weiter.“).

**„Jetzt prüfen“** fragt die CPEs der gefolgten Produkte sofort (höchstens alle 10 Minuten, höchstens 60 Anfragen);
der übrige Katalog läuft im Hintergrund weiter. Ist Vendor News aus, ist der Knopf gesperrt.

### Einen Eintrag korrigieren {#eintrag-korrigieren}

Der Katalog ist nicht in der Oberfläche änderbar. Er besteht aus Daten-Dateien im Image
(`backend/app/catalog/`, je Kategorie eine Datei unter `products/`) und kommt mit jedem Update. Ein falscher Eintrag
wird dort korrigiert und ist mit dem **nächsten Update** von Cobe News behoben (siehe
[Update](/docs/betrieb#update)).

Wer das Image selbst baut, ändert den Eintrag in der Datei seiner Kategorie, zählt `catalog_version` in
`catalog.yaml` hoch und baut neu (`docker compose up -d --build`). Ein Fehler in den Dateien stoppt den Start mit Datei
und Produkt im Log. Bis zur Korrektur lässt sich ein Produkt mit der richtigen CPE über
[„Nicht im Katalog?“](#eigene-produkte) als eigener Eintrag folgen.

„Katalog aktualisieren“ unter *Einstellungen → Integrationen → Vendor News* baut den Katalog mit den aktuellen Daten
von endoflife.date neu auf – das ändert Release-Daten, nicht die gepflegten Einträge.

### Katalogversion {#katalogversion}

Die **Katalogversion** (Form `Jahr.Monat.Tag-Nummer`, z. B. `2026.10.29-4`) steht unten im Katalog, in der
Katalog-Pflege und auf *Version & Changelog*. Sie zählt getrennt von der App-Version und ändert sich, wenn Produkte
dazukommen oder korrigiert werden. Kommt mit einem Update ein neuer Katalog, gilt er sofort – ohne auf die nächste
Aktualisierung zu warten.
