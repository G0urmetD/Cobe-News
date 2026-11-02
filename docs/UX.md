# Bedienung: Regeln für neue Masken

Kurze, konkrete Regeln, damit sich Cobe News überall gleich anfühlt. Zielgruppe: Admins und IT-Mitarbeitende, die
schnell sehen wollen, ob etwas sie betrifft – auch ohne Security-Hintergrund.

## Gesetzt oder Eingabe – nie verwechselbar

- **Was gespeichert ist, wird angezeigt, nicht als Eingabefeld.** Eingetragene Werte (Versionen, Notizen) stehen als
  Text bzw. Karte da – groß, mit Bezeichnung und Status. Bearbeiten erst auf Wunsch: Stift-Knopf (`Pencil`, `aria-label`
  „… bearbeiten“) macht genau diesen einen Eintrag zum Formular mit „Speichern“ und „Abbrechen“.
- **Neues wird in einem eigenen, beschrifteten Formular eingetragen** – optisch abgesetzt (Rahmen in Primärfarbe,
  Überschrift „Neue … eintragen“) oder hinter einem Knopf „+ … hinzufügen“, der das Formular aufklappt. Ein leeres
  Formular darf nie wie ein gespeicherter Eintrag aussehen.
- **Beschriftung über jedem Feld** (`Field` aus `components/cobe/form.tsx`), optionale Felder mit „(optional)“.
  Platzhalter nur als Beispiel: immer mit „z. B. …“ beginnen und blass (`placeholder:text-muted-foreground/60`) – ein
  Platzhalter ist nie ein Wert.
- **Prüfen beim Tippen:** unter dem Feld ein Satz – grau das erwartete Format, rot was nicht passt, grün „Format passt.“
  Der Hauptknopf bleibt gesperrt, bis alles gültig ist (und beim Bearbeiten, bis sich etwas geändert hat).
- Hilfen, die man zum Ausfüllen braucht (z. B. der Befehl, der die Version zeigt), stehen **im Formular**, mit
  Kopieren-Knopf.

## Reihenfolge nach Wichtigkeit

- Oben, was die Frage „betrifft es uns?“ beantwortet; darunter, womit man es ändert; dann Hintergrund; Nebensachen
  (Notizen, Tags) zuletzt.
- Beispiel Reiter „Versionen“: 1) installierte Versionen, 2) Version hinzufügen, 3) Release-Linien, 4) Notizen.
- **Nichts, was wächst, steht über etwas anderem.** Mehrere wachsende Bereiche: Unter-Reiter (`SubTabs`, Auswahl über
  `?view=`), nicht immer längere Seiten.
- Lange Listen mit wenig relevantem Inhalt werden gefaltet: „Ältere Linien ohne Support anzeigen (21)“ – was den
  Benutzer betrifft (seine Linie), bleibt immer sichtbar.

## Fachbegriffe erklären

- **Jeder Fachbegriff hat einen Tooltip:** `<Term k="…">` (gepunktet unterstrichen, Glossar in
  `components/cobe/glossary.tsx`: CPE, CVSS, KEV, EUVD, PSIRT, EOL, Hotfix, LTS …) oder `<Explained label text>`
  (Info-Symbol) für Überschriften und Spaltenköpfe („Release-Linie“, „Aktuellste Version“, Status-Spalten).
- Erklärungen in einfachen Worten, ein bis drei Sätze, mit Beispiel („eine Hauptversion wie 11.2 …“).
- Tooltips öffnen bei Maus **und** Tastaturfokus – nie von selbst (siehe Fokus).

## Leerzustände erklären den Nutzen

- Ein leerer Bereich sagt, **warum** es sich lohnt, etwas einzutragen – nicht nur „Keine Einträge“.
  Beispiel: „Ohne Version zeigen wir alle Schwachstellen des Produkts; mit Version prüfen wir genau …“
- Wer nichts ändern darf (reader), bekommt denselben Text plus „Ein Admin kann … eintragen.“
- Eine Liste, die nicht geladen werden konnte, zeigt nie „Noch keine …“, sondern `QueryError` mit „Erneut versuchen“.

## Status-Chips und Farben

`Pill` aus `components/cobe/badges.tsx`, Farbe über Design-Tokens (hell und dunkel):

| Farbe | Token | Bedeutung | Beispiele |
|---|---|---|---|
| Grün | `--success` | in Ordnung, nichts zu tun | „Aktuell“, „Unterstützt“, „Keine bekannte Schwachstelle“, „Nicht betroffen“ |
| Blau | `--primary` | Hinweis, Handlung möglich | „Update verfügbar → 11.2.16“, „eure Linie“ |
| Gelb/Bernstein | `--warning` | handeln / bald handeln | „betrifft euch“, „Support endet bald“ (unter 6 Monaten), „möglicherweise betroffen“ |
| Rot | `--sev-critical` | sofort handeln | „aktiv ausgenutzt“, „N kritisch“, „Kein Support mehr seit …“ |
| Grau | `--muted-foreground` | neutrale Information | „Support bis 02.05.2027“, Kategorie, Tags |

- Ein Chip sagt den Zustand in Worten, nicht nur in Farbe (Farbe allein reicht nicht – Farbsehschwäche, Ausdruck).
- Zahlen-Chips, die auf eine Liste verweisen, sind Links dorthin („3 betreffen diese Version“ → Schwachstellen).
- Kurzlisten (Kacheln) zeigen dieselben Status und dieselbe Reihenfolge wie die Detailansicht; ein Klick auf einen
  Eintrag öffnet die Schublade **bei diesem Eintrag** (markiert, hingescrollt).
- Unsichere Befunde stehen getrennt und beschriftet („Möglicherweise betroffen – Daten nicht eindeutig“, mit Tooltip
  und Grund je Version), nie vermischt mit sicheren.

### Rahmen und Akzent von Karten (Vendor News, Übersicht)

Rot ist selten, damit es auffällt – nicht jede betroffene Karte ist rot:

| Lage | Rahmen/Akzent | Beispiel |
|---|---|---|
| aktiv ausgenutzt oder kritisch – und betrifft eine Version | Rot (`--sev-critical`) | „aktiv ausgenutzt“, „2 kritisch“ |
| betroffen (oder Support beendet) | Bernstein (`--warning`) | „Update auf 4.14.6 behebt alle 31 Lücken“ |
| nur „möglicherweise“, ohne Version, Support endet bald, Cloud-Dienst | neutral (Standardrahmen) | „Keine bestätigte Lücke – 3 möglicherweise“ |
| alles in Ordnung | kompakte grüne Karte (nach den anderen, oder allein unter „Alles aktuell“) | |

- Zuerst steht, **was zu tun ist** (Zielversion aus dem Server, je Version eine Zeile, wenn sie sich unterscheiden),
  daneben nur die stärksten Signale; Zahlen und Details folgen darunter.
- Reihenfolge nach Dringlichkeit: ausgenutzt → kritisch → betroffen → möglicherweise → in Ordnung.
- Oben eine einzige Statuszeile mit vier Feldern „Handlungsbedarf 4 · 2 Sofort | Möglicherweise 2 | Aktuell 12 |
  Alle 18“ (auf dem Handy 2×2) – eine Auswahl (Radiogruppe, Pfeiltasten), je Browser gemerkt; die Zahlen zählen, was
  Suche und Filter übrig lassen. Keine zweite Zusammenfassung mit denselben Zahlen.
- Darunter eine Werkzeugzeile: Suche, „Filter“ (Popover mit Schaltern, Zahl der aktiven am Knopf), „Ansicht: …“,
  Kacheln/Liste als ein Symbolknopf. Aktive Filter als entfernbare Chips darunter, rechts „Alle N als gelesen“ für
  genau das Angezeigte. Seltene Aktionen (Katalog, Vorschlagen, Jetzt abrufen, Einstellungen) im ⋯-Menü des Kopfs.
- Zahlenspalten einer Tabelle stehen rechtsbündig mit `tabular-nums`, ihre Köpfe ebenso (Sortierpfeil vor dem Text).
- „Unklare Altdaten“ (unklare Daten, lange vor der installierten Linie veröffentlicht) zählen nirgends mit – gefaltet
  in der Schublade, mit Erklärung.

## Datum und Zeit

- Zeitpunkte mit `<Ts at>` (relativ oder Datum + Uhrzeit, Tooltip mit Ortszeit und UTC).
- Kalendertage (EOL, Erscheinungsdatum) mit `fmtDay` aus `lib/format.ts`: Deutsch **02.05.2027**, Englisch
  „2 May 2027“ – nie das ISO-Format der Quelle („2027-05-02“) anzeigen.

## Löschen und Entfernen

- Entfernen braucht eine Bestätigung (`confirmAction` aus `components/cobe/confirm.tsx`) mit einem Satz, was danach
  passiert („11.2.4-h23 (RZ Nord) wird nicht mehr geprüft …“). Der Bestätigungsknopf heißt wie die Aktion
  („Entfernen“), nicht „OK“.
- Löschen per Mülleimer-Symbol mit `aria-label`/`title` („11.2.4-h23 entfernen“), neben dem Stift.
- Nach dem Speichern oder Entfernen eine kurze Meldung (Toast), die das Objekt nennt („Version 11.2.4-h23 eingetragen“).

## Schubladen und Dialoge

- **Fokus:** Beim Öffnen bekommt die Schublade selbst den Fokus (`lib/focus.ts`, in `SheetContent` und
  `DialogContent` eingebaut) – nie das erste Element darin. Sonst öffnet sich z. B. der Tooltip eines Fachbegriffs im
  Kopf von selbst. Tab führt zum ersten Bedienelement, Escape schließt. Ein Feld, das sofort den Fokus braucht, setzt
  `autoFocus`.
- **Bestätigung „Bestätigen, dass du es bist“ immer obenauf:** Radix stapelt Schubladen und Dialoge in der Reihenfolge,
  in der sie einhängen, alle auf `z-50` – was später kommt, liegt darüber und behält Fokus und Klicks. Die Rückfrage
  (`components/cobe/reauth.tsx`) hat deshalb eine eigene Ebene (`z-[60]`/`z-[61]`) und wird neu gezeichnet, wenn danach
  noch eine Schublade oder ein Dialog einhängt (`coversPrompt` in `lib/reauth.ts`); Eingaben bleiben dabei erhalten.
  Ihr Feld bekommt den Fokus über `focusFieldOnOpen` statt `autoFocus`: In einem Dialog über einer offenen Schublade
  holt deren Fokusfalle ein `autoFocus` sofort zurück.
- Aktionen der Schublade (Folgen, Entfernen, Schließen) stehen **unten** in der Fußleiste.
- **„Testen“-Knöpfe** (Verbindung, Testmail, Testnachricht) antworten mit einem Toast – Erfolg, Warnung oder der Grund
  des Fehlers –, auch wenn darunter ein Kasten die Details zeigt. Der Knopf zeigt, dass er arbeitet; „Speichern“ wartet.
- Dialoge mit Eingaben schließen bei Klick daneben nicht ohne Rückfrage.

## Weitere Regeln

- Schalter (`Switch`/`ToggleRow`) statt Checkboxen.
- Auswahllisten: eigenes Radix-`Select` mit `position="popper"` (öffnet nach unten), kein natives `<select>`.
- Textfelder wachsen mit dem Inhalt (`Textarea`), kein Ziehgriff.
- Jeder Text in Deutsch **und** Englisch (`i18n/de.ts`/`en.ts`, Vendor News in `vendor.de.ts`/`vendor.en.ts` – ein Test
  prüft, dass beide dieselben Schlüssel haben).
- Funktioniert ab **375 px** Breite ohne waagrechtes Scrollen: Tabellen werden auf schmalen Bildschirmen zu Zeilen mit
  Beschriftung (`sm:grid` + `sm:hidden`-Labels), Knöpfe umbrechen.
- Hell und Dunkel: nur Design-Tokens (`var(--…)`, Tailwind-Farben aus dem Theme), keine festen Farbwerte.
- Ein gesperrter Knopf erklärt mit `title`, warum.
- Hinweise: ein Satz; Längeres zeigt `MoreText` als ersten Satz mit „mehr“.
