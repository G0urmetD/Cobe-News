# Handbuch – Format der Kapitel

Die Seite **Dokumentation** in der App (Benutzermenü → *Dokumentation*, Adresse `/docs/<kapitel>#<abschnitt>`) zeigt
die Markdown-Dateien in diesem Ordner. Sie kommen mit dem Image (`Dockerfile`: `/srv/handbuch`), der Server liefert sie
über `GET /api/docs` aus (`backend/app/docs.py`) und filtert dabei, was nur Admins sehen dürfen. Gerendert wird mit
einem kleinen eigenen Renderer (`frontend/src/lib/docs-markdown.ts`) – kein HTML aus den Dateien, keine fremde Bibliothek.

## Dateien

```
docs/handbuch/de/NN-<kapitel>.md    deutsch (zuerst schreiben)
docs/handbuch/en/NN-<kapitel>.md    englisch – dieselben Dateinamen, dieselben Abschnitts-IDs in derselben Reihenfolge
```

`NN` ist die Reihenfolge in der Seitenleiste, `<kapitel>` die feste ID in der Adresse (`/docs/anmeldung`). Ein Test
(`backend/tests/test_docs.py`) prüft, dass jedes Kapitel und jeder Abschnitt in beiden Sprachen existiert, dass nur
erlaubte Links und kein HTML darin stehen und dass jede Datei unter der Größengrenze bleibt (200 KB).

## Kopf jeder Datei

```
---
title: Anmeldung & Benutzer
summary: Ein Satz, worum es geht – erscheint unter dem Titel und in der Suche.
audience: admin
---
```

`audience`: `all` (alle Angemeldeten) oder `admin` (nur Admins – der Server liefert das Kapitel anderen gar nicht aus).

## Überschriften

- `## Titel {#abschnitt-id}` – ein Abschnitt (in der Seitenleiste, Deep Link `/docs/<kapitel>#abschnitt-id`).
- `### Titel {#unter-id}` – ein Unterabschnitt (ebenfalls verlinkbar).
- `{#id .admin}` – dieser Abschnitt (bis zur nächsten Überschrift derselben oder höheren Ebene) nur für Admins.
- IDs: klein, `a-z 0-9 -`, im ganzen Kapitel eindeutig, **nie ändern** (andere Kapitel und die Hilfe-Links der
  Einstellungen zeigen darauf). Jede `##`/`###`-Überschrift braucht eine ID. `#` (H1) gibt es nicht – den Titel setzt
  der Kopf.

## Inhalt

| Schreibweise | Ergebnis |
|---|---|
| `**fett**`, `*kursiv*`, `` `code` `` | wie üblich |
| `[Text](https://example.com/…)` | Link nach außen (nur `https://`/`http://`, öffnet neu) |
| `[Text](/settings/auth)` | Link in die App |
| `[Text](/docs/anmeldung#entra-fehler)` / `[Text](#abschnitt)` | Link in die Dokumentation |
| `[Text](term:cvss)` | Fachbegriff mit Erklärung beim Darüberfahren (Liste unten) |
| `{{redirect_uri}}` | Wert dieser Installation mit Kopieren-Knopf (Liste unten) – auch in Codeblöcken |
| `- Punkt` / `1. Schritt` | Liste; eingerückt (2 Leerzeichen je Ebene) verschachtelt, Fortsetzungszeilen eingerückt |
| ```` ```bash ```` … ```` ``` ```` | Codeblock mit Kopieren-Knopf (Sprache nur als Beschriftung) |
| `\| a \| b \|` + `\|---\|---\|` | Tabelle (auf schmalen Bildschirmen als Zeilen mit Beschriftung) |
| `> [!NOTE]` / `> [!TIP]` / `> [!WARNING]` + `> Text` | Hinweis-, Tipp- bzw. Warnkasten |

Nicht erlaubt: HTML (`<b>`, `<br>` …), spitze Klammern außerhalb von `code`, Bilder, andere Link-Arten (`javascript:`,
`mailto:`, `file:`). Der Renderer zeigt so etwas als Text; der Test lehnt es ab.

**Werte dieser Installation** (`{{…}}`): `base_url` (die Adresse aus `BASE_URL`), `redirect_uri` (Entra:
`BASE_URL` + `/api/auth/oidc/callback`, nur Admins), `version`. Unbekannte Namen bleiben als Text stehen. Nie
Geheimnisse.

**Fachbegriffe** (`term:…`): `kev euvd psirt cpe cvss eol hotfix lts epss ssvc tlp osv csaf revision ical bearer scope
openapi prometheus webhook` (Glossar der App, `glossary.*`) und
`totp ldaps starttls basedn binddn oidc tenant clientid clientsecret redirecturi adminconsent groupclaim hmac webhook rss
smtp cron fqdn hsts reverseproxy cidr csaf nvd envfile vapid pkce upn conditionalaccess groupsoverage releaseline
masterkey ssrf san pfx cvelist` (Texte in `frontend/src/i18n/docs.de.ts`/`docs.en.ts`, `docs.term.*`).

## Schreibstil

- Deutsch zuerst, dann eine getreue englische Fassung. Kurze Sätze, Schritte als nummerierte Liste, Menüpfade
  *kursiv* (*Einstellungen → Anmeldung*), Knöpfe in „Anführungszeichen“ (englisch: "quotes").
- Quelle der Wahrheit sind der Code und `docs/BETRIEB.md` – nichts erfinden.
- Keine echten Hostnamen, Mandanten-IDs, Namen von Firmen oder Personen, keine lokalen Pfade eines Rechners: Beispiele
  mit `corp.example`, `example.com`, `news.corp.example`, Installationsordner `/opt/cobe-news`.
