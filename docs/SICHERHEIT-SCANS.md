# Cobe News – Befunde von Image-Scannern

Für Betreiber und Nutzer, die die Images von Cobe News (`ghcr.io/g0urmetd/cobe-news`, `…/cobe-news-db`,
`…/cobe-news-proxy`) mit einem Scanner wie Trivy, Grype oder dem Scanner ihrer Registry prüfen: was der Release
zusichert, warum trotzdem Befunde übrig bleiben und wie man selbst scannt. Betrieb und Release im Einzelnen:
[`BETRIEB.md`](BETRIEB.md#release).

## Was der Release zusichert

Seit 0.1.55 scannt die Release-Pipeline jedes der drei Images für amd64 und arm64 mit Trivy (feste Version, Archiv per
Prüfsumme geprüft) – genau die Digests, die sie danach signiert und mit der Version taggt. **Ein hoher oder kritischer
Befund, für den es eine korrigierte Version gibt, stoppt den Release**: nichts wird signiert, kein Tag, `latest` bleibt
beim vorigen Release.

Zugesichert ist damit: Zum Zeitpunkt des Builds (Stand der Schwachstellen-Datenbank steht im Bericht) enthält keines der
drei Images einen bekannten hohen oder kritischen Befund, der sich durch ein Update beheben ließe. Nicht zugesichert:
dass ein Scan gar nichts findet (siehe unten), und was nach dem Release bekannt wird – ein Scan Wochen später findet
mehr, behoben wird das mit dem nächsten Release.

Dazu trägt der Build selbst bei:

- **Sicherheits-Updates beim Bauen**: `apt-get upgrade` (App, Debian) bzw. `apk upgrade` (Datenbank und Proxy, Alpine) –
  was Debian bzw. Alpine seit dem festgeschriebenen Basis-Image korrigiert hat, ist im Image.
- **Aktuelle Basis-Images**: Die Basis-Images sind per Digest festgeschrieben (ein Build nimmt genau dieses Image); die
  Digests werden zu jedem Release auf den aktuellen Stand ihres Tags gesetzt ([`BETRIEB.md`](BETRIEB.md#entwicklung--tests),
  Basis-Images).
- **Kein pip im App-Image**: pip wird nur zum Installieren der Abhängigkeiten gebraucht und danach entfernt – mit ihm
  seine mitgelieferten Bibliotheken (urllib3, msgpack, Teile von setuptools), die Scanner sonst als veraltet melden. Die
  App selbst nutzt keine davon; ihre Python-Abhängigkeiten sind mit Prüfsumme festgeschrieben und werden vor jedem
  Release zusätzlich mit `pip-audit` geprüft.
- **Kein gosu im Datenbank-Image**: Der Wechsel vom Root-Benutzer zu `postgres` beim Start läuft über `su-exec` aus
  Alpine statt über das `gosu` des offiziellen PostgreSQL-Images (gebaut mit einer alten Go-Version, deren
  Standardbibliothek hohe und kritische CVEs hat).

Die vollständigen Berichte jedes Releases – `trivy-<image-referenz>-<plattform>.txt` (Tabelle) und `.json`, mit allen
Schweregraden, auch den Befunden ohne Korrektur – liegen als Artefakt `trivy-reports` am Workflow-Lauf des Releases
(Actions → der Lauf → Artifacts), nicht im GitHub-Release. Selbst nachprüfen geht jederzeit mit dem Skript (unten).

## Warum Befunde übrig bleiben

Stand 0.1.55 (Scan vom 9. November 2026): Datenbank- und Proxy-Image ohne Befund. Im App-Image bleiben 229 Befunde
(0 kritisch, 50 hoch, 90 mittel, 89 niedrig) – **alle ohne korrigierte Version in Debian 13 (trixie)**. Das App-Image
beruht auf `python:3.13-slim`, also auf Debian stable; dabei bleibt es (aktiv gepflegt, Sicherheits-Updates über Jahre) –
kein Wechsel auf Debian testing oder eine andere Distribution, nur um Zähler zu senken.

Die hohen Befunde, mit der Einstufung im [Debian Security Tracker](https://security-tracker.debian.org/tracker/) (Stand
9. November 2026):

| Pakete im Image | CVE | Debian (trixie) | Wird im Image genutzt? |
|---|---|---|---|
| util-linux und seine Bibliotheken: `util-linux`, `bsdutils`, `mount`, `login`, `libblkid1`, `libmount1`, `libsmartcols1`, `libuuid1`, `liblastlog2-2` | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642), [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408), [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409), [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | no-dsa (Minor issue) | Grundpakete des Systems; im Container wird nichts eingehängt, niemand meldet sich an |
| ncurses: `libncursesw6`, `libtinfo6`, `ncurses-base`, `ncurses-bin` | [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | no-dsa (Minor issue) | nur für Terminal-Ausgabe (Shell, `psql` von Hand) |
| perl: `perl`, `perl-base`, `libperl5.40`, `perl-modules-5.40` | [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | postponed (Minor issue) | nur als Aufruf-Hülle von `pg_dump`/`pg_restore`/`psql` (pg_wrapper aus `postgresql-client-common`), mit den festen Argumenten der App |
| SQLite: `libsqlite3-0` | [CVE-2026-119373](https://security-tracker.debian.org/tracker/CVE-2026-119373), [CVE-2026-119374](https://security-tracker.debian.org/tracker/CVE-2026-119374), [CVE-2026-119379](https://security-tracker.debian.org/tracker/CVE-2026-119379) | no-dsa (Minor issue), korrigiert nur in sid | nur beim einmaligen Umzug einer eigenen SQLite-Datei von 0.1.15 (BETRIEB.md: PostgreSQL) |
| systemd: `libsystemd0`, `libudev1` | [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) | no-dsa (Minor issue) | Bibliotheken für andere Pakete; im Container läuft kein systemd und kein udev |
| acl: `libacl1` | [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | no-dsa – erst in unstable, dann mit einer Zwischenversion | Bibliothek der Grundwerkzeuge (coreutils, tar); die App setzt und liest keine ACLs |

Debian stuft all diese als geringes Risiko ein und gibt dafür **keine Sicherheitsmeldung (DSA)** heraus: Die Korrektur
ist in forky/sid schon da und kommt nach trixie mit einer späteren **Zwischenversion** (Point Release). Die mittleren
und niedrigen Befunde sind von derselben Art (Grundpakete wie glibc, Kerberos-Bibliotheken, PAM, tar, bash), ebenfalls
ohne Korrektur in trixie.

Warum das vertretbar ist:

- **Grundpakete, nicht entfernbar**: Fast alle sind in Debian *essential* oder Abhängigkeiten davon – ohne sie
  funktionieren `dpkg`/`apt` und das Basis-Image nicht; sie zu entfernen wäre ein selbst gebautes, ungetestetes System.
- **Nicht mit Eingaben von außen erreichbar**: Im Container laufen genau zwei Dinge – Python (die App, uvicorn) und bei
  Sicherung, Wiederherstellung und Rücksicherungs-Test `pg_dump`/`pg_restore`/`psql`. Keine Shell nach außen, keine
  Anmeldung, kein `mount`, kein systemd. Was von außen kommt (HTTP-Anfragen, Feeds, Advisories), verarbeitet die App in
  Python, nicht mit diesen Werkzeugen.
- **Gehärteter Container**: als eigener Benutzer (UID 10001, kein Root), Dateisystem schreibgeschützt, alle Capabilities
  entzogen, `no-new-privileges` (`docker-compose.yml`, `docker-compose.portainer.yml`).
- **Sie verschwinden von selbst**: Sobald Debian die Korrektur nach trixie bringt, nimmt der nächste Build sie mit
  (`apt-get upgrade`) – und von da an würde der Release ohne sie gar nicht mehr gebaut.

Ein Scanner, der Befunde ohne Korrektur mitzählt (Trivy ohne `--ignore-unfixed`, Grype ohne `--only-fixed`), zeigt sie
weiter an; die Zahlen unterscheiden sich je nach Scanner und Datenbankstand leicht.

## Selbst scannen

**Mit dem Skript** (im Repository; prüft wie die Release-Pipeline; die geprüften Images werden nur gelesen, nie nach
Docker geholt oder getaggt, kein Compose):

```bash
scripts/scan-images.sh                 # der lokale Build: cobe-news:latest, cobe-news-db:latest, cobe-news-proxy:latest
scripts/scan-images.sh 0.1.55          # die veröffentlichten Images einer Version, direkt von ghcr.io
PLATFORMS="linux/amd64 linux/arm64" scripts/scan-images.sh ghcr.io/g0urmetd/cobe-news@sha256:<digest>
```

Ohne installiertes Trivy holt es Trivys offizielles Image (`aquasec/trivy`, dieselbe Version wie die Pipeline, per
Digest festgeschrieben) und legt für dessen Schwachstellen-Datenbank das Docker-Volume `cobe-news-trivy-cache` an.
Eine `trivy.yaml` oder `.trivyignore` im Arbeitsordner und `TRIVY_*`-Einstellungen der Umgebung wirken nicht auf die
Prüfung. Ergebnis im Ordner `trivy-reports/<Zeit>/`: `summary.md` (Zahlen je Image, Ergebnis der Prüfung), je Image der
vollständige Bericht als Tabelle (`.txt`) und JSON, benannt nach der ganzen Image-Referenz. Exit-Code 0: kein
behebbarer hoher oder kritischer Befund, 1: mindestens einer (aufgelistet), 2: falscher Aufruf, ein Scan scheiterte
oder das Image hatte nicht die verlangte Plattform.

**Direkt mit Trivy**, am besten auf den Digest, den cosign geprüft hat (dann ist es sicher das signierte Image):

```bash
v=0.1.55
d=$(cosign verify ghcr.io/g0urmetd/cobe-news:$v \
  --certificate-identity-regexp '^https://github\.com/G0urmetD/Cobe-News/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com | jq -r '.[0].critical.image."docker-manifest-digest"')
trivy image --severity HIGH,CRITICAL --ignore-unfixed ghcr.io/g0urmetd/cobe-news@$d   # die Prüfung des Releases
trivy image ghcr.io/g0urmetd/cobe-news@$d                                              # alles, auch ohne Korrektur
```

Ebenso für `cobe-news-db` und `cobe-news-proxy`. Findet ein eigener Scan einen behebbaren hohen oder kritischen Befund in
einem aktuellen Release, bitte nicht öffentlich als Issue, sondern über
[GitHub Security Advisories](https://github.com/G0urmetD/Cobe-News/security/advisories/new) melden – meist genügt dann
ein neuer Build.
