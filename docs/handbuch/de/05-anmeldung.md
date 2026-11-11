---
title: Anmeldung & Benutzer
summary: Lokale Konten, Notfall-Admin, Active Directory und Microsoft Entra ID einrichten, Gruppen Rollen zuordnen, Sitzungen und Sperren verstehen.
audience: admin
---

## Überblick {#ueberblick}

Cobe News kennt drei Arten, sich anzumelden. Sie lassen sich kombinieren – die Anmeldeseite zeigt nur, was eingeschaltet
und vollständig eingerichtet ist.

### Anmeldearten {#anmeldearten}

| Art | Wer legt das Konto an | Zweiter Faktor | Rolle kommt aus |
|---|---|---|---|
| **Lokal** | ein Admin unter *Einstellungen → Benutzer & Rollen* | [TOTP](term:totp) oder ein [Passkey](#passkeys) in Cobe News – Pflicht für Admins (TOTP), für Leser freiwillig oder [Pflicht für alle](#zweiter-faktor-alle) | der Einstellung am Konto |
| **Active Directory / LDAP** | entsteht automatisch, sobald es in einer zugeordneten Gruppe ist ([vorab geladen](#vorab-laden)) – ohne Passwort; je nach [Automatischer Anmeldung](#freigabe) sofort aktiv oder nach Freigabe | TOTP in Cobe News – Pflicht für Admins, für Leser freiwillig oder [Pflicht für alle](#zweiter-faktor-alle) | der [Rollen-Zuordnung](#gruppen-rollen) |
| **Microsoft Entra ID** | wie AD: [vorab geladen](#vorab-laden), sofort aktiv oder nach [Freigabe](#freigabe) | verlangt Microsoft ([Conditional Access](term:conditionalaccess)); wo ein zweiter Faktor Pflicht ist und das Token ihn nicht nachweist, zusätzlich TOTP in Cobe News ([MFA-Nachweis](#entra-mfa-nachweis)) | der [Rollen-Zuordnung](#gruppen-rollen) |

Die Anmeldeseite zeigt dann „Mit Microsoft anmelden“ (Entra ID) und darunter die Reiter „Active Directory“ und
„Lokales Konto“.

### Rollen {#rollen}

- **Admin** – Einstellungen, Quellen, Benachrichtigungsregeln, Benutzer und Anmeldung. TOTP ist Pflicht – bei
  Entra-Konten nur, solange das Token von Microsoft keinen zweiten Faktor nachweist ([MFA-Nachweis](#entra-mfa-nachweis)).
- **Leser** – liest News, markiert als gelesen und stellt die eigenen Desktop-Benachrichtigungen ein.

Mehr dazu, was jede Rolle darf: [Rollen](/docs/erste-schritte#rollen).

### Der Notfall-Admin {#ueberblick-notfall}

Das erste Konto aus der Ersteinrichtung ist der **Notfall-Admin**: lokal, immer aktiver Admin, nie vom Verzeichnis
abgeschaltet und nie durch Fehlversuche gesperrt. Er ist der Weg hinein, wenn AD oder Entra ID ausfallen oder falsch
eingerichtet sind. Details: [Notfall-Admin](#notfall-admin).

### Reihenfolge beim Einrichten {#einrichtung-reihenfolge}

1. Ersteinrichtung mit dem Setup-Token – der Notfall-Admin entsteht.
2. Bei Bedarf weitere lokale Konten anlegen.
3. AD und/oder Entra ID unter *Einstellungen → Anmeldung* einrichten, testen, speichern.
4. Unter *Einstellungen → Benutzer & Rollen → Rollen-Zuordnung* Gruppen den Rollen zuordnen. **Ohne Zuordnung kann sich
   niemand aus AD oder Entra ID anmelden.**
5. Mit einem Testkonto aus jeder Gruppe anmelden und die Rolle prüfen.

## Lokale Benutzer {#lokale-benutzer}

Lokale Konten verwaltest du unter [Einstellungen → Benutzer & Rollen](/settings/users), Reiter *Benutzer*. AD- und
Entra-Benutzer erscheinen in derselben Liste, sobald sie sich einmal angemeldet haben (Spalte mit der Herkunft *Lokal*,
*Active Directory* oder *Entra ID*).

### Anlegen {#benutzer-anlegen}

1. *Einstellungen → Benutzer & Rollen* öffnen und „Lokalen Benutzer anlegen“ wählen.
2. Benutzername, Anzeigename, optional E-Mail und die Rolle eintragen.
3. „Anlegen“ klicken. Ein Admin-Konto anzulegen verlangt, dass du [erneut bestätigst](#erneut-bestaetigen), wer du bist.
4. Cobe News zeigt **einmal** ein temporäres Passwort (vier Fünfergruppen mit Bindestrichen). Kopieren, auf sicherem Weg
   weitergeben und mit „Notiert“ schließen. Danach ist es nicht mehr abrufbar.
5. Bei der ersten Anmeldung legt die Person ein eigenes Passwort fest. Bis dahin trägt das Konto die Markierung
   *Startpasswort läuft ab am …*.

Ein temporäres Passwort gilt **7 Tage** ab Vergabe (einstellbar von 1 bis 30 Tagen, [Zeitlimits](#sitzungen-zeitlimits)) –
das gilt auch für eines aus „Passwort zurücksetzen“ und aus `reset-emergency`. Danach lehnt Cobe News die Anmeldung damit
ab („Startpasswort abgelaufen – Admin um ein neues bitten“), und die Liste zeigt *Startpasswort abgelaufen*. Ein Admin
vergibt dann mit „Passwort zurücksetzen“ ein neues. Eine längere Einstellung gilt auch für schon vergebene Passwörter
(gerechnet ab ihrer Vergabe). Das eigene Passwort einer Person läuft nie ab.

Regeln für Passwörter: mindestens 12 Zeichen, kein häufiges Passwort, nicht der Benutzername darin und keines der
**letzten fünf Passwörter** des Kontos (das aktuelle und die vier davor) – „eines der letzten fünf Passwörter“.
Cobe News hebt dafür von den früheren Passwörtern nur ihre Argon2-Hashes auf, nie das
Passwort selbst; sie erscheinen nirgends (kein Protokoll, keine Antwort, kein Export). Das gilt für die eigene
Passwortänderung und für das Ersetzen eines temporären Passworts. Temporäre Passwörter (vom Admin gesetzt) kommen nie
in die Liste – das Passwort davor schon: Nach dem Zurücksetzen lässt sich nicht wieder das alte wählen. Nur lokale
Konten; AD- und Entra-Passwörter verwaltet das Verzeichnis.

### Zweiter Faktor (TOTP) {#benutzer-totp}

- **Admins** (lokal und AD) müssen bei der ersten Anmeldung eine Authenticator-App einrichten („Zweiten Faktor
  einrichten“: QR-Code scannen, 6-stelligen Code eingeben). Ohne das kommen sie nicht weiter.
- **Leser** können TOTP freiwillig einrichten – im Benutzermenü unten links unter *Profil & Sicherheit*. Ist
  [Zweiter Faktor für alle](#zweiter-faktor-alle) an, ist er auch für sie Pflicht.
- **Entra-Konten** bekommen TOTP in Cobe News nur, wo ein zweiter Faktor Pflicht ist und das Token von Microsoft ihn
  nicht nachweist – eingerichtet bei der Anmeldung ([MFA-Nachweis](#entra-mfa-nachweis)). Sonst verlangt Microsoft den
  zweiten Faktor.
- Fünf falsche Codes bei einer Anmeldung beenden den Anmeldeversuch („Zu viele falsche Codes – bitte neu anmelden.“).

Eigenes Passwort und eigenes TOTP ändert jede Person selbst unter *Profil & Sicherheit*, siehe
[Eigenes Konto](/docs/erste-schritte#eigenes-konto).

### Zweiter Faktor für alle {#zweiter-faktor-alle}

[Einstellungen → Anmeldung](/settings/auth), Karte *Zweiter Faktor*, Schalter „Zweiter Faktor für alle Pflicht“ –
**standardmäßig aus**: Nach einem Update meldet sich niemand anders an als vorher. Speichern verlangt eine
[erneute Bestätigung](#erneut-bestaetigen) und steht im [Protokoll](/docs/betrieb#protokoll).

Ist er an, braucht jede Anmeldung einen zweiten Faktor – nicht nur die der Admins:

| Konto | Was bei der nächsten Anmeldung passiert |
|---|---|
| Lokal, ohne TOTP und ohne Passkey | Nach dem Passwort der Schritt „Zweiten Faktor einrichten“: Authenticator-App **oder** „Stattdessen einen Passkey einrichten“ (wenn [Passkeys](#passkeys) an sind und die Seite unter ihrer Adresse läuft). Danach angemeldet. |
| Lokal, mit Passkey, ohne TOTP | Die Anmeldung **mit dem Passkey** braucht nichts weiter. Mit dem Passwort angemeldet, kommt der Einrichtungsschritt – mit dem Hinweis, sich besser mit dem Passkey anzumelden. |
| Lokal oder AD, mit TOTP | wie bisher: Passwort, dann Code. |
| AD, ohne TOTP | Einrichtungsschritt (nur Authenticator-App – Passkeys gibt es für AD-Konten nicht). |
| Entra ID | Wie für Admins: Weist das Token einen zweiten Faktor nach, angemeldet; sonst der eigene TOTP von Cobe News ([MFA-Nachweis](#entra-mfa-nachweis)). |

- **Laufende Sitzungen** bleiben unverändert, bis sie ablaufen oder die Person sich abmeldet – die Pflicht gilt ab der
  nächsten Anmeldung. Wer sofort sicher sein will, beendet die Sitzungen der Konten (*Benutzer & Rollen* →
  „Sitzungen & Passkeys“).
- Solange der Schalter an ist, kann niemand seinen TOTP unter *Profil & Sicherheit* entfernen, der keinen Passkey hat
  („Ein zweiter Faktor ist Pflicht …“).
- Ausschalten nimmt niemandem etwas weg: eingerichtete Apps und Passkeys bleiben.

### Zweiten Faktor auf dem Gerät merken {#geraet-merken}

[Einstellungen → Anmeldung](/settings/auth), Karte *Zweiter Faktor*, Schalter „Zweiten Faktor auf dem Gerät merken“ –
**standardmäßig aus**: Er schwächt den zweiten Faktor, das entscheidet der Admin. Speichern verlangt eine
[erneute Bestätigung](#erneut-bestaetigen) und steht im [Protokoll](/docs/betrieb#protokoll).

Ist er an, zeigt der Schritt mit dem Code den Schalter „Auf diesem Gerät merken (bis …)“. Wer ihn einschaltet, gibt in
diesem Browser bis dahin nur noch das **Passwort** ein – der Code wird übersprungen.

| Einstellung | Auswahl | Standard |
|---|---|---|
| Merken für | Sitzungsdauer (die Höchstdauer unter [Zeitlimits](#sitzungen-zeitlimits)), 1, 7 oder 30 Tage | Sitzungsdauer |
| Auch für Admins | an / aus | aus – Admins geben den Code bei jeder Anmeldung ein |

- **Nur der Code** wird übersprungen, nie das Passwort. Ein [Startpasswort](#benutzer-anlegen) wird trotzdem ersetzt,
  eine fällige Einrichtung trotzdem verlangt. Sperren nach falschen Passwörtern gelten wie immer.
- **Das Notfall-Konto** wird nie gemerkt.
- **Entra-Konten:** gilt nur dort, wo Cobe News seinen eigenen TOTP fragt ([MFA-Nachweis](#entra-mfa-nachweis)). Den
  zweiten Faktor bei Microsoft regelt Microsoft.
- **Heikle Änderungen** fragen trotzdem nach dem Code: Eine Anmeldung über ein gemerktes Gerät zählt nicht als
  [erneute Bestätigung](#erneut-bestaetigen). Das eigene Passwort ändern verlangt mit TOTP immer den Code, eine
  [Kalender-Adresse](/docs/benachrichtigungen#kalender-ical) erzeugen in einer solchen Sitzung erst die Bestätigung.
- **Wie es gespeichert ist:** Der Browser hält ein zufälliges Token in einem eigenen Cookie (HttpOnly, Secure wie das
  Sitzungs-Cookie, SameSite=Strict, nur für `/api/auth`), der Server nur dessen Hash. Es gilt nur für das Konto, für
  das es gemerkt wurde.
- **Es gilt nicht mehr**, sobald sich Passwort, TOTP oder Rolle des Kontos ändern, die Dauer abgelaufen ist (eine
  kürzere Dauer gilt sofort auch für schon gemerkte Geräte), der Schalter aus ist oder Admins ausgenommen werden.
- **Vergessen** werden gemerkte Geräte unter [Meine Sitzungen](#meine-sitzungen) (eins oder alle), durch einen Admin
  („Sitzungen & Passkeys“ → „Gemerkte Geräte vergessen“), mit „Alle anderen abmelden“ / „Alle Sitzungen beenden“, beim
  Sperren, Deaktivieren und Zurücksetzen, nach einer [Wiederherstellung](/docs/sicherung#wiederherstellung) alle.
  Ausschalten vergisst alle – wieder einschalten bringt keins zurück.
- **Ein Browser, zwei Konten:** Der Browser merkt sich nur ein Gerät – das zuletzt gemerkte. Das Gerät des anderen
  Kontos steht weiter in dessen Liste, gilt in diesem Browser aber nicht mehr (dort fragt die Anmeldung wieder nach dem
  Code); „Vergessen“ räumt es weg. „Alle Geräte vergessen“ des einen Kontos lässt das gemerkte Gerät des anderen stehen.
- Im [Protokoll](/docs/betrieb#protokoll): „Gerät für den zweiten Faktor gemerkt“, „Gemerkte Geräte vergessen“; die
  Anmeldung eines Admins über ein gemerktes Gerät mit der Anmeldeart „Passwort + gemerktes Gerät“.

### Verwalten {#benutzer-verwalten}

In jeder Zeile der Benutzerliste:

| Was | Wo | Hinweise |
|---|---|---|
| Rolle ändern | Auswahl *Rolle* | Nur lokale Konten – bei AD/Entra folgt die Rolle der Gruppe. Verlangt erneute Bestätigung. Alle Sitzungen des Kontos enden. |
| Freigeben / Ablehnen | Schaltflächen in der Zeile (*Wartet auf Freigabe*) | Nur solange die [automatische Anmeldung](#freigabe) aus ist. „Freigeben“ schaltet das Konto ein – als Admin mit erneuter Bestätigung; den Schalter *Aktiv* einschalten ist dasselbe. „Ablehnen“ lässt es aus wie *Dauerhaft sperren*. |
| Aufstieg freigeben / Bleibt Leser | Schaltflächen in der Zeile (*Aufstieg zum Admin wartet auf Freigabe*) | „Aufstieg freigeben“ macht den Leser zum Admin (erneute Bestätigung, alle Sitzungen enden). „Bleibt Leser“: Solange das Konto in der Admin-Gruppe ist, wird nicht wieder gefragt. |
| Deaktivieren / aktivieren | Schalter *Aktiv* | **Ausschalten:** Sitzungen enden sofort; bei einem Admin-Konto mit [erneuter Bestätigung](#erneut-bestaetigen). Ein von dir ausgeschaltetes Verzeichniskonto schaltet der Verzeichnisabgleich nie wieder ein. **Einschalten:** immer mit erneuter Bestätigung. Ein lokales Konto ist sofort wieder aktiv. Ein Verzeichniskonto, das du ausgeschaltet hattest, geht an den Abgleich zurück: Es bleibt vorerst aus (Hinweis „geht an den Verzeichnisabgleich zurück“) und wird aktiv, sobald die nächste Anmeldung oder der stündliche Abgleich es in einer zugeordneten Gruppe (oder einem Team) findet. Ein Verzeichniskonto, das der Abgleich ausgeschaltet hat (nicht mehr in einer zugeordneten Gruppe, im Verzeichnis deaktiviert oder gelöscht), schaltet nur das Verzeichnis wieder ein – der Schalter sagt das und lässt es aus. |
| Dauerhaft sperren | „Weitere Aktionen“ → „Dauerhaft sperren“ | Auch für ein Konto, das der Abgleich oder Teams schon ausgeschaltet hat (sein Schalter steht schon auf aus). Danach steht *Vom Admin gesperrt*: Weder der Abgleich noch Teams noch eine Anmeldung schalten das Konto wieder ein. Verlangt erneute Bestätigung, alle Sitzungen enden. |
| Dauerhafte Sperre aufheben | „Weitere Aktionen“ → „Dauerhafte Sperre aufheben“ | Verzeichniskonto: Danach entscheidet wieder der Abgleich (*Wartet auf Abgleich*) – aktiv, sobald eine Anmeldung oder der nächste Abgleich eine zugeordnete Gruppe oder ein Team findet. Lokales Konto: sofort wieder aktiv. Verlangt erneute Bestätigung. |
| Sperre aufheben | Menü „Weitere Aktionen“ → „Sperre aufheben“ | Nur aktiv, wenn das Konto wegen Fehlversuchen gesperrt ist (Markierung *Gesperrt (… min)*). |
| Passwort zurücksetzen | „Weitere Aktionen“ → „Passwort zurücksetzen“ | Nur lokale Konten. Neues temporäres Passwort, einmal angezeigt. Die Passkeys des Kontos werden entfernt. Alle Sitzungen enden. |
| TOTP zurücksetzen | „Weitere Aktionen“ → „TOTP zurücksetzen“ | Lokale und AD-Konten mit TOTP. Admins richten bei der nächsten Anmeldung eine neue App ein. Alle Sitzungen enden. |
| Sitzungen & Passkeys | „Weitere Aktionen“ → „Sitzungen & Passkeys“ | Laufende Sitzungen des Kontos beenden, Passkeys entfernen – je mit erneuter Bestätigung, siehe [Meine Sitzungen](#meine-sitzungen) und [Passkeys eines Kontos](#passkeys-admin). |
| Löschen | „Weitere Aktionen“ → „Löschen“ | Löscht das Konto und seine Gelesen-Markierungen. Ein Verzeichniskonto entsteht bei der nächsten Anmeldung neu, solange die Gruppe passt – zum Aussperren lieber deaktivieren. |

Warum ein Konto aus ist, zeigt seine Markierung (mit Erklärung beim Darüberfahren): *Vom Admin gesperrt* ist die
dauerhafte Sperre (auch nach „Ablehnen“). *Wartet auf Freigabe* schaltet nur ein Admin ein ([Freigabe](#freigabe)). *Kein Team mehr*, *Teams ausgeschaltet*, *Keine Rollen-Gruppe mehr*, *Im Verzeichnis deaktiviert* und
*Nicht mehr im Verzeichnis* hat der Abgleich gesetzt – solche Konten schaltet er von selbst wieder ein, sobald es wieder
passt. Wer nicht zurückkommen soll, bekommt „Dauerhaft sperren“.

Zurücksetzen und Löschen verlangen immer eine [erneute Bestätigung](#erneut-bestaetigen). Geschützt sind:

- **das eigene Konto** – nicht herabstufen, deaktivieren, zurücksetzen oder löschen (dafür *Profil & Sicherheit*),
- **der Notfall-Admin** – bleibt immer aktiver Admin; zurücksetzen nur auf dem Server ([Notfall-Admin](#notfall-admin)),
- **der letzte aktive Admin** – lässt sich nicht herabstufen, deaktivieren oder löschen.

> [!NOTE]
> Ändern zwei Admins gleichzeitig dasselbe Konto, gewinnt nicht stillschweigend der Letzte: Wer auf einem veralteten
> Stand speichert, sieht „Inzwischen von jemand anderem geändert“ und lädt neu.

## Passkeys {#passkeys}

Lokale Konten können sich mit einem [Passkey](term:passkey) ([WebAuthn](term:webauthn)) anmelden statt mit Passwort und
TOTP. Wie Personen ihn einrichten: [Passkeys](/docs/erste-schritte#passkeys). AD- und Entra-Konten melden sich weiter
über ihr Verzeichnis an – für sie gibt es keine Passkeys.

### Voraussetzungen {#passkeys-voraussetzungen}

- **HTTPS und ein Hostname** in `BASE_URL` (z. B. `https://news.corp.example`). Der Hostname ist die *RP ID*, an die jeder
  Passkey gebunden ist; die Adresse in `BASE_URL` (mit Port) ist die einzige, unter der Passkeys gehen. Plain HTTP geht
  nur für `localhost`.
- **Keine IP-Adresse**: Browser lassen für eine IP-Adresse keine Passkeys zu. Steht in `BASE_URL` eine IP, zeigt
  [Einstellungen → Anmeldung](/settings/auth) *Nicht möglich* mit dem Grund, und die Anmeldeseite bietet keinen Passkey
  an.
- Öffnet jemand Cobe News unter einer anderen Adresse (IP, anderer Name), erscheint dort kein Passkey-Knopf.

### Ein- und ausschalten {#passkeys-schalter}

[Einstellungen → Anmeldung](/settings/auth), Karte *Passkeys*, Schalter *Passkeys erlauben* – ab Werk **an**: Niemand
hat einen Passkey, bevor er selbst einen einrichtet, und ein Passkey ist sicherer als Passwort + TOTP (lässt sich nicht
abphishen). Speichern verlangt eine [erneute Bestätigung](#erneut-bestaetigen). Aus heißt: keine neuen Passkeys, keine
Anmeldung mit Passkey. Eingerichtete Passkeys bleiben gespeichert (sichtbar, entfernbar) und gehen wieder, sobald der
Schalter an ist.

### Hostname ändern {#passkeys-hostname}

> [!WARNING]
> Ändert sich der Hostname in `BASE_URL` (z. B. von `news.corp.example` auf `secnews.corp.example`), funktionieren
> **alle** vorhandenen Passkeys nicht mehr – sie gehören zum alten Namen. Alle melden sich dann mit Passwort an,
> entfernen den alten Passkey und richten einen neuen ein. Ein anderer Port allein ändert die RP ID nicht, aber die
> Adresse, unter der Passkeys gehen.

### Was geprüft wird {#passkeys-pruefung}

- **Zwei Faktoren**: Cobe News verlangt *User Verification* – das Gerät hat Fingerabdruck, Gesicht oder PIN geprüft.
  Ein Passkey ohne diese Prüfung wird abgelehnt (beim Einrichten und bei jeder Anmeldung). Danach gilt wie sonst: Ein
  temporäres Passwort wird zuerst ersetzt, ein Admin ohne TOTP richtet es ein.
- **Herkunft und Einmal-Challenge**: genau die Adresse aus `BASE_URL`, die RP ID, eine Challenge, die nur einmal und
  nur drei Minuten gilt und an diesen Browser bzw. diese Sitzung gebunden ist. Challenges liegen nur im Speicher, nie in
  der Datenbank oder einer Sicherung.
- **Gespeichert** werden nur Kennung, öffentlicher Schlüssel, Zähler, Übertragungswege, Name und Zeiten – der geheime
  Schlüssel verlässt das Gerät nie. Eine Sicherung enthält also nur öffentliche Schlüssel.
- **Zähler**: Geht der Zähler eines Passkeys zurück, kann er kopiert worden sein. Die Anmeldung wird nicht verweigert
  (sonst könnte eine Kopie den Besitzer aussperren); der Passkey trägt dann *Prüfen*, das Protokoll eine Warnung. Synchronisierte
  Passkeys (iCloud, Google, Passwortmanager) zählen nicht – bei ihnen steht der Zähler immer auf 0.
- **Fehlversuche** zählen auf der Adresse wie falsche Passwörter ([Fehlversuche und Sperren](#sperren)); von einer
  geblockten Adresse geht keine Passkey-Anmeldung. Höchstens 30 Passkey-Anmeldungen je Adresse (IPv6: je /64) und 300
  je IPv6-/48 in 10 Minuten. Die
  Kontosperre nach falschen Passwörtern hält einen Passkey nicht auf (er lässt sich nicht erraten); ein deaktiviertes
  oder gesperrtes Konto meldet sich nie an.
- Erlaubte Verfahren: ES256, EdDSA, RS256; Bescheinigung (*Attestation*) „none“ oder Selbstbescheinigung.

### Passkeys eines Kontos {#passkeys-admin}

In der Benutzerliste über „Weitere Aktionen“ → „Sitzungen & Passkeys“. Ein Admin sieht dort die Passkeys des Kontos
(Name, erstellt, zuletzt benutzt, Warnung) und entfernt einen – z. B. bei verlorenem Gerät. Das verlangt eine
[erneute Bestätigung](#erneut-bestaetigen) und meldet alle Sitzungen ab, die mit diesem Passkey angemeldet sind. Die
Spalte neben TOTP zeigt, wie viele Passkeys ein Konto hat. *Passwort zurücksetzen* entfernt alle Passkeys des
Kontos mit.

## Notfall-Admin {#notfall-admin}

Der Notfall-Admin ist das lokale Admin-Konto aus der Ersteinrichtung. Es

- kann von keinem anderen Admin deaktiviert, herabgestuft oder gelöscht werden,
- wird vom Verzeichnisabgleich nie berührt,
- wird durch Fehlversuche nie gesperrt – sein **richtiges** Passwort mit TOTP wird auch von einer geblockten Adresse
  angenommen. Als Bremse wartet nach 20 Fehlversuchen in einer Stunde jede Prüfung 3 Sekunden, und es läuft nur eine
  gleichzeitig.
- meldet, wenn jemand sein Passwort rät: Überschreiten die Fehlversuche die 20 in einer Stunde, schreibt Cobe News eine
  Warnung ins Log der App („emergency admin: … failed sign-in checks“), einen Eintrag ins
  [Protokoll](/docs/betrieb#protokoll) („Notfall-Admin: Fehlversuchs-Budget überschritten“) und zeigt 24 Stunden lang
  einen Hinweis unter [Einstellungen → HTTPS & Zertifikat](/settings/https) – höchstens einmal pro Stunde, ein Angreifer
  kann damit weder Log noch Protokoll fluten.

Bewahre Passwort und TOTP-Zugang des Notfall-Admins offline auf (Passwort-Tresor).

### Setup-Token {#setup-token}

Beim ersten Start schreibt die App ein einmaliges **Setup-Token** in ihr Log. Es gilt 60 Minuten und nur einmal; bei
jedem Neustart bis zum Abschluss der Einrichtung gibt es ein neues.

```bash
cd /opt/cobe-news
docker compose logs app | grep -A1 "Setup token"
```

Im Browser führt ein Assistent in drei Schritten: Token eingeben, Benutzername, Anzeigename und Passwort wählen, dann die
Authenticator-App einrichten. Das Token wird erst verbraucht, wenn das Konto wirklich angelegt ist – scheitert dabei
etwas, bleibt es gültig.

Ein neues Token ohne Neustart (nur solange es noch keinen Notfall-Admin gibt):

```bash
docker compose exec app python -m app.cli new-setup-token
```

Ist die Einrichtung schon abgeschlossen, antwortet der Befehl „Setup is already done.“

### Zugang wiederherstellen {#notfall-zuruecksetzen}

Passwort oder Authenticator des Notfall-Admins verloren? Auf dem Server:

```bash
cd /opt/cobe-news
docker compose exec app python -m app.cli reset-emergency
```

Der Befehl

- gibt ein **temporäres Passwort** aus,
- entfernt das TOTP (es wird bei der nächsten Anmeldung neu eingerichtet) und alle Passkeys des Kontos – keiner, den
  jemand anderes eingerichtet hat, öffnet danach noch die Tür,
- beendet alle Sitzungen des Kontos und hebt eine Sperre auf.

Danach mit dem temporären Passwort anmelden, ein neues Passwort festlegen und TOTP neu einrichten. Es gilt wie jedes
temporäre Passwort 7 Tage ([einstellbar](#sitzungen-zeitlimits)); danach den Befehl einfach noch einmal ausführen.
Weitere Befehle: [Kommandozeile](/docs/betrieb#cli).

## Active Directory / LDAP {#ad-ldap}

Mit AD melden sich Benutzer mit `sAMAccountName` oder [UPN](term:upn) und ihrem AD-Passwort an. Cobe News prüft das Passwort am
Domänencontroller, liest die Gruppen und bestimmt daraus die Rolle. Admins aus dem AD richten zusätzlich TOTP ein.

### Voraussetzungen {#ad-voraussetzungen}

- Ein **Dienstkonto** mit Leserechten im AD ([Bind-DN](term:binddn)), z. B.
  `CN=svc-cobe-news,OU=Service,DC=corp,DC=example` – oder als UPN `svc-cobe-news@corp.example`.
- Ein oder mehrere Domänencontroller, erreichbar über [LDAPS](term:ldaps) (Port 636) oder [StartTLS](term:starttls)
  (Port 389).
- Bei einer internen Zertifizierungsstelle: deren Root-CA-Zertifikat im PEM-Format.

### Einrichten {#ad-einrichten}

[Einstellungen → Anmeldung](/settings/auth), Karte *Active Directory / LDAP*:

1. Den Schalter „Anmeldung mit Active Directory“ einschalten – erst dann lassen sich die Felder bearbeiten. Wirksam wird
   er beim Speichern.
2. **Domänencontroller**: einer pro Zeile, höchstens 4, optional mit Port (z. B. `dc01.corp.example`). Der erste
   erreichbare wird genutzt.
3. **Verschlüsselung**: „LDAPS (636)“ – von Anfang an verschlüsselt – oder „StartTLS (389)“ – schaltet nach dem Verbinden
   auf TLS um. „Keine (unsicher)“ geht nur zusammen mit dem Schalter „Unverschlüsseltes LDAP ausdrücklich erlauben“:
   dann geht jedes Passwort lesbar über das Netz. Nur für Tests.
4. **Zertifikat prüfen** eingeschaltet lassen. Bei einer internen CA deren Zertifikat in das Feld *Eigenes
   CA-Zertifikat (PEM, optional)* einfügen (beginnt mit `-----BEGIN CERTIFICATE-----`).
5. **Zeitlimit**: 2–60 Sekunden (Standard 10).
6. **Base-DN** ([Basis-DN](term:basedn)): wo Benutzer und Gruppen gesucht werden, z. B. `DC=corp,DC=example`. Leer
   gelassen, leitet Cobe News ihn aus dem Namen des ersten Servers ab.
7. **Dienstkonto (Bind-DN)** und **Passwort des Dienstkontos**. Das Passwort wird verschlüsselt gespeichert und nie
   wieder angezeigt; leer lassen behält das gespeicherte.
8. **Benutzerfilter**: Standard ist `sAMAccountName` oder `userPrincipalName`; `{username}` steht für die Eingabe bei der
   Anmeldung und muss im Filter vorkommen. **Verschachtelte Gruppen**: eingeschaltet zählen auch Gruppen in Gruppen.
9. „Verbindung testen“ – Erfolg: „Dienstkonto angemeldet, Base-DN gefunden.“ Getestet wird der Stand im Formular,
   gespeichert wird dabei nichts.
10. „Speichern“ – verlangt eine [erneute Bestätigung](#erneut-bestaetigen).
11. Unter *Benutzer & Rollen → Rollen-Zuordnung* AD-Gruppen zuordnen ([Gruppen → Rollen](#gruppen-rollen)).

> [!NOTE]
> Änderst du Server, Verschlüsselung, Zertifikatsprüfung, CA-Zertifikat oder Bind-DN, musst du das Passwort des
> Dienstkontos neu eingeben („Bitte das Passwort erneut eingeben …“). So geht das gespeicherte Passwort nie an einen
> anderen Server oder für ein anderes Konto hinaus.

### Erlaubte Ziele {#ad-ziele}

Domänencontroller dürfen im Firmennetz liegen (private Adressen sind erlaubt). Nie erlaubt sind Loopback, Link-Local,
die eigenen Docker-Netze von Cobe News und der Docker-Host selbst (z. B. `host.docker.internal`, bei Docker Desktop das
Netz `192.168.65.0/24`). „Verbindung testen“ meldet dann „Ziel nicht erlaubt …“. Geprüft wird der Name und – beim
Verbinden – die Adresse, die tatsächlich erreicht wurde, bevor StartTLS oder ein Passwort folgt (ein Name, der danach auf
ein verbotenes Ziel zeigt, hilft nicht). Bei Fehlern zeigt Cobe News nur deren
Art, nie Antworten des Servers.

### Fehler beim Testen {#ad-fehler}

| Meldung | Ursache und Abhilfe |
|---|---|
| Keine Verbindung (Netz, Firewall oder Proxy prüfen). | DC-Name, Port, Firewall zwischen Cobe News und DC prüfen. |
| TLS-Fehler – Zertifikat oder CA prüfen. | Zertifikat des DC passt nicht zum Namen oder die interne CA fehlt im PEM-Feld. Den DC unter dem Namen eintragen, der im Zertifikat steht. |
| Das Dienstkonto wird abgelehnt (Bind-DN oder Passwort falsch). | Bind-DN (voller DN oder UPN) und Passwort prüfen; Konto gesperrt oder abgelaufen? |
| Die Suche ist fehlgeschlagen (Base-DN prüfen). | Base-DN existiert nicht oder das Dienstkonto darf ihn nicht lesen. |
| Ziel nicht erlaubt … | siehe [Erlaubte Ziele](#ad-ziele). |
| Unverschlüsseltes LDAP ist nicht ausdrücklich erlaubt. | LDAPS oder StartTLS wählen – oder für einen Test den Schalter setzen. |

### Anmelden mit AD {#ad-anmelden}

Auf der Anmeldeseite den Reiter „Active Directory“ wählen und den Benutzernamen (`a.weber`) oder UPN
(`a.weber@corp.example`) eingeben. Ist das Verzeichnis nicht erreichbar, erscheint „Das Verzeichnis ist gerade nicht
erreichbar.“ Ein richtiges Passwort ohne passende Gruppe wird wie ein falsches beantwortet – die Anmeldeseite verrät
nicht, ob ein AD-Passwort stimmt.

## Entra ID: App-Registrierung {#entra-app-registrierung}

Für die Anmeldung mit Microsoft braucht Cobe News eine **App-Registrierung** in eurem [Mandanten](term:tenant). Cobe News
nutzt [OIDC](term:oidc) mit Authorization Code Flow und [PKCE](term:pkce) und prüft das ID-Token vollständig. Die Schritte im
[Microsoft Entra Admin Center](https://entra.microsoft.com) brauchen eine Rolle wie *Anwendungsadministrator*; die
Administratorzustimmung in Schritt 5 braucht einen *Globalen Administrator* oder *Administrator für privilegierte Rollen*.

> [!TIP]
> Microsoft ordnet das Menü des Admin Centers gelegentlich neu. Findest du einen Pfad nicht, tippe den Namen der Seite
> (z. B. „App-Registrierungen“) in die Suche oben.

### Schritt 1: Registrieren {#entra-registrieren}

1. *Identität → Anwendungen → App-Registrierungen* öffnen und „Neue Registrierung“ wählen.
2. **Name**: z. B. „Cobe News“ – erscheint bei der Anmeldung und in den Unternehmensanwendungen.
3. **Unterstützte Kontotypen**: „Nur Konten in diesem Organisationsverzeichnis“ (einzelner Mandant). Cobe News prüft,
   dass das Token aus genau diesem Mandanten kommt.
4. **Umleitungs-URI**: gleich hier eintragen – siehe [Schritt 2](#entra-redirect-uri).
5. „Registrieren“ klicken.
6. In der **Übersicht** der App die *Anwendungs-ID (Client)* ([Client-ID](term:clientid)) und die *Verzeichnis-ID
   (Mandant)* notieren. Beides sind GUIDs wie `00000000-0000-0000-0000-000000000000`.

### Schritt 2: Umleitungs-URI {#entra-redirect-uri}

Die [Umleitungs-URI](term:redirecturi) ist die Adresse, an die Microsoft den Browser nach der Anmeldung zurückschickt.
Für diese Installation lautet sie:

```text
{{redirect_uri}}
```

Sie steht auch in *Einstellungen → Anmeldung*, Karte *Microsoft Entra ID*, Feld *Umleitungs-URI* – mit Knopf zum
Kopieren.

1. In der App-Registrierung *Authentifizierung* öffnen (bei der Registrierung: Feld *Umleitungs-URI*).
2. „Plattform hinzufügen“ → **Web** wählen – nicht „Single-Page-Anwendung“ und nicht „Mobile Anwendungen und
   Desktopanwendungen“.
3. Den Wert oben **exakt** einfügen und speichern.
4. Die Kästchen unter *Implizite Genehmigung und Hybridflows* bleiben leer – Cobe News braucht sie nicht.

Die Regel dahinter: **`BASE_URL` + `/api/auth/oidc/callback`** – Zeichen für Zeichen.

- **Schema**: `https://` (Microsoft erlaubt `http://` nur für `localhost`).
- **Port**: gehört dazu, wenn er in `BASE_URL` steht, z. B. `https://news.corp.example:8095/api/auth/oidc/callback`.
- **Hostname**: genau der aus `BASE_URL` – nicht die IP-Adresse, nicht ein anderer DNS-Name.
- **Kein Schrägstrich am Ende.**

> [!WARNING]
> Ändert sich `BASE_URL` (anderer Name, anderer Port), ändert sich auch die Umleitungs-URI. Trage dann den neuen Wert
> in der App-Registrierung ein, sonst scheitert jede Anmeldung mit AADSTS50011. Wie `BASE_URL` gesetzt wird:
> [Adresse](/docs/betrieb#adresse).

Öffne Cobe News außerdem immer unter der Adresse aus `BASE_URL`. Wer die Anmeldung unter einer anderen Adresse beginnt
(z. B. per IP), landet nach Microsoft auf der `BASE_URL`-Adresse, deren Browser-Cookie fehlt – Ergebnis: „Die Anmeldung
mit Microsoft passt nicht zu diesem Browser“.

### Schritt 3: Clientgeheimnis {#entra-geheimnis}

Mit dem [Clientgeheimnis](term:clientsecret) weist sich Cobe News bei Microsoft aus.

1. *Zertifikate & Geheimnisse* → Reiter *Geheime Clientschlüssel* → „Neuer geheimer Clientschlüssel“.
2. Eine Beschreibung eintragen (z. B. „Cobe News 2026“) und die Gültigkeit wählen (Microsoft empfiehlt 180 Tage;
   höchstens 24 Monate).
3. „Hinzufügen“.
4. Sofort den **Wert** kopieren – **nicht die Geheimnis-ID**. Der Wert ist nur jetzt sichtbar; später zeigt das Portal
   ihn nur noch gekürzt.

> [!WARNING]
> **Das Geheimnis läuft ab.** Trag dir das Ablaufdatum sofort in den Kalender ein (mit ein paar Wochen Vorlauf).
> Nach Ablauf scheitert jede Anmeldung mit Microsoft („Die Anmeldung mit Microsoft ist fehlgeschlagen.“, im Log
> AADSTS7000222), Gruppensuche und stündlicher Abgleich gehen nicht mehr. Rechtzeitig wechseln: neues Geheimnis
> anlegen, in Cobe News eintragen, speichern, das alte in Entra löschen.

### Abgelaufenes Geheimnis ersetzen {#entra-geheimnis-abgelaufen}

Ein Admin, der mit Microsoft angemeldet ist, kann das neue Geheimnis dann **nicht** speichern: Die Änderung verlangt
eine [erneute Bestätigung](#erneut-bestaetigen), und die läuft über Microsoft – die lehnt Cobe News mit dem
abgelaufenen Geheimnis ab. Cobe News meldet dann „Microsoft lehnt das Clientgeheimnis von Cobe News ab – es ist
abgelaufen oder falsch …“.

1. In Entra ein neues Geheimnis anlegen und den **Wert** kopieren (wie oben).
2. Mit einem **lokalen Administrator** oder dem [Notfall-Admin](#notfall-admin) (in der Benutzerliste
   „Notfallkonto“) bei Cobe News anmelden – Reiter „Lokales Konto“ der Anmeldeseite.
3. *Einstellungen → Anmeldung* ([öffnen](/settings/auth)), Karte **Microsoft Entra ID**: das neue Geheimnis
   eintragen, „Verbindung testen“, speichern.

> [!TIP]
> Haltet deshalb immer ein lokales Admin-Konto oder den Notfall-Admin bereit (Zugangsdaten im Passwort-Tresor) und
> notiert das Ablaufdatum des Geheimnisses – zum Beispiel im Kalender und in der Beschreibung des Geheimnisses in
> Entra.

### Schritt 4: Gruppenanspruch {#entra-gruppenanspruch}

Damit Cobe News die Gruppen kennt, muss das ID-Token sie enthalten ([Gruppenanspruch](term:groupclaim)).

1. *Tokenkonfiguration* → „Gruppenanspruch hinzufügen“.
2. **Sicherheitsgruppen** ankreuzen.
3. Unter *ID* den Typ **Gruppen-ID** wählen (Standard) – Cobe News ordnet Gruppen über ihre Objekt-ID zu, nicht über
   Namen.
4. „Hinzufügen“.

Hat ein Benutzer mehr als 200 Gruppen, setzt Microsoft statt der Liste nur einen Verweis ins Token
([Gruppen-Überlauf](term:groupsoverage), „Groups Overage“). Cobe News holt die Gruppen dann über Microsoft Graph –
dafür braucht es die Berechtigungen aus Schritt 5.

### Schritt 5: API-Berechtigungen {#entra-api-berechtigungen}

1. *API-Berechtigungen* → „Berechtigung hinzufügen“ → **Microsoft Graph** → **Anwendungsberechtigungen** (nicht
   „Delegierte Berechtigungen“).
2. `GroupMember.Read.All` und `User.Read.All` suchen, ankreuzen, „Berechtigungen hinzufügen“.
3. „Administratorzustimmung für … erteilen“ klicken und mit „Ja“ bestätigen
   ([Administratorzustimmung](term:adminconsent)). In der Spalte *Status* steht danach ein grüner Haken „Gewährt für …“.

| Berechtigung | Typ | Wofür Cobe News sie braucht | Was ohne sie nicht geht |
|---|---|---|---|
| `GroupMember.Read.All` | Anwendung | Gruppensuche unter *Rollen-Zuordnung* und bei Teams; Gruppen von Benutzern mit mehr als 200 Gruppen (oder ohne Gruppenanspruch im Token); Gruppen im stündlichen Abgleich; [Teams](#teams) und [Vorab laden](#vorab-laden): die Mitglieder einer gebundenen bzw. zugeordneten Gruppe (`transitiveMembers`) | Die Gruppensuche meldet „Der App-Registrierung fehlt eine Berechtigung“ – Entra-Gruppen lassen sich in der Oberfläche **nicht zuordnen**. Benutzer mit mehr als 200 Gruppen können sich nicht anmelden („Die Anmeldung mit Microsoft ist fehlgeschlagen.“). Teams: die Gruppe zeigt „Microsoft Graph verweigert den Zugriff (403) …“, niemand wird geladen. |
| `User.Read.All` | Anwendung | Stündlicher Abgleich: gibt es das Konto noch, ist es aktiviert, in welchen Gruppen ist es; [Teams](#teams): Name, UPN, E-Mail und Status der geladenen Mitglieder | Der Abgleich für Entra wird übersprungen (Log: `directory sync (entra) skipped: forbidden`). Wer in Entra deaktiviert, gelöscht oder aus der Gruppe genommen wird, behält eine laufende Sitzung bis zu deren Ablauf (Standard: 60 Minuten ohne Aktion, spätestens 12 Stunden); erst die nächste Anmeldung prüft neu. Teams: Graph liefert nur IDs, die Gruppe zeigt „Graph liefert nur IDs ohne Namen …“, niemand wird geladen. |

Für [Teams](#teams) mit Entra-Gruppen sind **beide Pflicht** – neue Berechtigungen braucht Teams nicht.

Beide sind **Anwendungsberechtigungen**: Cobe News fragt Graph mit dem eigenen Geheimnis, ohne angemeldete Person – darum
ist die Administratorzustimmung nötig. Gelesen wird nur; Cobe News schreibt nichts in euer Verzeichnis.

> [!NOTE]
> „Verbindung testen“ prüft, ob Graph Gruppen lesen darf (sonst die Warnung „Graph darf keine Gruppen lesen …“).
> `User.Read.All` prüft der Test nicht – ob der Abgleich läuft, zeigt das Log
> (`docker compose logs app | grep "directory sync"`).

### Schritt 6: In Cobe News eintragen {#entra-in-cobe-news}

[Einstellungen → Anmeldung](/settings/auth), Karte *Microsoft Entra ID*:

1. Den Schalter „Anmeldung mit Microsoft Entra ID“ einschalten – erst dann lassen sich die Felder bearbeiten.
2. **Verzeichnis-ID (Mandant)**: die GUID aus der Übersicht der App-Registrierung (kein Domänenname).
3. **Anwendungs-ID (Client)**: die GUID aus der Übersicht.
4. **Clientgeheimnis**: der **Wert** aus Schritt 3. Er wird verschlüsselt gespeichert und nie wieder angezeigt; leer
   lassen behält das gespeicherte.
5. „Verbindung testen“ – Erfolg: „Mandant, Client-ID und Geheimnis stimmen.“ Getestet wird der Stand im Formular.
6. **MFA-Nachweis** wählen ([unten](#entra-mfa-nachweis)) – am besten mit Authentifizierungskontext.
7. „Speichern“ – verlangt eine [erneute Bestätigung](#erneut-bestaetigen).
8. Unter *Benutzer & Rollen → Rollen-Zuordnung* Entra-Gruppen zuordnen ([Gruppen → Rollen](#gruppen-rollen)). Die
   Gruppensuche geht erst, wenn die Einstellungen gespeichert sind.
9. In einem privaten Browserfenster „Mit Microsoft anmelden“ ausprobieren.

Mögliche Meldungen von „Verbindung testen“:

| Meldung | Abhilfe |
|---|---|
| Anmeldung der Anwendung abgelehnt (Mandant, Client-ID oder Geheimnis falsch bzw. abgelaufen). | IDs neu aus der Übersicht kopieren; Geheimnis: Wert statt Geheimnis-ID, Ablaufdatum prüfen. |
| Keine Verbindung (Netz, Firewall oder Proxy prüfen). | Cobe News muss `login.microsoftonline.com` und `graph.microsoft.com` über HTTPS erreichen (ggf. über `HTTPS_PROXY`). |
| Graph darf keine Gruppen lesen … | `GroupMember.Read.All` als Anwendungsberechtigung mit Administratorzustimmung erteilen (Schritt 5). |
| Nicht vollständig eingerichtet. | Mandant, Client-ID oder Geheimnis fehlt. |

### MFA-Nachweis {#entra-mfa-nachweis}

Den zweiten Faktor einer Entra-Anmeldung verlangt Microsoft per [Conditional Access](term:conditionalaccess). Fehlt die
Richtlinie, greift sie für ein Konto nicht oder schließt sie einen Standort aus, reicht das **Entra-Passwort allein** –
auch für Admins. Cobe News prüft deshalb, was das ID-Token von Microsoft nachweist, und verlangt sonst seinen eigenen
TOTP. Einstellung „MFA-Nachweis“ in der Karte *Microsoft Entra ID*:

| Einstellung | Leser | Admins |
|---|---|---|
| **Entra vertrauen (bedingter Zugriff)** – Standard | wie bisher: angemeldet | nur mit Nachweis im Token, sonst zusätzlich der eigene TOTP von Cobe News |
| **Authentifizierungskontext verlangen** | Das Token muss den Kontext enthalten – sonst nur mit eigenem TOTP | wie Leser |
| **Nachweis verlangen** | Nachweis im Token, sonst der eigene TOTP | wie Leser |

Was als Nachweis zählt:

- **Authentifizierungskontext** (`acrs`): Cobe News fordert den eingetragenen Kontext (C1 bis C99) bei der Anmeldung als
  „essential claim“ an; Entra stellt ihn nur aus, wenn die verknüpfte Richtlinie (MFA) erfüllt ist. Das ist der einzige
  verlässliche Nachweis – empfohlen.
- **`amr` mit „mfa“**: Steht das im Token, zählt es; „pwd“ ohne „mfa“ zählt als Gegenbeweis. Die üblichen ID-Tokens
  (v2.0) enthalten `amr` aber meist nicht – dann weiß Cobe News nichts und verlangt, wo nötig, den eigenen TOTP.

Ohne Nachweis, wo einer nötig ist:

- **Mit eigenem TOTP**: Nach Microsoft fragt Cobe News nach dem Code (Anmeldeart „Microsoft + TOTP“).
- **Ohne TOTP, Token sagt nichts**: Der TOTP wird bei dieser Anmeldung eingerichtet. Das erste Einrichten schützt
  dann nur die Entra-Anmeldung selbst – ein Grund mehr für den Authentifizierungskontext.
- **Ohne TOTP, Token widerspricht** (Kontext fehlt, oder `amr` ohne „mfa“): **abgelehnt** – „Microsoft hat für diese
  Anmeldung keinen zweiten Faktor nachgewiesen …“. Sonst würde das Entra-Passwort allein den „zweiten“ Faktor einrichten.
  Von dieser Anmeldung bleibt nichts (kein neues Konto, keine geänderte Rolle).

Solange kein Kontext eingetragen ist, zeigt die Karte einen Hinweis. Einen Kontext anlegen:

1. Entra Admin Center → *Schutz → Bedingter Zugriff → Authentifizierungskontext* → „Neuer Authentifizierungskontext“,
   z. B. „Cobe News MFA“, ID **C1**, „Für Apps veröffentlichen“ an.
2. *Bedingter Zugriff → Richtlinien* → neue Richtlinie: Benutzer = die Gruppen von Cobe News, *Zielressourcen* →
   „Authentifizierungskontext“ → C1, *Gewähren* → „Multi-Faktor-Authentifizierung erforderlich“, aktivieren.
3. In Cobe News „Authentifizierungskontext verlangen“ wählen, **C1** eintragen, speichern.
4. Mit einem Testkonto anmelden: Microsoft fragt nach dem zweiten Faktor, Cobe News nicht mehr.

> [!NOTE]
> **Nach dem Update auf 0.1.42**: Mit der Standardeinstellung brauchen Entra-Admins, deren Token keinen Nachweis trägt,
> bei der nächsten Anmeldung den eigenen TOTP von Cobe News (er wird dann eingerichtet). Leser melden sich an wie bisher.
> Auch die [erneute Bestätigung](#erneut-bestaetigen) eines Entra-Admins verlangt den Nachweis.

### Optional: Zugang auf bestimmte Personen beschränken {#entra-zuweisung}

Wer Cobe News überhaupt nutzen darf, regelt die [Rollen-Zuordnung](#gruppen-rollen). Soll Microsoft schon vorher
abweisen, geht das in der zugehörigen Unternehmensanwendung:

1. *Identität → Anwendungen → Unternehmensanwendungen* → die App „Cobe News“ öffnen.
2. *Eigenschaften* → „Zuweisung erforderlich?“ auf **Ja** → „Speichern“.
3. *Benutzer und Gruppen* → „Benutzer/Gruppe hinzufügen“ → die Gruppen wählen, die Zugang haben sollen.

Nicht zugewiesene Personen sehen dann bei Microsoft AADSTS50105. Die Rollen-Zuordnung in Cobe News braucht es trotzdem.

## Entra ID: Fehler {#entra-fehler}

Fehler bei der Anmeldung mit Microsoft zeigen sich an einer von zwei Stellen: **bei Microsoft** (eine Fehlerseite mit
einem Code `AADSTS…`, der Browser kommt nicht zurück) oder **in Cobe News** (eine Meldung auf der Anmeldeseite, Details
im Log).

### AADSTS-Meldungen {#entra-aadsts}

| Code | Bedeutung | Wo sichtbar | Abhilfe |
|---|---|---|---|
| AADSTS500113 | Für die App ist keine Antwortadresse registriert. | Microsoft-Seite | Umleitungs-URI unter *Authentifizierung* als Plattform **Web** eintragen ([Schritt 2](#entra-redirect-uri)). |
| AADSTS50011 | Die Umleitungs-URI der Anfrage passt zu keiner registrierten. | Microsoft-Seite | Exakt `{{redirect_uri}}` eintragen. Typische Unterschiede: `http` statt `https`, fehlender oder anderer Port, anderer Hostname, Schrägstrich am Ende, `BASE_URL` geändert. |
| AADSTS700016 | Anwendung im Verzeichnis nicht gefunden. | Microsoft-Seite; „Verbindung testen“: „Anmeldung der Anwendung abgelehnt …“ | Client-ID falsch, oder die App ist in einem anderen Mandanten registriert als die eingetragene Mandanten-ID. Beide GUIDs neu aus der Übersicht kopieren. |
| AADSTS90002 | Mandant nicht gefunden. | Microsoft-Seite; Test wie oben | Verzeichnis-ID (Mandant) prüfen. |
| AADSTS7000215 | Ungültiges Clientgeheimnis. | Cobe News: „Microsoft lehnt das Clientgeheimnis von Cobe News ab …“; Log | Meist wurde die **Geheimnis-ID statt des Werts** eingetragen. Neues Geheimnis anlegen und den Wert eintragen ([Schritt 3](#entra-geheimnis)). |
| AADSTS7000222 | Das Clientgeheimnis ist abgelaufen. | Cobe News: „Microsoft lehnt das Clientgeheimnis von Cobe News ab …“; Log | Neues Geheimnis anlegen und mit einem lokalen Admin oder dem Notfall-Admin eintragen ([Abgelaufenes Geheimnis](#entra-geheimnis-abgelaufen)). Ablaufdatum in den Kalender. |
| AADSTS65001 (auch AADSTS90094) | Zustimmung fehlt – Benutzer dürfen der App nicht selbst zustimmen. | Microsoft-Seite („Genehmigung erforderlich“) oder Cobe News: „Microsoft hat die Anmeldung abgebrochen oder abgelehnt.“ | *API-Berechtigungen* → „Administratorzustimmung für … erteilen“. Ist die Benutzerzustimmung im Mandanten ganz abgeschaltet, vorher unter Microsoft Graph → *Delegierte Berechtigungen* `openid`, `profile` und `email` hinzufügen und dann zustimmen. |
| AADSTS50105 | Das Konto ist der App nicht zugewiesen („Zuweisung erforderlich“ ist an). | Microsoft-Seite | Person oder Gruppe unter *Unternehmensanwendungen → Cobe News → Benutzer und Gruppen* zuweisen – oder „Zuweisung erforderlich?“ auf Nein ([Zuweisung](#entra-zuweisung)). |
| AADSTS9002327 | Plattform „Single-Page-Anwendung“ statt „Web“. | Cobe News: „… fehlgeschlagen.“; Log | Umleitungs-URI unter der Plattform **Web** eintragen, den SPA-Eintrag entfernen. |

### Meldungen von Cobe News {#entra-meldungen}

| Meldung auf der Anmeldeseite | Ursache | Abhilfe |
|---|---|---|
| Microsoft lehnt das Clientgeheimnis von Cobe News ab – es ist abgelaufen oder falsch. … | Microsoft nimmt das Clientgeheimnis nicht an (AADSTS7000215/7000222). Niemand kommt über Microsoft herein – auch keine erneute Bestätigung. | Neues Geheimnis mit einem lokalen Admin oder dem Notfall-Admin eintragen ([Abgelaufenes Geheimnis](#entra-geheimnis-abgelaufen)). |
| Die Anmeldung mit Microsoft ist fehlgeschlagen. | Der Austausch mit Microsoft danach scheiterte: falsche Plattform, Token ungültig, Graph nicht erreichbar oder ohne Berechtigung (bei mehr als 200 Gruppen). | Log ansehen ([Diagnose](#entra-diagnose)). |
| Microsoft hat die Anmeldung abgebrochen oder abgelehnt. | Microsoft schickte einen Fehler zurück, z. B. abgebrochene Anmeldung, fehlende Zustimmung, Conditional Access. | Anmeldeprotokoll in Entra prüfen; Zustimmung erteilen. |
| Dein Konto ist in keiner Gruppe, die Zugang zu Cobe News gibt. | Anmeldung bei Microsoft klappte, aber keine zugeordnete Gruppe passt. | Person in eine zugeordnete Gruppe aufnehmen oder Gruppe zuordnen; Gruppenanspruch prüfen ([Schritt 4](#entra-gruppenanspruch)). |
| Dein Konto ist deaktiviert. | Ein Admin hat das Konto in Cobe News deaktiviert. | Unter *Benutzer & Rollen* wieder aktivieren. |
| Ein anderes Konto hat schon diesen Benutzernamen – wende dich an einen Admin. | Ein lokales Konto heißt schon wie der UPN der Person. Ein Verzeichniskonto übernimmt nie ein lokales. | Lokales Konto umbenennen oder löschen. |
| Die Anmeldung mit Microsoft passt nicht zu diesem Browser – bitte erneut versuchen. | Das Anmelde-Cookie fehlt oder passt nicht – oft, weil Cobe News unter einer anderen Adresse als `BASE_URL` geöffnet wurde. | Cobe News unter der `BASE_URL`-Adresse öffnen. |
| Die Anmeldung mit Microsoft hat zu lange gedauert – bitte erneut versuchen. | Zwischen Start und Rückkehr lagen mehr als 10 Minuten. | Neu starten. |
| Gerade laufen zu viele Anmeldungen – bitte gleich noch einmal. | Mehr als 30 Anmeldestarts von einer Adresse in 10 Minuten (bei einer [geteilten Adresse](#geteilte-adressen) 300). | Kurz warten. |
| Die Anmeldung mit Microsoft ist ausgeschaltet. | Der Schalter ist aus oder Mandant, Client-ID oder Geheimnis fehlen. | Einstellungen prüfen und speichern. |
| Deine Adresse ist wegen zu vieler Fehlversuche vorübergehend gesperrt (bei IPv6 das ganze /64-Netz). | Die Adresse ist geblockt, bei IPv6 ihr /64-Netz ([Sperren](#sperren)). | Warten oder `SHARED_ADDRESSES` prüfen. |
| Microsoft hat für diese Anmeldung keinen zweiten Faktor nachgewiesen, und für dein Konto ist in Cobe News keiner eingerichtet. … | Ein zweiter Faktor ist Pflicht, das Token widerspricht (Kontext fehlt, `amr` ohne „mfa“), und das Konto hat keinen TOTP ([MFA-Nachweis](#entra-mfa-nachweis)). | Conditional Access prüfen: Greift die Richtlinie mit MFA für dieses Konto und – mit Kontext – für den Authentifizierungskontext? Anmeldeprotokoll in Entra ansehen. |

### Wo die Ursache steht {#entra-diagnose}

**Log von Cobe News** – Fehler beim Austausch mit Microsoft stehen mit dem AADSTS-Code im Log:

```bash
cd /opt/cobe-news
docker compose logs app | grep -i entra
```

Eine Zeile wie `entra token endpoint 401: … AADSTS7000215 …` nennt den Code. Schickt Microsoft den Browser mit einem
Fehler zurück, steht im Log nur dessen Kurzname (z. B. `access_denied`).

**Anmeldeprotokolle in Entra** – *Identität → Überwachung und Integrität → Anmeldeprotokolle*, nach der Anwendung
„Cobe News“ filtern. Dort stehen Code und Grund jeder abgelehnten Anmeldung, auch für Conditional Access.

## Gruppen → Rollen {#gruppen-rollen}

AD- und Entra-Konten bekommen ihre Rolle **nur** über Gruppen. Die Zuordnung liegt unter
[Einstellungen → Benutzer & Rollen](/settings/users?tab=mapping), Reiter *Rollen-Zuordnung*.

1. Unter *Gruppe zuordnen* das **Verzeichnis** wählen: „Active Directory“ oder „Entra ID“. Es muss vorher eingerichtet
   und gespeichert sein.
2. Unter **Gruppe suchen** den Namen tippen – gesucht wird live im Verzeichnis (AD: voller DN, Entra: Objekt-ID).
3. Die Gruppe in der Liste anklicken, die **Rolle** wählen („Leser“ oder „Admin“).
4. „… zuordnen“ klicken – verlangt eine [erneute Bestätigung](#erneut-bestaetigen).

Regeln:

- **Ohne passende Gruppe kein Zugang.** Es gibt keine Standardrolle. Bei AD scheitert die Anmeldung wie mit falschem
  Passwort, bei Entra erscheint „Dein Konto ist in keiner Gruppe, die Zugang zu Cobe News gibt.“
- **Admin gewinnt**: Passen eine Admin- und eine Leser-Gruppe, wird das Konto Admin.
- Die Rolle wird **bei jeder Anmeldung und stündlich** neu bestimmt ([Abgleich](#abgleich)). Ändert sie sich, enden
  alle älteren Sitzungen des Kontos – eine Leser-Sitzung wird nie still zur Admin-Sitzung.
- AD: Mit *Verschachtelte Gruppen* zählen auch Gruppen in Gruppen. Entra: Das Token bzw. Graph liefert alle Gruppen,
  auch verschachtelte.
- Eine Zuordnung entfernen (Papierkorb-Symbol): siehe [Zuordnung entfernen](#gruppen-entfernen).
- Die Rolle eines Verzeichniskontos lässt sich in der Benutzerliste nicht von Hand ändern – sie folgt der Gruppe.

> [!TIP]
> Lege für Cobe News eigene Gruppen an (z. B. „Cobe News Admins“ und „Cobe News Leser“). Dann ist im Verzeichnis
> sichtbar, wer Zugang hat, und niemand bekommt ihn zufällig über eine große Abteilungsgruppe.

### Zuordnung entfernen {#gruppen-entfernen}

Das Papierkorb-Symbol fragt nach, nennt vorher, wie viele Konten betroffen sind, und hat den Schalter **„Betroffene
sofort abmelden“** (Standard: an). Verlangt eine [erneute Bestätigung](#erneut-bestaetigen).

- **An**: Die Konten der Gruppe werden sofort neu bewertet – anhand der Gruppen, die Cobe News bei ihrer letzten
  Anmeldung bzw. beim letzten Abgleich gespeichert hat. Das Verzeichnis wird dafür nicht gefragt; ein Ausfall von DC oder
  Microsoft hält die Änderung also nicht auf.
  - Wer **keine Rolle mehr** hat, wird ausgeschaltet (*Keine Rollen-Gruppe mehr*) und sofort abgemeldet.
  - Wer **vom Admin zum Leser** wird, wird sofort abgemeldet und meldet sich als Leser neu an.
  - Wer über **eine andere Zuordnung oder ein Team dieselbe Rolle** behält, bleibt angemeldet.
  - Wer angemeldet ist, aber noch **keine gespeicherten Gruppen** hat (zuletzt vor diesem Update angemeldet und seitdem
    nicht abgeglichen), könnte seinen Zugang nur über diese Gruppe haben: Er wird vorsorglich abgemeldet, seine Rolle
    bestimmt die nächste Anmeldung bzw. der nächste Abgleich.
- **Aus**: wie bisher – die Rollen ändern sich beim nächsten stündlichen Abgleich. Ist das Verzeichnis dann nicht
  erreichbar, gelten laufende Sitzungen bis zu ihrem Ende (Standard: höchstens 12 Stunden).

Lokale Konten und der Notfall-Admin sind nie betroffen. **Hängt dein eigener Admin-Zugang an der Gruppe**, lässt sich die
Zuordnung nicht entfernen – du würdest dich aussperren. Entferne sie dann mit einem anderen Admin-Konto, z. B. dem
Notfallkonto.

## Automatische Anmeldung und Freigabe {#freigabe}

Ganz oben unter [Einstellungen → Anmeldung](/settings/auth) steht der Schalter **„Automatische Anmeldung über AD/Entra
ID zulassen“**. Er gilt für AD/LDAP und Entra ID zusammen; lokale Konten und der Notfall-Admin sind nie betroffen.
Ändern verlangt eine [erneute Bestätigung](#erneut-bestaetigen) und steht im Protokoll.

- **An** (Standard, wie bis 0.1.51): Wer in einer zugeordneten Gruppe – oder einer [Team](#teams)-Gruppe – ist, meldet
  sich sofort an. Nach dem Update ändert sich nichts.
- **Aus**: Ein Admin entscheidet, wer hineinkommt.
  - **Neue Konten warten.** Vorab geladene, bei der Anmeldung entstandene und von einem Team geladene Konten stehen
    unter [Benutzer](/settings/users) als *Wartet auf Freigabe*, der Schalter *Aktiv* ist aus. „Freigeben“ (oder den
    Schalter einschalten) schaltet das Konto mit der Rolle ein, die seine Gruppen gerade geben – als Admin nur mit
    erneuter Bestätigung. „Ablehnen“ lässt es dauerhaft aus (*Vom Admin gesperrt*). Kein Abgleich, kein Team und keine
    Anmeldung schaltet ein wartendes Konto ein.
  - **Aufstieg zum Admin wartet.** Kommt ein freigegebener Leser in eine Admin-Gruppe, bleibt er Leser und die Zeile
    zeigt *Aufstieg zum Admin wartet auf Freigabe*. „Aufstieg freigeben“ (erneute Bestätigung) macht ihn zum Admin, seine
    Sitzungen enden; „Bleibt Leser“ fragt nicht wieder, solange er in der Admin-Gruppe ist.
  - **Absenken und Ausschalten bleiben automatisch.** Raus aus der Admin-Gruppe, gelöscht, deaktiviert oder in keiner
    Gruppe mehr – das geschieht sofort wie bisher ([Abgleich](#abgleich)).
  - **Anmeldung eines wartenden Kontos**: Erst nach dem richtigen AD-Passwort bzw. der erfolgreichen Anmeldung bei
    Microsoft erscheint „Konto wartet auf Freigabe durch einen Admin.“ – mit falschem Passwort sieht es aus wie immer.
    Wer noch kein Konto hat, bekommt dabei eines (*Wartet auf Freigabe*), damit Admins es sehen.
  - **Freigabe gehört zur Verzeichnis-ID** (AD: `objectGUID`, Entra: Objekt-ID), nie zum Namen. Wird ein Konto im
    Verzeichnis gelöscht und mit gleichem Namen neu angelegt, wartet das neue wieder. Ein Konto, das nie angemeldet war,
    vom Abgleich ausgeschaltet wurde und jetzt zurückkommt, wartet ebenfalls; eines, das schon in Gebrauch war, kommt wie
    bisher von selbst wieder.

Was beim **Umschalten** geschieht, sagt „Speichern“ vorher:

- **An → Aus**: Alle Verzeichniskonten, die schon aktiv sind, bleiben aktiv (die Zahl steht im Dialog). Nur neue
  warten.
- **Aus → An**: Wartende Konten und Aufstiege werden **nicht** still eingeschaltet. Der Dialog nennt, wie viele warten,
  und bietet **„Auch alle wartenden freigeben“** an (Standard: aus). Eingeschaltet wird jedes Konto mit der Rolle seiner
  Gruppen, jede Freigabe einzeln im Protokoll; der Dialog warnt, wenn dabei jemand Admin wird.

Wartet etwas, zeigt *Benutzer & Rollen* in der Einstellungs-Navigation eine Zahl, und die Benutzerliste hat den Filter
„Wartet auf Freigabe“.

Im [Protokoll](/settings/audit): *Konto wartet auf Freigabe*, *Konto freigegeben*, *Freigabe abgelehnt*, *Aufstieg zum
Admin wartet auf Freigabe*, *… freigegeben*, *… abgelehnt*, *Anmeldung abgewiesen – Konto wartet auf Freigabe*; das
Umschalten als *Anmeldung konfiguriert*. Wartende Konten und Freigaben sind unter „Nur Auffälliges“ markiert.

### Mitglieder vorab laden {#vorab-laden}

Die Mitglieder **jeder zugeordneten Gruppe** (Leser und Admin, AD/LDAP und Entra ID; verschachtelte Gruppen
wie bei der Anmeldung – bei AD nur mit *Verschachtelte Gruppen*) lädt Cobe News selbst – sobald eine Zuordnung hinzukommt oder entfernt wird und dann stündlich mit dem
[Abgleich](#abgleich). So stehen sie unter [Benutzer](/settings/users) schon vor der ersten Anmeldung, als *Noch nie
angemeldet*: ohne Passwort und ohne Sitzung. Das geschieht unabhängig vom Schalter oben – an sind sie sofort aktiv, aus
warten sie auf die Freigabe.

- Wer sich noch nie angemeldet hat, wird hier auf Stand gehalten: Name, Anzeigename, E-Mail, Rolle (Admin, wenn eine
  seiner Gruppen Admin gibt) und an/aus wie im Verzeichnis. Wer sich einmal angemeldet hat, folgt der Anmeldung und dem
  stündlichen Abgleich.
- **Datensparsam**: Ein Konto, das **nie angemeldet** war und in **keiner zugeordneten Gruppe und keinem Team** mehr ist,
  wird **gelöscht** – nicht nur ausgeschaltet. Nur wenn alle zugeordneten Gruppen seines Verzeichnisses gelesen werden
  konnten (eine Gruppe, die nicht lesbar ist, ändert nichts), nie ein Konto, das ein Admin gesperrt oder abgelehnt hat,
  und nie eines mit laufender Anmeldung. Konten, die sich je angemeldet haben, werden wie bisher nur ausgeschaltet.
  Das Protokoll behält, wer gelöscht wurde (*Konto gelöscht*, Grund „nie angemeldet, in keiner zugeordneten Gruppe
  mehr“).
- Große Gruppen werden wie bei Teams in Paketen zu 500 Konten geschrieben; eine Gruppe darf höchstens 50 000 Mitglieder
  haben. Im Protokoll steht pro Lauf ein Eintrag *Mitglieder der zugeordneten Gruppen geladen*; einzelne Einträge
  (wartende, gelöschte Konten) höchstens 200 pro Lauf, der Rest gezählt.
- Ein lokales Konto gleichen Namens wird nie übernommen (*Name schon vergeben*).
- **Entra ID** braucht dafür `GroupMember.Read.All` und `User.Read.All` – dieselben
  [API-Berechtigungen](#entra-api-berechtigungen) wie Teams. Ohne sie bleibt die Gruppe ungelesen und es ändert sich
  nichts.

## Stündlicher Abgleich {#abgleich}

Einmal pro Stunde fragt Cobe News für jedes AD- und Entra-Konto das Verzeichnis:

- **Gelöscht, deaktiviert oder in keiner zugeordneten Gruppe mehr** → das Konto wird deaktiviert, alle Sitzungen enden
  sofort. In der Benutzerliste steht der Grund: *Nicht mehr im Verzeichnis*, *Im Verzeichnis deaktiviert* oder *Keine
  Rollen-Gruppe mehr*.
- **Wieder aktiv und in einer Gruppe** → ein vom Abgleich deaktiviertes Konto wird wieder eingeschaltet. Ein Konto, das
  ein Admin deaktiviert oder [dauerhaft gesperrt](#benutzer-verwalten) hat, bleibt aus, ein *wartendes* Konto ebenso
  ([Freigabe](#freigabe)).
- **Andere Gruppe, höhere Rolle bei ausgeschalteter automatischer Anmeldung** → der Aufstieg zum Admin wartet auf die
  [Freigabe](#freigabe); absenken geschieht sofort.
- **Andere Gruppe, andere Rolle** → die Rolle folgt; alle Sitzungen enden, die neue Rolle gilt ab der nächsten
  Anmeldung.
- **Umbenannt** → Konten werden an ihrer ID erkannt, nicht am Namen. Der neue Name (AD: `sAMAccountName`, Entra: UPN)
  folgt bei der nächsten Anmeldung, bei AD auch im Abgleich. Der Name eines im Verzeichnis gelöschten Kontos wird frei,
  damit ein neu angelegtes Konto gleichen Namens sich anmelden kann.
- **Verzeichnis nicht erreichbar** → der Abgleich ändert **nichts**. Ein Ausfall von DC oder Microsoft sperrt niemanden
  aus.

Lokale Konten – vor allem der Notfall-Admin – berührt der Abgleich nie. Für Entra braucht er beide
[API-Berechtigungen](#entra-api-berechtigungen); ohne sie wird er übersprungen und Änderungen greifen erst bei der
nächsten Anmeldung.

### AD oder Entra ID ausschalten {#verzeichnis-ausschalten}

Schaltest du unter [Einstellungen → Anmeldung](/settings/auth) *Active Directory / LDAP* oder *Entra ID* aus, fragt
„Speichern“ vorher nach: Es nennt, wie viele Konten dieser Anmeldeart gerade angemeldet sind, und hat den Schalter
**„Betroffene sofort abmelden“** (Standard: an). An: Alle Sitzungen dieser Konten enden sofort. Aus: Sie laufen bis zu
ihrem Ende weiter. Die Konten selbst bleiben erhalten; nach dem Wiedereinschalten melden sie sich wie gewohnt an.

Bist du **selbst** mit einem Konto dieser Anmeldeart angemeldet, lässt sie sich nicht ausschalten – du könntest dich
danach nicht mehr anmelden. Melde dich mit einem lokalen Admin-Konto an (z. B. dem Notfallkonto) und schalte sie von dort
aus aus.

Mit [Teams](#teams) lädt der Abgleich zuerst die Mitglieder aller gebundenen Gruppen, dann die der zugeordneten Gruppen
([vorab laden](#vorab-laden)), dann prüft er die Konten wie oben.
Konten, die ein Team geladen hat und die sich noch nie angemeldet haben, fragt er nicht einzeln ab – sie haben keine
Sitzung, und die erste Anmeldung prüft ohnehin alles.

## Teams {#teams .admin}

Teams fassen Personen zusammen, die sich um dieselben Produkte kümmern. Ein Team ist an eine oder mehrere Gruppen aus AD
oder Entra ID gebunden; seine Mitglieder sehen unter [Vendor News](/docs/vendor-news#mein-team) mit „Mein Team“ nur die
Produkte des Teams, und eine Benachrichtigungsregel lässt sich auf die Produkte von Teams beschränken
([Regeln](/docs/benachrichtigungen#regel-teams)). Teams ist **standardmäßig aus** – solange es aus ist, ändert sich für
niemanden etwas.

### Einschalten {#teams-einschalten}

1. [Einstellungen → Teams](/settings/teams?tab=settings), Reiter *Einstellungen*.
2. **Teams einschalten** – verlangt eine [erneute Bestätigung](#erneut-bestaetigen), denn ab jetzt dürfen die
   Mitglieder aller Team-Gruppen lesen. Ausschalten verlangt sie ebenso.
3. Optional die **Willkommens-Mail** einschalten ([unten](#teams-willkommen)).

Voraussetzung: AD/LDAP oder Entra ID ist eingerichtet. Für Entra braucht die App-Registrierung `GroupMember.Read.All`
**und** `User.Read.All` als Anwendungsberechtigungen ([Schritt 5](#entra-api-berechtigungen)).

### Team anlegen und Gruppen binden {#teams-gruppen}

1. Reiter *Teams* → **Team anlegen**, Name und optional eine Beschreibung.
2. In der Schublade *Gruppen*: Verzeichnis wählen, Gruppe live suchen, anklicken, **binden** (erneute Bestätigung).
   Gruppen aus der [Rollen-Zuordnung](#gruppen-rollen) stehen schon oben unter *Aus der Rollen-Zuordnung* – mit ihrer
   Rolle daneben und ohne die, die schon am Team hängen. Der Suchtext filtert auch sie. Die Rolle ändert sich durchs
   Binden nicht.
3. Die Mitglieder werden **sofort** im Hintergrund geladen – die Gruppe zeigt „Wird geladen …“, danach „N Personen
   geladen“. Danach hält der [stündliche Abgleich](#abgleich) sie aktuell; *Jetzt laden* unter *Mitglieder* lädt
   sofort neu.

Verschachtelte Gruppen zählen mit: AD sucht mit `LDAP_MATCHING_RULE_IN_CHAIN` (OID `1.2.840.113556.1.4.1941`) seitenweise,
Entra liest `transitiveMembers` (nur Benutzer) seitenweise. Eine Gruppe hat höchstens 50 000 Mitglieder.

- Wer **aus der Gruppe genommen** oder wessen **Gruppe gelöst** wird, verlässt das Team beim nächsten Laden (beim Lösen
  sofort).
- Wer dabei in **keiner Team-Gruppe mehr** ist und sich **nie angemeldet** hat, wird automatisch deaktiviert – unter
  *Benutzer* steht dann „Kein Team mehr“. Kommt die Person wieder in eine Team-Gruppe, ist das Konto beim nächsten Laden
  wieder aktiv. Wer sich schon angemeldet hat, verliert den Zugang mit dem [stündlichen Abgleich](#abgleich), wenn ihm
  keine Gruppe mehr eine Rolle gibt.
- Kann eine Gruppe **nicht gelesen** werden (Verzeichnis nicht erreichbar, fehlende Berechtigung), bleibt das Team, wie
  es ist – ein Ausfall leert kein Team. Der Grund steht an der Gruppe.
- Ist Teams aus, kannst du Teams und Gruppen schon vorbereiten; die Gruppe zeigt „Wartet – Teams ist ausgeschaltet“.

### Mitglieder und Rollen {#teams-mitglieder}

- Geladene Personen erscheinen sofort unter [Benutzer](/settings/users) als AD- bzw. Entra-Konto mit *Noch nie
  angemeldet*, bis sie sich zum ersten Mal anmelden. Ein lokales Konto gleichen Namens wird nie übernommen. Ist die
  [automatische Anmeldung](#freigabe) aus, warten neue Team-Konten auf die Freigabe (die Willkommens-Mail geht erst
  danach).
- Eine Team-Gruppe gibt die Rolle **Leser**. Ist jemand auch in einer Admin-Gruppe der
  [Rollen-Zuordnung](#gruppen-rollen), wird er Admin – Admin gewinnt. Teams ist ein zusätzlicher Weg zum Lesen, nur
  solange Teams eingeschaltet ist; es gibt weiterhin keine Standardrolle.
- **Lokale Konten** fügst du unter *Mitglieder* von Hand hinzu. Ihre Rolle ändert sich dadurch nicht.
- Teams ausschalten: Wer nur über ein Team Zugang hatte, verliert ihn beim nächsten Abgleich. Geladene Konten, die sich
  nie angemeldet haben, werden sofort deaktiviert („Teams ausgeschaltet“) und nach dem Wiedereinschalten wieder aktiv.

### Sperren {#teams-sperren}

Unter [Benutzer](/settings/users) schaltest du ein Konto mit dem Schalter *Aktiv* aus – auch eines, das sich noch nie
angemeldet hat. Das gilt als Sperre durch einen Admin: Weder das Laden der Gruppen noch der stündliche Abgleich schalten
es wieder ein; die Person bleibt Mitglied, kann sich aber nicht anmelden. Hat Teams das Konto schon selbst ausgeschaltet
(*Kein Team mehr*, *Teams ausgeschaltet*), steht der Schalter bereits auf aus – dann sperrt „Weitere Aktionen →
Dauerhaft sperren“ es so, dass es auch bei der Rückkehr in eine Team-Gruppe aus bleibt. **Lösche** ein geladenes Konto
nicht, solange die Person in der Gruppe ist – das nächste Laden legt es wieder an. Sperren statt löschen.

### Produkte {#teams-produkte}

Unter *Produkte* wählst du die [gefolgten Produkte](/docs/vendor-news#produkten-folgen) des Teams; ein Produkt kann zu
mehreren Teams gehören. Wird einem Produkt nicht mehr gefolgt (gelöscht), verschwindet es aus allen Teams. Ein Team,
auf das eine Regel beschränkt ist, lässt sich erst löschen, wenn die Regel geändert ist. Wer im Team welches Produkt
bekommt, legst du darunter fest ([Wer bekommt was?](#teams-zuteilung)).

### Wer bekommt was? {#teams-zuteilung}

Unter *Produkte* hat jedes zugeordnete Produkt den Schalter **Alle im Team** (ab Werk an): Dann bekommt jedes Mitglied
die News dazu. Schaltest du ihn aus, wählst du die Personen selbst – zum Beispiel „Anna und Ben bekommen Palo Alto, Anna
und Cem bekommen Cisco“:

1. [Einstellungen → Teams](/settings/teams), Team öffnen, Bereich *Produkte*.
2. Beim Produkt **Alle im Team** ausschalten.
3. **Person hinzufügen**, Namen suchen, anklicken. Gewählte Personen stehen als Chips da; das × nimmt sie wieder heraus.
4. **Speichern**.

- Wählbar sind nur Mitglieder des Teams.
- Ist niemand gewählt, steht da „Niemand bekommt die News zu diesem Produkt.“
- Wer das Team verlässt (Gruppe, Abgleich oder von Hand), verliert auch seine Auswahl.
- Unter *Mitglieder* steht bei jeder Person, welche Produkte sie bekommt.
- Die Auswahl gilt für „Mein Team“ in [Vendor News](/docs/vendor-news#mein-team) und für die
  [persönlichen Benachrichtigungen](#teams-persoenlich). Wer ein Produkt neu bekommt, erhält dessen Meldungen ab jetzt –
  keine älteren.

### Weiterleitungs-Kanal {#teams-weiterleiten}

Mitglieder können eine Meldung oder einen Befund mit Kommentar „ans Team weiterleiten“
([An mein Team weiterleiten](/docs/benachrichtigungen#weiterleiten)). Wohin das geht, legst nur du fest:

1. [Einstellungen → Teams](/settings/teams), Team öffnen, Bereich *Allgemein*.
2. Unter **Weiterleitungs-Kanal** einen der bestehenden [Kanäle](/docs/benachrichtigungen#kanaele) wählen, *Speichern*.

Ab Werk ist kein Kanal gewählt – dann ist Weiterleiten für das Team aus. Leser sehen nur, *dass* es einen Kanal gibt,
nicht welchen. Wird der Kanal gelöscht, hat das Team keinen mehr. Der Kanal sendet wie bei den Regeln (dieselben
Prüfungen der Ziele); Weiterleiten ändert aber nichts an seiner Pause oder seinem letzten Fehler.

### Persönliche Benachrichtigungen {#teams-persoenlich}

Jede Person kann sich die Vendor News **ihrer** Produkte selbst schicken lassen
([Hersteller-News meiner Produkte](/docs/benachrichtigungen#meine-produkte)). Welche Wege es gibt, entscheidest du unter
[Einstellungen → Teams](/settings/teams?tab=settings), Reiter *Einstellungen*, Abschnitt **Persönliche
Benachrichtigungen**. Jeder Weg ist **standardmäßig aus**:

| Weg | Was geschieht | Voraussetzung |
|---|---|---|
| E-Mail | eine Mail an die Adresse aus dem Konto | ein eingerichteter [E-Mail-Server](/docs/benachrichtigungen#e-mail) |
| Desktop | ein Push an die Browser der Person, auch bei geschlossenem Tab | Web Push auf dem Server (`WEB_PUSH`) |
| Microsoft Teams | eine Karte an den eigenen Workflows-Webhook der Person | ausgehend https zu Microsoft |

- Solange ein Weg aus ist, bekommt niemand etwas darüber; die Person sieht „Vom Admin ausgeschaltet“. Was in dieser Zeit
  dazukam, wird beim Einschalten nicht nachgeschickt.
- Ist Teams ausgeschaltet, gibt es keine persönlichen Benachrichtigungen.
- Für den Teams-Webhook einer Person gelten nur Adressen von Microsoft (`*.logic.azure.com`, `*.powerplatform.com`,
  `*.webhook.office.com`, https, Port 443) und nur öffentliche Ziele. `WEBHOOK_HOSTS` und `WEBHOOK_PRIVATE_NETS` gelten
  hier nicht.
- Die Schalter brauchen keine erneute Bestätigung – sie ändern nicht, wer lesen darf.
- **Security-Meldungen nach eigener Auswahl** (ab Werk aus): Ist der Schalter an, kann sich **jede Person** – auch ohne
  Team – Security-Meldungen nach eigener Auswahl per E-Mail oder an ihren Teams-Webhook schicken lassen
  ([Security-Meldungen per E-Mail oder Teams](/docs/benachrichtigungen#security-meldungen)), auf den Wegen *E-Mail*
  und *Microsoft Teams* oben. Desktop hat dafür die eigenen [Desktop-Benachrichtigungen](/docs/benachrichtigungen#desktop).
  Solange der Schalter aus ist, kommt nichts, und beim Einschalten kommt nichts Älteres nach. Die Änderung steht im
  Protokoll („Einstellungen geändert“).

### Abwesenheit eintragen {#teams-abwesenheit}

Im Team, Reiter **Mitglieder**, trägt das Kalender-Symbol einer Person deren
[Abwesenheit](/docs/benachrichtigungen#abwesenheit) ein: von–bis, eine **Vertretung aus diesem Team** und optional
„Trotzdem auch an mich“. Es gelten dieselben Regeln wie bei der Person selbst. Die Liste zeigt „Abwesend bis … –
vertreten durch …“ und einen Hinweis, wenn die Vertretung dann selbst abwesend ist.

### Wochenrückblick {#teams-wochenrueckblick}

Im Team, Reiter **Wochenrückblick**, schaltest du eine kurze E-Mail pro Woche zu den Produkten des Teams ein
(**standardmäßig aus**): Wochentag, Uhrzeit und Zeitzone (ab Werk Montag 08:00, *Europe/Berlin*).

- Sie geht nur an Mitglieder, die sie unter
  [Hersteller-News meiner Produkte](/docs/benachrichtigungen#wochenrueckblick) selbst einschalten, deren Konto aktiv
  ist und die eine E-Mail-Adresse haben. Der Reiter zeigt, wie viele das sind.
- Eingeschaltet oder verschoben gilt ab dem nächsten Termin – die laufende Woche wird nicht nachgeschickt.
- Pro Team, Person und Woche genau einmal, auch nach einem Neustart. Nach einem Ausfall höchstens die letzte verpasste
  Woche.
- Ohne eingerichteten [E-Mail-Server](/docs/benachrichtigungen#e-mail) zeigt der Reiter einen Hinweis, und es wird
  nichts versucht.
- Höchstens 200 Mails pro Runde; ein großes Team bekommt den Rückblick über einige Minuten.

### Willkommens-Mail {#teams-willkommen}

Eigener Schalter, **standardmäßig aus**. Ist er an, bekommt jede **neu geladene** Person genau **eine** E-Mail über den
eingerichteten [E-Mail-Server](/docs/benachrichtigungen#e-mail): dass sie Cobe News nutzen kann, die Adresse
`{{base_url}}` und wie sie sich anmeldet – nie ein Passwort.

- Nie zweimal – auch nicht nach einem Neustart, erneutem Laden oder wenn das Konto gelöscht und wieder geladen wird.
- Ohne E-Mail-Adresse im Verzeichnis wird die Person übersprungen; die Benutzerliste zeigt *Keine E-Mail*.
- Wer geladen wurde, während der Schalter aus war, bekommt keine Mail.
- Ist kein E-Mail-Server eingerichtet, warten die Mails. Lehnt der Server die Verbindung ab, versucht Cobe News es
  später erneut; bei einem Fehler, nach dem die Mail angekommen sein könnte (z. B. Zeitüberschreitung), nicht – die
  Benutzerliste zeigt dann *Willkommens-Mail fehlgeschlagen*.
- Höchstens 50 Mails pro Minute; ein großes Team bekommt seine Mails über einige Minuten.

## Sitzungen & Sperren {#sitzungen}

Sitzungen liegen auf dem Server; der Browser hält nur ein zufälliges Token in einem Cookie (HttpOnly, Secure,
SameSite=Lax). Abmelden beendet die Sitzung sofort.

### Zeitlimits {#sitzungen-zeitlimits}

[Einstellungen → Anmeldung](/settings/auth), Karte *Sitzungen*:

| Einstellung | Bereich | Standard |
|---|---|---|
| Abmelden nach Inaktivität | 5–480 Minuten ohne Aktion | 60 Minuten |
| Spätestens neu anmelden nach | 1–72 Stunden, auch bei Aktivität | 12 Stunden |
| Startpasswort gültig für | 1–30 Tage ab Vergabe eines temporären Passworts ([Anlegen](#benutzer-anlegen)) | 7 Tage |

Ein kürzeres Limit gilt sofort auch für laufende Sitzungen. Speichern verlangt eine
[erneute Bestätigung](#erneut-bestaetigen).

Als Aktivität zählt nur, was die Person selbst tut (eine Seite öffnen, klicken, speichern). Automatische
Aktualisierungen im Hintergrund – Zähler, neue Meldungen, Desktop-Benachrichtigungen, der Stand einer laufenden
Sicherung – halten die Sitzung nicht offen: Ein offen stehender Tab wird nach der eingestellten Zeit abgemeldet.

### Alle Tabs gemeinsam {#sitzungen-tabs}

Die Tabs eines Browsers teilen sich eine Sitzung (ein Cookie) und stimmen sich ab: Abmelden in einem Tab, eine
abgelaufene Sitzung (Inaktivität oder Höchstdauer) oder eine von einem Admin beendete – jeder Tab geht zur Anmeldung,
verwirft die geladenen Daten und schließt offene Dialoge. Nach dem Abmelden zeigen die anderen Tabs „Abgemeldet – in
einem anderen Tab.“, nach dem Ablauf „Deine Sitzung ist abgelaufen“. Meldet man sich in einem Tab an (auch mit Passkey
oder über Microsoft), laden Tabs, die auf der Anmeldeseite stehen, und sind wieder drin.

- **Ablauf ohne Klick:** Der Server nennt den Tabs die Restzeit der Sitzung. Jede Anfrage, die du in einem Tab
  auslöst, gilt für alle (so wie der Server „zuletzt aktiv“ höchstens alle 5 Minuten schreibt). Kurz nach dem
  errechneten Ende fragt ein Tab nach (`GET /api/auth/session`) – diese Nachfrage verlängert die Sitzung nicht. Wird ein Tab wieder sichtbar, fragt er
  sofort nach; so fällt auch eine inzwischen beendete Sitzung auf.
- **Warnung:** Zwei Minuten vor dem Ablauf wegen Inaktivität erscheint „Deine Sitzung läuft bald ab“ mit der Uhrzeit.
  *Angemeldet bleiben* ist eine normale Anfrage und verlängert die Sitzung; Schließen in einem Tab schließt die Warnung in
  allen. Vor der Höchstdauer gibt es keine Warnung – sie lässt sich nicht verlängern.
- **Was die Tabs austauschen:** nur das Ereignis und Zeiten (BroadcastChannel, in älteren Browsern ein Eintrag im
  localStorage) – kein Token, nichts über die Person.
- Andere Browser und Geräte haben eigene Sitzungen und bleiben unberührt. Eine andere Adresse (etwa der Notzugang
  `http://localhost:8096`, [`APP_PORT`](/docs/betrieb#env-adresse)) ist für den Browser ein eigener Bereich mit eigener
  Sitzung: Ihre Tabs stimmen sich nur untereinander ab.

### Meine Sitzungen {#meine-sitzungen}

Jede Person sieht unter *Profil & Sicherheit → Meine Sitzungen* ihre laufenden Sitzungen und meldet eine oder alle
anderen ab ([Abmelden und Sitzungen](/docs/erste-schritte#abmelden)). Angezeigt werden Browser und System (grob aus dem
User-Agent), die Anmeldeart, Beginn, zuletzt aktiv und die **volle IP-Adresse** – es sind die eigenen Daten der Person.
„Zuletzt aktiv“ schreibt Cobe News höchstens alle 5 Minuten, nicht bei jeder Anfrage. Auch begonnene Anmeldungen
(Passwort richtig, Code fehlt noch) erscheinen, markiert.

Ein Admin sieht und beendet die Sitzungen jedes Kontos über „Weitere Aktionen“ → „Sitzungen & Passkeys“: eine einzelne
oder mit „Alle Sitzungen beenden“ alle (die eigene aktuelle Sitzung bleibt). Beides verlangt eine
[erneute Bestätigung](#erneut-bestaetigen). Eine beendete Sitzung ist sofort weg – die nächste Anfrage dieses Browsers
wird abgelehnt.

Sitzungen enden außerdem von selbst bei: Passwortänderung (alle anderen), Zurücksetzen von Passwort oder TOTP durch
einen Admin, Rolle ändern, Deaktivieren oder Sperren (alle) und Entfernen eines Passkeys (die damit angemeldeten).

Ist [Zweiten Faktor auf dem Gerät merken](#geraet-merken) an, steht darunter *Gemerkte Geräte*: wo die Anmeldung nach
dem Passwort nicht nach dem Code fragt – mit „Dieses Gerät“, seit wann, bis wann, zuletzt genutzt. „Vergessen“ für
eins, „Alle Geräte vergessen“ für alle. „Alle anderen abmelden“ vergisst sie ebenfalls.

### Erneut bestätigen {#erneut-bestaetigen}

Heikle Änderungen verlangen, dass du dich in den letzten **10 Minuten** ausgewiesen hast – die Anmeldung selbst zählt
dazu (nicht die über ein [gemerktes Gerät](#geraet-merken) ohne Code). Betroffen sind:

- **Anmeldung und Konten:** Anmelde-Einstellungen (AD, Entra, Sitzungen), Rollen-Zuordnungen, einen Admin anlegen, eine
  Rolle ändern, ein Admin-Konto aktivieren oder deaktivieren oder seine E-Mail-Adresse ändern, Passwort oder TOTP eines
  anderen zurücksetzen, ein Konto [dauerhaft sperren](#benutzer-verwalten) oder die Sperre aufheben, ein Konto löschen,
  einen Passkey hinzufügen oder entfernen, die Sitzungen eines anderen beenden.
- **[Teams](#teams):** Teams ein- oder ausschalten, eine Gruppe an ein Team binden oder lösen, ein Team mit gebundenen
  Gruppen löschen.
- **Betrieb:** [API-Tokens](/docs/api#token-anlegen) anlegen oder widerrufen, den [Export](/docs/sicherung#export)
  herunterladen, bei der [Aufbewahrung](/docs/sicherung#aufbewahrung) weniger Sicherungen behalten (ältere werden sofort
  gelöscht).

- **Lokale und AD-Konten**: Ein Dialog „Bestätigen, dass du es bist“ fragt nach dem Passwort und – falls eingerichtet –
  dem aktuellen Code aus der App. Danach wird die Änderung ausgeführt.
- **Entra-Konten**: „Bei Microsoft bestätigen“ – Microsoft fragt die Anmeldung erneut ab. Danach kommst du zurück und
  führst die Änderung noch einmal aus. Scheitert die Bestätigung, zeigt Cobe News „Bestätigung bei Microsoft
  fehlgeschlagen“ mit dem Grund. Ist das Clientgeheimnis abgelaufen, geht das nicht mehr – siehe
  [Abgelaufenes Geheimnis](#entra-geheimnis-abgelaufen). Der zweite Faktor wird geprüft wie bei der Anmeldung
  ([MFA-Nachweis](#entra-mfa-nachweis)): Hat das Konto den eigenen TOTP, fragt der Dialog zuerst nach dem Code, dann geht
  es zu Microsoft. Ohne Nachweis und ohne Code: „Die Bestätigung bei Microsoft hat keinen zweiten Faktor nachgewiesen.“
- Fünf falsche Bestätigungen beenden die Sitzung (das Konto selbst wird dadurch nicht gesperrt).

### Fehlversuche und Sperren {#sperren}

- **Konto**: 5 Fehlversuche in 15 Minuten sperren das Konto für 15 Minuten; bei wiederholten Sperren länger (bis
  2 Stunden). Ein Admin hebt die Sperre unter *Benutzer & Rollen* mit „Sperre aufheben“ auf. Ein gesperrtes AD-Konto
  wird gar nicht erst am DC geprüft – die Sperre in Cobe News zählt nicht gegen die Sperrrichtlinie eures AD.
- **Adresse**: Erst 30 Fehlversuche über mindestens 5 verschiedene Namen in 15 Minuten (Password Spraying) blocken eine
  Adresse für 30 Minuten. Tippfehler einer Person sperren nur deren Konto.
- **IPv6 zählt je /64-Netz**: Ein Anschluss bekommt meist ein ganzes /64 mit unzählig vielen Adressen. Deshalb zählen
  und sperren alle Adressen eines /64 gemeinsam (z. B. `2001:db8:1:2::/64`). IPv4 zählt je einzelner Adresse, eine
  IPv4-mapped IPv6-Adresse (`::ffff:192.0.2.1`) wie die IPv4-Adresse. Eine [geteilte Adresse](#geteilte-adressen)
  zählt immer für sich allein.
- **Neustart**: Die Zähler (Fehlversuche bisher) liegen nur im Speicher – ein Neustart leert sie. Laufende **Sperren**
  von Konten und Adressen dagegen überstehen ihn: Cobe News schreibt jede in die Datenbank (Tabelle `auth_locks`) und
  liest beim Start die noch laufenden zurück. Abgelaufene verschwinden beim Start und stündlich, höchstens 10 000 werden
  aufgehoben. „Sperre aufheben“ entfernt auch den gespeicherten Eintrag.
- Fehlversuche zählen je Herkunft getrennt: Eine abgelehnte AD-Anmeldung sperrt nie das gleichnamige lokale Konto.
- Jeder Fehlversuch verzögert die nächste Prüfung ein wenig.
- Der Notfall-Admin wird nie gesperrt ([Notfall-Admin](#notfall-admin)).
- **Fehlgeschlagene CSRF-Prüfung**: Ein schreibender Aufruf ohne oder mit falschem CSRF-Token (eine fremde Seite, ein
  Skript – der Browser mit Cobe News schickt es immer mit) wird abgelehnt und als Warnung ins Log der App geschrieben
  („csrf check failed“, mit Methode, Pfad und Adresse bzw. /64-Netz, nie mit Token oder Cookie). Höchstens eine Zeile
  pro Adresse und Minute; was dazwischen kam, zählt die nächste Zeile mit.

### Geteilte Adressen {#geteilte-adressen}

Die Client-Adresse kommt vom mitgelieferten nginx. Eine **geteilte Adresse** – das Docker-Gateway (unter Docker
Desktop kommen alle Clients von dort), ein [Reverse Proxy](term:reverseproxy) davor oder eine Adresse aus
`SHARED_ADDRESSES` – wird nie geblockt; Spraying über sie wird stattdessen gebremst (3 Sekunden je Fehlversuch), einzelne
Konten sperren wie immer.

Sitzen viele Kolleginnen und Kollegen hinter einem Büro-NAT, trage dessen Adresse in der `.env` ein (kommagetrennt, auch
Netze in [CIDR](term:cidr)-Schreibweise) und starte die App neu:

```bash
SHARED_ADDRESSES=192.0.2.10,198.51.100.0/24
```

Läuft ein eigener Proxy vor Cobe News, muss er die echte Client-Adresse weitergeben – sonst teilen sich alle die
Adresse des Proxys. Siehe [Reverse Proxy](/docs/betrieb#reverse-proxy).
