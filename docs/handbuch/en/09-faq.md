---
title: Troubleshooting & FAQ
summary: Answers to common questions – what to do when news is missing, notifications do not arrive, sign-in fails or the server causes trouble.
audience: all
---

## Questions from readers {#leser}

### I see no news at all {#keine-news}

- If the page says "News are switched off", nobody has switched the news on yet. Only an admin can do that – ask one.
  Out of the box the news are off, so the server fetches nothing before someone has chosen the sources.
- If it says "Nothing new", you have read everything. Read stories are in the "Read" tab.
- If a filter or a search is active, the page shows only matching stories. "Reset filter" shows all again.
- Right after switching on, stories appear only after the first fetch round.

More: [Reading news](/docs/news-quellen#news-lesen) and [New and Read](/docs/erste-schritte#gelesen).

### Why is a story "High" or "Critical"? {#warum-hoch}

Cobe News rates every story by fixed rules – by the [CVSS](term:cvss) score, the rating of an authority or vendor, signs
of active exploitation (e.g. in the [KEV](term:kev) catalog) or of ransomware. Open the story: the section "Estimated
by rules" says which rule applied. The rating is a hint for the order, not an assessment of your own risk.

More: [Severity](/docs/news-quellen#schwere).

### Why does a story appear twice – or "also at"? {#doppelt}

Cobe News shows a story only once if it has the same address (without tracking additions) or the same title within
3 days. The same CVE from CISA KEV, ENISA EUVD and the BSI warnings appears only once within 30 days; the other sources
are then listed on the story as "also at …".

If two outlets report on the same event with different titles, those are two stories – Cobe News does not recognise
that they are about the same thing.

### Desktop notifications do not appear {#desktop-kommt-nicht}

Check in this order:

1. *Settings → Notifications*: is "Desktop notifications" switched on and saved?
2. If "Permission" says "Blocked", the browser has blocked notifications for this site. Allow them in the browser's
   site settings, then reload the page.
3. Choose "Test notification". If it does not arrive, the operating system is the cause: allow notifications for the
   browser in the system settings, switch off focus or "Do not disturb".
4. With the tab closed, only "Push with the tab closed" helps, together with a certificate your computer trusts. If
   it says "Not available", the card names the reason – usually the certificate. Then ask an admin to distribute it.
   The open tab still notifies.
5. Notifications only work through the https address.

More: [Desktop notifications](/docs/benachrichtigungen#desktop).

### On the Mac I do not see the notifications {#macos-hauptdisplay}

macOS shows notifications only on the main display. If you work with several screens, they may appear on one you are
not looking at. Make the screen you want the main display: *System Settings → Displays*, choose the screen, "Use as:
Main display".

### Vendor News says "Possibly affected" – what does that mean? {#moeglicherweise-betroffen}

The data about this vulnerability is not enough for a certain answer. Typical reasons:

- The vendor or the NVD does not name the affected versions clearly.
- The version entered is too coarse, e.g. `11.2` instead of the exact version. It then covers several releases that
  are affected differently. With the exact version the answer becomes certain.

More: [Rating](/docs/vendor-news#bewertung) and [Entering versions](/docs/vendor-news#versionen).

### What does “Please review” on a version mean? {#bitte-pruefen}

Nobody confirmed or changed the version for longer than the set period (90 days by default). Cobe News does not know
whether it still runs – only you do. If it still runs like this: “Confirm”. Otherwise change the version. The members
of the product's teams and the admins may confirm. More: [Reviewing versions](/docs/vendor-news#versionen-pruefen).

### A product is missing from the catalogue {#produkt-fehlt}

*Vendor News* → **⋯ → Suggest a product** (or “Product missing? Suggest it” in the catalogue) – an admin adds it. More:
[Suggesting a product](/docs/vendor-news#produkt-vorschlagen).

“VMware vSphere” is two products in the catalogue: **VMware vCenter Server** and **VMware ESXi** – the version from
the VAMI (`8.0.3.00400`) or the build is taken. More: [VMware vSphere](/docs/vendor-news#vmware-vsphere).

A product that was in the catalogue twice so far (e.g. IBM Db2, Omnissa Horizon, Juniper SRX) is there once since
0.1.45 – followed products moved along. More: [Merged products](/docs/vendor-news#zusammengelegte-produkte). Citrix
bulletins come through the CVE data, not as a source of their own: [Citrix and NetScaler](/docs/vendor-news#citrix).

### Why was I suddenly signed out? {#abgemeldet}

A session ends after a time without activity and at the latest after a fixed maximum – out of the box after 60 minutes
idle or 12 hours. An admin can change both. Your session also ends when an admin resets your password or TOTP or when
your role changes. Just sign in again.

### Forgot the password or lost TOTP {#passwort-vergessen}

There is no self-service. Contact an admin:

- **Local account:** the admin resets the password and/or TOTP. You get a temporary password and choose your own at
  the next sign-in.
- **Active Directory or Microsoft account:** the password belongs to your directory – contact your IT. For Microsoft
  accounts, Microsoft itself asks for the second factor.

More: [Your own account](/docs/erste-schritte#eigenes-konto).

### I get no vendor news of my products {#keine-hersteller-news}

Check in this order, under *Settings → Notifications*:

1. **No tab *Vendor news of my products*?** Then *Teams* is switched off or you are in no team (and watch no CVE).
   Only an admin can change that.
2. **"No product is assigned to you yet."** An admin decides in the team who gets which product.
3. **"Switched off by the admin"** at a way: an admin has not allowed this way.
4. **Way switched on and saved?** E-mail needs an address in your account. Desktop needs "Push with the tab closed" in
   at least one browser (tab *New stories*). Teams needs a workflow URL – "Send test" shows whether it works.
5. **Only what is new:** older messages, the first check of a product and anything your filter (kind, severity) left
   out never come.
6. **Quiet hours or "Collected at …":** normal messages wait until the quiet hours end or until that time.
7. **Absence:** in that time everything goes to the deputy – unless "Also to me" is on.

Under each way you see when something was last delivered, or the last error with the next attempt.

More: [Vendor news of my products](/docs/benachrichtigungen#meine-produkte).

### "Forward to team" is missing or greyed out {#weiterleiten-geht-nicht}

- **The button is missing:** *Teams* is switched off or you are in no team.
- **The button is greyed out:** an admin has not set a forward channel for any of your teams – the tooltip says so.
  Only an admin chooses the channel, in the team under *General*.
- **A message says when it works again:** at most 10 forwards per hour and person, the same story to the same team only
  once in 10 minutes.
- **The channel rejected the message:** then an admin should check the channel.

More: [Forward to my team](/docs/benachrichtigungen#weiterleiten).

### Why is a finding at "Now"? {#warum-sofort}

The [urgency](/docs/vendor-news#dringlichkeit) is a number from 0 to 100 made of fixed points: severity, EPSS, KEV or
actively exploited, your version, whether a fix exists, and age. From 60 it is *Now*, from 35 *Soon*. Hover over the
number – the tooltip shows every factor with its points. A critical vulnerability that affects your version is always
*Now*; a version that is not affected always stays below 35.

More: [How it is computed](/docs/vendor-news#dringlichkeit-formel).

### A product is missing under "My team" {#mein-team-fehlt}

"My team" shows only the products you get through your teams. If one is missing, it is not assigned to your team, or
only chosen people in the team get it and you are not one of them. An admin changes both in the team under
*Products*. Until then, *All* shows every followed product.

More: [My team](/docs/vendor-news#mein-team).

## Questions from admins {#admin .admin}

### The browser warns about the certificate {#zertifikatswarnung}

Out of the box Cobe News uses a self-signed certificate. Browsers warn until the computer trusts it.

- Download the certificate in *Settings → HTTPS & certificate* and mark it as trusted on all computers – again after
  every renewal ([distributing](/docs/betrieb#zertifikat-verteilen)).
- Or use a certificate from your own CA ([own certificate](/docs/betrieb#eigenes-zertifikat)).
- If the browser warns although the certificate is trusted: does the name in the address bar match "Valid for"? The
  page *HTTPS & certificate* shows a hint when the certificate does not cover the name from `BASE_URL` or has expired.

### Colleagues cannot reach the page {#kollegen-erreichen-nicht}

- `BIND` is `127.0.0.1` out of the box – then the page can only be reached on the server. Set `BIND=0.0.0.0`.
- The server's firewall must open the port from `PORT` (8095 out of the box) to the company network.
- The DNS name must point to the server, and `BASE_URL` must be exactly that address.
- After changes to the `.env` run `docker compose up -d` – a `restart` does not apply them.

Step by step: [Address for colleagues](/docs/betrieb#fuer-kollegen).

### A channel reports "Target not allowed" {#ziel-nicht-erlaubt}

Notification channels (including the generic [webhook](term:webhook)) post only to public addresses out of the box.
Since version 0.1.22 this also applies to targets in the company network, e.g. an n8n at a `10.…` address.

1. Put the target's address or network into the `.env`, e.g. `WEBHOOK_PRIVATE_NETS=10.20.0.5/32`.
2. `docker compose up -d`.
3. Choose "Test" in the channel.

With an entry, private addresses, the own Docker networks and the Docker host work – the latter only by its address,
never by a name like `host.docker.internal`. Always blocked, even with an entry, are loopback (`127.0.0.1`, `::1`),
link-local including cloud metadata (`169.254.169.254`), "any" (`0.0.0.0`) and multicast. A service that listens only
on the server's `127.0.0.1` is reached through the Docker host's address, not through `127.0.0.1`. More:
[Targets](/docs/benachrichtigungen#webhook-ziele).

### Signing in with Microsoft shows an AADSTS error {#entra-aadsts}

The number after "AADSTS" says what does not match in Entra. The most common ones with their fix:
[Entra errors](/docs/anmeldung#entra-fehler).

### After changing BASE_URL, signing in with Microsoft no longer works {#base-url-entra}

The redirect URI depends on `BASE_URL`. Microsoft then usually reports AADSTS50011. In the app registration in Entra,
under *Authentication*, change the redirect URI to this value – exactly, without a trailing slash:

```
{{redirect_uri}}
```

More: [Redirect URI](/docs/anmeldung#entra-redirect-uri).

### A source is "dead" or "disturbed" {#quelle-tot}

- **disturbed:** 3 failures in a row, an error that is not just temporary (wrong address, unreadable answer,
  certificate), or an unreadable answer in the last 24 hours. The source pauses until the next attempt.
- **dead:** the source refuses fetches (401, 403 or 410 twice in a row), its address no longer exists (404 three
  times), no fetch has worked for 14 days or – for news – no new story has come for 60 days.

In *Settings → Integrations → Health* a click on the source shows its history and the last error. If many sources are
affected at once, the cause is usually the outbound network (proxy, firewall, DNS) – see
[outbound data](/docs/integrationen#ausgehende-daten). A single dead source has often changed its address: adjust an
own source or switch it off.

More: [Source health](/docs/news-quellen#quellen-gesundheit).

### The backup failed {#sicherung-fehlgeschlagen}

*Settings → Backup & export* shows the reason under "Last backup" and the technical message below it.

| Message | What to do |
|---|---|
| Another backup was already running. | Not an error – wait until it is done. |
| The passphrase is too short | Set `BACKUP_PASSPHRASE` with at least 12 characters. |
| pg_dump did not answer in time / failed | Is the database running (`docker compose ps -a`)? Is there enough disk space? Read the app's log. |

If the backup runs by cron, the result is in its log file; an exit code other than 0 means "not backed up".
More: [Backup](/docs/sicherung#jetzt-sichern) and [cron](/docs/sicherung#cron).

### I am locked out {#ausgesperrt}

- **An account is locked** (5 failed attempts in 15 minutes): the lockout ends by itself after 15 minutes. Another
  admin can lift it at once under *Settings → Users & roles* with "Unlock".
- **No admin can get in any more:** sign in with the emergency admin. It is never locked by failed attempts, and it
  does not depend on Active Directory or Entra.
- **The emergency admin's password is gone too:** reset it on the server ([next question](#notfall-totp-verloren)).

More: [Emergency admin](/docs/anmeldung#notfall-admin).

### The emergency admin's TOTP or password is lost {#notfall-totp-verloren}

On the server:

```bash
cd /opt/cobe-news
docker compose exec app python -m app.cli reset-emergency
```

The command prints a temporary password, removes the TOTP, ends all sessions of the emergency admin and lifts a
lockout. Sign in with the temporary password, choose a new password and set up TOTP again. Keep the new credentials
offline, e.g. in a password vault.

### Emails do not arrive {#mails-kommen-nicht}

1. *Settings → Channels & rules*, tab *Channels*, row *Mail server*: "Edit", then "Send test mail". The message names
   the kind of error (refused, no connection, TLS …).
2. If the test mail arrives but no stories do: does a rule match? Check severities, sources and language. A new rule
   applies only to stories that arrive after it ([Rules](/docs/benachrichtigungen#regeln)).
3. If the channel shows an error and a next attempt, it pauses after failures. "Test" checks it at once.
4. If the [SMTP](term:smtp) relay is on the Docker host itself, Cobe News refuses it as an internal target. Put its
   address (the container's gateway, e.g. `172.31.250.1`, or with Docker Desktop the address behind
   `host.docker.internal`) into `SMTP_ALLOW_INTERNAL`, then `docker compose up -d`. `127.0.0.1` never works – that
   would be the container itself.
5. Check the recipients' spam folder.

### Vendor News shows nothing {#vendor-news-leer}

- Without a followed product, Vendor News queries nothing. First follow products from the catalogue under
  *Vendor News* ([Following products](/docs/vendor-news#produkten-folgen)).
- The first fetch takes a while. Without an NVD API key the [NVD](term:nvd) allows only few requests; a free key
  speeds this up ([Setting up Vendor News](/docs/integrationen#vendor-news)).
- Look in *Settings → Integrations → Health* whether the Vendor News queries work.

### I changed the .env, but nothing happens {#env-wirkt-nicht}

Changes to the `.env` only take effect when the containers are recreated: `docker compose up -d` in the install
folder. `docker compose restart` keeps the old values.

### The app does not start {#app-startet-nicht}

1. `docker compose ps -a` shows which container is missing or restarting.
2. `docker compose logs db-init` – if it fails, the app does not start. Most common reason: `POSTGRES_PASSWORD` in
   the `.env` was changed. Put the old password back ([Database](/docs/betrieb#db-rollen)).
3. `docker compose logs --tail 100 app` – after an update it shows e.g. an error in the migration.

### Where do I find the logs? {#wo-logs}

```bash
cd /opt/cobe-news
docker compose logs -f app
```

Which container for what: [Logs](/docs/betrieb#logs).

### A team group shows "Group not readable" {#team-gruppe-fehler}

The group names the reason; until then the team stays as it is – an outage never empties a team.

| Reason | What to do |
|---|---|
| The directory refuses the search | check the rights of the AD/LDAP service account |
| Microsoft Graph refuses access (403) | give the app registration `GroupMember.Read.All` as an application permission, with admin consent ([Step 5](/docs/anmeldung#entra-api-berechtigungen)) |
| Graph returns ids without names | the same for `User.Read.All` |
| The directory is not set up or switched off | set up and switch on AD/LDAP or Entra ID under *Settings → Sign-in* |
| The group has more than 50,000 members | bind a smaller group |
| The group was not found | the group was deleted in the directory – unbind it and bind the right one |

Then "Load now" under *Members*. More: [Creating a team and binding groups](/docs/anmeldung#teams-gruppen).

### The restore test failed {#ruecksicherungs-test-fehlgeschlagen}

*Settings → Backup & export*, tab *Restore test*, names a code. The most common ones:

- `not_configured` – `POSTGRES_RESTORE_PASSWORD` is missing in the `.env`: `scripts/setup-env.sh`, then
  `docker compose up -d`.
- `passphrase` – the backup is encrypted with a passphrase only the cron job knows: let the host start the test
  ([By host cron](/docs/sicherung#ruecksicherungs-test-host)).
- `no_backup` – there is no backup yet: "Back up now".

Every code with its remedy: [What is checked](/docs/sicherung#ruecksicherungs-test-pruefungen).

### A script gets 401 with its API token {#token-401}

The 401 (`invalid_token`) deliberately does not say why. The reason is under *Settings → API & metrics*, tab *Tokens*,
in the column *State*: expired, revoked or orphaned (the admin who made it is no longer an active admin). In every
case, make a new token and revoke the old one. If it is active, the token does not arrive correctly: exactly
`Authorization: Bearer cnt_…`, without a session cookie and never in the URL.

More: [Errors and limits](/docs/api#fehler).

### How do I report a problem? {#problem-melden}

These details help the search:

- the version from the user menu, *Version & changelog* (here: {{version}}),
- what you did and what you expected,
- time and text of the error message,
- the matching lines from `docker compose logs --since 1h app`.

Before passing them on, remove setup tokens, temporary passwords, webhook URLs and other secrets from logs and
screenshots. Never send the `.env`.
