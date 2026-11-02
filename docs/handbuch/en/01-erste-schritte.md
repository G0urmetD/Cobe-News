---
title: Getting started
summary: What Cobe News does, where the stories come from, who may do what and how to find your way around the interface.
audience: all
---

## What is Cobe News? {#was-ist-cobe-news}

Cobe News collects security news in one place. The server fetches public sources regularly, rates every story and
shows it to you as a tile – each story only once, even when several sources carry it.

The stories come from these kinds of sources:

| Kind | Examples |
|---|---|
| Authorities & CERTs | BSI, CERT-EU, CERT.at, NCSC UK |
| Vulnerability catalogs | [CISA KEV](term:kev), [ENISA EUVD](term:euvd), Microsoft Patchday |
| Vendor advisories ([PSIRT](term:psirt)) | Fortinet, Palo Alto Networks, Cisco, Siemens, Veeam |
| Research | Cisco Talos, Microsoft Threat Intelligence, Unit 42 |
| Press | heise, golem.de, BleepingComputer, The Hacker News |

An admin decides which sources are switched on. The full list is under
[Built-in sources](/docs/news-quellen#eingebaute-quellen).

What Cobe News does for you:

- **Rates the severity** – every story gets a level from *Info* to *Critical*, with the reasons
  ([how it is rated](/docs/news-quellen#schwere)).
- **Merges duplicates** – the same story from several sources appears once, with "also at …".
- **Remembers what you have read** – per person, see [New and Read](#gelesen).
- **Notifies** – as a desktop notification in the browser or (set up by admins) by e-mail, Teams, Slack, Discord,
  Telegram or webhook, see [Notifications](/docs/benachrichtigungen#ueberblick). If you are in a team, also personally
  with the vendor news of your products.
- **Checks your systems** – in [Vendor News](/docs/vendor-news#ueberblick), the vulnerabilities that affect exactly
  the products and versions you run.

> [!NOTE]
> Cobe News reads public sources only. It does not query any of your systems – admins enter the products and versions
> you run in Vendor News themselves.

## News and Vendor News {#news-und-vendor-news}

The sidebar has the two main pages under *Analysis & knowledge*:

| | News | Vendor News |
|---|---|---|
| Question | What is happening in the security world right now? | Does a vulnerability affect our systems? |
| Content | Stories of all switched-on sources | Vulnerabilities, new versions and end of support for the products you follow |
| Based on | Feeds and catalogs | Vendor advisories, [NVD](term:nvd), CISA KEV, endoflife.date |
| Number in the sidebar | unread stories (your own) | products a vulnerability affects (red: one of them is actively exploited) |
| Read state | per person | – |

**News** is the broad overview: everything the sources publish. **Vendor News** is the focused view of your own
environment: an admin picks the products you run from the catalogue and enters the versions, and Cobe News checks
every version on its own – *affected*, *possibly affected* or *not affected*.

The two pages work together: when you follow a product, a matching news story shows "Affects your systems".
More in the chapter [Vendor News & catalogue](/docs/vendor-news#ueberblick).

Below them, the third entry is [*Watched CVEs*](/watch): your personal list of single CVEs you follow – even without a
team and without a followed product ([Watching CVEs](/docs/benachrichtigungen#cves-beobachten)).

## Roles {#rollen}

There are two roles. Yours is shown at the bottom of the sidebar under your name.

| Role | may |
|---|---|
| **Reader** | read News and Vendor News, mark stories read/unread, set up their own desktop notifications, watch CVEs, subscribe to the end of support as a calendar, manage their own password and second factor. In a team also: receive the vendor news of their own products (with quiet hours, absence and weekly review) and forward stories to the team |
| **Admin** | in addition everything under *Settings*: sources and integrations, following products in Vendor News and entering versions, notification channels and rules, users and roles, teams, sign-in (AD, Entra ID), HTTPS, backup, API tokens and metrics |

- A second factor ([TOTP](term:totp)) is required for admins, optional but recommended for readers.
- Readers see no *Settings* entry in the sidebar. They reach their personal pages through the user menu:
  *Profile & security* opens the settings, and *Notifications* sits next to it on the left under *Personal*.
- What you get through a team is only there once an admin has switched *Teams* on and put you in a team (usually
  through a group in the directory).
- If you sign in with Active Directory or Entra ID, your group in the directory decides the role
  ([Groups and roles](/docs/anmeldung#gruppen-rollen)).

## Read and unread {#gelesen}

Whether you have read a story counts **per person** – what you read stays unread for your colleagues. This holds for
the stories under *News* and for the findings under *Vendor News*
([Vendor News: read, muted, views](/docs/vendor-news#vendor-lesen)).

- **Unread** shows as a dot in front of the title and a bold title.
- **Opening marks it read.** The story stays in the list, only the dot goes.
- The tick at the top right of the tile (or "Mark as read" in the story) marks it without opening. Once read, the same
  button (the arrow) sets it back with **"Mark as unread"**. A notice at the bottom offers "Undo".
- The switch **"Unread only"** hides everything read – work through the list like an inbox.

**All at once:** "Mark all read" marks every unread story that currently matches the search and filters. A dialog asks
first and says how many there are. Whatever arrives afterwards stays unread.

**Read by themselves:** whatever arrived more than **30 days** ago counts as read. A new account starts with everything
read – nobody begins with thousands of unread stories. Only what you explicitly set to "Mark as unread" stays unread,
also when it is older.

> [!TIP]
> Filter by severity first (e.g. *Info* and *Low*), then "Mark all read" – that clears away the unimportant ones and
> the important stories stay.

The numbers next to *News* and *Vendor News* in the sidebar show your unread stories and findings (from 100 on as
"99+"). What you [muted](/docs/benachrichtigungen#stummschalten) does not count there.

## Interface {#oberflaeche}

### Sidebar {#seitenleiste}

- **News**, **Vendor News** and **Watched CVEs** at the top, **Settings** at the bottom (admins only), your **user
  menu** at the very bottom.
- The button at the top left of the header collapses and expands the sidebar (keyboard: Ctrl+B or ⌘+B). Collapsed,
  only the icons remain.

### User menu {#benutzermenue}

A click on your name at the bottom of the sidebar opens:

| Entry | What for |
|---|---|
| *Profile & security* | name, password, second factor – see [Your account](#eigenes-konto) |
| *Language* | Deutsch or English |
| *Appearance* | Light, Dark or System (follows the operating system's setting) |
| *Documentation* | this handbook – chapters and sections for admins are shown to admins only |
| *Version & changelog* | which version is running and what has changed |
| *Sign out* | ends the session in this browser |

Language and appearance are remembered by the **browser**, not your account. On another computer you choose them
again. Cobe News does not translate the stories themselves – they appear in the source's language.

> [!TIP]
> Mention the number from *Version & changelog* when something behaves differently after an update. This installation
> is currently running version {{version}}.

### Search and filters {#suche-filter}

Above the tiles of the news page:

- **Search box** ("Title, text, CVE …") – searches title, summary and CVE numbers; upper/lower case and accents do not
  matter.
- **Source** and **Severity** – multiple choice, e.g. only *Critical* and *High* from two particular sources.
  "Reset filter" clears both.
- **Unread only** and **Show muted** – two switches below.
- The filters are part of the page's address: a bookmark or a shared link opens exactly this choice.

Details about tiles and stories: [Reading news](/docs/news-quellen#news-lesen).

### Views {#ansichten}

A filter choice you need often is saved as a **view** – on *News* and on *Vendor News*, up to 30 per page, names up to
60 characters. The **Views** button next to the filters opens the list:

| Action | Effect |
|---|---|
| Enter a name, *Save* | the current filters under this name |
| Click on the name | apply the view's filters |
| Star | this page's **default**: opens when you open the page without a filter (e.g. from the sidebar) |
| Pencil, bin | rename, delete |
| *Copy link* | the address with the filters – whoever opens it sees the same filters |

Views belong to your account and work on every computer. A shared link carries only the filters, not the view itself;
what the recipient sees depends on their own read state.

### Times {#zeitangaben}

Times are shown relative ("5 minutes ago"). Hover over one to see local time and UTC – with a button that copies the
UTC timestamp (handy for tickets and reports).

### Links to a story {#links}

An open story is part of the browser's address. You can copy that address and pass it on – whoever opens it (and is
signed in) sees the same story. Desktop notifications and links in e-mails open a story the same way.

## Your account {#eigenes-konto}

Under *Profile & security* (user menu or [directly](/settings/profile)) you manage your account.

### Change your password {#passwort}

Local accounts only. If you sign in with Active Directory, change the password there; with Microsoft (Entra ID),
Microsoft manages it.

1. Open *Profile & security* and choose "Change password".
2. Enter the current password and the new one, "Save".
3. Other browsers you are signed in to are signed out.

Rules for the new password: at least 12 characters, not too common, not the user name and not the current password.

### Second factor (TOTP) {#totp}

The second factor is a 6-digit code from an authenticator app (e.g. Microsoft Authenticator). It is required for
admins and optional for readers.

1. Open *Profile & security*, tab *Sign-in & security*, and click "Authenticator app" under *Second factor*.
2. Confirm it is you with your password.
3. Scan the QR code in the app (or type in the key).
4. Enter the code shown.

"Set up again" moves it to a new phone; the old key stays valid until you confirm the first new code. Readers can
switch the second factor off again with "Remove". When you sign in with Microsoft, Microsoft asks for the second
factor itself – then there is nothing to set up here.

> [!WARNING]
> Lost your phone? An admin can reset your second factor
> ([Local users](/docs/anmeldung#lokale-benutzer)).

### Passkeys {#passkeys}

With a [passkey](term:passkey) you sign in without a password: your device (laptop, phone or security key) asks for
your fingerprint, face or PIN, and you are in. That counts as two factors – password and TOTP code are not needed. Local
accounts only; with Active Directory or Microsoft you keep signing in there.

1. Open *Profile & security*, tab *Sign-in & security*, and click "Add passkey" under *Passkeys*.
2. Give it a name (e.g. "Laptop") and choose "Create passkey". If you did not sign in just now, you first confirm with
   your password (and code) that it is you.
3. The browser asks for fingerprint, face or PIN – or for a security key or your phone.

Afterwards choose "Sign in with a passkey" on the sign-in page – no user name needed. Up to 10 passkeys per account;
"Rename" and "Remove" are in the list. Removing asks again whether it is you and signs out every session signed in with
that passkey. The passkey stays stored on the device itself until you delete it there.

- Passkeys only work at the configured address ({{base_url}}) and only over HTTPS. At another address (e.g. the
  server's IP address) the button does not appear.
- If a passkey shows *Check*, its counter went backwards – it may have been copied. Remove it and set up a new one.
- Lost the device? Sign in with your password and remove the passkey – or ask an admin to.

### Signing out and sessions {#abmelden}

- *Sign out* in the user menu ends the session in this browser. If you switched on "Push with the tab closed" there,
  that ends for this browser too.
- A session ends when you do nothing for a while (60 minutes by default) and at the latest after a fixed time
  (12 hours by default). Then you sign in again. An admin sets these times ([Sessions](/docs/anmeldung#sitzungen)).
- All tabs together: when you sign out in one tab or the session has expired, every tab of this browser goes to the
  sign-in – also one you are not using right now; what it showed is gone. Two minutes before the inactivity timeout
  "Your session ends soon" appears, *Stay signed in* extends it. Sign in again in one tab and the others are back in
  too ([All tabs together](/docs/anmeldung#sitzungen-tabs)).
- After several wrong passwords the account is locked for a few minutes. The message at sign-in says how many attempts
  are left.
- **My sessions** (*Profile & security*, tab *My sessions*) shows where your account is signed in right now: browser
  and system (roughly read from the browser, otherwise *Unknown device*), the sign-in method (password, password + TOTP,
  passkey, Active Directory, Microsoft), since when, last active (only updated every few minutes) and the full IP
  address. *This session* is the one you are in. "Sign out" ends another session at once, "Sign out all others" all but
  this one. *Sign-in not finished* means: your password was entered there, the code is still missing – if that was not
  you, change your password.

### Desktop notifications {#desktop-kurz}

Under [*Settings → Notifications*](/settings/notifications) you choose what reaches you – this applies to you only. The
page has up to three tabs:

| Tab | What for |
|---|---|
| *New stories* | whether and for which stories your browser notifies you – [Desktop notifications](/docs/benachrichtigungen#desktop) |
| *Vendor news of my products* | only in a team (or with a watched CVE): Vendor News of your products by e-mail, desktop push or Microsoft Teams, with quiet hours, absence and weekly review – [more](/docs/benachrichtigungen#meine-produkte) |
| *Calendar* | the end of support of your versions as a calendar subscription – [Calendar (iCal)](/docs/benachrichtigungen#kalender-ical) |

## What's new {#was-ist-neu}

The most important features of the recent versions at a glance, each with the section that explains it. Every detail
of every version is in the user menu under *Version & changelog*.

| Since | Feature | Where | More |
|---|---|---|---|
| 0.1.26 | **EPSS and SSVC** – how likely a vulnerability is to be exploited, CISA's assessment | findings in Vendor News, a story's details | [EPSS and SSVC](/docs/vendor-news#epss-ssvc) |
| 0.1.28 | **My team / All** – only the products you get through your team | Vendor News, above the overview | [My team](/docs/vendor-news#mein-team) |
| 0.1.30 | **Vendor news of my products** – by e-mail, desktop push or your own Teams webhook | *Settings → Notifications* | [Vendor news of my products](/docs/benachrichtigungen#meine-produkte) |
| 0.1.33 | **Advisory changes** – what a vendor changed afterwards, with the effect on your versions | Vendor News, tab *Changes* in the product | [Changes to advisories](/docs/vendor-news#aenderungen) |
| 0.1.34 | **Watching CVEs** – follow single CVEs, even without a team | star next to the CVE, sidebar *Watched CVEs* | [Watching CVEs](/docs/benachrichtigungen#cves-beobachten) |
| 0.1.34 | **End-of-support warning** – 90 and 30 days ahead | rules and personal ways with *Versions & EOL* | [Warning](/docs/vendor-news#eol-vorwarnung) |
| 0.1.34 | **Calendar (iCal)** – subscribe to the end of support in Outlook & co. | *Settings → Notifications → Calendar* | [Calendar (iCal)](/docs/benachrichtigungen#kalender-ical) |
| 0.1.36 | **Urgency** – a number from 0 to 100 with the level *Now*, *Soon*, *Watch* | cards, list and drawer in Vendor News | [Urgency](/docs/vendor-news#dringlichkeit) |
| 0.1.36 | **Forward to my team** – a story or a finding with a comment | "Forward to team" in a story and a finding | [Forwarding](/docs/benachrichtigungen#weiterleiten) |
| 0.1.36 | **Quiet hours**, **absence with a deputy**, **weekly review** | *Vendor news of my products*, own tabs | [Quiet hours](/docs/benachrichtigungen#ruhezeiten), [Absence](/docs/benachrichtigungen#abwesenheit), [Weekly review](/docs/benachrichtigungen#wochenrueckblick) |

### New for admins {#was-ist-neu-admin .admin}

| Since | Feature | Where | More |
|---|---|---|---|
| 0.1.26 | **More sources**: CSAF advisories of Siemens, Cisco and Schneider Electric, cvelistV5, EPSS, OSV | *Integrations → Vendor News → More sources* | [More sources](/docs/integrationen#weitere-quellen) |
| 0.1.26 | **Safe webhook and SMTP targets** – loopback, the metadata address and multicast always blocked | channels | [Allowed targets](/docs/benachrichtigungen#webhook-ziele) |
| 0.1.28 | **Teams** – bind AD/Entra groups, load members at once, products per team, rules limited to teams | *Settings → Teams* | [Teams](/docs/anmeldung#teams) |
| 0.1.30 | **Who gets what** – products per person; allowing the personal ways | team → *Products*; *Teams → Settings* | [Who gets what?](/docs/anmeldung#teams-zuteilung), [Personal notifications](/docs/anmeldung#teams-persoenlich) |
| 0.1.33 | **Rule kind "Advisory changed"** | *Channels & rules → Rules* | [Kinds](/docs/benachrichtigungen#regel-arten) |
| 0.1.33 | **Block permanently** and **revoke a role at once** | *Users & roles* | [Managing](/docs/anmeldung#benutzer-verwalten), [Removing a mapping](/docs/anmeldung#gruppen-entfernen) |
| 0.1.36 | **Forward channel** and **weekly review** per team, the members' absences | team → *General*, *Weekly review*, *Members* | [Forward channel](/docs/anmeldung#teams-weiterleiten), [Weekly review](/docs/anmeldung#teams-wochenrueckblick) |
| 0.1.37 | **API tokens**, **API reference** and **metrics for Prometheus** | *Settings → API & metrics* | [API & metrics](/docs/api#ueberblick) |
| 0.1.37 | **Restore test** – restore the newest backup weekly as a test | *Backup & export → Restore test* | [Restore test](/docs/sicherung#ruecksicherungs-test) |
