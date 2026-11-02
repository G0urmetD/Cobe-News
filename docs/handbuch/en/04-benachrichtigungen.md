---
title: Notifications
summary: Desktop notifications in the browser for everyone, plus channels (Teams, Slack, Discord, Telegram, Mattermost, ntfy, Gotify, email, webhook), rules and the delivery log for admins.
audience: all
---

## Overview {#ueberblick}

Cobe News reports new stories in two ways:

| | Desktop notifications | Channels & rules |
|---|---|---|
| For whom | each person for themselves (readers and admins) | the team – set up by admins |
| Where to set it up | *Settings → Notifications* | *Settings → Channels & rules* |
| Where to | system notification of this browser | Teams, Slack, Discord, Telegram, Mattermost, ntfy, Gotify, email or an own webhook |
| What | new security stories of the news feed | security stories, Vendor News and the state of the sources |

- **Desktop:** you choose severities and sources. The browser shows new stories as system notifications – in the open
  tab and, if you like, also with the tab closed (Web Push).
- **Channels** say *where* a message goes. **Rules** say *what* goes to which channels. A rule can send to several
  channels, and several rules can use the same channel.

The two are independent: a rule changes nothing about your desktop notifications, and vice versa.

On top of that there are ways that concern only you:

| What | For whom | Where | More |
|---|---|---|---|
| Vendor news of your products – by e-mail, desktop push or Microsoft Teams, with quiet hours, absence and weekly review | members of a team, once an admin has allowed the ways | *Settings → Notifications*, tab *Vendor news of my products* | [Vendor news of my products](#meine-produkte) |
| News about single CVEs (fix, KEV, EPSS, withdrawn) | everybody | star next to a CVE, sidebar *Watched CVEs* | [Watching CVEs](#cves-beobachten) |
| End of support as a calendar subscription | everybody (readers: the products from their team) | *Settings → Notifications*, tab *Calendar* | [Calendar (iCal)](#kalender-ical) |
| Send a story with a comment to your team | members of a team with a forward channel | "Forward to team" in a story and a finding | [Forward to my team](#weiterleiten) |

## Desktop notifications {#desktop}

The settings apply to your account. The state (permission, push) applies to the browser you are using right now.

### Switching them on {#desktop-einschalten}

1. Open Cobe News at its https address, e.g. {{base_url}}.
2. Go to [*Settings → Notifications*](/settings/notifications).
3. Switch on "Desktop notifications". The browser asks for permission – allow it.
4. Choose the **severities** (critical and high by default) and the **sources**. Empty means: all.
5. Click "Save".

Below, the card "State in this browser" shows:

| Row | Meaning |
|---|---|
| Permission | "Granted", "Blocked" or "Not asked yet" (then with the button "Allow in the browser"). |
| Background tab | "Background tab: active" with the time of the last check – or why not (e.g. "Save first"). |
| Push with the tab closed | Switch for Web Push in this browser: "Active", "Off", "Not available" (with the reason) or "Delivery failing". |

If the browser blocked notifications, allow them in the browser's site settings (lock icon in the address bar).

### Open tab and push with the tab closed {#desktop-push}

**Open tab (always):** as long as Cobe News is open in a tab – also in the background, in a minimised window or behind
another app – one of the tabs asks for new stories about once a minute. Each story appears only once, also with several
tabs. A click opens it. If the browser freezes a tab, another one takes over; when you come back, it catches up at once.
Nothing is lost, nothing comes twice – also after a reload.

**Push with the tab closed (optional, per browser):** with the switch "Push with the tab closed" the server sends new
stories through the push service of the browser vendor (Google, Mozilla, Apple, Microsoft). They then arrive even when
no tab is open – as long as the browser is running.

- The content (title, severity, source, link) is encrypted end to end. The push service only sees its size.
- The switch only works once desktop notifications are switched on and saved and the browser does not block them.
- While push is active in this browser, the open tab shows no notifications of its own – there are no doubles.
- At most 10 browsers per person; an eleventh replaces the oldest.
- Signing out switches push off for this browser. A deactivated account gets nothing. A session that merely expired
  does not end push.

For both ways: up to three stories of a round come one by one, more as one summary ("N more new stories"). "Critical"
stays on screen until you dismiss it. Desktop notifications only show security stories of the news feed; Vendor News and
the state of the sources come through channels and rules – the Vendor News of your own products also through
[Vendor news of my products](#meine-produkte).

### Test notification {#desktop-test}

1. Click "Test notification" (only works once permission is granted).
2. Switch to another tab or app. The notification arrives after **5 seconds**.
3. Read the result on the card.

The test takes the same way as real stories: through Web Push when push is active in this browser, otherwise through the
tab. Afterwards the card says:

- "Test delivered" – the browser handed the notification to the system. If you still see nothing, the system settings
  are the cause (see below).
- "The browser refused to show it" – with the browser's reason.
- No answer after 20 seconds – with push, the server probably does not reach the push service (outbound access, proxy,
  firewall), or the browser is offline.

The system settings decide whether and how notifications appear:

- macOS: *System Settings → Notifications →* allow the browser, Focus or "Do Not Disturb" off.
- Windows: *Settings → System → Notifications →* switch the browser on, "Do not disturb" off.

### Prerequisites {#desktop-voraussetzungen}

- **HTTPS.** Notifications only work over https (or localhost).
- **A certificate your computer trusts** – only needed for push. If the browser shows a certificate warning, it refuses
  the service worker. Push is then "Not available"; the open tab still notifies. Fix: mark the certificate as trusted or
  use one of your own CA (see [HTTPS](/docs/betrieb#https)).
- **The server reaches the push services** (outbound https). An admin sets this up, see
  [Web Push](/docs/integrationen#web-push). If Web Push is switched off on the server (`WEB_PUSH=0`), that is shown as
  the reason.
- **The browser is running.** Chrome and Edge usually keep running in the background, Firefox has to be open. Safari
  supports Web Push from macOS 13.

### Tip for macOS: notifications on the main display {#desktop-macos}

macOS shows notifications only on the **main display**. If you work with several screens and see nothing, look at the
other screen – or make the screen you look at the main display:

1. Open *System Settings → Displays*.
2. Choose the screen you want.
3. At "Use as", choose "Main display".

## Vendor news of my products {#meine-produkte}

If you are in a [team](/docs/anmeldung#teams) and products are assigned to you, you can have their Vendor News sent to
you: by **e-mail**, as a **desktop push** or in **Microsoft Teams**. The part is there only while Teams is switched on
and you are in a team – or [watch a CVE](#cves-beobachten).

### Switching it on {#meine-produkte-einschalten}

1. Go to [*Settings → Notifications*](/settings/notifications?tab=vendor), tab *Vendor news of my products*.
2. At the top are **My products** – an admin decides in the team which they are.
3. Switch on the ways you want:
   - **E-mail** goes to the address of your account (shown there). Without one the switch cannot be switched on.
   - **Desktop** uses your browsers with "Push with the tab closed" ([above](#desktop-push)). Switch that on there first.
   - **Microsoft Teams** needs your own Workflows webhook ([below](#meine-produkte-teams)).
4. Choose **what** comes: *Vulnerabilities*, *Versions & EOL* and/or *[Advisory changed](/docs/vendor-news#aenderungen)*,
   and from which **severity** vulnerabilities and advisory changes come. By default *Vulnerabilities* and
   *Versions & EOL* are on, *Advisory changed* is off, and every severity comes.
5. Click "Save".

"Switched off by the admin" at a way means an admin has not allowed it. Under each way that is on you see when
something was last delivered – or the last error and when it is tried again.

### Creating your own Teams webhook {#meine-produkte-teams}

Teams takes the messages through a **workflow** you create yourself. It posts into a chat.

1. In Teams open the **Workflows** app (in the bar on the left, otherwise "…" → *Workflows*).
2. Choose the template **"Send webhook alerts to a chat"** or **"Post to a chat when a webhook request is received"**.
3. Enter a name (e.g. "Cobe News"), confirm the connection with your account and click "Next".
4. Choose the chat the cards should appear in – for example the chat with the Workflows bot – and click "Add workflow".
5. Copy the URL shown.
6. In Cobe News: switch **Microsoft Teams** on, paste the URL into *Workflow URL*, "Save", then **"Send test"**. A test
   card appears in the chat.

> [!NOTE]
> Only Microsoft addresses are accepted: `*.logic.azure.com`, `*.powerplatform.com` and `*.webhook.office.com`, only
> over https (port 443) and only public targets. Cobe News refuses other addresses.

- The URL is a secret: whoever knows it can post into your chat. Cobe News stores it encrypted and afterwards shows only
  its host. To change it you paste a new URL; "Remove URL" deletes it.
- The workflow runs under your account. If it is disabled or you delete the workflow, nothing arrives any more – the
  part then shows the error.
- "Send test" works at most every 10 seconds.

### What comes and when {#meine-produkte-was}

- **Only what is new.** You get what comes after a way was switched on and after the product was assigned. Older news
  and anything from the first check of a product do not come.
- **Filter.** What your filter (kind, severity) left out once does not come later after the filter is changed either.
- **Muted.** What you [muted](#stummschalten) does not come – also not when the mute ends.
- **Collected.** Several stories of one round come together: one mail, one card, one push with "N new vendor news". At
  most 100 per round, the most severe first; the rest comes with the next round.
- **Large teams.** With very many recipients Cobe News spreads the sending over several rounds: at most 2000 messages
  and about 30 seconds per round. Whoever has waited longest comes first. The next round follows right away, and the
  other tasks (news, Vendor News, push) go on in between.
- **Exactly once.** Each story comes at most once per way – also after a restart. If the server refuses (e.g. the mail
  server cannot be reached), Cobe News tries again later with a growing pause. Not after an error after which the
  message may have arrived (e.g. a timeout).
- A click in the message opens the story in [Vendor News](/docs/vendor-news).
- **End of support.** With *Versions & EOL* the [warnings](/docs/vendor-news#eol-vorwarnung) 90 and 30 days before the
  end of support of each version entered of your products come as well.

### Quiet hours and urgent messages {#ruhezeiten}

Under [*Vendor news of my products*](/settings/notifications?tab=vendor&part=quiet), tab **Quiet hours**, you choose
when normal messages should not disturb you. Everything is off by default – then everything comes at once, as before.

- **Quiet hours**: a time window, e.g. 18:00–08:00 (across midnight), and if you like **the whole weekend**. Meanwhile
  normal messages are collected. When the quiet hours end they come as **one** summary per way.
- **Time zone**: *Europe/Berlin* by default. The times apply in this zone – also across the change to and from summer
  time (08:00 stays 08:00 local time).
- **Urgent still comes at once.** You choose what is urgent; all four by default:
  - severity **critical**,
  - added to **[CISA KEV](term:kev)** or actively exploited,
  - an **own version is affected now** (an [advisory change](/docs/vendor-news#aenderungen) with an effect),
  - a **[watched CVE](#cves-beobachten)**.
- **Desktop push** comes only for urgent messages in the quiet hours.
- **Delivery per way**: *At once* (default) or **Collected at HH:MM**. Normal messages on that way then wait for the time
  and come together once a day. If the time does not exist on a day (change to summer time, e.g. 02:30), the collection
  comes right after the gap; if it exists twice, only the first time.

Here too: each message exactly once per way, and what waits does not count against the limits of a round.

### Absence and deputy {#abwesenheit}

When you are away, the vendor news of your products go to a **deputy** – on the deputy's own ways. Enter it under
[*Vendor news of my products*](/settings/notifications?tab=vendor&part=absence), tab **Absence** (like *Weekly review*,
this tab is there only when you are in a team):

1. **From** and **To** (whole days, the end included, in your time zone; one year at most). A start in the past counts
   from now on.
2. Choose the **deputy**. You can choose an active member of one of your teams that gives you products. The deputy gets
   only the products of teams they are a member of themselves; you keep getting the rest.
3. Optionally **Also to me**. Otherwise you get none of it in that time.
4. "Save".

- **Exactly once.** Each message comes exactly once per recipient and way – also when the deputy gets the product
  anyway.
- **No chains.** If the deputy is away too (or switched off, without a way switched on), nothing is passed on. The
  messages then come to you, and the tab shows a hint.
- **Private.** [Watched CVEs](#cves-beobachten) never go to the deputy; they keep coming to you.
- **End.** When the absence ends, everything comes to you again. "End now" ends a running absence at once; what went to
  the deputy in that time does not come to you again afterwards.
- The deputy sees in the same tab for whom they are standing in. An admin can also enter the absence in the
  [team](/docs/anmeldung#teams-abwesenheit).

### Weekly review {#wochenrueckblick}

If an admin switches on the weekly review for your team, you can switch it on for yourself under
[*Vendor news of my products*](/settings/notifications?tab=vendor&part=weekly), tab **Weekly review** (off by default).
It comes once a week by e-mail to the address of your account – from next week on – and sums up the last 7 days of the
team's products:

- new vulnerabilities by severity, the most severe listed,
- own versions affected now,
- [advisory changes](/docs/vendor-news#aenderungen) with an effect on your versions,
- [end of support](term:eol) in the next 90 days,
- new versions,
- each with a link to Cobe News.

It comes exactly once per team and week, also after a restart. After an outage at most the last missed week comes,
never several old ones. Without a mail server set up nothing is attempted.

## Watching CVEs {#cves-beobachten}

Follow a single CVE – independent of teams and followed products. Click the **star** next to a CVE: on a story card
(when it names exactly one CVE), in an opened story and its source details, at a finding in Vendor News or on a product
card of the overview. Or enter the CVE id at the top right of [*Watched CVEs*](/watch) in the sidebar. After the star,
“To the list” in the confirmation goes straight to the CVE in the list.

### All CVEs of a story {#cves-alle}

When a story names many CVEs (a GitLab patch release, say), the opened story shows twelve of them first; **“+ N more
CVEs”** expands the whole list (each with copy and star), **“fewer”** collapses it again. At a finding in Vendor News
it is six.

- **“Watch all (N)”** above the list of CVEs watches all CVEs of the story at once – N are those you do not watch yet.
  A finding in Vendor News with several CVEs has the same button.
- Once you watch all of them, the button says **“Unwatch all”**: it stops watching every CVE of the story (also those
  you watch from elsewhere) – with “Undo” in the confirmation. Undo watches them anew from that moment, each with its
  previous origin.
- **Not enough room:** if not all new ones fit into your list, Cobe News asks first: “Only K left – watch the first K?”
  For a story the ones with the highest [EPSS](term:epss) come first, for a finding its order counts. When the list is
  full, you only get the hint to remove some first.
- “To the list” in the confirmation opens the list grouped by origin, at this story.

**Origin:** every watched CVE remembers where you watch it from – a story (with its title of then), a finding
(product, advisory, title) or “added one by one” (entered on the page). Watching the same CVE later from somewhere else
keeps the **first origin** (and the start) – nothing changes. CVEs you watched before version 0.1.42 have no origin
and are listed under “Added one by one”.

### The watchlist {#cves-liste}

[*Watched CVEs*](/watch) is a watchlist with what Cobe News knows about each CVE right now:

- **Tiles** at the top: *Watched* (of at most 500), *Actively exploited* (in [KEV](term:kev)), *No fix* (a source knows
  the CVE but names no fixed version yet) and *New since your last visit*. A click on a tile filters.
- **Filters** *All · KEV · No fix · EPSS high · New* and **order** *Last change* (default), *Severity*, *EPSS* or *CVE
  number*. “EPSS high” means a percentile from 0.9 – the same threshold from which a notice comes. Filter and order are
  in the address; a bookmark keeps them.
- **Group by** (next to the order, also in the address): **Product** (default), **Origin** or *None*. Each group
  shows its title at the top, the number of CVEs (“3 of 21 CVEs” when a filter hides some) and, briefly, *KEV*, *No
  fix* and *New*. The arrow collapses and expands a group. Filter and order apply within the groups. **“Unwatch
  group”** stops watching every CVE of the group – also those a filter hides right now – and, as for a single CVE,
  “Undo” takes it back (each CVE again with its origin).
  - **Product:** the CVEs by the product they concern – no matter whether you added them by star, with “Watch all” or
    by hand. Watch five CVEs that all concern GitLab and they are listed under *GitLab*. How the product is determined
    is explained [below](#cves-produkt). Groups with KEV or something new come first, then by name; *No product
    assigned* last.
  - **Origin:** the CVEs by the story or finding you watch them from ([origin](#cves-alle)). A click on the title opens
    the story or the finding. The group watched last comes first, *Added one by one* last. Older links with
    `?groups=1` open this grouping.
- **Rows:** the CVE id (copyable) with its title, severity, KEV (since when; ransomware in the tooltip),
  [EPSS](term:epss) (the percentile as a bar) and the first fixed version (“+2”: two more). A CVE no source knows yet
  says “No source knows it yet”.
- **Open a row** (click it or the arrow): the **history** since you started watching, newest first – a fixed version
  appeared (in which advisory), added to KEV, EPSS rose, an advisory withdrawn; at the bottom since when you watch it.
  Below: *Stories (n)* (the story list searching for the CVE), *Open advisory* (the vendor's page, else CSAF or NVD) and
  *Stop watching*. “Undo” in the confirmation takes that back – the CVE is then watched anew from that moment.
- **New since your last visit:** Cobe News remembers when you last opened the list. Whatever happened to a CVE after
  that is marked “New”. The marks stay until you open the page the next time. On your very first visit nothing is new,
  and adding a CVE yourself is no news.
- **Notifications off:** while no personal way is on, a thin line at the top says the list is only a reminder list and
  – where possible – leads to *Switch on a way*.

### Groups by product {#cves-produkt}

Which product a CVE concerns is worked out anew each time the list opens, from what is stored at that moment – in this
order:

1. **Catalogue products** Vendor News has linked the CVE's advisories to. A followed product comes first (the group
   says “Followed”), then the one with the most advisories, then the name. The catalogue's name of today counts – also
   for a [merged or renamed product](/docs/vendor-news#zusammengelegte-produkte); a
   [product outside the catalogue](/docs/vendor-news#eigene-produkte) has the name it was given. The group's title
   opens the product in Vendor News.
2. Else the vendor and product the [CNA](term:cna) names as affected in the CVE record (from cvelistV5, else from the
   NVD's copy) – as given there, case does not matter; “GitLab / GitLab” becomes “GitLab”. The group says “per CNA”.
   When the name is exactly that of a catalogue product, it is that product.
3. Else the vendor and product of the NVD's [CPE](term:cpe), made readable (`a:gitlab:gitlab` is the catalogue product
   GitLab, otherwise e.g. “Microsoft Windows Server 2022”). The group says “per NVD CPE”.
4. Else **No product assigned** – no source names a product yet (a CVE nobody knows yet, for instance).

A CVE that concerns several products is listed under the first; “+ N more products” in its row names the others in a
tooltip. Nothing is stored: when Vendor News links an advisory only hours after you started watching, the CVE is in the
right group the next time the list opens. Without grouping or by origin the product is shown small next to the CVE id.

### When a notice comes {#cves-meldungen}

The question mark next to “Watch” sums it up briefly.

A notice comes when something important happens to the CVE:

| Event | When |
|---|---|
| Fix available | an advisory (vendor, NVD, cvelistV5, OSV, CSAF) names a new fixed version – also through a revision |
| CISA KEV | the CVE is added to the catalogue of actively exploited vulnerabilities |
| EPSS | the percentile reaches **0.9** (among the 10 % likeliest) or the score rises by **0.1** (10 percentage points) since the last notice; at most one notice a day |
| Withdrawn | an advisory about the CVE is withdrawn (e.g. NVD rejects the CVE) |

EPSS has a small margin: once a percentile above 0.9 was reported, the next such notice comes only after it fell below
0.85 – swinging around 0.9 makes no series of notices. The rise by 0.1 counts from the last reported value (or the
lowest value since).

- **Ways.** The notices come on your [personal ways](#meine-produkte-einschalten) – e-mail, desktop, Teams – with the
  same rules: only what is new, exactly once, collected per round, bounded rounds. The filters *kind* and *severity*
  do not apply to watched CVEs – you chose the CVE yourself.
- **Without a team.** Anybody can watch. Whoever is in no team but watches a CVE still sees the tab *Vendor news of my
  products* and can switch on their ways there. An admin allows the ways themselves under *Settings → Teams*; while
  Teams is off there are no personal ways – the list is then a reminder list, and the page says so.
- **Only what is new.** What was true of the CVE when you started watching it (already in KEV, already patched) is not
  reported.
- **Limits.** At most 500 CVEs per person, valid CVE ids only (`CVE-YYYY-NNNN`). Everybody sees and changes their own
  list only. “Watch all” works at most 20 times in five minutes; Cobe News checks the origin itself (the story must be
  visible in the lists, the CVE must be one it names).
- **No extra queries.** Cobe News asks no service extra for watched CVEs. What the sources fetch anyway counts. A CVE
  Cobe News does not know yet stays in the list ("No source knows it yet") and counts as soon as a source brings it.
  EPSS exists only for CVEs of findings and of stories of the last 30 days.

## Mute {#stummschalten}

A product or a CVE is a nuisance right now (a patch is scheduled, a false alarm is settled)? Mute it **for a while**:
for **7 days**, **30 days** or **until a date** (at most a year).

**Where:** in the **⋯** menu of a story or a product tile, at the bottom of a story or product drawer, on a finding and
in the list of [watched CVEs](#cves-liste) (an opened row).

**What it does – only for you:**

- **No personal notifications** about it on your ways (e-mail, desktop push, your own Teams webhook): vendor news of a
  muted product, findings whose CVEs are all muted, and the notices of a muted **watched CVE** – watching it was your
  choice too, the newer one counts until it ends. What is left out meanwhile does not come later.
- **In your lists** pale or hidden ("Show muted") and **not in your numbers** in the sidebar. A story counts as muted
  when **all** of its CVEs are – a story about five CVEs stays when you mute one of them.
- **Actively exploited stays visible:** when a muted product lands in the KEV catalogue you get no notification (your
  choice), but the tile stays in the list with "KEV while muted".

**What it does not touch:** other people, a team's channels, the admins' rules, the
[weekly review](#wochenrueckblick) and [stand-ins](#abwesenheit) – whoever stands in for you decides about their own
mutes. The [desktop notifications for news](#desktop) keep following severity and source.

**My mutes** (*Settings → Notifications → Mutes*) lists all running ones with the time left; *Unmute* ends one at
once. Expired ones disappear by themselves.

## Calendar (iCal) {#kalender-ical}

The end of support of your versions entered as a calendar to subscribe to ([iCal](term:ical)): one all-day event per
version on the day support ends, with reminders **90** and **30 days** before. The event holds product, version,
release line, date and a link to Cobe News – no CVE details and no names (not a version's label either).

**What is in it:** as an admin every followed product. As a reader the products your team assigns to you (only while
Teams is switched on). This is checked again on every fetch: if a product is added or your role changes, the calendar
is right with the next fetch.

### Creating the address {#kalender-adresse}

1. Go to [*Settings → Notifications → Calendar*](/settings/notifications?tab=calendar).
2. Click "Create a calendar address". The address is shown **only now** – copy it.
3. "Create a new address" ends the old one at once; "Delete the address" ends it.

### Subscribing in Outlook {#kalender-outlook}

1. **Outlook on the web / new Outlook:** open the calendar → *Add calendar* → *Subscribe from web*.
   **Classic Outlook:** Calendar → *Add calendar* → *From Internet …*.
2. Paste the address, give it a name (e.g. "End of support") and click *Import* or *OK*.
3. Outlook then fetches the events itself, usually every few hours. Changed dates arrive with the next fetch.

Apple Calendar and other apps also open the address through the link "Open in the calendar app (webcal)".

> [!WARNING]
> The address is a secret like a password: whoever knows it sees the events – without signing in. Do not pass it on.
> If it got into the wrong hands, create a new one.

- Cobe News stores only a fingerprint of the address, not the address, and writes it into no log.
- If your account is switched off, the address ends for good – after a reactivation you create a new one.
- A calendar may fetch the address at most 30 times in 10 minutes; more is briefly refused.

## Forward to my team {#weiterleiten}

You send a story or a finding in Vendor News with a short comment to your team – for example “Concerns our firewalls,
please patch today”.

1. Open the story (News) or, in a product's drawer, the finding (Vendor News) and click **“Forward to team”**.
2. If you are in several teams, choose the team. Only teams for which an admin has set a forward channel are offered.
3. Optionally write a **comment** (at most 1000 characters), **Forward**.

The message goes to the **team's channel** (Teams, Slack, Discord, Telegram, Mattermost, ntfy, Gotify, email or
webhook) and contains: who forwards it, the title, a link to Cobe News and – for a finding – the
[urgency](/docs/vendor-news#dringlichkeit) and your versions. For a story your versions are included when its details
concern a followed product. In the chat channels it is the same **card** as a notification
([What a message looks like](#nachrichten-format)): product (only when reliably known), source, category, for a
finding the urgency and your versions, your comment as a field of its own, **"Comment"**, and the short description.
The email stays as it is.

Good to know:

- **An admin decides where it goes** – in the team under [Settings → Teams](/docs/anmeldung#teams-weiterleiten). You
  never choose an address or a channel yourself. Without a channel the button is off; the tooltip says why.
- The comment is **text only**: links are defanged (`example[.]com`, `https[:]//…`) and not clickable, `@` mentions
  nobody, formatting is shown as characters.
- **Limits:** at most 10 forwards per hour and person; the same story to the same team only once in 10 minutes (from
  whoever). The message says when it works again.
- If sending fails, the reason is in the notice (e.g. “the channel rejected the message”) – an admin should then check
  the channel. You can try again right away.
- Cobe News does not store who forwarded what.
- If *Teams* is off or you are in no team, there is no button.

## Channels {#kanaele .admin}

A channel is a target: a mailbox, a Teams, Slack, Discord or Telegram chat, or an own [webhook](term:webhook). You find
the channels under [*Settings → Channels & rules*](/settings/rules), tab "Channels".

| Channel | Target | Format |
|---|---|---|
| Email | recipients (one address per line, at most 20); server in the row "Mail server" | HTML and text |
| Microsoft Teams | workflow URL (or the URL of a classic "Incoming Webhook") | Adaptive Card |
| Slack | incoming webhook URL `https://hooks.slack.com/services/…` | Block Kit |
| Discord | webhook URL `https://discord.com/api/webhooks/…` (also `discordapp.com`) | embeds |
| Telegram | bot token and chat ID | text message |
| Mattermost | incoming webhook URL `https://…/hooks/…` | Markdown (defused), colour by severity |
| ntfy | server, topic, optional access token | plain text, priority by severity |
| Gotify | server and application token | plain text, priority by severity |
| Webhook | own URL, e.g. an n8n workflow | JSON, version 1 (see [Webhook](#webhook)) |

Text from the feeds is defused for each format: no `@everyone` in Discord, no `<!channel>` in Slack, no own links in
Teams, no `@channel` and no Markdown in Mattermost; links only `http(s)`.

### What a message looks like {#nachrichten-format}

In Teams, Slack, Discord, Mattermost and Telegram every story is a **card** with labelled fields; ntfy and Gotify get
the same content as compact text. The colour follows the severity.

| Field | Content |
|---|---|
| Title | the story's title, linking to the original article |
| **Product** | only when reliably known: for Vendor News the product with your version and the fix ("PAN-OS 11.1.2 → 11.1.6-h3"); for stories a followed product the [details from the source](/docs/news-quellen#details-aus-der-quelle) concern (likewise with version and fix), else the details' first affected product ("GitLab < 19.5.1"). When nothing is reliably known, the field is left out – nothing is guessed. A followed product is named as the catalogue names it today – also after a rename, a split or a [merge](/docs/vendor-news#zusammengelegte-produkte). |
| **Source** | the source's name |
| **Category** | the story's [topics](/docs/news-quellen#themen) (at most three) and the severity, e.g. "Zero-day · Actively exploited · Critical"; without a topic the severity and the kind of source ("High · Authority") |
| **Short description** | the first one or two sentences of the summary, at most about 200 characters – cut at a sentence end, a too long first sentence at the last word end with "…" |
| Footer | date and "Open in Cobe News" |

Example (Telegram):

```text
New security story · Critical to SOC

Chrome zero-day: Google fixes actively exploited flaw
Product: Chrome < 142.0.7444.59
Source: BleepingComputer
Category: Zero-day · Actively exploited · Critical
Google released an emergency update for Chrome. CVE-2026-1234 is already exploited.
2026-11-02 08:00 UTC · Open in Cobe News
```

When **more than 3** stories come at once (a [summary](#einmal-pro-kanal)), it becomes a **compact list**: one line per
story – "title · product · category", the title opens the story in Cobe News – and "… and N more in Cobe News". So
every message stays within the services' limits (Discord: one embed, Slack: at most 50 blocks, Telegram: below 4096
characters). The labels are in the rule's language. Email stays as it is (a card with severity, source and date). The
"Test" button sends the newest story (with its product, when known) or an example in exactly this format.

### Creating a channel {#kanal-anlegen}

1. *Settings → Channels & rules*, tab "Channels".
2. Click "Add channel" and choose the kind.
3. In the drawer, give it a **name** (at least 2 characters, e.g. "Teams SOC"). The box "How to set it up" sums up the
   steps.
4. Enter the target (URL, token or recipients – see below).
5. Save.
6. In the list, click "Test" at the channel.
7. On the tab "Rules", decide what goes to the channel (see [Rules](#regeln)).

For each channel the list shows the target (only the host, the recipients or the chat ID), which rules use it ("used by
no rule" if none) and its state: "Last sent …", "Nothing sent yet" or the last error. The kind of a channel cannot be
changed – for another service, create a new channel.

### Microsoft Teams (Workflows) {#teams}

Teams takes messages through a **workflow**. Its template is called "Post to a channel when a webhook request is
received".

1. In Teams, click "…" (More options) at the channel you want and choose "Workflows".
2. Choose the template "Post to a channel when a webhook request is received".
3. Give it a name (e.g. "Cobe News"), confirm the connection with your account and click "Next".
4. Check team and channel and click "Add workflow".
5. Copy the URL shown. It lives on `*.logic.azure.com` or `*.powerplatform.com`.
6. In Cobe News, create a channel "Microsoft Teams", paste the URL into "Workflow URL", save and test.

> [!NOTE]
> The workflow runs under the account that created it. If that account is deactivated, no more messages arrive. Create
> it with an account that stays, and write down who owns it.

The URL of a classic "Incoming Webhook" (`*.webhook.office.com`) works as well. Microsoft is retiring these connectors
step by step, though – use Workflows for new channels. If the URL lives on another host (e.g. an own cloud environment),
an admin has to add it to `WEBHOOK_HOSTS` (see [Allowed targets](#webhook-ziele)).

### Slack {#slack}

Slack takes messages through an **incoming webhook**: a Slack app that posts whatever goes to its URL into a fixed
channel.

1. On [api.slack.com/apps](https://api.slack.com/apps), choose "Create New App" → "From scratch", enter a name and the
   workspace.
2. In the app, open "Incoming Webhooks" and switch it on.
3. Click "Add New Webhook to Workspace", choose the Slack channel and allow it.
4. Copy the URL `https://hooks.slack.com/services/…`.
5. In Cobe News, create a channel "Slack", paste the URL into "Webhook URL", save and test.

If your workspace already has the app "Incoming Webhooks" from the Slack directory, its URL works too.

### Discord {#discord}

1. In Discord, open *Server Settings → Integrations → Webhooks* (you need the permission to manage webhooks).
2. Click "New Webhook", choose a name and the channel.
3. Click "Copy Webhook URL".
4. In Cobe News, create a channel "Discord", paste the URL into "Webhook URL", save and test.

Cobe News only takes URLs on `discord.com` or `discordapp.com` with the path `/api/webhooks/…`. Messages trigger no
mentions.

### Telegram {#telegram}

Telegram needs a **bot** and the **chat ID** of the chat it writes to.

1. In Telegram, open the bot @BotFather, send `/newbot`, give it a name and a username (ending in `bot`).
2. Copy the token (form `123456789:AA…`). Whoever has it can write in the bot's name.
3. Add the bot to the group – to a channel as an admin with the right to post.
4. Write a message in the chat, e.g. `/start`.
5. In your own browser, open `https://api.telegram.org/bot<TOKEN>/getUpdates` (replace `<TOKEN>`) and read the value
   `chat.id`.
6. In Cobe News, create a channel "Telegram", enter "Bot token" and "Chat ID", save and test.

Chat IDs: groups start with `-`, channels and supergroups with `-100`, public channels also work as `@name`.

### Email {#e-mail}

Emails go out through an [SMTP](term:smtp) server that applies to all email channels. It is in the row **"Mail
server"** above the list of channels: server and port, plus "set up" or "not set up".

1. In the row "Mail server", click "Configure" or "Edit".
2. Enter:
   - "Server" and "Port",
   - "Encryption": [STARTTLS](term:starttls) (usually port 587), SSL/TLS (port 465) or "None (internal relay
     only)",
   - "Verify certificate" – leave it on,
   - "User" and "Password" – empty for a relay without sign-in,
   - "Sender address" (required) and "Sender name".
3. Enter an address at "Test mail to" and click "Send test mail". The test takes the values in the form, also unsaved.
4. Save.
5. "Add channel" → "Email", enter the recipients (one address per line, at most 20), save and test.

Good to know:

- A new email channel without a configured server asks for the server first. Channels without a server show "Mail
  server missing".
- Saving the server restarts all email channels – without a pause and without the old error.
- If server, port, encryption, "Verify certificate" or user change, you have to enter the password again.
- A relay in the company network is fine. Cobe News' own Docker networks and the Docker host (the container's
  gateway, `host.docker.internal`) work only when their address is in `SMTP_ALLOW_INTERNAL` (see
  [Operations](/docs/betrieb#env-referenz)) – then also by name. Loopback (`127.0.0.1`), link-local including cloud
  metadata, "any" and multicast are always blocked, even with an entry. A relay that listens only on the server's
  `127.0.0.1` is reached through the Docker host's address, not through `127.0.0.1`.
- Errors only show their kind (refused, no connection, TLS …), never the server's text.

### Mattermost {#mattermost}

Mattermost takes messages through an **incoming webhook** – like Slack, but on your own server.

1. In Mattermost open *Main menu → Integrations → Incoming Webhooks* (a system admin must have allowed integrations).
2. Click "Add Incoming Webhook", choose a title and the channel, save.
3. Copy the URL `https://chat.corp.example/hooks/…`. Whoever knows it can post to the channel.
4. In Cobe News create a channel "Mattermost", paste the URL into "Webhook URL", save and test.

Each story comes as an attachment with a colour bar by severity (critical red, high orange …), with the title as a
link, the fields product, source and category, the short description, date and a link to Cobe News
([What a message looks like](#nachrichten-format)). Text from the feeds is defused: Markdown characters are escaped
(no own links, emphasis or emoji), `@channel`, `@all`, `@here` and `@name` mention nobody, `~channel` becomes no channel
link. Only `https://`. The server is usually internal – its address must then be in `WEBHOOK_PRIVATE_NETS` (see
[Allowed targets](#webhook-ziele)).

### ntfy {#ntfy}

ntfy is a simple push service: whatever goes to a **topic** shows up on every phone and browser
subscribed to it – through the ntfy app, without an account. You can use the public server ntfy.sh or run your own.

1. Make up a topic. On a public server anyone who knows the name can read and write – pick a long, random name
   (letters, digits, `-` and `_`, at most 64 characters).
2. Protected topic (recommended, on your own server with access control): create a user allowed to write to the topic
   and an **access token** for it (`ntfy token add <user>` – it starts with `tk_`).
3. In Cobe News create a channel "ntfy":
   - **Server**, e.g. `https://ntfy.corp.example` (also with a path behind a reverse proxy, without `?` and `#`),
   - **Topic**,
   - for a protected topic switch on "Access token" and enter the token,
   - optionally **tags** (comma-separated, at most 5) – a tag naming an emoji (`warning`) is shown by ntfy as that
     emoji in front of the title.
4. Save and test. Subscribe to the topic on the same server in the ntfy app.

| Severity | Priority | Tag (emoji) |
|---|---|---|
| Critical | 5 (urgent) | `rotating_light` |
| High | 4 | `warning` |
| Medium | 3 | `large_orange_diamond` |
| Low | 2 | `small_blue_diamond` |
| Info | 1 | `information_source` |

A tap on the notification opens the story in Cobe News (for a summary the start page). Cobe News sends everything as
JSON in the body to the server's root – title and text are never in a header; they are plain text (ntfy's Markdown
stays off), line breaks and control characters are removed. The token goes only in the header
`Authorization: Bearer …`.

### Gotify {#gotify}

Gotify is a self-hosted push server with its own Android app and web UI.

1. In Gotify, under *Apps*, click "Create Application", give it a name (e.g. "Cobe News"), save.
2. Copy the application's **token**.
3. In Cobe News create a channel "Gotify": enter **server** (e.g. `https://gotify.corp.example`, also with a path) and
   **application token**, save and test.

Priority by severity: critical 10, high 8, medium 5, low 2, info 1 – the app lets you choose from which priority on it
rings. The text is plain text (`text/plain`), a tap opens the story in Cobe News. The token goes only in the header
`X-Gotify-Key`, never in the URL.

> [!NOTE]
> Mattermost, ntfy and Gotify work only over `https://` and through the same egress check as all webhooks: public
> addresses, internal ones only through `WEBHOOK_PRIVATE_NETS`, never loopback, link-local, the own Docker networks or
> the Docker host. They are not available as **personal ways** (vendor news of my products) yet – only as channels for
> rules and team forwards.

### Testing, errors and pause {#kanal-testen}

"Test" sends a test message right away with the newest story (or an example story). It is marked as a test and does not
count as sent. The **saved** channel is tested – so save first. Two tests of the same channel are at least 3 seconds
apart.

If sending fails, the story stays open for that channel. Cobe News tries again with a growing pause: 2, 4, 8 … minutes
up to 6 hours at most. If the service asks for a wait (HTTP 429), Cobe News waits at least that long. A broken channel
never holds back the others. When a test arrives, error and pause disappear; whatever waits for the retry goes out in
the next round. Changing the target also resets error and pause.

| Error | What to do |
|---|---|
| Target not allowed | The address is internal. See [Allowed targets](#webhook-ziele). |
| This host is not allowed | Teams/Slack: host in `WEBHOOK_HOSTS`; Discord: only `discord.com`. |
| Sign-in refused | HTTP 401/403 or SMTP sign-in: check token, password or auth header. |
| Refused by the recipient | HTTP 404/410 (URL deleted, e.g. workflow removed) or recipients refused: check the URL or addresses. |
| Throttled by the service | too many messages; Cobe News waits and tries again. |
| No answer | timeout: check network, proxy and firewall. |
| TLS error | check the target's certificate; an own CA comes through `CA_FILE`. |
| Stored secret unreadable | The key changed: enter URL, token or secret again. |

Every attempt – also every test – is in the [delivery log](#zustellprotokoll), with the HTTP status or SMTP code.

### Secrets {#geheimnisse}

Webhook URLs (also Mattermost's), the Telegram bot token, topic and token of ntfy, the Gotify token, the HMAC secret,
the auth header value and the SMTP password are stored encrypted ([master key](term:masterkey) `SECRET_KEY` or the file
`data/secret.key`). The browser never gets them back – it only sees "stored" and the host. An empty field on saving
keeps the old value. Topic and token of ntfy and the Gotify token belong to their server: whoever changes the server has
to enter them again – they never go to a new target unasked. The server address itself is no secret and is shown.

## Generic webhook {#webhook .admin}

The channel "Webhook" sends every notification by `POST` as JSON to an own URL – e.g. to n8n, Node-RED or an own
service. Optionally with an [HMAC](term:hmac) signature and an own auth header. In the drawer, "Show example" shows the
format.

### Content (JSON, version 1) {#webhook-payload}

This is what a message looks like (formatted for reading here – the real body is compact JSON in UTF-8, without spaces
and with non-ASCII characters as they are):

```json
{
  "version": 1,
  "type": "news.stories",
  "id": "00000000-0000-4000-8000-000000000001",
  "sent_at": "2026-10-28T12:00:03Z",
  "app": "cobe-news",
  "app_url": "https://news.corp.example:8095/",
  "channel": "n8n SOC",
  "rules": ["Critical to SOC"],
  "lang": "en",
  "total": 1,
  "more": 0,
  "stories": [
    {
      "id": "00000000-0000-4000-8000-000000000002",
      "title": "Critical flaw in Example Gateway (CVE-2026-0001)",
      "summary": "Attackers can run code without signing in …",
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

| Field | Meaning |
|---|---|
| `version` | Format version, currently `1`. New fields may be added; an incompatible change raises the version. |
| `type` | `news.stories` or `news.test` (button "Test"). |
| `id` | ID of the message, equal to the header `X-Cobe-Delivery`. The same message sent again has the same `id`; a test gets a new one every time. |
| `sent_at` | Time it was sent (UTC). |
| `app_url` | Address of this installation (`BASE_URL`). |
| `channel`, `rules` | Name of the channel and of the rules that brought the stories (empty for a test). |
| `lang` | Language of the rule: `de` or `en`. |
| `total`, `more` | Stories in total; `stories` holds at most 10, `more` counts the rest. |

Fields of a story in `stories`:

| Field | Meaning |
|---|---|
| `id` | ID of the story or event. |
| `title`, `summary` | Title and summary. |
| `url` | Original link (empty if it does not start with `http(s)`). |
| `link` | opens the story in Cobe News. |
| `severity` | `critical`, `high`, `medium`, `low` or `info`. |
| `source` | Name of the source. |
| `published_at` | Publication (for Vendor News and source events: time of the event). |
| `cves` | CVE numbers, if known. |
| `kind` | `news`, `vendor.vuln`, `vendor.version`, `vendor.eol`, `vendor.change` or `source.health`. |
| `topics` | the story's [topics](/docs/news-quellen#themen): `zeroday`, `exploited`, `ransomware`, `nopatch`, `breach`, `supply`, `phishing`, `ot` (since 0.1.46; for Vendor News `exploited` when actively exploited). |
| `product` | the product when reliably known (like the field "Product" of the [cards](#nachrichten-format)), else empty (since 0.1.46). |

For `vendor.*`, `link` opens the product on the Vendor News page; `source` is "Vendor News". For `source.health`, `url`
and `link` lead to the page *Integrations → Health*; the severity is `high` (dead), `medium` (disturbed) or `info` (back
to normal).

> [!WARNING]
> Titles, summaries and links come from third-party feeds. Treat them as untrusted at the receiver – do not run them as
> commands, do not show them unchecked as HTML.

### Forwarded stories {#webhook-weiterleiten}

If a webhook channel is a [team's forward channel](/docs/anmeldung#teams-weiterleiten), a forwarded story arrives with
`"type": "news.forward"` (header `X-Cobe-Event: news.forward`, signed as usual). Instead of `stories` it carries an
object `forward`: `by` (display name), `team`, `comment` (defanged, line breaks kept), `kind` (`story` or `finding`),
`title`, `summary`, `url`, `link`, `severity`, `source`, `published_at`, `cves`, `score` (`value`, `level` – findings
only), `versions` and, since 0.1.46, as in `stories`, `topics` and `product` (empty when not reliably known). Treat name and comment as untrusted at the receiver as well.

### Headers and response {#webhook-header}

| Header | Content |
|---|---|
| `Content-Type` | `application/json` |
| `User-Agent` | `Cobe-News-Webhook/1` |
| `X-Cobe-Event` | like `type`: `news.stories` or `news.test` |
| `X-Cobe-Delivery` | like `id` |
| `X-Cobe-Timestamp` | Unix time in seconds – only with a signature |
| `X-Cobe-Signature` | `sha256=` and the HMAC as hex – only with a signature |
| own header | e.g. `Authorization` – only with "Own auth header" |

The receiver's response:

- **2xx** means delivered.
- Cobe News does not follow redirects (3xx) – they count as an error.
- 401/403 shows "Sign-in refused", 404/410 "Refused by the recipient", 429 "Throttled by the service" (a `Retry-After`
  is respected), anything else "The other side refused the call".
- The receiver has 10 seconds to accept the connection and at most 25 seconds per call in total. Answer quickly and do
  long work afterwards.

Cobe News delivers **at least once**: if the response gets lost on the way, the same message comes again – with the same
`id`.

### Signature (HMAC) {#webhook-signatur}

With "Sign (HMAC-SHA256)" the receiver checks that a call comes from Cobe News and is unchanged. Recommended – above all
without an own auth header.

1. In the drawer, switch on "Sign (HMAC-SHA256)".
2. Click "Generate" (or enter an own secret with at least 16 characters).
3. Copy the secret and enter it at the receiver – after saving it is never shown again.
4. Save.

This is how Cobe News computes it:

1. `ts` = current Unix time in seconds as text, e.g. `1793102403`. It is in `X-Cobe-Timestamp`.
2. Message = `ts`, a dot, then the **raw bytes** of the body: `"<X-Cobe-Timestamp>.<body>"`.
3. HMAC-SHA256 over this message with the secret (UTF-8) as key, as lowercase hex.
4. `X-Cobe-Signature: sha256=<hex>`.

Every attempt is signed anew (new timestamp); the `id` stays the same.

The receiver should:

- check the signature over the **raw body bytes** – not over JSON it parsed and serialised again (other spacing or
  `ü` instead of "ü" give another signature),
- compare in **constant time**,
- accept only timestamps that differ by at most a few minutes (e.g. 5) – so old calls cannot be replayed; keep both
  clocks in sync with NTP,
- remember `id` or `X-Cobe-Delivery` and drop a second delivery.

### Verifying the signature: examples {#signatur-pruefen}

**Python** (standard library only). `body` are the raw bytes, e.g. `request.get_data()` in Flask,
`await request.body()` in FastAPI or `request.body` in Django. The headers must be readable regardless of case – they
are in these frameworks.

```python
import hashlib
import hmac
import time

SECRET = b"the-secret-from-cobe-news"
TOLERANCE = 300  # seconds


def verify(headers, body: bytes) -> bool:
    ts = headers.get("X-Cobe-Timestamp", "")
    sig = headers.get("X-Cobe-Signature", "")
    if not (ts.isascii() and ts.isdigit()) or abs(time.time() - int(ts)) > TOLERANCE:
        return False
    mac = hmac.new(SECRET, ts.encode() + b"." + body, hashlib.sha256)
    return hmac.compare_digest(("sha256=" + mac.hexdigest()).encode(), sig.encode())
```

**Node.js** (no packages) – a small receiver on port 8081. With Express, take the raw bytes instead of `JSON`:
`express.raw({ type: "application/json" })`.

```js
const crypto = require("node:crypto");
const http = require("node:http");

const SECRET = process.env.COBE_SECRET ?? "";
const TOLERANCE = 300; // seconds
const seen = new Map(); // X-Cobe-Delivery -> time

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
    const raw = Buffer.concat(chunks); // the raw bytes
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

**PowerShell** (Windows PowerShell 5.1 and PowerShell 7) – the check as a function, below it a small receiver with
`HttpListener` on port 8082 (on Windows, start it as administrator).

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

    # compare in constant time
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
    $body = $ms.ToArray()   # the raw bytes
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

In all three examples the receiver remembers the `id` in memory only. In production it belongs in a database or a cache
with an expiry (e.g. one day).

### Own auth header {#webhook-auth-header}

If the receiver requires a sign-in (e.g. n8n with "Header Auth"), Cobe News sends a fixed header with every call.

1. Switch on "Own auth header".
2. Enter the "Header name" – `Authorization` is prefilled, `X-Api-Key` is common as well.
3. Enter the "Value", e.g. `Bearer …`. It is stored encrypted and never shown again.
4. Save.

The name consists of letters, digits and hyphens (at most 64 characters). Not allowed are headers Cobe News sets itself
or that change the request (e.g. `Host`, `Content-Type`, `Content-Length`, `User-Agent`, `Cookie`) and anything starting
with `X-Cobe-`.

If the URL moves to another host, another port or from https to http, you have to enter the HMAC secret and the header
value again. A stored secret never goes to a new target unasked.

### Options: http and proxy {#webhook-optionen}

**"Allow unencrypted (http)"** – off by default; then Cobe News only takes `https://` URLs. Switch it on only for a
target in your own, trusted network: over http, stories, signature and auth header cross the network in clear text.

**"Through the proxy (HTTPS_PROXY)"** – only matters when `HTTPS_PROXY` is set on the server. For a new webhook the
switch is off – in the form as well as through the API (a call without `use_proxy`). Channels saved before keep their
setting.

- **Off:** Cobe News connects directly. The name is resolved once, the address is checked (see
  [Allowed targets](#webhook-ziele)) and exactly that address is connected to. Right for internal targets like n8n.
- **On:** the call goes through the proxy, and the proxy resolves the name. Cobe News then only checks addresses written
  directly in the URL. Right for services on the internet when your network only reaches out through the proxy.

Teams, Slack, Discord and Telegram always go through the proxy when one is set.

### Allowed targets {#webhook-ziele}

**Teams and Slack** only take URLs on `hooks.slack.com`, `*.webhook.office.com`, `*.logic.azure.com` and
`*.powerplatform.com` by default. An admin adds further hosts to `WEBHOOK_HOSTS` in the [.env](term:envfile)
(comma-separated, exact or with `*.` for all names below). Discord and Telegram have fixed hosts; the generic webhook has
no host list.

**Internal addresses** are blocked for all channels by default – also for the webhook. Only public addresses are allowed.

Why? A webhook URL makes the server send requests to any target. Without the block, someone with admin access (or a
stolen admin session) could use it to reach services in the company network that are not reachable from outside
([SSRF](term:ssrf), server-side request forgery). The Docker host is especially delicate: services there often listen
only on `127.0.0.1` and take a request from there as "local" and therefore trusted.

You allow an internal target – e.g. n8n in the company network – deliberately with `WEBHOOK_PRIVATE_NETS`: a list of
addresses or networks in [CIDR](term:cidr) notation. To allow exactly one address, open `/opt/cobe-news/.env` on the
server and add this line:

```bash
WEBHOOK_PRIVATE_NETS=10.20.0.15/32
```

Then start the app with the new setting and check the channel with "Test":

```bash
cd /opt/cobe-news
docker compose up -d
```

Separate several entries with commas, e.g. `10.20.0.15/32,10.20.5.0/28`. An address without `/` counts as exactly that
one. Invalid entries are skipped silently – so check with "Test" after the restart.

**Blocked as long as the address is not in the list** – an entry in `WEBHOOK_PRIVATE_NETS` allows it:

- private addresses (`10.…`, `172.16–31.…`, `192.168.…`, IPv6 ULA and other non-public ranges),
- Cobe News' own Docker networks, e.g. a receiver in the network `edge`: `WEBHOOK_PRIVATE_NETS=172.31.250.50`,
- the Docker host: the container's gateway (`172.31.250.1` out of the box), with Docker Desktop `192.168.65.0/24`.

**Always blocked**, even when the address is in the list:

- loopback (`127.0.0.0/8`, `::1`),
- link-local (`169.254.0.0/16` including the cloud metadata address `169.254.169.254`, `fe80::/10`) and AWS's metadata
  address for IPv6 (`fd00:ec2::254`),
- "this network" or "any" (`0.0.0.0/8`, `::`) and multicast,
- the same addresses hidden in IPv6 notations (IPv4-mapped, NAT64, 6to4 …),
- names that stand for the Docker host, e.g. `host.docker.internal`, `gateway.docker.internal` or
  `host.lima.internal`. A target on the Docker host only works by its address.

`127.0.0.1` in a webhook URL would be Cobe News' own container, not your server. A service on the server is reached
through the Docker host's address (see [below](#webhook-testen)).

> [!WARNING]
> An address in `WEBHOOK_PRIVATE_NETS` is allowed without further checks. Enter only exactly the targets you need
> (preferably `/32`), no large ranges like `10.0.0.0/8` or `0.0.0.0/0`.

The name in a URL is resolved once, checked, and exactly that address is connected to. A name that later points to
another address cannot get around the check that way (DNS rebinding). If a blocked address is written directly in the
URL, saving already refuses it; if a name points to a blocked address, sending reports "Target not allowed".

### Testing a webhook {#webhook-testen}

Before the real receiver is ready, a small test receiver shows you what arrives.

**Option 1: a public request-bin service.** Such services give you an https URL and show every call with headers and
body. This works without changing the `.env`, because the target is public. The service sees the content, though – test
messages contain the newest story, channel and rule names and the address of your installation. Use a test secret there
and delete the channel afterwards.

**Option 2: an own receiver on a machine in the LAN.** This Python script (standard library only) takes calls on port
8080, checks the signature when `COBE_SECRET` is set, drops duplicates and prints every message. Save it as
`receiver.py`:

```python
import hashlib
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ.get("COBE_SECRET", "").encode()  # empty: channel without a signature
PORT = int(os.environ.get("PORT", "8080"))
TOLERANCE = 300  # seconds
seen = set()  # X-Cobe-Delivery already handled


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
            print("signature wrong or too old")
            self.send_response(401)
            self.end_headers()
            return
        delivery = self.headers.get("X-Cobe-Delivery", "")
        if delivery in seen:
            print("duplicate, dropped:", delivery)
        else:
            seen.add(delivery)
            msg = json.loads(body)
            print(msg["type"], msg["total"], [s["title"] for s in msg["stories"]])
        self.send_response(204)
        self.end_headers()


HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
```

Start it (the secret from the channel's drawer; without a signature leave out `COBE_SECRET`):

```bash
COBE_SECRET='the-secret-from-cobe-news' python3 receiver.py
```

Then in Cobe News – assuming the machine has the address `10.20.0.15`:

1. Add `WEBHOOK_PRIVATE_NETS=10.20.0.15/32` to the `.env` and run `docker compose up -d` (see
   [Allowed targets](#webhook-ziele)).
2. Create a channel "Webhook", "Target URL" `http://10.20.0.15:8080/`.
3. Switch on "Allow unencrypted (http)", leave "Through the proxy" off.
4. Optionally "Sign (HMAC-SHA256)" with the same secret as when starting the script.
5. Save and click "Test". A line with `news.test` appears in the terminal.

Nothing arrives? Does the machine's firewall allow port 8080? If the channel shows "Target not allowed", the entry in
`WEBHOOK_PRIVATE_NETS` is wrong or the app was not restarted.

**Receiver on the Docker host itself:** `127.0.0.1` does not work – that would be Cobe News' own container, and
loopback is always blocked. Instead:

- **Linux:** the script listens on `0.0.0.0` (as above). As the target, use the machine's LAN address or the
  container's gateway (`172.31.250.1` out of the box) and enter exactly that address in `WEBHOOK_PRIVATE_NETS`.
- **Docker Desktop:** services that listen only on the machine's `127.0.0.1` are reached by the container through the
  address behind `host.docker.internal`, usually `192.168.65.254`. Use that address in the URL and enter it in
  `WEBHOOK_PRIVATE_NETS` – Cobe News always refuses the name `host.docker.internal` itself.

After the test: delete the channel and remove the entry from `WEBHOOK_PRIVATE_NETS` again (then `docker compose up -d`
once more).

## Rules {#regeln .admin}

Rules decide *what* goes to which channels. You find them under [*Settings → Channels & rules*](/settings/rules), tab
"Rules". Create at least one channel first.

### Creating a rule {#regel-anlegen}

1. Tab "Rules" → "New rule".
2. Leave "Rule active" switched on.
3. Give it a **name**, e.g. "Critical to SOC".
4. Choose the **language** (Deutsch or English) – messages come in this language.
5. Choose the **channels** – at least one, several are possible. "Create a new channel" leads to the channels.
6. Under "What is sent?", switch on one or more kinds (see below).
7. Choose the **severities** (critical and high by default; empty = all) and, for security stories, the **sources**
   (empty = all).
8. Save.

In the list, the switch on the right turns a rule on and off; the pencil opens it, the bin deletes it. A rule without a
channel sends nothing.

### Kinds {#regel-arten}

| Kind (in the code) | In the interface | What comes | Severities / sources |
|---|---|---|---|
| `news` | "Security stories" | new stories of the news feed | both apply |
| `vendor_vuln` | "Vulnerability affects one of our systems" | a new vulnerability affects an entered version or a followed product without a version | severities apply |
| `vendor_version` | "New version / EOL coming" | newer version in the [release line](term:releaseline), end of support in less than 6 months, a [warning](/docs/vendor-news#eol-vorwarnung) 90 and 30 days before the end of support of each version entered, end of support reached | do not apply |
| `vendor_change` | "Advisory changed" | a vendor revised an advisory about a followed product: new fixed version, other severity, range, KEV, withdrawn ([more](/docs/vendor-news#aenderungen)) | severities apply |
| `source_health` | "Source disturbed or dead" | a source becomes disturbed or dead – and back to normal; once per change of state | do not apply |

"Advisory changed" is new and has to be switched on in a rule **explicitly** – existing rules do not get the kind. It
is sent only when the advisory concerns or concerned your entered versions (without a version: every change). The
message says briefly what changed, the effect on your versions first, e.g. "Revision 2: PAN-OS 11.2.4-h23: now affected
(before: not affected) – fix 11.2.4-h30". A revision comes once per channel.

The warnings before the end of support (90 and 30 days) are part of "New version / EOL coming": existing rules with
this kind get them without a change. Notices about [watched CVEs](#cves-beobachten) never go through rules and
channels, only to the person who watches.

Vendor News reports each vulnerability once per product and version. What is already known when a newly entered version
is first checked is on the page, but not sent. More in [Vendor News](/docs/vendor-news#ueberblick) and
[Source health](/docs/news-quellen#quellen-gesundheit).

### Dry run {#probelauf}

Before you save or widen a rule: **"Dry run"** at the bottom of the rule editor shows what it would have brought.

1. Choose the period: last day, last 7 or last 30 days.
2. Click "Dry run".

The rule is checked **as it is in the form right now** – saved or not – against the stored stories, Vendor News events
and source state changes, with the same logic as the real sending (as if a channel had been linked all along). The
result:

- the number of matches and a list of the newest (title, time, severity and why it matches: kind, severity, source,
  team),
- how many **messages** that would have been – what arrives within the same minute comes in one round, from 4 stories on
  as one [summary](#einmal-pro-kanal) –, on average a day and on the busiest day,
- the warning **"This channel would be flooded"** when one day would have had more than 20 messages.

The dry run sends nothing and writes nothing: no "sent" mark, no change to rule or channel. It runs read-only and with a
time limit; if it takes too long, choose a shorter period. If the form changes afterwards, the result fades – just run
it again. Admins only.

### Limiting to teams {#regel-teams}

When [Teams](/docs/anmeldung#teams) is on, a rule has a **Teams** field. Empty means: all products. With teams the rule
reports Vendor News events (`vendor_vuln`, `vendor_version`, `vendor_change`) only for the products of these teams. Security stories and
source health have no product – the field does not apply to them. When a product is newly assigned to a team, its
events come from then on, not the older ones; removing the team filter works like [widening a rule](#nur-neues).

### Only new stories – no flood of old ones {#nur-neues}

A rule only sends what arrives **after** it was saved or switched on. Older stories are never sent afterwards.

- **New or re-enabled rule:** counts from that moment. What arrived while it was off does not come.
- **Channel added to a rule later:** gets only what arrives afterwards.
- **Widened filter** (more severities, sources or kinds): what only matches because of it comes from the change on.
  What matched before and is still open keeps coming.
- **Newly switched-on source:** the older stories it brings with its first fetch are not sent – only what arrives fresh
  afterwards.

### Once per channel, summary and retry {#einmal-pro-kanal}

- After every fetch round Cobe News looks at what is new. Every 10 minutes it also checks everything – so a story that
  was rated higher in the meantime follows as well.
- Each story goes out **at most once per channel** – even when several rules send it to the same channel.
- **Up to 3** stories of a round come one by one (oldest first). **More** come as **one summary**: the 10 most
  important, the rest counted. Rules with different languages get separate messages.
- The channels are served side by side. If a channel fails, its stories stay open and come with the next try – after
  2, 4, 8 … minutes, at most 6 hours (see [Testing, errors and pause](#kanal-testen)).
- Each message is marked as sent right after it went out. If the process dies exactly in between, it comes again; a
  webhook recognises it by the same `id`.

## Delivery log {#zustellprotokoll .admin}

The delivery log shows **every attempt to deliver** to a channel with its outcome. You find it under
[*Settings → Channels & rules*](/settings/rules?tab=log), tab "Delivery log" (all channels), and in a channel's drawer,
tab "Log" (only that channel).

In the channel list a small badge shows the last 24 hours: "Last delivery ok 3 h ago" (green) or "3 failures in 24 h"
(yellow when something got through afterwards; red when nothing did). Tests do not count for it.

### What it holds {#protokoll-inhalt}

| Kind | When |
|---|---|
| Rule | a rule's message to a channel – every automatic retry and every "Send again" as another attempt of the same delivery |
| Forward | a [team forward](#weiterleiten) |
| Weekly review | a [weekly review](#wochenrueckblick) mail to a person |
| Test | "Test" of a channel |

Per delivery: the channel (with the name it had then – also after it was deleted), what was sent (story, event or
finding with its title; for a summary the listed ones and how many in all), the rules, time, attempt and outcome:

| Outcome | Meaning |
|---|---|
| Delivered | accepted (HTTP 2xx or accepted by the mail server) |
| HTTP 4xx/5xx | the receiver refused – with the status |
| Timeout | no answer in time |
| Blocked by the egress guard | the target is not allowed (see [Allowed targets](#webhook-ziele)) – nothing was sent |
| SMTP error | the mail server refused – with its reply code (e.g. 550) when it gave one |
| Error | DNS, TLS, connection, secret unreadable … |

Filter by channel, outcome ("Failures only" or one kind of failure), kind and period (24 hours, 7 or 30 days). The arrow
on the right opens all attempts of a delivery, with a short error text and the duration.

**Never in the log:** the content of a message, webhook URLs (not even their path), tokens, the ntfy topic, the HMAC
secret, auth headers, SMTP credentials and the receiver's answers. The error text is cleaned on top: addresses only
with their host, anything that looks like a token or an e-mail address replaced. A **forward** holds neither sender nor
comment – only team and story. A **weekly review** names the person who got it (only admins see the log), never the
mail. **Personal ways** (vendor news of my products) belong to each person and are not in the log – the bottom of the
tab shows only their numbers of the last 24 hours.

### Send again {#erneut-senden}

A failed delivery of a rule has **"Send again"**. It sends the same stories to the same channel again, now – the same
way with the egress check; a generic webhook gets the same `id` when it is the same message.

- **Right away:** the channel's pause after failures does not apply – you ask it explicitly. Quiet hours exist only for
  personal ways, never for channels.
- **If it arrives,** it counts as sent (the next round does not send it again), and the channel's error and pause end as
  after a successful test. **If it fails,** everything stays as the round left it – it is still retried automatically.
- **Only once:** if the delivery has arrived meanwhile (also through an automatic retry), another click sends nothing.
  What the channel got meanwhile is not sent again; if the stories were deleted meanwhile, there is nothing to send.
- **Throttled:** the same channel at most every 5 seconds, at most 20 times in 10 minutes per admin.

Tests, forwards and weekly reviews cannot be sent again: repeat a test with "Test", a forward is sent again by the
person (their comment is not stored), the weekly review retries by itself.

### Retention {#protokoll-aufbewahrung}

Entries are kept **30 days** and pruned every hour (at most 200,000 entries, the oldest first). The log is part of the
[backup](/docs/sicherung#ueberblick) – it holds no secrets and is small. For monitoring, `/metrics` counts the attempts
by kind, channel type and outcome (`cobe_news_delivery_attempts_total`) and each channel's failures of the last 24 hours
(`cobe_news_channel_delivery_failures_24h`) – without names or addresses (see [API](/docs/api#metriken-liste)).
