---
title: News & sources
summary: Reading stories, how the severity comes about, which sources are built in – and how admins add their own feeds and keep an eye on their health.
audience: all
---

## Reading news {#news-lesen}

The *News* page shows the stories of all switched-on sources as tiles, newest first. Further down, "Load more" loads
older ones.

### The tile {#kachel}

Each tile shows:

- at the top the source's logo and name, on the right the tick to mark it read (read: the arrow back to unread) and the
  **⋯** menu (read/unread, [mute](/docs/benachrichtigungen#stummschalten) the story's CVEs),
- the title and the start of the summary,
- if known, the affected product ("affects GitLab …" or "affects your systems: …"),
- at the bottom the **severity**, "Our product: …" (when the story concerns a followed product, see
  [Concerns our products](#unsere-produkte)), the [topics](#themen), the CVE mentioned (or "3 CVEs") and the age of the
  story.

Critical stories have a red border. Unread ones have a dot in front of a bold title; muted ones (visible only with
"Show muted") are pale and say "Muted".

### Opening a story {#schublade}

A click on the tile opens the story in a drawer on the right:

| Part | Content |
|---|---|
| Header | source, time, "also at …" (further sources with the same story), title |
| Rating | the severity and "Estimated by rules" – the reasons for it, see [Severity](#schwere) |
| Affects your systems | only when you follow the product in Vendor News and an entered version is affected |
| Affected versions | details from the advisory, see [Details from the source](#details-aus-der-quelle) |
| Changes | only when the advisory behind it changed afterwards – what changed, see [Changes to advisories](/docs/vendor-news#aenderungen) |
| Text | summary and article text, cleaned by the server (structure and links, no images, no scripts) |
| CVEs mentioned | each CVE, ready to copy, with a star to [watch](/docs/benachrichtigungen#cves-beobachten) it |

Opening marks the story as read ([Read and unread](/docs/erste-schritte#gelesen)). At the bottom: "Forward to
team" (only in a team, see [Forwarding](/docs/benachrichtigungen#weiterleiten)), "Mute" (the story's CVEs and the
affected products, for 7 or 30 days or until a date), "Mark as unread", "Open article" (the original article in a new
tab) and "Close".

### Search and filter {#suchen-filtern}

- **Search** ("Title, text, CVE …"): searches title, summary and CVE numbers, e.g. `CVE-2026-1234`, `FortiOS` or
  `Ransomware`. Upper/lower case and accents do not matter; at most 100 characters.
- **Source**, **Severity** and **Topic**: several values at once. Within one filter any chosen value is enough, all
  filters together must match – "Topic: Zero-day, Supply chain" and "Severity: Critical" shows critical stories that are
  a zero-day **or** about the supply chain. What the [topics](#themen) mean is written under each topic in the filter,
  next to it the number of stories it would have with the other filters.
- The **sources** are grouped by their kind (authorities & CERTs, vulnerability catalogues, vendor advisories, research,
  press, own sources). "All: Authorities & CERTs" picks a whole group – e.g. for the authorities' warnings.
- **Quick filters** below the filter row: "Actively exploited", "Zero-day" and "No patch" in one click – the same filter
  as *Topic*, with the number of stories. Next to them **"Concerns our products"** as soon as you follow a product in
  Vendor News ([more](#unsere-produkte)) – it applies on top of all other filters.
- The browser also remembers source, severity, topic and "Concerns our products" for your account (when you have no
  default view).
- "Reset filter" clears source, severity, topic and "Concerns our products".
- **Unread only**: hides what is read. **Show muted**: also shows the stories whose CVEs you all muted (pale) – otherwise
  they are left out.
- **Views**: save the filters under a name, make one the default, share it as a link ([Views](/docs/erste-schritte#ansichten)).
- "Mark all read" acts on exactly the unread stories that currently match the search and filters
  ([Read and unread](/docs/erste-schritte#gelesen)).

### Each story only once {#doppelte}

When several sources carry the same story, you see it once – with "also at …" in the header. The same story means:

- the same address (without tracking additions such as `utm_…`),
- the same title within 3 days from another source,
- between CISA KEV, ENISA EUVD and the BSI cyber security warnings: the same CVE within 30 days, when the story is
  about exactly that one CVE. The higher severity applies.

A press article about the same CVE stays a story of its own. A story that other sources carry too counts for each of
them – in the source filter and in notifications. When a source updates its story (say "[UPDATE] …"), Cobe News takes
the new version; the severity can only rise, new CVEs are added.

### When nothing appears {#keine-news}

- "News are switched off": an admin has to switch the news on first ([Setting up news](/docs/integrationen#news)).
- "Nothing new" in the **New** tab: everything is read – or a filter hides the stories.
- Stories disappear after the retention time (90 days by default), read and unread alike.

## Severity {#schwere}

Every story gets one of five levels:

| Level | Typically means |
|---|---|
| **Critical** | already exploited, zero-day, emergency patch, [CVSS](term:cvss) 9 or more |
| **High** | serious impact possible (remote code execution, ransomware, data breach, backdoor, authentication bypass), CVSS 7 or more, every entry in CISA KEV |
| **Medium** | a vulnerability or a patch, phishing, malware, CVSS 4 or more |
| **Low** | a security topic without a concrete vulnerability |
| **Info** | no sign of a vulnerability or an attack |

The reasons are shown in the open story under "Estimated by rules". A rating by rules does not replace your own
judgement – it helps with sorting.

### How it is rated {#bewertung-regeln}

1. **CVSS score in the text** – in German form too ("CVSS-Basiswert 9,8"). A bare version such as `CVSS:3.1/AV:N…` or
   "CVSS 3.1" never counts as a score.
2. **The publisher's rating** – BSI "[hoch]" in the title, Palo Alto "(Severity: HIGH)", Cisco "Security Impact
   Rating". It stands; only a higher CVSS score or "actively exploited" raise it further.
3. **Keywords** in title and summary – "actively exploited", "zero-day", "emergency patch" → critical; "ransomware",
   "remote code execution", "data breach" → high; "vulnerability", "patch", "phishing" → medium.
4. A keyword found **only in the article text** (not in title or summary) counts one level lower – a long report
   often mentions "zero-day" only in passing.

The highest matching level applies.

### What does not count as exploitation {#verneinungen}

Vendors often write under their advisories that a vulnerability is *not* exploited. Cobe News recognises such
negations, for example:

- "not known to be actively exploited", "no evidence … exploited in the wild",
- "bislang nicht aktiv ausgenutzt", "keine aktive Ausnutzung", "Kein Zero-Day".

Nor do the Zero Day Initiative (a programme), an "out-of-band management interface" (hardware) or malware seen
"in the wild" count – only *exploitation* in the wild does.

A **duty to report exploitation** is no exploitation either: "manufacturers must report actively exploited
vulnerabilities within 24 hours" (the Cyber Resilience Act) names a kind of flaw in a rule – nothing is attacked. When
the same sentence states such a duty ("must report", "reporting obligation", "müssen … melden", "Meldepflicht"), or the
title is about it ("Meldepflicht", "Cyber Resilience Act", "CRA"), "actively exploited" does not count there.
"Microsoft reports actively exploited flaw" stays an exploitation.

### Catalogs of exploited vulnerabilities {#schwere-kataloge}

The text rules do not apply to catalog entries – each entry brings its own rating:

| Source | Severity |
|---|---|
| [CISA KEV](term:kev) | **high**; **critical** when CISA reports known ransomware use |
| [ENISA EUVD](term:euvd) | **high**; **critical** from CVSS 9 |
| Microsoft Patchday | **high** |

## Topics {#themen}

Besides its severity every story gets its **topics** – none, one or several. They show as coloured badges next to the
severity on the tile (the first two, "+n" for more; hovering explains them), in the opened story under "Topics" with
the reason ("CISA KEV lists CVE-…", "in the title: ‘actively exploited’") and in the *Topic* filter.

| Topic | How Cobe News recognises it |
|---|---|
| **Zero-day** | "zero-day", "0-day" in title or teaser (not the Zero Day Initiative, not "Kein Zero-Day"). A zero-day story is also *actively exploited*. |
| **Actively exploited** | an entry of the [CISA KEV](term:kev) or [ENISA EUVD](term:euvd) catalogues; a CVE of the story is in the KEV (see below); the [details from the source](#details-aus-der-quelle) say "exploited"; words such as "actively exploited", "exploited in the wild", "aktiv ausgenutzt", "wird bereits ausgenutzt" – not denied, not as a duty to report ([negations](#verneinungen)) |
| **Exploit published** | a public exploit or proof of concept is known: CISA rates a CVE of the story in [SSVC](term:ssvc) with "Exploitation: poc" (from the CVE list, see below); a switched-on exploit collection (Metasploit, Exploit-DB, nuclei – [Public exploit](/docs/vendor-news#oeffentlicher-exploit)) lists a CVE of the story; words such as "PoC exploit", "proof-of-concept exploit released", "Exploit-Code veröffentlicht", "public exploit" – not denied ("no public exploit", "a public exploit is not known"). No evidence of attacks yet – that is *Actively exploited*. |
| **Ransomware** | "ransomware", "Erpressertrojaner", known gangs (LockBit, Akira, Qilin, Black Basta, Cl0p); for KEV entries CISA's note on ransomware campaigns |
| **No patch** | "[UNGEPATCHT]" in the title of a BSI warning; a CSAF advisory with "no fix available" or "no fix planned" and no vendor fix; a few unambiguous phrases ("no patch yet", "noch kein Update", "unpatched flaw") |
| **Incident/data leak** | "data breach", "Datenleck", "Datenpanne", "Kundendaten", "cyberattack on …", stolen or exposed data |
| **Supply chain** | "supply chain", "Lieferkette", malicious npm/PyPI packages or extensions, typosquatting, "dependency confusion" |
| **Phishing/social engineering** | "phishing", "vishing", "smishing", "ClickFix", "AitM", "social engineering", fake sign-in pages – not "campaign" or "threat actor" alone |
| **OT/ICS** | the OT sources Siemens ProductCERT, CERT@VDE and SecurityWeek ICS/OT; terms such as SIMATIC, CODESYS, PLC/SPS, SCADA, ICS, OT security |

An **authority warning** is no topic but a kind of source: in the source filter "All: Authorities & CERTs" picks all
authorities at once.

### How topics are recognised {#themen-erkennung}

- **Only title and teaser** count, never the whole article – a long report often mentions "phishing" or "zero-day" only
  in passing. German and English are recognised.
- **Catalogues** (CISA KEV, ENISA EUVD) get their topics from their data, not from their text: their boilerplate ("Known
  ransomware campaign use: Unknown") does not count.
- **CISA KEV by CVE:** when a CVE of a story is in the KEV catalogue, the story is *actively exploited* – if its title
  or teaser names that CVE or it names at most three CVEs. A Patch Tuesday round-up with 80 CVEs does not become
  "actively exploited" because one of them is in the KEV. CISA's ransomware note goes only to the KEV entry itself, not
  to every story about the same CVE.
- **Exploit published by CVE:** Cobe News reads CISA's SSVC rating from the stored entries of the CVE list (cvelistV5 –
  Vendor News keeps them for the followed products and for the CVEs it looks up for stories and findings). "poc" makes
  the story *Exploit published* – by the same round-up rule as for the KEV. "active" (active exploitation) is no PoC:
  that story is *Actively exploited*. When CISA changes its rating, the stories about that CVE follow.
- **Exploit published by the exploit collections:** when a switched-on collection (Metasploit, Exploit-DB, nuclei)
  lists a CVE of the story, it is *Exploit published* as well (same round-up rule); the drawer names the collection as
  the reason. When a collection adds or drops a CVE, the stories about that CVE follow at once; on a collection's first
  load, with very many changes at once and when a collection is switched on or off, Cobe News recomputes all stories in
  the background.
- **Ads** ("heise-Angebot", "Anzeige", "Webinar:", "(g+)") get no topics from their words.
- **Recomputed** whenever something changes: the story is updated, the details from the source arrive, a CVE is newly
  added to the KEV catalogue or a KEV story about the same CVE appears. After an update or a change of the rules
  Cobe News recomputes all stored stories in the background (in blocks of 500).
- So that *Actively exploited* is right without followed products too, Cobe News fetches the KEV catalogue once a day
  while the news are switched on ([special cases](#quellen-besonderheiten)).

### Limits {#themen-grenzen}

- Topics are **rules about words and data**, no understanding of the text. A title like "What to do about ransomware?"
  gets *Ransomware*; an incident naming its kind only in the article text gets no topic.
- *No patch* recognises only cases said explicitly. No such note does not mean that a patch exists.
- *Actively exploited* via the KEV needs the story to name the CVE; stories without a CVE are recognised by their
  wording only.
- *Exploit published* knows only what CISA rates in SSVC, what a switched-on exploit collection lists and what title
  and teaser say. With all collections off, only SSVC and the wording count.
- Topics also apply to [notification rules](/docs/benachrichtigungen#regel-themen) and to
  [desktop notifications and Web Push](/docs/benachrichtigungen#desktop-einschalten).

## Concerns our products {#unsere-produkte}

The quick filter **"Concerns our products"** shows only the stories that concern a product you follow in
[Vendor News](/docs/vendor-news#ueberblick). The tile then says **"Our product: PAN-OS"** (for several "+n", hovering
names all). The number on the toggle says how many stories that is with the other filters.

- **How Cobe News knows:** from the [details from the source](#details-aus-der-quelle) – the CSAF product tree, the
  NVD's CPE data, the affected products of the CVE list –, judged as in Vendor News. It is the same decision as
  "Affects your systems" in the opened story. **Never from words:** a title naming "Exchange" does not make a story
  yours.
- **Versions count:** if you entered versions and none of them is affected, the story does not count. Without an entered
  version every story about the product counts.
- **My team:** if Vendor News is set to ["My team"](/docs/vendor-news#mein-team) for you, the filter shows only your
  teams' products ("Concerns our products (my team)"). With "All" every followed product counts.
- **When it changes:** as soon as a story's details arrive, and when you follow a product, unfollow it or change its
  versions – Cobe News then recomputes the stored stories for that product in the background (in blocks of 500,
  usually within a minute). After the update to this version that happens once for all.
- **Limits:** stories without details (no CVE, press articles without an advisory) concern no product for the filter –
  even if their text names one. The toggle appears only once you follow at least one product.

## Built-in sources {#eingebaute-quellen}

Cobe News comes with 46 sources in five groups. 14 of them are switched on by default; admins switch others on or
off ([Integrations → News](/docs/integrationen#news)). The language is shown as DE, EN or FR next to the source.

| Group | On by default | Optional |
|---|---|---|
| Authorities & CERTs | BSI Cyber-Sicherheitswarnungen, CERT-EU Security Advisories, CERT.at Warnungen | BSI CERT-Bund (WID), BSI Presse, NCSC UK, Canadian Centre for Cyber Security, CERT-FR Alertes (FR) |
| Vulnerability catalogs | CISA KEV | ENISA EUVD, Microsoft Patchday (MSRC) |
| Vendor advisories | CERT@VDE (OT-Hersteller), Veeam Security | Fortinet PSIRT, Palo Alto Networks PSIRT, Cisco PSIRT, Ivanti Security Advisories, Siemens ProductCERT, Oracle Security Alerts |
| Research | Microsoft Threat Intelligence, Cisco Talos | Unit 42, Google Threat Intelligence (Mandiant), Kaspersky Securelist, ESET WeLiveSecurity, Check Point Research, Zero Day Initiative (ZDI), SANS Internet Storm Center, watchTowr Labs, Huntress |
| Press | heise online, heise Security, The Hacker News, golem.de Security, BleepingComputer, SecurityWeek ICS/OT | SecurityWeek, Krebs on Security, Dark Reading, The Record, Borns IT- und Windows-Blog, Security-Insider, t3n Security, Risky Bulletin |

### Special cases {#quellen-besonderheiten}

- **CISA KEV and ENISA EUVD** are not feeds but catalogs of actively exploited vulnerabilities. Every entry becomes a
  story ("CVE · Vendor Product: Name"), linking to the NVD or the EUVD entry. KEV stories show the date by which US
  agencies must patch.
- **Cobe News downloads the KEV catalogue once for everything:** the same fetch brings the KEV stories and the whole
  catalogue for Vendor News and the [topics](#themen). When the CISA KEV source is off or failing, Vendor News fetches
  the catalogue itself – once a day, also without a followed product, while the news are switched on. When
  `www.cisa.gov` refuses the fetch (HTTP 403, bot protection), Cobe News loads the same file from CISA's official mirror
  on GitHub (`raw.githubusercontent.com/cisagov/kev-data`). On 429/503 the source's pause applies, no fallback.
- **Microsoft Patchday (MSRC)** brings one story per Patchday release ("Microsoft: October 2026 Security Updates")
  linking to the release notes – instead of hundreds of single stories per CVE.
- **Vendor advisories** are precise but cover only that vendor's products. Cobe News takes the severity from the vendor.
- **CISA Alerts and Rockwell Automation** are no built-in sources since 0.1.49: both refuse automatic fetches from
  most networks (HTTP 403). Cobe News does not work around that and shows "The source refuses automatic fetches" for
  such a source. CISA's KEV catalogue stays.
- **BSI CERT-Bund (WID)** brings many advisories a day – hence off by default.

### New sources and the backlog {#rueckstand}

When an admin switches a source on, its first fetch often brings many older stories at once – the first KEV fetch
about 100 entries of the last 90 days. This **backlog** is shown on the page but triggers **no** notification:
notifications only go out for stories that were at most one day old when fetched.

Stories older than the retention time are not taken at all. Per fetch, Cobe News reads at most the newest 200 entries
of a source.

## Details from the source {#details-aus-der-quelle}

For many stories Cobe News fetches the structured advisory behind them. The open story shows it at the top as
**"Affected versions"**:

- per product the affected version ranges (e.g. `<19.5.1`) and the fixed versions ("Fix: …"),
- the CVSS score, the CVEs, "Remotely exploitable" and "Workaround/mitigation available",
- "As of: update of …" and where it comes from ("Details: …").

The tile shows the CVSS score and the affected product.

| Source of the story | Where the details come from |
|---|---|
| BSI CERT-Bund (WID), Siemens ProductCERT, Cisco PSIRT, Fortinet PSIRT | the publisher's [CSAF](term:csaf) document |
| Palo Alto Networks PSIRT | the vendor's advisory as JSON |
| Veeam Security | the story's own text (the KB article) |
| CISA KEV, ENISA EUVD | the story itself and the [NVD](term:nvd) |
| other stories with a CVE | the NVD (for the first three CVEs), marked "from NVD" |

Good to know:

- Stories **without a CVE** from other sources have no details.
- The NVD often lags a few days behind with new CVEs – the details then appear later. Until then Cobe News completes
  the data from the CVE list (cvelistV5), unless an admin has switched that source off – marked "completed from the
  CVE list (cvelistV5)".
- Each CVE of the story shows its [EPSS](term:epss) value ("Exploitation within 30 days"), plus CISA's
  [SSVC](term:ssvc) assessment where it says more than "nothing known" – see
  [EPSS and SSVC](/docs/vendor-news#epss-ssvc).
- Cisco does not name fixed versions in its advisories (only through its own Software Checker).
- Stories younger than 30 days are checked again daily; a story whose title changes ("[UPDATE] …") at once.
- **"Affects your systems"**: when you follow the product in Vendor News, Cobe News compares the ranges with your
  entered versions. Advisories from BSI, Siemens and Cisco also become findings in
  [Vendor News](/docs/vendor-news#bewertung).

Admins switch the details off under *Settings → Integrations → News* with "Details from the source"
([Settings](/docs/integrationen#news)).

## Own sources {#eigene-quellen .admin}

Besides the built-in sources, an admin can add feeds of their own – a vendor's blog, say, or an industry CERT.

### What works {#eigene-formate}

| Format | Note |
|---|---|
| [RSS](term:rss) 2.0, RSS 1.0 (RDF), Atom | the usual case |
| JSON in the format of CISA KEV (`{"vulnerabilities": […]}`) | each entry a story |
| JSON in the format of ENISA EUVD (a list or `{"items": […]}`) | each entry a story |
| JSON in the format of the Microsoft CVRF index (`{"value": […]}`) | one story per release |

Other JSON (e.g. "JSON Feed") and HTML pages do not work. The format is recognised by the content, not the
Content-Type.

### Adding a source {#eigene-hinzufuegen}

1. *Settings → Integrations*, click "Configure" on *News*.
2. At the very bottom under **Own source**, enter a **Name** (2–100 characters) and the **Feed address**.
3. Click "Check": Cobe News fetches the feed once and reports how many entries it read and the newest title – or why
   it fails.
4. Click "Add". The source then appears in the group **Own sources**, is switched on and is fetched with the next
   round.

To remove an own source, use the bin next to its switch. Its stories go with it – except those another source carries
too. Rules and desktop settings that had chosen only this source send no more news afterwards. Built-in sources can
only be switched on and off, not removed.

### Rules and limits {#eigene-grenzen}

- **`https://` only.** Redirects (at most 3) must stay on https too.
- **No internal targets:** never loopback, link-local or cloud metadata. Private networks (`10.…`, `172.16–31.…`,
  `192.168.…`) only when the [.env](term:envfile) contains `ALLOW_PRIVATE_FEEDS=1`. The name is resolved once,
  checked, and exactly that address is connected.
- **Size and time:** at most 5 MB and 30 seconds per fetch.
- **XML with a DTD or entities** is refused.
- **At most one request per website and minute;** unchanged feeds (`ETag`/`Last-Modified`) cost only a short question.
  After HTTP 429/503 Cobe News waits as long as asked (at least one hour), otherwise with a growing pause of up to
  24 hours.
- Dates outside 1990–2100 count as "no date".

> [!NOTE]
> With `HTTPS_PROXY` the proxy resolves the names. Cobe News then checks only addresses written as an IP in the URL –
> the proxy itself has to block internal targets behind names
> ([Outbound data](/docs/integrationen#ausgehende-daten)).

### Fetch interval, retention, main switch {#eigene-einstellungen}

These settings apply to all sources, own and built-in – see [Integrations → News](/docs/integrationen#news): the main
switch "Fetch news" (off by default), the fetch interval per source (15–1440 minutes) and the retention (7–365 days).

### Error messages when checking {#eigene-fehler}

| Message | Cause |
|---|---|
| Not a readable feed (RSS, Atom or JSON catalog) | an HTML page, unknown JSON or broken XML |
| Feed without usable entries | entries without title or link |
| Feed too large (more than 5 MB) | the feed delivers its whole history |
| No answer within 30 seconds | server too slow or a firewall drops the request |
| No connection (network, proxy or DNS?) | name not resolvable, proxy missing, target blocked |
| The source refuses automatic fetches (403) | the website's bot protection – Cobe News does not work around it |
| The site asks for a pause (too many requests) | HTTP 429 – try again later |

## Source health {#quellen-gesundheit .admin}

Cobe News watches how well each source is fetched – so a failing source stands out before stories go missing. It is
shown under *Settings → Integrations → Health* ([The health view](/docs/integrationen#gesundheit)). When a source is
dead, *Integrations* shows the number in the navigation.

Every news source, every source family of Vendor News and each of the [more sources](/docs/integrationen#weitere-quellen)
(CSAF providers, cvelistV5, EPSS, OSV) gets a state. The first one that fits applies:

| State | When |
|---|---|
| **off** | the source or the news are switched off; for Vendor News: switched off, or no followed product needs this query |
| **not fetched yet** | switched on but never asked – happens with the next round |
| **dead** (red) | HTTP 401/403/410 twice in a row; HTTP 404 three times in a row; no successful fetch for **14 days**; news only: no new story for **60 days** although fetching works |
| **disturbed** (amber) | 3 failures in a row; a current failure that is not just passing (e.g. wrong address, certificate, unreadable answer) – the source pauses until its next try; an unreadable answer within the last 24 hours |
| **slow** (blue) | more than 5 seconds per request on average over the last 7 days (big downloads of more than 1 MB per request do not count here – such as the first full NVD fetch of a product just followed); frequent timeouts (at least 3 and at least a quarter of the fetches); or a passing failure about to be retried |
| **healthy** (green) | everything else |

Passing failures are timeouts, connection errors, HTTP 5xx and "too many requests". They pause a source for at most
one hour (or one fetch interval, if that is longer).

What to do:

- **slow** – nothing; the stories still come.
- **disturbed** – check soon: is the address still right? Certificate? Proxy?
- **dead** – check the source or switch it off. A source that brings nothing new for 60 days has often moved.

Cobe News can send a notification once per change of state – rule kind "Source disturbed or dead"
([Rules](/docs/benachrichtigungen#regeln)).
