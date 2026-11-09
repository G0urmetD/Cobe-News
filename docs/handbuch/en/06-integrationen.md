---
title: Integrations & source health
summary: Setting up News and Vendor News, controlling Web Push, understanding which data leaves the server, and monitoring the health of the sources.
audience: admin
---

## Overview {#ueberblick}

*Settings → Integrations* ([open](/settings/integrations)) is the place for everything Cobe News fetches from outside.
The page has two sub-tabs:

| Tab | Content |
|---|---|
| **Sources** | two tiles: **News** and **Vendor News** – each with its state, key figures and "Configure" |
| **Health** | how well each source is fetched, see [Health](#gesundheit) |

The tile shows at a glance whether the integration is switched on, how many sources are running, how many have a
problem ("N with a problem") and – for Vendor News – whether an NVD key is set and whether catalogue entries need
care. "Configure" opens the drawer on the right with all settings. Changes are stored with "Save" at the bottom of
the drawer.

- The "Sources" button at the top of the news page leads straight here.
- When a source is dead, *Integrations* shows the number in red in the navigation.
- When two admins save at the same time, the last one does not silently win: whoever saves on an outdated state sees
  "Changed by someone else meanwhile" and loads the current state.

## News {#news}

*Integrations → News → "Configure"*

| Setting | Default | Range | Meaning |
|---|---|---|---|
| **Fetch news** | off | on/off | Main switch. Off: not a single request goes out, the news page shows "News are switched off". |
| **Fetch interval per source** | 30 minutes | 15–1440 minutes | How often each source is asked. Unchanged feeds cost only a short question. |
| **Retention** | 90 days | 7–365 days | Older stories are deleted, read and unread alike. A story without a date of its own stays while its feed still lists it (or another feed lists the same address). A shorter period says before saving how many stories go – for good, they are not fetched again later. |
| **Details from the source** | on | on/off | Fetches the advisory behind each story ([Details from the source](/docs/news-quellen#details-aus-der-quelle)). |

The fields can only be edited once the main switch is on.

### First setup {#news-einrichten}

1. Open *Settings → Integrations* and click "Configure" on **News**.
2. Switch "Fetch news" on.
3. Check the fetch interval and retention, "Save".
4. Under **Sources**, switch on the sources you want. Each group expands; "3 of 9 on" shows how many are running.
5. Click "Fetch now" – the sources are asked one after the other, the first stories appear within a few minutes.

### Sources {#news-quellen}

- The sources are listed in groups (Authorities & CERTs, Vulnerability catalogs, Vendor advisories, Research, Press,
  Own sources) with their language (DE/EN/FR) and feed address. Which ones exist:
  [Built-in sources](/docs/news-quellen#eingebaute-quellen).
- Each source's switch takes effect at once, without "Save". A source switched on again is asked in the next round,
  without its old pause or old error.
- Under each switched-on source its state is shown: number of stories and last success, "Not fetched yet", or the
  error with "next try".
- What an admin switches stays that way – even when an update changes the default of a built-in source. New built-in
  sources arrive with an update in their default state.
- Own feeds: "Own source" at the very bottom, see [Own sources](/docs/news-quellen#eigene-quellen).

### Fetch now {#news-jetzt-abrufen}

"Fetch now" starts a round immediately instead of waiting for the interval – at most once a minute. Even then, each
website gets at most one request per minute, and sources pausing after a refusal (429/503) stay paused.

> [!TIP]
> A short interval hardly brings stories faster: most sources publish only a few times a day. 30 minutes is a good
> value.

## Vendor News {#vendor-news}

*Integrations → Vendor News → "Configure"*. The drawer has three tabs: **Settings**, **More sources**
([More sources](#weitere-quellen)) and **Catalogue care**.

| Setting | Default | Range | Meaning |
|---|---|---|---|
| **Vendor News** | on | on/off | Main switch |
| **Advisories & NVD every** | 6 hours | 1–48 hours | Vendor advisories (Palo Alto, Fortinet, Veeam, CSAF providers) and the [NVD](term:nvd)'s CVEs; afterwards only what changed |
| **Versions & KEV every** | 24 hours | 6–168 hours | [Release lines](term:releaseline) from endoflife.date and CISA's KEV catalogue (the KEV also without a followed product while the news are on – for the [topics](/docs/news-quellen#themen); when the news source CISA KEV brings it already, it is not downloaded a second time) |
| **NVD API key (optional)** | empty | – | faster NVD queries, see below |

> [!NOTE]
> Vendor News is **on** by default – still, not a single request goes out as long as nobody follows a product.
> After that, only for the followed products.

### NVD API key {#nvd-schluessel}

Without a key the NVD allows 5 requests per 30 seconds; Cobe News keeps to that. The first fetch of many products then
takes a few minutes, and the [Details from the source](/docs/news-quellen#details-aus-der-quelle) look up only 8
instead of 40 CVEs per round at the NVD.

1. Request the free key at
   [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).
2. Paste it into the **NVD API key** field, "Save".
3. The tile then shows "NVD key set".

The key is stored encrypted and never shown again. Leaving the field empty keeps it; "Remove" (then "Save") deletes it.

### Catalogue and queries {#vendor-katalog}

- **Refresh catalogue** rebuilds the product catalogue from endoflife.date in the background. Next to it: how many
  products it has and its date. At most every 10 minutes; normally not needed – the daily fetch keeps it current.
- **Queries** lists every running query (per followed product, NVD per CPE …) with last success, error and next run.
  "None yet" means: no product followed yet.
- **Fetch now** starts a round immediately. Depending on the NVD's rate limit it takes a few minutes.

### Catalogue care {#vendor-katalog-pflege}

The **Catalogue care** tab shows catalogue entries that are probably outdated or wrong (a CPE that no longer exists,
no CVE for a long time …). "Check now" checks the followed products immediately. Details:
[Catalogue care](/docs/vendor-news#katalog-pflege). How to follow products and enter versions:
[Following products](/docs/vendor-news#produkten-folgen).

## More sources {#weitere-quellen}

Four structured sources complement the vendors' advisories and the [NVD](term:nvd): the vendors'
[CSAF](term:csaf) providers, the CVE list [cvelistV5](term:cvelist), [EPSS](term:epss) from FIRST and [OSV](term:osv).
Three collections of public exploits come on top ([Exploit hints](#exploit-hinweise)). They are in
*Integrations → Vendor News → "Configure"*, sub-tab **More sources**
([open directly](/settings/integrations?vendor=sources)).

- Each source has its own switch and is **on by default** – except Exploit-DB. Saved with "Save" at the bottom of the
  drawer.
- Each one asks only for what the followed products need (EPSS also for the CVEs of stories). As long as nobody
  follows a product, none of them asks anything. With Vendor News off, none asks.
- Below each switch: what leaves the server and the state of its queries. "History under Health" leads to
  [Health](#gesundheit).

| Source | What it brings | When |
|---|---|---|
| **CSAF providers** | the security advisories of Siemens, Cisco, Schneider Electric and Open-Xchange straight from the vendor: affected products with version ranges, fixed versions, CVEs, CVSS | with the Vendor News round ("Advisories & NVD every", 6 hours by default), only with a followed product of that vendor |
| **cvelistV5** | CVE records as the vendor (CNA) publishes them, and CISA's assessment (CVSS, [SSVC](term:ssvc), KEV) – above all for CVEs the NVD has not analysed yet | the day's changes three times a day, the end of day once a day; single records on demand |
| **EPSS** | probability that a CVE is exploited in the next 30 days, with percentile | each CVE at most once a day |
| **OSV** | affected and fixed versions of open-source packages (Tomcat, Jenkins, Django …) | each CVE daily while it is younger than 30 days, weekly after that |
| **Exploit hints** (Metasploit, Exploit-DB, nuclei) | whether public exploit code or a ready-made check exists for a CVE | each collection at most once a day, conditional (unchanged: no data) |

### CSAF providers {#csaf-anbieter}

Which providers Cobe News knows and which vendors they speak for is part of the catalogue (`csaf.yaml`):

| Provider | Domain | speaks for products of the vendor |
|---|---|---|
| Siemens ProductCERT | `cert-portal.siemens.com` | Siemens |
| Cisco PSIRT | `www.cisco.com` | Cisco (with Duo), Splunk (Cisco) |
| Schneider Electric CPCERT | `www.se.com` | Schneider Electric |
| Open-Xchange GmbH (since 0.1.45) | `www.open-xchange.com` | Open-Xchange (OX App Suite) |

A provider is only asked when you follow a product of its vendor (the "vendor" field in the catalogue). The list
under *More sources* shows "fetched" or "no followed product" for each provider. Adding another provider is catalogue
care: an entry in `backend/app/catalog/csaf.yaml` (described in `docs/BETRIEB.md` under "Katalog pflegen" → "CSAF-Anbieter"),
effective with the next update:

```yaml
- key: example                     # short, unique (under Health: csaf:example)
  name: Example Corp PSIRT
  domain: psirt.example.com
  vendors: [Example Corp]          # vendor as in the products' vendor field
```

**How Cobe News finds and reads the advisories:**

1. **Finding the provider:** first an entry on the provider's domain in the BSI's provider list (the CSAF aggregator
   on `wid.cert-bund.de`, read once a day), else `https://<domain>/.well-known/csaf/provider-metadata.json`.
2. **List of documents:** a ROLIE feed or the `changes.csv` file of a directory – fetched conditionally, so an
   unchanged list costs only a short request.
3. **Public documents – TLP:GREEN only on request:** feeds and documents labelled [TLP](term:tlp):WHITE or
   TLP:CLEAR are read. A document without a label only from a distribution not labelled otherwise. TLP:GREEN only
   where an admin allows it for this provider ([below](#tlp-green)); AMBER, AMBER+STRICT and RED are never read.
4. **Hash:** where the provider offers a hash (`.sha512` or `.sha256`), it has to match – otherwise the document is
   skipped (counted as unreadable under *Health*). If the feed lists a hash that cannot be fetched right now, the
   document is not taken this round and tried again later. If a provider has no hash files at all, Cobe News remembers
   that and asks for them again only after a while.
5. **Position per provider:** Cobe News remembers the time and address of the last document read and afterwards reads
   only what changed later – the oldest first, at most **25 documents per round**. The rest follows 20 minutes later.
6. **Temporary errors:** if a document fails temporarily (server error 5xx, timeout), it is tried again in the next
   rounds – after 5 tries or 24 hours Cobe News gives it up. The other documents go on.
7. **Times in the future** (more than a day) are ignored – a document with a wrong date cannot move the position
   forward.

**No OpenPGP signature check.** The providers also sign their documents (`.asc`). Cobe News does not check that
signature: the key for it is on the same server as the document. Whoever could change a document there could swap the
key as well – the signature would add protection beyond TLS and the hash only with a key stored independently.

### Allowing TLP:GREEN per provider {#tlp-green}

**TLP:GREEN** means: share only within your organisation or community, not publicly. Some providers label even
advisories they put online for anyone that way – the known case is **Open-Xchange** (OX App Suite and Dovecot, all
documents TLP:GREEN). By default Cobe News does not read such documents.

Under *Settings → Integrations → Vendor News → More sources* every CSAF provider has the switch **Allow TLP:GREEN**
(off by default). Switched on:

- This provider's TLP:GREEN documents are read; its list is read once from the start for that. What is older than
  7 days shows on the page as with a first fetch, but is not notified.
- Every finding from them carries the mark **TLP:GREEN** (explained on hover) – on the product card, in the drawer, in
  e-mails and chat messages (field “TLP: TLP:GREEN – share internally only”, `[TLP:GREEN]` in front of the title), when
  forwarded to a team, in the weekly report, in the webhook (`"tlp": "GREEN"`) and in the API (`/api/v1`, field
  `tlp`). Where your channels go is your decision – a channel to the outside should not get such messages.
- AMBER, AMBER+STRICT and RED are always refused.

Switched off again, Cobe News removes the stored TLP:GREEN advisories of this provider at once (and checks again every
round) – without a "withdrawn" message; messages from them not sent yet do not go out any more. Removed rather than
only hidden, because you decided not to keep such content: it would otherwise stay in the database, in backups and
exports. Every change of the switch is in the audit log ("Settings changed", field `csaf_green`).

Details of news stories (BSI, Siemens, Cisco) are shown only from public documents (TLP:CLEAR/WHITE) – a TLP:GREEN
document there is not used.

### Rules for CSAF documents {#csaf-regeln}

So that a provider can only speak for its own products, these rules apply:

- **Only its own vendors:** a document counts only for products whose catalogue vendor is one of the provider's
  vendors (`vendors` in `csaf.yaml`). In addition, the vendor in the document itself (the "vendor" branch of the
  product tree) has to match the product's vendor. A Siemens document can therefore never report a Cisco product as
  affected.
- **Publisher on its own domain:** the publisher namespace in the document has to be on the provider's domain.
- **Addresses stay with the provider:** redirects are followed only within the provider's domain. If the link to the
  advisory points elsewhere, Cobe News links the document's own address instead.
- **Nothing is overwritten:** a document never replaces an advisory of another publisher – neither an advisory of the
  BSI (WID-SEC) nor an advisory with the same id from another provider.
- **One advisory, one finding:** Siemens and Cisco advisories that also come through a news story
  ([Details from the source](/docs/news-quellen#details-aus-der-quelle)) share one record with the provider's
  document – one advisory, one finding, one notification.

### First fetch {#erstabruf}

A provider's first fetch goes back **90 days**. So that it does not cause a flood of notifications:

- Documents that are **older than 7 days** at the first fetch carry the marker **"First fetch"** in the product's
  drawer. They are shown and count like any other finding – but they are **never sent**.
- Younger documents of the first fetch are notified as usual.
- Everything that comes after the first fetch is notified as usual.

What the marker looks like for readers: [First fetch](/docs/vendor-news#erstabruf).

### cvelistV5 {#cvelist}

cvelistV5 is the official CVE list on GitHub (project CVEProject/cvelistV5): every CVE record as the vendor or another
assigning authority (CNA) publishes it, plus CISA's assessment (ADP). Cobe News **never downloads the whole list**
(about 650 MB), only changes:

- **When:** Cobe News looks at GitHub's newest release (a small JSON answer from `api.github.com`) only when something
  is due. It downloads the zip file "everything changed since midnight (UTC)" **three times a day**, once the release
  of 05:00, 11:00 or 17:00 UTC is out – GitHub publishes each hourly release about 20 to 40 minutes after the hour.
- **End of day:** once after the day changes, the zip file with all changes of the previous day follows (published
  around 00:30–00:40 UTC). If it is still missing, Cobe News waits for it until 06:00 UTC – so the last hours of the
  day are not lost.
- **Data volume:** about 9 to 11 MB a day (example 2026-10-29: 0.4 + 0.7 + 4.3 + 5.3 MB) instead of about 50 MB with a
  download every hour. A change reaches Cobe News after about 7.5 hours at most.
- **Computer asleep, app stopped:** a missed slot is caught up by the next slot or the end-of-day file, missed days
  (at most 3) by their end-of-day files.
- **Broken file:** a zip file that cannot be read or is too large is skipped and shows up as an error under *Health*;
  the day's other files are read anyway.
- **What is kept:** only records that concern a followed product (the vendor names it, or CISA names one of its
  [CPE](term:cpe)s), and records stored before (an update). A withdrawn record ("rejected") is removed.
- **Single records on demand:** for CVEs of findings the NVD has not analysed yet, and of stories the NVD cannot
  describe, Cobe News fetches the single record from `raw.githubusercontent.com` – each CVE at most once a week, at
  most 20 per round. A failed request is repeated next round; a CVE counts as "asked" only after an answer, a "not
  found" (404) or an unreadable record.
- **What is used:** the vendor's (CNA's) affected versions and CISA's data (ADP): CVSS, SSVC and KEV.

### EPSS {#epss}

[EPSS](term:epss) (Exploit Prediction Scoring System, by FIRST) estimates how likely a CVE is to be exploited in the
next 30 days and gives its percentile among all CVEs. Readers see the value on each finding and in the story
([EPSS and SSVC](/docs/vendor-news#epss-ssvc)).

- Asked for the CVEs of the followed products' findings and the CVEs of the stories of the last 30 days.
- Each CVE at most once a day (FIRST recalculates daily), up to 100 CVEs in one request to `api.first.org`.
- Only CVE numbers leave the server.

### OSV {#osv}

[OSV](term:osv) (osv.dev) knows affected and fixed versions of open-source packages. Cobe News asks OSV only by number:

- only with the CVE and its aliases (`GHSA-…`, `GO-…`, `PYSEC-…`, `RUSTSEC-…`) – never with product names or
  versions,
- only for products whose catalogue entry has the field `osv`: a list of ecosystem and package, e.g.
  `[Maven, org.apache.tomcat:tomcat-catalina]`. The list under *More sources* shows how many followed products have
  OSV packages,
- version ranges of the kinds ECOSYSTEM and SEMVER are kept, GIT ranges (commits) are dropped – they say nothing about
  an installed version,
- withdrawn OSV records are ignored,
- each CVE once a day while it is younger than 30 days, once a week after that.

### Exploit hints {#exploit-hinweise}

Three public collections say whether **public exploit code** or a **ready-made check** that exploits the vulnerability
exists for a CVE. Readers see it as “Public exploit code” on findings, in stories and on watched CVEs
([Public exploit](/docs/vendor-news#oeffentlicher-exploit)); in the [urgency](/docs/vendor-news#dringlichkeit-formel)
it counts +10 as long as the vulnerability is not already known as exploited.

| Collection | File | Size a day | Licence | Default |
|---|---|---|---|---|
| **Metasploit** (Rapid7) | `db/modules_metadata_base.json` from `raw.githubusercontent.com` – only modules of type “exploit” count | ~11 MB, ~1.4 MB compressed on the wire | BSD-3-Clause | **on** |
| **nuclei-templates** (ProjectDiscovery) | `cves.json` from `raw.githubusercontent.com` | ~2.3 MB, ~0.5 MB compressed | MIT | **on** |
| **Exploit-DB** (OffSec, GitLab mirror) | `files_exploits.csv` from `gitlab.com` | ~10 MB, uncompressed | GPL-2.0 (repository) | **off** |

- **The same file for everyone:** each collection is a public file – Cobe News loads it whole and looks up locally. No
  CVE number, no product, nothing about your installation leaves the server.
- **At most once a day**, conditional (`ETag`/`If-Modified-Since`): an unchanged file answers just “not modified”. A
  size limit per file (Metasploit and Exploit-DB 24 MB, nuclei 8 MB), the same hardening as every fetch
  ([Outgoing data](#ausgehende-daten)).
- **Only when needed:** like the KEV catalogue – with a followed product (Vendor News on) or with the news switched on,
  and while somebody watches a CVE.
- **Stored** per CVE and collection: only the link to the entry and when Cobe News first saw it – never the exploit
  itself. When a collection no longer lists a CVE, the hint goes with the next load. An answer with fewer than half of
  the entries so far counts as broken: an error, nothing is deleted.
- **First load** (or after more than three days without a fetch, e.g. because the collection was off): what it brings is
  shown but not notified as “Exploit published”.
- **Exploit-DB is off by default:** the biggest file, uncompressed, and its daily changes are mostly old entries edited.
  Switch it on if you want it.
- **Not used:** unofficial collections of PoC repositories (lists that search GitHub for “CVE-…”): unchecked, partly
  with malware, no stable licence. The GitHub Security Advisories say nothing about exploits.

Under *Health* the three appear as the family **“Exploit-Hinweise”** (kind “More sources”), one query
`exploit:<collection>` each.

### What leaves the server {#weitere-quellen-daten}

Only requests to the public addresses of these services and CVE or vulnerability numbers – **never** product names,
versions, your inventory or host names.

| Source | Targets | What is sent |
|---|---|---|
| CSAF providers | `wid.cert-bund.de` (the BSI's provider list), `cert-portal.siemens.com`, `www.cisco.com`, `www.se.com` | fetches of the public CSAF addresses |
| cvelistV5 | `api.github.com`, `github.com` (and GitHub's download servers), `raw.githubusercontent.com` | fetches of public files without sign-in; for single records the CVE number in the path |
| EPSS | `api.first.org` | CVE numbers |
| OSV | `api.osv.dev` | CVE and advisory numbers in the path |
| Exploit hints | `raw.githubusercontent.com` (Metasploit, nuclei), `gitlab.com` (Exploit-DB, when switched on) | nothing – a fetch of the same public file for everyone |

### Which source decides {#urteil-reihenfolge}

When several sources name the same vulnerability, this order decides for each version:

1. the vendor's own advisory (Palo Alto, Fortinet, Veeam, CSAF providers),
2. the NVD where it has analysed the CVE (CPE configuration),
3. cvelistV5 – the vendor's (CNA's) data; only if it does not name the product, CISA's (ADP),
4. the NVD's copy of the vendor's data – here too CISA's (ADP) only where the vendor does not name the product,
5. OSV last: it only decides a "possibly affected" and adds a missing fixed version, but never changes a clear verdict.

Also:

- A CSAF document of the BSI (WID) is no vendor advisory: it sums up several CVEs and the vendors' data. Next to the
  CVE records of its CVEs it decides only where they do not. If it names a product without a version ("every
  version") and the CVE records say "not affected", the verdict is "possibly affected"; its "not affected" (for
  example from per-line bounds that merge two CVEs) never counts against an "affected" of the CVE records.
- If the vendor names its affected ranges in the CVE record and explicitly not your version (every other version
  "unaffected", or the fix of your line), but the NVD's analysis has a range that includes it, the verdict is
  "possibly affected" – not "affected".
- A release above the end of an affected range of the same line counts as fixed (GitLab `>=12.8, <12.9.8`: 12.9.8
  contains the fix).

### Switching a source off {#weitere-quellen-aus}

Switch off and "Save":

- The source stops all requests at once.
- What it has fetched stays stored but no longer counts in the verdicts (EPSS is no longer shown).
- Switched on again, the stored records count again at once – without a new fetch.

Without cvelistV5, news of a new vulnerability only comes through the NVD and the vendors' advisories. Under *Health*
the sources appear as the kind **"More sources (Vendor News)"** (internally `structured`): the CSAF providers one by
one and the BSI's provider list, cvelistV5, EPSS, OSV and the exploit hints.

## Web Push {#web-push}

Web Push brings desktop notifications even when **no tab** of Cobe News is open – as long as the browser is running.
Each person switches it on for their own browser
([Desktop notifications](/docs/benachrichtigungen#desktop)). As an admin you only control the server.

How it works:

- After each fetch round the server sends new stories through the push service of the browser's maker.
- Content: title, severity and source of the story, end-to-end encrypted – the push service only sees the size.
- Signed with the server's [VAPID](term:vapid) key; it is created on first use and stored encrypted in the database.

### Settings in the .env {#web-push-env}

| Variable | Default | Meaning |
|---|---|---|
| `WEB_PUSH` | `1` | `0` switches Web Push off for everyone – then no request goes to the push services. Notifications in an open tab keep working. |
| `PUSH_CONTACT` | empty | Contact address for the push services, `mailto:` or `https:`, e.g. `mailto:secops@corp.example`. Empty: `BASE_URL` (here {{base_url}}). The push services see this address. |

Changes in the [.env](term:envfile) take effect after a restart:

```bash
cd /opt/cobe-news
docker compose up -d
```

With `WEB_PUSH=0` the card under *Notifications* shows "Not available because Web Push is switched off on the server
(WEB_PUSH=0)".

### Prerequisites {#web-push-voraussetzungen}

- **A certificate the computers trust.** With a certificate warning the browser refuses the service worker – push is
  then "not available", the open tab keeps notifying ([HTTPS](/docs/betrieb#https)).
- **Outbound https (port 443) to the push services**, through `HTTPS_PROXY` if set:

| Browser | Push service |
|---|---|
| Chrome, Edge on Android … | `fcm.googleapis.com` |
| Firefox | `*.push.services.mozilla.com` |
| Safari | `*.push.apple.com` |
| Edge on Windows | `*.notify.windows.com` |

The server accepts no other targets.

### Renewing the VAPID key {#web-push-vapid}

If you suspect a leak, this command creates a new key pair – effective at once, without a restart:

```bash
cd /opt/cobe-news
docker compose exec app python -m app.cli rotate-vapid
```

The existing push subscriptions are deleted; the browsers sign up again with the new key on their next visit. The same
happens automatically when the key can no longer be read (say after a changed [master key](term:masterkey)
`SECRET_KEY`).

## Outbound data {#ausgehende-daten}

Cobe News only fetches data – it reports no usage data anywhere. What does leave the server:

| Integration | Targets | What is sent |
|---|---|---|
| **News** (switched-on sources only) | the feeds' hosts, e.g. `www.heise.de`, `www.bsi.bund.de`, `www.cisa.gov`; the home pages once for the logos; when `www.cisa.gov` refuses the KEV fetch (HTTP 403), the official mirror `raw.githubusercontent.com/cisagov/kev-data` | plain fetches with the identifier `Cobe/…` and values for conditional fetches (`ETag`/`If-Modified-Since`). No user data. The server fetches the logos – the browser loads nothing from the news sites. |
| **Details from the source** | `services.nvd.nist.gov` and the advisories' hosts (`wid.cert-bund.de`, `cert-portal.siemens.com`, `sec.cloudapps.cisco.com`, `filestore.fortinet.com`, `security.paloaltonetworks.com`) | advisory identifiers and CVE numbers from public stories |
| **Vendor News** (only with a followed product; the KEV catalogue from `www.cisa.gov` or its mirror also without one while the news are on) | `services.nvd.nist.gov`, `endoflife.date`, `www.cisa.gov`; with products of these vendors also `security.paloaltonetworks.com`, `filestore.fortinet.com`, `www.veeam.com` | the CPE names and product names of the **followed** products (so the NVD learns which products you watch), the NVD key as a header. Your **versions** stay on the server – the comparison is local. The CPE search under "Not in the catalogue?" sends the search term to the NVD. |
| **Catalogue care** | `services.nvd.nist.gov` | CPE names of the catalogue, at most 20 requests per hour – only with Vendor News on and a followed product |
| **More sources** (CSAF providers, cvelistV5, EPSS, OSV) | `wid.cert-bund.de`, `cert-portal.siemens.com`, `www.cisco.com`, `www.se.com`, `api.github.com`, `github.com`, `raw.githubusercontent.com`, `api.first.org`, `api.osv.dev` | only fetches of public addresses and CVE or vulnerability numbers – never products, versions or host names ([What leaves the server](#weitere-quellen-daten)) |
| **Exploit hints** (Metasploit and nuclei on by default, Exploit-DB off) | `raw.githubusercontent.com`, `gitlab.com` (Exploit-DB only) | nothing – at most once a day the same fetch of a public file for everyone, conditional ([Exploit hints](#exploit-hinweise)) |
| **Update notice** (**on** by default, switch off under *Version & changelog*) | `api.github.com` (`/repos/G0urmetD/Cobe-News/releases/latest`) | one fetch without sign-in at most every 12 hours, conditional (`ETag`), with the user agent `Cobe/<version>` – nothing else about your installation ([Update notice](/docs/betrieb#update-hinweis)) |
| **Notification channels** | the respective service (Teams, Slack, Discord, Telegram, your mail server, your own webhook) | title, summary, severity, source, CVEs and links of the stories, the channel's and rule's name; for Vendor News rules also **product and version** of your systems ([Channels](/docs/benachrichtigungen#kanaele)) |
| **Personal notifications** (only once an admin allows the ways) | your mail server; for a person's own Teams webhook `*.logic.azure.com`, `*.powerplatform.com` or `*.webhook.office.com`; desktop through Web Push | the Vendor News messages of that person's products, as with the Vendor News rules with **product and version**; plus the weekly review and the welcome mail by e-mail ([Personal notifications](/docs/anmeldung#teams-persoenlich)) |
| **Forwarding to the team** | the team's forward channel | who forwards, the comment, title and link, for a finding the urgency and your versions ([Forwarding](/docs/benachrichtigungen#weiterleiten)) |
| **Web Push** | the browsers' push services | title, severity and source – end-to-end encrypted; `PUSH_CONTACT` |
| **Sign-in** | your domain controllers or `login.microsoftonline.com` and `graph.microsoft.com` | only when set up ([Sign-in](/docs/anmeldung#ueberblick)) |

The same hardening applies to every fetch: https only, no internal targets, size and time limits, at most one request
per website and minute, pauses after errors.

### Proxy (HTTPS_PROXY) {#proxy}

If the server has to reach the internet through a proxy, set in the `.env`:

```bash
HTTPS_PROXY=http://proxy.corp.example:3128
```

- The fetches of News, Details and Vendor News, the notification channels, Web Push and the sign-in with Microsoft go
  through it. E-mail (SMTP) and Active Directory connect directly.
- With a proxy, the **proxy** resolves the names. Cobe News then checks only addresses written as an IP in the URL –
  the proxy itself has to block internal targets behind names.
- A webhook into your own network (e.g. n8n) can bypass the proxy: switch off "Through the proxy (HTTPS_PROXY)" in
  the channel ([Webhook options](/docs/benachrichtigungen#webhook-optionen)).

### Own CA (CA_FILE) {#ca-file}

If the proxy breaks up TLS (TLS inspection) or a target uses a certificate of your internal CA, Cobe News needs that
CA's certificate:

1. Put the CA certificate (PEM) into the installation's `data` folder, e.g. `/opt/cobe-news/data/ca.pem`.
2. In the `.env`, enter the path **inside the container**: `CA_FILE=/data/ca.pem`.
3. `docker compose up -d`.

The CA applies in addition to the system's certificates – for feeds, details, Vendor News and notification channels.
TLS is always checked; it cannot be switched off.

> [!WARNING]
> `ALLOW_PRIVATE_FEEDS=1` allows feeds from private networks. Set it only if you really want to fetch an internal
> feed – otherwise an admin account could use it to reach internal services. Loopback and cloud metadata stay blocked
> in any case.

All variables with their defaults: [Operations → environment variables](/docs/betrieb#env-referenz).

## Health {#gesundheit}

*Integrations → Health* ([open](/settings/integrations?view=health)) shows how well each source is fetched: every news
source, every source family of Vendor News (NVD, Palo Alto Networks, Fortinet PSIRT, Veeam KB, CISA KEV,
endoflife.date) and, as the kind "More sources (Vendor News)", each of the [more sources](#weitere-quellen). The rules
for the states: [Source health](/docs/news-quellen#quellen-gesundheit). When sources are disturbed or dead, the
**Health** tab carries a marker.

### The table {#gesundheit-tabelle}

| Column | Content |
|---|---|
| **Source** | name; for Vendor News the family with the number of its queries |
| **State** | dead, disturbed, slow, healthy, off, not fetched yet – its meaning on hover |
| **Last success** | when the last fetch worked |
| **Last error** | kind and time of the last error |
| **New per week** | new items per week over the last 4 weeks, oldest on the left; "–" = no fetch that week |
| **Response time** | average duration of a request over the last 7 days, successful fetches only |

The worst come first. **"Problems only"** hides everything that is not disturbed or dead (the browser remembers the
choice). Switched-off sources are folded away and can be shown.

### The drawer {#gesundheit-schublade}

A click on a line opens its history:

- **Why** the state is what it is, last success and error, failures in a row, next try or pause,
- **Conditional fetches** – whether the source supports `ETag`/`Last-Modified` (then it answers just 304 when
  nothing is new),
- averages of the last 7 days: response time, size, number of fetches, timeouts, unreadable items,
- for Vendor News the single **Queries** (e.g. one per CPE),
- **Recent fetches** (time, status, duration, size, new items), **Recent errors** and **State changes**,
- "Set up source" leads back to the integration's tile (News or Vendor News).

The statistics go back 60 days. A fetch that did not ask at all (source paused) does not count.

### Notification on failure {#gesundheit-benachrichtigung}

So you do not notice a failure only in the table:

1. *Settings → Channels & rules*, tab **Rules**, create a rule.
2. Under "What is sent?" choose **"Source disturbed or dead"**, plus one or more channels.
3. "Save".

It is sent **once per change of state**: into disturbed or dead, from disturbed to dead, and back to healthy or slow –
never every round. The rule's severities and sources do not apply to it. Switching a source off and the first state
after an update send nothing. The states are compared every 5 minutes; a restart does not send anything twice either.
For Vendor News one message comes per family (if the NVD fails: one message, not one per CPE). More on rules:
[Rules](/docs/benachrichtigungen#regeln).
