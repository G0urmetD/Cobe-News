---
title: Vendor News & catalogue
summary: Follow the products and versions you run – and see which vulnerabilities affect exactly your versions, which update helps and when support ends.
audience: all
---

## Overview {#ueberblick}

The **Vendor News** menu item shows, for the products and versions you run, the vulnerabilities that affect
**exactly these versions**, newer versions of the same [release line](term:releaseline), the end of support and related stories.

The page shows the followed products and how they stand. From top to bottom:

- **Header:** under the title one line such as "Next end of support: PAN-OS in 6 months · fetched 2 minutes ago" (each
  only when known). On the right the **⋯** menu with "Add product" (admins; readers: "Browse the catalogue"), "Suggest
  a product", "Suggestions" or "My suggestions" and, for admins, "Fetch now" and "Settings". While suggestions wait for
  an admin, the **Suggestions** button with their number stands next to it.
- **Status row** with four fields and their numbers: **Action needed** (with "· 2 Now" inside, see
  [Urgency](#dringlichkeit)), **Possibly**, **Up to date** and **All**. A click shows only these products; the chosen
  field is highlighted. With the keyboard: Tab reaches the chosen field, the arrow keys move.
- **Tool row:** the search, **Filters** (with the number switched on), **View** (your [saved views](#vendor-lesen),
  "Default" without one) and a button that switches between cards and **list** (columns product, versions, target
  version, affected, critical, exploited, support until, urgency – every column sortable).
- **Active filters** as chips below it – a click on × removes one. On their right **"Mark all N read"** for exactly the
  products shown (see [Read, muted and views](#vendor-lesen)).

**Filters** holds the switches "Unread only" (with the number of unread findings), "Show muted", "Versions to review"
(with their number, when [reviewing versions](#versionen-pruefen) is on) and "My team | All" (see [My team](#mein-team)).

The **catalogue** – every product you can follow (more than 900, in categories) – opens with **⋯ → Add product**
(readers: "Browse the catalogue"), the **suggestions** with ⋯ or the button. Both have "Back to the overview" at the
top; the overview's search and filters stay as they were.

Each **card** shows for one product:

- how many vulnerabilities affect your versions ("3 affect you"), how many possibly do ("2 possibly"), and of those
  how many are critical and actively exploited,
- the target version (see [Target version](#zielversion)), "Update available", "Support ends soon" or
  "Support ended",
- the most important vulnerabilities – a click opens the drawer right at that entry.

A click on the card opens the product's **drawer** with the tabs "Vulnerabilities", "Versions" and "News", plus the
release lines, notes and tags.

**The number on the menu item** "Vendor News" counts the products where at least one vulnerability **affects** an
entered version (not "possibly"). It is orange, and red as soon as one of them is actively exploited.

> [!NOTE]
> If the page says "Vendor News is switched off", an admin has turned the feature off under *Settings →
> Integrations*. As long as it is off, no request goes to vendors, NVD or endoflife.date.

## Following products {#produkten-folgen}

The **catalogue** (⋯ → "Add product", for readers "Browse the catalogue") lists the products by category (firewalls & VPN, operating systems, virtualisation, storage &
backup, databases …). On the left are the categories with "followed / total" counters, plus "All" and "Followed".

- The **search** ("Search product, vendor or CPE …") is fuzzy: it finds vendors, product names, other spellings and
  [CPE](term:cpe) and forgives a typo.
- Each row shows vendor, category and whether the product has a CPE ("CPE" or "no CPE – news only"),
  "Versions & EOL" (release data available), "Vendor advisories" or "Cloud service".
- A click on a row opens the product's drawer – also for products nobody follows (then with release lines and news).

**Follow** (admins only):

1. Open the catalogue with **⋯ → Add product** and search the product.
2. Switch on **"Follow"** on the right of the row.
3. In the drawer, under "Versions", enter the versions you run (see [Versions](#versionen)).

Readers see the same list but cannot use the switch ("Only admins decide which products are followed.").

To pause, switching "Follow" off is enough – versions and notes stay. "Remove" in the drawer deletes the product with
all its versions and notes.

### Without a version or with versions {#ohne-oder-mit-version}

| | Without a version | With versions |
|---|---|---|
| What shows | every vulnerability and story about the product | only what affects your versions |
| Verdict | "concerns the product – enter a version for an exact check" | affected / possibly / not affected, with the fixed version |
| Update and end of support | no | yes, per version |
| Useful for | libraries and runtimes such as PHP or Node.js where you want to see the big current hole | everything whose version you know |

## Entering versions {#versionen}

In the drawer of a followed product, tab **"Versions"**:

1. Click "Add version" – the form "Enter a new version" opens.
2. Enter the **version**. The field checks it at once ("Format looks right." or the reason, e.g. "Unknown format –
   expected e.g. …"). Where a display form is translated, it shows before saving what is stored and compared
   ("→ 15.2.1748.24") – more under [version formats per vendor](#versionsformate).
3. Optionally a **label** (e.g. "DC North", "HA pair") and a **count** (devices with this version, 1 to 100,000).
4. "Add version".

Several versions per product are normal, for example one per site or cluster – at most 30 per product. Each version
is checked on its own. A vulnerability then shows "affects 2 of 3 versions", the card the worst state.

Entered versions appear as cards with their state: number of vulnerabilities, "Current" or "Update available → …",
"Support until …". The pencil edits a version, "Remove …" deletes it. An edited version is evaluated again at once,
without a new fetch.

> [!TIP]
> A version that is too short, such as `7.4` for FortiOS, covers several releases. It is accepted but marked
> "imprecise" – where the releases are affected differently, it says "possibly affected". Enter the exact version.

### Version schemes {#versionsschemata}

The format is checked per vendor so that versions are compared correctly:

| Product | Format | Example |
|---|---|---|
| PAN-OS, Panorama | version with [hotfix](term:hotfix) `-h` | `11.2.4-h23` (newer than `11.2.4-h4` and `11.2.4`) |
| FortiOS and other Fortinet products | three numbers, build optional, also the GUI/CLI line | `7.4.8`, `v7.4.3 build2573 (GA.F)`, `FortiGate-60F v7.4.3,build2573,240201 (GA.F)` |
| Cisco ASA, NX-OS | brackets | `9.18(4)22`, `10.2(5)` |
| Cisco IOS XE, FTD | letter as one more part, numbers; “(build …)” is ignored | `17.9.4a`, `7.2.5.1`, `7.2.5 (build 208)` |
| Cisco IOS (classic) | release with its train – compared within the train only | `15.9(3)M9` |
| Windows, Windows Server roles | build number, **no KB number**; also “OS Build …” from winver | `10.0.20348.2762`, `OS Build 26100.2605` |
| Sophos Firewall (SFOS) | MR = third part, build = fourth | `21.0.1.272`, `SFOS 21.0.1 MR-1-Build272`, `21.0 MR1` |
| Oracle Java SE | Java 8 in any spelling, stored as `8u…` | `8u411`, `1.8.0_411`, `Java 8 Update 411`, `21.0.5` |
| SAP (S/4HANA, NetWeaver) | component release as in SAP's advisories | `S4CORE 108`, `SAP_BASIS 758`, `7.58` |
| VMware ESXi, vCenter | version with update, also the VAMI version and the build ([more](#vmware-vsphere)) | `8.0 U3c`, `8.0 Update 3c`, `8.0c`, `8.0.3.00400`, `24322831` |
| Ivanti | R releases | `22.7R2.3` |
| Veeam | the whole build | `12.3.2.4934`, `13.1.2 (build 13.1.2.57)` |
| WAGO PFC100/PFC200 | firmware with its index in brackets – the index counts | `04.06.03(28)`, `FW28` |
| Zoho ManageEngine (ServiceDesk Plus, ADSelfService Plus, Password Manager Pro, PAM360, OpManager) | version with build number – the build counts | `14.6 Build 14600`, `14600`, `12.8.329` (OpManager) |
| Linux distributions | release | `12`, `9.4`, `24.04` |
| everything else | numbers and letters | `8.3.14`, `1.0.2u`, `9.8p1` |

Special cases:

- **Windows:** a KB number cannot be compared and is refused. Which KB is which build is in Microsoft's update
  history.
- **Veeam:** best enter the whole build. A short `12.3.2` stands for every build of 12.3.2 – only what holds for all of
  them is decided, otherwise it says "possibly affected". `12.3.2 P4` cannot be compared; the KB article says which
  build a patch is. The Veeam Agent has a catalogue entry per operating system.
- **Zoho ManageEngine:** the products count by build number (Help → About: "14.6 Build 14600"). The build is compared –
  with the advisories' build bounds ("before 10509") and with NVD's bounds as a version line ("< 14.9" = before every
  build of 14.9). A version without build (`14.6`) stands for every build of 14.6; only what holds for all of them is
  decided. Fix and target version are shown as a build ("14.9 Build 14920").
- **Linux distributions:** Vendor News shows the release line and the end of support. Whether a hole is closed depends
  on the package versions – only the distribution's advisory says that.
- **Cloud services** have no version on your side; advisories show as "Cloud service affected".

For every entered version: a word standing on its own before a number must be a separator word (`Update`, `build`,
`Patch`, `SP`, `CU`, `RU`, `Take` …). “iLO 6 v1.62” would otherwise be version 6.1.62 – so the product's name is removed
first (1.62 is stored), an unknown word is refused. Platforms like `x64` or `amd64` after the version are ignored.

### Version formats per vendor {#versionsformate}

Many vendors show their version differently from how their advisories name it. Vendor News takes the display form and
stores what advisories compare – the form shows it first (“→ …”):

| Product | What you see | stored as |
|---|---|---|
| Microsoft Exchange Server | `15.02.1748.037` (ExSetup), `2019 CU15 Apr25HU`, `SE RTM Oct26SU` | the build, e.g. `15.2.1748.24` |
| Microsoft Exchange Server | `2019 CU15` (without an update) | `15.2.1748` – stands for every build of CU15 (“imprecise”) |
| Microsoft SQL Server | `2022 CU16`, `2022 CU16 GDR`, `KB5048033`, the whole line of `SELECT @@VERSION` | the build, e.g. `16.0.4165.4` |
| VMware Tools | code in the vSphere Client `12416` | `12.4.0` |
| GlobalProtect App | build `6.2.8-c948` | hotfix `6.2.8-h10` |
| VMware vCenter, ESXi | `8.0.3.00400`, build `24322831` ([more](#vmware-vsphere)) | `8.0 U3d` |
| HPE iLO | `iLO 6 v1.62` | `1.62` |
| Adobe Acrobat/Reader | `2024.005.20320` | `24.005.20320` |
| Microsoft Office / 365 Apps | `Version 2411 (Build 18227.20162 Click-to-Run)` | `16.0.18227.20162` |
| NetScaler ADC/Gateway | `NS14.1: Build 29.72.nc` | `14.1-29.72` (FIPS builds: `14.1-29.72 FIPS`) |
| Cisco ISE | `3.2.0.542 Patch 5` | `3.2 Patch 5` |
| Check Point | `R81.20 JHF Take 99`, `R81.20 - Build 012` | `R81.20 Take 99`, `R81.20` |
| NGINX Plus | `nginx/1.27.2 (nginx-plus-r33)` | `R33` |
| Sophos Firewall | `SFOS 21.0.1 MR-1-Build272` | `21.0.1.272` |
| Oracle Java SE | `1.8.0_411`, `Java 8 Update 411` | `8u411` |

The tables come with the catalogue and name their source and fetch date (Microsoft Learn for Exchange and SQL Server,
VMware's version table for the Tools, Palo Alto Networks' release notes, Broadcom's KB articles for vSphere). What a
table does not know is **refused, never guessed** – then enter the build. A name Microsoft gives to several builds
(`2022 GDR`) does not work; neither does Exchange's AdminDisplayVersion (“Version 15.2 (Build 1748.10)”): it does not
show security updates.

Refused on purpose, with a hint in the form:

- **.NET:** the SDK version from `dotnet --version` (`8.0.403`) – advisories name the runtime (`dotnet --list-runtimes`,
  e.g. `8.0.11`).
- **SAP S/4HANA:** the product release (`2023`) – SAP's advisories name the component (`S4CORE 108`).
- **Office:** the version number alone (`2411`).
- **GlobalProtect:** a build the release notes map to no hotfix (e.g. `6.3.3-c1199`) – then enter the hotfix
  (`6.3.3-hN`).

### Plausibility check {#plausibilitaet}

A version must fit the product's release lines (endoflife.date, shipped with the catalogue and refreshed daily). If its
major version lies far above every known line – more than one and a half times the highest and more than ten above
it –, it is almost certainly a year, a marketing number or an internal code: `2411` for Firefox, `2019` for nginx. The
form refuses it and names the known lines and an example. Lines newer or older than the known ones are fine. Products
without release lines are not checked for this; some have a fixed pattern instead (Exchange and SQL Server: build
numbers, VMware Tools: `12.4.0`).

Some products have only part of the lines: **Mozilla Firefox ESR** only the ESR lines (115, 128, 140, 153 …),
**Jenkins LTS** only the LTS lines (2.555, 2.568 …). A version in between that is on none of them – `134.0` for
Firefox ESR, `2.500.1` for Jenkins LTS – is refused by the form, which names the lines; mostly it is the other product
(Mozilla Firefox, Jenkins weekly). A line newer than all known ones is fine here too.

### Split products {#getrennte-produkte}

Products with two version lines under one name are split, because their advisories count them apart:

| Product | split into |
|---|---|
| pfSense | **pfSense CE** (`2.8.0`) and **pfSense Plus** (`24.11`) |
| Firefox | **Mozilla Firefox** and **Mozilla Firefox ESR** (`140.4.0esr`) – NVD tells them apart by the edition `esr` |
| Jenkins | **Jenkins LTS** (`2.492.2`) and **Jenkins (weekly)** (`2.499`) – NVD tells them apart by the edition `lts` |
| nginx | **nginx (Open Source)** (`1.27.2`) and **NGINX Plus** (`R33`) |

Whoever already follows the former product keeps following it. A version that belongs to the other product (`24.11`
for pfSense CE, `128.5.1esr` for Firefox) stays entered but shows [“Please review”](#versionen-pruefen) with a hint
which product it belongs to – until then it only counts as “possibly affected”. Follow the other product, enter the
version there and remove it here.

Similar for products whose editions share version numbers: Vendor News tells **SharePoint** 2016, 2019 and
Subscription Edition (all 16.0.x) apart by the build, **SQL Server**'s GDR and CU branches likewise, and for
**Exchange** only the row of a build's own cumulative update counts – a row for another edition or CU says nothing about
your version.

### Merged products {#zusammengelegte-produkte}

Some products were in the catalogue twice up to 0.1.44. Since 0.1.45 there is one of each:

| formerly also | now |
|---|---|
| IBM Db2 (`db2`) | **IBM Db2** (`ibm-db2`, endoflife.date's key) |
| Omnissa Horizon (`vmware-horizon`) | **Omnissa Horizon (VMware Horizon)** (`horizon`) – “2412” is stored as `8.2412`, as endoflife.date writes the lines |
| Juniper SRX (`juniper-srx`) | **Juniper Junos OS** (`junos`) – SRX runs Junos OS, a vulnerability holds for both |
| VMware Harbor Registry | **Harbor** (`harbor`) |
| Stormshield Firewall (device models) | **Stormshield Network Security (SNS)** (`sns-firmware`) – the firmware is compared |
| Cisco Secure Email Gateway (`cisco-sma`) | **Cisco Secure Email Gateway (ESA)** (`cisco-esa`); the management appliance (SMA) is now **Cisco Secure Email and Web Manager** (`cisco-sewm`) |

The update moves everything along: followed products with their versions, notes and tags, team assignments with the
chosen people, findings with their “already notified”, read marks, mutes, watched CVEs and saved views. Whoever followed
both entries has one afterwards – with the versions of both (a version both had, once). Old links
(`/vendor?product=db2`) open the new product; the old name still finds it in the catalogue search.

### Windows Server roles {#windows-rollen}

WSUS, AD DS (domain controller), Remote Desktop Services/RD Gateway, NPS, RRAS, DHCP, DNS, AD FS and AD CS are entries
of their own but have no version of their own: enter the **build of the server** holding the role (`winver` or
`[Environment]::OSVersion`, e.g. `10.0.20348.2762`). They share Windows Server's CPEs; only CVEs whose description names
the role are shown (for the domain controller also Kerberos, Netlogon and LDAP). The cumulative Windows update fixes
them – so follow **Microsoft Windows Server** as well.

### Where is the version? {#wo-steht-die-version}

The form "Enter a new version" helps you find it:

- **"How to find the version:"** – a command with a copy button, e.g. `show version`. If the command comes from
  endoflife.date, it says "from endoflife.date – read it before running it".
- **"Where is the version?"** – a text for products without a simple command, e.g. for Veeam Backup & Replication:
  console → main menu → Help → About.
- Hints for the product, e.g. for Windows: `winver` or `[Environment]::OSVersion` shows the build.

Products NVD knows only per device model (DrayTek, Zyxel, Teltonika, mGuard, RUGGEDCOM, StoreOnce …) name the common
models; printers and multifunction devices (HP, Canon, Kyocera, Konica Minolta) and products without a CPE (e.g.
Matrix42 Empirum, Aagon ACMP, Swyx, d.velop, ELO, ESET PROTECT, iRMC, iLO 7, iDRAC10) have a hint saying so: stories and
the CVEs whose vendor data names the product are shown there – no version is compared.

**Search names:** the catalogue search also finds products by old and short names – VBR, SCCM/MECM/ConfigMgr, Lync,
M365 Apps/Office 365, MDE, SEP, OfficeScan, KES, ConnectWise Control, Check_MK, NSX-T, vROps, VCF, XenApp/XenDesktop,
domain controller, WS2022, SRX, IronPort, Bomgar, AirWatch, vManage …

### VMware vSphere: vCenter Server and ESXi {#vmware-vsphere}

"VMware vSphere" is two products in the catalogue – searching for "vSphere" finds both:

- **VMware vCenter Server** for the vCenter (the appliance, VCSA). The version is in the VAMI at
  `https://<vcenter>:5480` → **Summary** or in the vSphere Client under Help → About VMware vSphere.
- **VMware ESXi** for the hosts. `vmware -v` on the host shows the version (`VMware ESXi 8.0.3 build-24022510`), and so
  does the Host Client under Help → About.

The version can be entered the way it is shown there:

| Input | Example | stored as |
|---|---|---|
| release | `8.0 U3d`, `8.0 Update 3d`, `8.0c` (patch of the GA release), `8.0` (GA) | as entered |
| vCenter's four-part version (VAMI) | `8.0.3.00400` | `8.0 U3d` |
| build, alone or with the version | `24322831`, `build-24022510`, `8.0.3-24022510`, `VMware ESXi 8.0.3 build-24022510` | `8.0 U3d` or `8.0 U3` |

Before saving, the form shows which release it is ("→ 8.0 U3d"). Four-part versions and builds are looked up in
Broadcom's tables (KB 326316 for vCenter, KB 316595 for ESXi) – vCenter and ESXi have build numbers of their own, an
ESXi build entered for vCenter is not recognised. An unknown build is refused rather than guessed: then enter the
release, such as `8.0 U3d`. `vmware -l` does not name the patch letter (`8.0 Update 3` for 3e too) – better take the
build from `vmware -v`. From vSphere 9 on, the four-part version is the release itself (`9.0.2.0100`).

Advisories name the releases that are compared: `8.0 U3c` < `8.0 U3d`, and the patches of the GA release come before
(`8.0` < `8.0a` < `8.0c` < `8.0 U1`). If a product of the vSphere family is missing, you can
[suggest it](#produkt-vorschlagen).

## Reviewing versions {#versionen-pruefen}

Cobe News never queries a system – you enter the versions by hand. Over time they age, and then “affected” or “not
affected” becomes unreliable. So every entered version remembers **when somebody last said it still runs like this**,
and who:

- **Entering or changing** a version confirms it.
- **“Confirm”** (“still running like this”) confirms it without changing anything. Nothing is evaluated anew, the
  [urgency](#dringlichkeit) stays as it is.
- **“Confirm all”** confirms all due versions of a product or a team at once – after a question. Really check first:
  a wrong version makes the verdict unreliable.

If a version was not confirmed for longer than the set period (90 days by default), it shows **“Please review”** – on
the card, in the list, on the drawer's “Versions” tab (“not confirmed for 120 days”) and on the vulnerabilities whose
verdict depends on that version (“Review version”). Under **Filters** the switch **“Versions to review”** shows their
number; switched on, it shows them above the overview – grouped by team, each with “Confirm”.

**Entries that no longer fit:** if an entered version no longer fits the product after a catalogue update – it belongs
to a [split product](#getrennte-produkte), a table does not know it, it is [implausible](#plausibilitaet) –, it shows
“Please review” as well, however recent its confirmation, with the reason on the card (“Entry no longer fits – please
correct it”). It is still checked, but only as “possibly affected”; “Confirm” does not change that, only correcting it.
An entry from before a table that the table can translate (`2019 CU15` for Exchange) is compared correctly right away –
the card shows “compared as 15.2.1748”.

**Who is responsible:** with *Teams* switched on, a product's teams see and confirm its versions. All other products –
and all of them while Teams is off – are the admins' job. Admins can confirm any version; readers without a team see
the hints but confirm nothing.

**Reminder by e-mail:** whoever gets their team's [weekly review](/docs/benachrichtigungen#wochenrueckblick) finds the
section “Versions to review” in it – once a week at most, bundled, no setting of its own.

> [!NOTE]
> Admins set the period under *Settings › Integrations › Vendor News*: 30, 60, 90, 180 or 365 days, or off. After the
> update to this version, versions entered before count as confirmed at their last change – only those nobody
> touched for longer than the period are due.

## Target version, update and end of support {#zielversion}

For each entered version Vendor News works out what to do:

- **Target version** – the smallest version of **your** release line that fixes the most of the vulnerabilities
  affecting this version. Each candidate is checked with the same data as your version (hotfix levels, builds). The
  card then says "Updating to … fixes all 3 vulnerabilities" or "Updating to … fixes 2 of 3".
- If your line has no fix, it says "Newer line needed: …". If there is no fix at all yet, it says "No fix yet for …".
- If the target version is itself affected by another vulnerability, that is shown as well.

**Update available** means: your release line has a newer patch (according to endoflife.date) – an update within the
line, not a line change. "Current" means: you run the newest patch of the line.

**End of support** ([EOL](term:eol)) comes from endoflife.date:

| Shown | Meaning |
|---|---|
| "Support until …" / "Supported" | support runs for at least 6 more months |
| "Support ends soon" | ends within 6 months |
| "No support since …" / "No support" | EOL reached, no more security updates – plan a line change |

The same 6-month threshold applies to card, drawer and notification.

### Warning before the end of support {#eol-vorwarnung}

For **each version entered** a warning comes **90 days** and **30 days** before its end of support, and one when the
support **has ended** – each stage exactly once per version. They belong to the kind "Versions & EOL": rules with this
kind and the personal notifications with "Versions & EOL" get them; a rule's team filter applies as usual.

- **Date moved.** If the vendor moves the end of support, the new date counts. Only what is more urgent than what was
  said last is sent: after "30 days left", an end moved to 80 days from now gives no second 90-day warning – the 30
  days of the new date come when it is time.
- **No catch-up.** After the update to this version only the state of now counts: if support ends in 20 days, a 30-day
  warning comes, no 90-day warning before it. An end of support already reported, or more than 30 days ago, does not
  come again.
- A newly entered version starts silently as always (first check).

You can also subscribe to the dates as a calendar: [Calendar (iCal)](/docs/benachrichtigungen#kalender-ical). The drawer shows the product's **release lines**
with the latest version, release date, end of support and status; "your line" is marked, older lines without support
are folded. A line with especially long support is called [LTS](term:lts).

## Affected, possibly, not affected {#bewertung}

Each vulnerability is judged for each entered version on its own. The drawer groups them accordingly:

| Verdict | When |
|---|---|
| **Affected** ("Affects your versions") | The source names your version explicitly as affected, or it lies in the affected version range. The fixed version is shown. |
| **Possibly affected** ("data not conclusive") | The data is not enough for a sure answer – the reason is shown with each version. |
| **Not affected** | Only when the data decides it: your version contains the fix, the vendor says the line is not affected, or your version is newer than everything the advisory names. |
| Concerns the product | Product followed without a version. |
| Cloud service affected | A service of the vendor – the vendor fixes it; whether you need to act is in the advisory. |

Typical reasons for **"possibly"**:

- the entered version has a format that cannot be compared, or is too imprecise (`7.4` instead of `7.4.8`),
- the source names the version without a hotfix or update level,
- the advisory does not name your release line,
- NVD says "all versions" without a limit,
- only single hotfix levels are affected and yours is not named,
- a PAN-OS advisory that says nothing about Panorama,
- the sources disagree: not affected according to the vendor, in the affected range according to the NVD – or "every
  version" without a version according to the BSI, not affected according to the CVE data.

Every reason names its source: "according to the vendor" appears only where the verdict comes from the vendor itself
(its advisory or its data in the CVE record); otherwise "according to the NVD", "CISA (ADP)", "the BSI", "OSV" or
"source: …". A CVE record counts as the vendor's word only when the vendor wrote it (it is the record's CNA). When
someone else wrote it – GitHub's advisory database for an open-source project, VulDB, MITRE or HackerOne, for example –
it reads "according to GitHub (not the vendor)", "according to VulDB (not the vendor)" …; a CNA the NVD names only by
an identifier shows as "CNA (not the vendor)". Such data never outweighs the NVD's analysis: when the NVD says
"affected", that stands.

When several sources name the same vulnerability, the vendor's advisory decides before the [NVD](term:nvd), the NVD
before the CVE list ([cvelistV5](term:cvelist)), and OSV comes last – details:
[Which source decides](/docs/integrationen#urteil-reihenfolge). Vulnerabilities that do not affect you are folded
("also show … not affecting"). When in doubt, "Open advisory" and read it there.

### Unclear old data {#unklare-altdaten}

Old CVEs with unclear data, published at least a year before your release line came out, go to **"Unclear old
data"**: they do not count as "possibly", do not appear in numbers and notifications and are folded – only for
checking. Actively exploited CVEs never go there.

### First fetch {#erstabruf}

Some advisories carry the grey marker **"First fetch"**. They came with the first fetch of a [CSAF](term:csaf)
provider (Siemens, Cisco, Schneider Electric, Open-Xchange) once you follow a product of that vendor. This first fetch goes back
90 days; what is older than 7 days is marked.

- The advisory **is shown** and counts like any other finding (affected, possibly …).
- It is **not sent** – no notification, so that a new provider does not set off a flood of old advisories.
- Newer advisories from the same provider are notified as usual.

How the fetch works: [CSAF providers](/docs/integrationen#erstabruf) (admins).

## Actively exploited {#aktiv-ausgenutzt}

A vulnerability counts as **actively exploited** when it is in CISA's [KEV](term:kev) catalogue, reported as
exploited in the [EUVD](term:euvd) (from the news, when that source is switched on) or the vendor says so in its
advisory. It then carries "actively exploited", counts as at least high, and a KEV entry linked to ransomware shows
"ransomware" as well.

Actively exploited vulnerabilities that affect your versions put the card first (red edge, "… actively exploited")
and turn the number on the menu item red – update these first.

**Notification:** the rule kind "Vulnerability affects one of our systems" reports each vulnerability **once per
product and version**. If a known vulnerability is later actively exploited (e.g. new in the KEV), exactly one
**"Now actively exploited: …"** follows. Not sent: what is already known when a newly followed product or a new or
changed version is checked for the first time (it is on the page), and advisories older than 30 days – unless fresh in
the KEV. Admins set up the rules, see [Notifications](/docs/benachrichtigungen#regeln).

## Changes to advisories {#aenderungen}

Vendors often revise advisories after publishing them: a new fixed version, another severity, a wider affected range, an
advisory withdrawn, an addition to the [KEV](term:kev). Vendor News remembers what an advisory said last and records a
new [revision](term:revision) for every change **in content** – for example "Revision 3: New fixed version 11.1.6,
severity from High to Critical".

**What counts:**

- fixed versions (new or removed)
- affected ranges and products (widened or narrowed)
- severity and [CVSS](term:cvss)
- more or removed CVEs
- addition to the KEV
- withdrawn (the source took the advisory back)

**What does not count:** whitespace, case, order, time stamps, a reworded description and the document's version number
alone. If a source suddenly lacks a value (no CVSS any more, no fixed version), that is a gap of the source, not a
change – the last known value stays.

**No noise:** the first time an advisory is stored and the first fetch of a source have nothing to compare with. If an
update of Cobe News changes how a source is read, the state is set anew silently. If a source changes nearly all known
advisories at once, that counts as a reformat and is taken over silently as well.

**Effect on your versions:** if the revision changes the verdict for a version entered – say "not affected" → "affected",
or there is a fixed version now – it is shown at the top and in red. The verdict is that of the changed source; the
list of findings still shows the overall verdict of all sources.

**Where you see it:**

- A finding shows **"Changed"** with the date when its advisory changed within the last 30 days. The tooltip says what
  changed.
- The product has the tab **Changes** with all revisions, newest first.
- A product's card shows "Changed", in red when a change concerns your versions.
- A story with details from the source shows under "Changes" how the advisory behind it changed.

The last 20 revisions per advisory are kept, for one year at most. **Notification:** with the rule kind "Advisory
changed" ([rules](/docs/benachrichtigungen#regel-arten)). Existing rules do not get it automatically.

## EPSS and SSVC {#epss-ssvc}

Besides the severity and the [CVSS](term:cvss) score, findings show two hints at **how urgent** a vulnerability is.
They complement "actively exploited" – they do not replace it.

### EPSS {#epss}

[EPSS](term:epss) is the probability that a vulnerability is exploited in the **next 30 days**. FIRST calculates it
daily for every CVE. The finding shows it as a percentage, e.g. **"EPSS 0.4 %"** or **"EPSS 97 %"**. If a finding has
several CVEs, the highest value is shown.

Hovering shows more, e.g. "EPSS 97 % for CVE-2026-1234 (percentile 99.9), as of …":

- **Percentage:** the estimated probability of exploitation.
- **Percentile:** how many CVEs are lower – 99 means: higher than 99 % of all CVEs.
- **As of:** the day FIRST calculated the value.

| Colour | EPSS | How to read it |
|---|---|---|
| red | from 50 % | very likely exploited – act now |
| orange | from 10 % | clearly raised – patch soon |
| yellow | from 1 % | raised |
| grey | below 1 % | the vast majority of CVEs |

Good to know:

- EPSS is a **prediction**, not an observation. A vulnerability in the [KEV](term:kev) catalogue is already being
  exploited – "actively exploited" always weighs more than an EPSS value.
- A low value does not mean "harmless": new CVEs often get a meaningful value only after a few days.
- If the value is missing, FIRST does not know the CVE yet or an admin has switched EPSS off.
- The details of a story show the EPSS value for each CVE as well
  ([Details from the source](/docs/news-quellen#details-aus-der-quelle)).

### SSVC {#ssvc}

[SSVC](term:ssvc) is the US agency CISA's assessment of a CVE (from the CVE list cvelistV5). Cobe News shows it only
when it says more than "nothing known":

| Shown | Meaning |
|---|---|
| **"SSVC: actively exploited"** (red) | CISA knows of attacks exploiting the vulnerability. |
| **"SSVC: public exploit code"** (orange) | Code or instructions for exploiting it are public – attacks are possible at any time. |
| Addition **"· automatable"** | An attacker can automate the exploitation, say for mass scans on the internet. That raises the urgency considerably. |

When "SSVC: actively exploited" is shown, the separate "actively exploited" marker is left out (it says the same); a
KEV entry is still shown as **KEV**.

### Public exploit {#oeffentlicher-exploit}

**“Public exploit code”** (orange) means: a public collection lists code that exploits the vulnerability, or a ready-made
check that exploits it. Next to it, one link per collection opens its entry:

| Collection | What it lists |
|---|---|
| **Metasploit** | an exploit module of the Metasploit Framework (only modules of type “exploit”, no mere scanners) |
| **Exploit-DB** | an entry in OffSec's Exploit Database (proof of concept, exploit code) |
| **nuclei** | a template of ProjectDiscovery's nuclei-templates – a ready-made check that finds the vulnerability on the network |

Good to know:

- This is **no statement about attacks**: a public exploit makes attacks easy, “actively exploited” means they happen.
  If both are shown, “actively exploited” counts (also in the [urgency](#dringlichkeit-formel)).
- Cobe News stores only the CVE, the collection, the link and when it first saw the entry – **never the code**.
- The collections are loaded at most once a day; a new entry shows up by the next day at the latest. An admin decides
  which collections are loaded ([Exploit hints](/docs/integrationen#exploit-hinweise)) – by default Metasploit and
  nuclei, not Exploit-DB.
- No hint only means: none of the switched-on collections lists the CVE. Exploits circulate elsewhere too.
- The same hint is shown in a story's details next to its CVEs and in the list of
  [watched CVEs](/docs/benachrichtigungen#cves-liste); when an exploit appears for a watched CVE, the notice **“Exploit
  published”** comes once ([When a notice comes](/docs/benachrichtigungen#cves-meldungen)).

### Sorting by EPSS {#nach-epss-sortieren}

In a product's drawer, tab "Vulnerabilities", the **"Sort"** choice appears when there is more than one vulnerability:

- **"Relevance"** (default) – affected before possibly, actively exploited first, then by CVSS.
- **"EPSS – most likely to be exploited"** – within each group (affected, possibly …) the vulnerability with the
  highest EPSS value first; findings without a value come last.

The groups themselves keep their order – a vulnerability that affects you never sits below one that only possibly
affects you.

## Urgency {#dringlichkeit}

Every finding gets a **number from 0 to 100**: how urgent is this vulnerability *for your version*? The number comes
with its **level**, e.g. **“77 · Now”**. Hovering shows how it came about – for example “CVSS 9.8 (Critical) +35, KEV
+30, your version affected +25, known for 3 days +10”.

| Level | Number | Colour | Reading |
|---|---|---|---|
| **Now** | 60 and above | red | act today |
| **Soon** | 35 to 59 | orange | in the next maintenance window |
| **Watch** | below 35 | grey | keep an eye on it |

The number replaces nothing: the verdict (affected, possibly …), “actively exploited” and the target version stay as
they are. It only puts them into **one** order.

### How it is computed {#dringlichkeit-formel}

No model, no learning – fixed points, added up and kept between 0 and 100:

| Factor | Points |
|---|---|
| Severity from the [CVSS](term:cvss) score (without CVSS: the severity given) | critical (9.0 and above) +35 · high (7.0 and above) +25 · medium (4.0 and above) +12 · low +4 |
| [EPSS](term:epss) percentile | 95 % and above +20 · 80 % and above +10 · 50 % and above +5 |
| In the [KEV](term:kev) catalogue | +30 |
| Otherwise known as exploited (vendor, [EUVD](term:euvd)) | +25 |
| [Public exploit](#oeffentlicher-exploit) (Metasploit, Exploit-DB, nuclei) – only when the vulnerability is not already known as exploited | +10 |
| Your version | affected +25 · possibly affected or no version given +5 · cloud service 0 · unclear old data −50 · not affected −70 |
| No fix known (when affected or possibly affected) | +5 |
| Age | published within the last 7 days +10 · within the last 30 days +5 |

Good to know:

- **“Not affected” pushes down hard:** even a critical, exploited vulnerability with a high EPSS stays below 35 for a
  version that is not affected – that is, at *Watch*.
- If a finding concerns **several of your versions**, the most urgent one counts; the tooltip names it.
- **Critical and affected** gives at least 60 (*Now*), **high and affected** 50 (*Soon*) – in line with the red and
  orange cards of the overview.
- **Public exploit +10** sits deliberately between “nothing known” (0) and “exploited” (+25/+30) – as
  [SSVC](term:ssvc)'s “exploit code public” sits between “none” and “active”. If the vulnerability is already known as
  exploited, only that counts; never both. So **high and affected** with a public exploit gives 60 (*Now*) instead of
  50 – findings without an exploit keep their number.
- The server computes the number from data Cobe News has anyway – no extra query. The age moves on daily, so a number
  can drop overnight.

### Where it shows {#dringlichkeit-anzeige}

- **A product's card:** the number of its most urgent finding, top right.
- **List:** the *Urgency* column – a click sorts by it (most urgent first).
- **Status row above the overview:** “· N Now” in the “Action needed” field – how many of the products that need
  action have a finding marked “Now”.
- **Order of the cards:** as before by need for action (exploited → critical → affected …); within a group the higher
  number comes first.
- **A product's drawer:** on every finding; under *Sort*, **“Urgency – most urgent first”** sorts by it within each
  group.

## Read, muted and views {#vendor-lesen}

Vendor News, too, remembers **per person** what you have seen – the unit is the **finding**: one vulnerability of one
followed product (the same CVE on two products is two findings, as you check it per product).

- **New** is a finding reported as news – or again, e.g. because it is now actively exploited – that you have not
  opened since. What was there at a product's first fetch ([First fetch](#erstabruf)) is not new; what came more than
  30 days ago counts as read.
- The tile says "3 new", the lines of the worst findings carry a dot. **Opening** the drawer marks the product's
  findings as read; there the ones unread before keep "New" until you close it. On a finding, "Mark as unread" sets it
  back.
- **Unread only** (under *Filters*, with the number of unread findings) shows only products with new findings.
  **"Mark all N read"** next to the filter chips marks the unread findings of exactly the products shown – N is their
  number (a muted product's only with "Show muted"). It appears as soon as N is above 0.
- The tile's **⋯** menu: "Mark all findings as read" and [mute](/docs/benachrichtigungen#stummschalten) the product. On a
  finding, "Mute" mutes its CVEs.
- Muted products are left out until you switch on **Show muted** under *Filters* (then pale with "Muted until …"). **Exception:** when
  an actively exploited finding affects the product, the tile stays visible with "KEV while muted" – you still get no
  notification about it.
- Status, search and filters are part of the address – savable and shareable as a
  [view](/docs/erste-schritte#ansichten). **View: …** in the tool row names the one chosen ("Default" without filters,
  "Custom" for filters that are not a saved view). Older links and views keep working: "Now", "actively exploited" and
  "support ending / ended" of the former summary show as a chip, `?tab=catalog` and `?tab=suggestions` open the
  catalogue and the suggestions.

## My team {#mein-team}

When an admin has switched *Teams* on and you belong to a team, **Filters** has the choice **My team | All**; "My
team" then shows as a chip under the tool row (× switches to *All*):

- **My team** shows only the products you get through your teams: a team's products set to "Everyone in the team"
  and those an admin has picked you for in person. The same choice decides the
  [vendor news of my products](/docs/benachrichtigungen#meine-produkte).
- **All** shows every followed product.

This browser remembers your choice for you. It starts at *My team*. If no product is assigned to your team yet, the list
is empty – *Show all* takes you back. The number at "Vendor News" in the sidebar counts your unread findings in the same
choice; its colour (or a dot when nothing is unread) shows whether a followed product is affected (red: actively
exploited).

## Products outside the catalogue {#eigene-produkte}

If a product is missing from the catalogue, an admin can add it by its [CPE](term:cpe):

1. In the catalogue (⋯ → "Add product") click **"Not in the catalogue?"** – "Add a product by CPE" opens.
2. Under "Search the CPE dictionary" enter vendor or product (at least 3 characters). The search asks NVD's CPE
   dictionary – at most every 7 seconds, results are kept for an hour.
3. Pick a hit or type the CPE yourself, form `part:vendor:product`, e.g. `a:zyxel:usg_flex_100_firmware`.
4. Choose **display name** and **category**, then "Add and follow".

The entry carries "Own entry" and behaves like a catalogue product with CVEs from NVD – without vendor advisories and
without release data. If the search finds nothing: try another spelling or search the vendor only.

## Suggesting a product {#produkt-vorschlagen}

If a product you use is missing, anybody signed in can suggest it: **⋯ → Suggest a product**, **“Product missing?
Suggest it”** in the catalogue (also when the search finds nothing) and below the overview.

1. Enter **vendor** and **product**. Similar products of the catalogue appear below (“Did you mean …?”) – a click opens
   them. If none fits, go on.
2. Optionally the **website or advisory page** (`http`/`https` only; Cobe News does not fetch it) and the
   [CPE](term:cpe), if known.
3. **Why** – where it runs, what you need it for. Optionally a **team**.
4. “Suggest”.

At most 10 suggestions a day per person. You see their state under **⋯ → My suggestions**: open, accepted, rejected
(with a reason) or duplicate (with the existing product). A new answer shows a dot on ⋯ and a number on the entry. Only an admin sees
other people's suggestions.

### Answering suggestions {#vorschlaege-beantworten .admin}

Admins open the suggestions with the **“Suggestions”** button next to the title (it appears with their number while
some are open) or with **⋯ → Suggestions** – there the open and the answered ones:

- **Accept** – either *add by CPE*: “Add product by CPE” opens prefilled ([products outside the
  catalogue](#eigene-produkte)); once added, the suggestion counts as accepted. Or *into the bundled catalogue*: the
  curated catalogue lives in the repository (`backend/app/catalog/products/`); the dialog shows an entry to copy, “Mark
  as accepted” answers the suggestion.
- **Duplicate** – choose the existing product.
- **Reject** – with an optional reason.

A suggestion is answered exactly once. Addresses are only shown as text and link, never fetched by the server.

## Data sources and fetching {#datenquellen}

| Source | For |
|---|---|
| Palo Alto Networks ([PSIRT](term:psirt)) | PAN-OS, Panorama, GlobalProtect, Prisma, Cortex and more: affected and fixed versions per line, down to the hotfix |
| Fortinet (PSIRT RSS and the [CSAF](term:csaf) file of each advisory) | affected and unaffected ranges per product, fix per line |
| Veeam (security KB feed) | affected builds and fixed builds per release line |
| [NVD](term:nvd) | every product with a CPE: CVEs with version ranges and the vendor's data (Microsoft: build ranges), [CVSS](term:cvss); new CVEs not analysed yet by keyword search over the last 30 days |
| CISA [KEV](term:kev) | "actively exploited" |
| endoflife.date | release lines, latest version per line, end of support |
| ENISA [EUVD](term:euvd) | "actively exploited" – from the news, when that source is switched on |
| CSAF providers (Siemens, Cisco, Schneider Electric, Open-Xchange) | the [CSAF](term:csaf) advisories straight from the vendor: affected ranges and fixed versions per product |
| CVE list (cvelistV5) | the vendor's data on a CVE and CISA's assessment ([SSVC](term:ssvc)) – above all while the NVD has not analysed a CVE yet |
| FIRST [EPSS](term:epss) | probability of exploitation within 30 days |
| [OSV](term:osv) | fixed versions of open-source packages (Tomcat, Jenkins, Django …) |
| Metasploit, Exploit-DB, nuclei-templates | “Public exploit code” ([Public exploit](#oeffentlicher-exploit)) |

Vendor advisories are only fetched when a product of that vendor is followed. An admin can switch off the last seven
sources one by one ([More sources](/docs/integrationen#weitere-quellen)); only CVE numbers and public addresses leave
the server, never your products or versions.

**Fetching:** Vendor News is on by default – but requests only go out once somebody follows a product, and only for
the followed products. Fetching runs in the background, independent of the news:

| What | Default | Adjustable |
|---|---|---|
| vendor advisories and NVD ("Advisories & NVD every") | 6 hours | 1 to 48 hours |
| endoflife.date and KEV ("Versions & KEV every") | 24 hours | 6 to 168 hours |

Per CPE, Vendor News first fetches the newest 2000 CVEs, after that only what NVD changed since the last fetch. After
errors it asks again with growing pauses; if NVD refuses ("too many requests"), all NVD queries pause together. Admins
find the settings under *Settings → Integrations → Vendor News*, see
[Integrations](/docs/integrationen#vendor-news).

### Citrix and NetScaler {#citrix}

Citrix (Cloud Software Group) publishes its security bulletins (CTX…) as web pages on `support.citrix.com` only –
without a [CSAF](term:csaf) provider (neither in the BSI's list nor under `/.well-known/csaf/` of citrix.com,
netscaler.com or cloud.com) and without an RSS or JSON feed (checked on 2 November 2026; the former RSS feed now
returns just the web page). Vendor News does not read the web pages.

**Citrix: through the CVE list and NVD.** Citrix is a CNA and enters its bulletins with affected and fixed builds into
the CVE data – NetScaler ADC/Gateway, Virtual Apps and Desktops, Workspace app, StoreFront and Hypervisor are assessed
through it (NetScaler builds like `14.1-29.72`, FIPS/NDcPP apart). For Citrix holes the BSI's [CSAF](term:csaf)
warnings (WID) in the news bring the “details from the source”. The workaround or mitigation (e.g. ending sessions
after the update) is in the bulletin – its link is at the finding.

### NVD API key {#nvd-api-schluessel}

Without a key NVD allows 5 requests per 30 seconds. Cobe News keeps to that – the first fetch of many products then
takes a few minutes ("First fetch running …"). With a key it is much faster.

1. Request a free key from NVD:
   [nvd.nist.gov – Request an API Key](https://nvd.nist.gov/developers/request-an-api-key).
2. Under *Settings → Integrations → Vendor News*, tab "Settings", enter it in **"NVD API key (optional)"** and save.

The key is stored encrypted and not shown again ("Stored (encrypted) – leave empty to keep it.").

## Catalogue care {#katalog-pflege .admin}

Cobe News checks its catalogue itself. *Settings → Integrations → Vendor News*, tab **"Catalogue care"**
([open directly](/settings/integrations?vendor=care)), shows under "Needs care" which entries need attention – with
the reason, for example "CPE … does not exist in NVD", "No CVE data for 40 months" or "endoflife.date no longer knows
the key …". Followed products with a problem also show it in their drawer ("Catalogue entry needs care", with "Open
catalogue care").

| Status | Meaning |
|---|---|
| Error | The entry is wrong – without a fix, vulnerabilities or support data are missing. |
| Check | Probably outdated – worth a look. |
| OK | All checks passed. |
| Not checked yet | NVD has not been asked about this entry yet. |

The switch "Followed products only" limits the list to your products; switched off it shows the whole catalogue. At
the top are "Last check", the catalogue version and how many CPEs have been checked.

### What is checked {#was-geprueft-wird}

| Check | Result |
|---|---|
| Is the CPE in NVD's CPE dictionary? | missing: **error**; only deprecated entries: warning with the successor |
| CVEs for the CPE in the last 3 years? | none or only older ones: warning (not for cloud services) |
| Does endoflife.date still know the key? | unknown: **error**; another vendor: warning |
| The vendor's last advisory (Palo Alto, Fortinet, Veeam) | older than 2 years: warning |
| Followed, but without a CPE | warning – vulnerabilities only come from vendor advisories and news |

**Limits:** only NVD is asked, through the same brake as the Vendor News fetch, and only when Vendor News is on, a
product is followed and no Vendor News round is running. Followed products are checked **weekly**, the whole catalogue
**monthly**, with at most **20 requests per hour**, spread over the hour and counted across a restart. The first full
pass therefore takes about five days. Why the check is waiting is shown below the list (e.g. "Hourly budget reached –
it goes on next hour.").

**"Check now"** asks about the CPEs of the followed products at once (at most every 10 minutes, at most 60 requests);
the rest of the catalogue goes on in the background. While Vendor News is off, the button is locked.

### Fixing an entry {#eintrag-korrigieren}

The catalogue cannot be changed in the interface. It consists of data files in the image (`backend/app/catalog/`, one
file per category under `products/`) and comes with every update. A wrong entry is fixed there and is corrected with
the **next update** of Cobe News (see [Update](/docs/betrieb#update)).

If you build the image yourself, change the entry in its category's file, raise `catalog_version` in `catalog.yaml`
and rebuild (`docker compose up -d --build`). An error in the files stops the start with file and product in the log.
Until the fix arrives, you can follow the product with the right CPE as an own entry via
["Not in the catalogue?"](#eigene-produkte).

"Refresh catalogue" under *Settings → Integrations → Vendor News* rebuilds the catalogue with the current data from
endoflife.date – that changes release data, not the curated entries.

### Catalogue version {#katalogversion}

The **catalogue version** (form `year.month.day-number`, e.g. `2026.10.29-4`) is shown at the bottom of the
catalogue, in catalogue care and on *Version & changelog*. It is counted separately from the app version and
changes when products are added or corrected. A new catalogue that comes with an update applies at once – without
waiting for the next refresh.
