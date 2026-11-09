"""Systeme of the notification rules ("nur Palo Alto, nur Kritisch" as one rule): the catalogue systems a story
concerns, kept on the story (news_items.systems), and what a rule's choice of systems stands for.

A rule names catalogue vendors ({"vendor": "Palo Alto Networks"} – every product of that vendor, expanded when matched,
so a product the catalogue adds later counts) or single products ({"product": "panos"}) – from the WHOLE catalogue,
not only the followed products. An entry the catalogue no longer knows (a product removed, a vendor renamed) stands for
nothing – never for "all" (as a rule's unreadable source ids). A merged product (catalogue `replaces`) counts as the
product it is now.

A story concerns a system when either
- **exact**: its structured details (CSAF product tree, the NVD's CPE configurations, the CNA's affected rows) concern
  that product – the matcher of "Betrifft unsere Produkte" (story_details.matches → vendor_match.evaluate), without
  versions; "not affected" does not count. Not every product is judged per story: the words of the details pick the
  candidates first (story_details.anchors – a word of a name the matcher compares; the products without one are always
  candidates), then the matcher decides (tests: the same result as judging the whole catalogue). Stored as the key;
- **mention**: its title or teaser names the product ("m:<key>") or the vendor ("v:<vendor id>") – in whole words,
  case and accents ignored (db.fold), "PAN-OS" also as "PAN OS" (words are runs of letters and digits). Names are the
  catalogue's label (without a parenthesis: "PAN-OS (Firewalls)" is "PAN-OS"), its `names` and `kw`, and aliases of
  two words or more (the single-word aliases are search slugs: "xdr", "NGFW", "EPV"). Against false positives: a name
  made only of ordinary words (COMMON – "Exchange", "Panorama", "Expedition", "Teams", "Secure Client", "Cloud NGFW")
  or of two letters counts only when the vendor is named as well (title or teaser) – "Microsoft Exchange",
  "Palo Alto Networks: … Panorama". A vendor is named by its name ("Palo Alto Networks"), its short form without a
  company word ("Palo Alto"; not when only an ordinary word is left: "Extreme Networks" stays whole) and a name in
  parentheses that is no other vendor's ("Broadcom (VMware)" → "VMware"; "CyberArk (Palo Alto Networks)" not). Vendors
  the catalogue only derived from the first word of a product's label (endoflife.date products without a CPE: "Red",
  "Cloud") name nothing.

Loud and quiet (as the topics: news.loud_topic): a system gained by an event of the story's own – stored, its title or
teaser changed, its details arrived or changed – is loud; one gained by a recompute (the first backfill, a catalogue
change: systems_round; details fetched again unchanged) is quiet (news_items.quiet_systems) – matched and shown, never
a reason for a rule to send an older story. A rule asks only for loud ones (loud)."""

import asyncio
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import ColumnElement, Text, and_, any_, cast, false, func, literal, literal_column, or_, select, update
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import array as pg_array
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as dbm
from app import settings as settings_store
from app import vendor_catalog as catalog
from app.models import NewsItem, StoryDetail

log = logging.getLogger("cobe_news.systems")

SYSTEMS_V = 5  # raised when the matching changes: every stored story is computed again (quietly) – 2: vendor identities, context; 3: tag lists, CISA; 4: catalogue 2026.11.06-3 (one spelling per vendor); 5: ordinary words of new names (weekly, valve, meta …), a second name after one preposition
STATE = "news_systems"  # settings row: {"v": SYSTEMS_V, "sig": {"p": {key: hash}, "v": {vendor id: hash}}}
BATCH = 500
MENTION, VENDOR = "m:", "v:"
ENTRIES_MAX = 50  # systems a rule names

# Ordinary words – a name made only of these (or of two letters) is no reliable sign of the product on its own: it
# counts only together with its vendor (or, for the names of CONTEXT, in a security context). Product names of the
# catalogue that are plain English (or German) words, generic product words, and the common abbreviations of security
# news.
COMMON = frozenset(
    """
    a an and the of for on in to by with at app apps
    abacus access acrobat active admin agent agents analytics angular appliance assistant automation backup bamboo
    bind blender bootstrap boundary bun business cache cachet caddy calico camel canonical center central certificate
    certificates chef client clients cloud corporate datacenter coder collaboration commander communications compact composer connect
    console consul contour control controller core cyber data database deep defend defender desk desktop desktops
    device devices directory discourse domain drucker edge electron elixir email ember endpoint engine enterprise envoy exchange
    expedition explorer express extreme fabric falcon federation files firewall firewalls fleet fluent flux foreman
    forwarder foundation framework gatekeeper gateway greenlight grunt guzzle harbor harvester helm help horizon http
    https hub identity infor insight instant jaeger jekyll julia keeper kirby kuma linux local logic machine mail
    managed management manager mandrel meetings mfp micro mobile mobility models monitor native network networks nexus
    node nomad nord office one os orchestrator orion outlook packer panorama pass password phantom phone platform pleasant policy portal privileged pro
    progress prometheus protect protection provider puppet purity quasar react receiver recovery remote replication
    robo router routing ruby rust sage salt scala secret secrets secure security sentinel sentry server servers service services
    small solutions spark spectrum spring squid storage studio suite support surface switch switches sync system tails teams
    teleport terraform tools twig unbound unified unify unity universal unleashed vault vigor virtual vision visual vue
    watch web webmail workflows workplace workspace workstation yarn zoom
    weekly satellite valve meta symantec eclipse bcdr
    cisa
    vpn waf edr xdr mdr siem soar sase ztna sdwan wan lan mfa sso api ssl tls nas san ups iot ot ics plc hmi scada rdp
    ssh ftp smb dns dhcp ldap ngfw utm ids ips
    """.split()
)
# names of three letters or fewer that are the product or the vendor – no abbreviation of the news ("SAP-Patchday",
# "IBM warnt", "HPE iLO"); not BMC (the baseboard management controller), RSA, ISC (SANS ISC), SEP, GNU
SHORT_OK = frozenset({"php", "git", "vlc", "xen", "3cx", "h3c", "sap", "ibm", "hpe", "hp", "avm", "aws", "f5", "amd"})
# words that are no name alone, though a name of more words with them is ("Linux Kernel", "Spring Boot", "Windows
# Server", "Grafana Loki" – the label without its vendor's name in front: "Heroku Postgres" is no "Postgres")
ALONE_NOT = frozenset(
    """
    windows kernel boot stream driver runner runtime verify automate documents glue lambda processors virtualization
    hypervisor ingress beats pulsar neptune photon pixel plasma postgres loki zulu xray groovy subversion supermarket
    toolkit dockerized sesam avalanche gpus apex artemis cassandra
    """.split()
)
# names of ordinary words that count alone in a security context – right before a word of SECURITY ("Zoom fixes flaws",
# "Zoom-Sicherheitslücke", "Outlook-Lücke", "Spring Framework RCE"), after one and a preposition ("Kritische Lücke in
# Exchange", "Angriffe auf Exchange-Server"), or – True – before a version ("Windows 11", "Edge 130", "Exchange 2019").
# Only these: "Teams of attackers", "Zoom in on ransomware", "The Spring of ransomware" stay nothing; "Spring" alone
# (the season) and the generic words (Gateway, Firewall, Access …) never.
CONTEXT = {
    ("zoom",): False,
    ("exchange",): True,
    ("exchange", "server"): True,
    ("teams",): False,
    ("outlook",): True,
    ("edge",): True,
    ("windows",): True,
    ("windows", "server"): True,
    ("office",): True,
    ("defender",): False,
    ("sentinel",): False,
    ("panorama",): False,
    ("expedition",): False,
    ("spring", "framework"): True,
    ("spring", "security"): True,
    ("spring", "cloud"): True,
    # vendor names that are ordinary words too – "valve controls", "Meta-Studie", "Symantec researchers uncover …" (a
    # research team's findings are no story about its products): only in a security context or as their own product
    ("valve",): False,
    ("meta",): False,
    ("symantec",): False,
}
CONTEXT_AFTER = {
    ("edge",): frozenset({"browser"}),
    ("windows",): frozenset({"kernel"}),
    ("valve",): frozenset({"steam", "steamos"}),
    ("meta",): frozenset({"llama", "whatsapp", "instagram", "facebook", "platforms", "quest"}),
    ("symantec",): frozenset({"endpoint", "sep", "dlp", "messaging", "web"}),
}  # a word after the name that says which one it is ("Edge-Browser")
SECURITY = frozenset(
    """
    lucke lucken sicherheitslucke sicherheitslucken schwachstelle schwachstellen sicherheitsproblem sicherheitsprobleme
    sicherheitsupdate sicherheitsupdates sicherheitswarnung sicherheitsleck leck patch patches patched patchday patchen
    gepatcht update updates fix fixes fixed flaw flaws bug bugs vulnerability vulnerabilities vulnerable vuln vulns
    exploit exploits exploited exploitation ausgenutzt angriff angriffe angegriffen angreifer attack attacks attacked
    attackers hack hacked zeroday 0day rce cve advisory warnt warnung backdoor
    """.split()
)
_PREP = frozenset("in im bei fur for of on auf gegen affecting betrifft".split())
_AND = frozenset("und and oder or sowie".split())
_VERSION = re.compile(r"\d{1,4}[a-z0-9]*")
# a vendor's name as a place ("PALO ALTO, Calif. – PRNewswire", "Ransomware gang hits Palo Alto city hall", "The city of
# Palo Alto") or as a term ("Threat Intel") is no mention of the vendor
_PLACE_AFTER = frozenset("calif california ca kalifornien city stadt police polizei mayor council residents resident school schools university airport based headquartered area".split())
_PLACE_BEFORE = (("city", "of"), ("town", "of"), ("stadt",))
_NOT_AFTER = {("intel",): frozenset({"threat", "cyber"})}
# company words a vendor's short form leaves out ("Palo Alto Networks" → "Palo Alto") – and that make no other vendor
# ("Nagios Enterprises" is "Nagios", "LANCOM Systems" is "LANCOM", "Apache Software Foundation" is "Apache")
COMPANY = frozenset(
    "networks networking inc corp corporation software systems technologies technology group gmbh ag se sa ltd llc co security solutions project foundation labs team enterprises international ab oy nv bv plc holdings".split()
)
_TOKEN = re.compile(r"[a-z0-9]+")
_PAREN = re.compile(r"\s*\(([^()]*)\)\s*$")
_TAGS = re.compile(r"\s*\((?:[^(),]{1,40},\s*)+[^(),]{1,40}\)\s*$")  # a list of two or more tags in parentheses at the very end


def tokens(text: str) -> list[str]:
    """The words of a text as the mentions compare them: folded (case and accents ignored, db.fold), runs of letters and
    digits – "PAN-OS-Lücke" is pan, os, lucke."""
    return _TOKEN.findall(dbm.fold(text or ""))


def vendor_id(name: str) -> str:
    """A vendor's spelling as the rules and the stories keep it: folded, letters and digits only – "Red Hat" and "Redhat",
    "VMware" and "Vmware" are one spelling. One vendor of several spellings ("VMware", "Broadcom (VMware)"): group."""
    return "".join(_TOKEN.findall(dbm.fold(name or "")))


def common(words: tuple[str, ...] | list[str]) -> bool:
    """A name of ordinary words only (COMMON), of digits only, of two letters, one word of ALONE_NOT, or one short word
    of three (an abbreviation – "IIS", "UCS", "ROS"; not SHORT_OK): it needs its vendor named as well."""
    if len(words) == 1 and words[0] in SHORT_OK:
        return False
    if sum(len(w) for w in words) < 3 or all(w.isdigit() for w in words) or (len(words) == 1 and words[0] in ALONE_NOT):
        return True
    if len(words) == 1 and len(words[0]) <= 3 and not any(c.isdigit() for c in words[0]):
        return True
    return all(w in COMMON for w in words)


# ---------------------------------------------------------------- the catalogue, prepared once per catalogue


@dataclass
class _Index:
    data: dict | None = None
    products: dict[str, dict] = field(default_factory=dict)
    vendor_of: dict[str, str] = field(default_factory=dict)  # key → vendor id (of its group)
    # vendor id → {"name", "keys", "names": every spelling, "ids": every spelling's id} – one per vendor identity
    vendors: dict[str, dict] = field(default_factory=dict)
    alias: dict[str, str] = field(default_factory=dict)  # a spelling's id (and the group's own) → the group's vendor id
    anchors: dict[str, set[str]] = field(default_factory=dict)  # word → product keys (story_details.anchors)
    always: set[str] = field(default_factory=set)  # products without anchors: candidates for every story
    # first word → (words, "p" | "v", key or vendor id, counts alone) – the mentions
    phrases: dict[str, list[tuple[tuple[str, ...], str, str, bool]]] = field(default_factory=dict)
    sig: dict = field(default_factory=dict)  # {"p": {key: hash}, "v": {vendor id: hash}} – what systems_round compares


_ix = _Index()
# what the matching reads of a product (story_details.matches → vendor_match.evaluate, the mentions): only a change of
# these makes systems_round compute the stories again – not an example, a version command or a hint
MATCH_FIELDS = ("key", "label", "vendor", "names", "kw", "aliases", "cna", "cpes", "cpe_editions", "editions", "excluded_names", "osv", "adv", "cloud", "filter", "scheme", "line_depth")


def _hash(x: object) -> str:
    return hashlib.sha256(json.dumps(x, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()[:20]


def _names_of_vendor(name: str) -> tuple[list[str], str]:
    """(the vendor's main names, the name in parentheses) – "Bacula Systems / Bareos" has two main names."""
    m = _PAREN.search(name)
    main = _PAREN.sub("", name) if m else name
    return [x.strip() for x in main.split(" / ") if x.strip()], (m.group(1).strip() if m else "")


def _short(words: list[str]) -> list[str]:
    out = list(words)
    while out and out[0] == "the":
        out = out[1:]
    while len(out) > 1 and out[-1] in COMPANY:
        out = out[:-1]
    return out


def _identity(name: str) -> str:
    """A brand's name as one vendor: without its company words ("LANCOM Systems" → "lancom", "Apache Software Foundation"
    → "apache") – unless only an ordinary word is left ("Extreme Networks", "Cloud Software Group" stay whole)."""
    full = tokens(name)
    short = _short(full)
    return "".join(short if short and not common(short) else full)


def _starts(words: list[str], prefix: list[str]) -> bool:
    return bool(prefix) and words[: len(prefix)] == prefix


def _brands(name: str, labels: list[str]) -> list[str]:
    """The brands a catalogue vendor stands for – its main names; for "Owner (Brand)" the one its products are labelled
    with: "Broadcom (VMware)" (VMware ESXi, VMware vCenter) is VMware, "CyberArk (Palo Alto Networks)" (CyberArk PAM)
    is CyberArk, "Kaseya (Datto)" (Datto RMM) is Datto. No label says it: the parenthesis ("Rapid7 (Velocidex)")."""
    mains, paren = _names_of_vendor(name)
    if not paren:
        return mains
    by_label = [tokens(x) for x in labels]
    in_paren = sum(_starts(w, _short(tokens(paren))) for w in by_label)
    in_main = sum(any(_starts(w, _short(tokens(m))) for m in mains) for w in by_label)
    return [paren] if in_paren > in_main or not in_main else mains


def _groups(cat: dict) -> tuple[dict[str, str], dict[str, dict]]:
    """The catalogue's vendors as identities: the spellings of one brand are one vendor – "VMware" (Photon, Site
    Recovery Manager) and "Broadcom (VMware)" (ESXi, vCenter …), "Apache" and "Apache Software Foundation", "LANCOM"
    and "LANCOM Systems", "Nagios" and "Nagios Enterprises" (_brands, _identity) – so "VMware (alle Produkte)" is all of
    them. An owner is no brand: "CyberArk (Palo Alto Networks)" stays CyberArk, "Splunk (Cisco)" Splunk. Returns (the id
    of each spelling → its group's id, group id → {"name", "names", "ids", "keys"}). The name shown: the spelling with
    the most curated products (then the most products); several owners of one brand ("Arctera (Veritas)", "Cohesity
    (Veritas)"): the brand."""
    spellings: dict[str, dict[str, list[int]]] = {}  # spelling's id → spelling → [curated products, products]
    labels: dict[str, list[str]] = {}
    keys: dict[str, list[str]] = {}
    for p in cat["products"]:
        vname = str(p.get("vendor") or "").strip()
        vid = vendor_id(vname)
        if not vid:
            continue
        c = spellings.setdefault(vid, {}).setdefault(vname, [0, 0])
        c[0] += p.get("source") != "eol"
        c[1] += 1
        labels.setdefault(vid, []).append(_PAREN.sub("", str(p.get("label") or "")))
        keys.setdefault(vid, []).append(str(p["key"]))
    parent = {vid: vid for vid in spellings}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    by_brand: dict[str, str] = {}
    brand_of: dict[str, list[str]] = {}
    for vid, sp in spellings.items():
        name = sorted(sp.items(), key=lambda x: (-x[1][0], -x[1][1], x[0]))[0][0]
        brand_of[vid] = _brands(name, labels[vid])
        for b in brand_of[vid]:
            if not (ident := _identity(b)):
                continue
            if ident in by_brand:
                parent[find(vid)] = find(by_brand[ident])
            else:
                by_brand[ident] = vid
    members: dict[str, list[str]] = {}
    for vid in spellings:
        members.setdefault(find(vid), []).append(vid)
    alias: dict[str, str] = {}
    groups: dict[str, dict] = {}
    for ids in members.values():
        counts: dict[str, list[int]] = {}
        for vid in ids:
            for n, c in spellings[vid].items():
                counts[n] = [counts.get(n, [0, 0])[0] + c[0], counts.get(n, [0, 0])[1] + c[1]]
        name = sorted(counts.items(), key=lambda x: (-x[1][0], -x[1][1], x[0]))[0][0]
        parens = {_names_of_vendor(n)[1] for vid in ids for n in spellings[vid]}
        if len(ids) > 1 and len(parens) == 1 and "" not in parens and all(brand_of[v] == [next(iter(parens))] for v in ids):
            name = next(iter(parens))  # only owners of one brand: the brand
        gid = vendor_id(name)
        groups[gid] = {"name": name, "names": sorted(counts), "ids": sorted(ids), "keys": sorted(k for v in ids for k in keys[v])}
        for vid in [*ids, gid]:
            alias[vid] = gid
    return alias, groups


def _build(cat: dict) -> _Index:
    from app import story_details

    ix = _Index(data=cat)
    ix.alias, ix.vendors = _groups(cat)
    named: set[str] = set()  # spellings' ids whose name is a real one (curated, or taken from a CPE)
    spelling: dict[str, str] = {}  # spelling's id → the spelling (most products)
    count: dict[str, dict[str, list[int]]] = {}  # spelling's id → spelling → [curated products, products]
    for p in cat["products"]:
        key = str(p["key"])
        ix.products[key] = p
        vname = str(p.get("vendor") or "").strip()
        vid = vendor_id(vname)
        if not vid:
            continue
        ix.vendor_of[key] = ix.alias[vid]
        c = count.setdefault(vid, {}).setdefault(vname, [0, 0])
        c[0] += p.get("source") != "eol"
        c[1] += 1
        if p.get("source") != "eol" or p.get("cpes"):
            named.add(vid)
        words = story_details.anchors(p)
        if words is None:
            ix.always.add(key)
        else:
            for w in words:
                ix.anchors.setdefault(w, set()).add(key)
    for vid, c in count.items():
        spelling[vid] = sorted(c.items(), key=lambda x: (-x[1][0], -x[1][1], x[0]))[0][0]
    mains = {vendor_id(n) for vid in named for n in _names_of_vendor(spelling[vid])[0]}
    whole = set(spelling)

    def add(words: tuple[str, ...], kind: str, ref: str, alone: bool) -> None:
        if words and (words, kind, ref, alone) not in ix.phrases.get(words[0], []):
            ix.phrases.setdefault(words[0], []).append((words, kind, ref, alone))

    # the vendors: their names, short forms and a parenthesis that is no other vendor's – each for its group
    vnames: dict[str, set[tuple[str, ...]]] = {}  # group id → its names as words (a label without them, below)
    vmain: dict[str, set[tuple[str, ...]]] = {}  # group id → its main names and short forms (no parenthesis)
    vsig: dict[str, list] = {}
    for vid in sorted(spelling):
        gid = ix.alias[vid]
        mainnames, paren = _names_of_vendor(spelling[vid])
        got: list[tuple[list[str], bool]] = []
        for n in mainnames:
            full = tokens(n)
            if not full:
                continue
            other = ix.alias.get(vendor_id(n))
            if paren and vendor_id(n) in whole and other != gid:
                continue  # an owner that is another vendor ("Broadcom (VMware)", "Kaseya (Datto)"): not this one's name
            vnames.setdefault(gid, set()).update({tuple(full), tuple(_short(full))})
            vmain.setdefault(gid, set()).update({tuple(full), tuple(_short(full))})
            got.append((full, len(full) >= 2 or not common(full)))  # a company name of two words or more is one
            short = _short(full)
            if short and short != full:
                got.append((short, not common(short)))
        if paren and (vendor_id(paren) not in mains or ix.alias.get(vendor_id(paren)) == gid) and (alias := tokens(paren)):
            vnames.setdefault(gid, set()).add(tuple(alias))
            got.append((alias, not common(alias)))
        if vid not in named:
            continue  # derived from the first word of a label ("Red", "Cloud"): names nothing
        for words, alone in got:
            add(tuple(words), "v", gid, alone)
        vsig.setdefault(gid, []).append([spelling[vid], sorted(got)])
    # the products: label (without a parenthesis, and without its vendor's name in front – "Google Chrome" is "Chrome"
    # too), names, kw, aliases of two words or more. A name that is its vendor's own (not a parenthesis: "Progress
    # (Kemp)" – Kemp is the LoadMaster's name), of a vendor with more products
    # ("Zyxel", "SonicWall", "LANCOM" in the kw of one of them), names the vendor, not that product; a name several
    # products of one vendor share counts for the one whose label it is ("PAN-OS" is PAN-OS, not Panorama, which runs
    # it) – none: for each ("GlobalProtect": the app and the PAN-OS gateway)
    per_vendor: dict[str, dict[tuple[str, ...], dict[str, bool]]] = {}  # group → name → key → from its label
    labels = {key: tokens(_PAREN.sub("", str(p.get("label") or ""))) for key, p in ix.products.items()}
    for key, p in ix.products.items():
        gid = ix.vendor_of.get(key, "")
        label = labels[key]
        own = {tuple(label)} if label else set()
        # a label that is only the vendor's name and a parenthesis ("Jenkins (weekly)" next to "Jenkins LTS", "Datto
        # (SIRIS …)" next to "Datto RMM"): no more this product's name than its siblings' – "Grafana" alone is Grafana
        if "(" in str(p.get("label") or "") and tuple(label) in vmain.get(gid, ()):
            if any(k != key and _starts(labels[k], label) for k in ix.vendors.get(gid, {}).get("keys", [])):
                own.discard(tuple(label))
        for v in vnames.get(gid, ()):
            if _starts(label, list(v)) and len(label) > len(v):
                own.add(tuple(label[len(v) :]))
        names = [*(str(n) for n in p.get("names") or []), *(str(n) for n in p.get("kw") or [])]
        names += [str(a) for a in p.get("aliases") or [] if len(tokens(str(a))) >= 2]
        found = {w: True for w in own if w}
        for n in names:
            if (w := tuple(tokens(n))) and w not in found:
                found[w] = False
        for w, by_label in found.items():
            per_vendor.setdefault(gid, {}).setdefault(w, {})[key] = by_label
    for gid, by_name in per_vendor.items():
        several = len(ix.vendors.get(gid, {}).get("keys", [])) > 1
        for w, keys in by_name.items():
            if several and w in vmain.get(gid, ()) and not any(keys.values()):
                continue  # the vendor's own name in a product's kw: the vendor (named above), not this product
            owners = [k for k, by_label in keys.items() if by_label]
            for k in owners or list(keys):
                add(w, "p", k, not common(w))
    ix.sig = {
        "p": {key: _hash({f: p.get(f) for f in MATCH_FIELDS}) for key, p in ix.products.items()},
        "v": {gid: _hash([ix.vendors[gid]["keys"], sorted(x)]) for gid, x in vsig.items()},
    }
    return ix


def index() -> _Index:
    """The catalogue prepared for the matching – built again when the catalogue in use changes (a refresh, a rollout)."""
    global _ix
    cat = catalog.load()
    if _ix.data is not cat:
        _ix = _build(cat)
    return _ix


def group_of(name: str) -> str | None:
    """The vendor (its group's id) a spelling stands for – "VMware" and "Broadcom (VMware)" are one; None: unknown."""
    return index().alias.get(vendor_id(name))


# ---------------------------------------------------------------- what a story concerns


def _words(details: dict) -> set[str]:
    """Every word (vendor_match.name_words) of every text in the details – for the candidates (anchors). A word ending
    in a full stop counts with and without it."""
    from app.vendor_match import name_words

    out: set[str] = set()
    stack: list = [details]
    while stack:
        x = stack.pop()
        if isinstance(x, str):
            for w in name_words(x):
                out.add(w)
                out.add(w.rstrip("."))
        elif isinstance(x, dict):
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
    return out


def exact(details: dict | None, only: set[str] | None = None) -> list[str]:
    """The catalogue products (keys, sorted) a story's details concern – of `only`, when given."""
    from app import story_details

    if not details or not isinstance(details, dict):
        return []
    ix = index()
    cands = set(ix.always)
    for w in _words(details):
        cands |= ix.anchors.get(w, set())
    if only is not None:
        cands &= only
    if not cands:
        return []
    return sorted({m["product"] for m in story_details.matches(details, [(ix.products[k], []) for k in sorted(cands)])})


def _in_context(words: list[str], i: int, j: int, phrase: tuple[str, ...]) -> bool:
    """A name of CONTEXT at words[i:j] stands in a security context: a word of SECURITY right after it ("Zoom fixes",
    "Outlook-Lücke") or a version (when CONTEXT says so: "Windows 11"), or a word of SECURITY and a preposition before
    it ("Lücke in Exchange", "Zero-Day in Edge", "Angriffe auf Exchange-Server")."""
    after = words[j] if j < len(words) else ""
    if after in SECURITY or after in CONTEXT_AFTER.get(phrase, ()) or (CONTEXT[phrase] and _VERSION.fullmatch(after) and after[0].isdigit()):
        return True
    if i >= 2 and words[i - 1] in _PREP:
        return words[i - 2] in SECURITY or (i >= 3 and words[i - 3 : i - 1] == ["zero", "day"])
    # the second of two names after one preposition: "Lücke in Exchange Online und Exchange Server"
    if i >= 4 and words[i - 1] in _AND:
        for k in range(i - 2, max(0, i - 6), -1):
            if words[k] in _PREP:
                return k >= 1 and (words[k - 1] in SECURITY or (k >= 2 and words[k - 2 : k] == ["zero", "day"]))
            if not words[k] or words[k] in SECURITY:
                break
    return False


def _place(words: list[str], i: int, j: int) -> bool:
    """A vendor's name at words[i:j] stands for a place ("Palo Alto, Calif.", "Palo Alto city hall", "city of Palo Alto")."""
    if j < len(words) and words[j] in _PLACE_AFTER:
        return True
    return any(tuple(words[max(0, i - len(b)) : i]) == b for b in _PLACE_BEFORE)


def mentions(title: str, teaser: str) -> list[str]:
    """What a story's title and teaser name: "m:<key>" per product, "v:<vendor id>" per vendor (sorted). A name of
    ordinary words only counts with its vendor named in the title or teaser as well (COMMON) – or, one of CONTEXT, in a
    security context. A vendor's name as a place or a term ("Palo Alto city hall", "Threat Intel") names nothing."""
    ix = index()
    # a feed's topic tags at the end of the teaser ("… Prüfstellen. (Security, PHP)" – golem.de) are the publisher's
    # filing, no statement of the story: an article about AI liability tagged "PHP" names no PHP
    teaser = _TAGS.sub("", teaser or "")
    words = [*tokens(title), "", *tokens(teaser)]  # no name across the end of the title
    named: dict[str, list[range]] = {}  # vendors named at all (also by a name that does not count alone): where
    vendors: set[str] = set()
    alone: list[tuple[str, range]] = []
    need: list[tuple[str, range]] = []
    for i, w in enumerate(words):
        for phrase, kind, ref, solo in ix.phrases.get(w, ()):
            j = i + len(phrase)
            if tuple(words[i:j]) != phrase or (i and words[i - 1] in _NOT_AFTER.get(phrase, ())):
                continue
            if not solo and phrase in CONTEXT and _in_context(words, i, j, phrase):
                solo = True
            if kind == "v":
                if _place(words, i, j):
                    continue
                named.setdefault(ref, []).append(range(i, j))
                if solo:
                    vendors.add(ref)
            elif solo:
                alone.append((ref, range(i, j)))
            else:
                need.append((ref, range(i, j)))
    # the vendor named elsewhere than the product's own words: "Zoom" alone is not product and vendor at once
    hits = alone + [(k, at) for k, at in need if any(not set(at) & set(v) for v in named.get(ix.vendor_of.get(k, ""), []))]
    # the longest name wins: "NGINX Plus" is no story about nginx, "Grafana Loki" none about Grafana
    keys = {k for k, at in hits if not any(o.start <= at.start and at.stop <= o.stop and len(o) > len(at) for _, o in hits)}
    return sorted({MENTION + k for k in keys} | {VENDOR + v for v in vendors})


def _is_mention(entry: str) -> bool:
    return entry.startswith((MENTION, VENDOR))


def merge(old: list[str], quiet_before: list[str], new: list[str], scope, *, quiet: bool) -> tuple[list[str], list[str]]:  # noqa: ANN001
    """A story's systems after a recompute of the entries `scope` says (a predicate): `new` replaces them, the rest
    stays. Gained quietly (`quiet`): quiet; lost: no longer quiet; the rest stays as it was (news.quiet_after)."""
    keep = [e for e in old or [] if not scope(e)]
    out = sorted(set(keep) | set(new))
    gained = set(out) - set(old or [])
    q = (set(quiet_before or []) & set(out)) | (gained if quiet else set())
    return out, sorted(q)


def _all_exact(e: str) -> bool:
    return not _is_mention(e)


async def set_exact(db: AsyncSession, item_id, keys: list[str], *, quiet: bool) -> bool:  # noqa: ANN001
    """The products a story's details concern, after its details arrived or were fetched again (story_details.
    enrich_round) – `quiet`: the details did not change (a product found now is the catalogue's doing, no news). In the
    caller's transaction. True: a system was gained loudly – the next notification round looks at every rule."""
    row = (await db.execute(select(NewsItem.systems, NewsItem.quiet_systems, NewsItem.changes).where(NewsItem.id == item_id))).one_or_none()
    if row is None:
        return False
    old, q = list(row[0] or []), list(row[1] or [])
    out, q2 = merge(old, q, keys, _all_exact, quiet=quiet)
    if (out, q2) == (sorted(old), sorted(q)):
        return False
    gained = sorted(set(out) - set(old) - set(q2))
    values: dict = {"systems": out, "quiet_systems": q2}
    if gained:
        # a story newly matching a system loudly is a change of the story – kept per entry (news.noted: a rule widened
        # before judges it by these entries, notify._earlier_news) and the next notification round looks at every rule.
        # Never for the quiet path (quiet=True) nor for recompute()/systems_round.
        from app import news, notify  # news imports this module

        values["changes"] = news.noted(row[2], datetime.now(UTC), systems=gained)
        notify.changed()
    await db.execute(update(NewsItem).where(NewsItem.id == item_id).values(**values).execution_options(synchronize_session=False))
    return bool(gained)


def remention(item: NewsItem) -> None:
    """The mentions of a story whose title or teaser changed ("[UPDATE] …") – an event of its own: what it names now is
    loud. On the ORM object (the caller flushes)."""
    old, q = list(item.systems or []), list(item.quiet_systems or [])
    out, q2 = merge(old, q, mentions(item.title, item.summary or ""), _is_mention, quiet=False)
    if out != sorted(old) or q2 != sorted(q):
        item.systems, item.quiet_systems = out, q2
        if gained := sorted(set(out) - set(old)):
            # a name gained by a new title or teaser: a change of the story (per entry + the next round looks again)
            from app import news

            news.touched(item, systems=gained)


# ---------------------------------------------------------------- what a rule's systems stand for


def entries(values) -> list[dict]:  # noqa: ANN001
    """A rule's systems as stored – [{"vendor": …} | {"product": …}], anything else dropped."""
    out = []
    for x in values or []:
        if isinstance(x, dict) and isinstance(x.get("product"), str) and x["product"]:
            out.append({"product": x["product"]})
        elif isinstance(x, dict) and isinstance(x.get("vendor"), str) and x["vendor"]:
            out.append({"vendor": x["vendor"]})
    return out


def known(entry: dict) -> bool:
    """Whether the catalogue knows the entry (a merged product as the one it is now)."""
    ix = index()
    if "product" in entry:
        return catalog.REPLACED.get(entry["product"], entry["product"]) in ix.products
    return vendor_id(entry.get("vendor", "")) in ix.alias


def text_of(entry: dict) -> str:
    """An entry as one comparable text – the rules' filter (notify.rule_filter): "p:panos", "v:paloaltonetworks"."""
    if "product" in entry:
        return f"p:{catalog.REPLACED.get(entry['product'], entry['product'])}"
    vid = vendor_id(entry.get("vendor", ""))
    return f"v:{index().alias.get(vid, vid)}"  # by its group: another spelling of the same vendor is the same choice


def of_text(values) -> list[dict]:  # noqa: ANN001
    """notify.rule_filter's texts back as entries (a vendor by its id – vendor_id of an id is the id)."""
    out = []
    for x in values or []:
        kind, _, ref = str(x).partition(":")
        if ref and kind == "p":
            out.append({"product": ref})
        elif ref and kind == "v":
            out.append({"vendor": ref})
    return out


def product_keys(values) -> list[str]:  # noqa: ANN001
    """The catalogue products a rule's systems stand for (a vendor: all of its products as the catalogue has them now)
    – sorted; with the keys merged into them (a Vendor News event of before a merge)."""
    ix = index()
    out: set[str] = set()
    for e in entries(values):
        if "product" in e:
            k = catalog.REPLACED.get(e["product"], e["product"])
            if k in ix.products:
                out.add(k)
        elif (gid := ix.alias.get(vendor_id(e["vendor"]))) is not None:
            out |= set(ix.vendors[gid]["keys"])
    out |= {old for old, new in catalog.REPLACED.items() if new in out}
    return sorted(out)


def wanted(values) -> list[str]:  # noqa: ANN001
    """The story entries a rule's systems stand for: each product's key and mention, a vendor's own mention (by its
    group – any of its spellings, and their ids as stories of an older matching kept them)."""
    ix = index()
    out: set[str] = set()
    for e in entries(values):
        if "vendor" in e and (gid := ix.alias.get(vendor_id(e["vendor"]))) is not None:
            out |= {VENDOR + gid, *(VENDOR + v for v in ix.vendors[gid]["ids"])}
    for k in product_keys(values):
        if k in ix.products:
            out |= {k, MENTION + k}
    return sorted(out)


_QUIET = literal_column("ARRAY(SELECT jsonb_array_elements_text(news_items.quiet_systems))", type_=ARRAY(Text))


def loud(want: list[str]) -> ColumnElement:
    """SQL: the story has one of these entries, and not only quietly – the GIN index first, then the quiet ones taken out.
    Nothing wanted (only entries the catalogue no longer knows): no story."""
    if not want:
        return false()
    arr = pg_array(sorted(set(want)))
    return and_(NewsItem.systems.op("?|")(arr), NewsItem.systems.op("-", return_type=JSONB)(_QUIET).op("?|")(arr))


def has(want: list[str]) -> ColumnElement:
    """SQL: the story has one of these entries, also only quietly (the dry run: what a rule covers) – no entry: no story."""
    return NewsItem.systems.op("?|")(pg_array(sorted(set(want)))) if want else false()


def label(entry: dict, lang: str = "de") -> str:
    """An entry by its name: the product's label of today, a vendor with "(alle Produkte)" – the audit log, the editor."""
    ix = index()
    if "product" in entry:
        p = ix.products.get(catalog.REPLACED.get(entry["product"], entry["product"]))
        return str(p.get("label") or p["key"]) if p else entry["product"]
    v = ix.vendors.get(ix.alias.get(vendor_id(entry.get("vendor", ""))) or "")
    return f"{v['name'] if v else entry.get('vendor', '')} ({'all products' if lang == 'en' else 'alle Produkte'})"


def _within(words: tuple[str, ...], text: list[str]) -> bool:
    n = len(words)
    return any(tuple(text[i : i + n]) == words for i in range(len(text) - n + 1)) if n else False


def hits(story_systems: list[str], quiet: list[str], want: list[str], text: str = "") -> list[str]:
    """What a story matched a rule's systems by, as names – the loud entries (else all): the messages' "Treffer". The
    exact ones first, then those named, then vendors. A product by its label without the parenthesis ("PAN-OS
    (Firewalls)" → "PAN-OS"); of the products named, those whose label `text` (title and teaser) has – Panorama, named
    by its catalogue name "PAN-OS" as well, is no "Treffer" of "PAN-OS: …" next to PAN-OS."""
    ix = index()
    w = set(want)
    got = [e for e in story_systems or [] if e in w and e not in set(quiet or [])] or [e for e in story_systems or [] if e in w]
    got.sort(key=lambda e: (e.startswith(VENDOR), e.startswith(MENTION), e))

    def name_of(e: str) -> str:
        if e.startswith(VENDOR):
            return str((ix.vendors.get(ix.alias.get(e[2:], e[2:])) or {}).get("name") or "")
        p = ix.products.get(e.removeprefix(MENTION))
        return _PAREN.sub("", str(p.get("label") or p["key"])) if p else ""

    named = [e for e in got if e.startswith(MENTION)]
    if text and named:
        words = tokens(text)
        shown = [e for e in named if _within(tuple(tokens(name_of(e))), words)]
        got = [e for e in got if not e.startswith(MENTION) or e in (shown or named)]
    out: list[str] = []
    for e in got:
        if (name := name_of(e)) and name not in out:
            out.append(name)
    return out


# ---------------------------------------------------------------- the stored stories: first backfill, catalogue changes

_seen = [None]  # the catalogue at the last look – the same: nothing to compare


def reset() -> None:
    """Forget the last look (tests: a database of their own each)."""
    _seen[0] = None


def _changed(old: dict, new: dict) -> set[str]:
    old = old if isinstance(old, dict) else {}
    return {k for k in set(old) | set(new) if old.get(k) != new.get(k)}


async def systems_round(db: AsyncSession) -> int | None:
    """Background (the news loop): the stories' systems once per SYSTEMS_V (a new installation, the upgrade that
    brought the column – every story), else again for the catalogue products and vendors whose entry changed since the
    last look (a signature each, kept in the settings row STATE) – a catalogue refresh or rollout. Quiet: a story never
    comes because of it. Nothing changed: None – and while the catalogue in use stays the same object, not even a read."""
    cat = catalog.load()
    if _seen[0] is cat:
        return None
    ix = index()
    state = await settings_store.get(db, STATE)
    due = int(state.get("v") or 0) < SYSTEMS_V
    old = state.get("sig") if isinstance(state.get("sig"), dict) else {}
    keys = vendors = None
    if not due:
        keys = _changed(old.get("p") or {}, ix.sig["p"])
        vendors = _changed(old.get("v") or {}, ix.sig["v"])
    n = None
    if due or keys or vendors:
        await dbm.release(db)
        n = await recompute(db, keys, vendors)
        await settings_store.put(db, STATE, {"v": SYSTEMS_V, "sig": ix.sig})
        await db.commit()
        if n:
            log.info("systems of %d stories computed", n)
    _seen[0] = cat
    return n


async def recompute(db: AsyncSession, keys: set[str] | None = None, vendors: set[str] | None = None) -> int:
    """The stored stories' systems computed again, quietly – for these product keys and vendor ids only (the rest of each
    list stays), or all (None). In chunks of BATCH stories by id (the details' JSON decoded and matched off the event
    loop), each chunk committed on its own; a row changed meanwhile (its details arrived) is left to that change.
    For some keys only the stories that can concern them are read: details containing one of their anchors or a
    mention of their names in the search text (trigram index), or listing them already. Returns how many changed."""
    ix = index()
    scope_exact = None if keys is None else set(keys)
    scope_mention: set[str] | None = None
    where: list = []
    if keys is not None or vendors is not None:
        keys, vendors = set(keys or ()), set(vendors or ())
        mkeys = keys | {k for v in vendors for k in (ix.vendors.get(v) or {}).get("keys", [])}
        scope_mention = {MENTION + k for k in mkeys} | {VENDOR + v for v in vendors}
        listed = sorted(scope_exact | scope_mention)
        conds = [NewsItem.systems.op("?|")(pg_array(listed))] if listed else []
        live = [k for k in keys if k in ix.products]  # a product gone from the catalogue: only the lists naming it
        if live:
            from app import story_details

            words: set[str] | None = set()
            for k in live:
                got = story_details.anchors(ix.products[k])
                words = None if got is None or words is None else words | got
            if words is None:  # a product without anchors (Windows): every story with details
                conds.append(StoryDetail.item_id.is_not(None))
            elif words:
                conds.append(func.lower(cast(StoryDetail.data, Text)).like(any_(pg_array(sorted(f"%{w}%" for w in words)))))
        firsts = sorted({ph[0] for ps in ix.phrases.values() for ph, kind, ref, _ in ps if (kind == "p" and ref in mkeys) or (kind == "v" and ref in vendors)})
        if firsts:
            conds.append(NewsItem.search.like(any_(pg_array([f"%{w}%" for w in firsts]))))
        if not conds:
            return 0
        where.append(or_(*conds))

    def in_exact(e: str) -> bool:
        return not _is_mention(e) and (scope_exact is None or e in scope_exact)

    def in_mention(e: str) -> bool:
        return _is_mention(e) and (scope_mention is None or e in scope_mention)

    changed, last = 0, None
    while True:
        stmt = (
            select(NewsItem.id, NewsItem.title, NewsItem.summary, NewsItem.systems, NewsItem.quiet_systems, cast(StoryDetail.data, Text))
            .outerjoin(StoryDetail, and_(StoryDetail.item_id == NewsItem.id, StoryDetail.status == "ok", StoryDetail.data.is_not(None)))
            .where(*where)
            .order_by(NewsItem.id)
            .limit(BATCH)
        )
        if last is not None:
            stmt = stmt.where(NewsItem.id > last)
        rows = (await db.execute(stmt)).all()
        if not rows:
            break
        last = rows[-1][0]

        def compute(rows=rows) -> list[tuple]:  # noqa: ANN001
            out = []
            for iid, title, summary, systems, quiet, raw in rows:
                old, q = list(systems or []), list(quiet or [])
                try:
                    details = json.loads(raw) if raw else None
                except ValueError:
                    details = None
                new_exact = exact(details, scope_exact)
                s1, q1 = merge(old, q, new_exact, in_exact, quiet=True)
                found = [e for e in mentions(title or "", summary or "") if scope_mention is None or e in scope_mention]
                s2, q2 = merge(s1, q1, found, in_mention, quiet=True)
                if s2 != sorted(old) or q2 != sorted(q):
                    out.append((iid, old, q, s2, q2))
            return out

        upd = await asyncio.to_thread(compute)
        await dbm.release(db)
        for iid, old, q, s2, q2 in upd:
            # only the row as it was read: one that changed meanwhile (its details arrived, loudly) keeps that
            same = and_(NewsItem.systems == cast(literal(json.dumps(old)), JSONB), NewsItem.quiet_systems == cast(literal(json.dumps(q)), JSONB))
            stmt = update(NewsItem).where(NewsItem.id == iid, same)
            res = await db.execute(stmt.values(systems=s2, quiet_systems=q2).execution_options(synchronize_session=False))
            changed += res.rowcount or 0
        await db.commit()
        if len(rows) < BATCH:
            break
    return changed
