"""Catalogue 2026.11.06-3 (0.1.54): one spelling per vendor – the notification rules' "Systeme" follow.

The catalogue now writes each vendor once ("Apache" and "Apache Software Foundation" are "Apache Software Foundation",
"Grafana" is "Grafana Labs", endoflife.date's "Red", "Cloud", "Djangoproject" are Red Hat, Google, Django Software
Foundation …) and puts some products under their real vendor ("Broadcom" is Brocade now, Symantec "Broadcom (Symantec)";
the Linux kernel "Linux Kernel Organization", "The Linux Foundation" its projects). A rule names vendors by spelling
({"vendor": "Nagios"}, compared folded – systems.vendor_id): a spelling the catalogue no longer has would stand for
nothing, and "Broadcom" / "The Linux Foundation" would stand for something else. So every vendor entry of a rule moves:

- to the vendor's spelling now, when it is the same vendor ("Nagios" → "Nagios Enterprises", "Spring" → "Broadcom
  (Spring)", "Red" → "Red Hat", "Broadcom" → "Broadcom (Symantec)", "The Linux Foundation" → "Linux Kernel Organization");
- to the products it stood for, when the catalogue now counts them under a larger vendor that the rule did not choose
  ("Azure" → the three Azure services, not all of Microsoft; "Rapid7 (Velocidex)" → Velociraptor, not all of Rapid7).

The same for the rules' earlier filters (notify_rules.earlier – "v:<vendor id>" texts, notify.rule_filter), so a rule
widened before keeps judging older stories as then. Entries of vendors the catalogue still spells the same stay. A
rule's version is raised when it changes (an editor open on the old one gets a conflict instead of saving it back).
Only rules with such an entry are touched – a handful of rows. The stories' systems are computed again by the
background job (systems.SYSTEMS_V 5), quietly.

The downgrade moves vendor entries back to a spelling 0.1.53 knows for the same vendor ("Nagios Enterprises" stays,
"Grafana Labs" → "Grafana", "Broadcom (Symantec)" → "Broadcom", "Linux Kernel Organization" → "The Linux Foundation",
"The Linux Foundation" → "Linuxfoundation"); a vendor 0.1.53 does not know ("Broadcom" = Brocade, AMD) becomes its
products, which 0.1.53 does not know either (such an entry stands for nothing there). Product entries stay.

Revision ID: 0041
Revises: 0040
Create Date: 2026-11-06
"""

import json
import re
import unicodedata
from collections.abc import Sequence
from urllib.parse import unquote_plus, urlencode

import sqlalchemy as sa
from alembic import op

revision: str = "0041"
down_revision: str | None = "0040"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def V(name: str) -> list[dict]:  # noqa: N802 - reads as the table below
    return [{"vendor": name}]


def P(*keys: str) -> list[dict]:  # noqa: N802
    return [{"product": k} for k in keys]


# a vendor spelling of catalogue 2026.11.06-2 (folded, as systems.vendor_id) → what it stands for now, and the name of
# its vendor then – tests/test_catalog_vendors.py checks it against the catalogue
MOVES: dict[str, tuple[list[dict], str]] = {
    "apache": (V("Apache Software Foundation"), "Apache Software Foundation"),
    "argo": (V("Argo Project"), "Argo"),
    "aristauntangle": (V("Arista Networks"), "Arista Networks"),
    "azure": (P("azure-database-for-mysql", "azure-database-for-postgresql", "azure-kubernetes-service"), "Azure"),
    "bind": (P("bind-9"), "BIND"),
    "bmc": (V("BMC Software"), "Bmc"),
    "broadcom": (V("Broadcom (Symantec)"), "Broadcom"),
    "caddyserver": (V("Caddy"), "Caddyserver"),
    "chef": (V("Progress (Chef)"), "Chef"),
    "ciscoduo": (V("Cisco"), "Cisco"),
    "citrix": (V("Cloud Software Group (Citrix)"), "Citrix"),
    "cloud": (P("cloud-sql-auth-proxy"), "Cloud"),
    "cloudsoftwaregroup": (V("Cloud Software Group (Citrix)"), "Cloud Software Group"),
    "cncfhelm": (V("Helm Project"), "CNCF (Helm)"),
    "cnspec": (V("Mondoo"), "Cnspec"),
    "cockroachdb": (V("Cockroach Labs"), "CockroachDB"),
    "dbt": (V("dbt Labs"), "dbt"),
    "djangoproject": (V("Django Software Foundation"), "Djangoproject"),
    "dovecot": (V("Dovecot (Open-Xchange)"), "Dovecot (Open-Xchange)"),
    "eclipse": (V("Eclipse Foundation"), "Eclipse"),
    "electronjs": (V("Electron"), "Electronjs"),
    "exabeamlogrhythm": (P("logrhythm"), "Exabeam (LogRhythm)"),
    "facebook": (V("Meta"), "Facebook"),
    "filemaker": (V("Claris"), "FileMaker"),
    "fluent": (P("fluent-bit"), "Fluent"),
    "fluentdprojectcncf": (V("Fluentd Project"), "Fluentd Project (CNCF)"),
    "fluxcd": (V("Flux"), "Fluxcd"),
    "freedesktop": (V("freedesktop.org"), "Freedesktop"),
    "getcomposer": (V("Composer"), "Getcomposer"),
    "getkirby": (V("Kirby"), "Getkirby"),
    "gitscm": (V("Git"), "Git-scm"),
    "glasgow": (V("Haskell.org"), "Glasgow"),
    "gnu": (V("Northern.tech"), "Gnu"),
    "goauthentik": (V("Authentik Security"), "Goauthentik"),
    "goteleport": (V("Teleport"), "Goteleport"),
    "grafana": (V("Grafana Labs"), "Grafana"),
    "gruntjs": (V("Grunt"), "Gruntjs"),
    "guzzlephp": (V("Guzzle"), "Guzzlephp"),
    "hornetsecurity": (V("Hornetsecurity (Proofpoint)"), "Hornetsecurity"),
    "idl": (V("NV5 Geospatial"), "IDL"),
    "internet": (P("internet-explorer"), "Internet"),
    "jekyllrb": (V("Jekyll"), "Jekyllrb"),
    "joinmastodon": (V("Mastodon"), "Joinmastodon"),
    "julialang": (V("Julia"), "Julialang"),
    "kaseyadatto": (V("Datto (Kaseya)"), "Datto (Kaseya)"),
    "kiteworkstotemo": (P("totemomail"), "Kiteworks (totemo)"),
    "lancom": (V("LANCOM Systems"), "LANCOM Systems"),
    "lfprojects": (P("valkey"), "Lfprojects"),
    "linux": (V("Linux Kernel Organization"), "Linux"),
    "linuxfoundation": (V("The Linux Foundation"), "Linuxfoundation"),
    "louislamdockge": (P("dockge"), "Louis Lam (Dockge)"),
    "magento": (P("magento"), "Magento"),
    "mandrel": (P("mandrel"), "Mandrel"),
    "mediawiki": (V("Wikimedia Foundation"), "Mediawiki"),
    "mitelunify": (P("unify-openscape"), "Mitel (Unify)"),
    "mule": (V("MuleSoft"), "Mule"),
    "mx": (V("MX Linux"), "MX"),
    "nagios": (V("Nagios Enterprises"), "Nagios"),
    "netbackup": (P("netbackup-appliance-os"), "NetBackup"),
    "netwrixpingcastle": (P("pingcastle"), "Netwrix (PingCastle)"),
    "nextjs": (V("Vercel"), "Next.js"),
    "nix": (P("nix"), "nix"),
    "onigurumaproject": (V("Oniguruma"), "Oniguruma project"),
    "openjsf": (V("OpenJS Foundation"), "Openjsf"),
    "otobo": (V("Rother OSS"), "OTOBO"),
    "phoenix": (V("Phoenix Framework"), "Phoenix"),
    "pivotalsoftware": (V("Broadcom (RabbitMQ)"), "Pivotal software"),
    "podmanproject": (V("Podman"), "Podman project"),
    "popos": (V("System76"), "Pop!_OS"),
    "progresskemp": (V("Progress") + V("Progress (Chef)"), "Progress"),
    "progress": (V("Progress") + V("Progress (Chef)"), "Progress"),  # Progress (alle) covered Chef Infra Server – now Chef's own group
    "rapid7velocidex": (P("velociraptor"), "Rapid7 (Velocidex)"),
    "raspberry": (V("Raspberry Pi"), "Raspberry"),
    "red": (V("Red Hat"), "Red"),
    "rocky": (V("Rocky Linux"), "Rocky"),
    "ros": (V("Open Robotics"), "ROS"),
    "rtpengine": (V("Sipwise"), "rtpengine"),
    "rubylang": (V("Ruby"), "Ruby-lang"),
    "rustlang": (V("Rust Project"), "Rust-lang"),
    "sapmachine": (P("sapmachine"), "SapMachine"),
    "scalalang": (V("Scala"), "Scala-lang"),
    "sensiolabs": (V("Symfony"), "Sensiolabs"),
    "sonarqube": (P("sonarqube-server"), "SonarQube"),
    "spring": (V("Broadcom (Spring)"), "Spring"),
    "squidcache": (V("Squid"), "Squid-cache"),
    "suserancher": (P("k3s"), "SUSE (Rancher)"),
    "tailsproject": (V("Tor Project"), "Tails project"),
    "tailwind": (V("Tailwind Labs"), "Tailwind"),
    "telegraf": (P("telegraf"), "Telegraf"),
    "theforeman": (V("Foreman"), "Theforeman"),
    "thelinuxfoundation": (V("Linux Kernel Organization"), "The Linux Foundation"),
    "truenas": (V("iXsystems"), "TrueNAS"),
    "twig": (P("twig"), "Twig"),
    "unity": (V("Unity Technologies"), "Unity"),
    "valvesoftware": (V("Valve"), "Valvesoftware"),
    "visual": (V("Rocket Software"), "Visual"),
    "vmware": (V("Broadcom (VMware)"), "Broadcom (VMware)"),
    "vuetifyjs": (V("Vuetify"), "Vuetifyjs"),
    "weakforced": (V("PowerDNS"), "Weakforced"),
    "wireshark": (V("Wireshark Foundation"), "Wireshark"),
    "xcpng": (P("xcp-ng"), "XCP-ng"),
    "yarnpkg": (V("Yarn"), "Yarnpkg"),
    "youtrack": (P("youtrack"), "YouTrack"),
}
# the downgrade: a vendor spelling of this catalogue that 0.1.53 does not know (or knows as another vendor) → a spelling
# 0.1.53 has for it (its products, where it has none); every other entry stays – 0.1.53 knows those spellings
BACK: dict[str, list[dict]] = {
    "argoproject": V("Argo"),
    "authentiksecurity": V("Goauthentik"),
    "bmcsoftware": V("Bmc"),
    "broadcomrabbitmq": V("Pivotal software"),
    "broadcomspring": V("Spring"),
    "broadcomsymantec": V("Broadcom"),
    "caddy": V("Caddyserver"),
    "claris": V("FileMaker"),
    "cloudsoftwaregroupcitrix": V("Cloud Software Group"),
    "cockroachlabs": V("CockroachDB"),
    "composer": V("Getcomposer"),
    "dbtlabs": V("dbt"),
    "djangosoftwarefoundation": V("Djangoproject"),
    "eclipsefoundation": V("Eclipse"),
    "electron": V("Electronjs"),
    "fluentdproject": V("Fluentd Project (CNCF)"),
    "flux": V("Fluxcd"),
    "foreman": V("Theforeman"),
    "freedesktoporg": V("Freedesktop"),
    "git": V("Git-scm"),
    "grafanalabs": V("Grafana"),
    "grunt": V("Gruntjs"),
    "guzzle": V("Guzzlephp"),
    "haskellorg": V("Glasgow"),
    "helmproject": V("CNCF (Helm)"),
    "ixsystems": V("TrueNAS"),
    "jekyll": V("Jekyllrb"),
    "julia": V("Julialang"),
    "kirby": V("Getkirby"),
    "linuxkernelorganization": V("The Linux Foundation"),
    "mastodon": V("Joinmastodon"),
    "meta": V("Facebook"),
    "mondoo": V("Cnspec"),
    "mulesoft": V("Mule"),
    "mxlinux": V("MX"),
    "northerntech": V("Gnu"),
    "nv5geospatial": V("IDL"),
    "oniguruma": V("Oniguruma project"),
    "openrobotics": V("ROS"),
    "phoenixframework": V("Phoenix"),
    "podman": V("Podman project"),
    "powerdns": V("Weakforced"),
    "progresschef": V("Chef"),
    "raspberrypi": V("Raspberry"),
    "rocketsoftware": V("Visual"),
    "rockylinux": V("Rocky"),
    "rotheross": V("OTOBO"),
    "ruby": V("Ruby-lang"),
    "rustproject": V("Rust-lang"),
    "scala": V("Scala-lang"),
    "sipwise": V("rtpengine"),
    "squid": V("Squid-cache"),
    "symfony": V("Sensiolabs"),
    "system76": V("Pop!_OS"),
    "tailwindlabs": V("Tailwind"),
    "teleport": V("Goteleport"),
    "torproject": V("Tails project"),
    "unitytechnologies": V("Unity"),
    "valve": V("Valvesoftware"),
    "vercel": V("Next.js"),
    "vuetify": V("Vuetifyjs"),
    "wikimediafoundation": V("Mediawiki"),
    "wiresharkfoundation": V("Wireshark"),
    "yarn": V("Yarnpkg"),
    "broadcom": P("brocade-fos"),  # Brocade (0.1.53: "Broadcom" was Symantec)
    "thelinuxfoundation": V("Linuxfoundation"),  # its projects (0.1.53: "The Linux Foundation" was the kernel)
    "amd": P("amd-epyc", "amd-ryzen"),
    "crushftp": P("crushftp"),
    "cleo": P("cleo-mft"),
    "gladinet": P("gladinet-centrestack"),
    "n8n": P("n8n"),
}


def vendor_id(name: str) -> str:
    """systems.vendor_id: folded (db.fold), letters and digits only."""
    t = unicodedata.normalize("NFKD", (name or "").casefold())
    return "".join(re.findall(r"[a-z0-9]+", "".join(c for c in t if not unicodedata.combining(c))))


def forward() -> dict[str, list[dict]]:
    return {k: v for k, (v, _old) in MOVES.items()}


def backward() -> dict[str, list[dict]]:
    return dict(BACK)


def _entries(values: list, table: dict[str, list[dict]]) -> list:
    out: list = []
    for x in values:
        if isinstance(x, dict) and isinstance(x.get("vendor"), str) and (to := table.get(vendor_id(x["vendor"]))) is not None:
            out += [e for e in to if e not in out]
        elif x not in out:
            out.append(x)
    return out


def _texts(values, table: dict[str, list[dict]]):  # noqa: ANN001, ANN202
    """notify.rule_filter's texts ("v:<id>", "p:<key>") – sorted and unique, as rule_filter writes them."""
    if not isinstance(values, list):
        return values
    out: set = set()
    for x in values:
        kind, _, ref = str(x).partition(":")
        if kind == "v" and (to := table.get(ref)) is not None:
            out |= {f"v:{vendor_id(e['vendor'])}" if "vendor" in e else f"p:{e['product']}" for e in to}
        else:
            out.add(x)
    return sorted(out)


def _earlier(values: list, table: dict[str, list[dict]]) -> list:
    out = []
    for f in values:
        if isinstance(f, dict):
            f = dict(f)
            if isinstance(f.get("systems"), list):
                f["systems"] = _texts(f["systems"], table)
            c = f.get("concern")
            if isinstance(c, list) and c and isinstance(c[0], list):
                f["concern"] = [_texts(c[0], table), *c[1:]]
        out.append(f)
    return out


def _query(query: str, table: dict[str, list[dict]]) -> str:
    """A saved view's query string: its `system=v:<vendor>` parameters by `table` ("v:<spelling>" / "p:<key>") – every
    other part of the text stays as it is, byte for byte (order, spelling, its own encoding, even a malformed one)."""
    lead = "?" if query.startswith("?") else ""
    parts = query[len(lead) :].split("&")
    out: list[str] = []
    seen: set[str] = set()  # the systems written so far (decoded) – a moved vendor that is there already is not twice
    changed = False
    for part in parts:
        key, eq, raw = part.partition("=")
        value = unquote_plus(raw) if eq else ""
        is_system = eq and unquote_plus(key) == "system"
        kind, _, ref = value.partition(":")
        if is_system and kind == "v" and (to := table.get(vendor_id(ref))) is not None:
            changed = True
            for e in to:
                item = f"v:{e['vendor']}" if "vendor" in e else f"p:{e['product']}"
                if item not in seen:
                    seen.add(item)
                    out.append(urlencode([("system", item)]))
            continue
        if is_system:
            if value in seen:
                continue
            seen.add(value)
        out.append(part)
    return lead + "&".join(out) if changed else query


def _own(conn, table: dict[str, list[dict]]) -> int:  # noqa: ANN001
    """The persons' own choices of 0.1.54 that name vendors too: the desktop choice (users.desktop → systems), "Hersteller-
    News meiner Produkte" (person_notify.systems) and the News page's saved views (`system=` in the query)."""
    n = 0
    for uid, desk in conn.execute(sa.text("SELECT id, desktop FROM users WHERE desktop ? 'systems'")).all():
        desk = desk if isinstance(desk, dict) else json.loads(desk or "{}")
        if isinstance(desk.get("systems"), list) and (s2 := _entries(desk["systems"], table)) != desk["systems"]:
            conn.execute(sa.text("UPDATE users SET desktop = CAST(:d AS jsonb) WHERE id = :id"), {"d": json.dumps({**desk, "systems": s2}), "id": uid})
            n += 1
    for pid, systems in conn.execute(sa.text("SELECT user_id, systems FROM person_notify WHERE systems <> '[]'::jsonb")).all():
        systems = systems if isinstance(systems, list) else json.loads(systems or "[]")
        if (s2 := _entries(systems, table)) != systems:
            conn.execute(sa.text("UPDATE person_notify SET systems = CAST(:s AS jsonb) WHERE user_id = :id"), {"s": json.dumps(s2), "id": pid})
            n += 1
    for vid, query in conn.execute(sa.text("SELECT id, query FROM saved_views WHERE query LIKE '%system=%'")).all():
        if (q2 := _query(query or "", table)) != query:
            conn.execute(sa.text("UPDATE saved_views SET query = :q WHERE id = :id"), {"q": q2, "id": vid})
            n += 1
    return n


def move(conn, table: dict[str, list[dict]]) -> int:  # noqa: ANN001
    """Rewrite the rules' vendor entries by `table` (folded spelling → entries) – the number of rules changed – and the
    persons' own choices (_own)."""
    n = _own(conn, table)
    rows = conn.execute(sa.text("SELECT id, systems, earlier FROM notify_rules WHERE systems <> '[]'::jsonb OR earlier <> '[]'::jsonb")).all()
    for rid, systems, earlier in rows:
        systems = systems if isinstance(systems, list) else json.loads(systems or "[]")
        earlier = earlier if isinstance(earlier, list) else json.loads(earlier or "[]")
        s2, e2 = _entries(systems, table), _earlier(earlier, table)
        if (s2, e2) != (systems, earlier):
            conn.execute(
                sa.text("UPDATE notify_rules SET systems = CAST(:s AS jsonb), earlier = CAST(:e AS jsonb), version = version + 1 WHERE id = :id"),
                {"s": json.dumps(s2), "e": json.dumps(e2), "id": rid},
            )
            n += 1
    return n


def upgrade() -> None:
    move(op.get_bind(), forward())


def downgrade() -> None:
    move(op.get_bind(), backward())
