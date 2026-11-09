"""Katalog 2026.11.06-3 (0.1.54): one spelling per vendor, no vendor made up from a label's first word or a CPE, the new
products (AMD, Exchange Online, Entra ID, Brocade, CrushFTP, Cleo, Gladinet, n8n) and migration 0041, which moves the
rules' vendor entries along."""

import importlib
import json
import re

import pytest

from sqlalchemy import text

from app import cvelist, db, systems, vendor, version_input
from app import vendor_catalog as catalog
from app.models import NotifyRule, PersonNotify, SavedView, User

M = importlib.import_module("app.migrations.versions.0041_catalog_vendor_names")
LEGAL = frozenset("inc corp corporation co ltd llc gmbh ag se sa plc nv bv ab oy limited company holdings group foundation project software systems networks technologies technology labs international enterprises".split())


def _products() -> list[dict]:
    return catalog.load()["products"]


def _core(name: str) -> str:
    """A vendor's name without "The" and legal forms – "LANCOM Systems" and "LANCOM" are one; its parenthesis stays."""
    m = re.match(r"^(.*?)\s*(\([^()]*\))?\s*$", name)
    w = re.findall(r"[a-z0-9]+", m.group(1).lower())
    while len(w) > 1 and w[-1] in LEGAL:
        w = w[:-1]
    while w and w[0] == "the":
        w = w[1:]
    return "".join(w) + (m.group(2) or "").lower()


def test_one_spelling_per_vendor():
    """No two spellings of one vendor – not in case ("IBM" / "Ibm"), not with a legal form ("Nagios" / "Nagios
    Enterprises"), not as an owner of its own brand ("Rapid7" / "Rapid7 (Velocidex)"). An owner in parentheses stays
    where the brand is its own (Splunk, CyberArk, Datto, ownCloud, Chef, Symantec, VMware …)."""
    spellings = {str(p.get("vendor") or "") for p in _products()} - {""}
    by_id: dict[str, set[str]] = {}
    by_core: dict[str, set[str]] = {}
    for v in spellings:
        by_id.setdefault(systems.vendor_id(v), set()).add(v)
        by_core.setdefault(_core(v), set()).add(v)
    assert not [v for v in by_id.values() if len(v) > 1]
    assert not [v for v in by_core.values() if len(v) > 1]
    gone = ["Linux", "Red", "Cloud", "Internet", "Azure", "Visual", "Glasgow", "Raspberry", "Mule", "Vmware", "VMware", "Ibm", "Redhat", "Suse", "Haproxy", "Jfrog", "Jquery", "Openbsd", "Apache", "LANCOM", "Nagios", "Citrix", "Spring", "Chef", "Fluent", "SonarQube", "Telegraf"]  # fmt: skip
    gone += ["Louis Lam (Dockge)", "Netwrix (PingCastle)", "Rapid7 (Velocidex)", "Exabeam (LogRhythm)", "Mitel (Unify)", "Kiteworks (totemo)", "SUSE (Rancher)", "CNCF (Helm)", "Fluentd Project (CNCF)", "Cisco (Duo)", "Kaseya (Datto)", "Progress (Kemp)", "Arista (Untangle)"]  # fmt: skip
    gone += ["Djangoproject", "Linuxfoundation", "Postgresql", "Mariadb", "Gitlab", "Hashicorp", "Typo3", "Wordpress", "Openjsf", "Konghq", "Gnu", "Facebook"]
    assert not set(gone) & spellings, set(gone) & spellings


def test_endoflife_products_get_their_vendor():
    """endoflife.date names no vendor: the catalogue took the first word of the label ("Red Hat Satellite" → "Red") or
    the CPE's vendor ("a:djangoproject:django" → "Djangoproject"). An entry without a label now says it."""
    by = {p["key"]: p for p in _products()}
    want = {
        "redhat-satellite": "Red Hat", "rhel": "Red Hat", "ansible": "Red Hat", "keycloak": "Red Hat",
        "cloud-sql-auth-proxy": "Google", "internet-explorer": "Microsoft", "azure-kubernetes-service": "Microsoft",
        "django": "Django Software Foundation", "photon": "Broadcom (VMware)", "vmware-srm": "Broadcom (VMware)",
        "ibm-aix": "IBM", "rancher": "SUSE", "sles": "SUSE", "apache-kafka": "Apache Software Foundation",
        "citrix-vad": "Cloud Software Group (Citrix)", "bind-9": "ISC", "spring-boot": "Broadcom (Spring)",
        "chef-infra-server": "Progress (Chef)", "containerd": "The Linux Foundation", "postgresql": "PostgreSQL",
        "netbackup-appliance-os": "Cohesity (Veritas)", "xcp-ng": "Vates", "sapmachine": "SAP", "react": "Meta",
    }  # fmt: skip
    assert {k: by[k]["vendor"] for k in want} == want
    assert all(by[k]["source"] != "overlay" for k in want)  # still endoflife.date's products (release lines, keys)
    # the Linux kernel is no project of the Foundation, and "Linux" alone names nothing
    assert by["linux"]["vendor"] == by["kvm"]["vendor"] == "Linux Kernel Organization"
    assert by["symantec-endpoint"]["vendor"] == "Broadcom (Symantec)" and by["brocade-fos"]["vendor"] == "Broadcom"


def test_owner_pairs_are_one_vendor():
    by = {p["key"]: p["vendor"] for p in _products()}
    for keys, vendor_ in [
        (("uptime-kuma", "dockge"), "Louis Lam"), (("netwrix-password-secure", "pingcastle"), "Netwrix"),
        (("rapid7-insight-agent", "velociraptor"), "Rapid7"), (("exabeam", "logrhythm"), "Exabeam"),
        (("mitel-mivoice", "unify-openscape"), "Mitel"), (("kiteworks", "totemomail"), "Kiteworks"),
        (("harvester", "k3s", "rancher"), "SUSE"), (("cisco-asa", "duo"), "Cisco"), (("datto", "datto-rmm"), "Datto (Kaseya)"),
        (("moveit-transfer", "kemp-loadmaster"), "Progress"), (("altaro", "hornetsecurity"), "Hornetsecurity (Proofpoint)"),
        (("lancom-lcos", "lancom-lcos-fx"), "LANCOM Systems"), (("nagios", "nagios-xi"), "Nagios Enterprises"),
        (("fluentd", "fluent-bit"), "Fluentd Project"),
    ]:  # fmt: skip
        assert {k: by[k] for k in keys} == dict.fromkeys(keys, vendor_)
    assert by["owncloud"] == "ownCloud (Kiteworks)"  # a brand of its own


def test_no_label_only_of_the_vendor_next_to_a_sibling():
    """"Jenkins (weekly)" next to "Jenkins LTS" was the vendor's name with a parenthesis: no name of its own."""
    by = {p["key"]: p["label"] for p in _products()}
    assert by["jenkins-weekly"] == "Jenkins Weekly" and by["datto"] == "Datto BCDR (SIRIS, ALTO)" and by["okta"] == "Okta Workforce Identity Cloud"
    assert systems.mentions("Jenkins weekly 2.500 fixes", "") == ["m:jenkins-weekly", "v:jenkinsproject"]


def test_the_cnas_and_providers_name_vendors_of_the_catalogue():
    spellings = {str(p.get("vendor") or "").lower() for p in _products()}
    for c in catalog.CNAS:
        assert {v.lower() for v in c["vendors"]} <= spellings, c["key"]
    for p in catalog.CSAF_PROVIDERS:
        assert {v.lower() for v in p["vendors"]} <= spellings, p["key"]
    assert next(c for c in catalog.CNAS if c["key"] == "glibc")["vendors"] == []  # CFEngine's CPE says gnu; it is no glibc


NEW = ("amd-epyc", "amd-ryzen", "exchange-online", "entra-id", "brocade-fos", "crushftp", "cleo-mft", "gladinet-centrestack", "n8n")


def test_new_products_are_complete():
    by = {p["key"]: p for p in _products()}
    for k in NEW:
        p = by[k]
        assert p["source"] == "overlay" and p["category"] != "other" and p.get("kw"), k
        assert p.get("cloud") or p.get("where"), k
        assert p["cpes"] or p.get("hint") == "amd_firmware", k
        if p.get("example"):
            assert version_input.check(p, p["example"]).ok, (k, p["example"])
    assert by["exchange-online"]["cloud"] and by["exchange-online"]["scheme"] == "cloud" and by["exchange-online"]["category"] == "mail"
    assert by["entra-id"]["cloud"] and by["entra-id"]["scheme"] == "cloud" and by["entra-id"]["category"] == "iam"
    assert by["amd-epyc"]["vendor"] == by["amd-ryzen"]["vendor"] == "AMD" and by["amd-epyc"]["category"] == "devices"


def _record(vendor_: str, product: str, versions: list[dict], default: str | None) -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": "CVE-2026-11111", "state": "PUBLISHED", "assignerShortName": "x", "datePublished": "2026-10-29T10:00:00.000Z"},
        "containers": {"cna": {"title": "t", "descriptions": [{"lang": "en", "value": "d"}], "affected": [{"vendor": vendor_, "product": product, "defaultStatus": default, "versions": versions}]}},
    }


def test_new_products_are_found_in_the_cna_records():
    """The rows of the vendors' own CVE records (checked 2026-11-06) – and not those of a neighbour (Entra Connect, Exchange
    Server)."""
    ix = vendor.build_index()
    cases = [
        ("AMD", "AMD EPYC™ 9004 Series", [{"version": "GenoaPI 1.0.0.E", "status": "unaffected"}], "affected", "amd-epyc"),
        ("AMD", "3rd Gen AMD EPYC™ Processors", [{"version": "various", "status": "affected", "lessThan": "Milan PI 1.0.0.D"}], "unaffected", "amd-epyc"),
        ("AMD", "AMD EPYC™ Embedded 9004", [{"version": "EmbGenoaPI-SP5 1.0.0.9", "status": "unaffected"}], "affected", "amd-epyc"),
        ("AMD", "AMD Ryzen™ 7000 Series Desktop Processors", [{"version": "ComboAM5PI 1.0.0.a", "status": "unaffected"}], "affected", "amd-ryzen"),
        ("AMD", "AMD Ryzen™ Threadripper™ PRO 3000WX Series Processors", [{"version": "x", "status": "unaffected"}], "affected", "amd-ryzen"),
        ("AMD", "AMD Ryzen™ AI 300 Series", [{"version": "x", "status": "unaffected"}], "affected", "amd-ryzen"),
        ("Brocade", "Fabric OS", [{"version": "9.1.0", "lessThan": "9.2.2d", "status": "affected", "versionType": "custom"}], "unaffected", "brocade-fos"),
        ("Microsoft", "Microsoft Entra", [{"version": "-", "status": "affected"}], None, "entra-id"),
        ("Microsoft", "Azure Active Directory", [{"version": "-", "status": "affected"}], None, "entra-id"),
        ("Microsoft", "Microsoft Entra Connect", [{"version": "2.0", "lessThan": "2.4.27.0", "status": "affected"}], "unaffected", "entra-connect"),
        ("Microsoft", "Microsoft Exchange Online", [{"version": "-", "status": "affected"}], None, "exchange-online"),
        ("CrushFTP", "CrushFTP", [{"version": "11", "lessThan": "11.3.4_23", "status": "affected", "versionType": "custom"}], "unaffected", "crushftp"),
        ("n8n-io", "n8n", [{"version": "0", "lessThan": "1.123.76", "status": "affected", "versionType": "semver"}], "unaffected", "n8n"),
        ("Gladinet", "CentreStack", [{"version": "0", "lessThan": "16.4.10315.56368", "status": "affected"}], "unaffected", "gladinet-centrestack"),
    ]  # fmt: skip
    for v, p, versions, default, key in cases:
        assert sorted(vendor.link(cvelist.parse_record(_record(v, p, versions, default)), ix)) == [key], p


def test_brocade_s_cna_is_the_vendor():
    from app.vendor_match import cna_by

    assert cna_by(catalog.product("brocade-fos"), {"assigner": "brocade"}) == ("vendor", "")
    assert cna_by(catalog.product("brocade-fos"), {"assigner": "sirt@brocade.com"}) == ("vendor", "")
    assert cna_by(catalog.product("symantec-endpoint"), {"assigner": "symantec"}) == ("vendor", "")
    assert cna_by(catalog.product("netscaler-adc"), {"assigner": "citrix"}) == ("vendor", "")


@pytest.mark.parametrize(
    ("title", "found", "absent"),
    [
        # names left as ordinary words by the vendor cleanup ("Jenkins Weekly" without Jenkins, "Red Hat Satellite"
        # without Red Hat, the vendors Valve, Meta, Symantec, Eclipse): no story about them
        ("⚡ Weekly Recap: Chrome 0-Day, Ivanti Exploits", {"m:chrome"}, {"m:jenkins-weekly"}),
        ("Security Weekly: Ransomware im Mittelstand", set(), {"m:jenkins-weekly"}),
        ("Attack on satellite communications: Viasat KA-SAT", set(), {"m:redhat-satellite"}),
        ("Hackers manipulated valve controls at water utility", set(), {"v:valve"}),
        ("Valve-Manipulation: Angriff auf Wasserwerk", set(), {"v:valve"}),
        ("Meta-Studie: Phishing nimmt zu", set(), {"v:meta"}),
        ("Meta-Analyse zu Passwörtern", set(), {"v:meta"}),
        ("Symantec researchers uncover Chinese espionage campaign", set(), {"v:broadcomsymantec"}),  # research, no product
        ("Symantec: Neue Ransomware-Gruppe entdeckt", set(), {"v:broadcomsymantec"}),
        ("Eclipse-Phishing", set(), {"v:eclipsefoundation"}),
        ("BCDR-Plan für den Mittelstand", set(), {"m:datto"}),
        # … and their own stories still are
        ("Jenkins weekly release fixes XSS", {"m:jenkins-weekly"}, set()),
        ("Red Hat Satellite flaw", {"m:redhat-satellite", "v:redhat"}, set()),
        ("Valve Steam client flaw", {"v:valve"}, set()),
        ("Valve fixes SteamOS bug", {"m:steamos", "v:valve"}, set()),
        ("Meta Llama flaw", {"v:meta"}, set()),
        ("Meta fixes WhatsApp zero-day", {"v:meta"}, set()),
        ("Symantec Endpoint Protection flaw", {"m:symantec-endpoint", "v:broadcomsymantec"}, set()),
        ("Lücke in Symantec", {"v:broadcomsymantec"}, set()),
        ("Eclipse Jetty flaw", {"m:eclipse-jetty"}, set()),
        ("Datto BCDR flaw", {"m:datto"}, set()),
        # recall: SaltStack is the vendor's name again; a second name after one preposition counts as the first
        ("SaltStack Salt master vulnerability", {"m:salt", "v:saltstack"}, set()),
        ("Lücke in Exchange Online und Exchange Server", {"m:exchange-online", "m:msexchange"}, set()),
        ("Kritische Lücken in Outlook und Teams", {"m:outlook", "m:teams"}, set()),
        ("Teams in Exchange und Sales", set(), {"m:msexchange", "m:teams"}),
    ],
)
def test_ordinary_words_of_new_names(title, found, absent):
    got = set(systems.mentions(title, ""))
    assert found <= got and not (absent & got), got


def test_new_names_in_the_news():
    """The new products by their names; "Exchange Online" is no story about Exchange Server, "Azure AD Connect" none
    about Entra ID."""
    cases = [
        ("Exchange Online: Microsoft behebt Lücke", {"m:exchange-online"}, {"m:msexchange"}),
        ("Entra ID: Token-Lücke erlaubte Zugriff auf jeden Tenant", {"m:entra-id"}, {"m:entra-connect"}),
        ("Azure AD Connect flaw", {"m:entra-connect"}, {"m:entra-id"}),
        ("AMD EPYC: SEV-SNP-Lücke", {"m:amd-epyc"}, {"m:amd-ryzen"}),
        ("Ryzen-Prozessoren: Microcode-Lücke", {"m:amd-ryzen"}, {"m:amd-epyc"}),
        ("CrushFTP zero-day exploited", {"m:crushftp"}, set()),
        ("Cleo Harmony und VLTrader angegriffen", {"m:cleo-mft"}, set()),
        ("Triofox flaw", {"m:gladinet-centrestack"}, set()),
        ("n8n: kritische Lücke", {"m:n8n"}, set()),
        ("Brocade Fabric OS: Lücken geschlossen", {"m:brocade-fos", }, {"v:broadcomvmware", "v:broadcomsymantec"}),
        ("Helm charts with malware", {"m:helm"}, set()),
        ("Linux KVM: guest escape", {"m:kvm"}, set()),
        ("Citrix warnt vor NetScaler-Lücke", {"m:netscaler-adc", "v:cloudsoftwaregroupcitrix"}, set()),
        ("Broadcom fixes chip flaw", {"v:broadcom"}, {"v:broadcomvmware", "v:broadcomsymantec", "v:broadcomspring"}),
    ]  # fmt: skip
    for title, found, absent in cases:
        got = set(systems.mentions(title, ""))
        assert found <= got and not (absent & got), (title, got)


# ---------------------------------------------------------------- migration 0041: the rules' vendor entries


def test_migration_0041_moves_to_what_the_catalogue_has():
    """Every spelling it moves is gone from the catalogue (or – Broadcom, The Linux Foundation – another vendor now);
    every target is a vendor spelling or a product of the catalogue; the downgrade's spellings are no spellings of
    this catalogue (except the products, which 0.1.53 does not know)."""
    spellings = {systems.vendor_id(str(p.get("vendor") or "")): p["vendor"] for p in _products()}
    keys = {p["key"] for p in _products()}
    for old, (new, _then) in M.MOVES.items():
        assert old not in spellings or old in ("broadcom", "thelinuxfoundation", "progress"), old
        for e in new:
            assert ("vendor" in e and spellings.get(systems.vendor_id(e["vendor"])) == e["vendor"]) or e.get("product") in keys, (old, e)
    for new, back in M.BACK.items():
        assert new in spellings, new
        for e in back:
            # Broadcom and The Linux Foundation: their meaning in 0.1.53 (Symantec, the kernel)
            assert ("vendor" in e and (systems.vendor_id(e["vendor"]) not in spellings or e["vendor"] in ("Broadcom", "The Linux Foundation"))) or e.get("product") in keys, (new, e)
    # what a rule meant stays: the same products (or, the same vendor, a few more of its own)
    assert systems.product_keys(M.forward()["broadcom"]) == ["symantec-endpoint"]
    assert systems.product_keys(M.forward()["thelinuxfoundation"]) == ["kvm", "linux"]
    assert systems.product_keys(M.forward()["azure"]) == ["azure-database-for-mysql", "azure-database-for-postgresql", "azure-kubernetes-service"]
    assert systems.product_keys(M.forward()["rapid7velocidex"]) == ["velociraptor"]
    assert set(systems.product_keys(M.forward()["vmware"])) >= {"esxi", "photon", "vmware-srm"}


async def test_migration_0041_moves_the_rules_vendor_entries():
    async with db.session() as s:
        moved = NotifyRule(
            name="moved",
            systems=[{"vendor": "Nagios"}, {"vendor": "VMware"}, {"vendor": "Azure"}, {"product": "panos"}, {"vendor": "Palo Alto Networks"}, {"vendor": "broadcom"}],
            earlier=[{"seq": 1, "at": "2026-11-06T10:00:00+00:00", "systems": ["p:panos", "v:nagios", "v:rapid7velocidex"]}, {"seq": 2, "concern": [["v:cloud"], ["exchange"]]}],
        )
        kept = NotifyRule(name="kept", systems=[{"vendor": "Palo Alto Networks"}, {"product": "panos"}], earlier=[{"seq": 1, "systems": ["v:paloaltonetworks"]}])
        s.add_all([moved, kept])
        await s.commit()
        ids = {"moved": moved.id, "kept": kept.id}

    def step(conn):  # noqa: ANN001, ANN202
        n = M.move(conn, M.forward())
        rows = {r[0]: r[1:] for r in conn.execute(text("SELECT name, systems, earlier, version FROM notify_rules")).all()}
        back = M.move(conn, M.backward())
        rows_back = {r[0]: r[1] for r in conn.execute(text("SELECT name, systems FROM notify_rules")).all()}
        return n, rows, back, rows_back

    async with db.engine().connect() as conn:
        trans = await conn.begin()
        try:
            n, rows, back, rows_back = await conn.run_sync(step)
        finally:
            await trans.rollback()
    assert ids and n == 1 and back == 1

    def load(x):  # noqa: ANN001, ANN202
        return x if isinstance(x, list) else json.loads(x)

    systems_, earlier, version = load(rows["moved"][0]), load(rows["moved"][1]), rows["moved"][2]
    assert systems_ == [
        {"vendor": "Nagios Enterprises"}, {"vendor": "Broadcom (VMware)"},
        {"product": "azure-database-for-mysql"}, {"product": "azure-database-for-postgresql"}, {"product": "azure-kubernetes-service"},
        {"product": "panos"}, {"vendor": "Palo Alto Networks"}, {"vendor": "Broadcom (Symantec)"},
    ]  # fmt: skip
    assert all(systems.known(e) for e in systems_) and version == 2
    assert earlier[0]["systems"] == ["p:panos", "p:velociraptor", "v:nagiosenterprises"] and earlier[1]["concern"] == [["p:cloud-sql-auth-proxy"], ["exchange"]]
    assert load(rows["kept"][0]) == [{"vendor": "Palo Alto Networks"}, {"product": "panos"}] and rows["kept"][2] == 1
    # down again: spellings 0.1.53 knows (any of a vendor's spellings is that vendor there)
    assert load(rows_back["moved"]) == [
        {"vendor": "Nagios Enterprises"}, {"vendor": "Broadcom (VMware)"},
        {"product": "azure-database-for-mysql"}, {"product": "azure-database-for-postgresql"}, {"product": "azure-kubernetes-service"},
        {"product": "panos"}, {"vendor": "Palo Alto Networks"}, {"vendor": "Broadcom"},
    ]  # fmt: skip


async def test_migration_0041_moves_the_persons_own_choices():
    """Desktop choice, "Hersteller-News meiner Produkte" and the News page's saved views name vendors too (0.1.54)."""
    async with db.session() as s:
        u = User(username="viewer1", display_name="Viewer", role="reader", auth_source="local", desktop={"enabled": True, "systems": [{"vendor": "Nagios"}, {"product": "panos"}]})
        s.add(u)
        await s.flush()
        s.add(PersonNotify(user_id=u.id, systems=[{"vendor": "Azure"}]))
        s.add(SavedView(user_id=u.id, page="news", name="mine", query="sev=critical&system=v%3ANagios&system=p%3Apanos&q=a+b"))
        s.add(SavedView(user_id=u.id, page="news", name="other", query="system=v%3APalo+Alto+Networks"))
        await s.commit()
        uid = u.id

    def step(conn):  # noqa: ANN001, ANN202
        M.move(conn, M.forward())
        desk = conn.execute(text("SELECT desktop FROM users WHERE id = :i"), {"i": uid}).scalar_one()
        own = conn.execute(text("SELECT systems FROM person_notify WHERE user_id = :i"), {"i": uid}).scalar_one()
        views = dict(conn.execute(text("SELECT name, query FROM saved_views WHERE user_id = :i"), {"i": uid}).all())
        return desk, own, views

    async with db.engine().connect() as conn:
        trans = await conn.begin()
        try:
            desk, own, views = await conn.run_sync(step)
        finally:
            await trans.rollback()
    desk = desk if isinstance(desk, dict) else json.loads(desk)
    own = own if isinstance(own, list) else json.loads(own)
    assert desk["systems"] == [{"vendor": "Nagios Enterprises"}, {"product": "panos"}] and desk["enabled"] is True
    assert {"vendor": "Azure"} not in own and own and all("product" in e for e in own)
    assert views["mine"] == "sev=critical&system=v%3ANagios+Enterprises&system=p%3Apanos&q=a+b"
    assert views["other"] == "system=v%3APalo+Alto+Networks"  # unchanged: written as it was


def test_migration_0041_rewrites_only_the_moved_systems_of_a_view():
    """Every other part of a saved view's query stays byte for byte – a bare flag, its own encoding, a malformed %."""
    t = M.forward()
    q = "a&sev=critical&q=%zz+caf%C3%A9&system=v%3ANagios&x=1;y&system=v%3ANagios+Enterprises&system=p:panos&empty="
    assert M._query(q, t) == "a&sev=critical&q=%zz+caf%C3%A9&system=v%3ANagios+Enterprises&x=1;y&system=p:panos&empty="
    assert M._query("?system=v:Azure&q=%E4", t) == "?system=p%3Aazure-database-for-mysql&system=p%3Aazure-database-for-postgresql&system=p%3Aazure-kubernetes-service&q=%E4"
    unchanged = "a&q=%zz&system=v%3APalo+Alto+Networks"
    assert M._query(unchanged, t) is unchanged


def test_migration_0041_narrows_no_vendor():
    """What a rule's vendor stood for in 0.1.53 is still in what the migration makes of it – Progress covered Chef Infra
    Server (endoflife.date's CPE said progress), which is "Progress (Chef)" now."""
    assert {"chef-infra-server", "moveit-transfer", "kemp-loadmaster"} <= set(systems.product_keys(M.forward()["progress"]))
    assert {"chef-infra-server", "kemp-loadmaster"} <= set(systems.product_keys(M.forward()["progresskemp"]))
    assert "saltstack" not in M.MOVES and systems.product_keys([{"vendor": "Saltstack"}]) == ["salt"]  # the spelling of 0.1.53
