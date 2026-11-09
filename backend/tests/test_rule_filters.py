"""The rules' "Betrifft" (systems of the whole catalogue – a vendor or a product, exact from the details or named in the
title or teaser – and own words) and "Nicht senden, wenn enthalten": the matching (mentions without the obvious false
positives, exact as the matcher judges the whole catalogue), the live round with severities and sources, Vendor News
events by system, a product the catalogue adds later, details that arrive later (sent once) against a quiet recompute
(never sent), widening, the dry run, the API's checks, the audit names, the messages' "Treffer" – and the source a
message names for a story a rule brought for a further source ("B (auch A)")."""

import json
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text, update
from test_notify import SLACK, Hooks, _channel, _dispatch, _rule, _source

from app import db, keywords, news, notify, notify_api, story_details, systems
from app import vendor_catalog as catalog
from app.models import AuditEntry, NewsItem, NewsItemSource, NewsSource, NotifyRule, StoryDetail, VendorEvent

FIX = Path(__file__).parent / "fixtures" / "vendor"
PAN = {"vendor": "Palo Alto Networks"}


@pytest.fixture
def hooks(monkeypatch):
    h = Hooks()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(h.handler))
    return h


def _pan_details() -> dict:
    return story_details.parse_cve5((FIX / "cve5_pan.json").read_bytes())  # PAN-OS (and Panorama, which runs it)


def _forti_details() -> dict:
    return story_details.parse_csaf((FIX / "fortinet_csaf_wad.json").read_bytes(), "fortinet")


async def _news(src: NewsSource, title: str, summary: str = "", severity: str = "critical", details: dict | None = None) -> uuid.UUID:
    """A story as news.store keeps it (search text, the systems its title and teaser name) – with details, when given,
    as if they had come with it (loud)."""
    now = datetime.now(UTC)
    key = f"{time.time_ns()}-{uuid.uuid4().hex[:6]}"
    async with db.session() as s:
        i = NewsItem(
            source_id=src.id,
            url=f"https://news.example.org/{key}",
            url_key=key,
            title=title,
            title_key=f"t{key}",
            summary=summary,
            published_at=now,
            fetched_at=now,
            severity=severity,
            cves=[],
            search=news.search_text(title, summary, []),
            systems=systems.mentions(title, summary),
            seq=await news.next_seq(s),
        )
        s.add(i)
        await s.flush()
        if details is not None:
            s.add(StoryDetail(item_id=i.id, kind="nvd", status="ok", data=details, fetched_at=now))
            await systems.set_exact(s, i.id, systems.exact(details), quiet=False)
        await s.commit()
        return i.id


def _slack_texts(hooks: Hooks) -> list[str]:
    return [json.dumps(Hooks.body(r), ensure_ascii=False) for r in hooks.to("hooks.slack.com")]


async def _sent_titles(hooks: Hooks) -> list[str]:
    async with db.session() as s:
        titles = {str(i.id): i.title for i in await s.scalars(select(NewsItem))}
    return sorted(t for t in titles.values() if any(t in x for x in _slack_texts(hooks)))


async def _setup(c, **rule) -> tuple[NewsSource, dict]:  # noqa: ANN001
    src = await _source()
    ch = await _channel(c, name="SOC", type="slack", url=SLACK)
    r = await _rule(c, "Palo", [ch["id"]], **{"severities": [], **rule})
    return src, r


# ---------------------------------------------------------------- the matching


@pytest.mark.parametrize(
    ("title", "teaser", "found", "absent"),
    [
        ("Palo Alto Networks: Kritische Lücke in PAN-OS wird angegriffen", "", {"m:panos", "v:paloaltonetworks"}, set()),
        ("Palo-Alto-Firewalls: Angreifer nutzen GlobalProtect-Lücke aus", "", {"m:pangp", "v:paloaltonetworks"}, set()),
        ("PAN OS 11.2 fixes", "", {"m:panos"}, set()),
        # ordinary words count only with the vendor named (title or teaser)
        ("Expedition: Lücke im Migrationswerkzeug", "Palo Alto Networks schließt sie.", {"m:expedition"}, set()),
        ("Die Expedition ins Darknet", "Forscher berichten über Ransomware.", set(), {"m:expedition"}),
        ("Panorama der Bedrohungen 2026", "", set(), {"m:panorama"}),
        ("Exchange Server: Microsoft patcht kritische Lücke", "", {"m:msexchange", "v:microsoft"}, set()),
        # … or, a few distinctive ones, in a security context: before a word of it, after one and a preposition, before
        # a version (systems.CONTEXT)
        ("Exchange-Lücke wird ausgenutzt", "", {"m:msexchange"}, {"v:microsoft"}),
        ("Kritische Lücke in Exchange", "", {"m:msexchange"}, set()),
        ("Hackers demand ransom in exchange for data", "", set(), {"m:msexchange"}),
        ("Zoom fixes flaws in Workplace app", "", {"m:zoom", "v:zoom"}, set()),
        ("Zoom-Sicherheitslücke", "", {"m:zoom"}, set()),
        ("Outlook-Lücke", "", {"m:outlook"}, {"m:office"}),
        ("Windows-Lücke wird ausgenutzt", "", {"m:windows"}, set()),
        ("Edge-Browser: Update schließt Lücken", "", {"m:edge"}, set()),
        ("Edge 130 update", "", {"m:edge"}, set()),
        ("On the edge of ransomware", "", set(), {"m:edge"}),
        ("Spring Framework RCE", "", {"m:spring-framework"}, set()),
        ("Spring attacks on hospitals rise", "", set(), {"m:spring-framework", "v:spring", "v:broadcomspring"}),
        # a product by its label without its vendor in front; vendors of three letters or fewer that are no abbreviation
        ("Chrome 130 schließt Lücken", "", {"m:chrome"}, set()),
        ("SAP-Patchday: 20 Lücken", "", {"v:sap"}, set()),
        ("IBM warnt vor Lücke in QRadar", "", {"m:ibm-qradar", "v:ibm"}, set()),
        ("HPE iLO angreifbar", "", {"v:hpe"}, set()),
        ("AVM", "", {"v:avmfritz"}, set()),
        # a vendor's name as a place or a term, a German word: nothing
        ("Ransomware gang hits Palo Alto city hall", "The city of Palo Alto, California, …", set(), {"v:paloaltonetworks"}),
        ("PALO ALTO, Calif., Nov. 5 /PRNewswire/ -- HP Inc. today announced", "", {"v:hpinc"}, {"v:paloaltonetworks"}),
        ("Palo Alto warnt vor Zero-Day", "", {"v:paloaltonetworks"}, set()),
        ("Threat Intel: neue Kampagne", "", set(), {"v:intel"}),
        ("Intel-Prozessoren: Lücke", "", {"v:intel"}, set()),
        ("BSI-Chef warnt", "Signal-Chef äußert sich", set(), {"v:chef", "v:progress", "v:progresschef"}),
        # one name, one product: PAN-OS is PAN-OS (Panorama runs it, but a story naming PAN-OS is not about Panorama);
        # a vendor's own name in one product's keywords is the vendor ("Zyxel warnt" is no switch story)
        ("PAN-OS: kritische Lücke", "", {"m:panos"}, {"m:panorama"}),
        ("GlobalProtect-Lücke wird aktiv ausgenutzt", "", {"m:pangp", "m:panos"}, set()),  # the app and the PAN-OS gateway
        ("Zyxel warnt vor Angriffen", "", {"v:zyxel"}, {"m:zyxel-switch", "m:zyxel-firewall"}),
        ("Zyxel firewalls", "", {"m:zyxel-firewall"}, {"m:zyxel-switch"}),
        ("SonicWall SMA 100", "", {"m:sonicwall-sma"}, {"m:sonicwall-sonicos"}),
        ("MikroTik routers hijacked", "", {"v:mikrotik"}, {"m:routeros"}),
        ("Jenkins fixes RCE", "", {"v:jenkinsproject"}, {"m:jenkins", "m:jenkins-weekly"}),  # "Jenkins (weekly)" is no more Jenkins
        ("Grafana fix", "", {"m:grafana", "v:grafanalabs"}, set()),  # the product that is called so (and the vendor's short name)
        # the longest name wins
        ("NGINX Plus", "", {"m:nginx-plus"}, {"m:nginx"}),
        ("Grafana Loki flaw", "", {"m:grafana-loki"}, {"m:grafana"}),
        # one vendor of several spellings
        ("VMware ESXi ransomware", "", {"m:esxi", "v:broadcomvmware"}, {"v:vmware"}),
        ("Apache Struts 2 flaw", "", {"m:apache-struts", "v:apachesoftwarefoundation"}, {"v:apache"}),
        ("Teams of attackers target banks", "", set(), {"m:teams"}),
        ("Microsoft Teams: Phishing über Chats", "", {"m:teams"}, set()),
        ("Cloud NGFW", "", set(), {"m:cloud-ngfw"}),
        ("Zoom in on ransomware", "", set(), {"m:zoom"}),  # the product's name is its vendor's: not both at once
        # whole words only
        ("Fortinets neue Strategie", "", set(), {"v:fortinet"}),
        ("Firefox 145 schließt Sicherheitslücken", "", {"m:firefox"}, set()),
        ("FortiGate devices under attack", "", {"m:fortios"}, set()),
        ("Red Hat Enterprise Linux 10 update", "", {"m:rhel", "v:redhat"}, set()),
        ("Linux-Kernel: Lücke", "", {"m:linux"}, {"v:linux", "v:thelinuxfoundation", "v:linuxkernelorganization"}),
        ("Linux Foundation startet neues Projekt", "Linux-Server betroffen?", set(), {"m:linux", "v:linuxkernelorganization"}),
        # a brand of another vendor is named by its products, not by its parent's name
        ("Cisco ASA: Zero-Day", "", {"m:cisco-asa", "v:cisco"}, {"m:duo"}),
        # no name across the end of the title
        ("Neues von Palo", "Alto Networks? Nein.", set(), {"v:paloaltonetworks"}),
        # a feed's topic tags at the end of the teaser (golem.de) are no statement of the story
        ("Antrag: Grüne fordern Haftung für KI-Firmen", "Die Grünen fordern strengere Auflagen. (Security, PHP)", set(), {"m:php", "v:thephpgroup"}),
        ("PHP 8.4.1 schließt kritische Lücke", "Details im Advisory. (Security, PHP)", {"m:php"}, set()),
        # the US authority is no vendor in the news – its tool is named by its own name
        ("CISA warns of exploited Cisco flaw", "", {"v:cisco"}, {"v:cisa"}),
        ("CISA ScubaGear 2.0 released", "", {"m:scubagear"}, set()),
        # AMD is a vendor name, no abbreviation of the news
        ("AMD warnt vor Lücken in Prozessoren", "", {"v:amd"}, set()),
    ],
)
def test_mentions_name_systems_without_the_obvious_false_positives(title, teaser, found, absent):
    got = set(systems.mentions(title, teaser))
    assert found <= got and not (absent & got), got


def test_exact_systems_are_what_the_matcher_finds_in_the_whole_catalogue():
    """The candidates (words of the details → story_details.anchors) narrow, they never decide: the same products as
    judging every catalogue product against every fixture's details – "not affected" never counts."""
    from test_topics_phase2 import _fixture_details

    prods = catalog.load()["products"]
    found = 0
    for d in _fixture_details():
        full = sorted({m["product"] for m in story_details.matches(d, [(p, []) for p in prods])})
        assert systems.exact(d) == full
        found += bool(full)
    assert found > 20
    assert systems.exact(_pan_details()) == ["panorama", "panos"] and systems.exact(None) == [] and systems.exact({}) == []


def test_keywords_are_plain_whole_words_escaped_for_the_database():
    assert keywords.clean([" Palo  Alto ", "palo alto", "C++", ".NET"]) == ["Palo Alto", "C++", ".NET"]
    for bad in (["x"], ["a" * 61], ["<script>"], ["a|b"], ["(a+)+$"], ["--"], ["a\x00b"], [f"w{n}" for n in range(31)]):
        with pytest.raises(ValueError):
            keywords.clean(bad)
    p = keywords.pattern(["C++", "Palo Alto", "a.b"])
    assert p == r"(^|[^[:alnum:]])(a\.b|c\+\+|palo[-[:space:]]+alto)($|[^[:alnum:]])"
    s = news.search_text("Palo-Alto-Firewalls: neue Lücke in C++-Bibliothek", "Ein Fortinets-Gerät", [])
    assert keywords.hits(s, ["Palo Alto", "C++", "Fortinet", "Lücke", "bibliothek x"]) == ["Palo Alto", "C++", "Lücke"]


async def test_keywords_in_the_database_match_whole_words_and_take_no_pattern(admin_client):
    src = await _source()
    a = await _news(src, "Ransomware-Angriff auf Klinik")
    b = await _news(src, "Ransomwaregruppe zerschlagen")
    c = await _news(src, "Lücke in C++-Bibliothek", "Ein Beispiel")
    d = await _news(src, "Lücke in C-Bibliothek und .NET")
    async with db.session() as s:

        async def ids(words):  # noqa: ANN001, ANN202
            return set(await s.scalars(select(NewsItem.id).where(keywords.clause(words))))

        assert await ids(["ransomware"]) == {a}  # "Ransomwaregruppe" is another word
        assert await ids(["C++"]) == {c} and await ids([".NET"]) == {d}  # signs are plain text, never a pattern
        assert await ids(["RANSOMWARE", "c-bibliothek"]) == {a, d}  # "C++-Bibliothek" is not "C-Bibliothek"
        assert set(await s.scalars(select(NewsItem.id).where(keywords.none_of(["ransomware"])))) == {b, c, d}


# ---------------------------------------------------------------- the live round


async def test_only_palo_alto_only_critical_one_rule(admin_client, hooks):
    src, _ = await _setup(admin_client, systems=[PAN], severities=["critical"])
    await _news(src, "Palo Alto Networks: Kritische Lücke in PAN-OS")
    await _news(src, "Palo Alto Networks: Lücke in Prisma Access", severity="high")  # not critical
    await _news(src, "Fortinet: Kritische Lücke in FortiOS")  # another vendor
    await _news(src, "Kritische Lücke in einem Router")  # no system at all
    await _news(src, "CVE-2026-1234: kritische Lücke", details=_pan_details())  # exact: its details concern PAN-OS
    await _dispatch()
    assert await _sent_titles(hooks) == ["CVE-2026-1234: kritische Lücke", "Palo Alto Networks: Kritische Lücke in PAN-OS"]
    body = "\n".join(_slack_texts(hooks))
    assert "Treffer" in body and "PAN-OS" in body


async def test_a_product_systems_or_keywords_and_exclusions(admin_client, hooks):
    src, _ = await _setup(admin_client, systems=[{"product": "panos"}], keywords=["Citrix Bleed"], exclude=["Webinar"])
    await _news(src, "PAN-OS: neue Version")
    await _news(src, "Citrix-Bleed 3 wird ausgenutzt")  # a word – blank or hyphen alike
    await _news(src, "Webinar: PAN-OS richtig härten")  # excluded, whatever else it matches
    await _news(src, "Prisma Access: Lücke", "Palo Alto Networks warnt.")  # the vendor, not the product
    await _dispatch()
    assert await _sent_titles(hooks) == ["Citrix-Bleed 3 wird ausgenutzt", "PAN-OS: neue Version"]
    assert "Citrix Bleed" in "\n".join(_slack_texts(hooks))  # the word it matched by


async def test_systems_and_words_together_with_the_sources(admin_client, hooks):
    src = await _source()
    async with db.session() as s:
        other = NewsSource(key="feed-y", name="Other Feed", url="https://news.example.org/y.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(other)
        await s.commit()
    ch = await _channel(admin_client, name="SOC", type="slack", url=SLACK)
    await _rule(admin_client, "Palo", [ch["id"]], severities=[], sources=[str(src.id)], systems=[PAN])
    await _news(src, "PAN-OS: Lücke")
    await _news(other, "PAN-OS: Lücke anderswo")  # not of the rule's source
    await _dispatch()
    assert await _sent_titles(hooks) == ["PAN-OS: Lücke"]


async def test_an_entry_the_catalogue_no_longer_knows_stands_for_nothing(admin_client, hooks):
    src, r = await _setup(admin_client, systems=[{"product": "panos"}])
    async with db.session() as s:
        await s.execute(update(NotifyRule).where(NotifyRule.id == uuid.UUID(r["id"])).values(systems=[{"product": "gone-product"}, {"vendor": "Nobody Inc"}]))
        await s.commit()
    await _news(src, "PAN-OS: Lücke")
    await _news(src, "Irgendeine Lücke")
    await _dispatch()
    assert hooks.to("hooks.slack.com") == []  # never "all"
    # kept on a save (it is the rule's already) – a new unknown one is refused
    rr = (await admin_client.get("/api/admin/notify/rules")).json()[0]
    body = {k: rr[k] for k in ("name", "channels", "severities", "sources", "topics", "lang", "kinds", "teams", "systems", "keywords", "exclude")}
    assert (await admin_client.put(f"/api/admin/notify/rules/{r['id']}", json={**body, "version": rr["version"]})).status_code == 200
    bad = await admin_client.put(f"/api/admin/notify/rules/{r['id']}", json={**body, "systems": [*body["systems"], {"product": "other-gone"}]})
    assert bad.status_code == 422 and bad.json()["detail"]["code"] == "system_not_found"


async def test_vendor_news_events_by_system(admin_client, hooks):
    await _setup(admin_client, systems=[PAN], kinds=["vendor_vuln"])
    async with db.session() as s:
        for k in ("panos", "fortios"):
            s.add(VendorEvent(key=f"vuln:{k}:*:x", kind="vuln", product=k, severity="critical", data={"product": k, "status": "affected", "title": f"Lücke in {k}"}))
        await s.commit()
    await _dispatch()
    body = "\n".join(_slack_texts(hooks))
    assert "PAN-OS" in body and "FortiOS" not in body


@pytest.mark.parametrize("spelling", ["Broadcom (VMware)", "broadcom (vmware)", "BROADCOM (VMWARE)"])
async def test_one_vendor_is_one_choice_whatever_its_case(admin_client, hooks, spelling):
    """VMware is "Broadcom (VMware)" in the catalogue (ESXi, vCenter … and, since catalogue 2026.11.06-3, Photon and Site
    Recovery Manager, which endoflife.date spelled "VMware"/"Vmware"): a rule "VMware (alle Produkte)" in any case is
    all of them – news and Vendor News events – and never Broadcom's other brands (Symantec, Spring, Brocade)."""
    want = set(systems.product_keys([{"vendor": spelling}]))
    assert {"esxi", "vcenter", "vmware-srm", "photon"} <= want
    assert not {"symantec-endpoint", "spring-boot", "rabbitmq", "brocade-fos"} & want  # Broadcom's other brands: not VMware
    assert systems.known({"vendor": spelling}) and systems.text_of({"vendor": spelling}) == "v:broadcomvmware"
    assert systems.label({"vendor": spelling}) == "Broadcom (VMware) (alle Produkte)"
    src, _ = await _setup(admin_client, systems=[{"vendor": spelling}], kinds=["news", "vendor_vuln"])
    async with db.session() as s:
        for k in ("esxi", "vcenter", "symantec-endpoint"):
            s.add(VendorEvent(key=f"vuln:{k}:*:x", kind="vuln", product=k, severity="critical", data={"product": k, "status": "affected", "title": f"Lücke in {k}"}))
        await s.commit()
    await _news(src, "VMware warnt vor Lücke")  # the brand in the parenthesis names the vendor
    await _dispatch()
    body = "\n".join(_slack_texts(hooks))
    assert "vendor?product=esxi" in body and "vendor?product=vcenter" in body and "symantec" not in body
    assert "VMware warnt vor Lücke" in body


def test_the_vendor_identities_of_the_catalogue():
    """Catalogue 2026.11.06-3: one spelling per vendor – the identity groups (systems._groups) are single spellings,
    except one brand with several owners (Veritas: NetBackup at Cohesity, Backup Exec at Arctera)."""
    ix = systems.index()
    several = {gid: v["names"] for gid, v in ix.vendors.items() if len(v["names"]) > 1}
    assert several == {"veritas": ["Arctera (Veritas)", "Cohesity (Veritas)"]}, several
    # an owner in parentheses is no brand: CyberArk stays CyberArk, Splunk Splunk – "Palo Alto Networks (alle)" is
    # Palo Alto's own products; Broadcom's brands are each their own (and "Broadcom" itself is Brocade)
    apart = [
        ("CyberArk (Palo Alto Networks)", "Palo Alto Networks"), ("Splunk (Cisco)", "Cisco"), ("Broadcom", "Broadcom (VMware)"),
        ("Broadcom (Symantec)", "Broadcom (VMware)"), ("Broadcom (Spring)", "Broadcom (VMware)"), ("Kaseya", "Datto (Kaseya)"),
        ("ownCloud (Kiteworks)", "Kiteworks"), ("Progress (Chef)", "Progress"), ("Linux Kernel Organization", "The Linux Foundation"),
    ]  # fmt: skip
    for a, b in apart:
        assert systems.group_of(a) != systems.group_of(b) and systems.group_of(a) and systems.group_of(b), (a, b)
    assert not {"cyberark-pam", "cyberark-privilege-cloud"} & set(systems.product_keys([PAN]))
    assert set(systems.product_keys([{"vendor": "Broadcom (Symantec)"}])) == {"symantec-endpoint"}
    assert set(systems.product_keys([{"vendor": "Broadcom"}])) == {"brocade-fos"}
    assert {"linux", "kvm"} == set(systems.product_keys([{"vendor": "Linux Kernel Organization"}]))
    # every product in one group
    assert len(ix.vendor_of) == sum(1 for p in catalog.load()["products"] if str(p.get("vendor") or "").strip())


def test_the_vendor_identities_of_several_spellings():
    """The groups still join what one vendor's spellings would be – catalogue data of later (an endoflife.date product
    with a CPE's spelling) or of a custom catalogue: "VMware" (Photon) and "Broadcom (VMware)" (ESXi), "Apache" and
    "Apache Software Foundation", "LANCOM" and "LANCOM Systems" are one vendor; an owner in parentheses makes none."""
    def p(key, label, vendor, source="overlay"):
        return {"key": key, "label": label, "vendor": vendor, "source": source, "cpes": []}

    cat = {"products": [
        p("esxi", "VMware ESXi", "Broadcom (VMware)"), p("photon", "VMware Photon", "Vmware", "eol"), p("srm", "VMware SRM", "VMware", "eol"),
        p("symantec", "Symantec Endpoint Protection", "Broadcom (Symantec)"), p("fos", "Brocade Fabric OS", "Broadcom"),
        p("tomcat", "Apache Tomcat", "Apache Software Foundation"), p("kafka", "Apache Kafka", "Apache", "eol"),
        p("lcos", "LANCOM LCOS", "LANCOM Systems"), p("lcos-fx", "LANCOM LCOS FX", "LANCOM"),
        p("cyberark", "CyberArk PAM", "CyberArk (Palo Alto Networks)"), p("panos", "PAN-OS", "Palo Alto Networks"),
        p("netbackup", "Veritas NetBackup", "Cohesity (Veritas)"), p("backup-exec", "Veritas Backup Exec", "Arctera (Veritas)"),
    ]}  # fmt: skip
    alias, groups = systems._groups(cat)
    by = {gid: set(g["keys"]) for gid, g in groups.items()}
    assert by[alias["vmware"]] == {"esxi", "photon", "srm"} and groups[alias["vmware"]]["name"] == "Broadcom (VMware)"
    assert by[alias["apache"]] == {"tomcat", "kafka"} and by[alias["lancom"]] == {"lcos", "lcos-fx"}
    assert by[alias["broadcomsymantec"]] == {"symantec"} and by[alias["broadcom"]] == {"fos"}
    assert by[alias["cyberarkpaloaltonetworks"]] == {"cyberark"} and by[alias["paloaltonetworks"]] == {"panos"}
    assert by[alias["cohesityveritas"]] == {"netbackup", "backup-exec"} and groups[alias["cohesityveritas"]]["name"] == "Veritas"


async def test_the_catalogue_names_each_product_s_vendor_identity(reader_client):
    got = {p["key"]: p for p in (await reader_client.get("/api/vendor/catalog")).json()["products"]}
    assert got["esxi"]["vendor_group"] == got["photon"]["vendor_group"] == "broadcomvmware"
    assert got["photon"]["vendor_group_name"] == got["photon"]["vendor"] == "Broadcom (VMware)"
    assert got["veritas-netbackup"]["vendor_group"] == got["backup-exec"]["vendor_group"] == "veritas"
    assert got["veritas-netbackup"]["vendor_group_name"] == "Veritas" and got["veritas-netbackup"]["vendor"] == "Cohesity (Veritas)"


def test_the_signature_follows_what_the_matching_reads_only(monkeypatch):
    """systems_round computes the stories again for the products whose entry changed – an example, a version command or
    a hint change no match and cost no recompute; a name does."""
    cat = catalog.load()
    ix = systems._build(cat)
    p = next(x for x in cat["products"] if x["key"] == "panos")
    changed = {**cat, "products": [({**p, "example": "12.1.0", "version_cmd": "show version", "hint": "x"} if x is p else x) for x in cat["products"]]}
    assert systems._build(changed).sig == ix.sig
    named = {**cat, "products": [({**p, "names": [*p.get("names", []), "Strata"]} if x is p else x) for x in cat["products"]]}
    assert systems._build(named).sig["p"]["panos"] != ix.sig["p"]["panos"]


async def test_a_vendor_counts_a_product_the_catalogue_adds_later(admin_client, hooks, monkeypatch):
    src, _ = await _setup(admin_client, systems=[PAN], kinds=["news", "vendor_vuln"])
    cat = catalog.load()
    new = {**catalog.product("expedition"), "key": "pan-sentinel", "label": "Sentinelfire Gateway", "names": ["Sentinelfire Gateway"], "kw": [], "cpes": [], "cna": None}
    later = {**cat, "products": [*cat["products"], new]}
    await _news(src, "Sentinelfire Gateway: Lücke")  # stored before the catalogue knew it: no system
    monkeypatch.setattr(catalog._cache, "data", later)
    monkeypatch.setattr(catalog._cache, "by_key", {p["key"]: p for p in later["products"]})
    async with db.session() as s:
        assert await systems.systems_round(s) is not None  # the first backfill – quiet
        s.add(VendorEvent(key="vuln:pan-sentinel:*:x", kind="vuln", product="pan-sentinel", severity="high", data={"product": "Sentinelfire Gateway", "status": "affected"}))
        await s.commit()
    await _news(src, "Sentinelfire Gateway 2: Lücke")  # after: named, loud
    await _dispatch()
    body = "\n".join(_slack_texts(hooks))
    assert "Sentinelfire Gateway 2: Lücke" in body and "Sentinelfire Gateway: Lücke" not in body  # the older one: quiet
    assert "vendor?product=pan-sentinel" in body  # the event of the new product


async def test_details_that_arrive_later_send_the_story_once(admin_client, hooks):
    src, _ = await _setup(admin_client, systems=[{"product": "panos"}])
    iid = await _news(src, "CVE-2026-1234: Lücke in einer Firewall")
    await _dispatch()
    assert hooks.to("hooks.slack.com") == []
    async with db.session() as s:
        s.add(StoryDetail(item_id=iid, kind="nvd", status="ok", data=_pan_details(), fetched_at=datetime.now(UTC)))
        assert await systems.set_exact(s, iid, systems.exact(_pan_details()), quiet=False) is True  # loud: notify.changed()
        await s.commit()
    await _dispatch()
    assert len(hooks.to("hooks.slack.com")) == 1
    async with db.session() as s:  # fetched again unchanged: nothing new
        assert await systems.set_exact(s, iid, systems.exact(_pan_details()), quiet=True) is False
        await s.commit()
    await _dispatch()
    assert len(hooks.to("hooks.slack.com")) == 1


async def test_enrich_round_marks_new_details_loud_and_the_same_again_quiet(admin_client, monkeypatch):
    src = await _source()
    iid = await _news(src, "CVE-2026-1234: Lücke")
    async with db.session() as s:
        await s.execute(update(NewsItem).where(NewsItem.id == iid).values(cves=["CVE-2026-1234"]))
        await s.commit()
    async def build(db_, item, source, prev, key, budget, cvl=None):  # noqa: ANN001, ANN202
        return _pan_details()

    monkeypatch.setattr(story_details, "build", build)
    from conftest import set_news

    await set_news(enabled=True)
    async with db.session() as s:
        await story_details.enrich_round(s)
        i = await s.get(NewsItem, iid)
        assert {"panos", "panorama"} <= set(i.systems) and i.quiet_systems == []
        # the catalogue learned something meanwhile – the same details again bring it quietly
        await s.execute(update(NewsItem).where(NewsItem.id == iid).values(systems=[]))
        await s.execute(update(StoryDetail).where(StoryDetail.item_id == iid).values(next_try_at=datetime.now(UTC) - timedelta(seconds=1)))
        await s.commit()
        await story_details.enrich_round(s)
        i = await s.get(NewsItem, iid, populate_existing=True)
        assert set(i.quiet_systems) == {"panos", "panorama"}


async def test_a_quiet_recompute_never_sends_an_older_story(admin_client, hooks):
    src, _ = await _setup(admin_client, systems=[{"product": "panos"}])
    iid = await _news(src, "CVE-2026-1234: Lücke in einer Firewall")
    async with db.session() as s:  # details stored before the upgrade: the backfill finds the system
        s.add(StoryDetail(item_id=iid, kind="nvd", status="ok", data=_pan_details(), fetched_at=datetime.now(UTC)))
        await s.commit()
        assert await systems.systems_round(s) == 1
        assert await systems.systems_round(s) is None  # the same catalogue: not even a read
        i = await s.get(NewsItem, iid)
        assert "panos" in i.systems and "panos" in i.quiet_systems
    await _dispatch()
    assert hooks.to("hooks.slack.com") == []


async def test_a_catalogue_change_recomputes_only_the_changed_products_quietly(admin_client, monkeypatch):
    src = await _source()
    a = await _news(src, "Sentinelfire Gateway: Lücke")
    b = await _news(src, "PAN-OS: Lücke")
    async with db.session() as s:
        await systems.systems_round(s)  # the first backfill
    systems.reset()
    cat = catalog.load()
    new = {**catalog.product("expedition"), "key": "pan-sentinel", "label": "Sentinelfire Gateway", "names": [], "kw": [], "cpes": [], "cna": None}
    later = {**cat, "products": [*cat["products"], new]}
    monkeypatch.setattr(catalog._cache, "data", later)
    monkeypatch.setattr(catalog._cache, "by_key", {p["key"]: p for p in later["products"]})
    async with db.session() as s:
        assert await systems.systems_round(s) == 1
        ia, ib = await s.get(NewsItem, a), await s.get(NewsItem, b)
        assert ia.systems == ["m:pan-sentinel"] and ia.quiet_systems == ["m:pan-sentinel"]
        assert "m:panos" in ib.systems and ib.quiet_systems == []  # untouched


async def test_store_names_the_systems_and_an_update_names_them_loudly(admin_client):
    src = await _source()
    now = datetime.now(UTC)
    entry = {"link": "https://news.example.org/a", "title": "Neue Lücke in einer Firewall", "summary": "", "content": "", "date": now - timedelta(hours=1)}
    async with db.session() as s:
        await news.store(s, await s.get(NewsSource, src.id), [entry])
    async with db.session() as s:
        i = await s.scalar(select(NewsItem))
        assert i.systems == [] and i.quiet_systems == []
    async with db.session() as s:
        await news.store(s, await s.get(NewsSource, src.id), [{**entry, "title": "[UPDATE] Neue Lücke in PAN-OS"}])
    async with db.session() as s:
        i = await s.scalar(select(NewsItem))
        assert "m:panos" in i.systems and "m:panos" not in i.quiet_systems


# ---------------------------------------------------------------- widening


async def test_widening_by_a_system_or_word_and_by_an_exclusion_less(admin_client, hooks):
    src, r = await _setup(admin_client, systems=[{"product": "panos"}], exclude=["webinar"])
    await _news(src, "FortiOS: Lücke vor der Änderung")
    await _news(src, "PAN-OS Webinar vor der Änderung")
    rr = (await admin_client.get("/api/admin/notify/rules")).json()[0]
    body = {k: rr[k] for k in ("name", "channels", "severities", "sources", "topics", "lang", "kinds", "teams", "systems", "keywords", "exclude")}
    # wider: another system and no exclusion – what arrived before comes only when it matched the old filter as well
    up = await admin_client.put(f"/api/admin/notify/rules/{r['id']}", json={**body, "systems": [*body["systems"], {"product": "fortios"}], "exclude": [], "version": rr["version"]})
    assert up.status_code == 200
    async with db.session() as s:
        earlier = (await s.get(NotifyRule, uuid.UUID(r["id"]))).earlier
    assert earlier[-1]["systems"] == ["p:panos"] and earlier[-1]["exclude"] == ["webinar"]
    await _news(src, "FortiOS: Lücke nach der Änderung")
    await _news(src, "PAN-OS Webinar nach der Änderung")
    await _dispatch()
    assert await _sent_titles(hooks) == ["FortiOS: Lücke nach der Änderung", "PAN-OS Webinar nach der Änderung"]


def test_widens_and_merges_with_the_new_fields():
    base = {"severities": None, "sources": None, "topics": None, "kinds": ["news"], "teams": None}
    old = {**base}  # a filter of before 0.1.53: no "Betrifft", no exclusions
    assert not notify.widens(old, {**base, "systems": ["p:panos"], "keywords": None, "exclude": ["webinar"]})
    sys_ = {**base, "systems": ["p:panos"], "keywords": None, "exclude": None}
    assert notify.widens(sys_, {**sys_, "systems": ["p:fortios", "p:panos"]})
    assert notify.widens(sys_, {**sys_, "keywords": ["citrix"]})
    assert notify.widens(sys_, {**sys_, "systems": None})  # no restriction any more
    assert not notify.widens(sys_, {**sys_, "exclude": ["webinar"]})  # an exclusion more narrows
    assert notify.widens({**sys_, "exclude": ["webinar"]}, sys_)
    rule = NotifyRule(earlier=[], active_since=datetime.now(UTC) - timedelta(days=1))
    at = datetime.now(UTC)
    for n, f in enumerate([{**sys_, "exclude": ["a"]}, {**base, "systems": None, "keywords": ["citrix"], "exclude": ["b"]}] + [base] * 9):
        notify.widened(rule, f, n, at + timedelta(seconds=n))
    first = rule.earlier[0]  # the two oldest made one: stricter than both
    # news: PAN-OS or "citrix" of both – nothing; Vendor News: PAN-OS (the second never limited the events)
    assert first["concern"] == [[], []] and first["systems"] == ["p:panos"] and first["exclude"] == ["a", "b"]
    from sqlalchemy.dialects import postgresql

    for clause in [*notify._earlier_news(rule), *notify._earlier_vendor(rule)]:
        str(clause.compile(dialect=postgresql.dialect()))  # every filter of before makes valid SQL


# ---------------------------------------------------------------- dry run, API, audit, the source named


async def test_the_dry_run_covers_systems_and_topics_gained_quietly(admin_client):
    """Right after the upgrade the background job gives every stored story its systems – quietly. The dry run says what
    the rule covers: those count (a "Palo Alto + Kritisch" preview used to show nothing for 30 days); the live round
    still sends on loud ones only."""
    src = await _source()
    iid = await _news(src, "Palo Alto Networks PAN-OS: kritische Lücke", "CVSS 9.8")
    other = await _news(src, "Ransomware gang strikes again")
    async with db.session() as s:
        await s.execute(update(NewsItem).values(systems=[], quiet_systems=[]))  # as before the upgrade
        await s.commit()
        assert await systems.recompute(s) == 1
        i = await s.get(NewsItem, iid)
        assert "v:paloaltonetworks" in i.systems and set(i.quiet_systems) == set(i.systems)
        await s.execute(update(NewsItem).where(NewsItem.id == other).values(topics=["ransomware"], quiet_topics=["ransomware"]))
        await s.commit()
    body = {"severities": ["critical"], "kinds": ["news"], "systems": [PAN], "days": 7}
    dry = (await admin_client.post("/api/admin/notify/rules/dry-run", json=body)).json()
    assert dry["count"] == 1 and [x["title"] for x in dry["items"]] == ["Palo Alto Networks PAN-OS: kritische Lücke"]
    assert dry["items"][0]["hits"]  # what it matched by is named all the same
    notify_api._dry_at.clear()  # one dry run a second per admin – the test asks faster
    dry = (await admin_client.post("/api/admin/notify/rules/dry-run", json={"severities": [], "kinds": ["news"], "topics": ["ransomware"], "days": 7})).json()
    assert dry["count"] == 1
    async with db.session() as s:  # the live round: never
        rule = NotifyRule(name="r", severities=["critical"], sources=[], kinds=["news"], systems=[PAN], active_since=datetime.now(UTC) - timedelta(days=1))
        assert await notify.pending(s, rule, uuid.uuid4(), rule.active_since) == []


async def test_dry_run_agrees_with_the_live_round(admin_client, hooks):
    src, _ = await _setup(admin_client, systems=[PAN], keywords=["Citrix Bleed"], exclude=["webinar"], severities=["critical", "high"])
    await _news(src, "PAN-OS: Lücke")
    await _news(src, "Citrix Bleed 3")
    await _news(src, "PAN-OS: Webinar")
    await _news(src, "PAN-OS: Info", severity="info")
    await _news(src, "Ohne Bezug")
    await _news(src, "CVE-2026-1: Lücke", details=_pan_details())
    body = {"severities": ["critical", "high"], "kinds": ["news"], "systems": [PAN], "keywords": ["Citrix Bleed"], "exclude": ["webinar"], "days": 1}
    dry = (await admin_client.post("/api/admin/notify/rules/dry-run", json=body)).json()
    await _dispatch()
    assert sorted(x["title"] for x in dry["items"]) == await _sent_titles(hooks) and dry["count"] == 3
    by = {x["title"]: x for x in dry["items"]}
    assert by["PAN-OS: Lücke"]["hits"] == ["PAN-OS"] and by["Citrix Bleed 3"]["hits"] == ["Citrix Bleed"] and set(by["CVE-2026-1: Lücke"]["hits"]) == {"PAN-OS", "Panorama"}
    assert by["PAN-OS: Lücke"]["match"]["concern"] is True


async def test_api_checks_and_limits(admin_client):
    ch = await _channel(admin_client, name="SOC", type="slack", url=SLACK)
    ok = await _rule(admin_client, "Palo", [ch["id"]], systems=[PAN, {"product": "panos"}, PAN], keywords=["Bleed", "bleed"], exclude=["Webinar"])
    assert ok["systems"] == [PAN, {"product": "panos"}] and ok["keywords"] == ["Bleed"] and ok["exclude"] == ["Webinar"]
    base = {"name": "X rule", "channels": [ch["id"]]}
    for extra in (
        {"keywords": [f"w{n}" for n in range(31)]},
        {"keywords": ["x"]},
        {"exclude": ["<b>"]},
        {"systems": [{"vendor": "Palo Alto Networks", "product": "panos"}]},
        {"systems": [{}]},
        {"systems": [{"product": "No Such"}]},
        {"systems": [{"product": "no-such-product"}]},
        {"systems": [{"vendor": "Nobody Inc"}]},
        {"systems": [{"product": "panos"}] * 51},
    ):
        r = await admin_client.post("/api/admin/notify/rules", json={**base, **extra})
        assert r.status_code == 422, extra
    # an older client (no new fields): the rule keeps what it has
    up = await admin_client.put(f"/api/admin/notify/rules/{ok['id']}", json={"name": "Palo", "channels": [ch["id"]], "version": ok["version"]})
    assert up.json()["systems"] == ok["systems"] and up.json()["keywords"] == ["Bleed"]


async def test_the_audit_log_names_systems_not_keys(admin_client):
    ch = await _channel(admin_client, name="SOC", type="slack", url=SLACK)
    r = await _rule(admin_client, "Palo", [ch["id"]], systems=[{"product": "panos"}])
    up = await admin_client.put(f"/api/admin/notify/rules/{r['id']}", json={"name": "Palo", "channels": [ch["id"]], "systems": [PAN], "keywords": ["Bleed"], "version": r["version"]})
    assert up.status_code == 200
    async with db.session() as s:
        e = await s.scalar(select(AuditEntry).where(AuditEntry.action == "rule.changed"))
    blob = json.dumps(e.details, ensure_ascii=False)
    assert "PAN-OS (Firewalls)" in blob and "Palo Alto Networks (alle Produkte)" in blob and "Bleed" in blob and '"panos"' not in blob


async def test_a_story_a_rule_brought_for_a_further_source_names_that_source(admin_client, hooks):
    a = await _source()  # "Example Feed": the story's own source
    async with db.session() as s:
        b = NewsSource(key="feed-b", name="Bravo Feed", url="https://news.example.org/b.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(b)
        await s.commit()
    ch = await _channel(admin_client, name="SOC", type="slack", url=SLACK)
    await _rule(admin_client, "Bravo", [ch["id"]], severities=[], sources=[str(b.id)], lang="de")
    iid = await _news(a, "Lücke, auch bei Bravo")
    async with db.session() as s:
        # carried while fresh (news._carried_by) – a carry that is not fresh counts for no rule (the failure of the
        # release run: this line without fresh, before the carries were marked)
        s.add(NewsItemSource(item_id=iid, source_id=b.id, fresh=True, carried_at=datetime.now(UTC)))
        await s.commit()
    r = await admin_client.post("/api/admin/notify/rules/dry-run", json={"kinds": ["news"], "sources": [str(b.id)], "days": 1})
    assert r.status_code == 200, r.text
    dry = r.json()
    assert dry["count"] == 1, dry
    assert dry["items"][0]["source"] == "Bravo Feed (auch Example Feed)"
    await _dispatch()
    assert "Bravo Feed (auch Example Feed)" in "\n".join(_slack_texts(hooks))


async def test_mail_and_webhook_say_what_matched():
    st = notify.Story("00000000-0000-4000-8000-000000000002", "PAN-OS: Lücke", "Text", "https://x.example/", "critical", "Feed", datetime.now(UTC), hits=["PAN-OS", "Palo <b>Alto</b>"])
    subject, text_, html = notify.render_mail("Palo", [st], 1, "de")
    assert "Treffer: PAN-OS, Palo <b>Alto</b>" in text_ and "Treffer: PAN-OS, Palo &lt;b&gt;Alto&lt;/b&gt;" in html
    assert ("Match", "PAN-OS, Palo <b>Alto</b>") in notify.card_fields(st, "en")
    assert notify.render_webhook("SOC", ["Palo"], [st], 1, "en")["stories"][0]["match"] == ["PAN-OS", "Palo <b>Alto</b>"]
    assert re.search(r"Treffer", json.dumps(notify.render_slack("Palo", [st], 1, "de"), ensure_ascii=False))


async def test_migration_0039_down_and_up(admin_client):
    from alembic import command
    from sqlalchemy import inspect

    ch = await _channel(admin_client, name="SOC", type="slack", url=SLACK)
    await _rule(admin_client, "Palo", [ch["id"]], systems=[PAN])

    def cols(conn, table):  # noqa: ANN001, ANN202
        return {c["name"] for c in inspect(conn).get_columns(table)}

    def down(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "0038")
        return cols(conn, "notify_rules"), cols(conn, "news_items")

    def up(conn):  # noqa: ANN001, ANN202
        command.upgrade(db.alembic_config(conn), "head")
        return cols(conn, "notify_rules"), cols(conn, "news_items")

    async with db.engine().begin() as conn:
        rules, items = await conn.run_sync(down)
    assert not {"systems", "keywords", "exclude"} & rules and not {"systems", "quiet_systems"} & items
    async with db.engine().begin() as conn:
        rules, items = await conn.run_sync(up)
    assert {"systems", "keywords", "exclude"} <= rules and {"systems", "quiet_systems"} <= items
    async with db.engine().connect() as conn:
        assert await conn.scalar(text("SELECT systems FROM notify_rules")) == []  # a rule from before: no restriction
