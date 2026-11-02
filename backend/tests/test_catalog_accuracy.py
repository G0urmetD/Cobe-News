"""Katalog-Genauigkeit (0.1.44): the version an admin sees is what is compared – build tables, product rules,
plausibility, the stricter parser – and the matching reads the vendors' records as they are meant. Every fix has a
parser/check test here and a verdict on a realistic record (tests/fixtures/vendor/accuracy_records.json: trimmed CVE
records of the CNAs, NVD configurations in NVD's form); the verdict each case had before is in the case's comment of
the report, the one it must have now is in the file."""

import json
import re
from pathlib import Path

import pytest

from app import build_maps, catalog_data, version_input
from app import vendor_catalog as catalog
from app.catalog_data import CatalogError
from app.vendor_match import bound_v, evaluate, upto
from app.vendor_versions import parse, strict_problem, validate

FIX = Path(__file__).parent / "fixtures" / "vendor" / "accuracy_records.json"


@pytest.fixture(scope="module")
def cat():
    return {p["key"]: p for p in catalog.load()["products"]}


def check(cat, key, text):
    return version_input.check(cat[key], text)


# ---------------------------------------------------------------- the verdicts on realistic records

_F = json.loads(FIX.read_text())


@pytest.mark.parametrize("case", _F["cases"], ids=[c["case"] for c in _F["cases"]])
def test_verdict_on_real_record(cat, case):
    r = evaluate(cat[case["product"]], case["source"], _F["records"][case["record"]], case["version"])
    assert r is not None and r.status == case["after"], (case, r)


# ---------------------------------------------------------------- the generic parser


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("131.0.2903.86 x64", (131, 0, 2903, 86)),  # x64 was read as one part more (the tokenizer split it)
        ("24.7.12_4-amd64", (24, 7, 12, 4)),
        ("1.2.3 (X64)", (1, 2, 3)),
        ("2.3.0p34.cee", (2, 3, 0, 34)),  # Checkmk editions
        ("23.2R2-S1-EVO", (23, 2, 2, 1)),  # Junos OS Evolved
        ("10.2.1.15-81sv", (10, 2, 1, 15, 81)),  # SonicWall SMA
        ("2402 LTSR CU1", (2402, 1)),  # Citrix
        ("14.1-29.72.nc", (14, 1, 29, 72)),
    ],
)
def test_generic_trailing_words(text, key):
    assert parse("generic", text).key == key
    assert validate("generic", text)[0]


def test_strict_input_words_of_their_own():
    """parse() stays lenient for advisory data; what an admin types must not have a word of its own before a number
    that is no separator – the model number would become the first part ("iLO 6 v1.62" → 6.1.62)."""
    for bad in ("iLO 6 v1.62", "MX 18.211.5", "Exchange 2019 CU15", "QTS 5.2.3.3006"):
        assert strict_problem(bad) and validate("generic", bad) == (False, bad, "format"), bad
        assert parse("generic", bad) is not None  # stored ones are still read (compatibility, app/version_input.py)
    for ok in ("8.0 Update 3", "6.4 build 6402", "22.4R3-S5", "R81.20 Take 99", "1.37-eks-4", "pc.7.6.0.8", "Version 15.2", "v7.4.3", "10.80 RU5", "4.0 SP1"):
        assert not strict_problem(ok), ok
    assert validate("generic", "131.0.2903.86 x64") == (True, "131.0.2903.86", "")


def test_java_forms_are_one_version():
    """1.8.0_411, 8u411, "Java 8 Update 411" and NVD's jre:1.8.0:update411 were (1,8,0,411), (8,411), (8,411) and
    (1,8,0,411) – now all (8, 0, 411), the same form as 11.0.23."""
    forms = ["1.8.0_411", "8u411", "Java 8 Update 411", "1.8.0 update411", "1.8.0_411-b09", "8u411b33", "Oracle Java SE:8u411"]
    assert {parse("java", f).key for f in forms} == {(8, 0, 411)}
    assert validate("java", "1.8.0_411") == (True, "8u411", "")
    assert parse("java", "8u411") < parse("java", "8u441") < parse("java", "11.0.23") < parse("java", "21.0.5+11")
    assert parse("java", "21.0.5+11").key == (21, 0, 5)
    assert parse("java", "1.4.2_42").key == (4, 2, 42)
    from app.vendor_versions import from_cpe

    assert from_cpe("java", "1.8.0", "update411")[0].key == (8, 0, 411)
    assert from_cpe("java", "1.8.0", "update_411")[0].key == (8, 0, 411)


def test_sfos_scheme():
    """Sophos: MR n is the third part, the build the fourth – "21.0.1 MR-1-Build272" was (21,0,1,1,272) and the CNA's
    "21.0 MR1 (21.0.1)" (21,0,1,21,0,1)."""
    assert parse("sfos", "SFOS 21.0.1 MR-1-Build272").key == (21, 0, 1, 272) == parse("sfos", "21.0.1.272").key
    assert parse("sfos", "21.0 MR1").key == parse("sfos", "21.0 MR1 (21.0.1)").key == (21, 0, 1)
    assert parse("sfos", "21.0.0 GA-Build169").key == (21, 0, 0, 169)
    assert parse("sfos", "21.0.2 MR-1") is None and parse("sfos", "21.0 MR1 (21.0.2)") is None
    assert validate("sfos", "SFOS 21.0.1 MR-1-Build272") == (True, "21.0.1.272", "")


def test_sap_scheme():
    """SAP's records name component releases: "S4CORE 102", "103", "SAP_BASIS 758"; NetWeaver 7.58 is SAP_BASIS 758.
    The generic rule read "S4CORE 108" as (4, 108) – the 4 of S4CORE – and "2023" as a version."""
    assert parse("sap", "S4CORE 108").key == parse("sap", "108").key == (108,)
    assert parse("sap", "SAP_BASIS 758").key == parse("sap", "7.58").key == (758,)
    assert parse("sap", "7.5").key == (750,)
    assert parse("sap", "S4CORE 108 SP02").key == (108, 2)
    assert parse("sap", "2023") is None


def test_cisco_classic_ios_and_ftd():
    assert parse("cisco", "15.9(3)M9") < parse("cisco", "15.9(3)M10")
    assert parse("cisco", "15.9(3)M9") == parse("cisco", "15.9(3)m9")  # NVD writes the train in lower case
    assert parse("cisco", "12.2(55)SE12") is not None
    assert parse("cisco", "7.0(3)I7(9)") is None  # still not read as 7.0.3.7.9
    assert parse("cisco", "7.2.5 (build 208)") == parse("cisco", "7.2.5")
    assert parse("cisco", "9.18(4)22").key == (9, 18, 4, 22)  # ASA unchanged


def test_windows_os_build_and_fortios_display_forms():
    assert parse("windows", "OS Build 26100.2605").text == "10.0.26100.2605"
    assert parse("windows", "Version 24H2 (OS Build 26100.2605)").text == "10.0.26100.2605"
    for t in ("v7.4.3 build2573 (GA.F)", "FortiGate-60F v7.4.3,build2573,240201 (GA.F)", "7.4.3"):
        assert validate("fortios", t) == (True, "7.4.3", ""), t
    assert parse("fortios", "7.4.2.1737").key == (7, 4, 2)  # FortiClient: the fourth part is the build


def test_bounds_with_alternatives_and_lines():
    """"21.0 MR1 (21.0.1)": the plain version in brackets; "7.2.5 (build 208)" / "6.2.8-h2 (6.2.8-c243)": the one in
    front. An inclusive bound shorter than the version covers its line ("≤ 21.0.0" includes 21.0.0.169, "≤ 128.*")."""
    assert bound_v("generic", "21.0 MR1 (21.0.1)").key == (21, 0, 1)
    assert bound_v("generic", "7.2.5 (build 208)").key == (7, 2, 5)
    assert bound_v("generic", "6.2.8-h2 (6.2.8-c243)").key == (6, 2, 8, 2)
    v = parse("generic", "21.0.0.169")
    assert upto(v, parse("generic", "21.0.0"), True) and not upto(v, parse("generic", "21.0.0"), False)
    assert upto(parse("generic", "128.10.1"), parse("generic", "128"), True)
    assert not upto(parse("generic", "129.0"), parse("generic", "128"), True)
    assert upto(parse("generic", "2.426.3"), parse("generic", "2.426"), False, line=True)


# ---------------------------------------------------------------- the product rules (app/version_input.py)


@pytest.mark.parametrize(
    ("key", "text", "stored"),
    [
        ("msexchange", "2019 CU15 Apr25HU", "15.2.1748.24"),
        ("msexchange", "Exchange Server 2019 CU15 Apr25HU", "15.2.1748.24"),
        ("msexchange", "Microsoft Exchange Server 2019 Cumulative Update 15", "15.2.1748"),
        ("msexchange", "2019 CU15", "15.2.1748"),  # the line: every build of CU15
        ("msexchange", "SE RTM Oct26SU", "15.2.2562.56"),
        ("msexchange", "Subscription Edition RTM", "15.2.2562"),
        ("msexchange", "15.02.1748.037", "15.02.1748.037"),
        ("mssqlserver", "2022 CU16", "16.0.4165.4"),
        ("mssqlserver", "SQL Server 2022 CU16", "16.0.4165.4"),
        ("mssqlserver", "KB5059390", "16.0.4205.1"),
        ("mssqlserver", "Microsoft SQL Server 2022 (RTM-CU20) (KB5059390) - 16.0.4205.1 (X64) Jul 1 2025 Copyright", "16.0.4205.1"),
        ("vmware-tools", "12416", "12.4.0"),
        ("vmware-tools", "12.4.0", "12.4.0"),
        ("pangp", "6.2.8-c948", "6.2.8-h10"),
        ("pangp", "6.2.8-431", "6.2.8-h6"),
        ("pangp", "6.2.8-h6", "6.2.8-h6"),
        ("hpe-ilo", "iLO 6 v1.62", "1.62"),
        ("hpe-ilo", "HPE iLO 6 1.62", "1.62"),
        ("adobe-acrobat", "2024.005.20320", "24.005.20320"),
        ("office", "Version 2411 (Build 18227.20162 Click-to-Run)", "16.0.18227.20162"),
        ("cisco-ise", "3.2.0.542 Patch 5", "3.2 Patch 5"),
        ("cisco-ise", "3.2.0.542", "3.2.0"),
        ("netscaler-adc", "NS14.1: Build 29.72.nc", "14.1-29.72"),
        ("netscaler-gateway", "NetScaler NS13.1: Build 49.15.nc", "13.1-49.15"),
        ("checkpoint-gaia", "R81.20 JHF Take 99", "R81.20 Take 99"),
        ("checkpoint-gaia", "R81.20 - Build 012", "R81.20"),
        ("nginx-plus", "nginx/1.27.2 (nginx-plus-r33)", "R33"),
        ("nginx-plus", "nginx-plus-r33-p1", "R33 P1"),
        ("sophos-firewall", "SFOS 21.0.1 MR-1-Build272", "21.0.1.272"),
        ("oracle-jdk", "Java 8 Update 411", "8u411"),
        ("sap-s4hana", "S4CORE 108", "S4CORE 108"),
        ("sap-netweaver-abap", "7.58", "7.58"),
        ("cisco-meraki", "MX 18.211.5", "18.211.5"),
        ("windows", "OS Build 26100.2605", "10.0.26100.2605"),
        ("vcenter", "8.0.3.00400", "8.0 U3d"),  # VMware's table, now one kind of the generic build tables
    ],
)
def test_typed_forms_are_stored_as_compared(cat, key, text, stored):
    c = check(cat, key, text)
    assert c.ok and c.value == stored, c
    assert version_input.effective(cat[key], text) == stored


@pytest.mark.parametrize(
    ("key", "text", "reason"),
    [
        ("msexchange", "2019 CU12 Foo24SU", "unknown_name"),  # a name the table does not know – never guessed
        ("msexchange", "Version 15.2 (Build 1748.10)", "unknown_name"),  # AdminDisplayVersion hides the SU
        ("msexchange", "2019", "unknown_name"),
        ("mssqlserver", "2022 GDR", "unknown_name"),  # Microsoft gives that name to several builds
        ("mssqlserver", "2022 CU99", "unknown_name"),
        ("vmware-tools", "12999", "unknown_name"),
        ("pangp", "6.3.3-c1199", "unknown_name"),  # only 6.2.8's builds are in the release notes
        ("dotnet", "8.0.403", "pattern"),  # the SDK, not the runtime
        ("office", "2411", "pattern"),
        ("sap-s4hana", "2023", "format"),
        ("pfsense", "24.11", "other_product"),
        ("pfsense-plus", "2.8.0", "other_product"),
        ("firefox", "128.5.1esr", "other_product"),
        ("jenkins", "2.499", "other_product"),
        ("jenkins-weekly", "2.492.2", "other_product"),
        ("nginx", "R33", "other_product"),
        ("nginx-plus", "1.27.2", "other_product"),
    ],
)
def test_refused_forms(cat, key, text, reason):
    c = check(cat, key, text)
    assert not c.ok and c.reason == reason, c
    if reason == "other_product":
        assert c.to in cat
    if reason in ("unknown_name", "pattern"):
        assert c.hint in catalog.DATA.texts["hints"] or c.hint is None


def test_plausibility_against_release_lines(cat):
    """A major far beyond every release line of the product is refused (a year, a marketing number, a code)."""
    nginx = cat["nginx"]  # endoflife.date: 1.x
    c = version_input.check(nginx, "2024.1")
    assert not c.ok and c.reason == "implausible" and c.lines
    assert version_input.check(nginx, "1.29.0").ok  # a newer line than the data knows is fine
    assert version_input.check(nginx, "0.8.55").ok  # an older one too
    firefox = cat["firefox"]
    assert version_input.check(firefox, "190.0").ok  # 1.5 × 159 and more – a year of new majors is room enough
    assert version_input.check(firefox, "2411").reason == "implausible"
    # products without release lines are never refused for it
    assert version_input.check({"key": "x", "scheme": "generic"}, "2411").ok


def test_stored_versions_still_evaluate(cat):
    """A version stored before 0.1.44 whose form the strict check refuses now ("format") is compared as it was read
    then (after the product's name is dropped); one a rule refuses (other product, unknown build) is not compared –
    "möglicherweise betroffen" – but never dropped. Typical stored forms of the review stay comparable."""
    for key, text in [
        ("qnap-qts", "QTS 5.2.3.3006 build 20250108"),  # QTS is the product's name
        ("synology-dsm", "7.2.1-69057 Update 5"),
        ("lancom-lcos", "10.80 RU5"),
        ("citrix-vad", "2402 LTSR CU1"),
        ("checkmk", "2.3.0p34.cee"),
        ("junos-evolved", "23.2R2-S1-EVO"),
        ("sonicwall-sma", "10.2.1.15-81sv"),
        ("opnsense", "24.7.12_4-amd64"),
        ("skype-business-server", "2019 CU8"),
    ]:
        assert version_input.effective(cat[key], text) is not None, (key, text)
    # refused by a rule: not compared
    assert version_input.effective(cat["pfsense"], "24.11") is None
    # refused by the strict check only: compared as read before – and shown "bitte prüfen"
    odd = {"key": "odd", "label": "Odd", "vendor": "X", "scheme": "generic"}
    assert not version_input.check(odd, "Foo 6 v1.2").ok
    assert version_input.effective(odd, "Foo 6 v1.2") == "Foo 6 v1.2"


# ---------------------------------------------------------------- the build tables (catalog/build_maps)


def test_build_tables_loaded_with_their_sources():
    maps = catalog.DATA.build_maps
    assert set(maps) >= {"vmware", "exchange", "sqlserver", "vmware_tools", "globalprotect"}
    for name, m in maps.items():
        assert m["fetched"] == "2026-11-02" and m["sources"], name
        text = (catalog_data.DIR / "build_maps" / f"{name}.yaml").read_text()
        assert "fetched 2026-11-02" in text, name  # the header names source and date
    assert build_maps.lookup("msexchange", "2019 CU15 Apr25HU") == ("15.2.1748.24", "")
    assert build_maps.lookup("vcenter", "8.0.3.00400") == ("8.0 U3d", "")  # VMware through the same entry
    assert build_maps.lookup("panos", "2019 CU15") == (None, "")
    assert build_maps.name_key("Exchange Server 2019 Cumulative Update 15 Apr25HU", ("exchange", "server")) == "2019 cu15 apr25hu"


def test_every_table_row_is_a_version_of_its_product(cat):
    for m in catalog.DATA.build_maps.values():
        if m["kind"] != "names":
            continue
        for key in m["products"]:
            p = cat[key]
            for r in m["rows"]:
                assert parse(p.get("scheme") or "generic", r["value"]) is not None, (key, r)
                for n in r["names"]:
                    assert build_maps.lookup_names(key, n) == (r["value"], ""), (key, n)


def test_broken_build_table_is_refused(tmp_path):
    import shutil

    d = tmp_path / "catalog"
    shutil.copytree(catalog_data.DIR, d)
    path = d / "build_maps" / "exchange.yaml"
    text = path.read_text()
    for old, new, message in [
        ('{value: "15.2.1748.24", names: ["2019 CU15 Apr25HU"]', '{value: "15.2.1748.24", names: ["2019 CU15 May25HU"]', "already stands for"),
        ('{value: "15.2.1748.24",', '{value: "fifteen",', "no version of 'msexchange'"),
        ("products: [msexchange]", "products: [no-such-product]", "not in the catalogue"),
        ("hint: exchange_names", "hint: no_such_text", "has no text in texts.yaml"),
        ("kind: names", "kind: other", "kind must be one of"),
        ('sources:\n  - "https', 'sources: []\n  # - "https', "sources"),
    ]:
        assert old in text, old
        path.write_text(text.replace(old, new, 1))
        with pytest.raises(CatalogError, match=re.escape(message)):
            catalog_data.load(d)
    path.write_text(text)
    assert catalog_data.load(d).build_maps["exchange"]["rows"]


# ---------------------------------------------------------------- the catalogue itself (CI)


def test_every_example_is_taken_by_its_product(cat):
    """Every example the form shows is a version the product takes (the review found four that were not)."""
    bad = [(k, p["example"], version_input.check(p, p["example"]).reason) for k, p in cat.items() if p.get("example") and not version_input.check(p, p["example"]).ok]
    assert not bad, bad


def test_every_product_with_a_scheme_has_an_example():
    """A product the catalogue gives its own version scheme shows how a version of it is written."""
    missing = [o["key"] for o in catalog.OVERLAY if o.get("label") and o.get("scheme") not in (None, "generic", "cloud", "distro") and not o.get("example")]
    assert not missing, missing


def test_product_rules_are_checked_at_load(tmp_path):
    import shutil

    d = tmp_path / "catalog"
    shutil.copytree(catalog_data.DIR, d)
    path = d / "products" / "firewall.yaml"
    text = path.read_text()
    for old, new, message in [
        ("to: pfsense-plus}", "to: pfsense-pluss}", "no other product of the catalogue"),
        ("belongs: [{pattern: '^", "belongs: [{pattern: '(^", "no regular expression"),
        ("  scheme: sfos", "  scheme: sfos\n  pattern_hint: no_such_hint", "has no text in texts.yaml"),
    ]:
        assert old in text, old
        path.write_text(text.replace(old, new, 1))
        with pytest.raises(CatalogError, match=re.escape(message)):
            catalog_data.load(d)
    path.write_text(text)


def test_split_products(cat):
    """pfSense CE / Plus, Firefox / Firefox ESR, Jenkins LTS / weekly, NGINX open source / Plus: one product per axis."""
    assert cat["pfsense"]["cpes"] == ["a:pfsense:pfsense"] and cat["pfsense-plus"]["cpes"] == ["a:netgate:pfsense_plus"]
    assert "a:f5:nginx_plus" not in cat["nginx"]["cpes"] and cat["nginx-plus"]["cpes"] == ["a:f5:nginx_plus"]
    assert cat["firefox-esr"]["eol"] == "firefox" and cat["jenkins-weekly"]["eol"] == "jenkins"
    assert cat["jenkins"]["label"] == "Jenkins LTS" and cat["jenkins"]["osv"]


def test_microsoft_roles_keep_their_own_cpes(cat):
    from app.vendor_match import product_cpes

    v = parse("windows", "10.0.25398.1611")
    assert product_cpes(cat["azure-local"], v) == {"o:microsoft:windows_server_2022_23h2", "a:microsoft:azure_stack_hci"}
    assert product_cpes(cat["windows-server"], parse("windows", "10.0.20348.2762")) == {"o:microsoft:windows_server_2022"}


# ---------------------------------------------------------------- the API


async def test_validate_endpoint_explains(reader_client):
    r = await reader_client.get("/api/vendor/validate", params={"product": "msexchange", "version": "2019 CU15 Apr25HU"})
    assert r.json()["ok"] and r.json()["mapped"] and r.json()["normalized"] == "15.2.1748.24"
    r = await reader_client.get("/api/vendor/validate", params={"product": "pfsense", "version": "24.11"})
    body = r.json()
    assert not body["ok"] and body["reason"] == "other_product" and body["to"] == "pfsense-plus" and body["to_label"] == "pfSense Plus"
    r = await reader_client.get("/api/vendor/validate", params={"product": "msexchange", "version": "Version 15.2 (Build 1748.10)"})
    body = r.json()
    assert body["reason"] == "unknown_name" and "ExSetup" in body["hint"]["de"] and "ExSetup" in body["hint"]["en"]


async def test_stored_version_compared_as_meant_and_flagged(admin_client):
    """A version stored before the rules ("2019 CU15" for Exchange) is compared as the line 15.2.1748 and the card says
    so; one a rule refuses now ("24.11" under pfSense CE) is "bitte prüfen" with its reason – kept, not dropped."""
    import uuid
    from datetime import UTC, datetime

    from app import db
    from app.models import VendorFollow, VendorVersion

    now = datetime.now(UTC)
    async with db.session() as s:
        for key, text in (("msexchange", "2019 CU15"), ("pfsense", "24.11")):
            f = VendorFollow(product=key, enabled=True, created_at=now, updated_at=now)
            s.add(f)
            await s.flush()
            s.add(VendorVersion(id=uuid.uuid4(), follow_id=f.id, version=text, label="", created_at=now, updated_at=now, confirmed_at=now))
        await s.commit()
    r = await admin_client.get("/api/vendor/products/msexchange")
    assert r.status_code == 200, r.text
    (ex,) = r.json()["versions"]
    assert ex["valid"] and ex["version"] == "2019 CU15" and ex["effective"] == "15.2.1748"
    r = await admin_client.get("/api/vendor/products/pfsense")
    (pf,) = r.json()["versions"]
    assert not pf["valid"] and pf["invalid_reason"] == "other_product" and pf["invalid_to_label"] == "pfSense Plus"
    assert pf["review"]["due"] and pf["review"]["invalid"]  # "bitte prüfen", whatever its age
    # entering it again is refused with the same explanation
    r = await admin_client.post("/api/vendor/follows/pfsense/versions", json={"version": "24.11"})
    assert r.status_code == 422 and r.json()["detail"]["reason"] == "other_product"


def test_release_values_stay_comparable(cat):
    """The compatibility check of 0.1.44: every latest release endoflife.date names – the forms admins copy – is still
    compared under the stricter rules. Left out on purpose: a version of the other half of a split product (Jenkins'
    weekly line under Jenkins LTS and back) and GlobalProtect builds no release notes map to a hotfix – compared as a
    build they decided wrongly ("6.3.3-c1199" is newer than every 6.3.3-hN)."""
    lost = []
    for key, p in cat.items():
        for r in catalog.releases(p.get("eol"))[:40]:
            text = r.get("latest")
            if not text or parse(p.get("scheme") or "generic", text) is None:
                continue
            if version_input.effective(p, text) is None:
                c = version_input.check(p, text)
                if c.reason == "other_product" or (key == "pangp" and c.reason == "unknown_name"):
                    continue
                lost.append((key, text, c.reason))
    assert not lost, lost


def test_the_example_is_on_one_of_the_products_lines():
    """A product without an example of its own shows the latest release of its newest line (endoflife.date) – not the
    generic scheme's 8.3.14, which matches none of the lines the plausibility hint names."""
    from app import vendor_catalog, version_input

    pg = vendor_catalog.product("postgresql")
    assert pg is not None and not pg.get("example")
    ex = version_input.example_for(pg)
    assert ex and ex != "8.3.14"
    majors, _ = version_input.known_majors(pg)
    assert int(ex.split(".")[0]) in majors
    assert version_input.example_for({"scheme": "generic", "example": "1.2"}) == "1.2"
    assert version_input.example_for({"scheme": "generic"}) == "8.3.14"
