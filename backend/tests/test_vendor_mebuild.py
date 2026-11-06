"""Zoho ManageEngine versions by build number (scheme ``build``): "14.6 Build 14600" is build 14600 – compared with
the build numbers of the records ("before 10509", "< 14730", CPE 14.9:14910), with NVD's version-only bounds ("< 14.9",
"≤ 14.7") as the release line. Before, the generic rule read "14.6 Build 14600" as 14.6.14600 and a bound "10509" as
the version 10509: every build was "betroffen, Fix: 10509" and the update target was "10509".

The records are real NVD records (tests/fixtures/vendor/manageengine_records.json, fetched 2026-11-06, stored as
vendor_sources.parse_nvd stores them, trimmed to the ManageEngine CPE matches)."""

import json
import uuid
from pathlib import Path

import pytest

from app import vendor, version_input
from app import vendor_catalog as catalog
from app.models import VendorAdvisory, VendorVersion
from app.vendor_match import evaluate, text_build_fix
from app.vendor_versions import build_line, from_cpe, parse

REC = json.loads((Path(__file__).parent / "fixtures" / "vendor" / "manageengine_records.json").read_text())["records"]
ME = ("manageengine-servicedesk", "manageengine-adselfservice", "manageengine-pmp", "manageengine-pam360", "manageengine-opmanager")


@pytest.fixture(scope="module")
def cat():
    return {p["key"]: p for p in catalog.load()["products"]}


# ---------------------------------------------------------------- the scheme


@pytest.mark.parametrize(
    ("text", "key", "shown"),
    [
        ("14.6 Build 14600", (14, 6, 14600), "14.6 Build 14600"),
        ("14.6 build 14600", (14, 6, 14600), "14.6 Build 14600"),
        ("14.6 (Build 14600)", (14, 6, 14600), "14.6 Build 14600"),
        ("Version 14.6, Build 14600", (14, 6, 14600), "14.6 Build 14600"),
        ("Build 14600", (14, 6, 14600), "14.6 Build 14600"),
        ("14600", (14, 6, 14600), "14.6 Build 14600"),
        ("10509", (10, 5, 10509), "10.5 Build 10509"),  # NVD's versionEndExcluding of CVE-2019-15046
        ("9403", (9, 4, 9403), "9.4 Build 9403"),
        ("6.4 build 6402", (6, 4, 6402), "6.4 Build 6402"),
        ("12.8 Build 128329", (12, 8, 128329), "12.8 Build 128329"),  # OpManager: six digits
        ("12.8.329", (12, 8, 128329), "12.8 Build 128329"),  # OpManager's own form ("before 12.3.214")
        ("12.3 build123001", (12, 3, 123001), "12.3 Build 123001"),  # NVD's update field
        ("11.1 build 11101", (11, 1, 11101), "11.1 Build 11101"),
        ("5.0.6", (5, 0, 5006), "5.0 Build 5006"),  # ADSelfService Plus "before 5.0.6"
        ("14.6", (14, 6), "14.6"),  # a line: every build of 14.6
        ("10.0.0", (10, 0), "10.0"),
        ("10", (10,), "10"),  # NVD's start "10" (CVE-2019-15046): the major version, not build 10
    ],
)
def test_build_scheme_reads_the_build(text, key, shown):
    v = parse("build", text)
    assert v is not None and v.key == key and v.text == shown
    assert parse("build", v.text).key == key  # the text a fix or target shows is read back as the same version


def test_build_decides_over_the_version_written_next_to_it():
    # NVD pairs odd versions with builds (adselfservice_plus:5.7:4500) – the build counts
    assert from_cpe("build", "5.7", "4500")[0].key == (4, 5, 4500)
    assert from_cpe("build", "14.9", "14910") == (parse("build", "14910"), False)
    assert from_cpe("build", "14.9", "*") == (parse("build", "14.9"), True)
    assert from_cpe("build", "123222", "*")[0].key == (12, 3, 123222)  # OpManager: the build as the CPE version
    assert build_line(14600) == (14, 6) and build_line(128329) == (12, 8) and build_line(6402) == (6, 4)
    assert parse("build", "14.6 Build 900") is None and parse("build", "abc") is None


def test_catalogue_marks_the_build_products(cat):
    assert {k for k, p in cat.items() if p.get("scheme") == "build"} == set(ME)
    assert cat["manageengine-endpoint-central"].get("scheme") in (None, "generic")  # 11.3.2416.10: dotted, compared as it is
    for k in ME:
        p = cat[k]
        assert version_input.check(p, p["example"]).ok and len(parse("build", p["example"]).key) == 3, k
        assert not vendor.short_version(p, p["example"]) and vendor.short_version(p, "14.6")


def test_typed_versions(cat):
    sdp = cat["manageengine-servicedesk"]
    c = version_input.check(sdp, "ServiceDesk Plus 14.6 Build 14600")
    assert c.ok and c.value == "14.6 Build 14600"
    assert version_input.check(sdp, "14600").value == "14.6 Build 14600"
    assert version_input.effective(sdp, "14.6 Build 14600") == "14.6 Build 14600"  # stored as typed before: read the same
    assert version_input.check(cat["manageengine-opmanager"], "12.8.329").value == "12.8 Build 128329"


# ---------------------------------------------------------------- verdicts on the real records


@pytest.mark.parametrize(
    ("product", "cve", "version", "status", "fixed", "after"),
    [
        # the owner's ServiceDesk Plus 14.6 Build 14600 – 7 × "betroffen" before, 4 now
        ("manageengine-servicedesk", "CVE-2019-15046", "14.6 Build 14600", "not_affected", None, None),  # was: affected, Fix 10509
        ("manageengine-servicedesk", "CVE-2018-5799", "14.6 Build 14600", "not_affected", None, None),  # was: affected, Fix 9403
        ("manageengine-servicedesk", "CVE-2024-50053", "14.6 Build 14600", "affected", "14.9 Build 14920", "14.9 Build 14910"),  # was: Fix 14.9
        ("manageengine-servicedesk", "CVE-2024-41150", "14.6 Build 14600", "affected", None, "14.8 Build 14810"),  # was: bis 14.7
        ("manageengine-servicedesk", "CVE-2024-27314", "14.6 Build 14600", "affected", "14.7 Build 14730", "14.6"),
        ("manageengine-servicedesk", "CVE-2024-38869", "14.6 Build 14600", "affected", None, "14.7"),  # NVD lists SDP ≤ 14.7
        ("manageengine-servicedesk", "CVE-2019-15046", "10.5 Build 10508", "affected", "10.5 Build 10509", None),
        ("manageengine-servicedesk", "CVE-2024-50053", "14.9 Build 14920", "not_affected", None, None),  # was: possible
        ("manageengine-servicedesk", "CVE-2024-27314", "14.7 Build 14730", "not_affected", None, None),
        # "ServiceDesk Plus MSP before 10530" is not ServiceDesk Plus' fix – "before 11306" is
        ("manageengine-servicedesk", "CVE-2021-44077", "10.5 Build 10508", "affected", "11.3 Build 11306", None),
        # a line without build: decided where every build of it is
        ("manageengine-servicedesk", "CVE-2019-15046", "14.6", "not_affected", None, None),
        ("manageengine-servicedesk", "CVE-2024-50053", "14.6", "affected", "14.9 Build 14920", "14.9 Build 14910"),
        ("manageengine-adselfservice", "CVE-2021-40539", "6.1", "possible", None, None),  # 6113 and prior
        ("manageengine-adselfservice", "CVE-2021-40539", "6.1 Build 6113", "affected", None, None),
        ("manageengine-adselfservice", "CVE-2021-40539", "6.1 Build 6114", "not_affected", None, None),
        # the CNA's "< 6402" with defaultStatus affected: a later build is fixed (not "default affected")
        ("manageengine-adselfservice", "CVE-2024-0252", "6.5 Build 6510", "not_affected", None, None),
        ("manageengine-adselfservice", "CVE-2024-0252", "6.1 Build 6114", "affected", "6.4 Build 6402", None),
        ("manageengine-adselfservice", "CVE-2019-12476", "5.0 Build 5005", "affected", "5.0 Build 5006", None),
        ("manageengine-adselfservice", "CVE-2019-12476", "6.4 Build 6402", "not_affected", None, None),
        # Password Manager Pro / PAM360: the fixed build itself was "betroffen, Fix: 13221" before
        ("manageengine-pmp", "CVE-2025-11669", "13.2 Build 13221", "not_affected", None, None),
        ("manageengine-pmp", "CVE-2025-11669", "13.2 Build 13220", "affected", "13.2 Build 13221", None),
        ("manageengine-pam360", "CVE-2025-11669", "8.2 Build 8202", "not_affected", None, None),
        ("manageengine-pam360", "CVE-2025-11669", "8.1 Build 8100", "affected", "8.2 Build 8202", None),
        ("manageengine-pam360", "CVE-2024-27312", "6.6 Build 6601", "affected", "6.6 Build 6602", None),
        # OpManager: six-digit builds, "12.3.214" is build 123214, the CNA's "≤ 128329" (NVD stops at 12.8 Build 128187)
        ("manageengine-opmanager", "CVE-2024-5466", "12.8 Build 128329", "affected", None, "12.8 Build 128329"),  # was: not affected
        ("manageengine-opmanager", "CVE-2024-5466", "12.8.330", "not_affected", None, None),
        ("manageengine-opmanager", "CVE-2021-20078", "12.5.329", "affected", "12.5 Build 125346", None),  # was: not affected
        ("manageengine-opmanager", "CVE-2018-18980", "12.3 Build 123213", "affected", "12.3 Build 123214", None),
        ("manageengine-opmanager", "CVE-2018-18980", "12.3.214", "not_affected", None, None),
    ],
)
def test_verdict_on_real_record(cat, product, cve, version, status, fixed, after):
    r = evaluate(cat[product], "nvd", REC[cve], version)
    assert r is not None and (r.status, r.fixed, r.detail.get("after")) == (status, fixed, after), r


def test_without_the_scheme_the_build_is_not_comparable(cat):
    """0.1.51 read "10509" as a version above 14.6.14600 ("affected, Fix 10509"); the generic rule now says the bound is
    on another scale ("possibly", tests/test_version_scale.py) – the build scheme decides it."""
    generic = {**cat["manageengine-servicedesk"], "scheme": "generic"}
    generic.pop("cna", None)
    r = evaluate(generic, "nvd", REC["CVE-2019-15046"], "14.6 Build 14600")
    assert (r.status, r.reason, r.fixed) == ("possible", "other_scale", None)


def test_fix_from_the_description_names_the_product():
    sdp = {"kw": ["ServiceDesk Plus"], "cna": [["ManageEngine", "ServiceDesk Plus"]]}
    assert text_build_fix(sdp, "ServiceDesk Plus versions below 14920 , ServiceDesk Plus MSP and SupportCentre Plus versions below 14910").text == "14.9 Build 14920"
    assert text_build_fix(sdp, "ServiceDesk Plus MSP before 10530, and SupportCenter Plus before 11014") is None
    assert text_build_fix(sdp, "Zoho ManageEngine ServiceDesk Plus (SDP) before 10.0 build 10012 allows").text == "10.0 Build 10012"
    assert text_build_fix(sdp, "ServiceDesk Plus 10 before 10509 allows").text == "10.5 Build 10509"
    assert text_build_fix(sdp, "ServiceDesk Plus versions 13010 and prior") is None  # the last affected, no fix
    op = {"kw": ["OpManager"]}
    assert text_build_fix(op, "OpManager before 12.3 Build 123196 does not").text == "12.3 Build 123196"
    assert text_build_fix(op, "OpManager before 12.3.214 via").text == "12.3 Build 123214"
    assert text_build_fix(op, "OpManager Plus before 126100") is None


# ---------------------------------------------------------------- the update target


def _adv(cve: str) -> VendorAdvisory:
    return VendorAdvisory(
        id=f"nvd:{cve}", source="nvd", ident=cve, title=cve, summary=REC[cve]["desc"], url="", cves=[cve], cvss=7.5, severity="high", exploited=False,
        published_at=None, updated_at=None, data=REC[cve],
    )


def test_update_target_is_a_build_above_the_installed_one(cat):
    """ServiceDesk Plus 14.6 Build 14600: "Update auf 14.9 Build 14920" – before "Neuere Linie: 10509"."""
    sdp = cat["manageengine-servicedesk"]
    advs = [_adv(c) for c in ("CVE-2019-15046", "CVE-2018-5799", "CVE-2024-50053", "CVE-2024-41150", "CVE-2024-27314", "CVE-2024-38869")]
    v = VendorVersion(id=uuid.uuid4(), follow_id=uuid.uuid4(), version="14.6 Build 14600", label="", count=None)
    groups = vendor.groups_of(advs)
    found = vendor.findings(sdp, advs, [v], {}, set(), groups)
    assert sorted(f["primary"]["ident"] if "primary" in f else f["ident"] for f in found if f["versions"][0]["status"] == "affected") == [
        "CVE-2024-27314",
        "CVE-2024-38869",
        "CVE-2024-41150",
        "CVE-2024-50053",
    ]
    t = vendor.target_versions(sdp, groups, found, [v])[str(v.id)]
    assert (t["kind"], t["to"], t["fixes"], t["open"]) == ("update", "14.9 Build 14920", 4, 0)


def test_manageengine_nvd_records_keep_the_vendors_weight(cat):
    """The NVD names Zoho's CNA only by its UUID: its rows stay the vendor's own word once a record carries its CNA
    (migration 0036) – PAM360 CVE-2024-27312: NVD "< 6.6", Zoho "only 6601": "possibly", not "affected"."""
    data = {**REC["CVE-2024-27312"], "assigner": "0fc0942c-577d-436f-ae8e-945763c79b02"}
    r = evaluate(cat["manageengine-pam360"], "nvd", data, "5.5 Build 5500")
    assert (r.status, r.reason) == ("possible", "vendor_unaffected")


def test_a_version_line_is_never_shown_as_the_fix(cat):
    """NVD's "< 14.9" alone (no build in the CNA's rows or the description): affected – but "Fix 14.9" would name every
    build of 14.9, the affected ones too; no fix shown instead (review 0.1.52, L8)."""
    sdp = cat["manageengine-servicedesk"]
    cpe = sdp["cpes"][0]
    rec = {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": f"cpe:2.3:{cpe}:*:*:*:*:*:*:*:*", "versionEndExcluding": "14.9"}]}]}], "cna": [], "desc": "A flaw in ServiceDesk Plus."}
    r = evaluate(sdp, "nvd", rec, "14.6 Build 14600")
    assert r is not None and (r.status, r.fixed) == ("affected", None), r
    rec["desc"] = "ServiceDesk Plus versions below 14920 allow"
    assert evaluate(sdp, "nvd", rec, "14.6 Build 14600").fixed == "14.9 Build 14920"  # a build named: shown
    # whatever source gave a line as the fix (a CNA's "unaffected 14.9", an OSV "fixed"): the build or nothing
    from app.vendor_match import Verdict, _with_build_fix

    v = parse("build", "14.6 Build 14600")
    line = Verdict("affected", "in_range", "14.9", {"by": "vendor", "after": "14.8"})
    assert _with_build_fix(sdp, {"desc": ""}, line, v).fixed is None
    assert _with_build_fix(sdp, {"desc": ""}, line, v, Verdict("affected", "in_range", "14910", {"by": "nvd"})).fixed == "14.9 Build 14910"
    assert _with_build_fix(sdp, {"desc": ""}, Verdict("affected", "in_range", "14.9 Build 14920", {}), v).fixed == "14.9 Build 14920"


def test_a_bare_line_in_the_cna_rows_names_every_build_of_it(cat):
    """Review 0.1.52: a CNA row {"version": "14.6", "status": "affected"} covers 14.6 Build 14600 – before, the bare line
    counted as below its builds and the install came out "not affected (newer than listed)"."""
    from app.vendor_match import eval_cna

    p = cat["manageengine-servicedesk"]
    rows = [{"affectedData": [{"vendor": "ManageEngine", "product": "ServiceDesk Plus", "versions": [{"version": "14.6", "status": "affected"}]}]}]
    got = eval_cna(p, rows, parse("build", "14.6 Build 14600"))
    assert got is not None and got.status == "affected"
    other = eval_cna(p, rows, parse("build", "14.9 Build 14920"))  # another line: newer than the one listed
    assert other is not None and other.status != "affected"
