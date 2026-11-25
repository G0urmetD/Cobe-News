"""The Vendor News overview: the version to go to per installed version ("Update auf 4.14.6 behebt alle 5 Lücken"), how
urgent a product is (the order of the cards), readable titles instead of NVD boilerplate, "unklare Altdaten" (an old CVE
with unclear data before the installed release line existed – folded, not counted, not notified) and products that
share their vulnerability data. Pure functions on invented, realistic records; the API part offline."""

import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app import db, vendor
from app import vendor_catalog as catalog
from app import vendor_sources as src
from app import vendor_titles as titles
from app.models import VendorAdvisory, VendorAdvisoryProduct, VendorEvent, VendorFetch, VendorFollow, VendorVersion

WAZUH = {"key": "custom-wazuh", "label": "Wazuh Manager", "vendor": "Wazuh", "category": "siem", "cpes": ["a:wazuh:wazuh"], "eol": None, "scheme": "generic", "source": "custom"}
ABOUT_WAZUH = "Wazuh is a free and open source platform used for threat prevention, detection, and response. "


def _nvd(cve: str, *, end_excl: str | None = None, end_incl: str | None = None, start: str | None = None, cpe: str = "a:wazuh:wazuh", ver: str = "*",
         published: datetime | None = None, desc: str = "", cvss: float = 7.5, exploited: bool = False, cwe: list[str] | None = None) -> VendorAdvisory:
    m = {"vulnerable": True, "criteria": f"cpe:2.3:{cpe}:{ver}:*:*:*:*:*:*:*"}
    if start:
        m["versionStartIncluding"] = start
    if end_excl:
        m["versionEndExcluding"] = end_excl
    if end_incl:
        m["versionEndIncluding"] = end_incl
    desc = desc or f"{ABOUT_WAZUH}Prior to version {end_excl or '4.15.0'}, an issue in the analysis engine allows a crash."
    return VendorAdvisory(
        id=f"nvd:{cve}", source="nvd", ident=cve, title=desc[:180] + " …", summary=desc, url=f"https://nvd.nist.gov/vuln/detail/{cve}", cves=[cve], cvss=cvss,
        severity=src.severity_of(cvss), exploited=exploited, published_at=published or datetime(2026, 9, 1, tzinfo=UTC), updated_at=None,
        data={"configs": [{"nodes": [{"cpeMatch": [m]}]}], "cna": [], "desc": desc, "cwe": cwe or []},
    )


def _ver(text: str) -> VendorVersion:
    return VendorVersion(id=uuid.uuid4(), follow_id=uuid.uuid4(), version=text, label="", count=None)


def _targets(product: dict, advs: list[VendorAdvisory], vers: list[VendorVersion]) -> tuple[list[dict], dict[str, dict]]:
    groups = vendor.groups_of(advs)
    found = vendor.findings(product, advs, vers, {}, set(), groups)
    return found, vendor.target_versions(product, groups, found, vers)


# ---------------------------------------------------------------- the version to go to


def test_wazuh_update_in_the_line_fixes_all():
    # Wazuh 4.14.4: three CVEs fixed in 4.14.5, two more only in 4.14.6 – the smallest version that fixes everything
    advs = [_nvd(f"CVE-2026-6100{i}", end_excl="4.14.5", start="4.4.0") for i in range(3)] + [_nvd(f"CVE-2026-6110{i}", end_excl="4.14.6") for i in range(2)]
    v = _ver("4.14.4")
    found, t = _targets(WAZUH, advs, [v])
    assert all(f["versions"][0]["status"] == "affected" for f in found)
    assert t[str(v.id)] == {"kind": "update", "to": "4.14.6", "line": "4.14", "fixes": 5, "total": 5, "open": 0, "possible": 0, "newer": None}


def test_partial_fix_and_no_fix_yet():
    # one CVE affects everything up to and including 4.14.6 – no fixed version known yet
    advs = [_nvd("CVE-2026-61000", end_excl="4.14.5"), _nvd("CVE-2026-61001", end_excl="4.14.6"), _nvd("CVE-2026-61002", end_incl="4.14.6")]
    v = _ver("4.14.4")
    _, t = _targets(WAZUH, advs, [v])
    assert t[str(v.id)] | {"newer": None} == {"kind": "update", "to": "4.14.6", "line": "4.14", "fixes": 2, "total": 3, "open": 1, "possible": 0, "newer": None}
    # nothing fixed anywhere: no target
    _, t = _targets(WAZUH, [_nvd("CVE-2026-61003", end_incl="4.14.6")], [v])
    assert t[str(v.id)]["kind"] == "no_fix" and t[str(v.id)]["open"] == 1 and t[str(v.id)]["to"] is None


def test_versions_get_their_own_target_and_a_newer_line_when_theirs_has_no_fix():
    advs = [_nvd("CVE-2026-62000", end_excl="4.14.5"), _nvd("CVE-2026-62001", end_excl="4.14.6", start="4.10.0")]
    new, old = _ver("4.14.4"), _ver("4.13.2")
    _, t = _targets(WAZUH, advs, [new, old])
    assert t[str(new.id)]["kind"] == "update" and t[str(new.id)]["to"] == "4.14.6"
    # 4.13.2: the fixes exist only in 4.14 – "Neuere Linie nötig: 4.14"
    assert t[str(old.id)] | {"newer": None} == {"kind": "newer_line", "to": "4.14.6", "line": "4.14", "fixes": 2, "total": 2, "open": 0, "possible": 0, "newer": None}
    # a version nothing affects
    ok = _ver("4.14.6")
    _, t = _targets(WAZUH, advs, [ok])
    assert t[str(ok.id)]["kind"] == "none" and t[str(ok.id)]["total"] == 0


def _pan(ident: str, affected: str, fixed: str) -> VendorAdvisory:
    return VendorAdvisory(
        id=f"paloalto:{ident}", source="paloalto", ident=ident, title=f"{ident} PAN-OS: Example vulnerability in the management interface", summary="", url="https://security.paloaltonetworks.com/x",
        cves=[ident], cvss=8.1, severity="high", exploited=False, published_at=datetime(2026, 9, 1, tzinfo=UTC),
        data={"lines": [{"name": "PAN-OS 11.2", "affected": affected, "fixed": fixed}], "affected_list": [], "products": ["PAN-OS"]},
    )


def test_panos_hotfix_of_the_own_base_is_the_target():
    p = catalog.product("panos")
    advs = [_pan("CVE-2026-0400", "< 11.2.4-h22, < 11.2.7-h8", ">= 11.2.4-h22, >= 11.2.7-h8"), _pan("CVE-2026-0401", "< 11.2.4-h25, < 11.2.7-h11", ">= 11.2.4-h25, >= 11.2.7-h11")]
    v = _ver("11.2.4-h5")
    _, t = _targets(p, advs, [v])
    # the hotfix on the installed base that fixes both – smaller than the line's latest 11.2.x
    assert t[str(v.id)]["kind"] == "update" and t[str(v.id)]["to"] == "11.2.4-h25" and t[str(v.id)]["fixes"] == 2 and t[str(v.id)]["line"] == "11.2"


def test_veeam_build_target():
    feed = src.parse_veeam((Path(__file__).parent / "fixtures" / "vendor" / "veeam_feed.xml").read_bytes())
    kb = next(a for a in feed if a["ident"] == "KB4948")
    adv = VendorAdvisory(**{k: kb[k] for k in ("id", "source", "ident", "title", "summary", "url", "cves", "cvss", "severity", "published_at", "data")}, exploited=False)
    p = catalog.product("veeam-backup-and-replication")
    v = _ver("13.1.1.18")
    found, t = _targets(p, [adv], [v])
    assert found[0]["versions"][0]["status"] == "affected"
    assert t[str(v.id)]["kind"] == "update" and t[str(v.id)]["to"] == "13.1.2.57" and t[str(v.id)]["open"] == 0


def test_urgency_order():
    rel_ok = [{"eol_state": "ok"}]
    assert vendor.urgency({"affected": 2, "exploited_affected": 1, "critical_affected": 1}, rel_ok) == "exploited"
    assert vendor.urgency({"affected": 2, "critical_affected": 1}, rel_ok) == "critical"
    assert vendor.urgency({"affected": 2}, rel_ok) == "affected"
    assert vendor.urgency({}, [{"eol_state": "past"}]) == "affected"  # no support any more: act
    assert vendor.urgency({"possible": 3, "exploited": 1}, rel_ok) == "possible"  # exploited but only "possibly": not red
    assert vendor.urgency({}, [{"eol_state": "soon"}]) == "possible"
    assert vendor.urgency({"unversioned": 4}, []) == "possible"
    assert vendor.urgency({"service": 1}, []) == "info"
    assert vendor.urgency({"stale": 2}, rel_ok) == "ok"  # "unklare Altdaten" never make a product urgent


# ---------------------------------------------------------------- "unklare Altdaten"


def test_old_cve_with_unclear_data_before_the_line_is_stale():
    p = catalog.product("typo3")  # line 13 released 2024-01-30 (endoflife.date)
    v = _ver("13.4.37")
    old = _nvd("CVE-2009-3631", cpe="a:typo3:typo3", published=datetime(2009, 10, 22, tzinfo=UTC), desc="Cross-site scripting (XSS) vulnerability in the Backend subcomponent in TYPO3 allows remote attackers to inject arbitrary web script.")
    dashed = _nvd("CVE-2009-3635", cpe="a:typo3:typo3", ver="-", published=datetime(2009, 10, 22, tzinfo=UTC))
    recent = _nvd("CVE-2023-47125", cpe="a:typo3:typo3", published=datetime(2023, 11, 14, tzinfo=UTC))  # under a year before the line
    exploited = _nvd("CVE-2010-3714", cpe="a:typo3:typo3", published=datetime(2010, 10, 20, tzinfo=UTC), exploited=True)
    clear = _nvd("CVE-2010-3715", cpe="a:typo3:typo3", end_excl="4.4.5", published=datetime(2010, 10, 20, tzinfo=UTC))
    found = {f["ident"]: f for f in vendor.findings(p, [old, dashed, recent, exploited, clear], [v], {}, set())}
    assert found["CVE-2009-3631"]["status"] == "stale"
    row = found["CVE-2009-3631"]["versions"][0]
    assert row["reason"] == "predates_line" and row["detail"] == {"line": "13", "released": "2024-01-30"}
    assert found["CVE-2009-3635"]["status"] == "stale"  # "typo3:-": NVD names the product without a version
    assert found["CVE-2023-47125"]["status"] == "possible"  # not a clear margin before the line
    assert found["CVE-2010-3714"]["status"] == "possible"  # exploited: never folded
    assert found["CVE-2010-3715"]["status"] == "not_affected"  # the data decides – nothing to fold
    # without a release line (a product endoflife.date does not know) nothing is folded
    w = {f["ident"]: f["status"] for f in vendor.findings(WAZUH, [_nvd("CVE-2009-0001", published=datetime(2009, 1, 1, tzinfo=UTC))], [_ver("4.14.4")], {}, set())}
    assert w == {"CVE-2009-0001": "possible"}


async def test_stale_is_not_counted_nor_notified(admin_client, reader_client):
    now = datetime.now(UTC)
    async with db.session() as s:
        f = VendorFollow(product="typo3", enabled=True, created_at=now, updated_at=now)
        s.add(f)
        await s.flush()
        s.add(VendorVersion(follow_id=f.id, version="13.4.37", label="Website", count=None))
        for a in (
            _nvd("CVE-2009-3631", cpe="a:typo3:typo3", published=datetime(2009, 10, 22, tzinfo=UTC)),
            _nvd("CVE-2026-50001", cpe="a:typo3:typo3", published=now - timedelta(days=1)),  # unclear, but new: possibly
            _nvd("CVE-2026-50002", cpe="a:typo3:typo3", start="13.0.0", end_excl="13.4.38", published=now - timedelta(days=1), cvss=9.8),
        ):
            a.fetched_at = now
            s.add(a)
            s.add(VendorAdvisoryProduct(product="typo3", advisory_id=a.id))
        s.add(VendorFetch(key="nvd:a:typo3:typo3", failures=0, items=3, last_ok_at=now))
        await s.commit()
        vendor.bump()
        await vendor.evaluate_events(s)  # the baseline
        events = {e.data["ident"] for e in await s.scalars(select(VendorEvent).where(VendorEvent.kind == "vuln"))}
    assert events == {"CVE-2026-50001", "CVE-2026-50002"}  # never an event for "unklare Altdaten"
    card = (await reader_client.get("/api/vendor/overview")).json()["items"][0]
    assert card["counts"]["possible"] == 1 and card["counts"]["stale"] == 1 and card["counts"]["affected"] == 1
    assert card["counts"]["critical_affected"] == 1 and card["urgency"] == "critical"
    vid = card["versions"][0]["id"]
    per = card["summary"]["per_version"][vid]
    assert per["possible"] == 1 and per["stale"] == 1
    assert per["target"]["kind"] == "update" and per["target"]["to"] == "13.4.38" and per["target"]["fixes"] == 1
    assert all(x["ident"] != "CVE-2009-3631" for x in card["latest"])
    assert card["latest"][0]["headline"]  # the readable title goes with it
    d = (await reader_client.get("/api/vendor/products/typo3")).json()
    assert {f["ident"]: f["status"] for f in d["findings"]}["CVE-2009-3631"] == "stale"  # in the drawer, folded


async def test_products_with_the_same_cpe_name_each_other(admin_client, reader_client):
    for label in ("Wazuh Manager", "Wazuh Agent"):
        r = await admin_client.post("/api/vendor/custom", json={"cpe": "a:wazuh:wazuh", "label": label, "category": "siem"})
        assert r.status_code == 200
    r = await admin_client.put("/api/vendor/follows/fortios", json={"enabled": True})
    assert r.status_code == 200
    items = {i["product"]["label"]: i for i in (await reader_client.get("/api/vendor/overview")).json()["items"]}
    assert items["Wazuh Manager"]["same_data"] == ["Wazuh Agent"]
    assert items["Wazuh Agent"]["same_data"] == ["Wazuh Manager"]
    assert items["FortiOS (FortiGate)"]["same_data"] == []


# ---------------------------------------------------------------- readable titles


@pytest.mark.parametrize(
    "desc,cwe,want",
    [
        (ABOUT_WAZUH + "Prior to version 4.14.5, a heap buffer overflow in the wazuh-analysisd daemon allows an authenticated agent to crash the manager. This issue has been patched in version 4.14.5.",
         ["CWE-122"], "Heap buffer overflow in the wazuh-analysisd daemon"),
        (ABOUT_WAZUH + "In versions 4.4.0 through 4.14.4, the cluster API does not check the node's role, which lets a worker node run commands on the master. Version 4.14.5 fixes the issue.",
         ["CWE-863"], "Incorrect Authorization in the cluster API"),
        ("TYPO3 is an open source PHP based web content management system released under the GNU GPL. Failing to properly encode user input, the backend page tree is vulnerable to "
         "cross-site scripting. Updating to 13.4.18 fixes the problem.", ["CWE-79"], "Cross-Site Scripting"),
        ("Multiple cross-site scripting (XSS) vulnerabilities in the Backend subcomponent in TYPO3 4.0.13 and earlier, 4.1.x before 4.1.11, and 4.2.x before 4.2.6 allow remote "
         "authenticated users to inject arbitrary web script or HTML via unspecified vectors.", [], "Multiple cross-site scripting (XSS) vulnerabilities in the Backend subcomponent in TYPO3"),
        ("An issue was discovered in TYPO3 before 13.4.5. Missing authorization checks in the file list allow backend users to rename files they cannot see.", ["CWE-862"],
         "Missing authorization checks in the file list"),
        ("A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may "
         "enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.", ["CWE-77"], "Command Injection in the GlobalProtect feature"),
        # nothing readable before "allows": the impact the text names
        ("When the export option is enabled, the reporting module of Example Suite allows remote attackers to execute arbitrary code.", [], "Remote Code Execution"),
    ],
)
def test_headline_from_nvd_descriptions(desc, cwe, want):
    assert titles.headline("nvd", desc[:180] + " …", desc, cwe, "Wazuh") == want


def test_headline_prefers_the_vendor_and_kev_titles():
    assert titles.headline("paloalto", "CVE-2024-3400 PAN-OS: Arbitrary File Creation Leads to OS Command Injection in the GlobalProtect Feature") == (
        "PAN-OS: Arbitrary File Creation Leads to OS Command Injection in the GlobalProtect Feature"
    )
    assert titles.headline("fortinet", "Heap-based buffer overflow in sslvpnd") == "Heap-based buffer overflow in sslvpnd"
    # an NVD record with CISA's name of an exploited vulnerability
    assert titles.headline("nvd", "Palo Alto Networks PAN-OS Command Injection Vulnerability", "A command injection vulnerability in the GlobalProtect feature …") == (
        "Palo Alto Networks PAN-OS Command Injection Vulnerability"
    )
    assert titles.headline("nvd", "x", "y", [], "", cna_title="Wazuh: heap overflow in analysisd") == "Wazuh: heap overflow in analysisd"
    assert len(titles.headline("csaf", "A" * 300)) <= titles.TITLE_MAX + 2


def test_headline_is_linear_on_hostile_text():
    hostile = ["in " + "a " * 900 + "b", "1." * 900, "Prior to " + "x," * 600, "the " + "-" * 1500 + " module", ("version 1.2 " * 150) + "allows", "A" * 1500]
    t0 = time.perf_counter()
    for h in hostile:
        assert len(titles.headline("nvd", h[:180], h, ["CWE-79"])) <= titles.TITLE_MAX + 2
    assert time.perf_counter() - t0 < 1.0


def test_nvd_parse_keeps_the_weaknesses():
    body = {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-61000", "vulnStatus": "Analyzed", "published": "2026-09-01T10:00:00.000", "descriptions": [{"lang": "en", "value": "x"}],
            "weaknesses": [{"source": "cna@example.com", "type": "Secondary", "description": [{"lang": "en", "value": "CWE-122"}]},
                           {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-787"}, {"lang": "en", "value": "NVD-CWE-noinfo"}]}]}}]}
    _, advs = src.parse_nvd(json.dumps(body).encode())
    assert advs[0]["data"]["cwe"] == ["CWE-787", "CWE-122"]


def test_target_version_is_not_itself_affected():
    """Bug hunt 0.1.16 M6: installed 4.14.4; CVE-A affects < 4.14.6, CVE-B (a regression, CVSS 9.8) 4.14.5 ≤ v < 4.14.9.
    "Update auf 4.14.6" would trade A for B – the target is 4.14.9, which fixes A and is not affected by B."""
    a = _nvd("CVE-2026-70000", end_excl="4.14.6")
    b = _nvd("CVE-2026-70001", start="4.14.5", end_excl="4.14.9", cvss=9.8)
    v = _ver("4.14.4")
    _, t = _targets(WAZUH, [a, b], [v])
    assert t[str(v.id)]["to"] == "4.14.9" and "introduces" not in t[str(v.id)]
    found, _ = _targets(WAZUH, [a, b], [_ver("4.14.9")])
    assert all(f["versions"][0]["status"] != "affected" for f in found)


def test_target_names_what_it_would_newly_be_affected_by():
    """No release of the line avoids the regression yet (no fix known): the target stays, and says so."""
    a = _nvd("CVE-2026-70010", end_excl="4.14.6")
    b = _nvd("CVE-2026-70011", start="4.14.5", end_incl="4.14.99")
    v = _ver("4.14.4")
    _, t = _targets(WAZUH, [a, b], [v])
    assert t[str(v.id)]["to"] == "4.14.6" and t[str(v.id)]["introduces"] == 1


def _cna_only(cve: str, rows: list[dict], cpes: list[str]) -> VendorAdvisory:
    """An NVD record whose CNA (a third party) names a range, NVD's own analysis only the pre-releases (CVE-2026-67307)."""
    desc = f"{ABOUT_WAZUH}Wazuh 5.0.0-beta1 (fixed in 5.0.0-beta3) does not validate a field of inventory-sync messages."
    nodes = [{"cpeMatch": [{"vulnerable": True, "criteria": c} for c in cpes]}]
    return VendorAdvisory(
        id=f"nvd:{cve}", source="nvd", ident=cve, title=desc[:180], summary=desc, url=f"https://nvd.nist.gov/vuln/detail/{cve}", cves=[cve], cvss=7.7,
        severity="high", exploited=False, published_at=datetime(2026, 11, 1, tzinfo=UTC), updated_at=None,
        data={"configs": [{"nodes": nodes}], "cna": [{"affectedData": [{"vendor": "wazuh", "product": "wazuh", "versions": rows, "defaultStatus": "unaffected"}]}],
              "assigner": "disclosure@vulncheck.com", "desc": desc, "cwe": []},
    )  # fmt: skip


def test_a_pre_release_is_never_the_target(monkeypatch):
    """Wazuh 4.14.10, the live case of 0.1.58: the CNA's range "0 < 5.0.0-beta3" – the only fix a beta. No "Neuere Linie
    nötig: 5.0 – 5.0.0-beta3 behebt die Lücke": no stable fix yet, the pre-release named as such. (That record itself is
    "möglicherweise" since – test_third_party_range_…; the target logic is checked here with it read as affected.)"""
    from app import vendor_match

    monkeypatch.setattr(vendor_match, "_prerelease_only", lambda *a, **k: False)
    beta = _cna_only("CVE-2026-67307", [{"status": "affected", "version": "0", "lessThan": "5.0.0-beta3", "versionType": "semver"}], ["cpe:2.3:a:wazuh:wazuh:5.0.0:beta1:*:*:*:*:*:*"])
    v = _ver("4.14.10")
    found, t = _targets(WAZUH, [beta], [v])
    row = found[0]["versions"][0]
    assert row["status"] == "affected" and row["fixed"] == "5.0.0-beta3" and row["fixed_pre"] is True
    assert t[str(v.id)] == {"kind": "no_fix", "to": None, "line": None, "fixes": 0, "total": 1, "open": 1, "possible": 0, "newer": None, "prerelease": {"to": "5.0.0-beta3", "fixes": 1}}
    # next to a stable fix in the line: the update stays the target, the beta is named only for what remains
    stable = _nvd("CVE-2026-61000", end_excl="4.14.11")
    old = _ver("4.14.4")
    _, t = _targets(WAZUH, [beta, stable], [old])
    assert t[str(old.id)] | {"newer": None} == {"kind": "update", "to": "4.14.11", "line": "4.14", "fixes": 1, "total": 2, "open": 1, "possible": 0, "newer": None, "prerelease": {"to": "5.0.0-beta3", "fixes": 1}}
    # a stable 5.0.0 that fixes it as well: the newer line, no pre-release hint
    rel = _cna_only("CVE-2026-67308", [{"status": "affected", "version": "0", "lessThan": "5.0.0", "versionType": "semver"}], ["cpe:2.3:a:wazuh:wazuh:5.0.0:beta1:*:*:*:*:*:*"])
    _, t = _targets(WAZUH, [rel], [v])
    assert t[str(v.id)]["kind"] == "newer_line" and t[str(v.id)]["to"] == "5.0.0" and "prerelease" not in t[str(v.id)]
    # a stable fix: no flag on the row
    found, _ = _targets(WAZUH, [stable], [old])
    assert "fixed_pre" not in found[0]["versions"][0]


def test_a_notification_names_a_pre_release_fix_as_such():
    from app import notify

    data = {"product": "Wazuh Manager (Server)", "version": "4.14.10", "status": "affected", "fixed": "5.0.0-beta3", "ident": "CVE-2026-67307", "title": "x", "url": "https://nvd.nist.gov/x"}
    ev = VendorEvent(id=uuid.uuid4(), key="vuln:wazuh:4.14.10:nvd:CVE-2026-67307", kind="vuln", product="wazuh", severity="high", data=data, created_at=datetime.now(UTC))
    de = notify.vendor_story(ev, "de")
    assert "Fix: 5.0.0-beta3 (Vorabversion – noch kein stabiler Fix)" in de.summary and "→" not in de.product
    assert "(pre-release – no stable fix yet)" in notify.vendor_story(ev, "en").summary
    ev.data = data | {"fixed": "4.14.11"}
    assert "Fix: 4.14.11 ·" in notify.vendor_story(ev, "de").summary + " ·" and notify.vendor_story(ev, "de").product.endswith("→ 4.14.11")


# ---------------------------------------------------------------- a third party's range for a record about pre-releases


def _wazuh_67307(**over) -> VendorAdvisory:  # noqa: ANN003
    a = _cna_only("CVE-2026-67307", [{"status": "affected", "version": "0", "lessThan": "5.0.0-beta3", "versionType": "semver"}], ["cpe:2.3:a:wazuh:wazuh:5.0.0:beta1:*:*:*:*:*:*"])
    a.data = {**a.data, **over}
    return a


def test_third_party_range_from_zero_for_a_pre_release_record_is_only_possible():
    """The user's decision on CVE-2026-67307: VulnCheck (not Wazuh) writes "0 < 5.0.0-beta3", NVD's analysis names only
    5.0.0 beta1, the description "Wazuh 5.0.0-beta1 (fixed in 5.0.0-beta3)" – 4.14.10 is possibly affected, not surely."""
    from app import vendor_match

    p = catalog.product("wazuh")
    adv = _wazuh_67307()
    got = vendor_match.evaluate(p, "nvd", adv.data, "4.14.10")
    assert (got.status, got.reason, got.fixed, got.detail) == ("possible", "prerelease_only", "5.0.0-beta3", {"by": "cna", "cna": "VulnCheck"})
    assert vendor_match.evaluate(p, "nvd", adv.data, "5.0.0-beta1").status == "affected"  # the beta itself: as listed
    assert vendor_match.evaluate(p, "nvd", adv.data, "5.0.0").status == "not_affected"
    # without NVD's analysis the description alone decides the same
    assert vendor_match.evaluate(p, "nvd", _wazuh_67307(configs=[]).data, "4.14.10").reason == "prerelease_only"


def test_a_genuine_third_party_range_stays_affected():
    from app import vendor_match

    p = catalog.product("wazuh")
    # NVD's analysis names stable versions too (a range up to the fix): the range counts as written
    ranged = [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*", "versionEndExcluding": "4.14.11"},
                                       {"vulnerable": True, "criteria": "cpe:2.3:a:wazuh:wazuh:5.0.0:beta1:*:*:*:*:*:*"}]}]}]  # fmt: skip
    assert vendor_match.evaluate(p, "nvd", _wazuh_67307(configs=ranged).data, "4.14.10").status == "affected"
    # the description names a stable version
    desc = "Wazuh 4.0.0 before 4.14.11 and 5.0.0-beta2 allow a denial of service."
    assert vendor_match.evaluate(p, "nvd", _wazuh_67307(desc=desc, configs=[]).data, "4.14.10").status == "affected"
    # a lower bound: no open range
    rows = [{"status": "affected", "version": "4.0.0", "lessThan": "5.0.0-beta3", "versionType": "semver"}]
    lo = _cna_only("CVE-2026-67309", rows, ["cpe:2.3:a:wazuh:wazuh:5.0.0:beta1:*:*:*:*:*:*"])
    assert vendor_match.evaluate(p, "nvd", lo.data, "4.14.10").status == "affected"
    # the vendor itself as CNA stays authoritative
    own = _wazuh_67307(assigner="security@wazuh.com")
    assert vendor_match.cna_by(p, own.data) == ("vendor", "")
    assert vendor_match.evaluate(p, "nvd", own.data, "4.14.10").status == "affected"


async def test_affected_turning_possible_sends_nothing(admin_client, monkeypatch):
    """0.1.58 made "betroffen" events for CVE-2026-67307; the downgrade to "möglicherweise" is no news (same event key)."""
    from app import vendor_match
    from app.models import VendorAdvisoryProduct

    async with db.session() as s:
        s.add(_wazuh_67307())
        await s.flush()
        s.add(VendorAdvisoryProduct(product="wazuh", advisory_id="nvd:CVE-2026-67307"))
        await s.commit()
    assert (await admin_client.put("/api/vendor/follows/wazuh", json={"enabled": True})).status_code == 200
    assert (await admin_client.post("/api/vendor/follows/wazuh/versions", json={"version": "4.14.10"})).status_code == 200
    monkeypatch.setattr(vendor, "_ready", lambda *_a: True)  # the sources' first answers (a round) are not part of this
    real = vendor_match._prerelease_only
    monkeypatch.setattr(vendor_match, "_prerelease_only", lambda *a, **k: False)  # as 0.1.58 judged it
    async with db.session() as s:
        await vendor.evaluate_events(s, full=True)
        await s.commit()
        before = list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "vuln")))
    assert [e.data["status"] for e in before] == ["affected"]
    monkeypatch.setattr(vendor_match, "_prerelease_only", real)
    vendor.bump(["wazuh"])
    async with db.session() as s:
        await vendor.evaluate_events(s, full=True)
        await s.commit()
        after = list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "vuln")))
    assert [e.id for e in after] == [e.id for e in before]  # no new event
    d = (await admin_client.get("/api/vendor/products/wazuh")).json()
    assert d["findings"][0]["versions"][0]["reason"] == "prerelease_only"
