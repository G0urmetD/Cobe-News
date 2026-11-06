"""Verdicts per advisory, product and version – with trimmed real responses (tests/fixtures/vendor) and the edge cases
that must never end in a false "not affected"."""

from pathlib import Path

import pytest

from app import vendor_catalog as catalog
from app import vendor_sources as src
from app.vendor_match import evaluate, name_matches

FIX = Path(__file__).parent / "fixtures" / "vendor"


@pytest.fixture(scope="module")
def cat():
    return {p["key"]: p for p in catalog.load()["products"]}


@pytest.fixture(scope="module")
def pan():
    return {a["ident"]: a for a in src.parse_pan((FIX / "pan_list.json").read_bytes())}


def verdict(cat, key, source, data, version):
    r = evaluate(cat[key], source, data, version)
    return None if r is None else (r.status, r.fixed)


# ---------------------------------------------------------------- Palo Alto


def test_pan_parse(pan):
    a = pan["CVE-2026-0322"]
    assert a["severity"] == "high" and a["cvss"] == 8.6
    assert a["url"] == "https://security.paloaltonetworks.com/CVE-2026-0322"
    assert a["cves"] == ["CVE-2026-0322"]
    assert any(ln["name"] == "PAN-OS 11.2" for ln in a["data"]["lines"])
    assert "PAN-OS 11.2.4-h21" in a["data"]["affected_list"]
    # the advisory about two PHP CVEs is filed under the first – it decides both (title and text name the second)
    assert pan["CVE-2026-109618"]["cves"] == ["CVE-2026-109618", "CVE-2026-109619"]


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("11.2.4-h23", ("not_affected", None)),  # the user's firewalls: fixed in 11.2.4-h22
        ("11.2.4-h22", ("not_affected", None)),
        ("11.2.4-h21", ("affected", "11.2.4-h22")),
        ("11.2.4-h4", ("affected", "11.2.4-h22")),  # h4 < h22 numerically
        ("11.2.4", ("affected", "11.2.4-h22")),
        ("11.2.15", ("affected", "11.2.16")),  # a base without its own hotfix: up to the line's fix
        ("11.2.16", ("not_affected", None)),
        ("10.2.13-h5", ("affected", "10.2.13-h26")),
        ("11.1.6-h3", ("affected", "11.1.6-h39")),
        ("12.2.3", ("affected", "12.2.4")),
        ("9.1.0", ("possible", None)),  # an old line the advisory does not name: never "not affected"
    ],
)
def test_pan_hotfix_bases(cat, pan, version, expected):
    assert verdict(cat, "panos", "paloalto", pan["CVE-2026-0322"]["data"], version) == expected


def test_pan_panorama_only_advisory(cat, pan):
    data = pan["CVE-2026-0318"]["data"]  # "< 11.2.4-h22 on Panorama" – a DoS of Panorama
    assert verdict(cat, "panos", "paloalto", data, "11.2.4-h5") == ("not_affected", None)
    assert verdict(cat, "panorama", "paloalto", data, "11.2.4-h5") == ("affected", "11.2.4-h22")
    assert verdict(cat, "panorama", "paloalto", data, "11.2.4-h23") == ("not_affected", None)


def test_pan_firewall_advisory_on_panorama_is_only_possible(cat, pan):
    data = pan["CVE-2026-0279"]["data"]  # PAN-OS XSS, says nothing about Panorama
    assert verdict(cat, "panos", "paloalto", data, "11.2.4-h23") == ("affected", "11.2.13")
    assert verdict(cat, "panorama", "paloalto", data, "11.2.4-h23") == ("possible", "11.2.13")


def test_pan_all_none_and_newer_lines(cat, pan):
    data = pan["CVE-2026-0279"]["data"]
    assert verdict(cat, "panos", "paloalto", data, "10.2.13-h5") == ("affected", None)  # "All": no fix in 10.2
    assert verdict(cat, "panos", "paloalto", data, "12.2.3") == ("not_affected", None)  # 12.2 newer than every listed line
    assert verdict(cat, "panos", "paloalto", pan["PAN-SA-2026-0006"]["data"], "11.2.4") == ("not_affected", None)


def test_pan_without_version_and_cloud(cat, pan):
    assert verdict(cat, "panos", "paloalto", pan["CVE-2026-0322"]["data"], None) == ("unversioned", None)
    assert verdict(cat, "prisma-access", "paloalto", pan["CVE-2026-0310"]["data"], None) == ("service", None)
    assert verdict(cat, "prisma-access", "paloalto", pan["CVE-2026-0322"]["data"], None) is None or verdict(cat, "prisma-access", "paloalto", pan["CVE-2026-0322"]["data"], None)[0] == "not_affected"
    assert verdict(cat, "cloud-ngfw", "paloalto", pan["CVE-2026-0310"]["data"], None) == ("service", None)
    assert evaluate(cat["pangp"], "paloalto", pan["CVE-2026-0322"]["data"], "6.2.8") is None  # not about GlobalProtect


def test_pan_regression_ranges():
    """CVE-2025-4619: only some hotfixes affected ('>= 11.1.2-h9, < 11.1.2-h18') – an unlisted base stays possible."""
    p = catalog.product("panos")
    data = {
        "lines": [
            {
                "name": "PAN-OS 11.1",
                "affected": ">= 11.1.2-h9, < 11.1.2-h18, >= 11.1.3-h2, >= 11.1.4-h4, < 11.1.4-h13, < 11.1.6-h1, < 11.1.7",
                "fixed": "< 11.1.2-h9, >= 11.1.2-h18, < 11.1.3-h2, < 11.1.4-h4, >= 11.1.4-h13, >= 11.1.6-h1, >= 11.1.7",
            }
        ],
        "affected_list": [],
    }
    e = lambda v: (r := evaluate(p, "paloalto", data, v)) and (r.status, r.fixed)  # noqa: E731
    assert e("11.1.2-h8") == ("not_affected", None)
    assert e("11.1.2-h9") == ("affected", "11.1.2-h18")
    assert e("11.1.2-h18") == ("not_affected", None)
    assert e("11.1.4-h5") == ("affected", "11.1.4-h13")
    assert e("11.1.6") == ("affected", "11.1.6-h1")
    assert e("11.1.5")[0] == "possible"  # base not listed while ranges start somewhere
    assert e("11.1.7") == ("not_affected", None)


def test_pan_affected_list_wins():
    p = catalog.product("panos")
    data = {"lines": [{"name": "PAN-OS 11.2", "affected": "< 11.2.3", "fixed": ">= 11.2.3"}], "affected_list": ["PAN-OS 11.2.4-h1"]}
    assert evaluate(p, "paloalto", data, "11.2.4-h1").status == "affected"
    assert evaluate(p, "paloalto", data, "11.2.4-h2").status == "not_affected"


def test_unparsable_version_is_possible_never_not_affected(cat, pan):
    r = evaluate(cat["panos"], "paloalto", pan["CVE-2026-0322"]["data"], "11.2 latest")
    assert (r.status, r.reason) == ("possible", "unparsed_version")


# ---------------------------------------------------------------- Fortinet


@pytest.fixture(scope="module")
def forti():
    item = {"ident": "FG-IR-26-161", "title": "Stack buffer overflow in WAD", "link": "https://fortiguard.fortinet.com/psirt/FG-IR-26-161"}
    return src.parse_forti_csaf((FIX / "fortinet_csaf_wad.json").read_bytes(), item)


def test_forti_rss():
    items = src.parse_forti_rss((FIX / "fortinet_ir.xml").read_bytes())
    assert [i["ident"] for i in items] == ["FG-IR-26-187", "FG-IR-26-186", "FG-IR-26-180"]
    assert all(i["csaf"].startswith("https://filestore.fortinet.com/") for i in items)


def test_forti_rss_refuses_dtd_and_foreign_csaf_hosts():
    from app.news import NewsError

    with pytest.raises(NewsError):
        src.parse_forti_rss(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><rss><channel/></rss>')
    rss = (
        b'<rss xmlns:csaf="https://fortiguard.fortinet.com/rss/ns/csaf"><channel><item><title>x</title>'
        b"<link>https://fortiguard.fortinet.com/psirt/FG-IR-26-1</link><csaf:link>https://evil.example/csaf.json</csaf:link></item></channel></rss>"
    )
    assert src.parse_forti_rss(rss)[0]["csaf"] == ""


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("7.6.1", ("affected", "7.6.7")),
        ("7.6.6", ("affected", "7.6.7")),
        ("v7.6.3 build3510", ("affected", "7.6.7")),
        ("7.6.7", ("not_affected", None)),
        ("7.6.0", ("not_affected", None)),
        ("7.4.3", ("not_affected", None)),  # "FortiOS 7.4 all versions" not affected
        ("8.0.1", ("not_affected", None)),
        ("7.0.15", ("possible", None)),  # 7.0 not named at all
    ],
)
def test_forti_csaf(cat, forti, version, expected):
    assert forti["cves"] == ["CVE-2026-71407"] and forti["cvss"] == 5.1
    assert verdict(cat, "fortios", "fortinet", forti["data"], version) == expected


def test_forti_other_products(cat, forti):
    assert evaluate(cat["fortiproxy"], "fortinet", forti["data"], "7.6.1") is None
    assert verdict(cat, "fortios", "fortinet", forti["data"], None) == ("unversioned", None)


# ---------------------------------------------------------------- NVD


@pytest.fixture(scope="module")
def nvd():
    total, advs = src.parse_nvd((FIX / "nvd_fortios.json").read_bytes())
    assert total == len(advs) == 6
    return {a["ident"]: a for a in advs}


def test_nvd_parse(nvd):
    a = nvd["CVE-2025-59718"]
    assert a["exploited"] and a["data"]["kev"]["added"] == "2025-12-16"
    assert a["severity"] == "critical" and a["url"].endswith("CVE-2025-59718")
    assert a["data"]["configs"] and a["data"]["cna"]


@pytest.mark.parametrize(
    ("cve", "version", "status"),
    [
        ("CVE-2025-59718", "7.4.3", "affected"),
        ("CVE-2025-59718", "7.4.9", "not_affected"),
        ("CVE-2024-21754", "7.4.3", "affected"),
        ("CVE-2024-21754", "7.4.4", "not_affected"),
        ("CVE-2024-26015", "7.4.3", "affected"),  # versionEndIncluding 7.4.3
    ],
)
def test_nvd_fortios(cat, nvd, cve, version, status):
    assert evaluate(cat["fortios"], "nvd", nvd[cve]["data"], version).status == status


def test_nvd_without_version_and_unrelated_product(cat, nvd):
    assert evaluate(cat["fortios"], "nvd", nvd["CVE-2024-21754"]["data"], None).status == "unversioned"
    assert evaluate(cat["php"], "nvd", nvd["CVE-2024-21754"]["data"], "8.3.1") is None


def _cfg(*matches):
    return {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, **m} for m in matches]}]}], "cna": [], "desc": ""}


def test_nvd_explicit_lists_cisco(cat):
    data = _cfg({"criteria": "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.18.4.22:*:*:*:*:*:*:*"}, {"criteria": "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.18.4.8:*:*:*:*:*:*:*"})
    asa = cat["cisco-asa"]
    assert evaluate(asa, "nvd", data, "9.18(4)22").status == "affected"
    assert evaluate(asa, "nvd", data, "9.18(4)47").status == "not_affected"  # newer than every listed 9.18
    assert evaluate(asa, "nvd", data, "9.18(4)10").status == "possible"  # between listed ones, not listed itself
    assert evaluate(asa, "nvd", data, "9.16(4)48").status == "possible"


def test_nvd_any_update_is_imprecise_for_hotfixes(cat):
    data = _cfg({"criteria": "cpe:2.3:o:paloaltonetworks:pan-os:11.2.4:*:*:*:*:*:*:*"})
    assert evaluate(cat["panos"], "nvd", data, "11.2.4").status == "affected"
    assert evaluate(cat["panos"], "nvd", data, "11.2.4-h23").status == "possible"
    exact = _cfg({"criteria": "cpe:2.3:o:paloaltonetworks:pan-os:11.2.4:h1:*:*:*:*:*:*"})
    assert evaluate(cat["panos"], "nvd", exact, "11.2.4-h1").status == "affected"
    assert evaluate(cat["panos"], "nvd", exact, "11.2.4-h23").status == "not_affected"


def test_nvd_all_versions_and_older_lines_stay_possible(cat):
    assert evaluate(cat["php"], "nvd", _cfg({"criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}), "8.3.14").status == "possible"
    ranged = _cfg({"criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.31"})
    assert evaluate(cat["php"], "nvd", ranged, "8.1.30").fixed == "8.1.31"
    assert evaluate(cat["php"], "nvd", ranged, "8.1.31").status == "not_affected"
    assert evaluate(cat["php"], "nvd", ranged, "7.4.33").status == "possible"  # below every range: nobody assessed it
    bad = _cfg({"criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "versionEndExcluding": "8.x"})
    assert evaluate(cat["php"], "nvd", bad, "8.3.1").status == "possible"


def test_nvd_windows_build_ranges_by_release(cat):
    data = _cfg(
        {"criteria": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", "versionEndExcluding": "10.0.20348.2849"},
        {"criteria": "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*", "versionEndExcluding": "10.0.17763.6532"},
    )
    ws = cat["windows-server"]
    assert evaluate(ws, "nvd", data, "10.0.20348.2762").fixed == "10.0.20348.2849"
    assert evaluate(ws, "nvd", data, "10.0.20348.2849").status == "not_affected"
    assert evaluate(ws, "nvd", data, "10.0.17763.6414").status == "affected"
    assert evaluate(ws, "nvd", data, "10.0.26100.2605") is None  # Server 2025 not named: the CVE is not about it
    assert evaluate(ws, "nvd", data, "10.0.31337.1").status == "possible"  # a build we cannot place


def test_cna_data_microsoft_and_changes(cat):
    data = {
        "configs": [],
        "desc": "",
        "cna": [
            {
                "affectedData": [
                    {
                        "vendor": "Microsoft",
                        "product": "Microsoft Exchange Server 2019 Cumulative Update 14",
                        "defaultStatus": "unaffected",
                        "versions": [{"version": "15.02.0", "lessThan": "15.02.1544.014", "status": "affected", "versionType": "custom"}],
                    }
                ]
            }
        ],
    }
    ex = cat["msexchange"]
    assert evaluate(ex, "nvd", data, "15.2.1544.13").status == "affected"
    assert evaluate(ex, "nvd", data, "15.2.1544.14").status == "not_affected"
    pan = {
        "configs": [],
        "desc": "",
        "cna": [
            {
                "affectedData": [
                    {
                        "vendor": "Palo Alto Networks",
                        "product": "PAN-OS",
                        "versions": [
                            {"version": "11.1.0", "lessThan": "11.1.2-h3", "status": "affected", "changes": [{"at": "11.1.0-h3", "status": "unaffected"}, {"at": "11.1.1-h1", "status": "unaffected"}]}
                        ],
                    }
                ]
            }
        ],
    }
    p = cat["panos"]
    assert evaluate(p, "nvd", pan, "11.1.0-h2").status == "affected"
    assert evaluate(p, "nvd", pan, "11.1.0-h3").status == "not_affected"
    assert evaluate(p, "nvd", pan, "11.1.1").status == "affected"  # a hotfix change only applies to its own base
    assert evaluate(p, "nvd", pan, "11.1.2-h3").status == "not_affected"


def test_name_matching():
    assert name_matches("Microsoft Exchange Server 2019 Cumulative Update 14", "Exchange Server", "Microsoft")
    assert name_matches("Windows Server 2022", "Windows Server")
    assert name_matches("PAN-OS", "PAN-OS")
    assert not name_matches("phpMyAdmin", "PHP")
    assert not name_matches("PHP Everywhere", "PHP")
    assert not name_matches("Exchange Online", "Exchange Server")


def test_hyper_v_filter(cat):
    data = _cfg({"criteria": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", "versionEndExcluding": "10.0.20348.2849"})
    assert evaluate(cat["hyper-v"], "nvd", {**data, "desc": "Windows Kerberos Elevation of Privilege"}, "10.0.20348.2762") is None
    assert evaluate(cat["hyper-v"], "nvd", {**data, "desc": "Windows Hyper-V Remote Code Execution"}, "10.0.20348.2762").status == "affected"


def test_cpe_search_parse():
    items = src.parse_cpes((FIX / "nvd_cpes.json").read_bytes())
    assert {"cpe": "a:citrix:netscaler", "title": "Citrix NetScaler", "vendor": "citrix", "product": "netscaler"} in items
    assert len({i["cpe"] for i in items}) == len(items)


# ---------------------------------------------------------------- 0.1.4: PHP on PAN-OS (two CVEs, NVD's "pan-os:-")


@pytest.fixture(scope="module")
def php_nvd():
    _, advs = src.parse_nvd((FIX / "nvd_php_panos.json").read_bytes())
    return advs[0]


@pytest.mark.parametrize(
    ("version", "status"),
    [
        ("11.2.4-h23", "not_affected"),  # newer than every listed hotfix – not "all versions" because of "pan-os:-"
        ("11.2.4-h20", "affected"),
        ("11.2.4-h18", "affected"),
        ("11.2.3", "affected"),  # the range 11.2.0 – <11.2.4
        ("10.2.13-h5", "affected"),
    ],
)
def test_nvd_version_dash_is_not_every_version(cat, php_nvd, version, status):
    assert evaluate(cat["panos"], "nvd", php_nvd["data"], version).status == status


def test_nvd_version_dash_alone_is_only_possible(cat):
    data = {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:o:paloaltonetworks:pan-os:-:*:*:*:*:*:*:*"}]}]}]}
    r = evaluate(cat["panos"], "nvd", data, "11.2.4-h23")
    assert (r.status, r.reason) == ("possible", "no_version")
    assert evaluate(cat["panos"], "nvd", data, None).status == "unversioned"


def test_nvd_platform_half_of_running_on_is_dropped(php_nvd):
    # the PAN-OS node of the AND pairing is not vulnerable itself – trimmed away, only vulnerable matches stay
    crit = [m["criteria"] for c in php_nvd["data"]["configs"] for n in c["nodes"] for m in n["cpeMatch"]]
    assert "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*" in crit  # from the explicit ranges
    assert all(m.get("vulnerable") for c in php_nvd["data"]["configs"] for n in c["nodes"] for m in n["cpeMatch"])


@pytest.mark.parametrize(
    ("version", "status"),
    [("11.2.4-h23", "not_affected"), ("11.2.3", "not_affected"), ("11.2.2", "affected"), ("11.2.2-h1", "affected"), ("11.2.1", "possible")],
)
def test_pan_single_affected_release(cat, version, status):
    # CVE-2024-8686: "affected: 11.2.2", "fixed: >= 11.2.3" – was "possibly affected (data not comparable)" for everyone
    data = {"lines": [{"name": "PAN-OS 11.2", "affected": "11.2.2", "fixed": ">= 11.2.3"}, {"name": "PAN-OS 11.1", "affected": "None", "fixed": "All"}],
            "affected_list": ["PAN-OS 11.2.2-h1", "PAN-OS 11.2.2"]}
    assert evaluate(cat["panos"], "paloalto", data, version).status == status


# ---------------------------------------------------------------- review: several ranges in one text, CVE 5 "unknown"


def test_several_ranges_in_one_version_text_are_all_kept():
    """A CSAF product_version_range with several intervals / lines / versions (allowed by the vers spec): every one of
    them counts – before, only the last one did (1.2.3 below came out "not affected")."""
    from app.vendor_match import eval_ranges, range_of, ranges_of
    from app.vendor_versions import parse

    def ev(text: str, version: str) -> str:
        return eval_ranges("generic", {"affected": ranges_of(text), "fixed": []}, parse("generic", version)).status

    two = "vers:intdot/>=1.2.0|<1.2.5|>=1.2.8|<1.2.9"
    assert [r["text"] for r in ranges_of(two)] == [">=1.2.0 <1.2.5", ">=1.2.8 <1.2.9"]
    assert [ev(two, x) for x in ("1.2.3", "1.2.6", "1.2.8", "1.2.9")] == ["affected", "not_affected", "affected", "not_affected"]
    lines = "<19.5.1, <19.4.3"
    assert [ev(lines, x) for x in ("19.4.1", "19.4.5", "19.5.0", "19.5.1")] == ["affected", "not_affected", "affected", "not_affected"]
    assert [ev("2.4.1|2.4.3", x) for x in ("2.4.1", "2.4.3")] == ["affected", "affected"]
    # one interval stays one – also written the other way round
    assert ranges_of(">=7.4.5|<=7.4.8") == [range_of(">=7.4.5|<=7.4.8")] and len(ranges_of("<=7.4.8, >=7.4.5")) == 1
    assert ranges_of("not a version") == [] and range_of("not a version") is None
    # "not affected" with several versions: each of them
    entry = {"affected": ranges_of("<3.0"), "fixed": [], "not_affected": ["2.4.1|2.4.3"]}
    assert eval_ranges("generic", entry, parse("generic", "2.4.1")).status == "not_affected"


def test_cve5_exact_version_with_status_unknown_is_not_cleared():
    from app.vendor_match import eval_cna
    from app.vendor_versions import parse

    product = {"key": "widget", "label": "Widget", "vendor": "Acme", "scheme": "generic", "cna": [["Acme", "Widget"]]}
    versions = [{"version": "2.0", "status": "unknown"}, {"version": "1.0", "status": "affected"}, {"version": "1.5", "status": "unaffected"}]
    aff = [{"affectedData": [{"vendor": "Acme", "product": "Widget", "defaultStatus": "affected", "versions": versions}]}]
    assert eval_cna(product, aff, parse("generic", "2.0")).status == "possible"
    assert eval_cna(product, aff, parse("generic", "1.0")).status == "affected"
    assert eval_cna(product, aff, parse("generic", "1.5")).status == "not_affected"


# ---------------------------------------------------------------- NVD: the CNA's data and CISA's ADP kept apart


def test_nvd_cisa_adp_default_is_not_the_vendors_word(cat):
    """GitLab CVE-2024-4835: GitLab's own rows (15.11 – < 16.10.6, 16.11 – < 16.11.3, 17.0 – < 17.0.1, default
    unaffected) and CISA's ADP (15.11 – < 17.0.1, default *affected*), which NVD lists side by side. CISA's default
    once made every later version "affected" – "laut Hersteller alle anderen Versionen betroffen" for 19.5.3."""
    _, advs = src.parse_nvd((FIX / "nvd_gitlab_adp.json").read_bytes())
    data = advs[0]["data"]
    assert [r["vendor"] for b in data["cna"] for r in b["affectedData"]] == ["GitLab"]
    assert [r["vendor"] for b in data["adp"] for r in b["affectedData"]] == ["gitlab"]
    assert data["adp"][0]["affectedData"][0]["cpes"] == ["cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"]
    gl = cat["gitlab"]
    assert evaluate(gl, "nvd", data, "19.5.3").status == "not_affected"
    assert evaluate(gl, "nvd", data, "16.11.2").status == "affected"
    assert evaluate(gl, "nvd", data, "17.0.0").status == "affected"
    assert evaluate(gl, "nvd", data, "16.10.6").status == "not_affected"


def test_nvd_adp_only_where_the_cna_does_not_name_the_product(cat):
    """CISA's rows still count where the CNA's do not name the product (as for cvelistV5) – and a record without
    sources (stored before) keeps every block as the CNA's."""
    adp_block = {"source": "134c704f-9b21-4f2e-91b3-4a467353bcc0", "affectedData": [{"vendor": "gitlab", "product": "gitlab", "cpes": ["cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"], "defaultStatus": "unknown", "versions": [{"version": "15.0", "lessThan": "17.0.1", "status": "affected", "versionType": "custom"}]}]}
    cna_block = {"source": "cve@example.org", "affectedData": [{"vendor": "Example", "product": "Other thing", "defaultStatus": "unaffected", "versions": [{"version": "1.0", "lessThan": "1.2", "status": "affected"}]}]}
    cna, adp = src._split_affected([cna_block, adp_block], "cve@example.org")
    assert cna == [cna_block] and adp == [adp_block]
    assert src._split_affected([cna_block, adp_block], "") == ([cna_block, adp_block], [])
    assert src._split_affected([{"affectedData": []}], "cve@example.org") == ([{"affectedData": []}], [])
    data = {"configs": [], "desc": "", "cna": src._trim_cna(cna), "adp": src._trim_cna(adp, cpes=True)}
    gl = cat["gitlab"]
    assert evaluate(gl, "nvd", data, "16.0.0").status == "affected"
    assert evaluate(gl, "nvd", data, "17.0.1").status == "not_affected"


def test_nvd_analysis_decides_where_the_cna_wrote_prose(cat):
    """BookStack CVE-2022-40690: JPCERT's row says "versions prior to v22.09" (no range anyone can read), NVD's analysis
    says < 22.09 – a later version is not affected, not "possibly"."""
    _, advs = src.parse_nvd((FIX / "nvd_bookstack_prose.json").read_bytes())
    data, bs = advs[0]["data"], cat["bookstack"]
    assert evaluate(bs, "nvd", data, "22.08").status == "affected"
    assert evaluate(bs, "nvd", data, "22.09").status == "not_affected"
    assert evaluate(bs, "nvd", data, "26.09.2").status == "not_affected"
    assert evaluate(bs, "nvd", {**data, "configs": []}, "26.09.2").status == "possible"  # without the analysis: still open


def test_ranges_written_into_the_version_field():
    """GitHub's advisories and many CNAs write the range into "version" (">= 3.2.0, < 4.7.1", "< 25.7.0"): read as one
    version it was 3.2.0.4.7.1 – the fixed release "listed as affected", everything above the start "newer"."""
    from app.vendor_match import _range_row

    assert _range_row({"version": ">= 3.2.0, < 4.7.1", "status": "affected"}) == {"version": "3.2.0", "lessThan": "4.7.1", "status": "affected"}
    assert _range_row({"version": "< 25.7.0", "status": "affected"}) == {"version": "0", "lessThan": "25.7.0", "status": "affected"}
    assert _range_row({"version": "<= 2.1", "status": "affected"}) == {"version": "0", "lessThanOrEqual": "2.1", "status": "affected"}
    assert _range_row({"version": "= 1.4.0", "status": "affected"}) == {"version": "1.4.0", "status": "affected"}
    for same in ({"version": ">= 1.0", "status": "affected"}, {"version": "1.2.3"}, {"version": "< 2.0", "lessThan": "2.0"}, {"version": "< 2 or so"}):
        assert _range_row(same) == same


def _gitlab_cna(rows: list, default: str = "unaffected") -> dict:
    return {"configs": [], "desc": "", "cna": [{"affectedData": [{"vendor": "GitLab", "product": "GitLab", "defaultStatus": default, "versions": rows}]}]}


def test_range_strings_decide_like_ranges(cat):
    gl = cat["gitlab"]
    data = _gitlab_cna([{"version": ">= 3.2.0, < 4.7.1", "status": "affected"}])
    assert evaluate(gl, "nvd", data, "4.5.0").status == "affected"  # was "newer than listed"
    assert evaluate(gl, "nvd", data, "4.7.1").status == "not_affected"  # was "listed as affected"
    assert evaluate(gl, "nvd", data, "3.1.0").status == "not_affected"
    below = _gitlab_cna([{"version": "< 25.7.0", "status": "affected"}], default="unknown")
    assert evaluate(gl, "nvd", below, "25.6.2").status == "affected" and evaluate(gl, "nvd", below, "25.7.0").status == "not_affected"


def test_cisa_adp_never_over_nvds_analysis_and_never_a_default(cat):
    """CISA's rows count only where neither NVD's analysis nor the CNA names the product – and their defaultStatus
    "affected" is no statement about every other version (cvelistV5 as well)."""
    _, advs = src.parse_nvd((FIX / "nvd_gitlab_adp.json").read_bytes())
    full, gl = advs[0]["data"], cat["gitlab"]
    no_cna = {**full, "cna": []}  # the CNA wrote "n/a" (VMware Cloud Foundation CVE-2022-22948)
    assert evaluate(gl, "nvd", no_cna, "16.10.6").status == "not_affected"  # NVD: < 16.10.6; CISA: 15.11 – < 17.0.1
    only_adp = {**no_cna, "configs": []}
    assert evaluate(gl, "nvd", only_adp, "16.10.6").status == "affected"  # nothing else speaks: CISA's range counts
    assert evaluate(gl, "nvd", only_adp, "19.5.3").status != "affected"  # its default does not
    cvl = {"desc": "", "cna": [], "adp": full["adp"]}
    assert evaluate(gl, "cvelist", cvl, "19.5.3").status != "affected" and evaluate(gl, "cvelist", cvl, "16.0.0").status == "affected"


def test_nvd_records_stored_before_the_split(cat):
    """Stored before 0.1.47: the CNA's and CISA's blocks in one list (the CNA's first) – read apart without a refetch."""
    _, advs = src.parse_nvd((FIX / "nvd_gitlab_adp.json").read_bytes())
    new = advs[0]["data"]
    old = {k: val for k, val in new.items() if k != "adp"} | {"cna": [*new["cna"], *[{"affectedData": [{k: val for k, val in r.items() if k != "cpes"} for r in b["affectedData"]]} for b in new["adp"]]]}
    gl = cat["gitlab"]
    assert evaluate(gl, "nvd", old, "19.5.3").status == "not_affected" and evaluate(gl, "nvd", old, "16.11.2").status == "affected"


def test_cisa_adp_settles_a_possibly_of_nvds_analysis(cat):
    """vCenter: NVD's configurations name exact update CPEs (only "possibly" for others), the CNA wrote "n/a" – CISA's
    range then decides. Here: NVD lists only 17.0.0, CISA 15.11 – < 17.0.1."""
    _, advs = src.parse_nvd((FIX / "nvd_gitlab_adp.json").read_bytes())
    full, gl = advs[0]["data"], cat["gitlab"]
    exact = [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:gitlab:gitlab:17.0.0:*:*:*:community:*:*:*"}]}]}]
    data = {**full, "cna": [], "configs": exact}
    assert evaluate(gl, "nvd", {**data, "adp": []}, "16.0.0").status == "possible"  # NVD alone: not listed
    assert evaluate(gl, "nvd", data, "16.0.0").status == "affected"
    assert evaluate(gl, "nvd", data, "17.0.1").status == "not_affected"


# ---------------------------------------------------------------- 0.1.51: who speaks, the BSI, the vendor's "unaffected", fixes per line


def _adv(source: str, ident: str, data: dict, cves: list | None = None):  # noqa: ANN202
    from app import vendor

    return vendor.Adv(f"{source}:{ident}", source, ident, ident, "", "", cves or [ident], None, "high", False, None, None, data)


def _bsi(products: list) -> dict:
    return {"publisher": "BSI (CSAF)", "products": products}


def _python_cna(rows: list) -> dict:
    return {"configs": [], "desc": "", "cna": [{"affectedData": [{"vendor": "Python Software Foundation", "product": "CPython", "defaultStatus": "unaffected", "versions": rows}]}]}


def test_every_verdict_says_where_it_comes_from(cat, pan):
    """Verdict.detail["by"]: "laut Hersteller" only for the vendor's own word (the drawer: lib/vendor-reason.ts)."""
    gl = cat["gitlab"]
    assert evaluate(cat["panos"], "paloalto", pan["CVE-2026-0322"]["data"], "11.2.4-h5").detail["by"] == "vendor"
    cna = _gitlab_cna([{"version": "17.0", "lessThan": "17.0.1", "status": "affected"}])
    assert evaluate(gl, "nvd", cna, "17.0.0").detail["by"] == "vendor"  # the CNA's rows name the product's vendor
    configs = [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", "versionEndExcluding": "17.0.1"}]}]}]
    assert evaluate(gl, "nvd", {"configs": configs, "cna": [], "desc": ""}, "17.0.0").detail["by"] == "nvd"
    _, advs = src.parse_nvd((FIX / "nvd_gitlab_adp.json").read_bytes())
    only_adp = {**advs[0]["data"], "cna": [], "configs": []}
    assert evaluate(gl, "nvd", only_adp, "16.10.6").detail["by"] == "adp"
    assert evaluate(gl, "cvelist", {"desc": "", "cna": [], "adp": advs[0]["data"]["adp"]}, "16.0.0").detail["by"] == "adp"
    entry = {"name": "GitLab", "vendor": "GitLab", "cpe": "a:gitlab:gitlab", "affected": [{"to": "17.0.1", "text": "<17.0.1"}], "fixed": ["17.0.1"], "not_affected": []}
    assert evaluate(gl, "csaf", _bsi([entry]), "17.0.0").detail["by"] == "bsi"
    assert evaluate(gl, "csaf", {"publisher": "Example CERT", "products": [entry]}, "17.0.0").detail["by"] == "csaf"
    assert evaluate(gl, "csaf", {"publisher": "Siemens ProductCERT (CSAF)", "products": [entry]}, "17.0.0").detail["by"] == "vendor"
    assert evaluate(gl, "csaf", {"publisher": "BSI (CSAF)", "provider": "x", "products": [entry]}, "17.0.0") is None  # a provider speaks only for its vendors
    # a derived verdict keeps the origin of the one it comes from (a short version, a version we cannot compare)
    assert evaluate(gl, "nvd", cna, "17.0").reason == "short_version" and evaluate(gl, "nvd", cna, "17.0").detail["by"] == "vendor"


def test_bsi_every_version_does_not_beat_the_cve_records(cat):
    """D: the BSI lists the product without a version ("alle Versionen") – the CVE records say this version is not
    affected: "possibly", with the BSI named; where the records say "affected", their range (and fix) counts."""
    from app import vendor

    gl = cat["gitlab"]
    bsi = _adv("csaf", "WID-SEC-W-2026-0001", _bsi([{"name": "GitLab", "vendor": "GitLab", "cpe": "a:gitlab:gitlab", "affected": [{"all": True, "text": "alle Versionen"}], "fixed": [], "not_affected": []}]), ["CVE-2026-1"])
    nvd = _adv("nvd", "CVE-2026-1", _gitlab_cna([{"version": "17.0", "lessThan": "17.0.1", "status": "affected"}]))
    g = vendor.groups_of([bsi, nvd])[0]
    assert g["primary"] is bsi
    got = vendor.group_verdict(gl, g, "19.5.3")
    assert (got.status, got.reason, got.detail["by"]) == ("possible", "all_listed_disputed", "bsi")
    got = vendor.group_verdict(gl, g, "17.0.0")
    assert (got.status, got.reason, got.fixed) == ("affected", "in_range", "17.0.1")
    alone = vendor.group_verdict(gl, vendor.groups_of([bsi])[0], "19.5.3")
    assert (alone.status, alone.reason) == ("affected", "all_listed")  # nothing says otherwise


def test_bsi_per_line_bounds_never_beat_the_cnas_affected(cat):
    """D: the BSI merges two CVEs into per-line bounds ("<3.16.0, <3.15.2 …": 3.15.2 fixed) – the vendor says every
    version below 3.16.0 is affected by one of them (CVE-2026-103995): affected, never a false "not affected"."""
    from app import story_details, vendor

    py = cat["python"]
    entry = {"name": "Python", "vendor": "Open Source", "cpe": "a:python:python", "affected": [{"to": "3.16.0", "text": "<3.16.0"}, {"to": "3.15.2", "text": "<3.15.2"}], "fixed": ["3.16.0", "3.15.2"], "not_affected": []}
    bsi = _adv("csaf", "WID-SEC-W-2026-4189", _bsi([entry]), ["CVE-2026-103995", "CVE-2026-114583"])
    one = _adv("nvd", "CVE-2026-103995", _python_cna([{"version": "0", "lessThan": "3.16.0", "status": "affected"}]))
    two = _adv("nvd", "CVE-2026-114583", _python_cna([{"version": "3.15.0", "lessThan": "3.15.2", "status": "affected"}]))
    assert evaluate(py, "csaf", bsi.data, "3.15.2").status == "not_affected"  # the document alone
    g = vendor.groups_of([bsi, one, two])[0]
    got = vendor.group_verdict(py, g, "3.15.2")
    assert (got.status, got.fixed) == ("affected", "3.16.0")
    # the stories' "betrifft deine Systeme" judges the same way
    details = {"kind": "bsi", "publisher": "BSI (CSAF)", "products": [entry], "match": [{"source": "nvd", "data": one.data}, {"source": "nvd", "data": two.data}]}

    class V:
        id, version, label = None, "3.15.2", ""

    rows = story_details.matches(details, [(py, [V()])])
    assert rows and rows[0]["versions"][0]["status"] == "affected"
    every = {**details, "products": [{**entry, "affected": [{"all": True, "text": "alle Versionen"}], "fixed": []}], "match": [{"source": "nvd", "data": _python_cna([{"version": "3.0", "lessThan": "3.10.1", "status": "affected"}])}]}
    assert story_details.matches(every, [(py, [V()])])[0]["versions"][0]["status"] == "possible"


def test_the_vendors_unaffected_against_nvds_range_is_possible(cat):
    """E: the vendor's CNA names its ranges with every other version "unaffected" (or the fix of the installed line),
    NVD's analysis takes in more (GitLab CVE-2026-84284: NVD "< 19.4.2", GitLab "19.3 < 19.3.6", "19.4 < 19.4.2";
    PAN-OS CVE-2026-0262: NVD "< 10.2.7", PAN-OS 10.2 on only) – "possibly", not "affected"."""
    gl = cat["gitlab"]
    data = _gitlab_cna([{"version": "19.3", "lessThan": "19.3.6", "status": "affected"}, {"version": "19.4", "lessThan": "19.4.2", "status": "affected"}])
    data["configs"] = [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", "versionEndExcluding": "19.4.2"}]}]}]
    for v in ("19.3.7", "18.11.0"):
        got = evaluate(gl, "nvd", data, v)
        assert (got.status, got.reason, got.detail["by"]) == ("possible", "vendor_unaffected", "nvd"), v
    assert evaluate(gl, "nvd", data, "19.3.5").status == "affected" and evaluate(gl, "nvd", data, "19.4.1").status == "affected"
    assert evaluate(gl, "nvd", data, "19.4.2").status == "not_affected"
    # CISA's rows are no vendor: NVD's range stays
    _, advs = src.parse_nvd((FIX / "nvd_gitlab_adp.json").read_bytes())
    adp = {**advs[0]["data"], "cna": [], "configs": data["configs"]}
    assert evaluate(gl, "nvd", adp, "18.11.0").status == "affected"


def test_a_fixed_release_above_a_range_in_its_line_is_fixed(cat):
    """F: GitLab ">=12.8, <12.9.8", ">=12.10, <12.10.7", ">=13.0, <13.0.1": 12.9.8 (and 12.9.9) are fixed – was
    "possibly" (not every named version below it); PAN-OS "12.2.0 < 12.2.4" with defaultStatus "affected": 12.2.4-h1 is
    fixed – was "affected" by the default (CVE-2026-0316); a line no row names keeps the default."""
    gl = cat["gitlab"]
    data = _gitlab_cna([{"version": ">=12.8, <12.9.8", "status": "affected"}, {"version": ">=12.10, <12.10.7", "status": "affected"}, {"version": ">=13.0, <13.0.1", "status": "affected"}], default="")
    for v, want in (("12.9.8", "not_affected"), ("12.9.9", "not_affected"), ("12.9.7", "affected"), ("12.10.7", "not_affected"), ("12.11.0", "possible")):
        assert evaluate(gl, "nvd", data, v).status == want, v
    assert evaluate(gl, "nvd", data, "12.9.8").reason == "fixed"
    pan = {"configs": [], "desc": "", "cna": [{"affectedData": [{"vendor": "Palo Alto Networks", "product": "PAN-OS", "defaultStatus": "affected", "versions": [
        {"version": "12.2.0", "lessThan": "12.2.4", "status": "affected", "changes": [{"at": "12.2.4", "status": "unaffected"}], "versionType": "custom"},
        {"version": "11.2.0", "lessThan": "11.2.16", "status": "affected", "changes": [{"at": "11.2.16", "status": "unaffected"}], "versionType": "custom"},
    ]}]}]}
    p = cat["panos"]
    assert evaluate(p, "nvd", pan, "12.2.4-h1").status == "not_affected" and evaluate(p, "nvd", pan, "11.2.16").status == "not_affected"
    assert evaluate(p, "nvd", pan, "12.2.3").status == "affected" and evaluate(p, "nvd", pan, "11.2.4-h23").status == "affected"
    assert (evaluate(p, "nvd", pan, "10.2.13-h5").status, evaluate(p, "nvd", pan, "10.2.13-h5").reason) == ("affected", "default_affected")


def test_commit_ranges_are_no_versions(cat):
    """The Linux kernel's CNA writes commit ranges (versionType "git") next to its semver rows: read as versions they
    made every kernel "affected, fixed in 8dbed691…" (CVE-2026-52943) – only the semver rows decide."""
    lx = cat["linux"]
    git = [{"version": "6fa01ccd883021105e9f8af7d04b9f156fa3494a", "lessThan": "8dbed691e43a50903658130bde0fcb5abc425b37", "status": "affected", "versionType": "git"}]
    semver = [
        {"version": "7.2", "status": "affected"},
        {"version": "0", "lessThan": "7.2", "status": "unaffected", "versionType": "semver"},
        {"version": "7.2.9", "lessThanOrEqual": "7.2.*", "status": "unaffected", "versionType": "semver"},
    ]
    data = {"configs": [], "desc": "", "cna": [{"affectedData": [{"vendor": "Linux", "product": "Linux", "defaultStatus": "unaffected", "versions": git}, {"vendor": "Linux", "product": "Linux", "defaultStatus": "affected", "versions": semver}]}]}
    assert evaluate(lx, "nvd", data, "7.1.13").status == "not_affected"
    got = evaluate(lx, "nvd", data, "7.2.5")
    assert got.status == "affected" and (got.fixed is None or "." in got.fixed)  # never a commit as the fix
    assert evaluate(lx, "nvd", data, "7.2.10").status == "not_affected"
    only_git = {**data, "cna": [{"affectedData": [{"vendor": "Linux", "product": "Linux", "defaultStatus": "unaffected", "versions": git}]}]}
    assert evaluate(lx, "nvd", only_git, "7.1.13") is None  # commits alone say nothing about a release


def test_a_third_partys_possibly_stays_when_not_every_cve_has_a_record(cat):
    """H1 (review 0.1.51): the BSI says "possibly" for a document on two CVEs; one record says "not affected", the
    other CVE has no record that judges the product (prose only, unanalysed) – that one may affect the version: the
    "possibly" stays (group and the stories' drawer). With a judging record for every CVE their "not affected" counts."""
    from app import story_details, vendor

    gl = cat["gitlab"]
    entry = {"name": "GitLab", "vendor": "GitLab", "cpe": "a:gitlab:gitlab", "affected": [{"to": "17.0.5", "text": "<17.0.5"}], "fixed": ["17.0.5"], "not_affected": []}
    bsi = _adv("csaf", "WID-SEC-W-2026-0002", _bsi([entry]), ["CVE-2026-10", "CVE-2026-11"])
    a = _adv("nvd", "CVE-2026-10", _gitlab_cna([{"version": "16.0", "lessThan": "16.0.3", "status": "affected"}]))
    b = _adv("nvd", "CVE-2026-11", {"configs": [], "desc": "prose only", "cna": []})
    assert vendor.group_verdict(gl, vendor.groups_of([bsi])[0], "17.0").status == "possible"
    got = vendor.group_verdict(gl, vendor.groups_of([bsi, a, b])[0], "17.0")
    assert got.status == "possible" and got.detail["by"] == "bsi"
    b2 = _adv("nvd", "CVE-2026-11", _gitlab_cna([{"version": "15.0", "lessThan": "15.0.1", "status": "affected"}]))
    assert vendor.group_verdict(gl, vendor.groups_of([bsi, a, b2])[0], "17.0").status == "not_affected"  # both judged

    class V:
        id, version, label = None, "17.0", ""

    details = {"kind": "bsi", "publisher": "BSI (CSAF)", "products": [entry], "cves": ["CVE-2026-10", "CVE-2026-11"], "match": [{"source": "nvd", "data": a.data}, {"source": "nvd", "data": b.data}]}
    rows = story_details.matches(details, [(gl, [V()])])
    assert rows and rows[0]["versions"][0]["status"] == "possible"
    both = {**details, "match": [{"source": "nvd", "data": a.data}, {"source": "nvd", "data": b2.data}]}
    assert story_details.matches(both, [(gl, [V()])]) == []  # not affected: not shown


def test_an_inclusive_bound_is_no_fix(cat):
    """M1 (review 0.1.51): "≤ 12.9.7" or "≤ 12.9.*" names the last affected release known, not a fix – above it the
    defaultStatus "affected" still speaks; only an exclusive "< X" is a fix of its line."""
    gl = cat["gitlab"]
    incl = _gitlab_cna([{"version": "12.9.0", "lessThanOrEqual": "12.9.7", "status": "affected"}], default="affected")
    assert (evaluate(gl, "nvd", incl, "12.9.8").status, evaluate(gl, "nvd", incl, "12.9.8").reason) == ("affected", "default_affected")
    line = _gitlab_cna([{"version": "12.0", "lessThanOrEqual": "12.9.*", "status": "affected"}], default="affected")
    assert evaluate(gl, "nvd", line, "12.10.1").reason == "default_affected"
    excl = _gitlab_cna([{"version": "12.9.0", "lessThan": "12.9.8", "status": "affected"}], default="affected")
    assert (evaluate(gl, "nvd", excl, "12.9.8").status, evaluate(gl, "nvd", excl, "12.9.8").reason) == ("not_affected", "fixed")


def test_only_the_vendors_own_ranges_outweigh_nvds_range(cat):
    """L4 (review 0.1.51): "possibly" against NVD's "affected" only where the product's own vendor (catalogue vendor or
    CNA names) delimits ranges – a CNA listing single versions with defaultStatus "unaffected" (VulDB, MITRE style)
    leaves NVD's analysis as it is."""
    gl = cat["gitlab"]
    configs = [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", "versionEndExcluding": "19.4.2"}]}]}]
    single = {**_gitlab_cna([{"version": "19.4.0", "status": "affected"}, {"version": "19.4.1", "status": "affected"}]), "configs": configs}
    assert evaluate(gl, "nvd", single, "18.11.0").status == "affected"  # single versions: NVD's range stays
    ranged = {**_gitlab_cna([{"version": "19.4", "lessThan": "19.4.2", "status": "affected"}]), "configs": configs}
    assert evaluate(gl, "nvd", ranged, "18.11.0").reason == "vendor_unaffected"
    from app.vendor_match import _vendor_ranges

    assert _vendor_ranges(gl, ranged["cna"]) and not _vendor_ranges(gl, single["cna"])
    assert not _vendor_ranges({**gl, "vendor": "", "cna": None}, ranged["cna"])  # no vendor known: unsure, no demotion


def test_a_two_part_end_is_no_fix_of_the_major_line(cat):
    """Final review 0.1.51: "< 12.9" with defaultStatus "affected" said nothing about 12.10.1 – the defaultStatus
    decides there, not a "fix" of the whole major line 12."""
    gl = cat["gitlab"]
    d = _gitlab_cna([{"version": "12.0", "lessThan": "12.9", "status": "affected"}], default="affected")
    assert (evaluate(gl, "nvd", d, "12.10.1").status, evaluate(gl, "nvd", d, "12.10.1").reason) == ("affected", "default_affected")
    assert evaluate(gl, "nvd", d, "12.8.3").status == "affected"
    three = _gitlab_cna([{"version": "12.0", "lessThan": "12.9.0", "status": "affected"}], default="affected")
    assert evaluate(gl, "nvd", three, "12.9.4").reason == "fixed"  # a three-part end in the line: its fix


def test_a_document_with_the_full_stored_cve_list_is_never_complete(cat):
    """Optional (final review 0.1.51): a stored CSAF document keeps its first 30 CVEs – with 30 of them it may name
    more, its "possibly" stays even when all 30 records say "not affected"."""
    from app import vendor

    gl = cat["gitlab"]
    entry = {"name": "GitLab", "vendor": "GitLab", "cpe": "a:gitlab:gitlab", "affected": [{"to": "17.0.5", "text": "<17.0.5"}], "fixed": ["17.0.5"], "not_affected": []}
    cves = [f"CVE-2026-{20000 + i}" for i in range(vendor.STORED_CVES)]
    bsi = _adv("csaf", "WID-SEC-W-2026-0030", _bsi([entry]), cves)
    recs = [_adv("nvd", c, _gitlab_cna([{"version": "16.0", "lessThan": "16.0.3", "status": "affected"}])) for c in cves]
    assert vendor.group_verdict(gl, vendor.groups_of([bsi, *recs])[0], "17.0").status == "possible"
    short = _adv("csaf", "WID-SEC-W-2026-0031", _bsi([entry]), cves[:29])
    assert vendor.group_verdict(gl, vendor.groups_of([short, *recs[:29]])[0], "17.0").status == "not_affected"
