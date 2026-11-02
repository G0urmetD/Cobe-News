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
