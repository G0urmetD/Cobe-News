"""Bounds on another scale than the installed version (catalogue sweep 0.1.52): a knowledge-base article or a commit
where a record should name a version was read by the generic rule as a version number – "KB88287" as 88287, so every
VMware Cloud Foundation release was "betroffen, Fix: KB88287"; BSI's "commit 8670835" was FFmpeg's fix. They are no
versions: the row cannot be read ("möglicherweise"), the fix list leaves them out. Records trimmed from the live data."""

import pytest

from app import vendor_catalog as catalog
from app import version_input
from app.vendor_match import bound_v, evaluate

# CVE-2023-34048 as stored (NVD record: no CPE configuration for VCF, CISA's ADP rows with CPE names)
VCF_ADP = {
    "configs": [],
    "cna": [{"affectedData": [{"vendor": "VMware", "product": "VMware vCenter Server", "versions": [{"version": "8.0", "lessThan": "8.0U2", "status": "affected"}]}]}],
    "adp": [
        {
            "affectedData": [
                {"cpes": ["cpe:2.3:a:vmware:cloud_foundation:4.0:*:*:*:*:*:*:*"], "vendor": "vmware", "product": "cloud_foundation", "defaultStatus": "unknown",
                 "versions": [{"status": "affected", "version": "4.0", "lessThan": "KB88287", "versionType": "custom"}]},
                {"cpes": ["cpe:2.3:a:vmware:cloud_foundation:5.0:*:*:*:*:*:*:*"], "vendor": "vmware", "product": "cloud_foundation", "defaultStatus": "unknown",
                 "versions": [{"status": "affected", "version": "5.0", "lessThan": "KB88287", "versionType": "custom"}]},
            ]
        }
    ],
    "desc": "vCenter Server contains an out-of-bounds write vulnerability in the implementation of the DCERPC protocol.",
}  # fmt: skip

# WID-SEC-W-2026-2526 (BSI CSAF): commits in the list of fixed versions
FFMPEG_BSI = {
    "kind": "bsi",
    "products": [
        {"cpe": "a:ffmpeg:ffmpeg", "name": "ffmpeg", "vendor": "Open Source", "fixed": ["commit 8670835", "commit b506faf"], "affected": [{"to": "8.1.2", "text": "<=8.1.2", "to_incl": True}]}
    ],
}


@pytest.fixture(scope="module")
def cat():
    return {p["key"]: p for p in catalog.load()["products"]}


@pytest.mark.parametrize("text", ["KB88287", "kb 5048033", "KB-5048033", "commit 8670835"])
def test_references_are_no_version(text):
    assert bound_v("generic", text) is None


@pytest.mark.parametrize("text", ["8670835", "R81.20", "7.2.5 (build 208)", "12.3.2.4934"])
def test_versions_stay_versions(text):
    assert bound_v("generic", text) is not None


def test_vcf_is_no_longer_affected_up_to_a_kb_article(cat):
    for version in ("9.0.2.0", "5.2.3"):
        r = evaluate(cat["vmware-cloud-foundation"], "nvd", VCF_ADP, version)
        assert r is not None and r.status == "possible" and r.fixed is None, (version, r)  # was: affected, Fix KB88287


def test_a_commit_is_no_fixed_version(cat):
    r = evaluate(cat["ffmpeg"], "csaf", FFMPEG_BSI, "8.1.1")
    assert r is not None and r.status == "affected" and r.fixed is None  # was: Fix "commit 8670835"


# CVE-2021-45491 as stored (NVD): "3CX System through 2022-03-17" – a date as versionEndIncluding
CX_DATE = {
    "configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:3cx:3cx:*:*:*:*:*:*:*:*", "versionEndIncluding": "2022-03-17"}]}]}],
    "cna": [],
    "desc": "3CX System through 2022-03-17 stores cleartext passwords in a database.",
}


def test_a_date_bound_is_not_compared_with_a_version(cat):
    r = evaluate(cat["3cx"], "nvd", CX_DATE, "20.0.4")
    assert r is not None and r.status == "possible" and r.reason == "other_scale"  # was: affected "bis einschließlich 2022-03-17"
    # a product versioned by date is compared as before
    dated = {**cat["3cx"], "key": "dated"}
    assert evaluate(dated, "nvd", CX_DATE, "2022.03.17").status == "affected"
    assert evaluate(dated, "nvd", CX_DATE, "2022.04.01").status == "not_affected"


# CVE-2023-36869 as stored (NVD): Microsoft's CNA rows name builds by their date ("< 20230601.3"), NVD lists releases
ADO_DATE_BUILD = {
    "configs": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:microsoft:azure_devops_server:2020.1.2:-:*:*:*:*:*:*"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:microsoft:azure_devops_server:2022.0.1:-:*:*:*:*:*:*"},
    ]}]}],
    "cna": [{"affectedData": [
        {"vendor": "Microsoft", "product": "Azure DevOps Server 2020.1.2", "defaultStatus": "unaffected", "versions": [{"version": "2020.1.0", "lessThan": "20230601.3", "versionType": "custom", "status": "affected"}]},
        {"vendor": "Microsoft", "product": "Azure DevOps Server 2022.0.1", "defaultStatus": "unaffected", "versions": [{"version": "2022.0.0", "lessThan": "20230602.5", "versionType": "custom", "status": "affected"}]},
    ]}],
    "desc": "Azure DevOps Server Spoofing Vulnerability",
}  # fmt: skip


def test_a_build_named_by_its_date_is_not_compared_with_a_release(cat):
    p = cat["azure-devops-server"]
    r = evaluate(p, "nvd", ADO_DATE_BUILD, "2022.2 Patch 12")
    assert r is not None and r.status == "possible" and r.reason == "other_scale" and r.fixed is None  # was: affected, Fix 20230601.3


# CVE-2023-25143 as stored (NVD): the SaaS edition counts 14.0.N, the on-prem server 14.0.0.N
APEX_ONE = {
    "configs": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:trendmicro:apex_one:*:*:*:*:saas:*:*:*", "versionEndExcluding": "14.0.11960"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:trendmicro:apex_one:2019:-:*:*:*:*:*:*"},
    ]}]}],
    "cna": [{"affectedData": [{"vendor": "Trend Micro, Inc.", "product": "Trend Micro Apex One", "defaultStatus": "",
                               "versions": [{"version": "2019 (14.0)", "lessThan": "14.0.0.11564", "status": "affected", "versionType": "semver"}]}]}],
    "desc": "A vulnerable component of Trend Micro Apex One and Apex One as a Service could allow an attacker",
}  # fmt: skip


def test_apex_one_on_prem_is_not_measured_by_the_saas_numbers(cat):
    p = cat["trendmicro-apex-one"]
    r = evaluate(p, "nvd", APEX_ONE, "14.0.0.12980")
    assert r is not None and r.status == "not_affected"  # was: affected, Fix 14.0.11960 (the SaaS build, 12980 read as patch 0)
    assert evaluate(p, "nvd", APEX_ONE, "14.0.0.11000").status == "affected"


# CVE-2023-44153 as stored (NVD): Acronis' CNA counts global builds ("Cyber Protect 15 < 35979"), installed "16 (build 39938)"
ACRONIS = {
    "configs": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:acronis:cyber_protect:*:*:*:*:*:*:*:*", "versionEndExcluding": "15"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:acronis:cyber_protect:15:update5:*:*:*:*:*:*"},
    ]}]}],
    "cna": [{"affectedData": [{"vendor": "Acronis", "product": "Acronis Cyber Protect 15", "defaultStatus": "unaffected",
                               "versions": [{"version": "unspecified", "lessThan": "35979", "status": "affected", "versionType": "semver"}]}]}],
    "desc": "The following products are affected: Acronis Cyber Protect 15 (Linux, macOS, Windows) before build 35979.",
}  # fmt: skip
# CVE-2025-49731 (Microsoft CNA): "Microsoft Teams for Desktop" lessThan "25060212643"
TEAMS = {
    "configs": [],
    "cna": [{"affectedData": [{"vendor": "Microsoft", "product": "Microsoft Teams for Desktop", "defaultStatus": "",
                               "versions": [{"version": "1.0.0", "lessThan": "25060212643", "status": "affected", "versionType": "custom"}]}]}],
    "desc": "Improper handling of insufficient permissions or privileges in Microsoft Teams allows an authorized attacker to elevate privileges locally.",
}  # fmt: skip


def test_a_bare_build_far_above_the_version_is_not_compared(cat):
    r = evaluate(cat["acronis-cyber-protect"], "nvd", ACRONIS, "16 (build 39938)")
    assert r is not None and r.status == "possible" and r.fixed is None  # was: affected, Fix 35979 (35979 read as version 35979)
    r = evaluate(cat["teams"], "nvd", TEAMS, "24335.206.3315.1658")
    assert r is not None and r.status == "possible" and r.reason == "other_scale"  # was: affected, Fix 25060212643
    # a bare number on the version's own scale stays a version (Citrix "< 2402" for 2311.1)
    assert bound_v("generic", "2402") is not None


# CVE-2022-22962 as stored (NVD): Horizon's release named by year and month ("< 2203") – today 8.2412
HORIZON = {
    "configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:vmware:horizon:*:*:*:*:*:*:*:*", "versionEndExcluding": "2203"}]}]}],
    "cna": [],
    "desc": "VMware Horizon Agent for Linux (prior to 22.x) contains a local privilege escalation vulnerability.",
}  # fmt: skip


def test_an_old_yymm_bound_is_not_above_every_8x_release(cat):
    r = evaluate(cat["horizon"], "nvd", HORIZON, "8.2412")
    assert r is not None and r.status == "possible" and r.reason == "other_scale"  # was: affected, Fix 2203


def test_a_month_bound_is_not_compared_with_a_version(cat):
    """CVE-2021-27223 (NVD): Kaspersky "< 2021-06" for Endpoint Security 12.7 – was "affected, Fix 2021-06"."""
    rec = {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:kaspersky:endpoint_security:*:*:*:*:*:*:*:*", "versionEndExcluding": "2021-06"}]}]}], "cna": []}
    p = {"key": "k", "scheme": "generic", "cpes": ["a:kaspersky:endpoint_security"]}
    assert evaluate(p, "nvd", rec, "12.7").reason == "other_scale"
    assert evaluate(p, "nvd", rec, "2021.05").status == "affected"  # a version written as a date compares


def test_ipfire_core_update_cpe_is_the_core_number(cat):
    """NVD writes IPFire's Core Updates in the update field ("2.29:core_update195"); read as "2.29 core update195" the
    word pair made it unreadable – every IPFire record was "möglicherweise"."""
    rec = {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:ipfire:ipfire:2.29:core_update195:*:*:*:*:*:*"}]}]}], "cna": []}
    p = cat["ipfire"]
    assert evaluate(p, "nvd", rec, "2.29 Core 195").status == "affected"
    assert evaluate(p, "nvd", rec, "2.29 Core 196").status == "not_affected"


@pytest.mark.parametrize(
    ("cpe", "bound", "version"),
    [
        # CVE-2024-21402 (NVD): Office written as "Version 2401, Build 17231.20236" – compared form 16.0.18227.20162
        ("a:microsoft:365_apps", "2401.17231.20236", "16.0.18227.20162"),
        # CVE-2019-6187 (NVD): Lenovo XCC firmware codes ("tei392m") – the generic rule read 392.13, above 9.40
        ("a:lenovo:xclarity_controller", "tei392m", "9.40"),
        # CVE-2021-36230 (NVD): "202107-1" (a release by year and month) for Terraform 1.17.1
        ("a:hashicorp:terraform", "202107-1", "1.17.1"),
    ],
)
def test_other_scale_end_bounds(cpe, bound, version):
    rec = {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": f"cpe:2.3:{cpe}:*:*:*:*:*:*:*:*", "versionEndIncluding": bound}]}]}], "cna": []}
    r = evaluate({"key": "x", "scheme": "generic", "cpes": [cpe]}, "nvd", rec, version)
    assert r is not None and r.status == "possible" and r.reason == "other_scale"  # was: affected


# CVE-2022-45137 as stored (NVD): WAGO bounds by the firmware index ("16 – < 22", FW23 listed)
WAGO = {
    "configs": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:o:wago:pfc200_firmware:*:*:*:*:*:*:*:*", "versionStartIncluding": "16", "versionEndExcluding": "22"},
        {"vulnerable": True, "criteria": "cpe:2.3:o:wago:pfc200_firmware:22:-:*:*:*:*:*:*"},
        {"vulnerable": True, "criteria": "cpe:2.3:o:wago:pfc200_firmware:23:*:*:*:*:*:*:*"},
    ]}]}],
    "cna": [],
}  # fmt: skip


@pytest.mark.parametrize(
    ("version", "status"),
    [("04.02.13(23)", "affected"), ("03.06.09(18)", "affected"), ("04.06.03(28)", "not_affected"), ("FW28", "not_affected"), ("03.00.39(12)", "not_affected")],
)
def test_wago_firmware_by_its_index(cat, version, status):
    """04.02.13(23) was read as 4.2.13.23 – below "22" and not FW23: "nicht betroffen"; 04.06.03(28) "affected, Fix 22"."""
    r = evaluate(cat["wago-pfc"], "nvd", WAGO, version)
    assert r is not None and r.status == status, r


@pytest.mark.parametrize(("typed", "stored"), [("04.06.03", "04.06.03"), ("4.6.3", "04.06.03"), ("Firmware version 04.06.03", "04.06.03"), ("04.06.03(28)", "04.06.03(28)")])
def test_wago_without_its_index_is_accepted_as_unknown(cat, typed, stored):
    """The firmware without "(28)": not refused – stored, and "möglicherweise" where the index decides (review 0.1.52)."""
    got = version_input.check(cat["wago-pfc"], typed)
    assert got.ok and got.value == stored, got
    r = evaluate(cat["wago-pfc"], "nvd", WAGO, stored)
    assert r is not None and r.status == ("not_affected" if "(" in stored else "possible"), r


@pytest.mark.parametrize("typed", ["2.27 Core Update 174", "2.27 - Core Update 174", "IPFire 2.27 (x86_64) - Core Update 174", "2.27 Core 174", "2.27 core update 174"])
def test_ipfire_in_its_own_words(cat, typed):
    """IPFire's web UI writes "IPFire 2.27 (x86_64) - Core Update 174": stored as the NVD's CPEs are read, "2.27 Core 174"."""
    got = version_input.check(cat["ipfire"], typed)
    assert got.ok and got.value == "2.27 Core 174", got
    rec = {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:ipfire:ipfire:2.27:core_update174:*:*:*:*:*:*"}]}]}], "cna": []}
    assert evaluate(cat["ipfire"], "nvd", rec, got.value).status == "affected"
