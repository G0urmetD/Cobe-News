"""Katalog-Erweiterung (0.1.45): new products, aliases, categories, the Windows roles' filters, Open-Xchange's CSAF
provider – and the catalogue-wide checks the review asked for (no CPE in two products without a filter or a reason)."""

from collections import defaultdict

import pytest

from app import vendor_catalog as catalog
from app import version_input
from app.vendor_match import evaluate, filter_ok
from tests.test_vendor_catalog import _search


@pytest.fixture(scope="module")
def cat():
    return {p["key"]: p for p in catalog.load()["products"]}


NEW = (
    "windows-wsus", "windows-ad-ds", "windows-rds", "windows-nps", "windows-rras", "windows-dhcp",
    "trellix-epo", "trellix-ens", "beyondtrust-remote-support", "beyondtrust-pra", "papercut", "3cx", "avm-fritzos",
    "draytek-vigor", "ncp-secure-client", "ncp-vpn-server", "baramundi", "matrix42-empirum", "aagon-acmp", "ivanti-dsm",
    "cisco-sdwan-manager", "omnissa-workspace-one-uem", "omnissa-workspace-one-access", "ivanti-sentry",
    "ivanti-neurons-itsm", "ivanti-avalanche", "sonicwall-netextender", "sonicwall-email-security", "n-able-n-central",
    "ninjaone", "datto-rmm", "simplehelp", "splashtop", "open-xchange", "grommunio", "mailcow", "cryptshare", "kiteworks",
    "totemomail", "barracuda-esg", "univention-ucs", "openldap", "rsa-securid-am", "sailpoint-identityiq",
    "manageengine-opmanager", "whatsup-gold", "librenms", "owncloud", "seafile", "dvelop-documents", "elo-ecm",
    "docuware", "teamcity", "gitea", "starface", "innovaphone", "swyx", "auerswald", "unify-openscape", "mitel-mivoice",
    "lenovo-xcc", "fujitsu-irmc", "dell-openmanage-enterprise", "igel-os", "citrix-workspace-app", "citrix-storefront",
    "gdata-business", "withsecure-elements", "eset-protect", "kaspersky-security-center", "phoenix-mguard",
    "siemens-sinema-rc", "siemens-ruggedcom-ros", "teltonika-rutos", "insys-icom", "ewon", "mbconnect24",
    "hpe-storeonce", "dell-powerstore", "fujitsu-eternus", "pure-purity", "mfp-hp", "mfp-canon", "mfp-kyocera",
    "mfp-konica-minolta", "sap-hana", "sap-business-one", "sap-web-dispatcher", "sap-router", "fortiextender",
    "fortisoar", "fortiwlm", "hpe-ilo5", "hpe-ilo7", "dell-idrac10", "cisco-sewm",
)  # fmt: skip


def test_new_products_are_complete(cat):
    """Every new product: a category, a 'where is the version' text, CPEs or (kw only) a hint saying so; an example
    the product itself takes where a version is compared."""
    for k in NEW:
        p = cat[k]
        assert p["category"] != "other" or k == "papercut", k
        assert p.get("where"), k
        assert p["cpes"] or p.get("hint") in ("nocpe", "mfp"), k
        assert p.get("kw"), k
        if p.get("example"):
            assert version_input.check(p, p["example"]).ok, (k, p["example"])
        elif p["cpes"]:
            assert p.get("hint") == "per_model", k  # only per-model firmware without a common version form


def test_no_cpe_in_two_products_without_a_filter_or_a_reason(cat):
    """The same CPE in two products would show every CVE twice: allowed only for a product that narrows it (filter –
    the Windows roles; cpe_editions – Firefox ESR, Jenkins LTS) or for the pairs named here with their reason."""
    allowed = {
        frozenset({"panos", "panorama"}),  # Panorama runs PAN-OS (hint panorama: "möglicherweise" unless named)
        frozenset({"wazuh", "wazuh-agent"}),  # one CPE for server and agent in NVD
        frozenset({"windows-server", "hyper-v-server-2019"}),  # the standalone Hyper-V Server is a Windows Server 2019
        frozenset({"ansible", "ansible-core"}),  # both endoflife.date products, NVD has one CPE
    }
    by = defaultdict(list)
    for p in cat.values():
        narrowed = {c for c, _ in p.get("cpe_editions") or []}
        for c in p["cpes"]:
            if not p.get("filter") and c not in narrowed:
                by[c].append(p["key"])
    bad = {c: ks for c, ks in by.items() if len(ks) > 1 and frozenset(ks) not in allowed}
    assert not bad, bad


@pytest.mark.parametrize(
    ("query", "key"),
    [
        ("VBR", "veeam-backup-and-replication"),
        ("MECM", "configmgr"),
        ("ConfigMgr", "configmgr"),
        ("SCCM", "configmgr"),
        ("Lync", "skype-business-server"),
        ("M365 Apps", "office"),
        ("Office 365", "office"),
        ("Click-to-Run", "office"),
        ("Windows Defender", "defender"),
        ("MDE", "defender-endpoint"),
        ("SEP", "symantec-endpoint"),
        ("OfficeScan", "trendmicro-apex-one"),
        ("Server & Workload Protection", "trendmicro-deep-security"),
        ("KES", "kaspersky-endpoint"),
        ("ConnectWise Control", "connectwise-screenconnect"),
        ("Check_MK", "checkmk"),
        ("NSX-T", "vmware-nsx"),
        ("vROps", "vmware-aria-operations"),
        ("vRealize Operations", "vmware-aria-operations"),
        ("VCF", "vmware-cloud-foundation"),
        ("XenApp", "citrix-vad"),
        ("XenDesktop", "citrix-vad"),
        ("Domain Controller", "windows-ad-ds"),
        ("AD DS", "windows-ad-ds"),
        ("WS2022", "windows-server"),
        ("SRX", "junos"),
        ("Juniper SRX", "junos"),
        ("Db2", "ibm-db2"),
        ("VMware Harbor Registry", "harbor"),
        ("VMware Horizon", "horizon"),
        ("WSUS", "windows-wsus"),
        ("RD Gateway", "windows-rds"),
        ("NPS", "windows-nps"),
        ("RRAS", "windows-rras"),
        ("McAfee ePO", "trellix-epo"),
        ("Bomgar", "beyondtrust-remote-support"),
        ("FRITZ!Box", "avm-fritzos"),
        ("Fritzbox", "avm-fritzos"),
        ("vManage", "cisco-sdwan-manager"),
        ("AirWatch", "omnissa-workspace-one-uem"),
        ("vIDM", "omnissa-workspace-one-access"),
        ("IronPort", "cisco-esa"),
        ("ESA", "cisco-esa"),
        ("SMA", "cisco-sewm"),
        ("XCC", "lenovo-xcc"),
        ("iLO 5", "hpe-ilo5"),
        ("iDRAC10", "dell-idrac10"),
        ("Talk2M", "ewon"),
        ("SAP B1", "sap-business-one"),
        ("Citrix Receiver", "citrix-workspace-app"),
        ("USG FLEX", "zyxel-firewall"),
    ],
)
def test_search_finds_new_names(query, key):
    assert key in _search(query)


def test_endoflife_products_in_their_categories(cat):
    want = {
        "sns-smc": "firewall", "horizon": "virtualization", "clamav": "security", "squid": "lb", "samba": "storage",
        "openzfs": "storage", "pgadmin": "database", "phpmyadmin": "database", "centreon": "monitoring",
        "telegraf": "monitoring", "jaeger": "monitoring", "ldap-account-manager": "iam", "teleport": "remote",
        "boundary": "remote", "artifactory": "dev", "nexus": "dev", "gerrit": "dev", "forgejo": "dev",
        "gitlab-runner": "dev", "bigbluebutton": "collaboration", "greenlight": "collaboration",
        "rocket-chat": "collaboration", "dotnetfx": "web", "cert-manager": "containers",
    }  # fmt: skip
    for k, c in want.items():
        assert cat[k]["category"] == c, (k, cat[k]["category"])
    assert cat["phpmyadmin"]["osv"]  # moved with its OSV package
    assert "Check_MK" in cat["checkmk"]["aliases"]  # a labelless entry may add aliases now


def test_cisco_esa_and_sma_are_two_products(cat):
    esa, sma = cat["cisco-esa"], cat["cisco-sewm"]
    assert "a:cisco:asyncos" not in esa["cpes"]  # AsyncOS is ESA, WSA and SMA – too broad
    assert "a:cisco:secure_email_gateway" in esa["cpes"] and "a:cisco:secure_email_and_web_manager" in sma["cpes"]
    assert not set(esa["cpes"]) & set(sma["cpes"])


def test_zyxel_has_cpes_and_its_cna_series(cat):
    z = cat["zyxel-firewall"]
    assert "o:zyxel:usg_flex_100_firmware" in z["cpes"] and "o:zyxel:atp100_firmware" in z["cpes"]
    assert z["hint"] == "per_model" and ["Zyxel", "USG FLEX series firmware"] in z["cna"]
    rec = {"desc": "x", "configs": [], "cna": [{"affectedData": [{"vendor": "Zyxel", "product": "USG FLEX series firmware", "versions": [{"version": "V5.00", "lessThan": "V5.39", "status": "affected"}]}]}]}
    assert evaluate(z, "nvd", rec, "5.38") is not None


def test_windows_role_filters_take_alternatives(cat):
    rds = cat["windows-rds"]
    assert filter_ok(rds, {"desc": "Windows Remote Desktop Gateway (RD Gateway) Service Remote Code Execution Vulnerability"})
    assert filter_ok(rds, {"desc": "Windows Remote Desktop Licensing Service Denial of Service Vulnerability"})
    assert not filter_ok(rds, {"desc": "Windows Kerberos Elevation of Privilege Vulnerability"})
    dc = cat["windows-ad-ds"]
    for desc in ("Windows Kerberos Elevation of Privilege Vulnerability", "Netlogon Elevation of Privilege Vulnerability", "Active Directory Domain Services Elevation of Privilege Vulnerability"):
        assert filter_ok(dc, {"desc": desc}), desc
    assert not filter_ok(dc, {"desc": "Windows DHCP Server Remote Code Execution Vulnerability"})
    assert filter_ok(cat["windows-dhcp"], {"desc": "Windows DHCP Server Remote Code Execution Vulnerability"})
    assert filter_ok(cat["windows-wsus"], {"desc": "Windows Server Update Service (WSUS) Remote Code Execution Vulnerability"})
    assert filter_ok(cat["adcs"], {"desc": "Active Directory Certificate Services Elevation of Privilege"})  # one word: as before
    assert filter_ok({"key": "x"}, {"desc": ""})  # no filter: every CVE


def test_a_windows_role_cve_counts_only_for_its_role(cat):
    rec = {
        "desc": "Windows Routing and Remote Access Service (RRAS) Remote Code Execution Vulnerability",
        "configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", "versionStartIncluding": "10.0.20348.0", "versionEndExcluding": "10.0.20348.3807"}]}]}],
        "cna": [],
    }
    assert evaluate(cat["windows-rras"], "nvd", rec, "10.0.20348.2762").status == "affected"
    assert evaluate(cat["windows-rras"], "nvd", rec, "10.0.20348.3807").status == "not_affected"
    assert evaluate(cat["windows-nps"], "nvd", rec, "10.0.20348.2762") is None
    assert evaluate(cat["windows-server"], "nvd", rec, "10.0.20348.2762").status == "affected"


def test_horizon_yymm_is_stored_as_the_lines_write_it(cat):
    h = cat["horizon"]
    for typed, stored in (("2412", "8.2412"), ("2412.1", "8.2412.1"), ("Horizon 8 2503", "8.2503"), ("8.2406", "8.2406")):
        c = version_input.check(h, typed)
        assert c.ok and c.value == stored, (typed, c)
    assert version_input.effective(h, "2412") == "8.2412"  # a version moved from vmware-horizon compares in this form


def test_open_xchange_csaf_provider():
    prov = next(p for p in catalog.CSAF_PROVIDERS if p["key"] == "openxchange")
    assert prov["domain"] == "www.open-xchange.com" and prov["vendors"] == ["Open-Xchange"]
    assert catalog.product("open-xchange")["vendor"] == "Open-Xchange"


def test_citrix_products_say_where_their_bulletins_come_from(cat):
    for k in ("netscaler-adc", "netscaler-gateway", "citrix-vad", "citrix-workspace-app", "citrix-storefront"):
        assert cat[k].get("hint") == "citrix", k
    text = catalog.DATA.texts["hints"]["citrix"]
    assert "CSAF" in text["de"] and "CSAF" in text["en"]
