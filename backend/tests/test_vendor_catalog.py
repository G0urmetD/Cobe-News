"""The Vendor News catalogue on disk: the overlay fingerprint, a refreshed copy built from an older overlay (it gets the
current overlay applied on load instead of hiding new products until the next refresh), copies that cannot be used, and
the password manager category."""

import json
from pathlib import Path

import pytest

from app import vendor
from app import vendor_catalog as catalog
from app.vendor_catalog import CATEGORIES, OVERLAY


def P(key: str, label: str, vendor: str, cat: str, cpes: tuple = (), **kw) -> dict:  # noqa: N802 - an overlay entry as the loader returns it
    return {"key": key, "label": label, "vendor": vendor, "category": cat, "cpes": list(cpes), **kw}

FIX = Path(__file__).parent / "fixtures"
LATER = "2099-01-01T00:00:00+00:00"  # newer than the bundled copy


@pytest.fixture(autouse=True)
def data_file(monkeypatch, tmp_path):
    """The refreshed copy lives in this test's folder; the cache is cleared before and after."""
    path = tmp_path / "vendor_catalog.json"
    monkeypatch.setattr(catalog, "_data_file", lambda: path)
    catalog._cache.stamp = ()
    yield path
    catalog._cache.stamp = ()


def _eol() -> dict:
    return json.loads((FIX / "vendor" / "eol_full.json").read_text())


def _write(path: Path, cat: dict) -> None:
    path.write_text(json.dumps(cat))
    catalog._cache.stamp = ()


def test_catalog_carries_overlay_fingerprint_and_eol_part():
    cat = catalog.build(_eol())
    fp = catalog.fingerprint()
    assert cat["format"] == catalog.FORMAT == 2 and cat["overlay"] == fp and len(fp) == 64
    assert fp == catalog.fingerprint()  # stable
    assert {r["key"] for r in cat["eol_products"]} == {p["name"] for p in _eol()["result"]}
    panos = next(r for r in cat["eol_products"] if r["key"] == "panos")
    assert set(panos) <= {"key", "label", "category", "cpes", "aliases", "version_cmd"}  # compact, before the overlay
    assert "o:paloaltonetworks:pan-os" not in panos.get("cpes", []) and next(p for p in cat["products"] if p["key"] == "panos")["cpes"] == ["o:paloaltonetworks:pan-os"]
    # applying the overlay again to the kept part gives the same catalogue
    again = catalog.apply_overlay(cat["eol_products"], cat["releases"], cat["eol_generated_at"], cat["generated_at"])
    assert again == cat
    bundled = catalog.load()
    assert bundled["overlay"] == fp and len(bundled["eol_products"]) >= 400


def test_refreshed_copy_from_older_overlay_gets_current_overlay(monkeypatch, data_file):
    # a daily refresh while the old overlay (without the new product) was running …
    monkeypatch.setattr(catalog, "OVERLAY", [o for o in OVERLAY if o["key"] != "keepass"])
    old = catalog.build(_eol())
    old["generated_at"] = LATER
    _write(data_file, old)
    assert "keepass" not in {p["key"] for p in catalog.load()["products"]}
    # … then a rollout with new overlay entries
    new = P("example-vault", "Example Vault", "Example Corp", "passwords", ("a:example:example_vault",), kw=["Example Vault"])
    monkeypatch.setattr(catalog, "OVERLAY", [*OVERLAY, new])
    catalog._cache.stamp = ()
    cat = catalog.load()
    by = {p["key"]: p for p in cat["products"]}
    assert cat["overlay"] == catalog.fingerprint() != old["overlay"]
    assert cat["generated_at"] == LATER and cat["eol_generated_at"] == old["eol_generated_at"]  # still the refreshed copy …
    assert "postgresql" not in by and set(cat["releases"]) == set(old["releases"])  # … with its endoflife.date data
    assert by["example-vault"]["category"] == "passwords" and by["example-vault"]["cpes"] == ["a:example:example_vault"]
    assert by["keepass"]["category"] == "passwords"
    assert by["panos"]["source"] == "eol+overlay" and by["panos"]["scheme"] == "panos"
    assert catalog.product("example-vault")["label"] == "Example Vault"
    assert catalog.load() is cat  # applied once, not per request


def test_bundled_copy_from_older_overlay_gets_current_overlay(monkeypatch):
    monkeypatch.setattr(catalog, "OVERLAY", [*OVERLAY, P("example-pam", "Example PAM", "Example Corp", "passwords")])
    cat = catalog.load()
    assert catalog.product("example-pam")["category"] == "passwords"
    assert cat["overlay"] == catalog.fingerprint() and len(cat["products"]) >= 600


def test_copy_with_same_fingerprint_used_as_is(data_file):
    cat = catalog.build(_eol())
    cat["generated_at"] = LATER
    cat["products"].append({"key": "marker", "label": "Marker", "vendor": "Example", "category": "other", "cpes": [], "scheme": "generic", "source": "eol"})
    _write(data_file, cat)
    got = catalog.load()
    assert got["generated_at"] == LATER and catalog.product("marker")["label"] == "Marker"
    assert got["products"] == cat["products"]


@pytest.mark.parametrize(
    "content",
    [
        # format 1 (before the endoflife.date part was kept)
        {"format": 1, "generated_at": LATER, "products": [{"key": "stale", "category": "other", "cpes": []}], "releases": {}},
        # this format, another overlay, but no endoflife.date part to apply it to
        {"format": catalog.FORMAT, "generated_at": LATER, "overlay": "0" * 64, "products": [{"key": "stale", "category": "other", "cpes": []}], "releases": {}},
        # a damaged endoflife.date part
        {"format": catalog.FORMAT, "generated_at": LATER, "overlay": "0" * 64, "products": [{"key": "stale"}], "releases": {}, "eol_products": [{"label": "no key"}]},
        "not json at all",
    ],
)
def test_unusable_copy_falls_back_to_bundled_with_current_overlay(data_file, content):
    data_file.write_text(content if isinstance(content, str) else json.dumps(content))
    cat = catalog.load()
    assert cat["generated_at"] != LATER and catalog.product("stale") is None
    assert cat["overlay"] == catalog.fingerprint() and len(cat["products"]) >= 600


def test_password_category():
    assert "passwords" in CATEGORIES
    by = {p["key"]: p for p in catalog.load()["products"]}
    for key in ("bitwarden", "vaultwarden", "passwork", "keepass", "keepassxc", "1password", "delinea-secret-server", "cyberark-pam"):
        assert by[key]["category"] == "passwords", key
    assert by["vaultwarden"]["cpes"] == ["a:dani-garcia:vaultwarden"] and "Bitwarden_RS" in by["vaultwarden"]["aliases"]
    assert by["passwork"]["cpes"] == ["a:passwork:passwork"]
    for key in ("lastpass", "dashlane", "nordpass", "zoho-vault", "cyberark-privilege-cloud"):
        assert by[key]["category"] == "passwords" and by[key]["cloud"] and by[key]["scheme"] == "cloud", key
    assert catalog.load()["counts"]["passwords"] >= 25


# ---------------------------------------------------------------- the curated overlay itself

def test_overlay_keys_unique_and_categories_valid():
    import re

    keys = [o["key"] for o in OVERLAY]
    assert len(keys) == len(set(keys)), sorted(k for k in keys if keys.count(k) > 1)
    assert len(CATEGORIES) == len(set(CATEGORIES))
    for o in OVERLAY:
        assert o["category"] in CATEGORIES, o["key"]
        assert re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", o["key"]), o["key"]
        for c in o["cpes"]:
            assert re.fullmatch(r"[aoh]:[^:\s]+:[^:\s]+", c.replace("\\:", "x")), (o["key"], c)
        if o.get("cloud"):
            assert o.get("scheme") == "cloud", o["key"]


def test_new_categories_hold_their_products():
    cat = catalog.load()
    by = {p["key"]: p for p in cat["products"]}
    expect = {
        "backup": ("veeam-backup-and-replication", "veeam-one", "proxmox-backup-server", "commvault", "veritas-netbackup", "zerto", "veeam-agent", "acronis-cyber-protect", "backup-exec"),
        "storage": ("netapp-ontap", "synology-dsm", "qnap-qts", "truenas"),
        "containers": ("kubernetes", "docker-engine", "podman", "red-hat-openshift", "helm", "portainer"),
        "virtualization": ("proxmox-ve", "hyper-v", "esxi", "nutanix-ahv", "qemu", "xcp-ng"),
        "siem": ("wazuh", "splunk", "splunk-uf", "graylog", "fortisiem", "ibm-qradar", "ms-sentinel"),
        "monitoring": ("zabbix", "checkmk", "prtg", "grafana", "prometheus", "uptime-kuma"),
        "iam": ("keycloak", "adfs", "okta", "entra-connect", "privacyidea"),
        "lb": ("big-ip", "netscaler-adc", "haproxy", "nginx", "kemp-loadmaster"),
        "mail": ("postfix", "dovecot", "exim", "zimbra", "seppmail", "nospamproxy", "proxmox-mail-gateway"),
        "itsm": ("jira-service-management", "glpi", "zammad", "znuny", "servicenow"),
        "dns": ("bind-9", "infoblox-nios", "unbound", "windows-dns"),
        "pki": ("ejbca", "adcs"),
        "scanner": ("nessus", "greenbone", "qualys-agent"),
        "ot": ("siemens-s7-1500", "siemens-wincc", "rockwell-controllogix", "codesys", "wago-pfc"),
        "firewall": ("securepoint-utm", "sophos-utm", "sns-firmware", "genugate", "kerio-control", "netscaler-gateway"),
        "network": ("aruba-aos-s", "unifi-switch", "cisco-meraki", "arista-eos", "vyos"),
    }
    for c, keys in expect.items():
        for k in keys:
            assert by[k]["category"] == c, (k, by[k]["category"], c)
    for c in CATEGORIES:
        assert cat["counts"].get(c, 0) > 0, c
    assert by["sns-firmware"]["label"] == "Stormshield Network Security (SNS)"
    assert by["ms-sentinel"]["cloud"] and by["okta"]["cloud"]


def _search(query: str) -> set[str]:
    """The catalogue search of the page (lib/vendor-api.ts matchScore), simplified: every word in label, vendor,
    aliases, CPE or key."""
    import re
    import unicodedata

    def fold(s: str) -> str:
        s = unicodedata.normalize("NFKD", s.lower())
        return re.sub(r"[^a-z0-9]+", " ", "".join(c for c in s if not unicodedata.combining(c))).strip()

    words = fold(query).split()
    out = set()
    for p in catalog.load()["products"]:
        hay = " " + fold(" ".join([p["label"], p.get("vendor") or "", *p.get("aliases", []), *(c.split(":", 1)[1].replace(":", " ") for c in p["cpes"]), p["key"]]))
        if all(f" {w}" in hay for w in words):
            out.add(p["key"])
    return out


@pytest.mark.parametrize(
    ("query", "key"),
    [
        ("Proxmox", "proxmox-ve"),
        ("Hyper-V", "hyper-v"),
        ("HyperV", "hyper-v"),
        ("Hyper V", "hyper-v"),
        ("Sophos", "sophos-firewall"),
        ("XG", "sophos-firewall"),
        ("XGS", "sophos-firewall"),
        ("SFOS", "sophos-firewall"),
        ("Aruba", "aruba-aos-s"),
        ("HPE", "aruba-aoscx"),
        ("ProCurve", "aruba-aos-s"),
        ("UniFi", "unifi-network"),
        ("Ubiquiti", "unifi-switch"),
        ("Unifi Switch", "unifi-switch"),
        ("Stormshield", "sns-firmware"),
        ("Veeam Agent", "veeam-agent"),
    ],
)
def test_search_finds(query, key):
    assert key in _search(query)


# ---------------------------------------------------------------- bug hunt 0.1.16 M10: examples never "ungenau"


@pytest.mark.parametrize("key", ["7-zip", "keepass", "iis", "cyberark-pam", "mssqlserver", "notepad-plus-plus", "oracle-jdk", "pangp", "oracle-database"])
async def test_a_products_own_example_is_not_short(key, reader_client):
    p = catalog.product(key)
    r = (await reader_client.get("/api/vendor/validate", params={"product": key, "version": p["example"]})).json()
    assert r["ok"] and not r["short"], (key, p["example"], r)


def test_no_catalogue_example_is_short():
    """Without release data nothing says how long a complete version is (7-Zip 24.09) – never short; a suffix of the
    latest release (SQL Server "CU27+GDR", GlobalProtect "-c1084") or a five-part build is no reason either."""
    assert [p["key"] for p in catalog.load()["products"] if p.get("example") and vendor.short_version(p, p["example"])] == []
    assert vendor.short_version(catalog.product("nginx"), "1.25") and vendor.short_version(catalog.product("pangp"), "6.2")
    assert catalog.full_depth([{"latest": "16.0.4305.5 CU27+GDR"}, {"latest": "17.0.5035.5 CU10"}]) == 4
    assert catalog.full_depth([{"latest": "8.9.8.1"}, {"latest": "8.8.9"}]) == 3 and catalog.full_depth([]) == 0


def test_a_latest_release_with_a_suffix_still_says_update_available():
    """SQL Server's line 16.0 lists "16.0.4305.5 CU27+GDR" as its latest: an older build gets "Update verfügbar"."""
    info = vendor.release_info(catalog.product("mssqlserver"), "16.0.4155.4")
    assert info["update_available"] and not info["update_unknown"]


def test_endoflife_keys_and_commands_are_checked():
    """Security review 0.1.16 L6: an endoflife.date key goes into links and chat markup – only a plain key is taken;
    its versionCommand loses control characters and is marked as endoflife.date's."""
    eol = {"result": [
        {"name": "acme-os", "label": "Acme OS", "category": "os", "versionCommand": "acme --version\x1b[2J", "releases": []},
        {"name": "evil|<https://x.example|click>", "label": "Evil", "category": "os", "releases": []},
        {"name": "Upper Case", "label": "U", "category": "os", "releases": []},
    ]}  # fmt: skip
    rows, _ = catalog.base(eol)
    assert [r["key"] for r in rows] == ["acme-os"] and rows[0]["version_cmd"] == "acme --version[2J"
    p = catalog._expand(rows[0])
    assert p["version_cmd_from"] == "eol"
    from app.vendor_api import _product_out

    assert _product_out(p)["version_cmd_from"] == "eol" and _product_out(catalog.product("arista-eos"))["version_cmd_from"] == "catalog"
