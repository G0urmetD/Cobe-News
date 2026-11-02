"""VMware vCenter Server and ESXi: the version forms admins see (vCenter's four-part version, build numbers) are looked
up in Broadcom's tables (catalog/vmware_builds.yaml) and stored as the release the advisories name (8.0 U3d); patches
of the GA release (8.0c, 7.0.0d) sort before Update 1; unknown builds are refused, never guessed."""

import shutil

import pytest
from sqlalchemy import select

from app import catalog_data, db, vendor, vmware_builds
from app import vendor_catalog as catalog
from app.catalog_data import CatalogError
from app.models import AuditEntry
from app.vendor_match import evaluate
from app.vendor_versions import parse, validate

from test_vendor_catalog import _search


def P(text: str):  # noqa: N802
    v = parse("vmware", text)
    assert v is not None, text
    return v


# ---------------------------------------------------------------- the scheme: letters on the GA line, vSphere 9


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("8.0", "8.0a"),
        ("8.0a", "8.0b"),
        ("8.0c", "8.0g"),
        ("8.0g", "8.0 U1"),  # ESXi 8.0g came out in 2026, but it is a patch of the GA line – before Update 1
        ("8.0 U1", "8.0 U1a"),
        ("8.0 U2f", "8.0 U3"),
        ("8.0 U3", "8.0 U3d"),
        ("7.0", "7.0.0b"),
        ("7.0.0d", "7.0 U1"),
        ("7.0 U3w", "8.0"),
        ("8.0 U3k", "9.0.0.0"),
        ("9.0.1.0", "9.0.2.0100"),
    ],
)
def test_vmware_order(lower, higher):
    assert P(lower) < P(higher)


def test_vmware_ga_letters_and_refusals():
    assert P("7.0.0d") == P("7.0d") and P("8.0.0c") == P("8.0c")
    assert P("8.0a") != P("8.0 U1")  # the generic rule read 8.0a as 8.0.1 = 8.0 U1
    assert P("8.0") == P("8.0.0") and P("8.0 U3") == P("8.0.3")
    for bad in ("8.0a U1", "8.0.3a", "8.0.3.00400", "24322831", "8.0.3-24022510"):
        assert parse("vmware", bad) is None, bad  # vCenter's four-part version and builds: looked up, not parsed
    assert validate("vmware", "8.0c") == (True, "8.0c", "")
    # other schemes are untouched
    assert parse("generic", "8.0a").key == (8, 0, 1)


# ---------------------------------------------------------------- the tables


def test_tables_loaded_from_the_catalogue():
    raw = catalog.DATA.vmware_builds
    assert raw["fetched"] == "2026-11-02"
    vc, esxi = raw["vcenter"], raw["esxi"]
    assert {"release": "8.0 U3d", "version": "8.0.3.00400", "build": 24322831, "date": "2024-10-21"} in vc
    assert {"release": "8.0 U3e", "build": 24674464, "date": "2025-04-10"} in esxi
    assert len(vc) >= 60 and len(esxi) >= 60
    # no formula: vCenter 8.0 U3f does not exist (ESXi's does), nor do 7.0.3.00200 / 7.0.3.00400
    assert "8.0 U3f" not in {r["release"] for r in vc} and "8.0 U3f" in {r["release"] for r in esxi}
    assert not {"7.0.3.00200", "7.0.3.00400"} & {r["version"] for r in vc}
    for r in vc + esxi:
        assert parse("vmware", r["release"]) is not None, r


@pytest.mark.parametrize(
    ("text", "release"),
    [
        ("8.0.3.00400", "8.0 U3d"),
        ("8.0.3.00000", "8.0 U3"),
        ("8.0.3.400", "8.0 U3d"),  # the leading zeros of the last part left out
        ("8.0.0.10300", "8.0c"),
        ("8.0.0.10000", "8.0"),
        ("7.0.0.10700", "7.0.0d"),
        ("7.0.3.02500", "7.0 U3w"),
        ("24322831", "8.0 U3d"),
        ("build-24322831", "8.0 U3d"),
        ("Build 24322831", "8.0 U3d"),
        ("8.0.3-24322831", "8.0 U3d"),
        ("Version 8.0.3.00400 Build 24322831", "8.0 U3d"),
        ("Version: 8.0.3, Build: 24322831", "8.0 U3d"),
        ("vCenter Server 8.0.3.00400", "8.0 U3d"),
        ("VMware vCenter Server 8.0 Update 3 (build 24022515)", "8.0 U3"),
        ("20519528", "8.0"),
    ],
)
def test_vcenter_forms(text, release):
    assert vmware_builds.lookup("vcenter", text) == (release, "")
    assert vendor.validate_version(catalog.product("vcenter"), text) == (True, release, "")


@pytest.mark.parametrize(
    ("text", "release"),
    [
        ("24022510", "8.0 U3"),
        ("8.0.3, 24022510", "8.0 U3"),
        ("8.0.3-24022510", "8.0 U3"),
        ("VMware ESXi 8.0.3 build-24022510", "8.0 U3"),
        ("VMware ESXi 8.0 Update 3 (build 24674464)", "8.0 U3e"),  # vmware -l leaves the letter out – the build has it
        ("8.0 U3e build-24674464", "8.0 U3e"),
        ("8.0 build-21493926", "8.0c"),
        ("ESXi 8.0.0 build-25191479", "8.0g"),
        ("15843807", "7.0"),
        ("7.0b, 16324942", "7.0b"),
    ],
)
def test_esxi_forms(text, release):
    assert vmware_builds.lookup("esxi", text) == (release, "")
    assert vendor.validate_version(catalog.product("esxi"), text) == (True, release, "")


def test_builds_are_per_product_and_unknown_ones_refused():
    vc, esxi = catalog.product("vcenter"), catalog.product("esxi")
    # 8.0 U3: vCenter 24022515, ESXi 24022510 – each only in its own table
    assert vmware_builds.lookup("vcenter", "24022515") == ("8.0 U3", "")
    assert vmware_builds.lookup("esxi", "24022515") == (None, "unknown_build")
    assert vmware_builds.lookup("vcenter", "24022510") == (None, "unknown_build")
    assert vmware_builds.lookup("esxi", "24322831") == (None, "unknown_build")  # vCenter 8.0 U3d
    # four-part versions the table does not have (no formula: 8.0 U3f, 7.0.3.00200 do not exist), and ESXi has none
    for text in ("8.0.3.00450", "7.0.3.00200", "7.0.3.00400", "6.7.0.54000"):
        assert vendor.validate_version(vc, text) == (False, text, "unknown_build"), text
    assert vendor.validate_version(esxi, "8.0.3.00400") == (False, "8.0.3.00400", "unknown_build")
    assert vendor.validate_version(vc, "99999999") == (False, "99999999", "unknown_build")
    # a version next to a build that is not the build's release
    assert vmware_builds.lookup("vcenter", "8.0.3.00300 Build 24322831") == (None, "build_mismatch")
    assert vmware_builds.lookup("esxi", "8.0 U3d build-24674464") == (None, "build_mismatch")
    assert vmware_builds.lookup("esxi", "8.0.2-24022510") == (None, "build_mismatch")
    assert vmware_builds.lookup("esxi", "8.0 U3-21493926") == (None, "build_mismatch")  # 8.0c is on the GA line


def test_releases_and_vsphere9_left_to_the_scheme():
    vc = catalog.product("vcenter")
    for text in ("8.0 U3d", "8.0 Update 3d", "8.0.3", "8.0c", "8.0", "7.0.0d"):
        assert vmware_builds.lookup("vcenter", text) == (None, ""), text
        assert vendor.validate_version(vc, text) == (True, text, ""), text
    assert vendor.validate_version(vc, "9.0.2.0100") == (True, "9.0.2.0100", "")
    assert vendor.validate_version(vc, "9.0.1.0 build 24957454") == (True, "9.0.1.0", "")
    assert vendor.validate_version(vc, "8.0.3.00400.1")[2] == "format"
    # other products are untouched: a build number of something else stays what its scheme says
    assert vmware_builds.lookup("panos", "24322831") == (None, "")
    assert vendor.validate_version(catalog.product("vmware-tools"), "12.5.0") == (True, "12.5.0", "")
    assert vendor.validate_version({"key": "vcenter", "scheme": "generic"}, "8.0.3.00400") == (True, "8.0.3.00400", "")


def test_broken_table_is_refused(tmp_path):
    d = tmp_path / "catalog"
    shutil.copytree(catalog_data.DIR, d)
    path = d / "build_maps" / "vmware.yaml"
    text = path.read_text()
    for old, new, message in [
        ('build: 24322831, date: "2024-10-21"', 'build: 24305161, date: "2024-10-21"', "build 24305161 listed twice"),
        ('version: "8.0.3.00400"', 'version: "8.0.2.00400"', "not of the release's line"),
        ('release: "8.0 U3d"', 'release: "8.0 Update 3d"', "build_maps/vmware.yaml: vcenter"),
        ('release: "8.0", version', "release: 8.0, version", "build_maps/vmware.yaml"),  # a float, not a string
    ]:
        assert old in text, old
        path.write_text(text.replace(old, new, 1))
        with pytest.raises(CatalogError, match=message.replace("(", r"\(")):
            catalog_data.load(d)
    path.write_text(text)
    assert catalog_data.load(d).vmware_builds["vcenter"]


# ---------------------------------------------------------------- matching: stored as the release, compared as one


def _advisory(product: str, fixed: str) -> dict:
    """A CVE record's CNA data as VMware writes it: affected from 8.0 up to the fixed release."""
    name = {"vcenter": "VMware vCenter Server", "esxi": "VMware ESXi"}[product]
    return {
        "configs": [],
        "desc": "",
        "cna": [{"affectedData": [{"vendor": "VMware", "product": name, "defaultStatus": "unknown", "versions": [{"version": "8.0", "lessThan": fixed, "status": "affected", "versionType": "custom"}]}]}],
    }


def test_vcenter_four_part_against_fixed_in_u3d():
    vc = catalog.product("vcenter")
    data = _advisory("vcenter", "8.0 U3d")
    stored = {text: vendor.validate_version(vc, text)[1] for text in ("8.0.3.00400", "8.0.3.00000", "8.0.3.00300", "24322831")}
    assert stored == {"8.0.3.00400": "8.0 U3d", "8.0.3.00000": "8.0 U3", "8.0.3.00300": "8.0 U3c", "24322831": "8.0 U3d"}
    assert evaluate(vc, "nvd", data, stored["8.0.3.00400"]).status == "not_affected"
    assert evaluate(vc, "nvd", data, stored["24322831"]).status == "not_affected"
    v = evaluate(vc, "nvd", data, stored["8.0.3.00000"])
    assert (v.status, v.fixed) == ("affected", "8.0 U3d")
    assert evaluate(vc, "nvd", data, stored["8.0.3.00300"]).status == "affected"
    # the GA line's patches are before Update 1 – affected by a fix in 8.0 U3d
    assert evaluate(vc, "nvd", data, vendor.validate_version(vc, "8.0.0.10300")[1]).status == "affected"


def test_esxi_build_against_fixed_in_u3e():
    esxi = catalog.product("esxi")
    data = _advisory("esxi", "8.0 U3e")
    assert evaluate(esxi, "nvd", data, vendor.validate_version(esxi, "VMware ESXi 8.0.3 build-24674464")[1]).status == "not_affected"
    assert evaluate(esxi, "nvd", data, vendor.validate_version(esxi, "8.0.3, 24585383")[1]).status == "affected"  # 8.0 U3d


# ---------------------------------------------------------------- API


async def _follow(c, key: str) -> None:
    assert (await c.put(f"/api/vendor/follows/{key}", json={"enabled": True})).status_code == 200


async def test_api_stores_the_release(admin_client):
    await _follow(admin_client, "vcenter")
    r = await admin_client.post("/api/vendor/follows/vcenter/versions", json={"version": "8.0.3.00400", "label": "RZ Nord"})
    assert r.status_code == 200, r.text
    assert r.json()["version"] == "8.0 U3d" and r.json()["label"] == "RZ Nord" and r.json()["valid"]
    vid = r.json()["id"]
    r = await admin_client.put(f"/api/vendor/versions/{vid}", json={"version": "build-24305161", "label": ""})
    assert r.status_code == 200 and r.json()["version"] == "8.0 U3c" and r.json()["label"] == ""
    await _follow(admin_client, "esxi")
    r = await admin_client.post("/api/vendor/follows/esxi/versions", json={"version": "VMware ESXi 8.0.3 build-24022510"})
    assert r.status_code == 200 and r.json()["version"] == "8.0 U3"
    # a release as before
    r = await admin_client.post("/api/vendor/follows/esxi/versions", json={"version": "8.0 U3e"})
    assert r.json()["version"] == "8.0 U3e"
    d = (await admin_client.get("/api/vendor/products/vcenter")).json()
    assert [v["version"] for v in d["versions"]] == ["8.0 U3c"]
    # the audit log keeps what was typed next to what was stored
    async with db.session() as s:
        rows = (await s.execute(select(AuditEntry).where(AuditEntry.action.in_(("catalog.version_added", "catalog.version_changed"))).order_by(AuditEntry.id))).scalars().all()
    assert rows[0].details == {"version": "8.0 U3d", "label": "RZ Nord", "count": None, "entered": "8.0.3.00400"}
    assert rows[1].details["entered"] == "build-24305161"
    assert "entered" not in rows[-1].details  # 8.0 U3e typed as it is stored


async def test_api_refuses_unknown_builds(admin_client):
    await _follow(admin_client, "vcenter")
    r = await admin_client.post("/api/vendor/follows/vcenter/versions", json={"version": "8.0.3.00450"})
    assert r.status_code == 422
    d = r.json()["detail"]
    assert d["code"] == "version_invalid" and d["reason"] == "unknown_build" and d["example"] == "8.0 U3d"
    assert "8.0 U3d" in d["hint"]["de"] and "VAMI" in d["hint"]["de"] and "Unknown build" in d["hint"]["en"]
    await _follow(admin_client, "esxi")
    r = await admin_client.post("/api/vendor/follows/esxi/versions", json={"version": "24322831"})  # a vCenter build
    assert r.status_code == 422 and r.json()["detail"]["reason"] == "unknown_build"
    r = await admin_client.post("/api/vendor/follows/esxi/versions", json={"version": "8.0 U3d build-24674464"})
    assert r.status_code == 422 and r.json()["detail"]["reason"] == "build_mismatch" and r.json()["detail"]["hint"]["en"]
    # other products: the error as before (no hint)
    await _follow(admin_client, "panos")
    r = await admin_client.post("/api/vendor/follows/panos/versions", json={"version": "24322831"})
    assert r.json()["detail"] == {"code": "version_invalid", "reason": "format", "example": "11.2.4-h23"}


async def test_validate_endpoint_previews_the_release(reader_client):
    async def check(product: str, version: str) -> dict:
        r = await reader_client.get("/api/vendor/validate", params={"product": product, "version": version})
        assert r.status_code == 200
        return r.json()

    r = await check("vcenter", "8.0.3.00400")
    assert r["ok"] and r["normalized"] == "8.0 U3d" and r["mapped"] and not r["short"]
    r = await check("vcenter", "8.0 U3d")
    assert r["ok"] and r["normalized"] == "8.0 U3d" and not r["mapped"]
    r = await check("esxi", "24022515")
    assert not r["ok"] and r["reason"] == "unknown_build" and not r["mapped"]
    r = await check("panos", "11.2.4-h23")
    assert r["ok"] and not r["mapped"]


async def test_catalogue_marks_products_with_builds(reader_client):
    d = (await reader_client.get("/api/vendor/catalog")).json()
    by = {p["key"]: p for p in d["products"]}
    assert by["vcenter"]["builds"] and by["esxi"]["builds"]
    assert not by["vsphere-replication"]["builds"] and not by["panos"]["builds"]
    assert {"vSphere", "vSphere Client", "VCSA", "vCenter Server Appliance"} <= set(by["vcenter"]["aliases"])
    assert {"vSphere Hypervisor", "vSphere ESXi"} <= set(by["esxi"]["aliases"])
    assert by["esxi"]["version_cmd"] == "vmware -v" and by["vcenter"]["version_where"] == "vmware_vcenter"
    meta = (await reader_client.get("/api/vendor/catalog/meta")).json()
    assert "5480" in meta["texts"]["where"]["vmware_vcenter"]["de"] and "vmware -v" in meta["texts"]["where"]["vmware_esxi"]["en"]


@pytest.mark.parametrize(
    ("query", "keys"),
    [
        ("vSphere", {"vcenter", "esxi", "vsphere-replication"}),
        ("VMware vSphere", {"vcenter", "esxi", "vsphere-replication"}),
        ("vSphere Client", {"vcenter"}),
        ("VCSA", {"vcenter"}),
        ("vCenter Server Appliance", {"vcenter"}),
        ("vSphere Hypervisor", {"esxi"}),
    ],
)
def test_search_finds_vsphere(query, keys):
    assert keys <= _search(query)
