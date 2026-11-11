"""Vendor News end to end, offline: following products and versions (admins), what readers see, the background round
against a MockTransport serving trimmed real responses, conditional requests and backoff, release lines from
endoflife.date, related stories, and notifications – each finding once per product and version, never the baseline."""

import json
import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app import db, notify, vendor
from app import vendor_catalog as catalog
from app.models import NewsItem, NewsSource, VendorAdvisory, VendorAdvisoryProduct, VendorDelivery, VendorEvent, VendorFetch, VendorFollow, VendorVersion
from conftest import STRUCTURED_OFF

FIX = Path(__file__).parent / "fixtures"
HOOK = "https://n8n.corp.example/webhook/vendor"
EMPTY_NVD = {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "format": "NVD_CVE", "version": "2.0", "vulnerabilities": []}


class Vendors:
    """The fake vendor sites: every request recorded; ETag "v1" on Palo Alto, KEV and endoflife.date (304 when sent back)."""

    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.nvd_status = 200
        self.nvd_by_cpe: dict[str, str] = {}  # virtualMatchString → fixture file

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        host, path = req.url.host, req.url.path
        etag = {"ETag": "W/\"v1\""}
        if req.headers.get("if-none-match") == 'W/"v1"':
            return httpx.Response(304)
        if host == "security.paloaltonetworks.com":
            body = (FIX / "vendor" / "pan_list.json").read_bytes() if req.url.params.get("page") == "1" else b"[]"
            return httpx.Response(200, content=body, headers=etag)
        if host == "filestore.fortinet.com" and path.endswith("ir.xml"):
            return httpx.Response(200, content=(FIX / "vendor" / "fortinet_ir.xml").read_bytes())
        if host == "filestore.fortinet.com" and "/psirt/csaf_" in path:
            return httpx.Response(200, content=(FIX / "vendor" / "fortinet_csaf_wad.json").read_bytes())
        if host == "services.nvd.nist.gov":
            if self.nvd_status != 200:
                return httpx.Response(self.nvd_status, headers={"Retry-After": "7200"})
            vm = req.url.params.get("virtualMatchString") or ""
            if vm in self.nvd_by_cpe:
                return httpx.Response(200, content=(FIX / "vendor" / self.nvd_by_cpe[vm]).read_bytes())
            if vm == "cpe:2.3:o:fortinet:fortios":
                return httpx.Response(200, content=(FIX / "vendor" / "nvd_fortios.json").read_bytes())
            return httpx.Response(200, json=EMPTY_NVD)
        if host == "www.cisa.gov":
            return httpx.Response(200, content=(FIX / "news" / "kev.json").read_bytes(), headers=etag)
        if host == "endoflife.date":
            return httpx.Response(200, content=(FIX / "vendor" / "eol_full.json").read_bytes(), headers=etag)
        raise AssertionError(f"unexpected request {req.url}")

    def to(self, host: str) -> list[httpx.Request]:
        return [c for c in self.calls if c.url.host == host]


@pytest.fixture(autouse=True)
def vendor_reset(monkeypatch, tmp_path):
    vendor.reset()
    # a refreshed catalogue goes to this test's folder, never into another test's
    monkeypatch.setattr(catalog, "_data_file", lambda: tmp_path / "vendor_catalog.json")
    catalog._cache.stamp = ()
    yield


@pytest.fixture
def sites(monkeypatch):
    v = Vendors()
    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(v.handler))
    return v


@pytest.fixture
def hooks(monkeypatch):
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.host == "n8n.corp.example"
        calls.append(req)
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(notify, "transport", httpx.MockTransport(handler))
    return calls


async def _follow(c, key: str, *versions: str) -> None:
    r = await c.put(f"/api/vendor/follows/{key}", json={"enabled": True, "note": "Rechenzentrum"})
    assert r.status_code == 200, r.text
    for v in versions:
        r = await c.post(f"/api/vendor/follows/{key}/versions", json={"version": v, "label": f"Standort {v}"})
        assert r.status_code == 200, r.text


async def _round(force: bool = True) -> dict:
    out = await vendor.run_round(force=force)
    async with db.session() as s:
        await vendor.evaluate_events(s)
    return out


# ---------------------------------------------------------------- permissions, validation


async def test_readers_see_admins_edit(admin_client, reader_client):
    assert (await reader_client.get("/api/vendor/catalog")).status_code == 200
    assert (await reader_client.get("/api/vendor/overview")).status_code == 200
    assert (await reader_client.get("/api/vendor/products/panos")).status_code == 200
    assert (await reader_client.get("/api/vendor/validate?product=panos&version=11.2.4-h23")).json()["ok"] is True
    assert (await reader_client.put("/api/vendor/follows/panos", json={"enabled": True})).status_code == 403
    await _follow(admin_client, "panos", "11.2.4-h23")
    vid = (await reader_client.get("/api/vendor/products/panos")).json()["versions"][0]["id"]
    assert (await reader_client.post("/api/vendor/follows/panos/versions", json={"version": "11.1.6-h3"})).status_code == 403
    assert (await reader_client.put(f"/api/vendor/versions/{vid}", json={"version": "11.1.6-h3"})).status_code == 403
    assert (await reader_client.delete(f"/api/vendor/versions/{vid}")).status_code == 403
    assert (await reader_client.delete("/api/vendor/follows/panos")).status_code == 403
    assert (await reader_client.post("/api/vendor/custom", json={"cpe": "a:example:thing", "label": "Thing"})).status_code == 403
    assert (await reader_client.get("/api/vendor/cpe-search?q=netscaler")).status_code == 403
    assert (await reader_client.get("/api/admin/vendor")).status_code == 403
    assert (await reader_client.put("/api/admin/vendor", json={"enabled": False})).status_code == 403
    assert (await reader_client.post("/api/admin/vendor/fetch")).status_code == 403
    assert (await reader_client.post("/api/admin/vendor/catalog")).status_code == 403


async def test_anonymous_sees_nothing(client):
    for path in ("/api/vendor/catalog", "/api/vendor/overview", "/api/vendor/products/panos", "/api/vendor/validate?product=panos&version=1"):
        assert (await client.get(path)).status_code == 401


async def test_version_format_per_vendor(admin_client):
    await _follow(admin_client, "panos")
    r = await admin_client.post("/api/vendor/follows/panos/versions", json={"version": "11.2"})
    assert r.status_code == 422 and r.json()["detail"] == {"code": "version_invalid", "reason": "format", "example": "11.2.4-h23"}
    await _follow(admin_client, "windows-server")
    r = await admin_client.post("/api/vendor/follows/windows-server/versions", json={"version": "KB5044281"})
    assert r.json()["detail"]["reason"] == "kb"
    r = await admin_client.post("/api/vendor/follows/panos/versions", json={"version": "11.2.4-H23", "label": "HA-Paar", "count": 2})
    assert r.status_code == 200 and r.json()["version"] == "11.2.4-h23" and r.json()["count"] == 2
    assert (await admin_client.put("/api/vendor/follows/does-not-exist", json={"enabled": True})).status_code == 404
    await _follow(admin_client, "prisma-access")
    r = await admin_client.post("/api/vendor/follows/prisma-access/versions", json={"version": "11.2"})
    assert r.json()["detail"]["reason"] == "cloud"


async def test_catalogue_counts_and_custom_products(admin_client, reader_client):
    d = (await reader_client.get("/api/vendor/catalog")).json()
    assert len(d["products"]) >= 600
    assert d["categories"]["firewall"]["total"] >= 20 and d["categories"]["firewall"]["followed"] == 0
    keys = {p["key"] for p in d["products"]}
    assert {"panos", "panorama", "pangp", "prisma-access", "cortex-xdr", "fortios", "fortimanager", "cisco-asa", "cisco-ftd", "esxi", "vcenter", "msexchange", "php", "nodejs", "sap-netweaver-abap"} <= keys
    r = await admin_client.post("/api/vendor/custom", json={"cpe": "cpe:2.3:a:example:widget_server", "label": "Widget Server", "category": "other"})
    key = r.json()["key"]
    d = (await reader_client.get("/api/vendor/catalog")).json()
    assert d["followed"][key] == {"enabled": True, "versions": 0}
    assert next(p for p in d["products"] if p["key"] == key)["cpes"] == ["a:example:widget_server"]
    assert (await admin_client.post("/api/vendor/custom", json={"cpe": "not a cpe", "label": "x"})).status_code == 422


# ---------------------------------------------------------------- the round


async def test_no_request_without_followed_products(sites):
    await _round()
    assert sites.calls == []


async def test_switched_off_means_no_request(admin_client, sites):
    await _follow(admin_client, "panos", "11.2.4-h23")
    assert (await admin_client.put("/api/admin/vendor", json={"enabled": False})).status_code == 200
    await _round()
    assert sites.calls == []
    assert (await admin_client.post("/api/admin/vendor/fetch")).status_code == 409


async def test_round_finds_what_affects_exactly_these_versions(admin_client, reader_client, sites):
    await _follow(admin_client, "panos", "11.2.4-h23", "10.2.13-h5", "11.1.6-h3")
    await _follow(admin_client, "panorama", "11.2.4-h23")
    await _follow(admin_client, "fortios", "7.4.3")
    await _round()
    hosts = {c.url.host for c in sites.calls}
    assert {"security.paloaltonetworks.com", "filestore.fortinet.com", "services.nvd.nist.gov", "www.cisa.gov", "endoflife.date"} <= hosts
    # every request: https, the hardened download (one per host gap in production)
    assert all(c.url.scheme == "https" for c in sites.calls)
    detail = (await reader_client.get("/api/vendor/products/panos")).json()
    by = {f["ident"]: f for f in detail["findings"]}
    rce = by["CVE-2026-0322"]
    per = {v["version"]: (v["status"], v["fixed"]) for v in rce["versions"]}
    assert per == {"11.2.4-h23": ("not_affected", None), "10.2.13-h5": ("affected", "10.2.13-h26"), "11.1.6-h3": ("affected", "11.1.6-h39")}
    assert rce["status"] == "affected"
    assert "CVE-2026-0318" not in by  # the Panorama DoS is not a finding of the firewalls
    pano = {f["ident"]: f for f in (await reader_client.get("/api/vendor/products/panorama")).json()["findings"]}
    assert pano["CVE-2026-0279"]["versions"][0]["status"] == "possible"  # a firewall XSS: Panorama not decidable
    forti = (await reader_client.get("/api/vendor/products/fortios")).json()
    fby = {f["ident"]: f for f in forti["findings"]}
    assert fby["CVE-2025-59718"]["exploited"] and fby["CVE-2025-59718"]["versions"][0]["status"] == "affected"
    assert fby["CVE-2025-59718"]["kev"] is None or fby["CVE-2025-59718"]["kev"]["added"]
    # release lines from endoflife.date
    v = next(x for x in (await reader_client.get("/api/vendor/products/panos")).json()["versions"] if x["version"] == "11.2.4-h23")
    assert v["release"]["line"]["name"] == "11.2" and v["release"]["update_available"] is True
    ov = (await reader_client.get("/api/vendor/overview")).json()
    card = next(i for i in ov["items"] if i["product"]["key"] == "panos")
    assert card["counts"]["affected"] >= 3 and card["summary"]["worst"] == "affected"
    per_version = card["summary"]["per_version"]
    ids = {x["version"]: x["id"] for x in card["versions"]}
    assert per_version[ids["10.2.13-h5"]]["affected"] > per_version[ids["11.2.4-h23"]]["affected"]


async def test_conditional_requests_and_backoff(admin_client, sites):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    sites.calls.clear()
    sites.nvd_status = 429
    await _round()
    pan = sites.to("security.paloaltonetworks.com")
    assert pan and pan[0].headers.get("if-none-match") == 'W/"v1"'
    async with db.session() as s:
        st = await s.get(VendorFetch, "nvd:o:paloaltonetworks:pan-os")
        assert st.error.startswith("rate_limited")
        assert st.next_fetch_at - datetime.now(UTC) >= timedelta(minutes=110)  # Retry-After 2 h, at least an hour
    sites.calls.clear()
    await _round()  # forced, but a refusal pause is respected
    assert not sites.to("services.nvd.nist.gov")


async def test_version_change_is_evaluated_at_once_without_fetching(admin_client, reader_client, sites):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    n = len(sites.calls)
    vid = (await reader_client.get("/api/vendor/products/panos")).json()["versions"][0]["id"]
    r = await admin_client.put(f"/api/vendor/versions/{vid}", json={"version": "11.2.4-h5", "label": "RZ Nord"})
    assert r.status_code == 200
    f = {x["ident"]: x for x in (await reader_client.get("/api/vendor/products/panos")).json()["findings"]}
    assert f["CVE-2026-0322"]["versions"][0] | {"score": None} == {"score": None, "id": vid, "version": "11.2.4-h5", "status": "affected", "reason": "in_range", "fixed": "11.2.4-h22", "detail": {"by": "vendor"}}
    assert len(sites.calls) == n


async def test_followed_later_gets_what_is_stored(admin_client, reader_client, sites):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    await _follow(admin_client, "panorama")  # same PAN-OS data – linked from what is stored
    async with db.session() as s:
        n = len(list(await s.scalars(select(VendorAdvisoryProduct).where(VendorAdvisoryProduct.product == "panorama"))))
    assert n >= 3
    d = (await reader_client.get("/api/vendor/products/panorama")).json()
    assert all(f["versions"][0]["status"] == "unversioned" for f in d["findings"])


# ---------------------------------------------------------------- release lines


def test_release_info_from_endoflife(monkeypatch):
    cat = catalog.build(json.loads((FIX / "vendor" / "eol_full.json").read_text()))
    monkeypatch.setattr(catalog, "load", lambda: cat)
    p = {k: x for x in cat["products"] for k in [x["key"]]}
    info = vendor.release_info(p["panos"], "11.2.4-h23", date(2026, 10, 29))
    assert info["line"]["name"] == "11.2" and info["line"]["latest"] == "11.2.16" and info["update_available"]
    assert info["eol_state"] == "ok" and info["newer_line"]["name"] == "12.2"
    assert vendor.release_info(p["panos"], "11.2.16", date(2026, 10, 29))["update_available"] is False
    assert vendor.release_info(p["panos"], "11.2.4-h23", date(2027, 3, 1))["eol_state"] == "soon"  # 2027-05-02
    assert vendor.release_info(p["panos"], "11.2.4-h23", date(2027, 6, 1))["eol_state"] == "past"
    # "Support endet bald": under half a year (183 days) – as the drawer computes it in the browser (vendor-api.ts)
    assert vendor.EOL_SOON_DAYS == 183
    assert vendor.release_info(p["panos"], "11.2.4-h23", date(2026, 10, 31))["eol_state"] == "ok"  # 183 days left
    assert vendor.release_info(p["panos"], "11.2.4-h23", date(2026, 11, 1))["eol_state"] == "soon"  # 182 days left
    assert vendor.release_info(p["panos"], "11.2.4-h23", date(2026, 11, 15))["eol_state"] == "soon"  # was "ok" with 90 days
    ws = vendor.release_info(p["windows-server"], "10.0.20348.2762", date(2026, 10, 29))
    assert ws["line"]["name"] == "2022" and ws["update_available"] is False  # 10.0.20348 says nothing about patches
    assert vendor.release_info(p["php"], "8.3.14", date(2026, 10, 29))["update_available"]
    assert vendor.release_info(p["panos"], "13.0.1", date(2026, 10, 29))["line"] is None
    assert len(vendor.release_info(p["panos"], None)["lines"]) > 5


def test_catalog_build_from_data():
    eol = json.loads((FIX / "vendor" / "eol_full.json").read_text())
    cat = catalog.build(eol)
    by = {x["key"]: x for x in cat["products"]}
    assert by["panos"]["source"] == "eol+overlay" and by["panos"]["scheme"] == "panos" and by["panos"]["cpes"] == ["o:paloaltonetworks:pan-os"]
    assert by["panorama"]["eol"] == "panos" and by["cisco-asa"]["eol"] is None
    assert by["fortios"]["category"] == "firewall" and by["php"]["category"] == "web"
    assert by["confluence"]["cpes"][:2] == ["a:atlassian:confluence_data_center", "a:atlassian:confluence_server"]
    assert set(cat["releases"]) >= {"panos", "php", "windows-server"}
    assert sum(cat["counts"].values()) == len(cat["products"])
    bundled = catalog.load()
    assert len(bundled["products"]) >= 600 and bundled["counts"]["os"] >= 30


# ---------------------------------------------------------------- related stories


async def test_related_news_by_cve_and_name():
    async with db.session() as s:
        src = NewsSource(key="feed-v", name="Example Feed", url="https://news.example.org/v.xml", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.flush()
        now = datetime.now(UTC)
        for n, (title, cves) in enumerate([("Kritische Lücke in PAN-OS", []), ("Patchday", ["CVE-2026-0322"]), ("phpMyAdmin XSS", []), ("PHP 8.3.15 behebt Lücken", [])]):
            s.add(NewsItem(source_id=src.id, url=f"https://news.example.org/{n}", url_key=f"k{n}", title=title, title_key=f"t{n}", summary="", published_at=now, cves=cves, search=f"{title.lower()} {' '.join(cves).lower()}"))
        await s.commit()
        got = await vendor.related_news(s, catalog.product("panos"), ["CVE-2026-0322"])
        assert {x["title"] for x in got} == {"Kritische Lücke in PAN-OS", "Patchday"}
        assert next(x for x in got if x["title"] == "Patchday")["by"] == "cve"
        php = await vendor.related_news(s, catalog.product("php"), [])
        assert [x["title"] for x in php] == ["PHP 8.3.15 behebt Lücken"]


# ---------------------------------------------------------------- notifications


async def _webhook_rule(c, kinds: list[str], severities: list[str] | None = None) -> None:
    ch = (await c.post("/api/admin/notify/channels", json={"name": "n8n", "type": "webhook", "url": HOOK})).json()
    r = await c.post("/api/admin/notify/rules", json={"name": "Systeme", "channels": [ch["id"]], "kinds": kinds, "severities": severities or ["critical", "high", "medium", "low", "info"]})
    assert r.status_code == 200 and r.json()["kinds"] == kinds


def _fresh_pan(ident: str, affected: str, fixed: str) -> dict:
    now = datetime.now(UTC)
    return {
        "id": f"paloalto:{ident}",
        "source": "paloalto",
        "ident": ident,
        "title": "PAN-OS: Example vulnerability in the management interface",
        "summary": "Example.",
        "url": f"https://security.paloaltonetworks.com/{ident}",
        "cves": [ident],
        "cvss": 9.3,
        "severity": "critical",
        "published_at": now - timedelta(hours=2),
        "updated_at": now - timedelta(hours=1),
        "names": ["PAN-OS", "PAN-OS 11.2"],
        "data": {"lines": [{"name": "PAN-OS 11.2", "affected": affected, "fixed": fixed}], "affected_list": [], "products": ["PAN-OS"]},
    }


async def _dispatch() -> dict:
    async with db.session() as s:
        return await notify.dispatch(s)


async def test_new_finding_notifies_once_per_version(admin_client, sites, hooks):
    await _follow(admin_client, "panos", "11.2.4-h23", "10.2.13-h5")
    await _webhook_rule(admin_client, ["vendor_vuln"])
    await _round()  # the baseline: everything found now is on the page, nothing is sent
    await _dispatch()
    assert hooks == []
    async with db.session() as s:
        evs = list(await s.scalars(select(VendorEvent)))
        assert evs and all(e.baseline for e in evs)
        await vendor.store(s, [_fresh_pan("CVE-2026-9999", "< 11.2.4-h30, < 11.2.16", ">= 11.2.4-h30, >= 11.2.16")], vendor.build_index())
        # 11.2.4-h23 affected; the 10.2 line is not named in the advisory – "possibly affected" is said as well
        assert await vendor.evaluate_events(s) == 2
    await _dispatch()
    assert len(hooks) == 2
    stories = {s["title"].split(":")[0]: s for h in hooks for s in json.loads(h.content)["stories"]}
    story = stories["PAN-OS (Firewalls) 11.2.4-h23 (Standort 11.2.4-h23)"]
    assert story["kind"] == "vendor.vuln" and "CVE-2026-9999" in story["title"]
    # the link opens the product's drawer at the finding (notify.vendor_path) – not only the product
    assert story["link"] == "https://news.corp.example:8095/vendor?product=panos&finding=paloalto%3ACVE-2026-9999" and "11.2.4-h30" in story["summary"]
    assert stories["PAN-OS (Firewalls) 10.2.13-h5 (Standort 10.2.13-h5)"]["summary"].startswith("Status: möglicherweise betroffen")
    await _dispatch()
    async with db.session() as s:
        assert await vendor.evaluate_events(s) == 0
    await _dispatch()
    assert len(hooks) == 2  # once per product, version and finding
    async with db.session() as s:
        assert len(list(await s.scalars(select(VendorDelivery)))) == 2


async def test_changed_version_is_a_new_baseline(admin_client, reader_client, sites, hooks):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _webhook_rule(admin_client, ["vendor_vuln"])
    await _round()
    vid = (await reader_client.get("/api/vendor/products/panos")).json()["versions"][0]["id"]
    await admin_client.put(f"/api/vendor/versions/{vid}", json={"version": "11.2.4-h5"})
    async with db.session() as s:
        await vendor.evaluate_events(s)
        assert (await s.get(VendorVersion, uuid.UUID(vid))).baseline_at is not None
    await _dispatch()
    assert hooks == []  # the person who changed it sees the findings on the page


async def test_rules_without_vendor_kinds_send_no_vendor_events(admin_client, sites, hooks):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _webhook_rule(admin_client, ["news"])
    await _round()
    async with db.session() as s:
        await vendor.store(s, [_fresh_pan("CVE-2026-9998", "< 11.2.16", ">= 11.2.16")], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1
    await _dispatch()
    assert hooks == []


async def test_severity_filter_and_unversioned_products(admin_client, sites, hooks):
    await _follow(admin_client, "panos")  # no version: every vulnerability of the product
    await _webhook_rule(admin_client, ["vendor_vuln"], ["critical"])
    await _round()
    async with db.session() as s:
        low = _fresh_pan("CVE-2026-9997", "< 11.2.16", ">= 11.2.16") | {"cvss": 4.0, "severity": "medium"}
        await vendor.store(s, [low, _fresh_pan("CVE-2026-9996", "< 11.2.16", ">= 11.2.16")], vendor.build_index())
        assert await vendor.evaluate_events(s) == 2
    await _dispatch()
    assert len(hooks) == 1 and "CVE-2026-9996" in json.loads(hooks[0].content)["stories"][0]["title"]


async def test_version_and_eol_events(admin_client, sites, hooks, monkeypatch):
    real, real_stage = vendor.release_info, vendor.eol_stage

    def on(day: date) -> None:
        """The EOL clock (the line's state and the version's pre-warning stage) on a fixed day – with the real day the
        EOL of 11.2 (2027-05-02) would come near, then pass, and the test would depend on the calendar."""
        monkeypatch.setattr(vendor, "release_info", lambda p, v, today=None: real(p, v, day))
        monkeypatch.setattr(vendor, "eol_stage", lambda eol_from, today: real_stage(eol_from, day))

    # the first round on a fixed day well before the EOL window of 11.2 – its end lands in no baseline
    on(date(2026, 10, 1))
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _webhook_rule(admin_client, ["vendor_version"])
    await _round()
    async with db.session() as s:
        kinds = {e.kind for e in await s.scalars(select(VendorEvent).where(VendorEvent.baseline.is_(True)))}
    assert "version" in kinds  # 11.2.16 is out: shown, not sent (baseline)
    on(date(2027, 3, 1))
    async with db.session() as s:
        assert await vendor.evaluate_events(s, full=True) == 1  # EOL of 11.2 on 2027-05-02 is near now (the hourly full evaluation)
    await _dispatch()
    assert len(hooks) == 1 and json.loads(hooks[0].content)["stories"][0]["kind"] == "vendor.eol"


async def test_rules_from_before_keep_sending_news(admin_client):
    ch = (await admin_client.post("/api/admin/notify/channels", json={"name": "n8n", "type": "webhook", "url": HOOK})).json()
    r = await admin_client.post("/api/admin/notify/rules", json={"name": "Alt", "channels": [ch["id"]]})
    assert r.json()["kinds"] == ["news"]
    assert (await admin_client.post("/api/admin/notify/rules", json={"name": "Leer", "channels": [ch["id"]], "kinds": []})).status_code == 422
    assert (await admin_client.post("/api/admin/notify/rules", json={"name": "Falsch", "channels": [ch["id"]], "kinds": ["spam"]})).status_code == 422


async def test_settings_keep_the_nvd_key_secret(admin_client):
    r = await admin_client.put("/api/admin/vendor", json={"enabled": True, "every_h": 6, "eol_every_h": 24, "nvd_key": "0000aaaa-bbbb-cccc-dddd-eeeeffff0000"})
    assert r.json() == {"enabled": True, "every_h": 6, "eol_every_h": 24, "nvd_key_set": True, **STRUCTURED_OFF, "review_days": 90, "csaf_green": [], "rev": 1}  # tests: those off (conftest)
    d = (await admin_client.get("/api/admin/vendor")).json()
    assert "0000aaaa" not in json.dumps(d) and d["settings"]["nvd_key_set"]
    r = await admin_client.put("/api/admin/vendor", json={"enabled": True})
    assert r.json()["nvd_key_set"] is True  # empty: kept
    assert (await admin_client.put("/api/admin/vendor", json={"clear_nvd_key": True})).json()["nvd_key_set"] is False
    assert (await admin_client.put("/api/admin/vendor", json={"nvd_key": "bad key!"})).status_code == 422


async def test_nvd_key_is_sent_as_header(admin_client, sites):
    await admin_client.put("/api/admin/vendor", json={"nvd_key": "0000aaaa-bbbb-cccc-dddd-eeeeffff0000"})
    await _follow(admin_client, "fortios", "7.4.3")
    await _round()
    nvd = sites.to("services.nvd.nist.gov")
    assert nvd and all(c.headers.get("apikey") == "0000aaaa-bbbb-cccc-dddd-eeeeffff0000" for c in nvd)
    assert all("apiKey" not in str(c.url) for c in nvd)


async def test_delete_follow_removes_versions(admin_client):
    await _follow(admin_client, "panos", "11.2.4-h23")
    assert (await admin_client.delete("/api/vendor/follows/panos")).status_code == 200
    async with db.session() as s:
        assert list(await s.scalars(select(VendorFollow))) == []
        assert list(await s.scalars(select(VendorVersion))) == []


# ---------------------------------------------------------------- 0.1.4: the vendor's verdict decides every CVE it names


async def test_vendor_advisory_decides_all_its_cves(admin_client, reader_client, sites):
    sites.nvd_by_cpe["cpe:2.3:o:paloaltonetworks:pan-os"] = "nvd_php_panos.json"
    await _follow(admin_client, "panos", "11.2.4-h23", "11.2.4-h20")
    await _round()
    d = (await reader_client.get("/api/vendor/products/panos?all=true")).json()
    by = {f["id"]: f for f in d["findings"]}
    assert "nvd:CVE-2026-109619" not in by  # grouped under Palo Alto's own advisory, not judged by NVD alone
    php = by["paloalto:CVE-2026-109618"]
    assert set(php["cves"]) >= {"CVE-2026-109618", "CVE-2026-109619"}
    assert any(a["ident"] == "CVE-2026-109619" for a in php["also"])
    per = {v["version"]: v["status"] for v in php["versions"]}
    assert per == {"11.2.4-h23": "not_affected", "11.2.4-h20": "affected"}
    # the card lists only what concerns the versions – the patched one is not "possibly affected"
    ov = (await reader_client.get("/api/vendor/overview")).json()
    card = next(i for i in ov["items"] if i["product"]["key"] == "panos")
    assert all(x["id"] != "nvd:CVE-2026-109619" for x in card["latest"])
    rank = {"affected": 4, "possible": 3, "service": 2, "unversioned": 1}
    assert [rank[x["status"]] for x in card["latest"]] == sorted((rank[x["status"]] for x in card["latest"]), reverse=True)


async def test_stored_advisories_get_all_their_cves_at_start():
    async with db.session() as s:
        s.add(VendorAdvisory(id="paloalto:CVE-2026-109618", source="paloalto", ident="CVE-2026-109618", title="Impact of Critical Vulnerabilities in PHP (CVE-2026-109618, CVE-2026-109619) on Palo Alto Networks Products",
                             summary="", url="https://security.paloaltonetworks.com/CVE-2026-109618", cves=["CVE-2026-109618"], severity="critical", data={}, fetched_at=datetime.now(UTC)))
        await s.commit()
    async with db.session() as s:
        assert await vendor.repair_advisory_cves(s) == 1
        assert await vendor.repair_advisory_cves(s) == 0  # once repaired, nothing to do
        a = await s.get(VendorAdvisory, "paloalto:CVE-2026-109618")
        assert a.cves == ["CVE-2026-109618", "CVE-2026-109619"]


async def test_related_news_keeps_the_cve_story_behind_many_substring_hits():
    """Bug hunt 0.1.16 M7: "git" is part of "Digital" and "GitHub" – 300 newer such stories pushed the story with Git's
    CVE out of "Passende News". CVE hits and whole-word name hits are found apart; substring-only stories never count."""
    async with db.session() as s:
        src = NewsSource(key="feed-v", name="Example Feed", url="https://news.example.org/v.xml", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.flush()
        now = datetime.now(UTC)
        s.add(NewsItem(source_id=src.id, url="https://news.example.org/git", url_key="kgit", title="Patchday: Lücke behoben", title_key="tgit", summary="",
                       published_at=now - timedelta(days=5), cves=["CVE-2026-1111"], search="patchday: lucke behoben cve-2026-1111", seq=1))  # fmt: skip
        s.add(NewsItem(source_id=src.id, url="https://news.example.org/word", url_key="kword", title="Neue Version von Git (C++ Teil)", title_key="tword", summary="",
                       published_at=now - timedelta(days=6), cves=[], search="neue version von git (c++ teil)", seq=2))  # fmt: skip
        for n in range(300):
            t = f"Digital-Ministerium warnt vor GitHub-Phishing {n}"
            s.add(NewsItem(source_id=src.id, url=f"https://news.example.org/{n}", url_key=f"k{n}", title=t, title_key=f"t{n}", summary="",
                           published_at=now - timedelta(minutes=n), cves=[], search=t.lower(), seq=n + 3))  # fmt: skip
        await s.commit()
        got = await vendor.related_news(s, catalog.product("git"), ["CVE-2026-1111"])
    assert [(x["title"], x["by"]) for x in got] == [("Patchday: Lücke behoben", "cve"), ("Neue Version von Git (C++ Teil)", "name")]


async def test_related_news_cache_drops_the_least_recently_used():
    """Security review L7: the cache no longer empties itself completely after 200 entries (readers could keep it
    cold by walking through the catalogue) – the least recently used entry goes."""
    vendor._related.clear()
    products = catalog.load()["products"][: vendor.RELATED_CACHE + 5]
    async with db.session() as s:
        for p in products:
            await vendor.related_news(s, p, [])
        await vendor.related_news(s, products[0], [])  # used again: computed anew, now the newest entry
    keys = [k[0] for k in vendor._related]
    assert len(keys) == vendor.RELATED_CACHE and keys[-1] == products[0]["key"] and products[1]["key"] not in keys and products[-1]["key"] in keys
    assert vendor._pg_word("C++") == r"(^|[^[:alnum:]_-])(C\+\+)($|[^[:alnum:]_-])"
