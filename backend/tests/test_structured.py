"""The structured sources (0.1.26): CSAF providers (discovery, ROLIE / changes.csv, hashes, TLP, watermark, dedupe with
the story details), cvelistV5 (delta zips, missed days, single records, verdict order), FIRST EPSS and OSV (by id only)
– parsed from trimmed real answers in tests/fixtures/structured, fetched offline against a MockTransport."""

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app import csaf_providers, cvelist, db, epss, news, osv, source_health, story_details, vendor
from app import settings as settings_store
from app import vendor_catalog as catalog
from app.models import EpssScore, NewsItem, NewsSource, StoryDetail, VendorAdvisory, VendorAdvisoryProduct, VendorEvent, VendorFetch, VendorFollow
from app.news import NewsError
from app.vendor import Adv
from app.vendor_match import evaluate

FIX = Path(__file__).parent / "fixtures" / "structured"
VFIX = Path(__file__).parent / "fixtures" / "vendor"
ON = {"csaf": True, "cvelist": True, "epss": True, "osv": True}
CISCO = "https://www.cisco.com/.well-known/csaf/"
ASA_DOC = CISCO + "2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json"


def fx(name: str) -> bytes:
    return (FIX / name).read_bytes()


def record(cid: str, vendor_: str, product: str, versions: list[dict], *, state: str = "PUBLISHED", updated: str = "2026-10-30T06:00:00.000Z") -> dict:
    """A small CVE 5 record (the shape of cvelistV5's files)."""
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": cid, "state": state, "assignerShortName": "example", "datePublished": "2026-10-29T10:00:00.000Z", "dateUpdated": updated},
        "containers": {
            "cna": {
                "title": f"{product}: example vulnerability",
                "descriptions": [{"lang": "en", "value": f"A flaw in {product} lets a remote attacker do things."}],
                "affected": [{"vendor": vendor_, "product": product, "defaultStatus": "unaffected", "versions": versions}],
                "metrics": [{"cvssV3_1": {"baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "version": "3.1"}}],
            }
        },
    }


def delta_zip(*docs) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for d in docs:
            if isinstance(d, tuple):
                z.writestr(*d)
            else:
                z.writestr(f"deltaCves/{d['cveMetadata']['cveId']}.json", json.dumps(d))
    return buf.getvalue()


class Net:
    """The fake internet: routes by URL (exact or prefix), every request recorded. ETag "v1" → 304 when sent back."""

    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.routes: dict[str, object] = {}

    def add(self, url: str, body, status: int = 200, headers: dict | None = None) -> None:
        self.routes[url] = (status, body, headers or {})

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        u = str(req.url)
        hit = self.routes.get(u) or next((v for k, v in self.routes.items() if k.endswith("*") and u.startswith(k[:-1])), None)
        if hit is None:
            return httpx.Response(404, text="not found")
        status, body, headers = hit
        if callable(body):
            return body(req)
        if headers.get("ETag") and req.headers.get("if-none-match") == headers["ETag"]:
            return httpx.Response(304)
        content = body if isinstance(body, bytes) else json.dumps(body).encode() if not isinstance(body, str) else body.encode()
        return httpx.Response(status, content=content, headers=headers)

    def urls(self, host: str | None = None) -> list[str]:
        return [str(c.url) for c in self.calls if host is None or c.url.host == host]


@pytest.fixture
def net(monkeypatch, tmp_path):
    n = Net()
    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(n.handler))
    monkeypatch.setattr(catalog, "_data_file", lambda: tmp_path / "vendor_catalog.json")
    catalog._cache.stamp = ()
    vendor._last.clear()
    vendor.bump()
    return n


@pytest.fixture
def structured_on(monkeypatch):
    monkeypatch.setitem(settings_store.DEFAULTS, "vendor", {**settings_store.DEFAULTS["vendor"], **ON})


async def _follow(c, key: str, *versions: str) -> None:
    r = await c.put(f"/api/vendor/follows/{key}", json={"enabled": True})
    assert r.status_code == 200, r.text
    for v in versions:
        r = await c.post(f"/api/vendor/follows/{key}/versions", json={"version": v})
        assert r.status_code == 200, r.text


def _adv(id_: str, source: str, ident: str, data: dict, *, cves: list[str] | None = None, cvss: float | None = None, exploited: bool = False) -> Adv:
    return Adv(id_, source, ident, ident, "", "", cves or [ident], cvss, "high", exploited, datetime(2026, 10, 1, tzinfo=UTC), None, data)


# ---------------------------------------------------------------- the catalogue: providers, OSV packages


def test_catalogue_maps_providers_and_osv_packages():
    keys = {p["key"]: p for p in csaf_providers.providers()}
    assert {"siemens", "cisco", "schneider"} <= set(keys) and keys["cisco"]["vendors"] == ["Cisco", "Cisco (Duo)", "Splunk (Cisco)"]
    assert [p["key"] for p in csaf_providers.providers_for(catalog.product("cisco-asa"))] == ["cisco"]
    assert csaf_providers.providers_for(catalog.product("fortios")) == []  # its own advisory source
    assert csaf_providers.providers_for({"vendor": "cisco"})[0]["key"] == "cisco"  # a product added by CPE ("cisco")
    assert ["Maven", "org.apache.tomcat:tomcat-catalina"] in catalog.product("tomcat")["osv"]
    assert catalog.product("django")["osv"] == [["PyPI", "django"]] and catalog.product("django")["category"] == "dev"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("providers:\n  - key: acme\n    name: Acme\n    domain: acme.example\n    vendors: [No Such Vendor]\n", "vendor 'No Such Vendor' is no vendor"),
        ("providers:\n  - key: a\n    name: A\n    domain: www.cisco.com\n    vendors: [Cisco]\n  - key: a\n    name: B\n    domain: b.example\n    vendors: [Cisco]\n", "listed twice"),
        ("providers:\n  - key: a\n    name: A\n    domain: http://x\n    vendors: [Cisco]\n", "csaf.yaml"),
        ("providers:\n  - key: a\n    name: A\n    domain: x.example\n    metadata: http://x.example/pm.json\n    vendors: [Cisco]\n", "csaf.yaml"),
    ],
)
def test_broken_csaf_yaml_is_refused(tmp_path, text, message):
    import shutil

    from app import catalog_data

    d = tmp_path / "catalog"
    shutil.copytree(catalog_data.DIR, d)
    (d / "csaf.yaml").write_text(text)
    with pytest.raises(catalog_data.CatalogError, match=message):
        catalog_data.load(d)


def test_osv_ecosystem_is_checked(tmp_path):
    import shutil

    from app import catalog_data

    d = tmp_path / "catalog"
    shutil.copytree(catalog_data.DIR, d)
    p = d / "products" / "dev.yaml"
    p.write_text(p.read_text().replace("[[PyPI, django]]", "[[Debian, django]]"))
    with pytest.raises(catalog_data.CatalogError, match="osv ecosystem 'Debian'"):
        catalog_data.load(d)


# ---------------------------------------------------------------- CSAF: parsers


def test_aggregator_and_provider_metadata():
    hosts = csaf_providers.parse_aggregator(fx("aggregator.json"))
    assert hosts["cert-portal.siemens.com"] == "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json"
    assert "www.se.com" in hosts and all(u.startswith("https://") for u in hosts.values())
    siemens = next(p for p in csaf_providers.providers() if p["key"] == "siemens")
    meta = csaf_providers.parse_metadata(fx("pm_siemens.json"), siemens)
    assert meta["feeds"] == [{"url": "https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json", "tlp": "WHITE"}] and meta["directories"] == []
    cisco = next(p for p in csaf_providers.providers() if p["key"] == "cisco")
    assert csaf_providers.parse_metadata(fx("pm_cisco.json"), cisco)["directories"] == [CISCO]
    # TLP:GREEN feeds and other hosts are never read
    doc = {
        "distributions": [
            {"rolie": {"feeds": [{"tlp_label": "GREEN", "url": "https://www.cisco.com/green.json"}, {"tlp_label": "CLEAR", "url": "https://evil.example/feed.json"}]}},
            {"directory_url": "http://www.cisco.com/plain/"},
        ]
    }
    got = csaf_providers.parse_metadata(json.dumps(doc).encode(), cisco)
    assert got["feeds"] == [] and got["directories"] == []
    with pytest.raises(NewsError):
        csaf_providers.parse_metadata(b"{}", cisco)


def test_rolie_and_changes_csv():
    siemens = next(p for p in csaf_providers.providers() if p["key"] == "siemens")
    rows = csaf_providers.parse_rolie(fx("rolie_siemens.json"), siemens, "WHITE")
    assert len(rows) == 3 and rows[0]["url"].endswith(".json") and rows[0]["hash"].endswith(".sha512") and rows[0]["ts"].endswith("Z")
    cisco = next(p for p in csaf_providers.providers() if p["key"] == "cisco")
    csv_ = b'2026/cisco-sa-one.json,2026-10-30T06:01:02Z\n"2025/cisco-sa-two.json","2025-01-02T03:04:05.000Z"\n../etc/passwd.json,2026-10-30T00:00:00Z\nhttps://evil.example/x.json,2026-10-30T00:00:00Z\nbroken line\n'
    rows = csaf_providers.parse_changes(csv_, CISCO, cisco)
    assert [(r["url"], r["ts"]) for r in rows] == [(CISCO + "2026/cisco-sa-one.json", "2026-10-30T06:01:02Z"), (CISCO + "2025/cisco-sa-two.json", "2025-01-02T03:04:05Z")]


def test_hash_and_tlp():
    body = b'{"x": 1}'
    assert csaf_providers.check_hash(body, f"{hashlib.sha512(body).hexdigest().upper()}  x.json\n".encode()) is True
    assert csaf_providers.check_hash(body, f"{hashlib.sha256(body).hexdigest()} x.json".encode()) is True
    assert csaf_providers.check_hash(body + b" ", hashlib.sha256(body).hexdigest().encode()) is False
    assert csaf_providers.check_hash(body, b"<html>not found</html>") is None
    assert csaf_providers.tlp_ok("WHITE", "") and csaf_providers.tlp_ok("CLEAR", "WHITE") and csaf_providers.tlp_ok("", "")
    assert not csaf_providers.tlp_ok("GREEN", "WHITE") and not csaf_providers.tlp_ok("", "AMBER") and not csaf_providers.tlp_ok("AMBER+STRICT", "")


def test_advisory_of_a_document():
    cisco = next(p for p in csaf_providers.providers() if p["key"] == "cisco")
    adv = csaf_providers.advisory(fx("csaf_cisco_asa.json"), cisco, {"url": ASA_DOC, "tlp": ""})
    assert adv["id"] == "csaf:cisco-sa-asaftd-tunnel-dos-s6mgkb75" and adv["source"] == "csaf" and adv["url"].startswith("https://sec.cloudapps.cisco.com/")
    assert adv["data"]["publisher"] == "Cisco PSIRT (CSAF)"  # the same record the story details store for Cisco
    assert evaluate(catalog.product("cisco-asa"), "csaf", adv["data"], "9.20.2").status == "affected"
    doc = json.loads(fx("csaf_cisco_asa.json"))
    doc["document"]["distribution"] = {"tlp": {"label": "GREEN"}}
    with pytest.raises(NewsError, match="blocked"):
        csaf_providers.advisory(json.dumps(doc).encode(), cisco, {"url": ASA_DOC, "tlp": ""})


# ---------------------------------------------------------------- CSAF: the provider round


def _cisco_routes(net: Net, *, csv_: str, doc: bytes | None = None, digest: str | None = None) -> None:
    net.add(csaf_providers.AGGREGATOR, fx("aggregator.json"), headers={"ETag": '"agg"'})
    net.add(CISCO + "provider-metadata.json", fx("pm_cisco.json"))
    net.add(CISCO + "changes.csv", csv_, headers={"ETag": '"c1"'})
    body = doc or fx("csaf_cisco_asa.json")
    net.add(ASA_DOC, body)
    net.add(ASA_DOC + ".sha512", f"{digest or hashlib.sha512(body).hexdigest()}  cisco-sa-asaftd-tunnel-dos-s6mgkb75.json\n")


async def _csaf_round(force: bool = True) -> dict:
    async with db.session() as s:
        products = [p for f in await vendor.follows(s) if (p := vendor.product_of(f))]
        return await csaf_providers.sync_all(s, products, timedelta(hours=6), await vendor.current_index(s), force)


async def test_provider_round_hash_watermark_and_quiet_first_fill(net, structured_on, admin_client, reader_client):
    await _follow(admin_client, "cisco-asa", "9.20.2")
    now = datetime.now(UTC)
    # older than FRESH_FILL (7 days): the first fill keeps it quiet; older than INITIAL (90 days): not read at all
    recent, old = (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ"), (now - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _cisco_routes(net, csv_=f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{recent}\n2024/cisco-sa-old-one.json,{old}\n")
    assert await _csaf_round() == {"csaf:cisco": 1}
    asked = net.urls()
    assert csaf_providers.AGGREGATOR in asked and CISCO + "provider-metadata.json" in asked  # not in the aggregator: well-known
    assert ASA_DOC in asked and ASA_DOC + ".sha512" in asked and not any("old-one" in u for u in asked)  # older than the first fill
    async with db.session() as s:
        a = await s.get(VendorAdvisory, "csaf:cisco-sa-asaftd-tunnel-dos-s6mgkb75")
        assert a is not None and a.data.get("initial") is True
        assert "cisco-asa" in set(await s.scalars(select(VendorAdvisoryProduct.product).where(VendorAdvisoryProduct.advisory_id == a.id)))
        st = await s.get(VendorFetch, "csaf:cisco")
        assert json.loads(st.cursor)["w"].startswith(recent) and json.loads(st.cursor)["hash"] == ".sha512" and st.etag == '"c1"'
        rows = list(await s.scalars(select(source_health.SourceFetchStat).where(source_health.SourceFetchStat.key == "csaf:cisco")))
        assert rows[0].kind == "structured" and rows[0].items == 1 and rows[0].ok
    f = next(x for x in (await reader_client.get("/api/vendor/products/cisco-asa")).json()["findings"] if x["id"].startswith("csaf:"))
    assert f["status"] == "affected" and f["quiet"] is True
    # the next round: changes.csv unchanged (304) – no document asked again
    n = len(net.calls)
    await _csaf_round()
    assert len(net.calls) - n == 3 and ASA_DOC not in net.urls()[n:]  # (forced) aggregator 304, metadata, changes.csv 304


async def test_first_fill_is_never_notified_later_documents_are(net, structured_on, admin_client):
    """A product followed long before (its baseline done): what the provider's first fill brings is shown, not sent;
    a document published after it is sent."""
    await _follow(admin_client, "cisco-asa", "9.20.2")
    now = datetime.now(UTC)
    async with db.session() as s:
        f = (await s.scalars(select(VendorFollow).where(VendorFollow.product == "cisco-asa"))).one()
        f.baseline_at = now - timedelta(days=100)
        for v in (await vendor.versions_of(s, [f.id]))[f.id]:
            v.baseline_at = now - timedelta(days=100)
        s.add(VendorFetch(key="nvd:a:cisco:adaptive_security_appliance_software", failures=0, items=0, last_ok_at=now))
        await s.commit()
    t1 = (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")  # older than FRESH_FILL: quiet (a younger one: M7 test)
    _cisco_routes(net, csv_=f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{t1}\n")
    await _csaf_round()

    async def vuln_events() -> list[VendorEvent]:
        async with db.session() as s:
            await vendor.evaluate_events(s, full=True)
            return list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "vuln")))

    first = await vuln_events()
    assert len(first) == 1 and first[0].baseline  # the first fill: quiet
    doc = json.loads(fx("csaf_cisco_asa.json"))
    doc["document"]["tracking"]["id"] = "cisco-sa-asaftd-second-x"
    doc["vulnerabilities"][0]["cve"] = "CVE-2026-76419"
    body = json.dumps(doc).encode()
    t2 = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    net.add(CISCO + "changes.csv", f"2026/cisco-sa-asaftd-second-x.json,{t2}\n2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{t1}\n", headers={"ETag": '"c2"'})
    net.add(CISCO + "2026/cisco-sa-asaftd-second-x.json", body)
    net.add(CISCO + "2026/cisco-sa-asaftd-second-x.json.sha512", hashlib.sha512(body).hexdigest())
    await _csaf_round()
    later = [e for e in await vuln_events() if e.key.endswith("cisco-sa-asaftd-second-x")]
    assert len(later) == 1 and not later[0].baseline


async def test_provider_skips_a_wrong_hash_and_goes_on(net, structured_on, admin_client):
    await _follow(admin_client, "cisco-asa")
    recent = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _cisco_routes(net, csv_=f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{recent}\n", digest="0" * 128)
    assert await _csaf_round() == {"csaf:cisco": 0}
    async with db.session() as s:
        assert await s.get(VendorAdvisory, "csaf:cisco-sa-asaftd-tunnel-dos-s6mgkb75") is None
        st = await s.get(VendorFetch, "csaf:cisco")
        assert st.error is None and recent in json.loads(st.cursor)["w"]  # skipped for good, the watermark moved on
        stat = (await s.scalars(select(source_health.SourceFetchStat).where(source_health.SourceFetchStat.key == "csaf:cisco"))).one()
        assert stat.parse_errors == 1


async def test_provider_backlog_is_bounded_and_resumed(net, structured_on, admin_client, monkeypatch):
    monkeypatch.setattr(csaf_providers, "DOCS_PER_ROUND", 1)
    await _follow(admin_client, "cisco-asa")
    t1, t2 = ((datetime.now(UTC) - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ") for d in (3, 1))
    _cisco_routes(net, csv_=f"2026/cisco-sa-second.json,{t2}\n2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{t1}\n")
    net.add(CISCO + "2026/cisco-sa-second.json", fx("csaf_cisco_asa.json"))
    net.add(CISCO + "2026/cisco-sa-second.json.sha512", hashlib.sha512(fx("csaf_cisco_asa.json")).hexdigest())
    await _csaf_round()
    async with db.session() as s:
        st = await s.get(VendorFetch, "csaf:cisco")
        cur = json.loads(st.cursor)
        assert cur["initial"] is True and t1 in cur["w"] and st.etag is None  # oldest first; the list again next time
        assert st.next_fetch_at - datetime.now(UTC) < timedelta(minutes=25)
    assert ASA_DOC in net.urls() and CISCO + "2026/cisco-sa-second.json" not in net.urls()
    await _csaf_round()
    assert CISCO + "2026/cisco-sa-second.json" in net.urls()
    async with db.session() as s:
        cur = json.loads((await s.get(VendorFetch, "csaf:cisco")).cursor)
    assert t2 in cur["w"] and cur["initial"] is False


async def test_provider_passing_error_retries_the_document(net, structured_on, admin_client):
    """A document answering 503: the provider's error (backoff) – the document waits on the retry list (the watermark
    moves on, security review M2) and is read in a later round."""
    await _follow(admin_client, "cisco-asa")
    recent = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _cisco_routes(net, csv_=f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{recent}\n")
    net.add(ASA_DOC, b"", status=503)
    await _csaf_round()
    async with db.session() as s:
        st = await s.get(VendorFetch, "csaf:cisco")
        cur = json.loads(st.cursor)
        assert st.failures == 1 and st.error.startswith("rate_limited") and cur["retry"][ASA_DOC]["n"] == 1
    net.add(ASA_DOC, fx("csaf_cisco_asa.json"))
    vendor._blocked.clear()  # the 503 paused the host …
    async with db.session() as s:
        (await s.get(VendorFetch, "csaf:cisco")).next_fetch_at = None  # … and the provider (backoff)
        await s.commit()
    await _csaf_round()
    async with db.session() as s:
        st = await s.get(VendorFetch, "csaf:cisco", populate_existing=True)
        assert json.loads(st.cursor)["retry"] == {} and st.failures == 0
        assert await s.get(VendorAdvisory, "csaf:cisco-sa-asaftd-tunnel-dos-s6mgkb75") is not None


async def test_story_and_provider_store_one_record(net, structured_on, admin_client):
    """The same Cisco advisory from a story (story details) and from the provider: one record, one finding."""
    await _follow(admin_client, "cisco-asa", "9.20.2")
    recent = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _cisco_routes(net, csv_=f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{recent}\n")
    await _csaf_round()
    d = story_details.parse_csaf(fx("csaf_cisco_asa.json"), "cisco", story_details.STORE_PRODUCTS)
    item = NewsItem(url="https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tunnel-dos-s6mgkb75", title="t", summary="", published_at=datetime.now(UTC))
    async with db.session() as s:
        await story_details._store_as_advisory(s, d, item)
        ids = list(await s.scalars(select(VendorAdvisory.id).where(VendorAdvisory.source == "csaf")))
    assert ids == ["csaf:cisco-sa-asaftd-tunnel-dos-s6mgkb75"]


async def test_provider_only_while_a_product_of_its_vendor_is_followed(net, structured_on, admin_client):
    await _follow(admin_client, "fortios")
    assert await _csaf_round() == {} and net.calls == []
    async with db.session() as s:
        assert "csaf:cisco" not in await vendor.active_keys(s)
    await _follow(admin_client, "cisco-asa")
    async with db.session() as s:
        keys = await vendor.active_keys(s)
    assert {"csaf:cisco", csaf_providers.AGGREGATOR_KEY} <= keys and "csaf:siemens" not in keys


# ---------------------------------------------------------------- cvelistV5: parsers


def test_release_names_the_delta_only():
    rel = cvelist.parse_release(fx("release_latest.json"))
    assert rel["at"] == "0700Z" and rel["day"] == "2026-10-30" and rel["url"].startswith(cvelist.DOWNLOAD) and "all_CVEs" not in rel["url"]
    doc = json.loads(fx("release_latest.json"))
    doc["assets"] = [a for a in doc["assets"] if "all_CVEs" in a["name"]]
    with pytest.raises(NewsError) as e:
        cvelist.parse_release(json.dumps(doc).encode())
    assert "without a delta" in e.value.detail
    doc = json.loads(fx("release_latest.json"))
    for a in doc["assets"]:
        a["browser_download_url"] = a["browser_download_url"].replace("github.com/CVEProject", "github.com/someone-else")
    with pytest.raises(NewsError):
        cvelist.parse_release(json.dumps(doc).encode())
    assert cvelist.raw_url("CVE-2024-3400").endswith("/cves/2024/3xxx/CVE-2024-3400.json")
    assert cvelist.raw_url("CVE-2026-102010").endswith("/cves/2026/102xxx/CVE-2026-102010.json")


def test_record_with_cisa_adp():
    a = cvelist.parse_one(fx("cve_CVE-2024-3400.json"))
    assert a["id"] == "cvelist:CVE-2024-3400" and a["cvss"] == 10.0 and a["severity"] == "critical" and a["exploited"]
    d = a["data"]
    assert d["ssvc"]["exploitation"] == "active" and d["ssvc"]["automatable"] == "yes" and d["kev"]["added"] == "2024-04-12"
    assert d["cna"][0]["affectedData"][0]["product"] == "PAN-OS" and d["adp"][0]["affectedData"][0]["cpes"][0].startswith("cpe:2.3:o:paloaltonetworks:pan-os")
    assert d["configs"] == [] and "CWE-77" in d["cwe"]
    assert cvelist.parse_record(record("CVE-2026-10001", "Example", "X", [], state="REJECTED")) == "rejected:CVE-2026-10001"
    assert cvelist.parse_record({"cveMetadata": {"cveId": "nope"}}) is None
    with pytest.raises(NewsError):
        cvelist.parse_one(b"not json")


def test_read_delta_and_its_limits(monkeypatch):
    blob = delta_zip(
        record("CVE-2026-90001", "Example Corp", "Gateway", [{"version": "2.0", "lessThan": "2.4.1", "status": "affected", "versionType": "semver"}]),
        record("CVE-2026-90002", "Example Corp", "Gateway", [], state="REJECTED"),
        ("deltaCves/CVE-2026-90003.json", "{broken"),
        ("deltaCves/readme.txt", "x"),
    )
    advs, rejected, bad = cvelist.read_delta(blob)
    assert [a["ident"] for a in advs] == ["CVE-2026-90001"] and rejected == ["CVE-2026-90002"] and bad == 1
    monkeypatch.setattr(cvelist, "UNZIPPED_LIMIT", 100)
    with pytest.raises(NewsError, match="too_large|unpacks"):
        cvelist.read_delta(blob)
    with pytest.raises(NewsError):
        cvelist.read_delta(b"no zip")


# ---------------------------------------------------------------- cvelistV5: verdict order


PAN = {"key": "panos", "label": "PAN-OS", "vendor": "Palo Alto Networks", "cpes": ["o:paloaltonetworks:pan-os"], "scheme": "panos", "cna": [["Palo Alto Networks", "PAN-OS"]]}


def test_cvelist_decides_where_nvd_has_no_configuration():
    cvl = cvelist.parse_one(fx("cve_CVE-2024-3400.json"))
    rec = _adv(cvl["id"], "cvelist", "CVE-2024-3400", cvl["data"], cvss=10.0, exploited=True)
    # the NVD record without CPE configuration (not analysed) and without the CNA's data
    nvd = _adv("nvd:CVE-2024-3400", "nvd", "CVE-2024-3400", {"configs": [], "cna": [], "desc": "x"})
    groups = vendor.groups_of([nvd, rec])
    assert len(groups) == 1 and groups[0]["primary"] is nvd and groups[0]["cve"] == [rec]
    # 10.2.0 < 10.2.9-h1 (the CNA's range; its hotfix changes)
    assert vendor.group_verdict(PAN, groups[0], "10.2.7").status == "affected"
    assert vendor.group_verdict(PAN, groups[0], "10.2.7").fixed == "10.2.9-h1"
    assert vendor.group_verdict(PAN, groups[0], "9.1.0").status == "not_affected"
    # analysed by the NVD (a configuration): the NVD decides
    analysed = _adv("nvd:CVE-2024-3400", "nvd", "CVE-2024-3400", {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", "versionStartIncluding": "10.2.0", "versionEndExcluding": "10.2.8"}]}]}], "cna": []})
    g = vendor.groups_of([analysed, rec])[0]
    assert vendor.group_verdict(PAN, g, "10.2.8").status == "not_affected"
    # a cvelistV5 record alone (the NVD has none yet): it leads
    g = vendor.groups_of([rec])[0]
    assert g["primary"] is rec and vendor.group_verdict(PAN, g, "11.0.2").status == "affected"
    # findings: exploited (SSVC "active", KEV), the SSVC decision, the record in "also"
    f = vendor.findings(PAN, [nvd, rec], [], {}, set(), epss={"CVE-2024-3400": {"cve": "CVE-2024-3400", "score": 0.97, "percentile": 0.999, "date": "2026-10-29"}})[0]
    assert f["exploited"] and f["ssvc"]["exploitation"] == "active" and f["also"][0]["source"] == "cvelist" and f["cvss"] == 10.0
    assert f["epss"] == {"cve": "CVE-2024-3400", "score": 0.97, "percentile": 0.999, "date": "2026-10-29"}


def test_vendor_advisory_still_decides_first():
    cvl = cvelist.parse_one(fx("cve_CVE-2024-3400.json"))
    rec = _adv(cvl["id"], "cvelist", "CVE-2024-3400", cvl["data"])
    pan = _adv("paloalto:CVE-2024-3400", "paloalto", "CVE-2024-3400", {"lines": [{"name": "PAN-OS 10.2", "affected": "< 10.2.9-h1", "fixed": ">= 10.2.9-h1"}], "affected_list": [], "products": ["PAN-OS"]})
    g = vendor.groups_of([pan, rec])[0]
    assert g["primary"] is pan and g["cve"] == [rec]
    assert vendor.group_verdict(PAN, g, "10.2.9-h1").status == "not_affected"


def test_adp_rows_only_where_the_cna_says_nothing():
    data = {"configs": [], "cna": [{"affectedData": [{"vendor": "Other", "product": "Thing", "versions": [{"version": "1.0", "status": "affected"}]}]}], "adp": [{"affectedData": [{"vendor": "fortinet", "product": "fortios", "cpes": ["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"], "defaultStatus": "unknown", "versions": [{"version": "7.4.0", "lessThan": "7.4.9", "status": "affected", "versionType": "semver"}]}]}], "desc": "x"}
    fortios = catalog.product("fortios")
    assert evaluate(fortios, "cvelist", data, "7.4.8").status == "affected"
    assert evaluate(fortios, "cvelist", data, "7.4.9").status == "not_affected"
    # a short version stands for every release inside it (as for the NVD): "7.4" is only "possibly"
    assert evaluate(fortios, "cvelist", data, "7.4").reason == "short_version"
    ix = vendor.index_of([fortios])
    assert vendor.link({"id": "cvelist:X", "source": "cvelist", "data": data}, ix) == {"fortios"}


# ---------------------------------------------------------------- cvelistV5: the hourly delta, single records


def _gh_routes(net: Net, blob: bytes, *, tag: str = "cve_2026-10-30_0700Z") -> dict:
    rel = json.loads(fx("release_latest.json"))
    rel["tag_name"] = tag
    zip_url = next(a["browser_download_url"] for a in rel["assets"] if "_delta_" in a["name"])
    net.add(cvelist.LATEST, rel, headers={"ETag": '"r1"'})
    net.add(zip_url, blob)
    return rel


async def _delta(force: bool = True) -> int | None:
    async with db.session() as s:
        products = [p for f in await vendor.follows(s) if (p := vendor.product_of(f))]
        return await cvelist.sync_delta(s, products, await vendor.current_index(s), force)


async def test_delta_keeps_followed_and_known_records(net, structured_on, admin_client):
    await _follow(admin_client, "panos", "10.2.7")
    pan = json.loads(fx("cve_CVE-2024-3400.json"))
    other = record("CVE-2026-90001", "Example Corp", "Gateway", [{"version": "2.0", "lessThan": "2.4.1", "status": "affected"}])
    gone = record("CVE-2026-90002", "Example Corp", "Gateway", [], state="REJECTED")
    async with db.session() as s:  # stored before (a story asked for it): rejected now – removed
        await vendor.store(s, [cvelist.parse_record(record("CVE-2026-90002", "Example Corp", "Gateway", []))], await vendor.current_index(s))
    _gh_routes(net, delta_zip(pan, other, gone))
    assert await _delta() == 1
    async with db.session() as s:
        ids = set(await s.scalars(select(VendorAdvisory.id).where(VendorAdvisory.source == "cvelist")))
        assert ids == {"cvelist:CVE-2024-3400"}
        assert "panos" in set(await s.scalars(select(VendorAdvisoryProduct.product).where(VendorAdvisoryProduct.advisory_id == "cvelist:CVE-2024-3400")))
        st = await s.get(VendorFetch, cvelist.DELTA_KEY)
        cur = json.loads(st.cursor)
        assert {k: cur[k] for k in ("tag", "day", "at")} == {"tag": "cve_2026-10-30_0700Z", "day": "2026-10-30", "at": "0700Z"} and st.etag == '"r1"'
    hosts = {c.url.host for c in net.calls}
    assert hosts == {"api.github.com", "github.com"}
    # unchanged (304): the zip is not asked again
    n = len(net.calls)
    await _delta()
    assert len(net.calls) == n + 1


async def test_delta_reads_missed_days_from_their_end_of_day_zip(net, structured_on, admin_client):
    await _follow(admin_client, "panos")
    async with db.session() as s:
        s.add(VendorFetch(key=cvelist.DELTA_KEY, failures=0, items=0, cursor=json.dumps({"tag": "cve_2026-10-28_1500Z", "day": "2026-10-28", "at": "1500Z"})))
        await s.commit()
    _gh_routes(net, delta_zip(json.loads(fx("cve_CVE-2024-3400.json"))))
    for day in ("2026-10-28", "2026-10-29"):
        rel = json.loads(fx("release_latest.json"))
        rel["tag_name"] = f"cve_{day}_at_end_of_day"
        rel["assets"] = [{"name": f"{day}_delta_CVEs_at_end_of_day.zip", "size": 100, "browser_download_url": f"{cvelist.DOWNLOAD}cve_{day}_at_end_of_day/{day}_delta_CVEs_at_end_of_day.zip"}]
        net.add(cvelist.BY_TAG.format(tag=f"cve_{day}_at_end_of_day"), rel)
        net.add(rel["assets"][0]["browser_download_url"], delta_zip(record("CVE-2026-1" + day[-2:] + "00", "Palo Alto Networks", "PAN-OS", [{"version": "11.0.0", "lessThan": "11.0.9", "status": "affected"}])))
    await _delta()
    async with db.session() as s:
        ids = set(await s.scalars(select(VendorAdvisory.ident).where(VendorAdvisory.source == "cvelist")))
    assert ids == {"CVE-2024-3400", "CVE-2026-12800", "CVE-2026-12900"}
    assert not any("all_CVEs" in u for u in net.urls())


async def test_single_record_and_backfill_of_unanalysed_cves(net, structured_on, admin_client):
    await _follow(admin_client, "panos", "10.2.7")
    nvd = {"id": "nvd:CVE-2024-3400", "source": "nvd", "ident": "CVE-2024-3400", "title": "x", "summary": "", "url": "", "cves": ["CVE-2024-3400"], "cvss": None, "severity": "info", "published_at": datetime(2024, 4, 12, tzinfo=UTC), "updated_at": None,
           "data": {"configs": [], "cna": [{"affectedData": [{"vendor": "Palo Alto Networks", "product": "PAN-OS", "versions": [{"version": "10.2.0", "lessThan": "10.3", "status": "affected"}]}]}], "desc": "x", "status": "Awaiting Analysis"}}  # fmt: skip
    async with db.session() as s:
        await vendor.store(s, [nvd], await vendor.current_index(s))
    net.add(cvelist.raw_url("CVE-2024-3400"), fx("cve_CVE-2024-3400.json"))
    async with db.session() as s:
        products = [p for f in await vendor.follows(s) if (p := vendor.product_of(f))]
        assert await cvelist.backfill(s, products, await vendor.current_index(s), True) == 1
        assert await s.get(VendorAdvisory, "cvelist:CVE-2024-3400") is not None
        # asked once: not again within the week
        assert await cvelist.backfill(s, products, await vendor.current_index(s), True) is None
    assert net.urls() == [cvelist.raw_url("CVE-2024-3400")]
    # the finding now follows the CNA's current data (hotfix changes) instead of the NVD's old copy
    vendor.bump()
    async with db.session() as s:
        f = (await s.scalars(select(VendorFollow).where(VendorFollow.product == "panos"))).one()
        vs = (await vendor.versions_of(s, [f.id]))[f.id]
        view = await vendor.product_view(s, f, vs)
    hit = next(x for x in view["findings"] if "CVE-2024-3400" in x["cves"])
    assert hit["status"] == "affected" and hit["versions"][0]["fixed"] == "10.2.9-h1" and hit["exploited"]


async def test_story_details_use_cvelist_when_nvd_knows_nothing(net, structured_on):
    from tests.conftest import set_news

    await set_news(enabled=True)
    net.add("https://services.nvd.nist.gov/*", {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []})
    net.add(cvelist.raw_url("CVE-2024-3400"), fx("cve_CVE-2024-3400.json"))
    async with db.session() as s:
        src_ = (await s.scalars(select(NewsSource).where(NewsSource.key == "heise"))).one()
        src_.enabled = True
        url = "https://www.heise.de/news/pan-os.html"
        item = NewsItem(source_id=src_.id, url=url, url_key=news._key(news.normalize_url(url)), title="PAN-OS-Lücke", title_key=news.title_key("PAN-OS-Lücke"), summary="", published_at=datetime.now(UTC), fetched_at=datetime.now(UTC), cves=["CVE-2024-3400"], seq=await news.next_seq(s))
        s.add(item)
        await s.commit()
        await story_details.enrich_round(s)
        det = await s.get(StoryDetail, item.id)
    assert det.status == "ok" and det.data["via_cvelist"] and det.data["cvss"][0]["score"] == 10.0 and det.data["exploited"]
    assert det.data["products"][0]["name"] == "PAN-OS" and det.data["ssvc"]["exploitation"] == "active"
    assert story_details.matches(det.data, [(catalog.product("panos"), [])])[0]["product"] == "panos"


# ---------------------------------------------------------------- EPSS


def test_epss_parse_and_batches():
    rows = epss.parse(fx("epss.json"))
    assert rows[0] == {"cve": "CVE-2024-3400", "score": 0.99999, "percentile": 1.0, "date": "2026-10-29"}
    assert epss.parse(b'{"data": [{"cve": "x", "epss": "2"}, {"cve": "CVE-2026-1234", "epss": "nope"}]}') == []
    many = [f"CVE-2026-{100000 + i}" for i in range(250)]
    parts = epss.batches(many)
    assert [len(p) for p in parts] == [100, 100, 50] and all(len(",".join(p)) < epss.QUERY_MAX for p in parts)
    assert epss.url(["CVE-2024-3400", "CVE-2021-44228"]) == "https://api.first.org/data/v1/epss?cve=CVE-2024-3400,CVE-2021-44228&limit=100"


async def test_epss_for_findings_and_stories_once_a_day(net, structured_on, admin_client, reader_client):
    from tests.conftest import set_news

    await set_news(enabled=True)
    await _follow(admin_client, "panos", "10.2.7")
    cvl = cvelist.parse_one(fx("cve_CVE-2024-3400.json"))
    async with db.session() as s:
        await vendor.store(s, [cvl], await vendor.current_index(s))
        src_ = (await s.scalars(select(NewsSource).where(NewsSource.key == "heise"))).one()
        url = "https://www.heise.de/news/log4j.html"
        s.add(NewsItem(source_id=src_.id, url=url, url_key=news._key(news.normalize_url(url)), title="Log4Shell", title_key=news.title_key("Log4Shell"), summary="", published_at=datetime.now(UTC), fetched_at=datetime.now(UTC), cves=["CVE-2021-44228"], seq=await news.next_seq(s)))
        await s.commit()
    net.add("https://api.first.org/data/v1/epss*", fx("epss.json"))
    async with db.session() as s:
        assert await epss.refresh(s, force=True) == 2
    (req,) = [c for c in net.calls if c.url.host == "api.first.org"]
    assert set(req.url.params) == {"cve", "limit"} and set(req.url.params["cve"].split(",")) == {"CVE-2024-3400", "CVE-2021-44228"}
    async with db.session() as s:
        rows = {r.cve: r for r in await s.scalars(select(EpssScore))}
        assert rows["CVE-2024-3400"].score == 0.99999 and rows["CVE-2024-3400"].day == "2026-10-29"
        assert await epss.refresh(s, force=True) is None  # asked today: not again
    assert len([c for c in net.calls if c.url.host == "api.first.org"]) == 1
    f = (await reader_client.get("/api/vendor/products/panos")).json()["findings"]
    assert next(x for x in f if "CVE-2024-3400" in x["cves"])["epss"]["score"] == 0.99999
    story = next(x for x in (await reader_client.get("/api/news?state=new")).json()["items"] if x["title"] == "Log4Shell")
    assert (await reader_client.get(f"/api/news/{story['id']}")).json()["epss"][0]["cve"] == "CVE-2021-44228"


async def test_findings_sorted_by_epss(net, structured_on, admin_client, reader_client):
    await _follow(admin_client, "panos")
    recs = [cvelist.parse_record(record(f"CVE-2026-9000{i}", "Palo Alto Networks", "PAN-OS", [{"version": "10.0.0", "lessThan": "12.0", "status": "affected"}])) for i in range(3)]
    async with db.session() as s:
        await vendor.store(s, recs, await vendor.current_index(s))
        for i, score in enumerate((0.1, 0.9, 0.5)):
            s.add(EpssScore(cve=f"CVE-2026-9000{i}", score=score, percentile=score, day="2026-10-29", fetched_at=datetime.now(UTC)))
        await s.commit()
    vendor.bump()
    got = (await reader_client.get("/api/vendor/products/panos?sort=epss")).json()["findings"]
    assert [x["epss"]["score"] for x in got] == [0.9, 0.5, 0.1]
    assert (await reader_client.get("/api/vendor/products/panos?sort=cheese")).status_code == 422


# ---------------------------------------------------------------- OSV


def test_osv_parse_keeps_ecosystem_ranges_only():
    own = osv.parse(fx("osv_CVE-2023-46589.json"))
    assert own["id"] == "CVE-2023-46589" and "GHSA-fccv-jmmp-qg76" in own["aliases"] and own["packages"] == []  # GIT ranges: dropped
    gh = osv.parse(fx("osv_GHSA-fccv-jmmp-qg76.json"))
    pkg = gh["packages"][0]
    assert (pkg["ecosystem"], pkg["name"]) == ("Maven", "org.apache.tomcat:tomcat-catalina") and pkg["ranges"] == [{"introduced": "11.0.0-M1", "fixed": "11.0.0-M11"}]
    adv = osv.to_advisory("CVE-2023-46589", [own, gh])
    assert adv["id"] == "osv:CVE-2023-46589" and adv["url"].endswith("GHSA-fccv-jmmp-qg76")
    ranges = {r["fixed"] for p in adv["data"]["packages"] if p["name"] == "org.apache.tomcat:tomcat-catalina" for r in p["ranges"]}
    assert {"9.0.83", "10.1.16", "8.5.96"} <= ranges
    assert osv.to_advisory("CVE-2023-46589", [own]) is None
    with pytest.raises(NewsError):
        osv.parse(b'{"id": "<script>"}')


@pytest.mark.parametrize(
    ("version", "status", "fixed"),
    [("9.0.80", "affected", "9.0.83"), ("9.0.83", "not_affected", None), ("10.1.15", "affected", "10.1.16"), ("8.5.96", "not_affected", None), (None, "unversioned", None)],
)
def test_osv_verdicts(version, status, fixed):
    adv = osv.to_advisory("CVE-2023-46589", [osv.parse(fx("osv_GHSA-fccv-jmmp-qg76.json"))])
    v = evaluate(catalog.product("tomcat"), "osv", adv["data"], version)
    assert (v.status, v.fixed) == (status, fixed)
    assert evaluate(catalog.product("nginx"), "osv", adv["data"], "1.27.1") is None  # not its package


def test_osv_decides_a_possibly_and_names_the_fix():
    tomcat = catalog.product("tomcat")
    adv = osv.to_advisory("CVE-2023-46589", [osv.parse(fx("osv_GHSA-fccv-jmmp-qg76.json"))])
    o = _adv(adv["id"], "osv", "CVE-2023-46589", adv["data"])
    # the NVD: the product without a version bound ("possibly")
    nvd = _adv("nvd:CVE-2023-46589", "nvd", "CVE-2023-46589", {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"}]}]}], "cna": []})
    t = {**tomcat, "cpes": ["a:apache:tomcat"]}
    assert vendor.group_verdict(t, vendor.groups_of([nvd])[0], "9.0.80").status == "possible"
    g = vendor.groups_of([nvd, o])[0]
    assert g["osv"] == [o]
    v = vendor.group_verdict(t, g, "9.0.80")
    assert (v.status, v.fixed) == ("affected", "9.0.83")
    assert vendor.group_verdict(t, g, "9.0.90").status == "not_affected"


async def test_osv_round_asks_by_id_only(net, structured_on, admin_client):
    await _follow(admin_client, "tomcat", "9.0.80")
    nvd = {"id": "nvd:CVE-2023-46589", "source": "nvd", "ident": "CVE-2023-46589", "title": "Tomcat", "summary": "", "url": "", "cves": ["CVE-2023-46589"], "cvss": 7.5, "severity": "high", "published_at": datetime(2023, 11, 28, tzinfo=UTC), "updated_at": None,
           "data": {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"}]}]}], "cna": [], "desc": "x"}}  # fmt: skip
    async with db.session() as s:
        await vendor.store(s, [nvd], await vendor.current_index(s))
    net.add(osv.API + "CVE-2023-46589", fx("osv_CVE-2023-46589.json"))
    net.add(osv.API + "GHSA-fccv-jmmp-qg76", fx("osv_GHSA-fccv-jmmp-qg76.json"))
    async with db.session() as s:
        assert await osv.refresh(s, force=True) == 1
        assert await s.get(VendorAdvisory, "osv:CVE-2023-46589") is not None
        assert "tomcat" in set(await s.scalars(select(VendorAdvisoryProduct.product).where(VendorAdvisoryProduct.advisory_id == "osv:CVE-2023-46589")))
    paths = [c.url.path for c in net.calls]
    assert all(c.method == "GET" and not c.url.query for c in net.calls)  # no product, no version: only the id in the path
    assert paths[:2] == ["/v1/vulns/CVE-2023-46589", "/v1/vulns/GHSA-fccv-jmmp-qg76"]  # the reviewed advisory first
    n = len(net.calls)
    async with db.session() as s:
        assert await osv.refresh(s, force=True) is None  # asked this week (an old CVE): not again
    assert len(net.calls) == n


# ---------------------------------------------------------------- settings, health


async def test_settings_switch_each_source(net, admin_client):
    d = (await admin_client.get("/api/admin/vendor")).json()
    assert {k: d["settings"][k] for k in ON} == {k: False for k in ON}  # tests: off (conftest); the app ships them on
    assert settings_store.DEFAULTS["vendor"]["csaf"] is False
    assert [p["key"] for p in d["structured"]["csaf_providers"]] == ["siemens", "cisco", "schneider", "openxchange"]
    r = await admin_client.put("/api/admin/vendor", json={"enabled": True, "every_h": 6, "eol_every_h": 24, "cvelist": True, "epss": True, "rev": d["settings"]["rev"]})
    assert r.status_code == 200 and r.json()["cvelist"] and r.json()["epss"] and not r.json()["csaf"]
    # a form without the switches keeps them
    r = await admin_client.put("/api/admin/vendor", json={"enabled": True, "every_h": 8, "eol_every_h": 24, "rev": r.json()["rev"]})
    assert r.json()["cvelist"] and r.json()["every_h"] == 8


def test_the_shipped_defaults_are_on():
    """The app ships every structured source on (each asks only for what followed products or stories need)."""
    src_ = Path(settings_store.__file__).read_text()
    assert '"csaf": True, "cvelist": True, "epss": True, "osv": True' in src_


async def test_health_shows_structured_sources_as_their_own_kind(net, structured_on, admin_client):
    await _follow(admin_client, "panos")
    _gh_routes(net, delta_zip(json.loads(fx("cve_CVE-2024-3400.json"))))
    await _delta()
    d = (await admin_client.get("/api/admin/source-health")).json()
    rows = {(r["kind"], r["key"]): r for r in d["items"]}
    assert rows[("structured", "cvelist")]["state"] in ("healthy", "never") and rows[("structured", "cvelist")]["name"].startswith("cvelistV5")
    assert ("vendor", "cvelist") not in rows
    det = (await admin_client.get("/api/admin/source-health/structured/cvelist")).json()
    assert det["fetches"][0]["key"] == cvelist.DELTA_KEY and det["fetches"][0]["ok"]
    assert {m["key"] for m in det["members"]} >= {cvelist.DELTA_KEY}
    # switched off: off, no request
    async with db.session() as s:
        await settings_store.put(s, "vendor", {**(await vendor.config(s)), "cvelist": False})
        await s.commit()
    d = (await admin_client.get("/api/admin/source-health")).json()
    assert next(r for r in d["items"] if r["key"] == "cvelist")["state"] == "off"
    async with db.session() as s:
        assert cvelist.DELTA_KEY not in await vendor.active_keys(s)


async def test_rolie_provider_found_through_the_bsi_aggregator(net, structured_on, admin_client):
    """Siemens: its provider-metadata.json is not at a well-known place – the BSI's aggregator names it; its ROLIE feed
    (TLP:WHITE) lists the documents with their hash files."""
    await _follow(admin_client, "siemens-sinec-nms")
    feed = json.loads(fx("rolie_siemens.json"))
    doc = (VFIX / "csaf_siemens.json").read_bytes()
    now = datetime.now(UTC)
    for n, e in enumerate(feed["feed"]["entry"]):
        e["updated"] = (now - timedelta(days=1 + n * 200)).strftime("%Y-%m-%dT%H:%M:%SZ")  # the last one: before the first fill
    first = feed["feed"]["entry"][0]
    first["link"] = [{"rel": "self", "href": "https://cert-portal.siemens.com/productcert/csaf/ssa-566512.json"}, {"rel": "hash", "href": "https://cert-portal.siemens.com/productcert/csaf/ssa-566512.json.sha512"}]
    net.add(csaf_providers.AGGREGATOR, fx("aggregator.json"))
    net.add("https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json", fx("pm_siemens.json"))
    net.add("https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json", feed)
    net.add("https://cert-portal.siemens.com/productcert/csaf/ssa-566512.json", doc)
    net.add("https://cert-portal.siemens.com/productcert/csaf/ssa-566512.json.sha512", hashlib.sha512(doc).hexdigest() + "  ssa-566512.json")
    await _csaf_round()
    asked = net.urls()
    assert "https://cert-portal.siemens.com/.well-known/csaf/provider-metadata.json" not in asked  # the aggregator named it
    assert not any(u.endswith(".sha256") for u in asked)  # the feed names its hash file
    async with db.session() as s:
        a = await s.get(VendorAdvisory, "csaf:SSA-566512")
        assert a is not None and a.data["publisher"] == "Siemens ProductCERT (CSAF)" and a.cves == ["CVE-2026-109618", "CVE-2026-109619"]
        st = await s.get(VendorFetch, "csaf:siemens")
        assert st.error is None and st.items == 1


async def test_epss_refusal_pauses_only_epss(net, structured_on, admin_client):
    await _follow(admin_client, "panos")
    async with db.session() as s:
        await vendor.store(s, [cvelist.parse_one(fx("cve_CVE-2024-3400.json"))], await vendor.current_index(s))
    net.add("https://api.first.org/data/v1/epss*", b"slow down", status=429, headers={"Retry-After": "120"})
    async with db.session() as s:
        assert await epss.refresh(s, force=True) == 0
        st = await s.get(VendorFetch, epss.KEY)
        assert st.failures == 1 and st.error.startswith("rate_limited") and st.next_fetch_at > datetime.now(UTC)
        assert await epss.refresh(s) is None  # paused: not asked again before then
    assert len(net.urls("api.first.org")) == 1


async def test_backfill_not_starved_by_cves_with_a_record_already(net, structured_on, admin_client):
    """The newest unanalysed CVEs that have a cvelist record already (the delta brought it) are left out before the
    LIMIT: an older one without a record is still asked (before: 80 such newer ones kept it out for ever)."""
    await _follow(admin_client, "panos", "10.2.7")

    def nvd(cid: str, at: datetime) -> dict:
        return {"id": f"nvd:{cid}", "source": "nvd", "ident": cid, "title": "x", "summary": "", "url": "", "cves": [cid], "cvss": None, "severity": "info", "published_at": at, "updated_at": None,
                "data": {"configs": [], "cna": [{"affectedData": [{"vendor": "Palo Alto Networks", "product": "PAN-OS", "versions": [{"version": "10.2.0", "lessThan": "10.3", "status": "affected"}]}]}], "desc": "x", "status": "Awaiting Analysis"}}  # fmt: skip

    newer = [f"CVE-2026-{20000 + i}" for i in range(cvelist.SINGLE_PER_ROUND * 4 + 5)]
    rows = [nvd(c, datetime(2026, 10, 1, tzinfo=UTC) + timedelta(minutes=i)) for i, c in enumerate(newer)]
    rows += [{**nvd(c, datetime(2026, 10, 1, tzinfo=UTC)), "id": f"cvelist:{c}", "source": "cvelist"} for c in newer]
    rows.append(nvd("CVE-2024-3400", datetime(2024, 4, 12, tzinfo=UTC)))
    async with db.session() as s:
        await vendor.store(s, rows, await vendor.current_index(s))
    net.add(cvelist.raw_url("CVE-2024-3400"), fx("cve_CVE-2024-3400.json"))
    async with db.session() as s:
        products = [p for f in await vendor.follows(s) if (p := vendor.product_of(f))]
        assert await cvelist.backfill(s, products, await vendor.current_index(s), True) == 1
    assert net.urls() == [cvelist.raw_url("CVE-2024-3400")]


async def test_osv_record_without_packages_any_more_drops_the_old_copy(net, structured_on, admin_client):
    """OSV answers the CVE again, without any package range now (not withdrawn): the stored advisory goes – before,
    only a withdrawn record removed it and the old ranges kept deciding the findings."""
    await test_osv_round_asks_by_id_only(net, structured_on, admin_client)
    bare = {**json.loads(fx("osv_CVE-2023-46589.json")), "affected": [], "aliases": []}
    net.add(osv.API + "CVE-2023-46589", bare)
    async with db.session() as s:
        row = await s.get(VendorFetch, osv.PER_CVE + "CVE-2023-46589")
        row.last_fetch_at = datetime.now(UTC) - timedelta(days=60)
        await s.commit()
        await osv.refresh(s, force=True)
        assert await s.get(VendorAdvisory, "osv:CVE-2023-46589", populate_existing=True) is None
