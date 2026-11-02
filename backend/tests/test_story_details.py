"""Details aus der Quelle: the structured advisory behind a story (BSI WID / Siemens / Cisco / Fortinet CSAF, Palo Alto
CVE 5, KEV/EUVD, NVD fallback) – parsed from trimmed real documents, fetched offline against a MockTransport, linked
to the followed products of Vendor News (and its notifications)."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app import db, news, story_details, vendor
from app import vendor_catalog as catalog
from app.models import NewsItem, NewsSource, StoryDetail, VendorAdvisory, VendorAdvisoryProduct, VendorEvent, VendorFetch
from app.vendor_match import evaluate

FIX = Path(__file__).parent / "fixtures" / "vendor"
WID_URL = "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4115"


def csaf(name: str, kind: str) -> dict:
    return story_details.parse_csaf((FIX / name).read_bytes(), kind)


# ---------------------------------------------------------------- where the details are


@pytest.mark.parametrize(
    ("source", "url", "cves", "expected"),
    [
        ("cert-bund", WID_URL, [], ("bsi", "WID-SEC-W-2026-4115", "https://wid.cert-bund.de/.well-known/csaf/white/2026/wid-sec-w-2026-4115.json")),
        ("siemens-productcert", "https://cert-portal.siemens.com/productcert/html/ssa-566512.html", [], ("siemens", "SSA-566512", "https://cert-portal.siemens.com/productcert/csaf/ssa-566512.json")),
        (
            "cisco-psirt",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk?vs_f=Cisco",
            [],
            ("cisco", "cisco-sa-sdwan-rpa-EHchtZk", "https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk/csaf/cisco-sa-sdwan-rpa-EHchtZk.json"),
        ),
        ("paloalto-psirt", "https://security.paloaltonetworks.com/CVE-2026-0322", [], ("paloalto", "CVE-2026-0322", "https://security.paloaltonetworks.com/json/CVE-2026-0322")),
        ("fortinet-psirt", "https://fortiguard.fortinet.com/psirt/FG-IR-26-161", [], ("fortinet", "FG-IR-26-161", None)),
        ("cisa-kev", "https://nvd.nist.gov/vuln/detail/CVE-2025-59718", ["CVE-2025-59718"], ("kev", "CVE-2025-59718", None)),
        ("heise", "https://www.heise.de/news/x.html", ["CVE-2024-21754"], ("nvd", "CVE-2024-21754", None)),
        ("heise", "https://www.heise.de/news/y.html", [], ("none", "", None)),
        # a link that only looks like a vendor's: never sent elsewhere
        ("heise", "https://evil.example/cert-portal.siemens.com/productcert/html/ssa-566512.html", [], ("none", "", None)),
    ],
)
def test_plan(source, url, cves, expected):
    assert story_details.plan(source, url, cves) == expected


# ---------------------------------------------------------------- parsing


def test_bsi_wid_csaf():
    d = csaf("csaf_wid.json", "bsi")
    assert d["id"] == "WID-SEC-W-2026-4115" and d["severity_text"] == "hoch" and d["publisher"] == "BSI (CSAF)"
    gl = d["products"][0]
    assert (gl["vendor"], gl["name"], gl["cpe"]) == ("Open Source", "GitLab", "a:gitlab:gitlab")
    assert [r["text"] for r in gl["affected"]][:2] == ["<19.5.1", "<19.4.3"] and gl["fixed"][:2] == ["19.5.1", "19.4.3"]
    assert d["products"][1]["name"] == "Red Hat Enterprise Linux"  # added by the update
    assert d["revision"] == {"current": "2026-10-27T23:00:00.000+00:00", "initial": "2026-10-21T22:00:00.000+00:00", "version": "2", "summary": "Neue Updates von Red Hat aufgenommen", "count": 2}
    assert "CVE-2026-103515" in d["cves"] and d["cvss"] == []  # no CVSS in the BSI's CSAF – it comes from NVD


def test_siemens_cisco_fortinet_csaf():
    s = csaf("csaf_siemens.json", "siemens")
    assert s["cvss"][0]["score"] == 9.8 and s["remote"] is True and s["products"][0]["affected"] == [{"all": True, "text": "alle Versionen"}]
    c = csaf("csaf_cisco.json", "cisco")
    assert c["cvss"][0]["score"] == 10.0 and c["cves"] == ["CVE-2026-20127"] and c["revision"]["count"] == 5
    assert c["products"][0]["name"].startswith("Cisco Catalyst SD-WAN") and c["products"][0]["affected"][0].get("exact")
    f = csaf("fortinet_csaf_wad.json", "fortinet")
    assert f["products"][0]["affected"][0]["from"] == "7.6.1" and f["mitigation"] is True
    assert "7.4 all versions" in f["products"][0]["not_affected"]


def test_palo_alto_cve5():
    d = story_details.parse_cve5((FIX / "cve5_pan.json").read_bytes())
    assert d["id"] == "CVE-2026-0322" and d["cvss"][0]["score"] == 8.6 and d["cvss"][0]["version"] == "4.0"
    pan = next(p for p in d["products"] if p["name"] == "PAN-OS")
    assert pan["affected"][0]["text"] == "12.2.0 – < 12.2.4" and "12.1.10-h2" in pan["fixed"]
    assert not any(p["name"] == "Cloud NGFW" for p in d["products"])  # "unaffected / All": not listed
    # the matching uses the CNA rows with their hotfix changes
    p = catalog.product("panos")
    assert evaluate(p, "nvd", d["match"][0]["data"], "12.1.4-h12").status == "not_affected"
    assert evaluate(p, "nvd", d["match"][0]["data"], "12.1.4-h11").status == "affected"


def test_refuses_what_is_not_csaf():
    from app.news import NewsError

    for body in (b"not json", b"[]", b'{"document": {}}'):
        with pytest.raises(NewsError):
            story_details.parse_csaf(body, "bsi")


# ---------------------------------------------------------------- ranges against versions


@pytest.mark.parametrize(
    ("version", "status", "fixed"),
    [
        ("19.5.0", "affected", "19.5.1"),
        ("19.5.1", "not_affected", None),
        ("19.4.2", "affected", "19.4.3"),
        ("19.4.5", "not_affected", None),  # its own line's fix – not "< 19.5.1"
        ("18.11.12", "affected", "18.11.13"),
        ("18.10.3", "possible", None),  # an older line the advisory does not name
        ("19.6.0", "not_affected", None),
    ],
)
def test_bsi_ranges_per_line(version, status, fixed):
    r = evaluate(catalog.product("gitlab"), "csaf", csaf("csaf_wid.json", "bsi"), version)
    assert (r.status, r.fixed) == (status, fixed)


def test_fortinet_ranges_and_lines():
    f = csaf("fortinet_csaf_wad.json", "fortinet")
    p = catalog.product("fortios")
    assert evaluate(p, "csaf", f, "7.6.3").status == "affected"
    assert evaluate(p, "csaf", f, "7.4.2").status == "not_affected"  # "7.4 all versions" not affected
    assert evaluate(p, "csaf", f, "7.0.1").status == "possible"  # 7.0 not named
    assert evaluate(p, "csaf", f, "8.2.0").status == "not_affected"


def test_cisco_explicit_versions():
    c = csaf("csaf_cisco.json", "cisco")
    entry = c["products"][0]
    listed = entry["affected"][0]["exact"]
    prod = {"key": "x", "label": entry["name"], "scheme": "cisco", "cpes": [], "cna": []}
    assert evaluate(prod, "csaf", c, listed).status == "affected"
    assert evaluate(prod, "csaf", c, "99.1.1").status == "not_affected"
    assert evaluate(prod, "csaf", c, None).status == "unversioned"


# ---------------------------------------------------------------- the round, offline


class Sites:
    def __init__(self):
        self.calls: list[httpx.Request] = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        u = str(req.url)
        if u.endswith("wid-sec-w-2026-4115.json"):
            return httpx.Response(200, content=(FIX / "csaf_wid.json").read_bytes())
        if u.endswith("ssa-566512.json"):
            return httpx.Response(200, content=(FIX / "csaf_siemens.json").read_bytes())
        if "contentjson/CiscoSecurityAdvisory" in u:
            return httpx.Response(200, content=(FIX / "csaf_cisco.json").read_bytes())
        if u.endswith("/json/CVE-2026-0322"):
            return httpx.Response(200, content=(FIX / "cve5_pan.json").read_bytes())
        if req.url.host == "services.nvd.nist.gov":
            cve = req.url.params.get("cveId")
            doc = json.loads((FIX / "nvd_fortios.json").read_text())
            doc["vulnerabilities"] = [v for v in doc["vulnerabilities"] if v["cve"]["id"] == cve]
            doc["totalResults"] = len(doc["vulnerabilities"])
            return httpx.Response(200, json=doc)
        raise AssertionError(f"unexpected request {u}")


@pytest.fixture
def sites(monkeypatch, tmp_path):
    s = Sites()
    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(s.handler))
    monkeypatch.setattr(catalog, "_data_file", lambda: tmp_path / "vendor_catalog.json")
    vendor._last.clear()
    vendor.bump()
    return s


async def _stories(*rows) -> dict[str, uuid.UUID]:
    out = {}
    now = datetime.now(UTC)
    async with db.session() as s:
        srcs = {x.key: x for x in await s.scalars(select(NewsSource))}
        for n, (key, url, title, cves) in enumerate(rows):
            src = srcs[key]
            src.enabled = True
            i = NewsItem(source_id=src.id, url=url, url_key=news._key(news.normalize_url(url)), title=title, title_key=news.title_key(title), summary="", published_at=now - timedelta(hours=n), fetched_at=now, cves=cves, seq=await news.next_seq(s))
            s.add(i)
            await s.flush()
            out[key] = i.id
        await s.commit()
    return out


async def _round() -> int:
    async with db.session() as s:
        return await story_details.enrich_round(s)


async def test_nothing_while_news_are_off(sites):
    await _stories(("cert-bund", WID_URL, "[NEU] [hoch] GitLab: Mehrere Schwachstellen", []))
    assert await _round() == 0 and sites.calls == []


async def test_round_and_story_api(sites, reader_client, admin_client):
    from tests.conftest import set_news

    await set_news(enabled=True)
    ids = await _stories(
        ("cert-bund", WID_URL, "[NEU] [hoch] GitLab: Mehrere Schwachstellen", ["CVE-2026-103515"]),
        ("siemens-productcert", "https://cert-portal.siemens.com/productcert/html/ssa-566512.html", "SSA-566512", []),
        ("paloalto-psirt", "https://security.paloaltonetworks.com/CVE-2026-0322", "CVE-2026-0322 PAN-OS: RCE", ["CVE-2026-0322"]),
        ("heise", "https://www.heise.de/news/fortios.html", "FortiOS-Lücke", ["CVE-2024-21754"]),
        ("talos", "https://blog.talosintelligence.com/x/", "Ohne CVE", []),
    )
    assert await _round() >= 4
    async with db.session() as s:
        dets = {d.item_id: d for d in await s.scalars(select(StoryDetail))}
    assert dets[ids["cert-bund"]].status == "ok" and dets[ids["cert-bund"]].kind == "bsi"
    assert dets[ids["talos"]].status == "none" and not any("talos" in str(c.url) for c in sites.calls)
    assert dets[ids["heise"]].data["via_nvd"] and dets[ids["heise"]].data["cvss"][0]["score"] > 0
    # one fetch per advisory: a second round asks nothing again
    n = len(sites.calls)
    await _round()
    assert len(sites.calls) == n
    d = (await reader_client.get(f"/api/news/{ids['cert-bund']}")).json()
    assert d["details"]["products"][0]["name"] == "GitLab" and "match" not in d["details"] and d["affects"] == []
    lst = (await reader_client.get("/api/news?state=new")).json()["items"]
    card = next(x for x in lst if x["id"] == str(ids["cert-bund"]))
    assert card["hint"]["product"].startswith("GitLab <19.5.1")
    # the BSI advisory became a Vendor News advisory of GitLab
    async with db.session() as s:
        assert await s.get(VendorAdvisory, "csaf:WID-SEC-W-2026-4115") is not None
        assert "gitlab" in set(await s.scalars(select(VendorAdvisoryProduct.product).where(VendorAdvisoryProduct.advisory_id == "csaf:WID-SEC-W-2026-4115")))
    # follow GitLab: the story says "betrifft deine Systeme", with which version entries
    await admin_client.put("/api/vendor/follows/gitlab", json={"enabled": True})
    for v in ("19.5.0", "19.4.5"):
        assert (await admin_client.post("/api/vendor/follows/gitlab/versions", json={"version": v, "label": f"Instanz {v}"})).status_code == 200
    d = (await reader_client.get(f"/api/news/{ids['cert-bund']}")).json()
    rows = {r["version"]: (r["status"], r["fixed"]) for r in d["affects"][0]["versions"]}
    assert d["affects"][0]["product"] == "gitlab" and rows == {"19.5.0": ("affected", "19.5.1"), "19.4.5": ("not_affected", None)}
    card = next(x for x in (await reader_client.get("/api/news?state=new")).json()["items"] if x["id"] == str(ids["cert-bund"]))
    assert card["hint"]["affects"] is True
    # … and Vendor News shows it as a finding of GitLab
    f = (await reader_client.get("/api/vendor/products/gitlab")).json()["findings"]
    bsi = next(x for x in f if x["id"] == "csaf:WID-SEC-W-2026-4115")
    assert {v["version"]: v["status"] for v in bsi["versions"]} == {"19.5.0": "affected", "19.4.5": "not_affected"}


async def test_update_title_asks_again(sites):
    from tests.conftest import set_news

    await set_news(enabled=True)
    ids = await _stories(("cert-bund", WID_URL, "[NEU] [hoch] GitLab: Mehrere Schwachstellen", []))
    await _round()
    n = len(sites.calls)
    async with db.session() as s:
        src = (await s.scalars(select(NewsSource).where(NewsSource.key == "cert-bund"))).one()
        entry = {"link": WID_URL, "title": "[UPDATE] [hoch] GitLab: Mehrere Schwachstellen", "summary": "x", "date": datetime.now(UTC)}
        await news.store(s, src, [entry])
        d = await s.get(StoryDetail, ids["cert-bund"])
        assert d.next_try_at <= datetime.now(UTC)  # due again right away
        assert (await s.get(NewsItem, ids["cert-bund"])).title.startswith("[UPDATE]")
    await _round()
    assert len(sites.calls) == n + 1


async def test_details_notify_followed_products(sites, admin_client):
    """A BSI advisory that affects a followed GitLab version is a Vendor News event (once)."""
    from tests.conftest import set_news

    await set_news(enabled=True)
    await admin_client.put("/api/vendor/follows/gitlab", json={"enabled": True})
    await admin_client.post("/api/vendor/follows/gitlab/versions", json={"version": "19.5.0"})
    async with db.session() as s:
        for key in ("nvd:a:gitlab:gitlab",):
            s.add(VendorFetch(key=key, last_ok_at=datetime.now(UTC), failures=0, items=0))
        await s.commit()
        await vendor.evaluate_events(s)  # baseline: nothing yet
    await _stories(("cert-bund", WID_URL, "[NEU] [hoch] GitLab: Mehrere Schwachstellen", []))
    await _round()
    async with db.session() as s:
        evs = list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "vuln")))
        assert evs == [] or all(e.baseline for e in evs)
        created = await vendor.evaluate_events(s)
        ev = (await s.scalars(select(VendorEvent).where(VendorEvent.key.like("%csaf:WID-SEC-W-2026-4115")))).one()
    assert created == 1 and not ev.baseline and ev.data["fixed"] == "19.5.1"


async def test_nvd_budget_per_round(sites, monkeypatch):
    from tests.conftest import set_news

    await set_news(enabled=True)
    monkeypatch.setattr(story_details, "NVD_PER_ROUND", (1, 1))
    await _stories(("heise", "https://www.heise.de/a.html", "a", ["CVE-2024-21754"]), ("golem-security", "https://www.golem.de/b.html", "b", ["CVE-2024-23111"]))
    await _round()
    assert len([c for c in sites.calls if c.url.host == "services.nvd.nist.gov"]) == 1


async def test_missing_document_is_not_asked_again(sites, monkeypatch):
    from tests.conftest import set_news

    await set_news(enabled=True)
    real = sites.handler
    monkeypatch.setattr(sites, "handler", lambda req: httpx.Response(404) if "wid.cert-bund.de" in str(req.url) else real(req))
    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(lambda req: sites.handler(req)))
    ids = await _stories(("cert-bund", "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-9999", "[NEU] [mittel] Example", []))
    await _round()
    async with db.session() as s:
        d = await s.get(StoryDetail, ids["cert-bund"])
    assert (d.status, d.next_try_at) == ("none", None)
