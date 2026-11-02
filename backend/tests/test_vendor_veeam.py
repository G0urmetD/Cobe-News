"""Veeam's security KB feed as a Vendor News source: the parser on a trimmed real copy of the feed (fixtures/vendor/
veeam_feed.xml – eight articles with different phrasings, one of them a running "List of Security Fixes" page), the
build scheme (full build or a short 12.3.1), the verdicts per product and release line – never a false "not affected" –,
the vendor deciding before NVD, the round (one feed request, only with a Veeam product followed, conditional) and the
details of a Veeam story in the news. Offline: a MockTransport, never www.veeam.com."""

import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app import db, news, story_details, vendor
from app import vendor_catalog as catalog
from app import vendor_sources as src
from app.models import NewsItem, NewsSource, StoryDetail, VendorAdvisory, VendorFetch
from app.vendor_match import evaluate, veeam_name
from app.vendor_versions import parse, validate

FIX = Path(__file__).parent / "fixtures" / "vendor"
FEED = (FIX / "veeam_feed.xml").read_bytes()
BR, ONE, AGENT_WIN, AGENT_LINUX, SPC, VB365 = "veeam-backup-and-replication", "veeam-one", "veeam-agent", "veeam-agent-linux", "veeam-spc", "veeam-backup-for-microsoft-365"


@pytest.fixture(scope="module")
def advs() -> dict[str, dict]:
    return {a["ident"]: a for a in src.parse_veeam(FEED)}


def verdict(key: str, adv: dict, version: str | None) -> tuple[str, str | None] | None:
    r = evaluate(catalog.product(key), "veeam", adv["data"], version)
    return None if r is None else (r.status, r.fixed)


# ---------------------------------------------------------------- the parser


def test_feed_articles_and_what_is_skipped(advs):
    # the running "List of Security Fixes and Improvements" page is no advisory (every fix of every build, no ranges)
    assert set(advs) == {"KB4948", "KB4957", "KB4953", "KB4934", "KB4902", "KB4893", "KB4879"}
    a = advs["KB4948"]
    assert a["id"] == "veeam:KB4948" and a["source"] == "veeam" and a["url"] == "https://www.veeam.com/kb4948"
    assert a["cves"] == ["CVE-2026-105477", "CVE-2026-108140", "CVE-2026-108141", "CVE-2026-108142"]  # every CVE of the article
    assert a["cvss"] == 9.1 and a["severity"] == "critical"
    assert a["published_at"] == datetime(2026, 10, 27, tzinfo=UTC)
    assert a["names"] == ["Veeam Backup & Replication", "Veeam Agent for Linux"]
    first = a["data"]["issues"][0]
    assert first["cves"] == ["CVE-2026-108142"] and first["vector"].startswith("AV:N/AC:L") and first["cvss_version"] == "4.0"
    assert first["affected"] == [
        {"product": "Veeam Backup & Replication", "upto": "13.1.1.18", "lines": ["13.1"], "earlier": True},
        {"product": "Veeam Backup & Replication", "upto": "13.0.2.29", "lines": ["13.0"], "earlier": True},
    ]
    assert first["fixed"] == [
        {"product": "Veeam Backup & Replication", "name": "13.1.2", "build": "13.1.2.57"},
        {"product": "Veeam Backup & Replication", "name": "13.0.3", "build": "13.0.3.63"},
    ]
    assert first["older"] == "not_affected"  # "Older versions (e.g., 12.x) are not affected."
    agent = a["data"]["issues"][3]
    assert agent["cves"] == ["CVE-2026-105477"] and agent["affected"][0]["product"] == "Veeam Agent for Linux"


def test_phrasings(advs):
    # "Article Applicability": "Affect only … 12.3.2 P3 (build 12.3.2.4854) and older builds", "Version 13 is not affected"
    kb = advs["KB4934"]["data"]["issues"]
    assert {r["upto"] for x in kb for r in x["affected"]} == {"12.3.2.4854"}
    assert all(x["not_lines"] == ["13"] for x in kb)
    assert kb[2]["affected"][0]["product"] == "Veeam Backup Enterprise Manager (Veeam Backup & Replication)"
    assert kb[0]["fixed"][0] == {"product": "Veeam Backup & Replication", "name": "12.3.2 P4", "build": "12.3.2.4934"}
    # "… and all earlier version 13 and 6 builds", "… all earlier versions of 12 builds", a mitigation section
    kb = {x["cves"][0]: x for x in advs["KB4902"]["data"]["issues"]}
    assert kb["CVE-2026-58068"]["affected"][0]["lines"] == ["13", "6"]
    assert kb["CVE-2026-58069"]["affected"][1] == {"product": "Veeam Backup & Replication", "upto": "12.3.2.4854", "lines": ["12"], "earlier": True}
    assert kb["CVE-2026-58069"]["older"] == "affected"  # "Unsupported product versions … should be considered vulnerable"
    assert advs["KB4902"]["data"]["mitigation"] is True
    # article-wide: "All vulnerabilities disclosed in this article affect …" and "These vulnerabilities were fixed starting with …"
    for x in advs["KB4893"]["data"]["issues"]:
        assert x["affected"] == [{"product": "Veeam Service Provider Console", "upto": "9.2.1.33875", "lines": ["9"], "earlier": True}]
        assert x["fixed"] == [{"product": "Veeam Service Provider Console", "name": "9.3.0.35057", "build": "9.3.0.35057"}]
    # "Veeam products … are not affected" (PHP2Shell); an article without builds (the appliance's updater component)
    assert advs["KB4953"]["data"]["none_affected"] is True and advs["KB4953"]["cves"] == ["CVE-2026-109618", "CVE-2026-109619"]
    assert advs["KB4879"]["data"]["issues"] == [] and advs["KB4879"]["names"] == ["Veeam Backup & Replication"] and advs["KB4879"]["cvss"] == 8.4


def test_story_text_parses_like_the_feed():
    """The news keep a cleaned copy of the article (content_html): the details read it with the same parser."""
    root = ET.fromstring(FEED)  # noqa: S314 - our own fixture
    for e in root.findall(f"{src.ATOM}entry"):
        title, link, content = e.findtext(f"{src.ATOM}title"), e.find(f"{src.ATOM}link").get("href"), e.findtext(f"{src.ATOM}content")
        a, b = src.parse_veeam_entry(title, link, content), src.parse_veeam_entry(title, link, news.clean_html(content))
        assert (a and a["data"]) == (b and b["data"])


def test_refuses_what_is_no_kb_feed():
    with pytest.raises(news.NewsError):
        src.parse_veeam(b"<rss><channel/></rss>")
    with pytest.raises(news.NewsError):
        src.parse_veeam(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><feed xmlns="http://www.w3.org/2005/Atom"/>')
    assert src.parse_veeam_entry("Vulnerabilities Resolved", "https://evil.example/kb4948", "<p>x</p>") is None  # only www.veeam.com/kbNNNN
    assert src.parse_veeam_entry("List of Security Fixes and Improvements in Veeam ONE", "https://www.veeam.com/kb4858", "<p>CVE-2026-1 fixed</p>") is None


# ---------------------------------------------------------------- the build scheme


@pytest.mark.parametrize(
    ("text", "key", "norm"),
    [
        ("12.3.2.4934", (12, 3, 2, 4934), "12.3.2.4934"),
        ("12.3.1", (12, 3, 1), "12.3.1"),
        ("13.1.2 (build 13.1.2.57)", (13, 1, 2, 57), "13.1.2.57"),
        ("11.0.1.1261 P20240304", (11, 0, 1, 1261, 20240304), "11.0.1.1261 P20240304"),
        ("12.3.2 P4", None, None),  # a patch number is no build – the KB says which build it is
        ("13", None, None),
        ("12.3.2.4934 P4", None, None),
    ],
)
def test_veeam_versions(text, key, norm):
    v = parse("veeam", text)
    assert (v.key if v else None) == key
    ok, normalized, reason = validate("veeam", text)
    assert ok is (key is not None) and (normalized == norm if ok else reason == "format")


# ---------------------------------------------------------------- verdicts


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("13.1.1.18", ("affected", "13.1.2.57")),  # the last affected build of its line
        ("13.1.0.411", ("affected", "13.1.2.57")),
        ("13.1.2.57", ("not_affected", None)),  # at the fix
        ("13.0.2.29", ("affected", "13.0.3.63")),  # the other line: its own fix
        ("13.0.3.63", ("not_affected", None)),
        ("12.3.2.4934", ("not_affected", None)),  # "Older versions (e.g., 12.x) are not affected"
        ("13.1.2", ("not_affected", None)),  # the fixed release without its build: every 13.1.2 build is above 13.1.1.18
        ("13.0.1", ("affected", "13.0.3.63")),  # every 13.0.1 build is below 13.0.2.29
        ("13.1", ("possible", "13.1.2.57")),  # 13.1.0 … 13.1.x – the build decides
        ("13.0.2", ("possible", "13.0.3.63")),
        ("12.3.2 P4", ("possible", None)),  # not comparable – never "not affected"
    ],
)
def test_br_kb4948(advs, version, expected):
    assert verdict(BR, advs["KB4948"], version) == expected


def test_reasons_short_build_and_lines(advs):
    p = catalog.product(BR)
    assert evaluate(p, "veeam", advs["KB4948"]["data"], "13.1").reason == "build_needed"
    assert evaluate(p, "veeam", advs["KB4948"]["data"], "12.3.2.4934").reason == "line_none"
    assert evaluate(p, "veeam", advs["KB4948"]["data"], "13.1.2.57").reason == "fixed"
    assert evaluate(p, "veeam", advs["KB4948"]["data"], "12.3.2 P4").reason == "unparsed_version"
    assert evaluate(p, "veeam", advs["KB4948"]["data"], None).status == "unversioned"


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("12.3.2.4854", ("affected", "12.3.2.4934")),
        ("12.3.1.1139", ("affected", "12.3.2.4934")),
        ("12.3.1", ("affected", "12.3.2.4934")),  # every 12.3.1 build lies below 12.3.2.4854
        ("12.3.2", ("possible", "12.3.2.4934")),  # 12.3.2.4465 is, 12.3.2.4934 is not
        ("12.3.2.4934", ("not_affected", None)),
        ("13.0.1.2067", ("not_affected", None)),  # "Version 13 is not affected"
        ("11.0.1.1261", ("possible", "12.3.2.4934")),  # older than the line it names, no word on older ones
    ],
)
def test_br_kb4934(advs, version, expected):
    assert verdict(BR, advs["KB4934"], version) == expected


def test_agents_and_other_products(advs):
    # B&R article with a Linux agent CVE: the Linux agent gets it, the Windows agent does not, B&R only its own CVEs
    assert verdict(AGENT_LINUX, advs["KB4948"], "13.1.1.4") == ("affected", "13.1.2.11")
    assert verdict(AGENT_LINUX, advs["KB4948"], "13.0.3.213") == ("not_affected", None)  # "Older versions (e.g., 13.0.x and 6.x) are not affected"
    assert verdict(AGENT_WIN, advs["KB4948"], "13.1.0.544") is None
    # "13.0.4.1341 and all earlier version 13 and 6 builds"; older ones "should be considered vulnerable"
    assert verdict(AGENT_WIN, advs["KB4902"], "6.3.2.1302") == ("affected", "13.1.0.544")
    assert verdict(AGENT_WIN, advs["KB4902"], "13.1.0.544") == ("not_affected", None)
    r = evaluate(catalog.product(AGENT_WIN), "veeam", advs["KB4902"]["data"], "5.0.3.5029")
    assert (r.status, r.reason) == ("affected", "older_untested")
    # B&R in KB4902: 13 up to 13.0.2.29 (fixed 13.0.3.63 / 13.1.0.411), 12 up to 12.3.2.4854
    assert verdict(BR, advs["KB4902"], "13.0.2.29") == ("affected", "13.0.3.63")
    assert verdict(BR, advs["KB4902"], "13.1.0.411") == ("not_affected", None)
    assert verdict(BR, advs["KB4902"], "12.3.2.4854") == ("affected", "12.3.2.4934")
    # Microsoft 365: two fixes in one article – the build that fixes every CVE
    assert verdict(VB365, advs["KB4957"], "8.5.0.1014") == ("affected", "8.6.0.5011")
    assert verdict(VB365, advs["KB4957"], "8.6.0.1102") == ("affected", "8.6.0.5011")
    assert verdict(VB365, advs["KB4957"], "8.6.0.5011") == ("not_affected", None)
    # Service Provider Console: the statements for the whole article
    assert verdict(SPC, advs["KB4893"], "9.2.1.33875") == ("affected", "9.3.0.35057")
    assert verdict(SPC, advs["KB4893"], "9.3.0.35057") == ("not_affected", None)
    assert verdict(ONE, advs["KB4893"], "13.1.0.7940") is None  # another product


def test_unclear_is_possible_never_not_affected(advs):
    # an article without builds (updater component of the appliance): with a version "possibly", without "the product"
    assert verdict(BR, advs["KB4879"], "13.0.1.2067") == ("possible", None)
    assert verdict(BR, advs["KB4879"], None) == ("unversioned", None)
    # an affected statement whose build cannot be read
    data = {"issues": [{"cves": ["CVE-2026-1"], "affected": [{"product": "Veeam ONE", "upto": "13.1 Patch 2", "lines": ["13.1"], "earlier": True}], "fixed": [], "older": "", "not_lines": []}], "products": ["Veeam ONE"]}
    r = evaluate(catalog.product(ONE), "veeam", data, "13.1.0.7940")
    assert (r.status, r.reason) == ("possible", "unparsed_data")
    # a line the article does not name, between named ones
    data = {"issues": [{"cves": ["CVE-2026-2"], "affected": [{"product": "Veeam ONE", "upto": "13.0.2.6723", "lines": ["13"], "earlier": True}, {"product": "Veeam ONE", "upto": "11.0.1.1880", "lines": ["11"], "earlier": True}], "fixed": [], "older": "", "not_lines": []}], "products": ["Veeam ONE"]}
    r = evaluate(catalog.product(ONE), "veeam", data, "12.3.0.7165")
    assert (r.status, r.reason) == ("possible", "line_not_listed")
    # only the fix is named: at or above it fixed, below it unclear
    data = {"issues": [{"cves": ["CVE-2026-3"], "affected": [], "fixed": [{"product": "Veeam ONE", "name": "12.3.0.7165", "build": "12.3.0.7165"}], "older": "", "not_lines": []}], "products": ["Veeam ONE"]}
    assert evaluate(catalog.product(ONE), "veeam", data, "12.3.0.7165").status == "not_affected"
    r = evaluate(catalog.product(ONE), "veeam", data, "12.3.0.4670")
    assert (r.status, r.reason, r.fixed) == ("possible", "fix_only", "12.3.0.7165")
    # "Veeam products … are not affected"
    assert verdict(BR, advs["KB4953"], "13.1.2.57") == ("not_affected", None)


def test_names():
    assert veeam_name("Veeam Backup Enterprise Manager (Veeam Backup & Replication)", ["Veeam Backup & Replication"])
    assert veeam_name("Veeam Backup and Replication", ["Veeam Backup & Replication"])
    assert not veeam_name("Veeam Backup for Microsoft 365", ["Veeam Backup & Replication"])
    assert not veeam_name("Veeam Agent for Linux", ["Veeam Agent for Microsoft Windows", "Veeam Agent for Windows"])


def test_release_line_of_a_short_build(monkeypatch):
    rel = [{"name": "12", "label": "12", "releaseDate": "2023-01-30", "latest": "12.3.2.4934", "eolFrom": "2027-02-28", "isMaintained": True}]
    monkeypatch.setattr(catalog, "releases", lambda key: rel)
    p = catalog.product(BR)
    assert vendor.release_info(p, "12.3.2.4465")["update_available"] is True
    short = vendor.release_info(p, "12.3.2")  # may be 12.3.2.4934 already: neither "update" nor "current"
    assert short["update_available"] is False and short["update_unknown"] is True and short["line"]["name"] == "12"
    assert vendor.release_info(p, "12.3.1")["update_available"] is True  # every 12.3.1 build is older than 12.3.2.4934


# ---------------------------------------------------------------- Vendor News end to end


class Sites:
    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.etag = 'W/"veeam1"'
        self.nvd: dict = {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "format": "NVD_CVE", "version": "2.0", "vulnerabilities": []}

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        if req.url.host == "www.veeam.com" and req.url.path == "/services/open/kb/security-feed":
            if req.headers.get("if-none-match") == self.etag:
                return httpx.Response(304)
            return httpx.Response(200, content=FEED, headers={"ETag": self.etag, "Content-Type": "application/xml;charset=utf-8"})
        if req.url.host == "services.nvd.nist.gov":
            return httpx.Response(200, json=self.nvd)
        if req.url.host == "www.cisa.gov":
            return httpx.Response(200, json={"vulnerabilities": []})
        if req.url.host == "endoflife.date":
            return httpx.Response(304)
        raise AssertionError(f"unexpected request {req.url}")

    def to(self, host: str) -> list[httpx.Request]:
        return [c for c in self.calls if c.url.host == host]


@pytest.fixture
def sites(monkeypatch, tmp_path):
    s = Sites()
    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(s.handler))
    monkeypatch.setattr(catalog, "_data_file", lambda: tmp_path / "vendor_catalog.json")
    catalog._cache.stamp = ()
    vendor._last.clear()
    vendor.bump()
    return s


async def _follow(c, key: str, *versions: str) -> None:
    assert (await c.put(f"/api/vendor/follows/{key}", json={"enabled": True})).status_code == 200
    for v in versions:
        r = await c.post(f"/api/vendor/follows/{key}/versions", json={"version": v})
        assert r.status_code == 200, r.text


async def _round(force: bool = True) -> None:
    await vendor.run_round(force=force)
    async with db.session() as s:
        await vendor.evaluate_events(s)


async def test_feed_only_with_a_veeam_product(admin_client, sites):
    await _follow(admin_client, "panos")
    vendor.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=[]) if req.url.host == "security.paloaltonetworks.com" else sites.handler(req))
    await _round()
    assert sites.to("www.veeam.com") == []


async def test_round_and_findings(admin_client, reader_client, sites):
    await _follow(admin_client, BR, "13.1.1.18", "12.3.2", "13.1.2 (build 13.1.2.57)")
    await _round()
    feed = sites.to("www.veeam.com")
    assert len(feed) == 1 and feed[0].url.scheme == "https"
    assert feed[0].headers["user-agent"] == news.USER_AGENT  # the app's own agent – no browser disguise
    d = (await reader_client.get(f"/api/vendor/products/{BR}?all=true")).json()
    assert [v["version"] for v in d["versions"]] == ["13.1.1.18", "12.3.2", "13.1.2.57"]  # the build counts
    by = {f["id"]: f for f in d["findings"]}
    assert {"veeam:KB4948", "veeam:KB4934", "veeam:KB4902", "veeam:KB4879"} <= set(by) and "veeam:KB4893" not in by
    kb = by["veeam:KB4948"]
    assert kb["source"] == "veeam" and kb["url"] == "https://www.veeam.com/kb4948" and kb["cvss"] == 9.1
    assert {v["version"]: (v["status"], v["fixed"]) for v in kb["versions"]} == {
        "13.1.1.18": ("affected", "13.1.2.57"),
        "12.3.2": ("not_affected", None),
        "13.1.2.57": ("not_affected", None),
    }
    assert {v["version"]: (v["status"], v["reason"]) for v in by["veeam:KB4934"]["versions"]}["12.3.2"] == ("possible", "build_needed")
    assert d["product"]["version_where"] == "veeam_br" and d["product"]["advisory"] == "veeam"
    async with db.session() as s:
        st = await s.get(VendorFetch, "veeam:feed")
        assert st.last_ok_at is not None and st.etag == 'W/"veeam1"' and st.items == 7
    # the next round asks conditionally – unchanged: 304
    sites.calls.clear()
    await _round()
    feed = sites.to("www.veeam.com")
    assert len(feed) == 1 and feed[0].headers.get("if-none-match") == 'W/"veeam1"'
    # not forced: the feed is not due before the interval
    sites.calls.clear()
    await _round(force=False)
    assert sites.to("www.veeam.com") == []
    # followed later: the Linux agent gets its CVE from the stored B&R article at once – no new request
    await _follow(admin_client, AGENT_LINUX, "13.1.1.4")
    d = (await reader_client.get(f"/api/vendor/products/{AGENT_LINUX}")).json()
    kb = next(f for f in d["findings"] if f["id"] == "veeam:KB4948")
    assert kb["versions"][0]["status"] == "affected" and kb["versions"][0]["fixed"] == "13.1.2.11"
    assert sites.to("www.veeam.com") == []


async def test_vendor_decides_before_nvd_for_all_cves(admin_client, reader_client, sites):
    """NVD calls every B&R build up to 13.0.3 affected by both CVEs of KB4934 – Veeam says version 13 is not; the
    record of the second CVE is grouped under the article too, not judged alone."""
    rec = []
    for cve in ("CVE-2025-64393", "CVE-2026-93026"):
        rec.append(
            {
                "cve": {
                    "id": cve,
                    "vulnStatus": "Analyzed",
                    "published": "2026-10-06T12:00:00.000",
                    "lastModified": "2026-10-07T12:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Veeam Backup & Replication issue."}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.9, "baseSeverity": "CRITICAL"}}]},
                    "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:veeam:veeam_backup_\\&_replication:*:*:*:*:*:*:*:*", "versionEndExcluding": "13.0.3.63"}]}]}],
                }
            }
        )
    sites.nvd = {"resultsPerPage": 2, "startIndex": 0, "totalResults": 2, "format": "NVD_CVE", "version": "2.0", "vulnerabilities": rec}
    await _follow(admin_client, BR, "13.0.1.2067", "12.3.2.4854")
    await _round()
    d = (await reader_client.get(f"/api/vendor/products/{BR}?all=true")).json()
    by = {f["id"]: f for f in d["findings"]}
    assert "nvd:CVE-2025-64393" not in by and "nvd:CVE-2026-93026" not in by
    kb = by["veeam:KB4934"]
    assert {"CVE-2025-64393", "CVE-2026-93026"} <= set(kb["cves"]) and {a["ident"] for a in kb["also"]} == {"CVE-2025-64393", "CVE-2026-93026"}
    assert {v["version"]: v["status"] for v in kb["versions"]} == {"13.0.1.2067": "not_affected", "12.3.2.4854": "affected"}


# ---------------------------------------------------------------- the news: Veeam KB stories


async def test_story_details_from_the_kb_text(admin_client, reader_client, sites):
    from tests.conftest import set_news

    await set_news(enabled=True)
    root = ET.fromstring(FEED)  # noqa: S314 - our own fixture
    entries = {e.findtext(f"{src.ATOM}id"): e for e in root.findall(f"{src.ATOM}entry")}
    now = datetime.now(UTC)
    ids: dict[str, uuid.UUID] = {}
    async with db.session() as s:
        source = await s.scalar(select(NewsSource).where(NewsSource.key == "veeam"))
        for n, kb in enumerate(("kb4948", "kb4856")):
            e = entries[f"https://www.veeam.com/{kb}"]
            st = news.story({"link": f"https://www.veeam.com/{kb}", "title": e.findtext(f"{src.ATOM}title"), "summary": "", "content": e.findtext(f"{src.ATOM}content"), "date": now - timedelta(hours=n)}, now)
            st.pop("undated")
            i = NewsItem(source_id=source.id, fetched_at=now, seq=await news.next_seq(s), **st)
            s.add(i)
            await s.flush()
            ids[kb] = i.id
        await s.commit()
    assert story_details.plan("veeam", "https://www.veeam.com/kb4948", []) == ("veeam", "KB4948", None)
    async with db.session() as s:
        await story_details.enrich_round(s)
    assert sites.calls == []  # read from the story itself
    async with db.session() as s:
        dets = {d.item_id: d for d in await s.scalars(select(StoryDetail))}
    assert dets[ids["kb4948"]].kind == "veeam" and dets[ids["kb4948"]].status == "ok" and dets[ids["kb4948"]].next_try_at is not None
    assert dets[ids["kb4856"]].status == "none"  # the running list of fixes: no details
    d = (await reader_client.get(f"/api/news/{ids['kb4948']}")).json()["details"]
    assert d["publisher"] == "Veeam Security (KB)" and d["id"] == "KB4948" and d["cvss"][0]["score"] == 9.1 and d["remote"] is True
    assert d["revision"]["current"] == "2026-10-27"  # the KB dates by day only – shown as a day, not as midnight UTC
    prods = {p["name"]: p for p in d["products"]}
    assert [r["text"] for r in prods["Veeam Backup & Replication"]["affected"]] == ["≤ 13.1.1.18 (13.1.x)", "≤ 13.0.2.29 (13.0.x)"]
    assert prods["Veeam Backup & Replication"]["fixed"] == ["13.1.2.57", "13.0.3.63"]
    assert prods["Veeam Agent for Linux"]["fixed"] == ["13.1.2.11"]
    card = next(x for x in (await reader_client.get("/api/news?state=new")).json()["items"] if x["id"] == str(ids["kb4948"]))
    assert card["hint"]["product"].startswith("Veeam Backup & Replication ≤ 13.1.1.18")
    # following B&R: "betrifft deine Systeme" from the same data
    await _follow(admin_client, BR, "13.1.1.18", "13.1.2.57")
    got = (await reader_client.get(f"/api/news/{ids['kb4948']}")).json()["affects"]
    assert got[0]["product"] == BR
    assert {r["version"]: (r["status"], r["fixed"]) for r in got[0]["versions"]} == {"13.1.1.18": ("affected", "13.1.2.57"), "13.1.2.57": ("not_affected", None)}
    async with db.session() as s:
        assert await s.get(VendorAdvisory, "veeam:KB4948") is None  # the story's text is not a second copy of the feed
