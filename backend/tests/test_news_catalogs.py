"""News: the JSON catalogs of exploited vulnerabilities (CISA KEV, ENISA EUVD), one story per
CVE across the vulnerability sources, feeds that carry their whole history oldest first, vendor ratings, the built-in
list – and that the KEV backlog of a first fetch reaches neither the notification rules nor desktop notifications."""

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import set_news
from sqlalchemy import delete, select, update

from app import db, news, notify
from app.models import NewsItem, NewsSource

FIX = Path(__file__).parent / "fixtures" / "news"
KEV = (FIX / "kev.json").read_bytes()
EUVD = (FIX / "euvd.json").read_bytes()
MSRC = (FIX / "msrc.json").read_bytes()
OLDEST_FIRST = (FIX / "oldest_first.atom").read_bytes()
NOW = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)
FIXTURE_DAY = date(2026, 10, 28)


def _fresh(data: bytes, *days: str) -> bytes:
    """The fixture as if it had been fetched today: the given dates move by the days since the fixture was made –
    the retention (keep_days) counts from the real now."""
    shift = date.today() - FIXTURE_DAY
    for d in days:
        data = data.replace(d.encode(), (date.fromisoformat(d) + shift).isoformat().encode())
    return data


def test_kev_is_read_newest_first():
    entries, meta = news.parse_feed(KEV)
    assert meta == {"icon": ""}
    # sorted by dateAdded (the fixture is out of order), the entry without a CVE is skipped
    assert [e["cves"] for e in entries] == [["CVE-2026-48356"], ["CVE-2026-109618"], ["CVE-2026-59310"], ["CVE-2021-44228"]]
    s = news.story(entries[0], NOW)
    assert s["title"] == "CVE-2026-48356 · Adobe Commerce and Magento: Unrestricted Upload of File with Dangerous Type Vulnerability"
    assert s["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-48356" and s["published_at"] == datetime(2026, 10, 27, tzinfo=UTC)
    assert s["severity"] == "high" and s["reasons"] == [{"kind": "kev", "value": "2026-11-10"}] and s["cves"] == ["CVE-2026-48356"]
    assert "Required action: Apply mitigations" in s["summary"] and "<li><strong>Due date (US federal agencies):</strong> 2026-11-10</li>" in s["content_html"]
    assert "cve-2026-48356" in s["search"]  # found by its CVE
    # known ransomware use: critical, with the reason
    vc = news.story(entries[2], NOW)
    assert vc["severity"] == "critical" and {"kind": "ransomware", "value": "CISA"} in vc["reasons"]
    # stable and unique per entry: the same catalog read twice gives the same keys
    assert [news.story(e, NOW)["url_key"] for e in news.parse_feed(KEV)[0]] == [news.story(e, NOW)["url_key"] for e in entries]


def test_only_the_newest_catalog_entries(monkeypatch):
    monkeypatch.setattr(news, "MAX_ENTRIES", 2)
    assert [e["cves"][0] for e in news.parse_feed(KEV)[0]] == ["CVE-2026-48356", "CVE-2026-109618"]


def test_euvd_is_read():
    entries, _ = news.parse_feed(EUVD)
    stories = [news.story(e, NOW) for e in entries]
    adobe, php, nocve = stories
    assert adobe["url"] == "https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-44420" and adobe["cves"] == ["CVE-2026-48356"]
    assert adobe["title"].startswith("CVE-2026-48356 · Adobe: Adobe Commerce is affected")
    # exploited and CVSS ≥ 9: critical; exploited alone: high
    assert adobe["severity"] == "critical" and adobe["reasons"] == [{"kind": "euvd", "value": "2026-10-27"}, {"kind": "cvss", "value": "9.3"}]
    assert php["severity"] == "high" and php["title"].startswith("CVE-2026-109618 · PHP Group PHP:")
    assert php["published_at"] == datetime(2026, 10, 26, tzinfo=UTC)  # "12:00:00 AM" – Java's narrow space before AM
    assert "https://www.php.net/ChangeLog-8.php" in php["content_html"] and "javascript" not in php["content_html"]
    # no CVE: the EUVD id heads the title, no "exploited since": the publication date
    assert nocve["title"].startswith("EUVD-2026-90001: ") and nocve["cves"] == [] and nocve["severity"] == "high"
    assert nocve["published_at"] == datetime(2026, 10, 20, 15, 5, tzinfo=UTC)
    # the search API's shape {"items": [...]} as well
    assert len(news.parse_feed(json.dumps({"items": json.loads(EUVD), "total": 3}).encode())[0]) == 3


def test_msrc_release_index():
    """Microsoft's CVRF index: one story per Patchday release, newest first; odd ids are not put into a link."""
    entries, _ = news.parse_feed(MSRC)
    stories = [news.story(e, NOW) for e in entries]
    assert [s["url"] for s in stories] == [
        "https://msrc.microsoft.com/update-guide/releaseNote/2026-Nov",
        "https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct",
        "https://msrc.microsoft.com/update-guide/releaseNote/2026-Sep",
        "https://msrc.microsoft.com/update-guide/releaseNote/2017-May-B",
    ]
    oct_ = stories[1]
    assert oct_["title"] == "Microsoft: October 2026 Security Updates" and oct_["published_at"] == datetime(2026, 10, 13, 7, tzinfo=UTC)
    assert oct_["severity"] == "high" and oct_["reasons"] == [{"kind": "vendor", "value": "Microsoft Patchday"}] and oct_["cves"] == []
    assert "<li><strong>Last updated:</strong> 2026-10-29T01:43:28Z</li>" in oct_["content_html"]
    assert stories[0]["title"] == "Microsoft: November & more" and "<script" not in "".join(s["title"] + s["content_html"] for s in stories)
    assert news.MSRC_ID.fullmatch("2018-FEB") and not news.MSRC_ID.fullmatch("2026-October")
    # a list of something else under "value" is no catalog
    with pytest.raises(news.NewsError, match="format"):
        news.parse_feed(b'{"value": [{"a": 1}]}')


def test_hostile_or_unknown_json():
    for bad in (b"[" * 100_000, b'{"vulnerabilities": "x"}', b'{"a": 1}', b"[1, 2, 3]", b'{"x": ', b'\xef\xbb\xbf{"a": [}'):
        with pytest.raises(news.NewsError, match="format"):
            news.parse_feed(bad)
    assert news.parse_feed(b"[]") == ([], {"icon": ""})  # an empty catalog is a catalog
    # values of the wrong type count as empty – no crash, no "None" in a title
    odd = {"vulnerabilities": [{"cveID": "CVE-2026-0001", "vendorProject": 7, "product": None, "vulnerabilityName": ["x"], "dateAdded": 20261027}]}
    (e,) = news.parse_feed(json.dumps(odd).encode())[0]
    assert e["title"] == "CVE-2026-0001: " and e["date"] is None
    # XML still goes through the DTD refusal (no entity expansion)
    with pytest.raises(news.NewsError, match="format"):
        news.parse_feed(b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "x">]><rss><channel/></rss>')


def test_feeds_are_cut_after_sorting(monkeypatch):
    """A feed with its whole history oldest first (Siemens: 2474 advisories since 2018): the newest are taken."""
    monkeypatch.setattr(news, "MAX_ENTRIES", 2)
    entries, _ = news.parse_feed(OLDEST_FIRST)
    assert [e["title"][:10] for e in entries] == ["SSA-137528", "SSA-566435"]
    rss = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>
<item><title>old</title><link>https://news.example.org/1</link><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate></item>
<item><title>undated</title><link>https://news.example.org/2</link></item>
<item><title>new</title><link>https://news.example.org/3</link><pubDate>Tue, 27 Oct 2026 00:00:00 GMT</pubDate></item>
</channel></rss>"""
    assert [e["title"] for e in news.parse_feed(rss)[0]] == ["new", "old"]


def test_vendor_ratings_and_denials():
    def sev(title: str, text: str = "") -> str:
        return news.rate(title, text)[0]

    # Palo Alto rates in the title, Cisco in the text – the publisher's rating stands over keyword guesses
    assert sev("CVE-2026-0317 PAN-OS: Denial of Service Vulnerability (Severity: LOW)") == "low"
    assert news.rate("PAN-OS: Authenticated RCE (Severity: MEDIUM)", "")[1] == [{"kind": "vendor", "value": "medium"}]
    assert sev("Snort 3 Hardening Release", "Security Impact Rating:  Critical\nCVE-2026-20043") == "critical"
    assert sev("Emergency Distrust of Root CAs", "Security Impact Rating: Informational") == "info"
    # "not known to be actively exploited" is no exploitation – a real one still raises the vendor's rating
    denied = "Security Impact Rating: High. These vulnerabilities were found during internal testing and are not known to be actively exploited."
    assert sev("Cisco Expressway Hardening Release", denied) == "high"
    assert sev("PAN-OS: Command Injection (Severity: HIGH)", "This issue is actively exploited.") == "critical"
    assert sev("October Security Update", "At the time of disclosure, Ivanti is not aware of exploitation in the wild.") == "medium"
    assert sev("October Security Update", "We have no evidence of these vulnerabilities being exploited in the wild.") == "medium"
    assert sev("Connect Secure", "At the time of disclosure, Ivanti is aware of limited exploitation in the wild.") == "critical"
    assert sev("No patch yet", "There is no fix for the zero-day.") == "critical"  # "no" alone denies nothing
    assert sev("Lücke", "Es gibt keine Hinweise auf eine aktive Ausnutzung.") == "medium"
    # the Zero Day Initiative is a program, not a zero-day
    assert sev("ZDI-26-811: MailEnable Information Disclosure", "Reported via Trend Micro's Zero Day Initiative.") == "info"
    # small additions: German "kritische Schwachstelle(n)", plural "critical vulnerabilities", authentication bypass
    assert sev("PHP - Kritische Schwachstellen bedrohen Webanwendungen weltweit") == "high"
    assert sev("Impact of Critical Vulnerabilities in PHP") == "high"
    assert sev("SSA-137528 V1.0: Authentication Bypass Vulnerability in Mendix SAML module") == "high"
    assert sev("F5 BIG-IP APM - Aktive Ausnutzung einer Schwachstelle") == "critical"
    # the BSI's own rating stands as well: "[mittel]" with "Remote Code Execution" in the text stays medium
    assert sev("[NEU] [mittel] Produkt: Schwachstelle", "ermöglicht Remote Code Execution") == "medium"


async def _src(key: str) -> NewsSource:
    async with db.session() as s:
        return await s.scalar(select(NewsSource).where(NewsSource.key == key))


async def test_one_story_per_cve_across_vulnerability_sources():
    """BSI warning, KEV entry and EUVD entry about the same CVE: one story, "also in" the others, the highest rating."""
    async with db.session() as s:
        await news.ensure_sources(s)
        s.add(NewsSource(key="feed-a", name="feed-a", url="https://news.example.org/a.xml", site="", builtin=False, enabled=True, failures=0))
        await s.commit()
    bsi, kev, euvd, press = [await _src(k) for k in ("bsi-csw", "cisa-kev", "enisa-euvd", "feed-a")]
    # a German warning on one CVE (rated "high" by its words), and a news article naming another CVE
    warn = {
        "link": "https://www.bsi.example.org/csw/2026-1",
        "title": "Version 1.0: Adobe Commerce - Kritische Schwachstelle CVE-2026-48356",
        "summary": "Angreifer laden Dateien hoch.",
        "content": "",
        "date": datetime(2026, 10, 27, 12, tzinfo=UTC),
    }
    article = {**warn, "link": "https://news.example.org/vcenter", "title": "vCenter: CVE-2026-59310 used by ransomware gangs", "summary": "Patch now."}
    async with db.session() as s:
        assert await news.store(s, bsi, [warn]) == 1
        assert await news.store(s, press, [article]) == 1
        # KEV: the Adobe CVE is the BSI's story; vCenter is new – a news article is not a vulnerability source
        assert await news.store(s, kev, news.parse_feed(KEV)[0]) == 3
        assert await news.store(s, kev, news.parse_feed(KEV)[0]) == 0  # read again: nothing twice
        # EUVD: Adobe once more (critical: CVSS 9.3), PHP is the KEV's story, the one without a CVE is new
        assert await news.store(s, euvd, news.parse_feed(EUVD)[0]) == 1
    async with db.session() as s:
        items = list(await s.scalars(select(NewsItem)))
        assert len(items) == 6

        def by(start: str) -> NewsItem:
            return next(i for i in items if i.title.startswith(start))

        adobe = by("Version 1.0: Adobe")
        assert adobe.source_id == bsi.id and adobe.also_in == ["CISA KEV", "ENISA EUVD"]
        assert adobe.severity == "critical" and adobe.reasons[0] == {"kind": "euvd", "value": "2026-10-27"}
        php = by("CVE-2026-109618 · PHP")
        assert php.source_id == kev.id and php.also_in == ["ENISA EUVD"] and php.severity == "high"
        assert by("vCenter:").also_in == [] and by("CVE-2026-59310 · Broadcom").severity == "critical"


async def test_a_warning_on_many_cves_is_not_one_kev_entry():
    """Only when one side is about that single CVE: a BSI warning on two CVEs does not swallow a KEV entry of one."""
    async with db.session() as s:
        await news.ensure_sources(s)
    bsi, kev = await _src("bsi-csw"), await _src("cisa-kev")
    warn = {"link": "https://www.bsi.example.org/csw/2", "title": "Sammelwarnung CVE-2026-48356 und CVE-2026-0002", "summary": "x", "content": "", "date": datetime(2026, 10, 27, tzinfo=UTC)}
    async with db.session() as s:
        assert await news.store(s, bsi, [warn]) == 1
        # the KEV entry on one of them: its single CVE matches the warning
        assert await news.store(s, kev, news.parse_feed(KEV)[0][:1]) == 0
        # outside the 30 days: a story of its own
        far = dict(news.parse_feed(KEV)[0][0], date=datetime(2026, 7, 1, tzinfo=UTC), link="https://www.example.org/kev/CVE-2026-48356")
        assert await news.store(s, kev, [far]) == 1


async def test_catalog_and_octet_stream_feed_through_the_worker():
    """JSON detected by its body, conditional requests as for feeds; an Atom feed sent as binary/octet-stream."""
    await set_news(enabled=True, every_min=30, keep_days=90)
    async with db.session() as s:
        await news.ensure_sources(s)
        await s.execute(update(NewsSource).values(enabled=False))
        for key, url in (("own-kev", "https://news.example.org/kev.json"), ("own-cert", "https://feeds.example.net/advisories.atom")):
            s.add(NewsSource(key=key, name=key, url=url, site="https://news.example.org", builtin=False, enabled=True, failures=0))
        await s.commit()
    kev = _fresh(KEV, "2026-10-27", "2026-10-26", "2026-08-18")
    atom = _fresh(OLDEST_FIRST, "2026-10-23", "2026-10-26")
    calls: list = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        if req.url.path.endswith(".ico") or req.url.path == "/":
            return httpx.Response(404)
        if req.headers.get("if-none-match") == '"k1"':
            return httpx.Response(304)
        if req.url.path == "/kev.json":
            return httpx.Response(200, content=kev, headers={"content-type": "application/json", "etag": '"k1"'})
        return httpx.Response(200, content=atom, headers={"content-type": "binary/octet-stream"})

    news._host_last.clear()
    # KEV: three within the 90 days (Log4j from 2021 is older); the advisories: the two of this month
    assert await news.refresh_due(transport=httpx.MockTransport(handler)) == {"own-kev": 3, "own-cert": 2}
    kev_req = next(c for c in calls if c.url.path == "/kev.json")
    assert "application/json" in kev_req.headers["accept"]
    async with db.session() as s:
        await s.execute(update(NewsSource).values(next_fetch_at=None))
        await s.commit()
    calls.clear()
    news._host_last.clear()
    assert (await news.refresh_due(transport=httpx.MockTransport(handler)))["own-kev"] == 0
    assert next(c for c in calls if c.url.path == "/kev.json").headers["if-none-match"] == '"k1"'


async def test_builtin_sources_on_existing_installations():
    """A key new to an installation comes with its default; what an admin switched stays as it is."""
    async with db.session() as s:
        await news.ensure_sources(s)
        await s.execute(update(NewsSource).where(NewsSource.key == "bsi-csw").values(enabled=False))  # an admin's choice
        await s.execute(update(NewsSource).where(NewsSource.key == "fortinet-psirt").values(enabled=True))
        await s.execute(update(NewsSource).where(NewsSource.key == "heise").values(enabled=False))
        await s.execute(delete(NewsSource).where(NewsSource.key.in_(["cisa-kev", "enisa-euvd", "talos"])))  # as before this version
        await s.commit()
        await news.ensure_sources(s)
        on = dict((await s.execute(select(NewsSource.key, NewsSource.enabled))).all())
    assert on["bsi-csw"] is False and on["fortinet-psirt"] is True and on["heise"] is False
    assert on["cisa-kev"] is True and on["talos"] is True and on["enisa-euvd"] is False
    # 44 since 0.1.49 (cisa, rockwell retired)
    assert len(news.BUILTIN) == 44 and len({b.key for b in news.BUILTIN}) == 44 and all(b.url.startswith("https://") for b in news.BUILTIN)
    assert {b.category for b in news.BUILTIN} == {"authority", "vendor", "research", "press", "catalog"} and {b.lang for b in news.BUILTIN} == {"de", "en", "fr"}
    assert {b.key for b in news.BUILTIN if b.on} >= {"bsi-csw", "cert-eu", "microsoft-ti", "talos", "cisa-kev"}


async def test_admin_list_has_group_and_language(admin_client):
    r = await admin_client.post("/api/admin/news/sources", json={"name": "Mein Feed", "url": "https://news.example.org/feed"})
    assert r.status_code == 200, r.text
    assert r.json()["category"] == "custom" and r.json()["lang"] is None
    keys = {s["key"]: s for s in (await admin_client.get("/api/admin/news")).json()["sources"]}
    assert (keys["cisa-kev"]["category"], keys["cisa-kev"]["lang"], keys["cisa-kev"]["enabled"]) == ("catalog", "en", True)
    assert (keys["bsi-csw"]["category"], keys["bsi-csw"]["lang"]) == ("authority", "de") and keys["siemens-productcert"]["category"] == "vendor"
    assert not keys["enisa-euvd"]["enabled"] and not keys["zdi"]["enabled"]


# ---------------------------------------------------------------- the KEV backlog and notifications


def _big_kev(days: int) -> bytes:
    """A catalog like the real one on its first fetch: one entry per day back from today (the first one added today)."""
    today = date.today()
    vulns = [
        {
            "cveID": f"CVE-2026-{10000 + n}",
            "vendorProject": "Example",
            "product": f"Gateway {n}",
            "vulnerabilityName": "Remote Code Execution Vulnerability",
            "dateAdded": (today - timedelta(days=n)).isoformat(),
            "shortDescription": "An example vulnerability.",
            "requiredAction": "Apply mitigations.",
            "dueDate": (today + timedelta(days=21)).isoformat(),
            "knownRansomwareCampaignUse": "Known" if n % 10 == 3 else "Unknown",
        }
        for n in range(days)
    ]
    return json.dumps({"title": "CISA Catalog of Known Exploited Vulnerabilities", "vulnerabilities": vulns}).encode()


async def test_kev_backlog_reaches_no_notification(admin_client, reader_client, monkeypatch):
    """The first KEV fetch brings ~90 high/critical stories of the last 90 days at once: the rules send only the ones
    added today and yesterday (a date without a time counts to the end of its day; the backlog is older than a day when
    it arrives), the desktop endpoint offers only those too."""
    sent: list[httpx.Request] = []
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(lambda req: (sent.append(req), httpx.Response(200))[1]))
    await set_news(enabled=True, every_min=30, keep_days=90)
    async with db.session() as s:
        await news.ensure_sources(s)
        await s.execute(update(NewsSource).where(NewsSource.key != "cisa-kev").values(enabled=False))
        await s.commit()
    ch = (await admin_client.post("/api/admin/notify/channels", json={"name": "Slack", "type": "slack", "url": "https://hooks.slack.com/services/T0/B0/X"})).json()
    r = await admin_client.post("/api/admin/notify/rules", json={"name": "Kritisch+Hoch", "channels": [ch["id"]], "severities": ["critical", "high"]})
    assert r.status_code == 200
    since = (await reader_client.get("/api/news/recent")).json()["now"]
    await reader_client.put("/api/me/desktop", json={"enabled": True, "severities": ["critical", "high"], "sources": []})

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("known_exploited_vulnerabilities.json"):
            return httpx.Response(200, content=_big_kev(100), headers={"content-type": "application/json"})
        return httpx.Response(404)

    news._host_last.clear()
    got = await news.refresh_due(transport=httpx.MockTransport(handler))
    assert got["cisa-kev"] == 90  # 100 entries, the ones older than the 90 days of retention not taken (day 90 at midnight is)
    async with db.session() as s:
        out = await notify.dispatch(s)
    assert out == {"Slack": 2} and len(sent) == 2  # only the entries added today and yesterday – no summary of the backlog
    assert {"CVE-2026-10000", "CVE-2026-10001"} == {c for r in sent for c in ("CVE-2026-10000", "CVE-2026-10001") if c in r.content.decode()}
    recent = (await reader_client.get("/api/news/recent", params={"since": since, "mine": "true"})).json()
    assert recent["total"] == 2 and recent["items"][0]["title"].startswith("CVE-2026-1000")
    # the next fetch with one new entry: that one goes out
    async with db.session() as s:
        await s.execute(update(NewsSource).values(next_fetch_at=None, etag=None, last_modified=None))
        await s.commit()
    newer = json.loads(_big_kev(100))
    newer["vulnerabilities"].insert(0, {**newer["vulnerabilities"][0], "cveID": "CVE-2026-20000"})

    def handler2(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("known_exploited_vulnerabilities.json"):
            return httpx.Response(200, content=json.dumps(newer).encode(), headers={"content-type": "application/json"})
        return httpx.Response(404)

    news._host_last.clear()
    assert (await news.refresh_due(transport=httpx.MockTransport(handler2)))["cisa-kev"] == 1
    async with db.session() as s:
        assert await notify.dispatch(s) == {"Slack": 1}
    assert "CVE-2026-20000" in sent[-1].content.decode() and len(sent) == 3
