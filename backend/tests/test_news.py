"""Security news: feeds read (RSS, Atom, RDF), each story once, severity by
rules, polite fetching, read per person, the settings and sources. No real feed is fetched: all HTTP is mocked."""

from datetime import UTC, datetime, timedelta
from unittest.mock import ANY

import httpx
import pytest
from conftest import add_user, make_client, set_news, sign_in
from sqlalchemy import delete, select, update

from app import db, netaddr, news
from app.models import NewsItem, NewsRead, NewsSource

NOW = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)

ATOM = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>heise Security</title>
<entry><title>Angreifer nehmen L\xc3\xbccken in Magento ins Visier</title>
<link href="https://www.heise.de/news/Magento-Lecks-11502623.html?wt_mc=rss.red.security.beitrag.atom"/>
<id>https://heise.de/-11502623</id><published>2026-10-28T08:00:00+01:00</published>
<summary>In freier Wildbahn wurden Angriffe auf kritische Sicherheitsl\xc3\xbccken beobachtet (CVE-2026-1234).</summary>
<content type="html">&lt;p&gt;Text &lt;img src="https://heise.cloudimg.io/x.jpg"&gt; &lt;a href="https://example.org/a" onclick="x()"&gt;Link&lt;/a&gt;&lt;/p&gt;</content>
</entry></feed>"""

def fresh(feed: bytes) -> bytes:
    """The feed's dates moved to the last hours – stories older than a day when they arrive are backlog (no notification)."""
    import email.utils
    import re

    n = iter(range(1, 100))
    return re.sub(rb"<pubDate>[^<]+</pubDate>", lambda _: b"<pubDate>" + email.utils.format_datetime(datetime.now(UTC) - timedelta(hours=next(n)), usegmt=True).encode() + b"</pubDate>", feed)


RSS = b"""<?xml version="1.0"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><title>Example</title>
<image><url>https://example.org/logo.png</url></image>
<item><title>New ransomware gang hits hospitals</title><link>https://news.example.org/ransomware/?utm_source=rss</link>
<pubDate>Tue, 28 Oct 2026 07:00:00 GMT</pubDate><description>&lt;b&gt;Data&lt;/b&gt; stolen.</description></item>
<item><title>Patch for CVE-2026-9999 (CVSS 9.8)</title><link>https://news.example.org/patch</link>
<pubDate>Tue, 28 Oct 2026 06:00:00 GMT</pubDate><description>Update now.</description></item>
<item><title>A quiet day</title><link>https://news.example.org/quiet</link><pubDate>Tue, 28 Oct 2026 05:00:00 GMT</pubDate></item>
</channel></rss>"""

RDF = b"""<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel><title>RDF</title></channel>
<item><title>[NEU] [hoch] Linux Kernel: Schwachstelle</title><link>https://wid.example.org/1</link><dc:date>2026-10-28T06:00:00Z</dc:date></item>
</rdf:RDF>"""


# ---------------------------------------------------------------- parsing, keys, severity


def test_feeds_are_read():
    e, meta = news.parse_feed(ATOM)
    assert e[0]["title"].startswith("Angreifer") and e[0]["link"].startswith("https://www.heise.de/news/") and e[0]["date"].hour == 7
    e, meta = news.parse_feed(RSS)
    assert len(e) == 3 and meta["icon"] == "https://example.org/logo.png" and e[0]["date"] == datetime(2026, 10, 28, 7, tzinfo=UTC)
    e, _ = news.parse_feed(RDF)
    assert e[0]["link"] == "https://wid.example.org/1"
    # no DTD, no entities – nothing that could expand or reach out
    with pytest.raises(news.NewsError, match="format"):
        news.parse_feed(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><rss/>')
    with pytest.raises(news.NewsError, match="format"):
        news.parse_feed(b'<?xml version="1.0"?><!ENTITY x SYSTEM "file:///etc/passwd"><rss/>')
    with pytest.raises(news.NewsError, match="format"):
        news.parse_feed(b"<html><body>no feed</body></html>")
    with pytest.raises(news.NewsError, match="format"):
        news.parse_feed(b"not xml at all")


def test_story_keys_text_and_severity():
    s = news.story(news.parse_feed(ATOM)[0][0], NOW)
    assert s["severity"] == "critical" and {"kind": "exploited", "value": "In freier Wildbahn"} in s["reasons"] and s["cves"] == ["CVE-2026-1234"]
    assert "<img" not in s["content_html"] and "onclick" not in s["content_html"] and 'rel="noopener noreferrer nofollow"' in s["content_html"]
    # the same article with and without tracking, http or https, with or without www: one key
    a = news.normalize_url("https://www.heise.de/news/X-1.html?wt_mc=rss.red&utm_source=x#top")
    assert a == news.normalize_url("http://heise.de/news/X-1.html") == "heise.de/news/X-1.html"
    assert news.normalize_url("javascript:alert(1)") is None and news.normalize_url("ftp://example.org/x") is None
    rss = [news.story(e, NOW) for e in news.parse_feed(RSS)[0]]
    assert [x["severity"] for x in rss] == ["high", "critical", "info"]
    assert rss[1]["reasons"][0] == {"kind": "cvss", "value": "9.8"}
    assert news.story(news.parse_feed(RDF)[0][0], NOW)["severity"] == "high"  # the BSI's own rating in the title
    assert news.title_key("Patchday: Microsoft schließt Lücken!") == news.title_key("patchday microsoft schliesst lucken")


def test_severity_rules():
    assert news.rate("Zero-Day in Example VPN", "")[0] == "critical"
    assert news.rate("Neue Sicherheitslücke in Beispiel-CMS", "")[0] == "medium"
    assert news.rate("Ein Tag ohne Vorfälle", "")[0] == "info"
    assert news.rate("Konferenz zu Cyber-Themen", "")[0] == "low"
    assert news.rate("Update", "CVSS score 7.5")[0] == "high"
    # only in the long article text: one level lower, marked as such
    level, reasons = news.rate("Festnahme in Europa", "Die Polizei hat Verdächtige festgenommen.", "… nutzten einen Zero-Day …")
    assert level == "high" and reasons[0]["in_text"] is True
    # a feed's future date does not keep the story on top
    s = news.story({"link": "https://news.example.org/x", "title": "X", "date": NOW + timedelta(days=3)}, NOW)
    assert s["published_at"] == NOW
    assert news.story({"link": "", "title": "no link"}, NOW) is None and news.story({"link": "https://a.example.org/", "title": " "}, NOW) is None


def test_logo_formats():
    assert news.logo_type(b"\x89PNG\r\n\x1a\n...") == "image/png" and news.logo_type(b"\x00\x00\x01\x00..") == "image/x-icon"
    assert news.logo_type(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"
    assert news.logo_type(b"<svg onload='x()'>") is None  # an SVG can carry script


def test_targets():
    # https only, no credentials, no internal targets – and here (no login) no private networks either
    assert netaddr.valid_url("https://news.example.org/feed", https_only=True)
    assert not netaddr.valid_url("http://news.example.org/feed", https_only=True)
    assert not netaddr.valid_url("https://user:pw@news.example.org/feed", https_only=True)
    for bad in ("https://127.0.0.1/x", "https://169.254.169.254/latest", "https://10.1.2.3/x", "https://192.168.1.1/x", "https://[::1]/x", "https://0.0.0.0/x"):
        assert netaddr.forbidden_literal(bad), bad
    assert not netaddr.forbidden_literal("https://93.184.215.14/x")


# ---------------------------------------------------------------- fetching


def _site(feeds: dict[str, bytes], calls: list, status: dict | None = None):
    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        st = (status or {}).get(req.url.path)
        if st:
            return httpx.Response(st[0], headers=st[1])
        if req.url.path.endswith(".ico"):
            return httpx.Response(200, content=b"\x00\x00\x01\x00icon")
        body = feeds.get(req.url.path)
        if body is None:
            return httpx.Response(404)
        if req.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, content=body, headers={"etag": '"v1"'})

    return httpx.MockTransport(handler)


async def _sources(*pairs):
    async with db.session() as s:
        await news.ensure_sources(s)
        await s.execute(update(NewsSource).values(enabled=False))
        out = []
        for key, url in pairs:
            src = NewsSource(key=key, name=key, url=url, site="https://news.example.org", builtin=False, enabled=True, failures=0)
            s.add(src)
            out.append(src)
        await s.commit()
        return [x.id for x in out]


async def test_fetch_once_politely_and_without_duplicates():
    await set_news(enabled=True)
    a, b = await _sources(("feed-a", "https://news.example.org/a.xml"), ("feed-b", "https://feeds.example.net/b.xml"))
    calls: list = []
    # the same story in both feeds (other host, tracking parameter) – and the same title under another URL
    dup = RSS.replace(b"https://news.example.org/ransomware/?utm_source=rss", b"https://news.example.org/ransomware").replace(
        b"https://news.example.org/quiet", b"https://mirror.example.net/quiet-copy"
    )
    transport = _site({"/a.xml": RSS, "/b.xml": dup}, calls)
    got = await news.refresh_due(transport=transport)
    assert got == {"feed-a": 3, "feed-b": 0}
    async with db.session() as s:
        items = list(await s.scalars(select(NewsItem)))
        assert len(items) == 3 and all(i.source_id == a for i in items) and all(i.also_in == ["feed-b"] for i in items)
        assert (await s.get(NewsSource, a)).logo == b"\x00\x00\x01\x00icon"
    # not due yet: nobody is asked; due again: a conditional request, 304, nothing new
    news._host_last.clear()
    calls.clear()
    assert await news.refresh_due(transport=transport) == {}
    async with db.session() as s:
        await s.execute(update(NewsSource).where(NewsSource.id.in_([a, b])).values(next_fetch_at=None))
        await s.commit()
    news._host_last.clear()
    assert await news.refresh_due(transport=transport) == {"feed-a": 0, "feed-b": 0}
    assert all(c.headers.get("if-none-match") == '"v1"' for c in calls) and calls[0].headers["user-agent"].startswith("Cobe/")
    # one host at most once a minute: a second due feed on the same host waits for the next round
    c_id = (await _sources(("feed-c", "https://news.example.org/c.xml")))[0]
    async with db.session() as s:
        await s.execute(update(NewsSource).where(NewsSource.id.in_([a, c_id])).values(enabled=True, next_fetch_at=None))
        await s.commit()
    news._host_last.clear()
    got = await news.refresh_due(transport=_site({"/a.xml": RSS, "/c.xml": RSS}, []))
    assert len(got) == 1


async def test_refusal_pauses_the_source():
    await set_news(enabled=True)
    (a,) = await _sources(("feed-a", "https://news.example.org/a.xml"))
    assert await news.refresh_due(transport=_site({}, [], {"/a.xml": (429, {"retry-after": "7200"})})) == {"feed-a": -1}
    async with db.session() as s:
        src = await s.get(NewsSource, a)
        assert src.error.startswith("rate_limited") and src.failures == 1 and src.next_fetch_at - datetime.now(UTC) > timedelta(hours=1, minutes=55)
    # "fetch now" leaves a source alone that was asked to wait
    news._host_last.clear()
    assert await news.refresh_due(force=True, transport=_site({"/a.xml": RSS}, [])) == {}
    # other failures: a growing pause (30 min × 2^n), the error kept for the settings
    (b,) = await _sources(("feed-b", "https://feeds.example.net/b.xml"))
    assert await news.refresh_due(transport=_site({"/b.xml": b"<html>no feed</html>"}, [])) == {"feed-b": -1}
    async with db.session() as s:
        src = await s.get(NewsSource, b)
        assert src.error.startswith("format") and src.next_fetch_at - datetime.now(UTC) > timedelta(minutes=59)
    # switched off as a whole: nothing is fetched at all
    await set_news(enabled=False)
    news._host_last.clear()
    assert await news.refresh_due(force=True, transport=_site({"/a.xml": RSS}, [])) == {}


async def test_source_removed_while_fetching():
    """A source deleted in the settings during a round: that one is skipped, the round goes on."""
    await set_news(enabled=True)
    a, b = await _sources(("feed-a", "https://news.example.org/a.xml"), ("feed-b", "https://feeds.example.net/b.xml"))

    async def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/a.xml":
            async with db.engine().begin() as conn:  # another connection, as the API would
                await conn.execute(delete(NewsSource).where(NewsSource.id == a))
            return httpx.Response(500)
        return httpx.Response(200, content=RSS.replace(b"news.example.org", b"feeds.example.net"))

    assert await news.refresh_due(transport=httpx.MockTransport(handler)) == {"feed-b": 3}


async def test_fetch_now_asks_each_source_once():
    """"Fetch now" asks each source once, not again every round."""
    await set_news(enabled=True)
    await _sources(("feed-a", "https://news.example.org/a.xml"))
    transport = _site({"/a.xml": RSS}, [])
    assert await news.refresh_due(transport=transport) == {"feed-a": 3}
    since = datetime.now(UTC)
    news._host_last.clear()
    assert await news.refresh_due(force=since, transport=transport) == {"feed-a": 0}  # 304
    news._host_last.clear()
    assert await news.refresh_due(force=since, transport=transport) == {}


async def test_prune_removes_old_stories_and_their_reads(reader_client):
    client = reader_client
    await set_news(enabled=True, keep_days=7)
    await _sources(("feed-a", "https://news.example.org/a.xml"))
    await news.refresh_due(transport=_site({"/a.xml": RSS}, []))
    first = (await client.get("/api/news")).json()["items"][0]
    await client.post(f"/api/news/{first['id']}/read")
    async with db.session() as s:
        await s.execute(update(NewsItem).values(published_at=datetime.now(UTC) - timedelta(days=30)))
        await s.commit()
        assert await news.prune(s) == 3
        assert list(await s.scalars(select(NewsRead))) == []


# ---------------------------------------------------------------- the API


async def test_filter_lists_every_source_with_stories(reader_client):
    """The source filter offers every switched-on source – also one in an error state – sorted regardless of case."""
    names = ("heise online", "The Hacker News", "golem.de Security", "BleepingComputer", "off")
    ids = await _sources(*((k, f"https://news.example.org/{k}.xml") for k in names))
    async with db.session() as s:
        await s.execute(update(NewsSource).where(NewsSource.id == ids[1]).values(error="http: HTTP 403", failures=3))
        await s.execute(update(NewsSource).where(NewsSource.id == ids[4]).values(enabled=False))
        await s.commit()
    got = (await reader_client.get("/api/news/sources")).json()
    assert [s["name"] for s in got] == ["BleepingComputer", "golem.de Security", "heise online", "The Hacker News"]


async def test_news_api_read_per_person(reader_client):
    client = reader_client
    await set_news(enabled=True)
    await _sources(("feed-a", "https://news.example.org/a.xml"))
    await news.refresh_due(transport=_site({"/a.xml": RSS}, []))
    d = (await client.get("/api/news")).json()
    assert d["counts"] == {"new": 3, "read": 0, "topics": ANY} and d["enabled"] and [i["severity"] for i in d["items"]] == ["high", "critical", "info"]
    first = d["items"][0]
    assert first["source"]["logo"] and (await client.get(f"/api/news/sources/{first['source']['id']}/logo")).headers["content-type"] == "image/x-icon"
    full = (await client.get(f"/api/news/{first['id']}")).json()
    assert full["reasons"] and "content_html" in full
    assert (await client.post(f"/api/news/{first['id']}/read")).status_code == 200
    d = (await client.get("/api/news")).json()
    assert d["counts"] == {"new": 2, "read": 1, "topics": ANY} and first["id"] not in [i["id"] for i in d["items"]]
    assert [i["id"] for i in (await client.get("/api/news?state=read")).json()["items"]] == [first["id"]]
    # filters and "all read"
    assert [i["severity"] for i in (await client.get("/api/news?severity=critical")).json()["items"]] == ["critical"]
    # several at once: critical and high
    both = [i["severity"] for st in ("new", "read") for i in (await client.get(f"/api/news?state={st}&severity=critical&severity=high")).json()["items"]]
    assert sorted(both) == ["critical", "high"]
    src = first["source"]["id"]
    assert len((await client.get(f"/api/news?source={src}&source={src}")).json()["items"]) == 2
    # search: title, teaser and CVE ids, case-insensitive
    assert [i["title"] for i in (await client.get("/api/news?q=cve-2026-9999")).json()["items"]] == ["Patch for CVE-2026-9999 (CVSS 9.8)"]
    assert (await client.get("/api/news?q=QUIET")).json()["counts"]["new"] == 1
    assert (await client.get("/api/news?q=%25")).json()["counts"]["new"] == 2  # % is no wildcard: matches like an empty search
    assert (await client.post("/api/news/read-all", json={"severity": ["critical"]})).json() == {"marked": 1}
    assert (await client.delete(f"/api/news/{first['id']}/read")).status_code == 200
    assert (await client.get("/api/news")).json()["counts"] == {"new": 2, "read": 1, "topics": ANY}
    # read per person: an account made later starts with everything read (app/reader.py) – but another reader's marks
    # never count for it: what arrives now is new for tom, though rudi read everything
    tom = await add_user("tom")
    async with make_client() as other:
        await sign_in(other, tom)
        assert (await other.get("/api/news")).json()["counts"] == {"new": 0, "read": 3, "topics": ANY}
        await client.post("/api/news/read-all", json={})
        async with db.session() as s:
            src_a = await s.scalar(select(NewsSource).where(NewsSource.key == "feed-a"))
            await news.store(s, src_a, [{"link": "https://news.example.org/another", "title": "Another day", "summary": "", "content": "", "date": datetime.now(UTC)}])
            await s.commit()
        assert (await other.get("/api/news")).json()["counts"]["new"] == 1
        assert (await client.get("/api/news")).json()["counts"]["new"] == 1
    # without signing in: nothing
    async with make_client() as anon:
        assert (await anon.get("/api/news")).status_code == 401
    assert (await client.get("/api/news/00000000-0000-0000-0000-000000000000")).status_code == 404
    assert (await client.get("/api/news?severity=nonsense")).json()["detail"]["code"] == "invalid"


async def test_search_ignores_case_and_accents(reader_client):
    client = reader_client
    await set_news(enabled=True)
    await _sources(("feed-a", "https://news.example.org/a.xml"))
    feed = RSS.replace(b"A quiet day", "Kritische Lücke in Übersetzungs-Tool".encode())
    await news.refresh_due(transport=_site({"/a.xml": feed}, []))
    for q in ("lücke", "LÜCKE", "lucke", "übersetzung"):
        assert (await client.get("/api/news", params={"q": q})).json()["counts"]["new"] == 1, q


async def test_sources_and_settings(admin_client, monkeypatch):
    client = admin_client
    d = (await client.get("/api/admin/news")).json()
    keys = {s["key"]: s for s in d["sources"]}
    assert keys["heise-security"]["enabled"] and not keys["cert-bund"]["enabled"] and d["settings"]["enabled"] is False  # off by default
    # built-in: switched off, never renamed or removed
    hs = keys["heise-security"]["id"]
    assert (await client.patch(f"/api/admin/news/sources/{hs}", json={"enabled": False})).json()["enabled"] is False
    assert (await client.patch(f"/api/admin/news/sources/{hs}", json={"url": "https://evil.example/x"})).status_code == 409
    assert (await client.delete(f"/api/admin/news/sources/{hs}")).status_code == 409
    # an own feed: https only, no internal or private addresses, not twice
    bad_urls = ("http://news.example.org/feed", "https://127.0.0.1/feed", "https://169.254.169.254/latest", "https://10.0.0.5/feed", "javascript:alert(1)")
    for bad in bad_urls:
        assert (await client.post("/api/admin/news/sources", json={"name": "Mein Feed", "url": bad})).status_code == 422, bad
    r = await client.post("/api/admin/news/sources", json={"name": "Mein Feed", "url": "https://news.example.org/feed"})
    assert r.status_code == 200 and not r.json()["builtin"]
    assert (await client.post("/api/admin/news/sources", json={"name": "Nochmal", "url": "https://news.example.org/feed"})).status_code == 409
    assert (await client.delete(f"/api/admin/news/sources/{r.json()['id']}")).status_code == 200
    # "fetch now" only when switched on, at most once a minute
    assert (await client.post("/api/admin/news/fetch")).json()["detail"]["code"] == "news_off"
    assert (await client.put("/api/admin/settings/news", json={"enabled": True, "every_min": 5, "keep_days": 90})).status_code == 422
    assert (await client.put("/api/admin/settings/news", json={"enabled": True, "every_min": 30, "keep_days": 90, "x": 1})).status_code == 422
    assert (await client.put("/api/admin/settings/news", json={"enabled": True, "every_min": 30, "keep_days": 90})).json() == {
        "enabled": True,
        "every_min": 30,
        "keep_days": 90,
        "details": True,  # Details aus der Quelle: on unless switched off
        "rev": 1,  # the saved state – a form loaded before another admin's save is refused (409 stale)
    }
    assert (await client.get("/api/admin/settings/news")).json()["enabled"] is True
    assert (await client.post("/api/admin/news/fetch")).status_code == 200
    assert (await client.post("/api/admin/news/fetch")).status_code == 429

    async def fake_download(url, **kw):
        return news.Fetched(200, httpx.Headers(), RSS)

    monkeypatch.setattr(news, "download", fake_download)
    t = (await client.post("/api/admin/news/test", json={"url": "https://news.example.org/feed"})).json()
    assert t == {"ok": True, "entries": 3, "newest": "New ransomware gang hits hospitals", "error": None}
    assert (await client.post("/api/admin/news/test", json={"url": "https://news.example.org/feed"})).status_code == 429  # one every few seconds


async def test_recent_for_desktop_notifications(reader_client):
    await set_news(enabled=True)
    await _sources(("feed-a", "https://news.example.org/a.xml"))
    first = (await reader_client.get("/api/news/recent")).json()
    assert first["items"] == [] and first["now"]  # a new tab: no backlog, only the cursor
    await news.refresh_due(transport=_site({"/a.xml": fresh(RSS)}, []))
    got = (await reader_client.get("/api/news/recent", params={"since": first["now"]})).json()
    assert len(got["items"]) == 3
    assert (await reader_client.get("/api/news/recent", params={"since": got["now"]})).json()["items"] == []


async def _a_story(title: str) -> None:
    import uuid

    async with db.session() as s:
        src = await s.scalar(select(NewsSource).where(NewsSource.key == "heise"))
        await news.store(s, src, [{"link": f"https://www.heise.de/{uuid.uuid4()}", "title": title, "summary": "", "content": "", "date": datetime.now(UTC)}])


async def test_read_all_marks_only_what_had_arrived_when_the_list_was_loaded(reader_client):
    """Bug hunt 0.1.16 M14: the dialog said 2, a story arrived meanwhile, "Alle als gelesen" marked 3 – the new one was
    never seen. The list tells `upto` (the arrival number when it was read); read-all marks up to it."""
    await set_news(enabled=True)
    await _a_story("One")
    await _a_story("Two")
    page = (await reader_client.get("/api/news")).json()
    assert page["counts"]["new"] == 2 and isinstance(page["upto"], int)
    await _a_story("Arrived meanwhile")
    assert (await reader_client.post("/api/news/read-all", json={"upto": page["upto"]})).json() == {"marked": 2}
    assert [i["title"] for i in (await reader_client.get("/api/news")).json()["items"]] == ["Arrived meanwhile"]
    assert (await reader_client.post("/api/news/read-all", json={})).json() == {"marked": 1}  # without upto: everything, as before


@pytest.mark.parametrize(
    "url",
    [
        "/api/news?before=9999-12-31T23:59:59-14:00|00000000-0000-0000-0000-000000000001",
        "/api/news?before=0001-01-01T00:00:00%2B14:00|00000000-0000-0000-0000-000000000001",
        "/api/news?before=2200-01-01T00:00:00|00000000-0000-0000-0000-000000000001",
        "/api/news/recent?since=9999-12-31T23:59:59-14:00",
        "/api/news/recent?since=0001-01-01T00:00:00%2B14:00",
    ],
)
async def test_times_out_of_range_are_refused_not_a_500(reader_client, url):
    """Bug hunt 0.1.16 L1: a cursor or `since` near the ends of the calendar overflowed (OverflowError, 500)."""
    r = await reader_client.get(url)
    assert r.status_code == 422, r.text[:200]
    assert (await reader_client.get(f"/api/news/recent?after={2**63}")).status_code in (200, 422)
