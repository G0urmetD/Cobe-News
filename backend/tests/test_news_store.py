"""The storage side of the news (news.store / fetch_source / prune, api.py, the backlog guards): dedupe by title only
across sources, updates of a known story, stories carried by several sources, backlog decided once when stored,
transient backoff, retention horizon, sources added / moved / deleted. All HTTP is mocked."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import add_user, make_client, set_news, sign_in
from sqlalchemy import select, update

from app import api, db, news, notify, vendor
from app.models import NewsItem, NewsItemSource, NewsSource, NotifyRule, StoryDetail, User


@pytest.fixture(autouse=True)
async def builtins_off():
    """Only the sources a test adds are fetched."""
    async with db.session() as s:
        await s.execute(update(NewsSource).values(enabled=False))
        await s.commit()


async def _src(key: str, name: str | None = None, *, url: str | None = None, enabled: bool = True, primed: bool = True) -> uuid.UUID:
    async with db.session() as s:
        src = NewsSource(
            key=key,
            name=name or key,
            url=url or f"https://{key}.example.org/feed.xml",
            site="",
            builtin=False,
            enabled=enabled,
            failures=0,
            primed_at=datetime.now(UTC) if primed else None,
        )
        s.add(src)
        await s.commit()
        return src.id


async def _store(sid: uuid.UUID, entries: list[dict], keep: timedelta | None = None) -> int:
    async with db.session() as s:
        src = await s.get(NewsSource, sid)
        return await news.store(s, src, entries, keep)


def _e(link: str, title: str, *, summary: str = "", date: datetime | None = None, undated: bool = False) -> dict:
    return {"link": link, "title": title, "summary": summary, "content": "", "date": None if undated else (date or datetime.now(UTC) - timedelta(hours=1))}


async def _carriers(item_id: uuid.UUID) -> list[uuid.UUID]:
    """The further sources of a story (news_item_sources)."""
    async with db.session() as s:
        return list(await s.scalars(select(NewsItemSource.source_id).where(NewsItemSource.item_id == item_id).order_by(NewsItemSource.n)))


async def _items() -> list[NewsItem]:
    async with db.session() as s:
        return list(await s.scalars(select(NewsItem).order_by(NewsItem.seq)))


# ---------------------------------------------------------------- B-H2: title dedupe only across sources, Unicode keys


async def test_same_title_in_one_source_is_two_stories_across_sources_one():
    cisa, other = await _src("cisa-x"), await _src("other")
    title = "CISA Adds Two Known Exploited Vulnerabilities to Catalog"
    assert await _store(cisa, [_e("https://cisa-x.example.org/a1", title)]) == 1
    # a few days later the same title under a new URL: a new announcement, not "the same story"
    assert await _store(cisa, [_e("https://cisa-x.example.org/a2", title)]) == 1
    # another source with that title: the same story, only "also in"
    assert await _store(other, [_e("https://other.example.org/x", title)]) == 0
    items = await _items()
    assert len(items) == 2
    merged = [i for i in items if i.also_in]
    assert len(merged) == 1 and merged[0].also_in == ["other"] and await _carriers(merged[0].id) == [other]
    # the second announcement of the other source pairs with the second one of CISA; a third, with both carried
    # already, is a story of its own (a source never merges its own stories by title)
    assert await _store(other, [_e("https://other.example.org/y", title)]) == 0
    assert await _store(other, [_e("https://other.example.org/z", title)]) == 1
    assert [await _carriers(i.id) for i in await _items()] == [[other], [other], []]


def test_title_key_keeps_latin_keys_and_tells_other_scripts_apart():
    old = news._key("linux kernel schwachstelle ermoglicht codeausfuhrung")  # the key 0.1.6 stored for this title
    assert news.title_key("[hoch] Linux Kernel: Schwachstelle ermöglicht Codeausführung") == news._key("hoch linux kernel schwachstelle ermoglicht codeausfuhrung")
    assert news.title_key("Linux Kernel: Schwachstelle ermöglicht Codeausführung") == old
    ru1, ru2 = "Уязвимость в продукте CVE-2026-1234", "Атака на банки CVE-2026-1234"
    zh1, zh2 = "安全漏洞公告", "勒索软件攻击"
    keys = {news.title_key(t) for t in (ru1, ru2, zh1, zh2)}
    assert len(keys) == 4 and news.title_key(ru1) != news.title_key("CVE-2026-1234")
    assert news.title_key("Уязвимость  в продукте: CVE-2026-1234!") == news.title_key(ru1)  # punctuation and case still ignored


# ---------------------------------------------------------------- B-M1: updates of a known URL


async def test_update_of_a_known_url_rerates_upward_and_merges_cves():
    sid = await _src("bsi")
    url = "https://bsi.example.org/w/1"
    await _store(sid, [_e(url, "[mittel] Produkt X: Schwachstelle", summary="Betrifft CVE-2026-1111.")])
    (item,) = await _items()
    assert item.severity == "medium" and item.cves == ["CVE-2026-1111"]
    async with db.session() as s:
        s.add(StoryDetail(item_id=item.id, kind="bsi", status="ok", next_try_at=None))
        await s.commit()
    # the advisory is updated: exploited now, a second CVE
    upd = "Betrifft CVE-2026-1111 und CVE-2026-2222. Die Lücke wird aktiv ausgenutzt."
    assert await _store(sid, [_e(url, "[UPDATE] [mittel] Produkt X: Schwachstelle", summary=upd)]) == 0
    (item,) = await _items()
    assert item.title.startswith("[UPDATE]") and item.severity == "critical" and item.cves == ["CVE-2026-1111", "CVE-2026-2222"]
    assert "cve-2026-2222" in item.search and "aktiv ausgenutzt" in item.summary
    async with db.session() as s:
        assert (await s.get(StoryDetail, item.id)).next_try_at is not None  # details asked again
    # a later, milder text does not undo the rating, the CVEs stay merged
    await _store(sid, [_e(url, "[UPDATE 2] [niedrig] Produkt X: Schwachstelle", summary="Betrifft CVE-2026-1111.")])
    (item,) = await _items()
    assert item.severity == "critical" and item.cves == ["CVE-2026-1111", "CVE-2026-2222"] and item.title.startswith("[UPDATE 2]")


# ---------------------------------------------------------------- B-M2: a story carried by several sources


async def test_story_carried_by_several_sources_counts_for_each(reader_client, admin_client):
    await set_news(enabled=True)
    a, b = await _src("feed-a", "Feed A"), await _src("feed-b", "Feed B")
    url = "https://news.example.org/story"
    await _store(a, [_e(url, "Ransomware hits example hospital")])
    await _store(b, [_e(url + "?utm_source=rss", "Ransomware hits example hospital")])
    (item,) = await _items()
    assert item.source_id == a and item.also_in == ["Feed B"] and await _carriers(item.id) == [b]
    # the list: found under either source
    for sid in (a, b):
        got = (await reader_client.get("/api/news", params={"source": str(sid)})).json()
        assert [x["id"] for x in got["items"]] == [str(item.id)] and got["counts"]["new"] == 1
    # the source it was first stored for is switched off: still shown, it is carried by B
    async with db.session() as s:
        await s.execute(update(NewsSource).where(NewsSource.id == a).values(enabled=False))
        await s.commit()
    assert len((await reader_client.get("/api/news")).json()["items"]) == 1
    assert len((await reader_client.get("/api/news", params={"source": str(a)})).json()["items"]) == 0  # A is off
    assert len((await reader_client.get("/api/news", params={"source": str(b)})).json()["items"]) == 1
    # the settings count it for both
    counts = {x["key"]: x["items"] for x in (await admin_client.get("/api/admin/news")).json()["sources"]}
    assert counts["feed-a"] == 1 and counts["feed-b"] == 1
    # desktop choice and notification rule naming only B get it
    async with db.session() as s:
        where = [NewsItem.id == item.id, *api.desktop_filter({"sources": [str(b)]}), *api.fresh_filter()]
        rows, total, _top = await api.arrived(s, where)
        assert total == 1
        rule = NotifyRule(name="B only", severities=[], sources=[str(b)], kinds=["news"], active_since=datetime.now(UTC) - timedelta(days=1))
        s.add(rule)
        await s.commit()
        assert [i.id for i, _ in await notify.pending(s, rule, uuid.uuid4(), rule.active_since)] == [item.id]
        rule.sources = [str(a)]  # only the switched-off one: nothing
        assert await notify.pending(s, rule, uuid.uuid4(), rule.active_since) == []
        rule.sources = ["not-a-uuid"]  # unreadable ids: nothing, not "all sources"
        assert await notify.pending(s, rule, uuid.uuid4(), rule.active_since) == []


async def test_euvd_cves_include_kev_stories_euvd_carries():
    async with db.session() as s:
        await s.execute(update(NewsSource).where(NewsSource.key.in_(["cisa-kev", "enisa-euvd"])).values(enabled=True, primed_at=datetime.now(UTC)))
        await s.commit()
        kev = await s.scalar(select(NewsSource.id).where(NewsSource.key == "cisa-kev"))
        euvd = await s.scalar(select(NewsSource.id).where(NewsSource.key == "enisa-euvd"))
    day = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    entry = {"title": "CVE-2026-5555 · Example Gateway: RCE", "summary": "", "content": "", "date": day, "severity": "high", "reasons": [], "cves": ["CVE-2026-5555"]}
    await _store(kev, [{**entry, "link": "https://nvd.example.org/CVE-2026-5555"}])
    await _store(euvd, [{**entry, "link": "https://euvd.example.org/EUVD-2026-1", "title": "CVE-2026-5555 · Example: RCE"}])
    (item,) = await _items()
    assert await _carriers(item.id) == [euvd]
    async with db.session() as s:
        assert "CVE-2026-5555" in await vendor.euvd_cves(s)


# ---------------------------------------------------------------- B-H3 / B-M5: backlog decided once, when stored


def test_backlog_rule():
    now = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)
    yesterday, three_days = datetime(2026, 10, 27, tzinfo=UTC), datetime(2026, 10, 25, tzinfo=UTC)
    # a date without a time (midnight UTC) counts to the end of that day: KEV of yesterday, fetched 33 h "late", is news
    assert news._backlog(yesterday, now, undated=False, primed=True) is False
    assert news._backlog(datetime(2026, 10, 26, tzinfo=UTC), now, undated=False, primed=True) is True
    assert news._backlog(three_days, now, undated=False, primed=True) is True
    # with a time: older than a day is backlog, as before
    assert news._backlog(now - timedelta(hours=25), now, undated=False, primed=True) is True
    assert news._backlog(now - timedelta(hours=23), now, undated=False, primed=True) is False
    # without a date: backlog in a source's first fetch only
    assert news._backlog(now, now, undated=True, primed=False) is True
    assert news._backlog(now, now, undated=True, primed=True) is False


async def test_late_catalog_entry_and_undated_backlog_reach_rules_tab_and_push_alike(reader_client):
    await set_news(enabled=True)
    sid = await _src("feed", primed=False)
    day = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    first = [
        {"link": "https://feed.example.org/kev", "title": "CVE-2026-7777 · Example: RCE", "summary": "", "content": "", "date": day, "severity": "high", "reasons": [], "cves": ["CVE-2026-7777"]},
        _e("https://feed.example.org/undated-1", "Undated story one", undated=True),
        _e("https://feed.example.org/old", "Old story", date=datetime.now(UTC) - timedelta(days=5)),
    ]
    cur = (await reader_client.get("/api/news/recent")).json()["cursor"]
    async with db.session() as s:
        src = await s.get(NewsSource, sid)
        await news.store(s, src, first)
        src.primed_at = datetime.now(UTC)  # what fetch_source does after a successful first fetch
        await s.commit()
        await news.store(s, await s.get(NewsSource, sid), [_e("https://feed.example.org/undated-2", "Undated story two", undated=True)])
    flags = {i.title: i.backlog for i in await _items()}
    assert flags == {"CVE-2026-7777 · Example: RCE": False, "Undated story one": True, "Old story": True, "Undated story two": False}
    # the tab (and Web Push, same filter) and the rules see the same two
    got = (await reader_client.get("/api/news/recent", params={"after": cur})).json()
    assert sorted(x["title"] for x in got["items"]) == ["CVE-2026-7777 · Example: RCE", "Undated story two"]
    async with db.session() as s:
        rule = NotifyRule(name="All", severities=[], sources=[], kinds=["news"], active_since=datetime.now(UTC) - timedelta(minutes=5))
        s.add(rule)
        await s.commit()
        sent = await notify.pending(s, rule, uuid.uuid4(), rule.active_since)
        assert sorted(i.title for i, _ in sent) == ["CVE-2026-7777 · Example: RCE", "Undated story two"]


async def test_first_fetch_primes_the_source_and_switching_on_again_resets_it(admin_client):
    await set_news(enabled=True)
    feed = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>X</title>
    <item><title>No date here</title><link>https://feed.example.org/1</link></item></channel></rss>"""
    sid = await _src("feed", url="https://feed.example.org/feed.xml", primed=False)
    news._host_last.clear()
    assert await news.refresh_due(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=feed))) == {"feed": 1}
    async with db.session() as s:
        assert (await s.get(NewsSource, sid)).primed_at is not None
        await s.execute(update(NewsSource).where(NewsSource.id == sid).values(enabled=False, error="timeout", failures=4))
        await s.commit()
    got = (await admin_client.patch(f"/api/admin/news/sources/{sid}", json={"enabled": True})).json()
    assert got["error"] is None and got["next_fetch_at"] is None
    async with db.session() as s:
        src = await s.get(NewsSource, sid)
        assert src.primed_at is None and src.failures == 0


# ---------------------------------------------------------------- undated stories and the retention


async def test_undated_story_stays_while_listed_and_pruned_ones_never_come_back(reader_client):
    await set_news(enabled=True, keep_days=7)
    sid = await _src("feed")
    await _store(sid, [_e("https://feed.example.org/u", "Undated", undated=True), _e("https://feed.example.org/d", "Dated", date=datetime.now(UTC) - timedelta(days=1))])
    async with db.session() as s:
        await s.execute(update(NewsItem).values(published_at=datetime.now(UTC) - timedelta(days=30)))
        await s.execute(update(NewsItem).where(NewsItem.seen_at.is_not(None)).values(seen_at=datetime.now(UTC) - timedelta(days=30)))
        await s.commit()
    # still listed: its last sighting moves on, the prune keeps it
    await _store(sid, [_e("https://feed.example.org/u", "Undated", undated=True)])
    async with db.session() as s:
        assert await news.prune(s) == 1
    assert [i.title for i in await _items()] == ["Undated"]
    # keep_days raised afterwards: the story deleted by the retention is not taken again (it would be new and unread)
    await set_news(enabled=True, keep_days=90)
    assert await _store(sid, [_e("https://feed.example.org/d", "Dated", date=datetime.now(UTC) - timedelta(days=30))], keep=timedelta(days=90)) == 0
    # newer than what was deleted: taken
    assert await _store(sid, [_e("https://feed.example.org/n", "Newer", date=datetime.now(UTC) - timedelta(days=5))], keep=timedelta(days=90)) == 1


# ---------------------------------------------------------------- fetching: transient backoff, interval, moved sources


async def test_transient_failures_pause_at_most_an_hour():
    await set_news(enabled=True, every_min=30)
    sid = await _src("feed", url="https://feed.example.org/feed.xml")
    async with db.session() as s:
        await s.execute(update(NewsSource).where(NewsSource.id == sid).values(failures=5))
        await s.commit()

    def refused(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    news._host_last.clear()
    assert await news.refresh_due(transport=httpx.MockTransport(refused)) == {"feed": -1}
    async with db.session() as s:
        src = await s.get(NewsSource, sid)
        assert src.error.startswith("connection") and src.failures == 6
        assert src.next_fetch_at - datetime.now(UTC) <= timedelta(hours=1)  # not 30 min × 2^6 = 24 h
    # a site that answers wrongly still backs off as before
    async with db.session() as s:
        await s.execute(update(NewsSource).where(NewsSource.id == sid).values(next_fetch_at=None))
        await s.commit()
    news._host_last.clear()
    assert await news.refresh_due(transport=httpx.MockTransport(lambda r: httpx.Response(500))) == {"feed": -1}
    async with db.session() as s:
        assert (await s.get(NewsSource, sid)).next_fetch_at - datetime.now(UTC) > timedelta(hours=20)


async def test_shorter_interval_reschedules_healthy_sources():
    await set_news(enabled=True, every_min=15)
    sid = await _src("feed", url="https://feed.example.org/feed.xml")
    async with db.session() as s:
        # fetched 20 minutes ago under a daily interval: due again only tomorrow – now the interval is 15 minutes
        await s.execute(update(NewsSource).where(NewsSource.id == sid).values(last_fetch_at=datetime.now(UTC) - timedelta(minutes=20), next_fetch_at=datetime.now(UTC) + timedelta(hours=23)))
        await s.commit()
    news._host_last.clear()
    assert await news.refresh_due(transport=httpx.MockTransport(lambda r: httpx.Response(304))) == {"feed": 0}


async def test_moved_builtin_source_starts_afresh():
    async with db.session() as s:
        await s.execute(
            update(NewsSource)
            .where(NewsSource.key == "heise")
            .values(url="https://old.example.org/feed", etag='"old"', last_modified="Mon, 01 Jan 2026 00:00:00 GMT", failures=3, error="http: HTTP 404", next_fetch_at=datetime.now(UTC) + timedelta(hours=8), primed_at=datetime.now(UTC))
        )
        await s.execute(update(NewsSource).where(NewsSource.key == "talos").values(etag='"keep"'))
        await s.commit()
        await news.ensure_sources(s)
        heise = await s.scalar(select(NewsSource).where(NewsSource.key == "heise").execution_options(populate_existing=True))
        assert heise.url == news.BUILTIN_BY_KEY["heise"].url
        assert (heise.etag, heise.last_modified, heise.failures, heise.error, heise.next_fetch_at, heise.primed_at) == (None, None, 0, None, None, None)
        talos = await s.scalar(select(NewsSource).where(NewsSource.key == "talos").execution_options(populate_existing=True))
        assert talos.etag == '"keep"'  # unchanged address: kept


# ---------------------------------------------------------------- sources in the settings


async def test_parallel_adds_of_one_address_give_one_source(admin_client):
    body = {"name": "Example", "url": "https://feed.example.org/rss"}
    async with make_client() as other:
        await sign_in(other, admin_client.user)
        got = await asyncio.gather(admin_client.post("/api/admin/news/sources", json=body), other.post("/api/admin/news/sources", json=body))
    assert sorted(r.status_code for r in got) == [200, 409]
    async with db.session() as s:
        assert len(list(await s.scalars(select(NewsSource).where(NewsSource.url == body["url"])))) == 1
    # another source moved onto that address: refused as well
    other_id = (await admin_client.post("/api/admin/news/sources", json={"name": "Other", "url": "https://feed.example.org/other"})).json()["id"]
    assert (await admin_client.patch(f"/api/admin/news/sources/{other_id}", json={"url": body["url"]})).status_code == 409


async def test_eight_parallel_adds_of_one_address_give_one_source(admin_client):
    """Bug hunt 0.1.16 M3: under PostgreSQL the "insert unless it exists" was no longer atomic – 8 parallel POSTs gave up
    to 8 sources of one address. The unique index decides now: one 200, seven 409, every time."""
    for attempt in range(5):
        url = f"https://feed{attempt}.example.org/rss"
        clients = [make_client() for _ in range(8)]
        for c in clients:
            c.cookies.update(admin_client.cookies)
        try:
            got = await asyncio.gather(*[c.post("/api/admin/news/sources", json={"name": "Feed X", "url": url}) for c in clients])
        finally:
            for c in clients:
                await c.aclose()
        assert sorted(r.status_code for r in got) == [200] + [409] * 7, [r.status_code for r in got]
        async with db.session() as s:
            assert len(list(await s.scalars(select(NewsSource).where(NewsSource.url == url)))) == 1


async def test_parallel_moves_onto_one_address_give_one_409(admin_client):
    ids = [(await admin_client.post("/api/admin/news/sources", json={"name": f"Feed {i}", "url": f"https://f{i}.example.org/rss"})).json()["id"] for i in range(2)]
    async with make_client() as other:
        await sign_in(other, admin_client.user)
        got = await asyncio.gather(*[c.patch(f"/api/admin/news/sources/{i}", json={"url": "https://same.example.org/rss"}) for c, i in zip((admin_client, other), ids, strict=True)])
    assert sorted(r.status_code for r in got) == [200, 409]
    # a built-in address is no address of one's own either
    async with db.session() as s:
        builtin = await s.scalar(select(NewsSource.url).where(NewsSource.builtin.is_(True)).limit(1))
    assert (await admin_client.post("/api/admin/news/sources", json={"name": "Copy", "url": builtin})).status_code == 409


async def test_migration_0005_merges_duplicate_addresses(admin_client):
    """Duplicates made before the index: the oldest stays and takes over the stories, the carried stories, the rules'
    and the desktop choices' references; then the index is created."""
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import text

    import app.migrations as mig

    spec = importlib.util.spec_from_file_location("m0005", Path(mig.__file__).parent / "versions" / "0005_source_url_unique.py")
    m0005 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m0005)
    now = datetime.now(UTC)
    url = "https://dup.example.org/rss"
    async with db.engine().begin() as conn:
        await conn.execute(text("DROP INDEX ux_news_sources_url"))
    keep, gone, other = await _src("dup-a", "Dup", url=url), await _src("dup-b", "Dup B", url=url), await _src("other")
    async with db.session() as s:  # the second one is younger
        await s.execute(update(NewsSource).where(NewsSource.id == keep).values(created_at=now - timedelta(days=2)))
        await s.execute(update(NewsSource).where(NewsSource.id == gone).values(created_at=now - timedelta(days=1)))
        await s.commit()
    await _store(gone, [_e("https://n.example.org/own", "Own of B"), _e("https://n.example.org/shared", "Shared")])
    await _store(other, [_e("https://n.example.org/o", "Of other")])
    await _store(gone, [_e("https://n.example.org/o", "Of other")])  # B carries a story of "other"
    await _store(keep, [_e("https://n.example.org/shared", "Shared")])  # A carries a story of B
    reader = await add_user("rita", desktop={"enabled": True, "severities": [], "sources": [str(gone), str(other)]})
    async with db.session() as s:
        s.add(NotifyRule(name="B", severities=[], sources=[str(gone), str(keep)], kinds=["news"]))
        await s.commit()
    async with db.engine().begin() as conn:

        def run(c):  # noqa: ANN001, ANN202
            with Operations.context(MigrationContext.configure(c)):
                m0005.upgrade()

        await conn.run_sync(run)
    items = {i.title: i for i in await _items()}
    assert items["Own of B"].source_id == keep and items["Shared"].source_id == keep and await _carriers(items["Shared"].id) == []
    assert items["Shared"].also_in == [] and items["Of other"].source_id == other and await _carriers(items["Of other"].id) == [keep]
    assert items["Of other"].also_in == ["Dup"]
    async with db.session() as s:
        assert await s.get(NewsSource, gone) is None
        assert (await s.scalar(select(NotifyRule).where(NotifyRule.name == "B"))).sources == [str(keep)]
        assert (await s.get(User, reader.id)).desktop["sources"] == [str(keep), str(other)]
        assert await s.scalar(text("SELECT count(*) FROM pg_indexes WHERE indexname = 'ux_news_sources_url'")) == 1


async def test_deleting_a_source_cleans_up_after_it(admin_client):
    a = (await admin_client.post("/api/admin/news/sources", json={"name": "Feed A", "url": "https://a.example.org/rss"})).json()["id"]
    b = (await admin_client.post("/api/admin/news/sources", json={"name": "Feed B", "url": "https://b.example.org/rss"})).json()["id"]
    c = (await admin_client.post("/api/admin/news/sources", json={"name": "Feed C", "url": "https://c.example.org/rss"})).json()["id"]
    a_id, b_id, c_id = uuid.UUID(a), uuid.UUID(b), uuid.UUID(c)
    await _store(a_id, [_e("https://news.example.org/shared", "Shared story"), _e("https://news.example.org/own", "Own story")])
    await _store(b_id, [_e("https://news.example.org/shared", "Shared story")])
    await _store(c_id, [_e("https://news.example.org/c", "C story")])
    await _store(a_id, [_e("https://news.example.org/c", "C story")])
    reader = await add_user("rita", desktop={"enabled": True, "severities": ["critical"], "sources": [a]})
    other_reader = await add_user("otto", desktop={"enabled": True, "severities": [], "sources": [a, c]})
    async with db.session() as s:
        s.add_all(
            [
                NotifyRule(name="Only A", severities=[], sources=[a], kinds=["news"]),
                NotifyRule(name="A and vendor", severities=[], sources=[a], kinds=["news", "vendor_vuln"]),
                NotifyRule(name="A and C", severities=[], sources=[a, c], kinds=["news"]),
            ]
        )
        await s.commit()
    assert (await admin_client.delete(f"/api/admin/news/sources/{a}")).status_code == 200
    items = {i.title: i for i in await _items()}
    assert set(items) == {"Shared story", "C story"}  # its own story alone went with it
    assert items["Shared story"].source_id == b_id and items["Shared story"].also_in == [] and await _carriers(items["Shared story"].id) == []
    assert items["C story"].source_id == c_id and items["C story"].also_in == [] and await _carriers(items["C story"].id) == []
    async with db.session() as s:
        rules = {r.name: r for r in await s.scalars(select(NotifyRule))}
        assert rules["Only A"].enabled is False and rules["Only A"].sources == []
        assert rules["A and vendor"].enabled is True and rules["A and vendor"].kinds == ["vendor_vuln"] and rules["A and vendor"].sources == []
        assert rules["A and C"].enabled is True and rules["A and C"].sources == [c]
        assert (await s.get(User, reader.id)).desktop == {"enabled": False, "severities": ["critical"], "sources": []}
        assert (await s.get(User, other_reader.id)).desktop["sources"] == [c]


# ---------------------------------------------------------------- rollback: nothing doubled on retry


async def test_a_failed_store_leaves_nothing_and_the_retry_stores_once(monkeypatch):
    await set_news(enabled=True)
    sid = await _src("feed", url="https://feed.example.org/feed.xml")
    feed = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>X</title>
    <item><title>One</title><link>https://feed.example.org/1</link><pubDate>{datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")}</pubDate></item>
    <item><title>Two</title><link>https://feed.example.org/2</link><pubDate>{datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")}</pubDate></item>
    </channel></rss>""".encode()
    transport = httpx.MockTransport(lambda r: httpx.Response(200, content=feed, headers={"etag": '"v1"'}))
    real = news.next_seq
    calls = {"n": 0}

    async def flaky(s):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("disk I/O error")  # the second story of the round fails
        return await real(s)

    monkeypatch.setattr(news, "next_seq", flaky)
    news._host_last.clear()
    assert await news.refresh_due(transport=transport) == {}
    async with db.session() as s:
        src = await s.get(NewsSource, sid)
        assert await _items() == [] and src.etag is None  # no half round, and no ETag that would make the retry a 304
        assert await news.last_seq(s) == 0
        src.next_fetch_at = None
        await s.commit()
    news._host_last.clear()
    assert await news.refresh_due(transport=transport) == {"feed": 2}
    assert [i.title for i in await _items()] == ["One", "Two"]


# ---------------------------------------------------------------- control characters (PostgreSQL refuses a NUL)


def _kev(name: str) -> bytes:
    import json

    today = datetime.now(UTC).date().isoformat()
    vulns = [
        {"cveID": "CVE-2026-11111", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "Good one", "dateAdded": today, "shortDescription": "ok", "requiredAction": "patch", "dueDate": today},
        {"cveID": "CVE-2026-22222", "vendorProject": "Acme", "product": "Gadget", "vulnerabilityName": name, "dateAdded": today, "shortDescription": "x\u0000y", "requiredAction": "patch", "dueDate": today},
    ]
    return json.dumps({"vulnerabilities": vulns}).encode()


async def test_a_nul_in_a_catalog_entry_is_dropped_and_the_feed_stored():
    """Security review 0.1.16 M1 / bug hunt M4: one JSON entry with \\u0000 made PostgreSQL refuse the whole batch – and
    the source looked healthy. The control characters are dropped; both entries are stored."""
    await set_news(enabled=True)
    sid = await _src("own-kev", url="https://kev.example.org/kev.json")
    body = _kev("Bad\u0000na\u0007me")
    news._host_last.clear()
    got = await news.refresh_due(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body, headers={"content-type": "application/json"})))
    assert got == {"own-kev": 2}
    titles = sorted(i.title for i in await _items())
    assert len(titles) == 2 and not any("\x00" in t or "\x07" in t for t in titles) and any("Badname" in t for t in titles)
    async with db.session() as s:
        src = await s.get(NewsSource, sid)
        assert src.error is None and src.failures == 0 and src.last_ok_at is not None


def test_story_drops_control_characters_but_keeps_line_breaks():
    s = news.story({"link": "https://e.example/a\x00b", "title": "T\x00i\x1ftle", "summary": "one\ttwo\nthree\x00\x0b", "content": "", "date": None}, datetime.now(UTC))
    assert s["title"] == "Title" and s["url"] == "https://e.example/ab" and s["summary"] == "one two three" and "\x00" not in s["search"]


async def test_a_story_the_database_refuses_is_skipped_not_the_whole_feed(monkeypatch):
    """A savepoint per story: one the database refuses is logged and left out, the others are stored."""
    sid = await _src("feed")
    real = news._store_one

    async def picky(db_, src, s, now, **kw):
        if s["title"] == "Two":  # a story whose insert fails in the database (here: a source that does not exist)
            return await real(db_, NewsSource(id=uuid.uuid4(), key="x", name="x", url="https://x.example/"), s, now, **kw)
        return await real(db_, src, s, now, **kw)

    monkeypatch.setattr(news, "_store_one", picky)
    entries = [_e("https://feed.example.org/1", "One"), _e("https://feed.example.org/2", "Two"), _e("https://feed.example.org/3", "Three")]
    facts: dict = {}
    async with db.session() as s:
        assert await news.store(s, await s.get(NewsSource, sid), entries, None, facts) == 2
    assert sorted(i.title for i in await _items()) == ["One", "Three"] and facts["unusable"] == 1


async def test_a_store_the_database_refuses_shows_on_the_source_and_the_round_goes_on(monkeypatch):
    """fetch_source did not catch a database error of store(): the source kept "healthy" (no error, no pause) while it
    stored nothing. Now it shows the error and pauses; the next source of the round is fetched."""
    from sqlalchemy.exc import DBAPIError

    await set_news(enabled=True)
    bad = await _src("bad", url="https://bad.example.org/feed.xml")
    good = await _src("good", url="https://good.example.org/feed.xml")
    real = news.store

    async def refusing(db_, src, entries, keep=None, facts=None):
        if src.key == "bad":
            raise DBAPIError("INSERT …", {}, Exception("invalid byte sequence"))
        return await real(db_, src, entries, keep, facts)

    monkeypatch.setattr(news, "store", refusing)
    feed = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>X</title>
    <item><title>One</title><link>https://n.example.org/1</link><pubDate>{datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")}</pubDate></item>
    </channel></rss>""".encode()
    news._host_last.clear()
    got = await news.refresh_due(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=feed, headers={"etag": '"v1"'})))
    assert got == {"bad": -1, "good": 1}
    async with db.session() as s:
        b, g = await s.get(NewsSource, bad), await s.get(NewsSource, good)
        assert b.failures == 1 and b.error and b.error.startswith("format") and b.etag is None and b.next_fetch_at > datetime.now(UTC)
        assert g.error is None and g.failures == 0
