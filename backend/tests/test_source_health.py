"""Quellen-Gesundheit (app/source_health.py): one stats row per fetch (success, 304, error, unreadable), the error
categories, the states and their edge cases (switched off, never fetched, no new story for 60 days), the retention,
the admin API (readers get 403), one query set however many sources there are, notifications once per state change
(not again next round, not after a restart), and the migration. All HTTP is mocked."""

import email.utils
import ssl
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import set_news
from sqlalchemy import delete, event, func, select, update

from app import db, news, notify, source_health, sqlite_import, vendor
from app.models import NewsItem, NewsSource, SourceFetchStat, SourceHealthDelivery, SourceHealthEvent, VendorFetch
from app.news import NewsError
from app.source_health import Facts, classify

NOW = datetime.now(UTC)


def _days_ago(days: int, hours: int) -> bytes:
    """An RSS date relative to the run – a fixed one would fall out of the news retention (keep_days) one day."""
    return email.utils.format_datetime(NOW - timedelta(days=days, hours=hours), usegmt=True).encode()


RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Example</title>
<item><title>New ransomware gang hits hospitals</title><link>https://news.example.org/ransomware</link>
<pubDate>""" + _days_ago(3, 2) + b"""</pubDate><description>Data stolen.</description></item>
<item><title>Patch for CVE-2026-9999</title><link>https://news.example.org/patch</link><pubDate>""" + _days_ago(3, 3) + b"""</pubDate></item>
<item><title></title><link>https://news.example.org/no-title</link></item>
</channel></rss>"""
HOOK = "https://n8n.corp.example/webhook/health"


async def _source(key: str = "feed-a", url: str = "https://news.example.org/a.xml", **kw) -> NewsSource:
    async with db.session() as s:
        await s.execute(update(NewsSource).values(enabled=False))
        src = NewsSource(key=key, name=kw.pop("name", key.title()), url=url, site="https://news.example.org", builtin=False, enabled=True, failures=0, **kw)
        s.add(src)
        await s.commit()
        return src


async def _fetch(handler) -> dict:  # noqa: ANN001
    news._host_last.clear()
    return await news.refresh_due(force=True, transport=httpx.MockTransport(handler))


async def _stats(key: str = "feed-a") -> list[SourceFetchStat]:
    async with db.session() as s:
        return list(await s.scalars(select(SourceFetchStat).where(SourceFetchStat.key == key).order_by(SourceFetchStat.id)))


async def _add_stats(*rows: dict) -> None:
    async with db.session() as s:
        for r in rows:
            s.add(SourceFetchStat(**{"kind": "news", "key": "feed-a", "ok": True, "requests": 1, "duration_ms": 300, "bytes": 1000, "items": 0, "not_modified": False, "parse_errors": 0, **r}))
        await s.commit()


async def _row(key: str = "feed-a", kind: str = "news") -> dict:
    async with db.session() as s:
        out = await source_health.overview(s)
    return next(x for x in out["items"] if x["kind"] == kind and x["key"] == key)


# ---------------------------------------------------------------- recording


async def test_a_fetch_records_one_row_success_304_and_errors():
    await set_news(enabled=True)
    await _source()

    def ok(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith((".ico", ".png")):
            return httpx.Response(404)
        if req.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, content=RSS, headers={"etag": '"v1"'})

    assert (await _fetch(ok))["feed-a"] >= 1
    (first,) = await _stats()
    assert first.ok and first.status == 200 and first.error is None and first.requests == 1 and first.bytes == len(RSS)
    assert first.items == 2 and first.parse_errors == 1  # the entry without a title could not be read
    assert first.duration_ms >= 0 and not first.not_modified
    await _fetch(ok)  # the logo is not asked again; the feed answers 304
    second = (await _stats())[-1]
    assert second.ok and second.not_modified and second.status == 304 and second.items == 0 and second.bytes == 0
    row = await _row()
    assert row["conditional"] and row["not_modified_7d"] == 1 and row["state"] == "healthy" and row["weeks"][-1] == 2

    async with db.session() as s:
        await s.execute(update(NewsSource).values(etag=None, last_modified=None))
        await s.commit()
    await _fetch(lambda req: httpx.Response(403))
    await _fetch(lambda req: httpx.Response(200, content=b"<html>no feed</html>"))
    await _fetch(lambda req: httpx.Response(502))

    def slow(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=req)

    await _fetch(slow)
    rows = (await _stats())[2:]
    assert [(r.ok, r.status, r.error) for r in rows] == [(False, 403, "blocked"), (False, 200, "parse"), (False, 502, "http_5xx"), (False, None, "timeout")]
    assert rows[1].parse_errors == 1  # the whole answer unreadable


async def test_nothing_recorded_without_a_request():
    """A fetch that never asked the network (not due, a paused host) is no fetch."""
    async with db.session() as s:
        assert source_health.record(s, "news", "x", ok=False, exc=NewsError("rate_limited", "paused")) is None
        source_health.start()
        source_health.measure(0.2, 200, 10)
        assert source_health.record(s, "news", "x", ok=True) is not None
        assert source_health.record(s, "news", "x", ok=True) is None  # the meter is used up
        await s.rollback()


def test_error_categories():
    cat = source_health.category
    assert cat(NewsError("timeout")) == "timeout" and cat(NewsError("connection", "ConnectError")) == "connection"
    assert cat(NewsError("blocked", "HTTP 403")) == "blocked" and cat(NewsError("http", "HTTP 403")) == "blocked"
    assert cat(NewsError("http", "HTTP 404")) == "http_4xx" and cat(NewsError("http", "HTTP 410")) == "http_4xx"
    assert cat(NewsError("http", "HTTP 500")) == "http_5xx" and cat(NewsError("http"), 503) == "http_5xx"
    assert cat(NewsError("rate_limited", "HTTP 429")) == "rate_limited" and cat(NewsError("http", "HTTP 429")) == "rate_limited"
    assert cat(NewsError("format", "no XML")) == "parse" and cat(NewsError("parse", "content-encoding")) == "parse"
    assert cat(NewsError("too_large", "> 5120 KB")) == "too_large"
    assert cat(NewsError("http", "redirect to non-https")) == "other" and cat(ValueError("x")) == "other"
    try:
        try:
            raise ssl.SSLCertVerificationError("certificate verify failed")
        except ssl.SSLError as inner:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]") from inner
    except httpx.ConnectError as outer:
        try:
            raise NewsError("connection", "ConnectError") from outer
        except NewsError as exc:
            assert cat(exc) == "tls"
    assert source_health.category_of_text("blocked: HTTP 403") == ("blocked", 403)
    assert source_health.category_of_text("http: HTTP 404") == ("http_4xx", 404)
    assert source_health.category_of_text(None) == (None, None)


async def test_vendor_queries_are_recorded(admin_client, monkeypatch, tmp_path):
    from test_vendor_service import Vendors, _follow

    from app import vendor_catalog as catalog

    monkeypatch.setattr(catalog, "_data_file", lambda: tmp_path / "vendor_catalog.json")
    catalog._cache.stamp = ()
    v = Vendors()
    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(v.handler))
    await _follow(admin_client, "panos")
    await vendor.run_round(force=True)
    async with db.session() as s:
        rows = list(await s.scalars(select(SourceFetchStat).where(SourceFetchStat.kind == "vendor")))
    keys = {r.key for r in rows}
    assert {"kev", "eol", "paloalto:PAN-OS"} <= keys and any(k.startswith("nvd:") for k in keys), keys
    assert all(r.ok and r.requests >= 1 for r in rows)
    pan = next(r for r in rows if r.key == "paloalto:PAN-OS")
    assert pan.items > 0  # advisories stored
    vendor.reset()
    v.nvd_status = 500
    await vendor.run_round(force=True)  # Palo Alto, KEV, eol: 304 – NVD: 500
    async with db.session() as s:
        again = list(await s.scalars(select(SourceFetchStat).where(SourceFetchStat.kind == "vendor", SourceFetchStat.id > max(r.id for r in rows))))
    by = {r.key: r for r in again}
    assert by["paloalto:PAN-OS"].not_modified and by["kev"].not_modified
    nvd = [r for k, r in by.items() if k.startswith("nvd:")]
    assert nvd and all((not r.ok) and r.error == "http_5xx" and r.status == 500 for r in nvd)
    async with db.session() as s:
        out = await source_health.overview(s)
    fam = {x["key"]: x for x in out["items"] if x["kind"] == "vendor"}
    assert fam["nvd"]["state"] == "slow" and "retrying" in fam["nvd"]["reasons"]  # one passing failure: retried soon
    assert fam["nvd"]["members"]["total"] >= 1 and fam["paloalto"]["state"] == "healthy" and fam["paloalto"]["conditional"]
    detail = (await admin_client.get("/api/admin/source-health/vendor/nvd")).json()
    assert detail["members"] and all(m["key"].startswith(("nvd:", "nvdkw:")) for m in detail["members"])
    assert detail["fetches"] and all(f["key"].startswith(("nvd:", "nvdkw:")) for f in detail["fetches"])


# ---------------------------------------------------------------- states


def test_states():
    now = NOW
    ago = lambda **kw: now - timedelta(**kw)  # noqa: E731
    fine = {"last_fetch_at": ago(minutes=5), "last_ok_at": ago(minutes=5), "since": ago(days=200)}
    assert classify(Facts(active=False, **fine), now) == ("off", [])
    assert classify(Facts(), now) == ("never", [])
    assert classify(Facts(**fine), now) == ("healthy", [])
    # dead
    assert classify(Facts(**fine | {"failures": 2, "error": "blocked", "status": 403}), now) == ("dead", ["blocked"])
    assert classify(Facts(**fine | {"failures": 1, "error": "blocked", "status": 403}), now)[0] == "disturbed"  # once: a hiccup
    assert classify(Facts(**fine | {"failures": 2, "error": "http_4xx", "status": 410}), now) == ("dead", ["blocked"])
    assert classify(Facts(**fine | {"failures": 3, "error": "http_4xx", "status": 404}), now) == ("dead", ["not_found"])
    assert classify(Facts(**fine | {"failures": 2, "error": "http_4xx", "status": 404}), now) == ("disturbed", ["error"])
    assert classify(Facts(**fine | {"last_ok_at": ago(days=15), "failures": 1, "error": "timeout"}), now) == ("dead", ["no_success"])
    assert classify(Facts(**fine | {"last_ok_at": None, "since": ago(days=20), "failures": 1, "error": "connection"}), now) == ("dead", ["no_success"])
    # switched on again a week ago after months: its old success does not count against it
    assert classify(Facts(**fine | {"last_ok_at": ago(days=90), "since": ago(days=7), "failures": 1, "error": "timeout"}), now)[0] == "slow"
    # disturbed
    assert classify(Facts(**fine | {"failures": 3, "error": "timeout"}), now) == ("disturbed", ["failing"])
    assert classify(Facts(**fine | {"failures": 1, "error": "parse"}), now) == ("disturbed", ["error"])
    assert classify(Facts(**fine | {"failures": 1, "error": "tls"}), now) == ("disturbed", ["error"])
    assert classify(Facts(**fine | {"parse_fails": 1}), now) == ("disturbed", ["parse"])
    # slow
    assert classify(Facts(**fine | {"avg_ms": 6000, "measured": 5}), now) == ("slow", ["slow"])
    assert classify(Facts(**fine | {"avg_ms": 6000, "measured": 2}), now) == ("healthy", [])  # too few to tell
    assert classify(Facts(**fine | {"timeouts": 3, "fetches": 10}), now) == ("slow", ["timeouts"])
    assert classify(Facts(**fine | {"timeouts": 3, "fetches": 40}), now) == ("healthy", [])
    assert classify(Facts(**fine | {"failures": 1, "error": "http_5xx"}), now) == ("slow", ["retrying"])


def test_no_new_story_for_60_days():
    now = NOW
    base = Facts(last_fetch_at=now, last_ok_at=now, since=now - timedelta(days=200), stale_check=True, items_known_since=now - timedelta(days=90))
    assert classify(base, now) == ("dead", ["stale"])  # never brought anything in 90 days
    assert classify(Facts(**{**base.__dict__, "last_item_at": now - timedelta(days=61)}), now) == ("dead", ["stale"])
    assert classify(Facts(**{**base.__dict__, "last_item_at": now - timedelta(days=59)}), now) == ("healthy", [])
    # not judged before the stories and the stats cover 60 days (keep_days 7, stats just started) …
    assert classify(Facts(**{**base.__dict__, "items_known_since": now - timedelta(days=7)}), now) == ("healthy", [])
    # … nor for a source switched on lately, nor for Vendor News queries (0 changes is normal there)
    assert classify(Facts(**{**base.__dict__, "since": now - timedelta(days=10)}), now) == ("healthy", [])
    assert classify(Facts(**{**base.__dict__, "stale_check": False}), now) == ("healthy", [])


def test_worth_sending():
    w = source_health.worth_sending
    assert w("healthy", "disturbed") and w("slow", "dead") and w("disturbed", "dead") and w("never", "disturbed")
    assert w("dead", "healthy") and w("disturbed", "slow")
    assert not w(None, "dead") and not w("dead", "dead") and not w("dead", "disturbed") and not w("dead", "off")
    assert not w("healthy", "slow") and not w("off", "healthy") and not w("never", "healthy")


async def test_off_never_stale_on_the_overview():
    await set_news(enabled=True, keep_days=90)
    old = NOW - timedelta(days=120)
    a = await _source("feed-a", created_at=old, last_fetch_at=NOW, last_ok_at=NOW)
    async with db.session() as s:
        s.add(NewsSource(key="feed-b", name="B", url="https://news.example.org/b.xml", site="", builtin=False, enabled=True, failures=0))
        s.add(NewsSource(key="feed-c", name="C", url="https://news.example.org/c.xml", site="", builtin=False, enabled=False, failures=0, last_ok_at=NOW))
        s.add(NewsItem(source_id=a.id, url="https://news.example.org/x", url_key="x", title="Old", title_key="old", published_at=old, fetched_at=NOW - timedelta(days=70)))
        await s.commit()
    assert (await _row("feed-a"))["state"] == "dead" and (await _row("feed-a"))["reasons"] == ["stale"]
    assert (await _row("feed-b"))["state"] == "never" and (await _row("feed-c"))["state"] == "off"
    async with db.session() as s:
        s.add(NewsItem(source_id=a.id, url="https://news.example.org/y", url_key="y", title="New", title_key="new", published_at=NOW, fetched_at=NOW - timedelta(days=3)))
        await s.commit()
    assert (await _row("feed-a"))["state"] == "healthy"
    await set_news(enabled=False)  # the news switched off as a whole
    assert {x["state"] for x in (await source_health_items()) if x["kind"] == "news"} == {"off"}


async def source_health_items() -> list[dict]:
    async with db.session() as s:
        return (await source_health.overview(s))["items"]


async def test_overview_numbers_and_sparkline():
    await set_news(enabled=True)
    await _source(last_fetch_at=NOW, last_ok_at=NOW, etag='"x"')
    await _add_stats(
        {"at": NOW - timedelta(days=22), "items": 4},
        {"at": NOW - timedelta(days=1), "items": 3, "duration_ms": 6000, "requests": 1, "bytes": 3000},
        {"at": NOW - timedelta(hours=5), "items": 2, "duration_ms": 8000, "requests": 1, "bytes": 1000},
        {"at": NOW - timedelta(hours=3), "ok": False, "error": "timeout", "status": None, "duration_ms": 30000, "bytes": 0},
        {"at": NOW - timedelta(hours=1), "not_modified": True, "status": 304, "bytes": 0, "duration_ms": 1000},
    )
    row = await _row()
    assert row["weeks"] == [4, None, None, 5]  # oldest first; a week without a fetch is unknown, not 0
    assert row["avg_ms"] == 5000 and row["avg_bytes"] == 2000  # failed fetches do not count; 304 has no body
    assert row["fetches_7d"] == 4 and row["timeouts_7d"] == 1 and row["not_modified_7d"] == 1 and row["conditional"]
    assert row["last_error"]["category"] == "timeout" and row["error"] is None and row["state"] == "healthy"


async def test_big_downloads_do_not_make_a_source_slow():
    """A first full NVD fetch (several MB in a few pages) takes long by nature – it is shown in the average, but "slow"
    is judged without it."""
    await set_news(enabled=True)
    await _source(last_fetch_at=NOW, last_ok_at=NOW)
    await _add_stats(
        {"at": NOW - timedelta(hours=2), "duration_ms": 26000, "requests": 4, "bytes": 6_000_000},
        {"at": NOW - timedelta(hours=1), "duration_ms": 600, "requests": 1, "bytes": 70_000},
    )
    row = await _row()
    assert row["state"] == "healthy" and row["avg_ms"] == 5320  # the shown average still counts the big fetch
    await _add_stats(*({"at": NOW - timedelta(minutes=m), "duration_ms": 7000, "requests": 1, "bytes": 70_000} for m in (10, 20, 30)))
    assert (await _row())["state"] == "slow"  # small answers that take long still do


# ---------------------------------------------------------------- retention, API, queries


async def test_prune_after_60_days():
    await _add_stats({"at": NOW - timedelta(days=61)}, {"at": NOW - timedelta(days=59)}, *({"at": NOW - timedelta(days=70)} for _ in range(5)))
    async with db.session() as s:
        s.add(SourceHealthEvent(kind="news", key="feed-a", state="healthy", created_at=NOW - timedelta(days=90)))
        s.add(SourceHealthEvent(kind="news", key="feed-a", state="dead", created_at=NOW - timedelta(days=80)))  # its newest: stays
        s.add(SourceHealthEvent(kind="news", key="feed-b", state="healthy", created_at=NOW - timedelta(days=1)))
        await s.commit()
    async with db.session() as s:
        assert await source_health.prune(s) == 6
        assert await s.scalar(select(func.count()).select_from(SourceFetchStat)) == 1
        assert sorted(await s.scalars(select(SourceHealthEvent.state))) == ["dead", "healthy"]


async def test_prune_in_batches(monkeypatch):
    monkeypatch.setattr(source_health, "PRUNE_BATCH", 3)
    await _add_stats(*({"at": NOW - timedelta(days=61)} for _ in range(8)))
    async with db.session() as s:
        assert await source_health.prune(s) == 8


async def test_api_is_admin_only(admin_client, reader_client, client):
    await set_news(enabled=True)
    await _source(last_fetch_at=NOW, last_ok_at=NOW)
    assert (await reader_client.get("/api/admin/source-health")).status_code == 403
    assert (await reader_client.get("/api/admin/source-health/news/feed-a")).status_code == 403
    assert (await client.get("/api/admin/source-health")).status_code == 401
    r = await admin_client.get("/api/admin/source-health")
    assert r.status_code == 200 and r.json()["counts"]["healthy"] >= 1
    await _add_stats({"at": NOW - timedelta(hours=1), "ok": False, "error": "blocked", "status": 403})
    d = (await admin_client.get("/api/admin/source-health/news/feed-a")).json()
    assert d["item"]["key"] == "feed-a" and d["fetches"][0]["error"] == "blocked" and d["errors"][0]["status"] == 403 and d["members"] == []
    assert (await admin_client.get("/api/admin/source-health/news/nope")).status_code == 404
    assert (await admin_client.get("/api/admin/source-health/other/feed-a")).status_code == 422


async def test_overview_queries_do_not_grow_with_the_sources():
    """No N+1: the same statements for 3 sources and for 40 (with their stats and Vendor News queries)."""
    await set_news(enabled=True)

    async def count() -> int:
        seen: list[str] = []

        def on(conn, cursor, statement, *a):  # noqa: ANN001, ANN002
            seen.append(statement)

        sync = db.engine().sync_engine
        event.listen(sync, "before_cursor_execute", on)
        try:
            async with db.session() as s:
                await source_health.overview(s)
        finally:
            event.remove(sync, "before_cursor_execute", on)
        return len(seen)

    async def grow(n: int, start: int) -> None:
        async with db.session() as s:
            for i in range(start, start + n):
                s.add(NewsSource(key=f"f{i}", name=f"F{i}", url=f"https://news.example.org/{i}.xml", site="", builtin=False, enabled=True, failures=i % 4, last_fetch_at=NOW))
                s.add(VendorFetch(key=f"nvd:a:example:p{i}", failures=0, items=0, last_fetch_at=NOW, last_ok_at=NOW))
                for h in range(3):
                    s.add(SourceFetchStat(kind="news", key=f"f{i}", at=NOW - timedelta(hours=h), ok=True, requests=1, duration_ms=200, bytes=10, items=1, not_modified=False, parse_errors=0))
            await s.commit()

    await grow(3, 0)
    few = await count()
    await grow(37, 3)
    assert await count() == few


# ---------------------------------------------------------------- notifications


async def _health_rule(admin_client) -> dict:  # noqa: ANN001
    ch = (await admin_client.post("/api/admin/notify/channels", json={"name": "Hook", "type": "webhook", "url": HOOK})).json()
    r = await admin_client.post("/api/admin/notify/rules", json={"name": "Quellen", "channels": [ch["id"]], "severities": [], "kinds": ["source_health"]})
    assert r.status_code == 200, r.text
    return r.json()


async def _evaluate() -> int:
    async with db.session() as s:
        return await source_health.evaluate(s)


async def _dispatch() -> dict:
    async with db.session() as s:
        return await notify.dispatch(s)


@pytest.fixture
def hook(monkeypatch):
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.host == "n8n.corp.example"
        calls.append(req)
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(notify, "transport", httpx.MockTransport(handler))
    return calls


async def test_notified_once_per_state_change(admin_client, hook):
    await set_news(enabled=True)
    src = await _source(name="Example Feed", last_fetch_at=NOW, last_ok_at=NOW)
    await _health_rule(admin_client)
    assert await _evaluate() == 0  # the baseline: nothing sent
    assert await _dispatch() == {}
    async with db.session() as s:  # refused twice in a row: dead
        await s.execute(update(NewsSource).where(NewsSource.id == src.id).values(failures=2, error="blocked: HTTP 403", next_fetch_at=NOW + timedelta(hours=2)))
        await s.commit()
    assert await _evaluate() == 1
    assert await _dispatch() == {"Hook": 1}
    body = hook[-1].read().decode()
    assert "Quelle tot: Example Feed (News)" in body and "lehnt automatische Abrufe ab" in body and '"kind":"source.health"' in body.replace(" ", "")
    assert "view=health" in body
    # the next round, and a restart (the in-process marks forgotten): nothing again
    assert await _evaluate() == 0 and await _dispatch() == {}
    notify.reset()
    assert await _evaluate() == 0 and await _dispatch() == {}
    assert len(hook) == 1
    async with db.session() as s:  # back: one message
        await s.execute(update(NewsSource).where(NewsSource.id == src.id).values(failures=0, error=None, last_ok_at=datetime.now(UTC)))
        await s.commit()
    assert await _evaluate() == 1 and await _dispatch() == {"Hook": 1}
    assert "Quelle wieder in Ordnung" in hook[-1].read().decode()
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(SourceHealthDelivery)) == 2
        states = list(await s.scalars(select(SourceHealthEvent.state).where(SourceHealthEvent.key == "feed-a").order_by(SourceHealthEvent.n)))
    assert states == ["healthy", "dead", "healthy"]


async def test_slow_and_off_are_not_sent_and_old_changes_not_after_widening(admin_client, hook):
    await set_news(enabled=True)
    src = await _source(last_fetch_at=NOW, last_ok_at=NOW)
    ch = (await admin_client.post("/api/admin/notify/channels", json={"name": "Hook", "type": "webhook", "url": HOOK})).json()
    rule = (await admin_client.post("/api/admin/notify/rules", json={"name": "News", "channels": [ch["id"]], "severities": [], "kinds": ["news"]})).json()
    await _evaluate()
    async with db.session() as s:  # a change worth a message – while the rule does not send them
        await s.execute(update(NewsSource).where(NewsSource.id == src.id).values(failures=3, error="timeout"))
        await s.commit()
    assert await _evaluate() == 1
    body = {"name": "News", "channels": [ch["id"]], "severities": [], "kinds": ["news", "source_health"]}
    assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body | {"version": rule["version"]})).status_code == 200
    assert await _dispatch() == {}  # widened: the change from before is not sent
    async with db.session() as s:  # switched off: no message
        await s.execute(update(NewsSource).where(NewsSource.id == src.id).values(enabled=False))
        await s.commit()
    assert await _evaluate() == 0 and await _dispatch() == {}
    assert hook == []


async def test_a_vendor_family_is_one_message(admin_client, hook, monkeypatch):
    """NVD down: one message for the family, not one per CPE query."""
    keys = {f"nvd:a:example:p{i}" for i in range(5)} | {"kev", "eol"}

    async def active(_db):  # noqa: ANN001, ANN202
        return keys

    monkeypatch.setattr(vendor, "active_keys", active)
    async with db.session() as s:
        for k in keys:
            s.add(VendorFetch(key=k, failures=0, items=0, last_fetch_at=NOW, last_ok_at=NOW))
        await s.commit()
    await _health_rule(admin_client)
    await _evaluate()
    async with db.session() as s:
        await s.execute(update(VendorFetch).where(VendorFetch.key.startswith("nvd:")).values(failures=3, error="http: HTTP 500"))
        await s.commit()
    assert await _evaluate() == 1
    assert await _dispatch() == {"Hook": 1}
    assert "Quelle gestört: NVD (Vendor News)" in hook[-1].read().decode()
    row = next(x for x in await source_health_items() if x["key"] == "nvd")
    assert row["members"] == {"total": 5, "active": 5, "problems": 5} and row["error"]["category"] == "http_5xx"


# ---------------------------------------------------------------- schema, import, backup


async def test_migration_up():
    """0003 on a database at 0002: the tables come (and go again with a downgrade)."""
    from alembic import command
    from sqlalchemy import inspect

    def down(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "0002")
        return set(inspect(conn).get_table_names())

    async with db.engine().begin() as conn:
        tables = await conn.run_sync(down)
    assert "source_fetch_stats" not in tables and "news_items" in tables
    assert await db.revision() == "0002"
    await db.migrate()
    assert await db.revision() == db.head()
    async with db.engine().connect() as conn:
        tables = await conn.run_sync(lambda c: set(inspect(c).get_table_names()))
    assert {"source_fetch_stats", "source_health_events", "source_health_deliveries"} <= tables


async def test_new_tables_are_backed_up_not_imported():
    names = {t.name for t in sqlite_import.import_tables()}
    assert not names & sqlite_import.NOT_IN_SQLITE and {"news_items", "vendor_events"} <= names
    from app import backup

    await _add_stats({"at": NOW})
    async with db.engine().connect() as conn:
        counts = await backup.table_counts(conn)
    assert counts["source_fetch_stats"] == 1 and "source_health_events" in counts


async def test_deleted_source_drops_out():
    await set_news(enabled=True)
    await _source(last_fetch_at=NOW, last_ok_at=NOW)
    await _add_stats({"at": NOW})
    async with db.session() as s:
        await s.execute(delete(NewsSource).where(NewsSource.key == "feed-a"))
        await s.commit()
    assert not any(x["key"] == "feed-a" for x in await source_health_items())
