"""Short transactions (kept from the SQLite days, still right in PostgreSQL): a background round that waits on a slow
vendor site holds no transaction meanwhile – a request's session touch or any other write goes through at once. The
touch itself is best-effort (a locked session row skips it), and a write transaction held too long is logged
(slow-write watchdog)."""

import asyncio
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select, update

from app import db, news, story_details, vendor, vendor_sources
from app import vendor_catalog as catalog
from app.models import (
    NewsItem,
    NewsSource,
    StoryDetail,
    UserSession,
    VendorFollow,
    VendorVersion,
)
from tests.conftest import DATABASE_URL, set_news
from tests.test_story_details import FIX, Sites

SLOW = 3.0  # each vendor request answers after this long


@pytest.fixture
def slow_sites(monkeypatch, tmp_path):
    """The vendor sites of the details tests (fixtures), each answer after SLOW seconds; `entered` says when a request
    is waiting."""
    s = Sites()
    entered: asyncio.Queue[str] = asyncio.Queue()

    async def handler(req: httpx.Request) -> httpx.Response:
        await entered.put(str(req.url))
        await asyncio.sleep(SLOW)
        host = req.url.host
        if host in ("www.cisa.gov", "endoflife.date", "security.paloaltonetworks.com"):
            return httpx.Response(404)  # an answer is enough here – the round goes on
        if host == "services.nvd.nist.gov" and not req.url.params.get("cveId"):
            return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})
        return s.handler(req)

    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(handler))
    monkeypatch.setattr(catalog, "_data_file", lambda: tmp_path / "vendor_catalog.json")
    vendor._last.clear()
    vendor.bump()
    s.entered = entered
    return s


async def _write() -> float:
    """Another writer (a story's arrival number, as the news round takes it) – how long it took, in seconds."""
    t0 = time.monotonic()
    async with db.session() as s:
        await news.next_seq(s)
        await s.commit()
    return time.monotonic() - t0


async def _writes_during(task: asyncio.Task, entered: asyncio.Queue, n: int) -> list[tuple[str, float]]:
    """While each of the next n slow requests is waiting: one write – its duration."""
    out = []
    for _ in range(n):
        url = await asyncio.wait_for(entered.get(), 30)
        await asyncio.sleep(0.2)  # the round is now inside the request
        assert not task.done()
        out.append((url, await _write()))
    return out


async def test_details_round_waiting_on_the_network_blocks_no_writer(slow_sites):
    await set_news(enabled=True)
    now = datetime.now(UTC)
    async with db.session() as s:
        srcs = {x.key: x for x in await s.scalars(select(NewsSource))}
        rows = [
            ("heise", "https://www.heise.de/news/a.html", "FortiOS a", ["CVE-2024-21754"]),
            ("heise", "https://www.heise.de/news/b.html", "FortiOS b", ["CVE-2024-23111"]),
            ("talos", "https://blog.talosintelligence.com/c/", "ohne CVE", []),  # a "none" row, written before the requests
        ]
        ids = []
        for n, (key, url, title, cves) in enumerate(rows):
            srcs[key].enabled = True
            i = NewsItem(source_id=srcs[key].id, url=url, url_key=news._key(news.normalize_url(url)), title=title, title_key=news.title_key(title), summary="", published_at=now - timedelta(hours=n), fetched_at=now, cves=cves, seq=await news.next_seq(s))
            s.add(i)
            await s.flush()
            ids.append(i.id)
        # a story whose details are due again: its row exists (the old code changed it before the request)
        s.add(StoryDetail(item_id=ids[1], kind="nvd", status="ok", data=None, failures=0, next_try_at=now - timedelta(minutes=1)))
        await s.commit()
    async with db.session() as s:
        task = asyncio.create_task(story_details.enrich_round(s))
        took = await _writes_during(task, slow_sites.entered, 2)
        assert await task == 2
    assert all(t < 1.0 for _, t in took), took
    async with db.session() as s:
        dets = {d.item_id: d for d in await s.scalars(select(StoryDetail))}
    assert dets[ids[0]].status == "ok" and dets[ids[0]].data["via_nvd"] and dets[ids[1]].status == "ok" and dets[ids[2]].status == "none"


async def test_vendor_round_waiting_on_the_network_blocks_no_writer(slow_sites):
    now = datetime.now(UTC)
    async with db.session() as s:
        f = VendorFollow(product="panos", enabled=True, note="", tags=[], created_at=now, updated_at=now)
        s.add(f)
        await s.flush()
        s.add(VendorVersion(follow_id=f.id, version="11.1.2", label="", created_at=now, updated_at=now))
        await s.commit()
    task = asyncio.create_task(vendor.run_round(force=True))
    try:
        # KEV, endoflife.date, Palo Alto: each a new query state (written before the request in the old code)
        took = await _writes_during(task, slow_sites.entered, 3)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert all(t < 1.0 for _, t in took), took


# ---------------------------------------------------------------- the session touch is best-effort


async def _stale(client) -> uuid.UUID:
    """The client's session last seen 10 minutes ago: its next request touches it."""
    async with db.session() as s:
        sid = (await s.scalars(select(UserSession.id).where(UserSession.user_id == client.user.id))).one()
        await s.execute(update(UserSession).where(UserSession.id == sid).values(last_seen_at=datetime.now(UTC) - timedelta(minutes=10)))
        await s.commit()
    return sid


async def _seen(sid: uuid.UUID) -> datetime:
    async with db.session() as s:
        return (await s.get(UserSession, sid)).last_seen_at


async def _hold_row(sid: uuid.UUID):  # noqa: ANN202
    """Another connection holds the session's row (as a request ending that session would) – returned open."""
    import asyncpg

    conn = await asyncpg.connect(DATABASE_URL.set(drivername="postgresql").render_as_string(hide_password=False))
    tr = conn.transaction()
    await tr.start()
    await conn.execute("SELECT 1 FROM user_sessions WHERE id = $1 FOR UPDATE", sid)
    return conn, tr


async def test_touch_on_a_locked_row_never_fails_the_request(reader_client):
    sid = await _stale(reader_client)
    before = await _seen(sid)
    other, tr = await _hold_row(sid)
    try:
        t0 = time.monotonic()
        r = await reader_client.get("/api/news")
        took = time.monotonic() - t0
    finally:
        await tr.rollback()
        await other.close()
    assert r.status_code == 200 and took < 3.0, (r.status_code, took)
    assert await _seen(sid) == before  # skipped, not failed
    r = await reader_client.get("/api/news")  # free again: touched
    assert r.status_code == 200 and await _seen(sid) > before


async def test_write_after_a_skipped_touch_goes_through(reader_client):
    """The skipped touch leaves no transaction behind: the request's own write works while the row is still held."""
    await set_news(enabled=True)
    async with db.session() as s:
        src = (await s.scalars(select(NewsSource).where(NewsSource.key == "heise"))).one()
        i = NewsItem(source_id=src.id, url="https://www.heise.de/x.html", url_key="x", title="x", title_key="x", summary="", published_at=datetime.now(UTC), fetched_at=datetime.now(UTC), cves=[], seq=await news.next_seq(s))
        s.add(i)
        await s.commit()
    sid = await _stale(reader_client)
    other, tr = await _hold_row(sid)
    try:
        r = await reader_client.post(f"/api/news/{i.id}/read")
    finally:
        await tr.rollback()
        await other.close()
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------- slow-write watchdog


async def test_a_write_held_too_long_is_logged_with_its_place(monkeypatch, caplog):
    monkeypatch.setattr(db, "SLOW_WRITE_S", 0.1)
    with caplog.at_level(logging.WARNING, logger="cobe_news.db"):
        async with db.session() as s:
            await news.next_seq(s)
            await asyncio.sleep(0.3)
            await s.commit()
        await _write()  # a short one: not logged
    msgs = [r.getMessage() for r in caplog.records if "slow write" in r.getMessage()]
    assert len(msgs) == 1 and "news.py" in msgs[0] and "next_seq" in msgs[0], msgs


async def test_store_writes_big_batches_in_short_transactions(monkeypatch):
    """An NVD backfill (here 5 records, batches of 2): one short transaction per batch, every record stored."""
    monkeypatch.setattr(vendor, "STORE_BATCH", 2)
    _, advs = vendor_sources.parse_nvd((FIX / "nvd_fortios.json").read_bytes())
    commits = 0
    async with db.session() as s:
        real = s.commit

        async def commit():
            nonlocal commits
            commits += 1
            await real()

        monkeypatch.setattr(s, "commit", commit)
        assert await vendor.store(s, advs[:5], vendor.build_index()) == 5
        assert await vendor.store(s, advs[:5], vendor.build_index()) == 0  # unchanged: nothing written again
    assert commits == 1 + 3 + 1  # the caller's pending state, three batches; the second call only releases
