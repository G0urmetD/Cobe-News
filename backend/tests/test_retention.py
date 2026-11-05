"""Retention (0.1.50): every prune on its own (one failing never stops the others), batches that skip rows another
transaction holds (no deadlock with a concurrent update of many stories), undated stories kept while their feed still
lists them, revision numbers that never repeat after an advisory went, the daily Vendor News prunes also with Vendor
News switched off, the count before a shorter news retention – and the prunes nothing tested before."""

import asyncio
import os
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import add_user, set_news
from sqlalchemy import func, select, text, update

from app import advisory_changes as ch
from app import audit, backup, db, delivery_log, epss, main, news, notify, passkeys_api, personal, vendor, weekly
from app import settings as settings_store
from app.auth import bruteforce, lock_store, sessions
from app.config import get_config
from app.models import (
    EpssScore,
    NewsItem,
    NewsSource,
    NotifyRule,
    PersonAbsence,
    PersonDelivery,
    Team,
    TeamWeeklySend,
    UserSession,
    VendorAdvisoryChange,
    VendorEvent,
    VendorFetch,
    VendorFollow,
)

NOW = datetime.now(UTC)


@pytest.fixture(autouse=True)
def vendor_reset():
    vendor.reset()
    yield


async def _only_source(key: str = "feed", *, url: str = "https://feed.example.org/feed.xml", primed: bool = False) -> uuid.UUID:
    async with db.session() as s:
        await s.execute(update(NewsSource).values(enabled=False))
        src = NewsSource(key=key, name=key, url=url, site="", builtin=False, enabled=True, failures=0, primed_at=NOW if primed else None)
        s.add(src)
        await s.commit()
        return src.id


async def _fetch(body: bytes | None, status: int = 200) -> dict:
    """One round of the news: every switched-on source due now, answering `body` (or only `status`, e.g. 304)."""
    async with db.session() as s:
        await s.execute(update(NewsSource).values(next_fetch_at=None))
        await s.commit()
    news._host_last.clear()
    resp = (lambda r: httpx.Response(200, content=body, headers={"etag": str(hash(body))})) if body is not None else (lambda r: httpx.Response(status))
    return await news.refresh_due(transport=httpx.MockTransport(resp))


def _rss(*items: str) -> bytes:
    """A feed whose entries carry no date of their own (dated by when Cobe News first saw them)."""
    entries = "".join(f"<item><title>{t}</title><link>https://feed.example.org/{t.replace(' ', '-')}</link></item>" for t in items)
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>X</title>{entries}</channel></rss>'.encode()


async def _age_all(days: int) -> None:
    """Every story (and the sources' last read) as if it happened `days` ago."""
    old = datetime.now(UTC) - timedelta(days=days)
    async with db.session() as s:
        await s.execute(update(NewsItem).values(published_at=old, fetched_at=old))
        await s.execute(update(NewsItem).where(NewsItem.seen_at.is_not(None)).values(seen_at=old))
        await s.execute(update(NewsSource).where(NewsSource.parsed_at.is_not(None)).values(parsed_at=old - timedelta(minutes=1)))
        await s.commit()


async def _titles() -> dict[str, bool]:
    async with db.session() as s:
        return {i.title: i.backlog for i in await s.scalars(select(NewsItem))}


async def _would_send() -> list[str]:
    async with db.session() as s:
        rule = NotifyRule(name="All", severities=[], sources=[], kinds=["news"], active_since=datetime.now(UTC) - timedelta(minutes=5))
        s.add(rule)
        await s.commit()
        return sorted(i.title for i, _ in await notify.pending(s, rule, uuid.uuid4(), rule.active_since))


# ---------------------------------------------------------------- undated stories (M3)


async def test_undated_story_of_an_unchanged_feed_is_not_pruned_and_never_comes_back_as_news():
    """Up to 0.1.49: a feed answering "304 Not Modified" longer than the retention lost its undated stories although it
    still listed them – and the next time it changed they came back as new, unread and notified."""
    await set_news(enabled=True, keep_days=90)
    await _only_source()
    assert await _fetch(_rss("Advisory without a date")) == {"feed": 1}
    await _age_all(100)  # 100 days of "304 Not Modified": still listed, unchanged
    assert await _fetch(None, 304) == {"feed": 0}
    async with db.session() as s:
        assert await news.prune(s) == 0  # still listed: it stays
    assert await _fetch(_rss("Advisory without a date", "Second one")) == {"feed": 1}  # only the new one is new
    assert set(await _titles()) == {"Advisory without a date", "Second one"}
    assert await _would_send() == ["Second one"]


async def test_undated_story_goes_once_its_feed_no_longer_lists_it():
    await set_news(enabled=True, keep_days=90)
    await _only_source()
    await _fetch(_rss("Gone soon", "Stays"))
    await _age_all(100)
    async with db.session() as s:
        assert await news.prune(s) == 0  # not read since: it may still be listed
    await _fetch(_rss("Stays"))  # read again – "Gone soon" no longer listed
    async with db.session() as s:
        assert await news.prune(s) == 1
    assert list(await _titles()) == ["Stays"]


async def test_undated_story_stays_while_its_feed_fails_or_news_is_off():
    await set_news(enabled=True, keep_days=90)
    await _only_source()
    await _fetch(_rss("Listed"))
    await _age_all(100)
    assert await _fetch(None, 500) == {"feed": -1}  # failing: nothing known about the list
    await set_news(enabled=False, keep_days=90)  # News switched off: the feed is never read
    async with db.session() as s:
        assert await news.prune(s) == 0
    assert list(await _titles()) == ["Listed"]


async def test_undated_story_carried_by_a_second_feed_stays_while_that_one_was_not_read():
    await set_news(enabled=True, keep_days=90)
    a = await _only_source("a", url="https://feed.example.org/a.xml")
    async with db.session() as s:
        b = NewsSource(key="b", name="b", url="https://other.example.org/b.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(b)
        await s.commit()
    await _fetch(_rss("Shared"))  # both list it: one story, carried by both
    await _age_all(100)
    async with db.session() as s:
        # a read again without it; b not read since it last listed it
        await s.execute(update(NewsSource).where(NewsSource.id == a).values(parsed_at=datetime.now(UTC)))
        await s.commit()
        assert await news.prune(s) == 0
        await s.execute(update(NewsSource).values(parsed_at=datetime.now(UTC)))
        # another feed's story, seen after that read: it must not hold this one back (each story by its own sources)
        s.add(NewsItem(source_id=b.id, url="https://x.example/other", url_key="x.example/other", title="Other", title_key="other", published_at=NOW, fetched_at=NOW, seen_at=datetime.now(UTC) + timedelta(hours=1)))
        await s.commit()
        assert await news.prune(s) == 1
        assert list(await s.scalars(select(NewsItem.title))) == ["Other"]


async def test_switching_news_on_again_makes_the_first_fetch_a_baseline(admin_client):
    await set_news(enabled=True)
    sid = await _only_source(primed=True)
    cfg = (await admin_client.get("/api/admin/settings/news")).json()
    r = await admin_client.put("/api/admin/settings/news", json={**cfg, "enabled": False})
    assert r.status_code == 200, r.text
    async with db.session() as s:
        assert (await s.get(NewsSource, sid)).primed_at is not None  # switching off changes nothing
    cfg = (await admin_client.get("/api/admin/settings/news")).json()
    r = await admin_client.put("/api/admin/settings/news", json={**cfg, "enabled": True})
    assert r.status_code == 200, r.text
    async with db.session() as s:
        assert (await s.get(NewsSource, sid)).primed_at is None
    # what the feed listed undated meanwhile is backlog – shown, never notified
    await _fetch(_rss("Listed while News was off"))
    assert await _titles() == {"Listed while News was off": True}


# ---------------------------------------------------------------- the news prune and concurrent writers (M2)


async def test_news_prune_skips_a_story_another_transaction_holds():
    """A story another transaction is updating (the topics of many stories at once, in the Vendor News task) is left
    for the next prune – the prune neither waits for it nor deadlocks with it."""
    await set_news(enabled=True, keep_days=7)
    sid = await _only_source()
    async with db.session() as s:
        for i in range(3):
            s.add(NewsItem(source_id=sid, url=f"https://x.example/{i}", url_key=f"x.example/{i}", title=f"Old {i}", title_key=f"old {i}", published_at=NOW - timedelta(days=30), fetched_at=NOW - timedelta(days=30), seq=i))
        await s.commit()
        held_id = await s.scalar(select(NewsItem.id).where(NewsItem.title == "Old 0"))
    async with db.session() as holder:
        await holder.execute(select(NewsItem).where(NewsItem.id == held_id).with_for_update())
        async with db.session() as s:
            t0 = time.monotonic()
            assert await asyncio.wait_for(news.prune(s), 10) == 2
            assert time.monotonic() - t0 < 5
        await holder.rollback()
    async with db.session() as s:
        assert await news.prune(s) == 1  # the next prune takes it
        assert await s.scalar(select(func.count()).select_from(NewsItem)) == 0


async def test_prune_preview_counts_what_a_shorter_retention_removes(admin_client, reader_client):
    await set_news(enabled=True, keep_days=90)
    sid = await _only_source()
    async with db.session() as s:
        for i, age in enumerate((5, 20, 40, 100)):
            s.add(NewsItem(source_id=sid, url=f"https://x.example/{i}", url_key=f"x.example/{i}", title=f"S{i}", title_key=f"s{i}", published_at=NOW - timedelta(days=age), fetched_at=NOW - timedelta(days=age), seq=i))
        await s.commit()
    got = (await admin_client.get("/api/admin/settings/news/prune-preview", params={"keep_days": 30})).json()
    assert got == {"keep_days": 30, "count": 2}
    assert (await admin_client.get("/api/admin/settings/news/prune-preview", params={"keep_days": 7})).json()["count"] == 3
    assert (await admin_client.get("/api/admin/settings/news/prune-preview", params={"keep_days": 3})).status_code == 422
    assert (await reader_client.get("/api/admin/settings/news/prune-preview", params={"keep_days": 30})).status_code == 403


# ---------------------------------------------------------------- each prune on its own (M1)


async def test_one_failing_prune_does_not_stop_the_others(monkeypatch):
    ran: list[str] = []

    async def broken(s):  # noqa: ANN001, ANN202 - a statement the database refuses: the session must be rolled back
        await s.execute(text("SELECT 1/0"))

    def tracked(name: str):  # noqa: ANN202
        async def f(s):  # noqa: ANN001, ANN202
            assert await s.scalar(text("SELECT 1")) == 1  # the session works again
            ran.append(name)
            return 0

        return f

    monkeypatch.setattr(news, "prune", broken)
    monkeypatch.setattr(audit, "prune", tracked("audit"))
    monkeypatch.setattr(delivery_log, "prune", tracked("delivery log"))
    monkeypatch.setattr(lock_store, "prune", tracked("auth locks"))
    purged: list[str] = []
    monkeypatch.setattr(bruteforce, "purge", lambda: purged.append("bruteforce"))
    monkeypatch.setattr(passkeys_api, "purge", lambda: purged.append("passkeys"))
    out = await main.FetchLoop()._prune()
    assert out["news"] is None and out["source health"] == 0
    assert ran == ["audit", "delivery log", "auth locks"]
    assert purged == ["bruteforce", "passkeys"]


async def test_vendor_daily_prunes_each_on_its_own_and_a_failure_is_retried_within_the_hour(monkeypatch):
    calls: list[str] = []

    async def broken(s, now=None):  # noqa: ANN001, ANN202
        calls.append("lookups")
        await s.execute(text("SELECT 1/0"))

    async def changes(s, now=None):  # noqa: ANN001, ANN202
        calls.append("changes")
        return 0

    async def scores(s):  # noqa: ANN001, ANN202
        calls.append("epss")
        return 0

    monkeypatch.setattr(vendor, "prune_lookups", broken)
    monkeypatch.setattr(ch, "prune", changes)
    monkeypatch.setattr(epss, "_prune", scores)
    t = datetime.now(UTC)
    async with db.session() as s:
        out = await vendor.daily_prunes(s, t)
        assert out == {"single lookups": None, "advisory revisions": 0, "epss": 0}
        assert await vendor.daily_prunes(s, t + timedelta(minutes=30)) == {}  # not yet
        assert (await vendor.daily_prunes(s, t + timedelta(minutes=61)))["single lookups"] is None  # an hour later, not a day
        monkeypatch.setattr(vendor, "prune_lookups", changes)
        assert (await vendor.daily_prunes(s, t + timedelta(minutes=122)))["single lookups"] == 0
        assert await vendor.daily_prunes(s, t + timedelta(hours=5)) == {}  # all done: the next in a day
    assert calls.count("epss") == 3


async def test_vendor_daily_prunes_run_with_vendor_news_switched_off(monkeypatch):
    async with db.session() as s:
        await settings_store.put(s, "vendor", {**(await settings_store.get(s, "vendor")), "enabled": False})
        s.add(VendorFetch(key="nvdcve:CVE-2020-0001", failures=0, items=0, last_fetch_at=NOW - timedelta(days=40)))
        s.add(EpssScore(cve="CVE-2020-0001", score=0.1, percentile=0.5, day="2026-01-01", fetched_at=NOW - timedelta(days=40)))
        await s.commit()

    async def nothing(**kw):  # noqa: ANN003, ANN202
        return {}

    monkeypatch.setattr(vendor, "run_round", nothing)
    await vendor.VendorLoop().round()
    async with db.session() as s:
        assert await s.get(VendorFetch, "nvdcve:CVE-2020-0001") is None
        assert await s.get(EpssScore, "CVE-2020-0001") is None


# ---------------------------------------------------------------- revision numbers after an advisory went (L4)


def _pan(**kw) -> dict:
    a = {
        "id": "paloalto:CVE-2026-1001",
        "source": "paloalto",
        "ident": "CVE-2026-1001",
        "title": "PAN-OS: Example vulnerability",
        "summary": "Example.",
        "url": "https://security.paloaltonetworks.com/CVE-2026-1001",
        "cves": ["CVE-2026-1001"],
        "cvss": 7.5,
        "severity": "high",
        "published_at": NOW - timedelta(days=90),
        "updated_at": NOW - timedelta(days=60),
        "names": ["PAN-OS", "PAN-OS 11.2"],
        "data": {"lines": [{"name": "PAN-OS 11.2", "affected": "< 11.2.4-h10", "fixed": ">= 11.2.4-h10"}], "affected_list": [], "products": ["PAN-OS"], "solution": "Upgrade."},
    }
    return a | kw


async def _store(a: dict) -> None:
    async with db.session() as s:
        await vendor.store(s, [a], vendor.build_index())


async def test_an_advisory_stored_again_continues_its_revision_numbers(admin_client):
    """Its state goes with the advisory, its revisions and change events stay: stored again it counted from 1 again – a
    revision number twice and the change event's key taken, so the change was never sent."""
    r = await admin_client.put("/api/vendor/follows/panos", json={"enabled": True})
    assert r.status_code == 200, r.text
    async with db.session() as s:
        await s.execute(update(VendorFollow).where(VendorFollow.product == "panos").values(baseline_at=NOW))
        await s.commit()
    await _store(_pan())
    await _store(_pan(cvss=9.3, severity="critical", updated_at=NOW))  # revision 2
    async with db.session() as s:
        await vendor.drop_advisories(s, ["paloalto:CVE-2026-1001"])  # revision 3: withdrawn – the record goes
    await _store(_pan(cvss=9.3, severity="critical", updated_at=NOW))  # back: no comparison yet
    await _store(_pan(cvss=9.8, severity="critical", updated_at=NOW + timedelta(hours=1)))  # a change again
    async with db.session() as s:
        revs = list(await s.scalars(select(VendorAdvisoryChange.revision).where(VendorAdvisoryChange.advisory_id == "paloalto:CVE-2026-1001").order_by(VendorAdvisoryChange.id)))
        events = list(await s.scalars(select(VendorEvent.data["revision"].as_integer()).where(VendorEvent.kind == "change").order_by(VendorEvent.n)))
    assert revs == [2, 3, 4]
    assert events == [2, 3, 4]  # the last change has its event – it is sent


async def test_next_revision():
    async with db.session() as s:
        assert await ch.next_revision(s, "nvd:CVE-1", 2) == 2
        s.add(VendorAdvisoryChange(advisory_id="nvd:CVE-1", source="nvd", revision=5, at=NOW))
        await s.flush()
        assert await ch.next_revision(s, "nvd:CVE-1", 2) == 6
        assert await ch.next_revision(s, "nvd:CVE-1", 9) == 9


# ---------------------------------------------------------------- batched prunes (L6) and the ones not tested before


async def test_advisory_changes_and_watch_events_are_pruned_in_batches(monkeypatch):
    from app import cve_watch

    monkeypatch.setattr(db, "PRUNE_BATCH", 2)
    old = NOW - timedelta(days=400)
    async with db.session() as s:
        for i in range(5):
            s.add(VendorAdvisoryChange(advisory_id=f"nvd:CVE-{i}", source="nvd", revision=2, at=old))
            s.add(VendorEvent(key=f"change:p:{i}", kind="change", product="p", created_at=old))
            s.add(VendorEvent(key=f"watch:{i}", kind="watch", product="", created_at=old))
        s.add(VendorEvent(key="change:p:new", kind="change", product="p", created_at=NOW))
        await s.commit()
        assert await ch.prune(s) == 10
        assert await cve_watch.prune(s) == 5
        assert await s.scalar(select(func.count()).select_from(VendorEvent)) == 1


async def test_weekly_prune_keeps_open_and_recent_sends():
    u = await add_user("weekly-reader")
    async with db.session() as s:
        team = Team(name="Netz")
        s.add(team)
        await s.flush()
        for week, status, age in (("2026-W01", "sent", 100), ("2026-W02", "failed", 100), ("2026-W03", "pending", 100), ("2026-W40", "sent", 10)):
            s.add(TeamWeeklySend(team_id=team.id, user_id=u.id, week=week, status=status, created_at=NOW - timedelta(days=age)))
        await s.commit()
        assert await weekly.prune(s) == 2
        assert sorted(await s.scalars(select(TeamWeeklySend.week))) == ["2026-W03", "2026-W40"]


async def test_personal_prune_keeps_open_and_recent_deliveries():
    u = await add_user("personal-reader")
    old = NOW - timedelta(days=100)
    async with db.session() as s:
        evs = [VendorEvent(key=f"vuln:p:{i}", kind="vuln", product="p", created_at=old) for i in range(5)]
        s.add_all(evs)
        await s.flush()
        for ev, status, at in zip(evs, ("sent", "skipped", "failed", "pending", "sent"), (old, old, old, old, NOW), strict=True):
            s.add(PersonDelivery(event_id=ev.id, user_id=u.id, way="email", status=status, created_at=at))
        s.add(PersonAbsence(user_id=u.id, deputy_id=u.id, starts_at=old, ends_at=old + timedelta(days=1)))
        s.add(PersonAbsence(user_id=u.id, deputy_id=u.id, starts_at=NOW, ends_at=NOW + timedelta(days=1)))
        await s.commit()
        assert await personal.prune(s) == 3
        assert sorted(await s.scalars(select(PersonDelivery.status))) == ["pending", "sent"]
        assert await s.scalar(select(func.count()).select_from(PersonAbsence)) == 1


async def test_epss_prune_removes_scores_not_asked_for_a_month():
    async with db.session() as s:
        s.add(EpssScore(cve="CVE-2020-1", day="", fetched_at=NOW - timedelta(days=31)))
        s.add(EpssScore(cve="CVE-2020-2", day="", fetched_at=NOW - timedelta(days=29)))
        await s.commit()
        assert await epss._prune(s) == 1
        assert list(await s.scalars(select(EpssScore.cve))) == ["CVE-2020-2"]


async def test_sessions_cleanup_removes_expired_ones():
    u = await add_user("session-reader")
    async with db.session() as s:
        for i, ends in enumerate((NOW - timedelta(minutes=1), NOW + timedelta(hours=1))):
            s.add(UserSession(token_hash=f"h{i}", user_id=u.id, stage="active", expires_at=ends))
        await s.commit()
        assert await sessions.cleanup(s) == 1
        assert list(await s.scalars(select(UserSession.token_hash))) == ["h1"]


def test_backup_sweep_removes_only_old_leftovers():
    cfg = get_config()
    work = cfg.data_dir / ".backup-work"
    work.mkdir(parents=True, exist_ok=True)
    cfg.backup_dir.mkdir(parents=True, exist_ok=True)
    old, fresh = work / ".partial-old", work / ".partial-fresh"
    old.mkdir()
    fresh.mkdir()
    half = cfg.backup_dir / "cobe-news-20260101-000000.tar.partial"
    kept = cfg.backup_dir / "cobe-news-20260101-000000.tar"
    half.write_bytes(b"x")
    kept.write_bytes(b"x")
    long_ago = time.time() - backup.STALE_S - 60
    for p in (old, half, kept):
        os.utime(p, (long_ago, long_ago))
    gone = backup.sweep()
    assert sorted(gone) == sorted([".partial-old", half.name])
    assert fresh.exists() and kept.exists() and not old.exists() and not half.exists()
    kept.unlink()
    fresh.rmdir()


def test_passkey_purge_drops_expired_challenges():
    passkeys_api.reset()
    t = time.monotonic()
    passkeys_api._login["old"] = passkeys_api._Pending(challenge=b"a", expires=t - 1)
    passkeys_api._login["new"] = passkeys_api._Pending(challenge=b"b", expires=t + 300)
    passkeys_api._register[uuid.uuid4()] = passkeys_api._Pending(challenge=b"c", expires=t - 1)
    passkeys_api._starts["10.0.0.1"] = [t - passkeys_api.WINDOW - 1]
    passkeys_api.purge()
    assert list(passkeys_api._login) == ["new"] and passkeys_api._register == {} and passkeys_api._starts == {}
    passkeys_api.reset()
