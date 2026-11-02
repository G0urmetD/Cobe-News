"""The rule's dry run (Probelauf): the same matcher as the live round (what the round sent equals what the dry run finds),
nothing sent and nothing written, the window, the estimate of messages a day and the flood warning, admins only."""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import func, select, text, update
from test_notify import SLACK, Hooks, _channel, _dispatch, _rule, _source, _stories

from app import db, news, notify, notify_api
from app.models import NewsItem, NewsSource, NotifyDelivery, SourceHealthEvent, VendorDelivery, VendorEvent


@pytest.fixture
def hooks(monkeypatch):
    h = Hooks()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(h.handler))
    return h


async def _other_source() -> NewsSource:
    async with db.session() as s:
        src = NewsSource(key="feed-y", name="Other Feed", url="https://news.example.org/y.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.commit()
        return src


async def _event(kind: str, severity: str, product: str = "example-gw", **data) -> VendorEvent:
    async with db.session() as s:
        ev = VendorEvent(key=f"{kind}:{product}:{uuid.uuid4()}", kind=kind, product=product, severity=severity, data={"product": product, "ident": "CVE-2026-0002", "version": "1.0", **data}, baseline=False)
        s.add(ev)
        await s.commit()
        return ev


async def _dry(c, **body) -> dict:
    notify_api._dry_at.clear()  # one dry run a second per admin – the tests ask faster
    r = await c.post("/api/admin/notify/rules/dry-run", json={"kinds": ["news"], **body})
    assert r.status_code == 200, r.text
    return r.json()


async def _counts() -> dict:
    async with db.session() as s:
        out = {}
        for t in ("notify_deliveries", "vendor_deliveries", "source_health_deliveries", "delivery_log", "notify_channels", "notify_rules", "notify_rule_channels"):
            out[t] = await s.scalar(text(f"SELECT count(*) FROM {t}"))
        out["channels"] = [tuple(r) for r in (await s.execute(text("SELECT id, failures, next_try_at, last_error, last_sent_at, version FROM notify_channels ORDER BY id"))).all()]
        out["rules"] = [tuple(r) for r in (await s.execute(text("SELECT id, active_since, earlier::text, version FROM notify_rules ORDER BY id"))).all()]
        return out


async def test_live_round_and_dry_run_agree(admin_client, hooks):
    """The same rule: what the round sends (a channel linked before everything arrived) is exactly what the dry run finds."""
    a = await _source()
    b = await _other_source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    body = {"severities": ["critical", "high"], "sources": [str(a.id)], "kinds": ["news", "vendor_vuln", "vendor_version", "source_health"], "lang": "de"}
    await _rule(admin_client, "Probe", [slack["id"]], **body)
    await _stories(a, "critical", "high", "medium", "low")
    await _stories(b, "critical", "high")  # another source: not chosen
    async with db.session() as s:  # a backlog story (a source switched on later): never sent
        await s.execute(update(NewsItem).where(NewsItem.severity == "high", NewsItem.source_id == a.id).values(backlog=True))
        await s.commit()
    await _stories(a, "high")
    v1 = await _event("vuln", "critical")
    await _event("vuln", "low")  # below the severities
    v3 = await _event("version", "info", latest="1.1", line="1")  # versions: not filtered by severity
    await _event("change", "critical")  # vendor_change not chosen
    async with db.session() as s:
        h = SourceHealthEvent(kind="news", key="feed-x", name="Example Feed", state="dead", prev="healthy", reasons=["blocked"], notify=True)
        s.add(h)
        s.add(SourceHealthEvent(kind="news", key="feed-y", name="Other", state="slow", prev="healthy", reasons=[], notify=False))
        await s.commit()
    await _dispatch()
    async with db.session() as s:
        sent = {str(x) for x in await s.scalars(select(NotifyDelivery.item_id))} | {str(x) for x in await s.scalars(select(VendorDelivery.event_id))}
        sent |= {str(x) for x in await s.scalars(text("SELECT event_id FROM source_health_deliveries"))}
    dry = await _dry(admin_client, **body, days=1)
    found = {x["id"] for x in dry["items"]}
    assert found == sent and dry["count"] == len(sent)
    assert {str(v1.id), str(v3.id), str(h.id)} <= found and len([x for x in dry["items"] if x["kind"] == "news"]) == 2
    first = next(x for x in dry["items"] if x["kind"] == "news")
    assert first["match"] == {"kind": "news", "severity": True, "source": True, "teams": False} and first["source"] == "Example Feed"


async def test_dry_run_sends_nothing_and_writes_nothing(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    await _stories(src, "critical", "high")
    before = await _counts()
    dry = await _dry(admin_client, severities=[], kinds=["news", "vendor_vuln", "source_health"], days=30)
    assert dry["count"] == 2
    assert hooks.calls == [] and await _counts() == before
    # and the round afterwards still sends both: the dry run left no "sent" mark behind
    assert await _dispatch() == {"Slack": 2}


def test_the_matcher_is_one_function_of_the_rule():
    """The filters take the rule's fields only – no channel, no time: the live round and the dry run share them."""
    from app.models import NotifyRule

    r = NotifyRule(name="x", severities=["critical"], sources=[], kinds=["news", "vendor_version"], lang="de", earlier=[])
    assert len(notify.news_filter(r)) == 3  # not backlog, severity, a visible source
    assert notify.vendor_filter(r, []) is not None and notify.health_filter(r) is None
    assert notify.vendor_filter(NotifyRule(name="x", severities=[], sources=[], kinds=["news"], lang="de", earlier=[]), []) is None
    assert str(notify._teams_clause([]).compile()) == "true"


async def test_window_estimate_and_flood_warning(admin_client):
    src = await _source()
    now = datetime.now(UTC)
    async with db.session() as s:
        # 30 stories, each in a minute of its own, yesterday-ish: 30 single messages that day – a flood
        for n in range(30):
            at = now - timedelta(hours=2, minutes=n * 2)
            s.add(NewsItem(source_id=src.id, url=f"https://news.example.org/f{n}", url_key=f"f{n}", title=f"Flut {n}", title_key=f"tf{n}", summary="", published_at=at, fetched_at=at, severity="high", cves=[], seq=await news.next_seq(s)))
        # 12 stories in the same minute, 3 days ago: one summary
        at = (now - timedelta(days=3)).replace(second=5)
        for n in range(12):
            s.add(NewsItem(source_id=src.id, url=f"https://news.example.org/b{n}", url_key=f"b{n}", title=f"Bündel {n}", title_key=f"tb{n}", summary="", published_at=at, fetched_at=at, severity="high", cves=[], seq=await news.next_seq(s)))
        await s.commit()
    one = await _dry(admin_client, severities=["high"], days=1)
    assert one["count"] == 30 and one["flood"] is True and one["peak_per_day"] >= 21 and one["flood_limit"] == notify.FLOOD_PER_DAY
    week = await _dry(admin_client, severities=["high"], days=7)
    assert week["count"] == 42 and week["messages"] == 31  # 30 single messages + 1 summary
    bundle = next(d for d in week["per_day"] if d["matches"] == 12)
    assert bundle["messages"] == 1
    # another severity: nothing
    assert (await _dry(admin_client, severities=["critical"], days=30))["count"] == 0


async def test_dry_run_lists_at_most_the_limit(admin_client, monkeypatch):
    monkeypatch.setattr(notify, "DRY_LIMIT", 5)
    src = await _source()
    await _stories(src, *["high"] * 8)
    r = await _dry(admin_client, severities=[], days=1)
    assert r["count"] == 8 and len(r["items"]) == 5 and r["truncated"] is True


async def test_dry_run_is_for_admins_and_checks_its_input(admin_client, reader_client):
    assert (await reader_client.post("/api/admin/notify/rules/dry-run", json={"kinds": ["news"]})).status_code == 403
    assert (await admin_client.post("/api/admin/notify/rules/dry-run", json={"kinds": ["news"], "days": 3})).status_code == 422
    assert (await admin_client.post("/api/admin/notify/rules/dry-run", json={"kinds": []})).status_code == 422
    assert (await admin_client.post("/api/admin/notify/rules/dry-run", json={"kinds": ["news"], "channels": []})).status_code == 422
    assert (await admin_client.post("/api/admin/notify/rules/dry-run", json={"kinds": ["news"]})).status_code == 200
    assert (await admin_client.post("/api/admin/notify/rules/dry-run", json={"kinds": ["news"]})).status_code == 429  # throttled


async def test_dry_run_counts_nothing_into_the_database(admin_client):
    """The dry run's transaction is read-only – a write in it would fail."""
    async with db.session() as s:
        from app.models import NotifyRule

        r = NotifyRule(name="x", severities=[], sources=[], kinds=["news"], lang="de", earlier=[])
        await notify.dry_run(s, r, [], 1)
        assert await s.scalar(select(func.count()).select_from(NotifyDelivery)) == 0
