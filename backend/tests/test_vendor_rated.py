# ruff: noqa: F811 - the fixtures of test_vendor_service are imported and used by name
"""Vendor News, 0.1.53: a vulnerability rated higher after its first event ("now rated higher"). NVD's "awaiting
analysis" (or OSV without a rating) stores the event as info – a rule of "critical, high" filters by that stored
severity and never got it, also when NVD rated it 9.8 a few days later. Now: one event per higher level, silent where a
new one would be, and silent in the first evaluation that knows it (no flood of the rises of before)."""

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select

from app import db, notify, personal, reader, vendor
from app.models import Counter, VendorEvent
from test_vendor_fixes import _nvd
from test_vendor_service import _dispatch, _follow, _round, _webhook_rule, hooks, sites, vendor_reset  # noqa: F401 - fixtures

CVE = "CVE-2026-8101"


def _unrated(cve: str = CVE, **kw) -> dict:
    """NVD's record before its analysis: no CVSS, no rating (Vendor News: info)."""
    rec = _nvd(cve, **kw)
    return rec | {"severity": "info", "cvss": None, "data": {**rec["data"], "status": "Awaiting Analysis"}}


def _rated(rec: dict, severity: str, cvss: float, minutes: int = 5) -> dict:
    return rec | {"severity": severity, "cvss": cvss, "updated_at": rec["updated_at"] + timedelta(minutes=minutes), "data": {**rec["data"], "status": "Analyzed"}}


async def _vulns(s) -> list[VendorEvent]:
    """The vulnerability events of the CVEs of these tests (not the baseline of the fixtures' advisories)."""
    evs = await s.scalars(select(VendorEvent).where(VendorEvent.kind == "vuln").order_by(VendorEvent.n))
    return [e for e in evs if "CVE-2026-81" in e.key]


async def test_a_finding_rated_higher_later_reaches_a_rule_of_critical_and_high(admin_client, sites, hooks):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _webhook_rule(admin_client, ["vendor_vuln"], ["critical", "high"])
    await _round()  # the baseline
    rec = _unrated()
    async with db.session() as s:
        await vendor.store(s, [rec], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1  # the finding – as info
    await _dispatch()
    assert hooks == []  # not of the rule's severities
    async with db.session() as s:
        await vendor.store(s, [_rated(rec, "critical", 9.8)], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1  # used to be 0: the CVE was known – and never came
        assert await vendor.evaluate_events(s, full=True) == 0  # once
        evs = await _vulns(s)
    assert [e.severity for e in evs] == ["info", "critical"] and not evs[1].baseline
    ev = evs[1]
    assert ev.key == f"rated:critical:vuln:panos:11.2.4-h23:nvd:{CVE}" and ev.data["rated_higher"] == {"from": "info", "to": "critical"}
    await _dispatch()
    assert len(hooks) == 1
    (story,) = json.loads(hooks[0].content)["stories"]
    assert story["title"].startswith("Jetzt höher eingestuft: Kritisch (vorher Info): PAN-OS") and CVE in story["title"] and story["severity"] == "critical"
    assert notify.vendor_story(ev, "en").title.startswith("Now rated higher: Critical (was Info): PAN-OS")
    # the finding it is about: Vendor News' read state and the links of the personal ways
    assert reader.finding_of(ev.key, ev.scope) == f"nvd:{CVE}"
    assert personal.event_path(ev) == f"/vendor?product=panos&finding=nvd%3A{CVE}"
    await _dispatch()
    assert len(hooks) == 1


async def test_only_upward_once_per_level_and_silent_when_not_fresh(admin_client, sites):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    rec = _unrated()
    old = _unrated("CVE-2026-8102", age_h=24 * 60)  # published two months ago: shown, not notified
    async with db.session() as s:
        await vendor.store(s, [rec, old], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1  # the old one is silent anyway
        await vendor.store(s, [_rated(rec, "high", 7.5), _rated(old, "critical", 9.8)], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1  # info → high; the old one's rise is silent (not fresh)
        await vendor.store(s, [_rated(rec, "critical", 9.1, minutes=10)], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1  # high → critical: the next level, once more
        await vendor.store(s, [_rated(rec, "medium", 5.0, minutes=15)], vendor.build_index())
        assert await vendor.evaluate_events(s) == 0  # rated lower again: nothing (only upward)
        await vendor.store(s, [_rated(rec, "critical", 9.8, minutes=20)], vendor.build_index())
        assert await vendor.evaluate_events(s, full=True) == 0  # critical again: said already
        evs = await _vulns(s)
    mine = [(e.severity, e.baseline, (e.data.get("rated_higher") or {}).get("from")) for e in evs if CVE in e.key]
    assert mine == [("info", False, None), ("high", False, "info"), ("critical", False, "high")]
    theirs = [(e.severity, e.baseline) for e in evs if "CVE-2026-8102" in e.key]
    assert theirs == [("info", True), ("critical", True)]


async def test_the_first_evaluation_that_knows_it_only_notes_the_ratings(admin_client, sites):
    """The update to 0.1.53: findings rated higher before it are no news – no flood of them in the first round."""
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    rec = _unrated()
    async with db.session() as s:
        await vendor.store(s, [rec], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1
        await vendor.store(s, [_rated(rec, "critical", 9.8)], vendor.build_index())
        # as after the update: the rises are not noted yet
        await s.execute(delete(Counter).where(Counter.name.like(f"{vendor.RATED_PRIMED}:%")))
        await s.commit()
    vendor.reset()  # a new process
    async with db.session() as s:
        assert await vendor.evaluate_events(s) == 0
        evs = await _vulns(s)
        assert [(e.severity, e.baseline) for e in evs] == [("info", False), ("critical", True)]
        assert await s.scalar(select(Counter.value).where(Counter.name == f"{vendor.RATED_PRIMED}:panos")) == 1
        # from then on a rise is news again
        rec2 = _unrated("CVE-2026-8103")
        await vendor.store(s, [rec2], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1
        await vendor.store(s, [_rated(rec2, "high", 8.1)], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1


async def test_a_product_not_ready_in_the_first_evaluation_is_primed_when_it_is(admin_client, sites, monkeypatch):
    """Priming is per product: one whose sources had not answered yet (or held for a keyword search) when the others
    were primed is primed at its own first evaluation – its rises of before the update are no flood later."""
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    rec = _unrated()
    async with db.session() as s:
        await vendor.store(s, [rec], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1
        await vendor.store(s, [_rated(rec, "critical", 9.8)], vendor.build_index())  # rated higher before the update
        await s.execute(delete(Counter).where(Counter.name.like(f"{vendor.RATED_PRIMED}:%")))
        await s.commit()
    vendor.reset()  # a new process – and PAN-OS not ready in its first round
    real = vendor._ready
    monkeypatch.setattr(vendor, "_ready", lambda p, answered: p["key"] != "panos" and real(p, answered))
    async with db.session() as s:
        assert await vendor.evaluate_events(s) == 0
        assert await s.scalar(select(Counter.value).where(Counter.name == f"{vendor.RATED_PRIMED}:panos")) is None
    monkeypatch.setattr(vendor, "_ready", real)  # ready now: noted, not sent (used to come as "now rated higher")
    async with db.session() as s:
        assert await vendor.evaluate_events(s) == 0
        evs = await _vulns(s)
        assert [(e.severity, e.baseline) for e in evs] == [("info", False), ("critical", True)]
        assert await s.scalar(select(Counter.value).where(Counter.name == f"{vendor.RATED_PRIMED}:panos")) == 1


async def test_events_are_stamped_when_their_product_is_written(admin_client, sites, monkeypatch):
    """Not with the round's start: a rule switched on while the round worked on other products took an event stamped
    earlier as "before me" and never sent it (notify.vendor_pending: created after the rule)."""
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    async with db.session() as s:
        await vendor.store(s, [_nvd("CVE-2026-8104")], vendor.build_index())
    real = vendor._evaluate_product
    started: list[datetime] = []

    async def slow(db_, f, p, vs, view, now, **kw):  # noqa: ANN001, ANN003
        started.append(now)
        return await real(db_, f, p, vs, view, now - timedelta(minutes=5), **kw)  # as if the round began 5 minutes ago

    monkeypatch.setattr(vendor, "_evaluate_product", slow)
    async with db.session() as s:
        assert await vendor.evaluate_events(s) == 1
        (ev,) = [e for e in await _vulns(s) if not e.baseline]
    assert ev.created_at >= started[0] - timedelta(seconds=1)
    assert ev.created_at <= datetime.now(UTC)
