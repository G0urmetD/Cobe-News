"""EOL pre-warnings (app/vendor.py, 0.1.34): per version entered one warning 90 and one 30 days before its support ends,
one when it has ended – each stage once per version and date; a date the vendor moves gives the stage of the new date
only when it is more urgent than what was said (no second message); the first round after the update says only what is
true now (no flood of old ends, no 90 after the 30). They are events of the kind "eol": the rules and the personal ways
with "Versionen & EOL" get them. Release data is set in the test; nothing is fetched."""

from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select

from app import db, notify, personal, vendor
from app import vendor_catalog as catalog
from app.models import NotifyRule, PersonNotify, VendorEvent, VendorFollow, VendorVersion

PAST = datetime.now(UTC) - timedelta(days=30)


def _rel(days: int | None) -> list[dict]:
    eol = (datetime.now(UTC).date() + timedelta(days=days)).isoformat() if days is not None else None
    return [{"name": "11.1", "label": "11.1", "releaseDate": "2023-06-01", "latest": "11.1.4", "eolFrom": eol, "isMaintained": True}]


@pytest.fixture
def eol(monkeypatch):
    """The release line's end of support, `days` from today (set per call)."""
    state = {"rel": _rel(200)}
    monkeypatch.setattr(catalog, "releases", lambda key: state["rel"])

    def set_days(days: int | None) -> None:
        state["rel"] = _rel(days)

    return set_days


async def _setup(*versions: str, baseline: bool = True) -> None:
    async with db.session() as s:
        f = VendorFollow(product="panos", baseline_at=PAST)
        s.add(f)
        await s.flush()
        for v in versions:
            s.add(VendorVersion(follow_id=f.id, version=v, baseline_at=PAST if baseline else None))
        await s.commit()


async def _run() -> int:
    async with db.session() as s:
        f = await s.scalar(select(VendorFollow).where(VendorFollow.product == "panos"))
        vs = list(await s.scalars(select(VendorVersion).where(VendorVersion.follow_id == f.id).order_by(VendorVersion.version)))
        return await vendor._evaluate_product(s, f, catalog.product("panos"), vs, {"findings": []}, datetime.now(UTC))


async def _eol_events() -> list[VendorEvent]:
    async with db.session() as s:
        return list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "eol").order_by(VendorEvent.n)))


def _sent(evs: list[VendorEvent]) -> list[tuple]:
    return [(e.data.get("version"), e.data.get("stage") or e.data.get("eol_state")) for e in evs if not e.baseline]


def test_stage_of_a_date():
    today = date(2026, 10, 30)
    assert vendor.eol_stage("2027-03-01", today) is None  # 122 days
    assert vendor.eol_stage("2027-01-28", today)[0] == "90"  # 90 days
    assert vendor.eol_stage("2026-11-29", today)[0] == "30"  # 30 days
    assert vendor.eol_stage("2026-10-30", today)[0] == "past"  # the day itself: ended (as release_info)
    assert vendor.eol_stage("2026-01-01T00:00:00", today)[0] == "past"
    assert vendor.eol_stage(None, today) is None and vendor.eol_stage("bald", today) is None


async def test_90_30_and_ended_each_once_per_version(eol):
    await _setup("11.1.2", "11.1.3")
    eol(120)  # "Support endet bald" of the line (as before), no stage yet
    await _run()
    assert _sent(await _eol_events()) == [("11.1.2", "soon")]
    eol(85)
    await _run()
    assert _sent(await _eol_events())[1:] == [("11.1.2", "90"), ("11.1.3", "90")]  # per version, not per line
    assert await _run() == 0  # once
    eol(25)
    await _run()
    assert _sent(await _eol_events())[3:] == [("11.1.2", "30"), ("11.1.3", "30")]
    assert await _run() == 0
    eol(0)
    await _run()
    assert _sent(await _eol_events())[5:] == [("11.1.2", "past"), ("11.1.3", "past")]
    assert await _run() == 0
    evs = await _eol_events()
    assert len({e.key for e in evs}) == len(evs) == 7
    e30 = next(e for e in evs if e.data.get("stage") == "30")
    assert e30.severity == "high" and e30.scope == "eol:panos:11.1.2" and e30.data["days"] == 25
    assert next(e for e in evs if e.data.get("stage") == "90").severity == "medium"


async def test_moved_date_no_second_message_and_the_new_stages_come(eol):
    await _setup("11.1.2")
    eol(25)
    await _run()
    assert [s for _v, s in _sent(await _eol_events())] == ["30"]  # the first round: only the stage of now, no 90 before it
    eol(80)  # the vendor extends the support: 90 days before the new date – less urgent than the 30 said: silent
    await _run()
    evs = await _eol_events()
    assert [s for _v, s in _sent(evs)] == ["30"] and evs[-1].baseline and evs[-1].data["stage"] == "90"
    eol(28)  # the new date comes closer: its 30 days are news
    await _run()
    assert [s for _v, s in _sent(await _eol_events())] == ["30", "30"]
    eol(5)  # moved earlier – the same stage of another date: silent
    await _run()
    assert [s for _v, s in _sent(await _eol_events())] == ["30", "30"]
    eol(-1)  # ended: more urgent
    await _run()
    assert [s for _v, s in _sent(await _eol_events())] == ["30", "30", "past"]
    assert await _run() == 0


async def test_first_round_after_the_update_no_flood_of_old_ends(eol):
    await _setup("11.1.2")
    # 0.1.33 said "Support beendet" of the line already (key eol:<product>:<line>:past) – ten days ago
    ended = (datetime.now(UTC).date() - timedelta(days=10)).isoformat()
    async with db.session() as s:
        s.add(VendorEvent(key="eol:panos:11.1:past", kind="eol", product="panos", severity="high", data={"eol_state": "past", "eol_from": ended}, created_at=PAST))
        await s.commit()
    eol(-10)
    await _run()
    assert _sent(await _eol_events()) == [(None, "past")]  # only the 0.1.33 one
    evs = await _eol_events()
    assert [e.data.get("stage") for e in evs if e.data.get("stage")] == ["past"] and evs[-1].baseline  # shown, not sent
    # an end long gone (no 0.1.33 event): not news either
    async with db.session() as s:
        for e in await s.scalars(select(VendorEvent)):
            await s.delete(e)
        await s.commit()
    eol(-200)
    await _run()
    assert [e for e in await _eol_events() if e.data.get("stage") and not e.baseline] == []


async def test_new_version_is_a_baseline(eol):
    await _setup("11.1.2", baseline=False)
    eol(20)
    await _run()
    evs = [e for e in await _eol_events() if e.data.get("stage")]
    assert [e.data["stage"] for e in evs] == ["30"] and evs[0].baseline
    eol(-1)
    await _run()
    assert _sent(await _eol_events()) == [("11.1.2", "past")]  # its baseline is set now: the end is news


async def test_story_rules_and_personal_ways_get_them(eol):
    await _setup("11.1.2")
    eol(25)
    await _run()
    ev = next(e for e in await _eol_events() if e.data.get("stage") == "30")
    s = notify.vendor_story(ev, "de")
    assert s.title.startswith("PAN-OS (Firewalls) 11.1.2: Support endet in 25 Tagen (") and s.kind == "vendor.eol"
    assert "in 25 days" in notify.vendor_story(ev, "en").title
    # an existing rule with "Versionen & EOL" gets it (same kind as "Support endet bald")
    async with db.session() as s:
        rule = NotifyRule(name="r", kinds=["vendor_version"], severities=[], enabled=True, earlier=[])
        s.add(rule)
        await s.flush()
        got = await notify.vendor_pending(s, rule, rule.id, PAST)
        assert ev.id in {e.id for e in got}
        rule.kinds = ["vendor_vuln"]
        assert ev.id not in {e.id for e in await notify.vendor_pending(s, rule, rule.id, PAST)}
        await s.rollback()
    p = PersonNotify(kinds=["vendor_version"], min_severity="critical")
    assert personal.wants(p, "eol", "medium") and not personal.wants(PersonNotify(kinds=["vendor_vuln"], min_severity="info"), "eol", "high")


async def test_removed_version_takes_its_warnings_along(eol):
    await _setup("11.1.2", "11.1.3")
    eol(25)
    await _run()
    async with db.session() as s:
        await s.delete(await s.scalar(select(VendorVersion).where(VendorVersion.version == "11.1.3")))
        await s.commit()
        fs = await vendor.follows(s)
        await vendor.prune_events(s, fs, await vendor.versions_of(s, [f.id for f in fs]))
    assert {e.scope for e in await _eol_events() if e.scope} == {"eol:panos:11.1.2"}
