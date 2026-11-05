# ruff: noqa: F811 - the fixtures of test_personal (mails, web) are imported and used by name
"""Quiet hours, urgent, collected delivery (app/quiet.py) and absence with a deputy (app/absence.py) on top of the
personal notifications (app/personal.py): the time windows in the person's zone across the summer time changes, urgent
passes at once, what waited goes out as one digest when the quiet hours end, a held person takes no place in a bounded
round; the deputy gets an absent person's product news exactly once per way (also when getting the product anyway),
never a watched CVE, no chains, nothing old and nothing again when the absence ends; only the own settings and a deputy
from the own teams. Nothing leaves the machine; the clock is frozen where a test needs a time of day."""

from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from conftest import make_client, sign_in
from sqlalchemy import func, select, update
from test_personal import HOUR, _dispatch, _event, _person, _rows, _subscribe, _switch, _team, _ways, mails, web  # noqa: F401

from app import absence, cve_watch, db, personal, quiet
from app.models import CveWatch, PersonAbsence, PersonNotify, VendorEvent

BERLIN = ZoneInfo("Europe/Berlin")
NIGHT = {"quiet": True, "from": "18:00", "to": "08:00", "weekends": False, "tz": "Europe/Berlin"}


def utc(*a) -> datetime:  # noqa: ANN002
    return datetime(*a, tzinfo=UTC)


def freeze(monkeypatch, module, at: datetime) -> None:  # noqa: ANN001
    """`module`'s clock stands at `at` (its datetime.now) – the rest of the test keeps the real one."""

    class Frozen(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ANN001, ANN206
            return at if tz else at.replace(tzinfo=None)

    monkeypatch.setattr(module, "datetime", Frozen)


async def _schedule(u, **s) -> None:  # noqa: ANN001, ANN003
    async with db.session() as x:
        await x.execute(update(PersonNotify).where(PersonNotify.user_id == u.id).values(schedule=quiet.clean(s)))
        await x.commit()


# ---------------------------------------------------------------- the windows (pure)


@pytest.mark.parametrize(
    ("at", "want"),
    [
        # spring forward (29 March 2026, 02:00 CET → 03:00 CEST): 08:00 local is 06:00 UTC that morning, 07:00 the day before
        (utc(2026, 3, 28, 6, 59), True),
        (utc(2026, 3, 28, 7, 0), False),
        (utc(2026, 3, 29, 5, 59), True),
        (utc(2026, 3, 29, 6, 0), False),
        (utc(2026, 3, 29, 15, 59), False),  # 17:59 CEST
        (utc(2026, 3, 29, 16, 0), True),  # 18:00 CEST
        # fall back (25 October 2026, 03:00 CEST → 02:00 CET): the other way round
        (utc(2026, 10, 24, 5, 59), True),
        (utc(2026, 10, 24, 6, 0), False),
        (utc(2026, 10, 25, 6, 59), True),
        (utc(2026, 10, 25, 7, 0), False),
        (utc(2026, 10, 25, 16, 59), False),  # 17:59 CET
        (utc(2026, 10, 25, 17, 0), True),
    ],
)
def test_quiet_window_follows_the_local_clock_across_summer_time(at, want):
    assert quiet.is_quiet(NIGHT, at) is want


def test_quiet_window_inside_the_hour_that_is_skipped_or_doubled():
    s = {**NIGHT, "from": "01:00", "to": "03:00"}
    assert quiet.is_quiet(s, utc(2026, 3, 29, 0, 30))  # 01:30 CET
    assert not quiet.is_quiet(s, utc(2026, 3, 29, 1, 0))  # 03:00 CEST – the gap is passed, the window over
    assert quiet.is_quiet(s, utc(2026, 10, 25, 0, 30))  # 02:30 CEST
    assert quiet.is_quiet(s, utc(2026, 10, 25, 1, 30))  # 02:30 CET – the hour that comes twice is quiet twice
    assert not quiet.is_quiet(s, utc(2026, 10, 25, 2, 0))  # 03:00 CET


def test_weekends_and_off_and_other_zones():
    s = {**NIGHT, "weekends": True}
    assert quiet.is_quiet(s, datetime(2026, 10, 31, 12, 0, tzinfo=BERLIN))  # Saturday noon
    assert quiet.is_quiet(s, datetime(2026, 11, 1, 23, 0, tzinfo=BERLIN))  # Sunday night
    assert not quiet.is_quiet(s, datetime(2026, 10, 30, 12, 0, tzinfo=BERLIN))  # Friday noon
    assert quiet.is_quiet(s, datetime(2026, 10, 30, 18, 30, tzinfo=BERLIN))  # Friday evening (the window)
    assert not quiet.is_quiet(s, datetime(2026, 11, 2, 8, 0, tzinfo=BERLIN))  # Monday 08:00 – over
    assert not quiet.is_quiet({**NIGHT, "quiet": False}, datetime(2026, 10, 30, 23, 0, tzinfo=BERLIN))
    assert not quiet.is_quiet({}, datetime(2026, 10, 30, 23, 0, tzinfo=BERLIN))
    ny = {**NIGHT, "tz": "America/New_York"}
    assert not quiet.is_quiet(ny, utc(2026, 10, 30, 21, 0))  # 17:00 in New York
    assert quiet.is_quiet(ny, utc(2026, 10, 30, 23, 0))  # 19:00 there
    assert quiet.zone("Not/AZone").key == "Europe/Berlin" and not quiet.valid_tz("Not/AZone") and quiet.valid_tz("Europe/Vienna")


def test_collecting_time_once_a_day_across_summer_time():
    # 02:30 does not exist on 29 March 2026: the first moment after the gap (03:30 CEST = 01:30 UTC), once
    assert quiet.last_slot("02:30", "Europe/Berlin", utc(2026, 3, 29, 1, 29)) == utc(2026, 3, 28, 1, 30)
    assert quiet.last_slot("02:30", "Europe/Berlin", utc(2026, 3, 29, 1, 30)) == utc(2026, 3, 29, 1, 30)
    # 02:30 exists twice on 25 October 2026: the first one only – no second digest an hour later
    assert quiet.last_slot("02:30", "Europe/Berlin", utc(2026, 10, 25, 0, 30)) == utc(2026, 10, 25, 0, 30)
    assert quiet.last_slot("02:30", "Europe/Berlin", utc(2026, 10, 25, 1, 45)) == utc(2026, 10, 25, 0, 30)
    # 08:00 every day, whatever the offset
    assert quiet.last_slot("08:00", "Europe/Berlin", utc(2026, 3, 29, 6, 0)) == utc(2026, 3, 29, 6, 0)
    assert quiet.last_slot("08:00", "Europe/Berlin", utc(2026, 3, 28, 7, 0)) == utc(2026, 3, 28, 7, 0)
    # the weekly time and its ISO week
    assert quiet.last_weekly(0, "08:00", "Europe/Berlin", utc(2026, 11, 2, 7, 0)) == utc(2026, 11, 2, 7, 0)
    assert quiet.last_weekly(0, "08:00", "Europe/Berlin", utc(2026, 11, 2, 6, 59)) == utc(2026, 10, 26, 7, 0)
    assert quiet.week_of(utc(2026, 11, 2, 7, 0), "Europe/Berlin") == "2026-W45"


def test_marks_of_events():
    b = quiet.BITS
    assert quiet.marks_of("vuln", "critical", {}) == b["critical"]
    assert quiet.marks_of("vuln", "high", {"exploited": True}) == b["kev"]
    assert quiet.marks_of("vuln", "high", {}) == 0
    assert quiet.marks_of("watch", "high", {"what": "fix"}) == b["watch"]
    assert quiet.marks_of("watch", "high", {"what": "kev"}) == b["watch"] | b["kev"]
    assert quiet.marks_of("change", "medium", {"diff": [{"f": "kev", "cve": "CVE-2026-1"}]}) == b["kev"]
    assert quiet.marks_of("change", "high", {"impact": [{"product": "panos", "from": "possible", "to": "affected"}]}) == b["affected"]
    assert quiet.marks_of("change", "high", {"impact": [{"product": "panos", "from": "affected", "to": "not_affected"}]}) == 0
    assert quiet.marks_of("version", "low", {}) == 0
    assert quiet.mask({}) == 15 and quiet.mask({"urgent": ["critical"]}) == 1 and quiet.mask({"urgent": []}) == 0


# ---------------------------------------------------------------- quiet hours in the round


def _next_local(hour: int, minute: int = 0, after: datetime | None = None) -> datetime:
    """The next local hh:mm (Berlin) after now, as UTC – a time of day the test freezes the round at."""
    base = (after or datetime.now(UTC)).astimezone(BERLIN)
    at = base.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if at <= base:
        at = (base + timedelta(days=1)).replace(hour=hour, minute=minute, second=0, microsecond=0)
    return at.astimezone(UTC)


async def test_quiet_hours_hold_normal_urgent_passes_and_one_digest_at_the_end(mails, web, monkeypatch):
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True, desktop=True)
    await _subscribe(a)
    await _schedule(a, **NIGHT)
    night = _next_local(23)
    freeze(monkeypatch, personal, night)
    for k in range(3):
        await _event("panos", severity="medium", title=f"Normal {k}")
    await _event("panos", kind="version", severity="low")
    crit = await _event("panos", severity="critical", title="Dringend")
    assert await _dispatch() == {"sent": 2}  # the critical one at once, by mail and as a push
    assert len(mails.sent) == 1 and "Dringend" in mails.sent[0]["subject"]
    assert len(web.to("fcm.googleapis.com")) == 1  # desktop in the quiet hours: urgent only
    assert {r.status for r in await _rows(event_id=crit)} == {"sent"}
    assert {r.status for r in await _rows() if r.event_id != crit} == {"pending"}
    # later that night: still nothing (and nothing is skipped meanwhile)
    freeze(monkeypatch, personal, night + 3 * HOUR)
    assert await _dispatch() == {}
    # 08:00: the quiet hours end – one digest per way with everything that waited
    freeze(monkeypatch, personal, _next_local(8, 0, after=night))
    assert await _dispatch() == {"sent": 8}
    assert len(mails.sent) == 2 and "4 neue" in mails.sent[1]["subject"]
    assert len(web.to("fcm.googleapis.com")) == 2
    assert {r.status for r in await _rows()} == {"sent"}
    await _dispatch()
    assert len(mails.sent) == 2  # exactly once


async def test_urgent_is_the_persons_choice(mails, monkeypatch):
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True)
    await _schedule(a, **NIGHT, urgent=["affected"])  # critical is not urgent for this person
    freeze(monkeypatch, personal, _next_local(2))
    await _event("panos", severity="critical")
    async with db.session() as s:
        s.add(VendorEvent(key="change:panos:x:1", kind="change", product="panos", severity="high", data={"product": "PAN-OS", "ident": "PAN-SA-1", "impact": [{"product": "panos", "from": None, "to": "affected"}], "diff": []}))
        await s.commit()
    await _ways(a, email=True, kinds=list(personal.KINDS))
    await _dispatch()
    assert len(mails.sent) == 1 and "PAN-SA-1" in mails.sent[0]["subject"]  # only the change that makes a version affected


def _next_spring_forward() -> date:
    """The next last Sunday of March (Europe/Berlin: 02:00 CET → 03:00 CEST) whose morning is still ahead – the event
    of the test must come after the team, the ways and the switch (an hour or two before the real now)."""
    now = datetime.now(UTC)
    for year in (now.year, now.year + 1):
        day = date(year, 3, 31)
        day -= timedelta(days=(day.weekday() - 6) % 7)
        if utc(day.year, day.month, day.day, 5, 0) > now:
            return day
    raise AssertionError("unreachable")


async def test_summer_time_end_of_the_quiet_hours_in_the_round(mails, monkeypatch):
    """The next spring forward (28 March 2027 when written): 08:00 local is 06:00 UTC – not 07:00 as the day before."""
    d = _next_spring_forward()
    assert datetime(d.year, d.month, d.day, 8, tzinfo=BERLIN).utcoffset() == timedelta(hours=2) != datetime(d.year, d.month, d.day - 1, 8, tzinfo=BERLIN).utcoffset()
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True)
    await _schedule(a, **NIGHT)
    await _event("panos", at=utc(d.year, d.month, d.day, 5, 0))
    freeze(monkeypatch, personal, utc(d.year, d.month, d.day, 5, 59))  # 07:59 CEST
    await _dispatch()
    assert mails.sent == []
    freeze(monkeypatch, personal, utc(d.year, d.month, d.day, 6, 0))  # 08:00 CEST
    await _dispatch()
    assert len(mails.sent) == 1


async def test_collected_at_a_time_per_way(mails, web, monkeypatch):
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True, teams_=True)
    await _schedule(a, quiet=False, tz="Europe/Berlin", daily={"email": "08:00"})  # Teams stays "at once"
    noon = _next_local(12)
    freeze(monkeypatch, personal, noon)
    await _event("panos", severity="high")
    await _event("panos", severity="medium")
    await _dispatch()
    assert mails.sent == [] and len(web.to("logic.azure.com")) == 1
    freeze(monkeypatch, personal, _next_local(7, 59, after=noon))
    await _dispatch()
    assert mails.sent == []
    freeze(monkeypatch, personal, _next_local(8, 1, after=noon))
    await _dispatch()
    assert len(mails.sent) == 1 and "2 neue" in mails.sent[0]["subject"]
    # what is queued after 08:00 waits for the next day's 08:00
    await _event("panos")
    await _dispatch()
    assert len(mails.sent) == 1


async def test_held_people_take_no_place_in_a_bounded_round(mails, monkeypatch):
    monkeypatch.setattr(personal, "ROUND_JOBS", 1)
    await _switch()
    a, b = await _person("anja"), await _person("bert")
    await _team([a, b])
    await _ways(a, email=True)
    await _ways(b, email=True)
    await _schedule(a, **NIGHT)
    freeze(monkeypatch, personal, _next_local(23))
    await _event("panos")
    personal.reset()
    assert await _dispatch() == {"sent": 1}
    assert [m["to"][0] for m in mails.sent] == ["bert@corp.example"]  # anja's held row did not take the one place
    assert not personal.backlog()


async def test_no_schedule_is_exactly_as_before(mails, monkeypatch):
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True)
    freeze(monkeypatch, personal, _next_local(23))
    await _event("panos", severity="low")
    await _dispatch()
    assert len(mails.sent) == 1
    async with db.session() as s:
        assert (await s.get(PersonNotify, a.id)).schedule == {}


# ---------------------------------------------------------------- the own schedule (API)


async def _client(u):  # noqa: ANN001, ANN202
    c = make_client()
    await sign_in(c, u)
    return c


async def test_schedule_api_own_only_and_checked():
    await _switch()
    a, b = await _person("anja"), await _person("bert")
    await _team([a, b])
    async with await _client(a) as c:
        me = (await c.get("/api/me/vendor-notify")).json()
        assert me["schedule"] == {"quiet": False, "from": "18:00", "to": "08:00", "weekends": False, "tz": "Europe/Berlin", "urgent": list(quiet.URGENT), "daily": {"email": None, "desktop": None, "teams": None}}
        body = {"quiet": True, "from": "19:00", "to": "07:30", "weekends": True, "tz": "Europe/Vienna", "urgent": ["critical", "watch"], "daily": {"email": "08:15"}}
        r = await c.put("/api/me/vendor-notify/schedule", json=body)
        assert r.status_code == 200, r.text
        assert r.json()["schedule"] == {**body, "daily": {"email": "08:15", "desktop": None, "teams": None}}
        for bad in ({"tz": "Mars/Base"}, {"from": "25:00"}, {"urgent": ["everything"]}, {"daily": {"fax": "08:00"}}, {"user_id": str(b.id)}):
            r = await c.put("/api/me/vendor-notify/schedule", json={**body, **bad})
            assert r.status_code == 422, bad
        r = await c.put("/api/me/vendor-notify/schedule", json={**body, "from": "08:00", "to": "08:00", "weekends": False})
        assert r.status_code == 422 and r.json()["detail"]["code"] == "quiet_empty"
    async with db.session() as s:
        assert (await s.get(PersonNotify, b.id)) is None  # nothing of anyone else
        assert (await s.get(PersonNotify, a.id)).schedule["tz"] == "Europe/Vienna"


# ---------------------------------------------------------------- absence with a deputy


async def _away(u, deputy, *, also_me: bool = False, start: date | None = None, end: date | None = None) -> None:  # noqa: ANN001
    today = datetime.now(BERLIN).date()
    async with db.session() as s:
        await absence.put(s, u.id, start or today, end or today + timedelta(days=3), deputy.id, also_me)
        await s.commit()


async def test_deputy_gets_the_absent_persons_products_exactly_once(mails):
    await _switch()
    a, d, x = await _person("anja"), await _person("dora"), await _person("xaver")
    await _team([a, d, x], products=("panos", "fortios"))
    for u in (a, d, x):
        await _ways(u, email=True)
    await _away(a, d)
    ev = await _event("panos", severity="high")
    await _dispatch()
    got = sorted(m["to"][0] for m in mails.sent)
    # dora gets panos anyway (all members) – once, not twice; anja nothing; xaver as always
    assert got == ["dora@corp.example", "xaver@corp.example"]
    assert sorted((r.user_id, r.way) for r in await _rows(event_id=ev)) == sorted([(d.id, "email"), (x.id, "email")])
    personal.reset()
    await _dispatch()
    assert len(mails.sent) == 2


async def test_deputy_gets_a_product_not_routed_to_them_and_only_of_their_teams(admin_client, mails):
    await _switch()
    a, d = await _person("anja"), await _person("dora")
    tid, _ = await _team([a, d], products=("panos",))
    tid2, _ = await _team([a], products=("fortios",), name="Firewall")  # dora is not in this team
    await admin_client.put(f"/api/admin/teams/{tid}/routing", json={"product": "panos", "all_members": False, "members": [str(a.id)]})
    await _ways(a, email=True)
    await _ways(d, email=True)
    await _away(a, d)
    await _event("panos")
    await _event("fortios")
    await _dispatch()
    # panos (not routed to dora herself) goes to dora; fortios stays with anja – dora is in no team that has it
    assert sorted((m["to"][0], m["subject"]) for m in mails.sent)[0][0] == "anja@corp.example"
    assert {m["to"][0] for m in mails.sent} == {"anja@corp.example", "dora@corp.example"}
    assert len(mails.sent) == 2


async def test_also_to_me_no_chains_and_watched_cves_stay_private(mails):
    await _switch()
    a, d, e = await _person("anja"), await _person("dora"), await _person("emil")
    await _team([a, d, e])
    for u in (a, d, e):
        await _ways(u, email=True)
    # also to me: both
    await _away(a, d, also_me=True)
    await _event("panos")
    await _dispatch()
    assert sorted(m["to"][0] for m in mails.sent) == ["anja@corp.example", "dora@corp.example", "emil@corp.example"]
    mails.sent.clear()
    # dora is away herself (emil stands in for her): anja's news are not passed on to emil – anja gets them
    async with db.session() as s:
        await s.execute(update(PersonAbsence).where(PersonAbsence.user_id == a.id).values(also_me=False))
        await s.commit()
    await _away(d, e)
    async with await _client(a) as c:
        me = (await c.get("/api/me/vendor-notify")).json()
        assert me["absence"]["deputy_absent"] is True and me["absence"]["deputy"]["username"] == "dora"
    await _event("panos")
    personal.reset()
    await _dispatch()
    assert sorted(m["to"][0] for m in mails.sent) == ["anja@corp.example", "emil@corp.example"]  # emil once (his own; dora's goes to him)
    mails.sent.clear()
    # a watched CVE of anja's (dora back again): to anja, never to her deputy
    async with db.session() as s:
        await absence.end(s, d.id)
        await cve_watch.add(s, a.id, "CVE-2026-31337")
        await s.commit()
        w = await s.get(CveWatch, (a.id, "CVE-2026-31337"))
        w.created_at = datetime.now(UTC) - HOUR
        s.add(VendorEvent(key="watch:CVE-2026-31337:kev", kind="watch", product="", severity="high", scope="watch:CVE-2026-31337", data={"cve": "CVE-2026-31337", "what": "kev", "kev": {"added": "2026-10-30"}}))
        await s.commit()
    personal.reset()
    await _dispatch()
    assert [m["to"][0] for m in mails.sent] == ["anja@corp.example"]


async def test_the_end_ends_it_and_nothing_comes_again(mails):
    await _switch()
    a, d = await _person("anja"), await _person("dora")
    await _team([a, d], products=("panos", "fortios"))
    await _ways(a, email=True)
    await _ways(d, email=True)
    async with await _client(a) as c:
        today = datetime.now(BERLIN).date()
        r = await c.put("/api/me/vendor-notify/absence", json={"start": today.isoformat(), "end": (today + timedelta(days=2)).isoformat(), "deputy_id": str(d.id)})
        assert r.status_code == 200, r.text
        assert r.json()["absence"]["running"] is True and r.json()["absence"]["end"] == (today + timedelta(days=2)).isoformat()
        during = await _event("panos")
        await _dispatch()
        assert [m["to"][0] for m in mails.sent] == ["dora@corp.example"]
        # dora sees for whom she stands in
        async with await _client(d) as cd:
            cov = (await cd.get("/api/me/vendor-notify")).json()["covering"]
            assert [x["name"] for x in cov] == ["Anja"] and cov[0]["running"]
        # back early: over now – the absence's event does not come to anja afterwards, new ones do
        assert (await c.delete("/api/me/vendor-notify/absence")).json()["absence"] is None
    personal.reset()
    await _dispatch()
    assert len(mails.sent) == 1 and not await _rows(event_id=during, user_id=a.id)
    await _event("fortios")
    await _dispatch()
    assert len(mails.sent) == 3 and sorted(m["to"][0] for m in mails.sent[1:]) == ["anja@corp.example", "dora@corp.example"]


async def test_a_new_deputy_while_running_splits_the_absence(admin_client, mails):
    await _switch()
    a, d, e = await _person("anja"), await _person("dora"), await _person("emil")
    tid, _ = await _team([a, d, e])
    await admin_client.put(f"/api/admin/teams/{tid}/routing", json={"product": "panos", "all_members": False, "members": [str(a.id)]})
    for u in (a, d, e):
        await _ways(u, email=True)
    await _away(a, d)
    first = await _event("panos")
    async with db.session() as s:
        ways = await personal.allowed(s)
        await personal.enqueue(s, ways)  # queued for dora, not sent yet
    await _away(a, e)  # another deputy now: the old part ends now, a new one starts now
    async with db.session() as s:
        rows = list(await s.scalars(select(PersonAbsence).where(PersonAbsence.user_id == a.id).order_by(PersonAbsence.starts_at)))
    assert len(rows) == 2 and rows[0].deputy_id == d.id and rows[0].ends_at <= rows[1].starts_at and rows[1].deputy_id == e.id
    second = await _event("panos")
    personal.reset()
    await _dispatch()
    # the first event stays dora's (queued for her, still routed by the ended part), the second goes to emil, anja nothing
    assert {(r.user_id, r.status) for r in await _rows(event_id=first)} == {(d.id, "sent")}
    assert {(r.user_id, r.status) for r in await _rows(event_id=second)} == {(e.id, "sent")}
    assert sorted(m["to"][0] for m in mails.sent) == ["dora@corp.example", "emil@corp.example"]


async def test_absence_api_deputy_only_from_the_own_teams(admin_client):
    await _switch()
    a, d, z, q = await _person("anja"), await _person("dora"), await _person("zora"), await _person("quinn", active=False)
    tid, _ = await _team([a, d, q])
    await _team([z], name="Other")
    today = datetime.now(BERLIN).date().isoformat()
    later = (datetime.now(BERLIN).date() + timedelta(days=5)).isoformat()
    async with await _client(a) as c:
        names = [x["username"] for x in (await c.get("/api/me/vendor-notify/deputies")).json()["items"]]
        assert names == ["dora"]  # not anja herself, not zora (another team), not quinn (switched off)
        for who, code in ((z, "deputy_not_in_team"), (a, "deputy_not_in_team"), (q, "deputy_not_in_team")):
            r = await c.put("/api/me/vendor-notify/absence", json={"start": today, "end": later, "deputy_id": str(who.id)})
            assert r.status_code == 422 and r.json()["detail"]["code"] == code, who.username
        r = await c.put("/api/me/vendor-notify/absence", json={"start": later, "end": today, "deputy_id": str(d.id)})
        assert r.status_code == 422 and r.json()["detail"]["code"] == "absence_range"
        r = await c.put("/api/me/vendor-notify/absence", json={"start": "2020-01-01", "end": "2020-01-02", "deputy_id": str(d.id)})
        assert r.status_code == 422 and r.json()["detail"]["code"] == "absence_past"
        # only the own absence – nothing in the body names another person
        r = await c.put("/api/me/vendor-notify/absence", json={"start": today, "end": later, "deputy_id": str(d.id), "user_id": str(z.id)})
        assert r.status_code == 422
        assert (await c.put("/api/me/vendor-notify/absence", json={"start": today, "end": later, "deputy_id": str(d.id)})).status_code == 200
        # admin endpoints refuse a reader
        assert (await c.put(f"/api/admin/teams/{tid}/members/{d.id}/absence", json={"start": today, "end": later, "deputy_id": str(a.id)})).status_code == 403
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(PersonAbsence).where(PersonAbsence.user_id != a.id)) == 0
    # an admin sets it for a member – the deputy from this team; the members list says it
    r = await admin_client.put(f"/api/admin/teams/{tid}/members/{d.id}/absence", json={"start": today, "end": later, "deputy_id": str(z.id)})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "deputy_not_in_team"
    r = await admin_client.put(f"/api/admin/teams/{tid}/members/{z.id}/absence", json={"start": today, "end": later, "deputy_id": str(a.id)})
    assert r.status_code == 404  # zora is no member of this team
    r = await admin_client.put(f"/api/admin/teams/{tid}/members/{d.id}/absence", json={"start": today, "end": later, "deputy_id": str(a.id)})
    assert r.status_code == 200 and r.json()["absence"]["deputy"]["username"] == "anja"
    deputies = (await admin_client.get(f"/api/admin/teams/{tid}/members/{d.id}/deputies")).json()["items"]
    assert [x["username"] for x in deputies] == ["anja"]
    items = {m["username"]: m["absence"] for m in (await admin_client.get(f"/api/admin/teams/{tid}/members")).json()["items"]}
    assert items["anja"]["deputy"]["username"] == "dora" and items["anja"]["deputy_absent"] is True  # dora is away then too
    assert items["dora"]["end"] == later and items["quinn"] is None
    assert (await admin_client.delete(f"/api/admin/teams/{tid}/members/{d.id}/absence")).json()["absence"] is None


async def test_a_planned_absence_changes_freely_and_its_start_in_the_past_is_now():
    await _switch()
    a, d, e = await _person("anja"), await _person("dora"), await _person("emil")
    await _team([a, d, e])
    today = datetime.now(BERLIN).date()
    async with db.session() as s:
        p = await absence.put(s, a.id, today + timedelta(days=3), today + timedelta(days=4), d.id, False)
        await s.commit()
        assert p.starts_at > datetime.now(UTC)
        p2 = await absence.put(s, a.id, today + timedelta(days=5), today + timedelta(days=6), e.id, True)
        await s.commit()
        assert p2.id == p.id and p2.deputy_id == e.id  # planned: changed in place
        assert await absence.end(s, a.id)
        await s.commit()
        assert await s.scalar(select(func.count()).select_from(PersonAbsence)) == 0  # planned and taken back: gone
        before = datetime.now(UTC)
        p3 = await absence.put(s, a.id, today - timedelta(days=2), today, d.id, False)
        await s.commit()
        assert p3.starts_at >= before  # a start in the past is now – nothing old goes to the deputy
