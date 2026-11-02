# ruff: noqa: F811 - the fixtures of test_personal (mails) are imported and used by name
"""The weekly review of a team by e-mail (app/weekly.py, the switches in app/teams_api.py and app/personal_api.py): off by
default for the team and for each member; once per team, person and week – also after a restart and after a crash
between claim and send; after an outage only the last week, never a flood of old ones; the content (new vulnerabilities
by severity, versions affected now, advisory changes with an effect, EOL within 90 days, new versions, links), HTML
escaped with a text alternative; nothing without a mail server. Mails are recorded, the clock frozen."""

from datetime import UTC, datetime, timedelta

import pytest
from conftest import make_client, sign_in
from sqlalchemy import select, update
from test_personal import _person, _switch, _team, mails  # noqa: F401
from test_quiet_absence import freeze, utc

from app import db, settings as settings_store, weekly
from app.models import PersonNotify, TeamWeekly, TeamWeeklySend, VendorEvent, VendorFollow, VendorVersion

REAL_AFFECTED, REAL_EOL = weekly._affected, weekly._eol
MONDAY = utc(2026, 11, 2, 7, 5)  # Monday 08:05 in Berlin (week 45)


async def _optin(u, on: bool = True, since: datetime | None = None, lang: str = "de") -> None:  # noqa: ANN001
    async with db.session() as s:
        p = await s.get(PersonNotify, u.id) or PersonNotify(user_id=u.id, kinds=["vendor_vuln"], min_severity="info", state_email={}, state_desktop={}, state_teams={}, schedule={})
        p.weekly_on, p.weekly_since, p.lang = on, since or utc(2026, 10, 1), lang
        s.add(p)
        await s.commit()


async def _weekly(tid, *, enabled: bool = True, since: datetime | None = None, weekday: int = 0, at: str = "08:00") -> None:  # noqa: ANN001
    async with db.session() as s:
        await s.merge(TeamWeekly(team_id=tid, enabled=enabled, weekday=weekday, at=at, tz="Europe/Berlin", since=since or utc(2026, 10, 1)))
        await s.commit()


async def _run(monkeypatch, at: datetime) -> int:  # noqa: ANN001
    freeze(monkeypatch, weekly, at)
    async with db.session() as s:
        return await weekly.run(s)


async def _sends() -> list[TeamWeeklySend]:
    async with db.session() as s:
        return list(await s.scalars(select(TeamWeeklySend).order_by(TeamWeeklySend.week)))


@pytest.fixture(autouse=True)
def no_views(monkeypatch):
    """The product views need Vendor News data – the content test sets its own lists."""

    async def none(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        return []

    monkeypatch.setattr(weekly, "_affected", none)
    monkeypatch.setattr(weekly, "_eol", none)


async def test_once_per_team_person_and_week_also_after_a_restart(mails, monkeypatch):
    await _switch()
    a, b, c, d = await _person("anja"), await _person("bert"), await _person("cleo", active=False), await _person("dora", email=False)
    tid, _ = await _team([a, b, c, d])
    await _weekly(tid)
    await _optin(a)
    for u in (c, d):
        await _optin(u)  # switched off / no address: never
    # bert did not switch it on: nothing for him
    assert await _run(monkeypatch, MONDAY) == 1
    assert [m["to"] for m in mails.sent] == [["anja@corp.example"]]
    assert "Wochenrückblick Security" in mails.sent[0]["subject"] and "KW 45/2026" in mails.sent[0]["subject"]
    for at in (MONDAY + timedelta(minutes=1), MONDAY + timedelta(days=3)):
        assert await _run(monkeypatch, at) == 0  # the same week: never again (rows and last_week are in the database)
    assert [(r.week, r.status) for r in await _sends()] == [("2026-W45", "sent")]
    # the next Monday: once more
    assert await _run(monkeypatch, MONDAY + timedelta(days=7)) == 1
    assert len(mails.sent) == 2
    # Monday 07:59: not yet
    assert await _run(monkeypatch, utc(2026, 11, 16, 6, 59)) == 0


async def test_crash_between_claim_and_send_never_twice(mails, monkeypatch):
    await _switch()
    a = await _person("anja")
    tid, _ = await _team([a])
    await _weekly(tid)
    await _optin(a)
    freeze(monkeypatch, weekly, MONDAY)
    async with db.session() as s:
        await weekly.queue(s, MONDAY)
        claimed = await weekly._claim(s, 10)
    assert len(claimed) == 1  # claimed and committed – and then the process "stopped"
    assert await _run(monkeypatch, MONDAY + timedelta(minutes=5)) == 0
    assert await _run(monkeypatch, MONDAY + timedelta(hours=2)) == 0
    assert mails.sent == [] and [(r.status, r.error) for r in await _sends()] == [("failed", "interrupted")]


async def test_after_an_outage_only_the_last_week_and_no_catching_up(mails, monkeypatch):
    await _switch()
    a = await _person("anja")
    tid, _ = await _team([a])
    await _weekly(tid, since=utc(2026, 9, 1))
    await _optin(a, since=utc(2026, 9, 1))
    # an old week was queued but never sent (the mail server was away) – a newer week skips it
    async with db.session() as s:
        s.add(TeamWeeklySend(team_id=tid, user_id=a.id, week="2026-W40", status="pending", tries=1, created_at=utc(2026, 9, 28, 6, 0)))
        await s.execute(update(TeamWeekly).where(TeamWeekly.team_id == tid).values(last_week="2026-W40"))
        await s.commit()
    assert await _run(monkeypatch, MONDAY + timedelta(days=2)) == 1  # five weeks later: one review, of week 45
    assert [(r.week, r.status, r.error) for r in await _sends()] == [("2026-W40", "skipped", "superseded"), ("2026-W45", "sent", None)]
    assert len(mails.sent) == 1


async def test_switched_on_after_this_weeks_time_starts_next_week(mails, monkeypatch):
    await _switch()
    a, b = await _person("anja"), await _person("bert")
    tid, _ = await _team([a, b])
    await _weekly(tid, since=MONDAY + timedelta(hours=1))  # switched on Monday 09:05
    await _optin(a)
    await _optin(b, since=MONDAY + timedelta(days=8))  # bert only from week 47 on
    assert await _run(monkeypatch, MONDAY + timedelta(hours=2)) == 0
    assert await _run(monkeypatch, MONDAY + timedelta(days=7)) == 1
    assert [m["to"] for m in mails.sent] == [["anja@corp.example"]]


async def test_no_mail_server_nothing_is_tried(mails, monkeypatch):
    await _switch()
    a = await _person("anja")
    tid, _ = await _team([a])
    await _weekly(tid)
    await _optin(a)
    async with db.session() as s:
        await settings_store.put(s, "smtp", settings_store.DEFAULTS["smtp"])
        await s.commit()
    assert await _run(monkeypatch, MONDAY) == 0
    assert mails.sent == [] and await _sends() == []
    # Teams off: nothing either
    await _switch(enabled=False)
    assert await _run(monkeypatch, MONDAY) == 0 and await _sends() == []


async def test_a_mail_server_failure_retries_one_that_may_have_arrived_does_not(mails, monkeypatch):
    await _switch()
    a, b = await _person("anja"), await _person("bert")
    tid, _ = await _team([a, b])
    await _weekly(tid)
    await _optin(a)
    await _optin(b)
    mails.fail.append("refused")
    assert await _run(monkeypatch, MONDAY) == 0
    rows = await _sends()
    assert sorted(r.status for r in rows) == ["pending", "pending"] and sorted(r.tries for r in rows) == [0, 1]  # the second never started
    mails.fail[:] = ["timeout"]
    await _run(monkeypatch, MONDAY + timedelta(minutes=1))
    assert sorted(r.status for r in await _sends()) == ["failed", "pending"]  # a timeout may have delivered it: never again
    mails.fail.clear()
    assert await _run(monkeypatch, MONDAY + timedelta(minutes=2)) == 1
    assert len(mails.sent) == 1


async def test_content_sections_links_and_escaping(mails, monkeypatch):
    await _switch()
    a = await _person("anja")
    tid, _ = await _team([a], products=("panos", "fortios"))
    await _weekly(tid)
    await _optin(a)
    inside, before = MONDAY - timedelta(days=2), MONDAY - timedelta(days=9)
    async with db.session() as s:
        for k, (sev, at) in enumerate([("critical", inside), ("high", inside), ("high", inside), ("medium", before)]):
            s.add(
                VendorEvent(
                    key=f"vuln:panos:10.2.3:ADV-{k}",
                    kind="vuln",
                    product="panos",
                    severity=sev,
                    scope="vuln:panos:10.2.3",
                    created_at=at,
                    data={"product": "PAN-OS", "version": "10.2.3", "ident": f"CVE-2026-{k}", "headline": "<script>alert(1)</script>" if k == 0 else f"Lücke {k}"},
                )
            )
        # the same finding on a second version: counted once
        s.add(VendorEvent(key="vuln:panos:11.0.1:ADV-1", kind="vuln", product="panos", severity="high", scope="vuln:panos:11.0.1", created_at=inside, data={"ident": "CVE-2026-1", "headline": "Lücke 1"}))
        s.add(VendorEvent(key="vuln:panos:10.2.3:base", kind="vuln", product="panos", severity="critical", baseline=True, created_at=inside, data={"ident": "CVE-2026-99"}))
        s.add(VendorEvent(key="change:fortios:a:2", kind="change", product="fortios", severity="high", created_at=inside, data={"ident": "FG-IR-26-001", "title": "FortiOS advisory", "impact": [{"product": "fortios", "from": None, "to": "affected"}]}))
        s.add(VendorEvent(key="change:fortios:b:1", kind="change", product="fortios", severity="low", created_at=inside, data={"ident": "FG-IR-26-002", "title": "No effect", "impact": []}))
        s.add(VendorEvent(key="version:panos:10.2.3:10.2.9", kind="version", product="panos", severity="low", created_at=inside, data={"version": "10.2.3", "latest": "10.2.9"}))
        s.add(VendorEvent(key="vuln:other:1:X", kind="vuln", product="other", severity="critical", created_at=inside, data={"ident": "CVE-2026-777"}))  # not the team's
        await s.commit()

    async def affected(db_, follows):  # noqa: ANN001, ANN202
        return [{"product": "panos", "version": "10.2.3", "n": 4, "critical": 1}]

    async def eol(db_, follows, today):  # noqa: ANN001, ANN202
        return [{"product": "fortios", "version": "7.0.12", "date": "2026-12-31"}]

    monkeypatch.setattr(weekly, "_affected", affected)
    monkeypatch.setattr(weekly, "_eol", eol)
    assert await _run(monkeypatch, MONDAY) == 1
    m = mails.sent[0]
    t = m["text"]
    assert "Kritisch 1 · Hoch 2" in t and "CVE-2026-99" not in t and "CVE-2026-777" not in t and "CVE-2026-3" not in t
    assert t.index("CVE-2026-0") < t.index("CVE-2026-1")  # the most severe first
    assert "PAN-OS 10.2.3: 4 Schwachstellen (1 kritisch)" in t or "10.2.3: 4 Schwachstellen (1 kritisch)" in t
    assert "FG-IR-26-001" in t and "FG-IR-26-002" not in t  # only changes with an effect
    assert "7.0.12: Support endet am 31.12.2026" in t
    assert "10.2.3 → 10.2.9" in t
    assert "https://news.corp.example:8095/vendor?product=panos&finding=ADV-0" in t
    assert "https://news.corp.example:8095/vendor?product=fortios&view=changes" in t
    assert "<script>" not in m["html"] and "&lt;script&gt;" in m["html"] and "<script>alert(1)</script>" in t  # escaped in HTML, plain in text
    assert "Wochenrückblick" in m["html"] and "Vendor News öffnen" in m["html"]


async def test_english_review(mails, monkeypatch):
    await _switch()
    a = await _person("anja")
    tid, _ = await _team([a])
    await _weekly(tid)
    await _optin(a, lang="en")
    await _run(monkeypatch, MONDAY)
    assert "Weekly review Security" in mails.sent[0]["subject"] and "No new vulnerabilities." in mails.sent[0]["text"]


# ---------------------------------------------------------------- the switches (API)


async def test_admin_switch_and_member_opt_in(admin_client, mails):
    await _switch()
    a, z = await _person("anja"), await _person("zora", email=False)
    tid, _ = await _team([a, z])
    team = next(t for t in (await admin_client.get("/api/admin/teams")).json() if t["id"] == str(tid))
    assert team["weekly"] == {"enabled": False, "weekday": 0, "at": "08:00", "tz": "Europe/Berlin", "last_week": None, "recipients": 0}
    r = await admin_client.put(f"/api/admin/teams/{tid}/weekly", json={"enabled": True, "weekday": 4, "at": "07:30", "tz": "Europe/Vienna"})
    assert r.status_code == 200 and r.json()["weekly"]["enabled"] is True and r.json()["weekly"]["weekday"] == 4
    for bad in ({"tz": "Nowhere/Land"}, {"weekday": 7}, {"at": "7:30"}):
        r = await admin_client.put(f"/api/admin/teams/{tid}/weekly", json={"enabled": True, **bad})
        assert r.status_code == 422, bad
    async with make_client() as c:
        await sign_in(c, a)
        me = (await c.get("/api/me/vendor-notify")).json()
        assert me["weekly"]["on"] is False and me["weekly"]["teams"] == [{"team": "Security", "weekday": 4, "at": "07:30", "tz": "Europe/Vienna"}]
        r = await c.put("/api/me/vendor-notify/weekly", json={"on": True})
        assert r.status_code == 200 and r.json()["weekly"]["on"] is True
        assert (await c.put(f"/api/admin/teams/{tid}/weekly", json={"enabled": False})).status_code == 403
        assert (await c.put("/api/me/vendor-notify/weekly", json={"on": True, "user_id": str(z.id)})).status_code == 422
    async with make_client() as c:
        await sign_in(c, z)
        r = await c.put("/api/me/vendor-notify/weekly", json={"on": True})
        assert r.status_code == 409 and r.json()["detail"]["code"] == "no_address"
    team = next(t for t in (await admin_client.get("/api/admin/teams")).json() if t["id"] == str(tid))
    assert team["weekly"]["recipients"] == 1
    async with db.session() as s:
        assert (await s.get(PersonNotify, a.id)).weekly_since is not None
        assert await s.get(PersonNotify, z.id) is None


async def test_eol_within_90_days_and_affected_from_the_real_views(monkeypatch):
    """The two lists from the product data itself (no monkeypatched helpers): the release line's end of support, and the
    product view (no advisories here – nothing affected, and no error)."""
    from app import vendor_catalog as catalog

    rel = [
        {"name": "11.1", "label": "11.1", "releaseDate": "2023-06-01", "latest": "11.1.4", "eolFrom": "2026-12-01", "isMaintained": True},
        {"name": "10.2", "label": "10.2", "releaseDate": "2022-01-01", "latest": "10.2.9", "eolFrom": "2027-06-01", "isMaintained": True},
    ]
    monkeypatch.setattr(catalog, "releases", lambda key: rel if key == "panos" else [])
    async with db.session() as s:
        f = VendorFollow(product="panos", baseline_at=utc(2026, 1, 1))
        s.add(f)
        await s.flush()
        s.add(VendorVersion(follow_id=f.id, version="11.1.2", baseline_at=utc(2026, 1, 1)))
        s.add(VendorVersion(follow_id=f.id, version="10.2.3", baseline_at=utc(2026, 1, 1)))
        await s.commit()
        follows = list(await s.scalars(select(VendorFollow)))
        got = await REAL_EOL(s, follows, MONDAY.date())
        assert got == [{"product": "panos", "version": "11.1.2", "date": "2026-12-01"}]  # 10.2 ends in more than 90 days
        assert await REAL_AFFECTED(s, follows) == []
