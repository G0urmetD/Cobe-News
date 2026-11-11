# ruff: noqa: F811 - the fixtures of test_personal (mails, web) are imported and used by name
"""Absence (deep review 0.1.56): an absent person's event goes to the deputy only when a way of the deputy can carry it
– the same rules as the deputy routes: allowed by an admin (since before the event), switched on before the event,
Teams with a URL. Otherwise the person keeps it (as without a deputy) – it never reaches nobody."""

from datetime import UTC, datetime, timedelta

from test_personal import HOUR, _dispatch, _event, _person, _rows, _subscribe, _switch, _team, _ways, mails, web  # noqa: F401
from test_quiet_absence import _away

from app import db
from app import settings as settings_store


async def _anja_and_dora():  # noqa: ANN202
    a, d = await _person("anja"), await _person("dora")
    await _team([a, d], products=("panos",))
    await _ways(a, email=True)
    return a, d


async def _who(ev) -> list[tuple[str, str]]:  # noqa: ANN001
    return sorted((str(r.user_id), r.way) for r in await _rows(event_id=ev))


async def test_the_deputys_only_way_not_allowed_by_the_admin_leaves_the_event_with_the_person(mails):
    await _switch(teams=False)  # e-mail and desktop allowed, Teams not
    a, d = await _anja_and_dora()
    await _ways(d, teams_=True)  # dora: only Teams on
    await _away(a, d)
    ev = await _event("panos")
    await _dispatch()
    assert await _who(ev) == [(str(a.id), "email")]
    assert [m["to"][0] for m in mails.sent] == ["anja@corp.example"]


async def test_the_deputys_way_switched_on_after_the_event_leaves_it_with_the_person(mails):
    await _switch()
    a, d = await _anja_and_dora()
    ev = await _event("panos", at=datetime.now(UTC) - timedelta(minutes=20))
    await _ways(d, email=True, since=datetime.now(UTC) - timedelta(minutes=10))  # on after the event
    await _away(a, d)
    await _dispatch()
    assert await _who(ev) == [(str(a.id), "email")]


async def test_the_deputys_teams_way_without_a_url_leaves_it_with_the_person(mails):
    await _switch()
    a, d = await _anja_and_dora()
    await _ways(d, teams_=True, teams_url_enc=None, teams_host=None)
    await _away(a, d)
    ev = await _event("panos")
    await _dispatch()
    assert (str(a.id), "email") in await _who(ev)
    assert "anja@corp.example" in [m["to"][0] for m in mails.sent]


async def test_the_deputys_way_allowed_only_after_the_event_leaves_it_with_the_person(mails):
    await _switch()
    async with db.session() as s:  # desktop allowed by the admin only ten minutes ago
        conf = await settings_store.get(s, "teams")
        await settings_store.put(s, "teams", {**conf, "personal_desktop_since": (datetime.now(UTC) - timedelta(minutes=10)).isoformat()})
        await s.commit()
    a, d = await _anja_and_dora()
    await _ways(d, desktop=True, since=datetime.now(UTC) - HOUR)
    await _away(a, d)
    ev = await _event("panos", at=datetime.now(UTC) - timedelta(minutes=20))
    await _dispatch()
    assert await _who(ev) == [(str(a.id), "email")]


async def test_a_deputy_way_that_carries_it_still_takes_the_event(mails):
    await _switch(teams=False)
    a, d = await _anja_and_dora()
    await _ways(d, email=True, teams_=True)
    await _away(a, d)
    ev = await _event("panos")
    await _dispatch()
    assert await _who(ev) == [(str(d.id), "email")]
    assert [m["to"][0] for m in mails.sent] == ["dora@corp.example"]


async def test_the_deputys_desktop_way_without_a_browser_leaves_it_with_the_person(mails, web):
    """Final review 0.1.56: desktop on but no browser subscribed – the round skips the deputy's row as no_device, so
    the event stays with the person."""
    await _switch()
    a, d = await _anja_and_dora()
    await _ways(d, desktop=True)
    await _away(a, d)
    ev = await _event("panos")
    await _dispatch()
    rows = {(r.user_id, r.way): (r.status, r.error) for r in await _rows(event_id=ev)}
    assert rows[(a.id, "email")][0] == "sent" and rows.get((d.id, "desktop"), ("skipped", "no_device")) == ("skipped", "no_device")
    assert [m["to"][0] for m in mails.sent] == ["anja@corp.example"]


async def test_the_deputys_desktop_way_with_a_browser_takes_it(mails, web):
    await _switch()
    a, d = await _anja_and_dora()
    await _ways(d, desktop=True)
    await _subscribe(d)
    await _away(a, d)
    ev = await _event("panos")
    await _dispatch()
    assert await _who(ev) == [(str(d.id), "desktop")]
    assert mails.sent == []


async def test_the_deputys_email_way_without_an_address_leaves_it_with_the_person(mails):
    await _switch()
    a = await _person("anja")
    d = await _person("dora", email=False)
    await _team([a, d], products=("panos",))
    await _ways(a, email=True)
    await _ways(d, email=True)
    await _away(a, d)
    ev = await _event("panos")
    await _dispatch()
    rows = {(r.user_id, r.way): (r.status, r.error) for r in await _rows(event_id=ev)}
    assert rows[(a.id, "email")][0] == "sent" and rows.get((d.id, "email"), ("skipped", "no_address")) == ("skipped", "no_address")
    assert [m["to"][0] for m in mails.sent] == ["anja@corp.example"]
