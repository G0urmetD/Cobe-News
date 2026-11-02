# ruff: noqa: F811 - the fixtures of test_personal (mails, web) are imported and used by name
"""The bounded round of the personal notifications (app/personal.py): at most ROUND_JOBS messages and none started
after ROUND_S, the rest the next round – fair (the one waiting longest first, a pausing person does not hold up the
line) –, and the guarantees through all of it: exactly once per way also when the process stops mid-round (before the
claim, after the claim, after sending), messages never started go back without a try, a batch whose results cannot be
written at once is written person by person, the browsers' and the ways' states. Nothing leaves the machine."""

import asyncio
import time
from collections import Counter
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select, update
from test_personal import HOUR, _dispatch, _event, _person, _rows, _subscribe, _switch, _team, _ways, mails, web  # noqa: F401

from app import db, notify, personal
from app.models import PersonDelivery, PersonNotify, PushSubscription


class Crash(BaseException):
    """The process stopping right here (nothing after it runs – no except Exception catches it)."""


async def _people(n: int, **ways) -> list:
    await _switch()
    people = [await _person(f"p{i:02d}") for i in range(n)]
    await _team(people)
    for u in people:
        await _ways(u, **(ways or {"email": True}))
    return people


def _per_person(mails) -> Counter:  # noqa: ANN001
    return Counter(m["to"][0] for m in mails.sent)


async def _open() -> int:
    return len([r for r in await _rows() if r.status in ("pending", "sending")])


async def test_a_round_takes_at_most_round_jobs_the_rest_follows_exactly_once(mails, monkeypatch):
    monkeypatch.setattr(personal, "ROUND_JOBS", 3)
    monkeypatch.setattr(personal, "BATCH", 2)
    people = await _people(7)
    await _event("panos")
    counts = []
    for _ in range(5):
        got = await _dispatch()
        counts.append(got.get("sent", 0))
        if not personal.backlog():
            break
    assert counts == [3, 3, 1]  # bounded, and the backlog says when there is more
    assert not personal.backlog()
    assert _per_person(mails) == Counter({f"{u.username}@corp.example": 1 for u in people})
    assert await _open() == 0
    await _dispatch()
    assert len(mails.sent) == 7


async def test_fair_the_one_waiting_longest_first_nobody_starves(mails, monkeypatch):
    """New events every round for everybody: who was served goes to the back of the line (their oldest open row is
    newer now) – after ceil(7/2) rounds everybody got a message."""
    monkeypatch.setattr(personal, "ROUND_JOBS", 2)
    people = await _people(7)
    served: list[set] = []
    for _ in range(4):
        await _event("panos")
        personal.reset()  # queue the new event at once (as after FULL_EVERY)
        before = len(mails.sent)
        await _dispatch()
        served.append({m["to"][0] for m in mails.sent[before:]})
    assert all(len(s) == 2 for s in served[:3])
    assert set().union(*served) == {f"{u.username}@corp.example" for u in people}
    # nobody twice before everybody once
    first_rounds = [x for s in served[:3] for x in s]
    assert len(first_rounds) == len(set(first_rounds))


async def test_a_pausing_person_does_not_hold_up_the_line(mails, monkeypatch):
    monkeypatch.setattr(personal, "ROUND_JOBS", 2)
    a, b, c, d = await _people(4)
    later = (datetime.now(UTC) + HOUR).isoformat()
    async with db.session() as s:
        for u in (a, b):  # oldest in line, but pausing after a failure
            await s.execute(update(PersonNotify).where(PersonNotify.user_id == u.id).values(state_email={"failures": 1, "next_try_at": later, "last_error": "refused"}))
        # a malformed pause counts as none (never stops the round)
        await s.execute(update(PersonNotify).where(PersonNotify.user_id == c.id).values(state_email={"next_try_at": "soon"}))
        await s.commit()
    await _event("panos")
    assert await _dispatch() == {"sent": 2}
    assert {m["to"][0] for m in mails.sent} == {"p02@corp.example", "p03@corp.example"}
    assert {r.user_id for r in await _rows(status="pending")} == {a.id, b.id}


async def test_desktop_with_every_browser_pausing_waits_without_taking_a_place(mails, web, monkeypatch):
    monkeypatch.setattr(personal, "ROUND_JOBS", 1)
    await _switch()
    a = await _person("anja")
    b = await _person("bert")
    await _team([a, b])
    await _ways(a, desktop=True)
    await _ways(b, desktop=True)
    await _subscribe(a)
    await _subscribe(b)
    async with db.session() as s:
        await s.execute(update(PushSubscription).where(PushSubscription.user_id == a.id).values(next_try_at=datetime.now(UTC) + HOUR))
        await s.commit()
    await _event("panos")
    assert await _dispatch() == {"sent": 1}
    (push,) = web.to("fcm.googleapis.com")
    assert push.url.path.endswith("-bert")
    assert [r.user_id for r in await _rows(status="pending")] == [a.id]


async def test_the_time_budget_ends_the_round_messages_not_started_go_back_without_a_try(mails, monkeypatch):
    monkeypatch.setattr(personal, "ROUND_S", 0.3)
    monkeypatch.setattr(personal, "CONCURRENCY", 2)
    monkeypatch.setattr(personal, "BATCH", 10)
    slow = 0.2

    async def send_mail(cfg, to, subject, text, body):  # noqa: ANN001, ANN202
        await asyncio.sleep(slow)
        mails.sent.append({"to": to, "subject": subject, "text": text, "html": body})

    monkeypatch.setattr(notify, "send_mail", send_mail)
    people = await _people(10)
    await _event("panos")
    t0 = time.monotonic()
    first = await _dispatch()
    wall = time.monotonic() - t0
    assert wall < personal.ROUND_S + slow + 0.5  # bounded: the deadline plus at most the messages already started
    assert 0 < first["sent"] < 10 and personal.backlog()
    rows = await _rows()
    assert {r.status for r in rows} == {"sent", "pending"}
    # never started: back in line, no try counted, no claim left behind
    assert all(r.tries == 0 and r.claimed_at is None for r in rows if r.status == "pending")
    assert all(r.tries == 1 for r in rows if r.status == "sent")
    for _ in range(20):
        if not personal.backlog():
            break
        await _dispatch()
    assert _per_person(mails) == Counter({f"{u.username}@corp.example": 1 for u in people})
    assert {r.status for r in await _rows()} == {"sent"}


@pytest.mark.parametrize("where", ["before_claim", "after_claim", "after_send"])
async def test_a_stop_mid_round_never_sends_twice_and_the_rest_follows(mails, monkeypatch, where):
    """The process stops in the second batch: before its claim is committed (its rows stay pending – sent after the
    restart), after the claim (nothing sent – never sent, failed "interrupted" after an hour) or after sending, before
    the results are written (sent once – never again, also failed "interrupted" after an hour: never twice)."""
    monkeypatch.setattr(personal, "BATCH", 2)
    people = await _people(6)
    await _event("panos")
    calls = Counter()
    real = {"skip": personal._skip_groups, "send": personal._send_batch, "settle": personal._settle_batch}

    async def skip_groups(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        calls["skip"] += 1
        if where == "before_claim" and calls["skip"] == 4:  # three calls per batch: the second batch's first
            raise Crash
        return await real["skip"](*a, **kw)

    async def send_batch(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        calls["send"] += 1
        if where == "after_claim" and calls["send"] == 2:
            raise Crash
        return await real["send"](*a, **kw)

    async def settle_batch(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        calls["settle"] += 1
        if where == "after_send" and calls["settle"] == 2:
            raise Crash
        return await real["settle"](*a, **kw)

    monkeypatch.setattr(personal, "_skip_groups", skip_groups)
    monkeypatch.setattr(personal, "_send_batch", send_batch)
    monkeypatch.setattr(personal, "_settle_batch", settle_batch)
    with pytest.raises(Crash):
        await _dispatch()
    sent_before = len(mails.sent)
    assert sent_before == {"before_claim": 2, "after_claim": 2, "after_send": 4}[where]
    monkeypatch.setattr(personal, "_skip_groups", real["skip"])
    monkeypatch.setattr(personal, "_send_batch", real["send"])
    monkeypatch.setattr(personal, "_settle_batch", real["settle"])
    personal.reset()  # the restart: nothing in memory
    await _dispatch()
    await _dispatch()
    per = _per_person(mails)
    assert set(per.values()) == {1}  # nobody twice
    stuck = [r for r in await _rows() if r.status == "sending"]
    if where == "before_claim":
        assert len(per) == 6 and not stuck  # rolled back: everybody exactly once
    else:
        assert len(per) == {"after_claim": 4, "after_send": 6}[where] and len(stuck) == 2
        async with db.session() as s:
            await s.execute(update(PersonDelivery).where(PersonDelivery.status == "sending").values(claimed_at=datetime.now(UTC) - 2 * HOUR))
            await s.commit()
        await _dispatch()
        assert {(r.status, r.error) for r in await _rows() if r.user_id in {x.user_id for x in stuck}} == {("failed", "interrupted")}
        assert len(mails.sent) == len(per)
    assert {u.username for u in people} >= {k.split("@")[0] for k in per}


async def test_a_batch_not_written_at_once_is_written_person_by_person(mails, web, monkeypatch):
    people = await _people(3, email=True, teams_=True)
    mails.fail.append("refused")  # e-mail: certainly not delivered – again after a pause
    await _event("panos")
    real = personal._patch_states
    broken = {"n": 0}

    async def patch_states(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        broken["n"] += 1
        if broken["n"] == 1:
            raise RuntimeError("the database refused the batch")
        return await real(*a, **kw)

    monkeypatch.setattr(personal, "_patch_states", patch_states)
    got = await _dispatch()
    assert got == {"sent": 3, "failed": 3}
    rows = {(r.user_id, r.way): r for r in await _rows()}
    for u in people:
        assert (rows[(u.id, "teams")].status, rows[(u.id, "email")].status, rows[(u.id, "email")].error) == ("sent", "pending", "refused")
    async with db.session() as s:
        for u in people:
            p = await s.get(PersonNotify, u.id)
            assert p.state_teams["last_ok_at"] and p.state_teams["failures"] == 0
            assert p.state_email["failures"] == 1 and p.state_email["next_try_at"] and p.state_email["last_error"] == "refused"


async def test_desktop_in_bulk_each_browser_its_own_state(mails, web, monkeypatch):
    """Many browsers in one batch: delivered (state reset), a failure that certainly delivered nothing (backoff on the
    browser, the rows again later), gone at the push service (410: the browser removed)."""
    people = await _people(6, desktop=True)
    for u in people:
        await _subscribe(u)
    status = {"p00": 201, "p01": 201, "p02": 500, "p03": 500, "p04": 410, "p05": 410}

    def handler(req: httpx.Request) -> httpx.Response:
        web.requests.append(req)
        return httpx.Response(status[req.url.path.rsplit("-", 1)[1]])

    monkeypatch.setattr(notify, "transport", httpx.MockTransport(handler))
    await _event("panos")
    got = await _dispatch()
    assert got == {"sent": 2, "failed": 4}
    async with db.session() as s:
        subs = {x.endpoint.rsplit("-", 1)[1]: x for x in await s.scalars(select(PushSubscription))}
        assert set(subs) == {"p00", "p01", "p02", "p03"}  # 410: removed
        assert subs["p00"].failures == 0 and subs["p00"].last_ok_at is not None
        assert subs["p02"].failures == 1 and subs["p02"].next_try_at is not None and subs["p02"].last_error.startswith("http")
        states = {u.username: (await s.get(PersonNotify, u.id)).state_desktop for u in people}
    assert states["p00"]["last_ok_at"] and states["p02"]["last_error"].startswith("http") and states["p02"]["next_try_at"]
    rows = {r.user_id: r for r in await _rows()}
    by_name = {u.username: rows[u.id] for u in people}
    assert by_name["p00"].status == "sent" and by_name["p02"].status == "pending" and by_name["p04"].status == "failed"
    # the browser's pause: the next round leaves it alone
    await _dispatch()
    assert len(web.requests) == 6


async def test_no_address_and_no_browser_say_so_under_the_way(mails, web):
    await _switch()
    a = await _person("anja", email=False)
    await _team([a])
    await _ways(a, email=True, desktop=True)
    await _event("panos")
    await _dispatch()
    async with db.session() as s:
        p = await s.get(PersonNotify, a.id)
    assert p.state_email["last_error"] == "no_address" and p.state_email["last_error_at"]
    assert p.state_desktop["last_error"] == "no_device" and p.state_desktop["last_error_at"]


async def test_switched_off_inactive_and_expired_decided_in_bulk(mails, web):
    await _switch()
    a, b, c = await _person("anja"), await _person("bert"), await _person("cleo")
    await _team([a, b, c])
    for u in (a, b, c):
        await _ways(u, email=True, teams_=True)
    ev = await _event("panos")
    async with db.session() as s:
        await personal.enqueue(s, await personal.allowed(s))
    # after queueing: the admin switches Teams delivery off, B is switched off, C switches e-mail off, the event ages
    await _switch(teams=False)
    async with db.session() as s:
        from app.models import User

        await s.execute(update(User).where(User.id == b.id).values(is_active=False))
        await s.execute(update(PersonNotify).where(PersonNotify.user_id == c.id).values(email_on=False))
        await s.commit()
    await _dispatch()
    rows = {(r.user_id, r.way): (r.status, r.error) for r in await _rows(event_id=ev)}
    assert rows[(a.id, "teams")] == ("skipped", "way_off") and rows[(a.id, "email")] == ("sent", None)
    assert rows[(b.id, "email")] == ("skipped", "inactive")
    assert rows[(c.id, "email")] == ("skipped", "off")
    assert [m["to"] for m in mails.sent] == [["anja@corp.example"]] and web.requests == []
