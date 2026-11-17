# ruff: noqa: F811 - the fixtures of test_personal (mails, web) are imported and used by name
"""The rounds of the personal ways work set-based, a batch of person-ways at a time (app/personal.py BATCH,
app/personal_news.py CHUNK and its settled-at-once results): whoever gets what must not depend on how the people fall
into batches. A mixed set – quiet hours, absent with a deputy, muted, a confirmed finding, no way on, no address, a
narrow filter, a Teams target that refuses (certainly nothing delivered: again later) and one that may have taken it
(kept as sent) – gives the same recipients and the same outcomes with batches of one, of two and of all; and the
person-by-person fallback (the batch statements failing) gives them too."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import httpx
import pytest
from sqlalchemy import select, update
from test_notify import _source
from test_personal import HOUR, _dispatch, _event, _person, _rows, _switch, _team, _ways, mails, web  # noqa: F401
from test_personal_news import _allow
from test_personal_scale import url_of
from test_quiet_absence import _away, _schedule
from test_rule_filters import _news

from app import db, finding_confirm, news, notify, personal, personal_news, reader
from app.crypto import encrypt_str
from app.models import NewsItem, PersonAbsence, PersonMute, PersonNews, PersonNewsSent, PersonNotify, User, VendorEvent

BERLIN = ZoneInfo("Europe/Berlin")


def _quiet_now() -> dict:
    """Quiet hours around this very moment (Berlin) – nothing is urgent for the person."""
    now = datetime.now(BERLIN)
    return {"quiet": True, "from": (now - HOUR).strftime("%H:%M"), "to": (now + HOUR).strftime("%H:%M"), "weekends": True, "tz": "Europe/Berlin", "urgent": []}


async def _mute(u: User, kind: str, key: str) -> None:
    async with db.session() as s:
        s.add(PersonMute(user_id=u.id, kind=kind, key=key, until=datetime.now(UTC) + timedelta(days=1)))
        await s.commit()


# ---------------------------------------------------------------- Vendor News of the own products (app/personal.py)


@pytest.mark.parametrize("batch", [1, 2, 1000])
async def test_vendor_news_same_recipients_whatever_the_batches(monkeypatch, mails, web, batch):
    monkeypatch.setattr(personal, "BATCH", batch)
    await _switch()
    names = ("anja", "berta", "carl", "dora", "emil", "fritz", "hans")
    p = {n: await _person(n) for n in names}
    p["gerd"] = await _person("gerd", email=False)
    await _team(list(p.values()), products=("panos",))
    for n in ("anja", "berta", "carl", "dora", "emil", "gerd"):
        await _ways(p[n], email=True)
    await _ways(p["fritz"])  # no way on
    await _ways(p["hans"], teams_=True)
    await _schedule(p["berta"], **_quiet_now())
    await _away(p["carl"], p["dora"])  # dora gets it anyway – once
    await _mute(p["emil"], "product", "panos")
    ok = await _event("panos", title="Die eine Lücke")
    held = await _event("panos", title="Bestätigt")
    async with db.session() as s:
        await personal.enqueue(s, {"email": True, "desktop": True, "teams": True})  # both queued – then the one is confirmed
        ev = await s.get(VendorEvent, held)
        await finding_confirm.confirm(s, p["anja"], "panos", {"id": reader.finding_of(ev.key, ev.scope), "severity": "high", "exploited": False, "cves": [], "versions": []}, "not_affected", "")
        await s.commit()
    await _dispatch()
    name = {u.id: n for n, u in p.items()}
    got = {(name[r.user_id], r.way, r.event_id == ok): (r.status, r.error) for r in await _rows()}
    want_ok = {
        ("anja", "email"): ("sent", None),
        ("berta", "email"): ("pending", None),  # quiet hours: waits
        ("dora", "email"): ("sent", None),
        ("emil", "email"): ("skipped", "muted"),
        ("gerd", "email"): ("skipped", "no_address"),
        ("hans", "teams"): ("sent", None),
    }
    assert {(k[0], k[1]): v for k, v in got.items() if k[2]} == want_ok
    # the confirmed finding: nobody gets it (emil's was muted already when queued, gerd's skipped for the address)
    held_rows = {(k[0], k[1]): v for k, v in got.items() if not k[2]}
    assert held_rows.pop(("emil", "email")) == ("skipped", "muted")
    assert held_rows.pop(("berta", "email")) == ("pending", None)  # held by the quiet hours: decided when they end
    assert set(held_rows.values()) == {("skipped", "confirmed")}
    assert set(held_rows) == {("anja", "email"), ("dora", "email"), ("gerd", "email"), ("hans", "teams")}
    assert sorted(m["to"][0] for m in mails.sent) == ["anja@corp.example", "dora@corp.example"]
    assert all("Die eine Lücke" in m["text"] and "Bestätigt" not in m["text"] for m in mails.sent)
    assert len(web.to("logic.azure.com")) == 1
    async with db.session() as s:
        states = {name[x.user_id]: x for x in await s.scalars(select(PersonNotify))}
    assert states["anja"].state_email["failures"] == 0 and states["anja"].state_email["last_ok_at"]
    assert states["gerd"].state_email["last_error"] == "no_address"


# ---------------------------------------------------------------- the own security stories (app/personal_news.py)


async def _news_person(u: User, top: int, *, email: bool = False, teams: int | None = None, **kw) -> None:
    past = datetime.now(UTC) - HOUR
    async with db.session() as s:
        s.add(PersonNotify(user_id=u.id, lang="de", teams_url_enc=encrypt_str(url_of(teams)) if teams is not None else None, teams_host="prod.westeurope.logic.azure.com" if teams is not None else None, state_email={}, state_desktop={}, state_teams={}))
        s.add(PersonNews(user_id=u.id, lang="de", **{"severities": [], **kw}, filter_seq=top, filter_at=past, email_on=email, email_on_seq=top, teams_on=teams is not None, teams_on_seq=top, state_email={}, state_teams={}))
        await s.commit()


def _teams_answers(monkeypatch, refuse: int, unsure: int) -> list[str]:  # noqa: ANN001
    """Teams: target `refuse` answers 500 (certainly nothing delivered), `unsure` 404 (a dead target), the rest 202."""
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url.path)
        if f"/{refuse:06d}/" in req.url.path:
            return httpx.Response(500)
        if f"/{unsure:06d}/" in req.url.path:
            return httpx.Response(404)
        return httpx.Response(202)

    monkeypatch.setattr(notify, "transport", httpx.MockTransport(handler))
    return seen


@pytest.mark.parametrize("mode", ["chunk1", "chunk2", "all", "fallback"])
async def test_security_stories_same_outcomes_whatever_the_batches(monkeypatch, mails, mode, caplog):
    if mode == "fallback":  # the set-based writes fail: person-way by person-way, as before 0.1.57

        async def broken(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
            raise RuntimeError("batch refused")

        monkeypatch.setattr(personal_news, "_write_all", broken)
        settle_all = personal_news._settle_all

        async def settle_fallback(db_, jobs, results, now):  # noqa: ANN001, ANN202
            """The first statement of the settled-at-once results fails: job by job instead."""
            orig, calls = db_.execute, []

            async def first_fails(*a, **k):  # noqa: ANN002, ANN003, ANN202
                calls.append(1)
                if len(calls) == 1:
                    raise RuntimeError("batch refused")
                return await orig(*a, **k)

            db_.execute = first_fails
            try:
                return await settle_all(db_, jobs, results, now)
            finally:
                db_.execute = orig

        monkeypatch.setattr(personal_news, "_settle_all", settle_fallback)
    else:
        monkeypatch.setattr(personal_news, "CHUNK", {"chunk1": 1, "chunk2": 2, "all": 1000}[mode])
    cards = _teams_answers(monkeypatch, refuse=8, unsure=9)
    await _allow()
    src = await _source()
    async with db.session() as s:
        top = await news.last_seq(s)
    names = ("anja", "berta", "carl", "dora", "emil", "kai", "hans", "ida", "jan")
    p = {n: await _person(n) for n in names}
    p["gerd"] = await _person("gerd", email=False)
    for n in ("anja", "berta", "carl", "emil", "gerd"):
        await _news_person(p[n], top, email=True)
    await _news_person(p["dora"], top)  # no way on
    await _news_person(p["kai"], top, email=True, severities=["critical"])  # the story is "high": not chosen
    await _news_person(p["hans"], top, teams=7)
    await _news_person(p["ida"], top, teams=8)  # refused: comes again after the pause
    await _news_person(p["jan"], top, teams=9)  # a dead target: kept as sent, never twice
    async with db.session() as s:
        await s.execute(update(PersonNotify).where(PersonNotify.user_id == p["berta"].id).values(schedule=_quiet_now()))
        await s.commit()
    async with db.session() as s:  # away (the stories have no deputy)
        s.add(PersonAbsence(user_id=p["carl"].id, deputy_id=p["dora"].id, starts_at=datetime.now(UTC) - HOUR, ends_at=datetime.now(UTC) + 24 * HOUR))
        await s.commit()
    await _mute(p["emil"], "cve", "CVE-2026-4242")
    item = await _news(src, "Kritische Lücke in PAN-OS", severity="high")
    async with db.session() as s:
        await s.execute(update(NewsItem).where(NewsItem.id == item).values(cves=["CVE-2026-4242"]))
        await s.commit()
        newest = await news.last_seq(s)
    async with db.session() as s:
        got = await personal_news.dispatch(s)
    assert got == {"sent": 2, "failed": 2}
    one_by_one = [r.getMessage() for r in caplog.records if "one by one" in r.getMessage()]
    assert len(one_by_one) == (2 if mode == "fallback" else 0), one_by_one
    assert [m["to"][0] for m in mails.sent] == ["anja@corp.example"]
    assert sorted(c.split("/")[2] for c in cards) == ["000007", "000008", "000009"]
    name = {u.id: n for n, u in p.items()}
    async with db.session() as s:
        sent = sorted((name[r.user_id], r.way) for r in await s.scalars(select(PersonNewsSent)))
        rows = {name[r.user_id]: r for r in await s.scalars(select(PersonNews))}
        assert await s.scalar(select(PersonAbsence.user_id)) == p["carl"].id
    assert sent == [("anja", "email"), ("hans", "teams"), ("jan", "teams")]
    assert all(r.email_claim_at is None and r.teams_claim_at is None for r in rows.values())
    # sent: the GAP begins, the state says so
    assert rows["anja"].email_sent_at is not None and rows["anja"].state_email["failures"] == 0 and rows["anja"].state_email["last_ok_at"]
    assert rows["anja"].email_checked_seq == newest and rows["hans"].teams_sent_at is not None
    # refused: taken back, judged anew from where it was, the pause and the error shown
    ida = rows["ida"]
    assert ida.teams_sent_at is None and ida.teams_next_at is not None and ida.teams_checked_seq == 0
    assert ida.state_teams["failures"] == 1 and ida.state_teams["last_error"].startswith("http")
    # a dead target: kept as sent (never twice), the error shown
    jan = rows["jan"]
    assert jan.teams_next_at is not None and jan.state_teams["failures"] == 1 and jan.state_teams["last_error"].startswith("rejected")
    # no address: the start follows the newest story, the error shown
    assert rows["gerd"].email_on_seq == newest and rows["gerd"].state_email["last_error"] == "no_address"
    # away: the start follows the newest story, nothing waits for the return
    assert rows["carl"].email_on_seq == newest and rows["carl"].email_checked_seq == 0
    # muted and filtered: judged, nothing sent
    assert rows["emil"].email_checked_seq == newest and rows["kai"].email_checked_seq == newest
    # quiet hours: not judged – it waits
    assert rows["berta"].email_checked_seq == 0 and rows["berta"].email_on_seq == top
    # no way on: not even looked at
    assert rows["dora"].email_seen_at is None and rows["dora"].teams_seen_at is None
