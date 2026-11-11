# ruff: noqa: F811 - the fixtures of test_personal (mails) are imported and used by name
"""The own security stories (app/personal_news.py, deep review 0.1.56): "gesammelt um HH:MM" sends what came by the
collecting time – a story after it waits for the next one, also when nothing was due at this one, and is not lost; one
person's error in a round never abandons the jobs already claimed for the others."""

import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from test_notify import _source
from test_personal import mails  # noqa: F401
from test_personal_news import _allow, _body, _dispatch, _no_gap, _signed
from test_rule_filters import _news

from app import db, personal_news, quiet
from app.models import PersonNews, PersonNewsSent


async def _yesterday_sent(uid, slot: datetime) -> None:  # noqa: ANN001
    async with db.session() as s:
        p = await s.get(PersonNews, uid)
        p.email_sent_at = slot - timedelta(hours=20)  # the message of yesterday's collecting time
        await s.commit()


async def test_a_story_after_a_collecting_time_with_nothing_due_waits_for_the_next(mails, monkeypatch):
    await _allow()
    src = await _source()
    u, c = await _signed()
    async with c:
        assert (await c.put("/api/me/news-notify", json=_body())).status_code == 200
    slot = datetime.now(UTC) - timedelta(hours=2)  # the collecting time was two hours ago, nothing was due then
    monkeypatch.setattr(quiet, "hold", lambda schedule, way, at: (True, slot))
    await _yesterday_sent(u.id, slot)
    await _dispatch()
    await _news(src, "Kam zwei Stunden nach der Sammelzeit")
    await _dispatch()
    await _dispatch()
    assert mails.sent == []  # waits – not at once
    # the next collecting time: it comes then (it was not judged away meanwhile)
    nxt = datetime.now(UTC) + timedelta(seconds=1)
    monkeypatch.setattr(quiet, "hold", lambda schedule, way, at: (True, nxt))
    await _dispatch()
    assert len(mails.sent) == 1 and "Kam zwei Stunden nach der Sammelzeit" in mails.sent[0]["text"]


async def test_at_the_collecting_time_only_what_came_by_then_goes(mails, monkeypatch):
    await _allow()
    src = await _source()
    u, c = await _signed()
    async with c:
        assert (await c.put("/api/me/news-notify", json=_body())).status_code == 200
    await _news(src, "Vor der Sammelzeit")
    slot = datetime.now(UTC) + timedelta(milliseconds=200)
    await _yesterday_sent(u.id, slot)
    await asyncio.sleep(0.3)  # past the collecting time
    await _news(src, "Nach der Sammelzeit")
    monkeypatch.setattr(quiet, "hold", lambda schedule, way, at: (True, slot))
    await _dispatch()
    assert len(mails.sent) == 1
    assert "Vor der Sammelzeit" in mails.sent[0]["text"] and "Nach der Sammelzeit" not in mails.sent[0]["text"]
    await _no_gap(u.id)
    nxt = datetime.now(UTC) + timedelta(seconds=1)
    monkeypatch.setattr(quiet, "hold", lambda schedule, way, at: (True, nxt))
    await _dispatch()
    assert len(mails.sent) == 2 and "Nach der Sammelzeit" in mails.sent[1]["text"]


async def test_one_persons_error_never_abandons_the_jobs_claimed_for_the_others(mails, monkeypatch, caplog):
    await _allow()
    src = await _source()
    people = [await _signed("anja"), await _signed("bert")]
    for _, c in people:
        async with c:
            assert (await c.put("/api/me/news-notify", json=_body())).status_code == 200
    await _news(src, "Für beide")
    # the person-ways are taken by user id: the second one fails – after the first one's job was claimed
    bad = max(u.id for u, _ in people)
    good = min(u.id for u, _ in people)
    real = personal_news._story_list

    def broken(p, rows):  # noqa: ANN001, ANN202
        if p.user_id == bad:
            raise ValueError("a story this round cannot read")
        return real(p, rows)

    monkeypatch.setattr(personal_news, "_story_list", broken)
    await _dispatch()
    assert len(mails.sent) == 1  # the first one's job sent
    assert "not prepared" in caplog.text
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(PersonNewsSent).where(PersonNewsSent.user_id == bad)) == 0
        assert (await s.get(PersonNews, bad)).email_claim_at is None
        assert (await s.get(PersonNews, good)).email_claim_at is None  # settled
    monkeypatch.setattr(personal_news, "_story_list", real)
    await _dispatch()
    assert len(mails.sent) == 2  # the other one's stories came again
