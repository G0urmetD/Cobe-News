"""The personal security stories of very many people (app/personal_news.py): PERSONAL_NEWS_SCALE_N people (2000), each with
e-mail and their own Teams webhook on and "alle" chosen, one new story. Measured per round: the statements sent to the
database, the wall time and the longest write transaction. Asserted: a round's statements do not grow with the number
of people, a round is bounded (ROUND_JOBS person-ways, ROUND_S seconds) and after a few rounds everybody got exactly one
mail and one card. Nothing leaves the machine: mails are recorded, HTTP is a MockTransport. `pytest -s` prints the
measurements. 0.1.56 (a claim and a settlement per person-way, each with its own statements and commit): 3014
statements and 3.1 s per round of 500, 5000 people in 63 s; set-based since 0.1.57: 547 statements and 0.8 s."""

import asyncio
import math
import os
import time
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import func, insert, select, text
from test_notify import _source
from test_personal_news import _allow
from test_personal_scale import DELAY, Meter, url_of
from test_rule_filters import _news

from app import db, news, notify, personal_news
from app.crypto import encrypt_str
from app.models import PersonNews, PersonNewsSent, PersonNotify, User

HOUR = timedelta(hours=1)
N = int(os.environ.get("PERSONAL_NEWS_SCALE_N", "2000"))


async def seed(n: int) -> None:
    await _allow()
    past = datetime.now(UTC) - HOUR
    ids = [uuid.uuid4() for _ in range(n)]
    async with db.session() as s:
        top = await news.last_seq(s)
        await s.execute(insert(User), [{"id": u, "username": f"p{i:06d}", "display_name": f"P {i}", "email": f"p{i:06d}@corp.example", "role": "reader"} for i, u in enumerate(ids)])
        await s.execute(
            insert(PersonNotify),
            [{"user_id": u, "lang": "de", "teams_url_enc": encrypt_str(url_of(i)), "teams_host": "prod.westeurope.logic.azure.com", "state_email": {}, "state_desktop": {}, "state_teams": {}} for i, u in enumerate(ids)],
        )
        await s.execute(
            insert(PersonNews),
            [
                {"user_id": u, "lang": "de", "severities": [], "filter_seq": top, "filter_at": past, "email_on": True, "email_on_seq": top, "teams_on": True, "teams_on_seq": top, "state_email": {}, "state_teams": {}}
                for u in ids
            ],
        )
        await s.commit()
    async with db.engine().connect() as conn:
        await conn.execute(text("ANALYZE"))
        await conn.commit()


async def test_many_people_are_served_in_bounded_rounds_each_once(monkeypatch):
    mails: Counter = Counter()
    cards: Counter = Counter()

    async def send_mail(cfg, to, subject, text_, body):  # noqa: ANN001, ANN202
        await asyncio.sleep(DELAY)
        mails[to[0]] += 1

    async def handler(req: httpx.Request) -> httpx.Response:
        await asyncio.sleep(DELAY)
        cards[req.url.path] += 1
        return httpx.Response(202)

    monkeypatch.setattr(notify, "send_mail", send_mail)
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(handler))
    src = await _source()
    await seed(N)
    await _news(src, "Kritische Lücke in PAN-OS wird ausgenutzt")
    meter = Meter()
    rounds: list[tuple[int, float, float, dict]] = []
    try:
        for _ in range(200):
            meter.reset()
            t0 = time.monotonic()
            async with db.session() as s:
                got = await personal_news.dispatch(s)
            rounds.append((meter.queries, time.monotonic() - t0, meter.longest_write, got))
            if not personal_news.backlog():
                break
    finally:
        meter.close()
    for k, (q, wall, write, got) in enumerate(rounds, 1):
        print(f"round {k:3d}: {q:6d} statements, {wall:6.2f} s, longest write transaction {write:5.2f} s, {got}")
    print(f"{N} people, 2 ways: {len(rounds)} rounds, {sum(r[0] for r in rounds)} statements, {sum(r[1] for r in rounds):.1f} s in all")
    assert len(mails) == N and set(mails.values()) == {1}
    assert len(cards) == N and set(cards.values()) == {1}
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(PersonNewsSent)) == 2 * N
        assert await s.scalar(select(func.count()).select_from(PersonNews).where((PersonNews.email_claim_at.is_not(None)) | (PersonNews.teams_claim_at.is_not(None)))) == 0
    # bounded: at most ROUND_JOBS person-ways a round …
    if not DELAY:
        assert len(rounds) <= math.ceil(2 * N / personal_news.ROUND_JOBS) + 1
    assert all(sum(r[3].values()) <= personal_news.ROUND_JOBS for r in rounds)
    assert all(r[1] < personal_news.ROUND_S + DELAY + 10 for r in rounds)
    # … one query per person-way (its own filter), everything else a fixed number per CHUNK and per round …
    per_round = personal_news.ROUND_JOBS + 12 * math.ceil(personal_news.ROUND_JOBS / personal_news.CHUNK) + 40
    assert max(r[0] for r in rounds) <= per_round, [r[0] for r in rounds]
    # … and no write transaction held for long
    assert max(r[2] for r in rounds) < 5.0
