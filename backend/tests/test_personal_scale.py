"""The personal notifications of a very large team (app/personal.py): 5000 people (PERSONAL_SCALE_N), each with e-mail
and their own Teams webhook on, one new Vendor News event. Measured per round: the statements sent to the database, the
wall time and the longest write transaction. Asserted: a round's statements do not grow with the team, a round is
bounded (ROUND_JOBS messages, ROUND_S seconds), and after a few rounds everybody got exactly one mail and one card.
Nothing leaves the machine: mails are recorded, HTTP is a MockTransport. `pytest -s` prints the measurements;
PERSONAL_SCALE_DELAY=0.05 makes each message take 50 ms (then the time budget ends the rounds)."""

import asyncio
import math
import os
import time
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import event, func, insert, select, text

from app import db, notify, personal
from app.crypto import encrypt_str
from app.models import PersonDelivery, PersonNotify, Team, TeamMember, TeamProduct, User, VendorEvent, VendorFollow

N = int(os.environ.get("PERSONAL_SCALE_N", "5000"))
DELAY = float(os.environ.get("PERSONAL_SCALE_DELAY", "0"))  # s per message (a real mail server, Teams): shows the time bound
HOUR = timedelta(hours=1)


class Meter:
    """Statements and the longest write transaction (first write to commit) on the app's engine."""

    def __init__(self) -> None:
        self.queries = 0
        self.longest_write = 0.0
        self.sync = db.engine().sync_engine
        event.listen(self.sync, "before_cursor_execute", self._exec)
        event.listen(self.sync, "commit", self._end)
        event.listen(self.sync, "rollback", self._end)

    def _exec(self, conn, _cur, statement, *_a) -> None:  # noqa: ANN001
        self.queries += 1
        if "meter_t0" not in conn.info and statement.lstrip()[:7].upper().startswith(("INSERT", "UPDATE", "DELETE")):
            conn.info["meter_t0"] = time.monotonic()

    def _end(self, conn) -> None:  # noqa: ANN001
        t0 = conn.info.pop("meter_t0", None)
        if t0 is not None:
            self.longest_write = max(self.longest_write, time.monotonic() - t0)

    def reset(self) -> None:
        self.queries, self.longest_write = 0, 0.0

    def close(self) -> None:
        event.remove(self.sync, "before_cursor_execute", self._exec)
        event.remove(self.sync, "commit", self._end)
        event.remove(self.sync, "rollback", self._end)


def url_of(i: int) -> str:
    return f"https://prod-{i % 50}.westeurope.logic.azure.com/workflows/{i:06d}/triggers/manual/paths/invoke?sig=Sig{i:06d}"


async def seed(n: int) -> None:
    """Teams on, e-mail and Teams allowed; one team of n people with both ways on; the product for all members."""
    from test_personal import _switch

    await _switch()
    past = datetime.now(UTC) - HOUR
    ids = [uuid.uuid4() for _ in range(n)]
    async with db.session() as s:
        await s.execute(insert(User), [{"id": u, "username": f"p{i:06d}", "display_name": f"P {i}", "email": f"p{i:06d}@corp.example", "role": "reader"} for i, u in enumerate(ids)])
        await s.execute(
            insert(PersonNotify),
            [
                {
                    "user_id": u,
                    "lang": "de",
                    "kinds": list(personal.KINDS),
                    "min_severity": "info",
                    "email_on": True,
                    "email_since": past,
                    "teams_on": True,
                    "teams_since": past,
                    "teams_url_enc": encrypt_str(url_of(i)),
                    "teams_host": "prod.westeurope.logic.azure.com",
                    "state_email": {},
                    "state_desktop": {},
                    "state_teams": {},
                }
                for i, u in enumerate(ids)
            ],
        )
        t = Team(name="Alle")
        f = VendorFollow(product="panos")
        s.add_all([t, f])
        await s.flush()
        s.add(TeamProduct(team_id=t.id, follow_id=f.id, all_members=True, added_at=past))
        await s.execute(insert(TeamMember), [{"team_id": t.id, "user_id": u, "origin": "manual", "added_at": past} for u in ids])
        s.add(
            VendorEvent(
                key="vuln:panos:10.2.3:ADV-1",
                kind="vuln",
                product="panos",
                severity="critical",
                baseline=False,
                scope="vuln:panos:10.2.3",
                data={"product": "PAN-OS", "version": "10.2.3", "status": "affected", "ident": "CVE-2026-1001", "headline": "Lücke", "url": "https://security.example.com/adv"},
                created_at=datetime.now(UTC),
            )
        )
        await s.commit()
    # fresh statistics for the thousands of rows just written – autovacuum would have them in a real installation; without
    # them a slow machine (CI) plans the routing join badly and runs into the statement timeout
    async with db.engine().connect() as conn:
        await conn.execute(text("ANALYZE"))
        await conn.commit()


async def open_rows() -> int:
    async with db.session() as s:
        return await s.scalar(select(func.count()).select_from(PersonDelivery).where(PersonDelivery.status.in_(("pending", "sending")))) or 0


async def test_a_large_team_is_served_in_bounded_rounds_each_person_exactly_once(monkeypatch):
    mails: Counter = Counter()
    cards: Counter = Counter()

    async def send_mail(cfg, to, subject, text, body):  # noqa: ANN001, ANN202
        await asyncio.sleep(DELAY)
        mails[to[0]] += 1

    async def handler(req: httpx.Request) -> httpx.Response:
        await asyncio.sleep(DELAY)
        cards[req.url.path] += 1
        return httpx.Response(202)

    monkeypatch.setattr(notify, "send_mail", send_mail)
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(handler))
    await seed(N)
    meter = Meter()
    rounds: list[tuple[int, float, float, dict]] = []
    try:
        for _ in range(500):
            meter.reset()
            t0 = time.monotonic()
            async with db.session() as s:
                got = await personal.dispatch(s)
            rounds.append((meter.queries, time.monotonic() - t0, meter.longest_write, got))
            if not await open_rows():
                break
    finally:
        meter.close()
    for k, (q, wall, write, got) in enumerate(rounds, 1):
        print(f"round {k:3d}: {q:6d} statements, {wall:6.2f} s, longest write transaction {write:5.2f} s, {got}")
    total_q = sum(r[0] for r in rounds)
    total_t = sum(r[1] for r in rounds)
    print(f"{N} people, 2 ways: {len(rounds)} rounds, {total_q} statements, {total_t:.1f} s in all")
    # everybody exactly once on each way
    assert len(mails) == N and set(mails.values()) == {1}
    assert len(cards) == N and set(cards.values()) == {1}
    async with db.session() as s:
        assert set(await s.scalars(select(PersonDelivery.status).distinct())) == {"sent"}
    # bounded: a round sends at most ROUND_JOBS messages and starts none after ROUND_S, so the work spreads over a few
    # rounds …
    if not DELAY:
        assert len(rounds) <= math.ceil(2 * N / personal.ROUND_JOBS) + 1
    assert all(r[1] < personal.ROUND_S + DELAY + 10 for r in rounds)
    assert all(sum(r[3].values()) <= personal.ROUND_JOBS for r in rounds)
    # … its statements do not grow with the team (a fixed number per batch of BATCH messages) …
    per_round = 30 + 12 * math.ceil(personal.ROUND_JOBS / personal.BATCH)
    assert max(r[0] for r in rounds) <= per_round, [r[0] for r in rounds]
    # … and no write transaction is held for long (the first round's queueing of 2N rows is the longest)
    assert max(r[2] for r in rounds) < 5.0
