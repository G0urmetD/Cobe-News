"""Treffer bestätigen at scale (review 0.1.56): whether an event is held back (finding_confirm.held) is one index lookup
of its product and record – the personal round over a big team with many confirmations stays fast (it compared every
event with every confirmation per member: 5–18 s for 1500 events × 50 members × 2000 confirmations, near the statement
timeout). Measured by EXPLAIN ANALYZE of the round's routing query; the bound is generous (it takes ~0.1 s)."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import event, insert, text
from test_personal import _switch

from app import db, finding_confirm, personal
from app.models import (
    PersonNotify,
    Team,
    TeamMember,
    TeamProduct,
    User,
    VendorConfirm,
    VendorConfirmRecord,
    VendorEvent,
    VendorFollow,
)

HOUR = timedelta(hours=1)
EVENTS, MEMBERS, CONFIRMS = 1500, 50, 1000
BOUND_MS = 3000.0


async def _seed() -> list[uuid.UUID]:
    await _switch()
    now = datetime.now(UTC)
    uids = [uuid.uuid4() for _ in range(MEMBERS)]
    async with db.session() as s:
        await s.execute(insert(User), [{"id": u, "username": f"h{i}", "display_name": f"H {i}", "email": f"h{i}@corp.example", "role": "reader"} for i, u in enumerate(uids)])
        await s.execute(
            insert(PersonNotify),
            [{"user_id": u, "lang": "de", "kinds": list(personal.KINDS), "min_severity": "info", "email_on": True, "email_since": now - 400 * HOUR, "state_email": {}, "state_desktop": {}, "state_teams": {}} for u in uids],
        )
        t, f = Team(name="Win"), VendorFollow(product="windows-11")
        s.add_all([t, f])
        await s.flush()
        s.add(TeamProduct(team_id=t.id, follow_id=f.id, all_members=True, added_at=now - 400 * HOUR))
        await s.execute(insert(TeamMember), [{"team_id": t.id, "user_id": u, "origin": "manual", "added_at": now - 400 * HOUR} for u in uids])
        scope = "vuln:windows-11:10.0.26100.4061"
        ids = [uuid.uuid4() for _ in range(EVENTS)]
        await s.execute(
            insert(VendorEvent),
            [
                {
                    "id": ids[i],
                    "key": f"{scope}:msrc:CVE-2026-{i:05d}" if i % 2 else f"change:windows-11:msrc:CVE-2026-{i:05d}:1",
                    "kind": "vuln" if i % 2 else "change",
                    "product": "windows-11",
                    "severity": "high",
                    "baseline": False,
                    "scope": scope if i % 2 else None,
                    "data": {"advisory": f"msrc:CVE-2026-{i:05d}", "ident": f"CVE-2026-{i:05d}"},
                    "created_at": now - timedelta(minutes=i % 5000 + 1),
                }
                for i in range(EVENTS)
            ],
        )
        # many confirmations of the product, standing and ended – of other findings, and of the first 20 events' ones
        rows, recs = [], []
        for i in range(2 * CONFIRMS):
            cid = uuid.uuid4()
            fid = f"msrc:CVE-2026-{i:05d}" if i < 20 else f"msrc:CVE-2025-{i:05d}"
            row = {"id": cid, "product": "windows-11", "finding": fid, "status": "not_affected", "note": "", "user_name": "A", "confirmed_at": now - 48 * HOUR, "facts": {}, "held_from": finding_confirm.EPOCH}
            if i >= CONFIRMS:
                row |= {"held_until": now - 24 * HOUR, "ended_at": now - 24 * HOUR, "ended_reason": "undone"}
            rows.append(row)
            recs += [{"confirm_id": cid, "record": r, "product": "windows-11"} for r in finding_confirm.members_of({"id": fid, "cves": [fid.partition(":")[2]]})]
        await s.execute(insert(VendorConfirm), rows)
        await s.execute(insert(VendorConfirmRecord), recs)
        await s.commit()
    async with db.engine().connect() as conn:
        await conn.execute(text("ANALYZE"))
        await conn.commit()
    return ids


async def _explain_ms(stmt) -> float:  # noqa: ANN001
    got = []
    sync = db.engine().sync_engine

    def grab(conn, cur, statement, params, *_a):  # noqa: ANN001, ANN202
        got.append((statement, params))

    event.listen(sync, "before_cursor_execute", grab)
    try:
        async with db.session() as s:
            rows = (await s.execute(stmt)).all()
    finally:
        event.remove(sync, "before_cursor_execute", grab)
    sql, params = got[-1]
    async with db.engine().connect() as conn:
        raw = await conn.get_raw_connection()
        plan = [r[0] for r in await raw.driver_connection.fetch("EXPLAIN ANALYZE " + sql, *(params or ()))]
    return float(plan[-1].split(":")[1].strip().split()[0]), len(rows)


async def test_the_personal_routing_stays_fast_with_many_confirmations():
    ids = await _seed()
    ms, n = await _explain_ms(personal._routes("email"))
    assert ms < BOUND_MS, f"{ms:.0f} ms"
    # the first 20 events' findings stand confirmed: held – every other event goes to every member
    assert n == (EVENTS - 20) * MEMBERS
    async with db.session() as s:
        assert len(await finding_confirm.held_events(s, ids[:40])) == 20
