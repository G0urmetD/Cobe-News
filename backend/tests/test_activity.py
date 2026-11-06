"""The sidebar's "Meldungen" (app/activity_api.py): admins only, a short allow-list of audit actions plus the sign-ins
from the accounts, newest first, cut to `limit`; sign-ins next to each other one line; the viewer's own doings left
out; the approval actions (written by the approval of new accounts and roles) shown as soon as they are there; a fixed
number of statements whatever the log holds."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import event, update

from app import activity_api, db
from app.models import AuditEntry, User
from conftest import add_user

NOW = datetime.now(UTC)


async def _entry(action: str, minutes_ago: float, *, actor: User | None = None, kind: str = "user", target: tuple | None = None, details: dict | None = None) -> int:
    """An entry written straight into the table – also of actions this version's audit.record does not know yet."""
    async with db.session() as s:
        e = AuditEntry(
            at=NOW - timedelta(minutes=minutes_ago),
            actor_kind=kind if actor is None else "user",
            actor_id=actor.id if actor else None,
            actor_name=actor.username if actor else kind,
            actor_display=actor.display_name if actor else "",
            action=action,
            target_type=target[0] if target else None,
            target_id=target[1] if target else None,
            target_label=target[2] if target else None,
            details=details or {},
        )
        s.add(e)
        await s.commit()
        return e.id


async def _signed_in(u: User, minutes_ago: float) -> None:
    async with db.session() as s:
        await s.execute(update(User).where(User.id == u.id).values(last_login_at=NOW - timedelta(minutes=minutes_ago)))
        await s.commit()


async def _named(username: str, role: str, display: str) -> User:
    u = await add_user(username, role)
    async with db.session() as s:
        await s.execute(update(User).where(User.id == u.id).values(display_name=display))
        await s.commit()
    u.display_name = display
    return u


async def _items(c, limit: int | None = None) -> list[dict]:  # noqa: ANN001
    r = await c.get("/api/admin/activity" + (f"?limit={limit}" if limit else ""))
    assert r.status_code == 200, r.text
    return r.json()["items"]


async def test_admins_only(reader_client, client):
    assert (await reader_client.get("/api/admin/activity")).status_code == 403
    assert (await client.get("/api/admin/activity")).status_code == 401


async def test_empty(admin_client):
    assert await _items(admin_client) == []


async def test_only_the_allowed_actions_newest_first_cut_to_the_limit(admin_client):
    ben = await add_user("ben", "admin")
    for action, ago in [("settings.changed", 1), ("login.success", 2), ("backup.created", 3), ("catalog.version_added", 4), ("audit.exported", 5)]:
        await _entry(action, ago, actor=ben)  # noise: never shown
    await _entry("catalog.followed", 30, actor=ben, target=("product", "fortinet-fortios", "Fortinet FortiOS"))
    await _entry("user.created", 20, actor=ben, target=("user", None, "carla"))
    await _entry("catalog.custom_added", 10, actor=ben, target=("product", "custom-1", "Acme Gateway"))
    await _entry("backup.restored", 40, kind="cli", target=("backup", "b.tar", "b.tar"))
    got = await _items(admin_client)
    assert [i["action"] for i in got] == ["catalog.custom_added", "user.created", "catalog.followed"]
    assert [i["action"] for i in await _items(admin_client, 10)] == ["catalog.custom_added", "user.created", "catalog.followed", "backup.restored"]
    assert [i["action"] for i in await _items(admin_client, 1)] == ["catalog.custom_added"]
    for bad in (0, 11, -1):
        assert (await admin_client.get(f"/api/admin/activity?limit={bad}")).status_code == 422


async def test_the_shape(admin_client):
    ben = await _named("ben", "admin", "Ben Bauer")
    eid = await _entry("catalog.followed", 5, actor=ben, target=("product", "fortinet-fortios", "Fortinet FortiOS"), details={"enabled": True, "tags": ["x"]})
    (item,) = await _items(admin_client)
    assert item == {
        "id": f"a{eid}",
        "entry": eid,
        "action": "catalog.followed",
        "at": (NOW - timedelta(minutes=5)).isoformat(),
        "actor": {"kind": "user", "id": str(ben.id), "name": "ben", "display": "Ben Bauer"},
        "target": {"type": "product", "id": "fortinet-fortios", "label": "Fortinet FortiOS", "display": None},
        "details": {},  # only what the texts use – no tags, no free text of the entry
    }


async def test_the_approval_actions_render(admin_client):
    """Not written by this version yet: rows of them as the approval feature writes them are shown with their role."""
    carla = await _named("carla", "reader", "Carla Clausen")
    ben = await add_user("ben", "admin")
    await _entry("user.approval_pending", 50, actor=carla, target=("user", str(carla.id), "carla"))
    await _entry("role.approval_pending", 40, kind="sync", target=("user", str(carla.id), "carla"), details={"role": "admin"})
    await _entry("user.approved", 30, actor=ben, target=("user", str(carla.id), "carla"))
    await _entry("user.declined", 20, actor=ben, target=("user", "0e7a2b8e-0000-4000-8000-000000000000", "dora"))
    await _entry("role.approved", 10, actor=ben, target=("user", str(carla.id), "carla"), details={"changes": {"role": {"from": "reader", "to": "admin"}}})
    await _entry("role.declined", 5, actor=ben, target=("user", str(carla.id), "carla"), details={"from": "reader", "to": "admin"})
    got = await _items(admin_client, 10)
    assert [i["action"] for i in got] == ["role.declined", "role.approved", "user.declined", "user.approved", "role.approval_pending", "user.approval_pending"]
    assert got[0]["details"] == {"role": "admin"} and got[0]["target"]["display"] == "Carla Clausen"  # "Ben hat den Aufstieg von Carla abgelehnt"
    got = got[1:]
    assert got[0]["details"] == {"role": "admin"}  # the new role of a change
    assert got[3]["details"] == {"role": "admin"} and got[3]["actor"]["kind"] == "sync"
    # the account by its current name; one that is gone by the name the log kept
    assert got[0]["target"]["display"] == "Carla Clausen"
    assert got[1]["target"] == {"type": "user", "id": "0e7a2b8e-0000-4000-8000-000000000000", "label": "dora", "display": None}
    assert set(activity_api.ACTIONS) >= {"user.approval_pending", "role.approval_pending", "user.approved", "user.declined", "role.approved", "role.declined"}


async def test_a_waiting_line_says_whether_it_still_waits(admin_client):
    """An approval by the viewing admin is their own doing (left out) – the "… wartet auf Freigabe" line must not keep
    standing out once it is dealt with; `pending` counts what waits now, also when its line is not among the newest.
    A waiting raise's entry names its role as `to` (directory.follow_role)."""
    from app.auth import directory

    carla = await _named("carla", "reader", "Carla Clausen")
    dora = await _named("dora", "reader", "Dora Dietz")
    eve = await _named("eve", "reader", "Eve Ebert")
    async with db.session() as s:
        await s.execute(update(User).where(User.id == carla.id).values(is_active=False, deactivated_reason=directory.PENDING, auth_source="ldap"))
        await s.execute(update(User).where(User.id == eve.id).values(pending_role="admin", auth_source="ldap"))
        await s.commit()
    await _entry("user.approval_pending", 30, kind="sync", target=("user", str(carla.id), "carla"))
    await _entry("user.approval_pending", 20, kind="sync", target=("user", str(dora.id), "dora"))  # approved since: on
    await _entry("role.approval_pending", 10, kind="sync", target=("user", str(eve.id), "eve"), details={"from": "reader", "to": "admin", "source": "ldap"})
    await _entry("user.approval_pending", 5, kind="sync", target=("user", "0e7a2b8e-0000-4000-8000-000000000000", "gone"))
    r = await admin_client.get("/api/admin/activity?limit=10")
    got = r.json()
    assert [(i["target"]["label"], i["open"]) for i in got["items"]] == [("gone", False), ("eve", True), ("dora", False), ("carla", True)]
    assert got["items"][1]["details"] == {"role": "admin"}
    assert got["pending"] == 2
    async with db.session() as s:
        assert got["pending"] == sum(v for k, v in (await directory.pending_counts(s)).items() if k != "accounts_admin")
    # the waiting lines pushed out of the newest by others: the count still says it
    for n in range(3):
        await _entry("catalog.followed", 1 - n / 10, kind="sync", target=("product", f"p{n}", f"P{n}"))
    got = (await admin_client.get("/api/admin/activity")).json()
    assert {i["action"] for i in got["items"]} == {"catalog.followed"} and got["pending"] == 2


async def test_own_doings_left_out_the_system_kept(admin_client):
    me = admin_client.user
    await _entry("catalog.followed", 5, actor=me, target=("product", "p1", "P1"))
    await _entry("user.deactivated", 6, kind="sync", target=("user", None, "eve"), details={"reason": "sync:disabled"})
    await _signed_in(me, 1)
    got = await _items(admin_client)
    assert [i["action"] for i in got] == ["user.deactivated"]
    assert got[0]["details"] == {}  # the reason is not a text's


async def test_signins_from_the_accounts_one_line_per_run(admin_client):
    """All roles (the log has the admins' only); one per person; neighbours joined, an entry between them splits."""
    ben = await add_user("ben", "admin")
    a, b, c, d = [await add_user(n) for n in ("ali", "bea", "cem", "dan")]
    await _signed_in(a, 1)
    await _signed_in(b, 2)
    await _signed_in(c, 3)
    await _entry("catalog.followed", 4, actor=ben, target=("product", "p1", "P1"))
    await _signed_in(d, 5)
    await add_user("never")  # never signed in
    got = await _items(admin_client)
    assert [i["action"] for i in got] == ["signin", "catalog.followed", "signin"]
    first = got[0]
    assert first["actor"] == {"kind": "user", "id": str(a.id), "name": "ali", "display": "Ali", "role": "reader"}
    assert first["at"] == (NOW - timedelta(minutes=1)).isoformat()
    assert (first["others"], first["others_more"], first["names"]) == (2, False, ["Ali", "Bea", "Cem"])
    assert (got[2]["others"], got[2]["names"]) == (0, ["Dan"])


async def test_a_long_run_says_more(admin_client):
    for n in range(activity_api.SIGNINS_MAX + 3):
        await _signed_in(await add_user(f"user{n:02d}"), n + 1)
    (run,) = await _items(admin_client)
    assert run["others"] == activity_api.SIGNINS_MAX - 1 and run["others_more"] is True
    assert len(run["names"]) == 6


async def test_older_signins_have_no_slot(admin_client):
    ben = await add_user("ben", "admin")
    for ago in (1, 2, 3):
        await _entry("catalog.followed", ago, actor=ben, target=("product", f"p{ago}", "P"))
    await _signed_in(await add_user("old"), 60)
    assert [i["action"] for i in await _items(admin_client)] == ["catalog.followed"] * 3


async def test_a_fixed_number_of_statements(admin_client):
    ben = await add_user("ben", "admin")
    async with db.session() as s:
        s.add_all(
            AuditEntry(at=NOW - timedelta(seconds=n), actor_kind="user", actor_id=ben.id, actor_name="ben", action=a, target_type="user", target_id=str(ben.id), target_label="ben", details={})
            for n in range(600)
            for a in (activity_api.ACTIONS[n % len(activity_api.ACTIONS)], "settings.changed")
        )
        await s.commit()
    for n in range(30):
        await _signed_in(await add_user(f"r{n}"), n / 10)
    statements: list[str] = []

    def count(conn, cursor, stmt, *a):  # noqa: ANN001, ANN202
        if stmt.lstrip().upper().startswith("SELECT") and ("audit_log" in stmt or "FROM users" in stmt):
            statements.append(stmt)

    eng = db.engine().sync_engine
    event.listen(eng, "before_cursor_execute", count)
    try:
        got = await _items(admin_client, 10)
    finally:
        event.remove(eng, "before_cursor_execute", count)
    assert len(got) == 10
    # the session's own lookup of the signed-in admin, the entries, the sign-ins, the accounts' names, what waits
    assert len(statements) <= 5, statements
    assert sum("audit_log" in s for s in statements) == 1
