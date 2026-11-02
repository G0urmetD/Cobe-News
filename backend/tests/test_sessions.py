"""Meine Sitzungen (app/sessions_api.py): only the own sessions, ending one or all others, the admins' view (re-confirmed),
ended at once, the sign-in method of each session and the throttled "last active"."""

import time
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
from conftest import PASSWORD, add_user, make_client, sign_in
from sqlalchemy import select, update

from app import db
from app import settings as settings_store
from app.auth import sessions
from app.models import User, UserSession


async def _age_reauth(user_id) -> None:  # noqa: ANN001
    async with db.session() as s:
        await s.execute(update(UserSession).where(UserSession.user_id == user_id).values(reauth_at=datetime.now(UTC) - timedelta(hours=1)))
        await s.commit()


async def test_own_sessions_only_and_current_first(reader_client):
    other = await add_user("otto")
    async with make_client() as c2, make_client() as oc:
        await sign_in(c2, reader_client.user)
        await sign_in(oc, other)
        rows = (await reader_client.get("/api/me/sessions")).json()
        assert len(rows) == 2 and rows[0]["current"] and not rows[1]["current"]
        assert {r["ip"] for r in rows} == {"127.0.0.1"} and rows[0]["user_agent"] == "pytest"
        assert set(rows[0]) == {"id", "current", "stage", "method", "passkey", "created_at", "last_seen_at", "expires_at", "ip", "user_agent"}
        # another person's session: neither listed nor endable
        theirs = (await oc.get("/api/me/sessions")).json()[0]["id"]
        assert theirs not in {r["id"] for r in rows}
        assert (await reader_client.delete(f"/api/me/sessions/{theirs}")).status_code == 404
        assert (await oc.get("/api/me")).status_code == 200


async def test_end_one_and_all_others_take_effect_at_once(reader_client):
    async with make_client() as c2, make_client() as c3:
        await sign_in(c2, reader_client.user)
        await sign_in(c3, reader_client.user)
        rows = (await reader_client.get("/api/me/sessions")).json()
        mine = next(r["id"] for r in rows if r["current"])
        r = await reader_client.delete(f"/api/me/sessions/{mine}")
        assert r.status_code == 409 and r.json()["detail"]["code"] == "current_session"
        c2_id = next(r["id"] for r in (await c2.get("/api/me/sessions")).json() if r["current"])
        assert (await reader_client.delete(f"/api/me/sessions/{c2_id}")).json() == {"ok": True}
        assert (await c2.get("/api/me")).status_code == 401  # the very next request
        assert (await c3.get("/api/me")).status_code == 200
        assert (await reader_client.post("/api/me/sessions/end-others")).json() == {"ok": True, "ended": 1}
        assert (await c3.get("/api/me")).status_code == 401
        assert (await reader_client.get("/api/me")).status_code == 200
        assert len((await reader_client.get("/api/me/sessions")).json()) == 1


async def test_ended_sessions_are_not_listed(reader_client):
    async with make_client() as c2:
        await sign_in(c2, reader_client.user)
        async with db.session() as s:
            await s.execute(update(UserSession).where(UserSession.user_agent == "pytest").values(last_seen_at=datetime.now(UTC) - timedelta(minutes=30)))
            await s.commit()
        cid = next(r["id"] for r in (await reader_client.get("/api/me/sessions")).json() if r["current"])
        async with db.session() as s:
            await s.execute(update(UserSession).where(UserSession.id != uuid.UUID(cid)).values(last_seen_at=datetime.now(UTC) - timedelta(hours=2)))
            await s.commit()
        assert [r["id"] for r in (await reader_client.get("/api/me/sessions")).json()] == [cid]


async def test_sign_in_method_is_recorded(client):
    secret = pyotp.random_base32()
    await add_user("rudi")
    await add_user("tina", totp_secret=secret)
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    assert (await client.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).json()["next"] == "done"
    assert [r["method"] for r in (await client.get("/api/me/sessions")).json()] == ["password"]
    async with make_client() as c:
        assert (await c.post("/api/auth/login", json={"username": "tina", "password": PASSWORD})).json() == {"next": "mfa"}
        # under way: listed for the person, marked by its stage
        async with make_client() as t2:
            await sign_in(t2, (await _user("tina")))
            rows = (await t2.get("/api/me/sessions")).json()
            assert sorted(r["stage"] for r in rows) == ["active", "mfa"]
        assert (await c.post("/api/auth/mfa", json={"code": pyotp.TOTP(secret).now()})).json()["next"] == "done"
        cur = next(r for r in (await c.get("/api/me/sessions")).json() if r["current"])
        assert cur["method"] == "password_totp"


async def _user(name: str):  # noqa: ANN202
    from app.models import User

    async with db.session() as s:
        return await s.scalar(select(User).where(User.username == name))


async def test_last_active_is_written_at_most_every_few_minutes(reader_client):
    async with db.session() as s:
        before = (await s.scalar(select(UserSession))).last_seen_at
    for _ in range(3):
        assert (await reader_client.get("/api/me")).status_code == 200
    async with db.session() as s:
        assert (await s.scalar(select(UserSession))).last_seen_at == before  # no write per request
        old = datetime.now(UTC) - sessions.TOUCH_INTERVAL - timedelta(seconds=5)
        await s.execute(update(UserSession).values(last_seen_at=old))
        await s.commit()
    assert (await reader_client.get("/api/me")).status_code == 200
    async with db.session() as s:
        seen = (await s.scalar(select(UserSession))).last_seen_at
    assert seen > old + timedelta(minutes=1) and abs(seen.timestamp() - time.time()) < 60


async def test_admin_sees_and_ends_a_users_sessions(admin_client, reader_client):
    uid = reader_client.user.id
    async with make_client() as c2:
        await sign_in(c2, reader_client.user)
        rows = (await admin_client.get(f"/api/admin/users/{uid}/sessions")).json()
        assert len(rows) == 2 and not any(r["current"] for r in rows)
        assert (await reader_client.get(f"/api/admin/users/{uid}/sessions")).status_code == 403
        await _age_reauth(admin_client.user.id)
        r = await admin_client.delete(f"/api/admin/users/{uid}/sessions/{rows[0]['id']}")
        assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
        r = await admin_client.post(f"/api/admin/users/{uid}/sessions/end-all")
        assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
        async with db.session() as s:
            await s.execute(update(UserSession).where(UserSession.user_id == admin_client.user.id).values(reauth_at=datetime.now(UTC)))
            await s.commit()
        # a session id of another account under this one's address: not found
        admin_sess = (await admin_client.get("/api/me/sessions")).json()[0]["id"]
        assert (await admin_client.delete(f"/api/admin/users/{uid}/sessions/{admin_sess}")).status_code == 409  # the own current one
        other = await add_user("otto")
        async with make_client() as oc:
            await sign_in(oc, other)
            otto_sess = (await oc.get("/api/me/sessions")).json()[0]["id"]
            assert (await admin_client.delete(f"/api/admin/users/{uid}/sessions/{otto_sess}")).status_code == 404
            assert (await oc.get("/api/me")).status_code == 200
        assert (await admin_client.delete(f"/api/admin/users/{uid}/sessions/{rows[0]['id']}")).json() == {"ok": True}
        assert (await admin_client.post(f"/api/admin/users/{uid}/sessions/end-all")).json() == {"ok": True, "ended": 1}
        assert (await c2.get("/api/me")).status_code == 401 and (await reader_client.get("/api/me")).status_code == 401
        # the admin's own account: everything but the current session
        async with make_client() as a2:
            await sign_in(a2, admin_client.user)
            assert (await admin_client.post(f"/api/admin/users/{admin_client.user.id}/sessions/end-all")).json()["ended"] == 1
            assert (await a2.get("/api/me")).status_code == 401
        assert (await admin_client.get("/api/me")).status_code == 200


async def test_password_change_and_block_still_end_sessions(admin_client, reader_client):
    async with make_client() as c2:
        await sign_in(c2, reader_client.user)
        r = await reader_client.post("/api/me/password", json={"current_password": PASSWORD, "new_password": "Ein-anderes-langes-Passwort-77"})
        assert r.status_code == 200
        assert (await c2.get("/api/me")).status_code == 401
        await sign_in(c2, reader_client.user)
        r = await admin_client.post(f"/api/admin/users/{reader_client.user.id}/block", json={"blocked": True})
        assert r.status_code == 200
        assert (await c2.get("/api/me")).status_code == 401 and (await reader_client.get("/api/me")).status_code == 401


# ---------------------------------------------------------------- the tabs' look at the session (GET /api/auth/session)


async def _last_seen() -> datetime:
    async with db.session() as s:
        return (await s.scalar(select(UserSession))).last_seen_at


async def _set_session(**values) -> None:
    async with db.session() as s:
        await s.execute(update(UserSession).values(**values))
        await s.commit()


async def test_session_status_tells_the_time_left_without_extending_it(reader_client):
    old = datetime.now(UTC) - timedelta(minutes=50)  # idle 60 min: ten left – and older than the touch interval
    await _set_session(last_seen_at=old)
    for _ in range(3):
        r = await reader_client.get("/api/auth/session")
        assert r.status_code == 200
        body = r.json()
        assert set(body) == {"idle_left_s", "absolute_left_s", "idle_min", "touch_s"}
        assert 9 * 60 < body["idle_left_s"] <= 10 * 60 and body["idle_min"] == 60 and body["touch_s"] == 300
        assert 11 * 3600 < body["absolute_left_s"] <= 12 * 3600
    assert await _last_seen() == old  # looking never keeps it alive
    # a real request does move it (throttled touch) – and the state tells the tabs the new time
    state = (await reader_client.get("/api/auth/state")).json()
    assert state["stage"] == "active" and state["session"]["idle_left_s"] > 59 * 60
    assert await _last_seen() > old + timedelta(minutes=45)


async def test_session_status_is_401_after_idle_or_absolute_end(reader_client):
    await _set_session(last_seen_at=datetime.now(UTC) - timedelta(minutes=61))
    r = await reader_client.get("/api/auth/session")
    assert r.status_code == 401 and r.json()["detail"]["code"] == "not_authenticated"
    async with db.session() as s:
        assert list(await s.scalars(select(UserSession))) == []  # over: gone, like with any other request
    await sign_in(reader_client, reader_client.user)
    assert (await reader_client.get("/api/auth/session")).status_code == 200
    # absolute: the lifetime as set now – a shorter one also ends a session begun before the change
    await _set_session(created_at=datetime.now(UTC) - timedelta(hours=3))
    async with db.session() as s:
        await settings_store.put(s, "sessions", {"idle_min": 60, "absolute_h": 2})
        await s.commit()
    assert (await reader_client.get("/api/auth/session")).status_code == 401
    await sign_in(reader_client, reader_client.user)
    await _set_session(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    assert (await reader_client.get("/api/auth/session")).status_code == 401


async def test_session_status_needs_an_active_session_but_no_csrf_token(client, reader_client):
    # nobody signed in, an unknown cookie, a sign-in still under way: 401
    assert (await client.get("/api/auth/session")).status_code == 401
    client.cookies.set(sessions.cookie_name(), "x" * 43)
    assert (await client.get("/api/auth/session")).status_code == 401
    u = await add_user("tina", totp_secret=pyotp.random_base32())
    async with make_client() as c:
        async with db.session() as s:
            _, token = await sessions.create(s, await s.get(User, u.id), "mfa", "127.0.0.1", "pytest")
            await s.commit()
        c.cookies.set(sessions.cookie_name(), token)
        assert (await c.get("/api/auth/state")).json() == {"stage": "mfa"}  # no times for a sign-in under way
        assert (await c.get("/api/auth/session")).status_code == 401
    # a plain GET without any CSRF cookie or header (a fresh client with only the session cookie)
    async with make_client() as bare:
        bare.cookies.set(sessions.cookie_name(), reader_client.cookies.get(sessions.cookie_name()))
        r = await bare.get("/api/auth/session")
        assert r.status_code == 200 and "x-csrf-token" not in {k.lower() for k in r.request.headers}


# ---------------------------------------------------------------- background requests (X-Cobe-Background: 1)

BG = {"X-Cobe-Background": "1"}


async def test_a_background_request_works_but_does_not_keep_the_session_alive(reader_client):
    old = datetime.now(UTC) - sessions.TOUCH_INTERVAL - timedelta(minutes=1)  # due for a "last active" write
    await _set_session(last_seen_at=old)
    for path in ("/api/me", "/api/reader/counts?scope=all", "/api/auth/state"):
        assert (await reader_client.get(path, headers=BG)).status_code == 200, path
    assert (await reader_client.post("/api/me/push/state", json={"endpoint": "https://push.example/x"}, headers=BG)).status_code == 200
    assert await _last_seen() == old
    # anything else than exactly "1" is an ordinary request
    assert (await reader_client.get("/api/me", headers={"X-Cobe-Background": "true"})).status_code == 200
    assert await _last_seen() > old + timedelta(minutes=5)


async def test_without_the_header_the_throttled_touch_is_unchanged(reader_client):
    recent = datetime.now(UTC) - timedelta(minutes=2)  # within TOUCH_INTERVAL: not written either way
    await _set_session(last_seen_at=recent)
    assert (await reader_client.get("/api/me")).status_code == 200
    assert await _last_seen() == recent
    old = datetime.now(UTC) - sessions.TOUCH_INTERVAL - timedelta(seconds=5)
    await _set_session(last_seen_at=old)
    assert (await reader_client.get("/api/me")).status_code == 200
    assert await _last_seen() > old + timedelta(minutes=4)


async def test_the_header_is_honoured_only_on_reading_requests_and_changes_nothing_else(reader_client):
    old = datetime.now(UTC) - sessions.TOUCH_INTERVAL - timedelta(minutes=1)
    await _set_session(last_seen_at=old)
    # a change is the person's own doing: it counts, header or not
    assert (await reader_client.put("/api/me/desktop", json={"enabled": False}, headers=BG)).status_code == 200
    assert await _last_seen() > old + timedelta(minutes=5)
    # the CSRF token is still required
    r = await reader_client.put("/api/me/desktop", json={"enabled": False}, headers={**BG, "X-CSRF-Token": ""})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "csrf_failed"
    # an ended session stays ended
    await _set_session(last_seen_at=datetime.now(UTC) - timedelta(minutes=61))
    r = await reader_client.get("/api/me", headers=BG)
    assert r.status_code == 401 and r.json()["detail"]["code"] == "not_authenticated"
