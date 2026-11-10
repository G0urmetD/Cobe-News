""""Zweiten Faktor auf dem Gerät merken" (app/auth/devices.py): off by default – no switch at the TOTP step, no cookie
honoured; on – a remembered browser skips only the TOTP step and only after the right password; another person's
cookie, an expired, forgotten or shortened one, a changed password, TOTP or role, the switch off: the code again. The
cookie's flags, only a hash stored, the audit entries, the lists and the admin's "vergessen"."""

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
from conftest import PASSWORD, add_user, make_client, sign_in
from fastapi import Response
from sqlalchemy import select, update

from app import config, db
from app import settings as settings_store
from app.auth import devices, passwords, sessions
from app.crypto import encrypt_str, token_hash
from app.models import AuditEntry, RememberedDevice, User, UserSession

DEVICE = "cobe_news_device"
NEW_PASSWORD = "Ein-neues-langes-Passwort-2026"  # test fixture only


async def _setup(**mfa) -> None:  # noqa: ANN003
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await settings_store.put(s, "mfa", {**settings_store.DEFAULTS["mfa"], **mfa})
        await s.commit()


async def _code(user_id, secret: str) -> str:  # noqa: ANN001
    """A fresh code: the step a test used already is forgotten (each code counts once)."""
    async with db.session() as s:
        await s.execute(update(User).where(User.id == user_id).values(totp_last_step=None))
        await s.commit()
    return pyotp.TOTP(secret).now()


async def _login(c, name: str, password: str = PASSWORD) -> dict:  # noqa: ANN001
    return (await c.post("/api/auth/login", json={"username": name, "password": password})).json()


async def _remembered(c, user, secret: str) -> str:  # noqa: ANN001
    """Signed in with the code and "Auf diesem Gerät merken", signed out again – the device cookie's value."""
    assert await _login(c, user.username) == {"next": "mfa"}
    r = await c.post("/api/auth/mfa", json={"code": await _code(user.id, secret), "remember": True})
    assert r.json()["next"] == "done", r.text
    token = c.cookies.get(DEVICE)
    assert token
    await c.post("/api/auth/logout")
    return token


async def _rows(user_id=None) -> list[RememberedDevice]:  # noqa: ANN001
    async with db.session() as s:
        q = select(RememberedDevice)
        if user_id is not None:
            q = q.where(RememberedDevice.user_id == user_id)
        return list(await s.scalars(q))


async def _entries(action: str) -> list[AuditEntry]:
    async with db.session() as s:
        return list(await s.scalars(select(AuditEntry).where(AuditEntry.action == action).order_by(AuditEntry.id)))


async def _method(c) -> str:  # noqa: ANN001
    return next(r["method"] for r in (await c.get("/api/me/sessions")).json() if r["current"])


async def _user(uid) -> User:  # noqa: ANN001
    async with db.session() as s:
        return await s.get(User, uid)


async def _reauth_at(user_id, at: datetime) -> None:  # noqa: ANN001
    async with db.session() as s:
        await s.execute(update(UserSession).where(UserSession.user_id == user_id).values(reauth_at=at))
        await s.commit()


# ---------------------------------------------------------------- off (the default)


async def test_off_no_switch_and_no_cookie_honoured(client):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret)
    await _setup()
    assert await _login(client, "tina") == {"next": "mfa"}
    assert (await client.get("/api/auth/state")).json() == {"stage": "mfa"}  # no switch offered
    r = await client.post("/api/auth/mfa", json={"code": await _code(u.id, secret), "remember": True})
    assert r.json()["next"] == "done" and DEVICE not in r.headers.get("set-cookie", "")
    assert await _rows() == []
    # a cookie of a device remembered while it was on: not honoured while off
    await _setup(remember=True)
    async with make_client() as c:
        await _remembered(c, u, secret)
        await _setup(remember=False)
        assert await _login(c, "tina") == {"next": "mfa"}


# ---------------------------------------------------------------- on


async def test_remembered_browser_skips_only_the_code_after_the_right_password(client):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret)
    await _setup(remember=True)
    assert await _login(client, "tina") == {"next": "mfa"}
    st = (await client.get("/api/auth/state")).json()
    assert st["stage"] == "mfa" and st["remember"]["offer"] is True and st["remember"]["device"] is False
    until = datetime.fromisoformat(st["remember"]["until"])
    assert timedelta(hours=11, minutes=59) < until - datetime.now(UTC) <= timedelta(hours=12)  # the session lifetime
    # the switch not ticked: nothing remembered
    r = await client.post("/api/auth/mfa", json={"code": await _code(u.id, secret)})
    assert r.json()["next"] == "done" and not client.cookies.get(DEVICE) and await _rows() == []
    await client.post("/api/auth/logout")
    await _remembered(client, u, secret)
    # a wrong password is a wrong password – the device does not stand in for it
    r = await client.post("/api/auth/login", json={"username": "tina", "password": "falsch-falsch-falsch"})
    assert r.status_code == 401 and r.json()["detail"]["code"] == "invalid_credentials"
    # the right one: signed in, no code
    r = await _login(client, "tina")
    assert r["next"] == "done" and r["user"]["username"] == "tina"
    assert await _method(client) == "password_device"
    [row] = await _rows(u.id)
    assert row.last_used_at is not None
    # the device list marks this browser
    [d] = (await client.get("/api/auth/devices")).json()
    assert d["current"] is True and set(d) == {"id", "current", "created_at", "expires_at", "last_used_at", "ip", "user_agent"}


async def test_cookie_flags_and_only_a_hash_stored(client, monkeypatch):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret)
    await _setup(remember=True, remember_days=7)
    assert await _login(client, "tina") == {"next": "mfa"}
    r = await client.post("/api/auth/mfa", json={"code": await _code(u.id, secret), "remember": True})
    [h] = [x for x in r.headers.get_list("set-cookie") if x.startswith(f"{DEVICE}=")]
    low = h.lower()
    assert "httponly" in low and "samesite=strict" in low and "path=/api/auth" in low and f"max-age={7 * 86400}" in low
    token = client.cookies.get(DEVICE)
    [row] = await _rows(u.id)
    assert row.token_hash == token_hash(token) and token not in row.token_hash and len(token) >= 40
    assert row.factor not in (token, token_hash(token))
    # Secure, with the __Secure- prefix, where the session cookie is Secure
    secure = dataclasses.replace(config.get_config(), cookie_secure=True)
    monkeypatch.setattr(devices, "get_config", lambda: secure)
    resp = Response()
    devices.set_cookie(resp, "x" * 43, 3600)
    h = resp.headers["set-cookie"]
    assert h.startswith("__Secure-cobe_news_device=") and "Secure" in h and "HttpOnly" in h and "Path=/api/auth" in h


async def test_another_persons_cookie_is_ignored(client):
    s1, s2 = pyotp.random_base32(), pyotp.random_base32()
    tina = await add_user("tina", totp_secret=s1)
    await add_user("otto", totp_secret=s2)
    await _setup(remember=True)
    token = await _remembered(client, tina, s1)
    async with make_client() as c:
        c.cookies.set(DEVICE, token, domain="news.test", path="/api/auth")
        assert await _login(c, "otto") == {"next": "mfa"}
    assert len(await _rows(tina.id)) == 1  # tina's row untouched


async def test_expired_shortened_or_forgotten_asks_again(client):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret)
    await _setup(remember=True, remember_days=30)
    await _remembered(client, u, secret)
    # expired by its own end: asked, the row is gone
    async with db.session() as s:
        await s.execute(update(RememberedDevice).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        await s.commit()
    assert await _login(client, "tina") == {"next": "mfa"}
    assert await _rows() == []
    await client.post("/api/auth/logout")
    # a shorter duration counts at once (measured from when it was remembered)
    await _remembered(client, u, secret)
    async with db.session() as s:
        await s.execute(update(RememberedDevice).values(created_at=datetime.now(UTC) - timedelta(days=2)))
        await s.commit()
    assert (await _login(client, "tina"))["next"] == "done"
    await client.post("/api/auth/logout")
    await _setup(remember=True, remember_days=1)
    assert await _login(client, "tina") == {"next": "mfa"}
    await client.post("/api/auth/logout")
    # forgotten by the person: asked again
    await _setup(remember=True, remember_days=7)
    await _remembered(client, u, secret)
    assert (await _login(client, "tina"))["next"] == "done"
    [d] = (await client.get("/api/auth/devices")).json()
    assert d["current"] is True
    r = await client.delete(f"/api/auth/devices/{d['id']}")
    assert r.json() == {"ok": True} and any(h.startswith(f"{DEVICE}=") for h in r.headers.get_list("set-cookie"))
    assert (await client.delete(f"/api/auth/devices/{d['id']}")).status_code == 404
    await client.post("/api/auth/logout")
    assert await _login(client, "tina") == {"next": "mfa"}


async def test_changed_factors_ask_again(client):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret)
    await _setup(remember=True)
    # a new TOTP secret
    await _remembered(client, u, secret)
    secret = pyotp.random_base32()
    async with db.session() as s:
        await s.execute(update(User).where(User.id == u.id).values(totp_secret_enc=encrypt_str(secret)))
        await s.commit()
    assert await _login(client, "tina") == {"next": "mfa"}
    await client.post("/api/auth/logout")
    # a new password hash (written behind the app's back – the fingerprint alone decides)
    await _remembered(client, u, secret)
    async with db.session() as s:
        await s.execute(update(User).where(User.id == u.id).values(password_hash=passwords.hash_password(PASSWORD)))
        await s.commit()
    assert await _login(client, "tina") == {"next": "mfa"}
    await client.post("/api/auth/logout")
    # a new role
    await _remembered(client, u, secret)
    async with db.session() as s:
        await s.execute(update(User).where(User.id == u.id).values(role="admin"))
        await s.commit()
    await _setup(remember=True, remember_admins=True)
    assert await _login(client, "tina") == {"next": "mfa"}
    await client.post("/api/auth/logout")
    # the own password change: every device forgotten with the other sessions
    await _remembered(client, u, secret)
    async with make_client() as c:
        await sign_in(c, await _user(u.id))
        r = await c.post("/api/me/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
        assert r.json() == {"ok": True}
    assert await _rows() == []


async def test_end_all_sessions_block_and_reset_forget(admin_client):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret)
    await _setup(remember=True)
    async with make_client() as c, make_client() as other:
        await _remembered(c, u, secret)
        await sign_in(other, u)
        assert (await other.post("/api/me/sessions/end-others")).json()["ok"] is True
        assert await _rows() == []
        assert await _login(c, "tina") == {"next": "mfa"}
        await c.post("/api/auth/logout")
        await _remembered(c, u, secret)
    # the admin blocks the account
    r = await admin_client.post(f"/api/admin/users/{u.id}/block", json={"blocked": True})
    assert r.status_code == 200 and await _rows() == []
    await admin_client.post(f"/api/admin/users/{u.id}/block", json={"blocked": False})
    async with make_client() as c:
        await _remembered(c, u, secret)
    # the admin resets the TOTP
    r = await admin_client.post(f"/api/admin/users/{u.id}/reset", json={"password": False, "totp": True})
    assert r.status_code == 200 and await _rows() == []
    # the admin ends all sessions
    secret = pyotp.random_base32()
    async with db.session() as s:
        await s.execute(update(User).where(User.id == u.id).values(totp_secret_enc=encrypt_str(secret)))
        await s.commit()
    async with make_client() as c:
        await _remembered(c, u, secret)
    assert (await admin_client.post(f"/api/admin/users/{u.id}/sessions/end-all")).json()["ok"] is True
    assert await _rows() == []
    [e] = [e for e in await _entries("device.forgotten") if e.details["by_admin"]]
    assert e.details == {"scope": "all", "count": 1, "by_admin": True} and e.actor_id == admin_client.user.id


async def test_switch_off_forgets_everybody_and_admins_only_when_included(admin_client):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret)
    await _setup(remember=True)
    async with make_client() as c:
        await _remembered(c, u, secret)
    # an admin: not offered while admins are excluded
    asecret = pyotp.random_base32()
    a = await add_user("adam", "admin", totp_secret=asecret)
    async with make_client() as c:
        assert await _login(c, "adam") == {"next": "mfa"}
        assert "remember" not in (await c.get("/api/auth/state")).json()
        r = await c.post("/api/auth/mfa", json={"code": await _code(a.id, asecret), "remember": True})
        assert r.json()["next"] == "done" and not c.cookies.get(DEVICE)
    cur = (await admin_client.get("/api/admin/auth/mfa")).json()
    assert cur["remember"] is True and cur["remember_admins"] is False and cur["remember_days"] == 0
    r = await admin_client.put("/api/admin/auth/mfa", json={"required_all": False, "remember": True, "remember_admins": True, "rev": cur["rev"]})
    assert r.json()["remember_admins"] is True
    async with make_client() as c:
        await _remembered(c, a, asecret)
        assert (await _login(c, "adam"))["next"] == "done"
        assert await _method(c) == "password_device"
        # a remembered sign-in is no fresh proof of identity: sensitive actions want the code
        r = await c.put("/api/admin/auth/sessions", json={"idle_min": 60, "absolute_h": 12})
        assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
        [e] = [e for e in await _entries("login.success") if e.details.get("method") == "password_device"]
        assert e.target_id == str(a.id)
        await c.post("/api/auth/logout")
        # admins excluded again: theirs are forgotten, the readers' stay
        r = await admin_client.put("/api/admin/auth/mfa", json={"required_all": False, "remember_admins": False})
        assert r.status_code == 200
        assert {x.user_id for x in await _rows()} == {u.id}
        assert await _login(c, "adam") == {"next": "mfa"}
        await c.post("/api/auth/logout")
    # switched off: all forgotten, logged with the count
    r = await admin_client.put("/api/admin/auth/mfa", json={"required_all": False, "remember": False})
    assert r.json()["remember"] is False and await _rows() == []
    e = (await _entries("signin.config_changed"))[-1]
    assert e.details["changes"]["remember"] == {"from": True, "to": False} and e.details["devices_forgotten"] == 1
    # only the durations offered
    assert (await admin_client.put("/api/admin/auth/mfa", json={"required_all": False, "remember_days": 90})).status_code == 422


async def test_emergency_account_is_never_remembered(client):
    secret = pyotp.random_base32()
    em = await add_user("notfall", "admin", totp_secret=secret, emergency=True)
    await _setup(remember=True, remember_admins=True)
    assert await _login(client, "notfall") == {"next": "mfa"}
    assert "remember" not in (await client.get("/api/auth/state")).json()
    r = await client.post("/api/auth/mfa", json={"code": await _code(em.id, secret), "remember": True})
    assert r.json()["next"] == "done" and await _rows() == []


async def test_temporary_password_is_replaced_first_and_the_device_stands_on_the_new_one(client):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret, must_change_password=True, temp_password_at=datetime.now(UTC))
    await _setup(remember=True)
    assert await _login(client, "tina") == {"next": "mfa"}
    r = await client.post("/api/auth/mfa", json={"code": await _code(u.id, secret), "remember": True})
    assert r.json() == {"next": "password"} and not client.cookies.get(DEVICE) and await _rows() == []
    r = await client.post("/api/auth/password", json={"new_password": NEW_PASSWORD})
    assert r.json()["next"] == "done" and client.cookies.get(DEVICE)
    await client.post("/api/auth/logout")
    assert (await _login(client, "tina", NEW_PASSWORD))["next"] == "done"


async def test_required_for_all_a_remembered_reader_is_not_sent_to_the_set_up(client):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret)
    await _setup(remember=True, required_all=True)
    await _remembered(client, u, secret)
    assert (await _login(client, "tina"))["next"] == "done"


async def test_entra_own_totp_the_page_asks_with_the_device(client):
    """Entra: back from Microsoft without the SameSite=Strict cookie – the TOTP step's page asks POST /auth/mfa/device."""
    secret = pyotp.random_base32()
    await _setup(remember=True)
    async with db.session() as s:
        u = User(username="erika@corp.example", display_name="Erika", role="reader", auth_source="entra", external_id=str(uuid.uuid4()), totp_secret_enc=encrypt_str(secret))
        s.add(u)
        await s.commit()

    async def mfa_session(c) -> None:  # noqa: ANN001 - what the callback leaves: a session in stage mfa
        async with db.session() as s:
            sess, _ = await sessions.create(s, await s.get(User, u.id), "pre", "127.0.0.1", "pytest", method="entra")
            token = await sessions.promote(s, sess, "mfa")
            await s.commit()
        c.cookies.set(sessions.cookie_name(), token)

    await mfa_session(client)
    r = await client.post("/api/auth/mfa/device")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "device_unknown"
    r = await client.post("/api/auth/mfa", json={"code": await _code(u.id, secret), "remember": True})
    assert r.json()["next"] == "done" and client.cookies.get(DEVICE)
    assert await _method(client) == "entra_totp"
    await client.post("/api/auth/logout")
    await mfa_session(client)
    assert (await client.get("/api/auth/state")).json()["remember"]["device"] is True
    assert (await client.post("/api/auth/mfa/device")).json()["next"] == "done"
    assert await _method(client) == "entra_device"
    # only from the TOTP step: an active session has nothing to skip
    assert (await client.post("/api/auth/mfa/device")).status_code == 403


async def test_admin_lists_and_forgets_a_users_devices(admin_client):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret)
    await _setup(remember=True)
    async with make_client() as c:
        await _remembered(c, u, secret)
    [d] = (await admin_client.get(f"/api/admin/users/{u.id}/devices")).json()
    assert d["current"] is False
    async with make_client() as rc:
        await sign_in(rc, u)
        assert (await rc.get(f"/api/admin/users/{u.id}/devices")).status_code == 403
        assert (await rc.post(f"/api/admin/users/{u.id}/devices/forget-all")).status_code == 403
    await _reauth_at(admin_client.user.id, datetime.now(UTC) - timedelta(hours=1))
    r = await admin_client.post(f"/api/admin/users/{u.id}/devices/forget-all")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    await _reauth_at(admin_client.user.id, datetime.now(UTC))
    assert (await admin_client.post(f"/api/admin/users/{u.id}/devices/forget-all")).json() == {"ok": True, "forgotten": 1}
    assert await _rows() == []


async def test_audit_entries(client):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret)
    await _setup(remember=True)
    token = await _remembered(client, u, secret)
    [e] = await _entries("device.remembered")
    assert e.target_id == str(u.id) and set(e.details) == {"device", "until"} and token not in str(e.details)
    async with make_client() as c:
        await sign_in(c, u)
        assert (await c.post("/api/auth/devices/forget-all")).json() == {"ok": True, "forgotten": 1}
        [e] = await _entries("device.forgotten")
        assert e.details == {"scope": "all", "count": 1, "by_admin": False}
        # nothing to forget: no entry
        await c.post("/api/auth/devices/forget-all")
    assert len(await _entries("device.forgotten")) == 1


async def test_hourly_cleanup_removes_expired_devices(client):
    secret = pyotp.random_base32()
    u = await add_user("tina", totp_secret=secret)
    await _setup(remember=True)
    await _remembered(client, u, secret)
    async with db.session() as s:
        await s.execute(update(RememberedDevice).values(expires_at=datetime.now(UTC) - timedelta(minutes=1)))
        await s.commit()
        await sessions.cleanup(s)
    assert await _rows() == []
