"""Sign-in: the one-time setup token, local accounts (password, TOTP – required for admins), temporary passwords,
lockout per account and address, CSRF, sessions, and the role check on every write endpoint."""

import re
import time
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from conftest import PASSWORD, add_user, make_client, sign_in
from sqlalchemy import select, update

from app import db, settings as settings_store
from app.auth import bruteforce
from app.auth_api import issue_setup_token
from app.crypto import decrypt_str
from app.models import UserSession


def code(secret: str, offset: int = 0) -> str:
    return pyotp.TOTP(secret).at(time.time() + offset * 30)


async def _token() -> str:
    async with db.session() as s:
        return await issue_setup_token(s)


async def test_setup_token_creates_the_emergency_admin_once(client):
    assert (await client.get("/api/auth/config")).json()["setup_required"] is True
    assert (await client.post("/api/auth/login", json={"username": "x", "password": "y"})).json()["detail"]["code"] == "setup_required"
    token = await _token()
    body = {"token": token, "username": "Notfall", "display_name": "Notfall-Admin", "password": PASSWORD}
    assert (await client.post("/api/setup", json={**body, "token": "AAAA-BBBB-CCCC-DDDD"})).status_code == 401
    assert (await client.post("/api/setup", json={**body, "password": "kurz"})).json()["detail"]["rules"] == ["min_length"]
    assert (await client.post("/api/setup", json={**body, "password": "password1234"})).json()["detail"]["rules"] == ["common"]
    r = await client.post("/api/setup", json={**body, "token": token.lower().replace("-", " ")})  # typed loosely
    assert r.json() == {"next": "enroll"}
    # TOTP is required for the admin: set it up, then signed in
    st = (await client.post("/api/auth/enroll/start")).json()
    assert st["uri"].startswith("otpauth://totp/") and "Cobe%20News" in st["uri"]
    assert (await client.post("/api/auth/enroll/confirm", json={"code": "000000"})).status_code == 401
    done = (await client.post("/api/auth/enroll/confirm", json={"code": code(st["secret"])})).json()
    assert done["next"] == "done" and done["user"]["role"] == "admin" and done["user"]["is_emergency"] and done["user"]["totp"]
    assert (await client.get("/api/me")).json()["username"] == "notfall"
    # single use: the same token (and any other) does nothing any more
    async with make_client() as other:
        assert (await other.post("/api/setup", json=body)).json()["detail"]["code"] == "setup_completed"
    async with db.session() as s:
        assert (await settings_store.get(s, "setup"))["token_hash"] == ""
        assert await issue_setup_token(s) is None  # no new token after the setup


async def test_admin_needs_totp_reader_does_not(client):
    secret = pyotp.random_base32()
    await add_user("anna", "admin", totp_secret=secret)
    await add_user("rudi", "reader")
    await add_user("ida", "admin")  # an admin without TOTP yet
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    r = await client.post("/api/auth/login", json={"username": "Anna", "password": PASSWORD})
    assert r.json() == {"next": "mfa"}
    assert (await client.get("/api/me")).status_code == 401  # not signed in before the code
    assert (await client.post("/api/auth/mfa", json={"code": code(secret)})).json()["user"]["role"] == "admin"
    assert (await client.get("/api/me")).json()["username"] == "anna"
    # the same code twice: replay refused
    async with make_client() as c2:
        assert (await c2.post("/api/auth/login", json={"username": "anna", "password": PASSWORD})).json() == {"next": "mfa"}
        assert (await c2.post("/api/auth/mfa", json={"code": code(secret)})).status_code == 401
    async with make_client() as c3:
        assert (await c3.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).json()["next"] == "done"
    async with make_client() as c4:
        assert (await c4.post("/api/auth/login", json={"username": "ida", "password": PASSWORD})).json() == {"next": "enroll"}
        assert (await c4.get("/api/news")).status_code == 401
    # logout ends the session in the database
    assert (await client.post("/api/auth/logout")).status_code == 200
    assert (await client.get("/api/me")).status_code == 401


async def test_temporary_password_and_admin_user_management(admin_client):
    r = await admin_client.post("/api/admin/users", json={"username": "lena", "display_name": "Lena", "role": "reader"})
    assert r.status_code == 200 and r.json()["must_change_password"]
    tmp = r.json()["temp_password"]
    uid = r.json()["id"]
    assert (await admin_client.post("/api/admin/users", json={"username": "LENA"})).status_code == 409
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    async with make_client() as lena:
        assert (await lena.post("/api/auth/login", json={"username": "lena", "password": tmp})).json() == {"next": "password"}
        assert (await lena.get("/api/news")).status_code == 401
        assert (await lena.post("/api/auth/password", json={"new_password": tmp})).status_code == 400  # not the same again
        assert (await lena.post("/api/auth/password", json={"new_password": PASSWORD + "!"})).json()["next"] == "done"
        assert (await lena.get("/api/news")).status_code == 200
        # optional TOTP for a reader: on and off again
        # setting it up (or replacing it) needs the password first – a session left open is not enough
        assert (await lena.post("/api/me/totp/start", json={})).status_code == 401
        assert (await lena.post("/api/me/totp/start", json={"password": "falsch-falsch"})).status_code == 401
        st = (await lena.post("/api/me/totp/start", json={"password": PASSWORD + "!"})).json()
        assert (await lena.post("/api/me/totp/confirm", json={"code": code(st["secret"])})).json()["totp"] is True
        # removing it needs the current code (the password is not enough any more)
        assert (await lena.post("/api/me/totp/remove", json={"password": PASSWORD + "!"})).status_code == 401
        assert (await lena.post("/api/me/totp/remove", json={"code": code(st["secret"], 1)})).json()["totp"] is False
        # switched off by the admin: the session ends at once
        assert (await admin_client.patch(f"/api/admin/users/{uid}", json={"is_active": False})).json()["is_active"] is False
        assert (await lena.get("/api/news")).status_code == 401
    # the admin keeps the TOTP; oneself and the emergency admin are protected
    assert (await admin_client.post("/api/me/totp/remove", json={})).json()["detail"]["code"] == "totp_required"
    me = admin_client.user.id
    assert (await admin_client.patch(f"/api/admin/users/{me}", json={"role": "reader"})).status_code == 409
    assert (await admin_client.delete(f"/api/admin/users/{me}")).status_code == 409
    em = await add_user("notfall", "admin", emergency=True, totp_secret=pyotp.random_base32())
    for call in (
        admin_client.patch(f"/api/admin/users/{em.id}", json={"is_active": False}),
        admin_client.patch(f"/api/admin/users/{em.id}", json={"role": "reader"}),
        admin_client.post(f"/api/admin/users/{em.id}/reset", json={"password": True}),
        admin_client.delete(f"/api/admin/users/{em.id}"),
    ):
        assert (await call).json()["detail"]["code"] == "user_protected"
    # reset: new temporary password, TOTP removed
    r = (await admin_client.post(f"/api/admin/users/{uid}/reset", json={"password": True, "totp": True})).json()
    assert r["temp_password"] and r["must_change_password"] and not r["totp"]
    assert (await admin_client.delete(f"/api/admin/users/{uid}")).status_code == 200


async def test_lockout_per_account_and_address(client):
    await add_user("rudi")
    em = await add_user("notfall", "admin", emergency=True, totp_secret=pyotp.random_base32())
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    for left in (4, 3, 2, 1):
        r = await client.post("/api/auth/login", json={"username": "rudi", "password": "falsch-falsch-falsch"})
        assert r.status_code == 401 and r.json()["detail"]["attempts_left"] == left
    r = await client.post("/api/auth/login", json={"username": "rudi", "password": "falsch-falsch-falsch"})
    assert r.status_code == 423 and r.json()["detail"]["retry_after"] == 900
    # locked: even the right password does not help now
    assert (await client.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).status_code == 423
    # an unknown name answers like a known one (no hint which accounts exist)
    assert (await client.post("/api/auth/login", json={"username": "gibtsnicht", "password": "x"})).json()["detail"] == {"code": "invalid_credentials", "attempts_left": 4}
    # the emergency admin is never locked from outside …
    for _ in range(8):
        await client.post("/api/auth/login", json={"username": em.username, "password": "falsch-falsch-falsch"})
    assert (await client.post("/api/auth/login", json={"username": em.username, "password": PASSWORD})).json() == {"next": "mfa"}
    # … but the address is, once failures spread over many names (password spraying): 30 across at least 5 names
    for _ in range(16):
        await client.post("/api/auth/login", json={"username": "x" + str(_), "password": "y"})
    r = await client.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "ip_blocked"
    # the emergency admin's right password still works from that address (it may be everybody's address behind a
    # gateway) – a wrong one is still refused and counted
    assert (await client.post("/api/auth/login", json={"username": em.username, "password": "falsch-falsch-falsch"})).status_code in (401, 403)
    assert (await client.post("/api/auth/login", json={"username": em.username, "password": PASSWORD})).json() == {"next": "mfa"}
    bruteforce.reset()
    assert (await client.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).json()["next"] == "done"


async def test_client_address_only_from_the_bundled_proxy():
    """X-Forwarded-For counts only from the proxy's fixed address – a client cannot choose its own (lockout, logs)."""
    await add_user("rudi")
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    # straight to the app (not via nginx): the header is ignored, the failures count for the real peer
    async with make_client(client=("10.9.9.9", 5000)) as direct:
        for i in range(30):
            await direct.post("/api/auth/login", json={"username": f"u{i}", "password": "x"}, headers={"X-Forwarded-For": f"203.0.113.{i}"})
    assert bruteforce.ip_blocked("10.9.9.9") and not bruteforce.ip_blocked("203.0.113.5")
    bruteforce.reset()
    # via the bundled proxy (172.31.250.10): the address it reports
    async with make_client(client=("172.31.250.10", 5000)) as proxied:
        for i in range(30):
            await proxied.post("/api/auth/login", json={"username": f"u{i}", "password": "x"}, headers={"X-Forwarded-For": "198.51.100.7"})
    assert bruteforce.ip_blocked("198.51.100.7") and not bruteforce.ip_blocked("172.31.250.10")


async def test_csrf_and_cookies(reader_client):
    r = await reader_client.post("/api/news/read-all", json={}, headers={"X-CSRF-Token": "falsch"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "csrf_failed"
    assert (await reader_client.post("/api/news/read-all", json={})).status_code == 200
    async with make_client() as fresh:
        r = await fresh.get("/api/auth/config")
        cookie = r.headers["set-cookie"].lower()
        assert "cobe_news_csrf" in cookie and "samesite=strict" in cookie and "httponly" not in cookie
        # no token at all
        r = await fresh.request("POST", "/api/auth/logout", headers={"X-CSRF-Token": ""})
    await add_user("lisa")
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    async with make_client() as c:
        r = await c.post("/api/auth/login", json={"username": "lisa", "password": PASSWORD})
        sc = [h.lower() for h in r.headers.get_list("set-cookie") if h.startswith("cobe_news_session")][0]
        assert "httponly" in sc and "samesite=lax" in sc


async def test_session_idle_and_absolute_timeout(reader_client):
    assert (await reader_client.get("/api/me")).status_code == 200
    # absolute: 12 h after the sign-in, however active
    async with db.session() as s:
        await s.execute(update(UserSession).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        await s.commit()
    assert (await reader_client.get("/api/me")).status_code == 401
    await sign_in(reader_client, reader_client.user)
    assert (await reader_client.get("/api/me")).status_code == 200
    # idle: an hour without a request
    async with db.session() as s:
        await s.execute(update(UserSession).values(last_seen_at=datetime.now(UTC) - timedelta(minutes=61)))
        await s.commit()
    assert (await reader_client.get("/api/me")).status_code == 401
    async with db.session() as s:
        assert list(await s.scalars(select(UserSession))) == []


def _write_routes() -> list[tuple[str, str]]:
    from app.admin_api import router as admin_router
    from app.api import router as news_router
    from app.notify_api import router as notify_router
    from app.passkeys_api import admin_router as passkeys_admin
    from app.sessions_api import admin_router as sessions_admin

    out = []
    for r in [*admin_router.routes, *notify_router.routes, *news_router.routes, *passkeys_admin.routes, *sessions_admin.routes]:
        path = getattr(r, "path", "")
        for m in getattr(r, "methods", set()) or set():
            if m not in ("GET", "HEAD") and path.startswith("/api/admin"):
                out.append((m, path))
    return sorted(out)


ADMIN_WRITES = _write_routes()


def test_every_admin_write_route_is_listed():
    paths = {p for _, p in ADMIN_WRITES}
    for p in ("/api/admin/news/sources", "/api/admin/notify/rules", "/api/admin/users", "/api/admin/auth/ldap", "/api/admin/auth/mappings", "/api/admin/settings/news"):
        assert p in paths
    assert len(ADMIN_WRITES) >= 24


@pytest.mark.parametrize(("method", "path"), ADMIN_WRITES)
async def test_role_check_on_every_admin_write(method, path, reader_client):
    url = re.sub(r"\{[^}]+\}", "00000000-0000-0000-0000-000000000000", path)
    r = await reader_client.request(method, url, json={})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "forbidden", (method, path, r.text)
    async with make_client() as anon:
        r = await anon.request(method, url, json={})
        assert r.status_code == 401, (method, path, r.text)


async def test_admin_reads_are_admin_only(reader_client):
    for path in ("/api/admin/users", "/api/admin/notify/rules", "/api/admin/notify/smtp", "/api/admin/auth/ldap", "/api/admin/auth/entra", "/api/admin/tls", "/api/admin/news"):
        assert (await reader_client.get(path)).status_code == 403, path
    # a reader keeps their own things
    assert (await reader_client.put("/api/me/desktop", json={"enabled": True, "severities": ["critical"], "sources": []})).json()["enabled"] is True
    assert (await reader_client.get("/api/me/desktop")).json()["severities"] == ["critical"]


async def test_secrets_are_encrypted_and_masked(admin_client):
    r = await admin_client.put(
        "/api/admin/auth/ldap",
        json={"enabled": True, "servers": ["dc01.corp.example"], "bind_dn": "CN=svc,DC=corp,DC=example", "bind_password": "geheim-123"},
    )
    out = r.json()
    assert out["bind_password_set"] and "bind_password_enc" not in out and "geheim" not in r.text and out["base_dn"] == "DC=corp,DC=example"
    async with db.session() as s:
        stored = await settings_store.get(s, "ldap")
    assert "geheim" not in stored["bind_password_enc"] and decrypt_str(stored["bind_password_enc"]) == "geheim-123"
    # saved again without a password: the stored one stays
    r = await admin_client.put("/api/admin/auth/ldap", json={"enabled": True, "servers": ["dc01.corp.example"], "bind_dn": "CN=svc,DC=corp,DC=example"})
    async with db.session() as s:
        assert decrypt_str((await settings_store.get(s, "ldap"))["bind_password_enc"]) == "geheim-123"
    # clear-text LDAP only with the explicit switch
    assert (await admin_client.put("/api/admin/auth/ldap", json={"servers": ["dc01.corp.example"], "encryption": "none"})).json()["detail"]["code"] == "ldap_plain_refused"
    r = await admin_client.put("/api/admin/auth/entra", json={"enabled": True, "tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "AAAAAAAA-2222-3333-4444-555555555555", "client_secret": "s3cr3t"})
    assert r.json()["client_secret_set"] and "s3cr3t" not in r.text and r.json()["redirect_uri"] == "https://news.corp.example:8095/api/auth/oidc/callback"


async def _age_reauth(user_id) -> None:  # noqa: ANN001
    async with db.session() as s:
        await s.execute(update(UserSession).where(UserSession.user_id == user_id).values(reauth_at=datetime.now(UTC) - timedelta(hours=1)))
        await s.commit()


async def test_own_password_change_is_no_reauth_for_sensitive_actions():
    """Bug hunt 0.1.16 H4: /me/password needs only the current password – it must not count as the re-confirmation
    (password + TOTP) that creating an admin and the like demand – not even with the code it asks since 0.1.56."""
    secret = pyotp.random_base32()
    u = await add_user("anna", "admin", totp_secret=secret)
    async with make_client() as c:
        await sign_in(c, u)
        await _age_reauth(u.id)
        r = await c.post("/api/admin/users", json={"username": "evil", "role": "admin"})
        assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
        r = await c.post("/api/me/password", json={"current_password": PASSWORD, "new_password": "Ein-anderes-langes-Passwort-77", "code": pyotp.TOTP(secret).now()})
        assert r.status_code == 200
        r = await c.post("/api/admin/users", json={"username": "evil", "role": "admin"})
        assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
        assert (await c.get("/api/me")).status_code == 200  # the session itself goes on (new token in the cookie)


async def test_own_password_change_keeps_the_absolute_session_lifetime():
    """Bug hunt 0.1.16 L6: a password change re-keys the session but does not start its absolute lifetime over."""
    u = await add_user("rudi", "reader")
    async with make_client() as c:
        await sign_in(c, u)
        async with db.session() as s:
            await s.execute(update(UserSession).where(UserSession.user_id == u.id).values(created_at=datetime.now(UTC) - timedelta(hours=11, minutes=50)))
            await s.commit()
            old_hash = await s.scalar(select(UserSession.token_hash).where(UserSession.user_id == u.id))
        r = await c.post("/api/me/password", json={"current_password": PASSWORD, "new_password": "Ein-anderes-langes-Passwort-77"})
        assert r.status_code == 200
        async with db.session() as s:
            sess = await s.scalar(select(UserSession).where(UserSession.user_id == u.id))
        assert datetime.now(UTC) - sess.created_at > timedelta(hours=11)
        assert sess.token_hash != old_hash  # still re-keyed (no fixation)


async def test_an_outside_lock_does_not_stop_the_signed_in_owner():
    """Bug hunt 0.1.16 L6: five wrong passwords typed by anybody on the sign-in page lock the account – the owner who
    is already signed in can still change the password and set up TOTP (as /auth/reauth always could)."""
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    u = await add_user("rudi", "reader")
    async with make_client() as c:
        await sign_in(c, u)
        async with make_client(client=("203.0.113.9", 40000)) as attacker:
            for _ in range(5):
                await attacker.post("/api/auth/login", json={"username": "rudi", "password": "falsch"})
            assert (await attacker.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).status_code == 423
        r = await c.post("/api/me/totp/start", json={"password": PASSWORD})
        assert r.status_code == 200, r.text
        r = await c.post("/api/me/password", json={"current_password": PASSWORD, "new_password": "Ein-anderes-langes-Passwort-77"})
        assert r.status_code == 200, r.text


async def test_guessing_the_current_password_in_a_session_ends_it():
    """No account lock there – the session's own counter holds guessing instead: 5 misses end the session."""
    u = await add_user("rudi", "reader")
    async with make_client() as c:
        await sign_in(c, u)
        codes = [(await c.post("/api/me/password", json={"current_password": "falsch", "new_password": "Ein-anderes-langes-Passwort-77"})).status_code for _ in range(5)]
        assert codes[:4] == [401] * 4 and codes[4] == 401
        assert (await c.get("/api/me")).status_code == 401  # the session is over
    async with make_client() as c:  # the account itself is not locked by it
        await sign_in(c, u)


async def test_switching_an_admin_account_on_or_off_or_its_mail_needs_reauth():
    """Security review 0.1.16 L8 / bug hunt L6: like its role – switching another admin off or back on, or changing its
    e-mail, needs a fresh re-confirmation. A reader's account does not."""
    me = await add_user("anna", "admin", totp_secret=pyotp.random_base32())
    other = await add_user("bert", "admin", totp_secret=pyotp.random_base32(), is_active=False, deactivated_reason="admin")
    reader = await add_user("rudi", "reader")
    async with make_client() as c:
        await sign_in(c, me)
        await _age_reauth(me.id)
        for body in ({"is_active": True}, {"email": "bert@corp.example"}):
            r = await c.patch(f"/api/admin/users/{other.id}", json=body)
            assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required", body
        assert (await c.patch(f"/api/admin/users/{reader.id}", json={"is_active": False})).status_code == 200
        assert (await c.patch(f"/api/admin/users/{other.id}", json={"display_name": "Bert B."})).status_code == 200


def test_totp_codes_are_compared_in_constant_time(monkeypatch):
    from app.auth import totp

    calls = []
    real = totp.hmac.compare_digest
    monkeypatch.setattr(totp.hmac, "compare_digest", lambda a, b: calls.append((a, b)) or real(a, b))
    secret = pyotp.random_base32()
    assert totp.verify(secret, code(secret), None) is not None
    assert totp.verify(secret, "000000" if code(secret) != "000000" else "111111", None) is None
    assert calls  # every candidate step through hmac.compare_digest, never ==


async def test_cli_reset_emergency(capsys):
    """The recovery path: a new temporary password, TOTP gone, every session ended – and no bruteforce.unlock any more,
    which could only ever touch the CLI process's own (empty) counters, never the running app's."""
    from app import cli

    u = await add_user("notfall", "admin", totp_secret=pyotp.random_base32(), emergency=True)
    async with make_client() as c:
        await sign_in(c, u)
        assert (await c.get("/api/me")).status_code == 200
        assert await cli._account("reset-emergency") == 0
        assert (await c.get("/api/me")).status_code == 401
    pw = re.search(r"temporary password (\S+)", capsys.readouterr().out).group(1)
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    async with make_client() as c:
        assert (await c.post("/api/auth/login", json={"username": "notfall", "password": pw})).json() == {"next": "password"}
    async with db.session() as s:
        row = await s.get(type(u), u.id)
        assert row.totp_secret_enc is None and row.must_change_password
    assert not hasattr(cli, "bruteforce")
