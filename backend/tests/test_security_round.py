"""Security/auth fix round: Web Push that one browser cannot hold up, shared client addresses (Docker Desktop), SMTP
targets, the emergency admin's brake, cookie prefixes, an all-or-nothing setup, VAPID keys that cannot be read,
optimistic concurrency of admin edits, re-confirmation for sensitive actions, directory accounts (role change, lock keys,
renames), session lifetimes, migration backups and the oldest schema."""

import asyncio
import dataclasses
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pyotp
import pytest
from conftest import PASSWORD, add_user, make_client
from sqlalchemy import select, update
from test_entra import ms  # noqa: F401 - fixture
from test_entra import _sign_in as entra_sign_in
from test_ldap import ANNA, OTTO, _login, _setup, ad  # noqa: F401 - fixture
from test_push import FCM, Browser, PushService, _desktop, _dispatch, _source, _stories

from app import auth_api, config, db, deps, netaddr, notify, webpush
from app import settings as settings_store
from app.auth import bruteforce, sessions
from app.auth import sync as directory_sync
from app.crypto import decrypt_str
from app.models import PushSubscription, User, UserSession

# ---------------------------------------------------------------- Web Push: one browser cannot hold up the others


@pytest.fixture
def service(monkeypatch):
    s = PushService()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(s.handler))
    return s


async def _subscribe(client, endpoint: str, b: Browser | None = None) -> Browser:
    b = b or Browser()
    r = await client.post("/api/me/push", json={"endpoint": endpoint, "keys": b.keys()})
    assert r.status_code == 200, r.text
    return b


async def test_slow_push_service_does_not_hold_up_the_others(reader_client, monkeypatch):
    slow = "https://fcm.googleapis.com/fcm/send/slow"
    seen: list[str] = []

    async def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        if str(req.url) == slow:
            await asyncio.sleep(5)
        return httpx.Response(201)

    monkeypatch.setattr(notify, "transport", httpx.MockTransport(handler))
    monkeypatch.setattr(webpush, "SUB_DEADLINE", 0.3)
    await _desktop(reader_client.user)
    await _subscribe(reader_client, slow)
    await _subscribe(reader_client, FCM)
    await _stories(await _source(), 1)
    t0 = time.monotonic()
    assert await _dispatch() == {"sent": 1, "failed": 1}
    assert time.monotonic() - t0 < 2
    async with db.session() as s:
        subs = {x.endpoint: x for x in await s.scalars(select(PushSubscription))}
    assert subs[slow].last_error == "timeout" and subs[slow].next_try_at is not None and subs[FCM].failures == 0


async def test_round_deadline_cancels_what_is_late(reader_client, monkeypatch):
    async def handler(req: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(201)

    monkeypatch.setattr(notify, "transport", httpx.MockTransport(handler))
    monkeypatch.setattr(webpush, "ROUND_DEADLINE", 0.3)
    await _desktop(reader_client.user)
    await _subscribe(reader_client, FCM)
    await _stories(await _source(), 1)
    t0 = time.monotonic()
    assert await _dispatch() == {"sent": 0, "failed": 1}
    assert time.monotonic() - t0 < 2


async def test_failing_subscription_goes_after_max_failures(reader_client, service, monkeypatch):
    monkeypatch.setattr(webpush, "MAX_FAILURES", 3)
    service.status = 500
    await _desktop(reader_client.user)
    await _subscribe(reader_client, FCM)
    src = await _source()
    for n in range(3):
        await _stories(src, 1, prefix=f"F{n}")
        assert await _dispatch() == {"sent": 0, "failed": 1}
        async with db.session() as s:
            sub = await s.scalar(select(PushSubscription))
            if n < 2:
                assert sub.failures == n + 1
                sub.next_try_at = datetime.now(UTC) - timedelta(seconds=1)
                await s.commit()
            else:
                assert sub is None  # removed – the browser hands it over again when still in use


async def test_no_burst_after_an_account_is_switched_on_again(reader_client, service):
    b = Browser()
    await _desktop(reader_client.user)
    await _subscribe(reader_client, FCM, b)
    src = await _source()
    async with db.session() as s:
        await s.execute(update(User).where(User.id == reader_client.user.id).values(is_active=False))
        await s.commit()
    await _stories(src, 5, prefix="Off")
    assert await _dispatch() == {} and service.requests == []
    async with db.session() as s:
        await s.execute(update(User).where(User.id == reader_client.user.id).values(is_active=True))
        await s.commit()
    assert await _dispatch() == {} and service.requests == []  # what arrived while switched off never comes
    await _stories(src, 1, prefix="On")
    assert await _dispatch() == {"sent": 1, "failed": 0}
    assert [b.read(r.content)["title"] for r in service.requests] == ["On 0"]


async def test_unreadable_vapid_key_is_replaced_and_old_subscriptions_go(reader_client, service, caplog):
    first = (await reader_client.get("/api/me/push")).json()["public_key"]
    await _subscribe(reader_client, FCM)
    async with db.session() as s:
        cfg = await settings_store.get(s, webpush.SECTION)
        await settings_store.put(s, webpush.SECTION, {**cfg, "private_enc": "v1:AAAA-not-a-key"})  # another SECRET_KEY
        await s.commit()
    webpush.reset_cache()
    info = (await reader_client.get("/api/me/push")).json()
    assert info["public_key"] and info["public_key"] != first and info["devices"] == 0
    assert "unreadable" in caplog.text
    # the new key is kept: the next process start uses the same one
    webpush.reset_cache()
    assert (await reader_client.get("/api/me/push")).json()["public_key"] == info["public_key"]


async def test_vapid_rotation_is_taken_at_once_and_concurrent_first_use_makes_one_key(reader_client):
    keys = await asyncio.gather(*(reader_client.get("/api/me/push") for _ in range(5)))
    assert len({k.json()["public_key"] for k in keys}) == 1
    await _subscribe(reader_client, FCM)
    async with db.session() as s:  # as python -m app.cli rotate-vapid – another process
        await webpush.vapid(s, rotate=True)
    info = (await reader_client.get("/api/me/push")).json()
    assert info["public_key"] != keys[0].json()["public_key"] and info["devices"] == 0


# ---------------------------------------------------------------- shared addresses (Docker Desktop: everyone is the gateway)


async def test_shared_gateway_address_is_slowed_never_blocked(monkeypatch):
    monkeypatch.setattr(netaddr, "container_gateway", lambda: "172.31.250.1")
    monkeypatch.setattr(bruteforce, "SPRAY_DELAY", 0.0)
    await add_user("rudi")
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    async with make_client(client=("172.31.250.1", 5000)) as c:
        for i in range(40):
            await c.post("/api/auth/login", json={"username": f"u{i}", "password": "x"})
        assert not bruteforce.ip_blocked("172.31.250.1")
        assert (await c.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).json()["next"] == "done"
    # any other address is blocked as before
    async with make_client(client=("10.9.9.9", 5000)) as c:
        for i in range(30):
            await c.post("/api/auth/login", json={"username": f"u{i}", "password": "x"})
    assert bruteforce.ip_blocked("10.9.9.9")


def test_shared_addresses_from_configuration(monkeypatch):
    cfg = dataclasses.replace(config.get_config(), shared_addresses=("192.0.2.0/24",))
    monkeypatch.setattr(netaddr, "get_config", lambda: cfg)
    monkeypatch.setattr(netaddr, "container_gateway", lambda: None)
    assert netaddr.shared_address("192.0.2.7") and netaddr.shared_address("::ffff:192.0.2.7")
    assert netaddr.shared_address("172.31.250.10")  # the bundled proxy itself (no usable X-Forwarded-For)
    assert not netaddr.shared_address("198.51.100.1") and not netaddr.shared_address("garbage")


def test_entra_start_limit_is_not_one_persons_limit_on_a_shared_address(monkeypatch):
    monkeypatch.setattr(netaddr, "container_gateway", lambda: "172.31.250.1")
    auth_api._oidc_starts.clear()
    assert all(auth_api._oidc_rate_ok("172.31.250.1") for _ in range(auth_api.OIDC_PER_IP + 10))
    assert not all(auth_api._oidc_rate_ok("203.0.113.9") for _ in range(auth_api.OIDC_PER_IP + 1))
    auth_api._oidc_starts.clear()


# ---------------------------------------------------------------- SMTP: no internal targets


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "0.0.0.0", "::1", "localhost"])
async def test_smtp_host_never_internal(monkeypatch, host):
    cfg = dataclasses.replace(config.get_config(), smtp_allow_internal=())
    monkeypatch.setattr(netaddr, "get_config", lambda: cfg)
    with pytest.raises(notify.NotifyError) as exc:
        await notify.send_mail({"host": host, "port": 25, "from_addr": "news@corp.example", "encryption": "none"}, ["soc@corp.example"], "s", "t", "<p>b</p>")
    assert exc.value.category == "forbidden_target"


async def test_smtp_resolved_name_checked_and_pinned(monkeypatch):
    import socket

    cfg = dataclasses.replace(config.get_config(), smtp_allow_internal=())
    monkeypatch.setattr(netaddr, "get_config", lambda: cfg)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 25))])
    with pytest.raises(netaddr.ForbiddenTarget):
        await netaddr.mail_socket("mail.corp.example", 25, 1)


# ---------------------------------------------------------------- the emergency admin: slowed beyond its budget, never locked


async def test_emergency_admin_brake(client, monkeypatch):
    em = await add_user("notfall", "admin", emergency=True, totp_secret=pyotp.random_base32())
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    monkeypatch.setattr(bruteforce, "EMERGENCY_BUDGET", 3)
    monkeypatch.setattr(bruteforce, "EMERGENCY_SLOW", 0.3)
    for _ in range(3):
        await client.post("/api/auth/login", json={"username": em.username, "password": "falsch-falsch-falsch"})
    # beyond the budget: one check at a time across all addresses, each waits first – parallel guesses get 429
    clients = [make_client(client=(f"203.0.113.{i}", 5000)) for i in range(4)]
    try:
        rs = await asyncio.gather(*(c.post("/api/auth/login", json={"username": em.username, "password": "falsch"}) for c in clients))
    finally:
        for c in clients:
            await c.aclose()
    codes = sorted(r.status_code for r in rs)
    assert codes.count(429) >= 2 and 401 in codes
    # never locked: the right password still gets in (a little slower)
    t0 = time.monotonic()
    assert (await client.post("/api/auth/login", json={"username": em.username, "password": PASSWORD})).json() == {"next": "mfa"}
    assert time.monotonic() - t0 >= 0.3


# ---------------------------------------------------------------- cookies


async def test_csrf_cookie_has_the_host_prefix_with_secure_cookies(monkeypatch):
    secure = dataclasses.replace(config.get_config(), cookie_secure=True)
    monkeypatch.setattr(sessions, "get_config", lambda: secure)
    assert sessions.csrf_cookie_name() == "__Host-cobe_news_csrf" and sessions.cookie_name() == "__Host-cobe_news_session"
    async with make_client() as c:
        c.cookies.set("cobe_news_csrf", "old-unprefixed")
        r = await c.get("/api/auth/config")
        cookies = r.headers.get_list("set-cookie")
    assert any(h.startswith("__Host-cobe_news_csrf=") and "Path=/" in h for h in cookies)
    assert any(h.startswith('cobe_news_csrf=""') or h.startswith("cobe_news_csrf=;") for h in cookies)  # the old one goes


# ---------------------------------------------------------------- setup: all or nothing


async def _token() -> str:
    async with db.session() as s:
        return await auth_api.issue_setup_token(s)


async def test_setup_failing_half_way_keeps_the_token(client, monkeypatch):
    token = await _token()
    body = {"token": token, "username": "notfall", "password": PASSWORD}

    async def broken(*a, **kw):
        raise RuntimeError("disk full")

    monkeypatch.setattr(sessions, "create", broken)
    with pytest.raises(RuntimeError):
        await client.post("/api/setup", json=body)
    monkeypatch.undo()
    async with db.session() as s:
        assert not (await settings_store.get(s, "setup"))["completed"]
        assert await s.scalar(select(User)) is None
    assert (await client.post("/api/setup", json=body)).json() == {"next": "enroll"}


async def test_parallel_setup_creates_one_admin(client):
    token = await _token()
    body = {"token": token, "username": "notfall", "password": PASSWORD}
    async with make_client() as other:
        a, b = await asyncio.gather(client.post("/api/setup", json=body), other.post("/api/setup", json={**body, "username": "zweiter"}))
    assert sorted((a.status_code, b.status_code)) == [200, 404]
    async with db.session() as s:
        assert len(list(await s.scalars(select(User)))) == 1


async def test_completed_setup_without_emergency_admin_opens_again(client):
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True, "token_hash": "", "token_expires": 0})
        await s.commit()
    token = await _token()
    assert token
    assert (await client.get("/api/auth/config")).json()["setup_required"] is True
    assert (await client.post("/api/setup", json={"token": token, "username": "notfall", "password": PASSWORD})).json() == {"next": "enroll"}
    assert await _token() is None


# ---------------------------------------------------------------- optimistic concurrency, parallel creates


async def test_user_edit_of_an_older_state_is_refused(admin_client):
    other = await add_user("ben", "admin", totp_secret=pyotp.random_base32())
    row = next(u for u in (await admin_client.get("/api/admin/users")).json() if u["username"] == "ben")
    v = row["version"]
    assert (await admin_client.patch(f"/api/admin/users/{other.id}", json={"is_active": False, "version": v})).status_code == 200
    # another admin's form still shows the old state
    r = await admin_client.patch(f"/api/admin/users/{other.id}", json={"role": "reader", "version": v})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "stale"
    r = await admin_client.post(f"/api/admin/users/{other.id}/reset", json={"password": True, "version": v})
    assert r.status_code == 409
    assert (await admin_client.patch(f"/api/admin/users/{other.id}", json={"is_active": True, "version": v + 1})).json()["version"] == v + 2


async def test_settings_save_of_an_older_state_is_refused(admin_client):
    s1 = (await admin_client.get("/api/admin/auth/sessions")).json()
    rev = s1.get("rev", 0)
    assert (await admin_client.put("/api/admin/auth/sessions", json={"idle_min": 30, "absolute_h": 8, "rev": rev})).json()["rev"] == rev + 1
    r = await admin_client.put("/api/admin/auth/sessions", json={"idle_min": 90, "absolute_h": 12, "rev": rev})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "stale"
    assert (await admin_client.get("/api/admin/auth/sessions")).json()["idle_min"] == 30
    ldap = (await admin_client.get("/api/admin/auth/ldap")).json()
    body = {k: v for k, v in ldap.items() if k not in ("bind_password_set", "usable")}
    assert (await admin_client.put("/api/admin/auth/ldap", json=body)).status_code == 200
    assert (await admin_client.put("/api/admin/auth/ldap", json=body)).status_code == 409  # same rev again
    entra = (await admin_client.get("/api/admin/auth/entra")).json()
    e = {"enabled": False, "tenant_id": "", "client_id": "", "client_secret": "", "rev": entra.get("rev", 0)}
    assert (await admin_client.put("/api/admin/auth/entra", json=e)).status_code == 200
    assert (await admin_client.put("/api/admin/auth/entra", json=e)).status_code == 409


async def test_parallel_create_answers_409_not_500(admin_client, monkeypatch):
    from app import admin_api

    real = admin_api.passwords.ahash_password

    async def racing(pw):  # another admin creates the same name between the check and the insert
        async with db.session() as s:
            s.add(User(username="lena", display_name="Lena", role="reader", auth_source="local"))
            await s.commit()
        return await real(pw)

    monkeypatch.setattr(admin_api.passwords, "ahash_password", racing)
    r = await admin_client.post("/api/admin/users", json={"username": "lena"})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "username_taken"


# ---------------------------------------------------------------- re-confirmation for sensitive actions


async def _age_reauth(user_id) -> None:
    async with db.session() as s:
        await s.execute(update(UserSession).where(UserSession.user_id == user_id).values(reauth_at=datetime.now(UTC) - timedelta(hours=1)))
        await s.commit()


async def test_sensitive_actions_need_a_fresh_confirmation(admin_client):
    secret = pyotp.random_base32()
    async with db.session() as s:
        u = await s.get(User, admin_client.user.id)
        from app.crypto import encrypt_str

        u.totp_secret_enc = encrypt_str(secret)
        await s.commit()
    other = await add_user("ben")
    await _age_reauth(admin_client.user.id)
    calls = [
        ("put", "/api/admin/auth/sessions", {"idle_min": 60, "absolute_h": 12}),
        ("put", "/api/admin/auth/ldap", {"enabled": False}),
        ("put", "/api/admin/auth/entra", {"enabled": False}),
        ("post", "/api/admin/auth/mappings", {"source": "entra", "group_id": "0a0a0a0a-0000-0000-0000-000000000002", "role": "admin"}),
        ("post", "/api/admin/users", {"username": "neu-admin", "role": "admin"}),
        ("patch", f"/api/admin/users/{other.id}", {"role": "admin"}),
        ("post", f"/api/admin/users/{other.id}/reset", {"password": True}),
        ("delete", f"/api/admin/users/{other.id}", None),
    ]
    for method, path, body in calls:
        r = await admin_client.request(method.upper(), path, json=body)
        assert r.status_code == 403 and r.json()["detail"] == {"code": "reauth_required", "via": "password", "totp": True}, path
    # routine things stay as they are
    assert (await admin_client.post("/api/admin/users", json={"username": "neu-leser"})).status_code == 200
    assert (await admin_client.patch(f"/api/admin/users/{other.id}", json={"is_active": False})).status_code == 200
    # the password alone is not enough for an account with TOTP, neither is the code alone
    assert (await admin_client.post("/api/auth/reauth", json={"password": PASSWORD})).status_code == 401
    assert (await admin_client.post("/api/auth/reauth", json={"code": pyotp.TOTP(secret).now()})).status_code == 401
    r = await admin_client.post("/api/auth/reauth", json={"password": PASSWORD, "code": pyotp.TOTP(secret).now()})
    assert r.json() == {"ok": True, "valid_min": 10}
    for method, path, body in calls[:1] + calls[-1:]:
        assert (await admin_client.request(method.upper(), path, json=body)).status_code == 200, path


async def test_failed_confirmations_end_the_session_without_locking_the_account(admin_client):
    await _age_reauth(admin_client.user.id)
    for _ in range(4):
        assert (await admin_client.post("/api/auth/reauth", json={"password": "falsch", "code": "000000"})).status_code == 401
    r = await admin_client.post("/api/auth/reauth", json={"password": "falsch", "code": "000000"})
    assert r.json()["detail"]["code"] == "session_revoked"
    assert (await admin_client.get("/api/me")).status_code == 401
    assert bruteforce.locked_for(bruteforce.local_key("anna")) == 0


async def test_reader_without_totp_confirms_with_the_password(reader_client):
    assert (await reader_client.post("/api/auth/reauth", json={"password": PASSWORD})).json()["ok"] is True


async def test_entra_admin_confirms_at_microsoft(ms):  # noqa: F811 - fixture
    ms.claims = {"groups": ["0a0a0a0a-0000-0000-0000-000000000002"], "amr": ["pwd", "mfa"]}  # admin, MFA proven by the token
    cb, c = await entra_sign_in(ms)
    assert cb.status_code == 302
    await _age_reauth(uuid.UUID((await c.get("/api/me")).json()["id"]))
    r = await c.put("/api/admin/auth/sessions", json={"idle_min": 60, "absolute_h": 12})
    assert r.json()["detail"]["via"] == "entra"
    assert (await c.post("/api/auth/reauth", json={"password": "x"})).json()["detail"]["code"] == "entra_reauth"

    async def confirm(auth_time: int | None):
        start = await c.get("/api/auth/oidc/start", params={"reauth": 1, "next": "/settings"})
        q = parse_qs(urlsplit(start.headers["location"]).query)
        assert q["prompt"] == ["login"] and q["max_age"] == ["0"]
        ms.nonce = json.loads(decrypt_str(c.cookies.get(auth_api.OIDC_COOKIE).strip('"')))["n"]
        ms.claims = {**ms.claims, "auth_time": auth_time}
        return await c.get("/api/auth/oidc/callback", params={"code": "the-code", "state": q["state"][0]})

    stale = await confirm(int(time.time()) - 3600)  # Microsoft's single sign-on without a new sign-in
    assert stale.headers["location"] == "/?login_error=entra_reauth"
    assert (await c.put("/api/admin/auth/sessions", json={"idle_min": 60, "absolute_h": 12})).status_code == 403
    ok = await confirm(int(time.time()))
    assert ok.headers["location"] == "/settings"
    assert (await c.put("/api/admin/auth/sessions", json={"idle_min": 60, "absolute_h": 12})).status_code == 200
    # the client secret expired: the re-confirmation fails at the code exchange – with its own error code
    await _age_reauth(uuid.UUID((await c.get("/api/me")).json()["id"]))
    ms.token_error = httpx.Response(401, json={"error": "invalid_client", "error_description": "AADSTS7000222: The provided client secret keys are expired."})
    assert (await confirm(int(time.time()))).headers["location"] == "/?login_error=entra_secret"
    assert (await c.put("/api/admin/auth/sessions", json={"idle_min": 60, "absolute_h": 12})).status_code == 403
    ms.token_error = None
    await c.aclose()
    # a reauth start without an Entra session is refused
    async with make_client() as anon:
        assert (await anon.get("/api/auth/oidc/start", params={"reauth": 1})).headers["location"] == "/?login_error=entra_reauth"


# ---------------------------------------------------------------- directory accounts


async def test_ad_user_promoted_at_sign_in_loses_older_sessions(ad, admin_client):  # noqa: F811 - fixture
    await _setup(admin_client)
    async with make_client() as old:
        assert (await old.post("/api/auth/login", json={"username": "a.weber", "password": "Anna-Pw-2026!", "source": "ldap"})).json()["next"] == "done"
        assert (await old.get("/api/me")).json()["role"] == "reader"
        from test_ldap import ADMINS

        ad.groups_of("cn=Anna Weber,ou=Users,dc=corp,dc=example", [ADMINS])
        r, me = await _login("a.weber", "Anna-Pw-2026!")
        assert r.json() == {"next": "enroll"}  # admins set up TOTP first
        # the session from before cannot act as the admin without a second factor
        assert (await old.get("/api/me")).status_code == 401
        assert (await old.get("/api/admin/users")).status_code == 401


async def test_ad_lock_is_shown_and_lifted_by_admins(ad, admin_client):  # noqa: F811 - fixture
    await _setup(admin_client)
    assert (await _login("a.weber", "Anna-Pw-2026!"))[0].json()["next"] == "done"
    for _ in range(5):
        await _login("A.Weber@corp.example", "falsch")  # UPN: the same account
    row = next(u for u in (await admin_client.get("/api/admin/users")).json() if u["username"] == "a.weber")
    assert row["locked_for"] > 0
    assert (await _login("a.weber", "Anna-Pw-2026!"))[0].status_code == 423
    assert (await admin_client.post(f"/api/admin/users/{row['id']}/unlock")).json()["locked_for"] == 0
    assert (await _login("a.weber", "Anna-Pw-2026!"))[0].json()["next"] == "done"


async def test_lock_is_checked_before_the_directory_is_asked(ad, admin_client):  # noqa: F811 - fixture
    await _setup(admin_client)
    assert (await _login("a.weber", "Anna-Pw-2026!"))[0].json()["next"] == "done"
    for _ in range(5):
        await _login("a.weber", "falsch")
    before = len(ad.filters)
    assert (await _login("a.weber", "Anna-Pw-2026!"))[0].status_code == 423
    assert len(ad.filters) == before  # no search, no bind


async def test_refused_ad_sign_ins_never_lock_the_local_account(ad, admin_client):  # noqa: F811 - fixture
    await _setup(admin_client)
    await add_user("m.muster")  # a local account with the name of an AD account without a mapped group
    for _ in range(6):
        r, _ = await _login("m.muster", "Max-Pw-2026!")
        assert r.status_code in (401, 423)
    async with make_client() as c:
        r = await c.post("/api/auth/login", json={"username": "m.muster", "password": PASSWORD})
    assert r.json()["next"] == "done"
    # and unknown AD names do not lock local ones either
    for _ in range(6):
        await _login("rudi-lokal", "x")
    await add_user("rudi-lokal")
    async with make_client() as c:
        assert (await c.post("/api/auth/login", json={"username": "rudi-lokal", "password": PASSWORD})).json()["next"] == "done"


async def test_ad_rename_follows_and_gone_names_are_released(ad, admin_client, monkeypatch):  # noqa: F811 - fixture
    from ldap3 import MODIFY_REPLACE, Connection

    from app.auth import ldap_dir

    await _setup(admin_client)
    assert (await _login("a.weber", "Anna-Pw-2026!"))[0].json()["next"] == "done"
    admin = Connection(ad.srv, user="cn=svc-news,dc=corp,dc=example", password="svc-pw", client_strategy="MOCK_SYNC")
    assert admin.bind() and admin.modify("cn=Anna Weber,ou=Users,dc=corp,dc=example", {"sAMAccountName": [(MODIFY_REPLACE, ["a.mueller"])]})
    r, me = await _login("a.mueller", "Anna-Pw-2026!")
    assert me.json()["username"] == "a.mueller"
    async with db.session() as s:
        assert len(list(await s.scalars(select(User).where(User.auth_source == "ldap")))) == 1
    # the account is removed from AD (sync:gone) – a new account with its old name can sign in
    async with db.session() as s:
        await s.execute(update(User).where(User.external_id == str(ANNA)).values(is_active=False, deactivated_reason="sync:gone"))
        await s.commit()
    assert admin.modify("cn=Anna Weber,ou=Users,dc=corp,dc=example", {"sAMAccountName": [(MODIFY_REPLACE, ["a.alt"])]})
    assert admin.modify("cn=Otto Admin,ou=Users,dc=corp,dc=example", {"sAMAccountName": [(MODIFY_REPLACE, ["a.mueller"])]})
    from test_ldap import READERS

    ad.groups_of("cn=Otto Admin,ou=Users,dc=corp,dc=example", [READERS])
    r, me = await _login("a.mueller", "Otto-Pw-2026!")
    assert r.json()["next"] == "done" and me.json()["username"] == "a.mueller"
    async with db.session() as s:
        gone = await s.scalar(select(User).where(User.external_id == str(ANNA)))
        assert gone.username.startswith("a.mueller~")
    # the hourly sync renames as well (AD reads the name as the sign-in does)
    assert admin.modify("cn=Otto Admin,ou=Users,dc=corp,dc=example", {"sAMAccountName": [(MODIFY_REPLACE, ["o.neu"])]})
    async with db.session() as s:
        await directory_sync.run(s)
    async with db.session() as s:
        assert (await s.scalar(select(User).where(User.external_id == str(OTTO)))).username == "o.neu"
    assert ldap_dir  # imported for the fixture's patches


# ---------------------------------------------------------------- sessions, migrations


async def test_shorter_absolute_lifetime_ends_running_sessions(admin_client, reader_client):
    async with db.session() as s:
        await s.execute(update(UserSession).values(created_at=datetime.now(UTC) - timedelta(hours=3)))
        await s.commit()
    assert (await reader_client.get("/api/me")).status_code == 200
    # the admin re-confirms (its own session is three hours old as well – and survives only if the new limit allows)
    assert (await admin_client.put("/api/admin/auth/sessions", json={"idle_min": 60, "absolute_h": 4})).status_code == 200
    assert (await reader_client.get("/api/me")).status_code == 200
    async with db.session() as s:
        await settings_store.put(s, "sessions", {"idle_min": 60, "absolute_h": 2})
        await s.commit()
    assert (await reader_client.get("/api/me")).status_code == 401


def test_deps_reauth_window():
    sess = UserSession(id=uuid.uuid4(), reauth_at=datetime.now(UTC) - sessions.REAUTH_WINDOW - timedelta(seconds=1))
    user = User(auth_source="local", totp_secret_enc=None)
    with pytest.raises(Exception) as exc:
        deps.require_reauth(sess, user)
    assert exc.value.detail == {"code": "reauth_required", "via": "password", "totp": False}
    sess.reauth_at = datetime.now(UTC)
    deps.require_reauth(sess, user)
