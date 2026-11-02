"""Sign-in hardening (0.1.42): the Entra MFA proof ("MFA-Nachweis": trust Conditional Access, an authentication
context the token must carry, or a proof / the own TOTP), "Zweiter Faktor für alle", brute-force locks that survive a
restart (table auth_locks), API tokens of at most a year, and the password history (none of the last five)."""

import importlib
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pyotp
import pytest
from conftest import PASSWORD, add_user, make_client, sign_in
from sqlalchemy import func, select, text, update
from test_entra import ADMINS, READERS, TENANT, _sign_in  # noqa: F401
from test_entra import ms  # noqa: F401 - fixture
from test_ldap import _login as ldap_login
from test_ldap import _setup as ldap_setup
from test_ldap import ad  # noqa: F401 - fixture
from test_passkeys import Authenticator, passkey_login

from app import audit, auth_api, db
from app import settings as settings_store
from app.auth import bruteforce, entra, lock_store, passwords
from app.crypto import decrypt_str, encrypt_str
from app.models import ApiToken, AuditEntry, AuthLock, PasswordHistory, User, UserPasskey, UserSession


@pytest.fixture(autouse=True)
def _oidc_start_counts():
    """The many Entra sign-ins here count against the per-address start limit (in memory, not reset by conftest): each
    test starts and leaves it empty, so the modules after this one start as they would alone."""
    auth_api._oidc_starts.clear()
    yield
    auth_api._oidc_starts.clear()


def code(secret: str, offset: int = 0) -> str:
    return pyotp.TOTP(secret).at(time.time() + offset * 30)


async def _setup_done() -> None:
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()


async def _put(section: str, value: dict) -> None:
    async with db.session() as s:
        await settings_store.put(s, section, {**(await settings_store.get(s, section)), **value})
        await s.commit()


async def _user(name: str) -> User | None:
    async with db.session() as s:
        return await s.scalar(select(User).where(User.username == name))


async def _entries(action: str) -> list[AuditEntry]:
    async with db.session() as s:
        return list(await s.scalars(select(AuditEntry).where(AuditEntry.action == action).order_by(AuditEntry.at)))


# ================================================================ 1. Entra: the MFA proof


def test_mfa_proven_by_mode_and_token():
    ctx = {"mfa_mode": "context", "auth_context": "c1"}
    assert entra.mfa_proven(ctx, {"acrs": ["c1"]}) is True
    assert entra.mfa_proven(ctx, {"acrs": ["C1", "c2"]}) is True  # case does not matter
    assert entra.mfa_proven(ctx, {"acrs": ["c2"]}) is False
    assert entra.mfa_proven(ctx, {"amr": ["mfa"]}) is False  # with a context required, amr does not stand in for it
    assert entra.mfa_proven(ctx, {"acrs": "c1"}) is False  # not a list
    assert entra.mfa_proven({"mfa_mode": "context", "auth_context": ""}, {"acrs": ["c1"]}) is False  # nothing configured
    for mode in ("entra", "require"):
        cfg = {"mfa_mode": mode, "auth_context": "c1"}  # a context only counts in mode "context"
        assert entra.mfa_proven(cfg, {"amr": ["pwd", "mfa"]}) is True
        assert entra.mfa_proven(cfg, {"amr": ["pwd"]}) is False
        assert entra.mfa_proven(cfg, {}) is None  # the usual v2.0 ID token: no amr – nothing proven either way
        assert entra.mfa_proven(cfg, {"amr": "mfa"}) is None
    assert entra.mfa_mode({}) == "entra" and entra.mfa_mode({"mfa_mode": "nonsense"}) == "entra"


def test_entra_stage_decides():
    u = User(username="x", role="reader", auth_source="entra")
    assert auth_api.entra_stage(u, None, False) == "active"  # nothing required: as before
    assert auth_api.entra_stage(u, True, True) == "active"
    assert auth_api.entra_stage(u, None, True) == "enroll"  # cannot tell, no TOTP yet: set it up now
    assert auth_api.entra_stage(u, False, True) is None  # disproven and no TOTP: refused
    u.totp_secret_enc = encrypt_str(pyotp.random_base32())
    assert auth_api.entra_stage(u, None, True) == "mfa" and auth_api.entra_stage(u, False, True) == "mfa"


def test_authorize_url_asks_for_the_context_as_an_essential_claim():
    base = {"tenant_id": TENANT, "client_id": "c", "mfa_mode": "context", "auth_context": "c7"}
    q = parse_qs(urlsplit(entra.authorize_url(base, state="s", nonce="n", challenge="x")).query)
    assert json.loads(q["claims"][0]) == {"id_token": {"acrs": {"essential": True, "value": "c7"}}}
    for cfg in ({**base, "mfa_mode": "entra"}, {**base, "mfa_mode": "require"}, {**base, "auth_context": ""}):
        assert "claims" not in parse_qs(urlsplit(entra.authorize_url(cfg, state="s", nonce="n", challenge="x")).query)


async def test_entra_settings_store_the_mfa_mode(admin_client, ms):  # noqa: F811 - fixture
    body = {"enabled": True, "tenant_id": TENANT, "client_id": str(uuid.uuid4())}
    r = await admin_client.put("/api/admin/auth/entra", json={**body, "mfa_mode": "context", "auth_context": "C3"})
    assert r.status_code == 200 and r.json()["mfa_mode"] == "context" and r.json()["auth_context"] == "c3"
    assert (await admin_client.put("/api/admin/auth/entra", json={**body, "mfa_mode": "context", "auth_context": ""})).json()["detail"]["code"] == "auth_context_missing"
    for bad in ("c0", "c100", "x1", "c1;"):
        assert (await admin_client.put("/api/admin/auth/entra", json={**body, "auth_context": bad})).status_code == 422, bad
    assert (await admin_client.put("/api/admin/auth/entra", json={**body, "mfa_mode": "always"})).status_code == 422
    # an older client (no such fields): the stored choice stays
    r = await admin_client.put("/api/admin/auth/entra", json=body)
    assert r.json()["mfa_mode"] == "context" and r.json()["auth_context"] == "c3"
    changes = [e.details["changes"] for e in await _entries("signin.config_changed") if e.target_id == "entra"]
    assert {"from": "entra", "to": "context"} in [c.get("mfa_mode") for c in changes]
    assert {"from": "", "to": "c3"} in [c.get("auth_context") for c in changes]


async def _entra_mode(admin_client, mode: str, context: str = "") -> None:
    r = await admin_client.put("/api/admin/auth/entra", json={"enabled": True, "tenant_id": TENANT, "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "mfa_mode": mode, "auth_context": context})
    assert r.status_code == 200, r.text


async def test_context_mode_the_token_must_carry_it(admin_client, ms):  # noqa: F811 - fixture
    await _entra_mode(admin_client, "context", "c1")
    # the sign-in asks for it …
    async with make_client() as c:
        q = parse_qs(urlsplit((await c.get("/api/auth/oidc/start")).headers["location"]).query)
        assert json.loads(q["claims"][0])["id_token"]["acrs"]["value"] == "c1"
    # … a token with it: signed in, readers and admins alike
    ms.claims = {"acrs": ["c1"]}
    cb, c = await _sign_in(ms)
    assert (await c.get("/api/me")).json()["role"] == "reader"
    await c.aclose()
    ms.claims = {"acrs": ["c1"], "groups": [ADMINS], "oid": str(uuid.uuid4()), "preferred_username": "boss@corp.example"}
    cb, c = await _sign_in(ms)
    assert (await c.get("/api/me")).json()["role"] == "admin"
    await c.aclose()
    # without it (a policy that did not apply, the parameter dropped from the link): refused, no account made
    ms.claims = {"oid": str(uuid.uuid4()), "preferred_username": "neu@corp.example"}
    cb, c = await _sign_in(ms)
    assert cb.headers["location"] == "/?login_error=entra_mfa_missing" and (await c.get("/api/auth/state")).json()["stage"] is None
    assert await _user("neu@corp.example") is None
    await c.aclose()
    # an account with its own TOTP: that is asked instead
    secret = pyotp.random_base32()
    async with db.session() as s:
        await s.execute(update(User).where(User.username == "erika@corp.example").values(totp_secret_enc=encrypt_str(secret)))
        await s.commit()
    ms.claims = {"acrs": ["c2"]}
    cb, c = await _sign_in(ms)
    assert cb.headers["location"] == "/" and (await c.get("/api/auth/state")).json() == {"stage": "mfa"}
    assert (await c.get("/api/me")).status_code == 401
    done = (await c.post("/api/auth/mfa", json={"code": code(secret)})).json()
    assert done["next"] == "done"
    assert (await c.get("/api/me/sessions")).json()[0]["method"] == "entra_totp"
    await c.aclose()


async def test_require_mode_proof_or_own_totp(admin_client, ms):  # noqa: F811 - fixture
    await _entra_mode(admin_client, "require")
    # no amr (the usual v2.0 ID token): Cobe News' own TOTP – none yet, so it is set up now
    cb, c = await _sign_in(ms)
    st = (await c.get("/api/auth/state")).json()
    assert st == {"stage": "enroll", "enroll": {"reason": "required", "passkey": False, "has_passkey": False}}
    secret = (await c.post("/api/auth/enroll/start")).json()["secret"]
    assert (await c.post("/api/auth/enroll/confirm", json={"code": code(secret, -1)})).json()["next"] == "done"
    await c.aclose()
    # the next time: the code
    cb, c = await _sign_in(ms)
    assert (await c.get("/api/auth/state")).json() == {"stage": "mfa"}
    assert (await c.post("/api/auth/mfa", json={"code": code(secret)})).json()["next"] == "done"
    await c.aclose()
    # a token proving MFA (amr): straight in
    ms.claims = {"amr": ["pwd", "mfa"]}
    cb, c = await _sign_in(ms)
    assert (await c.get("/api/me")).status_code == 200
    await c.aclose()
    # a token saying "password only" and no own TOTP: refused – the Entra password must not set up the second factor
    ms.claims = {"amr": ["pwd"], "oid": str(uuid.uuid4()), "preferred_username": "neu@corp.example"}
    cb, c = await _sign_in(ms)
    assert cb.headers["location"] == "/?login_error=entra_mfa_missing" and await _user("neu@corp.example") is None
    await c.aclose()


async def test_entra_mode_trusts_ca_for_readers_not_for_admins(admin_client, ms):  # noqa: F811 - fixture
    # the default: a reader as before 0.1.42 – also with amr saying "password only"
    ms.claims = {"amr": ["pwd"]}
    cb, c = await _sign_in(ms)
    assert (await c.get("/api/me")).json()["role"] == "reader"
    await c.aclose()
    # an admin needs a proof: amr without mfa and no TOTP – refused (no account, no role)
    ms.claims = {"amr": ["pwd"], "groups": [ADMINS], "oid": str(uuid.uuid4()), "preferred_username": "boss@corp.example"}
    cb, c = await _sign_in(ms)
    assert cb.headers["location"] == "/?login_error=entra_mfa_missing" and await _user("boss@corp.example") is None
    await c.aclose()
    # nothing proven either way: the own TOTP is set up
    ms.claims = {**ms.claims, "amr": None}
    cb, c = await _sign_in(ms)
    assert (await c.get("/api/auth/state")).json()["stage"] == "enroll"
    await c.aclose()
    # "Zweiter Faktor für alle": readers like admins
    await _put("mfa", {"required_all": True})
    ms.claims = {}
    cb, c = await _sign_in(ms)
    assert (await c.get("/api/auth/state")).json()["stage"] == "enroll"
    await c.aclose()


async def _confirm(c, ms, **claims):  # noqa: ANN001, ANN202, F811
    start = await c.get("/api/auth/oidc/start", params={"reauth": 1, "next": "/settings"})
    q = parse_qs(urlsplit(start.headers["location"]).query)
    ms.nonce = json.loads(decrypt_str(c.cookies.get(auth_api.OIDC_COOKIE).strip('"')))["n"]
    ms.claims = {**ms.claims, "auth_time": int(time.time()), **claims}
    return await c.get("/api/auth/oidc/callback", params={"code": "the-code", "state": q["state"][0]})


async def _age(user_id) -> None:  # noqa: ANN001
    async with db.session() as s:
        await s.execute(update(UserSession).where(UserSession.user_id == user_id).values(reauth_at=datetime.now(UTC) - timedelta(hours=1)))
        await s.commit()


async def test_reauth_at_microsoft_proves_mfa_the_same_way(admin_client, ms):  # noqa: F811 - fixture
    """An Entra admin's re-confirmation: proven by the token, or by the own TOTP code given just before – the Entra
    password alone (a fresh sign-in at Microsoft without MFA) is not enough."""
    ms.claims = {"groups": [ADMINS]}
    cb, c = await _sign_in(ms)
    secret = (await c.post("/api/auth/enroll/start")).json()["secret"]
    assert (await c.post("/api/auth/enroll/confirm", json={"code": code(secret, -1)})).json()["next"] == "done"
    uid = (await c.get("/api/me")).json()["id"]
    await _age(uid)
    r = await c.put("/api/admin/auth/sessions", json={"idle_min": 60, "absolute_h": 12})
    assert r.json()["detail"] == {"code": "reauth_required", "via": "entra", "totp": True}
    # Microsoft alone, no proof in the token: refused
    assert (await _confirm(c, ms)).headers["location"] == "/?login_error=entra_reauth_mfa"
    assert (await c.put("/api/admin/auth/sessions", json={"idle_min": 60, "absolute_h": 12})).status_code == 403
    # a wrong code first: counted on the session, nothing noted
    assert (await c.post("/api/auth/reauth", json={"code": "000000"})).json()["detail"]["code"] == "invalid_code"
    assert (await c.post("/api/auth/reauth", json={"password": "x"})).json()["detail"]["code"] == "entra_reauth"
    # the code, then Microsoft: confirmed
    assert (await c.post("/api/auth/reauth", json={"code": code(secret)})).json() == {"ok": True, "next": "entra"}
    assert (await _confirm(c, ms)).headers["location"] == "/settings"
    assert (await c.put("/api/admin/auth/sessions", json={"idle_min": 60, "absolute_h": 12})).status_code == 200
    # the noted code is used once
    await _age(uid)
    assert (await _confirm(c, ms)).headers["location"] == "/?login_error=entra_reauth_mfa"
    # a token proving MFA: no code needed
    assert (await _confirm(c, ms, amr=["pwd", "mfa"])).headers["location"] == "/settings"
    await c.aclose()


async def test_a_reader_reauth_needs_no_proof_while_none_is_required(admin_client, ms):  # noqa: F811 - fixture
    cb, c = await _sign_in(ms)
    await _age((await c.get("/api/me")).json()["id"])
    assert (await _confirm(c, ms)).headers["location"] == "/settings"
    await c.aclose()


# ================================================================ 2. "Zweiter Faktor für alle"


async def test_second_factor_for_all_setting(admin_client):
    assert (await admin_client.get("/api/admin/auth/mfa")).json() == {"required_all": False, "rev": 0}
    r = await admin_client.put("/api/admin/auth/mfa", json={"required_all": True, "rev": 0})
    assert r.json() == {"required_all": True, "rev": 1}
    assert (await admin_client.put("/api/admin/auth/mfa", json={"required_all": False, "rev": 0})).json()["detail"]["code"] == "stale"
    [e] = await _entries("signin.config_changed")
    assert e.target_id == "mfa" and e.details["changes"] == {"required_all": {"from": False, "to": True}}
    async with make_client() as rc:
        await sign_in(rc, await add_user("rudi"))
        assert (await rc.get("/api/admin/auth/mfa")).status_code == 403
        assert (await rc.put("/api/admin/auth/mfa", json={"required_all": False})).status_code == 403
    await _age(admin_client.user.id)
    assert (await admin_client.put("/api/admin/auth/mfa", json={"required_all": False, "rev": 1})).json()["detail"]["code"] == "reauth_required"


async def test_off_readers_sign_in_as_before(client):
    await _setup_done()
    await add_user("rudi")
    assert (await client.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).json()["next"] == "done"


async def test_on_a_local_reader_sets_up_totp_running_sessions_go_on(client):
    await _setup_done()
    rudi = await add_user("rudi")
    async with make_client() as running:
        await sign_in(running, rudi)
        await _put("mfa", {"required_all": True})
        assert (await running.get("/api/me")).status_code == 200  # a session already running is not ended
    r = await client.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})
    assert r.json() == {"next": "enroll"} and (await client.get("/api/news")).status_code == 401
    assert (await client.get("/api/auth/state")).json()["enroll"]["reason"] == "required"
    secret = (await client.post("/api/auth/enroll/start")).json()["secret"]
    assert (await client.post("/api/auth/enroll/confirm", json={"code": code(secret, -1)})).json()["next"] == "done"
    # now with the code; removing the TOTP is refused while the setting is on
    async with make_client() as c:
        assert (await c.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).json() == {"next": "mfa"}
        assert (await c.post("/api/auth/mfa", json={"code": code(secret)})).json()["next"] == "done"
        assert (await c.post("/api/me/totp/remove", json={"code": code(secret, 1)})).json()["detail"]["code"] == "totp_required"


async def test_on_a_temporary_password_first_then_the_set_up(client):
    await _setup_done()
    await add_user("neu", must_change_password=True)
    await _put("mfa", {"required_all": True})
    assert (await client.post("/api/auth/login", json={"username": "neu", "password": PASSWORD})).json() == {"next": "password"}
    assert (await client.post("/api/auth/password", json={"new_password": "Ganz-Neues-Passwort-2026"})).json() == {"next": "enroll"}


async def test_on_an_ad_reader_sets_up_totp(ad, admin_client):  # noqa: F811 - fixture
    await ldap_setup(admin_client)
    await _put("mfa", {"required_all": True})
    r, me = await ldap_login("a.weber", "Anna-Pw-2026!")
    assert r.json() == {"next": "enroll"} and me.status_code == 401


async def test_on_a_passkey_counts_and_can_be_set_up_instead(client):
    await _setup_done()
    rudi = await add_user("rudi")
    await _put("mfa", {"required_all": True})
    # the set-up step offers a passkey to a local reader …
    assert (await client.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).json() == {"next": "enroll"}
    assert (await client.get("/api/auth/state")).json()["enroll"] == {"reason": "required", "passkey": True, "has_passkey": False}
    auth = Authenticator()
    opts = (await client.post("/api/auth/enroll/passkey/options")).json()
    assert opts["authenticatorSelection"]["userVerification"] == "required"
    r = await client.post("/api/auth/enroll/passkey", json=auth.attestation(opts, name="Laptop"))
    assert r.json()["next"] == "done" and r.json()["user"]["username"] == "rudi"
    async with db.session() as s:
        pk = await s.scalar(select(UserPasskey))
        sess = await s.scalar(select(UserSession).where(UserSession.stage == "active"))
        assert pk.user_id == rudi.id and sess.passkey_id == pk.id and sess.method == "password"
    [added] = await _entries("passkey.added")
    assert added.details["at_signin"] is True
    # … the sign-in with it needs nothing more
    c, r = await passkey_login(auth, rudi)
    assert r.json()["next"] == "done"
    await c.aclose()
    # a password sign-in without TOTP still ends in the set-up step – which says a passkey would do
    async with make_client() as c2:
        assert (await c2.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).json() == {"next": "enroll"}
        assert (await c2.get("/api/auth/state")).json()["enroll"]["has_passkey"] is True
    # an option of the set-up step only: neither before it nor once signed in
    async with make_client() as c3:
        assert (await c3.post("/api/auth/enroll/passkey/options")).status_code == 401


async def test_admins_keep_totp_no_passkey_instead(client):
    await _setup_done()
    await add_user("ida", "admin")
    assert (await client.post("/api/auth/login", json={"username": "ida", "password": PASSWORD})).json() == {"next": "enroll"}
    assert (await client.get("/api/auth/state")).json()["enroll"] == {"reason": "admin", "passkey": False, "has_passkey": False}
    assert (await client.post("/api/auth/enroll/passkey/options")).json()["detail"]["code"] == "totp_required"


# ================================================================ 3. brute-force locks survive a restart


async def _restart() -> None:
    """What a restart does to the brute-force state: the memory is gone, the start reads the table."""
    bruteforce.reset()
    async with db.session() as s:
        await lock_store.load(s)


async def test_an_account_lock_survives_a_restart_and_an_unlock_ends_it(admin_client):
    await _setup_done()
    await add_user("rudi")
    async with make_client() as c:
        for _ in range(bruteforce.ACCOUNT_MAX):
            r = await c.post("/api/auth/login", json={"username": "rudi", "password": "falsch-falsch"})
        assert r.status_code == 423
    async with db.session() as s:
        row = await s.get(AuthLock, "acct:local:rudi")
    assert row is not None and row.strikes == 1 and timedelta(minutes=14) < row.until - datetime.now(UTC) <= timedelta(minutes=15)
    await _restart()
    assert 0 < bruteforce.locked_for("local:rudi") <= bruteforce.ACCOUNT_LOCK
    async with make_client() as c:
        assert (await c.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).status_code == 423
    # the admin's unlock removes the stored lock too – the next restart does not bring it back
    rudi = await _user("rudi")
    assert (await admin_client.post(f"/api/admin/users/{rudi.id}/unlock")).json()["locked_for"] == 0
    async with db.session() as s:
        assert await s.get(AuthLock, "acct:local:rudi") is None
    await _restart()
    async with make_client() as c:
        assert (await c.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).json()["next"] == "done"


async def test_an_address_block_survives_a_restart():
    await _setup_done()
    async with make_client() as c:
        for i in range(bruteforce.IP_MAX):
            r = await c.post("/api/auth/login", json={"username": f"name{i % 6}", "password": "falsch"})
        assert r.json()["detail"]["code"] == "ip_blocked"
    async with db.session() as s:
        rows = list(await s.scalars(select(AuthLock).where(AuthLock.key.like("ip:%"))))
    assert [r.key for r in rows] == ["ip:127.0.0.1"]
    await _restart()
    assert bruteforce.ip_blocked("127.0.0.1")


async def test_expired_rows_go_and_the_table_is_bounded(monkeypatch):
    now = datetime.now(UTC)
    async with db.session() as s:
        s.add(AuthLock(key="acct:local:alt", until=now - timedelta(seconds=1), created_at=now - timedelta(hours=1)))
        s.add(AuthLock(key="ip:192.0.2.9", until=now + timedelta(minutes=5), created_at=now))
        await s.commit()
    await _restart()
    assert bruteforce.locked_for("local:alt") == 0 and bruteforce.ip_blocked("192.0.2.9")
    async with db.session() as s:
        assert [r.key for r in await s.scalars(select(AuthLock))] == ["ip:192.0.2.9"]
    # a clock set far ahead in the table: never longer than the longest lock there is
    async with db.session() as s:
        s.add(AuthLock(key="acct:local:weit", until=now + timedelta(days=30), created_at=now, strikes=99))
        await s.commit()
    await _restart()
    assert bruteforce.locked_for("local:weit") <= lock_store.LONGEST
    # at most MAX_ROWS: the ones ending first go
    monkeypatch.setattr(lock_store, "MAX_ROWS", 3)
    mono = time.monotonic()
    async with db.session() as s:
        await lock_store.write(s, {f"ip:198.51.100.{i}": (mono + 60 * (i + 1), 1) for i in range(5)})
        await s.commit()
        keys = set(await s.scalars(select(AuthLock.key)))
    assert len(keys) == 3 and "ip:198.51.100.4" in keys and "ip:198.51.100.0" not in keys
    # hourly: expired rows go
    async with db.session() as s:
        await s.execute(update(AuthLock).values(until=now - timedelta(seconds=1)))
        await s.commit()
        assert await lock_store.prune(s) == 3


async def test_a_database_hiccup_never_fails_the_sign_in(monkeypatch):
    def broken():  # noqa: ANN202
        raise RuntimeError("database away")

    monkeypatch.setattr(lock_store.dbm, "session", broken)
    bruteforce._dirty["ip:203.0.113.1"] = (time.monotonic() + 60, 1)
    await lock_store.flush()  # logged, not raised
    assert bruteforce._dirty == {}


# ================================================================ 4. API tokens: at most a year


async def test_api_tokens_expire_within_a_year(admin_client):
    r = await admin_client.post("/api/admin/api-tokens", json={"name": "SIEM", "scopes": ["read"]})
    assert r.status_code == 201
    exp = datetime.fromisoformat(r.json()["item"]["expires_at"])
    assert timedelta(days=364) < exp - datetime.now(UTC) <= timedelta(days=365) and r.json()["item"]["expiry_added"] is False
    for days in (None, 0, 366, 3650):
        assert (await admin_client.post("/api/admin/api-tokens", json={"name": "x", "scopes": ["read"], "expires_days": days})).status_code == 422, days
    listing = (await admin_client.get("/api/admin/api-tokens")).json()
    assert listing["max_days"] == 365 and listing["default_days"] == 365


async def test_migration_0023_gives_eternal_tokens_an_expiry(admin_client):
    """A token made with "never" before 0.1.42 gets migration time + 365 days and the note "Ablauf ergänzt"; a revoked one
    and one with an expiry stay as they were. In a transaction that is rolled back – the test database stays as it was."""
    from alembic import command

    prev = importlib.import_module("app.migrations.versions.0023_auth_hardening").down_revision
    fixed = datetime(2027, 1, 1, tzinfo=UTC)

    def step(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), prev)
        for name, exp, rev in (("ewig", None, None), ("fest", fixed, None), ("weg", None, fixed)):
            conn.execute(
                text("INSERT INTO api_tokens (id, name, prefix, token_hash, scopes, created_by, created_at, expires_at, revoked_at) VALUES (:i, :n, 'cnt_x', :h, '[\"read\"]', :u, now(), :e, :r)"),
                {"i": uuid.uuid4(), "n": name, "h": name, "u": admin_client.user.id, "e": exp, "r": rev},
            )
        command.upgrade(db.alembic_config(conn), "0023")
        return {r[0]: (r[1], r[2]) for r in conn.execute(text("SELECT name, expires_at, expiry_added FROM api_tokens"))}

    async with db.engine().connect() as conn:
        trans = await conn.begin()
        try:
            rows = await conn.run_sync(step)
        finally:
            await trans.rollback()
    exp, added = rows["ewig"]
    assert added is True and timedelta(days=364) < exp - datetime.now(UTC) <= timedelta(days=365)
    assert rows["fest"] == (fixed, False) and rows["weg"] == (None, False)


# ================================================================ 5c. password history


async def _change(c, current: str, new: str):  # noqa: ANN001, ANN202
    return await c.post("/api/me/password", json={"current_password": current, "new_password": new})


async def test_none_of_the_last_five_passwords_again(client):
    await _setup_done()
    u = await add_user("rudi")
    await sign_in(client, u)
    pws = [PASSWORD] + [f"Neues-Passwort-Nummer-{i}-x" for i in range(1, 6)]
    for old, new in zip(pws, pws[1:5], strict=False):  # four changes: PASSWORD and three more are history now
        assert (await _change(client, old, new)).status_code == 200
    current = pws[4]
    for again in pws[:5]:
        r = await _change(client, current, again)
        assert r.json()["detail"] == {"code": "password_policy", "rules": ["reused"]}, again
    # a fifth change: the oldest (PASSWORD) is out of the last five
    assert (await _change(client, current, pws[5])).status_code == 200
    assert (await _change(client, pws[5], PASSWORD)).status_code == 200
    async with db.session() as s:
        assert int(await s.scalar(select(func.count()).select_from(PasswordHistory).where(PasswordHistory.user_id == u.id))) == passwords.HISTORY - 1


async def test_the_history_holds_after_a_reset_temporary_passwords_never_count(admin_client):
    await _setup_done()
    rudi = await add_user("rudi")
    r = await admin_client.post(f"/api/admin/users/{rudi.id}/reset", json={"password": True})
    temp = r.json()["temp_password"]
    async with db.session() as s:
        [h] = list(await s.scalars(select(PasswordHistory.password_hash).where(PasswordHistory.user_id == rudi.id)))
    assert passwords.verify_password(h, PASSWORD)  # the person's own password is kept, as a hash
    async with make_client() as c:
        assert (await c.post("/api/auth/login", json={"username": "rudi", "password": temp})).json() == {"next": "password"}
        # back to the old password: refused
        assert (await c.post("/api/auth/password", json={"new_password": PASSWORD})).json()["detail"]["rules"] == ["reused"]
        assert (await c.post("/api/auth/password", json={"new_password": "Ganz-Neues-Passwort-2026"})).json()["next"] == "done"
    async with db.session() as s:
        hashes = list(await s.scalars(select(PasswordHistory.password_hash).where(PasswordHistory.user_id == rudi.id)))
    assert len(hashes) == 1 and not any(passwords.verify_password(x, temp) for x in hashes)  # the temporary one: never kept


async def test_the_history_never_reaches_the_log_or_an_answer(admin_client):
    assert audit.is_secret("password_hash")
    await _setup_done()
    u = await add_user("rudi")
    async with make_client() as c:
        await sign_in(c, u)
        assert (await _change(c, PASSWORD, "Neues-Passwort-Nummer-1-x")).status_code == 200
        me = (await c.get("/api/me")).text
    async with db.session() as s:
        [h] = list(await s.scalars(select(PasswordHistory.password_hash)))
        logged = json.dumps([e.details for e in await s.scalars(select(AuditEntry))])
    users = (await admin_client.get("/api/admin/users")).text
    for blob in (me, logged, users):
        assert h not in blob and "argon2" not in blob


@pytest.mark.parametrize("source", ["ldap", "entra"])
async def test_directory_accounts_keep_no_history(source):
    async with db.session() as s:
        u = User(username=f"x-{source}", role="reader", auth_source=source, external_id=str(uuid.uuid4()), password_hash=passwords.hash_password(PASSWORD))
        s.add(u)
        await s.flush()
        await passwords.remember(s, u)
        await s.commit()
        assert await s.scalar(select(PasswordHistory)) is None
