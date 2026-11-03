"""Hardening round (0.1.47): temporary passwords expire, the request body limit in the app, the warning for a short
SECRET_KEY, throttled log lines for suspicious events, control characters in mail/chat."""

from datetime import UTC, datetime, timedelta

import pyotp
from conftest import PASSWORD, add_user, make_client
from sqlalchemy import select, update

from app import db
from app import settings as settings_store
from app.models import AuditEntry, User


async def _setup_done() -> None:
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()


async def _age_temp(username: str, days: float) -> None:
    async with db.session() as s:
        await s.execute(update(User).where(User.username == username).values(temp_password_at=datetime.now(UTC) - timedelta(days=days)))
        await s.commit()


# ---------------------------------------------------------------- 1. temporary passwords expire


async def test_temporary_password_expires_after_the_configured_days(admin_client):
    await _setup_done()
    r = (await admin_client.post("/api/admin/users", json={"username": "lena", "role": "reader"})).json()
    tmp, uid = r["temp_password"], r["id"]
    end = datetime.fromisoformat(r["temp_password_expires_at"])
    assert timedelta(days=6, hours=23) < end - datetime.now(UTC) <= timedelta(days=7) and r["temp_password_expired"] is False
    # 8 days later: the right temporary password is refused with its own code (no session), a wrong one as always
    await _age_temp("lena", 8)
    async with make_client() as lena:
        r = await lena.post("/api/auth/login", json={"username": "lena", "password": tmp})
        assert r.status_code == 401 and r.json()["detail"]["code"] == "temp_password_expired"
        assert (await lena.get("/api/auth/state")).json() == {"stage": None}
        r = await lena.post("/api/auth/login", json={"username": "lena", "password": "falsch-falsch-falsch"})
        assert r.json()["detail"]["code"] == "invalid_credentials"
    row = next(u for u in (await admin_client.get("/api/admin/users")).json() if u["id"] == uid)
    assert row["must_change_password"] and row["temp_password_expired"] is True
    # the setting (1–30 days, sign-in settings – audited as a sign-in change): 30 days, the same password works again
    cfg = (await admin_client.get("/api/admin/auth/sessions")).json()
    assert cfg["temp_password_days"] == 7
    assert (await admin_client.put("/api/admin/auth/sessions", json={**cfg, "temp_password_days": 31})).status_code == 422
    assert (await admin_client.put("/api/admin/auth/sessions", json={**cfg, "temp_password_days": 0})).status_code == 422
    assert (await admin_client.put("/api/admin/auth/sessions", json={**cfg, "temp_password_days": 30})).status_code == 200
    async with db.session() as s:
        e = (await s.scalars(select(AuditEntry).where(AuditEntry.action == "signin.config_changed"))).one()
        assert e.details["changes"] == {"temp_password_days": {"from": 7, "to": 30}}
    # an older client without the field keeps the stored value
    cfg = (await admin_client.get("/api/admin/auth/sessions")).json()
    old = {"idle_min": cfg["idle_min"], "absolute_h": cfg["absolute_h"], "rev": cfg["rev"]}
    assert (await admin_client.put("/api/admin/auth/sessions", json=old)).json()["temp_password_days"] == 30
    async with make_client() as lena:
        assert (await lena.post("/api/auth/login", json={"username": "lena", "password": tmp})).json() == {"next": "password"}
        assert (await lena.post("/api/auth/password", json={"new_password": PASSWORD + "!"})).json()["next"] == "done"
    async with db.session() as s:
        u = await s.scalar(select(User).where(User.username == "lena"))
        assert u.temp_password_at is None and not u.must_change_password
    row = next(u for u in (await admin_client.get("/api/admin/users")).json() if u["id"] == uid)
    assert row["temp_password_expires_at"] is None and row["temp_password_expired"] is False
    # a reset issues a new one, valid from now on
    await _age_temp("lena", 40)
    r = (await admin_client.post(f"/api/admin/users/{uid}/reset", json={"password": True})).json()
    assert datetime.fromisoformat(r["temp_password_expires_at"]) - datetime.now(UTC) > timedelta(days=29)
    async with make_client() as lena:
        assert (await lena.post("/api/auth/login", json={"username": "lena", "password": r["temp_password"]})).json() == {"next": "password"}


async def test_own_password_never_expires_and_the_cli_reset_starts_the_clock(capsys):
    from app import cli

    await _setup_done()
    await add_user("rudi", created_at=datetime.now(UTC) - timedelta(days=400))  # an own password: no expiry
    async with make_client() as c:
        assert (await c.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD})).json()["next"] == "done"
    await add_user("notfall", "admin", emergency=True, totp_secret=pyotp.random_base32())
    assert await cli._account("reset-emergency") == 0
    pw = capsys.readouterr().out.split("temporary password ")[1].split()[0]
    async with db.session() as s:
        u = await s.scalar(select(User).where(User.username == "notfall"))
        assert u.must_change_password and datetime.now(UTC) - u.temp_password_at < timedelta(minutes=1)
    async with make_client() as c:
        assert (await c.post("/api/auth/login", json={"username": "notfall", "password": pw})).json() == {"next": "password"}
    await _age_temp("notfall", 7.01)
    async with make_client() as c:
        assert (await c.post("/api/auth/login", json={"username": "notfall", "password": pw})).json()["detail"]["code"] == "temp_password_expired"


# ---------------------------------------------------------------- 2. request body limit in the app


async def test_a_body_over_the_limit_is_refused_413_with_the_security_headers(reader_client):
    from app.bodylimit import DEFAULT

    big = b'{"q": "' + b"x" * DEFAULT + b'"}'
    r = await reader_client.put("/api/me/desktop", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413 and r.json()["detail"] == {"code": "body_too_large", "limit": DEFAULT}
    assert r.headers["x-content-type-options"] == "nosniff" and "content-security-policy" in r.headers and r.headers["cache-control"] == "no-store"
    # chunked (no Content-Length): counted while read – refused as soon as it passes the limit
    sent = []

    async def chunks():
        for _ in range(40):
            sent.append(1)
            yield b"x" * 65536

    r = await reader_client.put("/api/me/desktop", content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code == 413 and r.json()["detail"]["code"] == "body_too_large"
    assert r.headers["x-frame-options"] == "DENY" and "content-length" not in r.request.headers
    assert len(sent) < 40  # not read to the end
    # a body under the limit goes through as before (here: refused by the route's own validation, not by the limit)
    r = await reader_client.put("/api/me/desktop", content=b'{"x": 1}', headers={"content-type": "application/json"})
    assert r.status_code not in (413, 500)


async def test_body_limit_asgi_streaming_and_content_length():
    """The middleware alone: Content-Length over the limit – the route never runs; chunks without one – the route sees
    the client gone and its own answer is dropped; under the limit – untouched."""
    from app.bodylimit import BodyLimit

    ran = []

    async def route(scope, receive, send):  # noqa: ANN001, ANN202
        body = b""
        while True:
            m = await receive()
            if m["type"] == "http.disconnect":
                ran.append("disconnect")
                break
            body += m.get("body", b"")
            if not m.get("more_body"):
                ran.append(len(body))
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def call(headers, parts):  # noqa: ANN001, ANN202
        msgs = [{"type": "http.request", "body": p, "more_body": i < len(parts) - 1} for i, p in enumerate(parts)]
        out = []

        async def receive():  # noqa: ANN202
            return msgs.pop(0) if msgs else {"type": "http.disconnect"}

        async def send(m):  # noqa: ANN001, ANN202
            out.append(m)

        await BodyLimit(route, limit=100)({"type": "http", "headers": headers}, receive, send)
        return out

    out = await call([(b"content-length", b"101")], [b"x" * 101])
    assert out[0]["status"] == 413 and ran == []
    out = await call([(b"content-length", b"abc")], [b"x"])
    assert out[0]["status"] == 413 and ran == []
    out = await call([], [b"x" * 60, b"x" * 60, b"x" * 60])
    assert [m.get("status") for m in out if m["type"] == "http.response.start"] == [413] and ran == ["disconnect"]
    assert b"body_too_large" in out[1]["body"]
    ran.clear()
    out = await call([], [b"x" * 50, b"x" * 50])
    assert out[0]["status"] == 200 and ran == [100]


def test_max_body_bytes_from_the_environment(monkeypatch):
    from app.config import get_config

    for value, want in (("2097152", 2097152), ("", 1048576), ("abc", 1048576), ("10", 1048576), ("4_194_304", 4194304)):
        monkeypatch.setenv("MAX_BODY_BYTES", value)
        get_config.cache_clear()
        assert get_config().max_body_bytes == want
    get_config.cache_clear()
