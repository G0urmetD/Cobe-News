"""Hardening round (0.1.47): temporary passwords expire, the request body limit in the app, the warning for a short
SECRET_KEY, throttled log lines for suspicious events, control characters in mail/chat."""

from datetime import UTC, datetime, timedelta

import pyotp
import pytest
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


async def test_a_route_reading_the_raw_body_after_the_refusal_ends_quietly_with_413():
    """Starlette's request.body() raises ClientDisconnect once the middleware said the client is gone: caught there –
    the one 413 is the answer, no traceback; a client that really went still raises."""
    from fastapi import FastAPI, Request
    from starlette.requests import ClientDisconnect

    from app.bodylimit import BodyLimit

    app = FastAPI()

    @app.post("/raw")
    async def raw(request: Request) -> dict:
        return {"n": len(await request.body())}

    async def call(parts: list[bytes], gone: bool = False) -> list[dict]:
        msgs = [{"type": "http.request", "body": p, "more_body": True} for p in parts]
        out: list[dict] = []

        async def receive():  # noqa: ANN202
            return msgs.pop(0) if msgs else {"type": "http.disconnect"}

        async def send(m):  # noqa: ANN001, ANN202
            out.append(m)

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http", "path": "/raw", "raw_path": b"/raw",
                 "query_string": b"", "root_path": "", "headers": [(b"host", b"t")], "client": ("1.2.3.4", 1), "server": ("t", 80)}  # fmt: skip
        await BodyLimit(app, limit=1000)(scope, receive, send)
        return out

    out = await call([b"a" * 600, b"a" * 600])  # chunked, past the limit: no exception out of the app
    assert [m["status"] for m in out if m["type"] == "http.response.start"] == [413]
    assert sum(1 for m in out if m["type"] == "http.response.body") == 1
    with pytest.raises(ClientDisconnect):
        await call([b"a" * 10])  # under the limit, then the client went: not hidden


def test_max_body_bytes_from_the_environment(monkeypatch):
    from app.config import get_config

    for value, want in (("2097152", 2097152), ("", 1048576), ("abc", 1048576), ("10", 1048576), ("4_194_304", 4194304)):
        monkeypatch.setenv("MAX_BODY_BYTES", value)
        get_config.cache_clear()
        assert get_config().max_body_bytes == want
    get_config.cache_clear()


# ---------------------------------------------------------------- 3. a short SECRET_KEY: a warning, never a refusal


def test_short_master_key_is_a_warning_without_the_key(monkeypatch, caplog):
    from types import SimpleNamespace

    from app import crypto, main

    for key, env, want in (
        (b"kurz-aber-da", "kurz-aber-da", "env"),
        (b"a" * 40, "a" * 40, "env"),  # long, but hardly any entropy
        (b"x7Hq2pLm9VzK4wRt8sYn3bCd6fGj1kQe5u", "x7Hq2pLm9VzK4wRt8sYn3bCd6fGj1kQe5u", None),
        (b"0123456789abcdefghij", "", "file"),  # a key file of 20 bytes (16 is the least it takes)
        (b"A" * 44, "", "file"),
    ):
        monkeypatch.setattr(crypto, "master", lambda key=key: key)
        monkeypatch.setattr(crypto, "get_config", lambda env=env: SimpleNamespace(secret_key=env))
        assert crypto.key_weakness() == want, key
        caplog.clear()
        assert main.warn_weak_key() is bool(want)
        lines = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert len(lines) == (1 if want else 0)
        if want:
            assert key.decode() not in lines[0] and ("SECRET_KEY is short" in lines[0] if env else "secret.key in DATA_DIR is short" in lines[0])


async def test_short_key_and_the_emergency_alert_show_in_the_https_pane(admin_client, monkeypatch):
    from app import crypto

    assert (await admin_client.get("/api/admin/tls")).json()["system"] == []  # the test key is fine
    monkeypatch.setattr(crypto, "key_weakness", lambda: "env")
    assert (await admin_client.get("/api/admin/tls")).json()["system"] == [{"code": "secret_key_short", "source": "env", "min": 32}]


# ---------------------------------------------------------------- 5. suspicious events: throttled log lines


async def test_csrf_failures_are_logged_throttled_per_source_never_the_token(client, caplog):
    from app import suspicious

    suspicious.reset()
    caplog.set_level("WARNING", logger="cobe_news.security")
    await client.get("/api/auth/config")  # the CSRF cookie
    cookie = client.cookies.get("cobe_news_csrf")
    for headers in ({"X-CSRF-Token": "falsch-" + "x" * 30}, {"X-CSRF-Token": ""}, {"X-CSRF-Token": "y" * 40}):
        r = await client.post("/api/auth/logout", headers=headers)
        assert r.status_code == 403 and r.json()["detail"]["code"] == "csrf_failed"
    lines = [r.getMessage() for r in caplog.records if r.name == "cobe_news.security"]
    assert len(lines) == 1 and "csrf check failed: POST /api/auth/logout from 127.0.0.1 (token mismatch)" in lines[0]
    assert cookie not in lines[0] and "falsch" not in lines[0]
    # a line feed in the path cannot start a forged line
    suspicious.reset()
    caplog.clear()
    assert suspicious.csrf_failed("POST", "/api/x\nINFO forged", "2001:db8:1:2::7", cookie=False, header=True)
    (line,) = [r.getMessage() for r in caplog.records if r.name == "cobe_news.security"]
    assert "\n" not in line and "/api/x?INFO forged from 2001:db8:1:2::/64 (token cookie missing)" in line


def test_throttle_one_line_per_source_and_minute_and_a_cap_for_all():
    from app.suspicious import Throttle

    t = Throttle(every=60, total=3, max_keys=5)
    assert t.hit("a", 0) == 0
    assert [t.hit("a", s) for s in (1, 2, 30)] == [None, None, None]
    assert t.hit("a", 61) == 3  # the next line names what was held back
    assert t.hit("b", 62) == 0 and t.hit("c", 63) == 0
    assert t.hit("d", 64) is None  # three lines in the last minute already – across all sources
    assert t.hit("d", 125) == 1
    for k in "efghij":
        t.hit(k, 200)
    assert len(t._last) == 5  # bounded


async def test_emergency_budget_exceeded_is_reported_once(client, admin_client, monkeypatch, caplog):
    from app.auth import bruteforce

    monkeypatch.setattr(bruteforce, "EMERGENCY_BUDGET", 4)
    monkeypatch.setattr(bruteforce, "EMERGENCY_SLOW", 0.0)
    await _setup_done()
    await add_user("notfall", "admin", emergency=True, totp_secret=pyotp.random_base32())
    caplog.set_level("WARNING", logger="cobe_news.auth")
    for _ in range(9):
        r = await client.post("/api/auth/login", json={"username": "notfall", "password": "falsch-falsch-falsch"})
        assert r.status_code == 401
    lines = [r.getMessage() for r in caplog.records if "emergency admin" in r.getMessage()]
    assert len(lines) == 1 and "4 failed sign-in checks in the last hour (budget 4)" in lines[0] and "falsch" not in lines[0]
    async with db.session() as s:
        (e,) = list(await s.scalars(select(AuditEntry).where(AuditEntry.action == "login.emergency_slowed")))
        assert e.actor_kind == "system" and e.target_label == "notfall" and e.details == {"failures_1h": 4, "budget": 4, "stage": "password"}
    system = (await admin_client.get("/api/admin/tls")).json()["system"]
    assert [w["code"] for w in system] == ["emergency_failures"] and system[0]["failures"] == 4
    # an hour later (the throttle): reported again
    monkeypatch.setattr(bruteforce, "_emergency_alerted", [bruteforce._emergency_alerted[0] - 3601])
    f = bruteforce.register_failure("local:notfall", "127.0.0.1", lock_account=False, emergency=True)
    assert f.emergency_alert >= 4


# ---------------------------------------------------------------- 6. control and direction characters in mail/chat

# U+202A–202E, U+2066–2069, U+200E/F, U+061C and other control characters (C0 but \n and \t, DEL, C1) – built from their
# code points, so this file shows what it tests
DIRECTION = [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C]
CONTROL = [0x00, 0x07, 0x08, 0x0B, 0x0C, 0x1B, 0x7F, 0x85, 0x9B, 0x2028, 0x2029]
BAD = {chr(c) for c in DIRECTION + CONTROL}
EVIL = "Update" + chr(0x202E) + "fdp.exe" + chr(0x2066) + " fix" + chr(0x07) + chr(0x1B) + "[31m" + chr(0x200F) + chr(0x85)


def _clean(out) -> None:  # noqa: ANN001 - a str, a tuple or a dict of what went out
    import json

    text = out if isinstance(out, str) else json.dumps(out, ensure_ascii=False)
    found = sorted({f"U+{ord(c):04X}" for c in text if c in BAD})
    assert not found, found


def test_plaintext_neutral():
    from app.plaintext import neutral

    assert neutral(EVIL) == "Updatefdp.exe fix  [31m "
    assert neutral("Zeile 1\r\nZeile 2\rZeile 3\tTab") == "Zeile 1\nZeile 2\nZeile 3\tTab"
    assert neutral("") == "" and neutral(None) == ""  # type: ignore[arg-type]
    for c in BAD:
        assert c not in neutral(f"a{c}b")


def test_every_channel_gets_the_story_without_direction_or_control_characters():
    from app import notify, webpush

    s = notify.Story("00000000-0000-4000-8000-000000000009", EVIL, f"Erster Satz {EVIL}. Zweiter.\n{EVIL}", "https://x.example/a", "critical", f"Quelle {EVIL}", datetime(2026, 11, 3, tzinfo=UTC), ["CVE-2026-1"], product=f"Produkt {EVIL}")
    many = [notify.Story(f"00000000-0000-4000-8000-00000000001{i}", EVIL, EVIL, "https://x.example/a", "high", EVIL, datetime(2026, 11, 3, tzinfo=UTC), product=EVIL) for i in range(8)]
    for stories in ([s], many):
        total = len(stories)
        subject, text, html = notify.render_mail("Regel", stories, total, "de")
        _clean(subject)
        _clean(text)
        _clean(html)
        _clean(notify.render_slack("Regel", stories, total, "de"))
        _clean(notify.render_teams("Regel", stories, total, "de"))
        _clean(notify.render_discord("Regel", stories, total, "de"))
        _clean(notify.render_telegram("Regel", stories, total, "de"))
        _clean(notify.render_webhook("Kanal", ["Regel"], stories, total, "de"))
        _clean(notify.render_mattermost("Regel", stories, total, "de"))
        title, message, _sev, _click = notify.render_push("Regel", stories, total, "de")
        _clean(notify.ntfy_payload("topic", title, message, "high", "https://x.example/"))
        _clean(notify.gotify_payload(title, message, "high", "https://x.example/"))
    # the subject of one story still reads as the title (the characters gone, the words kept)
    assert notify.one_line(notify.render_mail("Regel", [s], 1, "de")[0]) == "[Cobe News] Kritisch: Updatefdp.exe fix [31m"  # as send_mail sets it
    # a rule or label passed in raw: the one-line helpers neutralise it as well
    _clean(notify.one_line(EVIL))
    _clean(notify.plain_block(EVIL))
    _clean(notify.render_slack(EVIL, [s], 1, "de"))
    # desktop push (Web Push)
    _clean(webpush.story_payload({"id": "x", "title": EVIL, "severity": "high", "source": EVIL}, "de"))
    _clean(webpush.vendor_payload("x", EVIL, EVIL, "high", "/vendor", "de"))


def test_forwarded_story_and_comment_without_direction_or_control_characters():
    from app import forward

    f = forward.Forward(
        sender="Rudi", team="SOC", comment=forward.clean_comment(f"Bitte prüfen {EVIL}\n\n\n\nZeile"), title=EVIL, summary=f"Erster {EVIL}. Zweiter.", url="https://x.example/a",
        link="https://news.corp.example/?story=x", severity="high", source=EVIL, published_at=datetime(2026, 11, 3, tzinfo=UTC), product=EVIL,
    )
    assert f.comment.startswith("Bitte prüfen Updatefdp[.]exe fix") and "\n\nZeile" in f.comment and "\n\n\n" not in f.comment
    for out in (
        forward.render_slack(f, "de"),
        forward.render_teams(f, "de"),
        forward.render_discord(f, "de"),
        forward.render_telegram(f, "en"),
        forward.render_text(f, "de"),
        forward.render_mattermost(f, "de"),
        forward.render_mail(f, "de"),
        forward.render_webhook(f, "Kanal", "de", "d-1"),
    ):
        _clean(out)
