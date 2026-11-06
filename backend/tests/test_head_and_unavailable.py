"""HEAD where GET is public (0.1.51 – 0.1.50 answered 405 on the page, its files, the calendar feed and the health
check: uptime monitors and calendar clients probe with HEAD), and the answer while the database is gone: /api/health
503 with a minimal body, every other request 503 "unavailable" instead of a bare 500."""

import re

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app import api, main
from app.config import get_config
from conftest import make_client


@pytest.fixture
def ui_app(tmp_path, monkeypatch):
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><title>ui</title>")
    (static / "assets" / "app-1.js").write_text("console.log(1)")
    monkeypatch.setenv("STATIC_DIR", str(static))
    get_config.cache_clear()
    try:
        return main.create_app()
    finally:
        get_config.cache_clear()


async def test_head_on_the_page_its_files_and_the_health_check(ui_app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ui_app), base_url="http://news.test") as c:
        for path in ("/", "/vendor", "/settings/rules", "/assets/app-1.js", "/api/health"):
            got, head = await c.get(path), await c.head(path)
            assert head.status_code == got.status_code == 200, path
            assert head.content == b"" and head.headers.get("content-type") == got.headers.get("content-type"), path
        assert (await c.head("/assets/missing.js")).status_code == 404
        assert (await c.head("/api/nothing")).status_code in (404, 405)  # never the page under /api/
        assert (await c.post("/")).status_code == 405  # only GET and HEAD


async def test_head_on_the_calendar_feed(reader_client):
    url = (await reader_client.post("/api/me/calendar")).json()["url"]
    token = re.search(r"/cal/([^/]+)\.ics", url).group(1)
    async with make_client() as anon:
        head = await anon.head(f"/cal/{token}.ics")
        assert head.status_code == 200 and head.headers["content-type"].startswith("text/calendar") and head.content == b""
        assert (await anon.head("/cal/" + "A" * 43 + ".ics")).status_code == 404


async def test_health_answers_503_without_the_database(client, monkeypatch):
    assert (await client.get("/api/health")).json()["ok"] is True

    class Down:
        async def __aenter__(self):
            raise OSError("connection refused")

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(api.dbm, "session", lambda: Down())
    for method in ("GET", "HEAD"):
        r = await client.request(method, "/api/health")
        assert r.status_code == 503 and r.headers["retry-after"] == "10", method
    r = await client.get("/api/health")
    assert r.json() == {"ok": False}  # nothing more – no version, no error text


async def test_health_does_not_wait_for_a_hanging_database(client, monkeypatch):
    import asyncio

    class Hangs:
        async def __aenter__(self):
            await asyncio.sleep(60)

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(api, "HEALTH_DB_TIMEOUT", 0.2)
    monkeypatch.setattr(api.dbm, "session", lambda: Hangs())
    assert (await client.get("/api/health")).status_code == 503


def _raised_in(module: str, exc: BaseException):
    """A coroutine function whose frame belongs to `module` (as if the driver raised it)."""
    scope = {"__name__": module, "exc": exc}
    exec("async def broken(*a, **kw):\n    raise exc\n", scope)  # noqa: S102 - a test helper, fixed code
    return scope["broken"]


@pytest.mark.parametrize("exc", [OperationalError("SELECT 1", {}, OSError("gone")), ConnectionRefusedError("refused"), TimeoutError()])
async def test_a_request_meeting_no_database_gets_503_unavailable(reader_client, monkeypatch, exc):
    from app import reader

    broken = _raised_in("asyncpg.connect_utils", exc)

    monkeypatch.setattr(reader, "marks", broken)
    r = await reader_client.get("/api/reader/counts")
    assert r.status_code == 503 and r.json() == {"detail": {"code": "unavailable"}}


async def test_other_errors_stay_500(reader_client, monkeypatch):
    from app import reader

    async def broken(*a, **kw):
        raise ValueError("a bug")

    monkeypatch.setattr(reader, "marks", broken)
    with pytest.raises(ValueError):
        await reader_client.get("/api/reader/counts")  # the test transport raises what the app does not answer


@pytest.mark.parametrize("exc", [ConnectionRefusedError("refused"), TimeoutError(), OSError("x")])
async def test_an_outbound_connection_error_is_no_database_outage(reader_client, monkeypatch, exc):
    """A webhook or SMTP test that leaks a refused connection or a timeout: a 500 with its trace, not "database
    unavailable"."""
    from app import reader

    async def broken(*a, **kw):
        raise exc

    monkeypatch.setattr(reader, "marks", broken)
    with pytest.raises(type(exc)):
        await reader_client.get("/api/reader/counts")
