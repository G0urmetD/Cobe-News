"""The platform review (0.1.38): the same security headers on every answer of the app – also on the ones the guard
refuses before any route runs –, no CORS, no API description or debug pages, and the web UI's file lookup never leaves
the built UI (dot segments, encoded ones, absolute paths) and takes a NUL without a 500."""

import httpx
import pytest

from app import main
from app.config import get_config

BASE = ("x-content-type-options", "referrer-policy", "x-frame-options", "content-security-policy", "permissions-policy", "cross-origin-opener-policy")


def _secured(r: httpx.Response, api: bool = True) -> None:
    for h in BASE:
        assert h in r.headers, (r.request.url, h)
    assert r.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "camera=()" in r.headers["permissions-policy"]
    if api:
        assert r.headers["cache-control"] == "no-store", r.request.url
    assert "access-control-allow-origin" not in r.headers


async def test_headers_also_on_answers_the_guard_refuses(client):
    _secured(await client.get("/api/auth/config"))
    # no CSRF token: refused before the route – still with every header and not cached
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://news.test") as bare:
        r = await bare.post("/api/auth/logout")
        assert r.status_code == 403 and r.json()["detail"]["code"] == "csrf_failed"
        _secured(r)
        # an API token may only read
        r = await bare.post("/api/v1/news", headers={"Authorization": "Bearer cnt_" + "a" * 40})
        assert r.status_code == 403
        _secured(r)
        # a NUL in a query
        r = await bare.get("/api/news?q=%00")
        assert r.status_code == 422
        _secured(r)


async def test_no_cors_and_no_api_description(client):
    evil = {"Origin": "https://evil.example"}
    r = await client.options("/api/auth/login", headers={**evil, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "x-csrf-token"})
    assert "access-control-allow-origin" not in r.headers and "access-control-allow-credentials" not in r.headers
    r = await client.get("/api/health", headers=evil)
    assert r.status_code == 200 and "access-control-allow-origin" not in r.headers
    for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect", "/api/openapi.json", "/api/v1/openapi.json"):
        assert (await client.get(path)).status_code == 404, path
    assert main.app.debug is False


@pytest.fixture
def ui(tmp_path, monkeypatch):
    """An app with a built UI next to a file it must never hand out."""
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><title>ui</title>")
    (static / "assets" / "app-1.js").write_text("console.log(1)")
    (static / "sw.js").write_text("self.x = 1")
    (tmp_path / "secret.txt").write_text("SECRET")
    monkeypatch.setenv("STATIC_DIR", str(static))
    get_config.cache_clear()
    try:
        app = main.create_app()
    finally:
        get_config.cache_clear()
    return app, tmp_path / "secret.txt"


async def test_the_ui_files_stay_inside_the_build(ui):
    app, secret = ui
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://news.test") as c:
        r = await c.get("/")
        assert r.status_code == 200 and "<title>ui</title>" in r.text and r.headers["cache-control"] == "no-cache"
        _secured(r, api=False)
        r = await c.get("/assets/app-1.js")
        assert r.status_code == 200 and r.text == "console.log(1)"
        _secured(r, api=False)
        assert (await c.get("/sw.js")).headers["cache-control"] == "no-cache"
        for path in ("/%2e%2e/secret.txt", "/..%2fsecret.txt", "/assets/%2e%2e/%2e%2e/secret.txt", "/" + str(secret), "/%2e%2e/static/../secret.txt"):
            r = await c.get(path)
            assert "SECRET" not in r.text, path
        # under /api/ never the UI, not even with dot segments; a NUL (the app's own port – nginx refuses it): no 500
        for path in ("/api/%2e%2e/index.html", "/api", "/api/nothing", "/x%00.js", "/%00"):
            r = await c.get(path)
            assert r.status_code == 404 and r.headers["content-type"] == "application/json", path
        # a missing build file is a 404, not the page (the proxy would otherwise keep a wrong answer for a year)
        assert (await c.get("/assets/missing.js")).status_code == 404
