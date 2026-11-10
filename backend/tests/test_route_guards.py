"""Every route of the app and the guard it has: public (a short, fixed list), an API token (/api/v1, /metrics), a sign-in
under way (a stage), any signed-in person, or an admin. A new route without a guard – or an admin route a reader
reaches – fails here, whatever router it is in (the frontend hides pages, it protects nothing)."""

import re

import pytest
from conftest import make_client
from fastapi.routing import APIRoute

from app.main import app

PUBLIC = {
    ("POST", "/api/setup"),  # the one-time setup token from the log
    ("GET", "/api/auth/config"),
    ("GET", "/api/auth/state"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/logout"),
    ("GET", "/api/auth/oidc/start"),
    ("GET", "/api/auth/oidc/callback"),  # bound to the encrypted state cookie
    ("POST", "/api/auth/passkey/options"),  # a passkey sign-in starts here: rate-limited per address and per IPv6 /48
    ("POST", "/api/auth/passkey/login"),  # bound to the flow cookie and its single-use challenge
    ("GET", "/cal/{name}"),  # the calendar feed: a token of its own in the address
    ("GET", "/api/health"),
    ("GET", "/{path:path}"),  # the built web UI (only with static files)
}
# admin routes outside /api/admin/
ADMIN_ELSEWHERE = {"/api/vendor/follows/{key}", "/api/vendor/custom", "/api/vendor/follows/{key}/versions", "/api/vendor/versions/{vid}", "/api/vendor/cpe-search"}


def _deps(dependant, out: set[str]) -> set[str]:
    for sub in dependant.dependencies:
        out.add(getattr(sub.call, "__qualname__", getattr(sub.call, "__name__", "")))
        _deps(sub, out)
    return out


def _walk(routes, prefix: str = ""):
    for r in routes:
        if isinstance(r, APIRoute):
            yield prefix + r.path, r
        elif hasattr(r, "original_router"):  # an included router (FastAPI ≥ 0.120)
            yield from _walk(r.original_router.routes, prefix + r.include_context.prefix)
        elif hasattr(r, "routes") and hasattr(r, "path"):
            yield from _walk(r.routes, prefix + r.path)


def routes() -> list[tuple[str, str, str]]:
    """(method, path, guard) of every route: public | token | stage | reader | admin."""
    out = []
    for path, r in _walk(app.routes):
        d = _deps(r.dependant, set())
        guard = (
            "admin" if "admin_user" in d
            else "token" if any(x.startswith("require.") for x in d)
            else "reader" if "current_user" in d or "current_session" in d or "peek_session" in d  # peek: without touching it
            else "stage" if any(x.startswith("session_in_stage.") for x in d)
            else "public"
        )  # fmt: skip
        out.extend((m, path, guard) for m in sorted(r.methods) if m != "HEAD")
    return sorted(out)


ROUTES = routes()


def test_the_inventory_is_complete():
    assert len(ROUTES) >= 150
    public = {(m, p) for m, p, g in ROUTES if g == "public"}
    assert public <= PUBLIC, sorted(public - PUBLIC)  # a route without any guard that is not meant to be public


@pytest.mark.parametrize(("method", "path", "guard"), ROUTES)
def test_every_route_has_the_intended_guard(method, path, guard):
    if (method, path) in PUBLIC:
        assert guard == "public"
    elif path.startswith("/api/admin/") or path in ADMIN_ELSEWHERE:
        assert guard == "admin", (method, path, guard)
    elif path.startswith("/api/v1/") or path == "/metrics":
        assert guard == "token", (method, path, guard)
    elif path.startswith("/api/auth/") and guard == "stage":
        assert method == "POST" and re.fullmatch(r"/api/auth/(mfa|mfa/device|password|enroll/start|enroll/confirm|enroll/passkey/options|enroll/passkey)", path), path
    else:
        assert guard == "reader", (method, path, guard)


def _url(path: str) -> str:
    path = path.replace("{source}", "ldap").replace("{key:path}", "x")
    return re.sub(r"\{[^}]+\}", "00000000-0000-0000-0000-000000000000", path)


async def test_the_guards_hold_on_the_wire(reader_client):
    """Called for real: nobody signed in → 401 on everything that is not public; a reader → 403 on every admin route."""
    async with make_client() as anon:
        for method, path, guard in ROUTES:
            if guard == "public" or path == "/{path:path}":
                continue
            r = await anon.request(method, _url(path), json={})
            assert r.status_code == 401, (method, path, r.status_code, r.text[:200])
    for method, path, guard in ROUTES:
        if guard == "admin":
            r = await reader_client.request(method, _url(path), json={})
            assert r.status_code == 403 and r.json()["detail"]["code"] == "forbidden", (method, path, r.status_code, r.text[:200])
