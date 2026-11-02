"""API tokens (app/api_tokens.py), the documented read-only API (app/api_v1.py) and /metrics (app/metrics.py): a token
is ≥ 256 bit with a recognisable prefix, stored only as its keyed hash, shown once; made and revoked by admins with a
fresh proof of identity; reaches only GET /api/v1/… (scope read) and GET /metrics (scope metrics), never anything else
and never together with a session cookie; expired, revoked, orphaned and unknown tokens get the same 401; limited per
token and – shared with the calendar feed – per address for wrong ones. The metrics: the text format (names, HELP/TYPE,
escaping, numbers), the scope, no personal data, the cache. No public /docs or /openapi.json."""

import re
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select, update

from app import api_tokens, calendar_feed, db, metrics
from app.crypto import token_hash
from app.main import app
from app.models import ApiToken, NewsItem, NewsSource, NotifyChannel, User
from conftest import add_user, make_client, sign_in
from test_advisory_changes import _follow, _store, pan

NOW = datetime.now(UTC)


@pytest.fixture(autouse=True)
def fresh_metrics():
    metrics.reset()
    yield
    metrics.reset()


def bare(**headers) -> httpx.AsyncClient:
    """Not a browser: no cookies, no CSRF – a script or Prometheus."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://news.test", headers=headers)


async def make_token(c, name: str = "SIEM", scopes=("read",), days: int | None = None) -> str:
    r = await c.post("/api/admin/api-tokens", json={"name": name, "scopes": list(scopes), **({"expires_days": days} if days else {})})
    assert r.status_code == 201, r.text
    return r.json()["token"]


async def get(path: str, token: str | None, **kw) -> httpx.Response:
    async with bare(**({"Authorization": f"Bearer {token}"} if token else {})) as c:
        return await c.get(path, **kw)


async def _story(title: str = "Kritische Lücke in Example Gateway", **kw) -> NewsItem:
    async with db.session() as s:
        src = await s.scalar(select(NewsSource).where(NewsSource.enabled.is_(True)).limit(1))
        if src is None:
            src = await s.scalar(select(NewsSource).limit(1))
            src.enabled = True
        i = NewsItem(
            source_id=src.id,
            url=f"https://news.example.com/{uuid.uuid4()}",
            url_key=str(uuid.uuid4()),
            title=title,
            title_key=title.lower(),
            summary="Ein Beispiel.",
            published_at=kw.pop("published_at", NOW - timedelta(hours=1)),
            severity=kw.pop("severity", "critical"),
            cves=["CVE-2026-0001"],
            **kw,
        )
        s.add(i)
        await s.commit()
        return i


# ---------------------------------------------------------------- making and listing


async def test_token_is_long_prefixed_hashed_and_shown_once(admin_client):
    token = await make_token(admin_client)
    assert re.fullmatch(r"cnt_[A-Za-z0-9_-]{43}", token)  # 32 random bytes = 256 bit
    async with db.session() as s:
        row = await s.scalar(select(ApiToken))
    assert row.token_hash == token_hash(token) and token not in row.token_hash
    assert row.prefix == token[:10] and row.scopes == ["read"] and row.expires_at is not None and not row.expiry_added  # the default: 365 days
    listing = (await admin_client.get("/api/admin/api-tokens")).json()
    assert token not in str(listing) and token[10:] not in str(listing)
    item = listing["items"][0]
    assert item["state"] == "active" and item["prefix"] == token[:10] and item["created_by"]["username"] == "anna"
    # two tokens never share a value
    assert await make_token(admin_client, "Zweiter") != token


async def test_only_admins_with_a_fresh_proof_make_and_revoke(admin_client, reader_client):
    assert (await reader_client.get("/api/admin/api-tokens")).status_code == 403
    assert (await reader_client.post("/api/admin/api-tokens", json={"name": "x", "scopes": ["read"]})).status_code == 403
    token = await make_token(admin_client)
    tid = (await admin_client.get("/api/admin/api-tokens")).json()["items"][0]["id"]
    from app.models import UserSession

    async with db.session() as s:
        await s.execute(update(UserSession).values(reauth_at=datetime.now(UTC) - timedelta(hours=1)))
        await s.commit()
    r = await admin_client.post("/api/admin/api-tokens", json={"name": "y", "scopes": ["read"]})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    r = await admin_client.post(f"/api/admin/api-tokens/{tid}/revoke")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    assert (await get("/api/v1/news", token)).status_code == 200  # nothing happened


@pytest.mark.parametrize(
    "body",
    [
        {"name": "", "scopes": ["read"]},
        {"name": "x", "scopes": []},
        {"name": "x", "scopes": ["write"]},
        {"name": "x", "scopes": ["admin"]},
        {"name": "x", "scopes": ["read"], "expires_days": 0},
        {"name": "x", "scopes": ["read"], "expires_days": 366},  # at most a year
        {"name": "x", "scopes": ["read"], "expires_days": None},  # no "never" any more
        {"name": "a\nb", "scopes": ["read"]},
        {"name": "x", "scopes": ["read"], "role": "admin"},
    ],
)
async def test_no_writing_or_admin_scope_and_sane_input(admin_client, body):
    assert (await admin_client.post("/api/admin/api-tokens", json=body)).status_code == 422


async def test_expiry_is_stored(admin_client):
    await make_token(admin_client, days=30)
    async with db.session() as s:
        row = await s.scalar(select(ApiToken))
    assert timedelta(days=29, hours=23) < row.expires_at - datetime.now(UTC) <= timedelta(days=30)


# ---------------------------------------------------------------- what a token reaches


async def test_scopes_keep_to_their_endpoints(admin_client):
    read = await make_token(admin_client, "SIEM", ["read"])
    prom = await make_token(admin_client, "Prometheus", ["metrics"])
    both = await make_token(admin_client, "Beides", ["read", "metrics"])
    assert (await get("/api/v1/news", read)).status_code == 200
    assert (await get("/api/v1/vendor/products", read)).status_code == 200
    r = await get("/metrics", read)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "insufficient_scope"
    assert (await get("/metrics", prom)).status_code == 200
    r = await get("/api/v1/news", prom)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "insufficient_scope"
    assert (await get("/api/v1/news", both)).status_code == 200 and (await get("/metrics", both)).status_code == 200


@pytest.mark.parametrize("path", ["/api/news", "/api/me", "/api/admin/api-tokens", "/api/admin/api-tokens/openapi.json", "/api/admin/backup", "/api/vendor/overview", "/api/health", "/", "/settings"])
async def test_a_token_reaches_nothing_else(admin_client, path):
    token = await make_token(admin_client, scopes=["read", "metrics"])
    r = await get(path, token)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "token_not_allowed"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def test_a_token_only_reads(admin_client, method):
    token = await make_token(admin_client, scopes=["read", "metrics"])
    async with bare(Authorization=f"Bearer {token}") as c:
        for path in ("/api/v1/news", "/metrics", "/api/admin/api-tokens", "/api/news/read-all"):
            r = await c.request(method, path)
            assert r.status_code == 403, (method, path, r.status_code)
            if method != "HEAD":
                assert r.json()["detail"]["code"] == "token_read_only"


async def test_never_together_with_a_session_cookie(admin_client):
    """A bearer token next to a signed-in session is refused – also an admin's own session; the cookie alone never opens
    the token API (it is not the UI's)."""
    token = await make_token(admin_client)
    r = await admin_client.get("/api/v1/news", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "bearer_with_cookie"
    r = await admin_client.get("/api/admin/backup", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400  # not even for the admin's own pages
    r = await admin_client.get("/api/v1/news")
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")


async def test_bearer_needs_no_csrf_and_gets_no_csrf_cookie(admin_client):
    token = await make_token(admin_client)
    r = await get("/api/v1/news", token)
    assert r.status_code == 200 and "set-cookie" not in r.headers
    assert r.headers["cache-control"] == "no-store"


async def test_ended_tokens_get_one_and_the_same_answer(admin_client):
    """Unknown, malformed, revoked, expired, orphaned: the same status, body and header – nothing tells them apart."""
    gone = await make_token(admin_client, "revoked")
    old = await make_token(admin_client, "expired")
    async with db.session() as s:
        rows = {r.name: r for r in await s.scalars(select(ApiToken))}
        rows["expired"].expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await s.commit()
    assert (await admin_client.post(f"/api/admin/api-tokens/{rows['revoked'].id}/revoke")).status_code == 200
    answers = []
    for t in (gone, old, "cnt_" + "A" * 43, "cnt_short", "x" * 300, gone[:-1] + ("A" if gone[-1] != "A" else "B"), None):
        r = await get("/api/v1/news", t)
        answers.append((r.status_code, r.text, r.headers.get("www-authenticate")))
    assert len(set(answers)) == 1 and answers[0][0] == 401
    assert '"invalid_token"' in answers[0][1]
    states = {x["name"]: x["state"] for x in (await admin_client.get("/api/admin/api-tokens")).json()["items"]}
    assert states == {"revoked": "revoked", "expired": "expired"}


async def test_a_token_ends_with_its_admin(admin_client):
    """Made a reader, switched off or deleted: the admin's tokens stop at once."""
    token = await make_token(admin_client)
    uid = admin_client.user.id
    async with db.session() as s:
        await s.execute(update(User).where(User.id == uid).values(role="reader"))
        await s.commit()
    assert (await get("/api/v1/news", token)).status_code == 401
    async with db.session() as s:
        await s.execute(update(User).where(User.id == uid).values(role="admin", is_active=False))
        await s.commit()
    assert (await get("/api/v1/news", token)).status_code == 401
    async with db.session() as s:
        await s.execute(update(User).where(User.id == uid).values(is_active=True))
        await s.commit()
    assert (await get("/api/v1/news", token)).status_code == 200
    async with db.session() as s:
        await s.delete(await s.get(User, uid))
        await s.commit()
    assert (await get("/api/v1/news", token)).status_code == 401
    async with db.session() as s:
        assert await s.scalar(select(ApiToken)) is None  # deleted with the account


async def test_revoke_works_at_once_and_last_use_is_kept(admin_client):
    token = await make_token(admin_client)
    assert (await get("/api/v1/news", token)).status_code == 200
    item = (await admin_client.get("/api/admin/api-tokens")).json()["items"][0]
    assert item["last_used_at"] is not None
    r = await admin_client.post(f"/api/admin/api-tokens/{item['id']}/revoke")
    assert r.status_code == 200 and r.json()["items"][0]["state"] == "revoked"
    assert (await get("/api/v1/news", token)).status_code == 401
    assert (await admin_client.post(f"/api/admin/api-tokens/{uuid.uuid4()}/revoke")).status_code == 404


async def test_rate_limit_per_token(admin_client, monkeypatch):
    monkeypatch.setattr(api_tokens, "TOKEN_MAX", 3)
    a = await make_token(admin_client, "a")
    b = await make_token(admin_client, "b")
    assert [(await get("/api/v1/news", a)).status_code for _ in range(4)] == [200, 200, 200, 429]
    r = await get("/api/v1/news", a)
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    assert (await get("/api/v1/news", b)).status_code == 200  # the other token has its own budget


async def test_wrong_tokens_share_the_feeds_budget_per_address(admin_client, monkeypatch):
    """Guessing is held to the same few wrong secrets per address as the calendar feed – across both."""
    monkeypatch.setattr(calendar_feed, "FAIL_MAX", 3)
    good = await make_token(admin_client)
    for _ in range(2):
        assert (await get("/api/v1/news", "cnt_" + "B" * 43)).status_code == 401
    async with bare() as c:
        assert (await c.get("/cal/" + "C" * 43 + ".ics")).status_code == 404  # a wrong calendar address: the third
    assert (await get("/api/v1/news", "cnt_" + "D" * 43)).status_code == 429
    assert (await get("/api/v1/news", good)).status_code == 429  # the whole address waits
    async with bare() as c:
        assert (await c.get("/cal/" + "E" * 43 + ".ics")).status_code == 429
    calendar_feed.reset()
    assert (await get("/api/v1/news", good)).status_code == 200


async def test_requests_without_any_token_are_not_counted(monkeypatch):
    monkeypatch.setattr(calendar_feed, "FAIL_MAX", 2)
    for _ in range(5):
        assert (await get("/metrics", None)).status_code == 401


async def test_old_tokens_are_pruned(admin_client):
    await make_token(admin_client, "alt")
    await make_token(admin_client, "neu")
    async with db.session() as s:
        await s.execute(update(ApiToken).where(ApiToken.name == "alt").values(revoked_at=datetime.now(UTC) - timedelta(days=31)))
        await s.commit()
        assert await api_tokens.prune(s) == 1
        assert [t.name for t in await s.scalars(select(ApiToken))] == ["neu"]


# ---------------------------------------------------------------- the documented API


async def test_news_shapes_filters_and_paging(admin_client):
    token = await make_token(admin_client)
    for n in range(5):
        await _story(f"Story {n}", published_at=NOW - timedelta(hours=n), severity="critical" if n % 2 else "low")
    r = await get("/api/v1/news", token, params={"limit": 2})
    page = r.json()
    assert r.status_code == 200 and [x["title"] for x in page["items"]] == ["Story 0", "Story 1"] and page["next"]
    item = page["items"][0]
    assert set(item) == {"id", "title", "summary", "url", "source", "published_at", "severity", "cves", "also_in", "topics"}
    assert set(item["source"]) == {"key", "name"}
    page2 = (await get("/api/v1/news", token, params={"limit": 2, "before": page["next"]})).json()
    assert [x["title"] for x in page2["items"]] == ["Story 2", "Story 3"]
    crit = (await get("/api/v1/news", token, params={"severity": "critical"})).json()["items"]
    assert {x["title"] for x in crit} == {"Story 1", "Story 3"}
    since = (await get("/api/v1/news", token, params={"since": (NOW - timedelta(hours=1, minutes=30)).isoformat()})).json()["items"]
    assert [x["title"] for x in since] == ["Story 0", "Story 1"]
    one = await get(f"/api/v1/news/{item['id']}", token)
    assert one.status_code == 200 and one.json()["title"] == "Story 0" and one.json()["epss"] == []
    assert (await get(f"/api/v1/news/{uuid.uuid4()}", token)).status_code == 404
    assert (await get("/api/v1/news", token, params={"before": "nonsense"})).status_code == 422
    srcs = (await get("/api/v1/news/sources", token)).json()
    assert srcs and set(srcs[0]) == {"key", "name"}


async def test_vendor_products_and_findings(admin_client):
    token = await make_token(admin_client)
    await _follow(admin_client, "panos", "11.2.3")
    await _store(pan())
    r = await get("/api/v1/vendor/products", token)
    assert r.status_code == 200
    (p,) = r.json()["items"]
    assert p["key"] == "panos" and p["versions"][0]["version"] == "11.2.3" and p["counts"]["affected"] == 1
    assert "note" not in p and "follow" not in p
    d = (await get("/api/v1/vendor/products/panos", token)).json()
    assert d["shown"] == 1 and d["findings"][0]["id"] == "paloalto:CVE-2026-1001" and d["findings"][0]["status"] == "affected"
    assert d["findings"][0]["versions"] == [{"version": "11.2.3", "status": "affected", "fixed": d["findings"][0]["versions"][0]["fixed"]}]
    assert (await get("/api/v1/vendor/products/not-followed", token)).status_code == 404
    f = (await get("/api/v1/vendor/findings", token)).json()
    assert f["total"] == 1 and f["items"][0]["product"] == "panos"
    assert (await get("/api/v1/vendor/findings", token, params={"severity": "critical"})).json()["total"] == 0
    assert (await get("/api/v1/vendor/findings", token, params={"exploited": "true"})).json()["total"] == 0


async def test_curated_openapi_only_for_admins_and_no_public_docs(admin_client, reader_client):
    spec = (await admin_client.get("/api/admin/api-tokens/openapi.json")).json()
    assert spec["openapi"].startswith("3.") and spec["info"]["title"] == "Cobe News API"
    assert set(spec["paths"]) == {
        "/api/v1/news",
        "/api/v1/news/sources",
        "/api/v1/news/{story_id}",
        "/api/v1/vendor/products",
        "/api/v1/vendor/products/{key}",
        "/api/v1/vendor/findings",
        "/metrics",
    }
    assert spec["components"]["securitySchemes"]["bearer"] == {"type": "http", "scheme": "bearer", "description": "An API token (cnt_…)"}
    assert all(op["x-scope"] == ("metrics" if p == "/metrics" else "read") for p, ops in spec["paths"].items() for op in ops.values())
    assert all(list(ops) == ["get"] for ops in spec["paths"].values())
    assert (await reader_client.get("/api/admin/api-tokens/openapi.json")).status_code == 403
    assert app.openapi_url is None and app.docs_url is None and app.redoc_url is None
    async with bare() as c:
        for path in ("/docs", "/redoc", "/openapi.json", "/api/openapi.json", "/api/v1/openapi.json"):
            r = await c.get(path)
            assert r.status_code in (401, 404), path  # /api/v1/… without a token: 401, nothing is described


# ---------------------------------------------------------------- /metrics


SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\[\\"n])*"(,[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\[\\"n])*")*)?\})? (\S+)$')


def parse_exposition(body: str) -> dict[str, dict]:
    """A strict reader of the text format 0.0.4: HELP and TYPE once per family and before its samples, every sample of
    a declared family, label values properly escaped, values numbers (or NaN/±Inf), the body ends with a newline."""
    assert body.endswith("\n")
    fams: dict[str, dict] = {}
    current = None
    for line in body.rstrip("\n").split("\n"):
        if line.startswith("# HELP "):
            name, _, help_ = line[7:].partition(" ")
            assert name not in fams, f"family {name} twice"
            fams[name] = {"help": help_, "type": None, "samples": []}
            current = name
        elif line.startswith("# TYPE "):
            name, _, kind = line[7:].partition(" ")
            assert name == current and fams[name]["type"] is None and kind in ("gauge", "counter", "untyped")
            fams[name]["type"] = kind
        else:
            m = SAMPLE.match(line)
            assert m, f"bad sample line {line!r}"
            assert m.group(1) == current, f"{m.group(1)} outside its family"
            v = m.group(5)
            assert v in ("NaN", "+Inf", "-Inf") or re.fullmatch(r"-?\d+(\.\d+)?([eE][-+]?\d+)?", v), v
            labels = dict(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"', m.group(3) or ""))
            fams[current]["samples"].append((labels, v))
    return fams


def test_exposition_escapes_and_formats():
    out = metrics.Exposition()
    out.family("x_total", "counter", 'Help with \\ and\nnewline "quotes"', [({"name": 'a "b" \\ c\nd'}, 3)])
    out.one("y", "y", 0.5)
    out.one("z", "z", float("nan"))
    out.one("w", "w", None)
    out.one("v", "v", True)
    out.one("u", "u", float("inf"))
    body = out.render().decode()
    assert '# HELP x_total Help with \\\\ and\\nnewline "quotes"' in body
    assert 'x_total{name="a \\"b\\" \\\\ c\\nd"} 3' in body
    assert "\ny 0.5\n" in body and "\nz NaN\n" in body and "\nw NaN\n" in body and "\nv 1\n" in body and "\nu +Inf\n" in body
    fams = parse_exposition(body)
    assert fams["x_total"]["samples"] == [({"name": 'a \\"b\\" \\\\ c\\nd'}, "3")]
    with pytest.raises(ValueError):
        out.one("y", "again", 1)  # one family once
    with pytest.raises(ValueError):
        out.one("bad-name", "x", 1)
    with pytest.raises(ValueError):
        out.family("ok", "gauge", "x", [({"bad-label": "x"}, 1)])
    with pytest.raises(ValueError):
        out.family("ok2", "gauge", "x", [({"__reserved": "x"}, 1)])


async def test_metrics_content_format_and_no_personal_data(admin_client):
    from app import __version__

    token = await make_token(admin_client, scopes=["metrics"])
    await add_user("max", "reader", email="max@corp.example")
    async with db.session() as s:
        s.add(NotifyChannel(name="Max Mustermann privat", type="teams", failures=2, next_try_at=datetime.now(UTC) + timedelta(minutes=5)))
        await s.commit()
    await _story("Geheimer Titel einer Meldung")
    r = await get("/metrics", token)
    assert r.status_code == 200 and r.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
    assert r.headers["cache-control"] == "no-store"
    fams = parse_exposition(r.text)
    assert fams["cobe_news_info"]["samples"] == [({"version": __version__}, "1")]
    for name in (
        "cobe_news_source_state",
        "cobe_news_source_consecutive_failures",
        "cobe_news_sources",
        "cobe_news_channel_backoff",
        "cobe_news_channel_pending_items",
        "cobe_news_personal_deliveries",
        "cobe_news_backup_age_seconds",
        "cobe_news_restore_test_last_ok",
        "cobe_news_restore_test_configured",
        "cobe_news_database_size_bytes",
    ):
        assert name in fams and fams[name]["type"] == "gauge", name
    backoff = fams["cobe_news_channel_backoff"]["samples"]
    assert len(backoff) == 1 and backoff[0][1] == "1" and set(backoff[0][0]) == {"channel_id", "type"}
    states = [lab for lab, v in fams["cobe_news_source_state"]["samples"] if v == "1"]
    assert states and all(set(lab) == {"kind", "source", "name", "state"} for lab in states)
    # no people, no titles: no user name, no channel name, no story
    for secret in ("anna", "Anna", "Mustermann", "Geheimer Titel", "max@corp.example"):
        assert secret not in r.text, secret


async def test_metrics_are_cached(admin_client, monkeypatch):
    token = await make_token(admin_client, scopes=["metrics"])
    calls = []
    real = metrics._sources

    async def counting(s, out):
        calls.append(1)
        await real(s, out)

    monkeypatch.setattr(metrics, "_sources", counting)
    for _ in range(3):
        assert (await get("/metrics", token)).status_code == 200
    assert len(calls) == 1
    metrics._cache.at = -1e9
    assert (await get("/metrics", token)).status_code == 200
    assert len(calls) == 2


async def test_metrics_need_their_token(admin_client):
    assert (await get("/metrics", None)).status_code == 401
    assert (await admin_client.get("/metrics")).status_code == 401  # a signed-in admin's cookie is no token


async def test_other_reader_session_unaffected(reader_client, admin_client):
    """The UI goes on as before: cookie and CSRF, no Authorization header needed or looked at."""
    await make_token(admin_client)
    assert (await reader_client.get("/api/news")).status_code == 200
    r = await reader_client.post("/api/news/read-all", json={})
    assert r.status_code in (200, 422)


async def test_basic_auth_header_is_no_token(admin_client):
    u = await add_user("berta", "reader")
    async with make_client() as c:
        await sign_in(c, u)
        r = await c.get("/api/news", headers={"Authorization": "Basic Zm9vOmJhcg=="})
        assert r.status_code == 200  # another scheme: not a token, the session counts as always
