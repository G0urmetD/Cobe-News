"""The update notice for admins (app/update_check.py): GitHub's "latest release" asked every 12 hours at most,
conditional (ETag), offline against a MockTransport; only a final, plain x.y.z release newer than this version counts;
closed per admin and release; switched off: no request, no notice; readers see nothing; /metrics carries it."""

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app import __version__, db, metrics, update_check
from app import settings as settings_store


def _bump(v: str, by: int = 1) -> str:
    a, b, c = (int(x) for x in v.split("."))
    return f"{a}.{b}.{c + by}"


NEWER = _bump(__version__, 2)
OLDER = "0.0.1"


def test_versions():
    assert update_check.parse_version("0.1.48") == (0, 1, 48) == update_check.parse_version("v0.1.48")
    for bad in ("0.1.48-rc1", "0.1", "latest", "", None, 48, "01.2.3", "1.2.3.4", " v1.2.3x"):
        assert update_check.parse_version(bad) is None, bad
    assert update_check.newer(NEWER) is True
    assert update_check.newer(__version__) is False  # equal
    assert update_check.newer(OLDER) is False
    assert update_check.newer("0.1.100", "0.1.99") is True  # numeric, not text order
    assert update_check.newer("garbage") is False and update_check.newer(None) is False
    assert update_check.newer(f"{NEWER}-rc1") is False  # a pre-release tag


def _release(tag: str, **kw) -> bytes:
    return json.dumps({"tag_name": tag, "html_url": "https://evil.example/x", "draft": False, "prerelease": False, "published_at": "2026-11-02T10:00:00Z", **kw}).encode()


def test_parse_release():
    assert update_check.parse_release(_release("v0.1.48")) == {"version": "0.1.48", "tag": "v0.1.48", "published_at": "2026-11-02T10:00:00Z"}
    assert update_check.parse_release(_release("v0.1.48", prerelease=True)) is None
    assert update_check.parse_release(_release("v0.1.48", draft=True)) is None
    assert update_check.parse_release(_release("nightly")) is None
    for bad in (b"no json", b"[]", b'{"name": "x"}'):
        with pytest.raises(update_check.NewsError):
            update_check.parse_release(bad)
    # the link is ours, made from the validated tag – never the answer's html_url
    assert update_check.release_url("v0.1.48") == "https://github.com/G0urmetD/Cobe-News/releases/tag/v0.1.48"
    assert update_check.release_url("../x") == "https://github.com/G0urmetD/Cobe-News/releases/tag/"


class GitHub:
    def __init__(self, body: bytes, status: int = 200, etag: str = '"e1"'):
        self.body, self.status, self.etag = body, status, etag
        self.calls: list[httpx.Request] = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        if self.etag and req.headers.get("if-none-match") == self.etag:
            return httpx.Response(304)
        return httpx.Response(self.status, content=self.body, headers={"ETag": self.etag} if self.etag else {})


@pytest.fixture
def github(monkeypatch):
    gh = GitHub(_release(f"v{NEWER}"))
    monkeypatch.setattr(update_check, "transport", httpx.MockTransport(gh.handler))
    return gh


async def _check(now: datetime | None = None) -> dict:
    async with db.session() as s:
        return await update_check.check(s, now=now)


async def test_newer_release_shown_to_admins_only(github, admin_client, reader_client):
    st = await _check()
    assert st["latest"] == NEWER and st["etag"] == '"e1"' and st["error"] is None
    req = github.calls[0]
    assert str(req.url) == update_check.RELEASE_API and req.headers["accept"] == "application/vnd.github+json" and "authorization" not in req.headers
    r = await admin_client.get("/api/admin/update")
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is True and body["latest"] == NEWER and body["current"] == __version__ and body["dismissed"] is False
    assert body["url"] == f"https://github.com/G0urmetD/Cobe-News/releases/tag/v{NEWER}"
    assert (await reader_client.get("/api/admin/update")).status_code == 403


async def test_twelve_hours_at_most_and_conditional(github):
    t0 = datetime.now(UTC)
    await _check(t0)
    await _check(t0 + timedelta(hours=11))
    assert len(github.calls) == 1
    st = await _check(t0 + timedelta(hours=12, minutes=1))
    assert len(github.calls) == 2 and github.calls[1].headers["if-none-match"] == '"e1"'
    assert st["latest"] == NEWER  # 304: as it was


@pytest.mark.parametrize(("tag", "extra", "available"), [(__version__, {}, False), (OLDER, {}, False), (NEWER, {"prerelease": True}, False), ("garbage", {}, False), (NEWER, {}, True)])
async def test_equal_older_prerelease_garbage(monkeypatch, admin_client, tag, extra, available):
    gh = GitHub(_release(f"v{tag}", **extra))
    monkeypatch.setattr(update_check, "transport", httpx.MockTransport(gh.handler))
    await _check()
    assert (await admin_client.get("/api/admin/update")).json()["available"] is available


async def test_errors_are_kept_and_not_retried_before_the_time(monkeypatch, admin_client):
    for status, body, err in ((403, b'{"message": "API rate limit exceeded"}', "rate_limited: HTTP 403"), (200, b"<html>", "format: no JSON"), (500, b"", "http: HTTP 500")):
        gh = GitHub(body, status, etag="")
        monkeypatch.setattr(update_check, "transport", httpx.MockTransport(gh.handler))
        async with db.session() as s:
            await settings_store.put(s, update_check.STATE, {})
            await s.commit()
        st = await _check()
        assert st["error"] == err and not st.get("latest")
        await _check()
        assert len(gh.calls) == 1
    assert (await admin_client.get("/api/admin/update")).json()["available"] is False


async def test_dismissed_per_admin_and_release(github, admin_client, monkeypatch):
    await _check()
    r = await admin_client.post("/api/admin/update/dismiss", json={"version": NEWER})
    assert r.status_code == 200 and r.json()["dismissed"] is True
    assert (await admin_client.get("/api/admin/update")).json()["dismissed"] is True
    assert (await admin_client.post("/api/admin/update/dismiss", json={"version": "nope"})).status_code == 422
    # a newer release: shown again
    newest = _bump(NEWER)
    gh = GitHub(_release(f"v{newest}"), etag='"e2"')
    monkeypatch.setattr(update_check, "transport", httpx.MockTransport(gh.handler))
    await _check(datetime.now(UTC) + timedelta(hours=13))
    body = (await admin_client.get("/api/admin/update")).json()
    assert body["latest"] == newest and body["available"] is True and body["dismissed"] is False


async def test_switched_off_no_request_no_notice(github, admin_client):
    await _check()
    r = await admin_client.get("/api/admin/update")
    rev = r.json()["rev"]
    r = await admin_client.put("/api/admin/update/settings", json={"check": False, "rev": rev})
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["available"] is False and r.json()["url"] is None
    await _check(datetime.now(UTC) + timedelta(days=2))
    assert len(github.calls) == 1  # no further request
    async with db.session() as s:
        assert await update_check.available_metric(s) is None
    # a stale form: refused
    assert (await admin_client.put("/api/admin/update/settings", json={"check": True, "rev": rev})).status_code == 409


async def test_metric(github):
    async with db.session() as s:
        assert await update_check.available_metric(s) is None  # not checked yet
    await _check()
    async with db.session() as s:
        assert await update_check.available_metric(s) is True
    metrics.reset()
    body = (await metrics.render()).decode()
    assert "\ncobe_news_update_available 1\n" in body


def test_default_is_on():
    assert settings_store.DEFAULTS["updates"] == {"check": True}
