"""Web Push (webpush.py, push_api.py) and the arrival cursor of /news/recent: the payload encrypted for the browser
(RFC 8291 – checked with the independent http_ece), VAPID (RFC 8292), only push service hosts, at most three stories and
a summary per round, gone subscriptions removed. No push service is ever contacted: notify.transport is a MockTransport."""

import json
from datetime import UTC, datetime, timedelta

import http_ece
import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select, text, update

from app import db, news, notify, webpush
from app.models import NewsItem, NewsSource, PushSubscription, User
from tests.conftest import add_user, make_client, set_news, sign_in

FCM = "https://fcm.googleapis.com/fcm/send/test-endpoint-1"


class Browser:
    """A subscribing browser: its key pair and auth secret, and what it decrypts from a push request."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.auth = b"0123456789abcdef"
        self.public = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def keys(self) -> dict:
        return {"p256dh": webpush.b64u(self.public), "auth": webpush.b64u(self.auth)}

    def read(self, body: bytes) -> dict:
        return json.loads(http_ece.decrypt(body, private_key=self.key, auth_secret=self.auth, version="aes128gcm"))


class PushService:
    def __init__(self, status: int = 201) -> None:
        self.requests: list[httpx.Request] = []
        self.status = status

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        return httpx.Response(self.status)


@pytest.fixture
def service(monkeypatch):
    s = PushService()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(s.handler))
    return s


async def _source() -> NewsSource:
    async with db.session() as s:
        src = NewsSource(key="p", name="Push Feed", url="https://p.example.org/f.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.commit()
        return src


async def _stories(src: NewsSource, n: int, severity: str = "critical", prefix: str = "S") -> None:
    """Stories as store() keeps them: each with the next arrival number."""
    async with db.session() as s:
        now = datetime.now(UTC)
        for k in range(n):
            seq = await news.next_seq(s)
            s.add(NewsItem(source_id=src.id, url=f"https://p.example.org/{prefix}{k}", url_key=f"{prefix}{k}", title=f"{prefix} {k}", title_key=f"{prefix}{k}", published_at=now, fetched_at=now, severity=severity, seq=seq))
        await s.commit()


async def _desktop(user: User, **prefs) -> None:
    async with db.session() as s:
        u = await s.get(User, user.id)
        u.desktop = {"enabled": True, "severities": ["critical", "high"], "sources": [], **prefs}
        await s.commit()


async def _dispatch() -> dict:
    async with db.session() as s:
        return await webpush.dispatch(s)


# ---------------------------------------------------------------- crypto


def test_payload_is_encrypted_for_the_browser_only():
    b = Browser()
    body = webpush.encrypt(b'{"title":"x"}', b.public, b.auth)
    assert b'"title"' not in body  # the push service sees ciphertext
    assert json.loads(http_ece.decrypt(body, private_key=b.key, auth_secret=b.auth, version="aes128gcm")) == {"title": "x"}
    assert body[16:20] == (4096).to_bytes(4, "big") and body[20] == 65  # salt | rs | idlen | keyid (RFC 8188)
    with pytest.raises(webpush.PushError):
        webpush.encrypt(b"x" * 5000, b.public, b.auth)


async def test_vapid_key_is_kept_encrypted_and_signs_for_the_push_service():
    async with db.session() as s:
        key = await webpush.vapid(s)
        stored = (await s.execute(text("SELECT value FROM settings WHERE key = 'push'"))).scalar_one()
    assert "PRIVATE KEY" not in json.dumps(stored) and json.loads(stored if isinstance(stored, str) else json.dumps(stored))["private_enc"].startswith("v1:")
    webpush.reset_cache()
    async with db.session() as s:
        assert (await webpush.vapid(s)).public == key.public  # the same key after a restart
    h = webpush.vapid_headers(FCM, key)["Authorization"]
    token, k = h.removeprefix("vapid t=").split(", k=")
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), webpush.unb64u(k))
    claims = jwt.decode(token, pub, algorithms=["ES256"], audience="https://fcm.googleapis.com")
    assert claims["sub"].startswith(("https://", "mailto:")) and claims["exp"] > datetime.now(UTC).timestamp()


@pytest.mark.parametrize(
    "url",
    [
        "http://fcm.googleapis.com/fcm/send/x",  # not https
        "https://fcm.googleapis.com.evil.example/x",  # look-alike
        "https://evil.example/fcm.googleapis.com",
        "https://fcm.googleapis.com:8443/x",  # other port
        "https://user@fcm.googleapis.com/x",
        "https://169.254.169.254/latest/meta-data",
        "https://localhost/x",
        "https://push.apple.com.example.org/x",
    ],
)
def test_only_push_service_hosts(url):
    with pytest.raises(webpush.PushError):
        webpush.check_endpoint(url)


@pytest.mark.parametrize("url", [FCM, "https://updates.push.services.mozilla.com/wpush/v2/x", "https://web.push.apple.com/x", "https://wns2-par02p.notify.windows.com/w/?token=x"])
def test_push_service_hosts_taken(url):
    assert webpush.check_endpoint(url) == url


# ---------------------------------------------------------------- API


async def test_subscribe_state_test_and_remove(reader_client, service):
    b = Browser()
    info = (await reader_client.get("/api/me/push")).json()
    assert info["enabled"] and len(webpush.unb64u(info["public_key"])) == 65 and info["devices"] == 0
    r = await reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": b.keys(), "lang": "en"})
    assert r.status_code == 200 and r.json()["registered"]
    assert (await reader_client.post("/api/me/push/state", json={"endpoint": FCM})).json()["registered"]
    # a test message through the push service, as the real ones
    assert (await reader_client.post("/api/me/push/test", json={"endpoint": FCM})).json() == {"ok": True}
    req = service.requests[-1]
    assert str(req.url) == FCM and req.headers["content-encoding"] == "aes128gcm" and req.headers["ttl"] and req.headers["authorization"].startswith("vapid t=")
    assert b.read(req.content)["title"] == "Test notification from Cobe News"
    assert (await reader_client.post("/api/me/push/test", json={"endpoint": FCM})).status_code == 429  # not in a loop
    # another person cannot see, test or remove my browser
    other = await add_user("olga")
    async with make_client() as c:
        await sign_in(c, other)
        assert not (await c.post("/api/me/push/state", json={"endpoint": FCM})).json()["registered"]
        assert (await c.post("/api/me/push/test", json={"endpoint": FCM})).status_code == 404
        await c.post("/api/me/push/remove", json={"endpoint": FCM})
    assert (await reader_client.post("/api/me/push/state", json={"endpoint": FCM})).json()["registered"]
    await reader_client.post("/api/me/push/remove", json={"endpoint": FCM})
    assert not (await reader_client.post("/api/me/push/state", json={"endpoint": FCM})).json()["registered"]


async def test_subscribe_refuses_other_hosts_and_bad_keys(reader_client, service):
    b = Browser()
    assert (await reader_client.post("/api/me/push", json={"endpoint": "https://hooks.example.org/x", "keys": b.keys()})).json()["detail"]["code"] == "endpoint_not_allowed"
    bad = {"p256dh": webpush.b64u(b"\x04" + b"\x01" * 64), "auth": webpush.b64u(b.auth)}
    assert (await reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": bad})).json()["detail"]["code"] == "invalid_keys"
    assert service.requests == []


async def test_push_off_by_configuration(reader_client, service, monkeypatch):
    import dataclasses

    from app import config, push_api

    off = dataclasses.replace(config.get_config(), web_push=False)
    for mod in (push_api, webpush):
        monkeypatch.setattr(mod, "get_config", lambda: off)
    assert (await reader_client.get("/api/me/push")).json() == {"enabled": False, "public_key": None, "devices": 0}
    assert (await reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": Browser().keys()})).status_code == 409
    assert await _dispatch() == {} and service.requests == []


# ---------------------------------------------------------------- dispatch after a round


async def test_dispatch_three_stories_and_a_summary_then_nothing_twice(reader_client, service):
    b = Browser()
    await _desktop(reader_client.user)
    src = await _source()
    await _stories(src, 1, prefix="old")  # before the subscription: backlog, never sent
    await reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": b.keys(), "lang": "de"})
    await _stories(src, 5)
    await _stories(src, 2, severity="low", prefix="L")  # not chosen for desktop notifications
    assert await _dispatch() == {"sent": 1, "failed": 0}
    got = [b.read(r.content) for r in service.requests]
    assert [g["title"] for g in got] == ["S 2", "S 3", "S 4", "2 neue Security-Meldungen"]
    assert got[0]["body"] == "Kritisch · Push Feed" and got[0]["url"].startswith("/?story=") and service.requests[0].headers["urgency"] == "high"
    assert await _dispatch() == {}  # the cursor moved: nothing twice
    await _stories(src, 1, prefix="N")
    await _dispatch()
    assert b.read(service.requests[-1].content)["title"] == "N 0"


async def test_dispatch_switched_off_or_inactive_sends_nothing(reader_client, service):
    b = Browser()
    src = await _source()
    await reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": b.keys()})
    await _stories(src, 2)  # desktop notifications are off for this person
    assert await _dispatch() == {} and service.requests == []
    await _desktop(reader_client.user)
    assert await _dispatch() == {}  # what arrived while switched off does not come later either
    async with db.session() as s:
        await s.execute(update(User).where(User.id == reader_client.user.id).values(is_active=False))
        await s.commit()
    await _stories(src, 1, prefix="X")
    assert await _dispatch() == {} and service.requests == []


async def test_gone_subscription_is_removed_and_errors_back_off(reader_client, service):
    b = Browser()
    await _desktop(reader_client.user)
    src = await _source()
    await reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": b.keys()})
    await _stories(src, 1)
    service.status = 500
    assert await _dispatch() == {"sent": 0, "failed": 1}
    async with db.session() as s:
        sub = await s.scalar(select(PushSubscription))
        assert sub.failures == 1 and sub.last_error == "http: HTTP 500" and sub.next_try_at > datetime.now(UTC) and sub.cursor == 0
        sub.next_try_at = datetime.now(UTC) - timedelta(seconds=1)
        await s.commit()
    service.status = 201
    assert await _dispatch() == {"sent": 1, "failed": 0}  # the story was kept for the next try
    await _stories(src, 1, prefix="G")
    service.status = 410
    await _dispatch()
    async with db.session() as s:
        assert await s.scalar(select(PushSubscription)) is None


async def test_same_browser_signed_in_by_another_person_is_theirs_now(reader_client, service):
    b = Browser()
    await reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": b.keys()})
    other = await add_user("olga")
    async with make_client() as c:
        await sign_in(c, other)
        await c.post("/api/me/push", json={"endpoint": FCM, "keys": b.keys()})
    async with db.session() as s:
        assert (await s.scalar(select(PushSubscription))).user_id == other.id


# ---------------------------------------------------------------- the arrival cursor


async def test_recent_cursor_returns_each_story_once(reader_client):
    await set_news(enabled=True)
    src = await _source()
    first = (await reader_client.get("/api/news/recent")).json()
    assert first["items"] == [] and isinstance(first["cursor"], int)
    await _stories(src, 12, severity="high")
    got = (await reader_client.get("/api/news/recent", params={"after": first["cursor"]})).json()
    assert len(got["items"]) == 10 and got["total"] == 12 and got["cursor"] == first["cursor"] + 12
    assert (await reader_client.get("/api/news/recent", params={"after": got["cursor"]})).json()["items"] == []
    # a cursor from a database that was bigger (a backup restored): from the current end on, not nothing forever
    await _stories(src, 1, prefix="R")
    assert len((await reader_client.get("/api/news/recent", params={"after": 10**9})).json()["items"]) == 0
    assert (await reader_client.get("/api/news/recent", params={"after": got["cursor"]})).json()["total"] == 1


async def test_story_committed_after_a_poll_comes_with_the_next_one(reader_client):
    """The bug of the time cursor: a transaction stamps fetched_at, a poll answers meanwhile, then it commits."""
    await set_news(enabled=True)
    src = await _source()
    cur = (await reader_client.get("/api/news/recent")).json()["cursor"]
    async with db.session() as s:  # store() in progress: number taken, not committed yet
        seq = await news.next_seq(s)
        now = datetime.now(UTC)
        s.add(NewsItem(source_id=src.id, url="https://p.example.org/late", url_key="late", title="Late", title_key="late", published_at=now, fetched_at=now, severity="high", seq=seq))
        await s.flush()
        mid = (await reader_client.get("/api/news/recent", params={"after": cur})).json()
        await s.commit()
    assert mid["items"] == [] and mid["cursor"] == cur
    assert [i["title"] for i in (await reader_client.get("/api/news/recent", params={"after": mid["cursor"]})).json()["items"]] == ["Late"]



FCM2 = "https://fcm.googleapis.com/fcm/send/test-endpoint-2"


@pytest.mark.parametrize("fails", [False, True])
async def test_a_browser_removed_mid_round_keeps_the_others_cursors(reader_client, service, monkeypatch, fails):
    """Bug hunt 0.1.16 M11: a subscription deleted while the round sends (unsubscribe, takeover, person deleted) failed
    the round's commit and rolled back every other browser's cursor – they got the same push again next round."""
    from sqlalchemy import delete

    await _desktop(reader_client.user)
    other = await add_user("olga")
    await _desktop(other)
    await reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": Browser().keys()})
    async with make_client() as c:
        await sign_in(c, other)
        await c.post("/api/me/push", json={"endpoint": FCM2, "keys": Browser().keys()})
    await _stories(await _source(), 1)
    real = webpush.send_all

    async def send_all(sub, payloads, key):  # noqa: ANN001
        out = notify.NotifyError("http", "HTTP 500") if fails and sub.endpoint == FCM2 else await real(sub, payloads, key)
        if sub.endpoint == FCM2:  # olga unsubscribes while the round is sending
            async with db.session() as s:
                await s.execute(delete(PushSubscription).where(PushSubscription.endpoint == FCM2))
                await s.commit()
        return out

    monkeypatch.setattr(webpush, "send_all", send_all)
    await _dispatch()
    sent = len(service.requests)
    monkeypatch.setattr(webpush, "send_all", real)
    await _dispatch()
    assert len(service.requests) == sent  # nothing sent twice
    async with db.session() as s:
        assert await s.scalar(select(PushSubscription.cursor).where(PushSubscription.endpoint == FCM)) == await news.last_seq(s)
        assert await s.scalar(select(PushSubscription.id).where(PushSubscription.endpoint == FCM2)) is None


async def test_parallel_subscribes_of_one_endpoint(reader_client, service, monkeypatch):
    """Bug hunt 0.1.16 L6: two tabs of one browser subscribing at the same moment – one row, no HTTP 500."""
    import asyncio

    real = news.last_seq

    async def slow(s):  # noqa: ANN001 - the window between looking and inserting, as on a busy server
        v = await real(s)
        await asyncio.sleep(0.05)
        return v

    monkeypatch.setattr(news, "last_seq", slow)
    b = Browser()
    rs = await asyncio.gather(*(reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": b.keys()}) for _ in range(4)))
    assert [r.status_code for r in rs] == [200] * 4
    async with db.session() as s:
        assert len(list(await s.scalars(select(PushSubscription).where(PushSubscription.endpoint == FCM)))) == 1
