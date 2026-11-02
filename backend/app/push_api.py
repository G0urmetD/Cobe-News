"""Web Push of the signed-in person's browsers (see webpush.py): the server's public key, subscribe, unsubscribe, the
state of one browser and a test message to it. The endpoint is sent in the body, never in a URL (it is a capability)."""

import time

from fastapi import APIRouter, Request
from pydantic import ConfigDict, Field
from sqlalchemy import delete, func, select

from app import webpush
from app.config import get_config
from app.deps import Db, NoNul, Reader, api_error
from app.models import PushSubscription

router = APIRouter(prefix="/api/me/push", tags=["push"])
TEST_EVERY = 10.0
_last_test: dict[str, float] = {}


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Keys(_M):
    p256dh: str = Field(min_length=80, max_length=200)
    auth: str = Field(min_length=16, max_length=64)


class SubscribeIn(_M):
    endpoint: str = Field(min_length=10, max_length=1000)
    keys: Keys
    lang: str = Field(default="de", max_length=5)


class EndpointIn(_M):
    endpoint: str = Field(min_length=10, max_length=1000)


def _label(ua: str) -> str:
    """Browser and system in a few words – "Chrome · macOS" – so a person can tell their browsers apart."""
    ua = ua or ""
    browser = next((n for k, n in (("Edg/", "Edge"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"), ("Safari/", "Safari")) if k in ua), "Browser")
    system = next((n for k, n in (("Windows", "Windows"), ("Mac OS X", "macOS"), ("Android", "Android"), ("iPhone", "iOS"), ("iPad", "iPadOS"), ("Linux", "Linux")) if k in ua), "")
    return f"{browser} · {system}" if system else browser


def _state(sub: PushSubscription | None) -> dict:
    if sub is None:
        return {"registered": False}
    return {
        "registered": True,
        "ok": not sub.failures,
        "last_ok_at": sub.last_ok_at.isoformat() if sub.last_ok_at else None,
        "last_error": sub.last_error,
        "last_error_at": sub.last_error_at.isoformat() if sub.last_error_at else None,
    }


async def _mine(db: Db, user, endpoint: str) -> PushSubscription | None:  # noqa: ANN001
    return await db.scalar(select(PushSubscription).where(PushSubscription.endpoint == endpoint.strip(), PushSubscription.user_id == user.id))


@router.get("")
async def info(user: Reader, db: Db) -> dict:
    """Whether the server sends Web Push at all (WEB_PUSH), its public key and how many browsers of mine are subscribed."""
    if not get_config().web_push:
        return {"enabled": False, "public_key": None, "devices": 0}
    key = await webpush.vapid(db)
    n = await db.scalar(select(func.count()).select_from(PushSubscription).where(PushSubscription.user_id == user.id))
    return {"enabled": True, "public_key": key.public, "devices": int(n or 0)}


@router.post("")
async def subscribe(body: SubscribeIn, user: Reader, db: Db, request: Request) -> dict:
    if not get_config().web_push:
        raise api_error(409, "push_disabled")
    try:
        sub = await webpush.subscribe(db, user, body.endpoint, body.keys.p256dh, body.keys.auth, body.lang[:2], _label(request.headers.get("user-agent", "")))
    except webpush.PushError as exc:
        raise api_error(422, str(exc)) from exc
    return _state(sub)


@router.post("/state")
async def state(body: EndpointIn, user: Reader, db: Db) -> dict:
    """This browser's subscription as the server knows it: registered, last delivery, last error."""
    return _state(await _mine(db, user, body.endpoint))


@router.post("/remove")
async def remove(body: EndpointIn, user: Reader, db: Db) -> dict:
    await db.execute(delete(PushSubscription).where(PushSubscription.endpoint == body.endpoint.strip(), PushSubscription.user_id == user.id))
    await db.commit()
    return {"ok": True}


@router.post("/test")
async def test(body: EndpointIn, user: Reader, db: Db) -> dict:
    """A test message to this browser through its push service – the way the real ones take."""
    if not get_config().web_push:
        raise api_error(409, "push_disabled")
    key = await webpush.vapid(db)  # before the subscription is loaded: an unreadable key removes the subscriptions
    sub = await _mine(db, user, body.endpoint)
    if sub is None:
        raise api_error(404, "not_found")
    now = time.monotonic()
    if now - _last_test.get(str(user.id), -1e9) < TEST_EVERY:
        raise api_error(429, "rate_limited")
    _last_test[str(user.id)] = now
    if len(_last_test) > 1000:
        _last_test.clear()
    outcome = await webpush.send_all(sub, [webpush.test_payload(sub.lang)], key)
    ok = await webpush.settle(db, sub, outcome)
    await db.commit()
    if not ok:
        detail = outcome.category if outcome is not None and hasattr(outcome, "category") else "gone"
        raise api_error(502, "push_failed", detail=detail)
    return {"ok": True}
