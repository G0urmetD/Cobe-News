"""Admin only: the delivery log (app/delivery_log.py) – the deliveries of all channels or of one, filtered, each with its
attempts – and "Erneut senden" for a failed rule delivery (notify.resend)."""

import time
import uuid
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter
from sqlalchemy import and_, func, or_, select, tuple_

from app import delivery_log, notify
from app.deps import Admin, Db, api_error
from app.models import DeliveryLog, NotifyChannel, PersonDelivery, User

router = APIRouter(prefix="/api/admin/notify/log", tags=["notify"])
PAGE_MAX = 100
RESEND_EVERY = 5.0  # seconds between two resends to the same channel
RESEND_PER_10MIN = 20  # resends of one admin within ten minutes
_resend_at: dict[uuid.UUID, float] = {}  # channel → the last resend
_resends: dict[uuid.UUID, deque[float]] = {}  # admin → their resends within the last ten minutes
_running: set[tuple[uuid.UUID, str]] = set()  # (channel, delivery) being resent right now – a double click waits for nothing
clock = time.monotonic


def reset() -> None:
    _resend_at.clear()
    _resends.clear()
    _running.clear()


Outcome = Literal["ok", "failed", "http", "timeout", "blocked", "smtp", "error"]
Kind = Literal["rule", "forward", "weekly", "test"]


def _resendable(r: DeliveryLog, channel_ok: bool) -> bool:
    return r.kind == "rule" and not r.ok and channel_ok and bool(r.refs)


@router.get("")
async def listing(
    admin: Admin,
    db: Db,
    channel: uuid.UUID | None = None,
    outcome: Outcome | None = None,
    kind: Kind | None = None,
    hours: int = 168,
    before: datetime | None = None,
    limit: int = 50,
) -> dict:
    """The deliveries of the last `hours` (at most the retention), newest first: each as its latest attempt with all
    its attempts. `outcome` filters by the latest attempt ("failed": any failure). `before`: the page after the
    previous one (its last delivery's time)."""
    now = datetime.now(UTC)
    since = now - timedelta(hours=max(1, min(hours, delivery_log.RETENTION_DAYS * 24)))
    limit = max(1, min(limit, PAGE_MAX))
    rn = func.row_number().over(partition_by=(DeliveryLog.channel_id, DeliveryLog.kind, DeliveryLog.ref), order_by=(DeliveryLog.attempt.desc(), DeliveryLog.at.desc())).label("rn")
    where = [DeliveryLog.at >= since]
    if channel is not None:
        where.append(DeliveryLog.channel_id == channel)
    if kind is not None:
        where.append(DeliveryLog.kind == kind)
    inner = select(DeliveryLog.id, rn).where(*where).subquery()
    stmt = select(DeliveryLog).join(inner, and_(inner.c.id == DeliveryLog.id, inner.c.rn == 1))
    if outcome == "failed":
        stmt = stmt.where(DeliveryLog.ok.is_(False))
    elif outcome is not None:
        stmt = stmt.where(DeliveryLog.outcome == outcome)
    if before is not None:
        stmt = stmt.where(DeliveryLog.at < before)
    latest = list(await db.scalars(stmt.order_by(DeliveryLog.at.desc(), DeliveryLog.id.desc()).limit(limit + 1)))
    more = len(latest) > limit
    latest = latest[:limit]
    attempts: dict[tuple, list[DeliveryLog]] = {}
    if latest:
        keys = {(r.ref, r.kind) for r in latest}
        rows = await db.scalars(select(DeliveryLog).where(tuple_(DeliveryLog.ref, DeliveryLog.kind).in_(list(keys)), DeliveryLog.at >= since - timedelta(days=delivery_log.RETENTION_DAYS)).order_by(DeliveryLog.attempt, DeliveryLog.at))
        for r in rows:
            attempts.setdefault((r.channel_id, r.kind, r.ref), []).append(r)
    users = {r.user_id for r in latest if r.user_id}
    people = {u.id: (u.display_name or u.username) for u in await db.scalars(select(User).where(User.id.in_(users)))} if users else {}
    alive = set(await db.scalars(select(NotifyChannel.id).where(NotifyChannel.id.in_({r.channel_id for r in latest if r.channel_id})))) if latest else set()
    out = []
    for r in latest:
        row = delivery_log.row_out(r, people=people)
        row["attempts"] = [delivery_log.row_out(a, people=people) for a in attempts.get((r.channel_id, r.kind, r.ref), [r])]
        row["can_resend"] = _resendable(r, r.channel_id in alive)
        out.append(row)
    return {"deliveries": out, "more": more, "since": since.isoformat(), "retention_days": delivery_log.RETENTION_DAYS, "personal": await _personal(db, now) if channel is None else None}


async def _personal(db: Db, now: datetime) -> dict:
    """The personal deliveries (a person's own ways) as counts only – they are not in the log."""
    day = now - timedelta(hours=24)
    rows = (
        await db.execute(
            select(PersonDelivery.status, func.count())
            .where(or_(PersonDelivery.status.in_(("pending", "sending")), and_(PersonDelivery.status == "sent", PersonDelivery.sent_at >= day), and_(PersonDelivery.status == "failed", PersonDelivery.created_at >= day)))
            .group_by(PersonDelivery.status)
        )
    ).all()
    got = {st: int(n) for st, n in rows}
    return {"sent_24h": got.get("sent", 0), "failed_24h": got.get("failed", 0), "waiting": got.get("pending", 0) + got.get("sending", 0)}


def _rate(admin_id: uuid.UUID, channel_id: uuid.UUID, now: float) -> None:
    if now - _resend_at.get(channel_id, -1e9) < RESEND_EVERY:
        raise api_error(429, "rate_limited", retry_after=int(RESEND_EVERY) or 1)
    q = _resends.setdefault(admin_id, deque())
    while q and now - q[0] >= 600:
        q.popleft()
    if len(q) >= RESEND_PER_10MIN:
        raise api_error(429, "rate_limited", retry_after=max(1, int(600 - (now - q[0]))))
    _resend_at[channel_id] = now
    q.append(now)


@router.post("/{entry_id}/resend")
async def resend(entry_id: uuid.UUID, admin: Admin, db: Db) -> dict:
    """Send a failed rule delivery again, now, to the same channel (notify.resend). Refused when its latest attempt
    worked (409 already_delivered – also a second click after a resend that went out), while it is being resent
    (409 resend_running), when nothing of it is left (410 gone) or too often (429)."""
    row = await db.get(DeliveryLog, entry_id)
    if row is None:
        raise api_error(404, "not_found")
    if row.kind != "rule" or row.channel_id is None or not row.refs:
        raise api_error(409, "not_resendable")
    ch = await db.get(NotifyChannel, row.channel_id)
    if ch is None:
        raise api_error(409, "not_resendable")
    key = (ch.id, row.ref)
    if key in _running:
        raise api_error(409, "resend_running")
    latest = await db.scalar(select(DeliveryLog).where(DeliveryLog.channel_id == ch.id, DeliveryLog.ref == row.ref, DeliveryLog.kind == "rule").order_by(DeliveryLog.attempt.desc(), DeliveryLog.at.desc()).limit(1))
    if latest is not None and latest.ok:
        raise api_error(409, "already_delivered")
    _rate(admin.id, ch.id, clock())
    _running.add(key)
    try:
        err = await notify.resend(db, ch, latest or row, actor=admin)
    except notify.Gone as exc:
        raise api_error(409 if exc.reason == "already_delivered" else 410, exc.reason) from exc
    finally:
        _running.discard(key)
    if err is not None:
        return {"ok": False, "error": err.category, "detail": delivery_log.sanitize(err.detail) or ""}
    return {"ok": True}
