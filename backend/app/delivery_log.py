"""Zustellprotokoll – the delivery log: every attempt to deliver a message (docs/BETRIEB.md / handbook: Benachrichtigungen).

- **What is recorded.** A rule's message to a channel (kind "rule" – also every automatic retry of it and a manual
  resend), a team forward ("forward"), a weekly review mail ("weekly") and a test message ("test"): the channel (its id,
  and its name and type as they were), what was sent by reference and title only (the listed stories / events, at most
  ITEMS_MAX, and how many in all), the rules that brought it, when, which attempt, and the outcome – ok, the HTTP
  status, a timeout, blocked by the egress guard, the SMTP reply code – with a short, cleaned error text.
- **Never recorded:** a message body, a webhook URL (also not its path), a token, an HMAC secret, an auth header value,
  SMTP credentials or a response body. The error text is the category's own detail (never a URL – notify.NotifyError),
  cleaned once more here (sanitize): URLs cut to their host, token-like strings, e-mail addresses and the target's own
  secrets replaced, control characters out, DETAIL_MAX characters.
- **Team forwards** without the sender and without the comment (app/forward.py: no log of who forwarded what) – the
  team and the story / finding only. **Weekly reviews**: the team and the recipient (a person – only admins see the
  log, and only the way and the person, never the mail). **Personal deliveries** (app/personal.py) are not in the log:
  they are a person's own, with their own state per way (person_deliveries) – only counted (counters(), /metrics).
- **Attempts of one delivery** share `ref` (a hash of what the message carries – the same message sent again by the
  channel's backoff has the same ref, and the same webhook delivery id). A message planned anew (more stories arrived
  meanwhile) is a new delivery.
- **Writing never holds back sending:** each entry in a short transaction of its own (or with the round's own writes);
  a failure is logged and dropped.
- **Kept** RETENTION_DAYS (pruned by the hourly prune step), at most MAX_ROWS (the oldest go first).
"""

import hashlib
import logging
import re
import time
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

from sqlalchemy import Integer, and_, case, delete, func, insert, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import DeliveryLog, NotifyChannel
from app.news import TOPICS

log = logging.getLogger("cobe_news.delivery_log")

RETENTION_DAYS = 30
MAX_ROWS = 200_000
ITEMS_MAX = 10  # the stories / events listed in an entry (a summary carries more: counted in `total`)
REFS_MAX = 1000  # what a resend can send again (a rule's round brings at most notify.PENDING_MAX per rule)
TITLE_MAX = 200
DETAIL_MAX = 200
KINDS = ("rule", "forward", "weekly", "test")
OUTCOMES = ("ok", "http", "timeout", "blocked", "smtp", "error")
BLOCKED = ("forbidden_target", "host_not_allowed", "invalid_url")  # the egress guard / the URL checks said no
HTTP = ("http", "auth", "rejected", "rate_limited")

# ---------------------------------------------------------------- cleaning

_URL = re.compile(r"(?i)\b(?:https?|wss?|smtps?|ftp)://([^/\s\"'<>?#]+)[^\s\"']*")
_TG_TOKEN = re.compile(r"\b\d{5,12}:[A-Za-z0-9_-]{20,}\b")
_BEARER = re.compile(r"(?i)\b(bearer|basic|token|key|secret|password|passwd|pwd|sig|signature|auth)([=: ]+)\S+")
_LONG = re.compile(r"[A-Za-z0-9_\-+/=.]{24,}")  # a token, a key, a signature, a base64 blob
_MAIL = re.compile(r"[^\s@<>\"']+@[^\s@<>\"']+\.[A-Za-z]{2,}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f\x85  ‪-‮⁦-⁩]+")


def sanitize(text: str | None, secrets: tuple[str, ...] | list[str] = ()) -> str | None:
    """A short error text fit to be stored and shown: the target's own secrets (URL, token …) and anything that looks
    like one replaced, URLs cut to their host, e-mail addresses out, one line, at most DETAIL_MAX characters."""
    if not text:
        return None
    s = str(text)
    for secret in sorted((x for x in secrets if x and len(x) >= 4), key=len, reverse=True):
        s = s.replace(secret, "<redacted>")
    s = _URL.sub(lambda m: f"<{m.group(1).split('@')[-1]}>", s)
    s = _TG_TOKEN.sub("<token>", s)
    s = _BEARER.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", s)
    s = _MAIL.sub("<address>", s)
    s = _LONG.sub("<redacted>", s)
    s = " ".join(_CONTROL.sub(" ", s).split())
    return s[:DETAIL_MAX] or None


def title(text: str | None) -> str:
    return " ".join(_CONTROL.sub(" ", str(text or "")).split())[:TITLE_MAX]


def outcome(channel_type: str, exc: Exception | None) -> tuple[bool, str, str | None, int | None]:
    """(ok, outcome, error category, code) of an attempt."""
    if exc is None:
        return True, "ok", None, None
    category = str(getattr(exc, "category", None) or "connection")
    code = getattr(exc, "code", None)
    code = int(code) if isinstance(code, int) else None
    if category in BLOCKED:
        kind = "blocked"
    elif category == "timeout":
        kind = "timeout"
    elif channel_type == "email":
        kind = "smtp"
    elif category in HTTP or code is not None:
        kind = "http"
    else:
        kind = "error"
    return False, kind, category, code


def ref_of(key: str) -> str:
    """The delivery's reference: a hash of what the message carries (the key can be long – a summary's stories)."""
    return hashlib.sha256(key.encode()).hexdigest()[:32] if key else uuid.uuid4().hex


# ---------------------------------------------------------------- counters (/metrics)

_counts: Counter[tuple[str, str, str]] = Counter()


def count(kind: str, channel_type: str, result: str) -> None:
    _counts[(kind, channel_type, result)] += 1


def counters() -> dict[tuple[str, str, str], int]:
    """(kind, channel type or personal way, outcome) → attempts since the process started."""
    return dict(_counts)


def reset() -> None:
    _counts.clear()


# ---------------------------------------------------------------- writing


def entry(
    *,
    kind: str,
    channel: NotifyChannel | None = None,
    channel_id: uuid.UUID | None = None,
    channel_name: str = "",
    channel_type: str = "",
    ref: str,
    items: list[dict] | None = None,
    total: int | None = None,
    rules: list[dict] | None = None,
    refs: list[str] | None = None,
    lang: str = "de",
    team_id: uuid.UUID | None = None,
    team_name: str | None = None,
    user_id: uuid.UUID | None = None,
    error: Exception | None = None,
    secrets: tuple[str, ...] | list[str] = (),
    started: float | None = None,
    manual: bool = False,
    at: datetime | None = None,
):  # noqa: ANN201 - an INSERT statement
    """The INSERT of one attempt – its number one more than the delivery's attempts before (INSERT … SELECT: no read
    first). Counted for /metrics as well. A channel deleted meanwhile: the entry without it (it would fail its key)."""
    if channel is not None:
        channel_id, channel_name, channel_type = channel.id, channel.name, channel.type
    ok, result, category, code = outcome(channel_type, error)
    count(kind, channel_type or "email", result)
    detail = None
    if error is not None:
        raw = getattr(error, "detail", "") or ""
        detail = sanitize(raw, secrets) if raw and raw != category else None
    listed = [
        {
            "kind": str(x.get("kind") or ""),
            "id": str(x.get("id") or ""),
            "title": title(x.get("title")),
            "severity": str(x.get("severity") or ""),
            # a news story's topics when it went out (what a rule asking for topics matched by)
            **({"topics": [t for t in TOPICS if t in x["topics"]]} if isinstance(x.get("topics"), list) and x["topics"] else {}),
        }
        for x in (items or [])[:ITEMS_MAX]
    ]
    prev = select(func.coalesce(func.max(DeliveryLog.attempt), 0)).where(DeliveryLog.ref == ref)
    prev = prev.where(DeliveryLog.channel_id == channel_id) if channel_id else prev.where(DeliveryLog.channel_id.is_(None), DeliveryLog.kind == kind)
    alive = select(NotifyChannel.id).where(NotifyChannel.id == channel_id).scalar_subquery() if channel_id else None
    values = {
        "id": uuid.uuid4(),
        "at": at or datetime.now(UTC),
        "channel_id": alive,
        "channel_name": title(channel_name)[:100],
        "channel_type": channel_type or "",
        "kind": kind,
        "ref": ref,
        "attempt": (prev.scalar_subquery() + literal(1, Integer)),
        "manual": manual,
        "items": listed,
        "total": int(total if total is not None else len(items or [])),
        "rules": [{"id": str(r.get("id") or ""), "name": title(r.get("name"))[:100]} for r in (rules or [])][:20],
        "refs": list(refs or [])[:REFS_MAX],
        "lang": lang,
        "team_id": team_id,
        "team_name": title(team_name)[:100] if team_name else None,
        "user_id": user_id,
        "ok": ok,
        "outcome": result,
        "error": category,
        "code": code,
        "detail": detail,
        "duration_ms": int((time.monotonic() - started) * 1000) if started is not None else None,
    }
    return insert(DeliveryLog).values(**values)


async def record(db: AsyncSession, **kw) -> None:  # noqa: ANN003
    """One attempt in a short transaction of its own – a failure is logged, never raised (sending went on anyway)."""
    try:
        await db.execute(entry(**kw))
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        log.warning("delivery log: entry not written (%s)", type(exc).__name__)


# ---------------------------------------------------------------- reading


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def row_out(r: DeliveryLog, *, people: dict[uuid.UUID, str] | None = None) -> dict:
    return {
        "id": str(r.id),
        "at": r.at.isoformat(),
        "channel_id": str(r.channel_id) if r.channel_id else None,
        "channel_name": r.channel_name,
        "channel_type": r.channel_type,
        "kind": r.kind,
        "ref": r.ref,
        "attempt": r.attempt,
        "manual": r.manual,
        "items": list(r.items or []),
        "total": r.total,
        "rules": list(r.rules or []),
        "team_name": r.team_name,
        "person": (people or {}).get(r.user_id) if r.user_id else None,
        "ok": r.ok,
        "outcome": r.outcome,
        "error": r.error,
        "code": r.code,
        "detail": r.detail,
        "duration_ms": r.duration_ms,
    }


async def health(db: AsyncSession, channel_ids: list[uuid.UUID] | None = None, now: datetime | None = None) -> dict[uuid.UUID, dict]:
    """Per channel: the last successful and the last failed delivery, and the attempts and failures of the last 24 hours
    – the badge in the channel list. One grouped query by index."""
    now = now or datetime.now(UTC)
    day = now - timedelta(hours=24)
    stmt = (
        select(
            DeliveryLog.channel_id,
            func.max(case((DeliveryLog.ok.is_(True), DeliveryLog.at))),
            func.max(case((DeliveryLog.ok.is_(False), DeliveryLog.at))),
            func.count().filter(DeliveryLog.at >= day),
            func.count().filter(and_(DeliveryLog.at >= day, DeliveryLog.ok.is_(False))),
        )
        .where(DeliveryLog.channel_id.is_not(None), DeliveryLog.kind != "test")
        .group_by(DeliveryLog.channel_id)
    )
    if channel_ids is not None:
        stmt = stmt.where(DeliveryLog.channel_id.in_(channel_ids))
    return {
        cid: {"last_ok_at": _iso(ok_at), "last_failed_at": _iso(bad_at), "attempts_24h": int(n or 0), "failed_24h": int(bad or 0)}
        for cid, ok_at, bad_at, n, bad in (await db.execute(stmt)).all()
    }


async def prune(db: AsyncSession, days: int = RETENTION_DAYS) -> int:
    """Entries older than `days` – and beyond MAX_ROWS the oldest."""
    res = await db.execute(delete(DeliveryLog).where(DeliveryLog.at < datetime.now(UTC) - timedelta(days=days)))
    gone = res.rowcount or 0
    edge = await db.scalar(select(DeliveryLog.at).order_by(DeliveryLog.at.desc()).offset(MAX_ROWS).limit(1))
    if edge is not None:
        res = await db.execute(delete(DeliveryLog).where(DeliveryLog.at <= edge))
        gone += res.rowcount or 0
    await db.commit()
    return gone
