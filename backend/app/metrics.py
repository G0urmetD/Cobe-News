"""/metrics – the state of this installation in the Prometheus text format (0.0.4), for an API token with the scope
`metrics` (app/api_tokens.py). No personal data and no titles: sources by their key and name (sources are no people),
notification channels by their id and type (an admin may name a channel after a person), deliveries only as counts
(also the delivery log's attempts and outcomes).

Cheap to scrape: the whole answer is kept CACHE_S, the parts that cost more (what the channels still have to send, the
database size) SLOW_S; one scrape computes at a time, the others wait for it. Written by hand (no client library):
`Exposition` checks names, escapes label values and HELP texts and formats the numbers as the format wants them."""

import asyncio
import math
import re
import time
from collections.abc import Iterable
from datetime import UTC, datetime

from fastapi import APIRouter, Response
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__, backup, db, delivery_log, restore_test, source_health
from app.api_tokens import MetricsToken
from app.deps import Db
from app.models import NotifyChannel, PersonDelivery

router = APIRouter()
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
CACHE_S = 30.0
SLOW_S = 300.0
PENDING_TIMEOUT_S = 20.0

_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_LABEL = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
TYPES = ("gauge", "counter", "untyped")


def escape_label(value: object) -> str:
    """A label value: backslash, double quote and line feed escaped (nothing else is special)."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def escape_help(value: str) -> str:
    """A HELP text: backslash and line feed escaped."""
    return value.replace("\\", "\\\\").replace("\n", "\\n")


def number(v: float | int | bool | None) -> str:
    if v is None:
        return "NaN"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int):
        return str(v)
    if math.isnan(v):
        return "NaN"
    if math.isinf(v):
        return "+Inf" if v > 0 else "-Inf"
    return repr(float(v))


class Exposition:
    """One answer: each family once (HELP, TYPE, then its samples), in the order added."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.names: set[str] = set()

    def family(self, name: str, kind: str, help_: str, samples: Iterable[tuple[dict, float | int | bool | None]]) -> None:
        if not _NAME.fullmatch(name) or name in self.names or kind not in TYPES:
            raise ValueError(f"bad or repeated metric {name!r}")
        self.names.add(name)
        self.lines += [f"# HELP {name} {escape_help(help_)}", f"# TYPE {name} {kind}"]
        for labels, value in samples:
            for k in labels:
                if not _LABEL.fullmatch(k) or k.startswith("__"):
                    raise ValueError(f"bad label name {k!r}")
            lab = ",".join(f'{k}="{escape_label(v)}"' for k, v in labels.items())
            self.lines.append(f"{name}{{{lab}}} {number(value)}" if lab else f"{name} {number(value)}")

    def one(self, name: str, help_: str, value: float | int | bool | None, kind: str = "gauge") -> None:
        self.family(name, kind, help_, [({}, value)])

    def render(self) -> bytes:
        return ("\n".join(self.lines) + "\n").encode()


def _ts(d: datetime | None) -> float | None:
    return d.timestamp() if d else None


def _parse(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


# ---------------------------------------------------------------- the parts


async def _sources(s: AsyncSession, out: Exposition) -> None:
    now = datetime.now(UTC)
    rows = await source_health.collect(s, now)
    outs = [(r, source_health.row_out(r, now)) for r in rows]

    def lab(r) -> dict:  # noqa: ANN001
        return {"kind": r.kind, "source": r.key, "name": r.name}

    out.family(
        "cobe_news_source_state",
        "gauge",
        "Health state of a source (1 for its current state): healthy, slow, disturbed, dead, off, never",
        [({**lab(r), "state": st}, r.state == st) for r, _ in outs for st in source_health.STATES],
    )
    out.family("cobe_news_source_enabled", "gauge", "Whether the source is switched on and needed", [(lab(r), bool(o["enabled"])) for r, o in outs])
    out.family(
        "cobe_news_source_last_success_timestamp_seconds",
        "gauge",
        "Unix time of the last successful fetch",
        [(lab(r), _ts(_parse(o["last_ok_at"]))) for r, o in outs if o["last_ok_at"]],
    )
    out.family(
        "cobe_news_source_last_fetch_timestamp_seconds",
        "gauge",
        "Unix time of the last fetch, successful or not",
        [(lab(r), _ts(_parse(o["last_fetch_at"]))) for r, o in outs if o["last_fetch_at"]],
    )
    out.family("cobe_news_source_consecutive_failures", "gauge", "Failed fetches in a row", [(lab(r), int(o["failures"] or 0)) for r, o in outs])
    out.family("cobe_news_source_fetches_7d", "gauge", "Fetches within the last 7 days", [(lab(r), int(o["fetches_7d"] or 0)) for r, o in outs])
    out.family("cobe_news_source_timeouts_7d", "gauge", "Fetches that timed out within the last 7 days", [(lab(r), int(o["timeouts_7d"] or 0)) for r, o in outs])
    out.family("cobe_news_source_parse_errors_7d", "gauge", "Unreadable answers within the last 7 days", [(lab(r), int(o["parse_errors_7d"] or 0)) for r, o in outs])
    counts = source_health.counts(rows)
    out.family("cobe_news_sources", "gauge", "Sources per health state", [({"state": st}, n) for st, n in counts.items()])


async def _channels(s: AsyncSession, out: Exposition, pending: dict[str, int] | None) -> None:
    now = datetime.now(UTC)
    chs = list(await s.scalars(select(NotifyChannel).order_by(NotifyChannel.id)))

    def lab(c: NotifyChannel) -> dict:
        return {"channel_id": str(c.id), "type": c.type}

    out.family("cobe_news_channel_consecutive_failures", "gauge", "Failed sends of a notification channel in a row", [(lab(c), int(c.failures or 0)) for c in chs])
    out.family(
        "cobe_news_channel_backoff",
        "gauge",
        "1 while a channel pauses after a failure (its next try lies ahead)",
        [(lab(c), bool(c.failures and c.next_try_at and c.next_try_at > now)) for c in chs],
    )
    out.family(
        "cobe_news_channel_last_success_timestamp_seconds",
        "gauge",
        "Unix time of the last message a channel delivered",
        [(lab(c), _ts(c.last_sent_at)) for c in chs if c.last_sent_at],
    )
    health = await delivery_log.health(s, None, now)
    out.family(
        "cobe_news_channel_delivery_attempts_24h",
        "gauge",
        "Delivery attempts of a channel within the last 24 hours (the delivery log, tests not counted)",
        [(lab(c), health.get(c.id, {}).get("attempts_24h", 0)) for c in chs],
    )
    out.family(
        "cobe_news_channel_delivery_failures_24h",
        "gauge",
        "Failed delivery attempts of a channel within the last 24 hours (the delivery log, tests not counted)",
        [(lab(c), health.get(c.id, {}).get("failed_24h", 0)) for c in chs],
    )
    if pending is not None:
        out.family(
            "cobe_news_channel_pending_items",
            "gauge",
            f"Stories and events a channel still has to send (computed at most every {int(SLOW_S)} s)",
            [(lab(c), pending.get(str(c.id), 0)) for c in chs],
        )


async def _personal(s: AsyncSession, out: Exposition) -> None:
    from app import personal

    rows = (
        await s.execute(
            select(PersonDelivery.status, PersonDelivery.way, func.count())
            .where(PersonDelivery.status.in_(("pending", "sending", "failed")))
            .group_by(PersonDelivery.status, PersonDelivery.way)
        )
    ).all()
    got = {(st, way): int(n) for st, way, n in rows}
    ways = sorted({w for _, w in got} | {"email", "desktop", "teams"})
    out.family(
        "cobe_news_personal_deliveries",
        "gauge",
        "Personal Vendor News deliveries by state (pending, sending, failed – failed ones as long as they are kept)",
        [({"status": st, "way": w}, got.get((st, w), 0)) for st in ("pending", "sending", "failed") for w in ways],
    )
    out.one("cobe_news_personal_backlog", "1 when the last personal delivery round stopped at its budget with messages left", bool(personal.backlog()))


async def _audit(s: AsyncSession, out: Exposition) -> None:
    """The audit log by group – counts only, never who or on what (app/audit.py)."""
    from app import audit
    from app.models import AuditEntry

    got = dict((await s.execute(select(AuditEntry.action, func.count()).group_by(AuditEntry.action))).all())
    per = {g: sum(int(got.get(a, 0)) for a in actions) for g, actions in audit.GROUPS.items()}
    out.family("cobe_news_audit_entries", "gauge", "Audit log entries kept, by group of action", [({"group": g}, n) for g, n in per.items()])
    newest = await s.scalar(select(func.max(AuditEntry.at)))
    out.one("cobe_news_audit_newest_timestamp_seconds", "Unix time of the newest audit log entry (NaN: none yet)", _ts(newest))


def _deliveries(out: Exposition) -> None:
    """Delivery attempts since this process started, by what (rule, forward, weekly, test – personal: a person's own
    ways), the channel type (personal: the way) and the outcome – counts only, no channel, rule or person."""
    counts = delivery_log.counters()
    out.family(
        "cobe_news_delivery_attempts_total",
        "counter",
        "Delivery attempts since the start by kind, channel type (personal: way) and outcome: ok, http, timeout, blocked, smtp, error",
        [({"kind": k, "type": t, "outcome": o}, n) for (k, t, o), n in sorted(counts.items())],
    )


def _backup(conf_last: dict, out: Exposition) -> None:
    now = datetime.now(UTC)
    files = backup.listing()
    newest = _parse(files[0]["at"]) if files else None
    attempt = _parse(conf_last.get("at"))
    out.one("cobe_news_backup_last_ok", "1 when the last backup attempt worked, 0 when it failed, NaN before the first", None if not attempt else bool(conf_last.get("ok")))
    out.one("cobe_news_backup_last_attempt_timestamp_seconds", "Unix time of the last backup attempt", _ts(attempt))
    out.one("cobe_news_backup_newest_timestamp_seconds", "Unix time of the newest backup file", _ts(newest))
    out.one("cobe_news_backup_age_seconds", "Age of the newest backup file (NaN: none)", (now - newest).total_seconds() if newest else None)
    out.one("cobe_news_backup_files", "Backup files kept", len(files))


def _restore(st: dict, out: Exposition) -> None:
    now = datetime.now(UTC)
    last = st.get("last") or {}
    at = _parse(last.get("at"))
    out.one("cobe_news_restore_test_configured", "1 when the throwaway database for the restore test is set up", bool(st.get("configured")))
    out.one("cobe_news_restore_test_enabled", "1 when the restore test is switched on", bool(st.get("enabled")))
    out.one("cobe_news_restore_test_running", "1 while a restore test runs", bool(st.get("running")))
    out.one("cobe_news_restore_test_last_ok", "1 when the last restore test passed, 0 when it failed, NaN before the first", None if not at else bool(last.get("ok")))
    out.one("cobe_news_restore_test_last_timestamp_seconds", "Unix time the last restore test ended", _ts(at))
    out.one("cobe_news_restore_test_age_seconds", "Age of the last restore test (NaN: none yet)", (now - at).total_seconds() if at else None)
    out.one("cobe_news_restore_test_duration_seconds", "How long the last restore test took", last.get("seconds"))


# ---------------------------------------------------------------- caching


class _Cache:
    body: bytes | None = None
    at = -1e9
    slow_at = -1e9
    pending: dict[str, int] | None = None
    db_size: int | None = None
    lock: asyncio.Lock | None = None


_cache = _Cache()


def reset() -> None:
    global _cache
    _cache = _Cache()


async def _slow(s: AsyncSession) -> None:
    """What the channels still have to send (the notification round's own question) and the database size."""
    from app import notify

    pending: dict[str, int] = {}
    try:
        async with asyncio.timeout(PENDING_TIMEOUT_S):
            for ch in list(await s.scalars(select(NotifyChannel))):
                pending[str(ch.id)] = len(await notify.channel_pending(s, ch))
        _cache.pending = pending
    except Exception:  # noqa: BLE001 - a metric missing for a while is better than no answer
        _cache.pending = None
    try:
        _cache.db_size = int(await s.scalar(text("SELECT pg_database_size(current_database())")) or 0)
    except Exception:  # noqa: BLE001
        _cache.db_size = None
    await s.rollback()


async def render() -> bytes:
    """The whole answer – from the cache when it is younger than CACHE_S."""
    if _cache.lock is None:
        _cache.lock = asyncio.Lock()
    async with _cache.lock:
        now = time.monotonic()
        if _cache.body is not None and now - _cache.at < CACHE_S:
            return _cache.body
        out = Exposition()
        out.family("cobe_news_info", "gauge", "Version of Cobe News", [({"version": __version__}, 1)])
        async with db.session() as s:
            if now - _cache.slow_at >= SLOW_S:
                _cache.slow_at = now
                await _slow(s)
            await _sources(s, out)
            await _channels(s, out, _cache.pending)
            await _personal(s, out)
            await _audit(s, out)
            _deliveries(out)
            from app import settings as settings_store

            last = await settings_store.get(s, backup.LAST)
            st = await restore_test.status(s)
        _backup(last, out)
        _restore(st, out)
        if _cache.db_size is not None:
            out.one("cobe_news_database_size_bytes", "Size of the database on disk", _cache.db_size)
        out.one("cobe_news_metrics_generated_timestamp_seconds", f"Unix time this answer was computed (kept up to {int(CACHE_S)} s)", time.time())
        _cache.body, _cache.at = out.render(), time.monotonic()
        return _cache.body


@router.get(
    "/metrics",
    summary="Prometheus metrics",
    operation_id="metrics",
    tags=["Metrics"],
    response_class=Response,
    responses={
        200: {"description": "Prometheus text format 0.0.4", "content": {CONTENT_TYPE.split(";")[0]: {"schema": {"type": "string"}}}},
        401: {"description": "No token, or an unknown, malformed, revoked or expired one"},
        403: {"description": "The token lacks the scope `metrics`"},
        429: {"description": "Too many requests (Retry-After)"},
    },
)
async def metrics(token: MetricsToken, db_: Db) -> Response:
    """Source health, deliveries waiting or failed, backups and the restore test – kept 30 s."""
    await db_.commit()  # the token's "last used" – nothing else is written
    return Response(await render(), media_type=CONTENT_TYPE, headers={"Cache-Control": "no-store"})

