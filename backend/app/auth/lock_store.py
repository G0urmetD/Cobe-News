"""The brute-force locks survive a restart (app/auth/bruteforce.py): an account lock or an address block, once set, is
written to the table auth_locks; the start reads the ones still running back into memory. The counters themselves
(failures so far, delays) stay in memory – a restart forgets them, as before. An admin's unlock removes the row too.

- Written best-effort, in a transaction of its own, right after the failure that set the lock (the lock holds in memory
  either way – a database that is briefly unavailable only costs its survival of a restart).
- Bounded: at most MAX_ROWS rows; beyond that the ones ending first go. Expired rows go at the start and hourly.
- Times are wall-clock in the table (the monotonic clock of the process does not survive it): a clock set back makes
  a lock last longer, never shorter than set – capped at the longest lock there is."""

import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as dbm
from app.auth import bruteforce
from app.models import AuthLock

log = logging.getLogger("cobe_news.auth")
MAX_ROWS = 10_000
LONGEST = max(bruteforce.ACCOUNT_LOCK * bruteforce.LOCK_FACTOR_MAX, bruteforce.IP_BLOCK)


async def write(s: AsyncSession, changes: dict[str, tuple[float, int] | None]) -> None:
    """The changes of bruteforce.take_dirty in the session `s` (not committed)."""
    now, mono = datetime.now(UTC), time.monotonic()
    for key, v in changes.items():
        if v is None:
            await s.execute(delete(AuthLock).where(AuthLock.key == key))
            continue
        until = now + timedelta(seconds=max(0.0, v[0] - mono))
        stmt = insert(AuthLock).values(key=key[:600], until=until, strikes=int(v[1]), created_at=now)
        await s.execute(stmt.on_conflict_do_update(index_elements=[AuthLock.key], set_={"until": stmt.excluded.until, "strikes": stmt.excluded.strikes}))
    n = int(await s.scalar(select(func.count()).select_from(AuthLock)) or 0)
    if n > MAX_ROWS:
        cut = select(AuthLock.key).order_by(AuthLock.until).limit(n - MAX_ROWS).scalar_subquery()
        await s.execute(delete(AuthLock).where(AuthLock.key.in_(cut)))


async def flush() -> None:
    """What bruteforce noted since the last call, written in a session of its own – never raises."""
    changes = bruteforce.take_dirty()
    if not changes:
        return
    try:
        async with dbm.session() as s:
            await write(s, changes)
            await s.commit()
    except Exception as exc:  # noqa: BLE001 - the lock holds in memory; only its survival of a restart is lost
        log.warning("brute-force locks not stored (%s) – they hold until the next restart", type(exc).__name__)


async def load(s: AsyncSession) -> int:
    """At the start: expired rows go, the others are locks in memory again. Returns how many."""
    now = datetime.now(UTC)
    await s.execute(delete(AuthLock).where(AuthLock.until <= now))
    rows = list(await s.scalars(select(AuthLock).order_by(AuthLock.until.desc()).limit(MAX_ROWS)))
    await s.commit()
    for r in rows:
        bruteforce.restore(r.key, min((r.until - now).total_seconds(), LONGEST), r.strikes)
    if rows:
        log.info("brute-force: %s lock(s) and block(s) from before the restart still hold", len(rows))
    return len(rows)


async def prune(s: AsyncSession) -> int:
    """Expired rows (hourly)."""
    res = await s.execute(delete(AuthLock).where(AuthLock.until <= datetime.now(UTC)))
    await s.commit()
    return res.rowcount or 0
