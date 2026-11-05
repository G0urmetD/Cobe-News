"""PostgreSQL 18 (asyncpg), schema by Alembic (app/migrations), times as timestamptz, JSON as JSONB.

Up to 0.1.15 the data lived in SQLite (one writer at a time); app/sqlite_import.py moves such a file over once. Two
habits of those days stay on purpose: transactions are short – nothing waits on the network or sleeps with a
transaction open (`release()` first): in Postgres an open transaction holds its row locks (the arrival counter of the
stories, a channel's backoff), keeps a pooled connection and holds back vacuum – and the slow-write watchdog below
logs every write transaction held longer than SLOW_WRITE_S, with the code that started it. Every connection has a
statement timeout and an idle-in-transaction timeout: a runaway query or a forgotten transaction ends instead of
piling up."""

import asyncio
import logging
import re
import time
import unicodedata
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from sqlalchemy import JSON, Connection, DateTime, Text, event, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import ConnectionPoolEntry
from sqlalchemy.types import TypeDecorator

log = logging.getLogger("cobe_news.db")
SLOW_WRITE_S = 2.0  # a write transaction held longer than this is logged (slow-write watchdog)
_WRITES = ("INSERT", "UPDATE", "DELETE")
# one process (uvicorn --workers 1): the request handlers, the news round, the Vendor News round and the notification
# round share these. 10 + 5 keeps well below Postgres' 100 connections, also with a CLI command running beside it
POOL_SIZE, POOL_OVERFLOW = 10, 5
STATEMENT_TIMEOUT_MS = 30_000  # the slowest statement of a normal round (a big batch, a cold overview) takes < 2 s
IDLE_IN_TRANSACTION_MS = 300_000  # a transaction left open (a bug): ended after 5 minutes instead of holding locks
MIGRATION_LOCK = 0x636E_6E77  # pg_advisory_xact_lock key: one migrator at a time (app start, CLI)


class Base(DeclarativeBase):
    pass


# Control characters: PostgreSQL's text and jsonb refuse U+0000 (SQLite stored it) – one NUL from a feed or an API
# call made a whole batch fail. The other C0 controls (except tab, newline, carriage return) are no text anyone reads.
_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def clean_text(value: str) -> str:
    """The text without C0 control characters (tab, newline and carriage return stay)."""
    return _CONTROLS.sub("", value) if _CONTROLS.search(value) else value


def clean(value):  # noqa: ANN001, ANN201
    """clean_text() for every string in a JSON-like value (dict keys too); anything else as it is."""
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, dict):
        return {clean(k): clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    return value


def has_nul(value) -> bool:  # noqa: ANN001
    """A U+0000 anywhere in a JSON-like value (request bodies: refused with 422 instead of failing in the database).
    Without recursion: a body nested thousands deep ("[[[[…", a few KB – json.loads takes it) made it a RecursionError,
    a 500 with a traceback a thousand frames long in the log – also before the sign-in (/api/auth/login)."""
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if "\x00" in v:
                return True
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
    return False


def _no_nul(value):  # noqa: ANN001, ANN202
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {_no_nul(k): _no_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_no_nul(v) for v in value]
    return value


class SafeText(TypeDecorator):
    """text – a U+0000 is dropped on the way in (defence in depth: the input boundaries clean it already)."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return value.replace("\x00", "") if isinstance(value, str) and "\x00" in value else value


class SafeJson(TypeDecorator):
    """JSON columns: JSONB in Postgres (binary, indexable, `data['key']` without parsing text); plain JSON elsewhere – the
    one-off import reads the old SQLite file with the same models (app/sqlite_import.py). jsonb refuses \\u0000 in
    strings and keys: dropped on the way in, like SafeText."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(JSONB() if dialect.name == "postgresql" else JSON())

    def process_bind_param(self, value, dialect):
        return _no_nul(value)


Json = SafeJson


class UTCDateTime(TypeDecorator):
    """timestamptz, always read back as aware UTC (the code compares aware times). A naive value is taken as UTC."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


def fold(value: str | None) -> str:
    """Case- and accent-insensitive text for the search, folded once when a story is stored: "Lücke" finds "LUCKE"."""
    t = unicodedata.normalize("NFKD", (value or "").casefold())
    return "".join(c for c in t if not unicodedata.combining(c))


def contains(value: str) -> str:
    """A LIKE pattern for folded text containing `value`: % and _ are no wildcards here (dropped, as always), and the
    backslash – Postgres' escape character in LIKE, plain text in SQLite – is a plain backslash again."""
    return "%" + fold(value).replace("%", "").replace("_", "").replace("\\", "\\\\") + "%"


_engine: AsyncEngine | None = None
_sessions: async_sessionmaker[AsyncSession] | None = None


def engine_args(*, statement_timeout_ms: int = STATEMENT_TIMEOUT_MS, name: str = "cobe-news") -> dict:
    return {
        "pool_size": POOL_SIZE,
        "max_overflow": POOL_OVERFLOW,
        "pool_pre_ping": True,  # the database restarted (an update, a restore): a dead connection is replaced, not used
        "pool_recycle": 3600,
        "connect_args": {
            "command_timeout": max(60, statement_timeout_ms / 1000 + 30),  # the client gives up after the server would
            "server_settings": {
                "application_name": name,
                "statement_timeout": str(statement_timeout_ms),
                "idle_in_transaction_session_timeout": str(IDLE_IN_TRANSACTION_MS),
                "TimeZone": "UTC",
            },
        },
    }


def init(url: str | URL, *, name: str = "cobe-news") -> AsyncEngine:
    global _engine, _sessions
    u = make_url(url)
    if u.drivername in ("postgresql", "postgres"):
        u = u.set(drivername="postgresql+asyncpg")  # postgresql://… as libpq writes it
    # hide_parameters: a failed statement is logged without its values – they may be password hashes, encrypted secrets
    # or personal data
    _engine = create_async_engine(u, hide_parameters=True, **engine_args(name=name))
    _watch(_engine)
    _sessions = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def engine() -> AsyncEngine:
    assert _engine is not None, "db.init() first"
    return _engine


# ---------------------------------------------------------------- slow-write watchdog


def _where() -> str:
    """The app code that is writing: its frames (newest first) above SQLAlchemy's greenlet – the async caller."""
    try:
        import greenlet

        g = greenlet.getcurrent()
        frame = g.parent.gr_frame if g.parent is not None else None
    except Exception:  # noqa: BLE001 - only a hint for the log
        frame = None
    out: list[str] = []
    while frame is not None and len(out) < 3:
        f = frame.f_code.co_filename.replace("\\", "/")
        if "/app/" in f and not f.endswith("/app/db.py") and "site-packages" not in f:
            out.append(f"{f.rsplit('/app/', 1)[1]}:{frame.f_lineno} {frame.f_code.co_name}")
        frame = frame.f_back
    return " < ".join(out) or "?"


def _done(info: dict) -> None:
    t0 = info.pop("write_t0", None)
    where = info.pop("write_at", "?")
    if t0 is not None and (held := time.monotonic() - t0) > SLOW_WRITE_S:
        log.warning("slow write transaction: held its row locks %.1f s – started at %s", held, where)


def _watch(engine: AsyncEngine) -> None:
    """Measures each write transaction from its first write to its commit or rollback (per pooled connection)."""
    sync = engine.sync_engine

    @event.listens_for(sync, "after_cursor_execute")
    def _write(conn: Connection, _cur: object, statement: str, _params: object, _ctx: object, _many: bool) -> None:
        if "write_t0" not in conn.info and statement.lstrip()[:7].upper().startswith(_WRITES):
            conn.info["write_t0"] = time.monotonic()
            conn.info["write_at"] = _where()

    @event.listens_for(sync, "commit")
    def _commit(conn: Connection) -> None:
        _done(conn.info)

    @event.listens_for(sync, "rollback")
    def _rollback(conn: Connection) -> None:
        _done(conn.info)

    @event.listens_for(sync, "reset")
    def _reset(_dbapi: object, record: ConnectionPoolEntry, _state: object) -> None:  # back in the pool: an open one ends here
        _done(record.info)


# ---------------------------------------------------------------- schema (Alembic)


def alembic_config(connection: Connection | None = None):  # noqa: ANN201
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", "app:migrations")
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def _upgrade(conn: Connection, target: str) -> str | None:
    from alembic import command
    from alembic.runtime.migration import MigrationContext

    conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": MIGRATION_LOCK})  # the CLI and the app at once: one waits
    conn.execute(text("SET LOCAL statement_timeout = 0"))  # an index on a big table may take longer than a request may
    before = MigrationContext.configure(conn).get_current_revision()
    command.upgrade(alembic_config(conn), target)
    after = MigrationContext.configure(conn).get_current_revision()
    return None if before == after else f"{before or 'empty'} → {after}"


async def migrate(target: str = "head") -> None:
    """The schema brought to `target` (Alembic, one transaction – a failed migration leaves the database as it was)."""
    t0 = time.monotonic()
    async with engine().begin() as conn:
        done = await conn.run_sync(_upgrade, target)
    if done:
        log.info("database: schema %s in %.1f s", done, time.monotonic() - t0)


async def revision() -> str | None:
    from alembic.runtime.migration import MigrationContext

    async with engine().connect() as conn:
        return await conn.run_sync(lambda c: MigrationContext.configure(c).get_current_revision())


def head() -> str:
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(alembic_config()).get_current_head() or ""


async def dispose() -> None:
    if _engine is not None:
        await _engine.dispose()


def session() -> AsyncSession:
    assert _sessions is not None, "db.init() first"
    return _sessions()


async def get_db() -> AsyncIterator[AsyncSession]:
    async with session() as s:
        yield s


@asynccontextmanager
async def scoped() -> AsyncIterator[AsyncSession]:
    async with session() as s:
        yield s


async def release(db: AsyncSession) -> None:
    """Before waiting on the network (or sleeping): what the session has pending is written now in a short transaction
    and nothing stays open – no row lock, no pooled connection is held for the download. Loaded objects stay usable
    (expire_on_commit=False)."""
    await db.commit()


PRUNE_BATCH = 5000  # rows per transaction of a retention prune (delete_batched)


async def delete_batched(db: AsyncSession, model, *where, batch: int | None = None) -> int:  # noqa: ANN001 - a mapped class
    """The rows of `model` matching `where` deleted in short transactions of at most `batch` rows each (committed one by
    one) – the retention prunes: no statement runs long (the statement timeout), no transaction holds many row locks
    or a big cascade. Each batch takes its rows with FOR UPDATE SKIP LOCKED: a row another transaction holds (a
    concurrent update of many stories, a delivery being marked) is left for the next prune instead of waiting on it.
    That covers the rows of the table itself only: rows its ON DELETE CASCADE removes can still wait on locks (and, rarely,
    end in a deadlock) – the statement timeout and the prune's per-step try/rollback (main.py) cover that; the rest goes
    with the next prune. Returns how many rows went."""
    from sqlalchemy import delete, select, tuple_

    batch = batch or PRUNE_BATCH
    pk = list(model.__table__.primary_key.columns)
    pick = select(*pk).where(*where).limit(batch).with_for_update(skip_locked=True)
    cond = pk[0].in_(pick.scalar_subquery()) if len(pk) == 1 else tuple_(*pk).in_(pick)
    gone = 0
    while True:
        n = (await db.execute(delete(model).where(cond).execution_options(synchronize_session=False))).rowcount or 0
        await db.commit()
        gone += n
        if n < batch:  # the rest is gone – or held by another transaction: the next prune takes it
            return gone


async def wait_ready(timeout: float = 60.0) -> None:
    """At the start: Postgres may still be starting (depends_on waits for its health check, a restart of the database
    alone does not) – a few tries before giving up."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            async with engine().connect() as conn:
                await conn.execute(text("SELECT 1"))
            return
        except Exception as exc:  # noqa: BLE001 - refused, "the database system is starting up" and the like
            err = exc
        if time.monotonic() > deadline:
            raise RuntimeError(f"database not reachable: {type(err).__name__}") from err
        await asyncio.sleep(1)
