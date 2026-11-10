"""One-off move of a 0.1.15 SQLite database (data/news.db) into the empty PostgreSQL database of 0.1.16.

- The SQLite file is only read (opened read-only) – it stays as it is: the way back to 0.1.15 (docs/BETRIEB.md).
- Everything in one PostgreSQL transaction: a failure (or a stop half-way) leaves the database empty, and the next try
  starts over. Nothing serves a half-moved database.
- Tables in dependency order, in batches; the types are converted by the models themselves (the file is read through
  the same tables with SQLite's types: hex uuids, naive UTC times, JSON text, 0/1). SQLite's rowid goes into the
  identity columns that stand for it (news_item_sources.n, vendor_events.n); the identities are set past it.
- Checked before the commit: the rows per table, and up to SPOT rows of each table (with their JSON) compared value by
  value. Any difference: rolled back, nothing kept.
- Control characters (a NUL above all – SQLite stored it, PostgreSQL refuses it in text and JSON) are dropped from
  every text and JSON value on the way; the report counts the values changed so, per table.
- Refuses a target that holds data. Marked when done (settings "sqlite_import": when, from where, the counts) – at the
  next start nothing is imported again.

On the app's start (app.main) it runs by itself when PostgreSQL is empty and the file holds data; by hand:
`docker compose exec app python -m app.cli migrate-sqlite /data/news.db`."""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Engine, Table, create_engine, func, insert, inspect, literal_column, select, text, tuple_
from sqlalchemy.ext.asyncio import AsyncConnection

from app import __version__, db
from app import models  # noqa: F401 - registers the tables
from app.db import Base

log = logging.getLogger("cobe_news.db")
BATCH = 2000
SPOT = 25
MARKER = "sqlite_import"
ROWID_INTO = {"news_item_sources": "n", "vendor_events": "n"}  # SQLite's rowid → the identity column standing for it
# tables added after 0.1.15 (PostgreSQL only): not in the SQLite file – neither required nor imported. They start
# empty; the backup and the tests see them like any other table (tables()).
NOT_IN_SQLITE = frozenset({"source_fetch_stats", "source_health_events", "source_health_deliveries", "catalog_cpe_checks", "catalog_checks", "epss_scores", "teams", "team_groups", "team_members", "team_products", "team_product_members", "team_welcome", "notify_rule_teams", "person_routes", "person_notify", "person_news", "person_news_sent", "person_deliveries", "vendor_advisory_state", "vendor_advisory_changes", "cve_watches", "cve_watch_state", "calendar_feeds", "person_absences", "team_weekly", "team_weekly_sends", "api_tokens", "audit_log", "delivery_log", "product_suggestions", "user_passkeys", "reader_state", "vendor_reads", "person_mutes", "saved_views", "auth_locks", "password_history", "exploit_refs", "update_dismissals", "remembered_devices"})


class ImportRefused(Exception):
    """Nothing was changed: the reason says why (target not empty, source of another version, unreadable)."""


@dataclass
class Report:
    source: str
    tables: dict[str, int] = field(default_factory=dict)
    seconds: float = 0.0
    checked: int = 0  # rows compared value by value
    cleaned: dict[str, int] = field(default_factory=dict)  # values without their control characters, per table

    def lines(self) -> list[str]:
        width = max((len(t) for t in self.tables), default=10)
        out = [f"{t:<{width}}  {n:>8}" + (f"   ({self.cleaned[t]} values without control characters)" if self.cleaned.get(t) else "") for t, n in self.tables.items()]
        out.append(f"{'total':<{width}}  {sum(self.tables.values()):>8}   ({self.seconds:.1f} s, {self.checked} rows compared value by value)")
        return out


def tables() -> list[Table]:
    return list(Base.metadata.sorted_tables)  # parents before children (foreign keys)


def import_tables() -> list[Table]:
    """The tables a 0.1.15 SQLite file has – what is checked, moved and compared."""
    return [t for t in tables() if t.name not in NOT_IN_SQLITE]


def open_source(path: Path) -> Engine:
    """The SQLite file, read-only (never written, not even its journal mode): sqlite3 with mode=ro."""
    if not path.is_file():
        raise ImportRefused(f"{path}: no such file")
    return create_engine(f"sqlite:///file:{path}?mode=ro&uri=true", connect_args={"check_same_thread": False})


# columns added after 0.1.15 to tables the file has: not in it either – they start empty (NULL, or the column's default:
# news_items.topics '[]' – the background job computes them after the import, news.backfill_topics)
COLUMNS_NOT_IN_SQLITE = frozenset(
    {
        ("users", "role_groups"),
        ("vendor_versions", "confirmed_at"),
        ("vendor_versions", "confirmed_by"),
        ("user_sessions", "method"),
        ("user_sessions", "passkey_id"),
        ("news_reads", "unread"),
        ("news_items", "topics"),
        ("news_items", "quiet_topics"),  # 0.1.47: '[]' – the topics computed after the import are quiet (backfill)
        ("news_items", "products"),  # 0.1.47: '[]' – the background job computes them after the import (story_details, PRODUCTS_V)
        ("notify_rules", "topics"),  # 0.1.47: '[]' – a rule without topics, as before
        ("vendor_advisory_products", "quiet"),  # 0.1.47: links of the relink after a catalogue change – false
        ("users", "temp_password_at"),  # the import's time for a temporary password brought along (run), else NULL
        ("news_sources", "parsed_at"),  # 0.1.50: NULL – undated stories stay until their feed was read once (news.prune)
        ("users", "pending_role"),  # 0.1.52: NULL – no raise to admin waits
        ("news_items", "changes"),  # 0.1.53: '{}' – nothing changed since the story arrived
        ("news_item_sources", "carried_at"),  # 0.1.53: NULL – an imported carry is long decided
        ("news_item_sources", "fresh"),  # 0.1.53: false – an imported carry is long decided, it sends nothing more
        ("notify_rules", "active_seq"),  # 0.1.53: NULL – the rule's time decides, as before
        ("notify_rule_channels", "added_seq"),  # 0.1.53: NULL – the link's time decides, as before
        ("news_items", "systems"),  # 0.1.53: '[]' – the background job computes them after the import (systems.systems_round)
        ("news_items", "quiet_systems"),  # 0.1.53: '[]' – what that job finds is quiet
        ("notify_rules", "systems"),  # 0.1.53: '[]' – a rule without systems, keywords and exclusions, as before
        ("notify_rules", "keywords"),
        ("notify_rules", "exclude"),
    }
)


def _columns(table: Table) -> list:
    return [c for c in table.columns if not (table.name in ROWID_INTO and c.name == ROWID_INTO[table.name]) and (table.name, c.name) not in COLUMNS_NOT_IN_SQLITE]


def check_source(src: Engine) -> dict[str, int]:
    """Rows per table – and that the file is a sound database of 0.1.15 (every table and column the models read)."""
    with src.connect() as conn:
        ok = conn.exec_driver_sql("PRAGMA quick_check").scalar()
        if ok != "ok":
            raise ImportRefused(f"the SQLite file is damaged (quick_check: {ok})")
        insp = inspect(conn)
        missing = []
        for t in import_tables():
            if not insp.has_table(t.name):
                missing.append(t.name)
                continue
            have = {c["name"] for c in insp.get_columns(t.name)}
            missing += [f"{t.name}.{c.name}" for c in _columns(t) if c.name not in have]
        if missing:
            raise ImportRefused(f"the SQLite file is not of 0.1.15 (missing: {', '.join(missing[:8])}) – start 0.1.15 on it once first")
        return {t.name: int(conn.execute(select(func.count()).select_from(t)).scalar() or 0) for t in import_tables()}


def source_has_data(path: Path) -> bool:
    """Something worth moving: an account, a setting or a story (a fresh 0.1.15 that never ran the setup is nothing)."""
    try:
        src = open_source(path)
        with src.connect() as conn:
            names = set(inspect(conn).get_table_names())
            return any(t in names and conn.exec_driver_sql(f"SELECT EXISTS (SELECT 1 FROM {t})").scalar() for t in ("users", "settings", "news_items"))  # noqa: S608 - fixed names
    except Exception:  # noqa: BLE001 - unreadable: run() says why
        return True
    finally:
        if "src" in locals():
            src.dispose()


async def target_empty(conn: AsyncConnection) -> bool:
    """No rows in any table – also a fresh database without any schema yet (a new server)."""
    if await conn.scalar(text("SELECT to_regclass('public.alembic_version')")) is None:
        return True
    for t in tables():
        if await conn.scalar(select(literal_column("1")).select_from(t).limit(1)):
            return False
    return True


SEED_TABLES = ("news_sources", "settings")


async def seed_only(conn: AsyncConnection) -> bool:
    """What an app start leaves in an empty database, and nothing else: the built-in sources (no story, no source of an
    admin's) and the open setup (a setup token, no account). A manual import (SQLITE_IMPORT=0, then `migrate-sqlite`
    while the app runs) takes their place – before, it always refused: "PostgreSQL already holds data"."""
    if await conn.scalar(text("SELECT to_regclass('public.alembic_version')")) is None:
        return False
    for t in tables():
        if t.name not in SEED_TABLES and await conn.scalar(select(literal_column("1")).select_from(t).limit(1)):
            return False
    if await conn.scalar(text("SELECT 1 FROM news_sources WHERE NOT builtin LIMIT 1")):
        return False
    keys = dict((await conn.execute(text("SELECT key, value FROM settings"))).all())
    return set(keys) <= {"setup"} and not (keys.get("setup") or {}).get("completed")


async def imported(conn: AsyncConnection) -> dict | None:
    """The marker of an earlier import (None: never imported)."""
    from app.models import Setting

    return await conn.scalar(select(Setting.value).where(Setting.key == MARKER))


def _clean(d: dict) -> int:
    """The row's text and JSON values without control characters (in place); how many values changed."""
    n = 0
    for k, v in d.items():
        if isinstance(v, (str, dict, list)):
            c = db.clean(v)
            if c != v:
                d[k], n = c, n + 1
    return n


def _read(src: Engine, table: Table, after: int, limit: int, cleaned: dict[str, int] | None = None) -> list[dict]:
    """One batch, in rowid order (keyset, not OFFSET): rows as dicts of Python values, rowid → its identity column."""
    cols = _columns(table)
    rowid = literal_column("rowid")
    stmt = select(rowid, *cols).select_from(table).where(rowid > after).order_by(rowid).limit(limit)
    with src.connect() as conn:
        out = []
        for row in conn.execute(stmt).all():
            d = {c.name: row[i + 1] for i, c in enumerate(cols)}
            if n := _clean(d):
                if cleaned is not None:
                    cleaned[table.name] = cleaned.get(table.name, 0) + n
            d["__rowid"] = row[0]
            if table.name in ROWID_INTO:
                d[ROWID_INTO[table.name]] = row[0]
            out.append(d)
        return out


def _sample(src: Engine, table: Table) -> list[dict]:
    """Up to SPOT rows to compare value by value: the first, the last and random ones."""
    cols = _columns(table)
    rowid = literal_column("rowid")
    with src.connect() as conn:
        first = select(rowid).select_from(table).order_by(rowid).limit(3)
        last = select(rowid).select_from(table).order_by(rowid.desc()).limit(3)
        rand = select(rowid).select_from(table).order_by(func.random()).limit(SPOT - 6)
        ids = {r for q in (first, last, rand) for r in conn.execute(q).scalars()}
        if not ids:
            return []
        rows = conn.execute(select(rowid, *cols).select_from(table).where(rowid.in_(sorted(ids)))).all()
        out = [{c.name: r[i + 1] for i, c in enumerate(cols)} | ({ROWID_INTO[table.name]: r[0]} if table.name in ROWID_INTO else {}) for r in rows]
        for d in out:
            _clean(d)  # compared with what was moved: without its control characters
        return out


def _same(a: object, b: object) -> bool:
    if isinstance(a, float) or isinstance(b, float):
        return a == b or (a is not None and b is not None and abs(float(a) - float(b)) < 1e-9)
    if isinstance(a, memoryview):
        a = bytes(a)
    if isinstance(b, memoryview):
        b = bytes(b)
    return a == b


async def _verify(conn: AsyncConnection, src: Engine, counts: dict[str, int]) -> int:
    checked = 0
    for t in import_tables():
        got = int(await conn.scalar(select(func.count()).select_from(t)) or 0)
        if got != counts[t.name]:
            raise ImportRefused(f"{t.name}: {got} rows in PostgreSQL, {counts[t.name]} in SQLite – nothing kept")
        sample = await asyncio.to_thread(_sample, src, t)
        if not sample:
            continue
        pk = list(t.primary_key.columns)
        keys = [tuple(r[c.name] for c in pk) for r in sample]
        rows = (await conn.execute(select(*t.columns).where(tuple_(*pk).in_(keys)))).mappings().all()
        by_key = {tuple(r[c.name] for c in pk): r for r in rows}
        for want in sample:
            have = by_key.get(tuple(want[c.name] for c in pk))
            if have is None:
                raise ImportRefused(f"{t.name}: row {want[pk[0].name]} missing in PostgreSQL – nothing kept")
            for name, value in want.items():
                if not _same(value, have[name]):
                    raise ImportRefused(f"{t.name}.{name}: differs for row {want[pk[0].name]} – nothing kept")
            checked += 1
    return checked


async def run(path: Path, *, progress=None) -> Report:  # noqa: ANN001
    """Moves the SQLite file at `path` into the (empty) PostgreSQL database of db.init(); raises ImportRefused."""
    t0 = time.monotonic()
    src = open_source(path)
    report = Report(source=str(path))
    try:
        try:
            counts = await asyncio.to_thread(check_source, src)
        except ImportRefused:
            raise
        except Exception as exc:  # noqa: BLE001 - locked, not a database, no permission …
            raise ImportRefused(f"cannot read {path}: {type(exc).__name__}: {exc}") from exc
        async with db.engine().begin() as conn:  # one transaction: all or nothing
            await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": db.MIGRATION_LOCK})
            await conn.execute(text("SET LOCAL statement_timeout = 0"))
            if not await target_empty(conn):
                if not await seed_only(conn):
                    raise ImportRefused("PostgreSQL already holds data – nothing imported (an import runs only into an empty database)")
                for name in SEED_TABLES:  # the start's seed makes way for the file's own sources and settings
                    await conn.execute(text(f"DELETE FROM {name}"))  # noqa: S608 - fixed names
            for t in import_tables():
                after, done = 0, 0
                while rows := await asyncio.to_thread(_read, src, t, after, BATCH, report.cleaned):
                    after = rows[-1].pop("__rowid")
                    for r in rows:
                        r.pop("__rowid", None)
                    await conn.execute(insert(t), rows)
                    done += len(rows)
                    if progress:
                        progress(t.name, done, counts[t.name])
                report.tables[t.name] = done
            for name, col in ROWID_INTO.items():  # the next identity after the highest rowid taken over
                await conn.execute(
                    text(f"SELECT setval(pg_get_serial_sequence('{name}', '{col}'), coalesce((SELECT max({col}) FROM {name}), 0) + 1, false)")  # noqa: S608
                )
            report.checked = await _verify(conn, src, counts)
            # a temporary password brought along counts from the import: 0.1.15 kept no issue time – counted from the
            # account's creation it would have run out the moment it arrived (passwords.temp_expires_at)
            await conn.execute(text("UPDATE users SET temp_password_at = now() WHERE must_change_password AND auth_source = 'local' AND temp_password_at IS NULL"))
            from app.models import Setting

            report.seconds = round(time.monotonic() - t0, 1)
            marker = {"from": "sqlite", "file": str(path), "at": datetime.now(UTC).isoformat(), "version": __version__, "rows": report.tables, "seconds": report.seconds}
            if report.cleaned:
                marker["cleaned"] = report.cleaned
            await conn.execute(insert(Setting).values(key=MARKER, value=marker))
    finally:
        src.dispose()
    return report


def _note(path: Path, report: Report) -> None:
    """A note next to the file (the file itself stays untouched): where its data went and how to go back."""
    try:
        note = path.with_name(path.name + ".imported-to-postgresql.txt")
        note.write_text(
            f"{path.name} was imported into PostgreSQL on {datetime.now(UTC):%Y-%m-%d %H:%M} UTC by Cobe News {__version__}"
            f" ({sum(report.tables.values())} rows). Since then the data lives in PostgreSQL; this file is no longer written.\n"
            "It stays as the way back to 0.1.15 (docs/BETRIEB.md: PostgreSQL – Umstieg und zurück).\n"
        )
    except OSError:
        pass


async def on_start(path: Path) -> Report | None:
    """At the app's start, after the migrations: PostgreSQL empty and the SQLite file holds data – moved once. A failure
    raises: the app does not start (and does not serve an empty or half-filled database)."""
    if not path.is_file():
        return None
    async with db.engine().connect() as conn:
        if await imported(conn):
            return None
        empty = await target_empty(conn)
    if not await asyncio.to_thread(source_has_data, path):
        return None
    if not empty:
        log.warning("database: %s holds data, PostgreSQL too, but without an import marker – nothing imported (docs/BETRIEB.md)", path.name)
        return None
    log.info("database: PostgreSQL is empty and %s holds the data of an earlier version – importing it once (the file stays unchanged)", path.name)
    try:
        report = await run(path)
    except ImportRefused as exc:
        log.error("database: import of %s refused – %s. The app does not start; the SQLite file is unchanged (docs/BETRIEB.md)", path.name, exc)
        raise
    for line in report.lines():
        log.info("database: imported %s", line)
    log.info("database: import of %s done – %d rows in %.1f s; the file stays as the way back", path.name, sum(report.tables.values()), report.seconds)
    _note(path, report)
    return report
