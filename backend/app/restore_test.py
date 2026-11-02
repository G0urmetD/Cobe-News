"""Rücksicherungs-Test: the newest backup really restored – into a throwaway database, never into the app's own.

Where it restores to (docker-compose.yml, deploy/postgres/restore-role.sql): the database `cobe_news_restore_test` with
a role of its own, `cobe_news_restore`, made by db-init when POSTGRES_RESTORE_PASSWORD is set. That role owns only
that database; it is no superuser, cannot create databases or roles, is no member of the app's role and may not even
connect to the app's database. The app's own role gets no right at all – so a mistake in this code could never
restore into the real data: the database server itself would refuse it. Before anything is touched, `_guard()` asks the
server exactly that and refuses ("unsafe") otherwise.

What is checked – the same checks as a real restore (backup.prepare, backup._pipe_restore):
1. the file: decrypted with the passphrase (encrypted) or its signature with this installation's key (unencrypted),
   only the expected members, their checksums, the dump's table of contents, a schema revision this version knows;
2. the restore: pg_restore → psql into the throwaway database in one transaction, without errors;
3. inside that transaction: the rows per table exactly as the backup's manifest says, and the schema exactly that of a
   freshly migrated database of the backup's revision (made in the throwaway database and rolled back);
4. after it: the schema revision (alembic_version) in the restored database is the backup's.
Then the throwaway database is emptied again (its schema public dropped and made anew) – also after a failure.

When: by the app (mode "app": every `every_days` days within WINDOW_H hours after `hour` UTC – at night by default,
weekly, switched on) or by the host's cron (mode "host": scripts/restore-test.sh, the CLI `restore-test`) – for
backups encrypted with a passphrase the app does not know (a passphrase file only the cron job reads). The test runs at
low priority (pg_restore and psql niced to 19), one at a time (an advisory lock, also across the CLI), never while a
backup runs, and ends after TIMEOUT_S. Its outcome is a settings entry (restore_test_last): the page Sicherung & Export
and /metrics show it."""

import asyncio
import contextlib
import logging
import shutil
import time
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter
from pydantic import ConfigDict
from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app import audit, backup, db
from app import settings as settings_store
from app.config import get_config
from app.deps import Admin, Db, NoNul, api_error

log = logging.getLogger("cobe_news.restore_test")

SECTION = "restore_test"  # settings: {"enabled", "mode", "every_days", "hour", "rev"}
LAST = "restore_test_last"  # settings: the last outcome
DEFAULTS = {"enabled": True, "mode": "app", "every_days": 7, "hour": 3}
EVERY_CHOICES = (1, 7, 14, 30)
WINDOW_H = 3  # a run may start up to this many hours after `hour` (a restart at 03:10 still runs it)
CHECK_EVERY_S = 600.0
TIMEOUT_S = 3600.0
LOCK = 0x636E_7274  # pg_try_advisory_lock on the app's database: one restore test at a time (app, CLI)
APP_NAME = "cobe-news-restore-test"

router = APIRouter(prefix="/api/admin/restore-test", tags=["admin"])


class Failed(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- when


def _conf(raw: dict) -> dict:
    c = {**DEFAULTS, **raw}
    c["every_days"] = int(c["every_days"]) if int(c.get("every_days") or 0) in EVERY_CHOICES else DEFAULTS["every_days"]
    c["hour"] = int(c["hour"]) % 24
    c["mode"] = c["mode"] if c["mode"] in ("app", "host") else "app"
    c["enabled"] = bool(c["enabled"])
    return c


def _parse(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def _in_window(conf: dict, at: datetime) -> bool:
    return (at.hour - conf["hour"]) % 24 < WINDOW_H


def due(conf: dict, last_at: datetime | None, now: datetime) -> bool:
    """Whether the app runs a test now: within the window, and the last one (passed or not) is `every_days` old – less a
    little, so the next one falls into the same window and does not creep later."""
    if not _in_window(conf, now):
        return False
    return last_at is None or now - last_at >= timedelta(days=conf["every_days"]) - timedelta(hours=WINDOW_H + 1)


def next_at(conf: dict, last_at: datetime | None, now: datetime) -> datetime:
    """When the app will run the next test (the start of its window, or now when it is due now)."""
    if due(conf, last_at, now):
        return now
    base = max(now, last_at + timedelta(days=conf["every_days"]) - timedelta(hours=WINDOW_H + 1)) if last_at else now
    if _in_window(conf, base):
        return base
    start = base.replace(hour=conf["hour"], minute=0, second=0, microsecond=0)
    return start if start > base else start + timedelta(days=1)


# ---------------------------------------------------------------- state


_job: dict = {"task": None, "since": None}


async def running(s: AsyncSession) -> bool:
    task = _job["task"]
    if task is not None and not task.done():
        return True
    held = await s.scalar(
        text("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND classid = 0 AND objid = :k AND objsubid = 1 AND granted)"), {"k": LOCK}
    )
    return bool(held)


def target() -> URL | None:
    return get_config().restore_url


async def status(s: AsyncSession) -> dict:
    cfg = get_config()
    raw = await settings_store.get(s, SECTION)
    conf = _conf(raw)
    last = await settings_store.get(s, LAST)
    url = target()
    busy = await running(s)
    newest = _newest()
    last_at = _parse(last.get("at"))
    now = datetime.now(UTC)
    scheduled = url is not None and conf["enabled"] and conf["mode"] == "app"
    every = timedelta(days=conf["every_days"])
    return {
        "configured": url is not None,
        "target": {"database": url.database, "user": url.username} if url is not None else None,
        **{k: conf[k] for k in ("enabled", "mode", "every_days", "hour")},
        "every_choices": list(EVERY_CHOICES),
        "window_h": WINDOW_H,
        "timeout_s": int(TIMEOUT_S),
        "rev": int(raw.get("rev") or 0),
        "running": busy,
        "running_since": _job["since"] if busy and _job["task"] is not None and not _job["task"].done() else None,
        "last": last if last.get("at") else None,
        "next_at": next_at(conf, last_at, now).isoformat() if scheduled else None,
        # no test for longer than the period and a day: the cron job (mode host) or the app's schedule does not run
        "overdue": bool(url is not None and conf["enabled"] and last_at is not None and now - last_at > every + timedelta(days=1)),
        "passphrase": bool(cfg.backup_passphrase),
        "newest": newest,
    }


async def _record(value: dict) -> None:
    try:
        async with db.session() as s:
            await settings_store.put(s, LAST, value)
            await s.commit()
    except Exception:  # noqa: BLE001 - the outcome is logged anyway
        log.warning("restore test: outcome not recorded")


# ---------------------------------------------------------------- the throwaway database


def _same_db(a: URL, b: URL) -> bool:
    return (a.host or "localhost", a.port or 5432, a.database) == (b.host or "localhost", b.port or 5432, b.database)


_GUARD = text(
    """SELECT current_database() AS db, current_user AS usr, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
       (SELECT d.datdba = r.oid FROM pg_database d WHERE d.datname = current_database()) AS owns,
       EXISTS (SELECT 1 FROM pg_database d WHERE d.datname = :appdb AND has_database_privilege(r.oid, d.oid, 'CONNECT')) AS reaches_app,
       EXISTS (SELECT 1 FROM pg_roles a WHERE a.rolname = :appuser AND a.oid <> r.oid AND pg_has_role(r.oid, a.oid, 'MEMBER')) AS in_app_role
  FROM pg_roles r WHERE r.rolname = current_user"""
)


async def _guard(conn, app: URL) -> list[str]:  # noqa: ANN001
    """What makes the throwaway database unsafe to restore into – asked of the server itself."""
    g = (await conn.execute(_GUARD, {"appdb": app.database, "appuser": app.username or ""})).mappings().one()
    bad = []
    if g["db"] == app.database:
        bad.append("it is the app's own database")
    if g["rolsuper"] or g["rolbypassrls"] or g["rolreplication"]:
        bad.append(f"the role {g['usr']} is a superuser or has replication / bypass-RLS rights")
    if g["rolcreaterole"] or g["rolcreatedb"]:
        bad.append(f"the role {g['usr']} may create roles or databases")
    if g["reaches_app"]:
        bad.append(f"the role {g['usr']} may connect to the app's database {app.database}")
    if g["in_app_role"]:
        bad.append(f"the role {g['usr']} is a member of the app's role {app.username}")
    if not g["owns"]:
        bad.append(f"the role {g['usr']} does not own the database {g['db']}")
    return bad


def _engine(url: URL) -> AsyncEngine:
    return create_async_engine(
        url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"timeout": 15, "command_timeout": TIMEOUT_S, "server_settings": {"application_name": APP_NAME, "statement_timeout": "0", "TimeZone": "UTC"}},
    )


async def _reference(engine: AsyncEngine, revision: str) -> list[str]:
    """backup._SCHEMA of a freshly migrated database at `revision` – made in the throwaway database and rolled back."""
    from alembic import command

    async with engine.connect() as conn:
        trans = await conn.begin()
        try:
            for stmt in backup.RESET.split("; "):
                await conn.execute(text(stmt.rstrip(";")))
            await conn.run_sync(lambda c: command.upgrade(db.alembic_config(c), revision))
            await conn.execute(text("SET LOCAL search_path TO public"))
            return list(await conn.scalar(text(backup._SCHEMA)))
        finally:
            await trans.rollback()


async def _wipe(engine: AsyncEngine) -> None:
    """The throwaway database emptied: its schema public dropped (tables, data, the extension) and made anew."""
    async with engine.begin() as conn:
        for stmt in backup.RESET.split("; "):
            await conn.execute(text(stmt.rstrip(";")))


async def _counts(engine: AsyncEngine, tables: list[str]) -> dict[str, int]:
    out = {}
    async with engine.connect() as conn:
        exists = set(await conn.scalars(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")))
        for t in tables:
            if t in exists:
                q = conn.dialect.identifier_preparer.quote(t)
                out[t] = int(await conn.scalar(text(f"SELECT count(*) FROM public.{q}")) or 0)  # noqa: S608 - a quoted name of the server's own list
    return out


def _classify(exc: backup.BackupError) -> str:
    msg = str(exc)
    if "rows differ" in msg:
        return "rows"
    if "does not make the schema" in msg:
        return "schema"
    if "no end within" in msg:
        return "timeout"
    return "restore"


# ---------------------------------------------------------------- the test


def _newest() -> dict | None:
    """The newest backup: by its time, then by when the file was written (two in one second: "-2" sorts before ".tar")."""
    d = get_config().backup_dir

    def key(x: dict) -> tuple:
        try:
            return (x["at"], (d / x["name"]).stat().st_mtime_ns)
        except OSError:
            return (x["at"], 0)

    return max(backup.listing(), key=key, default=None)


async def run(*, passphrase: str | None = None, trigger: str = "manual") -> dict:
    """One test of the newest backup (see the module text) – its outcome, also recorded. Never raises for a failed test."""
    cfg = get_config()
    phrase = cfg.backup_passphrase if passphrase is None else passphrase
    t0 = time.monotonic()
    out: dict = {"ok": False, "trigger": trigger, "started_at": datetime.now(UTC).isoformat(), "head": db.head()}
    lock_conn = None
    plan = None
    try:
        url = target()
        if url is None:
            raise Failed("not_configured", "no throwaway database set up (POSTGRES_RESTORE_PASSWORD, docs/BETRIEB.md: Rücksicherungs-Test)")
        app = cfg.database_url
        if _same_db(url, app) or (url.username or "") == (app.username or ""):
            raise Failed("unsafe", "the throwaway database must be another database with a role of its own")
        lock_conn = await db.engine().connect()
        if not await lock_conn.scalar(text("SELECT pg_try_advisory_lock(:k)"), {"k": LOCK}):
            raise Failed("busy", "another restore test is running")
        await lock_conn.commit()
        async with db.session() as s:
            if await backup.running(s):  # also from the host's cron: never beside a backup
                raise Failed("busy", "a backup is running – try again later")
        newest = _newest()
        if newest is None:
            raise Failed("no_backup", "there is no backup to test")
        out["name"] = newest["name"]
        out["encrypted"] = newest["encrypted"]
        if newest["encrypted"] and not phrase:
            raise Failed("passphrase", "the newest backup is encrypted and the app has no BACKUP_PASSPHRASE – run the test from the host (scripts/restore-test.sh)")
        async with asyncio.timeout(TIMEOUT_S):
            try:
                plan = await asyncio.to_thread(backup.prepare, get_config().backup_dir / newest["name"], phrase)
            except backup.BackupError as exc:
                raise Failed("verify", str(exc)) from exc
            m = plan.manifest
            out.update(auth=plan.auth, revision=m.get("revision"), backup_version=m.get("version"), backup_at=m.get("created_at"), key_matches=plan.key_matches)
            want = {str(k): int(v) for k, v in (m.get("rows") or {}).items()}
            engine = _engine(url)
            try:
                try:
                    async with engine.connect() as conn:
                        problems = await _guard(conn, app)
                except Exception as exc:  # noqa: BLE001 - cannot reach it: the outcome says so
                    raise Failed("connect", f"{type(exc).__name__}: {str(exc)[:200]}") from exc
                if problems:
                    raise Failed("unsafe", "; ".join(problems))
                try:
                    reference = await _reference(engine, str(m.get("revision")))
                    left = max(60.0, TIMEOUT_S - (time.monotonic() - t0))
                    await backup._pipe_restore(plan.work / "db.dump", want, reference, left, env=backup._pg_env(url, APP_NAME), low_priority=True)
                except backup.BackupError as exc:
                    raise Failed(_classify(exc), str(exc)) from exc
                async with engine.connect() as conn:
                    restored = await conn.scalar(text("SELECT version_num FROM alembic_version"))
                got = await _counts(engine, list(want))
                out.update(tables=len(want), rows=sum(got.values()), restored_revision=restored)
                diff = {t: [got.get(t), n] for t, n in want.items() if got.get(t) != n}
                if diff:
                    raise Failed("rows", f"rows differ from the backup: {dict(list(diff.items())[:5])}")
                if restored != m.get("revision"):
                    raise Failed("revision", f"schema revision {restored} after the restore, the backup says {m.get('revision')}")
            finally:
                with contextlib.suppress(Exception):
                    await _wipe(engine)
                await engine.dispose()
        out["ok"] = True
    except Failed as exc:
        out.update(code=exc.code, error=str(exc)[:500])
    except TimeoutError:
        out.update(code="timeout", error=f"no end within {int(TIMEOUT_S)} s")
    except Exception as exc:  # noqa: BLE001 - recorded, the app goes on
        log.exception("restore test failed")
        out.update(code="failed", error=f"{type(exc).__name__}: {str(exc)[:300]}")
    finally:
        if plan is not None:
            shutil.rmtree(plan.work, ignore_errors=True)
        if lock_conn is not None:
            try:
                await lock_conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": LOCK})
                await lock_conn.commit()
                await lock_conn.close()
            except Exception:  # noqa: BLE001 - never back into the pool still holding the lock
                with contextlib.suppress(Exception):
                    await lock_conn.invalidate()
    out["at"] = datetime.now(UTC).isoformat()
    out["seconds"] = round(time.monotonic() - t0, 1)
    if out.get("code") != "busy":  # refused because another one runs: that one's outcome counts
        await _record(out)
    if out["ok"]:
        log.info("restore test %s: passed (%s tables, %s rows, %.1f s)", out.get("name"), out.get("tables"), out.get("rows"), out["seconds"])
    else:
        log.warning("restore test %s: %s – %s", out.get("name") or "-", out.get("code"), out.get("error"))
    return out


def start(trigger: str = "manual") -> bool:
    """A test in the background of this process; False when one of its own is still running."""
    task = _job["task"]
    if task is not None and not task.done():
        return False

    async def go() -> None:
        try:
            await run(trigger=trigger)
        except Exception:  # noqa: BLE001 - never an unobserved task exception
            log.exception("restore test task failed")

    _job["task"], _job["since"] = asyncio.create_task(go(), name="restore-test"), datetime.now(UTC).isoformat()
    return True


class Loop:
    """The app's schedule (mode "app"): looks every CHECK_EVERY_S whether a test is due."""

    async def tick(self) -> bool:
        if target() is None:
            return False
        async with db.session() as s:
            conf = _conf(await settings_store.get(s, SECTION))
            if not conf["enabled"] or conf["mode"] != "app":
                return False
            last = await settings_store.get(s, LAST)
            if not due(conf, _parse(last.get("at")), datetime.now(UTC)):
                return False
            if await running(s) or await backup.running(s):
                return False  # the next look, ten minutes later
        return start("schedule")

    async def run(self) -> None:
        await asyncio.sleep(120)  # not in the first minutes after a start
        while True:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001 - one bad look must not end the loop
                log.exception("restore test schedule failed")
            await asyncio.sleep(CHECK_EVERY_S)


# ---------------------------------------------------------------- admin API (cookie, CSRF as usual)


@router.get("")
async def get_status(admin: Admin, db_: Db) -> dict:
    return await status(db_)


class SettingsIn(NoNul):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    mode: Literal["app", "host"]
    every_days: Literal[1, 7, 14, 30]
    hour: int
    rev: int | None = None


@router.put("")
async def put_settings(body: SettingsIn, admin: Admin, db_: Db) -> dict:
    if not 0 <= body.hour <= 23:
        raise api_error(422, "invalid", errors="hour 0–23")
    value = body.model_dump(exclude={"rev"})
    if changes := audit.diff(_conf(await settings_store.get(db_, SECTION)), value, value.keys()):
        audit.record(db_, admin, "settings.changed", audit.target("settings", SECTION, SECTION), {"changes": changes})
    await settings_store.put_rev(db_, SECTION, value, body.rev)
    return await status(db_)


@router.post("", status_code=202)
async def run_now(admin: Admin, db_: Db) -> dict:
    """A test now, in the background (GET tells when it is done). 409: one runs, a backup runs, or nothing is set up."""
    if target() is None:
        raise api_error(409, "restore_test_not_configured")
    if await running(db_) or await backup.running(db_):
        raise api_error(409, "restore_test_busy")
    audit.record(db_, admin, "restore_test.run", audit.target("restore_test", None, None), {"trigger": "manual", "newest": (_newest() or {}).get("name")})
    await db_.commit()
    start("manual")
    return {"started": True, "status": await status(db_)}

