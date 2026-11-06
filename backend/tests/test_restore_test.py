"""The restore test (app/restore_test.py) against a real throwaway database made by deploy/postgres/restore-role.sql
(as db-init makes it): the newest backup restored and checked there, never into the app's database – a target that is
the app's own database, a superuser or a role that may reach the app's database is refused before anything happens;
a damaged, foreign or encrypted backup without the passphrase fails with its reason; the throwaway database is empty
afterwards; the schedule (due, next run), the admin API and the outcome in /metrics."""

import os
import shutil
import subprocess
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg
import pytest
from sqlalchemy import func, select
from sqlalchemy.engine import make_url

from app import backup, db, metrics, restore_test
from app import settings as settings_store
from app.config import get_config
from app.models import NewsSource
from conftest import DATABASE_URL, TEST_DB, _admin_dsn

pytestmark = pytest.mark.skipif(shutil.which("pg_dump") is None or shutil.which("psql") is None, reason="needs the PostgreSQL 18 client tools")

ROOT = Path(__file__).resolve().parents[2]
ROLE, RDB = "cobe_news_restore", "cobe_news_restore_test"
RPASS = "restore-test-only-password-0123456789"  # test fixture only


def _psql_env(password: str) -> dict:
    u = DATABASE_URL
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    return {**env, "PGHOST": u.host, "PGPORT": str(u.port), "PGUSER": "postgres", "PGPASSWORD": make_url(_admin_dsn()).password or "", "PGDATABASE": TEST_DB, "POSTGRES_RESTORE_PASSWORD": password}


def _db_init() -> subprocess.CompletedProcess:
    """deploy/postgres/restore-role.sql exactly as db-init.sh runs it (the superuser, on the app's database)."""
    return subprocess.run(
        ["psql", "--no-psqlrc", "--quiet", "-v", "ON_ERROR_STOP=1", "-f", str(ROOT / "deploy/postgres/restore-role.sql")], env=_psql_env(RPASS), capture_output=True, text=True, check=False
    )


async def _admin(sql: str) -> None:
    conn = await asyncpg.connect(_admin_dsn())
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


@pytest.fixture(scope="module")
def throwaway():
    """The role and the database as db-init makes them – the app's (test) database closed to PUBLIC as app-role.sql does."""
    import asyncio

    asyncio.run(_admin(f"REVOKE ALL ON DATABASE {TEST_DB} FROM PUBLIC"))
    for _ in range(2):  # idempotent: every start runs it again
        r = _db_init()
        assert r.returncode == 0, r.stderr
    assert "cobe_news_restore ready" in r.stdout + r.stderr
    url = DATABASE_URL.set(username=ROLE, password=RPASS, database=RDB)
    yield url
    asyncio.run(_admin(f"DROP DATABASE IF EXISTS {RDB} WITH (FORCE)"))
    asyncio.run(_admin(f"DROP ROLE IF EXISTS {ROLE}"))


@pytest.fixture(autouse=True)
def backups_here(tmp_path):
    cfg = get_config()
    old = cfg.backup_dir, cfg.backup_passphrase, cfg.backup_passphrase_file
    object.__setattr__(cfg, "backup_dir", tmp_path / "backups")
    object.__setattr__(cfg, "backup_passphrase", "")
    object.__setattr__(cfg, "backup_passphrase_file", "")
    metrics.reset()
    yield tmp_path / "backups"
    object.__setattr__(cfg, "backup_dir", old[0])
    object.__setattr__(cfg, "backup_passphrase", old[1])
    object.__setattr__(cfg, "backup_passphrase_file", old[2])


@pytest.fixture
def target(throwaway, monkeypatch):
    monkeypatch.setattr(restore_test, "target", lambda: throwaway)
    return throwaway


async def _tables_in(url) -> list[str]:  # noqa: ANN001
    conn = await asyncpg.connect(url.set(drivername="postgresql").render_as_string(hide_password=False))
    try:
        return [r[0] for r in await conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")]
    finally:
        await conn.close()


async def _last() -> dict:
    async with db.session() as s:
        return await settings_store.get(s, restore_test.LAST)


# ---------------------------------------------------------------- the throwaway database itself


async def test_the_role_cannot_reach_the_app_database(throwaway):
    """What db-init made: the role owns its database only – the server refuses it the app's database."""
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await asyncpg.connect(throwaway.set(drivername="postgresql", database=TEST_DB).render_as_string(hide_password=False))
    conn = await asyncpg.connect(throwaway.set(drivername="postgresql").render_as_string(hide_password=False))
    try:
        r = await conn.fetchrow("SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user")
        assert tuple(r) == (False, False, False)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("CREATE DATABASE cn_should_not_exist")
    finally:
        await conn.close()


async def test_db_init_refuses_a_role_that_could_reach_the_app_database(throwaway):
    await _admin(f"GRANT CONNECT ON DATABASE {TEST_DB} TO PUBLIC")
    try:
        r = _db_init()  # revokes the role's own grant – PUBLIC's would still let it in: refused
        assert r.returncode != 0 and "refused" in r.stdout + r.stderr
    finally:
        await _admin(f"REVOKE ALL ON DATABASE {TEST_DB} FROM PUBLIC")
    assert _db_init().returncode == 0


# ---------------------------------------------------------------- a test that passes


async def test_newest_backup_restored_checked_and_emptied(target):
    async with db.session() as s:
        n_sources = int(await s.scalar(select(func.count()).select_from(NewsSource)))
    await backup.create()
    res = await backup.create()  # the newest is tested
    out = await restore_test.run(trigger="manual")
    assert out["ok"], out
    assert out["name"] == res.name and out["auth"] == "signature" and out["revision"] == out["restored_revision"] == db.head()
    assert out["rows"] == sum(res.rows.values()) and out["rows"] >= n_sources and out["tables"] == len(res.rows)
    assert await _tables_in(target) == []  # emptied again
    last = await _last()
    assert last["ok"] and last["trigger"] == "manual" and last["seconds"] >= 0
    async with db.session() as s:
        st = await restore_test.status(s)
    assert st["configured"] and st["last"]["ok"] and st["target"] == {"database": RDB, "user": ROLE} and not st["running"]


async def test_encrypted_backup_needs_the_passphrase(target, backups_here):
    await backup.create(passphrase="eine-lange-test-passphrase")
    out = await restore_test.run()
    assert not out["ok"] and out["code"] == "passphrase"
    out = await restore_test.run(passphrase="eine-falsche-passphrase!")
    assert not out["ok"] and out["code"] == "verify" and "decrypt" in out["error"]
    out = await restore_test.run(passphrase="eine-lange-test-passphrase", trigger="cli")
    assert out["ok"] and out["auth"] == "passphrase" and out["trigger"] == "cli", out


async def test_the_app_opens_an_encrypted_backup_with_its_passphrase_file(target, backups_here, tmp_path):
    """BACKUP_PASSPHRASE_FILE (0.1.50): the app's own test decrypts with the file; a file it cannot read is the reason
    the test names."""
    await backup.create(passphrase="eine-lange-test-passphrase")
    f = tmp_path / "backup-pass"
    f.write_text("eine-lange-test-passphrase\n")
    object.__setattr__(get_config(), "backup_passphrase_file", str(f))
    out = await restore_test.run()
    assert out["ok"] and out["auth"] == "passphrase", out
    object.__setattr__(get_config(), "backup_passphrase_file", str(tmp_path / "fehlt"))
    out = await restore_test.run()
    assert not out["ok"] and out["code"] == "passphrase" and "not found" in out["error"], out


async def test_damaged_backup_fails_and_changes_nothing(target, backups_here):
    res = await backup.create()
    raw = bytearray(res.path.read_bytes())
    with tarfile.open(res.path) as tf:
        off = next(m for m in tf.getmembers() if m.name == "db.dump").offset_data
    raw[off + 200] ^= 0xFF
    res.path.write_bytes(bytes(raw))
    out = await restore_test.run()
    assert not out["ok"] and out["code"] == "verify" and "checksum" in out["error"]
    assert await _tables_in(target) == []


async def test_rows_that_differ_from_the_manifest_fail(target, monkeypatch):
    await backup.create()
    real = backup.prepare

    def lying(*a, **kw):
        plan = real(*a, **kw)
        plan.manifest["rows"]["news_sources"] += 1
        return plan

    monkeypatch.setattr(backup, "prepare", lying)
    out = await restore_test.run()
    assert not out["ok"] and out["code"] == "rows" and "news_sources" in out["error"]
    assert await _tables_in(target) == []  # the restore's transaction rolled back, the database emptied


async def test_no_backup_and_not_configured(monkeypatch, throwaway):
    monkeypatch.setattr(restore_test, "target", lambda: None)
    out = await restore_test.run()
    assert out["code"] == "not_configured"
    monkeypatch.setattr(restore_test, "target", lambda: throwaway)
    out = await restore_test.run()
    assert out["code"] == "no_backup"


# ---------------------------------------------------------------- never the real database


async def test_the_app_database_is_never_a_target(monkeypatch):
    await backup.create()
    monkeypatch.setattr(restore_test, "target", lambda: DATABASE_URL)
    out = await restore_test.run()
    assert not out["ok"] and out["code"] == "unsafe"
    async with db.session() as s:
        assert int(await s.scalar(select(func.count()).select_from(NewsSource))) > 0  # untouched


async def test_a_superuser_target_is_refused(monkeypatch):
    """Another database, but a superuser (could reach anything): the server's answer refuses it before any restore."""
    await backup.create()
    other = f"{TEST_DB}_other"
    await _admin(f"CREATE DATABASE {other}")
    try:
        monkeypatch.setattr(restore_test, "target", lambda: DATABASE_URL.set(database=other, username="postgres"))
        cfg = get_config()
        old = cfg.db_url
        # the app's role must differ from the target's (same role: refused by name) – pretend the app has its own
        object.__setattr__(cfg, "db_url", DATABASE_URL.set(username="cobe_news_app_x").render_as_string(hide_password=False))
        try:
            out = await restore_test.run()
        finally:
            object.__setattr__(cfg, "db_url", old)
        assert not out["ok"] and out["code"] == "unsafe" and "superuser" in out["error"], out
    finally:
        await _admin(f"DROP DATABASE IF EXISTS {other} WITH (FORCE)")


async def test_guard_names_every_reason(throwaway):
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(DATABASE_URL)  # the superuser on the app's database
    try:
        async with eng.connect() as conn:
            bad = await restore_test._guard(conn, DATABASE_URL.set(username="someone"))
    finally:
        await eng.dispose()
    text = " | ".join(bad)
    assert "app's own database" in text and "superuser" in text and "create roles or databases" in text
    eng = restore_test._engine(throwaway)
    try:
        async with eng.connect() as conn:
            assert await restore_test._guard(conn, DATABASE_URL) == []
    finally:
        await eng.dispose()


# ---------------------------------------------------------------- when


def _at(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 11, day, hour, minute, tzinfo=UTC)


def test_due_only_in_the_window_and_after_the_period():
    conf = restore_test._conf({})
    assert conf == {"enabled": True, "mode": "app", "every_days": 7, "hour": 3}
    assert restore_test.due(conf, None, _at(1, 3, 10))
    assert restore_test.due(conf, None, _at(1, 5, 59))
    assert not restore_test.due(conf, None, _at(1, 6))
    assert not restore_test.due(conf, None, _at(1, 2, 59))
    last = _at(1, 3, 10)
    assert not restore_test.due(conf, last, _at(2, 3, 10))
    assert restore_test.due(conf, last, _at(8, 3, 0))  # a week later, also a little earlier in the window
    assert restore_test.next_at(conf, last, _at(2, 12)) == _at(8, 3)
    assert restore_test.next_at(conf, None, _at(1, 12)) == _at(2, 3)
    late = restore_test._conf({"hour": 23})
    assert restore_test.due(late, None, _at(2, 1))  # the window runs past midnight
    assert restore_test._conf({"every_days": 5, "hour": 25, "mode": "x"}) == {"enabled": True, "mode": "app", "every_days": 7, "hour": 1}


async def test_schedule_runs_only_when_due(target, monkeypatch):
    started = []
    monkeypatch.setattr(restore_test, "start", lambda trigger="manual": started.append(trigger) or True)
    monkeypatch.setattr(restore_test, "due", lambda conf, last, now: True)
    assert await restore_test.Loop().tick() and started == ["schedule"]
    async with db.session() as s:
        await settings_store.put(s, restore_test.SECTION, {"mode": "host"})
        await s.commit()
    assert not await restore_test.Loop().tick()
    async with db.session() as s:
        await settings_store.put(s, restore_test.SECTION, {"mode": "app", "enabled": False})
        await s.commit()
    assert not await restore_test.Loop().tick()
    monkeypatch.setattr(restore_test, "target", lambda: None)
    async with db.session() as s:
        await settings_store.put(s, restore_test.SECTION, {})
        await s.commit()
    assert not await restore_test.Loop().tick() and started == ["schedule"]


# ---------------------------------------------------------------- admin API and metrics


async def test_admin_api(admin_client, reader_client, target, monkeypatch):
    assert (await reader_client.get("/api/admin/restore-test")).status_code == 403
    st = (await admin_client.get("/api/admin/restore-test")).json()
    assert st["configured"] and st["enabled"] and st["mode"] == "app" and st["every_days"] == 7 and st["last"] is None and st["next_at"]
    r = await admin_client.put("/api/admin/restore-test", json={"enabled": True, "mode": "host", "every_days": 14, "hour": 4, "rev": st["rev"]})
    assert r.status_code == 200 and r.json()["mode"] == "host" and r.json()["next_at"] is None
    r = await admin_client.put("/api/admin/restore-test", json={"enabled": True, "mode": "app", "every_days": 14, "hour": 4, "rev": st["rev"]})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "stale"
    for bad in ({"every_days": 5}, {"hour": 24}, {"mode": "cron"}):
        body = {"enabled": True, "mode": "app", "every_days": 7, "hour": 3, **bad}
        assert (await admin_client.put("/api/admin/restore-test", json=body)).status_code == 422
    started = []
    monkeypatch.setattr(restore_test, "start", lambda trigger="manual": started.append(trigger) or True)
    r = await admin_client.post("/api/admin/restore-test")
    assert r.status_code == 202 and started == ["manual"]
    monkeypatch.setattr(restore_test, "target", lambda: None)
    r = await admin_client.post("/api/admin/restore-test")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "restore_test_not_configured"


async def test_metrics_show_the_outcome(admin_client, target):
    await backup.create()
    await restore_test.run()
    token = (await admin_client.post("/api/admin/api-tokens", json={"name": "Prometheus", "scopes": ["metrics"]})).json()["token"]
    import httpx

    from app.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://news.test") as c:
        body = (await c.get("/metrics", headers={"Authorization": f"Bearer {token}"})).text
    assert "\ncobe_news_restore_test_last_ok 1\n" in body and "\ncobe_news_restore_test_configured 1\n" in body
    assert "\ncobe_news_backup_files 1\n" in body and "\ncobe_news_backup_last_ok 1\n" in body


def test_cli_reads_the_passphrase_from_stdin(monkeypatch):
    """scripts/restore-test.sh hands the passphrase over on standard input – never on a command line."""
    import io

    from app import cli

    monkeypatch.setattr("sys.stdin", io.StringIO("geheim-aus-der-datei\n"))
    assert cli._passphrase(["--passphrase-file", "-"]) == "geheim-aus-der-datei"


async def test_cli_exit_codes(target, capsys, monkeypatch):
    from app import cli

    monkeypatch.setattr(os, "nice", lambda n: 0)  # the CLI lowers its own priority – not the test run's

    assert await cli._restore_test([]) == 1  # no backup yet
    assert "FAILED (no_backup)" in capsys.readouterr().out
    await backup.create()
    assert await cli._restore_test([]) == 0
    assert "Restore test passed" in capsys.readouterr().out
    assert (await _last())["trigger"] == "cli"
