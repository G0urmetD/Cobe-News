"""The audit log's database lock (0.1.52, deploy/postgres/audit-lock.sql, app/audit_lock.py) on a database of its own,
set up exactly as the database image does it: app-role.sql and audit-lock.sql run by psql as the superuser, the app as
cobe_news_app. Locked, PostgreSQL itself lets the app only add, read and seal entries – UPDATE, DELETE, TRUNCATE, DROP
and ALTER are refused; the prune deletes only what is past the retention (never younger than 90 days) and still
writes its anchor; a restore sets the old entries aside instead of deleting them and leaves the lock in place; the
migrations run beside the locked table. Without the image (the plain test database) nothing changes: the lock is
shown as not set up."""

import logging
import os
import re
import secrets
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg
import pytest
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url

from app import audit, audit_lock, backup, cli, db, main
from app import settings as settings_store
from app.config import get_config
from app.models import AuditEntry, User
from conftest import DATABASE_URL, TEST_DB, _admin_dsn

pytestmark = pytest.mark.skipif(shutil.which("pg_dump") is None or shutil.which("psql") is None, reason="needs the PostgreSQL 18 client tools")

ROOT = Path(__file__).resolve().parents[2]
LOCK_DB = f"cn_lock_{secrets.token_hex(3)}"
APP_PW = "app-role-test-only-password-0123456789"  # test fixture only
APP_URL = DATABASE_URL.set(username="cobe_news_app", password=APP_PW, database=LOCK_DB)


def _psql(sql_file: str, database: str = LOCK_DB) -> subprocess.CompletedProcess:
    """A file of deploy/postgres exactly as db-init.sh runs it: psql as the superuser on the app's database."""
    u = make_url(_admin_dsn())
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    env.update(PGHOST=u.host or "localhost", PGPORT=str(u.port or 5432), PGUSER=u.username or "", PGPASSWORD=u.password or "", PGDATABASE=database, POSTGRES_APP_PASSWORD=APP_PW)
    r = subprocess.run(["psql", "--no-psqlrc", "--quiet", "-v", "ON_ERROR_STOP=1", "-f", str(ROOT / "deploy/postgres" / sql_file)], env=env, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    return r


async def _admin(sql: str, database: str = "postgres") -> None:
    conn = await asyncpg.connect(make_url(_admin_dsn()).set(database=database).render_as_string(hide_password=False))
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


def _dsn(url) -> str:  # noqa: ANN001
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


async def _use(url) -> None:  # noqa: ANN001
    cfg = get_config()
    object.__setattr__(cfg, "db_url", url.render_as_string(hide_password=False))
    await db.dispose()
    db.init(url)


@pytest.fixture(scope="module")
def lock_db():
    """A new database as the image sets it up: the first start before the app made its tables (only the role and the
    functions), the app migrates as cobe_news_app, the next start locks the table – run twice, it changes nothing."""
    import asyncio

    asyncio.run(_admin(f"CREATE DATABASE {LOCK_DB} TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER builtin BUILTIN_LOCALE 'C.UTF-8'"))
    first = _psql("app-role.sql").stdout + _psql("audit-lock.sql").stdout
    assert "lock follows once the app has made the table" in first

    async def migrate_as_app() -> dict:
        db.init(APP_URL)
        try:
            async with db.engine().connect() as conn:
                pending = await audit_lock.state(conn)
            await db.migrate()
            return pending
        finally:
            await db.dispose()

    pending = asyncio.run(migrate_as_app())
    assert pending["reason"] == "pending" and not pending["active"]
    for _ in range(2):  # every start runs both again
        out = _psql("app-role.sql").stdout + _psql("audit-lock.sql").stdout
        assert "audit log locked" in out
    yield APP_URL
    asyncio.run(_admin(f"DROP DATABASE IF EXISTS {LOCK_DB} WITH (FORCE)"))
    asyncio.run(_admin("DROP ROLE IF EXISTS cobe_news_app"))
    asyncio.run(_admin("DROP ROLE IF EXISTS cobe_news_audit"))


@pytest.fixture
async def locked(lock_db, tmp_path):
    """The app on the locked database (its audit log, archive and users emptied first – by the lock's own role, the
    only one that may delete there), its backups in a folder of its own; afterwards back on the test database."""
    cfg = get_config()
    old = cfg.db_url, cfg.backup_dir, cfg.backup_passphrase, cfg.backup_passphrase_file
    await _admin(
        "SET ROLE cobe_news_audit; DELETE FROM public.audit_log; DELETE FROM cobe_news_audit.audit_log_replaced; RESET ROLE; "
        "DELETE FROM users; DELETE FROM settings WHERE key IN ('audit', 'audit_chain')",
        LOCK_DB,
    )
    object.__setattr__(cfg, "backup_dir", tmp_path / "backups")
    object.__setattr__(cfg, "backup_passphrase", "")
    object.__setattr__(cfg, "backup_passphrase_file", "")
    await _use(lock_db)
    yield lock_db
    await db.dispose()
    object.__setattr__(cfg, "db_url", old[0])
    object.__setattr__(cfg, "backup_dir", old[1])
    object.__setattr__(cfg, "backup_passphrase", old[2])
    object.__setattr__(cfg, "backup_passphrase_file", old[3])
    db.init(DATABASE_URL)


async def _write(n: int, *, days_ago: float = 0, action: str = "settings.changed") -> list[int]:
    async with db.session() as s:
        got = []
        for i in range(n):
            e = audit.record(s, audit.SYSTEM, action, audit.target("settings", f"s{i}", f"Abschnitt {i}"), {"i": i})
            e.at = datetime.now(UTC) - timedelta(days=days_ago) + timedelta(seconds=i)
            got.append(e)
        await s.commit()
        return [e.id for e in got]


async def _ids() -> list[int]:
    async with db.session() as s:
        return list(await s.scalars(select(AuditEntry.id).order_by(AuditEntry.id)))


async def _refused(conn, sql: str) -> str:  # noqa: ANN001
    with pytest.raises(asyncpg.PostgresError) as exc:
        await conn.execute(sql)
    return str(exc.value)


async def _state() -> dict:
    async with db.engine().connect() as conn:
        return await audit_lock.state(conn)


# ---------------------------------------------------------------- the lock itself


async def test_db_init_locks_the_table_and_the_app_says_so(locked, caplog):
    conn = await asyncpg.connect(_dsn(make_url(_admin_dsn()).set(database=LOCK_DB)))
    try:
        owners = dict(await conn.fetch("SELECT c.relname, pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relname LIKE '%audit_log%'"))
        public = await conn.fetchval("SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'")
        others = await conn.fetchval("SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner <> 'cobe_news_app' AND tablename <> 'audit_log'")
    finally:
        await conn.close()
    assert set(owners.values()) == {"cobe_news_audit"} and {"audit_log", "audit_log_id_seq", "ix_audit_log_search"} <= set(owners)
    assert public == "cobe_news_audit" and others == 0  # every other table stays the app's (app-role.sql leaves the lock alone)
    st = await _state()
    assert st == {"active": True, "reason": None, "set_aside": 0, "set_aside_at": None}
    with caplog.at_level(logging.INFO, logger="cobe_news"):
        assert (await main.log_audit_lock())["active"]
    assert "audit log: database lock active" in caplog.text
    async with db.session() as s:
        out = await audit.verify(s)
    assert out["lock"]["active"] is True
    # a superuser connection on the locked database: nothing holds it back – shown as not active
    await _use(make_url(_admin_dsn()).set(drivername="postgresql+asyncpg", database=LOCK_DB))
    assert (await _state())["reason"] == "superuser"


async def test_the_app_adds_reads_and_seals_but_never_changes_or_deletes(locked):
    ids = await _write(3)
    assert await audit.seal_all() == 3  # sealing: an UPDATE of the chain's columns of an unsealed entry
    await _write(1)
    conn = await asyncpg.connect(_dsn(locked))
    try:
        assert await conn.fetchval("SELECT count(*) FROM audit_log") == 4
        assert await conn.fetchval("SELECT current_user") == "cobe_news_app"
        for sql in (
            f"UPDATE audit_log SET details = '{{\"i\": 99}}' WHERE id = {ids[0]}",  # the content of a sealed entry
            f"UPDATE audit_log SET hash = 'x' WHERE id = {ids[0]}",  # the seal itself
            "UPDATE audit_log SET details = details || '{\"x\": 1}', seq = 99 WHERE seq IS NULL",  # sealing that changes the content
        ):
            assert "locked" in await _refused(conn, sql)
        assert "permission denied" in await _refused(conn, f"UPDATE audit_log SET at = now() WHERE id = {ids[0]}")
        assert "permission denied" in await _refused(conn, f"DELETE FROM audit_log WHERE id = {ids[0]}")
        assert "permission denied" in await _refused(conn, "TRUNCATE audit_log")
        assert "must be owner" in await _refused(conn, "DROP TABLE audit_log")
        assert "must be owner" in await _refused(conn, "DROP SCHEMA public CASCADE")
        assert "must be owner" in await _refused(conn, "ALTER TABLE audit_log DISABLE TRIGGER ALL")
        assert "must be owner" in await _refused(conn, "ALTER TABLE audit_log OWNER TO cobe_news_app")
        assert "must be owner" in await _refused(conn, "ALTER SCHEMA public RENAME TO elsewhere")
        assert "permission denied" in await _refused(conn, "CREATE TRIGGER t BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION cobe_news_audit.guard()")
        assert "permission denied" in await _refused(conn, "DELETE FROM cobe_news_audit.audit_log_replaced")
        assert "permission denied" in await _refused(conn, "SELECT setval('audit_log_id_seq', 1)")
        assert "permission denied" in await _refused(conn, "SET session_replication_role = replica")
        # the lock's function deletes only what is past the retention – never younger than 90 days, whatever is asked
        assert "prune refused" in await _refused(conn, "SELECT cobe_news_audit.prune(1000000, 1)")
        # its own tables it still makes and drops (migrations), in the schema it no longer owns
        await conn.execute("CREATE TABLE zz_mine (a int); DROP TABLE zz_mine")
        assert await conn.fetchval("SELECT count(*) FROM audit_log") == 4
    finally:
        await conn.close()
    async with db.session() as s:
        assert (await audit.verify(s))["state"] == "ok"  # nothing changed behind the chain's back


async def test_sealing_may_add_a_mark_but_not_take_one_away(locked):
    await _write(1, days_ago=1)
    late = await _write(1, days_ago=2)  # well before the previous one: sealed with the mark "late_entry"
    await audit.seal_all()
    async with db.session() as s:
        e = await s.get(AuditEntry, late[0])
        assert e.notable and "late_entry" in e.details["anomalies"]
    conn = await asyncpg.connect(_dsn(locked))
    try:
        await conn.execute("INSERT INTO audit_log (at, actor_kind, actor_name, actor_display, action, details, notable) VALUES (now(), 'system', 'system', '', 'x', '{}', true)")
        assert "locked" in await _refused(conn, "UPDATE audit_log SET seq = 999, notable = false WHERE seq IS NULL")
    finally:
        await conn.close()


async def test_a_table_with_someone_elses_trigger_is_not_taken_over(lock_db):
    """A trigger (or rule, row security) the app put on audit_log before the lock – its function would run as the lock's
    role: audit-lock.sql refuses the hand-over, says why, and leaves everything as it was (not locked, shown as such)."""
    name = f"cn_lockodd_{secrets.token_hex(3)}"
    await _admin(f"CREATE DATABASE {name} TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER builtin BUILTIN_LOCALE 'C.UTF-8'")
    url = APP_URL.set(database=name)
    try:
        _psql("app-role.sql", name)
        await _use(url)
        await db.migrate()
        await _admin("CREATE FUNCTION public.zz() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NEW; END $f$", name)
        await _admin("ALTER FUNCTION public.zz() OWNER TO cobe_news_app", name)
        conn = await asyncpg.connect(_dsn(url))
        try:
            await conn.execute("CREATE TRIGGER zz_planted BEFORE DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION zz()")
        finally:
            await conn.close()
        out = _psql("audit-lock.sql", name).stdout
        assert "audit log NOT locked" in out and "zz_planted" in out
        st = await _state()
        assert st["reason"] == "pending" and not st["active"]
        async with db.engine().connect() as conn:
            assert await conn.scalar(text("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public.audit_log'::regclass")) == "cobe_news_app"
            assert await conn.scalar(text("SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'")) != "cobe_news_audit"
    finally:
        await db.dispose()
        object.__setattr__(get_config(), "db_url", DATABASE_URL.render_as_string(hide_password=False))
        await _admin(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        db.init(DATABASE_URL)


# ---------------------------------------------------------------- prune


async def test_prune_deletes_only_old_entries_and_writes_the_anchor(locked, monkeypatch):
    monkeypatch.setattr(audit, "PRUNE_BATCH", 3)  # batches, each through the lock's function
    async with db.session() as s:
        await settings_store.put(s, audit.SECTION, {"keep_days": 365})
        await s.commit()
    old = await _write(7, days_ago=400)
    young = await _write(3, days_ago=100)
    async with db.session() as s:
        assert await audit.prune(s) == 7
    async with db.session() as s:
        left = list(await s.scalars(select(AuditEntry).order_by(AuditEntry.seq)))
        pruned = [e for e in left if e.action == "audit.pruned"]
        out = await audit.verify(s)
    assert [e.id for e in left if e.action == "settings.changed"] == young and not set(old) & {e.id for e in left}
    assert len(pruned) == 1 and pruned[0].details["anchor_seq"] == 7  # the anchor declared before anything went
    assert out["state"] == "ok" and out["anchor_seq"] == 7 and out["problems"] == []
    # the database itself refuses what the app's own check would not let through either
    conn = await asyncpg.connect(_dsn(locked))
    try:
        top = await conn.fetchval("SELECT max(seq) FROM audit_log WHERE action = 'settings.changed'")
        assert "not all older than 365 days" in await _refused(conn, f"SELECT cobe_news_audit.prune({top}, 365)")
    finally:
        await conn.close()


async def test_the_floor_lets_through_what_is_past_90_days(locked):
    await _write(2, days_ago=95)
    await _write(1, days_ago=10)
    await audit.seal_all()
    conn = await asyncpg.connect(_dsn(locked))
    try:
        assert await conn.fetchval("SELECT cobe_news_audit.prune(2, 1)") == 2  # asked for 1 day: deleted are those past 90
        assert "prune refused" in await _refused(conn, "SELECT cobe_news_audit.prune(3, 1)")
        assert await conn.fetchval("SELECT count(*) FROM audit_log") == 1
    finally:
        await conn.close()


# ---------------------------------------------------------------- restore


async def test_restore_sets_the_old_entries_aside_and_keeps_the_lock(locked):
    async with db.session() as s:
        s.add(User(username="anna", display_name="Anna", role="admin", auth_source="local"))
        await s.commit()
    kept = await _write(3)
    await audit.seal_all()
    res = await backup.create()
    after = await _write(2)  # written after the backup: not in it – set aside by the restore, never deleted
    async with db.session() as s:
        s.add(User(username="bert", display_name="Bert", role="reader", auth_source="local"))
        await s.commit()
    before = await _ids()
    plan = backup.prepare(res.path, "")
    try:
        rows = await backup.restore(plan)
    finally:
        shutil.rmtree(plan.work)
    assert rows == plan.manifest["rows"]
    assert set(kept) <= set(await _ids()) and not set(after) & set(await _ids())
    async with db.session() as s:
        assert list(await s.scalars(select(User.username))) == ["anna"]
    st = await _state()
    assert st["active"] and st["set_aside"] == len(before) and st["set_aside_at"]
    conn = await asyncpg.connect(_dsn(locked))
    try:
        aside = [r["id"] for r in await conn.fetch("SELECT id FROM cobe_news_audit.audit_log_replaced ORDER BY id")]
        assert aside == before  # every entry as it was, the ones after the backup too
        assert "permission denied" in await _refused(conn, "DELETE FROM audit_log")
    finally:
        await conn.close()
    assert await db.revision() == db.head()
    new = await _write(1)  # the sequence is behind the restored ids
    assert new[0] > max(kept)
    async with db.session() as s:
        assert (await audit.verify(s))["state"] == "ok"


async def test_a_failed_restore_changes_nothing_also_not_the_log(locked):
    await _write(2)
    res = await backup.create()
    await _write(1)
    before = await _ids()
    plan = backup.prepare(res.path, "")
    try:
        plan.manifest["rows"]["users"] = 99  # rows that differ: the check inside the transaction rolls it all back
        with pytest.raises(backup.BackupError, match="rows differ"):
            await backup.restore(plan)
    finally:
        shutil.rmtree(plan.work)
    assert await _ids() == before
    st = await _state()
    assert st["active"] and st["set_aside"] == 0


async def test_a_backup_of_the_plain_database_restores_into_the_locked_one(locked, monkeypatch, capsys):
    """A backup from before the lock (or of an install without the image) – the CLI's restore, as an operator runs it."""
    await _use(DATABASE_URL)
    async with db.session() as s:
        s.add(User(username="carla", display_name="Carla", role="admin", auth_source="local"))
        await s.commit()
    await _write(4)
    await audit.seal_all()
    res = await backup.create()
    await _use(locked)

    async def nobody() -> int:
        return 0

    monkeypatch.setattr(backup, "others_connected", nobody)
    assert await cli._restore([str(res.path), "--yes"]) == 0
    # the locked log held the entry of the backup made right before the restore (backup.created): set aside
    assert re.search(r"database lock still active – 1 entry of the log before set aside", capsys.readouterr().out)
    async with db.session() as s:
        assert list(await s.scalars(select(User.username))) == ["carla"]
        actions = list(await s.scalars(select(AuditEntry.action).order_by(AuditEntry.id)))
        assert actions[:4] == ["settings.changed"] * 4 and actions[-1] == "backup.restored"
        restored = await s.scalar(select(AuditEntry).where(AuditEntry.action == "backup.restored"))
        assert restored.details["set_aside"] == 1
        assert (await audit.verify(s))["state"] == "ok"
    assert (await _state())["active"]


async def test_a_backup_of_the_locked_database_restores_where_there_is_no_lock(locked):
    """The restore test's throwaway database, a new server without the image: the table comes from the dump, the
    lock's triggers and schema never do."""
    await _write(3)
    await audit.seal_all()
    res = await backup.create()
    plan = backup.prepare(res.path, "")
    try:
        toc = (plan.work / "toc.list").read_text()
        assert "cobe_news_audit_lock" not in toc and "FUNCTION" not in toc and "audit_log_replaced" not in toc
        await _use(DATABASE_URL)
        await backup.restore(plan)
    finally:
        shutil.rmtree(plan.work)
    async with db.engine().connect() as conn:
        assert await conn.scalar(select(func.count()).select_from(AuditEntry)) == 3
        assert await conn.scalar(text("SELECT count(*) FROM pg_trigger WHERE tgrelid = 'public.audit_log'::regclass AND NOT tgisinternal")) == 0
        assert (await audit_lock.state(conn))["reason"] == "no_lock"


# ---------------------------------------------------------------- migrations


async def test_migrations_run_beside_the_locked_table(locked, caplog):
    """Down and up again (in a transaction, rolled back): the migrations that touch audit_log leave the locked table
    alone, the others run; and from scratch beside it – a restore's reference schema – they make the very schema there is."""
    from alembic import command

    with caplog.at_level(logging.INFO, logger="cobe_news.audit"):
        async with db.engine().connect() as conn:
            trans = await conn.begin()
            try:
                await conn.run_sync(lambda c: command.downgrade(db.alembic_config(c), "0016"))
                assert await conn.scalar(text("SELECT version_num FROM alembic_version")) == "0016"
                await conn.run_sync(lambda c: command.upgrade(db.alembic_config(c), "head"))
                assert await conn.scalar(text("SELECT version_num FROM alembic_version")) == db.head()
            finally:
                await trans.rollback()
    assert "migration 0032: audit_log is locked" in caplog.text and "migration 0017: audit_log is locked" in caplog.text
    reference = await backup.reference_schema(db.head(), locked=True)
    async with db.engine().connect() as conn:
        await conn.execute(text("SET search_path TO public"))
        assert await conn.scalar(text(backup._SCHEMA)) == reference
    assert (await _state())["active"]


async def test_an_install_from_before_the_chain_is_locked_and_migrates(lock_db):
    """An install at revision 0031 (0.1.49: audit_log without the chain's columns) updates straight to this image: the
    database starts first (audit-lock.sql brings the table to the shape of 0032/0033 and locks it – before, its GRANT
    on the missing column `seq` failed and db-init stopped the database at every start), then the app migrates
    beside the locked table and ends with the very schema of a fresh install."""
    name = f"cn_lock_old_{secrets.token_hex(3)}"
    url = APP_URL.set(database=name)
    old_url = get_config().db_url
    await _admin(f"CREATE DATABASE {name} TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER builtin BUILTIN_LOCALE 'C.UTF-8'")
    try:
        _psql("app-role.sql", name)
        await _use(url)
        await db.migrate("0031")
        await db.dispose()
        conn = await asyncpg.connect(_dsn(url))
        try:
            await conn.execute(
                "INSERT INTO audit_log (at, actor_kind, actor_name, actor_display, action, details) VALUES "
                "(now(), 'system', 'system', '', 'role.changed', '{}'), (now(), 'system', 'system', '', 'settings.changed', '{}')"
            )
        finally:
            await conn.close()
        out = _psql("app-role.sql", name).stdout + _psql("audit-lock.sql", name).stdout
        assert "shape of migration 0032" in out and "audit log locked" in out
        assert "audit log locked" in _psql("audit-lock.sql", name).stdout  # the next start: nothing more to add
        await _use(url)
        await db.migrate()
        async with db.engine().connect() as conn:
            assert (await audit_lock.state(conn))["active"]
            assert list(await conn.execute(text("SELECT action, notable FROM audit_log ORDER BY id"))) == [("role.changed", True), ("settings.changed", False)]
            await conn.execute(text("SET search_path TO public"))
            got = await conn.scalar(text(backup._SCHEMA))
        await _write(1)
        await audit.seal_all()
        async with db.session() as s:
            assert await s.scalar(select(func.count()).select_from(AuditEntry).where(AuditEntry.seq.is_(None))) == 0
        await _use(lock_db)  # a fresh install, locked
        async with db.engine().connect() as conn:
            await conn.execute(text("SET search_path TO public"))
            assert await conn.scalar(text(backup._SCHEMA)) == got
    finally:
        await db.dispose()
        object.__setattr__(get_config(), "db_url", old_url)
        db.init(DATABASE_URL)
        await _admin(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


async def test_the_documented_unlock_and_the_next_start_locks_again(locked):
    """docs/BETRIEB.md (Datenbank-Sperre, Aufheben): the superuser's three statements – the app owns the log again and
    may delete; the next start of the database (audit-lock.sql) locks it again."""
    await _write(2)
    await _admin("ALTER TABLE public.audit_log OWNER TO cobe_news_app; ALTER SCHEMA public OWNER TO pg_database_owner; DROP SCHEMA cobe_news_audit CASCADE", LOCK_DB)
    assert (await _state())["reason"] == "no_lock"
    conn = await asyncpg.connect(_dsn(locked))
    try:
        assert await conn.execute("DELETE FROM audit_log") == "DELETE 2"
        assert await conn.fetchval("SELECT count(*) FROM pg_trigger WHERE tgrelid = 'public.audit_log'::regclass AND NOT tgisinternal") == 0
    finally:
        await conn.close()
    assert "audit log locked" in _psql("app-role.sql").stdout + _psql("audit-lock.sql").stdout
    assert (await _state())["active"]


async def test_set_aside_outside_a_restore_warns(locked):
    """The app may call set_aside() at any time (only a restore does): nothing is deleted, and PostgreSQL warns."""
    await _write(2)
    conn = await asyncpg.connect(_dsn(locked))
    got: list = []
    conn.add_log_listener(lambda _c, msg: got.append(msg))
    try:
        async with conn.transaction():
            assert await conn.fetchval("SELECT cobe_news_audit.set_aside()") == 2
            assert await conn.fetchval("SELECT count(*) FROM cobe_news_audit.audit_log_replaced") == 2
            raise asyncpg.PostgresError("roll back")
    except asyncpg.PostgresError:
        pass
    finally:
        await conn.close()
    assert any(m.severity == "WARNING" and "set_aside() moved 2 audit log entries" in m.message for m in got), got
    assert len(await _ids()) == 2  # rolled back: where they were


# ---------------------------------------------------------------- the database itself (owned by the app)


async def test_the_app_cannot_drop_its_database_from_another_one(lock_db):
    """The app owns its database – DROP DATABASE needs a connection to another one, and app-role.sql closes postgres and
    template1 to PUBLIC: no way to drop it with the app's password (the current one cannot be dropped)."""
    for other in ("postgres", "template1"):
        with pytest.raises(asyncpg.InsufficientPrivilegeError, match="permission denied for database"):
            await asyncpg.connect(_dsn(lock_db.set(database=other)))
    conn = await asyncpg.connect(_dsn(lock_db))
    try:
        assert "currently open database" in await _refused(conn, f"DROP DATABASE {LOCK_DB} WITH (FORCE)")
        assert not await conn.fetchval("SELECT has_database_privilege('postgres', 'CONNECT') OR has_database_privilege('template1', 'CONNECT')")
    finally:
        await conn.close()


async def test_a_search_path_the_app_sets_never_runs_its_code_as_the_superuser(lock_db):
    """As the database's owner the app may set a search_path for it (ALTER DATABASE … SET) that puts a function of its
    own before pg_catalog – db-init (as the superuser, at every start) and a superuser's psql must never call it."""
    app = await asyncpg.connect(_dsn(lock_db))
    try:
        await app.execute(
            "CREATE SCHEMA trap; CREATE TABLE trap.hits (who text); GRANT USAGE ON SCHEMA trap TO PUBLIC; GRANT INSERT, SELECT ON trap.hits TO PUBLIC; "
            "CREATE FUNCTION trap.pg_get_userbyid(oid) RETURNS name LANGUAGE sql AS $$ INSERT INTO trap.hits VALUES (current_user) RETURNING 'x'::name $$; "
            f"ALTER DATABASE {LOCK_DB} SET search_path = trap, pg_catalog, public"
        )
        assert await app.fetchval("SELECT count(*) FROM trap.hits") == 0
    finally:
        await app.close()
    try:
        # a database from before this version: no setting of the superuser's role in it yet – the files pin their own
        await _admin("ALTER ROLE CURRENT_USER IN DATABASE " + LOCK_DB + " RESET search_path", LOCK_DB)
        for f in ("app-role.sql", "audit-lock.sql"):  # the next start of the database
            _psql(f)
        su = await asyncpg.connect(_dsn(make_url(_admin_dsn()).set(database=LOCK_DB)))
        try:
            assert await su.fetchval("SELECT count(*) FROM trap.hits") == 0
            # a superuser's own session: the role's setting in this database comes first (only a superuser sets it)
            assert await su.fetchval("SHOW search_path") == "pg_catalog, public"
            assert await su.fetchval("SELECT pg_get_userbyid(10)") != "x"
        finally:
            await su.close()
    finally:
        app = await asyncpg.connect(_dsn(lock_db))
        try:
            await app.execute(f"ALTER DATABASE {LOCK_DB} RESET search_path; DROP SCHEMA trap CASCADE")
        finally:
            await app.close()


# ---------------------------------------------------------------- without the image


async def test_without_the_image_nothing_changes(admin_client, caplog):
    """The plain test database (no lock): the prune deletes as before, the page and the log say "not set up"."""
    async with db.engine().connect() as conn:
        st = await audit_lock.state(conn)
        assert not await audit_lock.installed(conn)
    assert st == {"active": False, "reason": "no_lock", "set_aside": 0, "set_aside_at": None}
    with caplog.at_level(logging.INFO, logger="cobe_news"):
        await main.log_audit_lock()
    assert "database lock NOT active: not set up" in caplog.text
    r = await admin_client.get("/api/admin/audit/chain")
    assert r.status_code == 200 and r.json()["lock"]["reason"] == "no_lock"
    await _write(2, days_ago=400)
    async with db.session() as s:
        assert await audit.prune(s) == 2
    async with db.session() as s:
        await s.execute(text("UPDATE audit_log SET details = '{}'"))  # nothing in the database refuses it here
        await s.rollback()
    assert TEST_DB  # the conftest's own database
