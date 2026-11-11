"""Backup, restore and export (app/backup.py, admin API): the dump and its counts from one snapshot, the master key only
in an encrypted backup, a damaged or foreign backup refused before anything changes, a restore that brings back exactly
what was saved, the retention, and an export without any secret. Needs pg_dump / pg_restore / psql 18 (the image has
them; on a developer machine e.g. Homebrew's postgresql@18)."""

import asyncio
import csv
import hashlib
import io
import json
import os
import secrets
import subprocess
import shutil
import tarfile
import tracemalloc
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg

import pytest
from conftest import DATABASE_URL, _admin_dsn, add_user
from sqlalchemy import func, insert, select, update
from sqlalchemy.engine import make_url

from app import backup, cli, crypto, db
from app import settings as settings_store
from app.config import get_config
from app.crypto import encrypt_str
from app.auth import sessions
from app.models import AuditEntry, NewsItem, NewsSource, NotifyChannel, NotifyRule, NotifyRuleChannel, RememberedDevice, User, UserSession, VendorFollow, VendorVersion

pytestmark = pytest.mark.skipif(shutil.which("pg_dump") is None or shutil.which("psql") is None, reason="needs the PostgreSQL 18 client tools")


@pytest.fixture(autouse=True)
def backups_here(tmp_path):
    """Each test's backups in a folder of its own (the config is frozen: set and put back)."""
    cfg = get_config()
    old = cfg.backup_dir, cfg.backup_passphrase, cfg.backup_passphrase_file
    object.__setattr__(cfg, "backup_dir", tmp_path / "backups")
    object.__setattr__(cfg, "backup_passphrase", "")
    object.__setattr__(cfg, "backup_passphrase_file", "")
    yield tmp_path / "backups"
    object.__setattr__(cfg, "backup_dir", old[0])
    object.__setattr__(cfg, "backup_passphrase", old[1])
    object.__setattr__(cfg, "backup_passphrase_file", old[2])


async def _sources() -> int:
    async with db.session() as s:
        return int(await s.scalar(select(func.count()).select_from(NewsSource)))


async def test_backup_has_the_dump_its_counts_and_no_key(backups_here):
    res = await backup.create()
    assert res.path.parent == backups_here and res.path.name.endswith(".tar") and res.path.stat().st_mode & 0o777 == 0o600
    with tarfile.open(res.path) as tf:
        assert sorted(tf.getnames()) == ["db.dump", "manifest.json", "manifest.sig"]  # no secrets.json: the key is not in it
        manifest = json.loads(tf.extractfile("manifest.json").read())
    assert manifest["rows"]["news_sources"] == await _sources() and manifest["revision"] == db.head() and manifest["with_key"] is False
    assert manifest["key_id"] == crypto.key_id() and len(manifest["files"]["db.dump"]["sha256"]) == 64
    assert not any(p.name.startswith(".") for p in backups_here.iterdir())  # no work folder left behind
    assert [x["name"] for x in backup.listing()] == [res.name]


async def test_encrypted_backup_carries_the_key_and_needs_the_passphrase(backups_here):
    res = await backup.create(passphrase="eine lange Passphrase")
    assert res.path.name.endswith(".tar.enc") and crypto.is_sealed(res.path)
    raw = res.path.read_bytes()
    assert b"manifest" not in raw and crypto.master() not in raw  # nothing readable without the passphrase
    with pytest.raises(backup.BackupError, match="cannot decrypt"):
        backup.prepare(res.path, "falsch")
    with pytest.raises(backup.BackupError, match="encrypted"):
        backup.prepare(res.path, "")
    plan = backup.prepare(res.path, "eine lange Passphrase")
    try:
        assert plan.key_matches and plan.backup_key == crypto.master().decode()
    finally:
        shutil.rmtree(plan.work)


async def test_a_cut_off_or_changed_backup_is_refused(backups_here):
    res = await backup.create(passphrase="pp-lang-genug")
    data = res.path.read_bytes()
    cut = backups_here / "cobe-news-20200101-000000.tar.enc"
    cut.write_bytes(data[: len(data) - 40])
    with pytest.raises(backup.BackupError, match="cannot decrypt"):
        backup.prepare(cut, "pp-lang-genug")
    plain = await backup.create()
    work = backups_here / "x"
    work.mkdir()
    with tarfile.open(plain.path) as tf:
        tf.extractall(work, filter="data")
    dump = work / "db.dump"
    dump.write_bytes(dump.read_bytes()[:-10] + b"0123456789")
    bad = backups_here / "cobe-news-20200101-000001.tar"
    with tarfile.open(bad, "w") as tf:
        tf.add(work / "manifest.json", "manifest.json")
        tf.add(dump, "db.dump")
    with pytest.raises(backup.BackupError, match="checksum"):
        backup.prepare(bad, "")


async def test_restore_brings_back_exactly_what_was_saved(backups_here):
    async with db.session() as s:
        s.add(User(username="anna", display_name="Anna", role="admin", auth_source="local"))
        await s.commit()
    res = await backup.create()
    async with db.session() as s:  # changed after the backup: gone again after the restore
        s.add(User(username="bert", display_name="Bert", role="reader", auth_source="local"))
        await s.execute(NewsSource.__table__.delete().where(NewsSource.key == "heise"))
        await s.commit()
    plan = backup.prepare(res.path, "")
    try:
        rows = await backup.restore(plan)
    finally:
        shutil.rmtree(plan.work)
    assert rows == plan.manifest["rows"]
    async with db.session() as s:
        assert sorted(await s.scalars(select(User.username))) == ["anna"]
        assert await s.scalar(select(NewsSource.id).where(NewsSource.key == "heise")) is not None
    assert await db.revision() == db.head()


async def test_restore_streams_the_dump_instead_of_holding_it_in_memory(backups_here):
    """Bug hunt 0.1.16 H1: pg_restore's SQL went through Python's memory as one piece (a big database killed the 512m
    app container). Now it is piped through in small chunks: Python's own allocations stay far below the dump's size."""
    async with db.session() as s:
        sid = await s.scalar(select(NewsSource.id).where(NewsSource.key == "heise"))
        now = datetime.now(UTC)
        blob = secrets.token_hex(15_000)  # 30 kB of text per story that does not compress well: ~18 MB of SQL
        rows = [
            {"id": uuid.uuid4(), "source_id": sid, "url": f"https://news.example/{i}", "url_key": uuid.uuid4().hex, "title": "t", "title_key": uuid.uuid4().hex,
             "summary": "", "content_html": blob, "published_at": now, "fetched_at": now, "severity": "info", "reasons": [], "cves": [], "also_in": [],
             "backlog": True, "search": "t", "seq": i}
            for i in range(600)
        ]  # fmt: skip
        await s.execute(insert(NewsItem), rows)
        await s.commit()
    res = await backup.create()
    plan = backup.prepare(res.path, "")
    tracemalloc.start()
    try:
        await backup.restore(plan)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        shutil.rmtree(plan.work)
    assert peak < 6 * 1024 * 1024, f"restore held {peak / 1e6:.1f} MB in Python"
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(NewsItem)) == 600


async def test_restore_whose_counts_do_not_match_changes_nothing(backups_here):
    """The row check runs inside the restore's transaction: a mismatch rolls everything back (before: restored, then
    "rows differ")."""
    res = await backup.create()
    async with db.session() as s:
        s.add(User(username="bert", display_name="Bert", role="reader", auth_source="local"))
        await s.commit()
    plan = backup.prepare(res.path, "")
    plan.manifest["rows"]["news_sources"] += 1
    try:
        with pytest.raises(backup.BackupError, match="nothing changed"):
            await backup.restore(plan)
    finally:
        shutil.rmtree(plan.work)
    async with db.session() as s:
        assert sorted(await s.scalars(select(User.username))) == ["bert"]  # the state before the restore is still there


async def test_restore_into_a_fresh_empty_database(backups_here, monkeypatch):
    """Bug hunt 0.1.16 H2: a new server – an empty database, the app never started. The restore needs no schema there
    (before: "relation counters does not exist"), makes no backup of nothing and brings everything back."""
    async with db.session() as s:
        s.add(User(username="anna", display_name="Anna", role="admin", auth_source="local"))
        await s.commit()
    res = await backup.create()
    name = f"cn_fresh_{secrets.token_hex(3)}"
    conn = await asyncpg.connect(_admin_dsn())
    await conn.execute(f"CREATE DATABASE {name} TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER builtin BUILTIN_LOCALE 'C.UTF-8'")
    await conn.close()
    cfg = get_config()
    old = cfg.db_url
    url = DATABASE_URL.set(database=name)
    try:
        object.__setattr__(cfg, "db_url", url.render_as_string(hide_password=False))
        await db.dispose()
        db.init(url)

        async def nobody() -> int:
            return 0

        monkeypatch.setattr(backup, "others_connected", nobody)
        assert await cli._restore([str(res.path), "--yes", "--allow-superuser"]) == 0
        assert [x["name"] for x in backup.listing()] == [res.name]  # no pre-restore backup of an empty database
        async with db.session() as s:
            assert sorted(await s.scalars(select(User.username))) == ["anna"]
        assert await db.revision() == db.head()
    finally:
        object.__setattr__(cfg, "db_url", old)
        await db.dispose()
        conn = await asyncpg.connect(_admin_dsn())
        await conn.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        await conn.close()
        db.init(DATABASE_URL)


async def test_a_backup_of_another_installation_is_flagged(backups_here, monkeypatch):
    res = await backup.create()
    monkeypatch.setattr(crypto, "key_id", lambda: "0" * 16)
    with pytest.raises(backup.BackupError, match="another master key"):  # its signature cannot be checked here
        backup.prepare(res.path, "")
    plan = backup.prepare(res.path, "", allow_unsigned=True)
    try:
        assert not plan.key_matches and plan.backup_key is None and plan.auth == "other-key"
    finally:
        shutil.rmtree(plan.work)


async def test_retention_keeps_the_newest(backups_here):
    backups_here.mkdir(exist_ok=True)
    for i in range(1, 6):
        (backups_here / f"cobe-news-2026010{i}-000000.tar").write_bytes(b"x")
    (backups_here / "notes.txt").write_text("not a backup")
    assert backup.prune(2) == ["cobe-news-20260103-000000.tar", "cobe-news-20260102-000000.tar", "cobe-news-20260101-000000.tar"]
    assert sorted(p.name for p in backups_here.iterdir()) == ["cobe-news-20260104-000000.tar", "cobe-news-20260105-000000.tar", "notes.txt"]


async def test_two_backups_in_one_second_do_not_overwrite_each_other(backups_here):
    a, b = await backup.create(), await backup.create()
    assert a.name != b.name and a.path.is_file() and b.path.is_file()


# ---------------------------------------------------------------- admin API


async def _done(c) -> dict:  # noqa: ANN001
    """The status once the background backup started by POST /backup has finished."""
    for _ in range(200):
        st = (await c.get("/api/admin/backup")).json()
        if not st["running"]:
            return st
        await asyncio.sleep(0.05)
    raise AssertionError("backup did not finish")


async def test_backup_api_for_admins_only(admin_client, reader_client, backups_here):
    assert (await reader_client.get("/api/admin/backup")).status_code == 403
    assert (await reader_client.post("/api/admin/backup")).status_code == 403
    r = await admin_client.get("/api/admin/backup")
    assert r.status_code == 200 and r.json()["last"] is None and r.json()["keep"] == 7 and r.json()["with_key"] is False and r.json()["running"] is False
    r = await admin_client.post("/api/admin/backup")
    assert r.status_code == 202 and r.json()["started"] is True, r.text
    st = await _done(admin_client)
    assert st["last"]["ok"] and [x["name"] for x in st["backups"]] == [st["last"]["name"]]
    r = await admin_client.put("/api/admin/backup", json={"keep": 3, "rev": st["rev"]})
    assert r.status_code == 200 and r.json()["keep"] == 3
    assert (await admin_client.put("/api/admin/backup", json={"keep": 7, "rev": st["rev"]})).json()["detail"]["code"] == "stale"
    assert (await admin_client.put("/api/admin/backup", json={"keep": 5})).status_code == 422


async def test_backup_now_answers_at_once_and_runs_in_the_background(admin_client, backups_here, monkeypatch):
    """Bug hunt 0.1.16 M16: "Jetzt sichern" waited for pg_dump – longer than the proxy waits (504 while the backup went
    on). Now the request starts it and answers 202; the page asks until "running" is over."""
    gate = asyncio.Event()
    real = backup._run

    async def slow(*args, **kw):  # noqa: ANN002, ANN003
        await gate.wait()
        return await real(*args, **kw)

    monkeypatch.setattr(backup, "_run", slow)
    r = await admin_client.post("/api/admin/backup")
    assert r.status_code == 202 and r.json()["status"]["running"] is True and r.json()["status"]["running_since"]
    assert (await admin_client.post("/api/admin/backup")).json()["detail"]["code"] == "backup_busy"  # one at a time
    gate.set()
    st = await _done(admin_client)
    assert st["last"]["ok"] is True and len(st["backups"]) == 1


async def test_a_refused_parallel_backup_is_not_the_last_outcome(admin_client, backups_here):
    """Bug hunt 0.1.16 L4: a backup refused because another one runs (e.g. the cron job) was recorded as "failed" – the
    page showed red while the first was still running. Now the refusal is not recorded, and the page sees the running
    one (its lock)."""
    first = await backup.create()
    conn = await asyncpg.connect(DATABASE_URL.set(drivername="postgresql").render_as_string(hide_password=False))
    try:
        await conn.execute("SELECT pg_advisory_lock($1)", backup.BACKUP_LOCK)  # as the CLI / cron would hold it
        with pytest.raises(backup.BackupError, match="busy"):
            await backup.create()
        st = (await admin_client.get("/api/admin/backup")).json()
        assert st["running"] is True and st["last"]["ok"] is True and st["last"]["name"] == first.name
        assert (await admin_client.post("/api/admin/backup")).json()["detail"]["code"] == "backup_busy"
    finally:
        await conn.close()
    assert (await admin_client.get("/api/admin/backup")).json()["running"] is False


async def test_a_failed_backup_is_shown_as_the_last_one(admin_client, backups_here, monkeypatch):
    monkeypatch.setattr(backup.shutil, "which", lambda name: None)
    assert (await admin_client.post("/api/admin/backup")).status_code == 202
    last = (await _done(admin_client))["last"]
    assert last["ok"] is False and last["code"] == "no_pg_dump" and "pg_dump" in last["error"]


async def test_fewer_backups_and_the_export_need_a_fresh_confirmation(admin_client, backups_here):
    """Security review L1: lowering the retention deletes backups at once (also the way back before a restore), the
    export holds every user's name and e-mail – both now need the re-confirmation like the user administration."""
    async with db.session() as s:
        await s.execute(update(UserSession).values(reauth_at=datetime.now(UTC) - timedelta(hours=1)))
        await s.commit()
    st = (await admin_client.get("/api/admin/backup")).json()
    r = await admin_client.put("/api/admin/backup", json={"keep": 3, "rev": st["rev"]})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    r = await admin_client.put("/api/admin/backup", json={"keep": 14, "rev": st["rev"]})
    assert r.status_code == 200  # keeping more deletes nothing
    r = await admin_client.get("/api/admin/export?format=json")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"


async def test_a_short_passphrase_is_refused(backups_here):
    """Security review L12: scrypt slows guessing down, but a short passphrase still falls."""
    with pytest.raises(backup.BackupError, match="too short"):
        await backup.create(passphrase="kurz")
    assert backup.listing() == []


async def test_encrypted_backups_use_the_stronger_scrypt_and_old_ones_still_open(backups_here):
    """Security review L12: new files (CNBK2) derive their key with scrypt N=2^17; files of up to 0.1.23 (CNBK1, 2^15)
    still decrypt."""
    res = await backup.create(passphrase="eine lange Passphrase")
    assert res.path.read_bytes()[:6] == b"CNBK2\n"
    old = backups_here / "cobe-news-20200101-000000.tar.enc"
    salt, prefix = b"s" * 16, b"p" * 7
    header = crypto.SEAL_MAGIC_V1 + salt + prefix
    aead = crypto._passphrase_key("pp-alt-und-lang", salt, crypto.SEAL_MAGIC_V1)
    old.write_bytes(header + aead.encrypt(prefix + (0).to_bytes(4, "big") + b"\x01", b"inhalt", header))
    out = io.BytesIO()
    with old.open("rb") as f:
        crypto.open_sealed(f, out, "pp-alt-und-lang")
    assert out.getvalue() == b"inhalt"


async def _with_secrets() -> None:
    async with db.session() as s:
        ch = NotifyChannel(name="=Ops", type="slack", config={}, secrets={"url": encrypt_str("https://hooks.slack.com/services/T/B/geheim")})
        rule = NotifyRule(name="Kritisch", severities=["critical"], sources=[], kinds=["news"])
        s.add_all([ch, rule])
        await s.flush()
        s.add(NotifyRuleChannel(rule_id=rule.id, channel_id=ch.id))
        f = VendorFollow(product="fortios", note="RZ Nord", tags=["fw"])
        s.add(f)
        await s.flush()
        s.add(VendorVersion(follow_id=f.id, version="7.4.8", label="RZ"))
        s.add(User(username="berta", display_name="Berta", role="admin", auth_source="local", password_hash="$argon2id$geheim", totp_secret_enc=encrypt_str("TOTPSEED")))
        await s.commit()


async def test_export_without_any_secret(admin_client, reader_client):
    await _with_secrets()
    assert (await reader_client.get("/api/admin/export")).status_code == 403
    r = await admin_client.get("/api/admin/export?format=json")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    body = r.text
    for secret in ("geheim", "v1:", "TOTPSEED", "argon2", "hooks.slack.com"):
        assert secret not in body
    data = r.json()
    assert data["rules"][0]["channels"] == ["=Ops"] and data["channels"][0]["secrets_set"] == ["url"]
    assert data["follows"][0]["versions"] == [{"version": "7.4.8", "label": "RZ", "count": None}]
    assert {u["username"]: u["totp"] for u in data["users"]}["berta"] is True


async def test_csv_export_is_a_zip_without_formulas(admin_client):
    await _with_secrets()
    r = await admin_client.get("/api/admin/export?format=csv")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    assert sorted(zf.namelist()) == ["channels.csv", "follows.csv", "rules.csv", "sources.csv", "users.csv"]
    channels = list(csv.DictReader(io.StringIO(zf.read("channels.csv").decode("utf-8-sig"))))
    assert channels[0]["name"] == "'=Ops"  # a spreadsheet does not run it as a formula
    follows = list(csv.DictReader(io.StringIO(zf.read("follows.csv").decode("utf-8-sig"))))
    assert follows[0]["product"] == "fortios" and follows[0]["version"] == "7.4.8" and follows[0]["tags"] == "fw"
    assert b"geheim" not in r.content and b"TOTPSEED" not in r.content


# ---------------------------------------------------------------- a backup someone else made (security review M2)


def _pg_env_admin() -> dict:
    u = DATABASE_URL
    return {**os.environ, "PGHOST": u.host, "PGPORT": str(u.port), "PGUSER": "postgres", "PGPASSWORD": make_url(_admin_dsn()).password or ""}


async def _crafted(backups_here, sql: str, name: str = "cobe-news-20200101-000000.tar", *, sign: bool = True) -> Path:
    """A genuine backup, its dump changed by `sql` (as an attacker would: restored elsewhere, changed, dumped again)
    and packed again with a correct manifest – signed with this installation's key when `sign` (to test the checks
    behind the signature), else unsigned."""
    res = await backup.create()
    work = backups_here.parent / f"craft-{secrets.token_hex(3)}"
    work.mkdir()
    with tarfile.open(res.path) as tf:
        tf.extractall(work, filter="data")
    scratch = f"cn_craft_{secrets.token_hex(3)}"
    env = _pg_env_admin()
    conn = await asyncpg.connect(_admin_dsn())
    await conn.execute(f"CREATE DATABASE {scratch} TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER builtin BUILTIN_LOCALE 'C.UTF-8'")
    await conn.close()
    try:
        subprocess.run(["pg_restore", "--no-owner", "--no-privileges", f"--dbname={scratch}", str(work / "db.dump")], env=env, check=True, capture_output=True)
        subprocess.run(["psql", "-v", "ON_ERROR_STOP=1", "-q", f"--dbname={scratch}", "-c", sql], env=env, check=True, capture_output=True)
        subprocess.run(["pg_dump", "--format=custom", "--no-owner", "--no-privileges", f"--file={work / 'db.dump'}", scratch], env=env, check=True, capture_output=True)
    finally:
        conn = await asyncpg.connect(_admin_dsn())
        await conn.execute(f"DROP DATABASE IF EXISTS {scratch} WITH (FORCE)")
        await conn.close()
    manifest = json.loads((work / "manifest.json").read_text())
    dump = work / "db.dump"
    manifest["files"]["db.dump"] = {"sha256": hashlib.sha256(dump.read_bytes()).hexdigest(), "size": dump.stat().st_size}
    raw = json.dumps(manifest).encode()
    (work / "manifest.json").write_bytes(raw)
    (work / "manifest.sig").unlink()
    if sign:
        (work / "manifest.sig").write_text(json.dumps({"key_id": crypto.key_id(), "mac": crypto.backup_mac(raw)}))
    out = backups_here / name
    with tarfile.open(out, "w") as tf:
        for n in ("manifest.json", "manifest.sig", "db.dump"):
            if (work / n).is_file():
                tf.add(work / n, n)
    shutil.rmtree(work)
    return out


async def _users() -> list[str]:
    async with db.session() as s:
        return sorted(await s.scalars(select(User.username)))


async def test_an_unsigned_unencrypted_backup_is_refused_unless_allowed(backups_here):
    """Security review M2: an unencrypted backup proves nothing by itself (its checksums sit in the same file). It
    must carry this installation's signature; a file without one needs --allow-unsigned."""
    bad = await _crafted(backups_here, "SELECT 1", sign=False)
    with pytest.raises(backup.BackupError, match="no signature.*--allow-unsigned"):
        backup.prepare(bad, "")
    plan = backup.prepare(bad, "", allow_unsigned=True)
    shutil.rmtree(plan.work)
    assert plan.auth == "unsigned"


async def test_a_backup_changed_after_signing_is_refused(backups_here):
    res = await backup.create()
    work = backups_here.parent / "w"
    work.mkdir()
    with tarfile.open(res.path) as tf:
        tf.extractall(work, filter="data")
    manifest = json.loads((work / "manifest.json").read_text())
    manifest["rows"]["users"] = 99
    (work / "manifest.json").write_text(json.dumps(manifest))
    bad = backups_here / "cobe-news-20200101-000003.tar"
    with tarfile.open(bad, "w") as tf:
        for n in ("manifest.json", "manifest.sig", "db.dump"):
            tf.add(work / n, n)
    with pytest.raises(backup.BackupError, match="signature does not match"):
        backup.prepare(bad, "", allow_unsigned=True)  # a wrong signature is never overridden


async def test_a_dump_with_a_function_and_trigger_is_refused_before_anything_changes(backups_here):
    """The PoC of the review: a function (COPY … TO PROGRAM) called from a CHECK constraint. The table of contents
    holds a FUNCTION – refused before the database is touched, even when signed."""
    async with db.session() as s:
        s.add(User(username="anna", display_name="Anna", role="admin", auth_source="local"))
        await s.commit()
    sql = (
        "CREATE FUNCTION public.pwn(int) RETURNS int LANGUAGE plpgsql AS $f$ BEGIN RETURN $1; END $f$;"
        "CREATE TABLE public.zz_note (a int CHECK (public.pwn(a) = a)); INSERT INTO public.zz_note VALUES (1);"
    )
    bad = await _crafted(backups_here, sql)
    with pytest.raises(backup.BackupError, match="objects Cobe News never makes"):
        backup.prepare(bad, "")
    assert await _users() == ["anna"]


async def test_a_dump_that_changes_the_schema_is_rolled_back(backups_here):
    """Behind the table of contents: a dump whose entries are of the allowed kinds but change the schema (a default
    that is no Cobe News default, an extra check) – the schema check inside the restore's transaction rolls it all
    back."""
    async with db.session() as s:
        s.add(User(username="anna", display_name="Anna", role="admin", auth_source="local"))
        await s.commit()
    bad = await _crafted(backups_here, "ALTER TABLE public.users ADD CONSTRAINT zz_check CHECK (length(username) < 500); ALTER TABLE public.users ALTER COLUMN role SET DEFAULT 'admin'")
    async with db.session() as s:
        s.add(User(username="bert", display_name="Bert", role="reader", auth_source="local"))
        await s.commit()
    plan = backup.prepare(bad, "")
    try:
        with pytest.raises(backup.BackupError, match="does not make the schema.*zz_check"):
            await backup.restore(plan)
    finally:
        shutil.rmtree(plan.work)
    assert await _users() == ["anna", "bert"]  # nothing changed


async def test_a_dump_that_makes_another_schema_is_refused(backups_here):
    bad = await _crafted(backups_here, "CREATE SCHEMA evil")
    with pytest.raises(backup.BackupError, match="objects Cobe News never makes"):
        backup.prepare(bad, "")


@pytest.mark.parametrize("kind", ["symlink", "duplicate", "big-manifest", "unknown-file", "sparse"])
async def test_the_archive_itself_is_checked_strictly(backups_here, kind):
    """Security review M2/L14: only the known plain files, each once, within their sizes; the manifest lists only
    them (no absolute path as a hash oracle)."""
    res = await backup.create()
    work = backups_here.parent / f"w-{kind}"
    work.mkdir()
    with tarfile.open(res.path) as tf:
        tf.extractall(work, filter="data")
    bad = backups_here / "cobe-news-20200101-000004.tar"
    with tarfile.open(bad, "w", format=tarfile.GNU_FORMAT) as tf:
        for n in ("manifest.json", "manifest.sig", "db.dump"):
            if not (kind == "big-manifest" and n == "manifest.json"):
                tf.add(work / n, n)
        if kind == "symlink":
            ti = tarfile.TarInfo("secrets.json")
            ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tf.addfile(ti)
        elif kind == "duplicate":
            tf.add(work / "db.dump", "db.dump")
        elif kind == "big-manifest":
            data = (work / "manifest.json").read_bytes() + b" " * (2 << 20)
            ti = tarfile.TarInfo("manifest.json")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        elif kind == "unknown-file":
            m = json.loads((work / "manifest.json").read_text())
            m["files"]["/etc/hostname"] = {"sha256": "0" * 64, "size": 1}
            (work / "m2").write_text(json.dumps(m))
            tf.add(work / "m2", "secrets.json")
        elif kind == "sparse":
            ti = tarfile.TarInfo("secrets.json")
            ti.type, ti.size = tarfile.GNUTYPE_SPARSE, 0
            tf.addfile(ti)
    with pytest.raises(backup.BackupError):
        backup.prepare(bad, "", allow_unsigned=True)


async def test_restore_keeps_the_backup_it_restores_and_its_way_back(backups_here, monkeypatch):
    """Bug hunt 0.1.16 M2: the backup made before a restore counted against the retention and removed the oldest
    kept backup – the very file being restored. Now it is never pruned right then, and not counted for 30 days."""
    async with db.session() as s:
        await settings_store.put(s, backup.SECTION, {"keep": 3})
        await s.commit()
    # a session and a remembered device of the backup's time: gone after the restore (0.1.56)
    u = await add_user("tina")
    async with db.session() as s:
        await sessions.create(s, await s.get(User, u.id), "active", "127.0.0.1", "pytest")
        s.add(RememberedDevice(user_id=u.id, token_hash="h" * 64, factor="f", expires_at=datetime.now(UTC) + timedelta(days=1)))
        await s.commit()
    res = await backup.create()
    oldest = backups_here / "cobe-news-20260101-000000.tar"
    os.replace(res.path, oldest)
    for d in ("20260102", "20260103"):
        shutil.copy(oldest, backups_here / f"cobe-news-{d}-000000.tar")

    async def nobody() -> int:
        return 0

    monkeypatch.setattr(backup, "others_connected", nobody)
    # the tests connect as a superuser: refused without --allow-superuser, nothing changed
    assert await cli._restore([str(oldest), "--yes"]) == 1
    assert not any("-pre-restore" in p.name for p in backups_here.iterdir())
    assert await cli._restore([str(oldest), "--yes", "--allow-superuser"]) == 0
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(UserSession)) == 0
        assert await s.scalar(select(func.count()).select_from(RememberedDevice)) == 0
        e = await s.scalar(select(AuditEntry).where(AuditEntry.action == "backup.restored"))
        assert e.details["sessions_ended"] == 1 and e.details["devices_forgotten"] == 1
    names = sorted(p.name for p in backups_here.iterdir())
    assert oldest.name in names and any("-pre-restore" in n for n in names)
    async with db.session() as s:  # bug hunt L3: the last backup is the one made before the restore, not the restored one's note
        last = await settings_store.get(s, backup.LAST)
    assert last["ok"] and "-pre-restore" in last["name"]
    await backup.create()  # the next backup prunes to 3 regular ones – the pre-restore one stays
    names = [x["name"] for x in backup.listing()]
    assert sum("-pre-restore" in n for n in names) == 1 and len(names) == 4


async def test_leftovers_of_a_killed_backup_are_swept(backups_here):
    """Bug hunt 0.1.16 M1: a killed backup or restore left the dump and (encrypted) the master key in plain text in
    BACKUP_DIR – copied off the host by the rsync in docs/BETRIEB.md. Work folders are now outside BACKUP_DIR, and leftovers
    older than any backup are removed (next backup, restore, app start)."""
    backups_here.mkdir(exist_ok=True)
    old = backups_here / ".partial-abc"
    old.mkdir()
    (old / "secrets.json").write_text("{}")
    half = backups_here / "cobe-news-20200101-000000.tar.enc.partial"
    half.write_bytes(b"x")
    fresh = backups_here / ".restore-new"
    fresh.mkdir()
    for f in (old / "secrets.json", old, half):
        os.utime(f, (0, 0))
    res = await backup.create(passphrase="eine lange Passphrase")
    assert not old.exists() and not half.exists() and fresh.exists()  # a running one (fresh) is left alone
    assert sorted(p.name for p in backups_here.iterdir()) == sorted([res.name, ".restore-new"])


def test_listing_two_backups_of_one_second_newest_first(backups_here):
    """Two backups in the same second (a backup right before a restore gets "-2"): by name "-2" sorted after the first
    one, so prune and "the newest" took the older. Now by time, then by when the file was written."""
    backups_here.mkdir(exist_ok=True)
    first = backups_here / "cobe-news-20261030-120000.tar"
    second = backups_here / "cobe-news-20261030-120000-2.tar"
    older = backups_here / "cobe-news-20261029-120000.tar"
    for i, f in enumerate((older, first, second)):
        f.write_bytes(b"x")
        os.utime(f, ns=(1_000_000_000 * (i + 1), 1_000_000_000 * (i + 1)))
    assert [x["name"] for x in backup.listing()] == [second.name, first.name, older.name]


# ---------------------------------------------------------------- the key file (no SECRET_KEY)


@pytest.fixture
def key_file(tmp_path, monkeypatch):
    """crypto with DATA_DIR = tmp_path and no SECRET_KEY."""
    import dataclasses

    c = dataclasses.replace(get_config(), secret_key="", data_dir=tmp_path)
    monkeypatch.setattr(crypto, "get_config", lambda: c)
    monkeypatch.setattr(crypto, "KEY_FILE_WAIT", 0.6)
    crypto.reset_cache()
    yield tmp_path / crypto.KEY_FILE
    crypto.reset_cache()


def test_key_file_made_once_and_read_again(key_file):
    key = crypto.master()
    assert len(key) == 44 and key_file.read_bytes() == key and (key_file.stat().st_mode & 0o777) == 0o600
    crypto.reset_cache()
    assert crypto.master() == key


@pytest.mark.parametrize("content", [b"", b"\n", b"   \n", b"short"])
def test_an_empty_or_cut_key_file_is_never_used(key_file, content):
    """An empty secret.key (killed or a full disk between creating and writing it) was read as the key b"": HKDF takes
    it, and every secret, token MAC and backup signature rested on a key anybody knows."""
    key_file.write_bytes(content)
    with pytest.raises(crypto.KeyFileError):
        crypto.master()
    with pytest.raises(crypto.KeyFileError):
        crypto.encrypt_str("https://hooks.slack.com/services/T/B/x")
    assert key_file.read_bytes() == content  # left as it is – the operator decides


def test_a_new_key_file_is_never_seen_empty(key_file, monkeypatch):
    """0.1.52: the key is written to a temporary file and linked to the name – a start killed while writing leaves no
    empty secret.key (before: created first, written after; every later start refused it)."""
    real_fsync = os.fsync

    def killed(fd):  # noqa: ANN001
        raise KeyboardInterrupt  # the process dies after writing, before the key is durable

    monkeypatch.setattr(crypto.os, "fsync", killed)
    with pytest.raises(KeyboardInterrupt):
        crypto.master()
    assert not key_file.exists()  # no half-made secret.key …
    assert not list(key_file.parent.glob(".secret.key.*"))  # … and no temporary file left behind
    monkeypatch.setattr(crypto.os, "fsync", real_fsync)
    crypto.reset_cache()
    key = crypto.master()  # the next start simply makes one
    assert len(key) == 44 and key_file.read_bytes() == key and (key_file.stat().st_mode & 0o777) == 0o600


def test_a_data_folder_the_app_cannot_write_says_how_to_fix_it(key_file):
    """Linux, docker compose: ./data belongs to whoever cloned the repository – the app (UID 10001) cannot write it."""
    key_file.parent.chmod(0o555)
    try:
        with pytest.raises(crypto.KeyFileError, match="10001"):
            crypto.master()
    finally:
        key_file.parent.chmod(0o755)
    assert not key_file.exists()


def test_without_hard_links_the_key_file_is_still_made(key_file, monkeypatch):
    def no_links(src, dst):  # noqa: ANN001
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(crypto.os, "link", no_links)
    key = crypto.master()
    assert len(key) == 44 and key_file.read_bytes() == key and not list(key_file.parent.glob(".secret.key.*"))


@pytest.mark.parametrize("err", ["ENOSPC", "EIO", "EROFS", "EACCES"])
def test_another_link_error_is_raised_not_papered_over(key_file, monkeypatch, err):
    """Only "no hard links here" (EPERM, ENOTSUP/EOPNOTSUPP, EXDEV, EMLINK, ENOSYS) falls back to the old way – a full
    disk or an I/O error is raised: no secret.key, no temporary file left."""
    import errno

    code = getattr(errno, err)

    def broken(src, dst):  # noqa: ANN001
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(crypto.os, "link", broken)
    with pytest.raises(OSError) as exc:
        crypto.master()
    assert exc.value.errno == code
    assert not key_file.exists() and not list(key_file.parent.glob(".secret.key.*"))


@pytest.mark.parametrize("err", ["EPERM", "EOPNOTSUPP", "EXDEV", "EMLINK", "ENOSYS"])
def test_every_no_hard_links_answer_falls_back(key_file, monkeypatch, err):
    import errno

    code = getattr(errno, err)

    def no_links(src, dst):  # noqa: ANN001
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(crypto.os, "link", no_links)
    key = crypto.master()
    assert len(key) == 44 and key_file.read_bytes() == key and not list(key_file.parent.glob(".secret.key.*"))


def test_two_first_starts_share_one_key(key_file, monkeypatch):
    """The slower process finds the name taken when it links – and reads the faster one's key."""
    other = b"o" * 44
    real_link = os.link

    def faster_first(src, dst):  # noqa: ANN001
        key_file.write_bytes(other)
        return real_link(src, dst)

    monkeypatch.setattr(crypto.os, "link", faster_first)
    assert crypto.master() == other and key_file.read_bytes() == other


def test_a_key_file_another_process_is_writing_is_waited_for(key_file):
    """Two processes at the first start: the slower one finds the file before the faster one has written it."""
    import threading

    key_file.touch(mode=0o600)
    threading.Timer(0.3, lambda: key_file.write_bytes(b"k" * 44)).start()
    assert crypto.master() == b"k" * 44


# ---------------------------------------------------------------- BACKUP_PASSPHRASE_FILE (0.1.50)


def _phrase_file(tmp_path, content: bytes, name: str = "backup-pass") -> Path:
    d = tmp_path / "secret"
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_bytes(content)
    f.chmod(0o400)
    return f


def test_the_passphrase_file_is_read_without_its_newline(tmp_path):
    f = _phrase_file(tmp_path, b"eine lange Passphrase aus der Datei\n")
    assert backup.read_passphrase_file(f) == "eine lange Passphrase aus der Datei"
    assert backup.read_passphrase_file(_phrase_file(tmp_path, b"  mit Leerraum drumherum  \r\n", "b")) == "mit Leerraum drumherum"


@pytest.mark.parametrize(
    ("content", "why"),
    [(None, "missing"), (b"", "empty"), (b"\n\n", "empty"), (b"x" * 5000, "too_large"), (b"\xff\xfe kein utf-8", "not_text"), ("dir", "not_a_file")],
)
def test_a_passphrase_file_that_cannot_be_used_says_why_never_what(tmp_path, content, why):
    if content is None:
        f = tmp_path / "nicht-da"
    elif content == "dir":
        f = tmp_path / "ein-ordner"
        f.mkdir()
    else:
        f = _phrase_file(tmp_path, content)
    with pytest.raises(backup.PassphraseFileError) as exc:
        backup.read_passphrase_file(f)
    assert exc.value.why == why and exc.value.code == "passphrase_file" and str(f) in str(exc.value)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_an_unreadable_passphrase_file(tmp_path):
    f = _phrase_file(tmp_path, b"eine lange Passphrase\n")
    f.chmod(0)
    try:
        with pytest.raises(backup.PassphraseFileError) as exc:
            backup.read_passphrase_file(f)
        assert exc.value.why == "unreadable" and "10001" in str(exc.value)
    finally:
        f.chmod(0o600)


async def test_backup_now_encrypts_with_the_passphrase_file(backups_here, tmp_path, admin_client):
    """The app's own backups ("Jetzt sichern") encrypted without the passphrase in the environment: the file is read
    when needed, the page knows where the passphrase comes from – never the passphrase."""
    phrase = "Passphrase-aus-dem-Secret-42"
    f = _phrase_file(tmp_path, f"{phrase}\n".encode())
    object.__setattr__(get_config(), "backup_passphrase_file", str(f))
    st = (await admin_client.get("/api/admin/backup")).json()
    assert st["with_key"] is True and st["passphrase"] == {"source": "file", "file": str(f), "file_ignored": False, "ok": True, "error": None, "detail": None}
    assert phrase not in json.dumps(st)
    assert (await admin_client.post("/api/admin/backup")).status_code == 202
    st = await _done(admin_client)
    assert st["last"]["ok"] and st["last"]["encrypted"] is True and st["last"]["name"].endswith(".tar.enc")
    plan = backup.prepare(backups_here / st["last"]["name"], phrase)
    try:
        assert plan.auth == "passphrase" and plan.backup_key == crypto.master().decode()
    finally:
        shutil.rmtree(plan.work)
    # the restore test of the app opens it, too
    from app import restore_test

    async with db.session() as s:
        assert (await restore_test.status(s))["passphrase"] is True


async def test_backup_passphrase_wins_over_the_file(backups_here, tmp_path):
    """Both set: BACKUP_PASSPHRASE – a cron job's `exec -e BACKUP_PASSPHRASE` keeps working beside a mounted file."""
    cfg = get_config()
    object.__setattr__(cfg, "backup_passphrase", "die-aus-der-Umgebung-1")
    object.__setattr__(cfg, "backup_passphrase_file", str(_phrase_file(tmp_path, b"die-aus-der-Datei-22\n")))
    assert await backup.passphrase_state() == {"source": "env", "file": cfg.backup_passphrase_file, "file_ignored": True, "ok": True, "error": None, "detail": None}
    res = await backup.create()
    with pytest.raises(backup.BackupError, match="cannot decrypt"):
        backup.prepare(res.path, "die-aus-der-Datei-22")
    shutil.rmtree(backup.prepare(res.path, "die-aus-der-Umgebung-1").work)


async def test_a_missing_passphrase_file_fails_the_backup_never_a_plain_one(backups_here, tmp_path, admin_client):
    """A named file that is not there (not mounted, wrong path): no backup at all – not an unencrypted one in its place;
    the page shows why, the app keeps running."""
    object.__setattr__(get_config(), "backup_passphrase_file", str(tmp_path / "nicht-gemountet"))
    st = (await admin_client.get("/api/admin/backup")).json()
    assert st["with_key"] is False and st["passphrase"]["error"] == "missing" and "nicht-gemountet" in st["passphrase"]["detail"]
    assert (await admin_client.post("/api/admin/backup")).status_code == 202
    st = await _done(admin_client)
    assert st["last"]["ok"] is False and st["last"]["code"] == "passphrase_file" and st["backups"] == []
    assert not backups_here.exists() or not any(backups_here.iterdir())


async def test_a_short_phrase_in_the_file_is_refused_and_never_logged(backups_here, tmp_path, caplog):
    object.__setattr__(get_config(), "backup_passphrase_file", str(_phrase_file(tmp_path, b"kurz-geheim\n")))
    assert (await backup.passphrase_state())["error"] == "short"
    with pytest.raises(backup.BackupError, match="too short") as exc:
        await backup.create()
    assert exc.value.code == "passphrase"
    assert "kurz-geheim" not in caplog.text and "kurz-geheim" not in json.dumps(await backup.passphrase_state())


def test_cli_passphrase_file_reads_the_same_way(tmp_path):
    f = _phrase_file(tmp_path, b"eine lange Passphrase\n")
    assert cli._passphrase(["--passphrase-file", str(f)]) == "eine lange Passphrase"
    assert cli._passphrase([]) is None  # the app's own (backup.app_passphrase)
    with pytest.raises(backup.BackupError, match="not found"):
        cli._passphrase(["--passphrase-file", str(tmp_path / "fehlt")])


def test_a_fifo_never_blocks_the_read(tmp_path):
    """Review 0.1.50 L6: open() on a FIFO waits for a writer forever – opened without blocking, refused by fstat."""
    fifo = tmp_path / "backup-pass"
    os.mkfifo(fifo)
    with pytest.raises(backup.PassphraseFileError) as exc:
        backup.read_passphrase_file(fifo)  # returns at once (the test would hang otherwise)
    assert exc.value.why == "not_a_file" and "pipe" in str(exc.value)


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="no /dev/zero")
def test_a_device_is_refused_before_anything_is_read():
    with pytest.raises(backup.PassphraseFileError) as exc:
        backup.read_passphrase_file("/dev/zero")
    assert exc.value.why == "not_a_file"


def test_a_symlink_to_a_regular_file_counts_one_to_a_fifo_does_not(tmp_path):
    """Docker and Kubernetes secrets are often links – followed once, at the open; the check is on what was opened."""
    target = _phrase_file(tmp_path, b"eine lange Passphrase im Ziel\n")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert backup.read_passphrase_file(link) == "eine lange Passphrase im Ziel"
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    bad = tmp_path / "link-to-fifo"
    bad.symlink_to(fifo)
    with pytest.raises(backup.PassphraseFileError) as exc:
        backup.read_passphrase_file(bad)
    assert exc.value.why == "not_a_file"
    gone = tmp_path / "dangling"
    gone.symlink_to(tmp_path / "nicht-da")
    with pytest.raises(backup.PassphraseFileError, match="not found"):
        backup.read_passphrase_file(gone)


async def test_a_hanging_read_never_freezes_the_app(backups_here, tmp_path, monkeypatch):
    """The file is read in a thread with a time limit: a mount that hangs makes the page say "unreadable" and the backup
    fail – the event loop goes on meanwhile."""
    import time as _time

    object.__setattr__(get_config(), "backup_passphrase_file", str(_phrase_file(tmp_path, b"eine lange Passphrase\n")))
    monkeypatch.setattr(backup, "PASSPHRASE_READ_TIMEOUT", 0.3)
    monkeypatch.setattr(backup, "read_passphrase_file", lambda path: _time.sleep(1.5) or "nie")
    ticks = 0

    async def tick():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.05)
            ticks += 1

    t = asyncio.create_task(tick())
    try:
        st = await backup.passphrase_state()
        assert st["error"] == "unreadable" and "no answer" in st["detail"] and ticks >= 3  # the loop ran meanwhile
        with pytest.raises(backup.PassphraseFileError):
            await backup.create()
    finally:
        t.cancel()


# ---------------------------------------------------------------- download of encrypted backups (0.1.51)


@pytest.fixture(autouse=True)
def _fresh_download_limits():
    for d in (backup._dl_starts, backup._dl_running, backup._dl_tickets):
        d.clear()
    yield
    for d in (backup._dl_starts, backup._dl_running, backup._dl_tickets):
        d.clear()


async def _csrf(c) -> dict:  # noqa: ANN001
    if "cobe_news_csrf" not in c.cookies:
        await c.get("/api/auth/config")
    return {"X-CSRF-Token": c.cookies.get("cobe_news_csrf", "")}


async def _ticket(c, name: str):  # noqa: ANN001
    """Step 1 (0.1.52): the page asks for a ticket – a write, with the CSRF token."""
    return await c.post(f"/api/admin/backup/files/{name}/ticket", headers=await _csrf(c), json={})


async def _download(c, name: str, **kw):  # noqa: ANN001, ANN003
    """Both steps, as the page does them: the ticket, then the browser's own GET of the address (no CSRF header – an
    <a download> sends none). A refused step 1 is the answer."""
    r = await _ticket(c, name)
    if r.status_code != 200:
        return r
    assert r.json()["url"].startswith("/api/admin/backup/download/") and r.json()["expires_in"] == 60
    return await c.get(r.json()["url"], **kw)


async def test_an_encrypted_backup_downloads_whole_and_is_logged(admin_client, backups_here):
    from app.models import AuditEntry

    res = await backup.create(passphrase="eine lange Passphrase")
    r = await _download(admin_client, res.name)
    assert r.status_code == 200, r.text
    assert r.content == res.path.read_bytes() and r.headers["content-length"] == str(res.size)
    assert r.headers["content-disposition"] == f'attachment; filename="{res.name}"' and r.headers["cache-control"] == "no-store"
    assert r.headers["content-type"] == "application/octet-stream" and r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"
    async with db.session() as s:
        e = (await s.scalars(select(AuditEntry).where(AuditEntry.action == "backup.downloaded"))).one()
    assert e.notable and e.target_id == res.name and e.details == {"size": res.size, "encrypted": True} and e.actor_name == "anna"
    assert backup._dl_running == {}  # the slot is free again


# ---------------------------------------------------------------- the download ticket (0.1.52)


async def _downloads_logged() -> int:
    from app.models import AuditEntry

    async with db.session() as s:
        return int(await s.scalar(select(func.count()).select_from(AuditEntry).where(AuditEntry.action == "backup.downloaded")))


async def test_a_ticket_is_used_once(admin_client, backups_here):
    res = await backup.create(passphrase="eine lange Passphrase")
    r = await _ticket(admin_client, res.name)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    url = r.json()["url"]
    ticket = url.rsplit("/", 1)[1]
    assert len(ticket) == 43 and ticket not in str(backup._dl_tickets)  # 256 bits, kept only as its hash
    assert await _downloads_logged() == 0  # the ticket alone is no download: nothing logged, counted or claimed
    assert backup._dl_starts == {} and backup._dl_running == {}
    assert (await admin_client.get(url)).content == res.path.read_bytes()
    again = await admin_client.get(url)
    assert again.status_code == 403 and again.json()["detail"]["code"] == "backup_ticket_invalid"
    assert await _downloads_logged() == 1 and backup._dl_running == {}


async def test_a_ticket_expires(admin_client, backups_here, monkeypatch):
    res = await backup.create(passphrase="eine lange Passphrase")
    monkeypatch.setattr(backup, "TICKET_TTL", 0.0)
    url = (await _ticket(admin_client, res.name)).json()["url"]
    r = await admin_client.get(url)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "backup_ticket_invalid"
    assert await _downloads_logged() == 0 and backup._dl_running == {} and backup._dl_tickets == {}


async def test_a_ticket_counts_only_in_its_own_session(admin_client, backups_here):
    """Another session of the same admin, another admin, a reader, nobody signed in: refused – and a ticket shown to the
    wrong session is gone for its owner too."""
    from conftest import add_user, make_client, sign_in

    res = await backup.create(passphrase="eine lange Passphrase")
    bert = await add_user("bert", "admin", totp_secret="JBSWY3DPEHPK3PXP")
    rudi = await add_user("rudi", "reader")
    async with make_client() as anon:
        url = (await _ticket(admin_client, res.name)).json()["url"]
        assert (await anon.get(url)).status_code == 401
        async with make_client() as reader:
            await sign_in(reader, rudi)
            assert (await reader.get(url)).status_code == 403
        assert (await admin_client.get(url)).status_code == 200  # neither of them used it up
        for who in (bert, admin_client.user):
            url = (await _ticket(admin_client, res.name)).json()["url"]
            async with make_client() as other:
                await sign_in(other, who)  # another admin / the same admin in another browser
                r = await other.get(url)
                assert r.status_code == 403 and r.json()["detail"]["code"] == "backup_ticket_invalid" and res.path.read_bytes() not in r.content
            r = await admin_client.get(url)
            assert r.status_code == 403 and r.json()["detail"]["code"] == "backup_ticket_invalid"
    assert await _downloads_logged() == 1 and backup._dl_running == {}


async def test_a_ticket_ends_with_its_session(admin_client, backups_here):
    res = await backup.create(passphrase="eine lange Passphrase")
    url = (await _ticket(admin_client, res.name)).json()["url"]
    async with db.session() as s:
        await s.execute(update(UserSession).where(UserSession.user_id == admin_client.user.id).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        await s.commit()
    assert (await admin_client.get(url)).status_code == 401
    assert await _downloads_logged() == 0


async def test_a_new_ticket_replaces_the_older_one(admin_client, backups_here, monkeypatch):
    """At most one ticket per admin – asking again and again neither counts as downloads nor fills the memory."""
    res = await backup.create(passphrase="eine lange Passphrase")
    monkeypatch.setattr(backup, "DOWNLOADS_PER_HOUR", 2)
    urls = [(await _ticket(admin_client, res.name)).json()["url"] for _ in range(5)]
    assert len(set(urls)) == 5 and len(backup._dl_tickets) == 1
    assert (await admin_client.get(urls[0])).status_code == 403
    assert (await admin_client.get(urls[-1])).status_code == 200


@pytest.mark.parametrize(
    "ticket",
    ["x", "A" * 43, "A" * 44, "..%2F..%2Fbackups%2Fcobe-news-20261101-120000.tar.enc", "cobe-news-20261101-120000.tar.enc", "%2E%2E"],
)
async def test_a_made_up_ticket_downloads_nothing(admin_client, backups_here, ticket):
    res = await backup.create(passphrase="eine lange Passphrase")
    r = await admin_client.get(f"/api/admin/backup/download/{ticket}")
    assert r.status_code in (403, 404), (ticket, r.status_code)
    assert res.path.read_bytes() not in r.content and await _downloads_logged() == 0


async def test_a_backup_removed_after_the_ticket_is_not_found(admin_client, backups_here):
    res = await backup.create(passphrase="eine lange Passphrase")
    url = (await _ticket(admin_client, res.name)).json()["url"]
    res.path.unlink()
    r = await admin_client.get(url)
    assert r.status_code == 404 and backup._dl_running == {} and backup._dl_starts == {} and await _downloads_logged() == 0


async def test_the_ticket_never_lands_in_a_log(admin_client, backups_here, caplog):
    """The access log line and the audit entry's request show the route, not the ticket."""
    import logging

    from app.models import AuditEntry

    res = await backup.create(passphrase="eine lange Passphrase")
    url = (await _ticket(admin_client, res.name)).json()["url"]
    ticket = url.rsplit("/", 1)[1]
    with caplog.at_level(logging.INFO, logger="cobe_news.access"):
        assert (await admin_client.get(url)).status_code == 200
        assert (await admin_client.get(url)).status_code == 403
    assert "/api/admin/backup/download/…" in caplog.text and ticket not in caplog.text
    async with db.session() as s:
        e = (await s.scalars(select(AuditEntry).where(AuditEntry.action == "backup.downloaded"))).one()
    assert e.req_method == "GET" and e.req_path == "/api/admin/backup/download/…"


async def test_a_plain_backup_stays_on_the_server(admin_client, backups_here):
    res = await backup.create()
    r = await _download(admin_client, res.name)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "backup_not_encrypted"


@pytest.mark.parametrize(
    "name",
    [
        "..%2F..%2Fsecret.key",
        "%2E%2E%2Fsecret.key",
        "secret.key",
        ".partial-x",
        "cobe-news-20261101-120000.tar.enc.partial",
        "cobe-news-20261101-120000.tar.enc%00",
        "cobe-news-20991231-235959.tar.enc",  # the pattern, but not in the list
    ],
)
async def test_only_names_of_the_list_never_a_path(admin_client, backups_here, name):
    await backup.create(passphrase="eine lange Passphrase")
    (backups_here / "cobe-news-20261101-120000.tar.enc.partial").write_bytes(b"half")
    r = await _download(admin_client, name)
    assert r.status_code in (404, 422), (name, r.status_code, r.text)
    assert b"half" not in r.content and crypto.master() not in r.content


async def test_a_symlink_in_the_folder_is_never_followed(admin_client, backups_here, tmp_path):
    await backup.create(passphrase="eine lange Passphrase")
    outside = tmp_path / "outside.tar.enc"
    outside.write_bytes(b"not a backup of ours")
    link = backups_here / "cobe-news-20261101-120000.tar.enc"
    link.symlink_to(outside)
    r = await _download(admin_client, link.name)
    assert r.status_code == 404 and b"not a backup" not in r.content


async def test_the_download_needs_an_admin_a_fresh_proof_and_the_csrf_token(admin_client, reader_client, backups_here):
    res = await backup.create(passphrase="eine lange Passphrase")
    assert (await _download(reader_client, res.name)).status_code == 403
    # a form or a script on another site: no CSRF token, no ticket
    for token in ("", "wrong"):
        r = await admin_client.post(f"/api/admin/backup/files/{res.name}/ticket", json={}, headers={"X-CSRF-Token": token})
        assert r.status_code == 403 and r.json()["detail"]["code"] == "csrf_failed"
    assert backup._dl_tickets == {}
    # the address of 0.1.51 (a GET with the CSRF header) is gone: a link to it downloads nothing either
    r = await admin_client.get(f"/api/admin/backup/files/{res.name}", headers=await _csrf(admin_client))
    assert r.status_code in (404, 405) and res.path.read_bytes() not in r.content
    async with db.session() as s:
        await s.execute(update(UserSession).values(reauth_at=datetime.now(UTC) - timedelta(hours=1)))
        await s.commit()
    r = await _download(admin_client, res.name)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    async with db.session() as s:
        from app.models import AuditEntry

        assert await s.scalar(select(func.count()).select_from(AuditEntry).where(AuditEntry.action == "backup.downloaded")) == 0


async def test_a_few_per_hour_and_one_at_a_time(admin_client, backups_here, monkeypatch):
    res = await backup.create(passphrase="eine lange Passphrase")
    backup._dl_running[str(admin_client.user.id)] = ("other", __import__("time").monotonic())
    r = await _download(admin_client, res.name)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "backup_download_busy"
    backup._dl_running.clear()
    monkeypatch.setattr(backup, "DOWNLOADS_PER_HOUR", 2)
    assert (await _download(admin_client, res.name)).status_code == 200
    assert (await _download(admin_client, res.name)).status_code == 200
    r = await _download(admin_client, res.name)
    assert r.status_code == 429 and r.json()["detail"]["code"] == "backup_download_rate_limited" and 0 < r.json()["detail"]["retry_after"] <= 3601


async def test_a_big_backup_is_streamed_in_chunks(admin_client, backups_here, monkeypatch):
    """Never whole in memory: read in DOWNLOAD_CHUNK steps from one descriptor; the answer is exactly the file."""
    backups_here.mkdir(parents=True, exist_ok=True)
    big = backups_here / "cobe-news-20261101-120000.tar.enc"
    payload = os.urandom(5 * 1024 * 1024 + 123)
    big.write_bytes(payload)
    reads: list[int] = []
    real = os.read

    def counting(fd, n):  # noqa: ANN001
        reads.append(n)
        return real(fd, n)

    monkeypatch.setattr(backup, "DOWNLOAD_CHUNK", 1 << 20)
    monkeypatch.setattr(backup.os, "read", counting)
    url = (await _ticket(admin_client, big.name)).json()["url"]
    async with admin_client.stream("GET", url) as r:
        assert r.status_code == 200
        got = b"".join([chunk async for chunk in r.aiter_bytes()])
    assert got == payload and r.headers["content-length"] == str(len(payload))
    assert len(reads) >= 6 and max(reads) <= 1 << 20


async def test_a_backup_replaced_after_the_check_is_not_sent(backups_here):
    backups_here.mkdir(parents=True, exist_ok=True)
    f = backups_here / "cobe-news-20261101-120000.tar.enc"
    f.write_bytes(b"A" * 100)
    dl = backup.prepare_download(f.name, "u1")
    f.unlink()
    f.write_bytes(b"B" * 100)  # another file under the same name
    with pytest.raises(backup.DownloadRefused):
        async for _ in backup.stream_download(dl, "u1"):
            pass
    assert backup._dl_running == {}


async def test_two_downloads_in_parallel_one_waits(admin_client, backups_here, monkeypatch):
    """Review 0.1.51 L1: the slot is claimed by the check itself – requests while the first is still streaming get 409,
    and the first one's end frees it."""
    import threading

    backups_here.mkdir(parents=True, exist_ok=True)
    f = backups_here / "cobe-news-20261101-120000.tar.enc"
    f.write_bytes(os.urandom(3 * 65536))
    monkeypatch.setattr(backup, "DOWNLOAD_CHUNK", 65536)
    started, gate = threading.Event(), threading.Event()
    real = os.read

    def held(fd, n):  # noqa: ANN001 - the first download's read waits until the others have asked
        started.set()
        assert gate.wait(10)
        return real(fd, n)

    monkeypatch.setattr(backup.os, "read", held)
    first = asyncio.create_task(_download(admin_client, f.name))
    for _ in range(200):
        if started.is_set():
            break
        await asyncio.sleep(0.02)
    assert started.is_set()  # the first is streaming
    both = await asyncio.gather(_download(admin_client, f.name), _download(admin_client, f.name))
    assert [r.status_code for r in both] == [409, 409] and all(r.json()["detail"]["code"] == "backup_download_busy" for r in both)
    gate.set()
    r = await first
    assert r.status_code == 200 and r.content == f.read_bytes()
    assert backup._dl_running == {}
    assert (await _download(admin_client, f.name)).status_code == 200


async def test_requests_at_the_same_moment_get_one_slot(backups_here):
    """Two checks in a row before either stream starts (the race of 0.1.51): only the first gets the slot."""
    backups_here.mkdir(parents=True, exist_ok=True)
    f = backups_here / "cobe-news-20261101-120000.tar.enc"
    f.write_bytes(b"x" * 100)
    dl = backup.prepare_download(f.name, "u1")
    with pytest.raises(backup.DownloadRefused) as exc:
        backup.prepare_download(f.name, "u1")
    assert exc.value.code == "backup_download_busy"
    assert backup.prepare_download(f.name, "u2").token  # another admin has a slot of his own
    backup.release_download(dl, "u1")
    assert backup.prepare_download(f.name, "u1").token != dl.token


async def test_a_download_frees_only_its_own_slot(backups_here, monkeypatch):
    """After a stale slot (DOWNLOAD_SLOT_MAX) a new download claims it; the old one ending later must not free the new."""
    backups_here.mkdir(parents=True, exist_ok=True)
    f = backups_here / "cobe-news-20261101-120000.tar.enc"
    f.write_bytes(b"x" * 100)
    old = backup.prepare_download(f.name, "u1")
    backup._dl_running["u1"] = (old.token, backup._dl_running["u1"][1] - backup.DOWNLOAD_SLOT_MAX - 1)  # stale
    new = backup.prepare_download(f.name, "u1")
    async for _ in backup.stream_download(old, "u1"):  # the old one ends now
        pass
    assert backup._dl_running["u1"][0] == new.token
    backup.release_download(new, "u1")
    assert backup._dl_running == {}


async def test_an_answer_never_sent_frees_the_slot(admin_client, backups_here):
    """The client gone before the body began: the stream never runs – the answer frees the slot itself."""
    from app.admin_api import _BackupStream

    backups_here.mkdir(parents=True, exist_ok=True)
    f = backups_here / "cobe-news-20261101-120000.tar.enc"
    f.write_bytes(b"x" * 100)
    dl = backup.prepare_download(f.name, "u1")
    resp = _BackupStream(dl, "u1", backup.stream_download(dl, "u1"), media_type="application/octet-stream")

    async def gone(message):  # noqa: ANN001
        raise OSError("client disconnected")

    async def receive():
        return {"type": "http.disconnect"}

    with pytest.raises(Exception):  # noqa: B017, PT011 - Starlette names the disconnect its own way
        await resp({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, gone)
    assert backup._dl_running == {}
