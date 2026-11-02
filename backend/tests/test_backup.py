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
from conftest import DATABASE_URL, _admin_dsn
from sqlalchemy import func, insert, select, update
from sqlalchemy.engine import make_url

from app import backup, cli, crypto, db
from app import settings as settings_store
from app.config import get_config
from app.crypto import encrypt_str
from app.models import NewsItem, NewsSource, NotifyChannel, NotifyRule, NotifyRuleChannel, User, UserSession, VendorFollow, VendorVersion

pytestmark = pytest.mark.skipif(shutil.which("pg_dump") is None or shutil.which("psql") is None, reason="needs the PostgreSQL 18 client tools")


@pytest.fixture(autouse=True)
def backups_here(tmp_path):
    """Each test's backups in a folder of its own (the config is frozen: set and put back)."""
    cfg = get_config()
    old = cfg.backup_dir, cfg.backup_passphrase
    object.__setattr__(cfg, "backup_dir", tmp_path / "backups")
    object.__setattr__(cfg, "backup_passphrase", "")
    yield tmp_path / "backups"
    object.__setattr__(cfg, "backup_dir", old[0])
    object.__setattr__(cfg, "backup_passphrase", old[1])


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
        assert await cli._restore([str(res.path), "--yes"]) == 0
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
    res = await backup.create()
    oldest = backups_here / "cobe-news-20260101-000000.tar"
    os.replace(res.path, oldest)
    for d in ("20260102", "20260103"):
        shutil.copy(oldest, backups_here / f"cobe-news-{d}-000000.tar")

    async def nobody() -> int:
        return 0

    monkeypatch.setattr(backup, "others_connected", nobody)
    assert await cli._restore([str(oldest), "--yes"]) == 0
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


def test_a_key_file_another_process_is_writing_is_waited_for(key_file):
    """Two processes at the first start: the slower one finds the file before the faster one has written it."""
    import threading

    key_file.touch(mode=0o600)
    threading.Timer(0.3, lambda: key_file.write_bytes(b"k" * 44)).start()
    assert crypto.master() == b"k" * 44
