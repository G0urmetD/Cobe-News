"""Backup, restore and export (docs/BETRIEB.md: Sicherung).

A backup is one file in BACKUP_DIR (default data/backups, 0600):
- `cobe-news-<time>.tar` – manifest.json (version, schema revision, rows per table, checksums, the fingerprint of the
  master key) and db.dump (pg_dump, custom format). Without a passphrase the master key is NOT in it: the secrets in the
  database (webhook URLs, SMTP/LDAP passwords, the Entra secret, TOTP seeds) stay encrypted with SECRET_KEY /
  data/secret.key – keep that apart from the backups.
- `cobe-news-<time>.tar.enc` – with BACKUP_PASSPHRASE: the same plus secrets.json (the master key) – the whole file
  encrypted with the passphrase (crypto.seal_file: scrypt + AES-256-GCM). A restore on a new server needs only the
  file and the passphrase.

The app's own passphrase ("Jetzt sichern", the restore test): BACKUP_PASSPHRASE, else the file BACKUP_PASSPHRASE_FILE
names (a read-only mount or a Docker secret – read each time it is needed, so a changed file counts at once). Both set:
BACKUP_PASSPHRASE wins (an environment set for one command keeps working beside a file; --passphrase-file of the CLI wins over both). A file
that is named but cannot be read is an error – no backup, never an unencrypted one instead.

The dump and the row counts come from one snapshot (pg_export_snapshot → pg_dump --snapshot): the counts in the
manifest are exactly what the dump holds, and a restore checks them.

Restore (CLI only, with the app stopped – app.cli restore): checksums, schema revision, key fingerprint, then a backup
of the current state, then the dump in ONE transaction (DROP SCHEMA public … and the whole dump through psql
--single-transaction: a failure changes nothing), then the counts compared and the schema migrated to this version.

Export (admin UI, CLI): rules, channels, sources, followed products with their versions and users as JSON or CSV –
without any secret (no webhook URL, token, password hash or TOTP seed)."""

import asyncio
import contextlib
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__, crypto, db
from app import settings as settings_store
from app.config import get_config

log = logging.getLogger("cobe_news.backup")
FORMAT = 1
NAME_RX = re.compile(r"^cobe-news-(\d{8}-\d{6})(?:-[a-z0-9-]+)?\.tar(\.enc)?$")  # also -pre-restore, -2
BACKUP_LOCK = 0x636E_626B  # pg_try_advisory_lock: one backup at a time (UI, CLI, cron)
DUMP_TIMEOUT_S = 1800
KEEP_CHOICES = (3, 7, 14, 30, 90)
MIN_PASSPHRASE = 12  # BACKUP_PASSPHRASE: shorter ones are refused (scrypt slows guessing down, a short phrase still falls)
PASSPHRASE_FILE_MAX = 4096  # bytes: a passphrase file is short – anything bigger is the wrong file
PASSPHRASE_READ_TIMEOUT = 5.0  # s: reading it off the event loop – a hung mount answers "unreadable", never freezes the app
SECTION = "backup"  # settings: {"keep": 7, "rev": n}
LAST = "backup_last"  # settings: the last backup's outcome (also a failed one)


class BackupError(Exception):
    """A backup or restore did not happen; the message says why (nothing was changed). `code` names the kind for the
    UI (backup.err.<code>): busy, no_pg_dump, timeout, dump, passphrase, passphrase_file, failed."""

    def __init__(self, message: str, code: str = "failed") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Result:
    name: str
    path: Path
    size: int
    seconds: float
    encrypted: bool
    rows: dict[str, int]


class PassphraseFileError(BackupError):
    """BACKUP_PASSPHRASE_FILE (or --passphrase-file) cannot be used – `why` for the UI (backup.passFile.<why>): missing,
    unreadable, not_a_file, too_large, not_text, empty. The message names the path and the reason, never the content."""

    def __init__(self, path: Path, why: str, reason: str) -> None:
        super().__init__(f"passphrase file {path}: {reason}", "passphrase_file")
        self.why = why


# ---------------------------------------------------------------- the passphrase


def read_passphrase_file(path: str | Path) -> str:
    """The passphrase in a file – the whole file, whitespace around it (the newline of `printf '%s\\n'`) removed, as
    app.cli --passphrase-file has always read it. Only a regular file: opened without blocking (O_NONBLOCK – a FIFO
    would wait for a writer forever), then checked on the open descriptor (fstat) – a folder, pipe or device
    (/dev/zero) is refused before anything is read. A symlink to a regular file counts (Docker and Kubernetes secrets
    are links); it is followed once, at the open, so the check and the read concern the same file."""
    p = Path(path)
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise PassphraseFileError(p, "missing", "not found (mounted? the path is the one inside the container)") from None
    except IsADirectoryError:
        raise PassphraseFileError(p, "not_a_file", "a folder, not a file") from None
    except PermissionError:
        raise PassphraseFileError(p, "unreadable", "not readable – the app runs as UID 10001 (chown 10001, chmod 400)") from None
    except OSError as exc:
        raise PassphraseFileError(p, "unreadable", f"cannot be read ({exc.strerror or type(exc).__name__})") from None
    try:
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            raise PassphraseFileError(p, "not_a_file", "a folder, not a file")
        if not stat.S_ISREG(st.st_mode):
            raise PassphraseFileError(p, "not_a_file", "not a regular file (a pipe, socket or device)")
        if st.st_size > PASSPHRASE_FILE_MAX:
            raise PassphraseFileError(p, "too_large", f"larger than {PASSPHRASE_FILE_MAX} bytes – not a passphrase file")
        try:
            raw = os.read(fd, PASSPHRASE_FILE_MAX + 1)
        except OSError as exc:
            raise PassphraseFileError(p, "unreadable", f"cannot be read ({exc.strerror or type(exc).__name__})") from None
    finally:
        os.close(fd)
    if len(raw) > PASSPHRASE_FILE_MAX:
        raise PassphraseFileError(p, "too_large", f"larger than {PASSPHRASE_FILE_MAX} bytes – not a passphrase file")
    try:
        phrase = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise PassphraseFileError(p, "not_text", "not UTF-8 text") from None
    if not phrase:
        raise PassphraseFileError(p, "empty", "empty")
    return phrase


def app_passphrase() -> str:
    """The passphrase the app itself has: BACKUP_PASSPHRASE, else the file BACKUP_PASSPHRASE_FILE names, else "" (no
    encryption). PassphraseFileError when the file is named but cannot be used."""
    cfg = get_config()
    if cfg.backup_passphrase:
        return cfg.backup_passphrase
    if cfg.backup_passphrase_file:
        return read_passphrase_file(cfg.backup_passphrase_file)
    return ""


async def app_passphrase_async() -> str:
    """app_passphrase() off the event loop, at most PASSPHRASE_READ_TIMEOUT – the file may sit on a mount that hangs."""
    cfg = get_config()
    if cfg.backup_passphrase or not cfg.backup_passphrase_file:
        return app_passphrase()  # nothing to read
    try:
        return await asyncio.wait_for(asyncio.to_thread(app_passphrase), PASSPHRASE_READ_TIMEOUT)
    except TimeoutError:
        raise PassphraseFileError(Path(cfg.backup_passphrase_file), "unreadable", f"no answer within {PASSPHRASE_READ_TIMEOUT:.0f} s (a mount that hangs?)") from None


async def passphrase_state() -> dict:
    """What the page says about the app's passphrase – never the passphrase itself. `ok`: backups from the app are
    encrypted; `error` (missing, unreadable, …, short): "Jetzt sichern" fails until it is fixed."""
    cfg = get_config()
    out = {
        "source": "env" if cfg.backup_passphrase else "file" if cfg.backup_passphrase_file else None,
        "file": cfg.backup_passphrase_file or None,
        "file_ignored": bool(cfg.backup_passphrase and cfg.backup_passphrase_file),
        "ok": False,
        "error": None,
        "detail": None,
    }
    try:
        phrase = await app_passphrase_async()
    except PassphraseFileError as exc:
        out.update(error=exc.why, detail=str(exc))
        return out
    if phrase and len(phrase) < MIN_PASSPHRASE:
        out.update(error="short", detail=f"the passphrase is too short (at least {MIN_PASSPHRASE} characters)")
        return out
    out["ok"] = bool(phrase)
    return out


# ---------------------------------------------------------------- helpers


def _pg_env(url=None, app: str = "cobe-news-backup") -> dict[str, str]:  # noqa: ANN001 - a sqlalchemy URL
    """libpq's environment for pg_dump / pg_restore / psql – the password never on a command line (ps shows those).
    `url`: another database than the app's (the restore test's throwaway one, app/restore_test.py)."""
    url = url if url is not None else get_config().database_url
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    env.update(PGHOST=url.host or "localhost", PGPORT=str(url.port or 5432), PGUSER=url.username or "", PGDATABASE=url.database or "", PGAPPNAME=app)
    if url.password:
        env["PGPASSWORD"] = str(url.password)
    return env


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def backup_dir() -> Path:
    d = get_config().backup_dir
    d.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        d.chmod(0o700)
    return d


STALE_S = 6 * 3600  # a work folder or half-written file older than this belongs to a backup or restore that was killed


def _workdir(prefix: str) -> Path:
    """A work folder for a backup or restore – next to BACKUP_DIR, never in it (that folder is copied off the host,
    docs/BETRIEB.md: rsync): the dump and, for an encrypted backup, the master key lie there in plain text for a moment. Left
    behind by a killed process, it is removed by the next backup, restore or app start (sweep())."""
    base = get_config().data_dir / ".backup-work"
    base.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        base.chmod(0o700)
    sweep()
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base))


def sweep(max_age: float = STALE_S) -> list[str]:
    """Leftovers of a killed backup or restore: work folders (also the old ones inside BACKUP_DIR, up to 0.1.21) and
    half-written files – removed once they are older than any backup can take."""
    cfg = get_config()
    gone = []
    now = time.time()
    for d, pattern in ((cfg.data_dir / ".backup-work", "*"), (cfg.backup_dir, ".partial-*"), (cfg.backup_dir, ".restore-*"), (cfg.backup_dir, "*.partial")):
        if not d.is_dir():
            continue
        for f in d.glob(pattern):
            try:
                if now - f.lstat().st_mtime < max_age:
                    continue
                if f.is_dir() and not f.is_symlink():
                    shutil.rmtree(f)
                else:
                    f.unlink()
                gone.append(f.name)
            except OSError:
                continue
    if gone:
        log.warning("backup: removed %d leftover(s) of a backup or restore that did not finish: %s", len(gone), ", ".join(sorted(gone)[:5]))
    return gone


def listing() -> list[dict]:
    """The backups in BACKUP_DIR, newest first."""
    d = get_config().backup_dir
    if not d.is_dir():
        return []
    out = []
    for f in d.iterdir():
        m = NAME_RX.match(f.name)
        if not m or not f.is_file():
            continue
        try:
            at = datetime.strptime(m.group(1), "%Y%m%d-%H%M%S").replace(tzinfo=UTC)
        except ValueError:
            continue  # not one of ours
        st = f.stat()
        out.append((at, st.st_mtime_ns, {"name": f.name, "size": st.st_size, "at": at.isoformat(), "encrypted": bool(m.group(2))}))
    # by its time, then by when the file was written – by name, two of one second sorted wrong ("-2" before ".tar")
    return [x[2] for x in sorted(out, key=lambda x: (x[0], x[1]), reverse=True)]


PRE_RESTORE_DAYS = 30
PRE_RESTORE_RX = re.compile(r"-pre-restore(?:-\d+)?\.tar")


def prune(keep: int) -> list[str]:
    """Only the newest `keep` backups stay. A backup made right before a restore (the way back) is not counted and
    stays PRE_RESTORE_DAYS days."""
    gone = []
    now = datetime.now(UTC)
    regular = []
    for x in listing():
        if PRE_RESTORE_RX.search(x["name"]):
            if now - datetime.fromisoformat(x["at"]) > timedelta(days=PRE_RESTORE_DAYS):
                with contextlib.suppress(OSError):
                    (get_config().backup_dir / x["name"]).unlink()
                    gone.append(x["name"])
            continue
        regular.append(x)
    for x in regular[max(1, keep) :]:
        with contextlib.suppress(OSError):
            (get_config().backup_dir / x["name"]).unlink()
            gone.append(x["name"])
    return gone


async def table_counts(conn) -> dict[str, int]:  # noqa: ANN001
    from app.sqlite_import import tables

    return {t.name: int(await conn.scalar(select(func.count()).select_from(t)) or 0) for t in tables()}


async def _run(*args: str, timeout: float = DUMP_TIMEOUT_S, stdin: bytes | None = None) -> bytes:
    proc = await asyncio.create_subprocess_exec(*args, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_pg_env())
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin), timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise BackupError(f"{args[0]}: no answer within {timeout:.0f} s", "timeout") from None
    if proc.returncode != 0:
        raise BackupError(f"{args[0]} failed: {err.decode(errors='replace').strip()[-400:]}", "dump")
    return out


# ---------------------------------------------------------------- backup


async def create(*, reason: str = "", passphrase: str | None = None, actor=None) -> Result:  # noqa: ANN001 - an audit.Actor or a User
    """A backup now (see the module text). One at a time; BackupError when it did not work (logged, recorded as the
    last outcome). `passphrase` None: BACKUP_PASSPHRASE from the environment."""
    t0 = time.monotonic()
    cfg = get_config()
    try:
        phrase = await app_passphrase_async() if passphrase is None else passphrase
        if phrase and len(phrase) < MIN_PASSPHRASE:
            raise BackupError(f"the passphrase is too short (at least {MIN_PASSPHRASE} characters) – no backup made", "passphrase")
    except BackupError as exc:
        # a named passphrase file that cannot be read: no backup – never an unencrypted one in its place
        await _record({"ok": False, "at": datetime.now(UTC).isoformat(), "code": exc.code, "error": str(exc)[:300]})
        log.warning("backup failed: %s", exc)
        raise
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    tag = f"-{reason}" if reason else ""
    d = backup_dir()
    name = next(
        n
        for i in range(1, 100)
        if not (d / (n := f"cobe-news-{stamp}{tag}{'' if i == 1 else f'-{i}'}.tar" + (".enc" if phrase else ""))).exists()
    )  # two in the same second (a backup right before a restore): -2, never one over the other
    work = _workdir(".partial-")
    try:
        if shutil.which("pg_dump") is None:
            raise BackupError("pg_dump not found (the image brings it – outside the container install postgresql-client-18)", "no_pg_dump")
        async with db.engine().connect() as c0:
            conn = await c0.execution_options(isolation_level="REPEATABLE READ")
            async with conn.begin():
                # one snapshot for the counts and the dump: what the manifest says is exactly what the dump holds
                await conn.execute(text("SET TRANSACTION READ ONLY"))
                if not await conn.scalar(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": BACKUP_LOCK}):
                    raise BackupError("busy: another backup is running", "busy")
                await conn.execute(text("SET LOCAL idle_in_transaction_session_timeout = 0"))  # open while pg_dump reads
                await conn.execute(text("SET LOCAL statement_timeout = 0"))
                snap = await conn.scalar(text("SELECT pg_export_snapshot()"))
                rows = await table_counts(conn)
                revision = await conn.scalar(text("SELECT version_num FROM alembic_version"))
                server = await conn.scalar(text("SHOW server_version"))
                await _run("pg_dump", "--format=custom", "--no-owner", "--no-privileges", f"--snapshot={snap}", f"--file={work / 'db.dump'}")
        files = {"db.dump": {"sha256": _sha256(work / "db.dump"), "size": (work / "db.dump").stat().st_size}}
        if phrase:
            key = crypto.master().decode()
            (work / "secrets.json").write_text(json.dumps({"secret_key": key, "from": "env" if cfg.secret_key else "file"}))
            files["secrets.json"] = {"sha256": _sha256(work / "secrets.json"), "size": (work / "secrets.json").stat().st_size}
        manifest = {
            "format": FORMAT,
            "app": "cobe-news",
            "version": __version__,
            "revision": revision,
            "postgres": server,
            "created_at": datetime.now(UTC).isoformat(),
            "reason": reason or "manual",
            "key_id": crypto.key_id(),
            "with_key": bool(phrase),
            "rows": rows,
            "files": files,
        }
        raw = json.dumps(manifest, indent=1).encode()
        (work / "manifest.json").write_bytes(raw)
        # signed with the master key: a restore knows an unencrypted backup is this installation's, not a crafted one
        (work / "manifest.sig").write_text(json.dumps({"alg": "hmac-sha256", "key_id": manifest["key_id"], "mac": crypto.backup_mac(raw)}))
        await asyncio.to_thread(_pack, work, d / name, phrase)
        res = Result(name=name, path=d / name, size=(d / name).stat().st_size, seconds=round(time.monotonic() - t0, 1), encrypted=bool(phrase), rows=rows)
    except BackupError as exc:
        if exc.code != "busy":  # refused because another one runs: that one's outcome is the last, not this refusal
            await _record({"ok": False, "at": datetime.now(UTC).isoformat(), "code": exc.code, "error": str(exc)[:300]})
        log.warning("backup failed: %s", exc)
        raise
    except Exception as exc:
        await _record({"ok": False, "at": datetime.now(UTC).isoformat(), "code": "failed", "error": type(exc).__name__})
        log.exception("backup failed")
        raise BackupError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)
    async with db.session() as s:
        keep = int((await settings_store.get(s, SECTION)).get("keep") or 7)
    gone = [] if reason == "pre-restore" else prune(keep)  # never right before a restore: it may need the oldest one
    await _record({"ok": True, "at": datetime.now(UTC).isoformat(), "name": res.name, "size": res.size, "seconds": res.seconds, "encrypted": res.encrypted, "rows": sum(rows.values())})
    log.info("backup %s: %d bytes, %d rows, %.1f s%s", res.name, res.size, sum(rows.values()), res.seconds, f", {len(gone)} older removed" if gone else "")
    await _audit(actor, res, reason, gone)
    return res


async def _audit(actor, res: Result, reason: str, gone: list[str]) -> None:  # noqa: ANN001
    """The backup made (and the old ones it removed) in the audit log – who started it: an admin, the CLI, the system."""
    from app import audit

    try:
        async with db.session() as s:
            audit.record(s, actor or audit.SYSTEM, "backup.created", audit.target("backup", res.name, res.name), {"size": res.size, "encrypted": res.encrypted, "reason": reason or "manual"})
            if gone:
                audit.record(s, audit.SYSTEM, "backup.deleted", audit.target("backup", None, None), {"files": gone, "why": "keep"})
            await s.commit()
    except Exception:  # noqa: BLE001 - the backup itself matters, not its note
        log.warning("backup: audit entry not written")


def _pack(work: Path, dest: Path, phrase: str) -> None:
    """The tar (and with a passphrase its encryption) written under a temporary name and renamed when complete – a
    half-written backup never has a backup's name."""
    tmp = dest.with_name(dest.name + ".partial")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            if phrase:
                buf = work / "archive.tar"
                _tar(work, buf)
                with buf.open("rb") as src:
                    crypto.seal_file(src, out, phrase)
                buf.unlink()
            else:
                with tarfile.open(fileobj=out, mode="w") as tf:
                    _add(tf, work)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def _tar(work: Path, dest: Path) -> None:
    with tarfile.open(dest, mode="w") as tf:
        _add(tf, work)


def _add(tf: tarfile.TarFile, work: Path) -> None:
    for n in ("manifest.json", "manifest.sig", "db.dump", "secrets.json"):
        if (work / n).is_file():
            tf.add(work / n, arcname=n)


async def _record(value: dict) -> None:
    try:
        async with db.session() as s:
            await settings_store.put(s, LAST, value)
            await s.commit()
    except Exception:  # noqa: BLE001 - the backup itself matters, not its note
        log.warning("backup: outcome not recorded")


# "Jetzt sichern" in the UI: the backup runs as a task of its own, the request answers at once (a big database takes
# longer than the proxy waits – it answered 504 while the backup went on). The page asks status() until it is done.
_job: dict = {"task": None, "since": None}


def start(actor=None) -> bool:  # noqa: ANN001 - the admin who asked for it (audit log)
    """A backup in the background of this process; False when one of its own is still running."""
    task = _job["task"]
    if task is not None and not task.done():
        return False

    async def run() -> None:
        try:
            await create(actor=actor)
        except BackupError:
            pass  # recorded as the last outcome by create()
        except Exception:  # noqa: BLE001 - never an unobserved task exception
            log.exception("backup task failed")

    _job["task"], _job["since"] = asyncio.create_task(run(), name="backup"), datetime.now(UTC).isoformat()
    return True


async def running(s: AsyncSession) -> bool:
    """A backup runs now – one of this process, or one of the CLI or the cron job (it holds the backup lock)."""
    task = _job["task"]
    if task is not None and not task.done():
        return True
    held = await s.scalar(
        text("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND classid = 0 AND objid = :k AND objsubid = 1 AND granted)"),
        {"k": BACKUP_LOCK},
    )
    return bool(held)


async def record_restored(result: "Result | None", manifest: dict, name: str) -> None:
    """After a restore the database holds the outcome stored in the backup (the backup before it): the last backup is
    now the one made right before the restore – or, onto an empty database, the restored file itself."""
    if result is not None:
        value = {"ok": True, "at": datetime.now(UTC).isoformat(), "name": result.name, "size": result.size, "seconds": result.seconds, "encrypted": result.encrypted}
        value["rows"] = sum(result.rows.values())
    else:
        value = {"ok": True, "at": manifest.get("created_at") or datetime.now(UTC).isoformat(), "name": name, "rows": sum((manifest.get("rows") or {}).values())}
    await _record(value)


async def status(s: AsyncSession) -> dict:
    cfg = get_config()
    conf = await settings_store.get(s, SECTION)
    last = await settings_store.get(s, LAST)
    busy = await running(s)
    phrase = await passphrase_state()
    return {
        "running": busy,
        "running_since": _job["since"] if busy and _job["task"] is not None and not _job["task"].done() else None,
        "keep": int(conf.get("keep") or 7),
        "keep_choices": list(KEEP_CHOICES),
        "rev": int(conf.get("rev") or 0),
        "dir": str(cfg.backup_dir),
        "with_key": phrase["ok"],  # "Jetzt sichern" encrypts (and takes the master key along)
        "passphrase": phrase,
        "last": last if last.get("at") else None,
        "backups": listing()[:100],
    }


# ---------------------------------------------------------------- download (admin UI, encrypted backups only)

# An unencrypted backup holds the whole database readable – it never leaves the server through the browser (docker cp,
# docs/handbuch: Sicherung → Schritt für Schritt). An encrypted one is useless without the passphrase: an admin may
# download it after a fresh proof of identity, logged (backup.downloaded), a few per hour, one at a time.
DOWNLOADS_PER_HOUR = 6
DOWNLOAD_CHUNK = 1 << 20  # bytes read per step (in a thread – the event loop never waits on the disk)
DOWNLOAD_SLOT_MAX = 6 * 3600.0  # s: a slot older than this belongs to a download that never finished – freed
_dl_starts: dict[str, list[float]] = {}  # admin id → monotonic start times of the last hour
_dl_running: dict[str, tuple[str, float]] = {}  # admin id → (the download's token, when it was claimed)


class DownloadRefused(Exception):
    """Not offered: `status`/`code` for the API (404 not_found, 403 backup_not_encrypted, 409 backup_download_busy,
    429 backup_download_rate_limited with `retry` seconds)."""

    def __init__(self, status: int, code: str, retry: int | None = None) -> None:
        super().__init__(code)
        self.status, self.code, self.retry = status, code, retry


@dataclass(frozen=True)
class Download:
    name: str
    size: int
    dev: int
    ino: int
    token: str = ""  # its claim on the admin's slot (release_download frees only its own)


def _open_backup(name: str) -> tuple[int, os.stat_result]:
    """The backup's file opened read-only: never through a symlink (O_NOFOLLOW), never blocking (O_NONBLOCK), a regular
    file only (fstat on the open descriptor)."""
    try:
        fd = os.open(get_config().backup_dir / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise DownloadRefused(404, "not_found") from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise DownloadRefused(404, "not_found")
    return fd, st


def prepare_download(name: str, user_id: str) -> Download:
    """An encrypted backup of the list, checked for a download by this admin – names only from BACKUP_DIR's listing and
    its pattern (no path, no hidden or half-written file, nothing outside the folder), a few per hour, one at a time."""
    m = NAME_RX.match(name)
    if not m or name not in {x["name"] for x in listing()}:
        raise DownloadRefused(404, "not_found")
    if not m.group(2):
        raise DownloadRefused(403, "backup_not_encrypted")
    now = time.monotonic()
    held = _dl_running.get(user_id)
    if held is not None and now - held[1] < DOWNLOAD_SLOT_MAX:
        raise DownloadRefused(409, "backup_download_busy")
    starts = [t for t in _dl_starts.get(user_id, []) if now - t < 3600]
    if len(starts) >= DOWNLOADS_PER_HOUR:
        raise DownloadRefused(429, "backup_download_rate_limited", retry=int(3600 - (now - starts[0])) + 1)
    fd, st = _open_backup(name)
    os.close(fd)  # opened again by the stream itself – an answer that is never sent leaves nothing open
    starts.append(now)
    _dl_starts[user_id] = starts
    # the slot is claimed here, in the same step as the check (no await in between): a second request in parallel finds
    # it taken. Freed by release_download – when the stream ends, fails or is cancelled, or the answer is never sent
    token = secrets.token_hex(8)
    _dl_running[user_id] = (token, now)
    return Download(name=name, size=st.st_size, dev=st.st_dev, ino=st.st_ino, token=token)


def release_download(dl: Download, user_id: str) -> None:
    """Frees the admin's slot – only when it is still this download's (a newer one, after a stale slot, keeps its own).
    Called more than once for one download (the stream's end and the answer's end): harmless."""
    held = _dl_running.get(user_id)
    if held is not None and held[0] == dl.token:
        del _dl_running[user_id]


async def stream_download(dl: Download, user_id: str):  # noqa: ANN201 - an async iterator of bytes
    """The file in chunks, never whole in memory – the same file that was checked (device and inode), exactly the size
    announced (Content-Length). A backup removed by the retention meanwhile is still read to its end (open descriptor).
    The slot was claimed by prepare_download; freed here at the end (also on an error or a cancel)."""
    fd = -1
    try:
        fd, st = _open_backup(dl.name)
        if (st.st_dev, st.st_ino) != (dl.dev, dl.ino):
            raise DownloadRefused(404, "not_found")  # replaced since the check: the answer ends short, never another file
        left = dl.size
        while left > 0:
            chunk = await asyncio.to_thread(os.read, fd, min(DOWNLOAD_CHUNK, left))
            if not chunk:
                break
            left -= len(chunk)
            yield chunk
        if left:
            log.warning("backup download %s ended %d bytes short", dl.name, left)
    finally:
        if fd >= 0:
            os.close(fd)
        release_download(dl, user_id)


# ---------------------------------------------------------------- restore


# What a backup may contain, at most how big (None: no limit – the dump). Only plain files; anything else is refused.
MEMBERS: dict[str, int | None] = {"manifest.json": 1 << 20, "manifest.sig": 4096, "secrets.json": 64 << 10, "db.dump": None}
_REGULAR = (tarfile.REGTYPE, tarfile.AREGTYPE)


def _extract(tf: tarfile.TarFile, work: Path) -> None:
    """Only the expected names, each once, only plain files (no links, devices, sparse files), within their size
    limits – copied by hand, so nothing but these files ever lands in `work`."""
    seen: set[str] = set()
    for m in tf:
        cap = MEMBERS.get(m.name, -1)
        if cap == -1 or m.type not in _REGULAR or m.name in seen:
            raise BackupError(f"unexpected entry in the backup: {m.name!r}")
        if cap is not None and m.size > cap:
            raise BackupError(f"{m.name}: larger than a backup's ({m.size} bytes)")
        seen.add(m.name)
        src = tf.extractfile(m)
        if src is None:
            raise BackupError(f"unexpected entry in the backup: {m.name!r}")
        fd = os.open(work / m.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
    if "manifest.json" not in seen or "db.dump" not in seen:
        raise BackupError("not a Cobe News backup: manifest or dump missing")


def _unpack(path: Path, work: Path, passphrase: str) -> tuple[dict, str]:
    """The backup's files into `work` – checked: only the expected names, checksums as in its manifest – and how it is
    known to be genuine: "passphrase" (encrypted: decrypting proves it), "signature" (unencrypted, signed with this
    installation's master key), "other-key" (signed with another key – cannot be checked here) or "unsigned" (made
    before 0.1.22). A signature that does not match is refused outright."""
    tar_path = path
    sealed = crypto.is_sealed(path)
    if sealed:
        if not passphrase:
            raise BackupError("the backup is encrypted: BACKUP_PASSPHRASE, BACKUP_PASSPHRASE_FILE or --passphrase-file needed")
        tar_path = work / "archive.tar"
        try:
            with path.open("rb") as src, tar_path.open("wb") as dst:
                crypto.open_sealed(src, dst, passphrase)
        except crypto.DecryptError as exc:
            raise BackupError("cannot decrypt: wrong passphrase, or the file was changed or cut off") from exc
    try:
        with tarfile.open(tar_path, mode="r:") as tf:
            _extract(tf, work)
    except tarfile.TarError as exc:
        raise BackupError(f"not a readable backup: {exc}") from exc
    finally:
        if sealed:
            with contextlib.suppress(OSError):
                tar_path.unlink()
    raw = (work / "manifest.json").read_bytes()
    try:
        manifest = json.loads(raw)
    except ValueError as exc:
        raise BackupError("the backup has no readable manifest") from exc
    if not isinstance(manifest, dict) or manifest.get("app") != "cobe-news" or manifest.get("format") != FORMAT:
        raise BackupError("not a Cobe News backup of a known format")
    auth = "passphrase" if sealed else _signature(work, raw)
    files = manifest.get("files")
    if not isinstance(files, dict) or "db.dump" not in files or not set(files) <= {"db.dump", "secrets.json"}:
        raise BackupError("the backup's manifest lists unexpected files")
    for n, meta in files.items():
        f = work / n
        if not isinstance(meta, dict) or not f.is_file() or f.stat().st_size != meta.get("size") or _sha256(f) != meta.get("sha256"):
            raise BackupError(f"{n}: checksum does not match – the backup is damaged")
    if (work / "secrets.json").is_file() and "secrets.json" not in files:
        raise BackupError("the backup's manifest lists unexpected files")
    if not isinstance(manifest.get("rows"), dict) or not all(isinstance(v, int) for v in manifest["rows"].values()):
        raise BackupError("the backup's manifest has no row counts")
    return manifest, auth


def _signature(work: Path, manifest: bytes) -> str:
    sig = work / "manifest.sig"
    if not sig.is_file():
        return "unsigned"
    try:
        meta = json.loads(sig.read_text())
        mac, kid = str(meta["mac"]), str(meta["key_id"])
    except (ValueError, KeyError, TypeError) as exc:
        raise BackupError("the backup's signature is unreadable") from exc
    if kid != crypto.key_id():
        return "other-key"
    if not hmac.compare_digest(mac, crypto.backup_mac(manifest)):
        raise BackupError("the signature does not match: the backup was changed after it was made – not restored")
    return "signature"


# Entries a dump of Cobe News has (pg_restore -l): tables with their data, sequences, defaults, constraints, indexes and
# the trigram extension. A function, trigger, rule, view, policy, large object, another schema or extension in a backup
# was not made by Cobe News – refused before anything is touched. (The restore checks the result once more: _SCHEMA.)
_TOC_OK = (
    "TABLE DATA public ",
    "TABLE public ",
    "SEQUENCE SET public ",
    "SEQUENCE OWNED BY public ",
    "SEQUENCE public ",
    "FK CONSTRAINT public ",
    "CONSTRAINT public ",
    "INDEX public ",
    "DEFAULT public ",
    "EXTENSION - pg_trgm ",
    "COMMENT - EXTENSION pg_trgm ",
)
_TOC_LINE = re.compile(r"^\d+; \d+ \d+ (.*)$")
# a dump made after a restore of up to 0.1.21 also names the schema public itself (re-created then, not in its
# default state): left out – the restore makes it anew, in its default state (RESET)
_TOC_SKIP = ("SCHEMA - public ", "COMMENT - SCHEMA public ")
RESET = (
    "DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION pg_database_owner; GRANT USAGE ON SCHEMA public TO PUBLIC; "
    "COMMENT ON SCHEMA public IS 'standard public schema';"
)


def _toc_check(dump: Path) -> Path:
    """The dump's table of contents checked (_TOC_OK) and written as the list pg_restore restores (--use-list)."""
    try:
        out = subprocess.run(["pg_restore", "--list", str(dump)], capture_output=True, timeout=300, check=False)  # noqa: S603, S607
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupError(f"pg_restore --list: {type(exc).__name__}") from exc
    if out.returncode != 0:
        raise BackupError(f"not a readable dump: {out.stderr.decode(errors='replace').strip()[-300:]}")
    bad, keep = [], []
    for line in out.stdout.decode(errors="replace").splitlines():
        if not line.strip() or line.startswith(";"):
            continue
        m = _TOC_LINE.match(line)
        if m is not None and (m.group(1) + " ").startswith(_TOC_SKIP):
            continue
        if m is None or not (m.group(1) + " ").startswith(_TOC_OK):
            bad.append(line.strip()[:120])
        keep.append(line)
    if bad:
        raise BackupError(f"the dump holds objects Cobe News never makes ({len(bad)}, e.g. {bad[:3]}) – not restored")
    listed = dump.with_name("toc.list")
    listed.write_text("\n".join(keep) + "\n")
    return listed


@dataclass
class Plan:
    manifest: dict
    work: Path
    key_matches: bool
    backup_key: str | None  # the master key in the backup (only an encrypted one has it)
    auth: str = "passphrase"  # how it is known to be genuine (_unpack)


def prepare(path: Path, passphrase: str, *, allow_unsigned: bool = False) -> Plan:
    """Everything a restore checks before it changes anything (CLI: shown, then confirmed)."""
    if not path.is_file():
        raise BackupError(f"{path}: no such file")
    work = _workdir(".restore-")
    try:
        manifest, auth = _unpack(path, work, passphrase)
        if auth in ("unsigned", "other-key") and not allow_unsigned:
            why = (
                "it is signed with another master key than this installation's (SECRET_KEY / data/secret.key) – set that key"
                if auth == "other-key"
                else "it has no signature (made before 0.1.22, unencrypted)"
            )
            raise BackupError(
                f"cannot tell whether the backup is genuine: {why}. Restore only a file you know is yours: --allow-unsigned restores it anyway"
            )
        known = _revisions()
        if manifest.get("revision") not in known:
            raise BackupError(f"the backup's schema ({manifest.get('revision')}) is newer than this version ({__version__}) – restore it with that version or newer")
        _toc_check(work / "db.dump")  # writes work/toc.list
        key = None
        if (work / "secrets.json").is_file():
            key = json.loads((work / "secrets.json").read_text()).get("secret_key")
        return Plan(manifest=manifest, work=work, key_matches=manifest.get("key_id") == crypto.key_id(), backup_key=key, auth=auth)
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise


def _revisions() -> set[str]:
    from alembic.script import ScriptDirectory

    return {r.revision for r in ScriptDirectory.from_config(db.alembic_config()).walk_revisions()}


async def others_connected() -> int:
    """Other sessions on the database (a running app): a restore under them would mix states."""
    async with db.engine().connect() as conn:
        return int(
            await conn.scalar(text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() AND backend_type = 'client backend'"))
            or 0
        )


async def superuser() -> bool:
    """Restoring as a superuser would let a crafted dump run anything on the database server (docs/BETRIEB.md: PostgreSQL)."""
    async with db.engine().connect() as conn:
        return bool(await conn.scalar(text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")))


# Everything in the database a dump can bring along, as sorted lines: relations, columns (type, NOT NULL, identity,
# default), constraints, indexes, triggers, rules, policies, functions, types, operators, schemas, extensions, settings
# of the database and the role, large objects, publications. Objects of an extension (pg_trgm) are left out. A restore
# must end with exactly the lines a freshly migrated schema of the backup's revision has – checked inside its
# transaction (_pipe_restore), so a dump with a trigger, a function, a changed default or another schema is rolled
# back as a whole.
_NOT_EXT = "NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = '{cat}'::regclass AND d.objid = {obj} AND d.deptype = 'e')"
_SYS = "('pg_catalog'::regnamespace, 'information_schema'::regnamespace)"
_SCHEMA = f"""SELECT coalesce(jsonb_agg(x ORDER BY x), '[]'::jsonb) FROM (
  SELECT format('rel %s %s %s %s %s', c.relname, c.relkind, c.relpersistence, c.relrowsecurity, coalesce(c.relacl::text, '')) AS x
    FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND {_NOT_EXT.format(cat="pg_class", obj="c.oid")}
  UNION ALL
  SELECT format('col %s.%s %s %s %s %s %s', c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attidentity, a.attgenerated,
                coalesce(pg_get_expr(ad.adbin, ad.adrelid), ''))
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
   WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum > 0 AND NOT a.attisdropped
  UNION ALL
  SELECT format('con %s %s %s', co.conrelid::regclass, co.conname, pg_get_constraintdef(co.oid)) FROM pg_constraint co WHERE co.connamespace NOT IN {_SYS}
  UNION ALL
  SELECT format('idx %s', pg_get_indexdef(i.indexrelid)) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relnamespace NOT IN {_SYS}
     AND c.relnamespace <> 'pg_toast'::regnamespace
  UNION ALL
  SELECT format('trg %s', pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace NOT IN {_SYS}
  UNION ALL
  SELECT format('rule %s %s', r.ev_class::regclass, r.rulename) FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class WHERE c.relnamespace NOT IN {_SYS}
  UNION ALL
  SELECT format('policy %s %s', p.polrelid::regclass, p.polname) FROM pg_policy p
  UNION ALL
  SELECT format('func %s', p.oid::regprocedure) FROM pg_proc p WHERE p.pronamespace NOT IN {_SYS} AND {_NOT_EXT.format(cat="pg_proc", obj="p.oid")}
  UNION ALL
  SELECT format('type %s.%s %s', t.typnamespace::regnamespace, t.typname, t.typtype) FROM pg_type t
   WHERE t.typnamespace NOT IN {_SYS} AND t.typnamespace <> 'pg_toast'::regnamespace AND t.typrelid = 0 AND t.typcategory <> 'A'
     AND {_NOT_EXT.format(cat="pg_type", obj="t.oid")}
  UNION ALL
  SELECT format('operator %s', o.oid::regoperator) FROM pg_operator o WHERE o.oprnamespace NOT IN {_SYS} AND {_NOT_EXT.format(cat="pg_operator", obj="o.oid")}
  UNION ALL
  SELECT format('opclass %s', oc.opcname) FROM pg_opclass oc WHERE oc.opcnamespace NOT IN {_SYS} AND {_NOT_EXT.format(cat="pg_opclass", obj="oc.oid")}
  UNION ALL
  SELECT format('opfamily %s', f.opfname) FROM pg_opfamily f WHERE f.opfnamespace NOT IN {_SYS} AND {_NOT_EXT.format(cat="pg_opfamily", obj="f.oid")}
  UNION ALL
  SELECT format('collation %s', cl.collname) FROM pg_collation cl WHERE cl.collnamespace NOT IN {_SYS}
  UNION ALL
  SELECT format('conversion %s', cv.conname) FROM pg_conversion cv WHERE cv.connamespace NOT IN {_SYS}
  UNION ALL
  SELECT format('tsconfig %s', ts.cfgname) FROM pg_ts_config ts WHERE ts.cfgnamespace NOT IN {_SYS}
  UNION ALL
  SELECT format('tsdict %s', td.dictname) FROM pg_ts_dict td WHERE td.dictnamespace NOT IN {_SYS}
  UNION ALL
  SELECT format('statistics %s', se.stxname) FROM pg_statistic_ext se WHERE se.stxnamespace NOT IN {_SYS}
  UNION ALL
  SELECT format('cast %s %s', ca.castsource::regtype, ca.casttarget::regtype) FROM pg_cast ca WHERE ca.oid >= 16384 AND {_NOT_EXT.format(cat="pg_cast", obj="ca.oid")}
  UNION ALL
  SELECT format('schema %s %s', n.nspname, coalesce(n.nspacl::text, '')) FROM pg_namespace n
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND n.nspname NOT LIKE 'pg\\_temp\\_%' AND n.nspname NOT LIKE 'pg\\_toast\\_temp\\_%'
  UNION ALL
  SELECT format('ext %s %s', e.extname, e.extnamespace::regnamespace) FROM pg_extension e
  UNION ALL
  SELECT format('setting %s %s', s.setrole, array_to_string(s.setconfig, ',')) FROM pg_db_role_setting s
   WHERE s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database()) OR s.setrole = (SELECT oid FROM pg_roles WHERE rolname = current_user)
  UNION ALL
  SELECT format('database %s', coalesce(d.datacl::text, '')) FROM pg_database d WHERE d.datname = current_database()
  UNION ALL
  SELECT format('event-trigger %s', et.evtname) FROM pg_event_trigger et
  UNION ALL
  SELECT format('publication %s', pb.pubname) FROM pg_publication pb
  UNION ALL
  SELECT 'large-objects' FROM pg_largeobject_metadata HAVING count(*) > 0
) s"""


async def reference_schema(revision: str) -> list[str]:
    """_SCHEMA of a freshly migrated database at `revision` – made in a transaction on this database that is rolled
    back (the app is stopped; nothing changes)."""
    from alembic import command

    async with db.engine().connect() as conn:
        trans = await conn.begin()
        try:
            await conn.execute(text("SET LOCAL statement_timeout = 0"))
            for stmt in RESET.split("; "):
                await conn.execute(text(stmt.rstrip(";")))
            await conn.run_sync(lambda c: command.upgrade(db.alembic_config(c), revision))
            await conn.execute(text("SET LOCAL search_path TO public"))  # names print the same way as in the restore's check
            return list(await conn.scalar(text(_SCHEMA)))
        finally:
            await trans.rollback()


# inside the restore's transaction, after the dump: the rows per table must be the manifest's and the schema exactly a
# migrated one – otherwise psql stops (ON_ERROR_STOP) and the whole transaction is rolled back. The counts come in as a
# psql variable (quoted by psql), the schema as a dollar-quoted literal (made here, never from the backup).
_CHECK_ROWS = """SELECT set_config('cobe_news.rows', :'rows', false);
DO $check$
DECLARE r record; n bigint; bad text := '';
BEGIN
  FOR r IN SELECT key, value::bigint AS want FROM jsonb_each_text(current_setting('cobe_news.rows')::jsonb) LOOP
    EXECUTE format('SELECT count(*) FROM public.%I', r.key) INTO n;
    IF n <> r.want THEN bad := bad || format('%s %s (backup %s) ', r.key, n, r.want); END IF;
  END LOOP;
  IF bad <> '' THEN RAISE EXCEPTION 'rows differ from the backup: %', bad; END IF;
END $check$;
"""
_CHECK_SCHEMA = """SET search_path TO public;
DO $check$
DECLARE got jsonb; want jsonb := {lit}::jsonb; extra text; missing text;
BEGIN
  got := ({schema});
  IF got IS DISTINCT FROM want THEN
    SELECT string_agg(x, ' | ') INTO extra FROM (SELECT x FROM (SELECT jsonb_array_elements_text(got) EXCEPT SELECT jsonb_array_elements_text(want)) e(x) ORDER BY x LIMIT 5) s;
    SELECT string_agg(x, ' | ') INTO missing FROM (SELECT x FROM (SELECT jsonb_array_elements_text(want) EXCEPT SELECT jsonb_array_elements_text(got)) e(x) ORDER BY x LIMIT 5) s;
    RAISE EXCEPTION 'the dump does not make the schema of a Cobe News database – unexpected: [%] missing: [%]', coalesce(extra, ''), coalesce(missing, '');
  END IF;
END $check$;
"""
PIPE_CHUNK = 1 << 16


def _dollar(value: str) -> str:
    tag = f"$ref{secrets.token_hex(8)}$"
    assert tag not in value
    return f"{tag}{value}{tag}"


def _lower_priority(*procs) -> None:  # noqa: ANN002
    """The restore test's helpers at the lowest CPU priority (no right needed to lower one's own children)."""
    for p in procs:
        with contextlib.suppress(OSError, AttributeError):
            os.setpriority(os.PRIO_PROCESS, p.pid, 19)


async def _pipe_restore(
    dump: Path, rows: dict[str, int], schema: list[str] | None = None, timeout: float = DUMP_TIMEOUT_S, *, env: dict[str, str] | None = None, low_priority: bool = False
) -> None:
    """pg_restore's SQL streamed into psql – never the whole script in memory (a big database in a 512m container).
    psql runs the reset, the dump and the checks as one transaction; only when pg_restore ended well does psql see the
    end of its input – otherwise psql is killed mid-transaction and PostgreSQL rolls everything back.
    `env`: libpq's environment of another database (the restore test's – _pg_env(url)); the app's own by default."""
    env = env if env is not None else _pg_env()
    listed = dump.with_name("toc.list")
    with tempfile.NamedTemporaryFile("w", suffix=".sql", dir=dump.parent, delete=False) as f:
        f.write(_CHECK_ROWS)
        if schema is not None:
            f.write(_CHECK_SCHEMA.format(lit=_dollar(json.dumps(schema)), schema=_SCHEMA))
        check = f.name
    src = await asyncio.create_subprocess_exec(
        "pg_restore", "--no-owner", "--no-privileges", "--file=-", *([f"--use-list={listed}"] if listed.is_file() else []), str(dump), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
    )
    dst = await asyncio.create_subprocess_exec(
        "psql", "--no-psqlrc", "--quiet", "--single-transaction", "--set=ON_ERROR_STOP=1", f"--set=rows={json.dumps(rows)}",
        f"--command={RESET}", "--file=-", f"--file={check}",
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env,
    )  # fmt: skip
    if low_priority:
        _lower_priority(src, dst)
    err_src = asyncio.ensure_future(src.stderr.read())
    err_dst = asyncio.ensure_future(dst.stderr.read())

    async def pump() -> None:
        assert src.stdout is not None and dst.stdin is not None
        while chunk := await src.stdout.read(PIPE_CHUNK):
            dst.stdin.write(chunk)
            await dst.stdin.drain()  # back pressure: pg_restore waits for psql, nothing piles up here

    ok = False
    try:
        try:
            await asyncio.wait_for(pump(), timeout)
            rc_src = await asyncio.wait_for(src.wait(), 60)
        except (BrokenPipeError, ConnectionResetError):
            rc_src = await asyncio.wait_for(src.wait(), 60)  # psql stopped reading (it failed): its own error says why
        if rc_src != 0:
            raise BackupError(f"pg_restore failed: {(await err_src).decode(errors='replace').strip()[-400:]}")
        dst.stdin.close()  # the end of the dump: psql goes on with the check and commits
        rc_dst = await asyncio.wait_for(dst.wait(), timeout)
        if rc_dst != 0:
            raise BackupError(f"psql failed (nothing changed): {(await err_dst).decode(errors='replace').strip()[-400:]}")
        ok = True
    except TimeoutError:
        raise BackupError(f"restore: no end within {timeout:.0f} s (nothing changed)") from None
    finally:
        for proc in (dst, src) if not ok else ():
            with contextlib.suppress(ProcessLookupError):
                proc.kill()  # psql killed before its input ended: PostgreSQL rolls the open transaction back
            with contextlib.suppress(Exception):
                await proc.wait()
        err_src.cancel()
        err_dst.cancel()
        with contextlib.suppress(OSError):
            os.unlink(check)


async def restore(plan: Plan) -> dict[str, int]:
    """The dump of `plan` replaces the database, in one transaction that also checks the counts and the schema; then
    the schema migrated to this version."""
    want = {str(k): int(v) for k, v in (plan.manifest.get("rows") or {}).items()}
    reference = await reference_schema(str(plan.manifest.get("revision")))
    await _pipe_restore(plan.work / "db.dump", want, reference)
    await db.dispose()  # pooled connections knew the old tables
    db.init(get_config().database_url)
    async with db.engine().connect() as conn:
        rows = await table_counts(conn)
    diff = {t: (rows.get(t), n) for t, n in want.items() if rows.get(t) != n}
    if diff:
        raise BackupError(f"restored, but the rows differ from the backup's: {diff} – the backup made before the restore is the way back")
    await db.migrate()
    return rows


def write_key(key: str) -> Path:
    """The backup's master key as data/secret.key (the old one kept next to it) – only without SECRET_KEY."""
    cfg = get_config()
    path = cfg.data_dir / crypto.KEY_FILE
    if path.exists():
        path.rename(path.with_name(f"{crypto.KEY_FILE}.before-restore-{datetime.now(UTC):%Y%m%d-%H%M%S}"))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    crypto.reset_cache()
    return path


# ---------------------------------------------------------------- export (no secrets)


async def export_data(s: AsyncSession) -> dict:
    from app import vendor_catalog as catalog
    from app.models import NewsSource, NotifyChannel, NotifyRule, NotifyRuleChannel, User, VendorFollow, VendorVersion

    def at(v: datetime | None) -> str | None:
        return v.isoformat() if v else None

    sources = list(await s.scalars(select(NewsSource).order_by(NewsSource.builtin.desc(), NewsSource.key)))
    src_name = {str(x.id): x.name for x in sources}
    channels = list(await s.scalars(select(NotifyChannel).order_by(NotifyChannel.name)))
    ch_name = {x.id: x.name for x in channels}
    links: dict = {}
    for rc in await s.scalars(select(NotifyRuleChannel)):
        links.setdefault(rc.rule_id, []).append(ch_name.get(rc.channel_id, str(rc.channel_id)))
    rules = list(await s.scalars(select(NotifyRule).order_by(NotifyRule.name)))
    follows = list(await s.scalars(select(VendorFollow).order_by(VendorFollow.product)))
    vers: dict = {}
    for v in await s.scalars(select(VendorVersion).order_by(VendorVersion.version)):
        vers.setdefault(v.follow_id, []).append({"version": v.version, "label": v.label, "count": v.count})
    users = list(await s.scalars(select(User).order_by(User.username)))
    return {
        "app": "cobe-news",
        "version": __version__,
        "exported_at": datetime.now(UTC).isoformat(),
        "rules": [
            {
                "name": r.name,
                "enabled": r.enabled,
                "kinds": list(r.kinds or []),
                "severities": list(r.severities or []),
                "sources": [src_name.get(x, x) for x in r.sources or []],
                "lang": r.lang,
                "channels": sorted(links.get(r.id, [])),
                "created_at": at(r.created_at),
                "active_since": at(r.active_since),
            }
            for r in rules
        ],
        "channels": [
            {
                "name": c.name,
                "type": c.type,
                # not secret: recipients, chat id, header name, flags – the secrets themselves only by name
                "config": dict(c.config or {}),
                "secrets_set": sorted((c.secrets or {}).keys()),
                "target": c.target,
                "created_at": at(c.created_at),
                "last_sent_at": at(c.last_sent_at),
                "last_error": c.last_error,
            }
            for c in channels
        ],
        "sources": [
            {"key": x.key, "name": x.name, "url": x.url, "site": x.site, "builtin": x.builtin, "enabled": x.enabled, "last_ok_at": at(x.last_ok_at), "error": x.error}
            for x in sources
        ],
        "follows": [
            {
                "product": f.product,
                "label": ((f.custom or {}).get("label") or (catalog.product(f.product) or {}).get("label") or f.product),
                "enabled": f.enabled,
                "note": f.note,
                "tags": list(f.tags or []),
                "cpe": (f.custom or {}).get("cpe"),
                "versions": vers.get(f.id, []),
            }
            for f in follows
        ],
        "users": [
            {
                "username": u.username,
                "display_name": u.display_name,
                "email": u.email,
                "role": u.role,
                "auth_source": u.auth_source,
                "active": u.is_active,
                "deactivated_reason": u.deactivated_reason,
                "emergency": u.is_emergency,
                "totp": bool(u.totp_secret_enc),
                "created_at": at(u.created_at),
                "last_login_at": at(u.last_login_at),
            }
            for u in users
        ],
    }


def _cell(v: object) -> str:
    """A CSV cell: lists joined, objects as JSON – and never a formula (a leading = + - @ is quoted for spreadsheets)."""
    if v is None:
        s = ""
    elif isinstance(v, bool):
        s = "true" if v else "false"
    elif isinstance(v, list) and all(not isinstance(x, (dict, list)) for x in v):
        s = "; ".join(str(x) for x in v)
    elif isinstance(v, (dict, list)):
        s = json.dumps(v, ensure_ascii=False, sort_keys=True)
    else:
        s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv_zip(data: dict) -> bytes:
    """One CSV per section in a zip (UTF-8 with BOM – Excel opens it right); a followed product with versions: a row per version."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for section in ("rules", "channels", "sources", "follows", "users"):
            rows = data[section]
            if section == "follows":
                rows = [
                    {**{k: v for k, v in f.items() if k != "versions"}, "version": x.get("version"), "version_label": x.get("label"), "version_count": x.get("count")}
                    for f in rows
                    for x in (f["versions"] or [{}])
                ]
            out = io.StringIO()
            cols = list(rows[0].keys()) if rows else []
            w = csv.writer(out)
            w.writerow(cols)
            for r in rows:
                w.writerow([_cell(r.get(c)) for c in cols])
            zf.writestr(f"{section}.csv", "﻿" + out.getvalue())
    return buf.getvalue()


async def export_file(s: AsyncSession, fmt: str) -> tuple[bytes, str, str]:
    data = await export_data(s)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    if fmt == "csv":
        return to_csv_zip(data), f"cobe-news-export-{stamp}.zip", "application/zip"
    return json.dumps(data, ensure_ascii=False, indent=1).encode(), f"cobe-news-export-{stamp}.json", "application/json"
