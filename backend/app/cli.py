"""Server-side commands (docker compose exec app python -m app.cli …).

  reset-emergency       new temporary password for the emergency admin, its TOTP and passkeys removed, all its
                        sessions ended
  new-setup-token       only while no emergency admin exists: a fresh one-time setup token
  rotate-vapid          a new Web Push key pair (the old one leaked); every browser subscribes again by itself
  migrate               the database schema brought to this version (the app does it at every start, too)
  migrate-sqlite FILE   a 0.1.15 SQLite file (/data/news.db) moved into the empty PostgreSQL database – the file stays
                        unchanged; refuses a database that holds data (the app does this by itself at its first start)
  backup                a backup now (BACKUP_DIR, default /data/backups) – with BACKUP_PASSPHRASE encrypted, with the key
  restore FILE [--yes] [--use-backup-key | --ignore-key] [--allow-unsigned]
                        a backup back – with the app stopped (docs/BETRIEB.md: Sicherung); a backup of the current state first.
                        An unencrypted backup must carry this installation's signature (0.1.22 on) – --allow-unsigned
                        restores an older or foreign one anyway (only a file you know is yours)
  export [--format json|csv] [--out FILE]
                        rules, channels, sources, followed products and users without secrets (default: JSON to stdout)
  restore-test          the newest backup restored into the throwaway database and checked (docs/BETRIEB.md: Rücksicherungs-Test)
                        – never into the app's database; exit code 0: passed, 1: failed (scripts/restore-test.sh)

  --passphrase-file F   (backup, restore, restore-test) the passphrase from a file instead of BACKUP_PASSPHRASE –
                        "-": from standard input (docker compose exec -T app … --passphrase-file - < file)
"""

import asyncio
import contextlib
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from app import audit, backup, db, passkeys_api, sqlite_import, webpush
from app.auth import passwords, sessions
from app.auth_api import issue_setup_token
from app.config import get_config
from app.models import User


def _opt(args: list[str], name: str, default: str | None = None) -> str | None:
    if name in args:
        i = args.index(name)
        if i + 1 >= len(args):
            raise SystemExit(f"{name} needs a value")
        return args[i + 1]
    return default


def _passphrase(args: list[str]) -> str:
    f = _opt(args, "--passphrase-file")
    if f == "-":
        return sys.stdin.readline().strip()
    if f:
        return Path(f).read_text().strip()
    return get_config().backup_passphrase


async def _account(cmd: str) -> int:
    async with db.session() as s:
        if cmd == "reset-emergency":
            u = await s.scalar(select(User).where(User.is_emergency.is_(True)))
            if u is None:
                print("No emergency admin yet – finish the setup first.")
                return 1
            pw = passwords.temp_password()
            await passwords.remember(s, u)  # its own password stays refused after the reset (not a temporary one)
            u.password_hash, u.must_change_password, u.temp_password_at = passwords.hash_password(pw), True, datetime.now(UTC)
            u.totp_secret_enc = u.totp_last_step = None
            u.is_active, u.deactivated_reason = True, None
            # its passkeys go too: the reset is the way back in after a takeover – none the other person registered stays
            gone = await passkeys_api.remove_all_of(s, u.id)
            await sessions.revoke_all(s, u.id)
            audit.record(s, audit.CLI, "user.reset", audit.user_target(u), {"password": True, "totp": True, "sessions_ended": True, "emergency_admin": True})
            if gone:
                audit.record(s, audit.CLI, "passkey.removed", audit.user_target(u), {"by_admin": False, "reset": True, "count": gone, "emergency_admin": True})
            await s.commit()
            # no bruteforce.unlock here: the counters live in the app's memory, not in this process – and the emergency
            # admin is never locked anyway (auth/bruteforce.py: its checks are slowed down instead)
            print(f"Emergency admin '{u.username}': temporary password {pw}" + (f" ({gone} passkey(s) removed)" if gone else "") + "\nSign in, set a new password and set up TOTP again.")
            return 0
        if cmd == "rotate-vapid":
            key = await webpush.vapid(s, rotate=True)
            audit.record(s, audit.CLI, "settings.changed", audit.target("settings", "webpush", "webpush"), {"changes": {"vapid_key": dict(audit.SECRET_MARK)}})
            await s.commit()
            print(f"New Web Push key: {key.public}\nThe subscriptions of the old key are removed; browsers subscribe again on their next visit.")
            return 0
        token = await issue_setup_token(s)
        print(f"Setup token: {token}" if token else "Setup is already done.")
        return 0


async def _migrate_sqlite(args: list[str]) -> int:
    if not args:
        print("migrate-sqlite FILE (e.g. /data/news.db)")
        return 2
    path = Path(args[0])

    def progress(table: str, done: int, total: int) -> None:
        if done == total or done % 20000 == 0:
            print(f"  {table}: {done}/{total}", file=sys.stderr, flush=True)

    try:
        report = await sqlite_import.run(path, progress=progress)
    except sqlite_import.ImportRefused as exc:
        print(f"Not imported: {exc}")
        return 1
    print(f"Imported {path} into PostgreSQL (the file is unchanged):")
    print("\n".join(report.lines()))
    sqlite_import._note(path, report)
    return 0


async def _restore(args: list[str]) -> int:
    if not args or args[0].startswith("--"):
        print("restore FILE [--yes] [--use-backup-key | --ignore-key] [--allow-unsigned] [--passphrase-file F]")
        return 2
    try:
        plan = await asyncio.to_thread(backup.prepare, Path(args[0]), _passphrase(args), allow_unsigned="--allow-unsigned" in args)
    except backup.BackupError as exc:
        print(f"Not restored: {exc}")
        return 1
    try:
        m = plan.manifest
        print(f"Backup of {m.get('created_at')} – Cobe News {m.get('version')}, schema {m.get('revision')}, {sum((m.get('rows') or {}).values())} rows")
        print(
            {
                "passphrase": "Genuine: encrypted with the passphrase.",
                "signature": "Genuine: signed with this installation's key.",
                "other-key": "WARNING: signed with another key – not checked (--allow-unsigned).",
                "unsigned": "WARNING: no signature – not checked (--allow-unsigned).",
            }[plan.auth]
        )
        if await backup.superuser():
            print("WARNING: connected as a database superuser – Cobe News should use its own role (docs/BETRIEB.md: PostgreSQL, Rollen).")
        cfg = get_config()
        if not plan.key_matches:
            if plan.backup_key and "--use-backup-key" in args:
                if cfg.secret_key:
                    print("The backup has another key than SECRET_KEY in .env. Put the backup's key into .env (SECRET_KEY) or remove SECRET_KEY, then run this again.")
                    return 1
                print("The backup's key replaces data/secret.key (the current one is kept next to it).")
            elif "--ignore-key" in args:
                print("WARNING: other key – the stored secrets (webhook URLs, SMTP/LDAP passwords, TOTP of local accounts) will be unreadable.")
            else:
                hint = "--use-backup-key takes the key from the backup" if plan.backup_key else "the backup has no key (made without a passphrase)"
                print(f"Not restored: the backup was made with another master key than this installation's (SECRET_KEY / data/secret.key) – {hint}; --ignore-key restores anyway.")
                return 1
        others = await backup.others_connected()
        if others:
            print(f"Not restored: {others} other connection(s) to the database – stop the app first: docker compose stop app, then")
            print("  docker compose run --rm --no-deps app python -m app.cli restore …")
            return 1
        if "--yes" not in args:
            if not sys.stdin.isatty():
                print("Not restored: confirm with --yes (no terminal to ask).")
                return 1
            if input("Everything in the database is replaced by the backup. Type RESTORE to go on: ").strip() != "RESTORE":
                print("Not restored.")
                return 1
        # a new server (the app never started): the schema first – the check below and the backup of the current state
        # need its tables; the restore replaces it anyway
        await db.migrate()
        async with db.engine().connect() as conn:
            empty = await sqlite_import.target_empty(conn)
        before = None
        if not empty:
            before = await backup.create(reason="pre-restore", passphrase=_passphrase(args) or None, actor=audit.CLI)
            print(f"Current state saved first: {before.path}")
        rows = await backup.restore(plan)
        await backup.record_restored(before, plan.manifest, Path(args[0]).name)
        # in the restored database (its log is the backup's): the restore itself, and the backup made right before it
        async with db.session() as s:
            audit.record(
                s,
                audit.CLI,
                "backup.restored",
                audit.target("backup", Path(args[0]).name, Path(args[0]).name),
                {"backup_created_at": m.get("created_at"), "version": m.get("version"), "revision": m.get("revision"), "auth": plan.auth, "rows": sum(rows.values()), "pre_restore": before.name if before else None},
            )
            await s.commit()
        if not plan.key_matches and plan.backup_key and "--use-backup-key" in args:
            print(f"Key written: {backup.write_key(plan.backup_key)}")
        print(f"Restored: {sum(rows.values())} rows, schema now {await db.revision()}. Start the app: docker compose start app.")
        return 0
    except backup.BackupError as exc:
        print(f"Restore failed: {exc}")
        return 1
    finally:
        shutil.rmtree(plan.work, ignore_errors=True)


async def _restore_test(args: list[str]) -> int:
    """The restore test from the host's cron (scripts/restore-test.sh): read with the passphrase the cron job holds, at
    the lowest CPU priority. Recorded like the app's own runs (page Sicherung & Export, /metrics)."""
    import os

    from app import restore_test

    with contextlib.suppress(OSError):
        os.nice(19)
    out = await restore_test.run(passphrase=_passphrase(args) or None, trigger="cli")
    if out["ok"]:
        print(f"Restore test passed: {out.get('name')} – {out.get('tables')} tables, {out.get('rows')} rows, schema {out.get('revision')}, {out['seconds']} s")
        return 0
    print(f"Restore test FAILED ({out.get('code')}): {out.get('name') or '-'} – {out.get('error')}")
    return 1


async def _main(argv: list[str]) -> int:
    cmd, args = (argv[0] if argv else ""), argv[1:]
    if cmd not in ("reset-emergency", "new-setup-token", "rotate-vapid", "migrate", "migrate-sqlite", "backup", "restore", "export", "restore-test"):
        print(__doc__)
        return 2
    db.init(get_config().database_url, name="cobe-news-cli")
    try:
        await db.wait_ready(30)
        if cmd == "restore":
            return await _restore(args)
        if cmd == "restore-test":
            return await _restore_test(args)
        await db.migrate()
        if cmd == "migrate":
            print(f"Schema: {await db.revision()}")
            return 0
        if cmd == "migrate-sqlite":
            return await _migrate_sqlite(args)
        if cmd == "backup":
            phrase = _passphrase(args)
            try:
                res = await backup.create(passphrase=phrase, actor=audit.CLI)
            except backup.BackupError as exc:
                print(f"Backup failed: {exc}")
                return 1
            print(f"{res.path} – {res.size} bytes, {sum(res.rows.values())} rows, {res.seconds} s, {'encrypted, with the key' if res.encrypted else 'not encrypted, without the key'}")
            return 0
        if cmd == "export":
            fmt = _opt(args, "--format", "json")
            if fmt not in ("json", "csv"):
                print("--format json | csv")
                return 2
            async with db.session() as s:
                body, name, _ = await backup.export_file(s, fmt)
            out = _opt(args, "--out", "-")
            if out == "-":
                sys.stdout.buffer.write(body)
            else:
                Path(out).write_bytes(body)
                print(f"{out} ({name}, {len(body)} bytes)")
            return 0
        return await _account(cmd)
    finally:
        await db.dispose()


if __name__ == "__main__":
    sys.exit(asyncio.run(_main(sys.argv[1:])))
