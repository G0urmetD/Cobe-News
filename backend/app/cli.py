"""Server-side commands (docker compose exec app python -m app.cli …).

  reset-emergency       new temporary password for the emergency admin, its TOTP and passkeys removed, all its
                        sessions ended
  new-setup-token       only while no emergency admin exists: a fresh one-time setup token
  rotate-vapid          a new Web Push key pair (the old one leaked); every browser subscribes again by itself
  migrate               the database schema brought to this version (the app does it at every start, too)
  migrate-sqlite FILE   a 0.1.15 SQLite file (/data/news.db) moved into the empty PostgreSQL database – the file stays
                        unchanged; refuses a database that holds data (the app does this by itself at its first start)
  backup                a backup now (BACKUP_DIR, default /data/backups) – with a passphrase encrypted, with the key
  restore FILE [--yes] [--use-backup-key | --ignore-key] [--allow-unsigned]
                        a backup back – with the app stopped (docs/BETRIEB.md: Sicherung); a backup of the current state first.
                        An unencrypted backup must carry this installation's signature (0.1.22 on) – --allow-unsigned
                        restores an older or foreign one anyway (only a file you know is yours)
  export [--format json|csv] [--out FILE]
                        rules, channels, sources, followed products and users without secrets (default: JSON to stdout)
  restore-test          the newest backup restored into the throwaway database and checked (docs/BETRIEB.md: Rücksicherungs-Test)
                        – never into the app's database; exit code 0: passed, 1: failed (scripts/restore-test.sh)
  verify-audit [--accept-new-key]
                        the audit log's integrity chain checked in full, from the oldest kept entry (exit code 0: intact);
                        --accept-new-key: after a new master key, a restore with another key or a changed chain state –
                        the chain starts anew from its newest entry (logged)

  Each of them (but migrate and a plain verify-audit) is in the audit log with the actor "cli".

  --passphrase-file F   (backup, restore, restore-test) the passphrase from a file instead of BACKUP_PASSPHRASE –
                        "-": from standard input (docker compose exec -T app … --passphrase-file - < file)
                        Without it: BACKUP_PASSPHRASE, else the file BACKUP_PASSPHRASE_FILE names, else none.
"""

import asyncio
import contextlib
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete, select

from app import audit, audit_lock, backup, db, passkeys_api, sqlite_import, webpush
from app.auth import passwords, sessions
from app.auth_api import issue_setup_token
from app.config import get_config
from app.models import RememberedDevice, User, UserSession


def _opt(args: list[str], name: str, default: str | None = None) -> str | None:
    if name in args:
        i = args.index(name)
        if i + 1 >= len(args):
            raise SystemExit(f"{name} needs a value")
        return args[i + 1]
    return default


def _passphrase(args: list[str]) -> str | None:
    """--passphrase-file (a file, or "-": standard input) – None without it: the app's own (backup.app_passphrase).
    BackupError when the file cannot be read."""
    f = _opt(args, "--passphrase-file")
    if f == "-":
        return sys.stdin.readline().strip()
    if f:
        return backup.read_passphrase_file(f)
    return None


def _phrase_for_reading(args: list[str]) -> str:
    """The passphrase to open a backup with (restore, restore-test). The app's own file not readable: said, and on
    without – an unencrypted backup needs none; an encrypted one then says what is missing."""
    phrase = _passphrase(args)
    if phrase is not None:
        return phrase
    try:
        return backup.app_passphrase()
    except backup.BackupError as exc:
        print(f"Note: {exc} – going on without a passphrase", file=sys.stderr)
        return ""


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
        if token:
            # the token itself never: only that one was issued here (the setup it allows is logged when it is done)
            audit.record(s, audit.CLI, "setup.token_issued", audit.target("setup", None, None), {"valid_min": 60})
            await s.commit()
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
    async with db.session() as s:
        audit.record(s, audit.CLI, "backup.imported", audit.target("sqlite", path.name, path.name), {"tables": len(report.tables), "rows": sum(report.tables.values())})
        await s.commit()
    print(f"Imported {path} into PostgreSQL (the file is unchanged):")
    print("\n".join(report.lines()))
    sqlite_import._note(path, report)
    return 0


async def _restore(args: list[str]) -> int:
    if not args or args[0].startswith("--"):
        print("restore FILE [--yes] [--use-backup-key | --ignore-key] [--allow-unsigned] [--passphrase-file F] [--allow-superuser]")
        return 2
    try:
        phrase = _phrase_for_reading(args)
        plan = await asyncio.to_thread(backup.prepare, Path(args[0]), phrase, allow_unsigned="--allow-unsigned" in args)
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
            # the documented way restores as the app's own role (cobe_news_app, no superuser): a crafted dump could run
            # anything on the database server as a superuser. --allow-superuser: an own PostgreSQL without such a role
            if "--allow-superuser" not in args:
                print("Not restored: connected as a database superuser – Cobe News restores as its own role (docs/BETRIEB.md: PostgreSQL, Rollen); --allow-superuser restores anyway.")
                return 1
            print("WARNING: connected as a database superuser (--allow-superuser) – Cobe News should use its own role (docs/BETRIEB.md: PostgreSQL, Rollen).")
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
            before = await backup.create(reason="pre-restore", passphrase=phrase or None, actor=audit.CLI)
            print(f"Current state saved first: {before.path}")
        async with db.engine().connect() as conn:
            aside_before = (await audit_lock.state(conn))["set_aside"]
        rows = await backup.restore(plan)
        async with db.engine().connect() as conn:
            lock = await audit_lock.state(conn)
            lock_installed = await audit_lock.installed(conn)
        aside = lock["set_aside"] - aside_before  # the audit log's lock: the entries before set aside, not deleted
        await backup.record_restored(before, plan.manifest, Path(args[0]).name)
        # in the restored database (its log is the backup's): the restore itself, and the backup made right before it.
        # The sessions and remembered devices of the backup's time go – a browser of then must not be back in with them
        async with db.session() as s:
            ended = (await s.execute(delete(UserSession))).rowcount or 0
            forgotten = (await s.execute(delete(RememberedDevice))).rowcount or 0
            audit.record(
                s,
                audit.CLI,
                "backup.restored",
                audit.target("backup", Path(args[0]).name, Path(args[0]).name),
                {
                    "backup_created_at": m.get("created_at"),
                    "version": m.get("version"),
                    "revision": m.get("revision"),
                    "auth": plan.auth,
                    "rows": sum(rows.values()),
                    "pre_restore": before.name if before else None,
                    "sessions_ended": ended,
                    "devices_forgotten": forgotten,
                    **({"set_aside": aside} if lock_installed else {}),
                },
            )
            await s.commit()
        if not plan.key_matches and "--ignore-key" in args:
            # the restored audit log was sealed with the other key: restoring with --ignore-key is the operator's
            # decision – its chain starts anew here (logged: audit.chain_rekeyed)
            await audit.rekey("restore --ignore-key")
            print("Audit log: chain anchored anew with this installation's key (the older part cannot be checked any more).")
        if lock_installed:
            print(
                f"Audit log: database lock {'still active' if lock['active'] else 'NOT active (' + str(lock['reason']) + ')'} – "
                f"{aside} {'entry' if aside == 1 else 'entries'} of the log before set aside, not deleted ({audit_lock.ROLE}.audit_log_replaced)."
            )
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
    try:
        phrase = _phrase_for_reading(args)
    except backup.BackupError as exc:
        print(f"Restore test not started: {exc}")
        return 1
    out = await restore_test.run(passphrase=phrase or None, trigger="cli")
    async with db.session() as s:
        # a finished run with its result (the app's "Test starten" logs the start: restore_test.run)
        audit.record(s, audit.CLI, "restore_test.done", audit.target("restore_test", None, None), {"trigger": "cli", "outcome": "passed" if out["ok"] else "failed", "newest": out.get("name")})
        await s.commit()
    if out["ok"]:
        print(f"Restore test passed: {out.get('name')} – {out.get('tables')} tables, {out.get('rows')} rows, schema {out.get('revision')}, {out['seconds']} s")
        return 0
    print(f"Restore test FAILED ({out.get('code')}): {out.get('name') or '-'} – {out.get('error')}")
    return 1


async def _export(args: list[str]) -> int:
    fmt = _opt(args, "--format", "json")
    if fmt not in ("json", "csv"):
        print("--format json | csv")
        return 2
    async with db.session() as s:
        body, name, _ = await backup.export_file(s, fmt)
        # the same data as the page's export (every account's name and e-mail): logged the same way
        audit.record(s, audit.CLI, "export.downloaded", None, {"format": fmt, "via": "cli"})
        await s.commit()
    out = _opt(args, "--out", "-")
    if out == "-":
        sys.stdout.buffer.write(body)
    else:
        Path(out).write_bytes(body)
        print(f"{out} ({name}, {len(body)} bytes)")
    return 0


def _problem_text(p: dict) -> str:
    where = f"entry #{p['id']} (position {p['seq']})" if p.get("id") else f"position {p['seq']}"
    return {
        "changed": f"changed: {where}",
        "missing": f"{p.get('count', 1)} entr{'y' if p.get('count', 1) == 1 else 'ies'} missing before {where}",
        "link": f"link broken at {where}",
        "tail": f"the newest {p.get('count', 1)} entr{'y' if p.get('count', 1) == 1 else 'ies'} missing – after entry #{p['id']}" if p.get("id") else f"the newest {p.get('count', 1)} missing",
        "anchor": f"the start (position {p['seq']}) is not declared by any prune – entries deleted",
        "state": "the chain state was changed (or is missing)",
        "other_key": "sealed with another master key",
    }.get(p["kind"], f"{p['kind']} at {where}")


async def _verify_audit(args: list[str]) -> int:
    """The audit log's chain, checked from the oldest kept entry to the newest (all of it, not only the new ones).
    --accept-new-key: the operator's step after a new master key, a restore with another key or a changed chain state
    (also to acknowledge problems that were looked into) – the chain starts anew from its newest sealed entry; what lies
    before can no longer be checked (logged: audit.chain_rekeyed)."""
    if "--accept-new-key" in args:
        out = await audit.rekey("verify-audit --accept-new-key")
        print(f"Audit log: chain anchored anew at position {out['anchor_seq']} with this master key.")
    else:
        await audit.seal_all()
        async with db.session() as s:
            st = await audit.chain_state(s)
            if await audit._state_problem(s, st) is None:  # noqa: SLF001 - only a trusted state is restarted at its anchor
                st.pop("verified_seq", None)
                st.pop("verified_hash", None)
                await audit._put_state(s, st)  # noqa: SLF001
                await s.commit()
        out = await audit.verify(budget=10**12)
    if out["state"] == "other_key":
        print("Audit log: sealed with another master key, or its chain state was changed – cannot be checked with this key.")
        print("  After a new SECRET_KEY or a restore with another key: python -m app.cli verify-audit --accept-new-key")
        return 1
    if out["problems"] or out.get("logged_problems"):
        for p in out["problems"]:
            print(f"Audit log: {_problem_text(p)}")
        if out.get("logged_problems"):
            print(f"Audit log: {out['logged_problems']} problem(s) found earlier (audit.chain_problem) and not acknowledged")
        return 1
    print(f"Audit log: chain intact – checked up to position {out['verified_seq'] or 0} from position {out['anchor_seq']}.")
    return 0


async def _main(argv: list[str]) -> int:
    cmd, args = (argv[0] if argv else ""), argv[1:]
    if cmd not in ("reset-emergency", "new-setup-token", "rotate-vapid", "migrate", "migrate-sqlite", "backup", "restore", "export", "restore-test", "verify-audit"):
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
            try:
                res = await backup.create(passphrase=_passphrase(args), actor=audit.CLI)
            except backup.BackupError as exc:
                print(f"Backup failed: {exc}")
                return 1
            print(f"{res.path} – {res.size} bytes, {sum(res.rows.values())} rows, {res.seconds} s, {'encrypted, with the key' if res.encrypted else 'not encrypted, without the key'}")
            return 0
        if cmd == "export":
            return await _export(args)
        if cmd == "verify-audit":
            return await _verify_audit(args)
        return await _account(cmd)
    finally:
        await db.dispose()


if __name__ == "__main__":
    sys.exit(asyncio.run(_main(sys.argv[1:])))
