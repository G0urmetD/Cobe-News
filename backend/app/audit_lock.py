"""The audit log's database lock ("Datenbank-Sperre", 0.1.52) as the app sees it – set up by the database image, not by
the app: deploy/postgres/audit-lock.sql, run by db-init as the superuser at every start of the database
(docs/BETRIEB.md: Protokoll, Datenbank-Sperre).

Locked, the table public.audit_log and the schema public belong to the role cobe_news_audit (NOLOGIN, nobody is a
member of it). The app (cobe_news_app) may read the log and add entries, and seal an unsealed one (UPDATE of the
chain's columns) – PostgreSQL refuses every other UPDATE, every DELETE and TRUNCATE, and as the owner of neither the
table nor the schema it can neither drop nor alter it. Two functions of the lock role delete: `prune()` (the retention,
never entries younger than 90 days) and `set_aside()` (a restore – the entries are moved into
cobe_news_audit.audit_log_replaced, not deleted). Without the image (development, the tests, a PostgreSQL of one's
own) none of it exists: the app works as before, the lock is shown as not active.

`installed()`: the table belongs to the lock role – the prune and the restore take the lock's way (also for a superuser
connection, which the lock cannot hold back). `state()`: whether it is active, and why not – the Protokoll page, the
log line at the start. Migrations that touch audit_log ask `ddl_skipped()`: locked, the app may not alter the table –
its shape then comes from audit-lock.sql (docs/BETRIEB.md: Entwicklung, Migrationen am Protokoll)."""

import logging

from sqlalchemy import text

log = logging.getLogger("cobe_news.audit")

ROLE = "cobe_news_audit"  # owner of the locked table (and of the schema public), the lock's functions and its schema
TRIGGERS = ("cobe_news_audit_lock", "cobe_news_audit_lock_truncate")
FUNCTIONS = ("cobe_news_audit.prune(bigint,integer)", "cobe_news_audit.set_aside()", "cobe_news_audit.restored()")
KEEP_FLOOR_DAYS = 90  # prune() never deletes younger entries, whatever the app asks (= audit.KEEP_MIN)

_OWNER = text("SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = to_regclass('public.audit_log')")

_STATE = text(
    f"""SELECT r.rolsuper AS su,
       to_regnamespace('{ROLE}') IS NOT NULL AS set_up,
       (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = to_regclass('public.audit_log')) AS owner,
       (SELECT pg_get_userbyid(n.nspowner) FROM pg_namespace n WHERE n.nspname = 'public') AS public_owner,
       {" AND ".join(f"to_regprocedure('{f}') IS NOT NULL" for f in FUNCTIONS)} AS functions,
       (SELECT count(*) FROM pg_trigger t WHERE t.tgrelid = to_regclass('public.audit_log') AND t.tgname IN {TRIGGERS!r} AND t.tgenabled = 'A') AS triggers,
       CASE WHEN to_regclass('public.audit_log') IS NULL THEN false ELSE
         has_table_privilege(to_regclass('public.audit_log'), 'UPDATE') OR has_table_privilege(to_regclass('public.audit_log'), 'DELETE')
         OR has_table_privilege(to_regclass('public.audit_log'), 'TRUNCATE') OR has_table_privilege(to_regclass('public.audit_log'), 'TRIGGER')
         OR has_column_privilege(to_regclass('public.audit_log'), 'at', 'UPDATE') OR has_column_privilege(to_regclass('public.audit_log'), 'action', 'UPDATE')
       END AS too_much,
       CASE WHEN to_regclass('cobe_news_audit.audit_log_replaced') IS NOT NULL
             AND has_table_privilege(to_regclass('cobe_news_audit.audit_log_replaced'), 'SELECT') THEN true ELSE false END AS archive
  FROM pg_roles r WHERE r.rolname = current_user"""
)
_ARCHIVE = text("SELECT count(*), max(replaced_at) FROM cobe_news_audit.audit_log_replaced")


def ddl_skipped(bind, migration: str) -> bool:  # noqa: ANN001 - op.get_bind(): a sync Connection
    """In a migration that changes audit_log: True when the table is locked – the change is left out (the app may not
    make it; the database image's audit-lock.sql brings the same, idempotently, at the start before the app's)."""
    if bind.execute(_OWNER).scalar() != ROLE:
        return False
    log.info("migration %s: audit_log is locked (owner %s) – left out here, its shape comes from the database image (deploy/postgres/audit-lock.sql)", migration, ROLE)
    return True


async def installed(conn) -> bool:  # noqa: ANN001 - an AsyncConnection or AsyncSession
    """The table belongs to the lock role: deleting goes through its functions (prune, restore)."""
    return (await conn.scalar(_OWNER)) == ROLE


async def state(conn) -> dict:  # noqa: ANN001 - an AsyncConnection or AsyncSession
    """{"active": bool, "reason": why not – "no_lock" (no database image: nothing set up), "pending" (set up, the table
    follows when the database container sees it – seconds after the app's first start – else at its next start), "superuser" (the app connects as a superuser – no lock holds it back),
    "incomplete" (something of the lock is missing, or the app has a right too many) –, "set_aside": entries a restore
    set aside, "set_aside_at": the last time}."""
    g = (await conn.execute(_STATE)).mappings().one()
    if g["owner"] == ROLE and g["su"]:
        reason = "superuser"
    elif g["owner"] == ROLE:
        reason = None if g["functions"] and g["triggers"] == len(TRIGGERS) and g["public_owner"] == ROLE and not g["too_much"] else "incomplete"
    else:  # the lock's schema in this database: audit-lock.sql ran, the table was not there yet (or was refused: its log)
        reason = "pending" if g["set_up"] else "no_lock"
    out = {"active": reason is None, "reason": reason, "set_aside": 0, "set_aside_at": None}
    if g["archive"]:
        n, at = (await conn.execute(_ARCHIVE)).one()
        out.update(set_aside=int(n or 0), set_aside_at=at.isoformat() if at else None)
    return out


def describe(st: dict) -> str:
    """The state as one line for the log."""
    if st["active"]:
        return f"database lock active (owner {ROLE}: the app may read and add entries, not change or delete them)"
    why = {
        "no_lock": "not set up (no database image – a PostgreSQL of one's own)",
        "pending": "set up, becomes active once the database container sees the table (seconds after the first start; else at its next start)",
        "superuser": "the app connects as a database superuser",
        "incomplete": "incomplete – see the db-init lines of the database container's log",
    }.get(st["reason"] or "", st["reason"] or "?")
    return f"database lock NOT active: {why}"
