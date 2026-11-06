"""Audit log, second step (app/audit.py): where an entry came from and an integrity chain.

New columns, all empty on the entries before this version (the page shows what it has):
- who: the account's role then, whether it was the emergency account, how the session was signed in, and a short keyed
  reference of the session (never the session's token or id – a keyed hash, so the entries of one session can be found);
- from where: the browser and system coarse (family, major version, OS – never the full user agent), the request's
  method and path (no query string), its request id (also in the access log), how it arrived (directly, the bundled
  nginx, an own reverse proxy) and the app version;
- `notable`: a security-relevant action or an anomaly found when it was written (the reasons in details.anomalies) –
  the filter "Nur Auffälliges"; the existing entries of such actions are marked here;
- the chain: `seq` (the position), `prev_hash` and `hash` (HMAC over the canonical entry, keyed by the master key).
  Entries are sealed shortly after they are written (audit.seal, about every minute) – the old ones with the first
  seal after the upgrade (every row rewritten once – the table about doubles; VACUUM FULL audit_log gives the space
  back on a big log, under an exclusive lock: docs/BETRIEB.md).

What the chain proves: an entry is unchanged since it was sealed, and none was deleted or inserted since – against
someone without the master key. Not: that an entry was written by the app (one inserted before its seal is sealed with
the rest – marked "late_entry" when its time lies well before the previous one's), the newest entries not sealed yet,
or anything a holder of the master key does. The hourly log line "audit chain head: …" is a witness outside the
database for a log shipper.

No trigger (append-only in the database itself): a backup's dump may hold only the kinds of objects Cobe News makes –
tables, indexes, sequences – and its restore refuses a FUNCTION or TRIGGER (backup._toc_check).

Indexes for the new filters: actor kind (system, sync, cli – partial), address, session, notable (partial), seq.

Revision ID: 0032
Revises: 0031
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app.audit_lock import ddl_skipped

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TEXT_COLUMNS = ("actor_role", "auth_method", "session_ref", "ua_family", "ua_version", "ua_os", "req_method", "req_path", "request_id", "req_via", "app_version", "prev_hash", "hash")
# what counted as security-relevant before this version (audit.NOTABLE_ACTIONS at the time of the upgrade)
NOTABLE_BEFORE = (
    "login.locked",
    "login.ip_blocked",
    "login.emergency_slowed",
    "role.changed",
    "token.created",
    "token.revoked",
    "sessions.revoked",
    "backup.restored",
    "audit.exported",
    "passkey.sign_count_warning",
    "setup.completed",
)



def upgrade() -> None:
    if ddl_skipped(op.get_bind(), revision):  # locked (0.1.52): the table has these columns already
        return
    for name in TEXT_COLUMNS:
        op.add_column("audit_log", sa.Column(name, sa.Text(), nullable=True))
    op.add_column("audit_log", sa.Column("actor_emergency", sa.Boolean(), nullable=True))
    op.add_column("audit_log", sa.Column("notable", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("audit_log", sa.Column("seq", sa.BigInteger(), nullable=True))
    actions = ", ".join(f"'{a}'" for a in NOTABLE_BEFORE)
    op.execute(f"UPDATE audit_log SET notable = true WHERE action IN ({actions})")  # noqa: S608 - fixed names
    op.create_index("ix_audit_log_kind", "audit_log", ["actor_kind", "at"], postgresql_where=sa.text("actor_kind <> 'user'"))
    op.create_index("ix_audit_log_ip", "audit_log", ["ip", "at"], postgresql_where=sa.text("ip IS NOT NULL"))
    op.create_index("ix_audit_log_session", "audit_log", ["session_ref", "at"], postgresql_where=sa.text("session_ref IS NOT NULL"))
    op.create_index("ix_audit_log_notable", "audit_log", ["at", "id"], postgresql_where=sa.text("notable"))
    op.create_index("ux_audit_log_seq", "audit_log", ["seq"], unique=True, postgresql_where=sa.text("seq IS NOT NULL"))
    op.create_index("ix_audit_log_unsealed", "audit_log", ["id"], postgresql_where=sa.text("seq IS NULL"))


def downgrade() -> None:
    if ddl_skipped(op.get_bind(), revision):
        return
    for name in ("ix_audit_log_unsealed", "ux_audit_log_seq", "ix_audit_log_notable", "ix_audit_log_session", "ix_audit_log_ip", "ix_audit_log_kind"):
        op.drop_index(name, table_name="audit_log")
    for name in (*TEXT_COLUMNS, "actor_emergency", "notable", "seq"):
        op.drop_column("audit_log", name)
