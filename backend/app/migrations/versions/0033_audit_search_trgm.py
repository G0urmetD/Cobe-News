"""Audit log: the search (app/audit.py, Filters.q) over one expression – name, display name, action, target and
address – with a trigram index (pg_trgm, created by 0002). Without it a search that finds little read every entry:
650–730 ms at 450 000 entries; with it a few milliseconds. Terms of 3 or more characters use the index; shorter ones
still read the table (a trigram needs 3 characters).

Building the index reads the table once (seconds for a few hundred thousand entries – the migration has no statement
timeout).

Revision ID: 0033
Revises: 0032
Create Date: 2026-11-05
"""

from collections.abc import Sequence

from alembic import op

from app.audit_lock import ddl_skipped

revision: str = "0033"
down_revision: str | None = "0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# the one expression the search queries (audit.SEARCH_TEXT) – must stay exactly the same, or the index is not used
EXPR = (
    "lower(actor_name || ' ' || actor_display || ' ' || action || ' ' || coalesce(target_label, '') || ' ' || "
    "coalesce(target_id, '') || ' ' || coalesce(ip, ''))"
)


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")  # there since 0002 – harmless when it is
    if ddl_skipped(op.get_bind(), revision):  # locked (0.1.52): the table has the index already
        return
    op.execute(f"CREATE INDEX ix_audit_log_search ON audit_log USING gin ({EXPR} gin_trgm_ops)")


def downgrade() -> None:
    if ddl_skipped(op.get_bind(), revision):
        return
    op.execute("DROP INDEX IF EXISTS ix_audit_log_search")
