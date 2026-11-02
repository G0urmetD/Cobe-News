"""CVE beobachten and the calendar feed (0.1.34): the CVEs a person watches (cve_watches), what each watched CVE looked
like at its last check (cve_watch_state – the baseline its changes are measured against) and a person's secret
calendar address, as a keyed hash only (calendar_feeds). app/cve_watch.py, app/calendar_feed.py.

New tables only – the upgrade is instant on any size of database, and nothing changes for existing data: nobody
watches a CVE and nobody has a calendar address until they make one. The EOL pre-warnings (90 and 30 days, per version)
need no table – they are Vendor News events of the existing kind "eol" (app/vendor.py).

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)
JSONB = postgresql.JSONB()

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cve_watches",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("cve", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "cve"),
    )
    op.create_index(op.f("ix_cve_watches_cve"), "cve_watches", ["cve"])
    op.create_table(
        "cve_watch_state",
        sa.Column("cve", sa.Text(), nullable=False),
        sa.Column("state", JSONB, nullable=False),
        sa.Column("checked_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("cve"),
    )
    op.create_table(
        "calendar_feeds",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_used_at", TS, nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
        sa.UniqueConstraint("token_hash"),
    )


def downgrade() -> None:
    # the watch events go with the tables they were made from (0.1.33 does not know the kind)
    op.execute("DELETE FROM vendor_events WHERE kind = 'watch'")
    op.drop_table("calendar_feeds")
    op.drop_table("cve_watch_state")
    op.drop_index(op.f("ix_cve_watches_cve"), table_name="cve_watches")
    op.drop_table("cve_watches")
