"""Advisory changes (app/advisory_changes.py): per advisory what it said last, normalised (vendor_advisory_state), and
its content changes as revisions (vendor_advisory_changes) – fixed versions, affected ranges, severity, KEV, withdrawn.

New tables only – the upgrade is instant on any size of database. Advisories stored before have no state row: the first
time one is stored again, its state is made from the stored record – a change from then on is a revision. Nothing is
notified until a rule chooses the new kind "vendor_change" (existing rules do not get it).

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)
JSONB = postgresql.JSONB()

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vendor_advisory_state",
        sa.Column("advisory_id", sa.Text(), nullable=False),
        sa.Column("facts", JSONB, nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("changed_at", TS, nullable=True),
        sa.ForeignKeyConstraint(["advisory_id"], ["vendor_advisories.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("advisory_id"),
    )
    op.create_table(
        "vendor_advisory_changes",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("advisory_id", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("ident", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("doc_rev", sa.Text(), nullable=False),
        sa.Column("at", TS, nullable=False),
        sa.Column("diff", JSONB, nullable=False),
        sa.Column("impact", JSONB, nullable=False),
        sa.Column("products", JSONB, nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vendor_advisory_changes_advisory", "vendor_advisory_changes", ["advisory_id", "revision"])
    op.create_index("ix_vendor_advisory_changes_at", "vendor_advisory_changes", ["at"])


def downgrade() -> None:
    # the change events go with the tables they were made from (0.1.31 does not know the kind)
    op.execute("DELETE FROM vendor_events WHERE kind = 'change'")
    op.drop_index("ix_vendor_advisory_changes_at", table_name="vendor_advisory_changes")
    op.drop_index("ix_vendor_advisory_changes_advisory", table_name="vendor_advisory_changes")
    op.drop_table("vendor_advisory_changes")
    op.drop_table("vendor_advisory_state")
