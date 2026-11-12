"""Treffer bestätigen (app/finding_confirm.py): vendor_confirms – one row per period in which a finding of a followed
product stood confirmed (product key and finding id, the advisory id the drawer's `?finding=` uses; at most one standing
per finding): the assessment (not affected, mitigated, risk accepted), the reason, who and when (the name kept for
display), the facts it was confirmed on, which of its events are held back, and when and why it ended (undone by hand,
or lapsed because the finding changed).

Existing data: a new, empty table – nothing counts or notifies differently until somebody confirms a finding. The
downgrade drops it.

Revision ID: 0043
Revises: 0042
Create Date: 2026-11-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0043"
down_revision: str | None = "0042"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    ts = sa.DateTime(timezone=True)
    op.create_table(
        "vendor_confirms",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("finding", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("user_name", sa.Text(), nullable=False, server_default=""),
        sa.Column("confirmed_at", ts, nullable=False),
        sa.Column("facts", JSONB(), nullable=False),
        sa.Column("held_from", ts, nullable=False),
        sa.Column("held_until", ts, nullable=True),
        sa.Column("ended_at", ts, nullable=True),
        sa.Column("ended_reason", sa.Text(), nullable=True),
        sa.Column("ended_by", sa.Text(), nullable=True),
    )
    op.create_index("ix_vendor_confirms_finding", "vendor_confirms", ["product", "finding"])
    op.create_index("ux_vendor_confirms_standing", "vendor_confirms", ["product", "finding"], unique=True, postgresql_where=sa.text("ended_at IS NULL"))


def downgrade() -> None:
    op.drop_index("ux_vendor_confirms_standing", table_name="vendor_confirms")
    op.drop_index("ix_vendor_confirms_finding", table_name="vendor_confirms")
    op.drop_table("vendor_confirms")
