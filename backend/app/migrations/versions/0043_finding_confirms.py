"""Treffer bestätigen (app/finding_confirm.py): vendor_confirms – one row per finding of a followed product (product key
and finding id, the advisory id the drawer's `?finding=` uses): the assessment (not affected, mitigated, risk accepted),
the reason, who and when (the name kept for display), the facts it was confirmed on, which of its events are held
back, and when and why it ended (undone by hand, or lapsed because the finding changed).

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
        sa.Column("product", sa.Text(), primary_key=True),
        sa.Column("finding", sa.Text(), primary_key=True),
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


def downgrade() -> None:
    op.drop_table("vendor_confirms")
