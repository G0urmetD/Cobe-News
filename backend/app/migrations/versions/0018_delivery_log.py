"""Delivery log (app/delivery_log.py): every attempt to deliver a message to a channel – a rule's message, a team
forward, a weekly review mail, a test – with its outcome, kept 30 days.

A new table only – the upgrade is instant on any size of database, nothing changes for existing data: the log starts
empty and fills from the first delivery on.

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)
JSONB = postgresql.JSONB()

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "delivery_log",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("at", TS, nullable=False),
        sa.Column("channel_id", sa.Uuid(), nullable=True),
        sa.Column("channel_name", sa.Text(), nullable=False),
        sa.Column("channel_type", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("ref", sa.Text(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("manual", sa.Boolean(), nullable=False),
        sa.Column("items", JSONB, nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("rules", JSONB, nullable=False),
        sa.Column("refs", JSONB, nullable=False),
        sa.Column("lang", sa.Text(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=True),
        sa.Column("team_name", sa.Text(), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("code", sa.Integer(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["channel_id"], ["notify_channels.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_delivery_log_at"), "delivery_log", ["at"])
    op.create_index("ix_delivery_log_channel", "delivery_log", ["channel_id", "at"])
    op.create_index("ix_delivery_log_ref", "delivery_log", ["ref", "channel_id"])
    op.create_index(op.f("ix_delivery_log_user_id"), "delivery_log", ["user_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_delivery_log_user_id"), table_name="delivery_log")
    op.drop_index("ix_delivery_log_ref", table_name="delivery_log")
    op.drop_index("ix_delivery_log_channel", table_name="delivery_log")
    op.drop_index(op.f("ix_delivery_log_at"), table_name="delivery_log")
    op.drop_table("delivery_log")
