"""Source health: one row per fetch of a source (source_fetch_stats, kept 60 days), the health states a source went
through (source_health_events – the newest per source stays: the last known state survives a restart) and which state
change went to which notification channel (source_health_deliveries). app/source_health.py.

New tables only – nothing existing is touched, the upgrade is instant on any size of database.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)
JSONB = postgresql.JSONB()

# the one place with this migration's numbers (renumbered when another migration lands first)
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_fetch_stats",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("at", TS, nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("status", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("requests", sa.Integer(), nullable=False),
        sa.Column("bytes", sa.BigInteger(), nullable=False),
        sa.Column("items", sa.Integer(), nullable=False),
        sa.Column("not_modified", sa.Boolean(), nullable=False),
        sa.Column("parse_errors", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_source_fetch_stats_source", "source_fetch_stats", ["kind", "key", "at"], unique=False)
    op.create_index("ix_source_fetch_stats_at", "source_fetch_stats", ["at"], unique=False)
    op.create_table(
        "source_health_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("n", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("prev", sa.Text(), nullable=True),
        sa.Column("reasons", JSONB, nullable=False),
        sa.Column("notify", sa.Boolean(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("n"),
    )
    op.create_index("ix_source_health_events_source", "source_health_events", ["kind", "key", "n"], unique=False)
    op.create_index("ix_source_health_events_created", "source_health_events", ["created_at"], unique=False)
    op.create_table(
        "source_health_deliveries",
        sa.Column("channel_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.Uuid(), nullable=True),
        sa.Column("sent_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["channel_id"], ["notify_channels.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["source_health_events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("channel_id", "event_id"),
    )
    op.create_index(op.f("ix_source_health_deliveries_event_id"), "source_health_deliveries", ["event_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_source_health_deliveries_event_id"), table_name="source_health_deliveries")
    op.drop_table("source_health_deliveries")
    op.drop_index("ix_source_health_events_created", table_name="source_health_events")
    op.drop_index("ix_source_health_events_source", table_name="source_health_events")
    op.drop_table("source_health_events")
    op.drop_index("ix_source_fetch_stats_at", table_name="source_fetch_stats")
    op.drop_index("ix_source_fetch_stats_source", table_name="source_fetch_stats")
    op.drop_table("source_fetch_stats")
