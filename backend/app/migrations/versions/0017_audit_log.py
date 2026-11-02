"""Audit log (app/audit.py): the security-relevant admin and account actions – who, what, when, from where, on what,
and the changed fields before/after without any secret value. Append-only, kept 365 days by default (settings
section "audit"), pruned hourly.

A new table only – the upgrade is instant on any size of database, nothing changes for existing data: the log starts
empty with the first action after the upgrade.

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)

# the one place with this migration's numbers (renumbered when another migration lands first)
revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("at", TS, nullable=False),
        sa.Column("actor_kind", sa.Text(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("actor_name", sa.Text(), nullable=False),
        sa.Column("actor_display", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=True),
        sa.Column("target_id", sa.Text(), nullable=True),
        sa.Column("target_label", sa.Text(), nullable=True),
        sa.Column("ip", sa.Text(), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_log_at", "audit_log", ["at", "id"], unique=False)
    op.create_index("ix_audit_log_actor", "audit_log", ["actor_id", "at"], unique=False)
    op.create_index("ix_audit_log_action", "audit_log", ["action", "at"], unique=False)
    op.create_index("ix_audit_log_target", "audit_log", ["target_type", "target_id", "at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_log_target", table_name="audit_log")
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_index("ix_audit_log_actor", table_name="audit_log")
    op.drop_index("ix_audit_log_at", table_name="audit_log")
    op.drop_table("audit_log")
