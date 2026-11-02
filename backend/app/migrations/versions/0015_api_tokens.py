"""API tokens (app/api_tokens.py): named, read-only tokens for /api/v1 and /metrics, stored as a keyed hash only.

A new table only – the upgrade is instant on any size of database, nothing changes for existing data: no token exists
until an admin makes one. The restore test (app/restore_test.py) needs no table (its outcome is a settings entry).

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("prefix", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("scopes", postgresql.JSONB(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=True),
        sa.Column("last_used_at", TS, nullable=True),
        sa.Column("revoked_at", TS, nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_api_tokens_created_by"), "api_tokens", ["created_by"])


def downgrade() -> None:
    op.drop_index(op.f("ix_api_tokens_created_by"), table_name="api_tokens")
    op.drop_table("api_tokens")
