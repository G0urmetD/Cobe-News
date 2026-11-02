"""Sign-in hardening (0.1.42):

- auth_locks: the active brute-force locks of accounts and blocks of addresses (app/auth/lock_store.py) – the counters
  stay in memory, the locks survive a restart. New table, empty.
- password_history: the earlier passwords of local accounts (argon2 hashes), the last ones may not be chosen again.
  New table, empty – the history starts with the next password change.
- api_tokens: no token without expiry any more (at most 365 days). Tokens made with "never" get one: the time of this
  migration plus 365 days, and `expiry_added` (the list says so). Revoked tokens keep theirs (they are over anyway).
  The downgrade keeps the added expiry (a token does not become eternal again by itself) and drops the column.

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "auth_locks",
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("until", TS, nullable=False),
        sa.Column("strikes", sa.Integer(), server_default="1", nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_index("ix_auth_locks_until", "auth_locks", ["until"])
    op.create_table(
        "password_history",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_password_history_user_id", "password_history", ["user_id"])
    op.add_column("api_tokens", sa.Column("expiry_added", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    op.execute("UPDATE api_tokens SET expires_at = now() + interval '365 days', expiry_added = true WHERE expires_at IS NULL AND revoked_at IS NULL")


def downgrade() -> None:
    op.drop_column("api_tokens", "expiry_added")
    op.drop_index("ix_password_history_user_id", table_name="password_history")
    op.drop_table("password_history")
    op.drop_index("ix_auth_locks_until", table_name="auth_locks")
    op.drop_table("auth_locks")
