"""Passkeys (app/passkeys_api.py) and "Meine Sitzungen" (app/sessions_api.py): the table user_passkeys, and two columns
on user_sessions – how the session was signed in (`method`) and, for a passkey sign-in, with which passkey
(`passkey_id`: removing the passkey ends those sessions).

A new table and two nullable columns without a default – the upgrade is instant on any size of database. Running
sessions keep going; they show "unknown" as their sign-in method. No passkey exists until a person registers one. The
WebAuthn challenges are kept in memory only (never in the database, so never in a backup).

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user_passkeys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False),
        sa.Column("transports", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_used_at", TS, nullable=True),
        sa.Column("sign_count_warning_at", TS, nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("credential_id"),
    )
    op.create_index(op.f("ix_user_passkeys_user_id"), "user_passkeys", ["user_id"])
    op.add_column("user_sessions", sa.Column("method", sa.Text(), nullable=True))
    op.add_column("user_sessions", sa.Column("passkey_id", sa.Uuid(), nullable=True))
    op.create_foreign_key("user_sessions_passkey_id_fkey", "user_sessions", "user_passkeys", ["passkey_id"], ["id"], ondelete="SET NULL")
    op.create_index(op.f("ix_user_sessions_passkey_id"), "user_sessions", ["passkey_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_user_sessions_passkey_id"), table_name="user_sessions")
    op.drop_constraint("user_sessions_passkey_id_fkey", "user_sessions", type_="foreignkey")
    op.drop_column("user_sessions", "passkey_id")
    op.drop_column("user_sessions", "method")
    op.drop_index(op.f("ix_user_passkeys_user_id"), table_name="user_passkeys")
    op.drop_table("user_passkeys")
