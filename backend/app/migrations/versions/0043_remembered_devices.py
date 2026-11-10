""""Auf diesem Gerät merken" (app/auth/devices.py): the table remembered_devices – per account the browsers that may
skip the TOTP step after the right password: the keyed hash of the browser's token, a keyed fingerprint of the
account's factors at the time (password, TOTP secret, role), when it was remembered, until when, when last used, the
address and the browser.

Existing data: a new, empty table – nothing changes until an admin switches "Zweiten Faktor auf dem Gerät merken" on
(settings section "mfa", off by default) and a person ticks it at the TOTP step. The downgrade drops it.

Revision ID: 0043
Revises: 0042
Create Date: 2026-11-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)

revision: str = "0043"
down_revision: str | None = "0042"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "remembered_devices",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("factor", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("last_used_at", TS, nullable=True),
        sa.Column("ip", sa.Text(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_remembered_devices_user_id"), "remembered_devices", ["user_id"])
    op.create_index(op.f("ix_remembered_devices_expires_at"), "remembered_devices", ["expires_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_remembered_devices_expires_at"), table_name="remembered_devices")
    op.drop_index(op.f("ix_remembered_devices_user_id"), table_name="remembered_devices")
    op.drop_table("remembered_devices")
