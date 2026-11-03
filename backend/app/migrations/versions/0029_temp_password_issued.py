"""Temporary passwords expire (0.1.47): `users.temp_password_at` – when the temporary password an admin set (or the CLI's
reset-emergency) was issued. A sign-in with it after the configured days (settings section "sessions",
`temp_password_days`, default 7) is refused – the admin issues a new one.

Accounts that wait for their first password change already get the time of this migration: their temporary password
stays valid for the configured days from now on (an older one does not become invalid with the upgrade). The downgrade
drops the column.

Revision ID: 0029
Revises: 0028
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("temp_password_at", postgresql.TIMESTAMP(timezone=True), nullable=True))
    op.execute("UPDATE users SET temp_password_at = now() WHERE must_change_password AND auth_source = 'local'")


def downgrade() -> None:
    op.drop_column("users", "temp_password_at")
