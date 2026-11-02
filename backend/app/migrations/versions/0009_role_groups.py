"""Directory accounts remember the groups that gave them a role: users.role_groups – the mapped and the
team-bound groups found at the last sign-in or hourly sync. Removing a role mapping re-checks the accounts it concerns
at once from these (app/auth/directory.reassess_mapping) instead of waiting for the next sync.

One nullable column – no rewrite of the table, the upgrade is instant; NULL means "not known yet" (filled at the next
sign-in or sync) and is treated as "may depend on the removed group".

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("role_groups", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "role_groups")
