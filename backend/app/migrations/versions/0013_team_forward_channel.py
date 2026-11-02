"""A team's forward channel ("An mein Team weiterleiten", app/forward.py): which of the existing notification channels a
member's forward goes to – set by an admin in the team's drawer, never by the reader. Empty: forwarding is off for the
team. A deleted channel leaves the team without one (ON DELETE SET NULL).

Existing data: the column is added empty – no team forwards until an admin chooses a channel.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("teams", sa.Column("forward_channel_id", sa.Uuid(), nullable=True))
    op.create_foreign_key("teams_forward_channel_id_fkey", "teams", "notify_channels", ["forward_channel_id"], ["id"], ondelete="SET NULL")


def downgrade() -> None:
    op.drop_constraint("teams_forward_channel_id_fkey", "teams", type_="foreignkey")
    op.drop_column("teams", "forward_channel_id")
