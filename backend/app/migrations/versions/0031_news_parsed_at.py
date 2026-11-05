"""news_sources.parsed_at (0.1.50): when the last fetch began whose answer was read and stored. A story without a date
of its own goes with the retention only when a later read of its feed no longer listed it – a feed answering "304 Not
Modified" for months, a failing feed or News switched off never make a listed story go (and come back as news). Empty
after the upgrade: such a story stays until its feed was read once more.

Revision ID: 0031
Revises: 0030
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("news_sources", sa.Column("parsed_at", postgresql.TIMESTAMP(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("news_sources", "parsed_at")
