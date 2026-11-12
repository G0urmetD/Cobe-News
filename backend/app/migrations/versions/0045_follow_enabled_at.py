""""Unsere Produkte (aus Vendor News)" as a rule's system (app/systems.py, Followed): vendor_follows.enabled_at – when
the product was followed or last switched on. A product followed later counts for the notifications from then on: a
story that arrived before (and gained it no later, loudly) is no news because of the follow – a rule active for months
does not send the older stories about a product followed today.

Existing data: every follow gets its created_at (it counts as it always did); the column stays empty for none. Nothing
changes until a rule, a person's notifications or the News filter chooses "Unsere Produkte". The downgrade drops it.

Revision ID: 0045
Revises: 0044
Create Date: 2026-11-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)

revision: str = "0045"
down_revision: str | None = "0044"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("vendor_follows", sa.Column("enabled_at", TS, nullable=True))
    op.execute("UPDATE vendor_follows SET enabled_at = created_at")


def downgrade() -> None:
    op.drop_column("vendor_follows", "enabled_at")
