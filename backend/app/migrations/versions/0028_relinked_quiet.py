"""Links found by a relink after a catalogue change (app/vendor.py relink_catalog, 0.1.47): `quiet` on
vendor_advisory_products. A new catalogue version can give a product names its stored advisories carry (new CNA names –
Exchange SE, SharePoint SE, SAP "(Private Cloud or On-Premise)", Oracle "Java SE"); once per catalogue version the
followed products are linked again against the stored advisories, and a link that pass adds is quiet: a finding that
exists only through such links is shown, never notified (as the baseline of a new follow).

A boolean NOT NULL with a constant default – PostgreSQL 11+ adds it without rewriting the table. Existing links are not
quiet. The down migration drops the column (a quiet link becomes an ordinary one).

Revision ID: 0028
Revises: 0025
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028"
down_revision: str | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("vendor_advisory_products", sa.Column("quiet", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("vendor_advisory_products", "quiet")
