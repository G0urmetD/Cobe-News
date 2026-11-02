"""Structured sources (0.1.26): FIRST's EPSS per CVE of a finding or a story (epss_scores, app/epss.py). The CSAF
providers, cvelistV5 and OSV store their records as Vendor News advisories (vendor_advisories, sources csaf, cvelist,
osv) and their state in vendor_fetch – no new table for them.

A new table only – the upgrade is instant on any size of database.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "epss_scores",
        sa.Column("cve", sa.Text(), nullable=False),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("percentile", sa.Float(), nullable=True),
        sa.Column("day", sa.Text(), nullable=False),
        sa.Column("fetched_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("cve"),
    )
    op.create_index("ix_epss_scores_fetched", "epss_scores", ["fetched_at"])


def downgrade() -> None:
    # the structured sources' records go with the table they would be read with (0.1.25 does not know these sources)
    op.execute("DELETE FROM vendor_advisory_products WHERE advisory_id LIKE 'cvelist:%' OR advisory_id LIKE 'osv:%'")
    op.execute("DELETE FROM vendor_advisories WHERE source IN ('cvelist', 'osv')")
    op.execute("DELETE FROM vendor_fetch WHERE key LIKE 'csaf:%' OR key LIKE 'cvelist%' OR key LIKE 'epss:%' OR key LIKE 'osv%'")
    op.execute("DELETE FROM source_fetch_stats WHERE kind = 'structured'")
    op.execute("DELETE FROM source_health_events WHERE kind = 'structured'")
    op.drop_index("ix_epss_scores_fetched", table_name="epss_scores")
    op.drop_table("epss_scores")
