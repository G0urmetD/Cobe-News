"""A GIN index on vendor_advisories.cves: "which stored advisories name these CVEs" (CVE beobachten checks its CVEs
after every Vendor News round; the KEV changes ask the same) is an index lookup instead of reading every record.

Existing data: the index is built once over the stored advisories (a few seconds for tens of thousands of records;
writes to the table wait meanwhile – the app runs the migrations before its loops start). Nothing else changes.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-30
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_vendor_advisories_cves", "vendor_advisories", ["cves"], postgresql_using="gin")


def downgrade() -> None:
    op.drop_index("ix_vendor_advisories_cves", table_name="vendor_advisories", postgresql_using="gin")
