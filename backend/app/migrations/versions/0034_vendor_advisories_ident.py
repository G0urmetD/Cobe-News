"""Vendor News: an index on vendor_advisories.ident – "CVE beobachten" (app/cve_watch.py) reads the advisories of the
watched CVEs by `cves ?| … OR ident IN (…)`; without an index on ident the OR read the whole table (169–390 ms at
50 000 advisories, on every page view of the list), with it two index scans (about 10 ms). The cvelistV5 single
lookups ask by ident too.

Building the index reads the table once (well under a second for 50 000 rows).

Revision ID: 0034
Revises: 0033
Create Date: 2026-11-05
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0034"
down_revision: str | None = "0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_vendor_advisories_ident", "vendor_advisories", ["ident"])


def downgrade() -> None:
    op.drop_index("ix_vendor_advisories_ident", table_name="vendor_advisories")
