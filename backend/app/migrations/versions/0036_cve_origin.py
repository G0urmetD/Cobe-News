"""Vendor News: who wrote a CVE record (0.1.52) – the CNA's affected data is the vendor's own word only when the CNA is
the product's vendor (app/vendor_match.cna_by); GitHub's advisory database, VulDB, MITRE … are third parties. cvelistV5
records keep their CNA since 0.1.46 (data["assigner"]: assignerShortName); NVD records keep it from now on (the
record's sourceIdentifier) – the raw record is not stored, so the stored ones get it with their next full fetch: every
NVD CPE query is marked for one (`full_at` empty), as 0030 did. It comes when the query is due anyway (no extra round,
the weekly full fetch would bring it within 7 days), its records are written in the usual batches of 500; a query that
fails keeps the mark and does it on the next round. Until then (and for records no full fetch lists – older than the
newest 2000 of a CPE, keyword finds) a record without its CNA counts as the vendor's, as before.

The update itself touches one row per NVD CPE query (vendor_fetch, a few hundred) – milliseconds, no lock on
vendor_advisories. The downgrade changes nothing (a full fetch is harmless; the stored CNA is ignored by older code).

Revision ID: 0036
Revises: 0034
Create Date: 2026-11-06
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0036"
down_revision: str | None = "0034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("UPDATE vendor_fetch SET full_at = NULL WHERE key LIKE 'nvd:%' AND full_at IS NOT NULL")


def downgrade() -> None:
    pass
