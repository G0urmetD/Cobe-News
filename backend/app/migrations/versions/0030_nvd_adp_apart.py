"""NVD records keep the CNA's affected data and CISA's ADP rows apart (0.1.47): stored side by side, CISA's
defaultStatus "affected" counted as the vendor's word – every version outside its range "affected" (GitLab
CVE-2024-4835 for 19.5). The stored records get the new form with their next full fetch: every NVD CPE query is marked
for one (`full_at` empty) – it comes when the query is due anyway, no extra round. The downgrade changes nothing (a
full fetch is harmless).

Revision ID: 0030
Revises: 0029
Create Date: 2026-11-03
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("UPDATE vendor_fetch SET full_at = NULL WHERE key LIKE 'nvd:%'")


def downgrade() -> None:
    pass
