"""Palo Alto's own rating (0.1.57): its advisories are rated by the CVSS-BT threat score (base + threat metrics – what
Palo Alto's page shows as "Severity", the RSS title says and cve.org and the NVD carry), no longer by the pure CVSS 4.0
base: CVE-2026-0331 is MEDIUM 6.6, not HIGH 8.7 (vendor_sources._pan_one). The stored advisories keep only the score
they were rated by – the threat score is not stored, so they get it from Palo Alto again: every Palo Alto query
(vendor_fetch paloalto:<product name>) forgets its cursor and its validators, its next run reads all pages as a first
run does (up to vendor.PAN_MAX_PAGES), and when it is not pausing after errors that run is due at once. Each record is
rewritten once with the base beside its rating (data["base"]) – re-rated quietly (advisory_changes.rerated: no revision,
no event, a confirmation stays – a lowering never lapses one); what else changed in a record still counts.

The details of the Palo Alto stories (story_details kind "paloalto": the CVE 5 JSON, which has both scores as well) are
asked once again too, in the details rounds as usual (the newest 2000 stories, a few per round); the first details of the
new parser are quiet (story_details.reparsed).

Touches a handful of vendor_fetch rows and the Palo Alto stories' detail rows – no lock worth mentioning. The downgrade
changes nothing (a full fetch and a details refresh are harmless).

Revision ID: 0047
Revises: 0046
Create Date: 2026-11-16
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0047"
down_revision: str | None = "0046"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "UPDATE vendor_fetch SET cursor = NULL, etag = NULL, last_modified = NULL, "
        "next_fetch_at = CASE WHEN COALESCE(failures, 0) = 0 THEN NULL ELSE next_fetch_at END "
        "WHERE key LIKE 'paloalto:%'"
    )
    # details there (a story without any keeps "none": SQL NULL or JSON null)
    op.execute("UPDATE story_details SET next_try_at = now() WHERE kind = 'paloalto' AND COALESCE(data::text, 'null') <> 'null'")


def downgrade() -> None:
    pass
