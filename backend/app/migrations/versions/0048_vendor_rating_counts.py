"""Hersteller zählt (0.1.57): the rating of a CVE is its CNA's own – what cve.org and the vendor's page show –, the
NVD's own analysis only where the CNA gives none (vendor_sources._nvd_metrics; GitLab rates CVE-2025-2938 3.1 LOW, the
NVD 8.8 HIGH), and a finding is rated by the vendor's advisory and the CNAs, the NVD and a coordinator's document only
as a fallback (vendor.rating).

- NVD: the stored records keep only the score they were rated by – which rater it came from is not stored, so they get
  it from the NVD again: every NVD CPE query is marked for a full fetch (`full_at` empty, as 0036 did) and, when it is
  not pausing after errors, is due at once. A full fetch is what the weekly one does anyway (the newest 2000 records of
  the CPE, pages of 500 – four requests at most, with or without an API key within its limit). Each record is
  rewritten once with the rater beside its rating (data["rated"], data["rating"]) – re-rated quietly
  (advisory_changes.rerated: no revision, no event; vendor.unprime: no "jetzt höher eingestuft", a confirmation
  stays). Records no full fetch lists (older than the newest 2000 of a CPE, keyword and single finds) keep their
  rating until the NVD changes them – they count as before.
- A CSAF document of a story without a score of its own (the BSI's WID documents carry none) took the highest NVD
  score of its first CVEs as its own: "GitLab: Mehrere Schwachstellen" (WID-SEC-W-2026-3556, 11 CVEs) was 8.7 HIGH,
  its CVE-2026-10518 is 4.3. Those records are known by their story's details (the score shown with "nvd": true):
  their CVSS goes, their severity is the document's own word (aggregate_severity – "hoch": high). In place, no
  request; the next write of such a record is quiet (rerated).

Touches the NVD rows of vendor_fetch (a few hundred) and the CSAF records of the stories (a few thousand at most) – no
lock worth mentioning. The downgrade changes nothing (a full fetch is harmless; a CSAF record without the borrowed
score is what the new parser writes as well).

Revision ID: 0048
Revises: 0047
Create Date: 2026-11-16
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0048"
down_revision: str | None = "0047"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "UPDATE vendor_fetch SET full_at = NULL, "
        "next_fetch_at = CASE WHEN COALESCE(failures, 0) = 0 THEN NULL ELSE next_fetch_at END "
        "WHERE key LIKE 'nvd:%'"
    )
    op.execute(
        """
        UPDATE vendor_advisories AS a SET cvss = NULL,
            severity = CASE lower(btrim(COALESCE(d.data->>'severity_text', '')))
                WHEN 'kritisch' THEN 'critical' WHEN 'critical' THEN 'critical'
                WHEN 'hoch' THEN 'high' WHEN 'high' THEN 'high'
                WHEN 'mittel' THEN 'medium' WHEN 'medium' THEN 'medium' WHEN 'moderate' THEN 'medium'
                WHEN 'niedrig' THEN 'low' WHEN 'low' THEN 'low'
                ELSE 'info' END
        FROM story_details AS d
        WHERE d.kind IN ('bsi', 'siemens', 'cisco')
          AND jsonb_typeof(d.data) = 'object'
          AND d.data->'cvss'->0->>'nvd' = 'true'
          AND COALESCE(d.data->>'id', '') <> ''
          AND a.id = left('csaf:' || (d.data->>'id'), 120)
          AND a.source = 'csaf'
          AND abs(a.cvss - CASE WHEN jsonb_typeof(d.data->'cvss'->0->'score') = 'number' THEN (d.data->'cvss'->0->>'score')::float8 END) < 0.05
          AND COALESCE((a.data->>'rating')::text, '') = ''
        """
    )


def downgrade() -> None:
    pass
