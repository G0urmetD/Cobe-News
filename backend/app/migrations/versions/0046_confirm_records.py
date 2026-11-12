"""Treffer bestätigen, faster: vendor_confirm_records – per confirmation period the records its finding groups (the
leading advisory and the NVD, cvelistV5 and OSV records of its CVEs – what facts.members says), by product and record id.
Whether a Vendor News event is held back (app/finding_confirm.py held) is then one index lookup by the event's product and
record (a change's advisory, a vulnerability event's finding) instead of comparing every event with every confirmation –
the personal round over a big team took seconds with many confirmations.

Existing data: the records of the confirmations stored so far are filled in from their facts (and their finding). The
downgrade drops the table.

Revision ID: 0046
Revises: 0045
Create Date: 2026-11-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0046"
down_revision: str | None = "0045"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vendor_confirm_records",
        sa.Column("confirm_id", sa.Uuid(), sa.ForeignKey("vendor_confirms.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("record", sa.Text(), primary_key=True),
        sa.Column("product", sa.Text(), nullable=False),
    )
    op.create_index("ix_vendor_confirm_records_lookup", "vendor_confirm_records", ["product", "record"])
    op.execute(
        """
        INSERT INTO vendor_confirm_records (confirm_id, record, product)
        SELECT c.id, m.record, c.product
        FROM vendor_confirms c,
             LATERAL (SELECT c.finding AS record
                      UNION SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(c.facts -> 'members') = 'array'
                                                                  THEN c.facts -> 'members' ELSE '[]'::jsonb END)) m
        ON CONFLICT DO NOTHING
        """
    )


def downgrade() -> None:
    op.drop_index("ix_vendor_confirm_records_lookup", table_name="vendor_confirm_records")
    op.drop_table("vendor_confirm_records")
