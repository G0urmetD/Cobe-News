"""Katalog-Pflege by the people (app/catalog_care.py): "Versionen prüfen" and "Produkt vorschlagen".

- vendor_versions.confirmed_at / confirmed_by: when somebody last said an entered version still runs, and who. The
  evaluation never reads them (a confirmation recomputes nothing).
- product_suggestions: a reader's suggestion of a product the catalogue lacks, and the admins' answer.

Existing rows: confirmed_at is set to the row's updated_at – the last time somebody actually touched the entry, the
only honest date there is (created_at, then the migration time, where it is missing). Not the migration time for all:
that would claim a confirmation nobody gave and hide every old entry for a whole interval. Not "never" either: only
entries untouched for longer than the interval (90 days by default) are shown as "bitte prüfen" – exactly the ones the
feature is for – nothing is sent because of it (the weekly review is opt-in and lists them once a week at most), and
"Alle bestätigen" clears a product in one step. confirmed_by stays empty (unknown).

Instant on any size of database: two nullable columns, one UPDATE over vendor_versions (a few hundred rows), a new table.

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)

revision: str = "0019"
# merge note: the branches 0016–0018 come first – this one then revises the last of them
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("vendor_versions", sa.Column("confirmed_at", TS, nullable=True))
    op.add_column("vendor_versions", sa.Column("confirmed_by", sa.Uuid(), nullable=True))
    op.create_foreign_key("vendor_versions_confirmed_by_fkey", "vendor_versions", "users", ["confirmed_by"], ["id"], ondelete="SET NULL")
    op.execute("UPDATE vendor_versions SET confirmed_at = COALESCE(updated_at, created_at, now()) WHERE confirmed_at IS NULL")
    op.create_table(
        "product_suggestions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("vendor", sa.Text(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("cpe", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("answer", sa.Text(), nullable=False),
        sa.Column("product_key", sa.Text(), nullable=True),
        sa.Column("decided_by", sa.Uuid(), nullable=True),
        sa.Column("decided_at", TS, nullable=True),
        sa.Column("seen_at", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["decided_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_product_suggestions_status", "product_suggestions", ["status", "created_at"])
    op.create_index("ix_product_suggestions_user", "product_suggestions", ["user_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_product_suggestions_user", table_name="product_suggestions")
    op.drop_index("ix_product_suggestions_status", table_name="product_suggestions")
    op.drop_table("product_suggestions")
    op.drop_constraint("vendor_versions_confirmed_by_fkey", "vendor_versions", type_="foreignkey")
    op.drop_column("vendor_versions", "confirmed_by")
    op.drop_column("vendor_versions", "confirmed_at")
