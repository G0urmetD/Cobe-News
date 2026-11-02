"""Catalogue self-test ("Katalog-Pflege"): what the NVD said about each CPE of the catalogue (catalog_cpe_checks) and the
verdict per product with its reasons (catalog_checks). app/catalog_check.py.

New tables only – the upgrade is instant on any size of database.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)
JSONB = postgresql.JSONB()

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "catalog_cpe_checks",
        sa.Column("cpe", sa.Text(), nullable=False),
        sa.Column("tried_at", TS, nullable=True),
        sa.Column("checked_at", TS, nullable=True),
        sa.Column("exists", sa.Boolean(), nullable=True),
        sa.Column("deprecated_by", sa.Text(), nullable=True),
        sa.Column("cve_total", sa.Integer(), nullable=True),
        sa.Column("newest_cve", sa.Text(), nullable=True),
        sa.Column("newest_at", TS, nullable=True),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("cpe"),
    )
    op.create_table(
        "catalog_checks",
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("reasons", JSONB, nullable=False),
        sa.Column("followed", sa.Boolean(), nullable=False),
        sa.Column("checked_at", TS, nullable=False),
        sa.Column("catalog_version", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("product"),
    )


def downgrade() -> None:
    op.drop_table("catalog_checks")
    op.drop_table("catalog_cpe_checks")
