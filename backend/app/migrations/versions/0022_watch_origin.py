"""Where a watched CVE was watched from (app/cve_watch.py, 0.1.42): a story (its id and title as they were then), a
Vendor News finding (product, advisory id, title) or typed on /watch ("manual"). The list groups by it; "Gruppe nicht
mehr beobachten" removes by it.

Four nullable columns without a default – no table rewrite, instant on any size of database. Existing rows keep NULL:
their origin is unknown, the list shows them under "Einzeln hinzugefügt" with the manual ones. Nothing is sent or
changed for existing watches. The down migration drops the columns (the origins are lost, the watches stay).

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COLUMNS = ("origin_kind", "origin_ref", "origin_product", "origin_title")


def upgrade() -> None:
    for name in COLUMNS:
        op.add_column("cve_watches", sa.Column(name, sa.Text(), nullable=True))


def downgrade() -> None:
    for name in reversed(COLUMNS):
        op.drop_column("cve_watches", name)
