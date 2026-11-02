"""The last visit of the list of watched CVEs (person_notify.watch_seen_at): what happened to a watched CVE after it is
marked "new" on the page (app/watch_api.py).

One nullable column – no default, no table rewrite: instant on any size of database. Nobody has visited yet, so after
the upgrade nothing is marked new until a person's second visit; nothing is sent or changed for existing data.

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("person_notify", sa.Column("watch_seen_at", TS, nullable=True))


def downgrade() -> None:
    op.drop_column("person_notify", "watch_seen_at")
