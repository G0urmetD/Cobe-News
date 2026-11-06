"""Rule filters "Betrifft" and "Nicht senden, wenn enthalten": notify_rules.systems (catalogue vendors or products),
notify_rules.keywords (own words) and notify_rules.exclude (words that keep a story away) – and on the stories
news_items.systems (the catalogue systems a story concerns: by its details, or named in its title or teaser) with a GIN
index, and news_items.quiet_systems (those gained by a recompute – matched, never a reason to send an older story).

Existing data: every rule starts without them ('[]': unchanged, it sends what it sent before); every story starts
without systems – the background job (systems.systems_round, its state in the settings row `news_systems`) fills the
column in chunks of 500 stories after the start, quietly (an older story is never sent because of it). Only columns
with a constant default and one index: no table is rewritten.
The downgrade drops the five columns, the index and the job's state (a later upgrade fills the column again).

Revision ID: 0039
Revises: 0038
Create Date: 2026-11-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0039"
down_revision: str | None = "0038"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    for col in ("systems", "keywords", "exclude"):
        op.add_column("notify_rules", sa.Column(col, JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False))
    op.add_column("news_items", sa.Column("systems", JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False))
    op.add_column("news_items", sa.Column("quiet_systems", JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False))
    op.create_index("ix_news_items_systems", "news_items", ["systems"], postgresql_using="gin")


def downgrade() -> None:
    op.drop_index("ix_news_items_systems", table_name="news_items", postgresql_using="gin")
    op.drop_column("news_items", "quiet_systems")
    op.drop_column("news_items", "systems")
    for col in ("exclude", "keywords", "systems"):
        op.drop_column("notify_rules", col)
    op.execute("DELETE FROM settings WHERE key = 'news_systems'")
