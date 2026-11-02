"""Search: a trigram index on news_items.search (pg_trgm).

The search stays what it was – `search LIKE '%…%'` on the folded text (db.contains) – but no longer reads every story:
40 000 stories, "gitlab": 22 → 4 ms; the related news of a product (an OR of up to 46 LIKEs): 48 → 8 ms. Full-text
search was not taken: it matches words and stems, not parts of words ("fortio" finds "FortiOS" today).

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-29
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute("CREATE INDEX ix_news_items_search_trgm ON news_items USING gin (search gin_trgm_ops)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_news_items_search_trgm")
