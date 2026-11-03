"""Topics, phase 2: notify_rules.topics – a rule can require topics of a story (OR within the topics, AND with
severities and sources; empty: any) – and news_items.products – the followed products (catalogue keys) a story's details
concern, for the filter "Betrifft unsere Produkte" on News – with a GIN index.

Existing data: every rule starts without topics ('[]': unchanged, it sends what it sent before); every story starts
without products – the background job (story_details.products_round, its state in the settings row `news_products`)
fills the column in chunks of 500 stories after the start. The new topic "Exploit veröffentlicht" comes with the
topics' next rule version (news.TOPICS_V 2: every stored story is computed again by the topics job).
The downgrade drops both columns and the index, and the job's state (a later upgrade fills the column again).

Revision ID: 0026
Revises: 0025
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0026"
down_revision: str | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("notify_rules", sa.Column("topics", JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False))
    op.add_column("news_items", sa.Column("products", JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False))
    op.create_index("ix_news_items_products", "news_items", ["products"], postgresql_using="gin")


def downgrade() -> None:
    op.drop_index("ix_news_items_products", table_name="news_items", postgresql_using="gin")
    op.drop_column("news_items", "products")
    op.drop_column("notify_rules", "topics")
    op.execute("DELETE FROM settings WHERE key = 'news_products'")
