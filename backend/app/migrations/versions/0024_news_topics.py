"""Topics of the news (0.1.46): news_items.topics – a JSONB list of the story's topics (Aktiv ausgenutzt, Zero-Day,
Ransomware, Ohne Patch, Vorfall/Datenleck, Lieferkette, Phishing, OT/ICS; app/news.py topics_of) – with a GIN index for
the topic filter, and a GIN index on news_items.cves ("which stories name these CVEs": a CVE newly listed in the KEV, a
new KEV story marks the other stories about it).

Existing data: the column starts empty ('[]') for every story; the background job (news.backfill_topics, counter
`news_topics_v`) fills it in chunks of 500 stories after the start. The indexes are built once over the stored stories.
The downgrade drops the column and both indexes (the counter goes too, so a later upgrade fills the column again).

Revision ID: 0024
Revises: 0023
Create Date: 2026-11-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("news_items", sa.Column("topics", JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False))
    op.create_index("ix_news_items_topics", "news_items", ["topics"], postgresql_using="gin")
    op.create_index("ix_news_items_cves", "news_items", ["cves"], postgresql_using="gin")


def downgrade() -> None:
    op.drop_index("ix_news_items_cves", table_name="news_items", postgresql_using="gin")
    op.drop_index("ix_news_items_topics", table_name="news_items", postgresql_using="gin")
    op.drop_column("news_items", "topics")
    op.execute("DELETE FROM counters WHERE name = 'news_topics_v'")
