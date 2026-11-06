"""Notification rules (0.1.53): what matches is sent, and old stories are not.

- news_item_sources.fresh: a further source's carry counts for the rules only when it was fresh (the source listed the
  story within a day of its own date – news._backlog). A source switched on after weeks lists dozens of older stories
  other sources stored meanwhile; a rule limited to that source sent them as one summary. Existing carries: fresh only
  where the story itself arrived within the last day and is no backlog – what a round may still have pending (a channel
  pausing after failures waits at most 6 hours). Every older carry is long decided: it was sent then or not, and stays
  so – a later change of such a story (rated higher) makes it count for its own source, not for the carry.
- news_items.changes and news_item_sources.carried_at: when what a rule matches by changed loudly after the story
  arrived, per dimension – the rating rose (and from what), the title or teaser changed (and what it was), a topic or a
  system was gained loudly, a further source carried it fresh. A rule widened before such a change judges the story by
  the dimension that changed (notify._earlier_news): an unrelated change (a fresh carry when the widening added a
  severity) sends nothing. '{}' / empty for every existing story and carry (nothing changed since).
- notify_rules.active_seq, notify_rule_channels.added_seq: the arrival number when a rule was switched on or a channel
  added – "from now on" by arrival, not by the time a fetch began. Empty for the existing ones: their time decides, as
  before (their boundary is in the past, the race of a fetch under way at that moment is over).

Nullable columns, a boolean and a JSONB column with a constant default – PostgreSQL adds them without rewriting a table. The backfill
touches the carries of the last day's stories (by the fetched_at index) – a few hundred rows at most. The downgrade
drops the columns (older code ignores them).

Revision ID: 0038
Revises: 0037
Create Date: 2026-11-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from alembic import op

revision: str = "0038"
down_revision: str | None = "0037"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("news_item_sources", sa.Column("fresh", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("news_items", sa.Column("changes", JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False))
    op.add_column("news_item_sources", sa.Column("carried_at", postgresql.TIMESTAMP(timezone=True), nullable=True))
    op.add_column("notify_rules", sa.Column("active_seq", sa.BigInteger(), nullable=True))
    op.add_column("notify_rule_channels", sa.Column("added_seq", sa.BigInteger(), nullable=True))
    op.execute(
        "UPDATE news_item_sources s SET fresh = true FROM news_items i "
        "WHERE i.id = s.item_id AND i.fetched_at > now() - interval '1 day' AND NOT i.backlog"
    )


def downgrade() -> None:
    op.drop_column("notify_rule_channels", "added_seq")
    op.drop_column("notify_rules", "active_seq")
    op.drop_column("news_item_sources", "carried_at")
    op.drop_column("news_items", "changes")
    op.drop_column("news_item_sources", "fresh")
