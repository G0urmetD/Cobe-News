"""A person's own security stories by e-mail or their Microsoft Teams Workflows webhook (app/personal_news.py):
person_news – the filter (as a channel rule's) and when it was last saved, per way on/off and from which arrival on,
the message being sent (claimed), the last message, the pause after a failure, when a round last looked and up to
which arrival and time it judged the stories (only what arrived or changed since is judged again) – and
person_news_sent: which story went to whom on which way (each at most once; kept MAX_AGE plus a day – an older story
is never sent). The admin switch is the settings row `teams` (`personal_news`, off by default).

Existing data: two new, empty tables – nobody gets anything until an admin allows it and the person switches a way
on. The downgrade drops them.

Revision ID: 0042
Revises: 0041
Create Date: 2026-11-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0042"
down_revision: str | None = "0041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    empty = sa.text("'[]'::jsonb")
    ts = sa.DateTime(timezone=True)
    cols = [
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("lang", sa.Text(), nullable=False, server_default="de"),
        sa.Column("severities", JSONB(), nullable=False, server_default=sa.text("'[\"critical\", \"high\"]'::jsonb")),
        sa.Column("sources", JSONB(), nullable=False, server_default=empty),
        sa.Column("topics", JSONB(), nullable=False, server_default=empty),
        sa.Column("systems", JSONB(), nullable=False, server_default=empty),
        sa.Column("keywords", JSONB(), nullable=False, server_default=empty),
        sa.Column("exclude", JSONB(), nullable=False, server_default=empty),
        sa.Column("filter_seq", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("filter_at", ts, nullable=True),
    ]
    for way in ("email", "teams"):
        cols += [
            sa.Column(f"{way}_on", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column(f"{way}_on_seq", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(f"{way}_claim_at", ts, nullable=True),
            sa.Column(f"{way}_sent_at", ts, nullable=True),
            sa.Column(f"{way}_next_at", ts, nullable=True),
            sa.Column(f"{way}_seen_at", ts, nullable=True),
            sa.Column(f"{way}_checked_seq", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(f"{way}_checked_at", ts, nullable=True),
            sa.Column(f"state_{way}", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        ]
    cols.append(sa.Column("updated_at", ts, nullable=False, server_default=sa.text("now()")))
    op.create_table("person_news", *cols)
    op.create_table(
        "person_news_sent",
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("way", sa.Text(), primary_key=True),
        sa.Column("item_id", sa.Uuid(), sa.ForeignKey("news_items.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("sent_at", ts, nullable=False),
    )
    op.create_index("ix_person_news_sent_at", "person_news_sent", ["sent_at"])
    op.create_index("ix_person_news_sent_item", "person_news_sent", ["item_id"])


def downgrade() -> None:
    op.drop_index("ix_person_news_sent_item", table_name="person_news_sent")
    op.drop_index("ix_person_news_sent_at", table_name="person_news_sent")
    op.drop_table("person_news_sent")
    op.drop_table("person_news")
