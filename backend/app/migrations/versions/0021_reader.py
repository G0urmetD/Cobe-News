"""Reading (app/reader.py): read watermarks per person, sparse read marks for Vendor News findings, "unread again" on
the news read marks, mutes for a while, saved views.

- reader_state: one row per person with the watermarks. Existing accounts get news_seq 0 (their news read marks keep
  meaning exactly what they meant – within reader.AUTO_READ) and vendor_at = now (Vendor News had no read state: nothing
  of it is unread after the upgrade). Accounts made later have no row: read up to their creation.
- news_reads.unread: a column with a constant default – no table rewrite (PostgreSQL 11+), instant on any size.
- vendor_reads, person_mutes, saved_views: new tables, empty.

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("news_reads", sa.Column("unread", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    op.create_table(
        "reader_state",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("news_seq", sa.BigInteger(), nullable=True),
        sa.Column("news_at", TS, nullable=True),
        sa.Column("vendor_at", TS, nullable=True),
        sa.Column("updated_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.execute("INSERT INTO reader_state (user_id, news_seq, news_at, vendor_at, updated_at) SELECT id, 0, NULL, now(), now() FROM users")
    op.create_table(
        "vendor_reads",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("finding", sa.Text(), nullable=False),
        sa.Column("read_at", TS, nullable=False),
        sa.Column("unread", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "product", "finding"),
    )
    op.create_table(
        "person_mutes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("until", TS, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ux_person_mutes", "person_mutes", ["user_id", "kind", "key"], unique=True)
    op.create_index("ix_person_mutes_until", "person_mutes", ["until"])
    op.create_table(
        "saved_views",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("page", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("is_default", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ux_saved_views_name", "saved_views", ["user_id", "page", "name"], unique=True)
    op.create_index("ux_saved_views_default", "saved_views", ["user_id", "page"], unique=True, postgresql_where=sa.text("is_default"))


def downgrade() -> None:
    op.drop_index("ux_saved_views_default", table_name="saved_views")
    op.drop_index("ux_saved_views_name", table_name="saved_views")
    op.drop_table("saved_views")
    op.drop_index("ix_person_mutes_until", table_name="person_mutes")
    op.drop_index("ux_person_mutes", table_name="person_mutes")
    op.drop_table("person_mutes")
    op.drop_table("vendor_reads")
    op.drop_table("reader_state")
    # the marks "unread again" have no meaning without the watermark: they go (a read mark stays a read mark)
    op.execute("DELETE FROM news_reads WHERE unread")
    op.drop_column("news_reads", "unread")
