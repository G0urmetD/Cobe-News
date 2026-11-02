"""Baseline: the schema of 0.1.15 (the last SQLite version) in PostgreSQL types – uuid, timestamptz, JSONB, text.

Two columns are new: news_item_sources.n and vendor_events.n (identity) stand for SQLite's rowid, which the code used
for "the order they came in" / "something new". app/sqlite_import.py fills a database at this revision from a 0.1.15
SQLite file (the rowids go into n, the identities are set past them).

Revision ID: 0001
Revises:
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)
JSONB = postgresql.JSONB()

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "counters", sa.Column("name", sa.Text(), nullable=False), sa.Column("value", sa.BigInteger(), nullable=False), sa.PrimaryKeyConstraint("name")
    )
    op.create_table(
        "group_mappings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("group_id", sa.Text(), nullable=False),
        sa.Column("group_name", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ux_group_mappings", "group_mappings", ["source", "group_id"], unique=True)
    op.create_table(
        "news_sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("site", sa.Text(), nullable=False),
        sa.Column("builtin", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("switched_at", TS, nullable=True),
        sa.Column("etag", sa.Text(), nullable=True),
        sa.Column("last_modified", sa.Text(), nullable=True),
        sa.Column("last_fetch_at", TS, nullable=True),
        sa.Column("last_ok_at", TS, nullable=True),
        sa.Column("next_fetch_at", TS, nullable=True),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("logo", sa.LargeBinary(), nullable=True),
        sa.Column("logo_type", sa.Text(), nullable=True),
        sa.Column("logo_checked_at", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("primed_at", TS, nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key"),
    )
    op.create_table(
        "notify_channels",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("config", JSONB, nullable=False),
        sa.Column("secrets", JSONB, nullable=False),
        sa.Column("target", sa.Text(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_sent_at", TS, nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_error_at", TS, nullable=True),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("next_try_at", TS, nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "notify_rules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("severities", JSONB, nullable=False),
        sa.Column("sources", JSONB, nullable=False),
        sa.Column("lang", sa.Text(), nullable=False),
        sa.Column("kinds", JSONB, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("active_since", TS, nullable=False),
        sa.Column("earlier", JSONB, nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table("settings", sa.Column("key", sa.Text(), nullable=False), sa.Column("value", JSONB, nullable=False), sa.PrimaryKeyConstraint("key"))
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=True),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("auth_source", sa.Text(), nullable=False),
        sa.Column("external_id", sa.Text(), nullable=True),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("totp_secret_enc", sa.Text(), nullable=True),
        sa.Column("totp_last_step", sa.Integer(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("deactivated_reason", sa.Text(), nullable=True),
        sa.Column("is_emergency", sa.Boolean(), nullable=False),
        sa.Column("desktop", JSONB, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_login_at", TS, nullable=True),
        sa.Column("last_login_ip", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_index("ix_users_source_external", "users", ["auth_source", "external_id"], unique=False)
    op.create_table(
        "vendor_advisories",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("ident", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("cves", JSONB, nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("exploited", sa.Boolean(), nullable=False),
        sa.Column("published_at", TS, nullable=True),
        sa.Column("updated_at", TS, nullable=True),
        sa.Column("fetched_at", TS, nullable=False),
        sa.Column("data", JSONB, nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vendor_advisories_published", "vendor_advisories", ["published_at"], unique=False)
    op.create_table(
        "vendor_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("data", JSONB, nullable=False),
        sa.Column("baseline", sa.Boolean(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("n", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key"),
        sa.UniqueConstraint("n"),
    )
    op.create_index("ix_vendor_events_created", "vendor_events", ["created_at"], unique=False)
    op.create_index("ix_vendor_events_scope", "vendor_events", ["scope"], unique=False)
    op.create_table(
        "vendor_fetch",
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("etag", sa.Text(), nullable=True),
        sa.Column("last_modified", sa.Text(), nullable=True),
        sa.Column("cursor", sa.Text(), nullable=True),
        sa.Column("last_fetch_at", TS, nullable=True),
        sa.Column("last_ok_at", TS, nullable=True),
        sa.Column("next_fetch_at", TS, nullable=True),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("items", sa.Integer(), nullable=False),
        sa.Column("full_at", TS, nullable=True),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "vendor_follows",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("tags", JSONB, nullable=False),
        sa.Column("custom", JSONB, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("baseline_at", TS, nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("product"),
    )
    op.create_table(
        "vendor_kev",
        sa.Column("cve", sa.Text(), nullable=False),
        sa.Column("vendor", sa.Text(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("date_added", sa.Text(), nullable=False),
        sa.Column("due", sa.Text(), nullable=False),
        sa.Column("ransomware", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("cve"),
    )
    op.create_table(
        "news_items",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("url_key", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("title_key", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("content_html", sa.Text(), nullable=False),
        sa.Column("published_at", TS, nullable=False),
        sa.Column("fetched_at", TS, nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("reasons", JSONB, nullable=False),
        sa.Column("cves", JSONB, nullable=False),
        sa.Column("also_in", JSONB, nullable=False),
        sa.Column("seen_at", TS, nullable=True),
        sa.Column("backlog", sa.Boolean(), nullable=False),
        sa.Column("search", sa.Text(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["source_id"], ["news_sources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("url_key"),
    )
    op.create_index("ix_news_items_fetched", "news_items", ["fetched_at"], unique=False)
    op.create_index("ix_news_items_published", "news_items", ["published_at", "id"], unique=False)
    op.create_index(op.f("ix_news_items_seq"), "news_items", ["seq"], unique=False)
    op.create_index("ix_news_items_source", "news_items", ["source_id", "id"], unique=False)
    op.create_index("ix_news_items_title_key", "news_items", ["title_key"], unique=False)
    op.create_table(
        "notify_rule_channels",
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("channel_id", sa.Uuid(), nullable=False),
        sa.Column("added_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["channel_id"], ["notify_channels.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["rule_id"], ["notify_rules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("rule_id", "channel_id"),
    )
    op.create_index(op.f("ix_notify_rule_channels_channel_id"), "notify_rule_channels", ["channel_id"], unique=False)
    op.create_table(
        "push_subscriptions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("endpoint", sa.Text(), nullable=False),
        sa.Column("p256dh", sa.Text(), nullable=False),
        sa.Column("auth", sa.Text(), nullable=False),
        sa.Column("lang", sa.Text(), nullable=False),
        sa.Column("label", sa.Text(), nullable=False),
        sa.Column("cursor", sa.Integer(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_ok_at", TS, nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_error_at", TS, nullable=True),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("next_try_at", TS, nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("endpoint"),
    )
    op.create_index(op.f("ix_push_subscriptions_user_id"), "push_subscriptions", ["user_id"], unique=False)
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("stage", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_seen_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("ip", sa.Text(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("pending", JSONB, nullable=False),
        sa.Column("reauth_at", TS, nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_user_sessions_user_id"), "user_sessions", ["user_id"], unique=False)
    op.create_table(
        "vendor_advisory_products",
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("advisory_id", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["advisory_id"], ["vendor_advisories.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("product", "advisory_id"),
    )
    op.create_index(op.f("ix_vendor_advisory_products_advisory_id"), "vendor_advisory_products", ["advisory_id"], unique=False)
    op.create_table(
        "vendor_deliveries",
        sa.Column("channel_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.Uuid(), nullable=True),
        sa.Column("sent_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["channel_id"], ["notify_channels.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["vendor_events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("channel_id", "event_id"),
    )
    op.create_index(op.f("ix_vendor_deliveries_event_id"), "vendor_deliveries", ["event_id"], unique=False)
    op.create_table(
        "vendor_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("follow_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("label", sa.Text(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("baseline_at", TS, nullable=True),
        sa.ForeignKeyConstraint(["follow_id"], ["vendor_follows.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_vendor_versions_follow_id"), "vendor_versions", ["follow_id"], unique=False)
    op.create_table(
        "news_item_sources",
        sa.Column("item_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("n", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.ForeignKeyConstraint(["item_id"], ["news_items.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_id"], ["news_sources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("item_id", "source_id"),
        sa.UniqueConstraint("n"),
    )
    op.create_index(op.f("ix_news_item_sources_source_id"), "news_item_sources", ["source_id"], unique=False)
    op.create_table(
        "news_reads",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("item_id", sa.Uuid(), nullable=False),
        sa.Column("read_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["item_id"], ["news_items.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "item_id"),
    )
    op.create_index(op.f("ix_news_reads_item_id"), "news_reads", ["item_id"], unique=False)
    op.create_index("ix_news_reads_user_read", "news_reads", ["user_id", "read_at"], unique=False)
    op.create_table(
        "notify_deliveries",
        sa.Column("channel_id", sa.Uuid(), nullable=False),
        sa.Column("item_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.Uuid(), nullable=True),
        sa.Column("sent_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["channel_id"], ["notify_channels.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["item_id"], ["news_items.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("channel_id", "item_id"),
    )
    op.create_index(op.f("ix_notify_deliveries_item_id"), "notify_deliveries", ["item_id"], unique=False)
    op.create_table(
        "story_details",
        sa.Column("item_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("ident", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("data", JSONB, nullable=True),
        sa.Column("fetched_at", TS, nullable=True),
        sa.Column("next_try_at", TS, nullable=True),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["item_id"], ["news_items.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("item_id"),
    )


def downgrade() -> None:
    op.drop_table("story_details")
    op.drop_index(op.f("ix_notify_deliveries_item_id"), table_name="notify_deliveries")
    op.drop_table("notify_deliveries")
    op.drop_index("ix_news_reads_user_read", table_name="news_reads")
    op.drop_index(op.f("ix_news_reads_item_id"), table_name="news_reads")
    op.drop_table("news_reads")
    op.drop_index(op.f("ix_news_item_sources_source_id"), table_name="news_item_sources")
    op.drop_table("news_item_sources")
    op.drop_index(op.f("ix_vendor_versions_follow_id"), table_name="vendor_versions")
    op.drop_table("vendor_versions")
    op.drop_index(op.f("ix_vendor_deliveries_event_id"), table_name="vendor_deliveries")
    op.drop_table("vendor_deliveries")
    op.drop_index(op.f("ix_vendor_advisory_products_advisory_id"), table_name="vendor_advisory_products")
    op.drop_table("vendor_advisory_products")
    op.drop_index(op.f("ix_user_sessions_user_id"), table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_index(op.f("ix_push_subscriptions_user_id"), table_name="push_subscriptions")
    op.drop_table("push_subscriptions")
    op.drop_index(op.f("ix_notify_rule_channels_channel_id"), table_name="notify_rule_channels")
    op.drop_table("notify_rule_channels")
    op.drop_index("ix_news_items_title_key", table_name="news_items")
    op.drop_index("ix_news_items_source", table_name="news_items")
    op.drop_index(op.f("ix_news_items_seq"), table_name="news_items")
    op.drop_index("ix_news_items_published", table_name="news_items")
    op.drop_index("ix_news_items_fetched", table_name="news_items")
    op.drop_table("news_items")
    op.drop_table("vendor_kev")
    op.drop_table("vendor_follows")
    op.drop_table("vendor_fetch")
    op.drop_index("ix_vendor_events_scope", table_name="vendor_events")
    op.drop_index("ix_vendor_events_created", table_name="vendor_events")
    op.drop_table("vendor_events")
    op.drop_index("ix_vendor_advisories_published", table_name="vendor_advisories")
    op.drop_table("vendor_advisories")
    op.drop_index("ix_users_source_external", table_name="users")
    op.drop_table("users")
    op.drop_table("settings")
    op.drop_table("notify_rules")
    op.drop_table("notify_channels")
    op.drop_table("news_sources")
    op.drop_index("ux_group_mappings", table_name="group_mappings")
    op.drop_table("group_mappings")
    op.drop_table("counters")
