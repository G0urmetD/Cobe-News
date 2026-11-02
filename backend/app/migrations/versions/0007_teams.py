"""Teams (0.1.28): teams bound to directory groups (team_groups), their members (team_members – loaded from the groups,
or local accounts added by hand), the followed products of a team (team_products, with team_product_members prepared
for per-person routing), the welcome e-mail of a loaded person (team_welcome) and rules limited to teams
(notify_rule_teams). app/teams.py.

New tables only – the upgrade is instant on any size of database, and nothing changes until Teams is switched on.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "teams",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "team_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("group_id", sa.Text(), nullable=False),
        sa.Column("group_name", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("members", sa.Integer(), nullable=False),
        sa.Column("synced_at", TS, nullable=True),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ux_team_groups", "team_groups", ["team_id", "source", "group_id"], unique=True)
    op.create_index("ix_team_groups_group", "team_groups", ["source", "group_id"])
    op.create_table(
        "team_members",
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("origin", sa.Text(), nullable=False),
        sa.Column("added_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("team_id", "user_id"),
    )
    op.create_index(op.f("ix_team_members_user_id"), "team_members", ["user_id"])
    op.create_table(
        "team_products",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("follow_id", sa.Uuid(), nullable=False),
        sa.Column("all_members", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("added_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["follow_id"], ["vendor_follows.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ux_team_products", "team_products", ["team_id", "follow_id"], unique=True)
    op.create_index(op.f("ix_team_products_follow_id"), "team_products", ["follow_id"])
    op.create_table(
        "team_product_members",
        sa.Column("team_product_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["team_product_id"], ["team_products.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("team_product_id", "user_id"),
    )
    op.create_index(op.f("ix_team_product_members_user_id"), "team_product_members", ["user_id"])
    op.create_table(
        "team_welcome",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("external_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("tries", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("sent_at", TS, nullable=True),
        sa.PrimaryKeyConstraint("source", "external_id"),
    )
    op.create_table(
        "notify_rule_teams",
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["rule_id"], ["notify_rules.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("rule_id", "team_id"),
    )
    op.create_index(op.f("ix_notify_rule_teams_team_id"), "notify_rule_teams", ["team_id"])


def downgrade() -> None:
    # the accounts the teams loaded stay (directory accounts, as if they had signed in) – the hourly sync decides on them
    op.drop_index(op.f("ix_notify_rule_teams_team_id"), table_name="notify_rule_teams")
    op.drop_table("notify_rule_teams")
    op.drop_table("team_welcome")
    op.drop_index(op.f("ix_team_product_members_user_id"), table_name="team_product_members")
    op.drop_table("team_product_members")
    op.drop_index(op.f("ix_team_products_follow_id"), table_name="team_products")
    op.drop_index("ux_team_products", table_name="team_products")
    op.drop_table("team_products")
    op.drop_index(op.f("ix_team_members_user_id"), table_name="team_members")
    op.drop_table("team_members")
    op.drop_index("ix_team_groups_group", table_name="team_groups")
    op.drop_index("ux_team_groups", table_name="team_groups")
    op.drop_table("team_groups")
    op.drop_table("teams")
    op.execute("DELETE FROM settings WHERE key = 'teams'")
