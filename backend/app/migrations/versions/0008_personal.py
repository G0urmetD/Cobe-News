"""Personal notifications (0.1.30): since when a person gets a team product by its routing (person_routes), a person's
own notification settings for the Vendor News of their products – e-mail, desktop push, a Microsoft Teams Workflows
webhook (person_notify) – and each event's delivery per person and way, at most once (person_deliveries).
app/personal.py.

New tables only – the upgrade is instant on any size of database, and nothing is sent until an admin allows a way
(Einstellungen → Teams) and a person switches it on.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)
JSONB = postgresql.JSONB()

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "person_routes",
        sa.Column("team_product_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("since", TS, nullable=False),
        sa.ForeignKeyConstraint(["team_product_id"], ["team_products.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("team_product_id", "user_id"),
    )
    op.create_index(op.f("ix_person_routes_user_id"), "person_routes", ["user_id"])
    op.create_table(
        "person_notify",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("lang", sa.Text(), nullable=False),
        sa.Column("kinds", JSONB, nullable=False),
        sa.Column("min_severity", sa.Text(), nullable=False),
        sa.Column("email_on", sa.Boolean(), nullable=False),
        sa.Column("email_since", TS, nullable=True),
        sa.Column("desktop_on", sa.Boolean(), nullable=False),
        sa.Column("desktop_since", TS, nullable=True),
        sa.Column("teams_on", sa.Boolean(), nullable=False),
        sa.Column("teams_since", TS, nullable=True),
        sa.Column("teams_url_enc", sa.Text(), nullable=True),
        sa.Column("teams_host", sa.Text(), nullable=True),
        sa.Column("state_email", JSONB, nullable=False),
        sa.Column("state_desktop", JSONB, nullable=False),
        sa.Column("state_teams", JSONB, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.create_table(
        "person_deliveries",
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("way", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("tries", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("claimed_at", TS, nullable=True),
        sa.Column("sent_at", TS, nullable=True),
        sa.ForeignKeyConstraint(["event_id"], ["vendor_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("event_id", "user_id", "way"),
    )
    op.create_index("ix_person_deliveries_open", "person_deliveries", ["status", "user_id", "way"])
    op.create_index("ix_person_deliveries_created", "person_deliveries", ["created_at"])
    op.create_index(op.f("ix_person_deliveries_user_id"), "person_deliveries", ["user_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_person_deliveries_user_id"), table_name="person_deliveries")
    op.drop_index("ix_person_deliveries_created", table_name="person_deliveries")
    op.drop_index("ix_person_deliveries_open", table_name="person_deliveries")
    op.drop_table("person_deliveries")
    op.drop_table("person_notify")
    op.drop_index(op.f("ix_person_routes_user_id"), table_name="person_routes")
    op.drop_table("person_routes")
