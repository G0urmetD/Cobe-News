"""Personal delivery, more of it (0.1.35): quiet hours and what is urgent per person (person_notify.schedule), the
urgency of each queued event (person_deliveries.marks), absences with a deputy (person_absences) and the weekly review
of a team by e-mail (team_weekly, team_weekly_sends; person_notify.weekly_on / weekly_since). app/quiet.py,
app/absence.py, app/weekly.py.

Existing data: the new columns are added with a constant default (PostgreSQL stores it once – no table rewrite, instant
on any size) and the default is dropped again (the app always writes them). Every person starts with no quiet hours,
no absence and no weekly review – everything is delivered exactly as before until someone switches something on.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

TS = postgresql.TIMESTAMP(timezone=True)
JSONB = postgresql.JSONB()

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("person_notify", sa.Column("schedule", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")))
    op.add_column("person_notify", sa.Column("weekly_on", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("person_notify", sa.Column("weekly_since", TS, nullable=True))
    op.add_column("person_deliveries", sa.Column("marks", sa.SmallInteger(), nullable=False, server_default="0"))
    op.alter_column("person_notify", "schedule", server_default=None)
    op.alter_column("person_notify", "weekly_on", server_default=None)
    op.alter_column("person_deliveries", "marks", server_default=None)
    op.create_table(
        "person_absences",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("deputy_id", sa.Uuid(), nullable=False),
        sa.Column("starts_at", TS, nullable=False),
        sa.Column("ends_at", TS, nullable=False),
        sa.Column("also_me", sa.Boolean(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["deputy_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_person_absences_user", "person_absences", ["user_id", "ends_at"])
    op.create_index("ix_person_absences_deputy", "person_absences", ["deputy_id", "ends_at"])
    op.create_table(
        "team_weekly",
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("weekday", sa.SmallInteger(), nullable=False),
        sa.Column("at", sa.Text(), nullable=False),
        sa.Column("tz", sa.Text(), nullable=False),
        sa.Column("since", TS, nullable=False),
        sa.Column("last_week", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("team_id"),
    )
    op.create_table(
        "team_weekly_sends",
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("week", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("tries", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("claimed_at", TS, nullable=True),
        sa.Column("sent_at", TS, nullable=True),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("team_id", "user_id", "week"),
    )
    op.create_index("ix_team_weekly_sends_open", "team_weekly_sends", ["status", "created_at"])
    op.create_index(op.f("ix_team_weekly_sends_user_id"), "team_weekly_sends", ["user_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_team_weekly_sends_user_id"), table_name="team_weekly_sends")
    op.drop_index("ix_team_weekly_sends_open", table_name="team_weekly_sends")
    op.drop_table("team_weekly_sends")
    op.drop_table("team_weekly")
    op.drop_index("ix_person_absences_deputy", table_name="person_absences")
    op.drop_index("ix_person_absences_user", table_name="person_absences")
    op.drop_table("person_absences")
    op.drop_column("person_deliveries", "marks")
    op.drop_column("person_notify", "weekly_since")
    op.drop_column("person_notify", "weekly_on")
    op.drop_column("person_notify", "schedule")
