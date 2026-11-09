"""A person's "Hersteller-News meiner Produkte" by system: person_notify.systems – catalogue vendors or products
([{"vendor": …} | {"product": …}], app/concerns.py, as the channel rules' notify_rules.systems). Empty: every product of
the person's teams, as before.

Existing data: every person starts without ('[]' – unchanged, they get what they got before). One column with a
constant default: the table is not rewritten. The desktop choice (users.desktop, a JSON column) takes its systems,
words and exclusions without a migration. The downgrade drops the column.

Revision ID: 0040
Revises: 0039
Create Date: 2026-11-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0040"
down_revision: str | None = "0039"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("person_notify", sa.Column("systems", JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False))


def downgrade() -> None:
    op.drop_column("person_notify", "systems")
