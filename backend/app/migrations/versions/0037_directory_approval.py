"""Directory accounts: approval by an admin ("Automatische Anmeldung über AD/Entra ID zulassen" off) – users.pending_role,
the raise to admin that waits for an admin's approval ("admin") or that an admin declined ("declined"). A waiting
account itself needs no column: is_active false with deactivated_reason "pending". Nothing else changes – the switch
is on by default (settings section "directory"), every account keeps its state.

Revision ID: 0037
Revises: 0036
Create Date: 2026-11-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0037"
down_revision: str | None = "0036"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("pending_role", sa.Text(), nullable=True))


def downgrade() -> None:
    # an account still waiting for approval stays off after the downgrade (deactivated_reason "pending" is no "sync:"
    # reason – neither the sync nor a sign-in of an older version switches it on); a waiting raise is forgotten
    op.drop_column("users", "pending_role")
