"""PostgreSQL 18.7 (0.1.57): the database image moves from 18.6 to 18.7. Among its fixes is one for GIN posting trees:
deleting a page after an incomplete page split could disconnect sibling pages, so that later index searches miss rows.
The fix prevents it from now on but does not repair an index that is already affected; the release notes recommend a
REINDEX "if you suspect this has happened". Nobody can tell from the outside, and the app's GIN indexes are small (a few
MB: the news search, CVEs, topics, products and systems of the stories, the CVEs of the advisories), so they are rebuilt
once, as a precaution.

Only the indexes on tables the app owns: the audit log belongs to cobe_news_audit (audit-lock.sql), the app may not
touch it – its search index is rebuilt by hand if ever needed (docs/BETRIEB.md: PostgreSQL). The other two index
problems of 18.7 do not apply: no btree on bpchar columns, no GiST trigram (gist_trgm_ops) index.

REINDEX (not CONCURRENTLY – that cannot run in the migration's transaction) blocks writes to the table for the moment
the rebuild takes – seconds at these sizes, while the app starts. The downgrade changes nothing.

Revision ID: 0049
Revises: 0048
Create Date: 2026-11-16
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0049"
down_revision: str | None = "0048"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $reindex$
        DECLARE r record;
        BEGIN
          FOR r IN
            SELECT i.oid::regclass AS idx
              FROM pg_index x
              JOIN pg_class i ON i.oid = x.indexrelid
              JOIN pg_class t ON t.oid = x.indrelid
              JOIN pg_am a ON a.oid = i.relam
             WHERE a.amname = 'gin' AND t.relnamespace = current_schema()::regnamespace
               AND pg_has_role(current_user, t.relowner, 'USAGE')
          LOOP
            EXECUTE format('REINDEX INDEX %s', r.idx);
          END LOOP;
        END
        $reindex$
        """
    )


def downgrade() -> None:
    pass
