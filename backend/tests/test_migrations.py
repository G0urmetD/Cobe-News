"""The schema comes from Alembic (app/migrations) – and it is exactly what the models say: a column or index added to a
model without a migration (or the other way round) fails here instead of on a live database."""

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext

from app import db
from app.db import Base


async def test_models_and_migrations_agree():
    def diff(conn):  # noqa: ANN001, ANN202
        ctx = MigrationContext.configure(conn, opts={"compare_type": True, "compare_server_default": True})
        return compare_metadata(ctx, Base.metadata)

    async with db.engine().connect() as conn:
        assert await conn.run_sync(diff) == []
    assert await db.revision() == db.head()


async def test_pg_trgm_serves_the_search():
    """The search (LIKE '%…%') can use the trigram index (on a few test rows the planner would rather read them all)."""
    from sqlalchemy import text

    async with db.engine().begin() as conn:
        await conn.execute(text("SET LOCAL enable_seqscan = off"))
        plan = "\n".join(await conn.scalars(text("EXPLAIN SELECT id FROM news_items WHERE search LIKE '%gitlab%'")))
    assert "ix_news_items_search_trgm" in plan, plan
