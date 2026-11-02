"""Alembic: run by app.db.migrate() with an open connection (app start, CLI), or by the `alembic` command for development
(`cd backend && DATABASE_URL=postgresql://… uv run alembic revision --autogenerate -m "…"`)."""

import asyncio

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from app import models  # noqa: F401 - registers the tables
from app.db import Base

target_metadata = Base.metadata


def _run(connection) -> None:  # noqa: ANN001
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True, compare_server_default=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    from app.config import get_config

    context.configure(url=get_config().database_url.render_as_string(hide_password=True), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


async def _online() -> None:
    from app.config import get_config

    engine = create_async_engine(get_config().database_url)
    async with engine.begin() as conn:
        await conn.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
elif (conn := context.config.attributes.get("connection")) is not None:
    _run(conn)
else:
    asyncio.run(_online())
