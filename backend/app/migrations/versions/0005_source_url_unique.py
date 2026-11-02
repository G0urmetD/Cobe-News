"""One source per feed address: a unique index on news_sources(url) for the sources admins add (bug hunt 0.1.16 M3).

Up to 0.1.15 SQLite had one writer, and "insert unless the address exists" was atomic; under PostgreSQL two admins (or
a double click) adding the same address at once could get two sources. Duplicates that came about so are merged first
– the oldest one stays, the others hand over their stories, the stories they carried, their place in the notification
rules and in the desktop choices, then go. Built-in sources are not in the index: their address follows the code at each
start (a release may move one), and admins cannot add a built-in address anyway (checked by the API).

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _swap(ids: list | None, gone: str, keep: str) -> list | None:
    if not ids or gone not in ids:
        return None
    out: list = []
    for x in ids:
        x = keep if x == gone else x
        if x not in out:
            out.append(x)
    return out


def _merge(conn: sa.Connection) -> int:
    """Duplicates of one address merged into the oldest source of it; returns how many sources went."""
    groups = conn.execute(
        sa.text("SELECT url, array_agg(id ORDER BY created_at, id) AS ids FROM news_sources WHERE NOT builtin GROUP BY url HAVING count(*) > 1")
    ).all()
    gone_total = 0
    for _url, ids in groups:
        keep = ids[0]
        keep_name = conn.scalar(sa.text("SELECT name FROM news_sources WHERE id = :k"), {"k": keep})
        for gone in ids[1:]:
            gone_name = conn.scalar(sa.text("SELECT name FROM news_sources WHERE id = :g"), {"g": gone})
            touched = [
                r[0]
                for r in conn.execute(
                    sa.text("SELECT id FROM news_items WHERE source_id = :g UNION SELECT item_id FROM news_item_sources WHERE source_id = :g"), {"g": gone}
                )
            ]
            conn.execute(sa.text("UPDATE news_items SET source_id = :k WHERE source_id = :g"), {"k": keep, "g": gone})
            conn.execute(
                sa.text(
                    "INSERT INTO news_item_sources (item_id, source_id) SELECT item_id, :k FROM news_item_sources WHERE source_id = :g "
                    "ORDER BY n ON CONFLICT DO NOTHING"
                ),
                {"k": keep, "g": gone},
            )
            conn.execute(sa.text("DELETE FROM news_item_sources WHERE source_id = :g"), {"g": gone})
            # a story the kept source now owns is not "also in" itself
            conn.execute(sa.text("DELETE FROM news_item_sources s USING news_items i WHERE s.item_id = i.id AND s.source_id = i.source_id AND i.source_id = :k"), {"k": keep})
            for item_id in touched:
                row = conn.execute(sa.text("SELECT source_id, also_in FROM news_items WHERE id = :i"), {"i": item_id}).first()
                if row is None:
                    continue
                also: list = []
                for name in row.also_in or []:
                    name = keep_name if name == gone_name else name
                    if name not in also and not (row.source_id == keep and name == keep_name):
                        also.append(name)
                if also != (row.also_in or []):
                    conn.execute(sa.text("UPDATE news_items SET also_in = CAST(:a AS jsonb) WHERE id = :i"), {"a": _json(also), "i": item_id})
            g, k = str(gone), str(keep)
            for rid, sources in conn.execute(sa.text("SELECT id, sources FROM notify_rules")).all():
                if (new := _swap(sources, g, k)) is not None:
                    conn.execute(sa.text("UPDATE notify_rules SET sources = CAST(:s AS jsonb) WHERE id = :i"), {"s": _json(new), "i": rid})
            for uid, desktop in conn.execute(sa.text("SELECT id, desktop FROM users")).all():
                if isinstance(desktop, dict) and (new := _swap(desktop.get("sources"), g, k)) is not None:
                    conn.execute(sa.text("UPDATE users SET desktop = CAST(:d AS jsonb) WHERE id = :i"), {"d": _json({**desktop, "sources": new}), "i": uid})
            conn.execute(sa.text("DELETE FROM news_sources WHERE id = :g"), {"g": gone})
            gone_total += 1
    return gone_total


def _json(v: object) -> str:
    import json

    return json.dumps(v, ensure_ascii=False)


def upgrade() -> None:
    _merge(op.get_bind())
    op.create_index("ux_news_sources_url", "news_sources", ["url"], unique=True, postgresql_where=sa.text("NOT builtin"))


def downgrade() -> None:
    op.drop_index("ux_news_sources_url", table_name="news_sources")
