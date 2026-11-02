"""Catalogue duplicates merged (0.1.45, catalogue `replaces`): a product the catalogue had twice keeps one key –

    db2 → ibm-db2, vmware-horizon → horizon, juniper-srx → junos, vmware-harbor-registry → harbor, sns-hardware → sns-firmware,
    cisco-sma → cisco-esa (the key said SMA, the product was the Secure Email Gateway – SMA is cisco-sewm now)

Everything stored under the old key moves to the kept one, nothing is dropped silently:

- vendor_follows: renamed – or, when the kept product is followed as well, merged into that follow: its versions
  (a version text the kept follow already has stays once, the kept row wins), its team assignments (team_products; where
  the team has the kept product already, the chosen members and routes move to that assignment), note (appended), tags
  (united), switched on when either was. Then the old follow goes.
- vendor_events (product, key, scope – "vuln:db2:11.5.9:…" → "vuln:ibm-db2:11.5.9:…"): the findings and their
  "already notified" state move along, so nothing is notified again. An event the kept product has under the same key
  already stays as it is; the old one goes with its deliveries (the same finding twice).
- vendor_advisory_products, vendor_reads, person_mutes (product mutes: the later end wins), cve_watches.origin_product,
  product_suggestions.product_key, vendor_advisory_changes.products, saved_views (a product=… parameter), the keyword
  fetch state (vendor_fetch nvdkw:<key>).
- catalog_checks: the self-test's verdict of the old key goes (it is recomputed for the kept key).

The downgrade leaves the merged data where it is – ibm-db2, horizon, junos, harbor and sns-firmware are products of the
earlier catalogue as well (endoflife.date's), nothing is lost, the merge is not undone. Only cisco-esa, a key the earlier
catalogue does not know, goes back to cisco-sma (the same moves).

Revision ID: 0025
Revises: 0024
Create Date: 2026-11-02
"""

import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# old key → kept key; the catalogue says the same (`replaces` of the kept product – a test compares them)
MOVES: dict[str, str] = {
    "db2": "ibm-db2",
    "vmware-horizon": "horizon",
    "juniper-srx": "junos",
    "vmware-harbor-registry": "harbor",
    "sns-hardware": "sns-firmware",
    "cisco-sma": "cisco-esa",
}


def _typed(sql: str) -> str:
    """Parameters with their type (asyncpg cannot tell the type of a parameter in `'…' || $1`)."""
    sql = re.sub(r"(?<![:\w]):(old_rx|old|new)\b", r"CAST(:\1 AS text)", sql)
    return re.sub(r"(?<![:\w]):(o|n)\b", r"CAST(:\1 AS uuid)", sql)


def _move(conn, old: str, new: str) -> None:  # noqa: ANN001
    p = {"old": old, "new": new, "old_rx": re.escape(old)}
    x = lambda sql: conn.execute(sa.text(_typed(sql)), p)  # noqa: E731

    # ---- the follow
    old_id = conn.execute(sa.text("SELECT id FROM vendor_follows WHERE product = :old"), p).scalar()
    new_id = conn.execute(sa.text("SELECT id FROM vendor_follows WHERE product = :new"), p).scalar()
    if old_id is not None and new_id is None:
        x("UPDATE vendor_follows SET product = :new WHERE product = :old")
    elif old_id is not None:
        q = {"o": old_id, "n": new_id}
        y = lambda sql: conn.execute(sa.text(_typed(sql)), q)  # noqa: E731
        y("UPDATE vendor_versions SET follow_id = :n WHERE follow_id = :o AND version NOT IN (SELECT version FROM vendor_versions WHERE follow_id = :n)")
        # assignments of teams that do not have the kept product yet move as they are (members and routes with them)
        y("UPDATE team_products SET follow_id = :n WHERE follow_id = :o AND team_id NOT IN (SELECT team_id FROM team_products WHERE follow_id = :n)")
        # a team that has both: the chosen members and the routes join the kept assignment
        for table, col in (("team_product_members", "user_id"), ("person_routes", "user_id")):
            extra = ", since" if table == "person_routes" else ""
            y(
                f"INSERT INTO {table} (team_product_id, {col}{extra}) "  # noqa: S608 - fixed names
                f"SELECT k.id, m.{col}{', m.since' if extra else ''} FROM {table} m "
                "JOIN team_products t ON t.id = m.team_product_id AND t.follow_id = :o "
                "JOIN team_products k ON k.team_id = t.team_id AND k.follow_id = :n "
                "ON CONFLICT DO NOTHING"
            )
        y(
            "UPDATE vendor_follows n SET enabled = n.enabled OR o.enabled, "
            "note = CASE WHEN o.note = '' OR o.note = n.note THEN n.note WHEN n.note = '' THEN o.note ELSE n.note || E'\\n' || o.note END, "
            "tags = (SELECT COALESCE(jsonb_agg(t ORDER BY i), '[]'::jsonb) FROM (SELECT t, min(i) AS i FROM jsonb_array_elements(n.tags || o.tags) WITH ORDINALITY AS e(t, i) GROUP BY t) u), "
            "updated_at = now() FROM vendor_follows o WHERE n.id = :n AND o.id = :o"
        )
        y("DELETE FROM vendor_follows WHERE id = :o")  # its leftover versions and assignments go with it (cascade)

    # ---- the findings and their notified state
    rekey = "regexp_replace({c}, '^(exploited:)?([a-z]+):' || :old_rx || ':', '\\1\\2:' || :new || ':')"
    x(f"DELETE FROM vendor_events e WHERE e.product = :old AND EXISTS (SELECT 1 FROM vendor_events k WHERE k.key = {rekey.format(c='e.key')})")  # noqa: S608
    x(f"UPDATE vendor_events SET product = :new, key = {rekey.format(c='key')}, scope = CASE WHEN scope IS NULL THEN NULL ELSE {rekey.format(c='scope')} END WHERE product = :old")  # noqa: S608

    # ---- rows keyed by the product
    x("INSERT INTO vendor_advisory_products (product, advisory_id) SELECT :new, advisory_id FROM vendor_advisory_products WHERE product = :old ON CONFLICT DO NOTHING")
    x("DELETE FROM vendor_advisory_products WHERE product = :old")
    x("INSERT INTO vendor_reads (user_id, product, finding, read_at, unread) SELECT user_id, :new, finding, read_at, unread FROM vendor_reads WHERE product = :old ON CONFLICT DO NOTHING")
    x("DELETE FROM vendor_reads WHERE product = :old")
    x(
        "UPDATE person_mutes k SET until = GREATEST(k.until, o.until) FROM person_mutes o "
        "WHERE o.kind = 'product' AND o.key = :old AND k.kind = 'product' AND k.key = :new AND k.user_id = o.user_id"
    )
    x("DELETE FROM person_mutes o WHERE o.kind = 'product' AND o.key = :old AND EXISTS (SELECT 1 FROM person_mutes k WHERE k.kind = 'product' AND k.key = :new AND k.user_id = o.user_id)")
    x("UPDATE person_mutes SET key = :new WHERE kind = 'product' AND key = :old")
    x("UPDATE cve_watches SET origin_product = :new WHERE origin_product = :old")
    x("UPDATE product_suggestions SET product_key = :new WHERE product_key = :old")
    x(
        "UPDATE vendor_advisory_changes c SET products = (SELECT COALESCE(jsonb_agg(t ORDER BY i), '[]'::jsonb) FROM "
        "(SELECT t, min(i) AS i FROM jsonb_array_elements(CASE WHEN c.products ? :old THEN (c.products - :old) || jsonb_build_array(:new) ELSE c.products END) "
        "WITH ORDINALITY AS e(t, i) GROUP BY t) u) WHERE c.products ? :old"
    )
    x("UPDATE saved_views SET query = regexp_replace(query, '(^|&)product=' || :old_rx || '(&|$)', '\\1product=' || :new || '\\2') WHERE query ~ ('(^|&)product=' || :old_rx || '(&|$)')")
    x("UPDATE vendor_fetch SET key = 'nvdkw:' || :new WHERE key = 'nvdkw:' || :old AND NOT EXISTS (SELECT 1 FROM vendor_fetch WHERE key = 'nvdkw:' || :new)")
    x("DELETE FROM vendor_fetch WHERE key = 'nvdkw:' || :old")
    x("DELETE FROM catalog_checks WHERE product = :old")


def upgrade() -> None:
    conn = op.get_bind()
    for old, new in MOVES.items():
        _move(conn, old, new)


BACK: dict[str, str] = {"cisco-esa": "cisco-sma"}  # kept keys the earlier catalogue does not have


def downgrade() -> None:
    # the other kept keys are products of the earlier catalogue too – their data stays (module docstring)
    conn = op.get_bind()
    for new, old in BACK.items():
        _move(conn, new, old)
