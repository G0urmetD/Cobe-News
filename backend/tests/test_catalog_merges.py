"""Katalog-Erweiterung (0.1.45): duplicates merged into one key (catalogue `replaces`) and migration 0025, which moves
everything stored under an old key – follows, versions, team assignments and routes, findings with their notified state,
reads, mutes, watches, saved views – to the kept one."""

import importlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text

from app import db
from app import vendor_catalog as catalog
from app.models import (
    CatalogCheck,
    CveWatch,
    PersonMute,
    PersonRoute,
    SavedView,
    Team,
    TeamProduct,
    TeamProductMember,
    VendorAdvisory,
    VendorAdvisoryChange,
    VendorAdvisoryProduct,
    VendorEvent,
    VendorFollow,
    VendorRead,
    VendorVersion,
)

M = importlib.import_module("app.migrations.versions.0025_catalog_merges")


def test_catalogue_and_migration_name_the_same_merges():
    """What the catalogue says it replaces is exactly what migration 0025 moves – a merge without the migration would
    leave follows of a key the catalogue no longer has."""
    assert catalog.REPLACED == M.MOVES
    for old, new in M.MOVES.items():
        assert catalog.product(old) is None, old
        assert catalog.product(new) is not None, new


def test_replaced_names_stay_findable():
    by = {p["key"]: p for p in catalog.load()["products"]}
    assert "VMware Harbor Registry" in by["harbor"]["aliases"]
    assert by["horizon"]["category"] == "virtualization" and by["horizon"]["vendor"] == "Omnissa"
    assert by["ibm-db2"]["cna"] and by["ibm-db2"]["example"]
    assert "SRX" in by["junos"]["aliases"]
    assert by["sns-firmware"]["category"] == "firewall"


async def _seed(user_id):  # noqa: ANN001
    now = datetime.now(UTC)
    async with db.session() as s:
        old = VendorFollow(product="db2", note="Rechenzentrum", tags=["prod", "dc"])
        kept = VendorFollow(product="ibm-db2", note="Altsystem", tags=["dc", "legacy"], enabled=False)
        hz = VendorFollow(product="vmware-horizon")
        s.add_all([old, kept, hz])
        await s.flush()
        s.add_all(
            [
                VendorVersion(follow_id=old.id, version="11.5.9", label="alt"),
                VendorVersion(follow_id=old.id, version="11.5.8", label="RZ2"),
                VendorVersion(follow_id=kept.id, version="11.5.9", label="neu"),
                VendorVersion(follow_id=hz.id, version="2412"),
            ]
        )
        both, only_old = Team(name="Datenbanken"), Team(name="Betrieb")
        s.add_all([both, only_old])
        await s.flush()
        tp_old_both = TeamProduct(team_id=both.id, follow_id=old.id, all_members=False)
        tp_kept_both = TeamProduct(team_id=both.id, follow_id=kept.id, all_members=False)
        tp_only = TeamProduct(team_id=only_old.id, follow_id=old.id)
        s.add_all([tp_old_both, tp_kept_both, tp_only])
        await s.flush()
        s.add_all([TeamProductMember(team_product_id=tp_old_both.id, user_id=user_id), PersonRoute(team_product_id=tp_old_both.id, user_id=user_id, since=now)])
        s.add(VendorAdvisory(id="nvd:CVE-2026-1001", source="nvd", ident="CVE-2026-1001", cves=["CVE-2026-1001"], data={}))
        s.add(VendorAdvisory(id="nvd:CVE-2026-1002", source="nvd", ident="CVE-2026-1002", cves=["CVE-2026-1002"], data={}))
        await s.flush()
        s.add_all(
            [
                VendorAdvisoryProduct(product="db2", advisory_id="nvd:CVE-2026-1001"),
                VendorAdvisoryProduct(product="db2", advisory_id="nvd:CVE-2026-1002"),
                VendorAdvisoryProduct(product="ibm-db2", advisory_id="nvd:CVE-2026-1002"),
                VendorEvent(key="vuln:db2:11.5.8:nvd:CVE-2026-1001", kind="vuln", product="db2", scope="vuln:db2:11.5.8"),
                VendorEvent(key="exploited:vuln:db2:11.5.8:nvd:CVE-2026-1001", kind="vuln", product="db2", scope="vuln:db2:11.5.8"),
                VendorEvent(key="vuln:db2:11.5.9:nvd:CVE-2026-1002", kind="vuln", product="db2", scope="vuln:db2:11.5.9"),
                VendorEvent(key="vuln:ibm-db2:11.5.9:nvd:CVE-2026-1002", kind="vuln", product="ibm-db2", scope="vuln:ibm-db2:11.5.9"),
                VendorEvent(key="eol:db2:11.5.8:soon", kind="eol", product="db2"),
                VendorRead(user_id=user_id, product="db2", finding="nvd:CVE-2026-1001"),
                PersonMute(user_id=user_id, kind="product", key="db2", until=now + timedelta(days=7)),
                PersonMute(user_id=user_id, kind="product", key="ibm-db2", until=now + timedelta(days=1)),
                PersonMute(user_id=user_id, kind="product", key="juniper-srx", until=now + timedelta(days=3)),
                CveWatch(user_id=user_id, cve="CVE-2026-1001", origin_kind="finding", origin_ref="nvd:CVE-2026-1001", origin_product="juniper-srx"),
                SavedView(user_id=user_id, page="vendor", name="Horizon", query="tab=findings&product=vmware-horizon&severity=high"),
                SavedView(user_id=user_id, page="vendor", name="Andere", query="product=vmware-horizon-x"),
                VendorAdvisoryChange(advisory_id="nvd:CVE-2026-1001", source="nvd", revision=2, products=["db2", "ibm-db2", "other"]),
                CatalogCheck(product="db2", status="ok"),
            ]
        )
        await s.commit()
    return old.id, kept.id, tp_old_both.id, tp_kept_both.id, tp_only.id


async def test_migration_0025_moves_everything_to_the_kept_key(admin_client):
    uid = admin_client.user.id
    _old, _kept, _tp_old_both, tp_kept_both, tp_only = await _seed(uid)

    from alembic import command

    def step(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "0024")
        command.upgrade(db.alembic_config(conn), "0025")
        q = lambda sql: conn.execute(text(sql)).all()  # noqa: E731
        return {
            "follows": q("SELECT product, enabled, note, tags FROM vendor_follows ORDER BY product"),
            "versions": q("SELECT f.product, v.version, v.label FROM vendor_versions v JOIN vendor_follows f ON f.id = v.follow_id ORDER BY 1, 2"),
            "teams": q("SELECT t.name, f.product, tp.id::text FROM team_products tp JOIN teams t ON t.id = tp.team_id JOIN vendor_follows f ON f.id = tp.follow_id ORDER BY 1"),
            "members": q("SELECT team_product_id::text FROM team_product_members"),
            "routes": q("SELECT team_product_id::text FROM person_routes"),
            "events": q("SELECT key, product, scope FROM vendor_events ORDER BY key"),
            "links": q("SELECT product, advisory_id FROM vendor_advisory_products ORDER BY 2, 1"),
            "reads": q("SELECT product, finding FROM vendor_reads"),
            "mutes": q("SELECT key, until FROM person_mutes ORDER BY key"),
            "watch": q("SELECT origin_product FROM cve_watches"),
            "views": q("SELECT query FROM saved_views ORDER BY name"),
            "changes": q("SELECT products FROM vendor_advisory_changes"),
            "checks": q("SELECT product FROM catalog_checks"),
        }

    async with db.engine().connect() as conn:
        trans = await conn.begin()
        try:
            got = await conn.run_sync(step)
        finally:
            await trans.rollback()

    # one follow per kept key: db2 merged into ibm-db2 (on: either was; notes and tags joined), vmware-horizon renamed
    assert [(r[0], r[1]) for r in got["follows"]] == [("horizon", True), ("ibm-db2", True)]
    ibm = next(r for r in got["follows"] if r[0] == "ibm-db2")
    assert ibm[2] == "Altsystem\nRechenzentrum" and ibm[3] == ["dc", "legacy", "prod"]
    # the kept row wins for a version both had; the other version moved
    assert got["versions"] == [("horizon", "2412", ""), ("ibm-db2", "11.5.8", "RZ2"), ("ibm-db2", "11.5.9", "neu")]
    # the team with only db2 keeps its assignment (now ibm-db2); the team with both has one, members and routes joined it
    assert sorted((n, p) for n, p, _ in got["teams"]) == [("Betrieb", "ibm-db2"), ("Datenbanken", "ibm-db2")]
    assert {i for _, _, i in got["teams"]} == {str(tp_kept_both), str(tp_only)}
    assert got["members"] == [(str(tp_kept_both),)] and got["routes"] == [(str(tp_kept_both),)]
    # findings keep their notified state under the new key; the same finding under both keys stays once
    assert got["events"] == [
        ("eol:ibm-db2:11.5.8:soon", "ibm-db2", None),
        ("exploited:vuln:ibm-db2:11.5.8:nvd:CVE-2026-1001", "ibm-db2", "vuln:ibm-db2:11.5.8"),
        ("vuln:ibm-db2:11.5.8:nvd:CVE-2026-1001", "ibm-db2", "vuln:ibm-db2:11.5.8"),
        ("vuln:ibm-db2:11.5.9:nvd:CVE-2026-1002", "ibm-db2", "vuln:ibm-db2:11.5.9"),
    ]
    assert got["links"] == [("ibm-db2", "nvd:CVE-2026-1001"), ("ibm-db2", "nvd:CVE-2026-1002")]
    assert got["reads"] == [("ibm-db2", "nvd:CVE-2026-1001")]
    # mutes: the later end wins where both were muted; juniper-srx → junos
    mutes = dict(got["mutes"])
    assert set(mutes) == {"ibm-db2", "junos"} and mutes["ibm-db2"] > datetime.now(UTC) + timedelta(days=6)
    assert got["watch"] == [("junos",)]
    assert got["views"] == [("product=vmware-horizon-x",), ("tab=findings&product=horizon&severity=high",)]
    assert got["changes"] == [(["ibm-db2", "other"],)]
    assert got["checks"] == []


async def test_migration_0025_without_data_and_down_again():
    """Nothing to move: the upgrade changes nothing; the downgrade leaves the data (the kept keys are earlier products)."""
    from alembic import command

    async with db.session() as s:
        s.add(VendorFollow(product="junos"))
        await s.commit()

    def step(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "0024")
        command.upgrade(db.alembic_config(conn), "0025")
        command.downgrade(db.alembic_config(conn), "0024")
        return conn.execute(text("SELECT product FROM vendor_follows")).all()

    async with db.engine().connect() as conn:
        trans = await conn.begin()
        try:
            rows = await conn.run_sync(step)
        finally:
            await trans.rollback()
    assert rows == [("junos",)]
    async with db.session() as s:
        assert (await s.scalars(select(VendorFollow.product))).all() == ["junos"]


async def test_an_old_link_opens_the_kept_product(reader_client):
    r = await reader_client.get("/api/vendor/products/db2")
    assert r.status_code == 200 and r.json()["product"]["key"] == "ibm-db2"
    assert (await reader_client.get("/api/vendor/products/no-such-product")).status_code == 404
