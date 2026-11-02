"""CVE beobachten, 0.1.42 (app/cve_watch.py, app/watch_api.py): "Alle beobachten" of a story or a finding (bulk), the
origin of each watch (resolved by the server, the title from the database), the first origin stays, the groups of the
list and "Gruppe nicht mehr beobachten", the limit of 500 (and what fits when fewer places are left), the bulk rate
limit, migration 0022 down and up, and a list of 500 watched CVEs read with a bounded number of queries."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import event, select

from app import cve_watch, db, news, vendor, watch_api
from app.models import CveWatch, NewsItem, NewsSource, StoryDetail, VendorAdvisory, VendorAdvisoryProduct, VendorFetch, VendorFollow, VendorKev, VendorVersion

STORY_CVES = ["CVE-2026-0101", "CVE-2026-0102", "CVE-2026-0103"]
DETAIL_CVES = ["CVE-2026-0104", "CVE-2026-0105"]


async def _story(title: str = "GitLab Patch Release 18.5.2", cves: list[str] | None = None, *, enabled: bool = True, details: list[str] | None = None) -> str:
    async with db.session() as s:
        await news.ensure_sources(s)
        src = NewsSource(key=f"feed-wg-{uuid.uuid4().hex[:6]}", name="Example Feed", url=f"https://news.example.org/{uuid.uuid4().hex[:6]}.xml", site="", builtin=False, enabled=enabled, failures=0)
        s.add(src)
        await s.flush()
        now = datetime.now(UTC)
        i = NewsItem(
            source_id=src.id, url=f"https://news.example.org/{uuid.uuid4().hex}", url_key=uuid.uuid4().hex, title=title, title_key=uuid.uuid4().hex, summary="",
            published_at=now, fetched_at=now, severity="high", cves=list(STORY_CVES if cves is None else cves), seq=await news.next_seq(s),
        )
        s.add(i)
        await s.flush()
        if details is not None:
            s.add(StoryDetail(item_id=i.id, kind="nvd", ident="x", status="ok", data={"cves": details}, fetched_at=now))
        await s.commit()
        return str(i.id)


async def _finding(cves: list[str]) -> tuple[str, str]:
    now = datetime.now(UTC)
    async with db.session() as s:
        f = VendorFollow(product="typo3", enabled=True, created_at=now, updated_at=now)
        s.add(f)
        await s.flush()
        s.add(VendorVersion(follow_id=f.id, version="13.4.37", label="Website", count=None))
        m = {"vulnerable": True, "criteria": "cpe:2.3:a:typo3:typo3:*:*:*:*:*:*:*:*", "versionStartIncluding": "13.0.0", "versionEndExcluding": "13.4.38"}
        a = VendorAdvisory(
            id=f"nvd:{cves[0]}", source="nvd", ident=cves[0], title="TYPO3 issue", summary="An issue.", url=f"https://nvd.nist.gov/vuln/detail/{cves[0]}",
            cves=cves, cvss=9.8, severity="critical", exploited=False, published_at=now - timedelta(days=60), updated_at=None,
            data={"configs": [{"nodes": [{"cpeMatch": [m]}]}], "cna": [], "desc": "An issue.", "cwe": []}, fetched_at=now,
        )
        s.add(a)
        s.add(VendorAdvisoryProduct(product="typo3", advisory_id=a.id))
        s.add(VendorFetch(key="nvd:a:typo3:typo3", failures=0, items=1, last_ok_at=now))
        await s.commit()
    vendor.bump()
    return "typo3", f"nvd:{cves[0]}"


async def _rows(user) -> dict[str, CveWatch]:  # noqa: ANN001
    async with db.session() as s:
        return {r.cve: r for r in await s.scalars(select(CveWatch).where(CveWatch.user_id == user.id))}


def test_the_limit_is_500():
    assert cve_watch.MAX_PER_PERSON == 500 and cve_watch.BULK_MAX == 500


# ---------------------------------------------------------------- watch all of a story / a finding


async def test_bulk_of_a_story_with_its_title_from_the_database(reader_client):
    sid = await _story(details=DETAIL_CVES)
    every = [*STORY_CVES, *DETAIL_CVES]
    r = await reader_client.post("/api/me/cve-watch/bulk", json={"cves": [c.lower() for c in every], "origin": {"kind": "story", "id": sid}})
    assert r.status_code == 200, r.text
    assert r.json() == {"added": every, "already": [], "skipped": [], "limit": 500, "count": 5}
    rows = await _rows(reader_client.user)
    assert {(r.origin_kind, r.origin_ref, r.origin_title) for r in rows.values()} == {("story", sid, "GitLab Patch Release 18.5.2")}
    items = (await reader_client.get("/api/me/cve-watch")).json()["items"]
    assert {i["cve"]: i["origin"] for i in items}[STORY_CVES[0]] == {"kind": "story", "id": sid, "title": "GitLab Patch Release 18.5.2"}
    # again: nothing new, nothing changed
    r = await reader_client.post("/api/me/cve-watch/bulk", json={"cves": every, "origin": {"kind": "story", "id": sid}})
    assert r.json()["added"] == [] and r.json()["already"] == every
    # a title from the client is refused (the snapshot is the server's)
    r = await reader_client.post("/api/me/cve-watch/bulk", json={"cves": every, "origin": {"kind": "story", "id": sid, "title": "Fake"}})
    assert r.status_code == 422


async def test_bulk_refuses_what_the_origin_does_not_name_and_invisible_stories(reader_client):
    sid = await _story()
    bad = await reader_client.post("/api/me/cve-watch/bulk", json={"cves": ["CVE-2026-0101", "CVE-2026-9999"], "origin": {"kind": "story", "id": sid}})
    assert bad.status_code == 422 and bad.json()["detail"] == {"code": "cve_not_in_origin", "cves": ["CVE-2026-9999"]}
    assert (await reader_client.post("/api/me/cve-watch/bulk", json={"cves": ["CVE-2026-12a4"], "origin": {"kind": "story", "id": sid}})).json()["detail"]["code"] == "invalid_cve"
    # a story of a switched-off source, an unknown one: as if there were none
    off = await _story(enabled=False)
    for story in (off, str(uuid.uuid4())):
        r = await reader_client.post("/api/me/cve-watch/bulk", json={"cves": STORY_CVES[:1], "origin": {"kind": "story", "id": story}})
        assert r.status_code == 404 and r.json()["detail"]["code"] == "origin_not_found"
        r = await reader_client.post("/api/me/cve-watch", json={"cve": STORY_CVES[0], "origin": {"kind": "story", "id": story}})
        assert r.status_code == 404
    assert (await reader_client.post("/api/me/cve-watch/bulk", json={"cves": STORY_CVES, "origin": {"kind": "nope"}})).status_code == 422
    assert (await reader_client.post("/api/me/cve-watch/bulk", json={"cves": [], "origin": {"kind": "manual"}})).status_code == 422
    too_many = [f"CVE-2026-{10000 + i}" for i in range(501)]
    assert (await reader_client.post("/api/me/cve-watch/bulk", json={"cves": too_many, "origin": {"kind": "manual"}})).status_code == 422
    assert await _rows(reader_client.user) == {}


async def test_bulk_of_a_finding(reader_client):
    cves = ["CVE-2026-50030", "CVE-2026-50031", "CVE-2026-50032"]
    product, fid = await _finding(cves)
    r = await reader_client.post("/api/me/cve-watch/bulk", json={"cves": cves, "origin": {"kind": "finding", "product": product, "advisory": fid}})
    assert r.status_code == 200, r.text
    assert r.json()["added"] == cves
    row = (await _rows(reader_client.user))[cves[1]]
    assert (row.origin_kind, row.origin_product, row.origin_ref) == ("finding", "typo3", fid)
    assert row.origin_title.startswith("TYPO3") and "CVE-2026-50030" in row.origin_title
    # a product not followed, a finding the product does not have
    for o in ({"kind": "finding", "product": "panos", "advisory": fid}, {"kind": "finding", "product": product, "advisory": "nvd:CVE-1999-0001"}):
        assert (await reader_client.post("/api/me/cve-watch/bulk", json={"cves": cves, "origin": o})).status_code == 404


async def test_the_first_origin_stays(reader_client):
    sid = await _story()
    other = await _story(title="Another story", cves=STORY_CVES)
    assert (await reader_client.post("/api/me/cve-watch", json={"cve": STORY_CVES[0]})).json()["added"] is True  # typed on the list
    r = await reader_client.post("/api/me/cve-watch/bulk", json={"cves": STORY_CVES, "origin": {"kind": "story", "id": sid}})
    assert r.json()["added"] == STORY_CVES[1:] and r.json()["already"] == STORY_CVES[:1]
    # the star of another story: watched already – nothing changes
    r = await reader_client.post("/api/me/cve-watch", json={"cve": STORY_CVES[1], "origin": {"kind": "story", "id": other}})
    assert r.json() == {"cve": STORY_CVES[1], "added": False}
    rows = await _rows(reader_client.user)
    assert rows[STORY_CVES[0]].origin_kind == "manual" and rows[STORY_CVES[0]].origin_title is None
    assert rows[STORY_CVES[1]].origin_ref == sid and rows[STORY_CVES[2]].origin_ref == sid
    # the single star with a story: its origin
    third = await _story(title="Third", cves=["CVE-2026-0300"])
    assert (await reader_client.post("/api/me/cve-watch", json={"cve": "CVE-2026-0300", "origin": {"kind": "story", "id": third}})).json()["added"] is True
    assert (await _rows(reader_client.user))["CVE-2026-0300"].origin_title == "Third"
    # a CVE the story does not name
    r = await reader_client.post("/api/me/cve-watch", json={"cve": "CVE-2026-0301", "origin": {"kind": "story", "id": third}})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "cve_not_in_origin"


async def test_limit_edges_of_the_bulk(reader_client, monkeypatch):
    monkeypatch.setattr(cve_watch, "MAX_PER_PERSON", 5)
    for c in ("CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"):
        await reader_client.post("/api/me/cve-watch", json={"cve": c})
    many = ["CVE-2026-0201", "CVE-2026-0202", "CVE-2026-0203", "CVE-2026-0204"]
    sid = await _story(cves=["CVE-2025-0001", *many])
    body = {"cves": ["CVE-2025-0001", *many], "origin": {"kind": "story", "id": sid}}
    r = await reader_client.post("/api/me/cve-watch/bulk", json=body)
    assert r.status_code == 409 and r.json()["detail"] == {"code": "watch_limit", "limit": 5, "free": 2, "wanted": 4}
    assert len(await _rows(reader_client.user)) == 3  # nothing of it
    r = await reader_client.post("/api/me/cve-watch/bulk", json={**body, "partial": True})
    assert r.status_code == 200
    assert r.json() == {"added": many[:2], "already": ["CVE-2025-0001"], "skipped": many[2:], "limit": 5, "count": 5}
    # full: also "partial" watches nothing
    r = await reader_client.post("/api/me/cve-watch/bulk", json={**body, "partial": True})
    assert r.status_code == 409 and r.json()["detail"]["free"] == 0
    # exactly what fits
    await reader_client.post("/api/me/cve-watch/bulk-remove", json={"cves": many[:2]})
    r = await reader_client.post("/api/me/cve-watch/bulk", json={"cves": many[:2], "origin": {"kind": "story", "id": sid}})
    assert r.status_code == 200 and r.json()["count"] == 5


async def test_bulk_rate_limit(reader_client, monkeypatch):
    monkeypatch.setattr(watch_api, "BULK_PER", 2)
    now = [1000.0]
    monkeypatch.setattr(watch_api, "clock", lambda: now[0])
    for _ in range(2):
        assert (await reader_client.post("/api/me/cve-watch/bulk", json={"cves": ["CVE-2026-0001"], "origin": {"kind": "manual"}})).status_code == 200
    r = await reader_client.post("/api/me/cve-watch/bulk", json={"cves": ["CVE-2026-0001"], "origin": {"kind": "manual"}})
    assert r.status_code == 429 and r.json()["detail"]["code"] == "watch_rate_limited" and r.json()["detail"]["retry_after"] == 300
    now[0] += watch_api.BULK_WINDOW
    assert (await reader_client.post("/api/me/cve-watch/bulk", json={"cves": ["CVE-2026-0001"], "origin": {"kind": "manual"}})).status_code == 200


# ---------------------------------------------------------------- groups


async def test_group_remove_and_undo(reader_client, admin_client):
    sid = await _story()
    other = await _story(title="Other", cves=["CVE-2026-0400"])
    await reader_client.post("/api/me/cve-watch/bulk", json={"cves": STORY_CVES, "origin": {"kind": "story", "id": sid}})
    await reader_client.post("/api/me/cve-watch", json={"cve": "CVE-2026-0400", "origin": {"kind": "story", "id": other}})
    await reader_client.post("/api/me/cve-watch", json={"cve": "CVE-2025-1111"})
    await admin_client.post("/api/me/cve-watch/bulk", json={"cves": STORY_CVES, "origin": {"kind": "story", "id": sid}})
    async with db.session() as s:  # a watch from before 0.1.42: no origin – one of the manual group
        s.add(CveWatch(user_id=reader_client.user.id, cve="CVE-2024-0001", created_at=datetime.now(UTC)))
        await s.commit()
    items = (await reader_client.get("/api/me/cve-watch")).json()["items"]
    assert {i["cve"]: i["origin"] for i in items}["CVE-2024-0001"] is None
    r = await reader_client.post("/api/me/cve-watch/bulk-remove", json={"group": {"kind": "story", "id": sid}})
    assert r.status_code == 200
    gone = r.json()["removed"]
    assert sorted(g["cve"] for g in gone) == STORY_CVES and all(g["origin"] == {"kind": "story", "id": sid, "title": "GitLab Patch Release 18.5.2"} for g in gone)
    assert set(await _rows(reader_client.user)) == {"CVE-2026-0400", "CVE-2025-1111", "CVE-2024-0001"}
    assert len(await _rows(admin_client.user)) == 3  # the other person's stay
    # undo: watched again with the same origin (from now on)
    o = {k: v for k, v in gone[0]["origin"].items() if k != "title"}
    r = await reader_client.post("/api/me/cve-watch/bulk", json={"cves": [g["cve"] for g in gone], "origin": o})
    assert sorted(r.json()["added"]) == STORY_CVES
    # the manual group: typed ones and those of unknown origin
    r = await reader_client.post("/api/me/cve-watch/bulk-remove", json={"group": {"kind": "manual"}})
    assert sorted(g["cve"] for g in r.json()["removed"]) == ["CVE-2024-0001", "CVE-2025-1111"]
    # by CVE ("Alle nicht mehr beobachten" of a story): only the own rows, whatever their origin
    r = await reader_client.post("/api/me/cve-watch/bulk-remove", json={"cves": [*STORY_CVES, "CVE-2026-0400", "CVE-2026-0999"]})
    assert len(r.json()["removed"]) == 4 and await _rows(reader_client.user) == {}
    assert len(await _rows(admin_client.user)) == 3
    # one of the two, never both or none; ids only
    assert (await reader_client.post("/api/me/cve-watch/bulk-remove", json={})).status_code == 422
    assert (await reader_client.post("/api/me/cve-watch/bulk-remove", json={"cves": STORY_CVES, "group": {"kind": "manual"}})).status_code == 422
    assert (await reader_client.post("/api/me/cve-watch/bulk-remove", json={"cves": ["nope-nope-1"]})).status_code == 422


async def test_finding_group_remove(reader_client):
    cves = ["CVE-2026-50030", "CVE-2026-50031"]
    product, fid = await _finding(cves)
    await reader_client.post("/api/me/cve-watch/bulk", json={"cves": cves, "origin": {"kind": "finding", "product": product, "advisory": fid}})
    await reader_client.post("/api/me/cve-watch/bulk-remove", json={"group": {"kind": "finding", "product": product, "advisory": "nvd:other"}})
    assert len(await _rows(reader_client.user)) == 2
    r = await reader_client.post("/api/me/cve-watch/bulk-remove", json={"group": {"kind": "finding", "product": product, "advisory": fid}})
    assert len(r.json()["removed"]) == 2 and await _rows(reader_client.user) == {}


# ---------------------------------------------------------------- the schema, the size of the list


async def test_migration_0022_down_and_up():
    """Four nullable columns: the downgrade drops them (the watches stay), the upgrade brings them back – in a
    transaction that is rolled back."""
    from alembic import command
    from sqlalchemy import inspect

    names = {"origin_kind", "origin_ref", "origin_product", "origin_title"}

    def step(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "0021")
        before = {c["name"] for c in inspect(conn).get_columns("cve_watches")}
        command.upgrade(db.alembic_config(conn), "0022")
        return before, {c["name"]: c["nullable"] for c in inspect(conn).get_columns("cve_watches")}

    async with db.engine().connect() as conn:
        trans = await conn.begin()
        try:
            before, after = await conn.run_sync(step)
        finally:
            await trans.rollback()
    assert not names & before and {"user_id", "cve", "created_at"} <= before
    assert all(after[n] is True for n in names)


async def _seed(user, n: int, start: int = 20000) -> None:  # noqa: ANN001
    now = datetime.now(UTC)
    cves = [f"CVE-2026-{start + i}" for i in range(n)]
    async with db.session() as s:
        s.add_all(CveWatch(user_id=user.id, cve=c, created_at=now - timedelta(seconds=i), origin_kind="manual") for i, c in enumerate(cves))
        s.add_all(VendorKev(cve=c, vendor="Example", product="FW", name="x", date_added="2026-10-01") for c in cves[::7])
        s.add_all(
            VendorAdvisory(id=f"nvd:{c}", source="nvd", ident=c, title=f"{c} in Example", url="https://nvd.example.com/x", cves=[c], severity="high", cvss=8.1, data={"configs": [], "cna": []})
            for c in cves[::3]
        )
        await s.commit()


async def test_the_list_of_500_is_read_with_a_bounded_number_of_queries(reader_client, admin_client):
    """No N+1: the list of 500 watched CVEs (with advisories, KEV, EPSS, the last events) takes as many queries as a
    list of 5."""
    counted: list[str] = []

    def count(conn, cursor, statement, *a):  # noqa: ANN001, ANN002, ANN202
        counted.append(statement)

    await _seed(admin_client.user, 5, 90000)
    await _seed(reader_client.user, 500)
    sync = db.engine().sync_engine
    event.listen(sync, "before_cursor_execute", count)
    try:
        small = await admin_client.get("/api/me/cve-watch")
        n_small = len(counted)
        counted.clear()
        big = await reader_client.get("/api/me/cve-watch")
        n_big = len(counted)
    finally:
        event.remove(sync, "before_cursor_execute", count)
    assert len(small.json()["items"]) == 5 and len(big.json()["items"]) == 500
    assert big.json()["limit"] == 500
    assert sum(1 for i in big.json()["items"] if i["kev"]) == 72 and sum(1 for i in big.json()["items"] if i["advisories"]) == 167
    assert n_big <= n_small + 1 and n_big <= 20, (n_small, n_big)
    # and the 501st is refused
    r = await reader_client.post("/api/me/cve-watch", json={"cve": "CVE-2027-0001"})
    assert r.status_code == 409 and r.json()["detail"] == {"code": "watch_limit", "limit": 500}
