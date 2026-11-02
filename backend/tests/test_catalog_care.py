"""Katalog-Pflege by the people (app/catalog_care.py): "Versionen prüfen" – entering or changing confirms, "Bestätigen"
confirms unchanged and recomputes nothing, the interval (and off), who may confirm and who sees what, the migration's
backfill, the weekly review's section – and "Produkt vorschlagen": validation, the limit per day, only the own
suggestions for readers, only admins answer, once."""

import uuid
from datetime import UTC, datetime, timedelta

from conftest import add_user, make_client, sign_in
from sqlalchemy import select, text, update

from app import catalog_care as care
from app import db, weekly
from app import settings as settings_store
from app import vendor as vendor_svc
from app.models import ProductSuggestion, Team, TeamMember, TeamProduct, VendorFollow, VendorVersion

OLD = timedelta(days=120)


async def _follow(c, key: str, *versions: str) -> list[str]:  # noqa: ANN001
    assert (await c.put(f"/api/vendor/follows/{key}", json={"enabled": True})).status_code == 200
    ids = []
    for v in versions:
        r = await c.post(f"/api/vendor/follows/{key}/versions", json={"version": v})
        assert r.status_code == 200, r.text
        ids.append(r.json()["id"])
    return ids


async def _age(vid: str, delta: timedelta = OLD) -> None:
    """The version was last confirmed (and entered) `delta` ago."""
    at = datetime.now(UTC) - delta
    async with db.session() as s:
        await s.execute(update(VendorVersion).where(VendorVersion.id == uuid.UUID(vid)).values(confirmed_at=at, updated_at=at, created_at=at))
        await s.commit()
    vendor_svc.bump()


async def _teams_on() -> None:
    async with db.session() as s:
        await settings_store.put(s, "teams", {"enabled": True})
        await s.commit()


async def _team(name: str, products: list[str], members: list) -> uuid.UUID:  # noqa: ANN001
    async with db.session() as s:
        t = Team(name=name)
        s.add(t)
        await s.flush()
        for key in products:
            f = await s.scalar(select(VendorFollow).where(VendorFollow.product == key))
            s.add(TeamProduct(team_id=t.id, follow_id=f.id))
        for u in members:
            s.add(TeamMember(team_id=t.id, user_id=u.id, origin="manual"))
        await s.commit()
        return t.id


def _version(card: dict, vid: str) -> dict:
    return next(v for v in card["versions"] if v["id"] == vid)


# ---------------------------------------------------------------- Versionen prüfen


async def test_entering_and_changing_confirm_and_bestaetigen_changes_nothing_else(admin_client):
    [vid] = await _follow(admin_client, "panos", "11.2.4-h23")
    d = (await admin_client.get("/api/vendor/products/panos")).json()
    v = _version(d, vid)
    assert v["review"]["due"] is False and v["review"]["age_days"] == 0 and v["review"]["confirmed_by"] == "Anna"
    assert d["review_days"] == 90 and d["can_confirm"] is True
    await _age(vid)
    d = (await admin_client.get("/api/vendor/products/panos")).json()
    assert _version(d, vid)["review"] == {**_version(d, vid)["review"], "due": True, "age_days": 120}
    async with db.session() as s:
        before = (await s.get(VendorVersion, uuid.UUID(vid))).updated_at
    view_stamp = await _stamp("panos")
    r = await admin_client.post(f"/api/vendor/versions/{vid}/confirm")
    assert r.status_code == 200 and r.json()["due"] is False and r.json()["age_days"] == 0
    async with db.session() as s:
        v = await s.get(VendorVersion, uuid.UUID(vid))
        assert v.updated_at == before and v.version == "11.2.4-h23"  # the entry itself is untouched
    # the cached evaluation is the same object: a confirmation recomputes nothing (and changes no score)
    assert await _stamp("panos") == view_stamp
    # changing it confirms it, too
    await _age(vid)
    r = await admin_client.put(f"/api/vendor/versions/{vid}", json={"version": "11.2.4-h23", "label": "RZ"})
    assert r.json()["review"]["due"] is False


async def _stamp(key: str) -> int:
    """Which computation of the product's cached view is served (a new one: something was evaluated again)."""
    async with db.session() as s:
        f = await s.scalar(select(VendorFollow).where(VendorFollow.product == key))
        vs = (await vendor_svc.versions_of(s, [f.id]))[f.id]
        return (await vendor_svc.product_view(s, f, vs))["stamp"]


async def test_interval_setting_and_off(admin_client):
    [a, b] = await _follow(admin_client, "panos", "11.2.4-h23", "10.2.13-h5")
    await _age(a, timedelta(days=45))
    await _age(b, timedelta(days=100))
    r = (await admin_client.get("/api/vendor/review")).json()
    assert r["days"] == 90 and r["count"] == 1 and r["items"][0]["versions"][0]["id"] == b
    cfg = (await admin_client.get("/api/admin/vendor")).json()["settings"]
    assert cfg["review_days"] == 90
    r = await admin_client.put("/api/admin/vendor", json={"enabled": True, "review_days": 30, "rev": cfg["rev"]})
    assert r.status_code == 200 and r.json()["review_days"] == 30
    assert (await admin_client.get("/api/vendor/review")).json()["count"] == 2
    ov = (await admin_client.get("/api/vendor/overview")).json()
    assert ov["review_days"] == 30 and all(v["review"]["due"] for v in ov["items"][0]["versions"])
    # a form that does not send it keeps it; a value not offered is refused
    r = await admin_client.put("/api/admin/vendor", json={"enabled": True, "every_h": 6})
    assert r.json()["review_days"] == 30
    assert (await admin_client.put("/api/admin/vendor", json={"enabled": True, "review_days": 45})).status_code == 422
    # off: nothing is due, nowhere
    await admin_client.put("/api/admin/vendor", json={"enabled": True, "review_days": 0})
    r = (await admin_client.get("/api/vendor/review")).json()
    assert r == {"days": 0, "enabled": False, "count": 0, "items": []}
    ov = (await admin_client.get("/api/vendor/overview")).json()
    assert not any(v["review"]["due"] for v in ov["items"][0]["versions"])


async def test_who_may_confirm_and_who_sees_what(admin_client, reader_client):
    [pan] = await _follow(admin_client, "panos", "11.2.4-h23")
    [forti] = await _follow(admin_client, "fortios", "7.4.8")
    await _age(pan)
    await _age(forti)
    # Teams off: the admins are responsible – a reader sees the versions but confirms nothing and has no list
    assert (await reader_client.post(f"/api/vendor/versions/{pan}/confirm")).status_code == 403
    assert (await reader_client.get("/api/vendor/review")).json()["count"] == 0
    assert (await reader_client.get("/api/vendor/review?scope=all")).status_code == 403
    assert (await reader_client.get("/api/vendor/products/panos")).json()["can_confirm"] is False
    assert (await admin_client.get("/api/vendor/review")).json()["count"] == 2
    # Teams on, PAN-OS belongs to the reader's team: the reader confirms PAN-OS, not FortiOS
    await _teams_on()
    other = await add_user("olga", "reader")
    tid = await _team("Netzwerk", ["panos"], [reader_client.user])
    await _team("Firewall-Ops", ["fortios"], [other])
    mine = (await reader_client.get("/api/vendor/review")).json()
    assert [i["product"]["key"] for i in mine["items"]] == ["panos"] and mine["items"][0]["teams"][0]["name"] == "Netzwerk"
    assert mine["items"][0]["can_confirm"] is True
    ov = {i["product"]["key"]: i for i in (await reader_client.get("/api/vendor/overview")).json()["items"]}
    assert ov["panos"]["can_confirm"] is True and ov["fortios"]["can_confirm"] is False
    assert (await reader_client.post(f"/api/vendor/versions/{forti}/confirm")).status_code == 403
    assert (await reader_client.post("/api/vendor/review/confirm", json={"product": "fortios"})).status_code == 403
    assert (await reader_client.post(f"/api/vendor/versions/{pan}/confirm")).status_code == 200
    # the admin's own list: products of no team only (both have a team now) – "all" shows every one
    assert (await admin_client.get("/api/vendor/review")).json()["count"] == 0
    assert (await admin_client.get("/api/vendor/review?scope=all")).json()["count"] == 1
    # "alle bestätigen" of a team: only a member (or an admin) – and only that team's products
    await _age(pan)
    assert (await reader_client.post("/api/vendor/review/confirm", json={"team_id": str(tid)})).json() == {"confirmed": 1}
    o = make_client()
    async with o:
        await sign_in(o, other)
        assert (await o.post("/api/vendor/review/confirm", json={"team_id": str(tid)})).status_code == 403
    assert (await reader_client.post("/api/vendor/review/confirm", json={})).status_code == 422
    assert (await admin_client.get("/api/vendor/review?scope=all")).json()["count"] == 1  # FortiOS still due


async def test_confirm_all_of_a_product(admin_client):
    ids = await _follow(admin_client, "panos", "11.2.4-h23", "10.2.13-h5", "11.1.6-h3")
    await _age(ids[0])
    await _age(ids[1])
    assert (await admin_client.post("/api/vendor/review/confirm", json={"product": "panos"})).json() == {"confirmed": 2}
    assert (await admin_client.get("/api/vendor/review")).json()["count"] == 0
    assert (await admin_client.post("/api/vendor/review/confirm", json={"product": "panos", "due_only": False})).json() == {"confirmed": 3}
    assert (await admin_client.post("/api/vendor/review/confirm", json={"product": "nope"})).status_code == 404


async def test_a_deleted_confirmer_leaves_the_date():
    u = await add_user("karl", "admin")
    async with db.session() as s:
        f = VendorFollow(product="panos", enabled=True)
        s.add(f)
        await s.flush()
        v = VendorVersion(follow_id=f.id, version="11.2.4-h23", confirmed_at=datetime.now(UTC), confirmed_by=u.id)
        s.add(v)
        await s.commit()
        await s.execute(text("DELETE FROM users WHERE id = :i"), {"i": u.id})
        await s.commit()
        await s.refresh(v)
        assert v.confirmed_by is None and v.confirmed_at is not None


def test_due_rules():
    now = datetime(2026, 10, 31, tzinfo=UTC)
    v = VendorVersion(version="1", created_at=now - timedelta(days=200), updated_at=now - timedelta(days=100), confirmed_at=None)
    assert care.confirmed_of(v) == now - timedelta(days=100)  # never confirmed (a SQLite import): from the last change
    assert care.is_due(v, 90, now) and not care.is_due(v, 180, now) and not care.is_due(v, 0, now)
    v.confirmed_at = now - timedelta(days=90)
    assert not care.is_due(v, 90, now)  # exactly the interval: not yet
    assert care.review_days_of({"review_days": 45}) == 90 and care.review_days_of({"review_days": "x"}) == 90 and care.review_days_of({"review_days": 0}) == 0


async def test_migration_backfills_from_updated_at():
    """0019 on a database at 0018: an existing version gets its updated_at as the confirmation – not the migration time
    (that would hide every old entry for a whole interval), not empty."""
    from alembic import command

    old = datetime(2026, 5, 1, tzinfo=UTC)
    async with db.engine().begin() as conn:
        await conn.run_sync(lambda c: command.downgrade(db.alembic_config(c), "0018"))
        fid = uuid.uuid4()
        await conn.execute(
            text("INSERT INTO vendor_follows (id, product, enabled, note, tags, created_at, updated_at) VALUES (:i, 'panos', true, '', '[]', :t, :t)"), {"i": fid, "t": old}
        )
        await conn.execute(
            text("INSERT INTO vendor_versions (id, follow_id, version, label, created_at, updated_at) VALUES (:i, :f, '11.2.4-h23', '', :c, :u)"),
            {"i": uuid.uuid4(), "f": fid, "c": old - timedelta(days=30), "u": old},
        )
    await db.migrate()
    assert await db.revision() == db.head()
    async with db.session() as s:
        v = await s.scalar(select(VendorVersion))
        assert v.confirmed_at == old and v.confirmed_by is None
        assert care.is_due(v, 90, datetime.now(UTC))


async def test_weekly_review_lists_the_teams_versions_to_review(admin_client):
    [pan] = await _follow(admin_client, "panos", "11.2.4-h23")
    await _follow(admin_client, "fortios", "7.4.8")
    await _age(pan, timedelta(days=130))
    await _teams_on()
    tid = await _team("Netzwerk", ["panos", "fortios"], [admin_client.user])
    async with db.session() as s:
        c = await weekly.content(s, tid, datetime.now(UTC))
    assert c["review"]["days"] == 90 and [(x["version"], x["n"]) for x in c["review"]["items"]] == [("11.2.4-h23", 130)]
    subject, body, html = weekly.render("Netzwerk", "2026-W44", c, "de")
    assert "Versionen zu prüfen" in body and "seit 130 Tagen nicht bestätigt" in body and "Versionen zu prüfen" in html
    # the review of versions off: no section at all
    async with db.session() as s:
        await settings_store.put(s, "vendor", {**(await settings_store.get(s, "vendor")), "review_days": 0})
        await s.commit()
        c = await weekly.content(s, tid, datetime.now(UTC))
    assert c["review"] is None and "Versionen zu prüfen" not in weekly.render("Netzwerk", "2026-W44", c, "de")[1]


# ---------------------------------------------------------------- Produkt vorschlagen

GOOD = {"vendor": "Example Corp", "product": "Edge Gateway", "url": "https://www.example.com/security", "cpe": "a:example:edge_gateway", "reason": "Läuft bei uns\nin zwei Standorten."}


async def test_suggest_validation(reader_client):
    r = await reader_client.post("/api/vendor/suggestions", json=GOOD)
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["status"] == "open" and s["cpe_short"] == "a:example:edge_gateway" and s["reason"] == "Läuft bei uns\nin zwei Standorten." and "by" not in s
    bad = [
        {"url": "javascript:alert(1)"},
        {"url": "data:text/html,<script>alert(1)</script>"},
        {"url": "https://user:pw@example.com/"},
        {"url": "ftp://example.com/x"},
        {"url": "https://exa mple.com/"},
        {"url": "https://" + "a" * 500 + ".example.com/"},
        {"cpe": "not a cpe"},
        {"vendor": "x"},
        {"product": "y" * 121},
        {"reason": "  "},
        {"reason": "z" * 1001},
        {"extra": 1},
    ]
    for b in bad:
        r = await reader_client.post("/api/vendor/suggestions", json={**GOOD, "product": f"Other {uuid.uuid4().hex[:6]}", **b})
        assert r.status_code == 422, (b, r.text)
    # control characters out of a line, markup stored as the plain text it is (React shows it as text)
    r = await reader_client.post("/api/vendor/suggestions", json={**GOOD, "vendor": "Acme\x07\nLtd", "product": "<img src=x onerror=alert(1)>", "url": None, "cpe": None})
    assert r.status_code == 200 and r.json()["vendor"] == "Acme Ltd" and r.json()["product"] == "<img src=x onerror=alert(1)>" and r.json()["url"] is None
    # the same open suggestion twice: refused
    assert (await reader_client.post("/api/vendor/suggestions", json={**GOOD, "product": "edge gateway"})).status_code == 409


async def test_suggest_limit_per_day(reader_client):
    for i in range(care.SUGGEST_PER_DAY):
        assert (await reader_client.post("/api/vendor/suggestions", json={**GOOD, "product": f"Product {i}"})).status_code == 200
    r = await reader_client.post("/api/vendor/suggestions", json={**GOOD, "product": "One too many"})
    assert r.status_code == 429 and r.json()["detail"]["code"] == "suggest_limit"
    # a day later: again
    async with db.session() as s:
        await s.execute(update(ProductSuggestion).values(created_at=datetime.now(UTC) - timedelta(days=1, minutes=1)))
        await s.commit()
    assert (await reader_client.post("/api/vendor/suggestions", json={**GOOD, "product": "Next day"})).status_code == 200


async def test_team_of_a_suggestion_must_be_the_own(reader_client):
    other = await add_user("olga", "reader")
    await _teams_on()
    async with db.session() as s:
        mine, theirs = Team(name="Netzwerk"), Team(name="Server")
        s.add_all([mine, theirs])
        await s.flush()
        s.add(TeamMember(team_id=mine.id, user_id=reader_client.user.id, origin="manual"))
        s.add(TeamMember(team_id=theirs.id, user_id=other.id, origin="manual"))
        await s.commit()
    assert (await reader_client.post("/api/vendor/suggestions", json={**GOOD, "team_id": str(theirs.id)})).status_code == 422
    r = await reader_client.post("/api/vendor/suggestions", json={**GOOD, "team_id": str(mine.id)})
    assert r.status_code == 200 and r.json()["team"]["name"] == "Netzwerk"


async def test_readers_see_only_their_own_and_only_admins_answer(admin_client, reader_client):
    other = await add_user("olga", "reader")
    sid = (await reader_client.post("/api/vendor/suggestions", json=GOOD)).json()["id"]
    o = make_client()
    async with o:
        await sign_in(o, other)
        assert (await o.get("/api/vendor/suggestions/mine")).json()["items"] == []
        assert (await o.get("/api/admin/suggestions")).status_code == 403
        assert (await o.post(f"/api/admin/suggestions/{sid}/reject", json={})).status_code == 403
        assert (await o.get("/api/vendor/suggestions/count")).json() == {"answered": 0, "open": None}
    assert (await reader_client.post(f"/api/admin/suggestions/{sid}/accept", json={})).status_code == 403
    q = (await admin_client.get("/api/admin/suggestions")).json()["items"]
    assert [x["id"] for x in q] == [sid] and q[0]["by"] == "Rudi"
    assert (await admin_client.get("/api/vendor/suggestions/count")).json()["open"] == 1
    # "Doppelt" needs a product that exists
    assert (await admin_client.post(f"/api/admin/suggestions/{sid}/duplicate", json={"product_key": "no-such-product"})).status_code == 422
    r = await admin_client.post(f"/api/admin/suggestions/{sid}/duplicate", json={"product_key": "panos", "answer": "Gibt es schon."})
    assert r.status_code == 200 and r.json()["status"] == "duplicate" and r.json()["result"]["key"] == "panos" and r.json()["decided_by"] == "Anna"
    # answered once: a second answer is refused
    assert (await admin_client.post(f"/api/admin/suggestions/{sid}/reject", json={})).status_code == 409
    assert (await admin_client.get("/api/admin/suggestions")).json()["items"] == []
    assert [x["id"] for x in (await admin_client.get("/api/admin/suggestions?state=done")).json()["items"]] == [sid]
    # the suggester sees the answer (not who gave it) and a number until it was seen
    assert (await reader_client.get("/api/vendor/suggestions/count")).json() == {"answered": 1, "open": None}
    [mine] = (await reader_client.get("/api/vendor/suggestions/mine")).json()["items"]
    assert mine["status"] == "duplicate" and mine["answer"] == "Gibt es schon." and mine["result"]["label"] and "decided_by" not in mine and not mine["seen"]
    await reader_client.post("/api/vendor/suggestions/seen")
    assert (await reader_client.get("/api/vendor/suggestions/count")).json()["answered"] == 0


async def test_accept_with_the_product_added_by_cpe_or_for_the_bundled_catalogue(admin_client, reader_client):
    a = (await reader_client.post("/api/vendor/suggestions", json=GOOD)).json()["id"]
    b = (await reader_client.post("/api/vendor/suggestions", json={**GOOD, "product": "Edge Manager"})).json()["id"]
    c = (await reader_client.post("/api/vendor/suggestions", json={**GOOD, "product": "Edge Toaster"})).json()["id"]
    key = (await admin_client.post("/api/vendor/custom", json={"cpe": "a:example:edge_gateway", "label": "Example Edge Gateway", "category": "network"})).json()["key"]
    r = await admin_client.post(f"/api/admin/suggestions/{a}/accept", json={"product_key": key})
    assert r.status_code == 200 and r.json()["result"] == {"key": key, "label": "Example Edge Gateway"}
    r = await admin_client.post(f"/api/admin/suggestions/{b}/accept", json={"answer": "Kommt mit dem nächsten Katalog."})
    assert r.status_code == 200 and r.json()["status"] == "accepted" and r.json()["result"] is None
    r = await admin_client.post(f"/api/admin/suggestions/{c}/reject", json={"answer": "Kein Sicherheitsprodukt."})
    assert r.json()["status"] == "rejected" and r.json()["answer"] == "Kein Sicherheitsprodukt."
    assert (await admin_client.post(f"/api/admin/suggestions/{uuid.uuid4()}/reject", json={})).status_code == 404


async def test_a_deleted_suggester_leaves_the_suggestion(admin_client):
    u = await add_user("karl", "reader")
    async with db.session() as s:
        s.add(ProductSuggestion(user_id=u.id, vendor="Example", product="Thing", reason="why"))
        await s.commit()
        await s.execute(text("DELETE FROM users WHERE id = :i"), {"i": u.id})
        await s.commit()
    [x] = (await admin_client.get("/api/admin/suggestions")).json()["items"]
    assert x["by"] is None and x["product"] == "Thing"


def test_url_and_cpe_rules():
    assert care.url_problem("https://www.example.com/a?b=c#d") is None
    assert care.url_problem("http://[2001:db8::1]/x") is None
    assert care.url_problem("HTTPS://Example.com") is None
    for bad in ("javascript:alert(1)", "https:///x", "https://localhost", "https://a@b.example", "https://example.com:99999/", "mailto:x@example.com"):
        assert care.url_problem(bad), bad
    assert care.cpe_short("cpe:2.3:a:Example:Edge_Gateway:1.0:*:*:*:*:*:*:*") == "a:example:edge_gateway"
    assert care.cpe_short("o:example:os") == "o:example:os" and care.cpe_short(None) is None
    assert care.CPE.fullmatch("cpe:2.3:a:example:edge:1.0:*:*:*:*:*:*:*") and not care.CPE.fullmatch("x:example:edge")
