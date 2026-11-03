"""Reading (app/reader.py, app/reader_api.py): the read watermark with its sparse marks, "Alle gelesen" by filter, the
unread numbers (filters, team scope, muted left out), the age rule, new accounts starting read; mutes for a while (the
person's own deliveries only – never a team channel or a rule, never anybody else), their end; saved views (limits, per
person). All offline, on invented data (example.com / corp.example)."""

import time
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import ANY

from conftest import add_user, make_client, set_news, sign_in
from sqlalchemy import event, func, select, update
from test_personal import _dispatch, _person, _rows, _switch, _team, _ways, mails  # noqa: F401 - mails: a fixture

from app import db, news, notify, reader
from app import settings as settings_store
from app.models import (
    CveWatch,
    NewsItem,
    NewsRead,
    NewsSource,
    NotifyChannel,
    NotifyRule,
    NotifyRuleChannel,
    PersonMute,
    ReaderState,
    SavedView,
    VendorAdvisory,
    VendorAdvisoryProduct,
    VendorEvent,
    VendorFollow,
    VendorRead,
    VendorVersion,
)

DAY = timedelta(days=1)


# ---------------------------------------------------------------- helpers


async def _source(key: str = "rd") -> uuid.UUID:
    async with db.session() as s:
        src = await s.scalar(select(NewsSource).where(NewsSource.key == key))
        if src is None:
            src = NewsSource(key=key, name=key.upper(), url=f"https://{key}.example.com/feed.xml", site="", builtin=False, enabled=True, failures=0)
            s.add(src)
            await s.commit()
        return src.id


async def _stories(*titles: str, key: str = "rd", cves: list[str] | None = None, severity: str = "info") -> list[uuid.UUID]:
    """Stories stored as the fetch stores them (an arrival number each)."""
    await _source(key)
    async with db.session() as s:
        src = await s.scalar(select(NewsSource).where(NewsSource.key == key))
        entries = [
            {"link": f"https://{key}.example.com/{uuid.uuid4()}", "title": t + (" " + " ".join(cves) if cves else ""), "summary": "", "content": "", "date": datetime.now(UTC)}
            for t in titles
        ]
        await news.store(s, src, entries)
        await s.commit()
        rows = list(await s.scalars(select(NewsItem).where(NewsItem.source_id == src.id).order_by(NewsItem.seq.desc()).limit(len(titles))))
        if severity != "info":
            for r in rows:
                r.severity = severity
            await s.commit()
        return [r.id for r in rows]


async def _list(c, **params) -> dict:  # noqa: ANN001
    r = await c.get("/api/news", params=params)
    assert r.status_code == 200, r.text
    return r.json()


async def _counts(c, **params) -> dict:  # noqa: ANN001
    r = await c.get("/api/reader/counts", params=params)
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- news: watermark, sparse marks, age


async def test_watermark_and_sparse_marks(reader_client):
    await set_news(enabled=True)
    a, b, c = await _stories("Alpha", "Beta", "Gamma")
    assert (await _counts(reader_client))["news"] == 3
    page = await _list(reader_client, state="all")
    assert {i["title"]: i["unread"] for i in page["items"]} == {"Alpha": True, "Beta": True, "Gamma": True}
    # read one (what opening the drawer does): one row, the numbers follow
    assert (await reader_client.post(f"/api/news/{a}/read")).status_code == 200
    assert (await _counts(reader_client))["news"] == 2
    assert (await _list(reader_client))["counts"] == {"new": 2, "read": 1, "topics": ANY, "ours": 0}
    # "Alle gelesen" without a filter: the watermark moves, no row per story – the marks below it go
    assert (await reader_client.post("/api/news/read-all", json={})).json() == {"marked": 2}
    async with db.session() as s:
        st = await s.get(ReaderState, reader_client.user.id)
        assert st is not None and st.news_seq is not None and st.news_seq >= 3
        assert await s.scalar(select(func.count()).select_from(NewsRead).where(NewsRead.user_id == reader_client.user.id)) == 0
    assert (await _counts(reader_client))["news"] == 0
    # unread again below the watermark: a mark of its own, counted
    assert (await reader_client.delete(f"/api/news/{b}/read")).status_code == 200
    assert (await _counts(reader_client))["news"] == 1
    assert [i["title"] for i in (await _list(reader_client))["items"]] == ["Beta"]
    assert (await reader_client.post(f"/api/news/{b}/read")).status_code == 200
    # what arrives after the watermark is new again
    await _stories("Delta")
    assert (await _counts(reader_client))["news"] == 1
    assert (await _list(reader_client, state="read"))["counts"] == {"new": 1, "read": 3, "topics": ANY, "ours": 0}
    # a story that is gone: 404 for both marks
    assert (await reader_client.post(f"/api/news/{uuid.uuid4()}/read")).status_code == 404
    assert (await reader_client.delete(f"/api/news/{uuid.uuid4()}/read")).status_code == 404
    _ = c


async def test_new_account_starts_read_and_age_rule(reader_client):
    await set_news(enabled=True)
    await _stories("Before tom")
    tom = await add_user("tom")
    async with make_client() as t:
        await sign_in(t, tom)
        assert (await _counts(t))["news"] == 0  # nobody starts with the backlog
        await _stories("After tom")
        assert (await _counts(t))["news"] == 1
        # older than AUTO_READ by arrival: read without a mark
        async with db.session() as s:
            await s.execute(update(NewsItem).values(fetched_at=datetime.now(UTC) - reader.AUTO_READ - DAY))
            await s.commit()
        assert (await _counts(t))["news"] == 0
        assert (await _counts(reader_client))["news"] == 0
        # … unless the person marks one unread again – their explicit choice outlasts the age rule
        old = (await _list(t, state="all"))["items"][0]
        await t.delete(f"/api/news/{old['id']}/read")
        assert (await _counts(t))["news"] == 1
    # rudi's state is his own
    assert (await _counts(reader_client))["news"] == 0


async def test_new_account_starts_read_even_when_arrival_numbers_run_against_fetch_time(reader_client):
    """Arrival numbers are handed out at commit: an earlier fetched story can carry the higher number. A new account's
    watermark is the highest number before it – not the number of the latest fetched story."""
    await set_news(enabled=True)
    early, late = await _stories("Early fetch", "Late fetch")
    now = datetime.now(UTC)
    async with db.session() as s:
        top = int(await s.scalar(select(func.max(NewsItem.seq))) or 0)
        await s.execute(update(NewsItem).where(NewsItem.id == early).values(fetched_at=now - timedelta(minutes=10), seq=top + 100))
        await s.execute(update(NewsItem).where(NewsItem.id == late).values(fetched_at=now - timedelta(minutes=5), seq=top + 50))
        await s.commit()
    tom = await add_user("tom")
    async with make_client() as t:
        await sign_in(t, tom)
        assert (await _counts(t))["news"] == 0


async def test_read_all_by_filter_is_bounded_and_idempotent(reader_client):
    await set_news(enabled=True)
    await _stories("Crit one", "Crit two", severity="critical")
    await _stories("Low one", severity="low")
    page = await _list(reader_client, severity="critical")
    assert page["counts"]["new"] == 2
    await _stories("Crit late", severity="critical")  # arrived after the page was loaded: stays unread
    r = await reader_client.post("/api/news/read-all", json={"severity": ["critical"], "upto": page["upto"]})
    assert r.json() == {"marked": 2}
    assert (await reader_client.post("/api/news/read-all", json={"severity": ["critical"], "upto": page["upto"]})).json() == {"marked": 0}
    left = {i["title"] for i in (await _list(reader_client))["items"]}
    assert left == {"Low one", "Crit late"}
    async with db.session() as s:
        # a filter writes marks for its unread stories (no watermark move: the low one stays unread)
        assert await s.scalar(select(func.count()).select_from(NewsRead).where(NewsRead.user_id == reader_client.user.id)) == 2
        assert (await s.get(ReaderState, reader_client.user.id)) is None


async def test_counter_is_bounded_with_thousands_of_stories(reader_client):
    """A few thousand stories, a dozen read: the counter asks a fixed handful of statements and stays fast."""
    await set_news(enabled=True)
    sid = await _source()
    now = datetime.now(UTC)
    async with db.session() as s:
        rows = [
            dict(id=uuid.uuid4(), source_id=sid, url=f"https://rd.example.com/{n}", url_key=f"rd{n}", title=f"S{n}", title_key=f"rd{n}", summary="", content_html="",
                 published_at=now - timedelta(minutes=n), fetched_at=now - timedelta(minutes=n), severity="low", reasons=[], cves=[], also_in=[], search="", seq=5000 - n)  # newer fetched, higher number – as the app hands them out
            for n in range(4000)
        ]
        await s.execute(NewsItem.__table__.insert(), rows)
        await s.commit()
        # the person's watermark below all of them (as if they came after the account): all unread but the dozen
        await reader.set_marks(s, reader_client.user.id, news_seq=0)
        for r in rows[:12]:
            await reader.news_mark(s, reader_client.user.id, r["id"], read=True)
        await s.commit()
    statements: list[str] = []

    def count(conn, cursor, stmt, *a):  # noqa: ANN001, ANN202
        statements.append(stmt)

    eng = db.engine().sync_engine
    event.listen(eng, "before_cursor_execute", count)
    try:
        t0 = time.monotonic()
        got = await _counts(reader_client)
        took = time.monotonic() - t0
    finally:
        event.remove(eng, "before_cursor_execute", count)
    assert got["news"] == 4000 - 12
    assert len(statements) <= 15, statements
    assert took < 2.0


# ---------------------------------------------------------------- mutes: the lists and the numbers


async def test_mute_cve_hides_stories_and_leaves_others_alone(reader_client, admin_client):
    await set_news(enabled=True)
    await _stories("Mono", cves=["CVE-2026-41001"])
    await _stories("Duo", cves=["CVE-2026-41001", "CVE-2026-41002"])
    await _stories("Plain")
    base_admin = (await _counts(admin_client))["news"]
    r = await reader_client.post("/api/me/mutes", json={"kind": "cve", "key": " cve-2026-41001 ", "days": 7})
    assert r.status_code == 200 and r.json()["key"] == "CVE-2026-41001"
    # all of a story's CVEs muted: left out (counted nowhere); one of two: stays
    assert (await _counts(reader_client))["news"] == 2
    assert {i["title"].split()[0] for i in (await _list(reader_client, state="all"))["items"]} == {"Duo", "Plain"}
    shown = {i["title"].split()[0]: i["muted"] for i in (await _list(reader_client, state="all", muted="true"))["items"]}
    assert shown == {"Mono": True, "Duo": False, "Plain": False}
    # nobody else is affected
    assert (await _counts(admin_client))["news"] == base_admin
    # the list of my mutes, "Aufheben"; another person's id: 404
    mine = (await reader_client.get("/api/me/mutes")).json()["items"]
    assert [m["key"] for m in mine] == ["CVE-2026-41001"]
    assert (await admin_client.delete(f"/api/me/mutes/{mine[0]['id']}")).status_code == 404
    assert (await reader_client.delete(f"/api/me/mutes/{mine[0]['id']}")).status_code == 200
    assert (await _counts(reader_client))["news"] == 3


async def test_mute_input_is_checked_and_expires(reader_client):
    for bad in (
        {"kind": "cve", "key": "CVE-26-1", "days": 7},
        {"kind": "cve", "key": "CVE-2026-1234", "days": 0},
        {"kind": "cve", "key": "CVE-2026-1234"},
        {"kind": "cve", "key": "CVE-2026-1234", "days": 7, "until": (datetime.now(UTC) + DAY).isoformat()},
        {"kind": "cve", "key": "CVE-2026-1234", "until": (datetime.now(UTC) - DAY).isoformat()},
        {"kind": "cve", "key": "CVE-2026-1234", "until": (datetime.now(UTC) + timedelta(days=400)).isoformat()},
        {"kind": "team", "key": "x", "days": 7},
    ):
        assert (await reader_client.post("/api/me/mutes", json=bad)).status_code == 422, bad
    assert (await reader_client.post("/api/me/mutes", json={"kind": "product", "key": "no-such-product-xyz", "days": 7})).status_code == 404
    r = await reader_client.post("/api/me/mutes", json={"kind": "product", "key": "panos", "until": (datetime.now(UTC) + 3 * DAY).isoformat()})
    assert r.status_code == 200 and r.json()["label"]
    # again: the end is replaced, not a second row
    assert (await reader_client.post("/api/me/mutes", json={"kind": "product", "key": "panos", "days": 30})).status_code == 200
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(PersonMute)) == 1
        await s.execute(update(PersonMute).values(until=datetime.now(UTC) - timedelta(minutes=1)))
        await s.commit()
    assert (await reader_client.get("/api/me/mutes")).json()["items"] == []  # ended: no effect any more
    async with db.session() as s:
        assert (await reader.prune(s))["mutes"] == 1


# ---------------------------------------------------------------- mutes: personal deliveries


async def _vuln(product: str, ident: str, cves: list[str], *, at: datetime | None = None, kind: str = "vuln") -> uuid.UUID:
    async with db.session() as s:
        scope = f"vuln:{product}:10.2.3"
        ev = VendorEvent(
            key=f"{scope}:nvd:{ident}:{uuid.uuid4().hex[:6]}",
            kind=kind,
            product=product,
            severity="high",
            baseline=False,
            scope=scope,
            data={"product": product, "version": "10.2.3", "status": "affected", "ident": ident, "headline": "Lücke", "url": "https://security.example.com/adv", "cves": cves},
            created_at=at or datetime.now(UTC),
        )
        s.add(ev)
        await s.commit()
        return ev.id


async def test_mute_stops_my_personal_deliveries_only(mails, reader_client):  # noqa: F811
    await _switch()
    a, b = await _person("anja"), await _person("bert")
    await _team([a, b], products=("panos", "cisco-asa"))
    for u in (a, b):
        await _ways(u, email=True)
    async with make_client() as ca:
        await sign_in(ca, a)
        assert (await ca.post("/api/me/mutes", json={"kind": "product", "key": "panos", "days": 7})).status_code == 200
        assert (await ca.post("/api/me/mutes", json={"kind": "cve", "key": "CVE-2026-42001", "days": 30})).status_code == 200
    e_prod = await _vuln("panos", "CVE-2026-42000", ["CVE-2026-42000"])
    e_cve = await _vuln("cisco-asa", "CVE-2026-42001", ["CVE-2026-42001"])
    e_two = await _vuln("cisco-asa", "CVE-2026-42002", ["CVE-2026-42001", "CVE-2026-42002"])  # one of two muted: comes
    # an admin's rule to a channel: untouched by anybody's mute
    async with db.session() as s:
        ch = NotifyChannel(name="SOC", type="email", config={"recipients": ["soc@corp.example"]})
        rule = NotifyRule(name="Alle", kinds=["vendor_vuln"], severities=[], sources=[], active_since=datetime.now(UTC) - timedelta(hours=2))
        s.add_all([ch, rule])
        await s.flush()
        s.add(NotifyRuleChannel(rule_id=rule.id, channel_id=ch.id))
        await s.commit()
        pending = {e.id for e in await notify.vendor_pending(s, rule, ch.id, datetime.now(UTC) - timedelta(hours=2))}
    assert {e_prod, e_cve, e_two} <= pending
    await _dispatch()
    mine = {r.event_id: (r.status, r.error) for r in await _rows(user_id=a.id)}
    assert mine[e_prod] == ("skipped", "muted") and mine[e_cve] == ("skipped", "muted") and mine[e_two][0] == "sent"
    theirs = {r.event_id: r.status for r in await _rows(user_id=b.id)}
    assert theirs == {e_prod: "sent", e_cve: "sent", e_two: "sent"}
    # muted after it was queued, before it went out: skipped as "muted" too – and never sent later
    e_late = await _vuln("cisco-asa", "CVE-2026-42003", ["CVE-2026-42003"])
    async with db.session() as s:
        await personal_enqueue(s)
    async with make_client() as ca:
        await sign_in(ca, a)
        await ca.post("/api/me/mutes", json={"kind": "cve", "key": "CVE-2026-42003", "days": 7})
    await _dispatch()
    assert {r.event_id: r.error for r in await _rows(user_id=a.id)}[e_late] == "muted"


async def personal_enqueue(s) -> None:  # noqa: ANN001
    from app import personal

    await personal.enqueue(s, await personal.allowed(s))


async def test_muted_watched_cve_is_silent_too(mails):  # noqa: F811
    await _switch()
    a = await _person("anja")
    await _ways(a, email=True)
    cve = "CVE-2026-43000"
    async with db.session() as s:
        s.add(CveWatch(user_id=a.id, cve=cve, created_at=datetime.now(UTC) - timedelta(hours=2)))
        s.add(VendorEvent(key=f"watch:{cve}:kev", kind="watch", product="", severity="critical", baseline=False, scope=f"watch:{cve}", data={"cve": cve, "what": "kev"}, created_at=datetime.now(UTC)))
        s.add(PersonMute(user_id=a.id, kind="cve", key=cve, until=datetime.now(UTC) + DAY))
        await s.commit()
    await _dispatch()
    assert [(r.status, r.error) for r in await _rows(user_id=a.id)] == [("skipped", "muted")]


# ---------------------------------------------------------------- Vendor News: findings


async def _followed(product: str = "typo3", cves=("CVE-2026-50101", "CVE-2026-50102")) -> None:
    now = datetime.now(UTC)
    async with db.session() as s:
        f = VendorFollow(product=product, enabled=True, created_at=now - 10 * DAY, updated_at=now - 10 * DAY)
        s.add(f)
        await s.flush()
        s.add(VendorVersion(follow_id=f.id, version="13.4.37", label="Website", count=None))
        for cve in cves:
            m = {"vulnerable": True, "criteria": "cpe:2.3:a:typo3:typo3:*:*:*:*:*:*:*:*", "versionStartIncluding": "13.0.0", "versionEndExcluding": "13.4.38"}
            a = VendorAdvisory(
                id=f"nvd:{cve}", source="nvd", ident=cve, title=f"TYPO3 issue {cve}", summary="An issue.", url=f"https://nvd.example.com/{cve}", cves=[cve], cvss=8.1,
                severity="high", exploited=False, published_at=now - DAY, updated_at=None, data={"configs": [{"nodes": [{"cpeMatch": [m]}]}], "cna": [], "desc": "An issue.", "cwe": []},
            )
            a.fetched_at = now
            s.add(a)
            s.add(VendorAdvisoryProduct(product=product, advisory_id=a.id))
        await s.commit()
    from app import vendor

    vendor.bump()
    for cve in cves:  # each arrived as news (not the baseline)
        async with db.session() as s:
            scope = f"vuln:{product}:13.4.37"
            s.add(VendorEvent(key=f"{scope}:nvd:{cve}", kind="vuln", product=product, severity="high", baseline=False, scope=scope, data={"cves": [cve]}, created_at=now))
            await s.commit()


async def test_vendor_findings_read_state_and_counter(reader_client, admin_client):
    await _followed()
    assert (await _counts(reader_client))["vendor"] == 2
    card = (await reader_client.get("/api/vendor/overview")).json()["items"][0]
    assert card["unread"] == 2 and card["muted"] is None and all(x["unread"] for x in card["latest"])
    # one finding read, then the product's drawer opened: the rest
    assert (await reader_client.post("/api/vendor/read", json={"product": "typo3", "finding": "nvd:CVE-2026-50101"})).json() == {"marked": 1}
    assert (await _counts(reader_client))["vendor"] == 1
    det = (await reader_client.get("/api/vendor/products/typo3")).json()
    assert {x["id"]: x["unread"] for x in det["findings"]} == {"nvd:CVE-2026-50101": False, "nvd:CVE-2026-50102": True}
    assert (await reader_client.post("/api/vendor/read", json={"product": "typo3", "upto": det["now"]})).json() == {"marked": 1}
    assert (await _counts(reader_client))["vendor"] == 0
    # unread again; a new event of a read finding ("now exploited") makes it unread too
    assert (await reader_client.post("/api/vendor/unread", json={"product": "typo3", "finding": "nvd:CVE-2026-50101"})).status_code == 200
    assert (await _counts(reader_client))["vendor"] == 1
    async with db.session() as s:
        scope = "vuln:typo3:13.4.37"
        s.add(VendorEvent(key=f"exploited:{scope}:nvd:CVE-2026-50102", kind="vuln", product="typo3", severity="high", baseline=False, scope=scope, data={"cves": ["CVE-2026-50102"]}, created_at=datetime.now(UTC)))
        await s.commit()
    assert (await _counts(reader_client))["vendor"] == 2
    # "Alle gelesen" without a filter: the watermark
    assert (await reader_client.post("/api/vendor/read-all", json={})).json()["marked"] == 2
    assert (await _counts(reader_client))["vendor"] == 0
    assert (await reader_client.post("/api/vendor/read-all", json={})).json()["marked"] == 0
    # another person: their own state; not a followed product: 404
    assert (await _counts(admin_client))["vendor"] == 2
    assert (await reader_client.post("/api/vendor/read", json={"product": "nope"})).status_code == 404


async def test_vendor_read_all_count_matches_with_muted_findings(reader_client):
    """"Alle N als gelesen": without "Stummgeschaltete zeigen" a muted CVE's finding stays unread (the list hid it); with
    it, unread_all counts it and the read-all marks it – N on the button is what is marked."""
    await _followed("typo3", ("CVE-2026-50301", "CVE-2026-50302"))
    assert (await reader_client.post("/api/me/mutes", json={"kind": "cve", "key": "CVE-2026-50302", "days": 7})).status_code == 200
    card = (await reader_client.get("/api/vendor/overview")).json()["items"][0]
    assert card["unread"] == 1 and card["unread_all"] == 2
    assert (await reader_client.post("/api/vendor/read-all", json={"products": ["typo3"]})).json()["marked"] == 1
    card = (await reader_client.get("/api/vendor/overview")).json()["items"][0]
    assert card["unread"] == 0 and card["unread_all"] == 1  # the muted one is still unread
    assert (await reader_client.post("/api/vendor/read-all", json={"products": ["typo3"], "muted": True})).json()["marked"] == 1
    card = (await reader_client.get("/api/vendor/overview")).json()["items"][0]
    assert card["unread_all"] == 0


async def test_vendor_counter_team_scope_and_muted_product_with_kev(reader_client):
    await _followed("typo3", ("CVE-2026-50201",))
    await _followed("wordpress", ("CVE-2026-50202",))
    async with db.session() as s:
        await settings_store.put(s, "teams", {"enabled": True, "welcome_mail": False, "personal_email": False, "personal_desktop": False, "personal_teams": False})
        await s.commit()
    from test_personal import _team as team

    await team([reader_client.user], products=("typo3",))
    # the WordPress finding has no CPE of its own here: it may not count – the team scope is what is checked
    all_ = (await _counts(reader_client))["vendor"]
    team_ = (await _counts(reader_client, scope="team"))["vendor"]
    assert team_ == 1 and all_ >= team_
    assert (await reader_client.post("/api/me/mutes", json={"kind": "product", "key": "typo3", "days": 7})).status_code == 200
    assert (await _counts(reader_client, scope="team"))["vendor"] == 0
    card = next(i for i in (await reader_client.get("/api/vendor/overview")).json()["items"] if i["product"]["key"] == "typo3")
    assert card["muted"] and card["unread"] == 0 and card["muted_kev"] is False
    async with db.session() as s:
        await s.execute(update(VendorAdvisory).where(VendorAdvisory.id == "nvd:CVE-2026-50201").values(exploited=True))
        await s.commit()
    from app import vendor

    vendor.bump()
    card = next(i for i in (await reader_client.get("/api/vendor/overview")).json()["items"] if i["product"]["key"] == "typo3")
    assert card["muted_kev"] is True  # shown with a badge, not counted
    assert (await _counts(reader_client, scope="team"))["vendor"] == 0


async def test_vendor_read_prune_keeps_unread_marks(reader_client):
    await _followed()
    await reader_client.post("/api/vendor/read", json={"product": "typo3", "finding": "nvd:CVE-2026-50101"})
    await reader_client.post("/api/vendor/unread", json={"product": "typo3", "finding": "nvd:CVE-2026-50102"})
    async with db.session() as s:
        await s.execute(update(VendorRead).values(read_at=datetime.now(UTC) - reader.AUTO_READ - DAY))
        await s.commit()
        assert (await reader.prune(s))["vendor"] == 1
        assert [r.finding for r in await s.scalars(select(VendorRead))] == ["nvd:CVE-2026-50102"]


# ---------------------------------------------------------------- saved views


async def test_views_crud_default_limits_and_isolation(reader_client, admin_client):
    r = await reader_client.post("/api/me/views", json={"page": "news", "name": "Kritisch", "query": "?severity=critical&story=abc&future=1", "default": True})
    assert r.status_code == 200, r.text
    v = r.json()
    assert v["query"] == "severity=critical&future=1" and v["default"]  # the drawer's parameter dropped, an unknown one kept
    assert (await reader_client.post("/api/me/views", json={"page": "news", "name": "Kritisch", "query": ""})).status_code == 409
    assert (await reader_client.post("/api/me/views", json={"page": "vendor", "name": "Kritisch", "query": "status=action"})).status_code == 200  # another page
    w = (await reader_client.post("/api/me/views", json={"page": "news", "name": "Hoch", "query": "severity=high", "default": True})).json()
    got = {x["name"]: x["default"] for x in (await reader_client.get("/api/me/views", params={"page": "news"})).json()["items"]}
    assert got == {"Hoch": True, "Kritisch": False}  # one default per page
    assert (await reader_client.patch(f"/api/me/views/{v['id']}", json={"name": "Hoch"})).status_code == 409
    r = await reader_client.patch(f"/api/me/views/{v['id']}", json={"name": "Nur kritisch", "default": True})
    assert r.status_code == 200 and r.json()["name"] == "Nur kritisch" and r.json()["default"]
    assert {x["name"]: x["default"] for x in (await reader_client.get("/api/me/views?page=news")).json()["items"]} == {"Hoch": False, "Nur kritisch": True}
    # names: at most 60 characters, no control characters
    assert (await reader_client.post("/api/me/views", json={"page": "news", "name": "x" * 61})).status_code == 422
    assert (await reader_client.post("/api/me/views", json={"page": "news", "name": "a\nb"})).status_code == 422
    assert (await reader_client.post("/api/me/views", json={"page": "other", "name": "a"})).status_code == 422
    # another person's view: 404 (never 403), and their list is their own
    assert (await admin_client.patch(f"/api/me/views/{w['id']}", json={"name": "mine"})).status_code == 404
    assert (await admin_client.delete(f"/api/me/views/{w['id']}")).status_code == 404
    assert (await admin_client.get("/api/me/views")).json()["items"] == []
    assert (await reader_client.delete(f"/api/me/views/{w['id']}")).status_code == 200
    assert (await reader_client.delete(f"/api/me/views/{w['id']}")).status_code == 404
    # at most VIEW_MAX per page
    for n in range(reader.VIEW_MAX - 1):
        assert (await reader_client.post("/api/me/views", json={"page": "news", "name": f"V{n}"})).status_code == 200
    r = await reader_client.post("/api/me/views", json={"page": "news", "name": "one too many"})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "too_many_views"
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(SavedView).where(SavedView.page == "news")) == reader.VIEW_MAX


def test_clean_query_keeps_unknown_and_drops_the_drawer():
    assert reader.clean_query("?q=a%20b&story=1&product=x&finding=y&view=versions&zzz=1") == "q=a+b&zzz=1"
    assert reader.clean_query("") == ""
    assert len(reader.clean_query("q=" + "a" * 5000)) <= reader.QUERY_MAX


def test_finding_of_event_keys():
    assert reader.finding_of("vuln:panos:10.2.3:nvd:CVE-2026-1", "vuln:panos:10.2.3") == "nvd:CVE-2026-1"
    assert reader.finding_of("exploited:vuln:panos:*:paloalto:CVE-2026-2", "vuln:panos:*") == "paloalto:CVE-2026-2"
    assert reader.finding_of("version:panos:10.2.3:10.2.9", None) is None


def test_mutes_decide_events():
    m = reader.Mutes(products={"panos": datetime.now(UTC)}, cves={"CVE-2026-1": datetime.now(UTC)})
    assert m.event("vuln", "panos", "vuln:panos:*", {"cves": ["CVE-2026-9"]})
    assert m.event("version", "panos", None, {})
    assert m.event("vuln", "fortios", "vuln:fortios:*", {"cves": ["CVE-2026-1"]})
    assert not m.event("vuln", "fortios", "vuln:fortios:*", {"cves": ["CVE-2026-1", "CVE-2026-2"]})
    assert not m.event("vuln", "fortios", "vuln:fortios:*", {"cves": []})
    assert m.event("watch", "", "watch:CVE-2026-1", {"cve": "CVE-2026-1"})
    assert not m.event("watch", "", "watch:CVE-2026-2", {})
    assert not reader.Mutes().event("vuln", "panos", None, {})
