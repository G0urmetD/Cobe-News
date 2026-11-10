"""Systeme, Schlagwörter and Ausschluss-Wörter beyond the channel rules (app/concerns.py – one implementation): the
News list's "Systeme" filter (also what a story has only quietly; read-all by the same filter; checked input), a
person's desktop choice (tab and Web Push: filtered on the server, loud systems only, "Treffer" in the notification;
validated, kept when an older page leaves the fields out, own settings only) and "Hersteller-News meiner Produkte" by
system (the event's product; watched CVEs never) – plus migration 0040."""

from datetime import UTC, datetime

import pytest
from conftest import make_client, set_news, sign_in
from sqlalchemy import select, text
from test_notify import _source
from test_personal import _dispatch as personal_dispatch
from test_personal import _event, _person, _rows, _switch, _team, _ways
from test_personal import mails  # noqa: F401 - fixture
from test_push import FCM, Browser, PushService
from test_rule_filters import _news, _pan_details

from app import db, notify, personal, systems, webpush
from app.models import PersonNotify, User

PAN = {"vendor": "Palo Alto Networks"}


@pytest.fixture
def service(monkeypatch):
    s = PushService()
    import httpx

    monkeypatch.setattr(notify, "transport", httpx.MockTransport(s.handler))
    return s


async def _quiet_pan(src) -> str:  # noqa: ANN001
    """A story whose title names nothing, that concerns PAN-OS only quietly (its details found by a recompute)."""
    iid = await _news(src, "Speicherfehler in einer Firewall", "Ein Update schließt die Lücke.")
    async with db.session() as s:
        await systems.set_exact(s, iid, systems.exact(_pan_details()), quiet=True)
        await s.commit()
    return str(iid)


# ---------------------------------------------------------------- the News list


async def test_news_list_by_system_quiet_ones_count_and_read_all_follows(reader_client):
    await set_news(enabled=True)
    src = await _source()
    pan = str(await _news(src, "Palo Alto Networks: Kritische Lücke in PAN-OS wird angegriffen"))
    gp = str(await _news(src, "Cortex XDR Agent: Lücke wird ausgenutzt"))  # a product of the vendor, the vendor not named
    forti = str(await _news(src, "Fortinet schließt Lücke in FortiOS"))
    other = str(await _news(src, "Ransomware trifft Krankenhaus"))
    quiet = await _quiet_pan(src)

    async def ids(*systems_: str, **params) -> set[str]:
        r = await reader_client.get("/api/news", params={"state": "all", "system": list(systems_), **params})
        assert r.status_code == 200, r.text
        return {i["id"] for i in r.json()["items"]}

    assert await ids() >= {pan, gp, forti, other, quiet}
    # a vendor: each of its products, named or by the details – also what a story has only quietly (a list, no news)
    assert await ids("v:Palo Alto Networks") == {pan, gp, quiet}
    assert await ids("p:panos") == {pan, quiet}
    assert await ids("p:panos", "p:fortios") == {pan, quiet, forti}
    # AND with the rest: the search
    assert await ids("v:Palo Alto Networks", q="Cortex") == {gp}
    # a system the catalogue does not know (an old link): nothing, not everything
    assert await ids("p:no-such-product") == set()
    r = await reader_client.get("/api/news", params={"state": "all", "system": "v:Palo Alto Networks"})
    assert r.json()["counts"]["new"] == 3 and r.json()["counts"]["read"] == 0  # the counts follow the filter
    # malformed: 422, never a 500
    for bad in ("x:panos", "p:", "p:Bad Key", "panos", "v:" + "a" * 121, "v:Palo Alto"):
        r = await reader_client.get("/api/news", params={"system": bad})
        assert r.status_code == 422, bad
    assert (await reader_client.get("/api/news", params={"system": [f"p:k{n}" for n in range(51)]})).status_code == 422
    # "Alle als gelesen" of the filtered list: only those
    r = await reader_client.post("/api/news/read-all", json={"system": ["v:Palo Alto Networks"]})
    assert r.status_code == 200 and r.json()["marked"] == 3
    assert await ids(state="new") >= {forti, other} and not {pan, gp, quiet} & await ids(state="new")
    assert (await reader_client.post("/api/news/read-all", json={"system": ["q:x"]})).status_code == 422


async def test_news_list_without_words_validated_and_read_all_follows(reader_client):
    await set_news(enabled=True)
    src = await _source()
    web = str(await _news(src, "Webinar: PAN-OS richtig härten"))
    bleed = str(await _news(src, "Citrix-Bleed wird ausgenutzt"))
    plain = str(await _news(src, "Fortinet schließt Lücke in FortiOS"))
    webinars = str(await _news(src, "Webinars zur Sicherheit"))  # a whole word: "Webinars" is no "Webinar"

    async def ids(**params) -> set[str]:
        r = await reader_client.get("/api/news", params={"state": "all", **params})
        assert r.status_code == 200, r.text
        return {i["id"] for i in r.json()["items"]}

    assert await ids(without="webinar") == {bleed, plain, webinars}
    assert await ids(without=["Webinar", "Citrix Bleed"]) == {plain, webinars}  # a blank stands for a hyphen too
    assert await ids(without="webinar", system="v:Palo Alto Networks") == set()
    r = await reader_client.get("/api/news", params={"state": "all", "without": "webinar"})
    assert r.json()["counts"]["new"] == 3
    # checked as a rule's words: plain text, 2–60 characters, at most 30 – never a pattern
    for bad in (["x"], ["(.*)+$"], ["a" * 61], [f"wort{n}" for n in range(31)]):
        assert (await reader_client.get("/api/news", params={"without": bad})).status_code == 422, bad
    assert await ids(without="a.b") == {web, bleed, plain, webinars}  # "." is a sign, not "any character"
    r = await reader_client.post("/api/news/read-all", json={"without": ["Webinar"]})
    assert r.status_code == 200 and r.json()["marked"] == 3
    assert await ids(state="new") == {web}
    assert (await reader_client.post("/api/news/read-all", json={"without": ["x"]})).status_code == 422


async def test_news_list_system_filter_uses_the_gin_index():
    """At a realistic number of stories the planner reads the systems' GIN index (ix_news_items_systems) for the
    filter, not every row."""
    from sqlalchemy import insert

    from app import concerns  # the clause the list adds (api.list_news)
    from app.models import NewsItem

    src = await _source()
    now = datetime.now(UTC)
    rows = [
        {"source_id": src.id, "url": f"https://x.example/{g}", "url_key": f"k{g}", "title": f"T{g}", "title_key": f"t{g}", "published_at": now, "fetched_at": now, "severity": "high", "search": f"t{g}", "systems": ["m:panos", "v:paloaltonetworks"] if g % 500 == 0 else ["m:chrome"]}
        for g in range(30_000)
    ]
    async with db.session() as s:
        for k in range(0, len(rows), 5000):
            await s.execute(insert(NewsItem), rows[k : k + 5000])
        await s.commit()
        await s.execute(text("ANALYZE news_items"))
        stmt = select(NewsItem.id).where(concerns.systems_clause([PAN], quiet_too=True))
        sql = str(stmt.compile(dialect=s.bind.dialect, compile_kwargs={"literal_binds": True}))
        plan = "\n".join(r[0] for r in await s.execute(text(f"EXPLAIN {sql}")))
    assert "ix_news_items_systems" in plan, plan


# ---------------------------------------------------------------- desktop (tab and Web Push)


async def test_desktop_choice_by_systems_and_words_validated_and_kept(reader_client):
    r = await reader_client.put("/api/me/desktop", json={"enabled": True, "severities": [], "sources": [], "systems": [PAN, {"product": "fortios"}], "keywords": ["Ransomware"], "exclude": ["Webinar"]})
    assert r.status_code == 200, r.text
    got = (await reader_client.get("/api/me/desktop")).json()
    assert got["systems"] == [PAN, {"product": "fortios"}] and got["keywords"] == ["Ransomware"] and got["exclude"] == ["Webinar"]
    # a page of before 0.1.54 sends none of the fields: the choice stays
    r = await reader_client.put("/api/me/desktop", json={"enabled": True, "severities": ["critical"], "sources": []})
    assert r.status_code == 200 and r.json()["systems"] == [PAN, {"product": "fortios"}] and r.json()["severities"] == ["critical"]
    # checked as a rule's: a known system, plain words, the limits
    for body, code in (
        ({"systems": [{"product": "no-such-product"}]}, "system_not_found"),
        ({"systems": [{"vendor": "Palo", "product": "panos"}]}, None),
        ({"systems": [{"product": "PAN OS"}]}, None),
        ({"systems": [{"product": f"k{n}"} for n in range(51)]}, None),
        ({"keywords": ["a"]}, None),
        ({"keywords": ["(.*)+$"]}, None),
        ({"exclude": [f"wort{n}" for n in range(31)]}, None),
        ({"keywords": ["x" * 61]}, None),
    ):
        r = await reader_client.put("/api/me/desktop", json={"enabled": True, "severities": [], "sources": [], **body})
        assert r.status_code == 422, (body, r.text)
        if code:
            assert r.json()["detail"]["code"] == code
    # one's own only – no id anywhere
    r = await reader_client.put("/api/me/desktop", json={"enabled": True, "severities": [], "sources": [], "user_id": "x"})
    assert r.status_code == 422


async def test_recent_mine_filters_by_systems_words_and_exclusions_on_the_server(reader_client):
    src = await _source()
    cursor = (await reader_client.get("/api/news/recent")).json()["cursor"]
    await reader_client.put("/api/me/desktop", json={"enabled": True, "severities": [], "sources": [], "systems": [PAN], "keywords": ["Ransomware"], "exclude": ["Webinar"]})
    pan = str(await _news(src, "Palo Alto Networks: Kritische Lücke in PAN-OS"))
    ransom = str(await _news(src, "Ransomware trifft Krankenhaus"))
    await _news(src, "Webinar: PAN-OS richtig härten")  # an exclusion word: never
    await _news(src, "Fortinet schließt Lücke in FortiOS")  # neither system nor word
    await _quiet_pan(src)  # only quietly – no news
    got = (await reader_client.get("/api/news/recent", params={"after": cursor, "mine": "true"})).json()
    assert {i["id"] for i in got["items"]} == {pan, ransom} and got["total"] == 2
    hits = {i["id"]: i["hits"] for i in got["items"]}
    assert hits[pan] == ["PAN-OS", "Palo Alto Networks"] and hits[ransom] == ["Ransomware"]
    # without `mine` everything, and no "Treffer"
    every = (await reader_client.get("/api/news/recent", params={"after": cursor})).json()
    assert every["total"] == 5 and all("hits" not in i for i in every["items"])


async def test_web_push_by_the_same_choice_says_what_matched(reader_client, service):
    b = Browser()
    async with db.session() as s:
        u = await s.get(User, reader_client.user.id)
        u.desktop = {"enabled": True, "severities": [], "sources": [], "systems": [PAN], "keywords": [], "exclude": ["Webinar"]}
        await s.commit()
    src = await _source()
    await reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": b.keys(), "lang": "de"})
    await _news(src, "Palo Alto Networks: Kritische Lücke in PAN-OS")
    await _news(src, "Webinar zu PAN-OS")
    await _news(src, "Fortinet schließt Lücke in FortiOS")
    async with db.session() as s:
        assert await webpush.dispatch(s) == {"sent": 1, "failed": 0}
    got = [b.read(r.content) for r in service.requests]
    assert [g["title"] for g in got] == ["Palo Alto Networks: Kritische Lücke in PAN-OS"]
    assert got[0]["body"] == "Kritisch · Treffer: PAN-OS, Palo Alto Networks · Example Feed"


async def test_web_push_names_the_product_without_a_choice_of_systems(reader_client, service):
    """The person chose only severities: the message still says which product a story is about (and no "Treffer"),
    the rest of a round in the summary by its highest severity and products."""
    b = Browser()
    async with db.session() as s:
        u = await s.get(User, reader_client.user.id)
        u.desktop = {"enabled": True, "severities": [], "sources": []}
        await s.commit()
    src = await _source()
    await reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": b.keys(), "lang": "de"})
    await _news(src, "Palo Alto Networks: Kritische Lücke in PAN-OS")
    async with db.session() as s:
        assert await webpush.dispatch(s) == {"sent": 1, "failed": 0}
    [got] = [b.read(r.content) for r in service.requests]
    assert got["body"] == "Kritisch · PAN-OS, Palo Alto Networks · Example Feed"
    # the recent list of the tab carries the same facts
    cursor = 0
    every = (await reader_client.get("/api/news/recent", params={"after": cursor})).json()
    assert every["items"][0]["notice"] == {"rated": True, "cvss": None, "exploited": False, "products": ["PAN-OS", "Palo Alto Networks"]}


def test_push_payload_hits_are_one_plain_line():
    p = webpush.story_payload({"id": "x", "title": "T", "severity": "high", "source": "F", "hits": ["A\nB", "C", "D", "E"]}, "en")
    assert p["body"] == "High · Match: A B, C, D +1 · F"
    assert webpush.story_payload({"id": "x", "title": "T", "severity": "high", "source": "F"}, "de")["body"] == "Hoch · F"


def test_push_line_severity_only_when_given_with_cvss_exploited_and_products():
    notice = {"rated": True, "cvss": "9.2", "exploited": True, "products": ["PAN-OS", "Prisma Cloud", "Panorama", "Cortex XDR"]}
    p = webpush.story_payload({"id": "x", "title": "T", "severity": "critical", "source": "BSI", "notice": notice}, "de")
    assert p["body"] == "Kritisch (CVSS 9.2) · ausgenutzt · PAN-OS, Prisma Cloud, Panorama +1 · BSI"
    unrated = {"rated": False, "cvss": None, "exploited": False, "products": ["Exchange Server"]}
    assert webpush.story_payload({"id": "x", "title": "T", "severity": "info", "source": "heise", "notice": unrated}, "en")["body"] == "Exchange Server · heise"
    # the summary: the highest severity of the rated ones, the products of all
    rest = [{"severity": "high", "notice": {**unrated, "rated": True, "products": ["FortiOS"]}}, {"severity": "info", "notice": unrated}, {"severity": "medium", "hits": ["PAN-OS"]}]
    assert webpush.summary_payload(3, "de", None, rest)["body"] == "Höchste Schwere: Hoch · FortiOS, Exchange Server, PAN-OS"
    assert webpush.summary_payload(3, "en")["body"] == "Open Cobe News"


# ---------------------------------------------------------------- "Hersteller-News meiner Produkte" by system


async def test_personal_vendor_news_by_system_watched_cves_untouched(mails):  # noqa: F811
    await _switch()
    a = await _person("anja")
    await _team([a], products=("panos", "fortios", "cisco-asa"))
    await _ways(a, email=True, systems=[PAN, {"product": "fortios"}])
    pan = await _event("panos", severity="critical")
    forti = await _event("fortios", severity="high")
    cisco = await _event("cisco-asa", severity="critical")
    await personal_dispatch()
    rows = {r.event_id: (r.status, r.error) for r in await _rows(user_id=a.id)}
    assert rows == {pan: ("sent", None), forti: ("sent", None), cisco: ("skipped", "filtered")}
    assert len(mails.sent) == 1 and "2 neue" in mails.sent[0]["subject"]
    assert personal.wants(PersonNotify(kinds=list(personal.KINDS), min_severity="info", systems=[PAN]), "watch", "low", "cisco-asa")  # a watched CVE: always


async def test_personal_systems_api_own_row_checked_kept(reader_client):
    await _switch()
    await _team([reader_client.user], products=("panos",))
    base = {"kinds": ["vendor_vuln"], "min_severity": "high"}
    r = await reader_client.put("/api/me/vendor-notify", json={**base, "systems": [PAN, PAN, {"vendor": "palo alto networks"}]})
    assert r.status_code == 200, r.text
    assert len(r.json()["systems"]) == 1  # each choice once (another spelling of the same vendor too)
    # an older page leaves the field out: kept
    kept = r.json()["systems"]
    assert (await reader_client.put("/api/me/vendor-notify", json=base)).json()["systems"] == kept
    r = await reader_client.put("/api/me/vendor-notify", json={**base, "systems": [{"product": "no-such-product"}]})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "system_not_found"
    r = await reader_client.put("/api/me/vendor-notify", json={**base, "systems": [{"product": "x"}] * 51})
    assert r.status_code == 422
    assert (await reader_client.put("/api/me/vendor-notify", json={**base, "systems": []})).json()["systems"] == []
    async with make_client() as other:
        u = await _person("otto")
        await sign_in(other, u)
        assert (await other.get("/api/me/vendor-notify")).json()["systems"] == []


# ---------------------------------------------------------------- migration


async def test_migration_0040_down_and_up():
    from alembic import command
    from sqlalchemy import inspect

    u = await _person("anja")
    async with db.session() as s:
        s.add(PersonNotify(user_id=u.id, kinds=list(personal.KINDS), min_severity="info", state_email={}, state_desktop={}, state_teams={}, systems=[PAN]))
        await s.commit()

    def cols(conn):  # noqa: ANN001, ANN202
        return {c["name"] for c in inspect(conn).get_columns("person_notify")}

    def down(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "0039")
        return cols(conn)

    def up(conn):  # noqa: ANN001, ANN202
        command.upgrade(db.alembic_config(conn), "head")
        return cols(conn)

    async with db.engine().begin() as conn:
        assert "systems" not in await conn.run_sync(down)
    async with db.engine().begin() as conn:
        assert "systems" in await conn.run_sync(up)
    async with db.engine().connect() as conn:
        assert await conn.scalar(text("SELECT systems FROM person_notify")) == []  # from before: every product
