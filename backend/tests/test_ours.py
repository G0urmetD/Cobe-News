""""Unsere Produkte (aus Vendor News)" as a system ({"ours": true}, app/systems.py Followed): the products followed when
a story is judged – as if each were chosen on its own (exact or named, loud only for a notification), a product followed
later counts from then on (no flood of older stories), one no longer followed stops counting, a product followed by CPE
by the story's details (news_items.products), nothing followed: nothing. The same everywhere the systems choice works:
a channel rule (news and Vendor News events), its dry run, the News list's `system=ours`, a person's desktop
notifications (tab and Web Push) and "Security-Meldungen" – "Treffer" names the matched products. Checked input, the
audit log's name, not offered for "Hersteller-News meiner Produkte" – and migration 0045."""

import uuid
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from conftest import set_news
from sqlalchemy import select, text, update
from test_notify import SLACK, _channel, _dispatch, _rule, _source
from test_own_filters import service  # noqa: F401 - fixture
from test_personal import _switch, _team
from test_personal import mails  # noqa: F401 - fixture
from test_personal_news import _allow, _body, _signed
from test_personal_news import _dispatch as _news_dispatch
from test_push import FCM, Browser
from test_rule_filters import _news, _pan_details, _sent_titles, _slack_texts, hooks  # noqa: F401 - fixture

from app import concerns, db, notify_api, systems, webpush
from app.models import AuditEntry, NewsItem, VendorEvent, VendorFollow

OURS = {"ours": True}


async def _follow(c, key: str, enabled: bool = True) -> None:  # noqa: ANN001
    r = await c.put(f"/api/vendor/follows/{key}", json={"enabled": enabled})
    assert r.status_code == 200, r.text


async def _custom(c, label: str = "Hausgemachte Firewall") -> str:  # noqa: ANN001
    r = await c.post("/api/vendor/custom", json={"cpe": "cpe:2.3:a:acme:homefw", "label": label})
    assert r.status_code == 200, r.text
    return r.json()["key"]


async def _concerns_custom(iid: uuid.UUID, key: str) -> None:
    """As story_details does when the story's details concern a product followed by CPE."""
    async with db.session() as s:
        await s.execute(update(NewsItem).where(NewsItem.id == iid).values(products=[key]))
        await s.commit()


async def _setup(c, **rule) -> None:  # noqa: ANN001
    ch = await _channel(c, name="SOC", type="slack", url=SLACK)
    await _rule(c, "Unsere", [ch["id"]], **{"severities": [], "systems": [OURS], **rule})


# ---------------------------------------------------------------- a channel rule


async def test_a_rule_with_our_products_sends_followed_ones_exact_or_named(admin_client, hooks):  # noqa: F811
    src = await _source()
    await _follow(admin_client, "panos")
    await _setup(admin_client)
    await _news(src, "PAN-OS: Kritische Lücke wird ausgenutzt")  # named
    await _news(src, "CVE-2026-1234: Speicherfehler", details=_pan_details())  # exact: its details concern PAN-OS
    await _news(src, "Fortinet schließt Lücke in FortiOS")  # a product nobody follows
    await _news(src, "Ransomware trifft Krankenhaus")  # no system
    await _dispatch()
    assert await _sent_titles(hooks) == ["CVE-2026-1234: Speicherfehler", "PAN-OS: Kritische Lücke wird ausgenutzt"]
    body = "\n".join(_slack_texts(hooks))
    assert "Treffer" in body and "PAN-OS" in body and "Unsere Produkte" not in body  # the product, not the choice


async def test_a_product_followed_later_counts_from_then_on_one_unfollowed_stops(admin_client, hooks):  # noqa: F811
    src = await _source()
    await _follow(admin_client, "panos")
    await _setup(admin_client)
    old = await _news(src, "FortiOS: Lücke vor dem Folgen")  # FortiOS not followed yet
    quiet_then_loud = await _news(src, "Speicherfehler in einer Firewall")  # names nothing – its details come later
    await _dispatch()
    assert await _sent_titles(hooks) == []
    await _follow(admin_client, "fortios")
    await _news(src, "FortiOS: Lücke nach dem Folgen")
    # details that arrive after the follow: a change of the story's own, loudly – it counts then
    async with db.session() as s:
        await systems.set_exact(s, quiet_then_loud, ["fortios"], quiet=False)
        await s.commit()
    await _dispatch()
    assert await _sent_titles(hooks) == ["FortiOS: Lücke nach dem Folgen", "Speicherfehler in einer Firewall"]  # not the older one
    async with db.session() as s:
        assert (await s.get(NewsItem, old)).systems  # it does concern FortiOS – it is just no news because of the follow
    # switched off (not followed any more): stops counting – and switched on again counts from then on
    await _follow(admin_client, "fortios", enabled=False)
    await _news(src, "FortiOS: Lücke während aus")
    await _dispatch()
    assert "FortiOS: Lücke während aus" not in await _sent_titles(hooks)
    await _follow(admin_client, "fortios")
    await _news(src, "FortiOS: wieder an")
    await _dispatch()
    sent = await _sent_titles(hooks)
    assert "FortiOS: wieder an" in sent and "FortiOS: Lücke während aus" not in sent and "FortiOS: Lücke vor dem Folgen" not in sent
    # removed: stops as well
    assert (await admin_client.delete("/api/vendor/follows/fortios")).status_code == 200
    await _news(src, "FortiOS: nach dem Entfernen")
    await _dispatch()
    assert "FortiOS: nach dem Entfernen" not in await _sent_titles(hooks)


async def test_a_product_followed_by_cpe_counts_by_the_story_s_details(admin_client, hooks):  # noqa: F811
    src = await _source()
    await _setup(admin_client)
    key = await _custom(admin_client)
    iid = await _news(src, "CVE-2026-9999: Lücke in einer Appliance")
    await _concerns_custom(iid, key)
    await _news(src, "Andere Appliance: Lücke")
    await _dispatch()
    assert await _sent_titles(hooks) == ["CVE-2026-9999: Lücke in einer Appliance"]
    assert "Hausgemachte Firewall" in "\n".join(_slack_texts(hooks))  # its label as the "Treffer"


async def test_nothing_followed_matches_nothing_never_all(admin_client, hooks):  # noqa: F811
    src = await _source()
    await _setup(admin_client)
    await _news(src, "PAN-OS: Kritische Lücke")
    await _news(src, "Ransomware trifft Krankenhaus")
    await _dispatch()
    assert hooks.to("hooks.slack.com") == []
    async with db.session() as s:
        await systems.load_followed(s)
    assert systems.product_keys([OURS]) == [] and systems.wanted([OURS]) == []


async def test_vendor_news_events_of_the_followed_products(admin_client, hooks):  # noqa: F811
    await _follow(admin_client, "panos")
    await _setup(admin_client, kinds=["vendor_vuln"])
    async with db.session() as s:
        for k in ("panos", "fortios"):  # an event of a product no longer followed (left from before)
            s.add(VendorEvent(key=f"vuln:{k}:*:x", kind="vuln", product=k, severity="critical", data={"product": k, "status": "affected", "title": f"Lücke in {k}"}))
        await s.commit()
    await _dispatch()
    body = "\n".join(_slack_texts(hooks))
    assert "PAN-OS" in body and "FortiOS" not in body


async def test_the_dry_run_counts_our_products_also_older_and_quiet(admin_client):
    src = await _source()
    await _news(src, "PAN-OS: Lücke vor dem Folgen")
    await _news(src, "FortiOS: Lücke")
    await _follow(admin_client, "panos")
    body = {"severities": [], "kinds": ["news"], "systems": [OURS], "days": 7}
    dry = (await admin_client.post("/api/admin/notify/rules/dry-run", json=body)).json()
    assert [x["title"] for x in dry["items"]] == ["PAN-OS: Lücke vor dem Folgen"] and dry["items"][0]["hits"] == ["PAN-OS"]
    notify_api._dry_at.clear()


# ---------------------------------------------------------------- checks, the audit log


async def test_the_entry_is_checked_and_named(admin_client):
    ch = await _channel(admin_client, name="SOC", type="slack", url=SLACK)
    ok = await _rule(admin_client, "Unsere", [ch["id"]], systems=[OURS, {"product": "panos"}, OURS])
    assert ok["systems"] == [OURS, {"product": "panos"}]  # once
    base = {"name": "X rule", "channels": [ch["id"]]}
    for bad in ({"ours": False}, {"ours": "yes"}, {"ours": 1}, {"ours": True, "product": "panos"}, {"ours": True, "vendor": "Palo Alto Networks"}, {"ours": True, "all": True}, {"ours": None}):
        r = await admin_client.post("/api/admin/notify/rules", json={**base, "systems": [bad]})
        assert r.status_code == 422, bad
    up = await admin_client.put(f"/api/admin/notify/rules/{ok['id']}", json={"name": "Unsere", "channels": [ch["id"]], "systems": [OURS], "version": ok["version"]})
    assert up.status_code == 200
    async with db.session() as s:
        e = await s.scalar(select(AuditEntry).where(AuditEntry.action == "rule.changed"))
    assert "Unsere Produkte (aus Vendor News)" in str(e.details)
    assert systems.label(OURS, "en") == "Our products (from Vendor News)"
    assert systems.of_text([systems.text_of(OURS)]) == [OURS] and systems.known(OURS)
    # an address: `system=ours`
    assert concerns.from_query(["ours", "p:panos", "ours"]) == [OURS, {"product": "panos"}]
    for bad in ("OURS", "ours:x", "o:ours", "ours!"):
        with pytest.raises(ValueError):
            concerns.from_query([bad])


async def test_not_offered_for_the_vendor_news_of_my_products(reader_client):
    await _switch()
    await _team([reader_client.user], products=("panos",))
    r = await reader_client.put("/api/me/vendor-notify", json={"kinds": ["vendor_vuln"], "min_severity": "high", "systems": [OURS]})
    assert r.status_code == 422


# ---------------------------------------------------------------- the News list, the own notifications


async def test_news_list_by_our_products(admin_client):
    await set_news(enabled=True)
    src = await _source()
    pan = str(await _news(src, "PAN-OS: Lücke vor dem Folgen"))  # a list counts what arrived before too
    exact = str(await _news(src, "CVE-2026-1: Speicherfehler", details=_pan_details()))
    forti = str(await _news(src, "FortiOS: Lücke"))
    appliance = await _news(src, "CVE-2026-2: Appliance")

    async def ids(*values: str) -> set[str]:
        r = await admin_client.get("/api/news", params={"state": "all", "system": list(values)})
        assert r.status_code == 200, r.text
        return {i["id"] for i in r.json()["items"]}

    assert await ids("ours") == set()  # nothing followed: nothing
    await _follow(admin_client, "panos")
    key = await _custom(admin_client)
    await _concerns_custom(appliance, key)
    assert await ids("ours") == {pan, exact, str(appliance)}
    assert await ids("ours", "p:fortios") == {pan, exact, str(appliance), forti}
    r = await admin_client.post("/api/news/read-all", json={"system": ["ours"]})
    assert r.status_code == 200 and r.json()["marked"] == 3
    await _follow(admin_client, "panos", enabled=False)
    assert await ids("ours") == {str(appliance)}  # no longer followed: no longer ours
    assert (await admin_client.get("/api/news", params={"system": "Ours"})).status_code == 422


async def test_desktop_tab_and_web_push_name_the_matched_product(admin_client, service):  # noqa: F811
    await _follow(admin_client, "panos")
    src = await _source()
    r = await admin_client.put("/api/me/desktop", json={"enabled": True, "severities": [], "sources": [], "systems": [OURS]})
    assert r.status_code == 200 and r.json()["systems"] == [OURS]
    cursor = (await admin_client.get("/api/news/recent")).json()["cursor"]
    b = Browser()
    await admin_client.post("/api/me/push", json={"endpoint": FCM, "keys": b.keys(), "lang": "de"})
    pan = str(await _news(src, "Palo Alto Networks: Kritische Lücke in PAN-OS"))
    await _news(src, "Fortinet schließt Lücke in FortiOS")
    got = (await admin_client.get("/api/news/recent", params={"after": cursor, "mine": "true"})).json()
    assert [i["id"] for i in got["items"]] == [pan] and got["items"][0]["hits"] == ["PAN-OS"]
    async with db.session() as s:
        assert await webpush.dispatch(s) == {"sent": 1, "failed": 0}
    [msg] = [b.read(x.content) for x in service.requests]
    assert msg["title"] == "Palo Alto Networks: Kritische Lücke in PAN-OS" and msg["body"] == "Kritisch · Treffer: PAN-OS · Example Feed"


async def test_personal_security_stories_by_our_products(admin_client, mails):  # noqa: F811
    await _allow()
    await _follow(admin_client, "panos")
    src = await _source()
    _u, c = await _signed()
    async with c:
        r = await c.put("/api/me/news-notify", json=_body(systems=[OURS]))
        assert r.status_code == 200 and r.json()["systems"] == [OURS]
    await _news(src, "Palo Alto Networks: Kritische Lücke in PAN-OS")
    await _news(src, "Fortinet schließt Lücke in FortiOS")
    assert await _news_dispatch() == {"sent": 1}
    [m] = mails.sent
    assert "Kritische Lücke in PAN-OS" in m["text"] and "Treffer: PAN-OS" in m["text"] and "FortiOS" not in m["text"]


# ---------------------------------------------------------------- the followed products: read once, kept


async def test_followed_products_are_read_once_and_again_after_a_change(admin_client):
    async with db.session() as s:
        a = await systems.load_followed(s)
        assert a.keys == frozenset() and await systems.load_followed(s) is a  # kept
    await _follow(admin_client, "panos")  # vendor.bump: read again
    async with db.session() as s:
        b = await systems.load_followed(s)
        assert b.keys == frozenset({"panos"}) and b.since["panos"] <= datetime.now(UTC)
        await s.execute(text("UPDATE vendor_follows SET enabled = false"))  # elsewhere (no bump): after FOLLOWED_TTL
        await s.commit()
        assert await systems.load_followed(s) is b
        systems._followed[0] = replace(b, at=b.at - systems.FOLLOWED_TTL - 1)
        assert (await systems.load_followed(s)).keys == frozenset()


async def test_migration_0045_down_and_up():
    from alembic import command
    from sqlalchemy import inspect

    def columns(conn):  # noqa: ANN001, ANN202
        return {c["name"] for c in inspect(conn).get_columns("vendor_follows")}

    def down(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "0044")
        return columns(conn)

    def up(conn):  # noqa: ANN001, ANN202
        command.upgrade(db.alembic_config(conn), "head")
        return columns(conn)

    async with db.engine().begin() as conn:
        assert "enabled_at" not in await conn.run_sync(down)
        await conn.execute(text("INSERT INTO vendor_follows (id, product, enabled, note, tags, created_at, updated_at) VALUES (gen_random_uuid(), 'panos', true, '', '[]', now() - interval '3 days', now())"))
    async with db.engine().begin() as conn:
        assert "enabled_at" in await conn.run_sync(up)
    async with db.session() as s:
        f = await s.scalar(select(VendorFollow))
        assert f.enabled_at == f.created_at  # an existing follow counts as it always did
