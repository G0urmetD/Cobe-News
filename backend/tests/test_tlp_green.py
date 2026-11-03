"""TLP:GREEN per CSAF provider: refused by default, read where an admin allows it (settings vendor.csaf_green, audited),
labelled in every view, message, forward, webhook and the API – and removed again (silently) once it is switched off.
AMBER, AMBER+STRICT and RED are never read."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app import csaf_providers, db, forward, notify, story_details, vendor
from app.models import AuditEntry, VendorAdvisory, VendorEvent, VendorFetch
from app.news import NewsError
from tests.test_api_tokens import get, make_token
from tests.test_structured import ASA_DOC, _cisco_routes, _csaf_round, _follow, fx, net, structured_on  # noqa: F401

CISCO = next(p for p in csaf_providers.providers() if p["key"] == "cisco")
ADV_ID = "csaf:cisco-sa-asaftd-tunnel-dos-s6mgkb75"


def _labelled(label: str) -> bytes:
    doc = json.loads(fx("csaf_cisco_asa.json"))
    doc["document"]["distribution"] = {"tlp": {"label": label}}
    return json.dumps(doc).encode()


# ---------------------------------------------------------------- the rules


def test_green_only_where_allowed_amber_and_red_never():
    assert not csaf_providers.tlp_ok("GREEN", "") and csaf_providers.tlp_ok("GREEN", "", green=True)
    assert csaf_providers.tlp_ok("", "GREEN", green=True) and not csaf_providers.tlp_ok("", "GREEN")
    for label in ("AMBER", "AMBER+STRICT", "RED"):
        assert not csaf_providers.tlp_ok(label, "", green=True) and not csaf_providers.tlp_ok("", label, green=True)
    assert csaf_providers.tlp_ok("CLEAR", "") and csaf_providers.tlp_ok("WHITE", "", green=True)
    doc = {"distributions": [{"rolie": {"feeds": [{"tlp_label": "GREEN", "url": "https://www.cisco.com/green.json"}, {"tlp_label": "AMBER", "url": "https://www.cisco.com/amber.json"}]}}]}
    assert csaf_providers.parse_metadata(json.dumps(doc).encode(), CISCO)["feeds"] == []
    assert csaf_providers.parse_metadata(json.dumps(doc).encode(), CISCO, True)["feeds"] == [{"url": "https://www.cisco.com/green.json", "tlp": "GREEN"}]


def test_advisory_of_a_green_document_carries_the_label():
    with pytest.raises(NewsError, match="blocked"):
        csaf_providers.advisory(_labelled("GREEN"), CISCO, {"url": ASA_DOC, "tlp": ""})
    adv = csaf_providers.advisory(_labelled("GREEN"), CISCO, {"url": ASA_DOC, "tlp": ""}, green=True)
    assert adv["data"]["tlp"] == "GREEN"
    assert "tlp" not in csaf_providers.advisory(_labelled("CLEAR"), CISCO, {"url": ASA_DOC, "tlp": ""}, green=True)["data"]
    for label in ("AMBER", "AMBER+STRICT", "RED"):
        with pytest.raises(NewsError, match="blocked"):
            csaf_providers.advisory(_labelled(label), CISCO, {"url": ASA_DOC, "tlp": ""}, green=True)


def test_green_allowed_takes_known_providers_only():
    assert csaf_providers.green_allowed({"csaf_green": ["openxchange", "nope"]}) == {"openxchange"}
    assert csaf_providers.green_allowed({}) == frozenset()


# ---------------------------------------------------------------- end to end: off, on, labelled, off again


def _csv() -> str:
    return f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{(datetime.now(UTC) - timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"


async def _audit(field: str) -> list[AuditEntry]:
    async with db.session() as s:
        rows = list(await s.scalars(select(AuditEntry).where(AuditEntry.action == "settings.changed").order_by(AuditEntry.id)))
    return [r for r in rows if field in (r.details.get("changes") or {})]


async def test_green_end_to_end(net, structured_on, admin_client, reader_client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(vendor, "_ready", lambda p, answered: True)  # only the CSAF provider is served here
    _cisco_routes(net, csv_=_csv(), doc=_labelled("GREEN"))
    await _follow(admin_client, "cisco-asa", "9.20.2")
    await _csaf_round()
    async with db.session() as s:
        assert await s.get(VendorAdvisory, ADV_ID) is None  # refused by default
    cur = (await admin_client.get("/api/admin/vendor")).json()
    assert cur["settings"]["csaf_green"] == [] and not next(p for p in cur["structured"]["csaf_providers"] if p["key"] == "cisco")["green"]

    # on: audited, the provider's list read again from the start, the document stored with its label
    r = await admin_client.put("/api/admin/vendor", json={"enabled": True, "csaf_green": ["cisco"], "rev": cur["settings"]["rev"]})
    assert r.status_code == 200 and r.json()["csaf_green"] == ["cisco"]
    assert (await admin_client.put("/api/admin/vendor", json={"enabled": True, "csaf_green": ["nope"]})).status_code == 422
    (entry,) = await _audit("csaf_green")
    assert entry.details["changes"]["csaf_green"] == {"from": [], "to": ["cisco"]}
    async with db.session() as s:
        st = await s.get(VendorFetch, "csaf:cisco")
        assert st.cursor is None
        out = await csaf_providers.sync_all(s, [vendor.product_of(f) for f in await vendor.follows(s)], timedelta(hours=6), await vendor.current_index(s), True, frozenset({"cisco"}))
        assert out["csaf:cisco"] == 1
        a = await s.get(VendorAdvisory, ADV_ID)
        assert a is not None and a.data["tlp"] == "GREEN"

    # the views and the API say it
    d = (await reader_client.get("/api/vendor/products/cisco-asa")).json()
    f = next(x for x in d["findings"] if x["id"] == ADV_ID)
    assert f["tlp"] == "GREEN"
    card = next(x for x in (await reader_client.get("/api/vendor/overview")).json()["items"] if x["product"]["key"] == "cisco-asa")
    assert any(x["tlp"] == "GREEN" for x in card["latest"])
    token = await make_token(admin_client)
    v1 = (await get("/api/v1/vendor/products/cisco-asa", token)).json()
    assert next(x for x in v1["findings"] if x["id"] == ADV_ID)["tlp"] == "GREEN"
    rows = (await get("/api/v1/vendor/findings", token)).json()["items"]
    assert next(x for x in rows if x["id"] == ADV_ID)["tlp"] == "GREEN"
    # the event (notification) carries it; a team forward too
    async with db.session() as s:
        await vendor.evaluate_events(s)
        ev = (await s.scalars(select(VendorEvent).where(VendorEvent.key.endswith(":" + ADV_ID)))).first()
        assert ev is not None and ev.data["tlp"] == "GREEN"
        _, fw = await forward._finding(s, "cisco-asa", ADV_ID, "de")
        assert fw.tlp == "GREEN" and fw.title.startswith("[TLP:GREEN]")
        sent = VendorEvent(id=uuid.uuid4(), key="x:" + ADV_ID, kind="vuln", product="cisco-asa", severity="high", data={**ev.data}, baseline=False, created_at=datetime.now(UTC), scope="x")
        s.add(sent)
        await s.commit()
        sent_id = sent.id

    # off again: gone at once, its pending event never goes out, audited
    cur = (await admin_client.get("/api/admin/vendor")).json()
    r = await admin_client.put("/api/admin/vendor", json={"enabled": True, "csaf_green": [], "rev": cur["settings"]["rev"]})
    assert r.status_code == 200 and r.json()["csaf_green"] == []
    assert len(await _audit("csaf_green")) == 2
    async with db.session() as s:
        assert await s.get(VendorAdvisory, ADV_ID) is None
        assert (await s.get(VendorEvent, sent_id)).baseline is True
    d = (await reader_client.get("/api/vendor/products/cisco-asa")).json()
    assert all(x["id"] != ADV_ID for x in d["findings"])


async def test_the_round_removes_green_of_a_provider_no_longer_allowed(net, structured_on, admin_client):  # noqa: F811
    _cisco_routes(net, csv_=_csv(), doc=_labelled("GREEN"))
    await _follow(admin_client, "cisco-asa", "9.20.2")
    async with db.session() as s:
        ix = await vendor.current_index(s)
        prods = [vendor.product_of(f) for f in await vendor.follows(s)]
        await csaf_providers.sync_all(s, prods, timedelta(hours=6), ix, True, frozenset({"cisco"}))
        assert await s.get(VendorAdvisory, ADV_ID) is not None
        # the setting says nothing is allowed (the default): the round's first step removes it, silently
        out = await vendor.sync_structured(s, await vendor.config(s), prods, timedelta(hours=6), ix, False)
        assert out.get("csaf:tlp_green_removed") == 1
        assert await s.get(VendorAdvisory, ADV_ID, populate_existing=True) is None
        assert await csaf_providers.purge_green(s, frozenset()) == 0


# ---------------------------------------------------------------- every renderer labels it


def _event(tlp: str | None) -> VendorEvent:
    data = {"product": "Cisco ASA", "version": "9.20.2", "status": "affected", "fixed": "9.20.3", "title": "Cisco ASA: DoS", "headline": "DoS", "summary": "A flaw.",
            "url": "https://sec.cloudapps.cisco.com/x", "ident": "cisco-sa-x", "cves": ["CVE-2026-1"], "cvss": 8.6, "exploited": False}  # fmt: skip
    if tlp:
        data["tlp"] = tlp
    return VendorEvent(id=uuid.uuid4(), key="vuln:cisco-asa:9.20.2:csaf:x", kind="vuln", product="cisco-asa", severity="high", data=data, baseline=False, created_at=datetime.now(UTC), scope="vuln:cisco-asa:9.20.2")


@pytest.mark.parametrize("lang", ["de", "en"])
def test_every_notification_format_labels_green(lang):
    green = notify.vendor_story(_event("GREEN"), lang)
    plain = notify.vendor_story(_event(None), lang)
    line = notify.tlp_line(lang)
    assert line == ("TLP:GREEN – nur intern weitergeben" if lang == "de" else "TLP:GREEN – share internally only")
    assert green.tlp == "GREEN" and green.title.startswith("[TLP:GREEN]") and not plain.tlp and "TLP" not in plain.title
    subject, text, html = notify.render_mail("Regel", [green], 1, lang)
    assert "[TLP:GREEN]" in subject and line in text and line in html
    assert line not in notify.render_mail("Regel", [plain], 1, lang)[1]
    rendered = [
        json.dumps(notify.render_slack("Regel", [green], 1, lang), ensure_ascii=False),
        json.dumps(notify.render_teams("Regel", [green], 1, lang), ensure_ascii=False),
        json.dumps(notify.render_discord("Regel", [green], 1, lang), ensure_ascii=False),
        json.dumps(notify.render_mattermost("Regel", [green], 1, lang), ensure_ascii=False),
        notify.render_telegram("Regel", [green], 1, lang),
        "\n".join(notify.render_push("Regel", [green], 1, lang)[:2]),
    ]
    for r in rendered:
        r = r.replace("\\", "")  # Discord escapes the colon
        assert "TLP:GREEN" in r, r[:200]
        assert line.split("–")[1].strip().split()[0] in r  # the field's text, escaped as each format does
    many = [green] + [notify.vendor_story(_event(None), lang) for _ in range(20)]
    assert "TLP:GREEN" in json.dumps(notify.render_slack("Regel", many, len(many), lang))  # the compact list: the title
    hook = notify.render_webhook("n8n", ["Regel"], [green, plain], 2, lang)
    assert [s["tlp"] for s in hook["stories"]] == ["GREEN", ""]
    change = VendorEvent(id=uuid.uuid4(), key="change:x", kind="change", product="cisco-asa", severity="high", data={"tlp": "GREEN", "ident": "cisco-sa-x", "revision": 2}, baseline=False, created_at=datetime.now(UTC))
    assert notify.vendor_story(change, lang).tlp == "GREEN"


@pytest.mark.parametrize("lang", ["de", "en"])
def test_forward_card_labels_green(lang):
    f = forward.Forward(sender="Anna", team="SOC", comment="", title="[TLP:GREEN] Cisco ASA: x", summary="A flaw.", url="https://sec.cloudapps.cisco.com/x", link="https://news.test/vendor",
                        severity="high", source="Vendor News", published_at=datetime.now(UTC), kind="finding", product="Cisco ASA", source_kind="vendor_news", tlp="GREEN")  # fmt: skip
    line = notify.tlp_line(lang)
    _, text, html = forward.render_mail(f, lang)
    assert line in text and line in html
    assert line in json.dumps(forward.render_teams(f, lang), ensure_ascii=False)
    assert "TLP:GREEN" in forward.render_telegram(f, lang)
    assert forward.render_webhook(f, "n8n", lang, "d1")["forward"]["tlp"] == "GREEN"
    assert forward.render_webhook(forward.Forward(**{**f.__dict__, "tlp": ""}), "n8n", lang, "d1")["forward"]["tlp"] == ""


# ---------------------------------------------------------------- the stories' details take public documents only


async def test_story_details_never_use_a_green_document(monkeypatch):
    async def fake_get(url, **kw):  # noqa: ANN001, ANN003
        return _labelled("GREEN")

    monkeypatch.setattr(vendor, "get", fake_get)

    class Item:
        cves = ["CVE-2026-20001"]
        url = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tunnel-dos-s6mgkb75"
        title = summary = "x"
        published_at = datetime.now(UTC)

    class Source:
        key = "cisco-psirt"

    async with db.session() as s:
        assert await story_details.build(s, Item(), Source(), None, "", [0]) is None
        assert await s.get(VendorAdvisory, ADV_ID) is None
