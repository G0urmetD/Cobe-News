"""The chat messages as cards (0.1.46): per story labelled fields – Produkt (only when reliably known), Quelle, Kategorie
(topics and severity, else the kind of source) – and a short description cut at a sentence end; many stories as a
compact list. Per channel: the payload's shape, escaping, the platform limits, a missing product left out."""

import json
import uuid
from datetime import UTC, datetime
from unittest.mock import ANY

import pytest
from sqlalchemy import select, update

from app import db, news, notify, story_details, vendor_catalog
from app.models import NewsItem, NewsSource, StoryDetail, VendorEvent

LONG = (
    "Angreifer können über eine präparierte Anfrage beliebigen Code ausführen. Der Hersteller hat Updates veröffentlicht "
    "und rät dringend zur Installation. Weitere Details nennt das Advisory, darunter die betroffenen Versionen und Workarounds."
)


def story(**kw) -> notify.Story:  # noqa: ANN003
    base = dict(
        id=str(uuid.uuid4()),
        title="Chrome-Zero-Day: Google schließt Lücke",
        summary=LONG,
        url="https://news.example.org/a",
        severity="critical",
        source="heise online",
        published_at=datetime(2026, 11, 2, 8, tzinfo=UTC),
        cves=["CVE-2026-1234"],
        product="Chrome < 142.0.7444.59",
        topics=["zeroday", "exploited"],
        source_kind="press",
    )
    return notify.Story(**{**base, **kw})


# ---------------------------------------------------------------- the pieces


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Kurz.", "Kurz."),
        ("Erster Satz. Zweiter Satz. Dritter Satz.", "Erster Satz. Zweiter Satz."),
        (LONG, "Angreifer können über eine präparierte Anfrage beliebigen Code ausführen. Der Hersteller hat Updates veröffentlicht und rät dringend zur Installation."),
        ("Status: betroffen · Fix: 11.2.4-h30\nThe advisory text. More text.", "Status: betroffen · Fix: 11.2.4-h30 The advisory text."),
        ("", ""),
    ],
)
def test_brief_cuts_at_a_sentence_end(text: str, expected: str):
    assert notify.brief(text) == expected


def test_brief_of_one_long_sentence_ends_at_a_word():
    out = notify.brief("Wort " * 80)
    assert out.endswith(" …") and len(out) <= notify.BRIEF_MAX + 1 and out[:-2].split(" ")[-1] == "Wort"
    assert notify.brief("x" * 500).endswith(" …") and len(notify.brief("x" * 500)) <= notify.BRIEF_MAX + 1


def test_fields_and_category():
    assert notify.card_fields(story(), "de") == [("Produkt", "Chrome < 142.0.7444.59"), ("Quelle", "heise online"), ("Kategorie", "Zero-Day · Aktiv ausgenutzt · Kritisch")]
    # no product known: the field is left out; no topic: the kind of source
    assert notify.card_fields(story(product="", topics=[], source_kind="authority", severity="high"), "en") == [("Source", "heise online"), ("Category", "High · Authority")]
    assert notify.category(story(topics=[], source_kind=""), "de") == "Kritisch"
    # at most three topics, in the badges' order
    assert notify.category(story(topics=["ot", "breach", "ransomware", "zeroday"]), "de") == "Zero-Day · Ransomware · Vorfall/Datenleck · Kritisch"


# ---------------------------------------------------------------- per channel


def test_discord_card_and_list():
    p = notify.render_discord("Regel", [story()], 1, "de")
    (e,) = p["embeds"]
    assert {f["name"]: f["value"] for f in e["fields"]} == {"Produkt": "Chrome \\< 142.0.7444.59", "Quelle": "heise online", "Kategorie": "Zero\\-Day · Aktiv ausgenutzt · Kritisch"}
    assert all(f["inline"] and len(f["value"]) <= 1024 for f in e["fields"])
    assert e["description"].startswith("Angreifer können") and "Workarounds" not in e["description"] and "?story=" in e["description"]
    assert e["color"] == notify.DISCORD_COLORS["critical"] and e["url"] == "https://news.example.org/a"
    # without a product: no field "Produkt"
    assert [f["name"] for f in notify.render_discord("R", [story(product="")], 1, "de")["embeds"][0]["fields"]] == ["Quelle", "Kategorie"]
    # a huge field value is capped
    big = notify.render_discord("R", [story(product="P" * 5000, source="S" * 5000)], 1, "de")
    assert all(len(f["value"]) <= 1024 for f in big["embeds"][0]["fields"])
    # many: one embed, a line each, the platform's limits kept
    many = notify.render_discord("R", [story(title="T " * 120)] * 10, 40, "en")
    assert len(many["embeds"]) == 1 and len(many["embeds"][0]["description"]) <= 4096
    assert sum(notify._embed_size(x) for x in many["embeds"]) <= 6000 and "more in Cobe News" in many["content"]
    assert many["embeds"][0]["description"].count("\n") < 10  # cut before the limit, the rest counted


def test_slack_card_fields_and_list():
    p = notify.render_slack("Regel", [story(product="<!channel> Gateway")], 1, "de")
    fields = next(b for b in p["blocks"] if "fields" in b)["fields"]
    assert [f["text"].split("\n")[0] for f in fields] == ["*Produkt*", "*Quelle*", "*Kategorie*"]
    assert "<!channel>" not in json.dumps(p) and "&lt;!channel&gt; Gateway" in fields[0]["text"]
    texts = [b["text"]["text"] for b in p["blocks"] if b["type"] == "section" and "text" in b]
    assert any(t.startswith("Angreifer können") for t in texts) and p["blocks"][-1]["type"] == "actions"
    many = notify.render_slack("R", [story()] * 10, 25, "en")
    assert len(many["blocks"]) <= 50 and all(len(b["text"]["text"]) <= 3000 for b in many["blocks"] if b["type"] == "section")
    listing = next(b for b in many["blocks"] if b["type"] == "section")["text"]["text"]
    assert listing.count("\n") == 9 and "· Chrome &lt; 142.0.7444.59 · Zero-day · Actively exploited · Critical" in listing
    assert not any("fields" in b for b in many["blocks"])


def test_teams_factset_and_list():
    p = notify.render_teams("Regel", [story(product="[x](https://evil.example)")], 1, "de")
    body = p["attachments"][0]["content"]["body"]
    facts = next(i for c in body if c.get("type") == "Container" for i in c["items"] if i["type"] == "FactSet")["facts"]
    assert [f["title"] for f in facts] == ["Produkt", "Quelle", "Kategorie"] and facts[0]["value"] == "\\[x\\]\\(https://evil.example\\)"
    assert len(json.dumps(p)) < 28_000  # a Teams card: at most 28 KB
    many = notify.render_teams("R", [story(product="")] * 10, 14, "de")
    lines = [b for b in many["attachments"][0]["content"]["body"] if b["type"] == "TextBlock" and b.get("color")]
    assert len(lines) == 10 and lines[0]["text"].endswith("· Zero-Day · Aktiv ausgenutzt · Kritisch") and lines[0]["color"] == "Attention"


def test_mattermost_attachment_fields_and_list():
    p = notify.render_mattermost("Regel", [story(product="@all **x**")], 1, "de")
    a = p["attachments"][0]
    assert [f["title"] for f in a["fields"]] == ["Produkt", "Quelle", "Kategorie"] and all(f["short"] for f in a["fields"])
    assert "@all" not in json.dumps(p, ensure_ascii=False) and "\\*\\*x\\*\\*" in a["fields"][0]["value"]
    assert a["color"] == notify.ACCENTS["critical"] and "Angreifer können" in a["text"]
    many = notify.render_mattermost("R", [story()] * 10, 12, "en")
    assert len(many["attachments"]) == 1 and many["attachments"][0]["text"].count("\n") == 9 and "2 more" in many["text"]


def test_telegram_card_and_limit():
    out = notify.render_telegram("Regel", [story(product="<b>x</b> & y")], 1, "de")
    assert "<b>Produkt:</b> &lt;b&gt;x&lt;/b&gt; &amp; y" in out and "<b>Quelle:</b> heise online" in out
    assert "<b>Kategorie:</b> Zero-Day · Aktiv ausgenutzt · Kritisch" in out and "Workarounds" not in out
    assert "<b>Produkt:</b>" not in notify.render_telegram("R", [story(product="")], 1, "de")
    many = notify.render_telegram("R", [story(title="Lang " * 60)] * 10, 80, "en")
    assert len(many) < 4096 and many.count("\n• ") >= 5 and "more in Cobe News" in many


def test_push_text_card_and_list():
    title, message, sev, _ = notify.render_push("Regel", [story()], 1, "de")
    assert title.startswith("Kritisch: Chrome-Zero-Day") and sev == "critical"
    assert "Produkt: Chrome < 142.0.7444.59\nQuelle: heise online\nKategorie: Zero-Day · Aktiv ausgenutzt · Kritisch" in message
    assert "In Cobe News öffnen: https://" in message
    _, message, _, _ = notify.render_push("R", [story(product="")] * 8, 30, "en")
    assert message.count("• ") == 8 and "Product" not in message and "22 more" in message and len(message) <= notify.PUSH_TEXT_MAX


# ---------------------------------------------------------------- what the stories bring


async def _news_story(**kw) -> NewsItem:  # noqa: ANN003
    async with db.session() as s:
        await news.ensure_sources(s)
        src = await s.scalar(select(NewsSource).where(NewsSource.key == "bsi-csw"))
        i = NewsItem(
            source_id=src.id, url="https://example.org/x", url_key=str(uuid.uuid4()), title="[hoch] Produkt: Schwachstelle", title_key="t", summary="Text.",
            published_at=datetime.now(UTC), severity="high", topics=["nopatch"], **kw,
        )
        s.add(i)
        await s.commit()
        return i


async def test_news_story_brings_topics_kind_and_product_from_details():
    i = await _news_story()
    async with db.session() as s:
        row = (await s.execute(select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).where(NewsItem.id == i.id))).one()
        st = notify._story(*row)
        assert st.topics == ["nopatch"] and st.source_kind == "authority" and st.product == ""
        await notify.with_products(s, [st])
        assert st.product == ""  # no details: nothing guessed
        data = {"kind": "bsi", "products": [{"vendor": "Ex", "name": "Example Gateway", "cpe": "", "affected": [{"text": "< 2.4.1"}], "fixed": [], "not_affected": []}], "cvss": []}
        s.add(StoryDetail(item_id=i.id, kind="bsi", status="ok", data=data))
        await s.commit()
        await notify.with_products(s, [st])
    assert st.product == "Example Gateway < 2.4.1" == story_details.hint(data)["product"]
    assert notify.card_fields(st, "de")[0] == ("Produkt", "Example Gateway < 2.4.1")
    # a direction character in the CSAF product name (set after the Story was made): neutral in every renderer – the
    # webhook's JSON as well
    async with db.session() as s:
        bidi = {**data, "products": [{**data["products"][0], "name": "Example\u202e yawetaG\u2066\u0007"}]}
        await s.execute(update(StoryDetail).where(StoryDetail.item_id == i.id).values(data=bidi))
        await s.commit()
        st.product = ""
        await notify.with_products(s, [st])
    assert st.product == "Example yawetaG  < 2.4.1"
    hook = notify.render_webhook("c", [], [st], 1, "de")["stories"][0]
    assert hook["product"] == st.product and not any(c in json.dumps(hook, ensure_ascii=False) for c in "\u202e\u2066\u0007")


def test_vendor_event_product_line():
    ev = VendorEvent(
        id=uuid.uuid4(), key="k", kind="vuln", product="panos", severity="critical", created_at=datetime.now(UTC),
        data={"product": "PAN-OS", "version": "11.1.2", "fixed": "11.1.6-h3", "status": "affected", "exploited": True, "ident": "CVE-2026-1", "title": "x"},
    )
    st = notify.vendor_story(ev, "de")
    # the catalogue's label of today ("PAN-OS (Firewalls)"), not the one stored with the event
    label = vendor_catalog.product("panos")["label"]
    assert label != "PAN-OS"
    assert st.product == f"{label} 11.1.2 → 11.1.6-h3" and st.topics == ["exploited"] and st.source_kind == "vendor_news"
    assert notify.category(st, "de") == "Aktiv ausgenutzt · Kritisch"
    ev.data = {**ev.data, "exploited": False, "fixed": None}
    assert notify.vendor_story(ev, "en").product == f"{label} 11.1.2" and notify.category(notify.vendor_story(ev, "en"), "en") == "Critical · Vendor News"


@pytest.mark.parametrize("kind", ["vuln", "version", "eol", "change"])
def test_vendor_event_names_the_product_as_the_catalogue_does_today(kind: str):
    """A product merged into another key (catalogue `replaces`, migration 0025 moved the event's key, not its data) or
    renamed since: the card's Produkt and the title use today's label; a custom product keeps its own."""
    data = {"product": "DB2 (alt)", "version": "11.5.8", "status": "affected", "ident": "CVE-2026-1", "title": "x", "latest": "11.5.9", "line": "11.5", "eol_from": "2027-04-30", "revision": 2}
    label = vendor_catalog.product("ibm-db2")["label"]
    for key in ("ibm-db2", "db2"):  # moved by the migration – or an event still under the old key
        st = notify.vendor_story(VendorEvent(id=uuid.uuid4(), key="k", kind=kind, product=key, severity="high", created_at=datetime.now(UTC), data=data), "de")
        assert st.product.startswith(label) and "DB2 (alt)" not in st.product + st.title, (key, st)
    custom = notify.vendor_story(VendorEvent(id=uuid.uuid4(), key="k", kind=kind, product="custom-0123456789ab", severity="high", created_at=datetime.now(UTC), data={**data, "product": "Hausgemacht"}), "de")
    assert custom.product.startswith("Hausgemacht")


def test_webhook_carries_topics_and_product():
    st = notify.render_webhook("c", [], [story()], 1, "de")["stories"][0]
    assert st["topics"] == ["zeroday", "exploited"] and st["product"] == "Chrome < 142.0.7444.59"
    assert notify.render_webhook("c", [], [story(product="", topics=[])], 1, "de")["stories"][0] == {**st, "topics": [], "product": "", "id": ANY, "link": ANY}
