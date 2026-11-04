# ruff: noqa: F811 - the fixtures of test_personal (mails) are imported and used by name
"""The notification mail: the publisher's status tags out of the title (mail, chat cards, push – not the
webhook), the order (our products, actively exploited, severity, newest) also for what makes the cut, a subject that
says what the stories are about, a summary line instead of a second heading, a facts line per story (product, CVEs,
topics), "Betrifft eure Produkte", the recipient's local time with its zone, a dark mode, a compact list from
COMPACT_FROM stories on and a footer that names the rule with a link to edit it – the plain text part says the same."""

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from test_personal import _dispatch, _event, _person, _switch, _team, _ways, mails  # noqa: F401
from test_quiet_absence import _schedule

from app import db, news, notify, personal
from app.models import NewsItem, NewsSource, NotifyRule, VendorEvent, VendorFollow

WINTER = datetime(2026, 11, 4, 9, 19, tzinfo=UTC)
SUMMER = datetime(2026, 7, 1, 9, 19, tzinfo=UTC)


def story(n: int = 1, **kw) -> notify.Story:  # noqa: ANN003
    base = dict(
        id=f"00000000-0000-4000-8000-{n:012d}",
        title=f"Produkt {n}: Lücke",
        summary="Ein Angreifer kann Code ausführen.",
        url=f"https://wid.example.org/{n}",
        severity="medium",
        source="BSI CERT-Bund (WID)",
        published_at=WINTER - timedelta(hours=n),
    )
    return notify.Story(**{**base, **kw})


# ---------------------------------------------------------------- the title


@pytest.mark.parametrize(
    ("title", "want"),
    [
        ("[NEU] [hoch] Emerson Ovation: Mehrere Schwachstellen", "Emerson Ovation: Mehrere Schwachstellen"),
        ("[UPDATE] [kritisch] SolarWinds Dameware: Codeausführung", "SolarWinds Dameware: Codeausführung"),
        ("[UPDATE] [UNGEPATCHT] [mittel] Exchange: Lücke", "Exchange: Lücke"),
        ("[niedrig] Browser: Spoofing", "Browser: Spoofing"),
        ("[NEU][HOCH]  Linux Kernel: Schwachstelle", "Linux Kernel: Schwachstelle"),
        ("[TLP:GREEN] [NEU] [hoch] Gerät: Lücke", "[TLP:GREEN] Gerät: Lücke"),
        # never real content: other brackets, tags inside the title, a title of nothing but tags
        ("[Video] So funktioniert der Angriff", "[Video] So funktioniert der Angriff"),
        ("Patchday [hoch]: Microsoft schließt 60 Lücken", "Patchday [hoch]: Microsoft schließt 60 Lücken"),
        ("[NEUES] Werkzeug veröffentlicht", "[NEUES] Werkzeug veröffentlicht"),
        ("[NEU] [hoch]", "[NEU] [hoch]"),
        ("", ""),
    ],
)
def test_headline_strips_only_the_publishers_tags_in_front(title, want):
    assert notify.headline(title) == want
    assert story(title=title).headline == want


def test_tags_out_in_mail_cards_and_push_but_not_in_the_webhook():
    s = story(title="[NEU] [hoch] Emerson Ovation: Mehrere Schwachstellen", severity="high")
    subject, text, html = notify.render_mail("R", [s], 1, "de")
    assert subject == "[Cobe News] Hoch: Emerson Ovation: Mehrere Schwachstellen"
    for out in (text, html, str(notify.render_slack("R", [s], 1, "de")), str(notify.render_teams("R", [s], 1, "de")), str(notify.render_discord("R", [s], 1, "de")),
                notify.render_telegram("R", [s], 1, "de"), str(notify.render_mattermost("R", [s], 1, "de")), "\n".join(notify.render_push("R", [s], 1, "de")[:2])):  # fmt: skip
        assert "[NEU]" not in out and "[hoch]" not in out and "Emerson Ovation" in out
    assert notify.render_push("R", [s], 1, "de")[0] == "Hoch: Emerson Ovation: Mehrere Schwachstellen"
    # the webhook's receiver gets the title as the source wrote it
    assert notify.render_webhook("n8n", ["R"], [s], 1, "de")["stories"][0]["title"] == s.title


# ---------------------------------------------------------------- the order


def test_order_our_products_then_exploited_then_severity_then_newest():
    crit = story(1, severity="critical")
    old_high = story(2, severity="high", published_at=WINTER - timedelta(days=2))
    new_high = story(3, severity="high")
    hot = story(4, severity="low", topics=["exploited"])
    ours = story(5, severity="info", ours=["PAN-OS"])
    got = sorted([crit, old_high, new_high, hot, ours], key=notify.priority, reverse=True)
    assert [s.id[-1] for s in got] == ["5", "4", "1", "3", "2"]
    # the mail lists them so, whatever order it is given
    text = notify.render_mail("R", [crit, old_high, new_high, hot, ours], 5, "de")[1]
    assert [text.index(f"Produkt {n}: Lücke") for n in (5, 4, 1, 3, 2)] == sorted(text.index(f"Produkt {n}: Lücke") for n in (5, 4, 1, 3, 2))


def test_what_makes_the_cut_follows_the_same_order():
    rule = NotifyRule(id=uuid.uuid4(), name="Alles", lang="de")
    many = [notify.Row(story(n, severity="critical"), rule, ("news", uuid.uuid4())) for n in range(1, 15)]
    low_ours = notify.Row(story(20, severity="low", ours=["Example Gateway"]), rule, ("news", uuid.uuid4()))
    low_hot = notify.Row(story(21, severity="low", topics=["exploited"]), rule, ("news", uuid.uuid4()))
    [m] = notify.plan([*many, low_ours, low_hot])
    assert m.total == 16 and len(m.stories) == notify.LIST
    assert m.stories[0] is low_ours.story and m.stories[1] is low_hot.story
    resent = notify.summary([(r.story, "news", rule.id) for r in [*many, low_ours, low_hot]], "de", [{"id": str(rule.id), "name": "Alles"}])
    assert resent.stories[:2] == [low_ours.story, low_hot.story]


# ---------------------------------------------------------------- subject, heading, summary line


def test_subject_names_the_stories():
    stories = [
        story(1, title="[NEU] [hoch] Emerson Ovation: Mehrere Schwachstellen", severity="high"),
        story(2, title="[UPDATE] [kritisch] SolarWinds Dameware: Codeausführung", severity="critical"),
        story(3, title="Hackers abuse a flaw in a very popular remote management tool used by many companies", severity="low"),
        story(4, title="Gerät: Lücke", severity="low", ours=["Example Gateway"]),
        story(5, title="Noch ein Gerät: Lücke", severity="low"),
    ]
    subject = notify.render_mail("Regel", stories, 7, "de")[0]
    assert subject.startswith("[Cobe News] 7 neue Meldungen: Example Gateway, SolarWinds Dameware, Emerson Ovation, Hackers abuse a flaw in a very popular…")
    assert re.search(r" \+\d$", subject) and len(subject) <= notify.SUBJECT_MAX
    assert notify.render_mail("Rule", stories, 5, "en")[0].startswith("[Cobe News] 5 new stories: Example Gateway, ")
    # the same name twice is named once (and counted)
    twice = notify.render_mail("R", [story(1, title="Gerät: x"), story(2, title="Gerät: y")], 2, "de")[0]
    assert twice == "[Cobe News] 2 neue Meldungen: Gerät"
    # a TLP:GREEN story among them: marked in front; the test message as before
    green = story(6, title="[TLP:GREEN] Example Firewall 7.2: Lücke", tlp="GREEN")
    assert notify.render_mail("R", [green, story(1)], 2, "de")[0].startswith("[Cobe News] [TLP:GREEN] 2 neue Meldungen: ")
    assert notify.render_mail("Kanal", [story(1)], 1, "de", test=True)[0] == "[Cobe News] Testnachricht · Kanal"


@pytest.mark.parametrize("lang", ["de", "en"])
def test_heading_once_and_a_summary_line(lang):
    stories = [story(1, severity="high", ours=["PAN-OS"]), story(2, severity="critical", topics=["exploited"]), story(3), story(4), story(5, topics=["exploited"])]
    _, text, html = notify.render_mail("R", stories, 5, lang)
    heading = "5 neue Security-Meldungen" if lang == "de" else "5 new security stories"
    line = "Höchste Schwere: Kritisch · 1 betrifft eure Produkte · 2 aktiv ausgenutzt" if lang == "de" else "Highest severity: Critical · 1 concerns your products · 2 actively exploited"
    assert html.count(heading) == 1  # the heading – no eyebrow repeating it
    assert line in html and text.startswith(f"{heading}\n{line}\n")
    plain = notify.render_mail("R", [story(1), story(2)], 2, lang)[1]
    assert ("Höchste Schwere: Mittel\n" if lang == "de" else "Highest severity: Medium\n") in plain  # nothing to count: left out
    one = notify.render_mail("R", [story(1, severity="high", ours=["PAN-OS"], topics=["exploited"])], 1, lang)[1]
    assert ("Schwere: Hoch · Betrifft eure Produkte · Aktiv ausgenutzt" if lang == "de" else "Severity: High · Concerns your products · Actively exploited") in one


# ---------------------------------------------------------------- the story


@pytest.mark.parametrize("lang", ["de", "en"])
def test_facts_line_and_our_products(lang):
    s = story(1, severity="high", product="Example Gateway 2.3.0 → 2.4.1", cves=["CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4", "CVE-2026-5"],
              topics=["poc", "exploited", "zeroday"], ours=["Example Gateway", "Example VPN"])  # fmt: skip
    _, text, html = notify.render_mail("R", [s], 1, lang)
    topics = "Zero-Day, Aktiv ausgenutzt, Exploit veröffentlicht" if lang == "de" else "Zero-day, Actively exploited, Exploit published"
    assert f"Example Gateway 2.3.0 → 2.4.1 · CVE-2026-1, CVE-2026-2, CVE-2026-3 +2 · {topics}" in text
    ours = ("Betrifft eure Produkte" if lang == "de" else "Concerns your products") + ": Example Gateway, Example VPN"
    assert ours in text and ours in html and 'class="cn-ours"' in html
    assert "CVE-2026-4" not in html and ">+2<" not in html and " +2" in html
    # without a product, CVEs or topics: no facts line, no mark
    _, text, html = notify.render_mail("R", [story(2)], 1, lang)
    assert 'class="cn-ours"' not in html and "CVE" not in text


def test_feed_text_is_escaped():
    evil = story(1, title='<img src=x onerror=alert(1)>: "x"', summary="<script>alert(1)</script>", product="<b>P</b>", ours=["<i>O</i>"], source="<s>Q</s>", cves=["<CVE>"])
    for stories in ([evil], [evil] * notify.COMPACT_FROM):
        html = notify.render_mail("<u>Regel</u>", stories, len(stories), "de", rules=["<u>Regel</u>"])[2]
        for raw in ("<img", "<script", "<b>P", "<i>O", "<s>Q", "<CVE>", "<u>Regel"):
            assert raw not in html


# ---------------------------------------------------------------- the time


def test_local_time_with_the_zone():
    assert notify._local(WINTER, "de") == "04.11.2026 10:19 MEZ"
    assert notify._local(SUMMER, "de") == "01.07.2026 11:19 MESZ"
    assert notify._local(WINTER, "en") == "2026-11-04 10:19 CET"
    assert notify._local(SUMMER, "en") == "2026-07-01 11:19 CEST"
    assert notify._local(WINTER, "de", "America/New_York") == "04.11.2026 04:19 EST"
    assert notify._local(WINTER, "de", "Not/AZone") == "04.11.2026 10:19 MEZ"  # an unknown zone: Europe/Berlin
    _, text, html = notify.render_mail("R", [story(1, published_at=WINTER)], 1, "de")
    assert "04.11.2026 10:19 MEZ" in text and "04.11.2026 10:19 MEZ" in html and "UTC" not in text


async def test_personal_mail_in_the_persons_zone(mails):
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True)
    await _schedule(a, quiet=False, tz="America/New_York")
    await _event("panos", severity="high", title="Lücke im VPN")
    await _dispatch()
    [m] = mails.sent
    assert re.search(r"\d\d:\d\d E[SD]T", m["text"]) and "MEZ" not in m["text"]
    # every event is of the person's products: no mark on each, the footer says why
    assert "Betrifft eure Produkte" not in m["text"] and "Regel bearbeiten" not in m["text"]
    assert personal.LABELS["de"]["footer"][0] in m["text"]


# ---------------------------------------------------------------- the layout


def test_compact_list_from_the_threshold_on():
    cards = [story(n, summary=f"Zusammenfassung {n}") for n in range(1, notify.COMPACT_FROM)]
    _, text, html = notify.render_mail("R", cards, len(cards), "de")
    assert "Zusammenfassung 1" in html and "Zusammenfassung 1" in text and "Artikel öffnen" in html
    many = [story(n, summary=f"Zusammenfassung {n}") for n in range(1, notify.COMPACT_FROM + 3)]
    _, text, html = notify.render_mail("R", many, 30, "de")
    assert "Zusammenfassung" not in html and "Zusammenfassung" not in text and "Artikel öffnen" not in html
    assert html.count('class="cn-line"') == len(many) and text.count("\n• [Mittel] ") == len(many)
    assert f'href="{notify._link(many[0].id)}"' in html  # the title opens the story in Cobe News
    assert "… und 22 weitere in Cobe News." in text


def test_dark_mode_and_no_external_resources():
    html = notify.render_mail("R", [story(1, tlp="GREEN", ours=["X"], topics=["exploited"])], 1, "de")[2]
    assert '<meta name="color-scheme" content="light dark">' in html and '<meta name="supported-color-schemes" content="light dark">' in html
    assert "@media (prefers-color-scheme: dark)" in html and "[data-ogsc] .cn-text" in html and "[data-ogsb] .cn-card" in html
    for cls in ("cn-sev-medium", "cn-ourspill", "cn-hot", "cn-tlp"):
        assert f"class=\"{cls}\"" in html and f".{cls}{{" in html
    assert "<img" not in html and "src=" not in html and "url(" not in html


def _contrast(a: str, b: str) -> float:
    def lum(h: str) -> float:
        r, g, b_ = (int(h[i : i + 2], 16) / 255 for i in (1, 3, 5))
        f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4  # noqa: E731
        return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b_)

    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_pills_are_readable_in_both_modes():
    for fg, bg in notify.SEV_COLORS.values():
        assert _contrast(fg, bg) >= 4.5, (fg, bg)
    for cls, (fg, bg, _) in notify.DARK.items():
        if fg and bg:
            assert _contrast(fg, bg) >= 4.5, cls


# ---------------------------------------------------------------- the footer


def test_footer_names_the_rule_with_a_link_to_edit_it():
    rid = str(uuid.uuid4())
    _, text, html = notify.render_mail("Kritisch", [story(1)], 1, "de", rules=["Kritisch"], rule_ids=[rid])
    link = f"https://news.corp.example:8095/settings/rules?tab=rules&amp;rule={rid}"
    assert "Regel „Kritisch“" in html and f'href="{link}"' in html and ">Regel bearbeiten</a>" in html
    assert f"Regel „Kritisch“ · Regel bearbeiten: {link.replace('&amp;', '&')}" in text
    _, text, html = notify.render_mail("A, B", [story(1)], 1, "en", rules=["A", "B"], rule_ids=[str(uuid.uuid4()), rid])
    assert "Rules “A”, “B” · Edit rules: https://news.corp.example:8095/settings/rules?tab=rules\n" in text
    # the personal notifications keep their own footer
    _, text, html = notify.render_mail("Hersteller-News", [story(1)], 1, "de", footer=["Warum du sie bekommst."])
    assert "Warum du sie bekommst." in text and "Regel" not in text.split("-- ")[1]


async def test_a_rule_mail_links_its_rule(admin_client, monkeypatch):
    """The round passes the rules that brought a message to the mail (deliver → render_mail)."""
    seen = {}

    def fake(rule, stories, total, lang, **kw):  # noqa: ANN001, ANN003
        seen.update(kw)
        return "s", "t", "h"

    async def fake_send(*_a):  # noqa: ANN002
        return None

    monkeypatch.setattr(notify, "render_mail", fake)
    monkeypatch.setattr(notify, "send_mail", fake_send)
    t = notify.Target(id=uuid.uuid4(), name="Mail", type="email", recipients=["soc@corp.example"])
    await notify.deliver(t, [story(1)], 1, "de", "Kritisch", rules=["Kritisch"], rule_ids=["r1"])
    assert seen["rules"] == ["Kritisch"] and seen["rule_ids"] == ["r1"]


# ---------------------------------------------------------------- "Betrifft eure Produkte" from the database


async def test_our_products_come_from_the_story_and_the_followed_ones():
    async with db.session() as s:
        await news.ensure_sources(s)
        src = await s.scalar(select(NewsSource).where(NewsSource.key == "bsi-csw"))
        s.add(VendorFollow(product="panos", enabled=True))
        i = NewsItem(source_id=src.id, url="https://example.org/o", url_key=str(uuid.uuid4()), title="[NEU] [hoch] PAN-OS: Lücke", title_key="o", summary="", published_at=datetime.now(UTC),
                     severity="high", products=["panos", "not-followed"])  # fmt: skip
        j = NewsItem(source_id=src.id, url="https://example.org/p", url_key=str(uuid.uuid4()), title="Anderes", title_key="p", summary="", published_at=datetime.now(UTC), severity="critical")
        s.add_all([i, j])
        await s.commit()
        rows = (await s.execute(select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id))).all()
        stories = [notify._story(*r) for r in rows]
        await notify.with_products(s, stories)
    ours = next(x for x in stories if x.id == str(i.id))
    from app import vendor_catalog

    assert ours.ours == [vendor_catalog.product("panos")["label"]] and next(x for x in stories if x.id == str(j.id)).ours == []
    assert sorted(stories, key=notify.priority, reverse=True)[0] is ours  # before the critical one


def test_a_vendor_finding_is_ours_a_version_is_not():
    vuln = VendorEvent(id=uuid.uuid4(), key="k", kind="vuln", product="panos", severity="high", created_at=datetime.now(UTC), data={"product": "PAN-OS", "version": "11.1.2", "status": "affected", "ident": "PAN-SA-1"})
    version = VendorEvent(id=uuid.uuid4(), key="v", kind="version", product="panos", severity="low", created_at=datetime.now(UTC), data={"product": "PAN-OS", "version": "11.1.2", "latest": "11.1.6"})
    assert notify.vendor_story(vuln, "de").ours and not notify.vendor_story(version, "de").ours
    assert personal.story(vuln, "de").ours == []


@pytest.mark.parametrize("lang", ["de", "en"])
def test_tlp_green_is_said_once_in_the_mail_body(lang):
    green = story(6, title="[TLP:GREEN] Example Firewall 7.2: Lücke", tlp="GREEN")
    line = notify.tlp_line(lang)
    for stories in ([green], [green, story(1)], [green, *(story(n) for n in range(1, notify.COMPACT_FROM))]):
        subject, text, html = notify.render_mail("R", stories, len(stories), lang)
        assert "[TLP:GREEN]" in subject  # the subject keeps it
        body = html.split("</head>", 1)[1]
        assert "[TLP:GREEN]" not in body and "Example Firewall 7.2: Lücke" in body and 'class="cn-tlp"' in body
        if len(stories) >= notify.COMPACT_FROM:  # the compact text line: the prefix is its one marker
            assert text.count("TLP:GREEN") == 1 and f"• [{notify.LABELS[lang]['sev']['medium']}] [TLP:GREEN] Example Firewall 7.2: Lücke" in text
        else:  # a card: the labelled line, the title without the prefix
            assert text.count("TLP:GREEN") == 1 and line in text and "\nExample Firewall 7.2: Lücke\n" in text
    # the chat cards as before: the title keeps the prefix, the card its TLP field – no third mention
    slack = str(notify.render_slack("R", [green], 1, lang)["blocks"])  # (the notification's fallback text aside)
    assert slack.count("[TLP:GREEN]") == 1 and slack.count(line) == 1
