# ruff: noqa: F811 - fixtures imported from test_news_store / test_notify are used by name
"""A widened rule and a story that changes after the widening, per dimension (news_items.changes,
news_item_sources.carried_at – notify._earlier_news): the story comes only when the dimension in which it newly matched
by the widening is the one that changed, so that only then did it match the rule as it is now. A change of another
dimension – a fresh carry, its details arriving, an unrelated topic, an "[UPDATE]" of a title that named the word
already – sends nothing: the story matched the wider rule at the widening already, and the widening sends no older
stories. (The changes that do send – rated higher, carried fresh by an added source, a loud topic – are in
test_rule_delivery.py.)"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from test_news_store import _e, _items, _src, _store, builtins_off  # noqa: F401 - fixture
from test_notify import SLACK, _channel, _dispatch, _rule, hooks  # noqa: F401 - fixture
from test_rule_filters import _news

from app import db, news, notify, systems
from app.models import NewsItem, NewsSource, NotifyRule

HIGH = "The flaw has a CVSS score of 7.5."
MEDIUM = "Some text"


async def _widen(c, rule: dict, **body) -> None:  # noqa: ANN001
    r = await c.put(f"/api/admin/notify/rules/{rule['id']}", json={"name": rule["name"], "channels": rule["channels"], **body})
    assert r.status_code == 200, r.text


async def _sent(hooks) -> list[str]:  # noqa: ANN001
    """The titles of the stories sent so far (Slack bodies)."""
    async with db.session() as s:
        titles = [i.title for i in await s.scalars(select(NewsItem))]
    bodies = [str(hooks.body(r)) for r in hooks.to("hooks.slack.com")]
    return sorted(t for t in titles if any(t in b for b in bodies))


async def _source(key: str = "feed-x") -> NewsSource:
    async with db.session() as s:
        await news.ensure_sources(s)
        src = NewsSource(key=key, name=f"Feed {key}", url=f"https://news.example.org/{key}.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.commit()
        return src


# ---------------------------------------------------------------- severities widened, another dimension changes


async def test_a_fresh_carry_after_a_severity_widening_sends_no_older_story(admin_client, hooks):
    a, c = await _src("feed-a"), await _src("feed-c")
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Wichtig", [slack["id"]], severities=["critical"])
    await _store(a, [_e("https://a.example.org/x", "Example story about patches", summary=HIGH)])
    await _widen(admin_client, rule, severities=["critical", "high"])
    assert await _dispatch() == {}  # high, from before the widening
    # another source carries it fresh, rated the same: nothing a rule asks for changed
    await _store(c, [_e("https://a.example.org/x", "Example story about patches", summary=HIGH)])
    assert await _dispatch() == {}
    # rated critical later: it would have come without the widening as well
    await _store(a, [_e("https://a.example.org/x", "Example story about patches", summary="The flaw has a CVSS score of 9.8.")])
    assert await _dispatch() == {"Slack": 1}


async def test_details_after_a_severity_widening_send_no_older_story(admin_client, hooks):
    a = await _src("feed-a")
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Wichtig", [slack["id"]], severities=["critical"])
    await _store(a, [_e("https://a.example.org/y", "Example story about patches", summary=HIGH)])
    await _widen(admin_client, rule, severities=["critical", "high"])
    assert await _dispatch() == {}
    i = next(x for x in await _items() if "/y" in x.url)
    async with db.session() as s:
        assert await systems.set_exact(s, i.id, ["panos"], quiet=False)  # its details arrive: loud
        await s.commit()
    assert await _dispatch() == {}
    async with db.session() as s:
        assert set((await s.get(NewsItem, i.id)).changes["systems"]) == {"panos"}


# ---------------------------------------------------------------- the widened dimension itself changes


async def test_systems_widened_a_story_named_before_stays_one_matching_only_now_comes(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Systeme", [slack["id"]], severities=[], systems=[{"product": "panos"}])
    named = await _news(src, "FortiOS: Lücke in SSL-VPN")  # names FortiOS from the start
    later = await _news(src, "Neue Lücke in einer Firewall")  # names nothing
    await _widen(admin_client, rule, severities=[], systems=[{"product": "panos"}, {"product": "fortios"}])
    assert await _dispatch() == {}
    async with db.session() as s:
        # both get their details: FortiOS – loud, after the widening
        for iid in (named, later):
            assert await systems.set_exact(s, iid, ["fortios"], quiet=False)
        await s.commit()
    # the one that named FortiOS matched the wider rule at the widening already: not sent; the other matches only now
    assert await _dispatch() == {"Slack": 1}
    assert await _sent(hooks) == ["Neue Lücke in einer Firewall"]


async def test_topics_widened_an_unrelated_topic_sends_nothing_a_wanted_one_does(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Themen", [slack["id"]], severities=[], topics=["exploited"])
    had = await _news(src, "Ransomware gang strikes again")
    gains = await _news(src, "A flaw in a router")
    async with db.session() as s:
        await s.execute(update(NewsItem).where(NewsItem.id == had).values(topics=["ransomware"]))
        await s.commit()
    await _widen(admin_client, rule, severities=[], topics=["exploited", "ransomware"])
    assert await _dispatch() == {}
    now = datetime.now(UTC)
    async with db.session() as s:
        # loudly, after the widening: the first a topic the rule does not ask for, the second one it does
        a, b = await s.get(NewsItem, had), await s.get(NewsItem, gains)
        a.topics, a.changes = ["ransomware", "poc"], news.noted(a.changes, now, topics=["poc"])
        b.topics, b.changes = ["ransomware"], news.noted(b.changes, now, topics=["ransomware"])
        await s.commit()
    notify.changed()
    assert await _dispatch() == {"Slack": 1}
    assert await _sent(hooks) == ["A flaw in a router"]


async def test_keywords_widened_an_update_of_a_title_that_named_the_word_sends_nothing(admin_client, hooks):
    a = await _src("feed-a")
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Wörter", [slack["id"]], severities=[], keywords=["PAN-OS"])
    await _store(a, [_e("https://a.example.org/x", "Fortinet patches a flaw", summary=MEDIUM), _e("https://a.example.org/y", "A vendor patches a flaw", summary=MEDIUM)])
    await _widen(admin_client, rule, severities=[], keywords=["PAN-OS", "Fortinet"])
    assert await _dispatch() == {}
    # the source updates both: the first named Fortinet already, the second names it only now
    await _store(a, [_e("https://a.example.org/x", "[UPDATE] Fortinet patches a flaw", summary=MEDIUM), _e("https://a.example.org/y", "Fortinet: a vendor patches a flaw", summary=MEDIUM)])
    x = next(i for i in await _items() if i.url.endswith("/x"))
    assert len(x.changes["text"]) == 1 and x.changes["text"][0][1].startswith("fortinet patches a flaw")  # the text before
    assert await _dispatch() == {"Slack": 1}
    assert await _sent(hooks) == ["Fortinet: a vendor patches a flaw"]


async def test_sources_widened_a_carry_by_a_source_the_rule_does_not_name_sends_nothing(admin_client, hooks):
    a, b, c, d = await _src("feed-a"), await _src("feed-b"), await _src("feed-c"), await _src("feed-d")
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Quellen", [slack["id"]], severities=[], sources=[str(a)])
    # C's story, carried by B before the widening
    await _store(c, [_e("https://c.example.org/x", "Example story about patches", summary=MEDIUM)])
    await _store(b, [_e("https://c.example.org/x", "Example story about patches", summary=MEDIUM)])
    await _widen(admin_client, rule, severities=[], sources=[str(a), str(b)])
    assert await _dispatch() == {}  # B carried it at the widening already
    await _store(d, [_e("https://c.example.org/x", "Example story about patches", summary=MEDIUM)])  # D: not the rule's
    assert await _dispatch() == {}


async def test_exclusions_widened_a_story_kept_away_stays_away_when_its_title_still_has_the_word(admin_client, hooks):
    a = await _src("feed-a")
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Ohne", [slack["id"]], severities=[], exclude=["webinar", "promo"])
    await _store(a, [_e("https://a.example.org/x", "Join our webinar on patches", summary=MEDIUM)])
    assert await _dispatch() == {}
    await _widen(admin_client, rule, severities=[], exclude=["promo"])
    await _store(a, [_e("https://a.example.org/x", "[UPDATE] Join our webinar on patches", summary=MEDIUM)])
    assert await _dispatch() == {}  # kept away before, and the change did not make it match now


# ---------------------------------------------------------------- two filters of before merged


def test_merging_a_filter_of_words_alone_keeps_vendor_news_unlimited():
    base = {"severities": None, "sources": None, "topics": None, "kinds": ["news", "vendor_vuln"], "teams": None, "exclude": None}
    rule = NotifyRule(earlier=[], active_since=datetime.now(UTC) - timedelta(days=1))
    at = datetime.now(UTC)
    filters = [{**base, "systems": None, "keywords": ["bleed"]}, {**base, "systems": None, "keywords": None}] + [base] * 9
    for n, f in enumerate(filters):
        notify.widened(rule, f, n, at + timedelta(seconds=n))
    first = rule.earlier[0]
    # news: only "bleed"; Vendor News: every product, as neither filter limited the events (was: [] – no event at all)
    assert first["concern"] == [[], ["bleed"]] and first["systems"] is None
    assert notify._concern(first) == (set(), {"bleed"})
    from sqlalchemy.dialects import postgresql

    sql = " ".join(str(c.compile(dialect=postgresql.dialect())) for c in notify._earlier_vendor(rule))
    assert "false" not in sql.lower()


async def test_a_rule_widened_twice_judges_by_each_widening(admin_client, hooks):
    a = await _src("feed-a")
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Wichtig", [slack["id"]], severities=["critical"])
    await _store(a, [_e("https://a.example.org/x", "Example story about patches", summary=MEDIUM)])
    await _widen(admin_client, rule, severities=["critical", "high"])
    await _widen(admin_client, rule, severities=["critical", "high", "medium"])
    assert await _dispatch() == {}  # medium from before both
    await _store(a, [_e("https://a.example.org/x", "Example story about patches", summary=HIGH)])  # rated high now
    assert await _dispatch() == {"Slack": 1}
    async with db.session() as s:
        assert len((await s.get(NotifyRule, uuid.UUID(rule["id"]))).earlier) == 2
