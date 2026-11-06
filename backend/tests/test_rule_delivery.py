# ruff: noqa: F811 - fixtures imported from test_news_store / test_notify are used by name
"""Notification rules, 0.1.53: what matches is sent, and old stories are not.

- a source switched on after weeks lists older stories others stored meanwhile: shown under its name, but a rule
  limited to it is not sent them (news_item_sources.fresh) – nor does its rating raise them,
- the same story from a further source (by URL or title) rated higher raises it (only rises), as an update by its own
  source and the CVE peers did,
- a rule widened before a story changed (rated higher, carried fresh by a further source, a topic gained loudly) judges
  it by the dimension that changed (news_items.changes, news_item_sources.carried_at) – an unrelated change sends nothing,
- "from now on" by arrival number: a story of a fetch under way when the rule was switched on (its fetched_at earlier,
  visible only after) is sent – also to a channel added later."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text, update
from test_news_store import _e, _items, _src, _store, builtins_off  # noqa: F401 - fixture
from test_notify import DISCORD, SLACK, _channel, _dispatch, _rule, hooks  # noqa: F401 - fixture

from app import db, news, notify
from app.models import NewsItem, NewsItemSource, NotifyRule, NotifyRuleChannel

MEDIUM = "Some text"  # news.rate: medium (a patch story)
HIGH = "The flaw has a CVSS score of 7.5."
CRITICAL = "The flaw has a CVSS score of 9.8."


async def _by_url(url_part: str) -> NewsItem:
    return next(i for i in await _items() if url_part in i.url)


async def _fresh_of(item_id: uuid.UUID) -> dict[uuid.UUID, bool]:
    async with db.session() as s:
        return dict((await s.execute(select(NewsItemSource.source_id, NewsItemSource.fresh).where(NewsItemSource.item_id == item_id))).all())


async def _pending(rule: NotifyRule) -> list[str]:
    async with db.session() as s:
        return sorted(i.url for i, _ in await notify.pending(s, rule, uuid.uuid4(), rule.active_since))


async def _stored_rule(**kw) -> NotifyRule:  # noqa: ANN003
    async with db.session() as s:
        rule = NotifyRule(**{"name": "r", "severities": [], "sources": [], "kinds": ["news"], "active_since": datetime.now(UTC) - timedelta(days=30), **kw})
        s.add(rule)
        await s.commit()
        return rule


# ---------------------------------------------------------------- a carry of a source switched on later


async def test_a_source_switched_on_later_brings_no_summary_of_older_stories(reader_client):
    a, b = await _src("feed-a"), await _src("feed-b", primed=False)
    rule = await _stored_rule(sources=[str(b)])
    # A stored two stories 20 days ago (fresh then) – B was off
    await _store(a, [_e("https://a.example.org/old-1", "Old story one about patches", summary=MEDIUM), _e("https://a.example.org/old-2", "Old story two", summary=MEDIUM)])
    async with db.session() as s:
        await s.execute(text("UPDATE news_items SET published_at = published_at - interval '20 days', fetched_at = fetched_at - interval '20 days'"))
        await s.commit()
    await _store(a, [_e("https://a.example.org/new", "A story of today", summary=MEDIUM)])
    # B is switched on: its first fetch lists all three – the old ones with their old dates, one of them rated critical
    old = datetime.now(UTC) - timedelta(days=20)
    await _store(
        b,
        [
            _e("https://a.example.org/old-1", "Old story one about patches", summary=CRITICAL, date=old),
            _e("https://a.example.org/old-2", "Old story two", summary=MEDIUM, date=old),
            _e("https://a.example.org/new", "A story of today", summary=MEDIUM),
        ],
    )
    # the rule limited to B: only what B carried fresh (used to be all three – a summary of 20-day-old stories)
    assert await _pending(rule) == ["https://a.example.org/new"]
    one, new = await _by_url("old-1"), await _by_url("/new")
    assert await _fresh_of(one.id) == {b: False} and await _fresh_of(new.id) == {b: True}
    assert one.severity == "medium" and one.changes == {}  # a backlog carry's rating raises nothing
    # the list shows every carry under B
    got = (await reader_client.get("/api/news", params={"source": str(b), "state": "all"})).json()
    assert len(got["items"]) == 3


# ---------------------------------------------------------------- a further source's higher rating


async def test_a_further_source_rating_the_same_story_higher_raises_it():
    a, b = await _src("feed-a"), await _src("feed-b")
    await _store(a, [_e("https://a.example.org/x", "Example story about patches", summary=MEDIUM)])
    await _store(a, [_e("https://a.example.org/y", "Another example story about patches", summary=MEDIUM)])
    rule = await _stored_rule(sources=[str(b)], severities=["critical", "high"])
    assert await _pending(rule) == []
    # by URL: B's article of the same address says CVSS 9.8; by title: B's own address, the same title, CVSS 7.5
    await _store(b, [_e("https://a.example.org/x", "Example story about patches", summary=CRITICAL)])
    await _store(b, [_e("https://b.example.org/other", "Another example story about patches", summary=HIGH)])
    x, y = await _by_url("/x"), await _by_url("/y")
    assert (x.severity, x.reasons[0]) == ("critical", {"kind": "cvss", "value": "9.8"}) and [w for _, w in x.changes["sev"]] == ["medium"]
    assert y.severity == "high" and y.source_id == a
    assert await _pending(rule) == ["https://a.example.org/x", "https://a.example.org/y"]
    # only rises: a later lower rating changes nothing
    await _store(b, [_e("https://a.example.org/x", "Example story about patches", summary=MEDIUM)])
    assert (await _by_url("/x")).severity == "critical"


# ---------------------------------------------------------------- widened before the story changed


async def test_a_story_rated_higher_after_the_widening_comes(admin_client, hooks):
    a = await _src("feed-a")
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Wichtig", [slack["id"]], severities=["critical"])
    await _store(a, [_e("https://a.example.org/x", "Example story about patches", summary=MEDIUM)])
    assert await _dispatch() == {}
    body = {"name": "Wichtig", "channels": [slack["id"]], "severities": ["critical", "high"]}
    assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body)).status_code == 200
    assert await _dispatch() == {}  # medium: not for this rule
    # an hour later its source updates it: CVSS 7.5 – high. Without the widening it would have come at the moment it
    # became critical; with it, it used to never come (it arrived before the widening and was no critical then)
    await _store(a, [_e("https://a.example.org/x", "[UPDATE] Example story about patches", summary=HIGH)])
    assert (await _by_url("/x")).severity == "high"
    assert await _dispatch() == {"Slack": 1}
    assert await _dispatch() == {}


async def test_a_story_carried_fresh_by_a_source_added_in_the_widening_comes(admin_client, hooks):
    a, b, c = await _src("feed-a"), await _src("feed-b"), await _src("feed-c")
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Quellen", [slack["id"]], severities=[], sources=[str(a)])
    await _store(c, [_e("https://c.example.org/x", "Example story about patches", summary=MEDIUM)])
    body = {"name": "Quellen", "channels": [slack["id"]], "severities": [], "sources": [str(a), str(b)]}
    assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body)).status_code == 200
    assert await _dispatch() == {}  # C's story, from before the widening: no
    await _store(b, [_e("https://c.example.org/x", "Example story about patches", summary=MEDIUM)])  # B carries it now
    assert await _dispatch() == {"Slack": 1}


async def test_a_loud_topic_marks_the_story_changed_a_quiet_one_does_not():
    a = await _src("feed-a")
    await _store(a, [_e("https://a.example.org/x", "Example story about patches", summary=MEDIUM), _e("https://a.example.org/y", "Another story", summary=MEDIUM)])
    x, y = await _by_url("/x"), await _by_url("/y")
    async with db.session() as s:
        title = "Example story about patches: actively exploited"
        await s.execute(update(NewsItem).where(NewsItem.id.in_([x.id, y.id])).values(title=title))
        await news.retopic(s, NewsItem.id == x.id)  # an event of its own: loud
        await news.retopic(s, NewsItem.id == y.id, bulk=True)  # the full recompute: quiet
        await s.commit()
    x, y = await _by_url("/x"), await _by_url("/y")
    assert "exploited" in x.topics and set(x.changes["topics"]) == {"exploited"}
    assert "exploited" in y.topics and y.quiet_topics == ["exploited"] and y.changes == {}


# ---------------------------------------------------------------- "from now on" by arrival number


async def _in_flight(src_id: uuid.UUID, fetched_at: datetime, sev: str = "high") -> NewsItem:
    """A story of a fetch that began at `fetched_at` and commits now – its arrival number is taken now."""
    async with db.session() as s:
        key = uuid.uuid4().hex
        i = NewsItem(
            source_id=src_id, url=f"https://a.example.org/{key}", url_key=key, title=f"Story {key}", title_key=key, published_at=fetched_at, fetched_at=fetched_at,
            severity=sev, seq=await news.next_seq(s),
        )
        s.add(i)
        await s.commit()
        return i


async def test_a_story_of_a_fetch_under_way_when_the_rule_was_switched_on_comes(admin_client, hooks):
    a = await _src("feed-a")
    await _in_flight(a, datetime.now(UTC) - timedelta(minutes=5))  # before the rule: no
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    async with db.session() as s:
        r = await s.get(NotifyRule, uuid.UUID(rule["id"]))
        top = await news.last_seq(s)
    # the fetch began two seconds before the rule was saved and commits after it
    await _in_flight(a, r.active_since - timedelta(seconds=2))
    assert await _dispatch() == {"Slack": 1}  # used to be never: fetched_at before active_since
    assert r.active_seq == top
    # a channel added later: the same by its own number
    discord = await _channel(admin_client, name="Discord", type="discord", url=DISCORD)
    body = {"name": "Alles", "channels": [slack["id"], discord["id"]], "severities": []}
    assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body)).status_code == 200
    async with db.session() as s:
        link = await s.get(NotifyRuleChannel, (uuid.UUID(rule["id"]), uuid.UUID(discord["id"])))
        assert link.added_seq is not None
    await _in_flight(a, link.added_at - timedelta(seconds=2))
    assert await _dispatch() == {"Discord": 1, "Slack": 1}
    assert await _dispatch() == {}


async def test_a_rule_from_before_the_numbers_keeps_its_time():
    a = await _src("feed-a")
    rule = await _stored_rule()  # active_seq empty (a rule of 0.1.52)
    since = rule.active_since
    await _in_flight(a, since - timedelta(seconds=2))
    late = await _in_flight(a, since + timedelta(seconds=2))
    async with db.session() as s:
        got = await notify.pending(s, rule, uuid.uuid4(), since, (since, None))
    assert [i.id for i, _ in got] == [late.id]
