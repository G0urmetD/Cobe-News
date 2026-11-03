"""A topic rule never floods (news_items.quiet_topics, news.loud_topic): an exploit list switched on (its first import,
the baseline), a list switched on again, a new topics rule version (TOPICS_V, the backfill) or a full recompute
(topics_again) give old stories a topic – shown and filtered, but no rule sends them for it. A topic gained by an
event of its own (a list's new entry, a new KEV entry, the details of a story arriving) is sent once. Desktop and Web
Push follow the arrival cursor: an old story is never theirs again either way."""

from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import func, select, text, update

from app import db, exploits, news, notify, notify_api, vendor
from app import settings as settings_store
from app.models import ExploitRef, NewsItem, NotifyDelivery, VendorKev
from test_exploits import ON, Net
from test_notify import SLACK, Hooks, _channel, _dispatch, _rule, _source, _stories


@pytest.fixture
def hooks(monkeypatch):
    h = Hooks()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(h.handler))
    return h


@pytest.fixture
def net(monkeypatch):
    n = Net()
    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(n.handler))
    vendor._last.clear()
    return n


def _lists(monkeypatch, **on: bool) -> None:
    monkeypatch.setitem(settings_store.DEFAULTS, "vendor", {**settings_store.DEFAULTS["vendor"], **{k: False for k in ON}, **{f"exploit_{k}": v for k, v in on.items()}})


async def _old_stories(src, cves: list[str], title: str = "Lücke {n} in Gateway"):  # noqa: ANN001, ANN202
    items = []
    for n, cve in enumerate(cves):
        items += await _stories(src, "high", title=title.format(n=n))
        async with db.session() as s:
            await s.execute(update(NewsItem).where(NewsItem.id == items[-1].id).values(cves=[cve]))
            await s.commit()
    return items


async def _delivered() -> int:
    async with db.session() as s:
        return int(await s.scalar(select(func.count()).select_from(NotifyDelivery)))


async def _backfill() -> None:
    async with db.session() as s:
        await news.backfill_topics(s)


async def _topics(iid) -> tuple[list, list]:  # noqa: ANN001
    async with db.session() as s:
        i = await s.get(NewsItem, iid, populate_existing=True)
        return list(i.topics or []), list(i.quiet_topics or [])


async def test_switching_on_an_exploit_list_sends_no_old_story(admin_client, hooks, net, monkeypatch):
    # the probe of the review: 25 stories, a rule asking for "Exploit veröffentlicht", Exploit-DB switched on – its first
    # import (the baseline) names their CVEs: every story gets the topic, none is sent for it
    _lists(monkeypatch)
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "PoC", [slack["id"]], severities=[], topics=["poc"])
    cves = [f"CVE-2020-{1000 + n}" for n in range(25)]
    items = await _old_stories(src, cves)
    await _dispatch()
    assert await _delivered() == 0
    url = exploits.SOURCES["exploitdb"].url
    net.bodies[url] = ("id,file,description,codes\n" + "".join(f"{n + 1},exploits/x/{n + 1}.txt,Exploit {n},{c}\n" for n, c in enumerate(cves))).encode()
    async with db.session() as s:
        cfg = await settings_store.get(s, "vendor")
        rev = cfg.get("rev")
    r = await admin_client.put("/api/admin/vendor", json={"enabled": True, "every_h": 6, "eol_every_h": 24, "exploit_exploitdb": True, "rev": rev})
    assert r.status_code == 200, r.text
    _lists(monkeypatch, exploitdb=True)
    async with db.session() as s:
        s.add(VendorKev(cve="CVE-2019-0001", vendor="x", product="y", name="z", date_added=datetime.now(UTC).date().isoformat()))  # the news want the lists
        await s.commit()
    monkeypatch.setattr(exploits, "wanted", _yes)
    async with db.session() as s:
        assert await exploits.sync_all(s) == {"exploit:exploitdb": 25}
    await _backfill()
    assert [await _topics(i.id) for i in items] == [(["poc"], ["poc"])] * len(items)  # shown – quietly
    await _dispatch()
    assert await _delivered() == 0 and hooks.to("hooks.slack.com") == []
    # the dry run (the same matcher) agrees
    notify_api._dry_at.clear()
    r = await admin_client.post("/api/admin/notify/rules/dry-run", json={"kinds": ["news"], "topics": ["poc"], "days": 1})
    assert r.status_code == 200, r.text
    assert r.json()["count"] == 0
    # a list's new entry for one of them is no news for that story (it has the topic) – a new entry for a CVE an old
    # story names that had none yet is: sent once
    other = (await _old_stories(src, ["CVE-2021-7777"], title="Noch eine Lücke {n}"))[0]
    await _dispatch()
    assert await _delivered() == 0
    net.bodies[url] += b"999,exploits/x/999.txt,Exploit new,CVE-2021-7777\n"
    net.etag[url] = "v2"
    async with db.session() as s:
        assert await exploits.sync_all(s, force=True) == {"exploit:exploitdb": 1}
    assert await _topics(other.id) == (["poc"], [])
    await _dispatch()
    assert await _delivered() == 1
    await _dispatch()
    assert await _delivered() == 1  # once


async def _yes(db_):  # noqa: ANN001
    return True


async def test_a_new_rule_version_or_a_full_recompute_sends_nothing(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "PoC", [slack["id"]], severities=[], topics=["poc", "zeroday"])
    # stored with the topics of an older rule version: none
    items = await _stories(src, "high", "high", title="PoC exploit released for gateway flaw {n}")
    async with db.session() as s:
        await s.execute(update(NewsItem).values(topics=[]))
        await s.execute(text("INSERT INTO counters (name, value) VALUES ('news_topics_v', 1) ON CONFLICT (name) DO UPDATE SET value = 1"))
        await s.commit()
    await _dispatch()
    assert await _delivered() == 0
    await _backfill()  # the new version: every story again
    assert [await _topics(i.id) for i in items] == [(["poc"], ["poc"])] * len(items)
    await _dispatch()
    assert await _delivered() == 0
    # topics_again (the KEV's first fetch …): the same
    async with db.session() as s:
        await s.execute(update(NewsItem).values(topics=[], quiet_topics=[]))
        await news.topics_again(s)
        await s.commit()
    await _backfill()
    await _dispatch()
    assert await _delivered() == 0
    # an event of its own afterwards – the title updated with a new topic: sent, once
    async with db.session() as s:
        await s.execute(update(NewsItem).where(NewsItem.id == items[0].id).values(title="Zero-day: PoC exploit released for gateway flaw"))
        await news.retopic(s, NewsItem.id == items[0].id)
        await s.commit()
    assert await _topics(items[0].id) == (["zeroday", "exploited", "poc"], ["poc"])  # the zero-day is news, the PoC stays quiet
    await _dispatch()
    assert await _delivered() == 1


async def test_a_new_kev_entry_still_sends_an_older_story(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Exploited", [slack["id"]], severities=[], topics=["exploited"])
    (item,) = await _old_stories(src, ["CVE-2024-5555"])
    await _dispatch()
    assert await _delivered() == 0
    async with db.session() as s:
        s.add(VendorKev(cve="CVE-2024-5555", vendor="x", product="y", name="z", date_added=datetime.now(UTC).date().isoformat()))
        await s.flush()
        await news.retopic_cves(s, ["CVE-2024-5555"])  # vendor.kev_store: the newly listed CVEs
        await s.commit()
    assert await _topics(item.id) == (["exploited"], [])
    await _dispatch()
    assert await _delivered() == 1


async def test_poc_through_a_baseline_entry_only_is_quiet_also_in_an_event(admin_client, hooks, monkeypatch):
    # the story's teaser changes (an event) – but its "poc" rests only on a list's baseline entry: quiet
    _lists(monkeypatch, nuclei=True)
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "PoC", [slack["id"]], severities=[], topics=["poc"])
    (item,) = await _old_stories(src, ["CVE-2024-6666"])
    async with db.session() as s:
        s.add(ExploitRef(cve="CVE-2024-6666", source="nuclei", url="https://github.com/projectdiscovery/nuclei-templates/blob/main/x.yaml", first_seen=datetime.now(UTC), baseline=True))
        await s.commit()
    exploits.invalidate()
    async with db.session() as s:
        await news.retopic(s, NewsItem.id == item.id)
        await s.commit()
    assert await _topics(item.id) == (["poc"], ["poc"])
    await _dispatch()
    assert await _delivered() == 0
    # the same entry no baseline: news
    async with db.session() as s:
        await s.execute(update(NewsItem).where(NewsItem.id == item.id).values(topics=[], quiet_topics=[]))
        await s.execute(update(ExploitRef).values(baseline=False))
        await s.commit()
    exploits.invalidate()
    async with db.session() as s:
        await news.retopic(s, NewsItem.id == item.id)
        await s.commit()
    assert await _topics(item.id) == (["poc"], [])
    await _dispatch()
    assert await _delivered() == 1


def test_quiet_after():
    q = news.quiet_after
    assert q([], ["poc"], [], bulk=True) == ["poc"]
    assert q([], ["poc"], [], bulk=False) == []
    assert q([], ["poc"], [], bulk=False, baseline_poc=True) == ["poc"]
    assert q(["poc"], [], ["poc"], bulk=False) == []  # lost: no longer quiet
    assert q(["poc"], ["poc", "ot"], ["poc"], bulk=False) == ["poc"]  # stays quiet, "ot" is news
    assert q(["ot"], ["ot", "poc"], [], bulk=True) == ["poc"]  # what it had stays loud
