"""The notification round: incremental (nothing new – nothing scanned), each channel's outcome on its own (a story, rule
or channel deleted meanwhile never undoes the others), a widened rule starts from then, stable webhook delivery ids,
a stale channel error cleared, parallel edits refused as stale (channels, rules, mail server, news and Vendor News
settings). Every HTTP channel against a MockTransport – never the real services."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import delete, select, text, update
from test_notify import DISCORD, HOOK, SLACK, Hooks, _channel, _channels, _dispatch, _rule, _source, _stories, _unpause

from app import db, notify, notify_api
from app.models import NewsItem, NotifyChannel, NotifyDelivery, NotifyRule, VendorEvent
from tests.conftest import execute_elsewhere


@pytest.fixture
def hooks(monkeypatch):
    h = Hooks()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(h.handler))
    return h


@pytest.fixture
def scans(monkeypatch):
    """Which channels a round looked at (channel_pending – the expensive part)."""
    seen: list[str] = []
    real = notify.channel_pending

    async def counting(s, ch, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        seen.append(ch.name)
        return await real(s, ch, *a, **kw)

    monkeypatch.setattr(notify, "channel_pending", counting)
    return seen


async def _sent(channel_id: str) -> set[uuid.UUID]:
    async with db.session() as s:
        return set(await s.scalars(select(NotifyDelivery.item_id).where(NotifyDelivery.channel_id == uuid.UUID(channel_id))))


# ---------------------------------------------------------------- C: incremental


async def test_nothing_new_nothing_scanned_but_retries_and_changes_are(admin_client, hooks, scans, monkeypatch):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    discord = await _channel(admin_client, name="Discord", type="discord", url=DISCORD)
    rule = await _rule(admin_client, "Alles", [slack["id"], discord["id"]], severities=[])
    await _stories(src, "high")
    assert await _dispatch() == {"Discord": 1, "Slack": 1} and sorted(scans) == ["Discord", "Slack"]
    scans.clear()
    assert await _dispatch() == {} and scans == []  # nothing arrived, nothing changed: no scan at all
    # a failing channel: its retry is looked at when it is due – and only that channel
    hooks.queue["discord.com"] = [httpx.Response(500)]
    await _stories(src, "high")
    assert await _dispatch() == {"Slack": 1}
    scans.clear()
    assert await _dispatch() == {} and scans == []  # Discord pauses, nothing new
    async with db.session() as s:
        await s.execute(update(NotifyChannel).where(NotifyChannel.id == uuid.UUID(discord["id"])).values(next_try_at=datetime.now(UTC) - timedelta(seconds=1)))
        await s.commit()
    assert await _dispatch() == {"Discord": 1} and scans == ["Discord"]
    scans.clear()
    # a rule changed: everything again (a channel added to it, switched on …)
    body = {"name": "Alles", "channels": [slack["id"], discord["id"]], "severities": ["critical"]}
    assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body)).status_code == 200
    assert await _dispatch() == {} and sorted(scans) == ["Discord", "Slack"]
    scans.clear()
    assert await _dispatch() == {} and scans == []
    # a Vendor News event is something new as well
    async with db.session() as s:
        s.add(VendorEvent(key=f"vuln:x:{uuid.uuid4()}", kind="vuln", product="x", severity="critical", data={}, baseline=False))
        await s.commit()
    assert await _dispatch() == {} and sorted(scans) == ["Discord", "Slack"]
    scans.clear()
    # and once in a while a full look anyway (a story rated higher or carried by another source since)
    monkeypatch.setattr(notify._seen, "full_at", notify._seen.full_at - notify.FULL_EVERY - 1)
    assert await _dispatch() == {} and sorted(scans) == ["Discord", "Slack"]


async def test_a_story_rated_higher_comes_with_the_next_full_look(admin_client, hooks, monkeypatch):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Kritisch", [slack["id"]], severities=["critical"])
    (item,) = await _stories(src, "high")
    assert await _dispatch() == {}
    async with db.session() as s:  # "[UPDATE] … wird aktiv ausgenutzt" – the story itself, no new arrival number
        await s.execute(update(NewsItem).where(NewsItem.id == item.id).values(severity="critical"))
        await s.commit()
    assert await _dispatch() == {}  # nothing new by the marks
    monkeypatch.setattr(notify._seen, "full_at", notify._seen.full_at - notify.FULL_EVERY - 1)
    assert await _dispatch() == {"Slack": 1}


async def test_a_due_retry_with_nothing_left_shows_no_next_try(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    (item,) = await _stories(src, "high")
    hooks.queue["hooks.slack.com"] = [httpx.Response(500)]
    assert await _dispatch() == {}
    assert (await _channels(admin_client))["Slack"]["next_try_at"] is not None
    async with db.session() as s:  # the story is gone meanwhile (retention)
        await s.execute(delete(NewsItem).where(NewsItem.id == item.id))
        await s.commit()
    await _unpause()
    assert await _dispatch() == {}
    c = (await _channels(admin_client))["Slack"]
    assert c["next_try_at"] is None and c["last_error"]  # no retry pending – the last error stays until something works


# ---------------------------------------------------------------- A-M2: each channel on its own


async def test_a_story_and_a_channel_deleted_while_sending_undo_nothing(admin_client, monkeypatch):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    discord = await _channel(admin_client, name="Discord", type="discord", url=DISCORD)
    hook = await _channel(admin_client, name="n8n", type="webhook", url=HOOK)
    await _rule(admin_client, "Alles", [slack["id"], discord["id"], hook["id"]], severities=[])
    one, two = await _stories(src, "high", "high")
    calls: list[str] = []

    async def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.host)
        if req.url.host == "hooks.slack.com" and len([c for c in calls if c == "hooks.slack.com"]) == 1:
            # while the first message goes out: the second story is pruned, the Discord channel deleted
            async with db.session() as s:
                await s.execute(delete(NewsItem).where(NewsItem.id == two.id))
                await s.execute(delete(NotifyChannel).where(NotifyChannel.id == uuid.UUID(discord["id"])))
                await s.commit()
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(notify, "transport", httpx.MockTransport(handler))
    out = await _dispatch()  # used to roll the whole round back (foreign key / stale channel) – and send it all again
    assert out["Slack"] == 2 and out["n8n"] == 2
    assert await _sent(slack["id"]) == {one.id} and await _sent(hook["id"]) == {one.id}  # the deleted story: simply not marked
    async with db.session() as s:
        assert await s.get(NotifyChannel, uuid.UUID(discord["id"])) is None
        assert (await s.get(NotifyChannel, uuid.UUID(slack["id"]))).last_sent_at is not None
    calls.clear()
    assert await _dispatch() == {} and calls == []  # nothing again


async def test_one_channels_failing_write_keeps_the_others(admin_client, hooks, monkeypatch):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    discord = await _channel(admin_client, name="Discord", type="discord", url=DISCORD)
    await _rule(admin_client, "Alles", [slack["id"], discord["id"]], severities=[])
    (item,) = await _stories(src, "high")
    real = notify._marked

    def broken(channel_id, items, at):  # noqa: ANN001
        out = real(channel_id, items, at)
        return [*out, text("INSERT INTO no_such_table VALUES (1)")] if str(channel_id) == discord["id"] else out  # the write fails

    monkeypatch.setattr(notify, "_marked", broken)
    assert await _dispatch() == {"Discord": 1, "Slack": 1}
    assert await _sent(slack["id"]) == {item.id} and await _sent(discord["id"]) == set()  # at least once: Discord gets it again


# ---------------------------------------------------------------- A-L: a widened rule starts from then


async def test_a_widened_rule_sends_what_newly_matches_only_from_then_on(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Kritisch", [slack["id"]], severities=["critical"])
    hooks.queue["hooks.slack.com"] = [httpx.Response(500)]
    (crit,) = await _stories(src, "critical")
    assert await _dispatch() == {}  # failed: the critical story waits for the retry
    await _stories(src, *["high"] * 5, "medium")  # arrived under the old filter – not for this rule
    body = {"name": "Kritisch", "channels": [slack["id"]], "severities": ["critical", "high", "medium"]}
    r = await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body)
    assert r.status_code == 200
    await _unpause()
    assert await _dispatch() == {"Slack": 1}  # what matched before still comes – not the older high/medium ones
    assert await _sent(slack["id"]) == {crit.id}
    (new,) = await _stories(src, "high")
    assert await _dispatch() == {"Slack": 1} and new.id in await _sent(slack["id"])
    # all severities, another time: still nothing older
    body["severities"] = []
    assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body)).status_code == 200
    await _stories(src, "low")
    assert await _dispatch() == {"Slack": 1}
    async with db.session() as s:
        r = await s.get(NotifyRule, uuid.UUID(rule["id"]))
        assert [x["severities"] for x in r.earlier] == [["critical"], ["critical", "high", "medium"]]
    # narrowing is no widening; a rule switched off and on starts anew (nothing kept)
    body["severities"] = ["critical"]
    assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body)).status_code == 200
    async with db.session() as s:
        assert len((await s.get(NotifyRule, uuid.UUID(rule["id"]))).earlier) == 2
    for on in (False, True):
        assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json={**body, "enabled": on})).status_code == 200
    async with db.session() as s:
        assert (await s.get(NotifyRule, uuid.UUID(rule["id"]))).earlier == []


async def test_widening_sources_and_kinds(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Eine Quelle", [slack["id"]], severities=[], sources=[str(uuid.uuid4())])
    await _stories(src, "critical")  # not of the rule's source
    async with db.session() as s:
        s.add(VendorEvent(key=f"vuln:x:{uuid.uuid4()}", kind="vuln", product="x", severity="critical", data={"product": "X"}, baseline=False))
        await s.commit()
    assert await _dispatch() == {}
    body = {"name": "Eine Quelle", "channels": [slack["id"]], "severities": [], "sources": [], "kinds": ["news", "vendor_vuln"]}
    assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body)).status_code == 200
    assert await _dispatch() == {}  # neither the older story of another source nor the older vulnerability
    await _stories(src, "critical")
    async with db.session() as s:
        s.add(VendorEvent(key=f"vuln:x:{uuid.uuid4()}", kind="vuln", product="x", severity="critical", data={"product": "X"}, baseline=False))
        await s.commit()
    assert await _dispatch() == {"Slack": 2}


def test_widening_rules_and_the_cap():
    f = {"severities": ["critical"], "sources": None, "kinds": ["news"]}
    assert notify.widens(f, {**f, "severities": ["critical", "high"]}) and notify.widens(f, {**f, "severities": None})
    assert notify.widens(f, {**f, "kinds": ["news", "vendor_vuln"]}) and not notify.widens(f, {**f, "kinds": ["news"]})
    assert not notify.widens(f, {**f, "sources": ["a"]}) and notify.widens({**f, "sources": ["a"]}, {**f, "sources": ["a", "b"]})
    assert notify.widens({**f, "sources": ["a"]}, f) and not notify.widens(f, {**f, "severities": []})
    rule = NotifyRule(name="x", severities=[], sources=[], kinds=["news"], earlier=[], active_since=datetime.now(UTC) - timedelta(days=1))
    sevs = ["critical", "high", "medium", "low", "info"]
    for n in range(notify.EARLIER_MAX + 3):
        notify.widened(rule, {"severities": sevs[: 1 + n % 5], "sources": None, "kinds": ["news", "vendor_vuln"]}, n, datetime.now(UTC))
    assert len(rule.earlier) == notify.EARLIER_MAX
    first = rule.earlier[0]  # the oldest merged: stricter (the intersection), up to the later number
    assert first["severities"] == ["critical"] and first["seq"] == 3 and first["kinds"] == ["news", "vendor_vuln"]


# ---------------------------------------------------------------- delivery id, stale errors


async def test_webhook_delivery_id_stays_the_same_for_the_same_message(admin_client, hooks):
    src = await _source()
    ch = await _channel(admin_client, name="n8n", type="webhook", url=HOOK)
    await _rule(admin_client, "Alles", [ch["id"]], severities=[])
    await _stories(src, "high")
    hooks.queue["n8n.corp.example"] = [httpx.Response(503)]
    assert await _dispatch() == {}
    await _unpause()
    assert await _dispatch() == {"n8n": 1}
    first, again = hooks.to("n8n.corp.example")
    assert first.headers["x-cobe-delivery"] == again.headers["x-cobe-delivery"] == json.loads(again.content)["id"]
    uuid.UUID(first.headers["x-cobe-delivery"])
    tests = []
    for _ in range(2):
        notify_api._last_test.clear()
        assert (await admin_client.post(f"/api/admin/notify/channels/{ch['id']}/test")).json() == {"ok": True}
        tests.append(hooks.to("n8n.corp.example")[-1].headers["x-cobe-delivery"])
    assert tests[0] != tests[1] and first.headers["x-cobe-delivery"] not in tests


async def test_a_working_test_clears_the_old_error_and_the_pause(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    await _stories(src, "high")
    hooks.queue["hooks.slack.com"] = [httpx.Response(500)]
    assert await _dispatch() == {}
    c = (await _channels(admin_client))["Slack"]
    assert c["last_error"] and c["next_try_at"] and c["failures"] == 1
    hooks.queue["hooks.slack.com"] = [httpx.Response(500)]
    assert (await admin_client.post(f"/api/admin/notify/channels/{slack['id']}/test")).json()["ok"] is False
    assert (await _channels(admin_client))["Slack"]["failures"] == 1  # a failed test changes nothing
    notify_api._last_test.clear()
    assert (await admin_client.post(f"/api/admin/notify/channels/{slack['id']}/test")).json() == {"ok": True}
    c = (await _channels(admin_client))["Slack"]
    assert c["last_error"] is None and c["next_try_at"] is None and c["failures"] == 0
    assert await _dispatch() == {"Slack": 1}  # the story that waited for the retry goes out now


# ---------------------------------------------------------------- parallel edits


async def test_rule_or_channel_deleted_in_parallel_is_stale_not_500(admin_client, hooks, monkeypatch):
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    real_rule, real_channel = notify_api._rule, notify_api._channel

    async def rule_then_gone(s, rid):  # noqa: ANN001
        r = await real_rule(s, rid)
        async with db.session() as other:  # another admin deletes it meanwhile
            await other.execute(delete(NotifyRule).where(NotifyRule.id == rid))
            await other.commit()
        return r

    monkeypatch.setattr(notify_api, "_rule", rule_then_gone)
    r = await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json={"name": "Neu", "channels": [slack["id"]]})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "stale"

    async def channel_then_gone(s, cid):  # noqa: ANN001
        c = await real_channel(s, cid)
        async with db.session() as other:
            await other.execute(delete(NotifyChannel).where(NotifyChannel.id == cid))
            await other.commit()
        return c

    monkeypatch.setattr(notify_api, "_channel", channel_then_gone)
    r = await admin_client.put(f"/api/admin/notify/channels/{slack['id']}", json={"name": "Slack 2", "type": "slack"})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "stale"


async def test_new_rule_with_a_channel_deleted_in_parallel_is_stale(admin_client, hooks, monkeypatch):
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    real = notify_api._apply_rule

    async def racing(s, rule, body, *, new):  # noqa: ANN001
        async with db.session() as other:  # the channel is gone already when the rule is checked
            await other.execute(delete(NotifyChannel).where(NotifyChannel.id == uuid.UUID(slack["id"])))
            await other.commit()
        return await real(s, rule, body, new=new)

    monkeypatch.setattr(notify_api, "_apply_rule", racing)
    r = await admin_client.post("/api/admin/notify/rules", json={"name": "Alles", "channels": [slack["id"]]})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "channel_not_found"  # gone before the check
    monkeypatch.setattr(notify_api, "_apply_rule", real)
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    gone: list[bool] = []
    real_filter = notify.rule_filter

    def filter_then_gone(rule, teams=None):  # noqa: ANN001 - _apply_rule asks for it right after checking the channels
        if not gone:  # the other admin's DELETE gets in between the check and the write (nothing written yet: no lock)
            execute_elsewhere("DELETE FROM notify_channels WHERE id = $1", uuid.UUID(slack["id"]))
            gone.append(True)
        return real_filter(rule, teams)

    monkeypatch.setattr(notify, "rule_filter", filter_then_gone)
    r = await admin_client.post("/api/admin/notify/rules", json={"name": "Alles", "channels": [slack["id"]]})
    assert gone and r.status_code == 409 and r.json()["detail"]["code"] == "stale"  # not a 500 (foreign key)
    async with db.session() as s:
        assert list(await s.scalars(select(NotifyRule))) == []


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/admin/notify/smtp", {"host": "mail.corp.example", "port": 587, "from_addr": "news@corp.example"}),
        ("/api/admin/settings/news", {"enabled": False, "every_min": 30, "keep_days": 90, "details": True}),
        ("/api/admin/vendor", {"enabled": True, "every_h": 6, "eol_every_h": 24}),
    ],
)
async def test_settings_saved_in_parallel_are_stale(admin_client, path, body):
    get = path if path != "/api/admin/vendor" else "/api/admin/vendor"
    loaded = (await admin_client.get(get)).json()
    rev = (loaded.get("settings") or loaded)["rev"]
    assert rev == 0
    first = await admin_client.put(path, json={**body, "rev": rev})
    assert first.status_code == 200 and first.json()["rev"] == 1
    second = await admin_client.put(path, json={**body, "rev": rev})  # the other admin's form, loaded before
    assert second.status_code == 409 and second.json()["detail"]["code"] == "stale"
    assert (await admin_client.put(path, json=body)).status_code == 200  # an older client without rev: not checked


async def test_saving_the_mail_server_restarts_the_mail_channels(admin_client, hooks):
    mail = await _channel(admin_client, name="SOC Mail", type="email", recipients=["soc@corp.example"])
    async with db.session() as s:
        await s.execute(update(NotifyChannel).values(failures=3, next_try_at=datetime.now(UTC) + timedelta(hours=1), last_error="not_configured: smtp"))
        await s.commit()
    r = await admin_client.put("/api/admin/notify/smtp", json={"host": "mail.corp.example", "port": 587, "from_addr": "news@corp.example", "rev": 0})
    assert r.status_code == 200 and r.json()["password_set"] is False
    c = (await _channels(admin_client))["SOC Mail"]
    assert c["id"] == mail["id"] and c["failures"] == 0 and c["next_try_at"] is None and c["last_error"] is None


async def test_editing_a_channel_or_rule_made_on_an_older_state_is_stale(admin_client, hooks):
    """Two admins edit the same channel / rule: the second save, made on the state before the first, is refused (409)
    instead of silently undoing the first. The delivery state (errors, pauses) does not count as an edit."""
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    assert slack["version"] == 1
    r = await admin_client.put(f"/api/admin/notify/channels/{slack['id']}", json={"name": "Slack A", "type": "slack", "version": 1})
    assert r.status_code == 200 and r.json()["version"] == 2
    r = await admin_client.put(f"/api/admin/notify/channels/{slack['id']}", json={"name": "Slack B", "type": "slack", "version": 1})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "stale"
    async with db.session() as s:
        await s.execute(update(NotifyChannel).where(NotifyChannel.id == uuid.UUID(slack["id"])).values(failures=3, last_error="http: HTTP 500"))
        await s.commit()
    r = await admin_client.put(f"/api/admin/notify/channels/{slack['id']}", json={"name": "Slack C", "type": "slack", "version": 2})
    assert r.status_code == 200 and r.json()["name"] == "Slack C"
    # an older client without a version: not checked
    assert (await admin_client.put(f"/api/admin/notify/channels/{slack['id']}", json={"name": "Slack D", "type": "slack"})).status_code == 200

    rule = await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    assert rule["version"] == 1
    body = {"name": "Neu", "channels": [slack["id"]], "severities": ["critical"]}
    r = await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json={**body, "version": 1})
    assert r.status_code == 200 and r.json()["version"] == 2
    r = await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json={**body, "name": "Anders", "version": 1})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "stale"
    got = await admin_client.get("/api/admin/notify/rules")
    assert [x["name"] for x in got.json()] == ["Neu"]


async def test_a_fix_saved_during_the_round_is_not_overwritten(admin_client, hooks, monkeypatch):
    """Bug hunt 0.1.16 M13: an admin saves a fixed URL while the round still sends to the old one – the round's failure
    (computed from the count it read before) must not overwrite the fix with a long pause and the old error."""
    src = await _source()
    ch = await _channel(admin_client, name="n8n", type="webhook", url=HOOK)
    await _rule(admin_client, "Alles", [ch["id"]], severities=[])
    async with db.session() as s:  # it has been failing for a while
        await s.execute(update(NotifyChannel).where(NotifyChannel.id == uuid.UUID(ch["id"])).values(failures=7, next_try_at=datetime.now(UTC), last_error="timeout"))
        await s.commit()
    await _stories(src, "high")

    async def deliver(*_a, **_kw):  # while the old URL times out, the admin saves the fixed one
        r = await admin_client.put(f"/api/admin/notify/channels/{ch['id']}", json={"name": "n8n", "type": "webhook", "url": HOOK.replace("n8n.", "n8n2.")})
        assert r.status_code == 200
        raise notify.NotifyError("timeout")

    monkeypatch.setattr(notify, "deliver", deliver)
    await _dispatch()
    async with db.session() as s:
        c = await s.get(NotifyChannel, uuid.UUID(ch["id"]))
    assert c.failures == 0 and c.next_try_at is None and c.last_error is None


async def test_a_failure_counts_up_in_the_database(admin_client, hooks, monkeypatch):
    """The failure count of a round is counted in the database (+1 on what is stored), with the growing pause."""
    src = await _source()
    ch = await _channel(admin_client, name="n8n", type="webhook", url=HOOK)
    await _rule(admin_client, "Alles", [ch["id"]], severities=[])
    await _stories(src, "high")

    async def deliver(*_a, **_kw):
        raise notify.NotifyError("timeout")

    monkeypatch.setattr(notify, "deliver", deliver)
    await _dispatch()
    async with db.session() as s:
        c = await s.get(NotifyChannel, uuid.UUID(ch["id"]))
    assert c.failures == 1 and c.last_error == "timeout" and c.next_try_at > datetime.now(UTC)
