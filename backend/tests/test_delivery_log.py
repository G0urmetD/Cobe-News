"""The delivery log (Zustellprotokoll): an entry per attempt – ok, an HTTP error, a timeout, blocked by the egress guard –
the channel's automatic retries as attempts of one delivery, no secret in anything stored, the manual resend (once,
rate limited, marks as sent, the same webhook delivery id), test sends and team forwards (without sender and comment),
retention, the channel list's badge and the metrics counters. Every HTTP channel against a MockTransport."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import add_user, make_client, sign_in
from sqlalchemy import func, select, update
from test_notify import DISCORD, HOOK, SLACK, TG_TOKEN, Hooks, _channel, _channels, _dispatch, _rule, _source, _stories, _unpause

from app import db, delivery_log, delivery_log_api, forward, metrics, notify
from app import settings as settings_store
from app.crypto import encrypt_str
from app.models import DeliveryLog, NotifyChannel, NotifyDelivery, Team, TeamMember


@pytest.fixture
def hooks(monkeypatch):
    h = Hooks()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(h.handler))
    return h


async def _log(**where) -> list[DeliveryLog]:
    async with db.session() as s:
        stmt = select(DeliveryLog).order_by(DeliveryLog.at, DeliveryLog.attempt)
        for k, v in where.items():
            stmt = stmt.where(getattr(DeliveryLog, k) == v)
        return list(await s.scalars(stmt))


def _dump(rows: list[DeliveryLog]) -> str:
    return json.dumps([delivery_log.row_out(r) | {"refs": r.refs} for r in rows], ensure_ascii=False)


def _no_secret(text: str, *secrets: str) -> None:
    for x in secrets:
        assert x not in text, x


# ---------------------------------------------------------------- outcomes


async def test_ok_entry_with_what_was_sent_and_no_secret(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack SOC", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    (item,) = await _stories(src, "high", title="Lücke <b>x</b>")
    assert await _dispatch() == {"Slack SOC": 1}
    (e,) = await _log()
    assert (e.kind, e.ok, e.outcome, e.attempt, e.manual, e.channel_name, e.channel_type) == ("rule", True, "ok", 1, False, "Slack SOC", "slack")
    assert e.items == [{"kind": "news", "id": str(item.id), "title": "Lücke <b>x</b>", "severity": "high"}]
    assert e.rules == [{"id": rule["id"], "name": "Alles"}] and e.total == 1 and e.refs == [f"news:{item.id}:{rule['id']}"]
    assert e.duration_ms is not None and e.error is None and e.code is None
    _no_secret(_dump([e]), SLACK, "XXXXXXXXXXXXXXXX", "/services/")


async def test_http_error_then_the_retry_as_attempts_of_one_delivery(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    await _stories(src, "critical")
    hooks.queue["hooks.slack.com"] = [httpx.Response(500, text=f"upstream failed for {SLACK}")]
    assert await _dispatch() == {}
    await _unpause()
    assert await _dispatch() == {"Slack": 1}
    first, second = await _log()
    assert (first.ok, first.outcome, first.error, first.code, first.attempt) == (False, "http", "http", 500, 1)
    assert (second.ok, second.attempt) == (True, 2) and first.ref == second.ref
    _no_secret(_dump([first, second]), SLACK, "XXXXXXXXXXXXXXXX")
    # the API: one delivery, two attempts, the latest ok – nothing to resend
    r = (await admin_client.get("/api/admin/notify/log")).json()
    (d,) = r["deliveries"]
    assert d["ok"] and [a["attempt"] for a in d["attempts"]] == [1, 2] and d["can_resend"] is False
    assert (await admin_client.get("/api/admin/notify/log", params={"outcome": "failed"})).json()["deliveries"] == []


async def test_timeout_is_its_own_outcome(admin_client, hooks):
    src = await _source()
    discord = await _channel(admin_client, name="Discord", type="discord", url=DISCORD)
    await _rule(admin_client, "Alles", [discord["id"]], severities=[])
    await _stories(src, "high")
    hooks.queue["discord.com"] = [httpx.ReadTimeout("read timed out")]
    assert await _dispatch() == {}
    (e,) = await _log()
    assert (e.ok, e.outcome, e.error, e.code) == (False, "timeout", "timeout", None)


async def test_blocked_by_the_egress_guard(admin_client, hooks):
    """A stored target that the guard refuses now (WEBHOOK_PRIVATE_NETS no longer lists it): blocked, nothing sent."""
    src = await _source()
    async with db.session() as s:
        ch = NotifyChannel(name="Intern", type="webhook", config={"allow_http": False, "use_proxy": False, "header_name": ""}, secrets={"url": encrypt_str("https://10.20.30.40/hook")}, failures=0)
        s.add(ch)
        await s.commit()
        cid = str(ch.id)
    await _rule(admin_client, "Alles", [cid], severities=[])
    await _stories(src, "high")
    assert await _dispatch() == {}
    assert hooks.calls == []
    (e,) = await _log()
    assert (e.ok, e.outcome, e.error) == (False, "blocked", "forbidden_target")
    _no_secret(_dump([e]), "10.20.30.40/hook")


async def test_an_echoed_token_and_url_never_reach_the_log(admin_client, hooks):
    src = await _source()
    tg = await _channel(admin_client, name="Telegram", type="telegram", bot_token=TG_TOKEN, chat_id="-1001234567890")
    await _rule(admin_client, "Alles", [tg["id"]], severities=[])
    await _stories(src, "high")
    echo = f"Bad Request: https://api.telegram.org/bot{TG_TOKEN}/sendMessage refused, token {TG_TOKEN}, ask admin@corp.example"
    hooks.queue["api.telegram.org"] = [httpx.Response(400, json={"ok": False, "description": echo})]
    assert await _dispatch() == {}
    (e,) = await _log()
    assert e.outcome == "http" and e.code == 400 and e.detail
    _no_secret(_dump([e]), TG_TOKEN, TG_TOKEN.split(":")[1], "/sendMessage", "admin@corp.example")
    assert "api.telegram.org" in e.detail  # the host only


def test_sanitize():
    s = delivery_log.sanitize
    assert s(None) is None and s("") is None
    assert s("POST https://hooks.example.com/services/T0/B0/abc failed") == "POST <hooks.example.com> failed"
    assert s("Authorization: Bearer abc.def-ghi") == "Authorization: Bearer <redacted>"
    assert s("key=0123456789abcdef0123456789abcdef") == "key=<redacted>"
    assert s("bad\r\nheader\x00 injected") == "bad header injected"
    assert s("secretvalue here", ["secretvalue"]) == "<redacted> here"
    assert s("user@corp.example said no") == "<address> said no"
    assert len(s("x " * 500) or "") <= delivery_log.DETAIL_MAX


def test_outcome_classes():
    o = delivery_log.outcome
    assert o("slack", None) == (True, "ok", None, None)
    assert o("slack", notify.NotifyError("http", code=502)) == (False, "http", "http", 502)
    assert o("slack", notify.NotifyError("rate_limited", code=429))[1] == "http"
    assert o("webhook", notify.NotifyError("forbidden_target"))[1] == "blocked"
    assert o("email", notify.NotifyError("rejected", code=550)) == (False, "smtp", "rejected", 550)
    assert o("email", notify.NotifyError("timeout"))[1] == "timeout"
    assert o("teams", notify.NotifyError("dns"))[1] == "error"


# ---------------------------------------------------------------- resend


async def test_resend_a_failed_delivery_once(admin_client, hooks):
    src = await _source()
    hook = await _channel(admin_client, name="n8n", type="webhook", url=HOOK)
    await _rule(admin_client, "Alles", [hook["id"]], severities=[])
    (item,) = await _stories(src, "critical")
    hooks.queue["n8n.corp.example"] = [httpx.Response(503)]
    assert await _dispatch() == {}
    first_id = hooks.to("n8n.corp.example")[0].headers["X-Cobe-Delivery"]
    (d,) = (await admin_client.get("/api/admin/notify/log", params={"outcome": "failed"})).json()["deliveries"]
    assert d["can_resend"] and d["outcome"] == "http" and d["code"] == 503
    # the channel still pauses (its backoff) – a manual resend goes out now anyway
    assert (await _channels(admin_client))["n8n"]["next_try_at"] is not None
    r = await admin_client.post(f"/api/admin/notify/log/{d['id']}/resend")
    assert r.status_code == 200 and r.json() == {"ok": True}
    calls = hooks.to("n8n.corp.example")
    assert len(calls) == 2 and calls[1].headers["X-Cobe-Delivery"] == first_id  # the same message: the same delivery id
    assert hooks.body(calls[1])["stories"][0]["id"] == str(item.id)
    # marked as sent, the channel's pause and error over: the round sends nothing again
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(NotifyDelivery)) == 1
    c = (await _channels(admin_client))["n8n"]
    assert c["next_try_at"] is None and c["last_error"] is None
    await _unpause()
    assert await _dispatch() == {} and len(hooks.to("n8n.corp.example")) == 2
    rows = await _log()
    assert [(x.attempt, x.ok, x.manual) for x in rows] == [(1, False, False), (2, True, True)] and len({x.ref for x in rows}) == 1
    # a second click: delivered already – nothing sent
    r = await admin_client.post(f"/api/admin/notify/log/{d['id']}/resend")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "already_delivered"
    assert len(hooks.to("n8n.corp.example")) == 2


async def test_resend_is_rate_limited_failed_ones_are_logged_and_only_rules_resent(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    await _stories(src, "critical")
    hooks.queue["hooks.slack.com"] = [httpx.Response(500), httpx.Response(500)]
    assert await _dispatch() == {}
    (d,) = (await admin_client.get("/api/admin/notify/log")).json()["deliveries"]
    r = await admin_client.post(f"/api/admin/notify/log/{d['id']}/resend")
    assert r.status_code == 200 and r.json()["ok"] is False and r.json()["error"] == "http"
    r = await admin_client.post(f"/api/admin/notify/log/{d['id']}/resend")
    assert r.status_code == 429  # the same channel again within RESEND_EVERY
    (d,) = (await admin_client.get("/api/admin/notify/log")).json()["deliveries"]
    assert [(a["attempt"], a["manual"], a["ok"]) for a in d["attempts"]] == [(1, False, False), (2, True, False)]
    # a test send is logged but never resent
    assert (await admin_client.post(f"/api/admin/notify/channels/{slack['id']}/test", json={"lang": "de"})).json()["ok"] is True
    (t,) = (await admin_client.get("/api/admin/notify/log", params={"kind": "test"})).json()["deliveries"]
    assert t["kind"] == "test" and t["ok"] and t["can_resend"] is False
    delivery_log_api.reset()
    assert (await admin_client.post(f"/api/admin/notify/log/{t['id']}/resend")).status_code == 409


async def test_resend_of_stories_gone_meanwhile(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    (item,) = await _stories(src, "critical")
    hooks.queue["hooks.slack.com"] = [httpx.Response(500)]
    assert await _dispatch() == {}
    async with db.session() as s:
        await s.delete(await s.get(type(item), item.id))
        await s.commit()
    (d,) = (await admin_client.get("/api/admin/notify/log")).json()["deliveries"]
    r = await admin_client.post(f"/api/admin/notify/log/{d['id']}/resend")
    assert r.status_code == 410 and r.json()["detail"]["code"] == "gone"


async def test_the_log_is_for_admins_only(reader_client):
    assert (await reader_client.get("/api/admin/notify/log")).status_code == 403
    assert (await reader_client.post(f"/api/admin/notify/log/{uuid.uuid4()}/resend")).status_code == 403


# ---------------------------------------------------------------- forwards, retention, badge, metrics


async def test_a_forward_is_logged_without_sender_and_comment(admin_client, hooks):
    async with db.session() as s:
        await settings_store.put(s, "teams", {"enabled": True, "welcome_mail": False})
        await s.commit()
    rudi = await add_user("rudi", "reader")
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    async with db.session() as s:
        team = Team(name="SOC", forward_channel_id=uuid.UUID(slack["id"]))
        s.add(team)
        await s.flush()
        s.add(TeamMember(team_id=team.id, user_id=rudi.id, origin="manual"))
        await s.commit()
        team_id = str(team.id)
    src = await _source()
    (item,) = await _stories(src, "critical", title="Lücke im Gateway")
    forward.reset()
    async with make_client() as c:
        await sign_in(c, rudi)
        r = await c.post("/api/forward", json={"team_id": team_id, "story_id": str(item.id), "comment": "Geheimer Kommentar von Rudi", "lang": "de"})
        assert r.status_code == 200, r.text
    (e,) = await _log(kind="forward")
    assert e.ok and e.team_name == "SOC" and e.items[0]["title"] == "Lücke im Gateway" and e.user_id is None
    text = _dump([e])
    _no_secret(text, "Geheimer Kommentar", "Rudi", "rudi", SLACK)


async def test_prune_keeps_the_retention(admin_client):
    now = datetime.now(UTC)
    async with db.session() as s:
        for days in (1, 29, 31, 60):
            await s.execute(delivery_log.entry(kind="test", channel_type="slack", ref=uuid.uuid4().hex, at=now - timedelta(days=days)))
        await s.commit()
        assert await delivery_log.prune(s) == 2
        assert await s.scalar(select(func.count()).select_from(DeliveryLog)) == 2


async def test_channel_badge_and_metrics_counters(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    await _stories(src, "critical")
    hooks.queue["hooks.slack.com"] = [httpx.Response(500)]
    assert await _dispatch() == {}
    await _unpause()
    await _stories(src, "high")
    assert await _dispatch() == {"Slack": 2}
    d = (await _channels(admin_client))["Slack"]["delivery"]
    assert d["attempts_24h"] == 3 and d["failed_24h"] == 1 and d["last_ok_at"] and d["last_failed_at"]  # two single messages after the retry
    assert delivery_log.counters()[("rule", "slack", "ok")] == 2 and delivery_log.counters()[("rule", "slack", "http")] == 1
    metrics.reset()
    body = (await metrics.render()).decode()
    assert 'cobe_news_delivery_attempts_total{kind="rule",type="slack",outcome="http"} 1' in body
    assert f'cobe_news_channel_delivery_failures_24h{{channel_id="{slack["id"]}",type="slack"}} 1' in body
    assert "Slack" not in body.split("cobe_news_delivery_attempts_total")[1].split("\n# HELP")[0]


async def test_a_deleted_channel_keeps_its_entries_with_its_name(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Alt-Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    await _stories(src, "critical")
    assert await _dispatch() == {"Alt-Slack": 1}
    assert (await admin_client.delete(f"/api/admin/notify/channels/{slack['id']}")).status_code == 200
    (e,) = await _log()
    assert e.channel_id is None and e.channel_name == "Alt-Slack"
    (d,) = (await admin_client.get("/api/admin/notify/log")).json()["deliveries"]
    assert d["channel_name"] == "Alt-Slack" and d["can_resend"] is False


async def test_a_log_write_failure_never_undoes_the_sent_marks(admin_client, hooks, monkeypatch):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Alles", [slack["id"]], severities=[])
    await _stories(src, "critical")
    monkeypatch.setattr(delivery_log, "entry", lambda **kw: update(NotifyChannel).where(NotifyChannel.name == func.no_such_function()))
    assert await _dispatch() == {"Slack": 1}
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(NotifyDelivery)) == 1
    await _unpause()
    assert await _dispatch() == {}
