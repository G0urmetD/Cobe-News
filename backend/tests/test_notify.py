"""Push notifications: channels (e-mail, Teams, Slack, Discord, Telegram, generic webhook) with masked, encrypted secrets
and per-channel backoff; rules pointing to one or several channels; each story once per channel, only stories after the
rule (and the link) was made; up to three single messages, then one summary. Every HTTP channel against a MockTransport
(never the real services), mail through a local fake SMTP server (aiosmtpd); escaping, SSRF blocks and the migration of
the old single-channel rules."""

import asyncio
import email
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import uuid
from datetime import UTC, datetime, timedelta
from email import policy

import httpcore
import httpx
import pytest
from aiosmtpd.controller import Controller
from sqlalchemy import select, update

from app import db, netaddr, news, notify, notify_api
from app.crypto import decrypt_str
from app.models import NewsItem, NewsSource, NotifyChannel, NotifyDelivery

SLACK = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX"
TEAMS = "https://prod-01.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=secret"
DISCORD = "https://discord.com/api/webhooks/123456789012345678/AbCdEf-ghij_KLmnSecretPart"
TG_TOKEN = "123456789:AAH" + "testonlytokenxxxxxxxxxxxxxxxxxx"  # test fixture only – the shape of a bot token
HOOK = "https://n8n.corp.example/webhook/cobe-news"
HOSTS = ("hooks.slack.com", "prod-01.westeurope.logic.azure.com", "discord.com", "api.telegram.org", "n8n.corp.example", "n8n2.corp.example")


class Hooks:
    """The fake receivers: every request recorded; per host a queue of responses (default 200)."""

    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.queue: dict[str, list] = {}

    def handler(self, req: httpx.Request) -> httpx.Response:
        assert req.url.host in HOSTS, req.url.host
        self.calls.append(req)
        q = self.queue.get(req.url.host)
        if q:
            r = q.pop(0)
            if isinstance(r, Exception):
                raise r
            return r
        if req.url.host == "api.telegram.org":
            return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
        return httpx.Response(200, text="ok")

    def to(self, host: str) -> list[httpx.Request]:
        return [c for c in self.calls if c.url.host == host]

    @staticmethod
    def body(req: httpx.Request) -> dict:
        return json.loads(req.content)


@pytest.fixture
def hooks(monkeypatch):
    h = Hooks()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(h.handler))
    return h


async def _source() -> NewsSource:
    async with db.session() as s:
        await news.ensure_sources(s)
        src = NewsSource(key="feed-x", name="Example Feed", url="https://news.example.org/x.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.commit()
        return src


async def _stories(src: NewsSource, *severities: str, title: str = "Story {n} <b>& more</b>", url: str = "") -> list[NewsItem]:
    """New stories as a fetch round would store them."""
    now = datetime.now(UTC)
    out = []
    async with db.session() as s:
        for n, sev in enumerate(severities):
            key = f"{now.timestamp()}-{n}-{uuid.uuid4().hex[:6]}"
            i = NewsItem(
                source_id=src.id,
                url=url or f"https://news.example.org/{key}",
                url_key=key,
                title=title.format(n=n),
                title_key=f"t{key}",
                summary="What happened.",
                published_at=now - timedelta(minutes=n),
                fetched_at=now,
                severity=sev,
                cves=["CVE-2026-0001"],
                seq=await news.next_seq(s),  # the arrival number, as store() gives it
            )
            s.add(i)
            out.append(i)
        await s.commit()
    return out


async def _dispatch() -> dict:
    async with db.session() as s:
        return await notify.dispatch(s)


async def _channel(c, **body) -> dict:
    r = await c.post("/api/admin/notify/channels", json=body)
    assert r.status_code == 200, r.text
    return r.json()


async def _rule(c, name: str, channels: list[str], **body) -> dict:
    r = await c.post("/api/admin/notify/rules", json={"name": name, "channels": channels, **body})
    assert r.status_code == 200, r.text
    return r.json()


async def _channels(c) -> dict[str, dict]:
    return {x["name"]: x for x in (await c.get("/api/admin/notify/channels")).json()}


async def _unpause():
    async with db.session() as s:
        await s.execute(update(NotifyChannel).values(next_try_at=datetime.now(UTC) - timedelta(seconds=1)))
        await s.commit()


def _code(r: httpx.Response) -> str:
    return r.json()["detail"]["code"]


# ---------------------------------------------------------------- channels: secrets and checks


async def test_channel_secrets_are_masked_kept_and_checked(admin_client, hooks, monkeypatch):
    ch = await _channel(admin_client, name="SOC Slack", type="slack", url=SLACK)
    assert ch["url_set"] and ch["host"] == "hooks.slack.com" and "XXXX" not in json.dumps(ch)
    async with db.session() as s:
        stored = await s.get(NotifyChannel, uuid.UUID(ch["id"]))
        assert "hooks.slack.com" not in json.dumps(stored.secrets) and decrypt_str(stored.secrets["url"]) == SLACK
    # saved again with an empty URL: kept; the type cannot change
    body = {"name": "SOC Slack 2", "type": "slack", "url": ""}
    r = await admin_client.put(f"/api/admin/notify/channels/{ch['id']}", json=body)
    assert r.json()["url_set"] and r.json()["name"] == "SOC Slack 2"
    assert _code(await admin_client.put(f"/api/admin/notify/channels/{ch['id']}", json={**body, "type": "teams"})) == "type_fixed"
    assert "XXXX" not in (await admin_client.get("/api/admin/notify/channels")).text
    bad = [
        ({"type": "slack", "url": "http://hooks.slack.com/services/x"}, "url_invalid_url"),
        ({"type": "slack", "url": "https://evil.example.com/hook"}, "url_host_not_allowed"),
        ({"type": "slack", "url": "https://hooks.slack.com.evil.example/x"}, "url_host_not_allowed"),
        ({"type": "teams", "url": "https://127.0.0.1/hook"}, "url_forbidden_target"),
        ({"type": "slack", "url": ""}, "url_missing"),
        ({"type": "discord", "url": "https://discord.example.com/api/webhooks/1/x"}, "url_host_not_allowed"),
        ({"type": "discord", "url": "https://discord.com/channels/1/2"}, "url_host_not_allowed"),
        ({"type": "discord", "url": "https://discord.com:8443/api/webhooks/1/x"}, "url_host_not_allowed"),
        ({"type": "telegram", "bot_token": "", "chat_id": "-100123"}, "token_missing"),
        ({"type": "telegram", "bot_token": "not-a-token", "chat_id": "-100123"}, "token_invalid"),
        ({"type": "telegram", "bot_token": TG_TOKEN, "chat_id": "chat one"}, "chat_id_invalid"),
        ({"type": "email", "recipients": []}, "recipients_missing"),
        ({"type": "webhook", "url": "http://n8n.corp.example/hook"}, "url_invalid_url"),  # http needs the toggle
        ({"type": "webhook", "url": HOOK, "hmac_secret": "short"}, "hmac_too_short"),
        ({"type": "webhook", "url": HOOK, "header_name": "Host", "header_value": "x"}, "header_name_invalid"),
        ({"type": "webhook", "url": HOOK, "header_name": "X-Cobe-Signature", "header_value": "x"}, "header_name_invalid"),
        ({"type": "webhook", "url": HOOK, "header_name": "Authorization"}, "header_value_missing"),
    ]
    for body, code in bad:
        r = await admin_client.post("/api/admin/notify/channels", json={"name": "x-channel", **body})
        assert r.status_code == 422 and _code(r) == code, (body, r.text)
    assert (await admin_client.post("/api/admin/notify/channels", json={"name": "Mail", "type": "email", "recipients": ["kein-mail"]})).status_code == 422
    # http only with the explicit toggle; a private company address (n8n next door) only when WEBHOOK_PRIVATE_NETS lists it
    r = await admin_client.post("/api/admin/notify/channels", json={"name": "n8n plain", "type": "webhook", "url": "http://10.20.30.40:5678/webhook/x", "allow_http": True})
    assert r.status_code == 422 and _code(r) == "url_forbidden_target"
    monkeypatch.setattr(netaddr, "channel_policy", lambda: {"private_ok": False, "allow": (ipaddress.ip_network("10.20.0.0/16"),)})
    plain = await _channel(admin_client, name="n8n plain", type="webhook", url="http://10.20.30.40:5678/webhook/x", allow_http=True)
    assert plain["allow_http"] and plain["host"] == "10.20.30.40"
    # switching the toggle off later: the kept http URL no longer passes
    r = await admin_client.put(f"/api/admin/notify/channels/{plain['id']}", json={"name": "n8n plain", "type": "webhook", "allow_http": False})
    assert _code(r) == "url_invalid_url"
    tg = await _channel(admin_client, name="Telegram SOC", type="telegram", bot_token=TG_TOKEN, chat_id="-1001234567890")
    assert tg["token_set"] and tg["chat_id"] == "-1001234567890" and TG_TOKEN not in json.dumps(tg)
    # chat id changed, token kept
    r = await admin_client.put(f"/api/admin/notify/channels/{tg['id']}", json={"name": "Telegram SOC", "type": "telegram", "chat_id": "@corp_example_soc"})
    assert r.status_code == 200 and r.json()["token_set"] and r.json()["chat_id"] == "@corp_example_soc"
    d = await _channel(admin_client, name="Discord", type="discord", url=DISCORD)
    assert d["host"] == "discord.com" and "SecretPart" not in json.dumps(d)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/x",
        "https://[::1]/x",
        "https://169.254.169.254/latest/meta-data",
        "https://0.0.0.0/x",
        "https://[::ffff:127.0.0.1]/x",
        "https://[64:ff9b::7f00:1]/x",  # NAT64 carries 127.0.0.1
        "https://[2002:7f00:1::1]/x",  # 6to4 carries 127.0.0.1
        "https://[2002:a9fe:a9fe::1]/x",  # 6to4 carries 169.254.169.254
        "https://[fe80::1]/x",
        "https://224.0.0.1/x",
    ],
)
async def test_webhook_never_targets_internal_addresses(admin_client, url):
    r = await admin_client.post("/api/admin/notify/channels", json={"name": "bad", "type": "webhook", "url": url})
    assert r.status_code == 422 and _code(r) in ("url_forbidden_target", "url_invalid_url"), url


def test_address_rules(monkeypatch):
    ip = ipaddress.ip_address
    for a in ("127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::", "fe80::1", "224.0.0.1"):
        assert netaddr._forbidden_ip(ip(a), True), a
    for a in ("10.1.2.3", "192.168.1.10", "172.20.0.5", "fd00::1", "93.184.216.34"):
        assert not netaddr._forbidden_ip(ip(a), True), a
    # the feeds: private networks only with ALLOW_PRIVATE_FEEDS
    assert netaddr._forbidden_ip(ip("10.1.2.3"), False) and not netaddr._forbidden_ip(ip("93.184.216.34"), False)
    # this container's own Docker networks (from /proc/net/route) are never a target – also not for "private ok"
    monkeypatch.setattr(netaddr, "stack_networks", lambda: (ipaddress.ip_network("172.31.250.0/24"),))
    assert netaddr._forbidden_ip(ip("172.31.250.10"), True) and netaddr._forbidden_ip(ip("::ffff:172.31.250.10"), True)
    assert not netaddr._forbidden_ip(ip("172.31.251.10"), True)


@pytest.mark.host_networks
def test_stack_networks_from_proc_net_route(monkeypatch, tmp_path):
    route = tmp_path / "route"
    # little-endian hex as in /proc/net/route: the default route, 172.31.250.0/24 and 10.0.0.0/8
    route.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t01FA1FAC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "eth0\t00FA1FAC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
        "eth1\t0000000A\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n"
    )
    real_open = open
    monkeypatch.setattr("builtins.open", lambda p, *a, **kw: real_open(route if p == "/proc/net/route" else p, *a, **kw))
    netaddr.stack_networks.cache_clear()
    try:
        assert netaddr.stack_networks() == (ipaddress.ip_network("172.31.250.0/24"),)  # a /8 is "half the world", not a bridge
    finally:
        monkeypatch.undo()
        netaddr.stack_networks.cache_clear()


async def test_dns_is_pinned_resolved_once_checked_and_connected(monkeypatch):
    """The name is resolved once; an internal answer (or one internal among good ones) refuses the connection, a good
    answer is connected to exactly – no second lookup a rebinding DNS server could answer differently."""
    answers = {"n8n.corp.example": ["10.20.30.40"], "rebind.example.com": ["93.184.216.34", "127.0.0.1"], "own.example.com": ["172.31.250.10"]}
    lookups: list[str] = []

    def getaddrinfo(host, port, *a, **kw):
        lookups.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, port)) for addr in answers[host]]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(netaddr, "stack_networks", lambda: (ipaddress.ip_network("172.31.250.0/24"),))
    connected: list[str] = []

    class Inner(httpcore.AsyncNetworkBackend):
        async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # noqa: ASYNC109
            connected.append(host)
            raise httpcore.ConnectError("test: not really connecting")

    backend = netaddr._PinnedBackend(Inner(), private_ok=True)
    with pytest.raises(httpcore.ConnectError, match="not really"):
        await backend.connect_tcp("n8n.corp.example", 443)
    assert connected == ["10.20.30.40"] and lookups == ["n8n.corp.example"]
    for host in ("rebind.example.com", "own.example.com"):
        with pytest.raises(httpcore.ConnectError, match="forbidden target"):
            await backend.connect_tcp(host, 443)
    assert connected == ["10.20.30.40"]
    # and through the sender: a name answering with loopback is a "forbidden_target" error on the channel
    answers["n8n2.corp.example"] = ["127.0.0.1"]
    with pytest.raises(notify.NotifyError) as e:
        await notify._post_once("https://n8n2.corp.example/hook", b"{}", {}, use_proxy=False)
    assert e.value.category == "forbidden_target"


async def test_webhook_secrets_are_bound_to_the_target(admin_client, hooks):
    ch = await _channel(admin_client, name="n8n", type="webhook", url=HOOK, hmac_secret="s" * 32, header_name="Authorization", header_value="Bearer abc-123")
    assert ch["hmac_set"] and ch["header_set"] and ch["header_name"] == "Authorization" and "abc-123" not in json.dumps(ch)
    base = {"name": "n8n", "type": "webhook", "header_name": "Authorization"}
    # same target, secrets left empty: kept
    r = await admin_client.put(f"/api/admin/notify/channels/{ch['id']}", json={**base, "url": HOOK + "-2"})
    assert r.status_code == 200 and r.json()["hmac_set"] and r.json()["header_set"]
    # another host: the HMAC secret and the header value would go somewhere else – enter them again
    other = "https://n8n2.corp.example/webhook/x"
    assert _code(await admin_client.put(f"/api/admin/notify/channels/{ch['id']}", json={**base, "url": other})) == "secret_required"
    assert _code(await admin_client.put(f"/api/admin/notify/channels/{ch['id']}", json={**base, "url": other, "hmac_secret": "t" * 32})) == "secret_required"
    r = await admin_client.put(f"/api/admin/notify/channels/{ch['id']}", json={**base, "url": other, "hmac_secret": "t" * 32, "header_value": "Bearer new"})
    assert r.status_code == 200 and r.json()["host"] == "n8n2.corp.example"
    # or cleared on purpose
    r = await admin_client.put(f"/api/admin/notify/channels/{ch['id']}", json={"name": "n8n", "type": "webhook", "url": HOOK, "clear_hmac": True, "header_name": ""})
    assert r.status_code == 200 and not r.json()["hmac_set"] and not r.json()["header_set"]


async def test_new_webhook_does_not_use_the_proxy_unless_asked(admin_client, hooks):
    # the UI form starts with "through the proxy" off – a webhook created without the field is stored the same way
    ch = await _channel(admin_client, name="n8n", type="webhook", url=HOOK)
    assert ch["use_proxy"] is False
    async with db.session() as s:
        assert (await s.get(NotifyChannel, uuid.UUID(ch["id"]))).config["use_proxy"] is False
    ch = await _channel(admin_client, name="n8n proxied", type="webhook", url=HOOK, use_proxy=True)
    assert ch["use_proxy"] is True
    # a channel stored before the key existed went through the proxy and keeps doing so
    async with db.session() as s:
        row = await s.get(NotifyChannel, uuid.UUID(ch["id"]))
        row.config = {"allow_http": False, "header_name": ""}
        await s.commit()
    assert (await _channels(admin_client))["n8n proxied"]["use_proxy"] is True


# ---------------------------------------------------------------- rules → channels


async def test_rule_needs_existing_channels(admin_client, hooks):
    r = await admin_client.post("/api/admin/notify/rules", json={"name": "Ohne", "channels": []})
    assert _code(r) == "channels_missing"
    r = await admin_client.post("/api/admin/notify/rules", json={"name": "Falsch", "channels": [str(uuid.uuid4())]})
    assert _code(r) == "channel_not_found"


async def test_once_per_channel_no_backlog_single_then_summary(admin_client, hooks):
    src = await _source()
    await _stories(src, "critical", "critical")  # the backlog before the rule exists
    slack = await _channel(admin_client, name="SOC Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Kritisch", [slack["id"]], severities=["critical", "high"])
    assert rule["channels"] == [slack["id"]]
    assert await _dispatch() == {} and hooks.calls == []  # no flood of the backlog
    await _stories(src, "critical", "low", "high")
    assert await _dispatch() == {"SOC Slack": 2}  # low does not match
    assert len(hooks.calls) == 2 and all("Story" in Hooks.body(c)["text"] for c in hooks.calls)
    blocks = Hooks.body(hooks.calls[0])["blocks"]
    assert blocks[0]["type"] == "header" and "&lt;b&gt;" in json.dumps(blocks)  # free text escaped for Slack
    assert await _dispatch() == {} and len(hooks.calls) == 2  # each story once
    # more than three at once: one summary, at most LIST listed
    hooks.calls.clear()
    await _stories(src, *["high"] * 14)
    assert await _dispatch() == {"SOC Slack": 14}
    assert len(hooks.calls) == 1
    summary = json.dumps(Hooks.body(hooks.calls[0]))
    assert "14 neue Security-Meldungen" in summary and "4 weitere" in summary
    # a source filter
    body = {"name": "Kritisch", "channels": [slack["id"]], "severities": [], "sources": ["00000000-0000-0000-0000-000000000000"]}
    assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body)).json()["sources"] == body["sources"]
    hooks.calls.clear()
    await _stories(src, "critical")
    assert await _dispatch() == {} and hooks.calls == []


async def test_one_rule_many_channels_and_two_rules_one_channel(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    discord = await _channel(admin_client, name="Discord", type="discord", url=DISCORD)
    await _rule(admin_client, "Alles", [slack["id"], discord["id"]], severities=[])
    await _rule(admin_client, "Kritisch", [slack["id"]], severities=["critical"])
    await _stories(src, "critical")
    assert await _dispatch() == {"Discord": 1, "Slack": 1}  # both channels; Slack once although two rules bring it
    assert len(hooks.to("hooks.slack.com")) == 1 and len(hooks.to("discord.com")) == 1
    async with db.session() as s:
        rows = list(await s.scalars(select(NotifyDelivery)))
    assert len(rows) == 2 and {r.channel_id for r in rows} == {uuid.UUID(slack["id"]), uuid.UUID(discord["id"])}
    # a channel added to an old rule later: from then on, no backlog
    teams = await _channel(admin_client, name="Teams", type="teams", url=TEAMS)
    rules = {r["name"]: r for r in (await admin_client.get("/api/admin/notify/rules")).json()}
    r = await admin_client.put(f"/api/admin/notify/rules/{rules['Alles']['id']}", json={"name": "Alles", "channels": [slack["id"], discord["id"], teams["id"]], "severities": []})
    assert set(r.json()["channels"]) == {slack["id"], discord["id"], teams["id"]}
    assert await _dispatch() == {} and hooks.to("prod-01.westeurope.logic.azure.com") == []
    listed = await _channels(admin_client)
    assert [x["name"] for x in listed["Slack"]["rules"]] == ["Alles", "Kritisch"] and listed["Teams"]["rules"][0]["name"] == "Alles"
    # deleting a channel: its links go with it, the rule keeps the others
    assert (await admin_client.delete(f"/api/admin/notify/channels/{discord['id']}")).json() == {"ok": True}
    r = next(x for x in (await admin_client.get("/api/admin/notify/rules")).json() if x["name"] == "Alles")
    assert set(r["channels"]) == {slack["id"], teams["id"]}


async def test_a_failing_channel_never_blocks_the_others(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    teams = await _channel(admin_client, name="Teams", type="teams", url=TEAMS)
    hook = await _channel(admin_client, name="n8n", type="webhook", url=HOOK)
    await _rule(admin_client, "Kritisch", [slack["id"], teams["id"], hook["id"]], severities=["critical"])
    await _stories(src, "critical")
    hooks.queue["hooks.slack.com"] = [httpx.Response(500)]
    hooks.queue["n8n.corp.example"] = [httpx.ReadTimeout("slow")]
    assert await _dispatch() == {"Teams": 1}
    listed = await _channels(admin_client)
    assert listed["Slack"]["last_error"] == "http: HTTP 500" and listed["Slack"]["failures"] == 1 and listed["Slack"]["next_try_at"]
    assert listed["n8n"]["last_error"] == "timeout" and listed["Teams"]["last_error"] is None and listed["Teams"]["last_sent_at"]
    card = Hooks.body(hooks.to("prod-01.westeurope.logic.azure.com")[0])
    assert card["type"] == "message" and card["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert card["attachments"][0]["content"]["actions"][0]["url"] == "https://news.corp.example:8095/"
    # pausing: nothing tried; a second failure doubles the pause
    assert await _dispatch() == {}
    await _unpause()
    hooks.queue["hooks.slack.com"] = [httpx.Response(502)]
    assert await _dispatch() == {"n8n": 1}
    async with db.session() as s:
        ch = await s.get(NotifyChannel, uuid.UUID(slack["id"]))
        assert ch.failures == 2 and timedelta(minutes=3) < ch.next_try_at - datetime.now(UTC) <= timedelta(minutes=4)
    await _unpause()
    assert await _dispatch() == {"Slack": 1}
    listed = await _channels(admin_client)
    assert listed["Slack"]["last_error"] is None and listed["Slack"]["failures"] == 0
    # switched off and on again: from now on, not what came in between
    rule = (await admin_client.get("/api/admin/notify/rules")).json()[0]
    body = {"name": "Kritisch", "channels": rule["channels"], "severities": ["critical"]}
    await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json={**body, "enabled": False})
    await _stories(src, "critical")
    await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json={**body, "enabled": True})
    hooks.calls.clear()
    assert await _dispatch() == {} and hooks.calls == []


async def test_a_slow_channel_does_not_delay_the_others(admin_client, hooks, monkeypatch):
    """The channels are sent to side by side, each within its own deadline."""
    src = await _source()
    slow = await _channel(admin_client, name="Langsam", type="webhook", url=HOOK)
    fast = await _channel(admin_client, name="Schnell", type="slack", url=SLACK)
    await _rule(admin_client, "Alles", [slow["id"], fast["id"]], severities=[])
    await _stories(src, "high")
    order: list[str] = []
    real = notify.deliver

    async def deliver(t, *a, **kw):
        if t.name == "Langsam":
            await asyncio.sleep(1)  # hangs past its deadline
        order.append(t.name)
        return await real(t, *a, **kw)

    monkeypatch.setattr(notify, "deliver", deliver)
    monkeypatch.setattr(notify, "CHANNEL_DEADLINE", 0.3)
    assert await _dispatch() == {"Schnell": 1}
    assert order == ["Schnell"] and (await _channels(admin_client))["Langsam"]["last_error"] == "timeout"


async def test_an_unreadable_secret_is_an_error_of_that_channel_only(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    teams = await _channel(admin_client, name="Teams", type="teams", url=TEAMS)
    await _rule(admin_client, "Alle", [slack["id"], teams["id"]], severities=[])
    async with db.session() as s:
        await s.execute(update(NotifyChannel).where(NotifyChannel.id == uuid.UUID(slack["id"])).values(secrets={"url": "v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}))
        await s.commit()
    await _stories(src, "high")
    assert await _dispatch() == {"Teams": 1}
    assert (await _channels(admin_client))["Slack"]["last_error"] == "secret_unreadable"


# ---------------------------------------------------------------- Discord


async def test_discord_embeds_escape_and_never_mention(admin_client, hooks):
    src = await _source()
    ch = await _channel(admin_client, name="Discord SOC", type="discord", url=DISCORD)
    await _rule(admin_client, "@everyone Regel", [ch["id"]], severities=[])
    await _stories(src, "critical", title="@everyone <@123> [click](https://evil.example) **bold** `x`", url="https://news.example.org/a)b")
    assert await _dispatch() == {"Discord SOC": 1}
    req = hooks.to("discord.com")[0]
    assert req.url.path.startswith("/api/webhooks/")
    p = Hooks.body(req)
    assert p["allowed_mentions"] == {"parse": []}  # nobody is pinged, whatever the text says
    text = json.dumps(p, ensure_ascii=False)
    assert "@everyone" not in text and "@\u200beveryone" in text
    e = p["embeds"][0]
    assert e["title"].startswith("@\u200beveryone \\<@\u200b123\\> \\[click\\]\\(https\\:")  # no mention, no masked link
    assert "**bold**" not in e["title"] and "\\*\\*bold\\*\\*" in e["title"]
    assert e["url"] == "https://news.example.org/a%29b" and e["color"] == notify.DISCORD_COLORS["critical"]
    assert "?story=" in e["description"] and {f["name"]: f["value"] for f in e["fields"]} == {"Quelle": "Example Feed", "Kategorie": "Kritisch · Eigene Quelle"}


async def test_discord_429_waits_as_asked(admin_client, hooks):
    src = await _source()
    ch = await _channel(admin_client, name="Discord", type="discord", url=DISCORD)
    await _rule(admin_client, "Alles", [ch["id"]], severities=[])
    await _stories(src, "high")
    # a short wait: waited for (without blocking) and tried again right away
    hooks.queue["discord.com"] = [httpx.Response(429, json={"retry_after": 0.01, "global": False})]
    assert await _dispatch() == {"Discord": 1} and len(hooks.to("discord.com")) == 2
    # a long one: the channel pauses at least that long
    await _stories(src, "high")
    hooks.queue["discord.com"] = [httpx.Response(429, json={"retry_after": 1800, "global": False}, headers={"Retry-After": "1800"})]
    assert await _dispatch() == {}
    async with db.session() as s:
        c = await s.get(NotifyChannel, uuid.UUID(ch["id"]))
        assert c.last_error.startswith("rate_limited") and c.next_try_at - datetime.now(UTC) > timedelta(minutes=29)


async def test_discord_summary(admin_client, hooks):
    src = await _source()
    ch = await _channel(admin_client, name="Discord", type="discord", url=DISCORD)
    await _rule(admin_client, "Alles", [ch["id"]], severities=[], lang="en")
    await _stories(src, *["medium"] * 13)
    assert await _dispatch() == {"Discord": 13}
    p = Hooks.body(hooks.to("discord.com")[0])
    # a compact list: one embed, a line per story (title · category), the rest counted
    assert len(p["embeds"]) == 1 and "13 new security stories" in p["content"] and "3 more" in p["content"]
    lines = p["embeds"][0]["description"].split("\n")
    assert len(lines) == 10 and all(x.startswith("• [") and x.endswith("· Medium · Own feed") and "?story=" in x for x in lines)
    assert "What happened" not in p["embeds"][0]["description"]  # no summaries in a summary


# ---------------------------------------------------------------- Telegram


async def test_telegram_html_escaped_429_and_token_never_logged(admin_client, hooks, caplog):
    caplog.set_level(logging.DEBUG)
    src = await _source()
    ch = await _channel(admin_client, name="Telegram", type="telegram", bot_token=TG_TOKEN, chat_id="-1001234567890")
    await _rule(admin_client, "Telegram <b>Regel</b>", [ch["id"]], severities=[])
    await _stories(src, "critical", title='<script>alert(1)</script> & "quotes"', url='https://news.example.org/x"><b>y')
    assert await _dispatch() == {"Telegram": 1}
    req = hooks.to("api.telegram.org")[0]
    assert req.url.path == f"/bot{TG_TOKEN}/sendMessage"
    p = Hooks.body(req)
    assert p["chat_id"] == -1001234567890 and p["parse_mode"] == "HTML" and p["link_preview_options"] == {"is_disabled": True}
    assert "<script>" not in p["text"] and "&lt;script&gt;alert(1)&lt;/script&gt; &amp;" in p["text"]
    assert "Telegram &lt;b&gt;Regel&lt;/b&gt;" in p["text"]
    assert '<a href="https://news.example.org/x%22%3E%3Cb%3Ey">' in p["text"]  # the link cannot break out of href
    # 429 with parameters.retry_after – the channel pauses; Telegram's own description is kept, never the URL
    await _stories(src, "high")
    hooks.queue["api.telegram.org"] = [
        httpx.Response(429, json={"ok": False, "error_code": 429, "description": "Too Many Requests: retry after 600", "parameters": {"retry_after": 600}})
    ]
    assert await _dispatch() == {}
    async with db.session() as s:
        c = await s.get(NotifyChannel, uuid.UUID(ch["id"]))
        assert c.last_error.startswith("rate_limited: HTTP 429: Too Many Requests") and c.next_try_at - datetime.now(UTC) > timedelta(minutes=9)
    await _unpause()
    hooks.queue["api.telegram.org"] = [httpx.Response(400, json={"ok": False, "error_code": 400, "description": "Bad Request: chat not found"})]
    assert await _dispatch() == {}
    listed = (await admin_client.get("/api/admin/notify/channels")).json()[0]
    assert listed["last_error"] == "http: HTTP 400: Bad Request: chat not found"
    assert TG_TOKEN not in caplog.text and "testonlytoken" not in json.dumps(listed)
    # even with httpx' request log switched on again, neither the token nor a webhook path is logged
    caplog.set_level(logging.DEBUG, logger="httpx")
    await _unpause()
    assert await _dispatch() == {"Telegram": 1}
    assert "HTTP Request" in caplog.text and "https://api.telegram.org/…" in caplog.text and TG_TOKEN not in caplog.text


async def test_telegram_summary_stays_below_the_limit(admin_client, hooks):
    src = await _source()
    ch = await _channel(admin_client, name="Telegram", type="telegram", bot_token=TG_TOKEN, chat_id="@corp_example_soc")
    await _rule(admin_client, "Alles", [ch["id"]], severities=[], lang="en")
    await _stories(src, *["high"] * 12, title="A very long title " * 20 + "{n}")
    assert await _dispatch() == {"Telegram": 12}
    p = Hooks.body(hooks.to("api.telegram.org")[0])
    assert p["chat_id"] == "@corp_example_soc" and len(p["text"]) < 4096 and "12 new security stories" in p["text"] and "more in Cobe News" in p["text"]


# ---------------------------------------------------------------- generic webhook


async def test_generic_webhook_payload_signature_and_auth_header(admin_client, hooks):
    src = await _source()
    secret = "k" * 40
    ch = await _channel(admin_client, name="n8n SOC", type="webhook", url=HOOK, hmac_secret=secret, header_name="X-Api-Key", header_value="api-key-123")
    await _rule(admin_client, "Kritisch an SOC", [ch["id"]], severities=["critical"])
    await _stories(src, "critical")
    assert await _dispatch() == {"n8n SOC": 1}
    req = hooks.to("n8n.corp.example")[0]
    p = json.loads(req.content)
    assert p["version"] == 1 and p["type"] == "news.stories" and p["channel"] == "n8n SOC" and p["rules"] == ["Kritisch an SOC"]
    assert p["total"] == 1 and p["more"] == 0 and p["stories"][0]["severity"] == "critical" and p["stories"][0]["cves"] == ["CVE-2026-0001"]
    assert p["stories"][0]["title"] == "Story 0 <b>& more</b>"  # data, not markup: the receiver decides how to show it
    ts = req.headers["x-cobe-timestamp"]
    expected = "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + req.content, hashlib.sha256).hexdigest()
    assert req.headers["x-cobe-signature"] == expected and req.headers["x-api-key"] == "api-key-123"
    assert req.headers["x-cobe-event"] == "news.stories" and req.headers["x-cobe-delivery"] == p["id"]
    # no redirects followed: a 3xx is an error, the stories stay
    await _stories(src, "critical")
    hooks.queue["n8n.corp.example"] = [httpx.Response(302, headers={"Location": "http://127.0.0.1/"})]
    assert await _dispatch() == {} and len(hooks.to("n8n.corp.example")) == 2
    # unsigned without a secret
    plain = await _channel(admin_client, name="n8n plain", type="webhook", url=HOOK)
    async with db.session() as s:
        c = await s.get(NotifyChannel, uuid.UUID(plain["id"]))
    await notify.deliver(notify.resolve(c), [notify.EXAMPLE], 1, "de", "x", test=True)
    last = hooks.to("n8n.corp.example")[-1]
    assert "x-cobe-signature" not in last.headers and json.loads(last.content)["type"] == "news.test"


# ---------------------------------------------------------------- the test button


async def test_channel_test_marks_nothing_and_is_throttled(admin_client, hooks):
    src = await _source()
    ch = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Alles", [ch["id"]], severities=[])
    await _stories(src, "critical")
    assert (await admin_client.post(f"/api/admin/notify/channels/{ch['id']}/test", json={"lang": "en"})).json() == {"ok": True}
    assert "Test message" in json.dumps(Hooks.body(hooks.calls[-1]))
    assert (await admin_client.post(f"/api/admin/notify/channels/{ch['id']}/test")).status_code == 429  # one every few seconds
    async with db.session() as s:
        assert list(await s.scalars(select(NotifyDelivery))) == []
    # a failing test: the error comes back, the channel's backoff stays as it was
    notify_api._last_test.clear()
    hooks.queue["hooks.slack.com"] = [httpx.Response(404)]
    assert (await admin_client.post(f"/api/admin/notify/channels/{ch['id']}/test")).json() == {"ok": False, "error": "rejected", "detail": "HTTP 404"}
    assert (await admin_client.get("/api/admin/notify/channels")).json()[0]["failures"] == 0


async def test_readers_cannot_touch_channels(reader_client):
    assert (await reader_client.get("/api/admin/notify/channels")).status_code == 403
    assert (await reader_client.post("/api/admin/notify/channels", json={"name": "x", "type": "slack", "url": SLACK})).status_code == 403


# ---------------------------------------------------------------- e-mail


class Inbox:
    def __init__(self):
        self.messages: list[tuple[str, list[str], bytes]] = []

    async def handle_DATA(self, server, session, envelope):  # noqa: N802 - aiosmtpd's interface
        self.messages.append((envelope.mail_from, list(envelope.rcpt_tos), envelope.content))
        return "250 OK"


@pytest.fixture
def smtp(monkeypatch):
    # the fake server listens on loopback – never a target in production, even when listed (netaddr.never, 0.1.26);
    # here SMTP_ALLOW_INTERNAL=127.0.0.1 (conftest) reaches it because loopback is let through for these tests only
    real = netaddr.never
    monkeypatch.setattr(netaddr, "never", lambda a: str(a) != "127.0.0.1" and real(a))
    with socket.socket() as probe:  # a free local port
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    inbox = Inbox()
    ctl = Controller(inbox, hostname="127.0.0.1", port=port)
    ctl.start()
    yield inbox, ctl.port
    ctl.stop()


async def test_mail_through_a_local_smtp_server(admin_client, smtp):
    inbox, port = smtp
    cfg = {"host": "127.0.0.1", "port": port, "encryption": "none", "from_addr": "news@corp.example", "from_name": "Cobe News", "password": "smtp-pw-123"}
    r = await admin_client.put("/api/admin/notify/smtp", json=cfg)
    assert r.json()["password_set"] and "smtp-pw" not in r.text
    # the stored password stays when saved empty; it is never sent back
    r = await admin_client.put("/api/admin/notify/smtp", json={**cfg, "password": "", "username": ""})
    assert r.json()["password_set"]
    assert (await admin_client.post("/api/admin/notify/smtp/test", json={**cfg, "password": "", "username": "", "to": "soc@corp.example"})).json() == {"ok": True}
    src = await _source()
    ch = await _channel(admin_client, name="SOC Mail", type="email", recipients=["SOC@corp.example", "isb@corp.example"])
    assert ch["recipients"] == ["soc@corp.example", "isb@corp.example"]
    await _rule(admin_client, "Kritisch", [ch["id"]], severities=["critical"])
    await _stories(src, "critical", url="javascript:alert(1)")
    assert await _dispatch() == {"SOC Mail": 1}
    await asyncio.sleep(0.05)
    sender, rcpts, raw = inbox.messages[-1]
    assert sender == "news@corp.example" and rcpts == ["soc@corp.example", "isb@corp.example"]
    msg = email.message_from_bytes(raw, policy=policy.default)
    assert msg["Subject"].startswith("[Cobe News] Kritisch: Story 0") and msg["Auto-Submitted"] == "auto-generated"
    body = msg.get_body(("html",)).get_content()
    text = msg.get_body(("plain",)).get_content()
    assert "Story 0 &lt;b&gt;&amp; more&lt;/b&gt;" in body and "https://news.corp.example:8095/?story=" in body  # escaped, with the link
    assert "javascript" not in body and "javascript" not in text  # no link at all instead of a script link
    # the channel's test button sends to its recipients
    notify_api._last_test.clear()
    assert (await admin_client.post(f"/api/admin/notify/channels/{ch['id']}/test")).json() == {"ok": True}
    await asyncio.sleep(0.05)
    assert "Testnachricht" in email.message_from_bytes(inbox.messages[-1][2], policy=policy.default)["Subject"]
    # another server or port: the stored password is not sent there – it has to be entered again
    r = await admin_client.put("/api/admin/notify/smtp", json={**cfg, "port": 1, "password": ""})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "secret_required"
    notify_api._last_test.clear()
    r = await admin_client.post("/api/admin/notify/smtp/test", json={**cfg, "port": 1, "password": "", "to": "soc@corp.example"})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "secret_required"
    await admin_client.put("/api/admin/notify/smtp", json={**cfg, "port": 1})
    notify_api._last_test.clear()
    r = (await admin_client.post("/api/admin/notify/smtp/test", json={**cfg, "port": 1, "to": "soc@corp.example"})).json()
    assert r["ok"] is False and r["error"] in ("refused", "connection")


# ---------------------------------------------------------------- escaping of every format


def test_feed_text_cannot_inject_markup_or_mentions():
    s = notify.Story(str(uuid.uuid4()), "<!channel> @here [x](https://evil.example) <@U1>", "**sum** <!everyone>", "https://x.example/a|<!channel>(b)[c]", "high", "Src @everyone", datetime.now(UTC))
    slack = json.dumps(notify.render_slack("R <!here>", [s], 1, "de"))
    assert "<!channel>" not in slack and "<!here>" not in slack and "<!everyone>" not in slack and "a%7C%3C!channel%3E%28b%29%5Bc%5D" in slack
    teams = json.dumps(notify.render_teams("R", [s], 1, "de"))
    assert "(https://x.example/a%7C%3C!channel%3E%28b%29%5Bc%5D)" in teams and "\\\\[x\\\\]\\\\(https" in teams  # no link of its own
    discord = json.dumps(notify.render_discord("R", [s], 1, "de"), ensure_ascii=False)
    assert "@here" not in discord and "@everyone" not in discord and "<@U1>" not in discord
    tg = notify.render_telegram("R", [s], 1, "de")
    assert "<!channel>" not in tg and "&lt;!channel&gt;" in tg
    bad = notify.Story(str(uuid.uuid4()), "T", "", "javascript:alert(1)", "high", "Src", datetime.now(UTC))
    for out in (notify.render_slack("R", [bad], 1, "de"), notify.render_teams("R", [bad], 1, "de"), notify.render_discord("R", [bad], 1, "de"), notify.render_telegram("R", [bad], 1, "de")):
        assert "javascript" not in json.dumps(out)
    assert notify.render_webhook("c", [], [bad], 1, "de")["stories"][0]["url"] == ""


# ---------------------------------------------------------------- migration of the single-channel rules


OLD_SCHEMA = (
    """CREATE TABLE notify_rules (id CHAR(32) NOT NULL PRIMARY KEY, name VARCHAR(100) NOT NULL, enabled BOOLEAN NOT NULL,
    channel VARCHAR(8) NOT NULL, recipients JSON NOT NULL, webhook_enc TEXT, severities JSON NOT NULL, sources JSON NOT NULL,
    lang VARCHAR(2) NOT NULL, created_at DATETIME NOT NULL, active_since DATETIME NOT NULL, last_sent_at DATETIME,
    last_error VARCHAR(200), last_error_at DATETIME, failures INTEGER NOT NULL, next_try_at DATETIME)""",
    """CREATE TABLE notify_sent (rule_id CHAR(32) NOT NULL REFERENCES notify_rules (id) ON DELETE CASCADE,
    item_id CHAR(32) NOT NULL REFERENCES news_items (id) ON DELETE CASCADE, sent_at DATETIME NOT NULL, PRIMARY KEY (rule_id, item_id))""",
    "CREATE INDEX ix_notify_sent_item_id ON notify_sent (item_id)",
)



async def test_a_line_break_never_breaks_the_mails(admin_client, monkeypatch):
    """Bug hunt 0.1.16 L6 / security review L4: a line break in a rule or channel name is refused; one coming from
    elsewhere (a product or version label, a title) is a space in the mail subject – before, the email package refused
    the header and the channel failed and retried the same messages for ever."""
    for path, body in (("/api/admin/notify/rules", {"name": "Kritisch\nalles", "channels": []}), ("/api/admin/notify/channels", {"name": "SOC\r\nBcc: x", "type": "email", "recipients": ["soc@corp.example"]})):
        r = await admin_client.post(path, json=body)
        assert r.status_code == 422, (path, r.text)
    subject, text, html = notify.render_mail("Kritisch\nalles", [notify.EXAMPLE], 1, "de", test=True)  # the rule's name in the subject
    broken = notify.Story("00000000-0000-4000-8000-000000000002", "Example\r\nGateway: Lücke", "", "", "high", "Q", datetime.now(UTC))
    many = notify.render_mail("Kritisch\nalles", [notify.EXAMPLE, broken, notify.EXAMPLE, notify.EXAMPLE], 4, "de")[0]  # a story's name
    sent = []

    async def fake_send(msg, **kw):  # noqa: ANN001, ANN003
        sent.append(msg["Subject"])

    async def fake_socket(*_a):  # noqa: ANN002
        return None

    monkeypatch.setattr(notify.aiosmtplib, "send", fake_send)
    monkeypatch.setattr(notify.netaddr, "mail_socket", fake_socket)
    await notify.send_mail({"host": "mail.corp.example", "from_addr": "news@corp.example", "port": 25}, ["a@corp.example"], subject, text, html)
    assert sent and "\n" not in sent[0] and "Kritisch alles" in sent[0]
    await notify.send_mail({"host": "mail.corp.example", "from_addr": "news@corp.example", "port": 25}, ["a@corp.example"], many, text, html)
    assert "\n" not in sent[1] and "\r" not in sent[1] and "Example Gateway" in sent[1]
    assert notify.one_line("a\r\n\tb c\x00d") == "a b c d"


async def test_one_mail_address_is_one_recipient(smtp):
    """An address from the directory (LDAP/Entra `mail`) or typed by an admin is one recipient: a comma (or ;, <>, a
    space) in it made the personal and weekly mails go to every address it held – also one outside the company."""
    inbox, port = smtp
    cfg = {"host": "127.0.0.1", "port": port, "encryption": "none", "from_addr": "news@corp.example"}
    for bad in ("me@corp.example,spy@evil.example", "me@corp.example;spy@evil.example", "Me <me@corp.example>, spy@evil.example", "me@corp.example spy@evil.example", "<spy@evil.example>"):
        with pytest.raises(notify.NotifyError) as exc:
            await notify.send_mail(cfg, [bad], "s", "t", "<p>t</p>")
        assert exc.value.category == "not_configured", bad
    assert inbox.messages == []
    await notify.send_mail(cfg, ["me@corp.example", "isb@corp.example"], "s", "t", "<p>t</p>")
    await asyncio.sleep(0.05)
    assert inbox.messages[-1][1] == ["me@corp.example", "isb@corp.example"]
