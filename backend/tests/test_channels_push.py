"""ntfy, Gotify and Mattermost channels: secrets encrypted and never sent back (bound to the server), URL checks and the
egress guard, the payloads (plain text for ntfy / Gotify – nothing of the feed in a header, no CR/LF anywhere; Markdown
escaped and mentions defused for Mattermost), priorities by severity, the round, a test send and a team forward."""

import json
import uuid

import httpx
import pytest
from sqlalchemy import select
from test_notify import _dispatch, _rule, _source, _stories

from app import db, forward, notify
from app.crypto import decrypt_str
from app.models import NotifyChannel

NTFY = "https://ntfy.corp.example"
GOTIFY = "https://gotify.corp.example/push"
MM = "https://chat.corp.example/hooks/abcdefghij1234567890xyz"
NTFY_TOKEN = "tk_testonlytokenxxxxxxxxxxxxxx"  # test fixture only – the shape of an ntfy access token
GOTIFY_TOKEN = "AtestonlyTokenX"  # test fixture only
TOPIC = "cobe-soc-testtopic"
EVIL = "Lücke **fett** [klick](https://evil.example/x) @channel @all ~town :smile: <b>x</b> # H\r\nX-Injected: 1\n"


class Recv:
    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.status = 200

    def handler(self, req: httpx.Request) -> httpx.Response:
        assert req.url.host in ("ntfy.corp.example", "gotify.corp.example", "chat.corp.example"), req.url.host
        self.calls.append(req)
        return httpx.Response(self.status, json={"id": 1})

    def body(self, n: int = -1) -> dict:
        return json.loads(self.calls[n].content)


@pytest.fixture
def recv(monkeypatch):
    r = Recv()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(r.handler))
    return r


async def _add(c, **body) -> httpx.Response:
    return await c.post("/api/admin/notify/channels", json={"name": f"Kanal {uuid.uuid4().hex[:4]}", **body})


def _code(r: httpx.Response) -> str:
    return r.json()["detail"]["code"]


# ---------------------------------------------------------------- secrets and checks


async def test_ntfy_secrets_are_encrypted_never_returned_and_bound_to_the_server(admin_client):
    r = await _add(admin_client, type="ntfy", server_url=NTFY + "/", topic=TOPIC, token=NTFY_TOKEN, tags=["soc", "cobe"])
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["server"] == NTFY and out["host"] == "ntfy.corp.example" and out["topic_set"] and out["token_set"] and out["tags"] == ["soc", "cobe"]
    listed = (await admin_client.get("/api/admin/notify/channels")).text
    for x in (TOPIC, NTFY_TOKEN):
        assert x not in r.text and x not in listed
    async with db.session() as s:
        ch = await s.get(NotifyChannel, uuid.UUID(out["id"]))
        assert decrypt_str(ch.secrets["topic"]) == TOPIC and decrypt_str(ch.secrets["token"]) == NTFY_TOKEN
        assert TOPIC not in json.dumps(ch.config) and ch.target == "https://ntfy.corp.example:443"
    base = {"name": out["name"], "type": "ntfy", "version": out["version"]}
    # another server: the topic and token must be entered again
    r = await admin_client.put(f"/api/admin/notify/channels/{out['id']}", json={**base, "server_url": "https://ntfy.example.com"})
    assert r.status_code == 422 and _code(r) == "secret_required"
    # the same server, nothing typed: both kept; the token cleared on purpose
    r = await admin_client.put(f"/api/admin/notify/channels/{out['id']}", json={**base, "server_url": NTFY, "clear_token": True})
    assert r.status_code == 200 and r.json()["topic_set"] and not r.json()["token_set"]


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"type": "ntfy", "server_url": "http://ntfy.corp.example", "topic": TOPIC}, "url_invalid_url"),
        ({"type": "ntfy", "server_url": "https://ntfy.corp.example?x=1", "topic": TOPIC}, "url_invalid_url"),
        ({"type": "ntfy", "server_url": "https://10.0.0.5", "topic": TOPIC}, "url_forbidden_target"),
        ({"type": "ntfy", "server_url": "https://127.0.0.1", "topic": TOPIC}, "url_forbidden_target"),
        ({"type": "ntfy", "server_url": NTFY, "topic": "bad topic/../x"}, "topic_invalid"),
        ({"type": "ntfy", "server_url": NTFY}, "topic_missing"),
        ({"type": "ntfy", "server_url": NTFY, "topic": TOPIC, "token": "tk_x\r\nX-Evil: 1"}, "push_token_invalid"),
        ({"type": "ntfy", "server_url": NTFY, "topic": TOPIC, "tags": ["ok", "no spaces"]}, "tags_invalid"),
        ({"type": "gotify", "server_url": GOTIFY}, "push_token_missing"),
        ({"type": "gotify", "server_url": "https://169.254.169.254", "token": GOTIFY_TOKEN}, "url_forbidden_target"),
        ({"type": "mattermost", "url": "https://chat.corp.example/api/v4/posts"}, "url_invalid_url"),
        ({"type": "mattermost", "url": "http://chat.corp.example/hooks/abcdefghij1234567890xyz"}, "url_invalid_url"),
        ({"type": "mattermost", "url": "https://192.168.1.10/hooks/abcdefghij1234567890xyz"}, "url_forbidden_target"),
        ({"type": "mattermost"}, "url_missing"),
    ],
)
async def test_targets_are_checked(admin_client, body, code):
    r = await _add(admin_client, **body)
    assert r.status_code == 422 and _code(r) == code, r.text


async def test_gotify_and_mattermost_secrets_never_returned(admin_client):
    g = await _add(admin_client, type="gotify", server_url=GOTIFY, token=GOTIFY_TOKEN)
    m = await _add(admin_client, type="mattermost", url=MM)
    assert g.status_code == 200 and m.status_code == 200, (g.text, m.text)
    listed = (await admin_client.get("/api/admin/notify/channels")).text
    for x in (GOTIFY_TOKEN, "abcdefghij1234567890xyz"):
        assert x not in listed and x not in g.text and x not in m.text
    assert m.json()["host"] == "chat.corp.example" and m.json()["url_set"] and g.json()["server"] == GOTIFY and g.json()["token_set"]


# ---------------------------------------------------------------- payloads


def _story(**kw) -> notify.Story:
    return notify.Story(**{**notify.EXAMPLE.__dict__, "title": EVIL, "summary": EVIL, "url": "https://news.example.org/a b)(", **kw})


def test_ntfy_payload_plain_and_without_line_breaks_where_none_belong():
    title, message, sev, click = notify.render_push("Regel\r\nX: y", [_story()], 1, "de")
    p = notify.ntfy_payload(TOPIC, title, message, sev, click, ["soc", "bad tag\n"])
    assert "\r" not in json.dumps(p) and "\n" not in p["title"] and "X-Injected" in p["title"]
    assert p["markdown"] is False and p["priority"] == 5 and p["tags"] == ["rotating_light", "soc"] and p["topic"] == TOPIC
    assert p["click"] == "https://news.corp.example:8095/?story=00000000-0000-4000-8000-000000000001"
    assert "https://news.example.org/a%20b%29%28" in p["message"]
    assert {notify.ntfy_payload(TOPIC, "t", "m", s, "https://x.example/", [])["priority"] for s in ("critical", "high", "medium", "low", "info")} == {5, 4, 3, 2, 1}
    # a summary: the title says how many, the click opens the news list (only the shown stories known: not all six)
    title, message, sev, click = notify.render_push("Regel", [_story(severity="low"), _story(severity="high")] * 3, 6, "en")
    assert title.startswith("6 new security stories") and sev == "high" and click == "https://news.corp.example:8095/"


def test_gotify_payload():
    title, message, sev, click = notify.render_push("Regel", [_story(severity="medium")], 1, "de")
    p = notify.gotify_payload(title, message, sev, click)
    assert p["priority"] == 5 and p["extras"]["client::display"]["contentType"] == "text/plain"
    assert p["extras"]["client::notification"]["click"]["url"].startswith("https://news.corp.example:8095/")
    assert "\r" not in json.dumps(p) and len(p["message"]) <= notify.PUSH_TEXT_MAX
    assert {notify.gotify_payload("t", "m", s, "https://x.example/")["priority"] for s in ("critical", "high")} == {10, 8}


def test_mattermost_markdown_escaped_and_mentions_defused():
    p = notify.render_mattermost("Regel @here", [_story()], 1, "de")
    blob = json.dumps(p, ensure_ascii=False)
    assert "@channel" not in blob and "@all" not in blob and "@here" not in blob and "@​channel" in blob
    text = p["attachments"][0]["text"]
    assert "\\*\\*fett\\*\\*" in text and "\\[klick\\]\\(https\\:" in text and "\\~town" in text and "\\:smile\\:" in text and "\\<b\\>" in text
    assert "\r" not in blob and "X-Injected" in text  # one line: the line break became a blank
    assert p["attachments"][0]["color"] == notify.ACCENTS["critical"] and "(https://news.example.org/a%20b%29%28)" in text
    assert "(https://news.corp.example:8095/?story=" in text


def test_forward_text_and_mattermost():
    f = forward.Forward(sender="Rudi @all", team="SOC", comment=forward.clean_comment(EVIL), title=EVIL, summary="", url="https://news.example.org/a", link="https://news.corp.example:8095/?story=x", severity="high", source="Feed", published_at=None)
    title, message = forward.render_text(f, "de")
    assert "\n" not in title and "\r" not in message and "https[:]//evil[.]example" in message
    mm = json.dumps(forward.render_mattermost(f, "de"), ensure_ascii=False)
    assert "@all" not in mm and "@channel" not in mm and "\\\\*\\\\*fett" in mm


# ---------------------------------------------------------------- sending


async def test_the_round_sends_to_ntfy_gotify_and_mattermost(admin_client, recv):
    src = await _source()
    ids = []
    for body in ({"type": "ntfy", "server_url": NTFY, "topic": TOPIC, "token": NTFY_TOKEN}, {"type": "gotify", "server_url": GOTIFY, "token": GOTIFY_TOKEN}, {"type": "mattermost", "url": MM}):
        r = await _add(admin_client, **body)
        assert r.status_code == 200, r.text
        ids.append(r.json()["id"])
    await _rule(admin_client, "Alles", ids, severities=[])
    await _stories(src, "critical", title="Lücke @channel **x**\r\nX-Evil: 1")
    assert sum((await _dispatch()).values()) == 3
    by = {c.url.host: c for c in recv.calls}
    n = by["ntfy.corp.example"]
    assert str(n.url) == NTFY + "/" and n.headers["Authorization"] == f"Bearer {NTFY_TOKEN}" and "X-Evil" not in n.headers
    assert json.loads(n.content)["topic"] == TOPIC and json.loads(n.content)["priority"] == 5
    g = by["gotify.corp.example"]
    assert str(g.url) == GOTIFY + "/message" and g.headers["X-Gotify-Key"] == GOTIFY_TOKEN and json.loads(g.content)["priority"] == 10
    m = by["chat.corp.example"]
    assert str(m.url) == MM and "@channel" not in m.content.decode()
    # a refused token: the channel's error, the delivery log without the token
    recv.status = 401
    r = await admin_client.post(f"/api/admin/notify/channels/{ids[0]}/test", json={"lang": "de"})
    assert r.json()["ok"] is False and r.json()["error"] == "auth"
    async with db.session() as s:
        from app.models import DeliveryLog

        rows = list(await s.scalars(select(DeliveryLog)))
    blob = json.dumps([[r.detail, r.error, r.items, r.refs] for r in rows])
    for x in (NTFY_TOKEN, TOPIC, GOTIFY_TOKEN, "abcdefghij1234567890xyz"):
        assert x not in blob
