"""An mein Team weiterleiten (app/forward.py): a member forwards a story or a finding with a comment to the forward channel
an admin chose for the team – never to a target of their own. Only own teams (a foreign one looks like none), only the
team's channel, the comment as text in every format (no markup, no link, no mention, no mail header), the limits per
person and per thing, a channel that is missing or fails. Every HTTP channel against a MockTransport, mail through a
recorder – nothing leaves the machine."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import add_user, make_client, sign_in

from app import db, forward, news, notify, vendor
from app import settings as settings_store
from app.models import User, NewsItem, NewsSource, NotifyChannel, Team, TeamMember, VendorAdvisory, VendorAdvisoryProduct, VendorFetch, VendorFollow, VendorVersion

SLACK = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX"
TEAMS = "https://prod-01.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=secret"
DISCORD = "https://discord.com/api/webhooks/123456789012345678/AbCdEf-ghij_KLmnSecretPart"
TG_TOKEN = "123456789:AAH" + "testonlytokenxxxxxxxxxxxxxxxxxx"  # test fixture only – the shape of a bot token
HOOK = "https://n8n.corp.example/webhook/cobe-news"
HOSTS = ("hooks.slack.com", "prod-01.westeurope.logic.azure.com", "discord.com", "api.telegram.org", "n8n.corp.example")
EVIL = "Bitte prüfen <!channel> @here @everyone <@123> [klick](https://evil.example/x) *fett* <b>x</b> https://evil.example/a?b=1 www.evil.example\nZweite Zeile &amp; <script>"


class Hooks:
    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.status = 200

    def handler(self, req: httpx.Request) -> httpx.Response:
        assert req.url.host in HOSTS, req.url.host
        self.calls.append(req)
        if req.url.host == "api.telegram.org":
            return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
        return httpx.Response(self.status, text="ok")

    def body(self, n: int = -1) -> dict:
        return json.loads(self.calls[n].content)


@pytest.fixture(autouse=True)
def fresh_limits():
    forward.reset()
    yield
    forward.reset()


@pytest.fixture
def hooks(monkeypatch):
    h = Hooks()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(h.handler))
    return h


@pytest.fixture
def mails(monkeypatch):
    sent: list[dict] = []

    async def send_mail(cfg, to, subject, text, body):  # noqa: ANN001, ANN202
        sent.append({"to": to, "subject": subject, "text": text, "html": body})

    monkeypatch.setattr(notify, "send_mail", send_mail)
    return sent


async def _teams_on(on: bool = True) -> None:
    async with db.session() as s:
        await settings_store.put(s, "teams", {"enabled": on, "welcome_mail": False})
        await s.commit()


async def _channel(admin_client, **body) -> str:
    r = await admin_client.post("/api/admin/notify/channels", json={"name": f"Kanal {uuid.uuid4().hex[:4]}", **body})
    assert r.status_code == 200, r.text
    return r.json()["id"]


async def _team(name: str, *members, channel: str | None = None) -> str:
    async with db.session() as s:
        t = Team(name=name, forward_channel_id=uuid.UUID(channel) if channel else None)
        s.add(t)
        await s.flush()
        for u in members:
            s.add(TeamMember(team_id=t.id, user_id=u.id, origin="manual"))
        await s.commit()
        return str(t.id)


async def _story(title: str = "Kritische Lücke in Example Gateway <b>&</b>", url: str = "https://news.example.org/a", topics: list[str] | None = None) -> str:
    async with db.session() as s:
        await news.ensure_sources(s)
        src = NewsSource(key=f"feed-fw-{uuid.uuid4().hex[:6]}", name="Example Feed", url=f"https://news.example.org/{uuid.uuid4().hex[:6]}.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.flush()
        now = datetime.now(UTC)
        i = NewsItem(
            source_id=src.id, url=url, url_key=uuid.uuid4().hex, title=title, title_key=uuid.uuid4().hex, summary="Was passiert ist.", published_at=now, fetched_at=now,
            severity="critical", cves=["CVE-2026-0001"], seq=await news.next_seq(s), topics=topics or [],
        )
        s.add(i)
        await s.commit()
        return str(i.id)


async def _finding() -> tuple[str, str]:
    now = datetime.now(UTC)
    async with db.session() as s:
        f = VendorFollow(product="typo3", enabled=True, created_at=now, updated_at=now)
        s.add(f)
        await s.flush()
        s.add(VendorVersion(follow_id=f.id, version="13.4.37", label="Website", count=None))
        m = {"vulnerable": True, "criteria": "cpe:2.3:a:typo3:typo3:*:*:*:*:*:*:*:*", "versionStartIncluding": "13.0.0", "versionEndExcluding": "13.4.38"}
        a = VendorAdvisory(
            id="nvd:CVE-2026-50030", source="nvd", ident="CVE-2026-50030", title="TYPO3 issue", summary="An issue.", url="https://nvd.nist.gov/vuln/detail/CVE-2026-50030",
            cves=["CVE-2026-50030"], cvss=9.8, severity="critical", exploited=False, published_at=now - timedelta(days=60), updated_at=None,
            data={"configs": [{"nodes": [{"cpeMatch": [m]}]}], "cna": [], "desc": "An issue.", "cwe": []}, fetched_at=now,
        )
        s.add(a)
        s.add(VendorAdvisoryProduct(product="typo3", advisory_id=a.id))
        s.add(VendorFetch(key="nvd:a:typo3:typo3", failures=0, items=1, last_ok_at=now))
        await s.commit()
    vendor.bump()
    return "typo3", "nvd:CVE-2026-50030"


@pytest.fixture
async def setup(admin_client, hooks):
    """Teams on; Rudi in the team "SOC" whose forward channel is a Slack webhook; Rudi signed in."""
    await _teams_on()
    rudi = await add_user("rudi", "reader")
    async with db.session() as s:
        (await s.get(User, rudi.id)).display_name = "Rudi <b>Rüssel</b>"
        await s.commit()
    ch = await _channel(admin_client, type="slack", url=SLACK)
    team = await _team("SOC", rudi, channel=ch)
    async with make_client() as c:
        await sign_in(c, rudi)
        c.user = rudi
        yield type("S", (), {"c": c, "team": team, "channel": ch, "admin": admin_client, "hooks": hooks, "rudi": rudi})


def _fields(slack: dict) -> dict[str, str]:
    """The card's labelled fields of a Slack message: label → value."""
    sec = next(b for b in slack["blocks"] if b["type"] == "section" and "fields" in b)
    return dict(f["text"].removeprefix("*").split("*\n", 1) for f in sec["fields"])


def _code(r: httpx.Response) -> str:
    return r.json()["detail"]["code"]


# ---------------------------------------------------------------- the team's channel, chosen by an admin


async def test_admin_sets_the_forward_channel_and_readers_see_only_whether_there_is_one(setup):
    a = setup.admin
    teams = {t["id"]: t for t in (await a.get("/api/admin/teams")).json()}
    assert teams[setup.team]["forward_channel_id"] == setup.channel
    other = await _team("NOC")
    t = teams[setup.team]
    # set, unknown channel refused, set to none
    r = await a.patch(f"/api/admin/teams/{other}", json={"forward_channel_id": setup.channel})
    assert r.status_code == 200 and r.json()["forward_channel_id"] == setup.channel
    r = await a.patch(f"/api/admin/teams/{other}", json={"forward_channel_id": str(uuid.uuid4())})
    assert r.status_code == 422 and _code(r) == "channel_not_found"
    r = await a.patch(f"/api/admin/teams/{other}", json={"forward_channel_id": None})
    assert r.json()["forward_channel_id"] is None
    # a patch of the name leaves the channel alone
    r = await a.patch(f"/api/admin/teams/{setup.team}", json={"name": "SOC 2", "version": t["version"]})
    assert r.json()["forward_channel_id"] == setup.channel
    # the reader: whether forwarding works, not where it goes
    mine = (await setup.c.get("/api/me/teams")).json()
    assert mine == {"enabled": True, "teams": [{"id": setup.team, "name": "SOC 2", "forward": True}]}
    assert "hooks.slack.com" not in json.dumps(mine) and setup.channel not in json.dumps(mine)
    # readers cannot set it
    r = await setup.c.patch(f"/api/admin/teams/{setup.team}", json={"forward_channel_id": None})
    assert r.status_code == 403
    # the channel deleted: the team has none any more
    assert (await a.delete(f"/api/admin/notify/channels/{setup.channel}")).status_code == 200
    assert (await setup.c.get("/api/me/teams")).json()["teams"][0]["forward"] is False


async def test_forward_a_story_to_slack(setup):
    sid = await _story(topics=["exploited", "zeroday"])
    r = await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": sid, "comment": EVIL, "lang": "de"})
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "team": "SOC"}
    assert len(setup.hooks.calls) == 1 and str(setup.hooks.calls[0].url) == SLACK
    body = setup.hooks.body()
    blocks = body["blocks"]
    assert blocks[0]["text"]["type"] == "plain_text" and "Rudi <b>Rüssel</b> hat eine Meldung an SOC weitergeleitet" in blocks[0]["text"]["text"]
    # the story: its title escaped as the notifications do
    assert "&lt;b&gt;&amp;&lt;/b&gt;" in blocks[1]["text"]["text"]
    # the card as the notifications have it: Quelle, Kategorie (topics in news.TOPICS order, then the severity) – no
    # Produkt without details (no guess)
    assert _fields(body) == {"Quelle": "Example Feed", "Kategorie": "Zero-Day · Aktiv ausgenutzt · Kritisch"}
    # the comment: its own field, plain text (Slack parses nothing in it), links and mentions defused, both lines kept
    c = blocks[3]["text"]
    assert c["type"] == "plain_text" and c["text"].startswith("Kommentar:\n")
    assert "https[:]//evil[.]example/a" in c["text"] and "www[.]evil[.]example" in c["text"] and "https://" not in c["text"]
    assert "@​here" in c["text"] and "@​everyone" in c["text"] and "\nZweite Zeile" in c["text"]
    assert "<!channel>" not in json.dumps([b for i, b in enumerate(blocks) if i != 3])  # only in the plain_text comment
    # the short description, the link to Cobe News
    assert blocks[4]["text"]["text"] == "Was passiert ist."
    assert blocks[-1]["elements"][0]["url"] == f"https://news.corp.example:8095/?story={sid}"


async def test_comment_escaped_for_every_channel(setup, mails):
    a = setup.admin
    sid = await _story()
    async with db.session() as s:
        await settings_store.put(s, "smtp", {**settings_store.DEFAULTS["smtp"], "host": "mail.corp.example", "from_addr": "news@corp.example"})
        await s.commit()
    chans = {
        "teams": await _channel(a, type="teams", url=TEAMS),
        "discord": await _channel(a, type="discord", url=DISCORD),
        "telegram": await _channel(a, type="telegram", bot_token=TG_TOKEN, chat_id="-1001234567890"),
        "webhook": await _channel(a, type="webhook", url=HOOK, hmac_secret="ein-geheimnis-fuer-tests-1234"),
        "email": await _channel(a, type="email", recipients=["soc@corp.example"]),
    }
    got = {}
    for kind, cid in chans.items():
        t = await _team(f"T-{kind}", setup.rudi, channel=cid)
        r = await setup.c.post("/api/forward", json={"team_id": t, "story_id": sid, "comment": EVIL})
        assert r.status_code == 200, (kind, r.text)
        got[kind] = mails[-1] if kind == "email" else setup.hooks.calls[-1]
    # Teams: markdown characters escaped, no [label](link) of the reader's, no bare link
    card = json.loads(got["teams"].content)["attachments"][0]["content"]
    items = card["body"][1]["items"]
    assert {f["title"]: f["value"] for f in items[1]["facts"]} == {"Quelle": "Example Feed", "Kategorie": "Kritisch · Eigene Quelle"}
    box = next(x for x in items if x.get("style") == "emphasis")
    assert box["items"][0]["text"] == "Kommentar"
    quoted = box["items"][1]["text"]
    assert r"\[klick\]\(https\[:\]//evil\[.\]example/x\)" in quoted and r"\*fett\*" in quoted and r"\<b\>" in quoted
    assert "https://evil" not in json.dumps(card)
    # Discord: escaped, nobody pinged
    d = json.loads(got["discord"].content)
    fields = {f["name"]: f["value"] for f in d["embeds"][0]["fields"]}
    assert set(fields) == {"Quelle", "Kategorie", "Kommentar"} and fields["Kategorie"] == r"Kritisch · Eigene Quelle"
    com = fields["Kommentar"]
    assert d["allowed_mentions"] == {"parse": []} and "@everyone" not in com and "@here" not in com and "<@1" not in com and r"\<@" in com
    assert r"\[klick\]" in com and "https://evil" not in json.dumps(d) and "Bitte" not in d["content"]
    # Telegram: HTML escaped – the reader's <b> and <script> are text, the only tags are ours
    tg = json.loads(got["telegram"].content)
    assert tg["parse_mode"] == "HTML" and "&lt;script&gt;" in tg["text"] and "&lt;b&gt;x&lt;/b&gt;" in tg["text"] and "<script>" not in tg["text"]
    assert "evil[.]example" in tg["text"] and 'href="https://evil' not in tg["text"]
    assert "<b>Quelle:</b> Example Feed" in tg["text"] and "<b>Kategorie:</b> Kritisch · Eigene Quelle" in tg["text"] and "<b>Kommentar:</b>\nBitte prüfen" in tg["text"]
    # webhook: JSON, signed, the comment as data (defanged), its own event type
    w = got["webhook"]
    wb = json.loads(w.content)
    assert w.headers["X-Cobe-Event"] == "news.forward" and w.headers["X-Cobe-Signature"].startswith("sha256=")
    assert wb["type"] == "news.forward" and wb["forward"]["by"] == "Rudi <b>Rüssel</b>" and wb["forward"]["team"] == "T-webhook"
    assert wb["forward"]["comment"].startswith("Bitte prüfen <!channel>") and "https[:]//evil" in wb["forward"]["comment"]
    assert wb["forward"]["topics"] == [] and wb["forward"]["product"] == ""
    # mail: the comment never in a header, HTML escaped, kept as lines
    m = got["email"]
    assert m["to"] == ["soc@corp.example"] and "\n" not in m["subject"] and "evil" not in m["subject"] and "Bitte" not in m["subject"]
    assert m["subject"].startswith("[Cobe News] Weitergeleitet von Rudi <b>Rüssel</b>: Kritische Lücke")
    assert "&lt;script&gt;" in m["html"] and "<script>" not in m["html"] and "Rudi &lt;b&gt;Rüssel&lt;/b&gt;" in m["html"]
    assert 'href="https://evil' not in m["html"] and "white-space:pre-line" in m["html"]
    assert "> Zweite Zeile &amp; <script>" in m["text"]  # the text part is plain text


async def test_mail_header_injection_through_title_or_name(setup, mails):
    """A title or a display name with a line break (feed data, directory data) never adds a header."""
    a = setup.admin
    async with db.session() as s:
        await settings_store.put(s, "smtp", {**settings_store.DEFAULTS["smtp"], "host": "mail.corp.example", "from_addr": "news@corp.example"})
        u = await s.get(User, setup.rudi.id)
        u.display_name = "Rudi\r\nBcc: victim@corp.example"
        await s.commit()
    sid = await _story(title="Titel\r\nBcc: victim@corp.example")
    t = await _team("Mail", setup.rudi, channel=await _channel(a, type="email", recipients=["soc@corp.example"]))
    assert (await setup.c.post("/api/forward", json={"team_id": t, "story_id": sid, "comment": "x\r\nBcc: victim@corp.example"})).status_code == 200
    subject = mails[-1]["subject"]
    assert "\r" not in subject and "\n" not in subject
    # and the real message builder takes it as one header
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["Subject"] = notify.one_line(subject)
    assert msg.keys() == ["Subject"]


async def test_forward_a_finding_with_urgency_and_versions(setup):
    product, fid = await _finding()
    r = await setup.c.post("/api/forward", json={"team_id": setup.team, "product": product, "finding": fid, "comment": "Bitte heute patchen", "lang": "en"})
    assert r.status_code == 200, r.text
    blocks = setup.hooks.body()["blocks"]
    assert "forwarded a story to SOC" in blocks[0]["text"]["text"]
    # the card: the product (the catalogue's label), Vendor News as the source, the category; critical, affected, a fix:
    # 35 + 25 = 60 – "Now"; the own version with its verdict and the fix
    assert _fields(setup.hooks.body()) == {
        "Product": "TYPO3",
        "Source": "Vendor News",
        "Category": "Critical · Vendor News",
        "Urgency": "60 (Now)",
        "Your versions": "TYPO3 13.4.37 (Website): affected, fix 13.4.38",
    }
    assert any(b["type"] == "section" and b.get("text", {}).get("text") == "Comment:\nBitte heute patchen" for b in blocks)
    assert blocks[-1]["elements"][0]["url"] == "https://news.corp.example:8095/vendor?product=typo3&finding=nvd%3ACVE-2026-50030"


async def test_only_own_teams_only_known_things(setup, admin_client):
    sid = await _story()
    other_user = await add_user("olga", "reader")
    foreign = await _team("Fremd", other_user, channel=setup.channel)
    c = setup.c
    # a foreign team and an unknown one look the same
    r = await c.post("/api/forward", json={"team_id": foreign, "story_id": sid})
    assert r.status_code == 404 and _code(r) == "not_found"
    r = await c.post("/api/forward", json={"team_id": str(uuid.uuid4()), "story_id": sid})
    assert r.status_code == 404
    # an unknown story, a product not followed, a finding the product does not have
    assert (await c.post("/api/forward", json={"team_id": setup.team, "story_id": str(uuid.uuid4())})).status_code == 404
    assert (await c.post("/api/forward", json={"team_id": setup.team, "product": "panos", "finding": "nvd:CVE-2026-1"})).status_code == 404
    product, _ = await _finding()
    assert (await c.post("/api/forward", json={"team_id": setup.team, "product": product, "finding": "nvd:CVE-1999-0001"})).status_code == 404
    # the admin is in no team: no team to forward to
    assert (await admin_client.post("/api/forward", json={"team_id": setup.team, "story_id": sid})).status_code == 404
    assert setup.hooks.calls == []


async def test_the_reader_never_names_a_target(setup):
    sid = await _story()
    for extra in ({"url": "https://evil.example/hook"}, {"channel_id": setup.channel}, {"to": "x@evil.example"}, {"recipients": ["x@evil.example"]}):
        r = await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": sid, **extra})
        assert r.status_code == 422, extra
    # exactly one thing; the comment at most 1000 characters
    assert (await setup.c.post("/api/forward", json={"team_id": setup.team})).status_code == 422
    assert (await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": sid, "product": "typo3", "finding": "x"})).status_code == 422
    assert (await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": sid, "comment": "x" * 1001})).status_code == 422
    assert (await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": sid, "comment": "a\u0000b"})).status_code == 422
    assert setup.hooks.calls == []
    assert (await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": sid, "comment": "x" * 1000})).status_code == 200


async def test_no_channel_no_teams_and_signed_out(setup):
    sid = await _story()
    bare = await _team("Ohne Kanal", setup.rudi)
    r = await setup.c.post("/api/forward", json={"team_id": bare, "story_id": sid})
    assert r.status_code == 409 and _code(r) == "forward_no_channel"
    await _teams_on(False)
    r = await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": sid})
    assert r.status_code == 409 and _code(r) == "teams_off"
    async with make_client() as anon:
        assert (await anon.post("/api/forward", json={"team_id": setup.team, "story_id": sid})).status_code in (401, 403)
    assert setup.hooks.calls == []


async def test_channel_errors_are_said_and_may_be_tried_again(setup):
    sid = await _story()
    setup.hooks.status = 404
    r = await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": sid})
    assert r.status_code == 502 and r.json()["detail"] == {"code": "forward_failed", "detail": "rejected"}
    assert "hooks.slack.com" not in r.text
    # not sent: the same thing may go again at once (no "already forwarded")
    setup.hooks.status = 200
    assert (await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": sid})).status_code == 200
    # the channel's own state (the rules' backoff) is not touched by a forward
    async with db.session() as s:
        ch = await s.get(NotifyChannel, uuid.UUID(setup.channel))
        assert ch.failures == 0 and ch.last_error is None


async def test_limits_per_person_and_per_thing(setup, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(forward, "clock", lambda: now[0])
    stories = [await _story(url=f"https://news.example.org/{n}") for n in range(12)]
    # the same story to the same team: once within ten minutes – also from someone else
    assert (await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": stories[0]})).status_code == 200
    r = await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": stories[0]})
    assert r.status_code == 409 and _code(r) == "forward_duplicate" and 0 < r.json()["detail"]["retry_after"] <= 600
    olga = await add_user("olga", "reader")
    async with db.session() as s:
        s.add(TeamMember(team_id=uuid.UUID(setup.team), user_id=olga.id, origin="manual"))
        await s.commit()
    async with make_client() as oc:
        await sign_in(oc, olga)
        assert _code(await oc.post("/api/forward", json={"team_id": setup.team, "story_id": stories[0]})) == "forward_duplicate"
    # after ten minutes it may go again
    now[0] += 601
    assert (await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": stories[0]})).status_code == 200
    # ten an hour per person
    for n in range(1, 9):
        assert (await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": stories[n]})).status_code == 200, n
    r = await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": stories[10]})
    assert r.status_code == 429 and _code(r) == "forward_rate_limited" and r.json()["detail"]["retry_after"] > 0
    assert len(setup.hooks.calls) == 10
    # an hour after the first: one more
    now[0] += 3600 - 600
    assert (await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": stories[10]})).status_code == 200


def test_defang_and_clean():
    assert forward.defang("https://evil.example/a") == "https[:]//evil[.]example/a"
    assert forward.defang("mail a@b.example, Version 7.4.1, z.B. so") == "mail a@​b[.]example, Version 7.4.1, z.B. so"
    out = forward.clean_comment("eins\r\n\r\n\r\n\r\nzwei‮drei\x07\tvier")
    assert out == "eins\n\nzweidrei vier"
    assert len(forward.clean_comment("x" * 5000)) == forward.COMMENT_MAX

async def test_story_forward_names_the_own_versions(setup, monkeypatch):
    """A story whose details concern a followed product: the own versions go with it (as "betrifft deine Systeme")."""
    from app import story_details
    from app.models import StoryDetail

    sid = await _story()
    async with db.session() as s:
        s.add(StoryDetail(item_id=uuid.UUID(sid), status="ok", kind="nvd", ident="CVE-2026-0001", data={"kind": "nvd"}))
        await s.commit()
    rows = [{"product": "typo3", "label": "TYPO3", "versions": [{"id": "x", "version": "13.4.37", "label": "Website", "status": "affected", "fixed": "13.4.38"}]}]

    async def followed(db):  # noqa: ANN001, ANN202
        return []

    monkeypatch.setattr(story_details, "followed", followed)
    monkeypatch.setattr(story_details, "matches", lambda data, fol: rows)
    assert (await setup.c.post("/api/forward", json={"team_id": setup.team, "story_id": sid})).status_code == 200
    got = _fields(setup.hooks.body())
    # Produkt as the notifications' card has it (the followed product, its version and the fix), the own versions
    assert got["Produkt"] == "TYPO3 13.4.37 → 13.4.38" and got["Eure Versionen"] == "TYPO3 13.4.37 (Website): betroffen, Fix 13.4.38"


def _card_forward() -> forward.Forward:
    return forward.Forward(
        sender="Rudi", team="SOC", comment=forward.clean_comment(EVIL), title="PAN-OS: CVE-2026-1 – Lücke im Portal", summary="Erster Satz. Zweiter Satz. Dritter Satz, der nicht mehr passt.",
        url="https://security.paloaltonetworks.com/CVE-2026-1", link="https://news.corp.example:8095/vendor?product=panos&finding=x", severity="critical", source="Vendor News",
        published_at=datetime(2026, 11, 2, 8, 30, tzinfo=UTC), score={"value": 80, "level": "now"},
        versions=[{"product": "PAN-OS (Firewalls)", "version": "11.1.2", "label": "", "status": "affected", "fixed": "11.1.6-h3"}], kind="finding",
        product="PAN-OS (Firewalls)", topics=["exploited", "zeroday"], source_kind="vendor_news",
    )


def test_forward_card_in_every_chat_format():
    """The same card as the notifications (Produkt, Quelle, Kategorie, short description) plus Dringlichkeit, the own
    versions and the comment as a field of its own – in every chat format, the comment still plain text."""
    f = _card_forward()
    want = {"Produkt": "PAN-OS (Firewalls)", "Quelle": "Vendor News", "Kategorie": "Zero-Day · Aktiv ausgenutzt · Kritisch", "Dringlichkeit": "80 (Sofort)"}
    # ntfy / Gotify: plain lines "Label: value", the comment under "Kommentar:", the short description (two sentences)
    title, msg = forward.render_text(f, "de")
    assert title == "Rudi hat eine Meldung an SOC weitergeleitet"
    for k, v in want.items():
        assert f"\n{k}: {v}\n" in msg, k
    assert "\nEure Versionen: PAN-OS (Firewalls) 11.1.2: betroffen, Fix 11.1.6-h3\n" in msg
    assert "\nKommentar:\nBitte prüfen <!channel> @​here" in msg and "https://evil" not in msg
    assert "Erster Satz. Zweiter Satz." in msg and "Dritter" not in msg
    # Mattermost: fields (the comment a long field of its own, escaped line by line), no comment in the heading
    mm = forward.render_mattermost(f, "de")
    fields = {x["title"]: x for x in mm["attachments"][0]["fields"]}
    assert list(fields) == ["Produkt", "Quelle", "Kategorie", "Dringlichkeit", "Eure Versionen", "Kommentar"]
    assert fields["Kommentar"]["short"] is False and "@​" in fields["Kommentar"]["value"] and r"\[klick\]" in fields["Kommentar"]["value"]
    assert "\n" in fields["Kommentar"]["value"] and "Bitte" not in mm["text"] and "https://evil" not in json.dumps(mm)
    # Telegram: "<b>Label:</b> value" lines, the comment HTML-escaped
    tg = forward.render_telegram(f, "de")
    for k, v in want.items():
        assert f"<b>{k}:</b> {v}" in tg, k
    assert "<b>Kommentar:</b>\nBitte prüfen &lt;!channel&gt;" in tg and "<script>" not in tg
    # Discord: inline fields, the comment a field of its own; Teams: a FactSet, the comment in its own box
    d = forward.render_discord(f, "en")
    assert [x["name"] for x in d["embeds"][0]["fields"]] == ["Product", "Source", "Category", "Urgency", "Your versions", "Comment"]
    assert d["embeds"][0]["fields"][-1]["inline"] is False and d["allowed_mentions"] == {"parse": []}
    teams = forward.render_teams(f, "en")["attachments"][0]["content"]["body"][1]["items"]
    assert [x["title"] for x in teams[1]["facts"]] == ["Product", "Source", "Category", "Urgency", "Your versions"]
    assert teams[2]["style"] == "emphasis" and teams[2]["items"][0]["text"] == "Comment"
    # the webhook: topics and product as the notifications' stories have them
    w = forward.render_webhook(f, "Hook", "de", "d1")["forward"]
    assert w["topics"] == ["exploited", "zeroday"] and w["product"] == "PAN-OS (Firewalls)"
