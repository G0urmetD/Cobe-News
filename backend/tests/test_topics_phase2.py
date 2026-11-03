"""Topics, phase 2: the topic "Exploit veröffentlicht" (CISA's SSVC "poc", the wording, the hook for exploit
hints), topics in the notification rules (the live round, a topic that arrives later sent once, widening, the dry run,
the audit diff, the delivery log), topics for desktop notifications and Web Push, and "Betrifft unsere Produkte" (the
stored products of a story: from the details, recomputed when follows change, the backfill, the filter, the facet,
the badge, "Mein Team") – and migration 0026."""

import importlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text, update
from test_notify import SLACK, Hooks, _channel, _dispatch, _rule, _source, _stories

from app import db, news, notify, notify_api, story_details, vendor, webpush
from app.models import AuditEntry, DeliveryLog, NewsItem, NewsSource, NotifyDelivery, NotifyRule, StoryDetail, Team, TeamMember, TeamProduct, VendorAdvisory, VendorFollow, VendorKev
from tests.conftest import set_news

FIX = Path(__file__).parent / "fixtures" / "vendor"


def topics(title: str, teaser: str = "", source: str = "heise", ids=None, **kw) -> list[str]:  # noqa: ANN001, ANN003
    return news.topic_list(title, teaser, source, ids, **kw)


@pytest.fixture
def hooks(monkeypatch):
    h = Hooks()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(h.handler))
    return h


# ---------------------------------------------------------------- "Exploit veröffentlicht"


@pytest.mark.parametrize(
    ("title", "teaser", "expected"),
    [
        ("PoC exploit released for Fortinet flaw", "", ["poc"]),
        ("Proof-of-concept exploit for Citrix Bleed 2 published", "", ["poc"]),
        ("Exploit for Citrix Bleed 2 released", "", ["poc"]),
        ("Researchers publish PoC for CVE-2026-1234", "", ["poc"]),
        ("Exploit-Code für Lücke in Exchange veröffentlicht", "", ["poc"]),
        ("Exploit für kritische Lücke in Citrix Netscaler veröffentlicht", "", ["poc"]),
        ("Lücke in Exchange", "Forscher veröffentlichen Exploit für die Lücke.", ["poc"]),
        ("Router-Lücke", "Ein Exploit-Code ist öffentlich.", ["poc"]),
        ("Lücke in VPN", "A public PoC is available on GitHub.", ["poc"]),
        # denied, or "exploit" alone, or a patch published – no PoC
        ("Lücke in Exchange", "Ein öffentlicher Exploit ist bislang nicht bekannt.", []),
        ("Lücke in Exchange", "Kein öffentlicher Exploit.", []),
        ("Flaw in VPN", "A public exploit is not known.", []),
        ("Lücke in Exchange", "Ein öffentlicher Exploit ist verfügbar.", ["poc"]),
        ("Patch for router", "There is no public exploit.", []),
        ("Ein Exploit ist noch nicht öffentlich", "", []),
        ("Attackers could exploit the flaw", "", []),
        ("Microsoft hat gegen den Exploit Updates veröffentlicht", "", []),
        ("Fix released for exploit", "", []),
        ("Proof of Concept für Quantencomputer", "", []),
        # with a zero-day: both, in the badges' order
        ("Zero-day: PoC exploit released", "", ["zeroday", "exploited", "poc"]),
    ],
)
def test_poc_wording(title: str, teaser: str, expected: list[str]):
    assert topics(title, teaser) == expected


def test_poc_from_ssvc_and_exploit_hints_with_the_digest_rule():
    ex = {"CVE-2026-1111": news.SSVC_LABEL}
    # a CVE with a known exploit (the hook: exploit_cves) – also for a catalogue's story
    assert news.topics_of("Lücke CVE-2026-1111", "", "heise", ["CVE-2026-1111"], exploits=ex)["poc"] == {"kind": "exploit", "value": "CVE-2026-1111 · CISA SSVC"}
    assert "poc" in topics("CVE-2026-1111 · Vendor X", "", "cisa-kev", ["CVE-2026-1111"], exploits=ex)
    # a digest of many CVEs: only when its title or teaser names that CVE
    many = [f"CVE-2026-{n:04d}" for n in range(2000, 2010)] + ["CVE-2026-1111"]
    assert "poc" not in topics("Patchday: 11 Lücken", "", "heise", many, exploits=ex)
    assert "poc" in topics("Patchday: CVE-2026-1111 und weitere", "", "heise", many, exploits=ex)
    # the details' SSVC: "poc" counts (not for a digest), "active" is "exploited" (the details say so), not PoC
    det = {"ssvc": {"exploitation": "poc", "automatable": "no"}}
    assert news.topics_of("Lücke", "", "heise", ["CVE-2026-3333"], details=det)["poc"] == {"kind": "ssvc", "value": "CISA SSVC"}
    assert "poc" not in topics("Patchday", "", "heise", many, details=det)
    assert topics("Lücke", "", "heise", ["CVE-2026-3333"], details={"ssvc": {"exploitation": "active"}, "exploited": True}) == ["exploited"]
    assert news.TOPICS.index("poc") == news.TOPICS.index("exploited") + 1 and news.TOPICS_V >= 2


async def _cvelist(cve: str, exploitation: str) -> dict:
    return {
        "id": f"cvelist:{cve}",
        "source": "cvelist",
        "ident": cve,
        "title": cve,
        "summary": "",
        "url": f"https://www.cve.org/CVERecord?id={cve}",
        "cves": [cve],
        "cvss": None,
        "severity": "high",
        "exploited": exploitation == "active",
        "published_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
        "data": {"configs": [], "cna": [], "adp": [], "ssvc": {"exploitation": exploitation, "automatable": "no", "technical_impact": "total", "at": ""}},
    }


async def test_poc_from_a_stored_cvelist_record_and_its_change():
    src = await _source()
    (i,) = await _stories(src, "high", title="Lücke in Gateway")
    async with db.session() as s:
        await vendor.store(s, [await _cvelist("CVE-2026-0001", "none")], await vendor.current_index(s))
    async with db.session() as s:
        assert (await s.get(NewsItem, i.id)).topics == []
        assert await news.exploit_cves(s, ["cve-2026-0001"]) == {}
    # CISA's SSVC turns to "poc": the stories naming the CVE get the topic (vendor.store → news.retopic_cves)
    async with db.session() as s:
        await vendor.store(s, [await _cvelist("CVE-2026-0001", "poc")], await vendor.current_index(s))
    async with db.session() as s:
        assert (await s.get(NewsItem, i.id)).topics == ["poc"]
        assert await news.exploit_cves(s, ["CVE-2026-0001", "CVE-2026-9999"]) == {"CVE-2026-0001": "CISA SSVC"}
        assert await news.exploit_all(s) == {"CVE-2026-0001": "CISA SSVC"}
        # the drawer says why
        assert await news.story_topics(s, await s.get(NewsItem, i.id), "feed-x", None) == [{"topic": "poc", "kind": "exploit", "value": "CVE-2026-0001 · CISA SSVC"}]
    # a new story naming it gets it when stored
    async with db.session() as s:
        heise = await s.scalar(select(NewsSource).where(NewsSource.key == "heise"))
        entry = {"link": "https://www.heise.de/news/x.html", "title": "Gateway: Lücke CVE-2026-0001", "summary": "Update.", "date": datetime.now(UTC)}
        await news.store(s, heise, [entry])
        assert (await s.scalar(select(NewsItem).where(NewsItem.title == entry["title"]))).topics == ["poc"]
    # … and back to "none": the topic goes
    async with db.session() as s:
        await vendor.store(s, [await _cvelist("CVE-2026-0001", "none")], await vendor.current_index(s))
    async with db.session() as s:
        assert (await s.get(NewsItem, i.id)).topics == []


async def test_backfill_brings_poc_to_stored_stories():
    src = await _source()
    (i,) = await _stories(src, "high", title="Lücke in Gateway")
    async with db.session() as s:
        s.add(VendorAdvisory(id="cvelist:CVE-2026-0001", source="cvelist", ident="CVE-2026-0001", title="x", data={"ssvc": {"exploitation": "POC"}}, cves=["CVE-2026-0001"]))
        await s.execute(text("INSERT INTO counters (name, value) VALUES ('news_topics_v', 1) ON CONFLICT (name) DO UPDATE SET value = 1"))
        await s.commit()
    async with db.session() as s:
        assert await news.topics_due(s)  # the rule version of 0.1.46: every story again
        assert await news.backfill_topics(s) == 1
        assert (await s.get(NewsItem, i.id)).topics == ["poc"]


# ---------------------------------------------------------------- topics in the rules


async def _kev(*cves: str) -> None:
    async with db.session() as s:
        for c in cves:
            s.add(VendorKev(cve=c))
        await s.commit()
        await news.retopic_cves(s, cves)
        await s.commit()


async def _sent(channel_id: str) -> set[uuid.UUID]:
    async with db.session() as s:
        return set(await s.scalars(select(NotifyDelivery.item_id).where(NotifyDelivery.channel_id == uuid.UUID(channel_id))))


async def test_a_rule_with_topics_and_a_topic_that_arrives_later(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Ausgenutzt", [slack["id"]], severities=[], topics=["exploited", "poc", "exploited"])
    assert rule["topics"] == ["exploited", "poc"]  # in the order of the topics, once each
    assert (await admin_client.post("/api/admin/notify/rules", json={"name": "X", "channels": [slack["id"]], "topics": ["nonsense"]})).status_code == 422
    (plain,) = await _stories(src, "critical", title="Neue Version von Gateway")  # no topic: not for this rule
    hit = (await _stories(src, "high", title="Gateway: Lücke wird aktiv ausgenutzt"))[0]
    async with db.session() as s:  # as store() computes them
        await news.retopic(s, NewsItem.id.in_([plain.id, hit.id]))
        await s.commit()
    assert await _dispatch() == {"Slack": 1}
    assert await _sent(slack["id"]) == {hit.id}
    # the KEV lists the plain story's CVE later: it is "exploited" now – sent with the next round, once
    async with db.session() as s:
        await s.execute(update(NewsItem).where(NewsItem.id == plain.id).values(cves=["CVE-2026-4242"]))
        await s.commit()
    await _kev("CVE-2026-4242")
    assert await _dispatch() == {"Slack": 1}  # no FULL_EVERY wait: a topic change makes the round look again
    assert await _sent(slack["id"]) == {hit.id, plain.id}
    # another topic later, the rule saved again: nothing twice
    async with db.session() as s:
        await vendor.store(s, [await _cvelist("CVE-2026-4242", "poc")], await vendor.current_index(s))
    assert await _dispatch() == {}
    assert len(hooks.calls) == 2
    # the delivery log keeps the topics of what went out
    async with db.session() as s:
        items = [x for e in await s.scalars(select(DeliveryLog)) for x in e.items]
    assert sorted(x.get("topics", []) for x in items) == [["exploited"], ["exploited"]]


async def test_rule_topics_and_the_other_filters_and_kinds(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    await _rule(admin_client, "Kritisch und Ransomware", [slack["id"]], severities=["critical"], topics=["ransomware"], kinds=["news", "vendor_vuln"])
    a = (await _stories(src, "critical", title="Ransomware trifft Klinik"))[0]
    await _stories(src, "high", title="Ransomware trifft Stadtwerke")  # AND with the severity
    await _stories(src, "critical", title="Lücke in Gateway")  # AND with the topics
    async with db.session() as s:
        await news.retopic(s, text("true"))
        s.add(notify.VendorEvent(key=f"vuln:x:{uuid.uuid4()}", kind="vuln", product="x", severity="critical", data={"product": "X"}, baseline=False))
        await s.commit()
    assert await _dispatch() == {"Slack": 2}  # the topic counts for news only – the vulnerability comes as before
    assert await _sent(slack["id"]) == {a.id}


async def test_widening_and_narrowing_topics(admin_client, hooks):
    src = await _source()
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Zero-Days", [slack["id"]], severities=[], topics=["zeroday"])
    zd = (await _stories(src, "high", title="Chrome-Zero-Day"))[0]
    await _stories(src, "high", title="Neue Version von Gateway")  # under the old filter: not sent after widening
    async with db.session() as s:
        await news.retopic(s, text("true"))
        await s.commit()
    hooks.queue["hooks.slack.com"] = [httpx.Response(500)]
    assert await _dispatch() == {}  # failed: the zero-day waits for the retry
    body = {"name": "Zero-Days", "channels": [slack["id"]], "severities": [], "topics": []}  # every topic: widened
    assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body)).status_code == 200
    async with db.session() as s:
        r = await s.get(NotifyRule, uuid.UUID(rule["id"]))
        assert [x["topics"] for x in r.earlier] == [["zeroday"]]
        await s.execute(update(notify.NotifyChannel).values(next_try_at=datetime.now(UTC) - timedelta(seconds=1)))
        await s.commit()
    assert await _dispatch() == {"Slack": 1} and await _sent(slack["id"]) == {zd.id}
    (new,) = await _stories(src, "high", title="Neue Version von Browser")
    assert await _dispatch() == {"Slack": 1} and new.id in await _sent(slack["id"])
    # narrowing again is no widening
    body["topics"] = ["phishing"]
    assert (await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json=body)).status_code == 200
    async with db.session() as s:
        assert len((await s.get(NotifyRule, uuid.UUID(rule["id"]))).earlier) == 1


def test_widens_and_merge_with_topics():
    f = {"severities": None, "sources": None, "topics": ["zeroday"], "kinds": ["news"]}
    assert notify.widens(f, {**f, "topics": None}) and notify.widens(f, {**f, "topics": ["zeroday", "poc"]})
    assert not notify.widens(f, {**f, "topics": ["zeroday"]}) and not notify.widens({**f, "topics": None}, f)
    old = {"severities": None, "sources": None, "kinds": ["news"]}  # a filter kept from before topics existed
    assert not notify.widens(old, f) and notify.widens(f, old)
    rule = NotifyRule(name="x", severities=[], sources=[], kinds=["news"], earlier=[], active_since=datetime.now(UTC) - timedelta(days=1))
    for n in range(notify.EARLIER_MAX + 1):
        notify.widened(rule, {**f, "topics": ["zeroday", "poc"] if n == 0 else ["poc", "ot"]}, n, datetime.now(UTC))
    assert rule.earlier[0]["topics"] == ["poc"]  # merged: stricter (the intersection)
    assert notify.rule_filter(NotifyRule(severities=[], sources=[], topics=["poc", "zeroday", "bogus"], kinds=["news"]))["topics"] == ["poc", "zeroday"]


async def test_dry_run_with_topics(admin_client):
    src = await _source()
    await _stories(src, "high", title="Chrome-Zero-Day")
    await _stories(src, "high", title="Neue Version von Gateway")
    async with db.session() as s:
        await news.retopic(s, text("true"))
        await s.commit()
    notify_api._dry_at.clear()
    got = (await admin_client.post("/api/admin/notify/rules/dry-run", json={"kinds": ["news"], "topics": ["zeroday", "ot"]})).json()
    assert got["count"] == 1 and got["items"][0]["title"] == "Chrome-Zero-Day"
    assert got["items"][0]["topics"] == ["zeroday"] and got["items"][0]["match"]["topic"] is True
    notify_api._dry_at.clear()
    got = (await admin_client.post("/api/admin/notify/rules/dry-run", json={"kinds": ["news"]})).json()
    assert got["count"] == 2 and all(x["match"]["topic"] is False and x["topics"] == [] for x in got["items"])


async def test_rule_topics_in_the_audit_diff(admin_client):
    slack = await _channel(admin_client, name="Slack", type="slack", url=SLACK)
    rule = await _rule(admin_client, "Regel", [slack["id"]])
    assert rule["topics"] == []
    r = await admin_client.put(f"/api/admin/notify/rules/{rule['id']}", json={"name": "Regel", "channels": [slack["id"]], "topics": ["poc", "zeroday"]})
    assert r.status_code == 200 and r.json()["topics"] == ["zeroday", "poc"]
    async with db.session() as s:
        e = await s.scalar(select(AuditEntry).where(AuditEntry.action == "rule.changed"))
    assert e.details["changes"]["topics"] == {"from": [], "to": ["zeroday", "poc"]}
    assert [x["topics"] for x in (await admin_client.get("/api/admin/notify/rules")).json()] == [["zeroday", "poc"]]


# ---------------------------------------------------------------- desktop and Web Push


async def test_desktop_topics_for_the_tab_and_web_push(reader_client, monkeypatch):
    await set_news(enabled=True)
    assert (await reader_client.get("/api/me/desktop")).json()["topics"] == []  # an older choice: every topic
    r = await reader_client.put("/api/me/desktop", json={"enabled": True, "severities": [], "sources": [], "topics": ["exploited"]})
    assert r.status_code == 200 and r.json()["topics"] == ["exploited"]
    assert (await reader_client.put("/api/me/desktop", json={"enabled": True, "topics": ["nonsense"]})).status_code == 422
    src = await _source()
    first = (await reader_client.get("/api/news/recent")).json()["cursor"]
    await _stories(src, "low", title="Lücke wird aktiv ausgenutzt")
    await _stories(src, "critical", title="Neue Version von Gateway")
    async with db.session() as s:
        await news.retopic(s, text("true"))
        await s.commit()
    got = (await reader_client.get("/api/news/recent", params={"after": first, "mine": "true"})).json()
    assert [x["title"] for x in got["items"]] == ["Lücke wird aktiv ausgenutzt"]  # every severity, only the topic
    assert len((await reader_client.get("/api/news/recent", params={"after": first})).json()["items"]) == 2
    # Web Push sends exactly the same (api.desktop_filter)
    from test_push import FCM, Browser, PushService

    service = PushService()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(service.handler))
    async with db.session() as s:
        await s.execute(update(NewsItem).values(seq=NewsItem.seq + 100))  # arrived after the subscription
        await s.execute(text("UPDATE counters SET value = value + 100 WHERE name = 'news_seq'"))
        await s.commit()
    b = Browser()
    async with db.session() as s:
        await webpush.vapid(s)
    assert (await reader_client.post("/api/me/push", json={"endpoint": FCM, "keys": b.keys()})).status_code == 200
    async with db.session() as s:
        await s.execute(text("UPDATE push_subscriptions SET cursor = 0"))
        await s.commit()
    async with db.session() as s:
        assert await webpush.dispatch(s) == {"sent": 1, "failed": 0}
    assert [b.read(x.content)["title"] for x in service.requests] == ["Lücke wird aktiv ausgenutzt"]


# ---------------------------------------------------------------- "Betrifft unsere Produkte"


def _gitlab_details() -> dict:
    return story_details.parse_csaf((FIX / "csaf_wid.json").read_bytes(), "bsi")


async def _feed() -> NewsSource:
    async with db.session() as s:
        got = await s.scalar(select(NewsSource).where(NewsSource.key == "feed-x"))
    return got or await _source()


async def _story_with_details(title: str = "GitLab: Mehrere Schwachstellen", details: dict | None = None) -> uuid.UUID:
    (i,) = await _stories(await _feed(), "high", title=title)
    async with db.session() as s:
        s.add(StoryDetail(item_id=i.id, kind="bsi", status="ok", data=details or _gitlab_details(), fetched_at=datetime.now(UTC)))
        await s.commit()
    return i.id


async def _products(iid: uuid.UUID) -> list[str]:
    async with db.session() as s:
        return list((await s.get(NewsItem, iid, populate_existing=True)).products)


async def _round() -> int | None:
    async with db.session() as s:
        return await story_details.products_round(s)


async def test_products_backfill_follow_changes_and_versions(admin_client):
    iid = await _story_with_details()
    other = await _story_with_details("Ohne Details")
    async with db.session() as s:
        await s.execute(update(StoryDetail).where(StoryDetail.item_id == other).values(data=None, status="none"))
        await s.execute(update(NewsItem).where(NewsItem.id == other).values(products=["gitlab"]))  # stale: goes with the backfill
        await s.commit()
    assert await _round() == 1  # nothing followed: the backfill clears what no details back
    assert await _products(iid) == [] and await _products(other) == []
    assert await _round() is None  # nothing changed since: not even the signatures are computed
    # GitLab followed (no versions): the story concerns it
    assert (await admin_client.put("/api/vendor/follows/gitlab", json={"enabled": True})).status_code == 200
    assert await _round() == 1 and await _products(iid) == ["gitlab"]
    assert await _round() is None
    # a version that is not affected: no longer ours to worry about – then an affected one as well
    v = await admin_client.post("/api/vendor/follows/gitlab/versions", json={"version": "19.4.5"})
    assert v.status_code == 200
    assert await _round() == 1 and await _products(iid) == []
    assert (await admin_client.post("/api/vendor/follows/gitlab/versions", json={"version": "19.5.0"})).status_code == 200
    assert await _round() == 1 and await _products(iid) == ["gitlab"]
    # unfollowed: out of every list without looking at the details
    async with db.session() as s:
        await s.execute(update(NewsItem).where(NewsItem.id == other).values(products=["gitlab", "other-product"]))
        await s.commit()
    assert (await admin_client.delete("/api/vendor/follows/gitlab")).status_code == 200
    assert await _round() == 2
    assert await _products(iid) == [] and await _products(other) == ["other-product"]


async def test_products_when_the_details_arrive(monkeypatch, admin_client):
    await set_news(enabled=True, details=True)
    assert (await admin_client.put("/api/vendor/follows/gitlab", json={"enabled": True})).status_code == 200
    async with db.session() as s:
        src = await s.scalar(select(NewsSource).where(NewsSource.key == "bsi-csw"))
        url = "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4115"
        await news.store(s, src, [{"link": url, "title": "[hoch] GitLab: Mehrere Schwachstellen", "summary": "x", "date": datetime.now(UTC)}])
    details = _gitlab_details()

    async def build(*a, **kw):  # noqa: ANN002, ANN003
        return details

    monkeypatch.setattr(story_details, "build", build)
    monkeypatch.setattr(story_details, "plan", lambda *a: ("bsi", "WID-SEC-2026-4115", "https://example.org/csaf.json"))
    async with db.session() as s:
        assert await story_details.enrich_round(s) == 1
        assert (await s.scalar(select(NewsItem))).products == ["gitlab"]


async def _team_of(user_id: uuid.UUID, product: str) -> None:
    async with db.session() as s:
        await s.execute(text("""INSERT INTO settings (key, value) VALUES ('teams', '{"enabled": true}') ON CONFLICT (key) DO UPDATE SET value = '{"enabled": true}'"""))
        t = Team(name="Netz")
        s.add(t)
        await s.flush()
        s.add(TeamMember(team_id=t.id, user_id=user_id))
        f = await s.scalar(select(VendorFollow).where(VendorFollow.product == product))
        s.add(TeamProduct(team_id=t.id, follow_id=f.id))
        await s.commit()


async def test_news_filter_facet_badge_and_team_scope(admin_client, reader_client):
    await set_news(enabled=True)
    iid = await _story_with_details()
    await _stories(await _feed(), "critical", title="Chrome-Zero-Day")
    async with db.session() as s:
        await news.retopic(s, text("true"))
        await s.commit()
    page = (await reader_client.get("/api/news", params={"state": "all"})).json()
    assert page["ours_on"] is False and page["counts"]["ours"] == 0
    assert (await reader_client.get("/api/news", params={"state": "all", "ours": "true"})).json()["items"] == []
    for key in ("gitlab", "fortios"):
        assert (await admin_client.put(f"/api/vendor/follows/{key}", json={"enabled": True})).status_code == 200
    await _round()
    page = (await reader_client.get("/api/news", params={"state": "all"})).json()
    assert page["ours_on"] is True and page["counts"]["ours"] == 1
    card = next(x for x in page["items"] if x["id"] == str(iid))
    assert card["products"] == [{"key": "gitlab", "label": "GitLab"}]
    assert next(x for x in page["items"] if x["id"] != str(iid))["products"] == []
    got = (await reader_client.get("/api/news", params={"state": "all", "ours": "true"})).json()
    assert [x["id"] for x in got["items"]] == [str(iid)]
    # the topics' facets follow the product filter; the product count follows the topic filter
    assert sum(got["counts"]["topics"].values()) == 0
    assert (await reader_client.get("/api/news", params={"state": "all", "topic": "zeroday"})).json()["counts"]["ours"] == 0
    assert (await reader_client.get(f"/api/news/{iid}")).json()["products"] == [{"key": "gitlab", "label": "GitLab"}]
    # "Mein Team": only the products of the person's teams – FortiOS here, not GitLab
    await _team_of(reader_client.user.id, "fortios")
    team = (await reader_client.get("/api/news", params={"state": "all", "ours": "true", "scope": "team"})).json()
    assert team["items"] == [] and team["counts"]["ours"] == 0 and team["ours_on"] is True
    assert (await reader_client.get("/api/news", params={"state": "all", "ours": "true"})).json()["counts"]["ours"] == 1
    # read-all of the filter: only the stories about our products
    r = await reader_client.post("/api/news/read-all", json={"ours": True, "upto": page["upto"]})
    assert r.json() == {"marked": 1}
    assert [x["title"] for x in (await reader_client.get("/api/news")).json()["items"]] == ["Chrome-Zero-Day"]


# ---------------------------------------------------------------- the migration


async def test_migration_0026_up_and_down():
    from alembic import command

    mod = importlib.import_module("app.migrations.versions.0026_topics_phase2")
    assert (mod.revision, mod.down_revision) == ("0026", "0025")

    def cols(conn, table: str) -> set[str]:  # noqa: ANN001
        return {r[0] for r in conn.execute(text(f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table}'"))}

    def step(conn):  # noqa: ANN001, ANN202
        conn.execute(text("""INSERT INTO settings (key, value) VALUES ('news_products', '{"v": 1}')"""))
        command.downgrade(db.alembic_config(conn), "0025")
        down = (cols(conn, "news_items"), cols(conn, "notify_rules"), conn.execute(text("SELECT count(*) FROM settings WHERE key = 'news_products'")).scalar())
        command.upgrade(db.alembic_config(conn), "0026")
        idx = {r[0] for r in conn.execute(text("SELECT indexname FROM pg_indexes WHERE tablename = 'news_items'"))}
        default = conn.execute(text("SELECT column_default, is_nullable FROM information_schema.columns WHERE table_name = 'notify_rules' AND column_name = 'topics'")).one()
        return down, cols(conn, "news_items"), idx, default

    async with db.engine().connect() as conn:
        trans = await conn.begin()
        try:
            down, up, idx, default = await conn.run_sync(step)
        finally:
            await trans.rollback()
    assert "products" not in down[0] and "topics" not in down[1] and down[2] == 0
    assert "products" in up and "ix_news_items_products" in idx
    assert default[0].startswith("'[]'::jsonb") and default[1] == "NO"


def test_topic_lists_agree():
    """The literals of the API models name exactly news.TOPICS."""
    import typing

    from app import api, api_v1, auth_api

    assert typing.get_args(api.Topic) == news.TOPICS == typing.get_args(api_v1.Topic) == typing.get_args(notify_api.Topic)
    assert typing.get_args(typing.get_args(auth_api.DesktopIn.model_fields["topics"].annotation)[0]) == news.TOPICS
    assert set(notify.CARD_LABELS["de"]["topics"]) == set(news.TOPICS) == set(notify.CARD_LABELS["en"]["topics"])
    assert json.dumps(news.TOPICS)


# ---------------------------------------------------------------- one follow edit: only the details that can concern it


def _fixture_details() -> list[dict]:
    """Details as the stories keep them: the CSAF documents of the fixtures (BSI, Cisco, Siemens, Fortinet), Palo Alto's
    CVE record, and the trimmed CNA/NVD records of the catalogue accuracy test – each as an NVD and a cvelist match."""
    out = [
        story_details.parse_csaf((FIX / name).read_bytes(), kind)
        for name, kind in (("csaf_wid.json", "bsi"), ("csaf_cisco.json", "cisco"), ("csaf_siemens.json", "siemens"), ("fortinet_csaf_wad.json", "fortinet"))
    ]
    out.append(story_details.parse_cve5((FIX / "cve5_pan.json").read_bytes()))
    out.append(story_details.parse_csaf((FIX.parent / "structured" / "csaf_cisco_asa.json").read_bytes(), "cisco", story_details.STORE_PRODUCTS))
    records = json.loads((FIX / "accuracy_records.json").read_text())["records"]
    for rec in records.values():
        out.append({"kind": "nvd", "match": [{"source": "nvd", "data": rec}]})
        out.append({"kind": "cvelist", "match": [{"source": "cvelist", "data": rec}]})
    return out


def test_the_prefilter_never_drops_a_story_the_matcher_finds():
    """Every catalogue product against every fixture's details: whenever the matcher finds the product, its anchors are
    in the details' text – the SQL prefilter (story_details.anchors) narrows, it never decides."""
    from app import vendor_catalog

    details = _fixture_details()
    texts = [json.dumps(d, ensure_ascii=False) for d in details]
    found = skipped = 0
    for p in vendor_catalog.load()["products"]:
        words = story_details.anchors(p)
        if words is None:
            skipped += 1
            continue
        for d, raw in zip(details, texts, strict=True):
            if story_details.matches(d, [(p, [])]):
                found += 1
                assert story_details.anchor_hit(words, raw), (p["key"], words)
    assert found > 20 and skipped < 30  # the fixtures do concern products – and almost every product has anchors


async def test_a_follow_edit_reads_only_the_details_that_can_concern_it_with_the_same_result(admin_client, monkeypatch):
    details = _fixture_details()
    ids = [await _story_with_details(f"Story {n}", d) for n, d in enumerate(details)]
    for key in ("gitlab", "panos", "msexchange", "fortios"):
        assert (await admin_client.put(f"/api/vendor/follows/{key}", json={"enabled": True})).status_code == 200
    assert (await admin_client.post("/api/vendor/follows/panos/versions", json={"version": "12.2.5"})).status_code == 200
    await _round()
    before = {i: await _products(i) for i in ids}
    assert any(before.values())
    seen: list[int] = []
    real = story_details.products_of

    def spy(d, fol):  # noqa: ANN001, ANN202
        seen.append(1)
        return real(d, fol)

    monkeypatch.setattr(story_details, "products_of", spy)
    # a version of one product (an affected one, beside a fixed one): only the stories whose details name it are judged …
    assert (await admin_client.post("/api/vendor/follows/panos/versions", json={"version": "12.2.1"})).status_code == 200
    await _round()
    assert 0 < len(seen) < len(ids) / 3
    partial = {i: await _products(i) for i in ids}
    assert partial != before  # the edit did change lists
    # … with exactly what the full pass gives
    async with db.session() as s:
        await story_details.reproduct(s, await story_details.followed(s))
    full = {i: await _products(i) for i in ids}
    assert partial == full
    # a story that listed the product and whose details no longer name it still leaves the list
    async with db.session() as s:
        await s.execute(update(StoryDetail).where(StoryDetail.item_id == ids[0]).values(data={"kind": "bsi", "products": []}))
        await s.execute(update(NewsItem).where(NewsItem.id == ids[0]).values(products=["panos"]))
        await s.commit()
    assert (await admin_client.post("/api/vendor/follows/panos/versions", json={"version": "11.2.0"})).status_code == 200
    await _round()
    assert "panos" not in await _products(ids[0])
