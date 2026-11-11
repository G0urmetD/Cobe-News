"""Where a Vendor News event's links lead (notify.vendor_path, 0.1.56): a rule's mail, Teams card and webhook – and the
person's own messages (personal.event_path) – open the product's drawer at what the event is about: a vulnerability at
its finding, a new version or an end of support at the versions, a revised advisory at the changes, a watched CVE in the
list of watched CVEs. Before, a rule's channels always linked the bare product (the drawer at "Schwachstellen" – for a
version event an empty list)."""

import html
import json
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from app import db, notify, personal
from app.models import VendorEvent, VendorFollow

BASE = "https://news.corp.example:8095"
TEAMS = "https://prod-01.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=secret"
HOOK = "https://n8n.corp.example/webhook/cobe-news"
SCOPE = "vuln:panos:11.2.4-h23"


def _ev(kind: str, key: str, **data) -> VendorEvent:  # noqa: ANN003
    scope = SCOPE if kind == "vuln" else None
    base = {"product": "PAN-OS", "version": "11.2.4-h23", "line": "11.2"}
    return VendorEvent(id=uuid.uuid4(), key=key, kind=kind, product="panos", severity="high", scope=scope, created_at=datetime.now(UTC), data={**base, **data})


EVENTS = {
    "vuln": (
        lambda: _ev("vuln", f"{SCOPE}:paloalto:CVE-2026-0101", status="affected", ident="CVE-2026-0101", headline="Befund", url="https://security.paloaltonetworks.com/CVE-2026-0101"),
        "/vendor?product=panos&finding=paloalto%3ACVE-2026-0101",
    ),
    "exploited": (
        lambda: _ev("vuln", f"exploited:{SCOPE}:paloalto:CVE-2026-0102", status="affected", ident="CVE-2026-0102", headline="Befund", now_exploited=True, exploited=True),
        "/vendor?product=panos&finding=paloalto%3ACVE-2026-0102",
    ),
    "version": (lambda: _ev("version", "version:panos:11.2.4-h23:11.2.16", latest="11.2.16"), "/vendor?product=panos&view=versions"),
    "eol": (lambda: _ev("eol", "eol:panos:11.2:30", stage="30", days=30, eol_from="2027-05-02"), "/vendor?product=panos&view=versions"),
    "change": (lambda: _ev("change", "change:panos:paloalto:CVE-2026-0103:2", ident="CVE-2026-0103", revision=2, diff=[], impact=[]), "/vendor?product=panos&view=changes"),
}
WATCH = (
    lambda: VendorEvent(id=uuid.uuid4(), key="watch:CVE-2026-0104:fix", kind="watch", product="", severity="high", created_at=datetime.now(UTC), data={"cve": "CVE-2026-0104", "what": "fix", "fixed": ["1.2"]}),
    "/watch?cve=CVE-2026-0104",
)


@pytest.mark.parametrize("name", [*EVENTS, "watch"])
def test_every_way_links_to_the_event_itself(name):
    make, path = WATCH if name == "watch" else EVENTS[name]
    ev = make()
    assert notify.vendor_path(ev) == path
    assert personal.event_path(ev) == path  # the person's messages: the same place
    story = notify.vendor_story(ev, "de")
    assert story.link == BASE + path
    # one story: the message's button ("Cobe News öffnen") opens it as well
    assert notify.overview_link([story], 1) == BASE + path
    _, text, body = notify.render_mail("Kritisch / Hoch", [story], 1, "de")
    assert BASE + path in text and html.escape(BASE + path) in body
    assert BASE + path in json.dumps(notify.render_teams("Kritisch / Hoch", [story], 1, "de"))
    assert notify.render_webhook("n8n", ["Kritisch / Hoch"], [story], 1, "de")["stories"][0]["link"] == BASE + path


def test_several_events_of_one_product_keep_what_they_share():
    v1, v2 = (notify.vendor_story(EVENTS[k][0](), "de") for k in ("version", "eol"))
    assert notify.overview_link([v1, v2], 2) == f"{BASE}/vendor?product=panos&view=versions"
    a, b = (notify.vendor_story(EVENTS[k][0](), "de") for k in ("vuln", "exploited"))
    assert notify.overview_link([a, b], 2) == f"{BASE}/vendor?product=panos"  # two findings: the product
    same = notify.vendor_story(EVENTS["vuln"][0](), "de"), notify.vendor_story(_ev("vuln", f"rated:critical:{SCOPE}:paloalto:CVE-2026-0101"), "de")
    assert notify.overview_link(list(same), 2) == f"{BASE}/vendor?product=panos&finding=paloalto%3ACVE-2026-0101"  # one finding
    assert notify.overview_link([v1, a], 2) == f"{BASE}/vendor?product=panos"  # a version and a finding: the product
    assert notify.overview_link([v1, v2], 3) == f"{BASE}/vendor"  # one not shown: unknown


async def test_a_rules_mail_teams_card_and_webhook_open_the_event(admin_client, monkeypatch):
    """Through a real round (notify.dispatch): one rule, three channels, one event at a time."""
    mails: list[tuple[str, str]] = []

    async def send_mail(cfg, to, subject, text, body):  # noqa: ANN001, ANN202
        mails.append((text, body))

    posts: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        posts.append(req)
        return httpx.Response(202 if req.url.host.endswith("azure.com") else 200, text="ok")

    monkeypatch.setattr(notify, "send_mail", send_mail)
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(handler))
    async with db.session() as s:
        old = datetime.now(UTC) - timedelta(days=30)
        s.add(VendorFollow(product="panos", enabled=True, created_at=old, updated_at=old, baseline_at=old, enabled_at=old))
        await s.commit()
    ids = []
    for body in ({"name": "Mail", "type": "email", "recipients": ["soc@corp.example"]}, {"name": "Teams", "type": "teams", "url": TEAMS}, {"name": "n8n", "type": "webhook", "url": HOOK}):
        r = await admin_client.post("/api/admin/notify/channels", json=body)
        assert r.status_code == 200, r.text
        ids.append(r.json()["id"])
    r = await admin_client.post("/api/admin/notify/rules", json={"name": "Kritisch / Hoch", "channels": ids, "kinds": list(notify.VENDOR_KINDS), "severities": ["critical", "high"]})
    assert r.status_code == 200, r.text
    for name in ("vuln", "version", "eol", "change"):
        make, path = EVENTS[name]
        mails.clear()
        posts.clear()
        async with db.session() as s:
            s.add(make())
            await s.commit()
        async with db.session() as s:
            await notify.dispatch(s)
        url = BASE + path
        assert len(mails) == 1, name
        text, body = mails[0]
        assert url in text and html.escape(url) in body, name
        # no link to the bare product left (the story's own "Artikel öffnen" may lead to the vendor's page)
        assert f"{BASE}/vendor?product=panos\n" not in text and html.escape(f"{BASE}/vendor?product=panos") + '"' not in body, name
        teams = next(p for p in posts if p.url.host.endswith("azure.com"))
        hook = json.loads(next(p for p in posts if p.url.host == "n8n.corp.example").content)
        assert url in teams.content.decode(), name
        assert hook["stories"][0]["link"] == url, name
        q = parse_qs(urlsplit(url).query)
        assert q["product"] == ["panos"] and (q.get("view") or q.get("finding")), name
