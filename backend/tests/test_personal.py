"""Per-person routing and personal notifications (app/personal.py, app/personal_api.py, the routing in
app/teams_api.py): who of a team gets a product, the three ways (e-mail, desktop push, a Teams Workflows webhook) –
each only for assigned, active people with the way on and allowed by an admin –, nothing old (before switching on,
before the assignment, baselines), exactly once (two rounds, a crash between claim and send), one digest per person
and round, the Teams URL (Microsoft hosts only, public addresses only, stored encrypted, never returned), the own
settings only. No mail server, Microsoft or push service is contacted: mails are recorded, HTTP is a MockTransport."""

import json
import socket
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import add_user, make_client, sign_in
from sqlalchemy import func, select, update
from test_push import FCM, Browser

from app import db, netaddr, notify, personal, personal_api, teams
from app import settings as settings_store
from app.auth.directory import DirectoryUser
from app.models import (
    PersonDelivery,
    PersonNotify,
    PersonRoute,
    PushSubscription,
    Team,
    TeamGroup,
    TeamMember,
    TeamProduct,
    TeamProductMember,
    User,
    VendorEvent,
    VendorFollow,
)

TEAMS_URL = "https://prod-12.westeurope.logic.azure.com:443/workflows/0123abcd/triggers/manual/paths/invoke?api-version=2016-06-01&sig=TopSecretSignature123"
HOUR = timedelta(hours=1)


# ---------------------------------------------------------------- fixtures and helpers


@pytest.fixture
def mails(monkeypatch):
    sent: list[dict] = []
    fail: list[str] = []

    async def send_mail(cfg, to, subject, text, body):  # noqa: ANN001, ANN202
        if fail:
            raise notify.NotifyError(fail[0])
        sent.append({"to": to, "subject": subject, "text": text, "html": body})

    monkeypatch.setattr(notify, "send_mail", send_mail)
    return type("M", (), {"sent": sent, "fail": fail})


@pytest.fixture
def web(monkeypatch):
    """Teams (logic.azure.com) and the push service (FCM) – recorded, answered with `status`."""

    class W:
        requests: list[httpx.Request] = []
        status = 202

        def handler(self, req: httpx.Request) -> httpx.Response:
            self.requests.append(req)
            return httpx.Response(self.status)

        def to(self, host: str) -> list[httpx.Request]:
            return [r for r in self.requests if r.url.host.endswith(host)]

    w = W()
    w.requests = []
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(w.handler))
    return w


async def _switch(enabled: bool = True, since: datetime | None = None, **ways) -> None:
    """Teams and the ways an admin allows (all, unless named off) – allowed since `since` (two hours ago)."""
    at = (since or datetime.now(UTC) - 2 * HOUR).isoformat()
    async with db.session() as s:
        await settings_store.put(
            s,
            "teams",
            {"enabled": enabled, "welcome_mail": False, **{f"personal_{w}": ways.get(w, True) for w in personal.WAYS}, **{f"personal_{w}_since": at for w in personal.WAYS}},
        )
        await settings_store.put(s, "smtp", {**settings_store.DEFAULTS["smtp"], "host": "mail.corp.example", "from_addr": "news@corp.example"})
        await s.commit()


async def _person(name: str, *, email: bool = True, active: bool = True) -> User:
    return await add_user(name, "reader", email=f"{name}@corp.example" if email else None, is_active=active)


async def _team(people: list[User], products=("panos",), name: str = "Security") -> tuple[uuid.UUID, dict[str, uuid.UUID]]:
    """A team (members added an hour ago) with products assigned an hour ago, for all members."""
    past = datetime.now(UTC) - HOUR
    async with db.session() as s:
        t = Team(name=name)
        s.add(t)
        await s.flush()
        for u in people:
            s.add(TeamMember(team_id=t.id, user_id=u.id, origin="manual", added_at=past))
        tps = {}
        for key in products:
            f = await s.scalar(select(VendorFollow).where(VendorFollow.product == key))
            if f is None:
                f = VendorFollow(product=key)
                s.add(f)
                await s.flush()
            tp = TeamProduct(team_id=t.id, follow_id=f.id, all_members=True, added_at=past)
            s.add(tp)
            await s.flush()
            tps[key] = tp.id
        await s.commit()
        return t.id, tps


async def _ways(u: User, *, email=False, desktop=False, teams_=False, since=None, **kw) -> None:
    """The person's settings as if switched on `since` (an hour ago)."""
    since = since or datetime.now(UTC) - HOUR
    async with db.session() as s:
        p = await s.get(PersonNotify, u.id) or PersonNotify(user_id=u.id, kinds=list(personal.KINDS), min_severity="info", state_email={}, state_desktop={}, state_teams={})
        p.email_on, p.desktop_on, p.teams_on = email, desktop, teams_
        p.email_since = p.desktop_since = p.teams_since = since
        if teams_:
            from app.crypto import encrypt_str

            p.teams_url_enc, p.teams_host = encrypt_str(TEAMS_URL), "prod-12.westeurope.logic.azure.com"
        for k, v in kw.items():
            setattr(p, k, v)
        s.add(p)
        await s.commit()


_n = iter(range(1, 10_000))


async def _event(product: str = "panos", *, kind: str = "vuln", severity: str = "high", baseline: bool = False, at: datetime | None = None, title: str = "") -> uuid.UUID:
    k = next(_n)
    async with db.session() as s:
        scope = f"vuln:{product}:10.2.3"
        ev = VendorEvent(
            key=f"{scope}:ADV-{k}" if kind == "vuln" else f"{kind}:{product}:{k}",
            kind=kind,
            product=product,
            severity=severity,
            baseline=baseline,
            scope=scope if kind == "vuln" else None,
            data={"product": "PAN-OS", "version": "10.2.3", "status": "affected", "ident": f"CVE-2026-{1000 + k}", "headline": title or f"Lücke {k}", "url": "https://security.example.com/adv"}
            if kind == "vuln"
            else {"product": "PAN-OS", "version": "10.2.3", "latest": "10.2.9", "line": "10.2"},
            created_at=at or datetime.now(UTC),
        )
        s.add(ev)
        await s.commit()
        return ev.id


async def _dispatch() -> dict:
    async with db.session() as s:
        return await personal.dispatch(s)


async def _rows(**where) -> list[PersonDelivery]:
    async with db.session() as s:
        q = select(PersonDelivery)
        for k, v in where.items():
            q = q.where(getattr(PersonDelivery, k) == v)
        return list(await s.scalars(q))


async def _subscribe(u: User) -> Browser:
    b = Browser()
    async with db.session() as s:
        k = b.keys()
        s.add(PushSubscription(user_id=u.id, endpoint=f"{FCM}-{u.username}", p256dh=k["p256dh"], auth=k["auth"], lang="de", cursor=0))
        await s.commit()
    return b


# ---------------------------------------------------------------- routing (admin)


async def test_routing_all_members_or_chosen_ones_and_leaving_drops_it(admin_client, mails):
    await _switch()
    a, b, c = await _person("anja"), await _person("bert"), await _person("cleo")
    tid, _ = await _team([a, b, c], products=("panos", "cisco-asa"))
    for u in (a, b, c):
        await _ways(u, email=True)
    # A and B get Palo Alto, A and C get Cisco
    r = await admin_client.put(f"/api/admin/teams/{tid}/routing", json={"product": "panos", "all_members": False, "members": [str(a.id), str(b.id)]})
    assert r.status_code == 200, r.text
    prods = {p["key"]: p for p in r.json()["products"]}
    assert prods["panos"]["all_members"] is False and {x["username"] for x in prods["panos"]["people"]} == {"anja", "bert"}
    assert prods["cisco-asa"]["all_members"] is True and prods["cisco-asa"]["people"] == []
    r = await admin_client.put(f"/api/admin/teams/{tid}/routing", json={"product": "cisco-asa", "all_members": False, "members": [str(a.id), str(c.id)]})
    assert r.status_code == 200
    # the members part says who gets what (read-only)
    items = {m["username"]: m["products"] for m in (await admin_client.get(f"/api/admin/teams/{tid}/members")).json()["items"]}
    assert len(items["anja"]) == 2 and len(items["bert"]) == 1 and len(items["cleo"]) == 1
    # only members of the team can be chosen
    stranger = await _person("zora")
    r = await admin_client.put(f"/api/admin/teams/{tid}/routing", json={"product": "panos", "all_members": False, "members": [str(stranger.id)]})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "not_member"
    # an empty choice: nobody
    await _event("panos")
    await _event("cisco-asa")
    await _dispatch()
    got = sorted((m["to"][0], m["subject"]) for m in mails.sent)
    assert [g[0] for g in got] == ["anja@corp.example", "bert@corp.example", "cleo@corp.example"]
    assert "2 neue" in next(s for to, s in got if to.startswith("anja"))  # A's two products in one mail
    # B leaves the team (removed by hand): the routing rows go with B
    r = await admin_client.delete(f"/api/admin/teams/{tid}/members/{b.id}")
    assert r.status_code == 200
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(TeamProductMember).where(TeamProductMember.user_id == b.id)) == 0
        assert await s.scalar(select(func.count()).select_from(PersonRoute).where(PersonRoute.user_id == b.id)) == 0
    # back to all members: who did not get it (D, new in the team) gets it from now on – A and C had it all along
    d = await _person("dora")
    assert (await admin_client.put(f"/api/admin/teams/{tid}/members/{d.id}")).status_code == 200
    r = await admin_client.put(f"/api/admin/teams/{tid}/routing", json={"product": "cisco-asa", "all_members": True, "members": []})
    assert r.status_code == 200
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(TeamProductMember)) == 1  # only panos' A (B is gone, cisco is for all again)
        tp_cisco = await s.scalar(select(TeamProduct.id).join(VendorFollow).where(VendorFollow.product == "cisco-asa"))
        assert set(await s.scalars(select(PersonRoute.user_id).where(PersonRoute.team_product_id == tp_cisco))) == {d.id}


async def test_leaving_through_the_sync_drops_the_routing(monkeypatch):
    async with db.session() as s:
        await settings_store.put(s, "ldap", {"enabled": True, "servers": ["dc01.corp.example"], "base_dn": "DC=corp,DC=example", "bind_dn": "CN=svc", "bind_password_enc": ""})
        await s.commit()
    await _switch()
    gid = "CN=Team-Net,OU=Groups,DC=corp,DC=example"
    people = [DirectoryUser(source="ldap", external_id=str(uuid.UUID(int=n)), username=f"user{n}", display_name=f"User {n}", email=f"user{n}@corp.example", enabled=True) for n in (1, 2)]
    members = {"now": people}

    async def fake(source, cfg, group_id):  # noqa: ANN001, ANN202
        return members["now"]

    monkeypatch.setattr(teams, "_members", fake)
    async with db.session() as s:
        t = Team(name="Net")
        s.add(t)
        await s.flush()
        s.add(TeamGroup(team_id=t.id, source="ldap", group_id=gid, group_name="Team-Net"))
        f = VendorFollow(product="fortios")
        s.add(f)
        await s.flush()
        tp = TeamProduct(team_id=t.id, follow_id=f.id, all_members=False)
        s.add(tp)
        await s.commit()
        tid, tp_id = t.id, tp.id
    async with db.session() as s:
        await teams.sync(s)
    async with db.session() as s:
        u2 = await s.scalar(select(User).where(User.username == "user2"))
        tpo = await s.get(TeamProduct, tp_id)
        await personal.set_routing(s, tpo, False, [u2.id])
        await s.commit()
    members["now"] = people[:1]  # user2 left the group
    async with db.session() as s:
        await teams.sync(s, {tid})
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(TeamProductMember)) == 0
        assert await s.scalar(select(func.count()).select_from(PersonRoute)) == 0


async def test_admin_endpoints_refuse_readers_and_switches_default_off(reader_client, admin_client):
    tid, _ = await _team([reader_client.user])
    r = await reader_client.put(f"/api/admin/teams/{tid}/routing", json={"product": "panos", "all_members": True})
    assert r.status_code == 403
    assert (await reader_client.get("/api/admin/teams/settings")).status_code == 403
    s = (await admin_client.get("/api/admin/teams/settings")).json()
    assert (s["personal_email"], s["personal_desktop"], s["personal_teams"]) == (False, False, False)
    # an older client that does not know the switches keeps them
    await _switch()
    r = await admin_client.get("/api/admin/teams/settings")
    r = await admin_client.put("/api/admin/teams/settings", json={"enabled": True, "welcome_mail": False, "rev": r.json()["rev"]})
    assert r.status_code == 200 and r.json()["personal_teams"] is True
    # no re-authentication for the switches (as for the team's products) – the session of this test is fresh anyway
    r = await admin_client.put("/api/admin/teams/settings", json={"enabled": True, "personal_email": False, "rev": r.json()["rev"]})
    assert r.status_code == 200 and r.json()["personal_email"] is False and r.json()["personal_desktop"] is True


# ---------------------------------------------------------------- the ways


async def test_each_way_only_to_assigned_active_people_with_the_way_on_and_allowed(admin_client, mails, web):
    await _switch()
    a, b, c, d = await _person("anja"), await _person("bert"), await _person("cleo", active=False), await _person("dora")
    tid, _ = await _team([a, b, c, d])
    await admin_client.put(f"/api/admin/teams/{tid}/routing", json={"product": "panos", "all_members": False, "members": [str(a.id), str(c.id), str(d.id)]})
    await _ways(a, email=True, desktop=True, teams_=True)
    await _ways(b, email=True, desktop=True, teams_=True)  # not chosen for the product
    await _ways(c, email=True, desktop=True, teams_=True)  # switched off account
    await _ways(d)  # every way off
    for u in (a, b, c, d):
        await _subscribe(u)
    # the routing was set just now: events before it are not A's – this one comes after
    ev = await _event("panos", severity="critical")
    got = await _dispatch()
    assert got == {"sent": 3}
    assert [m["to"] for m in mails.sent] == [["anja@corp.example"]]
    assert len(web.to("logic.azure.com")) == 1
    pushes = web.to("fcm.googleapis.com")
    assert len(pushes) == 1 and pushes[0].url.path.endswith("-anja")
    card = json.loads(web.to("logic.azure.com")[0].content)
    text = json.dumps(card, ensure_ascii=False)
    assert "Hersteller-News meiner Produkte" in text and f"/vendor?product=panos&finding=ADV-" in text
    # the push payload is the vendor one, with a link into Vendor News
    async with db.session() as s:
        assert {r.way for r in await s.scalars(select(PersonDelivery).where(PersonDelivery.event_id == ev, PersonDelivery.status == "sent"))} == {"email", "desktop", "teams"}
    # an admin switches e-mail off: nobody gets one any more, the others go on
    await _switch(email=False)
    await _event("panos")
    await _dispatch()
    assert len(mails.sent) == 1 and len(web.to("logic.azure.com")) == 2


async def test_push_payload_is_the_vendor_event(admin_client, web):
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, desktop=True)
    browser = await _subscribe(a)
    await _event("panos", severity="critical", title="Speicherfehler im Portal")
    await _dispatch()
    data = browser.read(web.to("fcm.googleapis.com")[0].content)
    assert data["kind"] == "vendor" and data["severity"] == "critical" and data["url"].startswith("/vendor?product=panos&finding=")
    assert "Speicherfehler" in data["title"] and "PAN-OS" in data["body"]


async def test_nothing_before_switching_on_before_the_assignment_and_no_baseline(admin_client, mails):
    await _switch()
    a = await _person("anja")
    tid, _ = await _team([a])
    await _event("panos", at=datetime.now(UTC) - 2 * HOUR)  # before the product was assigned (an hour ago)
    await _event("panos", baseline=True)  # the baseline of a newly followed version
    # switched on through the API: only what comes from now on
    async with make_client() as c:
        await sign_in(c, a)
        r = await c.put("/api/me/vendor-notify", json={"email_on": True, "kinds": ["vendor_vuln", "vendor_version"], "min_severity": "info", "lang": "de"})
        assert r.status_code == 200, r.text
    await _event("panos", at=datetime.now(UTC) - timedelta(minutes=5))  # before switching on
    await _dispatch()
    assert mails.sent == []
    # nobody chosen for the product; then A – an event from before the choice is not A's
    await admin_client.put(f"/api/admin/teams/{tid}/routing", json={"product": "panos", "all_members": False, "members": []})
    old = await _event("panos")
    await _dispatch()
    await admin_client.put(f"/api/admin/teams/{tid}/routing", json={"product": "panos", "all_members": False, "members": [str(a.id)]})
    await _dispatch()
    assert mails.sent == [] and not await _rows(event_id=old)
    await _event("panos")
    await _dispatch()
    assert len(mails.sent) == 1


async def test_exactly_once_across_rounds_and_after_a_crash_between_claim_and_send(mails):
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True)
    await _event("panos")
    await _dispatch()
    await _dispatch()
    assert len(mails.sent) == 1
    personal.reset()  # as after a restart: nothing in memory
    await _dispatch()
    assert len(mails.sent) == 1
    # a crash right after the claim: the rows are "sending" – never sent again, failed after an hour
    ev = await _event("panos")
    async with db.session() as s:
        ways = await personal.allowed(s)
        await personal.enqueue(s, ways)
        jobs = await personal._prepare(s, ways, datetime.now(UTC))
    assert len(jobs) == 1  # claimed and committed – and then the process "stopped"
    personal.reset()
    await _dispatch()
    assert len(mails.sent) == 1
    (row,) = await _rows(event_id=ev)
    assert row.status == "sending"
    async with db.session() as s:
        await s.execute(update(PersonDelivery).where(PersonDelivery.event_id == ev).values(claimed_at=datetime.now(UTC) - 2 * HOUR))
        await s.commit()
    await _dispatch()
    (row,) = await _rows(event_id=ev)
    assert (row.status, row.error) == ("failed", "interrupted") and len(mails.sent) == 1


async def test_digest_one_message_per_person_and_way(mails, web):
    await _switch()
    a = await _person("anja")
    await _team([a], products=("panos", "fortios"))
    await _ways(a, email=True, desktop=True, teams_=True)
    browser = await _subscribe(a)
    for k in range(4):
        await _event("panos", severity="medium", title=f"Lücke {k}")
    await _event("fortios", severity="critical", title="Die schlimmste")
    await _event("fortios", kind="version", severity="info")
    await _dispatch()
    assert len(mails.sent) == 1 and "6 neue" in mails.sent[0]["subject"]
    assert mails.sent[0]["text"].index("Die schlimmste") < mails.sent[0]["text"].index("Lücke 0")  # the most severe first
    assert "Hersteller-News meiner Produkte" in mails.sent[0]["text"]
    assert len(web.to("logic.azure.com")) == 1
    (push,) = web.to("fcm.googleapis.com")
    data = browser.read(push.content)
    assert data["kind"] == "vendor-summary" and "6" in data["title"] and data["severity"] == "critical"


async def test_cap_per_round(mails, monkeypatch):
    monkeypatch.setattr(personal, "CLAIM_MAX", 3)
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True)
    for _ in range(5):
        await _event("panos")
    await _dispatch()
    assert len(mails.sent) == 1 and "3 neue" in mails.sent[0]["subject"]
    await _dispatch()
    assert len(mails.sent) == 2 and "2 neue" in mails.sent[1]["subject"]


async def test_retry_and_permanent_failure_rules(mails, web):
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True, teams_=True)
    ev = await _event("panos")
    # the mail server refused the connection: certainly not delivered – again after a pause
    mails.fail.append("refused")
    web.status = 500  # Teams answered with an error: not taken – again after a pause
    await _dispatch()
    rows = {r.way: r for r in await _rows(event_id=ev)}
    assert (rows["email"].status, rows["email"].error, rows["email"].tries) == ("pending", "refused", 1)
    assert (rows["teams"].status, rows["teams"].error) == ("pending", "http")
    async with db.session() as s:
        p = await s.get(PersonNotify, a.id)
        assert p.state_email["failures"] == 1 and p.state_email["next_try_at"] and p.state_email["last_error"] == "refused"
    await _dispatch()  # pausing: nothing tried
    assert {r.tries for r in await _rows(event_id=ev)} == {1}
    # the pause is over; now a timeout – it may have arrived: never again
    async with db.session() as s:
        p = await s.get(PersonNotify, a.id)
        p.state_email = {**p.state_email, "next_try_at": None}
        p.state_teams = {**p.state_teams, "next_try_at": None}
        await s.commit()
    mails.fail[:] = ["timeout"]
    web.status = 202
    await _dispatch()
    rows = {r.way: r for r in await _rows(event_id=ev)}
    assert (rows["email"].status, rows["email"].error) == ("failed", "timeout")
    assert rows["teams"].status == "sent"
    async with db.session() as s:
        p = await s.get(PersonNotify, a.id)
        assert p.state_teams["failures"] == 0 and p.state_teams["last_ok_at"] and p.state_teams["last_error"] is None


async def test_teams_off_means_no_personal_delivery(mails, web):
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True, teams_=True)
    await _switch(enabled=False)
    await _event("panos")
    assert await _dispatch() == {}
    assert mails.sent == [] and web.requests == []
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(PersonDelivery)) == 0
    # switched on again: what came while it was off does not come as a burst
    await _switch(since=datetime.now(UTC))
    await _dispatch()
    assert mails.sent == [] and web.requests == []
    await _event("panos")
    await _dispatch()
    assert len(mails.sent) == 1


async def test_filters_kinds_and_minimum_severity_no_flood_when_widened(mails):
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True, kinds=["vendor_vuln"], min_severity="high")
    low = await _event("panos", severity="medium")
    ver = await _event("panos", kind="version", severity="info")
    hi = await _event("panos", severity="critical")
    await _dispatch()
    assert len(mails.sent) == 1 and "Kritisch" in mails.sent[0]["subject"]
    assert {r.event_id: r.status for r in await _rows(user_id=a.id)} == {low: "skipped", ver: "skipped", hi: "sent"}
    # widened: the older ones it left out stay out
    await _ways(a, email=True, kinds=list(personal.KINDS), min_severity="info")
    personal.reset()
    await _dispatch()
    assert len(mails.sent) == 1


async def test_advisory_changed_only_when_chosen_and_filtered_by_severity(mails):
    """ "Advisory geändert" is not among the defaults; chosen, it comes with the severity filter, linked to the changes."""
    assert "vendor_change" not in personal.DEFAULT_KINDS
    await _switch()
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True, kinds=list(personal.DEFAULT_KINDS), min_severity="info")
    skipped = await _event("panos", kind="change", severity="critical", title="PAN-SA-2026-0001")
    await _dispatch()
    assert mails.sent == [] and {r.status for r in await _rows(event_id=skipped)} == {"skipped"}
    await _ways(a, email=True, kinds=["vendor_change"], min_severity="high")
    personal.reset()
    low = await _event("panos", kind="change", severity="medium", title="PAN-SA-2026-0002")
    hi = await _event("panos", kind="change", severity="high", title="PAN-SA-2026-0003")
    await _dispatch()
    assert {r.event_id: r.status for r in await _rows(user_id=a.id) if r.event_id in (low, hi)} == {low: "skipped", hi: "sent"}
    assert len(mails.sent) == 1
    async with db.session() as s:
        ev = await s.get(VendorEvent, hi)
    assert personal.event_path(ev) == "/vendor?product=panos&view=changes"


async def test_no_address_and_no_browser(mails, web):
    await _switch()
    a = await _person("anja", email=False)
    await _team([a])
    await _ways(a, email=True, desktop=True)
    ev = await _event("panos")
    await _dispatch()
    rows = {r.way: (r.status, r.error) for r in await _rows(event_id=ev)}
    assert rows == {"email": ("skipped", "no_address"), "desktop": ("skipped", "no_device")}
    assert mails.sent == [] and web.requests == []


# ---------------------------------------------------------------- the own settings (API)


async def test_reader_settings_own_only_unavailable_outside_a_team(reader_client, mails):
    me = (await reader_client.get("/api/me/vendor-notify")).json()
    assert me["available"] is False and me["reason"] == "teams_off"
    await _switch(email=True, desktop=False, teams=False)
    assert (await reader_client.get("/api/me/vendor-notify")).json()["reason"] == "no_team"
    r = await reader_client.put("/api/me/vendor-notify", json={"email_on": True, "kinds": ["vendor_vuln"]})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "no_team"
    other = await _person("otto")
    await _team([reader_client.user, other])
    me = (await reader_client.get("/api/me/vendor-notify")).json()
    assert me["available"] and [p["key"] for p in me["products"]] == ["panos"] and me["products"][0]["teams"] == ["Security"]
    assert me["allowed"] == {"email": True, "desktop": False, "teams": False}
    # no address: e-mail cannot be switched on
    r = await reader_client.put("/api/me/vendor-notify", json={"email_on": True, "kinds": ["vendor_vuln"]})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "no_address"
    # a way the admin has not allowed
    r = await reader_client.put("/api/me/vendor-notify", json={"teams_on": True, "kinds": ["vendor_vuln"], "teams_url": TEAMS_URL})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "way_off"
    # the own row only – nothing in the body or the path names another person
    r = await reader_client.put("/api/me/vendor-notify", json={"kinds": ["vendor_version"], "min_severity": "high", "user_id": str(other.id)})
    assert r.status_code == 422
    r = await reader_client.put("/api/me/vendor-notify", json={"kinds": ["vendor_version"], "min_severity": "high"})
    assert r.status_code == 200 and r.json()["kinds"] == ["vendor_version"]
    async with db.session() as s:
        assert await s.get(PersonNotify, other.id) is None
        assert (await s.get(PersonNotify, reader_client.user.id)).min_severity == "high"
    assert (await make_client().get("/api/me/vendor-notify")).status_code == 401


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://prod-12.westeurope.logic.azure.com/workflows/x", "teams_url_invalid_url"),  # https only
        ("https://hooks.slack.com/services/T/B/x", "teams_url_host_not_allowed"),  # Slack is a channel's host, not a person's
        ("https://evil.example.com/logic.azure.com", "teams_url_host_not_allowed"),
        ("https://logic.azure.com.evil.example/x", "teams_url_host_not_allowed"),
        ("https://prod-12.westeurope.logic.azure.com:8443/x", "teams_url_host_not_allowed"),
        ("https://10.1.2.3/workflows/x", "teams_url_forbidden_target"),
        ("https://127.0.0.1/x", "teams_url_forbidden_target"),
        ("https://user:pw@prod-1.logic.azure.com/x", "teams_url_invalid_url"),
    ],
)
async def test_teams_url_hosts(reader_client, url, code):
    await _switch()
    await _team([reader_client.user])
    r = await reader_client.put("/api/me/vendor-notify", json={"teams_on": True, "kinds": ["vendor_vuln"], "teams_url": url})
    assert r.status_code == 422 and r.json()["detail"]["code"] == code, (url, r.text)


@pytest.mark.parametrize("url", [TEAMS_URL, "https://default0123.ab.environment.api.powerplatform.com/powerautomate/x", "https://corp.webhook.office.com/webhookb2/x"])
def test_teams_url_hosts_taken(url):
    assert personal.check_teams_url(url) == url


async def test_teams_url_stored_encrypted_never_returned_and_test_rate_limited(reader_client, web, monkeypatch):
    await _switch()
    await _team([reader_client.user])
    r = await reader_client.put("/api/me/vendor-notify", json={"teams_on": True, "kinds": ["vendor_vuln"], "teams_url": TEAMS_URL})
    assert r.status_code == 200, r.text
    for body in (r.text, (await reader_client.get("/api/me/vendor-notify")).text):
        assert "TopSecretSignature" not in body and "/workflows/" not in body
    assert r.json()["teams"]["url_hint"] == "prod-12.westeurope.logic.azure.com/…"
    async with db.session() as s:
        p = await s.get(PersonNotify, reader_client.user.id)
        assert p.teams_url_enc.startswith("v1:") and "TopSecret" not in p.teams_url_enc
    # saved again without a URL: the stored one stays
    r = await reader_client.put("/api/me/vendor-notify", json={"teams_on": True, "kinds": ["vendor_vuln", "vendor_version"]})
    assert r.status_code == 200 and r.json()["teams"]["url_set"]
    r = await reader_client.post("/api/me/vendor-notify/teams/test")
    assert r.json() == {"ok": True}
    (req,) = web.to("logic.azure.com")
    assert req.url.params["sig"] == "TopSecretSignature123" and "Testnachricht" in req.content.decode()
    r = await reader_client.post("/api/me/vendor-notify/teams/test")
    assert r.status_code == 429  # as the push test
    # a failing test says the category, never the URL
    personal_api._last_test.clear()
    web.status = 404
    r = await reader_client.post("/api/me/vendor-notify/teams/test")
    assert r.json()["ok"] is False and r.json()["error"] == "rejected" and "TopSecret" not in r.text
    # removed: the way goes off with it
    r = await reader_client.put("/api/me/vendor-notify", json={"teams_on": False, "kinds": ["vendor_vuln"], "teams_url": ""})
    assert r.status_code == 200 and r.json()["teams"]["url_set"] is False


async def test_personal_teams_url_never_reaches_private_addresses_even_when_listed(monkeypatch):
    """WEBHOOK_PRIVATE_NETS lets a channel reach a company address – a person's URL never: a Microsoft name answering
    with a private or loopback address is refused at connect (pinned resolution), whatever the list says."""
    import dataclasses

    from app import config

    c = dataclasses.replace(config.get_config(), webhook_private_nets=("10.0.0.0/8", "127.0.0.1"))
    monkeypatch.setattr(netaddr, "get_config", lambda: c)
    monkeypatch.setattr(notify, "get_config", lambda: c)
    monkeypatch.setattr(notify, "transport", None)
    for addr in ("10.20.30.40", "127.0.0.1"):
        monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, _addr=addr, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_addr, port))])
        with pytest.raises(notify.NotifyError) as e:
            await notify.post(TEAMS_URL, b"{}", notify.JSON_HEADERS, policy=notify.PUBLIC_ONLY)
        assert e.value.category == "forbidden_target"
    assert netaddr.forbidden_literal("https://10.1.2.3/x", **netaddr.channel_policy()) is False  # a channel may (listed)
    with pytest.raises(notify.NotifyError) as e:
        personal.check_teams_url("https://10.1.2.3/x")
    assert e.value.category == "forbidden_target"
