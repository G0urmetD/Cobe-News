"""Teams (app/teams.py, app/teams_api.py): off by default and then without any effect; members of bound groups (nested
ones too) loaded at once and kept in step by the sync; an admin's "off" sticks; a team group gives reader (admin wins);
local accounts added by hand; products of a team, "Mein Team" in Vendor News, rules limited to teams; the welcome
e-mail exactly once (none without an address); only admins manage teams. No directory, Graph or mail server is asked –
the members come from a fake directory, Graph from an httpx.MockTransport, the mail from a recorder."""

import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import add_user, make_client, sign_in
from sqlalchemy import func, select, update

from app import db, notify, teams
from app import settings as settings_store
from app.auth import directory, entra, ldap_dir
from app.auth import sync as directory_sync
from app.auth.directory import DirectoryUser
from app.crypto import encrypt_str
from app.models import (
    GroupMapping,
    NotifyChannel,
    NotifyRule,
    NotifyRuleChannel,
    Team,
    TeamGroup,
    TeamMember,
    TeamProduct,
    TeamWelcome,
    User,
    UserSession,
    VendorEvent,
    VendorFollow,
)

BASE = "DC=corp,DC=example"
SEC = f"CN=Team-Security,OU=Groups,{BASE}"
NET = f"CN=Team-Network,OU=Groups,{BASE}"
ADMINS = f"CN=News-Admins,OU=Groups,{BASE}"
LDAP_CFG = {"enabled": True, "servers": ["dc01.corp.example"], "base_dn": BASE, "bind_dn": f"CN=svc,{BASE}", "bind_password_enc": encrypt_str("svc-pw")}


def person(n: int, *, source: str = "ldap", email: bool = True, enabled: bool = True) -> DirectoryUser:
    return DirectoryUser(
        source=source,
        external_id=str(uuid.UUID(int=n)),
        username=f"user{n}" if source == "ldap" else f"user{n}@corp.example",
        display_name=f"User {n}",
        email=f"user{n}@corp.example" if email else None,
        enabled=enabled,
    )


@pytest.fixture
def directory_fake(monkeypatch):
    """The members of each group as the directory would answer (a list – nested members already in it, as the
    directory's in-chain search / transitiveMembers resolves them) or an error category."""
    groups: dict[tuple[str, str], list[DirectoryUser] | str] = {}
    asked: list[tuple[str, str]] = []

    async def members(source, cfg, group_id):  # noqa: ANN001, ANN202
        asked.append((source, group_id))
        return groups.get((source, group_id.lower()), [])

    monkeypatch.setattr(teams, "_members", members)

    class D:
        pass

    d = D()
    d.groups, d.asked = groups, asked
    d.set = lambda source, gid, value: groups.__setitem__((source, gid.lower()), value)
    return d


async def _settings(**teams_cfg):
    async with db.session() as s:
        await settings_store.put(s, "ldap", LDAP_CFG)
        await settings_store.put(s, "teams", {"enabled": True, "welcome_mail": False, **teams_cfg})
        await s.commit()


async def _team(name: str = "Security", *groups: tuple[str, str]) -> uuid.UUID:
    async with db.session() as s:
        t = Team(name=name)
        s.add(t)
        await s.flush()
        for source, gid in groups:
            s.add(TeamGroup(team_id=t.id, source=source, group_id=gid, group_name=gid.split(",")[0]))
        await s.commit()
        return t.id


async def _sync(team_ids=None) -> dict:
    async with db.session() as s:
        return await teams.sync(s, team_ids)


async def _members(team_id) -> set[str]:
    async with db.session() as s:
        q = select(User.username).join(TeamMember, TeamMember.user_id == User.id).where(TeamMember.team_id == team_id)
        return set(await s.scalars(q))


async def _user(name: str) -> User | None:
    async with db.session() as s:
        return await s.scalar(select(User).where(User.username == name))


# ---------------------------------------------------------------- off: no effect


async def test_off_by_default_and_without_effect(directory_fake, admin_client, reader_client):
    async with db.session() as s:
        assert (await teams.config(s)) == {"enabled": False, "welcome_mail": False, "personal_email": False, "personal_desktop": False, "personal_teams": False}
        await settings_store.put(s, "ldap", LDAP_CFG)
        await s.commit()
    tid = await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1), person(2)])
    assert await _sync() == {}  # nothing loaded, nobody created
    assert directory_fake.asked == [] and await _members(tid) == set()
    async with db.session() as s:
        assert await directory.resolve_role(s, "ldap", [SEC]) is None  # no reader through a team group
    me = (await reader_client.get("/api/me/teams")).json()
    assert me == {"enabled": False, "teams": []}
    # a rule cannot be limited to a team while Teams is off
    async with db.session() as s:
        ch = NotifyChannel(name="Mail", type="email", config={"recipients": ["soc@corp.example"]})
        s.add(ch)
        await s.commit()
    r = await admin_client.post("/api/admin/notify/rules", json={"name": "Team", "channels": [str(ch.id)], "kinds": ["vendor_vuln"], "teams": [str(tid)]})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "teams_off"


# ---------------------------------------------------------------- loading, sync add / remove


async def test_bind_loads_members_at_once_nested_included(directory_fake, admin_client):
    await _settings()
    # Ute is only in a group nested in Team-Security – the directory's in-chain answer lists her as a member
    directory_fake.set("ldap", SEC, [person(1), person(2), person(3, email=False)])
    t = (await admin_client.post("/api/admin/teams", json={"name": "Security"})).json()
    r = await admin_client.post(f"/api/admin/teams/{t['id']}/groups", json={"source": "ldap", "group_id": SEC, "group_name": "Team-Security"})
    assert r.status_code == 200 and r.json()["state"] == "loading"
    await teams.wait_idle()
    assert await _members(uuid.UUID(t["id"])) == {"user1", "user2", "user3"}
    u = await _user("user1")
    assert u.auth_source == "ldap" and u.role == "reader" and u.is_active and u.last_login_at is None
    users = {x["username"]: x for x in (await admin_client.get("/api/admin/users")).json()}
    assert users["user1"]["last_login_at"] is None and users["user1"]["teams"] == ["Security"]
    listed = (await admin_client.get("/api/admin/teams")).json()[0]
    assert listed["groups"][0]["state"] == "ok" and listed["groups"][0]["members"] == 3 and listed["members"] == {"group": 3, "manual": 0}


async def test_sync_adds_and_removes_and_unbinding_empties(directory_fake, admin_client):
    await _settings()
    tid = await _team("Security", ("ldap", SEC), ("ldap", NET))
    directory_fake.set("ldap", SEC, [person(1), person(2)])
    directory_fake.set("ldap", NET, [person(2), person(3)])
    await _sync()
    assert await _members(tid) == {"user1", "user2", "user3"}
    # user1 taken out of the group, user4 added
    directory_fake.set("ldap", SEC, [person(2), person(4)])
    got = await _sync()
    assert got["added"] == 1 and got["removed"] == 1
    assert await _members(tid) == {"user2", "user3", "user4"}
    # a group that cannot be read: nobody is taken out (an outage must not empty the team)
    directory_fake.set("ldap", NET, "connection")
    await _sync()
    assert await _members(tid) == {"user2", "user3", "user4"}
    async with db.session() as s:
        g = await s.scalar(select(TeamGroup).where(TeamGroup.group_id == NET))
        assert g.state == "error" and g.error == "connection"
    # unbinding: its members leave with the load that starts at once
    directory_fake.set("ldap", NET, [person(2), person(3)])
    r = await admin_client.delete(f"/api/admin/teams/{tid}/groups/{g.id}")
    assert r.status_code == 200
    await teams.wait_idle()
    assert await _members(tid) == {"user2", "user4"}


async def test_the_hourly_sync_runs_teams_first(directory_fake, monkeypatch):
    """The loop's directory step: the team load, then the account sync (which leaves never-signed-in accounts alone)."""
    from app.main import FetchLoop

    await _settings()
    tid = await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1)])
    asked: list = []

    def lookup_many(cfg, ids):  # noqa: ANN001, ANN202
        asked.extend(ids)
        return {}

    monkeypatch.setattr(ldap_dir, "lookup_many", lookup_many)
    await FetchLoop()._directory()
    assert await _members(tid) == {"user1"}
    assert asked == []  # user1 never signed in: not looked up one by one


async def test_big_group_in_batches(directory_fake, monkeypatch):
    """5000 members: loaded in batches (each its own transaction), quickly enough."""
    await _settings(welcome_mail=True)
    tid = await _team("Everyone", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(n) for n in range(1, 5001)])
    commits = 0
    real = teams._accounts

    async def counting(s, people, welcome):  # noqa: ANN001, ANN202
        nonlocal commits
        orig = s.commit

        async def commit():  # noqa: ANN202
            nonlocal commits
            commits += 1
            await orig()

        s.commit = commit
        try:
            return await real(s, people, welcome)
        finally:
            s.commit = orig

    monkeypatch.setattr(teams, "_accounts", counting)
    t0 = time.monotonic()
    got = await _sync()
    took = time.monotonic() - t0
    assert got["created"] == 5000 and got["added"] == 5000
    assert commits == 5000 // teams.BATCH  # one short transaction per batch
    assert took < 60, took
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(TeamMember).where(TeamMember.team_id == tid)) == 5000
        assert await s.scalar(select(func.count()).select_from(TeamWelcome).where(TeamWelcome.status == "pending")) == 5000
    # a second run changes nothing
    got = await _sync()
    assert "created" not in got and "added" not in got and "removed" not in got


async def test_a_local_account_is_never_taken_over(directory_fake):
    await _settings()
    await add_user("user1")
    tid = await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1), person(2)])
    got = await _sync()
    assert got["conflicts"] == 1
    assert await _members(tid) == {"user2"}
    assert (await _user("user1")).auth_source == "local"


# ---------------------------------------------------------------- blocking sticks, roles


async def test_admin_block_sticks_for_never_signed_in(directory_fake, admin_client):
    await _settings()
    tid = await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1)])
    await _sync()
    u = await _user("user1")
    r = await admin_client.patch(f"/api/admin/users/{u.id}", json={"is_active": False, "version": u.version})
    assert r.status_code == 200 and r.json()["deactivated_reason"] == "admin"
    # disabled and enabled again in the directory, synced each time: the admin's "off" stays
    directory_fake.set("ldap", SEC, [person(1, enabled=False)])
    await _sync()
    directory_fake.set("ldap", SEC, [person(1)])
    await _sync()
    u = await _user("user1")
    assert not u.is_active and u.deactivated_reason == "admin"
    assert await _members(tid) == {"user1"}  # still in the team – only the sign-in is blocked
    # the sign-in is refused, also with the team group
    async with db.session() as s:
        with pytest.raises(directory.DirectoryError) as exc:
            await directory.provision(s, DirectoryUser("ldap", u.external_id, "user1", "User 1", groups=[SEC]))
        assert exc.value.code == "disabled"
        # and the hourly account sync does not switch it on either
        assert await directory.apply_sync(s, u, DirectoryUser("ldap", u.external_id, "user1", "User 1", groups=[SEC])) == "unchanged"
        assert not u.is_active


async def test_directory_disabled_member_follows_the_directory(directory_fake):
    await _settings()
    await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1), person(2, enabled=False)])
    await _sync()
    assert await _user("user2") is None  # a disabled account is not created
    directory_fake.set("ldap", SEC, [person(1, enabled=False)])
    await _sync()
    u = await _user("user1")
    assert not u.is_active and u.deactivated_reason == "sync:disabled"
    directory_fake.set("ldap", SEC, [person(1)])
    await _sync()
    assert (await _user("user1")).is_active


async def test_role_reader_from_team_admin_wins():
    await _settings()
    await _team("Security", ("ldap", SEC), ("entra", "0a0a0a0a-0000-0000-0000-00000000000a"))
    async with db.session() as s:
        s.add(GroupMapping(source="ldap", group_id=ADMINS, group_name="News-Admins", role="admin"))
        await s.commit()
        assert await directory.resolve_role(s, "ldap", [SEC.lower()]) == "reader"
        assert await directory.resolve_role(s, "ldap", [SEC, ADMINS]) == "admin"
        assert await directory.resolve_role(s, "entra", ["0A0A0A0A-0000-0000-0000-00000000000A"]) == "reader"
        assert await directory.resolve_role(s, "ldap", ["CN=Other,OU=Groups," + BASE]) is None
        assert await directory.resolve_role(s, "entra", [SEC]) is None  # an AD group never counts for Entra
        # first sign-in of a loaded member: the account the team created is taken, its role from the groups
        u = await directory.provision(s, DirectoryUser("ldap", str(uuid.UUID(int=7)), "user7", "User 7", groups=[SEC, ADMINS]))
        assert u.role == "admin"
        await s.commit()
    # off again: the team group gives nothing – the next sync switches such readers off (sync:no_role)
    async with db.session() as s:
        await settings_store.put(s, "teams", {"enabled": False, "welcome_mail": False})
        await s.commit()
        assert await directory.resolve_role(s, "ldap", [SEC]) is None


async def test_nested_member_keeps_reader_through_the_loaded_membership(directory_fake):
    """AD with nested groups off at the sign-in (memberOf only): the load found the person through a nested group – the
    membership it wrote gives the reader role all the same; out of the group, it is gone at the next sync."""
    await _settings()
    tid = await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1)])
    await _sync()
    u = await _user("user1")
    async with db.session() as s:
        assert await directory.resolve_role(s, "ldap", ["CN=Sub,OU=Groups," + BASE], u.id) == "reader"
    directory_fake.set("ldap", SEC, [])
    await _sync()
    assert await _members(tid) == set()
    async with db.session() as s:
        assert await directory.resolve_role(s, "ldap", ["CN=Sub,OU=Groups," + BASE], u.id) is None


# ---------------------------------------------------------------- welcome e-mail


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


async def _smtp():
    async with db.session() as s:
        await settings_store.put(s, "smtp", {**settings_store.DEFAULTS["smtp"], "host": "mail.corp.example", "from_addr": "news@corp.example"})
        await s.commit()


async def _welcome() -> int:
    async with db.session() as s:
        return await teams.send_welcome(s)


async def test_welcome_mail_once_and_none_without_address(directory_fake, mails, admin_client):
    await _settings(welcome_mail=True)
    await _smtp()
    await _team("Security", ("ldap", SEC))
    odd = person(4)
    odd.email = "eve@corp.example, boss@corp.example"  # one directory value naming two – no mail at all
    directory_fake.set("ldap", SEC, [person(1), person(2, email=False), odd])
    await _sync()
    assert await _welcome() == 1
    assert [m["to"] for m in mails.sent] == [["user1@corp.example"]]
    m = mails.sent[0]
    assert "https://news.corp.example:8095/" in m["text"] and "https://news.corp.example:8095/" in m["html"]
    assert "Security" in m["text"] and "Active Directory" in m["text"]
    assert "passwort:" not in m["text"].lower() and "password:" not in m["text"].lower()  # never a password to sign in with
    # again, after a re-sync and as after a restart (nothing in memory): no second mail
    await _sync()
    teams._tasks.clear()
    assert await _welcome() == 0 and len(mails.sent) == 1
    users = {x["username"]: x for x in (await admin_client.get("/api/admin/users")).json()}
    assert users["user1"]["welcome"] == "sent" and users["user2"]["welcome"] == "no_address" and users["user4"]["welcome"] == "no_address"
    # deleted and loaded again: still no second mail (the record is by directory id)
    u = await _user("user1")
    async with db.session() as s:
        await s.delete(await s.get(User, u.id))
        await s.commit()
    await _sync()
    assert await _welcome() == 0 and len(mails.sent) == 1


async def test_welcome_mail_off_by_default_and_retry_rules(directory_fake, mails):
    await _settings()
    await _smtp()
    await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1)])
    await _sync()
    assert await _welcome() == 0 and mails.sent == []
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(TeamWelcome)) == 0  # loaded while off: never a mail
    # on: the server refuses the connection – tried again later; a timeout (maybe delivered) – never again
    async with db.session() as s:
        await settings_store.put(s, "teams", {"enabled": True, "welcome_mail": True})
        await s.commit()
    directory_fake.set("ldap", SEC, [person(1), person(2), person(3)])
    await _sync()
    mails.fail.append("refused")
    assert await _welcome() == 0
    async with db.session() as s:
        states = {w.external_id: (w.status, w.error) for w in await s.scalars(select(TeamWelcome))}
    assert sorted(states.values(), key=str) == [("pending", "refused"), ("pending", None)]
    mails.fail[:] = ["timeout"]
    assert await _welcome() == 0
    mails.fail.clear()
    assert await _welcome() == 1
    async with db.session() as s:
        assert sorted(w.status for w in await s.scalars(select(TeamWelcome))) == ["failed", "sent"]


async def test_welcome_mail_waits_for_smtp_and_skips_blocked(directory_fake, mails, admin_client):
    await _settings(welcome_mail=True)
    await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1), person(2)])
    await _sync()
    assert await _welcome() == 0  # no mail server yet: they wait
    u = await _user("user2")
    await admin_client.patch(f"/api/admin/users/{u.id}", json={"is_active": False, "version": u.version})
    await _smtp()
    assert await _welcome() == 1 and [m["to"] for m in mails.sent] == [["user1@corp.example"]]


# ---------------------------------------------------------------- products, Mein Team, rules


async def _follow(key: str) -> uuid.UUID:
    async with db.session() as s:
        f = VendorFollow(product=key)
        s.add(f)
        await s.commit()
        return f.id


async def test_products_and_my_team_filter(directory_fake, admin_client):
    await _settings()
    await _follow("panos")
    await _follow("fortios")
    t = (await admin_client.post("/api/admin/teams", json={"name": "Network"})).json()
    r = await admin_client.put(f"/api/admin/teams/{t['id']}/products", json={"products": ["panos", "nope"]})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "product_not_followed"
    r = await admin_client.put(f"/api/admin/teams/{t['id']}/products", json={"products": ["panos"]})
    assert [p["key"] for p in r.json()["products"]] == ["panos"]
    # a local reader added by hand; a directory account cannot be (its groups decide)
    lena = await add_user("lena")
    assert (await admin_client.put(f"/api/admin/teams/{t['id']}/members/{lena.id}")).status_code == 200
    async with db.session() as s:
        d = User(username="dirk", auth_source="ldap", external_id=str(uuid.uuid4()), role="reader")
        s.add(d)
        await s.commit()
    r = await admin_client.put(f"/api/admin/teams/{t['id']}/members/{d.id}")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "directory_managed"
    async with make_client() as c:
        await sign_in(c, lena)
        assert (await c.get("/api/me/teams")).json() == {"enabled": True, "teams": [{"id": t["id"], "name": "Network", "forward": False}]}
        mine = (await c.get("/api/vendor/overview?scope=team")).json()
        assert mine["team_scope"] is True and [i["product"]["key"] for i in mine["items"]] == ["panos"]
        assert mine["total"] == 2  # the number on the tab ("Alle") comes along – no second, full request for it
        every = (await c.get("/api/vendor/overview")).json()
        assert sorted(i["product"]["key"] for i in every["items"]) == ["fortios", "panos"] and every["total"] == 2
    # manual members carry no role: the local account keeps its own
    members = (await admin_client.get(f"/api/admin/teams/{t['id']}/members")).json()
    assert members["total"] == 1 and members["items"][0]["origin"] == "manual"
    assert (await admin_client.delete(f"/api/admin/teams/{t['id']}/members/{lena.id}")).status_code == 200
    # Teams off: "Mein Team" filters nothing
    async with db.session() as s:
        await settings_store.put(s, "teams", {"enabled": False})
        await s.commit()
    async with make_client() as c:
        await sign_in(c, lena)
        off = (await c.get("/api/vendor/overview?scope=team")).json()
        assert off["team_scope"] is False and len(off["items"]) == 2


async def test_my_team_without_products_reads_no_findings(admin_client, monkeypatch):
    """scope=team for a person in no team: an empty list with the full count – and no KEV list, no EUVD CVEs read."""
    from app import vendor as svc

    await _settings()
    await _follow("panos")
    await _follow("fortios")
    otto = await add_user("otto")
    read: list[str] = []

    async def kev(db):  # noqa: ANN001, ANN202
        read.append("kev")
        return {}

    async def euvd(db):  # noqa: ANN001, ANN202
        read.append("euvd")
        return set()

    monkeypatch.setattr(svc, "kev_index", kev)
    monkeypatch.setattr(svc, "euvd_cves", euvd)
    async with make_client() as c:
        await sign_in(c, otto)
        mine = (await c.get("/api/vendor/overview?scope=team")).json()
        assert mine["team_scope"] is True and mine["items"] == [] and mine["total"] == 2 and read == []
        assert len((await c.get("/api/vendor/overview")).json()["items"]) == 2 and read == ["kev", "euvd"]


async def test_rule_limited_to_a_team(admin_client):
    await _settings()
    pan, forti = await _follow("panos"), await _follow("fortios")
    long_ago = datetime.now(UTC) - timedelta(days=2)
    async with db.session() as s:
        t = Team(name="Network")
        ch = NotifyChannel(name="Mail", type="email", config={"recipients": ["soc@corp.example"]})
        s.add_all([t, ch])
        await s.flush()
        s.add(TeamProduct(team_id=t.id, follow_id=pan, added_at=long_ago))
        await s.commit()
    r = await admin_client.post("/api/admin/notify/rules", json={"name": "Netz", "channels": [str(ch.id)], "kinds": ["vendor_vuln"], "severities": [], "teams": [str(t.id)]})
    assert r.status_code == 200 and r.json()["teams"] == [str(t.id)]
    rid = uuid.UUID(r.json()["id"])
    async with db.session() as s:
        for product in ("panos", "fortios"):
            s.add(VendorEvent(key=f"vuln:{product}:*:CVE-2026-1", kind="vuln", product=product, severity="high", data={"title": product}))
        await s.commit()
        rule = await s.get(NotifyRule, rid)
        got = await notify.vendor_pending(s, rule, ch.id, rule.active_since - timedelta(seconds=5))
        assert [e.product for e in got] == ["panos"]
        # a product added to the team now brings its events from now on – not the one that came before
        s.add(TeamProduct(team_id=t.id, follow_id=forti))
        await s.commit()
        got = await notify.vendor_pending(s, rule, ch.id, rule.active_since - timedelta(seconds=5))
        assert [e.product for e in got] == ["panos"]
    # the team cannot be deleted while a rule is limited to it
    r = await admin_client.delete(f"/api/admin/teams/{t.id}")
    assert r.status_code == 409 and r.json()["detail"]["rules"] == ["Netz"]
    # the filter removed: the rule is wider – what newly matches counts from now on (no flood of fortios' older event)
    body = {"name": "Netz", "channels": [str(ch.id)], "kinds": ["vendor_vuln"], "severities": [], "teams": [], "version": 1}
    r = await admin_client.put(f"/api/admin/notify/rules/{rid}", json=body)
    assert r.status_code == 200 and r.json()["teams"] == []
    async with db.session() as s:
        rule = await s.get(NotifyRule, rid)
        assert rule.earlier and rule.earlier[-1]["teams"] == [str(t.id)]
        got = await notify.vendor_pending(s, rule, ch.id, rule.active_since - timedelta(seconds=5))
        assert [e.product for e in got] == ["panos"]
        assert await s.scalar(select(func.count()).select_from(NotifyRuleChannel)) == 1


# ---------------------------------------------------------------- authorization, re-confirmation, validation


async def test_readers_cannot_manage_teams(reader_client):
    tid = uuid.uuid4()
    for method, url, body in [
        ("GET", "/api/admin/teams", None),
        ("GET", "/api/admin/teams/settings", None),
        ("PUT", "/api/admin/teams/settings", {"enabled": True}),
        ("POST", "/api/admin/teams", {"name": "X1"}),
        ("PATCH", f"/api/admin/teams/{tid}", {"name": "X2"}),
        ("DELETE", f"/api/admin/teams/{tid}", None),
        ("POST", f"/api/admin/teams/{tid}/groups", {"source": "ldap", "group_id": SEC}),
        ("DELETE", f"/api/admin/teams/{tid}/groups/{tid}", None),
        ("POST", f"/api/admin/teams/{tid}/sync", None),
        ("GET", f"/api/admin/teams/{tid}/members", None),
        ("PUT", f"/api/admin/teams/{tid}/members/{tid}", None),
        ("DELETE", f"/api/admin/teams/{tid}/members/{tid}", None),
        ("PUT", f"/api/admin/teams/{tid}/products", {"products": []}),
        ("GET", "/api/admin/teams/products", None),
    ]:
        r = await reader_client.request(method, url, json=body)
        assert r.status_code == 403 and r.json()["detail"]["code"] == "forbidden", (method, url)
    async with make_client() as anon:
        assert (await anon.get("/api/admin/teams")).status_code == 401
        assert (await anon.get("/api/me/teams")).status_code == 401


async def test_switch_and_binding_need_reauth(directory_fake, admin_client):
    async with db.session() as s:
        await s.execute(update(UserSession).values(reauth_at=datetime.now(UTC) - timedelta(hours=2)))
        await s.commit()
    r = await admin_client.put("/api/admin/teams/settings", json={"enabled": True, "welcome_mail": False})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    # the welcome switch alone does not
    r = await admin_client.put("/api/admin/teams/settings", json={"enabled": False, "welcome_mail": True})
    assert r.status_code == 200 and r.json()["welcome_mail"] is True
    tid = await _team("Security")
    r = await admin_client.post(f"/api/admin/teams/{tid}/groups", json={"source": "ldap", "group_id": SEC})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"


async def test_group_ids_are_checked(admin_client):
    async with db.session() as s:
        await settings_store.put(s, "ldap", LDAP_CFG)
        await s.commit()
    tid = await _team("Security")
    for gid in ("CN=x,DC=other,DC=example", "not a dn", "a)(objectClass=*"):
        r = await admin_client.post(f"/api/admin/teams/{tid}/groups", json={"source": "ldap", "group_id": gid})
        assert r.status_code == 422, gid
    r = await admin_client.post(f"/api/admin/teams/{tid}/groups", json={"source": "entra", "group_id": "not-a-guid"})
    assert r.status_code == 422
    # Teams off: bound, but not loaded ("waiting")
    r = await admin_client.post(f"/api/admin/teams/{tid}/groups", json={"source": "ldap", "group_id": SEC})
    assert r.status_code == 200 and r.json()["state"] == "waiting"
    r = await admin_client.post(f"/api/admin/teams/{tid}/groups", json={"source": "ldap", "group_id": SEC.upper()})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "group_bound"
    assert (await admin_client.post("/api/admin/teams", json={"name": "security"})).json()["detail"]["code"] == "team_exists"


# ---------------------------------------------------------------- the directories themselves


class FakeLdap:
    """A service connection answering the member search page by page (paged results control) – records the filters."""

    def __init__(self, pages):
        self.pages, self.filters, self.cookies, self.result, self.response = pages, [], [], {}, []

    def search(self, base, flt, scope, attributes=None, paged_size=None, paged_cookie=None, **kw):  # noqa: ANN001, ANN201
        self.filters.append(flt)
        self.cookies.append(paged_cookie)
        i = int(paged_cookie or b"0")
        self.response = [{"type": "searchResEntry", "dn": f"CN={a['sAMAccountName']},OU=Users,{BASE}", "attributes": a} for a in self.pages[i]]
        nxt = str(i + 1).encode() if i + 1 < len(self.pages) else b""
        self.result = {"result": 0, "controls": {ldap_dir.PAGED_RESULTS: {"value": {"size": 0, "cookie": nxt}}}}
        return True

    def unbind(self):  # noqa: ANN201
        pass


def _entry(n: int, uac: str = "512") -> dict:
    return {"sAMAccountName": f"User{n}", "displayName": f"User {n}", "mail": f"user{n}@corp.example", "objectGUID": uuid.UUID(int=n).bytes_le, "userAccountControl": uac}


def test_ldap_members_paged_nested_and_escaped(monkeypatch):
    fake = FakeLdap([[_entry(1), _entry(2, "514")], [_entry(3)]])
    monkeypatch.setattr(ldap_dir, "_service", lambda cfg: fake)
    weird = f"CN=Team (Ops)*\\, a)(x\\=1,OU=Groups,{BASE}"
    got = ldap_dir.group_members(LDAP_CFG, weird)
    assert [p.username for p in got] == ["user1", "user2", "user3"] and [p.enabled for p in got] == [True, False, True]
    assert got[0].external_id == str(uuid.UUID(int=1)) and got[0].email == "user1@corp.example"
    assert fake.cookies == [None, b"1"]  # two pages
    flt = fake.filters[0]
    assert f":{ldap_dir.IN_CHAIN}:=" in flt  # nested groups by the directory itself
    assert "Team \\28Ops\\29\\2a" in flt and ")(x=1" not in flt  # the DN cannot end the filter
    with pytest.raises(ldap_dir.LdapError):
        ldap_dir.group_dn(LDAP_CFG, "CN=x,DC=elsewhere,DC=example")  # outside the base
    with pytest.raises(ldap_dir.LdapError):
        ldap_dir.group_dn(LDAP_CFG, "(objectClass=*)")


def test_ldap_members_limit(monkeypatch):
    monkeypatch.setattr(ldap_dir, "MEMBERS_MAX", 3)
    fake = FakeLdap([[_entry(n) for n in range(1, 3)], [_entry(n) for n in range(3, 5)]])
    monkeypatch.setattr(ldap_dir, "_service", lambda cfg: fake)
    with pytest.raises(ldap_dir.LdapError) as exc:
        ldap_dir.group_members(LDAP_CFG, SEC)
    assert exc.value.category == "too_many"


GROUP = "0a0a0a0a-0000-0000-0000-0000000000aa"
ENTRA = {"enabled": True, "tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "client_secret_enc": encrypt_str("s3cr3t")}


def _graph(pages: list[dict], status: int = 200):  # noqa: ANN202
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        if req.url.path.endswith("/oauth2/v2.0/token"):
            return httpx.Response(200, json={"access_token": "app-token", "expires_in": 3600})
        assert req.url.host == "graph.microsoft.com"
        if status != 200:
            return httpx.Response(status, json={"error": {"code": "Authorization_RequestDenied"}})
        return httpx.Response(200, json=pages[int(req.url.params.get("page", "0"))])

    return httpx.MockTransport(handler), calls


def _gu(n: int, **kw) -> dict:
    return {"@odata.type": "#microsoft.graph.user", "id": str(uuid.UUID(int=n)), "displayName": f"User {n}", "userPrincipalName": f"User{n}@corp.example", "mail": f"user{n}@corp.example", "accountEnabled": True, **kw}


async def test_entra_transitive_members_paged_users_only(monkeypatch):
    nxt = f"{entra.GRAPH}/groups/{GROUP}/transitiveMembers/microsoft.graph.user?page=1"
    pages = [
        {"value": [_gu(1), {"@odata.type": "#microsoft.graph.group", "id": str(uuid.uuid4())}, _gu(2, mail=None)], "@odata.nextLink": nxt},
        {"value": [_gu(3, accountEnabled=False)], "@odata.nextLink": "https://evil.example/next"},
    ]
    transport, calls = _graph(pages)
    monkeypatch.setattr(entra, "transport", transport)
    got = await entra.group_members(ENTRA, GROUP)
    assert [p.username for p in got] == ["user1@corp.example", "user2@corp.example", "user3@corp.example"]
    assert got[1].email is None and got[2].enabled is False
    graph = [c for c in calls if c.url.host == "graph.microsoft.com"]
    assert len(graph) == 2 and "/transitiveMembers/microsoft.graph.user" in graph[0].url.path  # not to evil.example
    assert graph[0].url.params["$top"] == "999"


async def test_entra_permission_errors(monkeypatch):
    transport, _ = _graph([], status=403)
    monkeypatch.setattr(entra, "transport", transport)
    with pytest.raises(entra.EntraError) as exc:
        await entra.group_members(ENTRA, GROUP)
    assert exc.value.category == "forbidden"  # GroupMember.Read.All missing
    entra._app_tokens.clear()
    transport, _ = _graph([{"value": [{"@odata.type": "#microsoft.graph.user", "id": str(uuid.UUID(int=1))}]}])
    monkeypatch.setattr(entra, "transport", transport)
    with pytest.raises(entra.EntraError) as exc:
        await entra.group_members(ENTRA, GROUP)
    assert exc.value.category == "user_read"  # only ids: User.Read.All missing


async def test_entra_group_load_end_to_end(monkeypatch, admin_client):
    """Bound through the API, loaded through Graph (mocked): a 403 shows on the group as "forbidden"."""
    async with db.session() as s:
        await settings_store.put(s, "entra", ENTRA)
        await settings_store.put(s, "teams", {"enabled": True, "welcome_mail": False})
        await s.commit()
    transport, _ = _graph([{"value": [_gu(1), _gu(2)]}])
    monkeypatch.setattr(entra, "transport", transport)
    tid = await _team("Cloud")
    r = await admin_client.post(f"/api/admin/teams/{tid}/groups", json={"source": "entra", "group_id": GROUP.upper(), "group_name": "Cloud-Team"})
    assert r.status_code == 200 and r.json()["group_id"] == GROUP
    await teams.wait_idle()
    assert await _members(tid) == {"user1@corp.example", "user2@corp.example"}
    entra._app_tokens.clear()
    transport, _ = _graph([], status=403)
    monkeypatch.setattr(entra, "transport", transport)
    await _sync()
    g = (await admin_client.get("/api/admin/teams")).json()[0]["groups"][0]
    assert g["state"] == "error" and g["error"] == "forbidden"
    assert await _members(tid) == {"user1@corp.example", "user2@corp.example"}  # kept


# ---------------------------------------------------------------- leaving: switched off automatically (0.1.29)


async def _signed_in(name: str) -> None:
    async with db.session() as s:
        await s.execute(update(User).where(User.username == name).values(last_login_at=datetime.now(UTC)))
        await s.commit()


async def test_leaving_the_last_team_group_disables_never_signed_in(directory_fake, admin_client):
    await _settings()
    sec = await _team("Security", ("ldap", SEC))
    await _team("Network", ("ldap", NET))
    directory_fake.set("ldap", SEC, [person(1), person(2), person(3), person(4)])
    directory_fake.set("ldap", NET, [person(2)])
    await _sync()
    await _signed_in("user3")  # signed in once: the hourly account sync decides about it
    u4 = await _user("user4")
    await admin_client.patch(f"/api/admin/users/{u4.id}", json={"is_active": False, "version": u4.version})
    directory_fake.set("ldap", SEC, [])
    got = await _sync()
    assert got["deactivated"] == 1
    u1, u2, u3, u4 = [await _user(f"user{i}") for i in (1, 2, 3, 4)]
    assert not u1.is_active and u1.deactivated_reason == "sync:no_team"
    assert u2.is_active  # still in the Network team
    assert u3.is_active
    assert u4.deactivated_reason == "admin"  # an admin's block stays an admin's block
    # back in a team group: active again with the next load
    directory_fake.set("ldap", SEC, [person(1)])
    await _sync()
    u1 = await _user("user1")
    assert u1.is_active and u1.deactivated_reason is None
    # a group that cannot be read never switches anyone off
    directory_fake.set("ldap", SEC, "connection")
    await _sync()
    assert (await _user("user1")).is_active
    # deleting the team: its members are switched off at once, the Network member stays
    r = await admin_client.delete(f"/api/admin/teams/{sec}")
    assert r.status_code == 200
    assert not (await _user("user1")).is_active and (await _user("user2")).is_active


async def test_a_mapped_group_signs_a_switched_off_account_in_again(directory_fake):
    await _settings()
    await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1)])
    await _sync()
    directory_fake.set("ldap", SEC, [])
    await _sync()
    u = await _user("user1")
    assert not u.is_active and u.deactivated_reason == "sync:no_team"
    async with db.session() as s:
        s.add(GroupMapping(source="ldap", group_id=ADMINS, role="reader"))
        await s.commit()
        user = await directory.provision(s, DirectoryUser("ldap", u.external_id, "user1", "User 1", groups=[ADMINS]))
        await s.commit()
        assert user.is_active and user.deactivated_reason is None


async def test_switching_teams_off_disables_loaded_accounts_until_on_again(directory_fake, admin_client):
    await _settings()
    await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1), person(2)])
    await _sync()
    await _signed_in("user2")
    r = await admin_client.put("/api/admin/teams/settings", json={"enabled": False, "welcome_mail": False})
    assert r.status_code == 200
    u1 = await _user("user1")
    assert not u1.is_active and u1.deactivated_reason == "sync:teams_off"
    assert (await _user("user2")).is_active  # signed in: the hourly account sync decides
    assert await _sync() == {}  # the hourly step while off: nothing more to switch off
    r = await admin_client.put("/api/admin/teams/settings", json={"enabled": True, "welcome_mail": False})
    assert r.status_code == 200
    await teams.wait_idle()
    u1 = await _user("user1")
    assert u1.is_active and u1.deactivated_reason is None


async def test_no_welcome_mail_once_out_of_the_team_again(directory_fake, mails):
    await _settings(welcome_mail=True)
    await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1)])
    await _sync()
    directory_fake.set("ldap", SEC, [])
    await _sync()
    await _smtp()
    assert await _welcome() == 0 and mails.sent == []
    async with db.session() as s:
        w = await s.scalar(select(TeamWelcome))
        assert w.status == "failed" and w.error == "inactive"


# ---------------------------------------------------------------- review: things changed while the directories are asked


async def test_teams_switched_off_during_a_load_writes_nothing(directory_fake, monkeypatch):
    """The load asks the directories with nothing open; Teams switched off meanwhile (put_settings switches the loaded
    accounts off): the load must not switch them on again, add members or mark the groups loaded."""
    await _settings()
    tid = await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", SEC, [person(1)])
    await _sync()
    async with db.session() as s:
        await settings_store.put(s, "teams", {"enabled": False, "welcome_mail": False})
        await s.commit()
        await teams.deactivate_left(s, "sync:teams_off")
        await s.execute(update(TeamGroup).values(state="waiting"))
        await s.commit()
    assert not (await _user("user1")).is_active

    async def switched_on_then_off(source, cfg, group_id):  # noqa: ANN001, ANN202
        return [person(1), person(2)]

    monkeypatch.setattr(teams, "_members", switched_on_then_off)
    monkeypatch.setattr(teams, "config", _config_seq([{"enabled": True}, {"enabled": False}]))
    assert await _sync() == {}
    u1 = await _user("user1")
    assert not u1.is_active and u1.deactivated_reason == "sync:teams_off"
    assert await _user("user2") is None and await _members(tid) == {"user1"}
    async with db.session() as s:
        assert (await s.scalar(select(TeamGroup.state).where(TeamGroup.team_id == tid))) == "waiting"


def _config_seq(answers: list[dict]):  # noqa: ANN202
    """teams.config answering these one after the other (the last one from then on)."""
    left = list(answers)

    async def config(db):  # noqa: ANN001, ANN202
        return left.pop(0) if len(left) > 1 else left[0]

    return config


async def test_team_deleted_during_a_load_does_not_break_the_others(directory_fake, monkeypatch):
    await _settings()
    gone = await _team("Gone", ("ldap", NET))
    kept = await _team("Security", ("ldap", SEC))
    directory_fake.set("ldap", NET, [person(1)])
    directory_fake.set("ldap", SEC, [person(2)])
    real = teams._members

    async def delete_while_loading(source, cfg, group_id):  # noqa: ANN001, ANN202
        if group_id.lower() == NET.lower():
            async with db.session() as s:
                await s.delete(await s.get(Team, gone))
                await s.commit()
        return await real(source, cfg, group_id)

    monkeypatch.setattr(teams, "_members", delete_while_loading)
    await _sync()
    assert await _members(kept) == {"user2"}
    async with db.session() as s:
        assert (await s.scalar(select(TeamGroup.state).where(TeamGroup.team_id == kept))) == "ok"
