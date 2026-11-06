"""Approval of directory accounts ("Automatische Anmeldung über AD/Entra ID zulassen", app/auth/directory.py) and the
preload of the mapped groups (app/preload.py). On by default – nothing changes for existing installations. Off: new
directory accounts (preloaded, created at a sign-in, loaded by a team) and raises to admin wait for an admin; the
directory, a sign-in or a team load never switch a waiting account on; lowering and switching off stay automatic.

No directory is asked: the AD sign-in is a fake ldap_dir.authenticate, the group members come from a fake
teams._members (as in tests/test_teams.py), Microsoft from tests/test_entra.py's MockTransport."""

import asyncio
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import make_client, sign_in
from sqlalchemy import func, select, update

from app import audit, auth_api, db, preload, teams
from app import settings as settings_store
from app.auth import directory, ldap_dir
from app.auth import sync as directory_sync
from app.auth.directory import DirectoryUser
from app.crypto import encrypt_str
from app.models import AuditEntry, GroupMapping, Team, TeamGroup, TeamMember, TeamWelcome, User, UserSession

BASE = "DC=corp,DC=example"
READERS = f"CN=News-Readers,OU=Groups,{BASE}"
ADMINS = f"CN=News-Admins,OU=Groups,{BASE}"
TEAM = f"CN=Team-Sec,OU=Groups,{BASE}"
LDAP_CFG = {"enabled": True, "servers": ["dc01.corp.example"], "base_dn": BASE, "bind_dn": f"CN=svc,{BASE}", "bind_password_enc": encrypt_str("svc-pw")}
PW = "Right-Pw-2026!"


def person(n: int, groups=(READERS,), *, name: str | None = None, enabled: bool = True, ext: str | None = None) -> DirectoryUser:
    return DirectoryUser(
        source="ldap",
        external_id=ext or str(uuid.UUID(int=n)),
        username=name or f"user{n}",
        display_name=f"User {n}",
        email=f"user{n}@corp.example",
        groups=list(groups),
        enabled=enabled,
    )


@pytest.fixture
async def ad(monkeypatch):
    """A fake AD: sign-in (`people` by name – password PW) and group members (`members[(source, group dn lower)]` – a
    list, or an error category)."""
    people: dict[str, DirectoryUser] = {}
    members: dict[tuple[str, str], list[DirectoryUser] | str] = {}
    binds: list[str] = []

    def authenticate(cfg, username, password, seen=None, locked=None):  # noqa: ANN001, ANN202
        du = people.get(username)
        if du is None:
            return None
        if seen is not None:
            seen.append(du.external_id)
        binds.append(username)
        return du if password == PW else None

    async def group_members(source, cfg, gid):  # noqa: ANN001, ANN202
        return members.get((source, gid.lower()), [])

    monkeypatch.setattr(ldap_dir, "authenticate", authenticate)
    monkeypatch.setattr(teams, "_members", group_members)
    async with db.session() as s:
        await settings_store.put(s, "ldap", LDAP_CFG)
        await settings_store.put(s, "setup", {"completed": True})
        for gid, role in ((READERS, "reader"), (ADMINS, "admin")):
            s.add(GroupMapping(source="ldap", group_id=gid, group_name=role, role=role))
        await s.commit()

    class D:
        pass

    d = D()
    d.people, d.members, d.binds = people, members, binds
    d.add = lambda du: people.__setitem__(du.username, du)
    d.set = lambda gid, value, source="ldap": members.__setitem__((source, gid.lower()), value)
    return d


async def _approval(on: bool) -> None:
    async with db.session() as s:
        await settings_store.put(s, directory.SECTION, {"auto_signin": on})
        await s.commit()


async def _user(name: str) -> User | None:
    async with db.session() as s:
        return await s.scalar(select(User).where(User.username == name))


async def _actions(action: str) -> list[AuditEntry]:
    async with db.session() as s:
        return list(await s.scalars(select(AuditEntry).where(AuditEntry.action == action).order_by(AuditEntry.id)))


async def _login(name: str, pw: str = PW):  # noqa: ANN202
    c = make_client()
    r = await c.post("/api/auth/login", json={"username": name, "password": pw, "source": "ldap"})
    return r, c


async def _stale_reauth(c) -> None:  # noqa: ANN001
    """The admin's proof of identity is older than the re-confirmation window."""
    async with db.session() as s:
        await s.execute(update(UserSession).where(UserSession.user_id == c.user.id).values(reauth_at=datetime.now(UTC) - timedelta(hours=2)))
        await s.commit()


async def _preload() -> dict:
    async with db.session() as s:
        return await preload.sync(s)


# ---------------------------------------------------------------- default: as before


async def test_on_by_default_nothing_changes(ad, admin_client):
    async with db.session() as s:
        assert await directory.approval_required(s) is False
    ad.add(person(1))
    r, c = await _login("user1")
    assert r.status_code == 200 and r.json()["next"] == "done"
    u = await _user("user1")
    assert u.is_active and u.deactivated_reason is None and u.pending_role is None
    got = (await admin_client.get("/api/admin/auth/approval")).json()
    assert got["auto_signin"] is True and got["accounts"] == 0 and got["active_directory"] == 1
    await c.aclose()


# ---------------------------------------------------------------- sign-in while approval is required


async def test_signin_creates_a_waiting_account_and_says_so(ad, admin_client):
    await _approval(False)
    ad.add(person(1))
    r, c = await _login("user1")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "approval_pending"
    assert "cobe_news_session" not in "".join(c.cookies.keys())
    u = await _user("user1")
    assert not u.is_active and u.deactivated_reason == "pending" and u.role == "reader" and u.last_login_at is None
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(UserSession).where(UserSession.user_id == u.id)) == 0
    (pending,) = await _actions("user.approval_pending")
    assert pending.details["why"] == "signin" and pending.details["source"] == "ldap" and pending.notable and pending.actor_kind == "sync"
    assert (await _actions("user.created"))[-1].details.get("pending") is True
    # once more: still refused, logged as a refused sign-in – no second "waits" entry
    r2, c2 = await _login("user1")
    assert r2.status_code == 403 and r2.json()["detail"]["code"] == "approval_pending"
    assert len(await _actions("user.approval_pending")) == 1 and len(await _actions("login.pending_refused")) == 1
    # retried again and again: logged once per quarter of an hour (only the right password causes it – no flood)
    for _ in range(3):
        r3, c3 = await _login("user1")
        assert r3.status_code == 403
        await c3.aclose()
    assert len(await _actions("login.pending_refused")) == 1
    # admins see it: the list, the number on "Benutzer"
    rows = {x["username"]: x for x in (await admin_client.get("/api/admin/users")).json()}
    assert rows["user1"]["deactivated_reason"] == "pending" and rows["user1"]["is_active"] is False
    assert (await admin_client.get("/api/admin/users/pending")).json() == {"accounts": 1, "accounts_admin": 0, "raises": 0}
    await c.aclose()
    await c2.aclose()


async def test_waiting_state_is_never_told_before_the_password(ad):
    """Enumeration: a wrong password for a waiting account is answered as for anybody – the same code, counted."""
    await _approval(False)
    ad.add(person(1))
    await _login("user1")  # now waiting
    wrong, c1 = await _login("user1", "wrong")
    unknown, c2 = await _login("nobody", "wrong")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"]["code"] == unknown.json()["detail"]["code"] == "invalid_credentials"
    assert len(await _actions("login.pending_refused")) == 0
    await c1.aclose()
    await c2.aclose()


async def test_approved_account_signs_in_reader_without_reauth_admin_with(ad, admin_client):
    await _approval(False)
    ad.add(person(1))
    ad.add(person(2, (ADMINS,)))
    await _login("user1")
    await _login("user2")
    u1, u2 = await _user("user1"), await _user("user2")
    assert u2.role == "admin" and u2.deactivated_reason == "pending"
    await _stale_reauth(admin_client)
    # a reader: no re-confirmation needed
    r = await admin_client.post(f"/api/admin/users/{u1.id}/approve", json={"version": u1.version})
    assert r.status_code == 200 and r.json()["is_active"] is True
    # an admin: re-confirmed first
    r = await admin_client.post(f"/api/admin/users/{u2.id}/approve", json={"version": u2.version})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    assert (await _user("user2")).deactivated_reason == "pending"
    # … also switched on through the active switch (the same approval)
    r = await admin_client.patch(f"/api/admin/users/{u2.id}", json={"is_active": True, "version": u2.version})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    (approved,) = await _actions("user.approved")
    assert approved.actor_name == "anna" and approved.details["role"] == "reader" and approved.notable
    ok, c = await _login("user1")
    assert ok.status_code == 200 and ok.json()["next"] == "done"
    await c.aclose()


async def test_approval_via_the_switch_and_an_admin_role_is_marked(ad, admin_client):
    await _approval(False)
    ad.add(person(2, (ADMINS,)))
    await _login("user2")
    u = await _user("user2")
    r = await admin_client.patch(f"/api/admin/users/{u.id}", json={"is_active": True, "version": u.version})
    assert r.status_code == 200 and r.json()["is_active"] and r.json()["role"] == "admin"
    (e,) = await _actions("user.approved")
    assert "role_admin" in e.details.get("anomalies", [])
    assert await _actions("user.activated") == []  # one entry, the approval


async def test_approval_follows_the_groups_now_and_the_version(ad, admin_client):
    await _approval(False)
    ad.add(person(1))
    await _login("user1")
    u = await _user("user1")
    # an older state (another admin – or the directory – changed it): refused
    assert (await admin_client.post(f"/api/admin/users/{u.id}/approve", json={"version": u.version - 1})).status_code == 409
    # the reader mapping is removed meanwhile: nothing to approve
    async with db.session() as s:
        m = await s.scalar(select(GroupMapping).where(GroupMapping.group_id == READERS))
        await s.delete(m)
        await s.commit()
    r = await admin_client.post(f"/api/admin/users/{u.id}/approve", json={"version": u.version})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "no_role"
    # the group now mapped to admin: the shown role (reader) is no longer what approving gives – stale, the list shows admin
    async with db.session() as s:
        s.add(GroupMapping(source="ldap", group_id=READERS, group_name="x", role="admin"))
        await s.commit()
    r = await admin_client.post(f"/api/admin/users/{u.id}/approve", json={"version": u.version})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "stale"
    u = await _user("user1")
    assert u.role == "admin" and u.deactivated_reason == "pending"


async def test_decline_keeps_it_off_for_good(ad, admin_client):
    await _approval(False)
    ad.add(person(1))
    await _login("user1")
    u = await _user("user1")
    r = await admin_client.post(f"/api/admin/users/{u.id}/decline", json={"version": u.version})
    assert r.status_code == 200 and r.json()["deactivated_reason"] == "admin"
    assert len(await _actions("user.declined")) == 1
    # a sign-in – answered like a wrong password; the switch on again – the directory cannot; the preload neither
    r, c = await _login("user1")
    assert r.status_code == 401
    await _approval(True)
    ad.set(READERS, [person(1)])
    await _preload()
    async with db.session() as s:
        await directory_sync.run(s)
    u = await _user("user1")
    assert not u.is_active and u.deactivated_reason == "admin"
    # nothing to approve or decline any more
    assert (await admin_client.post(f"/api/admin/users/{u.id}/approve", json={})).status_code == 409
    assert (await admin_client.post(f"/api/admin/users/{u.id}/decline", json={})).status_code == 409
    await c.aclose()


async def test_the_directory_never_switches_a_waiting_account_on(ad):
    await _approval(False)
    ad.add(person(1))
    await _login("user1")
    # the switch on again: still waiting – at a sign-in, the account sync, a team load, the preload
    await _approval(True)
    r, c = await _login("user1")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "approval_pending"
    async with db.session() as s:
        u = await s.scalar(select(User).where(User.username == "user1"))
        assert await directory.apply_sync(s, u, person(1)) == "unchanged"
        await s.commit()
    ad.set(READERS, [person(1)])
    await _preload()
    async with db.session() as s:
        await settings_store.put(s, "teams", {"enabled": True})
        t = Team(name="Sec")
        s.add(t)
        await s.flush()
        s.add(TeamGroup(team_id=t.id, source="ldap", group_id=TEAM, group_name="Sec"))
        await s.commit()
    ad.set(TEAM, [person(1)])
    async with db.session() as s:
        await teams.sync(s)
    u = await _user("user1")
    assert not u.is_active and u.deactivated_reason == "pending"
    await c.aclose()


async def test_a_waiting_account_holds_no_session(ad, admin_client):
    """Even a session row made behind the app's back is no way in, and approving ends any."""
    await _approval(False)
    ad.add(person(1))
    await _login("user1")
    from app.auth import sessions

    async with db.session() as s:
        u = await s.scalar(select(User).where(User.username == "user1"))
        sess, _ = await sessions.create(s, u, "pre", "127.0.0.1", "x")
        token = await sessions.promote(s, sess, "active")
        await s.commit()
    c = make_client()
    c.cookies.set(sessions.cookie_name(), token)
    assert (await c.get("/api/me")).status_code == 401
    r = await admin_client.post(f"/api/admin/users/{u.id}/approve", json={})
    assert r.status_code == 200
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(UserSession).where(UserSession.user_id == u.id)) == 0
    await c.aclose()


async def test_approval_endpoints_need_an_admin_and_the_csrf_token(ad, admin_client, reader_client):
    await _approval(False)
    ad.add(person(1))
    await _login("user1")
    u = await _user("user1")
    for path in ("approve", "decline", "approve-role", "decline-role"):
        assert (await reader_client.post(f"/api/admin/users/{u.id}/{path}", json={})).status_code == 403
        # a cross-site form or a script without the token (double submit)
        r = await admin_client.post(f"/api/admin/users/{u.id}/{path}", json={}, headers={"X-CSRF-Token": "wrong"})
        assert r.status_code == 403 and r.json()["detail"]["code"] == "csrf_failed"
    assert (await reader_client.get("/api/admin/users/pending")).status_code == 403
    assert (await reader_client.put("/api/admin/auth/approval", json={"auto_signin": True})).status_code == 403
    assert (await _user("user1")).deactivated_reason == "pending"


async def test_two_sign_ins_at_once_make_one_waiting_account(ad):
    await _approval(False)
    du = person(1)

    async def one():  # noqa: ANN202
        async with db.session() as s:
            try:
                await auth_api._provision(s, du)
            except directory.ApprovalPending:
                await s.commit()
                return "pending"
            return "in"

    got = await asyncio.gather(one(), one())
    assert got == ["pending", "pending"]
    async with db.session() as s:
        rows = list(await s.scalars(select(User).where(User.external_id == du.external_id)))
    assert len(rows) == 1 and rows[0].deactivated_reason == "pending"


# ---------------------------------------------------------------- bound to the directory id, never to the name


async def test_recreated_account_with_the_same_name_waits_again(ad, admin_client):
    await _approval(False)
    old = person(1)
    ad.add(old)
    await _login("user1")
    u = await _user("user1")
    assert (await admin_client.post(f"/api/admin/users/{u.id}/approve", json={})).status_code == 200
    ok, c = await _login("user1")
    assert ok.status_code == 200
    # deleted in AD, a new account with the same name (a new objectGUID): the sync marks the old one gone …
    async with db.session() as s:
        acc = await s.get(User, u.id)
        await directory.apply_sync(s, acc, None)
        await s.commit()
    new = person(1, ext=str(uuid.uuid4()))
    ad.add(new)
    r, c2 = await _login("user1")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "approval_pending"
    async with db.session() as s:
        rows = {x.external_id: x for x in await s.scalars(select(User).where(User.auth_source == "ldap"))}
    assert rows[new.external_id].username == "user1" and rows[new.external_id].deactivated_reason == "pending"
    assert rows[old.external_id].username.startswith("user1~") and rows[old.external_id].deactivated_reason == "sync:gone"
    await c.aclose()
    await c2.aclose()


async def test_a_waiting_account_cannot_take_an_approved_name(ad, admin_client):
    await _approval(False)
    ad.add(person(1))
    await _login("user1")
    u1 = await _user("user1")
    await admin_client.post(f"/api/admin/users/{u1.id}/approve", json={})
    # another directory account renamed to "user1" in AD: no account – the name is taken (never the approved one's)
    ad.add(person(2, name="user1x"))
    ad.people["user1"] = person(2, name="user1")
    r, c = await _login("user1")
    assert r.status_code == 401  # username_conflict: answered like a wrong password
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(User).where(User.external_id == str(uuid.UUID(int=2)))) == 0
        approved = await s.get(User, u1.id)
    assert approved.is_active and approved.external_id == str(uuid.UUID(int=1))
    await c.aclose()


async def test_a_sync_off_account_that_never_signed_in_waits_when_back(ad):
    await _approval(True)
    ad.set(READERS, [person(1)])
    await _preload()  # on: preloaded, on
    u = await _user("user1")
    assert u.is_active
    async with db.session() as s:
        acc = await s.get(User, u.id)
        acc.is_active, acc.deactivated_reason = False, "sync:no_role"
        await s.commit()
    await _approval(False)
    await _preload()  # back in the group, never signed in, approval required: waits like a new one
    u = await _user("user1")
    assert not u.is_active and u.deactivated_reason == "pending"
    # one that signed in before comes back on (it was in use – a short absence must not need a new approval)
    ad.add(person(2))
    await _approval(True)
    r, c = await _login("user2")
    assert r.status_code == 200
    await _approval(False)
    async with db.session() as s:
        acc = await s.scalar(select(User).where(User.username == "user2"))
        acc.is_active, acc.deactivated_reason = False, "sync:disabled"
        await s.commit()
    r, c2 = await _login("user2")
    assert r.status_code == 200 and (await _user("user2")).is_active
    await c.aclose()
    await c2.aclose()


# ---------------------------------------------------------------- the raise to admin


async def test_raise_to_admin_waits_lowering_does_not(ad, admin_client):
    await _approval(False)
    ad.add(person(1))
    await _login("user1")
    u = await _user("user1")
    await admin_client.post(f"/api/admin/users/{u.id}/approve", json={})
    ok, c = await _login("user1")
    assert ok.status_code == 200
    # added to the admin group (by themselves, or by mistake): still reader – the raise waits, signing in goes on as reader
    ad.add(person(1, (READERS, ADMINS)))
    ok, c2 = await _login("user1")
    assert ok.status_code == 200 and ok.json()["user"]["role"] == "reader"
    u = await _user("user1")
    assert u.role == "reader" and u.pending_role == "admin"
    (e,) = await _actions("role.approval_pending")
    assert e.details["from"] == "reader" and e.details["to"] == "admin" and e.notable
    ok, c3 = await _login("user1")  # asked once, not at every sign-in
    assert len(await _actions("role.approval_pending")) == 1
    assert (await admin_client.get("/api/admin/users/pending")).json()["raises"] == 1
    # the hourly sync keeps it waiting too
    async with db.session() as s:
        acc = await s.get(User, u.id)
        await directory.apply_sync(s, acc, person(1, (READERS, ADMINS)), True)
        await s.commit()
    assert (await _user("user1")).role == "reader"
    # approving it: re-confirmed, its sessions end (the next sign-in asks for the admin's second factor)
    await _stale_reauth(admin_client)
    r = await admin_client.post(f"/api/admin/users/{u.id}/approve-role", json={})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    await sign_in(admin_client, admin_client.user)
    r = await admin_client.post(f"/api/admin/users/{u.id}/approve-role", json={})
    assert r.status_code == 200 and r.json()["role"] == "admin" and r.json()["pending_role"] is None
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(UserSession).where(UserSession.user_id == u.id)) == 0
    (e,) = await _actions("role.approved")
    assert "role_admin" in e.details["anomalies"] and e.details["changes"]["role"] == {"from": "reader", "to": "admin"}
    # out of the admin group again: lowered at once, approval or not (the safe direction)
    ad.add(person(1))
    ok, c4 = await _login("user1")
    assert ok.status_code == 200 and ok.json()["user"]["role"] == "reader"
    for x in (c, c2, c3, c4):
        await x.aclose()


async def test_declined_raise_is_not_asked_again_until_the_groups_change(ad, admin_client):
    await _approval(False)
    async with db.session() as s:
        u = User(username="lea", role="reader", auth_source="ldap", external_id=str(uuid.uuid4()), role_groups=[ADMINS.lower()], last_login_at=datetime.now(UTC))
        s.add(u)
        await s.commit()
    du = DirectoryUser(source="ldap", external_id=u.external_id, username="lea", display_name="Lea", groups=[ADMINS])
    async with db.session() as s:
        acc = await s.get(User, u.id)
        assert await directory.apply_sync(s, acc, du, True) == "raise_pending"
        await s.commit()
    r = await admin_client.post(f"/api/admin/users/{u.id}/decline-role", json={})
    assert r.status_code == 200 and r.json()["pending_role"] == "declined" and r.json()["role"] == "reader"
    assert len(await _actions("role.declined")) == 1
    for approval in (True, False):  # declined: neither the sync nor the switch on make it admin
        async with db.session() as s:
            acc = await s.get(User, u.id)
            assert await directory.apply_sync(s, acc, du, approval) == "unchanged"
            await s.commit()
    assert (await _user("lea")).role == "reader" and len(await _actions("role.approval_pending")) == 1
    # out of the admin group: forgotten – back in, asked again
    async with db.session() as s:
        acc = await s.get(User, u.id)
        await directory.apply_sync(s, acc, DirectoryUser(source="ldap", external_id=u.external_id, username="lea", display_name="Lea", groups=[READERS]), False)
        await s.commit()
        acc = await s.get(User, u.id)
        assert acc.pending_role is None
        assert await directory.apply_sync(s, acc, du, True) == "raise_pending"
        await s.commit()
    assert len(await _actions("role.approval_pending")) == 2


async def test_raise_approval_refused_when_the_groups_give_admin_no_more(ad, admin_client):
    async with db.session() as s:
        u = User(username="lea", role="reader", auth_source="ldap", external_id=str(uuid.uuid4()), role_groups=[READERS.lower()], pending_role="admin")
        s.add(u)
        await s.commit()
    r = await admin_client.post(f"/api/admin/users/{u.id}/approve-role", json={})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "no_role"
    assert (await _user("lea")).pending_role is None and (await _user("lea")).role == "reader"


# ---------------------------------------------------------------- the switch


async def test_switching_off_keeps_active_ones_on_and_on_again_approves_only_when_chosen(ad, admin_client):
    ad.add(person(1))
    r, c = await _login("user1")  # on: in at once
    got = (await admin_client.get("/api/admin/auth/approval")).json()
    assert got["active_directory"] == 1
    await _stale_reauth(admin_client)
    assert (await admin_client.put("/api/admin/auth/approval", json={"auto_signin": False, "rev": got["rev"]})).status_code == 403
    await sign_in(admin_client, admin_client.user)
    r = await admin_client.put("/api/admin/auth/approval", json={"auto_signin": False, "rev": got["rev"]})
    assert r.status_code == 200 and r.json()["auto_signin"] is False
    (e,) = [x for x in await _actions("signin.config_changed") if x.target_id == "directory"]
    assert e.details["changes"]["auto_signin"] == {"from": True, "to": False} and e.target_type == "signin"
    assert (await _user("user1")).is_active  # already on: stays on
    ok, c1 = await _login("user1")
    assert ok.status_code == 200
    # new ones wait (one as admin, one raise)
    ad.add(person(2))
    ad.add(person(3, (ADMINS,)))
    await _login("user2")
    await _login("user3")
    ad.add(person(1, (READERS, ADMINS)))
    await _login("user1")
    got = (await admin_client.get("/api/admin/auth/approval")).json()
    assert (got["accounts"], got["accounts_admin"], got["raises"]) == (2, 1, 1)
    # "approve all" only together with switching on
    r = await admin_client.put("/api/admin/auth/approval", json={"auto_signin": False, "approve_pending": True, "rev": got["rev"]})
    assert r.status_code == 422
    # on again – by default nothing waiting is switched on
    r = await admin_client.put("/api/admin/auth/approval", json={"auto_signin": True, "rev": got["rev"]})
    assert r.status_code == 200 and r.json()["accounts"] == 2 and r.json()["approved"] == {"accounts": 0, "raises": 0}
    assert (await _user("user2")).deactivated_reason == "pending" and (await _user("user1")).role == "reader"
    # off and on again with "auch alle wartenden freigeben": each one approved and logged
    r = await admin_client.put("/api/admin/auth/approval", json={"auto_signin": False, "rev": r.json()["rev"]})
    rev = r.json()["rev"]
    shown = {"accounts": 2, "accounts_admin": 1, "raises": 1}  # what the dialog showed
    r = await admin_client.put("/api/admin/auth/approval", json={"auto_signin": True, "approve_pending": True, "rev": rev})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "approve_needs_counts"  # never without the numbers
    # another one came to wait since the dialog opened: refused, nothing approved, nothing switched
    ad.add(person(4))
    await _login("user4")
    r = await admin_client.put("/api/admin/auth/approval", json={"auto_signin": True, "approve_pending": True, "expect": shown, "rev": rev})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "stale"
    assert (await _user("user2")).deactivated_reason == "pending" and await _actions("user.approved") == []
    got = (await admin_client.get("/api/admin/auth/approval")).json()
    assert got["auto_signin"] is False and (got["accounts"], got["accounts_admin"], got["raises"]) == (3, 1, 1)
    # declined meanwhile (one waiting less): the dialog showed more than waits now – refused as well
    async with db.session() as s:
        u4 = await s.scalar(select(User).where(User.username == "user4"))
        u4.deactivated_reason = "admin"
        await s.commit()
    shown = {"accounts": 3, "accounts_admin": 1, "raises": 1}
    r = await admin_client.put("/api/admin/auth/approval", json={"auto_signin": True, "approve_pending": True, "expect": shown, "rev": rev})
    assert r.status_code == 409
    shown = {"accounts": 2, "accounts_admin": 1, "raises": 1}
    r = await admin_client.put("/api/admin/auth/approval", json={"auto_signin": True, "approve_pending": True, "expect": shown, "rev": rev})
    assert r.status_code == 200 and r.json()["approved"] == {"accounts": 2, "raises": 1}
    assert (await _user("user2")).is_active and (await _user("user3")).role == "admin" and (await _user("user1")).role == "admin"
    assert {e.details["why"] for e in await _actions("user.approved")} == {"bulk"} and len(await _actions("user.approved")) == 2
    assert len(await _actions("role.approved")) == 1
    # another admin saved in between: stale, and nothing of it is approved
    none = {"accounts": 0, "accounts_admin": 0, "raises": 0}
    assert (await admin_client.put("/api/admin/auth/approval", json={"auto_signin": True, "approve_pending": True, "expect": none, "rev": 0})).status_code == 409
    for x in (c, c1):
        await x.aclose()


async def test_local_accounts_and_the_emergency_admin_are_never_concerned(ad, admin_client):
    await _approval(False)
    async with db.session() as s:
        s.add(User(username="notfall", role="admin", auth_source="local", is_emergency=True))
        s.add(User(username="lokal", role="reader", auth_source="local"))
        await s.commit()
    ad.set(READERS, [person(1)])
    await _preload()
    for name in ("notfall", "lokal"):
        u = await _user(name)
        assert u.is_active and u.deactivated_reason is None
    # a directory account named like a local one is never created (nor approved into it)
    ad.set(READERS, [person(1), person(11, name="lokal")])
    got = await _preload()
    assert got.get("conflicts") == 1
    assert (await _user("lokal")).auth_source == "local"
    # nor renamed into it
    ad.set(READERS, [person(1, name="lokal")])
    await _preload()
    assert (await _user("user1")).external_id == str(uuid.UUID(int=1)) and (await _user("lokal")).auth_source == "local"


# ---------------------------------------------------------------- preload


async def test_preload_creates_accounts_on_and_waiting(ad, admin_client):
    ad.set(READERS, [person(1), person(2, enabled=False)])
    ad.set(ADMINS, [person(3), person(1)])
    got = await _preload()
    assert got["created"] == 2  # a disabled member gets no account
    u1, u3 = await _user("user1"), await _user("user3")
    assert u1.is_active and u1.role == "admin" and u1.last_login_at is None and u1.password_hash is None
    assert sorted(u1.role_groups) == sorted([READERS.lower(), ADMINS.lower()])
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(UserSession)) == 1  # the admin's own only
    (e,) = await _actions("directory.preloaded")
    assert e.details["created"] == 2 and e.actor_kind == "sync"
    # approval required: new members wait
    await _approval(False)
    ad.set(READERS, [person(1), person(4)])
    await _preload()
    u4 = await _user("user4")
    assert not u4.is_active and u4.deactivated_reason == "pending"
    assert [x.details["why"] for x in await _actions("user.approval_pending")] == ["preload"]
    assert (await _user("user3")).is_active  # on before: stays on


async def test_preload_deletes_unused_accounts_only_when_every_group_was_read(ad, admin_client):
    ad.set(READERS, [person(1), person(2), person(3), person(4), person(5)])
    await _preload()
    # user2 signs in once; user3 is declined/blocked by an admin; user4 is in a team; user5 has a sign-in in progress
    async with db.session() as s:
        rows = {u.username: u for u in await s.scalars(select(User).where(User.auth_source == "ldap"))}
        rows["user2"].last_login_at = datetime.now(UTC)
        rows["user3"].is_active, rows["user3"].deactivated_reason = False, "admin"
        t = Team(name="Sec")
        s.add(t)
        await s.flush()
        s.add(TeamMember(team_id=t.id, user_id=rows["user4"].id, origin="group"))
        await s.commit()
        from app.auth import sessions

        await sessions.create(s, rows["user5"], "mfa", "127.0.0.1", "x")
        await s.commit()
    u1 = rows["user1"]
    async with db.session() as s:
        audit.record(s, audit.SYNC, "user.activated", audit.user_target(u1), {})
        await s.commit()
    # out of every mapped group – but the admin group cannot be read: nothing deleted
    ad.set(READERS, [])
    ad.set(ADMINS, "unreachable")
    got = await _preload()
    assert "deleted" not in got and await _user("user1") is not None
    # both read: user1 goes (never signed in, nothing else holds it); the others stay
    ad.set(ADMINS, [])
    got = await _preload()
    assert got["deleted"] == 1 and await _user("user1") is None
    for name in ("user2", "user3", "user4", "user5"):
        assert await _user(name) is not None, name
    # the audit log keeps who it was (its target is text, no foreign key)
    async with db.session() as s:
        rows = list(await s.scalars(select(AuditEntry).where(AuditEntry.target_id == str(u1.id)).order_by(AuditEntry.id)))
    assert [r.action for r in rows] == ["user.created", "user.activated", "user.deleted"] and rows[-1].target_label == "user1" and rows[-1].details["why"] == "unused"


async def test_a_group_that_cannot_be_read_is_logged_when_that_is_new(ad, monkeypatch):
    """Entra without the Graph permissions: every hourly run fails the same groups – one directory.preloaded entry,
    again only when other groups fail, after a day, or when it fails again after it worked."""
    from app import preload as pl

    ad.set(READERS, "forbidden")
    ad.set(ADMINS, [])
    for _ in range(3):
        await _preload()
    (e,) = await _actions("directory.preloaded")
    assert e.details["failed_groups"] == 1 and e.details["groups"] == 2
    async with db.session() as s:
        st = await settings_store.get(s, pl.STATE)
    assert st["failed"] == [f"ldap:{READERS.lower()}"]
    # another set of groups fails: news
    ad.set(ADMINS, "unreachable")
    await _preload()
    await _preload()
    assert [x.details["failed_groups"] for x in await _actions("directory.preloaded")] == [1, 2]
    # the same, a day later: once more
    monkeypatch.setattr(pl, "FAILED_AGAIN", timedelta(0))
    await _preload()
    assert len(await _actions("directory.preloaded")) == 3
    monkeypatch.setattr(pl, "FAILED_AGAIN", timedelta(days=1))
    # it works again (nothing to change: no entry) – and fails again: news
    ad.set(READERS, [])
    ad.set(ADMINS, [])
    await _preload()
    async with db.session() as s:
        assert (await settings_store.get(s, pl.STATE))["failed"] == []
    assert len(await _actions("directory.preloaded")) == 3
    ad.set(READERS, "forbidden")
    await _preload()
    assert len(await _actions("directory.preloaded")) == 4
    # accounts changed in a run with the known failure: logged as always (with the count)
    ad.set(ADMINS, [person(7)])
    await _preload()
    last = (await _actions("directory.preloaded"))[-1]
    assert len(await _actions("directory.preloaded")) == 5 and last.details["created"] == 1 and last.details["failed_groups"] == 1


async def test_preload_never_lowers_on_half_an_answer(ad):
    ad.set(READERS, [person(1)])
    ad.set(ADMINS, [person(1)])
    await _preload()
    assert (await _user("user1")).role == "admin"
    ad.set(ADMINS, "timeout")
    await _preload()
    u = await _user("user1")
    assert u.role == "admin" and ADMINS.lower() in u.role_groups  # the unread group is kept
    ad.set(ADMINS, [])
    await _preload()
    assert (await _user("user1")).role == "reader"


async def test_preload_follows_on_off_and_never_touches_signed_in_accounts(ad):
    ad.set(READERS, [person(1), person(2)])
    await _preload()
    async with db.session() as s:
        await s.execute(update(User).where(User.username == "user2").values(last_login_at=datetime.now(UTC), display_name="Mine"))
        await s.commit()
    ad.set(READERS, [person(1, enabled=False), person(2, enabled=False)])
    got = await _preload()
    assert got["deactivated"] == 1
    assert (await _user("user1")).deactivated_reason == "sync:disabled"
    u2 = await _user("user2")
    assert u2.is_active and u2.display_name == "Mine"  # the hourly account sync decides for it
    ad.set(READERS, [person(1)])
    assert (await _preload())["reactivated"] == 1


async def test_mapping_added_loads_its_members_in_the_background(ad, admin_client):
    ad.set(f"CN=Ops,{BASE}", [person(7)])
    r = await admin_client.post("/api/admin/auth/mappings", json={"source": "ldap", "group_id": f"CN=Ops,{BASE}", "group_name": "Ops", "role": "reader"})
    assert r.status_code == 200
    await teams.wait_idle()
    assert (await _user("user7")).is_active
    # removed: the account that never signed in goes with it
    assert (await admin_client.delete(f"/api/admin/auth/mappings/{r.json()['id']}")).status_code == 200
    await teams.wait_idle()
    assert await _user("user7") is None


async def test_teams_never_switches_off_an_account_a_mapping_holds(ad):
    ad.set(READERS, [person(1)])
    await _preload()
    async with db.session() as s:
        assert await teams.deactivate_left(s) == 0
        assert await teams.deactivate_left(s, "sync:teams_off") == 0
    assert (await _user("user1")).is_active


async def test_team_loaded_accounts_wait_and_get_their_welcome_mail_once_approved(ad, admin_client, monkeypatch):
    await _approval(False)
    async with db.session() as s:
        await settings_store.put(s, "teams", {"enabled": True, "welcome_mail": True})
        await settings_store.put(s, "smtp", {**settings_store.DEFAULTS["smtp"], "host": "mail.corp.example", "from_addr": "news@corp.example"})
        t = Team(name="Sec")
        s.add(t)
        await s.flush()
        s.add(TeamGroup(team_id=t.id, source="ldap", group_id=TEAM, group_name="Sec"))
        await s.commit()
    ad.set(TEAM, [person(9)])
    async with db.session() as s:
        got = await teams.sync(s)
    assert got["created"] == 1
    u = await _user("user9")
    assert not u.is_active and u.deactivated_reason == "pending" and u.role == "reader"
    assert [e.details["why"] for e in await _actions("user.approval_pending")] == ["team"]
    sent: list = []

    async def send_mail(cfg, to, *a, **kw):  # noqa: ANN001, ANN002, ANN003, ANN202
        sent.append(to)

    from app import notify

    monkeypatch.setattr(notify, "send_mail", send_mail)
    async with db.session() as s:
        assert await teams.send_welcome(s) == 0
    async with db.session() as s:
        assert (await s.scalar(select(TeamWelcome.status))) == "pending"
    # approved (the team gives reader): the mail goes out
    r = await admin_client.post(f"/api/admin/users/{u.id}/approve", json={})
    assert r.status_code == 200 and r.json()["role"] == "reader"
    async with db.session() as s:
        assert await teams.send_welcome(s) == 1
    assert sent == [["user9@corp.example"]]


async def test_big_group_preloaded_in_batches(ad):
    """5000 members of a mapped group, approval required: in batches (each its own transaction), quickly enough, and the
    log gets one entry each up to the budget – the rest counted in the summary."""
    await _approval(False)
    ad.set(READERS, [person(n) for n in range(1, 5001)])
    commits = 0
    real = preload._batch

    async def counting(s, *a, **kw):  # noqa: ANN001, ANN002, ANN003, ANN202
        nonlocal commits
        commits += 1
        return await real(s, *a, **kw)

    preload._batch = counting
    try:
        t0 = time.monotonic()
        got = await _preload()
        took = time.monotonic() - t0
    finally:
        preload._batch = real
    assert got["created"] == 5000 and got["pending"] == 5000
    assert commits == 5000 // teams.BATCH
    assert took < 60, took
    assert len(await _actions("user.approval_pending")) == directory.AUDIT_EACH_MAX
    (e,) = await _actions("directory.preloaded")
    assert e.details["not_listed"] == 5000 - directory.AUDIT_EACH_MAX
    # a second run changes nothing and writes no entry
    assert await _preload() == {}
    # all of them leave: deleted, in batches
    ad.set(READERS, [])
    t0 = time.monotonic()
    assert (await _preload())["deleted"] == 5000
    assert time.monotonic() - t0 < 60


# ---------------------------------------------------------------- Entra ID


async def test_entra_sign_in_waits_too(admin_client, monkeypatch):
    from test_entra import FakeMicrosoft, _sign_in  # noqa: F401 - the mocked Microsoft of the Entra tests
    import httpx

    from app.auth import entra

    fake = FakeMicrosoft()
    monkeypatch.setattr(entra, "transport", httpx.MockTransport(fake.handler))
    from test_entra import CLIENT, READERS as E_READERS, TENANT

    r = await admin_client.put("/api/admin/auth/entra", json={"enabled": True, "tenant_id": TENANT, "client_id": CLIENT, "client_secret": "s3cr3t"})
    assert r.status_code == 200
    async with db.session() as s:
        s.add(GroupMapping(source="entra", group_id=E_READERS, group_name="r", role="reader"))
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    await _approval(False)
    cb, c = await _sign_in(fake)
    assert cb.headers["location"] == "/?login_error=directory_pending"
    assert (await c.get("/api/me")).status_code == 401
    async with db.session() as s:
        u = await s.scalar(select(User).where(User.auth_source == "entra"))
    assert u.deactivated_reason == "pending" and u.external_id == fake.user["id"]
    assert (await admin_client.post(f"/api/admin/users/{u.id}/approve", json={})).status_code == 200
    await c.aclose()
    cb, c = await _sign_in(fake)
    assert cb.headers["location"] == "/" and (await c.get("/api/me")).json()["role"] == "reader"
    await c.aclose()


# ---------------------------------------------------------------- review round: locks, logging, partial cases


async def test_a_failing_preload_never_skips_the_account_sync(ad, monkeypatch):
    from app.main import FetchLoop

    ran: list[str] = []

    async def broken(s):  # noqa: ANN001, ANN202
        raise RuntimeError("boom")

    async def account_sync(s):  # noqa: ANN001, ANN202
        ran.append("sync")
        return {}

    monkeypatch.setattr(preload, "sync", broken)
    monkeypatch.setattr(directory_sync, "run", account_sync)
    await FetchLoop()._directory()
    assert ran == ["sync"]


async def test_a_preloaded_admin_is_always_in_the_log(ad):
    ad.set(ADMINS, [person(1)])
    await _preload()
    (e,) = await _actions("user.created")
    assert e.details["role"] == "admin" and e.details["why"] == "preload" and "role_admin" in e.details["anomalies"]


async def test_kept_by_a_team_but_out_of_the_admin_group_falls_to_reader(ad):
    ad.set(ADMINS, [person(1)])
    await _preload()
    async with db.session() as s:
        u = await s.scalar(select(User).where(User.username == "user1"))
        await settings_store.put(s, "teams", {"enabled": True})
        t = Team(name="Sec")
        s.add(t)
        await s.flush()
        s.add(TeamMember(team_id=t.id, user_id=u.id, origin="group"))
        await s.commit()
    ad.set(ADMINS, [])
    got = await _preload()
    u = await _user("user1")
    assert got["role"] == 1 and u is not None and u.role == "reader" and ADMINS.lower() not in u.role_groups


def test_the_preload_reads_direct_members_when_nesting_is_off():
    assert ":1.2.840.113556.1.4.1941:=" in ldap_dir.member_filter("CN=G,DC=x")
    flt = ldap_dir.member_filter("CN=G,DC=x", nested=False)
    assert "(memberOf=CN=G,DC=x)" in flt and "1941" not in flt


async def test_preload_hands_the_nesting_choice_to_the_member_query(ad, monkeypatch):
    seen: list = []

    async def members(source, cfg, gid):  # noqa: ANN001, ANN202
        seen.append(cfg.get("members_nested"))
        return []

    monkeypatch.setattr(teams, "_members", members)
    async with db.session() as s:
        await settings_store.put(s, "ldap", {**LDAP_CFG, "nested_groups": False})
        await s.commit()
    await _preload()
    assert seen and set(seen) == {False}
