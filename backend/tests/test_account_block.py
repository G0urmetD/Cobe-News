"""Security review: an admin's lasting block also for accounts the sync switched off (POST /users/{id}/block), and
access taken away at once – a removed role mapping re-checks the accounts it concerns from the groups kept with them
(User.role_groups), switching AD/LDAP or Entra ID off ends the sessions of its accounts. Local accounts and the
emergency admin are never concerned; the admin doing it cannot lock itself out. No directory is asked – the members
come from a fake directory, the groups of a sign-in or sync are given as DirectoryUser."""

import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from conftest import add_user, make_client, sign_in
from sqlalchemy import func, select, update

from app import db, teams
from app import settings as settings_store
from app.auth import directory
from app.auth.directory import DirectoryUser
from app.crypto import encrypt_str
from app.models import GroupMapping, Team, TeamGroup, TeamMember, User, UserSession

BASE = "DC=corp,DC=example"
ADMINS = f"CN=News-Admins,OU=Groups,{BASE}"
ADMINS2 = f"CN=SOC-Leads,OU=Groups,{BASE}"
READERS = f"CN=News-Readers,OU=Groups,{BASE}"
SEC = f"CN=Team-Security,OU=Groups,{BASE}"
LDAP_CFG = {"enabled": True, "servers": ["dc01.corp.example"], "base_dn": BASE, "bind_dn": f"CN=svc,{BASE}", "bind_password_enc": encrypt_str("svc-pw")}


def du(n: int, *groups: str, enabled: bool = True) -> DirectoryUser:
    return DirectoryUser("ldap", str(uuid.UUID(int=n)), f"user{n}", f"User {n}", email=f"user{n}@corp.example", groups=list(groups), enabled=enabled)


@pytest.fixture
def directory_fake(monkeypatch):
    groups: dict[tuple[str, str], list[DirectoryUser]] = {}

    async def members(source, cfg, group_id):  # noqa: ANN001, ANN202
        return groups.get((source, group_id.lower()), [])

    monkeypatch.setattr(teams, "_members", members)
    return lambda gid, people: groups.__setitem__(("ldap", gid.lower()), people)


async def _setup(*, teams_on: bool = False) -> None:
    async with db.session() as s:
        await settings_store.put(s, "ldap", LDAP_CFG)
        await settings_store.put(s, "teams", {"enabled": teams_on, "welcome_mail": False})
        await s.commit()


async def _map(group_id: str, role: str) -> uuid.UUID:
    async with db.session() as s:
        m = GroupMapping(source="ldap", group_id=group_id, group_name=group_id.split(",")[0][3:], role=role)
        s.add(m)
        await s.commit()
        return m.id


async def _team(*group_ids: str) -> uuid.UUID:
    async with db.session() as s:
        t = Team(name=f"Team {uuid.uuid4().hex[:6]}")
        s.add(t)
        await s.flush()
        for g in group_ids:
            s.add(TeamGroup(team_id=t.id, source="ldap", group_id=g, group_name=g.split(",")[0]))
        await s.commit()
        return t.id


async def _signed_in(p: DirectoryUser) -> User:
    """A directory account as after its sign-in: provisioned from its groups (which keeps them), with a session."""
    async with db.session() as s:
        u = await directory.provision(s, p)
        u.last_login_at = datetime.now(UTC)
        if u.role == "admin":
            u.totp_secret_enc = encrypt_str(pyotp.random_base32())
        await s.commit()
    async with make_client() as c:
        await sign_in(c, u)
    return u


async def _get(uid) -> User:  # noqa: ANN001
    async with db.session() as s:
        return await s.get(User, uid)


async def _sessions(uid) -> int:  # noqa: ANN001
    async with db.session() as s:
        return int(await s.scalar(select(func.count()).select_from(UserSession).where(UserSession.user_id == uid)) or 0)


async def _age_reauth(user_id) -> None:  # noqa: ANN001
    async with db.session() as s:
        await s.execute(update(UserSession).where(UserSession.user_id == user_id).values(reauth_at=datetime.now(UTC) - timedelta(hours=1)))
        await s.commit()


# ---------------------------------------------------------------- task 1: the lasting block


async def test_sign_in_and_sync_keep_the_role_groups():
    await _setup()
    await _map(ADMINS, "admin")
    await _map(READERS, "reader")
    async with db.session() as s:
        u = await directory.provision(s, du(1, ADMINS, f"CN=Unrelated,{BASE}"))
        await s.commit()
        assert u.role_groups == [ADMINS.lower()]  # only the groups that matter for the role
        await directory.apply_sync(s, u, du(1, READERS))
        assert u.role_groups == [READERS.lower()] and u.role == "reader"
        await directory.apply_sync(s, u, None)  # gone
        assert u.role_groups == [] and not u.is_active


async def test_block_of_a_team_account_switched_off_by_the_sync_sticks(directory_fake, admin_client):
    await _setup(teams_on=True)
    await _team(SEC)
    directory_fake(SEC, [du(1)])
    async with db.session() as s:
        await teams.sync(s)
    directory_fake(SEC, [])
    async with db.session() as s:
        await teams.sync(s)
    u = await _get((await _by_name("user1")).id)
    assert not u.is_active and u.deactivated_reason == "sync:no_team"
    r = await admin_client.post(f"/api/admin/users/{u.id}/block", json={"blocked": True, "version": u.version})
    assert r.status_code == 200 and r.json()["deactivated_reason"] == "admin" and not r.json()["is_active"]
    # back in the team group: the team load does not switch it on again
    directory_fake(SEC, [du(1)])
    async with db.session() as s:
        await teams.sync(s)
    u = await _get(u.id)
    assert not u.is_active and u.deactivated_reason == "admin"
    # nor a sign-in with a mapped group, nor the hourly sync
    await _map(ADMINS, "admin")
    async with db.session() as s:
        with pytest.raises(directory.DirectoryError) as exc:
            await directory.provision(s, du(1, ADMINS))
        assert exc.value.code == "disabled"
    async with db.session() as s:
        u = await s.get(User, u.id)
        assert await directory.apply_sync(s, u, du(1, ADMINS)) == "unchanged"
        assert not u.is_active and u.deactivated_reason == "admin"


async def test_block_of_a_signed_in_account_switched_off_by_the_sync_sticks(admin_client):
    await _setup()
    mid = await _map(READERS, "reader")
    u = await _signed_in(du(2, READERS))
    async with db.session() as s:
        await s.delete(await s.get(GroupMapping, mid))
        acc = await s.get(User, u.id)
        assert await directory.apply_sync(s, acc, du(2, READERS)) == "deactivated"
        await s.commit()
    u = await _get(u.id)
    assert u.deactivated_reason == "sync:no_role"
    r = await admin_client.post(f"/api/admin/users/{u.id}/block", json={"blocked": True, "version": u.version})
    assert r.status_code == 200
    await _map(READERS, "reader")
    async with db.session() as s:
        acc = await s.get(User, u.id)
        assert await directory.apply_sync(s, acc, du(2, READERS)) == "unchanged"
        with pytest.raises(directory.DirectoryError):
            await directory.provision(s, du(2, READERS))
    assert (await _get(u.id)).deactivated_reason == "admin"


async def test_lifting_the_block_hands_the_account_back_to_the_sync(directory_fake, admin_client):
    await _setup(teams_on=True)
    await _team(SEC)
    directory_fake(SEC, [du(1), du(3)])
    async with db.session() as s:
        await teams.sync(s)
    u1, u3 = await _by_name("user1"), await _by_name("user3")
    for u in (u1, u3):
        assert (await admin_client.post(f"/api/admin/users/{u.id}/block", json={"blocked": True})).status_code == 200
    # lifted: off until the sync (or a sign-in) finds a group again – never on by itself
    r = await admin_client.post(f"/api/admin/users/{u1.id}/block", json={"blocked": False})
    assert r.status_code == 200 and not r.json()["is_active"] and r.json()["deactivated_reason"] == "sync:unblocked"
    directory_fake(SEC, [du(1)])  # user3 is no longer in the team group
    async with db.session() as s:
        await teams.sync(s)
    assert (await _get(u1.id)).is_active
    # user3: lifted while out of every group – stays off; a sign-in with a mapped group switches it on
    assert (await admin_client.post(f"/api/admin/users/{u3.id}/block", json={"blocked": False})).status_code == 200
    async with db.session() as s:
        await teams.sync(s)
    assert not (await _get(u3.id)).is_active
    await _map(READERS, "reader")
    async with db.session() as s:
        acc = await directory.provision(s, du(3, READERS))
        await s.commit()
        assert acc.is_active and acc.deactivated_reason is None
    # the hourly sync, too
    async with db.session() as s:
        acc = await s.get(User, u3.id)
        acc.is_active, acc.deactivated_reason = False, "sync:unblocked"
        assert await directory.apply_sync(s, acc, du(3, READERS)) == "reactivated"


async def test_block_rules(admin_client):
    emergency = await add_user("notfall", "admin", emergency=True)
    local = await add_user("lena", "reader")
    me = admin_client.user
    for u in (emergency, me):
        r = await admin_client.post(f"/api/admin/users/{u.id}/block", json={"blocked": True})
        assert r.status_code == 409 and r.json()["detail"]["code"] == "user_protected"
    r = await admin_client.post(f"/api/admin/users/{local.id}/block", json={"blocked": False})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "not_blocked"
    async with make_client() as c:
        await sign_in(c, local)
        assert (await admin_client.post(f"/api/admin/users/{local.id}/block", json={"blocked": True})).status_code == 200
        assert (await c.get("/api/me")).status_code == 401  # its sessions ended
    # a local account: lifted means on again (no sync decides for it)
    r = await admin_client.post(f"/api/admin/users/{local.id}/block", json={"blocked": False})
    assert r.status_code == 200 and r.json()["is_active"] and r.json()["deactivated_reason"] is None
    # stale version refused
    r = await admin_client.post(f"/api/admin/users/{local.id}/block", json={"blocked": True, "version": 1})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "stale"
    # re-confirmed, as the other sensitive account changes
    await _age_reauth(me.id)
    r = await admin_client.post(f"/api/admin/users/{local.id}/block", json={"blocked": True})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"


async def _by_name(name: str) -> User:
    async with db.session() as s:
        return await s.scalar(select(User).where(User.username == name))


# ---------------------------------------------------------------- task 2: a removed mapping takes effect at once


async def test_removed_admin_mapping_demotes_and_signs_out_at_once(admin_client):
    await _setup(teams_on=True)
    admins = await _map(ADMINS, "admin")
    await _map(ADMINS2, "admin")
    await _map(READERS, "reader")
    await _team(SEC)
    demoted = await _signed_in(du(1, ADMINS, READERS))  # admin → reader through another mapping
    other = await _signed_in(du(2, ADMINS, ADMINS2))  # admin through another admin mapping: stays
    lost = await _signed_in(du(3, ADMINS))  # nothing left: off
    team = await _signed_in(du(4, ADMINS, SEC))  # admin → reader through the team
    unknown = await _signed_in(du(5, ADMINS))
    async with db.session() as s:  # signed in before the groups were kept
        await s.execute(update(User).where(User.id == unknown.id).values(role_groups=None))
        await s.commit()
    reader = await _signed_in(du(6, READERS))  # a reader is not concerned by an admin mapping
    emergency = await add_user("notfall", "admin", emergency=True)
    local = await add_user("lisa", "admin", totp_secret=pyotp.random_base32())
    for u in (emergency, local):
        async with make_client() as c:
            await sign_in(c, u)

    r = await admin_client.get(f"/api/admin/auth/mappings/{admins}/impact")
    assert r.json() == {"lost": 1, "demoted": 2, "unknown": 1, "self": False, "affected": 4}
    r = await admin_client.delete(f"/api/admin/auth/mappings/{admins}")
    assert r.status_code == 200 and r.json()["affected"] == 4

    d, o, lo, t, un, rd = [await _get(u.id) for u in (demoted, other, lost, team, unknown, reader)]
    assert d.role == "reader" and d.is_active and await _sessions(d.id) == 0
    assert o.role == "admin" and await _sessions(o.id) == 1
    assert not lo.is_active and lo.deactivated_reason == "sync:no_role" and await _sessions(lo.id) == 0
    assert t.role == "reader" and t.is_active and await _sessions(t.id) == 0
    assert un.role == "admin" and un.is_active and await _sessions(un.id) == 0  # the safe side: signed out, role left to the sync
    assert rd.role == "reader" and await _sessions(rd.id) == 1
    for u in (emergency, local, admin_client.user):
        assert (await _get(u.id)).role == "admin" and await _sessions(u.id) == 1
    # a later sign-in of the one who lost the role through the group: refused (no mapped group left)
    async with db.session() as s:
        with pytest.raises(directory.DirectoryError):
            await directory.provision(s, du(3, ADMINS))


async def test_removed_reader_mapping_keeps_team_readers_signed_in(admin_client):
    await _setup(teams_on=True)
    readers = await _map(READERS, "reader")
    tid = await _team(f"CN=Other-Team,{BASE}")
    via_team = await _signed_in(du(1, READERS))
    async with db.session() as s:  # the team load found the person (a nested member – not among the kept groups)
        s.add(TeamMember(team_id=tid, user_id=via_team.id, origin="group"))
        await s.commit()
    only = await _signed_in(du(2, READERS))
    r = await admin_client.delete(f"/api/admin/auth/mappings/{readers}")
    assert r.status_code == 200 and r.json()["affected"] == 1
    t, o = await _get(via_team.id), await _get(only.id)
    assert t.is_active and t.role == "reader" and await _sessions(t.id) == 1
    assert not o.is_active and o.deactivated_reason == "sync:no_role" and await _sessions(o.id) == 0


async def test_removed_mapping_without_instant_check_waits_for_the_sync(admin_client):
    await _setup()
    admins = await _map(ADMINS, "admin")
    u = await _signed_in(du(1, ADMINS))
    r = await admin_client.delete(f"/api/admin/auth/mappings/{admins}?end_sessions=false")
    assert r.status_code == 200 and r.json()["affected"] == 0
    assert (await _get(u.id)).role == "admin" and await _sessions(u.id) == 1
    async with db.session() as s:
        assert await s.get(GroupMapping, admins) is None


async def test_removing_the_mapping_of_ones_own_admin_access_is_refused():
    await _setup()
    admins = await _map(ADMINS, "admin")
    await _map(READERS, "reader")
    me = await _signed_in(du(1, ADMINS, READERS))
    async with make_client() as c:
        await sign_in(c, me)
        r = await c.get(f"/api/admin/auth/mappings/{admins}/impact")
        assert r.json()["self"] is True and r.json()["affected"] == 0
        for url in (f"/api/admin/auth/mappings/{admins}", f"/api/admin/auth/mappings/{admins}?end_sessions=false"):
            r = await c.delete(url)
            assert r.status_code == 409 and r.json()["detail"]["code"] == "own_access"
        async with db.session() as s:
            assert await s.get(GroupMapping, admins) is not None
        assert (await _get(me.id)).role == "admin"
        # through a second admin mapping it is no lock-out: allowed, and the own session stays
        await _map(ADMINS2, "admin")
        async with db.session() as s:
            acc = await s.get(User, me.id)
            await directory.apply_sync(s, acc, du(1, ADMINS, ADMINS2))
            await s.commit()
        r = await c.delete(f"/api/admin/auth/mappings/{admins}")
        assert r.status_code == 200
        assert (await c.get("/api/me")).status_code == 200


# ---------------------------------------------------------------- task 2: AD/LDAP or Entra ID switched off


async def _ldap_form(c) -> dict:  # noqa: ANN001
    cur = (await c.get("/api/admin/auth/ldap")).json()
    for k in ("bind_password_set", "usable"):
        cur.pop(k)
    return {**cur, "bind_password": ""}


async def test_switching_ldap_off_ends_its_sessions(admin_client):
    await _setup()
    await _map(READERS, "reader")
    u = await _signed_in(du(1, READERS))
    reader = await add_user("rita", "reader")
    async with make_client() as c:
        await sign_in(c, reader)
    r = await admin_client.get("/api/admin/auth/ldap/impact")
    assert r.json() == {"accounts": 1, "self": False}
    form = await _ldap_form(admin_client)
    r = await admin_client.put("/api/admin/auth/ldap", json={**form, "enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert await _sessions(u.id) == 0 and await _sessions(reader.id) == 1 and await _sessions(admin_client.user.id) == 1
    assert (await _get(u.id)).is_active  # only signed out: switched on again, the account signs in as before


async def test_switching_ldap_off_without_ending_sessions(admin_client):
    await _setup()
    await _map(READERS, "reader")
    u = await _signed_in(du(1, READERS))
    form = await _ldap_form(admin_client)
    r = await admin_client.put("/api/admin/auth/ldap", json={**form, "enabled": False, "end_sessions": False})
    assert r.status_code == 200
    assert await _sessions(u.id) == 1
    # saving again while off ends nothing either (only the switch from on to off does)
    form = await _ldap_form(admin_client)
    assert (await admin_client.put("/api/admin/auth/ldap", json=form)).status_code == 200
    assert await _sessions(u.id) == 1


async def test_an_admin_of_the_source_cannot_switch_it_off():
    await _setup()
    await _map(ADMINS, "admin")
    me = await _signed_in(du(1, ADMINS))
    async with make_client() as c:
        await sign_in(c, me)
        assert (await c.get("/api/admin/auth/ldap/impact")).json()["self"] is True
        form = await _ldap_form(c)
        for end in (True, False):
            r = await c.put("/api/admin/auth/ldap", json={**form, "enabled": False, "end_sessions": end})
            assert r.status_code == 409 and r.json()["detail"]["code"] == "own_source"
        assert (await c.get("/api/admin/auth/ldap")).json()["enabled"] is True
        assert (await c.get("/api/me")).status_code == 200
        # Entra is another source: an AD admin may switch it off
        async with db.session() as s:
            await settings_store.put(s, "entra", {"enabled": True, "tenant_id": "", "client_id": "", "client_secret_enc": ""})
            await s.commit()
        cur = (await c.get("/api/admin/auth/entra")).json()
        body = {"enabled": False, "tenant_id": cur["tenant_id"], "client_id": cur["client_id"], "client_secret": "", "rev": cur["rev"]}
        assert (await c.put("/api/admin/auth/entra", json=body)).status_code == 200


async def test_switching_entra_off_ends_its_sessions(admin_client):
    async with db.session() as s:
        await settings_store.put(s, "entra", {"enabled": True, "tenant_id": "", "client_id": "", "client_secret_enc": ""})
        s.add(User(username="eva@corp.example", display_name="Eva", role="reader", auth_source="entra", external_id=str(uuid.uuid4())))
        await s.commit()
    eva = await _by_name("eva@corp.example")
    async with make_client() as c:
        await sign_in(c, eva)
    assert (await admin_client.get("/api/admin/auth/entra/impact")).json() == {"accounts": 1, "self": False}
    cur = (await admin_client.get("/api/admin/auth/entra")).json()
    body = {"enabled": False, "tenant_id": cur["tenant_id"], "client_id": cur["client_id"], "client_secret": "", "rev": cur["rev"]}
    assert (await admin_client.put("/api/admin/auth/entra", json=body)).status_code == 200
    assert await _sessions(eva.id) == 0
