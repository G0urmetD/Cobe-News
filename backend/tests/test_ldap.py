"""AD / LDAP sign-in against ldap3's in-memory directory (MOCK_SYNC): sAMAccountName or UPN,
group → role (no group, no access – answered like a wrong password), admins need TOTP, escaping, the live group search,
and the hourly sync that switches off accounts that lost their group (never the emergency admin)."""

import types
import uuid

import pytest
from conftest import PASSWORD, add_user, make_client
from ldap3 import MOCK_SYNC, MODIFY_REPLACE, Connection, Server
from sqlalchemy import select

from app import db
from app import settings as settings_store
from app.auth import ldap_dir
from app.auth import sync as directory_sync
from app.models import User

BASE = "dc=corp,dc=example"
SVC = f"cn=svc-news,{BASE}"
READERS = f"CN=News-Readers,OU=Groups,{BASE}"
ADMINS = f"CN=News-Admins,OU=Groups,{BASE}"
ANNA = uuid.UUID("6f1c2a4e-1b2c-4d3e-8f90-0123456789ab")
OTTO = uuid.UUID("9c1f5e7a-3b2d-4c8e-a1f0-b2c3d4e5f607")


@pytest.fixture
def ad(monkeypatch):
    srv = Server("fake-dc")
    seed = Connection(srv, client_strategy=MOCK_SYNC)
    add = seed.strategy.add_entry
    add(BASE, {"objectClass": "domain", "dc": "corp"})
    add(SVC, {"userPassword": "svc-pw", "objectClass": "person"})
    for cn in ("News-Readers", "News-Admins", "Staff"):
        add(f"CN={cn},OU=Groups,{BASE}", {"objectClass": "group", "cn": cn, "description": f"{cn} group"})

    def person(cn, sam, pw, groups, guid, uac="512"):
        add(
            f"cn={cn},ou=Users,{BASE}",
            {
                "userPassword": pw,
                "objectClass": ["person", "user"],
                "objectCategory": "person",
                "sAMAccountName": sam,
                "userPrincipalName": f"{sam}@corp.example",
                "displayName": cn,
                "mail": f"{sam}@corp.example",
                "userAccountControl": uac,
                "memberOf": groups,
                "objectGUID": guid.bytes_le,
            },
        )

    person("Anna Weber", "a.weber", "Anna-Pw-2026!", [READERS, f"CN=Staff,OU=Groups,{BASE}"], ANNA)
    person("Otto Admin", "o.admin", "Otto-Pw-2026!", [ADMINS], OTTO)
    person("Dora Disabled", "d.disabled", "Dora-Pw-2026!", [READERS], uuid.uuid4(), uac="514")
    person("Max Muster", "m.muster", "Max-Pw-2026!", [f"CN=Staff,OU=Groups,{BASE}"], uuid.uuid4())
    filters: list[str] = []

    class MockConn(Connection):
        def __init__(self, server, **kw):
            super().__init__(srv, client_strategy=MOCK_SYNC, **kw)

        def search(self, base, flt, *a, **kw):
            filters.append(flt)
            return super().search(base, flt, *a, **kw)

    monkeypatch.setattr(ldap_dir, "_pool", lambda cfg: srv)
    monkeypatch.setattr(ldap_dir, "Connection", MockConn)
    def groups_of(dn, groups):
        admin = Connection(srv, user=SVC, password="svc-pw", client_strategy=MOCK_SYNC)
        assert admin.bind() and admin.modify(dn, {"memberOf": [(MODIFY_REPLACE, groups)]})

    return types.SimpleNamespace(srv=srv, seed=seed, filters=filters, groups_of=groups_of)


CFG = {"enabled": True, "servers": ["dc01.corp.example"], "base_dn": BASE, "bind_dn": SVC, "bind_password": "svc-pw", "nested_groups": False}


async def _setup(admin_client, *, roles=(("ldap", READERS, "reader"), ("ldap", ADMINS, "admin"))):
    assert (await admin_client.put("/api/admin/auth/ldap", json=CFG)).json()["usable"]
    for src, gid, role in roles:
        assert (await admin_client.post("/api/admin/auth/mappings", json={"source": src, "group_id": gid, "group_name": gid.split(",")[0][3:], "role": role})).status_code == 200
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()


async def _login(name, pw):
    async with make_client() as c:
        r = await c.post("/api/auth/login", json={"username": name, "password": pw, "source": "ldap"})
        return r, (await c.get("/api/me"))


async def test_sign_in_by_name_or_upn_with_the_mapped_role(ad, admin_client):
    await _setup(admin_client)
    assert (await admin_client.get("/api/auth/config")).json()["ldap_enabled"] is True
    r, me = await _login("A.Weber", "Anna-Pw-2026!")
    assert r.json()["next"] == "done" and me.json()["role"] == "reader" and me.json()["auth_source"] == "ldap" and me.json()["username"] == "a.weber"
    r, _ = await _login("a.weber@corp.example", "Anna-Pw-2026!")  # UPN
    assert r.json()["next"] == "done"
    async with db.session() as s:
        users = list(await s.scalars(select(User).where(User.auth_source == "ldap", User.username == "a.weber")))
    assert len(users) == 1 and users[0].external_id == str(ANNA)  # the same account both times (preloaded or not)
    # an admin from AD sets up TOTP first
    r, me = await _login("o.admin", "Otto-Pw-2026!")
    assert r.json() == {"next": "enroll"} and me.status_code == 401


async def test_no_group_wrong_password_or_disabled_look_the_same(ad, admin_client):
    await _setup(admin_client)
    for name, pw in (("a.weber", "falsch"), ("m.muster", "Max-Pw-2026!"), ("d.disabled", "Dora-Pw-2026!"), ("niemand", "x")):
        r, _ = await _login(name, pw)
        assert r.status_code == 401 and r.json()["detail"]["code"] == "invalid_credentials", name
    # no LDAP injection: the name is escaped before it goes into the filter
    await _login("*)(sAMAccountName=*", "x")
    assert any("\\2a\\29\\28" in f for f in ad.filters)
    # an AD account never takes over a local one with the same name (the preloaded AD accounts removed first)
    from app import teams

    await teams.wait_idle()
    async with db.session() as s:
        for u in await s.scalars(select(User).where(User.auth_source == "ldap")):
            await s.delete(u)
        await s.commit()
    await add_user("a.weber")
    r, _ = await _login("a.weber", "Anna-Pw-2026!")
    assert r.status_code == 401


async def test_connection_test_and_group_search(ad, admin_client):
    assert (await admin_client.post("/api/admin/auth/ldap/test", json=CFG)).json() == {"ok": True}
    assert (await admin_client.post("/api/admin/auth/ldap/test", json={**CFG, "bind_password": "falsch"})).json() == {"ok": False, "error": "service_bind"}
    await admin_client.put("/api/admin/auth/ldap", json=CFG)
    groups = (await admin_client.get("/api/admin/auth/ldap/groups", params={"q": "News"})).json()
    assert [g["name"] for g in groups] == ["News-Admins", "News-Readers"] and groups[1]["id"] == READERS and groups[1]["path"] == "corp.example/Groups"


async def test_sync_switches_off_who_lost_the_group_never_the_emergency_admin(ad, admin_client):
    await _setup(admin_client)
    await _login("a.weber", "Anna-Pw-2026!")
    em = await add_user("notfall", "admin", emergency=True)
    async with db.session() as s:
        assert await directory_sync.run(s) == {}
    # Anna leaves the readers group
    ad.groups_of(f"cn=Anna Weber,ou=Users,{BASE}", [f"CN=Staff,OU=Groups,{BASE}"])
    async with db.session() as s:
        assert await directory_sync.run(s) == {"deactivated": 1}
        anna = await s.scalar(select(User).where(User.username == "a.weber"))
        assert not anna.is_active and anna.deactivated_reason == "sync:no_role"
        assert (await s.get(User, em.id)).is_active
    r, _ = await _login("a.weber", "Anna-Pw-2026!")
    assert r.status_code == 401
    # back in the group: she comes back by herself at the next sign-in
    ad.groups_of(f"cn=Anna Weber,ou=Users,{BASE}", [READERS])
    r, me = await _login("a.weber", "Anna-Pw-2026!")
    assert r.json()["next"] == "done" and me.json()["role"] == "reader"


def test_plain_ldap_needs_the_explicit_switch():
    with pytest.raises(ldap_dir.LdapError, match="plain_refused"):
        ldap_dir.connection({"servers": ["dc01.corp.example"], "encryption": "none"}, SVC, "x")
    assert not ldap_dir.usable({"servers": ["dc"], "base_dn": BASE, "bind_dn": SVC, "bind_password_enc": "x", "encryption": "none"})
    assert ldap_dir.derive_base_dn("dc01.corp.example") == "DC=corp,DC=example"
    _ = PASSWORD


def test_the_address_reached_at_connect_is_checked_again(monkeypatch):
    """0.1.56 review: ldap3 resolves the server's name again when it connects – a name that passed the check and then
    points at a forbidden address (DNS rebinding) is refused at the socket, before StartTLS or any bind."""
    import socket
    import threading

    from app import netaddr

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    seen: list[bytes] = []

    def accept() -> None:
        try:
            c, _ = srv.accept()
            c.settimeout(2)
            try:
                seen.append(c.recv(100))
            except OSError:
                pass
            c.close()
        except OSError:
            pass

    t = threading.Thread(target=accept, daemon=True)
    t.start()
    real = netaddr.check_host
    calls: list[str] = []

    def check(host: str) -> None:  # the name's check passes (as when DNS answered a company address)…
        calls.append(host)
        if len(calls) > 1:
            real(host)  # … the address reached at connect is the real one: loopback

    monkeypatch.setattr(netaddr, "check_host", check)
    binds: list[int] = []
    monkeypatch.setattr(Connection, "bind", lambda self, *a, **k: binds.append(1) or True)
    try:
        with pytest.raises(ldap_dir.LdapError, match="forbidden_target"):
            ldap_dir.connection({"servers": [f"127.0.0.1:{port}"], "encryption": "starttls", "timeout": 2}, SVC, "secret-pw")
    finally:
        srv.close()
        t.join(3)
    assert calls[-1] == "127.0.0.1" and not binds and seen in ([], [b""])  # nothing sent: no StartTLS, no bind


async def test_a_locked_account_is_never_bound_however_its_name_is_typed(ad, admin_client, monkeypatch):
    """Bug hunt 0.1.16 M12: locked in Cobe News (counted per objectGUID), typed as UPN (with another case than the
    stored mail): refused before the DC is asked – every bind with a wrong password would count on the DC's own lockout."""
    await _setup(admin_client)
    admin = Connection(ad.srv, user=SVC, password="svc-pw", client_strategy=MOCK_SYNC)
    assert admin.bind() and admin.modify(f"cn=Anna Weber,ou=Users,{BASE}", {"mail": [(MODIFY_REPLACE, ["Anna.Weber@corp.example"])]})
    r, _ = await _login("a.weber", "Anna-Pw-2026!")
    assert r.json()["next"] == "done"
    for _ in range(5):
        await _login("a.weber", "falsch")
    assert (await _login("a.weber", "falsch"))[0].status_code == 423
    binds = []
    real = ldap_dir.connection

    def counting(cfg, user, password, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        if user != SVC:
            binds.append(user)
        return real(cfg, user, password, *a, **kw)

    monkeypatch.setattr(ldap_dir, "connection", counting)
    for name in ("a.weber", "a.weber@corp.example", "A.Weber@Corp.Example"):
        r, _ = await _login(name, "falsch")
        assert r.status_code == 423, name
    assert binds == []
