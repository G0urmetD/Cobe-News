"""Audit log, second step (0.1.50): the integrity chain (seal, incremental and full check, prune keeps it checkable,
tampering found, a backup with it restores), where an entry came from (request id, browser, session, how it arrived),
anomalies, the bounded locks of unknown names, the sessions ended by failures, the new filters and the expanded entry,
the export's guards (cross-site, formula after a separator, semicolon, truncation) and the scrub hardening."""

import csv
import re
import io
import json
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from sqlalchemy import select, text

from app import audit, db
from app import settings as settings_store
from app.models import AuditEntry, User
from conftest import PASSWORD, add_user, make_client, sign_in


async def _entries(action: str | None = None) -> list[AuditEntry]:
    async with db.session() as s:
        q = select(AuditEntry).order_by(AuditEntry.id)
        if action:
            q = q.where(AuditEntry.action == action)
        return list(await s.scalars(q))


async def _write(n: int, *, days_ago: float = 0, action: str = "settings.changed") -> list[int]:
    """n entries, oldest first, `days_ago` back (one second apart)."""
    async with db.session() as s:
        got = []
        for i in range(n):
            e = audit.record(s, audit.SYSTEM, action, audit.target("settings", f"s{i}", f"Abschnitt {i}"), {"i": i})
            e.at = datetime.now(UTC) - timedelta(days=days_ago) + timedelta(seconds=i)
            got.append(e)
        await s.commit()
        return [e.id for e in got]


async def _setup_done() -> None:
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()


async def _raw(sql: str, **params) -> None:
    """A change behind the app's back."""
    async with db.session() as s:
        await s.execute(text(sql), params)
        await s.commit()


async def _verify() -> dict:
    async with db.session() as s:
        return await audit.verify(s)


# ---------------------------------------------------------------- the chain


async def test_entries_are_sealed_and_the_chain_checks_out(admin_client):
    await _write(5)
    r = await admin_client.get("/api/admin/audit/chain")
    st = r.json()
    assert st["state"] == "ok" and st["sealed_seq"] == 5 and st["verified_seq"] == 5 and st["unsealed"] == 0 and st["problems"] == []
    rows = await _entries()
    assert [e.seq for e in rows] == [1, 2, 3, 4, 5]
    assert rows[0].prev_hash == "" and all(rows[i].prev_hash == rows[i - 1].hash for i in range(1, 5))
    assert all(e.hash == audit.entry_hash(e) for e in rows)
    # new entries: sealed on, the check goes on from where it stopped
    await _write(2)
    assert (await admin_client.get("/api/admin/audit")).status_code == 200  # opening the log seals them
    assert [e.seq for e in await _entries()][-2:] == [6, 7]
    assert (await _verify())["verified_seq"] == 7


async def test_chain_finds_a_changed_entry():
    ids = await _write(4)
    assert (await _verify())["state"] == "ok"
    await _raw("UPDATE audit_log SET actor_name = 'mallory' WHERE id = :id", id=ids[1])
    async with db.session() as s:
        st = await audit.chain_state(s)
        st.pop("verified_seq")
        await audit._put_state(s, st)  # noqa: SLF001 - check from the start again
        await s.commit()
    out = await _verify()
    assert out["state"] == "problem" and {"id": ids[1], "seq": 2, "kind": "changed"} in out["problems"]
    logged = await _entries("audit.chain_problem")
    assert len(logged) == 1 and logged[0].target_id == str(ids[1]) and logged[0].notable
    # found again by the next check: not logged twice
    async with db.session() as s:
        await audit.sweep(s)
    assert len(await _entries("audit.chain_problem")) == 1


async def test_the_full_sweep_finds_a_change_after_the_first_check():
    ids = await _write(6)
    await _verify()
    await _raw("UPDATE audit_log SET details = '{\"i\": 99}' WHERE id = :id", id=ids[4])
    assert (await _verify())["state"] == "ok"  # the incremental check does not look back …
    async with db.session() as s:
        st = await audit.sweep(s)  # … the hourly sweep does
    assert any(p["kind"] == "changed" and p["id"] == ids[4] for p in st["problems"]) and st.get("full_at")


async def test_chain_finds_a_deleted_entry_and_a_cut_tail():
    ids = await _write(5)
    await _verify()
    await _raw("DELETE FROM audit_log WHERE id = :id", id=ids[2])
    await _raw("DELETE FROM audit_log WHERE id = :id", id=ids[4])
    async with db.session() as s:
        st = await audit.chain_state(s)
        st.pop("verified_seq")
        await audit._put_state(s, st)  # noqa: SLF001
        await s.commit()
    kinds = {(p["kind"], p["seq"]) for p in (await _verify())["problems"]}
    assert ("missing", 4) in kinds and ("tail", 5) in kinds


async def test_prune_keeps_the_chain_checkable(monkeypatch):
    monkeypatch.setattr(audit, "PRUNE_BATCH", 3)  # batches
    await _write(7, days_ago=400)
    young = await _write(3, days_ago=1)
    async with db.session() as s:
        assert await audit.prune(s) == 7
    left = await _entries()
    assert [e.id for e in left if e.action == "settings.changed"] == young
    out = await _verify()
    assert out["state"] == "ok" and out["anchor_seq"] == 7 and out["problems"] == []
    async with db.session() as s:
        st = await audit.sweep(s)
        assert not st.get("problems")
        assert left[0].prev_hash == st["anchor_hash"]  # the oldest kept entry links to the anchor


async def test_prune_stops_at_an_entry_within_the_retention():
    """The chain is pruned from its start: an old entry behind a young one waits (a late commit – seconds in practice)."""
    await _write(2, days_ago=400)
    await _write(1, days_ago=1)
    await _write(2, days_ago=400)
    async with db.session() as s:
        assert await audit.prune(s) == 2
    assert len(await _entries("settings.changed")) == 3 and (await _verify())["state"] == "ok"


async def test_another_master_key_waits_for_the_operator(monkeypatch):
    """H1 of the review: a new key (or a changed key field) never re-keys by itself – the chain shows it until an
    operator accepts it; then it starts anew, logged, and the page keeps the time."""
    await _write(3)
    await _verify()
    monkeypatch.setattr(audit, "_chain_key", lambda: b"another-master-key-0123456789abcd")
    await _write(2)
    out = await _verify()
    assert out["state"] == "other_key" and not out["rekeyed_at"]
    assert [e.seq for e in await _entries()][-2:] == [None, None]  # nothing sealed with the new key behind its back
    out = await audit.rekey("test")
    assert out["state"] == "ok" and out["rekeyed_at"] and out["anchor_seq"] == 3 and out["problems"] == []
    (e,) = await _entries("audit.chain_rekeyed")
    assert e.notable and e.actor_kind == "cli" and e.details["was"] == "other_key" and e.details["anchor_seq"] == 3
    assert all(x.seq for x in await _entries())


async def _state_sql(sql: str) -> None:
    """The chain state changed in the database directly (someone without the master key)."""
    async with db.session() as s:
        await s.execute(text(sql))
        await s.commit()


async def test_a_changed_key_field_is_no_rekey():
    await _write(3)
    await _verify()
    await _state_sql("UPDATE settings SET value = jsonb_set(value, '{key}', '\"0000000000000000\"') WHERE key = 'audit_chain'")
    await _write(1)
    out = await _verify()
    assert out["state"] == "other_key" and (await _entries())[-1].seq is None


async def test_a_state_changed_behind_the_apps_back_is_a_problem():
    ids = await _write(5)
    await _verify()
    # the newest entries deleted, the head set back to match – without the key the state's MAC no longer fits
    await _raw("DELETE FROM audit_log WHERE id >= :id", id=ids[3])
    await _state_sql("UPDATE settings SET value = jsonb_set(jsonb_set(value, '{head_seq}', '3'), '{verified_seq}', '3') WHERE key = 'audit_chain'")
    out = await _verify()
    assert out["state"] == "problem" and out["problems"][0]["kind"] == "state"
    # cleared problems: the logged audit.chain_problem keeps it a problem until an operator acknowledges it
    await audit.rekey("test")
    assert (await _verify())["state"] == "ok"


async def test_problems_stay_until_acknowledged():
    ids = await _write(4)
    await _raw("UPDATE audit_log SET actor_name = 'x' WHERE id = :id", id=ids[0])
    await audit.seal()
    await _raw("UPDATE audit_log SET actor_name = 'mallory' WHERE id = :id", id=ids[1])
    assert (await _verify())["state"] == "problem"
    async with db.session() as s:  # the state's problems cleared (with the key): the logged problem still counts
        st = await audit.chain_state(s)
        st["problems"] = []
        await audit._put_state(s, st)  # noqa: SLF001
        await s.commit()
    out = await _verify()
    assert out["state"] == "problem" and out["logged_problems"] == 1


async def test_deleting_the_oldest_beyond_a_declared_anchor_is_found():
    """M2: the oldest entries deleted and the anchor set to the last one's hash – no audit.pruned declares it."""
    ids = await _write(8)
    await _verify()
    async with db.session() as s:
        seq, h = (await s.execute(select(AuditEntry.seq, AuditEntry.hash).where(AuditEntry.id == ids[3]))).one()
        await s.execute(text("DELETE FROM audit_log WHERE id <= :id"), {"id": ids[3]})
        st = await audit.chain_state(s)
        st.update(anchor_seq=seq, anchor_hash=h, verified_seq=None, sweep_seq=None)
        st = {k: v for k, v in st.items() if v is not None}
        await audit._put_state(s, st)  # noqa: SLF001 - even with the key
        await s.commit()
    out = await _verify()
    assert out["state"] == "problem" and any(p["kind"] == "anchor" for p in out["problems"])


async def test_late_and_future_entries_are_marked_and_the_future_does_not_hold_the_prune():
    await _write(3, days_ago=400)
    async with db.session() as s:
        e = audit.record(s, audit.SYSTEM, "settings.changed", None, {"x": "future"})
        e.at = datetime.now(UTC) + timedelta(days=30)
        await s.commit()
    await _write(1, days_ago=401)  # written after them: a day older than the entry sealed before it
    await _write(2)
    await audit.seal()
    rows = await _entries()
    assert "future_entry" in rows[3].details["anomalies"] and rows[3].notable
    assert "late_entry" in rows[4].details["anomalies"]
    async with db.session() as s:
        assert await audit.prune(s) == 5  # the future one does not hold the four old ones behind it
    assert (await _verify())["state"] == "ok"
    (p,) = await _entries("audit.pruned")
    assert p.details["anchor_seq"] == 5 and p.details["anchor_link"].startswith("h:")


async def test_prune_waits_for_a_day_past_the_retention():
    await _write(2, days_ago=365.5)
    async with db.session() as s:
        assert await audit.prune(s) == 0  # half a day past it: tomorrow
    await _write(1)
    async with db.session() as s:
        assert await audit.prune(s, now=datetime.now(UTC) + timedelta(days=1)) == 2


async def test_the_prune_logs_the_head_as_a_witness(caplog):
    import logging

    await _write(2)
    with caplog.at_level(logging.INFO, logger="cobe_news.audit"):
        async with db.session() as s:
            await audit.prune(s)
    line = next(r.getMessage() for r in caplog.records if "audit chain head" in r.getMessage())
    async with db.session() as s:
        st = await audit.chain_state(s)
    assert f"seq={st['head_seq']}" in line and st["head_hash"] in line


async def test_export_and_chain_while_another_holds_the_chain_lock(admin_client):
    """M1: a sealer of another process holds the lock – the export still works (the chain never touches the request's
    session), the chain check answers at once."""
    import asyncio

    await _write(2)
    started, release = asyncio.Event(), asyncio.Event()

    async def hold() -> None:
        async with db.session() as s:
            await s.execute(text(f"SELECT pg_advisory_xact_lock({audit.CHAIN_LOCK})"))
            started.set()
            await release.wait()
            await s.rollback()

    task = asyncio.create_task(hold())
    await started.wait()
    try:
        r = await admin_client.get("/api/admin/audit/export")
        assert r.status_code == 200, r.text
        assert (await admin_client.get("/api/admin/audit")).status_code == 200
        assert (await admin_client.get("/api/admin/audit/chain")).json()["busy"] is True
    finally:
        release.set()
        await task
    assert len(await _entries("audit.exported")) == 1


# ---------------------------------------------------------------- where it came from


async def test_request_context_session_and_browser(admin_client):
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6) Gecko/20100101 Firefox/144.0"
    r = await admin_client.post("/api/admin/teams", json={"name": "Netz"}, headers={"User-Agent": ua})
    assert r.status_code < 300 and len(r.headers["x-request-id"]) == 12
    e = (await _entries("team.created"))[-1]
    assert (e.ua_family, e.ua_version, e.ua_os) == ("Firefox", "144", "macOS")
    assert e.req_method == "POST" and e.req_path == "/api/admin/teams" and e.request_id == r.headers["x-request-id"]
    assert e.req_via == "direct" and e.app_version and e.actor_role == "admin" and e.actor_emergency is False
    assert e.session_ref and len(e.session_ref) == 12
    async with db.session() as s:
        sess_ids = [str(x) for x in await s.scalars(text("SELECT id FROM user_sessions"))]
    assert all(e.session_ref not in x.replace("-", "") for x in sess_ids)  # a keyed hash, not the id
    assert "Gecko" not in json.dumps(audit.entry_out(e))  # never the full user agent
    # the session filter finds its entries
    body = (await admin_client.get("/api/admin/audit", params={"session": e.session_ref, "total": 1})).json()
    assert body["total"] >= 1 and all(x["session"]["ref"] == e.session_ref for x in body["items"])


@pytest.mark.parametrize(
    ("ua", "want"),
    [
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0", ("Edge", "142", "Windows")),
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", ("Chrome", "141", "Windows")),
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1", ("Safari", "18", "iOS")),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15", ("Safari", "26", "macOS")),
        ("Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Mobile Safari/537.36", ("Chrome", "140", "Android")),
        ("curl/8.7.1", ("curl", "8", None)),
        ("", (None, None, None)),
        ("something", ("other", None, None)),
    ],
)
def test_user_agent_is_kept_coarse(ua, want):
    assert audit.parse_ua(ua) == want


def test_address_classes(monkeypatch):
    from app import netaddr

    monkeypatch.setattr(netaddr, "container_gateway", lambda: "172.17.0.1")
    assert audit.ip_class("127.0.0.1") == "loopback" and audit.ip_class("172.17.0.1") == "gateway"
    assert audit.ip_class("10.1.2.3") == "internal" and audit.ip_class("fd00::1") == "internal"
    assert audit.ip_class("8.8.8.8") == "external" and audit.ip_class(None) is None and audit.ip_class("nope") is None


async def test_directory_decision_in_a_request_takes_its_address():
    tok = audit.set_request(audit.RequestContext(ip="192.0.2.9", via="bundled", method="POST", path="/api/auth/login", request_id="abc123abc123"))
    try:
        async with db.session() as s:
            audit.record(s, audit.SYNC, "role.changed", audit.target("user", uuid.uuid4(), "dora"), {"changes": {"role": {"from": "reader", "to": "admin"}}, "why": "signin"})
            audit.record(s, audit.SYSTEM, "backup.deleted", None, {"files": []})  # the system without its own address: none
            await s.commit()
    finally:
        audit.reset_request(tok)
    rc, bd = (await _entries("role.changed"))[-1], (await _entries("backup.deleted"))[-1]
    assert rc.ip == "192.0.2.9" and rc.req_via == "bundled" and rc.request_id == "abc123abc123"
    assert rc.notable and "role_admin" in rc.details["anomalies"]
    assert bd.ip is None and bd.request_id is None


async def test_team_sync_names_the_admin(admin_client, monkeypatch):
    from app import teams

    from test_audit import _teams_on

    monkeypatch.setattr(teams, "start", lambda *a, **k: None)
    t = await _teams_on(admin_client)
    r = await admin_client.post(f"/api/admin/teams/{t['id']}/sync")
    assert r.status_code < 300, r.text
    e = (await _entries("team.sync_started"))[-1]
    assert e.actor_id == admin_client.user.id and e.target_id == t["id"]


# ---------------------------------------------------------------- anomalies and sign-ins


async def test_sign_in_anomalies(monkeypatch):
    await _setup_done()
    secret = pyotp.random_base32()
    ada = await add_user("ada", "admin", totp_secret=secret, emergency=True)
    monkeypatch.setattr(audit, "_local_zone", lambda: __import__("zoneinfo").ZoneInfo("UTC"))

    async def sign_in_once(c, wrong: int = 0) -> None:  # noqa: ANN001
        for _ in range(wrong):
            await c.post("/api/auth/login", json={"username": "ada", "password": "falsch"})
        await c.post("/api/auth/login", json={"username": "ada", "password": PASSWORD})
        r = await c.post("/api/auth/mfa", json={"code": pyotp.TOTP(secret).now()})
        assert r.status_code < 300, r.text

    async with make_client() as c:
        await sign_in_once(c, wrong=3)
    e = (await _entries("login.success"))[-1]
    assert "failures_before" in e.details["anomalies"] and e.details["failures_before"] >= 3 and e.notable
    assert e.session_ref and e.auth_method == "password_totp" and e.actor_emergency is True
    # off hours: computed from the time of the sign-in
    flags, _ = await audit.signin_anomalies(None, ada, None, 0, now=datetime(2026, 11, 7, 23, 30, tzinfo=UTC))  # a Saturday night
    assert flags == ["emergency_off_hours"]
    flags, _ = await audit.signin_anomalies(None, ada, None, 0, now=datetime(2026, 11, 4, 10, 0, tzinfo=UTC))  # a Wednesday morning
    assert flags == []
    # a new address: one none of the sign-ins of the last 90 days came from
    async with db.session() as s:
        u = await s.get(User, ada.id)
        assert "new_address" in (await audit.signin_anomalies(s, u, "203.0.113.5"))[0]
        assert "new_address" not in (await audit.signin_anomalies(s, u, "127.0.0.1"))[0]


async def test_retention_lowered_and_export_are_marked(admin_client):
    r = await admin_client.put("/api/admin/audit/settings", json={"keep_days": 200})
    assert r.status_code < 300, r.text
    e = (await _entries("settings.changed"))[-1]
    assert e.notable and e.details["anomalies"] == ["retention_lowered"]
    await admin_client.put("/api/admin/audit/settings", json={"keep_days": 300})
    assert not (await _entries("settings.changed"))[-1].notable  # longer: nothing to mark
    body = (await admin_client.get("/api/admin/audit", params={"notable": 1})).json()
    assert [x["action"] for x in body["items"]] == ["settings.changed"] and body["items"][0]["anomalies"] == ["retention_lowered"]


async def test_mfa_failures_ending_a_session_are_logged():
    await _setup_done()
    secret = pyotp.random_base32()
    await add_user("ada", "admin", totp_secret=secret, emergency=True)  # never locked: the session's counter ends it
    async with make_client() as c:
        await c.post("/api/auth/login", json={"username": "ada", "password": PASSWORD})
        for _ in range(5):
            await c.post("/api/auth/mfa", json={"code": "000000"})
    (e,) = await _entries("sessions.revoked")
    assert e.actor_kind == "system" and e.target_label == "ada" and e.ip == "127.0.0.1" and e.notable
    assert e.details["why"] == "failures" and e.details["stage"] == "mfa" and e.details["failures"] == 5 and e.session_ref


async def test_reauth_failures_ending_a_session_are_logged(admin_client):
    for _ in range(5):
        await admin_client.post("/api/auth/reauth", json={"password": "falsch", "code": "000000"})
    (e,) = await _entries("sessions.revoked")
    assert e.details["stage"] == "reauth" and e.details["why"] == "failures" and e.target_id == str(admin_client.user.id)


async def test_a_lock_names_its_stage():
    await _setup_done()
    await add_user("erika", "reader")
    async with make_client() as c:
        for _ in range(5):
            await c.post("/api/auth/login", json={"username": "erika", "password": "falsch"})
    (e,) = await _entries("login.locked")
    assert e.details["stage"] == "password" and e.notable


async def test_unknown_names_are_counted_not_named(monkeypatch):
    await _setup_done()
    monkeypatch.setattr(audit, "UNKNOWN_FIRST_MAX", 2)
    async with make_client() as c:
        for name in ("Sommer2026", "Winter2026", "Herbst2026"):
            for _ in range(5):
                await c.post("/api/auth/login", json={"username": name, "password": "x"})
    first = await _entries("login.locked_unknown")
    assert len(first) == 1 and first[0].target_id == "127.0.0.1"  # the first of the address – the others counted
    async with db.session() as s:
        assert await audit.flush_floods(s, force=True)
        await s.commit()
    summary = (await _entries("login.locked_unknown"))[-1]
    assert summary.target_type is None and summary.details["names"] == 3 and summary.details["sources"] == {"127.0.0.1": 3}
    text_all = json.dumps([(e.target_label, e.target_id, e.details) for e in await _entries()])
    assert "Sommer" not in text_all and "Winter" not in text_all and "Herbst" not in text_all
    # address blocks beyond the hour's cap: counted into the summary
    assert audit.note_block("198.51.100.1") and audit.note_block("198.51.100.2") and not audit.note_block("198.51.100.3")
    async with db.session() as s:
        assert await audit.flush_floods(s, force=True)
        await s.commit()
    assert (await _entries("login.locked_unknown"))[-1].details["blocks"] == 1


# ---------------------------------------------------------------- filters, the expanded entry, actors


async def test_filters_ip_session_target_and_counts(admin_client):
    async with db.session() as s:
        for ip in ("192.0.2.1", "192.0.2.1", "192.0.2.2"):
            audit.record(s, audit.SYSTEM, "login.locked", audit.target("user", "u1", "bob"), {"locked_for_s": 900}, ip=ip)
        await s.commit()

    async def ids(**params) -> list[int]:  # noqa: ANN003
        return [x["id"] for x in (await admin_client.get("/api/admin/audit", params=params)).json()["items"]]

    assert len(await ids(ip="192.0.2.1")) == 2 and len(await ids(ip="192.0.2.2")) == 1
    assert len(await ids(target_type="user", target_id="u1")) == 3
    body = (await admin_client.get("/api/admin/audit", params={"ip": "192.0.2.1", "total": 1})).json()
    assert body["total"] == 2 and body["total_more"] is False
    for bad in ({"since": "0001-01-01T00:00:00+14:00"}, {"until": "9999-12-31T00:00:00Z"}):
        assert (await admin_client.get("/api/admin/audit", params=bad)).status_code == 422


async def test_bad_cursors_are_422(admin_client):
    import base64

    for raw in (b"2026-01-01T00:00:00+00:00|99999999999999999999", b"0001-01-01T00:00:00+14:00|5", b"2026-01-01T00:00:00+00:00|-1", b"x|y"):
        c = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        assert (await admin_client.get("/api/admin/audit", params={"cursor": c})).status_code == 422, raw


async def test_the_expanded_entry_and_its_surroundings(admin_client):
    async with db.session() as s:
        u = await s.get(User, admin_client.user.id)
        t0 = datetime.now(UTC) - timedelta(hours=2)
        for i, action in enumerate(("login.success", "team.changed", "team.changed", "login.locked")):
            e = audit.record(s, u if action != "login.locked" else audit.SYSTEM, action, audit.target("team", "t1", "Netz"), {"i": i}, ip="192.0.2.7")
            e.at = t0 + timedelta(minutes=i)
        await s.commit()
    last = (await _entries())[-1]
    r = await admin_client.get(f"/api/admin/audit/{last.id}")
    body = r.json()
    assert r.status_code == 200 and body["id"] == last.id
    ctx = body["context"]
    assert [x["action"] for x in ctx["history"]] == ["team.changed", "team.changed", "login.success"]
    assert ctx["ip_24h"] == {"entries": 4, "locks": 1} and ctx["previous_signin"] is None  # the lock's actor is the system
    mid = (await _entries("team.changed"))[-1]
    ctx = (await admin_client.get(f"/api/admin/audit/{mid.id}")).json()["context"]
    assert ctx["previous_signin"]["ip"] == "192.0.2.7"
    assert (await admin_client.get("/api/admin/audit/999999")).status_code == 404


async def test_entries_of_older_versions_show_gracefully(admin_client):
    async with db.session() as s:
        await s.execute(
            text(
                "INSERT INTO audit_log (at, actor_kind, actor_name, actor_display, action, details) "
                "VALUES (now(), 'user', 'alt', 'Alt', 'user.changed', '{}')"
            )
        )
        await s.commit()
    body = (await admin_client.get("/api/admin/audit")).json()
    e = body["items"][0]
    assert e["browser"] is None and e["session"] is None and e["request"] is None and e["ip_class"] is None and e["anomalies"] == []
    assert e["seq"] == 1  # sealed when the log was opened


async def test_actors_are_sorted_and_loose_scanned(admin_client):
    async with db.session() as s:
        for name, display in (("zeta", "Zora"), ("alpha", "Bert"), ("mid", "anton")):
            u = User(id=uuid.uuid4(), username=name, display_name=display, role="admin", auth_source="local")
            for _ in range(3):
                audit.record(s, u, "user.changed", None, {})
        audit.record(s, audit.CLI, "user.reset", None, {})
        await s.commit()
    got = (await admin_client.get("/api/admin/audit/actors")).json()
    assert [a["display"] for a in got if a["kind"] == "user"] == ["anton", "Bert", "Zora"]
    assert [a["id"] for a in got if a["kind"] != "user"] == ["cli"]


# ---------------------------------------------------------------- the export


async def test_export_refuses_another_site(admin_client):
    for path in ("/api/admin/audit/export", "/api/admin/export?format=json"):
        for site in ("cross-site", "none", "same-origin"):  # without the token: refused, whatever the browser says
            r = await admin_client.get(path, headers={"Sec-Fetch-Site": site, "X-CSRF-Token": ""})
            assert r.status_code == 403 and r.json()["detail"]["code"] == "csrf_failed", (path, site)
        await admin_client.get("/api/auth/config")  # the CSRF cookie
        r = await admin_client.get(path, headers={"Sec-Fetch-Site": "cross-site", "X-CSRF-Token": admin_client.cookies.get("cobe_news_csrf")})
        assert r.status_code == 200, path
    assert len(await _entries("audit.exported")) == 1  # the refused one wrote nothing


async def test_export_formula_after_a_separator_and_semicolon(admin_client):
    async with db.session() as s:
        audit.record(s, audit.SYSTEM, "passkey.added", audit.target("user", "u1", "x;=1+1;y"), {"name": 'k;=HYPERLINK("https://evil.example/x");', "n": [-1, -2]})
        await s.commit()
    for delimiter, sep in (("comma", ","), ("semicolon", ";")):
        r = await admin_client.get("/api/admin/audit/export", params={"group": "accounts", "delimiter": delimiter})
        rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig")), delimiter=sep))
        row = rows[1]
        assert row[audit.CSV_COLUMNS.index("target")] == "x;'=1+1;y"
        details = row[audit.CSV_COLUMNS.index("details")]
        assert json.loads(details)["name"] == 'k;=HYPERLINK("https://evil.example/…");'  # still JSON – the same text once parsed
        assert ";=" not in details and ",=" not in details
        # split on the other separator (a spreadsheet of another language): no piece starts a formula
        for other in (",", ";"):
            line = r.content.decode("utf-8-sig").splitlines()[1]
            assert not [p for p in line.split(other) if p.strip()[:1] in ("=", "+", "@") or p.strip()[:1] == "-" and not p.strip()[1:2].isdigit()], (delimiter, other)


async def test_export_says_when_it_is_cut(admin_client, monkeypatch):
    monkeypatch.setattr(audit, "EXPORT_MAX", 3)
    await _write(5)
    r = await admin_client.get("/api/admin/audit/export")
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert r.headers["x-audit-truncated"] == "3" and len(rows) == 1 + 3 + 1 and rows[-1][0].startswith("# truncated")
    assert (await _entries("audit.exported"))[-1].details["truncated"] is True
    monkeypatch.setattr(audit, "EXPORT_MAX", 100)
    r = await admin_client.get("/api/admin/audit/export")
    assert "x-audit-truncated" not in r.headers and "# truncated" not in r.text


async def test_cli_actions_are_logged(monkeypatch, tmp_path, capsys):
    import os

    from app import cli, restore_test

    monkeypatch.setattr(os, "nice", lambda n: 0)  # the test process keeps its priority

    async def fake_run(**kw):  # noqa: ANN003, ANN202
        return {"ok": True, "name": "b.tar", "tables": 1, "rows": 1, "revision": "x", "seconds": 0}

    monkeypatch.setattr(restore_test, "run", fake_run)
    assert await cli._export(["--format", "json", "--out", str(tmp_path / "x.json")]) == 0
    assert await cli._account("new-setup-token") == 0
    assert await cli._restore_test([]) == 0
    capsys.readouterr()  # the setup token printed – never logged
    got = {e.action: e for e in await _entries() if e.actor_kind == "cli"}
    assert got["export.downloaded"].details == {"format": "json", "via": "cli"}
    assert "setup.token_issued" in got and got["setup.token_issued"].notable
    assert got["restore_test.done"].details == {"trigger": "cli", "outcome": "passed", "newest": "b.tar"}
    async with db.session() as s:
        token_hash = (await settings_store.get(s, "setup"))["token_hash"]
    assert token_hash not in json.dumps([e.details for e in got.values()])


async def test_cli_verify_audit(capsys):
    from app import cli

    await _write(3)
    assert await cli._verify_audit([]) == 0
    assert "chain intact" in capsys.readouterr().out
    await _raw("UPDATE audit_log SET actor_name = 'x' WHERE seq = 2")
    assert await cli._verify_audit([]) == 1


# ---------------------------------------------------------------- scrub hardening


@pytest.mark.parametrize(
    ("value", "want"),
    [
        ("socks5://bob:hunter2@proxy.corp:1080", "socks5://proxy.corp:1080"),
        ("postgresql://app:S3cr3t@db/x", "postgresql://db/…"),
        ("see https://hooks.slack.com/services/T00/B00/XXXX please", "see https://hooks.slack.com/… please"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwx", audit.SECRET_MARK),
        ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc here", "token ••• here"),
        ("xoxb-1234-5678-abcdEFGHijkl", audit.SECRET_MARK),
        ("laptop-5g-for-business-7th-edition-intel", "laptop-5g-for-business-7th-edition-intel"),
        ("b714dbdb3c29e0f178aa1c06317ab6b9", "b714dbdb3c29e0f178aa1c06317ab6b9"),  # a 32-digit reference
        ("‮gnp.exe", "gnp.exe"),
        ("a\x00b​c⁦d", "abcd"),
    ],
)
def test_scrub_hardening(value, want):
    assert audit.scrub({"v": value})["v"] == want


def test_secret_names_and_changed_only():
    assert audit.scrub({"headers": {"Authorization": "Basic Ym9i"}})["headers"]["Authorization"] == audit.SECRET_MARK
    assert audit.diff({"server": "https://a.example/x"}, {"server": "https://a.example/y"}) == {"server": {"changed": True}}
    assert audit.diff({"server": "https://a.example/x"}, {"server": "https://b.example/x"}) == {"server": {"from": "https://a.example/…", "to": "https://b.example/…"}}


async def test_record_cleans_names_and_labels():
    async with db.session() as s:
        u = User(id=uuid.uuid4(), username="eve‮", display_name="Eve⁦", role="reader", auth_source="local")
        audit.record(s, u, "passkey.added", audit.target("user", u.id, "eve‮"), {"name": "Key‮1"})
        await s.commit()
    e = (await _entries("passkey.added"))[-1]
    assert e.actor_name == "eve" and e.actor_display == "Eve" and e.target_label == "eve" and e.details["name"] == "Key1"


async def test_the_chain_survives_a_backup_and_its_restore(tmp_path):
    """A backup brings the chain along (entries, anchor and state are rows like any other): restored, it checks out."""
    import shutil

    from app import backup
    from app.config import get_config

    cfg = get_config()
    old = cfg.backup_dir, cfg.backup_passphrase
    object.__setattr__(cfg, "backup_dir", tmp_path / "backups")
    object.__setattr__(cfg, "backup_passphrase", "")
    try:
        await _write(4, days_ago=400)
        await _write(3)
        async with db.session() as s:
            await audit.prune(s)
        res = await backup.create()
        await _write(2)  # after the backup: gone again after the restore
        plan = backup.prepare(res.path, "")
        try:
            await backup.restore(plan)
        finally:
            shutil.rmtree(plan.work)
    finally:
        object.__setattr__(cfg, "backup_dir", old[0])
        object.__setattr__(cfg, "backup_passphrase", old[1])
    out = await _verify()
    assert out["state"] == "ok" and out["anchor_seq"] == 4 and out["problems"] == []
    async with db.session() as s:
        st = await audit.sweep(s)
    assert not st.get("problems")


# ---------------------------------------------------------------- every logged field has a name in the UI


def _logged_fields() -> set[str]:
    """Every key an entry's details can carry: the literal dicts of the record() calls (and the helpers that pass theirs
    on), and the fields audit.diff() compares – settings models, a channel's state, a rule's state, the patched rows."""
    import ast
    from pathlib import Path

    from app import admin_api, api, notify_api, passkeys_api, restore_test, teams_api, update_check, vendor_api
    from app import settings as settings_store

    out: set[str] = set()
    for f in (Path(__file__).resolve().parents[1] / "app").rglob("*.py"):
        for n in ast.walk(ast.parse(f.read_text("utf-8"))):
            if not (isinstance(n, ast.Call) and getattr(n.func, "attr", getattr(n.func, "id", "")) in ("record", "_audit", "_log")):
                continue
            for arg in [*n.args[3:5], *(k.value for k in n.keywords if k.arg == "details")]:
                if isinstance(arg, ast.Dict):  # the details' own keys (not those of a dict inside them)
                    out |= {k.value for k in arg.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    models = (
        api.NewsIn,
        api.SourcePatch,
        vendor_api.VendorSettingsIn,
        vendor_api.FollowIn,
        vendor_api.VersionIn,
        update_check.SettingsIn,
        admin_api.UserPatch,
        admin_api.SessionsIn,
        admin_api.MfaIn,
        admin_api.LdapIn,
        admin_api.EntraIn,
        admin_api.BackupSettingsIn,
        notify_api.SmtpIn,
        passkeys_api.PasskeySettingsIn,
        restore_test.SettingsIn,
        teams_api.SettingsIn,
        teams_api.TeamPatch,
    )
    for m in models:
        out |= set(m.model_fields)
    out |= set(settings_store.DEFAULTS.get("vendor", {}))
    out |= {"name", "type", "target", "kinds", "severities", "sources", "topics", "lang", "channels", "teams", "keep_days"}
    out |= {f"config.{k}" for k in ("recipients", "chat_id", "server", "tags", "allow_http", "use_proxy", "header_name")}
    out |= {f"secret.{k}" for k in ("url", "token", "hmac", "header_value", "topic")}
    skip = {"changes", "anomalies", "rev", "version_", "end_sessions", "clear_hmac", "clear_header", "clear_password", "clear_nvd_key"}
    return {k.removesuffix("_enc") for k in out if k not in skip and not k.endswith("_set")}


def test_every_logged_field_has_a_name_in_both_languages():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "frontend" / "src" / "i18n"
    if not root.is_dir():
        pytest.skip("no frontend next to the backend")
    for lang in ("de", "en"):
        text = (root / f"audit.{lang}.ts").read_text("utf-8")
        named = set(re.findall(r'"audit\.field\.([^"]+)"', text))
        missing = sorted(_logged_fields() - named)
        assert missing == [], f"{lang}: no audit.field.<name> for {missing}"


async def test_deleting_the_newest_is_found_by_every_check():
    """B1 of the test round: the newest sealed entries deleted – the page's check, the hourly sweep and the prune find
    it, not only the command line; the problem names the last entry that is still there."""
    ids = await _write(6)
    await _verify()
    await _raw("DELETE FROM audit_log WHERE id >= :id", id=ids[4])
    async with db.session() as s:
        st = await audit.sweep(s)
    assert any(p["kind"] == "tail" and p["id"] == ids[3] and p["count"] == 2 for p in st["problems"])
    out = await _verify()
    assert out["state"] == "problem" and out["problems"][0]["kind"] == "tail" and out["problems"][0]["id"] == ids[3]


async def test_the_full_check_on_the_command_line_sets_full_at():
    from app import cli

    await _write(3)
    assert await cli._verify_audit([]) == 0
    async with db.session() as s:
        assert (await audit.chain_state(s)).get("full_at")


async def test_check_then_acknowledge_in_one_run_each(capsys):
    """B2: the documented sequence – verify-audit finds a change (and logs it), --accept-new-key acknowledges it at once."""
    from app import cli

    ids = await _write(4)
    await audit.seal()
    await _raw("UPDATE audit_log SET actor_name = 'mallory' WHERE id = :id", id=ids[1])
    assert await cli._verify_audit([]) == 1
    assert "changed: entry #" in capsys.readouterr().out
    assert await cli._verify_audit(["--accept-new-key"]) == 0
    out = await _verify()
    assert out["state"] == "ok" and out["logged_problems"] == 0
    assert await cli._verify_audit([]) == 0
    assert "#-" not in capsys.readouterr().out


async def test_search_uses_the_trigram_index(admin_client):
    """The search is the indexed expression: on a few rows the planner reads them all – with seq scans off it must be
    able to take the index (migration 0033)."""
    from sqlalchemy.dialects import postgresql

    q = audit._query(audit.Filters(q="mallory")).with_only_columns(AuditEntry.id)  # noqa: SLF001
    sql = str(q.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    async with db.engine().begin() as conn:
        await conn.execute(text("SET LOCAL enable_seqscan = off"))
        plan = "\n".join(await conn.scalars(text("EXPLAIN " + sql)))
    assert "ix_audit_log_search" in plan, plan
    await _write(2)
    async with db.session() as s:
        audit.record(s, audit.SYSTEM, "login.locked", audit.target("user", "u1", "Mallory Muster"), {}, ip="192.0.2.77")
        await s.commit()
    hits = lambda q: admin_client.get("/api/admin/audit", params={"q": q})  # noqa: E731
    for term, n in (("MALLORY", 1), ("192.0.2.77", 1), ("login.lock", 1), ("abschnitt", 2), ("zz", 0), ("100%_", 0)):
        assert len((await hits(term)).json()["items"]) == n, term
