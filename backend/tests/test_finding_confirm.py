# ruff: noqa: F811 - the fixtures of test_vendor_service are imported and used by name
"""Treffer bestätigen (app/finding_confirm.py): who may confirm and undo (admins, the members of a team the product
belongs to – nobody else), what a confirmed finding no longer does (count where "needs attention" is counted, notify on
the rules' channels and the personal ways, appear in the weekly review), that it lapses by itself when the finding
changes materially (exploited, rated higher, a new CVE, a version's verdict, withdrawn) – and not when only a fixed
version is added –, and the audit entries."""

import json
from datetime import UTC, datetime, timedelta

from conftest import add_user, make_client, sign_in
from sqlalchemy import select
from test_api_tokens import get, make_token
from test_catalog_care import _team as _care_team
from test_catalog_care import _teams_on
from test_personal import _event, _person, _switch, _ways, mails  # noqa: F401 - fixture
from test_personal import _team as _personal_team
from test_vendor_fixes import _nvd
from test_vendor_service import (  # noqa: F401 - fixtures
    _dispatch,
    _follow,
    _fresh_pan,
    _round,
    _webhook_rule,
    hooks,
    sites,
    vendor_reset,
)

from app import db, finding_confirm, notify, personal, reader, vendor, weekly
from app.models import (
    AuditEntry,
    PersonDelivery,
    VendorConfirm,
    VendorDelivery,
    VendorEvent,
)

CVE = "CVE-2026-8301"
FID = f"paloalto:{CVE}"
_step = iter(range(1, 1000))


def _adv(**kw) -> dict:
    """A PAN-OS advisory that affects 11.2.4-h23 – every call a newer record (stored again, not "the same")."""
    a = _fresh_pan(CVE, "< 11.2.4-h30", ">= 11.2.4-h30")
    a["updated_at"] = datetime.now(UTC) - timedelta(minutes=50) + timedelta(seconds=next(_step))
    return a | kw


async def _store(a: dict) -> int:
    async with db.session() as s:
        await vendor.store(s, [a], vendor.build_index())
        return await vendor.evaluate_events(s)


async def _setup(c, *kinds: str) -> None:
    """PAN-OS 11.2.4-h23 followed (baseline done), a webhook rule of these kinds, the advisory stored and notified."""
    await _follow(c, "panos", "11.2.4-h23")
    if kinds:
        await _webhook_rule(c, list(kinds))
    await _round()
    assert await _store(_adv()) == 1


async def _confirm(c, status: str = "not_affected", note: str = "Brotli nicht aktiviert", finding: str = FID, product: str = "panos"):  # noqa: ANN001, ANN202
    return await c.post("/api/vendor/findings/confirm", json={"product": product, "finding": finding, "status": status, "note": note})


async def _unconfirm(c, finding: str = FID):  # noqa: ANN001, ANN202
    return await c.post("/api/vendor/findings/unconfirm", json={"product": "panos", "finding": finding})


async def _row(finding: str = FID) -> VendorConfirm | None:
    """The finding's latest confirmation (one row per period it stood)."""
    async with db.session() as s:
        q = select(VendorConfirm).where(VendorConfirm.product == "panos", VendorConfirm.finding == finding)
        return await s.scalar(q.order_by(VendorConfirm.held_from.desc(), VendorConfirm.confirmed_at.desc()).limit(1))


async def _entries(action: str) -> list[AuditEntry]:
    async with db.session() as s:
        return list(await s.scalars(select(AuditEntry).where(AuditEntry.action == action).order_by(AuditEntry.at)))


def _finding(d: dict, fid: str = FID) -> dict:
    return next(f for f in d["findings"] if f["id"] == fid)


# ---------------------------------------------------------------- who may


async def test_admins_and_the_products_team_confirm_everybody_else_reads(admin_client, reader_client, sites):
    await _setup(admin_client)
    # Teams off: a reader may not – the API refuses, the drawer shows it read-only
    assert (await _confirm(reader_client)).status_code == 403
    r = await _confirm(admin_client)
    assert r.status_code == 200, r.text
    assert r.json()["confirmed"] | {"at": None} == {"status": "not_affected", "note": "Brotli nicht aktiviert", "by": "Anna", "at": None}
    d = (await reader_client.get("/api/vendor/products/panos")).json()
    assert d["can_confirm"] is False and _finding(d)["confirmed"]["note"] == "Brotli nicht aktiviert" and d["confirmed"] == 1
    assert (await _unconfirm(reader_client)).status_code == 403
    # Teams on: the members of a team PAN-OS belongs to may – a reader of another team may not
    await _teams_on()
    other = await add_user("olga", "reader")
    await _care_team("Netzwerk", ["panos"], [reader_client.user])
    await _care_team("Server", [], [other])
    assert (await reader_client.get("/api/vendor/products/panos")).json()["can_confirm"] is True
    assert (await _unconfirm(reader_client)).status_code == 200
    assert (await _unconfirm(reader_client)).status_code == 404  # nothing stands any more
    o = make_client()
    async with o:
        await sign_in(o, other)
        assert (await _confirm(o, "mitigated", "WAF-Regel")).status_code == 403
    assert (await _confirm(reader_client, "mitigated", "WAF-Regel")).status_code == 200
    assert (await _confirm(admin_client, "accepted", "Ersatz bestellt")).status_code == 200  # admins always – a change
    row = await _row()
    assert (row.status, row.note, row.user_name, row.ended_at) == ("accepted", "Ersatz bestellt", "Anna", None)
    # the audit: who, what, why – and the change says what it was before
    made = await _entries("vendor.finding_confirmed")
    assert [e.details["status"] for e in made] == ["not_affected", "mitigated", "accepted"]
    assert made[-1].details["was"] == {"status": "mitigated", "note": "WAF-Regel"} and made[-1].target_id == "panos" and made[-1].details["finding"] == FID
    [undone] = await _entries("vendor.finding_unconfirmed")
    assert undone.actor_name == "rudi" and undone.details["status"] == "not_affected" and undone.details["ident"] == CVE


async def test_what_a_confirmation_needs(admin_client, sites):
    await _setup(admin_client)
    assert (await _confirm(admin_client, "accepted", "  ")).json()["detail"]["code"] == "note_required"  # a reason, always
    assert (await _confirm(admin_client, "ignored")).status_code == 422
    assert (await _confirm(admin_client, note="x" * (finding_confirm.NOTE_MAX + 1))).status_code == 422
    assert (await _confirm(admin_client, finding="paloalto:CVE-2026-0000")).status_code == 404
    assert (await _confirm(admin_client, product="fortios")).status_code == 404  # not followed
    r = await _confirm(admin_client, "mitigated", "")  # optional otherwise
    assert r.status_code == 200 and r.json()["confirmed"]["note"] == ""
    assert (await _confirm(admin_client, note="Brotli\n  nicht   aktiviert")).json()["confirmed"]["note"] == "Brotli nicht aktiviert"


# ---------------------------------------------------------------- what it no longer does


async def test_a_confirmed_finding_counts_as_handled_everywhere(admin_client, reader_client, sites):
    await _setup(admin_client)
    # the fixtures' advisories (the baseline) affect the version too: only the one confirmed must go
    ov = (await reader_client.get("/api/vendor/overview")).json()["items"][0]
    n, unread = ov["counts"]["affected"], ov["unread"]
    assert n >= 1 and unread >= 1 and FID in [x["id"] for x in ov["latest"]] and ov["confirmed"] == 0
    vid = ov["versions"][0]["id"]
    per = ov["summary"]["per_version"][vid]["affected"]
    unread_all = (await reader_client.get("/api/reader/counts")).json()["vendor"]
    token = await make_token(admin_client)
    assert (await get("/api/v1/vendor/products", token)).json()["items"][0]["counts"]["affected"] == n
    total = (await get("/api/v1/vendor/findings", token)).json()["total"]
    assert (await _confirm(admin_client)).status_code == 200
    ov = (await reader_client.get("/api/vendor/overview")).json()["items"][0]
    assert ov["counts"]["affected"] == n - 1 and ov["unread"] == unread - 1 and FID not in [x["id"] for x in ov["latest"]]
    assert ov["confirmed"] == 1 and ov["latest_confirmed"][0]["id"] == FID and ov["latest_confirmed"][0]["confirmed"]["status"] == "not_affected"
    assert ov["summary"]["per_version"][vid]["affected"] == per - 1
    assert (ov["score"] or {}).get("finding") != FID
    assert (await reader_client.get("/api/reader/counts")).json()["vendor"] == unread_all - 1
    d = (await reader_client.get("/api/vendor/products/panos")).json()
    assert d["summary"]["per_version"][vid]["affected"] == per - 1 and d["unread"] == unread - 1
    assert _finding(d)["status"] == "affected"  # still listed (dimmed in the drawer), with its verdict
    # API v1: not counted, the finding carries the confirmation, the list can leave it out
    assert (await get("/api/v1/vendor/products", token)).json()["items"][0]["counts"]["affected"] == n - 1
    x = next(x for x in (await get("/api/v1/vendor/findings", token)).json()["items"] if x["id"] == FID)
    assert x["confirmed"]["status"] == "not_affected" and x["confirmed"]["by"] == "Anna"
    assert (await get("/api/v1/vendor/findings?confirmed=false", token)).json()["total"] == total - 1
    assert (await get("/api/v1/vendor/findings?confirmed=true", token)).json()["total"] == 1
    assert _finding((await get("/api/v1/vendor/products/panos", token)).json())["confirmed"]["note"] == "Brotli nicht aktiviert"
    # undone: counted again at once
    assert (await _unconfirm(admin_client)).status_code == 200
    assert (await reader_client.get("/api/vendor/overview")).json()["items"][0]["counts"]["affected"] == n
    assert (await get("/api/v1/vendor/findings?confirmed=false", token)).json()["total"] == total


async def test_the_badge_leaves_a_confirmed_finding_out(admin_client, reader_client, sites):
    """The sidebar's number counts products a vulnerability affects: all of them confirmed – not counted."""
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    assert (await reader_client.get("/api/vendor/badge")).json()["affected"] == 1
    d = (await admin_client.get("/api/vendor/products/panos")).json()
    open_ = [f["id"] for f in d["findings"] if f["status"] in reader.RELEVANT]
    for fid in open_:
        assert (await _confirm(admin_client, finding=fid)).status_code == 200, fid
    assert (await reader_client.get("/api/vendor/badge")).json()["affected"] == 0
    ov = (await reader_client.get("/api/vendor/overview")).json()["items"][0]
    assert ov["counts"]["affected"] == ov["counts"]["possible"] == 0 and ov["latest"] == [] and ov["confirmed"] == len(open_)
    assert ov["urgency"] not in ("exploited", "critical", "affected")


async def test_the_weekly_review_leaves_a_confirmed_finding_out(admin_client, reader_client, sites):
    await _setup(admin_client)
    await _teams_on()
    tid = await _care_team("Netzwerk", ["panos"], [reader_client.user])
    until = datetime.now(UTC) + timedelta(minutes=1)
    async with db.session() as s:
        before = await weekly.content(s, tid, until)
    await _confirm(admin_client)
    async with db.session() as s:
        after = await weekly.content(s, tid, until)
    assert before["vulns"]["total"] == 1 and after["vulns"]["total"] == 0  # the week's new one (the baseline is no news)
    assert after["affected"][0]["n"] == before["affected"][0]["n"] - 1


async def test_no_message_while_it_stands_and_none_later_and_a_new_fix_keeps_it(admin_client, sites, hooks):
    await _setup(admin_client, "vendor_vuln", "vendor_change")
    await _dispatch()
    assert len(hooks) == 1  # the finding, before anybody confirmed it
    await _confirm(admin_client)
    # the vendor names one more fixed version: an advisory change – no reason to look again, nothing is sent
    fixed = _adv()
    fixed["data"] = {**fixed["data"], "lines": [{"name": "PAN-OS 11.2", "affected": "< 11.2.4-h30", "fixed": ">= 11.2.4-h30, >= 11.2.4-h26"}]}
    assert await _store(fixed) == 0
    async with db.session() as s:
        change = await s.scalar(select(VendorEvent).where(VendorEvent.kind == "change"))
    assert change is not None and not change.baseline
    await _dispatch()
    assert len(hooks) == 1
    row = await _row()
    assert row.ended_at is None  # still stands
    # undone: what was held back stays unsent – only what comes from now on is sent
    await _unconfirm(admin_client)
    await _dispatch()
    assert len(hooks) == 1
    async with db.session() as s:
        assert await s.scalar(select(VendorDelivery).where(VendorDelivery.event_id == change.id)) is None


async def test_personal_ways_skip_a_confirmed_finding(admin_client, mails):
    await _switch()
    u = await _person("pia")
    await _personal_team([u])
    await _ways(u, email=True)
    held = await _event(title="Brotli")  # key vuln:panos:10.2.3:ADV-<n> – its finding is ADV-<n>
    sent = await _event(title="Andere Lücke")
    async with db.session() as s:
        await personal.enqueue(s, {"email": True})  # both queued – then the one is confirmed
        ev = await s.get(VendorEvent, held)
        await finding_confirm.confirm(s, u, "panos", _bare(reader.finding_of(ev.key, ev.scope)), "not_affected", "")
        await s.commit()
    await _dispatch_personal()
    rows = {r.event_id: r for r in await _rows_of()}
    assert rows[sent].status == "sent" and (rows[held].status, rows[held].error) == ("skipped", "confirmed")
    assert len(mails.sent) == 1 and "Andere Lücke" in mails.sent[0]["text"]
    # an event made while it stands is not even queued
    later = await _event(title="Noch eine")
    async with db.session() as s:
        ev = await s.get(VendorEvent, later)
        await finding_confirm.confirm(s, u, "panos", _bare(reader.finding_of(ev.key, ev.scope)), "mitigated", "")
        await s.commit()
    await _dispatch_personal()
    assert later not in {r.event_id for r in await _rows_of()}


def _bare(fid: str | None) -> dict:
    assert fid
    return {"id": fid, "severity": "high", "exploited": False, "cves": [], "versions": [{"version": "10.2.3", "status": "affected"}]}


async def _dispatch_personal() -> dict:
    async with db.session() as s:
        return await personal.dispatch(s)


async def _rows_of() -> list[PersonDelivery]:
    async with db.session() as s:
        return list(await s.scalars(select(PersonDelivery)))


# ---------------------------------------------------------------- it lapses by itself


async def _lapsed_by(reason: str) -> VendorConfirm:
    row = await _row()
    assert row is not None and row.ended_reason == reason and row.ended_at is not None, (row.ended_reason if row else None)
    [e] = await _entries("vendor.finding_confirm_lapsed")
    assert e.actor_kind == "system" and e.details["reason"] == reason and e.details["finding"] == FID and e.details["confirmed_by"] == "Anna"
    return row


async def test_now_exploited_lifts_it_and_the_message_says_so(admin_client, reader_client, sites, hooks):
    await _setup(admin_client, "vendor_vuln")
    await _dispatch()
    await _confirm(admin_client)
    assert await _store(_adv(exploited=True)) == 1  # "now exploited"
    await _lapsed_by("exploited")
    async with db.session() as s:
        ev = await s.scalar(select(VendorEvent).where(VendorEvent.key.like("exploited:%")))
    assert ev.data["confirm_lapsed"] == "exploited"
    await _dispatch()
    assert len(hooks) == 2
    [story] = json.loads(hooks[1].content)["stories"]
    assert story["summary"].startswith("Bestätigung aufgehoben: jetzt ausgenutzt")
    assert notify.vendor_story(ev, "en").summary.startswith("Confirmation lifted: now exploited")
    # counted again, and the drawer says why the confirmation is gone
    assert (await reader_client.get("/api/vendor/badge")).json()["affected"] == 1
    f = _finding((await reader_client.get("/api/vendor/products/panos")).json())
    assert f["confirmed"] is None and f["confirm_lapsed"]["reason"] == "exploited" and f["confirm_lapsed"]["status"] == "not_affected"
    # confirmed again – also while exploited: it stands
    assert (await _confirm(admin_client, "mitigated", "Brotli aus, Port zu")).status_code == 200
    assert await _store(_adv(exploited=True)) == 0
    assert (await _row()).ended_at is None


async def test_rated_higher_lifts_it(admin_client, sites):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    assert await _store(_adv(severity="medium", cvss=5.5)) == 1
    await _confirm(admin_client)
    assert await _store(_adv(severity="critical", cvss=9.3)) == 1  # "now rated higher"
    await _lapsed_by("severity")


async def test_a_new_cve_lifts_it_and_its_change_goes_out(admin_client, sites, hooks):
    await _setup(admin_client, "vendor_change")
    await _confirm(admin_client)
    # the advisory names a second CVE: no new vulnerability event (the finding is known), an advisory change – made by
    # the round before the evaluation saw it, and still sent (the confirmation lapsed because of it)
    assert await _store(_adv(cves=[CVE, "CVE-2026-8302"])) == 0
    await _lapsed_by("cves")
    await _dispatch()
    assert len(hooks) == 1 and "CVE-2026-8302" in hooks[0].content.decode()


async def test_a_version_entered_later_and_affected_lifts_it(admin_client, sites):
    await _setup(admin_client)
    await _confirm(admin_client)
    assert (await admin_client.post("/api/vendor/follows/panos/versions", json={"version": "11.2.4-h25"})).status_code == 200
    async with db.session() as s:
        await vendor.evaluate_events(s)
    await _lapsed_by("verdict")


async def test_a_version_no_longer_affected_keeps_it(admin_client, reader_client, sites):
    await _follow(admin_client, "panos", "11.2.4-h23", "11.2.4-h25")
    await _round()
    assert await _store(_adv()) == 2
    await _confirm(admin_client)
    vid = next(v["id"] for v in (await reader_client.get("/api/vendor/products/panos")).json()["versions"] if v["version"] == "11.2.4-h25")
    assert (await admin_client.delete(f"/api/vendor/versions/{vid}")).status_code == 200  # fewer concerned: no reason
    async with db.session() as s:
        await vendor.evaluate_events(s)
    assert (await _row()).ended_at is None


async def test_withdrawn_lifts_it(admin_client, sites):
    await _setup(admin_client)
    await _confirm(admin_client)
    async with db.session() as s:
        await vendor.drop_advisories(s, [FID])
    await _lapsed_by("withdrawn")


async def test_the_facts_compared(admin_client):
    f = {"id": FID, "severity": "high", "exploited": False, "cves": ["CVE-1"], "versions": [{"version": "1", "status": "possible"}, {"version": "2", "status": "not_affected"}]}
    old = finding_confirm.facts_of(f)
    same = {**f, "versions": [{"version": "1", "status": "possible", "fixed": "1.1"}, {"version": "2", "status": "not_affected"}]}
    assert finding_confirm.lapse_reason(old, same) is None  # a fix named: no reason
    assert finding_confirm.lapse_reason(old, {**f, "severity": "medium"}) is None  # rated lower: no reason
    assert finding_confirm.lapse_reason(old, {**f, "cves": []}) is None  # a CVE less: no reason
    assert finding_confirm.lapse_reason(old, {**f, "exploited": True}) == "exploited"
    assert finding_confirm.lapse_reason(old, {**f, "severity": "critical"}) == "severity"
    assert finding_confirm.lapse_reason(old, {**f, "cves": ["cve-1", "CVE-2"]}) == "cves"
    assert finding_confirm.lapse_reason(old, {**f, "versions": [{"version": "1", "status": "affected"}]}) == "verdict"  # more surely
    assert finding_confirm.lapse_reason(old, {**f, "versions": [{"version": "2", "status": "possible"}]}) == "verdict"
    assert finding_confirm.lapse_reason(old, {**f, "versions": [{"version": "3", "status": "possible"}]}) == "verdict"  # a new one
    assert finding_confirm.lapse_reason(old, {**f, "versions": [{"version": "1", "status": "not_affected"}]}) is None


async def test_a_product_no_longer_followed_takes_its_confirmations(admin_client, sites):
    await _setup(admin_client)
    await _confirm(admin_client)
    assert (await admin_client.delete("/api/vendor/follows/panos")).status_code == 200
    async with db.session() as s:
        assert (await reader.prune(s))["confirms"] == 1
    assert await _row() is None


# ---------------------------------------------------------------- review 0.1.56: the records of the group, the periods


def _nvd_rec(start: str = "11.2.0", **kw) -> dict:
    """NVD's record of the finding's CVE – grouped under the PAN-OS advisory (the same finding)."""
    rec = _nvd(CVE, start=start, end="11.2.4-h30")
    rec["updated_at"] = datetime.now(UTC) - timedelta(minutes=40) + timedelta(seconds=next(_step))
    return rec | kw


async def test_a_revision_of_a_grouped_record_is_held_too(admin_client, sites, hooks):
    """M1: a change event is per advisory – the NVD record of the finding's CVE revised (its range widened, the verdict
    of our version unchanged) is a change of the confirmed finding and is held like one of its leading advisory."""
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _webhook_rule(admin_client, ["vendor_vuln", "vendor_change"])
    await _round()
    async with db.session() as s:
        await vendor.store(s, [_adv(), _nvd_rec()], vendor.build_index())
        await vendor.evaluate_events(s)
    await _dispatch()
    before = len(hooks)
    f = _finding((await admin_client.get("/api/vendor/products/panos")).json())
    assert f"nvd:{CVE}" in [f"{a['source']}:{a['ident']}" for a in f["also"]]
    assert (await _confirm(admin_client)).status_code == 200
    assert f"nvd:{CVE}" in (await _row()).facts["members"]
    assert await _store(_nvd_rec(start="11.1.0")) == 0
    async with db.session() as s:
        evs = list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "change")))
        assert evs and {e.data["advisory"] for e in evs} == {f"nvd:{CVE}"}
        assert await finding_confirm.held_events(s, [e.id for e in evs]) == {e.id for e in evs}
    assert (await _row()).ended_at is None  # no reason to look again
    await _dispatch()
    assert len(hooks) == before


async def test_a_new_confirmation_after_a_lapse_holds_nothing_of_the_time_between(admin_client, sites):
    """M2: confirmed, lapsed, confirmed again, undone – an event made while none stood is not held (each period is a row)."""
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    assert await _store(_adv()) == 1
    t0 = datetime.now(UTC) - timedelta(days=10)
    assert (await _confirm(admin_client)).status_code == 200
    async with db.session() as s:
        c = await finding_confirm.current(s, "panos", FID)
        c.held_from = c.confirmed_at = t0
        finding_confirm._end(c, "exploited", t0 + timedelta(days=2))  # lapsed 8 days ago – held until 9 days ago
        ev = await s.scalar(select(VendorEvent).where(VendorEvent.kind == "vuln", VendorEvent.key.like(f"%{FID}")))
        held = VendorEvent(key=f"rated:high:{ev.scope}:{FID}", kind="vuln", product="panos", severity="high", data=ev.data, created_at=t0 + timedelta(hours=12), scope=ev.scope)
        gap = VendorEvent(key=f"exploited:{ev.scope}:{FID}", kind="vuln", product="panos", severity="critical", data=ev.data, created_at=t0 + timedelta(days=5), scope=ev.scope)
        s.add_all([held, gap])
        await s.commit()
        ids = (held.id, gap.id)
    assert (await _confirm(admin_client)).status_code == 200  # confirmed again
    assert (await _unconfirm(admin_client)).status_code == 200
    async with db.session() as s:
        assert await finding_confirm.held_events(s, ids) == {ids[0]}  # the first period's – not the time between
        rows = list(await s.scalars(select(VendorConfirm).order_by(VendorConfirm.held_from)))
    assert [(r.ended_reason, r.held_from == t0) for r in rows] == [("exploited", True), ("undone", False)]


async def test_the_api_cache_generation_moves_after_the_commit(admin_client, sites):
    """L1: the generation of API v1's cached lists moves only once the change is stored."""
    await _setup(admin_client)
    g = finding_confirm.generation()
    d = (await admin_client.get("/api/vendor/products/panos")).json()
    async with db.session() as s:
        await finding_confirm.confirm(s, admin_client.user, "panos", _finding(d), "not_affected", "")
        assert finding_confirm.generation() == g  # not yet – nothing is stored
        await s.rollback()
    assert (await _confirm(admin_client)).status_code == 200
    assert finding_confirm.generation() == g + 1
    assert (await _unconfirm(admin_client)).status_code == 200
    assert finding_confirm.generation() == g + 2


async def test_the_reason_is_a_plain_label(admin_client, sites):
    """L4: no direction or control characters in the reason (plaintext.label, as every typed label)."""
    await _setup(admin_client)
    r = await _confirm(admin_client, note="Brotli\u202e nicht\u0007 aktiviert\u200f")
    assert r.json()["confirmed"]["note"] == "Brotli nicht aktiviert"


async def test_api_v1_product_counts_confirmed_findings_apart(admin_client, sites):
    """L5: GET /api/v1/vendor/products/{key} – a confirmed finding is not among by_status, it is counted as confirmed."""
    await _setup(admin_client)
    token = await make_token(admin_client)
    before = (await get("/api/v1/vendor/products/panos", token)).json()
    assert before["confirmed"] == 0
    await _confirm(admin_client)
    after = (await get("/api/v1/vendor/products/panos", token)).json()
    assert after["confirmed"] == 1 and after["by_status"].get("affected", 0) == before["by_status"]["affected"] - 1
