"""CVE beobachten (app/cve_watch.py, app/watch_api.py, the routing in app/personal.py): a person follows one CVE – a fix,
CISA KEV, a jump of its EPSS, a withdrawn advisory come on their own ways; only what is new after the watch began,
each once, through the bounded personal round; without a team; the own rows only (no IDOR), at most MAX_PER_PERSON,
CVE ids only. Nothing leaves the machine: mails are recorded, HTTP is a MockTransport (and no_network guards)."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app import cve_watch, db, notify, personal, vendor
from app.models import CveWatch, CveWatchState, EpssScore, NotifyRule, PersonDelivery, VendorAdvisory, VendorAdvisoryState, VendorEvent, VendorKev
from conftest import make_client, sign_in
from test_personal import _dispatch, _event, _person, _switch, _team, _ways, mails, web  # noqa: F401 - fixtures

CVE = "CVE-2026-31337"
HOUR = timedelta(hours=1)


def _adv(cve: str = CVE, *, ident: str | None = None, end: str = "11.2.4-h30", source: str = "nvd") -> VendorAdvisory:
    return VendorAdvisory(
        id=f"{source}:{ident or cve}",
        source=source,
        ident=ident or cve,
        title=f"{cve} in Example",
        url="https://nvd.example.com/x",
        cves=[cve],
        severity="high",
        cvss=8.1,
        data={"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:o:example:fw:*:*:*:*:*:*:*:*", "versionEndExcluding": end}]}]}], "cna": []},
    )


async def _add(*rows) -> None:  # noqa: ANN002
    async with db.session() as s:
        for r in rows:
            await s.merge(r)
        await s.commit()


async def _evaluate(cves=None) -> int:  # noqa: ANN001
    async with db.session() as s:
        return await cve_watch.evaluate(s, cves)


async def _watch(u, cve: str = CVE, at: datetime | None = None) -> None:  # noqa: ANN001
    async with db.session() as s:
        await cve_watch.add(s, u.id, cve)
        if at is not None:
            row = await s.get(CveWatch, (u.id, cve))
            row.created_at = at
            await s.commit()


async def _watch_events() -> list[VendorEvent]:
    async with db.session() as s:
        return list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "watch").order_by(VendorEvent.n)))


# ---------------------------------------------------------------- the list (API)


async def test_add_list_remove_own_only_and_format(reader_client, admin_client):
    for bad in ("CVE-26-1", "cve-2026-12", "GHSA-xxxx-yyyy", "CVE-2026-1234; DROP", "CVE-2026-12a4"):
        r = await reader_client.post("/api/me/cve-watch", json={"cve": bad})
        assert r.status_code == 422, bad
    r = await reader_client.post("/api/me/cve-watch", json={"cve": " cve-2026-31337 "})  # trimmed, upper case
    assert r.status_code == 200 and r.json() == {"cve": CVE, "added": True}
    assert (await reader_client.post("/api/me/cve-watch", json={"cve": CVE})).json()["added"] is False
    assert (await admin_client.post("/api/me/cve-watch", json={"cve": "CVE-2025-0001"})).json()["added"] is True
    # unknown to Cobe News: kept all the same (nothing is asked outside – no_network would fail the test)
    items = (await reader_client.get("/api/me/cve-watch")).json()["items"]
    assert [(i["cve"], i["known"]) for i in items] == [(CVE, False)]
    assert (await reader_client.get("/api/me/cve-watch/ids")).json() == {"cves": [CVE]}
    # no IDOR: a body naming another person is refused, a path names a CVE only – and only the own row goes
    r = await reader_client.post("/api/me/cve-watch", json={"cve": "CVE-2025-0001", "user_id": str(admin_client.user.id)})
    assert r.status_code == 422
    assert (await reader_client.delete("/api/me/cve-watch/CVE-2025-0001")).json()["removed"] is False
    assert (await admin_client.get("/api/me/cve-watch/ids")).json() == {"cves": ["CVE-2025-0001"]}
    assert (await reader_client.delete("/api/me/cve-watch/not-a-cve")).status_code == 422
    assert (await reader_client.delete(f"/api/me/cve-watch/{CVE.lower()}")).json() == {"cve": CVE, "removed": True}
    assert (await reader_client.get("/api/me/cve-watch/ids")).json() == {"cves": []}
    async with make_client() as anon:
        assert (await anon.get("/api/me/cve-watch")).status_code == 401
        assert (await anon.post("/api/me/cve-watch", json={"cve": CVE})).status_code == 401


async def test_limit_per_person(reader_client, monkeypatch):
    monkeypatch.setattr(cve_watch, "MAX_PER_PERSON", 3)
    for i in range(3):
        assert (await reader_client.post("/api/me/cve-watch", json={"cve": f"CVE-2026-100{i}"})).status_code == 200
    r = await reader_client.post("/api/me/cve-watch", json={"cve": "CVE-2026-1009"})
    assert r.status_code == 409 and r.json()["detail"] == {"code": "watch_limit", "limit": 3}
    assert (await reader_client.post("/api/me/cve-watch", json={"cve": "CVE-2026-1001"})).json()["added"] is False  # known: fine
    assert (await reader_client.get("/api/me/cve-watch")).json()["limit"] == 3


async def test_notify_hint_without_teams_and_ways_available_without_a_team(reader_client, mails):
    await reader_client.post("/api/me/cve-watch", json={"cve": CVE})
    n = (await reader_client.get("/api/me/cve-watch")).json()["notify"]
    assert n["reason"] == "teams_off" and not any(n["ways"].values())  # a reminder list – the page says why
    await _switch(email=True, desktop=False, teams=False)
    me = (await reader_client.get("/api/me/vendor-notify")).json()
    assert me["available"] is True and me["in_team"] is False and me["products"] == []  # watching: the ways are there
    n = (await reader_client.get("/api/me/cve-watch")).json()["notify"]
    assert n["reason"] == "no_way_on" and n["allowed"]["email"] is True
    await reader_client.delete(f"/api/me/cve-watch/{CVE}")
    assert (await reader_client.get("/api/me/vendor-notify")).json()["reason"] == "no_team"  # as before 0.1.34


# ---------------------------------------------------------------- what is news


async def test_baseline_is_silent_kev_and_fix_once(reader_client):
    await _add(_adv(), VendorKev(cve="CVE-2026-0002", vendor="Example", product="FW", name="x", date_added="2026-10-01"))
    await reader_client.post("/api/me/cve-watch", json={"cve": CVE})
    await reader_client.post("/api/me/cve-watch", json={"cve": "CVE-2026-0002"})  # in KEV already: not news
    assert await _evaluate() == 0
    async with db.session() as s:
        st = await s.get(CveWatchState, CVE)
        assert st.state["fixed"] == ["example:fw: 11.2.4-h30"] and st.state["kev"] is False
    # CISA lists it
    await _add(VendorKev(cve=CVE, vendor="Example", product="FW", name="Example FW", date_added="2026-10-30", due="2026-11-20", ransomware=True))
    assert await _evaluate() == 1
    assert await _evaluate() == 0  # once
    # a new fixed version (another advisory, a revision): a fix event; the known one is no news
    await _add(_adv(ident="FG-IR-26-001", source="fortinet", end="7.4.9"))
    async with db.session() as s:
        s.add(VendorAdvisoryState(advisory_id="fortinet:FG-IR-26-001", facts={"fixed": ["FortiOS: 7.4.9", "example:fw: 11.2.4-h30"]}, revision=1))
        await s.commit()
    assert await _evaluate() == 1
    assert await _evaluate() == 0
    evs = await _watch_events()
    assert [e.data["what"] for e in evs] == ["kev", "fix"]
    assert evs[0].severity == "high" and evs[0].scope == f"watch:{CVE}" and evs[0].product == ""
    assert evs[1].data["fixed"] == ["FortiOS: 7.4.9"]
    s_ = notify.vendor_story(evs[0], "de")
    assert s_.title == f"{CVE}: jetzt in CISA KEV (aktiv ausgenutzt)" and "Ransomware" in s_.summary and s_.link.endswith(f"/watch?cve={CVE}")
    assert notify.vendor_story(evs[1], "en").title == f"{CVE}: fixed version available"


def test_epss_threshold():
    st = cve_watch.baseline({"epss": {"score": 0.05, "percentile": 0.80, "day": "2026-10-01"}})
    assert st == {"kev": False, "fixed": [], "epss_base": 0.05, "epss_high": False}

    def step(st, score, pct, day):  # noqa: ANN001, ANN202
        return cve_watch.compare(CVE, st, {"epss": {"score": score, "percentile": pct, "day": day}})

    st, ev = step(st, 0.12, 0.88, "2026-10-02")  # +0.07: below the jump, percentile below 0.9
    assert ev == [] and st["epss_base"] == 0.05
    st, ev = step(st, 0.14, 0.91, "2026-10-03")  # the percentile reaches 0.9
    assert [e["data"]["reasons"] for e in ev] == [["high"]] and ev[0]["severity"] == "high" and ev[0]["key"] == f"watch:{CVE}:epss:2026-10-03"
    assert st["epss_base"] == 0.14 and st["epss_high"] is True
    st, ev = step(st, 0.15, 0.87, "2026-10-04")  # between 0.85 and 0.9: no flapping
    assert ev == [] and st["epss_high"] is True
    st, ev = step(st, 0.10, 0.84, "2026-10-05")  # below 0.85: may come again; the jump counts from the lowest value
    assert ev == [] and st["epss_high"] is False and st["epss_base"] == 0.10
    st, ev = step(st, 0.20, 0.89, "2026-10-06")  # +0.10 absolute
    assert [e["data"]["reasons"] for e in ev] == [["jump"]] and ev[0]["data"]["from"] == 0.10 and ev[0]["severity"] == "medium"
    st, ev = step(st, 0.29, 0.93, "2026-10-07")  # high again (it fell below 0.85 before)
    assert [e["data"]["reasons"] for e in ev] == [["high"]]
    st, ev = step(st, 0.29, 0.93, "2026-10-08")
    assert ev == []
    # no EPSS at the start: its first value is the reference, a high percentile counts
    st, ev = cve_watch.compare(CVE, cve_watch.baseline({}), {"epss": {"score": 0.4, "percentile": 0.5, "day": "d"}})
    assert ev == [] and st["epss_base"] == 0.4


async def test_epss_from_the_stored_scores(reader_client):
    await _add(EpssScore(cve=CVE, score=0.02, percentile=0.6, day="2026-10-29"))
    await reader_client.post("/api/me/cve-watch", json={"cve": CVE})
    await _add(EpssScore(cve=CVE, score=0.31, percentile=0.97, day="2026-10-30"))
    assert await _evaluate() == 1
    ev = (await _watch_events())[0]
    assert ev.data["reasons"] == ["high", "jump"] and notify.vendor_story(ev, "de").title == f"{CVE}: EPSS gestiegen auf 31,0 %"


async def test_withdrawn_advisory_of_a_watched_cve(reader_client):
    await _add(_adv(), _adv("CVE-2026-0003"))
    await reader_client.post("/api/me/cve-watch", json={"cve": CVE})
    async with db.session() as s:
        await vendor.drop_advisories(s, [f"nvd:{CVE}", "nvd:CVE-2026-0003"])
    evs = await _watch_events()
    assert [(e.data["what"], e.data["cve"], e.severity) for e in evs] == [("withdrawn", CVE, "info")]  # the other one is not watched
    assert "zurückgezogen" in notify.vendor_story(evs[0], "de").title


# ---------------------------------------------------------------- the way to the person


async def test_delivered_once_only_new_without_a_team(mails, web):
    await _switch(email=True, desktop=False, teams=False)
    a, b = await _person("anja"), await _person("bert")
    await _ways(a, email=True, kinds=["vendor_vuln"], min_severity="critical")  # kind and severity filters do not apply
    await _ways(b, email=True)
    await _watch(a, at=datetime.now(UTC) - HOUR)
    await _add(VendorKev(cve=CVE, vendor="Example", product="FW", name="Example FW", date_added="2026-10-30"))
    assert await _evaluate() == 1
    # bert starts watching after the change was seen: not his news (his watch begins after it)
    await _watch(b)
    assert await _dispatch() == {"sent": 1}
    assert [m["to"] for m in mails.sent] == [["anja@corp.example"]] and CVE in mails.sent[0]["subject"] + mails.sent[0]["text"]
    assert await _dispatch() == {}  # exactly once
    assert len(mails.sent) == 1
    # an event from before the watch began is never sent (nothing old)
    async with db.session() as s:
        row = await s.get(CveWatch, (a.id, CVE))
        row.created_at = datetime.now(UTC)
        await s.commit()
    await _add(EpssScore(cve=CVE, score=0.5, percentile=0.99, day="2026-10-30"))
    async with db.session() as s:
        await cve_watch.evaluate(s, now=datetime.now(UTC) - timedelta(minutes=5))
    assert await _dispatch() == {} and len(mails.sent) == 1


async def test_unwatched_before_the_round_not_sent_and_teams_unchanged(mails, web):
    await _switch(email=True, desktop=False, teams=False)
    a = await _person("anja")
    await _team([a])
    await _ways(a, email=True)
    await _watch(a, at=datetime.now(UTC) - HOUR)
    await _add(VendorKev(cve=CVE, vendor="Example", product="FW", name="x", date_added="2026-10-30"))
    await _evaluate()
    team_ev = await _event("panos")
    async with db.session() as s:
        await personal.enqueue(s, await personal.allowed(s))
        await s.execute(CveWatch.__table__.delete())
        await s.commit()
    assert await _dispatch() == {"sent": 1}  # the team's event – the CVE's was dropped with the watch
    async with db.session() as s:
        rows = {(r.event_id == team_ev, r.status, r.error) for r in await s.scalars(select(PersonDelivery))}
    assert rows == {(True, "sent", None), (False, "skipped", "not_routed")}


async def test_inactive_person_and_ways_off_get_nothing(mails, web):
    await _switch(email=True, desktop=False, teams=False)
    a = await _person("anja", active=False)
    await _ways(a, email=True)
    await _watch(a, at=datetime.now(UTC) - HOUR)
    await _add(VendorKev(cve=CVE, vendor="Example", product="FW", name="x", date_added="2026-10-30"))
    await _evaluate()
    assert await _dispatch() == {} and mails.sent == []
    await _switch(enabled=False)  # Teams off: no personal way at all
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(PersonDelivery).where(PersonDelivery.status == "pending")) == 0


async def test_rules_never_get_watch_events_and_pruning(reader_client):
    await reader_client.post("/api/me/cve-watch", json={"cve": CVE})
    await _add(VendorKev(cve=CVE, vendor="Example", product="FW", name="x", date_added="2026-10-30"))
    await _evaluate()
    async with db.session() as s:
        rule = NotifyRule(name="all", kinds=["news", "vendor_vuln", "vendor_version", "vendor_change"], severities=[], enabled=True, earlier=[])
        s.add(rule)
        await s.flush()
        assert await notify.vendor_pending(s, rule, rule.id, datetime.now(UTC) - HOUR) == []
        await s.rollback()
        # Vendor News' pruning (no product followed) leaves them alone – they belong to no product
        await vendor.prune_events(s, [], {})
        assert len(await _watch_events()) == 1
    await reader_client.delete(f"/api/me/cve-watch/{CVE}")
    async with db.session() as s:
        assert await cve_watch.prune(s) == 1  # the state nobody watches
        assert await cve_watch.prune(s, datetime.now(UTC) + cve_watch.KEEP + HOUR) == 1  # the event, after KEEP
    assert await _watch_events() == []


async def test_due_check_only_after_a_change(reader_client, monkeypatch):
    calls = []
    real = cve_watch.evaluate

    async def counting(db_, cves=None, **kw):  # noqa: ANN001, ANN202
        calls.append(cves)
        return await real(db_, cves, **kw)

    monkeypatch.setattr(cve_watch, "evaluate", counting)
    async with db.session() as s:
        assert await cve_watch.evaluate_due(s, (1, 1)) == 0 and calls == []  # nobody watches
    await reader_client.post("/api/me/cve-watch", json={"cve": CVE})
    calls.clear()
    async with db.session() as s:
        await cve_watch.evaluate_due(s, (1, 1))
        await cve_watch.evaluate_due(s, (1, 1))
        assert len(calls) == 1
        await cve_watch.evaluate_due(s, (2, 1))
        assert len(calls) == 2


@pytest.mark.parametrize("value", [None, "", "CVE-2026-1", "CVE-2026-1234567890123", "XCVE-2026-1234"])
def test_normalize_refuses(value):
    assert cve_watch.normalize(value) is None


async def test_sign_in_of_another_person_sees_only_theirs(reader_client):
    other = await _person("otto")
    await _watch(other, "CVE-2024-3400")
    assert (await reader_client.get("/api/me/cve-watch")).json()["items"] == []
    async with make_client() as c:
        await sign_in(c, other)
        assert [i["cve"] for i in (await c.get("/api/me/cve-watch")).json()["items"]] == ["CVE-2024-3400"]


# ---------------------------------------------------------------- the list's timeline and "new since the last visit"


async def _event_at(cve: str, what: str, at: datetime, **data) -> None:  # noqa: ANN003
    async with db.session() as s:
        s.add(VendorEvent(key=f"watch:{cve}:{what}:{at.isoformat()}", kind="watch", product="", severity="high", scope=cve_watch.scope(cve), created_at=at, data={"cve": cve, "what": what, "title": "x", **data}))
        await s.commit()


async def _since(u, cve: str, at: datetime) -> None:  # noqa: ANN001
    async with db.session() as s:
        row = await s.get(CveWatch, (u.id, cve))
        row.created_at = at
        await s.commit()


async def test_timeline_only_own_watch_since_it_began_newest_first(reader_client):
    now = datetime.now(UTC)
    await reader_client.post("/api/me/cve-watch", json={"cve": CVE})
    await _since(reader_client.user, CVE, now - 10 * HOUR)
    await _event_at(CVE, "kev", now - 20 * HOUR, kev={"added": "2026-10-01", "due": "2026-10-21", "ransomware": True, "name": "x"})  # before the watch
    await _event_at(CVE, "fix", now - 5 * HOUR, fixed=["FortiOS: 7.4.9"], more=0, by=[{"source": "fortinet", "ident": "FG-IR-26-001"}])
    await _event_at(CVE, "epss", now - 2 * HOUR, score=0.31, percentile=0.97, **{"from": 0.02}, reasons=["high", "jump"], day="2026-10-30")
    await _event_at(CVE, "withdrawn", now - HOUR, advisory=f"nvd:{CVE}", source="nvd", ident=CVE)
    await _event_at("CVE-2026-0009", "kev", now - HOUR, kev={})  # another CVE
    r = await reader_client.get(f"/api/me/cve-watch/{CVE.lower()}/events")
    assert r.status_code == 200
    d = r.json()
    assert d["cve"] == CVE and d["stories"] == 0
    assert [e["what"] for e in d["events"]] == ["withdrawn", "epss", "fix"]  # the KEV came before the watch began
    assert d["events"][0] == {"what": "withdrawn", "at": d["events"][0]["at"], "source": "nvd", "ident": CVE}
    assert d["events"][1] | {"at": None} == {"what": "epss", "at": None, "score": 0.31, "percentile": 0.97, "from": 0.02, "reasons": ["high", "jump"]}
    assert d["events"][2]["fixed"] == ["FortiOS: 7.4.9"] and d["events"][2]["by"] == [{"source": "fortinet", "ident": "FG-IR-26-001"}]
    assert all("key" not in e and "id" not in e and "title" not in e for e in d["events"])  # only what the list shows
    # the list's last event is the newest since the watch began, too
    item = (await reader_client.get("/api/me/cve-watch")).json()["items"][0]
    assert item["last_event"]["what"] == "withdrawn"


async def test_timeline_404_unless_watched_by_this_person(reader_client):
    other = await _person("otto")
    await _watch(other, "CVE-2024-3400")
    await _event_at("CVE-2024-3400", "kev", datetime.now(UTC), kev={})
    assert (await reader_client.get("/api/me/cve-watch/CVE-2024-3400/events")).status_code == 404  # otto's, not rudi's
    assert (await reader_client.get("/api/me/cve-watch/CVE-2026-9999/events")).status_code == 404  # nobody's
    assert (await reader_client.get("/api/me/cve-watch/not-a-cve/events")).status_code == 422
    async with make_client() as anon:
        assert (await anon.get("/api/me/cve-watch/CVE-2024-3400/events")).status_code == 401
        assert (await anon.post("/api/me/cve-watch/seen")).status_code in (401, 403)


async def test_timeline_capped_and_counts_the_stories(reader_client):
    now = datetime.now(UTC)
    await reader_client.post("/api/me/cve-watch", json={"cve": CVE})
    await _since(reader_client.user, CVE, now - 100 * HOUR)
    for i in range(cve_watch.TIMELINE + 5):
        await _event_at(CVE, "fix", now - timedelta(minutes=i), fixed=[f"v{i}"], more=0)
    async with db.session() as s:
        from app import news as news_svc
        from app.models import NewsItem, NewsSource

        src = await s.scalar(select(NewsSource).limit(1))
        src.enabled = True
        for n, cves in enumerate(([CVE], ["CVE-2026-0001"], [CVE, "CVE-2026-0002"])):
            title = f"Story {n}"
            s.add(NewsItem(source_id=src.id, url=f"https://news.example.com/{n}", url_key=f"k{n}", title=title, title_key=title.lower(), summary="", published_at=now, cves=cves, search=news_svc.search_text(title, "", cves)))
        await s.commit()
    d = (await reader_client.get(f"/api/me/cve-watch/{CVE}/events")).json()
    assert len(d["events"]) == cve_watch.TIMELINE and d["events"][0]["fixed"] == ["v0"]  # the newest
    assert d["stories"] == 2


async def test_seen_before_moves_only_when_the_page_says_so(reader_client):
    first = (await reader_client.get("/api/me/cve-watch")).json()
    assert first["seen_before"] is None  # never visited: nothing is new
    r = await reader_client.post("/api/me/cve-watch/seen")
    assert r.status_code == 200
    at = r.json()["seen_at"]
    assert (await reader_client.get("/api/me/cve-watch")).json()["seen_before"] == at
    assert (await reader_client.get("/api/me/cve-watch")).json()["seen_before"] == at  # reading does not move it
    async with db.session() as s:
        from app.models import PersonNotify

        p = await s.get(PersonNotify, reader_client.user.id)
        assert p.watch_seen_at is not None and not (p.email_on or p.desktop_on or p.teams_on or p.weekly_on)  # nothing switched on
        assert list(p.kinds) == list(personal.DEFAULT_KINDS)
    # the ways the person had stay as they were
    me = (await reader_client.get("/api/me/vendor-notify")).json()
    assert me["email"]["on"] is False and me["kinds"] == list(personal.DEFAULT_KINDS)
    second = (await reader_client.post("/api/me/cve-watch/seen")).json()["seen_at"]
    assert second >= at
    # another person's visit is theirs
    other = await _person("otto")
    async with make_client() as c:
        await sign_in(c, other)
        assert (await c.get("/api/me/cve-watch")).json()["seen_before"] is None


async def test_last_event_before_the_watch_is_not_this_persons(reader_client):
    now = datetime.now(UTC)
    await _event_at(CVE, "kev", now - 3 * HOUR, kev={})  # somebody else's watch saw it
    await reader_client.post("/api/me/cve-watch", json={"cve": CVE})
    item = (await reader_client.get("/api/me/cve-watch")).json()["items"][0]
    assert item["last_event"] is None
    assert (await reader_client.get(f"/api/me/cve-watch/{CVE}/events")).json()["events"] == []


async def test_fix_event_names_the_advisory_and_the_list_its_link(reader_client):
    await _add(_adv())
    await reader_client.post("/api/me/cve-watch", json={"cve": CVE})
    await _add(_adv(ident="FG-IR-26-001", source="fortinet", end="7.4.9"))
    async with db.session() as s:
        s.add(VendorAdvisoryState(advisory_id="fortinet:FG-IR-26-001", facts={"fixed": ["FortiOS: 7.4.9"]}, revision=1))
        await s.commit()
    assert await _evaluate() == 1
    ev = (await _watch_events())[0]
    assert ev.data["fixed"] == ["FortiOS: 7.4.9"] and ev.data["by"] == [{"source": "fortinet", "ident": "FG-IR-26-001"}]
    item = (await reader_client.get("/api/me/cve-watch")).json()["items"][0]
    assert item["advisory"] == {"source": "fortinet", "ident": "FG-IR-26-001", "url": "https://nvd.example.com/x"}  # the vendor's before the NVD's
    d = (await reader_client.get(f"/api/me/cve-watch/{CVE}/events")).json()
    assert d["events"][0]["by"] == [{"source": "fortinet", "ident": "FG-IR-26-001"}]


def test_advisory_link_only_a_web_address():
    assert cve_watch._link("nvd", CVE, "javascript:alert(1)", "high", True) is None
    assert cve_watch._link("nvd", CVE, "", "high", True) is None
    assert cve_watch._link("nvd", CVE, "https://nvd.example.com/x", "high", True)[1]["url"] == "https://nvd.example.com/x"


async def test_migration_adds_the_visit_column():
    from sqlalchemy import inspect

    async with db.engine().connect() as conn:
        cols = await conn.run_sync(lambda c: {x["name"]: x for x in inspect(c).get_columns("person_notify")})
    assert cols["watch_seen_at"]["nullable"] is True
