# ruff: noqa: F811 - the fixtures of test_vendor_service are imported and used by name
"""Palo Alto's own rating (0.1.57): its JSON carries the pure CVSS 4.0 base (baseScore 8.7 HIGH for CVE-2026-0331) and
its rating – CVSS-BT, base and threat metrics (threatScore 6.6, threatSeverity and severity MEDIUM) – which its page,
the RSS title, cve.org and the NVD show. Vendor News and the story details go by the rating, the base is kept beside it.
The stored advisories get it with one full refetch (migration 0047) – quietly: no revision, no event, no message, a
confirmation stays; the story details likewise (story_details.PARSER_V)."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text, update
from test_vendor_service import _dispatch, _follow, _round, _webhook_rule, hooks, sites, vendor_reset  # noqa: F401 - fixtures

from app import advisory_changes as ch
from app import db, story_details, systems, vendor
from app import vendor_sources as src
from app.models import NewsItem, StoryDetail, VendorAdvisory, VendorAdvisoryChange, VendorAdvisoryState, VendorConfirm, VendorEvent, VendorFetch

FIX = Path(__file__).parent / "fixtures" / "vendor"
ID = "paloalto:CVE-2026-0331"


def _list(recent: bool = False) -> bytes:
    """A trimmed real page of Palo Alto's PAN-OS list (taken 16 Nov 2026) – `recent`: dated a day ago (fresh events)."""
    doc = json.loads((FIX / "pan_rating.json").read_bytes())
    if recent:
        at = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        for a in doc:
            a["date"] = a["updated"] = at
    return json.dumps(doc).encode()


def _advs(recent: bool = False) -> dict[str, dict]:
    return {a["ident"]: a for a in src.parse_pan(_list(recent))}


def _as_before(a: dict, **kw) -> dict:
    """The record as the parser before 0.1.57 stored it: rated by the CVSS base, no base beside it."""
    data = {k: v for k, v in a["data"].items() if k != "base"}
    return {**a, "cvss": a["data"]["base"]["cvss"], "severity": a["data"]["base"]["severity"], "data": data} | kw


# ---------------------------------------------------------------- the parsers


def test_vendor_news_rates_by_palo_altos_rating_and_keeps_the_base():
    advs = _advs()
    a = advs["CVE-2026-0331"]
    assert (a["severity"], a["cvss"]) == ("medium", 6.6)  # as Palo Alto's page, its RSS title, cve.org and the NVD say
    assert a["data"]["base"] == {"cvss": 8.7, "severity": "high"}
    assert (advs["CVE-2026-0328"]["severity"], advs["CVE-2026-0328"]["cvss"]) == ("low", 2.7)  # base: HIGH 7.0
    assert (advs["CVE-2026-111497"]["severity"], advs["CVE-2026-111497"]["cvss"]) == ("critical", 9.2)  # both the same
    assert advs["PAN-SA-2026-0005"]["severity"] == "info"  # INFORMATIONAL, score 0
    # an advisory of CVSS 3.x (2012): no threat score – the base is the rating, as before
    old = advs["CVE-2012-6602"]
    assert (old["severity"], old["cvss"], old["data"]["base"]) == ("high", 8.4, {"cvss": 8.4, "severity": "high"})


@pytest.mark.parametrize(
    ("fields", "want"),
    [
        ({"baseScore": 8.7, "baseSeverity": "HIGH", "threatScore": 6.6, "threatSeverity": "MEDIUM", "severity": "MEDIUM"}, ("medium", 6.6)),
        ({"baseScore": 8.7, "baseSeverity": "HIGH", "threatScore": 6.6, "threatSeverity": "MEDIUM"}, ("medium", 6.6)),  # no "severity"
        ({"baseScore": 7.5, "baseSeverity": "HIGH", "threatSeverity": ""}, ("high", 7.5)),  # no threat score
        ({"baseSeverity": "HIGH", "threatSeverity": "", "severity": "MEDIUM"}, ("medium", None)),  # no score: Palo's word
        ({"baseSeverity": "HIGH"}, ("high", None)),
        ({"baseScore": 8.7, "threatScore": "6.6", "severity": "MEDIUM"}, ("high", 8.7)),  # not a number: the base
    ],
)
def test_the_rating_falls_back_to_the_base(fields, want):
    [a] = src.parse_pan(json.dumps([{"ID": "CVE-2026-0001", "title": "x", **fields}]).encode())
    assert (a["severity"], a["cvss"]) == want


def test_story_details_show_the_threat_score_and_the_base_beside_it():
    d = story_details.parse_cve5((FIX / "cve5_pan_0331.json").read_bytes())
    [c] = d["cvss"]
    assert (c["score"], c["base"], c["temporal"]) == (6.6, 8.7, None) and "E:U" in c["vector"]
    assert story_details.hint(d)["cvss"] == 6.6 and d["v"] == story_details.PARSER_V["paloalto"]
    # a rating that is the base (exploited: E:A) – nothing beside it
    [c] = story_details.parse_cve5((FIX / "cve5_pan.json").read_bytes())["cvss"]
    assert (c["score"], c["base"]) == (8.6, None)


def test_rerated_only_for_the_first_record_with_the_base():
    assert ch.rerated("paloalto", {"lines": []}, {"lines": [], "base": {"cvss": 8.7}})
    assert not ch.rerated("paloalto", {"base": {"cvss": 8.7}}, {"base": {"cvss": 8.7}})  # stored by this parser already
    assert not ch.rerated("nvd", {}, {"base": {}})
    assert story_details.reparsed("paloalto", {"cvss": []}, {"cvss": [], "v": 2})
    assert not story_details.reparsed("paloalto", {"v": 2}, {"v": 2}) and not story_details.reparsed("paloalto", None, {"v": 2})
    assert not story_details.reparsed("nvd", {}, {"v": 2})


# ---------------------------------------------------------------- the stored advisories: re-rated quietly


async def _store(*advs: dict) -> int:
    async with db.session() as s:
        await vendor.store(s, list(advs), vendor.build_index())
        return await vendor.evaluate_events(s)


async def _events() -> list[tuple]:
    async with db.session() as s:
        return [(e.n, e.key, e.kind, e.severity, e.baseline) for e in await s.scalars(select(VendorEvent).order_by(VendorEvent.n))]


async def _revisions(aid: str = ID) -> list[VendorAdvisoryChange]:
    async with db.session() as s:
        return list(await s.scalars(select(VendorAdvisoryChange).where(VendorAdvisoryChange.advisory_id == aid).order_by(VendorAdvisoryChange.revision)))


@pytest.mark.parametrize("confirmed", [False, True], ids=["open", "confirmed"])
@pytest.mark.parametrize("state", [False, True], ids=["stored-once", "with-state"])
async def test_the_re_rating_sends_nothing_and_keeps_a_confirmation(admin_client, sites, hooks, confirmed, state):
    await _follow(admin_client, "panos", "11.2.4-h20")
    await _webhook_rule(admin_client, ["vendor_vuln", "vendor_change"])
    await _round()  # the baseline
    new = _advs(recent=True)["CVE-2026-0331"]
    old = _as_before(new, updated_at=new["updated_at"] - timedelta(hours=2))
    assert await _store(old) == 1  # HIGH 8.7, as 0.1.56 rated it – notified
    if state:  # stored twice: the record has its facts
        await _store(old | {"updated_at": new["updated_at"] - timedelta(hours=1)})
    await _dispatch()
    assert len(hooks) == 1
    if confirmed:
        r = await admin_client.post("/api/vendor/findings/confirm", json={"product": "panos", "finding": ID, "status": "mitigated", "note": "Management-Interface nicht erreichbar"})
        assert r.status_code == 200, r.text
    before = await _events()
    assert await _store(new) == 0  # MEDIUM 6.6 now: no event …
    assert await _events() == before and await _revisions() == []  # … no revision
    await _dispatch()
    assert len(hooks) == 1  # nothing sent
    async with db.session() as s:
        a = await s.get(VendorAdvisory, ID)
        st = await s.get(VendorAdvisoryState, ID)
        conf = await s.scalar(select(VendorConfirm).where(VendorConfirm.finding == ID))
    assert (a.severity, a.cvss) == ("medium", 6.6) and (st.facts["sev"], st.facts["cvss"]) == ("medium", 6.6)
    if confirmed:
        assert conf is not None and conf.ended_at is None  # a lowering never lapses it
    f = next(x for x in (await admin_client.get("/api/vendor/products/panos")).json()["findings"] if x["id"] == ID)
    assert (f["severity"], f["cvss"], f["cvss_base"]) == ("medium", 6.6, 8.7)
    # from then on Palo Alto's own re-rating is a change as always (exploited now: E:A – 8.7 HIGH)
    later = new | {"cvss": 8.7, "severity": "high", "updated_at": new["updated_at"] + timedelta(hours=1)}
    await _store(later)
    [rev] = await _revisions()
    assert [x["f"] for x in rev.diff] == ["severity"] and rev.diff[0]["from"] == "medium"


async def test_the_re_rating_keeps_another_change_of_the_same_record(admin_client, sites):
    await _follow(admin_client, "panos", "11.2.4-h20")
    await _round()
    new = _advs(recent=True)["CVE-2026-0331"]
    old = _as_before(new, updated_at=new["updated_at"] - timedelta(hours=2))
    await _store(old)
    await _store(old | {"updated_at": new["updated_at"] - timedelta(hours=1)})
    lines = [dict(x) for x in new["data"]["lines"]]
    lines[3]["fixed"] += ", >= 11.2.4-h21"  # a new fixed version in the same record
    await _store(new | {"data": {**new["data"], "lines": lines}})
    [rev] = await _revisions()
    assert [x["f"] for x in rev.diff] == ["fixed"]  # the fix counts – the re-rating does not


async def test_findings_take_no_higher_score_from_the_cve_records(admin_client, sites):
    """The NVD and cvelistV5 carry Palo Alto's CVSS-BT (6.6) as their score: the finding's maximum over its records
    stays 6.6 MEDIUM."""
    await _follow(admin_client, "panos", "11.2.4-h20")
    await _round()
    pan = _advs(recent=True)["CVE-2026-0331"]
    nvd = {"id": "nvd:CVE-2026-0331", "source": "nvd", "ident": "CVE-2026-0331", "title": "CVE-2026-0331", "summary": "", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0331", "cves": ["CVE-2026-0331"], "cvss": 6.6, "severity": "medium", "published_at": pan["published_at"], "updated_at": pan["updated_at"], "names": [], "data": {"configs": []}}
    await _store(pan, nvd)
    f = next(x for x in (await admin_client.get("/api/vendor/products/panos")).json()["findings"] if x["id"] == ID)
    assert (f["severity"], f["cvss"], f["cvss_base"]) == ("medium", 6.6, 8.7)


# ---------------------------------------------------------------- migration 0047: one full refetch


async def test_migration_refetches_every_palo_alto_query_and_the_round_re_rates_quietly(admin_client, monkeypatch, sites, hooks):
    from alembic import command

    from app import news

    await _follow(admin_client, "panos", "11.2.4-h20")
    await _webhook_rule(admin_client, ["vendor_vuln", "vendor_change"])
    await _round()  # the baseline
    advs = _advs(recent=True)
    olds = [_as_before(a) for a in advs.values()]
    assert await _store(*olds) >= 1
    await _dispatch()
    sent = len(hooks)
    now = datetime.now(UTC)
    newest = max(a["updated_at"] for a in olds).isoformat()
    async with db.session() as s:  # as after the last run of 0.1.56: cursor and validators, the next run hours away
        for row in (
            VendorFetch(key="paloalto:PAN-OS", cursor=newest, etag='W/"v1"', last_modified="x", next_fetch_at=now + timedelta(hours=5), failures=0, items=5),
            VendorFetch(key="paloalto:GlobalProtect", cursor=newest, etag='W/"v1"', next_fetch_at=now + timedelta(hours=2), failures=3, items=0),
            VendorFetch(key="fortinet:rss", cursor="c", etag='W/"f"', next_fetch_at=now + timedelta(hours=5), failures=0, items=0),
        ):
            await s.merge(row)
        srcrow = await s.scalar(text("SELECT id FROM news_sources LIMIT 1"))
        items = []
        for n, kind in enumerate(("paloalto", "bsi", "paloalto")):
            i = NewsItem(source_id=srcrow, url=f"https://security.paloaltonetworks.com/CVE-2026-03{n}", url_key=f"m47-{n}", title=f"t{n}", title_key=f"t{n}", summary="", published_at=now - timedelta(days=60), cves=[], seq=await news.next_seq(s))
            s.add(i)
            await s.flush()
            items.append(i.id)
            s.add(StoryDetail(item_id=i.id, kind=kind, ident="x", status="ok" if n < 2 else "none", data={"cvss": [{"score": 8.7}]} if n < 2 else None))
        await s.commit()

    def down(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "0046")

    async with db.engine().begin() as conn:
        await conn.run_sync(down)
    await db.migrate()
    assert await db.revision() == db.head()
    async with db.session() as s:
        pan, gp, ft = [await s.get(VendorFetch, k) for k in ("paloalto:PAN-OS", "paloalto:GlobalProtect", "fortinet:rss")]
        assert (pan.cursor, pan.etag, pan.last_modified, pan.next_fetch_at) == (None, None, None, None)
        assert (gp.cursor, gp.etag) == (None, None) and gp.next_fetch_at is not None  # pausing after errors: it waits
        assert (ft.cursor, ft.etag) == ("c", 'W/"f"')
        due = [(await s.get(StoryDetail, i)).next_try_at is not None for i in items]
    assert due == [True, False, False]  # the Palo Alto story's details once again – not the BSI's, not one without

    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        assert req.url.host == "security.paloaltonetworks.com" and "if-none-match" not in req.headers
        return httpx.Response(200, content=_list(recent=True) if req.url.params.get("page") == "1" else b"[]", headers={"ETag": 'W/"v2"'})

    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(handler))
    before = await _events()
    async with db.session() as s:
        assert await vendor.sync_paloalto(s, "PAN-OS", timedelta(hours=6), vendor.build_index(), False) == len(advs)
        await vendor.evaluate_events(s)
    assert len(calls) == 1  # one page: fewer than 25 advisories
    assert await _events() == before
    async with db.session() as s:
        assert (await s.scalars(select(VendorAdvisoryChange))).all() == []
        got = {a.ident: (a.severity, a.cvss) for a in await s.scalars(select(VendorAdvisory).where(VendorAdvisory.source == "paloalto"))}
    assert got["CVE-2026-0331"] == ("medium", 6.6) and got["CVE-2026-0328"] == ("low", 2.7) and got["CVE-2012-6602"] == ("high", 8.4)
    await _dispatch()
    assert len(hooks) == sent


# ---------------------------------------------------------------- the story details: asked again, quietly


async def test_details_of_the_new_parser_are_quiet(monkeypatch):
    from conftest import set_news
    from test_notify import _source
    from test_rule_filters import _news

    srcrow = await _source()
    iid = await _news(srcrow, "CVE-2026-0331 PAN-OS: Sensitive Information Disclosure Vulnerability (Severity: MEDIUM)", severity="medium")
    old = story_details.parse_cve5((FIX / "cve5_pan_0331.json").read_bytes())
    old = {k: v for k, v in old.items() if k != "v"} | {"cvss": [{"score": 8.7, "temporal": None, "vector": old["cvss"][0]["vector"], "version": "4.0"}]}
    async with db.session() as s:
        await s.execute(update(NewsItem).where(NewsItem.id == iid).values(url="https://security.paloaltonetworks.com/CVE-2026-0331", systems=[], quiet_systems=[]))
        # stored by 0.1.56 (CVSS 8.7) before the catalogue knew it concerns PAN-OS; migration 0047 asks it again
        s.add(StoryDetail(item_id=iid, kind="paloalto", ident="CVE-2026-0331", status="ok", data=old, fetched_at=datetime.now(UTC), next_try_at=datetime.now(UTC) - timedelta(seconds=1)))
        await s.commit()

    async def build(db_, item, source, prev, key, budget, cvl=None):  # noqa: ANN001, ANN202
        return story_details.parse_cve5((FIX / "cve5_pan_0331.json").read_bytes())

    monkeypatch.setattr(story_details, "build", build)
    await set_news(enabled=True)
    async with db.session() as s:
        assert await story_details.enrich_round(s) == 1
    async with db.session() as s:
        i = await s.get(NewsItem, iid)
        det = await s.get(StoryDetail, iid)
    assert det.data["cvss"][0]["score"] == 6.6 and det.data["cvss"][0]["base"] == 8.7
    assert "panos" in i.systems and "panos" in i.quiet_systems  # gained quietly: shown, never a rule's delivery
    assert det.next_try_at is None or det.next_try_at > datetime.now(UTC)  # not due again at once
    assert "systems" not in (i.changes or {})  # no loud change a rule would send the story for
    assert "panos" in systems.exact(det.data)  # the details do concern PAN-OS
