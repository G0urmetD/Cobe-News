"""Advisory changes (app/advisory_changes.py): a stored advisory that comes again with other content becomes a revision –
content only (fixed versions, ranges, severity, KEV, withdrawn), never a reformat, the first store, a parser change or a
CSAF provider's first fill; the impact on the versions entered; the limits; the new notification kind that no existing
rule gets; the API."""

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import func, select, text, update

from app import advisory_changes as ch
from app import db, news, notify, story_details, vendor
from app.models import NewsItem, NewsSource, StoryDetail, VendorAdvisory, VendorAdvisoryChange, VendorAdvisoryState, VendorDelivery, VendorEvent, VendorFollow, VendorKev

HOOK = "https://n8n.corp.example/webhook/changes"
NOW = datetime.now(UTC)


@pytest.fixture(autouse=True)
def vendor_reset():
    vendor.reset()
    yield


@pytest.fixture
def hooks(monkeypatch):
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.host == "n8n.corp.example"
        calls.append(req)
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(notify, "transport", httpx.MockTransport(handler))
    return calls


def pan(ident: str = "CVE-2026-1001", affected: str = "< 11.2.4-h10", fixed: str = ">= 11.2.4-h10", **kw) -> dict:
    a = {
        "id": f"paloalto:{ident}",
        "source": "paloalto",
        "ident": ident,
        "title": "PAN-OS: Example vulnerability in the management interface",
        "summary": "Example.",
        "url": f"https://security.paloaltonetworks.com/{ident}",
        "cves": [ident],
        "cvss": 7.5,
        "severity": "high",
        "published_at": NOW - timedelta(days=90),
        "updated_at": NOW - timedelta(days=60),
        "names": ["PAN-OS", "PAN-OS 11.2"],
        "data": {"lines": [{"name": "PAN-OS 11.2", "affected": affected, "fixed": fixed}], "affected_list": [], "products": ["PAN-OS"], "solution": "Upgrade."},
    }
    return a | kw


async def _store(*advs: dict) -> int:
    async with db.session() as s:
        return await vendor.store(s, list(advs), vendor.build_index())


async def _changes(aid: str = "paloalto:CVE-2026-1001") -> list[VendorAdvisoryChange]:
    async with db.session() as s:
        return list(await s.scalars(select(VendorAdvisoryChange).where(VendorAdvisoryChange.advisory_id == aid).order_by(VendorAdvisoryChange.revision)))


async def _state(aid: str = "paloalto:CVE-2026-1001") -> VendorAdvisoryState | None:
    async with db.session() as s:
        return await s.get(VendorAdvisoryState, aid)


async def _follow(c, key: str, *versions: str, baseline: bool = True) -> None:
    r = await c.put(f"/api/vendor/follows/{key}", json={"enabled": True})
    assert r.status_code == 200, r.text
    for v in versions:
        r = await c.post(f"/api/vendor/follows/{key}/versions", json={"version": v, "label": "Rechenzentrum"})
        assert r.status_code == 200, r.text
    if baseline:  # evaluated once (as after the first round): what comes now is news
        async with db.session() as s:
            await s.execute(update(VendorFollow).where(VendorFollow.product == key).values(baseline_at=NOW))
            await s.commit()


async def _webhook_rule(c, kinds: list[str], severities: list[str] | None = None) -> None:
    chn = (await c.post("/api/admin/notify/channels", json={"name": "n8n", "type": "webhook", "url": HOOK})).json()
    r = await c.post("/api/admin/notify/rules", json={"name": "Systeme", "channels": [chn["id"]], "kinds": kinds, "severities": severities or ["critical", "high", "medium", "low", "info"]})
    assert r.status_code == 200 and r.json()["kinds"] == kinds, r.text


async def _dispatch() -> dict:
    async with db.session() as s:
        return await notify.dispatch(s)


# ---------------------------------------------------------------- facts and diff (no database needed)


def _facts(a: dict) -> dict:
    return ch.facts_of(a["source"], a["severity"], a["cvss"], a["cves"], a["data"])


def test_cosmetic_is_no_change():
    a = pan(fixed=">= 11.2.4-h10, >= 11.2.7-h3")
    b = pan(fixed=">=   11.2.7-h3,  >= 11.2.4-h10 ", summary="Another text entirely.", title="New title", updated_at=NOW)
    b["data"]["lines"][0]["name"] = "pan-os 11.2"  # case
    b["data"]["solution"] = "Upgrade now, please."  # the description's text
    assert ch.diff(_facts(a), ch.merge(_facts(a), _facts(b))) == []
    # the same set in another order
    a2 = pan(data={"lines": [{"name": "PAN-OS 11.2", "affected": "< 11.2.4-h10", "fixed": ">= 11.2.4-h10"}, {"name": "PAN-OS 11.1", "affected": "< 11.1.6", "fixed": ">= 11.1.6"}], "products": ["PAN-OS"]})
    b2 = pan(data={"lines": list(reversed(a2["data"]["lines"])), "products": ["PAN-OS"]})
    assert ch.diff(_facts(a2), _facts(b2)) == []


def test_content_changes_are_named():
    a = pan()
    b = pan(affected="< 11.2.4-h30", fixed=">= 11.2.4-h30", cvss=9.3, severity="critical", cves=["CVE-2026-1001", "CVE-2026-1002"])
    d = {x["f"]: x for x in ch.diff(_facts(a), _facts(b))}
    assert d["fixed"] == {"f": "fixed", "add": ["PAN-OS 11.2: 11.2.4-h30"], "del": ["PAN-OS 11.2: 11.2.4-h10"]}
    assert d["severity"] == {"f": "severity", "from": "high", "to": "critical", "cvss_from": 7.5, "cvss_to": 9.3}
    assert d["affected"]["add"] == ["PAN-OS 11.2: < 11.2.4-h30"] and d["cves"]["add"] == ["CVE-2026-1002"]
    text = ch.describe(list(d.values()), [], "de")
    assert "neue Fix-Version PAN-OS 11.2: 11.2.4-h30" in text and "Schwere von Hoch auf Kritisch (CVSS 7.5 → 9.3)" in text
    assert "new fixed version PAN-OS 11.2: 11.2.4-h30" in ch.describe(list(d.values()), [], "en")


def test_a_gap_of_the_source_is_no_change():
    before = _facts(pan())
    gap = _facts(pan(cvss=None, severity="info", fixed=""))  # no score, no fixed version: the source says less, not other
    merged = ch.merge(before, gap)
    assert ch.diff(before, merged) == [] and merged["cvss"] == 7.5 and merged["fixed"] == before["fixed"]
    # back again: still nothing (the gap never became the state)
    assert ch.diff(merged, ch.merge(merged, before)) == []


def test_diff_lists_are_limited():
    a = pan(data={"lines": [], "products": ["PAN-OS"]})
    b = pan(data={"lines": [{"name": f"PAN-OS 11.{i}", "affected": f"< 11.{i}.5", "fixed": f">= 11.{i}.5"} for i in range(30)], "products": ["PAN-OS"]})
    d = {x["f"]: x for x in ch.diff(_facts(a), _facts(b))}
    assert len(d["fixed"]["add"]) == ch.DIFF_ITEMS and d["fixed"]["more"] == 30 - ch.DIFF_ITEMS


def test_facts_of_every_source():
    nvd = ch.facts_of(
        "nvd",
        "high",
        8.1,
        ["CVE-2026-2001"],
        {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "versionStartIncluding": "7.0.0", "versionEndExcluding": "7.0.17"}]}]}], "cna": []},
    )
    assert nvd["affected"] == ["fortinet:fortios: >=7.0.0 <7.0.17"] and nvd["fixed"] == ["fortinet:fortios: 7.0.17"]
    cvl = ch.facts_of("cvelist", "high", 8.1, [], {"cna": [{"affectedData": [{"vendor": "Example", "product": "Gateway", "versions": [{"version": "1.0", "lessThan": "1.4.2", "status": "affected"}]}]}]})
    assert cvl["affected"] == ["Example Gateway: 1.0 <1.4.2"] and cvl["fixed"] == ["Example Gateway: 1.4.2"]
    osv = ch.facts_of("osv", "info", None, [], {"packages": [{"ecosystem": "PyPI", "name": "example", "ranges": [{"introduced": "0", "fixed": "2.1.0"}]}]})
    assert osv["fixed"] == ["PyPI/example: 2.1.0"]
    csaf = ch.facts_of("csaf", "high", 7.0, [], {"products": [{"name": "SIMATIC Example", "affected": [{"text": "< V3.1"}], "fixed": ["V3.1"]}], "rev": "1.2.0"})
    assert csaf["fixed"] == ["SIMATIC Example: V3.1"] and csaf["rev"] == "1.2.0"
    forti = ch.facts_of("fortinet", "high", 7.0, [], {"products": {"FortiOS": {"affected": ["FortiOS 7.6.0-7.6.6"]}}, "remediation": "FortiOS 8.0: Not Applicable\nFortiOS 7.6: Upgrade to 7.6.7 or above"})
    assert forti["fixed"] == ["FortiOS 7.6: 7.6.7"]


# ---------------------------------------------------------------- storing


async def test_first_store_and_cosmetic_stores_make_no_revision():
    assert await _store(pan()) == 1
    assert await _changes() == [] and await _state() is None  # nothing to compare with yet
    again = pan(summary="Reworded.", updated_at=NOW, fixed=">=  11.2.4-h10 ")
    again["data"]["solution"] = "Upgrade to a fixed version."
    assert await _store(again) == 1  # stored (it differs) – but no revision
    assert await _changes() == []
    st = await _state()
    assert st is not None and st.revision == 1 and st.changed_at is None and st.facts["v"] == ch.EXTRACT_V


async def test_content_change_is_a_revision():
    await _store(pan())
    await _store(pan(affected="< 11.2.4-h30", fixed=">= 11.2.4-h30", cvss=9.3, severity="critical", updated_at=NOW))
    [c] = await _changes()
    assert c.revision == 2 and c.source == "paloalto" and c.ident == "CVE-2026-1001" and "panos" in c.products
    assert {x["f"] for x in c.diff} == {"fixed", "severity", "affected"}
    st = await _state()
    assert st.revision == 2 and st.changed_at is not None
    # the same again: no second revision
    await _store(pan(affected="< 11.2.4-h30", fixed=">= 11.2.4-h30", cvss=9.3, severity="critical", updated_at=NOW + timedelta(hours=1)))
    assert len(await _changes()) == 1


async def test_parser_change_sets_the_facts_anew_silently(monkeypatch):
    await _store(pan())
    await _store(pan(updated_at=NOW))  # the state row exists now
    monkeypatch.setitem(ch.PARSER_V, "paloalto", ch.PARSER_V["paloalto"] + 1)
    # a new parser reads more (another fixed version): no revision, the facts as it says now
    await _store(pan(fixed=">= 11.2.4-h10, >= 11.2.7-h3", updated_at=NOW + timedelta(hours=1)))
    assert await _changes() == []
    st = await _state()
    assert st.facts["p"] == ch.PARSER_V["paloalto"] and "PAN-OS 11.2: 11.2.7-h3" in st.facts["fixed"]
    # from then on a change is one again
    await _store(pan(fixed=">= 11.2.4-h10, >= 11.2.7-h3, >= 11.2.10", updated_at=NOW + timedelta(hours=2)))
    [c] = await _changes()
    assert c.diff[0] == {"f": "fixed", "add": ["PAN-OS 11.2: 11.2.10"], "del": []}


async def test_another_extractor_recomputes_instead_of_reporting(monkeypatch):
    await _store(pan())
    await _store(pan(updated_at=NOW))
    async with db.session() as s:  # a state of an older extractor (that read nothing at all)
        await s.execute(update(VendorAdvisoryState).values(facts={"v": 0, "p": 1, "sev": "low", "cvss": None, "fixed": [], "affected": [], "products": [], "cves": []}))
        await s.commit()
    await _store(pan(updated_at=NOW + timedelta(hours=1)))
    assert await _changes() == []
    assert (await _state()).facts["v"] == ch.EXTRACT_V


async def test_csaf_first_fill_is_silent():
    doc = {
        "id": "csaf:SSA-100001",
        "source": "csaf",
        "ident": "SSA-100001",
        "title": "Example",
        "summary": "",
        "url": "https://cert-portal.siemens.com/productcert/html/ssa-100001.html",
        "cves": ["CVE-2026-3001"],
        "cvss": 7.0,
        "severity": "high",
        "published_at": NOW - timedelta(days=200),
        "updated_at": NOW - timedelta(days=200),
        "data": {"products": [{"vendor": "Siemens", "name": "SIMATIC Example", "cpe": "", "affected": [{"text": "< V3.1"}], "fixed": ["V3.1"], "not_affected": []}], "publisher": "Siemens ProductCERT (CSAF)", "provider": "siemens"},
    }
    await _store(doc)
    newer = json.loads(json.dumps(doc, default=str)) | {"published_at": doc["published_at"], "updated_at": NOW}
    newer["data"]["products"][0]["fixed"] = ["V3.2"]
    newer["data"]["initial"] = True  # the provider's first fill brings the newer document
    await _store(newer)
    assert await _changes("csaf:SSA-100001") == []


async def test_a_reformatted_source_makes_no_revisions(monkeypatch):
    monkeypatch.setattr(ch, "MASS_MIN", 3)
    advs = [pan(f"CVE-2026-11{i:02d}") for i in range(4)]
    await _store(*advs)
    # the source now writes every range differently (another severity text, other fixed versions): all at once
    await _store(*[a | {"severity": "critical", "cvss": 9.0, "updated_at": NOW} for a in advs])
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(VendorAdvisoryChange)) == 0
    # one of them alone later: a revision as usual
    await _store(advs[0] | {"severity": "medium", "cvss": 5.0, "updated_at": NOW + timedelta(hours=1)})
    assert len(await _changes("paloalto:CVE-2026-1100")) == 1


async def test_revisions_are_limited_in_number_and_age(monkeypatch):
    monkeypatch.setattr(ch, "PER_ADVISORY", 3)
    await _store(pan())
    for i in range(5):
        await _store(pan(fixed=f">= 11.2.4-h{11 + i}", affected=f"< 11.2.4-h{11 + i}", updated_at=NOW + timedelta(hours=i)))
    got = await _changes()
    assert [c.revision for c in got] == [4, 5, 6] and (await _state()).revision == 6
    async with db.session() as s:
        await s.execute(update(VendorAdvisoryChange).where(VendorAdvisoryChange.revision == 4).values(at=NOW - ch.KEEP - timedelta(days=1)))
        await s.commit()
        assert await ch.prune(s) == 1
    assert [c.revision for c in await _changes()] == [5, 6]


async def test_stored_before_the_update(admin_client):
    """Advisories from before 0.1.32 have no state row: the stored record is the state – a reformat is no change, the
    first content change already a revision."""
    await _store(pan())
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(VendorAdvisoryState)) == 0
    await _store(pan(summary="New words.", updated_at=NOW))
    assert await _changes() == []
    await _store(pan(fixed=">= 11.2.4-h12", affected="< 11.2.4-h12", updated_at=NOW + timedelta(hours=1)))
    assert [c.revision for c in await _changes()] == [2]


async def test_migration_on_existing_data():
    """0010 on a database at 0009 with advisories and events: they stay; the tables come; down again removes only what
    0010 brought (the change events with them)."""
    from alembic import command
    from sqlalchemy import inspect

    await _store(pan())
    await _store(pan(fixed=">= 11.2.4-h12", affected="< 11.2.4-h12", updated_at=NOW))
    async with db.session() as s:
        s.add(VendorEvent(key="change:panos:x:2", kind="change", product="panos", severity="high", data={}))
        s.add(VendorEvent(key="vuln:panos:*:x", kind="vuln", product="panos", severity="high", data={}))
        await s.commit()

    def down(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "0009")
        return set(inspect(conn).get_table_names())

    async with db.engine().begin() as conn:
        tables = await conn.run_sync(down)
    assert "vendor_advisory_changes" not in tables and "vendor_advisory_state" not in tables
    async with db.engine().connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM vendor_advisories")) == 1
        assert list(await conn.scalars(text("SELECT kind FROM vendor_events"))) == ["vuln"]
    await db.migrate()
    assert await db.revision() == db.head()
    async with db.engine().connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM vendor_advisory_state")) == 0
    # the existing advisory: a reformat stays silent, a content change is a revision
    await _store(pan(fixed=">=  11.2.4-h12", affected="< 11.2.4-h12", updated_at=NOW + timedelta(hours=1), summary="x"))
    assert await _changes() == []
    await _store(pan(fixed=">= 11.2.4-h14", affected="< 11.2.4-h14", updated_at=NOW + timedelta(hours=2)))
    assert [c.revision for c in await _changes()] == [2]


# ---------------------------------------------------------------- what it means for the versions entered, events


async def test_impact_on_a_version_entered(admin_client, reader_client):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _store(pan())  # fixed in h10: 11.2.4-h23 is not affected
    await _store(pan(affected="< 11.2.4-h30", fixed=">= 11.2.4-h30", updated_at=NOW))
    [c] = await _changes()
    [imp] = c.impact
    assert imp["product"] == "panos" and imp["version"] == "11.2.4-h23" and imp["from"] == "not_affected" and imp["to"] == "affected" and imp["fixed_to"] == "11.2.4-h30"
    async with db.session() as s:
        [ev] = list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "change")))
    assert ev.product == "panos" and ev.severity == "high" and not ev.baseline and ev.data["revision"] == 2 and ev.data["impact"] == [imp]
    lines = ch.describe(ev.data["diff"], ev.data["impact"], "de")
    assert lines[0] == "PAN-OS (Firewalls) 11.2.4-h23: jetzt betroffen (vorher nicht betroffen) – Fix 11.2.4-h30"
    # the drawer: the finding is marked, the product's changes listed, the overview card says so
    d = (await reader_client.get("/api/vendor/products/panos")).json()
    f = next(x for x in d["findings"] if x["id"] == "paloalto:CVE-2026-1001")
    assert f["changed"]["revision"] == 2 and f["changed"]["impact"][0]["to"] == "affected"
    got = (await reader_client.get("/api/vendor/products/panos/changes")).json()["changes"]
    assert [x["revision"] for x in got] == [2] and got[0]["impact"] == [imp]
    row = next(x for x in (await reader_client.get("/api/vendor/overview")).json()["items"] if x["product"]["key"] == "panos")
    assert row["changed"]["count"] == 1 and row["changed"]["impact"] is True


async def test_no_event_where_the_versions_are_not_concerned(admin_client):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _store(pan())
    await _store(pan(fixed=">= 11.2.4-h11", affected="< 11.2.4-h11", updated_at=NOW))  # still not affected
    assert len(await _changes()) == 1  # the history has it …
    async with db.session() as s:
        assert list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "change"))) == []  # … no event


async def test_new_follow_gets_silent_change_events(admin_client):
    await _follow(admin_client, "panos", baseline=False)  # not evaluated yet
    await _store(pan())
    await _store(pan(cvss=9.3, severity="critical", updated_at=NOW))
    async with db.session() as s:
        [ev] = list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "change")))
    assert ev.baseline


async def test_withdrawn_and_kev(admin_client):
    await _follow(admin_client, "panos")
    await _store(pan(), pan("CVE-2026-1002"))
    async with db.session() as s:
        assert await vendor._kev_changes(s, [{"cve": "CVE-2026-1001", "date_added": "2026-10-29", "ransomware": True}]) == 1
        await s.commit()
    [k] = await _changes()
    assert k.diff == [{"f": "kev", "cve": "CVE-2026-1001", "added": "2026-10-29", "ransomware": True}] and k.revision == 2
    async with db.session() as s:
        await vendor.drop_advisories(s, ["paloalto:CVE-2026-1001"])
        await vendor.drop_advisories(s, ["paloalto:CVE-2026-1002"], withdrawn=False)  # only no usable data any more
        assert await s.get(VendorAdvisory, "paloalto:CVE-2026-1001") is None
    assert [c.diff for c in await _changes()][-1] == [{"f": "withdrawn"}]  # the history outlives the record
    assert await _changes("paloalto:CVE-2026-1002") == []
    async with db.session() as s:
        evs = list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "change").order_by(VendorEvent.n)))
    assert [e.data["diff"][0]["f"] for e in evs] == ["kev", "withdrawn"]


async def test_kev_sync_adds_a_revision_but_not_on_the_first_fetch(monkeypatch):
    bodies = [
        {"vulnerabilities": [{"cveID": "CVE-2026-1001", "dateAdded": "2026-10-01"}]},
        {"vulnerabilities": [{"cveID": "CVE-2026-1001", "dateAdded": "2026-10-01"}, {"cveID": "CVE-2026-1002", "dateAdded": "2026-10-29"}]},
    ]

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=bodies.pop(0) if len(bodies) > 1 else bodies[0])

    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(handler))
    monkeypatch.setitem(vendor.GAPS, "www.cisa.gov", 0.0)
    await _store(pan(), pan("CVE-2026-1002"))
    async with db.session() as s:
        await vendor.sync_kev(s, timedelta(hours=1), True)
        assert await s.scalar(select(func.count()).select_from(VendorKev)) == 1
    assert await _changes() == []  # the first fetch: the whole catalogue, no news
    async with db.session() as s:
        await vendor.sync_kev(s, timedelta(hours=1), True)
    assert await _changes() == []
    [k] = await _changes("paloalto:CVE-2026-1002")
    assert k.diff[0]["f"] == "kev" and k.diff[0]["cve"] == "CVE-2026-1002"


# ---------------------------------------------------------------- notifications


async def test_existing_rules_do_not_get_the_new_kind(admin_client, hooks):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _webhook_rule(admin_client, ["news", "vendor_vuln", "vendor_version"])  # a rule from before
    await _store(pan())
    await _store(pan(affected="< 11.2.4-h30", fixed=">= 11.2.4-h30", updated_at=NOW))
    await _dispatch()
    assert hooks == []


async def test_rule_with_vendor_change_sends_once(admin_client, hooks):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _webhook_rule(admin_client, ["vendor_change"])
    await _store(pan())
    await _store(pan(affected="< 11.2.4-h30", fixed=">= 11.2.4-h30", title="PAN-OS: <b>Example</b> & more", updated_at=NOW))
    await _dispatch()
    await _dispatch()
    assert len(hooks) == 1
    [story] = json.loads(hooks[0].content)["stories"]
    assert story["kind"] == "vendor.change" and story["title"].startswith("Advisory geändert: PAN-OS (Firewalls) – CVE-2026-1001 (Revision 2)")
    assert story["summary"].startswith("Revision 2: PAN-OS (Firewalls) 11.2.4-h23: jetzt betroffen (vorher nicht betroffen) – Fix 11.2.4-h30")
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(VendorDelivery)) == 1
        ev = await s.scalar(select(VendorEvent).where(VendorEvent.kind == "change"))
    # the channels escape the feed's text as they do a story's
    s_ = notify.vendor_story(ev, "de")
    s_.summary = s_.summary.split("\n")[-1]  # the advisory's own title (with markup) – what the card's short description shows
    assert "<b>" in s_.summary
    assert "<b>" not in json.dumps(notify.render_slack("Systeme", [s_], 1, "de")) and "&lt;b&gt;" in json.dumps(notify.render_slack("Systeme", [s_], 1, "de"))
    assert "<b>Example" not in notify.render_telegram("Systeme", [s_], 1, "de")
    body = notify.render_teams("Systeme", [s_], 1, "de")["attachments"][0]["content"]["body"]
    assert any("\\<b\\>" in i.get("text", "") for c in body if c.get("type") == "Container" for i in c["items"])
    assert "Revision 2" in notify.vendor_story(ev, "en").summary and notify.vendor_story(ev, "en").title.startswith("Advisory changed")


async def test_rule_severities_filter_change_events(admin_client, hooks):
    await _follow(admin_client, "panos")  # no versions: every change of its advisories
    await _webhook_rule(admin_client, ["vendor_change"], ["critical"])
    await _store(pan(), pan("CVE-2026-1002", cvss=9.8, severity="critical"))
    await _store(pan(cves=["CVE-2026-1001", "CVE-2026-1003"], updated_at=NOW), pan("CVE-2026-1002", cvss=9.8, severity="critical", fixed=">= 11.2.4-h12", updated_at=NOW))
    await _dispatch()
    assert len(hooks) == 1 and "CVE-2026-1002" in json.loads(hooks[0].content)["stories"][0]["title"]


async def test_rule_api_accepts_the_new_kind(admin_client):
    await _webhook_rule(admin_client, ["vendor_vuln", "vendor_change"])
    r = await admin_client.get("/api/admin/notify/rules")
    assert r.json()[0]["kinds"] == ["vendor_vuln", "vendor_change"]


# ---------------------------------------------------------------- stories


async def test_story_shows_the_revisions_of_its_advisory(reader_client):
    await _store(pan())
    await _store(pan(cvss=9.3, severity="critical", updated_at=NOW))
    assert story_details.advisory_ids("paloalto", "CVE-2026-1001", []) == ["paloalto:CVE-2026-1001"]
    assert story_details.advisory_ids("siemens", "SSA-100001", []) == ["csaf:SSA-100001"]
    assert story_details.advisory_ids("kev", "CVE-2026-1", ["cve-2026-1"]) == ["nvd:CVE-2026-1"]
    async with db.session() as s:
        src = await s.scalar(select(NewsSource).limit(1))
        url = "https://security.paloaltonetworks.com/CVE-2026-1001"
        item = NewsItem(source_id=src.id, url=url, url_key="pan-1001", title="PAN-OS advisory", title_key="pan-os advisory", summary="", published_at=NOW, cves=["CVE-2026-1001"], seq=await news.next_seq(s))
        s.add(item)
        await s.flush()
        s.add(StoryDetail(item_id=item.id, kind="paloalto", ident="CVE-2026-1001", status="ok", data={"products": []}))
        await s.commit()
        sid = item.id
    d = (await reader_client.get(f"/api/news/{sid}")).json()
    assert [c["revision"] for c in d["changes"]] == [2] and d["changes"][0]["diff"][0]["f"] == "severity"
