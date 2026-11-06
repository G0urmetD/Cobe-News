# ruff: noqa: F811 - the fixtures of test_vendor_service are imported and used by name
"""Regression tests of the 0.1.11 review (Vendor News): one notification per CVE also when NVD reports it before the
vendor, never a false "not affected" for a short version, the follow switch keeps note and tags, the drawer pages
through every finding, the background round stays cheap with many events, NVD windows without gaps, one 429 pauses
NVD for the whole round, "now exploited" is notified, NVD rejections and removed CPEs are applied."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from app import db, vendor
from app.models import VendorAdvisory, VendorAdvisoryProduct, VendorEvent, VendorFetch, VendorFollow
from test_vendor_service import _follow, _fresh_pan, _round, sites, vendor_reset  # noqa: F401 - fixtures


def _nvd(cve: str, *, crit="cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", start="11.2.0", end="11.2.4-h30", age_h=2, kev=None, status="Analyzed") -> dict:
    now = datetime.now(UTC)
    return {
        "id": f"nvd:{cve}",
        "source": "nvd",
        "ident": cve,
        "title": f"{cve} example",
        "summary": "x",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "cves": [cve],
        "cvss": 7.5,
        "severity": "high",
        "exploited": bool(kev),
        "published_at": now - timedelta(hours=age_h),
        "updated_at": now - timedelta(hours=age_h),
        "data": {
            "configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": crit, "versionStartIncluding": start, "versionEndExcluding": end}]}]}],
            "cna": [],
            "desc": "x",
            "status": status,
            "kev": kev,
        },
    }


# ---------------------------------------------------------------- H4: the follow switch keeps note and tags


async def test_follow_switch_keeps_note_and_tags(admin_client):
    await admin_client.put("/api/vendor/follows/gitlab", json={"enabled": True, "note": "DMZ", "tags": ["prod"]})
    assert (await admin_client.put("/api/vendor/follows/gitlab", json={"enabled": False})).status_code == 200  # the catalogue switch
    async with db.session() as s:
        f = await s.scalar(select(VendorFollow).where(VendorFollow.product == "gitlab"))
    assert (f.enabled, f.note, f.tags) == (False, "DMZ", ["prod"])
    await admin_client.put("/api/vendor/follows/gitlab", json={"note": ""})  # sent: changed
    async with db.session() as s:
        f = await s.scalar(select(VendorFollow).where(VendorFollow.product == "gitlab").execution_options(populate_existing=True))
    assert (f.enabled, f.note, f.tags) == (False, "", ["prod"])


# ---------------------------------------------------------------- drawer: every finding, page by page


async def test_product_detail_pages_through_every_finding(admin_client, reader_client):
    await _follow(admin_client, "panos", "11.2.4-h23")
    advs = [_nvd(f"CVE-2026-{20000 + i}", age_h=i + 1) for i in range(230)]
    async with db.session() as s:
        await vendor.store(s, advs, vendor.build_index())
    seen: list[str] = []
    offset = 0
    while True:
        r = await reader_client.get(f"/api/vendor/products/panos?offset={offset}&limit=100")
        d = r.json()
        assert r.status_code == 200 and d["shown"] == 230 and d["by_status"]["affected"] == 230
        assert (d["news"] == []) == (offset > 0) or offset == 0
        seen += [f["id"] for f in d["findings"]]
        offset += 100
        if offset >= d["shown"]:
            break
    assert len(seen) == len(set(seen)) == 230  # no silent cap, no duplicates


# ---------------------------------------------------------------- H2: short versions never "not affected" by mistake


def test_short_version_is_never_falsely_not_affected():
    from app import vendor_catalog as catalog
    from app.vendor_match import evaluate

    forti = catalog.product("fortios")
    data = {"products": {"FortiOS": {"affected": ["FortiOS >=7.4.5|<=7.4.8"], "not_affected": []}}, "remediation": ""}
    assert evaluate(forti, "fortinet", data, "7.4").status == "possible"  # 7.4.6 is affected, 7.4.2 is not
    assert evaluate(forti, "fortinet", data, "7.4").reason == "short_version"
    assert evaluate(forti, "fortinet", data, "7.4.6").status == "affected"
    assert evaluate(forti, "fortinet", data, "7.4.9").status == "not_affected"
    nginx = catalog.product("nginx")
    nvd = {"configs": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "versionStartIncluding": "1.25.3", "versionEndExcluding": "1.27.2"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "versionStartIncluding": "1.20.0", "versionEndExcluding": "1.24.0"}]}]}], "cna": []}  # fmt: skip
    got = evaluate(nginx, "nvd", nvd, "1.25")
    assert (got.status, got.reason, got.fixed) == ("possible", "short_version", "1.27.2")
    assert evaluate(nginx, "nvd", nvd, "1.21").status == "affected"  # every 1.21.x lies in the range: decided
    assert evaluate(nginx, "nvd", nvd, "1.24").status == "not_affected"  # no 1.24.x is in a range
    assert evaluate(nginx, "nvd", nvd, "1.28").status == "not_affected"
    # a complete version of a product with two-part versions (PostgreSQL 16.4) is decided as it is
    pg = catalog.product("postgresql")
    rng = {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*", "versionStartIncluding": "16.0", "versionEndIncluding": "16.4"}]}]}], "cna": []}  # fmt: skip
    assert evaluate(pg, "nvd", rng, "16.4").status == "affected"


async def test_short_version_is_flagged_in_the_form(admin_client):
    r = await admin_client.get("/api/vendor/validate", params={"product": "fortios", "version": "7.4"})
    assert r.json()["ok"] is True and r.json()["short"] is True
    r = await admin_client.get("/api/vendor/validate", params={"product": "fortios", "version": "7.4.8"})
    assert r.json()["short"] is False
    r = await admin_client.get("/api/vendor/validate", params={"product": "postgresql", "version": "16.4"})
    assert r.json()["short"] is False


async def _events(s) -> list[VendorEvent]:
    return list(await s.scalars(select(VendorEvent).order_by(VendorEvent.created_at)))


# ---------------------------------------------------------------- H1: one notification per CVE, NVD first, vendor later


async def test_nvd_then_vendor_advisory_notifies_once(admin_client, sites):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()  # baseline
    async with db.session() as s:
        await vendor.store(s, [_nvd("CVE-2026-7777")], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1  # the NVD record
    async with db.session() as s:
        # the vendor's advisory of the same CVE a round later: the same vulnerability, already notified
        await vendor.store(s, [_fresh_pan("CVE-2026-7777", "< 11.2.4-h30", ">= 11.2.4-h30")], vendor.build_index())
        assert await vendor.evaluate_events(s) == 0
        evs = [e for e in await _events(s) if not e.baseline]
    assert len(evs) == 1 and evs[0].scope == "vuln:panos:11.2.4-h23"


# ---------------------------------------------------------------- H3: an idle round stays cheap, events do not pile up


async def test_idle_evaluation_reads_nothing_and_old_versions_are_pruned(admin_client, sites, monkeypatch):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    async with db.session() as s:
        await vendor.store(s, [_nvd("CVE-2026-7001"), _nvd("CVE-2026-7002")], vendor.build_index())
        assert await vendor.evaluate_events(s) == 2
    calls = []
    real = vendor._evaluate_product

    async def counting(*a, **kw):  # noqa: ANN002, ANN003
        calls.append(a[1].product)
        return await real(*a, **kw)

    monkeypatch.setattr(vendor, "_evaluate_product", counting)
    async with db.session() as s:
        assert await vendor.evaluate_events(s) == 0
    assert calls == []  # nothing changed: no product evaluated, no event read
    # the version changed: a new silent baseline – and the old version's events go
    vid = (await admin_client.get("/api/vendor/products/panos")).json()["versions"][0]["id"]
    assert (await admin_client.put(f"/api/vendor/versions/{vid}", json={"version": "11.2.4-h25"})).status_code == 200
    async with db.session() as s:
        assert await vendor.evaluate_events(s, full=True) == 0
        scopes = {e.scope for e in await _events(s) if e.kind == "vuln"}
    assert scopes == {"vuln:panos:11.2.4-h25"}
    # not followed any more: its events go
    assert (await admin_client.delete("/api/vendor/follows/panos")).status_code == 200
    async with db.session() as s:
        await vendor.evaluate_events(s, full=True)
        assert [e for e in await _events(s) if e.product == "panos"] == []


async def test_enrich_round_does_not_read_every_detail(admin_client):
    """The details round looks only at stories without details or due again – by the index, not every row with JSON."""
    from sqlalchemy import event

    from app import news, story_details
    from app.models import NewsItem, NewsSource, StoryDetail

    async with db.session() as s:
        await news.save_config(s, {**news.DEFAULTS, "enabled": True, "details": True})
        src = await s.scalar(select(NewsSource).limit(1))
        now = datetime.now(UTC)
        for i in range(30):
            it = NewsItem(source_id=src.id, url=f"https://example.org/{i}", url_key=f"k{i}", title=f"Story {i}", title_key=f"t{i}", summary="x", published_at=now - timedelta(minutes=i), fetched_at=now, severity="info", reasons=[], cves=[], also_in=[], search=f"story {i}", seq=i)
            s.add(it)
            await s.flush()
            s.add(StoryDetail(item_id=it.id, kind="none", status="none", fetched_at=now, next_try_at=None))
        await s.commit()
    seen: list[str] = []
    eng = db._engine.sync_engine
    listener = lambda *a: seen.append(a[2])  # noqa: E731
    event.listen(eng, "before_cursor_execute", listener)
    try:
        async with db.session() as s:
            assert await story_details.enrich_round(s) == 0
    finally:
        event.remove(eng, "before_cursor_execute", listener)
    assert not any("story_details.data" in q for q in seen)  # no detail JSON read when nothing is due


# ---------------------------------------------------------------- M1: custom products get what the story details store


async def test_custom_product_gets_a_record_stored_by_story_details(admin_client):
    r = await admin_client.post("/api/vendor/custom", json={"cpe": "a:acme:widget", "label": "Acme Widget"})
    key = r.json()["key"]
    adv = _nvd("CVE-2026-5555", crit="cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", start="1.0", end="1.5")
    async with db.session() as s:
        await vendor.store(s, [adv], await vendor.current_index(s))  # what story_details does now
        links = list(await s.scalars(select(VendorAdvisoryProduct).where(VendorAdvisoryProduct.product == key)))
    assert [x.advisory_id for x in links] == ["nvd:CVE-2026-5555"]


# ---------------------------------------------------------------- M2: an NVD window with more than 2000 changes


def _nvd_pages(total: int, seen: list[dict], extra: dict | None = None):
    import httpx

    def handler(req: httpx.Request) -> httpx.Response:
        p = dict(req.url.params)
        seen.append(p)
        if req.url.host != "services.nvd.nist.gov":
            return httpx.Response(404)
        start = int(p.get("startIndex", 0))
        n = max(0, min(500, total - start))
        vulns = [
            {"cve": {"id": f"CVE-2026-{100000 + start + i}", "published": "2026-01-01T00:00:00.000", "lastModified": "2026-10-01T00:00:00.000", "vulnStatus": "Modified", "descriptions": [{"lang": "en", "value": "x"}], "metrics": {}, "configurations": []}}
            for i in range(n)
        ]
        return httpx.Response(200, json={"totalResults": total, "startIndex": start, "resultsPerPage": n, "vulnerabilities": vulns + (extra or {}).get(start, [])})

    return httpx.MockTransport(handler)


async def test_incremental_window_over_2000_fetches_every_page(admin_client, monkeypatch):
    seen: list[dict] = []
    monkeypatch.setattr(vendor, "transport", _nvd_pages(2600, seen))
    async with db.session() as s:
        st = await vendor._state(s, "nvd:a:acme:widget")
        st.cursor = (datetime.now(UTC) - timedelta(hours=6)).isoformat()  # a run 6 hours ago
        st.full_at = datetime.now(UTC) - timedelta(days=1)
        await s.commit()
        await vendor.sync_nvd_cpe(s, "a:acme:widget", timedelta(hours=6), vendor.build_index(), "", True)
        stored = await s.scalar(select(func.count()).select_from(VendorAdvisory))
    starts = sorted(int(p.get("startIndex", 0)) for p in seen)
    assert starts == [0, 500, 1000, 1500, 2000, 2500] and all("lastModStartDate" in p for p in seen)
    assert stored == 2600  # none thrown away, none left out


# ---------------------------------------------------------------- M3: one 429 pauses NVD for everybody


async def test_nvd_429_stops_the_round_and_pauses_the_host(admin_client, sites):
    sites.nvd_status = 429
    for key in ("gitlab", "nginx", "openssl", "php", "postgresql", "jenkins", "tomcat"):
        await _follow(admin_client, key)
    await vendor.run_round(force=True)
    assert len(sites.to("services.nvd.nist.gov")) == 1  # the first refusal – then no further request into the pause
    assert vendor.blocked_for("services.nvd.nist.gov") > 0
    r = await admin_client.get("/api/vendor/cpe-search", params={"q": "widget"})
    assert r.json()["error"] == "rate_limited" and len(sites.to("services.nvd.nist.gov")) == 1


# ---------------------------------------------------------------- M4: "now actively exploited"


async def test_kev_added_later_is_notified_once(admin_client, sites):
    from app.models import VendorKev

    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    async with db.session() as s:
        await vendor.store(s, [_nvd("CVE-2026-6666")], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1
        s.add(VendorKev(cve="CVE-2026-6666", vendor="Palo Alto", product="PAN-OS", name="x", date_added=datetime.now(UTC).date().isoformat(), due="", ransomware=True))
        await s.commit()
        vendor.bump()
        assert await vendor.evaluate_events(s) == 1  # now exploited
        assert await vendor.evaluate_events(s, full=True) == 0  # once
        ev = next(e for e in await _events(s) if e.key.startswith("exploited:"))
    from app import notify

    story = notify.vendor_story(ev, "de")
    assert story.title.startswith("Jetzt aktiv ausgenutzt: PAN-OS") and "Ransomware" in story.summary and ev.severity in ("high", "critical")


# ---------------------------------------------------------------- M10: rejected records and CPEs NVD removed


async def test_rejected_nvd_record_is_removed(admin_client, monkeypatch):
    seen: list[dict] = []
    rejected = {0: [{"cve": {"id": "CVE-2026-4242", "published": "2026-01-01T00:00:00.000", "lastModified": "2026-10-20T00:00:00.000", "vulnStatus": "Rejected", "descriptions": [], "metrics": {}, "configurations": []}}]}
    await _follow(admin_client, "panos", "11.2.4-h23")
    async with db.session() as s:
        await vendor.store(s, [_nvd("CVE-2026-4242")], vendor.build_index())
        st = await vendor._state(s, "nvd:o:paloaltonetworks:pan-os")
        st.cursor, st.full_at = (datetime.now(UTC) - timedelta(hours=6)).isoformat(), datetime.now(UTC) - timedelta(days=1)
        await s.commit()
    monkeypatch.setattr(vendor, "transport", _nvd_pages(0, seen, rejected))
    async with db.session() as s:
        await vendor.sync_nvd_cpe(s, "o:paloaltonetworks:pan-os", timedelta(hours=6), vendor.build_index(), "", True)
        assert await s.get(VendorAdvisory, "nvd:CVE-2026-4242") is None
    assert (await admin_client.get("/api/vendor/products/panos")).json()["shown"] == 0


async def test_weekly_full_fetch_unlinks_what_nvd_no_longer_lists(admin_client, monkeypatch):
    seen: list[dict] = []
    await _follow(admin_client, "panos", "11.2.4-h23")
    async with db.session() as s:
        await vendor.store(s, [_nvd("CVE-2026-100001"), _nvd("CVE-2026-4343")], vendor.build_index())
        st = await vendor._state(s, "nvd:o:paloaltonetworks:pan-os")
        st.cursor, st.full_at = (datetime.now(UTC) - timedelta(hours=6)).isoformat(), datetime.now(UTC) - timedelta(days=8)
        await s.commit()
    monkeypatch.setattr(vendor, "transport", _nvd_pages(40, seen))  # NVD lists CVE-2026-100000…100039, not 4343 any more
    async with db.session() as s:
        await vendor.sync_nvd_cpe(s, "o:paloaltonetworks:pan-os", timedelta(hours=6), vendor.build_index(), "", True)
        assert "lastModStartDate" not in seen[0]  # the weekly full fetch
        links = set(await s.scalars(select(VendorAdvisoryProduct.advisory_id).where(VendorAdvisoryProduct.product == "panos")))
    assert "nvd:CVE-2026-4343" not in links


# ---------------------------------------------------------------- LOW


def test_findings_newest_first_within_ties():
    from app import vendor_catalog as catalog
    from app.models import VendorVersion

    p = catalog.product("panos")
    advs = []
    for i, age in enumerate((300, 1)):
        a = _nvd(f"CVE-2026-{1000 + i}", age_h=age)
        advs.append(VendorAdvisory(**{k: a[k] for k in ("id", "source", "ident", "title", "summary", "url", "cves", "cvss", "severity", "exploited", "published_at", "updated_at", "data")}))
    out = vendor.findings(p, advs, [VendorVersion(version="11.2.4-h23", label="")], {}, set())
    assert [f["ident"] for f in out] == ["CVE-2026-1001", "CVE-2026-1000"]


def test_version_parser_corner_cases():
    from app.vendor_versions import V, parse

    assert V((7, 4), "7.4").startswith(V((7, 4, 0), "7.4.0"))
    assert not V((11, 20), "").startswith(V((11, 2), ""))
    assert parse("generic", "1:2.3") is None  # a Debian epoch, not 1.2.3
    assert parse("cisco", "7.0(3)I7(9)") is None and parse("cisco", "9.18(4)22").key == (9, 18, 4, 22)
    assert parse("generic", "17.4.1-ee") == parse("generic", "17.4.1") and parse("generic", "16.11.10-ce.0") == parse("generic", "16.11.10")


async def test_a_source_that_keeps_failing_does_not_hold_back_the_events(admin_client):
    from app.models import VendorFetch

    p = vendor.product_of(VendorFollow(product="veeam-backup-and-replication", custom=None))
    async with db.session() as s:
        for k in vendor.fetch_keys(p):
            s.add(VendorFetch(key=k, failures=0, items=0, last_ok_at=datetime.now(UTC)))
        await s.commit()
        assert vendor._ready(p, await vendor._answered(s))
        st = await s.get(VendorFetch, "veeam:feed")
        st.last_ok_at, st.failures = None, 1
        await s.commit()
        assert not vendor._ready(p, await vendor._answered(s))  # not answered yet
        st.failures = 3
        await s.commit()
        assert vendor._ready(p, await vendor._answered(s))  # refused again and again: the other sources' events go on


async def test_catalogue_refresh_works_while_vendor_news_is_off(admin_client, sites):
    assert (await admin_client.put("/api/admin/vendor", json={"enabled": False})).status_code == 200
    out = await vendor.run_round(only="catalog")
    assert out == {"catalog": 1} and len(sites.to("endoflife.date")) == 1


async def test_notification_uses_the_readable_title(admin_client, sites):
    from app import notify

    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    a = _nvd("CVE-2026-8888")
    desc = (
        "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature "
        "configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall."
    )
    a["summary"] = a["data"]["desc"] = desc
    a["title"], a["data"]["cwe"] = desc[:180] + " …", ["CWE-77"]  # how NVD records are stored: the description's start
    async with db.session() as s:
        await vendor.store(s, [a], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1
        ev = next(e for e in await _events(s) if not e.baseline)
    title = notify.vendor_story(ev, "en").title
    assert title.endswith("CVE-2026-8888 – Command Injection in the GlobalProtect feature")


def test_veeam_catalogue_uses_the_cpes_nvd_has():
    from app import vendor_catalog as catalog

    assert catalog.product("veeam-one")["cpes"] == ["a:veeam:one", "a:veeam:one_reporter"]
    linux = catalog.product("veeam-agent-linux")
    assert linux["cpes"] == [] and linux["hint"] == "nocpe" and linux["adv"] == "veeam"
    assert "a:veeam:backup_and_replication" in catalog.product("veeam-backup-and-replication")["cpes"]
    for key, cpe in (("veeam-backup-azure", "a:veeam:backup"), ("veeam-backup-gcp", "a:veeam:veeam_backup_for_google_cloud"), ("veeam-management-pack", "a:veeam:management_pack")):
        assert catalog.product(key)["cpes"] == [cpe]
# ---------------------------------------------------------------- the sidebar badge without the overview's payload


async def test_badge_counts_affected_products_like_the_overview(admin_client, reader_client):
    assert (await reader_client.get("/api/vendor/badge")).json() == {"affected": 0, "exploited": False, "enabled": True}
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _follow(admin_client, "gitlab")  # followed, nothing stored for it
    async with db.session() as s:
        await vendor.store(s, [_nvd("CVE-2026-31000"), _nvd("CVE-2026-31001", kev={"added": "2026-10-01", "due": "2026-10-22", "ransomware": False})], vendor.build_index())
    b = (await reader_client.get("/api/vendor/badge")).json()
    items = (await reader_client.get("/api/vendor/overview")).json()["items"]
    assert b["affected"] == sum(1 for i in items if i["counts"]["affected"] > 0) == 1
    assert b["exploited"] is any(i["counts"]["exploited_affected"] > 0 for i in items) is True


async def test_switching_a_follow_off_and_on_does_not_notify_again(admin_client, sites):
    """Bug hunt 0.1.16 H3: switched off, its events pruned, switched on again – what is found then is a baseline for
    its versions, too: the CVE notified before is not sent a second time."""
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()  # baseline
    async with db.session() as s:
        await vendor.store(s, [_nvd("CVE-2026-7101")], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1  # notified once
    assert (await admin_client.put("/api/vendor/follows/panos", json={"enabled": False})).status_code == 200
    async with db.session() as s:
        await vendor.evaluate_events(s, full=True)  # the full pass prunes the events of the switched-off product
        assert not list(await s.scalars(select(VendorEvent).where(VendorEvent.product == "panos")))
    assert (await admin_client.put("/api/vendor/follows/panos", json={"enabled": True})).status_code == 200
    async with db.session() as s:
        assert await vendor.evaluate_events(s) == 0
        assert await vendor.evaluate_events(s, full=True) == 0
        await vendor.store(s, [_nvd("CVE-2026-7102")], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1  # after the new baseline, a new finding is news again


# ---------------------------------------------------------------- 0.1.16 reviews: NUL and other control characters


def _nvd_rec(cid: str, desc: str) -> dict:
    return {"cve": {"id": cid, "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": desc}], "published": "2026-10-01T00:00:00.000", "lastModified": "2026-10-02T00:00:00.000"}}


async def test_nul_in_an_nvd_record_is_stripped_and_the_batch_stored():
    """Security review M1 / bug hunt M4: PostgreSQL refuses U+0000 – one such record rolled back the whole batch on
    every run. The parsers drop it (and the other C0 controls except tab and line breaks)."""
    import json

    from app import vendor_sources as src

    body = json.dumps({"totalResults": 2, "vulnerabilities": [_nvd_rec("CVE-2026-1000", "fine"), _nvd_rec("CVE-2026-1001", "bad\u0000de\u0007sc\tok\nyes")]}).encode()
    _, advs = src.parse_nvd(body)
    async with db.session() as s:
        assert await vendor.store(s, advs, vendor.Index([], {}, {"paloalto": {}, "fortinet": {}}, [])) == 2
        a = await s.get(VendorAdvisory, "nvd:CVE-2026-1001")
    assert "\x00" not in a.summary and "\x07" not in a.summary and "desc\tok\nyes" in a.summary


async def test_a_record_the_database_refuses_is_skipped_not_the_batch(monkeypatch):
    """A record the database still refuses (here: a cleaning gap simulated) costs only itself: savepoint per advisory."""
    from app import vendor_sources as src

    good, bad = _nvd("CVE-2026-7201"), _nvd("CVE-2026-7202")
    bad["cvss"] = "not a number"
    skipped: list[str] = []
    async with db.session() as s:
        assert await vendor.store(s, [good, bad], vendor.build_index(), skipped) == 1
        ids = set(await s.scalars(select(VendorAdvisory.id)))
    assert ids == {"nvd:CVE-2026-7201"} and skipped == ["nvd:CVE-2026-7202"]
    assert src.clean({"a\x00": ["x\x1fy", {"k": "\x0bz"}]}) == {"a": ["xy", {"k": "z"}]}


async def test_nvd_fetch_with_a_refused_record_moves_the_cursor_and_shows_the_error(admin_client, monkeypatch):
    """The good records are stored, the cursor moves on, and the query shows the refused one as its error."""
    import httpx

    def handler(req: httpx.Request) -> httpx.Response:
        recs = [_nvd_rec("CVE-2026-1100", "fine"), _nvd_rec("CVE-2026-1101", "also fine")]
        return httpx.Response(200, json={"totalResults": 2, "startIndex": 0, "resultsPerPage": 2, "vulnerabilities": recs})

    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(handler))
    real = vendor.src.parse_nvd

    def parse(body, rejected=None):  # noqa: ANN001
        total, advs = real(body, rejected)
        advs[1]["cvss"] = "refused"
        return total, advs

    monkeypatch.setattr(vendor.src, "parse_nvd", parse)
    async with db.session() as s:
        await vendor.sync_nvd_cpe(s, "a:acme:widget", timedelta(hours=6), vendor.build_index(), "", True)
        st = await vendor._state(s, "nvd:a:acme:widget")
        stored = set(await s.scalars(select(VendorAdvisory.id)))
    assert stored == {"nvd:CVE-2026-1100"}
    assert st.cursor and st.failures == 0 and "1 record(s) not stored" in (st.error or "")


# ---------------------------------------------------------------- bug hunt 0.1.16 M5 / L5: edits during the evaluation


async def test_version_corrected_during_the_evaluation_stays_a_baseline(admin_client, sites, monkeypatch):
    """M5: the round must not write its stale baseline over the one the admin's correction reset – the corrected
    version's findings would all be notified."""
    await _follow(admin_client, "panos")
    await _round()
    async with db.session() as s:
        await vendor.store(s, [_nvd(f"CVE-2026-{8800 + i}", end="11.2.4-h10") for i in range(5)], vendor.build_index())
        await vendor.evaluate_events(s)
    assert (await admin_client.post("/api/vendor/follows/panos/versions", json={"version": "11.2.4-h23"})).status_code == 200
    vid = (await admin_client.get("/api/vendor/products/panos")).json()["versions"][0]["id"]
    vendor.bump(["panos"])
    real, done = vendor.product_view, []

    async def view_and_edit(*a, **kw):  # noqa: ANN002, ANN003
        if not done:
            done.append((await admin_client.put(f"/api/vendor/versions/{vid}", json={"version": "11.2.4-h5"})).status_code)
        return await real(*a, **kw)

    monkeypatch.setattr(vendor, "product_view", view_and_edit)
    async with db.session() as s:
        await vendor.evaluate_events(s)
    monkeypatch.setattr(vendor, "product_view", real)
    async with db.session() as s:
        assert await vendor.evaluate_events(s) == 0
        sent = [e for e in await s.scalars(select(VendorEvent)) if not e.baseline and e.scope == "vuln:panos:11.2.4-h5"]
    assert done == [200] and sent == []


async def test_version_deleted_during_the_evaluation_does_not_end_the_round(admin_client, sites, monkeypatch):
    """L5: a version removed while the round evaluates its product is no row any more – no StaleDataError, the round
    goes on with the next product."""
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _follow(admin_client, "gitlab", "17.0.1")
    vid = (await admin_client.get("/api/vendor/products/panos")).json()["versions"][0]["id"]
    vendor.reset()
    real, done = vendor.product_view, []

    async def view_and_delete(db_, f, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        if f.product == "panos" and not done:
            done.append((await admin_client.delete(f"/api/vendor/versions/{vid}")).status_code)
        return await real(db_, f, *a, **kw)

    monkeypatch.setattr(vendor, "product_view", view_and_delete)
    monkeypatch.setattr(vendor, "_ready", lambda p, answered: True)
    async with db.session() as s:
        await vendor.evaluate_events(s, full=True)
        fs = {f.product: f.baseline_at for f in await s.scalars(select(VendorFollow).execution_options(populate_existing=True))}
    assert done == [200] and fs["panos"] is not None and fs["gitlab"] is not None


# ---------------------------------------------------------------- bug hunt 0.1.16 M8: validators only when complete


def _forti_sites(csaf_calls: list[str], refuse_second: dict):
    import httpx

    from test_vendor_service import FIX

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("ir.xml"):
            if req.headers.get("if-none-match") == '"r1"':
                return httpx.Response(304)
            return httpx.Response(200, content=(FIX / "vendor" / "fortinet_ir.xml").read_bytes(), headers={"ETag": '"r1"'})
        if "/psirt/csaf_" in req.url.path:
            csaf_calls.append(req.url.path)
            if len(csaf_calls) == 2 and refuse_second["on"]:
                return httpx.Response(429, headers={"Retry-After": "60"})
            return httpx.Response(200, content=(FIX / "vendor" / "fortinet_csaf_wad.json").read_bytes())
        raise AssertionError(req.url)

    return httpx.MockTransport(handler)


async def test_fortinet_feed_etag_waits_until_every_advisory_was_fetched(monkeypatch):
    """A 429 on the 2nd CSAF file: the feed's ETag is not kept, so the next round gets the feed (not 304) and fetches
    the rest – before, only 1 of 3 advisories was ever stored."""
    calls: list[str] = []
    refuse = {"on": True}
    monkeypatch.setattr(vendor, "transport", _forti_sites(calls, refuse))
    async with db.session() as s:
        await vendor.sync_fortinet(s, timedelta(hours=6), vendor.build_index(), True)
        st = await s.get(VendorFetch, "fortinet:rss")
        assert st.etag is None and (st.error or "").startswith("rate_limited")
        st.next_fetch_at = datetime.now(UTC) - timedelta(minutes=1)
        await s.commit()
    vendor._blocked.clear()
    async with db.session() as s:
        await vendor.sync_fortinet(s, timedelta(hours=6), vendor.build_index(), False)
        n = await s.scalar(select(func.count()).select_from(VendorAdvisory).where(VendorAdvisory.source == "fortinet"))
        st = await s.get(VendorFetch, "fortinet:rss", populate_existing=True)
    assert n == 3 and st.etag == '"r1"'  # complete now: the next round may ask conditionally


async def test_fortinet_feed_etag_not_kept_when_the_csaf_cap_was_hit(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(vendor, "transport", _forti_sites(calls, {"on": False}))
    monkeypatch.setattr(vendor, "FORTI_MAX_CSAF", 1)
    async with db.session() as s:
        await vendor.sync_fortinet(s, timedelta(hours=6), vendor.build_index(), True)
        st = await s.get(VendorFetch, "fortinet:rss")
    assert len(calls) == 1 and st.etag is None and st.error is None


async def test_incomplete_weekly_full_fetch_also_asks_the_change_window(admin_client, monkeypatch):
    """Bug hunt 0.1.16 M9: a CPE with more records than the full fetch takes (2600 > 2000): NVD's changes since the last
    run to the older records come from the window – the cursor must not move past them."""
    seen: list[dict] = []
    changed = {"cve": {"id": "CVE-2026-100005", "published": "2026-01-01T00:00:00.000", "lastModified": "2026-10-20T00:00:00.000", "vulnStatus": "Modified",
                       "descriptions": [{"lang": "en", "value": "changed by NVD"}], "metrics": {}, "configurations": []}}  # fmt: skip
    base = _nvd_pages(2600, seen)

    def handler(req):  # noqa: ANN001, ANN202
        import httpx

        if "lastModStartDate" in req.url.params:
            seen.append(dict(req.url.params))
            return httpx.Response(200, json={"totalResults": 1, "startIndex": 0, "resultsPerPage": 1, "vulnerabilities": [changed]})
        return base.handle_request(req)

    import httpx

    async with db.session() as s:
        await vendor.store(s, [_nvd("CVE-2026-100005", crit="cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*")], vendor.build_index())
        st = await vendor._state(s, "nvd:a:acme:widget")
        st.cursor = (datetime.now(UTC) - timedelta(hours=6)).isoformat()
        st.full_at = datetime.now(UTC) - timedelta(days=8)
        await s.commit()
    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(handler))
    async with db.session() as s:
        await vendor.sync_nvd_cpe(s, "a:acme:widget", timedelta(hours=6), vendor.build_index(), "", True)
        a = await s.get(VendorAdvisory, "nvd:CVE-2026-100005", populate_existing=True)
    assert any("lastModStartDate" in p for p in seen) and "changed by NVD" in (a.summary or "")


# ---------------------------------------------------------------- bug hunt 0.1.16 L5


async def test_custom_product_added_during_a_round_keeps_its_links(admin_client):
    """The round's index was built before the custom product existed: storing a changed record with it must not drop the
    link the custom product's relink just made."""
    adv = _nvd("CVE-2026-5556", crit="cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", start="1.0", end="1.5")
    async with db.session() as s:
        old_ix = await vendor.current_index(s)  # the round starts
        await vendor.store(s, [adv], old_ix)
    key = (await admin_client.post("/api/vendor/custom", json={"cpe": "a:acme:widget", "label": "Acme Widget"})).json()["key"]  # relinks
    changed = adv | {"summary": "updated by NVD", "updated_at": adv["updated_at"] + timedelta(hours=1)}
    async with db.session() as s:
        await vendor.store(s, [changed], old_ix)  # the same round stores the changed record
        links = list(await s.scalars(select(VendorAdvisoryProduct.advisory_id).where(VendorAdvisoryProduct.product == key)))
    assert links == ["nvd:CVE-2026-5556"]


async def test_errors_of_queries_no_longer_asked_are_not_counted(admin_client, reader_client, sites):
    """Bug hunt L5: the failed query of a product no longer followed counted under "Quellen mit Fehlern" forever."""
    await _follow(admin_client, "panos")
    sites.nvd_status = 500
    await vendor.run_round(force=True)
    assert (await reader_client.get("/api/vendor/overview")).json()["status"]["errors"] > 0
    assert (await admin_client.delete("/api/vendor/follows/panos")).status_code == 200
    sites.nvd_status = 200
    await _follow(admin_client, "fortios")
    await vendor.run_round(force=True)
    assert (await reader_client.get("/api/vendor/overview")).json()["status"]["errors"] == 0


def test_story_hint_judges_a_short_version_like_vendor_news():
    """Story details ("betrifft deine Systeme") for FortiOS "7.4" and a CSAF range 7.4.5–7.4.8: "possible", as Vendor
    News says – before it was judged as 7.4.0, "not affected", and the story had no hint."""
    import uuid

    from app import story_details
    from app import vendor_catalog as catalog
    from app.models import VendorVersion
    from app.vendor_match import range_of

    p = catalog.product("fortios")
    v = VendorVersion(id=uuid.uuid4(), follow_id=uuid.uuid4(), version="7.4", label="", count=None)
    d = {"kind": "bsi", "products": [{"name": "Fortinet FortiOS", "vendor": "Fortinet", "cpe": "", "affected": [range_of(">=7.4.5|<=7.4.8")], "fixed": ["7.4.9"], "not_affected": []}], "match": []}
    got = story_details.matches(d, [(p, [v])])
    assert got and got[0]["versions"][0]["status"] == "possible" == vendor.evaluate(p, "csaf", {"products": d["products"]}, "7.4").status
    v.version = "7.4.x-odd"
    assert story_details.matches(d, [(p, [v])])[0]["versions"][0]["status"] == "possible"  # unparsed: possible, as before


async def test_a_finding_without_cve_can_become_actively_exploited(admin_client, sites):
    """A vendor finding naming no CVE: notified once – and when the vendor marks it exploited later, "jetzt aktiv
    ausgenutzt" follows like for a CVE (before: never)."""
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    adv = _nvd("CVE-2026-7301") | {"id": "nvd:NOCVE-1", "ident": "PAN-SA-2026-0001", "cves": []}
    async with db.session() as s:
        await vendor.store(s, [adv], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1
        assert await vendor.evaluate_events(s, full=True) == 0  # not twice
        now_exploited = adv | {"exploited": True, "updated_at": adv["updated_at"] + timedelta(minutes=5), "data": {**adv["data"], "kev": {"dateAdded": datetime.now(UTC).date().isoformat()}}}
        await vendor.store(s, [now_exploited], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1
        ev = list(await s.scalars(select(VendorEvent).where(VendorEvent.key.startswith("exploited:"))))
        assert await vendor.evaluate_events(s, full=True) == 0
    assert len(ev) == 1 and ev[0].data.get("now_exploited") and not ev[0].baseline


# ---------------------------------------------------------------- security review 0.1.16 L3: odd JSON shapes


def test_vendor_parsers_survive_fields_of_an_unexpected_type():
    """Fuzzing found TypeErrors for fields of another type than documented (1 for a list, "x" for an object): a whole
    vendor source paused, one odd CSAF stopped all Fortinet alerts, the CPE search answered 500. Now a parser either
    reads what it can or fails as NewsError("format") – and an odd record next to good ones costs only itself."""
    import json

    import pytest

    from app import story_details as sd
    from app import vendor_sources as src
    from app.news import NewsError

    it = {"ident": "FG-IR-24-001", "title": "t", "link": "https://fortiguard.example/x", "date": None, "summary": "", "csaf": ""}
    cases = [
        (src.parse_pan, [{"ID": "CVE-2026-0001", "solution": 1}]),
        (src.parse_pan, [{"ID": "CVE-2026-0001", "problem": 1}]),
        (src.parse_pan, [{"ID": "CVE-2026-0001", "product": 1}]),
        (lambda b: src.parse_nvd(b, []), {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001", "metrics": "x"}}]}),
        (lambda b: src.parse_nvd(b, []), {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001", "configurations": [{"nodes": 1}]}}]}),
        (lambda b: src.parse_nvd(b, []), {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001", "descriptions": 1}}]}),
        (src.parse_cpes, {"products": 1}),
        (src.parse_cpes, {"products": [{"cpe": "x"}]}),
        (src.parse_cpes, {"products": [{"cpe": {"cpeName": "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*", "titles": 1}}]}),
        (lambda b: src.parse_forti_csaf(b, it), {"document": 1, "product_tree": {}}),
        (lambda b: sd.parse_csaf(b, "csaf"), {"document": {}, "product_tree": {"relationships": 1}}),
        (lambda b: sd.parse_csaf(b, "csaf"), {"document": {"tracking": 1}, "product_tree": {}}),
        (lambda b: sd.parse_csaf(b, "csaf"), {"document": {"aggregate_severity": "x"}, "product_tree": {}}),
        (sd.parse_cve5, {"containers": {"cna": {"affected": []}}, "cveMetadata": "x"}),
        (sd.parse_cve5, {"containers": {"cna": {"affected": [], "solutions": 1}}}),
    ]
    for fn, doc in cases:
        try:
            fn(json.dumps(doc).encode())
        except NewsError:
            pass  # a documented failure – no TypeError/AttributeError
    good = {"cve": {"id": "CVE-2026-0002", "descriptions": [{"lang": "en", "value": "fine"}]}}
    odd = {"cve": {"id": "CVE-2026-0003", "weaknesses": [{"description": 5}], "affected": [{"affectedData": [{"versions": 7}]}]}}
    _, advs = src.parse_nvd(json.dumps({"totalResults": 2, "vulnerabilities": [odd, good]}).encode())
    assert sorted(a["ident"] for a in advs) == ["CVE-2026-0002", "CVE-2026-0003"]
    pan = src.parse_pan(json.dumps([{"ID": "CVE-2026-0004", "version": "x", "affected": 3}, {"ID": "CVE-2026-0005", "title": "ok"}]).encode())
    assert [a["ident"] for a in pan] == ["CVE-2026-0004", "CVE-2026-0005"]
    a = src.parse_forti_csaf(json.dumps({"document": 1, "product_tree": {}, "vulnerabilities": [{"scores": [{"cvss_v3": "x"}], "remediations": 2}]}).encode(), it)
    assert a["ident"] == "FG-IR-24-001" and a["cvss"] is None
    with pytest.raises(NewsError) as e:  # what still slips through fails as a documented error
        src._shaped(lambda: {}["missing"])()
    assert e.value.category == "format" and "unexpected structure" in e.value.detail


# ---------------------------------------------------------------- relink: PostgreSQL preselects the candidates


async def test_relink_preselects_by_cpe_and_cna_and_still_finds_everything():
    """Following a product reads only the advisories that can concern it (CPE in a configuration – as the catalogue
    writes it or without CPE escapes –, a word of its CNA names, every vendor advisory); link() still decides."""
    from app import vendor_catalog as catalog

    def cna(cve: str, vendor_: str, product: str) -> dict:
        a = _nvd(cve, crit="cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*")
        a["data"]["cna"] = [{"affectedData": [{"vendor": vendor_, "product": product, "defaultStatus": "unaffected", "versions": [{"version": "6.0", "lessThan": "6.11.5", "status": "affected", "versionType": "semver"}]}]}]
        return a

    advs = [
        _nvd("CVE-2026-9001", crit="cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:*:*:*:*:*:*:*:*", start="8.0", end="8.7.5"),
        _nvd("CVE-2026-9002", crit="cpe:2.3:a:notepad-plus-plus:notepad++:*:*:*:*:*:*:*:*", start="8.0", end="8.7.5"),
        cna("CVE-2026-9003", "Enpass", "Enpass Password Manager"),
        cna("CVE-2026-9004", "Sinew", "Enpass"),
        _nvd("CVE-2026-9005", crit="cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*"),
    ]
    async with db.session() as s:
        await vendor.store(s, advs, vendor.Index([], {}, {"paloalto": {}, "fortinet": {}}, []))  # linked to nothing yet
        for key in ("notepad-plus-plus", "enpass"):
            await vendor.relink(s, catalog.product(key))
        links = {(x.product, x.advisory_id) for x in await s.scalars(select(VendorAdvisoryProduct))}
    # exactly what link() says when it is asked about every stored record (the matching itself is unchanged)
    want = {(k, a["id"]) for a in advs for k in ("notepad-plus-plus", "enpass") if k in vendor.link(a, vendor.build_index())}
    assert links == want and {("notepad-plus-plus", "nvd:CVE-2026-9001"), ("notepad-plus-plus", "nvd:CVE-2026-9002"), ("enpass", "nvd:CVE-2026-9003")} <= want


async def test_nvd_api_key_never_follows_a_redirect(admin_client, monkeypatch):
    """Security review 0.1.16 L5: httpx strips only Authorization on a cross-host redirect – the apiKey header went
    along. A request with the key follows no redirect (an error for the query); one without the key still does."""
    import httpx

    seen: list[tuple[str, str | None]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.url.host, req.headers.get("apikey")))
        if req.url.host == "services.nvd.nist.gov":
            return httpx.Response(302, headers={"Location": "https://collector.example.net/steal"})
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(handler))
    async with db.session() as s:
        await vendor.sync_nvd_cpe(s, "a:acme:widget", timedelta(hours=6), vendor.build_index(), "secret-test-key", True)
        st = await vendor._state(s, "nvd:a:acme:widget")
    assert seen == [("services.nvd.nist.gov", "secret-test-key")] and (st.error or "").startswith("http")
    seen.clear()
    assert await vendor.get("https://services.nvd.nist.gov/rest/json/cves/2.0", conditional=False) is not None  # without key: followed
    assert [h for h, _ in seen] == ["services.nvd.nist.gov", "collector.example.net"] and all(k is None for _, k in seen)
