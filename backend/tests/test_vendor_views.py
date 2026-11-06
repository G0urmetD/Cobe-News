"""The cached Vendor News views (0.1.51 bug hunt B1, perf): after a change for all the overview, the badge and the counts
show the previous views until the new ones are ready; the KEV and the EUVD CVEs are read once per change, and a change
of them recomputes only the views whose CVEs it touches; EPSS and exploit-list changes only the products naming them."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import insert

from app import db, vendor
from app.models import VendorKev, VendorVersion


def _nvd(cve: str, *, crit="cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", start="11.2.0", end="11.2.4-h30") -> dict:
    now = datetime.now(UTC) - timedelta(hours=2)
    return {
        "id": f"nvd:{cve}", "source": "nvd", "ident": cve, "title": f"{cve} example", "summary": "x", "url": "https://nvd.nist.gov/",
        "cves": [cve], "cvss": 7.5, "severity": "high", "exploited": False, "published_at": now, "updated_at": now,
        "data": {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": crit, "versionStartIncluding": start, "versionEndExcluding": end}]}]}], "cna": [], "desc": "x", "status": "Analyzed"},
    }  # fmt: skip


async def _setup(admin_client) -> None:
    for key, ver in (("panos", "11.2.4-h23"), ("gitlab", "17.0.0")):
        assert (await admin_client.put(f"/api/vendor/follows/{key}", json={"enabled": True})).status_code == 200
        assert (await admin_client.post(f"/api/vendor/follows/{key}/versions", json={"version": ver})).status_code == 200
    async with db.session() as s:
        await vendor.store(s, [_nvd("CVE-2026-41000"), _nvd("CVE-2026-41001", crit="cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", start="16.0", end="17.0.1")], vendor.build_index())


@pytest.fixture
def computed(monkeypatch):
    """Which products' views were computed – and a switch to make each computation slow."""
    seen: list[str] = []
    slow = [0.0]
    orig = vendor._compute_view

    async def counted(f, vers, kev, euvd):  # noqa: ANN001, ANN202
        seen.append(f.product)
        if slow[0]:
            await asyncio.sleep(slow[0])
        return await orig(f, vers, kev, euvd)

    monkeypatch.setattr(vendor, "_compute_view", counted)
    return seen, slow


async def test_after_a_change_for_all_the_previous_views_are_shown_until_the_new_ones_are_ready(admin_client, computed, monkeypatch):
    seen, slow = computed
    await _setup(admin_client)
    first = (await admin_client.get("/api/vendor/badge")).json()
    assert first["affected"] == 2 and sorted(seen) == ["gitlab", "panos"]
    seen.clear()
    monkeypatch.setattr(vendor, "STALE_WAIT", 0.05)
    slow[0] = 1.0  # the recomputation takes a second
    vendor.bump()
    t0 = asyncio.get_running_loop().time()
    assert (await admin_client.get("/api/vendor/badge")).json() == first  # the previous views – at once
    assert (await admin_client.get("/api/reader/counts")).status_code == 200
    items = (await admin_client.get("/api/vendor/overview")).json()["items"]
    assert len(items) == 2 and asyncio.get_running_loop().time() - t0 < 0.9
    assert len(seen) == len(set(seen)) <= 2  # one computation each at most (single flight), one at a time
    await asyncio.sleep(2.3)
    assert sorted(seen) == ["gitlab", "panos"]  # both done in the background
    slow[0] = 0.0
    seen.clear()
    assert (await admin_client.get("/api/vendor/badge")).json() == first and seen == []  # the new ones are stored


async def test_a_change_of_the_products_own_data_is_never_shown_stale(admin_client, computed, monkeypatch):
    seen, slow = computed
    await _setup(admin_client)
    assert (await admin_client.get("/api/vendor/badge")).json()["affected"] == 2
    monkeypatch.setattr(vendor, "STALE_WAIT", 0.01)
    slow[0] = 0.3
    async with db.session() as s:  # GitLab's version moves past the fix: its view is computed before it is shown
        v = await s.scalar(insert(VendorVersion).returning(VendorVersion.id).values(follow_id=(await vendor.follows(s))[1].id, version="17.0.1"))
        await s.commit()
    vendor.bump(["gitlab"])
    r = await admin_client.get("/api/vendor/overview")
    gl = next(i for i in r.json()["items"] if i["product"]["key"] == "gitlab")
    assert str(v) in str(gl)  # the new version is in the answer: computed now, not the previous view


async def test_kev_and_euvd_are_read_once_and_a_change_touches_only_the_views_naming_it(admin_client, computed, monkeypatch):
    seen, _ = computed
    await _setup(admin_client)
    await admin_client.get("/api/vendor/overview")
    reads = {"kev": 0, "euvd": 0}

    async def count_overview() -> None:
        await admin_client.get("/api/vendor/overview")
        await admin_client.get("/api/vendor/badge")
        await admin_client.get("/api/reader/counts")

    from app import models

    real = vendor.select

    def spy(*a, **kw):  # noqa: ANN002, ANN003, ANN202
        if a and a[0] is models.VendorKev:
            reads["kev"] += 1
        if a and getattr(a[0], "class_", None) is models.NewsSource:
            reads["euvd"] += 1
        return real(*a, **kw)

    monkeypatch.setattr(vendor, "select", spy)
    seen.clear()
    await count_overview()
    assert reads == {"kev": 0, "euvd": 0} and seen == []  # three requests: neither list read, no view computed
    async with db.session() as s:  # a KEV entry of an unrelated CVE: no view computed
        await s.execute(insert(VendorKev).values(cve="CVE-2020-0001", vendor="x", product="y", name="z", date_added="2026-11-01", due="", ransomware=False))
        await s.commit()
    vendor.kev_changed()
    vendor.bump([])
    await count_overview()
    assert reads["kev"] == 1 and seen == []
    async with db.session() as s:  # one of GitLab's CVEs: only GitLab's view
        await s.execute(insert(VendorKev).values(cve="CVE-2026-41001", vendor="GitLab", product="GitLab", name="x", date_added="2026-11-01", due="", ransomware=False))
        await s.commit()
    vendor.kev_changed()
    vendor.bump([])
    await count_overview()
    assert seen == ["gitlab"]
    gl = next(i for i in (await admin_client.get("/api/vendor/overview")).json()["items"] if i["product"]["key"] == "gitlab")
    assert gl["counts"]["exploited_affected"] == 1


async def test_epss_and_exploit_changes_recompute_only_the_products_naming_the_cves(admin_client, computed):
    seen, _ = computed
    await _setup(admin_client)
    await admin_client.get("/api/vendor/overview")
    seen.clear()
    async with db.session() as s:
        assert await vendor.bump_cves(s, {"CVE-2026-41000"}) == 2  # PAN-OS and Panorama (linked, Panorama not followed)
    await admin_client.get("/api/vendor/overview")
    assert seen == ["panos"]
    async with db.session() as s:
        assert await vendor.bump_cves(s, {"CVE-1999-0001"}) == 0
    seen.clear()
    await admin_client.get("/api/vendor/overview")
    assert seen == []


async def test_euvd_cves_are_read_again_after_stories_were_stored(admin_client):
    from app import news
    from app.models import NewsSource
    from sqlalchemy import select, update

    async with db.session() as s:
        assert await vendor.euvd_cves(s) == frozenset()
        await s.execute(update(NewsSource).where(NewsSource.key == "enisa-euvd").values(enabled=True, primed_at=datetime.now(UTC)))
        await s.commit()
        src = await s.scalar(select(NewsSource).where(NewsSource.key == "enisa-euvd"))
        entry = {"link": "https://euvd.example.org/EUVD-2026-9", "title": "CVE-2026-41001 · GitLab: RCE", "summary": "", "content": "", "date": datetime.now(UTC) - timedelta(hours=1), "severity": "high", "reasons": [], "cves": ["CVE-2026-41001"]}
        assert await news.store(s, src, [entry]) == 1
        assert "CVE-2026-41001" in await vendor.euvd_cves(s)  # the cached (empty) set was not kept


async def test_switched_off_vendor_news_has_no_badge_and_no_count(admin_client):
    await _setup(admin_client)
    assert (await admin_client.get("/api/vendor/badge")).json()["affected"] == 2
    from app import settings as settings_store

    async with db.session() as s:
        await settings_store.put(s, "vendor", {**(await vendor.config(s)), "enabled": False})
        await s.commit()
    assert (await admin_client.get("/api/vendor/badge")).json() == {"affected": 0, "exploited": False, "enabled": False}
    counts = (await admin_client.get("/api/reader/counts")).json()
    assert counts["vendor"] == 0 and counts["vendor_enabled"] is False


async def test_api_findings_pages_slice_one_sorted_list(admin_client, monkeypatch):
    """B5: /api/v1/vendor/findings sorts the findings once per state of the views (and filter) – the next page is a
    slice of the same list, the contract (items, total, offset, limit) stays."""
    from app import api_v1
    from tests.conftest import make_client

    await _setup(admin_client)
    tok = (await admin_client.post("/api/admin/api-tokens", json={"name": "siem", "scopes": ["read"]})).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    built = [0]
    orig = api_v1._finding

    def count(x):  # noqa: ANN001, ANN202
        built[0] += 1
        return orig(x)

    monkeypatch.setattr(api_v1, "_finding", count)
    async with make_client() as c:
        one = (await c.get("/api/v1/vendor/findings", params={"limit": 1}, headers=h)).json()
        two = (await c.get("/api/v1/vendor/findings", params={"limit": 1, "offset": 1}, headers=h)).json()
        assert one["total"] == two["total"] == 2 and one["items"][0] != two["items"][0] and built[0] == 2
        assert (await c.get("/api/v1/vendor/findings", params={"limit": 1, "status": "affected", "severity": "high"}, headers=h)).json()["total"] == 2
        assert built[0] == 4  # another filter: its own list
        async with db.session() as s:
            await vendor.store(s, [_nvd("CVE-2026-41002")], vendor.build_index())
        assert (await c.get("/api/v1/vendor/findings", params={"limit": 1}, headers=h)).json()["total"] == 3  # a changed view: anew


async def test_status_says_failed_when_nothing_ever_answered(admin_client):
    """B10: every source asked failed and none ever answered – "failed", not "Erster Abruf läuft" (that never ended)."""
    from app.models import VendorFetch

    assert (await admin_client.put("/api/vendor/follows/panos", json={"enabled": True})).status_code == 200
    async with db.session() as s:
        keys = sorted(await vendor.active_keys(s))
        now = datetime.now(UTC)
        for k in keys:
            s.add(VendorFetch(key=k, failures=3, items=0, error="timeout: ReadTimeout", last_fetch_at=now))
        await s.commit()
    st = (await admin_client.get("/api/vendor/overview")).json()["status"]
    assert st["fetched"] is False and st["failed"] is True and st["errors"] == len(keys)
    async with db.session() as s:
        row = await s.get(VendorFetch, keys[0])
        row.error, row.last_ok_at = None, datetime.now(UTC)
        await s.commit()
    st = (await admin_client.get("/api/vendor/overview")).json()["status"]
    assert st["fetched"] is True and st["failed"] is False


async def test_a_failing_recomputation_is_shown_not_hidden_behind_the_previous_view(admin_client, monkeypatch, caplog):
    """Final review 0.1.51: the new computation fails after a change for all – the previous view is shown at most for
    the request that started it; then the error shows (logged, no "Task exception was never retrieved") until a
    computation succeeds again. A view out of date longer than STALE_MAX is not shown either."""
    await _setup(admin_client)
    assert (await admin_client.get("/api/vendor/badge")).status_code == 200
    orig = vendor._compute_view

    async def boom(f, vers, kev, euvd):  # noqa: ANN001, ANN202
        await asyncio.sleep(0.2)
        raise RuntimeError("new catalogue breaks the evaluation")

    monkeypatch.setattr(vendor, "_compute_view", boom)
    monkeypatch.setattr(vendor, "STALE_WAIT", 0.01)
    vendor.bump()
    async with db.session() as s:
        fs = await vendor.follows(s)
        f = next(x for x in fs if x.product == "gitlab")
        vers = (await vendor.versions_of(s, [f.id]))[f.id]
        first = await vendor.product_view(s, f, vers, deadline=vendor.stale_deadline(vendor.STALE_WAIT))
        assert first["findings"]  # the previous view, once
        await asyncio.sleep(0.4)  # the background computation failed
        assert "gitlab" in vendor._failed and "could not be computed" in caplog.text
        with pytest.raises(RuntimeError):
            await vendor.product_view(s, f, vers, deadline=vendor.stale_deadline(vendor.STALE_WAIT))
        monkeypatch.setattr(vendor, "_compute_view", orig)
        again = await vendor.product_view(s, f, vers, deadline=vendor.stale_deadline(vendor.STALE_WAIT))
        assert again["findings"] and "gitlab" not in vendor._failed
        # out of date for longer than STALE_MAX: the request waits for the new view
        vendor.bump()
        hit = vendor._views["gitlab"]
        hit.stale_since = __import__("time").monotonic() - vendor.STALE_MAX - 1
        slow = [0]

        async def counted(f, vers, kev, euvd):  # noqa: ANN001, ANN202
            slow[0] += 1
            await asyncio.sleep(0.1)
            return await orig(f, vers, kev, euvd)

        monkeypatch.setattr(vendor, "_compute_view", counted)
        got = await vendor.product_view(s, f, vers, deadline=vendor.stale_deadline(0.01))
        assert slow[0] == 1 and vendor._views["gitlab"].view is got  # the new one, not the old
