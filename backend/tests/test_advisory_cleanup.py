"""The cleanup of Vendor News advisories nobody needs (app/advisory_cleanup.py, 0.1.51): a product no longer followed
loses its records after a year – unless a watched CVE, a stored story or its details, or a recent revision still needs
them, or their source could not bring them back (CSAF, Fortinet). Following it again starts its queries in full: the
records come back before the baseline is taken, nothing old is sent."""

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import add_user
from sqlalchemy import func, select, update

from app import advisory_cleanup as cleanup
from app import db, vendor
from app import vendor_catalog as catalog
from app.models import (
    CveWatch,
    NewsItem,
    NewsSource,
    StoryDetail,
    VendorAdvisory,
    VendorAdvisoryChange,
    VendorAdvisoryProduct,
    VendorAdvisoryState,
    VendorEvent,
    VendorFetch,
    VendorFollow,
)

FIX = Path(__file__).parent / "fixtures"
EMPTY_NVD = {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "format": "NVD_CVE", "version": "2.0", "vulnerabilities": []}
FORTIOS_NVD = ["CVE-2025-59718", "CVE-2025-25249", "CVE-2024-21754", "CVE-2024-23111", "CVE-2024-26010", "CVE-2024-26015"]
OLD = datetime.now(UTC) - timedelta(days=400)


class Sites:
    """NVD with the FortiOS records, Fortinet's PSIRT feed, KEV and endoflife.date – every request recorded."""

    def __init__(self):
        self.calls: list[httpx.Request] = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        host, path = req.url.host, req.url.path
        if host == "services.nvd.nist.gov":
            if req.url.params.get("virtualMatchString") == "cpe:2.3:o:fortinet:fortios":
                return httpx.Response(200, content=(FIX / "vendor" / "nvd_fortios.json").read_bytes())
            return httpx.Response(200, json=EMPTY_NVD)
        if host == "filestore.fortinet.com" and path.endswith("ir.xml"):
            return httpx.Response(200, content=(FIX / "vendor" / "fortinet_ir.xml").read_bytes())
        if host == "filestore.fortinet.com" and "/psirt/csaf_" in path:
            return httpx.Response(200, content=(FIX / "vendor" / "fortinet_csaf_wad.json").read_bytes())
        if host == "www.cisa.gov":
            return httpx.Response(200, content=(FIX / "news" / "kev.json").read_bytes())
        if host == "endoflife.date":
            return httpx.Response(200, content=(FIX / "vendor" / "eol_full.json").read_bytes())
        raise AssertionError(f"unexpected request {req.url}")

    def nvd(self) -> list[httpx.Request]:
        return [c for c in self.calls if c.url.host == "services.nvd.nist.gov"]


@pytest.fixture(autouse=True)
def vendor_reset(monkeypatch, tmp_path):
    vendor.reset()
    monkeypatch.setattr(catalog, "_data_file", lambda: tmp_path / "vendor_catalog.json")
    catalog._cache.stamp = ()
    yield


@pytest.fixture
def sites(monkeypatch):
    s = Sites()
    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(s.handler))
    return s


async def _round() -> None:
    await vendor.run_round(force=True)
    async with db.session() as s:
        await vendor.evaluate_events(s)


async def _nvd_ids() -> set[str]:
    async with db.session() as s:
        return set(await s.scalars(select(VendorAdvisory.ident).where(VendorAdvisory.source == "nvd")))


async def _age(*, days: int = 400) -> None:
    async with db.session() as s:
        await s.execute(update(VendorAdvisory).values(fetched_at=datetime.now(UTC) - timedelta(days=days)))
        await s.commit()


async def _prune() -> int:
    async with db.session() as s:
        return await cleanup.prune(s)


async def _followed_once_then_dropped(admin_client) -> None:
    """FortiOS followed, its round stored – then no longer followed."""
    assert (await admin_client.put("/api/vendor/follows/fortios", json={"enabled": True})).status_code == 200
    await _round()
    assert await _nvd_ids() == set(FORTIOS_NVD)
    assert (await admin_client.delete("/api/vendor/follows/fortios")).status_code == 200


async def test_unfollowed_advisories_go_after_a_year_with_links_and_state(admin_client, sites):
    await _followed_once_then_dropped(admin_client)
    await _age(days=100)
    assert await _prune() == 0  # younger than a year: stays
    await _age()
    assert await _prune() == len(FORTIOS_NVD)
    assert await _nvd_ids() == set()
    async with db.session() as s:
        left = set(await s.scalars(select(VendorAdvisory.source)))
        assert left == {"fortinet"}  # Fortinet's PSIRT feed lists only the newest: its records stay
        assert await s.scalar(select(func.count()).select_from(VendorAdvisoryProduct).where(VendorAdvisoryProduct.advisory_id.like("nvd:%"))) == 0
        assert await s.scalar(select(func.count()).select_from(VendorAdvisoryState).where(VendorAdvisoryState.advisory_id.like("nvd:%"))) == 0
        # the query nobody asks any more starts in full: no cursor, no full fetch, never answered
        st = await s.get(VendorFetch, "nvd:o:fortinet:fortios")
        assert st.cursor is None and st.full_at is None and st.last_ok_at is None and st.next_fetch_at is None


async def test_switched_off_counts_as_not_followed_but_a_followed_link_keeps_it(admin_client, sites):
    await _followed_once_then_dropped(admin_client)
    await _age()
    async with db.session() as s:
        s.add(VendorFollow(product="fortios", enabled=False))  # followed, but switched off
        s.add(VendorFollow(product="panos", enabled=True))
        s.add(VendorAdvisoryProduct(product="panos", advisory_id="nvd:CVE-2024-21754"))
        await s.commit()
    assert await _prune() == len(FORTIOS_NVD) - 1
    assert await _nvd_ids() == {"CVE-2024-21754"}


async def test_a_watched_cve_a_story_its_details_and_a_recent_revision_keep_records(admin_client, sites):
    await _followed_once_then_dropped(admin_client)
    await _age()
    u = await add_user("watcher")
    async with db.session() as s:
        s.add(CveWatch(user_id=u.id, cve="CVE-2025-59718"))
        src = await s.scalar(select(NewsSource).limit(1))
        story = NewsItem(source_id=src.id, url="https://x.example/1", url_key="x.example/1", title="FortiOS", title_key="fortios", published_at=datetime.now(UTC), cves=["CVE-2025-25249"])
        detailed = NewsItem(source_id=src.id, url="https://x.example/2", url_key="x.example/2", title="KEV", title_key="kev", published_at=datetime.now(UTC), cves=[])
        s.add_all([story, detailed])
        await s.flush()
        # a story's details behind a vendor advisory id (story_details.advisory_ids): the record stays
        s.add(StoryDetail(item_id=detailed.id, kind="paloalto", ident="CVE-2024-21754", status="ok"))
        s.add(VendorAdvisory(id="paloalto:CVE-2024-21754", source="paloalto", ident="CVE-2024-21754", fetched_at=OLD, cves=[]))
        s.add(VendorAdvisoryChange(advisory_id="nvd:CVE-2024-23111", source="nvd", revision=2, at=datetime.now(UTC) - timedelta(days=30)))
        await s.commit()
    assert await _prune() == 3
    assert await _nvd_ids() == {"CVE-2025-59718", "CVE-2025-25249", "CVE-2024-23111"}
    async with db.session() as s:
        assert await s.get(VendorAdvisory, "paloalto:CVE-2024-21754") is not None


async def test_a_lone_bsi_document_goes_other_csaf_stays(admin_client):
    """Data growth (0.1.51): a BSI document of a story long gone that no product concerns goes after a year; one linked
    to a product (followed or not), a provider's document and one a story still names stay."""
    from app.models import VendorAdvisoryProduct

    async with db.session() as s:
        for n in (1, 2, 3, 4):
            s.add(VendorAdvisory(id=f"csaf:WID-SEC-W-2025-000{n}", source="csaf", ident=f"WID-SEC-W-2025-000{n}", fetched_at=OLD, cves=[f"CVE-2020-100{n}"], data={"publisher": "BSI (CSAF)", "products": []}))
        s.add(VendorAdvisory(id="csaf:siemens:SSA-1", source="csaf", ident="SSA-1", fetched_at=OLD, cves=["CVE-2020-1009"], data={"publisher": "BSI (CSAF)", "provider": "siemens"}))
        await s.flush()
        s.add(VendorAdvisoryProduct(product="rhel", advisory_id="csaf:WID-SEC-W-2025-0002"))  # not followed: still a link
        s.add(VendorAdvisory(id="csaf:WID-SEC-W-2025-0009", source="csaf", ident="WID-SEC-W-2025-0009", fetched_at=datetime.now(UTC), cves=[], data={"publisher": "BSI (CSAF)"}))
        await s.commit()
    assert await _prune() == 3  # 0001, 0003, 0004 (no story names them) – not the linked, the provider's, the young one
    async with db.session() as s:
        assert set(await s.scalars(select(VendorAdvisory.id))) == {"csaf:WID-SEC-W-2025-0002", "csaf:siemens:SSA-1", "csaf:WID-SEC-W-2025-0009"}


async def test_csaf_documents_stay(admin_client):
    async with db.session() as s:
        s.add(VendorAdvisory(id="csaf:SSA-123456", source="csaf", ident="SSA-123456", fetched_at=OLD, cves=["CVE-2020-0001"]))
        s.add(VendorAdvisory(id="osv:CVE-2020-0002", source="osv", ident="CVE-2020-0002", fetched_at=OLD, cves=["CVE-2020-0002"]))
        await s.commit()
    assert await _prune() == 1
    async with db.session() as s:
        assert set(await s.scalars(select(VendorAdvisory.id))) == {"csaf:SSA-123456"}


async def test_following_again_brings_them_back_before_the_baseline_and_sends_nothing(admin_client, sites):
    await _followed_once_then_dropped(admin_client)
    await _age()
    assert await _prune() == len(FORTIOS_NVD)
    async with db.session() as s:
        await s.execute(VendorEvent.__table__.delete())
        await s.commit()
    sites.calls.clear()
    assert (await admin_client.put("/api/vendor/follows/fortios", json={"enabled": True})).status_code == 200
    # not answered yet: no evaluation (the baseline waits for the records)
    async with db.session() as s:
        await vendor.evaluate_events(s)
        assert await s.scalar(select(func.count()).select_from(VendorEvent)) == 0
    await _round()
    full = [c for c in sites.nvd() if c.url.params.get("virtualMatchString") == "cpe:2.3:o:fortinet:fortios"]
    assert full and all("lastModStartDate" not in c.url.params for c in full)  # a full fetch, not "changed since"
    assert await _nvd_ids() == set(FORTIOS_NVD)
    async with db.session() as s:
        evs = list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "vuln")))
    assert evs and all(e.baseline for e in evs)  # the baseline as for a new follow – nothing is sent


async def test_switching_on_again_resets_only_the_queries_nobody_else_asks(admin_client, sites):
    await _followed_once_then_dropped(admin_client)
    assert (await admin_client.put("/api/vendor/follows/fortios", json={"enabled": False})).status_code == 200
    assert (await admin_client.put("/api/vendor/follows/fortiproxy", json={"enabled": True})).status_code == 200
    stamp = datetime.now(UTC) - timedelta(days=2)
    async with db.session() as s:
        await s.execute(update(VendorFetch).values(cursor=stamp.isoformat(), full_at=stamp, last_ok_at=stamp))
        await s.commit()
    assert (await admin_client.put("/api/vendor/follows/fortios", json={"enabled": True})).status_code == 200
    async with db.session() as s:
        mine = await s.get(VendorFetch, "nvd:o:fortinet:fortios")
        assert mine.cursor is None and mine.full_at is None and mine.last_ok_at == stamp  # in full – evaluated at once
        shared = await s.get(VendorFetch, "fortinet:rss")  # its documents are kept – never reset
        assert shared is None or shared.last_ok_at is not None


async def test_the_cleanup_is_a_daily_step(monkeypatch):
    ran = []

    async def fake(s, now=None):  # noqa: ANN001, ANN202
        ran.append(1)
        return 0

    monkeypatch.setattr(cleanup, "prune", fake)
    async with db.session() as s:
        out = await vendor.daily_prunes(s)
    assert out["unfollowed advisories"] == 0 and ran == [1]


async def test_batches_and_a_locked_record_is_left_for_the_next_day(monkeypatch):
    monkeypatch.setattr(cleanup, "SCAN", 3)
    async with db.session() as s:
        for i in range(7):
            s.add(VendorAdvisory(id=f"nvd:CVE-2019-{i:04d}", source="nvd", ident=f"CVE-2019-{i:04d}", fetched_at=OLD, cves=[f"CVE-2019-{i:04d}"]))
        await s.commit()
    async with db.session() as holder:
        await holder.execute(select(VendorAdvisory).where(VendorAdvisory.id == "nvd:CVE-2019-0003").with_for_update())
        assert await _prune() == 6
        await holder.rollback()
    assert await _prune() == 1


async def test_on_follow_of_an_unknown_product_changes_nothing():
    async with db.session() as s:
        assert await cleanup.on_follow(s, {"key": f"custom-{uuid.uuid4().hex[:8]}", "cpes": ["a:example:x"]}) == 0


# ---------------------------------------------------------------- review 0.1.51: a CPE another product still asks (H2)

WS2019 = "cpe:2.3:o:microsoft:windows_server_2019"


def _ms(cve: str, desc: str) -> dict:
    return {
        "cve": {
            "id": cve,
            "sourceIdentifier": "secure@microsoft.com",
            "published": "2024-01-09T18:15:00.000",
            "lastModified": "2024-01-10T18:15:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": desc}],
            "metrics": {},
            "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{"vulnerable": True, "criteria": f"{WS2019}:-:*:*:*:*:*:*:*", "matchCriteriaId": "X"}]}]}],
            "references": [],
        }
    }


WS_BODY = {
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 2,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2024-02-01T00:00:00.000",
    "vulnerabilities": [_ms("CVE-2024-0001", "Windows DNS Server Remote Code Execution Vulnerability"), _ms("CVE-2024-0002", "Windows Kerberos Elevation of Privilege Vulnerability")],
}


@pytest.fixture
def windows(monkeypatch):
    """NVD lists both records for Windows Server 2019 – in full only; "changed since" brings nothing."""
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        if req.url.host == "services.nvd.nist.gov":
            if req.url.params.get("virtualMatchString") == WS2019 and "lastModStartDate" not in req.url.params:
                return httpx.Response(200, json=WS_BODY)
            return httpx.Response(200, json={**WS_BODY, "resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []})
        if req.url.host == "www.cisa.gov":
            return httpx.Response(200, content=(FIX / "news" / "kev.json").read_bytes())
        if req.url.host == "endoflife.date":
            return httpx.Response(200, content=(FIX / "vendor" / "eol_full.json").read_bytes())
        return httpx.Response(404)

    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(handler))
    return calls


async def _links() -> dict[str, set[str]]:
    async with db.session() as s:
        rows = (await s.execute(select(VendorAdvisoryProduct.advisory_id, VendorAdvisoryProduct.product).where(VendorAdvisoryProduct.advisory_id.like("nvd:%")))).all()
    out: dict[str, set[str]] = {}
    for aid, prod in rows:
        out.setdefault(aid, set()).add(prod)
    return out


async def test_a_record_of_a_cpe_still_asked_stays_and_a_product_followed_later_finds_it(admin_client, windows):
    """Windows DNS followed: NVD's Windows Server 2019 query also brings a Kerberos record that links only to products
    nobody follows (link() links against the whole catalogue). Deleted, it never came back – the query is still asked,
    so never reset, and following Windows Server later fetched only what changed."""
    assert (await admin_client.put("/api/vendor/follows/windows-dns", json={"enabled": True})).status_code == 200
    await vendor.run_round(force=True)
    kerberos = (await _links())["nvd:CVE-2024-0002"]
    assert "windows-dns" not in kerberos and "windows-server" in kerberos  # linked only to unfollowed products
    await _age()
    assert await _prune() == 0  # the asked query lists it: it stays
    windows.clear()
    assert (await admin_client.put("/api/vendor/follows/windows-server", json={"enabled": True})).status_code == 200
    await vendor.run_round(force=True)
    assert "windows-server" in (await _links())["nvd:CVE-2024-0002"]
    # once nobody follows any product of that CPE, the record goes – and the query starts in full next time
    assert (await admin_client.delete("/api/vendor/follows/windows-dns")).status_code == 200
    assert (await admin_client.delete("/api/vendor/follows/windows-server")).status_code == 200
    await _age()
    assert await _prune() == 2
    async with db.session() as s:
        st = await s.get(VendorFetch, "nvd:o:microsoft:windows_server_2019")
        assert st.cursor is None and st.full_at is None and st.last_ok_at is None


async def test_an_unanalysed_record_naming_a_catalogue_product_stays():
    """No CPE yet (only the keyword search of the last days brought it): no query would list it again."""
    async with db.session() as s:
        s.add(VendorAdvisory(id="nvd:CVE-2023-5555", source="nvd", ident="CVE-2023-5555", fetched_at=OLD, cves=["CVE-2023-5555"], data={"cna": [{"affectedData": [{"product": "PAN-OS"}]}]}))
        s.add(VendorAdvisory(id="nvd:CVE-2023-6666", source="nvd", ident="CVE-2023-6666", fetched_at=OLD, cves=["CVE-2023-6666"], data={}))
        await s.flush()
        s.add(VendorAdvisoryProduct(product="panos", advisory_id="nvd:CVE-2023-5555"))
        await s.commit()
    assert await _prune() == 1  # the one linked to nothing (a story's lookup) goes
    async with db.session() as s:
        assert set(await s.scalars(select(VendorAdvisory.id))) == {"nvd:CVE-2023-5555"}


def test_cpe_product_reads_strings_and_query_keys_alike():
    assert cleanup.cpe_product("cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*") == "o:microsoft:windows_server_2019"
    assert cleanup.cpe_product("o:microsoft:windows_server_2019") == "o:microsoft:windows_server_2019"
    assert cleanup.cpe_product(r"cpe:2.3:a:mailcow:mailcow\:_dockerized:2023:*") == "a:mailcow:mailcow:_dockerized"


# ---------------------------------------------------------------- review 0.1.51: the keyword search waits too (L3)


async def test_a_reset_keyword_search_holds_the_baseline_until_it_answered(admin_client, windows):
    assert (await admin_client.put("/api/vendor/follows/windows-dns", json={"enabled": True})).status_code == 200
    await vendor.run_round(force=True)
    key = "nvdkw:windows-dns"
    async with db.session() as s:
        st = await s.get(VendorFetch, key)
        assert st is not None and st.last_ok_at is not None
        assert await cleanup.reset_queries(s, [key]) == 1
        assert await cleanup.waiting(s) == {"windows-dns"}
        await s.execute(VendorEvent.__table__.delete())
        await s.execute(update(VendorFollow).values(baseline_at=None))
        await s.commit()
        vendor.reset()
        await vendor.evaluate_events(s)
        assert await s.scalar(select(func.count()).select_from(VendorEvent)) == 0  # held
    await vendor.run_round(force=True)  # the keyword search answers
    async with db.session() as s:
        assert await cleanup.waiting(s) == set()
        await vendor.evaluate_events(s)
        evs = list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "vuln")))
    assert evs and all(e.baseline for e in evs)


async def test_a_reset_keyword_search_the_round_no_longer_asks_holds_nothing(admin_client, monkeypatch):
    """Final review 0.1.51: the hold counts only while the round still runs the product's keyword search – after a
    catalogue change (distro/cloud, no CPE or CNA names any more) a reset nvdkw row never answers again, and the
    product would never get its baseline."""
    assert (await admin_client.put("/api/vendor/follows/panos", json={"enabled": True})).status_code == 200
    async with db.session() as s:
        s.add(VendorFetch(key="nvdkw:panos", cursor=cleanup.KW_RESET, failures=0, items=0))
        await s.commit()
        assert await cleanup.waiting(s) == {"panos"}
    monkeypatch.setattr(vendor, "_ready", lambda p, answered: True)  # its other queries answered
    monkeypatch.setattr(vendor, "_keyword_search", lambda p: False)  # the catalogue changed: no keyword search
    async with db.session() as s:
        vendor.reset()
        await vendor.evaluate_events(s)
        f = await s.scalar(select(VendorFollow).where(VendorFollow.product == "panos"))
    assert f.baseline_at is not None  # evaluated: its baseline is taken
