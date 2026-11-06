"""Katalog-Pflege (app/catalog_check.py): the verdict per product, what is due, the NVD requests against a mocked NVD –
budget, host-wide pause, nothing without a followed product – and the admin API."""

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from app import catalog_check as cc
from app import db, vendor
from app import settings as settings_store
from app import vendor_catalog as catalog
from app.models import CatalogCheck, CatalogCpeCheck, VendorAdvisory, VendorAdvisoryProduct, VendorFetch, VendorFollow

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def _cpe_dict(*names: str, deprecated_by: str | None = None) -> dict:
    prods = [{"cpe": {"cpeName": f"cpe:2.3:{n}:*:*:*:*:*:*:*:*", "deprecated": bool(deprecated_by), "deprecatedBy": [{"cpeName": f"cpe:2.3:{deprecated_by}:*:*:*:*:*:*:*:*"}] if deprecated_by else []}} for n in names]
    return {"resultsPerPage": len(prods), "startIndex": 0, "totalResults": len(prods), "products": prods}


def _cves(total: int, cve: str | None = None, published: str | None = None) -> dict:
    vulns = [{"cve": {"id": cve, "published": published}}] if cve else []
    return {"resultsPerPage": len(vulns), "startIndex": 0, "totalResults": total, "vulnerabilities": vulns}


class FakeNvd:
    """CPE dictionary and CVE API: known CPEs with their CVEs (count, newest), everything else unknown."""

    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.status = 200
        self.known: dict[str, tuple[int, str | None, str | None]] = {}
        self.deprecated: dict[str, str] = {}

    def handler(self, req: httpx.Request) -> httpx.Response:
        assert req.url.host == "services.nvd.nist.gov", req.url
        self.calls.append(req)
        if self.status != 200:
            return httpx.Response(self.status, headers={"Retry-After": "3600"})
        if req.url.path.endswith("/cpes/2.0"):
            cpe = req.url.params["cpeMatchString"].removeprefix("cpe:2.3:")
            if cpe in self.deprecated:
                return httpx.Response(200, json=_cpe_dict(cpe, deprecated_by=self.deprecated[cpe]))
            return httpx.Response(200, json=_cpe_dict(cpe) if cpe in self.known else _cpe_dict())
        cpe = req.url.params["virtualMatchString"].removeprefix("cpe:2.3:")
        total, cve, pub = self.known.get(cpe, (0, None, None))
        start = int(req.url.params.get("startIndex") or 0)
        if not total:
            return httpx.Response(200, json=_cves(0))
        # NVD lists oldest first: only the last index carries the newest
        return httpx.Response(200, json=_cves(total, cve if start == total - 1 else "CVE-2001-0001", pub if start == total - 1 else "2001-01-01T00:00:00.000"))

    def cpes_asked(self) -> list[str]:
        return [c.url.params["cpeMatchString"].removeprefix("cpe:2.3:") for c in self.calls if c.url.path.endswith("/cpes/2.0")]


@pytest.fixture(autouse=True)
def reset(monkeypatch, tmp_path):
    vendor.reset()
    vendor._blocked.clear()
    cc._sent.clear()
    monkeypatch.setattr(catalog, "_data_file", lambda: tmp_path / "vendor_catalog.json")
    catalog._cache.stamp = ()
    yield
    vendor._blocked.clear()
    cc._sent.clear()


@pytest.fixture
def nvd(monkeypatch):
    f = FakeNvd()
    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(f.handler))
    return f


async def _follow(*keys: str) -> None:
    async with db.session() as s:
        for k in keys:
            s.add(VendorFollow(product=k, enabled=True))
        await s.commit()


def _row(cpe: str, **kw) -> CatalogCpeCheck:
    base = {"tried_at": NOW, "checked_at": NOW, "exists": True, "cve_total": 10, "newest_cve": "CVE-2026-1", "newest_at": NOW - timedelta(days=30), "source": "nvd"}
    return CatalogCpeCheck(cpe=cpe, **(base | kw))


P = {"key": "example-fw", "label": "Example FW", "vendor": "Example", "category": "firewall", "cpes": ["o:example:fw"], "scheme": "generic", "source": "overlay", "eol": None}


# ---------------------------------------------------------------- parsing


def test_parse_dictionary_and_cve_page():
    assert cc.parse_dictionary(json.dumps(_cpe_dict("a:veeam:one")).encode()) == (True, None)
    assert cc.parse_dictionary(json.dumps(_cpe_dict()).encode()) == (False, None)
    assert cc.parse_dictionary(json.dumps(_cpe_dict("a:old:thing", deprecated_by="a:new:thing")).encode()) == (True, "a:new:thing")
    total, cve, at = cc.parse_cve_page(json.dumps(_cves(42, "CVE-2026-1234", "2026-05-01T10:00:00.000")).encode())
    assert (total, cve, at) == (42, "CVE-2026-1234", datetime(2026, 5, 1, 10, tzinfo=UTC))
    assert cc.parse_cve_page(b'{"totalResults": 0, "vulnerabilities": []}') == (0, None, None)
    # the short form keeps NVD's escapes
    assert cc._short("cpe:2.3:a:veeam:veeam_backup_\\&_replication:*:*:*:*:*:*:*:*") == "a:veeam:veeam_backup_\\&_replication"


# ---------------------------------------------------------------- the verdict


def _v(p=P, rows=(), eol=None, followed=False, last_adv=None, adv_ok=False):
    return cc.verdict(p, {r.cpe: r for r in rows}, eol or {}, followed, last_adv, adv_ok, NOW)


def test_verdict_ok_unchecked_and_missing_cpe():
    assert _v(rows=[_row("o:example:fw")]) == ("ok", [])
    assert _v(rows=[]) == ("unchecked", [])
    status, reasons = _v(rows=[_row("o:example:fw", exists=False)])
    assert status == "error" and reasons == [{"code": "cpe_missing", "level": "error", "cpe": "o:example:fw"}]
    # one of two CPEs wrong: still an error, the other one counts for the CVE facts
    p2 = P | {"cpes": ["o:example:fw", "o:example:typo"]}
    status, reasons = _v(p2, [_row("o:example:fw"), _row("o:example:typo", exists=False)])
    assert status == "error" and [r["code"] for r in reasons] == ["cpe_missing"]


def test_verdict_deprecated_no_and_old_cves():
    status, reasons = _v(rows=[_row("o:example:fw", deprecated_by="o:example:fw_os")])
    assert status == "warn" and reasons[0] == {"code": "cpe_deprecated", "level": "warn", "cpe": "o:example:fw", "by": "o:example:fw_os"}
    # the successor is listed too (1Password: a:agilebits:1password → a:1password:1password): nothing to do
    both = P | {"cpes": ["o:example:fw", "o:example:fw_os"]}
    assert _v(both, [_row("o:example:fw", deprecated_by="o:example:fw_os"), _row("o:example:fw_os")]) == ("ok", [])
    assert _v(rows=[_row("o:example:fw", cve_total=0, newest_at=None, newest_cve=None)])[1] == [{"code": "no_cves", "level": "warn"}]
    status, reasons = _v(rows=[_row("o:example:fw", newest_at=NOW - timedelta(days=1200), newest_cve="CVE-2023-9")])
    assert status == "warn" and reasons[0]["code"] == "stale_cves" and reasons[0]["months"] == 39 and reasons[0]["cve"] == "CVE-2023-9"
    # two years without a CVE is normal for a small product (any CVE in the last three years counts)
    assert _v(rows=[_row("o:example:fw", newest_at=NOW - timedelta(days=750))]) == ("ok", [])
    # a cloud service or a product filtered out of shared CPEs: no CVE age check
    assert _v(P | {"cloud": True, "scheme": "cloud"}, [_row("o:example:fw", cve_total=0)])[0] == "ok"
    assert _v(P | {"filter": "KVM"}, [_row("o:example:fw", cve_total=0)])[0] == "ok"


def test_verdict_endoflife_and_nocpe_and_advisories():
    p = P | {"eol": "example-fw-os"}
    assert _v(p, [_row("o:example:fw")])[1] == [{"code": "eol_missing", "level": "error", "key": "example-fw-os"}]
    assert _v(p, [_row("o:example:fw")], eol={"example-fw-os": {"key": "example-fw-os"}})[0] == "ok"
    status, reasons = _v(p, [_row("o:example:fw")], eol={"example-fw-os": {"key": "example-fw-os", "cpes": ["o:othervendor:fw"]}})
    assert status == "warn" and reasons[0]["code"] == "eol_mismatch" and reasons[0]["theirs"] == "othervendor"
    nocpe = P | {"cpes": []}
    assert _v(nocpe, followed=False) == ("ok", [])
    assert _v(nocpe, followed=True) == ("warn", [{"code": "nocpe_followed", "level": "warn"}])
    adv = P | {"adv": "paloalto"}
    rows = [_row("o:example:fw")]
    assert _v(adv, rows, followed=True, last_adv=NOW - timedelta(days=40), adv_ok=True) == ("ok", [{"code": "adv_last", "level": "info", "source": "paloalto", "last": "2026-09-19"}])
    assert _v(adv, rows, followed=True, last_adv=None, adv_ok=True) == ("ok", [{"code": "adv_none", "level": "info", "source": "paloalto"}])
    status, reasons = _v(adv, rows, followed=True, last_adv=NOW - timedelta(days=800), adv_ok=True)
    assert status == "warn" and reasons[0]["code"] == "adv_stale"
    assert _v(adv, rows, followed=True, last_adv=None, adv_ok=False) == ("ok", [])  # the source never fetched: nothing to say
    # a distribution: no NVD question at all
    assert _v(P | {"scheme": "distro"}) == ("ok", [])


# ---------------------------------------------------------------- what is due


def test_due_order_and_intervals():
    rows = {
        "a:x:followed_old": _row("a:x:followed_old", tried_at=NOW - timedelta(days=8)),
        "a:x:followed_new": _row("a:x:followed_new", tried_at=NOW - timedelta(days=2)),
        "a:x:old": _row("a:x:old", tried_at=NOW - timedelta(days=40)),
        "a:x:older": _row("a:x:older", tried_at=NOW - timedelta(days=50)),
        "a:x:recent": _row("a:x:recent", tried_at=NOW - timedelta(days=20)),
        "a:x:failed": _row("a:x:failed", tried_at=NOW - timedelta(hours=7), error="http: HTTP 500"),
        "a:x:failed_now": _row("a:x:failed_now", tried_at=NOW - timedelta(hours=1), error="http: HTTP 500"),
    }
    all_cpes = [*rows, "a:x:never"]
    got = cc.due(rows, {"a:x:followed_old", "a:x:followed_new"}, all_cpes, NOW)
    assert got == ["a:x:followed_old", "a:x:never", "a:x:older", "a:x:old", "a:x:failed"]


# ---------------------------------------------------------------- the round against a mocked NVD


async def test_nothing_asked_without_followed_product_or_when_off(nvd):
    out = await cc.run()
    assert out["stopped"] == "nothing_followed" and nvd.calls == []
    await _follow("fortios")
    async with db.session() as s:
        cfg = await vendor.config(s)
        from app import settings as st

        await st.put(s, "vendor", {**cfg, "enabled": False})
        await s.commit()
    out = await cc.run()
    assert out["stopped"] == "off" and nvd.calls == []
    async with db.session() as s:
        # the local checks still ran: every catalogue product has a verdict
        assert await s.scalar(select(CatalogCheck).where(CatalogCheck.product == "fortios")) is not None


async def test_followed_first_with_local_cve_facts_then_budget(nvd, monkeypatch):
    monkeypatch.setattr(cc, "BUDGET_PER_HOUR", 7)
    nvd.known = {"o:fortinet:fortios": (900, "CVE-2026-1", "2026-10-01T00:00:00.000"), "a:fortinet:fortiproxy": (50, "CVE-2026-2", "2026-09-01T00:00:00.000")}
    await _follow("fortios")
    async with db.session() as s:
        # Vendor News fetched FortiOS completely: its CVE facts are known – only the dictionary is asked
        s.add(VendorFetch(key="nvd:o:fortinet:fortios", failures=0, items=900, last_ok_at=NOW, full_at=NOW))
        s.add(VendorAdvisory(id="nvd:CVE-2026-1", source="nvd", ident="CVE-2026-1", published_at=datetime(2026, 10, 1, tzinfo=UTC), data={}))
        await s.flush()
        s.add(VendorAdvisoryProduct(product="fortios", advisory_id="nvd:CVE-2026-1"))
        await s.commit()
    out = await cc.run()
    asked = nvd.cpes_asked()
    assert asked[0] == "o:fortinet:fortios"
    # 1 request for the followed CPE first; a step asks at most its share of the hour (here 3), the next unfollowed CPE
    # (up to 3 requests) waits for the next step
    assert len(nvd.calls) <= cc.step_share() and out["stopped"] == "budget" and out["requests"] == len(nvd.calls)
    async with db.session() as s:
        row = await s.get(CatalogCpeCheck, "o:fortinet:fortios")
        assert row.exists and row.source == "local" and row.cve_total == 900 and row.newest_cve == "CVE-2026-1"
        verdict = await s.get(CatalogCheck, "fortios")
        assert verdict.status == "ok" and verdict.followed
    # step by step until the hour's budget of 7 is spent: then a step asks nothing
    total = len(nvd.calls)
    for _ in range(5):
        nvd.calls.clear()
        out = await cc.run()
        assert len(nvd.calls) <= cc.step_share()
        total += len(nvd.calls)
    assert total <= 7 and nvd.calls == [] and out["stopped"] == "budget"


async def test_unknown_cpe_is_an_error_and_shows_in_the_drawer(nvd, admin_client, monkeypatch):
    monkeypatch.setattr(catalog, "OVERLAY", [*catalog.OVERLAY, {"key": "example-typo", "label": "Example Typo", "vendor": "Example", "category": "firewall", "cpes": ["o:example:no_such_product"]}])
    catalog._cache.stamp = ()
    await _follow("example-typo")
    out = await cc.run(manual=True)
    assert nvd.cpes_asked() == ["o:example:no_such_product"] and out["cpes"] == 1
    async with db.session() as s:
        v = await s.get(CatalogCheck, "example-typo")
        assert v.status == "error" and v.reasons == [{"code": "cpe_missing", "level": "error", "cpe": "o:example:no_such_product"}]
    d = (await admin_client.get("/api/vendor/products/example-typo")).json()
    assert d["catalog_check"]["status"] == "error" and d["catalog_check"]["reasons"][0]["code"] == "cpe_missing"
    ov = (await admin_client.get("/api/admin/vendor/catalog-check")).json()
    item = next(i for i in ov["items"] if i["product"] == "example-typo")
    assert item["followed"] and item["status"] == "error" and ov["items"][0]["product"] == "example-typo"  # followed errors first
    assert ov["last_manual_at"] and ov["budget_per_hour"] == cc.BUDGET_PER_HOUR and ov["cpes"]["checked"] >= 1


async def test_rate_limit_pauses_the_host_and_keeps_cpes_due(nvd):
    nvd.status = 429
    await _follow("fortios")
    out = await cc.run(manual=True)
    assert out["stopped"] == "paused" and len(nvd.calls) == 1 and vendor.blocked_for("services.nvd.nist.gov") > 0
    async with db.session() as s:
        row = await s.get(CatalogCpeCheck, "o:fortinet:fortios")
        assert row.checked_at is None and row.error.startswith("rate_limited")
    nvd.calls.clear()
    out = await cc.run()
    assert nvd.calls == [] and out["stopped"] == "paused"  # nothing asked into the pause


@pytest.mark.parametrize("status", [500, 503, 403])
async def test_an_nvd_failing_on_its_side_ends_the_step_at_the_first_answer(nvd, status):
    """0.1.50: a failed request returned 0 "asked" – the budget never filled, and an NVD answering 5xx (or refusing, 403)
    was asked about every due CPE in one step (37 requests in a row in the bug hunt, budget 4). Now the step ends at
    the first failure and the request counts."""
    nvd.status = status
    await _follow("fortios")
    out = await cc.run()
    # 403 and 503 are the NVD's "slow down": the host pauses ("paused") – either way one request, then the end
    assert len(nvd.calls) == 1 and out["requests"] == 1 and out["stopped"] == ("unreachable" if status == 500 else "paused")
    async with db.session() as s:
        row = await s.get(CatalogCpeCheck, "o:fortinet:fortios")
        assert row.checked_at is None and row.error  # due again after RETRY_AFTER_ERROR
        assert len((await settings_store.get(s, cc.SETTING))["sent"]) == 1  # the failed request counts for the hour


async def test_an_unreachable_nvd_ends_the_step_and_never_exceeds_the_budget(monkeypatch):
    calls: list[httpx.Request] = []

    def down(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        raise httpx.ConnectError("All connection attempts failed", request=req)

    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(down))
    await _follow("fortios", "typo3", "gitlab")
    for _ in range(10):  # ten steps within the hour: never more than the hour's budget, each step stops at once
        before = len(calls)
        out = await cc.run(manual=True)
        assert len(calls) - before <= 1 and out["stopped"] in ("unreachable", "budget")
    assert len(calls) == 10 <= cc.BUDGET_PER_HOUR
    for _ in range(5):  # the scheduled steps: their share of what is left of the hour – the failed requests count
        await cc.run()
    assert 10 < len(calls) <= cc.BUDGET_PER_HOUR


async def test_a_cpe_unknown_to_the_nvd_does_not_end_the_step(nvd, monkeypatch):
    """A 4xx about one CPE (not a refusal) is that CPE's error – the step goes on with the next."""
    real = nvd.handler

    def handler(req: httpx.Request) -> httpx.Response:
        if "fortios" in str(req.url):
            nvd.calls.append(req)
            return httpx.Response(404)
        return real(req)

    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(handler))
    await _follow("fortios", "typo3")
    out = await cc.run(manual=True)
    assert out["stopped"] is None and out["cpes"] >= 2 and out["requests"] == len(nvd.calls)


async def test_the_stored_requests_count_once(nvd):
    """0.1.50: memory (exact times) and the stored copy (rounded to 0.1 s) were merged as a set of different values –
    every request counted twice from the next step on, the hourly budget was effectively half."""
    await _follow("fortios")
    await cc.run()
    first = len(nvd.calls)
    for _ in range(3):  # further steps (nothing new to ask once the budget of the step is used): no growth
        await cc.run()
    async with db.session() as s:
        state = await settings_store.get(s, cc.SETTING)
    assert len(state["sent"]) == len(nvd.calls) and state["sent_v"] == cc.SENT_V and len(cc._sent) == len(nvd.calls) >= first


async def test_a_doubled_list_of_older_versions_is_cleaned_up(nvd):
    now = __import__("time").time()
    legacy = [round(now - 100, 1), round(now - 100, 1), round(now - 50, 1), round(now - 50, 1)]
    async with db.session() as s:
        await settings_store.put(s, cc.SETTING, {"sent": legacy})  # 0.1.50: each request twice, no "sent_v"
        await s.commit()
    cc.merge_sent(await _state())
    assert list(cc._sent) == sorted(set(legacy))
    # the new form keeps two requests of the same millisecond
    cc._sent.clear()
    cc.merge_sent({"sent": [now, now], "sent_v": cc.SENT_V})
    assert len(cc._sent) == 2


async def _state() -> dict:
    async with db.session() as s:
        return await settings_store.get(s, cc.SETTING)


async def test_vendor_round_running_means_no_request(nvd):
    await _follow("fortios")
    out = await cc.run(vendor_busy=True)
    assert out["stopped"] == "vendor_busy" and nvd.calls == []


async def test_gone_endoflife_patch_is_reported(monkeypatch):
    monkeypatch.setattr(catalog, "OVERLAY", [*catalog.OVERLAY, {"key": "gone-from-eol", "label": None, "vendor": None, "category": "web", "cpes": []}])
    catalog._cache.stamp = ()
    async with db.session() as s:
        await cc.evaluate(s)
        v = await s.get(CatalogCheck, "gone-from-eol")
        assert v.status == "error" and v.reasons[0]["code"] == "eol_missing"
        # evaluating again changes nothing
        assert await cc.evaluate(s) == 0


async def test_bundled_catalogue_has_no_gone_patches():
    cat = catalog.load()
    assert [o["key"] for o in cc.gone_patches({r["key"]: r for r in cat["eol_products"]})] == []


# ---------------------------------------------------------------- API


async def test_api_admin_only_rate_limited_and_off(admin_client, reader_client, monkeypatch):
    assert (await reader_client.get("/api/admin/vendor/catalog-check")).status_code == 403
    assert (await reader_client.post("/api/admin/vendor/catalog-check")).status_code == 403
    from app import vendor_api

    monkeypatch.setattr(vendor_api, "_last_check", [-1e9])
    assert (await admin_client.post("/api/admin/vendor/catalog-check")).status_code == 200
    assert (await admin_client.post("/api/admin/vendor/catalog-check")).status_code == 429
    async with db.session() as s:
        from app import settings as st

        await st.put(s, "vendor", {**(await vendor.config(s)), "enabled": False})
        await s.commit()
    monkeypatch.setattr(vendor_api, "_last_check", [-1e9])
    assert (await admin_client.post("/api/admin/vendor/catalog-check")).status_code == 409
    body = (await admin_client.get("/api/admin/vendor/catalog-check")).json()
    assert set(body["counts"]) == {"error", "warn", "ok", "unchecked"} and body["catalog_version"] == catalog.catalog_version()


async def test_budget_survives_a_restart_and_is_spread_over_the_hour(nvd, monkeypatch):
    """Lead's 0.1.20 leftover: the hourly NVD budget lived only in memory (a restart started a fresh hour) and a step
    could spend the whole hour's budget at once. Now it is kept in the settings and each step asks its share."""
    nvd.known = {}
    await _follow("fortios")
    out = await cc.run()
    assert 0 < out["requests"] <= cc.step_share() == 4 and out["stopped"] == "budget"  # 20 per hour, a step every 10 min
    first = len(nvd.calls)
    async with db.session() as s:
        assert len((await settings_store.get(s, cc.SETTING))["sent"]) == first
    monkeypatch.setattr(cc, "BUDGET_PER_HOUR", first)  # this hour's budget is now spent
    cc._sent.clear()  # a restart: nothing in memory
    nvd.calls.clear()
    out = await cc.run()
    assert nvd.calls == [] and out["stopped"] == "budget"
    async with db.session() as s:  # an hour later the old requests no longer count
        state = await settings_store.get(s, cc.SETTING)
        await settings_store.put(s, cc.SETTING, {**state, "sent": [x - 3700 for x in state["sent"]]})
        await s.commit()
    cc._sent.clear()
    monkeypatch.setattr(cc, "BUDGET_PER_HOUR", 20)
    out = await cc.run()
    assert len(nvd.calls) > 0
