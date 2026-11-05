"""Security/bug review of the structured sources (0.1.26, branch structured-sources at 61fad2f): each test reproduced a
finding there (all failed on that commit) and pins its fix. Ids as in the review: H = high, M = medium, L = low.
"""

import hashlib
import io
import json
import struct
import tracemalloc
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app import csaf_providers, cvelist, db, osv, vendor
from app import vendor_catalog as catalog
from app.models import VendorAdvisory, VendorFetch
from app.news import NewsError
from tests.test_structured import ASA_DOC, CISCO, _adv, _cisco_routes, _csaf_round, _delta, _follow, _gh_routes, asa_recent, delta_zip, fx, net, record, structured_on  # noqa: F401

SCHNEIDER = next(p for p in csaf_providers.providers() if p["key"] == "schneider")


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _forged_tomcat_doc(track: str = "SEVD-2026-001-01", cve: str = "CVE-2026-11111") -> bytes:
    """A CSAF document on a Schneider Electric CSAF server that speaks about Apache Tomcat (another vendor): 10.1.15 'fixed'."""
    return json.dumps(
        {
            "document": {
                "category": "csaf_security_advisory",
                "csaf_version": "2.0",
                "title": "forged",
                "publisher": {"category": "vendor", "name": "Schneider Electric", "namespace": "https://www.se.com"},
                "tracking": {"id": track, "status": "final", "version": "1", "initial_release_date": "2020-01-01T00:00:00Z", "current_release_date": "2020-01-01T00:00:00Z",
                             "revision_history": [{"number": "1", "date": "2020-01-01T00:00:00Z", "summary": "x"}], "generator": {"engine": {"name": "x"}}},  # fmt: skip
                "distribution": {"tlp": {"label": "WHITE"}},
            },
            "product_tree": {
                "branches": [
                    {"category": "vendor", "name": "Apache Software Foundation", "branches": [{"category": "product_name", "name": "Apache Tomcat", "branches": [
                        {"category": "product_version", "name": "10.1.15", "product": {"name": "Apache Tomcat 10.1.15", "product_id": "T1"}},
                        {"category": "product_version", "name": "9.0.1", "product": {"name": "Apache Tomcat 9.0.1", "product_id": "T0"}}]}]},  # fmt: skip
                    {"category": "vendor", "name": "Schneider Electric", "branches": [{"category": "product_name", "name": "Some PLC", "branches": [
                        {"category": "product_version", "name": "1.0", "product": {"name": "Some PLC 1.0", "product_id": "S1"}}]}]},  # fmt: skip
                ]
            },
            "vulnerabilities": [{"cve": cve, "product_status": {"fixed": ["T1"], "known_affected": ["S1", "T0"]}}],
        }
    ).encode()


# ---------------------------------------------------------------- HIGH 1: a provider judges other vendors' products


def test_H1_provider_document_does_not_decide_for_another_vendors_product():
    """csaf_providers.advisory → vendor.link (entries_for: names only, vendor ignored) → group_verdict ("the vendor
    decides"): a document of the Schneider provider names "Apache Tomcat 10.1.15" as fixed and silences the CNA's
    "affected" for Tomcat 10.1.15 – a provider must only speak for the vendors csaf.yaml maps it to."""
    adv = csaf_providers.advisory(_forged_tomcat_doc(), SCHNEIDER, {"url": "https://www.se.com/ww/en/x.json", "tlp": "WHITE"})
    linked = vendor.link(adv, vendor.build_index())
    tomcat = catalog.product("tomcat")
    cna = cvelist.parse_record(record("CVE-2026-11111", "Apache Software Foundation", "Apache Tomcat", [{"version": "10.1.0", "lessThan": "10.1.16", "status": "affected", "versionType": "semver"}]))
    rec = _adv(cna["id"], "cvelist", "CVE-2026-11111", cna["data"])
    forged = _adv(adv["id"], "csaf", adv["ident"], adv["data"], cves=adv["cves"])
    honest = vendor.group_verdict(tomcat, vendor.groups_of([rec])[0], "10.1.15")
    assert honest.status == "affected"
    advs = [forged, rec] if "tomcat" in linked else [rec]  # what the Tomcat view gets from the store
    worst = max((vendor.group_verdict(tomcat, g, "10.1.15") for g in vendor.groups_of(advs)), key=lambda v: vendor.ORDER[v.status])
    assert "tomcat" not in linked and worst.status == "affected"


# ---------------------------------------------------------------- HIGH 2: one provider overwrites another's record


async def test_H2_provider_cannot_replace_the_record_of_another_provider(net, structured_on, admin_client):
    """Records are keyed csaf:<tracking id> without the provider: a document on the Schneider server with Cisco's
    tracking id replaces Cisco's advisory (sync_provider stores advisory() as it comes) – the Cisco finding is gone."""
    await _follow(admin_client, "cisco-asa", "9.20.2")
    recent = _ts(datetime.now(UTC) - timedelta(days=1))
    _cisco_routes(net, csv_=f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{recent}\n")
    await _csaf_round()
    forged = _forged_tomcat_doc(track="cisco-sa-asaftd-tunnel-dos-s6mgkb75")
    try:
        adv = csaf_providers.advisory(forged, SCHNEIDER, {"url": "https://www.se.com/ww/en/x.json", "tlp": "WHITE"})
    except NewsError:
        adv = None  # refused: fixed
    if adv is not None:
        async with db.session() as s:
            await vendor.store(s, [adv], await vendor.current_index(s))  # exactly what sync_provider does
    async with db.session() as s:
        a = await s.get(VendorAdvisory, "csaf:cisco-sa-asaftd-tunnel-dos-s6mgkb75", populate_existing=True)
        assert a is not None and a.data["publisher"] == "Cisco PSIRT (CSAF)"


# ---------------------------------------------------------------- MEDIUM: the watermark


async def test_M1_a_future_timestamp_does_not_freeze_the_watermark(net, structured_on, admin_client):
    """One changes.csv line dated 2099 moves the watermark to 2099: every later document is "older" and never read."""
    await _follow(admin_client, "cisco-asa", "9.20.2")
    body = fx("csaf_cisco_asa.json")
    _cisco_routes(net, csv_="2026/cisco-sa-typo.json,2099-10-30T00:00:00Z\n")
    net.add(CISCO + "2026/cisco-sa-typo.json", body)
    net.add(CISCO + "2026/cisco-sa-typo.json.sha512", hashlib.sha512(body).hexdigest())
    await _csaf_round()
    now = _ts(datetime.now(UTC))
    net.add(CISCO + "changes.csv", f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{now}\n2026/cisco-sa-typo.json,2099-10-30T00:00:00Z\n", headers={"ETag": '"c2"'})
    await _csaf_round()
    assert ASA_DOC in net.urls()


async def test_M2_one_document_failing_for_good_does_not_stall_the_provider(net, structured_on, admin_client):
    """A document that always answers 5xx (or times out – a large one on a slow line) is "passing": the watermark stays
    before it, so no newer document of the provider is ever read again."""
    await _follow(admin_client, "cisco-asa", "9.20.2")
    t1, t2 = _ts(datetime.now(UTC) - timedelta(days=3)), _ts(datetime.now(UTC) - timedelta(days=1))
    _cisco_routes(net, csv_=f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{t2}\n2026/cisco-sa-broken.json,{t1}\n")
    net.add(CISCO + "2026/cisco-sa-broken.json", b"oops", status=500)
    for _ in range(6):
        await _csaf_round()
    assert ASA_DOC in net.urls()


# ---------------------------------------------------------------- MEDIUM: cvelistV5


async def test_M3_day_rollover_race_loses_the_last_hour(net, structured_on, admin_client):
    """Live data (releases of 2026-10-28): cve_2026-10-28_0000Z was published 00:31:37Z, cve_2026-10-27_at_end_of_day
    only 00:37:54Z. A round in between gets 404 for the end-of-day release, skips it ("continue") and moves the cursor
    to 10-28 – the changes of 10-27 after the 2300Z zip are never read."""
    await _follow(admin_client, "panos")
    async with db.session() as s:
        s.add(VendorFetch(key=cvelist.DELTA_KEY, failures=0, items=0, cursor=json.dumps({"tag": "cve_2026-10-27_2300Z", "day": "2026-10-27", "at": "2300Z"})))
        await s.commit()
    _gh_routes(net, delta_zip(), tag="cve_2026-10-28_0000Z")
    rel = json.loads(fx("release_latest.json"))
    rel["tag_name"] = "cve_2026-10-28_0000Z"
    for a in rel["assets"]:
        a["name"] = a["name"].replace("2026-10-30", "2026-10-28").replace("0700Z", "0000Z")
        a["browser_download_url"] = f"{cvelist.DOWNLOAD}cve_2026-10-28_0000Z/{a['name']}"
    net.add(cvelist.LATEST, rel)
    net.add(next(a["browser_download_url"] for a in rel["assets"] if "_delta_" in a["name"]), delta_zip())
    await _delta()  # the end-of-day release is not there yet (404)
    eod = json.loads(fx("release_latest.json"))
    eod["tag_name"] = "cve_2026-10-27_at_end_of_day"
    eod["assets"] = [{"name": "2026-10-27_delta_CVEs_at_end_of_day.zip", "size": 100, "browser_download_url": f"{cvelist.DOWNLOAD}cve_2026-10-27_at_end_of_day/2026-10-27_delta_CVEs_at_end_of_day.zip"}]
    net.add(cvelist.BY_TAG.format(tag="cve_2026-10-27_at_end_of_day"), eod)
    net.add(eod["assets"][0]["browser_download_url"], delta_zip(record("CVE-2026-12700", "Palo Alto Networks", "PAN-OS", [{"version": "11.0.0", "lessThan": "11.0.9", "status": "affected"}])))
    rel["tag_name"] = "cve_2026-10-28_0100Z"  # the next round
    net.add(cvelist.LATEST, rel)
    await _delta()
    async with db.session() as s:
        assert await s.get(VendorAdvisory, "cvelist:CVE-2026-12700") is not None


async def test_M4_an_oversized_end_of_day_zip_does_not_block_the_source_for_days(net, structured_on, admin_client):
    """too_large of one missed day's zip fails the whole round before the newest zip is applied, and again every round
    until the day falls out of DAYS_BACK (3 days without cvelistV5)."""
    await _follow(admin_client, "panos", "10.2.7")
    async with db.session() as s:
        s.add(VendorFetch(key=cvelist.DELTA_KEY, failures=0, items=0, cursor=json.dumps({"tag": "cve_2026-10-29_1500Z", "day": "2026-10-29", "at": "1500Z"})))
        await s.commit()
    _gh_routes(net, delta_zip(json.loads(fx("cve_CVE-2024-3400.json"))))
    eod = json.loads(fx("release_latest.json"))
    eod["tag_name"] = "cve_2026-10-29_at_end_of_day"
    eod["assets"] = [{"name": "2026-10-29_delta_CVEs_at_end_of_day.zip", "size": cvelist.DELTA_LIMIT + 1, "browser_download_url": f"{cvelist.DOWNLOAD}cve_2026-10-29_at_end_of_day/2026-10-29_delta_CVEs_at_end_of_day.zip"}]
    net.add(cvelist.BY_TAG.format(tag="cve_2026-10-29_at_end_of_day"), eod)
    await _delta()
    async with db.session() as s:
        assert await s.get(VendorAdvisory, "cvelist:CVE-2024-3400") is not None


async def test_M5_a_passing_failure_is_not_remembered_for_a_week(net, structured_on):
    """cvelist.single: the `finally` stamps the CVE as asked also when the request failed (500, timeout, 429) – the
    docstring says only 404 is remembered; the record is then not asked again for SINGLE_EVERY (7 days)."""
    url = cvelist.raw_url("CVE-2024-3400")
    net.add(url, b"busy", status=500)
    async with db.session() as s:
        with pytest.raises(NewsError):
            await cvelist.single(s, "CVE-2024-3400", [1], vendor.build_index())
    net.add(url, fx("cve_CVE-2024-3400.json"))
    async with db.session() as s:
        got = await cvelist.single(s, "CVE-2024-3400", [1], vendor.build_index())
    assert got is not None and net.urls().count(url) == 2


def test_H3_read_delta_keeps_only_what_it_needs_in_memory():
    """read_delta parses and keeps EVERY record of the zip (the product filter runs afterwards in _apply): 5 000
    ordinary records (~8 MB zipped) keep ~48 MB; ~30 000 (a busy day, still below DELTA_LIMIT) exceed the app's
    512 MB mem_limit together with the rest. One bloated 7.5 MB record (CVE 5 allows big affected/versions/changes
    arrays and x_ fields) alone keeps ~55 MB. Measured: 20k records → 191 MB retained; 3 bloated → 164 MB.
    Fixed: the records are filtered while they are read (followed products, stored ids) – here none concerns one."""
    base = json.loads(fx("cve_CVE-2024-3400.json"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(5000):
            base["cveMetadata"]["cveId"] = f"CVE-2024-{100000 + i}"
            z.writestr(f"deltaCves/CVE-2024-{100000 + i}.json", json.dumps(base))
    blob = buf.getvalue()
    tracemalloc.start()
    followed = vendor.index_of([catalog.product("tomcat")])
    got = cvelist.read_delta(blob, followed, set())
    kept, _peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert got == ([], [], 0)
    del got
    assert kept < 16 * 1024 * 1024, f"read_delta keeps {kept / 1e6:.0f} MB for 5000 records"


def test_M6_withdrawn_osv_records_are_not_used():
    """OSV marks retracted records with `withdrawn` – osv.parse ignores it, so a withdrawn GHSA's ranges still turn a
    "possibly" into "not affected" (cve_verdict) or add a wrong fix."""
    doc = json.loads(fx("osv_GHSA-fccv-jmmp-qg76.json"))
    doc["withdrawn"] = "2026-10-01T00:00:00Z"
    rec = osv.parse(json.dumps(doc).encode())
    assert osv.to_advisory("CVE-2023-46589", [rec]) is None


# ---------------------------------------------------------------- LOW: parsers that escape their NewsError contract


def _corrupt_second_entry(blob: bytes, name: bytes) -> bytes:
    """Marks the stored entry `name` as deflated (method 8) in its local header and the central directory: its bytes
    are no deflate stream – zlib.error when it is read."""
    b = bytearray(blob)
    for sig, off in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
        i = 0
        while (i := b.find(sig, i)) >= 0:
            n_len = struct.unpack_from("<H", b, i + (26 if sig == b"PK\x03\x04" else 28))[0]
            start = i + (30 if sig == b"PK\x03\x04" else 46)
            if bytes(b[start : start + n_len]) == name:
                struct.pack_into("<H", b, i + off, 8)
            i += 4
    return bytes(b)


def test_L1_one_corrupt_zip_entry_is_one_bad_entry_not_a_failed_round():
    """zlib.error / LZMAError / OSError / NotImplementedError (fuzzer) from one entry escape read_delta – the whole
    delta (and every following round with the same cumulative zip) fails instead of counting it as unreadable."""
    good = record("CVE-2026-90001", "Example Corp", "Gateway", [{"version": "2.0", "lessThan": "2.4.1", "status": "affected"}])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("deltaCves/CVE-2026-90001.json"), json.dumps(good), compress_type=zipfile.ZIP_DEFLATED)
        z.writestr(zipfile.ZipInfo("deltaCves/CVE-2026-90002.json"), json.dumps(good).replace("90001", "90002"), compress_type=zipfile.ZIP_STORED)
    blob = _corrupt_second_entry(buf.getvalue(), b"deltaCves/CVE-2026-90002.json")
    advs, _rejected, bad = cvelist.read_delta(blob)
    assert [a["ident"] for a in advs] == ["CVE-2026-90001"] and bad == 1


@pytest.mark.parametrize("data", [b"2026/a.json,2026-10-30T00:00:00Z\r2026/b.json,2026-10-30T00:00:00Z", b'"' + b"a" * 200_000 + b'",2026-10-30T00:00:00Z'])
def test_L2_changes_csv_errors_are_format_errors(data):
    """csv.Error (a lone CR, a field > csv.field_size_limit) is no NewsError – the provider round fails as a crash."""
    cisco = next(p for p in csaf_providers.providers() if p["key"] == "cisco")
    try:
        csaf_providers.parse_changes(data, CISCO, cisco)
    except NewsError:
        pass


def test_L3_deep_nesting_in_a_cve_record_is_a_format_error():
    """parse_one: json.loads takes 5 000 levels (an x_ field of a CNA), src.clean() then raises RecursionError – no
    NewsError, so story_details._cvelist_for (catches NewsError only) aborts the story details round."""
    data = ('{"cveMetadata":{"cveId":"CVE-2024-0001"},"containers":{"cna":{"x_deep":' + "[" * 5000 + "]" * 5000 + "}}}").encode()
    try:
        cvelist.parse_one(data)
    except NewsError:
        pass


# ---------------------------------------------------------------- the further fixes (pinned with tests of their own)


def _cisco_doc(**changes) -> bytes:
    doc = json.loads(fx("csaf_cisco_asa.json"))
    for path, value in changes.items():
        d = doc["document"]
        *parts, last = path.split("__")
        for p in parts:
            d = d[p]
        d[last] = value
    return json.dumps(doc).encode()


CISCO_P = next(p for p in csaf_providers.providers() if p["key"] == "cisco")


def test_H2_a_document_of_another_publisher_or_id_kind_is_refused():
    """The publisher namespace must be the provider's domain; Siemens/Cisco (whose records the stories share) only
    under their own kind of tracking id; the other providers' records are namespaced (csaf:<provider>:<id>)."""
    entry = {"url": ASA_DOC, "tlp": ""}
    with pytest.raises(NewsError) as e:
        csaf_providers.advisory(_cisco_doc(publisher__namespace="https://evil.example"), CISCO_P, entry)
    assert e.value.category == "blocked" and "namespace" in e.value.detail
    with pytest.raises(NewsError) as e:
        csaf_providers.advisory(_cisco_doc(tracking__id="WID-SEC-W-2026-0001"), CISCO_P, entry)
    assert e.value.category == "blocked" and "tracking id" in e.value.detail
    ok = csaf_providers.advisory(fx("csaf_cisco_asa.json"), CISCO_P, entry)
    assert ok["id"] == "csaf:cisco-sa-asaftd-tunnel-dos-s6mgkb75" and ok["data"]["provider"] == "cisco" and ok["data"]["feed"] is True
    se = csaf_providers.advisory(_forged_tomcat_doc(), SCHNEIDER, {"url": "https://www.se.com/ww/en/x.json", "tlp": "WHITE"})
    assert se["id"] == "csaf:schneider:SEVD-2026-001-01" and se["ident"] == "SEVD-2026-001-01"


async def test_H2_a_stored_record_is_never_replaced_by_another_publisher(net, structured_on):
    """vendor.store: a CSAF record (here a BSI advisory from a story) is replaced only by its own publisher."""
    bsi = {"id": "csaf:WID-SEC-W-2026-0001", "source": "csaf", "ident": "WID-SEC-W-2026-0001", "title": "BSI", "summary": "", "url": "https://wid.cert-bund.de/x", "cves": [], "cvss": None,
           "severity": "high", "published_at": None, "updated_at": None, "data": {"products": [], "publisher": "BSI (CSAF)"}}  # fmt: skip
    async with db.session() as s:
        ix = await vendor.current_index(s)
        assert await vendor.store(s, [bsi], ix) == 1
        skipped: list[str] = []
        forged = {**bsi, "title": "forged", "data": {"products": [], "publisher": "Siemens ProductCERT (CSAF)", "provider": "siemens"}}
        assert await vendor.store(s, [forged], ix, skipped) == 0 and skipped == [bsi["id"]]
        assert await vendor.store(s, [{**bsi, "title": "BSI update"}], ix) == 1
        a = await s.get(VendorAdvisory, bsi["id"], populate_existing=True)
        assert a.title == "BSI update" and a.data["publisher"] == "BSI (CSAF)"


def test_H1_vendor_branch_must_match_in_a_provider_document():
    """Also among its own vendors' products: an entry counts only in the product's vendor branch."""
    asa = catalog.product("cisco-asa")
    doc = json.loads(fx("csaf_cisco_asa.json"))
    adv = csaf_providers.advisory(json.dumps(doc).encode(), CISCO_P, {"url": ASA_DOC, "tlp": ""})
    assert "cisco-asa" in vendor.link(adv, vendor.build_index())
    moved = {**adv["data"], "products": [{**p, "vendor": "Example Corp"} for p in adv["data"]["products"]]}
    assert not vendor.link({**adv, "data": moved}, vendor.build_index())
    assert vendor.evaluate(asa, "csaf", moved, "9.20.2") is None


async def test_M7_a_fresh_document_of_the_first_fill_is_notified(net, structured_on, admin_client):
    """The first fill of a provider: a document of the last FRESH_FILL days is notified as any other – only older
    ones are "Erstabruf" (shown, not sent)."""
    await _follow(admin_client, "cisco-asa", "9.20.2")
    now = datetime.now(UTC)
    async with db.session() as s:
        f = (await s.scalars(select(vendor.VendorFollow).where(vendor.VendorFollow.product == "cisco-asa"))).one()
        f.baseline_at = now - timedelta(days=100)
        for v in (await vendor.versions_of(s, [f.id]))[f.id]:
            v.baseline_at = now - timedelta(days=100)
        s.add(VendorFetch(key="nvd:a:cisco:adaptive_security_appliance_software", failures=0, items=0, last_ok_at=now))
        await s.commit()
    _cisco_routes(net, csv_=f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{_ts(now - timedelta(days=1))}\n", doc=asa_recent())
    await _csaf_round()
    async with db.session() as s:
        a = await s.get(VendorAdvisory, "csaf:cisco-sa-asaftd-tunnel-dos-s6mgkb75")
        assert a is not None and not a.data.get("initial")
        await vendor.evaluate_events(s, full=True)
        events = list(await s.scalars(select(vendor.VendorEvent).where(vendor.VendorEvent.kind == "vuln")))
    assert len(events) == 1 and not events[0].baseline


def _many_entries(n: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for i in range(n):
            z.writestr(f"{i}", b"")
    return buf.getvalue()


def test_L4_entry_count_is_read_before_the_zip_is_opened(monkeypatch):
    import time

    monkeypatch.setattr(cvelist, "MAX_ENTRIES", 1000)
    blob = _many_entries(5000)
    t = time.monotonic()
    tracemalloc.start()
    with pytest.raises(NewsError, match="too_large|entries"):
        cvelist.read_delta(blob)
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 1024 * 1024 and time.monotonic() - t < 0.5  # ZipFile() never parsed the central directory
    with pytest.raises(NewsError):
        cvelist.read_delta(b"PK\x05\x06" + b"\x00" * 10)  # a truncated record


SIEMENS_FEED = "https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"
SSA = "https://cert-portal.siemens.com/productcert/csaf/ssa-566512.json"


def _siemens_routes(net, *, hash_status: int = 200) -> bytes:
    from tests.test_structured import VFIX

    feed = json.loads(fx("rolie_siemens.json"))
    first = feed["feed"]["entry"][0]
    first["updated"] = _ts(datetime.now(UTC) - timedelta(days=1))
    first["link"] = [{"rel": "self", "href": SSA}, {"rel": "hash", "href": SSA + ".sha512"}]
    feed["feed"]["entry"] = [first]
    doc = (VFIX / "csaf_siemens.json").read_bytes()
    net.add(csaf_providers.AGGREGATOR, fx("aggregator.json"))
    net.add("https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json", fx("pm_siemens.json"))
    net.add(SIEMENS_FEED, feed)
    net.add(SSA, doc)
    net.add(SSA + ".sha512", hashlib.sha512(doc).hexdigest() + "  ssa-566512.json", status=hash_status)
    return doc


async def test_L5_a_listed_hash_that_cannot_be_fetched_keeps_the_document_out(net, structured_on, admin_client):
    """ROLIE lists the hash file: 403 → the document is not taken this round (retry list), never taken unchecked."""
    await _follow(admin_client, "siemens-sinec-nms")
    _siemens_routes(net, hash_status=403)
    await _csaf_round()
    async with db.session() as s:
        assert await s.get(VendorAdvisory, "csaf:SSA-566512") is None
        cur = json.loads((await s.get(VendorFetch, "csaf:siemens")).cursor)
        assert SSA in cur["retry"]
    _siemens_routes(net)
    await _csaf_round()
    async with db.session() as s:
        assert await s.get(VendorAdvisory, "csaf:SSA-566512") is not None
        assert json.loads((await s.get(VendorFetch, "csaf:siemens", populate_existing=True)).cursor)["retry"] == {}


async def test_L5_guessed_hash_files_are_asked_again_after_a_while(net, structured_on, admin_client):
    """No .sha512/.sha256 next to the document (404): the provider counts as one without – for HASH_AGAIN, not for good."""
    await _follow(admin_client, "cisco-asa")
    t1 = _ts(datetime.now(UTC) - timedelta(days=2))
    _cisco_routes(net, csv_=f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{t1}\n")
    del net.routes[ASA_DOC + ".sha512"]
    await _csaf_round()
    async with db.session() as s:
        st = await s.get(VendorFetch, "csaf:cisco")
        cur = json.loads(st.cursor)
        assert cur["hash"] == "none" and cur["hash_at"] and await s.get(VendorAdvisory, "csaf:cisco-sa-asaftd-tunnel-dos-s6mgkb75") is not None
        cur["hash_at"] = _ts(datetime.now(UTC) - csaf_providers.HASH_AGAIN - timedelta(hours=1))
        st.cursor = json.dumps(cur)
        await s.commit()
    body = fx("csaf_cisco_asa.json")
    second = CISCO + "2026/cisco-sa-second.json"
    net.add(CISCO + "changes.csv", f"2026/cisco-sa-second.json,{_ts(datetime.now(UTC))}\n", headers={"ETag": '"c2"'})
    net.add(second, body)
    net.add(second + ".sha512", hashlib.sha512(body).hexdigest())
    await _csaf_round()
    assert second + ".sha512" in net.urls()
    async with db.session() as s:
        assert json.loads((await s.get(VendorFetch, "csaf:cisco", populate_existing=True)).cursor)["hash"] == ".sha512"


async def test_L6_a_redirect_off_the_providers_domain_is_not_followed(net, structured_on, admin_client):
    import httpx

    await _follow(admin_client, "cisco-asa")
    _cisco_routes(net, csv_=f"2026/cisco-sa-asaftd-tunnel-dos-s6mgkb75.json,{_ts(datetime.now(UTC) - timedelta(days=1))}\n")
    net.add(ASA_DOC, lambda req: httpx.Response(302, headers={"Location": "https://evil.example/doc.json"}))
    net.add("https://evil.example/doc.json", fx("csaf_cisco_asa.json"))
    await _csaf_round()
    assert "https://evil.example/doc.json" not in net.urls()
    async with db.session() as s:
        assert await s.get(VendorAdvisory, "csaf:cisco-sa-asaftd-tunnel-dos-s6mgkb75") is None


def test_L7_the_advisory_link_stays_on_the_providers_domain():
    doc = json.loads(fx("csaf_cisco_asa.json"))
    doc["document"]["references"] = [{"category": "self", "summary": "x", "url": "https://evil.example/phish"}]
    adv = csaf_providers.advisory(json.dumps(doc).encode(), CISCO_P, {"url": ASA_DOC, "tlp": ""})
    assert adv["url"] == ASA_DOC
    good = csaf_providers.advisory(fx("csaf_cisco_asa.json"), CISCO_P, {"url": ASA_DOC, "tlp": ""})
    assert good["url"].startswith("https://sec.cloudapps.cisco.com/")


async def test_L8_old_single_lookups_are_pruned(net, structured_on):
    now = datetime.now(UTC)
    old, fresh = now - timedelta(days=40), now - timedelta(days=2)
    async with db.session() as s:
        for key, at in (("osvcve:CVE-2020-0001", old), ("cvelistcve:CVE-2020-0002", old), ("nvdcve:CVE-2020-0003", old), ("osvcve:CVE-2026-0004", fresh), ("csaf:cisco", old)):
            s.add(VendorFetch(key=key, failures=0, items=0, last_fetch_at=at))
        await s.commit()
        assert await vendor.prune_lookups(s, now) == 3
        left = set(await s.scalars(select(VendorFetch.key)))
    assert left == {"osvcve:CVE-2026-0004", "csaf:cisco"}


async def test_L9_a_switched_off_source_no_longer_decides(net, structured_on, admin_client, reader_client):
    """cvelistV5 off: its stored record stays stored but leaves the verdicts (and EPSS is not shown); on again: back."""
    await _follow(admin_client, "panos", "10.2.7")
    rec = cvelist.parse_record(json.loads(fx("cve_CVE-2024-3400.json")))
    async with db.session() as s:
        await vendor.store(s, [rec], await vendor.current_index(s))

    async def found() -> list[str]:
        return [f["id"] for f in (await reader_client.get("/api/vendor/products/panos")).json()["findings"]]

    assert "cvelist:CVE-2024-3400" in await found()
    d = (await admin_client.get("/api/admin/vendor")).json()["settings"]
    r = await admin_client.put("/api/admin/vendor", json={"enabled": True, "every_h": 6, "eol_every_h": 24, "cvelist": False, "rev": d["rev"]})
    assert r.status_code == 200 and not r.json()["cvelist"]
    assert "cvelist:CVE-2024-3400" not in await found()
    async with db.session() as s:
        assert await s.get(VendorAdvisory, "cvelist:CVE-2024-3400") is not None
    r = await admin_client.put("/api/admin/vendor", json={"enabled": True, "every_h": 6, "eol_every_h": 24, "cvelist": True, "rev": r.json()["rev"]})
    assert "cvelist:CVE-2024-3400" in await found()


# ---------------------------------------------------------------- cvelistV5: three slots a day (bandwidth)


def _release_at(day: str, at: str, blob: bytes, net) -> dict:  # noqa: ANN001
    rel = json.loads(fx("release_latest.json"))
    rel["tag_name"] = f"cve_{day}_at_end_of_day" if at == "end_of_day" else f"cve_{day}_{at}"
    name = f"{day}_delta_CVEs_at_{at}.zip"
    rel["assets"] = [{"name": name, "size": len(blob), "browser_download_url": f"{cvelist.DOWNLOAD}{rel['tag_name']}/{name}"}]
    net.add(rel["assets"][0]["browser_download_url"], blob)
    return rel


async def test_cvelist_reads_the_cumulative_zip_only_once_per_slot(net, structured_on, admin_client):
    await _follow(admin_client, "panos")
    async with db.session() as s:
        s.add(VendorFetch(key=cvelist.DELTA_KEY, failures=0, items=0, cursor=json.dumps({"tag": "cve_2026-10-30_0500Z", "day": "2026-10-30", "at": "0500Z"})))
        await s.commit()
    blob = delta_zip(json.loads(fx("cve_CVE-2024-3400.json")))
    for at, read in (("0600Z", False), ("1000Z", False), ("1100Z", True), ("1200Z", False), ("1700Z", True), ("2300Z", False)):
        rel = _release_at("2026-10-30", at, blob, net)
        net.add(cvelist.LATEST, rel)
        n = len(net.calls)
        await _delta()
        zips = [u for u in net.urls()[n:] if u.endswith(".zip")]
        assert bool(zips) is read, at
    # the day changes: the end-of-day zip once, today's 0000Z/0100Z zips not (no slot yet)
    eod = _release_at("2026-10-30", "end_of_day", blob, net)
    net.add(cvelist.BY_TAG.format(tag=eod["tag_name"]), eod)
    for at in ("0000Z", "0100Z"):
        net.add(cvelist.LATEST, _release_at("2026-10-31", at, blob, net))
        n = len(net.calls)
        await _delta()
        zips = [u for u in net.urls()[n:] if u.endswith(".zip")]
        assert zips == ([eod["assets"][0]["browser_download_url"]] if at == "0000Z" else []), at
    async with db.session() as s:
        cur = json.loads((await s.get(VendorFetch, cvelist.DELTA_KEY)).cursor)
    assert cur["day"] == "2026-10-31" and not cur.get("eod") and cur["at"] == ""


def test_cvelist_asks_github_only_when_a_slot_or_the_day_change_is_due():
    day = {"day": "2026-10-30", "at": "1100Z", "tag": "cve_2026-10-30_1100Z"}
    at = lambda h, m=30: datetime(2026, 10, 30, h, m, tzinfo=UTC)  # noqa: E731
    assert not cvelist._clock_due(day, at(12)) and not cvelist._clock_due(day, at(17, 10))
    assert cvelist._clock_due(day, at(17, 30)) and cvelist._clock_due(day, datetime(2026, 10, 31, 0, 30, tzinfo=UTC))
    assert cvelist._clock_due({}, at(3)) and cvelist._clock_due({**day, "eod": ["2026-10-29"]}, at(12))


def test_cisco_provider_speaks_for_duo_and_splunk():
    """csaf.yaml maps the Cisco provider to Cisco, Cisco (Duo) and Splunk (Cisco): its documents judge Duo and Splunk –
    in a Cisco or a Splunk branch – but never another vendor's branch, and no other provider speaks for them."""
    from app.vendor_match import entries_for

    duo, splunk = catalog.product("duo"), catalog.product("splunk")

    def doc(branch: str, name: str, provider: str = "cisco") -> dict:
        return {"provider": provider, "products": [{"vendor": branch, "name": name, "cpe": ""}]}

    assert entries_for(duo, doc("Cisco", "Cisco Duo"))
    assert entries_for(splunk, doc("Cisco", "Splunk Enterprise"))
    assert entries_for(splunk, doc("Splunk", "Splunk Enterprise"))
    assert not entries_for(splunk, doc("Cisco", "Cisco IOS XE Software"))
    assert not entries_for(splunk, doc("Example Corp", "Splunk Enterprise"))
    assert not entries_for(splunk, doc("Splunk", "Splunk Enterprise", provider="schneider"))
