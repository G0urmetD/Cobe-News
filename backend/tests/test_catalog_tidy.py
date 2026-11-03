"""Catalogue tidy-up (catalogue 2026.11.03-1): release lines only (Firefox ESR, Jenkins LTS), Exchange's ExSetup form
with leading zeros, consistent Mozilla labels, the relink of stored advisories after a catalogue change (quiet – no
flood of notifications), Dovecot through Open-Xchange (CSAF provider, CNA names, CPE), CPEs with an escaped colon
(mailcow: dockerized) and Dell's iDRAC9/iDRAC10 names as Dell's CVE records write them."""

import json

import pytest
from sqlalchemy import select, update

from app import catalog_care, catalog_data, csaf_providers, cvelist, db, story_details, vendor, version_input
from app import settings as settings_store
from app import vendor_catalog as catalog
from app.models import VendorAdvisoryProduct, VendorEvent, VendorFollow
from app.news import NewsError
from app.vendor_match import cpe_fields, cpe_vendor_product, entries_for, evaluate
from tests.test_structured import record
from tests.test_vendor_service import _dispatch, _follow, _fresh_pan, _round, _webhook_rule, hooks, sites, vendor_reset  # noqa: F401

OX = next(p for p in csaf_providers.providers() if p["key"] == "openxchange")


# ---------------------------------------------------------------- 1. release lines only


@pytest.mark.parametrize(
    ("key", "text", "ok"),
    [
        ("firefox-esr", "134.0", False),  # a release-channel version – no ESR line
        ("firefox-esr", "154.0", False),  # between the newest ESR (153) and the newest Firefox (159)
        ("firefox-esr", "140.4.0esr", True),
        ("firefox-esr", "153.1.0", True),
        ("firefox-esr", "115.30.0esr", True),
        ("firefox-esr", "68.12.0esr", True),  # older than every line endoflife.date lists: not judged
        ("firefox-esr", "160.0", True),  # a line newer than the release data knows: never refused
        ("firefox", "134.0", True),  # the release channel keeps the lenient check
        ("jenkins", "2.492.2", True),
        ("jenkins", "2.500.1", False),  # no LTS line 2.500
        ("jenkins", "2.569.1", True),  # newer than the newest LTS line: the next one may be out already
        ("jenkins", "2.300.1", True),  # older than the release data
    ],
)
def test_lines_only_refuses_versions_on_no_line_of_the_product(key, text, ok):
    c = version_input.check(catalog.product(key), text)
    assert c.ok is ok, c
    if not ok:
        assert c.reason == "implausible" and c.lines
        assert c.lines[0] == ("153" if key == "firefox-esr" else "2.568")


def test_lines_only_the_hint_names_the_products_own_lines():
    c = version_input.check(catalog.product("firefox-esr"), "134.0")
    assert set(c.lines) <= {"153", "140", "128", "115", "102", "91", "78"} and "134" not in c.lines


def test_lines_only_stored_version_is_not_compared():
    """A version stored before the rule: not compared ("möglicherweise betroffen"), never dropped."""
    p = catalog.product("firefox-esr")
    assert version_input.effective(p, "134.0") is None
    assert version_input.effective(p, "140.4.0esr") == "140.4.0esr"


def test_lines_only_all_and_without_release_data(monkeypatch):
    rels = {"x-lines": [{"name": "3.2", "latest": "3.2.4"}, {"name": "3.0", "latest": "3.0.9"}, {"name": "2.8", "latest": "2.8.1"}]}
    monkeypatch.setattr(catalog, "releases", lambda k: list(rels.get(k) or []))
    p = {"key": "x", "label": "X", "vendor": "Y", "scheme": "generic", "eol": "x-lines", "lines_only": "all"}
    assert not version_input.check(p, "3.1.0").ok  # no line 3.1
    assert version_input.check(p, "3.0.2").ok and version_input.check(p, "3.4.0").ok and version_input.check(p, "2.6.0").ok
    assert version_input.check(p | {"lines_only": None}, "3.1.0").ok  # without the flag: lenient as before
    assert version_input.check(p | {"eol": "none"}, "3.1.0").ok  # no release data: nothing to judge by
    # "lts" on data that marks no line LTS: no own lines – lenient
    assert version_input.check(p | {"lines_only": "lts"}, "3.1.0").ok


def test_lines_only_is_checked_in_the_catalogue():
    assert catalog.product("firefox-esr")["lines_only"] == "lts" and catalog.product("jenkins")["lines_only"] == "lts"
    assert not catalog.product("firefox").get("lines_only") and not catalog.product("jenkins-weekly").get("lines_only")
    with pytest.raises(Exception):  # noqa: B017, PT011 - pydantic's ValidationError: only lts / all
        catalog_data.Product.model_validate({"key": "x-y", "label": "X", "vendor": "Y", "lines_only": "yes"})


# ---------------------------------------------------------------- 2. Exchange ExSetup


@pytest.mark.parametrize(("text", "want"), [("15.02.1748.024", "15.2.1748.24"), ("15.02.2562.017", "15.2.2562.17"), ("15.01.2507.044", "15.1.2507.44"), ("15.2.1748.24", "15.2.1748.24")])
def test_exsetup_leading_zeros_are_stored_as_the_build_table_writes_them(text, want):
    p = catalog.product("msexchange")
    c = version_input.check(p, text)
    assert c.ok and c.value == want and c.mapped is (text != want)
    assert version_input.effective(p, text) == want


def test_leading_zeros_only_touch_plain_numbers():
    fn = version_input.NORMALIZE["leading_zeros"]
    assert fn("2019 CU15") == "2019 CU15" and fn("8u411") == "8u411" and fn("007") == "007" and fn("1.0") == "1.0"


async def test_exsetup_preview_shows_the_normalised_build(admin_client):
    r = (await admin_client.get("/api/vendor/validate", params={"product": "msexchange", "version": "15.02.1748.024"})).json()
    assert r["ok"] and r["normalized"] == "15.2.1748.24" and r["mapped"] is True
    await _follow(admin_client, "msexchange", "15.02.1748.024")
    v = (await admin_client.get("/api/vendor/products/msexchange")).json()["versions"][0]
    assert v["version"] == "15.2.1748.24"


# ---------------------------------------------------------------- 3. labels


def test_mozilla_labels_are_consistent_and_keys_stay():
    labels = {k: catalog.product(k)["label"] for k in ("firefox", "firefox-esr", "thunderbird")}
    assert labels == {"firefox": "Mozilla Firefox", "firefox-esr": "Mozilla Firefox ESR", "thunderbird": "Mozilla Thunderbird"}
    ff = catalog.product("firefox")
    assert ff["vendor"] == "Mozilla" and ff["eol"] == "firefox" and ff["kw"] == ["Firefox"]  # NVD's keyword search: still "Firefox"
    assert ff["cpes"] == ["a:mozilla:firefox"] and ff["belongs"][0]["to"] == "firefox-esr"
    assert vendor._keyword_words(ff) == "Firefox"


# ---------------------------------------------------------------- 4. relink after a catalogue change


def _hidden_pan(ident: str) -> dict:
    """A fresh PAN-OS advisory (published two hours ago) stored before the catalogue linked it: as if its names were new."""
    return _fresh_pan(ident, "< 11.2.4-h30, < 11.2.16", ">= 11.2.4-h30, >= 11.2.16")


async def _links(product: str) -> dict[str, bool]:
    async with db.session() as s:
        return {a: q for a, q in (await s.execute(select(VendorAdvisoryProduct.advisory_id, VendorAdvisoryProduct.quiet).where(VendorAdvisoryProduct.product == product))).all()}


async def test_relink_after_catalogue_change_is_quiet_and_once(admin_client, reader_client, sites, hooks, monkeypatch):
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _webhook_rule(admin_client, ["vendor_vuln"])
    await _round()  # baseline; the relink of this catalogue version ran in the round (nothing to add)
    async with db.session() as s:
        state = await settings_store.get(s, vendor.RELINK_STATE)
        assert state["version"] == catalog.catalog_version() and state["complete"] and "panos" in state["done"]
        assert await vendor.relink_catalog(s) is None  # done for this version
        # an advisory the old catalogue did not link to panos (stored with an index without it)
        await vendor.store(s, [_hidden_pan("CVE-2026-8888")], vendor.index_of([]))
    assert "paloalto:CVE-2026-8888" not in await _links("panos")
    await _dispatch()
    hooks.clear()

    # a new catalogue version: the stored advisory is linked – quietly
    async with db.session() as s:
        await settings_store.put(s, vendor.RELINK_STATE, {"version": "2000.01.01-1", "done": ["panos"], "complete": True})
        await s.commit()
        assert await vendor.relink_catalog(s) == 1
        assert await vendor.relink_catalog(s) is None
    assert (await _links("panos"))["paloalto:CVE-2026-8888"] is True
    d = (await reader_client.get("/api/vendor/products/panos")).json()
    f = next(x for x in d["findings"] if x["id"] == "paloalto:CVE-2026-8888")
    assert f["versions"][0]["status"] == "affected" and f["quiet"] is True  # shown …
    async with db.session() as s:
        assert await vendor.evaluate_events(s) == 0  # … not sent
        ev = (await s.scalars(select(VendorEvent).where(VendorEvent.key.like("%CVE-2026-8888%")))).one()
        assert ev.baseline
    await _dispatch()
    assert hooks == []

    # a normal new advisory still notifies, and a later store of the relinked one links it as an ordinary link
    async with db.session() as s:
        await vendor.store(s, [_hidden_pan("CVE-2026-7777")], vendor.build_index())
        assert await vendor.evaluate_events(s) == 1
        again = _hidden_pan("CVE-2026-8888") | {"title": "PAN-OS: Example vulnerability (updated)"}
        await vendor.store(s, [again], vendor.build_index())
        assert await vendor.evaluate_events(s) == 0  # notified as baseline before – not again
    assert (await _links("panos"))["paloalto:CVE-2026-8888"] is False
    await _dispatch()
    assert len(hooks) == 1 and "CVE-2026-7777" in hooks[0].content.decode()


async def test_relink_without_quiet_would_notify(admin_client, sites, hooks):
    """Why quiet: the same relink as an ordinary link makes a fresh old-stored advisory a notification."""
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    async with db.session() as s:
        await vendor.store(s, [_hidden_pan("CVE-2026-8889")], vendor.index_of([]))
        assert await vendor.relink(s, catalog.product("panos")) == 1
        assert await vendor.evaluate_events(s) == 1


async def test_relink_catalog_goes_in_chunks_and_on_after_a_restart(admin_client, sites, monkeypatch):
    for k in ("panos", "panorama", "fortios"):
        await _follow(admin_client, k)
    monkeypatch.setattr(vendor, "RELINK_PRODUCTS", 2)
    async with db.session() as s:
        await s.execute(update(VendorFollow).values(enabled=False).where(VendorFollow.product == "fortios"))  # switched off: relinked too
        await s.commit()
        assert await vendor.relink_catalog(s) == 0
        st = await settings_store.get(s, vendor.RELINK_STATE)
        assert st["done"] == ["fortios", "panorama"] and st["complete"] is False
    vendor.reset()  # a restart: the state is in the database
    async with db.session() as s:
        assert await vendor.relink_catalog(s) == 0
        st = await settings_store.get(s, vendor.RELINK_STATE)
        assert st["done"] == ["fortios", "panorama", "panos"] and st["complete"] is True
        assert await vendor.relink_catalog(s) is None


async def test_relink_failure_never_stops_the_round(admin_client, sites, monkeypatch):
    await _follow(admin_client, "panos", "11.2.4-h23")

    async def boom(db_):  # noqa: ANN001
        raise RuntimeError("x")

    monkeypatch.setattr(vendor, "relink_catalog", boom)
    out = await _round()
    assert "relink:catalog" not in out
    assert any(k.startswith("paloalto:") for k in out)


# ---------------------------------------------------------------- 5. Dovecot through Open-Xchange


def _ox_dovecot_doc(tlp: str = "WHITE") -> bytes:
    """A CSAF document in the form of Open-Xchange's Dovecot advisories (oxdc-adv-…): vendor branch "Open-Xchange GmbH",
    products "OX Dovecot Pro" and "OX Dovecot CE", ranges as vers:generic with the CPE a:open-xchange:dovecot."""

    def rng(pid: str, text: str) -> dict:
        return {"category": "product_version_range", "name": text, "product": {"name": text, "product_id": pid, "product_identification_helper": {"cpe": "cpe:2.3:a:open-xchange:dovecot:*:*:*:*:*:*:*:*"}}}

    def ver(pid: str, text: str) -> dict:
        return {"category": "product_version", "name": text, "product": {"name": text, "product_id": pid, "product_identification_helper": {"cpe": f"cpe:2.3:a:open-xchange:dovecot:{text}:*:*:*:*:*:*:*"}}}

    return json.dumps(
        {
            "document": {
                "category": "csaf_security_advisory",
                "csaf_version": "2.0",
                "title": "OX Dovecot security advisory (test)",
                "publisher": {"category": "vendor", "name": "Open-Xchange GmbH", "namespace": "https://open-xchange.com/"},
                "distribution": {"tlp": {"label": tlp}},
                "tracking": {"id": "OXDC-ADV-2026-9001", "status": "final", "version": "1", "initial_release_date": "2026-10-28T00:00:00+00:00", "current_release_date": "2026-10-28T00:00:00+00:00",
                             "revision_history": [{"number": "1", "date": "2026-10-28T00:00:00+00:00", "summary": "first"}]},  # fmt: skip
            },
            "product_tree": {
                "branches": [
                    {"category": "vendor", "name": "Open-Xchange GmbH", "branches": [
                        {"category": "product_name", "name": "OX Dovecot Pro", "branches": [rng("PRO_A", "vers:generic/>=3.0.0|<3.0.7"), ver("PRO_F", "3.0.7")]},
                        {"category": "product_name", "name": "OX Dovecot CE", "branches": [rng("CE_A", "vers:generic/>=2.3.0|<2.4.5"), ver("CE_F", "2.4.5")]},
                    ]},  # fmt: skip
                ]
            },
            "vulnerabilities": [{"cve": "CVE-2026-90901", "product_status": {"known_affected": ["PRO_A", "CE_A"], "first_fixed": ["PRO_F", "CE_F"]}, "scores": [{"cvss_v3": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "version": "3.1"}, "products": ["CE_A"]}]}],
        }
    ).encode()


def test_dovecot_is_spoken_for_by_the_open_xchange_provider():
    dov = catalog.product("dovecot")
    assert dov["vendor"] == "Dovecot (Open-Xchange)" and dov["eol"] == "dovecot" and "a:open-xchange:dovecot" in dov["cpes"]
    assert [p["key"] for p in csaf_providers.providers_for(dov)] == ["openxchange"]
    assert "openxchange" in {p["key"] for p in csaf_providers.needed([dov])}


def test_dovecot_finding_from_an_open_xchange_csaf_document():
    adv = csaf_providers.advisory(_ox_dovecot_doc(), OX, {"url": "https://documentation.open-xchange.com/dovecot/security/advisories/csaf/2026/x.json", "tlp": ""})
    assert adv["id"] == "csaf:openxchange:OXDC-ADV-2026-9001"
    dov = catalog.product("dovecot")
    # the catalogue's Dovecot is the community edition (endoflife.date's 2.3/2.4): OX Dovecot Pro (3.x) shares the CPE
    # but is another product – its "3.0.0 … 3.0.7" would make every 2.4 build "possibly affected"
    assert {e["name"] for e in entries_for(dov, adv["data"])} == {"OX Dovecot CE"}
    assert "dovecot" in vendor.link(adv, vendor.build_index())
    assert "open-xchange" not in vendor.link(adv, vendor.build_index())  # OX App Suite is another product
    assert evaluate(dov, "csaf", adv["data"], "2.4.1").status == "affected"
    assert evaluate(dov, "csaf", adv["data"], "2.4.5").status == "not_affected"


def test_open_xchange_documents_labelled_green_are_not_read():
    """Open-Xchange labels its CSAF documents TLP:GREEN (checked 2026-11-03, App Suite and Dovecot): the provider reads
    only TLP:WHITE/CLEAR – such a document is refused, never stored. Dovecot's findings then come from the CVE records
    (CNA "OX") and NVD (a:open-xchange:dovecot)."""
    with pytest.raises(NewsError) as e:
        csaf_providers.advisory(_ox_dovecot_doc("GREEN"), OX, {"url": "https://documentation.open-xchange.com/dovecot/x.json", "tlp": ""})
    assert e.value.category == "blocked"


def test_dovecot_cve_records_of_open_xchange():
    ce = cvelist.parse_record(record("CVE-2026-90902", "Open-Xchange GmbH", "OX Dovecot CE", [{"version": "0", "lessThanOrEqual": "2.3.21", "status": "affected", "versionType": "semver"}]))
    assert "dovecot" in vendor.link(ce, vendor.build_index())
    dov = catalog.product("dovecot")
    assert evaluate(dov, "cvelist", ce["data"], "2.3.20").status == "affected"
    assert evaluate(dov, "cvelist", ce["data"], "2.4.1").status == "not_affected"
    pro = cvelist.parse_record(record("CVE-2026-90905", "Open-Xchange GmbH", "OX Dovecot Pro", [{"version": "3.0.0", "lessThan": "3.0.7", "status": "affected", "versionType": "semver"}]))
    assert "dovecot" not in vendor.link(pro, vendor.build_index())


def test_dovecot_nvd_pro_edition_does_not_count():
    """NVD lists a:open-xchange:dovecot only with sw_edition pro (OX Dovecot Pro); the community edition is
    a:dovecot:dovecot – a Pro configuration says nothing about Dovecot CE."""
    dov = catalog.product("dovecot")

    def nvd(crit: str) -> dict:
        return {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": crit, "versionEndExcluding": "3.0.7"}]}]}]}

    assert evaluate(dov, "nvd", nvd("cpe:2.3:a:open-xchange:dovecot:*:*:*:*:pro:*:*:*"), "2.4.1") is None
    assert evaluate(dov, "nvd", nvd("cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*"), "2.4.1").status == "affected"
    assert evaluate(dov, "nvd", nvd("cpe:2.3:a:open-xchange:dovecot:*:*:*:*:*:*:*:*"), "2.4.1").status == "affected"


# ---------------------------------------------------------------- 6. escaped colon in a CPE (mailcow: dockerized)


def test_cpe_fields_keep_an_escaped_colon_in_its_field():
    assert cpe_fields("a:mailcow:mailcow\\:_dockerized") == ["a", "mailcow", "mailcow:_dockerized"]
    assert cpe_fields("cpe:2.3:a:mailcow:mailcow\\:_dockerized:2025-01a:*:*:*:*:*:*:*")[:4] == ["a", "mailcow", "mailcow:_dockerized", "2025-01a"]
    assert cpe_vendor_product("cpe:/a:mailcow:mailcow\\:_dockerized") == "mailcow:mailcow:_dockerized"
    assert cpe_vendor_product("a:notepad-plus-plus:notepad\\+\\+") == "notepad-plus-plus:notepad++"
    assert cpe_vendor_product("a:fortinet") == ""


def _mailcow_doc() -> bytes:
    cpe = "cpe:2.3:a:mailcow:mailcow\\:_dockerized:*:*:*:*:*:*:*:*"
    return json.dumps(
        {
            "document": {"category": "csaf_security_advisory", "csaf_version": "2.0", "title": "mailcow (test)", "publisher": {"category": "coordinator", "name": "Example CERT", "namespace": "https://cert.example"},
                         "distribution": {"tlp": {"label": "WHITE"}}, "tracking": {"id": "EX-2026-1", "status": "final", "version": "1", "initial_release_date": "2026-10-28T00:00:00Z", "current_release_date": "2026-10-28T00:00:00Z"}},  # fmt: skip
            "product_tree": {"branches": [{"category": "vendor", "name": "mailcow", "branches": [{"category": "product_name", "name": "mailcow dockerized", "branches": [
                {"category": "product_version_range", "name": "<2025-03a", "product": {"name": "mailcow <2025-03a", "product_id": "M1", "product_identification_helper": {"cpe": cpe}}}]}]}]},  # fmt: skip
            "vulnerabilities": [{"cve": "CVE-2026-90903", "product_status": {"known_affected": ["M1"]}}],
        }
    ).encode()


def test_csaf_entry_with_an_escaped_colon_is_the_catalogue_product():
    d = story_details.parse_csaf(_mailcow_doc(), "csaf")
    assert d["products"][0]["cpe"] == "a:mailcow:mailcow\\:_dockerized"  # the whole product field, not "mailcow\\"
    mc = catalog.product("mailcow")
    assert mc["cpes"] == ["a:mailcow:mailcow\\:_dockerized"]
    assert entries_for(mc, {"products": d["products"]})
    # also an entry stored with the colon unescaped by another parser: the same product
    assert entries_for(mc, {"products": [{"vendor": "mailcow", "name": "x", "cpe": "cpe:2.3:a:mailcow:mailcow\\:_dockerized:*"}]})
    assert not entries_for(mc, {"products": [{"vendor": "mailcow", "name": "x", "cpe": "a:mailcow:mailcow"}]})
    adv = story_details.csaf_advisory(d, "https://cert.example/x.json")
    assert "mailcow" in vendor.link(adv, vendor.build_index())


def test_cve_record_names_and_adp_cpe_of_mailcow():
    mc = catalog.product("mailcow")
    from app.vendor_match import _adp_product, _cna_names

    assert ("mailcow", "mailcow: dockerized") in _cna_names(mc)
    assert _adp_product(mc)["cna"] == [("mailcow", "mailcow: dockerized")]
    rec = cvelist.parse_record(record("CVE-2026-90904", "mailcow", "mailcow: dockerized", [{"version": "0", "lessThan": "2025-03a", "status": "affected"}]))
    assert "mailcow" in vendor.link(rec, vendor.build_index())
    nvd = {"configs": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:mailcow:mailcow\\:_dockerized:*:*:*:*:*:*:*:*", "versionEndExcluding": "2025-03a"}]}]}]}
    assert evaluate(mc, "nvd", nvd, None) is not None
    assert catalog_care.cpe_short("cpe:2.3:a:mailcow:mailcow\\:_dockerized:*:*:*:*:*:*:*:*") == "a:mailcow:mailcow\\:_dockerized"


# ---------------------------------------------------------------- 7. Dell iDRAC9 / iDRAC10


def test_idrac_names_as_dell_writes_them():
    """CVE-2026-23855 (Dell): rows "Dell / iDRAC9" and "Dell / iDRAC10", lessThan written "1.30.30.50 or later" (the
    fixed version); CVE-2026-35155: "Dell / iDRAC10"; NVD's CPE o:dell:idrac10_firmware (checked 2026-11-03)."""
    rec = cvelist.parse_record(record("CVE-2026-23855", "Dell", "iDRAC10", [{"version": "0", "lessThan": "1.30.30.50 or later", "status": "affected", "versionType": "custom"}]))
    rec["data"]["cna"][0]["affectedData"].insert(0, {"vendor": "Dell", "product": "iDRAC9", "defaultStatus": "unaffected", "versions": [{"version": "0", "lessThan": "7.30.10.50 or later", "status": "affected", "versionType": "custom"}]})
    linked = vendor.link(rec, vendor.build_index())
    assert {"dell-idrac", "dell-idrac10"} <= linked
    i10, i9 = catalog.product("dell-idrac10"), catalog.product("dell-idrac")
    assert i10["cpes"] == ["o:dell:idrac10_firmware"] and not i10.get("hint")
    got = evaluate(i10, "cvelist", rec["data"], "1.20.70.50")
    assert got.status == "affected" and got.fixed == "1.30.30.50"
    assert evaluate(i10, "cvelist", rec["data"], "1.30.30.50").status == "not_affected"
    assert evaluate(i9, "cvelist", rec["data"], "7.20.10.50").status == "affected"
    assert evaluate(i9, "cvelist", rec["data"], "7.30.10.50").status == "not_affected"


def test_catalogue_version_was_raised():
    assert catalog.catalog_version() >= "2026.11.03-1"

