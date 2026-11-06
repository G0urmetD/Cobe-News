"""Who wrote a CVE record (0.1.52): the CNA's affected data is the vendor's own word („laut Hersteller“) only when the
CNA is the product's vendor – GitHub's advisory database, VulDB, MITRE, HackerOne or an unknown CNA are third parties:
named in the verdict („laut GitHub (nicht der Hersteller)“) and never the vendor's weight against the NVD's analysis.
The CNA comes from cvelistV5 (assignerShortName) and from the NVD (sourceIdentifier); records stored before keep the
old reading until their next full fetch (migration 0036 marks every NVD CPE query for one)."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text

from app import catalog_data, cvelist, db, vendor
from app import vendor_catalog as catalog
from app import vendor_sources as src
from app.models import VendorAdvisory, VendorFetch
from app.vendor_match import cna_by, evaluate

GITLAB_CONFIGS = [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", "versionEndExcluding": "19.4.2"}]}]}]


@pytest.fixture(scope="module")
def cat():
    return {p["key"]: p for p in catalog.load()["products"]}


def _rows(vendor_: str, product: str, versions: list, default: str = "unaffected") -> list:
    return [{"affectedData": [{"vendor": vendor_, "product": product, "defaultStatus": default, "versions": versions}]}]


def _gitlab(assigner: str | None, *, configs: bool = True) -> dict:
    """GitLab's ranges ("19.4 < 19.4.2", every other version unaffected) next to NVD's "< 19.4.2" – the case where the
    vendor's "not affected" (18.11.0) outweighs NVD's range: "possibly" (vendor_match.eval_nvd, vendor_unaffected)."""
    data = {"configs": GITLAB_CONFIGS if configs else [], "desc": "", "cna": _rows("GitLab", "GitLab", [{"version": "19.4", "lessThan": "19.4.2", "status": "affected"}])}
    if assigner is not None:
        data["assigner"] = assigner
    return data


# ---------------------------------------------------------------- is the CNA the vendor?


@pytest.mark.parametrize(
    ("key", "ident", "want"),
    [
        # the name rule: short name or the domain of the address is the vendor's name
        ("fortios", "fortinet", ("vendor", "")),
        ("fortios", "psirt@fortinet.com", ("vendor", "")),
        ("panos", "palo_alto", ("vendor", "")),
        ("panos", "psirt@paloaltonetworks.com", ("vendor", "")),
        ("gitlab", "GitLab", ("vendor", "")),
        ("gitlab", "cve@gitlab.com", ("vendor", "")),
        # listed: vendors the rule cannot see (an odd address, the NVD's UUID)
        ("python", "PSF", ("vendor", "")),
        ("php", "security@php.net", ("vendor", "")),
        ("linux", "416baaa9-dc9f-4396-8d5f-8c081fb06d67", ("vendor", "")),
        # Zoho ManageEngine: the NVD names it only by its UUID (sourceIdentifier of every ManageEngine record)
        ("manageengine-servicedesk", "0fc0942c-577d-436f-ae8e-945763c79b02", ("vendor", "")),
        ("manageengine-opmanager", "ManageEngine", ("vendor", "")),
        ("ivanti-connect-secure", "3c1d8aa1-5a33-4ea4-8992-aadd6440af75", ("vendor", "")),
        # third parties
        ("nextcloud", "GitHub_M", ("cna", "GitHub")),
        ("nextcloud", "security-advisories@github.com", ("cna", "GitHub")),
        ("dlink-switch", "VulDB", ("cna", "VulDB")),
        ("dlink-switch", "cna@vuldb.com", ("cna", "VulDB")),
        ("gitlab", "mitre", ("cna", "MITRE")),
        ("ivanti-connect-secure", "support@hackerone.com", ("cna", "HackerOne")),
        ("wireshark", "cve@gitlab.com", ("cna", "gitlab.com")),  # GitLab writes Wireshark's records
        ("python", "secalert@redhat.com", ("cna", "Red Hat")),
        # unknown CNAs: a third party (the safe side) – named by what the record says
        ("gitlab", "somecert", ("cna", "somecert")),
        ("gitlab", "vuln@example-cert.org", ("cna", "example-cert.org")),
        ("gitlab", "0f0e0d0c-1111-2222-3333-444455556666", ("cna", "")),
    ],
)
def test_who_the_cna_is(cat, key, ident, want):
    assert cna_by(cat[key], {"assigner": ident}) == want


def test_listed_cnas_are_vendors_only_of_their_own_products(cat):
    """GitHub is the vendor of GitHub's products, not of the projects in its advisory database; Mandiant's address at
    google.com is no Google record; a CNA's name only begins another vendor's with four letters at least (git ≠ GitHub)."""
    github = {"key": "x", "vendor": "GitHub", "cpes": []}
    assert cna_by(github, {"assigner": "GitHub_P"}) == ("vendor", "")
    assert cna_by({"vendor": "Google"}, {"assigner": "mandiant-cve@google.com"}) == ("cna", "Mandiant")
    assert cna_by({"vendor": "Google"}, {"assigner": "cve-coordination@google.com"}) == ("vendor", "")
    assert cna_by({"vendor": "Git"}, {"assigner": "githubm"}) == ("cna", "githubm")
    assert cna_by({"vendor": "Juniper Networks"}, {"assigner": "sirt@juniper.net"}) == ("vendor", "")
    assert cna_by({"vendor": "QNAP"}, {"assigner": "security@qnapsecurity.com.tw"}) == ("vendor", "")
    # names the rule would misread: Israel's INCD (cyber.gov.il) is no CyberArk record, the kernel's "Linux" no Linux Mint one
    assert cna_by({"vendor": "CyberArk (Palo Alto Networks)"}, {"assigner": "cna@cyber.gov.il"}) == ("cna", "INCD (Israel)")
    assert cna_by({"vendor": "Linuxmint"}, {"assigner": "Linux"}) == ("cna", "Linux kernel")
    assert cna_by({"vendor": "Linuxmint"}, {"assigner": "Canonical"})[0] == "cna" and cna_by({"vendor": "Canon"}, {"assigner": "canonical"})[0] == "cna"
    # a vendor named after its parent ("Splunk (Cisco)"), and the vendors of a product's CNA names
    assert cna_by({"vendor": "Splunk (Cisco)"}, {"assigner": "psirt@cisco.com"}) == ("vendor", "")
    assert cna_by(cat["netscaler-adc"], {"assigner": "secure@citrix.com"}) == ("vendor", "")
    # … and of its CPEs (a product of endoflife.date with an odd vendor name)
    assert cna_by({"vendor": "Visual", "cpes": ["a:microsoft:visual_studio_code"]}, {"assigner": "secure@microsoft.com"}) == ("vendor", "")
    # a record that does not say who wrote it (stored before 0.1.52): the vendor's, as before
    assert cna_by(cat["gitlab"], {}) == ("vendor", "") and cna_by(cat["gitlab"], {"assigner": " "}) == ("vendor", "")


def test_every_listed_vendor_is_a_catalogue_vendor():
    """cnas.yaml names vendors as the products' vendor field does (a typo would map nothing)."""
    vendors = {str(p.get("vendor") or "") for p in catalog.load()["products"]} | {str(a) for p in catalog.load()["products"] for a, _ in p.get("cna") or []}
    low = {v.lower() for v in vendors}
    for c in catalog.CNAS:
        for v in c.get("vendors") or []:
            assert v.lower() in low, (c["key"], v)


def test_a_broken_cna_list_is_refused(tmp_path):
    import shutil

    d = tmp_path / "catalog"
    shutil.copytree(catalog_data.DIR, d)
    (d / "cnas.yaml").write_text("cnas:\n  - key: a\n    name: A\n    ids: [one]\n  - key: b\n    name: B\n    ids: [ONE]\n")
    with pytest.raises(catalog_data.CatalogError, match="cnas.yaml: CNA 'b'.*already an identifier of 'a'"):
        catalog_data.load(d)
    (d / "cnas.yaml").write_text("cnas:\n  - key: a\n    name: A\n    ids: ['has space']\n")
    with pytest.raises(catalog_data.CatalogError, match="cnas.yaml"):
        catalog_data.load(d)


# ---------------------------------------------------------------- wording and weight


def test_a_github_record_is_githubs_word_not_the_vendors(cat):
    """GitHub's advisory database writes Nextcloud's record: „laut GitHub“, not „laut Hersteller“."""
    nc = cat["nextcloud"]
    data = {"configs": [], "desc": "", "assigner": "GitHub_M", "cna": _rows("nextcloud", "nextcloud server", [{"version": ">= 28.0.0, < 28.0.6", "status": "affected"}], default="affected")}
    got = evaluate(nc, "cvelist", data, "28.0.4")
    assert (got.status, got.detail) == ("affected", {"by": "cna", "cna": "GitHub"})
    got = evaluate(nc, "cvelist", data, "29.0.1")
    assert got.reason == "default_affected" and got.detail == {"by": "cna", "cna": "GitHub"}
    # a version we cannot compare keeps the origin
    assert evaluate(nc, "cvelist", data, "28.x").detail == {"by": "cna", "cna": "GitHub"}


def test_a_vendor_cna_stays_the_vendor_and_keeps_its_weight(cat):
    """GitLab's own record: as before – „laut Hersteller“, and its "not affected" against NVD's range is "possibly"."""
    gl = cat["gitlab"]
    for assigner in (None, "GitLab", "cve@gitlab.com"):
        got = evaluate(gl, "nvd", _gitlab(assigner), "18.11.0")
        assert (got.status, got.reason, got.detail["by"]) == ("possible", "vendor_unaffected", "nvd"), assigner
        alone = evaluate(gl, "nvd", _gitlab(assigner, configs=False), "19.4.1")
        assert (alone.status, alone.detail) == ("affected", {"by": "vendor"}), assigner


@pytest.mark.parametrize(("assigner", "name"), [("cna@vuldb.com", "VulDB"), ("security-advisories@github.com", "GitHub"), ("0f0e0d0c-1111-2222-3333-444455556666", None)])
def test_a_third_party_never_outweighs_nvds_range(cat, assigner, name):
    """The same ranges from VulDB, GitHub or a CNA known only by its UUID: NVD's "affected" stays – no vendor weight."""
    gl = cat["gitlab"]
    got = evaluate(gl, "nvd", _gitlab(assigner), "18.11.0")
    assert (got.status, got.detail["by"]) == ("affected", "nvd")
    alone = evaluate(gl, "nvd", _gitlab(assigner, configs=False), "19.4.1")
    assert alone.status == "affected" and alone.detail == ({"by": "cna", "cna": name} if name else {"by": "cna"})
    # where NVD's analysis decides nothing, the third party's ranges still count (as CISA's do) – only no weight against it
    assert evaluate(gl, "nvd", _gitlab(assigner, configs=False), "18.11.0").status == "not_affected"


# ---------------------------------------------------------------- where the CNA comes from


def _nvd_page(source_id: str | None) -> bytes:
    cve = {
        "id": "CVE-2026-90001",
        "vulnStatus": "Analyzed",
        "published": "2026-10-01T10:00:00.000",
        "lastModified": "2026-10-02T10:00:00.000",
        "descriptions": [{"lang": "en", "value": "A flaw in Nextcloud Server."}],
        "metrics": {},
        "affected": [
            {"source": source_id or "x", "affectedData": [{"vendor": "nextcloud", "product": "nextcloud server", "defaultStatus": "unaffected", "versions": [{"version": "28.0.0", "lessThan": "28.0.6", "status": "affected"}]}]}
        ],
    }
    if source_id is not None:
        cve["sourceIdentifier"] = source_id
    return json.dumps({"totalResults": 1, "vulnerabilities": [{"cve": cve}]}).encode()


def test_nvd_records_keep_their_source_identifier(cat):
    _, advs = src.parse_nvd(_nvd_page("security-advisories@github.com"))
    data = advs[0]["data"]
    assert data["assigner"] == "security-advisories@github.com"
    assert evaluate(cat["nextcloud"], "nvd", data, "28.0.4").detail == {"by": "cna", "cna": "GitHub"}
    # a record without one stays as it was stored (no key – the vendor's, as before)
    _, advs = src.parse_nvd(_nvd_page(None))
    assert "assigner" not in advs[0]["data"]
    assert evaluate(cat["nextcloud"], "nvd", advs[0]["data"], "28.0.4").detail == {"by": "vendor"}


def test_cvelist_records_keep_their_assigner(cat):
    doc = {
        "cveMetadata": {"cveId": "CVE-2026-90002", "state": "PUBLISHED", "assignerShortName": "VulDB", "datePublished": "2026-10-29T10:00:00.000Z", "dateUpdated": "2026-10-30T06:00:00.000Z"},
        "containers": {"cna": {"providerMetadata": {"shortName": "VulDB"}, "descriptions": [{"lang": "en", "value": "D-Link DGS switch flaw."}], "affected": [{"vendor": "D-Link", "product": "DGS-1100", "versions": [{"version": "1.0", "status": "affected"}]}]}},
    }
    got = cvelist.parse_record(doc)
    assert got["data"]["assigner"] == "VulDB"
    # no assignerShortName: the CNA container's providerMetadata names it
    del doc["cveMetadata"]["assignerShortName"]
    assert cvelist.parse_record(doc)["data"]["assigner"] == "VulDB"


# ---------------------------------------------------------------- the stored records: migration 0036, the next full fetch


async def test_migration_marks_nvd_queries_for_a_full_fetch():
    """0036 empties `full_at` of every NVD CPE query (one row each – no lock on the advisories): the next due fetch is a
    full one and stores the records with their CNA; other queries keep theirs."""
    from alembic import command

    now = datetime.now(UTC)
    async with db.session() as s:
        s.add_all([VendorFetch(key="nvd:a:gitlab:gitlab", full_at=now, failures=0, items=0), VendorFetch(key="nvdkw:gitlab", full_at=now, failures=0, items=0), VendorFetch(key="cvelist:delta", full_at=now, failures=0, items=0)])
        await s.commit()

    def down(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "0034")

    async with db.engine().begin() as conn:
        await conn.run_sync(down)
    await db.migrate()
    assert await db.revision() == db.head()
    async with db.engine().connect() as conn:
        rows = dict((await conn.execute(text("SELECT key, full_at IS NULL FROM vendor_fetch"))).all())
    assert rows == {"nvd:a:gitlab:gitlab": True, "nvdkw:gitlab": False, "cvelist:delta": False}


async def test_a_full_fetch_stores_the_cna_of_a_record_stored_before(monkeypatch):
    """A record stored before 0.1.52 (no CNA) gets its CNA with the next full fetch – and no revision for it."""
    from app.models import VendorAdvisoryChange

    page = _nvd_page("security-advisories@github.com")
    _, advs = src.parse_nvd(page)
    old = {**advs[0], "data": {k: v for k, v in advs[0]["data"].items() if k != "assigner"}}
    ix = vendor.build_index()
    async with db.session() as s:
        await vendor.store(s, [old], ix)
        s.add(VendorFetch(key="nvd:a:nextcloud:nextcloud_server", cursor=(datetime.now(UTC) - timedelta(days=1)).isoformat(), full_at=None, failures=0, items=1))
        await s.commit()

    async def fake_get(url, **_kw):  # noqa: ANN001, ANN202
        assert "lastModStartDate" not in url  # full_at empty: a full fetch
        return page

    monkeypatch.setattr(vendor, "get", fake_get)
    async with db.session() as s:
        assert await vendor.sync_nvd_cpe(s, "a:nextcloud:nextcloud_server", timedelta(hours=4), ix, "", True) == 1
    async with db.session() as s:
        a = await s.get(VendorAdvisory, "nvd:CVE-2026-90001")
        assert a.data["assigner"] == "security-advisories@github.com"
        assert (await s.scalars(select(VendorAdvisoryChange))).all() == []
        assert (await s.get(VendorFetch, "nvd:a:nextcloud:nextcloud_server")).full_at is not None


# ---------------------------------------------------------------- the refetch of 0036 is no change (PARSER_V["nvd"] 2)


def _gitlab_nvd(assigner: str | None, *, updated: datetime) -> dict:
    """GitLab's record in the NVD as stored: NVD's range "< 19.4.2" and the CNA's ranges – 18.11.0 "possibly" while the
    CNA counts as the vendor (stored before 0.1.52, no assigner), "affected" once a third party (VulDB) wrote it."""
    _, advs = src.parse_nvd(_nvd_page(None))
    return {**advs[0], "id": "nvd:CVE-2026-90003", "ident": "CVE-2026-90003", "cves": ["CVE-2026-90003"], "cvss": 7.5, "severity": "high", "updated_at": updated, "data": _gitlab(assigner)}


async def _gitlab_followed(c) -> None:  # noqa: ANN001
    from sqlalchemy import update

    from app.models import VendorFollow

    assert (await c.put("/api/vendor/follows/gitlab", json={"enabled": True})).status_code == 200
    assert (await c.post("/api/vendor/follows/gitlab/versions", json={"version": "18.11.0", "label": ""})).status_code == 200
    async with db.session() as s:  # evaluated once: what comes now is news
        await s.execute(update(VendorFollow).where(VendorFollow.product == "gitlab").values(baseline_at=datetime.now(UTC)))
        await s.commit()


async def _revisions_and_events() -> tuple[list, list]:
    from app.models import VendorAdvisoryChange, VendorEvent

    async with db.session() as s:
        return list(await s.scalars(select(VendorAdvisoryChange))), list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "change")))


@pytest.mark.parametrize("state", [True, False], ids=["with-state", "stored-once"])
async def test_the_cna_refetch_flips_a_verdict_without_a_change_event(admin_client, cat, monkeypatch, state):
    """Migration 0036's refetch brings the CNA of every stored NVD record: GitLab's 18.11.0 goes from "possibly" (the
    CNA's "not affected" counted as the vendor's) to "affected" (VulDB wrote it) – the view shows the new verdict, but
    nothing new was said: no revision, no vendor_change event, no notification. The record's facts are stamped with
    parser 2; a real change after that is one again."""
    from app import advisory_changes as ch

    gl = cat["gitlab"]
    assert evaluate(gl, "nvd", _gitlab(None), "18.11.0").status == "possible"
    assert evaluate(gl, "nvd", _gitlab("cna@vuldb.com"), "18.11.0").status == "affected"
    await _gitlab_followed(admin_client)
    now = datetime.now(UTC)
    ix = vendor.build_index()
    with monkeypatch.context() as m:  # stored by 0.1.51: parser 1, no CNA
        m.setitem(ch.PARSER_V, "nvd", 1)
        async with db.session() as s:
            await vendor.store(s, [_gitlab_nvd(None, updated=now - timedelta(days=3))], ix)
            if state:  # stored twice: the record has its facts (parser 1)
                await vendor.store(s, [_gitlab_nvd(None, updated=now - timedelta(days=2))], ix)
    async with db.session() as s:
        await vendor.store(s, [_gitlab_nvd("cna@vuldb.com", updated=now - timedelta(days=1))], ix)
    assert await _revisions_and_events() == ([], [])
    from app.models import VendorAdvisoryState

    async with db.session() as s:
        st = await s.get(VendorAdvisoryState, "nvd:CVE-2026-90003")
    assert st is not None and st.facts["p"] == 2
    # from then on a change is one again: NVD moves its range, 18.11.0 drops out
    moved = _gitlab_nvd("cna@vuldb.com", updated=now)
    moved["data"]["configs"] = [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", "versionStartIncluding": "19.0", "versionEndExcluding": "19.4.2"}]}]}]
    async with db.session() as s:
        await vendor.store(s, [moved], ix)
    revs, evs = await _revisions_and_events()
    assert [r.revision for r in revs] == [2] and len(evs) == 1 and evs[0].data["impact"][0]["from"] == "affected"


def test_reparsed_without_a_state_only_for_an_nvd_record_that_gains_its_cna():
    from app import advisory_changes as ch

    assert ch.reparsed("nvd", None, {"configs": []}, {"configs": [], "assigner": "x"})
    assert not ch.reparsed("nvd", None, {"assigner": "x"}, {"assigner": "y"})  # stored by parser 2 already
    assert not ch.reparsed("nvd", None, {}, {})  # a record without sourceIdentifier
    assert not ch.reparsed("cvelist", None, {}, {"assigner": "x"})
    assert ch.reparsed("nvd", {"p": 1}, {}, {}) and not ch.reparsed("nvd", {"p": 2}, {}, {})


@pytest.mark.parametrize(
    ("vendor", "ident", "want"),
    [
        # a generic word or a part of another name never decides alone (L8, review 0.1.52)
        ("cert-manager", "cert@cert.at", "cna"),
        ("cert-manager", "CERT.at", "cna"),
        ("Phoenix Contact", "security@phoenix.com", "cna"),  # Phoenix Technologies
        ("Phoenix Contact", "Phoenix", "cna"),
        ("Micro Focus", "micro", "cna"),
        ("OpenText", "open", "cna"),
        ("Cloud Software Group", "cloud", "cna"),
        ("Datadog", "data@data.example", "cna"),
        ("Canonical", "canon", "cna"),
        ("Check Point", "check", "cna"),
        # the vendor's name in whole words, then a legal form or the like – or a CNA suffix after it
        ("Palo Alto Networks", "palo_alto", "vendor"),
        ("Juniper Networks", "juniper", "vendor"),
        ("Nagios Enterprises", "nagios", "vendor"),
        ("Pleasant Solutions", "security@pleasant.example", "vendor"),
        ("GitHub", "GitHub_P", "vendor"),
        ("QNAP", "security@qnapsecurity.com.tw", "vendor"),
        ("Apache", "apache_software_foundation", "vendor"),
        ("Example", "psirt@example.com", "vendor"),
    ],
)
def test_the_name_rule_needs_a_whole_name(vendor, ident, want):
    from app.vendor_match import _cna_origin

    _cna_origin.cache_clear()
    assert cna_by({"vendor": vendor}, {"assigner": ident})[0] == want
