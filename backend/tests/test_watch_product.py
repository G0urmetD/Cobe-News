"""CVE beobachten, 0.1.46 (app/watch_product.py): the product of a watched CVE – what the list groups by. The order
(catalogue links with the followed product first, the CNA's names, the NVD's CPE, none), several products ("others"),
merged and custom keys, a link that comes after the watch, and a list of 500 read with a bounded number of queries."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import event

from app import db, watch_product
from app import vendor_catalog as catalog
from app.models import CveWatch, VendorAdvisory, VendorAdvisoryProduct, VendorFollow


def test_names_made_readable():
    assert watch_product.cna_label("GitLab", "GitLab") == "GitLab"
    assert watch_product.cna_label(" gitlab ", "GitLab  CE/EE") == "GitLab CE/EE"
    assert watch_product.cna_label("Microsoft", "Windows Server 2022") == "Microsoft Windows Server 2022"
    assert watch_product.cna_label("n/a", "n/a") is None
    assert watch_product.cna_label("n/a", "libfoo") == "libfoo"
    assert watch_product.cna_label("Acme", "unspecified") == "Acme"
    assert watch_product.cpe_names("cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*") == ("gitlab", "gitlab")
    assert watch_product.cpe_names("cpe:2.3:a:mailcow:mailcow\\:_dockerized:*:*") == ("mailcow", "mailcow:_dockerized")
    assert watch_product.cpe_names("cpe:2.3:a:*:*:*") is None and watch_product.cpe_names("nonsense") is None
    assert watch_product.cpe_label("gitlab", "gitlab") == "Gitlab"
    assert watch_product.cpe_label("microsoft", "windows_server_2022") == "Microsoft Windows Server 2022"
    assert watch_product.cpe_label("examplecorp", "examplecorp_router_os") == "Examplecorp Router Os"
    assert watch_product.fold("  GitLab   CE ") == "gitlab ce"



def _adv(source: str, cve: str, *, cna: list[tuple[str, str]] | None = None, cpes: list[str] | None = None, ident: str | None = None) -> VendorAdvisory:
    ident = ident or cve
    data: dict = {"cna": [{"affectedData": [{"vendor": v, "product": p, "defaultStatus": "", "versions": []} for v, p in cna]}] if cna else [], "configs": []}
    if cpes:
        data["configs"] = [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": c} for c in cpes]}]}]
    return VendorAdvisory(id=f"{source}:{ident}", source=source, ident=ident, title=f"{ident} issue", url="https://advisories.example.com/x", cves=[cve], severity="high", data=data)


async def _watch(user, cves: list[str]) -> None:  # noqa: ANN001
    now = datetime.now(UTC)
    async with db.session() as s:
        s.add_all(CveWatch(user_id=user.id, cve=c, created_at=now - timedelta(seconds=i), origin_kind="manual") for i, c in enumerate(cves))
        await s.commit()


async def _products(client) -> dict[str, dict]:  # noqa: ANN001
    r = await client.get("/api/me/cve-watch")
    assert r.status_code == 200, r.text
    return {i["cve"]: i["product"] for i in r.json()["items"]}


async def test_catalogue_first_followed_preferred_then_most_advisories(reader_client):
    a, b, c = "CVE-2026-61001", "CVE-2026-61002", "CVE-2026-61003"
    now = datetime.now(UTC)
    async with db.session() as s:
        s.add(VendorFollow(product="typo3", enabled=True, created_at=now, updated_at=now))
        s.add(VendorFollow(product="fortios", enabled=False, created_at=now, updated_at=now))  # switched off: not followed
        # a: GitLab (two advisories) and TYPO3 (one, followed) – the followed one leads
        s.add_all([_adv("nvd", a), _adv("cvelist", a), _adv("osv", a, ident="GHSA-aaaa")])
        await s.flush()
        s.add_all(
            [
                VendorAdvisoryProduct(product="gitlab", advisory_id=f"nvd:{a}"),
                VendorAdvisoryProduct(product="gitlab", advisory_id=f"cvelist:{a}"),
                VendorAdvisoryProduct(product="typo3", advisory_id="osv:GHSA-aaaa"),
            ]
        )
        # b: none followed – GitLab with two advisories before FortiOS with one (switched off counts as not followed)
        s.add_all([_adv("nvd", b), _adv("cvelist", b)])
        await s.flush()
        s.add_all(
            [
                VendorAdvisoryProduct(product="fortios", advisory_id=f"nvd:{b}"),
                VendorAdvisoryProduct(product="gitlab", advisory_id=f"nvd:{b}"),
                VendorAdvisoryProduct(product="gitlab", advisory_id=f"cvelist:{b}"),
            ]
        )
        # c: two with one advisory each – by name; a key nobody knows any more is left out
        s.add(_adv("nvd", c))
        await s.flush()
        s.add_all(
            [
                VendorAdvisoryProduct(product="typo3", advisory_id=f"nvd:{c}"),
                VendorAdvisoryProduct(product="gitlab", advisory_id=f"nvd:{c}"),
                VendorAdvisoryProduct(product="custom-gone", advisory_id=f"nvd:{c}"),
            ]
        )
        await s.commit()
    await _watch(reader_client.user, [a, b, c])
    got = await _products(reader_client)
    assert got[a] == {"key": "typo3", "label": "TYPO3", "source": "catalog", "others": ["GitLab"], "followed": True}
    assert got[b] == {"key": "gitlab", "label": "GitLab", "source": "catalog", "others": [catalog.product("fortios")["label"]], "followed": False}
    # c: TYPO3 is followed – first; GitLab after it
    assert got[c]["key"] == "typo3" and got[c]["others"] == ["GitLab"]


async def test_merged_and_custom_keys_with_the_label_of_today(reader_client):
    old, new = next(iter(catalog.REPLACED.items()))
    a, b = "CVE-2026-62001", "CVE-2026-62002"
    custom = f"custom-{uuid.uuid4()}"
    now = datetime.now(UTC)
    async with db.session() as s:
        s.add(VendorFollow(product=custom, enabled=True, custom={"label": "Intranet Portal", "cpe": "a:examplecorp:intranet_portal", "vendor": "ExampleCorp"}, created_at=now, updated_at=now))
        s.add_all([_adv("nvd", a), _adv("nvd", b)])
        await s.flush()
        s.add_all([VendorAdvisoryProduct(product=old, advisory_id=f"nvd:{a}"), VendorAdvisoryProduct(product=custom, advisory_id=f"nvd:{b}")])
        await s.commit()
    await _watch(reader_client.user, [a, b])
    got = await _products(reader_client)
    assert got[a]["key"] == new and got[a]["label"] == catalog.product(new)["label"] and got[a]["source"] == "catalog"
    assert got[b] == {"key": custom, "label": "Intranet Portal", "source": "catalog", "others": [], "followed": True}


async def test_cna_then_nvd_then_none(reader_client):
    cna_gitlab, cna_acme, cna_cvelist_first, nvd_known, nvd_plain, nvd_custom, unknown, na = (f"CVE-2026-6300{i}" for i in range(1, 9))
    custom = f"custom-{uuid.uuid4()}"
    now = datetime.now(UTC)
    async with db.session() as s:
        s.add(VendorFollow(product=custom, enabled=True, custom={"label": "Intranet Portal", "cpe": "a:examplecorp:intranet_portal"}, created_at=now, updated_at=now))
        s.add_all(
            [
                # the CNA names a catalogue product by its label: that product (with its key – Vendor News opens it)
                _adv("cvelist", cna_gitlab, cna=[("GitLab", "GitLab")]),
                # several: the first named, the others as labels (each name once, case-insensitive)
                _adv("cvelist", cna_acme, cna=[("Acme", "Widget Server"), ("ACME", "widget server"), ("Acme", "Widget Client")]),
                # cvelistV5's names before the NVD's copy – and before the NVD's CPE
                _adv("cvelist", cna_cvelist_first, cna=[("Example Org", "Thing")]),
                _adv("nvd", cna_cvelist_first, cna=[("Other", "Name")], cpes=["cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"]),
                # no CNA names: the NVD's CPE – a catalogue product's CPE is that product
                _adv("nvd", nvd_known, cpes=["cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", "cpe:2.3:a:examplecorp:widget_os:*:*:*:*:*:*:*:*"]),
                _adv("nvd", nvd_plain, cpes=["cpe:2.3:o:examplecorp:router_firmware:*:*:*:*:*:*:*:*"]),
                _adv("nvd", nvd_custom, cpes=["cpe:2.3:a:examplecorp:intranet_portal:*:*:*:*:*:*:*:*"]),
                # MITRE's placeholders are no names
                _adv("cvelist", na, cna=[("n/a", "n/a")]),
            ]
        )
        await s.commit()
    await _watch(reader_client.user, [cna_gitlab, cna_acme, cna_cvelist_first, nvd_known, nvd_plain, nvd_custom, unknown, na])
    got = await _products(reader_client)
    assert got[cna_gitlab] == {"key": "gitlab", "label": "GitLab", "source": "cna", "others": [], "followed": False}
    assert got[cna_acme] == {"key": None, "label": "Acme Widget Server", "source": "cna", "others": ["Acme Widget Client"], "followed": False}
    assert got[cna_cvelist_first]["label"] == "Example Org Thing" and got[cna_cvelist_first]["source"] == "cna"
    assert got[nvd_known] == {"key": "gitlab", "label": "GitLab", "source": "nvd", "others": ["Examplecorp Widget Os"], "followed": False}
    assert got[nvd_plain] == {"key": None, "label": "Examplecorp Router Firmware", "source": "nvd", "others": [], "followed": False}
    assert got[nvd_custom] == {"key": custom, "label": "Intranet Portal", "source": "nvd", "others": [], "followed": True}
    assert got[unknown] == got[na] == {"key": None, "label": "", "source": "none", "others": [], "followed": False}


async def test_a_link_after_the_watch_moves_the_cve(reader_client):
    c = "CVE-2026-64001"
    async with db.session() as s:
        s.add(_adv("cvelist", c, cna=[("Acme", "Widget Server")]))
        await s.commit()
    await _watch(reader_client.user, [c])
    assert (await _products(reader_client))[c]["source"] == "cna"
    async with db.session() as s:
        s.add(VendorAdvisoryProduct(product="gitlab", advisory_id=f"cvelist:{c}"))
        await s.commit()
    assert (await _products(reader_client))[c] == {"key": "gitlab", "label": "GitLab", "source": "catalog", "others": [], "followed": False}


async def _seed(user, n: int, start: int) -> None:  # noqa: ANN001
    """n watched CVEs: a third linked to a product, a third with CNA names, the rest with an NVD CPE (and some unknown)."""
    now = datetime.now(UTC)
    cves = [f"CVE-2026-{start + i}" for i in range(n)]
    async with db.session() as s:
        s.add_all(CveWatch(user_id=user.id, cve=c, created_at=now - timedelta(seconds=i), origin_kind="manual") for i, c in enumerate(cves))
        advs, links = [], []
        for i, c in enumerate(cves):
            if i % 3 == 0:
                advs.append(_adv("nvd", c))
                links.append(VendorAdvisoryProduct(product="gitlab" if i % 2 else "typo3", advisory_id=f"nvd:{c}"))
            elif i % 3 == 1:
                advs += [_adv("cvelist", c, cna=[("Acme", f"Widget {i % 7}")]), _adv("nvd", c)]
            elif i % 5:
                advs.append(_adv("nvd", c, cpes=[f"cpe:2.3:a:examplecorp:product_{i % 4}:*:*:*:*:*:*:*:*"]))
        s.add_all(advs)
        await s.flush()
        s.add_all(links)
        await s.commit()


async def test_the_products_of_500_with_a_bounded_number_of_queries(reader_client, admin_client):
    counted: list[str] = []

    def count(conn, cursor, statement, *a):  # noqa: ANN001, ANN002, ANN202
        counted.append(statement)

    await _seed(admin_client.user, 6, 90000)
    await _seed(reader_client.user, 500, 70000)
    sync = db.engine().sync_engine
    event.listen(sync, "before_cursor_execute", count)
    try:
        small = await admin_client.get("/api/me/cve-watch")
        n_small = len(counted)
        counted.clear()
        big = await reader_client.get("/api/me/cve-watch")
        n_big = len(counted)
    finally:
        event.remove(sync, "before_cursor_execute", count)
    items = big.json()["items"]
    assert len(small.json()["items"]) == 6 and len(items) == 500
    by = {}
    for i in items:
        by[i["product"]["source"]] = by.get(i["product"]["source"], 0) + 1
    assert by == {"catalog": 167, "cna": 167, "nvd": 133, "none": 33}, by
    assert {i["product"]["label"] for i in items if i["product"]["source"] == "catalog"} == {"GitLab", "TYPO3"}
    assert n_big <= n_small + 1 and n_big <= 20, (n_small, n_big)
