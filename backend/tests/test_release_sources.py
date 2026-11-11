"""Release data from GitHub releases and vendors' release notes pages (app/release_sources.py) for products
endoflife.date does not know: the parsers on saved real answers (trimmed – tests/fixtures/vendor/github_*.atom,
passwork_release_notes.html, fetched 2026-11-11), lines / newest version / LTS, the catalogue's configs against tags
seen in the real feeds, the round (followed products only, baseline, "neue Version" for a later release, egress guard,
lost cache), the drawer's source line and the catalogue self-test."""

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app import catalog_check as cc
from app import catalog_data, db, release_sources, vendor
from app import vendor_catalog as catalog
from app.models import CatalogCheck, VendorEvent, VendorFetch
from test_vendor_service import Vendors

FIX = Path(__file__).parent / "fixtures" / "vendor"


def fx(name: str) -> bytes:
    return (FIX / name).read_bytes()


def cfg_of(key: str) -> dict:
    c = release_sources.config(catalog.product(key))
    assert c is not None, key
    return c


# ---------------------------------------------------------------- parsers


def test_github_atom_portainer_lts_and_sts_lines():
    vs = release_sources.parse(fx("github_portainer.atom"), cfg_of("portainer"))
    assert {v["v"] for v in vs} >= {"2.45.3", "2.45.0", "2.44.0", "2.39.8", "2.39.4"}
    lines = release_sources.lines_of(vs, 2)
    assert [(ln["name"], ln["latest"], ln["isLts"]) for ln in lines] == [("2.45", "2.45.3", True), ("2.44", "2.44.0", False), ("2.39", "2.39.8", True)]
    assert lines[0]["latestDate"] == "2026-10-22" and lines[0]["releaseDate"] == "2026-08-27"
    assert not any(k in ln for ln in lines for k in ("eolFrom", "isEol", "isMaintained"))  # no support data invented


def test_github_atom_skips_release_candidates_and_reads_the_tag_not_the_title():
    vs = release_sources.parse(fx("github_bloodhound.atom"), cfg_of("bloodhound"))
    assert sorted(v["v"] for v in vs) == ["9.9.0", "9.9.1", "9.9.2"]  # "BloodHound CE v9.9.2" and "v9.9.1" alike, no -rc
    with_pre = release_sources.parse(fx("github_bloodhound.atom"), {"github": "SpecterOps/BloodHound", "prerelease": True, "tag": r"^v?(?P<version>\d+\.\d+\.\d+)(?:-rc\d+)?$"})
    assert "9.10.0" in {v["v"] for v in with_pre}
    wz = release_sources.parse(fx("github_wazuh.atom"), cfg_of("wazuh"))
    assert {v["v"] for v in wz} == {"4.14.10", "4.14.9", "4.14.8", "4.10.5", "4.14.7"}  # betas and rcs of 5.0.0 left out
    assert [ln["name"] for ln in release_sources.lines_of(wz, 2)] == ["4.14", "4.10"]


def test_passwork_page_only_the_server_releases():
    vs = release_sources.parse(fx("passwork_release_notes.html"), cfg_of("passwork"))
    assert [(v["v"], v["date"]) for v in vs] == [("7.7.0", "2026-08-03"), ("7.6.2", "2026-06-20"), ("7.6.1", "2026-05-22")]
    # the desktop app, browser extension, Python connector and a script's text are no server release
    lines = release_sources.lines_of(vs, 2)
    assert [(ln["name"], ln["latest"]) for ln in lines] == [("7.7", "7.7.0"), ("7.6", "7.6.2")]


def test_a_feed_with_a_dtd_or_not_atom_is_refused():
    from app.news import NewsError

    with pytest.raises(NewsError):
        release_sources.parse(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><feed xmlns="http://www.w3.org/2005/Atom"/>', cfg_of("portainer"))
    with pytest.raises(ValueError):
        release_sources.parse(b"<rss/>", cfg_of("portainer"))


# tags as the real feeds named them (2026-11-11) → the version the catalogue's rule takes (None: left out)
TAGS = {
    "bookstack": [("v26.09.3", "26.09.3"), ("v26.09", "26.09")],
    "librenms": [("26.10.2", "26.10.2"), ("26.9.1.1", "26.9.1.1")],
    "vaultwarden": [("1.37.5", "1.37.5")],
    "gitea": [("v28.3.0", "28.3.0"), ("v1.27.3", "1.27.3"), ("v29.0.0-dev", None)],
    "netbox": [("v4.7.5", "4.7.5"), ("v4.7.0-beta2", None)],
    "uptime-kuma": [("2.5.9", "2.5.9")],
    "n8n": [("n8n@2.48.1", "2.48.1"), ("stable", None), ("v1", None), ("beta", None)],
    "semaphore-ui": [("v2.20.24", "2.20.24"), ("v2.20.21-rc1", None)],
    "velociraptor": [("v0.77.3", "0.77.3"), ("v0.77.1-rc1", None)],
    "passbolt": [("v5.17.0", "5.17.0"), ("v5.18.0-test.1", None)],
    "glpi": [("12.0.1", "12.0.1"), ("12.0.0-rc3", None)],
    "wikijs": [("3.3.1", "3.3.1"), ("3.0.0-beta.705", None)],
    "teampass": [("3.2.4.2", "3.2.4.2")],
    "security-onion": [("3.4.0-20261102", "3.4.0"), ("2.4.211-20260407", "2.4.211")],
    "apache-guacamole": [("1.6.0", "1.6.0"), ("1.6.0-RC3", None)],
    "oxidized": [("0.18.1", "0.18.1")],
    "bitwarden": [("v2026.10.1", "2026.10.1")],
    "zammad": [("7.2.3", "7.2.3"), ("7.4.0-alpha", None)],
    "wazuh-agent": [("v4.14.10", "4.14.10"), ("v5.0.0-beta5", None)],
}


def _feed(*tags: str) -> bytes:
    rows = "".join(
        f'<entry><id>tag:github.com,2008:Repository/1/{t}</id><updated>2026-11-0{i + 1}T10:00:00Z</updated>'
        f'<link rel="alternate" type="text/html" href="https://github.com/o/r/releases/tag/{t}"/><title>{t}</title></entry>'
        for i, t in enumerate(tags)
    )
    return f'<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom">{rows}</feed>'.encode()


@pytest.mark.parametrize("key", sorted(TAGS))
def test_catalogue_rules_take_the_real_tags(key):
    cfg = cfg_of(key)
    for tag, want in TAGS[key]:
        got = {v["v"] for v in release_sources.parse(_feed(tag), cfg)}
        assert got == ({want} if want else set()), (key, tag)


def test_every_release_source_of_the_catalogue_is_valid_and_has_no_endoflife_data():
    with_src = [p for p in catalog.load()["products"] if release_sources.config(p)]
    assert len(with_src) >= 23
    for p in with_src:
        assert not catalog.releases(p.get("eol")), p["key"]  # endoflife.date would come first – a source there is dead data


def test_schema_refuses_broken_sources():
    R = catalog_data.ReleaseSource
    for bad in (R(github="a/b", page="https://x.example/"), R(), R(page="https://x.example/"), R(page="https://x.example/", pattern="Passwork (\\d+)"), R(github="a/b", pattern="(?P<version>x)"), R(github="a/b", tag="(")):
        with pytest.raises(catalog_data.CatalogError):
            catalog_data._check_releases(bad, "products/x.yaml: product 'x'")
    with pytest.raises(Exception):  # noqa: B017 - pydantic's ValidationError: unknown field, not a repo, not https
        catalog_data.ProductsFile.model_validate({"products": [{"key": "xx", "label": "X", "vendor": "X", "releases": {"github": "a/b", "feed": "tags"}}]})
    with pytest.raises(Exception):  # noqa: B017
        catalog_data.ReleaseSource.model_validate({"page": "http://x.example/notes"})
    catalog_data._check_releases(R(github="portainer/portainer", lts=r"\bLTS\b"), "ok")


def test_merge_marks_the_first_fetch_as_baseline_and_keeps_history():
    cfg = cfg_of("portainer")
    now = datetime(2026, 11, 11, tzinfo=UTC)
    first, new = release_sources.merge(None, [{"v": "2.45.3", "date": "2026-10-22", "lts": True}], cfg, now)
    assert new == 0 and first["versions"] == [{"v": "2.45.3", "date": "2026-10-22", "lts": True, "base": True}]
    second, new = release_sources.merge(first, [{"v": "2.45.4", "date": "2026-11-10", "lts": True}], cfg, now)
    assert new == 1 and [(r["v"], r["base"]) for r in second["versions"]] == [("2.45.4", False), ("2.45.3", True)]  # the feed's 10 grow into a history
    other, _ = release_sources.merge(second, [{"v": "2.45.4", "date": None, "lts": False}], {**cfg, "lines": 1}, now)
    assert other["versions"][0]["base"] is True  # another rule in the catalogue: a new baseline


# ---------------------------------------------------------------- the round


class Sites(Vendors):
    """The vendors of test_vendor_service plus GitHub and Passwork."""

    def __init__(self):
        super().__init__()
        self.github: dict[str, bytes | int] = {"portainer/portainer": fx("github_portainer.atom")}
        self.passwork: bytes | int = fx("passwork_release_notes.html")

    def handler(self, req: httpx.Request) -> httpx.Response:
        if req.url.host == "github.com":
            self.calls.append(req)
            repo = req.url.path.removesuffix("/releases.atom").strip("/")
            body = self.github.get(repo, 404)
            if isinstance(body, int):
                return httpx.Response(body, content=b"")
            tag = f'"{len(body)}-{sum(body) % 99991}"'  # changes with the feed
            if req.headers.get("if-none-match") == tag:
                return httpx.Response(304)
            return httpx.Response(200, content=body, headers={"ETag": tag})
        if req.url.host == "passwork.pro":
            self.calls.append(req)
            return httpx.Response(self.passwork, content=b"") if isinstance(self.passwork, int) else httpx.Response(200, content=self.passwork)
        return super().handler(req)


@pytest.fixture(autouse=True)
def rel_file(monkeypatch, tmp_path):
    monkeypatch.setattr(catalog, "_data_file", lambda: tmp_path / "vendor_catalog.json")
    catalog._cache.stamp = ()
    monkeypatch.setattr(release_sources, "_data_file", lambda: tmp_path / "vendor_releases.json")
    release_sources.reset()
    yield tmp_path / "vendor_releases.json"
    release_sources.reset()


@pytest.fixture
def sites(monkeypatch):
    s = Sites()
    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(s.handler))
    return s


async def _follow(c, key: str, *versions: str) -> None:
    r = await c.put(f"/api/vendor/follows/{key}", json={"enabled": True})
    assert r.status_code == 200, r.text
    for v in versions:
        r = await c.post(f"/api/vendor/follows/{key}/versions", json={"version": v})
        assert r.status_code == 200, r.text


async def _round(force: bool = True) -> dict:
    out = await vendor.run_round(force=force)
    async with db.session() as s:
        await vendor.evaluate_events(s, full=True)
    return out


async def _version_events() -> list[VendorEvent]:
    async with db.session() as s:
        return list(await s.scalars(select(VendorEvent).where(VendorEvent.kind == "version").order_by(VendorEvent.key)))


async def _state(key: str) -> VendorFetch | None:
    async with db.session() as s:
        return await s.get(VendorFetch, key)


async def test_nothing_is_fetched_for_a_product_nobody_follows(admin_client, reader_client, sites):
    await _round()
    assert not sites.to("github.com") and not sites.to("passwork.pro")
    d = (await reader_client.get("/api/vendor/products/portainer")).json()
    # the drawer names the source – not fetched yet – and invents no lines
    assert d["releases"] == {"lines": [], "source": {"kind": "github", "ref": "portainer/portainer", "url": "https://github.com/portainer/portainer/releases", "fetched_at": None}}


async def test_baseline_then_a_later_release_is_news(admin_client, reader_client, sites):
    sites.github["portainer/portainer"] = 500  # the first round: no release data yet – the follow's baseline is made
    await _follow(admin_client, "portainer", "2.45.2")
    await _round()
    assert not await _version_events()
    st = await _state("releases:portainer")
    assert st is not None and st.error and st.failures == 1
    # the source answers: 2.45.3 was already out – shown, not notified (the release source's first fetch is a baseline)
    sites.github["portainer/portainer"] = fx("github_portainer.atom")
    async with db.session() as s:
        (await s.get(VendorFetch, "releases:portainer")).next_fetch_at = None
        await s.commit()
    await _round()
    evs = await _version_events()
    assert [(e.key, e.baseline) for e in evs] == [("version:portainer:2.45.2:2.45.3", True)]
    d = (await reader_client.get("/api/vendor/products/portainer")).json()
    rel = d["versions"][0]["release"]
    assert rel["update_available"] and rel["line"]["latest"] == "2.45.3" and rel["line"]["lts"] is True
    assert rel["eol_state"] == "unknown" and rel["line"]["eol_from"] is None  # no EOL from a release source
    assert rel["source"]["kind"] == "github" and rel["source"]["fetched_at"]
    assert [ln["name"] for ln in d["releases"]["lines"]] == ["2.45", "2.44", "2.39"]
    # a later release appears: news, once
    sites.github["portainer/portainer"] = fx("github_portainer.atom").replace(b"2.45.3", b"2.45.4", 3)
    await _round()
    evs = await _version_events()
    assert [(e.key, e.baseline) for e in evs] == [("version:portainer:2.45.2:2.45.3", True), ("version:portainer:2.45.2:2.45.4", False)]
    assert not [e for e in await _all_events() if e.kind == "eol"]  # never an EOL event from these sources
    await _round()
    assert len(await _version_events()) == 2


async def _all_events() -> list[VendorEvent]:
    async with db.session() as s:
        return list(await s.scalars(select(VendorEvent)))


async def test_conditional_and_a_lost_cache_is_filled_again(admin_client, sites, rel_file):
    await _follow(admin_client, "portainer")
    await _round()
    assert len(sites.to("github.com")) == 1 and rel_file.is_file()
    assert oct(rel_file.stat().st_mode & 0o777) == "0o600"
    await _round()
    assert sites.to("github.com")[-1].headers.get("if-none-match")
    rel_file.unlink()  # a restore without the file: the next fetch asks in full (a 304 would leave it empty)
    release_sources.reset()
    await _round()
    assert "if-none-match" not in sites.to("github.com")[-1].headers
    assert release_sources.lines(catalog.product("portainer"))


async def test_page_source_and_a_shared_feed_asked_once(admin_client, reader_client, sites):
    await _follow(admin_client, "passwork", "7.6.2")
    await _follow(admin_client, "wazuh", "4.14.9")
    await _follow(admin_client, "wazuh-agent", "4.14.9")
    sites.github["wazuh/wazuh"] = fx("github_wazuh.atom")
    await _round()
    assert len(sites.to("passwork.pro")) == 1 and len(sites.to("github.com")) == 1  # manager and agent: one request
    d = (await reader_client.get("/api/vendor/products/passwork")).json()
    rel = d["versions"][0]["release"]
    assert rel["line"]["name"] == "7.6" and not rel["update_available"] and rel["newer_line"]["name"] == "7.7"
    assert d["releases"]["source"]["kind"] == "page" and d["releases"]["source"]["ref"] == "passwork.pro"
    w = (await reader_client.get("/api/vendor/products/wazuh-agent")).json()["versions"][0]["release"]
    assert w["update_available"] and w["line"]["latest"] == "4.14.10"


async def test_endoflife_comes_first(sites, monkeypatch):
    p = {**catalog.product("panos"), "releases": {"github": "PaloAltoNetworks/nothing"}}
    assert catalog.releases(p["eol"]) and catalog.product_releases(p) == catalog.releases(p["eol"])
    assert catalog.release_source(p) == {"kind": "eol"}
    assert release_sources.wanted([p]) == []


async def test_egress_guard_refuses_an_internal_page(admin_client, sites, monkeypatch):
    real = catalog.product

    def product(key: str):  # noqa: ANN202
        p = real(key)
        if p and key == "passwork":
            return {**p, "releases": {"page": "https://127.0.0.1/release-notes/", "pattern": p["releases"]["pattern"]}}
        return p

    monkeypatch.setattr(catalog, "product", product)
    await _follow(admin_client, "passwork")
    await _round()
    st = await _state("releases:passwork")
    assert st is not None and st.error == "http: forbidden target"
    assert not any(c.url.host == "127.0.0.1" for c in sites.calls)  # never asked


async def test_catalogue_check_names_a_broken_source(admin_client, sites):
    sites.passwork = 404
    await _follow(admin_client, "passwork")
    sites.github["portainer/portainer"] = _feed("not-a-version")  # the rule finds nothing any more
    await _follow(admin_client, "portainer")
    await _round()
    async with db.session() as s:
        await cc.evaluate(s)
        rows = {r.product: r for r in await s.scalars(select(CatalogCheck).where(CatalogCheck.product.in_(["passwork", "portainer"])))}
    pw = [r for r in rows["passwork"].reasons if r["code"].startswith("releases")]
    assert pw == [{"code": "releases_failed", "level": "warn", "source": "passwork.pro", "error": "http: HTTP 404"}] and rows["passwork"].status == "warn"
    pt = [r for r in rows["portainer"].reasons if r["code"].startswith("releases")]
    assert pt == [{"code": "releases_none", "level": "warn", "source": "GitHub portainer/portainer"}]


def test_catalogue_check_stale_source():
    now = datetime(2026, 11, 11, tzinfo=UTC)
    p = catalog.product("apache-guacamole")
    rel = {"source": "GitHub apache/guacamole-server", "error": None, "newest": date(2025, 3, 1)}
    _, reasons = cc.verdict(p, {}, {}, True, None, False, now, rel)
    assert {"code": "releases_stale", "level": "warn", "source": "GitHub apache/guacamole-server", "months": 20, "last": "2025-03-01"} in reasons
    _, reasons = cc.verdict(p, {}, {}, True, None, False, now, rel | {"newest": (now - timedelta(days=40)).date()})
    assert not [r for r in reasons if r["code"].startswith("releases")]


def test_bloodhound_ce_without_the_legacy_cpe_needs_no_care():
    p = catalog.product("bloodhound")
    assert p["cpes"] == [] and ["SpecterOps", "BloodHound"] in p["cna"]
    assert vendor._keyword_search(p)  # its CVEs (no CPE in the NVD) come from the keyword search and the CNA rows
    status, reasons = cc.verdict(p, {}, {}, True, None, False, datetime.now(UTC))
    assert status == "ok" and reasons == []


def test_release_file_is_json_with_the_format(rel_file):
    release_sources.store("x", {"sig": "s", "versions": []})
    assert json.loads(rel_file.read_text())["format"] == release_sources.FORMAT
