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


def test_script_and_style_dropped_linearly_also_from_a_hostile_page():
    import time

    # not "tame" for nh3 (too many tags): the plain way – script/style content still dropped, the text kept
    many = "<b>x</b>" * 20_001
    page = f"<html>{many}<p>Jun 20, 2026 — Passwork 7.6.2</p><SCRIPT type=x>Aug 03, 2026 — Passwork 9.9.9</SCRIPT><scripts>Jul 01, 2026 — Passwork 7.6.3</scripts>"
    page += "<style>p{}</style><İ><p>May 22, 2026 — Passwork 7.6.1</p><script>never closed Aug 04, 2026 — Passwork 9.9.8"
    vs = release_sources.parse(page.encode(), cfg_of("passwork"))
    assert [v["v"] for v in vs] == ["7.6.2", "7.6.3", "7.6.1"]
    # unclosed "<script" repeated up to PAGE_LIMIT (a backtracking regex took minutes – holding the GIL): well under a second
    for hostile in ("<script " * (release_sources.PAGE_LIMIT // 8), "<script>a" * (release_sources.PAGE_LIMIT // 9), "<style>" + "<script x" * 300_000, "<scriptx" * 380_000):
        t0 = time.perf_counter()
        release_sources.parse(hostile.encode(), cfg_of("passwork"))
        assert time.perf_counter() - t0 < 1.0


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
    # added 0.1.59 (tags as the feeds and the repositories named them, 2026-11-25)
    "keepassxc": [("2.8.0", "2.8.0"), ("2.8.0-beta1", None), ("latest", None)],
    "dockge": [("1.5.0", "1.5.0"), ("1.4.0-beta.0", None)],
    "dfir-iris": [("v2.4.29", "2.4.29"), ("v3.0.0-beta.23", None)],
    "fluentd": [("v1.20.1", "1.20.1")],
    "helm": [("v4.3.2", "4.3.2"), ("v4.3.0-rc.1", None)],
    "privacyidea": [("v3.14.1", "3.14.1"), ("v3.14", "3.14"), ("v3.14dev4", None), ("v3.14.1dev0", None)],
    "rspamd": [("4.3.1", "4.3.1")],
    "unbound": [("release-1.26.2", "1.26.2"), ("release-1.26.0rc1", None)],
    "7-zip": [("26.06", "26.06")],
    "nagios": [("nagios-4.5.14", "4.5.14")],
    "wildfly": [("42.0.0.Final", "42.0.0"), ("42.0.0.Beta1", None)],
    "owncloud": [("v10.16.8", "10.16.8"), ("v11.1.0", "11.1.0")],
    "harvester": [("v1.9.1", "1.9.1"), ("v1.10.0-rc3", None), ("prime-v1.9.1", None)],
    "elastic-agent": [("v9.5.7", "9.5.7")],
    "scubagear": [("v2.0.0", "2.0.0")],
    "pingcastle": [("4.1.2.0", "4.1.2.0")],
    "gpozaurr": [("v1.1.11", "1.1.11")],
    "seafile": [("v13.0.30-server", "13.0.30"), ("v14.0.9-server", "14.0.9")],
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
        # the same rule on the repository's tags (the history)
        assert {v["v"] for v in release_sources.parse_tags(_adv(b"refs/tags/" + tag.encode()), cfg)} == got, (key, tag)


def test_every_github_source_of_the_catalogue_has_its_tags_checked():
    gh = {p["key"] for p in catalog.load()["products"] if (c := release_sources.config(p)) and c.get("github")}
    assert gh - set(TAGS) == {"bloodhound", "portainer", "wazuh"}  # those three: their real feeds above


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
        self.refs: dict[str, bytes | int] = {}  # the repositories' ref advertisements (404 when not set)
        self.passwork: bytes | int = fx("passwork_release_notes.html")

    def atom(self) -> list[httpx.Request]:
        return [c for c in self.to("github.com") if c.url.path.endswith("/releases.atom")]

    def tags(self) -> list[httpx.Request]:
        return [c for c in self.to("github.com") if c.url.path.endswith(".git/info/refs")]

    def handler(self, req: httpx.Request) -> httpx.Response:
        if req.url.host == "github.com" and req.url.path.endswith(".git/info/refs"):
            self.calls.append(req)
            assert req.url.params.get("service") == "git-upload-pack" and "if-none-match" not in req.headers
            body = self.refs.get(req.url.path.removesuffix(".git/info/refs").strip("/"), 404)
            if isinstance(body, int):
                return httpx.Response(body, content=b"")
            return httpx.Response(200, content=body, headers={"Content-Type": "application/x-git-upload-pack-advertisement"})
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
    assert len(sites.atom()) == 1 and rel_file.is_file()
    assert oct(rel_file.stat().st_mode & 0o777) == "0o600"
    await _round()
    assert sites.atom()[-1].headers.get("if-none-match")
    rel_file.unlink()  # a restore without the file: the next fetch asks in full (a 304 would leave it empty)
    release_sources.reset()
    await _round()
    assert "if-none-match" not in sites.atom()[-1].headers
    assert release_sources.lines(catalog.product("portainer"))


async def test_page_source_and_a_shared_feed_asked_once(admin_client, reader_client, sites):
    await _follow(admin_client, "passwork", "7.6.2")
    await _follow(admin_client, "wazuh", "4.14.9")
    await _follow(admin_client, "wazuh-agent", "4.14.9")
    sites.github["wazuh/wazuh"] = fx("github_wazuh.atom")
    await _round()
    assert len(sites.to("passwork.pro")) == 1 and len(sites.atom()) == 1 and len(sites.tags()) == 1  # manager and agent: one request each
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


# ---------------------------------------------------------------- the whole history: the repository's tags (0.1.59)


def _pkt(payload: bytes) -> bytes:
    return b"%04x" % (len(payload) + 4) + payload


def _adv(*refs: bytes, oid: bytes = b"a" * 40) -> bytes:
    body = _pkt(b"# service=git-upload-pack\n") + b"0000"
    for n, ref in enumerate(refs):
        body += _pkt(oid + b" " + ref + (b"\0multi_ack thin-pack agent=git/github\n" if n == 0 else b"\n"))
    return body + b"0000"


def test_tags_of_the_real_wazuh_advertisement_fill_the_missing_lines():
    # the feed's newest 10 had 4.14 and the backport 4.10.5 only – the tags have every line in between
    vs = release_sources.parse_tags(fx("github_wazuh.refs"), cfg_of("wazuh"))
    got = {v["v"] for v in vs}
    assert {"4.13.1", "4.12.0", "4.11.2", "4.10.5", "4.14.10", "3.13.6"} <= got
    assert not any("-" in v for v in got) and all(v["date"] is None and v["lts"] is False for v in vs)  # rcs/betas out, no dates
    names = [ln["name"] for ln in release_sources.lines_of(vs, 2)]
    assert names[:5] == ["4.14", "4.13", "4.12", "4.11", "4.10"]  # by version
    tags = release_sources.git_tags(fx("github_wazuh.refs"))
    assert "v5.0.0-beta3" in tags and len(tags) == len(set(tags)) and not any(t.endswith("^{}") for t in tags)  # peeled once
    assert not any(t.startswith(("refs/", "pull/")) for t in tags)  # branches and pull requests are no tags


def test_ref_advertisement_parser_is_strict_and_bounded(monkeypatch):
    ok = _adv(b"HEAD", b"refs/heads/main", b"refs/pull/1/head", b"refs/tags/v1.2.3", b"refs/tags/v1.2.3^{}", b"refs/tags/v1.3.0-rc1")
    assert release_sources.git_tags(ok) == ["v1.2.3", "v1.3.0-rc1"]
    assert release_sources.git_tags(_adv(b"refs/tags/v2.0.0", oid=b"b" * 64)) == ["v2.0.0"]  # a SHA-256 repository
    bad = [
        b"",  # nothing
        b"<!DOCTYPE html><html>Sign in</html>",  # a page in between
        _pkt(b"# service=git-receive-pack\n") + b"0000",  # another service
        b"zz1e# service=git-upload-pack\n",  # no hex length
        _pkt(b"# service=git-upload-pack\n") + b"0003",  # length below 4 that is no flush/delimiter
        _pkt(b"# service=git-upload-pack\n") + b"ffff" + b"x" * 10,  # beyond the body (a cut answer)
        _pkt(b"# service=git-upload-pack\n") + b"0000" + _pkt(b"not-an-oid refs/tags/v1.0.0\n"),
        _pkt(b"# service=git-upload-pack\n") + b"0000" + _pkt(b"a" * 40 + b"\n"),  # no ref name
        _pkt(b"# service=git-upload-pack\n") + b"0000" + b"%04x" % 65530 + b"a" * 65526,  # longer than a pkt-line can be
    ]
    for body in bad:
        with pytest.raises(ValueError):
            release_sources.git_tags(body)
    monkeypatch.setattr(release_sources, "REFS_PKTS", 50)
    with pytest.raises(ValueError):
        release_sources.git_tags(_pkt(b"# service=git-upload-pack\n") + b"0000" * 100)
    monkeypatch.setattr(release_sources, "REFS_PKTS", 500_000)
    monkeypatch.setattr(release_sources, "TAGS_MAX", 3)
    assert release_sources.git_tags(_adv(*(b"refs/tags/v1.0.%d" % i for i in range(10)))) == ["v1.0.0", "v1.0.1", "v1.0.2"]


def test_ref_advertisement_parser_is_linear():
    import time

    many = _pkt(b"# service=git-upload-pack\n") + b"0000" + b"".join(_pkt(b"a" * 40 + b" refs/pull/%d/head\n" % i) for i in range(300_000))
    assert len(many) > 15_000_000
    t0 = time.perf_counter()
    assert release_sources.git_tags(many) == []
    assert time.perf_counter() - t0 < 3.0


def test_lines_are_ordered_by_version_not_by_the_date_a_backport_was_seen():
    # the live data of 0.1.58: 4.10.5 published 15.09., after 4.14.7 (30.07.) – 4.10 is still the older line
    vs = [
        {"v": "4.14.10", "date": "2026-11-09"},
        {"v": "4.14.7", "date": "2026-07-30"},
        {"v": "4.10.5", "date": "2026-09-15"},
        {"v": "4.13.1", "date": None},
        {"v": "4.14.0", "date": None},
    ]
    lines = release_sources.lines_of(vs, 2)
    assert [ln["name"] for ln in lines] == ["4.14", "4.13", "4.10"]
    # the date a line was first seen is no release date of the line: 4.14.0 has none, 4.10.5 is no line start
    assert "releaseDate" not in lines[0] and "releaseDate" not in lines[2] and lines[0]["latestDate"] == "2026-11-09"
    assert release_sources.lines_of([{"v": "4.15.0", "date": "2026-12-01"}, {"v": "4.15.1", "date": "2026-12-20"}])[0]["releaseDate"] == "2026-12-01"


def _stored(key: str, versions: list[tuple[str, str | None]], **extra) -> None:  # noqa: ANN003
    cfg = cfg_of(key)
    release_sources.store(key, {"sig": release_sources.signature(cfg), "source": release_sources.describe(cfg), "fetched_at": "2026-11-21T16:13:24+00:00",
                                "versions": [{"v": v, "date": d, "lts": False, "base": True} for v, d in versions]} | extra)


def test_newer_line_and_target_by_version_for_a_release_source():
    _stored("wazuh", [("4.14.10", "2026-11-09"), ("4.14.7", "2026-07-30"), ("4.10.5", "2026-09-15")])
    p = catalog.product("wazuh")
    assert [ln["name"] for ln in catalog.product_releases(p)] == ["4.14", "4.10"]
    assert vendor.newest_line(p, catalog.product_releases(p))["name"] == "4.14"
    cur = vendor.release_info(p, "4.14.10")
    assert cur["line"]["name"] == "4.14" and cur["newer_line"] is None and not cur["update_available"]  # 4.10 is older, never "Neuere Linie"
    old = vendor.release_info(p, "4.10.2")
    assert old["newer_line"]["name"] == "4.14" and old["update_available"] and old["line"]["latest"] == "4.10.5"
    # endoflife.date's lines keep their own order (the line's release date)
    pan = catalog.product("panos")
    rels = catalog.product_releases(pan)
    assert vendor.newest_line(pan, rels) == max([r for r in rels if r.get("isMaintained") or not r.get("isEol")] or rels, key=lambda r: r.get("releaseDate") or "")


def test_merge_backfilled_tags_are_a_baseline_later_ones_news():
    cfg = cfg_of("wazuh")
    now = datetime(2026, 11, 25, tzinfo=UTC)
    # an installation of 0.1.58: the feed's versions, no history
    before, _ = release_sources.merge(None, [{"v": "4.14.10", "date": "2026-11-09"}, {"v": "4.10.5", "date": "2026-09-15"}], cfg, now - timedelta(days=14))
    assert "history" not in before and release_sources.history_due(before, now)
    tags = release_sources.parse_tags(fx("github_wazuh.refs"), cfg)
    filled, new = release_sources.merge(before, [], cfg, now, tags=tags)
    assert new == 0 and all(r["base"] for r in filled["versions"])  # the old lines filled in silently
    assert filled["history"]["ok_at"] and filled["history"]["error"] is None
    assert len(filled["versions"]) == len(tags) and next(r for r in filled["versions"] if r["v"] == "4.14.10")["date"] == "2026-11-09"  # the feed's date kept
    assert not release_sources.history_due(filled, now + timedelta(days=6)) and release_sources.history_due(filled, now + timedelta(days=7))
    # a week later the tags have a version nobody saw (more than 10 releases between two fetches): news
    later, new = release_sources.merge(filled, [], cfg, now + timedelta(days=7), tags=[*tags, {"v": "4.13.2", "date": None, "lts": False}])
    assert new == 1 and next(r for r in later["versions"] if r["v"] == "4.13.2")["base"] is False
    # an old tag below the KEEP_VERSIONS newest is trimmed again – no news
    many = [{"v": f"4.14.{i}", "date": None, "lts": False} for i in range(11, 11 + release_sources.KEEP_VERSIONS)]
    full, _ = release_sources.merge(filled, many, cfg, now)
    again, new = release_sources.merge(full, [], cfg, now + timedelta(days=7), tags=[*tags, {"v": "1.0.1", "date": None, "lts": False}])
    assert new == 0 and len(again["versions"]) == release_sources.KEEP_VERSIONS
    # a failure keeps the history and is tried again a day later (a week when it was too large)
    failed, _ = release_sources.merge(filled, [], cfg, now + timedelta(days=8), history_error="timeout")
    assert failed["history"]["ok_at"] == filled["history"]["ok_at"] and failed["history"]["error"] == "timeout"
    assert not release_sources.history_due(failed, now + timedelta(days=8, hours=23)) and release_sources.history_due(failed, now + timedelta(days=9))
    big, _ = release_sources.merge(None, [{"v": "4.14.10", "date": None}], cfg, now, history_error="too_large: > 16384 KB")
    assert not release_sources.history_due(big, now + timedelta(days=2)) and release_sources.history_due(big, now + timedelta(days=7))


async def test_round_reads_the_tags_once_a_week_and_the_upgrade_stays_silent(admin_client, reader_client, sites):
    sites.github["wazuh/wazuh"] = fx("github_wazuh.atom")
    sites.refs["wazuh/wazuh"] = 500  # the tags not readable on the first round: the feed's releases still count
    await _follow(admin_client, "wazuh", "4.12.0")
    await _round()
    assert len(sites.tags()) == 1
    src_ = (await reader_client.get("/api/vendor/products/wazuh")).json()["releases"]["source"]
    assert src_["complete"] is False and src_["known"] == 5  # the drawer says: only the newest releases
    assert [ln["name"] for ln in (await reader_client.get("/api/vendor/products/wazuh")).json()["releases"]["lines"]] == ["4.14", "4.10"]
    # a day later the tags answer: 4.12's own line appears with its latest 4.12.0 – the filled-in history is a baseline
    sites.refs["wazuh/wazuh"] = fx("github_wazuh.refs")
    async with db.session() as s:
        (await s.get(VendorFetch, "releases:wazuh")).next_fetch_at = None
        await s.commit()
    release_sources._cache.stamp = None
    e = release_sources.entry("wazuh")
    e["history"]["tried_at"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    release_sources.store("wazuh", e)
    await _round()
    assert len(sites.tags()) == 2
    d = (await reader_client.get("/api/vendor/products/wazuh")).json()
    assert d["releases"]["source"]["complete"] is True and d["releases"]["source"]["known"] > 100
    assert [ln["name"] for ln in d["releases"]["lines"]][:5] == ["4.14", "4.13", "4.12", "4.11", "4.10"]
    rel = d["versions"][0]["release"]
    assert rel["line"]["name"] == "4.12" and not rel["update_available"] and rel["newer_line"]["name"] == "4.14"
    assert all(e.baseline for e in await _version_events())
    # not due again within the week: the feed only
    await _round()
    assert len(sites.tags()) == 2


async def test_upgrade_of_an_installation_with_the_feed_only_makes_no_news(admin_client, sites):
    """0.1.58 stored the feed's 5 versions (base); 0.1.59's first round fills 4.11–4.13 in from the tags: whatever
    becomes a line's latest (4.13.1 for an installed 4.13.0) was out long ago – shown, not notified."""
    _stored("wazuh", [("4.14.10", "2026-11-09"), ("4.14.9", "2026-10-15"), ("4.14.8", "2026-09-25"), ("4.14.7", "2026-07-30"), ("4.10.5", "2026-09-15")], since="2026-11-11T16:24:35+00:00")
    sites.github["wazuh/wazuh"] = fx("github_wazuh.atom")
    sites.refs["wazuh/wazuh"] = 500
    await _follow(admin_client, "wazuh", "4.13.0", "4.10.2")
    await _round()  # the follow's own baseline is made (4.10.2 → 4.10.5 silently); 4.13 is no line yet
    assert [(e.key, e.baseline) for e in await _version_events()] == [("version:wazuh:4.10.2:4.10.5", True)]
    e = release_sources.entry("wazuh")
    assert not e["history"].get("ok_at") and e["history"]["error"] == "http: HTTP 500"
    e["history"]["tried_at"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    release_sources.store("wazuh", e)
    sites.refs["wazuh/wazuh"] = fx("github_wazuh.refs")
    async with db.session() as s:
        (await s.get(VendorFetch, "releases:wazuh")).next_fetch_at = None
        await s.commit()
    await _round()
    evs = await _version_events()
    assert [(e.key, e.baseline) for e in evs] == [("version:wazuh:4.10.2:4.10.5", True), ("version:wazuh:4.13.0:4.13.1", True)]


def test_drawer_source_says_how_complete_it_is():
    p = catalog.product("wazuh")
    assert release_sources.info(p)["fetched_at"] is None and "complete" not in release_sources.info(p)
    _stored("wazuh", [("4.14.10", "2026-11-09")])
    assert release_sources.info(p)["complete"] is False and release_sources.info(p)["known"] == 1
    _stored("wazuh", [("4.14.10", "2026-11-09")], history={"ok_at": "2026-11-25T00:00:00+00:00", "tried_at": "2026-11-25T00:00:00+00:00", "error": None})
    assert release_sources.info(p)["complete"] is True
    pw = catalog.product("passwork")
    _stored("passwork", [("7.7.0", "2026-08-03")])
    assert release_sources.info(pw)["complete"] is None  # a page: what it lists


# ---------------------------------------------------------------- ManageEngine ServiceDesk Plus: builds from the ReadMe


def test_servicedesk_plus_readme_builds_and_lines():
    p = catalog.product("manageengine-servicedesk")
    vs = release_sources.parse(fx("manageengine_sdp_readme.html"), cfg_of("manageengine-servicedesk"))
    # both date forms; the notes' "fixed in build 15280" and a script's text are no release
    assert [(v["v"], v["date"]) for v in vs] == [
        ("16040", "2026-11-19"), ("16030", "2026-11-04"), ("15100", "2025-06-18"), ("14990", "2025-08-11"), ("14870", "2025-08-13"),
        ("14600", "2023-12-11"), ("14000", "2022-09-29"), ("13013", "2023-06-29"), ("13000", "2022-02-07"),
    ]  # fmt: skip
    lines = release_sources.lines_of(vs, 2, "build", complete=True)
    assert [(ln["name"], ln["latest"], ln.get("releaseDate")) for ln in lines] == [
        ("16", "16.0 Build 16040", "2026-11-04"), ("15", "15.1 Build 15100", "2025-06-18"), ("14", "14.9 Build 14990", "2022-09-29"), ("13", "13.0 Build 13013", "2022-02-07"),
    ]  # fmt: skip  - a backport (14870 after 14990) is no newer release of the line
    cfg = cfg_of("manageengine-servicedesk")
    e, _ = release_sources.merge(None, vs, cfg, datetime(2026, 11, 25, tzinfo=UTC))
    release_sources.store(p["key"], e)
    info = vendor.release_info(p, "14.6 Build 14600")
    assert info["line"]["name"] == "14" and info["line"]["latest"] == "14.9 Build 14990" and info["update_available"]
    assert info["newer_line"]["name"] == "16" and info["source"]["kind"] == "page" and info["source"]["ref"] == "www.manageengine.com"
    assert vendor.release_info(p, "14990")["update_available"] is False  # a bare build is the same version
    assert catalog.release_baseline(p, "14.9 Build 14990") and not catalog.release_baseline(p, "14.9 Build 14991")
    assert not vendor.short_version(p, "14.6 Build 14600")


async def test_a_feed_of_pre_releases_only_is_no_error_while_the_tags_know_versions(admin_client, reader_client, sites):
    """DFIR-IRIS: the feed's newest 10 are all v3.0.0-beta.N – the stable 2.4 line comes from the tags."""
    sites.github["dfir-iris/iris-web"] = _feed(*(f"v3.0.0-beta.{n}" for n in range(1, 10)))
    sites.refs["dfir-iris/iris-web"] = _adv(b"refs/tags/v2.4.29", b"refs/tags/v2.4.28", b"refs/tags/v3.0.0-beta.9")
    await _follow(admin_client, "dfir-iris", "2.4.28")
    await _round()
    st = await _state("releases:dfir-iris")
    assert st is not None and st.error is None
    rel = (await reader_client.get("/api/vendor/products/dfir-iris")).json()["versions"][0]["release"]
    assert rel["line"]["latest"] == "2.4.29" and rel["update_available"]
    # neither the feed nor the tags know a version: the source is broken
    sites.github["SpecterOps/BloodHound"] = _feed("v9.10.0-rc1")
    sites.refs["SpecterOps/BloodHound"] = _adv(b"refs/tags/v9.10.0-rc1")
    await _follow(admin_client, "bloodhound")
    await _round()
    assert (await _state("releases:bloodhound")).error == "parse: no version found"
