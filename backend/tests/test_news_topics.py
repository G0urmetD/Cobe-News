"""Topics of the news (0.1.46): detection in title and teaser (German and English, denials, duties to report, ads),
from the structured data (catalogues, the KEV by CVE – not for digests –, details, CSAF remediations, OT sources), the
CRA press release that is no exploitation, recomputing on store / update / CVE merge / details / KEV changes, the
background job, the API (filter, facets, read-all, /api/v1) and the KEV's single download with the GitHub mirror."""

import importlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import set_news
from sqlalchemy import select, text, update

from app import db, news, story_details, vendor
from app.models import NewsItem, NewsSource, StoryDetail, VendorFetch, VendorKev

FIX = Path(__file__).parent / "fixtures" / "news"
KEV = (FIX / "kev.json").read_bytes()


def topics(title: str, teaser: str = "", source: str = "heise", ids=None, **kw) -> list[str]:  # noqa: ANN001, ANN003
    return news.topic_list(title, teaser, source, ids, **kw)


# ---------------------------------------------------------------- wording


@pytest.mark.parametrize(
    ("title", "teaser", "expected"),
    [
        # zero-day (and with it exploited) – German and English, denied ones and programs are none
        ("Chrome-Zero-Day: Google schließt Lücke", "", ["zeroday", "exploited"]),
        ("Google patches 0-day in Chrome", "", ["zeroday", "exploited"]),
        ("Kein Zero-Day: Lücke in Beispiel-Router", "", []),
        ("Gemeldet über die Zero-Day-Initiative", "", []),
        ("Microsoft startet Zero Day Quest 2027", "", []),
        # exploited
        ("Fortinet flaw actively exploited", "", ["exploited"]),
        ("Lücke in Exchange", "Die Schwachstelle wird bereits aktiv ausgenutzt.", ["exploited"]),
        ("Hackers exploit the flaw in the wild", "", ["exploited"]),
        ("Cisco", "Cisco is not aware of exploitation in the wild.", []),
        ("Ivanti-Update", "Es gibt keine Hinweise auf eine aktive Ausnutzung.", []),
        ("Lücke in Exchange", "Die Lücke wird bislang nicht aktiv ausgenutzt.", []),
        ("Patch for router", "The vulnerability is not actively exploited.", []),
        # a duty to report is no exploitation (the CRA)
        ("Cyber Resilience Act: Meldepflicht startet", "Hersteller müssen aktiv ausgenutzte Schwachstellen binnen 24 Stunden an die ENISA melden.", []),
        ("EU rules", "Manufacturers must report actively exploited vulnerabilities within 24 hours.", []),
        ("Neue Regeln", "Ab September gilt die Meldepflicht für aktiv ausgenutzte Lücken.", []),
        # ransomware
        ("Ransomware-Angriff auf Stadtwerke", "", ["ransomware", "breach"]),
        ("LockBit claims attack on retailer", "", ["ransomware"]),
        ("Erpressertrojaner legt Klinik lahm", "", ["ransomware"]),
        # no patch
        ("[UNGEPATCHT] [hoch] Microsoft Exchange: Schwachstelle", "", ["nopatch"]),
        ("Ivanti: no patch yet for VPN bug", "", ["nopatch"]),
        ("Lücke in Router", "Einen Patch gibt es noch nicht, noch kein Update verfügbar.", ["nopatch"]),
        ("Update für Firefox", "Kein Patch nötig für ESR.", []),
        ("Attackers target unpatched Fortinet devices", "", []),  # a patch exists: not "ohne Patch"
        # incident / data leak
        ("Datenleck bei Versicherer", "", ["breach"]),
        ("Cyberangriff auf Landkreis", "", ["breach"]),
        ("Retailer confirms data breach", "Customer data was stolen.", ["breach"]),
        # supply chain
        ("Malicious npm packages steal tokens", "", ["supply"]),
        ("Angriff auf die Lieferkette", "", ["supply"]),
        ("Typosquatting on PyPI", "", ["supply"]),
        ("npm 11 released with faster installs", "", []),
        # phishing / social engineering – a campaign or a threat actor alone is none
        ("New ClickFix lures", "", ["phishing"]),
        ("Phishing-Welle mit gefälschten Paketmails", "", ["phishing"]),
        ("Vishing gang targets helpdesks", "Social engineering of IT staff.", ["phishing"]),
        ("Threat actor launches campaign against telcos", "", []),
        # OT/ICS
        ("Siemens SIMATIC S7: Schwachstelle", "", ["ot"]),
        ("CODESYS runtime flaw affects PLCs", "", ["ot"]),
        ("SCADA-Systeme im Visier", "", ["ot"]),
        ("Robot vacuum bug", "", []),
        # ads: no wording topics
        ("heise-Angebot: Phishing erkennen – der Workshop", "", []),
        ("Webinar: Ransomware abwehren", "", []),
        ("Zero-Day-Exploits verstehen (g+)", "", []),
    ],
)
def test_wording(title: str, teaser: str, expected: list[str]):
    got = topics(title, teaser)
    assert sorted(got) == sorted(expected), (title, teaser, news.topics_of(title, teaser, "heise"))
    assert got == [t for t in news.TOPICS if t in got]  # ordered as the badges


def test_only_title_and_teaser_count_and_reasons_say_where():
    got = news.topics_of("Patchday im November", "Microsoft schließt 60 Lücken; eine davon wird aktiv ausgenutzt.", "heise")
    assert got == {"exploited": {"kind": "teaser", "value": "wird aktiv ausgenutzt"}}
    assert news.topics_of("Zero-Day in Chrome", "", "heise") == {"zeroday": {"kind": "title", "value": "Zero-Day"}, "exploited": {"kind": "zeroday", "value": ""}}


def test_the_cra_press_release_is_not_critical():
    """Rated critical before 0.1.46 ("aktiv ausgenutzte" in its teaser): a duty to report names a class of bugs, it is
    no exploitation – the severity rule and the topic rule both leave it."""
    title = "Cyber Resilience Act: Meldepflicht startet"
    teaser = "Ab dem 11. September 2026 müssen Hersteller aktiv ausgenutzte Schwachstellen und schwerwiegende Sicherheitsvorfälle an die ENISA melden."
    level, reasons = news.rate(title, teaser)
    assert level == "medium" and not any(r["kind"] == "exploited" for r in reasons), reasons
    assert news.rate("CRA: what changes", "Manufacturers will have to report actively exploited vulnerabilities.")[0] != "critical"
    # an exploitation stays one, also with a "must" in another sentence
    assert news.rate("Exchange", "Die Lücke wird aktiv ausgenutzt. Admins müssen das Update sofort installieren.")[0] == "critical"
    assert news.rate("Microsoft meldet aktiv ausgenutzte Lücke", "")[0] == "critical"


# ---------------------------------------------------------------- structured


def test_catalogues_kev_and_digests():
    kev_reasons = [{"kind": "kev", "value": "2026-11-10"}, {"kind": "ransomware", "value": "CISA"}]
    # the KEV's own story: exploited, its ransomware flag; its boilerplate text is never read
    assert topics("CVE-2026-59310 · Broadcom vCenter", "Known ransomware campaign use: Unknown phishing", "cisa-kev", ["CVE-2026-59310"], reasons=kev_reasons) == ["exploited", "ransomware"]
    assert topics("EUVD-2026-1: x", "phishing zero-day", "enisa-euvd", []) == ["exploited"]
    # another story with the same CVE: exploited by the KEV – never its ransomware flag
    assert topics("vCenter: Lücke CVE-2026-59310", "", "heise", ["CVE-2026-59310"], kev={"CVE-2026-59310"}) == ["exploited"]
    assert news.topics_of("vCenter", "", "heise", ["CVE-2026-59310"], kev={"CVE-2026-59310"})["exploited"] == {"kind": "kev", "value": "CVE-2026-59310"}
    # a digest of many CVEs: only when its title or teaser names the KEV CVE
    many = [f"CVE-2026-{1000 + n}" for n in range(10)]
    assert topics("Patchday: 10 Lücken", "", "heise", many, kev={"CVE-2026-1003"}) == []
    assert topics("Patchday: 10 Lücken", "Darunter CVE-2026-1003.", "heise", many, kev={"CVE-2026-1003"}) == ["exploited"]
    assert topics("Drei Lücken", "", "heise", many[:3], kev={"CVE-2026-1002"}) == ["exploited"]
    # … and the details' "exploited" does not bring it back for a digest with a KEV CVE
    assert topics("Patchday: 10 Lücken", "", "heise", many, kev={"CVE-2026-1003"}, details={"exploited": True}) == []
    assert topics("Lücke", "", "bsi-csw", ["CVE-2026-5555"], details={"exploited": True, "publisher": "BSI"}) == ["exploited"]
    # a story the KEV carries (same CVE: its reasons): exploited – its ransomware flag counts, it is the KEV's story too
    assert topics("Version 1.0: Adobe Commerce", "", "bsi-csw", ["CVE-2026-48356"], reasons=kev_reasons) == ["exploited", "ransomware"]


def test_no_patch_from_csaf_and_ot_from_sources():
    none = {"remediations": [{"category": "none_available", "text": "", "url": ""}]}
    assert topics("Schwachstelle in Produkt", "", "bsi-csw", details=none) == ["nopatch"]
    both = {"remediations": [{"category": "no_fix_planned"}, {"category": "vendor_fix"}]}
    assert topics("Schwachstelle in Produkt", "", "bsi-csw", details=both) == []
    assert topics("SSA-123456: Vulnerability in RUGGEDCOM", "", "siemens-productcert") == ["ot"]
    assert news.topics_of("x", "", "certvde")["ot"] == {"kind": "source", "value": "certvde"}


# ---------------------------------------------------------------- stored and recomputed


async def _sources() -> dict[str, NewsSource]:
    async with db.session() as s:
        await news.ensure_sources(s)
        return {x.key: x for x in await s.scalars(select(NewsSource))}


def _entry(title: str, summary: str = "", link: str | None = None, **kw) -> dict:  # noqa: ANN003
    return {"link": link or f"https://news.example.org/{uuid.uuid4()}", "title": title, "summary": summary, "content": "", "date": datetime.now(UTC) - timedelta(hours=1), **kw}


async def _topics_of() -> dict[str, list[str]]:
    async with db.session() as s:
        return {i.title: list(i.topics) for i in await s.scalars(select(NewsItem))}


async def test_store_update_and_merge_compute_topics():
    src = await _sources()
    heise = src["heise"]
    async with db.session() as s:
        await news.store(s, heise, [_entry("Lücke in Exchange", "Patch kommt.", link="https://www.heise.de/a")])
    assert (await _topics_of())["Lücke in Exchange"] == []
    # the source changed the story: "[UPDATE] … wird aktiv ausgenutzt" – its topics follow
    async with db.session() as s:
        await news.store(s, heise, [_entry("Lücke in Exchange wird aktiv ausgenutzt", "Patch kommt.", link="https://www.heise.de/a")])
    assert (await _topics_of())["Lücke in Exchange wird aktiv ausgenutzt"] == ["exploited"]
    # a BSI warning on one CVE, then the KEV entry of that CVE: the same story – "exploited" by the KEV's reasons
    warn = _entry("Version 1.0: Adobe Commerce - Schwachstelle CVE-2026-48356", "Angreifer laden Dateien hoch.", date=datetime(2026, 10, 27, 12, tzinfo=UTC))
    async with db.session() as s:
        await news.store(s, src["bsi-csw"], [warn])
    assert (await _topics_of())[warn["title"]] == []
    entries = [e for e in news.parse_feed(KEV)[0] if e["cves"] == ["CVE-2026-48356"]]
    async with db.session() as s:
        assert await news.store(s, src["cisa-kev"], entries) == 0
    assert (await _topics_of())[warn["title"]] == ["exploited"]


async def test_a_new_kev_story_marks_the_other_stories_of_its_cve():
    src = await _sources()
    article = _entry("vCenter: Lücke CVE-2026-59310 geschlossen", "Broadcom liefert Updates.")
    async with db.session() as s:
        await news.store(s, src["heise"], [article])
    assert (await _topics_of())[article["title"]] == []
    async with db.session() as s:
        await news.store(s, src["cisa-kev"], news.parse_feed(KEV)[0])
    got = await _topics_of()
    assert got[article["title"]] == ["exploited"]  # not "ransomware" – the KEV flag stays on the KEV's story
    assert got["CVE-2026-59310 · Broadcom VMware vCenter: Path Traversal Vulnerability"] == ["exploited", "ransomware"]


async def test_kev_changes_and_details_recompute():
    src = await _sources()
    article = _entry("Exchange: Lücke CVE-2026-77777", "Microsoft patcht.")
    async with db.session() as s:
        await news.store(s, src["heise"], [article])
        s.add(VendorKev(cve="CVE-2026-00001"))  # the catalogue was there before (not a first fetch)
        await s.commit()
    body = b'{"vulnerabilities": [{"cveID": "CVE-2026-00001"}, {"cveID": "CVE-2026-77777", "dateAdded": "2026-11-01"}]}'
    async with db.session() as s:
        n, added, first = await vendor.kev_store(s, body)
        await s.commit()
    assert (n, [a["cve"] for a in added], first) == (2, ["CVE-2026-77777"], False)
    assert (await _topics_of())[article["title"]] == ["exploited"]
    # details arrive: CSAF says no fix – "ohne Patch" (enrich_round computes them again, as retopic here)
    async with db.session() as s:
        item = await s.scalar(select(NewsItem).where(NewsItem.title == article["title"]))
        s.add(StoryDetail(item_id=item.id, kind="bsi", status="ok", data={"exploited": False, "remediations": [{"category": "none_available"}]}))
        await s.commit()
        await news.retopic(s, NewsItem.id == item.id)
        await s.commit()
    assert (await _topics_of())[article["title"]] == ["exploited", "nopatch"]


async def test_enrich_round_recomputes(monkeypatch):
    await set_news(enabled=True, details=True)
    src = await _sources()
    async with db.session() as s:
        await news.store(s, src["bsi-csw"], [_entry("[hoch] Produkt: Schwachstelle", "x", link="https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0001")])

    async def build(*a, **kw):  # noqa: ANN002, ANN003
        return {"kind": "bsi", "publisher": "BSI", "exploited": True, "remediations": [], "products": [], "cves": [], "cvss": []}

    monkeypatch.setattr(story_details, "build", build)
    monkeypatch.setattr(story_details, "plan", lambda *a: ("bsi", "WID-SEC-2026-0001", "https://example.org/csaf.json"))
    async with db.session() as s:
        assert await story_details.enrich_round(s) == 1
    assert (await _topics_of())["[hoch] Produkt: Schwachstelle"] == ["exploited"]


async def test_first_kev_fetch_and_backfill_job():
    src = await _sources()
    async with db.session() as s:
        await news.store(s, src["heise"], [_entry("Chrome-Zero-Day", ""), _entry("vCenter CVE-2026-59310", "")])
        # as after the upgrade: stored before topics existed
        await s.execute(update(NewsItem).values(topics=[]))
        await s.execute(text("DELETE FROM counters WHERE name = 'news_topics_v'"))
        await s.commit()
    monkey = news.RETOPIC_BATCH
    news.RETOPIC_BATCH = 1  # chunks of one: every chunk boundary is crossed
    try:
        async with db.session() as s:
            assert await news.backfill_topics(s) == 1  # the zero-day; vCenter is in no KEV yet
            assert await news.backfill_topics(s) is None  # done: one counter read
            # the KEV's first fetch (the whole catalogue): every story again with the next round
            await vendor.kev_store(s, KEV)
            await s.commit()
            assert await news.topics_due(s)
            assert await news.backfill_topics(s) == 1
    finally:
        news.RETOPIC_BATCH = monkey
    got = await _topics_of()
    assert got["Chrome-Zero-Day"] == ["zeroday", "exploited"] and got["vCenter CVE-2026-59310"] == ["exploited"]


# ---------------------------------------------------------------- the API


async def _seed() -> dict[str, str]:
    await set_news(enabled=True)
    src = await _sources()
    async with db.session() as s:
        await news.store(
            s,
            src["heise"],
            [_entry("Chrome-Zero-Day geschlossen"), _entry("Ransomware trifft Klinik"), _entry("Datenleck bei Shop"), _entry("Neue Version von Firefox")],
        )
        rows = {i.title: i for i in await s.scalars(select(NewsItem))}
        rows["Ransomware trifft Klinik"].severity = "critical"
        await s.commit()
        return {t: str(i.id) for t, i in rows.items()}


async def test_api_filter_facets_and_drawer(reader_client):
    ids = await _seed()
    r = await reader_client.get("/api/news", params={"state": "all"})
    page = r.json()
    assert page["counts"]["topics"] == {"zeroday": 1, "exploited": 1, "ransomware": 1, "nopatch": 0, "breach": 1, "supply": 0, "phishing": 0, "ot": 0}
    assert {i["title"]: i["topics"] for i in page["items"]}["Chrome-Zero-Day geschlossen"] == ["zeroday", "exploited"]
    # OR within the topics, AND with the severity; the facets ignore the topic filter, follow the others
    got = (await reader_client.get("/api/news", params=[("state", "all"), ("topic", "zeroday"), ("topic", "breach")])).json()
    assert sorted(i["title"] for i in got["items"]) == ["Chrome-Zero-Day geschlossen", "Datenleck bei Shop"]
    assert got["counts"]["topics"]["ransomware"] == 1 and got["counts"]["new"] == 2
    got = (await reader_client.get("/api/news", params=[("state", "all"), ("topic", "ransomware"), ("severity", "info")])).json()
    assert got["items"] == []
    got = (await reader_client.get("/api/news", params=[("state", "all"), ("severity", "critical")])).json()
    assert got["counts"]["topics"] == {**dict.fromkeys(news.TOPICS, 0), "zeroday": 1, "exploited": 1, "ransomware": 1}  # the breach is "high"
    assert (await reader_client.get("/api/news", params={"topic": "nonsense"})).status_code == 422
    # the drawer says why
    d = (await reader_client.get(f"/api/news/{ids['Chrome-Zero-Day geschlossen']}")).json()
    assert d["topic_reasons"] == [{"topic": "zeroday", "kind": "title", "value": "Zero-Day"}, {"topic": "exploited", "kind": "zeroday", "value": ""}]
    # the source filter knows each source's kind
    kinds = {x["key"]: x["category"] for x in (await reader_client.get("/api/news/sources")).json()}
    assert kinds["heise"] == "press" and kinds["bsi-csw"] == "authority" and kinds["cisa-kev"] == "catalog"


async def test_read_all_with_a_topic_marks_only_those(reader_client):
    await _seed()
    page = (await reader_client.get("/api/news", params={"topic": "zeroday"})).json()
    r = await reader_client.post("/api/news/read-all", json={"topic": ["zeroday"], "upto": page["upto"]})
    assert r.json() == {"marked": 1}
    left = sorted(i["title"] for i in (await reader_client.get("/api/news")).json()["items"])
    assert left == ["Datenleck bei Shop", "Neue Version von Firefox", "Ransomware trifft Klinik"]
    assert (await reader_client.post("/api/news/read-all", json={"topic": ["bogus"]})).status_code == 422


async def test_api_v1_topics(admin_client):
    from test_api_tokens import get, make_token

    await _seed()
    token = await make_token(admin_client)
    r = await get("/api/v1/news", token, params=[("topic", "ransomware"), ("topic", "breach")])
    assert r.status_code == 200, r.text
    assert sorted((i["title"], tuple(i["topics"])) for i in r.json()["items"]) == [("Datenleck bei Shop", ("breach",)), ("Ransomware trifft Klinik", ("ransomware",))]
    assert (await get("/api/v1/news", token, params={"topic": "x"})).status_code == 422
    spec = (await admin_client.get("/api/admin/api-tokens/openapi.json")).json()
    params = {p["name"] for p in spec["paths"]["/api/v1/news"]["get"]["parameters"]}
    assert "topic" in params and "topics" in spec["components"]["schemas"]["Story"]["properties"]


# ---------------------------------------------------------------- the KEV: one download, the mirror


class Cisa:
    def __init__(self, status: int = 200):
        self.status = status
        self.calls: list[httpx.Request] = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        if req.url.path.endswith((".ico", ".png")):
            return httpx.Response(404)
        if req.url.host == "www.cisa.gov":
            if self.status != 200:
                return httpx.Response(self.status)
            if req.headers.get("if-none-match") == '"c1"':
                return httpx.Response(304)
            return httpx.Response(200, content=KEV, headers={"etag": '"c1"'})
        if req.url.host == "raw.githubusercontent.com":
            assert req.url.path == "/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
            if req.headers.get("if-none-match") == '"g1"':
                return httpx.Response(304)
            return httpx.Response(200, content=KEV, headers={"etag": '"g1"'})
        raise AssertionError(f"unexpected {req.url}")

    def hosts(self) -> list[str]:
        return [c.url.host for c in self.calls if not c.url.path.endswith((".ico", ".png"))]


async def _only_kev() -> None:
    await set_news(enabled=True, every_min=30, keep_days=3650)
    async with db.session() as s:
        await news.ensure_sources(s)
        await s.execute(update(NewsSource).where(NewsSource.key != "cisa-kev").values(enabled=False))
        await s.commit()


async def test_one_kev_download_feeds_news_and_vendor_news(monkeypatch):
    await _only_kev()
    site = Cisa()
    mock = httpx.MockTransport(site.handler)
    monkeypatch.setattr(vendor, "transport", mock)
    news._host_last.clear()
    vendor.reset()
    assert (await news.refresh_due(transport=mock))["cisa-kev"] >= 1
    async with db.session() as s:
        assert {k.cve for k in await s.scalars(select(VendorKev))} == {"CVE-2026-48356", "CVE-2026-109618", "CVE-2026-59310", "CVE-2021-44228"}
        st = await s.get(VendorFetch, "kev")
        assert st is not None and st.last_ok_at is not None and st.next_fetch_at > datetime.now(UTC) + timedelta(hours=20)
    # Vendor News' round (nothing followed – the news need the KEV): no second download, the news brought it
    await vendor.run_round(force=True)
    assert site.hosts() == ["www.cisa.gov"]
    # the next news fetch is conditional – 304, the catalogue counts as checked
    async with db.session() as s:
        await s.execute(update(NewsSource).values(next_fetch_at=None))
        await s.commit()
    news._host_last.clear()
    assert (await news.refresh_due(transport=mock))["cisa-kev"] == 0
    assert site.calls[-1].headers["if-none-match"] == '"c1"'


async def test_kev_unconditional_while_the_catalogue_is_empty():
    """After the upgrade the news source has an ETag, the catalogue is empty: asked in full, not "unchanged"."""
    await _only_kev()
    site = Cisa()
    async with db.session() as s:
        await s.execute(update(NewsSource).where(NewsSource.key == "cisa-kev").values(etag='"c1"'))
        await s.commit()
    news._host_last.clear()
    await news.refresh_due(transport=httpx.MockTransport(site.handler))
    assert "if-none-match" not in site.calls[0].headers
    async with db.session() as s:
        assert await s.scalar(select(VendorKev.cve).limit(1)) is not None


async def test_kev_mirror_after_403(monkeypatch):
    await _only_kev()
    site = Cisa(status=403)
    mock = httpx.MockTransport(site.handler)
    news._host_last.clear()
    assert (await news.refresh_due(transport=mock))["cisa-kev"] >= 1
    assert site.hosts() == ["www.cisa.gov", "raw.githubusercontent.com"]
    async with db.session() as s:
        src = await s.scalar(select(NewsSource).where(NewsSource.key == "cisa-kev"))
        assert src.error is None and src.etag == '"g1"' and await s.scalar(select(VendorKev.cve).limit(1)) is not None
    # Vendor News on its own (the news source off): the same fallback through its request path
    async with db.session() as s:
        await s.execute(update(NewsSource).values(enabled=False))
        await s.execute(update(VendorFetch).where(VendorFetch.key == "kev").values(next_fetch_at=None))
        await s.commit()
    monkeypatch.setattr(vendor, "transport", mock)
    vendor.reset()
    site.calls.clear()
    await vendor.run_round(force=True)
    assert site.hosts() == ["www.cisa.gov", "raw.githubusercontent.com"]
    async with db.session() as s:
        st = await s.get(VendorFetch, "kev")
        assert st.error is None and st.items == 4


async def test_kev_rate_limit_pauses():
    await _only_kev()
    site = Cisa(status=429)
    news._host_last.clear()
    assert (await news.refresh_due(transport=httpx.MockTransport(site.handler)))["cisa-kev"] == -1
    assert site.hosts() == ["www.cisa.gov"]  # no mirror on a rate limit – the pause of the source applies
    async with db.session() as s:
        src = await s.scalar(select(NewsSource).where(NewsSource.key == "cisa-kev"))
        assert src.error.startswith("rate_limited") and src.next_fetch_at > datetime.now(UTC) + timedelta(minutes=50)


async def test_kev_fetched_with_nothing_followed():
    await set_news(enabled=True)
    async with db.session() as s:
        assert await vendor.kev_wanted(s) and "kev" in await vendor.active_keys(s)
    await set_news(enabled=False)
    async with db.session() as s:
        assert not await vendor.kev_wanted(s) and "kev" not in await vendor.active_keys(s)


# ---------------------------------------------------------------- the migration


async def test_migration_0024_up_and_down():
    from alembic import command

    prev = importlib.import_module("app.migrations.versions.0024_news_topics").down_revision
    assert prev == "0023"

    def step(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), prev)
        cols = {r[0] for r in conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name = 'news_items'"))}
        command.upgrade(db.alembic_config(conn), "0024")
        idx = {r[0] for r in conn.execute(text("SELECT indexname FROM pg_indexes WHERE tablename = 'news_items'"))}
        default = conn.execute(text("SELECT column_default, is_nullable FROM information_schema.columns WHERE table_name = 'news_items' AND column_name = 'topics'")).one()
        return cols, idx, default

    async with db.engine().connect() as conn:
        trans = await conn.begin()
        try:
            cols, idx, default = await conn.run_sync(step)
        finally:
            await trans.rollback()
    assert "topics" not in cols and {"ix_news_items_topics", "ix_news_items_cves"} <= idx
    assert default[0].startswith("'[]'::jsonb") and default[1] == "NO"
