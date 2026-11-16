# ruff: noqa: F811 - the fixtures of test_vendor_service are imported and used by name
"""Hersteller zählt (0.1.57): the rating of a CVE is its CNA's own – what cve.org and the vendor's page show. The NVD
keeps the CNA's metric beside its own analysis (type Secondary, source = the record's sourceIdentifier): Vendor News
used to take NVD's own first (GitLab CVE-2025-2938: NVD 8.8 HIGH, GitLab 3.1 LOW). A finding is rated by the vendor's
advisory and the CNAs; NVD's own value, a coordinator's document (the BSI's WID) and CISA's ADP only for a CVE none of
those rated – NVD's value is shown beside ("NVD 8.8"). Stored records get it with one full NVD fetch (migration 0048)
– quietly in both directions: no revision, no event, no message, a confirmation stays.

The samples are real: NVD API records (nvd_rating.json, references left out), cvelistV5 records (cve5_rating_*.json)
and the BSI's WID-SEC-W-2026-3556 "GitLab: Mehrere Schwachstellen" (csaf_wid_gitlab_3556.json), taken 16 Nov 2026."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text
from test_vendor_service import _dispatch, _follow, _webhook_rule, hooks, sites, vendor_reset  # noqa: F401 - fixtures

from app import advisory_changes as ch
from app import cvelist, db, story_details, vendor
from app import vendor_sources as src
from app.models import Counter, NewsItem, StoryDetail, VendorAdvisory, VendorAdvisoryChange, VendorAdvisoryProduct, VendorAdvisoryState, VendorConfirm, VendorEvent, VendorFetch

FIX = Path(__file__).parent / "fixtures" / "vendor"


def _page(recent: bool = False, only: tuple[str, ...] = ()) -> bytes:
    doc = json.loads((FIX / "nvd_rating.json").read_bytes())
    if only:
        doc["vulnerabilities"] = [v for v in doc["vulnerabilities"] if v["cve"]["id"] in only]
        doc["totalResults"] = doc["resultsPerPage"] = len(doc["vulnerabilities"])
    if recent:  # published two hours ago: fresh, its events are sent
        at = (datetime.now(UTC) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000")
        for v in doc["vulnerabilities"]:
            v["cve"]["published"] = v["cve"]["lastModified"] = at
    return json.dumps(doc).encode()


def _nvd(recent: bool = False) -> dict[str, dict]:
    return {a["ident"]: a for a in src.parse_nvd(_page(recent))[1]}


def _as_before(a: dict, cvss: float, severity: str, **kw) -> dict:
    """The record as the parser before 0.1.57 stored it: NVD's own analysis first, no rater beside it."""
    data = {k: v for k, v in a["data"].items() if k not in ("rating", "rated", "nvd_own")}
    return {**a, "cvss": cvss, "severity": severity, "data": data} | kw


# ---------------------------------------------------------------- the parsers


def test_the_nvd_record_is_rated_by_its_cna():
    a = _nvd()
    got = {k: (x["cvss"], x["severity"], x["data"]["rated"], (x["data"].get("nvd_own") or {}).get("cvss")) for k, x in a.items()}
    # GitLab's own rating counts, NVD's analysis beside it – higher …
    assert got["CVE-2025-2938"] == (3.1, "low", "cna", 8.8)
    assert got["CVE-2025-10871"] == (3.8, "low", "cna", 7.2)
    assert got["CVE-2020-13300"] == (8.0, "high", "cna", 10.0)
    # … and lower (NVD 4.3 MEDIUM, GitLab 7.4 HIGH)
    assert got["CVE-2020-13276"] == (7.4, "high", "cna", 4.3)
    assert got["CVE-2020-13283"] == (7.3, "high", "cna", 5.4)
    # the same: nothing beside it
    assert got["CVE-2026-10518"] == (4.3, "medium", "cna", None) and got["CVE-2026-4523"] == (3.7, "low", "cna", None)
    # Palo Alto rates CVSS 4.0 (9.3), NVD 3.1 (9.8): the CNA's newest version
    assert got["CVE-2024-0012"] == (9.3, "critical", "cna", 9.8)
    # MITRE gives no score: NVD's own analysis (CVSS 2) …
    assert got["CVE-2008-2717"] == (6.5, "medium", "nvd", None)
    # … none either: CISA's ADP (Secondary like a CNA – told apart by its source, not by "Secondary")
    assert got["CVE-2024-51092"] == (9.1, "critical", "adp", None)
    assert all(x["data"]["rating"] == src.RATING_V for x in a.values())


def test_several_metrics_of_the_cnas_version_the_highest():
    m = {
        "cvssMetricV40": [
            {"source": "psirt@paloaltonetworks.com", "type": "Secondary", "cvssData": {"baseScore": 1.2, "baseSeverity": "LOW"}},
            {"source": "psirt@paloaltonetworks.com", "type": "Secondary", "cvssData": {"baseScore": 2.7, "baseSeverity": "LOW"}},
        ],
        "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}],
    }
    assert src._nvd_metrics(m, "psirt@paloaltonetworks.com") == {"cvss": 2.7, "given": "LOW", "rated": "cna", "nvd": {"cvss": 5.3, "severity": "medium"}}
    # a record without its sourceIdentifier: NVD's own first, then the others
    assert src._nvd_metrics(m)["cvss"] == 5.3 and src._nvd_metrics(m)["rated"] == "nvd"
    assert src._nvd_metrics({}) == {"cvss": None, "given": "", "rated": "", "nvd": None}


def test_cvelist_takes_the_cnas_highest_scenario_and_adp_only_without_one():
    a = cvelist.parse_one((FIX / "cve5_rating_CVE-2025-0133.json").read_bytes())  # Palo Alto: 1.2 and 2.7 (CVSS 4.0)
    assert (a["cvss"], a["severity"], a["data"]["rated"]) == (2.7, "low", "cna")
    b = cvelist.parse_one((FIX / "cve5_rating_CVE-2024-51092.json").read_bytes())  # MITRE without, CISA 9.1
    assert (b["cvss"], b["data"]["rated"], b["data"]["cvss_from_adp"]) == (9.1, "adp", True)
    c = cvelist.parse_one((FIX / "cve5_rating_CVE-2025-2938.json").read_bytes())  # cve.org: GitLab's 3.1
    assert (c["cvss"], c["severity"], c["data"]["rated"], c["data"]["rating"]) == (3.1, "low", "cna", src.RATING_V)


def test_a_document_without_a_score_borrows_none_from_the_nvd():
    """WID-SEC-W-2026-3556 has no score of its own (the BSI's WID documents carry none): the story shows the highest NVD
    score of its first CVEs ("nvd") – the stored advisory is rated by its own word only ("hoch")."""
    d = story_details.parse_csaf((FIX / "csaf_wid_gitlab_3556.json").read_bytes(), "bsi", story_details.STORE_PRODUCTS)
    assert d["cvss"] == [] and d["scores"] == {} and d["severity_text"] == "hoch" and len(d["cves"]) == 11
    d["cvss"] = [{"score": 8.7, "temporal": None, "vector": "", "version": "", "cve": "CVE-2026-89078", "nvd": True}]  # as build() adds it
    adv = story_details.csaf_advisory(d, "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-W-2026-3556")
    assert (adv["cvss"], adv["severity"], adv["data"]["rating"]) == (None, "high", src.RATING_V) and "scores" not in adv["data"]


def test_a_document_with_scores_keeps_each_cves_own():
    doc = json.loads((FIX / "csaf_wid_gitlab_3556.json").read_bytes())
    for v, score in zip(doc["vulnerabilities"][:2], (4.3, 9.1), strict=True):
        v["scores"] = [{"products": [], "cvss_v3": {"version": "3.1", "baseScore": score, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]
    d = story_details.parse_csaf(json.dumps(doc).encode(), "bsi", story_details.STORE_PRODUCTS)
    assert d["scores"] == {"CVE-2026-10518": 4.3, "CVE-2026-4523": 9.1} and d["cvss"][0]["score"] == 9.1
    adv = story_details.csaf_advisory(d, "https://wid.cert-bund.de/x")
    assert adv["cvss"] == 9.1 and adv["data"]["scores"] == {"CVE-2026-10518": 4.3, "CVE-2026-4523": 9.1}


def test_story_details_show_nvds_own_beside_the_cnas():
    a = _nvd()["CVE-2025-2938"]
    rec = vendor.Adv(a["id"], "nvd", a["ident"], a["title"], "", a["url"], a["cves"], a["cvss"], a["severity"], False, None, None, a["data"])
    d = story_details.nvd_details([rec], ["CVE-2025-2938"])
    assert d["cvss"] == [{"score": 3.1, "temporal": None, "vector": "", "version": "", "cve": "CVE-2025-2938", "nvd_own": 8.8}]


def test_rerated_once_by_the_rating_rule():
    assert ch.rerated("nvd", {"configs": []}, {"configs": [], "rating": 2, "rated": "cna"})
    assert ch.rerated("cvelist", {"cvss_from_adp": False}, {"rating": 2})
    assert ch.rerated("csaf", {"products": []}, {"products": [], "rating": 2})
    assert not ch.rerated("nvd", {"rating": 2}, {"rating": 2})  # stored by this rule already
    assert not ch.rerated("osv", {}, {"rating": 2}) and not ch.rerated("fortinet", {}, {"rating": 2})


# ---------------------------------------------------------------- the rating of a finding


def _adv(aid: str, cvss: float | None, sev: str, cves: list[str], **data) -> vendor.Adv:
    source, _, ident = aid.partition(":")
    return vendor.Adv(aid, source, ident, "", "", "", cves, cvss, sev, False, None, None, data)


def test_the_cnas_rating_counts_nvds_own_beside_it():
    nvd = _adv("nvd:CVE-2025-2938", 3.1, "low", ["CVE-2025-2938"], rated="cna", nvd_own={"cvss": 8.8, "severity": "high"})
    assert vendor.rating([nvd], ["CVE-2025-2938"]) == (3.1, "low", 8.8)
    # a record of the parser before 0.1.57 (no rater): as it was stored, until its next fetch
    old = _adv("nvd:CVE-2025-2938", 8.8, "high", ["CVE-2025-2938"])
    assert vendor.rating([old], ["CVE-2025-2938"]) == (8.8, "high", None)


def test_the_bsis_one_score_is_only_a_fallback():
    """WID-SEC-W-2026-3556 groups 11 GitLab CVEs: each is rated by GitLab (CNA), the document only where none is."""
    wid = _adv("csaf:WID-SEC-W-2026-3556", None, "high", ["CVE-2026-10518", "CVE-2026-4523", "CVE-2026-84739"], publisher="BSI")
    a = _adv("nvd:CVE-2026-10518", 4.3, "medium", ["CVE-2026-10518"], rated="cna")
    b = _adv("nvd:CVE-2026-4523", 3.7, "low", ["CVE-2026-4523"], rated="cna")
    assert vendor.rating([wid, a, b], wid.cves) == (4.3, "high", None)  # CVE-2026-84739: no record – the document's word
    c = _adv("nvd:CVE-2026-84739", 5.0, "medium", ["CVE-2026-84739"], rated="nvd")
    assert vendor.rating([wid, a, b, c], wid.cves) == (5.0, "medium", None)  # NVD's own before the document
    # the document's score of that CVE before CISA's – the document's one word last
    scored = _adv("csaf:WID-SEC-W-2026-3556", 8.7, "high", wid.cves, publisher="BSI", scores={"CVE-2026-84739": 6.1})
    adp = _adv("cvelist:CVE-2026-84739", 9.8, "critical", ["CVE-2026-84739"], rated="adp", cvss_from_adp=True)
    assert vendor.rating([scored, a, b, adp], wid.cves) == (6.1, "medium", None)
    assert vendor.rating([wid, a, b, adp], wid.cves) == (9.8, "critical", None)


def test_the_vendors_advisory_counts_for_its_cves():
    pan = _adv("paloalto:CVE-2024-0012", 9.3, "critical", ["CVE-2024-0012", "CVE-2024-9474"])
    cna = _adv("nvd:CVE-2024-0012", 9.3, "critical", ["CVE-2024-0012"], rated="cna", nvd_own={"cvss": 9.8, "severity": "critical"})
    nvd = _adv("nvd:CVE-2024-9474", 6.9, "medium", ["CVE-2024-9474"], rated="nvd")
    # Palo Alto's 9.3 counts for both CVEs (NVD's 6.9 of CVE-2024-9474 is no fallback here); NVD's own of the finding: 9.8
    assert vendor.rating([pan, cna, nvd], pan.cves) == (9.3, "critical", 9.8)
    # a vendor's CSAF document (a CSAF provider) counts as well; another publisher's does not decide over the CNA
    cisco = _adv("csaf:cisco-sa-x", 5.3, "medium", ["CVE-2026-1"], provider="cisco")
    assert vendor.rating([cisco, _adv("nvd:CVE-2026-1", 9.8, "critical", ["CVE-2026-1"], rated="nvd")], ["CVE-2026-1"])[:2] == (5.3, "medium")
    # no CVE, no vendor: what the records say
    assert vendor.rating([_adv("csaf:WID-SEC-W-2026-1", 7.5, "high", [], publisher="BSI")], []) == (7.5, "high", None)


# ---------------------------------------------------------------- stored records re-rated quietly


async def _baseline(monkeypatch) -> None:  # noqa: ANN001
    """The follow's first evaluation – the baseline. (Not a whole round: the fake endoflife.date refreshes the
    catalogue to one without GitLab.)"""
    monkeypatch.setattr(vendor, "_ready", lambda p, answered: True)
    async with db.session() as s:
        await vendor.evaluate_events(s)


async def _events() -> list[tuple]:
    async with db.session() as s:
        return [(e.key, e.severity, e.baseline) for e in await s.scalars(select(VendorEvent).order_by(VendorEvent.n))]


async def _store(*advs: dict) -> int:
    async with db.session() as s:
        await vendor.store(s, list(advs), vendor.build_index())
        return await vendor.evaluate_events(s)


def _finding(page: dict, fid: str) -> dict:
    return next(x for x in page["findings"] if x["id"] == fid)


@pytest.mark.parametrize("state", [False, True], ids=["stored-once", "with-state"])
async def test_the_re_rating_is_quiet_both_ways_and_keeps_a_confirmation(admin_client, monkeypatch, sites, hooks, state):
    """GitLab 17.5.0 is affected by CVE-2025-2938 (NVD 8.8 HIGH → GitLab 3.1 LOW), 12.9.0 by CVE-2020-13276 (NVD 4.3
    MEDIUM → GitLab 7.4 HIGH, confirmed): neither a lowering nor a raising by the rule is news."""
    await _follow(admin_client, "gitlab", "17.5.0", "12.9.0")
    await _webhook_rule(admin_client, ["vendor_vuln", "vendor_change"])
    await _baseline(monkeypatch)
    new = _nvd(recent=True)
    low, high = new["CVE-2025-2938"], new["CVE-2020-13276"]
    olds = [_as_before(low, 8.8, "high"), _as_before(high, 4.3, "medium")]
    assert await _store(*olds) == 2  # as 0.1.56 rated them – both notified
    if state:  # stored twice: the records have their facts
        await _store(*[o | {"updated_at": o["updated_at"] + timedelta(minutes=1)} for o in olds])
    await _dispatch()
    sent = len(hooks)
    assert sent == 2  # one message per version
    r = await admin_client.post("/api/vendor/findings/confirm", json={"product": "gitlab", "finding": "nvd:CVE-2020-13276", "status": "mitigated", "note": "Nur intern erreichbar"})
    assert r.status_code == 200, r.text
    before = await _events()
    async with db.session() as s:
        await vendor.store(s, [low, high], vendor.build_index())
    # stored, not yet evaluated: the page shows the confirmation all the same (the evaluation takes the ratings anew)
    page = (await admin_client.get("/api/vendor/products/gitlab")).json()
    assert _finding(page, "nvd:CVE-2020-13276")["confirmed"] is not None
    async with db.session() as s:
        assert await vendor.evaluate_events(s) == 0
    after = await _events()
    assert [e for e in after if e not in before and not e[2]] == []  # nothing that is sent …
    assert [e[0].split(":")[0] for e in after if e not in before] == ["rated"]  # … the rise only noted
    await _dispatch()
    assert len(hooks) == sent
    async with db.session() as s:
        assert (await s.scalars(select(VendorAdvisoryChange))).all() == []  # no revision
        st = {x.advisory_id: (x.facts["sev"], x.facts["cvss"]) for x in await s.scalars(select(VendorAdvisoryState))}
        conf = await s.scalar(select(VendorConfirm).where(VendorConfirm.finding == "nvd:CVE-2020-13276"))
    assert st["nvd:CVE-2025-2938"] == ("low", 3.1) and st["nvd:CVE-2020-13276"] == ("high", 7.4)
    assert conf.ended_at is None and conf.facts["severity"] == "high"  # stands – on the new rating from now on
    page = (await admin_client.get("/api/vendor/products/gitlab")).json()
    f1, f2 = _finding(page, "nvd:CVE-2025-2938"), _finding(page, "nvd:CVE-2020-13276")
    assert (f1["severity"], f1["cvss"], f1["cvss_nvd"]) == ("low", 3.1, 8.8)
    assert (f2["severity"], f2["cvss"], f2["cvss_nvd"], f2["confirmed"] is not None) == ("high", 7.4, 4.3, True)
    # from then on GitLab's own re-rating is a change as always: critical now – a revision, "jetzt höher eingestuft"
    # and the confirmation lapses
    later = high | {"cvss": 9.1, "severity": "critical", "updated_at": high["updated_at"] + timedelta(hours=1)}
    assert await _store(later) == 1
    async with db.session() as s:
        [rev] = (await s.scalars(select(VendorAdvisoryChange))).all()
        conf = await s.scalar(select(VendorConfirm).where(VendorConfirm.finding == "nvd:CVE-2020-13276"))
    assert [x["f"] for x in rev.diff] == ["severity"] and conf.ended_at is not None and conf.ended_reason == "severity"
    await _dispatch()
    assert len(hooks) == sent + 2  # the revision (vendor_change) and "jetzt höher eingestuft" (vendor_vuln)


async def test_a_later_raise_of_the_same_product_is_still_news(admin_client, monkeypatch, sites, hooks):
    """The quiet evaluation is per product and once: the next rise of the same product is sent."""
    await _follow(admin_client, "gitlab", "12.9.0")
    await _webhook_rule(admin_client, ["vendor_vuln"])
    await _baseline(monkeypatch)
    high = _nvd(recent=True)["CVE-2020-13276"]
    await _store(_as_before(high, 4.3, "medium"))
    await _store(high)  # re-rated quietly
    async with db.session() as s:
        assert await s.scalar(select(Counter.value).where(Counter.name == f"{vendor.RATED_PRIMED}:gitlab")) == 1  # primed again
    await _dispatch()
    sent = len(hooks)
    assert await _store(high | {"cvss": 9.6, "severity": "critical", "updated_at": high["updated_at"] + timedelta(hours=1)}) == 1
    await _dispatch()
    assert len(hooks) == sent + 1


async def test_a_coordinators_document_is_rated_by_the_cnas_of_its_cves(admin_client, monkeypatch, sites):
    """The BSI's WID lists Node.js CVEs with a product whose NVD records are not linked to it: the CNA's ratings of
    those CVEs count (read for the rating only), not the document's word ("kritisch") for all."""
    await _follow(admin_client, "gitlab", "19.2.0")
    await _baseline(monkeypatch)
    d = story_details.parse_csaf((FIX / "csaf_wid_gitlab_3556.json").read_bytes(), "bsi", story_details.STORE_PRODUCTS)
    wid = story_details.csaf_advisory(d, "https://wid.cert-bund.de/x")
    wid["severity"] = "critical"  # as if the document said "kritisch"
    nvd = _nvd()
    other = {**nvd["CVE-2026-4523"], "data": {**nvd["CVE-2026-4523"]["data"], "configs": []}, "names": []}  # not linked to GitLab
    await _store(wid, nvd["CVE-2026-10518"], other)
    async with db.session() as s:
        linked = set(await s.scalars(text("SELECT advisory_id FROM vendor_advisory_products WHERE product = 'gitlab'")))
    assert "nvd:CVE-2026-4523" not in linked and {wid["id"], "nvd:CVE-2026-10518"} <= linked
    page = (await admin_client.get("/api/vendor/products/gitlab")).json()
    f = next(x for x in page["findings"] if "CVE-2026-10518" in x["cves"])
    # CVE-2026-10518 4.3 and CVE-2026-4523 3.7 (GitLab); nine CVEs without any record: the document's word, critical
    assert (f["cvss"], f["severity"]) == (4.3, "critical")
    rest = d["cves"][2:]
    async with db.session() as s:
        await s.execute(text("UPDATE vendor_advisories SET cves = CAST(:c AS jsonb) WHERE id = :i"), {"c": json.dumps(d["cves"][:2]), "i": wid["id"]})
        await s.commit()
    vendor.bump()
    page = (await admin_client.get("/api/vendor/products/gitlab")).json()
    f = next(x for x in page["findings"] if "CVE-2026-10518" in x["cves"])
    assert (f["cvss"], f["severity"]) == (4.3, "medium") and rest  # every CVE rated by GitLab: the document is not needed


# ---------------------------------------------------------------- migration 0048


async def test_migration_refetches_the_nvd_and_takes_back_the_borrowed_score(admin_client, monkeypatch, sites, hooks):
    from alembic import command

    from app import news

    await _follow(admin_client, "gitlab", "17.5.0", "12.9.0")
    await _webhook_rule(admin_client, ["vendor_vuln", "vendor_change"])
    await _baseline(monkeypatch)
    new = _nvd(recent=True)
    gitlab = [a for a in new.values() if a["ident"] in ("CVE-2025-2938", "CVE-2020-13276", "CVE-2025-10871", "CVE-2020-13300", "CVE-2020-13283")]
    was = {"CVE-2025-2938": (8.8, "high"), "CVE-2020-13276": (4.3, "medium"), "CVE-2025-10871": (7.2, "high"), "CVE-2020-13300": (10.0, "critical"), "CVE-2020-13283": (5.4, "medium")}
    await _store(*[_as_before(a, *was[a["ident"]]) for a in gitlab])
    await _dispatch()
    sent = len(hooks)
    now = datetime.now(UTC)
    wid = "csaf:WID-SEC-W-2026-3556"
    async with db.session() as s:  # as after 0.1.56: the NVD queries ran an hour ago, the WID borrowed NVD's 8.7
        for row in (
            VendorFetch(key="nvd:a:gitlab:gitlab", cursor=(now - timedelta(hours=1)).isoformat(), full_at=now - timedelta(days=1), next_fetch_at=now + timedelta(hours=5), last_ok_at=now, failures=0, items=5),
            VendorFetch(key="nvd:a:example:paused", cursor=(now - timedelta(hours=1)).isoformat(), full_at=now - timedelta(days=1), next_fetch_at=now + timedelta(hours=2), failures=3, items=0),
        ):
            await s.merge(row)
        srcrow = await s.scalar(text("SELECT id FROM news_sources LIMIT 1"))
        i = NewsItem(source_id=srcrow, url="https://wid.cert-bund.de/x", url_key="m48", title="GitLab: Mehrere Schwachstellen", title_key="m48", summary="", published_at=now - timedelta(days=60), cves=[], seq=await news.next_seq(s))
        s.add(i)
        await s.flush()
        s.add(StoryDetail(item_id=i.id, kind="bsi", ident="WID-SEC-W-2026-3556", status="ok", data={"id": "WID-SEC-W-2026-3556", "severity_text": "hoch", "cvss": [{"score": 8.7, "cve": "CVE-2026-89078", "nvd": True}]}))
        s.add(VendorAdvisory(id=wid, source="csaf", ident="WID-SEC-W-2026-3556", title="GitLab: Mehrere Schwachstellen", summary="", url="https://wid.cert-bund.de/x", cves=["CVE-2026-10518"], cvss=8.7, severity="high", exploited=False, data={"products": [], "publisher": "BSI"}))
        s.add(VendorAdvisory(id="csaf:WID-SEC-W-2026-0001", source="csaf", ident="WID-SEC-W-2026-0001", title="Own score", summary="", url="https://wid.cert-bund.de/y", cves=[], cvss=9.1, severity="critical", exploited=False, data={"products": [], "publisher": "BSI"}))
        await s.flush()
        s.add(VendorAdvisoryProduct(product="panos", advisory_id=wid))  # the WID's product: its ratings taken anew
        s.add(Counter(name=f"{vendor.RATED_PRIMED}:panos", value=1))
        await s.commit()

    def down(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "0047")

    async with db.engine().begin() as conn:
        await conn.run_sync(down)
    await db.migrate()
    assert await db.revision() == db.head()
    async with db.session() as s:
        gl, paused = [await s.get(VendorFetch, k) for k in ("nvd:a:gitlab:gitlab", "nvd:a:example:paused")]
        assert (gl.full_at, gl.next_fetch_at) == (None, None)
        assert paused.full_at is None and paused.next_fetch_at is not None  # pausing after errors: it waits
        a, own = await s.get(VendorAdvisory, wid), await s.get(VendorAdvisory, "csaf:WID-SEC-W-2026-0001")
        assert (a.cvss, a.severity) == (None, "high") and (own.cvss, own.severity) == (9.1, "critical")
        primed = set(await s.scalars(select(Counter.name).where(Counter.name.like(f"{vendor.RATED_PRIMED}:%"))))
    assert primed == {f"{vendor.RATED_PRIMED}:gitlab"}  # panos (the WID's product) is evaluated anew, quietly
    vendor.reset()  # a new process after the upgrade
    monkeypatch.setattr(vendor, "_ready", lambda p, answered: True)

    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        assert req.url.host == "services.nvd.nist.gov" and "lastModStartDate" not in req.url.params  # a full fetch
        return httpx.Response(200, content=_page(recent=True, only=tuple(was)))

    monkeypatch.setattr(vendor, "transport", httpx.MockTransport(handler))
    before = await _events()
    async with db.session() as s:
        await vendor.sync_nvd_cpe(s, "a:gitlab:gitlab", timedelta(hours=6), vendor.build_index(), "", False)
        assert await vendor.evaluate_events(s) == 0
    assert len(calls) == 1
    assert [e for e in await _events() if e not in before and not e[2]] == []
    async with db.session() as s:
        assert (await s.scalars(select(VendorAdvisoryChange))).all() == []
        got = {a.ident: (a.cvss, a.severity) for a in await s.scalars(select(VendorAdvisory).where(VendorAdvisory.source == "nvd"))}
    assert got["CVE-2025-2938"] == (3.1, "low") and got["CVE-2020-13276"] == (7.4, "high") and got["CVE-2020-13300"] == (8.0, "high")
    await _dispatch()
    assert len(hooks) == sent
    # the WID's next write by the new parser: quiet as well (its severity and CVSS are what migration 0048 set)
    d = story_details.parse_csaf((FIX / "csaf_wid_gitlab_3556.json").read_bytes(), "bsi", story_details.STORE_PRODUCTS)
    async with db.session() as s:
        await vendor.store(s, [story_details.csaf_advisory(d, "https://wid.cert-bund.de/x")], vendor.build_index())
        assert (await s.scalars(select(VendorAdvisoryChange).where(VendorAdvisoryChange.advisory_id == wid))).all() == []


async def test_a_watched_cve_has_the_severity_that_counts():
    """CVE beobachten names the same severity as the finding: GitLab's LOW for CVE-2025-2938, not the NVD's HIGH."""
    from app import cve_watch

    nvd = _nvd()
    wid = {"id": "csaf:WID-SEC-W-2026-3556", "source": "csaf", "ident": "WID-SEC-W-2026-3556", "title": "GitLab: Mehrere Schwachstellen", "summary": "", "url": "https://wid.cert-bund.de/x", "cves": ["CVE-2025-2938", "CVE-2026-84739"], "cvss": None, "severity": "critical", "published_at": None, "updated_at": None, "data": {"products": [], "publisher": "BSI"}}
    async with db.session() as s:
        await vendor.store(s, [nvd["CVE-2025-2938"], wid], vendor.build_index())
        got = await cve_watch.facts(s, ["CVE-2025-2938", "CVE-2026-84739"])
    assert got["CVE-2025-2938"]["severity"] == "low"  # the BSI's word does not count where GitLab rated it
    assert got["CVE-2026-84739"]["severity"] == "critical"  # nothing else rates it: the document's word
