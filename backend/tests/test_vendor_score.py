"""Dringlichkeit (app/vendor_score.py): one number 0–100 per finding from fixed points – severity, EPSS percentile, KEV /
exploited, the own version's verdict, no fix, age; the slot for "öffentlicher Exploit" stays unused. The weights are
pinned here (the handbook explains the same numbers), the breakdown says each factor, the value is kept between 0 and
100; computed once per cached view and day; the overview and the drawer carry it."""

from datetime import UTC, date, datetime, timedelta

from app import db, vendor
from app import vendor_score as vs
from app import vendor_sources as src
from app.models import VendorAdvisory, VendorAdvisoryProduct, VendorFetch, VendorFollow, VendorKev, VendorVersion

TODAY = date(2026, 10, 30)


def _s(**kw) -> dict:
    base = {"cvss": None, "severity": "info", "epss_percentile": None, "kev": False, "exploited": False, "status": "affected", "fixed": True, "published": "2026-01-01T00:00:00+00:00", "today": TODAY}
    return vs.score(**(base | kw))


def _parts(s: dict) -> dict[str, int]:
    return {p["factor"]: p["points"] for p in s["parts"]}


def test_weights_are_pinned():
    # the handbook (03-vendor-news.md#dringlichkeit) explains exactly these numbers – a change here changes it there
    assert vs.SEVERITY == {"critical": 35, "high": 25, "medium": 12, "low": 4, "info": 0}
    assert vs.EPSS == ((0.95, 20), (0.80, 10), (0.50, 5))
    assert (vs.KEV, vs.EXPLOITED, vs.NO_FIX) == (30, 25, 5)
    assert vs.VERSION == {"affected": 25, "possible": 5, "unversioned": 5, "service": 0, "stale": -50, "not_affected": -70}
    assert vs.AGE == ((7, 10), (30, 5))
    assert vs.LEVELS == ((60, "now"), (35, "soon"))
    # reserved for "öffentlicher Exploit bekannt" – the source is not approved: never counted
    assert vs.PUBLIC_EXPLOIT == 15 and vs.USE_PUBLIC_EXPLOIT is False
    s = _s(cvss=9.8, public_exploit=True)
    assert "public_exploit" not in _parts(s) and s["value"] == 60


def test_formula_and_breakdown():
    # critical, KEV, EPSS 97th percentile, affected, a fix exists, published three days ago: 35+20+30+25+10 = 120 → 100
    s = _s(cvss=9.8, severity="critical", epss_percentile=0.97, kev=True, published="2026-10-27T08:00:00+00:00")
    assert _parts(s) == {"severity": 35, "epss": 20, "kev": 30, "version": 25, "age": 10}
    assert s["raw"] == 120 and s["value"] == 100 and s["level"] == "now"
    sev = next(p for p in s["parts"] if p["factor"] == "severity")
    assert sev["band"] == "critical" and sev["cvss"] == 9.8
    assert next(p for p in s["parts"] if p["factor"] == "epss")["percentile"] == 0.97
    assert next(p for p in s["parts"] if p["factor"] == "age")["days"] == 3
    # high, affected, nothing else: 25+25 = 50 – "Bald"
    s = _s(cvss=7.5)
    assert _parts(s) == {"severity": 25, "version": 25} and (s["value"], s["level"]) == (50, "soon")
    # exploited (vendor / EUVD) but not in KEV: +25, never both
    s = _s(cvss=7.5, exploited=True)
    assert _parts(s)["exploited"] == 25 and "kev" not in _parts(s) and s["level"] == "now"
    assert "exploited" not in _parts(_s(cvss=7.5, exploited=True, kev=True))
    # no fixed version known: +5 (only where the version is or may be affected)
    assert _parts(_s(cvss=5.0, fixed=False))["no_fix"] == 5
    assert "no_fix" not in _parts(_s(cvss=5.0, fixed=False, status="not_affected"))


def test_severity_band_from_cvss_else_the_given_severity():
    assert vs.band(9.0, "low") == "critical" and vs.band(8.9, "critical") == "high" and vs.band(4.0, None) == "medium" and vs.band(0.1, None) == "low"
    assert vs.band(None, "high") == "high" and vs.band(0, "medium") == "medium" and vs.band(None, "nonsense") == "info"


def test_epss_and_age_bands():
    pts = lambda p: _parts(_s(epss_percentile=p)).get("epss", 0)  # noqa: E731
    assert [pts(x) for x in (None, 0.0, 0.4999, 0.5, 0.7999, 0.8, 0.9499, 0.95, 1.0)] == [0, 0, 0, 5, 5, 10, 10, 20, 20]
    age = lambda d: _parts(_s(published=(datetime(2026, 10, 30, 12, tzinfo=UTC) - timedelta(days=d)).isoformat())).get("age", 0)  # noqa: E731
    assert [age(d) for d in (0, 7, 8, 30, 31, 900)] == [10, 10, 5, 5, 0, 0]
    # no or a broken date: no points (never an error); a date in the future counts as today
    assert "age" not in _parts(_s(published=None)) and "age" not in _parts(_s(published="kaputt"))
    assert _parts(_s(published="2027-01-01T00:00:00Z"))["age"] == 10
    assert _parts(_s(published="2026-10-29"))["age"] == 10  # a day without time (naive): read as UTC


def test_clamped_and_levels_at_the_edges():
    # not affected pushes down hard: everything else at its maximum stays below "Bald"
    s = _s(cvss=10.0, epss_percentile=0.99, kev=True, status="not_affected", published="2026-10-30T00:00:00Z")
    assert s["raw"] == 35 + 20 + 30 - 70 + 10 and s["value"] == 25 and s["level"] == "watch"
    # below zero: 0, the raw sum kept for the explanation
    s = _s(cvss=None, severity="low", status="not_affected")
    assert s["raw"] == 4 - 70 and s["value"] == 0 and s["level"] == "watch"
    assert _s(status="stale", cvss=9.8)["value"] == 0  # "unklare Altdaten": 35 − 50
    assert [vs.level(x) for x in (0, 34, 35, 59, 60, 100)] == ["watch", "watch", "soon", "soon", "now", "now"]
    # the colour rule of the overview: critical and affected is red ("Sofort"), high and affected amber ("Bald")
    assert _s(cvss=9.0)["level"] == "now" and _s(cvss=8.9)["level"] == "soon" and _s(cvss=4.0)["level"] == "soon"
    # the version part is always in the breakdown (also with 0 points), parts without points are not
    s = _s(status="service", severity="info")
    assert [p["factor"] for p in s["parts"]] == ["version"] and s["value"] == 0


def _finding(**kw) -> dict:
    f = {
        "id": "nvd:CVE-2026-1",
        "ident": "CVE-2026-1",
        "cvss": 9.8,
        "severity": "critical",
        "epss": {"cve": "CVE-2026-1", "score": 0.4, "percentile": 0.96, "date": "2026-10-29"},
        "kev": None,
        "exploited": False,
        "published_at": "2026-09-01T00:00:00+00:00",
        "status": "affected",
        "versions": [
            {"id": "a", "version": "4.14.4", "status": "affected", "fixed": None},
            {"id": "b", "version": "4.15.0", "status": "not_affected", "fixed": None},
            {"id": "c", "version": "4.13.1", "status": "affected", "fixed": "4.13.9"},
        ],
    }
    return f | kw


def test_a_finding_takes_its_most_urgent_version():
    f = _finding()
    s = vs.of_finding(f, TODAY)
    # 4.14.4: affected without a fix (35+20+25+5 = 85), 4.13.1 with one (80), 4.15.0 not affected (0) – the highest wins
    assert [r["score"] for r in f["versions"]] == [85, 0, 80]
    assert s["value"] == 85 and s["version"] == "4.14.4" and _parts(s)["no_fix"] == 5
    # a finding without version rows (none stored like that) still has a number
    assert vs.of_finding(_finding(versions=[], status="possible"), TODAY)["value"] == 35 + 20 + 5 + 5


def test_apply_once_per_view_and_day():
    view = {"findings": [_finding(), _finding(id="x", ident="CVE-2026-2", cvss=5.0, severity="medium", epss=None, versions=[{"id": "a", "version": "1", "status": "possible", "fixed": "2"}])]}
    vs.apply(view, TODAY)
    first = view["findings"][0]["score"]
    assert view["_score_day"] == TODAY and first["value"] == 85
    top = vs.top(view)
    assert top["finding"] == "nvd:CVE-2026-1" and top["ident"] == "CVE-2026-1" and top["value"] == 85
    assert vs.top(view) is top  # kept on the view
    vs.apply(view, TODAY)
    assert view["findings"][0]["score"] is first  # the same day: not computed again
    # the next day the age may move on: computed again (and the card's number with it)
    view["findings"][0]["published_at"] = "2026-10-30T00:00:00+00:00"
    vs.apply(view, TODAY + timedelta(days=1))
    assert view["findings"][0]["score"]["value"] == 95 and vs.top(view)["value"] == 95
    assert vs.top({"findings": []}) is None


# ---------------------------------------------------------------- through the API


def _nvd(cve: str, *, cvss: float, end_excl: str, published: datetime) -> VendorAdvisory:
    m = {"vulnerable": True, "criteria": "cpe:2.3:a:typo3:typo3:*:*:*:*:*:*:*:*", "versionStartIncluding": "13.0.0", "versionEndExcluding": end_excl}
    return VendorAdvisory(
        id=f"nvd:{cve}", source="nvd", ident=cve, title=f"TYPO3 issue {cve}", summary="An issue.", url=f"https://nvd.nist.gov/vuln/detail/{cve}", cves=[cve], cvss=cvss,
        severity=src.severity_of(cvss), exploited=False, published_at=published, updated_at=None, data={"configs": [{"nodes": [{"cpeMatch": [m]}]}], "cna": [], "desc": "An issue.", "cwe": []},
    )


async def test_overview_and_drawer_carry_the_number(reader_client):
    now = datetime.now(UTC)
    async with db.session() as s:
        f = VendorFollow(product="typo3", enabled=True, created_at=now, updated_at=now)
        s.add(f)
        await s.flush()
        s.add(VendorVersion(follow_id=f.id, version="13.4.37", label="Website", count=None))
        for a in (
            _nvd("CVE-2026-50010", cvss=7.5, end_excl="13.4.38", published=now - timedelta(days=60)),  # high, affected, fix: 50
            _nvd("CVE-2026-50011", cvss=5.3, end_excl="13.4.38", published=now - timedelta(days=60)),  # medium: 37
            _nvd("CVE-2026-50012", cvss=9.8, end_excl="13.4.30", published=now - timedelta(days=60)),  # critical, not affected: 0
        ):
            a.fetched_at = now
            s.add(a)
            s.add(VendorAdvisoryProduct(product="typo3", advisory_id=a.id))
        s.add(VendorKev(cve="CVE-2026-50011", vendor="TYPO3", product="TYPO3", name="x", date_added="2026-10-01", due="2026-10-22", ransomware=False))
        s.add(VendorFetch(key="nvd:a:typo3:typo3", failures=0, items=3, last_ok_at=now))
        await s.commit()
    vendor.bump()
    card = (await reader_client.get("/api/vendor/overview")).json()["items"][0]
    # the card: its most urgent finding – the KEV one (12+30+25 = 67, "Sofort"), with the breakdown
    assert card["score"]["value"] == 67 and card["score"]["level"] == "now" and card["score"]["ident"] == "CVE-2026-50011"
    assert {p["factor"]: p["points"] for p in card["score"]["parts"]} == {"severity": 12, "kev": 30, "version": 25}
    assert card["urgency"] == "exploited"  # the existing tier stays (colour, order) – the number refines it
    assert card["latest"][0]["score"] == {"value": 67, "level": "now"}
    d = (await reader_client.get("/api/vendor/products/typo3?all=true")).json()
    got = {x["ident"]: x["score"]["value"] for x in d["findings"]}
    assert got == {"CVE-2026-50010": 50, "CVE-2026-50011": 67, "CVE-2026-50012": 0}
    assert d["findings"][0]["versions"][0]["score"] == d["findings"][0]["score"]["value"]
    # sort by Dringlichkeit: within each kind the most urgent first
    d = (await reader_client.get("/api/vendor/products/typo3?sort=score")).json()
    assert [x["ident"] for x in d["findings"]] == ["CVE-2026-50011", "CVE-2026-50010"]
    assert (await reader_client.get("/api/vendor/products/typo3?sort=nonsense")).status_code == 422


async def test_the_number_is_computed_once_per_cached_view(reader_client, monkeypatch):
    now = datetime.now(UTC)
    async with db.session() as s:
        f = VendorFollow(product="typo3", enabled=True, created_at=now, updated_at=now)
        s.add(f)
        await s.flush()
        s.add(VendorVersion(follow_id=f.id, version="13.4.37", label="", count=None))
        a = _nvd("CVE-2026-50020", cvss=7.5, end_excl="13.4.38", published=now - timedelta(days=60))
        a.fetched_at = now
        s.add(a)
        s.add(VendorAdvisoryProduct(product="typo3", advisory_id=a.id))
        await s.commit()
    vendor.bump()
    calls = []
    real = vs.of_finding
    monkeypatch.setattr(vs, "of_finding", lambda f, today: calls.append(f["id"]) or real(f, today))
    for _ in range(3):
        assert (await reader_client.get("/api/vendor/overview")).json()["items"][0]["score"]["value"] == 50
        assert (await reader_client.get("/api/vendor/products/typo3")).status_code == 200
    assert calls == ["nvd:CVE-2026-50020"]  # once – the view and its numbers are cached together
    vendor.bump(["typo3"])  # the product's data changed: a new view, a new number
    await reader_client.get("/api/vendor/overview")
    assert calls == ["nvd:CVE-2026-50020"] * 2
