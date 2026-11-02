"""News parsing and rating: denied exploitation, CVSS forms, CVEs
with other hyphens, German dates and zone names, Retry-After in the past, read timeouts, 403 as its own error – and
that hostile text from a feed or advisory cannot stall the app (no quadratic regex on unbounded input)."""

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import update

from app import db, news, story_details, vendor_match
from app.models import NewsSource
from conftest import set_news

FIX = Path(__file__).parent / "fixtures" / "news"
NOW = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)


# ---------------------------------------------------------------- rating


@pytest.mark.parametrize(
    ("text", "exploited"),
    [
        # denied – none of these is an exploitation
        ("Die Lücke wird bislang nicht aktiv ausgenutzt.", False),
        ("The vulnerability is not actively exploited.", False),
        ("The bug has not been exploited in the wild.", False),
        ("The flaw wasn't exploited in the wild.", False),
        ("There is no known exploit in the wild.", False),
        ("Es gibt keine aktive Ausnutzung.", False),
        ("Kein Zero-Day: Lücke in Beispiel-Router", False),
        ("Gemeldet über Trend Micros Zero-Day-Initiative.", False),
        ("Reported through the Zero Day Initiative.", False),
        ("Firmware fix for the out-of-band management interface", False),
        ("New infostealer spotted in the wild", False),
        ("Neue Malware in freier Wildbahn gesichtet", False),
        ("Ivanti is not aware of exploitation in the wild.", False),
        ("Es gibt keine Hinweise auf eine aktive Ausnutzung.", False),
        # exploited
        ("Fortinet flaw actively exploited", True),
        ("Die Lücke wird aktiv ausgenutzt.", True),
        ("Die Lücke wird bereits ausgenutzt.", True),
        ("Chrome zero-day fixed", True),
        ("Microsoft releases out-of-band update for Windows Server", True),
        ("The bug was exploited in the wild.", True),
        ("Attackers exploit the flaw in the wild", True),
        ("Ivanti is aware of limited exploitation in the wild.", True),
        ("Es gibt Hinweise auf aktive Ausnutzung.", True),
        ("In freier Wildbahn wurden Angriffe beobachtet.", True),
        ("Notfall-Patch für Exchange", True),
        ("No patch yet: Ivanti zero-day", True),
        ("There is no fix for the zero-day.", True),  # "no" alone, far from the match, denies nothing
        ("Kein Patch: Zero-Day in Chrome", True),
        ("CISA adds known exploited vulnerability to catalog", True),
    ],
)
def test_exploited_and_its_denials(text: str, exploited: bool):
    level, reasons = news.rate("Meldung", text)
    assert any(r["kind"] == "exploited" for r in reasons) is exploited, (text, reasons)
    assert (level == "critical") is exploited


@pytest.mark.parametrize(
    ("text", "score"),
    [
        ("Die Lücke hat einen CVSS-Score von 9.8.", "9.8"),
        ("CVSS-Basiswert 9,8", "9.8"),
        ("CVSS 3.1 Basisscore 9,8", "9.8"),
        ("CVSSv3.1 Base Score: 9.8", "9.8"),
        ("CVSS v3.1: 7.5", "7.5"),
        ("CVSS 4.0 score 9.3", "9.3"),
        ("CVSS-Score: 8,1", "8.1"),
        ("Patch for CVE-2026-9999 (CVSS 9.8)", "9.8"),
        ("CVSS 10.0", "10.0"),
        ("CVSS score of 3.1", "3.1"),  # after "score" a 3.1 is the score
        # the version is no score
        ("Vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None),
        ("Rated by CVSS 3.1 as medium", None),
    ],
)
def test_cvss_forms(text: str, score: str | None):
    got = [r["value"] for r in news.rate("Meldung", text)[1] if r["kind"] == "cvss"]
    assert got == ([score] if score else []), text


def test_cves_with_other_hyphens():
    # non-breaking hyphen (U+2011), hyphen (U+2010), figure dash (U+2012), en dash (U+2013)
    got = news.cves("CVE‑2026‑1234, CVE‐2026‐5678, CVE‒2026‒1111, CVE–2026–2222 und CVE-2026-9999")
    assert got == ["CVE-2026-1111", "CVE-2026-1234", "CVE-2026-2222", "CVE-2026-5678", "CVE-2026-9999"]


def test_csaf_exploit_status_denied_in_german():
    """The exploit status of a CSAF advisory: "nicht ausgenutzt" / "kein Exploit bekannt" is no exploitation."""
    doc = json.loads((Path(__file__).parent / "fixtures" / "vendor" / "csaf_wid.json").read_text())
    vuln = doc["vulnerabilities"][0]
    for details, exploited in (
        ("Die Schwachstelle wird bislang nicht ausgenutzt.", False),
        ("Kein Exploit bekannt.", False),
        ("Exploitation hasn't been observed.", False),
        ("Die Schwachstelle wird aktiv ausgenutzt.", True),
        ("Exploited in the wild.", True),
    ):
        doc["vulnerabilities"] = [{**vuln, "threats": [{"category": "exploit_status", "details": details}]}]
        assert story_details.parse_csaf(json.dumps(doc).encode(), "bsi")["exploited"] is exploited, details


# ---------------------------------------------------------------- dates, Retry-After, errors


def test_german_dates_and_zone_names():
    entries, _ = news.parse_feed((FIX / "german_dates.rss").read_bytes())
    by = {e["link"].rsplit("/", 1)[-1]: e for e in entries}
    assert by["1"]["date"] == datetime(2026, 10, 27, 9, tzinfo=UTC)  # "Di, 27 Okt 2026 10:00:00 MEZ"
    assert by["2"]["date"] == datetime(2026, 5, 27, 8, tzinfo=UTC)  # MESZ
    assert by["3"]["date"] == datetime(2026, 5, 27, 8, tzinfo=UTC)  # CEST – not taken as UTC any more
    assert by["4"]["date"] is None
    assert news.story(by["1"], NOW)["cves"] == ["CVE-2026-41234"]  # written with non-breaking hyphens
    assert news._date("2026-10-27") == datetime(2026, 10, 27, tzinfo=UTC)
    assert news._date("Dienstag, 27 Oktober 2026 10:00:00 +0100") == datetime(2026, 10, 27, 9, tzinfo=UTC)
    assert news._date("Tue, 27 Oct 2026 10:00:00 GMT") == datetime(2026, 10, 27, 10, tzinfo=UTC)  # English unchanged
    # CST stays RFC 822's US Central (-0600)
    assert news._date("Tue, 27 Oct 2026 10:00:00 CST") == datetime(2026, 10, 27, 16, tzinfo=UTC)


def test_retry_after_in_the_past_asks_for_no_pause():
    assert news._retry_after(httpx.Headers({"retry-after": "Tue, 01 Jan 2019 00:00:00 GMT"})) is None
    future = (datetime.now(UTC) + timedelta(hours=2)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert timedelta(hours=1, minutes=58) < news._retry_after(httpx.Headers({"retry-after": future})) <= timedelta(hours=2)
    far = (datetime.now(UTC) + timedelta(days=30)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert news._retry_after(httpx.Headers({"retry-after": far})) == news.MAX_BACKOFF


async def test_read_timeout_is_a_timeout():
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=req)

    with pytest.raises(news.NewsError) as e:
        await news.download("https://news.example.org/a.xml", proxy=None, transport=httpx.MockTransport(handler))
    assert e.value.category == "timeout" and e.value.detail == "ReadTimeout"

    def refused(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    with pytest.raises(news.NewsError) as e:
        await news.download("https://news.example.org/a.xml", proxy=None, transport=httpx.MockTransport(refused))
    assert e.value.category == "connection"


async def test_403_is_blocked_not_worked_around(admin_client, monkeypatch):
    """A site refusing automatic fetches (CISA from many networks): category "blocked", same request as always."""
    await set_news(enabled=True)
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(403, text="Access Denied")

    async with db.session() as s:
        await s.execute(update(NewsSource).values(enabled=False))
        src = NewsSource(key="blocked-feed", name="Blocked", url="https://news.example.org/a.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.commit()
        sid = src.id
    news._host_last.clear()
    assert await news.refresh_due(transport=httpx.MockTransport(handler)) == {"blocked-feed": -1}
    async with db.session() as s:
        assert (await s.get(NewsSource, sid)).error == "blocked: HTTP 403"
    assert len(calls) == 1 and calls[0].headers["user-agent"] == news.USER_AGENT  # once, as ourselves – no retry in disguise
    assert news.http_error(404).category == "http" and news.http_error(500).category == "http"

    async def fake_download(url, **kw):
        return news.Fetched(403, httpx.Headers(), b"")

    monkeypatch.setattr(news, "download", fake_download)
    t = (await admin_client.post("/api/admin/news/test", json={"url": "https://news.example.org/feed"})).json()
    assert t == {"ok": False, "error": "blocked", "detail": "HTTP 403"}


# ---------------------------------------------------------------- hostile input


def test_hostile_title_is_cut_before_the_regex():
    t = time.monotonic()
    s = news.story({"link": "https://a.example/x", "title": "<" * 400_000 + "Titel", "summary": "", "content": "", "date": None}, datetime.now(UTC))
    assert time.monotonic() - t < 1.0  # was over a minute for 400 KB
    assert s is None or len(s["title"]) <= 500


def test_hostile_text_stays_linear():
    """Every regex over feed or advisory text: 400 KB of the worst case each, well under a second."""
    n = 400_000
    cases = [
        lambda: news.rate("t", "CVSS" + " " * n),
        lambda: news.rate("t", "CVSS" + ":" * n),
        lambda: news.rate("t", "CVSS base" + "-" * n),
        lambda: news.rate("t", "not " * (n // 4) + "zero-day"),
        lambda: news.rate("t", "in freier wildbahn " * (n // 19)),
        lambda: news.rate("t", "exploited x x x " * (n // 16)),
        lambda: news.html_to_text("<br" + " " * n),
        lambda: news.clean_html("<p>" + " " * n),
        lambda: news._date("Di, " + "a." * n),
        lambda: news.cves("CVE-" * (n // 4)),
        lambda: vendor_match._vkey_text("(" * n),
        lambda: vendor_match.range_of("1" + " " * n + "x"),
        lambda: vendor_match._pan_bounds("(" * n),
    ]
    for i, case in enumerate(cases):
        t = time.monotonic()
        case()
        assert time.monotonic() - t < 1.0, i


def test_exploit_word_run_stays_linear():
    """"exploit" over and over inside one word (no space for the rule's \\s+): every occurrence was a new attempt that
    ran to the end of the word and backtracked through it – 200 KB of one feed entry held the GIL for a minute."""
    run = "exploit" * 8_000  # 56 KB: about 5 s before the fix, a few ms now
    for case in (lambda: news.rate("t", run), lambda: news.rate("t", "", run), lambda: news.rate("t", run + " in freier wildbahn")):
        t = time.monotonic()
        case()
        assert time.monotonic() - t < 0.5
    # still read as before: the word and its endings, up to three words before "in the wild" / "in freier Wildbahn"
    assert news.rate("Bug exploited in the wild", "")[0] == "critical"
    assert news.rate("Exploitation observed in the wild", "")[0] == "critical"
    assert news.rate("Lücke", "Exploits bereits in freier Wildbahn")[0] == "critical"
