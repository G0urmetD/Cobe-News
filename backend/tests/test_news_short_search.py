"""A news search term of 1–2 characters (0.1.51): no index serves it – the list comes without its counts (four more
full scans each: 217 ms alone, 550 ms under load at 30 000 stories in the bug hunt). From 3 characters on, as before."""

import pytest

from app.api import short_search


@pytest.mark.parametrize(("q", "short"), [("", False), ("  ", False), ("z", True), ("zz", True), (" zz ", True), ("zzz", False), ("CVE", False), ("%", False), ("%_", False), ("a%", True), ("%%%a", True)])
def test_short_search(q, short):
    assert short_search(q) is short


async def test_short_terms_come_without_counts(reader_client):
    for q, counted in (("", True), ("zz", False), ("x", False), ("zzz", True)):
        r = await reader_client.get("/api/news", params={"state": "all", "q": q})
        assert r.status_code == 200
        assert ("counts" in r.json()) is counted, q
