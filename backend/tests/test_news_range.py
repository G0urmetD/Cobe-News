"""The News list's "Zeitraum" (since / until on the published or the arrival time, "Seit meinem letzten Besuch" by the
read watermark) and `ids` (a notification's stories): validation (422, never a 500), the list, every count, the cursor
across pages and "Alle als gelesen" marking only what the filter shows. Offline, on invented data (example.com)."""

import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from conftest import set_news
from sqlalchemy import func, select, update
from test_reader import _list, _source, _stories

from app import db, reader
from app.models import NewsItem, NewsRead, ReaderState

H = timedelta(hours=1)


def _iso(d: datetime) -> str:
    return d.isoformat()


async def _dated(*specs: tuple[str, datetime, datetime], key: str = "tr", topics: list[str] | None = None) -> dict[str, uuid.UUID]:
    """Stories by title with (published, fetched) set – stored as the fetch stores them (an arrival number each)."""
    ids = await _stories(*[t for t, _, _ in specs], key=key)
    async with db.session() as s:
        rows = {r.title: r for r in await s.scalars(select(NewsItem).where(NewsItem.id.in_(ids)))}
        for title, pub, fetched in specs:
            rows[title].published_at = pub
            rows[title].fetched_at = fetched
            if topics is not None:
                rows[title].topics = topics
        await s.commit()
        return {t: r.id for t, r in rows.items()}


async def test_range_params_are_checked(reader_client):
    await set_news(enabled=True)
    bad = [
        {"since": "2026-11-05T08:00:00"},  # no zone: whose local time?
        {"until": "2026-11-05T08:00:00"},
        {"since": "9999-12-31T23:59:59-14:00"},  # past what the database holds – a 500 before
        {"until": "0001-01-01T00:00:00+14:00"},
        {"since": "1960-01-01T00:00:00Z"},
        {"since": "2026-11-05T10:00:00Z", "until": "2026-11-05T09:00:00Z"},
        {"since": "gestern"},
        {"time_field": "updated"},
        {"ids": ""},
        {"ids": "not-a-uuid"},
        {"ids": ",".join(str(uuid.uuid4()) for _ in range(51))},
    ]
    for p in bad:
        r = await reader_client.get("/api/news", params=p)
        assert r.status_code == 422, (p, r.text)
    # the same for "Alle als gelesen"
    for body in ({"since": "2026-11-05T08:00:00"}, {"until": "9999-12-31T23:59:59-14:00"}, {"ids": []}, {"ids": ["x"]}, {"time_field": "x"}):
        r = await reader_client.post("/api/news/read-all", json=body)
        assert r.status_code == 422, (body, r.text)
    # a zone in any notation; since == until is an empty range, not an error
    ok = await reader_client.get(f"/api/news?since={quote('2026-11-05T08:00:00+01:00')}&until={quote('2026-11-05T07:00:00Z')}")
    assert ok.status_code == 200 and ok.json()["items"] == []
    assert (await reader_client.get("/api/news", params={"ids": f"{uuid.uuid4()}, {uuid.uuid4()}"})).status_code == 200


async def test_range_on_published_or_arrival_with_counts(reader_client):
    await set_news(enabled=True)
    now = datetime.now(UTC).replace(microsecond=0)
    got = await _dated(
        ("Old published, fetched now", now - 72 * H, now - H),
        ("Fresh", now - 2 * H, now - 2 * H),
        ("Last week", now - 6 * 24 * H, now - 6 * 24 * H),
        topics=["exploited"],
    )
    async with db.session() as s:  # everything unread for the person
        await reader.set_marks(s, reader_client.user.id, news_seq=0, news_at=now - 30 * 24 * H)
        await s.commit()
    since = now - 24 * H
    pub = await _list(reader_client, state="all", since=_iso(since))
    assert [i["title"] for i in pub["items"]] == ["Fresh"]
    assert pub["counts"]["new"] == 1 and pub["counts"]["read"] == 0
    assert pub["counts"]["topics"]["exploited"] == 1  # the quick toggles count within the range
    arr = await _list(reader_client, state="all", since=_iso(since), time_field="fetched")
    assert [i["title"] for i in arr["items"]] == ["Fresh", "Old published, fetched now"]  # still ordered by the date
    assert arr["counts"]["topics"]["exploited"] == 2
    # until is exclusive; both bounds
    week = await _list(reader_client, state="all", since=_iso(now - 7 * 24 * H), until=_iso(now - 2 * H))
    assert [i["title"] for i in week["items"]] == ["Old published, fetched now", "Last week"]
    # "Nur ungelesene" within the range: one read, it leaves the unread list and the numbers follow
    assert (await reader_client.post(f"/api/news/{got['Fresh']}/read")).status_code == 200
    unread = await _list(reader_client, state="new", since=_iso(since), time_field="fetched")
    assert [i["title"] for i in unread["items"]] == ["Old published, fetched now"]
    assert unread["counts"]["new"] == 1 and unread["counts"]["read"] == 1
    assert unread["counts"]["topics"]["exploited"] == 1  # the facets under "Nur ungelesene" too


async def test_cursor_pages_stay_exact_within_a_range(reader_client):
    await set_news(enabled=True)
    sid = await _source("kp")
    now = datetime.now(UTC).replace(microsecond=0)
    async with db.session() as s:
        rows = [
            dict(id=uuid.uuid4(), source_id=sid, url=f"https://kp.example.com/{n}", url_key=f"kp{n}", title=f"K{n:03d}", title_key=f"kp{n}", summary="",
                 content_html="", published_at=now - timedelta(minutes=n // 2), fetched_at=now - timedelta(minutes=n), severity="low", reasons=[], cves=[],
                 also_in=[], search="", seq=1000 + n)  # two stories per minute: ties on the date go by id
            for n in range(150)
        ]
        await s.execute(NewsItem.__table__.insert(), rows)
        await s.commit()
    for field, col in (("published", "published_at"), ("fetched", "fetched_at")):
        since, until = now - timedelta(minutes=60), now - timedelta(minutes=10)
        want = sorted((r for r in rows if since <= r[col] < until), key=lambda r: (r["published_at"], r["id"]), reverse=True)
        seen: list[str] = []
        before = None
        while True:
            p = {"state": "all", "limit": 17, "since": _iso(since), "until": _iso(until), "time_field": field}
            if before:
                p |= {"before": before, "counts": "false"}
            page = await _list(reader_client, **p)
            seen += [i["title"] for i in page["items"]]
            if not page["more"]:
                break
            before = page["next"]
        assert seen == [r["title"] for r in want], field
        assert len(set(seen)) == len(seen)


async def test_read_all_marks_only_the_range(reader_client):
    await set_news(enabled=True)
    now = datetime.now(UTC).replace(microsecond=0)
    got = await _dated(("Today one", now - H, now - H), ("Today two", now - 2 * H, now - 2 * H), ("Days ago", now - 80 * H, now - 80 * H))
    async with db.session() as s:
        await reader.set_marks(s, reader_client.user.id, news_seq=0, news_at=now - 30 * 24 * H)
        await s.commit()
    since = _iso(now - 24 * H)
    page = await _list(reader_client, since=since)
    assert page["counts"]["new"] == 2
    r = await reader_client.post("/api/news/read-all", json={"since": since, "upto": page["upto"]})
    assert r.json() == {"marked": 2}
    left = await _list(reader_client)
    assert [i["title"] for i in left["items"]] == ["Days ago"]  # outside the range: still unread
    async with db.session() as s:
        st = await s.get(ReaderState, reader_client.user.id)
        assert st is not None and st.news_seq == 0  # a range is a filter: marks, the watermark stays
        n = await s.scalar(select(func.count()).select_from(NewsRead).where(NewsRead.user_id == reader_client.user.id))
        assert n == 2
    # on the arrival time: what arrived in the window only
    await reader_client.delete(f"/api/news/{got['Today one']}/read")
    r = await reader_client.post("/api/news/read-all", json={"since": _iso(now - 90 * H), "until": _iso(now - 70 * H), "time_field": "fetched"})
    assert r.json() == {"marked": 1}
    assert [i["title"] for i in (await _list(reader_client))["items"]] == ["Today one"]


async def test_since_my_last_visit_is_the_read_watermark(reader_client):
    await set_news(enabled=True)
    await _stories("Before", key="mk")
    assert (await reader_client.post("/api/news/read-all", json={})).status_code == 200  # the watermark moves
    page = await _list(reader_client, state="all")
    mark_at = datetime.fromisoformat(page["mark_at"])
    assert datetime.now(UTC) - mark_at < timedelta(minutes=1)
    a, b = await _stories("After one", "After two", key="mk")
    # an older date, arrived after the watermark: counted ("what is new since I was here", by arrival)
    async with db.session() as s:
        await s.execute(update(NewsItem).where(NewsItem.id == a).values(published_at=datetime.now(UTC) - 48 * H))
        await s.commit()
    vis = await _list(reader_client, state="all", since_mark="true")
    assert {i["title"] for i in vis["items"]} == {"After one", "After two"}
    assert vis["counts"]["new"] == 2
    # reading one keeps it in the range (it is no "unread" filter), only the numbers move
    await reader_client.post(f"/api/news/{b}/read")
    vis = await _list(reader_client, state="all", since_mark="true")
    assert len(vis["items"]) == 2 and vis["counts"]["new"] == 1 and vis["counts"]["read"] == 1
    r = await reader_client.post("/api/news/read-all", json={"since_mark": True, "upto": vis["upto"]})
    assert r.json() == {"marked": 1}


async def test_ids_show_exactly_those_stories(reader_client):
    await set_news(enabled=True)
    now = datetime.now(UTC).replace(microsecond=0)
    got = await _dated(("Mailed new", now - H, now - H), ("Mailed old", now - 50 * H, now - 50 * H), ("Not mailed", now - 2 * H, now - 2 * H), key="ml")
    async with db.session() as s:
        await reader.set_marks(s, reader_client.user.id, news_seq=0, news_at=now - 30 * 24 * H)
        await s.commit()
    gone = uuid.uuid4()  # a story removed meanwhile: simply not listed
    ids = f"{got['Mailed old']},{got['Mailed new']},{gone},{got['Mailed new']}"
    page = await _list(reader_client, state="all", ids=ids, muted="true")
    assert [i["title"] for i in page["items"]] == ["Mailed new", "Mailed old"]  # newest first
    assert page["counts"]["new"] == 2
    # the other filters still apply when sent (the page sends none with ids)
    assert (await _list(reader_client, state="all", ids=ids, severity="critical"))["items"] == []
    r = await reader_client.post("/api/news/read-all", json={"ids": [str(got["Mailed new"]), str(gone)]})
    assert r.json() == {"marked": 1}
    assert {i["title"] for i in (await _list(reader_client))["items"]} == {"Mailed old", "Not mailed"}
    async with db.session() as s:
        assert (await s.get(ReaderState, reader_client.user.id)).news_seq == 0  # ids are a filter: the watermark stays


def test_views_never_store_ids():
    assert reader.clean_query("range=today&ids=a,b&story=1") == "range=today"
