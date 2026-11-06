"""EPSS (Exploit Prediction Scoring System, FIRST): the probability that a CVE is exploited in the next 30 days, and its
percentile among all CVEs – for the CVEs of findings (followed products) and of recent stories, nothing else.

- API: https://api.first.org/data/v1/epss?cve=CVE-…,CVE-… – up to BATCH CVEs a request (the query string stays below
  QUERY_MAX characters, FIRST's limit is 2000), no key. Only CVE ids leave the machine.
- Each CVE at most once a day (FIRST publishes once a day); a CVE FIRST does not know yet is remembered as asked (score
  None) and asked again the next day. At most PER_ROUND requests a round – the rest next round.
- Stored in epss_scores (a score not asked for KEEP goes); shown with CVSS/KEV (findings, the story's CVEs); the drawer
  can sort findings by it. Read into memory once per change (_Table): computing a view asks no query for it.
"""

import asyncio
import logging
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as dbm
from app import source_health
from app import vendor_sources as src
from app.models import EpssScore, NewsItem, NewsSource
from app.news import NewsError

log = logging.getLogger("cobe_news.epss")

API = "https://api.first.org/data/v1/epss"
KEY = "epss:first"  # vendor_fetch: the source's state (backoff, health)
BATCH = 100
QUERY_MAX = 1800
PER_ROUND = 20  # requests – up to 2000 CVEs a round
EVERY = timedelta(hours=24)
STORY_DAYS = 30  # stories of the last days
MAX_WANTED = 20000
LIMIT = 1024 * 1024
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def _num(v) -> float | None:  # noqa: ANN001
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if 0.0 <= x <= 1.0 else None


@src._shaped
def parse(data: bytes) -> list[dict]:
    """FIRST's answer: one row per CVE it knows – {cve, score, percentile, date}."""
    doc = src._json(data)
    if not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
        raise NewsError("format", "no EPSS answer")
    out = []
    for r in doc["data"]:
        if not isinstance(r, dict):
            continue
        cve = src._s(r.get("cve"), 32).upper()
        score, pct = _num(r.get("epss")), _num(r.get("percentile"))
        if CVE_ID.match(cve) and score is not None:
            out.append({"cve": cve, "score": score, "percentile": pct, "date": src._s(r.get("date"), 10)})
    return out


def batches(cves: list[str]) -> list[list[str]]:
    """CVE lists for one request each: at most BATCH, the query string below QUERY_MAX."""
    out: list[list[str]] = []
    cur: list[str] = []
    size = 0
    for c in cves:
        if cur and (len(cur) >= BATCH or size + len(c) + 1 > QUERY_MAX):
            out.append(cur)
            cur, size = [], 0
        cur.append(c)
        size += len(c) + 1
    if cur:
        out.append(cur)
    return out


def url(cves: list[str]) -> str:
    return f"{API}?cve={quote(','.join(cves), safe=',-')}&limit={BATCH}"


class _Table:
    """The stored scores in memory (a few thousand rows – only the CVEs of findings and recent stories are kept): read
    once and again only after they changed (refresh, vendor.bump) – a view computed cold asks no query of its own."""

    rows: dict[str, dict] | None = None
    gen = 0  # bumped on every change
    loaded = -1
    lock: asyncio.Lock | None = None


_table = _Table()


def invalidate() -> None:
    _table.gen += 1


async def _rows(db: AsyncSession) -> dict[str, dict]:
    if _table.rows is not None and _table.loaded == _table.gen:
        return _table.rows
    if _table.lock is None:
        _table.lock = asyncio.Lock()
    async with _table.lock:
        if _table.rows is None or _table.loaded != _table.gen:
            gen = _table.gen
            out: dict[str, dict] = {}
            rows = await db.execute(select(EpssScore.cve, EpssScore.score, EpssScore.percentile, EpssScore.day).where(EpssScore.score.is_not(None)))
            for cve, score, pct, day in rows.all():
                out[cve] = {"cve": cve, "score": score, "percentile": pct, "date": day}
            _table.rows, _table.loaded = out, gen
    return _table.rows


async def scores(db: AsyncSession, cves) -> dict[str, dict]:  # noqa: ANN001
    """The stored scores of these CVEs (those FIRST knows): CVE → {cve, score, percentile, date}."""
    table = await _rows(db)
    return {c: table[c] for c in {str(x).upper() for x in cves if x} if c in table}


async def stories_on(db: AsyncSession) -> bool:
    """Whether the stories' CVEs are wanted: the news are on and their details fetched."""
    from app import news as news_svc

    ncfg = await news_svc.config(db)
    return bool(ncfg.get("enabled") and ncfg.get("details", True))


async def wanted(db: AsyncSession) -> list[str]:
    """The CVEs EPSS is asked for: those of the findings that concern a followed version (not the "not affected" ones)
    – from the cached views – and those of the stories of the last STORY_DAYS (while their details are fetched)."""
    from app import news as news_svc
    from app import vendor

    out: dict[str, None] = {}
    fs = await vendor.follows(db)
    if fs:
        vers = await vendor.versions_of(db, [f.id for f in fs])
        kev, euvd = await vendor.kev_index(db), await vendor.euvd_cves(db)
        for f in fs:
            view = await vendor.product_view(db, f, vers.get(f.id, []), kev=kev, euvd=euvd)
            for x in view["findings"]:
                if x["status"] != "not_affected":
                    out.update(dict.fromkeys(x["cves"]))
    if await stories_on(db):
        since = datetime.now(UTC) - timedelta(days=STORY_DAYS)
        stmt = select(NewsItem.cves).join(NewsSource, NewsSource.id == NewsItem.source_id).where(news_svc.visible(), NewsItem.published_at >= since)
        for cves in await db.scalars(stmt):
            out.update(dict.fromkeys(str(c).upper() for c in cves or []))
    return [c for c in out if CVE_ID.match(c)][:MAX_WANTED]


async def refresh(db: AsyncSession, *, force: bool = False) -> int | None:
    """Asks FIRST for the wanted CVEs not asked within a day (PER_ROUND requests at most); returns how many scores
    changed (None: nothing due). The cached views are recomputed when a score changed."""
    from app import vendor

    st = await vendor._state(db, KEY)
    now = datetime.now(UTC)
    if not vendor._due(st, now, force):
        return None
    want = await wanted(db)
    if not want:
        await dbm.release(db)
        return None
    fresh = set()
    for i in range(0, len(want), 5000):
        part = want[i : i + 5000]
        fresh.update(await db.scalars(select(EpssScore.cve).where(EpssScore.cve.in_(part), EpssScore.fetched_at > now - EVERY)))
    due = [c for c in want if c not in fresh]
    if not due:
        st.next_fetch_at = now + timedelta(hours=1)  # look again in an hour (a new finding or story)
        await db.commit()
        return None
    meter = source_health.start()
    changed = asked = 0
    moved: set[str] = set()  # the CVEs whose score changed – only their products' views are recomputed
    try:
        for part in batches(due)[:PER_ROUND]:
            body = await vendor.get(url(part), db=db, conditional=False, limit=LIMIT)
            rows = {r["cve"]: r for r in await asyncio.to_thread(parse, body or b'{"data": []}')}
            old = {c: (s, p) for c, s, p in (await db.execute(select(EpssScore.cve, EpssScore.score, EpssScore.percentile).where(EpssScore.cve.in_(part)))).all()}
            at = datetime.now(UTC)
            values = []
            for c in part:
                r = rows.get(c)
                values.append({"cve": c, "score": r["score"] if r else None, "percentile": r["percentile"] if r else None, "day": (r["date"] if r else "")[:10], "fetched_at": at})
                if r and old.get(c) != (r["score"], r["percentile"]):
                    changed += 1
                    moved.add(c)
            stmt = pg_insert(EpssScore).values(values)
            await db.execute(stmt.on_conflict_do_update(index_elements=["cve"], set_={k: stmt.excluded[k] for k in ("score", "percentile", "day", "fetched_at")}))
            await db.commit()
            asked += len(part)
        st = await vendor._state(db, KEY)
        left = len(due) > asked
        vendor._ok(st, timedelta(minutes=10) if left else timedelta(hours=1), asked)
        vendor._record(db, st, meter, items=changed)
    except Exception as exc:  # noqa: BLE001 - EPSS pauses, nothing else does
        await db.rollback()
        st = await vendor._state(db, KEY)
        vendor._record(db, st, meter, exc=vendor._fail(st, exc, timedelta(hours=1)))
    await db.commit()
    await _prune(db)
    if changed:
        invalidate()
        await vendor.bump_cves(db, moved)  # the findings show the scores – of these CVEs' products only (soft)
    return changed


KEEP = timedelta(days=30)


async def _prune(db: AsyncSession) -> int:
    """Scores not asked for a month (a CVE of no finding or recent story any more) go – in small batches."""
    gone = await dbm.delete_batched(db, EpssScore, EpssScore.fetched_at < datetime.now(UTC) - KEEP, batch=2000)
    if gone:
        invalidate()
    return gone
