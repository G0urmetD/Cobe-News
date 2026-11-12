"""The news API: stories for every signed-in person (read per
person), the news settings and the sources for admins."""

import asyncio
import json
import time
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import Text, and_, case, cast, delete, exists, false, func, literal, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.postgresql import JSONB, JSONPATH
from sqlalchemy.dialects.postgresql import array as pg_array
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__, advisory_changes, audit, concerns, epss, exploits, netaddr, reader, story_details
from app import db as dbm
from app import settings as settings_store
from app import keywords as words_svc
from app import news as news_svc
from app import systems as systems_svc
from app.config import get_config, tls_verify
from app.db import contains, fold
from app.deps import Admin, Db, NoNul, Reader, api_error
from app.models import NewsItem, NewsItemSource, NewsSource, NotifyRule, StoryDetail, User

router = APIRouter(prefix="/api", tags=["news"])
Severity = Literal["critical", "high", "medium", "low", "info"]
Topic = Literal["zeroday", "exploited", "poc", "ransomware", "nopatch", "breach", "supply", "phishing", "ot"]  # news.TOPICS
TimeField = Literal["published", "fetched"]  # what a time range is about: published_at (default) or fetched_at (arrival)
IDS_MAX = 50  # `ids` (a notification's stories): at most this many


# in-process, no Redis: one process, one background loop
RECENT_MAX = 10  # stories /news/recent lists – the count covers the rest


class _Limits:
    manual_at = -1e9  # last "fetch now"
    test_at = -1e9  # last "test feed"


limits = _Limits()


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


HEALTH_DB_TIMEOUT = 3.0  # s – below the container's health check (4 s): a hanging database answers 503, not nothing


@router.api_route("/health", methods=["GET", "HEAD"])
async def health() -> JSONResponse:
    """Up and with its database. Without the database (stopped, unreachable, not answering in time): 503 with a minimal
    body – not a 500 with a stack trace in the log (0.1.51). HEAD as GET (uptime monitors)."""
    try:
        async with asyncio.timeout(HEALTH_DB_TIMEOUT), dbm.session() as s:
            await s.execute(select(1))
    except Exception:  # noqa: BLE001 - whatever keeps the database from answering: not ready
        return JSONResponse({"ok": False}, status_code=503, headers={"Retry-After": "10"})
    return JSONResponse({"ok": True, "version": __version__})


def _source_ref(s: NewsSource) -> dict:
    return {"id": str(s.id), "key": s.key, "name": s.name, "logo": bool(s.logo)}


def source_category(s: NewsSource) -> str:
    """The kind of a source: authority | vendor | research | press | catalog – "custom" for a feed an admin added."""
    b = news_svc.BUILTIN_BY_KEY.get(s.key) if s.builtin else None
    return b.category if b else "custom"


def _item_out(i: NewsItem, s: NewsSource, read_at, *, full: bool = False, unread: bool | None = None, muted: bool = False) -> dict:
    out = {
        "id": str(i.id),
        "title": i.title,
        "summary": i.summary,
        "url": i.url,
        "source": _source_ref(s),
        "published_at": i.published_at.isoformat(),
        "severity": i.severity,
        "cves": list(i.cves or [])[: 30 if full else 5],
        "also_in": i.also_in or [],
        "topics": [t for t in news_svc.TOPICS if t in (i.topics or [])],
        "read_at": read_at.isoformat() if read_at else None,
        # read state of the person asking (app/reader.py: watermark, marks, age) – None where it is not asked (/news/recent)
        "unread": unread,
        "muted": muted,
    }
    if full:
        out |= {"content_html": i.content_html, "reasons": i.reasons or []}
    return out


def _topic_filter(topics: list[str]):  # noqa: ANN202
    """The story has one of these topics (OR within the topics; the GIN index on news_items.topics)."""
    return news_svc.has_topic(topics)


def _filters(sources: list[uuid.UUID], severity: list[str], q: str, topics: list[str] | None = None) -> list:
    # a story carried by several sources counts for each: shown while any of them is on, found under each of them
    where = [news_svc.visible(sources)]
    if severity:
        where.append(NewsItem.severity.in_(severity))
    if topics:
        where.append(_topic_filter(topics))
    if q.strip():
        # case and accents ignored also beyond ASCII (db.fold); % and _ are not wildcards here
        where.append(NewsItem.search.like(contains(q.strip()[:100])))  # folded when stored – no function call per row
    return where


def _with_source(stmt):  # noqa: ANN001, ANN202
    return stmt.join(NewsSource, NewsSource.id == NewsItem.source_id)


def _when(d: datetime | None, name: str) -> datetime | None:
    """A bound of the time range as aware UTC – 422 for a time without a zone (whose local time?) or outside
    1970–2100 (year 9999 at -14:00 overflows on the way: never a 500)."""
    if d is None:
        return None
    if d.tzinfo is None:
        raise api_error(422, "invalid", errors=f"{name} needs a time zone")
    if (s := _sane_time(d)) is None:
        raise api_error(422, "invalid", errors=f"{name} out of range")
    return s


def time_range(since: datetime | None, until: datetime | None, field: str = "published", mark: reader.Marks | None = None) -> list:
    """The list's "Zeitraum" as conditions: `since` (inclusive) to `until` (exclusive) on the published or the arrival
    time (both indexed: ix_news_items_published, ix_news_items_fetched); `mark` ("Seit meinem letzten Besuch"): what
    arrived after the person's read watermark – by its arrival number, as the read state decides it (app/reader.py)."""
    s, u = _when(since, "since"), _when(until, "until")
    if s is not None and u is not None and s > u:
        raise api_error(422, "invalid", errors="since is after until")
    col = NewsItem.fetched_at if field == "fetched" else NewsItem.published_at
    out: list = []
    if s is not None:
        out.append(col >= s)
    if u is not None:
        out.append(col < u)
    if mark is not None:
        out.append(or_(and_(NewsItem.seq.is_not(None), NewsItem.seq > mark.news_seq), and_(NewsItem.seq.is_(None), NewsItem.fetched_at > mark.news_at)))
    return out


def story_ids(raw: str | list[str] | None) -> list[uuid.UUID] | None:
    """`ids` – the stories of a notification ("a,b,c", also as several parameters): at most IDS_MAX, each a UUID,
    else 422 (never a 500). None: no such filter."""
    if raw is None:
        return None
    parts = [p.strip() for x in ([raw] if isinstance(raw, str) else raw) for p in x.split(",") if p.strip()]
    if not parts or len(parts) > IDS_MAX:
        raise api_error(422, "invalid", errors=f"ids: 1 to {IDS_MAX} story ids")
    try:
        return list(dict.fromkeys(uuid.UUID(p) for p in parts))
    except ValueError as exc:
        raise api_error(422, "invalid", errors="ids: not a story id") from exc


async def ours_keys(db: AsyncSession, user: User, scope: str, labels: dict[str, str] | None = None) -> set[str]:
    """"Betrifft unsere Produkte": the products that count – every followed one, or under "Mein Team" (`scope=team`, as
    Vendor News) those of the person's teams (while Teams is off: every followed one)."""
    from app import teams

    keys = set((labels if labels is not None else await story_details.followed_labels(db)).keys())
    if scope == "team" and (mine := await teams.my_products(db, user.id)) is not None:
        keys &= mine
    return keys


def _ours_filter(keys: set[str]):  # noqa: ANN202
    """The story concerns one of these products (news_items.products – story_details.products_of; the GIN index)."""
    return NewsItem.products.op("?|")(pg_array(sorted(keys))) if keys else false()


def _with_ours(items: list[dict], stored: list[list], labels: dict[str, str]) -> None:
    """The cards' badge "Unser Produkt: PAN-OS": the followed products a story concerns, by their label – those of
    `labels` only (the list passes the scope's: under "Mein Team" the team's products, as the filter and its number)."""
    for x, keys in zip(items, stored, strict=True):
        x["products"] = [{"key": k, "label": labels[k]} for k in keys or [] if k in labels]


SEARCH_MIN = 3  # the trigram index (ix_news_items_search_trgm) needs 3 characters – as the audit log's search


def short_search(q: str) -> bool:
    """A term of 1–2 characters: no index serves it – the list itself reads on until it has its page, but the counts
    (total, unread, the topics' facets, "Betrifft unsere Produkte") would each read every story: four full scans,
    217 ms alone and 550 ms under load at 30 000 stories (bug hunt 0.1.50). For such a term the list comes without
    counts (the page says so: at least 3 characters, as the audit log's search)."""
    term = fold(q.strip()[:100]).replace("%", "").replace("_", "").strip()  # as the filter uses it (db.contains)
    return 0 < len(term) < SEARCH_MIN


def system_filter(values: list[str]) -> list[dict]:
    """The list's "Systeme" (`system`) as entries – 422 for a malformed one (never a 500)."""
    try:
        return concerns.from_query(list(values))
    except ValueError as exc:
        raise api_error(422, "invalid", errors=str(exc)) from exc


def words_filter(values: list[str]) -> list[str]:
    """The list's "Ohne …" (`without`) checked as a rule's words – 422 otherwise."""
    try:
        return words_svc.clean(list(values))
    except ValueError as exc:
        raise api_error(422, "invalid", errors=str(exc)) from exc


@router.get("/news")
async def list_news(
    user: Reader,
    db: Db,
    state: Literal["all", "new", "read"] = "new",
    source: Annotated[list[uuid.UUID], Query(max_length=50)] = [],  # noqa: B006 - FastAPI query list (several sources)
    severity: Annotated[list[Severity], Query()] = [],  # noqa: B006 - FastAPI query list
    topic: Annotated[list[Topic], Query(max_length=9)] = [],  # noqa: B006 - FastAPI query list (OR within the topics)
    q: Annotated[str, Query(max_length=100)] = "",
    limit: Annotated[int, Query(ge=1, le=120)] = 60,
    before: Annotated[str | None, Query(max_length=100)] = None,
    counts: bool = True,
    muted: bool = False,
    ours: bool = False,
    scope: Literal["all", "team"] = "all",
    since: datetime | None = None,
    until: datetime | None = None,
    time_field: TimeField = "published",
    since_mark: bool = False,
    ids: Annotated[str | None, Query(max_length=IDS_MAX * 40)] = None,
    system: Annotated[list[str], Query(max_length=systems_svc.ENTRIES_MAX)] = [],  # noqa: B006 - FastAPI query list ("v:<vendor>" | "p:<key>" | "ours")
    without: Annotated[list[str], Query(max_length=words_svc.WORDS_MAX)] = [],  # noqa: B006 - FastAPI query list ("ohne …")
) -> dict:
    """Stories newest first – "all", "new" (unread by me) or "read" (read by me); app/reader.py decides what is read
    (the watermark, the marks, the age). `muted`: also the stories whose CVEs I all muted (flagged, dimmed by the page) –
    without it they are left out. `counts.new` counts the unread ones of the list (the filter, muted as asked).

    Paged by a cursor (`before` = the `next` of the previous page: time and id of its last story) instead of an
    offset – stories arriving or being read meanwhile neither repeat nor skip one on the next page.

    `ours` ("Betrifft unsere Produkte"): only stories whose details concern a followed product – under `scope=team`
    one of the person's teams. `counts.ours` counts them with every other filter; `ours_on`: anything is followed (in
    that scope) at all.

    "Zeitraum": `since` (inclusive) / `until` (exclusive) – times with a zone – on `time_field` (published: the story's
    date, fetched: its arrival); `since_mark`: what arrived after my read watermark ("Seit meinem letzten Besuch" – its
    time is `mark_at`). `ids`: only these stories (a notification's, "a,b,c", at most 50). `system` ("Systeme",
    app/concerns.py): stories about one of these catalogue vendors ("v:Palo Alto Networks" – each of its products) or
    products ("p:panos") or the products followed now ("ours" – "Unsere Produkte", also those followed by CPE by their
    details) – by their details or named in title or teaser, also what a story has only quietly (a list
    shows what concerns a system; only notifications ask for loud ones). `without` ("Ohne …"): none of these words, whole,
    in title or teaser – as a rule's "Nicht senden, wenn enthalten" (checked as there: plain text, at most 30). Each is
    one more filter: the list, every count and the cursor alike (the order stays by date)."""
    me = user.id
    wanted = story_ids(ids)
    chosen = system_filter(system)
    unwanted = words_filter(without)
    now = datetime.now(UTC)
    # the arrival number of the newest story stored before this list was read ("Alle gelesen" marks up to it, not
    # what arrived after the page was loaded) – read first: a story stored meanwhile has a higher number
    upto = await news_svc.last_seq(db)
    m = await reader.marks(db, user)
    mutes = await reader.mutes_of(db, me, now)
    r, on = reader.news_read_mark(me)
    where = _filters(list(source), list(severity), q)  # without the topics: the facets count every topic
    where += time_range(since, until, time_field, m if since_mark else None)
    if wanted is not None:
        where.append(NewsItem.id.in_(wanted))
    if chosen:
        if systems_svc.has_ours(chosen):
            await systems_svc.load_followed(db)  # "Unsere Produkte": the products followed now
        where.append(concerns.systems_clause(chosen, quiet_too=True))
    if (no := words_svc.none_of(unwanted)) is not None:
        where.append(no)  # last: the database applies it after the cheaper conditions (a regex per remaining row)
    hush = reader.news_muted(mutes)
    if hush is not None and not muted:
        where.append(~hush)
    labels = await story_details.followed_labels(db)
    keys = await ours_keys(db, user, scope, labels)
    facet_where = list(where)  # the topics' facets: every filter but the topics
    ours_where = list(where)  # the count of "Betrifft unsere Produkte": every filter but itself
    if topic:
        where.append(_topic_filter(list(topic)))
        ours_where.append(_topic_filter(list(topic)))
    if ours:
        where.append(_ours_filter(keys))
        facet_where.append(_ours_filter(keys))
    unread = reader.news_unread(r, m, now)
    cols = (NewsItem, NewsSource, r.read_at, unread.label("is_unread"), (hush if hush is not None else literal(False)).label("is_muted"))
    stmt = _with_source(select(*cols).select_from(NewsItem)).outerjoin(r, on).where(*where)
    if state == "new":
        stmt = stmt.where(unread)
    elif state == "read":
        stmt = stmt.where(~unread)
    key = NewsItem.published_at
    if before:
        at, sid = _cursor(before)
        stmt = stmt.where(or_(key < at, and_(key == at, NewsItem.id < sid)))
    rows = (await db.execute(stmt.order_by(key.desc(), NewsItem.id.desc()).limit(limit + 1))).all()
    items = [_item_out(i, s, None if un else ra, unread=bool(un), muted=bool(mu)) for i, s, ra, un, mu in rows[:limit]]
    _with_ours(items, [r[0].products for r in rows[:limit]], {k: v for k, v in labels.items() if k in keys})
    out: dict = {"items": items, "more": len(rows) > limit, "next": None, "upto": upto, "ours_on": bool(keys), "mark_at": m.news_at.isoformat()}
    await _with_hints(db, out["items"])
    if len(rows) > limit:
        i = rows[limit - 1][0]
        out["next"] = f"{i.published_at.isoformat()}|{i.id}"
    if counts and not short_search(q):  # the next pages do not need them; a term of 1–2 characters: none (below)
        total = int(await db.scalar(_with_source(select(func.count()).select_from(NewsItem)).where(*where)) or 0)
        new = await reader.news_unread_count(db, me, m, where, now, _with_source)
        out["counts"] = {
            "new": new,
            "read": max(0, total - new),
            "topics": await _topic_counts(db, facet_where, r, on, unread, state),
            "ours": await _ours_count(db, [*ours_where, _ours_filter(keys)], r, on, unread, state) if keys else 0,
        }
    out["enabled"] = bool((await news_svc.config(db)).get("enabled"))
    return out


async def _topic_counts(db: AsyncSession, where: list, r, on, unread, state: str) -> dict[str, int]:  # noqa: ANN001
    """Stories per topic of the list as it is filtered – every other filter (sources, severity, search, muted, the read
    state), not the topic filter itself: the numbers in the "Thema" filter say what choosing a topic would show."""
    inner = _with_source(select(func.jsonb_array_elements_text(NewsItem.topics).label("t")).select_from(NewsItem))
    if state != "all":
        inner = inner.outerjoin(r, on).where(unread if state == "new" else ~unread)
    # the cheap test first: the database keeps the order of conditions of equal cost – "Ohne …" (a regex) only for the
    # stories that have a topic at all
    sub = inner.where(NewsItem.topics != cast(literal("[]"), JSONB), *where).subquery()
    rows = (await db.execute(select(sub.c.t, func.count()).group_by(sub.c.t))).all()
    got = {str(t): int(n) for t, n in rows}
    return {t: got.get(t, 0) for t in news_svc.TOPICS}


async def _ours_count(db: AsyncSession, where: list, r, on, unread, state: str) -> int:  # noqa: ANN001
    """Stories of the list as it is filtered that concern one of our products (the number on the chip)."""
    stmt = _with_source(select(func.count()).select_from(NewsItem))
    if state != "all":
        stmt = stmt.outerjoin(r, on).where(unread if state == "new" else ~unread)
    return int(await db.scalar(stmt.where(*where)) or 0)


TIME_MIN, TIME_MAX = datetime(1970, 1, 1, tzinfo=UTC), datetime(2100, 1, 1, tzinfo=UTC)


def _sane_time(d: datetime) -> datetime | None:
    """A time from a query as aware UTC – None outside 1970–2100 (year 9999 at -14:00 is past what Python and the
    database can hold: it ended in a 500)."""
    try:
        d = (d if d.tzinfo else d.replace(tzinfo=UTC)).astimezone(UTC)
    except (OverflowError, ValueError):
        return None
    return d if TIME_MIN <= d < TIME_MAX else None


def _cursor(value: str) -> tuple[datetime, uuid.UUID]:
    try:
        at, sid = value.split("|", 1)
        d = _sane_time(datetime.fromisoformat(at))
        if d is None:
            raise ValueError("time out of range")
        return d, uuid.UUID(sid)
    except ValueError as exc:
        raise api_error(422, "invalid_cursor") from exc


@router.get("/news/sources")
async def sources(user: Reader, db: Db) -> list[dict]:
    """The switched-on sources – for the filter: every source whose stories the list shows (also one that failed lately),
    by name regardless of case and accents (db.fold; "golem.de" no longer trails "The Record") – a few dozen rows."""
    rows = sorted(await db.scalars(select(NewsSource).where(NewsSource.enabled.is_(True))), key=lambda s: (fold(s.name), s.key))
    return [{**_source_ref(s), "category": source_category(s)} for s in rows]


def desktop_filter(user_prefs: dict | None) -> list:
    """What a person chose for desktop notifications (severities, sources, topics; empty = all) as SQL conditions – the
    tab's /news/recent and the server's Web Push send exactly the same. The topics are those the story has when it
    arrives (title, teaser, source, the KEV) – a topic its details bring later does not pop up afterwards."""
    prefs = user_prefs or {}
    where = []
    if sev := [x for x in prefs.get("severities") or [] if x in news_svc.SEVERITIES]:
        where.append(NewsItem.severity.in_(sev))
    if topics := [x for x in news_svc.TOPICS if x in (prefs.get("topics") or [])]:
        where.append(news_svc.has_topic(topics))
    if ids := news_svc._ids(prefs.get("sources")):
        where.append(news_svc.visible(ids))  # also a story first stored for another source that this one carries too
    # "Systeme" or "Schlagwörter" (one of them is enough) and "Nicht anzeigen, wenn enthalten" – the channel rules'
    # clauses (app/concerns.py), loud systems only: what a story names when it arrives, and its details if they came
    # with it – a system its details bring later does not pop up afterwards (as a topic)
    where += concerns.news_where(*desktop_concerns(prefs), quiet_too=False)
    return where


async def load_desktop(db: AsyncSession, prefs: dict | None) -> None:
    """What desktop_filter and desktop_hits need read first: the followed products, when the person chose "Unsere
    Produkte" (systems.load_followed – kept, not read per person)."""
    if systems_svc.has_ours((prefs or {}).get("systems")):
        await systems_svc.load_followed(db)


def desktop_concerns(prefs: dict | None) -> tuple[list[dict], list[str], list[str]]:
    """A person's desktop systems, words and exclusions as stored (empty: none)."""
    prefs = prefs or {}
    words = lambda k: [str(x) for x in prefs.get(k) or [] if str(x).strip()]  # noqa: E731
    return systems_svc.entries(prefs.get("systems")), words("keywords"), words("exclude")


def desktop_hits(prefs: dict | None):  # noqa: ANN201
    """What a story matched the person's desktop systems and words by ("Treffer") – a function of the story; None when
    neither is chosen (the notification says nothing then, as a rule's)."""
    chosen, words, _ = desktop_concerns(prefs)
    if not chosen and not words:
        return None
    want = systems_svc.wanted(chosen)
    return lambda i: concerns.story_hits(i, chosen, words, want)


EXPLOITED_REASONS = ("kev", "euvd", "exploited", "ransomware")  # a reason of these kinds: the story says "ausgenutzt"
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def notice_facts(i: NewsItem) -> dict:
    """What a notification of one story says besides its title (the tab's and the Web Push's line, webpush.notice_line):
    `rated` – the severity comes from the story (a reason: CVSS, BSI, the vendor's rating …); an unrated story ("info"
    without a reason) shows none –, its CVSS when one was read, `exploited` (KEV, EUVD, the text says so) and `products`:
    the products it is about (concerns.story_names)."""
    reasons = [r for r in i.reasons or [] if isinstance(r, dict)]
    cvss = next((str(r.get("value") or "") for r in reasons if r.get("kind") == "cvss" and r.get("value")), None)
    return {
        "rated": bool(reasons) or i.severity != "info",
        "cvss": cvss,
        "exploited": any(r.get("kind") in EXPLOITED_REASONS for r in reasons),
        "products": concerns.story_names(i)[:10],
    }


# notice_facts in SQL – for the order of a round (arrived) and the highest severity of what it does not list
_EXPLOITED_SQL = func.jsonb_path_exists(NewsItem.reasons, cast("$[*] ? (" + " || ".join(f'@.kind == "{k}"' for k in EXPLOITED_REASONS) + ")", JSONPATH))
_RATED_SQL = or_(NewsItem.severity != "info", func.jsonb_path_exists(NewsItem.reasons, cast('$[*] ? (@.type() == "object")', JSONPATH)))
_SEV_RANK_SQL = case(SEV_RANK, value=NewsItem.severity, else_=0)
_PRIORITY_SQL = case((or_(NewsItem.severity == "critical", _EXPLOITED_SQL), 1), else_=0)


def fresh_filter() -> list:
    """No backlog, as for the notification rules: the first fetch of a catalog (CISA KEV: ~100 entries of the last 90
    days) or of a source switched on later pops up nothing – only what was fresh when it arrived (news._backlog, decided
    once when the story was stored)."""
    return [news_svc.visible(), NewsItem.backlog.is_(False)]


async def arrived(db: AsyncSession, where: list) -> tuple[list[tuple[NewsItem, NewsSource]], int, str | None]:
    """At most RECENT_MAX stories matching `where`, the most important first – critical or exploited (notice_facts),
    then the newest –, how many match in all, and the highest severity of the matching ones not listed (rated ones
    only, as the summary line; None: there are none). A notification round shows the first few of the list on their own
    (tab and Web Push alike), so a critical story is never only a number in the summary. The count and the severity are
    one aggregate over the same rows, asked only when the list is full."""
    q = select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).where(*where)
    order = (_PRIORITY_SQL.desc(), NewsItem.seq.desc(), NewsItem.published_at.desc())
    rows = [(r[0], r[1]) for r in (await db.execute(q.order_by(*order).limit(RECENT_MAX))).all()]
    if len(rows) < RECENT_MAX:
        return rows, len(rows), None
    rest = and_(_RATED_SQL, NewsItem.id.not_in([i.id for i, _s in rows]))
    agg = select(func.count(), func.max(_SEV_RANK_SQL).filter(rest)).select_from(NewsItem).join(NewsSource, NewsSource.id == NewsItem.source_id).where(*where)
    total, rank = (await db.execute(agg)).one()
    return rows, int(total or 0), next((k for k, v in SEV_RANK.items() if v == rank), None) if rank is not None else None


@router.get("/news/recent")
async def recent(user: Reader, db: Db, after: Annotated[int | None, Query(ge=0)] = None, since: datetime | None = None, mine: bool = False) -> dict:
    """For desktop notifications in an open tab: stories that arrived after the cursor `after` (the arrival number the
    tab got last time – `cursor` is the next one). Without a cursor nothing, only `cursor`: a new tab shows no backlog.
    `mine`: only what this person chose for desktop notifications (severities, sources, topics, systems, words – each
    story then with its `hits`, "Treffer", when systems or words are chosen). `items`: at most RECENT_MAX, critical or
    exploited ones first, then the newest (arrived); `total` counts all of them, `unlisted_top` is the highest severity
    of those not listed – the tab shows the first few on their own and one summary for the rest (its line names that
    severity too), nothing gets lost however many arrived.

    The cursor is read first and the stories up to it after: a story stored meanwhile has a higher number and comes the
    next time. `since` (a time, `now` of the last answer) is what tabs of the previous build still send – a time cursor misses stories
    whose transaction began before a poll and ended after it."""
    now = datetime.now(UTC)
    top = await news_svc.last_seq(db)
    if after is None and since is None:
        return {"items": [], "total": 0, "now": now.isoformat(), "cursor": top}
    if since is not None and (since := _sane_time(since)) is None:
        raise api_error(422, "invalid_since")
    where = fresh_filter()
    if after is not None:
        where += [NewsItem.seq > min(after, top), NewsItem.seq <= top]  # a cursor from a bigger (restored) database: from here on
    else:
        assert since is not None
        where += [NewsItem.fetched_at > since, NewsItem.fetched_at <= now]
    if mine:
        await load_desktop(db, user.desktop)
        where += desktop_filter(user.desktop)
    rows, total, unlisted_top = await arrived(db, where)
    hit = desktop_hits(user.desktop) if mine else None
    items = [_item_out(i, s, None) | {"notice": notice_facts(i)} | ({"hits": hit(i)} if hit else {}) for i, s in rows]
    return {"items": items, "total": total, "unlisted_top": unlisted_top, "now": now.isoformat(), "cursor": top}


@router.get("/news/sources/{sid}/logo")
async def logo(sid: uuid.UUID, user: Reader, db: Db) -> Response:
    """The icon the server fetched once – the browser loads nothing from the news sites."""
    s = await db.get(NewsSource, sid)
    if s is None or not s.logo or not s.logo_type:
        raise api_error(404, "not_found")
    return Response(s.logo, media_type=s.logo_type, headers={"Cache-Control": "private, max-age=86400", "X-Content-Type-Options": "nosniff"})


async def _story(db: AsyncSession, sid: uuid.UUID) -> tuple[NewsItem, NewsSource]:
    row = (await db.execute(select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).where(NewsItem.id == sid))).first()
    if row is None:
        raise api_error(404, "not_found")
    return row[0], row[1]


@router.get("/news/{sid}")
async def get_story(sid: uuid.UUID, user: Reader, db: Db) -> dict:
    i, s = await _story(db, sid)
    now = datetime.now(UTC)
    m = await reader.marks(db, user)
    r, on = reader.news_read_mark(user.id)
    read_at, unread = (await db.execute(select(r.read_at, reader.news_unread(r, m, now)).select_from(NewsItem).outerjoin(r, on).where(NewsItem.id == i.id))).one()
    mutes = await reader.mutes_of(db, user.id, now)
    out = _item_out(i, s, None if unread else read_at, full=True, unread=bool(unread), muted=mutes.all_cves(i.cves))
    _with_ours([out], [i.products], await story_details.followed_labels(db))
    det = await db.get(StoryDetail, i.id)
    data = det.data if det is not None and det.status == "ok" else None
    out["details"] = {k: v for k, v in data.items() if k != "match"} if data else None
    out["details_state"] = det.status if det is not None else "pending"
    # the drawer's "Themen": why each topic (computed on request, by the same rules as the stored list)
    out["topic_reasons"] = await news_svc.story_topics(db, i, s.key, det.data if det is not None else None)
    out["affects"] = story_details.matches(data, await story_details.followed(db)) if data else []
    # FIRST EPSS of the story's CVEs (as far as asked – app/epss.py), the likeliest first
    out["epss"] = sorted((await epss.scores(db, [c.upper() for c in (i.cves or [])[:60]])).values(), key=lambda e: -e["score"])[:12]
    # Exploit-Hinweise: the switched-on exploit lists naming the story's CVEs (its own and its details' – app/exploits.py)
    named = list(dict.fromkeys(str(c).upper() for c in [*(i.cves or []), *((data or {}).get("cves") or [])] if isinstance(c, str)))[:60]
    out["exploits"] = exploits.brief(await exploits.of_cves(db, named), named, 12)
    # the revisions of the advisory behind the story (Vendor News keeps them – app/advisory_changes.py)
    out["changes"] = await advisory_changes.of_advisories(db, story_details.advisory_ids(det.kind, det.ident, i.cves or [])) if det is not None else []
    return out


_hints: dict[tuple, dict | None] = {}  # (story, details fetched at, Vendor News state) → the card's hint


async def _with_hints(db: AsyncSession, items: list[dict]) -> None:
    """The cards' hint from the details (CVSS, "betrifft GitLab < 19.5.1") and whether it concerns a followed product.
    Matching a page of details against every followed product is CPU work: done off the event loop (the JSON decoded
    there too) and kept until the details or the followed products change."""
    from app import vendor

    if not items:
        return
    ids = [uuid.UUID(x["id"]) for x in items]
    stamp = vendor.gen.value
    rows = (await db.execute(select(StoryDetail.item_id, StoryDetail.fetched_at).where(StoryDetail.item_id.in_(ids), StoryDetail.status == "ok"))).all()
    want = {iid: (iid, at, stamp) for iid, at in rows}
    missing = [iid for iid, ck in want.items() if ck not in _hints]
    if missing:
        raw = dict((await db.execute(select(StoryDetail.item_id, cast(StoryDetail.data, Text)).where(StoryDetail.item_id.in_(missing)))).all())
        fol = await story_details.followed(db)

        def compute() -> dict:
            out = {}
            for iid, text_ in raw.items():
                data = json.loads(text_) if text_ else None
                h = story_details.hint(data)
                if h is not None and fol:
                    h["affects"] = any(any(v["status"] in ("affected", "possible") for v in m["versions"]) for m in story_details.matches(data, fol))
                out[want[iid]] = h
            return out

        got = await asyncio.to_thread(compute)
        if len(_hints) > 5000:
            _hints.clear()
        _hints.update(got)
    for x, iid in zip(items, ids, strict=True):
        ck = want.get(iid)
        h = _hints.get(ck) if ck else None
        x["hint"] = dict(h) if h else None


@router.post("/news/{sid}/read")
async def mark_read(sid: uuid.UUID, user: Reader, db: Db) -> dict:
    """Read – also what opening the story does (the page asks it once when the drawer opens an unread story)."""
    i, _ = await _story(db, sid)
    await reader.news_mark(db, user.id, i.id, read=True)
    await db.commit()
    return {"ok": True}


@router.delete("/news/{sid}/read")
async def mark_unread(sid: uuid.UUID, user: Reader, db: Db) -> dict:
    """"Als ungelesen markieren": unread again, also below the watermark or older than reader.AUTO_READ."""
    i, _ = await _story(db, sid)
    await reader.news_mark(db, user.id, i.id, read=False)
    await db.commit()
    return {"ok": True}


class ReadAllIn(_M):
    source: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    severity: list[Severity] = Field(default_factory=list, max_length=5)
    topic: list[Topic] = Field(default_factory=list, max_length=9)
    q: str = Field(default="", max_length=100)
    # the list's `upto`: only what had arrived when the page was loaded – a story arriving meanwhile stays new (unseen).
    # At most what the column holds (news_items.seq is an integer): a bigger number reached PostgreSQL – a 500
    upto: int | None = Field(default=None, ge=0, le=2**31 - 1)
    muted: bool = False  # the list showed the muted stories too ("Stummgeschaltete zeigen")
    ours: bool = False  # "Betrifft unsere Produkte"
    scope: Literal["all", "team"] = "all"
    # the list's "Zeitraum" (as GET /news resolved it – a preset's times as the page asked them) and `ids`
    since: datetime | None = None
    until: datetime | None = None
    time_field: TimeField = "published"
    since_mark: bool = False
    ids: list[uuid.UUID] | None = Field(default=None, min_length=1, max_length=IDS_MAX)
    system: list[Annotated[str, Field(max_length=concerns.QUERY_MAX)]] = Field(default_factory=list, max_length=50)  # the list's "Systeme"
    without: list[Annotated[str, Field(max_length=200)]] = Field(default_factory=list, max_length=words_svc.WORDS_MAX)  # the list's "Ohne …"


@router.post("/news/read-all")
async def read_all(body: ReadAllIn, user: Reader, db: Db) -> dict:
    """Everything unread of the current filter (up to `upto` when given) read at once – by the filter, never by ids:
    without a filter the person's watermark moves (app/reader.py), with one a mark per unread story. Idempotent.
    A time range or `ids` is a filter like any: only what the list shows is marked."""
    mutes = await reader.mutes_of(db, user.id)
    where = _filters(list(body.source), list(body.severity), body.q, list(body.topic))
    where += time_range(body.since, body.until, body.time_field, await reader.marks(db, user) if body.since_mark else None)
    if body.ids is not None:
        where.append(NewsItem.id.in_(list(dict.fromkeys(body.ids))))
    if chosen := system_filter(body.system):
        if systems_svc.has_ours(chosen):
            await systems_svc.load_followed(db)
        where.append(concerns.systems_clause(chosen, quiet_too=True))
    if (no := words_svc.none_of(words_filter(body.without))) is not None:
        where.append(no)
    hush = reader.news_muted(mutes)
    if hush is not None and not body.muted:
        where.append(~hush)
    if body.ours:
        where.append(_ours_filter(await ours_keys(db, user, body.scope)))
    # a topic (or our products) is a filter: marks for its unread stories, the watermark stays
    ranged = body.since is not None or body.until is not None or body.since_mark or body.ids is not None
    everything = not body.source and not body.severity and not body.topic and not body.ours and not chosen and no is None and not body.q.strip() and not ranged and (hush is None or body.muted)
    top = await news_svc.last_seq(db)
    upto = min(body.upto, top) if body.upto is not None else top
    marked = await reader.news_read_all(db, user, where, _with_source, upto=upto, everything=everything)
    await db.commit()
    return {"marked": marked}


# ---------------------------------------------------------------- settings and sources (admins)


class NewsIn(_M):
    enabled: bool = False
    every_min: int = Field(default=30, ge=15, le=1440)  # each feed at most every quarter of an hour – the sites' rate limits
    keep_days: int = Field(default=90, ge=7, le=365)
    details: bool = True  # Details aus der Quelle (CSAF, NVD) per story – app/story_details.py
    rev: int | None = None  # the state the form was loaded with (409 stale when another admin saved in between)


@router.get("/admin/settings/news")
async def get_settings(admin: Admin, db: Db) -> dict:
    cfg = await news_svc.config(db)
    return {**cfg, "rev": int(cfg.get("rev") or 0)}


@router.get("/admin/settings/news/prune-preview")
async def prune_preview(admin: Admin, db: Db, keep_days: int = Query(ge=7, le=365)) -> dict:
    """How many stories a shorter retention would delete with the next hourly prune – asked before it is saved (the
    stories go for good: what the retention deleted is never fetched again)."""
    return {"keep_days": keep_days, "count": await news_svc.prune_count(db, keep_days)}


@router.put("/admin/settings/news")
async def put_settings(body: dict, request: Request, admin: Admin, db: Db) -> dict:
    try:
        parsed = NewsIn.model_validate(body)
    except ValidationError as exc:
        raise api_error(422, "invalid", errors=str(exc)[:500]) from exc
    data = parsed.model_dump(exclude={"rev"})
    before = await news_svc.config(db)
    if changes := audit.diff(before, data, data.keys()):
        audit.record(db, admin, "settings.changed", audit.target("settings", "news", "news"), {"changes": changes})
    out = await settings_store.put_rev(db, "news", data, parsed.rev)
    if data["enabled"] and not before.get("enabled"):
        # switched on again: like a source switched on again – each feed's first fetch is a baseline (what a feed
        # listed undated meanwhile is backlog, not news); the stored stories, their read marks and cut stay
        await db.execute(update(NewsSource).values(primed_at=None))
        await db.commit()
        request.app.state.wake()  # switched on: the first round right away
    return out


def _source_out(s: NewsSource, count: int) -> dict:
    b = news_svc.BUILTIN_BY_KEY.get(s.key) if s.builtin else None
    return {
        **_source_ref(s),
        "url": s.url,
        "site": s.site,
        "builtin": s.builtin,
        # the group in the settings and the language of the texts (an own feed: "custom", language unknown)
        "category": source_category(s),
        "lang": b.lang if b else None,
        "enabled": s.enabled,
        "items": count,
        "last_fetch_at": s.last_fetch_at.isoformat() if s.last_fetch_at else None,
        "last_ok_at": s.last_ok_at.isoformat() if s.last_ok_at else None,
        "next_fetch_at": s.next_fetch_at.isoformat() if s.next_fetch_at else None,
        "error": s.error,
    }


async def source_counts(db: AsyncSession) -> dict[uuid.UUID, int]:
    """Stories per source – each story for every source that carries it (its own and the further ones of also_in)."""
    counts = dict((await db.execute(select(NewsItem.source_id, func.count()).group_by(NewsItem.source_id))).all())
    for sid, n in (await db.execute(select(NewsItemSource.source_id, func.count()).group_by(NewsItemSource.source_id))).all():
        counts[sid] = counts.get(sid, 0) + int(n)
    return counts


@router.get("/admin/news")
async def admin_news(admin: Admin, db: Db) -> dict:
    counts = await source_counts(db)
    rows = sorted(await db.scalars(select(NewsSource)), key=lambda s: (not s.builtin, fold(s.name), s.key))  # case-insensitive, as the filter
    return {"settings": await news_svc.config(db), "sources": [_source_out(s, int(counts.get(s.id, 0))) for s in rows]}


def _feed_url(v: str) -> str:
    v = netaddr.normal_url(v)  # one spelling of the address: host in lower case (IDNA), no default port (0.1.51)
    if not netaddr.valid_url(v, https_only=True) or netaddr.forbidden_literal(v):
        raise ValueError("invalid url")
    return v


async def _same_feed(db: AsyncSession, url: str, other_than: uuid.UUID | None = None) -> bool:
    """Is this address a source already – compared in one spelling (netaddr.normal_url): sources stored before 0.1.51
    may still be written with an upper-case host or the default port."""
    want = netaddr.normal_url(url)
    q = select(NewsSource.url)
    if other_than is not None:
        q = q.where(NewsSource.id != other_than)
    return any(netaddr.normal_url(u) == want for u in await db.scalars(q))


class SourceIn(_M):
    name: str = Field(min_length=2, max_length=100)
    url: str = Field(max_length=500)

    @field_validator("url")
    @classmethod
    def _u(cls, v: str) -> str:
        return _feed_url(v)


class SourcePatch(_M):
    enabled: bool | None = None
    name: str | None = Field(default=None, min_length=2, max_length=100)
    url: str | None = Field(default=None, max_length=500)

    @field_validator("url")
    @classmethod
    def _u(cls, v: str | None) -> str | None:
        return _feed_url(v) if v is not None else v


@router.post("/admin/news/sources")
async def add_source(body: SourceIn, admin: Admin, db: Db) -> dict:
    """A feed of one's own. Two admins (or a double click) adding the same address at once get one source and a 409,
    not two sources or a 500: the unique index on the address of added sources decides (migration 0005; the check in the
    statement covers the built-in addresses, which the index leaves out)."""
    if await _same_feed(db, body.url):
        raise api_error(409, "news_source_exists")
    sid, key = uuid.uuid4(), f"custom-{uuid.uuid4().hex[:12]}"
    values = select(
        literal(sid, NewsSource.id.type), literal(key), literal(body.name), literal(body.url), literal(""), literal(False), literal(True), literal(0), literal(datetime.now(UTC), NewsSource.created_at.type)
    ).where(~exists().where(NewsSource.url == body.url))
    cols = ["id", "key", "name", "url", "site", "builtin", "enabled", "failures", "created_at"]
    try:
        res = await db.execute(pg_insert(NewsSource).from_select(cols, values).on_conflict_do_nothing(index_elements=["url"], index_where=~NewsSource.builtin))
        if res.rowcount:
            audit.record(db, admin, "source.created", audit.target("news_source", sid, body.name), {"url": body.url})
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise api_error(409, "news_source_exists") from exc
    if not res.rowcount:
        raise api_error(409, "news_source_exists")
    s = await db.get(NewsSource, sid)
    assert s is not None
    return _source_out(s, 0)


@router.patch("/admin/news/sources/{sid}")
async def patch_source(sid: uuid.UUID, body: SourcePatch, admin: Admin, db: Db) -> dict:
    s = await db.get(NewsSource, sid)
    if s is None:
        raise api_error(404, "not_found")
    changes = body.model_dump(exclude_unset=True)
    if s.builtin and ({"name", "url"} & set(changes)):
        raise api_error(409, "news_source_builtin")  # built-in sources keep the address the code knows
    if changes.get("url") and changes["url"] != s.url and await _same_feed(db, changes["url"], other_than=s.id):
        raise api_error(409, "news_source_exists")
    moved, switched_on = bool(changes.get("url")) and changes["url"] != s.url, bool(changes.get("enabled")) and not s.enabled
    before = {"name": s.name, "url": s.url, "enabled": s.enabled}
    for k, v in changes.items():
        if v is not None:
            setattr(s, k, v)
    if moved:
        s.etag = s.last_modified = s.next_fetch_at = None
        s.logo = s.logo_type = s.logo_checked_at = None
    if changes.get("enabled") is not None:
        s.switched_at = datetime.now(UTC)  # an admin's choice – a later change of the built-in default leaves it alone
    if moved or switched_on:
        # asked in the next round, as a new feed: no pause or error of before, its first fetch the baseline again
        s.next_fetch_at, s.failures, s.error, s.primed_at = None, 0, None, None
    # the same host, another path or query: the URL logged as changed only (audit.diff – both look the same once cleaned)
    if delta := audit.diff(before, {"name": s.name, "url": s.url, "enabled": s.enabled}):
        audit.record(db, admin, "source.changed", audit.target("news_source", s.id, s.name), {"changes": delta, "builtin": s.builtin})
    try:
        await db.commit()
    except IntegrityError as exc:  # another admin moved a source to that address at the same moment (unique index)
        await db.rollback()
        raise api_error(409, "news_source_exists") from exc
    return _source_out(s, (await source_counts(db)).get(s.id, 0))


@router.delete("/admin/news/sources/{sid}")
async def delete_source(sid: uuid.UUID, admin: Admin, db: Db) -> dict:
    s = await db.get(NewsSource, sid)
    if s is None:
        raise api_error(404, "not_found")
    if s.builtin:
        raise api_error(409, "news_source_builtin")  # switched off instead – it would come back with the next start
    audit.record(db, admin, "source.deleted", audit.target("news_source", s.id, s.name), {"url": s.url})
    await forget_source(db, s)
    await db.delete(s)
    await db.commit()
    return {"ok": True}


async def forget_source(db: AsyncSession, s: NewsSource) -> None:
    """Before a source is deleted: its stories that other sources carry too stay (the first of those takes them over);
    stories of others no longer name it; the notification rules and the desktop choices no longer list it. A rule or a
    desktop choice that listed only this source would mean "all sources" without it – a rule then stops sending news
    (its other kinds go on; with none left it is switched off), a desktop choice is switched off."""
    sid = str(s.id)
    names = dict((await db.execute(select(NewsSource.id, NewsSource.name))).all())
    # its own stories carried by nobody else go with it (ON DELETE CASCADE, its news_item_sources rows too) – not loaded
    shared = or_(and_(NewsItem.source_id == s.id, news_svc._also(None, enabled=False)), news_svc._also([s.id], enabled=False))
    for item in await db.scalars(select(NewsItem).where(shared)):
        # the further sources in the order they came, without the one that goes
        others = [x for x in await db.scalars(select(NewsItemSource.source_id).where(NewsItemSource.item_id == item.id).order_by(NewsItemSource.n)) if x != s.id]
        also = [n for n in (item.also_in or []) if n != s.name or s.name in {names[x] for x in others}]
        if item.source_id == s.id:
            owner = others.pop(0)  # carried by another source (the query above): it takes the story over
            item.source_id = owner
            await db.execute(delete(NewsItemSource).where(NewsItemSource.item_id == item.id, NewsItemSource.source_id == owner))
            if names[owner] not in {names[x] for x in others}:
                also = [n for n in also if n != names[owner]]
        item.also_in = also
    await db.flush()  # before the source's DELETE: what it takes with it is only its own
    for rule in await db.scalars(select(NotifyRule)):
        if sid not in (rule.sources or []):
            continue
        rule.sources = [x for x in rule.sources if x != sid]
        if not rule.sources:
            kinds = [k for k in (rule.kinds or ["news"]) if k != "news"]
            if kinds:
                rule.kinds = kinds
            else:
                rule.enabled = False
    for user in await db.scalars(select(User)):
        prefs = dict(user.desktop or {})
        if sid not in (prefs.get("sources") or []):
            continue
        prefs["sources"] = [x for x in prefs["sources"] if x != sid]
        if not prefs["sources"]:
            prefs["enabled"] = False
        user.desktop = prefs


@router.post("/admin/news/fetch")
async def fetch_now(request: Request, admin: Admin, db: Db) -> dict:
    """Ask the background loop to fetch now – every switched-on source not pausing after a refusal, each host once a
    minute. At most once a minute."""
    if not (await news_svc.config(db)).get("enabled"):
        raise api_error(409, "news_off")
    if time.monotonic() - limits.manual_at < 60:
        raise api_error(429, "rate_limited")
    limits.manual_at = time.monotonic()
    request.app.state.force()
    return {"ok": True}


class TestIn(_M):
    url: str = Field(max_length=500)

    @field_validator("url")
    @classmethod
    def _u(cls, v: str) -> str:
        return _feed_url(v)


@router.post("/admin/news/test")
async def test_source(body: TestIn, admin: Admin) -> dict:
    """Fetch and read a feed address once (before adding it): how many entries, the newest title. One test every few
    seconds."""
    if time.monotonic() - limits.test_at < 3:
        raise api_error(429, "rate_limited")
    limits.test_at = time.monotonic()
    try:
        got = await news_svc.download(body.url, proxy=get_config().proxy, verify=tls_verify())
        if got.status >= 400:
            raise news_svc.http_error(got.status)
        # parsing and reading off the event loop – a hostile feed must not hold every other request
        entries, _ = await asyncio.to_thread(news_svc.parse_feed, got.body)
        now = datetime.now(UTC)
        stories = await asyncio.to_thread(lambda: [s for s in (news_svc.story(e, now) for e in entries) if s])
    except news_svc.NewsError as exc:
        return {"ok": False, "error": exc.category, "detail": exc.detail}
    except Exception as exc:  # noqa: BLE001 - whatever the feed sends: an answer, not a 500
        return {"ok": False, "error": "format", "detail": type(exc).__name__}
    return {"ok": bool(stories), "entries": len(stories), "newest": stories[0]["title"] if stories else None, "error": None if stories else "empty"}
