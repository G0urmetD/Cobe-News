"""The signed-in person's watched CVEs ("CVE beobachten", app/cve_watch.py): list, add, remove, the timeline of one,
the last visit ("new since"), "Alle beobachten" of a story or a finding (bulk) and "Gruppe nicht mehr beobachten"
(bulk-remove). Only the own rows – the path names a CVE, never a person; every statement is bound to the session's
account. At most cve_watch.MAX_PER_PERSON; a CVE id only (CVE-YYYY-NNNN…). Nothing is fetched from outside for a
watched CVE.

The origin of a watch (a story, a finding, manual) is named by the client and resolved here: the story must be one the
lists show (a switched-on source carries it), the finding one of a followed product, the CVE one that story or finding
names – the title kept with the watch comes from the database, never from the request. Personal actions: no audit
log (as for the single star)."""

import math
import time
import uuid
from collections import deque
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter
from pydantic import ConfigDict, Field, model_validator
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import cve_watch, personal, teams
from app import news as news_svc
from app import vendor as vendor_svc
from app.db import contains
from app.deps import Db, NoNul, Reader, api_error
from app.models import CveWatch, NewsItem, NewsSource, PersonNotify, StoryDetail, VendorFollow

router = APIRouter(prefix="/api/me/cve-watch", tags=["cve-watch"])

BULK_PER = 20  # "Alle beobachten" per person within BULK_WINDOW (each may check up to 500 CVEs)
BULK_WINDOW = 300.0
NAMED_SHOWN = 20  # CVEs named in a refusal
clock = time.monotonic  # tests move it on
_bulk_at: dict[uuid.UUID, deque[float]] = {}


def reset() -> None:
    _bulk_at.clear()


def _check_rate(user_id: uuid.UUID) -> None:
    now = clock()
    q = _bulk_at.setdefault(user_id, deque())
    while q and now - q[0] >= BULK_WINDOW:
        q.popleft()
    if len(q) >= BULK_PER:
        raise api_error(429, "watch_rate_limited", retry_after=max(1, math.ceil(BULK_WINDOW - (now - q[0]))))
    q.append(now)


class _Body(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class StoryOrigin(_Body):
    kind: Literal["story"]
    id: uuid.UUID


class FindingOrigin(_Body):
    kind: Literal["finding"]
    product: str = Field(min_length=1, max_length=200)
    advisory: str = Field(min_length=1, max_length=300)


class ManualOrigin(_Body):
    kind: Literal["manual"]


Origin = Annotated[StoryOrigin | FindingOrigin | ManualOrigin, Field(discriminator="kind")]
CveText = Annotated[str, Field(min_length=9, max_length=24)]


class WatchIn(_Body):
    cve: str = Field(min_length=9, max_length=24)
    origin: Origin | None = None  # none: typed on the list ("manual")


class BulkIn(_Body):
    cves: list[CveText] = Field(min_length=1, max_length=cve_watch.BULK_MAX)
    origin: Origin
    partial: bool = False  # more than fit: watch the first that do (the page asked the person first)


class BulkRemoveIn(_Body):
    """These CVEs – or one group of the list (its origin as the list names it)."""

    cves: list[CveText] | None = Field(default=None, min_length=1, max_length=cve_watch.MAX_PER_PERSON)
    group: Origin | None = None

    @model_validator(mode="after")
    def _one(self):  # noqa: ANN202
        if (self.cves is None) == (self.group is None):
            raise ValueError("cves or a group")
        return self


async def _story_origin(db: Db, sid: uuid.UUID) -> tuple[dict, set[str]]:
    """A story the lists show (a switched-on source carries it) – its title and the CVEs it names (its own and those of
    its details). Any other: 404, as an unknown one."""
    row = (await db.execute(select(NewsItem).join(NewsSource, NewsSource.id == NewsItem.source_id).where(NewsItem.id == sid, news_svc.visible()))).scalars().first()
    if row is None:
        raise api_error(404, "origin_not_found")
    named = {str(c).upper() for c in (row.cves or []) if isinstance(c, str)}
    det = await db.get(StoryDetail, row.id)
    if det is not None and det.status == "ok" and isinstance(det.data, dict):
        named |= {str(c).upper() for c in det.data.get("cves") or [] if isinstance(c, str)}
    return {"kind": "story", "ref": str(row.id), "title": row.title or ""}, named


async def _finding_origin(db: Db, product: str, advisory: str) -> tuple[dict, set[str]]:
    """A finding of a followed product (Vendor News, as the drawer shows it) – its title and its CVEs."""
    fol = await db.scalar(select(VendorFollow).where(VendorFollow.product == product))
    if fol is None:
        raise api_error(404, "origin_not_found")
    vs = (await vendor_svc.versions_of(db, [fol.id])).get(fol.id, [])
    view = await vendor_svc.product_view(db, fol, vs)
    x = next((y for y in view["findings"] if y["id"] == advisory), None)
    if x is None:
        raise api_error(404, "origin_not_found")
    label = view["product"].get("label") or product
    title = f"{label}: {x.get('ident') or ''} – {x.get('headline') or x.get('title') or ''}".strip(" –")
    named = {str(c).upper() for c in x.get("cves") or [] if isinstance(c, str)} | {str(x.get("ident") or "").upper()}
    return {"kind": "finding", "ref": x["id"], "product": product, "title": title}, named


async def _resolve(db: Db, origin, cves: list[str]) -> dict:  # noqa: ANN001
    """The origin as stored (title from the database). The CVEs must be ones it names – 422 otherwise."""
    if origin is None or isinstance(origin, ManualOrigin):
        return {"kind": "manual"}
    if isinstance(origin, StoryOrigin):
        out, named = await _story_origin(db, origin.id)
    else:
        out, named = await _finding_origin(db, origin.product, origin.advisory)
    foreign = [c for c in cves if c not in named]
    if foreign:
        raise api_error(422, "cve_not_in_origin", cves=foreign[:NAMED_SHOWN])
    return out


def _cve(value: str) -> str:
    c = cve_watch.normalize(value)
    if c is None:
        raise api_error(422, "invalid_cve")
    return c


async def _count(db: Db, user_id) -> int:  # noqa: ANN001
    return int(await db.scalar(select(func.count()).select_from(CveWatch).where(CveWatch.user_id == user_id)) or 0)


def _group(origin) -> dict:  # noqa: ANN001
    if isinstance(origin, StoryOrigin):
        return {"kind": "story", "id": str(origin.id)}
    if isinstance(origin, FindingOrigin):
        return {"kind": "finding", "product": origin.product, "advisory": origin.advisory}
    return {"kind": "manual"}


async def _notify(db: Db, user) -> dict:  # noqa: ANN001
    """Whether the notices can reach the person: Teams on (an admin allows the ways there), a way allowed and switched
    on. The list works without – then it is a reminder list, and the page says why nothing comes."""
    on = await teams.is_on(db)
    allowed = await personal.allowed(db)
    p = await db.get(PersonNotify, user.id)
    ways = {w: bool(p is not None and getattr(p, f"{w}_on") and allowed[w]) for w in personal.WAYS}
    reason = None if any(ways.values()) else "teams_off" if not on else "no_way_allowed" if not any(allowed.values()) else "no_way_on"
    return {"teams_on": on, "allowed": allowed, "ways": ways, "reason": reason}


@router.get("")
async def list_mine(user: Reader, db: Db) -> dict:
    """`seen_before`: the person's previous visit of the list (None: never) – what happened after it is new for them.
    Reading does not move it: the page says when it was seen (POST /seen), and keeps its marks for that visit. Each item
    carries its `product` (app/watch_product.py, worked out now) – the page groups by it; "Gruppe nicht mehr beobachten"
    of a product group sends its CVEs (bulk-remove with `cves`)."""
    seen = await db.scalar(select(PersonNotify.watch_seen_at).where(PersonNotify.user_id == user.id))
    return {
        "items": await cve_watch.listing(db, user.id),
        "limit": cve_watch.MAX_PER_PERSON,
        "notify": await _notify(db, user),
        "seen_before": seen.isoformat() if seen else None,
    }


@router.post("/seen")
async def seen_mine(user: Reader, db: Db) -> dict:
    """The person has seen their list now (the page, once per visit after it loaded)."""
    now = datetime.now(UTC)
    stmt = pg_insert(PersonNotify).values(
        user_id=user.id, kinds=list(personal.DEFAULT_KINDS), min_severity="info", state_email={}, state_desktop={}, state_teams={}, schedule={}, weekly_on=False, watch_seen_at=now
    )
    await db.execute(stmt.on_conflict_do_update(index_elements=[PersonNotify.user_id], set_={"watch_seen_at": now}))
    await db.commit()
    return {"seen_at": now.isoformat()}


@router.get("/ids")
async def ids_mine(user: Reader, db: Db) -> dict:
    """Just the CVE ids – for the stars next to CVEs on the other pages."""
    return {"cves": sorted(await db.scalars(select(CveWatch.cve).where(CveWatch.user_id == user.id)))}


@router.post("")
async def add_mine(body: WatchIn, user: Reader, db: Db) -> dict:
    """One CVE – with where it was watched from (the star of a story or a finding passes it; typed on the list: manual).
    Watched already: nothing changes, also not its origin (the first one stays)."""
    cve = _cve(body.cve)
    if await db.scalar(select(CveWatch.cve).where(CveWatch.user_id == user.id, CveWatch.cve == cve)):
        return {"cve": cve, "added": False}
    origin = await _resolve(db, body.origin, [cve])
    try:
        res = await cve_watch.add_many(db, user.id, [cve], origin)
    except cve_watch.LimitReached:
        raise api_error(409, "watch_limit", limit=cve_watch.MAX_PER_PERSON) from None
    return {"cve": cve, "added": bool(res["added"])}


@router.post("/bulk")
async def add_bulk(body: BulkIn, user: Reader, db: Db) -> dict:
    """"Alle beobachten": the CVEs of a story or a finding at once, all with that origin. More new ones than places
    left: 409 watch_limit with `free` and `wanted` – unless `partial` (the page asked "only K free – watch the first
    K?"): then the first K in the given order. Already watched ones keep their origin. At most BULK_PER calls per
    person in BULK_WINDOW seconds."""
    _check_rate(user.id)  # before any work
    cves = []
    for c in body.cves:
        n = cve_watch.normalize(c)
        if n is None:
            raise api_error(422, "invalid_cve")
        cves.append(n)
    cves = list(dict.fromkeys(cves))
    origin = await _resolve(db, body.origin, cves)
    try:
        res = await cve_watch.add_many(db, user.id, cves, origin, partial=body.partial)
    except cve_watch.LimitReached as e:
        raise api_error(409, "watch_limit", limit=cve_watch.MAX_PER_PERSON, free=e.free, wanted=e.wanted) from None
    return {**res, "limit": cve_watch.MAX_PER_PERSON, "count": await _count(db, user.id)}


@router.post("/bulk-remove")
async def remove_bulk(body: BulkRemoveIn, user: Reader, db: Db) -> dict:
    """These CVEs ("Alle nicht mehr beobachten" of a story) or one group of the list ("Gruppe nicht mehr beobachten" –
    the manual group holds the watches of unknown origin, too). Returns what went with its origin: the page's undo
    watches them again with it."""
    if body.cves is not None:
        cves = [n for c in body.cves if (n := cve_watch.normalize(c))]
        if len(cves) != len(body.cves):
            raise api_error(422, "invalid_cve")
        gone = await cve_watch.remove_many(db, user.id, cves=cves)
    else:
        gone = await cve_watch.remove_many(db, user.id, group=_group(body.group))
    return {"removed": gone}


@router.get("/{cve}/events")
async def events_mine(cve: str, user: Reader, db: Db) -> dict:
    """The timeline of a CVE the person watches (since they began, newest first) and how many stories name it – 404 for
    any other CVE, also one somebody else watches."""
    c = _cve(cve)
    out = await cve_watch.timeline(db, user.id, c)
    if out is None:
        raise api_error(404, "not_watched")
    # as the story list's search finds it (/?q=<CVE>): the folded text, switched-on sources
    where = [news_svc.visible(), NewsItem.search.like(contains(c))]
    out["stories"] = int(await db.scalar(select(func.count()).select_from(NewsItem).join(NewsSource, NewsSource.id == NewsItem.source_id).where(*where)) or 0)
    return out


@router.delete("/{cve}")
async def remove_mine(cve: str, user: Reader, db: Db) -> dict:
    c = _cve(cve)
    res = await db.execute(delete(CveWatch).where(CveWatch.user_id == user.id, CveWatch.cve == c))
    await db.commit()
    return {"cve": c, "removed": bool(res.rowcount)}
