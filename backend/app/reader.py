"""Reading: what a person has read (News and Vendor News), what they muted for a while, their saved views.

**Read state – a watermark plus a sparse set.** Per person one row (reader_state) says "everything that arrived up to
here is read": a news story by its arrival number (news_items.seq – the cursor of desktop and push notifications, which
becomes visible in order; a story without one by its arrival time, news_at), a Vendor News finding by the arrival time
of its newest event (vendor_at). On top of it a sparse set of single marks: news_reads / vendor_reads hold a row only
where the watermark and the age rule do not decide already – read after the watermark, or "unread again" (`unread`)
below it. Whatever arrived more than AUTO_READ ago counts as read without any row. So:

    unread(item) = mark.unread                                   if a mark exists and says unread
                 = False                                         if a mark exists and says read (and is not older than
                                                                 the item's last arrival – Vendor News)
                 = arrived > watermark and arrived > now - AUTO_READ   otherwise

No row (an account made after the upgrade): read up to the account's creation – nobody starts with thousands of unread
stories. "Alle gelesen" without a filter moves the watermark (one row written, the marks below it deleted); with a filter
it writes marks for the unread ones of that filter – at most what arrived within AUTO_READ, never ids from the browser.

The numbers are cheap however many stories and people there are: a count is bounded by AUTO_READ (the arrival index,
ix_news_items_fetched) plus the person's own "unread again" marks; the marks of a person stay few (the prune drops what
the watermark or the age covers). Vendor News counts in memory over the cached product views (as the sidebar's badge
always did) with one query for the recent events and one for the person's marks. Nothing is written by a GET.

**Muted** (person_mutes): a catalogue product or one CVE until a time – that person's own deliveries (app/personal.py)
leave it out, their lists dim or hide it, their unread numbers skip it. Nobody else's, never a team channel or an admin's
rule. A finding or story counts as muted when its product is muted or ALL of its CVEs are (an advisory on five CVEs
stays when one of them is muted). A watched CVE that is muted is silent too – both are the person's own choice, the
newer one wins until it ends. A muted product's KEV ("now exploited") is not delivered either, but the list shows it
with a badge even while muted ones are hidden – an exploited vulnerability never disappears from sight.

**Saved views** (saved_views): the raw query string of News or Vendor News under a name, per person – unknown
parameters are kept (a parameter renamed later must not break a view); the page validates what it reads.
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qsl, urlencode

from sqlalchemy import and_, cast, delete, func, literal, or_, select, tuple_
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app import db as dbm
from app.models import NewsItem, NewsRead, PersonMute, ReaderState, SavedView, User, VendorEvent, VendorFollow, VendorRead

AUTO_READ = timedelta(days=30)  # older than this (by arrival): read without a mark
RELEVANT = ("affected", "possible", "service", "unversioned")  # the findings the cards and the badge count
MUTE_KINDS = ("product", "cve")
MUTE_MAX = timedelta(days=366)
VIEW_PAGES = ("news", "vendor")
VIEW_MAX = 30
NAME_MAX = 60
QUERY_MAX = 2000
# the drawer of a story or product is no filter: never stored in a view – nor a notification's stories (`ids`)
VIEW_DROP = frozenset({"story", "product", "finding", "view", "ids"})
CHUNK = 5000
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def now_utc() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------- watermarks


@dataclass
class Marks:
    news_seq: int
    news_at: datetime
    vendor_at: datetime


async def seq_at(db: AsyncSession, at: datetime) -> int:
    """The highest arrival number among the stories stored up to `at` – the highest, not the one of the latest
    fetched_at: numbers are handed out at commit, so they need not follow fetched_at, and a new account would then see
    a few old stories as unread."""
    q = select(func.max(NewsItem.seq)).where(NewsItem.fetched_at <= at)
    return int(await db.scalar(q) or 0)


async def marks(db: AsyncSession, user: User) -> Marks:
    """The person's watermarks – without a row (or a value of it) those of the account's creation. Nothing is written."""
    row = await db.scalar(select(ReaderState).where(ReaderState.user_id == user.id))
    born = user.created_at or EPOCH
    news_seq = row.news_seq if row is not None and row.news_seq is not None else await seq_at(db, born)
    news_at = row.news_at if row is not None and row.news_at is not None else born
    vendor_at = row.vendor_at if row is not None and row.vendor_at is not None else born
    return Marks(news_seq, news_at, vendor_at)


async def set_marks(db: AsyncSession, user_id: uuid.UUID, **values) -> None:
    """Raise a watermark (never lowers one: two tabs' "Alle gelesen" in any order end at the higher one)."""
    now = now_utc()
    base = {"user_id": user_id, "news_seq": None, "news_at": None, "vendor_at": None, "updated_at": now}
    stmt = pg_insert(ReaderState).values(**(base | values))
    up: dict = {"updated_at": now}
    for k in values:
        col = getattr(ReaderState, k)
        up[k] = func.greatest(func.coalesce(col, stmt.excluded[k]), stmt.excluded[k])
    await db.execute(stmt.on_conflict_do_update(index_elements=["user_id"], set_=up))


# ---------------------------------------------------------------- mutes


@dataclass
class Mutes:
    products: dict[str, datetime] = field(default_factory=dict)
    cves: dict[str, datetime] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.products or self.cves)

    def all_cves(self, cves: list[str] | None) -> bool:
        cs = [str(c).upper() for c in cves or []]
        return bool(cs) and all(c in self.cves for c in cs)

    def finding(self, product: str, cves: list[str] | None) -> bool:
        return product in self.products or self.all_cves(cves)

    def event(self, kind: str, product: str | None, scope: str | None, data: dict | None) -> bool:
        """A Vendor News event muted for this person: a watched CVE's event by its CVE; a product's event (a
        vulnerability, a version, an EOL, an advisory change) by its product, or when all of its CVEs are muted."""
        if not self:
            return False
        if kind == "watch":
            cve = (scope or "")[len("watch:") :] if (scope or "").startswith("watch:") else str((data or {}).get("cve") or "")
            return cve.upper() in self.cves
        if product and product in self.products:
            return True
        return kind in ("vuln", "change") and self.all_cves((data or {}).get("cves"))


def _active(now: datetime):  # noqa: ANN202
    return PersonMute.until > now


async def mutes_of(db: AsyncSession, user_id: uuid.UUID, now: datetime | None = None) -> Mutes:
    return (await mutes_for(db, [user_id], now)).get(user_id, Mutes())


async def mutes_for(db: AsyncSession, user_ids, now: datetime | None = None) -> dict[uuid.UUID, Mutes]:  # noqa: ANN001
    """The running mutes of these people (expired ones are ignored until the prune deletes them)."""
    now = now or now_utc()
    ids = sorted(set(user_ids))
    out: dict[uuid.UUID, Mutes] = {}
    for i in range(0, len(ids), CHUNK):
        q = select(PersonMute.user_id, PersonMute.kind, PersonMute.key, PersonMute.until).where(PersonMute.user_id.in_(ids[i : i + CHUNK]), _active(now))
        for uid, kind, key, until in await db.execute(q):
            m = out.setdefault(uid, Mutes())
            (m.products if kind == "product" else m.cves)[key] = until
    return out


async def muted_events(db: AsyncSession, pairs: list[tuple[uuid.UUID, uuid.UUID]]) -> set[tuple[uuid.UUID, uuid.UUID]]:
    """Of these (event, person) pairs the ones the person muted. Only people with a running mute cost a lookup of
    their events – without any mute this is one small query."""
    if not pairs:
        return set()
    mutes = await mutes_for(db, {u for _, u in pairs})
    if not mutes:
        return set()
    evs = sorted({e for e, u in pairs if u in mutes})
    info: dict[uuid.UUID, tuple] = {}
    for i in range(0, len(evs), CHUNK):
        q = select(VendorEvent.id, VendorEvent.kind, VendorEvent.product, VendorEvent.scope, VendorEvent.data).where(VendorEvent.id.in_(evs[i : i + CHUNK]))
        for eid, kind, product, scope, data in await db.execute(q):
            info[eid] = (kind, product, scope, data)
    return {(e, u) for e, u in pairs if u in mutes and e in info and mutes[u].event(*info[e])}


def news_muted(m: Mutes):  # noqa: ANN201
    """SQL: the story names CVEs and all of them are muted (None: nothing muted – no condition)."""
    if not m.cves:
        return None
    return and_(NewsItem.cves != cast(literal("[]"), JSONB), NewsItem.cves.op("<@")(cast(literal(json.dumps(sorted(m.cves))), JSONB)))


# ---------------------------------------------------------------- news


def news_read_mark(user_id: uuid.UUID):  # noqa: ANN201
    """The person's mark of a story, outer-joined: (alias, on-clause)."""
    r = aliased(NewsRead)
    return r, and_(r.item_id == NewsItem.id, r.user_id == user_id)


def news_fresh(m: Marks, now: datetime):  # noqa: ANN201
    """SQL: arrived after the watermark and within AUTO_READ (without a mark: unread)."""
    # never NULL (a NOT of it must hold too): a story without an arrival number by its arrival time
    after = or_(and_(NewsItem.seq.is_not(None), NewsItem.seq > m.news_seq), and_(NewsItem.seq.is_(None), NewsItem.fetched_at > m.news_at))
    return and_(NewsItem.fetched_at > now - AUTO_READ, after)


def news_unread(r, m: Marks, now: datetime):  # noqa: ANN001, ANN201
    """SQL, never NULL: the story is unread for the person whose mark `r` is outer-joined."""
    return or_(func.coalesce(r.unread, False).is_(True), and_(r.item_id.is_(None), news_fresh(m, now)))


async def news_unread_count(db: AsyncSession, user_id: uuid.UUID, m: Marks, where: list, now: datetime, joins) -> int:  # noqa: ANN001
    """Unread stories matching `where` – two bounded counts instead of one OR the planner cannot index: the fresh ones
    without a mark (the arrival index, AUTO_READ back) and the person's own "unread again" marks."""
    r, on = news_read_mark(user_id)
    a = joins(select(func.count()).select_from(NewsItem)).outerjoin(r, on).where(*where, r.item_id.is_(None), news_fresh(m, now))
    b = joins(select(func.count()).select_from(r).join(NewsItem, NewsItem.id == r.item_id)).where(*where, r.user_id == user_id, r.unread.is_(True))
    return int(await db.scalar(a) or 0) + int(await db.scalar(b) or 0)


async def news_mark(db: AsyncSession, user_id: uuid.UUID, item_id: uuid.UUID, *, read: bool) -> None:
    """One story read or unread again – one row (a read mark the watermark covers goes with the prune)."""
    now = now_utc()
    stmt = pg_insert(NewsRead).values(user_id=user_id, item_id=item_id, read_at=now, unread=not read)
    await db.execute(stmt.on_conflict_do_update(index_elements=["user_id", "item_id"], set_={"read_at": now, "unread": not read}))


async def news_read_all(db: AsyncSession, user: User, where: list, joins, *, upto: int, everything: bool) -> int:  # noqa: ANN001
    """"Alle gelesen" for a list: what is unread in it and arrived up to `upto` (the list's arrival number when it was
    loaded) – a story arriving meanwhile stays unread. `everything` (no filter, nothing hidden): the watermark moves
    and the marks below it go; else marks for the unread ones of the filter (bounded by AUTO_READ and the person's own
    "unread again" marks). Idempotent: a second call finds nothing unread. Returns how many were unread."""
    now = now_utc()
    m = await marks(db, user)
    r, on = news_read_mark(user.id)
    upto_c = or_(NewsItem.seq <= upto, and_(NewsItem.seq.is_(None), NewsItem.fetched_at <= now))
    count = await news_unread_count(db, user.id, m, [*where, upto_c], now, joins)
    if not count:
        return 0
    if everything:
        await set_marks(db, user.id, news_seq=upto, news_at=now)
        # the marks the watermark covers now (read ones and "unread again" alike) – their stories arrived up to `upto`
        covered = select(NewsItem.id).where(NewsItem.seq <= upto)
        await db.execute(delete(NewsRead).where(NewsRead.user_id == user.id, NewsRead.item_id.in_(covered)))
        m = Marks(max(m.news_seq, upto), max(m.news_at, now), m.vendor_at)
    for _ in range(200):  # in chunks (bound variables per statement): what is still unread – usually nothing after a move
        ids = list(
            await db.scalars(joins(select(NewsItem.id).select_from(NewsItem)).outerjoin(r, on).where(*where, upto_c, news_unread(r, m, now)).limit(CHUNK))
        )
        if not ids:
            break
        stmt = pg_insert(NewsRead).values([{"user_id": user.id, "item_id": i, "read_at": now, "unread": False} for i in ids])
        await db.execute(stmt.on_conflict_do_update(index_elements=["user_id", "item_id"], set_={"read_at": now, "unread": False}))
    return count


# ---------------------------------------------------------------- Vendor News


def finding_of(key: str, scope: str | None) -> str | None:
    """The finding (advisory id) an event of kind "vuln" is about: its key is <scope>:<id>, exploited:<scope>:<id> or
    rated:<severity>:<scope>:<id> ("now rated higher" – the finding is unread again, as after "now exploited")."""
    from app.vendor import event_rest  # vendor imports much – only when asked

    rest = event_rest(key)
    if scope and rest.startswith(scope + ":"):
        return rest[len(scope) + 1 :] or None
    return None


@dataclass
class VendorReading:
    """One person's read state of Vendor News findings, read once per request."""

    arrivals: dict[tuple[str, str], datetime]
    reads: dict[tuple[str, str], tuple[datetime, bool]]
    floor: datetime
    mutes: Mutes

    def unread(self, product: str, finding: str) -> bool:
        k = (product, finding)
        mark = self.reads.get(k)
        if mark is not None and mark[1]:
            return True
        at = self.arrivals.get(k)
        if at is None or at <= self.floor:
            return False
        return mark is None or mark[0] < at

    def muted(self, product: str, f: dict) -> bool:
        return self.mutes.finding(product, f.get("cves"))

    def count(self, product: str, findings: list[dict]) -> int:
        """Unread findings of a product the card counts (not muted, of the kinds the card shows)."""
        if product in self.mutes.products:
            return 0
        return sum(1 for f in findings if f["status"] in RELEVANT and self.unread(product, f["id"]) and not self.muted(product, f))

    def count_all(self, product: str, findings: list[dict]) -> int:
        """Unread findings of a product including the muted ones – what "Alle N als gelesen" marks while "Stummgeschaltete
        zeigen" is on."""
        return sum(1 for f in findings if f["status"] in RELEVANT and self.unread(product, f["id"]))


async def vendor_reading(db: AsyncSession, user: User, products: list[str], now: datetime | None = None, m: Marks | None = None) -> VendorReading:
    """The arrivals of the findings of these products (their newest event within AUTO_READ that was notified – a
    baseline is read: it was there before), the person's marks of them and their mutes. Two small queries."""
    now = now or now_utc()
    m = m or await marks(db, user)
    floor = max(m.vendor_at, now - AUTO_READ)
    arrivals: dict[tuple[str, str], datetime] = {}
    reads: dict[tuple[str, str], tuple[datetime, bool]] = {}
    if products:
        q = select(VendorEvent.product, VendorEvent.key, VendorEvent.scope, VendorEvent.created_at).where(
            VendorEvent.kind == "vuln", VendorEvent.baseline.is_(False), VendorEvent.created_at > now - AUTO_READ, VendorEvent.product.in_(products)
        )
        for product, key, scope, at in await db.execute(q):
            fid = finding_of(key, scope)
            if fid is not None and at > arrivals.get((product, fid), EPOCH):
                arrivals[(product, fid)] = at
        rq = select(VendorRead.product, VendorRead.finding, VendorRead.read_at, VendorRead.unread).where(VendorRead.user_id == user.id, VendorRead.product.in_(products))
        reads = {(p, f): (at, un) for p, f, at, un in await db.execute(rq)}
    return VendorReading(arrivals, reads, floor, await mutes_of(db, user.id, now))


async def vendor_mark(db: AsyncSession, user_id: uuid.UUID, product: str, finding: str, *, read: bool, at: datetime | None = None) -> None:
    at = at or now_utc()
    stmt = pg_insert(VendorRead).values(user_id=user_id, product=product, finding=finding, read_at=at, unread=not read)
    await db.execute(stmt.on_conflict_do_update(index_elements=["user_id", "product", "finding"], set_={"read_at": at, "unread": not read}))


async def vendor_read_all(db: AsyncSession, user: User, views: list[tuple[str, list[dict]]], *, upto: datetime, everything: bool, skip_muted: bool = False) -> int:
    """"Alle gelesen" for the products of a list (or one product's drawer): every unread finding that arrived up to
    `upto`. `everything` (no filter, nothing hidden): the watermark moves and the marks go. `skip_muted`: muted findings
    (a muted CVE) stay unread – the list did not show them. Returns how many."""
    products = [p for p, _ in views]
    rd = await vendor_reading(db, user, products)
    todo = [
        (p, f["id"])
        for p, fs in views
        for f in fs
        if f["status"] in RELEVANT and rd.unread(p, f["id"]) and rd.arrivals.get((p, f["id"]), EPOCH) <= upto and not (skip_muted and rd.muted(p, f))
    ]
    if everything:
        await set_marks(db, user.id, vendor_at=upto)
        await db.execute(delete(VendorRead).where(VendorRead.user_id == user.id, or_(VendorRead.unread.is_(True), VendorRead.read_at <= upto)))
        rd = await vendor_reading(db, user, products)
        rest = [k for k in todo if rd.unread(*k)]  # "unread again" ones of findings without a recent event: a mark each
    else:
        rest = todo
    for i in range(0, len(rest), 1000):
        rows = [{"user_id": user.id, "product": p, "finding": f, "read_at": upto, "unread": False} for p, f in rest[i : i + 1000]]
        stmt = pg_insert(VendorRead).values(rows)
        await db.execute(stmt.on_conflict_do_update(index_elements=["user_id", "product", "finding"], set_={"read_at": upto, "unread": False}))
    return len(todo)


# ---------------------------------------------------------------- saved views


def clean_query(raw: str) -> str:
    """A page's query string as stored: without "?" and without the drawer's parameters, every other one kept as it
    came (also unknown ones) – re-encoded, so what is stored is always a well-formed query."""
    s = (raw or "").strip()
    if s.startswith("?"):
        s = s[1:]
    pairs = [(k, v) for k, v in parse_qsl(s, keep_blank_values=False) if k and k not in VIEW_DROP]
    return urlencode(pairs)[:QUERY_MAX]


def view_out(v: SavedView) -> dict:
    return {"id": str(v.id), "page": v.page, "name": v.name, "query": v.query, "default": v.is_default, "updated_at": v.updated_at.isoformat()}


# ---------------------------------------------------------------- the prune


async def prune(db: AsyncSession) -> dict[str, int]:
    """Hourly with the other prunes: expired mutes, and the read marks the watermark or the age cover (an "unread
    again" mark stays – it goes with its story, or when its product is no longer followed)."""
    now = now_utc()
    cut = now - AUTO_READ
    out = {"mutes": 0, "news": 0, "vendor": 0}
    out["mutes"] = (await db.execute(delete(PersonMute).where(PersonMute.until <= now))).rowcount or 0
    await db.commit()
    # read marks of stories older than AUTO_READ, or below the person's watermark – in batches (one short statement each)
    old = (
        select(NewsRead.user_id, NewsRead.item_id)
        .join(NewsItem, NewsItem.id == NewsRead.item_id)
        .outerjoin(ReaderState, ReaderState.user_id == NewsRead.user_id)
        .where(NewsRead.unread.is_(False), or_(NewsItem.fetched_at < cut, and_(ReaderState.news_seq.is_not(None), NewsItem.seq <= ReaderState.news_seq)))
        .limit(CHUNK)
        # a mark the person is changing right now ("Alle gelesen" writes many) is left for the next prune – no deadlock
        .with_for_update(of=NewsRead, skip_locked=True)
    )
    for _ in range(100):
        rows = (await db.execute(old)).all()
        if not rows:
            break
        await db.execute(delete(NewsRead).where(tuple_(NewsRead.user_id, NewsRead.item_id).in_([(r[0], r[1]) for r in rows])))
        await db.commit()
        out["news"] += len(rows)
    followed = select(VendorFollow.product)
    out["vendor"] = await dbm.delete_batched(db, VendorRead, or_(and_(VendorRead.unread.is_(False), VendorRead.read_at < cut), VendorRead.product.not_in(followed)))
    return out
