"""Treffer bestätigen: a Vendor News finding of a followed product assessed once, for everybody – "Nicht betroffen"
(a feature or configuration not in use: the PAN-OS Brotli advisory where Brotli is off), "Maßnahme umgesetzt" (a
workaround or mitigation in place), "Risiko akzeptiert" (with a reason, always). Muting (app/reader.py) is a person's
own and ends by itself after a while; a confirmation is the installation's assessment and stays – until somebody
undoes it, or the finding changes so that the assessment no longer fits.

Who: admins always; while Teams is on also the members of a team the product is assigned to – the same people who may
confirm its versions ("Versionen prüfen", catalog_care.confirmable: a team's product as "Mein Team" shows it, the
per-person routing included). Everybody else sees it read-only, the API refuses them (403).

**What it does while it stands** – the finding counts as handled: not in the numbers that mean "needs attention" (the
cards, the product's state, the sidebar badge, the unread numbers, the team's weekly review, API v1's counts) and no
notification about it any more (`held`: the rules' channels, the personal ways – an event made while it stood is never
sent later either, also not when it is undone). It stays visible: dimmed in the drawer with who, when and why; hidden in
the overview's lists unless "Mit Bestätigten" is on.

**It lapses by itself** (`check`, in every evaluation of the product's events – before its events are made, so the
event that brings the change goes out) when the finding changes materially: now exploited (KEV, the vendor, EUVD), rated
higher, a CVE added, more versions entered affected (or more surely affected) than before – a version added later, a
wider affected range; compared by the verdicts, not the versions' text (lapse_reason) –, the advisory withdrawn
(vendor.drop_advisories), its record now grouped under another leading record ("regrouped"). A new fixed version alone is no reason. A
lapsed confirmation stays as a row (ended_at, ended_reason) – the drawer says "Bestätigung aufgehoben: jetzt
ausgenutzt" for a while –, an audit entry (vendor.finding_confirm_lapsed) is written and the event of that change says
so. The events of the last LAPSE_GRACE before the lapse are let through: the advisory change that caused it (a KEV
listing, a new CVE) is often made by the round before the evaluation sees it.

**Which events are held.** Each period a confirmation stood is a row of its own. A period holds the events of its
finding made from the end of the finding's previous period (the first one: from the beginning – an event made before the
confirmation and still waiting on a channel stays unsent, as the personal ways skip it) up to its end; while it stands,
all of them. So the time between two periods, when none stood, is held by the next period: an event made then that
still waits on a channel when the finding is confirmed again stays unsent, like one made before the first
confirmation (what went out in between went out). Its finding's events are its vulnerability
events (by their key) and the advisory changes of every record it groups – its leading advisory and the NVD, cvelistV5
and OSV records of its CVEs (vendor_confirm_records: one index lookup per event). A watched CVE's events (kind "watch",
app/cve_watch.py) are the watcher's own and still come.

A finding is known by its product and its id – the advisory id the drawer uses (`?finding=`, reader.finding_of). When
the group's leading record changes (the vendor's advisory arrives after NVD's record) the finding gets a new id: the old
confirmation ends ("regrouped", check) and the finding counts again – the safe way round; it never stands on, unseen,
holding the new finding's changes."""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, case, delete, exists, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit
from app import db as dbm
from app.models import User, VendorConfirm, VendorConfirmRecord, VendorEvent, VendorFollow
from app.vendor_match import ORDER

STATUSES = ("not_affected", "mitigated", "accepted")
NOTE_MAX = 500
NOTE_REQUIRED = frozenset({"accepted"})  # "Risiko akzeptiert" only with a reason
REASONS = ("undone", "exploited", "severity", "cves", "verdict", "withdrawn", "regrouped")
CONCERNS = frozenset({"affected", "possible", "service", "unversioned"})  # a version's verdict that needs attention
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)  # a finding's first period holds from the beginning
LAPSE_GRACE = timedelta(days=1)  # events made this long before a lapse are let through (the change that caused it)
LAPSED_SHOWN = timedelta(days=30)  # "Bestätigung aufgehoben: …" in the drawer this long
_gen = [0]  # every change of a confirmation (caches of numbers that leave confirmed findings out: api_v1)


def generation() -> int:
    return _gen[0]


def changed() -> None:
    """After the commit of a change: a request between the change and its commit must not cache the old state under the
    new generation. The notification round looks at everything again at once (an undo or a lapse lets events through
    – they must not wait for its full look)."""
    from app import notify

    _gen[0] += 1
    notify.changed()


def now_utc() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------- the facts and the lapse


CVE_RECORDS = ("nvd", "cvelist", "osv")  # the records about one CVE a finding groups (vendor.CVE_SOURCES)


def members_of(f: dict) -> list[str]:
    """The ids of the records a finding groups: its leading advisory, the CVE records of its CVEs (nvd:, cvelist:, osv:
    <CVE> – whether stored or not) and the others it names. A revision of any of them is an advisory change of this
    finding (held while it stands)."""
    cves = sorted({str(c).upper() for c in f.get("cves") or []})
    also = [f"{a.get('source')}:{a.get('ident')}" for a in f.get("also") or [] if a.get("source") and a.get("ident")]
    return sorted({str(f["id"]), *also, *(f"{s}:{c}" for s in CVE_RECORDS for c in cves)})


def facts_of(f: dict) -> dict:
    """What a confirmation is made on: severity, exploited, the CVEs and each version's verdict. Not the fixed versions
    (a fix becoming available changes nothing about the assessment), not the texts, not EPSS. `members`: the records it
    groups – not compared (a new CVE is), only used to hold their advisory changes."""
    return {
        "severity": str(f.get("severity") or "info"),
        "exploited": bool(f.get("exploited")),
        "cves": sorted({str(c).upper() for c in f.get("cves") or []}),
        "versions": {str(r.get("version") or "*"): str(r.get("status")) for r in f.get("versions") or []},
        "members": members_of(f),
    }


# the verdicts that need attention, the most certain first: "how many versions are at least this concerned"
LEVELS = sorted(CONCERNS, key=lambda s: -ORDER.get(s, 0))


def _concerned(statuses) -> list[int]:  # noqa: ANN001
    """Per level (LEVELS) how many versions have a verdict at least that certain."""
    ranks = [ORDER.get(st, 0) for st in statuses if st in CONCERNS]
    return [sum(1 for r in ranks if r >= ORDER.get(level, 0)) for level in LEVELS]


def lapse_reason(old: dict, f: dict) -> str | None:
    """Why a confirmation made on `old` (facts_of) no longer fits the finding `f` – None: it still does.

    The versions are compared by their verdicts, not by their text: it lapses when more versions are affected (or more
    certainly affected) than when it was confirmed – a version added later that is affected, an affected range widened
    to a version entered, "possibly" become "affected". A version edited to another one with the same verdict (11.2.4-h23
    → 11.2.4-h25, both affected), a version removed or one no longer affected is no reason: nothing more is exposed than
    what was assessed."""
    if bool(f.get("exploited")) and not old.get("exploited"):
        return "exploited"
    if SEV_RANK.get(str(f.get("severity") or "info"), 0) > SEV_RANK.get(str(old.get("severity") or "info"), 0):
        return "severity"
    if {str(c).upper() for c in f.get("cves") or []} - {str(c).upper() for c in old.get("cves") or []}:
        return "cves"
    now = _concerned(str(r.get("status")) for r in f.get("versions") or [])
    was = _concerned((old.get("versions") or {}).values())
    if any(n > w for n, w in zip(now, was, strict=True)):
        return "verdict"
    return None


# ---------------------------------------------------------------- reading


def out(c: VendorConfirm | dict) -> dict:
    """As the UI and API v1 show it."""
    g = c.get if isinstance(c, dict) else lambda k: getattr(c, k)
    at = g("confirmed_at")
    return {"status": g("status"), "note": g("note") or "", "by": g("user_name") or "", "at": at.isoformat() if at else None}


def lapsed_out(c: dict) -> dict:
    return {"status": c["status"], "reason": c["ended_reason"], "at": c["ended_at"].isoformat(), "by": c.get("user_name") or ""}


_COLS = (
    VendorConfirm.product,
    VendorConfirm.finding,
    VendorConfirm.status,
    VendorConfirm.note,
    VendorConfirm.user_name,
    VendorConfirm.confirmed_at,
    VendorConfirm.facts,
    VendorConfirm.ended_at,
    VendorConfirm.ended_reason,
)


@dataclass
class Standing:
    """The confirmations of some products, read once per request: the standing ones and those that lapsed lately."""

    rows: dict[tuple[str, str], dict] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return any(c["ended_at"] is None for c in self.rows.values())

    def of(self, product: str, f: dict) -> dict | None:
        """The confirmation that stands for this finding now – none when there is none, it ended, or the finding
        changed since (lapsed, even before the next evaluation writes it down)."""
        c = self.rows.get((product, f["id"]))
        if c is None or c["ended_at"] is not None or lapse_reason(c["facts"], f) is not None:
            return None
        return c

    def lapsed(self, product: str, finding: str) -> dict | None:
        """A confirmation of this finding that lapsed by itself lately (not one undone by hand)."""
        c = self.rows.get((product, finding))
        return c if c is not None and c["ended_at"] is not None and c["ended_reason"] not in (None, "undone") else None

    def skip(self, product: str, fs: list[dict]) -> frozenset[str]:
        """The ids of the findings of a product that stand confirmed (none: the cached numbers apply as they are)."""
        if not any(p == product and c["ended_at"] is None for (p, _), c in self.rows.items()):
            return frozenset()
        return frozenset(f["id"] for f in fs if self.of(product, f) is not None)


async def standing(db: AsyncSession, products: list[str] | set[str] | None = None, now: datetime | None = None) -> Standing:
    """The confirmations of these products (None: all): standing ones and those lapsed within LAPSED_SHOWN. One query."""
    now = now or now_utc()
    # per finding the standing row – else the latest that ended within LAPSED_SHOWN (shown only when it lapsed by itself,
    # not when it was undone; an older lapse before a later undone confirmation is no news any more)
    q = select(*_COLS).where(or_(VendorConfirm.ended_at.is_(None), VendorConfirm.ended_at > now - LAPSED_SHOWN))
    if products is not None:
        keys = sorted(set(products))
        if not keys:
            return Standing()
        q = q.where(VendorConfirm.product.in_(keys))
    rows: dict[tuple[str, str], dict] = {}
    for p, fid, st, note, name, at, facts, ended, why in await db.execute(q):
        had = rows.get((p, fid))
        if had is not None and (had["ended_at"] is None or (ended is not None and ended <= had["ended_at"])):
            continue
        rows[(p, fid)] = {"status": st, "note": note, "user_name": name, "confirmed_at": at, "facts": facts or {}, "ended_at": ended, "ended_reason": why}
    return Standing(rows)


# ---------------------------------------------------------------- the events it holds back


def _record_of_event():  # noqa: ANN202
    """SQL: the record an event is about – an advisory change's advisory, a vulnerability event's finding (the end of its
    key after its scope: <scope>:<id>, exploited:<scope>:<id>, rated:<severity>:<scope>:<id>); other kinds none."""
    sc = VendorEvent.scope
    finding = func.substr(VendorEvent.key, func.strpos(VendorEvent.key, sc.concat(":")) + func.length(sc) + 1)
    return case(
        (VendorEvent.kind == "change", VendorEvent.data["advisory"].as_string()),
        (and_(VendorEvent.kind == "vuln", sc.is_not(None)), finding),
        else_=None,
    )


def held(*, standing_only: bool = False):  # noqa: ANN201
    """SQL: the Vendor News event is about a confirmed finding – one that stands now, or one whose period held it when it
    ended (held_from … held_until): never sent, also not after the confirmation ended. One index lookup per event: its
    product and record in vendor_confirm_records (the records the finding groups, the finding itself among them).
    `standing_only`: only a confirmation that stands now – what a summary of the past shows (the weekly review lists a
    finding again once it is undone)."""
    c, r = VendorConfirm, VendorConfirmRecord
    if standing_only:
        when = c.ended_at.is_(None)
    else:
        when = or_(c.ended_at.is_(None), and_(VendorEvent.created_at >= c.held_from, c.held_until.is_not(None), VendorEvent.created_at < c.held_until))
    return exists().where(r.product == VendorEvent.product, r.record == _record_of_event(), c.id == r.confirm_id, when)


async def held_events(db: AsyncSession, ids: list[uuid.UUID] | set[uuid.UUID]) -> set[uuid.UUID]:
    """Of these events the ones held back by a confirmation."""
    want = sorted(set(ids))
    got: set[uuid.UUID] = set()
    for i in range(0, len(want), 5000):
        got.update(await db.scalars(select(VendorEvent.id).where(VendorEvent.id.in_(want[i : i + 5000]), held())))
    return got


# ---------------------------------------------------------------- writing


def _name(user: User) -> str:
    return (user.display_name or user.username or "")[:200]


async def current(db: AsyncSession, product: str, finding: str) -> VendorConfirm | None:
    """The confirmation of a finding that stands (its row, locked for the change) – None: none stands."""
    q = select(VendorConfirm).where(VendorConfirm.product == product, VendorConfirm.finding == finding, VendorConfirm.ended_at.is_(None))
    return await db.scalar(q.with_for_update().execution_options(populate_existing=True))


async def confirm(db: AsyncSession, user: User, product: str, f: dict, status: str, note: str, now: datetime | None = None) -> VendorConfirm:
    """Confirm a finding as it is now – or change the one that stands (status, reason, facts; its period and what it
    holds go on). A confirmation made again after one ended is a new period, holding from the previous period's end:
    what was made in between and still waits on a channel stays unsent. Not committed; call changed() after the commit."""
    now = now or now_utc()
    values = {"status": status, "note": note, "user_id": user.id, "user_name": _name(user), "confirmed_at": now, "facts": facts_of(f)}
    c = await current(db, product, f["id"])
    if c is not None:
        for k, v in values.items():
            setattr(c, k, v)
        await db.flush()
        await _records(db, c.id, product, f)
        return c
    # a new period holds from where the previous one of this finding ended – what was made before and still waits on a
    # channel is held as well, and stays unsent when it ends (as the personal ways skip it) – the time between two
    # periods included
    prev = await db.scalar(select(func.max(VendorConfirm.ended_at)).where(VendorConfirm.product == product, VendorConfirm.finding == f["id"]))
    stmt = pg_insert(VendorConfirm).values(id=uuid.uuid4(), product=product, finding=f["id"], held_from=prev or EPOCH, **values)
    # two confirmations at the same moment: the second changes the one the first made (one standing per finding)
    up = stmt.on_conflict_do_update(index_elements=["product", "finding"], index_where=VendorConfirm.ended_at.is_(None), set_=values)
    cid = await db.scalar(up.returning(VendorConfirm.id))
    await _records(db, cid, product, f)
    return await db.get(VendorConfirm, cid, populate_existing=True)


async def _records(db: AsyncSession, cid: uuid.UUID, product: str, f: dict) -> None:
    """The records of the period (vendor_confirm_records) as the finding groups them now."""
    await db.execute(delete(VendorConfirmRecord).where(VendorConfirmRecord.confirm_id == cid))
    await db.execute(pg_insert(VendorConfirmRecord).values([{"confirm_id": cid, "record": r, "product": product} for r in members_of(f)]).on_conflict_do_nothing())


async def undo(db: AsyncSession, user: User, product: str, finding: str, now: datetime | None = None) -> VendorConfirm | None:
    """"Bestätigung aufheben": the finding counts and notifies again from now on. Not committed (changed() after the
    commit). None: none stands."""
    now = now or now_utc()
    c = await current(db, product, finding)
    if c is None:
        return None
    c.ended_at, c.held_until, c.ended_reason, c.ended_by = now, now, "undone", _name(user)
    return c


def _record_lapse(db: AsyncSession, c: VendorConfirm, reason: str, label: str, ident: str) -> None:
    details = {"finding": c.finding, "ident": ident, "status": c.status, "reason": reason, "confirmed_by": c.user_name}
    audit.record(db, audit.SYSTEM, "vendor.finding_confirm_lapsed", audit.target("product", c.product, label), details)


def _end(c: VendorConfirm, reason: str, now: datetime) -> None:
    """A lapse: what was made in the last LAPSE_GRACE is let through (the change that caused it)."""
    c.ended_at, c.held_until, c.ended_reason, c.ended_by = now, max(c.held_from, now - LAPSE_GRACE), reason, None


async def check(db: AsyncSession, product: dict, findings: list[dict], now: datetime | None = None) -> dict[str, str]:
    """The confirmations of this product that no longer fit its findings end now (with an audit entry each). Returns
    finding id → why, for the events made in the same evaluation. Not committed (the evaluation's transaction – changed()
    after its commit)."""
    now = now or now_utc()
    key = product["key"]
    # a row an undo or a new confirmation holds right now is left for the next evaluation (no lost update of theirs)
    q = select(VendorConfirm).where(VendorConfirm.product == key, VendorConfirm.ended_at.is_(None)).with_for_update(skip_locked=True)
    rows = list(await db.scalars(q.execution_options(populate_existing=True)))
    if not rows:
        return {}
    by_id = {f["id"]: f for f in findings}
    grouped: dict[str, dict] | None = None
    out_: dict[str, str] = {}
    for c in rows:
        f = by_id.get(c.finding)
        if f is None:
            # its record now belongs to a finding led by another one (NVD's record first, the vendor's advisory later):
            # the finding is a new one – it ends ("regrouped") and is looked at again rather than moved over, the new
            # leading record may say something else (another range, a workaround). Not shown at all (a source switched
            # off): nothing to compare with – it stays.
            if grouped is None:
                grouped = {r: x for x in findings for r in members_of(x)}
            f = grouped.get(c.finding)
            if f is None:
                continue
            why = "regrouped"
        else:
            why = lapse_reason(c.facts or {}, f)
        if why is None:
            continue
        _end(c, why, now)
        _record_lapse(db, c, why, str(product.get("label") or key), str(f.get("ident") or c.finding))
        out_[c.finding] = why
    return out_


async def withdrawn(db: AsyncSession, links: list[tuple[str, str]], labels: dict[str, str] | None = None, now: datetime | None = None) -> int:
    """Advisories withdrawn by their source (vendor.drop_advisories): (product, advisory id) – their confirmations end.
    Not committed (changed() after the commit)."""
    if not links:
        return 0
    now = now or now_utc()
    pairs = set(links)
    q = select(VendorConfirm).where(VendorConfirm.ended_at.is_(None), VendorConfirm.finding.in_(sorted({a for _, a in pairs})))
    rows = list(await db.scalars(q.with_for_update().execution_options(populate_existing=True)))
    n = 0
    for c in rows:
        if (c.product, c.finding) not in pairs:
            continue
        _end(c, "withdrawn", now)
        _record_lapse(db, c, "withdrawn", (labels or {}).get(c.product) or c.product, c.finding.partition(":")[2] or c.finding)
        n += 1
    return n


async def prune(db: AsyncSession) -> int:
    """The confirmations of products no longer followed (with the reads – reader.prune): a product followed again starts
    without them, as its events do."""
    n = await dbm.delete_batched(db, VendorConfirm, VendorConfirm.product.not_in(select(VendorFollow.product)))
    if n:
        changed()
    return n
