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
higher, a CVE added, a version entered is affected (or more surely affected) where it was not – a version added later,
a wider affected range –, the advisory withdrawn (vendor.drop_advisories). A new fixed version alone is no reason. A
lapsed confirmation stays as a row (ended_at, ended_reason) – the drawer says "Bestätigung aufgehoben: jetzt
ausgenutzt" for a while –, an audit entry (vendor.finding_confirm_lapsed) is written and the event of that change says
so. The events of the last LAPSE_GRACE before the lapse are let through: the advisory change that caused it (a KEV
listing, a new CVE) is often made by the round before the evaluation sees it. Between a change and the next evaluation
the numbers already treat it as lapsed (`Standing.of` compares the facts on every read).

A finding is known by its product and its id – the advisory id the drawer uses (`?finding=`, reader.finding_of). When
the group's leading record changes (the vendor's advisory arrives after NVD's record) the finding gets a new id: the
old confirmation no longer matches and the finding counts again – the safe way round."""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit
from app import db as dbm
from app.models import User, VendorConfirm, VendorEvent, VendorFollow
from app.vendor_match import ORDER

STATUSES = ("not_affected", "mitigated", "accepted")
NOTE_MAX = 500
NOTE_REQUIRED = frozenset({"accepted"})  # "Risiko akzeptiert" only with a reason
REASONS = ("undone", "exploited", "severity", "cves", "verdict", "withdrawn")
CONCERNS = frozenset({"affected", "possible", "service", "unversioned"})  # a version's verdict that needs attention
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
LAPSE_GRACE = timedelta(days=1)  # events made this long before a lapse are let through (the change that caused it)
LAPSED_SHOWN = timedelta(days=30)  # "Bestätigung aufgehoben: …" in the drawer this long
_gen = [0]  # every change of a confirmation (caches of numbers that leave confirmed findings out: api_v1)


def generation() -> int:
    return _gen[0]


def changed() -> None:
    _gen[0] += 1


def now_utc() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------- the facts and the lapse


def facts_of(f: dict) -> dict:
    """What a confirmation is made on: severity, exploited, the CVEs and each version's verdict. Not the fixed versions
    (a fix becoming available changes nothing about the assessment), not the texts, not EPSS."""
    return {
        "severity": str(f.get("severity") or "info"),
        "exploited": bool(f.get("exploited")),
        "cves": sorted({str(c).upper() for c in f.get("cves") or []}),
        "versions": {str(r.get("version") or "*"): str(r.get("status")) for r in f.get("versions") or []},
    }


def lapse_reason(old: dict, f: dict) -> str | None:
    """Why a confirmation made on `old` (facts_of) no longer fits the finding `f` – None: it still does."""
    cur = facts_of(f)
    if cur["exploited"] and not old.get("exploited"):
        return "exploited"
    if SEV_RANK.get(cur["severity"], 0) > SEV_RANK.get(str(old.get("severity") or "info"), 0):
        return "severity"
    if set(cur["cves"]) - {str(c).upper() for c in old.get("cves") or []}:
        return "cves"
    was = old.get("versions") or {}
    for v, st in cur["versions"].items():
        if st not in CONCERNS:
            continue
        before = was.get(v)
        if before not in CONCERNS or ORDER.get(st, 0) > ORDER.get(before, 0):
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
    q = select(*_COLS).where(or_(VendorConfirm.ended_at.is_(None), and_(VendorConfirm.ended_reason != "undone", VendorConfirm.ended_at > now - LAPSED_SHOWN)))
    if products is not None:
        keys = sorted(set(products))
        if not keys:
            return Standing()
        q = q.where(VendorConfirm.product.in_(keys))
    rows = {}
    for p, fid, st, note, name, at, facts, ended, why in await db.execute(q):
        rows[(p, fid)] = {"status": st, "note": note, "user_name": name, "confirmed_at": at, "facts": facts or {}, "ended_at": ended, "ended_reason": why}
    return Standing(rows)


# ---------------------------------------------------------------- the events it holds back


def _of_event():  # noqa: ANN202
    """SQL: the confirmation row is about the event's finding – a vulnerability event by its key (<scope>:<id>, also
    "now exploited" and "now rated higher", which end with it as well), an advisory change by its advisory."""
    c = VendorConfirm
    tail = VendorEvent.scope.concat(":").concat(c.finding)
    by_key = and_(VendorEvent.kind == "vuln", VendorEvent.scope.is_not(None), func.right(VendorEvent.key, func.length(tail)) == tail)
    by_advisory = and_(VendorEvent.kind == "change", VendorEvent.data["advisory"].as_string() == c.finding)
    return and_(c.product == VendorEvent.product, or_(by_key, by_advisory))


def held():  # noqa: ANN201
    """SQL: the Vendor News event is about a confirmed finding – one that stands now, or one that stood when the event was
    made (held_from … held_until): never sent, also not after the confirmation ended."""
    c = VendorConfirm
    when = or_(c.ended_at.is_(None), and_(VendorEvent.created_at >= c.held_from, c.held_until.is_not(None), VendorEvent.created_at < c.held_until))
    return exists().where(_of_event(), when)


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


async def confirm(db: AsyncSession, user: User, product: str, f: dict, status: str, note: str, now: datetime | None = None) -> VendorConfirm:
    """Confirm (or change the confirmation of) a finding as it is now. Not committed. A confirmation made again after
    one ended keeps where the held events began: what was held then is never sent."""
    now = now or now_utc()
    values = {
        "product": product,
        "finding": f["id"],
        "status": status,
        "note": note,
        "user_id": user.id,
        "user_name": _name(user),
        "confirmed_at": now,
        "facts": facts_of(f),
        "held_from": now,
        "held_until": None,
        "ended_at": None,
        "ended_reason": None,
        "ended_by": None,
    }
    stmt = pg_insert(VendorConfirm).values(**values)
    keep = {k: stmt.excluded[k] for k in values if k not in ("product", "finding", "held_from")}
    await db.execute(stmt.on_conflict_do_update(index_elements=["product", "finding"], set_=keep))
    changed()
    return await db.get(VendorConfirm, (product, f["id"]), populate_existing=True)


async def undo(db: AsyncSession, user: User, product: str, finding: str, now: datetime | None = None) -> VendorConfirm | None:
    """"Bestätigung aufheben": the finding counts and notifies again from now on. Not committed. None: none stands."""
    now = now or now_utc()
    c = await db.get(VendorConfirm, (product, finding), populate_existing=True)
    if c is None or c.ended_at is not None:
        return None
    c.ended_at, c.held_until, c.ended_reason, c.ended_by = now, now, "undone", _name(user)
    changed()
    return c


def _record_lapse(db: AsyncSession, c: VendorConfirm, reason: str, label: str, ident: str) -> None:
    details = {"finding": c.finding, "ident": ident, "status": c.status, "reason": reason, "confirmed_by": c.user_name}
    audit.record(db, audit.SYSTEM, "vendor.finding_confirm_lapsed", audit.target("product", c.product, label), details)


def _end(c: VendorConfirm, reason: str, now: datetime) -> None:
    c.ended_at, c.held_until, c.ended_reason, c.ended_by = now, max(c.held_from, now - LAPSE_GRACE), reason, None


async def check(db: AsyncSession, product: dict, findings: list[dict], now: datetime | None = None) -> dict[str, str]:
    """The confirmations of this product that no longer fit its findings end now (with an audit entry each). Returns
    finding id → why, for the events made in the same evaluation. Not committed (the evaluation's transaction)."""
    now = now or now_utc()
    key = product["key"]
    rows = list(await db.scalars(select(VendorConfirm).where(VendorConfirm.product == key, VendorConfirm.ended_at.is_(None))))
    if not rows:
        return {}
    by_id = {f["id"]: f for f in findings}
    out_: dict[str, str] = {}
    for c in rows:
        f = by_id.get(c.finding)
        if f is None:
            continue  # not shown now (a source switched off, the leading record changed): nothing to compare with
        why = lapse_reason(c.facts or {}, f)
        if why is None:
            continue
        _end(c, why, now)
        _record_lapse(db, c, why, str(product.get("label") or key), str(f.get("ident") or c.finding))
        out_[c.finding] = why
    if out_:
        changed()
    return out_


async def withdrawn(db: AsyncSession, links: list[tuple[str, str]], labels: dict[str, str] | None = None, now: datetime | None = None) -> int:
    """Advisories withdrawn by their source (vendor.drop_advisories): (product, advisory id) – their confirmations end.
    Not committed."""
    if not links:
        return 0
    now = now or now_utc()
    pairs = set(links)
    rows = list(await db.scalars(select(VendorConfirm).where(VendorConfirm.ended_at.is_(None), VendorConfirm.finding.in_(sorted({a for _, a in pairs})))))
    n = 0
    for c in rows:
        if (c.product, c.finding) not in pairs:
            continue
        _end(c, "withdrawn", now)
        _record_lapse(db, c, "withdrawn", (labels or {}).get(c.product) or c.product, c.finding.partition(":")[2] or c.finding)
        n += 1
    if n:
        changed()
    return n


async def prune(db: AsyncSession) -> int:
    """The confirmations of products no longer followed (with the reads – reader.prune): a product followed again starts
    without them, as its events do."""
    n = await dbm.delete_batched(db, VendorConfirm, VendorConfirm.product.not_in(select(VendorFollow.product)))
    if n:
        changed()
    return n
