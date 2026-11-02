"""Katalog-Pflege by the people who use it (0.1.x): "Versionen prüfen" and "Produkt vorschlagen".

Versionen prüfen – the versions entered are typed in by hand (Cobe News never asks a system), so they age:
- Every entered version has `confirmed_at` (+ who). Entering or changing it confirms it; "Bestätigen" ("läuft noch so")
  confirms it unchanged. A confirmation is never part of the evaluation: it does not touch `updated_at`, recomputes no
  view and changes no verdict, no urgency score (vendor_score) and no notification.
- An admin setting (Vendor News, `review_days`: 30/60/90/180/365, 0 = off, default 90): a version not confirmed for
  longer is "bitte prüfen" – shown with a badge wherever versions are shown, a filter, a count.
- A version whose text the product's rules no longer take (app/version_input.py – a rule came after it was entered:
  "24.11" for pfSense CE is pfSense Plus now, "2023" is no S/4HANA component release) is "bitte prüfen" as well,
  whatever its age: confirming does not change that, only correcting it. It stays evaluated meanwhile (as
  "möglicherweise betroffen" where the rules refuse it) – never dropped.
- Who is responsible: with Teams on, a product of teams belongs to their members (they may confirm it, they see the
  count); every other product – and all of them while Teams is off – to the admins. Admins may confirm anything.
- The reminder: one section "Versionen zu prüfen" in the team's weekly review mail (app/weekly.py) – already opt-in,
  once a week at most, bundled per team. No new kind of personal notification: one per version would be noise.

Produkt vorschlagen – any signed-in person suggests a product the catalogue lacks (vendor, name, optional address and
CPE, why, optional team). Plain text, limited in length and number (SUGGEST_PER_DAY a day); an address only http(s),
never fetched by the server. Admins answer: accepted (the product they added by CPE – or "for the bundled catalogue"),
rejected (optional reason) or duplicate (the existing product). The suggester sees the own suggestions and the answer.
"""

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app import teams
from app import settings as settings_store
from app.models import ProductSuggestion, Team, TeamMember, TeamProduct, User, VendorFollow, VendorVersion

REVIEW_CHOICES = (0, 30, 60, 90, 180, 365)  # 0: off
REVIEW_DEFAULT = 90
SUGGEST_PER_DAY = 10
SUGGEST_OPEN_MAX = 50  # open suggestions of one person at a time
STATES = ("open", "accepted", "rejected", "duplicate")
CONTROL_LINE = re.compile(r"[\x00-\x1f\x7f]")
CONTROL_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # a reason keeps its line breaks and tabs
CPE = re.compile(r"^(?:cpe:2\.3:)?[aoh]:[^:\s]+:[^:\s]+(?::[^:\s]*){0,10}$", re.I)


# ---------------------------------------------------------------- Versionen prüfen


def review_days_of(cfg: dict) -> int:
    v = cfg.get("review_days", REVIEW_DEFAULT)
    try:
        v = int(v)
    except (TypeError, ValueError):
        return REVIEW_DEFAULT
    return v if v in REVIEW_CHOICES else REVIEW_DEFAULT


async def review_days(db: AsyncSession) -> int:
    return review_days_of(await settings_store.get(db, "vendor"))


def confirmed_of(v: VendorVersion) -> datetime | None:
    """When the version was last confirmed: confirmed_at – or, never confirmed (a SQLite import), when it was entered."""
    return v.confirmed_at or v.updated_at or v.created_at


def age_days(v: VendorVersion, now: datetime) -> int:
    at = confirmed_of(v)
    return max(0, (now - at).days) if at else 0


def is_due(v: VendorVersion, days: int, now: datetime) -> bool:
    """"Bitte prüfen": not confirmed for longer than the interval (off: never)."""
    at = confirmed_of(v)
    return bool(days) and at is not None and now - at > timedelta(days=days)


def invalid(v: VendorVersion, product: dict | None) -> bool:
    """"Bitte prüfen" too: the stored text is no valid version of the product any more (see the module docstring)."""
    from app import version_input

    return product is not None and not version_input.check(product, v.version).ok


@dataclass
class Review:
    """What the version cards need about the review: the interval, now, and the confirmers' names."""

    days: int
    now: datetime
    names: dict[uuid.UUID, str] = field(default_factory=dict)

    def of(self, v: VendorVersion, product: dict | None = None) -> dict:
        at = confirmed_of(v)
        bad = invalid(v, product)
        return {
            "confirmed_at": at.isoformat() if at else None,
            "confirmed_by": self.names.get(v.confirmed_by) if v.confirmed_by else None,
            "age_days": age_days(v, self.now),
            "due": bad or is_due(v, self.days, self.now),
        } | ({"invalid": True} if bad else {})


async def review_ctx(db: AsyncSession, versions: list[VendorVersion]) -> Review:
    ids = {v.confirmed_by for v in versions if v.confirmed_by}
    names = {}
    if ids:
        names = {i: (d or u) for i, d, u in await db.execute(select(User.id, User.display_name, User.username).where(User.id.in_(ids)))}
    return Review(days=await review_days(db), now=datetime.now(UTC), names=names)


async def confirmable(db: AsyncSession, user: User) -> set[str] | None:
    """The products whose versions this person may confirm: None – all (an admin); a reader those of the own teams
    (Teams on), none otherwise."""
    if user.role == "admin":
        return None
    return await teams.my_products(db, user.id) or set()


async def product_teams(db: AsyncSession, follow_ids: list[uuid.UUID] | None = None) -> dict[uuid.UUID, list[dict]]:
    """Per followed product the teams it belongs to (id, name)."""
    q = select(TeamProduct.follow_id, Team.id, Team.name).join(Team, Team.id == TeamProduct.team_id).order_by(func.lower(Team.name))
    if follow_ids is not None:
        if not follow_ids:
            return {}
        q = q.where(TeamProduct.follow_id.in_(follow_ids))
    out: dict[uuid.UUID, list[dict]] = {}
    for fid, tid, name in await db.execute(q):
        out.setdefault(fid, []).append({"id": str(tid), "name": name})
    return out


async def responsible_for(db: AsyncSession, user: User) -> set[str] | None:
    """The products this person is responsible for confirming: with Teams on, those of the own teams – and, for an
    admin, every product of no team; while Teams is off the admins all of them (None) and readers none."""
    on = await teams.is_on(db)
    if not on:
        return None if user.role == "admin" else set()
    mine = await teams.my_products(db, user.id) or set()
    if user.role != "admin":
        return mine
    owned = select(TeamProduct.follow_id)
    orphans = set(await db.scalars(select(VendorFollow.product).where(VendorFollow.id.not_in(owned))))
    return mine | orphans


async def due_list(db: AsyncSession, keys: set[str] | None, days: int, now: datetime | None = None) -> list[dict]:
    """The followed products (of `keys`, None: all) with versions to confirm – each with only its due versions."""
    from app import vendor as vendor_svc

    if not days:
        return []
    now = now or datetime.now(UTC)
    fs = [f for f in await vendor_svc.follows(db) if keys is None or f.product in keys]
    vers = await vendor_svc.versions_of(db, [f.id for f in fs])
    prods = {f.id: vendor_svc.product_of(f) for f in fs}
    due = {f.id: [v for v in vers.get(f.id, []) if is_due(v, days, now) or invalid(v, prods[f.id])] for f in fs}
    fs = [f for f in fs if due[f.id]]
    if not fs:
        return []
    rv = await review_ctx(db, [v for f in fs for v in due[f.id]])
    rv.now = now
    tms = await product_teams(db, [f.id for f in fs])
    out = []
    for f in fs:
        p = prods[f.id] or {"key": f.product, "label": f.product, "vendor": ""}
        out.append(
            {
                "product": {"key": f.product, "label": p.get("label") or f.product, "vendor": p.get("vendor") or ""},
                "teams": tms.get(f.id, []),
                "versions": [{"id": str(v.id), "version": v.version, "label": v.label, **rv.of(v, prods[f.id])} for v in due[f.id]],
            }
        )
    out.sort(key=lambda x: (-max(v["age_days"] for v in x["versions"]), x["product"]["label"].lower()))
    return out


async def confirm(db: AsyncSession, versions: list[VendorVersion], user: User, now: datetime | None = None) -> int:
    """Confirmed as they are (not committed). Nothing else changes – not updated_at, not the evaluation."""
    if not versions:
        return 0
    now = now or datetime.now(UTC)
    for v in versions:
        v.confirmed_at, v.confirmed_by = now, user.id
    await db.flush()
    return len(versions)


# ---------------------------------------------------------------- Produkt vorschlagen


def clean_line(text: str) -> str:
    """One line of plain text: control characters become spaces, runs of white space one."""
    return " ".join(CONTROL_LINE.sub(" ", text or "").split())


def clean_text(text: str) -> str:
    t = CONTROL_TEXT.sub("", (text or "").replace("\r\n", "\n").replace("\r", "\n"))
    return re.sub(r"\n{3,}", "\n\n", t).strip()


def url_problem(url: str) -> str | None:
    """None: an http(s) address with a host, no user or password in it, no white space – shown as text and link only."""
    if len(url) > 500:
        return "too_long"
    if any(c.isspace() for c in url) or CONTROL_LINE.search(url):
        return "format"
    try:
        u = urlsplit(url)
        host = u.hostname
        u.port  # noqa: B018 - a bad port raises
    except ValueError:
        return "format"
    if u.scheme.lower() not in ("http", "https"):
        return "scheme"
    if not host or "@" in u.netloc or "." not in host.strip("[]") and ":" not in host:
        return "format"
    return None


def cpe_short(cpe: str | None) -> str | None:
    """'cpe:2.3:a:vendor:product:*:…' or 'a:vendor:product' → 'a:vendor:product' (what "add by CPE" takes)."""
    if not cpe:
        return None
    parts = cpe.removeprefix("cpe:2.3:").split(":")
    return ":".join(parts[:3]).lower() if len(parts) >= 3 else None


async def limit_reached(db: AsyncSession, user_id: uuid.UUID, now: datetime) -> bool:
    day = await db.scalar(select(func.count()).select_from(ProductSuggestion).where(ProductSuggestion.user_id == user_id, ProductSuggestion.created_at > now - timedelta(days=1)))
    if int(day or 0) >= SUGGEST_PER_DAY:
        return True
    still = await db.scalar(select(func.count()).select_from(ProductSuggestion).where(ProductSuggestion.user_id == user_id, ProductSuggestion.status == "open"))
    return int(still or 0) >= SUGGEST_OPEN_MAX


async def already_open(db: AsyncSession, user_id: uuid.UUID, vendor: str, product: str) -> bool:
    q = select(ProductSuggestion.id).where(
        ProductSuggestion.user_id == user_id,
        ProductSuggestion.status == "open",
        func.lower(ProductSuggestion.vendor) == vendor.lower(),
        func.lower(ProductSuggestion.product) == product.lower(),
    )
    return await db.scalar(q.limit(1)) is not None


async def team_allowed(db: AsyncSession, user: User, team_id: uuid.UUID) -> Team | None:
    """The team named in a suggestion: Teams on, and the person's own (an admin: any)."""
    if not await teams.is_on(db):
        return None
    t = await db.get(Team, team_id)
    if t is None:
        return None
    if user.role == "admin":
        return t
    member = await db.scalar(select(TeamMember.user_id).where(TeamMember.team_id == team_id, TeamMember.user_id == user.id))
    return t if member else None


async def known_product(db: AsyncSession, key: str) -> dict | None:
    """A product of the catalogue or one added by CPE (followed or not): {key, label}."""
    from app import vendor as vendor_svc
    from app import vendor_catalog as catalog

    p = catalog.product(key)
    if p is None:
        f = await db.scalar(select(VendorFollow).where(VendorFollow.product == key))
        p = vendor_svc.product_of(f) if f is not None else None
    return {"key": key, "label": p.get("label") or key} if p else None


async def labels_of(db: AsyncSession, keys: set[str]) -> dict[str, str]:
    out = {}
    for k in keys:
        p = await known_product(db, k)
        out[k] = p["label"] if p else k
    return out


async def out_list(db: AsyncSession, rows: list[ProductSuggestion], *, admin: bool) -> list[dict]:
    """Suggestions as the UI shows them – an admin's list also says who suggested and who answered."""
    team_ids = {r.team_id for r in rows if r.team_id}
    tnames = {i: n for i, n in await db.execute(select(Team.id, Team.name).where(Team.id.in_(team_ids)))} if team_ids else {}
    user_ids = {u for r in rows for u in (r.user_id, r.decided_by) if u} if admin else set()
    unames = {i: (d or u) for i, d, u in await db.execute(select(User.id, User.display_name, User.username).where(User.id.in_(user_ids)))} if user_ids else {}
    plabels = await labels_of(db, {r.product_key for r in rows if r.product_key})

    def iso(d: datetime | None) -> str | None:
        return d.isoformat() if d else None

    out = []
    for r in rows:
        x = {
            "id": str(r.id),
            "vendor": r.vendor,
            "product": r.product,
            "url": r.url,
            "cpe": r.cpe,
            "cpe_short": cpe_short(r.cpe),
            "reason": r.reason,
            "team": {"id": str(r.team_id), "name": tnames.get(r.team_id, "")} if r.team_id else None,
            "status": r.status,
            "answer": r.answer,
            "result": {"key": r.product_key, "label": plabels.get(r.product_key, r.product_key)} if r.product_key else None,
            "created_at": iso(r.created_at),
            "decided_at": iso(r.decided_at),
            "seen": r.seen_at is not None,
        }
        if admin:
            x["by"] = unames.get(r.user_id) if r.user_id else None
            x["decided_by"] = unames.get(r.decided_by) if r.decided_by else None
        out.append(x)
    return out


async def decide(db: AsyncSession, sid: uuid.UUID, admin: User, status: str, *, answer: str = "", product_key: str | None = None) -> bool:
    """open → status, once (a conditional UPDATE: two admins at once – the second gets False). Not committed: the caller
    commits it together with its audit entry."""
    res = await db.execute(
        update(ProductSuggestion)
        .where(and_(ProductSuggestion.id == sid, ProductSuggestion.status == "open"))
        .values(status=status, answer=answer, product_key=product_key, decided_by=admin.id, decided_at=datetime.now(UTC), seen_at=None)
        .execution_options(synchronize_session=False)
    )
    return (res.rowcount or 0) == 1
