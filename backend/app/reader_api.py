"""The signed-in person's reading (app/reader.py): the unread numbers of the sidebar, Vendor News read / unread / all
read, their mutes ("Meine Stummschaltungen") and their saved views ("Ansichten"). Only the own rows – every statement is
bound to the session's account; another person's id in a path is a 404, never a 403 (nothing tells it exists)."""

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import ConfigDict, Field, field_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import cve_watch, personal, reader, teams
from app import news as news_svc
from app import vendor as vendor_svc
from app import vendor_catalog as catalog
from app.api import _sane_time, _with_source
from app.db import fold
from app.deps import Db, NoNul, Reader, api_error
from app.models import PersonMute, SavedView, User, VendorFollow

router = APIRouter(prefix="/api", tags=["reader"])
MUTES_MAX = 200
PRODUCTS_MAX = 2000
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------- Vendor News: the followed products' findings


async def vendor_views(db: AsyncSession, keys: set[str] | None = None, *, wait: float | None = None) -> list[tuple[str, list[dict]]]:
    """(product, findings) of the followed products (of `keys` when given) – from the cached views (app/vendor.py).
    `wait`: after a change for all, the previous views once the new ones take longer (product_view's deadline)."""
    fs = await vendor_svc.follows(db)
    if keys is not None:
        fs = [f for f in fs if f.product in keys]
    if not fs:
        return []
    vers = await vendor_svc.versions_of(db, [f.id for f in fs])
    kev, euvd = await vendor_svc.kev_index(db), await vendor_svc.euvd_cves(db)
    dl = vendor_svc.stale_deadline(wait)
    return [(f.product, (await vendor_svc.product_view(db, f, vers.get(f.id, []), kev=kev, euvd=euvd, deadline=dl))["findings"]) for f in fs]


@router.get("/reader/counts")
async def counts(user: Reader, db: Db, scope: Literal["all", "team"] = "all") -> dict:
    """The unread numbers next to News and Vendor News in the sidebar (polled, and on focus): both without what the
    person muted. `scope=team`: Vendor News of the person's teams only ("Mein Team" – nothing changes while Teams is
    off or the person is in no team, as on the page). Read only – nothing is written."""
    now = datetime.now(UTC)
    m = await reader.marks(db, user)
    mutes = await reader.mutes_of(db, user.id, now)
    where = [news_svc.visible()]
    hush = reader.news_muted(mutes)
    if hush is not None:
        where.append(~hush)
    news_on = bool((await news_svc.config(db)).get("enabled"))
    n_news = await reader.news_unread_count(db, user.id, m, where, now, _with_source) if news_on else 0
    # as the page resolves it: "Mein Team" only while Teams is on and the person is in a team (else all products)
    mine = await teams.my_products(db, user.id) if scope == "team" and await personal.in_team(db, user.id) else None
    vendor_on = bool((await vendor_svc.config(db)).get("enabled", True))
    n_vendor = 0
    if vendor_on:  # Vendor News switched off: no number on it (and no view is computed for it)
        views = await vendor_views(db, mine, wait=vendor_svc.STALE_WAIT)
        rd = await reader.vendor_reading(db, user, [p for p, _ in views], now, m)
        n_vendor = sum(rd.count(p, fs) for p, fs in views)
    return {"news": n_news, "vendor": n_vendor, "news_enabled": news_on, "vendor_enabled": vendor_on}


class VendorReadIn(_M):
    product: str = Field(min_length=1, max_length=200)
    finding: str | None = Field(default=None, min_length=1, max_length=400)
    # the drawer's load time: what arrived after it stays unread (it was not shown)
    upto: datetime | None = None


class VendorUnreadIn(_M):
    product: str = Field(min_length=1, max_length=200)
    finding: str = Field(min_length=1, max_length=400)


class VendorReadAllIn(_M):
    # the products of the filtered list (a few hundred at most – never the findings' ids); None: every followed one
    products: list[Annotated[str, Field(min_length=1, max_length=200)]] | None = Field(default=None, max_length=PRODUCTS_MAX)
    upto: datetime | None = None  # the list's load time
    muted: bool = False  # the list showed the muted products too


def _upto(v: datetime | None) -> datetime:
    now = datetime.now(UTC)
    if v is None:
        return now
    d = _sane_time(v)
    if d is None:
        raise api_error(422, "invalid_upto")
    return min(d, now)


async def _followed(db: AsyncSession, key: str) -> None:
    if await db.scalar(select(VendorFollow.id).where(VendorFollow.product == key)) is None:
        raise api_error(404, "not_found")


@router.post("/vendor/read")
async def vendor_read(body: VendorReadIn, user: Reader, db: Db) -> dict:
    """One finding read – or, without `finding`, every unread finding of the product up to `upto` (opening its drawer)."""
    await _followed(db, body.product)
    if body.finding is not None:
        await reader.vendor_mark(db, user.id, body.product, body.finding, read=True)
        await db.commit()
        return {"marked": 1}
    marked = await reader.vendor_read_all(db, user, await vendor_views(db, {body.product}), upto=_upto(body.upto), everything=False)
    await db.commit()
    return {"marked": marked}


@router.post("/vendor/unread")
async def vendor_unread(body: VendorUnreadIn, user: Reader, db: Db) -> dict:
    """"Als ungelesen markieren" for one finding – also one older than the watermark or reader.AUTO_READ."""
    await _followed(db, body.product)
    await reader.vendor_mark(db, user.id, body.product, body.finding, read=False)
    await db.commit()
    return {"ok": True}


@router.post("/vendor/read-all")
async def vendor_read_all(body: VendorReadAllIn, user: Reader, db: Db) -> dict:
    """"Alle gelesen" for the Vendor News list: the products it showed (all followed ones without `products`), what
    arrived up to `upto`. Idempotent."""
    keys = set(body.products) if body.products is not None else None
    mutes = await reader.mutes_of(db, user.id)
    views = await vendor_views(db, keys)
    if mutes and not body.muted:
        views = [(p, fs) for p, fs in views if p not in mutes.products]
    everything = keys is None and (body.muted or not mutes)
    marked = await reader.vendor_read_all(db, user, views, upto=_upto(body.upto), everything=everything, skip_muted=bool(mutes) and not body.muted)
    await db.commit()
    return {"marked": marked}


# ---------------------------------------------------------------- mutes


def _label(db_follows: dict[str, VendorFollow], key: str) -> str:
    f = db_follows.get(key)
    p = vendor_svc.product_of(f) if f is not None else catalog.product(key)
    return str((p or {}).get("label") or key)


def mute_out(m: PersonMute, label: str) -> dict:
    return {"id": str(m.id), "kind": m.kind, "key": m.key, "label": label, "until": m.until.isoformat(), "created_at": m.created_at.isoformat()}


class MuteIn(_M):
    kind: Literal["product", "cve"]
    key: str = Field(min_length=1, max_length=200)
    days: int | None = Field(default=None, ge=1, le=366)  # 7 or 30 in the menus
    until: datetime | None = None  # "bis zum …" instead of days


@router.get("/me/mutes")
async def list_mutes(user: Reader, db: Db) -> dict:
    """The person's running mutes, the one ending first first."""
    now = datetime.now(UTC)
    rows = list(await db.scalars(select(PersonMute).where(PersonMute.user_id == user.id, PersonMute.until > now).order_by(PersonMute.until, PersonMute.key)))
    fs = {f.product: f for f in await db.scalars(select(VendorFollow).where(VendorFollow.product.in_([m.key for m in rows if m.kind == "product"])))} if rows else {}
    return {"items": [mute_out(m, _label(fs, m.key) if m.kind == "product" else m.key) for m in rows], "max": MUTES_MAX}


@router.post("/me/mutes")
async def add_mute(body: MuteIn, user: Reader, db: Db) -> dict:
    """Mute a product or a CVE for `days` or until a time (at most reader.MUTE_MAX ahead) – the same one again
    replaces its end. Only the person's own deliveries and lists are affected."""
    now = datetime.now(UTC)
    if (body.days is None) == (body.until is None):
        raise api_error(422, "mute_days_or_until")
    until = now + timedelta(days=body.days) if body.days is not None else _sane_time(body.until)  # type: ignore[arg-type]
    if until is None or until <= now or until > now + reader.MUTE_MAX:
        raise api_error(422, "invalid_until")
    if body.kind == "cve":
        key = cve_watch.normalize(body.key)
        if key is None:
            raise api_error(422, "invalid_cve")
        label = key
    else:
        key = body.key
        f = await db.scalar(select(VendorFollow).where(VendorFollow.product == key))
        if f is None and catalog.product(key) is None:
            raise api_error(404, "not_found")
        label = _label({key: f} if f is not None else {}, key)
    # serialised per person (the account's row): two tabs at the limit never make one too many
    await db.execute(select(User.id).where(User.id == user.id).with_for_update())
    have = await db.scalar(select(PersonMute.id).where(PersonMute.user_id == user.id, PersonMute.kind == body.kind, PersonMute.key == key))
    if have is None:
        n = int(await db.scalar(select(func.count()).select_from(PersonMute).where(PersonMute.user_id == user.id, PersonMute.until > now)) or 0)
        if n >= MUTES_MAX:
            raise api_error(409, "too_many_mutes", max=MUTES_MAX)
    stmt = pg_insert(PersonMute).values(id=uuid.uuid4(), user_id=user.id, kind=body.kind, key=key, until=until, created_at=now)
    await db.execute(stmt.on_conflict_do_update(index_elements=["user_id", "kind", "key"], set_={"until": until, "created_at": now}))
    await db.commit()
    m = await db.scalar(select(PersonMute).where(PersonMute.user_id == user.id, PersonMute.kind == body.kind, PersonMute.key == key))
    assert m is not None
    return mute_out(m, label)


@router.delete("/me/mutes/{mid}")
async def remove_mute(mid: uuid.UUID, user: Reader, db: Db) -> dict:
    """"Aufheben" – only the person's own (another's id: 404)."""
    res = await db.execute(delete(PersonMute).where(PersonMute.id == mid, PersonMute.user_id == user.id))
    await db.commit()
    if not res.rowcount:
        raise api_error(404, "not_found")
    return {"ok": True}


# ---------------------------------------------------------------- saved views


def _name(v: str) -> str:
    if CONTROL.search(v):
        raise ValueError("control characters")
    return v


class ViewIn(_M):
    page: Literal["news", "vendor"]
    name: str = Field(min_length=1, max_length=reader.NAME_MAX)
    query: str = Field(default="", max_length=reader.QUERY_MAX)
    default: bool = False

    @field_validator("name")
    @classmethod
    def _n(cls, v: str) -> str:
        return _name(v)


class ViewPatch(_M):
    name: str | None = Field(default=None, min_length=1, max_length=reader.NAME_MAX)
    query: str | None = Field(default=None, max_length=reader.QUERY_MAX)
    default: bool | None = None

    @field_validator("name")
    @classmethod
    def _n(cls, v: str | None) -> str | None:
        return _name(v) if v is not None else v


async def _own_view(db: AsyncSession, vid: uuid.UUID, user_id: uuid.UUID) -> SavedView:
    v = await db.scalar(select(SavedView).where(SavedView.id == vid, SavedView.user_id == user_id))
    if v is None:
        raise api_error(404, "not_found")
    return v


async def _name_taken(db: AsyncSession, user_id: uuid.UUID, page: str, name: str, but: uuid.UUID | None = None) -> bool:
    q = select(SavedView.id).where(SavedView.user_id == user_id, SavedView.page == page, SavedView.name == name)
    if but is not None:
        q = q.where(SavedView.id != but)
    return await db.scalar(q) is not None


async def _undefault(db: AsyncSession, user_id: uuid.UUID, page: str) -> None:
    await db.execute(update(SavedView).where(SavedView.user_id == user_id, SavedView.page == page, SavedView.is_default.is_(True)).values(is_default=False))


@router.get("/me/views")
async def list_views(user: Reader, db: Db, page: Annotated[Literal["news", "vendor"] | None, Query()] = None) -> dict:
    q = select(SavedView).where(SavedView.user_id == user.id)
    if page is not None:
        q = q.where(SavedView.page == page)
    rows = sorted(await db.scalars(q), key=lambda v: (v.page, fold(v.name), v.name))
    return {"items": [reader.view_out(v) for v in rows], "max": reader.VIEW_MAX}


@router.post("/me/views")
async def add_view(body: ViewIn, user: Reader, db: Db) -> dict:
    """A view of the page's current filter. At most reader.VIEW_MAX per person and page; the name once per page."""
    await db.execute(select(User.id).where(User.id == user.id).with_for_update())  # serialised per person (the limit)
    n = int(await db.scalar(select(func.count()).select_from(SavedView).where(SavedView.user_id == user.id, SavedView.page == body.page)) or 0)
    if n >= reader.VIEW_MAX:
        raise api_error(409, "too_many_views", max=reader.VIEW_MAX)
    if await _name_taken(db, user.id, body.page, body.name):
        raise api_error(409, "view_exists")
    if body.default:
        await _undefault(db, user.id, body.page)
    now = datetime.now(UTC)
    v = SavedView(user_id=user.id, page=body.page, name=body.name, query=reader.clean_query(body.query), is_default=body.default, created_at=now, updated_at=now)
    db.add(v)
    await db.commit()
    return reader.view_out(v)


@router.patch("/me/views/{vid}")
async def patch_view(vid: uuid.UUID, body: ViewPatch, user: Reader, db: Db) -> dict:
    """Rename, replace the filter, or make it the page's default (`default: false`: no default any more)."""
    await db.execute(select(User.id).where(User.id == user.id).with_for_update())
    v = await _own_view(db, vid, user.id)
    if body.name is not None and body.name != v.name:
        if await _name_taken(db, user.id, v.page, body.name, v.id):
            raise api_error(409, "view_exists")
        v.name = body.name
    if body.query is not None:
        v.query = reader.clean_query(body.query)
    if body.default is not None and body.default != v.is_default:
        if body.default:
            await _undefault(db, user.id, v.page)
            await db.flush()
        v.is_default = body.default
    v.updated_at = datetime.now(UTC)
    await db.commit()
    return reader.view_out(v)


@router.delete("/me/views/{vid}")
async def delete_view(vid: uuid.UUID, user: Reader, db: Db) -> dict:
    res = await db.execute(delete(SavedView).where(SavedView.id == vid, SavedView.user_id == user.id))
    await db.commit()
    if not res.rowcount:
        raise api_error(404, "not_found")
    return {"ok": True}

