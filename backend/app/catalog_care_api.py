"""API of "Versionen prüfen" and "Produkt vorschlagen" (app/catalog_care.py).

Versions: the list of versions to confirm that the caller is responsible for, confirming one or all of a product or a
team – admins any, readers those of their own teams (Teams on). Suggestions: every signed-in person suggests and sees
the own ones (never anybody else's); only admins see the queue and answer.

Audit log: a confirmation (catalog.version_confirmed, catalog.versions_confirmed – actor whoever confirmed, a reader as
well) and an admin's answer to a suggestion (suggestion.accepted | rejected | duplicate, with the answer cut to
ANSWER_LOGGED characters); making a suggestion is not logged (a reader's own request, no change of the catalogue)."""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import ConfigDict, Field, field_validator, model_validator
from sqlalchemy import func, select, update

from app import audit, teams
from app import catalog_care as care
from app import vendor as svc
from app.deps import Admin, Db, NoNul, Reader, api_error
from app.models import ProductSuggestion, Team, TeamMember, TeamProduct, VendorFollow, VendorVersion
from app.vendor_api import _follow_target

router = APIRouter(prefix="/api", tags=["catalog-care"])
ANSWER_LOGGED = 200  # characters of an admin's answer kept in the audit log


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------- Versionen prüfen


@router.get("/vendor/review")
async def review(user: Reader, db: Db, scope: Literal["mine", "all"] = "mine") -> dict:
    """The versions not confirmed for longer than the interval: `mine` – those the caller is responsible for (their
    teams' products; an admin also every product of no team, all while Teams is off); `all` – every one (admins)."""
    days = await care.review_days(db)
    if scope == "all" and user.role != "admin":
        raise api_error(403, "forbidden")
    keys = None if scope == "all" else await care.responsible_for(db, user)
    items = await care.due_list(db, keys, days)
    may = await care.confirmable(db, user)
    for i in items:
        i["can_confirm"] = may is None or i["product"]["key"] in may
    return {"days": days, "enabled": bool(days), "count": sum(len(i["versions"]) for i in items), "items": items}


async def _may_confirm(db, user, product: str) -> None:  # noqa: ANN001
    may = await care.confirmable(db, user)
    if may is not None and product not in may:
        raise api_error(403, "forbidden")


@router.post("/vendor/versions/{vid}/confirm")
async def confirm_version(vid: uuid.UUID, user: Reader, db: Db) -> dict:
    """"Bestätigen" – the version still runs as entered."""
    v = await db.get(VendorVersion, vid)
    f = await db.get(VendorFollow, v.follow_id) if v else None
    if v is None or f is None:
        raise api_error(404, "not_found")
    await _may_confirm(db, user, f.product)
    await care.confirm(db, [v], user)
    audit.record(db, user, "catalog.version_confirmed", _follow_target(f), {"version": v.version, "label": v.label})
    await db.commit()
    rv = await care.review_ctx(db, [v])
    return {"id": str(v.id), **rv.of(v, svc.product_of(f))}  # an invalid version stays "bitte prüfen"


class ConfirmAllIn(_M):
    product: str | None = Field(default=None, min_length=1, max_length=80)
    team_id: uuid.UUID | None = None
    due_only: bool = True  # only those "bitte prüfen" (False: every version of the product or team)

    @model_validator(mode="after")
    def _one(self) -> "ConfirmAllIn":
        if (self.product is None) == (self.team_id is None):
            raise ValueError("product or team_id, exactly one")
        return self


@router.post("/vendor/review/confirm")
async def confirm_all(body: ConfirmAllIn, user: Reader, db: Db) -> dict:
    """"Alle bestätigen" of a product or of a team – only what the caller may confirm."""
    may = await care.confirmable(db, user)
    if body.product is not None:
        f = await db.scalar(select(VendorFollow).where(VendorFollow.product == body.product))
        if f is None:
            raise api_error(404, "not_found")
        await _may_confirm(db, user, f.product)
        follows = [f]
    else:
        if user.role != "admin":
            member = await db.scalar(select(TeamMember.user_id).where(TeamMember.team_id == body.team_id, TeamMember.user_id == user.id))
            if member is None or not await teams.is_on(db):
                raise api_error(403, "forbidden")
        follows = list(await db.scalars(select(VendorFollow).join(TeamProduct, TeamProduct.follow_id == VendorFollow.id).where(TeamProduct.team_id == body.team_id, VendorFollow.enabled.is_(True))))
        follows = [f for f in follows if may is None or f.product in may]
    vers = await svc.versions_of(db, [f.id for f in follows])
    days, now = await care.review_days(db), datetime.now(UTC)
    todo = [v for f in follows for v in vers.get(f.id, []) if not body.due_only or care.is_due(v, days, now)]
    n = await care.confirm(db, todo, user, now)
    keys = {f.id: f.product for f in follows}
    if n:
        if body.product is not None:
            where = _follow_target(follows[0])
        else:
            team = await db.get(Team, body.team_id)
            where = audit.target("team", body.team_id, team.name if team else None)
        audit.record(db, user, "catalog.versions_confirmed", where, {"count": n, "due_only": body.due_only, **({"products": sorted({keys[v.follow_id] for v in todo})} if body.team_id else {})})
    await db.commit()
    return {"confirmed": n}


# ---------------------------------------------------------------- Produkt vorschlagen


class SuggestionIn(_M):
    vendor: str = Field(min_length=2, max_length=80)
    product: str = Field(min_length=2, max_length=120)
    url: str | None = Field(default=None, max_length=500)
    cpe: str | None = Field(default=None, max_length=200)
    reason: str = Field(min_length=3, max_length=1000)
    team_id: uuid.UUID | None = None

    @field_validator("vendor", "product")
    @classmethod
    def _line(cls, v: str) -> str:
        v = care.clean_line(v)
        if len(v) < 2:
            raise ValueError("too short")
        return v

    @field_validator("reason")
    @classmethod
    def _text(cls, v: str) -> str:
        v = care.clean_text(v)
        if len(v) < 3:
            raise ValueError("too short")
        return v

    @field_validator("url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        if not v:
            return None
        if why := care.url_problem(v):
            raise ValueError(f"url {why}")
        return v

    @field_validator("cpe")
    @classmethod
    def _cpe(cls, v: str | None) -> str | None:
        if not v:
            return None
        if not care.CPE.fullmatch(v):
            raise ValueError("not a CPE")
        return v


@router.post("/vendor/suggestions")
async def suggest(body: SuggestionIn, user: Reader, db: Db) -> dict:
    now = datetime.now(UTC)
    if await care.limit_reached(db, user.id, now):
        raise api_error(429, "suggest_limit", per_day=care.SUGGEST_PER_DAY)
    if await care.already_open(db, user.id, body.vendor, body.product):
        raise api_error(409, "already_suggested")
    if body.team_id is not None and await care.team_allowed(db, user, body.team_id) is None:
        raise api_error(422, "team_invalid")
    s = ProductSuggestion(user_id=user.id, vendor=body.vendor, product=body.product, url=body.url, cpe=body.cpe, reason=body.reason, team_id=body.team_id, created_at=now)
    db.add(s)
    await db.commit()
    return (await care.out_list(db, [s], admin=False))[0]


@router.get("/vendor/suggestions/mine")
async def my_suggestions(user: Reader, db: Db) -> dict:
    """The caller's own suggestions, newest first – nobody else's."""
    rows = list(await db.scalars(select(ProductSuggestion).where(ProductSuggestion.user_id == user.id).order_by(ProductSuggestion.created_at.desc()).limit(200)))
    return {"items": await care.out_list(db, rows, admin=False), "per_day": care.SUGGEST_PER_DAY}


@router.post("/vendor/suggestions/seen")
async def suggestions_seen(user: Reader, db: Db) -> dict:
    """The answers to the own suggestions were seen (the number on "Meine Vorschläge" goes)."""
    await db.execute(
        update(ProductSuggestion)
        .where(ProductSuggestion.user_id == user.id, ProductSuggestion.status != "open", ProductSuggestion.seen_at.is_(None))
        .values(seen_at=datetime.now(UTC))
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    return {"ok": True}


@router.get("/vendor/suggestions/count")
async def suggestions_count(user: Reader, db: Db) -> dict:
    """The numbers on the tab: answers to the own suggestions not seen yet – and, for admins, the open queue."""
    answered = await db.scalar(
        select(func.count()).select_from(ProductSuggestion).where(ProductSuggestion.user_id == user.id, ProductSuggestion.status != "open", ProductSuggestion.seen_at.is_(None))
    )
    out = {"answered": int(answered or 0), "open": None}
    if user.role == "admin":
        out["open"] = int(await db.scalar(select(func.count()).select_from(ProductSuggestion).where(ProductSuggestion.status == "open")) or 0)
    return out


@router.get("/admin/suggestions")
async def admin_suggestions(admin: Admin, db: Db, state: Literal["open", "done"] = "open", limit: Annotated[int, Query(ge=1, le=500)] = 200) -> dict:
    q = select(ProductSuggestion)
    if state == "open":
        q = q.where(ProductSuggestion.status == "open").order_by(ProductSuggestion.created_at)
    else:
        q = q.where(ProductSuggestion.status != "open").order_by(ProductSuggestion.decided_at.desc().nulls_last())
    rows = list(await db.scalars(q.limit(limit)))
    return {"items": await care.out_list(db, rows, admin=True)}


class AcceptIn(_M):
    product_key: str | None = Field(default=None, min_length=1, max_length=80)  # None: "for the bundled catalogue"
    answer: str = Field(default="", max_length=500)


class RejectIn(_M):
    answer: str = Field(default="", max_length=500)


class DuplicateIn(_M):
    product_key: str = Field(min_length=1, max_length=80)
    answer: str = Field(default="", max_length=500)


async def _decide(db, sid: uuid.UUID, admin, status: str, answer: str, key: str | None) -> dict:  # noqa: ANN001
    s = await db.get(ProductSuggestion, sid)
    if s is None:
        raise api_error(404, "not_found")
    if key is not None and await care.known_product(db, key) is None:
        raise api_error(422, "unknown_product")
    text = care.clean_text(answer)
    if not await care.decide(db, sid, admin, status, answer=text, product_key=key):
        await db.rollback()
        raise api_error(409, "already_decided")
    details = {"product_key": key, "answer": text if len(text) <= ANSWER_LOGGED else text[:ANSWER_LOGGED] + "…"}
    audit.record(db, admin, f"suggestion.{status}", audit.target("suggestion", s.id, f"{s.vendor} {s.product}"), details)
    await db.commit()
    await db.refresh(s)
    return (await care.out_list(db, [s], admin=True))[0]


@router.post("/admin/suggestions/{sid}/accept")
async def accept(sid: uuid.UUID, body: AcceptIn, admin: Admin, db: Db) -> dict:
    """"Übernehmen": the product the admin added for it (by CPE, app/vendor_api.add_custom) – or none, when it goes into
    the bundled catalogue data (app/catalog, a change of the repository)."""
    return await _decide(db, sid, admin, "accepted", body.answer, body.product_key)


@router.post("/admin/suggestions/{sid}/reject")
async def reject(sid: uuid.UUID, body: RejectIn, admin: Admin, db: Db) -> dict:
    return await _decide(db, sid, admin, "rejected", body.answer, None)


@router.post("/admin/suggestions/{sid}/duplicate")
async def duplicate(sid: uuid.UUID, body: DuplicateIn, admin: Admin, db: Db) -> dict:
    """"Doppelt": the catalogue has it already – the existing product."""
    return await _decide(db, sid, admin, "duplicate", body.answer, body.product_key)
