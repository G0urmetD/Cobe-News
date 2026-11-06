"""Admin only: the audit log (app/audit.py) – the list with filters (keyset pages), one entry with its surroundings,
the chain's check, the CSV export with the same filters and the retention. Nothing edits or deletes an entry; lowering
the retention (older entries go with the next prune) needs a fresh proof of identity, and both the export and a change
of the retention are logged themselves."""

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from pydantic import ConfigDict, Field
from sqlalchemy import select

from app import audit
from app import settings as settings_store
from app.deps import ActiveSession, Admin, Db, DownloadGuard, NoNul, api_error, require_reauth
from app.models import AuditEntry

router = APIRouter(prefix="/api/admin/audit", tags=["admin"])

Text = Annotated[str | None, Query(max_length=200)]
Ip = Annotated[str | None, Query(max_length=64)]
SessionRef = Annotated[str | None, Query(max_length=32)]


def _filters(
    since: datetime | None,
    until: datetime | None,
    actor: str | None,
    group: str | None,
    action: str | None,
    target_type: str | None,
    target_id: str | None,
    q: str | None,
    ip: str | None = None,
    session: str | None = None,
    notable: bool = False,
) -> audit.Filters:
    for d in (since, until):
        if d is not None and d.tzinfo is None:
            raise api_error(422, "invalid", errors="since/until need a time zone")
        if d is not None and not audit.in_range(d):
            raise api_error(422, "invalid", errors="since/until out of range")
    if group and group not in audit.GROUPS:
        raise api_error(422, "invalid", errors="unknown group")
    if action and action not in audit.ACTIONS:
        raise api_error(422, "invalid", errors="unknown action")
    return audit.Filters(
        since=since,
        until=until,
        actor=actor or None,
        group=group or None,
        action=action or None,
        target_type=target_type or None,
        target_id=target_id or None,
        ip=ip or None,
        session=session or None,
        notable=notable,
        q=q or None,
    )


@router.get("")
async def entries(
    admin: Admin,
    db: Db,
    since: datetime | None = None,
    until: datetime | None = None,
    actor: Text = None,
    group: Text = None,
    action: Text = None,
    target_type: Text = None,
    target_id: Text = None,
    ip: Ip = None,
    session: SessionRef = None,
    notable: bool = False,
    q: Text = None,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=audit.PAGE_MAX)] = 50,
    total: bool = False,  # also count the hits (up to audit.COUNT_CAP) – the filter chips show it
) -> dict:
    f = _filters(since, until, actor, group, action, target_type, target_id, q, ip, session, notable)
    if not cursor:
        await audit.seal()  # what was written since: sealed before it is shown (unless another request is doing it)
    try:
        rows, nxt = await audit.page(db, f, cursor, limit)
    except ValueError as exc:
        raise api_error(422, "invalid", errors="bad cursor") from exc
    out: dict = {"items": [audit.entry_out(e) for e in rows], "next": nxt, "groups": {g: list(a) for g, a in audit.GROUPS.items()}}
    if total:
        n = await audit.count(db, f)
        out["total"] = min(n, audit.COUNT_CAP)
        out["total_more"] = n > audit.COUNT_CAP
    return out


@router.get("/actors")
async def actors(admin: Admin, db: Db) -> list[dict]:
    return await audit.actors(db)


@router.get("/chain")
async def chain(admin: Admin, db: Db) -> dict:
    """The integrity chain: the new entries sealed and checked (incrementally, from where the last check stopped) – while
    another check runs (the hourly one), the state as it is, marked busy, instead of waiting."""
    return await audit.verify(wait=False)


@router.get("/export")
async def export(
    admin: Admin,
    db: Db,
    _guard: DownloadGuard,
    since: datetime | None = None,
    until: datetime | None = None,
    actor: Text = None,
    group: Text = None,
    action: Text = None,
    target_type: Text = None,
    target_id: Text = None,
    ip: Ip = None,
    session: SessionRef = None,
    notable: bool = False,
    q: Text = None,
    delimiter: Literal["comma", "semicolon"] = "comma",
) -> StreamingResponse:
    """The entries the filters find as CSV (newest first, at most audit.EXPORT_MAX – more: the header
    X-Audit-Truncated and a last row say so). The delimiter follows the reader's language (semicolon for German: Excel
    splits on its list separator). The export is logged itself."""
    f = _filters(since, until, actor, group, action, target_type, target_id, q, ip, session, notable)
    used = {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in vars(f).items() if v}
    await audit.seal()  # its own session: the request's (and `admin` in it) stays as it is
    truncated = await audit.export_truncated(db, f)
    audit.record(db, admin, "audit.exported", None, {"filters": used, **({"truncated": True} if truncated else {})})
    await db.commit()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    headers = {"Content-Disposition": f'attachment; filename="cobe-news-audit-{stamp}.csv"'}
    if truncated:
        headers["X-Audit-Truncated"] = str(audit.EXPORT_MAX)
    return StreamingResponse(audit.csv_chunks(f, audit.DELIMITERS[delimiter]), media_type="text/csv; charset=utf-8", headers=headers)


class SettingsIn(NoNul):
    model_config = ConfigDict(extra="forbid")

    keep_days: int = Field(ge=audit.KEEP_MIN, le=audit.KEEP_MAX)
    rev: int | None = None


async def _settings_out(db) -> dict:  # noqa: ANN001
    raw = await settings_store.get(db, audit.SECTION)
    return {"keep_days": await audit.keep_days(db), "keep_min": audit.KEEP_MIN, "keep_max": audit.KEEP_MAX, "keep_default": audit.KEEP_DEFAULT, "rev": int(raw.get("rev") or 0)}


@router.get("/settings")
async def get_settings(admin: Admin, db: Db) -> dict:
    return await _settings_out(db)


@router.put("/settings")
async def put_settings(body: SettingsIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    before = await audit.keep_days(db)
    if body.keep_days < before:
        require_reauth(sess, admin)  # a shorter retention removes older entries with the next prune
    if body.keep_days != before:
        audit.record(db, admin, "settings.changed", audit.target("settings", audit.SECTION, audit.SECTION), {"changes": audit.diff({"keep_days": before}, {"keep_days": body.keep_days})})
    await settings_store.put_rev(db, audit.SECTION, {"keep_days": body.keep_days}, body.rev)
    return await _settings_out(db)


@router.get("/{entry_id}")
async def entry(entry_id: int, admin: Admin, db: Db) -> dict:
    """One entry with its surroundings (the expanded row): the target's earlier entries, its session, its address in
    the 24 hours up to it, the account's sign-in before it."""
    if not 0 < entry_id < 2**63:
        raise api_error(404, "not_found")
    e = await db.scalar(select(AuditEntry).where(AuditEntry.id == entry_id))
    if e is None:
        raise api_error(404, "not_found")
    return {**audit.entry_out(e), "context": await audit.context(db, e)}
