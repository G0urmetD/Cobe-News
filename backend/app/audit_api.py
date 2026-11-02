"""Admin only: the audit log (app/audit.py) – the list with filters (keyset pages), the CSV export with the same filters
and the retention. Nothing edits or deletes an entry; lowering the retention (older entries go with the next prune)
needs a fresh proof of identity, and both the export and a change of the retention are logged themselves."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from pydantic import ConfigDict, Field

from app import audit
from app import settings as settings_store
from app.deps import ActiveSession, Admin, Db, NoNul, api_error, require_reauth

router = APIRouter(prefix="/api/admin/audit", tags=["admin"])

Text = Annotated[str | None, Query(max_length=200)]


def _filters(since: datetime | None, until: datetime | None, actor: str | None, group: str | None, action: str | None, target_type: str | None, target_id: str | None, q: str | None) -> audit.Filters:
    for d in (since, until):
        if d is not None and d.tzinfo is None:
            raise api_error(422, "invalid", errors="since/until need a time zone")
    if group and group not in audit.GROUPS:
        raise api_error(422, "invalid", errors="unknown group")
    if action and action not in audit.ACTIONS:
        raise api_error(422, "invalid", errors="unknown action")
    return audit.Filters(since=since, until=until, actor=actor or None, group=group or None, action=action or None, target_type=target_type or None, target_id=target_id or None, q=q or None)


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
    q: Text = None,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=audit.PAGE_MAX)] = 50,
) -> dict:
    f = _filters(since, until, actor, group, action, target_type, target_id, q)
    try:
        rows, nxt = await audit.page(db, f, cursor, limit)
    except ValueError as exc:
        raise api_error(422, "invalid", errors="bad cursor") from exc
    return {"items": [audit.entry_out(e) for e in rows], "next": nxt, "groups": {g: list(a) for g, a in audit.GROUPS.items()}}


@router.get("/actors")
async def actors(admin: Admin, db: Db) -> list[dict]:
    return await audit.actors(db)


@router.get("/export")
async def export(
    admin: Admin,
    db: Db,
    since: datetime | None = None,
    until: datetime | None = None,
    actor: Text = None,
    group: Text = None,
    action: Text = None,
    target_type: Text = None,
    target_id: Text = None,
    q: Text = None,
) -> StreamingResponse:
    """The entries the filters find as CSV (newest first, at most audit.EXPORT_MAX) – the export is logged itself."""
    f = _filters(since, until, actor, group, action, target_type, target_id, q)
    used = {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in vars(f).items() if v}
    audit.record(db, admin, "audit.exported", None, {"filters": used})
    await db.commit()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return StreamingResponse(
        audit.csv_chunks(f),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="cobe-news-audit-{stamp}.csv"'},
    )


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
