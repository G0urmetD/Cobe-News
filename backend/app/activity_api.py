"""Admin only: the sidebar's "Meldungen" box – the newest few things that happened in the app (not news): who signed in,
who followed a product, who waits for approval … A short allow-list of audit actions (ACTIONS), plus the sign-ins.

Sign-ins come from the accounts (users.last_login_at), not from the audit log: the log has an admin's sign-ins only (a
reader's every sign-in would flood it, auth_api._signed_in), and the account keeps one per person – repeated sign-ins of
the same person are one line by themselves. Sign-ins next to each other in time are joined into one line ("Anna und 2
weitere haben sich angemeldet"), so a busy morning does not push a pending approval out of the three slots.

The viewing admin's own doings are left out – the box shows what the others do.

Cost: the audit part is one statement – per allowed action the newest `limit` entries through ix_audit_log_action
(action, at), joined by UNION ALL and cut to `limit` (len(ACTIONS) × limit index rows at most, whatever the log's size);
the sign-ins one top-N over the accounts (a small table); the current names of the accounts the entries name one
primary-key lookup (also whether a waiting one still waits); what waits now one count over the accounts. Four statements,
no per-row queries.

A "… wartet auf Freigabe" line says whether it still waits (`open`): an approval by this admin is left out as their own
doing, and the line must not keep standing out once it is dealt with. `pending` – what waits now, whether or not its
line is among the newest – gives the collapsed sidebar's bell its dot."""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import Select, and_, func, or_, select, union_all

from app.auth import directory
from app.deps import Admin, Db
from app.models import AuditEntry, User

router = APIRouter(prefix="/api/admin/activity", tags=["admin"])

# what the box shows – each has a text in both languages (frontend lib/activity.ts, i18n activity.text.<action>). The
# approval ones come with the approval of new accounts and roles; listed here already, they show once they are written.
ACTIONS: tuple[str, ...] = (
    "user.approval_pending",
    "role.approval_pending",
    "user.approved",
    "user.declined",
    "role.approved",
    "role.declined",
    "user.created",
    "user.deactivated",
    "role.changed",
    "catalog.followed",
    "catalog.custom_added",
    "backup.restored",
)
PENDING_ACTIONS = ("user.approval_pending", "role.approval_pending")
SIGNIN = "signin"  # the sign-ins' kind (no audit action: they come from the accounts)
LIMIT_MAX = 10
SIGNINS_MAX = 25  # sign-ins read to join a run ("und 24 weitere"); a longer run says "more"
DETAIL_KEYS = ("role", "why")  # what of an entry's details the texts use (role: also a change's new one)


def _actor(e: AuditEntry) -> dict:
    return {"kind": e.actor_kind, "id": str(e.actor_id) if e.actor_id else None, "name": e.actor_name, "display": e.actor_display}


def _role_of(details: dict) -> str | None:
    """The role an entry is about: `role`, the new one of a change (`changes.role.to`) or of a waiting raise (`to`) –
    None when none."""
    role = details.get("role")
    if isinstance(role, str):
        return role
    if isinstance(details.get("to"), str):
        return details["to"]
    ch = details.get("changes")
    to = ch.get("role", {}).get("to") if isinstance(ch, dict) and isinstance(ch.get("role"), dict) else None
    return to if isinstance(to, str) else None


def _still_waits(action: str, u: tuple | None) -> bool:
    """A waiting line's account (is_active, deactivated_reason, pending_role) still waits – gone: not."""
    if u is None:
        return False
    active, reason, pending_role = u
    if action == "user.approval_pending":
        return not active and reason == directory.PENDING
    return bool(active) and pending_role == "admin"


def _entry_out(e: AuditEntry, names: dict[str, str], states: dict[str, tuple]) -> dict:
    d = e.details if isinstance(e.details, dict) else {}
    target = None
    if e.target_type:
        target = {"type": e.target_type, "id": e.target_id, "label": e.target_label, "display": names.get(e.target_id or "") if e.target_type == "user" else None}
    extra = {k: d[k] for k in DETAIL_KEYS if isinstance(d.get(k), str)}
    if (role := _role_of(d)) is not None:
        extra["role"] = role
    out = {"id": f"a{e.id}", "entry": e.id, "action": e.action, "at": e.at.isoformat(), "actor": _actor(e), "target": target, "details": extra}
    if e.action in PENDING_ACTIONS:
        out["open"] = e.target_type == "user" and _still_waits(e.action, states.get(e.target_id or ""))
    return out


def _signins_out(run: list[User], more: bool) -> dict:
    first = run[0]
    return {
        "id": f"s{first.id}",
        "entry": None,
        "action": SIGNIN,
        "at": first.last_login_at.isoformat(),  # type: ignore[union-attr]
        "actor": {"kind": "user", "id": str(first.id), "name": first.username, "display": first.display_name or "", "role": first.role},
        "target": None,
        "details": {},
        # the others of the run (the newest first): how many, and their names for the tooltip
        "others": len(run) - 1,
        "others_more": more,
        "names": [u.display_name or u.username for u in run[:6]],
    }


def _audit_query(me, limit: int) -> Select:  # noqa: ANN001 - the admin's id
    mine = or_(AuditEntry.actor_id.is_(None), AuditEntry.actor_id != me)
    parts = [
        select(AuditEntry.id, AuditEntry.at).where(AuditEntry.action == a, mine).order_by(AuditEntry.at.desc(), AuditEntry.id.desc()).limit(limit)
        for a in ACTIONS
    ]
    newest = union_all(*parts).subquery()
    return select(AuditEntry).join(newest, AuditEntry.id == newest.c.id).order_by(AuditEntry.at.desc(), AuditEntry.id.desc()).limit(limit)


def merge(entries: list[dict], signins: list[User], limit: int, signins_full: bool) -> list[dict]:
    """Entries and sign-ins in one line-up, newest first; sign-ins next to each other one line. `signins_full`: more
    sign-ins than were read – the last run may be longer than it says."""
    out: list[dict] = []
    i = j = 0
    while len(out) < limit and (i < len(entries) or j < len(signins)):
        s_at: datetime | None = signins[j].last_login_at if j < len(signins) else None
        if i < len(entries) and (s_at is None or datetime.fromisoformat(entries[i]["at"]) >= s_at):
            out.append(entries[i])
            i += 1
            continue
        run = [signins[j]]
        j += 1
        nxt = datetime.fromisoformat(entries[i]["at"]) if i < len(entries) else None
        while j < len(signins) and (nxt is None or signins[j].last_login_at >= nxt):  # type: ignore[operator]
            run.append(signins[j])
            j += 1
        out.append(_signins_out(run, more=signins_full and j == len(signins)))
    return out


@router.get("")
async def activity(admin: Admin, db: Db, limit: Annotated[int, Query(ge=1, le=LIMIT_MAX)] = 3) -> dict:
    """The newest `limit` lines (sign-ins joined, the admin's own left out), newest first."""
    rows = list(await db.scalars(_audit_query(admin.id, limit)))
    signed = select(User).where(User.last_login_at.is_not(None), User.id != admin.id)
    if len(rows) == limit:  # a sign-in older than all of them has no slot left
        signed = signed.where(User.last_login_at >= rows[-1].at)
    users = list(await db.scalars(signed.order_by(User.last_login_at.desc(), User.id).limit(SIGNINS_MAX + 1)))
    full = len(users) > SIGNINS_MAX
    users = users[:SIGNINS_MAX]
    # the accounts the entries are about, by their current name (the log keeps the sign-in name of then)
    ids = [u for e in rows if e.target_type == "user" and (u := _uuid(e.target_id)) is not None]
    names: dict[str, str] = {}
    states: dict[str, tuple] = {}
    if ids:
        q = select(User.id, User.display_name, User.is_active, User.deactivated_reason, User.pending_role).where(User.id.in_(ids))
        for i, d, active, reason, pending_role in (await db.execute(q)).all():
            if d:
                names[str(i)] = d
            states[str(i)] = (active, reason, pending_role)
    entries = [_entry_out(e, names, states) for e in rows]
    # what waits now (directory.pending_counts: accounts + raises – the number on "Benutzer"), in one statement
    waiting = or_(
        and_(User.is_active.is_(False), User.deactivated_reason == directory.PENDING, User.is_emergency.is_(False)),
        and_(User.is_active.is_(True), User.pending_role == "admin"),
    )
    pending = int(await db.scalar(select(func.count()).select_from(User).where(waiting)) or 0)
    return {"items": merge(entries, users, limit, full), "pending": pending}


def _uuid(v: str | None) -> uuid.UUID | None:
    try:
        return uuid.UUID(v) if v else None
    except ValueError:
        return None
