"""Meine Sitzungen: every signed-in person sees the sessions of their account and ends one or all others; admins do
the same for any account (re-confirmed).

- What a session shows: the browser's User-Agent (the page reads browser and system from it roughly), how it was
  signed in (sessions.METHODS – None for a session of an older version), when it began, when it was last active
  (written at most every sessions.TOUCH_INTERVAL – coarse on purpose, no write per request), until when it runs, and
  the full client address: it is the person's own data, and the admins see it in the access log anyway.
- Sign-ins under way (TOTP code, temporary password or TOTP set-up still open) are listed too, marked: one nobody
  expects means somebody knows the password.
- Ending a session deletes its row: its very next request is refused (sessions.load reads the row on every request).
  The own current session is not ended here (that is "Abmelden"): 409 current_session.
- Ending one's own sessions needs no re-confirmation – whoever has taken a session over can do nothing with it that the
  owner could not undo by signing in again. An admin ending someone's sessions is re-confirmed (deps.require_reauth).
- Audit log: every ending that ended something is `sessions.revoked` on the account – {scope: one | others | all,
  count, by_admin}, in the transaction of the deletion.
- Remembered devices ("Zweiten Faktor auf dem Gerät merken", app/auth/devices.py) are listed here too: forget one or
  all (the person; an admin re-confirmed). "Andere/Alle Sitzungen beenden" forgets them all as well – it is the button
  for "somebody else may have been in": every browser asks for the second factor again. The own list is served under
  /api/auth/devices – the device cookie (Path=/api/auth) comes along there, so the page can mark "dieses Gerät".
  Logged: device.forgotten {scope: one | all, count, by_admin}.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Request, Response
from sqlalchemy import delete, select

from app import audit
from app import settings as settings_store
from app.auth import devices, sessions
from app.deps import ActiveSession, Admin, Db, Reader, api_error, require_reauth
from app.models import User, UserPasskey, UserSession

router = APIRouter(prefix="/api", tags=["sessions"])
admin_router = APIRouter(prefix="/api/admin", tags=["admin"])


def _iso(v: datetime | None) -> str | None:
    return v.isoformat() if v else None


async def list_sessions(db, user_id: uuid.UUID, current: uuid.UUID | None) -> list[dict]:  # noqa: ANN001
    """The running sessions of one account – the current one first, then by last activity."""
    cfg = await settings_store.get(db, "sessions")
    t = datetime.now(UTC)
    rows = await db.execute(
        select(UserSession, UserPasskey.name).outerjoin(UserPasskey, UserPasskey.id == UserSession.passkey_id).where(UserSession.user_id == user_id)
    )
    out = []
    for s, passkey in rows:
        if sessions.ended(s, cfg, t):
            continue  # over – deleted when next used, or by the hourly cleanup
        out.append(
            {
                "id": str(s.id),
                "current": s.id == current,
                "stage": s.stage,
                "method": s.method,
                "passkey": passkey,
                "created_at": _iso(s.created_at),
                "last_seen_at": _iso(s.last_seen_at),
                "expires_at": _iso(s.expires_at),
                "ip": s.ip,
                "user_agent": s.user_agent or "",
            }
        )
    current_first = [x for x in out if x["current"]]
    rest = sorted((x for x in out if not x["current"]), key=lambda x: x["last_seen_at"] or "", reverse=True)
    return current_first + rest


def _log(db, actor: User, account: User, scope: str, n: int, by_admin: bool) -> None:  # noqa: ANN001
    """sessions.revoked on the account – only when something ended (nothing ended: nothing changed)."""
    if n:
        audit.record(db, actor, "sessions.revoked", audit.user_target(account), {"scope": scope, "count": n, "by_admin": by_admin})


async def _end_one(db, actor: User, account: User, sid: uuid.UUID, current: uuid.UUID, *, by_admin: bool) -> None:  # noqa: ANN001
    if sid == current:
        raise api_error(409, "current_session")  # that is "Abmelden"
    res = await db.execute(delete(UserSession).where(UserSession.id == sid, UserSession.user_id == account.id))
    if not res.rowcount:
        raise api_error(404, "not_found")  # unknown, over already – or another person's
    _log(db, actor, account, "one", res.rowcount, by_admin)
    await db.commit()


async def _end_all(db, actor: User, account: User, current: uuid.UUID, *, by_admin: bool) -> int:  # noqa: ANN001
    res = await db.execute(delete(UserSession).where(UserSession.user_id == account.id, UserSession.id != current))
    n = res.rowcount or 0
    _log(db, actor, account, "all" if by_admin else "others", n, by_admin)
    _forgotten(db, actor, account, "all", await devices.forget_all(db, account.id), by_admin)  # every browser asks again
    await db.commit()
    return n


def _forgotten(db, actor: User, account: User, scope: str, n: int, by_admin: bool, device: str | None = None) -> None:  # noqa: ANN001
    """device.forgotten on the account – only when something was forgotten."""
    if n:
        audit.record(db, actor, "device.forgotten", audit.user_target(account), {"scope": scope, "count": n, "by_admin": by_admin, **({"device": device} if device else {})})


# ---------------------------------------------------------------- own


@router.get("/me/sessions")
async def my_sessions(user: Reader, sess: ActiveSession, db: Db) -> list[dict]:
    return await list_sessions(db, user.id, sess.id)


@router.delete("/me/sessions/{sid}")
async def end_my_session(sid: uuid.UUID, user: Reader, sess: ActiveSession, db: Db) -> dict:
    await _end_one(db, user, user, sid, sess.id, by_admin=False)
    return {"ok": True}


@router.post("/me/sessions/end-others")
async def end_my_other_sessions(user: Reader, sess: ActiveSession, db: Db) -> dict:
    return {"ok": True, "ended": await _end_all(db, user, user, sess.id, by_admin=False)}


# ---------------------------------------------------------------- own remembered devices (under /api/auth: the cookie's path)


@router.get("/auth/devices")
async def my_devices(user: Reader, sess: ActiveSession, request: Request, db: Db) -> list[dict]:
    return await devices.listing(db, user, devices.cookie(request))


@router.delete("/auth/devices/{did}")
async def forget_my_device(did: uuid.UUID, user: Reader, sess: ActiveSession, request: Request, response: Response, db: Db) -> dict:
    row = await devices.forget_one(db, user.id, did)
    if row is None:
        raise api_error(404, "not_found")  # unknown, forgotten already – or another person's
    _forgotten(db, user, user, "one", 1, False, devices.label(row.user_agent))
    await db.commit()
    if (mine := devices.cookie(request)) and await devices.find(db, mine) is None:
        devices.clear_cookie(response)  # it was this browser's
    return {"ok": True}


@router.post("/auth/devices/forget-all")
async def forget_my_devices(user: Reader, sess: ActiveSession, response: Response, db: Db) -> dict:
    n = await devices.forget_all(db, user.id)
    _forgotten(db, user, user, "all", n, False)
    await db.commit()
    devices.clear_cookie(response)
    return {"ok": True, "forgotten": n}


# ---------------------------------------------------------------- admins


async def _target(db, uid: uuid.UUID) -> User:  # noqa: ANN001
    u = await db.get(User, uid)
    if u is None:
        raise api_error(404, "not_found")
    return u


@admin_router.get("/users/{uid}/sessions")
async def user_sessions(uid: uuid.UUID, admin: Admin, sess: ActiveSession, db: Db) -> list[dict]:
    await _target(db, uid)
    return await list_sessions(db, uid, sess.id)


@admin_router.delete("/users/{uid}/sessions/{sid}")
async def end_user_session(uid: uuid.UUID, sid: uuid.UUID, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    require_reauth(sess, admin)
    u = await _target(db, uid)
    await _end_one(db, admin, u, sid, sess.id, by_admin=True)
    return {"ok": True}


@admin_router.post("/users/{uid}/sessions/end-all")
async def end_user_sessions(uid: uuid.UUID, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """Every session of the account – the admin's own current one excepted (when it is the admin's own account)."""
    require_reauth(sess, admin)
    u = await _target(db, uid)
    return {"ok": True, "ended": await _end_all(db, admin, u, sess.id, by_admin=True)}


@admin_router.get("/users/{uid}/devices")
async def user_devices(uid: uuid.UUID, admin: Admin, db: Db) -> list[dict]:
    return await devices.listing(db, await _target(db, uid), None)


@admin_router.post("/users/{uid}/devices/forget-all")
async def forget_user_devices(uid: uuid.UUID, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """"Gemerkte Geräte vergessen": every browser of the account asks for its second factor again – re-confirmed, as
    ending its sessions."""
    require_reauth(sess, admin)
    u = await _target(db, uid)
    n = await devices.forget_all(db, u.id)
    _forgotten(db, admin, u, "all", n, True)
    await db.commit()
    return {"ok": True, "forgotten": n}
