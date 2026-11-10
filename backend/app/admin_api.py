"""Admin only: users, sign-in (AD/LDAP, Entra ID, sessions), directory group → role mappings, the HTTPS certificate.
Secrets (LDAP bind password, Entra client secret) are stored encrypted, never sent back – only whether one is set;
an empty field on saving keeps the stored one.

Sensitive changes (sign-in settings, group mappings, admins, resets, deletions) need a fresh proof of identity
(deps.require_reauth). Edits carry what they were made on – a user's `version`, a settings section's `rev` – and an edit
of an older state is refused (409 stale) instead of silently undoing another admin's change."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Query, Response
from fastapi.responses import StreamingResponse
from pydantic import ConfigDict, Field, field_validator
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.attributes import set_committed_value

from app import audit, crypto, passkeys_api, preload, tls
from app import settings as settings_store
from app.auth import bruteforce, devices, directory, entra, ldap_dir, lock_store, passwords, sessions
from app.auth_api import admins_count, user_out
from app.crypto import encrypt_str
from app.deps import ActiveSession, Admin, Db, DownloadGuard, NoNul, api_error, require_reauth
from app.models import AuditEntry, GroupMapping, Team, TeamMember, User, UserPasskey, UserSession

router = APIRouter(prefix="/api/admin", tags=["admin"])
Role = Literal["admin", "reader"]


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------- users


def _user_row(u: User, temp_days: int = passwords.TEMP_DAYS) -> dict:
    end = passwords.temp_expires_at(u, temp_days)
    return {
        **user_out(u),
        "is_active": u.is_active,
        "deactivated_reason": u.deactivated_reason,
        "must_change_password": u.must_change_password,
        # the temporary password's end (passwords.temp_expires_at) – after it the sign-in with it is refused
        "temp_password_expires_at": end.isoformat() if end else None,
        "temp_password_expired": bool(end and end <= datetime.now(UTC)),
        "locked_for": bruteforce.locked_for(bruteforce.lock_key(u)),
        # approval (app/auth/directory.py): a raise to admin waits ("admin") or was declined ("declined"); a waiting
        # account itself is deactivated_reason "pending"
        "pending_role": u.pending_role,
        "version": u.version or 1,
        "created_at": u.created_at.isoformat(),
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
    }


async def _temp_days(db) -> int:  # noqa: ANN001
    return passwords.temp_days(await settings_store.get(db, "sessions"))


@router.get("/users")
async def users(admin: Admin, db: Db) -> list[dict]:
    from app import teams

    rows = list(await db.scalars(select(User).order_by(User.role, User.username)))
    # Teams: the teams of each account and the state of its welcome e-mail (loaded accounts)
    welcome = await teams.welcome_of(db, rows)
    names: dict = {}
    for uid, name in await db.execute(select(TeamMember.user_id, Team.name).join(Team, Team.id == TeamMember.team_id).order_by(Team.name)):
        names.setdefault(uid, []).append(name)
    # passkeys per account (app/passkeys_api.py) – shown next to TOTP
    keys = dict((await db.execute(select(UserPasskey.user_id, func.count()).group_by(UserPasskey.user_id))).all())
    days = await _temp_days(db)
    return [{**_user_row(u, days), "teams": names.get(u.id, []), "welcome": welcome.get(u.id), "passkeys": int(keys.get(u.id, 0))} for u in rows]


@router.get("/users/pending")
async def users_pending(admin: Admin, db: Db) -> dict:
    """What waits for an admin's approval (the number on "Benutzer"): accounts – of them as admin – and raises to admin."""
    return await directory.pending_counts(db)


class UserIn(_M):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._@-]+$")
    display_name: str = Field(default="", max_length=255)
    email: str | None = Field(default=None, max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    role: Role = "reader"


async def _bump(db, u: User, version: int | None) -> None:
    """Optimistic concurrency: the edit was made on `version` (None: an older client – not checked); the counter goes up
    in the same transaction, conditionally – a parallel edit that got there first makes this one stale."""
    have = u.version or 1
    if version is not None and version != have:
        raise api_error(409, "stale")
    res = await db.execute(update(User).where(User.id == u.id, User.version == have).values(version=have + 1).execution_options(synchronize_session=False))
    if res.rowcount != 1:
        await db.rollback()
        raise api_error(409, "stale")
    set_committed_value(u, "version", have + 1)


@router.post("/users")
async def create_user(body: UserIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """A local account with a temporary password (shown once, changed at the first sign-in). An admin: re-confirmed."""
    if body.role == "admin":
        require_reauth(sess, admin)
    name = body.username.lower()
    if await db.scalar(select(User.id).where(User.username == name)):
        raise api_error(409, "username_taken")
    pw = passwords.temp_password()
    u = User(
        id=uuid.uuid4(),
        username=name,
        display_name=body.display_name or name,
        email=body.email,
        role=body.role,
        auth_source="local",
        password_hash=await passwords.ahash_password(pw),
        must_change_password=True,
        temp_password_at=datetime.now(UTC),
    )
    db.add(u)
    audit.record(db, admin, "user.created", audit.user_target(u), {"role": u.role, "auth_source": "local", "display_name": u.display_name, "email": u.email})
    try:
        await db.commit()
    except IntegrityError as exc:  # the same name created in parallel
        await db.rollback()
        raise api_error(409, "username_taken") from exc
    return {**_user_row(u, await _temp_days(db)), "temp_password": pw}


class UserPatch(_M):
    display_name: str | None = Field(default=None, max_length=255)
    email: str | None = Field(default=None, max_length=255, pattern=r"^([^@\s]+@[^@\s]+\.[^@\s]+)?$")
    role: Role | None = None
    is_active: bool | None = None
    version: int | None = None  # the state the edit was made on (409 stale otherwise)


async def _target(db, uid: uuid.UUID) -> User:
    u = await db.get(User, uid)
    if u is None:
        raise api_error(404, "not_found")
    return u


@router.patch("/users/{uid}")
async def patch_user(uid: uuid.UUID, body: UserPatch, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    u = await _target(db, uid)
    ch = body.model_dump(exclude_unset=True)
    version = ch.pop("version", None)
    if "role" in ch:
        require_reauth(sess, admin)  # making or unmaking an admin
    # an admin account switched on or off, or its e-mail changed: as sensitive as its role (switching one back on gives
    # its rights again; switching one off takes them from someone else)
    if u.role == "admin" and (("is_active" in ch and ch["is_active"] != u.is_active) or ("email" in ch and (ch["email"] or None) != u.email)):
        require_reauth(sess, admin)
    if ("role" in ch or ch.get("is_active") is False) and (u.is_emergency or u.id == admin.id):
        raise api_error(409, "user_protected")  # the emergency admin and oneself stay admin and active
    if "role" in ch and u.auth_source != "local":
        raise api_error(409, "directory_managed")  # the directory group decides
    if ch.get("is_active") and directory.is_pending(u):
        # switching a waiting account on is its approval – the same checks and the same entry as "Freigeben"
        if set(ch) - {"is_active"}:
            raise api_error(409, "approval_pending")
        return await _approve(u, version, admin, sess, db)
    # checked before anything is written: the last active admin is never demoted or switched off
    if u.role == "admin" and u.is_active and (ch.get("role") == "reader" or ch.get("is_active") is False) and await admins_count(db) <= 1:
        raise api_error(409, "last_admin")
    if "email" in ch:
        ch["email"] = ch["email"] or None
    await _bump(db, u, version)
    before = {"display_name": u.display_name, "email": u.email, "role": u.role, "is_active": u.is_active}
    for k, v in ch.items():
        if v is not None or k == "email":
            setattr(u, k, v)
    if ch.get("is_active") is False:
        u.deactivated_reason = "admin"
        await sessions.revoke_all(db, u.id)
    elif ch.get("is_active"):
        u.deactivated_reason = None
    if "role" in ch:
        await sessions.revoke_all(db, u.id)  # new rights at the next sign-in
    after = {"display_name": u.display_name, "email": u.email, "role": u.role, "is_active": u.is_active}
    who = audit.user_target(u)
    if changes := audit.diff(before, after, ("display_name", "email")):
        audit.record(db, admin, "user.changed", who, {"changes": changes})
    if before["role"] != u.role:
        audit.record(db, admin, "role.changed", who, {"changes": audit.diff(before, after, ("role",)), "sessions_ended": True})
    if before["is_active"] != u.is_active:
        audit.record(db, admin, "user.activated" if u.is_active else "user.deactivated", who, {"sessions_ended": not u.is_active})
    await db.commit()
    return _user_row(u, await _temp_days(db))


class BlockIn(_M):
    blocked: bool
    version: int | None = None


@router.post("/users/{uid}/block")
async def block_user(uid: uuid.UUID, body: BlockIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """The admin's lasting block ("admin") – also for an account the sync switched off (sync:…), whose switch is off
    already: neither a team load, the sync nor a sign-in switches it on again. Lifting it hands a directory account back
    to the sync – off ("sync:unblocked") until a sign-in or the next sync finds a mapped group (or a team) again; a local
    account is on at once (nothing else decides for it). Both re-confirmed, sessions end on blocking."""
    require_reauth(sess, admin)
    u = await _target(db, uid)
    if body.blocked:
        if u.is_emergency or u.id == admin.id:
            raise api_error(409, "user_protected")
        if u.role == "admin" and u.is_active and await admins_count(db) <= 1:
            raise api_error(409, "last_admin")
    elif u.is_active or u.deactivated_reason != "admin":
        raise api_error(409, "not_blocked")
    await _bump(db, u, body.version)
    if body.blocked:
        u.is_active, u.deactivated_reason = False, "admin"
        await sessions.revoke_all(db, u.id)
    elif u.auth_source == "local":
        u.is_active, u.deactivated_reason = True, None
    else:
        u.deactivated_reason = "sync:unblocked"
    audit.record(db, admin, "user.blocked" if body.blocked else "user.unblocked", audit.user_target(u), {"is_active": u.is_active, "reason": u.deactivated_reason})
    await db.commit()
    return _user_row(u, await _temp_days(db))


class ApprovalIn(_M):
    version: int | None = None  # the state the decision was made on (409 stale otherwise)


async def _approve(u: User, version: int | None, admin: User, sess, db) -> dict:  # noqa: ANN001
    """A waiting account switched on – with the role its groups give now (directory.approvable_role); one as admin
    re-confirmed. A role other than the one shown (a mapping changed meanwhile): the new one is stored and 409 stale – the
    admin decides on what is true now."""
    if not directory.is_pending(u) or u.auth_source == "local" or u.is_emergency:
        raise api_error(409, "not_pending")
    role = await directory.approvable_role(db, u)
    if role is None:
        raise api_error(409, "no_role")  # in no mapped group (nor a team) any more – nothing to give
    if role == "admin" or u.role == "admin":
        require_reauth(sess, admin)
    await _bump(db, u, version)
    if role != u.role:
        u.role = role
        await db.commit()
        raise api_error(409, "stale")
    await directory.approve(db, u, role, admin)
    await db.commit()
    return _user_row(u, await _temp_days(db))


@router.post("/users/{uid}/approve")
async def approve_user(uid: uuid.UUID, body: ApprovalIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """"Freigeben": a directory account waiting for approval is switched on (as admin: re-confirmed). Logged."""
    return await _approve(await _target(db, uid), body.version, admin, sess, db)


@router.post("/users/{uid}/decline")
async def decline_user(uid: uuid.UUID, body: ApprovalIn, admin: Admin, db: Db) -> dict:
    """"Ablehnen": a waiting account stays off – an admin's "off" (like a block: the directory never switches it on; the
    block can be lifted later). Logged."""
    u = await _target(db, uid)
    if not directory.is_pending(u) or u.auth_source == "local" or u.is_emergency:
        raise api_error(409, "not_pending")
    await _bump(db, u, body.version)
    directory.decline(db, u, admin)
    await db.commit()
    return _user_row(u, await _temp_days(db))


@router.post("/users/{uid}/approve-role")
async def approve_raise(uid: uuid.UUID, body: ApprovalIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """"Aufstieg freigeben": a reader whose groups give admin becomes admin – re-confirmed, its sessions end (the next
    sign-in asks for the admin's second factor). Also after a declined raise, while the groups still give admin."""
    require_reauth(sess, admin)
    u = await _target(db, uid)
    if not u.is_active or u.pending_role not in ("admin", directory.RAISE_DECLINED) or u.role != "reader" or u.auth_source == "local":
        raise api_error(409, "not_pending")
    if await directory.approvable_role(db, u) != "admin":
        await _bump(db, u, body.version)
        u.pending_role = None  # the groups give admin no more – nothing waits
        await db.commit()
        raise api_error(409, "no_role")
    await _bump(db, u, body.version)
    await directory.approve_raise(db, u, admin)
    await db.commit()
    return _user_row(u, await _temp_days(db))


@router.post("/users/{uid}/decline-role")
async def decline_raise(uid: uuid.UUID, body: ApprovalIn, admin: Admin, db: Db) -> dict:
    """"Bleibt Leser": the waiting raise declined – not asked again while the account stays in the admin groups."""
    u = await _target(db, uid)
    if not u.is_active or u.pending_role != "admin" or u.auth_source == "local":
        raise api_error(409, "not_pending")
    await _bump(db, u, body.version)
    directory.decline_raise(db, u, admin)
    await db.commit()
    return _user_row(u, await _temp_days(db))


class ResetIn(_M):
    password: bool = True
    totp: bool = False
    # the account's passkeys removed too – by default with the password: a reset after a takeover must leave no way in
    # that the other person set up (None: as `password`)
    passkeys: bool | None = None
    version: int | None = None


@router.post("/users/{uid}/reset")
async def reset_user(uid: uuid.UUID, body: ResetIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """A new temporary password and/or the TOTP removed (set up again at the next sign-in), with the password the
    passkeys too (ResetIn.passkeys); all sessions end."""
    require_reauth(sess, admin)
    u = await _target(db, uid)
    if u.auth_source != "local" and body.password:
        raise api_error(409, "directory_managed")
    if u.is_emergency or u.id == admin.id:
        raise api_error(409, "user_protected")  # oneself: Mein Konto; the emergency admin: python -m app.cli reset-emergency
    out: dict = {}
    await _bump(db, u, body.version)
    if body.password:
        pw = passwords.temp_password()
        new_hash = await passwords.ahash_password(pw)
        await passwords.remember(db, u)  # the person's own password stays refused after the reset (not the temporary one)
        u.password_hash, u.must_change_password, u.temp_password_at = new_hash, True, datetime.now(UTC)
        out["temp_password"] = pw
    if body.totp:
        u.totp_secret_enc, u.totp_last_step = None, None
    gone = await passkeys_api.remove_all_of(db, u.id) if (body.password if body.passkeys is None else body.passkeys) else 0
    out["passkeys_removed"] = gone
    bruteforce.unlock(bruteforce.lock_key(u))
    await lock_store.write(db, bruteforce.take_dirty())  # the stored lock goes with the change
    await sessions.revoke_all(db, u.id)
    audit.record(db, admin, "user.reset", audit.user_target(u), {"password": body.password, "totp": body.totp, "sessions_ended": True})
    if gone:
        audit.record(db, admin, "passkey.removed", audit.user_target(u), {"by_admin": True, "reset": True, "count": gone})
    await db.commit()
    return {**_user_row(u, await _temp_days(db)), **out}


@router.post("/users/{uid}/unlock")
async def unlock_user(uid: uuid.UUID, admin: Admin, db: Db) -> dict:
    u = await _target(db, uid)
    locked = bruteforce.locked_for(bruteforce.lock_key(u))
    bruteforce.unlock(bruteforce.lock_key(u))
    await lock_store.write(db, bruteforce.take_dirty())  # the stored lock goes with it (it would come back at a restart)
    audit.record(db, admin, "user.unlocked", audit.user_target(u), {"was_locked_s": locked})
    await db.commit()
    return _user_row(u, await _temp_days(db))


@router.delete("/users/{uid}")
async def delete_user(uid: uuid.UUID, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    require_reauth(sess, admin)
    u = await _target(db, uid)
    if u.is_emergency or u.id == admin.id:
        raise api_error(409, "user_protected")
    # before the delete (afterwards it would be too late): cannot happen while the emergency admin exists – a guard all the same
    if u.role == "admin" and u.is_active and await admins_count(db) <= 1:
        raise api_error(409, "last_admin")
    audit.record(db, admin, "user.deleted", audit.user_target(u), {"role": u.role, "auth_source": u.auth_source, "display_name": u.display_name})
    await db.delete(u)
    await db.commit()
    return {"ok": True}


# ---------------------------------------------------------------- sign-in: sessions, AD/LDAP, Entra


# a settings section written only when it is still the one the form was loaded with (409 stale otherwise)
_put_section = settings_store.put_rev


class SessionsIn(_M):
    idle_min: int = Field(ge=5, le=480)
    absolute_h: int = Field(ge=1, le=72)
    temp_password_days: int | None = Field(default=None, ge=1, le=30)  # None: an older client – the stored value stays
    rev: int | None = None


@router.get("/auth/sessions")
async def get_sessions(admin: Admin, db: Db) -> dict:
    cfg = await settings_store.get(db, "sessions")
    return {**cfg, "temp_password_days": passwords.temp_days(cfg), "rev": int(cfg.get("rev") or 0)}


@router.put("/auth/sessions")
async def put_sessions(body: SessionsIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    require_reauth(sess, admin)
    current = await settings_store.get(db, "sessions")
    new = body.model_dump(exclude={"rev"})
    if new["temp_password_days"] is None:
        new["temp_password_days"] = passwords.temp_days(current)
    if changes := audit.diff(current, new, new.keys()):
        audit.record(db, admin, "signin.config_changed", audit.target("signin", "sessions", "sessions"), {"changes": changes})
    out = await _put_section(db, "sessions", new, body.rev)
    # a shorter absolute lifetime holds for the sessions already running too (sessions.load checks it as well)
    cap = timedelta(hours=body.absolute_h)
    for s in await db.scalars(select(UserSession).where(UserSession.stage == "active")):
        if s.created_at + cap < s.expires_at:
            s.expires_at = s.created_at + cap
    await db.commit()
    return out


async def _switching_off(db, source: str, current: dict, enabled: bool, end_sessions: bool, admin: User) -> None:  # noqa: ANN001
    """AD/LDAP or Entra ID switched off: the admin doing it must not be an account of it – it could not sign in again
    (409 own_source: switch it off from a local account, the emergency admin for one). With `end_sessions` the sessions
    of its accounts end at once (in the transaction the settings are saved in) – otherwise they run out by themselves."""
    if not current.get("enabled") or enabled:
        return
    if admin.auth_source == source:
        raise api_error(409, "own_source")
    if end_sessions:
        n = await directory.source_impact(db, source)
        await directory.end_source_sessions(db, source)
        audit.record(db, admin, "sessions.revoked", audit.target("signin", source, source), {"why": "source_off", "accounts": n})


def _signin_changed(db, admin: User, source: str, current: dict, data: dict) -> None:  # noqa: ANN001
    """AD/LDAP or Entra ID saved: the changed fields in the audit log – the stored secret only as "changed"."""
    if changes := audit.diff(current, data, data.keys()):
        audit.record(db, admin, "signin.config_changed", audit.target("signin", source, source), {"changes": changes})


class MfaIn(_M):
    required_all: bool
    # "Zweiten Faktor auf dem Gerät merken" (app/auth/devices.py) – None: an older client, the stored value stays
    remember: bool | None = None
    remember_days: Literal[0, 1, 7, 30] | None = None  # 0: the maximum session lifetime
    remember_admins: bool | None = None
    rev: int | None = None


def _mfa_out(cfg: dict) -> dict:
    return {
        "required_all": bool(cfg["required_all"]),
        "remember": bool(cfg.get("remember")),
        "remember_days": devices.days_of(cfg),
        "remember_admins": bool(cfg.get("remember_admins")),
        "rev": int(cfg.get("rev") or 0),
    }


async def _session_h(db) -> int:  # noqa: ANN001
    """The maximum session lifetime – what "Sitzungsdauer" means for the remembered devices (shown with the choice)."""
    return int((await settings_store.get(db, "sessions"))["absolute_h"])


@router.get("/auth/mfa")
async def get_mfa(admin: Admin, db: Db) -> dict:
    return {**_mfa_out(await settings_store.get(db, "mfa")), "session_h": await _session_h(db)}


@router.put("/auth/mfa")
async def put_mfa(body: MfaIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """"Zweiter Faktor für alle": readers (local, AD/LDAP; Entra without a proof in the token) set up TOTP – a local one
    also a passkey – at their next sign-in. Sessions already running are not ended: they go on until they end.
    "Zweiten Faktor auf dem Gerät merken": switched off, every remembered device is forgotten (switching it on again
    brings none back); admins excluded again, theirs; a shorter duration counts at once (devices.valid)."""
    require_reauth(sess, admin)
    current = _mfa_out(await settings_store.get(db, "mfa"))
    value = {
        "required_all": body.required_all,
        "remember": current["remember"] if body.remember is None else body.remember,
        "remember_days": current["remember_days"] if body.remember_days is None else body.remember_days,
        "remember_admins": current["remember_admins"] if body.remember_admins is None else body.remember_admins,
    }
    forgotten = 0
    if current["remember"] and not value["remember"]:
        forgotten = await devices.forget_everyone(db)
    elif current["remember_admins"] and not value["remember_admins"]:
        forgotten = await devices.forget_everyone(db, admins_only=True)
    if changes := audit.diff(current, value, value.keys()):
        audit.record(db, admin, "signin.config_changed", audit.target("signin", "mfa", "mfa"), {"changes": changes, **({"devices_forgotten": forgotten} if forgotten else {})})
    out = await _put_section(db, "mfa", value, body.rev)  # commits – with the forgotten devices (a stale save: neither)
    return {**_mfa_out(out), "session_h": await _session_h(db)}


class PendingIn(_M):
    accounts: int = Field(ge=0)
    accounts_admin: int = Field(ge=0)
    raises: int = Field(ge=0)


class ApprovalSettingsIn(_M):
    auto_signin: bool
    # switching it on: also approve everything that waits (accounts and raises to admin) – an explicit choice, off by
    # default (nothing waiting is switched on silently)
    approve_pending: bool = False
    # with approve_pending: what the dialog showed (GET …/approval) – something else waiting now is 409 "stale"
    expect: PendingIn | None = None
    rev: int | None = None


async def _approval_state(db) -> dict:  # noqa: ANN001
    cfg = await settings_store.get(db, directory.SECTION)
    active = await db.scalar(select(func.count()).select_from(User).where(User.auth_source.in_(("ldap", "entra")), User.is_active.is_(True), User.is_emergency.is_(False)))
    return {"auto_signin": bool(cfg.get("auto_signin", True)), "rev": int(cfg.get("rev") or 0), "active_directory": int(active or 0), **await directory.pending_counts(db)}


@router.get("/auth/approval")
async def get_approval(admin: Admin, db: Db) -> dict:
    """"Automatische Anmeldung über AD/Entra ID zulassen" and what switching it concerns: the directory accounts that
    are on (they stay on when it is switched off), what waits (it keeps waiting when it is switched on – unless
    approve_pending)."""
    return await _approval_state(db)


@router.put("/auth/approval")
async def put_approval(body: ApprovalSettingsIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """Switched off: new directory accounts and raises to admin wait for an admin's approval; the accounts on now stay
    on. Switched on: new ones sign in at once again; what waits keeps waiting – or, with approve_pending, is approved
    now (each account logged). Re-confirmed."""
    require_reauth(sess, admin)
    if body.approve_pending and not body.auto_signin:
        raise api_error(422, "approve_needs_auto")
    current = await settings_store.get(db, directory.SECTION)
    value = {"auto_signin": body.auto_signin}
    approved = {"accounts": 0, "raises": 0}
    if body.approve_pending:
        if body.expect is None:
            raise api_error(422, "approve_needs_counts")
        # locked: a decline or a sign-in at the same moment waits – never written over
        pending = select(User).where(User.is_active.is_(False), User.deactivated_reason == directory.PENDING, User.is_emergency.is_(False), User.auth_source != "local")
        accounts = list(await db.scalars(pending.order_by(User.id).with_for_update()))
        raises = list(await db.scalars(select(User).where(User.is_active.is_(True), User.pending_role == "admin", User.role == "reader").order_by(User.id).with_for_update()))
        # never more than the dialog showed: the rows are locked now – what waits is counted as GET …/approval counts
        # it; an account that came (or was decided) since the dialog opened refuses the whole save
        now = await directory.pending_counts(db)
        if {k: now[k] for k in ("accounts", "accounts_admin", "raises")} != body.expect.model_dump():
            await db.rollback()
            raise api_error(409, "stale")
        for u in accounts:
            role = await directory.approvable_role(db, u)
            if role is None:
                continue  # in no mapped group any more: stays waiting (the preload deletes it once unused)
            await directory.approve(db, u, role, admin, why="bulk")
            u.version = (u.version or 1) + 1
            approved["accounts"] += 1
        for u in raises:
            if await directory.approvable_role(db, u) != "admin":
                continue
            await directory.approve_raise(db, u, admin, why="bulk")
            u.version = (u.version or 1) + 1
            approved["raises"] += 1
    if changes := audit.diff({"auto_signin": bool(current.get("auto_signin", True))}, value, value.keys()):
        audit.record(db, admin, "signin.config_changed", audit.target("signin", directory.SECTION, directory.SECTION), {"changes": changes, **({"approved": approved} if body.approve_pending else {})})
    await _put_section(db, directory.SECTION, value, body.rev)  # commits – the approvals with it, or nothing (stale)
    return {**await _approval_state(db), "approved": approved}


@router.get("/auth/{source}/impact")
async def source_impact(source: Literal["ldap", "entra"], admin: Admin, db: Db) -> dict:
    """What switching the source off would do: the accounts of it signed in now, and whether the admin is one."""
    return {"accounts": await directory.source_impact(db, source), "self": admin.auth_source == source}


def _public_ldap(cfg: dict) -> dict:
    out = {k: v for k, v in cfg.items() if k != "bind_password_enc"}
    out["bind_password_set"] = bool(cfg.get("bind_password_enc"))
    out["rev"] = int(cfg.get("rev") or 0)
    out["usable"] = ldap_dir.usable(cfg)
    return out


class LdapIn(_M):
    enabled: bool = False
    servers: list[str] = Field(default_factory=list, max_length=4)
    encryption: Literal["ldaps", "starttls", "none"] = "ldaps"
    allow_plain: bool = False
    verify_cert: bool = True
    ca_cert: str = Field(default="", max_length=20000)
    base_dn: str = Field(default="", max_length=500)
    bind_dn: str = Field(default="", max_length=500)
    bind_password: str = Field(default="", max_length=500)  # empty: keep the stored one
    user_filter: str = Field(default=settings_store.LDAP_FILTER, max_length=500)
    nested_groups: bool = True
    timeout: int = Field(default=10, ge=2, le=60)
    rev: int | None = None  # the state the form was loaded with (409 stale otherwise)
    end_sessions: bool = True  # switched off: the sessions of its accounts end at once (not stored)

    @field_validator("servers")
    @classmethod
    def _servers(cls, v: list[str]) -> list[str]:
        out = [x.strip() for x in v if x.strip()]
        for x in out:
            if not all(c.isalnum() or c in ".-:[]" for c in x):
                raise ValueError("invalid server")
        return out

    @field_validator("user_filter")
    @classmethod
    def _filter(cls, v: str) -> str:
        if "{username}" not in v or not v.startswith("(") or v.count("(") != v.count(")"):
            raise ValueError("filter needs {username}")
        return v


# the stored bind password goes only to the server, account and TLS settings it was entered for
LDAP_SECRET_BOUND = ("servers", "encryption", "allow_plain", "verify_cert", "ca_cert", "bind_dn")


def _ldap_value(body: LdapIn, current: dict) -> dict:
    data = body.model_dump(exclude={"rev", "end_sessions"})
    pw = data.pop("bind_password")
    if data["encryption"] == "none" and not data["allow_plain"]:
        raise api_error(422, "ldap_plain_refused")
    if not pw and current.get("bind_password_enc") and any(data[k] != current.get(k) for k in LDAP_SECRET_BOUND):
        raise api_error(422, "secret_required")  # enter it again – it would otherwise go to a new server or account
    data["bind_password_enc"] = encrypt_str(pw) if pw else current.get("bind_password_enc", "")
    if not data["base_dn"] and data["servers"]:
        data["base_dn"] = ldap_dir.derive_base_dn(data["servers"][0])
    return data


@router.get("/auth/ldap")
async def get_ldap(admin: Admin, db: Db) -> dict:
    return _public_ldap(await settings_store.get(db, "ldap"))


@router.put("/auth/ldap")
async def put_ldap(body: LdapIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    require_reauth(sess, admin)
    current = await settings_store.get(db, "ldap")
    data = _ldap_value(body, current)
    await _switching_off(db, "ldap", current, body.enabled, body.end_sessions, admin)
    _signin_changed(db, admin, "ldap", current, data)
    return _public_ldap(await _put_section(db, "ldap", data, body.rev))


@router.post("/auth/ldap/test")
async def test_ldap(body: LdapIn, admin: Admin, db: Db) -> dict:
    """The form as it is (not saved yet), with the stored password when none was typed: service bind + base search."""
    data = _ldap_value(body, await settings_store.get(db, "ldap"))
    try:
        return await ldap_dir.run(ldap_dir.test, data)
    except ldap_dir.LdapError as exc:
        return {"ok": False, "error": exc.category}


@router.get("/auth/ldap/groups")
async def ldap_groups(admin: Admin, db: Db, q: str = Query(default="", max_length=100)) -> list[dict]:
    try:
        return await ldap_dir.run(ldap_dir.search_groups, await settings_store.get(db, "ldap"), q)
    except ldap_dir.LdapError as exc:
        raise api_error(502, "directory_unavailable", reason=exc.category) from exc


def _public_entra(cfg: dict) -> dict:
    out = {k: v for k, v in cfg.items() if k != "client_secret_enc"}
    out["client_secret_set"] = bool(cfg.get("client_secret_enc"))
    out["rev"] = int(cfg.get("rev") or 0)
    out["redirect_uri"] = entra.redirect_uri()
    out["usable"] = entra.usable(cfg)
    return out


GUID = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"


class EntraIn(_M):
    enabled: bool = False
    tenant_id: str = Field(default="", pattern=rf"({GUID})|^$")
    client_id: str = Field(default="", pattern=rf"({GUID})|^$")
    client_secret: str = Field(default="", max_length=500)
    # "MFA-Nachweis" (app/auth/entra.py): None – an older client: the stored choice stays
    mfa_mode: Literal["entra", "context", "require"] | None = None
    auth_context: str | None = Field(default=None, pattern=r"^([cC]([1-9]|[1-9][0-9]))?$")  # C1–C99, as in Entra
    rev: int | None = None
    end_sessions: bool = True  # as LdapIn


def _entra_value(body: EntraIn, current: dict) -> dict:
    data = body.model_dump(exclude={"rev", "end_sessions"})
    secret = data.pop("client_secret")
    data["tenant_id"], data["client_id"] = data["tenant_id"].lower(), data["client_id"].lower()
    data["mfa_mode"] = data["mfa_mode"] or entra.mfa_mode(current)
    data["auth_context"] = (data["auth_context"] if data["auth_context"] is not None else str(current.get("auth_context") or "")).lower()
    if data["mfa_mode"] == "context" and not data["auth_context"]:
        raise api_error(400, "auth_context_missing")  # the mode needs the context it asks for
    data["client_secret_enc"] = encrypt_str(secret) if secret else current.get("client_secret_enc", "")
    return data


@router.get("/auth/entra")
async def get_entra(admin: Admin, db: Db) -> dict:
    return _public_entra(await settings_store.get(db, "entra"))


@router.put("/auth/entra")
async def put_entra(body: EntraIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    require_reauth(sess, admin)
    current = await settings_store.get(db, "entra")
    data = _entra_value(body, current)
    await _switching_off(db, "entra", current, body.enabled, body.end_sessions, admin)
    _signin_changed(db, admin, "entra", current, data)
    return _public_entra(await _put_section(db, "entra", data, body.rev))


@router.post("/auth/entra/test")
async def test_entra(body: EntraIn, admin: Admin, db: Db) -> dict:
    try:
        return await entra.test(_entra_value(body, await settings_store.get(db, "entra")))
    except entra.EntraError as exc:
        return {"ok": False, "error": exc.category}


@router.get("/auth/entra/groups")
async def entra_groups(admin: Admin, db: Db, q: str = Query(default="", max_length=100)) -> list[dict]:
    try:
        return await entra.search_groups(await settings_store.get(db, "entra"), q)
    except entra.EntraError as exc:
        raise api_error(502, "directory_unavailable", reason=exc.category) from exc


# ---------------------------------------------------------------- group → role


def _mapping_target(m: GroupMapping) -> audit.Target:
    return audit.target("role_mapping", m.id, m.group_name or m.group_id)


def _mapping(m: GroupMapping) -> dict:
    return {"id": str(m.id), "source": m.source, "group_id": m.group_id, "group_name": m.group_name, "role": m.role}


@router.get("/auth/mappings")
async def mappings(admin: Admin, db: Db) -> list[dict]:
    rows = await db.scalars(select(GroupMapping).order_by(GroupMapping.source, GroupMapping.group_name))
    return [_mapping(m) for m in rows]


class MappingIn(_M):
    source: Literal["ldap", "entra"]
    group_id: str = Field(min_length=3, max_length=500)
    group_name: str = Field(default="", max_length=255)
    role: Role

    @field_validator("group_id")
    @classmethod
    def _gid(cls, v: str) -> str:
        if "=" not in v and len(v) != 36:
            raise ValueError("a DN or an object id")
        return v


@router.post("/auth/mappings")
async def add_mapping(body: MappingIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    require_reauth(sess, admin)  # a mapped group decides who becomes admin
    if await db.scalar(select(GroupMapping.id).where(GroupMapping.source == body.source, GroupMapping.group_id == body.group_id)):
        raise api_error(409, "mapping_exists")
    m = GroupMapping(id=uuid.uuid4(), **body.model_dump())
    db.add(m)
    audit.record(db, admin, "role_mapping.created", _mapping_target(m), {"source": m.source, "group_id": m.group_id, "role": m.role})
    try:
        await db.commit()
    except IntegrityError as exc:  # the same mapping added in parallel
        await db.rollback()
        raise api_error(409, "mapping_exists") from exc
    preload.start()  # its members get their accounts now (app/preload.py) – in the background
    return _mapping(m)


@router.get("/auth/mappings/{mid}/impact")
async def mapping_impact(mid: uuid.UUID, admin: Admin, db: Db) -> dict:
    """Before removing: whom it concerns (from the groups kept with the accounts – the directory is not asked)."""
    m = await db.get(GroupMapping, mid)
    if m is None:
        raise api_error(404, "not_found")
    return await directory.reassess_mapping(db, m.source, m.group_id, m.role, me=admin.id)


@router.delete("/auth/mappings/{mid}")
async def delete_mapping(mid: uuid.UUID, admin: Admin, sess: ActiveSession, db: Db, end_sessions: bool = Query(default=True)) -> dict:
    """With `end_sessions` (the default) the accounts are re-checked at once (directory.reassess_mapping): who loses the
    role or falls to reader is signed out now – not at the next sync, or after the session's end when the directory
    cannot be reached. The admin's own access through this group: 409 own_access (remove it from another admin)."""
    require_reauth(sess, admin)
    m = await db.get(GroupMapping, mid)
    if m is None:
        raise api_error(404, "not_found")
    source, group_id, role = m.source, m.group_id, m.role
    if (await directory.reassess_mapping(db, source, group_id, role, me=admin.id))["self"]:
        raise api_error(409, "own_access")
    who = _mapping_target(m)
    await db.delete(m)
    await db.flush()
    out = {"affected": 0}
    if end_sessions:
        out = await directory.reassess_mapping(db, source, group_id, role, me=admin.id, apply=True, actor=admin)
    audit.record(db, admin, "role_mapping.deleted", who, {"source": source, "group_id": group_id, "role": role, "recheck": end_sessions, **{k: out.get(k, 0) for k in ("lost", "demoted", "unknown", "affected")}})
    await db.commit()
    preload.start()  # accounts that never signed in and are in no mapped group any more go (app/preload.py)
    return {"ok": True, **out}


# ---------------------------------------------------------------- HTTPS


EMERGENCY_ALERT_SHOWN = timedelta(hours=24)


async def system_warnings(db) -> list[dict]:  # noqa: ANN001
    """What needs an admin's look besides the certificate (shown above it, Einstellungen → HTTPS): a short master key
    (crypto.key_weakness – "env" SECRET_KEY / "file" secret.key) and, for 24 hours, that the emergency admin's failure
    budget was exceeded (the audit entry login.emergency_slowed – it survives a restart)."""
    out: list[dict] = []
    if weak := await asyncio.to_thread(crypto.key_weakness):
        out.append({"code": "secret_key_short", "source": weak, "min": crypto.MIN_STRONG_KEY})
    since = datetime.now(UTC) - EMERGENCY_ALERT_SHOWN
    last = await db.scalar(select(AuditEntry).where(AuditEntry.action == "login.emergency_slowed", AuditEntry.at >= since).order_by(AuditEntry.at.desc()).limit(1))
    if last is not None:
        out.append({"code": "emergency_failures", "at": last.at.isoformat(), "failures": int((last.details or {}).get("failures_1h") or 0)})
    return out


@router.get("/tls")
async def tls_status(admin: Admin, db: Db) -> dict:
    out = await asyncio.to_thread(tls.status)
    return {**out, "system": await system_warnings(db)}


@router.get("/tls/cobe.crt")
async def tls_download(admin: Admin) -> Response:
    """The certificate as served – public part only, never the key."""
    pem = await asyncio.to_thread(tls.pem)
    if pem is None:
        raise api_error(404, "not_found")
    return Response(pem, media_type="application/x-pem-file", headers={"Content-Disposition": 'attachment; filename="cobe-news.crt"'})


# ---------------------------------------------------------------- backup and export (app/backup.py)


@router.get("/backup")
async def backup_status(admin: Admin, db: Db) -> dict:
    from app import backup

    return await backup.status(db)


@router.post("/backup", status_code=202)
async def backup_now(admin: Admin, db: Db) -> dict:
    """A backup now (pg_dump; with BACKUP_PASSPHRASE encrypted and with the key) – in the background: the answer comes
    at once, GET /backup tells when it is done ("running", then "last"). One at a time: 409 busy."""
    from app import backup

    if await backup.running(db) or not backup.start(audit.actor_of(admin)):  # logged when it is done (backup.create)
        raise api_error(409, "backup_busy")
    await db.commit()
    return {"started": True, "status": await backup.status(db)}


BACKUP_DOWNLOAD_PATH = "/api/admin/backup/download/"  # + the ticket: never in a log (main.shown_path, nginx access_log off)


@router.post("/backup/files/{name}/ticket")
async def backup_download_ticket(name: str, admin: Admin, sess: ActiveSession) -> dict:
    """Step 1 of an encrypted backup's (.tar.enc) download – a fresh proof of identity first (it is the whole database,
    readable with the passphrase), only from this site's page (a write: the CSRF token), a few per hour and one at a
    time per admin; refused here with the reason (the page shows it). The answer: the address the browser downloads it
    from (step 2) – with a ticket for this admin, this session and this file, used once, valid for a minute. An
    unencrypted one stays on the server (403)."""
    from app import backup

    require_reauth(sess, admin)
    try:
        ticket = backup.issue_ticket(name, str(admin.id), str(sess.id))
    except backup.DownloadRefused as exc:
        raise api_error(exc.status, exc.code, **({"retry_after": exc.retry} if exc.retry else {})) from None
    return {"url": f"{BACKUP_DOWNLOAD_PATH}{ticket}", "expires_in": int(backup.TICKET_TTL)}


@router.get("/backup/download/{ticket}")
async def backup_download(ticket: str, admin: Admin, sess: ActiveSession, db: Db) -> StreamingResponse:
    """Step 2: the browser's own download (an <a download> of the page – saved straight to disk, never whole in the
    page's memory). The ticket stands in for the CSRF token: only the page that asked for it knows it, and it counts
    only with the same admin's same session (the session cookie). Logged when it starts (backup.downloaded, notable),
    streamed: never whole in memory either."""
    from app import backup

    uid = str(admin.id)
    try:
        name = backup.redeem_ticket(ticket, uid, str(sess.id))
        dl = backup.prepare_download(name, uid)  # checked again: removed meanwhile, another download running, the limit
    except backup.DownloadRefused as exc:
        raise api_error(exc.status, exc.code, **({"retry_after": exc.retry} if exc.retry else {})) from None
    try:
        audit.record(db, admin, "backup.downloaded", audit.target("backup", dl.name, dl.name), {"size": dl.size, "encrypted": True})
        await db.commit()
    except BaseException:
        backup.release_download(dl, uid)  # no answer goes out: the slot is free again
        raise
    headers = {
        "Content-Disposition": f'attachment; filename="{dl.name}"',  # the name matched backup.NAME_RX: no quote, no path
        "Content-Length": str(dl.size),
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    return _BackupStream(dl, uid, backup.stream_download(dl, uid), media_type="application/octet-stream", headers=headers)


class _BackupStream(StreamingResponse):
    """The download's answer: frees the admin's slot once it is over however it ends – sent, failed, cancelled, or the
    client gone before the body began (then the stream itself never runs and could not free it)."""

    def __init__(self, dl, uid: str, *a, **kw) -> None:  # noqa: ANN001, ANN002, ANN003 - a backup.Download
        super().__init__(*a, **kw)
        self._dl, self._uid = dl, uid

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
        from app import backup

        try:
            await super().__call__(scope, receive, send)
        finally:
            backup.release_download(self._dl, self._uid)


class BackupSettingsIn(_M):
    keep: Literal[3, 7, 14, 30, 90]
    rev: int | None = None


@router.put("/backup")
async def backup_settings(body: BackupSettingsIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    from app import backup

    conf = await settings_store.get(db, backup.SECTION)
    if body.keep < int(conf.get("keep") or 7):
        require_reauth(sess, admin)  # fewer backups kept: older ones are deleted at once
    if changes := audit.diff({"keep": int(conf.get("keep") or 7)}, {"keep": body.keep}):
        audit.record(db, admin, "settings.changed", audit.target("settings", backup.SECTION, backup.SECTION), {"changes": changes})
    await settings_store.put_rev(db, backup.SECTION, {"keep": body.keep}, body.rev)
    if gone := backup.prune(body.keep):
        # the files are gone already (no transaction holds a file): their names logged right after
        audit.record(db, admin, "backup.deleted", audit.target("backup", None, None), {"files": gone, "why": "keep"})
        await db.commit()
    return await backup.status(db)


@router.get("/export")
async def export(admin: Admin, sess: ActiveSession, db: Db, _guard: DownloadGuard, format: Literal["json", "csv"] = "json") -> Response:  # noqa: A002 - the query name
    """Rules, channels, sources, followed products with versions and users – without any secret, but with every user's
    name and e-mail: a fresh proof of identity first, as for the user administration."""
    from app import backup

    require_reauth(sess, admin)

    body, name, media = await backup.export_file(db, format)
    audit.record(db, admin, "export.downloaded", None, {"format": format})
    await db.commit()
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})
