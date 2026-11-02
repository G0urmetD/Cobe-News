"""Sign-in: first-start setup with the one-time token from the log, local and
AD/LDAP accounts (password → TOTP), Entra ID (OIDC + PKCE), sessions, the own account.

Stages of a session: mfa (TOTP code asked) → password (a temporary password is replaced) → enroll (an admin without
TOTP sets it up; a reader too while "Zweiter Faktor für alle" is on – or, local, registers a passkey) → active.
Entra accounts: Microsoft's MFA (Conditional Access) – proven by the token, or else Cobe News' own TOTP where a second
factor is required (factor_required, entra_stage; app/auth/entra.py mfa_proven)."""

import asyncio
import hmac
import json
import logging
import re
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import ConfigDict, Field
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.attributes import set_committed_value

from app import audit, netaddr
from app import db as dbm
from app import settings as settings_store
from app.auth import bruteforce, directory, entra, ldap_dir, lock_store, passwords, sessions, totp, webauthn
from app.config import get_config
from app.crypto import decrypt_str, encrypt_str, human_code, normalize_code, token_hash
from app.deps import ActiveSession, Db, NoNul, PeekedSession, Reader, api_error, client_ip, optional_session, session_in_stage, user_agent
from app.models import Setting, User, UserPasskey, UserSession

log = logging.getLogger("cobe_news.auth")
router = APIRouter(prefix="/api", tags=["auth"])

SETUP_TTL = 3600
MFA_MAX_FAILURES = 5
OIDC_COOKIE = "cobe_news_oidc"
OIDC_TTL = 600
OIDC_PER_IP = 30  # sign-in starts per address and 10 minutes
OIDC_PER_SHARED = 300  # … through an address everybody shares (Docker gateway, proxy): not one person's limit
REAUTH_SKEW = 120  # s: Entra's auth_time may be this much before the re-confirmation started (clocks)
_oidc_starts: dict[str, list[float]] = {}

MfaSession = Annotated[tuple[UserSession, User], Depends(session_in_stage("mfa"))]
PasswordSession = Annotated[tuple[UserSession, User], Depends(session_in_stage("password"))]
EnrollSession = Annotated[tuple[UserSession, User], Depends(session_in_stage("enroll"))]


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def user_out(u: User) -> dict:
    return {
        "id": str(u.id),
        "username": u.username,
        "display_name": u.display_name or u.username,
        "email": u.email,
        "role": u.role,
        "auth_source": u.auth_source,
        "totp": bool(u.totp_secret_enc),
        "is_emergency": u.is_emergency,
    }


# ---------------------------------------------------------------- first start


async def issue_setup_token(db) -> str | None:
    """At every start while no admin exists: a new one-time token (60 minutes), printed to the container log."""
    setup = await settings_store.get(db, "setup")
    if setup["completed"]:
        if await db.scalar(select(User.id).where(User.is_emergency.is_(True)).limit(1)) is not None:
            return None
        # marked done, but without the account it should have made (an older version could stop half-way): open again
        log.warning("setup marked completed but no emergency admin exists – setup opened again")
    token = human_code(4, 4)
    await settings_store.put(db, "setup", {**setup, "completed": False, "token_hash": token_hash(normalize_code(token)), "token_expires": int(time.time()) + SETUP_TTL})
    await db.commit()
    line = "=" * 64
    log.warning("\n%s\n  Cobe News setup required\n  Setup token: %s  (valid for 60 minutes, once)\n  Open the web UI and enter it to create the first admin.\n%s", line, token, line)
    return token


class SetupIn(_M):
    token: str = Field(min_length=8, max_length=40)
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._@-]+$")
    display_name: str = Field(default="", max_length=255)
    password: str = Field(min_length=1, max_length=256)


@router.post("/setup")
async def setup(body: SetupIn, request: Request, response: Response, db: Db):
    """The first local admin – the emergency account: never disabled by a directory, never locked by failed sign-ins."""
    st = await settings_store.get(db, "setup")
    if st["completed"]:
        raise api_error(404, "setup_completed")
    ip = client_ip(request)
    if bruteforce.ip_blocked(ip):
        raise api_error(403, "ip_blocked")
    expected = st.get("token_hash") or ""
    if not (expected and int(st.get("token_expires") or 0) > time.time() and hmac.compare_digest(expected, token_hash(normalize_code(body.token)))):
        f = bruteforce.register_failure("#setup", ip, lock_account=False)
        await lock_store.flush()
        await asyncio.sleep(f.delay)
        raise api_error(403 if f.ip_blocked else 401, "ip_blocked" if f.ip_blocked else "invalid_token")
    username = body.username.lower()
    if failed := passwords.check_policy(body.password, username=username):
        raise api_error(400, "password_policy", rules=failed)
    pw_hash = await passwords.ahash_password(body.password)  # before the write transaction – hashing takes a while
    # single use, and all or nothing: the token is consumed in the same transaction that creates the admin and its
    # session – a second request racing this one finds the token gone (the conditional UPDATE: it waits for the first
    # one's row lock and then checks the condition again on what that one wrote), and a failure half-way leaves the token
    # valid instead of a "completed" setup without an admin (which nobody could finish any more)
    try:
        open_ = func.coalesce(Setting.value["completed"].as_string(), "false").in_(["false", "0"])
        res = await db.execute(
            update(Setting)
            .where(Setting.key == "setup", Setting.value["token_hash"].as_string() == expected, open_)
            .values(value={"completed": True, "token_hash": "", "token_expires": 0})
            .execution_options(synchronize_session=False)
        )
        if res.rowcount != 1:
            await db.rollback()
            raise api_error(404, "setup_completed")
        user = User(username=username, display_name=body.display_name or username, role="admin", auth_source="local", password_hash=pw_hash, is_emergency=True)
        db.add(user)
        await db.flush()
        audit.record(db, user, "setup.completed", audit.user_target(user), {"emergency_admin": True}, ip=ip)
        sess, _ = await sessions.create(db, user, "enroll", ip, user_agent(request), method="password")
        return await _finish(db, sess, user, "enroll", response)
    except IntegrityError as exc:
        await db.rollback()
        raise api_error(409, "username_taken") from exc


# ---------------------------------------------------------------- sign-in


@router.get("/auth/config")
async def auth_config(db: Db) -> dict:
    ldap_cfg, entra_cfg = await settings_store.get(db, "ldap"), await settings_store.get(db, "entra")
    # passkeys (app/passkeys_api.py): switched on, and possible at BASE_URL (an https host name) – the page offers them
    # only when it is itself opened at that origin (a passkey is bound to it)
    rp, why = webauthn.availability()
    return {
        "setup_required": not (await settings_store.get(db, "setup"))["completed"],
        "ldap_enabled": bool(ldap_cfg["enabled"]) and ldap_dir.usable(ldap_cfg),
        "entra_enabled": bool(entra_cfg["enabled"]) and entra.usable(entra_cfg),
        "passkeys": {
            "enabled": bool((await settings_store.get(db, "passkeys"))["enabled"]),
            "available": rp is not None,
            "reason": why,
            "origin": rp.origin if rp else None,
        },
    }


@router.get("/auth/state")
async def state(request: Request, db: Db) -> dict:
    """Where this browser is in the sign-in (the SPA asks on load)."""
    got = await optional_session(request, db)
    if got is None:
        return {"stage": None}
    sess, user = got
    if sess.stage == "active":
        return {"stage": "active", "user": user_out(user), "session": sessions.timing(sess, await settings_store.get(db, "sessions"), sessions.now())}
    return {"stage": sess.stage, **({"enroll": await enroll_info(db, user)} if sess.stage == "enroll" else {})}


@router.get("/auth/session")
async def session_status(sess: PeekedSession, db: Db) -> dict:
    """Is this browser's session still there, and how long has it left – without extending it (deps.peek_session): the
    open tabs ask shortly after its end and when they become visible again, an idle tab must not keep it alive."""
    return sessions.timing(sess, await settings_store.get(db, "sessions"), sessions.now())


# ---------------------------------------------------------------- the second factor


async def factor_required(db, user: User) -> bool:  # noqa: ANN001
    """Must this account's sign-in end with a second factor? Admins always. Readers while "Zweiter Faktor für alle" is on
    (settings section "mfa") – Entra readers also with MFA-Nachweis "context" or "require". What counts: TOTP or a
    passkey (local), TOTP (AD/LDAP), a proof in the Entra token or the TOTP (Entra – entra_stage)."""
    if user.role == "admin":
        return True
    if (await settings_store.get(db, "mfa"))["required_all"]:
        return True
    if user.auth_source == "entra":
        return entra.mfa_mode(await settings_store.get(db, "entra")) != "entra"
    return False


def entra_stage(user: User, proven: bool | None, required: bool) -> str | None:
    """Where an Entra sign-in goes on: active (no second factor required, or the token proves it), mfa (the own TOTP),
    enroll (none set up yet and the token proves nothing either way: it is set up now) – None: refused (the token says the
    sign-in had no second factor, or lacks the required auth context, and there is no own TOTP: setting one up now would
    make the Entra password alone the "second" factor)."""
    if not required or proven is True:
        return "active"
    if user.totp_secret_enc:
        return "mfa"
    return None if proven is False else "enroll"


async def enroll_info(db, user: User) -> dict:  # noqa: ANN001
    """What the set-up step offers: TOTP always; a passkey for a local reader (admins keep TOTP) while passkeys are on and
    possible here. `has_passkey`: the account has one already – a sign-in with it needs no further factor."""
    rp, _ = webauthn.availability()
    local_reader = user.auth_source == "local" and user.role != "admin"
    pk_on = local_reader and rp is not None and bool((await settings_store.get(db, "passkeys"))["enabled"])
    has = user.auth_source == "local" and await db.scalar(select(UserPasskey.id).where(UserPasskey.user_id == user.id).limit(1)) is not None
    return {"reason": "admin" if user.role == "admin" else "required", "passkey": pk_on, "has_passkey": bool(has and pk_on)}


async def next_after_mfa(db, sess: UserSession, user: User) -> str:  # noqa: ANN001
    """After the password (and the TOTP code, when set up) or a passkey: a temporary password replaced first, then –
    where a second factor is required and this sign-in had none – its set-up. Admins keep TOTP (also with a passkey);
    a reader's passkey sign-in or TOTP code counts. Entra: the callback decided already (entra_stage)."""
    if user.must_change_password and user.auth_source == "local":
        return "password"
    if user.auth_source == "entra" or not await factor_required(db, user):
        return "active"
    if user.role == "admin":
        return "active" if user.totp_secret_enc else "enroll"
    return "active" if sess.method in ("password_totp", "ldap_totp", "passkey") else "enroll"


async def _next_after_password(db, sess: UserSession, user: User) -> str:  # noqa: ANN001
    return "mfa" if user.totp_secret_enc else await next_after_mfa(db, sess, user)


async def _finish(db, sess: UserSession, user: User, stage: str, response: Response, **extra) -> dict:
    token = await sessions.promote(db, sess, stage)
    if stage == "active":
        bruteforce.register_success(bruteforce.lock_key(user))
        user.last_login_at = datetime.now(UTC)
        user.last_login_ip = sess.ip
        _signed_in(db, user, sess.ip, sess.method)
    await db.commit()
    sessions.set_cookie(response, token)
    return {"next": "done" if stage == "active" else stage, **({"user": user_out(user)} if stage == "active" else {}), **extra}


def _signed_in(db, user: User, ip: str | None, method: str | None) -> None:  # noqa: ANN001
    """An admin's sign-in in the audit log (a reader's last sign-in is on the account – every one would flood the log),
    with how it was signed in (sessions.METHODS: password, password_totp, ldap, ldap_totp, passkey, entra)."""
    if user.role == "admin":
        audit.record(db, user, "login.success", audit.user_target(user), {"source": user.auth_source, "method": method}, ip=ip)


_NAME_SHAPE = re.compile(r"^[A-Za-z0-9._@~-]{1,64}$")


async def _lock_target(db, key: str) -> audit.Target:  # noqa: ANN001
    """The account a lock key names (bruteforce.lock_key) – or, unknown, the typed name when it looks like one (a
    password typed into the name field never lands in the log)."""
    kind, _, rest = key.partition(":")
    u = None
    if kind == "local":
        u = await db.scalar(select(User).where(User.username == rest, User.auth_source == "local"))
    elif kind in ("ldap", "entra") and rest:
        u = await db.scalar(select(User).where(User.auth_source == kind, User.external_id == rest))
    if u is not None:
        return audit.user_target(u)
    return audit.target("account", None, rest if _NAME_SHAPE.match(rest) else "?")


async def _fail(
    db, key: str, ip: str, code: str = "invalid_credentials", *, emergency: bool = False, lock: bool = True, sess: UserSession | None = None
) -> JSONResponse:
    """A failed check, counted on the lock key (bruteforce.lock_key – local:<name>, ldap:<objectGUID> …). `lock=False`:
    counted, but never locks the account (a session's own counter ends it instead)."""
    f = bruteforce.register_failure(key, ip, lock_account=lock and not emergency, emergency=emergency)
    # not each failure (anyone can send them) – the lock it started, the block of the address (a few per address at most)
    if f.locked_for:
        audit.record(db, audit.SYSTEM, "login.locked", await _lock_target(db, key), {"locked_for_s": f.locked_for}, ip=ip)
    if f.ip_blocked:
        audit.record(db, audit.SYSTEM, "login.ip_blocked", audit.target("ip", bruteforce.source_key(ip), bruteforce.source_key(ip)), {"blocked_for_s": bruteforce.IP_BLOCK}, ip=ip)
    revoked = False
    if sess is not None:
        n = int((sess.pending or {}).get("failures", 0)) + 1
        if n >= MFA_MAX_FAILURES or f.locked_for:
            await sessions.revoke(db, sess.id)
            revoked = True
        else:
            sess.pending = {**(sess.pending or {}), "failures": n}
    await db.commit()
    await db.close()  # the delay must not hold a database connection
    await lock_store.flush()  # a lock or block it set survives a restart
    await asyncio.sleep(f.delay)
    if f.ip_blocked:
        return JSONResponse({"detail": {"code": "ip_blocked"}}, status_code=403)
    if f.locked_for:
        return JSONResponse({"detail": {"code": "account_locked", "retry_after": f.locked_for}}, status_code=423)
    if revoked:
        return JSONResponse({"detail": {"code": "session_revoked"}}, status_code=401)
    return JSONResponse({"detail": {"code": code, "attempts_left": f.attempts_left}}, status_code=401)


async def _guard(key: str, ip: str, *, emergency: bool = False) -> None:
    # the emergency admin is checked even from a blocked address (it may be everybody's address behind a gateway) –
    # its password and TOTP still have to be right, and every miss still waits and counts
    if bruteforce.ip_blocked(ip) and not emergency:
        raise api_error(403, "ip_blocked")
    if not emergency and (left := bruteforce.locked_for(key)):
        bruteforce.register_failure("", ip, lock_account=False)  # still counts towards the address limit
        await lock_store.flush()  # … and may block it
        raise api_error(423, "account_locked", retry_after=left)


class LoginIn(_M):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)
    source: Literal["local", "ldap"] = "local"


@router.post("/auth/login")
async def login(body: LoginIn, request: Request, response: Response, db: Db):
    if not (await settings_store.get(db, "setup"))["completed"]:
        raise api_error(403, "setup_required")
    ip = client_ip(request)
    username = body.username.strip().lower()
    if body.source == "ldap":
        return await _login_ldap(db, username, body.password, ip, request, response)
    user = await db.scalar(select(User).where(User.username == username, User.auth_source == "local"))
    emergency = bool(user and user.is_emergency)
    key = bruteforce.local_key(username)
    await _guard(key, ip, emergency=emergency)
    async with bruteforce.gate(key, ip) as free, _brake(emergency) as go:
        if not free or not go:
            raise api_error(429, "too_many_attempts")
        ok = await passwords.averify_password(user.password_hash if user else None, body.password)
        if not ok or user is None or not user.is_active:
            return await _fail(db, key, ip, emergency=emergency)
        if user.password_hash and passwords.needs_rehash(user.password_hash):
            user.password_hash = await passwords.ahash_password(body.password)
        sess, _ = await sessions.create(db, user, "pre", ip, user_agent(request), method="password")
        return await _finish(db, sess, user, await _next_after_password(db, sess, user), response)


async def _login_ldap(db, username: str, password: str, ip: str, request: Request, response: Response):
    cfg = await settings_store.get(db, "ldap")
    if not (cfg["enabled"] and ldap_dir.usable(cfg)):
        raise api_error(400, "ldap_disabled")
    # the locks are checked before the directory is asked: a locked account costs the domain controller no bind (and
    # its lockout policy no count). Directory failures count in their own key space – never on the local account of the
    # same name – per account (objectGUID) when known, else per typed name
    name_key = bruteforce.ldap_name_key(username)
    known = await db.scalar(select(User).where(User.auth_source == "ldap", or_(User.username == username, func.lower(User.email) == username)).limit(1))
    await _guard(name_key, ip)
    if known is not None:
        await _guard(bruteforce.lock_key(known), ip)
    async with bruteforce.gate(name_key, ip) as free:
        if not free:
            raise api_error(429, "too_many_attempts")
        await dbm.release(db)  # nothing stays open while the directory is asked
        seen: list[str] = []

        def locked(guid: str) -> bool:  # however the name was typed: the account's own lock, before the DC sees a bind
            return bool(bruteforce.locked_for(f"ldap:{guid}"))

        try:
            du = await ldap_dir.run(ldap_dir.authenticate, cfg, username, password, seen, locked)
        except ldap_dir.AccountLocked:
            raise api_error(423, "account_locked", retry_after=max(1, bruteforce.locked_for(f"ldap:{seen[0]}"))) from None
        except ldap_dir.LdapError as exc:
            log.warning("ldap sign-in: directory unavailable (%s)", exc.category)
            raise api_error(503, "directory_unavailable") from exc
        # failures count per directory account (objectGUID), however its name was typed (sAMAccountName, UPN …)
        account = f"ldap:{seen[0]}" if seen else name_key
        if account != name_key and (left := bruteforce.locked_for(account)):
            raise api_error(423, "account_locked", retry_after=left)
        if du is None:
            return await _fail(db, account, ip)
        try:
            user = await _provision(db, du)
        except directory.DirectoryError as exc:
            # right password, but no access (no mapped group, disabled, name taken): answered like a wrong password –
            # and counted – otherwise this page would confirm the AD password of every account
            log.info("ldap sign-in of %s refused: %s", username, exc.code)
            await db.rollback()
            return await _fail(db, account, ip)
        sess, _ = await sessions.create(db, user, "pre", ip, user_agent(request), method="ldap")
        return await _finish(db, sess, user, await _next_after_password(db, sess, user), response)


async def _provision(db, du: directory.DirectoryUser) -> User:
    """directory.provision – two first sign-ins of one account at the same moment: the second finds the first's row."""
    try:
        user = await directory.provision(db, du)
        await db.flush()
        return user
    except IntegrityError:
        await db.rollback()
        return await directory.provision(db, du)


@asynccontextmanager
async def _brake(emergency: bool):
    """The emergency admin's checks beyond its hourly failure budget: slowed, one at a time (bruteforce.emergency_brake)."""
    if not emergency:
        yield True
        return
    async with bruteforce.emergency_brake() as go:
        yield go


class CodeIn(_M):
    code: str = Field(min_length=6, max_length=12)


async def _check_totp(db, user: User, code: str) -> bool:
    if not user.totp_secret_enc:
        return False
    step = totp.verify(decrypt_str(user.totp_secret_enc), code, user.totp_last_step)
    if step is None:
        return False
    # a code counts once, even when two requests (from two addresses) bring it at the same moment
    res = await db.execute(
        update(User)
        .where(User.id == user.id, or_(User.totp_last_step.is_(None), User.totp_last_step < step))
        .values(totp_last_step=step)
        .execution_options(synchronize_session=False)
    )
    if res.rowcount != 1:
        return False
    set_committed_value(user, "totp_last_step", step)
    return True


@router.post("/auth/mfa")
async def mfa(body: CodeIn, got: MfaSession, request: Request, response: Response, db: Db):
    sess, user = got
    ip = client_ip(request)
    key = bruteforce.lock_key(user)
    await _guard(key, ip, emergency=user.is_emergency)
    async with bruteforce.gate(key, ip) as free, _brake(user.is_emergency) as go:
        if not free or not go:
            raise api_error(429, "too_many_attempts")
        await db.refresh(sess)
        if not await _check_totp(db, user, body.code):
            return await _fail(db, key, ip, "invalid_code", emergency=user.is_emergency, sess=sess)
        sessions.with_totp(sess)
        return await _finish(db, sess, user, await next_after_mfa(db, sess, user), response)


class NewPasswordIn(_M):
    new_password: str = Field(min_length=1, max_length=256)
    current_password: str | None = Field(default=None, max_length=256)


async def _set_password(db, user: User, pw: str) -> None:
    """A password the person chose (own change, or the temporary one replaced): none of the last passwords.HISTORY
    (the current one and those kept before it) – "reused"; the replaced one is kept unless it was a temporary one."""
    if failed := passwords.check_policy(pw, username=user.username):
        raise api_error(400, "password_policy", rules=failed)
    if await passwords.reused(db, user, pw):
        raise api_error(400, "password_policy", rules=["reused"])
    new_hash = await passwords.ahash_password(pw)
    await passwords.remember(db, user)
    user.password_hash = new_hash
    user.must_change_password = False


@router.post("/auth/password")
async def change_temp_password(body: NewPasswordIn, got: PasswordSession, response: Response, db: Db):
    sess, user = got
    await _set_password(db, user, body.new_password)
    audit.record(db, user, "account.password_changed", audit.user_target(user), {"temporary_replaced": True})
    return await _finish(db, sess, user, await next_after_mfa(db, sess, user), response)


def _enroll_start(sess: UserSession, user: User) -> dict:
    secret = totp.new_secret()
    sess.pending = {**(sess.pending or {}), "totp": encrypt_str(secret)}
    return {"secret": secret, "uri": totp.provisioning_uri(secret, user.username)}


def _enroll_confirm(sess: UserSession, user: User, code: str) -> bool:
    enc = (sess.pending or {}).get("totp")
    if not enc:
        raise api_error(409, "totp_not_started")
    secret = decrypt_str(enc)
    step = totp.verify(secret, code, None)
    if step is None:
        return False
    user.totp_secret_enc, user.totp_last_step = encrypt_str(secret), step
    sess.pending = {k: v for k, v in (sess.pending or {}).items() if k != "totp"}
    return True


@router.post("/auth/enroll/start")
async def enroll_start(got: EnrollSession, db: Db) -> dict:
    out = _enroll_start(*got)
    await db.commit()
    return out


@router.post("/auth/enroll/confirm")
async def enroll_confirm(body: CodeIn, got: EnrollSession, request: Request, response: Response, db: Db):
    sess, user = got
    if not _enroll_confirm(sess, user, body.code):
        return await _fail(db, bruteforce.lock_key(user), client_ip(request), "invalid_code", lock=False, sess=sess)  # no account lock – the session ends after 5
    audit.record(db, user, "account.totp_enabled", audit.user_target(user), {"at_signin": True})
    sessions.with_totp(sess)  # the code of the new app was checked in this sign-in
    return await _finish(db, sess, user, "active", response)


@router.post("/auth/logout")
async def logout(request: Request, response: Response, db: Db) -> dict:
    got = await optional_session(request, db)
    if got:
        await sessions.revoke(db, got[0].id)
        await db.commit()
    sessions.clear_cookie(response)
    return {"ok": True}


# ---------------------------------------------------------------- Entra ID (OIDC, authorization code + PKCE)


def _oidc_fail(code: str) -> RedirectResponse:
    resp = RedirectResponse(f"/?login_error={code}", status_code=302)
    resp.delete_cookie(OIDC_COOKIE, path="/api/auth/oidc")
    return resp


def _oidc_rate_ok(ip: str) -> bool:
    """Sign-in starts per address – keyed like the brute-force counters (bruteforce.source_key: IPv6 per /64)."""
    t = time.monotonic()
    k = bruteforce.source_key(ip)
    hits = [x for x in _oidc_starts.get(k, []) if t - x < OIDC_TTL]
    if len(hits) >= (OIDC_PER_SHARED if netaddr.shared_address(ip) else OIDC_PER_IP):
        _oidc_starts[k] = hits
        return False
    hits.append(t)
    _oidc_starts[k] = hits
    if len(_oidc_starts) > 5000:  # forget addresses without recent starts
        for old in [x for x, v in _oidc_starts.items() if not v or t - v[-1] > OIDC_TTL]:
            _oidc_starts.pop(old, None)
    return True


def _safe_next(value: str | None) -> str:
    """Where to land after the sign-in: only a path of this app (no other site, no scheme-relative //host)."""
    v = (value or "").strip()
    return v if v.startswith("/") and not v.startswith("//") and "\\" not in v and len(v) <= 300 else "/"


@router.get("/auth/oidc/start")
async def oidc_start(
    request: Request,
    db: Db,
    next: str | None = Query(default=None, max_length=300),  # noqa: A002 - the query name
    reauth: bool = False,
) -> RedirectResponse:
    """`reauth=1`: an Entra admin confirms who they are for a sensitive action – Microsoft asks for the sign-in again
    (prompt=login, max_age=0), the answer must be for the account of this session and fresh (auth_time)."""
    cfg = await settings_store.get(db, "entra")
    if not (cfg["enabled"] and entra.usable(cfg)):
        return _oidc_fail("entra_disabled")
    if not _oidc_rate_ok(client_ip(request)):
        return _oidc_fail("entra_busy")
    sid = None
    if reauth:
        got = await optional_session(request, db)
        if got is None or got[0].stage != "active" or got[1].auth_source != "entra":
            return _oidc_fail("entra_reauth")
        sid = str(got[0].id)
    # stateless: state, nonce and PKCE verifier travel encrypted and authenticated in the browser's cookie – nothing is
    # kept on the server, so nobody can fill a store and block everybody's sign-in
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = entra.pkce()
    now = int(time.time())
    blob = encrypt_str(json.dumps({"s": state, "n": nonce, "v": verifier, "x": now + OIDC_TTL, "to": _safe_next(next), **({"sid": sid, "t0": now} if sid else {})}))
    resp = RedirectResponse(entra.authorize_url(cfg, state=state, nonce=nonce, challenge=challenge, force_login=reauth), status_code=302)
    # Lax: it must come along on the top-level redirect back from Microsoft. Binding the answer to this cookie stops
    # login CSRF (nobody can make a victim's browser finish the attacker's sign-in).
    resp.set_cookie(OIDC_COOKIE, blob, max_age=OIDC_TTL, httponly=True, secure=get_config().cookie_secure, samesite="lax", path="/api/auth/oidc")
    return resp


@router.get("/auth/oidc/callback")
async def oidc_callback(
    request: Request,
    db: Db,
    code: str | None = Query(default=None, max_length=4096),
    state: str | None = Query(default=None, max_length=128),
    error: str | None = Query(default=None, max_length=128),
) -> RedirectResponse:
    cookie = request.cookies.get(OIDC_COOKIE) or ""
    try:
        st = json.loads(decrypt_str(cookie)) if cookie else None
    except Exception:  # noqa: BLE001 - tampered, from another key, or garbage: no sign-in
        st = None
    if not state or not isinstance(st, dict) or not secrets.compare_digest(str(st.get("s", "")), state):
        return _oidc_fail("entra_state")
    if int(st.get("x") or 0) < time.time():
        return _oidc_fail("entra_expired")
    st = {"nonce": str(st["n"]), "verifier": str(st["v"]), "to": _safe_next(st.get("to")), "sid": st.get("sid"), "t0": int(st.get("t0") or 0)}
    if error or not code:
        log.info("entra sign-in: %s", re.sub(r"[^a-z_]", "", (error or "no_code").lower())[:64])
        return _oidc_fail("entra_denied")
    cfg = await settings_store.get(db, "entra")
    if not (cfg["enabled"] and entra.usable(cfg)):
        return _oidc_fail("entra_disabled")
    ip = client_ip(request)
    if bruteforce.ip_blocked(ip):
        return _oidc_fail("ip_blocked")
    try:
        tokens = await entra.exchange_code(cfg, code, st["verifier"])
        claims = await entra.validate_id_token(cfg, tokens.get("id_token", ""), st["nonce"])
        if st["sid"]:
            return await _oidc_reauth(request, db, claims, st, cfg)
        du = await entra.to_directory_user(cfg, claims)
    except entra.EntraError as exc:
        log.warning("entra sign-in failed: %s", exc.category)
        # an expired or wrong client secret: only a local admin or the emergency account can enter the new one
        return _oidc_fail("entra_secret" if entra.secret_rejected(exc) else "entra_failed")
    try:
        user = await _provision(db, du)
    except directory.DirectoryError as exc:
        await db.rollback()
        return _oidc_fail(f"directory_{exc.code}")
    proven = entra.mfa_proven(cfg, claims)
    stage = entra_stage(user, proven, await factor_required(db, user))
    if stage is None:
        # nothing of this sign-in stays (a new account, a changed role): the Entra password alone must not get in, nor
        # set up the "second" factor
        name = user.username
        await db.rollback()
        log.warning("entra sign-in of %s refused: the token proves no second factor (%s) and the account has no TOTP", name, "context missing" if entra.required_context(cfg) else "amr without mfa")
        return _oidc_fail("entra_mfa_missing")
    sess, _ = await sessions.create(db, user, "pre", ip, user_agent(request), method="entra")
    token = await sessions.promote(db, sess, stage)
    if stage == "active":
        bruteforce.register_success(bruteforce.lock_key(user))
        user.last_login_at, user.last_login_ip = datetime.now(UTC), ip
        _signed_in(db, user, ip, sess.method)
    # mfa / enroll: the sign-in page asks for the code or the set-up (GET /auth/state names the stage)
    await db.commit()
    resp = RedirectResponse(st["to"], status_code=302)
    resp.delete_cookie(OIDC_COOKIE, path="/api/auth/oidc")
    sessions.set_cookie(resp, token)
    return resp


async def _oidc_reauth(request: Request, db, claims: dict, st: dict, cfg: dict) -> RedirectResponse:
    """The answer to oidc_start(reauth=1): the same browser session, the same Entra account, a sign-in made just now –
    and, where a second factor is required, proven like at the sign-in: by the token (mfa_proven), or else by the own
    TOTP code given just before (POST /auth/reauth with the code: pending "entra_totp_at", used once)."""
    got = await optional_session(request, db)
    if got is None or str(got[0].id) != st["sid"] or got[0].stage != "active":
        return _oidc_fail("entra_reauth")
    sess, user = got
    oid = str(claims.get("oid") or claims.get("sub") or "")
    try:
        fresh = int(claims.get("auth_time") or 0) >= st["t0"] - REAUTH_SKEW
    except (TypeError, ValueError):
        fresh = False
    if user.auth_source != "entra" or oid.lower() != str(user.external_id or "").lower() or not fresh:
        log.info("entra re-confirmation refused (%s)", "stale" if oid.lower() == str(user.external_id or "").lower() else "other account")
        return _oidc_fail("entra_reauth")
    pending = dict(sess.pending or {})
    stamp = pending.pop("entra_totp_at", None)
    if await factor_required(db, user) and entra.mfa_proven(cfg, claims) is not True:
        try:
            coded = bool(user.totp_secret_enc) and time.time() - float(stamp) <= OIDC_TTL
        except (TypeError, ValueError):
            coded = False
        if not coded:
            log.info("entra re-confirmation of %s refused: no second factor (token proves none, no TOTP code given)", user.username)
            sess.pending = pending
            await db.commit()
            return _oidc_fail("entra_reauth_mfa")
    sess.pending = pending
    sess.reauth_at = sessions.now()
    await db.commit()
    resp = RedirectResponse(st["to"], status_code=302)
    resp.delete_cookie(OIDC_COOKIE, path="/api/auth/oidc")
    return resp


# ---------------------------------------------------------------- re-confirmation for sensitive admin actions


class ConfirmIn(_M):
    password: str | None = Field(default=None, max_length=1024)
    code: str | None = Field(default=None, max_length=12)


@router.post("/auth/reauth")
async def reauth(body: ConfirmIn, sess: ActiveSession, user: Reader, request: Request, db: Db):
    """Proof of identity for the next REAUTH_WINDOW minutes (sign-in settings, users, mappings): the password – of the
    local account or the AD account – and, when set up, the current TOTP code. Entra accounts: oidc/start?reauth=1 –
    with the own TOTP set up, its code first (here, `code` only): noted on the session for the next OIDC_TTL seconds,
    the answer from Microsoft then counts as proven even when the token proves no MFA (_oidc_reauth).
    No account-lock check (anyone can lock a name from outside – that must not stop a signed-in admin); guessing is
    held by the session's own counter: 5 misses end it."""
    if user.auth_source == "entra" and not (body.code and user.totp_secret_enc):
        raise api_error(409, "entra_reauth")
    ip = client_ip(request)
    if bruteforce.ip_blocked(ip) and not user.is_emergency:
        raise api_error(403, "ip_blocked")
    key = bruteforce.lock_key(user)
    async with bruteforce.gate(f"reauth:{sess.id}", ip) as free, _brake(user.is_emergency) as go:
        if not free or not go:
            raise api_error(429, "too_many_attempts")
        await db.refresh(sess)
        if user.auth_source == "entra":
            if not await _check_totp(db, user, body.code or ""):
                return await _fail(db, key, ip, "invalid_code", lock=False, sess=sess)
            sess.pending = {**{k: v for k, v in (sess.pending or {}).items() if k != "failures"}, "entra_totp_at": int(time.time())}
            await db.commit()
            return {"ok": True, "next": "entra"}
        ok = bool(body.password)
        if ok and user.auth_source == "local":
            ok = await passwords.averify_password(user.password_hash, body.password or "")
        elif ok:
            ok = await _ldap_password(db, user, body.password or "")
        if ok and user.totp_secret_enc:
            ok = bool(body.code) and await _check_totp(db, user, body.code or "")
        if not ok:
            return await _fail(db, key, ip, "reauth_failed", emergency=user.is_emergency, lock=False, sess=sess)
        sess.reauth_at = sessions.now()
        sess.pending = {k: v for k, v in (sess.pending or {}).items() if k != "failures"}
        await db.commit()
    return {"ok": True, "valid_min": int(sessions.REAUTH_WINDOW.total_seconds() // 60)}


# ---------------------------------------------------------------- the own account


@router.get("/me")
async def me(user: Reader) -> dict:
    return user_out(user)


@router.post("/me/password")
async def my_password(body: NewPasswordIn, user: Reader, sess: ActiveSession, request: Request, response: Response, db: Db):
    if user.auth_source != "local":
        raise api_error(400, "not_local_account")
    ip = client_ip(request)
    if bruteforce.ip_blocked(ip) and not user.is_emergency:
        raise api_error(403, "ip_blocked")
    # like /auth/reauth: no account-lock check (anyone can lock a name from outside – the signed-in owner must still be
    # able to change the password); guessing is held by the session's own counter instead – 5 misses end it
    key = bruteforce.lock_key(user)
    async with bruteforce.gate(f"reauth:{sess.id}", ip) as free, _brake(user.is_emergency) as go:
        if not free or not go:
            raise api_error(429, "too_many_attempts")
        if not await passwords.averify_password(user.password_hash, body.current_password or ""):
            return await _fail(db, key, ip, emergency=user.is_emergency, lock=False, sess=sess)
    await _set_password(db, user, body.new_password)
    await sessions.revoke_all(db, user.id, except_id=sess.id)  # other browsers sign in again
    audit.record(db, user, "account.password_changed", audit.user_target(user), {"other_sessions_ended": True})
    # a new token, but not a fresh re-confirmation: the current password alone is no second factor (TOTP)
    token = sessions.rekey(sess)
    await db.commit()
    sessions.set_cookie(response, token)
    return {"ok": True}


class ReauthIn(_M):
    """Proof that the person at the keyboard owns the account: the current TOTP code, or else the password."""

    code: str | None = Field(default=None, max_length=12)
    password: str | None = Field(default=None, max_length=1024)


async def _reauth(db, user: User, sess: UserSession, body: ReauthIn, request: Request) -> JSONResponse | None:
    """None when confirmed – otherwise the failure answer. As /auth/reauth: no account-lock check (a lock set from
    outside must not stop the signed-in owner), misses counted on the session – 5 end it."""
    ip = client_ip(request)
    if bruteforce.ip_blocked(ip) and not user.is_emergency:
        raise api_error(403, "ip_blocked")
    key = bruteforce.lock_key(user)
    async with bruteforce.gate(f"reauth:{sess.id}", ip) as free, _brake(user.is_emergency) as go:
        if not free or not go:
            raise api_error(429, "too_many_attempts")
        if user.totp_secret_enc:
            ok = bool(body.code) and await _check_totp(db, user, body.code or "")
            code = "invalid_code"
        elif user.auth_source == "local":
            ok, code = await passwords.averify_password(user.password_hash, body.password or ""), "invalid_credentials"
        elif user.auth_source == "ldap" and body.password:
            ok = await _ldap_password(db, user, body.password)
            code = "invalid_credentials"
        else:
            ok, code = False, "invalid_credentials"
        if not ok:
            return await _fail(db, key, ip, code, emergency=user.is_emergency, lock=False, sess=sess)
    return None


async def _ldap_password(db, user: User, password: str) -> bool:
    """The AD password of exactly this account (bound as it, found by its name – and it must be the same objectGUID)."""
    cfg = await settings_store.get(db, "ldap")
    if not (cfg["enabled"] and ldap_dir.usable(cfg)):
        return False
    await dbm.release(db)  # nothing stays open while the directory is asked
    try:
        du = await ldap_dir.run(ldap_dir.authenticate, cfg, user.username, password)
    except ldap_dir.LdapError as exc:
        raise api_error(503, "directory_unavailable") from exc
    return du is not None and str(du.external_id).lower() == str(user.external_id or "").lower()


@router.post("/me/totp/start")
async def my_totp_start(body: ReauthIn, user: Reader, sess: ActiveSession, request: Request, db: Db):
    if user.auth_source == "entra":
        raise api_error(400, "entra_mfa")  # Microsoft asks for the second factor
    if (refused := await _reauth(db, user, sess, body, request)) is not None:
        return refused
    out = _enroll_start(sess, user)
    await db.commit()
    return out


@router.post("/me/totp/confirm")
async def my_totp_confirm(body: CodeIn, user: Reader, sess: ActiveSession, request: Request, db: Db):
    if not _enroll_confirm(sess, user, body.code):
        return await _fail(db, bruteforce.lock_key(user), client_ip(request), "invalid_code", lock=False)
    audit.record(db, user, "account.totp_enabled", audit.user_target(user))
    await db.commit()
    return user_out(user)


@router.post("/me/totp/remove")
async def my_totp_remove(body: ReauthIn, user: Reader, sess: ActiveSession, request: Request, db: Db):
    if user.role == "admin":
        raise api_error(409, "totp_required")  # admins keep their second factor
    # a second factor required for everybody: the TOTP stays – unless a passkey (local accounts) takes its place
    if await factor_required(db, user) and (await enroll_info(db, user))["has_passkey"] is False:
        raise api_error(409, "totp_required")
    if (refused := await _reauth(db, user, sess, body, request)) is not None:
        return refused
    user.totp_secret_enc, user.totp_last_step = None, None
    audit.record(db, user, "account.totp_removed", audit.user_target(user))
    await db.commit()
    return user_out(user)


class DesktopIn(_M):
    enabled: bool = False
    severities: list[Literal["critical", "high", "medium", "low", "info"]] = Field(default_factory=lambda: ["critical", "high"], max_length=5)
    # source ids (UUIDs): each one short – the choice is stored on the account and read by every push round
    sources: list[Annotated[str, Field(max_length=64)]] = Field(default_factory=list, max_length=50)


@router.get("/me/desktop")
async def my_desktop(user: Reader) -> dict:
    return DesktopIn.model_validate({**DesktopIn().model_dump(), **(user.desktop or {})}).model_dump()


@router.put("/me/desktop")
async def put_my_desktop(body: DesktopIn, user: Reader, db: Db) -> dict:
    user.desktop = body.model_dump()
    await db.commit()
    return user.desktop


async def admins_count(db) -> int:
    return int(await db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.is_active.is_(True))) or 0)
