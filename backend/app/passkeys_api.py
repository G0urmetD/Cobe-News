"""Passkeys (WebAuthn) for local accounts: registered under Profil & Sicherheit, used on the sign-in page instead of
password and TOTP, seen and removed by admins. The checks themselves: app/auth/webauthn.py.

- **Two factors.** A passkey is requested and checked with user verification (`userVerification: "required"`, the UV
  flag): the device asked for its PIN or biometrics. Possession of the device plus that counts as two factors, so a
  passkey sign-in needs neither password nor TOTP. A passkey that does not verify the user is refused, at registration
  and at every sign-in. What still applies afterwards: a temporary password is replaced first, an admin without TOTP
  sets it up (admins keep TOTP as their fallback).
- **Without a user name.** Only discoverable credentials (`residentKey: "required"`): the sign-in page asks the
  browser for any passkey of this site; the credential id says whose it is, the user handle (the account's UUID) has to
  match.
- **Local accounts only.** AD/LDAP and Entra accounts sign in through their directory: 409 not_local_account.
- **Adding and removing** need a fresh proof of identity (deps.require_reauth). Removing one ends the sessions signed
  in with it – all of them, except the session that removes it.
- **At the sign-in** (stage "enroll", "Zweiter Faktor für alle" on): a local reader without a second factor may register
  a passkey instead of setting up TOTP – the password just checked in this sign-in is the proof of identity (as for the
  TOTP set-up there); the sign-in then ends active, bound to that passkey (removing it ends the session). Admins keep
  TOTP: not offered to them.
- **Challenges.** 32 random bytes, single use (taken out before anything is checked), CHALLENGE_TTL, in memory only
  (one app process; never in the database, so never in a backup). A sign-in's challenge is bound to the browser that
  asked for it (an httponly cookie with a random flow id), a registration's to the session and the account.
- **Signature counter.** A counter that does not go up – while it counts at all (synced passkeys always send 0) – can
  mean a cloned authenticator. The sign-in is *not* refused: the spec leaves it to the site, and a hard lock would let
  whoever used a clone first lock the owner out. Instead the passkey carries a warning (its owner and the admins see
  it, with the advice to remove it), the log gets a line, the stored counter keeps the highest value seen.
- **Limits.** PER_IP sign-in starts per address and 10 minutes (PER_SHARED through a shared address), PER_NET per
  IPv6 /48, at most MAX_PENDING sign-ins under way; REGISTER_PER_USER registrations under way per account. A refused
  sign-in counts like a wrong password on the address (bruteforce, IPv6 per /64; the "name" is the credential id –
  random ids for spraying count as many names) and waits the growing delay; a blocked address gets no passkey sign-in
  at all. The account lock after wrong passwords does not stop a passkey (it exists against guessing, and a passkey
  cannot be guessed); a blocked or deactivated account never signs in.
- **Admin switch** (Einstellungen → Anmeldung → Passkeys), on by default: nobody has a passkey until they register
  one themselves, and passkeys are the stronger, phishing-resistant way in. Off: no registration, no passkey sign-in –
  registered passkeys stay (listed, removable) and work again once it is back on.
- **RP ID** is the host of BASE_URL: another host name makes the registered passkeys useless (register them anew);
  with an IP address or plain http (except localhost) passkeys are unavailable (webauthn.availability).
"""

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ConfigDict, Field, field_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError

from app import audit, netaddr
from app import settings as settings_store
from app.auth import bruteforce, lock_store, sessions, webauthn
from app.auth_api import EnrollSession, _finish, enroll_info, next_after_mfa
from app.config import get_config
from app.deps import ActiveSession, Admin, Db, NoNul, Reader, api_error, client_ip, require_reauth, user_agent
from app.models import User, UserPasskey, UserSession

log = logging.getLogger("cobe_news.passkeys")
router = APIRouter(prefix="/api", tags=["passkeys"])
admin_router = APIRouter(prefix="/api/admin", tags=["admin"])

RP_NAME = "Cobe News"
COOKIE = "cobe_news_passkey"
COOKIE_PATH = "/api/auth/passkey"
TIMEOUT_MS = 120_000  # what the browser is told
CHALLENGE_TTL = 180.0  # s – a little longer than the browser waits
MAX_PER_USER = 10
MAX_PENDING = 5000
PER_IP = 30  # sign-in starts per address and WINDOW
PER_SHARED = 300  # … through an address everybody shares (Docker gateway, proxy)
# … and per IPv6 /48 (one end site – a provider hands out a /48 or a /56, so one person has 256 to 65 536 /64s): with
# CHALLENGE_TTL below WINDOW one network holds at most PER_NET of the MAX_PENDING sign-ins under way – filling them takes
# 17 sites, not one. IPv4 is held by PER_IP (at most 30 pending per address)
PER_NET = 300
V6_NET = 48
REGISTER_PER_USER = 3  # registrations under way per account (each of its sessions keeps one) – MAX_PENDING needs 1667 accounts
WINDOW = 600.0
TRANSPORTS = frozenset({"usb", "nfc", "ble", "internal", "hybrid", "smart-card"})
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class _Pending:
    challenge: bytes
    expires: float
    user_id: uuid.UUID | None = None


_login: dict[str, _Pending] = {}  # flow id (cookie) → challenge
_register: dict[uuid.UUID, _Pending] = {}  # session id → challenge
_starts: dict[str, list[float]] = {}


def reset() -> None:
    for d in (_login, _register, _starts):
        d.clear()


def _sweep(store: dict, t: float) -> None:
    for k, v in list(store.items()):
        if v.expires <= t:
            store.pop(k, None)


def purge() -> None:
    """Expired challenges and old start counts (hourly, with the brute-force counters)."""
    t = time.monotonic()
    _sweep(_login, t)
    _sweep(_register, t)
    for k, v in list(_starts.items()):
        if not v or t - v[-1] > WINDOW:
            _starts.pop(k, None)


def _network(ip: str) -> str | None:
    """The IPv6 /48 an address lies in – None for IPv4 (also IPv4-mapped), a shared address (its own PER_SHARED) or
    anything unparsable."""
    try:
        a = ipaddress.ip_address(ip.strip().split("%", 1)[0])
    except (ValueError, AttributeError):
        return None
    if not isinstance(a, ipaddress.IPv6Address) or a.ipv4_mapped or netaddr.shared_address(ip):
        return None
    return "net:" + str(ipaddress.IPv6Network((a, V6_NET), strict=False))


def _start_ok(ip: str, t: float) -> bool:
    """A sign-in start allowed for the address (IPv6: its /64) and, for IPv6, its /48 – counted only when both allow it."""
    limits = [(bruteforce.source_key(ip), PER_SHARED if netaddr.shared_address(ip) else PER_IP)]
    if (net := _network(ip)) is not None:
        limits.append((net, PER_NET))
    hits = {k: [x for x in _starts.get(k, []) if t - x < WINDOW] for k, _ in limits}
    ok = all(len(hits[k]) < n for k, n in limits)
    for k, v in hits.items():
        if ok:
            v.append(t)
        if v:
            _starts[k] = v
        else:
            _starts.pop(k, None)
    return ok


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _b64(limit: int):  # noqa: ANN202 - a pydantic field type
    return Annotated[str, Field(min_length=1, max_length=(limit * 4 + 2) // 3)]


class NameIn(_M):
    name: str = Field(min_length=1, max_length=64)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if _CONTROL.search(v):
            raise ValueError("control characters")
        return v


class RegistrationIn(NameIn):
    id: _b64(webauthn.MAX_CREDENTIAL_ID)
    raw_id: _b64(webauthn.MAX_CREDENTIAL_ID)
    type: Literal["public-key"]
    client_data_json: _b64(webauthn.MAX_CLIENT_DATA)
    attestation_object: _b64(webauthn.MAX_ATTESTATION)
    transports: list[Annotated[str, Field(max_length=16)]] = Field(default_factory=list, max_length=8)


class AssertionIn(_M):
    id: _b64(webauthn.MAX_CREDENTIAL_ID)
    raw_id: _b64(webauthn.MAX_CREDENTIAL_ID)
    type: Literal["public-key"]
    client_data_json: _b64(webauthn.MAX_CLIENT_DATA)
    authenticator_data: _b64(webauthn.MAX_AUTH_DATA)
    signature: _b64(webauthn.MAX_SIGNATURE)
    user_handle: Annotated[str, Field(max_length=88)] | None = None


def passkey_out(p: UserPasskey) -> dict:
    return {
        "id": str(p.id),
        "name": p.name,
        "created_at": p.created_at.isoformat(),
        "last_used_at": p.last_used_at.isoformat() if p.last_used_at else None,
        "transports": list(p.transports or []),
        "sign_count_warning_at": p.sign_count_warning_at.isoformat() if p.sign_count_warning_at else None,
    }


def relying_party() -> webauthn.RelyingParty:
    rp, why = webauthn.availability()
    if rp is None:
        raise api_error(409, "passkey_unavailable", reason=why)
    return rp


async def _switched_on(db) -> None:  # noqa: ANN001
    if not (await settings_store.get(db, "passkeys"))["enabled"]:
        raise api_error(409, "passkeys_disabled")


def _local(user: User) -> None:
    if user.auth_source != "local":
        raise api_error(409, "not_local_account")  # AD/LDAP and Entra accounts sign in through their directory


async def _list(db, user_id: uuid.UUID) -> list[UserPasskey]:  # noqa: ANN001
    return list(await db.scalars(select(UserPasskey).where(UserPasskey.user_id == user_id).order_by(UserPasskey.created_at)))


async def end_sessions_of(db, passkey_id: uuid.UUID, keep: uuid.UUID | None = None) -> int:  # noqa: ANN001
    """The sessions signed in with this passkey end (not committed) – except `keep` (the one removing it)."""
    stmt = delete(UserSession).where(UserSession.passkey_id == passkey_id)
    if keep is not None:
        stmt = stmt.where(UserSession.id != keep)
    res = await db.execute(stmt)
    return res.rowcount or 0


async def remove_all_of(db, user_id: uuid.UUID) -> int:  # noqa: ANN001
    """Every passkey of the account (an admin's password reset, cli reset-emergency) – not committed. The reset ends all
    sessions itself: a passkey someone else registered while they had the account must not outlive the reset."""
    res = await db.execute(delete(UserPasskey).where(UserPasskey.user_id == user_id))
    return res.rowcount or 0


# ---------------------------------------------------------------- sign-in (no user name)


@router.post("/auth/passkey/options")
async def login_options(request: Request, response: Response, db: Db) -> dict:
    if not (await settings_store.get(db, "setup"))["completed"]:
        raise api_error(403, "setup_required")
    rp = relying_party()
    await _switched_on(db)
    ip = client_ip(request)
    if bruteforce.ip_blocked(ip):
        raise api_error(403, "ip_blocked")
    t = time.monotonic()
    if not _start_ok(ip, t):
        raise api_error(429, "too_many_attempts")
    if (old := request.cookies.get(COOKIE)) is not None:
        _login.pop(old, None)  # a new start of this browser replaces its last one
    if len(_login) >= MAX_PENDING:
        _sweep(_login, t)
        if len(_login) >= MAX_PENDING:
            raise api_error(429, "passkey_busy")
    flow, challenge = secrets.token_urlsafe(32), secrets.token_bytes(32)
    _login[flow] = _Pending(challenge=challenge, expires=t + CHALLENGE_TTL)
    # Strict: only this site's own requests bring it back; it holds nothing but the random flow id
    response.set_cookie(COOKIE, flow, max_age=int(CHALLENGE_TTL), httponly=True, secure=get_config().cookie_secure, samesite="strict", path=COOKIE_PATH)
    return {"challenge": webauthn.b64url(challenge), "rpId": rp.rp_id, "timeout": TIMEOUT_MS, "userVerification": "required", "allowCredentials": []}


async def _refuse(db, key: str, ip: str, why: str) -> JSONResponse:  # noqa: ANN001
    """A refused passkey sign-in: counted on the address (and the credential), the growing delay, one answer for every
    reason – unknown passkey, wrong signature, blocked account all look the same from outside."""
    log.info("passkey sign-in refused: %s", why)
    f = bruteforce.register_failure(key, ip, lock_account=False)
    await db.rollback()
    if f.ip_blocked:  # not each refusal (anyone can send them) – the block of the address, as after wrong passwords
        audit.record(db, audit.SYSTEM, "login.ip_blocked", audit.target("ip", bruteforce.source_key(ip), bruteforce.source_key(ip)), {"blocked_for_s": bruteforce.IP_BLOCK, "via": "passkey"}, ip=ip)
        await db.commit()
    await db.close()  # the delay must not hold a database connection
    await lock_store.flush()  # a block it set survives a restart
    await asyncio.sleep(f.delay)
    if f.ip_blocked:
        return JSONResponse({"detail": {"code": "ip_blocked"}}, status_code=403)
    return JSONResponse({"detail": {"code": "passkey_failed"}}, status_code=401)


def _decode(value: str | None, limit: int) -> bytes | None:
    if value is None:
        return None
    return webauthn.unb64url(value, limit=limit)


@router.post("/auth/passkey/login")
async def login(body: AssertionIn, request: Request, response: Response, db: Db):
    flow = request.cookies.get(COOKIE) or ""
    pending = _login.pop(flow, None) if flow else None  # single use – also when the check below fails
    response.delete_cookie(COOKIE, path=COOKIE_PATH, secure=get_config().cookie_secure, httponly=True, samesite="strict")
    if not (await settings_store.get(db, "setup"))["completed"]:
        raise api_error(403, "setup_required")
    rp = relying_party()
    await _switched_on(db)
    ip = client_ip(request)
    if bruteforce.ip_blocked(ip):
        raise api_error(403, "ip_blocked")
    if pending is None or pending.expires <= time.monotonic():
        raise api_error(400, "passkey_expired")  # nothing guessed – start again
    try:
        raw_id = _decode(body.raw_id, webauthn.MAX_CREDENTIAL_ID) or b""
        same_id = body.id == body.raw_id  # `id` is the base64url form of `raw_id` – nothing secret
        client_data = _decode(body.client_data_json, webauthn.MAX_CLIENT_DATA) or b""
        auth_data = _decode(body.authenticator_data, webauthn.MAX_AUTH_DATA) or b""
        signature = _decode(body.signature, webauthn.MAX_SIGNATURE) or b""
        handle = _decode(body.user_handle, 64)
    except webauthn.WebAuthnError:
        return await _refuse(db, "#passkey", ip, "encoding")
    key = f"passkey:{hashlib.sha256(raw_id).hexdigest()[:32]}"
    async with bruteforce.gate(key, ip) as free:
        if not free:
            raise api_error(429, "too_many_attempts")
        if not same_id:
            return await _refuse(db, key, ip, "id")
        cred = await db.scalar(select(UserPasskey).where(UserPasskey.credential_id == raw_id))
        user = await db.get(User, cred.user_id) if cred is not None else None
        if cred is None or user is None:
            return await _refuse(db, key, ip, "unknown credential")
        if not user.is_active or user.auth_source != "local":
            return await _refuse(db, key, ip, "account inactive or not local")
        # a discoverable credential names its account: the user handle must be there and be this account's
        if handle is None or not hmac.compare_digest(handle, user.id.bytes):
            return await _refuse(db, key, ip, "user handle")
        try:
            count = webauthn.verify_assertion(rp, pending.challenge, public_key=cred.public_key, client_data_json=client_data, authenticator_data=auth_data, signature=signature)
        except webauthn.WebAuthnError as exc:
            return await _refuse(db, key, ip, exc.code)
        at = datetime.now(UTC)
        regressed = webauthn.counter_regressed(cred.sign_count, count)
        if not regressed and count:
            # conditional: two sign-ins at once with the same counter – the second one is the regression
            res = await db.execute(
                update(UserPasskey)
                .where(UserPasskey.id == cred.id, UserPasskey.sign_count < count)
                .values(sign_count=count, last_used_at=at)
                .execution_options(synchronize_session=False)
            )
            regressed = res.rowcount != 1
        if regressed:
            log.warning("passkey %s of %s: signature counter did not go up (stored %s, got %s) – possibly a cloned authenticator", cred.id, user.username, cred.sign_count, count)
            await db.execute(update(UserPasskey).where(UserPasskey.id == cred.id).values(sign_count_warning_at=at, last_used_at=at).execution_options(synchronize_session=False))
            audit.record(db, audit.SYSTEM, "passkey.sign_count_warning", audit.user_target(user), {"name": cred.name, "stored": cred.sign_count, "got": count}, ip=ip)
        elif not count:
            await db.execute(update(UserPasskey).where(UserPasskey.id == cred.id).values(last_used_at=at).execution_options(synchronize_session=False))
        sess, _ = await sessions.create(db, user, "pre", ip, user_agent(request), method="passkey", passkey_id=cred.id)
        out = await _finish(db, sess, user, await next_after_mfa(db, sess, user), response)
    return out


# ---------------------------------------------------------------- own passkeys


@router.get("/me/passkeys")
async def my_passkeys(user: Reader, db: Db) -> list[dict]:
    return [passkey_out(p) for p in await _list(db, user.id)]


@router.post("/me/passkeys/options")
async def register_options(user: Reader, sess: ActiveSession, db: Db) -> dict:
    _local(user)
    rp = relying_party()
    await _switched_on(db)
    require_reauth(sess, user)
    return await _registration_options(db, rp, user, sess)


async def _registration_options(db, rp: webauthn.RelyingParty, user: User, sess: UserSession) -> dict:  # noqa: ANN001
    have = await _list(db, user.id)
    if len(have) >= MAX_PER_USER:
        raise api_error(409, "passkey_limit", max=MAX_PER_USER)
    t = time.monotonic()
    # one account (one person signing in again and again, each sign-in a session of its own) holds only a few of them
    if sum(1 for k, v in _register.items() if v.user_id == user.id and k != sess.id and v.expires > t) >= REGISTER_PER_USER:
        raise api_error(429, "passkey_busy")
    if len(_register) >= MAX_PENDING:
        _sweep(_register, t)
        if len(_register) >= MAX_PENDING:
            raise api_error(429, "passkey_busy")
    challenge = secrets.token_bytes(32)
    _register[sess.id] = _Pending(challenge=challenge, expires=t + CHALLENGE_TTL, user_id=user.id)
    return {
        "rp": {"id": rp.rp_id, "name": RP_NAME},
        "user": {"id": webauthn.b64url(user.id.bytes), "name": user.username, "displayName": user.display_name or user.username},
        "challenge": webauthn.b64url(challenge),
        "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in webauthn.ALGORITHMS],
        "timeout": TIMEOUT_MS,
        "attestation": "none",
        "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"},
        # the same authenticator twice makes no sense – the browser says so (InvalidStateError)
        "excludeCredentials": [{"type": "public-key", "id": webauthn.b64url(p.credential_id), "transports": list(p.transports or [])} for p in have],
    }


@router.post("/me/passkeys")
async def register(body: RegistrationIn, user: Reader, sess: ActiveSession, db: Db) -> dict:
    _local(user)
    rp = relying_party()
    await _switched_on(db)
    require_reauth(sess, user)
    row = await _add(db, rp, user, sess, body)
    await db.commit()
    log.info("passkey %s registered for %s", row.id, user.username)
    return passkey_out(row)


async def _add(db, rp: webauthn.RelyingParty, user: User, sess: UserSession, body: RegistrationIn, *, at_signin: bool = False) -> UserPasskey:  # noqa: ANN001
    """The answer of the browser checked against the session's pending challenge, the passkey added and logged – flushed,
    not committed (409 passkey_exists when the credential is registered already)."""
    pending = _register.pop(sess.id, None)  # single use
    if pending is None or pending.expires <= time.monotonic() or pending.user_id != user.id:
        raise api_error(409, "passkey_expired")
    try:
        if body.id != body.raw_id:
            raise webauthn.WebAuthnError("credential_id")
        new = webauthn.verify_registration(
            rp,
            pending.challenge,
            raw_id=webauthn.unb64url(body.raw_id, limit=webauthn.MAX_CREDENTIAL_ID),
            client_data_json=webauthn.unb64url(body.client_data_json, limit=webauthn.MAX_CLIENT_DATA),
            attestation_object=webauthn.unb64url(body.attestation_object, limit=webauthn.MAX_ATTESTATION),
        )
    except webauthn.WebAuthnError as exc:
        log.info("passkey registration of %s refused: %s", user.username, exc.code)
        raise api_error(400, "passkey_invalid", reason=exc.code) from None
    # counted again in the transaction that adds it: two registrations at once do not pass the limit together
    await db.execute(select(User.id).where(User.id == user.id).with_for_update())
    if int(await db.scalar(select(func.count()).select_from(UserPasskey).where(UserPasskey.user_id == user.id)) or 0) >= MAX_PER_USER:
        raise api_error(409, "passkey_limit", max=MAX_PER_USER)
    row = UserPasskey(
        user_id=user.id,
        name=body.name,
        credential_id=new.credential_id,
        public_key=new.public_key,
        sign_count=new.sign_count,
        transports=sorted({t for t in body.transports if t in TRANSPORTS}),
    )
    db.add(row)
    audit.record(db, user, "passkey.added", audit.user_target(user), {"name": row.name, "transports": row.transports, **({"at_signin": True} if at_signin else {})})
    try:
        await db.flush()
    except IntegrityError as exc:  # this credential id is registered already (for anyone)
        await db.rollback()
        raise api_error(409, "passkey_exists") from exc
    return row


# ---------------------------------------------------------------- at the sign-in, instead of TOTP (stage "enroll")


async def _enroll_allowed(db, user: User) -> webauthn.RelyingParty:  # noqa: ANN001
    _local(user)
    rp = relying_party()
    await _switched_on(db)
    if not (await enroll_info(db, user))["passkey"]:
        raise api_error(409, "totp_required")  # an admin: TOTP
    return rp


@router.post("/auth/enroll/passkey/options")
async def enroll_options(got: EnrollSession, db: Db) -> dict:
    sess, user = got
    return await _registration_options(db, await _enroll_allowed(db, user), user, sess)


@router.post("/auth/enroll/passkey")
async def enroll_passkey(body: RegistrationIn, got: EnrollSession, response: Response, db: Db) -> dict:
    sess, user = got
    row = await _add(db, await _enroll_allowed(db, user), user, sess, body, at_signin=True)
    sess.passkey_id = row.id  # removing this passkey ends the session it completed
    log.info("passkey %s registered for %s at the sign-in", row.id, user.username)
    return await _finish(db, sess, user, "active", response)


async def _own(db, user_id: uuid.UUID, pid: uuid.UUID) -> UserPasskey:  # noqa: ANN001
    p = await db.get(UserPasskey, pid)
    if p is None or p.user_id != user_id:
        raise api_error(404, "not_found")
    return p


@router.patch("/me/passkeys/{pid}")
async def rename(pid: uuid.UUID, body: NameIn, user: Reader, db: Db) -> dict:
    """A name only – no re-confirmation."""
    p = await _own(db, user.id, pid)
    if (changes := audit.diff({"name": p.name}, {"name": body.name})):
        audit.record(db, user, "passkey.renamed", audit.user_target(user), {"changes": changes})
    p.name = body.name
    await db.commit()
    return passkey_out(p)


@router.delete("/me/passkeys/{pid}")
async def remove(pid: uuid.UUID, user: Reader, sess: ActiveSession, db: Db) -> dict:
    require_reauth(sess, user)
    p = await _own(db, user.id, pid)
    ended = await end_sessions_of(db, p.id, keep=sess.id)
    audit.record(db, user, "passkey.removed", audit.user_target(user), {"name": p.name, "by_admin": False, "sessions_ended": ended})
    await db.delete(p)
    await db.commit()
    log.info("passkey %s of %s removed by its owner (%s sessions ended)", pid, user.username, ended)
    return {"ok": True, "sessions_ended": ended}


# ---------------------------------------------------------------- admins


async def _target(db, uid: uuid.UUID) -> User:  # noqa: ANN001
    u = await db.get(User, uid)
    if u is None:
        raise api_error(404, "not_found")
    return u


@admin_router.get("/users/{uid}/passkeys")
async def user_passkeys(uid: uuid.UUID, admin: Admin, db: Db) -> list[dict]:
    await _target(db, uid)
    return [passkey_out(p) for p in await _list(db, uid)]


@admin_router.delete("/users/{uid}/passkeys/{pid}")
async def remove_user_passkey(uid: uuid.UUID, pid: uuid.UUID, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """An admin removes someone's passkey (lost device) – re-confirmed; the sessions signed in with it end."""
    require_reauth(sess, admin)
    u = await _target(db, uid)
    p = await _own(db, u.id, pid)
    ended = await end_sessions_of(db, p.id, keep=sess.id)
    audit.record(db, admin, "passkey.removed", audit.user_target(u), {"name": p.name, "by_admin": True, "sessions_ended": ended})
    await db.delete(p)
    await db.commit()
    log.info("passkey %s of %s removed by admin %s (%s sessions ended)", pid, u.username, admin.username, ended)
    return {"ok": True, "sessions_ended": ended}


class PasskeySettingsIn(_M):
    enabled: bool
    rev: int | None = None


async def _settings_out(db) -> dict:  # noqa: ANN001
    cfg = await settings_store.get(db, "passkeys")
    rp, why = webauthn.availability()
    return {"enabled": bool(cfg["enabled"]), "rev": int(cfg.get("rev") or 0), "available": rp is not None, "reason": why, "rp_id": rp.rp_id if rp else None, "origin": rp.origin if rp else None}


@admin_router.get("/auth/passkeys")
async def get_settings(admin: Admin, db: Db) -> dict:
    return await _settings_out(db)


@admin_router.put("/auth/passkeys")
async def put_settings(body: PasskeySettingsIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    require_reauth(sess, admin)
    cur = await settings_store.get(db, "passkeys")
    value = {"enabled": body.enabled}
    if changes := audit.diff(cur, value, value.keys()):
        audit.record(db, admin, "settings.changed", audit.target("settings", "passkeys", "passkeys"), {"changes": changes})
    await settings_store.put_rev(db, "passkeys", value, body.rev)
    return await _settings_out(db)
