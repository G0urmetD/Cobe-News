"""Server-side sessions: the browser holds a random token, the table its keyed
hash. Idle and absolute timeout from the "sessions" settings; stages before "active" live 10 minutes."""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import Response
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app import settings as settings_store
from app.config import get_config
from app.crypto import new_token, token_hash
from app.models import User, UserSession

SESSION_COOKIE = "cobe_news_session"
CSRF_COOKIE = "cobe_news_csrf"
PRE_AUTH = timedelta(minutes=10)
TOUCH_INTERVAL = timedelta(minutes=5)  # at most a fifth of the idle timeout (idle_min ≥ 5: at least every minute)
TOUCH_WAIT_MS = 1000  # the touch waits this long for another writer, then gives up – it is best-effort
log = logging.getLogger("cobe_news.sessions")


def now() -> datetime:
    return datetime.now(UTC)


METHODS = ("password", "password_totp", "ldap", "ldap_totp", "passkey", "entra", "entra_totp")


async def create(
    db: AsyncSession, user: User, stage: str, ip: str, user_agent: str | None, *, method: str | None = None, passkey_id: uuid.UUID | None = None
) -> tuple[UserSession, str]:
    cfg = await settings_store.get(db, "sessions")
    token = new_token()
    life = timedelta(hours=int(cfg["absolute_h"])) if stage == "active" else PRE_AUTH
    sess = UserSession(
        token_hash=token_hash(token),
        user_id=user.id,
        stage=stage,
        expires_at=now() + life,
        ip=ip,
        user_agent=(user_agent or "")[:255],
        pending={},
        method=method,
        passkey_id=passkey_id,
    )
    db.add(sess)
    await db.flush()
    return sess, token


async def promote(db: AsyncSession, sess: UserSession, stage: str) -> str:
    """Another stage with a new token (no session fixation across the steps of a sign-in)."""
    cfg = await settings_store.get(db, "sessions")
    token = new_token()
    sess.token_hash, sess.stage, sess.pending = token_hash(token), stage, {}
    sess.created_at = sess.last_seen_at = now()
    sess.expires_at = now() + (timedelta(hours=int(cfg["absolute_h"])) if stage == "active" else PRE_AUTH)
    if stage == "active":
        sess.reauth_at = now()  # the complete sign-in counts as a fresh proof of identity (REAUTH_WINDOW)
    return token


def with_totp(sess: UserSession) -> None:
    """The TOTP code was checked in this sign-in: password → password_totp, ldap → ldap_totp, entra → entra_totp."""
    if sess.method in ("password", "ldap", "entra"):
        sess.method = f"{sess.method}_totp"


def rekey(sess: UserSession) -> str:
    """A new token for the same session (after a password change: no fixation), nothing else – neither a fresh proof of
    identity for sensitive actions (that needs the TOTP code, /auth/reauth) nor a new absolute lifetime."""
    token = new_token()
    sess.token_hash, sess.pending = token_hash(token), {}
    return token


REAUTH_WINDOW = timedelta(minutes=10)


def reauth_valid(sess: UserSession) -> bool:
    """Sensitive admin actions (sign-in settings, users, mappings) need a proof of identity of the last minutes."""
    return bool(sess.reauth_at and now() - sess.reauth_at < REAUTH_WINDOW)


def _idle(sess: UserSession, cfg: dict) -> timedelta:
    return timedelta(minutes=int(cfg["idle_min"])) if sess.stage == "active" else PRE_AUTH


def ended(sess: UserSession, cfg: dict, t: datetime) -> bool:
    """Over by its lifetime, idle time or – as set now – absolute lifetime (a shorter one also ends sessions begun
    before the change); `load` deletes such a row when it is next used, `cleanup` hourly."""
    absolute = sess.stage == "active" and sess.created_at + timedelta(hours=int(cfg["absolute_h"])) <= t
    return sess.expires_at <= t or sess.last_seen_at + _idle(sess, cfg) <= t or absolute


def timing(sess: UserSession, cfg: dict, t: datetime) -> dict:
    """How long this active session has left, for the browser's tabs (lib/session-sync.ts): they look again shortly after
    the end instead of finding out with the next click. Seconds left (no clock of the browser involved), the idle limit
    and how often a request moves "last active" (TOUCH_INTERVAL, throttled) – times and limits only, nothing secret."""
    idle = _idle(sess, cfg)
    absolute = min(sess.expires_at, sess.created_at + timedelta(hours=int(cfg["absolute_h"])))
    return {
        "idle_left_s": max(0, int((sess.last_seen_at + idle - t).total_seconds())),
        "absolute_left_s": max(0, int((absolute - t).total_seconds())),
        "idle_min": int(cfg["idle_min"]),
        "touch_s": int(min(TOUCH_INTERVAL, idle / 5).total_seconds()),
    }


async def load(db: AsyncSession, token: str | None, *, touch: bool = True) -> tuple[UserSession, User] | None:
    if not token or len(token) > 128:
        return None
    sess = await db.scalar(select(UserSession).where(UserSession.token_hash == token_hash(token)))
    if sess is None:
        return None
    user = await db.get(User, sess.user_id)
    cfg = await settings_store.get(db, "sessions")
    t = now()
    idle = _idle(sess, cfg)
    if user is None or not user.is_active or ended(sess, cfg, t):
        try:
            await db.delete(sess)
            await db.commit()
        except DBAPIError:  # row locked by another request: the session is over anyway – cleanup() removes it later
            await db.rollback()
            log.info("session cleanup deferred: database busy")
        return None
    if touch and t - sess.last_seen_at > min(TOUCH_INTERVAL, idle / 5):
        await _touch(db, sess, user, t)
    return sess, user


async def _touch(db: AsyncSession, sess: UserSession, user: User, t: datetime) -> bool:
    """last_seen_at in a short transaction, waiting at most TOUCH_WAIT_MS for the row (another request of the same
    session touching or ending it). Best-effort: a locked row skips it (the next request touches again) – it never
    fails or holds up a request. The lock timeout is local to this transaction (gone with its commit or rollback)."""
    try:
        await db.execute(text(f"SET LOCAL lock_timeout = {int(TOUCH_WAIT_MS)}"))
        await db.execute(update(UserSession).where(UserSession.id == sess.id).values(last_seen_at=t))
        ok = True
    except DBAPIError:
        ok = False
    if ok:
        try:
            await db.commit()
        except DBAPIError:
            ok = False
    if not ok:
        await db.rollback()  # ends the begun transaction – a later write of this request starts fresh
        await db.refresh(sess)
        await db.refresh(user)
        log.info("session touch skipped: row busy")
        return False
    set_committed_value(sess, "last_seen_at", t)
    return True


async def revoke(db: AsyncSession, session_id: uuid.UUID) -> None:
    await db.execute(delete(UserSession).where(UserSession.id == session_id))


async def revoke_all(db: AsyncSession, user_id: uuid.UUID, except_id: uuid.UUID | None = None) -> None:
    stmt = delete(UserSession).where(UserSession.user_id == user_id)
    if except_id:
        stmt = stmt.where(UserSession.id != except_id)
    await db.execute(stmt)


async def revoke_users(db: AsyncSession, user_ids) -> None:  # noqa: ANN001 - a list of ids or a select of them
    """Every session of these accounts (a role mapping removed, a directory switched off) – not committed."""
    if isinstance(user_ids, list):
        for i in range(0, len(user_ids), 1000):
            await db.execute(delete(UserSession).where(UserSession.user_id.in_(user_ids[i : i + 1000])))
    else:
        await db.execute(delete(UserSession).where(UserSession.user_id.in_(user_ids)))


async def cleanup(db: AsyncSession) -> int:
    res = await db.execute(delete(UserSession).where(UserSession.expires_at <= now()))
    await db.commit()
    return res.rowcount or 0


def csrf_cookie_name() -> str:
    """The CSRF cookie with the same prefix: no subdomain or plain-http page can plant a token of its choice."""
    return f"__Host-{CSRF_COOKIE}" if get_config().cookie_secure else CSRF_COOKIE


def cookie_name() -> str:
    """__Host-: only this exact origin may set it (no subdomain, no plain http) – needs Secure, so not on plain http."""
    return f"__Host-{SESSION_COOKIE}" if get_config().cookie_secure else SESSION_COOKIE


def set_cookie(response: Response, token: str) -> None:
    # SameSite=Lax: the session comes along on the redirect back from Microsoft (Entra sign-in); writes are protected by
    # the CSRF token anyway
    response.set_cookie(cookie_name(), token, httponly=True, secure=get_config().cookie_secure, samesite="lax", path="/")


def clear_cookie(response: Response) -> None:
    response.delete_cookie(cookie_name(), path="/", secure=get_config().cookie_secure, httponly=True, samesite="lax")
