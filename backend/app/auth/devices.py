""""Zweiten Faktor auf dem Gerät merken": a browser where the TOTP code was given may skip the TOTP step at the next
sign-ins – for a while, and only after the right password.

- **Admin switch** (settings section "mfa": `remember`, off by default – it weakens the second factor, the admin
  decides). How long (`remember_days`): 0 = the maximum session lifetime (sessions settings `absolute_h`, "für die
  Sitzungsdauer"), or 1, 7 or 30 days – never longer (MAX_DAYS). Admin accounts only with `remember_admins` (off by
  default: admins keep their second factor everywhere else too – a passkey does not replace their TOTP). The emergency
  account never: it is the way back in after a takeover, its TOTP is not skipped.
- **What it skips.** Only the TOTP step (stage "mfa"), after the password (local, AD/LDAP) or Microsoft's sign-in
  (Entra – where Cobe News' own TOTP is asked; Microsoft's own MFA is Microsoft's business). Never the password, never
  the replacement of a temporary password, never a set-up that is due, never a re-confirmation for sensitive actions
  (/auth/reauth asks for the code; a remembered sign-in is no fresh proof of identity). Brute-force counters and locks
  stay as they are: the password is checked first, exactly as without.
- **The browser** holds a random token (32 bytes) in its own cookie: HttpOnly, Secure like the session cookie (then
  with the __Secure- prefix), SameSite=Strict, Path=/api/auth (only the sign-in and the device list see it), Max-Age =
  the duration. The table (RememberedDevice) holds only its keyed hash (crypto.token_hash), the account, when, until
  when, when last used, the address and the browser. MAX_PER_USER per account (the oldest go).
- **Bound to the account and its factors.** A row counts only for the account it was made for (another person's cookie
  is ignored, their row untouched), and only while `factor` – a keyed fingerprint of the account's password hash, TOTP
  secret, role and source – is unchanged: a new password (also a temporary one), a TOTP set up anew or reset, a new role
  all make it worthless. (An AD password changed in the directory cannot be seen here – the AD password itself is still
  asked every time.)
- **Forgotten** (rows deleted): by the person (Meine Sitzungen: one, or all), by an admin (user drawer), with "alle
  Sitzungen beenden", whenever an account's sessions are ended because of a block, deactivation, reset, role change or
  password change (sessions.revoke_all / revoke_users), when the admin switch goes off (all) or admins are excluded
  again (theirs). A shorter duration counts at once: `valid` measures from `created_at` with the duration set now.
  Expired rows go with the hourly session cleanup.
- **Audit log:** device.remembered and device.forgotten (by the person or an admin); a sign-in with a remembered device
  carries the method …_device (password_device, ldap_device, entra_device) – in an admin's login.success and on every
  entry made in that session."""

import hmac
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import Request, Response
from sqlalchemy import delete, select

from app import audit
from app import settings as settings_store
from app.config import get_config
from app.crypto import new_token, token_hash
from app.models import RememberedDevice, User

COOKIE = "cobe_news_device"
PATH = "/api/auth"
DAYS = (0, 1, 7, 30)  # 0: the maximum session lifetime (sessions settings absolute_h, at most 72 h)
MAX_DAYS = 30
MAX_PER_USER = 20


def now() -> datetime:
    return datetime.now(UTC)


def cookie_name() -> str:
    """__Secure-: only a secure origin may set it (no plain-http page can plant one). Not __Host- – that needs Path=/."""
    return f"__Secure-{COOKIE}" if get_config().cookie_secure else COOKIE


def cookie(request: Request) -> str | None:
    return request.cookies.get(cookie_name())


def set_cookie(response: Response, token: str, max_age: int) -> None:
    # Strict: it never comes along on a request another site starts – the page itself asks (Entra: POST /auth/mfa/device)
    response.set_cookie(cookie_name(), token, max_age=max_age, httponly=True, secure=get_config().cookie_secure, samesite="strict", path=PATH)


def clear_cookie(response: Response) -> None:
    response.delete_cookie(cookie_name(), path=PATH, secure=get_config().cookie_secure, httponly=True, samesite="strict")


def days_of(cfg: dict) -> int:
    d = int(cfg.get("remember_days") or 0)
    return d if d in DAYS else 0


def lifetime(mfa_cfg: dict, sess_cfg: dict) -> timedelta:
    """How long a remembered device counts, as set now – the session lifetime or 1, 7, 30 days."""
    d = days_of(mfa_cfg)
    return timedelta(days=min(d, MAX_DAYS)) if d else timedelta(hours=int(sess_cfg["absolute_h"]))


def applies(mfa_cfg: dict, user: User) -> bool:
    """May this account's TOTP step be skipped on a remembered device at all: the admin switch, admins only when
    included, never the emergency account – and only an account with TOTP (there is nothing else to skip)."""
    if not mfa_cfg.get("remember") or not user.is_active or user.is_emergency or not user.totp_secret_enc:
        return False
    return user.role != "admin" or bool(mfa_cfg.get("remember_admins"))


def factor(user: User) -> str:
    """The keyed fingerprint of what the remembered device stands on: any change of password, TOTP secret (encrypted
    with a fresh nonce each time it is set), role or source gives another value."""
    parts = ("device-factor", str(user.id), user.role or "", user.auth_source or "", user.password_hash or "", user.totp_secret_enc or "")
    return token_hash("\x1f".join(parts))


def valid(row: RememberedDevice, user: User, mfa_cfg: dict, sess_cfg: dict, t: datetime) -> bool:
    return (
        row.user_id == user.id
        and applies(mfa_cfg, user)
        and t < row.expires_at
        and t < row.created_at + lifetime(mfa_cfg, sess_cfg)
        and hmac.compare_digest(row.factor, factor(user))
    )


def label(ua: str | None) -> str:
    """Browser and system in a few words ("Chrome · macOS") – for the audit log; the page reads the User-Agent itself."""
    ua = ua or ""
    browser = next((n for k, n in (("Edg/", "Edge"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"), ("Safari/", "Safari")) if k in ua), "Browser")
    system = next((n for k, n in (("Windows", "Windows"), ("Mac OS X", "macOS"), ("Android", "Android"), ("iPhone", "iOS"), ("iPad", "iPadOS"), ("Linux", "Linux")) if k in ua), "")
    return f"{browser} · {system}" if system else browser


async def _cfgs(db) -> tuple[dict, dict]:  # noqa: ANN001
    return await settings_store.get(db, "mfa"), await settings_store.get(db, "sessions")


async def find(db, token: str | None) -> RememberedDevice | None:  # noqa: ANN001
    if not token or len(token) > 128:
        return None
    return await db.scalar(select(RememberedDevice).where(RememberedDevice.token_hash == token_hash(token)))


async def recognised(db, user: User, token: str | None, *, use: bool = True) -> bool:  # noqa: ANN001
    """Does this browser's cookie stand for a valid remembered device of exactly this account? `use`: note it as used
    now – and delete a row of this account that no longer counts (expired, factors changed, switched off). Another
    account's row is never touched. Not committed."""
    row = await find(db, token)
    if row is None or row.user_id != user.id:
        return False
    mfa_cfg, sess_cfg = await _cfgs(db)
    t = now()
    if not valid(row, user, mfa_cfg, sess_cfg, t):
        if use:
            await db.delete(row)
        return False
    if use:
        row.last_used_at = t
    return True


async def remember(db, user: User, ip: str | None, user_agent: str | None, old_token: str | None = None) -> tuple[str, int] | None:  # noqa: ANN001
    """Remember this browser for the account – (token for the cookie, max-age in seconds), or None when the rule does
    not allow it (switched off, an admin while admins are excluded, the emergency account). The browser's earlier row of
    the same account is replaced; at most MAX_PER_USER rows per account. Logged (device.remembered). Not committed."""
    mfa_cfg, sess_cfg = await _cfgs(db)
    if not applies(mfa_cfg, user):
        return None
    if (prev := await find(db, old_token)) is not None and prev.user_id == user.id:
        await db.delete(prev)
    t = now()
    life = lifetime(mfa_cfg, sess_cfg)
    token = new_token()
    row = RememberedDevice(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=token_hash(token),
        factor=factor(user),
        created_at=t,
        expires_at=t + life,
        last_used_at=t,
        ip=ip,
        user_agent=(user_agent or "")[:255],
    )
    db.add(row)
    await db.flush()
    keep = select(RememberedDevice.id).where(RememberedDevice.user_id == user.id).order_by(RememberedDevice.created_at.desc()).limit(MAX_PER_USER)
    await db.execute(delete(RememberedDevice).where(RememberedDevice.user_id == user.id, RememberedDevice.id.not_in(keep)))
    audit.record(db, user, "device.remembered", audit.user_target(user), {"device": label(user_agent), "until": (t + life).isoformat(timespec="minutes")}, ip=ip)
    return token, int(life.total_seconds())


async def offer(db, user: User) -> dict:  # noqa: ANN001
    """What the TOTP step shows: the switch "Auf diesem Gerät merken" – and until when it would count."""
    mfa_cfg, sess_cfg = await _cfgs(db)
    if not applies(mfa_cfg, user):
        return {"offer": False, "until": None}
    return {"offer": True, "until": (now() + lifetime(mfa_cfg, sess_cfg)).isoformat()}


async def listing(db, user: User, current: str | None) -> list[dict]:  # noqa: ANN001
    """The account's remembered devices that still count – this browser's first (`current`), then by last use."""
    mfa_cfg, sess_cfg = await _cfgs(db)
    t = now()
    mine = token_hash(current) if current and len(current) <= 128 else None
    out = [
        {
            "id": str(r.id),
            "current": r.token_hash == mine,
            "created_at": r.created_at.isoformat(),
            "expires_at": min(r.expires_at, r.created_at + lifetime(mfa_cfg, sess_cfg)).isoformat(),
            "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
            "ip": r.ip,
            "user_agent": r.user_agent or "",
        }
        for r in await db.scalars(select(RememberedDevice).where(RememberedDevice.user_id == user.id))
        if valid(r, user, mfa_cfg, sess_cfg, t)
    ]
    first = [x for x in out if x["current"]]
    rest = sorted((x for x in out if not x["current"]), key=lambda x: x["last_used_at"] or x["created_at"], reverse=True)
    return first + rest


async def forget_one(db, user_id: uuid.UUID, device_id: uuid.UUID) -> RememberedDevice | None:  # noqa: ANN001
    row = await db.scalar(select(RememberedDevice).where(RememberedDevice.id == device_id, RememberedDevice.user_id == user_id))
    if row is not None:
        await db.delete(row)
        await db.flush()
    return row


async def forget_all(db, user_id: uuid.UUID) -> int:  # noqa: ANN001
    return (await db.execute(delete(RememberedDevice).where(RememberedDevice.user_id == user_id))).rowcount or 0


async def forget_users(db, user_ids) -> int:  # noqa: ANN001 - a list of ids or a select of them
    if not isinstance(user_ids, list):
        return (await db.execute(delete(RememberedDevice).where(RememberedDevice.user_id.in_(user_ids)))).rowcount or 0
    n = 0
    for i in range(0, len(user_ids), 1000):
        n += (await db.execute(delete(RememberedDevice).where(RememberedDevice.user_id.in_(user_ids[i : i + 1000])))).rowcount or 0
    return n


async def forget_everyone(db, *, admins_only: bool = False) -> int:  # noqa: ANN001
    """The admin switch off (all), or admins excluded again (theirs). Not committed."""
    stmt = delete(RememberedDevice)
    if admins_only:
        stmt = stmt.where(RememberedDevice.user_id.in_(select(User.id).where(User.role == "admin")))
    return (await db.execute(stmt)).rowcount or 0


async def cleanup(db) -> int:  # noqa: ANN001
    """Expired rows (by their own end) – with the hourly session cleanup. Not committed."""
    return (await db.execute(delete(RememberedDevice).where(RememberedDevice.expires_at <= now()))).rowcount or 0
