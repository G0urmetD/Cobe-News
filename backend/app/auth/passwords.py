"""Local passwords: argon2id, at least 12 characters, no well-known password."""

import asyncio
import re
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # argon2id, library defaults (t=3, m=64 MiB, p=4)
_DUMMY_HASH = _hasher.hash("cobe-news-dummy-password-for-timing")
MIN_LENGTH = 12

# Small built-in list of the passwords tried first
_COMMON = frozenset(
    """
123456789012 1234567890123 123456789 12345678 1234567890 password passwort qwertz qwerty qwertzuiop qwertyuiop 111111111111
000000000000 abc123 iloveyou admin administrator welcome willkommen letmein sommer2025 sommer2026 winter2025 winter2026
herbst2025 herbst2026 passwort1 passwort123 password1 password123 password1234 passwort1234 hallo123 changeme geheim
secret dragon monkey football fussball master shadow sunshine azerty test123 testtest start123 security sicherheit
sicherheit123 cobenews cobe-news newsreader passwortpasswort passwordpassword administrator1 willkommen123 welcome123
""".split()
)


def check_policy(password: str, *, username: str | None = None) -> list[str]:
    """The violated rules (empty = fine): min_length | max_length | common."""
    failed = []
    if len(password) < MIN_LENGTH:
        failed.append("min_length")
    if len(password) > 256:
        failed.append("max_length")
    lowered = password.lower()
    stripped = re.sub(r"[\d\W_]+$", "", lowered)
    if lowered in _COMMON or stripped in _COMMON or len(set(lowered)) <= 3 or (username and len(username) >= 4 and username.lower() in lowered):
        failed.append("common")
    return failed


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Constant-ish time: always one argon2 verification, even without a stored hash (no hint which accounts exist)."""
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def temp_password() -> str:
    """A temporary password an admin hands over – changed at the next sign-in."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4))


TEMP_DAYS = 7  # default of `temp_password_days` (settings section "sessions"), 1–30


def temp_days(cfg: dict) -> int:
    """How many days a temporary password is valid (the "sessions" section; out of range: the default)."""
    try:
        days = int(cfg.get("temp_password_days", TEMP_DAYS))
    except (TypeError, ValueError):
        return TEMP_DAYS
    return days if 1 <= days <= 30 else TEMP_DAYS


def temp_expires_at(user, days: int) -> datetime | None:  # noqa: ANN001 - a models.User
    """When the account's temporary password stops being accepted – None: it has none (a local account only). The issue
    time is `temp_password_at`; an account without one (made before it was stored) counts from its creation."""
    if not (user.must_change_password and user.auth_source == "local"):
        return None
    issued = user.temp_password_at or user.created_at
    return issued + timedelta(days=days) if issued else None


def temp_expired(user, days: int, now: datetime | None = None) -> bool:  # noqa: ANN001
    end = temp_expires_at(user, days)
    return end is not None and end <= (now or datetime.now(UTC))


_slots: asyncio.Semaphore | None = None


def _sem() -> asyncio.Semaphore:
    global _slots  # noqa: PLW0603 - created lazily inside the running loop
    if _slots is None:
        _slots = asyncio.Semaphore(4)
    return _slots


async def averify_password(password_hash: str | None, password: str) -> bool:
    """Argon2 takes CPU time: in a thread, at most 4 at a time – a login flood must not stall the event loop."""
    async with _sem():
        return await asyncio.to_thread(verify_password, password_hash, password)


async def ahash_password(password: str) -> str:
    async with _sem():
        return await asyncio.to_thread(hash_password, password)


# ---------------------------------------------------------------- history: none of the last HISTORY passwords again

HISTORY = 5  # the current password and the HISTORY - 1 before it (table password_history) – local accounts only


async def reused(db, user, password: str) -> bool:  # noqa: ANN001 - an AsyncSession and a User (no import cycle)
    """True when `password` is the account's current one or one of the HISTORY - 1 kept before it. Each comparison is
    one argon2 verification (at most HISTORY) – the hashes never leave this function."""
    from sqlalchemy import select

    from app.models import PasswordHistory

    hashes = [user.password_hash] if user.password_hash else []
    hashes += list(
        await db.scalars(
            select(PasswordHistory.password_hash).where(PasswordHistory.user_id == user.id).order_by(PasswordHistory.created_at.desc()).limit(HISTORY - 1)
        )
    )
    for h in hashes:
        if await averify_password(h, password):
            return True
    return False


async def remember(db, user) -> None:  # noqa: ANN001
    """Before the account's password is replaced: its current one into the history – unless it is a temporary one (an
    admin's reset or a new account: never chosen by the person, never kept). Keeps the newest HISTORY - 1 (not
    committed)."""
    from sqlalchemy import delete, select

    from app.models import PasswordHistory

    if not user.password_hash or user.must_change_password or user.auth_source != "local":
        return
    db.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash))
    await db.flush()
    keep = select(PasswordHistory.id).where(PasswordHistory.user_id == user.id).order_by(PasswordHistory.created_at.desc(), PasswordHistory.id).limit(HISTORY - 1)
    await db.execute(delete(PasswordHistory).where(PasswordHistory.user_id == user.id, PasswordHistory.id.not_in(keep)).execution_options(synchronize_session=False))
