"""Audit log ("Protokoll"): the security-relevant admin and account actions – who, what, when, from where, on what, and
the changed fields before/after. Never a secret value: for a password, client secret, token, webhook URL, TOTP seed or
any other secret field only that it changed (`scrub`, the one place that decides – tests/test_audit.py fails when a new
field that looks secret would be logged in clear).

`record()` adds the entry to the session of the change itself: it is committed with the change, and a change that is
rolled back (refused, stale, failed) leaves no entry. Append-only – there is no API to edit or delete an entry; the
hourly prune removes what is older than the retention (settings section "audit", default 365 days, 90–3650).

Not logged: failed sign-ins one by one (anyone can send them – an unauthenticated flood would fill the log, and a
password typed into the name field would land in it) – nor refused passkey sign-ins, for the same reason; a lock of
an account and a block of an address are logged instead (login.locked, login.ip_blocked – at most a few per address,
the brute-force limits hold them; a passkey's refusals can block the address too). Sign-ins are logged for admins only
(login.success, with the method: password, password_totp, ldap, ldap_totp, passkey, entra, entra_totp) – a reader's last sign-in is
on the account; reading the log itself neither. A passkey whose signature counter went back is logged every time
(passkey.sign_count_warning, actor the system): it takes the passkey's own signature, nobody else can cause it."""

import base64
import contextvars
import csv
import io
import re
import uuid
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import Select, and_, delete, func, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditEntry

SECTION = "audit"  # settings: {"keep_days": 365, "rev": n}
KEEP_DEFAULT, KEEP_MIN, KEEP_MAX = 365, 90, 3650
PAGE_MAX = 200
EXPORT_MAX = 100_000  # rows in one CSV export (the newest – narrow the filters for older ones)
TEXT_MAX = 300  # a logged value is cut after this many characters
LIST_MAX = 50  # … a list after this many items

# ---------------------------------------------------------------- what is logged

# action → group (the filter and the icon in the UI; the texts are in the UI's i18n, audit.action.<key>)
GROUPS: dict[str, tuple[str, ...]] = {
    "accounts": (
        "user.created",
        "user.changed",
        "user.deleted",
        "user.activated",
        "user.deactivated",
        "user.blocked",
        "user.unblocked",
        "user.reset",
        "user.unlocked",
        "role.changed",
        "account.password_changed",
        "account.totp_enabled",
        "account.totp_removed",
        "passkey.added",
        "passkey.renamed",
        "passkey.removed",
        "passkey.sign_count_warning",
        "sessions.revoked",
    ),
    "signin": (
        "signin.config_changed",
        "role_mapping.created",
        "role_mapping.deleted",
        "login.success",
        "login.locked",
        "login.ip_blocked",
        "setup.completed",
    ),
    "tokens": ("token.created", "token.revoked"),
    "notify": ("channel.created", "channel.changed", "channel.deleted", "rule.created", "rule.changed", "rule.deleted", "delivery.resent"),
    "teams": (
        "team.created",
        "team.changed",
        "team.deleted",
        "team.group_added",
        "team.group_removed",
        "team.member_added",
        "team.member_removed",
        "team.products_changed",
        "team.routing_changed",
        "team.weekly_changed",
        "team.absence_set",
        "team.absence_ended",
        "team.synced",
    ),
    "settings": ("settings.changed",),
    "backup": ("backup.created", "backup.restored", "backup.deleted", "restore_test.run", "export.downloaded", "audit.exported"),
    "sources": (
        "source.created",
        "source.changed",
        "source.deleted",
        "catalog.followed",
        "catalog.unfollowed",
        "catalog.follow_changed",
        "catalog.custom_added",
        "catalog.version_added",
        "catalog.version_changed",
        "catalog.version_deleted",
        "catalog.version_confirmed",
        "catalog.versions_confirmed",
        "catalog.refreshed",
        "suggestion.accepted",
        "suggestion.rejected",
        "suggestion.duplicate",
    ),
}
ACTIONS: dict[str, str] = {a: g for g, actions in GROUPS.items() for a in actions}
ACTOR_KINDS = ("user", "system", "sync", "cli")


@dataclass(frozen=True)
class Actor:
    kind: str  # user | system | sync | cli
    id: uuid.UUID | None = None
    name: str = ""
    display: str = ""


SYSTEM = Actor("system", name="system")
SYNC = Actor("sync", name="directory-sync")  # the hourly sync, a team load, a directory sign-in deciding the role
CLI = Actor("cli", name="cli")  # python -m app.cli (reset-emergency, backup, restore …)


def actor_of(user) -> Actor:  # noqa: ANN001 - a User or an Actor
    if isinstance(user, Actor):
        return user
    return Actor("user", user.id, user.username or "", user.display_name or "")


@dataclass(frozen=True)
class Target:
    type: str
    id: str | None = None
    label: str | None = None


def target(kind: str, id_=None, label: str | None = None) -> Target:  # noqa: ANN001
    return Target(kind, None if id_ is None else str(id_), label)


def user_target(u) -> Target:  # noqa: ANN001 - a User
    return Target("user", str(u.id), u.username)


# the client address of the request being served – set by the middleware in main.py (deps.client_ip), so record() needs
# no Request in every endpoint's signature. Tasks started from a request inherit it: only an account's actions use it.
_ip: contextvars.ContextVar[str | None] = contextvars.ContextVar("audit_ip", default=None)


def set_ip(ip: str | None) -> contextvars.Token:
    return _ip.set(ip)


def reset_ip(token: contextvars.Token) -> None:
    _ip.reset(token)


# ---------------------------------------------------------------- never a secret (the one place that decides)

# a field whose name matches: never logged in clear – only {"secret": true, "changed": true}
SECRET_NAME = re.compile(
    r"pass(word|phrase)?|secret|token|hmac|_enc$|^enc_|header_value|private|credential|api_?key|nvd_key|totp|seed|cookie|signature|bearer|vapid|hash|salt|otp|webhook|teams_url|^auth$|p256dh|^topic$",
    re.IGNORECASE,
)
# names the SECRET_NAME pattern (or the broader one of the test) catches that are no secret – reviewed one by one
NOT_SECRET = frozenset(
    {
        "token_set",  # whether a token is set (a bool)
        "url_set",
        "hmac_set",
        "header_set",
        "password_set",
        "bind_password_set",
        "client_secret_set",
        "nvd_key_set",
        "temp_password_days",  # how many days a temporary password is valid (a number)
    }
)
SECRET_MARK = {"secret": True, "changed": True}
_SECRET_KEYS = frozenset(SECRET_MARK)


def is_secret(name: str) -> bool:
    n = str(name).lower()
    return n not in NOT_SECRET and bool(SECRET_NAME.search(n))


def _url_origin(v: str) -> str | None:
    """A URL as scheme://host[:port] only: a webhook keeps its token in the path, a feed may keep one in the query, an
    address may carry user:password – none of them is logged."""
    try:
        p = urlsplit(v)
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https", "ldap", "ldaps", "smtp", "smtps") or not p.hostname:
        return None
    host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname
    try:
        port = f":{p.port}" if p.port else ""
    except ValueError:
        port = ""
    rest = "/…" if (p.path not in ("", "/") or p.query or p.fragment) else ""
    return f"{p.scheme.lower()}://{host}{port}{rest}"


_TOKEN_LIKE = re.compile(r"^(v1:|cnt_|cnc_)|^[A-Za-z0-9_\-]{40,}$")  # an encrypted value, an API or calendar token, a long key


def _value(v):  # noqa: ANN001, ANN202
    if isinstance(v, str):
        if _TOKEN_LIKE.search(v):
            return dict(SECRET_MARK)
        if "://" in v and (o := _url_origin(v.strip())):
            return o
        return v if len(v) <= TEXT_MAX else v[:TEXT_MAX] + "…"
    if isinstance(v, (bool, int, float)) or v is None:
        return v
    if hasattr(v, "isoformat"):  # datetime, date, time
        return v.isoformat()
    if isinstance(v, uuid.UUID):
        return str(v)
    return None


def scrub(value, depth: int = 0):  # noqa: ANN001, ANN201
    """What may be logged of a value: a secret-named field (or anything below one) as SECRET_MARK, an encrypted or
    token-like string as SECRET_MARK, a URL as its origin, long texts and lists cut, at most 6 levels deep."""
    if depth > 6:
        return None
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            k = str(k)
            if is_secret(k):
                out[k] = v if isinstance(v, dict) and set(v) <= _SECRET_KEYS and all(isinstance(x, bool) for x in v.values()) else dict(SECRET_MARK)
            else:
                out[k] = scrub(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else list(value)
        cut = [scrub(x, depth + 1) for x in items[:LIST_MAX]]
        return cut + ["…"] if len(items) > LIST_MAX else cut
    return _value(value)


SKIP = frozenset({"rev", "version"})  # concurrency counters, no change of their own


def diff(before: dict | None, after: dict | None, fields: Iterable[str] | None = None) -> dict:
    """The changed fields: {"field": {"from": …, "to": …}} – a secret one as {"field": SECRET_MARK} (its name without
    "_enc"), never its values. `fields`: only these (default: all of both, without the counters of SKIP)."""
    b, a = before or {}, after or {}
    keys = list(fields) if fields is not None else sorted(set(b) | set(a))
    out: dict = {}
    for k in keys:
        if (fields is None and k in SKIP) or b.get(k) == a.get(k):
            continue
        name = k.removesuffix("_enc")
        if is_secret(k) or is_secret(name):
            out[name] = dict(SECRET_MARK)
        else:
            out[k] = {"from": scrub(b.get(k), 1), "to": scrub(a.get(k), 1)}
    return out


# ---------------------------------------------------------------- writing


def _label(v: str | None) -> str | None:
    """A target's name as it was – scrubbed like a value (a name that looks like a token or a URL with a path is not
    logged as it is)."""
    got = _value(v) if v else None
    return got if isinstance(got, str) and got else ("•••" if v else None)


def record(
    db: AsyncSession,
    actor,  # noqa: ANN001 - a User or an Actor
    action: str,
    target: Target | None = None,
    details: dict | None = None,
    request=None,  # noqa: ANN001 - a fastapi Request: its client address instead of the middleware's
    ip: str | None = None,  # the address itself (a lock or block the system sets: the address it came from)
) -> AuditEntry:
    """An entry, added to `db` – committed with the change it records, gone with it when that is rolled back."""
    if action not in ACTIONS:
        raise ValueError(f"unknown audit action {action!r}")
    who = actor_of(actor)
    if ip is None and request is not None:
        from app.deps import client_ip

        ip = client_ip(request)
    elif ip is None and who.kind == "user":
        ip = _ip.get()
    entry = AuditEntry(
        at=datetime.now(UTC),
        actor_kind=who.kind,
        actor_id=who.id,
        actor_name=(who.name or who.kind)[:255],
        actor_display=(who.display or "")[:255],
        action=action,
        target_type=target.type if target else None,
        target_id=(target.id or None) if target else None,
        target_label=_label(target.label) if target else None,
        ip=ip,
        details=scrub(details or {}),
    )
    db.add(entry)
    return entry


# ---------------------------------------------------------------- retention


async def keep_days(db: AsyncSession) -> int:
    from app import settings as settings_store

    raw = (await settings_store.get(db, SECTION)).get("keep_days")
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return KEEP_DEFAULT
    return min(max(n, KEEP_MIN), KEEP_MAX)


async def prune(db: AsyncSession, now: datetime | None = None) -> int:
    """Entries older than the retention go (hourly, main.FetchLoop._prune) – the only way one is ever removed."""
    cut = (now or datetime.now(UTC)) - timedelta(days=await keep_days(db))
    res = await db.execute(delete(AuditEntry).where(AuditEntry.at < cut))
    await db.commit()
    return res.rowcount or 0


# ---------------------------------------------------------------- reading


@dataclass
class Filters:
    since: datetime | None = None
    until: datetime | None = None
    actor: str | None = None  # an account's id, or a kind: system | sync | cli
    group: str | None = None
    action: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    q: str | None = None


def _where(f: Filters) -> list:
    w: list = []
    if f.since:
        w.append(AuditEntry.at >= f.since)
    if f.until:
        w.append(AuditEntry.at < f.until)
    if f.actor:
        if f.actor in ACTOR_KINDS and f.actor != "user":
            w.append(AuditEntry.actor_kind == f.actor)
        else:
            try:
                w.append(AuditEntry.actor_id == uuid.UUID(f.actor))
            except ValueError:
                w.append(AuditEntry.id.is_(None))  # nothing
    if f.group:
        w.append(AuditEntry.action.in_(GROUPS.get(f.group, ())))
    if f.action:
        w.append(AuditEntry.action == f.action)
    if f.target_type:
        w.append(AuditEntry.target_type == f.target_type)
    if f.target_id:
        w.append(AuditEntry.target_id == f.target_id)
    if f.q and f.q.strip():
        v = f.q.strip().lower()
        cols = (AuditEntry.actor_name, AuditEntry.actor_display, AuditEntry.action, AuditEntry.target_label, AuditEntry.target_id, AuditEntry.ip)
        w.append(or_(*(func.lower(func.coalesce(c, "")).contains(v, autoescape=True) for c in cols)))
    return w


def _query(f: Filters) -> Select:
    return select(AuditEntry).where(*_where(f)).order_by(AuditEntry.at.desc(), AuditEntry.id.desc())


def encode_cursor(e: AuditEntry) -> str:
    return base64.urlsafe_b64encode(f"{e.at.isoformat()}|{e.id}".encode()).decode().rstrip("=")


def decode_cursor(c: str) -> tuple[datetime, int]:
    """The keyset position after which the next page starts (ValueError: not one of ours)."""
    raw = base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)).decode()
    at, _, n = raw.partition("|")
    when = datetime.fromisoformat(at)
    if when.tzinfo is None:
        raise ValueError("naive")
    return when, int(n)


async def page(db: AsyncSession, f: Filters, cursor: str | None = None, limit: int = 50) -> tuple[list[AuditEntry], str | None]:
    """One page, newest first – keyset (at, id) after `cursor`, never OFFSET: a page stays right while entries arrive."""
    q = _query(f)
    if cursor:
        at, n = decode_cursor(cursor)
        q = q.where(tuple_(AuditEntry.at, AuditEntry.id) < tuple_(at, n))
    rows = list(await db.scalars(q.limit(limit + 1)))
    more = len(rows) > limit
    rows = rows[:limit]
    return rows, encode_cursor(rows[-1]) if more and rows else None


def entry_out(e: AuditEntry) -> dict:
    return {
        "id": e.id,
        "at": e.at.isoformat(),
        "actor": {"kind": e.actor_kind, "id": str(e.actor_id) if e.actor_id else None, "name": e.actor_name, "display": e.actor_display},
        "action": e.action,
        "group": ACTIONS.get(e.action, "other"),
        "target": {"type": e.target_type, "id": e.target_id, "label": e.target_label} if e.target_type else None,
        "ip": e.ip,
        "details": e.details or {},
    }


async def actors(db: AsyncSession) -> list[dict]:
    """Who appears in the log (for the filter): accounts by their newest name, then the other kinds."""
    newest = (
        select(AuditEntry.actor_id, func.max(AuditEntry.id).label("last"))
        .where(AuditEntry.actor_id.is_not(None))
        .group_by(AuditEntry.actor_id)
        .subquery()
    )
    rows = await db.execute(
        select(AuditEntry.actor_id, AuditEntry.actor_name, AuditEntry.actor_display).join(newest, and_(newest.c.last == AuditEntry.id)).limit(500)
    )
    users = sorted(({"id": str(i), "kind": "user", "name": n, "display": d} for i, n, d in rows), key=lambda x: (x["display"] or x["name"]).lower())
    kinds = set(await db.scalars(select(AuditEntry.actor_kind).where(AuditEntry.actor_kind != "user").distinct()))
    return users + [{"id": k, "kind": k, "name": k, "display": ""} for k in ACTOR_KINDS if k in kinds]


# ---------------------------------------------------------------- CSV (export)

CSV_COLUMNS = ("time_utc", "actor_kind", "actor", "actor_name", "actor_id", "action", "group", "target_type", "target_id", "target", "ip", "details")


def cell(v: object) -> str:
    """A CSV cell that is never a formula: a leading = + - @ (or tab / carriage return) is quoted for spreadsheets."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def csv_row(e: AuditEntry) -> list[str]:
    import json

    vals = (
        e.at.astimezone(UTC).isoformat(),
        e.actor_kind,
        e.actor_name,
        e.actor_display,
        str(e.actor_id) if e.actor_id else "",
        e.action,
        ACTIONS.get(e.action, ""),
        e.target_type,
        e.target_id,
        e.target_label,
        e.ip,
        json.dumps(e.details or {}, ensure_ascii=False, sort_keys=True) if e.details else "",
    )
    return [cell(v) for v in vals]


async def csv_chunks(f: Filters) -> AsyncIterator[bytes]:
    """The export, newest first, in chunks (UTF-8 with BOM – Excel opens it right), at most EXPORT_MAX rows. A session
    of its own, one short read transaction per chunk: the response streams after the request's session is gone."""
    from app import db as dbm

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    yield ("\ufeff" + buf.getvalue()).encode()
    cursor: str | None = None
    left = EXPORT_MAX
    async with dbm.session() as s:
        while left > 0:
            rows, cursor = await page(s, f, cursor, min(1000, left))
            buf = io.StringIO()
            w = csv.writer(buf)
            for e in rows:
                w.writerow(csv_row(e))
            await s.rollback()  # nothing stays open while the client reads
            left -= len(rows)
            if rows:
                yield buf.getvalue().encode()
            if not cursor:
                break
