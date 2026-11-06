"""Audit log ("Protokoll"): the security-relevant admin and account actions – who, what, when, from where, on what, and
the changed fields before/after. Never a secret value: for a password, client secret, token, webhook URL, TOTP seed or
any other secret field only that it changed (`scrub`, the one place that decides – tests/test_audit.py fails when a new
field that looks secret would be logged in clear).

`record()` adds the entry to the session of the change itself: it is committed with the change, and a change that is
rolled back (refused, stale, failed) leaves no entry. Append-only – there is no API to edit or delete an entry, and the
chain (below) shows one changed behind the app's back; the hourly prune removes what is older than the retention
(settings section "audit", default 365 days, 90–3650).

Where it came from (0.1.50): the request's context – client address, how it arrived, method and path, request id, the
browser and system coarse (never the full user agent) – comes from the middleware (main._guard → set_request), the
session – a keyed short reference, how it was signed in – from the session dependency (deps._session → set_session).

Integrity (0.1.50): every entry is sealed into a chain – its position (`seq`), the previous entry's hash and an HMAC
over the canonical entry, keyed by the master key (`seal`: every round of the background loop, when the log is opened,
by the hourly prune). The chain's state (settings section "audit_chain") carries an HMAC of its own; a state that fails
it, or another key, is shown as such and never re-keyed automatically – only by an operator (`rekey`: CLI
verify-audit --accept-new-key, a restore with --ignore-key; logged as audit.chain_rekeyed). `verify` checks the chain
from where it last stopped (incremental) and that its anchor is the one the newest audit.pruned / audit.chain_rekeyed
entry declares; the hourly prune also re-checks the whole chain bit by bit (`sweep`) and logs the head as an INFO line
(a witness outside the database). What it proves: unchanged since sealing, against someone without the master key –
not that an entry was written by the app, nor the newest unsealed entries, nor anything a key holder does.

Not logged: failed sign-ins one by one (anyone can send them – an unauthenticated flood would fill the log, and a
password typed into the name field would land in it) – nor refused passkey sign-ins, for the same reason; the lock of
an existing account and the block of an address are logged instead (login.locked, login.ip_blocked). A lock of a name
that is no account never names the name (it may be a password typed into the name field): per address and hour the
first one as login.locked_unknown (at most UNKNOWN_FIRST_MAX an hour); the rest – and address blocks beyond that many –
is counted into one summary entry an hour (`flush_floods`). A session ended because its second factor or proof of
identity was refused too often is logged (sessions.revoked, why "failures"). Sign-ins are logged for admins only
(login.success, with the method: password, password_totp, ldap, ldap_totp, passkey, entra, entra_totp) – a reader's
last sign-in is on the account; reading the log itself neither. A passkey whose signature counter went back is logged
every time (passkey.sign_count_warning, actor the system): it takes the passkey's own signature, nobody else can cause it.

Anomalies – marked, never acted on, computed when the entry is written from what is at hand: the emergency account
signed in outside 07–19 on a weekday (local time: TZ, else Europe/Berlin), an admin's sign-in from an address none of
its sign-ins of the last 90 days came from, several failed attempts right before a sign-in, a role raised to admin,
the retention lowered, an export of the log. The reasons are in details.anomalies; `notable` marks them and the
security-relevant actions (NOTABLE_ACTIONS) for the filter "Nur Auffälliges"."""

import base64
import contextvars
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import time
import uuid
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import Select, delete, exists, func, literal_column, select, text, tuple_
from sqlalchemy import Text as SAText
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditEntry

SECTION = "audit"  # settings: {"keep_days": 365, "rev": n}
CHAIN_SECTION = "audit_chain"  # settings: the chain's state (anchor, head, how far it is checked, problems found)
KEEP_DEFAULT, KEEP_MIN, KEEP_MAX = 365, 90, 3650
PAGE_MAX = 200
EXPORT_MAX = 100_000  # rows in one CSV export (the newest – narrow the filters for older ones)
COUNT_CAP = 10_000  # the hit count of a filter is counted up to here ("10 000+")
TEXT_MAX = 300  # a logged value is cut after this many characters
LIST_MAX = 50  # … a list after this many items
ACTORS_MAX = 2000  # accounts in the actor filter (sorted by name first)

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
        "login.locked_unknown",
        "login.ip_blocked",
        "login.emergency_slowed",
        "setup.completed",
        "setup.token_issued",
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
        "team.sync_started",
        "team.synced",
    ),
    "settings": ("settings.changed",),
    "backup": (
        "backup.created",
        "backup.restored",
        "backup.deleted",
        "backup.imported",
        "restore_test.run",
        "restore_test.done",
        "export.downloaded",
        "backup.downloaded",
        "audit.exported",
        "audit.chain_problem",
        "audit.chain_rekeyed",
        "audit.pruned",
    ),
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
# security-relevant whatever the details say – "Nur Auffälliges" shows them with the anomalies (migration 0032 marked
# the entries of before with the list of that version)
NOTABLE_ACTIONS = frozenset(
    {
        "login.locked",
        "login.locked_unknown",
        "login.ip_blocked",
        "login.emergency_slowed",
        "role.changed",
        "token.created",
        "token.revoked",
        "sessions.revoked",
        "backup.restored",
        "backup.downloaded",
        "audit.exported",
        "audit.chain_problem",
        "audit.chain_rekeyed",
        "passkey.sign_count_warning",
        "setup.completed",
        "setup.token_issued",
    }
)
ANOMALIES = ("emergency_off_hours", "new_address", "failures_before", "role_admin", "retention_lowered", "audit_export", "late_entry", "future_entry")
FAILURES_NOTABLE = 3  # failed attempts right before a sign-in from which it is marked
NEW_ADDRESS_DAYS = 90
LOCK_ACTIONS = ("login.locked", "login.locked_unknown", "login.ip_blocked")


@dataclass(frozen=True)
class Actor:
    kind: str  # user | system | sync | cli
    id: uuid.UUID | None = None
    name: str = ""
    display: str = ""
    role: str | None = None  # the account's role at the time
    emergency: bool | None = None


SYSTEM = Actor("system", name="system")
SYNC = Actor("sync", name="directory-sync")  # the hourly sync, a team load, a directory sign-in deciding the role
CLI = Actor("cli", name="cli")  # python -m app.cli (reset-emergency, backup, restore …)


def actor_of(user) -> Actor:  # noqa: ANN001 - a User or an Actor
    if isinstance(user, Actor):
        return user
    return Actor("user", user.id, user.username or "", user.display_name or "", getattr(user, "role", None), bool(getattr(user, "is_emergency", False)))


@dataclass(frozen=True)
class Target:
    type: str
    id: str | None = None
    label: str | None = None


def target(kind: str, id_=None, label: str | None = None) -> Target:  # noqa: ANN001
    return Target(kind, None if id_ is None else str(id_), label)


def user_target(u) -> Target:  # noqa: ANN001 - a User
    return Target("user", str(u.id), u.username)


# ---------------------------------------------------------------- the request and the session (context)


@dataclass(frozen=True)
class RequestContext:
    """What the middleware knows of the request being served (main._guard): its client address, how it arrived, method,
    path (never the query string), request id and the browser coarse."""

    ip: str | None = None
    via: str | None = None  # direct | bundled | proxy | bundled_proxy (deps.client_route)
    method: str | None = None
    path: str | None = None
    request_id: str | None = None
    ua_family: str | None = None
    ua_version: str | None = None
    ua_os: str | None = None


# set by the middleware, so record() needs no Request in every endpoint's signature. Tasks started from a request inherit
# it: an account's and the directory's entries take it; the system's only when it was given the same address (a lock).
_req: contextvars.ContextVar[RequestContext | None] = contextvars.ContextVar("audit_request", default=None)
# the session of the request (deps._session): its account, keyed reference and how it was signed in
_sess: contextvars.ContextVar[tuple[uuid.UUID, str, str | None] | None] = contextvars.ContextVar("audit_session", default=None)


def set_request(ctx: RequestContext | None) -> contextvars.Token:
    return _req.set(ctx)


def reset_request(token: contextvars.Token) -> None:
    _req.reset(token)


def set_ip(ip: str | None) -> contextvars.Token:
    """Only the address (tests)."""
    return _req.set(RequestContext(ip=ip))


def reset_ip(token: contextvars.Token) -> None:
    _req.reset(token)


def set_session(sess) -> None:  # noqa: ANN001 - a UserSession (or None)
    _sess.set((sess.user_id, session_ref(sess.id), sess.method) if sess is not None else None)


_KEYS: dict[tuple[bytes, bytes], bytes] = {}


def _key(info: bytes) -> bytes:
    """One key per purpose from the master key – derived once (HKDF for every entry hash would cost more than the
    hash), and again when the master key is another one (crypto.reset_cache in tests)."""
    from app import crypto

    m = crypto.master()
    k = _KEYS.get((m, info))
    if k is None:
        k = _KEYS[(m, info)] = crypto._derive(info)  # noqa: SLF001
    return k


def session_ref(session_id: uuid.UUID) -> str:
    """A session's reference in the log: a keyed hash of its id, 12 characters – the entries of one session belong
    together; neither its token nor its id can be read from it."""
    return hmac.new(_key(b"cobe-news/audit-session/v1"), session_id.bytes, hashlib.sha256).hexdigest()[:12]


_UA_FAMILY = (
    ("Edge", re.compile(r"\bEdg(?:e|A|iOS)?/(\d+)")),
    ("Opera", re.compile(r"\bOPR/(\d+)")),
    ("Vivaldi", re.compile(r"\bVivaldi/(\d+)")),
    ("Samsung Internet", re.compile(r"\bSamsungBrowser/(\d+)")),
    ("Firefox", re.compile(r"\b(?:Firefox|FxiOS)/(\d+)")),
    ("Chrome", re.compile(r"\b(?:Chrome|CriOS)/(\d+)")),
    ("Safari", re.compile(r"\bVersion/(\d+)(?:\.\d+)*(?: Mobile/\S+)? Safari/")),
    ("curl", re.compile(r"^curl/(\d+)")),
    ("PowerShell", re.compile(r"\bPowerShell/(\d+)")),
    ("Python", re.compile(r"^(?:python-requests|python-httpx|Python-urllib)/(\d+)")),
    ("Go", re.compile(r"^Go-http-client/(\d+)")),
)
_UA_OS = (
    ("iOS", re.compile(r"iPhone|iPod")),
    ("iPadOS", re.compile(r"iPad")),
    ("Android", re.compile(r"Android")),
    ("Windows", re.compile(r"Windows")),
    ("ChromeOS", re.compile(r"CrOS")),
    ("macOS", re.compile(r"Macintosh|Mac OS X")),
    ("Linux", re.compile(r"Linux|X11")),
)


def parse_ua(ua: str | None) -> tuple[str | None, str | None, str | None]:
    """The browser (family, major version) and the system of a user agent – coarse, all that is ever stored of it."""
    if not ua:
        return None, None, None
    ua = ua[:512]
    family = version = None
    for name, pattern in _UA_FAMILY:
        if m := pattern.search(ua):
            family, version = name, m.group(1)[:6]
            break
    system = next((name for name, pattern in _UA_OS if pattern.search(ua)), None)
    return family or "other", version, system


# internal networks: RFC 1918, carrier-grade NAT (RFC 6598), link-local, ULA – not the documentation ranges Python's
# is_private also counts
_INTERNAL = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10")
)


def ip_class(ip: str | None) -> str | None:
    """What kind of address: loopback, gateway (the Docker gateway – every request comes from there when Docker's port
    publishing hides the real addresses), shared (SHARED_ADDRESSES, a trusted proxy itself), internal (RFC 1918, ULA,
    link-local), external."""
    if not ip:
        return None
    from app import netaddr

    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.is_loopback:
        return "loopback"
    if ip == netaddr.container_gateway():
        return "gateway"
    if netaddr.shared_address(ip):
        return "shared"
    if any(a in n for n in _INTERNAL if n.version == a.version):
        return "internal"
    return "external"


def _local_zone() -> ZoneInfo:
    from app.quiet import DEFAULT_TZ

    for name in (os.environ.get("TZ"), DEFAULT_TZ):
        if name:
            try:
                return ZoneInfo(name.lstrip(":"))
            except (ZoneInfoNotFoundError, ValueError):
                continue
    return ZoneInfo("UTC")


# ---------------------------------------------------------------- never a secret (the one place that decides)

# a field whose name matches: never logged in clear – only {"secret": true, "changed": true}
SECRET_NAME = re.compile(
    r"pass(word|phrase)?|secret|token|hmac|_enc$|^enc_|header_value|private|credential|api_?key|nvd_key|totp|seed|cookie|signature|bearer|vapid|hash|salt|otp|webhook|teams_url|^auth$|p256dh|^topic$"
    r"|authori[sz]ation|^sig$|^dsn$|connection_?string",
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
CHANGED_MARK = {"changed": True}  # changed, but both values look the same once cleaned (a URL with another path)
_SECRET_KEYS = frozenset(SECRET_MARK)


def is_secret(name: str) -> bool:
    n = str(name).lower()
    return n not in NOT_SECRET and bool(SECRET_NAME.search(n))


def _url_origin(v: str) -> str | None:
    """A URL as scheme://host[:port] only: a webhook keeps its token in the path, a feed may keep one in the query, an
    address may carry user:password – none of them is logged. Any scheme (socks5://, postgresql://, ftp:// …); one
    without a host as its scheme only."""
    try:
        p = urlsplit(v)
    except ValueError:
        return None
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9+.\-]{0,15}", p.scheme or ""):
        return None
    scheme = p.scheme.lower()
    if not p.hostname:
        return f"{scheme}://…"
    host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname
    try:
        port = f":{p.port}" if p.port else ""
    except ValueError:
        port = ""
    rest = "/…" if (p.path not in ("", "/") or p.query or p.fragment) else ""
    return f"{scheme}://{host}{port}{rest}"


# an encrypted value, an API or calendar token, a well-known token form, a long hex key
_TOKEN_PREFIX = re.compile(r"^(v1:|cnt_|cnc_|xox[abposr]-|gh[pousr]_|github_pat_|glpat-|sk-[A-Za-z0-9]|AKIA[0-9A-Z]{12})")
_HEX_KEY = re.compile(r"^[0-9a-fA-F]{40,}$")  # a SHA-1/SHA-256 sized key (a 32-digit hex id is a reference)
_B64ISH = re.compile(r"^[A-Za-z0-9_\-+/]{32,}={0,2}$")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")
_URL_IN_TEXT = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^\s<>\"'`]+")
# control characters, zero-width and direction marks (a right-to-left override turns "gnp.exe" around on the screen)
INVISIBLE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f​‎‏‪-‮⁠⁦-⁩﻿]")


def _token_like(v: str) -> bool:
    """A secret by its form: a known token prefix, a hex key, a JWT, or a long run of base64 characters with upper and
    lower case and digits – a long slug ("laptop-5g-for-business-7th-edition-intel") is none."""
    if _TOKEN_PREFIX.search(v) or _HEX_KEY.match(v) or _JWT.fullmatch(v):
        return True
    return bool(_B64ISH.match(v)) and any(c.isupper() for c in v) and any(c.islower() for c in v) and any(c.isdigit() for c in v)


def clean_text(v: str) -> str:
    """A text as it may be logged: without invisible and direction characters, a URL in it only as its origin, a JWT in
    it as •••."""
    v = INVISIBLE.sub("", v)
    if "://" in v:
        v = _URL_IN_TEXT.sub(lambda m: _url_origin(m.group(0)) or "…", v)
    if "eyJ" in v:
        v = _JWT.sub("•••", v)
    return v


def _value(v):  # noqa: ANN001, ANN202
    if isinstance(v, str):
        stripped = INVISIBLE.sub("", v).strip()
        if _token_like(stripped):
            return dict(SECRET_MARK)
        if "://" in stripped and " " not in stripped and (o := _url_origin(stripped)):
            return o
        v = clean_text(v)
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
    token-like string as SECRET_MARK, a URL as its origin (also inside a text), invisible characters removed, long
    texts and lists cut, at most 6 levels deep."""
    if depth > 6:
        return None
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            k = INVISIBLE.sub("", str(k))[:TEXT_MAX]
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
    "_enc"), never its values; one whose values look the same once cleaned (a URL with another path on the same host)
    as {"field": CHANGED_MARK}. `fields`: only these (default: all of both, without the counters of SKIP)."""
    b, a = before or {}, after or {}
    keys = list(fields) if fields is not None else sorted(set(b) | set(a))
    out: dict = {}
    for k in keys:
        if (fields is None and k in SKIP) or b.get(k) == a.get(k):
            continue
        name = k.removesuffix("_enc")
        if is_secret(k) or is_secret(name):
            out[name] = dict(SECRET_MARK)
            continue
        old, new = scrub(b.get(k), 1), scrub(a.get(k), 1)
        out[k] = dict(CHANGED_MARK) if old == new else {"from": old, "to": new}
    return out


# ---------------------------------------------------------------- writing


def _label(v: str | None) -> str | None:
    """A target's name as it was – scrubbed like a value (a name that looks like a token or a URL with a path is not
    logged as it is)."""
    got = _value(v) if v else None
    return got if isinstance(got, str) and got else ("•••" if v else None)


def _auto_anomalies(action: str, target: Target | None, details: dict) -> list[str]:
    """The anomalies an entry shows by itself (the sign-in ones need the database: signin_anomalies)."""
    out = []
    changes = details.get("changes") if isinstance(details.get("changes"), dict) else {}
    role = changes.get("role") if isinstance(changes.get("role"), dict) else {}
    if (action == "role.changed" and role.get("to") == "admin") or (action == "user.created" and details.get("role") == "admin"):
        out.append("role_admin")
    if action == "settings.changed" and target is not None and target.type == "settings" and target.id == SECTION:
        keep = changes.get("keep_days") if isinstance(changes.get("keep_days"), dict) else {}
        if isinstance(keep.get("from"), int) and isinstance(keep.get("to"), int) and keep["to"] < keep["from"]:
            out.append("retention_lowered")
    if action == "audit.exported":
        out.append("audit_export")
    return out


def record(
    db: AsyncSession,
    actor,  # noqa: ANN001 - a User or an Actor
    action: str,
    target: Target | None = None,
    details: dict | None = None,
    request=None,  # noqa: ANN001 - a fastapi Request: its client address instead of the middleware's
    ip: str | None = None,  # the address itself (a lock or block the system sets: the address it came from)
    session=None,  # noqa: ANN001 - the UserSession the action belongs to (a sign-in: the new one), else the request's
    anomalies: Iterable[str] = (),
) -> AuditEntry:
    """An entry, added to `db` – committed with the change it records, gone with it when that is rolled back."""
    if action not in ACTIONS:
        raise ValueError(f"unknown audit action {action!r}")
    from app import __version__

    who = actor_of(actor)
    ctx = _req.get()
    if ip is None and request is not None:
        from app.deps import client_ip

        ip = client_ip(request)
    # the request's context: an account's and the directory's entries; the system's only for its own address (a lock)
    use = ctx is not None and who.kind != "cli" and (who.kind in ("user", "sync") or (ip is not None and ip == ctx.ip))
    if ip is None and use:
        ip = ctx.ip  # type: ignore[union-attr]
    sess_ref = method = None
    if session is not None:
        sess_ref, method = session_ref(session.id), session.method
    elif who.kind == "user" and (s := _sess.get()) is not None and s[0] == who.id:
        sess_ref, method = s[1], s[2]
    clean = scrub(details or {})
    flags = sorted({*anomalies, *_auto_anomalies(action, target, clean)})
    if flags:
        clean["anomalies"] = flags
    c = ctx if use else RequestContext()
    entry = AuditEntry(
        at=datetime.now(UTC),
        actor_kind=who.kind,
        actor_id=who.id,
        actor_name=clean_text(who.name or who.kind)[:255],
        actor_display=clean_text(who.display or "")[:255],
        actor_role=who.role,
        actor_emergency=who.emergency,
        auth_method=method,
        session_ref=sess_ref,
        action=action,
        target_type=target.type if target else None,
        target_id=(clean_text(target.id)[:TEXT_MAX] or None) if target and target.id else None,
        target_label=_label(target.label) if target else None,
        ip=ip,
        ua_family=c.ua_family,  # type: ignore[union-attr]
        ua_version=c.ua_version,  # type: ignore[union-attr]
        ua_os=c.ua_os,  # type: ignore[union-attr]
        req_method=c.method,  # type: ignore[union-attr]
        req_path=c.path,  # type: ignore[union-attr]
        request_id=c.request_id,  # type: ignore[union-attr]
        req_via=c.via,  # type: ignore[union-attr]
        app_version=__version__,
        notable=bool(flags) or action in NOTABLE_ACTIONS,
        details=clean,
    )
    db.add(entry)
    return entry


async def signin_anomalies(db: AsyncSession, user, ip: str | None, failures: int = 0, now: datetime | None = None) -> tuple[list[str], dict]:  # noqa: ANN001
    """The anomalies of an admin's sign-in, and the details they bring: the emergency account outside 07–19 on a
    weekday, an address none of the account's sign-ins of the last NEW_ADDRESS_DAYS came from (only when there were
    such sign-ins), FAILURES_NOTABLE or more failed attempts right before it."""
    now = now or datetime.now(UTC)
    out: list[str] = []
    extra: dict = {}
    if getattr(user, "is_emergency", False):
        local = now.astimezone(_local_zone())
        if local.weekday() >= 5 or not 7 <= local.hour < 19:
            out.append("emergency_off_hours")
    if failures >= FAILURES_NOTABLE:
        out.append("failures_before")
        extra["failures_before"] = failures
    if ip:
        seen = set(
            await db.scalars(
                select(AuditEntry.ip)
                .where(AuditEntry.actor_id == user.id, AuditEntry.action == "login.success", AuditEntry.at >= now - timedelta(days=NEW_ADDRESS_DAYS))
                .distinct()
                .limit(500)
            )
        )
        seen.discard(None)
        if seen and ip not in seen:
            out.append("new_address")
    return out, extra


# ---------------------------------------------------------------- floods of locks and blocks (bounded)

UNKNOWN_FIRST_MAX = 20  # an hour: first entries for unknown names, and single address blocks – the rest is counted
FLOOD_WINDOW = 3600.0


class _Floods:
    def __init__(self) -> None:
        self.start = time.monotonic()
        self.first: set[str] = set()  # sources with a first login.locked_unknown entry this window
        self.names: dict[str, int] = {}  # source → locks of unknown names
        self.blocks_written = 0
        self.blocks: dict[str, int] = {}  # source → address blocks not written one by one

    def pending(self) -> bool:
        return any(n > (1 if s in self.first else 0) for s, n in self.names.items()) or bool(self.blocks)


_floods = _Floods()


def note_unknown_lock(source: str) -> bool:
    """A lock of a name that is no account, from `source` (bruteforce.source_key): True when its first entry is written
    now (the first one of the address this hour, at most UNKNOWN_FIRST_MAX an hour) – else it is only counted."""
    _floods.names[source] = _floods.names.get(source, 0) + 1
    if source in _floods.first or len(_floods.first) >= UNKNOWN_FIRST_MAX:
        return False
    _floods.first.add(source)
    return True


def note_block(source: str) -> bool:
    """An address blocked: True when it is logged on its own (UNKNOWN_FIRST_MAX an hour), else it is counted."""
    if _floods.blocks_written < UNKNOWN_FIRST_MAX:
        _floods.blocks_written += 1
        return True
    _floods.blocks[source] = _floods.blocks.get(source, 0) + 1
    return False


async def flush_floods(db: AsyncSession, *, force: bool = False) -> bool:
    """The hour's summary (login.locked_unknown without a target): the locks of unknown names and the address blocks
    beyond the single entries – once the window is over (the hourly prune, the next lock), or `force`. Not committed."""
    global _floods  # noqa: PLW0603
    if not force and time.monotonic() - _floods.start < FLOOD_WINDOW:
        return False
    f, _floods = _floods, _Floods()
    if not f.pending():
        return False
    top = dict(sorted(f.names.items(), key=lambda x: (-x[1], x[0]))[:LIST_MAX])
    record(
        db,
        SYSTEM,
        "login.locked_unknown",
        None,
        {
            "summary": True,
            "names": sum(f.names.values()),
            "sources": top,
            "blocks": sum(f.blocks.values()),
            "blocked_sources": [k for k, _ in sorted(f.blocks.items(), key=lambda x: (-x[1], x[0]))][:LIST_MAX],
            "window_min": int(FLOOD_WINDOW // 60),
        },
    )
    return True


def reset_floods() -> None:
    """Forget the counts (tests)."""
    global _floods  # noqa: PLW0603
    _floods = _Floods()


# ---------------------------------------------------------------- the chain (integrity)

CHAIN_LOCK = 0x636E_6175  # pg_advisory_xact_lock: one sealer, checker or pruner at a time
SEAL_BATCH = 5000
VERIFY_BATCH = 2000
VERIFY_BUDGET = 50_000  # entries checked by one request of the page (the new ones since the last check)
SWEEP_BUDGET = 200_000  # entries re-checked by each hourly prune (the whole chain, bit by bit)
PROBLEMS_MAX = 20
LATE = timedelta(minutes=15)  # an entry this much older than the one sealed before it: marked "late_entry"
FUTURE = timedelta(days=1)  # an entry this far in the future: marked "future_entry" (and no longer holds the prune)
ANCHOR_ACTIONS = ("audit.pruned", "audit.chain_rekeyed")  # entries that declare where the chain starts
CHAIN_FIELDS = (
    "id",
    "at",
    "actor_kind",
    "actor_id",
    "actor_name",
    "actor_display",
    "actor_role",
    "actor_emergency",
    "auth_method",
    "session_ref",
    "action",
    "target_type",
    "target_id",
    "target_label",
    "ip",
    "ua_family",
    "ua_version",
    "ua_os",
    "req_method",
    "req_path",
    "request_id",
    "req_via",
    "app_version",
    "notable",
    "details",
    "seq",
    "prev_hash",
)


def _canon(v):  # noqa: ANN001, ANN202
    if isinstance(v, datetime):
        return v.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(v, uuid.UUID):
        return str(v)
    return v


def canonical(e: AuditEntry) -> bytes:
    """The entry as the chain hashes it: its fields (CHAIN_FIELDS) as JSON, keys sorted, no spaces."""
    return json.dumps({f: _canon(getattr(e, f)) for f in CHAIN_FIELDS}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _chain_key() -> bytes:
    return _key(b"cobe-news/audit-chain/v1")


def chain_key_id() -> str:
    """Which key seals the chain – a one-way fingerprint."""
    return hmac.new(_chain_key(), b"key-id", hashlib.sha256).hexdigest()[:16]


def entry_hash(e: AuditEntry) -> str:
    return hmac.new(_chain_key(), canonical(e), hashlib.sha256).hexdigest()


def state_mac(st: dict) -> str:
    """The chain state's own HMAC (over everything but the MAC): a state changed behind the app's back – the head
    moved back after the newest entries were deleted, the anchor moved forward, the key or the problems changed – no
    longer matches it."""
    body = json.dumps({k: v for k, v in st.items() if k != "mac"}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hmac.new(_chain_key(), b"state|" + body, hashlib.sha256).hexdigest()


async def _lock(db: AsyncSession, *, wait: bool) -> bool:
    if wait:
        await db.execute(select(func.pg_advisory_xact_lock(CHAIN_LOCK)))
        return True
    return bool(await db.scalar(select(func.pg_try_advisory_xact_lock(CHAIN_LOCK))))


async def chain_state(db: AsyncSession) -> dict:
    """The stored state as it is (with its MAC) – `_state_problem` says whether it can be trusted."""
    from app import settings as settings_store

    return dict(await settings_store.get(db, CHAIN_SECTION))


async def _put_state(db: AsyncSession, st: dict) -> None:
    """The state written with its MAC (keyed: only the app with the master key can write a valid one)."""
    from app import settings as settings_store

    st = {k: v for k, v in st.items() if k != "mac"}
    st["mac"] = state_mac(st)
    await settings_store.put(db, CHAIN_SECTION, st)


async def _last_sealed(db: AsyncSession) -> tuple[int, str, datetime] | None:
    row = (await db.execute(select(AuditEntry.seq, AuditEntry.hash, AuditEntry.at).where(AuditEntry.seq.is_not(None)).order_by(AuditEntry.seq.desc()).limit(1))).first()
    return (int(row[0]), row[1] or "", row[2]) if row else None


async def _state_problem(db: AsyncSession, st: dict) -> str | None:
    """Why the state cannot be used – None when it can: "other_key" (sealed with another master key, or its key field
    changed), "state" (its MAC does not match, or it is gone while sealed entries exist). Never repaired by itself: an
    operator decides (python -m app.cli verify-audit --accept-new-key, a restore with --ignore-key)."""
    if not st:
        return "state" if await db.scalar(select(exists().where(AuditEntry.seq.is_not(None)))) else None
    if st.get("key") not in (None, chain_key_id()):
        return "other_key"
    mac = st.get("mac")
    if not isinstance(mac, str) or not hmac.compare_digest(mac, state_mac(st)):
        return "state"
    return None


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _session():  # noqa: ANN202
    """The chain works in sessions of its own – never in a caller's (a rollback there would expire its objects, a commit
    would write its pending changes)."""
    from app import db as dbm

    return dbm.session()


def _link(h: str) -> str:
    """An anchor's hash as an entry's details carry it ("h:" – a bare hex string would be scrubbed as a key)."""
    return f"h:{h}"


def _flag(e: AuditEntry, why: str) -> None:
    d = dict(e.details or {})
    d["anomalies"] = sorted({*(d.get("anomalies") or []), why})
    e.details, e.notable = d, True


async def seal(_db: AsyncSession | None = None, *, wait: bool = False, batches: int = 1) -> int:
    """Seal the entries written since the last time into the chain (in the order of their ids – an entry committed late
    simply comes later in the chain, marked "late_entry" when its time lies more than LATE before the entry sealed
    before it). `wait`: wait for another sealer instead of leaving the work to it. Nothing is sealed while the state
    cannot be trusted (another key, a changed state) – never re-keyed here. Its own session (the argument is ignored)."""
    done = 0
    async with _session() as s:
        for _ in range(batches):
            if not await _lock(s, wait=wait):
                await s.rollback()
                return done
            rows = list(await s.scalars(select(AuditEntry).where(AuditEntry.seq.is_(None)).order_by(AuditEntry.id).limit(SEAL_BATCH)))
            if not rows:
                await s.commit()
                return done
            st = await chain_state(s)
            if await _state_problem(s, st):
                await s.rollback()
                return done
            st["key"] = chain_key_id()
            last = await _last_sealed(s)
            if st.get("head_seq") is not None and (last is None or last[0] <= int(st["head_seq"])):
                seq, h = int(st["head_seq"]), str(st.get("head_hash") or "")
            else:
                seq, h = (last[0], last[1]) if last else (int(st.get("anchor_seq") or 0), str(st.get("anchor_hash") or ""))
            prev_at = datetime.fromisoformat(st["head_at"]) if st.get("head_at") else (last[2] if last else None)
            future = datetime.now(UTC) + FUTURE
            for e in rows:
                if e.at > future:
                    _flag(e, "future_entry")
                elif prev_at is not None and e.at < prev_at - LATE:
                    _flag(e, "late_entry")
                seq += 1
                e.seq, e.prev_hash = seq, h
                e.hash = h = entry_hash(e)
                if e.at <= future:
                    prev_at = e.at if prev_at is None else max(prev_at, e.at)
            st["head_seq"], st["head_hash"] = seq, h
            if prev_at is not None:
                st["head_at"] = prev_at.isoformat()
            await s.flush()
            await _put_state(s, st)
            await s.commit()
            done += len(rows)
            if len(rows) < SEAL_BATCH:
                return done
    return done


async def seal_all(_db: AsyncSession | None = None) -> int:
    """Everything that is not sealed yet (the prune, the command line's check)."""
    total = 0
    while n := await seal(wait=True, batches=20):
        total += n
    return total


@dataclass
class _Walk:
    seq: int
    hash: str
    checked: int
    problems: list[dict]
    end: bool


async def _walk(db: AsyncSession, seq: int, prev: str, budget: int) -> _Walk:
    """Check the chain after position `seq` (whose hash is `prev`): positions without a gap, each entry's link to the
    one before and its own HMAC. A problem is noted and the walk goes on from the entry as stored."""
    problems: list[dict] = []
    checked = 0
    while checked < budget:
        rows = list(await db.scalars(select(AuditEntry).where(AuditEntry.seq > seq).order_by(AuditEntry.seq).limit(min(VERIFY_BATCH, budget - checked))))
        if not rows:
            return _Walk(seq, prev, checked, problems, True)
        for e in rows:
            if e.seq != seq + 1:
                problems.append({"id": e.id, "seq": e.seq, "kind": "missing", "count": int(e.seq) - seq - 1})
            elif e.prev_hash != prev:
                problems.append({"id": e.id, "seq": e.seq, "kind": "link"})
            if not e.hash or not hmac.compare_digest(e.hash, entry_hash(e)):
                problems.append({"id": e.id, "seq": e.seq, "kind": "changed"})
            seq, prev = int(e.seq), e.hash or ""
            checked += 1
            db.expunge(e)  # a long walk keeps no entries in memory
    return _Walk(seq, prev, checked, problems, False)


async def _tail_problem(db: AsyncSession, st: dict) -> dict | None:
    """The newest sealed entries deleted: the last one that is there lies before the head the state knows – checked at
    every check (not only once a walk reaches the end). The problem names the last entry that is still there."""
    head = st.get("head_seq")
    if head is None:
        return None
    row = (await db.execute(select(AuditEntry.seq, AuditEntry.id).where(AuditEntry.seq.is_not(None)).order_by(AuditEntry.seq.desc()).limit(1))).first()
    last = int(row[0]) if row else int(st.get("anchor_seq") or 0)
    if last >= int(head):
        return None
    return {"id": row[1] if row else None, "seq": last + 1, "kind": "tail", "count": int(head) - last}


async def _anchor_problem(db: AsyncSession, st: dict) -> dict | None:
    """The anchor (where the kept chain starts) must be declared inside the chain: by the newest audit.pruned or
    audit.chain_rekeyed entry. An anchor beyond the declared one means entries deleted that no prune removed."""
    anchor = int(st.get("anchor_seq") or 0)
    if anchor == 0:
        return None
    row = (
        await db.execute(
            select(AuditEntry.id, AuditEntry.details).where(AuditEntry.action.in_(ANCHOR_ACTIONS), AuditEntry.seq.is_not(None)).order_by(AuditEntry.seq.desc()).limit(1)
        )
    ).first()
    declared = int((row[1] or {}).get("anchor_seq") or 0) if row else 0
    if anchor > declared or (anchor == declared and (row[1] or {}).get("anchor_link") != _link(str(st.get("anchor_hash") or ""))):  # type: ignore[index]
        return {"id": row[0] if row else None, "seq": anchor, "kind": "anchor"}
    return None  # below the declared anchor: a prune half done – the next one goes on


async def _note_problems(db: AsyncSession, st: dict, found: list[dict]) -> None:
    known = {(p["seq"], p["kind"]) for p in st.get("problems") or []}
    new = [p for p in found if (p["seq"], p["kind"]) not in known]
    if not new:
        return
    st["problems"] = [*(st.get("problems") or []), *new][-PROBLEMS_MAX:]
    for p in new[:5]:
        tgt = target("audit_entry", p["id"], f"#{p['id']}") if p.get("id") else None
        record(db, SYSTEM, "audit.chain_problem", tgt, {"kind": p["kind"], "seq": p["seq"], **({"count": p["count"]} if "count" in p else {})})


async def verify(_db: AsyncSession | None = None, budget: int = VERIFY_BUDGET, *, wait: bool = True) -> dict:
    """Seal what is new, then check the chain from where the last check stopped (at most `budget` entries), and its
    anchor. A problem is kept in the state and logged once (audit.chain_problem). `wait=False`: when another check
    runs, answer at once ("busy"). Its own sessions. Returns status()."""
    await seal(wait=wait)
    async with _session() as s:
        if not await _lock(s, wait=wait):
            await s.rollback()
            return {**await status(s), "busy": True}
        st = await chain_state(s)
        if await _state_problem(s, st) is None:
            if st.get("verified_seq") is not None:
                start, prev = int(st["verified_seq"]), str(st.get("verified_hash") or "")
            else:
                start, prev = int(st.get("anchor_seq") or 0), str(st.get("anchor_hash") or "")
            w = await _walk(s, start, prev, budget)
            found = list(w.problems)
            if (t := await _tail_problem(s, st)) is not None:
                found.append(t)
            if (a := await _anchor_problem(s, st)) is not None:
                found.append(a)
            st.update(verified_seq=w.seq, verified_hash=w.hash, verified_at=_now_iso())
            if w.end and start == int(st.get("anchor_seq") or 0):
                st["full_at"] = _now_iso()  # the whole chain checked (the command line's full check)
            await _note_problems(s, st, found)
            await _put_state(s, st)
        await s.commit()
        return await status(s)


async def sweep(_db: AsyncSession | None = None, budget: int = SWEEP_BUDGET) -> dict:
    """Re-check the whole chain bit by bit (hourly, `budget` entries each time): an entry changed after its first check
    is found within a few hours. Its own session."""
    async with _session() as s:
        await _lock(s, wait=True)
        st = await chain_state(s)
        if await _state_problem(s, st) is None:
            anchor = (int(st.get("anchor_seq") or 0), str(st.get("anchor_hash") or ""))
            start = (int(st["sweep_seq"]), str(st.get("sweep_hash") or "")) if st.get("sweep_seq") is not None else anchor
            if start[0] < anchor[0]:
                start = anchor
            w = await _walk(s, start[0], start[1], budget)
            found = list(w.problems)
            if (t := await _tail_problem(s, st)) is not None:
                found.append(t)
            if w.end:
                st.update(sweep_seq=anchor[0], sweep_hash=anchor[1], full_at=_now_iso())
            else:
                st.update(sweep_seq=w.seq, sweep_hash=w.hash)
            await _note_problems(s, st, found)
            await _put_state(s, st)
        await s.commit()
        return st


async def rekey(reason: str, actor=None) -> dict:  # noqa: ANN001 - an Actor (default: the command line)
    """An operator's step, never automatic: the chain starts anew from its newest sealed entry, sealed with the current
    master key (after a restore with --ignore-key or a new SECRET_KEY: python -m app.cli verify-audit --accept-new-key;
    also to acknowledge problems that were looked into). What lies before can no longer be checked – an
    audit.chain_rekeyed entry (notable) says so, with what the state was, and the page shows the time for good.
    Everything found before – also a finding a check just wrote and that is sealed only now – counts as acknowledged."""
    await seal_all()  # pending entries first (a check's audit.chain_problem) – when the state still allows sealing
    async with _session() as s:
        await _lock(s, wait=True)
        old = await chain_state(s)
        why = await _state_problem(s, old)
        last = await _last_sealed(s)
        seq, h = (last[0], last[1]) if last else (0, "")
        st = {
            "key": chain_key_id(),
            "anchor_seq": seq,
            "anchor_hash": h,
            "head_seq": seq if last else None,
            "head_hash": h if last else None,
            "head_at": last[2].isoformat() if last else None,
            "verified_seq": seq,
            "verified_hash": h,
            "sweep_seq": seq,
            "sweep_hash": h,
            "accepted_seq": seq,
            "rekeyed_at": _now_iso(),
            "rekeys": int(old.get("rekeys") or 0) + 1 if why != "state" else 1,
            "problems": [],
        }
        st = {k: v for k, v in st.items() if v is not None}
        record(
            s,
            actor or CLI,
            "audit.chain_rekeyed",
            target("audit_chain", None, None),
            {"reason": reason, "anchor_seq": seq, "anchor_link": _link(h), "was": why or "ok", "problems": len(old.get("problems") or [])},
        )
        await _put_state(s, st)
        await s.commit()
    await seal_all()
    async with _session() as s:  # acknowledged up to the re-anchoring entry itself (and what was sealed with it)
        await _lock(s, wait=True)
        st = await chain_state(s)
        if await _state_problem(s, st) is None and st.get("head_seq") is not None:
            st["accepted_seq"] = int(st["head_seq"])
            await _put_state(s, st)
        await s.commit()
    return await verify(budget=10**12)


async def status(db: AsyncSession) -> dict:
    """The chain for the page: ok / problem / other_key / empty, how far it is sealed and checked, the problems – a
    problem stays until an operator acknowledges it (the audit.chain_problem entries after the last acceptance count)."""
    st = await chain_state(db)
    unsealed = int(await db.scalar(select(func.count()).select_from(select(AuditEntry.id).where(AuditEntry.seq.is_(None)).limit(COUNT_CAP).subquery())) or 0)
    why = await _state_problem(db, st)
    logged = int(
        await db.scalar(
            select(func.count()).where(AuditEntry.action == "audit.chain_problem", AuditEntry.seq.is_not(None), AuditEntry.seq > int(st.get("accepted_seq") or 0))
        )
        or 0
    )
    problems = list(st.get("problems") or []) if why is None else [{"id": None, "seq": int(st.get("head_seq") or 0), "kind": why}]
    if why == "other_key":
        state = "other_key"
    elif problems or logged:
        state = "problem"
    elif st.get("head_seq") is None:
        state = "empty"
    else:
        state = "ok"
    return {
        "state": state,
        "sealed_seq": st.get("head_seq"),
        "verified_seq": st.get("verified_seq") if why is None else None,
        "verified_at": st.get("verified_at"),
        "full_at": st.get("full_at"),
        "anchor_seq": int(st.get("anchor_seq") or 0),
        "unsealed": unsealed,
        "problems": problems,
        "logged_problems": logged,
        "rekeyed_at": st.get("rekeyed_at"),
        "busy": False,
    }


# ---------------------------------------------------------------- retention

PRUNE_BATCH = 20_000
PRUNE_STEP = timedelta(days=1)  # pruned once the oldest entry is this much past the retention: one audit.pruned a day


async def keep_days(db: AsyncSession) -> int:
    from app import settings as settings_store

    raw = (await settings_store.get(db, SECTION)).get("keep_days")
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return KEEP_DEFAULT
    return min(max(n, KEEP_MIN), KEEP_MAX)


async def _prune_target(s: AsyncSession, cut: datetime, now: datetime) -> tuple[int, str] | None:
    """The last entry of the chain's start that may go: in chain order up to the first entry still within the
    retention (an entry far in the future does not hold it). None: nothing to prune."""
    after, last = 0, None
    while True:
        rows = (
            await s.execute(select(AuditEntry.seq, AuditEntry.at, AuditEntry.hash).where(AuditEntry.seq > after).order_by(AuditEntry.seq).limit(PRUNE_BATCH))
        ).all()
        for r in rows:
            if r.at >= cut and r.at <= now + FUTURE:
                return last
            last = (int(r.seq), r.hash or "")
        if len(rows) < PRUNE_BATCH:
            return last
        after = int(rows[-1].seq)


async def prune(_db: AsyncSession | None = None, now: datetime | None = None) -> int:
    """Entries older than the retention go (hourly, main.FetchLoop._prune) – the only way one is ever removed. In chain
    order: up to the first entry still within the retention, so the chain stays whole from the oldest kept entry,
    whose link the anchor (the hash of the last deleted entry) checks. Daily steps: only once the oldest entry is a day
    past the retention. First an audit.pruned entry declares the new anchor and is sealed (a deletion beyond a declared
    anchor is a problem), then batches of PRUNE_BATCH, each its own short transaction. Before: the hour's flood summary
    and everything sealed; after: the incremental check, a part of the full one, and the head as an INFO line – a
    witness outside the database for a log shipper. Its own sessions."""
    import logging

    now = now or datetime.now(UTC)
    async with _session() as s:
        if await flush_floods(s):
            await s.commit()
        cut = now - timedelta(days=await keep_days(s))
    await seal_all()
    gone = 0
    async with _session() as s:
        oldest = await s.scalar(select(func.min(AuditEntry.at)).where(AuditEntry.seq.is_not(None)))
        tgt = await _prune_target(s, cut, now) if oldest is not None and oldest < cut - PRUNE_STEP else None
        st = await chain_state(s)
        if tgt is not None and await _state_problem(s, st) is None and tgt[0] > int(st.get("anchor_seq") or 0):
            record(s, SYSTEM, "audit.pruned", target("audit_chain", None, None), {"anchor_seq": tgt[0], "anchor_link": _link(tgt[1]), "before": cut.isoformat(), "keep_days": (now - cut).days})
            await s.commit()
        else:
            tgt = None
    if tgt is not None:
        await seal_all()  # the declaration is in the chain before anything goes
        while True:
            async with _session() as s:
                await _lock(s, wait=True)
                st = await chain_state(s)
                # the batch's last entry and its hash, read before it goes
                r = (await s.execute(select(AuditEntry.seq, AuditEntry.hash).where(AuditEntry.seq <= tgt[0]).order_by(AuditEntry.seq).offset(PRUNE_BATCH - 1).limit(1))).first()
                upto, h = (int(r[0]), r[1] or "") if r is not None else tgt
                res = await s.execute(delete(AuditEntry).where(AuditEntry.seq <= upto).execution_options(synchronize_session=False))
                if upto > int(st.get("anchor_seq") or 0):
                    st.update(anchor_seq=int(upto), anchor_hash=h)
                for k in ("verified", "sweep"):
                    if st.get(f"{k}_seq") is not None and int(st[f"{k}_seq"]) < upto:
                        st[f"{k}_seq"], st[f"{k}_hash"] = int(upto), h
                st["problems"] = [p for p in st.get("problems") or [] if int(p.get("seq") or 0) > upto]
                await _put_state(s, st)
                await s.commit()
                gone += res.rowcount or 0
                if upto >= tgt[0]:
                    break
    await verify(budget=SWEEP_BUDGET)  # the new entries – also when nobody opens the page
    await sweep()
    async with _session() as s:
        st = await chain_state(s)
    logging.getLogger("cobe_news.audit").info(
        "audit chain head: seq=%s hash=%s key=%s anchor=%s", st.get("head_seq"), st.get("head_hash"), st.get("key"), st.get("anchor_seq") or 0
    )
    return gone


# ---------------------------------------------------------------- reading


# the one expression of the trigram index ix_audit_log_search (migration 0033) – written literally, so that the database
# sees the indexed expression itself (a bound " " would not match it)
SEARCH_TEXT = literal_column(
    "lower(audit_log.actor_name || ' ' || audit_log.actor_display || ' ' || audit_log.action || ' ' || "
    "coalesce(audit_log.target_label, '') || ' ' || coalesce(audit_log.target_id, '') || ' ' || coalesce(audit_log.ip, ''))",
    SAText(),
)
SEARCH_MIN = 3  # characters from which the trigram index helps


@dataclass
class Filters:
    since: datetime | None = None
    until: datetime | None = None
    actor: str | None = None  # an account's id, or a kind: system | sync | cli
    group: str | None = None
    action: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    ip: str | None = None
    session: str | None = None  # a session reference (session_ref)
    notable: bool = False  # anomalies and security-relevant actions only
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
    if f.ip:
        w.append(AuditEntry.ip == f.ip)
    if f.session:
        w.append(AuditEntry.session_ref == f.session)
    if f.notable:
        w.append(AuditEntry.notable.is_(True))
    if f.q and f.q.strip():
        # one expression over name, display name, action, target and address – the one of the trigram index
        # ix_audit_log_search (migration 0033): from 3 characters on an index search, shorter terms read every entry
        w.append(SEARCH_TEXT.contains(f.q.strip().lower(), autoescape=True))
    return w


def _query(f: Filters) -> Select:
    return select(AuditEntry).where(*_where(f)).order_by(AuditEntry.at.desc(), AuditEntry.id.desc())


def encode_cursor(e: AuditEntry) -> str:
    return base64.urlsafe_b64encode(f"{e.at.isoformat()}|{e.id}".encode()).decode().rstrip("=")


TIME_MIN = datetime(2000, 1, 1, tzinfo=UTC)
TIME_MAX = datetime(9000, 1, 1, tzinfo=UTC)


def in_range(when: datetime) -> bool:
    """A time the database takes (an extreme one with a zone overflows on the way)."""
    return TIME_MIN <= when <= TIME_MAX


def decode_cursor(c: str) -> tuple[datetime, int]:
    """The keyset position after which the next page starts (ValueError: not one of ours)."""
    raw = base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)).decode()
    at, _, n = raw.partition("|")
    when = datetime.fromisoformat(at)
    if when.tzinfo is None:
        raise ValueError("naive")
    if not in_range(when):
        raise ValueError("time out of range")
    pos = int(n)
    if not 0 < pos < 2**63:
        raise ValueError("id out of range")
    return when, pos


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


async def count(db: AsyncSession, f: Filters, cap: int = COUNT_CAP) -> int:
    """How many entries the filters find – counted up to cap + 1 (more than cap: "cap+")."""
    sub = select(AuditEntry.id).where(*_where(f)).limit(cap + 1).subquery()
    return int(await db.scalar(select(func.count()).select_from(sub)) or 0)


def entry_out(e: AuditEntry) -> dict:
    d = dict(e.details or {})
    anomalies = d.pop("anomalies", None) or []
    return {
        "id": e.id,
        "at": e.at.isoformat(),
        "actor": {
            "kind": e.actor_kind,
            "id": str(e.actor_id) if e.actor_id else None,
            "name": e.actor_name,
            "display": e.actor_display,
            "role": e.actor_role,
            "emergency": e.actor_emergency,
        },
        "action": e.action,
        "group": ACTIONS.get(e.action, "other"),
        "target": {"type": e.target_type, "id": e.target_id, "label": e.target_label} if e.target_type else None,
        "ip": e.ip,
        "ip_class": ip_class(e.ip),
        "via": e.req_via,
        "browser": {"family": e.ua_family, "version": e.ua_version, "os": e.ua_os} if (e.ua_family or e.ua_os) else None,
        "session": {"ref": e.session_ref, "method": e.auth_method} if (e.session_ref or e.auth_method) else None,
        "request": {"method": e.req_method, "path": e.req_path, "id": e.request_id} if (e.req_method or e.request_id) else None,
        "app_version": e.app_version,
        "notable": bool(e.notable),
        "anomalies": anomalies,
        "seq": e.seq,
        "details": d,
    }


def _brief(e: AuditEntry) -> dict:
    return {"id": e.id, "at": e.at.isoformat(), "action": e.action, "actor": {"kind": e.actor_kind, "name": e.actor_name, "display": e.actor_display}, "ip": e.ip}


async def context(db: AsyncSession, e: AuditEntry) -> dict:
    """An expanded entry's surroundings: the target's earlier entries (newest 5), the entries of its session, its
    address in the 24 hours up to it (and the locks among them), the account's sign-in before it."""
    before = tuple_(AuditEntry.at, AuditEntry.id) < tuple_(e.at, e.id)
    out: dict = {"history": [], "session": None, "ip_24h": None, "previous_signin": None}
    if e.target_type and (e.target_id or e.target_label):
        same = AuditEntry.target_id == e.target_id if e.target_id else AuditEntry.target_label == e.target_label
        rows = await db.scalars(select(AuditEntry).where(AuditEntry.target_type == e.target_type, same, before).order_by(AuditEntry.at.desc(), AuditEntry.id.desc()).limit(5))
        out["history"] = [_brief(x) for x in rows]
    if e.session_ref:
        n, first, last = (await db.execute(select(func.count(), func.min(AuditEntry.at), func.max(AuditEntry.at)).where(AuditEntry.session_ref == e.session_ref))).one()
        out["session"] = {"ref": e.session_ref, "entries": int(n or 0), "first": first.isoformat() if first else None, "last": last.isoformat() if last else None}
    if e.ip:
        window = (AuditEntry.ip == e.ip, AuditEntry.at >= e.at - timedelta(hours=24), AuditEntry.at <= e.at)
        n, locks = (await db.execute(select(func.count(), func.count().filter(AuditEntry.action.in_(LOCK_ACTIONS))).where(*window))).one()
        out["ip_24h"] = {"entries": int(n or 0), "locks": int(locks or 0)}
    if e.actor_id:
        prev = await db.scalar(
            select(AuditEntry).where(AuditEntry.actor_id == e.actor_id, AuditEntry.action == "login.success", before).order_by(AuditEntry.at.desc(), AuditEntry.id.desc()).limit(1)
        )
        if prev is not None:
            out["previous_signin"] = {
                "id": prev.id,
                "at": prev.at.isoformat(),
                "ip": prev.ip,
                "ip_class": ip_class(prev.ip),
                "method": prev.auth_method or (prev.details or {}).get("method"),
                "browser": {"family": prev.ua_family, "version": prev.ua_version, "os": prev.ua_os} if (prev.ua_family or prev.ua_os) else None,
            }
    return out


_NEWEST_PER_ACTOR = text(
    """
    WITH RECURSIVE ids AS (
        (SELECT actor_id FROM audit_log WHERE actor_id IS NOT NULL ORDER BY actor_id LIMIT 1)
        UNION ALL
        SELECT (SELECT a.actor_id FROM audit_log a WHERE a.actor_id > ids.actor_id ORDER BY a.actor_id LIMIT 1)
        FROM ids WHERE ids.actor_id IS NOT NULL
    )
    SELECT l.actor_id, l.actor_name, l.actor_display FROM ids CROSS JOIN LATERAL (
        SELECT a.actor_id, a.actor_name, a.actor_display FROM audit_log a
        WHERE a.actor_id = ids.actor_id ORDER BY a.at DESC, a.id DESC LIMIT 1
    ) l
    WHERE ids.actor_id IS NOT NULL
    """
)


async def actors(db: AsyncSession) -> list[dict]:
    """Who appears in the log (for the filter): accounts by their newest name (a loose index scan – one step per
    account, not per entry), sorted by name, then the other kinds that occur."""
    rows = await db.execute(_NEWEST_PER_ACTOR)
    users = sorted(({"id": str(i), "kind": "user", "name": n, "display": d} for i, n, d in rows), key=lambda x: ((x["display"] or x["name"]).lower(), x["name"]))
    kinds = [k for k in ACTOR_KINDS if k != "user" and await db.scalar(select(exists().where(AuditEntry.actor_kind == k)))]
    return users[:ACTORS_MAX] + [{"id": k, "kind": k, "name": k, "display": ""} for k in kinds]


# ---------------------------------------------------------------- CSV (export)

CSV_COLUMNS = (
    "time_utc",
    "actor_kind",
    "actor",
    "actor_name",
    "actor_id",
    "action",
    "group",
    "target_type",
    "target_id",
    "target",
    "ip",
    "details",
    "notable",
    "anomalies",
    "actor_role",
    "session",
    "auth_method",
    "browser",
    "os",
    "request",
    "request_id",
    "via",
    "app_version",
    "seq",
    "hash",
)
DELIMITERS = {"comma": ",", "semicolon": ";"}
_FORMULA = ("=", "+", "-", "@", "\t", "\r")
# a formula start right after a separator: a spreadsheet that splits on the other separator (Excel with a German list
# separator opens a comma CSV split on ";") would start a new cell there
_AFTER_SEPARATOR = re.compile(r"([,;\t\r\n])(\s*)([=+\-@])")
_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_JSON_ESCAPE = {"=": "\\u003d", "+": "\\u002b", "-": "\\u002d", "@": "\\u0040"}


def cell(v: object) -> str:
    """A CSV cell that is never a formula: a leading = + - @ (or tab / carriage return) and one right after a comma,
    semicolon, tab or line break are quoted for spreadsheets."""
    s = "" if v is None else str(v)
    s = _AFTER_SEPARATOR.sub(r"\1\2'\3", s)
    return "'" + s if s[:1] in _FORMULA else s


def json_cell(value: dict | None) -> str:
    """The details as JSON that stays JSON and never starts a formula: a formula character after a separator inside a
    string is written as its \\u escape (the same text once parsed)."""
    if not value:
        return ""
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True)

    def fix(m: re.Match) -> str:
        return _AFTER_SEPARATOR.sub(lambda x: x.group(1) + x.group(2) + _JSON_ESCAPE[x.group(3)], m.group(0))

    return _JSON_STRING.sub(fix, raw)


def csv_row(e: AuditEntry) -> list[str]:
    d = dict(e.details or {})
    anomalies = d.pop("anomalies", None) or []
    browser = " ".join(x for x in (e.ua_family, e.ua_version) if x)
    request = " ".join(x for x in (e.req_method, e.req_path) if x)
    head = (
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
    )
    tail = (
        "1" if e.notable else "0",
        " ".join(anomalies),
        e.actor_role,
        e.session_ref,
        e.auth_method,
        browser,
        e.ua_os,
        request,
        e.request_id,
        e.req_via,
        e.app_version,
        e.seq,
        e.hash,
    )
    return [*(cell(v) for v in head), json_cell(d), *(cell(v) for v in tail)]


TRUNCATED_NOTE = "# truncated: the newest {n} entries only – narrow the filters (the time range) for the older ones"


async def export_truncated(db: AsyncSession, f: Filters) -> bool:
    """Whether the filters find more than EXPORT_MAX entries (the export is cut: a header and its last row say so)."""
    q = select(AuditEntry.id).where(*_where(f)).order_by(AuditEntry.at.desc(), AuditEntry.id.desc()).offset(EXPORT_MAX).limit(1)
    return await db.scalar(q) is not None


async def csv_chunks(f: Filters, delimiter: str = ",") -> AsyncIterator[bytes]:
    """The export, newest first, in chunks (UTF-8 with BOM; the delimiter of the reader's language – Excel splits on
    its list separator), at most EXPORT_MAX rows and then a last row saying so. A session of its own, one short read
    transaction per chunk: the response streams after the request's session is gone."""
    from app import db as dbm

    buf = io.StringIO()
    csv.writer(buf, delimiter=delimiter).writerow(CSV_COLUMNS)
    yield ("﻿" + buf.getvalue()).encode()
    cursor: str | None = None
    left = EXPORT_MAX
    async with dbm.session() as s:
        while left > 0:
            rows, cursor = await page(s, f, cursor, min(1000, left))
            buf = io.StringIO()
            w = csv.writer(buf, delimiter=delimiter)
            for e in rows:
                w.writerow(csv_row(e))
            await s.rollback()  # nothing stays open while the client reads
            left -= len(rows)
            if rows:
                yield buf.getvalue().encode()
            if not cursor:
                return
    if cursor:
        buf = io.StringIO()
        csv.writer(buf, delimiter=delimiter).writerow([TRUNCATED_NOTE.format(n=EXPORT_MAX)] + [""] * (len(CSV_COLUMNS) - 1))
        yield buf.getvalue().encode()
