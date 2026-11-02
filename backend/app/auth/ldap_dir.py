"""AD / LDAP sign-in: service bind → search the person (sAMAccountName or UPN) → bind as the person → groups.

ldap3 is synchronous; every public function here is meant to run in a thread (asyncio.to_thread).
- LDAPS or StartTLS, certificates verified by default; clear-text LDAP only with the explicit "allow_plain" switch –
  every password then crosses the network readable,
- every user input is escaped before it goes into a filter (no LDAP injection),
- an empty password is refused before binding – many directories treat it as an anonymous bind that "succeeds".
"""

import asyncio
import logging
import ssl
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

from ldap3 import BASE, FIRST, NONE, SIMPLE, SUBTREE, Connection, Server, ServerPool, Tls
from ldap3.utils.conv import escape_bytes, escape_filter_chars

from app import netaddr
from app.auth.directory import DirectoryUser
from app.crypto import decrypt_str
from app.settings import LDAP_FILTER

log = logging.getLogger("cobe_news.ldap")

USER_ATTRS = ["sAMAccountName", "userPrincipalName", "displayName", "mail", "memberOf", "objectGUID", "userAccountControl"]
IN_CHAIN = "1.2.840.113556.1.4.1941"  # AD: LDAP_MATCHING_RULE_IN_CHAIN (nested groups)
UAC_DISABLED = 0x2
GROUP_CLASSES = "(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"


def derive_base_dn(host: str) -> str:
    """dc01.corp.example → DC=corp,DC=example."""
    h = host.strip().lower().split("://", 1)[-1].rstrip("/")
    h = h.rsplit(":", 1)[0] if h.count(":") == 1 else h
    labels = [x for x in h.split(".") if x]
    if len(labels) < 2 or all(x.isdigit() for x in labels):
        return ""
    if len(labels) > 2:
        labels = labels[1:]
    return ",".join(f"DC={x}" for x in labels)


def normalize(cfg: dict) -> dict:
    out = dict(cfg)
    out["servers"] = [str(x).strip() for x in (out.get("servers") or []) if str(x).strip()][:4]
    out.setdefault("encryption", "ldaps")
    out["user_filter"] = out.get("user_filter") or LDAP_FILTER
    if not out.get("base_dn") and out["servers"]:
        out["base_dn"] = derive_base_dn(out["servers"][0])
    return out


def usable(cfg: dict) -> bool:
    cfg = normalize(cfg)
    plain_ok = cfg["encryption"] != "none" or cfg.get("allow_plain")
    return bool(cfg["servers"] and cfg.get("base_dn") and cfg.get("bind_dn") and cfg.get("bind_password_enc") and plain_ok)


def _server(cfg: dict, host: str) -> Server:
    # a directory server is admin input like the SMTP host: company networks fine, never loopback, link-local, this
    # container's Docker networks or the Docker host (host.docker.internal reaches services on the host's 127.0.0.1)
    try:
        netaddr.check_host(urlsplit(f"ldap://{host}").hostname or host)
    except (netaddr.ForbiddenTarget, ValueError) as exc:
        raise LdapError("forbidden_target") from exc
    ldaps = cfg.get("encryption") == "ldaps"
    tls = Tls(
        validate=ssl.CERT_REQUIRED if cfg.get("verify_cert", True) else ssl.CERT_NONE,
        version=ssl.PROTOCOL_TLS_CLIENT,
        ca_certs_data=cfg.get("ca_cert") or None,
    )
    return Server(f"{'ldaps' if ldaps else 'ldap'}://{host}", use_ssl=ldaps, tls=tls, get_info=NONE, connect_timeout=int(cfg.get("timeout") or 10))


def _pool(cfg: dict) -> ServerPool:
    """The first reachable server wins: the first entry is the primary DC, the others are fallbacks in order."""
    return ServerPool([_server(cfg, h) for h in cfg["servers"]], FIRST, active=1, exhaust=False)


def connection(cfg: dict, user: str, password: str) -> Connection:
    """Open and bind. A bound connection, an unbound one for bad credentials, or LdapError."""
    cfg = normalize(cfg)
    if not cfg["servers"]:
        raise LdapError("not_configured")
    if cfg["encryption"] == "none" and not cfg.get("allow_plain"):
        raise LdapError("plain_refused")
    conn = Connection(
        _pool(cfg),
        user=user,
        password=password,
        authentication=SIMPLE,
        read_only=True,
        receive_timeout=int(cfg.get("timeout") or 10),
        raise_exceptions=False,
        auto_bind=False,
        # a referral would send the service account's (or the user's) password to whichever server the answer names
        auto_referrals=False,
    )
    try:
        conn.open()
        if cfg["encryption"] == "starttls" and not conn.start_tls():
            raise LdapError("tls")
        conn.bind()
    except LdapError:
        _close(conn)
        raise
    except Exception as exc:  # noqa: BLE001 - socket/TLS errors of ldap3 have many types
        _close(conn)
        raise LdapError("tls" if "ssl" in type(exc).__name__.lower() or "tls" in str(exc).lower() else "connection") from exc
    return conn


def _close(conn: Connection) -> None:
    try:
        conn.unbind()
    except Exception:  # noqa: BLE001, S110 - closing is best effort
        pass


def _service(cfg: dict) -> Connection:
    cfg = normalize(cfg)
    if not usable(cfg):
        raise LdapError("not_configured")
    conn = connection(cfg, cfg["bind_dn"], decrypt_str(cfg["bind_password_enc"]))
    if not conn.bound:
        _close(conn)
        raise LdapError("service_bind")
    return conn


def _entries(conn: Connection) -> list[dict]:
    return [r for r in (conn.response or []) if r.get("type") == "searchResEntry"]


def _one(attrs: dict, name: str) -> Any:
    v = attrs.get(name)
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _many(attrs: dict, name: str) -> list:
    v = attrs.get(name)
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _cn(dn: str) -> str:
    first = dn.split(",", 1)[0]
    return first.split("=", 1)[1] if "=" in first else first


def _guid(attrs: dict, dn: str) -> str:
    g = _one(attrs, "objectGUID")
    if isinstance(g, bytes) and len(g) == 16:
        return str(uuid.UUID(bytes_le=g))
    if isinstance(g, str) and g.strip("{}"):
        try:
            return str(uuid.UUID(g.strip("{}")))
        except ValueError:
            pass
    return f"dn:{dn}"


def _dn_path(dn: str) -> str:
    """CN=Grp,OU=Groups,DC=corp,DC=example → corp.example/Groups."""
    parts = [p.split("=", 1) for p in dn.split(",") if "=" in p]
    dc = ".".join(v for k, v in parts if k.strip().lower() == "dc")
    ous = [v for k, v in parts[1:] if k.strip().lower() in ("ou", "cn")]
    return "/".join([dc, *reversed(ous)]) if dc else dn



class LdapError(Exception):
    """Coarse category: not_configured | connection | tls | service_bind | search."""

    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


class AccountLocked(LdapError):
    """The account the name led to is locked in Cobe News – not bound."""


def _uac(attrs: dict) -> int:
    try:
        return int(_one(attrs, "userAccountControl") or 0)
    except (TypeError, ValueError):
        return 0


def _groups(conn: Connection, cfg: dict, dn: str, attrs: dict) -> list[str]:
    dns = [str(g) for g in _many(attrs, "memberOf")]
    if cfg.get("nested_groups", True):
        ok = conn.search(cfg["base_dn"], f"(member:{IN_CHAIN}:={escape_filter_chars(dn)})", SUBTREE, attributes=["cn"], size_limit=1000)
        if ok:
            dns += [e["dn"] for e in _entries(conn)]
    # Full DNs only: a CN is unique per container, not per domain – anyone allowed to create a group with the same
    # name in another OU would otherwise get the mapped role.
    out: list[str] = []
    for g in dns:
        if g not in out:
            out.append(g)
    return out


def _rdns(dn: str) -> list[tuple[str, str]]:
    from ldap3.utils.dn import parse_dn

    return [(k.strip().lower(), v.strip().lower()) for k, v, _ in parse_dn(dn, strip=True)]


def _below(dn: str, base: str) -> bool:
    """dn is base or lies below it – compared RDN by RDN (not as text: "OU=IT Admins" ≠ "OU=ITAdmins", DC=notcorp ≠ DC=corp)."""
    try:
        d, b = _rdns(dn), _rdns(base)
    except Exception:  # noqa: BLE001 - ldap3 raises several types for malformed DNs
        return False
    return bool(b) and len(d) >= len(b) and d[len(d) - len(b) :] == b


def _object_filter(cfg: dict, object_id: str) -> tuple[str, str, str]:
    """(search base, filter, scope) for an id from a search result: objectGUID, or a DN below the configured base.

    DNs outside base_dn are refused.
    """
    from ldap3.utils.dn import parse_dn

    if object_id.startswith("dn:"):
        dn = object_id[3:]
        try:
            parse_dn(dn)
        except Exception as exc:  # noqa: BLE001 - ldap3 raises several types for malformed DNs
            raise LdapError("not_found") from exc
        if not _below(dn, cfg["base_dn"]):
            raise LdapError("not_found")
        return dn, "(objectClass=*)", BASE
    try:
        guid = uuid.UUID(object_id)
    except ValueError as exc:
        raise LdapError("not_found") from exc
    return cfg["base_dn"], f"(objectGUID={escape_bytes(guid.bytes_le)})", SUBTREE


def _to_directory_user(cfg: dict, conn: Connection, entry: dict) -> DirectoryUser:
    a = entry.get("attributes") or {}
    name_attr = cfg.get("attr_username") or "sAMAccountName"
    username = str(_one(a, name_attr) or _one(a, "sAMAccountName") or _cn(entry["dn"])).strip().lower()
    return DirectoryUser(
        source="ldap",
        external_id=_guid(a, entry["dn"]),
        username=username[:128],
        display_name=str(_one(a, "displayName") or username)[:255],
        email=(str(_one(a, "mail")) if _one(a, "mail") else None),
        groups=_groups(conn, cfg, entry["dn"], a),
        enabled=not (_uac(a) & UAC_DISABLED),
    )


# LDAP calls block (connect and receive timeouts of several seconds): their own few threads, so a slow or unreachable DC
# never takes the default pool that file and password hashing work also needs
_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ldap")


async def run(fn, *args):
    return await asyncio.get_running_loop().run_in_executor(_EXECUTOR, fn, *args)


def authenticate(cfg: dict, username: str, password: str, seen: list[str] | None = None, locked=None) -> DirectoryUser | None:  # noqa: ANN001
    """None for unknown user or wrong password (the caller counts it as a failed attempt). `seen` gets the account's
    objectGUID once the search found exactly one – failed attempts count per account, whatever name was typed.
    `locked(guid)`: asked between the search and the bind – True raises AccountLocked before the password goes to the
    DC (a name typed as UPN or in another form finds the locked account only here; its bind would count on the DC's own
    lockout policy)."""
    cfg = normalize(cfg)
    if not password or len(password) > 1024 or not username or len(username) > 256:
        return None
    svc = _service(cfg)
    try:
        flt = cfg["user_filter"].replace("{username}", escape_filter_chars(username))
        if not svc.search(cfg["base_dn"], flt, SUBTREE, attributes=USER_ATTRS, size_limit=2):
            return None
        found = _entries(svc)
        if len(found) != 1:
            return None  # unknown or ambiguous – never guess
        entry = found[0]
        guid = _guid(entry.get("attributes") or {}, entry["dn"])
        if seen is not None:
            seen.append(guid)
        if locked is not None and locked(guid):
            raise AccountLocked("locked")
        user_conn = connection(cfg, entry["dn"], password)
        ok = user_conn.bound
        user_conn.unbind()
        if not ok:
            return None
        return _to_directory_user(cfg, svc, entry)
    finally:
        svc.unbind()


def verify_password(cfg: dict, dn_or_user: str, password: str) -> bool:
    """Re-authentication of a directory user (bind with the stored account)."""
    du = authenticate(cfg, dn_or_user, password)
    return du is not None


def _lookup(cfg: dict, svc: Connection, external_id: str) -> DirectoryUser | None:
    """None only for a clean answer "no such account" – any other failed search raises (an error must never read as
    "gone", that would switch the account off)."""
    base, flt, scope = _object_filter(cfg, external_id)
    ok = svc.search(base, flt, scope, attributes=USER_ATTRS, size_limit=2)
    if not ok:
        if (svc.result or {}).get("result") in (0, 32):  # success without entries, noSuchObject
            return None
        raise LdapError("search")
    found = _entries(svc)
    if len(found) > 1:
        raise LdapError("search")  # ambiguous – never guess
    return _to_directory_user(cfg, svc, found[0]) if found else None


def lookup(cfg: dict, external_id: str) -> DirectoryUser | None:
    """Find an account by objectGUID (or DN)."""
    return lookup_many(cfg, [external_id])[external_id]


def lookup_many(cfg: dict, external_ids: list[str]) -> dict[str, DirectoryUser | None]:
    """For the periodic sync: all accounts with one bind of the service account."""
    cfg = normalize(cfg)
    svc = _service(cfg)
    try:
        return {i: _lookup(cfg, svc, i) for i in external_ids}
    finally:
        svc.unbind()


def test(cfg: dict) -> dict:
    cfg = normalize(cfg)
    svc = _service(cfg)
    try:
        if not svc.search(cfg["base_dn"], "(objectClass=*)", BASE, attributes=["objectClass"]):
            raise LdapError("search")
        return {"ok": True}
    finally:
        svc.unbind()


# ---------------------------------------------------------------- lookups for cases


def search_groups(cfg: dict, q: str, limit: int = 25) -> list[dict]:
    """Groups for the role mapping, searched live – the id stays the full DN (a CN alone is not unique)."""
    cfg = normalize(cfg)
    svc = _service(cfg)
    try:
        esc = escape_filter_chars(q.strip()[:100])
        flt = f"(&{GROUP_CLASSES}(|(cn=*{esc}*)(sAMAccountName=*{esc}*)(description=*{esc}*)))" if esc else GROUP_CLASSES
        svc.search(cfg["base_dn"], flt, SUBTREE, attributes=["cn", "description"], size_limit=limit)
        if (svc.result or {}).get("result") not in (0, 4):  # 4 = size limit reached, the first entries are still fine
            raise LdapError("search")
        out = [
            {"id": e["dn"], "name": str(_one(e.get("attributes") or {}, "cn") or _cn(e["dn"])), "description": str(_one(e.get("attributes") or {}, "description") or ""), "path": _dn_path(e["dn"])}
            for e in _entries(svc)
        ]
        return sorted(out, key=lambda g: g["name"].lower())
    finally:
        svc.unbind()


# ---------------------------------------------------------------- Teams: the members of a group


MEMBER_PAGE = 500  # paged search (RFC 2696): AD answers at most 1000 entries per page anyway
MEMBERS_MAX = 50_000  # one group – more is no team (and would keep the sync busy for long)
MEMBER_ATTRS = ["sAMAccountName", "userPrincipalName", "displayName", "mail", "objectGUID", "userAccountControl"]
PAGED_RESULTS = "1.2.840.113556.1.4.319"


def group_dn(cfg: dict, dn: str) -> str:
    """A bound group's DN, checked: a well-formed DN below the configured base (as a search result would be) – never a
    filter fragment. LdapError("not_found") otherwise."""
    from ldap3.utils.dn import parse_dn

    dn = (dn or "").strip()
    try:
        parse_dn(dn)
    except Exception as exc:  # noqa: BLE001 - ldap3 raises several types for malformed DNs
        raise LdapError("not_found") from exc
    if not _below(dn, normalize(cfg)["base_dn"]):
        raise LdapError("not_found")
    return dn


def member_filter(dn: str) -> str:
    """People in the group, nested groups too (LDAP_MATCHING_RULE_IN_CHAIN) – the DN escaped for the filter (RFC 4515):
    a group named "a)(objectClass=*" stays one value."""
    return f"(&(objectCategory=person)(objectClass=user)(memberOf:{IN_CHAIN}:={escape_filter_chars(dn)}))"


def _cookie(conn: Connection) -> bytes | None:
    ctrl = ((conn.result or {}).get("controls") or {}).get(PAGED_RESULTS) or {}
    return (ctrl.get("value") or {}).get("cookie") or None


def group_members(cfg: dict, dn: str) -> list[DirectoryUser]:
    """Everybody in the group (nested groups too), page by page with one bind of the service account. `groups` stays
    empty (the role comes from the sign-in and the hourly sync), `enabled` from userAccountControl. LdapError on any
    failed page – a half answer must never read as "these are all" (the sync would take the others out of the team)."""
    cfg = normalize(cfg)
    dn = group_dn(cfg, dn)
    svc = _service(cfg)
    out: list[DirectoryUser] = []
    try:
        flt = member_filter(dn)
        cookie: bytes | None = None
        name_attr = cfg.get("attr_username") or "sAMAccountName"
        while True:
            ok = svc.search(cfg["base_dn"], flt, SUBTREE, attributes=MEMBER_ATTRS, paged_size=MEMBER_PAGE, paged_cookie=cookie)
            if not ok and (svc.result or {}).get("result") not in (0, 32):
                raise LdapError("search")
            for e in _entries(svc):
                a = e.get("attributes") or {}
                username = str(_one(a, name_attr) or _one(a, "sAMAccountName") or _cn(e["dn"])).strip().lower()
                out.append(
                    DirectoryUser(
                        source="ldap",
                        external_id=_guid(a, e["dn"]),
                        username=username[:128],
                        display_name=str(_one(a, "displayName") or username)[:255],
                        email=(str(_one(a, "mail"))[:255] if _one(a, "mail") else None),
                        enabled=not (_uac(a) & UAC_DISABLED),
                    )
                )
            if len(out) > MEMBERS_MAX:
                raise LdapError("too_many")
            cookie = _cookie(svc)
            if not cookie:
                return out
    finally:
        svc.unbind()
