"""What every endpoint needs: the database, errors, the client address and who is signed in (reader or admin)."""

import ipaddress
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import sessions
from app.config import get_config
from app.db import get_db, has_nul
from app.models import User, UserSession

Db = Annotated[AsyncSession, Depends(get_db)]


class NoNul(BaseModel):
    """Base of every request body: a U+0000 anywhere in it (a value or a key, however deep) is refused with 422 – the
    database cannot store it, and no name, note or address needs it."""

    @model_validator(mode="before")
    @classmethod
    def _refuse_nul(cls, data):  # noqa: ANN001, ANN206
        if has_nul(data):
            raise ValueError("NUL character (U+0000) not allowed")
        return data


def api_error(status: int, code: str, **extra) -> HTTPException:
    return HTTPException(status, detail={"code": code, **extra})


def _ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value.strip().split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def client_ip(request: Request) -> str:
    """The direct peer – or, only when that is a trusted proxy (the bundled nginx at its fixed address, TRUSTED_PROXIES),
    the address it reports. nginx replaces X-Forwarded-For with the real peer, so the last entry is the client; anything a
    client wrote itself never counts."""
    peer = _ip(request.client.host) if request.client else None
    peer = peer or "0.0.0.0"  # noqa: S104 - placeholder, not a bind address
    nets = get_config().trusted_networks
    if not nets or not any(ipaddress.ip_address(peer) in n for n in nets):
        return peer
    hops = [h.strip() for h in ",".join(request.headers.getlist("x-forwarded-for")).split(",") if h.strip()]
    for hop in reversed(hops):
        ip = _ip(hop)
        if ip is None:
            return peer
        if not any(ipaddress.ip_address(ip) in n for n in nets):
            return ip
    return peer


def client_route(request: Request) -> tuple[str, str]:
    """The client address (client_ip) and how the request arrived: "direct" (the peer itself), "bundled" (through the
    bundled nginx), "proxy" (through a reverse proxy of your own – TRUSTED_PROXIES or the Docker host's), "bundled_proxy"
    (an own proxy in front of the bundled nginx). For the audit log's "Woher"."""
    ip = client_ip(request)
    peer = _ip(request.client.host) if request.client else None
    cfg = get_config()
    nets = cfg.trusted_networks
    if not peer or not nets or not any(ipaddress.ip_address(peer) in n for n in nets):
        return ip, "direct"
    bundled = bool(cfg.proxy_enabled and cfg.proxy_ip and peer == cfg.proxy_ip)
    hops = [h.strip() for h in ",".join(request.headers.getlist("x-forwarded-for")).split(",") if h.strip()]
    if not hops:
        return ip, "direct"  # the proxy itself asked
    own = False
    for hop in reversed(hops):
        a = _ip(hop)
        if a is None or not any(ipaddress.ip_address(a) in n for n in nets):
            break
        own = True  # a further trusted hop: a proxy of your own on the way
    if bundled:
        return ip, "bundled_proxy" if own else "bundled"
    return ip, "proxy"


def via_https(request: Request) -> bool:
    peer = _ip(request.client.host) if request.client else None
    trusted = peer is not None and any(ipaddress.ip_address(peer) in n for n in get_config().trusted_networks)
    return request.url.scheme == "https" or (trusted and request.headers.get("x-forwarded-proto") == "https")


def user_agent(request: Request) -> str:
    return (request.headers.get("user-agent") or "")[:255]


BACKGROUND_HEADER = "x-cobe-background"
# a POST that only reads (its body carries a push endpoint, which belongs in no address): the 10-minute push check
READ_ONLY_POSTS = frozenset({"/api/me/push/state"})


def background(request: Request) -> bool:
    """A request the page made on its own (a poll, a refetch – X-Cobe-Background: 1, lib/poll.ts): answered as usual, but
    it does not move "last active" – a tab left open must not keep its session alive past the idle timeout. Only for
    reading requests: a change is always the person's own doing. (The header can only make a session end sooner.)"""
    if request.headers.get(BACKGROUND_HEADER) != "1":
        return False
    return request.method in ("GET", "HEAD") or (request.method == "POST" and request.url.path in READ_ONLY_POSTS)


async def _session(request: Request, db: AsyncSession) -> tuple[UserSession, User] | None:
    cached = getattr(request.state, "session", None)
    if cached is not None:
        return cached
    got = await sessions.load(db, request.cookies.get(sessions.cookie_name()), touch=not background(request))
    request.state.session = got
    if got is not None:
        from app import audit

        audit.set_session(got[0])  # the audit log's "Wer": this session's reference and how it was signed in
    return got


async def optional_session(request: Request, db: Db) -> tuple[UserSession, User] | None:
    return await _session(request, db)


def session_in_stage(*stages: str):
    async def dep(request: Request, db: Db) -> tuple[UserSession, User]:
        got = await _session(request, db)
        if got is None:
            raise api_error(401, "not_authenticated")
        if got[0].stage not in stages:
            raise api_error(403, "wrong_stage", stage=got[0].stage)
        return got

    return dep


async def current_user(request: Request, db: Db) -> User:
    got = await _session(request, db)
    if got is None or got[0].stage != "active":
        raise api_error(401, "not_authenticated")
    return got[1]


async def admin_user(user: Annotated[User, Depends(current_user)]) -> User:
    if user.role != "admin":
        raise api_error(403, "forbidden")
    return user


async def current_session(request: Request, db: Db) -> UserSession:
    got = await _session(request, db)
    if got is None or got[0].stage != "active":
        raise api_error(401, "not_authenticated")
    return got[0]


async def peek_session(request: Request, db: Db) -> UserSession:
    """The active session without touching it ("last active" stays): GET /api/auth/session – the tabs look whether it is
    still there without keeping it alive. 401 once it is over (and `load` deletes the row)."""
    got = await sessions.load(db, request.cookies.get(sessions.cookie_name()), touch=False)
    if got is None or got[0].stage != "active":
        raise api_error(401, "not_authenticated")
    return got[0]


def require_reauth(sess: UserSession, user: User) -> None:
    """Sensitive admin actions (sign-in settings, group mappings, admins, resets, deletions) need a proof of identity of
    the last minutes (sessions.REAUTH_WINDOW): the full sign-in or POST /api/auth/reauth (Entra: oidc/start?reauth=1).
    A session left open – or taken over – is not enough for them."""
    if not sessions.reauth_valid(sess):
        raise api_error(403, "reauth_required", via="entra" if user.auth_source == "entra" else "password", totp=bool(user.totp_secret_enc))


def require_factor(sess: UserSession, user: User) -> None:
    """A session that skipped the TOTP step on a remembered device (method …_device, app/auth/devices.py) proved only the
    password: before a lasting change made with it (a calendar address) the second factor is shown once – the same
    re-confirmation as for sensitive actions (its sign-in set no reauth_at). Other sessions: nothing more asked."""
    if (sess.method or "").endswith("_device"):
        require_reauth(sess, user)


Reader = Annotated[User, Depends(current_user)]
Admin = Annotated[User, Depends(admin_user)]
ActiveSession = Annotated[UserSession, Depends(current_session)]
PeekedSession = Annotated[UserSession, Depends(peek_session)]


def download_guard(request: Request) -> None:
    """A download that is logged (the audit log's CSV, the data export): only from this site's own page – the CSRF token
    must come along (the page's api.getFile sends it). A link on another site or an address typed in (a top-level
    navigation carries the Lax session cookie) must not make an admin's browser download it and write the entry."""
    import hmac

    csrf = request.cookies.get(sessions.csrf_cookie_name()) or ""
    sent = request.headers.get("x-csrf-token") or ""
    if csrf and sent and hmac.compare_digest(csrf, sent):
        return
    raise api_error(403, "csrf_failed")


DownloadGuard = Annotated[None, Depends(download_guard)]
