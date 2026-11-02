"""API tokens: named, read-only tokens for the documented API (/api/v1, app/api_v1.py) and the metrics (/metrics,
app/metrics.py) – for scripts, a SIEM or Prometheus, never for a browser.

- **The token.** `cnt_` and 43 characters (crypto.new_token: 256 random bits) – the prefix lets secret scanners and
  people recognise it. Shown once when made; the database keeps only its keyed hash (crypto.token_hash, the HMAC of the
  session tokens) and its first characters (`prefix`) to tell tokens apart in the list.
- **Scopes.** `read` (the read-only endpoints under /api/v1: news, Vendor News, products, findings) and `metrics`
  (/metrics only). There is no writing scope and no admin scope; a token never reaches any other endpoint.
- **Validity.** Neither revoked nor expired, and the admin who made it is still an active admin – an admin switched off,
  deleted or made a reader takes their tokens with them. Making and revoking one needs a fresh proof of identity.
  Every token expires, after at most MAX_DAYS (365) – there is no "never" (since 0.1.42; migration 0023 gave the tokens
  made with "never" before an expiry of migration time + 365 days, marked `expiry_added`). A token is not extended:
  before it runs out, make a new one and swap it in the script.
- **Use.** `Authorization: Bearer cnt_…` on a GET. The middleware (main.py → `precheck`) refuses before anything else:
  a bearer request that also carries a session cookie (never both ways of signing in at once – 400), any other method
  than GET or any other path than /api/v1/… and /metrics (403). A bearer request needs no CSRF token (it changes
  nothing and no browser sends it by itself) and gets no CSRF cookie.
- **Answers.** Unknown, malformed, revoked, expired or orphaned: always the same 401 (`invalid_token`); a valid token
  without the scope: 403 (`insufficient_scope`).
- **Rate limits** (in-process, as for the calendar feed): wrong tokens count on the same per-address budget as wrong
  calendar addresses (calendar_feed.FAIL_MAX per WINDOW – then 429 for every token request and feed of that address);
  each token at most TOKEN_MAX requests per WINDOW. "Last used" is written at most every TOUCH_EVERY.
"""

import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import ConfigDict, Field, field_validator
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit, calendar_feed
from app.auth import bruteforce, sessions
from app.crypto import new_token, token_hash
from app.deps import ActiveSession, Admin, Db, NoNul, api_error, client_ip, require_reauth
from app.models import ApiToken, User

PREFIX = "cnt_"
TOKEN_RE = re.compile(r"^cnt_[A-Za-z0-9_-]{43}$")
SCOPES = ("read", "metrics")
Scope = Literal["read", "metrics"]
SHOWN_CHARS = 10  # "cnt_" and six characters – kept to tell tokens apart, 37 characters (> 220 bits) stay secret
MAX_ACTIVE = 50
MAX_DAYS = 365
DEFAULT_DAYS = 365  # as the UI offers it first
TOKEN_MAX = 600  # requests of one token per calendar_feed.WINDOW (10 minutes): a scrape every second at most
TOUCH_EVERY = timedelta(minutes=5)
KEEP_ENDED = timedelta(days=30)  # revoked or expired tokens stay listed this long, then they go (hourly prune)
API_PREFIX = "/api/v1/"
METRICS_PATH = "/metrics"

router = APIRouter(prefix="/api/admin/api-tokens", tags=["admin"])


def allowed_path(path: str) -> bool:
    """The only paths a bearer token may ask for."""
    return path == METRICS_PATH or path.startswith(API_PREFIX)


def bearer(request: Request) -> str | None:
    """The token of an `Authorization: Bearer …` header – None without one (another scheme counts as none)."""
    value = request.headers.get("authorization")
    if value is None:
        return None
    scheme, _, rest = value.strip().partition(" ")
    return rest.strip() if scheme.lower() == "bearer" else None


def _error(status: int, code: str, *, retry: int | None = None) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    if status == 401:
        headers["WWW-Authenticate"] = 'Bearer realm="cobe-news", error="invalid_token"'
    if status == 403 and code == "insufficient_scope":
        headers["WWW-Authenticate"] = 'Bearer realm="cobe-news", error="insufficient_scope"'
    if retry:
        headers["Retry-After"] = str(retry)
    return JSONResponse({"detail": {"code": code}}, status_code=status, headers=headers)


def precheck(request: Request) -> JSONResponse | None:
    """For the middleware, before any route runs: a request with a bearer token – None when it may go on."""
    if request.cookies.get(sessions.cookie_name()) or request.cookies.get(sessions.SESSION_COOKIE):
        return _error(400, "bearer_with_cookie")  # one way of signing in per request – never a mix of both
    if request.method != "GET":
        return _error(403, "token_read_only")
    if not allowed_path(request.url.path):
        return _error(403, "token_not_allowed")
    return None


class TokenError(Exception):
    def __init__(self, response: JSONResponse) -> None:
        self.response = response


def state(row: ApiToken, creator: User | None, now: datetime) -> str:
    """active | revoked | expired | orphaned (its admin is no active admin any more)."""
    if row.revoked_at is not None:
        return "revoked"
    if row.expires_at is not None and row.expires_at <= now:
        return "expired"
    if creator is None or not creator.is_active or creator.role != "admin":
        return "orphaned"
    return "active"


async def authenticate(request: Request, db: AsyncSession, scope: str) -> ApiToken:
    """The token of this request with `scope` – TokenError (with the answer) otherwise."""
    now = time.monotonic()
    ip = bruteforce.source_key(client_ip(request))  # IPv6 per /64, as the sign-in's counters
    fail_key = f"fail:{ip}"  # the same budget as wrong calendar addresses (calendar_feed)
    if calendar_feed._limited(fail_key, calendar_feed.FAIL_MAX, now, count=False):
        raise TokenError(_error(429, "rate_limited", retry=int(calendar_feed.WINDOW)))
    raw = bearer(request)
    if raw is None:
        raise TokenError(_error(401, "invalid_token"))  # no token at all: no guess, nothing counted
    row = await db.scalar(select(ApiToken).where(ApiToken.token_hash == token_hash(raw))) if TOKEN_RE.fullmatch(raw) else None
    creator = await db.get(User, row.created_by) if row is not None else None
    at = datetime.now(UTC)
    if row is None or state(row, creator, at) != "active":
        calendar_feed._limited(fail_key, calendar_feed.FAIL_MAX, now)
        raise TokenError(_error(401, "invalid_token"))
    if calendar_feed._limited(f"api:{row.id}", TOKEN_MAX, now):
        raise TokenError(_error(429, "rate_limited", retry=int(calendar_feed.WINDOW)))
    if scope not in (row.scopes or []):
        raise TokenError(_error(403, "insufficient_scope"))
    if row.last_used_at is None or at - row.last_used_at >= TOUCH_EVERY:
        row.last_used_at = at
        await db.commit()
    request.state.api_token = row
    return row


def require(scope: Scope):  # noqa: ANN201 - a FastAPI dependency
    async def dep(request: Request, db: Db) -> ApiToken:
        return await authenticate(request, db, scope)

    dep.__name__ = f"token_{scope}"
    return dep


ReadToken = Annotated[ApiToken, Depends(require("read"))]
MetricsToken = Annotated[ApiToken, Depends(require("metrics"))]


async def prune(db: AsyncSession) -> int:
    """Revoked and expired tokens go KEEP_ENDED after they ended (hourly)."""
    cut = datetime.now(UTC) - KEEP_ENDED
    res = await db.execute(delete(ApiToken).where(or_(ApiToken.revoked_at < cut, ApiToken.expires_at < cut)))
    await db.commit()
    return res.rowcount or 0


# ---------------------------------------------------------------- admin: make, list, revoke (cookie, CSRF as usual)


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def _out(row: ApiToken, creator: User | None, now: datetime) -> dict:
    return {
        "id": str(row.id),
        "name": row.name,
        "prefix": row.prefix,
        "scopes": [s for s in SCOPES if s in (row.scopes or [])],
        "created_at": _iso(row.created_at),
        "created_by": {"username": creator.username, "display_name": creator.display_name} if creator else None,
        "expires_at": _iso(row.expires_at),
        "last_used_at": _iso(row.last_used_at),
        "revoked_at": _iso(row.revoked_at),
        "expiry_added": bool(row.expiry_added),  # "never" before 0.1.42 – migration 0023 set the expiry
        "state": state(row, creator, now),
    }


async def _listing(db: AsyncSession) -> dict:
    now = datetime.now(UTC)
    rows = (await db.execute(select(ApiToken, User).outerjoin(User, User.id == ApiToken.created_by).order_by(ApiToken.created_at.desc()))).all()
    return {"items": [_out(t, u, now) for t, u in rows], "scopes": list(SCOPES), "max_active": MAX_ACTIVE, "max_days": MAX_DAYS, "default_days": DEFAULT_DAYS}


@router.get("")
async def list_tokens(admin: Admin, db: Db) -> dict:
    return await _listing(db)


class TokenIn(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=80)
    scopes: list[Scope] = Field(min_length=1, max_length=len(SCOPES))
    expires_days: int = Field(default=DEFAULT_DAYS, ge=1, le=MAX_DAYS)  # always – there is no "never" (at most a year)

    @field_validator("scopes")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        return [s for s in SCOPES if s in v]

    @field_validator("name")
    @classmethod
    def _one_line(cls, v: str) -> str:
        if any(ch in v for ch in "\r\n\t") or not v.isprintable():
            raise ValueError("one line of printable text")
        return v


@router.post("", status_code=201)
async def make_token(body: TokenIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """A new token – its value is in this answer only."""
    require_reauth(sess, admin)
    now = datetime.now(UTC)
    active = await db.scalar(
        select(func.count()).select_from(ApiToken).where(ApiToken.revoked_at.is_(None), or_(ApiToken.expires_at.is_(None), ApiToken.expires_at > now))
    )
    if int(active or 0) >= MAX_ACTIVE:
        raise api_error(409, "too_many_tokens", max=MAX_ACTIVE)
    token = PREFIX + new_token(32)
    row = ApiToken(
        id=uuid.uuid4(),
        name=body.name,
        prefix=token[:SHOWN_CHARS],
        token_hash=token_hash(token),
        scopes=list(body.scopes),
        created_by=admin.id,
        created_at=now,
        expires_at=now + timedelta(days=body.expires_days),
    )
    db.add(row)
    # the name, its scopes and validity – never the token (nor its prefix: the first characters of the secret)
    audit.record(db, admin, "token.created", audit.target("api_token", row.id, row.name), {"scopes": list(row.scopes), "expires_days": body.expires_days})
    await db.commit()
    return {"token": token, "item": _out(row, admin, now)}


@router.post("/{tid}/revoke")
async def revoke_token(tid: uuid.UUID, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """Ends a token at once (it stays listed as revoked for KEEP_ENDED)."""
    require_reauth(sess, admin)
    row = await db.get(ApiToken, tid)
    if row is None:
        raise api_error(404, "not_found")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        audit.record(db, admin, "token.revoked", audit.target("api_token", row.id, row.name), {"scopes": list(row.scopes or [])})
        await db.commit()
    return await _listing(db)


@router.get("/openapi.json")
async def openapi(admin: Admin) -> dict:
    """The curated description of what a token reaches (OpenAPI 3.1) – nothing else of the app is described anywhere."""
    from app import api_v1

    return api_v1.openapi()
