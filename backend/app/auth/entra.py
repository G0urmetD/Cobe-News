"""Microsoft Entra ID: OIDC sign-in (authorization code + PKCE) and the Graph calls for groups.

The ID token is verified completely: signature against the tenant's published keys, issuer, audience, expiry, tenant
and the nonce bound to this sign-in. Groups come from the token's `groups` claim; when the claim is missing or
overflows (more than 200 groups) from Graph (needs GroupMember.Read.All as an application permission).

The second factor (setting "MFA-Nachweis", `mfa_mode` of the section "entra"): Microsoft's MFA
is Conditional Access, and a policy that is missing or does not hold means the Entra password alone gets in. What the
token itself proves (`mfa_proven`): with an authentication context (`auth_context`, C1–C99) the sign-in asks for it
as an essential claim (`acrs`) and the token must carry it – Entra issues it only once the context's policy (MFA) was
met; otherwise `amr` containing "mfa" proves it, `amr` without it disproves it, no `amr` (the usual v2.0 ID token)
proves nothing. What Cobe News then asks for of its own (TOTP): auth_api.entra_stage.
"""

import base64
import hashlib
import json
import logging
import re
import secrets
import time
import uuid
from urllib.parse import urlencode

import httpx
import jwt

from app.auth.directory import DirectoryUser
from app.config import get_config
from app.crypto import decrypt_str

log = logging.getLogger("cobe_news.entra")

LOGIN = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com/v1.0"
_jwks_cache: dict[str, tuple[float, dict]] = {}
_app_tokens: dict[str, tuple[float, str]] = {}
transport: httpx.AsyncBaseTransport | None = None  # tests: a MockTransport – never Microsoft


class EntraError(Exception):
    """not_configured | auth | token | connection | http | forbidden | not_found."""

    def __init__(self, category: str, detail: str | None = None):
        super().__init__(category)
        self.category = category
        self.detail = detail


# the token endpoint refusing the app's own credentials: AADSTS7000215 a wrong client secret, AADSTS7000222 an expired one
# (both with error "invalid_client") – then nobody gets through Microsoft, not even to re-confirm and enter a new secret
SECRET_REJECTED = ("AADSTS7000215", "AADSTS7000222", '"invalid_client"')


def secret_rejected(exc: EntraError) -> bool:
    """True when the token endpoint refused the client secret (expired or wrong) – not the user's sign-in."""
    return exc.category == "auth" and any(m in (exc.detail or "") for m in SECRET_REJECTED)


def usable(cfg: dict) -> bool:
    return bool(cfg.get("tenant_id") and cfg.get("client_id") and cfg.get("client_secret_enc"))


MFA_MODES = ("entra", "context", "require")  # trust Conditional Access | the auth context must be in the token | proof or own TOTP
CONTEXT_RE = re.compile(r"^c([1-9]|[1-9][0-9])$")  # C1–C99, as in Entra


def mfa_mode(cfg: dict) -> str:
    m = cfg.get("mfa_mode")
    return m if m in MFA_MODES else "entra"


def required_context(cfg: dict) -> str | None:
    """The authentication context the token must carry – only in mode "context" and with a valid one configured."""
    ac = str(cfg.get("auth_context") or "").strip().lower()
    return ac if mfa_mode(cfg) == "context" and CONTEXT_RE.fullmatch(ac) else None


def mfa_proven(cfg: dict, claims: dict) -> bool | None:
    """True: the token proves the second factor (the required auth context, or `amr` says mfa). False: it proves the
    opposite, or the required context is missing. None: it cannot tell (no context required, no `amr`)."""
    ac = required_context(cfg)
    if ac is not None:
        acrs = claims.get("acrs")
        return isinstance(acrs, list) and ac in [str(x).lower() for x in acrs]
    if mfa_mode(cfg) == "context":
        return False  # the mode asks for a context but none (valid) is configured: nothing can prove it
    amr = claims.get("amr")
    if isinstance(amr, list):
        return "mfa" in [str(x).lower() for x in amr]
    return None


def redirect_uri() -> str:
    return get_config().base_url + "/api/auth/oidc/callback"


def http() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=10.0), follow_redirects=False, proxy=None if transport else get_config().proxy, transport=transport, trust_env=False)


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def authorize_url(cfg: dict, *, state: str, nonce: str, challenge: str, force_login: bool = False) -> str:
    """`force_login`: a re-confirmation – Microsoft asks for the sign-in again (prompt=login) and puts auth_time in the
    ID token (max_age=0); only URL parameters a browser could drop, so the callback checks auth_time itself. With an
    authentication context (mode "context"): asked for as an essential `acrs` claim of the ID token – also a parameter a
    browser could drop, so the callback checks the token for it (mfa_proven)."""
    params = {
        "client_id": cfg["client_id"],
        "response_type": "code",
        "redirect_uri": redirect_uri(),
        "response_mode": "query",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if force_login:
        params.update({"prompt": "login", "max_age": "0"})
    if (ac := required_context(cfg)) is not None:
        params["claims"] = json.dumps({"id_token": {"acrs": {"essential": True, "value": ac}}}, separators=(",", ":"))
    return f"{LOGIN}/{cfg['tenant_id']}/oauth2/v2.0/authorize?{urlencode(params)}"


def _secret(cfg: dict) -> str:
    try:
        return decrypt_str(cfg["client_secret_enc"])
    except Exception as exc:  # noqa: BLE001 - a key change: the secret has to be entered again
        raise EntraError("auth", "client secret unreadable") from exc


async def _post_token(cfg: dict, data: dict) -> dict:
    async with http() as c:
        try:
            resp = await c.post(f"{LOGIN}/{cfg['tenant_id']}/oauth2/v2.0/token", data={**data, "client_id": cfg["client_id"], "client_secret": _secret(cfg)})
        except httpx.HTTPError as exc:
            raise EntraError("connection") from exc
    if resp.status_code >= 400:
        log.warning("entra token endpoint %s: %s", resp.status_code, resp.text[:300])
        raise EntraError("auth" if resp.status_code in (400, 401) else "http", resp.text[:300])
    try:
        tok = resp.json()
    except ValueError as exc:
        raise EntraError("http") from exc
    if not isinstance(tok, dict):
        raise EntraError("http")
    return tok


async def exchange_code(cfg: dict, code: str, verifier: str) -> dict:
    return await _post_token(
        cfg, {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(), "code_verifier": verifier, "scope": "openid profile email"}
    )


async def _jwks(cfg: dict, *, refresh: bool = False) -> dict:
    cached = _jwks_cache.get(cfg["tenant_id"])
    if cached and not refresh and cached[0] > time.monotonic():
        return cached[1]
    async with http() as c:
        try:
            resp = await c.get(f"{LOGIN}/{cfg['tenant_id']}/discovery/v2.0/keys")
        except httpx.HTTPError as exc:
            raise EntraError("connection") from exc
    try:
        keys = resp.json() if resp.status_code == 200 else None
    except ValueError:
        keys = None
    if not isinstance(keys, dict) or not isinstance(keys.get("keys"), list):
        raise EntraError("http")
    _jwks_cache[cfg["tenant_id"]] = (time.monotonic() + 3600, keys)
    return keys


async def validate_id_token(cfg: dict, id_token: str, nonce: str) -> dict:
    try:
        kid = jwt.get_unverified_header(id_token).get("kid")
    except jwt.PyJWTError as exc:
        raise EntraError("token") from exc
    keys = await _jwks(cfg)
    jwk = next((k for k in keys.get("keys", []) if k.get("kid") == kid), None)
    if jwk is None:  # key rotation – fetch once more
        keys = await _jwks(cfg, refresh=True)
        jwk = next((k for k in keys.get("keys", []) if k.get("kid") == kid), None)
    if jwk is None:
        raise EntraError("token")
    try:
        claims = jwt.decode(
            id_token,
            key=jwt.PyJWK(jwk).key,
            algorithms=["RS256"],
            audience=str(cfg["client_id"]).lower(),
            issuer=f"{LOGIN}/{str(cfg['tenant_id']).lower()}/v2.0",
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            leeway=60,
        )
    except jwt.PyJWTError as exc:
        log.warning("id token rejected: %s", exc)
        raise EntraError("token") from exc
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce) or str(claims.get("tid", "")).lower() != str(cfg["tenant_id"]).lower():
        raise EntraError("token")
    return claims


async def app_token(cfg: dict, *, fresh: bool = False) -> str:
    k = "|".join((cfg["tenant_id"], cfg["client_id"], hashlib.sha256(cfg["client_secret_enc"].encode()).hexdigest()[:16]))
    cached = None if fresh else _app_tokens.get(k)
    if cached and cached[0] > time.monotonic():
        return cached[1]
    tok = await _post_token(cfg, {"grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"})
    if not isinstance(tok.get("access_token"), str):
        raise EntraError("token")
    _app_tokens[k] = (time.monotonic() + int(tok.get("expires_in") or 3600) - 120, tok["access_token"])
    return tok["access_token"]


async def graph(cfg: dict, path: str, params: dict | None = None, *, eventual: bool = False) -> dict:
    if not usable(cfg):
        raise EntraError("not_configured")
    headers = {"Authorization": f"Bearer {await app_token(cfg)}"}
    if eventual:
        headers["ConsistencyLevel"] = "eventual"
    async with http() as c:
        try:
            resp = await c.get(f"{GRAPH}{path}", params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise EntraError("connection") from exc
    if not 200 <= resp.status_code < 300:
        log.warning("graph %s -> %s %s", path, resp.status_code, resp.text[:300])
        raise EntraError({401: "auth", 403: "forbidden", 404: "not_found"}.get(resp.status_code, "http"), resp.text[:300])
    try:
        body = resp.json()
    except ValueError as exc:
        raise EntraError("http") from exc
    if not isinstance(body, dict):
        raise EntraError("http")
    return body


def _oid(v: str) -> str:
    try:
        return str(uuid.UUID(v))
    except (ValueError, TypeError) as exc:
        raise EntraError("not_found") from exc


async def user_groups(cfg: dict, oid: str) -> list[str]:
    ids: list[str] = []
    path: str | None = f"/users/{_oid(oid)}/transitiveMemberOf/microsoft.graph.group"
    params: dict | None = {"$select": "id", "$top": "999"}
    while path and len(ids) < 5000:
        body = await graph(cfg, path, params)
        ids += [g["id"] for g in body.get("value", []) if g.get("id")]
        nxt = body.get("@odata.nextLink")
        path = nxt[len(GRAPH) :] if isinstance(nxt, str) and nxt.startswith(GRAPH + "/") else None
        params = None
    return ids


async def to_directory_user(cfg: dict, claims: dict) -> DirectoryUser:
    oid = claims.get("oid") or claims["sub"]
    claim = claims.get("groups")
    overage = "groups" in (claims.get("_claim_names") or {})
    groups = [str(g) for g in claim] if isinstance(claim, list) and not overage else await user_groups(cfg, oid)
    # never the email claim as the name: it is not verified and a guest can set it (nOAuth)
    username = str(claims.get("preferred_username") or oid).lower()
    return DirectoryUser(
        source="entra",
        external_id=str(oid),
        username=username[:128],
        display_name=str(claims.get("name") or username)[:255],
        email=username if "@" in username else None,
        groups=groups,
        enabled=True,
    )


async def lookup(cfg: dict, oid: str) -> DirectoryUser | None:
    """For the hourly sync: the account and its groups – None when it is gone."""
    try:
        u = await graph(cfg, f"/users/{_oid(oid)}", {"$select": "id,accountEnabled,displayName,userPrincipalName,mail"})
    except EntraError as exc:
        if exc.category == "not_found":
            return None
        raise
    return DirectoryUser(
        source="entra",
        external_id=u["id"],
        username=str(u.get("userPrincipalName") or u["id"]).lower(),
        display_name=u.get("displayName") or "",
        email=u.get("mail"),
        groups=await user_groups(cfg, u["id"]),
        enabled=bool(u.get("accountEnabled", True)),
    )


async def test(cfg: dict) -> dict:
    """Tenant, client id and secret (an app token), and whether Graph may read groups (search, sync, group overage)."""
    if not usable(cfg):
        raise EntraError("not_configured")
    await app_token(cfg, fresh=True)
    try:
        await graph(cfg, "/groups", {"$top": "1", "$select": "id"})
        groups = "ok"
    except EntraError as exc:
        if exc.category != "forbidden":
            raise
        groups = "forbidden"
    return {"ok": True, "groups": groups, "redirect_uri": redirect_uri()}


async def search_groups(cfg: dict, q: str) -> list[dict]:
    v = q.replace('"', "").replace("\\", "").strip()[:100]
    params = {"$select": "id,displayName,description", "$top": "25", "$count": "true"}
    params |= {"$search": f'"displayName:{v}"'} if v else {"$orderby": "displayName"}
    body = await graph(cfg, "/groups", params, eventual=True)
    out = [{"id": g["id"], "name": g.get("displayName") or g["id"], "description": g.get("description") or "", "path": ""} for g in body.get("value", [])]
    return sorted(out, key=lambda g: g["name"].lower())


# ---------------------------------------------------------------- Teams: the members of a group

MEMBERS_MAX = 50_000  # one group – more is no team
MEMBER_PAGES_MAX = 60  # 999 a page: room for MEMBERS_MAX, never an endless chain of next links
MEMBER_SELECT = "id,displayName,userPrincipalName,mail,accountEnabled"


async def group_members(cfg: dict, group_id: str) -> list[DirectoryUser]:
    """Everybody in the group, nested groups too (Graph: transitiveMembers, users only), page by page. Needs the
    application permission GroupMember.Read.All (403 "forbidden" otherwise) – and User.Read.All for the members' names
    and addresses: without it Graph lists them with their id only ("user_read" – told apart here, a list of nameless
    accounts is no answer). Next links are followed only to Graph itself."""
    path: str | None = f"/groups/{_oid(group_id)}/transitiveMembers/microsoft.graph.user"
    params: dict | None = {"$select": MEMBER_SELECT, "$top": "999"}
    out: list[DirectoryUser] = []
    pages = 0
    while path:
        pages += 1
        if pages > MEMBER_PAGES_MAX:
            raise EntraError("too_many")
        body = await graph(cfg, path, params)
        for u in body.get("value", []):
            if not isinstance(u, dict) or not u.get("id"):
                continue
            kind = u.get("@odata.type")
            if kind and kind != "#microsoft.graph.user":
                continue
            upn = u.get("userPrincipalName")
            if not upn:
                raise EntraError("user_read", "members without userPrincipalName – User.Read.All missing")
            name = str(upn).lower()
            mail = u.get("mail")
            out.append(
                DirectoryUser(
                    source="entra",
                    external_id=_oid(str(u["id"])),
                    username=name[:128],
                    display_name=str(u.get("displayName") or name)[:255],
                    email=str(mail)[:255] if mail else None,
                    enabled=bool(u.get("accountEnabled", True)),
                )
            )
        if len(out) > MEMBERS_MAX:
            raise EntraError("too_many")
        nxt = body.get("@odata.nextLink")
        path = nxt[len(GRAPH) :] if isinstance(nxt, str) and nxt.startswith(GRAPH + "/") else None
        params = None
    return out
