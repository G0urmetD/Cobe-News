"""Entra ID sign-in (OIDC, authorization code + PKCE) against a mocked Microsoft: token endpoint, signing keys (JWKS)
and Graph via httpx.MockTransport – no call ever leaves the test. The ID token is checked completely (signature,
issuer, audience, nonce, tenant), the state cookie binds the answer to the browser that started, groups map to roles."""

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from conftest import make_client
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from app import auth_api, db
from app.crypto import decrypt_str
from app import settings as settings_store
from app.auth import entra
from app.auth import sync as directory_sync
from app.models import User

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID = "99999999-8888-7777-6666-555555555555"
READERS = "0a0a0a0a-0000-0000-0000-000000000001"
ADMINS = "0a0a0a0a-0000-0000-0000-000000000002"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key())), "kid": "k1", "use": "sig"}


class FakeMicrosoft:
    def __init__(self):
        self.claims: dict = {}
        self.calls: list[httpx.Request] = []
        self.graph_groups = [READERS]
        self.graph_status = 200
        self.token_error: httpx.Response | None = None  # the token endpoint refusing the code exchange
        self.user = {"id": OID, "accountEnabled": True, "displayName": "Erika Muster", "userPrincipalName": "erika@corp.example"}

    def id_token(self, nonce: str) -> str:
        now = int(time.time())
        claims = {
            "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
            "aud": CLIENT,
            "tid": TENANT,
            "sub": "pairwise-sub",
            "oid": OID,
            "iat": now,
            "exp": now + 600,
            "nonce": nonce,
            "preferred_username": "Erika@corp.example",
            "name": "Erika Muster",
            "groups": [READERS],
            **self.claims,
        }
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "k1"})

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        assert req.url.host in ("login.microsoftonline.com", "graph.microsoft.com")
        if req.url.path.endswith("/oauth2/v2.0/token"):
            form = parse_qs(req.content.decode())
            if form["grant_type"] == ["client_credentials"]:
                return httpx.Response(200, json={"access_token": "app-token", "expires_in": 3600})
            if self.token_error is not None:
                return self.token_error
            assert form["code"] == ["the-code"] and form["client_secret"] == ["s3cr3t"]
            self.verifier = form["code_verifier"][0]
            return httpx.Response(200, json={"id_token": self.id_token(self.nonce), "access_token": "user-token"})
        if req.url.path.endswith("/discovery/v2.0/keys"):
            return httpx.Response(200, json={"keys": [JWK]})
        if req.url.host == "graph.microsoft.com":
            if self.graph_status != 200:
                return httpx.Response(self.graph_status, json={"error": {"code": "Authorization_RequestDenied"}})
            if "transitiveMemberOf" in req.url.path:
                return httpx.Response(200, json={"value": [{"id": g} for g in self.graph_groups]})
            if req.url.path.endswith("/groups"):
                return httpx.Response(200, json={"value": [{"id": READERS, "displayName": "News Readers"}]})
            if req.url.path.endswith(f"/users/{OID}"):
                return httpx.Response(200, json=self.user) if self.user else httpx.Response(404, json={})
        return httpx.Response(404)


@pytest.fixture
async def ms(admin_client, monkeypatch):
    fake = FakeMicrosoft()
    monkeypatch.setattr(entra, "transport", httpx.MockTransport(fake.handler))
    r = await admin_client.put("/api/admin/auth/entra", json={"enabled": True, "tenant_id": TENANT, "client_id": CLIENT.upper(), "client_secret": "s3cr3t"})
    assert r.json()["usable"]
    for gid, role in ((READERS, "reader"), (ADMINS, "admin")):
        assert (await admin_client.post("/api/admin/auth/mappings", json={"source": "entra", "group_id": gid, "group_name": role, "role": role})).status_code == 200
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    return fake


async def _sign_in(fake: FakeMicrosoft, *, tamper=None) -> tuple[httpx.Response, httpx.AsyncClient]:
    c = make_client()
    start = await c.get("/api/auth/oidc/start")
    assert start.status_code == 302
    url = urlsplit(start.headers["location"])
    q = parse_qs(url.query)
    assert url.netloc == "login.microsoftonline.com" and url.path == f"/{TENANT}/oauth2/v2.0/authorize"
    assert q["redirect_uri"] == ["https://news.corp.example:8095/api/auth/oidc/callback"] and q["code_challenge_method"] == ["S256"]
    state = q["state"][0]
    # stateless: the nonce travels encrypted in the browser's cookie, nothing is kept on the server
    fake.nonce = json.loads(decrypt_str(c.cookies.get(auth_api.OIDC_COOKIE)))["n"]
    fake.challenge = q["code_challenge"][0]
    if tamper:
        tamper(c, state)
    cb = await c.get("/api/auth/oidc/callback", params={"code": "the-code", "state": state})
    return cb, c


async def test_sign_in_with_microsoft(ms):
    cb, c = await _sign_in(ms)
    assert cb.status_code == 302 and cb.headers["location"] == "/"
    # PKCE: the verifier sent for the code belongs to the challenge of the start
    assert base64.urlsafe_b64encode(hashlib.sha256(ms.verifier.encode()).digest()).decode().rstrip("=") == ms.challenge
    me = (await c.get("/api/me")).json()
    assert me["role"] == "reader" and me["auth_source"] == "entra" and me["username"] == "erika@corp.example"
    # the state is used once
    again = await c.get("/api/auth/oidc/callback", params={"code": "the-code", "state": "x" * 20})
    assert "login_error=entra_state" in again.headers["location"]
    await c.aclose()
    # admins from Entra: only with a proof of the second factor in the token (amr: mfa) – no own TOTP step then
    ms.claims = {"groups": [ADMINS], "amr": ["pwd", "mfa"]}
    cb, c = await _sign_in(ms)
    assert (await c.get("/api/me")).json()["role"] == "admin"
    await c.aclose()
    # … without one (the usual v2.0 ID token has no amr): Cobe News' own TOTP – set up now (tests/test_auth_hardening.py)
    ms.claims = {"groups": [ADMINS]}
    cb, c = await _sign_in(ms)
    assert (await c.get("/api/auth/state")).json()["stage"] == "enroll" and (await c.get("/api/me")).status_code == 401
    await c.aclose()


async def test_groups_from_graph_when_the_claim_overflows(ms):
    ms.claims = {"groups": None, "_claim_names": {"groups": "src1"}, "amr": ["mfa"]}  # amr: an admin proves the second factor
    ms.graph_groups = [ADMINS]
    cb, c = await _sign_in(ms)
    assert (await c.get("/api/me")).json()["role"] == "admin"
    assert any("transitiveMemberOf" in r.url.path for r in ms.calls)
    await c.aclose()


@pytest.mark.parametrize(
    ("claims", "error"),
    [
        ({"aud": "someone-else"}, "entra_failed"),
        ({"iss": "https://login.microsoftonline.com/other/v2.0"}, "entra_failed"),
        ({"tid": "00000000-0000-0000-0000-000000000000"}, "entra_failed"),
        ({"exp": int(time.time()) - 3600}, "entra_failed"),
        ({"groups": ["not-mapped"]}, "directory_no_role"),
    ],
)
async def test_tokens_that_do_not_fit_are_refused(ms, claims, error):
    ms.claims = claims
    cb, c = await _sign_in(ms)
    assert cb.headers["location"] == f"/?login_error={error}"
    assert (await c.get("/api/me")).status_code == 401
    await c.aclose()


async def test_answer_bound_to_the_starting_browser_and_nonce(ms):
    # another browser's state cookie (login CSRF)
    cb, c = await _sign_in(ms, tamper=lambda cl, state: cl.cookies.set(auth_api.OIDC_COOKIE, "someone-elses-state", path="/api/auth/oidc"))
    assert "login_error=entra_state" in cb.headers["location"]
    await c.aclose()
    # a token for another sign-in (wrong nonce)
    original = ms.id_token
    ms.id_token = lambda nonce: original("other-nonce")
    cb, c = await _sign_in(ms)
    assert "login_error=entra_failed" in cb.headers["location"]
    await c.aclose()


def _token_refused(error: str, code: int, text: str) -> httpx.Response:
    return httpx.Response(401 if error == "invalid_client" else 400, json={"error": error, "error_description": f"AADSTS{code}: {text}", "error_codes": [code]})


@pytest.mark.parametrize(
    ("answer", "error"),
    [
        (_token_refused("invalid_client", 7000222, "The provided client secret keys for app 'x' are expired."), "entra_secret"),
        (_token_refused("invalid_client", 7000215, "Invalid client secret provided."), "entra_secret"),
        (_token_refused("invalid_grant", 70008, "The provided authorization code or refresh token has expired."), "entra_failed"),
    ],
)
async def test_expired_client_secret_has_its_own_error(ms, answer, error):
    # an expired or wrong client secret: nobody gets through Microsoft (sign-in and re-confirmation) – the UI says that a
    # local admin or the emergency account has to enter the new one
    ms.token_error = answer
    cb, c = await _sign_in(ms)
    assert cb.headers["location"] == f"/?login_error={error}"
    assert (await c.get("/api/me")).status_code == 401
    await c.aclose()


async def test_connection_test_group_search_and_sync(ms, admin_client):
    body = {"enabled": True, "tenant_id": TENANT, "client_id": CLIENT, "client_secret": ""}
    assert (await admin_client.post("/api/admin/auth/entra/test", json=body)).json() == {
        "ok": True,
        "groups": "ok",
        "redirect_uri": "https://news.corp.example:8095/api/auth/oidc/callback",
    }
    assert (await admin_client.get("/api/admin/auth/entra/groups", params={"q": "News"})).json()[0]["id"] == READERS
    cb, c = await _sign_in(ms)
    await c.aclose()
    # disabled in Entra: the hourly sync switches the account off and ends its sessions
    ms.user = {**ms.user, "accountEnabled": False}
    async with db.session() as s:
        assert await directory_sync.run(s) == {"deactivated": 1}
        u = await s.scalar(select(User).where(User.auth_source == "entra"))
        assert not u.is_active and u.deactivated_reason == "sync:disabled"
    # Graph refuses (permission missing): nothing changes – an outage must not lock people out
    ms.user = {**ms.user, "accountEnabled": True}
    ms.graph_status = 403
    async with db.session() as s:
        assert await directory_sync.run(s) == {}
    ms.graph_status = 200
    assert (await admin_client.post("/api/admin/auth/entra/test", json=body)).json()["groups"] == "ok"
