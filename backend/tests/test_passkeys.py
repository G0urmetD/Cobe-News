"""Passkeys (WebAuthn): the strict CBOR decoder, the checks of app/auth/webauthn.py and the endpoints of
app/passkeys_api.py – driven by a software authenticator made here with `cryptography` (ES256, RS256, EdDSA)."""

import hashlib
from contextlib import aclosing
import json
import os
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from conftest import add_user, make_client, sign_in
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from sqlalchemy import select, update

from app import db, passkeys_api
from app import settings as settings_store
from app.auth import bruteforce, cbor, webauthn
from app.models import User, UserPasskey, UserSession

ORIGIN = "https://news.corp.example:8095"  # conftest's BASE_URL
RP_ID = "news.corp.example"

# ---------------------------------------------------------------- a tiny CBOR encoder and a software authenticator


def enc(v) -> bytes:  # noqa: ANN001
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError(n)

    if isinstance(v, bool):
        raise TypeError
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(enc(k) + enc(x) for k, x in v.items())
    raise TypeError(v)


b64 = webauthn.b64url


class Authenticator:
    """One credential on a pretend device: makes the attestation and the assertions a browser would hand over."""

    def __init__(self, alg: int = webauthn.ES256, *, counter: int = 0) -> None:
        self.alg = alg
        self.cred_id = os.urandom(32)
        self.counter = counter
        if alg == webauthn.ES256:
            self.key = ec.generate_private_key(ec.SECP256R1())
            n = self.key.public_key().public_numbers()
            self.cose = {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
        elif alg == webauthn.RS256:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            n = self.key.public_key().public_numbers()
            self.cose = {1: 3, 3: -257, -1: n.n.to_bytes(256, "big"), -2: n.e.to_bytes(3, "big")}
        else:
            self.key = ed25519.Ed25519PrivateKey.generate()
            from cryptography.hazmat.primitives import serialization

            raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.cose = {1: 1, 3: -8, -1: 6, -2: raw}

    def sign(self, data: bytes) -> bytes:
        if self.alg == webauthn.ES256:
            return self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        if self.alg == webauthn.RS256:
            return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return self.key.sign(data)

    @staticmethod
    def client_data(kind: str, challenge: str, origin: str = ORIGIN, **extra) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False, **extra}).encode()

    def auth_data(self, *, rp_id: str = RP_ID, flags: int = webauthn.FLAG_UP | webauthn.FLAG_UV, attested: bool = False, cose: dict | None = None) -> bytes:
        out = hashlib.sha256(rp_id.encode()).digest()
        if attested:
            flags |= webauthn.FLAG_AT
        out += bytes([flags]) + self.counter.to_bytes(4, "big")
        if attested:
            out += bytes(16) + len(self.cred_id).to_bytes(2, "big") + self.cred_id + enc(cose or self.cose)
        return out

    def attestation(self, options: dict, *, origin: str = ORIGIN, rp_id: str = RP_ID, flags: int = webauthn.FLAG_UP | webauthn.FLAG_UV, fmt: str = "none", name: str = "Laptop", **kw) -> dict:
        cd = self.client_data("webauthn.create", options["challenge"], origin)
        ad = self.auth_data(rp_id=rp_id, flags=flags, attested=True, **kw)
        stmt = {} if fmt == "none" else {"alg": self.alg, "sig": self.sign(ad + hashlib.sha256(cd).digest())}
        att = enc({"fmt": fmt, "attStmt": stmt, "authData": ad})
        return {"name": name, "id": b64(self.cred_id), "raw_id": b64(self.cred_id), "type": "public-key", "client_data_json": b64(cd), "attestation_object": b64(att), "transports": ["internal", "hybrid", "warp"]}

    def assertion(self, options: dict, user_handle: bytes | None, *, origin: str = ORIGIN, rp_id: str = RP_ID, flags: int = webauthn.FLAG_UP | webauthn.FLAG_UV, kind: str = "webauthn.get", step: int = 1) -> dict:
        self.counter += step
        cd = self.client_data(kind, options["challenge"], origin)
        ad = self.auth_data(rp_id=rp_id, flags=flags)
        sig = self.sign(ad + hashlib.sha256(cd).digest())
        return {
            "id": b64(self.cred_id),
            "raw_id": b64(self.cred_id),
            "type": "public-key",
            "client_data_json": b64(cd),
            "authenticator_data": b64(ad),
            "signature": b64(sig),
            "user_handle": b64(user_handle) if user_handle is not None else None,
        }


async def setup_done() -> None:
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()


async def register(c, auth: Authenticator, **kw) -> dict:  # noqa: ANN001
    r = await c.post("/api/me/passkeys/options")
    assert r.status_code == 200, r.text
    r = await c.post("/api/me/passkeys", json=auth.attestation(r.json(), **kw))
    return r


async def passkey_login(auth: Authenticator, user: User, **kw):  # noqa: ANN001, ANN201
    c = make_client()
    r = await c.post("/api/auth/passkey/options")
    assert r.status_code == 200, r.text
    r = await c.post("/api/auth/passkey/login", json=auth.assertion(r.json(), user.id.bytes, **kw))
    return c, r


async def _age_reauth(user_id) -> None:  # noqa: ANN001
    async with db.session() as s:
        await s.execute(update(UserSession).where(UserSession.user_id == user_id).values(reauth_at=datetime.now(UTC) - timedelta(hours=1)))
        await s.commit()


# ---------------------------------------------------------------- CBOR


def test_cbor_decodes_what_webauthn_needs():
    v = {"fmt": "none", "attStmt": {}, "authData": b"\x01\x02", 1: -7, -2: [1, 2, "x"]}
    assert cbor.decode(enc(v)) == v
    assert cbor.decode(bytes.fromhex("1bffffffffffffffff")) == 2**64 - 1
    assert cbor.decode(bytes.fromhex("3bffffffffffffffff")) == -(2**64)
    value, end = cbor.decode_prefix(enc(1) + b"\xff", 0)
    assert (value, end) == (1, 1)


@pytest.mark.parametrize(
    ("data", "why"),
    [
        (b"", "truncated"),
        (bytes.fromhex("5f"), "indefinite"),  # indefinite byte string
        (bytes.fromhex("9f01ff"), "indefinite"),  # indefinite array
        (bytes.fromhex("bf"), "indefinite"),  # indefinite map
        (bytes.fromhex("1c"), "reserved"),
        (bytes.fromhex("1a0000"), "truncated"),  # a 4-byte integer with 2 bytes
        (bytes.fromhex("5b") + (2**63).to_bytes(8, "big"), "truncated"),  # 2^63 announced bytes
        (bytes.fromhex("4401"), "truncated"),
        (bytes.fromhex("0101"), "trailing"),
        (bytes.fromhex("c11a514b67b0"), "tags"),  # tag 1 (date)
        (bytes.fromhex("f5"), "simple"),  # true
        (bytes.fromhex("f6"), "simple"),  # null
        (bytes.fromhex("fa47c35000"), "floats"),
        (bytes.fromhex("62c328"), "UTF-8"),  # invalid UTF-8
        (bytes.fromhex("a2010201 03"), "duplicate"),  # {1: 2, 1: 3}
        (bytes.fromhex("a1410102"), "key"),  # a byte-string key
        (bytes.fromhex("a1800102"), "key"),  # an array key
        (bytes.fromhex("81" * 10 + "01"), "deep"),
        (bytes.fromhex("98ff") + bytes(255), "long"),  # 255 elements
    ],
)
def test_cbor_refuses_malformed_input(data, why):
    with pytest.raises(cbor.CborError) as e:
        cbor.decode(data)
    assert why.lower() in str(e.value).lower(), str(e.value)


def test_cbor_size_limits_and_random_garbage():
    with pytest.raises(cbor.CborError):
        cbor.decode(bytes(cbor.MAX_BYTES + 1))
    with pytest.raises(cbor.CborError, match="too many items"):
        cbor.decode(bytes.fromhex("8a") + b"".join(bytes.fromhex("98") + bytes([cbor.MAX_ITEMS]) + bytes(cbor.MAX_ITEMS) for _ in range(10)))  # > MAX_TOTAL
    # fuzz-ish: random bytes and every truncation of a valid object never raise anything but CborError
    import random

    rnd = random.Random(20261031)
    good = enc({"fmt": "none", "attStmt": {}, "authData": os.urandom(80), 3: [-7, -257, {"a": b"b"}]})
    for i in range(len(good)):
        with pytest.raises(cbor.CborError):
            cbor.decode(good[:i])
    for _ in range(3000):
        blob = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 40)))
        try:
            cbor.decode(blob)
        except cbor.CborError:
            pass


# ---------------------------------------------------------------- the checks without the endpoints


def test_relying_party_from_base_url():
    assert webauthn.availability("https://news.corp.example:8095") == (webauthn.RelyingParty("news.corp.example", "https://news.corp.example:8095"), None)
    assert webauthn.availability("https://News.Corp.Example:443/")[0] == webauthn.RelyingParty("news.corp.example", "https://news.corp.example")
    assert webauthn.availability("http://localhost:8095")[0].origin == "http://localhost:8095"
    assert webauthn.availability("https://nachrichten.bücher.example")[0].rp_id == "nachrichten.xn--bcher-kva.example"
    assert webauthn.availability("https://192.0.2.10:8095") == (None, "ip_host")
    assert webauthn.availability("https://[2001:db8::1]") == (None, "ip_host")
    assert webauthn.availability("http://news.corp.example") == (None, "not_https")
    assert webauthn.availability("https://news.corp.example:99999") == (None, "bad_host")


def test_strict_base64url():
    assert webauthn.unb64url(b64(b"\x00\xff\xfe"), limit=3) == b"\x00\xff\xfe"
    for bad in ("AA==", "A", "AB", "a+b/", "AA AA", "ä"):
        with pytest.raises(webauthn.WebAuthnError):
            webauthn.unb64url(bad, limit=100)
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.unb64url(b64(bytes(10)), limit=9)


@pytest.mark.parametrize("alg", [webauthn.ES256, webauthn.RS256, webauthn.EDDSA])
def test_ceremonies_with_each_algorithm(alg):
    rp, _ = webauthn.availability()
    a = Authenticator(alg)
    ch = os.urandom(32)
    body = a.attestation({"challenge": b64(ch)})
    new = webauthn.verify_registration(
        rp, ch, raw_id=a.cred_id, client_data_json=webauthn.unb64url(body["client_data_json"], limit=4096), attestation_object=webauthn.unb64url(body["attestation_object"], limit=8192)
    )
    assert new.algorithm == alg and new.credential_id == a.cred_id and cbor.decode(new.public_key) == a.cose
    ch2 = os.urandom(32)
    got = a.assertion({"challenge": b64(ch2)}, None)
    args = {k: webauthn.unb64url(got[k], limit=4096) for k in ("client_data_json", "authenticator_data", "signature")}
    assert webauthn.verify_assertion(rp, ch2, public_key=new.public_key, client_data_json=args["client_data_json"], authenticator_data=args["authenticator_data"], signature=args["signature"]) == 1
    with pytest.raises(webauthn.WebAuthnError, match="challenge"):
        webauthn.verify_assertion(rp, ch, public_key=new.public_key, client_data_json=args["client_data_json"], authenticator_data=args["authenticator_data"], signature=args["signature"])
    with pytest.raises(webauthn.WebAuthnError, match="signature"):
        webauthn.verify_assertion(rp, ch2, public_key=new.public_key, client_data_json=args["client_data_json"], authenticator_data=args["authenticator_data"], signature=args["signature"][:-1] + bytes([args["signature"][-1] ^ 1]))  # one bit flipped: a changed signature (setting the byte to 0 was no change in 1 of 16 EdDSA runs)


def test_key_and_attestation_checks():
    rp, _ = webauthn.availability()
    a = Authenticator()
    # a point not on the curve, a private part along, a small RSA key, an unknown algorithm
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.load_key({**a.cose, -3: bytes(32)})
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.load_key({**a.cose, -4: b"\x01" * 32})
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_numbers()
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.load_key({1: 3, 3: -257, -1: small.n.to_bytes(128, "big"), -2: b"\x01\x00\x01"})
    with pytest.raises(webauthn.WebAuthnError, match="algorithm"):
        webauthn.load_key({**a.cose, 3: -35})
    ch = os.urandom(32)

    def reg(body: dict) -> None:
        webauthn.verify_registration(
            rp, ch, raw_id=a.cred_id, client_data_json=webauthn.unb64url(body["client_data_json"], limit=4096), attestation_object=webauthn.unb64url(body["attestation_object"], limit=8192)
        )

    reg(a.attestation({"challenge": b64(ch)}, fmt="packed"))  # self-attestation: signed with the new key
    cd = a.client_data("webauthn.create", b64(ch))
    ad = a.auth_data(attested=True)
    for att in (
        {"fmt": "packed", "attStmt": {"alg": -7, "sig": a.sign(ad + hashlib.sha256(cd).digest()), "x5c": [b"cert"]}, "authData": ad},
        {"fmt": "packed", "attStmt": {"alg": -7, "sig": b"\x30\x00"}, "authData": ad},
        {"fmt": "fido-u2f", "attStmt": {}, "authData": ad},
        {"fmt": "none", "attStmt": {"x": 1}, "authData": ad},
        {"fmt": "none", "attStmt": {}, "authData": ad + b"\x00"},  # trailing bytes after the key
        {"fmt": "none", "attStmt": {}, "authData": ad, "extra": 1},
    ):
        with pytest.raises(webauthn.WebAuthnError):
            reg({"client_data_json": b64(cd), "attestation_object": b64(enc(att))})
    # client data: duplicate keys, inside a frame, wrong type
    for bad in (
        b'{"type":"webauthn.create","type":"webauthn.create","challenge":"' + b64(ch).encode() + b'","origin":"' + ORIGIN.encode() + b'"}',
        a.client_data("webauthn.create", b64(ch), crossOrigin=True),
        a.client_data("webauthn.create", b64(ch), topOrigin="https://evil.example"),
        a.client_data("webauthn.get", b64(ch)),
        b"[]",
        b"\xff",
    ):
        with pytest.raises(webauthn.WebAuthnError):
            webauthn.check_client_data(bad, "webauthn.create", ch, rp)


def test_counter_regression_rule():
    assert not webauthn.counter_regressed(0, 0)  # synced passkeys
    assert not webauthn.counter_regressed(5, 6)
    assert webauthn.counter_regressed(5, 5) and webauthn.counter_regressed(5, 3) and webauthn.counter_regressed(5, 0)
    assert not webauthn.counter_regressed(0, 1)


# ---------------------------------------------------------------- registration and sign-in through the API


@pytest.mark.parametrize("alg", [webauthn.ES256, webauthn.RS256])
async def test_register_and_sign_in_with_a_passkey(reader_client, alg):
    await setup_done()
    a = Authenticator(alg)
    r = await register(reader_client, a)
    assert r.status_code == 200, r.text
    pk = r.json()
    assert pk["name"] == "Laptop" and pk["transports"] == ["hybrid", "internal"] and pk["last_used_at"] is None
    listed = (await reader_client.get("/api/me/passkeys")).json()
    assert [p["id"] for p in listed] == [pk["id"]]
    async with db.session() as s:
        row = await s.get(UserPasskey, __import__("uuid").UUID(pk["id"]))
        assert row.credential_id == a.cred_id and cbor.decode(row.public_key) == a.cose
    c, r = await passkey_login(a, reader_client.user)
    async with aclosing(c):
        assert r.status_code == 200, r.text
        assert r.json()["next"] == "done" and r.json()["user"]["username"] == "rudi"
        me = await c.get("/api/me/sessions")
        cur = [s for s in me.json() if s["current"]][0]
        assert cur["method"] == "passkey" and cur["passkey"] == "Laptop"
        # a passkey sign-in is a fresh proof of identity (two factors)
        assert (await c.post("/api/me/passkeys/options")).status_code == 200
    listed = (await reader_client.get("/api/me/passkeys")).json()
    assert listed[0]["last_used_at"] is not None and listed[0]["sign_count_warning_at"] is None


async def test_registration_options_ask_for_user_verification_and_no_attestation(reader_client):
    o = (await reader_client.post("/api/me/passkeys/options")).json()
    assert o["rp"] == {"id": RP_ID, "name": "Cobe News"} and o["attestation"] == "none"
    assert o["authenticatorSelection"] == {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"}
    assert [p["alg"] for p in o["pubKeyCredParams"]] == [-7, -8, -257]
    assert webauthn.unb64url(o["user"]["id"], limit=64) == reader_client.user.id.bytes
    a = Authenticator()
    assert (await reader_client.post("/api/me/passkeys", json=a.attestation(o))).status_code == 200
    o = (await reader_client.post("/api/me/passkeys/options")).json()
    assert [x["id"] for x in o["excludeCredentials"]] == [b64(a.cred_id)]


@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        ({"origin": "https://news.corp.example.evil.example"}, "origin"),
        ({"origin": "https://news.corp.example"}, "origin"),  # the port belongs to the origin
        ({"rp_id": "evil.example"}, "rp_id"),
        ({"flags": webauthn.FLAG_UP}, "user_verification"),
        ({"flags": webauthn.FLAG_UV}, "user_presence"),
        ({"flags": webauthn.FLAG_UP | webauthn.FLAG_UV | webauthn.FLAG_BS}, "auth_data"),
    ],
)
async def test_registration_refused(reader_client, kw, reason):
    r = await register(reader_client, Authenticator(), **kw)
    assert r.status_code == 400 and r.json()["detail"] == {"code": "passkey_invalid", "reason": reason}
    assert (await reader_client.get("/api/me/passkeys")).json() == []


async def test_registration_challenge_is_single_use_bound_and_expires(reader_client):
    a = Authenticator()
    o = (await reader_client.post("/api/me/passkeys/options")).json()
    body = a.attestation(o)
    # another session of the same person cannot use this session's challenge
    async with make_client() as other:
        await sign_in(other, reader_client.user)
        r = await other.post("/api/me/passkeys", json=body)
        assert r.status_code == 409 and r.json()["detail"]["code"] == "passkey_expired"
    assert (await reader_client.post("/api/me/passkeys", json=body)).status_code == 200
    # the same answer again: the challenge is gone
    assert (await reader_client.post("/api/me/passkeys", json=body)).json()["detail"]["code"] == "passkey_expired"
    # expired
    o = (await reader_client.post("/api/me/passkeys/options")).json()
    for p in passkeys_api._register.values():
        p.expires = 0
    assert (await reader_client.post("/api/me/passkeys", json=Authenticator().attestation(o))).json()["detail"]["code"] == "passkey_expired"
    # a wrong challenge
    await reader_client.post("/api/me/passkeys/options")
    r = await reader_client.post("/api/me/passkeys", json=Authenticator().attestation({"challenge": b64(os.urandom(32))}))
    assert r.json()["detail"] == {"code": "passkey_invalid", "reason": "challenge"}


async def test_same_credential_twice_and_limit(reader_client):
    a = Authenticator()
    assert (await register(reader_client, a)).status_code == 200
    r = await register(reader_client, a)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "passkey_exists"
    for _ in range(passkeys_api.MAX_PER_USER - 1):
        assert (await register(reader_client, Authenticator())).status_code == 200
    r = await reader_client.post("/api/me/passkeys/options")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "passkey_limit"


async def test_name_is_checked(reader_client):
    o = (await reader_client.post("/api/me/passkeys/options")).json()
    for name in ("", "x" * 65, "a\nb"):
        assert (await reader_client.post("/api/me/passkeys", json=Authenticator().attestation(o, name=name))).status_code == 422


async def test_adding_and_removing_need_reauth(reader_client):
    a = Authenticator()
    o = (await reader_client.post("/api/me/passkeys/options")).json()
    await _age_reauth(reader_client.user.id)
    r = await reader_client.post("/api/me/passkeys", json=a.attestation(o))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    r = await reader_client.post("/api/me/passkeys/options")
    assert r.status_code == 403 and r.json()["detail"] == {"code": "reauth_required", "via": "password", "totp": False}
    from conftest import PASSWORD

    assert (await reader_client.post("/api/auth/reauth", json={"password": PASSWORD})).status_code == 200
    pk = (await register(reader_client, a)).json()
    # renaming is no sensitive action
    await _age_reauth(reader_client.user.id)
    assert (await reader_client.patch(f"/api/me/passkeys/{pk['id']}", json={"name": "Handy"})).json()["name"] == "Handy"
    r = await reader_client.delete(f"/api/me/passkeys/{pk['id']}")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    await reader_client.post("/api/auth/reauth", json={"password": PASSWORD})
    assert (await reader_client.delete(f"/api/me/passkeys/{pk['id']}")).json() == {"ok": True, "sessions_ended": 0}


async def test_directory_accounts_cannot_register():
    for source in ("ldap", "entra"):
        async with db.session() as s:
            u = User(username=f"jdoe-{source}", display_name="J", role="reader", auth_source=source, external_id=f"id-{source}")
            s.add(u)
            await s.commit()
        async with make_client() as c:
            await sign_in(c, u)
            for r in (await c.post("/api/me/passkeys/options"), await c.post("/api/me/passkeys", json=Authenticator().attestation({"challenge": b64(os.urandom(32))}))):
                assert r.status_code == 409 and r.json()["detail"]["code"] == "not_local_account"


async def test_passkeys_switched_off_or_unavailable(reader_client, admin_client, monkeypatch):
    await setup_done()
    a = Authenticator()
    await register(reader_client, a)
    r = await admin_client.put("/api/admin/auth/passkeys", json={"enabled": False, "rev": 0})
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["rp_id"] == RP_ID
    assert (await admin_client.get("/api/auth/config")).json()["passkeys"] == {"enabled": False, "available": True, "reason": None, "origin": ORIGIN}
    assert (await reader_client.post("/api/me/passkeys/options")).json()["detail"]["code"] == "passkeys_disabled"
    async with make_client() as c:
        assert (await c.post("/api/auth/passkey/options")).json()["detail"]["code"] == "passkeys_disabled"
    assert len((await reader_client.get("/api/me/passkeys")).json()) == 1  # kept, listed
    await admin_client.put("/api/admin/auth/passkeys", json={"enabled": True, "rev": 1})
    c, r = await passkey_login(a, reader_client.user)
    await c.aclose()
    assert r.status_code == 200
    # an IP address as host: no RP ID possible
    monkeypatch.setattr(webauthn, "get_config", lambda: type("C", (), {"base_url": "https://192.0.2.10:8095"})())
    assert (await admin_client.get("/api/auth/config")).json()["passkeys"]["reason"] == "ip_host"
    r = await reader_client.post("/api/me/passkeys/options")
    assert r.status_code == 409 and r.json()["detail"] == {"code": "passkey_unavailable", "reason": "ip_host"}


async def test_admin_setting_needs_reauth(admin_client):
    await _age_reauth(admin_client.user.id)
    r = await admin_client.put("/api/admin/auth/passkeys", json={"enabled": False})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"


# ---------------------------------------------------------------- sign-in refusals


@pytest.mark.parametrize(
    ("kw", "why"),
    [
        ({"origin": "https://evil.example"}, "origin"),
        ({"rp_id": "evil.example"}, "rp_id"),
        ({"flags": webauthn.FLAG_UP}, "uv missing"),
        ({"kind": "webauthn.create"}, "type"),
    ],
)
async def test_sign_in_refused(reader_client, kw, why):
    await setup_done()
    a = Authenticator()
    await register(reader_client, a)
    c, r = await passkey_login(a, reader_client.user, **kw)
    async with aclosing(c):
        assert r.status_code == 401 and r.json()["detail"] == {"code": "passkey_failed"}, why
        assert (await c.get("/api/me")).status_code == 401


async def test_sign_in_challenge_single_use_bound_and_expiring(reader_client):
    await setup_done()
    a = Authenticator()
    await register(reader_client, a)
    async with make_client() as c, make_client() as other:
        o = (await c.post("/api/auth/passkey/options")).json()
        body = a.assertion(o, reader_client.user.id.bytes)
        # another browser (no flow cookie) cannot use it
        await other.post("/api/auth/passkey/options")
        r = await other.post("/api/auth/passkey/login", json=body)
        assert r.status_code == 401 and r.json()["detail"]["code"] == "passkey_failed"  # its own challenge differs
        assert (await c.post("/api/auth/passkey/login", json=body)).status_code == 200
        # replayed: the challenge is gone
        c.cookies.set(passkeys_api.COOKIE, "replay", path=passkeys_api.COOKIE_PATH)
        r = await c.post("/api/auth/passkey/login", json=body)
        assert r.status_code == 400 and r.json()["detail"]["code"] == "passkey_expired"
    async with make_client() as c:
        o = (await c.post("/api/auth/passkey/options")).json()
        for p in passkeys_api._login.values():
            p.expires = 0
        r = await c.post("/api/auth/passkey/login", json=a.assertion(o, reader_client.user.id.bytes))
        assert r.status_code == 400 and r.json()["detail"]["code"] == "passkey_expired"


async def test_wrong_user_handle_unknown_credential_and_blocked_account(reader_client):
    await setup_done()
    a = Authenticator()
    await register(reader_client, a)
    other = await add_user("otto")
    c, r = await passkey_login(a, other)  # the handle of another account
    await c.aclose()
    assert r.status_code == 401
    async with make_client() as c:
        o = (await c.post("/api/auth/passkey/options")).json()
        r = await c.post("/api/auth/passkey/login", json={**a.assertion(o, reader_client.user.id.bytes), "user_handle": None})
        assert r.status_code == 401
    c, r = await passkey_login(Authenticator(), reader_client.user)  # never registered
    await c.aclose()
    assert r.status_code == 401
    async with db.session() as s:
        await s.execute(update(User).where(User.id == reader_client.user.id).values(is_active=False))
        await s.commit()
    c, r = await passkey_login(a, reader_client.user)
    await c.aclose()
    assert r.status_code == 401 and r.json()["detail"]["code"] == "passkey_failed"


async def test_sign_count_regression_warns_but_does_not_lock(reader_client, caplog):
    await setup_done()
    a = Authenticator(counter=10)
    await register(reader_client, a)
    c, r = await passkey_login(a, reader_client.user)  # 11
    await c.aclose()
    assert r.status_code == 200
    async with db.session() as s:
        assert (await s.scalar(select(UserPasskey))).sign_count == 11
    a.counter = 5  # a clone with an older counter
    c, r = await passkey_login(a, reader_client.user)
    await c.aclose()
    assert r.status_code == 200
    assert "possibly a cloned authenticator" in caplog.text
    async with db.session() as s:
        row = await s.scalar(select(UserPasskey))
        assert row.sign_count == 11 and row.sign_count_warning_at is not None
    assert (await reader_client.get("/api/me/passkeys")).json()[0]["sign_count_warning_at"]
    # synced passkeys: 0 every time is fine
    b = Authenticator()
    await register(reader_client, b)
    for _ in range(2):
        c, r = await passkey_login(b, reader_client.user, step=0)
        await c.aclose()
        assert r.status_code == 200
    async with db.session() as s:
        assert (await s.scalar(select(UserPasskey).where(UserPasskey.credential_id == b.cred_id))).sign_count_warning_at is None


async def test_admin_without_totp_sets_it_up_after_a_passkey_and_temp_password_first():
    await setup_done()
    anna = await add_user("anna", "admin", totp_secret=pyotp.random_base32())
    a = Authenticator()
    async with make_client() as c:
        await sign_in(c, anna)
        assert (await register(c, a)).status_code == 200
    async with db.session() as s:
        await s.execute(update(User).where(User.id == anna.id).values(totp_secret_enc=None))
        await s.commit()
    c, r = await passkey_login(a, anna)
    await c.aclose()
    assert r.json() == {"next": "enroll"}
    async with db.session() as s:
        await s.execute(update(User).where(User.id == anna.id).values(must_change_password=True))
        await s.commit()
    c, r = await passkey_login(a, anna)
    await c.aclose()
    assert r.json() == {"next": "password"}


async def test_sign_in_rate_limits(reader_client, monkeypatch):
    await setup_done()
    a = Authenticator()
    await register(reader_client, a)
    async with make_client() as c:
        for _ in range(passkeys_api.PER_IP):
            assert (await c.post("/api/auth/passkey/options")).status_code == 200
        r = await c.post("/api/auth/passkey/options")
        assert r.status_code == 429 and r.json()["detail"]["code"] == "too_many_attempts"
    passkeys_api.reset()
    # refused sign-ins count on the address like wrong passwords: random credential ids are many names → blocked
    monkeypatch.setattr(passkeys_api, "PER_IP", 1000)
    async with make_client() as c:
        for _ in range(bruteforce.IP_MAX):
            o = (await c.post("/api/auth/passkey/options")).json()
            await c.post("/api/auth/passkey/login", json=Authenticator().assertion(o, reader_client.user.id.bytes))
        r = await c.post("/api/auth/passkey/options")
        assert r.status_code == 403 and r.json()["detail"]["code"] == "ip_blocked"
    # an account lock from wrong passwords does not stop the passkey (it cannot be guessed)
    bruteforce.reset()
    for _ in range(bruteforce.ACCOUNT_MAX):
        bruteforce.register_failure(bruteforce.local_key("rudi"), "198.51.100.7")
    assert bruteforce.locked_for(bruteforce.local_key("rudi"))
    c, r = await passkey_login(a, reader_client.user)
    await c.aclose()
    assert r.status_code == 200


async def test_pending_sign_ins_are_capped(monkeypatch):
    await setup_done()
    monkeypatch.setattr(passkeys_api, "MAX_PENDING", 3)
    monkeypatch.setattr(passkeys_api, "PER_IP", 100)
    async with make_client() as c:
        for _ in range(3):
            c.cookies.clear()
            assert (await c.post("/api/auth/passkey/options")).status_code == 200
        c.cookies.clear()
        r = await c.post("/api/auth/passkey/options")
        assert r.status_code == 429 and r.json()["detail"]["code"] == "passkey_busy"


# ---------------------------------------------------------------- removal and the admins' view


async def test_removing_a_passkey_ends_its_sessions(reader_client):
    await setup_done()
    a = Authenticator()
    pk = (await register(reader_client, a)).json()
    c, r = await passkey_login(a, reader_client.user)
    async with aclosing(c):
        assert (await c.get("/api/me")).status_code == 200
        assert (await reader_client.delete(f"/api/me/passkeys/{pk['id']}")).json() == {"ok": True, "sessions_ended": 1}
        assert (await c.get("/api/me")).status_code == 401  # at once
    assert (await reader_client.get("/api/me")).status_code == 200  # the one that removed it goes on


async def test_admin_sees_and_removes_a_users_passkeys(reader_client, admin_client):
    await setup_done()
    a = Authenticator()
    pk = (await register(reader_client, a)).json()
    uid = reader_client.user.id
    assert [p["id"] for p in (await admin_client.get(f"/api/admin/users/{uid}/passkeys")).json()] == [pk["id"]]
    assert [u["passkeys"] for u in (await admin_client.get("/api/admin/users")).json() if u["username"] == "rudi"] == [1]
    assert (await reader_client.get(f"/api/admin/users/{uid}/passkeys")).status_code == 403
    # another person's passkey through the own endpoint: not found
    other = await add_user("otto")
    async with make_client() as oc:
        await sign_in(oc, other)
        assert (await oc.delete(f"/api/me/passkeys/{pk['id']}")).status_code == 404
        assert (await oc.patch(f"/api/me/passkeys/{pk['id']}", json={"name": "x"})).status_code == 404
    c, _ = await passkey_login(a, reader_client.user)
    async with aclosing(c):
        await _age_reauth(admin_client.user.id)
        r = await admin_client.delete(f"/api/admin/users/{uid}/passkeys/{pk['id']}")
        assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
        async with db.session() as s:
            await s.execute(update(UserSession).where(UserSession.user_id == admin_client.user.id).values(reauth_at=datetime.now(UTC)))
            await s.commit()
        assert (await admin_client.delete(f"/api/admin/users/{other.id}/passkeys/{pk['id']}")).status_code == 404
        assert (await admin_client.delete(f"/api/admin/users/{uid}/passkeys/{pk['id']}")).json() == {"ok": True, "sessions_ended": 1}
        assert (await c.get("/api/me")).status_code == 401
    assert (await reader_client.get("/api/me")).status_code == 200  # signed in with the password: goes on
    c, r = await passkey_login(a, reader_client.user)
    await c.aclose()
    assert r.status_code == 401


async def test_passkeys_go_with_the_account(reader_client, admin_client):
    await register(reader_client, Authenticator())
    assert (await admin_client.delete(f"/api/admin/users/{reader_client.user.id}")).status_code == 200
    async with db.session() as s:
        assert list(await s.scalars(select(UserPasskey))) == []


# ---------------------------------------------------------------- fixes of the security review (passkey-fixes)


async def _version(uid) -> int:  # noqa: ANN001
    async with db.session() as s:
        return (await s.get(User, uid)).version or 1


async def test_a_password_reset_removes_the_passkeys(reader_client, admin_client):
    """A reset after a takeover must leave no way in the other person set up: with the password the passkeys go
    (ResetIn.passkeys, by default as `password`); a TOTP-only reset keeps them, unless asked."""
    from app.models import AuditEntry

    await setup_done()
    a = Authenticator()
    await register(reader_client, a)
    uid = reader_client.user.id
    r = await admin_client.post(f"/api/admin/users/{uid}/reset", json={"password": False, "totp": True, "version": await _version(uid)})
    assert r.status_code == 200 and r.json()["passkeys_removed"] == 0
    c, r = await passkey_login(a, reader_client.user)
    await c.aclose()
    assert r.status_code == 200  # TOTP only: the passkey stays
    r = await admin_client.post(f"/api/admin/users/{uid}/reset", json={"password": True, "passkeys": False, "version": await _version(uid)})
    assert r.json()["passkeys_removed"] == 0
    r = await admin_client.post(f"/api/admin/users/{uid}/reset", json={"password": True, "version": await _version(uid)})
    assert r.status_code == 200 and r.json()["passkeys_removed"] == 1 and r.json()["temp_password"]
    c, r = await passkey_login(a, reader_client.user)
    await c.aclose()
    assert r.status_code == 401
    async with db.session() as s:
        assert list(await s.scalars(select(UserPasskey))) == []
        e = (await s.scalars(select(AuditEntry).where(AuditEntry.action == "passkey.removed"))).one()
        assert e.details == {"by_admin": True, "reset": True, "count": 1} and e.actor_id == admin_client.user.id


async def test_cli_reset_emergency_removes_the_passkeys(capsys):
    from app import cli
    from app.models import AuditEntry

    await setup_done()
    u = await add_user("notfall", "admin", totp_secret=pyotp.random_base32(), emergency=True)
    a = Authenticator()
    async with make_client() as c:
        await sign_in(c, u)
        assert (await register(c, a)).status_code == 200
    assert await cli._account("reset-emergency") == 0
    assert "1 passkey(s) removed" in capsys.readouterr().out
    c, r = await passkey_login(a, u)
    await c.aclose()
    assert r.status_code == 401
    async with db.session() as s:
        assert list(await s.scalars(select(UserPasskey))) == []
        e = (await s.scalars(select(AuditEntry).where(AuditEntry.action == "passkey.removed"))).one()
        assert e.actor_kind == "cli" and e.details["reset"] is True and e.details["count"] == 1


async def test_a_cose_algorithm_that_is_no_integer_is_refused_not_a_500(reader_client):
    for alg in ([], {}, "ES256", b"\x07"):
        with pytest.raises(webauthn.WebAuthnError) as exc:
            webauthn.load_key(enc({1: 2, 3: alg, -1: 1, -2: bytes(32), -3: bytes(32)}))
        assert exc.value.code == "algorithm"
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.load_key({1: 2, 3: True})  # a bool is no algorithm (True == 1)
    a = Authenticator()
    r = await register(reader_client, a, cose={**a.cose, 3: []})
    assert r.status_code == 400 and r.json()["detail"] == {"code": "passkey_invalid", "reason": "algorithm"}


async def test_one_ipv6_48_cannot_fill_the_pending_sign_ins(monkeypatch):
    """Per /64 at most PER_IP starts – but one site has thousands of /64s: per /48 at most PER_NET, so one network never
    holds more than PER_NET of the MAX_PENDING sign-ins under way."""
    from app import netaddr

    await setup_done()
    monkeypatch.setattr(netaddr, "container_gateway", lambda: None)
    t = 1000.0
    for n in range(passkeys_api.PER_NET):
        assert passkeys_api._start_ok(f"2001:db8:7:{n:x}::1", t)  # a fresh /64 each time
    assert not passkeys_api._start_ok("2001:db8:7:ffff::1", t)  # the /48 is used up
    assert passkeys_api._start_ok("2001:db8:8::1", t)  # the next /48 is someone else
    assert passkeys_api._start_ok("198.51.100.7", t) and passkeys_api._start_ok("::ffff:198.51.100.8", t)  # IPv4: per address
    assert passkeys_api._start_ok("2001:db8:7:ffff::1", t + passkeys_api.WINDOW)  # the window moves on
    # refused at the /48 limit, the /64 is not charged
    assert len(passkeys_api._starts[bruteforce.source_key("2001:db8:7:ffff::1")]) == 1
    # on the wire
    passkeys_api.reset()
    monkeypatch.setattr(passkeys_api, "PER_NET", 2)
    for n, want in ((1, 200), (2, 200), (3, 429)):
        async with make_client(client=(f"2001:db8:9:{n}::1", 5000)) as c:
            r = await c.post("/api/auth/passkey/options")
            assert r.status_code == want, r.text


async def test_one_account_holds_only_a_few_pending_registrations(reader_client):
    """A person signing in again and again (each sign-in a session with its own registration slot) cannot fill
    MAX_PENDING for everybody else."""
    clients = []
    try:
        for _ in range(passkeys_api.REGISTER_PER_USER):
            c = make_client()
            clients.append(c)
            await sign_in(c, reader_client.user)
            assert (await c.post("/api/me/passkeys/options")).status_code == 200
        r = await reader_client.post("/api/me/passkeys/options")
        assert r.status_code == 429 and r.json()["detail"]["code"] == "passkey_busy"
        assert (await clients[0].post("/api/me/passkeys/options")).status_code == 200  # its own slot is replaced, not added
        other = await add_user("otto")
        async with make_client() as oc:
            await sign_in(oc, other)
            assert (await oc.post("/api/me/passkeys/options")).status_code == 200  # another account is not held up
    finally:
        for c in clients:
            await c.aclose()
