"""WebAuthn (passkeys) – the server's checks, with nothing but `cryptography` (W3C Web Authentication Level 3, §7).

What is accepted:
- **Relying party.** The RP ID is the host of BASE_URL (IDNA, lower case), the one origin accepted is BASE_URL's
  scheme://host[:port] (default port left out, as browsers write it). An IP address cannot be an RP ID (browsers refuse
  it) and WebAuthn needs a secure context: plain http only for "localhost". Otherwise passkeys are unavailable
  (`availability` says why). Changing the host name of BASE_URL makes every registered passkey useless – they are bound
  to the old RP ID.
- **Client data.** JSON (duplicate keys refused), `type` webauthn.create / webauthn.get, the challenge (single-use, from
  the caller), the origin exactly, no cross-origin (iframe) ceremony.
- **Authenticator data.** The SHA-256 of the RP ID, user presence (UP) **and** user verification (UV – PIN or
  biometrics on the device: the passkey then stands for two factors, possession and knowledge/biometrics), backup state
  only with backup eligibility, no trailing bytes; registration with attested credential data, an assertion without.
- **Attestation.** We ask for "none" and accept "none" (an empty statement) or "packed" self-attestation (alg and sig,
  no certificate – the signature is made with the new key itself and checked). Any other format is refused: we neither
  need nor check who made the authenticator.
- **Keys** (COSE_Key, only the labels the algorithm needs): ES256 (-7, P-256, the point checked to lie on the curve),
  EdDSA (-8, Ed25519) and RS256 (-257, RSA with 2048–8192 bit modulus).
- **Signatures** over authenticator data ‖ SHA-256(client data).

What the caller keeps: the credential id, the COSE key as the authenticator sent it, the signature counter.
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from app.auth import cbor
from app.config import get_config

ES256, EDDSA, RS256 = -7, -8, -257
ALGORITHMS = (ES256, EDDSA, RS256)  # in the order offered (pubKeyCredParams)
FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80
MAX_CREDENTIAL_ID = 1023  # the spec's limit
MAX_CLIENT_DATA = 4096
MAX_AUTH_DATA = 4096
MAX_ATTESTATION = 8192
MAX_SIGNATURE = 1024
RSA_MIN_BITS, RSA_MAX_BITS = 2048, 8192
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class WebAuthnError(Exception):
    """A ceremony refused – `code` names the check (logs, tests; the client only learns that it failed)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# ---------------------------------------------------------------- base64url


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value: str, *, limit: int) -> bytes:
    """Strict base64url without padding (as WebAuthn and browsers write it): any other character, a length no encoding
    has, a non-canonical last character or more than `limit` bytes → WebAuthnError("encoding")."""
    if not isinstance(value, str) or len(value) > (limit * 4 + 2) // 3 or not _B64URL.fullmatch(value) or len(value) % 4 == 1:
        raise WebAuthnError("encoding")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64url(raw) != value:  # unused bits set in the last character: not the one encoding of these bytes
        raise WebAuthnError("encoding")
    return raw


# ---------------------------------------------------------------- relying party


@dataclass(frozen=True)
class RelyingParty:
    rp_id: str
    origin: str

    @property
    def id_hash(self) -> bytes:
        return hashlib.sha256(self.rp_id.encode("ascii")).digest()


def availability(base_url: str | None = None) -> tuple[RelyingParty | None, str | None]:
    """The relying party of BASE_URL – or None and why not: no_host | ip_host | bad_host | not_https."""
    try:
        url = urlsplit(base_url if base_url is not None else get_config().base_url)
        host = (url.hostname or "").strip().rstrip(".").lower()
        port = url.port
    except ValueError:
        return None, "bad_host"
    if not host:
        return None, "no_host"
    try:
        ipaddress.ip_address(host)
        return None, "ip_host"
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None, "bad_host"
    scheme = url.scheme.lower()
    if scheme != "https" and not (scheme == "http" and host == "localhost"):
        return None, "not_https"
    default = 443 if scheme == "https" else 80
    origin = f"{scheme}://{host}" + (f":{port}" if port is not None and port != default else "")
    return RelyingParty(rp_id=host, origin=origin), None


# ---------------------------------------------------------------- client data


def _no_duplicates(pairs: list) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise WebAuthnError("client_data")
        out[k] = v
    return out


def check_client_data(raw: bytes, kind: str, challenge: bytes, rp: RelyingParty) -> bytes:
    """The client data of a ceremony checked – its SHA-256 (what the authenticator signed along)."""
    if not raw or len(raw) > MAX_CLIENT_DATA:
        raise WebAuthnError("client_data")
    try:
        data = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError):
        raise WebAuthnError("client_data") from None
    if not isinstance(data, dict):
        raise WebAuthnError("client_data")
    if data.get("type") != kind:
        raise WebAuthnError("type")
    sent = data.get("challenge")
    try:
        got = unb64url(sent, limit=256) if isinstance(sent, str) else b""
    except WebAuthnError:
        got = b""
    if not got or not hmac.compare_digest(got, challenge):
        raise WebAuthnError("challenge")
    if data.get("origin") != rp.origin:
        raise WebAuthnError("origin")
    # inside a frame of another site (crossOrigin true, topOrigin set): never – the sign-in page is not embeddable anyway
    if data.get("crossOrigin") not in (None, False) or "topOrigin" in data:
        raise WebAuthnError("cross_origin")
    return hashlib.sha256(raw).digest()


# ---------------------------------------------------------------- authenticator data and keys


@dataclass(frozen=True)
class AuthData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: bytes | None = None
    public_key: bytes | None = None  # the COSE_Key's bytes as sent


def parse_auth_data(raw: bytes, *, attested: bool) -> AuthData:
    if not isinstance(raw, (bytes, bytearray)) or not 37 <= len(raw) <= MAX_AUTH_DATA:
        raise WebAuthnError("auth_data")
    raw = bytes(raw)
    flags = raw[32]
    count = int.from_bytes(raw[33:37], "big")
    pos = 37
    cred_id = key = None
    if flags & FLAG_AT:
        if not attested:
            raise WebAuthnError("auth_data")  # an assertion carries no new credential
        if len(raw) < pos + 18:
            raise WebAuthnError("auth_data")
        pos += 16  # AAGUID – not used: "none" attestation tells nothing reliable about the model
        n = int.from_bytes(raw[pos : pos + 2], "big")
        pos += 2
        if not 1 <= n <= MAX_CREDENTIAL_ID or len(raw) < pos + n:
            raise WebAuthnError("auth_data")
        cred_id = raw[pos : pos + n]
        pos += n
        try:
            obj, end = cbor.decode_prefix(raw, pos)
        except cbor.CborError:
            raise WebAuthnError("public_key") from None
        if not isinstance(obj, dict):
            raise WebAuthnError("public_key")
        key = raw[pos:end]
        pos = end
    elif attested:
        raise WebAuthnError("auth_data")
    if flags & FLAG_ED:
        try:
            ext, pos = cbor.decode_prefix(raw, pos)
        except cbor.CborError:
            raise WebAuthnError("auth_data") from None
        if not isinstance(ext, dict):
            raise WebAuthnError("auth_data")
    if pos != len(raw):
        raise WebAuthnError("auth_data")
    return AuthData(rp_id_hash=raw[:32], flags=flags, sign_count=count, credential_id=cred_id, public_key=key)


def check_flags(ad: AuthData, rp: RelyingParty) -> None:
    if not hmac.compare_digest(ad.rp_id_hash, rp.id_hash):
        raise WebAuthnError("rp_id")
    if not ad.flags & FLAG_UP:
        raise WebAuthnError("user_presence")
    if not ad.flags & FLAG_UV:
        raise WebAuthnError("user_verification")
    if ad.flags & FLAG_BS and not ad.flags & FLAG_BE:
        raise WebAuthnError("auth_data")


_LABELS = {ES256: {1, 3, -1, -2, -3}, EDDSA: {1, 3, -1, -2}, RS256: {1, 3, -1, -2}}


def load_key(cose: bytes | dict) -> tuple[int, object]:
    """A COSE_Key (its bytes or decoded) → (algorithm, public key) – only the three algorithms, only their labels."""
    try:
        m = cbor.decode(cose) if isinstance(cose, (bytes, bytearray)) else cose
    except cbor.CborError:
        raise WebAuthnError("public_key") from None
    if not isinstance(m, dict):
        raise WebAuthnError("public_key")
    alg = m.get(3)
    # an integer, never a bool: an array or map from the authenticator is no dict key (TypeError – a 500 before)
    if not isinstance(alg, int) or isinstance(alg, bool) or alg not in _LABELS:
        raise WebAuthnError("algorithm")
    if not set(m) <= _LABELS[alg]:
        raise WebAuthnError("public_key")  # anything more (a private part "d", key_ops …) is not a plain public key
    try:
        if alg == ES256:
            x, y = m.get(-2), m.get(-3)
            if m.get(1) != 2 or m.get(-1) != 1 or not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
                raise WebAuthnError("public_key")
            return alg, ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
        if alg == EDDSA:
            x = m.get(-2)
            if m.get(1) != 1 or m.get(-1) != 6 or not (isinstance(x, bytes) and len(x) == 32):
                raise WebAuthnError("public_key")
            return alg, ed25519.Ed25519PublicKey.from_public_bytes(x)
        n, e = m.get(-1), m.get(-2)
        if m.get(1) != 3 or not (isinstance(n, bytes) and isinstance(e, bytes)) or not 1 <= len(e) <= 8:
            raise WebAuthnError("public_key")
        ni, ei = int.from_bytes(n, "big"), int.from_bytes(e, "big")
        if not RSA_MIN_BITS <= ni.bit_length() <= RSA_MAX_BITS or ei < 3 or ei % 2 == 0:
            raise WebAuthnError("public_key")
        return alg, rsa.RSAPublicNumbers(ei, ni).public_key()
    except ValueError:  # not on the curve, not a valid key
        raise WebAuthnError("public_key") from None


def verify_signature(alg: int, key: object, signature: bytes, data: bytes) -> None:
    if not signature or len(signature) > MAX_SIGNATURE:
        raise WebAuthnError("signature")
    try:
        if alg == ES256:
            key.verify(signature, data, ec.ECDSA(hashes.SHA256()))  # type: ignore[attr-defined]
        elif alg == RS256:
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[attr-defined]
        elif alg == EDDSA:
            key.verify(signature, data)  # type: ignore[attr-defined]
        else:
            raise WebAuthnError("algorithm")
    except (InvalidSignature, ValueError):
        raise WebAuthnError("signature") from None


# ---------------------------------------------------------------- the two ceremonies


@dataclass(frozen=True)
class NewCredential:
    credential_id: bytes
    public_key: bytes  # COSE_Key
    algorithm: int
    sign_count: int


def verify_registration(rp: RelyingParty, challenge: bytes, *, raw_id: bytes, client_data_json: bytes, attestation_object: bytes) -> NewCredential:
    cd_hash = check_client_data(client_data_json, "webauthn.create", challenge, rp)
    if not attestation_object or len(attestation_object) > MAX_ATTESTATION:
        raise WebAuthnError("attestation")
    try:
        att = cbor.decode(attestation_object)
    except cbor.CborError:
        raise WebAuthnError("attestation") from None
    if not isinstance(att, dict) or set(att) != {"fmt", "attStmt", "authData"}:
        raise WebAuthnError("attestation")
    fmt, stmt, auth_raw = att["fmt"], att["attStmt"], att["authData"]
    if not (isinstance(fmt, str) and isinstance(stmt, dict) and isinstance(auth_raw, bytes)):
        raise WebAuthnError("attestation")
    ad = parse_auth_data(auth_raw, attested=True)
    check_flags(ad, rp)
    if ad.credential_id is None or ad.public_key is None:
        raise WebAuthnError("auth_data")
    alg, key = load_key(ad.public_key)
    if fmt == "none":
        if stmt:
            raise WebAuthnError("attestation")
    elif fmt == "packed" and set(stmt) == {"alg", "sig"}:
        # self-attestation: signed with the new credential's own key – no certificate, nothing about the maker
        if stmt["alg"] != alg or not isinstance(stmt["sig"], bytes):
            raise WebAuthnError("attestation")
        verify_signature(alg, key, stmt["sig"], auth_raw + cd_hash)
    else:
        raise WebAuthnError("attestation_format")
    if not hmac.compare_digest(ad.credential_id, raw_id):
        raise WebAuthnError("credential_id")
    return NewCredential(credential_id=ad.credential_id, public_key=ad.public_key, algorithm=alg, sign_count=ad.sign_count)


def verify_assertion(rp: RelyingParty, challenge: bytes, *, public_key: bytes, client_data_json: bytes, authenticator_data: bytes, signature: bytes) -> int:
    """A sign-in with a stored credential – the authenticator's new signature counter."""
    cd_hash = check_client_data(client_data_json, "webauthn.get", challenge, rp)
    ad = parse_auth_data(authenticator_data, attested=False)
    check_flags(ad, rp)
    alg, key = load_key(public_key)
    verify_signature(alg, key, signature, bytes(authenticator_data) + cd_hash)
    return ad.sign_count


def counter_regressed(stored: int, new: int) -> bool:
    """A counter that did not go up although one of the two is not 0: maybe a cloned authenticator (§6.1.1). Synced
    passkeys always send 0 – 0 after 0 is no sign of anything."""
    return (stored != 0 or new != 0) and new <= stored
