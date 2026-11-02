"""Randomised fuzzing of the parsers that read what a browser sends at a passkey registration or sign-in: the CBOR
decoder (app/auth/cbor.py) and the WebAuthn checks (app/auth/webauthn.py). No new dependency – a seeded generator
(the same cases every run; FUZZ_SEED picks others) mutates valid structures (bit flips, cut, inserted and duplicated
ranges, CBOR headers that announce huge lengths, indefinite lengths, tags, floats, deep nesting) and makes random
values and bytes. What must hold: an input is accepted or refused with the module's own error – CborError,
WebAuthnError – never any other exception (IndexError, RecursionError, UnicodeDecodeError, OverflowError …), and
every call is quick (no input makes the parser loop or allocate what a header announces)."""

import hashlib
import json
import os
import random
import time

import pytest
from test_passkeys import ORIGIN, RP_ID, Authenticator, enc

from app.auth import cbor, webauthn

SEED = int(os.environ.get("FUZZ_SEED", "20261102"))
ROUNDS = int(os.environ.get("FUZZ_ROUNDS", "4000"))
SLOWEST = 0.25  # s: the most one call may take (a signature check of an RSA key is far below)
RP = webauthn.RelyingParty(rp_id=RP_ID, origin=ORIGIN)
CHALLENGE = b"c" * 32
HEADERS = [0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1F, 0x5B, 0x5F, 0x7B, 0x7F, 0x9B, 0x9F, 0xBB, 0xBF, 0xC0, 0xD8, 0xF4, 0xF6, 0xF7, 0xF9, 0xFA, 0xFB, 0xFF]


def mutate(rng: random.Random, data: bytes, pool: list[bytes]) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        kind = rng.randrange(9)
        pos = rng.randrange(len(b) + 1) if b else 0
        if kind == 0 and b:  # flip a bit
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
        elif kind == 1 and b:  # another byte
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif kind == 2:  # a CBOR header that announces something
            b[pos:pos] = bytes([rng.choice(HEADERS)]) + rng.randbytes(rng.choice((0, 1, 2, 4, 8)))
        elif kind == 3:  # random bytes in
            b[pos:pos] = rng.randbytes(rng.randint(1, 16))
        elif kind == 4 and b:  # a range out
            del b[pos : pos + rng.randint(1, 32)]
        elif kind == 5:  # cut
            del b[pos:]
        elif kind == 6 and b:  # a range doubled
            j = rng.randrange(len(b))
            b[pos:pos] = b[j : j + rng.randint(1, 64)]
        elif kind == 7 and pool:  # spliced with another valid input
            other = rng.choice(pool)
            k = rng.randrange(len(other) + 1)
            b = b[:pos] + bytearray(other[k:])
        elif kind == 8:  # a length byte of the item maxed out
            if b:
                b[rng.randrange(len(b))] |= 0x1B
    return bytes(b[: cbor.MAX_BYTES + 64])


def random_value(rng: random.Random, depth: int = 0):  # noqa: ANN201 - what CBOR holds
    kind = rng.randrange(7 if depth < 9 else 4)
    if kind == 0:
        return rng.choice((0, 1, 23, 24, 255, 256, 65535, 2**32, 2**64 - 1, rng.randrange(2**64)))
    if kind == 1:
        return -1 - rng.randrange(2**64)
    if kind == 2:
        return rng.randbytes(rng.choice((0, 1, 31, 32, 255, 600)))
    if kind == 3:
        return "".join(chr(rng.choice((0x41, 0xE4, 0x20AC, 0x1F600, rng.randrange(0x20, 0xD7FF)))) for _ in range(rng.randint(0, 12)))
    if kind in (4, 5):
        return [random_value(rng, depth + 1) for _ in range(rng.choice((0, 1, 3, 70)) if depth < 3 else rng.randint(0, 2))]
    out: dict = {}
    for _ in range(rng.randint(0, 5)):
        out[rng.choice((rng.randrange(-30, 30), "fmt", "attStmt", "authData", "x" * rng.randint(0, 5)))] = random_value(rng, depth + 1)
    return out


def _timed(fn, *a, allowed: tuple[type[BaseException], ...], **kw):  # noqa: ANN001, ANN202
    t0 = time.perf_counter()
    try:
        out = fn(*a, **kw)
    except allowed:
        out = None
    except Exception as exc:  # noqa: BLE001 - the finding: name the exception and the input
        raise AssertionError(f"{fn.__name__} raised {type(exc).__name__}: {exc}") from exc
    took = time.perf_counter() - t0
    assert took < SLOWEST, f"{fn.__name__} took {took:.3f} s"
    return out


def _valid_inputs() -> dict:
    out: dict = {"att": [], "cose": [], "auth": [], "assert": [], "cd_create": None, "cd_get": None}
    cd_create = json.dumps({"type": "webauthn.create", "challenge": webauthn.b64url(CHALLENGE), "origin": ORIGIN, "crossOrigin": False}).encode()
    cd_get = json.dumps({"type": "webauthn.get", "challenge": webauthn.b64url(CHALLENGE), "origin": ORIGIN, "crossOrigin": False}).encode()
    out["cd_create"], out["cd_get"] = cd_create, cd_get
    for alg in (webauthn.ES256, webauthn.RS256, webauthn.EDDSA):
        a = Authenticator(alg)
        ad = a.auth_data(attested=True)
        packed = {"alg": a.alg, "sig": a.sign(ad + hashlib.sha256(cd_create).digest())}
        for fmt, stmt in (("none", {}), ("packed", packed)):
            att = enc({"fmt": fmt, "attStmt": stmt, "authData": ad})
            # the valid one passes – the mutations start from something the parser accepts
            assert webauthn.verify_registration(RP, CHALLENGE, raw_id=a.cred_id, client_data_json=cd_create, attestation_object=att).algorithm == alg
            out["att"].append((a.cred_id, att))
        out["cose"].append(enc(a.cose))
        out["auth"].append(ad)
        a.counter += 1
        get_ad = a.auth_data()
        sig = a.sign(get_ad + hashlib.sha256(cd_get).digest())
        assert webauthn.verify_assertion(RP, CHALLENGE, public_key=enc(a.cose), client_data_json=cd_get, authenticator_data=get_ad, signature=sig) == a.counter
        out["assert"].append((enc(a.cose), get_ad, sig))
    return out


@pytest.fixture(scope="module")
def valid() -> dict:
    return _valid_inputs()


def test_cbor_random_values_round_trip_or_are_refused():
    """Generated values: what the decoder accepts comes back exactly as encoded; too deep, too long or too many items is
    a CborError – nothing else."""
    rng = random.Random(SEED)
    accepted = refused = 0
    t0 = time.perf_counter()
    for _ in range(ROUNDS):
        v = random_value(rng)
        data = enc(v)
        got = _timed(cbor.decode, data, allowed=(cbor.CborError,))
        if got is None and v is not None:
            refused += 1
            assert len(data) > cbor.MAX_BYTES or _too_big(v), v
        else:
            accepted += 1
            assert got == v
    assert accepted > ROUNDS // 4 and refused > 0  # both sides were reached
    assert time.perf_counter() - t0 < 30


def _too_big(v, depth: int = 0) -> bool:  # noqa: ANN001
    """Beyond the decoder's limits (depth, items per container, items in all) – roughly; exact counting is the decoder's."""
    count = [0]

    def walk(x, d):  # noqa: ANN001, ANN202
        count[0] += 1
        if d > cbor.MAX_DEPTH:
            return True
        if isinstance(x, list):
            return len(x) > cbor.MAX_ITEMS or any(walk(i, d + 1) for i in x)
        if isinstance(x, dict):
            return len(x) > cbor.MAX_ITEMS or any(walk(k, d + 1) or walk(i, d + 1) for k, i in x.items())
        return False

    return walk(v, depth) or count[0] > cbor.MAX_TOTAL


def test_cbor_mutated_and_random_bytes_only_cbor_errors(valid):
    rng = random.Random(SEED + 1)
    pool = [att for _, att in valid["att"]] + valid["cose"]
    t0 = time.perf_counter()
    for i in range(ROUNDS * 2):
        data = mutate(rng, rng.choice(pool), pool) if i % 4 else rng.randbytes(rng.randint(0, 300))
        _timed(cbor.decode, data, allowed=(cbor.CborError,))
        _timed(cbor.decode_prefix, data, rng.randint(-2, len(data) + 2), allowed=(cbor.CborError,))
    # the cases the docstring names, explicitly
    for data in (b"\x5b\xff\xff\xff\xff\xff\xff\xff\xff", b"\x9f\x01\xff", b"\xc0\x01", b"\xf5", b"\xfa\x00\x00\x00\x00", b"\x81" * 100 + b"\x01", b"\xa2\x01\x01\x01\x02", b"\x62\xc3\x28", b""):
        _timed(cbor.decode, data, allowed=(cbor.CborError,))
    _timed(cbor.decode, b"\x00" * (cbor.MAX_BYTES + 1), allowed=(cbor.CborError,))
    _timed(cbor.decode, "text", allowed=(cbor.CborError,))  # not bytes at all
    assert time.perf_counter() - t0 < 30


def test_webauthn_registration_mutated_only_webauthn_errors(valid):
    rng = random.Random(SEED + 2)
    pool = [att for _, att in valid["att"]]
    t0 = time.perf_counter()
    for i in range(ROUNDS):
        raw_id, att = rng.choice(valid["att"])
        if i % 5 == 0:
            att = enc({"fmt": rng.choice(("none", "packed", "tpm", "")), "attStmt": random_value(rng), "authData": mutate(rng, rng.choice(valid["auth"]), valid["auth"])})
        else:
            att = mutate(rng, att, pool)
        cd = valid["cd_create"] if i % 7 else mutate(rng, valid["cd_create"], [valid["cd_get"]])
        _timed(webauthn.verify_registration, RP, CHALLENGE, raw_id=raw_id, client_data_json=cd, attestation_object=att, allowed=(webauthn.WebAuthnError,))
    assert time.perf_counter() - t0 < 60


def test_webauthn_assertion_and_parts_mutated_only_webauthn_errors(valid):
    rng = random.Random(SEED + 3)
    t0 = time.perf_counter()
    for i in range(ROUNDS):
        cose, ad, sig = rng.choice(valid["assert"])
        which = i % 4
        cose = mutate(rng, cose, valid["cose"]) if which == 0 else cose
        ad = mutate(rng, ad, valid["auth"]) if which == 1 else ad
        sig = mutate(rng, sig, []) if which == 2 else sig
        cd = mutate(rng, valid["cd_get"], [valid["cd_create"]]) if which == 3 else valid["cd_get"]
        _timed(webauthn.verify_assertion, RP, CHALLENGE, public_key=cose, client_data_json=cd, authenticator_data=ad, signature=sig, allowed=(webauthn.WebAuthnError,))
        _timed(webauthn.parse_auth_data, mutate(rng, rng.choice(valid["auth"]), valid["auth"]), attested=bool(i % 2), allowed=(webauthn.WebAuthnError,))
        _timed(webauthn.load_key, mutate(rng, rng.choice(valid["cose"]), valid["cose"]), allowed=(webauthn.WebAuthnError,))
        _timed(webauthn.load_key, random_value(rng) if i % 3 else rng.randbytes(40), allowed=(webauthn.WebAuthnError,))
        _timed(webauthn.check_client_data, mutate(rng, valid["cd_get"], []), "webauthn.get", CHALLENGE, RP, allowed=(webauthn.WebAuthnError,))
    assert time.perf_counter() - t0 < 60


def test_base64url_random_strings_only_webauthn_errors():
    rng = random.Random(SEED + 4)
    alphabet = "ABCabc019-_=+/ .\nä"
    for _ in range(ROUNDS):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        got = _timed(webauthn.unb64url, s, limit=rng.randint(0, 64), allowed=(webauthn.WebAuthnError,))
        if got is not None:
            assert webauthn.b64url(got) == s  # accepted: exactly the one encoding of these bytes
