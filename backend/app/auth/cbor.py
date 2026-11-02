"""A minimal, strict CBOR decoder (RFC 8949) – only what WebAuthn needs (app/auth/webauthn.py): the attestation object,
the credential public key (COSE_Key) and the authenticator's extension map.

Accepted: unsigned and negative integers, byte strings, text strings (valid UTF-8), arrays and maps with integer or
text keys. Refused (CborError): indefinite lengths, the reserved additional-information values, tags, floats, simple
values (also true/false/null – nothing WebAuthn sends us needs them), duplicate map keys, nesting deeper than MAX_DEPTH,
more than MAX_ITEMS elements in one array or map or MAX_TOTAL items in all, an input longer than MAX_BYTES, a truncated
item and – with `decode` – any byte after the item. Lengths are checked against what is left before anything is read,
so a header announcing 2^64 bytes costs nothing."""

from typing import Any

MAX_BYTES = 16 * 1024
MAX_DEPTH = 6
MAX_ITEMS = 64
MAX_TOTAL = 512


class CborError(ValueError):
    """Not a CBOR item this decoder accepts – the message says why (for logs and tests, never shown to a client)."""


class _Reader:
    def __init__(self, data: bytes, pos: int) -> None:
        self.data = data
        self.pos = pos
        self.items = 0

    def take(self, n: int) -> bytes:
        if n < 0 or n > len(self.data) - self.pos:
            raise CborError("truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def head(self) -> tuple[int, int]:
        first = self.take(1)[0]
        major, info = first >> 5, first & 0x1F
        if info < 24:
            return major, info
        if info in (24, 25, 26, 27):
            return major, int.from_bytes(self.take(1 << (info - 24)), "big")
        if info == 31:
            raise CborError("indefinite length")
        raise CborError("reserved additional information")

    def item(self, depth: int) -> Any:  # noqa: ANN401 - what CBOR holds
        if depth > MAX_DEPTH:
            raise CborError("nested too deep")
        self.items += 1
        if self.items > MAX_TOTAL:
            raise CborError("too many items")
        major, arg = self.head()
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return self.take(arg)
        if major == 3:
            try:
                return self.take(arg).decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise CborError("text string is not UTF-8") from None
        if major == 4:
            if arg > MAX_ITEMS:
                raise CborError("array too long")
            return [self.item(depth + 1) for _ in range(arg)]
        if major == 5:
            if arg > MAX_ITEMS:
                raise CborError("map too long")
            out: dict = {}
            for _ in range(arg):
                key = self.item(depth + 1)
                if not isinstance(key, (int, str)):
                    raise CborError("map key is neither an integer nor a text")
                if key in out:
                    raise CborError("duplicate map key")
                out[key] = self.item(depth + 1)
            return out
        raise CborError("tags, floats and simple values are not accepted")


def decode_prefix(data: bytes, offset: int = 0) -> tuple[Any, int]:
    """The item starting at `offset` and where it ends (for the COSE key and the extensions inside authenticator data)."""
    if not isinstance(data, (bytes, bytearray)):
        raise CborError("not bytes")
    if len(data) > MAX_BYTES:
        raise CborError("input too long")
    if not 0 <= offset <= len(data):
        raise CborError("offset outside the input")
    r = _Reader(bytes(data), offset)
    value = r.item(0)
    return value, r.pos


def decode(data: bytes) -> Any:  # noqa: ANN401 - what CBOR holds
    """Exactly one item and nothing after it."""
    value, end = decode_prefix(data)
    if end != len(data):
        raise CborError("trailing bytes")
    return value
