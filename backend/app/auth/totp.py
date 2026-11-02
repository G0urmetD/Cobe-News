"""TOTP (RFC 6238) as the second factor."""

import hmac
import time
from urllib.parse import quote

import pyotp

ISSUER = "Cobe News"
STEP = 30


def new_secret() -> str:
    return pyotp.random_base32(length=32)


def provisioning_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret, issuer=ISSUER).provisioning_uri(name=account, issuer_name=ISSUER).replace(" ", quote(" "))


def verify(secret: str, code: str, last_step: int | None) -> int | None:
    """A code with ±1 step tolerance and replay protection: the matched step (stored as last_step) or None."""
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // STEP
    for step in (now_step, now_step - 1, now_step + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp.at(step * STEP), code):  # constant time: no hint how many digits were right
            return step
    return None
