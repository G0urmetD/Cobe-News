"""The HTTPS certificate of the bundled reverse proxy (nginx, docker-compose.yml).

Three ways to run it (TLS_MODE):
- selfsigned (default): the app makes its own certificate (180 days, EC P-256) for NEWS_HOSTNAME / the host of
  BASE_URL / localhost / 127.0.0.1 / TLS_NAMES and renews it 30 days before it ends (at start and once a day), at once
  when the names change. nginx picks the new one up by itself (it watches the files). Browsers warn until the
  certificate is trusted – it can be downloaded in the settings and handed out.
- own: the organisation's certificate (internal CA) for its own FQDN in TLS_SOURCE (cobe.crt with the chain, cobe.key).
  The app never writes there; it only watches the expiry (shown in the settings).
- external: TLS ends at a reverse proxy outside this stack (an existing nginx …) – nothing to do here.

Only a certificate the app made itself is ever replaced (the marker file holds that certificate's fingerprint): a file
put there by hand is left alone even in selfsigned mode.
"""

import ipaddress
import re
import logging
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.config import get_config

log = logging.getLogger("cobe_news.tls")

CERT, KEY, MARK = "cobe.crt", "cobe.key", ".cobe-selfsigned"
LIFETIME = timedelta(days=180)
RENEW_BEFORE = timedelta(days=30)
WARN_BEFORE = timedelta(days=30)  # an own certificate: shown as a problem this long before it ends
MODES = ("selfsigned", "own", "external")


def mode() -> str:
    return get_config().tls_mode


def folder() -> Path:
    return Path(get_config().tls_path)


def base_host() -> str:
    return get_config().base_host


def wanted_names() -> list[str]:
    """What the certificate must cover: the configured name, the address in the browser, localhost, extra names."""
    s = get_config()
    names = [s.hostname, base_host(), "localhost", "127.0.0.1", *s.tls_names]
    return list(dict.fromkeys(a for a in (_ascii_name(n) for n in names if n) if a))


def _ascii_name(name: str) -> str:
    """A name as it goes into the certificate: IP addresses as they are, other names IDNA-encoded (nachrichten.bücher.example
    → xn--…); one that cannot be encoded is left out (logged) instead of stopping the start."""
    n = name.strip().rstrip(".").lower()
    try:
        ipaddress.ip_address(n)
        return n
    except ValueError:
        pass
    try:
        return n.encode("idna").decode("ascii")
    except UnicodeError:
        log.warning("tls: name %r cannot be put into a certificate – left out", name)
        return ""


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _load(path: Path) -> x509.Certificate | None:
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError):
        return None


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [str(v).lower() for v in (*ext.get_values_for_type(x509.DNSName), *ext.get_values_for_type(x509.IPAddress))]


def covers(cert: x509.Certificate, host: str) -> bool:
    """Does the certificate fit this host name (incl. one wildcard level, *.corp.example)?"""
    host = host.lower().rstrip(".")
    for n in _sans(cert):
        if n == host or (n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]):
            return True
    return False


def _key_fits(d: Path, cert: x509.Certificate) -> bool:
    """Key and certificate belong together – a crash between writing the two would otherwise leave a pair nginx refuses."""
    try:
        key = serialization.load_pem_private_key((d / KEY).read_bytes(), password=None)
    except (OSError, ValueError, TypeError):
        return False
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    return key.public_key().public_bytes(serialization.Encoding.DER, pub) == cert.public_key().public_bytes(serialization.Encoding.DER, pub)


def _ours(d: Path, cert: x509.Certificate) -> bool:
    try:
        # one line, or two while a new pair is being written (new and old) – see ensure()
        return _fingerprint(cert) in (d / MARK).read_text().split()
    except OSError:
        return False


def _write(path: Path, data: bytes, mode_: int) -> None:
    """Atomic: nginx (watching the files) never reads half a certificate."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode_)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def make(names: list[str], now: datetime | None = None) -> tuple[bytes, bytes]:
    """A self-signed server certificate (PEM cert, PEM key) for these names – 180 days, not a CA."""
    now = now or datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    alt: list[x509.GeneralName] = []
    for n in names:
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            alt.append(x509.DNSName(n))
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cobe News"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "self-signed"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + LIFETIME)
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def ensure(now: datetime | None = None) -> str:
    """Selfsigned mode: create the certificate, or renew it when it nears its end or no longer covers the names.
    Returns what happened: created | renewed | ok | foreign (someone else's file – left alone) | own | external."""
    m = mode()
    if m != "selfsigned":
        return m
    now = now or datetime.now(UTC)
    d = folder()
    d.mkdir(parents=True, exist_ok=True)
    names = wanted_names()
    cert = _load(d / CERT)
    if cert is not None:
        if not _ours(d, cert):
            return "foreign"
        fits = set(names) <= set(_sans(cert))
        if fits and cert.not_valid_after_utc - now > RENEW_BEFORE and _key_fits(d, cert):
            return "ok"
    cert_pem, key_pem = make(names, now)
    new = _fingerprint(x509.load_pem_x509_certificate(cert_pem))
    # the marker names old and new pair while both files are replaced: a crash in between leaves a pair still known
    # as ours, whose key does not fit (_key_fits) – it is simply made again at the next start
    _write(d / MARK, f"{new}\n{_fingerprint(cert) if cert is not None else ''}".strip().encode(), 0o644)
    _write(d / KEY, key_pem, 0o600)
    _write(d / CERT, cert_pem, 0o644)
    _write(d / MARK, new.encode(), 0o644)
    what = "renewed" if cert is not None else "created"
    log.info("tls: certificate %s for %s (valid until %s)", what, ", ".join(names), (now + LIFETIME).date())
    return what


def pem() -> bytes | None:
    """The certificate as it is served (public part only) – to hand out or to compare the fingerprint."""
    try:
        data = (folder() / CERT).read_bytes()
    except OSError:
        return None
    if _load(folder() / CERT) is None:
        return None
    # only the certificate blocks – should someone have put the key into the same file, it never leaves
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", data, re.S)
    return b"\n".join(blocks) + b"\n" if blocks else None


def status(now: datetime | None = None) -> dict:
    """For the settings sheet: what is served, until when, and what needs a look."""
    now = now or datetime.now(UTC)
    s = get_config()
    m = mode()
    out: dict = {"mode": m, "base_url": s.base_url, "hostname": s.hostname or base_host(), "problems": [], "hsts": hsts()}
    problems: list[str] = out["problems"]
    if not s.base_url.startswith("https://"):
        problems.append("base_url_http")
    if m == "external":
        return out
    cert = _load(folder() / CERT)
    if cert is None:
        problems.append("missing")
        return out
    ours = _ours(folder(), cert)
    left = cert.not_valid_after_utc - now
    out |= {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_signed": cert.issuer == cert.subject,
        "ours": ours,
        "names": _sans(cert),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "days_left": max(0, left.days),
        "fingerprint": ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256())),
        "renews_at": (cert.not_valid_after_utc - RENEW_BEFORE).isoformat() if ours and m == "selfsigned" else None,
    }
    host = base_host()
    if host and not covers(cert, host):
        problems.append("name_mismatch")  # the browser would refuse the certificate for this address
    if left <= timedelta(0):
        problems.append("expired")
    elif left <= WARN_BEFORE and not (ours and m == "selfsigned" and left > timedelta(days=7)):
        problems.append("expiring")  # an own one ends soon – or the renewal of ours did not happen
    if m == "selfsigned" and not ours:
        problems.append("foreign")  # a file put there by hand: not renewed
    if m == "own" and cert.issuer == cert.subject:
        problems.append("own_is_self_signed")
    return out


def hsts() -> bool:
    """HSTS only with a certificate the browsers trust (own CA, or a proxy of one's own) – with the self-signed one a
    browser would refuse "continue anyway" for a year, and as soon as the app renews it (every ~150 days, a new
    certificate) every computer that trusted the old one would be locked out without a way past the warning. HSTS=1
    switches it on anyway (once the certificate is handed out). Sent only to a host name (hsts_host)."""
    return get_config().hsts or mode() in ("own", "external")


HSTS_HEADER = "max-age=31536000"  # no includeSubDomains (other services under the domain), no preload


def hsts_host(host: str) -> bool:
    """Whether the address in the browser may get HSTS: a real host name only. HSTS holds for the host across all ports –
    sent for localhost it would turn the plain-http emergency access http://localhost:8096 into https (which is not served
    there) for a year; *.localhost is loopback, too. IP literals are ignored by browsers anyway (RFC 6797 8.1) and are
    left out as well – also forms a browser reads as IPv4 (127.1, 0x7f.1, 2130706433). `host` is the Host header
    (with or without port)."""
    h = (host or "").strip().lower()
    if not h or any(c in h for c in "/\\@ "):
        return False
    if h.startswith("["):  # [v6]:port
        return False
    h = h.rsplit(":", 1)[0] if h.count(":") == 1 else h
    if ":" in h:  # a bare IPv6 address
        return False
    h = h.rstrip(".")
    if not h or h == "localhost" or h.endswith(".localhost"):
        return False
    try:
        ipaddress.ip_address(h)
        return False
    except ValueError:
        pass
    last = h.rsplit(".", 1)[-1]
    return not re.fullmatch(r"[0-9]+|0x[0-9a-f]*", last)  # ends in a number: the browser reads it as IPv4 (WHATWG URL)
