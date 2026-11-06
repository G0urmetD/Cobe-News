"""Secrets at rest (webhook URLs, SMTP/LDAP bind password, Entra client secret) and keyed hashes for tokens. The
master key is SECRET_KEY from the environment or, without it, a random key in
DATA_DIR/secret.key (created once, mode 0600). Losing the key file means re-entering those secrets."""

import base64
import errno
import hashlib
import hmac
import os
import secrets
import time
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import get_config

SECRETS_INFO = b"cobe-news/secrets-at-rest/v1"
TOKEN_MAC_INFO = b"cobe-news/token-mac/v1"
KEY_FILE = "secret.key"


MIN_FILE_KEY = 16  # bytes in secret.key – the file this module writes holds 44
KEY_FILE_WAIT = 2.0  # s: how long an empty secret.key is given – another process may have created it a moment ago


class KeyFileError(RuntimeError):
    """secret.key is there but holds no usable key (empty, cut off) – nothing is encrypted with it."""


def _read_key_file(path) -> bytes:  # noqa: ANN001
    """The key in the file – waiting up to KEY_FILE_WAIT for another process that has just created it to write it.
    An empty or short file is refused (KeyFileError): HKDF takes an empty key, and every secret, token MAC and backup
    signature would rest on a key anybody knows (a process killed or a full disk between creating and writing it)."""
    deadline = time.monotonic() + KEY_FILE_WAIT
    while True:
        key = path.read_bytes().strip()
        if len(key) >= MIN_FILE_KEY:
            return key
        if time.monotonic() >= deadline:
            raise KeyFileError(
                f"{path} holds no usable key ({len(key)} bytes) – not used. Restore the right file (backup), or remove it: a new key is"
                " made, and the stored secrets (webhook URLs, SMTP/LDAP passwords, the Entra secret, TOTP) have to be entered again"
            )
        time.sleep(0.05)


@lru_cache
def master() -> bytes:
    cfg = get_config()
    if cfg.secret_key:
        return cfg.secret_key.encode()
    path = cfg.data_dir / KEY_FILE
    try:
        return _read_key_file(path)
    except FileNotFoundError:
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        return _make_key_file(path)


# what link() says on a file system without hard links – only then the fallback (EMLINK: the link count is full)
NO_LINKS = frozenset({errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV, errno.EMLINK, errno.ENOSYS})


def _make_key_file(path) -> bytes:  # noqa: ANN001
    """A new key, written whole before secret.key exists: into a temporary file next to it (fsync), then linked to the
    name – a hard link never replaces a file, and the name appears complete or not at all. Before 0.1.52 the file was
    created first and written after: a start killed in between (OOM, a stop, a full disk) left an empty secret.key that
    every later start refused. Another process that was faster wins; its key is read. A file system without hard links
    (NO_LINKS: vfat, some FUSE/SMB/NFS mounts) falls back to creating the name exclusively (the old way); any other error
    (a full disk, an I/O error, a read-only file system) is raised – the temporary file removed, no secret.key made."""
    key = base64.urlsafe_b64encode(secrets.token_bytes(32))
    tmp = path.with_name(f".{KEY_FILE}.{os.getpid()}.{secrets.token_hex(4)}")
    try:
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except PermissionError as exc:
            raise KeyFileError(
                f"{path.parent} is not writable for this process (uid {os.getuid()}) – no key can be made. The data folder must"
                " belong to UID 10001, the app's user: on the host `sudo chown -R 10001:10001 ./data` (docker compose), or use"
                " a named volume (docs/BETRIEB.md)"
            ) from exc
        with os.fdopen(fd, "wb") as f:
            f.write(key)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:  # another process was faster
            return _read_key_file(path)
        except OSError as exc:
            if exc.errno not in NO_LINKS:
                raise
            return _write_exclusive(path, key)  # no hard links here: the name created exclusively, then written
        _fsync_dir(path.parent)
        return key
    finally:
        tmp.unlink(missing_ok=True)


def _write_exclusive(path, key: bytes) -> bytes:  # noqa: ANN001
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # another process was faster – and may not have written its key yet
        return _read_key_file(path)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
        f.flush()
        os.fsync(f.fileno())
    return key


def _fsync_dir(d) -> None:  # noqa: ANN001
    """The new name made durable (a crash right after must not lose the file the secrets are now encrypted with)."""
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


MIN_STRONG_KEY = 32  # bytes – below that (or with only a few different characters) a warning, never a refusal
MIN_KEY_SYMBOLS = 8


def key_weakness() -> str | None:
    """Is the master key short? "env" (SECRET_KEY) or "file" (secret.key – the one this module writes is 44 characters)
    when it has fewer than MIN_STRONG_KEY bytes or fewer than MIN_KEY_SYMBOLS different characters ("aaaa…"); None when
    it is fine. Only a warning (log at the start, Einstellungen → HTTPS): an install with a short key keeps running –
    changing the key means entering the stored secrets again. Never says anything about the key itself."""
    key = master()
    if len(key) >= MIN_STRONG_KEY and len(set(key)) >= MIN_KEY_SYMBOLS:
        return None
    return "env" if get_config().secret_key else "file"


def _derive(info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"cobe-news", info=info).derive(master())


@lru_cache
def _aead() -> AESGCM:
    return AESGCM(_derive(SECRETS_INFO))


@lru_cache
def _mac_key() -> bytes:
    return _derive(TOKEN_MAC_INFO)


def encrypt_str(value: str) -> str:
    nonce = secrets.token_bytes(12)
    return "v1:" + base64.urlsafe_b64encode(nonce + _aead().encrypt(nonce, value.encode(), None)).decode()


class DecryptError(Exception):
    pass


def decrypt_str(value: str) -> str:
    """The stored secret – DecryptError when the key changed (the secret has to be entered again)."""
    if not value.startswith("v1:"):
        raise DecryptError("format")
    raw = base64.urlsafe_b64decode(value[3:].encode())
    try:
        return _aead().decrypt(raw[:12], raw[12:], None).decode()
    except InvalidTag as exc:
        raise DecryptError("key") from exc


def token_hash(token: str) -> str:
    """Keyed hash for high-entropy tokens (session tokens, the setup token)."""
    return hmac.new(_mac_key(), token.encode(), hashlib.sha256).hexdigest()


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I


def human_code(groups: int = 4, size: int = 4) -> str:
    return "-".join("".join(secrets.choice(_ALPHABET) for _ in range(size)) for _ in range(groups))


def normalize_code(code: str) -> str:
    raw = "".join(ch for ch in code.upper() if ch.isalnum())
    return "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def reset_cache() -> None:
    """Tests: another DATA_DIR / SECRET_KEY."""
    master.cache_clear()
    _aead.cache_clear()
    _mac_key.cache_clear()


# ---------------------------------------------------------------- backups (app/backup.py)

BACKUP_KEY_ID_INFO = b"cobe-news/backup-key-id/v1"
SEAL_MAGIC = b"CNBK2\n"  # an encrypted backup: magic, salt, nonce prefix, then the sealed chunks
SEAL_MAGIC_V1 = b"CNBK1\n"  # up to 0.1.23: the same with scrypt N=2^15 – still read
SEAL_CHUNK = 1 << 20
# scrypt cost: 2^17 (128 MiB, about half a second) – what current guidance asks for; the container's limit is 512 MB
_SCRYPT_N = {SEAL_MAGIC: 1 << 17, SEAL_MAGIC_V1: 1 << 15}


def key_id() -> str:
    """Which master key this installation uses – a one-way fingerprint (never the key): a backup records it, a restore
    compares it before anything is changed."""
    return _derive(BACKUP_KEY_ID_INFO).hex()[:16]


BACKUP_SIGN_INFO = b"cobe-news/backup-signature/v1"


def backup_mac(data: bytes) -> str:
    """HMAC-SHA256 of a backup's manifest with a key derived from the master key: an unencrypted backup proves that
    this installation (whoever holds its key) made it – a file put together by someone else does not verify."""
    return hmac.new(_derive(BACKUP_SIGN_INFO), data, hashlib.sha256).hexdigest()


def _passphrase_key(passphrase: str, salt: bytes, magic: bytes = SEAL_MAGIC) -> AESGCM:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return AESGCM(Scrypt(salt=salt, length=32, n=_SCRYPT_N[magic], r=8, p=1).derive(passphrase.encode()))


def seal_file(src, dst, passphrase: str) -> None:  # noqa: ANN001 - binary file objects
    """`src` encrypted with a key from `passphrase` (scrypt) into `dst`: AES-256-GCM in chunks (STREAM: each chunk's
    nonce carries its number and whether it is the last – chunks cannot be reordered, dropped or cut off unnoticed)."""
    salt, prefix = secrets.token_bytes(16), secrets.token_bytes(7)
    header = SEAL_MAGIC + salt + prefix
    aead = _passphrase_key(passphrase, salt)
    dst.write(header)
    n, chunk = 0, src.read(SEAL_CHUNK)
    while True:
        nxt = src.read(SEAL_CHUNK)
        last = not nxt
        nonce = prefix + n.to_bytes(4, "big") + (b"\x01" if last else b"\x00")
        dst.write(aead.encrypt(nonce, chunk, header))
        if last:
            return
        n, chunk = n + 1, nxt


def is_sealed(path) -> bool:  # noqa: ANN001
    with open(path, "rb") as f:
        return f.read(len(SEAL_MAGIC)) in _SCRYPT_N


def open_sealed(src, dst, passphrase: str) -> None:  # noqa: ANN001
    """The reverse of seal_file; DecryptError for a wrong passphrase or a changed, shortened or damaged file."""
    header = src.read(len(SEAL_MAGIC) + 16 + 7)
    magic = header[: len(SEAL_MAGIC)]
    if len(header) != len(SEAL_MAGIC) + 23 or magic not in _SCRYPT_N:
        raise DecryptError("format")
    salt, prefix = header[len(SEAL_MAGIC) : len(SEAL_MAGIC) + 16], header[len(SEAL_MAGIC) + 16 :]
    aead = _passphrase_key(passphrase, salt, magic)
    size = SEAL_CHUNK + 16
    n, chunk = 0, src.read(size)
    while True:
        nxt = src.read(size)
        last = not nxt
        nonce = prefix + n.to_bytes(4, "big") + (b"\x01" if last else b"\x00")
        try:
            dst.write(aead.decrypt(nonce, chunk, header))
        except InvalidTag as exc:
            raise DecryptError("passphrase or file") from exc
        if last:
            return
        n, chunk = n + 1, nxt
