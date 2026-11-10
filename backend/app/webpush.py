"""Web Push: desktop notifications with every Cobe News tab closed.

The browser subscribes at its vendor's push service (Chrome/Edge: Google FCM or Microsoft WNS, Firefox: Mozilla, Safari:
Apple) and hands us an endpoint URL there plus two keys. After each round of feeds the server sends each subscribed
browser what arrived for its person (the same choice as in the tab: severities, sources, no backlog) – at most three
stories on their own and one summary, as the tab does. The payload is encrypted end to end for the browser (RFC 8291,
aes128gcm): the push service only sees its size. The server signs every request with its VAPID key (RFC 8292),
created once and kept encrypted in the settings.

Only https endpoints on the push services' hosts (PUSH_HOSTS) are taken – a subscription is browser input, it must not
make the server post anywhere else. Sent through the outbound proxy when one is set, as the other notifications.
A subscription is the browser's – one that fails or is slow must not hold up the others: each has its own deadline
(SUB_DEADLINE), the round as a whole one too (ROUND_DEADLINE), and after MAX_FAILURES failures in a row it is removed
(the browser hands it over again when it is still in use, lib/push.ts syncPush).

The VAPID key is created once and kept encrypted in the settings. Unreadable (SECRET_KEY / secret.key changed, the row
damaged): a new pair is made and the old subscriptions go – they were made for the old key and the push services refuse
them anyway; the browsers subscribe again with the new key (lib/push.ts compares it).
"""

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as dbm
from app import notify
from app import settings as settings_store
from app.config import get_config
from app.crypto import decrypt_str, encrypt_str
from app.models import PushSubscription, User
from app.plaintext import neutral

log = logging.getLogger("cobe_news.push")

# the push services of the browsers (endpoint hosts) – exact names and "*.": any name below
PUSH_HOSTS = ("fcm.googleapis.com", "*.push.services.mozilla.com", "*.push.apple.com", "*.notify.windows.com")
PER_USER = 10  # browsers per person – the oldest goes
TTL = 12 * 3600  # a push service keeps a message this long for a browser that is offline
SINGLE = 3  # stories on their own per round – more: one summary (as the tab)
RECORD = 4096
PAYLOAD_MAX = 3000  # the services take 4096 bytes of body: header, tag and padding included
BACKOFF_MAX = timedelta(hours=6)
CONCURRENCY = 16
SUB_DEADLINE = 30.0  # s: everything one browser gets in one round
ROUND_DEADLINE = 120.0  # s: the round as a whole – what is not done by then counts as a timeout for its browser
MAX_FAILURES = 12  # in a row (with the backoff: about two days) – then the subscription goes
SECTION = "push"


class PushError(Exception):
    pass


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def host_allowed(host: str) -> bool:
    host = host.lower().rstrip(".")
    for pat in PUSH_HOSTS:
        if pat.startswith("*.") and host.endswith(pat[1:]) and len(host) > len(pat) - 1:
            return True
        if host == pat:
            return True
    return False


def check_endpoint(url: str) -> str:
    """A subscription's endpoint – https on a push service host, port 443, no user info; else PushError."""
    url = url.strip()
    if len(url) > 1000:
        raise PushError("endpoint_too_long")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port not in (None, 443) or not host_allowed(parts.hostname):
        raise PushError("endpoint_not_allowed")
    return url


def check_keys(p256dh: str, auth: str) -> tuple[bytes, bytes]:
    """The browser's public key (uncompressed P-256 point) and auth secret (16 bytes)."""
    try:
        key, secret = unb64u(p256dh), unb64u(auth)
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key)
    except Exception as exc:  # noqa: BLE001 - whatever the browser sent: not a key
        raise PushError("invalid_keys") from exc
    if len(key) != 65 or len(secret) != 16:
        raise PushError("invalid_keys")
    return key, secret


# ---------------------------------------------------------------- RFC 8291: message encryption (aes128gcm)


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=SHA256(), length=length, salt=salt, info=info).derive(ikm)


def encrypt(plaintext: bytes, ua_public: bytes, auth_secret: bytes, *, salt: bytes | None = None, as_private: ec.EllipticCurvePrivateKey | None = None) -> bytes:
    """One record: salt | record size | key id length | our ephemeral public key | AES-128-GCM(payload | 0x02)."""
    as_private = as_private or ec.generate_private_key(ec.SECP256R1())
    as_public = as_private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    salt = salt or os.urandom(16)
    shared = as_private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public))
    ikm = _hkdf(auth_secret, shared, b"WebPush: info\x00" + ua_public + as_public, 32)
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    if len(plaintext) + 1 + 16 > RECORD:
        raise PushError("payload_too_large")
    body = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    return salt + RECORD.to_bytes(4, "big") + bytes([len(as_public)]) + as_public + body


# ---------------------------------------------------------------- RFC 8292: VAPID


@dataclass(frozen=True)
class Vapid:
    private: ec.EllipticCurvePrivateKey
    public: str  # base64url of the uncompressed point – the browser's applicationServerKey


_vapid: tuple[str, Vapid] | None = None  # the stored (encrypted) key it was loaded from, and the pair
_vapid_lock = asyncio.Lock()


def _load(enc: str) -> ec.EllipticCurvePrivateKey | None:
    """The stored key – None when it cannot be read (another SECRET_KEY, a damaged row, not a P-256 key)."""
    try:
        key = serialization.load_pem_private_key(decrypt_str(enc).encode(), password=None)
    except Exception:  # noqa: BLE001 - whatever is wrong with it: unusable
        return None
    return key if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1) else None


async def vapid(db: AsyncSession, *, rotate: bool = False) -> Vapid:
    """The server's VAPID key pair: created at the first use, the private key encrypted at rest (secret.key). One at a
    time (two first uses at once would make two keys, the second overwriting the one the first browsers subscribed
    with). The stored row is read each time (one small SELECT): a key rotated by `python -m app.cli rotate-vapid` is
    taken at once. `rotate`: a new pair on purpose."""
    global _vapid
    async with _vapid_lock:
        cfg = await settings_store.get(db, SECTION)
        enc = cfg.get("private_enc") or ""
        if _vapid is not None and _vapid[0] == enc and enc and not rotate:
            return _vapid[1]
        key = _load(enc) if enc and not rotate else None
        if key is None:
            if enc:
                log.warning("push: VAPID key %s – new key pair, the browsers subscribe again", "rotated" if rotate else "unreadable (SECRET_KEY changed?)")
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            enc = encrypt_str(pem.decode())
            await settings_store.put(db, SECTION, {**cfg, "private_enc": enc})
            if cfg.get("private_enc"):
                # subscriptions are bound to the public key they were made with – none of them can be sent to any more
                await db.execute(delete(PushSubscription))
            await db.commit()
        public = b64u(key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
        _vapid = (enc, Vapid(key, public))
        return _vapid[1]


def reset_cache() -> None:
    global _vapid, _vapid_lock
    _vapid, _vapid_lock = None, asyncio.Lock()


def contact() -> str:
    cfg = get_config()
    c = cfg.push_contact or cfg.base_url
    return c if c.startswith(("mailto:", "https://")) else f"https://{cfg.base_host or 'localhost'}"


def vapid_headers(endpoint: str, key: Vapid, *, now: float | None = None) -> dict[str, str]:
    parts = urlsplit(endpoint)
    claims = {"aud": f"{parts.scheme}://{parts.netloc}", "exp": int((now or time.time()) + 12 * 3600), "sub": contact()}
    token = jwt.encode(claims, key.private, algorithm="ES256", headers={"typ": "JWT"})
    return {"Authorization": f"vapid t={token}, k={key.public}"}


# ---------------------------------------------------------------- what is sent


SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
TEXTS = {
    "de": {
        "summary": "{n} neue Security-Meldungen",
        "summary_text": "In Cobe News öffnen",
        "summary_top": "Höchste Schwere: {sev}",
        "exploited": "ausgenutzt",
        "test": "Test-Benachrichtigung von Cobe News",
        "test_text": "Push bei geschlossenem Tab funktioniert.",
    },
    "en": {
        "summary": "{n} new security stories",
        "summary_text": "Open Cobe News",
        "summary_top": "Highest severity: {sev}",
        "exploited": "exploited",
        "test": "Test notification from Cobe News",
        "test_text": "Push with the tab closed works.",
    },
}


def _lang(lang: str) -> str:
    return lang if lang in TEXTS else "de"


def notice_line(story: dict, lang: str) -> str:
    """The line under a story's title – the same in the tab (frontend lib/desktop.ts storyBody) and by Web Push:
    "Kritisch (CVSS 9.8) · ausgenutzt · PAN-OS, Prisma Cloud · BSI". The severity only when the story has one (an
    unrated story says none), the CVSS and "ausgenutzt" when known, the products it is about – or, when the person chose
    systems or words, what it matched by ("Treffer: …", api.desktop_hits) – and the source last."""
    lang = _lang(lang)
    lb = notify.LABELS[lang]
    facts = story.get("notice") or {}
    parts: list[str] = []
    if facts.get("rated", True):
        sev = str(lb["sev"].get(story["severity"], story["severity"]))
        parts.append(f"{sev} (CVSS {facts['cvss']})" if facts.get("cvss") else sev)
    if facts.get("exploited"):
        parts.append(TEXTS[lang]["exploited"])
    hits = [str(x) for x in story.get("hits") or []]
    if hits:
        parts.append(f"{lb['hit']}: {notify.names_text(hits)}")
    elif names := notify.names_text([str(x) for x in facts.get("products") or []]):
        parts.append(names)
    parts.append(str(story["source"])[:80])
    return neutral(" · ".join(p for p in parts if p))


def story_payload(story: dict, lang: str) -> dict:
    """One story: its headline and notice_line (severity, products, source) – news from public feeds, nothing
    confidential; the text stays in Cobe News."""
    return {
        "v": 1,
        "kind": "story",
        "id": story["id"],
        "title": neutral(story["title"])[:200],
        "body": notice_line(story, lang)[:240],
        "severity": story["severity"],
        "url": f"/?story={story['id']}",
    }


def vendor_payload(event_id: str, title: str, product: str, severity: str, path: str, lang: str) -> dict:
    """A Vendor News event of the person's own products (app/personal.py): its title, severity and product; the link
    opens it in Vendor News (a path of this app – the service worker takes nothing else)."""
    lb = notify.LABELS[_lang(lang)]
    return {
        "v": 1,
        "kind": "vendor",
        "id": f"vendor-{event_id}",
        "title": neutral(title)[:200],
        "body": f"{lb['sev'].get(severity, severity)} · {neutral(product)[:80]}",
        "severity": severity,
        "url": path if path.startswith("/") else "/vendor",
    }


def summary_payload(count: int, lang: str, ids: list[str] | None = None, stories: list[dict] | None = None) -> dict:
    """The rest of a round in one notification: a click opens the news list filtered to exactly these stories
    (notify.overview_path – at most notify.NEWS_IDS_MAX, else the news list); `ids` unknown or incomplete: the news list.
    `stories` (those of the rest the round read): the line names their highest severity and their products."""
    t = TEXTS[_lang(lang)]
    url = notify.overview_path([], count, [("news", i) for i in ids]) if ids and len(ids) == count else notify.NEWS_PATH
    return {"v": 1, "kind": "summary", "id": f"summary-{int(time.time())}", "title": t["summary"].format(n=count), "body": summary_line(stories or [], lang), "severity": "info", "url": url}


def summary_line(stories: list[dict], lang: str) -> str:
    """ "Höchste Schwere: Kritisch · PAN-OS, FortiOS, Exchange +2" – what a summary is about; "In Cobe News öffnen"
    when nothing is known of them."""
    lang = _lang(lang)
    t, lb = TEXTS[lang], notify.LABELS[lang]
    rated = [s for s in stories if (s.get("notice") or {}).get("rated", True)]
    parts: list[str] = []
    if rated:
        top = max(rated, key=lambda s: SEV_RANK.get(s["severity"], 0))["severity"]
        parts.append(t["summary_top"].format(sev=lb["sev"].get(top, top)))
    names: list[str] = []
    for s in stories:
        for n in [*(s.get("hits") or []), *((s.get("notice") or {}).get("products") or [])]:
            if n not in names:
                names.append(str(n))
    if text := notify.names_text(names):
        parts.append(text)
    return neutral(" · ".join(parts))[:240] if parts else t["summary_text"]


def test_payload(lang: str) -> dict:
    t = TEXTS[_lang(lang)]
    return {"v": 1, "kind": "test", "id": f"test-{int(time.time())}", "title": t["test"], "body": t["test_text"], "severity": "high", "url": "/"}


def _urgency(payload: dict) -> str:
    return "high" if SEV_RANK.get(payload.get("severity", ""), 0) >= 3 else "normal"


async def send(sub: PushSubscription, payload: dict, key: Vapid) -> None:
    """One message to one browser; NotifyError from the HTTP layer (rejected = 404/410: the subscription is gone)."""
    check_endpoint(sub.endpoint)  # again: a row from an older version or written by hand
    ua_public, secret = check_keys(sub.p256dh, sub.auth)
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    if len(data) > PAYLOAD_MAX:
        payload = {**payload, "title": payload["title"][:80], "body": ""}
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    body = encrypt(data, ua_public, secret)
    headers = {
        **vapid_headers(sub.endpoint, key),
        "Content-Type": "application/octet-stream",
        "Content-Encoding": "aes128gcm",
        "TTL": str(TTL),
        "Urgency": _urgency(payload),
        "User-Agent": "Cobe-News",
    }
    await notify.post(sub.endpoint, body, headers, use_proxy=True)


def _failed(sub: PushSubscription, exc: notify.NotifyError) -> dict:
    """The backoff after a failed send – as values (the caller writes them)."""
    failures = (sub.failures or 0) + 1
    wait = timedelta(minutes=2 ** min(failures, 9))
    if exc.retry_after:
        wait = max(wait, timedelta(seconds=exc.retry_after))
    now = datetime.now(UTC)
    return {"failures": failures, "last_error": (f"{exc.category}: {exc.detail}" if exc.detail else exc.category)[:200], "last_error_at": now, "next_try_at": now + min(wait, BACKOFF_MAX)}


async def send_all(sub: PushSubscription, payloads: list[dict], key: Vapid) -> notify.NotifyError | PushError | None:
    """Sends the messages in order – without touching the database (runs in parallel for many browsers), within
    SUB_DEADLINE: a slow push service answer holds up this browser, never the others. None: all went out."""
    try:
        async with asyncio.timeout(SUB_DEADLINE):
            for p in payloads:
                await send(sub, p, key)
    except (notify.NotifyError, PushError) as exc:
        return exc
    except TimeoutError:
        return notify.NotifyError("timeout")
    return None


def _after(sub: PushSubscription, outcome: notify.NotifyError | PushError | None) -> tuple[bool, dict | None]:
    """(sent, the subscription's new values) after a send – None: remove it (404/410, unusable keys, too many failures)."""
    if outcome is None:
        return True, {"failures": 0, "last_error": None, "next_try_at": None, "last_ok_at": datetime.now(UTC)}
    if isinstance(outcome, PushError) or outcome.category == "rejected":
        log.info("push: subscription %s gone at the push service or unusable – removed", sub.id)
        return False, None
    values = _failed(sub, outcome)
    if values["failures"] >= MAX_FAILURES:
        log.info("push: subscription %s failed %s times in a row (%s) – removed", sub.id, values["failures"], values["last_error"])
        return False, None
    log.info("push: subscription %s: %s", sub.id, values["last_error"])
    return False, values


async def settle(db: AsyncSession, sub: PushSubscription, outcome: notify.NotifyError | PushError | None) -> bool:
    """The subscription's state after a send: 404/410 or unusable keys – removed; another error – backoff. True: sent."""
    sent, values = _after(sub, outcome)
    if values is None:
        await db.delete(sub)
    else:
        for k, v in values.items():
            setattr(sub, k, v)
    return sent


async def dispatch(db: AsyncSession) -> dict[str, int]:
    """After each round of feeds: every browser gets what arrived for its person since its cursor."""
    from app import api
    from app import news as news_svc
    from app.models import NewsItem

    if not get_config().web_push:
        return {}
    now = datetime.now(UTC)
    # every subscription, the ones of switched-off accounts too: their cursor moves on (below) – an account switched on
    # again gets what arrives from then on, not the burst of everything since it was switched off
    if await db.scalar(select(PushSubscription.id).limit(1)) is None:
        return {}
    key = await vapid(db)  # first: a key found unreadable removes the subscriptions made for it
    subs = list(await db.scalars(select(PushSubscription).where((PushSubscription.next_try_at.is_(None)) | (PushSubscription.next_try_at <= now))))
    if not subs:
        return {}
    top = await news_svc.last_seq(db)
    sent = failed = 0
    jobs: list[tuple[PushSubscription, list[dict]]] = []
    skip: list[PushSubscription] = []  # nothing to send: their cursor moves on – written after the sending, not before
    for sub in subs:
        if sub.cursor >= top:
            continue
        user = await db.get(User, sub.user_id)
        if user is None or not user.is_active or not (user.desktop or {}).get("enabled"):
            skip.append(sub)  # switched off (the account or its notifications): nothing piles up for later
            continue
        where = [*api.fresh_filter(), NewsItem.seq > sub.cursor, NewsItem.seq <= top, *api.desktop_filter(user.desktop)]
        rows, total = await api.arrived(db, where)
        if not rows:
            skip.append(sub)
            continue
        hit = api.desktop_hits(user.desktop)  # "Treffer" when the person chose systems or words
        single = [(api._item_out(i, s, None) | ({"hits": hit(i)} if hit else {}), i) for i, s in rows[:SINGLE]][::-1]  # the oldest of the newest first, as the tab
        payloads = [story_payload({"id": x["id"], "title": x["title"], "severity": x["severity"], "source": x["source"]["name"], "hits": x.get("hits") or [], "notice": api.notice_facts(i)}, sub.lang) for x, i in single]
        if total > len(single):
            # the rest by id when the round knows them all (rows holds the newest RECENT_MAX)
            rest = [str(i.id) for i, _s in rows[SINGLE:]] if total == len(rows) else None
            others = [{"severity": i.severity, "hits": hit(i) if hit else [], "notice": api.notice_facts(i)} for i, _s in rows[SINGLE:]]
            payloads.append(summary_payload(total - len(single), sub.lang, rest, others))
        jobs.append((sub, payloads))
    gate = asyncio.Semaphore(CONCURRENCY)

    async def one(sub: PushSubscription, payloads: list[dict]) -> notify.NotifyError | PushError | None:
        async with gate:
            return await send_all(sub, payloads, key)

    # the HTTP requests in parallel, the database afterwards (one session is never used by two tasks at once) – and
    # nothing pending or open while they run. What is not done by ROUND_DEADLINE is cancelled: a timeout for its browser.
    await dbm.release(db)
    tasks = [asyncio.create_task(one(s, p)) for s, p in jobs]
    if tasks:
        _done, late = await asyncio.wait(tasks, timeout=ROUND_DEADLINE)
        for t in late:
            t.cancel()
        await asyncio.gather(*late, return_exceptions=True)
    results = [t.result() if not t.cancelled() and t.exception() is None else notify.NotifyError("timeout") for t in tasks]
    # written row by row with Core statements, not through the loaded objects: a browser unsubscribed (or taken over,
    # or its person deleted) while the round was sending is simply no longer there (0 rows) – with the ORM its missing
    # row failed the whole commit and rolled back every other browser's cursor (they got the same pushes again)
    if skip:
        await db.execute(update(PushSubscription).where(PushSubscription.id.in_([s.id for s in skip])).values(cursor=top))
    for (sub, _), outcome in zip(jobs, results, strict=True):
        ok, values = _after(sub, outcome)
        if values is None:
            await db.execute(delete(PushSubscription).where(PushSubscription.id == sub.id))
        else:
            await db.execute(update(PushSubscription).where(PushSubscription.id == sub.id).values(**values, **({"cursor": top} if ok else {})))
        sent, failed = sent + ok, failed + (not ok)
    await db.commit()
    for sub in subs:
        if sub in db:
            db.expunge(sub)  # the loaded copies are stale now – never written back by a later flush
    return {"sent": sent, "failed": failed} if sent or failed else {}


async def subscribe(db: AsyncSession, user: User, endpoint: str, p256dh: str, auth: str, lang: str, label: str) -> PushSubscription:
    """Adds this browser (or takes it over: the same endpoint under another person – a shared computer – is now theirs).
    The cursor starts now: no backlog."""
    from app import news as news_svc

    endpoint = check_endpoint(endpoint)
    check_keys(p256dh, auth)
    top = await news_svc.last_seq(db)
    # INSERT … ON CONFLICT, then the row locked: two tabs of one browser subscribing at the same moment (same endpoint)
    # both end up with that one row – before, the second INSERT hit the unique endpoint (HTTP 500)
    await db.execute(
        pg_insert(PushSubscription)
        .values(id=uuid.uuid4(), user_id=user.id, endpoint=endpoint, p256dh=p256dh, auth=auth, cursor=top)
        .on_conflict_do_nothing(index_elements=[PushSubscription.endpoint])
    )
    sub = await db.scalar(select(PushSubscription).where(PushSubscription.endpoint == endpoint).with_for_update().execution_options(populate_existing=True))
    if sub.user_id != user.id:
        sub.user_id, sub.cursor = user.id, top
    sub.p256dh, sub.auth, sub.lang, sub.label = p256dh, auth, _lang(lang), label[:100]
    sub.failures, sub.last_error, sub.next_try_at = 0, None, None
    await db.flush()
    mine = list(await db.scalars(select(PushSubscription.id).where(PushSubscription.user_id == user.id).order_by(PushSubscription.created_at.desc())))
    if len(mine) > PER_USER:
        await db.execute(delete(PushSubscription).where(PushSubscription.id.in_(mine[PER_USER:])))
    await db.commit()
    return sub
