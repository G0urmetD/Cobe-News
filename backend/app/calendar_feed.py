"""The calendar feed (iCal, RFC 5545): one all-day event per version entered at the day its support ends, with reminders
90 and 30 days before – product, version, the date and a link to Cobe News. No CVE details, no names of people (not
the version's label either: an admin may write anything there).

Calendar clients (Outlook, Apple, Google) send no cookie, so the address carries a secret of its own:

- **The token.** 256 bits (crypto.new_token), shown once when made; the database keeps only its keyed hash
  (crypto.token_hash – the session tokens' HMAC with the master key). One per person: a new one ends the old one
  (the row is replaced), deleting it ends the address. A token that is not found answers 404 – the same for a
  wrong, a replaced, a deleted one and that of an account switched off (which also deletes it).
- **Fresh checks.** Each request reads the account again: switched off → 404 (and the address goes for good); the
  role and the teams decide what is in it now – an admin sees every followed product's versions, a reader those of
  the products their team routing gives them (Teams on); nothing else.
- **No side effects.** A GET outside /api/ (no CSRF needed – it changes nothing but when the address was last used,
  at most once an hour); answers `Cache-Control: no-store, private`, `X-Robots-Tag: noindex`; the app writes no access
  log line for it (the bundled nginx neither: deploy/nginx, location /cal/), so the token is in no log of ours.
- **Rate limits** (in-process): per client address at most IP_MAX requests per WINDOW, unknown tokens at most
  FAIL_MAX per WINDOW (then 429 for the rest of the window); per token at most TOKEN_MAX per WINDOW.
"""

import re
import time
import unicodedata
from datetime import UTC, date, datetime, timedelta
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Request, Response
from sqlalchemy import delete, select

from app import teams
from app.auth import bruteforce
from app.config import get_config
from app.crypto import new_token, token_hash
from app.deps import Db, Reader, client_ip
from app.models import CalendarFeed, PersonNotify, TeamProduct, User, VendorFollow

router = APIRouter(tags=["calendar"])
api = APIRouter(prefix="/api/me/calendar", tags=["calendar"])

PATH = "/cal/"
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}\.ics$")  # token_urlsafe(32) and the suffix
WINDOW = 600.0  # s
IP_MAX = 300  # requests of one address per WINDOW (Outlook on the web fetches from Microsoft's few addresses)
FAIL_MAX = 20  # unknown tokens of one address per WINDOW
TOKEN_MAX = 30  # requests of one token per WINDOW (a few devices polling every few minutes at most)
TOUCH_EVERY = timedelta(hours=1)
ALARMS = (90, 30)
LINE = 75  # octets of a content line (RFC 5545 3.1), without CRLF
MAX_ENTRIES = 5000
_hits: dict[str, list[float]] = {}

TEXT = {
    "de": {
        "cal": "Cobe News – Support-Ende",
        "summary": "Support-Ende: {product} {version}",
        "alarm": "Support-Ende in {days} Tagen: {product} {version}",
        "desc": "Produkt: {product}\nVersion: {version}\nRelease-Linie: {line}\nSupport-Ende: {date}\nIn Cobe News: {url}",
    },
    "en": {
        "cal": "Cobe News – end of support",
        "summary": "End of support: {product} {version}",
        "alarm": "End of support in {days} days: {product} {version}",
        "desc": "Product: {product}\nVersion: {version}\nRelease line: {line}\nEnd of support: {date}\nIn Cobe News: {url}",
    },
}


def reset() -> None:
    _hits.clear()


def _limited(key: str, limit: int, now: float, *, count: bool = True) -> bool:
    """Whether `key` had `limit` hits within WINDOW (sliding) – and, with `count`, one more now."""
    hits = [t for t in _hits.get(key, ()) if now - t < WINDOW]
    over = len(hits) >= limit
    if count and not over:
        hits.append(now)
    if hits:
        _hits[key] = hits
    else:
        _hits.pop(key, None)
    if len(_hits) > 20000:  # a flood of addresses: the oldest half goes (bounded memory)
        for k in list(_hits)[:10000]:
            _hits.pop(k, None)
    return over


# ---------------------------------------------------------------- RFC 5545


_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u2028\u2029]")


def escape(value: object) -> str:
    """A TEXT value (RFC 5545 3.3.11): backslash, semicolon, comma escaped, every line break as \\n, other control
    characters gone – nothing in it can end the line or start a property of its own."""
    s = unicodedata.normalize("NFC", str(value)).replace("\r\n", "\n").replace("\r", "\n")
    s = _CTRL.sub("", s)
    return s.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def fold(line: str) -> bytes:
    """One content line, folded at LINE octets (RFC 5545 3.1): CRLF and a space before each continuation, never inside
    a UTF-8 character. Ends with CRLF."""
    raw = line.encode("utf-8")
    out: list[bytes] = []
    limit = LINE
    while len(raw) > limit:
        cut = limit
        while cut > 0 and (raw[cut] & 0xC0) == 0x80:  # a continuation byte: cut before its character
            cut -= 1
        out.append(raw[:cut])
        raw = raw[cut:]
        limit = LINE - 1  # the leading space counts
    out.append(raw)
    return b"\r\n ".join(out) + b"\r\n"


def _stamp(d: datetime) -> str:
    return d.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def render(entries: list[dict], lang: str, host: str) -> bytes:
    """The calendar: entries {id, product, version, line, date, url, stamp}. Pure (the tests parse it)."""
    lb = TEXT.get(lang, TEXT["de"])
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Cobe News//EOL calendar//" + ("DE" if lang == "de" else "EN"),
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        f"X-WR-CALNAME:{escape(lb['cal'])}",
        "X-PUBLISHED-TTL:PT6H",
        "REFRESH-INTERVAL;VALUE=DURATION:PT6H",
    ]
    for e in entries:
        day: date = e["date"]
        product, version = e["product"], e["version"]
        summary = lb["summary"].format(product=product, version=version)
        desc = lb["desc"].format(product=product, version=version, line=e.get("line") or "–", date=day.isoformat(), url=e["url"])
        lines += [
            "BEGIN:VEVENT",
            f"UID:eol-{e['id']}@{host}",
            f"DTSTAMP:{_stamp(e['stamp'])}",
            f"DTSTART;VALUE=DATE:{day.strftime('%Y%m%d')}",
            f"DTEND;VALUE=DATE:{(day + timedelta(days=1)).strftime('%Y%m%d')}",
            f"SUMMARY:{escape(summary)}",
            f"DESCRIPTION:{escape(desc)}",
            f"URL:{e['url']}",
            "TRANSP:TRANSPARENT",
            "CLASS:PRIVATE",
        ]
        for days in ALARMS:
            lines += ["BEGIN:VALARM", "ACTION:DISPLAY", f"DESCRIPTION:{escape(lb['alarm'].format(days=days, product=product, version=version))}", f"TRIGGER:-P{days}D", "END:VALARM"]
        lines.append("END:VEVENT")
    lines.append("END:VCALENDAR")
    return b"".join(fold(x) for x in lines)


# ---------------------------------------------------------------- what is in a person's feed


async def entries(db: Db, user: User) -> list[dict]:
    """The versions entered of the person's products with a known end of support: an admin's – every followed product;
    a reader's – the products their team routing gives them (Teams on), else none. Read fresh on every request."""
    from app import vendor

    q = select(VendorFollow).where(VendorFollow.enabled.is_(True))
    if user.role != "admin":
        if not await teams.is_on(db):
            return []
        q = q.where(VendorFollow.id.in_(select(TeamProduct.follow_id).where(teams.mine_clause(user.id))))
    fs = list(await db.scalars(q.order_by(VendorFollow.created_at)))
    vers = await vendor.versions_of(db, [f.id for f in fs])
    base = get_config().base_url
    out: list[dict] = []
    for f in fs:
        p = vendor.product_of(f)
        if p is None:
            continue
        for v in vers.get(f.id, []):
            info = vendor.release_info(p, v.version) or {}
            line = info.get("line") or {}
            try:
                day = date.fromisoformat(str(line.get("eol_from") or "")[:10])
            except ValueError:
                continue
            url = f"{base}/vendor?{urlencode({'product': f.product, 'view': 'versions'})}"
            out.append({"id": str(v.id), "product": str(p.get("label") or f.product), "version": v.version, "line": str(line.get("label") or line.get("name") or ""), "date": day, "url": url, "stamp": v.updated_at or v.created_at})
            if len(out) >= MAX_ENTRIES:
                return out
    out.sort(key=lambda e: (e["date"], e["product"].lower(), e["version"]))
    return out


def feed_url(token: str) -> str:
    return f"{get_config().base_url}{PATH}{token}.ics"


# ---------------------------------------------------------------- the person's address (API, cookie and CSRF as usual)


@api.get("")
async def get_mine(user: Reader, db: Db) -> dict:
    row = await db.get(CalendarFeed, user.id)
    scope = "all" if user.role == "admin" else "teams"
    return {
        "active": row is not None,
        "created_at": row.created_at.isoformat() if row else None,
        "last_used_at": row.last_used_at.isoformat() if row and row.last_used_at else None,
        "scope": scope,
        "teams_on": await teams.is_on(db),
        "entries": len(await entries(db, user)),
    }


@api.post("")
async def make_mine(user: Reader, db: Db) -> dict:
    """A new address – the old one (if any) stops working at once. The token is in this answer only."""
    token = new_token(32)
    now = datetime.now(UTC)
    await db.execute(delete(CalendarFeed).where(CalendarFeed.user_id == user.id))
    db.add(CalendarFeed(user_id=user.id, token_hash=token_hash(token), created_at=now))
    await db.commit()
    return {"url": feed_url(token), "created_at": now.isoformat()}


@api.delete("")
async def delete_mine(user: Reader, db: Db) -> dict:
    res = await db.execute(delete(CalendarFeed).where(CalendarFeed.user_id == user.id))
    await db.commit()
    return {"removed": bool(res.rowcount)}


# ---------------------------------------------------------------- the feed itself (no cookie: the token)

_HEADERS = {"Cache-Control": "no-store, private", "X-Robots-Tag": "noindex, nofollow", "Referrer-Policy": "no-referrer"}


def _nope(status: int = 404, retry: int | None = None) -> Response:
    h = dict(_HEADERS)
    if retry:
        h["Retry-After"] = str(retry)
    return Response("not found\n" if status == 404 else "too many requests\n", status_code=status, media_type="text/plain", headers=h)


@router.get(PATH + "{name}", include_in_schema=False)
async def feed(name: str, request: Request, db: Db) -> Response:
    now = time.monotonic()
    ip = bruteforce.source_key(client_ip(request))  # IPv6 per /64, as the sign-in's counters
    if _limited(f"fail:{ip}", FAIL_MAX, now, count=False) or _limited(f"ip:{ip}", IP_MAX, now):
        return _nope(429, int(WINDOW))
    if not TOKEN_RE.fullmatch(name):
        _limited(f"fail:{ip}", FAIL_MAX, now)
        return _nope()
    digest = token_hash(name[:-4])
    if _limited(f"tok:{digest}", TOKEN_MAX, now):
        return _nope(429, int(WINDOW))
    row = await db.scalar(select(CalendarFeed).where(CalendarFeed.token_hash == digest))
    user = await db.get(User, row.user_id) if row is not None else None
    if row is None or user is None:
        _limited(f"fail:{ip}", FAIL_MAX, now)
        return _nope()
    if not user.is_active:
        # switched off: the address ends for good (switched on again, the person makes a new one)
        await db.execute(delete(CalendarFeed).where(CalendarFeed.user_id == user.id))
        await db.commit()
        return _nope()
    p = await db.get(PersonNotify, user.id)
    lang = p.lang if p is not None and p.lang in TEXT else "de"
    items = await entries(db, user)
    stamp = datetime.now(UTC)
    if row.last_used_at is None or stamp - row.last_used_at >= TOUCH_EVERY:
        row.last_used_at = stamp
        await db.commit()
    host = urlsplit(get_config().base_url).hostname or "cobe-news"
    body = render(items, lang, host)
    return Response(body, media_type="text/calendar; charset=utf-8", headers={**_HEADERS, "Content-Disposition": 'inline; filename="cobe-news-eol.ics"'})
