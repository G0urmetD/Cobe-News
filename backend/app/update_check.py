"""Update notice: admins see a small hint when a newer Cobe News release is published ("Version 0.1.48 verfügbar –
Changelog", linking to the release on GitHub). Readers see nothing.

- One request to GitHub's public release API (RELEASE_API, unauthenticated) every EVERY (12 hours) at most – also
  after a failure –, conditional (ETag: an unchanged answer is a 304 that does not count against GitHub's limit of 60
  requests an hour), a short timeout, a small size cap, through the hardened download (news.download: the egress
  guard, https only, redirects only on api.github.com). Sent: the request itself (Cobe News' User-Agent with its
  version, as every fetch sends) – nothing about the installation, its data or its people.
- Only a final release counts: drafts, pre-releases and tags that are no plain x.y.z are ignored; newer means a higher
  version number than app.__version__ (semver, numeric).
- Switch: settings "updates" {"check": True} (the admin page "Über Cobe News"). Off: no request at all, no notice.
- Closed per admin and release (update_dismissals): a newer release shows the notice again.
- /metrics: cobe_news_update_available (1 / 0 / NaN – not checked yet or switched off).

The state of the last check is kept in the settings row "updates_state" (latest version, ETag, when, the error)."""

import asyncio
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from fastapi import APIRouter
from pydantic import ConfigDict, Field
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__, audit, db
from app import settings as settings_store
from app.config import get_config, tls_verify
from app.deps import Admin, Db, NoNul
from app.models import UpdateDismissal
from app.news import NewsError

log = logging.getLogger("cobe_news.update_check")

REPO = "G0urmetD/Cobe-News"
RELEASE_API = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASE_PAGE = f"https://github.com/{REPO}/releases/tag/"
SECTION = "updates"  # {"check": bool, "rev"}
STATE = "updates_state"  # {"checked_at", "etag", "latest", "tag", "published_at", "error"}
EVERY = timedelta(hours=12)
TIMEOUT_S = 10.0
LIMIT = 256 * 1024
TICK_S = 600.0
VERSION = re.compile(r"^v?(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$")
transport = None  # tests: an httpx.MockTransport – never the real GitHub

router = APIRouter(prefix="/api/admin/update", tags=["admin"])


def parse_version(text: object) -> tuple[int, int, int] | None:
    """"0.1.48" or "v0.1.48" → (0, 1, 48); anything else (a pre-release "0.1.48-rc1", "latest", garbage) → None."""
    m = VERSION.match(str(text or "").strip()) if isinstance(text, str) else None
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def newer(latest: str | None, current: str = __version__) -> bool:
    a, b = parse_version(latest), parse_version(current)
    return a is not None and b is not None and a > b


def parse_release(body: bytes) -> dict | None:
    """GitHub's "latest release": {version, tag, published_at} – None for a draft, a pre-release or a tag that is no
    plain x.y.z. Raises NewsError("format") for an answer that is no release at all."""
    try:
        doc = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise NewsError("format", "no JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("tag_name"), str):
        raise NewsError("format", "no release")
    if doc.get("draft") or doc.get("prerelease"):
        return None
    tag = doc["tag_name"].strip()
    v = parse_version(tag)
    if v is None:
        return None
    pub = doc.get("published_at")
    return {"version": ".".join(map(str, v)), "tag": tag, "published_at": pub[:40] if isinstance(pub, str) else None}


def release_url(tag: str) -> str:
    """Our own link to the release, from the validated tag (never a URL taken from the answer)."""
    return RELEASE_PAGE + (tag if VERSION.match(tag) else "")


def _only(url: str) -> bool:
    return (urlsplit(url).hostname or "") == "api.github.com"


def _parse_at(v: object) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(v))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


async def enabled(s: AsyncSession) -> bool:
    return bool((await settings_store.get(s, SECTION)).get("check", True))


def due(state: dict, now: datetime) -> bool:
    at = _parse_at(state.get("checked_at"))
    return at is None or now - at >= EVERY or at > now + timedelta(minutes=5)


async def check(s: AsyncSession, *, now: datetime | None = None) -> dict:
    """Asks GitHub when the check is on and due (EVERY); the state afterwards (committed)."""
    from app import news as news_svc

    now = now or datetime.now(UTC)
    state = await settings_store.get(s, STATE)
    if not await enabled(s) or not due(state, now):
        await s.commit()
        return state
    new = {**state, "checked_at": now.isoformat(), "error": None}
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if state.get("etag") and state.get("latest"):
        headers["If-None-Match"] = str(state["etag"])
    await s.commit()  # nothing held open while GitHub answers
    try:
        async with asyncio.timeout(TIMEOUT_S):
            got = await news_svc.download(RELEASE_API, proxy=get_config().proxy, verify=tls_verify(), headers=headers, limit=LIMIT, transport=transport, only=_only)
        if got.status == 304:
            pass  # unchanged
        elif got.status == 404:
            new |= {"latest": None, "tag": None, "published_at": None, "etag": None}  # no release published (yet)
        elif got.status >= 300:
            raise NewsError("rate_limited" if got.status in (403, 429) else "http", f"HTTP {got.status}")
        else:
            rel = parse_release(got.body)
            etag = (got.headers.get("etag") or "")[:200] or None
            if rel is None:  # a pre-release or a draft marked latest: nothing to offer
                new |= {"latest": None, "tag": None, "published_at": None, "etag": etag}
            else:
                new |= {"latest": rel["version"], "tag": rel["tag"], "published_at": rel["published_at"], "etag": etag}
    except (NewsError, TimeoutError) as exc:
        err = f"{exc.category}: {exc.detail}" if isinstance(exc, NewsError) else "timeout"
        new["error"] = err[:200]
        log.info("update check: %s", new["error"])
    await settings_store.put(s, STATE, new)
    await s.commit()
    return new


async def status(s: AsyncSession, user_id=None) -> dict:  # noqa: ANN001
    """What the admin's notice shows: on, current and latest version, the release link, whether it is newer and
    whether this admin closed it."""
    on = await enabled(s)
    state = await settings_store.get(s, STATE)
    latest = state.get("latest") if on else None
    available = newer(latest)
    dismissed = False
    if available and user_id is not None:
        row = await s.get(UpdateDismissal, user_id)
        dismissed = row is not None and row.version == latest
    return {
        "enabled": on,
        "current": __version__,
        "latest": latest,
        "available": available,
        "ahead": newer(__version__, latest) if latest else False,  # this installation is newer than the latest release (built before its tag)
        "dismissed": dismissed,
        "url": release_url(str(state.get("tag") or "")) if available else None,
        "published_at": state.get("published_at") if available else None,
        "checked_at": state.get("checked_at") if on else None,
        "error": state.get("error") if on else None,
        "rev": int((await settings_store.get(s, SECTION)).get("rev") or 0),
    }


async def available_metric(s: AsyncSession) -> bool | None:
    """/metrics: True / False – None while switched off or not checked yet."""
    if not await enabled(s):
        return None
    state = await settings_store.get(s, STATE)
    if not state.get("checked_at") or (state.get("error") and not state.get("latest")):
        return None
    return newer(state.get("latest"))


class Loop:
    """Looks every TICK_S whether a check is due (the check itself keeps to EVERY)."""

    async def run(self) -> None:
        await asyncio.sleep(90)  # not in the first minute after a start
        while True:
            try:
                async with db.session() as s:
                    await check(s)
            except Exception:  # noqa: BLE001 - one bad look must not end the loop
                log.exception("update check failed")
            await asyncio.sleep(TICK_S)


# ---------------------------------------------------------------- admin API (cookie, CSRF as usual)


@router.get("")
async def get_status(admin: Admin, db_: Db) -> dict:
    return await status(db_, admin.id)


class DismissIn(NoNul):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(max_length=20)


@router.post("/dismiss")
async def dismiss(body: DismissIn, admin: Admin, db_: Db) -> dict:
    """Closes the notice for this admin and this release (a newer one shows it again)."""
    v = parse_version(body.version)
    if v is None:
        from app.deps import api_error

        raise api_error(422, "invalid", errors="version x.y.z")
    text_ = ".".join(map(str, v))
    stmt = pg_insert(UpdateDismissal).values(user_id=admin.id, version=text_, dismissed_at=datetime.now(UTC))
    await db_.execute(stmt.on_conflict_do_update(index_elements=["user_id"], set_={"version": stmt.excluded.version, "dismissed_at": stmt.excluded.dismissed_at}))
    await db_.commit()
    return await status(db_, admin.id)


class SettingsIn(NoNul):
    model_config = ConfigDict(extra="forbid")

    check: bool
    rev: int | None = None


@router.put("/settings")
async def put_settings(body: SettingsIn, admin: Admin, db_: Db) -> dict:
    cur = await settings_store.get(db_, SECTION)
    value = {"check": body.check}
    if changes := audit.diff(cur, value, value.keys()):
        audit.record(db_, admin, "settings.changed", audit.target("settings", SECTION, SECTION), {"changes": changes})
    await settings_store.put_rev(db_, SECTION, value, body.rev)
    return await status(db_, admin.id)
