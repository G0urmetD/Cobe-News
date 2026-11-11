"""The signed-in person's own notifications about the Vendor News of their products (app/personal.py): e-mail to the
own address, desktop push to the own browsers, a Microsoft Teams Workflows webhook of their own. Only the own
settings – there is no id in any path. The Teams URL is taken, checked and stored encrypted; it is never sent back
(only its host)."""

import time
import uuid
from datetime import UTC, date, datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Query
from pydantic import ConfigDict, Field
from sqlalchemy import func, select, update

from app import absence, concerns, notify, personal, quiet, teams, weekly
from app import systems as systems_svc
from app import settings as settings_store
from app.quiet import DEFAULT_TZ, DEFAULT_URGENT
from app.config import get_config
from app.crypto import encrypt_str
from app.deps import Db, NoNul, Reader, api_error
from app.models import CveWatch, PersonNews, PersonNotify, PushSubscription

router = APIRouter(prefix="/api/me/vendor-notify", tags=["personal"])
TEST_EVERY = 10.0  # as the push test
_last_test: dict[str, float] = {}


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


async def _available(db: Db, user) -> str | None:  # noqa: ANN001
    """None – or why the section is not there: Teams off (an admin allows the ways there), or the person in no team and
    watching no CVE (a watched CVE needs no team – its ways are there for anybody who watches one)."""
    if not await teams.is_on(db):
        return "teams_off"
    if not await personal.in_team(db, user.id) and not await db.scalar(select(CveWatch.cve).where(CveWatch.user_id == user.id).limit(1)):
        return "no_team"
    return None


async def _out(db: Db, user, p: PersonNotify | None) -> dict:  # noqa: ANN001
    why = await _available(db, user)
    ways = await personal.allowed(db)
    devices = await db.scalar(select(func.count()).select_from(PushSubscription).where(PushSubscription.user_id == user.id)) or 0
    address = user.email or ""
    in_team = await personal.in_team(db, user.id)
    return {
        "available": why is None,
        "reason": why,
        "in_team": in_team,
        "allowed": ways,
        "web_push": get_config().web_push,
        "products": await personal.products_of(db, user.id) if why is None else [],
        "lang": p.lang if p else "de",
        "kinds": list(p.kinds) if p else list(personal.DEFAULT_KINDS),
        "min_severity": p.min_severity if p else "info",
        "systems": personal.person_systems(p),
        "email": {"on": bool(p and p.email_on), "address": address or None, "address_ok": bool(address and teams.MAIL.fullmatch(address)), "state": personal.state_out(p, "email")},
        "desktop": {"on": bool(p and p.desktop_on), "devices": int(devices), "state": personal.state_out(p, "desktop")},
        "teams": {"on": bool(p and p.teams_on), "url_set": bool(p and p.teams_url_enc), "url_hint": personal.masked(p), "state": personal.state_out(p, "teams")},
        # 0.1.35: quiet hours and what is urgent (app/quiet.py), the absence and whom the person stands in for
        # (app/absence.py), the weekly review of the own teams (app/weekly.py)
        "schedule": quiet.out(p.schedule if p else None),
        "absence": (await absence.views(db, [user.id])).get(user.id) if in_team else None,
        "covering": await absence.covering(db, user.id) if in_team else [],
        "weekly": {
            "on": bool(p and p.weekly_on),
            "teams": await weekly.mine(db, user.id) if in_team else [],
            "address_ok": bool(address and teams.MAIL.fullmatch(address)),
            "smtp_ready": weekly.smtp_ready(await settings_store.get(db, "smtp")),
        },
    }


@router.get("")
async def get_mine(user: Reader, db: Db) -> dict:
    return await _out(db, user, await db.get(PersonNotify, user.id))


class MineIn(_M):
    email_on: bool = False
    desktop_on: bool = False
    teams_on: bool = False
    kinds: list[Literal["vendor_vuln", "vendor_version", "vendor_change"]] = Field(min_length=1, max_length=3)
    min_severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    # 0.1.54: only the Vendor News of these systems (a catalogue vendor – each of its products – or a product, as a
    # channel rule's; app/concerns.py) – empty: every product of my teams; None (not sent – an older page): kept
    systems: list[concerns.SystemIn] | None = Field(default=None, max_length=systems_svc.ENTRIES_MAX)
    lang: Literal["de", "en"] = "de"
    # None: the stored URL stays; "": removed (and the way off); otherwise a new one (checked)
    teams_url: str | None = Field(default=None, max_length=personal.URL_MAX)


async def _row(db: Db, user) -> PersonNotify:  # noqa: ANN001
    p = await db.get(PersonNotify, user.id)
    if p is None:
        p = PersonNotify(user_id=user.id, kinds=list(personal.DEFAULT_KINDS), min_severity="info", state_email={}, state_desktop={}, state_teams={}, schedule={}, weekly_on=False)
        db.add(p)
    return p


@router.put("")
async def put_mine(body: MineIn, user: Reader, db: Db) -> dict:
    why = await _available(db, user)
    if why is not None:
        raise api_error(409, why)
    ways = await personal.allowed(db)
    p = await _row(db, user)
    now = datetime.now(UTC)
    if body.teams_url is not None:
        if body.teams_url == "":
            p.teams_url_enc, p.teams_host = None, None
            # the person's one Teams URL: its way is off for the security stories as well (app/personal_news.py)
            await db.execute(update(PersonNews).where(PersonNews.user_id == user.id).values(teams_on=False).execution_options(synchronize_session=False))
        else:
            try:
                url = personal.check_teams_url(body.teams_url)
            except notify.NotifyError as exc:
                raise api_error(422, f"teams_url_{exc.category}") from exc
            p.teams_url_enc, p.teams_host = encrypt_str(url), (urlsplit(url).hostname or "").lower()
        p.state_teams = {}  # another target: its old error and pause do not count
    want = {"email": body.email_on, "desktop": body.desktop_on, "teams": body.teams_on}
    for way, on in want.items():
        was = bool(getattr(p, f"{way}_on"))
        if on and not was:
            if not ways[way]:
                raise api_error(409, "way_off", way=way)  # the admin has not allowed it
            if way == "email" and not (user.email and teams.MAIL.fullmatch(user.email)):
                raise api_error(409, "no_address")
            setattr(p, f"{way}_since", now)  # only what comes from now on
            setattr(p, f"state_{way}", {})
        if way == "teams" and on and not p.teams_url_enc:
            raise api_error(422, "teams_url_required")
        setattr(p, f"{way}_on", on)
    p.kinds = [k for k in personal.KINDS if k in body.kinds]
    p.min_severity = body.min_severity
    if body.systems is not None:
        chosen = concerns.dedupe([x.entry() for x in body.systems])
        if systems_svc.has_ours(chosen):
            # "Unsere Produkte" here would be every product of the person's teams – Vendor News is about followed
            # products only: what "leer" says already
            raise api_error(422, "invalid", errors="systems: ours is for news")
        concerns.check_known(chosen, personal.person_systems(p))
        p.systems = chosen
    p.lang = body.lang
    p.updated_at = now
    await db.commit()
    return await _out(db, user, p)


@router.post("/teams/test")
async def test_teams(user: Reader, db: Db) -> dict:
    """A test card to the own stored Teams URL – the way the real ones take (rate-limited as the push test)."""
    why = await _available(db, user)
    if why is not None:
        raise api_error(409, why)
    if not (await personal.allowed(db))["teams"]:
        raise api_error(409, "way_off", way="teams")
    p = await db.get(PersonNotify, user.id)
    if p is None or not p.teams_url_enc:
        raise api_error(422, "teams_url_required")
    now = time.monotonic()
    if now - _last_test.get(str(user.id), -1e9) < TEST_EVERY:
        raise api_error(429, "rate_limited")
    _last_test[str(user.id)] = now
    if len(_last_test) > 1000:
        _last_test.clear()
    try:
        await personal.send_teams_test(db, p)
    except notify.NotifyError as exc:
        return {"ok": False, "error": exc.category, "detail": exc.detail}  # as a channel's test: the category, never the URL
    return {"ok": True}


# ---------------------------------------------------------------- quiet hours and urgent (app/quiet.py)

HM = r"^([01][0-9]|2[0-3]):[0-5][0-9]$"
Urgent = Literal["critical", "kev", "affected", "watch"]


class DailyIn(_M):
    email: str | None = Field(default=None, pattern=HM)
    desktop: str | None = Field(default=None, pattern=HM)
    teams: str | None = Field(default=None, pattern=HM)


class ScheduleIn(_M):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, populate_by_name=True)
    quiet: bool = False
    from_: str = Field(default="18:00", alias="from", pattern=HM)
    to: str = Field(default="08:00", pattern=HM)
    weekends: bool = False
    tz: str = Field(default=DEFAULT_TZ, min_length=1, max_length=64)
    urgent: list[Urgent] = Field(default_factory=lambda: list(DEFAULT_URGENT), max_length=4)
    daily: DailyIn = Field(default_factory=DailyIn)


@router.put("/schedule")
async def put_schedule(body: ScheduleIn, user: Reader, db: Db) -> dict:
    """Quiet hours (a window and/or the weekend), what passes them at once, per way "at once" or "collected at HH:MM"."""
    why = await _available(db, user)
    if why is not None:
        raise api_error(409, why)
    if not quiet.valid_tz(body.tz):
        raise api_error(422, "invalid_tz")
    if body.quiet and body.from_ == body.to and not body.weekends:
        raise api_error(422, "quiet_empty")
    p = await _row(db, user)
    p.schedule = quiet.clean({"quiet": body.quiet, "from": body.from_, "to": body.to, "weekends": body.weekends, "tz": body.tz, "urgent": body.urgent, "daily": body.daily.model_dump()})
    p.updated_at = datetime.now(UTC)
    await db.commit()
    return await _out(db, user, p)


# ---------------------------------------------------------------- weekly review (app/weekly.py)


class WeeklyIn(_M):
    on: bool


@router.put("/weekly")
async def put_weekly(body: WeeklyIn, user: Reader, db: Db) -> dict:
    """The weekly review of the own teams by e-mail, for me – from the next week's time on."""
    why = await _available(db, user)
    if why is not None:
        raise api_error(409, why)
    if not await personal.in_team(db, user.id):
        raise api_error(409, "no_team")
    if body.on and not (user.email and teams.MAIL.fullmatch(user.email)):
        raise api_error(409, "no_address")
    p = await _row(db, user)
    if body.on and not p.weekly_on:
        p.weekly_since = datetime.now(UTC)
    p.weekly_on = body.on
    p.updated_at = datetime.now(UTC)
    await db.commit()
    return await _out(db, user, p)


# ---------------------------------------------------------------- absence with a deputy (app/absence.py)


class AbsenceIn(_M):
    start: date
    end: date
    deputy_id: uuid.UUID
    also_me: bool = False


async def _in_team(db: Db, user) -> None:  # noqa: ANN001
    why = await _available(db, user)
    if why is not None:
        raise api_error(409, why)
    if not await personal.in_team(db, user.id):
        raise api_error(409, "no_team")


@router.get("/deputies")
async def my_deputies(user: Reader, db: Db, q: Annotated[str, Query(max_length=100)] = "") -> dict:
    """Who can stand in for me: the active members of the teams that give me a product (never anybody else)."""
    await _in_team(db, user)
    return {"items": await absence.deputies(db, user.id, q)}


@router.put("/absence")
async def put_absence(body: AbsenceIn, user: Reader, db: Db) -> dict:
    await _in_team(db, user)
    try:
        await absence.put(db, user.id, body.start, body.end, body.deputy_id, body.also_me)
    except absence.AbsenceError as exc:
        raise api_error(exc.status, exc.code) from exc
    await db.commit()
    return await _out(db, user, await db.get(PersonNotify, user.id))


@router.delete("/absence")
async def delete_absence(user: Reader, db: Db) -> dict:
    """Back early (a running absence ends now) or not away after all (a planned one goes)."""
    await _in_team(db, user)
    await absence.end(db, user.id)
    await db.commit()
    return await _out(db, user, await db.get(PersonNotify, user.id))
