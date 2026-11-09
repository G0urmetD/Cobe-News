"""The signed-in person's own security stories by e-mail or their Teams Workflows webhook (app/personal_news.py): the
choice (as a channel rule's), the two ways on/off and their last delivery. Only the own settings – there is no id in
any path or body. The Teams URL is the person's one (person_notify, as for "Hersteller-News meiner Produkte"): taken,
checked and stored encrypted, never sent back (only its host)."""

import uuid
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter
from pydantic import Field

from app import concerns, notify, personal, personal_news, teams
from app import news as news_svc
from app import systems as systems_svc
from app.crypto import encrypt_str
from app.deps import Db, Reader, api_error
from app.models import PersonNews, PersonNotify

router = APIRouter(prefix="/api/me/news-notify", tags=["personal"])
Severity = Literal["critical", "high", "medium", "low", "info"]
Topic = Literal["zeroday", "exploited", "poc", "ransomware", "nopatch", "breach", "supply", "phishing", "ot"]  # news.TOPICS


async def _why(db: Db) -> str | None:
    """None – or why the section is not there: Teams off, or the admin has not allowed the security stories (or neither
    of their ways)."""
    conf = await teams.config(db)
    if not conf.get("enabled"):
        return "teams_off"
    if not any((await personal_news.allowed(db)).values()):
        return "news_off"
    return None


def _words(v) -> list[str]:  # noqa: ANN001
    return [str(x) for x in v or [] if str(x).strip()]


async def _out(db: Db, user, p: PersonNews | None) -> dict:  # noqa: ANN001
    n = await db.get(PersonNotify, user.id)
    address = user.email or ""
    return {
        "available": (why := await _why(db)) is None,
        "reason": why,
        "allowed": await personal_news.allowed(db),
        "lang": p.lang if p else "de",
        "severities": list(p.severities) if p else ["critical", "high"],
        "sources": [str(x) for x in p.sources or []] if p else [],
        "topics": [t for t in news_svc.TOPICS if t in (p.topics or [])] if p else [],
        "systems": systems_svc.entries(p.systems) if p else [],
        "keywords": _words(p.keywords) if p else [],
        "exclude": _words(p.exclude) if p else [],
        "email": {"on": bool(p and p.email_on), "address": address or None, "address_ok": bool(address and teams.MAIL.fullmatch(address)), "state": personal_news.state_out(p, "email")},
        "teams": {"on": bool(p and p.teams_on), "url_set": bool(n and n.teams_url_enc), "url_hint": personal.masked(n), "state": personal_news.state_out(p, "teams")},
    }


@router.get("")
async def get_mine(user: Reader, db: Db) -> dict:
    return await _out(db, user, await db.get(PersonNews, user.id))


class NewsMineIn(concerns.Concerns):
    email_on: bool = False
    teams_on: bool = False
    severities: list[Severity] = Field(default_factory=lambda: ["critical", "high"], max_length=5)
    sources: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    topics: list[Topic] = Field(default_factory=list, max_length=9)
    lang: Literal["de", "en"] = "de"
    # None: the stored URL stays; "": removed (and the Teams way off – here and for the vendor news); otherwise a new one
    teams_url: str | None = Field(default=None, max_length=personal.URL_MAX)


def _filter_of(p: PersonNews) -> dict:
    """The person's choice as a channel rule's filter (notify.rule_filter) – compared with notify.widens."""
    rule = personal_news.rule_of(p)
    rule.kinds = ["news"]
    return notify.rule_filter(rule)


@router.put("")
async def put_mine(body: NewsMineIn, user: Reader, db: Db) -> dict:
    """The own settings. While an admin does not allow it (or not a way), a way can still be switched off and the choice
    changed – only switching a way on is refused."""
    why = await _why(db)
    ways = await personal_news.allowed(db)
    p = await db.get(PersonNews, user.id)
    if p is None:
        p = PersonNews(user_id=user.id, state_email={}, state_teams={}, filter_seq=0, email_on=False, teams_on=False, email_on_seq=0, teams_on_seq=0)
        db.add(p)
    switching_on = [w for w, on in (("email", body.email_on), ("teams", body.teams_on)) if on and not getattr(p, f"{w}_on")]
    if switching_on and why is not None:
        raise api_error(409, why)
    n = await db.get(PersonNotify, user.id)
    if body.teams_url is not None:
        if n is None:
            n = PersonNotify(user_id=user.id, kinds=list(personal.DEFAULT_KINDS), min_severity="info", state_email={}, state_desktop={}, state_teams={}, schedule={}, weekly_on=False)
            db.add(n)
        if body.teams_url == "":
            # the one Teams URL of the person: removed, its way is off for the vendor news and here alike
            n.teams_url_enc, n.teams_host, n.teams_on = None, None, False
        else:
            try:
                url = personal.check_teams_url(body.teams_url)
            except notify.NotifyError as exc:
                raise api_error(422, f"teams_url_{exc.category}") from exc
            n.teams_url_enc, n.teams_host = encrypt_str(url), (urlsplit(url).hostname or "").lower()
        n.state_teams = {}
        p.state_teams, p.teams_next_at = {}, None  # another target: its old error and pause do not count
    before = _filter_of(p)
    chosen = body.system_entries()
    if chosen is not None:
        concerns.check_known(chosen, systems_svc.entries(p.systems))
        p.systems = chosen
    if body.keywords is not None:
        p.keywords = list(body.keywords)
    if body.exclude is not None:
        p.exclude = list(body.exclude)
    p.severities = [s for s in news_svc.SEVERITIES if s in body.severities]
    p.sources = [str(x) for x in dict.fromkeys(body.sources)]
    p.topics = [t for t in news_svc.TOPICS if t in body.topics]
    p.lang = body.lang
    top = await personal_news.start(db)
    now = datetime.now(UTC)
    if p.filter_at is None or notify.widens(before, _filter_of(p)):
        # a wider choice (as a rule's: another severity, source, topic, system or word, an exclusion less): what was
        # there already counts only through a change of its own from now on – no flood. A narrower one changes nothing
        # (what is due stays due, judged by the new choice).
        p.filter_seq, p.filter_at = top, now
    for way, on in (("email", body.email_on), ("teams", body.teams_on)):
        if way in switching_on:
            if not ways[way]:
                raise api_error(409, "way_off", way=way)
            if way == "email" and not (user.email and teams.MAIL.fullmatch(user.email)):
                raise api_error(409, "no_address")
            # from now on only: the newest story is where the way starts (no backlog, no burst); a message of an earlier
            # switch-on still being sent keeps its own claim (personal_news._settle touches only that)
            setattr(p, f"{way}_on_seq", top)
            setattr(p, f"{way}_claim_at", None)
            setattr(p, f"{way}_next_at", None)
            setattr(p, f"state_{way}", {})
        if way == "teams" and on and not (n and n.teams_url_enc):
            raise api_error(422, "teams_url_required")
        setattr(p, f"{way}_on", on)
    p.updated_at = now
    await db.commit()
    return await _out(db, user, p)
