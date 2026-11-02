"""Absence with a deputy (0.1.35): a person away from one day to another chooses a deputy from the teams that give them
their products. Meanwhile the Vendor News of the person's routed products go out on the deputy's ways (app/personal.py,
_deputy_routes) – the person gets nothing of them unless "also to me". Watched CVEs stay with the person (private).

- **The deputy** is an active account, not the person, and a member of a team that gives the person at least one product
  (checked when set, and per event: a product of a team the deputy is not in stays with the person).
- **No chains**: a deputy away themselves passes nothing on – the person gets it (and sees a hint).
- **Time that has passed is never changed**: a running absence is ended now or split (another deputy, "also to me"
  changed: the old part ends now, the new one starts now) – who got an event stays who gets it, nobody gets the
  absence's events again afterwards. A planned one is changed or deleted freely. The end comes by itself.
- Dates are whole days in the person's time zone (their quiet hours' zone, else Europe/Berlin): from 00:00 of the first
  to 24:00 of the last day; a start in the past is now (nothing old goes to the deputy).
"""

import uuid
from datetime import UTC, date, datetime, time, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import quiet, teams
from app.models import PersonAbsence, PersonNotify, Team, TeamMember, TeamProduct, User

MAX_DAYS = 366
DEPUTIES_LIMIT = 50


class AbsenceError(Exception):
    def __init__(self, code: str, status: int = 422):
        super().__init__(code)
        self.code = code
        self.status = status


async def tz_of(db: AsyncSession, user_id: uuid.UUID) -> str:
    sched = await db.scalar(select(PersonNotify.schedule).where(PersonNotify.user_id == user_id))
    return quiet.out(sched)["tz"]


def bounds(start: date, end: date, tz: str) -> tuple[datetime, datetime]:
    z = quiet.zone(tz)
    return datetime.combine(start, time(0), tzinfo=z).astimezone(UTC), datetime.combine(end + timedelta(days=1), time(0), tzinfo=z).astimezone(UTC)


async def current(db: AsyncSession, user_id: uuid.UUID, now: datetime) -> PersonAbsence | None:
    """The person's running or planned absence (at most one ends in the future)."""
    return await db.scalar(select(PersonAbsence).where(PersonAbsence.user_id == user_id, PersonAbsence.ends_at > now).order_by(PersonAbsence.starts_at).limit(1))


def _product_teams(user_id: uuid.UUID):  # noqa: ANN202
    """SQL: the ids of the teams that give this person at least one product."""
    return select(TeamProduct.team_id).where(teams.mine_clause(user_id)).distinct()


async def deputy_ok(db: AsyncSession, user_id: uuid.UUID, deputy_id: uuid.UUID, team_id: uuid.UUID | None = None) -> bool:
    """An active account other than the person, a member of a team that gives the person a product (with `team_id`:
    of that team)."""
    if deputy_id == user_id:
        return False
    q = (
        select(TeamMember.user_id)
        .join(User, User.id == TeamMember.user_id)
        .where(TeamMember.user_id == deputy_id, User.is_active.is_(True), TeamMember.team_id.in_(_product_teams(user_id)))
        .limit(1)
    )
    if team_id is not None:
        q = q.where(TeamMember.team_id == team_id)
    return await db.scalar(q) is not None


async def deputies(db: AsyncSession, user_id: uuid.UUID, q: str = "", team_id: uuid.UUID | None = None) -> list[dict]:
    """Who can be chosen: the active members of the teams that give the person a product (not the person)."""
    where = [TeamMember.team_id.in_(_product_teams(user_id)), User.is_active.is_(True), User.id != user_id]
    if team_id is not None:
        where.append(TeamMember.team_id == team_id)
    if q.strip():
        v = q.strip().lower()
        where.append(or_(*(func.lower(c).contains(v, autoescape=True) for c in (User.username, User.display_name))))
    rows = await db.execute(
        select(User.id, User.username, User.display_name, func.array_agg(func.distinct(Team.name)))
        .join(TeamMember, TeamMember.user_id == User.id)
        .join(Team, Team.id == TeamMember.team_id)
        .where(*where)
        .group_by(User.id, User.username, User.display_name)
        .order_by(func.lower(User.display_name), User.username)
        .limit(DEPUTIES_LIMIT)
    )
    return [{"id": str(uid), "username": un, "display_name": dn or un, "teams": sorted(ts or [], key=str.lower)} for uid, un, dn, ts in rows]


async def put(db: AsyncSession, user_id: uuid.UUID, start: date, end: date, deputy_id: uuid.UUID, also_me: bool, *, team_id: uuid.UUID | None = None) -> PersonAbsence:
    """Set the person's absence (checked; not committed)."""
    now = datetime.now(UTC)
    if end < start or (end - start).days >= MAX_DAYS:
        raise AbsenceError("absence_range")
    starts, ends = bounds(start, end, await tz_of(db, user_id))
    if ends <= now:
        raise AbsenceError("absence_past")
    if not await deputy_ok(db, user_id, deputy_id, team_id):
        raise AbsenceError("deputy_not_in_team")
    starts = max(starts, now)
    cur = await current(db, user_id, now)
    if cur is None:
        cur = PersonAbsence(user_id=user_id, deputy_id=deputy_id, starts_at=starts, ends_at=ends, also_me=also_me, created_at=now)
        db.add(cur)
    elif cur.starts_at > now:  # planned: changed freely
        cur.starts_at, cur.ends_at, cur.deputy_id, cur.also_me = starts, ends, deputy_id, also_me
    elif cur.deputy_id == deputy_id and cur.also_me == also_me:
        cur.ends_at = ends  # running: only the end moves (the start stays – that time has passed)
    else:  # running with another deputy or "also to me": the old part ends now, the new one starts now
        cur.ends_at = now
        cur = PersonAbsence(user_id=user_id, deputy_id=deputy_id, starts_at=now, ends_at=ends, also_me=also_me, created_at=now)
        db.add(cur)
    await db.flush()
    return cur


async def end(db: AsyncSession, user_id: uuid.UUID) -> bool:
    """Over now: a running absence ends now (its time stays as it was), a planned one goes. Not committed."""
    now = datetime.now(UTC)
    cur = await current(db, user_id, now)
    if cur is None:
        return False
    if cur.starts_at > now:
        await db.delete(cur)
    else:
        cur.ends_at = now
    await db.flush()
    return True


def _days(a: PersonAbsence, tz: str) -> tuple[str, str]:
    z = quiet.zone(tz)
    return a.starts_at.astimezone(z).date().isoformat(), (a.ends_at - timedelta(seconds=1)).astimezone(z).date().isoformat()


async def views(db: AsyncSession, user_ids: list[uuid.UUID], now: datetime | None = None) -> dict[uuid.UUID, dict]:
    """Per person their running or planned absence for the UI: dates (own zone), the deputy, whether the deputy is away
    then too (nothing is passed on – the person gets it)."""
    now = now or datetime.now(UTC)
    if not user_ids:
        return {}
    du = User
    rows = list(
        await db.execute(
            select(PersonAbsence, du.username, du.display_name, du.is_active)
            .join(du, du.id == PersonAbsence.deputy_id)
            .where(PersonAbsence.user_id.in_(user_ids), PersonAbsence.ends_at > now)
            .order_by(PersonAbsence.starts_at)
        )
    )
    deps = sorted({a.deputy_id for a, *_ in rows})
    theirs: dict[uuid.UUID, list[PersonAbsence]] = {}
    if deps:
        for d in await db.scalars(select(PersonAbsence).where(PersonAbsence.user_id.in_(deps), PersonAbsence.ends_at > now)):
            theirs.setdefault(d.user_id, []).append(d)
    tzs = {uid: quiet.out(s)["tz"] for uid, s in await db.execute(select(PersonNotify.user_id, PersonNotify.schedule).where(PersonNotify.user_id.in_(user_ids)))}
    out: dict[uuid.UUID, dict] = {}
    for a, username, display, active in rows:
        if a.user_id in out:
            continue
        first, last = _days(a, tzs.get(a.user_id, quiet.DEFAULT_TZ))
        overlap = [d for d in theirs.get(a.deputy_id, []) if d.starts_at < a.ends_at and d.ends_at > a.starts_at]
        out[a.user_id] = {
            "start": first,
            "end": last,
            "starts_at": a.starts_at.isoformat(),
            "ends_at": a.ends_at.isoformat(),
            "running": a.starts_at <= now,
            "also_me": a.also_me,
            "deputy": {"id": str(a.deputy_id), "username": username, "display_name": display or username, "active": bool(active)},
            "deputy_absent": bool(overlap),
        }
    return out


async def covering(db: AsyncSession, deputy_id: uuid.UUID) -> list[dict]:
    """For whom this person stands in now or later (their names and dates) – the deputy's own view."""
    now = datetime.now(UTC)
    rows = await db.execute(
        select(PersonAbsence, User.username, User.display_name)
        .join(User, User.id == PersonAbsence.user_id)
        .where(PersonAbsence.deputy_id == deputy_id, PersonAbsence.ends_at > now, User.is_active.is_(True))
        .order_by(PersonAbsence.starts_at)
    )
    tz = await tz_of(db, deputy_id)
    out = []
    for a, username, display in rows:
        first, last = _days(a, tz)
        out.append({"name": display or username, "start": first, "end": last, "running": a.starts_at <= now})
    return out

