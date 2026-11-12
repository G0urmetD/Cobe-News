"""A person's own security stories by e-mail or their Microsoft Teams Workflows webhook ("Security-Meldungen per
E-Mail oder Teams", 0.1.54) – what a channel rule does for a team, for one person, chosen by themselves.

- **What.** The person's filter is a channel rule's (notify.news_filter – one matcher): severities, sources, topics,
  systems or words (one of them is enough), AND with the rest; an exclusion word keeps a story away. Loud systems and
  topics only, never the backlog of a source switched on later. Watched CVEs and the Vendor News of the own products
  have their own ways (app/personal.py, app/cve_watch.py).
- **As a rule: also later.** A story counts when it arrived after the way was switched on and matches now – also one
  that matches only later through a loud change of its own (rated higher, a topic or a system gained – its details
  arrived –, a new title or teaser, a fresh carry by a further source: news_items.changes, news_item_sources.carried_at),
  as a channel rule sends it then. Not older than MAX_AGE (a week), at most once per person and way
  (person_news_sent). **No flood after widening**: a story that arrived before the person's filter was last saved
  counts only through such a change after that moment (`filter_seq` / `filter_at`) – a wider filter never brings what
  was there already.
- **Allowed.** Only while an admin allows it (Einstellungen → Teams: "Security-Meldungen nach eigener Auswahl", off by
  default) and the way itself (`personal_email`, `personal_teams`). While a way is not allowed, the person is away or
  the account is switched off, the way's start (`<way>_on_seq`) follows the newest story: nothing piles up for later.
- **Each story at most once.** A round writes the stories of a person-way's message into person_news_sent and marks the
  claim (`<way>_claim_at`) in one commit before anything is sent. A failure that certainly delivered nothing
  (personal.RETRY: a refused connection, an HTTP error answer, a rate limit …) takes them back – they come again after
  the channels' growing pause (`<way>_next_at`), at most personal.MAX_TRIES times; one that may have delivered (a
  timeout), or a claim a stopped process left behind (STALE), keeps them: never twice.
- **No flood.** One round, one person, one way: up to notify.BATCH stories each on its own, more as ONE summary (the
  notify.LIST most urgent listed – actively exploited or critical first –, the rest counted), at most CLAIM_MAX stories
  (the rest the next time). And at most one message per GAP and way: a person choosing "alle" gets a few messages an
  hour, never hundreds.
- **Quiet hours and collecting time** (the person's schedule, app/quiet.py) apply per way: in the quiet hours nothing
  goes – when they end, one message with what waited; with "gesammelt um HH:MM" one message after each such time with
  what arrived (or changed) by then – a later story waits for the next one, also after a time with nothing due. News
  have no "urgent" exception (that is for the own products' findings; the desktop notifications are the way for at once).
- **Absence** (app/absence.py): while the person is away (without "auch an mich"), nothing is sent and nothing waits;
  no deputy (the feed is nobody's product). **Muted** CVEs (app/reader.py) are left out.
- **One person's error** (a story or filter a round cannot read) is logged – once, then hourly – and never stops the
  others: the jobs claimed before it are sent, that person's claim is undone (their stories come again).
- **Bounded and fair.** The person-ways due (on, allowed, not pausing, outside GAP – decided in SQL) are taken the one
  looked at longest ago first (`<way>_seen_at`), at most ROUND_JOBS per round and none started after ROUND_S; every one
  looked at is marked, so one held by quiet hours never blocks the others. `backlog()` (the loop's "go on at once") only
  while some due person-way has not been looked at since the run of rounds began – never round after round for people
  who are only waiting (quiet hours).
- **Egress** as the personal notifications: mail through notify.send_mail, the Teams URL of person_notify (checked,
  encrypted, never logged). The messages say why: "Treffer: PAN-OS" (systems or words chosen)."""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import Text as SqlText
from sqlalchemy import and_, case, delete, exists, func, literal, literal_column, or_, select, union_all, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import concerns, delivery_log, notify, personal, quiet, reader, teams
from app import db as dbm
from app import news as news_svc
from app import settings as settings_store
from app import systems as systems_svc
from app.crypto import decrypt_str
from app.models import NewsItem, NewsItemSource, NewsSource, PersonAbsence, PersonNews, PersonNewsSent, PersonNotify, User

log = logging.getLogger("cobe_news.personal_news")

WAYS = ("email", "teams")
GAP = timedelta(minutes=15)  # at most one message per way in this time
STALE = timedelta(hours=1)  # a claim older than this: the process stopped while sending – kept as sent, never again
MAX_AGE = personal.MAX_AGE  # a story older than this is never sent (and its sent row can go a day later)
CLAIM_MAX = 200  # stories in one person-way's message at most – the rest the next time
LOOKBACK = timedelta(minutes=10)  # a change is looked for this much before the last judgement (one committed late)
ROUND_JOBS = 500
ROUND_S = 30.0
SEND_DEADLINE = 90.0
CONCURRENCY = 8
LABELS = {
    "de": {
        "label": "Meine Security-Meldungen",
        "footer": [
            "Diese Nachricht hat Cobe News automatisch an dich versendet – nach deiner eigenen Auswahl an Security-Meldungen.",
            "Ändern oder ausschalten: Einstellungen › Benachrichtigungen › Security-Meldungen.",
        ],
    },
    "en": {
        "label": "My security stories",
        "footer": [
            "Cobe News sent you this message automatically – by your own choice of security stories.",
            "Change or switch off: Settings › Notifications › Security stories.",
        ],
    },
}


def _lang(lang: str | None) -> str:
    return lang if lang in LABELS else "de"


def col(way: str, name: str):  # noqa: ANN201
    """A way's column of person_news: col("email", "on") is PersonNews.email_on, col("email", "state") state_email."""
    return getattr(PersonNews, f"state_{way}" if name == "state" else f"{way}_{name}")


async def allowed(db: AsyncSession) -> dict[str, bool]:
    """The ways an admin allows for the security stories: Teams on, "Security-Meldungen nach eigener Auswahl" on and the
    way's own switch (personal_email / personal_teams)."""
    conf = await teams.config(db)
    on = bool(conf.get("enabled")) and bool(conf.get("personal_news"))
    return {w: on and bool(conf.get(f"personal_{w}")) for w in WAYS}


def rule_of(p: PersonNews) -> SimpleNamespace:
    """The person's choice as a rule – notify.news_filter's matcher (the same as the channel rules')."""
    return SimpleNamespace(
        severities=list(p.severities or []),
        sources=[str(x) for x in p.sources or []],
        topics=list(p.topics or []),
        systems=list(p.systems or []),
        keywords=list(p.keywords or []),
        exclude=list(p.exclude or []),
    )


def state_out(p: PersonNews | None, way: str) -> dict:
    s = dict(getattr(p, f"state_{way}") or {}) if p is not None else {}
    nxt = getattr(p, f"{way}_next_at") if p is not None else None
    return {**{k: s.get(k) for k in ("last_ok_at", "last_error", "last_error_at")}, "next_try_at": nxt.isoformat() if nxt else None, "failures": int(s.get("failures") or 0)}


# ---------------------------------------------------------------- what is due for a person


def changed_after(at: datetime):  # noqa: ANN201
    """SQL: the story changed loudly after `at` in something a rule matches by – rated higher, its title or teaser
    changed, a topic or system gained (news_items.changes, news.noted: ISO times, compared as text – one format, UTC) –
    or a further source carried it fresh."""
    iso = literal(at.astimezone(UTC).isoformat(), SqlText)
    c = NewsItem.changes
    parts: list = []
    for k in ("sev", "text"):  # [[at, before], …]
        e = func.jsonb_array_elements(func.coalesce(c[k], literal_column("'[]'::jsonb"))).table_valued("value").alias(f"e_{k}")
        parts.append(exists(select(literal(1)).select_from(e).where(e.c.value.op("->>")(0) > iso)))
    for k in ("topics", "systems"):  # {entry: at}
        m = func.jsonb_each_text(func.coalesce(c[k], literal_column("'{}'::jsonb"))).table_valued("key", "value").alias(f"m_{k}")
        parts.append(exists(select(literal(1)).select_from(m).where(m.c.value > iso)))
    carried = exists().where(NewsItemSource.item_id == NewsItem.id, NewsItemSource.fresh.is_(True), NewsItemSource.carried_at > at)
    # most stories never changed: the cheap test first, the JSON only for the others
    return or_(and_(c != literal_column("'{}'::jsonb"), or_(*parts)), carried)


def due_where(p: PersonNews, way: str, now: datetime) -> list:
    """The stories due for this person and way (apart from the filter): arrived after the way was switched on, not
    older than MAX_AGE, not sent on this way – and arrived after the filter was last saved, or changed loudly since.
    Only what arrived or changed since the last judgement of this way (`<way>_checked_*`) is judged again: a story
    judged then that has not changed cannot match now (a wider filter: the rule above) – a round reads the new and the
    changed stories, not the whole week."""
    on_seq, f_seq, f_at = int(getattr(p, f"{way}_on_seq") or 0), int(p.filter_seq or 0), p.filter_at
    sent = exists().where(PersonNewsSent.user_id == p.user_id, PersonNewsSent.way == way, PersonNewsSent.item_id == NewsItem.id)
    since = NewsItem.seq > f_seq
    if f_at is not None and f_seq > on_seq and f_at > now - MAX_AGE:
        since = or_(since, changed_after(f_at))  # an older story only through a change of its own after the filter was saved
    where = [NewsItem.seq > on_seq, NewsItem.fetched_at > now - MAX_AGE, ~sent, since]
    c_seq, c_at = int(getattr(p, f"{way}_checked_seq") or 0), getattr(p, f"{way}_checked_at")
    if c_at is not None and c_seq > on_seq:
        where.append(or_(NewsItem.seq > c_seq, changed_after(c_at - LOOKBACK)))
    return where


def _priority():  # noqa: ANN202
    """SQL order of a message's stories: actively exploited or critical first, then by severity, the newest first
    (notify.priority without "our products" – a person's choice has no team)."""
    urgent = or_(NewsItem.severity == "critical", NewsItem.topics.op("?")(literal("exploited")))
    rank = case(*((NewsItem.severity == k, v) for k, v in notify.RANK.items()), else_=0)
    return (case((urgent, 1), else_=0).desc(), rank.desc(), NewsItem.published_at.desc(), NewsItem.id.desc())


def by_cut(cut: datetime):  # noqa: ANN201
    """SQL: the story arrived by the collecting time `cut` and has not changed loudly since – its message is the one of
    that time ("gesammelt um HH:MM": what came by then); a later one waits for the next (as personal._eligible)."""
    return and_(NewsItem.fetched_at <= cut, ~changed_after(cut))


async def _due(db: AsyncSession, p: PersonNews, way: str, now: datetime) -> list:
    """The conditions of what is due for the person and way: the filter, due_where, not muted."""
    if systems_svc.has_ours(p.systems):
        await systems_svc.load_followed(db)  # "Unsere Produkte": the products followed now (kept – not read per person)
    where = [*notify.news_filter(rule_of(p)), *due_where(p, way, now)]
    hush = reader.news_muted(await reader.mutes_of(db, p.user_id, now))
    if hush is not None:
        where.append(~hush)
    return where


async def stories_due(db: AsyncSession, p: PersonNews, way: str, now: datetime, cut: datetime | None = None) -> list[tuple[NewsItem, NewsSource]]:
    """What the person's filter lets through of what is due – the most urgent CLAIM_MAX. `cut`: only what is due by
    that collecting time (by_cut)."""
    where = await _due(db, p, way, now)
    if cut is not None:
        where.append(by_cut(cut))
    q = select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).where(*where).order_by(*_priority()).limit(CLAIM_MAX)
    return [(i, s) for i, s in (await db.execute(q)).all()]


async def _after_cut(db: AsyncSession, p: PersonNews, way: str, now: datetime, cut: datetime) -> bool:
    """Whether a story due now waits for the next collecting time (arrived or changed after `cut`)."""
    where = await _due(db, p, way, now)
    q = select(literal(1)).select_from(NewsItem).join(NewsSource, NewsSource.id == NewsItem.source_id).where(*where, ~by_cut(cut)).limit(1)
    return await db.scalar(q) is not None


def _story_list(p: PersonNews, rows: list[tuple[NewsItem, NewsSource]]) -> list[notify.Story]:
    rule = rule_of(p)
    chosen, words = systems_svc.entries(rule.systems), [str(x) for x in rule.keywords]
    want = systems_svc.wanted(chosen)
    return [notify._story(i, s, hits=concerns.story_hits(i, chosen, words, want) if chosen or words else None) for i, s in rows]


def _messages(stories: list[notify.Story]) -> list[tuple[list[notify.Story], int]]:
    """As a channel (notify.plan): up to notify.BATCH stories each on its own (the oldest first), more as one summary
    (the notify.LIST most urgent listed, all counted)."""
    if len(stories) <= notify.BATCH:
        return [([s], 1) for s in sorted(stories, key=lambda s: s.published_at)]
    return [(sorted(stories, key=notify.priority, reverse=True)[: notify.LIST], len(stories))]


def render(way: str, stories: list[notify.Story], total: int, lang: str, tz: str | None = None):  # noqa: ANN201
    lang = _lang(lang)
    if way == "email":
        return notify.render_mail(LABELS[lang]["label"], stories, total, lang, footer=LABELS[lang]["footer"], tz=tz)
    return notify.render_teams(LABELS[lang]["label"], stories, total, lang, tz=tz)


# ---------------------------------------------------------------- the round


@dataclass
class _Job:
    user_id: uuid.UUID
    way: str
    lang: str
    claimed_at: datetime
    checked: tuple[int, datetime | None]  # the way's last judgement before this one – back to it when taken back
    items: list[uuid.UUID]
    messages: list[tuple[list[notify.Story], int]]
    failures: int
    tz: str
    address: str = ""
    url: str = ""
    error: notify.NotifyError | None = None


async def _set(db: AsyncSession, user_id: uuid.UUID, values: dict, *where) -> int:  # noqa: ANN002
    res = await db.execute(update(PersonNews).where(PersonNews.user_id == user_id, *where).values(values).execution_options(synchronize_session=False))
    return res.rowcount


async def _housekeeping(db: AsyncSession, ways: dict[str, bool], top: int, now: datetime) -> None:
    """Claims a stopped process left behind: given up (their stories stay sent – never twice). Ways not allowed and
    accounts switched off: their start follows the newest story (nothing piles up for later)."""
    inactive = select(User.id).where(User.is_active.is_(False))
    for way in WAYS:
        claim, on, start, state = col(way, "claim_at"), col(way, "on"), col(way, "on_seq"), col(way, "state")
        await db.execute(
            update(PersonNews)
            .where(claim.is_not(None), claim < now - STALE)
            .values({claim: None, state: state.op("||")(func.jsonb_build_object("last_error", "interrupted", "last_error_at", now.isoformat()))})
            .execution_options(synchronize_session=False)
        )
        idle = and_(on.is_(True), start < top, claim.is_(None))
        who = idle if not ways.get(way) else and_(idle, PersonNews.user_id.in_(inactive))
        await db.execute(update(PersonNews).where(who).values({start: top}).execution_options(synchronize_session=False))
    await db.commit()


def _due_sql(ways: dict[str, bool], now: datetime):  # noqa: ANN202
    """SQL: (person, way, last looked at) of every person-way that may get a message now – on, allowed, no claim open,
    not pausing after a failure, its last message at least GAP ago, the account active. Quiet hours and absence are
    decided per person (time zones) – each one looked at is marked, so they never block the others."""
    parts = []
    for way in WAYS:
        if not ways.get(way):
            continue
        nxt, sent = col(way, "next_at"), col(way, "sent_at")
        parts.append(
            select(PersonNews.user_id.label("u"), literal(way, SqlText).label("w"), col(way, "seen_at").label("seen"))
            .join(User, User.id == PersonNews.user_id)
            .where(
                col(way, "on").is_(True),
                col(way, "claim_at").is_(None),
                or_(nxt.is_(None), nxt <= now),
                or_(sent.is_(None), sent <= now - GAP),
                User.is_active.is_(True),
            )
        )
    return union_all(*parts).subquery() if parts else None


@dataclass
class _State:
    more: bool = False
    cycle: datetime | None = None  # when the current run of back-to-back rounds began


_state = _State()


def backlog() -> bool:
    """Due person-ways not looked at yet in this run of rounds – the loop runs the next one right away."""
    return _state.more


async def _more(db: AsyncSession, ways: dict[str, bool], now: datetime) -> bool:
    """Whether a due person-way has not been looked at since the run of rounds began (a fair look at each, then the
    normal pace – people only waiting for their quiet hours to end do not keep the loop busy)."""
    due = _due_sql(ways, now)
    if due is None:
        return False
    cycle = _state.cycle or now
    return await db.scalar(select(literal(1)).select_from(due).where(or_(due.c.seen.is_(None), due.c.seen < cycle)).limit(1)) is not None


async def _prepare(db: AsyncSession, ways: dict[str, bool], top: int, now: datetime, deadline: float) -> list[_Job]:
    """The due person-ways, the one looked at longest ago first: checked (absence, quiet hours, address or URL), their
    stories claimed – written as sent and the claim marked, one commit per person-way – before anything is sent."""
    due = _due_sql(ways, now)
    if due is None:
        return []
    picked = (await db.execute(select(due.c.u, due.c.w).order_by(due.c.seen.asc().nulls_first(), due.c.u, due.c.w).limit(ROUND_JOBS))).all()
    if not picked:
        return []
    uids = sorted({u for u, _ in picked})
    q = (
        select(PersonNews, User.email, PersonNotify.schedule, PersonNotify.teams_url_enc)
        .join(User, User.id == PersonNews.user_id)
        .outerjoin(PersonNotify, PersonNotify.user_id == PersonNews.user_id)
        .where(PersonNews.user_id.in_(uids))
    )
    people = {p.user_id: (p, email, sched, url) for p, email, sched, url in await db.execute(q)}
    away = set(await db.scalars(select(PersonAbsence.user_id).where(PersonAbsence.user_id.in_(uids), PersonAbsence.starts_at <= now, PersonAbsence.ends_at > now, PersonAbsence.also_me.is_(False))))
    # every person-way picked is looked at now – the next round starts with the others
    for way in WAYS:
        if mine := [u for u, w in picked if w == way]:
            await db.execute(update(PersonNews).where(PersonNews.user_id.in_(mine)).values({col(way, "seen_at"): now}).execution_options(synchronize_session=False))
    await db.commit()
    jobs: list[_Job] = []
    for uid, way in picked:
        if time.monotonic() >= deadline:
            _state.more = True  # the round's time is up: the rest the next round (nothing of theirs claimed)
            break
        try:
            if (job := await _prepare_one(db, people[uid], uid, way, uid in away, top, now)) is not None:
                jobs.append(job)  # claimed and committed: sent (or taken back) by the round, whatever comes next
        except Exception as exc:  # noqa: BLE001 - one person's error never abandons the jobs claimed for the others
            await db.rollback()  # this person's claim (not committed) undone – their stories come again
            _failed_log(uid, way, exc)
            try:
                # the rollback expired everything loaded: the people read again for the rest of the round
                people = {p.user_id: (p, email, sched, url) for p, email, sched, url in await db.execute(q)}
                await db.commit()
            except Exception:  # noqa: BLE001 - the database itself: the jobs claimed so far still go, the rest next round
                await db.rollback()
                log.exception("personal news: the people not read again")
                _state.more = True
                break
    db.expunge_all()
    return jobs


FAIL_LOG = timedelta(hours=1)  # one person-way failing every round: its traceback once, then hourly (or on a new error)
_failures: dict[tuple[uuid.UUID, str], tuple[str, datetime]] = {}


def _failed_log(uid: uuid.UUID, way: str, exc: BaseException) -> None:
    now = datetime.now(UTC)
    what = f"{type(exc).__name__}: {exc}"[:300]
    seen = _failures.get((uid, way))
    if seen is None or seen[0] != what or now - seen[1] >= FAIL_LOG:
        if len(_failures) > 10_000:
            _failures.clear()
        _failures[(uid, way)] = (what, now)
        log.error("personal news %s of %s not prepared – the others go on", way, uid, exc_info=exc)
    else:
        log.warning("personal news %s of %s still not prepared (%s)", way, uid, what)


async def _prepare_one(db: AsyncSession, person: tuple, uid: uuid.UUID, way: str, away: bool, top: int, now: datetime) -> _Job | None:
    """One person-way of _prepare: checked, its stories claimed and committed – the job, or None (nothing to send)."""
    p, email, schedule, url_enc = person
    state = dict(getattr(p, f"state_{way}") or {})
    if away:
        await _set(db, uid, {col(way, "on_seq"): top})  # away: nothing waits for the return
        await db.commit()
        return None
    held, cut = quiet.hold(schedule, way, now)
    if held and (cut is None or ((last := getattr(p, f"{way}_sent_at")) is not None and last >= cut)):
        return None  # quiet hours, or the message of this collecting time went out already: it waits
    # "gesammelt um HH:MM": only what came by that time – a story after it waits for the next, also when nothing was
    # due at this one (the handbook: "kommt, was bis dahin eintraf")
    cut = cut if held else None
    rows = await stories_due(db, p, way, now, cut)
    before = (int(getattr(p, f"{way}_checked_seq") or 0), getattr(p, f"{way}_checked_at"))
    # judged up to the newest story now – unless more were due than one message takes (the rest the next time), or a
    # story waits for the next collecting time (it would count as judged and never come)
    judged = {col(way, "checked_seq"): top, col(way, "checked_at"): now} if len(rows) < CLAIM_MAX else {}
    if judged and cut is not None and await _after_cut(db, p, way, now, cut):
        judged = {}
    if not rows:
        if judged:
            await _set(db, uid, judged)
        await db.commit()
        return None
    job = _Job(uid, way, _lang(p.lang), now, before, [i.id for i, _ in rows], _messages(_story_list(p, rows)), int(state.get("failures") or 0), quiet.out(schedule)["tz"])
    if way == "email":
        if not email or not teams.MAIL.fullmatch(email):
            await _set(db, uid, {col(way, "on_seq"): top, col(way, "state"): {**state, "last_error": "no_address", "last_error_at": now.isoformat()}})
            await db.commit()
            return None
        job.address = email
    else:
        try:
            job.url = decrypt_str(url_enc) if url_enc else ""
        except Exception:  # noqa: BLE001 - another master key: the person enters the URL again
            job.error = notify.NotifyError("secret_unreadable")
        if not job.url and job.error is None:
            await _set(db, uid, {col(way, "on_seq"): top, col(way, "state"): {**state, "last_error": "no_url", "last_error_at": now.isoformat()}})
            await db.commit()
            return None
    # the claim: the stories written as sent and the claim marked in one commit – only while the way is still on
    # and nothing claimed it meanwhile
    if await _set(db, uid, {col(way, "claim_at"): now, **judged}, col(way, "on").is_(True), col(way, "claim_at").is_(None)):
        await db.execute(pg_insert(PersonNewsSent).values([{"user_id": uid, "way": way, "item_id": i, "sent_at": now} for i in job.items]).on_conflict_do_nothing())
        await db.commit()
        return job
    await db.commit()
    return None


async def _send(job: _Job, smtp: dict) -> tuple[notify.NotifyError | None, bool]:
    """The job's messages, one after the other – (the first failure, whether one went out before it). No database work."""
    if job.error is not None:
        return job.error, False
    sent = False
    try:
        async with asyncio.timeout(SEND_DEADLINE):
            for stories, total in job.messages:
                if job.way == "email":
                    subject, text_, html = render("email", stories, total, job.lang, job.tz)
                    await notify.send_mail(smtp, [job.address], subject, text_, html)
                else:
                    url = personal.check_teams_url(job.url)
                    await notify.post(url, notify._json(render("teams", stories, total, job.lang, job.tz)), notify.JSON_HEADERS, policy=notify.PUBLIC_ONLY)
                sent = True
    except notify.NotifyError as exc:
        return exc, sent
    except TimeoutError:
        return notify.NotifyError("timeout"), sent
    except Exception as exc:  # noqa: BLE001 - one broken target must not stop the round
        log.warning("personal news %s: %s", job.way, type(exc).__name__)
        return notify.NotifyError("connection", type(exc).__name__), sent
    return None, sent


async def _unclaim(db: AsyncSession, job: _Job) -> None:
    """Certainly not sent (a failure before anything went out, or never started): the stories are no longer sent – they
    come again – and the claim ends (only our own: switched off and on meanwhile, the new start stands)."""
    await db.execute(delete(PersonNewsSent).where(PersonNewsSent.user_id == job.user_id, PersonNewsSent.way == job.way, PersonNewsSent.item_id.in_(job.items), PersonNewsSent.sent_at == job.claimed_at))
    # judged anew the next time: the stories taken back are in the range judged with them
    back = {col(job.way, "claim_at"): None, col(job.way, "checked_seq"): job.checked[0], col(job.way, "checked_at"): job.checked[1]}
    await _set(db, job.user_id, back, col(job.way, "claim_at") == job.claimed_at)


async def _settle(db: AsyncSession, job: _Job, outcome: notify.NotifyError | None, partly: bool, now: datetime) -> None:
    """After one person-way's messages: sent – the claim ends, the GAP begins; a failure that certainly delivered
    nothing (and tries left) – taken back, again after the pause; anything else – kept as sent (never twice), the error
    shown. Only our own claim is touched: switched off and on meanwhile, the new start stands."""
    p = await db.get(PersonNews, job.user_id)
    if p is None:
        return  # the account was deleted meanwhile
    state = dict(getattr(p, f"state_{job.way}") or {})
    mine = col(job.way, "claim_at") == job.claimed_at
    delivery_log.count("personal", job.way, delivery_log.outcome(job.way, outcome)[1])  # counted only, as the personal ones
    if outcome is None:
        values = {col(job.way, "claim_at"): None, col(job.way, "sent_at"): now, col(job.way, "next_at"): None, col(job.way, "state"): {**state, "failures": 0, "last_ok_at": now.isoformat(), "last_error": None}}
        await _set(db, job.user_id, values, mine)
    else:
        f = notify._failure(job.failures, outcome, now)
        new = {**state, "failures": f["failures"], "last_error": f["last_error"], "last_error_at": now.isoformat()}
        log.info("personal news %s of %s: %s", job.way, job.user_id, f["last_error"])
        if outcome.category in personal.RETRY and not partly and f["failures"] < personal.MAX_TRIES:
            await _unclaim(db, job)
        else:
            await _set(db, job.user_id, {col(job.way, "claim_at"): None}, mine)
        await _set(db, job.user_id, {col(job.way, "next_at"): f["next_try_at"], col(job.way, "state"): new})
    await db.commit()


async def dispatch(db: AsyncSession) -> dict[str, int]:
    """After the personal notifications: per person and way what is due for them."""
    was_more, _state.more = _state.more, False  # never sticky: every way out of here says it anew
    if not was_more:
        _state.cycle = None
    if await db.scalar(select(PersonNews.user_id).where(or_(PersonNews.email_on.is_(True), PersonNews.teams_on.is_(True))).limit(1)) is None:
        _state.cycle = None
        await dbm.release(db)
        return {}
    ways = await allowed(db)
    now = datetime.now(UTC)
    _state.cycle = _state.cycle or now
    top = await news_svc.last_seq(db)
    await _housekeeping(db, ways, top, now)
    if not any(ways.values()):
        _state.cycle = None
        await dbm.release(db)
        return {}
    deadline = time.monotonic() + ROUND_S
    jobs = await _prepare(db, ways, top, now, deadline - ROUND_S / 2)  # the first half to prepare, the rest to start sending
    smtp = await settings_store.get(db, "smtp") if any(j.way == "email" for j in jobs) else {}
    await dbm.release(db)
    gate = asyncio.Semaphore(CONCURRENCY)

    async def one(j: _Job) -> tuple[notify.NotifyError | None, bool] | None:
        async with gate:
            if time.monotonic() >= deadline:
                return None  # not started: taken back, nothing was sent
            return await _send(j, smtp)

    results = await asyncio.gather(*(one(j) for j in jobs))
    out = {"sent": 0, "failed": 0}
    for job, res in zip(jobs, results, strict=True):
        try:
            if res is None:
                await _unclaim(db, job)
                await db.commit()
                _state.more = True
                continue
            await _settle(db, job, res[0], res[1], datetime.now(UTC))
            out["sent" if res[0] is None else "failed"] += 1
        except Exception:  # noqa: BLE001 - one person's write must not undo the others' (a claim left: given up after STALE)
            await db.rollback()
            log.exception("personal news: state of %s not written", job.user_id)
    _state.more = _state.more or await _more(db, ways, now)
    if not _state.more:
        _state.cycle = None
    await dbm.release(db)
    return {k: v for k, v in out.items() if v}


async def prune(db: AsyncSession) -> int:
    """Sent rows older than MAX_AGE and a day – their stories are never sent any more."""
    return await dbm.delete_batched(db, PersonNewsSent, PersonNewsSent.sent_at < datetime.now(UTC) - MAX_AGE - timedelta(days=1))


async def start(db: AsyncSession) -> int:
    """The start for a way switched on (or a filter saved) now: the newest story – nothing older ever comes by arrival."""
    return await news_svc.last_seq(db)
