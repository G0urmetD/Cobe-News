"""Personal notifications: the Vendor News of a person's own products ("Hersteller-News meiner Produkte"), by e-mail,
desktop push and a Microsoft Teams Workflows webhook of their own.

- **Routing.** A team's product goes to all its members (team_products.all_members, the default) or to the chosen ones
  (team_product_members). A new Vendor News event of a product goes to the people of every team that has it – while
  Teams is on, to active accounts only, and only on the ways an admin allows (Einstellungen → Teams, each off by
  default) and the person switched on.
- **Nothing old.** Only events created after the person switched the way on, after the product was assigned to the
  team, after the person joined the team and after the routing gave it to them (person_routes) – never a baseline.
  The decision is made once per event, person and way (a row in person_deliveries): what the filter (kinds, minimum
  severity) left out then is "skipped" and never sent later, when the filter is widened – no flood.
- **Exactly once.** Each row is claimed (pending → sending) and committed before anything is sent: a second round, a
  restart or a crash in between never sends it twice. A row left at "sending" is marked failed ("interrupted") after
  an hour. A failure that certainly delivered nothing (refused, DNS, TLS, an HTTP error answer, a rate limit …) puts
  the rows back with the channels' growing pause (notify._failure: 2 min … 6 h) – at most MAX_TRIES times; one that may
  have delivered (a timeout, a broken connection) or a dead target (404/410) marks them failed.
- **Digest.** Per person, way and round one message: one mail, one Teams card, one push (a single event as itself,
  more as a summary) – at most CLAIM_MAX events, the LIST most severe listed, the rest counted.
- **Large teams.** A round is bounded: at most ROUND_JOBS messages (person and way), and none started after ROUND_S
  seconds – the rest goes on in the next round, the one waiting longest first (its oldest pending row), so nobody
  starves. The work is set-based and in short transactions: the checks are bulk statements over all open rows, then
  BATCH person-ways at a time are read together, claimed and committed, sent (nothing open in the database) and settled
  together – a fixed number of statements per batch, not per person. A message not started by the deadline was
  claimed but certainly not sent: it goes back to pending without counting a try.
- **Watched CVEs** (app/cve_watch.py, 0.1.34): the events of a CVE the person watches (kind "watch") come the same way
  – without a team: watching is the person's own choice, so no team, product, kind or severity filter applies, only
  the way (allowed by an admin, switched on by the person) and "created after the watch began".
- **Quiet hours, urgent, collected** (app/quiet.py, 0.1.35): a person's held rows (normal ones in the quiet hours, or
  waiting for the way's collecting time) are left out of the round – not claimed, not counted against ROUND_JOBS – and go
  out together when they are due; urgent rows (person_deliveries.marks against the person's choice) pass at once.
- **Absence** (app/absence.py, 0.1.35): the events of an absent person's routed products created during the absence
  go to the deputy (a recipient like any other: keyed per person and way, so exactly once also when the deputy gets the
  product anyway) – never a watched CVE, never on to a deputy who is away themselves (then to the person).
- **Muted** (app/reader.py, person_mutes): what a person muted for a while – a product, or a CVE (all CVEs of the
  event; a watched CVE's events too) – is skipped ("muted") for that person, when queued and again before it is sent;
  never sent later when the mute ends. Only that person's rows: team channels, the admins' rules and everybody else are
  untouched.
- **Egress.** Mail through notify.send_mail (the SMTP settings, its pinned and checked connection). The Teams URL is a
  person's input: https on the Teams / Power Automate hosts only (TEAMS_HOSTS), public addresses only – never
  WEBHOOK_PRIVATE_NETS (notify.PUBLIC_ONLY) –, encrypted at rest (crypto) and never sent back or logged. Desktop push
  through the person's Web Push subscriptions (webpush.py).
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode, urlsplit

from sqlalchemy import Integer, Uuid, and_, case, cast, delete, exists, func, literal, or_, select, text, true, tuple_, union, update
from sqlalchemy import Text as SqlText
from sqlalchemy.dialects.postgresql import ARRAY, TIMESTAMP
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app import db as dbm
from app import delivery_log, netaddr, notify, quiet, reader, teams, webpush
from app import settings as settings_store
from app.config import get_config
from app.crypto import decrypt_str
from app.models import (
    CveWatch,
    PersonAbsence,
    PersonDelivery,
    PersonNotify,
    PersonRoute,
    PushSubscription,
    TeamMember,
    TeamProduct,
    TeamProductMember,
    User,
    VendorEvent,
    VendorFollow,
)

log = logging.getLogger("cobe_news.personal")

WAYS = ("email", "desktop", "teams")
KINDS = ("vendor_vuln", "vendor_version", "vendor_change")
DEFAULT_KINDS = ("vendor_vuln", "vendor_version")  # "Advisory geändert" only when the person picks it
SEVERITIES = ("critical", "high", "medium", "low", "info")
EVENT_KINDS = {"vuln": "vendor_vuln", "version": "vendor_version", "eol": "vendor_version", "change": "vendor_change"}
WATCH = "watch"  # a watched CVE's event (app/cve_watch.py): routed by cve_watches, never filtered by kind or severity
# the hosts of Teams Workflows / Power Automate and the classic Incoming Webhook (config.DEFAULT_WEBHOOK_HOSTS without
# Slack and without the own WEBHOOK_HOSTS – a person's URL may only ever reach Microsoft)
TEAMS_HOSTS = ("*.logic.azure.com", "*.powerplatform.com", "*.webhook.office.com")
URL_MAX = 2000
MAX_AGE = timedelta(days=7)  # an event older than this is not sent any more (a long outage: no burst of old news)
CLAIM_MAX = 100  # events per person, way and round – one message; the rest the next round
LIST = 10  # events listed in one message, the most severe first
MAX_TRIES = 12  # as a push subscription's failures in a row (webpush.MAX_FAILURES)
STALE_SENDING = timedelta(hours=1)
SEND_DEADLINE = 90.0  # one person's message on one way
CONCURRENCY = 8
FULL_EVERY = 600.0
ROUND_JOBS = 2000  # messages (person and way) one round takes on at most – the rest the next round
ROUND_S = 30.0  # s: no message is started after this (one started may take SEND_DEADLINE) – the rest the next round
BATCH = 100  # person-ways read, claimed, sent and settled together (a crash mid-way leaves at most these at "sending")
PER_GROUP = 2000  # open rows of one person and way checked in one round (the oldest first)
IN_CHUNK = 5000  # ids in one IN list (the driver's limit on parameters is 32767)
# failures after which the message certainly never arrived: tried again (the welcome e-mail's list, plus an answer of
# the service that refused it – an HTTP error status or a rate limit – and a target refused before connecting)
RETRY = teams.WELCOME_RETRY | {"rate_limited", "http", "host_not_allowed", "invalid_url"}

LABELS = {
    "de": {
        "label": "Hersteller-News meiner Produkte",
        "footer": [
            "Diese Nachricht hat Cobe News automatisch an dich versendet – für die Produkte, die dir in deinem Team zugeordnet sind, und die CVEs, die du beobachtest.",
            "Ein- und ausschalten: Einstellungen › Benachrichtigungen › Hersteller-News meiner Produkte (Beobachtete CVEs: Einstellungen › Benachrichtigungen › Beobachtete CVEs).",
        ],
        "summary": "{n} neue Hersteller-News",
        "summary_text": "Höchste Schwere: {sev} · {first}",
    },
    "en": {
        "label": "Vendor news of my products",
        "footer": [
            "Sent to you automatically by Cobe News – for the products assigned to you in your team and the CVEs you watch.",
            "Switch on or off: Settings › Notifications › Vendor news of my products (watched CVEs: Settings › Notifications › Watched CVEs).",
        ],
        "summary": "{n} new vendor news",
        "summary_text": "Highest severity: {sev} · {first}",
    },
}


def _lang(lang: str | None) -> str:
    return lang if lang in LABELS else "de"


# ---------------------------------------------------------------- what is allowed


async def allowed_since(db: AsyncSession) -> dict[str, datetime | None]:
    """Since when an admin allows each way (Teams on and the way's switch on) – events from before are never sent."""
    conf = await teams.config(db)
    out: dict[str, datetime | None] = {}
    for way in WAYS:
        v = conf.get(f"personal_{way}_since")
        try:
            out[way] = datetime.fromisoformat(v) if v else None
        except (TypeError, ValueError):
            out[way] = None
    return out


async def allowed(db: AsyncSession) -> dict[str, bool]:
    """The ways an admin allows (all off while Teams is off); desktop also needs Web Push on the server."""
    conf = await teams.config(db)
    if not conf.get("enabled"):
        return dict.fromkeys(WAYS, False)
    return {
        "email": bool(conf.get("personal_email")),
        "desktop": bool(conf.get("personal_desktop")) and get_config().web_push,
        "teams": bool(conf.get("personal_teams")),
    }


def _host_ok(host: str) -> bool:
    host = host.lower().rstrip(".")
    for pat in TEAMS_HOSTS:
        if host.endswith(pat[1:]) and len(host) > len(pat) - 1:
            return True
    return False


def check_teams_url(url: str) -> str:
    """A person's Teams Workflows URL – or notify.NotifyError(invalid_url | host_not_allowed | forbidden_target): https,
    port 443, on a Teams / Power Automate host, no address of a private network written in it. The address it resolves
    to is checked when connecting (pinned, public only)."""
    url = (url or "").strip()
    if len(url) > URL_MAX or not netaddr.valid_url(url, https_only=True):
        raise notify.NotifyError("invalid_url")
    if netaddr.forbidden_literal(url, **notify.PUBLIC_ONLY):
        raise notify.NotifyError("forbidden_target")
    parts = urlsplit(url)
    if parts.port not in (None, 443) or not _host_ok(parts.hostname or ""):
        raise notify.NotifyError("host_not_allowed")
    return url


def masked(p: PersonNotify | None) -> str | None:
    """What the UI shows of a stored URL: its host and "/…" – the path is the secret."""
    return f"{p.teams_host}/…" if p is not None and p.teams_url_enc and p.teams_host else None


def wants(p: PersonNotify, ev_kind: str, severity: str) -> bool:
    """The person's filter: the kind (vulnerabilities | versions & EOL | advisory changed) and, for vulnerabilities and
    advisory changes, the minimum severity (as the rules: the severity of a version or EOL event is not filtered)."""
    if ev_kind == WATCH:
        return True  # the person chose this very CVE
    if EVENT_KINDS.get(ev_kind) not in (p.kinds or []):
        return False
    return ev_kind not in ("vuln", "change") or notify.RANK.get(severity, 0) >= notify.RANK.get(p.min_severity or "info", 0)


# ---------------------------------------------------------------- routing


async def set_routing(db: AsyncSession, tp: TeamProduct, all_members: bool, members: list[uuid.UUID]) -> None:
    """A team product for all members or for these (already checked to be members). Whoever gets it from now on and did
    not before gets its events from now on (person_routes) – never the older ones. Not committed."""
    now = datetime.now(UTC)
    before = set(await db.scalars(select(TeamProductMember.user_id).where(TeamProductMember.team_product_id == tp.id)))

    async def since_now(rows) -> None:  # noqa: ANN001
        stmt = pg_insert(PersonRoute).from_select(["team_product_id", "user_id", "since"], rows) if not isinstance(rows, list) else pg_insert(PersonRoute).values(rows)
        await db.execute(stmt.on_conflict_do_update(index_elements=["team_product_id", "user_id"], set_={"since": now}))

    if all_members:
        if not tp.all_members:
            rows = select(literal(tp.id, Uuid()), TeamMember.user_id, literal(now, dbm.UTCDateTime())).where(TeamMember.team_id == tp.team_id)
            if before:
                rows = rows.where(TeamMember.user_id.not_in(before))
            await since_now(rows)
        await db.execute(delete(TeamProductMember).where(TeamProductMember.team_product_id == tp.id))
    else:
        want = set(members)
        new = set() if tp.all_members else want - before
        if new:
            await since_now([{"team_product_id": tp.id, "user_id": u, "since": now} for u in sorted(new)])
        await db.execute(delete(TeamProductMember).where(TeamProductMember.team_product_id == tp.id, TeamProductMember.user_id.not_in(want or {uuid.UUID(int=0)})))
        if want:
            await db.execute(pg_insert(TeamProductMember).values([{"team_product_id": tp.id, "user_id": u} for u in sorted(want)]).on_conflict_do_nothing())
        await db.execute(delete(PersonRoute).where(PersonRoute.team_product_id == tp.id, PersonRoute.user_id.not_in(want or {uuid.UUID(int=0)})))
    tp.all_members = all_members


def _routes(
    way: str,
    *,
    user_id: uuid.UUID | None = None,
    user_ids: list[uuid.UUID] | None = None,
    event_ids: list[uuid.UUID] | None = None,
    fresh: bool = True,
    after: datetime | None = None,
):  # noqa: ANN202
    """SQL: (event id, kind, severity, person, created) – a Vendor News event of a product of a team whose member gets
    it on `way`: not a baseline, not older than MAX_AGE, the account active, the way switched on before the event, the
    event after the assignment, the joining and the routing. `fresh`: only those not decided for that way yet."""
    on = getattr(PersonNotify, f"{way}_on")
    since = getattr(PersonNotify, f"{way}_since")
    chosen = exists().where(TeamProductMember.team_product_id == TeamProduct.id, TeamProductMember.user_id == TeamMember.user_id)
    later = exists().where(PersonRoute.team_product_id == TeamProduct.id, PersonRoute.user_id == TeamMember.user_id, PersonRoute.since >= VendorEvent.created_at)
    where = [
        VendorEvent.baseline.is_(False),
        VendorEvent.kind.in_(tuple(EVENT_KINDS)),
        VendorEvent.created_at > datetime.now(UTC) - MAX_AGE,
        User.is_active.is_(True),
        on.is_(True),
        since.is_not(None),
        VendorEvent.created_at > since,
        VendorEvent.created_at > TeamProduct.added_at,
        VendorEvent.created_at > TeamMember.added_at,
        or_(TeamProduct.all_members.is_(True), chosen),
        ~later,
        ~_covered(),  # away: the deputy gets it instead (unless "also to me")
    ]
    if after is not None:
        where.append(VendorEvent.created_at > after)  # the way allowed by an admin only since then
    if user_id is not None:
        where.append(TeamMember.user_id == user_id)
    if user_ids is not None:
        where.append(TeamMember.user_id.in_(user_ids))
    if event_ids is not None:
        where.append(VendorEvent.id.in_(event_ids))
    if fresh:
        where.append(~exists().where(PersonDelivery.event_id == VendorEvent.id, PersonDelivery.user_id == TeamMember.user_id, PersonDelivery.way == way))
    team = (
        select(VendorEvent.id, VendorEvent.kind, VendorEvent.severity, TeamMember.user_id, VendorEvent.created_at)
        .join(VendorFollow, VendorFollow.product == VendorEvent.product)
        .join(TeamProduct, TeamProduct.follow_id == VendorFollow.id)
        .join(TeamMember, TeamMember.team_id == TeamProduct.team_id)
        .join(User, User.id == TeamMember.user_id)
        .join(PersonNotify, PersonNotify.user_id == TeamMember.user_id)
        .where(*where)
        .distinct()
    )
    deputy = _deputy_routes(way, on, since, user_id=user_id, user_ids=user_ids, event_ids=event_ids, fresh=fresh, after=after)
    return union(team, _watch_routes(way, on, since, user_id=user_id, user_ids=user_ids, event_ids=event_ids, fresh=fresh, after=after), deputy)


def _deputy_ok(pa, team_id, at):  # noqa: ANN001, ANN202
    """SQL: the deputy of absence `pa` takes an event of a product of team `team_id` created at `at`: an active account,
    a member of that team since before the event, not away then themselves (no chains), with a way of their own on."""
    du, dm, dp, away = aliased(User), aliased(TeamMember), aliased(PersonNotify), aliased(PersonAbsence)
    # nested two levels deep: correlated explicitly (everything but the subquery's own table comes from outside)
    return and_(
        exists().where(du.id == pa.deputy_id, du.is_active.is_(True)).correlate_except(du),
        exists().where(dm.team_id == team_id, dm.user_id == pa.deputy_id, dm.added_at < at).correlate_except(dm),
        ~exists().where(away.user_id == pa.deputy_id, away.starts_at <= at, away.ends_at > at).correlate_except(away),
        exists().where(dp.user_id == pa.deputy_id, or_(dp.email_on.is_(True), dp.desktop_on.is_(True), dp.teams_on.is_(True))).correlate_except(dp),
    )


def _covered():  # noqa: ANN202
    """SQL (inside the team routes): the member was away when the event came and a deputy took it – not "also to me"."""
    pa = aliased(PersonAbsence)
    return exists().where(
        pa.user_id == TeamMember.user_id,
        pa.also_me.is_(False),
        pa.starts_at <= VendorEvent.created_at,
        pa.ends_at > VendorEvent.created_at,
        _deputy_ok(pa, TeamProduct.team_id, VendorEvent.created_at),
    )


def _deputy_routes(way: str, on, since, *, user_id, user_ids, event_ids, fresh: bool, after):  # noqa: ANN001, ANN202
    """SQL: the same columns for the deputies – an event of a product routed to an absent person, created during the
    absence, to the deputy (a member of the product's team) on the deputy's own way. Watched CVEs never (they are the
    person's own), and never on to a deputy who is away then."""
    pa, am, au, dm, du = aliased(PersonAbsence), aliased(TeamMember), aliased(User), aliased(TeamMember), aliased(User)
    away = aliased(PersonAbsence)
    chosen = exists().where(TeamProductMember.team_product_id == TeamProduct.id, TeamProductMember.user_id == am.user_id)
    later = exists().where(PersonRoute.team_product_id == TeamProduct.id, PersonRoute.user_id == am.user_id, PersonRoute.since >= VendorEvent.created_at)
    where = [
        VendorEvent.baseline.is_(False),
        VendorEvent.kind.in_(tuple(EVENT_KINDS)),
        VendorEvent.created_at > datetime.now(UTC) - MAX_AGE,
        au.is_active.is_(True),
        du.is_active.is_(True),
        on.is_(True),
        since.is_not(None),
        VendorEvent.created_at > since,
        VendorEvent.created_at > TeamProduct.added_at,
        VendorEvent.created_at > am.added_at,
        VendorEvent.created_at > dm.added_at,
        pa.starts_at <= VendorEvent.created_at,
        pa.ends_at > VendorEvent.created_at,
        or_(TeamProduct.all_members.is_(True), chosen),
        ~later,
        ~exists().where(away.user_id == pa.deputy_id, away.starts_at <= VendorEvent.created_at, away.ends_at > VendorEvent.created_at),
    ]
    if after is not None:
        where.append(VendorEvent.created_at > after)
    if user_id is not None:
        where.append(pa.deputy_id == user_id)
    if user_ids is not None:
        where.append(pa.deputy_id.in_(user_ids))
    if event_ids is not None:
        where.append(VendorEvent.id.in_(event_ids))
    if fresh:
        where.append(~exists().where(PersonDelivery.event_id == VendorEvent.id, PersonDelivery.user_id == pa.deputy_id, PersonDelivery.way == way))
    return (
        select(VendorEvent.id, VendorEvent.kind, VendorEvent.severity, pa.deputy_id, VendorEvent.created_at)
        .join(VendorFollow, VendorFollow.product == VendorEvent.product)
        .join(TeamProduct, TeamProduct.follow_id == VendorFollow.id)
        .join(am, am.team_id == TeamProduct.team_id)
        .join(pa, pa.user_id == am.user_id)
        .join(dm, and_(dm.team_id == TeamProduct.team_id, dm.user_id == pa.deputy_id))
        .join(au, au.id == am.user_id)
        .join(du, du.id == pa.deputy_id)
        .join(PersonNotify, PersonNotify.user_id == pa.deputy_id)
        .where(*where)
    )


def _watch_routes(way: str, on, since, *, user_id, user_ids, event_ids, fresh: bool, after):  # noqa: ANN001, ANN202
    """SQL: the same columns for the events of watched CVEs (kind "watch", scope watch:<CVE>) – to the people who watch
    the CVE since before the event, active, the way switched on before the event. No team needed."""
    where = [
        VendorEvent.kind == WATCH,
        VendorEvent.baseline.is_(False),
        VendorEvent.created_at > datetime.now(UTC) - MAX_AGE,
        User.is_active.is_(True),
        on.is_(True),
        since.is_not(None),
        VendorEvent.created_at > since,
        VendorEvent.created_at > CveWatch.created_at,
    ]
    if after is not None:
        where.append(VendorEvent.created_at > after)
    if user_id is not None:
        where.append(CveWatch.user_id == user_id)
    if user_ids is not None:
        where.append(CveWatch.user_id.in_(user_ids))
    if event_ids is not None:
        where.append(VendorEvent.id.in_(event_ids))
    if fresh:
        where.append(~exists().where(PersonDelivery.event_id == VendorEvent.id, PersonDelivery.user_id == CveWatch.user_id, PersonDelivery.way == way))
    return (
        select(VendorEvent.id, VendorEvent.kind, VendorEvent.severity, CveWatch.user_id, VendorEvent.created_at)
        .join(CveWatch, VendorEvent.scope == literal("watch:") + CveWatch.cve)
        .join(User, User.id == CveWatch.user_id)
        .join(PersonNotify, PersonNotify.user_id == CveWatch.user_id)
        .where(*where)
    )


async def enqueue(db: AsyncSession, ways: dict[str, bool]) -> int:
    """New events → a row per person and allowed way: pending, or skipped when the person's filter leaves it out (then
    it stays out, also after a wider filter later). Returns the pending rows added."""
    now = datetime.now(UTC)
    added = 0
    marks: dict[uuid.UUID, int] = {}  # per event, what makes it urgent (app/quiet.py) – read once for all ways
    since = await allowed_since(db)
    for way in WAYS:
        if not ways.get(way):
            continue
        rows = list(await db.execute(_routes(way, after=since.get(way))))
        if not rows:
            continue
        prefs = await _prefs(db, {r[3] for r in rows})
        await _marks(db, {r[0] for r in rows} - set(marks), marks)
        # muted by the person for a while (app/reader.py): decided now, like the filter – not sent later either
        hushed = await reader.muted_events(db, [(r[0], r[3]) for r in rows])
        values = []
        for ev_id, kind, sev, uid, _at in rows:
            ok = wants(prefs[uid], kind, sev) and (ev_id, uid) not in hushed
            why = None if ok else "muted" if (ev_id, uid) in hushed else "filtered"
            values.append({"event_id": ev_id, "user_id": uid, "way": way, "status": "pending" if ok else "skipped", "error": why, "tries": 0, "created_at": now, "marks": marks.get(ev_id, 0)})
            added += ok
        await dbm.release(db)  # what was read: no transaction stays open
        for i in range(0, len(values), 1000):
            # each chunk on its own (short transactions): the rows are keyed, a chunk written twice adds nothing
            await db.execute(pg_insert(PersonDelivery).values(values[i : i + 1000]).on_conflict_do_nothing())
            await db.commit()
    return added


async def _marks(db: AsyncSession, ids: set[uuid.UUID], into: dict[uuid.UUID, int]) -> None:
    """The urgency bits of these events (quiet.marks_of), added to `into`."""
    want = sorted(ids)
    for i in range(0, len(want), IN_CHUNK):
        q = select(VendorEvent.id, VendorEvent.kind, VendorEvent.severity, VendorEvent.data).where(VendorEvent.id.in_(want[i : i + IN_CHUNK]))
        for ev_id, kind, sev, data in await db.execute(q):
            into[ev_id] = quiet.marks_of(kind, sev, data)


async def _prefs(db: AsyncSession, user_ids: set[uuid.UUID]) -> dict[uuid.UUID, PersonNotify]:
    ids = sorted(user_ids)
    out: dict[uuid.UUID, PersonNotify] = {}
    for i in range(0, len(ids), IN_CHUNK):
        out.update({p.user_id: p for p in await db.scalars(select(PersonNotify).where(PersonNotify.user_id.in_(ids[i : i + IN_CHUNK])))})
    return out


# ---------------------------------------------------------------- the messages


def event_path(ev: VendorEvent) -> str:
    """The event in Vendor News: the product's drawer – at the finding (a vulnerability) or its versions."""
    if ev.kind == WATCH:
        return "/watch?" + urlencode({"cve": str((ev.data or {}).get("cve") or "")})
    q = {"product": ev.product}
    if ev.kind == "vuln" and ev.scope and ev.key.startswith(ev.scope + ":"):
        q["finding"] = ev.key[len(ev.scope) + 1 :]
    elif ev.kind in ("version", "eol"):
        q["view"] = "versions"
    elif ev.kind == "change":
        q["view"] = "changes"
    return "/vendor?" + urlencode(q)


def story(ev: VendorEvent, lang: str) -> notify.Story:
    s = notify.vendor_story(ev, lang)
    s.link = get_config().base_url + event_path(ev)
    s.ours = []  # every event here is of the person's own products – the footer says so, no mark on each
    return s


def _ordered(events: list[VendorEvent]) -> list[VendorEvent]:
    return sorted(events, key=lambda e: (notify.RANK.get(e.severity, 0), e.created_at), reverse=True)


def render_mail(events: list[VendorEvent], lang: str, tz: str | None = None) -> tuple[str, str, str]:
    """The person's mail – times in their own zone (`tz`: their quiet hours' zone, else Europe/Berlin). The LIST shown
    are cut in the order the mail shows them (notify.priority: exploited or critical first, then by severity, newest)."""
    lang = _lang(lang)
    shown = sorted((story(e, lang) for e in events), key=notify.priority, reverse=True)[:LIST]
    return notify.render_mail(LABELS[lang]["label"], shown, len(events), lang, footer=LABELS[lang]["footer"], tz=tz)


def render_teams(events: list[VendorEvent], lang: str, *, test: bool = False) -> dict:
    lang = _lang(lang)
    shown = _ordered(events)[:LIST] if events else []
    stories = [story(e, lang) for e in shown] or [notify.EXAMPLE]
    return notify.render_teams(LABELS[lang]["label"], stories, len(events) or 1, lang, test=test)


def push_payloads(events: list[VendorEvent], lang: str) -> list[dict]:
    """One event: itself (product, title, severity, a link to it in Vendor News); more: one summary."""
    lang = _lang(lang)
    top = _ordered(events)
    if len(top) == 1:
        s = story(top[0], lang)
        d = top[0].data or {}
        # the catalogue's label of today (a product renamed, split or merged since the event keeps its old one)
        product = notify.label_now(top[0].product, str(d["product"])) if d.get("product") else str(d.get("cve") or top[0].product)
        return [webpush.vendor_payload(str(top[0].id), s.title, product, top[0].severity, event_path(top[0]), lang)]
    first = story(top[0], lang)
    sev = notify.LABELS[lang]["sev"].get(top[0].severity, top[0].severity)
    lb = LABELS[lang]
    return [
        {
            "v": 1,
            "kind": "vendor-summary",
            "id": f"vendor-summary-{int(time.time())}",
            "title": lb["summary"].format(n=len(top)),
            "body": lb["summary_text"].format(sev=sev, first=first.title[:120]),
            "severity": top[0].severity,
            "url": "/vendor",
        }
    ]


# ---------------------------------------------------------------- the round


@dataclass
class _Seen:
    marks: tuple | None = None
    full_at: float = -1e9
    more: bool = False  # the last round stopped at its budget with work left


_seen = _Seen()


def reset() -> None:
    global _seen
    _seen = _Seen()


def backlog() -> bool:
    """The last round stopped at its budget (ROUND_JOBS, ROUND_S) with messages left – worth a next round soon."""
    return _seen.more


@dataclass
class _Job:
    user_id: uuid.UUID
    way: str
    lang: str
    events: list[VendorEvent]
    failures: int
    address: str = ""
    url: str = ""
    subs: list[PushSubscription] = field(default_factory=list)
    error: notify.NotifyError | None = None  # could not even be set up (the URL unreadable)
    tz: str = quiet.DEFAULT_TZ  # the person's zone (the mail's times)


_LATE = object()  # a message not started before the round's deadline: claimed, certainly not sent


def _state(p: PersonNotify, way: str) -> dict:
    return dict(getattr(p, f"state_{way}") or {})


async def _set_state(db: AsyncSession, user_id: uuid.UUID, way: str, values: dict) -> None:
    col = f"state_{way}"
    await db.execute(update(PersonNotify).where(PersonNotify.user_id == user_id).values({col: values}).execution_options(synchronize_session=False))


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


# set-based writes: many (event, person, way) rows in one statement – arrays, not one parameter per value
_ROWS = "unnest(CAST(:e AS uuid[]), CAST(:u AS uuid[]), CAST(:w AS text[])) AS t(e, u, w)"
_ON_ROWS = "d.event_id = t.e AND d.user_id = t.u AND d.way = t.w"


def _cols(rows: list[tuple[uuid.UUID, uuid.UUID, str]]) -> dict:
    return {"e": [r[0] for r in rows], "u": [r[1] for r in rows], "w": [r[2] for r in rows]}


async def _skip_rows(db: AsyncSession, rows: list[tuple[uuid.UUID, uuid.UUID, str]], why: str) -> None:
    """These pending rows (event, person, way): decided not to send."""
    if rows:
        await db.execute(text(f"UPDATE person_deliveries d SET status = 'skipped', error = :why FROM {_ROWS} WHERE {_ON_ROWS} AND d.status = 'pending'"), {**_cols(rows), "why": why})


async def _skip_groups(db: AsyncSession, groups: list[tuple[uuid.UUID, str]], why: str, now: datetime | None = None) -> None:
    """Every pending row of these person-ways: decided not to send; with `now` the way's state says why (the person sees
    it under the way)."""
    if not groups:
        return
    await db.execute(
        update(PersonDelivery)
        .where(PersonDelivery.status == "pending", tuple_(PersonDelivery.user_id, PersonDelivery.way).in_(groups))
        .values(status="skipped", error=why)
        .execution_options(synchronize_session=False)
    )
    if now is not None:
        for way in WAYS:
            uids = [u for u, w in groups if w == way]
            if uids:
                await _patch_states(db, way, [(u, {"last_error": why, "last_error_at": now.isoformat()}) for u in uids])


async def _patch_states(db: AsyncSession, way: str, patches: list[tuple[uuid.UUID, dict]]) -> None:
    """The way's state of many people at once, each merged with its own keys (the other keys stay)."""
    if not patches:
        return
    col = f"state_{way}"  # one of WAYS – never input
    await db.execute(
        text(f"UPDATE person_notify p SET {col} = COALESCE(p.{col}, '{{}}'::jsonb) || CAST(t.s AS jsonb) FROM unnest(CAST(:u AS uuid[]), CAST(:s AS text[])) AS t(u, s) WHERE p.user_id = t.u"),
        {"u": [u for u, _ in patches], "s": [notify._json(s).decode() for _, s in patches]},
    )


async def _sweep(db: AsyncSession, ways: dict[str, bool], now: datetime) -> None:
    """What will not be sent, decided for all open rows at once: a way an admin switched off, an account switched off,
    a way the person switched off, an event too old to be news any more (a long outage of the way). Committed."""

    def skip(why: str, *where) -> object:  # noqa: ANN002
        return update(PersonDelivery).where(PersonDelivery.status == "pending", *where).values(status="skipped", error=why).execution_options(synchronize_session=False)

    off = [w for w in WAYS if not ways.get(w)]
    if off:
        await db.execute(skip("way_off", PersonDelivery.way.in_(off)))
    await db.execute(skip("inactive", PersonDelivery.user_id.in_(select(User.id).where(User.is_active.is_(False)))))
    on = case((PersonDelivery.way == "email", PersonNotify.email_on), (PersonDelivery.way == "desktop", PersonNotify.desktop_on), else_=PersonNotify.teams_on)
    await db.execute(skip("off", ~exists().where(PersonNotify.user_id == PersonDelivery.user_id, on.is_(True))))
    await db.execute(skip("expired", PersonDelivery.event_id.in_(select(VendorEvent.id).where(VendorEvent.created_at <= now - MAX_AGE))))
    await db.commit()


Hold = tuple[uuid.UUID, str, datetime | None, int]  # person, way, cutoff (None: nothing normal), urgent bits


async def _holds(db: AsyncSession, now: datetime) -> list[Hold]:
    """The person-ways whose normal rows wait now (quiet hours, a collecting time) – read once per round, only for people
    with a schedule and something open. Everybody else: nothing held (as before 0.1.35)."""
    has_open = exists().where(PersonDelivery.user_id == PersonNotify.user_id, PersonDelivery.status == "pending")
    q = select(PersonNotify.user_id, PersonNotify.schedule).where(cast(PersonNotify.schedule, SqlText) != "{}", has_open)
    out: list[Hold] = []
    for uid, sched in await db.execute(q):
        if not quiet.active(sched):
            continue
        bits = quiet.mask(sched)
        for way in WAYS:
            held, cut = quiet.hold(sched, way, now)
            if held:
                out.append((uid, way, cut, bits))
    return out


def _eligible(holds: list[Hold] | None):  # noqa: ANN202
    """SQL: this person_deliveries row may go now – not held, or urgent for its person, or queued before its way's
    collecting time. One array-valued table for all held person-ways (no parameter per person)."""
    if not holds:
        return true()
    h = (
        func.unnest(
            literal([x[0] for x in holds], ARRAY(Uuid())),
            literal([x[1] for x in holds], ARRAY(SqlText())),
            literal([x[2] for x in holds], ARRAY(TIMESTAMP(timezone=True))),
            literal([x[3] for x in holds], ARRAY(Integer())),
        )
        .table_valued("u", "w", "c", "m")
        .render_derived(name="h")
    )
    blocked = (
        select(literal(1))
        .select_from(h)
        .where(h.c.u == PersonDelivery.user_id, h.c.w == PersonDelivery.way, PersonDelivery.marks.op("&")(h.c.m) == 0, or_(h.c.c.is_(None), PersonDelivery.created_at > h.c.c))
        .correlate(PersonDelivery)
        .exists()
    )
    return ~blocked


async def _candidates(db: AsyncSession, now: datetime, limit: int, holds: list[Hold] | None = None) -> list[tuple[uuid.UUID, str]]:
    """The person-ways with pending rows whose pause is over, the one waiting longest first (its oldest pending row) –
    fair: whoever is not served this round is ahead of everything that came later. Desktop: only with a browser that
    is not pausing (or with none – then the round skips it as "no_device")."""
    g = (
        select(PersonDelivery.user_id, PersonDelivery.way, func.min(PersonDelivery.created_at).label("oldest"))
        .where(PersonDelivery.status == "pending", _eligible(holds))
        .group_by(PersonDelivery.user_id, PersonDelivery.way)
        .subquery()
    )
    nxt = case(
        (g.c.way == "email", func.jsonb_extract_path_text(PersonNotify.state_email, "next_try_at")),
        (g.c.way == "desktop", func.jsonb_extract_path_text(PersonNotify.state_desktop, "next_try_at")),
        else_=func.jsonb_extract_path_text(PersonNotify.state_teams, "next_try_at"),
    )
    # a value that is no timestamp counts as no pause (CASE: the cast is only tried on one that looks like one)
    due = case((nxt.op("~")(r"^\d{4}-\d{2}-\d{2}"), cast(nxt, TIMESTAMP(timezone=True)) <= now), else_=true())
    has = exists().where(PushSubscription.user_id == g.c.user_id)
    ready = exists().where(PushSubscription.user_id == g.c.user_id, or_(PushSubscription.next_try_at.is_(None), PushSubscription.next_try_at <= now))
    q = (
        select(g.c.user_id, g.c.way)
        .join(PersonNotify, PersonNotify.user_id == g.c.user_id)
        .where(due, or_(g.c.way != "desktop", ~has, ready))
        .order_by(g.c.oldest, g.c.user_id, g.c.way)
        .limit(limit)
    )
    return [(r[0], r[1]) for r in await db.execute(q)]


async def _prepare(db: AsyncSession, ways: dict[str, bool], now: datetime, groups: list[tuple[uuid.UUID, str]] | None = None, holds: list[Hold] | None = None) -> list[_Job]:
    """The pending rows of these person-ways (else: the next BATCH due ones), checked again (the way, the account, the
    routing, the filter may have changed since they were queued), claimed and committed – nothing is sent before the
    claim is in the database. A fixed number of statements, whatever the number of people."""
    if groups is None:
        await _sweep(db, ways, now)
        holds = await _holds(db, now)
        groups = await _candidates(db, now, BATCH, holds)
    groups = [g for g in groups if ways.get(g[1])]
    if not groups:
        await db.commit()
        return []
    uids = sorted({u for u, _ in groups})
    people = {p.user_id: (p, email) for p, email in await db.execute(select(PersonNotify, User.email).join(User, User.id == PersonNotify.user_id).where(PersonNotify.user_id.in_(uids)))}
    # the open rows of these person-ways, at most PER_GROUP each (the oldest first)
    rn = func.row_number().over(partition_by=(PersonDelivery.user_id, PersonDelivery.way), order_by=(PersonDelivery.created_at, PersonDelivery.event_id)).label("rn")
    sub = (
        select(PersonDelivery.user_id, PersonDelivery.way, PersonDelivery.event_id, rn)
        .where(PersonDelivery.status == "pending", tuple_(PersonDelivery.user_id, PersonDelivery.way).in_(groups), _eligible(holds))
        .subquery()
    )
    open_: dict[tuple[uuid.UUID, str], list[uuid.UUID]] = {}
    for uid, way, ev in await db.execute(select(sub.c.user_id, sub.c.way, sub.c.event_id).where(sub.c.rn <= PER_GROUP)):
        open_.setdefault((uid, way), []).append(ev)
    # still routed and still wanted – one query per way for the whole batch
    still: dict[tuple[uuid.UUID, str], list[tuple]] = {}
    for way in WAYS:
        keys = [k for k in open_ if k[1] == way]
        if not keys:
            continue
        evs = sorted({e for k in keys for e in open_[k]})
        mine = {(k[0], e) for k in keys for e in open_[k]}
        who = sorted({k[0] for k in keys})
        for i in range(0, len(evs), IN_CHUNK):
            for ev, kind, sev, uid, at in await db.execute(_routes(way, user_ids=who, event_ids=evs[i : i + IN_CHUNK], fresh=False)):
                entry = people.get(uid)
                if (uid, ev) in mine and entry is not None and wants(entry[0], kind, sev):
                    still.setdefault((uid, way), []).append((ev, sev, at))
    # muted since it was queued (app/reader.py): skipped as "muted", never sent after the mute ends either
    hushed = await reader.muted_events(db, [(r[0], uid) for (uid, _way), rows in still.items() for r in rows])
    if hushed:
        still = {k: kept_ for k, rows in still.items() if (kept_ := [r for r in rows if (r[0], k[0]) not in hushed])}
    kept = {(uid, way, r[0]) for (uid, way), rows in still.items() for r in rows}
    gone = [(ev, uid, way) for (uid, way), evs in open_.items() for ev in evs if (uid, way, ev) not in kept]
    await _skip_rows(db, [g for g in gone if (g[0], g[1]) in hushed], "muted")
    await _skip_rows(db, [g for g in gone if (g[0], g[1]) not in hushed], "not_routed")
    jobs: list[_Job] = []
    no: dict[str, list[tuple[uuid.UUID, str]]] = {"no_address": [], "no_device": [], "no_url": []}
    desktop = sorted({uid for uid, way in still if way == "desktop"})
    subs: dict[uuid.UUID, list[PushSubscription]] = {}
    if desktop:
        for s in await db.scalars(select(PushSubscription).where(PushSubscription.user_id.in_(desktop))):
            subs.setdefault(s.user_id, []).append(s)
    for (uid, way), _rows in still.items():
        p, email = people[uid]
        job = _Job(uid, way, _lang(p.lang), [], int(_state(p, way).get("failures") or 0), tz=quiet.out(p.schedule)["tz"])
        if way == "email":
            if not email or not teams.MAIL.fullmatch(email):
                no["no_address"].append((uid, way))
                continue
            job.address = email
        elif way == "desktop":
            mine_subs = subs.get(uid, [])
            if not mine_subs:
                no["no_device"].append((uid, way))
                continue
            job.subs = [s for s in mine_subs if s.next_try_at is None or s.next_try_at <= now]
            if not job.subs:
                continue  # every browser is pausing: the next round
        else:
            try:
                job.url = decrypt_str(p.teams_url_enc) if p.teams_url_enc else ""
            except Exception:  # noqa: BLE001 - another master key: the person enters the URL again
                job.error = notify.NotifyError("secret_unreadable")
            if not job.url and job.error is None:
                no["no_url"].append((uid, way))
                continue
        jobs.append(job)
    await _skip_groups(db, no["no_address"], "no_address", now)
    await _skip_groups(db, no["no_device"], "no_device", now)
    await _skip_groups(db, no["no_url"], "no_url")
    # the claim: per person and way the most severe and newest first, at most CLAIM_MAX – the rest waits for the next round
    top: list[tuple[uuid.UUID, uuid.UUID, str]] = []
    for job in jobs:
        rows = sorted(still[(job.user_id, job.way)], key=lambda r: (notify.RANK.get(r[1], 0), r[2]), reverse=True)[:CLAIM_MAX]
        top += [(r[0], job.user_id, job.way) for r in rows]
    claimed: dict[tuple[uuid.UUID, str], list[uuid.UUID]] = {}
    if top:
        res = await db.execute(
            text(f"UPDATE person_deliveries d SET status = 'sending', tries = d.tries + 1, claimed_at = :now FROM {_ROWS} WHERE {_ON_ROWS} AND d.status = 'pending' RETURNING d.user_id, d.way, d.event_id"),
            {**_cols(top), "now": now},
        )
        for uid, way, ev in res:
            claimed.setdefault((uid, way), []).append(ev)
    want = sorted({e for evs in claimed.values() for e in evs})
    events: dict[uuid.UUID, VendorEvent] = {}
    for i in range(0, len(want), IN_CHUNK):
        events.update({e.id: e for e in await db.scalars(select(VendorEvent).where(VendorEvent.id.in_(want[i : i + IN_CHUNK])))})
    out = []
    for job in jobs:
        ids = claimed.get((job.user_id, job.way))
        if ids:  # none: another round took them meanwhile
            job.events = [events[i] for i in ids]
            out.append(job)
    await db.commit()  # every claim in the database before the first message goes out
    db.expunge_all()  # the jobs' events and browsers: plain values from here on, never written back by a later flush
    return out


async def _send(job: _Job, smtp: dict, key: webpush.Vapid | None) -> tuple[notify.NotifyError | None, list]:
    """One message (or one per browser) – no database work. (outcome, [(subscription, its outcome)])."""
    if job.error is not None:
        return job.error, []
    try:
        async with asyncio.timeout(SEND_DEADLINE):
            if job.way == "email":
                subject, text_, html = render_mail(job.events, job.lang, job.tz)
                await notify.send_mail(smtp, [job.address], subject, text_, html)
            elif job.way == "teams":
                url = check_teams_url(job.url)
                await notify.post(url, notify._json(render_teams(job.events, job.lang)), notify.JSON_HEADERS, policy=notify.PUBLIC_ONLY)
            else:
                if key is None:
                    return notify.NotifyError("not_configured"), []
                payloads = push_payloads(job.events, job.lang)
                outs = [(s, await webpush.send_all(s, payloads, key)) for s in job.subs]
                if any(o is None for _, o in outs):
                    return None, outs
                errs = [o for _, o in outs if isinstance(o, notify.NotifyError)]
                # every browser failed: again when one of them certainly got nothing, else failed
                retry = [e for e in errs if e.category in RETRY]
                return (retry or errs or [notify.NotifyError("rejected")])[0], outs
    except notify.NotifyError as exc:
        return exc, []
    except TimeoutError:
        return notify.NotifyError("timeout"), []
    except Exception as exc:  # noqa: BLE001 - one broken target must not stop the round
        log.warning("personal %s: %s", job.way, type(exc).__name__)
        return notify.NotifyError("connection", type(exc).__name__), []
    return None, []


async def _send_batch(jobs: list[_Job], smtp: dict, key: webpush.Vapid | None, deadline: float) -> list:
    """CONCURRENCY messages at a time, each within SEND_DEADLINE; one not started before `deadline` is not sent at all
    (_LATE). No database work."""
    gate = asyncio.Semaphore(CONCURRENCY)

    async def one(j: _Job) -> object:
        async with gate:
            if time.monotonic() >= deadline:
                return _LATE
            return await _send(j, smtp, key)

    return list(await asyncio.gather(*(one(j) for j in jobs)))


async def _settle(db: AsyncSession, job: _Job, outcome: notify.NotifyError | None, subs: list, now: datetime) -> int:
    """One message's rows, browsers and state (the fallback when a batch could not be written at once)."""
    ids = [e.id for e in job.events]
    rows = update(PersonDelivery).where(PersonDelivery.user_id == job.user_id, PersonDelivery.way == job.way, PersonDelivery.event_id.in_(ids), PersonDelivery.status == "sending")
    p = await db.get(PersonNotify, job.user_id)
    state = _state(p, job.way) if p is not None else {}
    for sub, out in subs:  # each browser's own state, as the news push does (404/410: the browser dropped it)
        _ok, values = webpush._after(sub, out)
        if values is None:
            await db.execute(delete(PushSubscription).where(PushSubscription.id == sub.id))
        else:
            await db.execute(update(PushSubscription).where(PushSubscription.id == sub.id).values(**values))
    if outcome is None:
        await db.execute(rows.values(status="sent", sent_at=now, error=None).execution_options(synchronize_session=False))
        new = {"failures": 0, "next_try_at": None, "last_ok_at": now.isoformat(), "last_error": None, "last_error_at": state.get("last_error_at")}
        sent = len(ids)
    else:
        again = outcome.category in RETRY
        status = case((PersonDelivery.tries < MAX_TRIES, "pending"), else_="failed") if again else "failed"
        await db.execute(rows.values(status=status, error=outcome.category).execution_options(synchronize_session=False))
        f = notify._failure(job.failures, outcome, now)
        new = {**state, "failures": f["failures"], "next_try_at": _iso(f["next_try_at"]), "last_error": f["last_error"], "last_error_at": now.isoformat()}
        log.info("personal %s of %s: %s", job.way, job.user_id, f["last_error"])
        sent = 0
    if p is not None:
        await _set_state(db, job.user_id, job.way, new)
    await db.commit()
    return sent


async def _settle_batch(db: AsyncSession, jobs: list[_Job], outcomes: list, now: datetime) -> dict[str, int]:
    """Every message of a batch written at once: sent rows, rows back to pending (a failure that certainly delivered
    nothing, below MAX_TRIES) or failed, rows never started back to pending without a try, each browser's and each
    way's state. One transaction; if it fails, message by message (one person's write must not undo the others')."""
    sent_rows: list[tuple] = []
    fail_rows: list[tuple] = []  # (event, person, way, category, again)
    late_rows: list[tuple] = []
    states: dict[str, list[tuple[uuid.UUID, dict]]] = {w: [] for w in WAYS}
    sub_gone: list[uuid.UUID] = []
    sub_ok: list[uuid.UUID] = []
    sub_failed: list[tuple[uuid.UUID, dict]] = []
    out = {"sent": 0, "failed": 0}
    for job, res in zip(jobs, outcomes, strict=True):
        triples = [(e.id, job.user_id, job.way) for e in job.events]
        if res is _LATE:
            late_rows += triples
            continue
        outcome, subs = res
        delivery_log.count("personal", job.way, delivery_log.outcome(job.way, outcome)[1])  # counted only, not logged
        for sub, o in subs:
            _ok, values = webpush._after(sub, o)
            if values is None:
                sub_gone.append(sub.id)
            elif o is None:
                sub_ok.append(sub.id)
            else:
                sub_failed.append((sub.id, values))
        if outcome is None:
            sent_rows += triples
            states[job.way].append((job.user_id, {"failures": 0, "next_try_at": None, "last_ok_at": now.isoformat(), "last_error": None}))
            out["sent"] += len(triples)
        else:
            again = outcome.category in RETRY
            fail_rows += [(*t, outcome.category, again) for t in triples]
            f = notify._failure(job.failures, outcome, now)
            states[job.way].append((job.user_id, {"failures": f["failures"], "next_try_at": _iso(f["next_try_at"]), "last_error": f["last_error"], "last_error_at": now.isoformat()}))
            log.info("personal %s of %s: %s", job.way, job.user_id, f["last_error"])
            out["failed"] += 1
    try:
        if sent_rows:
            await db.execute(text(f"UPDATE person_deliveries d SET status = 'sent', sent_at = :now, error = NULL FROM {_ROWS} WHERE {_ON_ROWS} AND d.status = 'sending'"), {**_cols(sent_rows), "now": now})
        if fail_rows:
            await db.execute(
                text(
                    "UPDATE person_deliveries d SET status = CASE WHEN t.again AND d.tries < :max THEN 'pending' ELSE 'failed' END, error = t.err "
                    "FROM unnest(CAST(:e AS uuid[]), CAST(:u AS uuid[]), CAST(:w AS text[]), CAST(:err AS text[]), CAST(:again AS boolean[])) AS t(e, u, w, err, again) "
                    f"WHERE {_ON_ROWS} AND d.status = 'sending'"
                ),
                {**_cols(fail_rows), "err": [r[3] for r in fail_rows], "again": [r[4] for r in fail_rows], "max": MAX_TRIES},
            )
        if late_rows:  # claimed, never started: certainly not sent – back in line, the try not counted
            await db.execute(text(f"UPDATE person_deliveries d SET status = 'pending', tries = GREATEST(d.tries - 1, 0), claimed_at = NULL FROM {_ROWS} WHERE {_ON_ROWS} AND d.status = 'sending'"), _cols(late_rows))
        if sub_gone:
            await db.execute(delete(PushSubscription).where(PushSubscription.id.in_(sub_gone)))
        if sub_ok:
            await db.execute(update(PushSubscription).where(PushSubscription.id.in_(sub_ok)).values(failures=0, last_error=None, next_try_at=None, last_ok_at=now))
        if sub_failed:
            await db.execute(
                text(
                    "UPDATE push_subscriptions s SET failures = t.f, last_error = t.err, last_error_at = t.at, next_try_at = t.nxt "
                    "FROM unnest(CAST(:id AS uuid[]), CAST(:f AS integer[]), CAST(:err AS text[]), CAST(:at AS timestamptz[]), CAST(:nxt AS timestamptz[])) AS t(id, f, err, at, nxt) "
                    "WHERE s.id = t.id"
                ),
                {
                    "id": [i for i, _ in sub_failed],
                    "f": [v["failures"] for _, v in sub_failed],
                    "err": [v["last_error"] for _, v in sub_failed],
                    "at": [v["last_error_at"] for _, v in sub_failed],
                    "nxt": [v["next_try_at"] for _, v in sub_failed],
                },
            )
        for way, patches in states.items():
            await _patch_states(db, way, patches)
        await db.commit()
        return out
    except Exception:  # noqa: BLE001 - written message by message instead
        await db.rollback()
        log.exception("personal: a batch's results not written at once – one by one")
    out = {"sent": 0, "failed": 0}
    late = [(job, res) for job, res in zip(jobs, outcomes, strict=True) if res is _LATE]
    if late:
        try:
            rows = [(e.id, job.user_id, job.way) for job, _ in late for e in job.events]
            await db.execute(text(f"UPDATE person_deliveries d SET status = 'pending', tries = GREATEST(d.tries - 1, 0), claimed_at = NULL FROM {_ROWS} WHERE {_ON_ROWS} AND d.status = 'sending'"), _cols(rows))
            await db.commit()
        except Exception:  # noqa: BLE001 - left at "sending": failed ("interrupted") after STALE_SENDING, never sent twice
            await db.rollback()
            log.exception("personal: messages not started could not be put back")
    for job, res in zip(jobs, outcomes, strict=True):
        if res is _LATE:
            continue
        outcome, subs = res
        try:
            n = await _settle(db, job, outcome, subs, now)
        except Exception:  # noqa: BLE001 - one person's write must not undo the others'
            await db.rollback()
            log.exception("personal: state of %s not written", job.user_id)
            continue
        out["sent" if outcome is None else "failed"] += n if outcome is None else 1
    return out


async def dispatch(db: AsyncSession) -> dict[str, int]:
    """After the rule dispatch: queue what is new for whom, then one message per person and way – at most ROUND_JOBS
    and none started after ROUND_S; the rest the next round (backlog() says so)."""
    _seen.more = False
    ways = await allowed(db)
    now = datetime.now(UTC)
    # claimed but never settled (the process stopped mid-way): never sent again – failed, so the state says so
    await db.execute(
        update(PersonDelivery)
        .where(PersonDelivery.status == "sending", PersonDelivery.claimed_at < now - STALE_SENDING)
        .values(status="failed", error="interrupted")
        .execution_options(synchronize_session=False)
    )
    if not any(ways.values()):
        # Teams or every way switched off: nothing waits for later (no burst when switched on again)
        await db.execute(update(PersonDelivery).where(PersonDelivery.status == "pending").values(status="skipped", error="way_off").execution_options(synchronize_session=False))
        await db.commit()
        await dbm.release(db)
        return {}
    await db.commit()
    marks = (await db.scalar(select(func.max(VendorEvent.n))), tuple(sorted(ways.items())))
    if marks != _seen.marks or time.monotonic() - _seen.full_at > FULL_EVERY:
        await enqueue(db, ways)
        _seen.marks, _seen.full_at = marks, time.monotonic()
    deadline = time.monotonic() + ROUND_S
    await _sweep(db, ways, now)
    holds = await _holds(db, now)  # quiet hours and collecting times: once per round
    groups = await _candidates(db, now, ROUND_JOBS + 1, holds)
    more = len(groups) > ROUND_JOBS
    groups = groups[:ROUND_JOBS]
    if not groups:
        await dbm.release(db)
        return {}
    smtp = await settings_store.get(db, "smtp") if any(w == "email" for _, w in groups) else {}
    key = await webpush.vapid(db) if any(w == "desktop" for _, w in groups) else None
    await dbm.release(db)
    out = {"sent": 0, "failed": 0}
    for i in range(0, len(groups), BATCH):
        if time.monotonic() >= deadline:
            more = True  # the rest keeps its place in line: the next round starts with it
            break
        jobs = await _prepare(db, ways, datetime.now(UTC), groups[i : i + BATCH], holds)
        if not jobs:
            continue
        outcomes = await _send_batch(jobs, smtp, key, deadline)  # nothing open in the database while sending
        more = more or any(o is _LATE for o in outcomes)
        got = await _settle_batch(db, jobs, outcomes, datetime.now(UTC))
        out = {k: out[k] + got[k] for k in out}
    _seen.more = more
    await dbm.release(db)
    return {k: v for k, v in out.items() if v}


async def prune(db: AsyncSession, days: int = 90) -> int:
    """Decided rows older than `days` (the events themselves go with the news' pruning)."""
    res = await db.execute(delete(PersonDelivery).where(PersonDelivery.status != "pending", PersonDelivery.status != "sending", PersonDelivery.created_at < datetime.now(UTC) - timedelta(days=days)))
    # absences over for longer than an event lives (MAX_AGE): no row of theirs can be routed any more
    await db.execute(delete(PersonAbsence).where(PersonAbsence.ends_at < datetime.now(UTC) - MAX_AGE - timedelta(days=1)))
    await db.commit()
    return res.rowcount or 0


async def send_teams_test(db: AsyncSession, p: PersonNotify) -> None:
    """A test card to the person's stored URL – marks nothing. When it went out, an old error and a pause end."""
    if not p.teams_url_enc:
        raise notify.NotifyError("not_configured")
    try:
        url = check_teams_url(decrypt_str(p.teams_url_enc))
    except notify.NotifyError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise notify.NotifyError("secret_unreadable") from exc
    body = notify._json(render_teams([], p.lang, test=True))
    uid = p.user_id
    await dbm.release(db)
    try:
        async with asyncio.timeout(SEND_DEADLINE):
            await notify.post(url, body, notify.JSON_HEADERS, policy=notify.PUBLIC_ONLY)
    except TimeoutError as exc:
        raise notify.NotifyError("timeout") from exc
    p = await db.get(PersonNotify, uid)
    if p is not None:
        st = _state(p, "teams")
        if st.get("failures") or st.get("next_try_at") or st.get("last_error"):
            await _set_state(db, uid, "teams", {**st, "failures": 0, "next_try_at": None, "last_error": None})
            await db.commit()


def state_out(p: PersonNotify | None, way: str) -> dict:
    """A way's state for the person: last delivery ok (when), or the last error (its category) and the next try."""
    st = _state(p, way) if p is not None else {}
    return {
        "last_ok_at": st.get("last_ok_at"),
        "last_error": st.get("last_error"),
        "last_error_at": st.get("last_error_at"),
        "next_try_at": st.get("next_try_at"),
        "failures": int(st.get("failures") or 0),
    }


async def products_of(db: AsyncSession, user_id: uuid.UUID) -> list[dict]:
    """The person's routed team products (label, the teams that give them)."""
    from app import vendor as vendor_svc
    from app.models import Team

    q = (
        select(VendorFollow, Team.name)
        .join(TeamProduct, TeamProduct.follow_id == VendorFollow.id)
        .join(Team, Team.id == TeamProduct.team_id)
        .where(teams.mine_clause(user_id))
    )
    out: dict[str, dict] = {}
    for f, team in await db.execute(q):
        label = ((vendor_svc.product_of(f) or {}).get("label")) or f.product
        out.setdefault(f.product, {"key": f.product, "label": label, "enabled": f.enabled, "teams": []})["teams"].append(team)
    for v in out.values():
        v["teams"].sort(key=str.lower)
    return sorted(out.values(), key=lambda x: x["label"].lower())


async def in_team(db: AsyncSession, user_id: uuid.UUID) -> bool:
    return await db.scalar(select(TeamMember.user_id).where(TeamMember.user_id == user_id).limit(1)) is not None

