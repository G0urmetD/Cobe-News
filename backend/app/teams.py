"""Teams (switched on in the settings, off by default – while off nothing changes for anyone).

- A team is bound to AD/LDAP or Entra ID groups. Their members – nested groups too (AD: LDAP_MATCHING_RULE_IN_CHAIN,
  Entra: Graph transitiveMembers) – are loaded when a group is bound and kept in step by the hourly sync: someone taken
  out of the group, or a group unbound, leaves the team at the next sync. A group that cannot be read changes nothing
  (an outage must not empty a team).
- Loaded people get a directory account at once (shown under Benutzer as "noch nie angemeldet" until they sign in).
  The sign-in and the hourly sync decide the role as before; a team group gives **reader** when no mapped group gives
  a role – admin still wins (auth/directory.resolve_role). An account an admin switched off stays off (`admin` is never
  a sync: reason).
- Local accounts are added by hand. Followed products belong to teams; a rule can be limited to teams (notify.py), the
  Vendor News overview shows "Mein Team" (vendor_api).
- Welcome e-mail (own switch, off by default): one per loaded person, through the SMTP server of the settings
  (notify.send_mail – its egress guard), never twice (team_welcome, by the directory id).

Big groups: the directory is asked with no transaction open; the accounts and memberships are written in batches of
BATCH, each its own short transaction, so 5000 members hold neither the database nor the event loop for long.
"""

import asyncio
import logging
import re
import time
import uuid
from datetime import UTC, datetime

from sqlalchemy import and_, delete, exists, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as dbm
from app import settings as settings_store
from app.auth import entra, ldap_dir
from app.auth.directory import DirectoryUser
from app.config import get_config
from app.models import PersonRoute, Team, TeamGroup, TeamMember, TeamProduct, TeamProductMember, TeamWelcome, User, VendorFollow

log = logging.getLogger("cobe_news.teams")

SECTION = "teams"
BATCH = 500  # accounts / memberships per transaction
WELCOME_PER_ROUND = 50  # mails per background round (one a few hundred ms – a big team takes a few rounds)
WELCOME_ROUND_S = 20.0
WELCOME_TRIES = 5
# failures where the message certainly never reached the server: tried again in a later round. Anything else (a
# timeout, a broken connection, a refused recipient) may have delivered it – never sent twice, so marked failed
WELCOME_RETRY = frozenset({"dns", "refused", "tls", "auth", "not_configured", "forbidden_target", "secret_unreadable"})

MAIL = re.compile(r"[^@\s,;<>\"()\[\]]{1,64}@[^@\s,;<>\"()\[\]]{1,253}\.[A-Za-z]{2,63}")
_lock = asyncio.Lock()  # one load at a time (bound group, settings switch, the hourly sync)
_tasks: set[asyncio.Task] = set()


async def config(db: AsyncSession) -> dict:
    return await settings_store.get(db, SECTION)


async def is_on(db: AsyncSession) -> bool:
    return bool((await config(db)).get("enabled"))


# ---------------------------------------------------------------- role and membership


async def grants_reader(db: AsyncSession, source: str, groups: list[str], user_id: uuid.UUID | None = None) -> bool:
    """Whether Teams gives this directory account the reader role: Teams on, and one of its groups is bound to a team –
    or the last load put it into a team through a group (a nested member when the sign-in reads direct groups only)."""
    if not await is_on(db):
        return False
    if groups:
        bound = {g.lower() for g in await db.scalars(select(TeamGroup.group_id).where(TeamGroup.source == source))}
        if bound & {g.lower() for g in groups}:
            return True
    if user_id is not None:
        q = select(TeamMember.user_id).where(TeamMember.user_id == user_id, TeamMember.origin == "group").limit(1)
        return await db.scalar(q) is not None
    return False


async def teams_of(db: AsyncSession, user_id: uuid.UUID) -> list[Team]:
    q = select(Team).join(TeamMember, TeamMember.team_id == Team.id).where(TeamMember.user_id == user_id).order_by(func.lower(Team.name))
    return list(await db.scalars(q))


def mine_clause(user_id: uuid.UUID):  # noqa: ANN201
    """SQL: the TeamProduct row is one of this person's – a member of its team, and the product is for all members of
    it or for this one (per-person routing, app/personal.py)."""
    member = exists().where(TeamMember.team_id == TeamProduct.team_id, TeamMember.user_id == user_id)
    chosen = exists().where(TeamProductMember.team_product_id == TeamProduct.id, TeamProductMember.user_id == user_id)
    return and_(member, or_(TeamProduct.all_members.is_(True), chosen))


async def drop_routing(db: AsyncSession, team_id: uuid.UUID, user_ids: list[uuid.UUID]) -> None:
    """People who left a team (sync, removed by hand): their chosen products of that team go with them, and since when
    the routing gave them one (app/personal.py). Not committed."""
    if not user_ids:
        return
    tps = select(TeamProduct.id).where(TeamProduct.team_id == team_id)
    await db.execute(delete(TeamProductMember).where(TeamProductMember.team_product_id.in_(tps), TeamProductMember.user_id.in_(user_ids)))
    await db.execute(delete(PersonRoute).where(PersonRoute.team_product_id.in_(tps), PersonRoute.user_id.in_(user_ids)))


async def my_products(db: AsyncSession, user_id: uuid.UUID) -> set[str] | None:
    """The product keys of this person's teams ("Mein Team") – None while Teams is off (no filter at all)."""
    if not await is_on(db):
        return None
    q = select(VendorFollow.product).join(TeamProduct, TeamProduct.follow_id == VendorFollow.id).where(mine_clause(user_id))
    return set(await db.scalars(q))


# ---------------------------------------------------------------- loading the groups


async def _members(source: str, cfg: dict, group_id: str) -> list[DirectoryUser] | str:
    """The members of one group – or the error category (nothing is changed for that group then)."""
    try:
        if source == "ldap":
            if not (cfg.get("enabled") and ldap_dir.usable(cfg)):
                return "not_configured"
            return await ldap_dir.run(ldap_dir.group_members, cfg, group_id)
        if not (cfg.get("enabled") and entra.usable(cfg)):
            return "not_configured"
        return await entra.group_members(cfg, group_id)
    except ldap_dir.LdapError as exc:
        return exc.category
    except entra.EntraError as exc:
        return exc.category
    except Exception:  # noqa: BLE001 - a broken answer must not stop the other groups
        log.exception("teams: loading %s group failed", source)
        return "error"


def _chunks(items: list, n: int = BATCH):  # noqa: ANN202
    for i in range(0, len(items), n):
        yield items[i : i + n]


async def _accounts(db: AsyncSession, people: list[DirectoryUser], welcome: bool) -> tuple[dict[tuple[str, str], uuid.UUID], dict[str, int]]:
    """The accounts of the loaded people, batch by batch: found by their directory id, created when new (and enabled),
    name, display name and e-mail kept in step for those who never signed in (afterwards the sign-in does that). Who
    never signed in follows the directory's on/off; an admin's "off" is never undone. A new account whose name a local
    account has is not created (a local account is never taken over)."""
    from app.auth import directory

    ids: dict[tuple[str, str], uuid.UUID] = {}
    counts = {"created": 0, "conflicts": 0, "deactivated": 0, "reactivated": 0}
    for chunk in _chunks(people):
        source = chunk[0].source
        have = {u.external_id: u for u in await db.scalars(select(User).where(User.auth_source == source, User.external_id.in_([p.external_id for p in chunk])))}
        names = {p.username for p in chunk if p.external_id not in have}
        taken = set(await db.scalars(select(User.username).where(User.username.in_(names)))) if names else set()
        seen = {(w.source, w.external_id) for w in await db.scalars(select(TeamWelcome).where(TeamWelcome.source == source, TeamWelcome.external_id.in_([p.external_id for p in chunk])))}
        for p in chunk:
            u = have.get(p.external_id)
            if u is None:
                if not p.enabled or not p.username:
                    continue
                if p.username in taken and not await directory._name_free(db, p.username):
                    counts["conflicts"] += 1
                    continue
                taken.add(p.username)
                u = User(
                    id=uuid.uuid4(),
                    username=p.username,
                    display_name=p.display_name or p.username,
                    email=p.email,
                    role="reader",
                    auth_source=source,
                    external_id=p.external_id,
                    is_active=True,
                )
                db.add(u)
                counts["created"] += 1
                if welcome and (source, p.external_id) not in seen:
                    db.add(TeamWelcome(source=source, external_id=p.external_id, status="pending" if p.email else "no_address"))
            elif u.last_login_at is None and not u.is_emergency:
                if p.username != u.username and await directory._name_free(db, p.username, u.id):
                    u.username = p.username
                u.display_name = p.display_name or u.display_name
                u.email = p.email or u.email
                reason = u.deactivated_reason or ""
                if not p.enabled and u.is_active:
                    u.is_active, u.deactivated_reason = False, "sync:disabled"
                    u.version = (u.version or 1) + 1
                    counts["deactivated"] += 1
                elif p.enabled and not u.is_active and reason.startswith("sync:"):
                    u.is_active, u.deactivated_reason = True, None  # back in the group / enabled again – never after an admin's "off"
                    u.version = (u.version or 1) + 1
                    counts["reactivated"] += 1
            ids[(source, p.external_id)] = u.id
        await db.commit()
        await asyncio.sleep(0)  # the event loop gets its turn between batches
    return ids, counts


async def deactivate_left(db: AsyncSession, reason: str = "sync:no_team") -> int:
    """Accounts a team load brought that never signed in: switched off once they are in no team group any more
    ("sync:no_team") – or all of them when Teams is switched off ("sync:teams_off"). Back in a team group, the next load
    switches them on again (_accounts); a sign-in with a mapped group does, too. An admin's "off" is never touched, and
    accounts that ever signed in are left to the hourly account sync (their role follows their groups there)."""
    q = update(User).where(
        User.auth_source.in_(("ldap", "entra")),
        User.is_active.is_(True),
        User.is_emergency.is_(False),
        User.last_login_at.is_(None),
    )
    if reason != "sync:teams_off":
        q = q.where(~exists().where(TeamMember.user_id == User.id, TeamMember.origin == "group"))
    res = await db.execute(q.values(is_active=False, deactivated_reason=reason, version=func.coalesce(User.version, 1) + 1).execution_options(synchronize_session=False))
    if res.rowcount:
        from app import audit

        # accounts that never signed in (no session to end): one entry for all of them, in the same transaction
        audit.record(db, audit.SYNC, "team.synced", audit.target("teams", None, None), {"deactivated": res.rowcount, "reason": reason})
    await db.commit()
    return res.rowcount or 0


async def sync(db: AsyncSession, team_ids: set[uuid.UUID] | None = None) -> dict[str, int]:
    """Load the bound groups (all teams, or these) and bring accounts and memberships in step. One at a time."""
    async with _lock:
        try:
            return await _sync(db, team_ids)
        finally:
            await dbm.release(db)


async def _sync(db: AsyncSession, team_ids: set[uuid.UUID] | None) -> dict[str, int]:
    conf = await config(db)
    if not conf.get("enabled"):
        off = await deactivate_left(db, "sync:teams_off")
        return {"deactivated": off} if off else {}
    cfgs = {"ldap": await settings_store.get(db, "ldap"), "entra": await settings_store.get(db, "entra")}
    q = select(Team.id)
    if team_ids is not None:
        q = q.where(Team.id.in_(team_ids))
    teams = list(await db.scalars(q))
    if not teams:
        return {}
    bound = list(await db.execute(select(TeamGroup.id, TeamGroup.team_id, TeamGroup.source, TeamGroup.group_id).where(TeamGroup.team_id.in_(teams))))
    await dbm.release(db)  # nothing open while the directories are asked
    # 1. each group once (bound to several teams: asked once)
    loads: dict[tuple[str, str], list[DirectoryUser] | str] = {}
    for _, _, source, gid in bound:
        key = (source, gid.lower())
        if key not in loads:
            loads[key] = await _members(source, cfgs[source], gid)
    # the directories may take minutes: Teams switched off meanwhile – nothing of this load is written (it would switch
    # the accounts on again that the switch just turned off); a team deleted meanwhile is left out (its memberships
    # would break the load of every other team)
    if not (await config(db)).get("enabled"):
        return {}
    teams = list(await db.scalars(select(Team.id).where(Team.id.in_(teams))))
    bound = [b for b in bound if b[1] in set(teams)]
    now = datetime.now(UTC)
    for gid_row, _, source, gid in bound:
        got = loads[(source, gid.lower())]
        values = {"state": "error", "error": got} if isinstance(got, str) else {"state": "ok", "error": None, "members": len(got), "synced_at": now}
        await db.execute(update(TeamGroup).where(TeamGroup.id == gid_row).values(**values).execution_options(synchronize_session=False))
    await db.commit()
    # 2. the accounts – each person once, whatever groups and teams brought them
    people: dict[tuple[str, str], DirectoryUser] = {}
    for got in loads.values():
        if isinstance(got, list):
            for p in got:
                people.setdefault((p.source, p.external_id), p)
    by_source = sorted(people.values(), key=lambda p: p.source)
    ids: dict[tuple[str, str], uuid.UUID] = {}
    out = {"created": 0, "conflicts": 0, "added": 0, "removed": 0, "failed_groups": sum(1 for x in loads.values() if isinstance(x, str))}
    switched = {"deactivated": 0, "reactivated": 0}
    for source in ("ldap", "entra"):
        part = [p for p in by_source if p.source == source]
        if part:
            got_ids, counts = await _accounts(db, part, bool(conf.get("welcome_mail")))
            ids.update(got_ids)
            out["created"] += counts["created"]
            out["conflicts"] += counts["conflicts"]
            for k in ("deactivated", "reactivated"):  # the audit log's (switched by the directory, never signed in)
                switched[k] += counts[k]
    # 3. the memberships per team: added as found; taken away only when every group of the team could be read
    groups_of: dict[uuid.UUID, list[tuple[str, str]]] = {t: [] for t in teams}
    for _, team_id, source, gid in bound:
        groups_of[team_id].append((source, gid.lower()))
    for team_id, keys in groups_of.items():
        complete = all(isinstance(loads[k], list) for k in keys)
        want = {ids[(p.source, p.external_id)] for k in keys if isinstance(loads[k], list) for p in loads[k] if (p.source, p.external_id) in ids}  # type: ignore[union-attr]
        have = set(await db.scalars(select(TeamMember.user_id).where(TeamMember.team_id == team_id, TeamMember.origin == "group")))
        for chunk in _chunks(sorted(want - have)):
            rows = [{"team_id": team_id, "user_id": uid, "origin": "group", "added_at": now} for uid in chunk]
            await db.execute(pg_insert(TeamMember).values(rows).on_conflict_do_nothing())
            await db.commit()
            out["added"] += len(chunk)
        if complete:
            for chunk in _chunks(sorted(have - want)):
                await db.execute(delete(TeamMember).where(TeamMember.team_id == team_id, TeamMember.origin == "group", TeamMember.user_id.in_(chunk)))
                await drop_routing(db, team_id, chunk)  # their chosen products of the team go with them
                await db.commit()
                out["removed"] += len(chunk)
    left = await deactivate_left(db)  # 4. who left their last team group and never signed in (logged by itself)
    # the load in the audit log: one entry for what it changed (it committed batch by batch – accounts that never signed
    # in, memberships; the role a membership gives is decided at the sign-in and by the account sync, logged there)
    loaded = {k: n for k, n in {**out, **switched}.items() if n and k in ("created", "reactivated", "deactivated", "added", "removed")}
    if loaded:
        from app import audit

        audit.record(db, audit.SYNC, "team.synced", audit.target("teams", None, None), {**loaded, "teams": len(teams), "failed_groups": out.get("failed_groups", 0)})
        await db.commit()
    out["deactivated"] = left
    return {k: v for k, v in out.items() if v}


def start(team_ids: set[uuid.UUID] | None = None) -> None:
    """Load in the background (a bound group, Teams switched on): the request answers at once, the team shows
    "wird geladen" until the load is done. Then the welcome e-mails, if switched on."""

    async def run() -> None:
        try:
            async with dbm.session() as s:
                got = await sync(s, team_ids)
                if got:
                    log.info("teams: %s", got)
            async with dbm.session() as s:
                await send_welcome(s)
        except Exception:  # noqa: BLE001 - logged; the hourly sync tries again
            log.exception("teams: background load failed")

    task = asyncio.get_running_loop().create_task(run())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def wait_idle() -> None:
    """Until the background loads started here are done (tests, shutdown)."""
    while _tasks:
        await asyncio.gather(*list(_tasks), return_exceptions=True)


# ---------------------------------------------------------------- welcome e-mail


TEXTS = {
    "de": {
        "heading": "Willkommen bei Cobe News",
        "hello": "Hallo {name},",
        "body": "du kannst Cobe News jetzt nutzen – Sicherheits-News und Vendor News, auch die Produkte deines Teams ({teams}).",
        "how": "Öffne die Adresse unten und melde dich mit deinem Firmenkonto an ({via}). Ein eigenes Passwort für Cobe News gibt es nicht.",
        "button": "Cobe News öffnen",
        "via": {"ldap": "Active Directory", "entra": "Anmelden mit Microsoft"},
    },
    "en": {
        "heading": "Welcome to Cobe News",
        "hello": "Hello {name},",
        "body": "you can use Cobe News now – security news and Vendor News, including the products of your team ({teams}).",
        "how": "Open the address below and sign in with your company account ({via}). There is no separate password for Cobe News.",
        "button": "Open Cobe News",
        "via": {"ldap": "Active Directory", "entra": "Sign in with Microsoft"},
    },
}
SUBJECT = "Willkommen bei Cobe News / Welcome to Cobe News"
FOOTER = "Automatisch gesendet, weil du einem Team in Cobe News angehörst. · Sent automatically because you belong to a team in Cobe News."


def render_welcome(name: str, source: str, teams: list[str]) -> tuple[str, str, str]:
    """(subject, text, html) – German, then English. The base URL and how to sign in; never a password or a token."""
    from app.notify import _env, one_line

    url = get_config().base_url + "/"
    name = one_line(name)[:120] or "–"
    team_text = ", ".join(one_line(t)[:80] for t in teams[:5]) or "–"
    parts = []
    lines: list[str] = []
    for lang in ("de", "en"):
        tx = TEXTS[lang]
        paragraphs = [tx["hello"].format(name=name), tx["body"].format(teams=team_text), tx["how"].format(via=tx["via"].get(source, ""))]
        parts.append({"lang": lang, "heading": tx["heading"], "paragraphs": paragraphs, "button": tx["button"]})
        lines += [tx["heading"], "=" * len(tx["heading"]), "", *paragraphs, "", url, "", ""]
    html = _env.get_template("welcome.html.j2").render(subject=SUBJECT, parts=parts, url=url, footer=FOOTER)
    return SUBJECT, "\n".join([*lines, "-- ", FOOTER]) + "\n", html


async def send_welcome(db: AsyncSession) -> int:
    """Pending welcome e-mails, at most WELCOME_PER_ROUND / WELCOME_ROUND_S per call. Each is claimed (pending → sending)
    and committed before it is sent: a second round, a restart or a crash in between never sends it twice."""
    from app import notify

    conf = await config(db)
    if not (conf.get("enabled") and conf.get("welcome_mail")):
        await dbm.release(db)
        return 0
    smtp = await settings_store.get(db, "smtp")
    if not smtp.get("host") or not smtp.get("from_addr"):
        await dbm.release(db)
        return 0  # waits for the mail server
    sent = 0
    deadline = time.monotonic() + WELCOME_ROUND_S
    while sent < WELCOME_PER_ROUND and time.monotonic() < deadline:
        row = (await db.execute(select(TeamWelcome.source, TeamWelcome.external_id).where(TeamWelcome.status == "pending").order_by(TeamWelcome.created_at).limit(1))).first()
        if row is None:
            break
        source, ext = row
        claimed = await db.execute(
            update(TeamWelcome)
            .where(TeamWelcome.source == source, TeamWelcome.external_id == ext, TeamWelcome.status == "pending")
            .values(status="sending", tries=TeamWelcome.tries + 1)
            .returning(TeamWelcome.tries)
        )
        tries = claimed.scalar()
        if tries is None:
            await db.commit()
            continue  # another round took it
        u = await db.scalar(select(User).where(User.auth_source == source, User.external_id == ext))
        names = [t.name for t in await teams_of(db, u.id)] if u is not None else []
        to, who = (u.email, u.display_name or u.username) if u is not None else (None, "")
        await db.commit()
        done: dict = {}
        if u is None:
            done = {"status": "failed", "error": "gone"}
        elif not to or not MAIL.fullmatch(to):
            done = {"status": "no_address", "error": None}  # none – or not one plain address (never a list of them)
        elif not u.is_active:
            # switched off before the mail went out: by an admin, or out of every team group again
            done = {"status": "failed", "error": "blocked" if u.deactivated_reason == "admin" else "inactive"}
        else:
            subject, text, html = render_welcome(who, source, names)
            try:
                await notify.send_mail(smtp, [to], subject, text, html)
                done = {"status": "sent", "error": None, "sent_at": datetime.now(UTC)}
                sent += 1
            except notify.NotifyError as exc:
                again = exc.category in WELCOME_RETRY and tries < WELCOME_TRIES
                done = {"status": "pending" if again else "failed", "error": exc.category}
                log.info("teams: welcome e-mail not sent (%s)", exc.category)
        await db.execute(update(TeamWelcome).where(TeamWelcome.source == source, TeamWelcome.external_id == ext).values(**done))
        await db.commit()
        if done.get("error") and done["error"] not in ("rejected", "gone", "blocked", "inactive") and done["status"] != "no_address":
            break  # the mail server is the problem (not this one recipient) – the next round goes on
    await dbm.release(db)
    return sent


async def welcome_of(db: AsyncSession, users: list[User]) -> dict[uuid.UUID, str]:
    """The welcome e-mail state per account (for the user list)."""
    ext = [u.external_id for u in users if u.external_id and u.auth_source != "local"]
    if not ext:
        return {}
    q = select(TeamWelcome.source, TeamWelcome.external_id, TeamWelcome.status)
    if len(ext) <= 1000:  # a page of members; the whole user list reads them all (no parameter list of thousands)
        q = q.where(TeamWelcome.external_id.in_(ext))
    rows = {(src, x): status for src, x, status in await db.execute(q)}
    return {u.id: rows[(u.auth_source, u.external_id)] for u in users if (u.auth_source, u.external_id) in rows}
