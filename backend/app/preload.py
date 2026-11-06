"""Preload of the mapped groups (0.1.52): the members of every group mapped to a role (AD/LDAP and Entra ID – nested
groups too, as the team loads read them: LDAP_MATCHING_RULE_IN_CHAIN / Graph transitiveMembers) get a directory
account before their first sign-in – shown under Benutzer as "noch nie angemeldet", without a password and without a
session. Loaded when a mapping is added or removed and by the hourly sync, whether approval is required or not.

- Approval required ("Automatische Anmeldung über AD/Entra ID zulassen" off, app/auth/directory.py): a new account
  waits for an admin's approval (deactivated_reason "pending"); a waiting one stays waiting whatever the load finds.
  Otherwise a new account is on at once – as the first sign-in would make it.
- Who never signed in is kept in step here: name, display name, e-mail, the role of the groups (admin when one of its
  groups is mapped to admin; a raise may wait for approval), on/off as the directory has it (an admin's "off" never
  undone). Accounts that ever signed in are left to the sign-in and the hourly account sync (app/auth/sync.py).
- Data minimisation: an account that never signed in and is in no mapped group and no team any more is deleted – not
  switched off. Only when every mapped group of its source could be read in this run (a group that cannot be read
  changes nothing), never an account an admin switched off or declined (its decision stays), never one created after the
  members were read or holding a session (a sign-in in progress), never a local account or the emergency admin.

Big groups: as the team loads (app/teams.py – the same lock, the same reading of the groups): the directory is asked
with no transaction open, the accounts are written in batches of teams.BATCH, each its own short transaction.
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, exists, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit, teams
from app import db as dbm
from app import settings as settings_store
from app.auth import directory, entra, ldap_dir
from app.auth.directory import DirectoryUser
from app.models import GroupMapping, TeamGroup, TeamMember, User, UserSession

log = logging.getLogger("cobe_news.preload")

SOURCES = ("ldap", "entra")


def _usable(source: str, cfg: dict) -> bool:
    return bool(cfg.get("enabled")) and (ldap_dir.usable(cfg) if source == "ldap" else entra.usable(cfg))


async def sync(db: AsyncSession) -> dict[str, int]:
    """Load the mapped groups and bring the accounts that never signed in in step. One load at a time (teams' lock:
    a team load writes the same accounts)."""
    async with teams._lock:  # noqa: SLF001 - one writer of the loaded accounts
        try:
            return await _sync(db)
        finally:
            await dbm.release(db)


async def _mappings(db: AsyncSession, sources: list[str]) -> list[tuple[str, str, str]]:
    return [(s, g, r) for s, g, r in await db.execute(select(GroupMapping.source, GroupMapping.group_id, GroupMapping.role).where(GroupMapping.source.in_(sources)))]


async def _sync(db: AsyncSession) -> dict[str, int]:
    cfgs = {s: await settings_store.get(db, s) for s in SOURCES}
    sources = [s for s in SOURCES if _usable(s, cfgs[s])]
    if not sources:
        await dbm.release(db)
        return {}
    maps = await _mappings(db, sources)
    started = datetime.now(UTC)  # an account created after this was not in the members read below
    await dbm.release(db)  # nothing open while the directories are asked
    loads: dict[tuple[str, str], list[DirectoryUser] | str] = {}
    for source, gid, _ in maps:
        key = (source, gid.lower())
        if key not in loads:
            # AD: nested members only while "Verschachtelte Gruppen" is on – as the sign-in counts groups (a team always
            # takes nested ones)
            cfg = {**cfgs[source], "members_nested": bool(cfgs[source].get("nested_groups", True))} if source == "ldap" else cfgs[source]
            loads[key] = await teams._members(source, cfg, gid)  # noqa: SLF001 - the team loads' reading
    # the directories may take minutes: what holds now counts – a mapping added meanwhile was not read (its source is
    # not complete then), one removed meanwhile gives nothing; a source switched off meanwhile is left alone
    cfgs = {s: await settings_store.get(db, s) for s in SOURCES}
    sources = [s for s in sources if _usable(s, cfgs[s])]
    maps = await _mappings(db, sources)
    approval = await directory.approval_required(db)
    bound = {(s, g.lower()) for s, g in await db.execute(select(TeamGroup.source, TeamGroup.group_id))}
    await dbm.release(db)
    complete = {s: True for s in sources}
    failed: dict[str, set[str]] = {s: set() for s in sources}
    read_ok: dict[str, set[str]] = {s: set() for s in sources}
    people: dict[str, dict[str, tuple[DirectoryUser, str, set[str]]]] = {s: {} for s in sources}
    for source, gid, role in maps:
        got = loads.get((source, gid.lower()))
        if not isinstance(got, list):
            complete[source] = False
            failed[source].add(gid.lower())
            continue
        read_ok[source].add(gid.lower())
        for p in got:
            if p.source != source or not p.external_id:
                continue
            have = people[source].get(p.external_id)
            best = "admin" if role == "admin" or (have and have[1] == "admin") else "reader"
            groups = (have[2] if have else set()) | {gid.lower()}
            people[source][p.external_id] = (have[0] if have else p, best, groups)
    out = {"created": 0, "pending": 0, "conflicts": 0, "deactivated": 0, "reactivated": 0, "role": 0, "raise_pending": 0, "deleted": 0, "failed_groups": sum(len(f) for f in failed.values())}
    budget = directory.AuditBudget()
    for source in sources:
        keep = {g for s, g in bound if s == source} | failed[source]
        counts = await _accounts(db, source, list(people[source].values()), approval=approval, complete=complete[source], keep=keep, budget=budget)
        for k, n in counts.items():
            out[k] += n
        if complete[source]:
            out["deleted"] += await _delete_unused(db, source, set(people[source]), started, budget)
            out["role"] += await _left_but_kept(db, source, set(people[source]), read_ok[source], approval, budget)
    changed = {k: n for k, n in out.items() if n and k != "failed_groups"}
    failing = sorted(f"{s}:{g}" for s in sources for g in failed[s])
    news = await _failure_news(db, failing)
    if changed or news:
        details = {**changed, "failed_groups": out["failed_groups"], "groups": len(maps)}
        if budget.over:
            details["not_listed"] = budget.over  # entries beyond the ones logged one by one
        audit.record(db, audit.SYNC, "directory.preloaded", audit.target("signin", "preload", "preload"), details)
    await _remember_failures(db, failing, logged=bool(changed or news))
    await db.commit()
    return {k: n for k, n in out.items() if n}


STATE = "preload_state"  # settings: the groups that could not be read at the last run, when that was last logged
FAILED_AGAIN = timedelta(days=1)  # an unchanged failure is logged again after this long


async def _failure_news(db: AsyncSession, failing: list[str]) -> bool:
    """Groups that cannot be read are worth an audit entry when that is new: other groups than at the last run – or the
    same ones, last logged a day ago. Entra without the Graph permissions fails every hour; one entry a day says so."""
    if not failing:
        return False
    st = await settings_store.get(db, STATE)
    if st.get("failed") != failing:
        return True
    try:
        at = datetime.fromisoformat(str(st.get("logged_at")))
    except ValueError:
        return True
    return datetime.now(UTC) - at >= FAILED_AGAIN


async def _remember_failures(db: AsyncSession, failing: list[str], *, logged: bool) -> None:
    """The groups that failed in this run (none: forgotten – the next failure is news again)."""
    st = await settings_store.get(db, STATE)
    new = {"failed": failing, "logged_at": datetime.now(UTC).isoformat() if logged and failing else (st.get("logged_at") if failing else None)}
    if {k: st.get(k) for k in new} != new:
        await settings_store.put(db, STATE, new)


async def _accounts(
    db: AsyncSession, source: str, people: list[tuple[DirectoryUser, str, set[str]]], *, approval: bool, complete: bool, keep: set[str], budget: directory.AuditBudget
) -> dict[str, int]:
    """The accounts of one source's loaded people, batch by batch (each its own transaction). A batch that meets a
    sign-in creating the same account at the same moment (the name is unique) is read again and written once more."""
    total: dict[str, int] = {}
    for chunk in teams._chunks(people):  # noqa: SLF001
        for attempt in (1, 2):
            counts: dict[str, int] = {}
            try:
                await _batch(db, source, chunk, counts, approval=approval, complete=complete, keep=keep, budget=budget)
                await db.commit()
            except IntegrityError:
                await db.rollback()
                if attempt == 2:
                    log.warning("preload: a batch of %s accounts could not be written (a name taken in parallel) – the next load tries again", source)
                    counts = {}
                continue
            break
        for k, n in counts.items():
            total[k] = total.get(k, 0) + n
        await asyncio.sleep(0)  # the event loop gets its turn between batches
    return total


def _add(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


async def _batch(
    db: AsyncSession, source: str, chunk: list[tuple[DirectoryUser, str, set[str]]], counts: dict[str, int], *, approval: bool, complete: bool, keep: set[str], budget: directory.AuditBudget
) -> None:
    # locked for the batch's short transaction: a sign-in or an approval of one of them waits (and is never written over)
    q = select(User).where(User.auth_source == source, User.external_id.in_([p.external_id for p, _, _ in chunk])).order_by(User.id).with_for_update()
    have = {u.external_id: u for u in await db.scalars(q.execution_options(populate_existing=True))}
    names = {p.username for p, _, _ in chunk if p.external_id not in have}
    taken = set(await db.scalars(select(User.username).where(User.username.in_(names)))) if names else set()
    for p, role, groups in chunk:
        u = have.get(p.external_id)
        if u is None:
            if not p.enabled or not p.username:
                continue
            if p.username in taken and not await directory._name_free(db, p.username):  # noqa: SLF001
                _add(counts, "conflicts")  # a local account (or a directory account still there) keeps its name
                continue
            taken.add(p.username)
            u = User(
                id=uuid.uuid4(),
                username=p.username,
                display_name=p.display_name or p.username,
                email=p.email,
                role=role,
                auth_source=source,
                external_id=p.external_id,
                is_active=not approval,
                deactivated_reason=directory.PENDING if approval else None,
                role_groups=sorted(groups),
            )
            db.add(u)
            _add(counts, "created")
            if approval:
                _add(counts, "pending")
                if budget.take():
                    directory._audit(db, u, "user.approval_pending", {"source": source, "why": "preload", "role": role})  # noqa: SLF001
            elif role == "admin" or budget.take():
                # on at once: an admin always in the log (the anomaly "role_admin"), readers within the budget
                directory._audit(db, u, "user.created", {"role": role, "auth_source": source, "why": "preload"})  # noqa: SLF001
            continue
        if u.is_emergency or u.auth_source == "local" or u.last_login_at is not None:
            continue  # signed in once: the sign-in and the hourly account sync keep it in step
        if p.username and p.username != u.username and await directory._name_free(db, p.username, u.id):  # noqa: SLF001
            u.username = p.username
        u.display_name = p.display_name or u.display_name
        u.email = p.email or u.email
        # its groups as read now; a group that could not be read – or one bound to a team – stays as it was
        kept = sorted(groups | {g for g in (u.role_groups or []) if g in keep})
        if u.role_groups != kept:
            u.role_groups = kept
        # with a group unread its role may be higher than read now: raised, never lowered on half an answer
        role_known = complete or role == "admin"
        reason = u.deactivated_reason or ""
        if reason == "admin":
            continue  # an admin's "off" (blocked, declined): never undone
        if reason == directory.PENDING:
            if role_known and u.role != role:
                u.role = role  # what approving it gives
                u.version = (u.version or 1) + 1
            continue
        if not p.enabled:
            if u.is_active:
                u.is_active, u.deactivated_reason, u.pending_role = False, "sync:disabled", None
                u.version = (u.version or 1) + 1
                _add(counts, "deactivated")
            continue
        if not u.is_active:  # sync:<why> – back in a mapped group
            if approval:
                if role_known:
                    u.role = role
                directory.wait_for_approval(db, u, "preload", audit=budget.take())
                _add(counts, "pending")
                continue
            if (role_known and role == "admin") or u.role == "admin" or budget.take():
                directory._audit(db, u, "user.activated", {"reason": u.deactivated_reason, "why": "preload"})  # noqa: SLF001
            u.is_active, u.deactivated_reason = True, None
            u.version = (u.version or 1) + 1
            _add(counts, "reactivated")
        if role_known:
            got = await directory.follow_role(db, u, role, approval, {"why": "preload"}, budget)
            if got != "unchanged":
                _add(counts, got)


def _unused(source: str, started: datetime):  # noqa: ANN202
    """SQL: a directory account of `source` that never signed in, holds no session and belongs to no team, made before
    `started`, not switched off by an admin – checked again in the DELETE itself (a sign-in in between keeps it)."""
    return (
        User.auth_source == source,
        User.is_emergency.is_(False),
        User.external_id.is_not(None),
        User.last_login_at.is_(None),
        User.created_at < started,
        or_(User.deactivated_reason.is_(None), User.deactivated_reason != "admin"),
        ~exists().where(TeamMember.user_id == User.id),
        ~exists().where(UserSession.user_id == User.id),
    )


async def _delete_unused(db: AsyncSession, source: str, found: set[str], started: datetime, budget: directory.AuditBudget) -> int:
    """Accounts of `source` that never signed in and are in none of the mapped groups any more (every one of them was
    read) and in no team: deleted, batch by batch. The audit log keeps who they were (one entry each up to the budget –
    its target is text, no foreign key; the rest counted in the load's summary)."""
    rows = list(await db.execute(select(User.id, User.external_id, User.username).where(*_unused(source, started))))
    await dbm.release(db)
    gone = [(uid, name) for uid, ext, name in rows if ext not in found]
    n = 0
    for chunk in teams._chunks(gone):  # noqa: SLF001
        ids = [uid for uid, _ in chunk]
        res = await db.execute(delete(User).where(User.id.in_(ids), *_unused(source, started)).returning(User.id, User.username).execution_options(synchronize_session=False))
        done = list(res)
        for uid, name in done:
            if budget.take():
                audit.record(db, audit.SYNC, "user.deleted", audit.target("user", uid, name), {"auth_source": source, "why": "unused", "never_signed_in": True})
        n += len(done)
        await db.commit()
        await asyncio.sleep(0)
    return n


async def _left_but_kept(db: AsyncSession, source: str, found: set[str], read: set[str], approval: bool, budget: directory.AuditBudget) -> int:
    """Accounts that never signed in, are in none of the mapped groups any more (all read) and stay through a team: the
    mapped groups go from their kept groups, an admin falls to reader (a team gives reader – never more). Returns the
    number lowered."""
    if not read:
        return 0
    q = select(User).where(
        User.auth_source == source,
        User.is_emergency.is_(False),
        User.last_login_at.is_(None),
        teams.held_by_mapping([(source, g) for g in read]),
    )
    lowered = 0
    for u in list(await db.scalars(q.order_by(User.id).with_for_update().execution_options(populate_existing=True))):
        if u.external_id in found:
            continue
        u.role_groups = sorted(g for g in (u.role_groups or []) if g not in read)
        if u.role != "admin" or (u.deactivated_reason or "") == "admin":
            continue
        if u.is_active:
            await directory.follow_role(db, u, "reader", approval, {"why": "preload"}, budget)
        else:
            u.role, u.pending_role = "reader", None  # waiting (or off): what approving it gives
            u.version = (u.version or 1) + 1
        lowered += 1
    await db.commit()
    return lowered


def start() -> None:
    """Load in the background (a mapping added or removed): the request answers at once. Tracked with the team loads –
    teams.wait_idle waits for it too."""

    async def run() -> None:
        try:
            async with dbm.session() as s:
                got = await sync(s)
                if got:
                    log.info("preload: %s", got)
        except Exception:  # noqa: BLE001 - logged; the hourly sync tries again
            log.exception("preload: background load failed")

    task = asyncio.get_running_loop().create_task(run())
    teams._tasks.add(task)  # noqa: SLF001
    task.add_done_callback(teams._tasks.discard)  # noqa: SLF001
