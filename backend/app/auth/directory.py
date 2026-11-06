"""Directory accounts (AD/LDAP, Entra ID): role from group membership, created at the first sign-in – or before it,
when the members of the mapped groups are loaded (app/preload.py) – kept in step at every sign-in and by the hourly
sync. Without a mapped group there is no access – there is no default role (Teams, when switched on, adds one way: a
team group gives reader). Admin wins over reader when groups of both are matched. (Two fixed roles.)

Approval (settings section "directory", `auto_signin` – on by default, as before 0.1.52): switched off, a new directory
account starts waiting for an admin's approval (is_active false, deactivated_reason PENDING) and a raise to admin waits
too (pending_role "admin", the account stays reader). States of a directory account:

- active – signs in; its role follows its groups (lowering at once, raising as above)
- pending – waits for approval: only an admin's approval switches it on (approve), never a sign-in, the sync or a team
  load – whatever the switch says later; a sign-in after the directory accepted the password is refused with
  "approval_pending"
- declined / blocked – deactivated_reason "admin": nothing of the directory switches it on again
- sync:<why> – switched off by the directory (gone, disabled, no_role …); back in a mapped group it is switched on again
  – unless approval is required and it never signed in: then it waits like a new account

Approval belongs to the account – found by its directory id (objectGUID / object id), never by its name: an account
re-created in the directory is a new account and waits again. Local accounts and the emergency admin are never
concerned."""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import settings as settings_store
from app.auth import sessions
from app.models import GroupMapping, TeamGroup, TeamMember, User, UserSession

ROLES = ("admin", "reader")
SECTION = "directory"  # settings: {"auto_signin": True}
PENDING = "pending"  # deactivated_reason of an account waiting for an admin's approval
RAISE_DECLINED = "declined"  # pending_role after an admin declined the raise to admin


@dataclass
class DirectoryUser:
    source: str  # ldap | entra
    external_id: str
    username: str
    display_name: str
    email: str | None = None
    groups: list[str] = field(default_factory=list)  # DNs (AD) or object ids (Entra)
    enabled: bool = True


class DirectoryError(Exception):
    """Sign-in refused: no_role | username_conflict | disabled | pending."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ApprovalPending(DirectoryError):
    """The directory accepted the person, but the account waits for an admin's approval. Unlike the other refusals, what
    provision wrote stays – the caller commits it (the waiting account, so that admins see it, and its audit entry) –
    and the sign-in is refused without a session."""

    def __init__(self) -> None:
        super().__init__("pending")


async def approval_required(db: AsyncSession) -> bool:
    """"Automatische Anmeldung über AD/Entra ID zulassen" off: new directory accounts and raises to admin wait."""
    return not bool((await settings_store.get(db, SECTION)).get("auto_signin", True))


def is_pending(user: User) -> bool:
    return not user.is_active and user.deactivated_reason == PENDING


def _bump(user: User) -> None:
    user.version = (user.version or 1) + 1


async def follow_role(db: AsyncSession, user: User, role: str, approval: bool, details: dict, budget: "AuditBudget | None" = None) -> str:
    """The role the groups give (`role`) applied to an account that is on. Lowering – and keeping the role – at once (a
    waiting raise is forgotten: the account left the admin groups); a raise to admin waits for an admin's approval while
    approval is required, while one already waits (switching approval off approves nothing silently) or after an admin
    declined it (until the account leaves the admin groups). Sessions end at a change: the new rights come with the next
    sign-in – above all never as an admin that never gave its second factor. `details`: added to the audit entry.
    Returns "role" (changed), "raise_pending" (a raise waits now) or "unchanged"."""
    if role == user.role:
        if user.pending_role is not None:
            user.pending_role = None
            _bump(user)
        return "unchanged"
    if role == "admin" and (approval or user.pending_role is not None):
        if user.pending_role is not None:
            return "unchanged"  # waits already, or declined
        user.pending_role = "admin"
        _bump(user)
        if budget is None or budget.take():
            _audit(db, user, "role.approval_pending", {"from": user.role, "to": role, "source": user.auth_source, **details})
        return "raise_pending"
    await sessions.revoke_all(db, user.id)
    # a raise to admin is always logged (the anomaly "role_admin"); a load's lowerings within its budget
    if role == "admin" or budget is None or budget.take():
        _audit(db, user, "role.changed", {"changes": {"role": {"from": user.role, "to": role}}, "sessions_ended": True, **details})
    user.role, user.pending_role = role, None
    _bump(user)
    return "role"


AUDIT_EACH_MAX = 200  # a load (preload, team): entries one by one per run – beyond, counted in the run's summary


class AuditBudget:
    """At most AUDIT_EACH_MAX entries of a load one by one (a first load of a group of thousands would fill the log with
    thousands of the same line); the rest is counted – the load's summary entry names the number."""

    def __init__(self, n: int = AUDIT_EACH_MAX) -> None:
        self.left, self.over = n, 0

    def take(self) -> bool:
        if self.left > 0:
            self.left -= 1
            return True
        self.over += 1
        return False


def wait_for_approval(db: AsyncSession, user: User, why: str, *, audit: bool = True) -> None:
    """The account waits for an admin's approval from now on (a new one, or one the directory switched off that never
    signed in and is back in a mapped group while approval is required). Not committed."""
    user.is_active, user.deactivated_reason, user.pending_role = False, PENDING, None
    _bump(user)
    if audit:
        _audit(db, user, "user.approval_pending", {"source": user.auth_source, "why": why, "role": user.role})


async def resolve_role(db: AsyncSession, source: str, groups: list[str], user_id=None) -> str | None:  # noqa: ANN001
    """admin > reader from the mapped groups; without one, Teams (while switched on) gives reader to the members of a
    team group (app/teams.grants_reader) – an additional way to read, never a way to become admin."""
    wanted = {g.lower() for g in groups}
    rows = list(await db.scalars(select(GroupMapping).where(GroupMapping.source == source)))
    roles = {m.role for m in rows if m.group_id.lower() in wanted}
    if "admin" in roles:
        return "admin"
    if "reader" in roles:
        return "reader"
    from app import teams  # teams → auth → directory: imported when used

    return "reader" if await teams.grants_reader(db, source, groups, user_id) else None


async def role_groups(db: AsyncSession, source: str, groups: list[str]) -> list[str]:
    """The groups of an account that matter for its role – mapped to one or bound to a team – in lower case. Kept with
    the account (User.role_groups) at every sign-in and sync: removing a mapping re-checks from these at once."""
    wanted = {g.lower() for g in groups}
    if not wanted:
        return []
    mapped = await db.scalars(select(GroupMapping.group_id).where(GroupMapping.source == source))
    bound = await db.scalars(select(TeamGroup.group_id).where(TeamGroup.source == source))
    return sorted(wanted & {g.lower() for g in [*mapped, *bound]})


def _keep_groups(user: User, groups: list[str]) -> None:
    if user.role_groups != groups:
        user.role_groups = groups


async def provision(db: AsyncSession, du: DirectoryUser) -> User:
    """Create or update the account of a directory user at sign-in (after the directory accepted the person: the AD
    password, the Entra token). Approval required: a new account is created waiting and the sign-in refused
    (ApprovalPending – the caller commits the account), a waiting one stays waiting."""
    if not du.enabled:
        raise DirectoryError("disabled")
    # locked until the sign-in commits: an admin's approval, a raise approved or the preload in between wait for it – and
    # it reads what they wrote (never a stale "reader" that makes an admin session without its second factor, never a
    # role written over an approval made meanwhile)
    user = await db.scalar(select(User).where(User.auth_source == du.source, User.external_id == du.external_id).with_for_update().execution_options(populate_existing=True))
    role = await resolve_role(db, du.source, du.groups, user.id if user is not None else None)
    if role is None:
        raise DirectoryError("no_role")
    approval = await approval_required(db)
    if user is None:
        if not await _name_free(db, du.username):
            # a sign-in of the same account committed its row between the look-up above and this one (two first sign-ins
            # at once): that row is this account's, no conflict – again, now finding it (and waiting on its lock)
            if await db.scalar(select(User.id).where(User.auth_source == du.source, User.external_id == du.external_id)) is not None:
                return await provision(db, du)
            raise DirectoryError("username_conflict")  # a local account with the same name is never taken over
        user = User(
            username=du.username,
            display_name=du.display_name or du.username,
            email=du.email,
            role=role,
            auth_source=du.source,
            external_id=du.external_id,
            is_active=not approval,
            deactivated_reason=PENDING if approval else None,
            role_groups=await role_groups(db, du.source, du.groups),
        )
        db.add(user)
        await db.flush()
        _audit(db, user, "user.created", {"role": role, "auth_source": du.source, "why": "signin", **({"pending": True} if approval else {})})
        if approval:
            _audit(db, user, "user.approval_pending", {"source": du.source, "why": "signin", "role": role})
            raise ApprovalPending()
        return user
    if is_pending(user):
        # waits: kept in step (what approving gives is its current role), never switched on here – whatever the switch
        await _in_step(db, user, du, role, pending=True)
        if not await _refused_lately(db, user):
            _audit(db, user, "login.pending_refused", {"source": du.source})
        raise ApprovalPending()
    if not user.is_active:
        if not (user.deactivated_reason or "").startswith("sync:"):
            raise DirectoryError("disabled")  # switched off by an admin – the directory cannot switch it on again
        if approval and user.last_login_at is None:
            # never used, switched off by the directory, back now: waits like a new account
            await _in_step(db, user, du, role, pending=True)
            wait_for_approval(db, user, "signin")
            raise ApprovalPending()
        _audit(db, user, "user.activated", {"reason": user.deactivated_reason, "why": "signin"})
        user.is_active, user.deactivated_reason = True, None
        _bump(user)
    # a changed role: the sessions from before end (the sign-in that called this makes a new session after it)
    await follow_role(db, user, role, approval, {"why": "signin"})
    await _in_step(db, user, du, role, pending=False)
    return user


REFUSED_LOG_EVERY = timedelta(minutes=15)


async def _refused_lately(db: AsyncSession, user: User) -> bool:
    """A refused sign-in of a waiting account was logged in the last REFUSED_LOG_EVERY: the next ones are not (only the
    person with the right password can cause them – retrying must not fill the log)."""
    from app.models import AuditEntry

    since = datetime.now(UTC) - REFUSED_LOG_EVERY
    q = select(AuditEntry.id).where(AuditEntry.target_type == "user", AuditEntry.target_id == str(user.id), AuditEntry.action == "login.pending_refused", AuditEntry.at >= since).limit(1)
    return await db.scalar(q) is not None


async def _in_step(db: AsyncSession, user: User, du: DirectoryUser, role: str, *, pending: bool) -> None:
    """Groups, name, display name and e-mail as the directory has them; a waiting account's role too (what approving
    it gives – a change counts as a new state: an approval made on the one before is stale)."""
    if pending and user.role != role:
        user.role = role
        _bump(user)
    _keep_groups(user, await role_groups(db, du.source, du.groups))
    # renamed in the directory (AD: new sAMAccountName, Entra: new UPN) – the account is found by its id, the name follows
    if du.username and du.username != user.username and await _name_free(db, du.username, user.id):
        user.username = du.username
    user.display_name = du.display_name or user.display_name
    user.email = du.email or user.email


async def _name_free(db: AsyncSession, username: str, own_id=None) -> bool:  # noqa: ANN001
    """Whether a directory account may take this name. The name of an account the directory removed (sync:gone) is
    released – renamed to name~<id> – so a re-created account (Entra: a new object id) can take it; a local account or
    a directory account still there keeps its name."""
    other = await db.scalar(select(User).where(User.username == username))
    if other is None or other.id == own_id:
        return True
    if other.auth_source != "local" and not other.is_active and other.deactivated_reason == "sync:gone":
        other.username = f"{username[:100]}~{other.id.hex[:8]}"
        await db.flush()
        return True
    return False


def _audit(db: AsyncSession, user: User, action: str, details: dict, actor=None) -> None:  # noqa: ANN001
    """An access change the directory decided (actor: the directory sync) – in the audit log, in the same transaction."""
    from app import audit  # audit → models only; imported when used like teams

    audit.record(db, actor or audit.SYNC, action, audit.user_target(user), details)


async def apply_sync(db: AsyncSession, user: User, du: DirectoryUser | None, approval: bool | None = None) -> str:
    """Hourly sync of one directory account: gone / disabled / no mapped group → switched off (sessions end), otherwise
    the role follows the groups (a raise to admin may wait: follow_role). A waiting account is never switched on.
    Local accounts – the emergency admin above all – are never touched. `approval`: approval_required (asked once by
    the caller for all accounts)."""
    if user.auth_source == "local" or user.is_emergency:
        return "skipped"
    if not user.is_active and not (user.deactivated_reason or "").startswith("sync:"):
        return "unchanged"  # an admin's block, or waiting for approval: the sync changes nothing on it
    if approval is None:
        approval = await approval_required(db)
    role = await resolve_role(db, du.source, du.groups, user.id) if du is not None and du.enabled else None
    _keep_groups(user, await role_groups(db, du.source, du.groups) if du is not None and du.enabled else [])
    if role is None:
        if user.pending_role is not None:
            user.pending_role = None  # nothing to raise any more
        if user.is_active:
            reason = "gone" if du is None else "disabled" if not du.enabled else "no_role"
            user.is_active, user.deactivated_reason = False, f"sync:{reason}"
            _bump(user)
            await sessions.revoke_all(db, user.id)
            _audit(db, user, "user.deactivated", {"reason": user.deactivated_reason, "sessions_ended": True})
            return "deactivated"
        return "unchanged"
    changed = "unchanged"
    if not user.is_active and (user.deactivated_reason or "").startswith("sync:"):
        if approval and user.last_login_at is None:
            user.role = role
            await sessions.revoke_all(db, user.id)
            wait_for_approval(db, user, "sync")
            return "pending"
        _audit(db, user, "user.activated", {"reason": user.deactivated_reason})
        user.is_active, user.deactivated_reason, changed = True, None, "reactivated"
        _bump(user)
    got = await follow_role(db, user, role, approval, {})
    if got != "unchanged":
        changed = got
    # AD: the sync reads the name as the sign-in does. Entra: the sign-in's preferred_username and Graph's UPN differ for
    # guests – there the name follows at the sign-in only (no flip-flop every hour)
    if user.auth_source == "ldap" and du.username and du.username != user.username and await _name_free(db, du.username, user.id):
        user.username = du.username
        changed = changed if changed != "unchanged" else "renamed"
    return changed


# ---------------------------------------------------------------- instant re-check: a mapping removed, a source switched off


async def reassess_mapping(db: AsyncSession, source: str, group_id: str, role: str, *, me: uuid.UUID | None = None, apply: bool = False, actor=None) -> dict:  # noqa: ANN001
    """Who a removed mapping (`source`, `group_id` → `role`) concerns, from the groups kept with each account
    (User.role_groups) – the directory is not asked. With `apply` (after the mapping is deleted, same transaction): who
    lost the role is switched off as the sync would (sync:no_role), who falls from admin to reader is demoted – both
    signed out at once; who keeps the role through another mapping or a team stays signed in. An account whose groups
    are not known yet (signed in before they were kept) may hold its role through this group only: its sessions end
    (the safe side), its role is left to the next sign-in or sync. Local accounts and the emergency admin are never
    concerned; nor is `me` (the admin doing it): `self` tells whether it would lose its own role – the caller refuses."""
    from app import teams  # teams → auth → directory: imported when used

    gid = group_id.lower()
    rest = [(g.lower(), r) for g, r in await db.execute(select(GroupMapping.group_id, GroupMapping.role).where(GroupMapping.source == source))]
    admin_groups = {g for g, r in rest if r == "admin" and g != gid}
    reader_groups = {g for g, r in rest if r == "reader" and g != gid}
    on = await teams.is_on(db)
    bound = {g.lower() for g in await db.scalars(select(TeamGroup.group_id).where(TeamGroup.source == source))} if on else set()
    # admin > reader: removing a reader mapping never touches an admin, removing an admin mapping never a reader
    who = select(User.id).where(User.auth_source == source, User.is_active.is_(True), User.is_emergency.is_(False), User.role == role)
    users = list(await db.scalars(select(User).where(User.id.in_(who))))
    in_team = set(await db.scalars(select(TeamMember.user_id).where(TeamMember.user_id.in_(who), TeamMember.origin == "group"))) if on else set()
    signed_in = set(await db.scalars(select(UserSession.user_id).where(UserSession.user_id.in_(who), UserSession.expires_at > sessions.now()).distinct()))
    out = {"lost": 0, "demoted": 0, "unknown": 0, "self": False}
    end: list[uuid.UUID] = []
    for u in users:
        if u.role_groups is None:
            if u.id in signed_in and u.id != me:
                out["unknown"] += 1
                end.append(u.id)
            continue
        have = {g.lower() for g in u.role_groups}
        if gid not in have:
            continue  # its role comes from elsewhere
        have.discard(gid)
        new = "admin" if have & admin_groups else "reader" if have & reader_groups or (on and (have & bound or u.id in in_team)) else None
        if new == u.role:
            continue  # another mapping (or a team) gives the same role
        if u.id == me:
            out["self"] = True
            continue
        out["lost" if new is None else "demoted"] += 1
        end.append(u.id)
        if apply:
            if new is None:
                u.is_active, u.deactivated_reason = False, "sync:no_role"
            else:
                u.role = new
            if actor is not None:  # the admin who removed the mapping (audit log: the consequence for each account)
                _audit(db, u, "user.deactivated" if new is None else "role.changed", {"why": "mapping_removed", "reason": "sync:no_role"} if new is None else {"changes": {"role": {"from": role, "to": new}}, "why": "mapping_removed"}, actor)
            u.role_groups = sorted(have)
            u.version = (u.version or 1) + 1
    if apply:
        await sessions.revoke_users(db, end)
    return {**out, "affected": len(end)}


async def source_impact(db: AsyncSession, source: str) -> int:
    """Accounts of this source that hold a session (what switching it off with "sign out at once" ends)."""
    q = select(func.count(func.distinct(UserSession.user_id))).join(User, User.id == UserSession.user_id).where(User.auth_source == source, User.is_emergency.is_(False), UserSession.expires_at > sessions.now())
    return int(await db.scalar(q) or 0)


async def end_source_sessions(db: AsyncSession, source: str) -> None:
    """Switching AD/LDAP or Entra ID off: every session of its accounts ends (not committed)."""
    await sessions.revoke_users(db, select(User.id).where(User.auth_source == source, User.is_emergency.is_(False)))


# ---------------------------------------------------------------- approval by an admin


async def approvable_role(db: AsyncSession, user: User) -> str | None:
    """The role an approval gives now: from the account's groups as last read (User.role_groups – the sign-in, the
    sync, the preload) and the mappings as they are now (a team: reader). None: no mapped group any more – nothing to
    approve."""
    return await resolve_role(db, user.auth_source, list(user.role_groups or []), user.id)


async def approve(db: AsyncSession, user: User, role: str, actor, why: str = "admin") -> None:  # noqa: ANN001
    """A waiting account switched on with `role` (the caller checked it is the approvable one, and re-confirmed an
    admin's). Not committed."""
    user.is_active, user.deactivated_reason, user.pending_role = True, None, None
    changed = user.role != role
    user.role = role
    await sessions.revoke_all(db, user.id)  # it holds none (the sign-in is refused while it waits) – the safe side
    _audit(db, user, "user.approved", {"source": user.auth_source, "role": role, "why": why, **({"role_changed": True} if changed else {})}, actor)


def decline(db: AsyncSession, user: User, actor) -> None:  # noqa: ANN001
    """A waiting account declined: off for good (deactivated_reason "admin", like a block – neither the directory nor a
    sign-in switches it on). Not committed."""
    user.is_active, user.deactivated_reason, user.pending_role = False, "admin", None
    _audit(db, user, "user.declined", {"source": user.auth_source, "role": user.role}, actor)


async def approve_raise(db: AsyncSession, user: User, actor, why: str = "admin") -> None:  # noqa: ANN001
    """The waiting raise to admin approved (the caller checked the groups still give admin, and re-confirmed): admin now,
    its sessions end – the next sign-in asks for the admin's second factor. Not committed."""
    before = user.role
    user.role, user.pending_role = "admin", None
    await sessions.revoke_all(db, user.id)
    _audit(db, user, "role.approved", {"changes": {"role": {"from": before, "to": "admin"}}, "sessions_ended": True, "why": why}, actor)


def decline_raise(db: AsyncSession, user: User, actor) -> None:  # noqa: ANN001
    """The waiting raise declined: stays reader – and is not asked again while the account stays in the admin groups
    (pending_role RAISE_DECLINED; leaving them forgets it). Not committed."""
    user.pending_role = RAISE_DECLINED
    _audit(db, user, "role.declined", {"from": user.role, "to": "admin"}, actor)


async def pending_counts(db: AsyncSession) -> dict[str, int]:
    """What waits for an admin: accounts (of them as admin) and raises to admin."""
    rows = (await db.execute(select(User.role, func.count()).where(User.is_active.is_(False), User.deactivated_reason == PENDING, User.is_emergency.is_(False)).group_by(User.role))).all()
    accounts = {r: int(n) for r, n in rows}
    raises = int(await db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(True), User.pending_role == "admin")) or 0)
    return {"accounts": sum(accounts.values()), "accounts_admin": accounts.get("admin", 0), "raises": raises}
