"""Directory accounts (AD/LDAP, Entra ID): role from group membership, created at the first sign-in, kept in step at
every sign-in and by the hourly sync. Without a mapped group there is no access – there is no default role (Teams, when
switched on, adds one way: a team group gives reader). Admin wins over reader when groups of both are matched. (Two
fixed roles.)"""

import uuid
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import sessions
from app.models import GroupMapping, TeamGroup, TeamMember, User, UserSession

ROLES = ("admin", "reader")


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
    """Sign-in refused: no_role | username_conflict | disabled."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


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
    """Create or update the account of a directory user at sign-in."""
    if not du.enabled:
        raise DirectoryError("disabled")
    user = await db.scalar(select(User).where(User.auth_source == du.source, User.external_id == du.external_id))
    role = await resolve_role(db, du.source, du.groups, user.id if user is not None else None)
    if role is None:
        raise DirectoryError("no_role")
    if user is None:
        if not await _name_free(db, du.username):
            raise DirectoryError("username_conflict")  # a local account with the same name is never taken over
        user = User(
            username=du.username,
            display_name=du.display_name or du.username,
            email=du.email,
            role=role,
            auth_source=du.source,
            external_id=du.external_id,
            is_active=True,
            role_groups=await role_groups(db, du.source, du.groups),
        )
        db.add(user)
        await db.flush()
        _audit(db, user, "user.created", {"role": role, "auth_source": du.source, "why": "signin"})
        return user
    if not user.is_active:
        if not (user.deactivated_reason or "").startswith("sync:"):
            raise DirectoryError("disabled")  # switched off by an admin – the directory cannot switch it on again
        _audit(db, user, "user.activated", {"reason": user.deactivated_reason, "why": "signin"})
        user.is_active, user.deactivated_reason = True, None
        user.version = (user.version or 1) + 1
    if user.role != role:
        # a session from before the change must not carry the new rights – above all not as an admin that never gave
        # its second factor (the sign-in that called this makes a new session after it)
        await sessions.revoke_all(db, user.id)
        _audit(db, user, "role.changed", {"changes": {"role": {"from": user.role, "to": role}}, "why": "signin"})
        user.role = role
        user.version = (user.version or 1) + 1
    _keep_groups(user, await role_groups(db, du.source, du.groups))
    # renamed in the directory (AD: new sAMAccountName, Entra: new UPN) – the account is found by its id, the name follows
    if du.username and du.username != user.username and await _name_free(db, du.username, user.id):
        user.username = du.username
    user.display_name = du.display_name or user.display_name
    user.email = du.email or user.email
    return user


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


async def apply_sync(db: AsyncSession, user: User, du: DirectoryUser | None) -> str:
    """Hourly sync of one directory account: gone / disabled / no mapped group → switched off (sessions end), otherwise
    the role follows the groups. Local accounts – the emergency admin above all – are never touched."""
    if user.auth_source == "local" or user.is_emergency:
        return "skipped"
    if not user.is_active and not (user.deactivated_reason or "").startswith("sync:"):
        return "unchanged"  # an admin's block: the sync changes nothing on it (sync.run does not ask for these anyway)
    role = await resolve_role(db, du.source, du.groups, user.id) if du is not None and du.enabled else None
    _keep_groups(user, await role_groups(db, du.source, du.groups) if du is not None and du.enabled else [])
    if role is None:
        if user.is_active:
            reason = "gone" if du is None else "disabled" if not du.enabled else "no_role"
            user.is_active, user.deactivated_reason = False, f"sync:{reason}"
            user.version = (user.version or 1) + 1
            await sessions.revoke_all(db, user.id)
            _audit(db, user, "user.deactivated", {"reason": user.deactivated_reason, "sessions_ended": True})
            return "deactivated"
        return "unchanged"
    changed = "unchanged"
    if not user.is_active and (user.deactivated_reason or "").startswith("sync:"):
        _audit(db, user, "user.activated", {"reason": user.deactivated_reason})
        user.is_active, user.deactivated_reason, changed = True, None, "reactivated"
        user.version = (user.version or 1) + 1
    if user.role != role:
        _audit(db, user, "role.changed", {"changes": {"role": {"from": user.role, "to": role}}, "sessions_ended": True})
        user.role, changed = role, "role"
        user.version = (user.version or 1) + 1
        await sessions.revoke_all(db, user.id)  # new rights at the next sign-in
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
