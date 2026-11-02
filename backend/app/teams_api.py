"""Teams API (app/teams.py). Admins: the switch (and the welcome e-mail's), the teams, their directory groups, members
added by hand (local accounts) and products. Everybody signed in: the own teams (for "Mein Team" in Vendor News).

Binding or unbinding a group and switching Teams on or off decide who may read – they need a fresh proof of identity
(deps.require_reauth), as the group → role mapping does; so does deleting a team that has groups. Who of a team gets a
product (routing, app/personal.py) and the switches of the personal notifications decide no access – no reauth, as
the team's products."""

import re
import uuid
from datetime import UTC, date, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import ConfigDict, Field, field_validator
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from app import absence, audit, notify, personal, quiet, teams, weekly
from app import settings as settings_store
from app import vendor as vendor_svc
from app.auth import entra, ldap_dir
from app.config import get_config
from app.deps import ActiveSession, Admin, Db, NoNul, Reader, api_error, require_reauth
from app.models import NotifyChannel, NotifyRule, NotifyRuleTeam, Team, TeamGroup, TeamMember, TeamProduct, TeamProductMember, User, VendorFollow

router = APIRouter(prefix="/api", tags=["teams"])
GUID = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
MAX_TEAMS = 200
MAX_GROUPS = 20  # per team
BUSY = 3  # background loads waiting at most (a "load now" more is refused: 409 busy)


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


# ---------------------------------------------------------------- the switch


async def _settings_out(db, cfg: dict) -> dict:
    smtp = await settings_store.get(db, "smtp")
    ldap_cfg, entra_cfg = await settings_store.get(db, "ldap"), await settings_store.get(db, "entra")
    return {
        "enabled": bool(cfg.get("enabled")),
        "welcome_mail": bool(cfg.get("welcome_mail")),
        # the personal notifications about the products of a person (app/personal.py) – each way off by default
        "personal_email": bool(cfg.get("personal_email")),
        "personal_desktop": bool(cfg.get("personal_desktop")),
        "personal_teams": bool(cfg.get("personal_teams")),
        "web_push": get_config().web_push,
        "rev": int(cfg.get("rev") or 0),
        "smtp_ready": bool(smtp.get("host") and smtp.get("from_addr")),
        "ldap_usable": bool(ldap_cfg.get("enabled")) and ldap_dir.usable(ldap_cfg),
        "entra_usable": bool(entra_cfg.get("enabled")) and entra.usable(entra_cfg),
        "base_url": get_config().base_url,
    }


@router.get("/admin/teams/settings")
async def get_settings(admin: Admin, db: Db) -> dict:
    return await _settings_out(db, await teams.config(db))


class SettingsIn(_M):
    enabled: bool
    welcome_mail: bool = False
    # None: as they are (an older client that does not know them)
    personal_email: bool | None = None
    personal_desktop: bool | None = None
    personal_teams: bool | None = None
    rev: int | None = None


@router.put("/admin/teams/settings")
async def put_settings(body: SettingsIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    cur = await teams.config(db)
    was = bool(cur.get("enabled"))
    if body.enabled != was:
        require_reauth(sess, admin)  # on: the members of every team group may read; off: they may not any more
    value = {"enabled": body.enabled, "welcome_mail": body.welcome_mail}
    now = datetime.now(UTC).isoformat()
    for way in personal.WAYS:
        k = f"personal_{way}"
        v = getattr(body, k)
        value[k] = bool(cur.get(k)) if v is None else v
        # a way allowed (again) from now on: what came while it was not is never sent (no burst)
        on_before, on_now = was and bool(cur.get(k)), body.enabled and value[k]
        value[f"{k}_since"] = now if on_now and not on_before else cur.get(f"{k}_since")
    if changes := audit.diff(cur, value, [k for k in value if not k.endswith("_since")]):
        audit.record(db, admin, "settings.changed", audit.target("settings", teams.SECTION, teams.SECTION), {"changes": changes})
    out = await settings_store.put_rev(db, teams.SECTION, value, body.rev)
    if body.enabled and not was:
        await db.execute(update(TeamGroup).values(state="loading").execution_options(synchronize_session=False))
        await db.commit()
        teams.start()
    elif was and not body.enabled:
        await db.execute(update(TeamGroup).values(state="waiting").execution_options(synchronize_session=False))
        await db.commit()
        await teams.deactivate_left(db, "sync:teams_off")  # loaded, never signed in: no team, no access
    return await _settings_out(db, out)


# ---------------------------------------------------------------- teams


def _group_out(g: TeamGroup) -> dict:
    return {
        "id": str(g.id),
        "source": g.source,
        "group_id": g.group_id,
        "group_name": g.group_name,
        "state": g.state,
        "error": g.error,
        "members": g.members,
        "synced_at": _iso(g.synced_at),
    }


def _label(f: VendorFollow) -> str:
    p = vendor_svc.product_of(f)
    return (p or {}).get("label") or f.product


async def _teams_out(db, rows: list[Team]) -> list[dict]:
    ids = [t.id for t in rows]
    groups: dict[uuid.UUID, list[dict]] = {i: [] for i in ids}
    for g in await db.scalars(select(TeamGroup).where(TeamGroup.team_id.in_(ids)).order_by(func.lower(TeamGroup.group_name))):
        groups[g.team_id].append(_group_out(g))
    counts: dict[tuple[uuid.UUID, str], int] = {}
    for tid, origin, n in await db.execute(select(TeamMember.team_id, TeamMember.origin, func.count()).where(TeamMember.team_id.in_(ids)).group_by(TeamMember.team_id, TeamMember.origin)):
        counts[(tid, origin)] = n
    products: dict[uuid.UUID, list[dict]] = {i: [] for i in ids}
    chosen: dict[uuid.UUID, list[dict]] = {}
    q = (
        select(TeamProductMember.team_product_id, User.id, User.username, User.display_name)
        .join(User, User.id == TeamProductMember.user_id)
        .join(TeamProduct, TeamProduct.id == TeamProductMember.team_product_id)
        .where(TeamProduct.team_id.in_(ids))
        .order_by(func.lower(User.display_name), User.username)
    )
    for tp_id, uid, username, display in await db.execute(q):
        chosen.setdefault(tp_id, []).append({"id": str(uid), "username": username, "display_name": display or username})
    for tid, tp_id, all_members, f in await db.execute(
        select(TeamProduct.team_id, TeamProduct.id, TeamProduct.all_members, VendorFollow).join(VendorFollow, VendorFollow.id == TeamProduct.follow_id).where(TeamProduct.team_id.in_(ids))
    ):
        # routing: for all members of the team, or for the chosen ones (`people`)
        products[tid].append({"key": f.product, "label": _label(f), "enabled": f.enabled, "all_members": all_members, "people": [] if all_members else chosen.get(tp_id, [])})
    for v in products.values():
        v.sort(key=lambda p: p["label"].lower())
    weeklies = await weekly.settings_of(db, ids)
    rules: dict[uuid.UUID, list[str]] = {i: [] for i in ids}
    for tid, name in await db.execute(select(NotifyRuleTeam.team_id, NotifyRule.name).join(NotifyRule, NotifyRule.id == NotifyRuleTeam.rule_id).where(NotifyRuleTeam.team_id.in_(ids))):
        rules[tid].append(name)
    return [
        {
            "id": str(t.id),
            "name": t.name,
            "description": t.description,
            "version": t.version or 1,
            "created_at": t.created_at.isoformat(),
            "groups": groups[t.id],
            "members": {"group": counts.get((t.id, "group"), 0), "manual": counts.get((t.id, "manual"), 0)},
            "products": products[t.id],
            "rules": sorted(rules[t.id], key=str.lower),
            # "An mein Team weiterleiten": the channel a member's forward goes to (app/forward.py) – none: off
            "forward_channel_id": str(t.forward_channel_id) if t.forward_channel_id else None,
            "weekly": weeklies[t.id],
        }
        for t in rows
    ]


@router.get("/admin/teams")
async def list_teams(admin: Admin, db: Db) -> list[dict]:
    return await _teams_out(db, list(await db.scalars(select(Team).order_by(func.lower(Team.name)))))


@router.get("/admin/teams/products")
async def followed_products(admin: Admin, db: Db) -> list[dict]:
    """What can be assigned: every followed product (switched-off ones too – they keep their team)."""
    out = [{"key": f.product, "label": _label(f), "enabled": f.enabled} for f in await vendor_svc.follows(db, enabled_only=False)]
    return sorted(out, key=lambda p: p["label"].lower())


class TeamIn(_M):
    name: str = Field(min_length=2, max_length=80)
    description: str = Field(default="", max_length=500)


def _team_target(t: Team) -> audit.Target:
    return audit.target("team", t.id, t.name)


async def _team(db, tid: uuid.UUID) -> Team:
    t = await db.get(Team, tid)
    if t is None:
        raise api_error(404, "not_found")
    return t


@router.post("/admin/teams")
async def create_team(body: TeamIn, admin: Admin, db: Db) -> dict:
    if (await db.scalar(select(func.count()).select_from(Team)) or 0) >= MAX_TEAMS:
        raise api_error(409, "too_many_teams")
    if await db.scalar(select(Team.id).where(func.lower(Team.name) == body.name.lower())):
        raise api_error(409, "team_exists")
    t = Team(id=uuid.uuid4(), name=body.name, description=body.description)
    db.add(t)
    audit.record(db, admin, "team.created", _team_target(t), {"description": t.description})
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise api_error(409, "team_exists") from exc
    return (await _teams_out(db, [t]))[0]


class TeamPatch(_M):
    name: str | None = Field(default=None, min_length=2, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    # sent as null: no forward channel (forwarding off for the team); not sent: unchanged
    forward_channel_id: uuid.UUID | None = None
    version: int | None = None


@router.patch("/admin/teams/{tid}")
async def patch_team(tid: uuid.UUID, body: TeamPatch, admin: Admin, db: Db) -> dict:
    t = await _team(db, tid)
    have = t.version or 1
    if body.version is not None and body.version != have:
        raise api_error(409, "stale")
    values: dict = {"version": have + 1}
    if body.name is not None and body.name != t.name:
        if await db.scalar(select(Team.id).where(func.lower(Team.name) == body.name.lower(), Team.id != t.id)):
            raise api_error(409, "team_exists")
        values["name"] = body.name
    if body.description is not None:
        values["description"] = body.description
    if "forward_channel_id" in body.model_fields_set:
        if body.forward_channel_id is not None and await db.get(NotifyChannel, body.forward_channel_id) is None:
            raise api_error(422, "channel_not_found")
        values["forward_channel_id"] = body.forward_channel_id
    before = {"name": t.name, "description": t.description, "forward_channel_id": str(t.forward_channel_id) if t.forward_channel_id else None}
    after = {**before, **{k: (str(v) if isinstance(v, uuid.UUID) else v) for k, v in values.items() if k != "version"}}
    if changes := audit.diff(before, after):
        audit.record(db, admin, "team.changed", audit.target("team", t.id, after["name"]), {"changes": changes})
    try:
        res = await db.execute(update(Team).where(Team.id == t.id, Team.version == have).values(**values).execution_options(synchronize_session=False))
        if res.rowcount != 1:
            await db.rollback()
            raise api_error(409, "stale")
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise api_error(409, "team_exists") from exc
    await db.refresh(t)
    return (await _teams_out(db, [t]))[0]


@router.delete("/admin/teams/{tid}")
async def delete_team(tid: uuid.UUID, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    t = await _team(db, tid)
    used = list(await db.scalars(select(NotifyRule.name).join(NotifyRuleTeam, NotifyRuleTeam.rule_id == NotifyRule.id).where(NotifyRuleTeam.team_id == t.id)))
    if used:
        # a rule limited to this team would send everything once the team is gone – the rule is changed first
        raise api_error(409, "team_in_rules", rules=sorted(used, key=str.lower))
    if await db.scalar(select(TeamGroup.id).where(TeamGroup.team_id == t.id).limit(1)):
        require_reauth(sess, admin)  # its groups' members may lose their access
    audit.record(db, admin, "team.deleted", _team_target(t))
    await db.delete(t)
    await db.commit()
    if await teams.is_on(db):
        await teams.deactivate_left(db)  # its members' memberships went with it
    return {"ok": True}


# ---------------------------------------------------------------- groups


class GroupIn(_M):
    source: Literal["ldap", "entra"]
    group_id: str = Field(min_length=3, max_length=500)
    group_name: str = Field(default="", max_length=255)

    @field_validator("group_id")
    @classmethod
    def _gid(cls, v: str) -> str:
        if "=" not in v:
            if not re.match(GUID, v):
                raise ValueError("a DN or an object id")
            v = v.lower()
        return v


@router.post("/admin/teams/{tid}/groups")
async def bind_group(tid: uuid.UUID, body: GroupIn, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """Bind a directory group: its members (nested groups too) are loaded at once in the background."""
    require_reauth(sess, admin)  # the group's members may read from now on
    t = await _team(db, tid)
    if body.source == "ldap":
        if "=" not in body.group_id:
            raise api_error(422, "invalid_group")
        try:
            gid = ldap_dir.group_dn(await settings_store.get(db, "ldap"), body.group_id)
        except ldap_dir.LdapError as exc:
            raise api_error(422, "invalid_group") from exc
    else:
        if "=" in body.group_id:
            raise api_error(422, "invalid_group")
        gid = body.group_id
    if (await db.scalar(select(func.count()).select_from(TeamGroup).where(TeamGroup.team_id == t.id)) or 0) >= MAX_GROUPS:
        raise api_error(409, "too_many_groups")
    if await db.scalar(select(TeamGroup.id).where(TeamGroup.team_id == t.id, TeamGroup.source == body.source, func.lower(TeamGroup.group_id) == gid.lower())):
        raise api_error(409, "group_bound")
    on = await teams.is_on(db)
    g = TeamGroup(team_id=t.id, source=body.source, group_id=gid, group_name=body.group_name or gid, state="loading" if on else "waiting")
    db.add(g)
    audit.record(db, admin, "team.group_added", _team_target(t), {"source": g.source, "group_id": gid, "group_name": g.group_name})
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise api_error(409, "group_bound") from exc
    if on:
        teams.start({t.id})
    return _group_out(g)


@router.delete("/admin/teams/{tid}/groups/{gid}")
async def unbind_group(tid: uuid.UUID, gid: uuid.UUID, admin: Admin, sess: ActiveSession, db: Db) -> dict:
    """Unbind: its members leave the team with the load that starts now (the next sync at the latest)."""
    require_reauth(sess, admin)
    g = await db.get(TeamGroup, gid)
    if g is None or g.team_id != tid:
        raise api_error(404, "not_found")
    t = await db.get(Team, tid)
    audit.record(db, admin, "team.group_removed", audit.target("team", tid, t.name if t else None), {"source": g.source, "group_id": g.group_id, "group_name": g.group_name})
    await db.delete(g)
    await db.commit()
    if await teams.is_on(db):
        await db.rollback()  # nothing open while the load runs
        teams.start({tid})
    return {"ok": True}


@router.post("/admin/teams/{tid}/sync")
async def sync_team(tid: uuid.UUID, admin: Admin, db: Db) -> dict:
    """Load the team's groups now (as the hourly sync does)."""
    t = await _team(db, tid)
    if not await teams.is_on(db):
        raise api_error(409, "teams_off")
    if len(teams._tasks) >= BUSY:
        raise api_error(409, "busy")
    await db.execute(update(TeamGroup).where(TeamGroup.team_id == t.id).values(state="loading").execution_options(synchronize_session=False))
    await db.commit()
    teams.start({t.id})
    return {"started": True}


# ---------------------------------------------------------------- members


@router.get("/admin/teams/{tid}/members")
async def members(
    tid: uuid.UUID,
    admin: Admin,
    db: Db,
    q: Annotated[str, Query(max_length=100)] = "",
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict:
    t = await _team(db, tid)
    where = [TeamMember.team_id == t.id]
    if q.strip():
        v = q.strip().lower()
        where.append(or_(*(func.lower(c).contains(v, autoescape=True) for c in (User.username, User.display_name, User.email))))
    base = select(User, TeamMember.origin).join(TeamMember, TeamMember.user_id == User.id).where(*where)
    total = await db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = (await db.execute(base.order_by(func.lower(User.display_name), User.username).offset(offset).limit(limit))).all()
    welcome = await teams.welcome_of(db, [u for u, _ in rows])
    away = await absence.views(db, [u.id for u, _ in rows])
    # which of the team's products each one gets (routing): all members' ones and those they are chosen for
    tps = list(await db.execute(select(TeamProduct.id, TeamProduct.all_members, VendorFollow).join(VendorFollow, VendorFollow.id == TeamProduct.follow_id).where(TeamProduct.team_id == t.id)))
    ids = [u.id for u, _ in rows]
    picked: dict[uuid.UUID, set[uuid.UUID]] = {}
    if ids and tps:
        q = select(TeamProductMember.user_id, TeamProductMember.team_product_id).where(TeamProductMember.team_product_id.in_([x[0] for x in tps]), TeamProductMember.user_id.in_(ids))
        for uid, tp_id in await db.execute(q):
            picked.setdefault(uid, set()).add(tp_id)

    def gets(uid: uuid.UUID) -> list[str]:
        return sorted((_label(f) for tp_id, every, f in tps if every or tp_id in picked.get(uid, set())), key=str.lower)

    return {
        "total": total,
        "offset": offset,
        "items": [
            {
                "id": str(u.id),
                "username": u.username,
                "display_name": u.display_name or u.username,
                "email": u.email,
                "auth_source": u.auth_source,
                "origin": origin,
                "is_active": u.is_active,
                "deactivated_reason": u.deactivated_reason,
                "last_login_at": _iso(u.last_login_at),
                "welcome": welcome.get(u.id),
                "products": gets(u.id),
                "absence": away.get(u.id),
            }
            for u, origin in rows
        ],
    }


@router.put("/admin/teams/{tid}/members/{uid}")
async def add_member(tid: uuid.UUID, uid: uuid.UUID, admin: Admin, db: Db) -> dict:
    """A local account, added by hand (directory accounts come with their groups). Gives no role."""
    t = await _team(db, tid)
    u = await db.get(User, uid)
    if u is None:
        raise api_error(404, "not_found")
    if u.auth_source != "local":
        raise api_error(409, "directory_managed")
    res = await db.execute(pg_insert(TeamMember).values(team_id=t.id, user_id=u.id, origin="manual", added_at=datetime.now(UTC)).on_conflict_do_nothing())
    if res.rowcount:
        audit.record(db, admin, "team.member_added", _team_target(t), {"user": u.username, "user_id": str(u.id)})
    await db.commit()
    return {"ok": True}


@router.delete("/admin/teams/{tid}/members/{uid}")
async def remove_member(tid: uuid.UUID, uid: uuid.UUID, admin: Admin, db: Db) -> dict:
    m = await db.get(TeamMember, (tid, uid))
    if m is None:
        raise api_error(404, "not_found")
    if m.origin != "manual":
        raise api_error(409, "directory_managed")  # the group decides – take the person out of the group
    t, u = await db.get(Team, tid), await db.get(User, uid)
    audit.record(db, admin, "team.member_removed", audit.target("team", tid, t.name if t else None), {"user": u.username if u else None, "user_id": str(uid)})
    await db.delete(m)
    await teams.drop_routing(db, tid, [uid])  # their chosen products of the team go with them
    await db.commit()
    return {"ok": True}


# ---------------------------------------------------------------- products


class ProductsIn(_M):
    products: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(default_factory=list, max_length=2000)


@router.put("/admin/teams/{tid}/products")
async def set_products(tid: uuid.UUID, body: ProductsIn, admin: Admin, db: Db) -> dict:
    """The team's products, as a whole. One kept keeps its assignment (and when it was made: a rule limited to the team
    sends a product's events from its assignment on)."""
    t = await _team(db, tid)
    keys = list(dict.fromkeys(body.products))
    follows = {f.product: f.id for f in await db.scalars(select(VendorFollow).where(VendorFollow.product.in_(keys)))} if keys else {}
    if len(follows) != len(keys):
        raise api_error(422, "product_not_followed", products=[k for k in keys if k not in follows][:20])
    have = {fid: tp_id for tp_id, fid in await db.execute(select(TeamProduct.id, TeamProduct.follow_id).where(TeamProduct.team_id == t.id))}
    want = set(follows.values())
    key_of = {fid: k for k, fid in follows.items()}
    if set(have) != want:
        had = {f.id: f.product for f in await db.scalars(select(VendorFollow).where(VendorFollow.id.in_(list(have))))} if have else {}
        audit.record(db, admin, "team.products_changed", _team_target(t), {"added": sorted(key_of[f] for f in want - set(have)), "removed": sorted(had.get(f, str(f)) for f in set(have) - want)})
    gone = [tp for fid, tp in have.items() if fid not in want]
    if gone:
        await db.execute(delete(TeamProduct).where(TeamProduct.id.in_(gone)))
    now = datetime.now(UTC)
    for fid in want - set(have):
        await db.execute(pg_insert(TeamProduct).values(id=uuid.uuid4(), team_id=t.id, follow_id=fid, all_members=True, added_at=now).on_conflict_do_nothing())
    await db.commit()
    notify.changed()  # rules limited to the team look again
    return (await _teams_out(db, [t]))[0]


class RoutingIn(_M):
    product: str = Field(min_length=1, max_length=200)
    all_members: bool = True
    members: list[uuid.UUID] = Field(default_factory=list, max_length=2000)


@router.put("/admin/teams/{tid}/routing")
async def set_routing(tid: uuid.UUID, body: RoutingIn, admin: Admin, db: Db) -> dict:
    """Who of the team gets a product's Vendor News (personal notifications, "Mein Team"): all members, or the chosen
    ones – members of the team only. Whoever gets it newly gets its events from now on, not the older ones."""
    t = await _team(db, tid)
    tp = await db.scalar(select(TeamProduct).join(VendorFollow, VendorFollow.id == TeamProduct.follow_id).where(TeamProduct.team_id == t.id, VendorFollow.product == body.product))
    if tp is None:
        raise api_error(404, "not_found")
    members = list(dict.fromkeys(body.members)) if not body.all_members else []
    if members:
        found = set(await db.scalars(select(TeamMember.user_id).where(TeamMember.team_id == t.id, TeamMember.user_id.in_(members))))
        if len(found) != len(members):
            raise api_error(422, "not_member")
    await personal.set_routing(db, tp, body.all_members, members)
    names = list(await db.scalars(select(User.username).where(User.id.in_(members)))) if members else []
    audit.record(db, admin, "team.routing_changed", _team_target(t), {"product": body.product, "all_members": body.all_members, "members": sorted(names)})
    await db.commit()
    return (await _teams_out(db, [t]))[0]


# ---------------------------------------------------------------- everybody: the own teams


@router.get("/me/teams")
async def my_teams(user: Reader, db: Db) -> dict:
    """The signed-in person's teams – "Mein Team" in Vendor News (empty while Teams is off)."""
    if not await teams.is_on(db):
        return {"enabled": False, "teams": []}
    # `forward`: the team has a forward channel ("An mein Team weiterleiten") – which one is the admin's business
    return {"enabled": True, "teams": [{"id": str(t.id), "name": t.name, "forward": t.forward_channel_id is not None} for t in await teams.teams_of(db, user.id)]}


# ---------------------------------------------------------------- weekly review (app/weekly.py)


class WeeklyIn(_M):
    enabled: bool
    weekday: int = Field(default=0, ge=0, le=6)
    at: str = Field(default="08:00", pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
    tz: str = Field(default=quiet.DEFAULT_TZ, min_length=1, max_length=64)


@router.put("/admin/teams/{tid}/weekly")
async def set_weekly(tid: uuid.UUID, body: WeeklyIn, admin: Admin, db: Db) -> dict:
    """The team's weekly review by e-mail: on/off, weekday, time and zone. Who gets it, each member chooses."""
    t = await _team(db, tid)
    if not quiet.valid_tz(body.tz):
        raise api_error(422, "invalid_tz")
    await weekly.put(db, t.id, body.enabled, body.weekday, body.at, body.tz)
    audit.record(db, admin, "team.weekly_changed", _team_target(t), {"enabled": body.enabled, "weekday": body.weekday, "at": body.at, "tz": body.tz})
    await db.commit()
    return (await _teams_out(db, [t]))[0]


# ---------------------------------------------------------------- absence of a member, set by an admin (app/absence.py)


class AbsenceIn(_M):
    start: date
    end: date
    deputy_id: uuid.UUID
    also_me: bool = False


async def _member(db, tid: uuid.UUID, uid: uuid.UUID) -> None:
    await _team(db, tid)
    if await db.get(TeamMember, (tid, uid)) is None:
        raise api_error(404, "not_found")


@router.get("/admin/teams/{tid}/members/{uid}/deputies")
async def member_deputies(tid: uuid.UUID, uid: uuid.UUID, admin: Admin, db: Db, q: Annotated[str, Query(max_length=100)] = "") -> dict:
    """Who of this team can stand in for the member (active, the team gives the member a product)."""
    await _member(db, tid, uid)
    return {"items": await absence.deputies(db, uid, q, team_id=tid)}


@router.put("/admin/teams/{tid}/members/{uid}/absence")
async def set_member_absence(tid: uuid.UUID, uid: uuid.UUID, body: AbsenceIn, admin: Admin, db: Db) -> dict:
    """A member's absence, set by an admin – the deputy from this team, checked as for the person themselves."""
    await _member(db, tid, uid)
    try:
        await absence.put(db, uid, body.start, body.end, body.deputy_id, body.also_me, team_id=tid)
    except absence.AbsenceError as exc:
        raise api_error(exc.status, exc.code) from exc
    u, deputy = await db.get(User, uid), await db.get(User, body.deputy_id)
    audit.record(db, admin, "team.absence_set", audit.target("user", uid, u.username if u else None), {"team_id": str(tid), "start": body.start, "end": body.end, "deputy": deputy.username if deputy else None})
    await db.commit()
    return {"absence": (await absence.views(db, [uid])).get(uid)}


@router.delete("/admin/teams/{tid}/members/{uid}/absence")
async def end_member_absence(tid: uuid.UUID, uid: uuid.UUID, admin: Admin, db: Db) -> dict:
    await _member(db, tid, uid)
    await absence.end(db, uid)
    u = await db.get(User, uid)
    audit.record(db, admin, "team.absence_ended", audit.target("user", uid, u.username if u else None), {"team_id": str(tid)})
    await db.commit()
    return {"absence": (await absence.views(db, [uid])).get(uid)}
