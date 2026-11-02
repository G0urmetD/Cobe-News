"""Hourly directory sync: AD/Entra accounts that are gone, disabled or no longer in a mapped group are switched off
(their sessions end); a changed group changes the role. A directory that cannot be reached changes nothing – an outage
must not lock everyone out. Local accounts (the emergency admin above all) are never touched."""

import logging

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import settings as settings_store
from app.auth import directory, entra, ldap_dir
from app.auth.directory import DirectoryUser
from app.models import User

log = logging.getLogger("cobe_news.sync")


async def run(db: AsyncSession) -> dict[str, int]:
    out: dict[str, int] = {}
    ldap_cfg, entra_cfg = await settings_store.get(db, "ldap"), await settings_store.get(db, "entra")
    sources = []
    if ldap_cfg["enabled"] and ldap_dir.usable(ldap_cfg):
        sources.append("ldap")
    if entra_cfg["enabled"] and entra.usable(entra_cfg):
        sources.append("entra")
    if not sources:
        return out
    rows = await db.scalars(
        select(User).where(
            User.auth_source.in_(sources),
            User.is_emergency.is_(False),
            User.external_id.is_not(None),
            # accounts a team loaded and that never signed in hold no session: the team's own sync keeps them in step
            # (thousands of lookups an hour otherwise), the first sign-in checks everything anyway
            User.last_login_at.is_not(None),
            or_(User.is_active.is_(True), User.deactivated_reason.like("sync:%")),
        )
    )
    todo = [(u.id, u.auth_source, u.external_id) for u in rows]
    await db.rollback()  # no transaction stays open while the directories are asked (SQLite: one writer at a time)
    if not todo:
        return out
    # 1. ask the directories – one LDAP bind for all accounts; a directory that fails is left out entirely
    found: dict[str, DirectoryUser | None] = {}
    if "ldap" in sources:
        ids = [x for _, src, x in todo if src == "ldap"]
        try:
            found.update(await ldap_dir.run(ldap_dir.lookup_many, ldap_cfg, ids) if ids else {})
        except ldap_dir.LdapError as exc:
            log.warning("directory sync (ldap) skipped: %s", exc.category)
            sources.remove("ldap")
    if "entra" in sources:
        for _, src, x in todo:
            if src != "entra":
                continue
            try:
                found[x] = await entra.lookup(entra_cfg, x)
            except entra.EntraError as exc:
                log.warning("directory sync (entra) skipped: %s", getattr(exc, "category", exc))
                sources.remove("entra")
                break
    # 2. write the outcome in one short transaction
    for uid, src, x in todo:
        if src not in sources or x not in found:
            continue
        u = await db.get(User, uid)
        if u is None or u.auth_source != src or u.is_emergency:
            continue
        what = await directory.apply_sync(db, u, found[x])
        if what not in ("unchanged", "skipped"):
            out[what] = out.get(what, 0) + 1
            log.info("directory sync: %s %s", u.username, what)
    await db.commit()
    return out
