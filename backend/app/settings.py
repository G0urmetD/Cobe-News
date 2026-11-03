"""Settings sections as JSON in the `settings` table, each with its defaults."""

import copy

from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Setting

LDAP_FILTER = "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username})))"

DEFAULTS: dict[str, dict] = {
    "news": {"enabled": False, "every_min": 30, "keep_days": 90, "details": True},
    # Vendor News: on – but nothing is requested until somebody follows a product (docs/BETRIEB.md: Vendor News). The structured
    # sources (CSAF providers, cvelistV5, EPSS, OSV) are on as well: each asks only for what followed products (EPSS: also
    # the stories) need, and only public addresses or CVE ids leave the machine (docs/BETRIEB.md: Weitere Quellen)
    # The exploit lists (app/exploits.py – the same public file for everyone, daily, conditional): Metasploit and the
    # nuclei templates on (small, compressed), Exploit-DB off (~10 MB a day, uncompressed)
    "vendor": {"enabled": True, "nvd_key_enc": "", "every_h": 6, "eol_every_h": 24, "csaf": True, "cvelist": True, "epss": True, "osv": True, "exploit_metasploit": True, "exploit_exploitdb": False, "exploit_nuclei": True, "review_days": 90, "csaf_green": []},
    # temp_password_days: how long a temporary password (an admin's, the CLI reset-emergency's) is valid – 1 to 30
    "sessions": {"idle_min": 60, "absolute_h": 12, "temp_password_days": 7},
    # passkeys (WebAuthn) for local accounts: on – nobody has one until they register it themselves (after re-confirming
    # who they are), and only while BASE_URL is an https host name (app/auth/webauthn.availability)
    "passkeys": {"enabled": True},
    "setup": {"completed": False, "token_hash": "", "token_expires": 0},
    "smtp": {
        "host": "",
        "port": 587,
        "encryption": "starttls",  # starttls | tls | none
        "verify_cert": True,
        "username": "",
        "password_enc": "",
        "from_addr": "",
        "from_name": "Cobe News",
    },
    "ldap": {
        "enabled": False,
        "servers": [],
        "encryption": "ldaps",  # ldaps | starttls | none (only with allow_plain)
        "allow_plain": False,
        "verify_cert": True,
        "ca_cert": "",
        "base_dn": "",
        "bind_dn": "",
        "bind_password_enc": "",
        "user_filter": LDAP_FILTER,
        "nested_groups": True,
        "timeout": 10,
    },
    # mfa_mode (app/auth/entra.py): entra – trust Conditional Access (readers as before 0.1.42; admins only with a proof in
    # the token, else Cobe News' own TOTP) | context – the authentication context `auth_context` must be in the token |
    # require – a proof in the token or the own TOTP, for everybody
    "entra": {"enabled": False, "tenant_id": "", "client_id": "", "client_secret_enc": "", "mfa_mode": "entra", "auth_context": ""},
    # a second factor for everybody (auth_api.factor_required): off – readers keep signing in as before; on: local and
    # AD/LDAP readers set up TOTP (or, local, a passkey) at their next sign-in, Entra readers need a proof or the TOTP
    "mfa": {"required_all": False},
    # Teams (app/teams.py): off – while off nothing changes for anyone; the welcome e-mail to loaded members and the
    # personal notifications (e-mail, desktop, Microsoft Teams – app/personal.py) off as well
    "teams": {"enabled": False, "welcome_mail": False, "personal_email": False, "personal_desktop": False, "personal_teams": False},
    # the update notice for admins (app/update_check.py): on – one request to GitHub's release API every 12 hours
    "updates": {"check": True},
}


async def get(db: AsyncSession, section: str) -> dict:
    row = await db.get(Setting, section)
    return {**copy.deepcopy(DEFAULTS.get(section, {})), **(row.value if row else {})}


async def put(db: AsyncSession, section: str, value: dict) -> dict:
    row = await db.get(Setting, section)
    if row is None:
        db.add(Setting(key=section, value=dict(value)))
    else:
        row.value = dict(value)
    await db.flush()
    return await get(db, section)


async def put_rev(db: AsyncSession, section: str, value: dict, rev: int | None) -> dict:
    """A settings section written only when it is still the one the form was loaded with (`rev`, counted up with every
    save; None: an older client – not checked) – checked and written in one conditional UPDATE, committed. Another
    admin's save in between: 409 "stale" instead of silently undoing it."""
    from app.deps import api_error  # deps → auth → settings: imported when used

    current = await get(db, section)
    have = int(current.get("rev") or 0)
    if rev is not None and rev != have:
        raise api_error(409, "stale")
    new = {**value, "rev": have + 1}
    if await db.get(Setting, section) is None:
        db.add(Setting(key=section, value=new))
        try:
            await db.flush()
        except IntegrityError as exc:  # saved for the first time in parallel
            await db.rollback()
            raise api_error(409, "stale") from exc
    else:
        res = await db.execute(
            update(Setting)
            .where(Setting.key == section, func.coalesce(Setting.value["rev"].as_integer(), 0) == have)
            .values(value=new)
            .execution_options(synchronize_session=False)
        )
        if res.rowcount != 1:
            await db.rollback()
            raise api_error(409, "stale")
    await db.commit()
    return {**copy.deepcopy(DEFAULTS.get(section, {})), **new}
