"""Audit log (app/audit.py, app/audit_api.py): every admin-mutating endpoint writes its entry in the transaction of the
change (a refused or rolled-back change leaves none), secrets never appear in clear (one central check, and a test that
fails when a new field that looks secret would be logged), admins only, keyset pages, filters, a formula-safe CSV,
the retention and the hourly prune; the directory sync as actor."""

import csv
import io
import json
import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, update

from app import audit, db, metrics
from app import settings as settings_store
from app.auth import directory
from app.auth.directory import DirectoryUser
from app.crypto import encrypt_str
from app.models import AuditEntry, NewsSource, User, UserSession
from conftest import PASSWORD, add_user
from test_notify import SLACK

SECRET = "Sehr-Geheim-Wert-0815-xyz"  # test fixture only – must never show up in the log


async def _entries(action: str | None = None) -> list[AuditEntry]:
    async with db.session() as s:
        q = select(AuditEntry).order_by(AuditEntry.id)
        if action:
            q = q.where(AuditEntry.action == action)
        return list(await s.scalars(q))


async def _count(action: str) -> int:
    async with db.session() as s:
        return int(await s.scalar(select(func.count()).select_from(AuditEntry).where(AuditEntry.action == action)) or 0)


def _ok(r) -> None:  # noqa: ANN001
    assert r.status_code < 300, r.text


# ---------------------------------------------------------------- every audited endpoint


async def _user(c):  # noqa: ANN001, ANN202
    r = await c.post("/api/admin/users", json={"username": "bob", "display_name": "Bob", "role": "reader"})
    _ok(r)
    return r.json()


async def _channel(c):  # noqa: ANN001, ANN202
    r = await c.post("/api/admin/notify/channels", json={"name": "SOC Slack", "type": "slack", "url": SLACK})
    _ok(r)
    return r.json()


async def _rule(c):  # noqa: ANN001, ANN202
    ch = await _channel(c)
    r = await c.post("/api/admin/notify/rules", json={"name": "Kritisch", "channels": [ch["id"]], "severities": ["critical"]})
    _ok(r)
    return r.json()


async def _team(c):  # noqa: ANN001, ANN202
    r = await c.post("/api/admin/teams", json={"name": "Netzwerk"})
    _ok(r)
    return r.json()


async def _source(c):  # noqa: ANN001, ANN202
    r = await c.post("/api/admin/news/sources", json={"name": "Example Feed", "url": "https://news.example.org/feed.xml"})
    _ok(r)
    return r.json()


async def _mapping(c):  # noqa: ANN001, ANN202
    r = await c.post("/api/admin/auth/mappings", json={"source": "entra", "group_id": "11111111-2222-3333-4444-555555555555", "group_name": "SOC", "role": "reader"})
    _ok(r)
    return r.json()


async def _token(c):  # noqa: ANN001, ANN202
    r = await c.post("/api/admin/api-tokens", json={"name": "SIEM", "scopes": ["read"]})
    _ok(r)
    return r.json()["item"]


async def _follow(c):  # noqa: ANN001, ANN202
    _ok(await c.put("/api/vendor/follows/gitlab", json={"enabled": True}))
    return "gitlab"


async def _version(c):  # noqa: ANN001, ANN202
    await _follow(c)
    r = await c.post("/api/vendor/follows/gitlab/versions", json={"version": "17.1.2", "label": "DMZ"})
    _ok(r)
    return r.json()


async def _teams_on(c):  # noqa: ANN001, ANN202
    _ok(await c.put("/api/admin/teams/settings", json={"enabled": True}))
    return await _team(c)


async def _local_member(c):  # noqa: ANN001, ANN202
    r = await c.post("/api/admin/teams", json={"name": "Anwendungen"})
    _ok(r)
    t = r.json()
    u = await _user(c)
    _ok(await c.put(f"/api/admin/teams/{t['id']}/members/{u['id']}"))
    return t, u


async def _nothing(c):  # noqa: ANN001, ANN202
    return None


def _register(c):  # noqa: ANN001, ANN202
    from test_passkeys import Authenticator, register

    return register(c, Authenticator(), name="YubiKey 5")


async def _passkey(c):  # noqa: ANN001, ANN202
    r = await _register(c)
    _ok(r)
    return r.json()


async def _users_passkey(c):  # noqa: ANN001, ANN202
    """bob (local) registers a passkey himself – an admin removes it."""
    from conftest import make_client, sign_in

    bob = await add_user("bob", "reader")
    async with make_client() as bc:
        await sign_in(bc, bob)
        return bob.id, (await _passkey(bc))["id"]


async def _session_of(user_id) -> str:  # noqa: ANN001
    """Another running session of the account (another browser)."""
    from app.auth import sessions

    async with db.session() as s:
        u = await s.get(User, user_id)
        sess, _ = await sessions.create(s, u, "pre", "192.0.2.10", "Firefox")
        await sessions.promote(s, sess, "active")
        await s.commit()
        return str(sess.id)


async def _my_other_session(c):  # noqa: ANN001, ANN202
    return await _session_of(c.user.id)


async def _bobs_session(c):  # noqa: ANN001, ANN202
    bob = await add_user("bob", "reader")
    return bob.id, await _session_of(bob.id)


async def _suggestion(c):  # noqa: ANN001, ANN202
    r = await c.post("/api/vendor/suggestions", json={"vendor": "Example Corp", "product": "Edge Gateway", "reason": "Läuft bei uns."})
    _ok(r)
    return r.json()


CASES = [
    # accounts
    ("user.created", _nothing, lambda c, x: c.post("/api/admin/users", json={"username": "bob", "role": "reader"})),
    ("user.changed", _user, lambda c, u: c.patch(f"/api/admin/users/{u['id']}", json={"display_name": "Robert"})),
    ("role.changed", _user, lambda c, u: c.patch(f"/api/admin/users/{u['id']}", json={"role": "admin"})),
    ("user.deactivated", _user, lambda c, u: c.patch(f"/api/admin/users/{u['id']}", json={"is_active": False})),
    ("user.blocked", _user, lambda c, u: c.post(f"/api/admin/users/{u['id']}/block", json={"blocked": True})),
    ("user.reset", _user, lambda c, u: c.post(f"/api/admin/users/{u['id']}/reset", json={"password": True, "totp": True})),
    ("user.unlocked", _user, lambda c, u: c.post(f"/api/admin/users/{u['id']}/unlock")),
    ("user.deleted", _user, lambda c, u: c.delete(f"/api/admin/users/{u['id']}")),
    # passkeys and sessions (own, and an admin's for an account)
    ("passkey.added", _nothing, lambda c, x: _register(c)),
    ("passkey.renamed", _passkey, lambda c, p: c.patch(f"/api/me/passkeys/{p['id']}", json={"name": "Laptop"})),
    ("passkey.removed", _passkey, lambda c, p: c.delete(f"/api/me/passkeys/{p['id']}")),
    ("passkey.removed", _users_passkey, lambda c, up: c.delete(f"/api/admin/users/{up[0]}/passkeys/{up[1]}")),
    ("sessions.revoked", _my_other_session, lambda c, sid: c.delete(f"/api/me/sessions/{sid}")),
    ("sessions.revoked", _my_other_session, lambda c, sid: c.post("/api/me/sessions/end-others")),
    ("sessions.revoked", _bobs_session, lambda c, us: c.delete(f"/api/admin/users/{us[0]}/sessions/{us[1]}")),
    ("sessions.revoked", _bobs_session, lambda c, us: c.post(f"/api/admin/users/{us[0]}/sessions/end-all")),
    # sign-in
    ("signin.config_changed", _nothing, lambda c, x: c.put("/api/admin/auth/sessions", json={"idle_min": 30, "absolute_h": 8})),
    ("signin.config_changed", _nothing, lambda c, x: c.put("/api/admin/auth/entra", json={"enabled": False, "tenant_id": str(uuid.uuid4()), "client_id": str(uuid.uuid4()), "client_secret": SECRET})),
    ("signin.config_changed", _nothing, lambda c, x: c.put("/api/admin/auth/ldap", json={"enabled": False, "servers": ["dc01.corp.example"], "bind_dn": "CN=svc,DC=corp,DC=example", "bind_password": SECRET})),
    ("role_mapping.created", _nothing, lambda c, x: c.post("/api/admin/auth/mappings", json={"source": "entra", "group_id": str(uuid.uuid4()), "group_name": "SOC", "role": "reader"})),
    ("role_mapping.deleted", _mapping, lambda c, m: c.delete(f"/api/admin/auth/mappings/{m['id']}")),
    ("settings.changed", _nothing, lambda c, x: c.put("/api/admin/auth/passkeys", json={"enabled": False})),
    # tokens
    ("token.created", _nothing, lambda c, x: c.post("/api/admin/api-tokens", json={"name": "SIEM", "scopes": ["read"]})),
    ("token.revoked", _token, lambda c, t: c.post(f"/api/admin/api-tokens/{t['id']}/revoke")),
    # channels and rules
    ("channel.created", _nothing, lambda c, x: c.post("/api/admin/notify/channels", json={"name": "SOC Slack", "type": "slack", "url": SLACK})),
    ("channel.changed", _channel, lambda c, ch: c.put(f"/api/admin/notify/channels/{ch['id']}", json={"name": "SOC Slack 2", "type": "slack", "url": ""})),
    ("channel.deleted", _channel, lambda c, ch: c.delete(f"/api/admin/notify/channels/{ch['id']}")),
    ("rule.created", _channel, lambda c, ch: c.post("/api/admin/notify/rules", json={"name": "Alles", "channels": [ch["id"]]})),
    ("rule.changed", _rule, lambda c, r: c.put(f"/api/admin/notify/rules/{r['id']}", json={"name": "Kritisch+", "channels": r["channels"], "severities": ["critical", "high"]})),
    ("rule.deleted", _rule, lambda c, r: c.delete(f"/api/admin/notify/rules/{r['id']}")),
    ("settings.changed", _nothing, lambda c, x: c.put("/api/admin/notify/smtp", json={"host": "mail.corp.example", "from_addr": "news@corp.example", "username": "news", "password": SECRET})),
    # teams
    ("settings.changed", _nothing, lambda c, x: c.put("/api/admin/teams/settings", json={"enabled": False, "welcome_mail": True})),
    ("team.created", _nothing, lambda c, x: c.post("/api/admin/teams", json={"name": "Netzwerk"})),
    ("team.changed", _team, lambda c, t: c.patch(f"/api/admin/teams/{t['id']}", json={"description": "Firewalls"})),
    ("team.deleted", _team, lambda c, t: c.delete(f"/api/admin/teams/{t['id']}")),
    ("team.group_added", _team, lambda c, t: c.post(f"/api/admin/teams/{t['id']}/groups", json={"source": "entra", "group_id": str(uuid.uuid4()), "group_name": "Netz"})),
    ("team.member_added", _nothing, None),  # covered by _local_member below
    ("team.member_removed", _local_member, lambda c, tu: c.delete(f"/api/admin/teams/{tu[0]['id']}/members/{tu[1]['id']}")),
    ("team.weekly_changed", _team, lambda c, t: c.put(f"/api/admin/teams/{t['id']}/weekly", json={"enabled": True, "weekday": 1, "at": "08:00", "tz": "Europe/Berlin"})),
    # settings, backup, export
    ("settings.changed", _nothing, lambda c, x: c.put("/api/admin/settings/news", json={"enabled": False, "every_min": 60, "keep_days": 30})),
    ("settings.changed", _nothing, lambda c, x: c.put("/api/admin/vendor", json={"enabled": True, "every_h": 12, "eol_every_h": 24, "nvd_key": "abcd-1234"})),
    ("settings.changed", _nothing, lambda c, x: c.put("/api/admin/backup", json={"keep": 14})),
    ("settings.changed", _nothing, lambda c, x: c.put("/api/admin/restore-test", json={"enabled": False, "mode": "host", "every_days": 7, "hour": 4})),
    ("settings.changed", _nothing, lambda c, x: c.put("/api/admin/audit/settings", json={"keep_days": 730})),
    ("export.downloaded", _nothing, lambda c, x: c.get("/api/admin/export?format=json")),
    ("audit.exported", _nothing, lambda c, x: c.get("/api/admin/audit/export")),
    # sources and products
    ("source.created", _nothing, lambda c, x: c.post("/api/admin/news/sources", json={"name": "Example Feed", "url": "https://news.example.org/feed.xml"})),
    ("source.changed", _source, lambda c, s: c.patch(f"/api/admin/news/sources/{s['id']}", json={"enabled": False})),
    ("source.deleted", _source, lambda c, s: c.delete(f"/api/admin/news/sources/{s['id']}")),
    ("catalog.followed", _nothing, lambda c, x: c.put("/api/vendor/follows/gitlab", json={"enabled": True})),
    ("catalog.follow_changed", _follow, lambda c, k: c.put(f"/api/vendor/follows/{k}", json={"enabled": True, "note": "DMZ", "tags": ["prod"]})),
    ("catalog.unfollowed", _follow, lambda c, k: c.delete(f"/api/vendor/follows/{k}")),
    ("catalog.custom_added", _nothing, lambda c, x: c.post("/api/vendor/custom", json={"cpe": "a:example:gateway", "label": "Example Gateway"})),
    ("catalog.version_added", _follow, lambda c, k: c.post(f"/api/vendor/follows/{k}/versions", json={"version": "17.1.2"})),
    ("catalog.version_changed", _version, lambda c, v: c.put(f"/api/vendor/versions/{v['id']}", json={"version": "17.1.3", "label": "DMZ"})),
    ("catalog.version_deleted", _version, lambda c, v: c.delete(f"/api/vendor/versions/{v['id']}")),
    ("catalog.version_confirmed", _version, lambda c, v: c.post(f"/api/vendor/versions/{v['id']}/confirm")),
    ("catalog.versions_confirmed", _version, lambda c, v: c.post("/api/vendor/review/confirm", json={"product": "gitlab", "due_only": False})),
    ("suggestion.accepted", _suggestion, lambda c, s: c.post(f"/api/admin/suggestions/{s['id']}/accept", json={"answer": "Kommt mit dem nächsten Katalog."})),
    ("suggestion.rejected", _suggestion, lambda c, s: c.post(f"/api/admin/suggestions/{s['id']}/reject", json={"answer": "Kein Hersteller-Feed."})),
    ("suggestion.duplicate", _suggestion, lambda c, s: c.post(f"/api/admin/suggestions/{s['id']}/duplicate", json={"product_key": "gitlab"})),
]


@pytest.mark.parametrize(("action", "prepare", "act"), [c for c in CASES if c[2] is not None], ids=lambda x: x if isinstance(x, str) else "")
async def test_each_audited_endpoint_writes_its_entry(admin_client, action, prepare, act):
    state = await prepare(admin_client)
    before = await _count(action)
    r = await act(admin_client, state)
    _ok(r)
    entries = await _entries(action)
    assert len(entries) == before + 1, [e.details for e in entries]
    e = entries[-1]
    assert e.actor_kind == "user" and e.actor_id == admin_client.user.id and e.actor_name == "anna"
    assert e.ip == "127.0.0.1"  # the middleware's client address (deps.client_ip)
    assert SECRET not in json.dumps(e.details) and "v1:" not in json.dumps(e.details)


def test_every_action_has_a_case_or_a_reason():
    """A new action without a test fails here: covered by the endpoint test above, or tested on its own below."""
    elsewhere = {
        "user.activated",  # test_directory_sync_is_the_actor
        "user.unblocked",  # test_block_and_unblock
        "account.password_changed",
        "account.totp_enabled",
        "account.totp_removed",  # test_own_account_actions
        "sessions.revoked",  # test_switching_a_source_off_logs_the_ended_sessions
        "login.success",
        "login.locked",
        "login.ip_blocked",  # test_sign_in_and_lockouts
        "setup.completed",  # test_setup_is_logged
        "team.group_removed",
        "team.products_changed",
        "team.routing_changed",
        "team.absence_set",
        "team.absence_ended",
        "team.synced",  # test_team_actions
        "backup.created",
        "backup.deleted",
        "backup.restored",  # test_backup_entries (restored: the CLI, see cli._restore)
        "restore_test.run",  # test_restore_test_run_is_logged
        "catalog.refreshed",  # test_catalog_refresh_is_logged
        "passkey.sign_count_warning",  # test_passkey_sign_in_and_counter_warning
        "delivery.resent",  # test_resend_is_logged
    }
    covered = {a for a, _, act in CASES if act is not None} | elsewhere | {"team.member_added"}
    assert set(audit.ACTIONS) == covered, set(audit.ACTIONS) ^ covered


# ---------------------------------------------------------------- never a secret


async def test_secrets_are_logged_as_changed_only(admin_client):
    _ok(await admin_client.put("/api/admin/notify/smtp", json={"host": "mail.corp.example", "from_addr": "news@corp.example", "username": "news", "password": SECRET}))
    _ok(await admin_client.put("/api/admin/auth/ldap", json={"enabled": False, "servers": ["dc01.corp.example"], "bind_dn": "CN=svc,DC=corp,DC=example", "bind_password": SECRET}))
    _ok(await admin_client.put("/api/admin/auth/entra", json={"enabled": False, "tenant_id": str(uuid.uuid4()), "client_id": str(uuid.uuid4()), "client_secret": SECRET}))
    ch = await _channel(admin_client)
    _ok(await admin_client.put(f"/api/admin/notify/channels/{ch['id']}", json={"name": "SOC Slack", "type": "slack", "url": SLACK.replace("XXXX", "YYYY")}))
    hook = await admin_client.post(
        "/api/admin/notify/channels",
        json={"name": "n8n", "type": "webhook", "url": "https://n8n.corp.example/webhook/cobe?token=" + SECRET, "hmac_secret": SECRET, "header_name": "X-Api-Key", "header_value": SECRET},
    )
    _ok(hook)
    tok = await admin_client.post("/api/admin/api-tokens", json={"name": "SIEM", "scopes": ["read"]})
    raw = json.dumps([e.details for e in await _entries()]) + json.dumps([e.target_label for e in await _entries()])
    for bad in (SECRET, "XXXXXXXXXXXXXXXX", "YYYY", "/services/", tok.json()["token"], tok.json()["item"]["prefix"], "v1:"):
        assert bad not in raw, bad
    smtp = (await _entries("settings.changed"))[0].details["changes"]
    assert smtp["password"] == audit.SECRET_MARK and smtp["host"] == {"from": "", "to": "mail.corp.example"}
    ldap = [e for e in await _entries("signin.config_changed") if e.target_id == "ldap"][0].details["changes"]
    assert ldap["bind_password"] == audit.SECRET_MARK and ldap["bind_dn"]["to"] == "CN=svc,DC=corp,DC=example"
    changed = (await _entries("channel.changed"))[0].details["changes"]
    assert changed == {"secret.url": audit.SECRET_MARK}  # same host – only that the URL changed
    made = [e for e in await _entries("channel.created") if e.target_label == "n8n"][0].details["changes"]
    assert made["target"]["to"] == "https://n8n.corp.example:443" and made["config.header_name"]["to"] == "X-Api-Key"
    assert {k for k, v in made.items() if v == audit.SECRET_MARK} == {"secret.url", "secret.hmac", "secret.header_value"}


async def test_push_channel_secrets_are_logged_as_changed_only(admin_client):
    """ntfy / Gotify / Mattermost (delivery-ops): topic and tokens live in the channel's secrets – "changed" only; the
    server is logged as its origin, a Mattermost hook URL not at all (a secret)."""
    from test_channels_push import GOTIFY, GOTIFY_TOKEN, MM, NTFY, NTFY_TOKEN, TOPIC

    r = await admin_client.post("/api/admin/notify/channels", json={"name": "ntfy", "type": "ntfy", "server_url": NTFY, "topic": TOPIC, "token": NTFY_TOKEN, "tags": ["soc"]})
    _ok(r)
    _ok(await admin_client.post("/api/admin/notify/channels", json={"name": "gotify", "type": "gotify", "server_url": GOTIFY, "token": GOTIFY_TOKEN}))
    _ok(await admin_client.post("/api/admin/notify/channels", json={"name": "mm", "type": "mattermost", "url": MM}))
    out = r.json()
    _ok(await admin_client.put(f"/api/admin/notify/channels/{out['id']}", json={"name": "ntfy", "type": "ntfy", "version": out["version"], "server_url": NTFY, "topic": TOPIC + "-2", "clear_token": True, "tags": ["soc"]}))
    raw = json.dumps([(e.target_label, e.details) for e in await _entries()])
    for bad in (TOPIC, NTFY_TOKEN, GOTIFY_TOKEN, "abcdefghij1234567890xyz", "/hooks/", "v1:"):
        assert bad not in raw, bad
    made = {e.target_label: e.details["changes"] for e in await _entries("channel.created")}
    assert made["ntfy"]["secret.topic"] == audit.SECRET_MARK and made["ntfy"]["secret.token"] == audit.SECRET_MARK
    assert made["ntfy"]["config.server"]["to"] == NTFY and made["ntfy"]["config.tags"]["to"] == ["soc"]
    assert made["gotify"]["secret.token"] == audit.SECRET_MARK and made["gotify"]["config.server"]["to"] == "https://gotify.corp.example/…"
    assert made["mm"]["secret.url"] == audit.SECRET_MARK
    changed = (await _entries("channel.changed"))[-1].details["changes"]
    assert changed == {"secret.topic": audit.SECRET_MARK, "secret.token": audit.SECRET_MARK}


def test_scrub_and_diff():
    assert audit.scrub({"password": "x", "nested": {"client_secret_enc": "v1:abc", "fine": "ok"}}) == {"password": audit.SECRET_MARK, "nested": {"client_secret_enc": audit.SECRET_MARK, "fine": "ok"}}
    assert audit.scrub({"note": "v1:Zm9vYmFy"}) == {"note": audit.SECRET_MARK}  # an encrypted value, whatever its name
    assert audit.scrub({"x": "cnt_" + "a" * 43}) == {"x": audit.SECRET_MARK}  # an API token
    assert audit.scrub({"u": "https://user:pw@hooks.example.com/services/T/B/C?x=1"}) == {"u": "https://hooks.example.com/…"}
    assert audit.scrub({"u": "https://news.example.org"}) == {"u": "https://news.example.org"}
    assert audit.scrub({"t": "a" * 500}) == {"t": audit.SECRET_MARK}  # one long word: as a key would look
    assert audit.scrub({"t": "a b" * 500})["t"].endswith("…") and len(audit.scrub({"t": "a b" * 500})["t"]) == audit.TEXT_MAX + 1
    assert len(audit.scrub(list(range(100)))) == audit.LIST_MAX + 1
    # a secret-named field keeps only the mark – also when a caller passed something else under the name
    assert audit.scrub({"token": {"secret": True, "changed": True}}) == {"token": audit.SECRET_MARK}
    assert audit.scrub({"token": {"secret": True, "value": "x"}}) == {"token": audit.SECRET_MARK}
    d = audit.diff({"host": "a", "password_enc": "v1:1", "rev": 1}, {"host": "b", "password_enc": "v1:2", "rev": 2})
    assert d == {"host": {"from": "a", "to": "b"}, "password": audit.SECRET_MARK}
    assert audit.diff({"password_enc": "v1:1"}, {"password_enc": "v1:1"}) == {}  # kept: not changed


# the broad net: any field name that looks like it could hold a secret
LOOKS_SECRET = re.compile(r"pass|secret|token|key|hmac|enc|cred|priv|cookie|seed|otp|sig|bearer|salt|hash|phrase|header|auth|cert|url|vapid", re.IGNORECASE)
# … and those of them that are no secret, each reviewed (a secret one belongs in audit.SECRET_NAME instead)
REVIEWED_NOT_SECRET = {
    "auth_source": "local | ldap | entra",
    "key": "a news source's or catalogue product's key",
    "keys": "the subscription's keys object is never logged (push_api is no admin action)",
    "url": "logged as its origin only (audit._url_origin) – a webhook's or feed's path and query never",
    "site": "a news source's home page (origin only, as url)",
    "ca_cert": "a CA certificate is public (PEM, cut to TEXT_MAX)",
    "verify_cert": "a switch",
    "encryption": "ldaps | starttls | none – a mode",
    "header_name": "the name of a webhook header, not its value",
    "nested_groups": "",
    "clear_hmac": "a switch",
    "clear_header": "a switch",
    "clear_password": "a switch",
    "clear_nvd_key": "a switch",
    "allow_http": "",
    "token_expires": "a time",
    "keep": "",
    "keep_days": "",
    "redirect_uri": "the app's own address",
    "base_url": "the app's own address",
    "use_proxy": "",
    "end_sessions": "",
    "keep_choices": "",
    "reauth_at": "a time",
    "endpoint": "a browser's push address – never logged (push_api is no admin action)",
    "p256dh": "never logged (push_api)",
    "webhook_url": "the personal Teams webhook – no admin action, never logged",
    "teams_webhook": "as webhook_url",
    "public_key": "a public key",
    "token_set": "a bool",
    "url_set": "a bool",
    "url_key": "a story's normalised address (news, never logged)",
    "certificate": "public",
    "is_emergency": "a flag (\"enc\" inside \"emergency\")",
    "title_key": "a story's normalised title (news, never logged)",
    "cert": "public",
    "authenticator_data": "a passkey sign-in's signed data (RP ID hash, flags, counter) – public, only in the sign-in request, never logged",
    "product_key": "a catalogue product's key (a suggestion's answer)",
    "server_url": "an ntfy / Gotify server's address – stored as config.server, logged as its origin only (as url)",
    "sign_count": "a passkey's signature counter",
    "sign_count_warning_at": "a time",
    "auth_context": "an Entra authentication context id (C1–C99) – a name, not a secret",
}


def _field_names() -> set[str]:
    """Every name a logged value could come under: the settings sections, the request bodies (all NoNul models of the
    app), the stored columns (and a channel's secret names)."""
    import importlib
    import pkgutil

    import app
    from app.db import Base
    from app.deps import NoNul

    names: set[str] = set()
    for section in settings_store.DEFAULTS.values():
        names |= set(section)
    for m in pkgutil.iter_modules(app.__path__):
        if m.name not in ("cli",):
            importlib.import_module(f"app.{m.name}")

    def walk(cls):  # noqa: ANN001, ANN202
        for sub in cls.__subclasses__():
            yield sub
            yield from walk(sub)

    for model in walk(NoNul):
        names |= set(model.model_fields)
    for table in Base.metadata.tables.values():
        names |= {c.name for c in table.columns}
    names |= {"url", "token", "hmac", "header_value", "topic"}  # NotifyChannel.secrets
    return names


def test_no_secret_looking_field_is_logged_in_clear():
    """Fails when a new field that looks secret would be logged in clear: add it to audit.SECRET_NAME (it is one) – or,
    reviewed, to REVIEWED_NOT_SECRET here."""
    unclear = sorted(n for n in _field_names() if LOOKS_SECRET.search(n) and not audit.is_secret(n) and n not in REVIEWED_NOT_SECRET)
    assert unclear == [], f"looks secret, not redacted by audit.is_secret and not reviewed: {unclear}"
    for name in ("auth", "p256dh", "teams_url", "webhook_url", "password", "bind_password_enc", "client_secret", "nvd_key_enc", "password_enc", "totp_secret_enc", "hmac_secret", "header_value", "bot_token", "token_hash", "password_hash", "secret.url", "passphrase", "api_key", "topic", "secret.topic", "secret.token"):
        assert audit.is_secret(name), name


# ---------------------------------------------------------------- transactions


async def test_a_rolled_back_change_leaves_no_entry(admin_client):
    u = await _user(admin_client)
    # stale: another admin saved in between – refused, nothing written, nothing logged
    assert (await admin_client.patch(f"/api/admin/users/{u['id']}", json={"display_name": "X", "version": 99})).status_code == 409
    _ok(await admin_client.put("/api/admin/auth/sessions", json={"idle_min": 30, "absolute_h": 8, "rev": 0}))
    n = await _count("signin.config_changed")
    assert (await admin_client.put("/api/admin/auth/sessions", json={"idle_min": 45, "absolute_h": 8, "rev": 0})).status_code == 409
    assert await _count("user.changed") == 0 and await _count("signin.config_changed") == n
    # refused by a guard after the entry was added (the last admin): rolled back with it
    assert (await admin_client.patch(f"/api/admin/users/{admin_client.user.id}", json={"is_active": False})).status_code == 409
    assert await _count("user.deactivated") == 0


async def test_record_lives_and_dies_with_the_transaction():
    async with db.session() as s:
        audit.record(s, audit.SYSTEM, "settings.changed", audit.target("settings", "news", "news"), {"changes": {}})
        await s.rollback()
    assert await _entries() == []
    with pytest.raises(ValueError):
        async with db.session() as s:
            audit.record(s, audit.SYSTEM, "no.such_action")


async def test_no_edit_or_delete_api(admin_client):
    async with db.session() as s:
        audit.record(s, audit.SYSTEM, "settings.changed")
        await s.commit()
    eid = (await _entries())[0].id
    for method in ("put", "patch", "delete", "post"):
        r = await getattr(admin_client, method)(f"/api/admin/audit/{eid}") if method != "post" else await admin_client.post("/api/admin/audit")
        assert r.status_code in (404, 405), (method, r.status_code)
    assert len(await _entries()) == 1


# ---------------------------------------------------------------- reading


async def test_admins_only(reader_client, client):
    for path in ("/api/admin/audit", "/api/admin/audit/export", "/api/admin/audit/actors", "/api/admin/audit/settings"):
        assert (await reader_client.get(path)).status_code == 403
        assert (await client.get(path)).status_code == 401
    assert (await reader_client.put("/api/admin/audit/settings", json={"keep_days": 400})).status_code == 403


async def _seed(n: int, **kw) -> None:
    t0 = datetime(2026, 10, 1, tzinfo=UTC)
    async with db.session() as s:
        for i in range(n):
            e = audit.record(s, kw.get("actor", audit.SYSTEM), kw.get("action", "settings.changed"), audit.target("settings", f"s{i}", f"Abschnitt {i}"), {"i": i})
            e.at = t0 + timedelta(minutes=i // 2)  # two entries per minute: the keyset needs the id as tie-breaker
        await s.commit()


async def test_keyset_pages_newest_first_without_gaps(admin_client):
    await _seed(25)
    seen, cursor = [], None
    while True:
        r = await admin_client.get("/api/admin/audit", params={"limit": 7, **({"cursor": cursor} if cursor else {})})
        body = r.json()
        seen += [x["id"] for x in body["items"]]
        cursor = body["next"]
        if not cursor:
            break
        # a new entry arriving between two pages shifts nothing (no OFFSET)
        async with db.session() as s:
            audit.record(s, audit.SYSTEM, "token.created")
            await s.commit()
    seeded = sorted(await _entries("settings.changed"), key=lambda e: (e.at, e.id), reverse=True)
    assert seen == [e.id for e in seeded]  # each once, newest first – the entries that came meanwhile are newer (not on later pages)
    assert (await admin_client.get("/api/admin/audit", params={"cursor": "kaputt"})).status_code == 422


async def test_filters(admin_client):
    bob = await add_user("bob", "admin")
    await _seed(3)
    await _seed(2, actor=bob, action="token.created")
    async with db.session() as s:
        audit.record(s, audit.SYNC, "user.deactivated", audit.target("user", uuid.uuid4(), "carol"), {"reason": "sync:gone"}, ip="192.0.2.7")
        await s.commit()

    async def ids(**params) -> int:  # noqa: ANN003
        r = await admin_client.get("/api/admin/audit", params=params)
        assert r.status_code == 200, r.text
        return len(r.json()["items"])

    assert await ids() == 6
    assert await ids(actor=str(bob.id)) == 2 and await ids(actor="sync") == 1 and await ids(actor="system") == 3
    assert await ids(group="tokens") == 2 and await ids(group="accounts") == 1 and await ids(action="settings.changed") == 3
    assert await ids(target_type="settings", target_id="s2") == 1
    assert await ids(q="CAROL") == 1 and await ids(q="192.0.2") == 1 and await ids(q="100%_") == 0
    assert await ids(since="2026-10-01T00:00:30Z", until="2026-10-01T00:01:30Z") == 1
    assert (await admin_client.get("/api/admin/audit", params={"group": "nope"})).status_code == 422
    assert (await admin_client.get("/api/admin/audit", params={"since": "2026-10-01T00:00:00"})).status_code == 422  # no zone
    actors = (await admin_client.get("/api/admin/audit/actors")).json()
    assert {a["id"] for a in actors} == {str(bob.id), "system", "sync"}


async def test_csv_export_is_formula_safe_and_filtered(admin_client):
    async with db.session() as s:
        audit.record(s, audit.SYSTEM, "team.created", audit.target("team", uuid.uuid4(), "=HYPERLINK(\"http://evil.example\")"), {"description": "+1"})
        audit.record(s, audit.SYSTEM, "team.created", audit.target("team", uuid.uuid4(), "@SUM(A1)"))
        audit.record(s, audit.SYSTEM, "token.created", audit.target("api_token", uuid.uuid4(), "-cmd"))
        await s.commit()
    r = await admin_client.get("/api/admin/audit/export", params={"group": "teams"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv") and "attachment" in r.headers["content-disposition"]
    text = r.content.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == list(audit.CSV_COLUMNS) and len(rows) == 3  # the header and the two team entries (not the token)
    labels = {row[audit.CSV_COLUMNS.index("target")] for row in rows[1:]}
    assert labels == {"'=HYPERLINK(\"http://evil.example\")", "'@SUM(A1)"}
    assert all(not cell[:1] in "=+-@" for row in rows for cell in row if cell)
    assert audit.cell("-1") == "'-1" and audit.cell("\tx") == "'\tx" and audit.cell("ok") == "ok"
    # the export itself is logged (with its filters)
    assert (await _entries("audit.exported"))[-1].details == {"filters": {"group": "teams"}}


# ---------------------------------------------------------------- retention


async def test_retention_and_prune(admin_client):
    r = await admin_client.get("/api/admin/audit/settings")
    assert r.json()["keep_days"] == 365 and r.json()["keep_min"] == 90 and r.json()["keep_max"] == 3650
    for bad in (89, 3651):
        assert (await admin_client.put("/api/admin/audit/settings", json={"keep_days": bad})).status_code == 422
    async with db.session() as s:
        for days in (10, 200, 400):
            e = audit.record(s, audit.SYSTEM, "settings.changed", None, {"days": days})
            e.at = datetime.now(UTC) - timedelta(days=days)
        await s.commit()
    async with db.session() as s:
        assert await audit.prune(s) == 1  # 400 days old, past 365
    _ok(await admin_client.put("/api/admin/audit/settings", json={"keep_days": 180}))
    async with db.session() as s:
        assert await audit.prune(s) == 1  # 200 days old
    left = [e.details.get("days") for e in await _entries()]
    assert 10 in left and 200 not in left and 400 not in left
    assert (await _entries("settings.changed"))[-1].details["changes"] == {"keep_days": {"from": 365, "to": 180}}


async def test_shorter_retention_needs_reauth(admin_client):
    async with db.session() as s:
        await s.execute(update(UserSession).values(reauth_at=None))
        await s.commit()
    assert (await admin_client.put("/api/admin/audit/settings", json={"keep_days": 100})).json()["detail"]["code"] == "reauth_required"
    _ok(await admin_client.put("/api/admin/audit/settings", json={"keep_days": 1000}))  # longer: no reauth


async def test_prune_runs_in_the_hourly_step(monkeypatch):
    from app import main

    called = []

    async def fake(s):  # noqa: ANN001, ANN202
        called.append(1)
        return 0

    monkeypatch.setattr(audit, "prune", fake)
    await main.FetchLoop()._prune()
    assert called == [1]


# ---------------------------------------------------------------- the other actors


async def test_directory_sync_is_the_actor():
    async with db.session() as s:
        u = User(username="dora", display_name="Dora", role="reader", auth_source="ldap", external_id="guid-dora", is_active=True, last_login_at=datetime.now(UTC))
        s.add(u)
        await s.commit()
        # gone from the directory: switched off by the sync
        assert await directory.apply_sync(s, u, None) == "deactivated"
        await s.commit()
    e = (await _entries("user.deactivated"))[-1]
    assert e.actor_kind == "sync" and e.actor_id is None and e.ip is None and e.target_label == "dora" and e.details["reason"] == "sync:gone"
    # back with a mapped group as admin: switched on again and the role changed
    from app.models import GroupMapping

    async with db.session() as s:
        s.add(GroupMapping(source="ldap", group_id="CN=Admins,DC=corp,DC=example", group_name="Admins", role="admin"))
        await s.commit()
        u = await s.get(User, u.id)
        du = DirectoryUser(source="ldap", external_id="guid-dora", username="dora", display_name="Dora", groups=["CN=Admins,DC=corp,DC=example"])
        await directory.apply_sync(s, u, du)
        await s.commit()
    assert (await _entries("user.activated"))[-1].actor_kind == "sync"
    role = (await _entries("role.changed"))[-1]
    assert role.actor_kind == "sync" and role.details["changes"] == {"role": {"from": "reader", "to": "admin"}}


async def test_switching_a_source_off_logs_the_ended_sessions(admin_client):
    async with db.session() as s:
        await settings_store.put(s, "entra", {**settings_store.DEFAULTS["entra"], "enabled": True, "tenant_id": str(uuid.uuid4()), "client_id": str(uuid.uuid4()), "client_secret_enc": encrypt_str(SECRET)})
        await s.commit()
    _ok(await admin_client.put("/api/admin/auth/entra", json={"enabled": False}))
    e = (await _entries("sessions.revoked"))[-1]
    assert e.target_id == "entra" and e.details == {"why": "source_off", "accounts": 0}
    change = [x for x in await _entries("signin.config_changed") if x.target_id == "entra"][-1].details["changes"]
    assert change["enabled"] == {"from": True, "to": False} and "client_secret" not in change  # kept: not changed


async def test_block_and_unblock(admin_client):
    u = await _user(admin_client)
    _ok(await admin_client.post(f"/api/admin/users/{u['id']}/block", json={"blocked": True}))
    _ok(await admin_client.post(f"/api/admin/users/{u['id']}/block", json={"blocked": False}))
    assert [e.action for e in await _entries() if e.action.startswith("user.") and e.action.endswith("blocked")] == ["user.blocked", "user.unblocked"]


async def test_own_account_actions(client):
    u = await add_user("rita", "reader")
    from conftest import sign_in

    await sign_in(client, u)
    _ok(await client.post("/api/me/password", json={"current_password": PASSWORD, "new_password": "Ein-neues-langes-Passwort-2026"}))
    e = (await _entries("account.password_changed"))[-1]
    assert e.actor_id == u.id and e.target_id == str(u.id) and "Passwort" not in json.dumps(e.details)
    import pyotp

    r = await client.post("/api/me/totp/start", json={"password": "Ein-neues-langes-Passwort-2026"})
    _ok(r)
    _ok(await client.post("/api/me/totp/confirm", json={"code": pyotp.TOTP(r.json()["secret"]).now()}))
    assert await _count("account.totp_enabled") == 1
    assert r.json()["secret"] not in json.dumps([x.details for x in await _entries()])


async def test_sign_in_and_lockouts(client):
    await add_user("erika", "reader")
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    # a reader's sign-in: not logged; failures one by one: not logged; the lock they start: logged once
    _ok(await client.post("/api/auth/login", json={"username": "erika", "password": PASSWORD}))
    assert await _count("login.success") == 0
    for _ in range(5):
        await client.post("/api/auth/login", json={"username": "erika", "password": "falsch-" + SECRET})
    locked = await _entries("login.locked")
    assert len(locked) == 1 and locked[0].target_label == "erika" and locked[0].ip == "127.0.0.1" and locked[0].actor_kind == "system"
    assert SECRET not in json.dumps([e.details for e in await _entries()])
    # an unknown name that is no name (a password typed into the field): never in the log
    for _ in range(5):
        await client.post("/api/auth/login", json={"username": "P@ss wort!" + SECRET, "password": "x"})
    assert (await _entries("login.locked"))[-1].target_label == "?"
    assert SECRET not in json.dumps([(e.target_label, e.details) for e in await _entries()])


async def test_admin_sign_in_is_logged(client):
    import pyotp

    secret = pyotp.random_base32()
    ada = await add_user("ada", "admin", totp_secret=secret)
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    r = await client.post("/api/auth/login", json={"username": "ada", "password": PASSWORD})
    assert r.json()["next"] == "mfa" and await _count("login.success") == 0  # complete only with the second factor
    _ok(await client.post("/api/auth/mfa", json={"code": pyotp.TOTP(secret).now()}))
    e = (await _entries("login.success"))[-1]
    assert e.actor_id == ada.id and e.ip == "127.0.0.1" and e.details == {"source": "local", "method": "password_totp"}


async def test_address_block_is_logged_once(client):
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    # the address block: 30 failures across 5 names
    for i in range(30):
        await client.post("/api/auth/login", json={"username": f"user{i % 6}", "password": "x"})
    assert await _count("login.ip_blocked") == 1


async def test_setup_is_logged(client):
    from app.auth_api import issue_setup_token

    async with db.session() as s:
        token = await issue_setup_token(s)
    _ok(await client.post("/api/setup", json={"token": token, "username": "root", "password": "Ein-sehr-langes-Setup-Passwort-2026"}))
    e = (await _entries("setup.completed"))[-1]
    assert e.target_label == "root" and e.actor_name == "root"


async def test_team_actions(admin_client, monkeypatch):
    from app import teams

    monkeypatch.setattr(teams, "start", lambda *a, **k: None)
    t = await _teams_on(admin_client)
    r = await admin_client.post(f"/api/admin/teams/{t['id']}/groups", json={"source": "entra", "group_id": str(uuid.uuid4()), "group_name": "Netz"})
    _ok(r)
    _ok(await admin_client.delete(f"/api/admin/teams/{t['id']}/groups/{r.json()['id']}"))
    await _follow(admin_client)
    _ok(await admin_client.put(f"/api/admin/teams/{t['id']}/products", json={"products": ["gitlab"]}))
    assert (await _entries("team.products_changed"))[-1].details == {"added": ["gitlab"], "removed": []}
    tu = await _local_member(admin_client)
    _ok(await admin_client.put(f"/api/admin/teams/{tu[0]['id']}/products", json={"products": ["gitlab"]}))
    _ok(await admin_client.put(f"/api/admin/teams/{tu[0]['id']}/routing", json={"product": "gitlab", "all_members": False, "members": [tu[1]["id"]]}))
    assert (await _entries("team.routing_changed"))[-1].details["members"] == ["bob"]
    for a in ("team.group_removed", "team.member_added"):
        assert await _count(a) == 1, a
    # the sync switching off loaded accounts that never signed in: one entry for all, actor the sync
    async with db.session() as s:
        s.add(User(username="lena", role="reader", auth_source="entra", external_id=str(uuid.uuid4()), is_active=True))
        await s.commit()
    async with db.session() as s:
        assert await teams.deactivate_left(s) == 1
    e = (await _entries("team.synced"))[-1]
    assert e.actor_kind == "sync" and e.details == {"deactivated": 1, "reason": "sync:no_team"}


async def test_member_absence(admin_client):
    from app.models import TeamMember

    t = await _team(admin_client)
    a, b = await add_user("anton"), await add_user("berta")
    async with db.session() as s:
        s.add_all([TeamMember(team_id=uuid.UUID(t["id"]), user_id=a.id, origin="manual"), TeamMember(team_id=uuid.UUID(t["id"]), user_id=b.id, origin="manual")])
        await s.commit()
    start = datetime.now(UTC).date()
    r = await admin_client.put(f"/api/admin/teams/{t['id']}/members/{a.id}/absence", json={"start": str(start), "end": str(start + timedelta(days=3)), "deputy_id": str(b.id)})
    if r.status_code == 200:  # the deputy needs a product of the team – either way: logged only when it was set
        assert (await _entries("team.absence_set"))[-1].details["deputy"] == "berta"
        _ok(await admin_client.delete(f"/api/admin/teams/{t['id']}/members/{a.id}/absence"))
        assert await _count("team.absence_ended") == 1
    else:
        assert await _count("team.absence_set") == 0


async def test_backup_entries(monkeypatch, tmp_path):
    from app import backup

    res = backup.Result(name="cobe-news-20261031-030000.tar", path=tmp_path / "x", size=1234, seconds=1.0, encrypted=False, rows={})
    await backup._audit(audit.CLI, res, "", ["cobe-news-20261001-030000.tar"])
    made, gone = (await _entries("backup.created"))[-1], (await _entries("backup.deleted"))[-1]
    assert made.actor_kind == "cli" and made.target_label == res.name and made.details["reason"] == "manual"
    assert gone.details == {"files": ["cobe-news-20261001-030000.tar"], "why": "keep"}


async def test_restore_test_run_is_logged(admin_client, monkeypatch):
    from app import restore_test

    from sqlalchemy.engine import make_url

    monkeypatch.setattr(restore_test, "target", lambda: make_url("postgresql+asyncpg://restore@db.invalid/cobe_news_restore_test"))
    monkeypatch.setattr(restore_test, "start", lambda *a: True)
    _ok(await admin_client.post("/api/admin/restore-test"))
    assert (await _entries("restore_test.run"))[-1].details["trigger"] == "manual"


async def test_catalog_refresh_is_logged(admin_client):
    from app import vendor_api

    vendor_api._last_catalog[0] = -1e9
    _ok(await admin_client.post("/api/admin/vendor/catalog"))
    assert await _count("catalog.refreshed") == 1


async def test_metrics_count_by_group_without_names(admin_client):
    await _seed(2)
    await _seed(1, action="token.created")
    metrics.reset()
    body = (await metrics.render()).decode()
    assert 'cobe_news_audit_entries{group="settings"} 2' in body and 'cobe_news_audit_entries{group="tokens"} 1' in body
    assert "cobe_news_audit_newest_timestamp_seconds" in body and "Abschnitt" not in body and "anna" not in body
    metrics.reset()


async def test_sources_logged_without_url_path(admin_client):
    s = await _source(admin_client)
    e = (await _entries("source.created"))[-1]
    assert e.details == {"url": "https://news.example.org/…"} and e.target_label == "Example Feed"
    _ok(await admin_client.patch(f"/api/admin/news/sources/{s['id']}", json={"url": "https://news.example.org/other.xml"}))
    assert (await _entries("source.changed"))[-1].details["changes"] == {"url": {"changed": True}}
    async with db.session() as s2:
        assert (await s2.get(NewsSource, uuid.UUID(s["id"]))).url.endswith("other.xml")


async def test_migration_0017_down_and_up():
    """The new table only: the downgrade drops it, the upgrade brings it back with its indexes – in a transaction that
    is rolled back, the test database stays as it was. Not in a 0.1.15 SQLite file (nothing to import)."""
    import importlib

    from alembic import command
    from sqlalchemy import inspect

    from app import sqlite_import

    prev = importlib.import_module("app.migrations.versions.0017_audit_log").down_revision

    def step(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), prev)
        gone = "audit_log" not in inspect(conn).get_table_names()
        command.upgrade(db.alembic_config(conn), "0017")
        return gone, {i["name"] for i in inspect(conn).get_indexes("audit_log")}

    async with db.engine().connect() as conn:
        trans = await conn.begin()
        try:
            gone, idx = await conn.run_sync(step)
        finally:
            await trans.rollback()
    assert gone and idx == {"ix_audit_log_at", "ix_audit_log_actor", "ix_audit_log_action", "ix_audit_log_target"}
    assert "audit_log" in sqlite_import.NOT_IN_SQLITE


def test_the_ui_knows_every_action():
    """The UI's copy of the groups (frontend/src/lib/audit.ts – its texts are checked there) is the server's."""
    from pathlib import Path

    ts = Path(__file__).resolve().parents[2] / "frontend" / "src" / "lib" / "audit.ts"
    if not ts.is_file():
        pytest.skip("no frontend next to the backend")
    block = ts.read_text("utf-8").split("export const AUDIT_GROUPS", 1)[1].split("} as const", 1)[0]
    groups = {g: set(re.findall(r'"([a-z_]+\.[a-z_]+)"', body)) for g, body in re.findall(r"(\w+): \[([^\]]*)\]", block)}
    assert groups == {g: set(a) for g, a in audit.GROUPS.items()}


# ---------------------------------------------------------------- passkeys, sessions, deliveries, catalogue care


async def test_passkey_entries_name_the_account_and_never_the_key(admin_client):
    p = await _passkey(admin_client)
    _ok(await admin_client.patch(f"/api/me/passkeys/{p['id']}", json={"name": "Laptop"}))
    _ok(await admin_client.delete(f"/api/me/passkeys/{p['id']}"))
    bob_id, pid = await _users_passkey(admin_client)
    _ok(await admin_client.delete(f"/api/admin/users/{bob_id}/passkeys/{pid}"))
    added, renamed = (await _entries("passkey.added"))[0], (await _entries("passkey.renamed"))[-1]
    assert added.target_id == str(admin_client.user.id) and added.details == {"name": "YubiKey 5", "transports": ["hybrid", "internal"]}
    assert renamed.details == {"changes": {"name": {"from": "YubiKey 5", "to": "Laptop"}}}
    own, by_admin = await _entries("passkey.removed")
    assert own.details == {"name": "Laptop", "by_admin": False, "sessions_ended": 0} and own.target_label == "anna"
    assert by_admin.actor_id == admin_client.user.id and by_admin.target_id == str(bob_id) and by_admin.target_label == "bob"
    assert by_admin.details == {"name": "YubiKey 5", "by_admin": True, "sessions_ended": 0}
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(AuditEntry).where(AuditEntry.action.like("passkey.%"))) == 5  # added, renamed, removed – bob's added and removed
    # a rename to the same name is no change
    p = await _passkey(admin_client)
    n = await _count("passkey.renamed")
    _ok(await admin_client.patch(f"/api/me/passkeys/{p['id']}", json={"name": "YubiKey 5"}))
    assert await _count("passkey.renamed") == n
    # the switch: settings.changed of the section "passkeys"
    _ok(await admin_client.put("/api/admin/auth/passkeys", json={"enabled": False}))
    e = (await _entries("settings.changed"))[-1]
    assert e.target_id == "passkeys" and e.details == {"changes": {"enabled": {"from": True, "to": False}}}


async def test_passkey_sign_in_and_counter_warning(reader_client):
    """An admin's passkey sign-in is login.success with method passkey (a reader's is not logged); a counter that went
    back is passkey.sign_count_warning (actor the system, on the account, the address it came from); refused passkey
    sign-ins are not logged one by one – the block of the address they lead to is (login.ip_blocked)."""
    import pyotp
    from conftest import make_client, sign_in
    from test_passkeys import Authenticator, passkey_login, register, setup_done

    from app import passkeys_api
    from app.auth import bruteforce

    await setup_done()
    ada = await add_user("ada", "admin", totp_secret=pyotp.random_base32())
    a = Authenticator(counter=10)
    async with make_client() as c:
        await sign_in(c, ada)
        _ok(await register(c, a))
    c, r = await passkey_login(a, ada)
    await c.aclose()
    _ok(r)
    e = (await _entries("login.success"))[-1]
    assert e.actor_id == ada.id and e.ip == "127.0.0.1" and e.details == {"source": "local", "method": "passkey"}
    # a reader's passkey sign-in: not logged
    b = Authenticator()
    _ok(await register(reader_client, b))
    c, r = await passkey_login(b, reader_client.user)
    await c.aclose()
    _ok(r)
    assert await _count("login.success") == 1
    # a clone with an older counter: signed in, warned, logged
    a.counter = 3
    c, r = await passkey_login(a, ada)
    await c.aclose()
    _ok(r)
    (w,) = await _entries("passkey.sign_count_warning")
    assert w.actor_kind == "system" and w.target_id == str(ada.id) and w.target_label == "ada" and w.ip == "127.0.0.1"
    assert w.details == {"name": "Laptop", "stored": 11, "got": 4}
    # refused sign-ins (random credentials): none logged – the block of the address once
    passkeys_api.reset()
    bruteforce.reset()
    before = len(await _entries())
    async with make_client() as c:
        for _ in range(bruteforce.IP_MAX):
            o = (await c.post("/api/auth/passkey/options")).json()
            await c.post("/api/auth/passkey/login", json=Authenticator().assertion(o, reader_client.user.id.bytes))
    rows = (await _entries())[before:]
    assert [x.action for x in rows] == ["login.ip_blocked"] and rows[0].details == {"blocked_for_s": bruteforce.IP_BLOCK, "via": "passkey"} and rows[0].actor_kind == "system"
    # nothing of a key, a credential or a signature anywhere
    raw = json.dumps([(x.target_label, x.details) for x in await _entries()])
    for bad in (webauthn_b64(a.cred_id), "public_key", "signature", "credential"):
        assert bad not in raw, bad


def webauthn_b64(raw: bytes) -> str:
    from app.auth import webauthn

    return webauthn.b64url(raw)


async def test_session_endings_are_logged_with_scope_and_count(admin_client, reader_client):
    for _ in range(2):
        await _session_of(reader_client.user.id)
    r = await reader_client.post("/api/me/sessions/end-others")
    assert r.json()["ended"] == 2
    assert (await reader_client.post("/api/me/sessions/end-others")).json()["ended"] == 0  # nothing ended: nothing logged
    _ok(await admin_client.post(f"/api/admin/users/{reader_client.user.id}/sessions/end-all"))  # the reader's current one
    sid = await _session_of(reader_client.user.id)
    _ok(await admin_client.delete(f"/api/admin/users/{reader_client.user.id}/sessions/{sid}"))
    own, everyone, one = await _entries("sessions.revoked")
    assert own.actor_id == reader_client.user.id and own.target_id == str(reader_client.user.id) and own.ip == "127.0.0.1"
    assert own.details == {"scope": "others", "count": 2, "by_admin": False}
    assert everyone.actor_id == admin_client.user.id and everyone.target_label == "rudi" and everyone.details == {"scope": "all", "count": 1, "by_admin": True}
    assert one.details == {"scope": "one", "count": 1, "by_admin": True}


async def test_resend_is_logged(admin_client, monkeypatch):
    import httpx
    from test_notify import HOOK, Hooks, _channel, _dispatch, _rule, _source, _stories

    from app import notify

    h = Hooks()
    monkeypatch.setattr(notify, "transport", httpx.MockTransport(h.handler))
    src = await _source()
    hook = await _channel(admin_client, name="n8n", type="webhook", url=HOOK)
    await _rule(admin_client, "Alles", [hook["id"]], severities=[])
    await _stories(src, "critical")
    h.queue["n8n.corp.example"] = [httpx.Response(503)]
    assert await _dispatch() == {}
    (d,) = (await admin_client.get("/api/admin/notify/log", params={"outcome": "failed"})).json()["deliveries"]
    assert await _count("delivery.resent") == 0  # the round's own attempts are no admin action
    r = await admin_client.post(f"/api/admin/notify/log/{d['id']}/resend")
    assert r.json() == {"ok": True}
    (e,) = await _entries("delivery.resent")
    assert e.actor_id == admin_client.user.id and e.ip == "127.0.0.1" and e.target_type == "channel" and e.target_id == hook["id"] and e.target_label == "n8n"
    assert e.details == {"ref": d["ref"], "ok": True}
    assert "n8n.corp.example/webhook" not in json.dumps(e.details)
    # refused (already delivered): nothing logged
    assert (await admin_client.post(f"/api/admin/notify/log/{d['id']}/resend")).status_code == 409
    assert await _count("delivery.resent") == 1


async def test_reader_confirmations_are_logged_with_the_reader_as_actor(admin_client, reader_client):
    _ok(await admin_client.put("/api/admin/teams/settings", json={"enabled": True}))
    v = await _version(admin_client)
    t = await _team(admin_client)
    _ok(await admin_client.put(f"/api/admin/teams/{t['id']}/products", json={"products": ["gitlab"]}))
    _ok(await admin_client.put(f"/api/admin/teams/{t['id']}/members/{reader_client.user.id}"))
    _ok(await reader_client.post(f"/api/vendor/versions/{v['id']}/confirm"))
    e = (await _entries("catalog.version_confirmed"))[-1]
    assert e.actor_id == reader_client.user.id and e.target_type == "product" and e.target_id == "gitlab" and e.details == {"version": "17.1.2", "label": "DMZ"}
    _ok(await reader_client.post("/api/vendor/review/confirm", json={"team_id": t["id"], "due_only": False}))
    e = (await _entries("catalog.versions_confirmed"))[-1]
    assert e.actor_id == reader_client.user.id and e.target_type == "team" and e.target_label == "Netzwerk"
    assert e.details == {"count": 1, "due_only": False, "products": ["gitlab"]}
    # nothing due: nothing confirmed, nothing logged
    n = await _count("catalog.versions_confirmed")
    assert (await reader_client.post("/api/vendor/review/confirm", json={"team_id": t["id"]})).json() == {"confirmed": 0}
    assert await _count("catalog.versions_confirmed") == n
    # making a suggestion is not logged; the admin's answer is – cut to 200 characters
    s = await _suggestion(reader_client)
    assert len(await _entries()) == len([x for x in await _entries() if not x.action.startswith("suggestion.")])
    _ok(await admin_client.post(f"/api/admin/suggestions/{s['id']}/reject", json={"answer": "Nein. " * 80}))
    e = (await _entries("suggestion.rejected"))[-1]
    assert e.target_type == "suggestion" and e.target_label == "Example Corp Edge Gateway" and e.details["product_key"] is None
    assert len(e.details["answer"]) == 201 and e.details["answer"].endswith("…")
    # decided already: refused, nothing more logged
    assert (await admin_client.post(f"/api/admin/suggestions/{s['id']}/accept", json={})).status_code == 409
    assert await _count("suggestion.accepted") == 0


async def test_review_interval_is_in_the_vendor_settings_change(admin_client):
    _ok(await admin_client.put("/api/admin/vendor", json={"enabled": True, "every_h": 6, "eol_every_h": 24, "review_days": 180}))
    changes = (await _entries("settings.changed"))[-1].details["changes"]
    assert changes["review_days"]["to"] == 180 and changes["review_days"]["from"] != 180
