"""Admin only: notification channels (where to), rules (what, with their dry run) and the SMTP server. Secrets (webhook
URLs – also Mattermost's –, the Telegram bot token, ntfy's topic and token, the Gotify token, the HMAC secret and auth
header value of a generic webhook, the SMTP password) are encrypted at rest and never
sent back – the browser sees whether one is set (and a URL's host); an empty field keeps it. A secret bound to a target
(HMAC secret, auth header value, SMTP password) has to be entered again when the target changes."""

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter
from pydantic import ConfigDict, Field, field_validator
from sqlalchemy import delete, select, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm.attributes import set_committed_value
from sqlalchemy.orm.exc import StaleDataError

from app import audit, delivery_log, netaddr, notify
from app import news as news_svc
from app import settings as settings_store
from app.crypto import decrypt_str, encrypt_str
from app.deps import Admin, Db, NoNul, api_error
from app.models import NotifyChannel, NotifyRule, NotifyRuleChannel, NotifyRuleTeam, Team

router = APIRouter(prefix="/api/admin/notify", tags=["notify"])
Severity = Literal["critical", "high", "medium", "low", "info"]
Topic = Literal["zeroday", "exploited", "poc", "ransomware", "nopatch", "breach", "supply", "phishing", "ot"]  # news.TOPICS
ChannelType = Literal["email", "teams", "slack", "discord", "telegram", "webhook", "ntfy", "gotify", "mattermost"]
PUSH_TYPES = ("ntfy", "gotify")  # a server address (no secret) and a token / topic (secrets bound to that server)
EMAIL = r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$"
TEST_EVERY = 3.0  # seconds between two tests of the same target
_last_test: dict[str, float] = {}


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _recipients(v: list[str]) -> list[str]:
    import re

    out = list(dict.fromkeys(x.strip().lower() for x in v if x.strip()))
    for x in out:
        if not re.match(EMAIL, x) or len(x) > 254:
            raise ValueError(f"invalid address: {x[:60]}")
    return out


def _throttle(key: str) -> None:
    now = time.monotonic()
    if now - _last_test.get(key, -1e9) < TEST_EVERY:
        raise api_error(429, "rate_limited")
    _last_test[key] = now
    if len(_last_test) > 500:
        _last_test.clear()


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


@asynccontextmanager
async def _change(db):  # noqa: ANN001, ANN202
    """A change of channels or rules, committed at the end – one that met a parallel change (a channel deleted while a
    rule was saved with it, the same rule saved or deleted twice at once) is refused as stale instead of failing with a
    500. The next notification round looks at everything again."""
    try:
        yield
        await db.commit()
    except (IntegrityError, StaleDataError) as exc:
        await db.rollback()
        raise api_error(409, "stale") from exc
    notify.changed()


async def _bump(db, model, row, version: int | None) -> None:  # noqa: ANN001
    """Optimistic concurrency for a channel or rule, as for users: the edit was made on `version`; the counter goes up in
    the same transaction, conditionally – a parallel edit that got there first makes this one stale (409)."""
    have = row.version or 1
    if version is not None and version != have:
        raise api_error(409, "stale")
    res = await db.execute(update(model).where(model.id == row.id, model.version == have).values(version=have + 1).execution_options(synchronize_session=False))
    if res.rowcount != 1:
        await db.rollback()
        raise api_error(409, "stale")
    set_committed_value(row, "version", have + 1)


# ---------------------------------------------------------------- channels


def _host(ch: NotifyChannel) -> str | None:
    """The host of a stored URL – from the target it is bound to (no decrypting), else from the URL itself."""
    if ch.target:
        return urlsplit(ch.target).hostname
    return notify.secret_hint((ch.secrets or {}).get("url"))


def _channel_out(ch: NotifyChannel, rules: list[NotifyRule], health: dict | None = None) -> dict:
    cfg, sec = ch.config or {}, ch.secrets or {}
    webhook = ch.type == "webhook"
    push = ch.type in PUSH_TYPES
    return {
        # ntfy / Gotify: the server's address (no secret); the topic and tokens only whether one is stored
        "server": str(cfg.get("server") or "") if push else "",
        "topic_set": bool(sec.get("topic")),
        "tags": [str(x) for x in cfg.get("tags") or []] if ch.type == "ntfy" else [],
        # the delivery log of the last 24 hours (the badge in the list): last ok, last failure, attempts and failures
        "delivery": health or {"last_ok_at": None, "last_failed_at": None, "attempts_24h": 0, "failed_24h": 0},
        "id": str(ch.id),
        "version": ch.version or 1,  # the state the edit is made on (409 stale when another admin saved in between)
        "name": ch.name,
        "type": ch.type,
        "recipients": list(cfg.get("recipients") or []) if ch.type == "email" else [],
        "chat_id": str(cfg.get("chat_id") or "") if ch.type == "telegram" else "",
        "url_set": bool(sec.get("url")),
        "host": _host(ch) if sec.get("url") or (push and ch.target) else None,
        "token_set": bool(sec.get("token")),
        "allow_http": bool(cfg.get("allow_http")) if webhook else False,
        "use_proxy": bool(cfg.get("use_proxy", True)) if webhook else False,
        "hmac_set": bool(sec.get("hmac")),
        "header_name": str(cfg.get("header_name") or "") if webhook else "",
        "header_set": bool(sec.get("header_value")),
        "rules": [{"id": str(r.id), "name": r.name, "enabled": r.enabled} for r in rules],
        "created_at": ch.created_at.isoformat(),
        "last_sent_at": _iso(ch.last_sent_at),
        "last_error": ch.last_error,
        "last_error_at": _iso(ch.last_error_at),
        "failures": ch.failures,
        "next_try_at": _iso(ch.next_try_at),
    }


# a name goes into mail subjects and chat messages: one line, no control characters
NAME = r"^[^\x00-\x1f\x7f\u2028\u2029]*$"


class ChannelIn(_M):
    name: str = Field(min_length=2, max_length=100, pattern=NAME)
    type: ChannelType
    recipients: list[str] = Field(default_factory=list, max_length=20)  # email
    url: str = Field(default="", max_length=2000)  # teams / slack / discord / webhook – empty on update: keep
    bot_token: str = Field(default="", max_length=100)  # telegram – empty on update: keep
    chat_id: str = Field(default="", max_length=40)  # telegram
    allow_http: bool = False  # webhook
    use_proxy: bool = False  # webhook (only with HTTPS_PROXY); off like the UI form – a stored channel without the key keeps the proxy (see _channel_out)
    hmac_secret: str = Field(default="", max_length=200)  # webhook – empty: keep
    clear_hmac: bool = False
    header_name: str = Field(default="", max_length=64)  # webhook
    header_value: str = Field(default="", max_length=2000)  # webhook – empty: keep
    clear_header: bool = False
    server_url: str = Field(default="", max_length=500)  # ntfy / gotify: the server's address (no secret)
    topic: str = Field(default="", max_length=64)  # ntfy – empty on update: keep
    token: str = Field(default="", max_length=200)  # ntfy (access token, optional) / gotify (application token) – empty: keep
    clear_token: bool = False  # ntfy: no access token any more (a public topic)
    tags: list[str] = Field(default_factory=list, max_length=notify.NTFY_TAGS_MAX)  # ntfy
    version: int | None = None  # update: the state the edit was made on (None: an older client – not checked)

    @field_validator("recipients")
    @classmethod
    def _rcpt(cls, v: list[str]) -> list[str]:
        return _recipients(v)


def _apply_channel(ch: NotifyChannel, body: ChannelIn, *, new: bool) -> None:
    if not new and body.type != ch.type:
        raise api_error(422, "type_fixed")  # another service: a new channel
    secrets = dict(ch.secrets or {})
    cfg: dict = {}
    target = ch.target
    if body.type == "email":
        if not body.recipients:
            raise api_error(422, "recipients_missing")
        cfg, secrets, target = {"recipients": body.recipients}, {}, None
    elif body.type in PUSH_TYPES:
        cfg, secrets, target = _apply_push(ch, body, secrets)
    elif body.type == "telegram":
        if body.bot_token:
            if not notify.TELEGRAM_TOKEN.match(body.bot_token):
                raise api_error(422, "token_invalid")
            secrets["token"] = encrypt_str(body.bot_token)
        elif not secrets.get("token"):
            raise api_error(422, "token_missing")
        if not notify.TELEGRAM_CHAT.match(body.chat_id):
            raise api_error(422, "chat_id_invalid")
        cfg, target = {"chat_id": body.chat_id}, netaddr.target_of(notify.TELEGRAM_API)
        secrets = {"token": secrets["token"]}
    else:
        allow_http = body.allow_http and body.type == "webhook"
        url = body.url
        if not url:
            if not secrets.get("url"):
                raise api_error(422, "url_missing")
            try:
                url = decrypt_str(secrets["url"])
            except Exception as exc:  # noqa: BLE001 - key changed
                raise api_error(422, "url_missing") from exc
        try:
            notify.check_url(body.type, url, allow_http=allow_http)  # also a kept URL: http needs the toggle
        except notify.NotifyError as exc:
            raise api_error(422, f"url_{exc.category}") from exc
        new_target = netaddr.target_of(url)
        if body.type == "webhook":
            name = body.header_name
            if name and (not notify.HEADER_NAME.match(name) or name.lower() in notify.RESERVED_HEADERS or name.lower().startswith("x-cobe-")):
                raise api_error(422, "header_name_invalid")
            moved = bool(ch.target) and new_target != ch.target  # the bound secrets would go somewhere else
            for key, typed, clear in (("hmac", body.hmac_secret, body.clear_hmac), ("header_value", body.header_value, body.clear_header or not name)):
                if clear:
                    secrets.pop(key, None)
                elif typed:
                    if key == "hmac" and len(typed) < 16:
                        raise api_error(422, "hmac_too_short")
                    secrets[key] = encrypt_str(typed)
                elif moved and secrets.get(key):
                    raise api_error(422, "secret_required")
            if name and not secrets.get("header_value"):
                raise api_error(422, "header_value_missing")
            cfg = {"allow_http": allow_http, "use_proxy": body.use_proxy, "header_name": name}
        else:
            secrets = {k: v for k, v in secrets.items() if k == "url"}
        if body.url:
            secrets["url"] = encrypt_str(body.url)
        target = new_target
    ch.name, ch.type, ch.config, ch.secrets, ch.target = body.name, body.type, cfg, secrets, target


def _channel_state(ch: NotifyChannel) -> dict:
    """What the audit log compares of a channel: name, type, the plain settings, the target (scheme://host:port) and each
    secret only by its stored (encrypted) value – audit.diff logs those as "changed", never a value."""
    return {
        "name": ch.name,
        "type": ch.type,
        "target": ch.target,
        **{f"config.{k}": v for k, v in (ch.config or {}).items()},
        **{f"secret.{k}": v for k, v in (ch.secrets or {}).items()},
    }


def _channel_target(ch: NotifyChannel) -> audit.Target:
    return audit.target("channel", ch.id, ch.name)


def _apply_push(ch: NotifyChannel, body: ChannelIn, secrets: dict) -> tuple[dict, dict, str | None]:
    """ntfy / Gotify: the server (https, checked like a webhook URL – public, or WEBHOOK_PRIVATE_NETS), the topic and
    the token encrypted. Topic and token are bound to the server: another server needs them entered again."""
    server = notify.server_base(body.server_url)
    if not server:
        raise api_error(422, "url_missing")
    try:
        notify.check_url(body.type, server)
    except notify.NotifyError as exc:
        raise api_error(422, f"url_{exc.category}") from exc
    new_target = netaddr.target_of(server)
    moved = bool(ch.target) and new_target != ch.target
    keep = {k: v for k, v in secrets.items() if k in ("token", "topic")}
    if body.type == "ntfy":
        if body.topic:
            if not notify.NTFY_TOPIC.match(body.topic):
                raise api_error(422, "topic_invalid")
            keep["topic"] = encrypt_str(body.topic)
        elif not keep.get("topic"):
            raise api_error(422, "topic_missing")
        elif moved:
            raise api_error(422, "secret_required")
    else:
        keep.pop("topic", None)
    if body.token:
        if not notify.PUSH_TOKEN.match(body.token):
            raise api_error(422, "push_token_invalid")
        keep["token"] = encrypt_str(body.token)
    elif body.type == "ntfy" and body.clear_token:
        keep.pop("token", None)
    elif keep.get("token") and moved:
        raise api_error(422, "secret_required")
    if body.type == "gotify" and not keep.get("token"):
        raise api_error(422, "push_token_missing")
    cfg: dict = {"server": server}
    if body.type == "ntfy":
        tags = list(dict.fromkeys(x.strip() for x in body.tags if x.strip()))
        if any(not notify.NTFY_TAG.match(x) for x in tags):
            raise api_error(422, "tags_invalid")
        cfg["tags"] = tags[: notify.NTFY_TAGS_MAX]
    return cfg, keep, new_target


async def _rules_of(db, channel_ids: list[uuid.UUID] | None = None) -> dict[uuid.UUID, list[NotifyRule]]:
    stmt = select(NotifyRuleChannel.channel_id, NotifyRule).join(NotifyRule, NotifyRule.id == NotifyRuleChannel.rule_id).order_by(NotifyRule.name)
    if channel_ids is not None:
        stmt = stmt.where(NotifyRuleChannel.channel_id.in_(channel_ids))
    out: dict[uuid.UUID, list[NotifyRule]] = {}
    for cid, rule in (await db.execute(stmt)).all():
        out.setdefault(cid, []).append(rule)
    return out


async def _channel(db, cid: uuid.UUID) -> NotifyChannel:
    ch = await db.get(NotifyChannel, cid)
    if ch is None:
        raise api_error(404, "not_found")
    return ch


@router.get("/channels")
async def channels(admin: Admin, db: Db) -> list[dict]:
    rows = list(await db.scalars(select(NotifyChannel).order_by(NotifyChannel.name, NotifyChannel.id)))
    used = await _rules_of(db)
    health = await delivery_log.health(db)
    return [_channel_out(c, used.get(c.id, []), health.get(c.id)) for c in rows]


@router.post("/channels")
async def add_channel(body: ChannelIn, admin: Admin, db: Db) -> dict:
    ch = NotifyChannel(id=uuid.uuid4(), failures=0, config={}, secrets={})
    async with _change(db):
        _apply_channel(ch, body, new=True)
        db.add(ch)
        audit.record(db, admin, "channel.created", _channel_target(ch), {"type": ch.type, "changes": audit.diff({}, _channel_state(ch))})
    return _channel_out(ch, [])


@router.put("/channels/{cid}")
async def update_channel(cid: uuid.UUID, body: ChannelIn, admin: Admin, db: Db) -> dict:
    ch = await _channel(db, cid)
    await _bump(db, NotifyChannel, ch, body.version)
    async with _change(db):
        before = (ch.config, ch.secrets, ch.target)
        state = _channel_state(ch)
        _apply_channel(ch, body, new=False)
        if changes := audit.diff(state, _channel_state(ch)):
            audit.record(db, admin, "channel.changed", _channel_target(ch), {"type": ch.type, "changes": changes})
        if (ch.config, ch.secrets, ch.target) != before:
            # set up anew: the next round tries it right away, the old target's error is not shown on it
            ch.failures, ch.next_try_at, ch.last_error = 0, None, None
    return _channel_out(ch, (await _rules_of(db, [ch.id])).get(ch.id, []), (await delivery_log.health(db, [ch.id])).get(ch.id))


@router.delete("/channels/{cid}")
async def delete_channel(cid: uuid.UUID, admin: Admin, db: Db) -> dict:
    ch = await _channel(db, cid)
    async with _change(db):
        audit.record(db, admin, "channel.deleted", _channel_target(ch), {"type": ch.type})
        await db.delete(ch)  # links and sent marks go with it (ON DELETE CASCADE)
    return {"ok": True}


class TestIn(_M):
    lang: Literal["de", "en"] = "de"


@router.post("/channels/{cid}/test")
async def test_channel(cid: uuid.UUID, admin: Admin, db: Db, body: TestIn | None = None) -> dict:
    """A test message right now (the newest story, marked as test) – nothing is marked as sent, the backoff stays."""
    ch = await _channel(db, cid)
    _throttle(f"channel:{ch.id}")
    try:
        await notify.send_test(db, ch, (body or TestIn()).lang)
    except notify.NotifyError as exc:
        return {"ok": False, "error": exc.category, "detail": exc.detail}
    return {"ok": True}


# ---------------------------------------------------------------- rules


async def _teams_of(db, rule_id: uuid.UUID) -> list[uuid.UUID]:
    return list(await db.scalars(select(NotifyRuleTeam.team_id).where(NotifyRuleTeam.rule_id == rule_id)))


def _rule_out(r: NotifyRule, channel_ids: list[uuid.UUID], team_ids: list[uuid.UUID] | None = None) -> dict:
    return {
        "teams": sorted(str(t) for t in team_ids or []),
        "id": str(r.id),
        "version": r.version or 1,
        "name": r.name,
        "enabled": r.enabled,
        "channels": [str(c) for c in channel_ids],
        "severities": list(r.severities or []),
        "sources": list(r.sources or []),
        "topics": notify.rule_topics(r),
        "lang": r.lang,
        "kinds": notify.rule_kinds(r),
        "created_at": r.created_at.isoformat(),
        "active_since": r.active_since.isoformat(),
    }


class RuleIn(_M):
    name: str = Field(min_length=2, max_length=100, pattern=NAME)
    enabled: bool = True
    channels: list[uuid.UUID] = Field(default_factory=list, max_length=20)
    severities: list[Severity] = Field(default_factory=lambda: ["critical", "high"], max_length=5)
    sources: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    # news only: stories with one of these topics (OR; AND with severities and sources) – empty: any story; None (not
    # sent – a client from before topics): an existing rule keeps its topics, a new one has none
    topics: list[Topic] | None = Field(default=None, max_length=9)
    lang: Literal["de", "en"] = "de"
    # news: stories of the feed; vendor_vuln: a vulnerability affects a followed product; vendor_version: newer
    # version in its line, EOL coming or reached; vendor_change: an advisory of a followed product was revised (a new
    # fixed version, another severity, KEV, withdrawn – app/advisory_changes.py); source_health: a source became
    # disturbed or dead, or is back
    kinds: list[Literal["news", "vendor_vuln", "vendor_version", "vendor_change", "source_health"]] = Field(default_factory=lambda: ["news"], min_length=1, max_length=5)
    # Teams: the Vendor News events of these teams' products only (empty: all products); news and source health stay
    teams: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    version: int | None = None  # update: the state the edit was made on (409 stale otherwise)


async def _links(db, rule_id: uuid.UUID) -> list[uuid.UUID]:
    stmt = select(NotifyRuleChannel.channel_id).join(NotifyChannel, NotifyChannel.id == NotifyRuleChannel.channel_id).where(NotifyRuleChannel.rule_id == rule_id).order_by(NotifyChannel.name)
    return list(await db.scalars(stmt))


async def _apply_rule(db, rule: NotifyRule, body: RuleIn, *, new: bool) -> list[uuid.UUID]:
    wanted = list(dict.fromkeys(body.channels))
    if not wanted:
        raise api_error(422, "channels_missing")
    found = set(await db.scalars(select(NotifyChannel.id).where(NotifyChannel.id.in_(wanted))))
    if len(found) != len(wanted):
        raise api_error(422, "channel_not_found")
    was_on = bool(rule.enabled) and not new
    had_teams = [] if new else await _teams_of(db, rule.id)
    want_teams = list(dict.fromkeys(body.teams))
    if set(want_teams) != set(had_teams):
        if want_teams and set(want_teams) - set(had_teams):
            from app import teams

            if not await teams.is_on(db):
                raise api_error(409, "teams_off")
        if len(set(await db.scalars(select(Team.id).where(Team.id.in_(want_teams))))) != len(want_teams):
            raise api_error(422, "team_not_found")
    before = notify.rule_filter(rule, had_teams)
    rule.name, rule.lang = body.name, body.lang
    rule.severities, rule.sources = list(body.severities), [str(x) for x in body.sources]
    if body.topics is not None or new:
        rule.topics = [t for t in news_svc.TOPICS if t in (body.topics or [])]
    rule.kinds = list(dict.fromkeys(body.kinds))
    rule.enabled = body.enabled
    now = datetime.now(UTC)
    if body.enabled and not was_on:
        rule.active_since = now  # switched on (or new): from now on – not the stories that came while it was off
        rule.earlier = []
    elif body.enabled and notify.widens(before, notify.rule_filter(rule, want_teams)):
        # widened: what newly matches counts from now on (the current arrival number) – what matched before still comes
        notify.widened(rule, before, await news_svc.last_seq(db), now)
    if new:
        db.add(rule)
        await db.flush()
        have: set[uuid.UUID] = set()
    else:
        have = set(await db.scalars(select(NotifyRuleChannel.channel_id).where(NotifyRuleChannel.rule_id == rule.id)))
        gone = have - set(wanted)
        if gone:
            await db.execute(delete(NotifyRuleChannel).where(NotifyRuleChannel.rule_id == rule.id, NotifyRuleChannel.channel_id.in_(gone)))
    for cid in wanted:
        if cid not in have:  # a channel added to the rule: from now on, too
            db.add(NotifyRuleChannel(rule_id=rule.id, channel_id=cid, added_at=now))
    if set(want_teams) != set(had_teams):
        await db.execute(delete(NotifyRuleTeam).where(NotifyRuleTeam.rule_id == rule.id))
        for tid in want_teams:
            db.add(NotifyRuleTeam(rule_id=rule.id, team_id=tid))
    return wanted


async def _rule_state(db, r: NotifyRule) -> dict:  # noqa: ANN001
    """What the audit log compares of a rule – channels, teams and sources by their names (ids where one is gone)."""
    from app.models import NewsSource

    chans = dict((await db.execute(select(NotifyChannel.id, NotifyChannel.name).join(NotifyRuleChannel, NotifyRuleChannel.channel_id == NotifyChannel.id).where(NotifyRuleChannel.rule_id == r.id))).all()) if r.id else {}
    teams = dict((await db.execute(select(Team.id, Team.name).join(NotifyRuleTeam, NotifyRuleTeam.team_id == Team.id).where(NotifyRuleTeam.rule_id == r.id))).all()) if r.id else {}
    ids = [uuid.UUID(x) for x in r.sources or [] if len(x) == 36]
    names = {str(i): n for i, n in (await db.execute(select(NewsSource.id, NewsSource.name).where(NewsSource.id.in_(ids)))).all()} if ids else {}
    return {
        "name": r.name,
        "enabled": r.enabled,
        "kinds": list(r.kinds or []),
        "severities": list(r.severities or []),
        "sources": sorted(names.get(x, x) for x in r.sources or []),
        "topics": notify.rule_topics(r),
        "lang": r.lang,
        "channels": sorted(chans.values(), key=str.lower),
        "teams": sorted(teams.values(), key=str.lower),
    }


class DryRunIn(_M):
    """A rule as it is being edited (not stored) – the fields that decide what it brings – and the window."""

    severities: list[Severity] = Field(default_factory=list, max_length=5)
    sources: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    topics: list[Topic] = Field(default_factory=list, max_length=9)
    lang: Literal["de", "en"] = "de"
    kinds: list[Literal["news", "vendor_vuln", "vendor_version", "vendor_change", "source_health"]] = Field(min_length=1, max_length=5)
    teams: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    days: Literal[1, 7, 30] = 7


_dry_lock = asyncio.Lock()
DRY_EVERY = 1.0  # seconds between two dry runs of one admin (switching 1 / 7 / 30 days stays quick)
_dry_at: dict[uuid.UUID, float] = {}


@router.post("/rules/dry-run")
async def dry_run(body: DryRunIn, admin: Admin, db: Db) -> dict:
    """Probelauf: what this rule would have brought in the last 1 / 7 / 30 days – nothing sent, nothing written
    (notify.dry_run: read-only, each query bounded). One dry run at a time, at most one per admin every few seconds."""
    now = time.monotonic()
    if now - _dry_at.get(admin.id, -1e9) < DRY_EVERY or _dry_lock.locked():
        raise api_error(429, "rate_limited")
    _dry_at[admin.id] = now
    if len(_dry_at) > 500:
        _dry_at.clear()
    rule = NotifyRule(
        name="dry run",
        severities=list(body.severities),
        sources=[str(x) for x in body.sources],
        topics=[t for t in news_svc.TOPICS if t in body.topics],
        kinds=list(dict.fromkeys(body.kinds)),
        lang=body.lang,
        earlier=[],
    )
    async with _dry_lock:
        try:
            return await notify.dry_run(db, rule, list(dict.fromkeys(body.teams)), body.days)
        except DBAPIError as exc:  # the statement timeout: too much to look at in this window
            raise api_error(503, "dry_run_timeout") from exc


@router.get("/rules")
async def rules(admin: Admin, db: Db) -> list[dict]:
    out = []
    for r in await db.scalars(select(NotifyRule).order_by(NotifyRule.name)):
        out.append(_rule_out(r, await _links(db, r.id), await _teams_of(db, r.id)))
    return out


@router.post("/rules")
async def add_rule(body: RuleIn, admin: Admin, db: Db) -> dict:
    r = NotifyRule(enabled=False, earlier=[])
    async with _change(db):
        await _apply_rule(db, r, body, new=True)
        await db.flush()
        audit.record(db, admin, "rule.created", audit.target("rule", r.id, r.name), {"changes": audit.diff({}, await _rule_state(db, r))})
    return _rule_out(r, await _links(db, r.id), await _teams_of(db, r.id))


async def _rule(db, rid: uuid.UUID) -> NotifyRule:
    r = await db.get(NotifyRule, rid)
    if r is None:
        raise api_error(404, "not_found")
    return r


@router.put("/rules/{rid}")
async def update_rule(rid: uuid.UUID, body: RuleIn, admin: Admin, db: Db) -> dict:
    r = await _rule(db, rid)
    await _bump(db, NotifyRule, r, body.version)
    async with _change(db):
        state = await _rule_state(db, r)
        await _apply_rule(db, r, body, new=False)
        await db.flush()
        if changes := audit.diff(state, await _rule_state(db, r)):
            audit.record(db, admin, "rule.changed", audit.target("rule", r.id, r.name), {"changes": changes})
    return _rule_out(r, await _links(db, r.id), await _teams_of(db, r.id))


@router.delete("/rules/{rid}")
async def delete_rule(rid: uuid.UUID, admin: Admin, db: Db) -> dict:
    r = await _rule(db, rid)
    async with _change(db):
        audit.record(db, admin, "rule.deleted", audit.target("rule", r.id, r.name))
        await db.delete(r)
    return {"ok": True}


# ---------------------------------------------------------------- SMTP


def _smtp_out(cfg: dict) -> dict:
    out = {k: v for k, v in cfg.items() if k != "password_enc"}
    out["password_set"] = bool(cfg.get("password_enc"))
    out["rev"] = int(cfg.get("rev") or 0)  # the saved state (409 stale when another admin saved in between)
    return out


class SmtpIn(_M):
    host: str = Field(default="", max_length=255, pattern=r"^[A-Za-z0-9.\-:\[\]]*$")
    port: int = Field(default=587, ge=1, le=65535)
    encryption: Literal["starttls", "tls", "none"] = "starttls"
    verify_cert: bool = True
    username: str = Field(default="", max_length=255)
    password: str = Field(default="", max_length=500)  # empty: keep the stored one
    clear_password: bool = False
    from_addr: str = Field(default="", max_length=255, pattern=rf"({EMAIL})|^$")
    from_name: str = Field(default="Cobe News", max_length=100, pattern=r"^[^\r\n<>\"]*$")
    rev: int | None = None  # the state the form was loaded with


# the stored password goes only to the server, port, account and TLS settings it was entered for
SMTP_SECRET_BOUND = ("host", "port", "encryption", "verify_cert", "username")


def _smtp_value(body: SmtpIn, current: dict) -> dict:
    data = body.model_dump(exclude={"rev"})
    pw, clear = data.pop("password"), data.pop("clear_password")
    if not pw and not clear and current.get("password_enc") and any(data[k] != current.get(k) for k in SMTP_SECRET_BOUND):
        raise api_error(422, "secret_required")  # enter it again – it would otherwise go to a new server
    data["password_enc"] = "" if clear else encrypt_str(pw) if pw else current.get("password_enc", "")
    return data


@router.get("/smtp")
async def get_smtp(admin: Admin, db: Db) -> dict:
    return _smtp_out(await settings_store.get(db, "smtp"))


@router.put("/smtp")
async def put_smtp(body: SmtpIn, admin: Admin, db: Db) -> dict:
    current = await settings_store.get(db, "smtp")
    value = _smtp_value(body, current)
    if changes := audit.diff(current, value, value.keys()):
        audit.record(db, admin, "settings.changed", audit.target("settings", "smtp", "smtp"), {"changes": changes})
    out = await settings_store.put_rev(db, "smtp", value, body.rev)
    # the e-mail channels start afresh with the new server: no pause, no error of the old one – tried in the next round
    await db.execute(
        update(NotifyChannel).where(NotifyChannel.type == "email").values(failures=0, next_try_at=None, last_error=None, last_error_at=None).execution_options(synchronize_session=False)
    )
    await db.commit()
    notify.changed()
    return _smtp_out(out)


class SmtpTestIn(SmtpIn):
    to: str = Field(max_length=254, pattern=EMAIL)
    lang: Literal["de", "en"] = "de"


@router.post("/smtp/test")
async def test_smtp(body: SmtpTestIn, admin: Admin, db: Db) -> dict:
    """A test mail with the form as it is (not saved yet; the stored password when none was typed)."""
    _throttle("smtp")
    data = _smtp_value(SmtpIn.model_validate(body.model_dump(exclude={"to", "lang"})), await settings_store.get(db, "smtp"))
    subject, text, html = notify.render_mail("SMTP-Test", [notify.EXAMPLE], 1, body.lang, test=True)
    try:
        await notify.send_mail(data, [body.to], subject, text, html)
    except notify.NotifyError as exc:
        return {"ok": False, "error": exc.category, "detail": exc.detail}
    return {"ok": True}
