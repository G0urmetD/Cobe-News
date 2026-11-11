"""NewsSource / NewsItem / NewsRead (PostgreSQL: uuid, timestamptz, JSONB; text columns – the lengths are kept
by the API and the code, as they were with SQLite, which never enforced them), plus the
accounts (users, server-side sessions, directory group → role mappings), the notification channels and rules and a
key/value table for the settings."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, Float, ForeignKey, Identity, Index, Integer, LargeBinary, SmallInteger, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, Json, UTCDateTime, utcnow
from app.db import SafeText as Text  # every text column drops U+0000 (PostgreSQL refuses it)


class NewsSource(Base):
    """A security news feed (RSS/Atom): built in (key = its name) or added in the settings (key = custom-<uuid>)."""

    __tablename__ = "news_sources"
    # one source per address among those admins add (migration 0005) – built-in ones follow the code's address
    __table_args__ = (Index("ux_news_sources_url", "url", unique=True, postgresql_where=text("NOT builtin")),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(Text, unique=True)
    name: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text)
    site: Mapped[str] = mapped_column(Text, default="")  # home page – where the logo comes from
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # when an admin last switched it on or off (None: never – a built-in source then follows the code's default when
    # that changes, see news.DEFAULT_CHANGED)
    switched_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    etag: Mapped[str | None] = mapped_column(Text)
    last_modified: Mapped[str | None] = mapped_column(Text)
    last_fetch_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_ok_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    next_fetch_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    logo: Mapped[bytes | None] = mapped_column(LargeBinary)
    logo_type: Mapped[str | None] = mapped_column(Text)
    logo_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # when its first fetch was stored (None: never, or switched on again / new address since) – until then its stories
    # without a date of their own are backlog: nothing tells how old they are
    primed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # when the last fetch began whose answer was read and stored (HTTP 200 – not a 304, not a failure): what the feed
    # listed then got its stories' `seen_at` after this time. An undated story whose seen_at is older was not listed
    # any more – only such a story may go with the retention (news.prune); None: never read since migration 0031
    parsed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


def _arrived_as_backlog(ctx) -> bool:  # noqa: ANN001
    """The default of NewsItem.backlog for a row stored without it (news.store() decides it itself): by its dates."""
    from datetime import UTC

    from app.news import _backlog

    p = ctx.get_current_parameters()
    pub, fetched = p.get("published_at"), p.get("fetched_at") or utcnow()
    if not isinstance(pub, datetime):
        return False
    aware = [(d if d.tzinfo else d.replace(tzinfo=UTC)) for d in (pub, fetched)]
    return _backlog(aware[0], aware[1], undated=False, primed=True)


class NewsItem(Base):
    """One article, once – the same story from a second feed (same URL or title within days) only adds `also_in`."""

    __tablename__ = "news_items"
    __table_args__ = (
        Index("ix_news_items_published", "published_at", "id"),
        Index("ix_news_items_title_key", "title_key"),
        Index("ix_news_items_fetched", "fetched_at"),  # /news/recent and the notification rules
        # the list's counts (and a source filter) read only this index, not the stories (50k: 66 → 24 ms)
        Index("ix_news_items_source", "source_id", "id"),
        # the search (LIKE '%…%' on the folded text): trigrams instead of reading every story (migration 0002)
        Index("ix_news_items_search_trgm", "search", postgresql_using="gin", postgresql_ops={"search": "gin_trgm_ops"}),
        # the topic filter (topics ?| …) and "which stories name these CVEs" (KEV changes, a new KEV story) – migration 0024
        Index("ix_news_items_topics", "topics", postgresql_using="gin"),
        # "Betrifft unsere Produkte" (products ?| the followed ones) – migration 0026
        Index("ix_news_items_products", "products", postgresql_using="gin"),
        Index("ix_news_items_cves", "cves", postgresql_using="gin"),
        # the notification rules' "Systeme" (systems ?| the entries a rule's systems stand for) – migration 0039
        Index("ix_news_items_systems", "systems", postgresql_using="gin"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("news_sources.id", ondelete="CASCADE"))
    url: Mapped[str] = mapped_column(Text)
    url_key: Mapped[str] = mapped_column(Text, unique=True)
    title: Mapped[str] = mapped_column(Text)
    title_key: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text, default="")
    content_html: Mapped[str] = mapped_column(Text, default="")
    published_at: Mapped[datetime] = mapped_column(UTCDateTime)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    severity: Mapped[str] = mapped_column(Text, default="info")  # critical | high | medium | low | info
    reasons: Mapped[list] = mapped_column(Json, default=list)  # why: [{"kind": "cvss", "value": "9.8"}, …]
    cves: Mapped[list] = mapped_column(Json, default=list)
    also_in: Mapped[list] = mapped_column(Json, default=list)  # names of further sources with the same story (by id: NewsItemSource)
    # a story without a date of its own (dated by when it was first seen): when its feed last listed it – it stays past
    # the retention while listed (deleted, it would come back as new with the next fetch)
    seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # arrived as backlog: listed, never notified (rules, desktop, Web Push) – older than a day when it arrived (a date
    # without a time counts to the end of that day), or undated in a source's first fetch (news._backlog)
    backlog: Mapped[bool] = mapped_column(Boolean, default=_arrived_as_backlog)
    # title, summary and CVEs folded once when stored (db.fold) – the search is a plain LIKE (trigram index), no function per row
    search: Mapped[str] = mapped_column(Text, default="")
    # arrival order (counters "news_seq", taken in the transaction that stores the story): the counter's row stays locked
    # until that transaction ends, so the next number goes to a transaction that commits later – whatever a reader sees
    # up to a number is complete. The cursor of desktop and push notifications (a time cursor skipped stories stored in
    # a transaction that began before a poll and ended after it; a Postgres sequence would hand numbers out of order)
    seq: Mapped[int | None] = mapped_column(Integer, index=True)
    # the story's topics (news.topics_of: zeroday, exploited, ransomware, nopatch, breach, supply, phishing, ot) – from
    # title, stored teaser, source, CVEs, details and the KEV; recomputed when any of them changes (news.retopic)
    topics: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    # those of its topics the story gained quietly – by a full recompute (news.backfill_topics: a new rule version, an
    # exploit list's first import or switched on) or through a list's baseline entries only: shown and filtered like
    # any, never a reason for a notification rule to send it (news.loud_topic) – an old story is no news because a list
    # was switched on. A topic lost is no longer quiet.
    quiet_topics: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    # the followed products (catalogue keys) the story's details concern – story_details.matches, as the drawer's
    # "Betrifft deine Systeme": from the advisory's structured data, never from words. Recomputed when the details arrive
    # and when a follow or its versions change (story_details.products_round); "Betrifft unsere Produkte" on News
    products: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    # what a notification rule matches by, changed loudly after the story arrived – per dimension, so that a rule widened
    # before judges the story by the dimension that changed, never by an unrelated one (notify._earlier_news, news.touched):
    # {"sev": [[at, rating before], …] (each rise), "text": [[at, search text before], …] (title or teaser changed, the
    # last TEXTS_KEPT), "topics": {topic: at}, "systems": {entry: at}} (gained loudly). Empty: unchanged since it arrived
    changes: Mapped[dict] = mapped_column(Json, default=dict, server_default=text("'{}'::jsonb"))
    # the catalogue systems the story concerns – for the notification rules' "Systeme" (app/systems.py), from the WHOLE
    # catalogue, not only the followed products: a catalogue key ("panos") when the details concern that product (the
    # same matcher as `products`, without versions), "m:<key>" when its title or teaser names the product, "v:<vendor
    # id>" when they name the vendor. Computed when the story is stored or its title or teaser changes (mentions), when
    # its details arrive (keys) and for the products whose catalogue entry changed (systems.systems_round)
    systems: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    # those of its systems the story gained quietly – by a recompute after a catalogue change or the first backfill,
    # or from details that did not change: matched and shown, never a reason for a rule to send it (systems.loud) –
    # an older story is no news because the catalogue learned a product name. One lost is no longer quiet.
    quiet_systems: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))


class NewsItemSource(Base):
    """A further source that carries a story ("also in", by id): the story counts for it too – source filters (list,
    rules, desktop, Web Push), visible while any of its sources is switched on, counted per source (news.visible /
    news.carried). A table, not a JSON list: the filters ask "which stories does source X carry" through the index;
    deleting a source or a story takes its rows along (ON DELETE CASCADE)."""

    __tablename__ = "news_item_sources"

    item_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("news_items.id", ondelete="CASCADE"), primary_key=True)
    source_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("news_sources.id", ondelete="CASCADE"), primary_key=True, index=True)
    # the order the further sources came in (SQLite's rowid up to 0.1.15): the first of them takes the story over when
    # its own source is deleted (api.forget_source)
    n: Mapped[int] = mapped_column(BigInteger, Identity(), unique=True)
    # the carry was fresh – the further source listed the story within news.BACKLOG_DAYS of its own date (news._backlog,
    # decided once, when the carry is noted): only a fresh carry counts for the notification rules ("also in" of a source
    # switched on later lists up to 200 older stories at once – no summary of them). The list counts every carry.
    fresh: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    # when a fresh carry was noted (empty: before 0.1.53, or no fresh one) – a rule widened by this source judges an older
    # story by it only when it came after the widening (notify._earlier_news)
    carried_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class Counter(Base):
    """A number that only grows (news_seq: the last story's `seq`) – deleting the newest stories never hands a number out twice."""

    __tablename__ = "counters"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[int] = mapped_column(BigInteger, default=0)


class NewsRead(Base):
    """Read per person – one person's "read" leaves the story new for everybody else. Sparse (app/reader.py, migration 0021):
    a row only where the person's watermark (reader_state) and the age rule do not decide already – a story read after
    the watermark, or one marked unread again (`unread`) below it or older than reader.AUTO_READ."""

    __tablename__ = "news_reads"
    __table_args__ = (Index("ix_news_reads_user_read", "user_id", "read_at"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    item_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("news_items.id", ondelete="CASCADE"), primary_key=True, index=True)
    read_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # "Als ungelesen markieren": unread although the watermark or the age would say read (the person's explicit choice)
    unread: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))


class User(Base):
    """An account: local (password + TOTP), or from AD/LDAP or Entra ID (role from the group mapping at every sign-in).
    Two roles only: admin (settings, sources, rules, users, sign-in) and reader (news, read marks, own preferences).
    `is_emergency`: the local admin of the setup – no directory sync, no admin can disable, demote or delete it."""

    __tablename__ = "users"
    __table_args__ = (Index("ix_users_source_external", "auth_source", "external_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(Text, unique=True)
    display_name: Mapped[str] = mapped_column(Text, default="")
    email: Mapped[str | None] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text, default="reader")  # admin | reader
    auth_source: Mapped[str] = mapped_column(Text, default="local")  # local | ldap | entra
    external_id: Mapped[str | None] = mapped_column(Text)  # objectGUID (AD) / object id (Entra)
    password_hash: Mapped[str | None] = mapped_column(Text)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    # when the temporary password was issued (admin, CLI reset-emergency): valid for `temp_password_days` (settings
    # section "sessions") – a sign-in with it after that is refused (auth_api.temp_password_expired)
    temp_password_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    totp_secret_enc: Mapped[str | None] = mapped_column(Text)
    totp_last_step: Mapped[int | None] = mapped_column(Integer)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # admin | sync:<why> | pending – waits for an admin's approval (directory accounts while "Automatische Anmeldung über
    # AD/Entra ID zulassen" is off, app/auth/directory.py): only an admin's approval switches it on, never the directory
    deactivated_reason: Mapped[str | None] = mapped_column(Text)
    is_emergency: Mapped[bool] = mapped_column(Boolean, default=False)
    desktop: Mapped[dict] = mapped_column(Json, default=dict)  # desktop notifications: {enabled, severities, sources}
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_login_ip: Mapped[str | None] = mapped_column(Text)
    # optimistic concurrency of admin edits (role, active, reset): an edit made on an older state is refused (409 stale)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    # directory accounts: their groups that were mapped to a role or bound to a team at the last sign-in or sync (lower
    # case) – what the instant re-check after a removed mapping reads (directory.reassess_mapping); None: not known yet
    role_groups: Mapped[list | None] = mapped_column(Json)
    # a directory account's raise to admin that waits for an admin's approval ("admin": the groups give admin, the account
    # stays reader until approved) or that an admin declined ("declined": stays reader until it leaves the admin groups)
    # – None: nothing waits. Lowering a role is never held back (migration 0037)
    pending_role: Mapped[str | None] = mapped_column(Text)


class UserSession(Base):
    """Server-side session: the browser holds a random token, the table its keyed hash. Stages before "active":
    mfa (code asked), enroll (an admin sets up TOTP), password (a temporary password is replaced)."""

    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    stage: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    ip: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)
    pending: Mapped[dict] = mapped_column(Json, default=dict)
    reauth_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # last proof of identity (sign-in or re-confirmation)
    # how it was signed in (shown under "Meine Sitzungen"): password | password_totp | ldap | ldap_totp | passkey | entra |
    # entra_totp | password_device | ldap_device | entra_device (the TOTP step skipped on a remembered device)
    # – None: a session of an older version
    method: Mapped[str | None] = mapped_column(Text)
    # signed in with this passkey: removing the passkey ends the session (app/passkeys_api.py)
    passkey_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("user_passkeys.id", ondelete="SET NULL"), index=True)


class UserPasskey(Base):
    """A passkey (WebAuthn credential) of a local account (app/passkeys_api.py, app/auth/webauthn.py): only what the
    checks need – the credential id, the public key as the authenticator sent it (COSE_Key), its signature counter and
    transports – plus a name and the times. No private key ever reaches the server; a backup holds only public keys."""

    __tablename__ = "user_passkeys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(Text)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0)  # the authenticator's counter (uint32)
    transports: Mapped[list] = mapped_column(Json, default=list)  # usb | nfc | ble | internal | hybrid | smart-card
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # the counter went back (or stood still) although it counts: maybe a cloned authenticator – shown as a warning
    sign_count_warning_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class RememberedDevice(Base):
    """"Auf diesem Gerät merken" (app/auth/devices.py): a browser that may skip the TOTP step after the right password.
    The browser holds a random token in its own cookie, the table its keyed hash – plus `factor`, a keyed fingerprint of
    the account's password, TOTP secret and role when it was remembered: any change of them makes the row worthless."""

    __tablename__ = "remembered_devices"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    factor: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    ip: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)


class PasswordHistory(Base):
    """The earlier passwords of a local account (argon2 hashes – secrets like password_hash, never logged, never sent):
    a new password may be none of the last passwords.HISTORY ones (the current one and those kept here). Only passwords
    the person chose – an admin's temporary password never lands here. Bounded: the newest passwords.HISTORY - 1 per
    account are kept (app/auth/passwords.remember)."""

    __tablename__ = "password_history"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AuthLock(Base):
    """An active brute-force lock of an account or block of an address (app/auth/lock_store.py): the counters stay in
    the app's memory, the locks they set survive a restart. `key`: "acct:<lock key>" or "ip:<source key>"; `strikes`:
    the account's locks in a row (the doubling). Expired rows go hourly, at most lock_store.MAX_ROWS are kept."""

    __tablename__ = "auth_locks"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    until: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    strikes: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class GroupMapping(Base):
    """A directory group gives a role: AD by the group's full DN, Entra by its object id. No mapped group – no access."""

    __tablename__ = "group_mappings"
    __table_args__ = (Index("ux_group_mappings", "source", "group_id", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(Text)  # ldap | entra
    group_id: Mapped[str] = mapped_column(Text)
    group_name: Mapped[str] = mapped_column(Text, default="")
    role: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class NotifyChannel(Base):
    """Where notifications go: e-mail recipients (through the SMTP server of the settings), a Teams / Slack / Discord
    webhook, a Telegram bot + chat, or a generic HTTP webhook. Secrets (webhook URLs, the bot token, the HMAC secret,
    an auth header value) are encrypted in `secrets` ({name: "v1:…"}) and never sent to the browser. Each channel has
    its own backoff and last error – one failing channel never holds back the others."""

    __tablename__ = "notify_channels"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(Text)  # email | teams | slack | discord | telegram | webhook
    # not secret: recipients (email), chat_id (telegram), allow_http / use_proxy / header_name (webhook)
    config: Mapped[dict] = mapped_column(Json, default=dict)
    secrets: Mapped[dict] = mapped_column(Json, default=dict)  # url | token | hmac | header_value → encrypted
    # scheme://host:port the secrets were entered for: a URL to another target needs them entered again
    target: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_error_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    next_try_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # counted up with every edit by an admin (not by the delivery state): an edit made on an older one is refused (409)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class NotifyRule(Base):
    """What is sent: stories of these severities and sources (empty = all) in this language, to the linked channels.
    Only stories that arrive after `active_since` (created or switched on) – no flood of the backlog."""

    __tablename__ = "notify_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severities: Mapped[list] = mapped_column(Json, default=list)
    sources: Mapped[list] = mapped_column(Json, default=list)
    lang: Mapped[str] = mapped_column(Text, default="de")
    # what the rule sends: news (stories), vendor_vuln (a vulnerability affects a followed product), vendor_version
    # (newer version in the line, EOL coming or reached)
    kinds: Mapped[list] = mapped_column(Json, default=lambda: ["news"])
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    active_since: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # the arrival number (news.last_seq) when it was switched on: stories after it count – a time misses those of a fetch
    # under way (fetched_at is set when the fetch begins, the story becomes visible when it commits). Empty (rules from
    # before 0.1.53): active_since decides
    active_seq: Mapped[int | None] = mapped_column(BigInteger)
    # the filters before each widening (more severities, sources or kinds): [{"seq", "at", "severities", "sources",
    # "kinds"}] – a story up to `seq` (a Vendor News event up to `at`) is sent only when it matched that filter as well,
    # so a wider rule starts from then instead of sending everything older that newly matches (notify.widened)
    earlier: Mapped[list] = mapped_column(Json, default=list)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")  # optimistic concurrency, as channels
    # news only: stories with one of these topics (news.TOPICS; empty = any) – AND with severities and sources
    topics: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    # "Betrifft": catalogue systems – [{"vendor": "Palo Alto Networks"}] (every product of that vendor, also one the
    # catalogue adds later) or [{"product": "panos"}] – and own words (Schlagwörter, news only); a story matches one of
    # either (OR), AND with the rest. Both empty: no restriction. Systems apply to Vendor News events as well (their
    # product); an entry the catalogue no longer knows stands for nothing, never for "all" (app/systems.py)
    systems: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    keywords: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    # "Nicht senden, wenn enthalten": a story whose title or teaser has one of these words never comes by this rule
    # (news only)
    exclude: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))


class NotifyRuleChannel(Base):
    """A rule sends to a channel – from `added_at` on (a channel added to an old rule gets no backlog either)."""

    __tablename__ = "notify_rule_channels"

    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notify_rules.id", ondelete="CASCADE"), primary_key=True)
    channel_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notify_channels.id", ondelete="CASCADE"), primary_key=True, index=True)
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    added_seq: Mapped[int | None] = mapped_column(BigInteger)  # the arrival number then (as NotifyRule.active_seq)


class NotifyDelivery(Base):
    """Each story at most once per channel – also when several rules bring it there."""

    __tablename__ = "notify_deliveries"

    channel_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notify_channels.id", ondelete="CASCADE"), primary_key=True)
    item_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("news_items.id", ondelete="CASCADE"), primary_key=True, index=True)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)  # which rule brought it (information only)
    sent_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Setting(Base):
    """Settings sections as JSON (app/settings.py: news, smtp, ldap, entra, sessions, setup)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[dict] = mapped_column(Json, default=dict)


class PushSubscription(Base):
    """Web Push of one browser of one person (desktop notifications with every tab closed). The endpoint is a URL of the
    browser vendor's push service (checked against PUSH_HOSTS), p256dh/auth the browser's keys for the end-to-end
    encryption of the payload. `cursor`: the last story (NewsItem.seq) this browser was told about. 404/410 from the push
    service: the browser dropped it – the row goes."""

    __tablename__ = "push_subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    endpoint: Mapped[str] = mapped_column(Text, unique=True)
    p256dh: Mapped[str] = mapped_column(Text)
    auth: Mapped[str] = mapped_column(Text)
    lang: Mapped[str] = mapped_column(Text, default="de")
    label: Mapped[str] = mapped_column(Text, default="")  # browser and system, from the user agent
    cursor: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_ok_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_error_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    next_try_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


# ---------------------------------------------------------------- Vendor News


class VendorFollow(Base):
    """A product of the catalogue (or one added by CPE) this installation follows – one row per product, edited by
    admins, seen by everybody. `enabled` False: not followed any more (versions and notes stay for a later switch-on).
    Without versions: every vulnerability and story about the product; with versions: each one checked exactly."""

    __tablename__ = "vendor_follows"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    product: Mapped[str] = mapped_column(Text, unique=True)  # catalogue key or custom-<uuid>
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(Json, default=list)
    custom: Mapped[dict | None] = mapped_column(Json)  # a product by CPE: {key, label, vendor, cpe, category}
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # the first evaluation after following (or switching on) is the baseline: what is found then is not notified
    baseline_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # when it was followed or last switched on (migration 0045): "Unsere Produkte" as a rule's system counts it for the
    # stories from then on (systems.Followed) – none: created_at
    enabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class VendorVersion(Base):
    """One installed version of a followed product (several at once: 11.2.4-h23 in the data centre, 10.2.13-h5 at a
    branch). Label and count are optional. A changed version text is a new evaluation (and a new baseline)."""

    __tablename__ = "vendor_versions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    follow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vendor_follows.id", ondelete="CASCADE"), index=True)
    version: Mapped[str] = mapped_column(Text)
    label: Mapped[str] = mapped_column(Text, default="")
    count: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    baseline_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # "Versionen prüfen" (app/catalog_care.py): when somebody last said this version still runs – entering or changing
    # it, or "Bestätigen". Never part of the evaluation (updated_at is, confirmed_at is not: a confirmation recomputes
    # nothing). None: never confirmed – counts from updated_at (rows of a SQLite import). Who: None after the account went.
    confirmed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    confirmed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class VendorAdvisory(Base):
    """A vulnerability as one source sees it: a Palo Alto or Fortinet advisory, or a CVE record of the NVD. `data` keeps
    what the matching needs (affected / fixed versions per product line, CPE configurations, the CNA's affected data)."""

    __tablename__ = "vendor_advisories"
    # cves: GIN – "which advisories name these CVEs" (CVE beobachten, KEV changes) without reading every record
    # ident: CVE beobachten reads by `cves ?| … OR ident IN (…)` (app/cve_watch.py) – without it the OR read every row
    __table_args__ = (Index("ix_vendor_advisories_published", "published_at"), Index("ix_vendor_advisories_cves", "cves", postgresql_using="gin"), Index("ix_vendor_advisories_ident", "ident"))

    id: Mapped[str] = mapped_column(Text, primary_key=True)  # <source>:<ident> – nvd:CVE-…, paloalto:CVE-…, fortinet:FG-IR-…, csaf:SSA-…, cvelist:CVE-…, osv:CVE-…
    source: Mapped[str] = mapped_column(Text)  # nvd | paloalto | fortinet | veeam | csaf | cvelist | osv
    ident: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(Text, default="")
    cves: Mapped[list] = mapped_column(Json, default=list)
    cvss: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(Text, default="info")
    exploited: Mapped[bool] = mapped_column(Boolean, default=False)  # NVD: in CISA's catalogue (cisaExploitAdd)
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    data: Mapped[dict] = mapped_column(Json, default=dict)


class VendorAdvisoryProduct(Base):
    """Which catalogue products an advisory concerns (by CPE, CNA product name or the vendor's product name)."""

    __tablename__ = "vendor_advisory_products"

    product: Mapped[str] = mapped_column(Text, primary_key=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("vendor_advisories.id", ondelete="CASCADE"), primary_key=True, index=True)
    # found by the relink after a catalogue change (vendor.relink_catalog): a finding only such links make is shown,
    # never notified – a later store of the advisory links it anew (not quiet)
    quiet: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))


class VendorFetch(Base):
    """State of one outbound query (nvd:<cpe>:<version>, paloalto:<product>, fortinet:rss, kev, eol …): conditional
    request headers, backoff after failures, the last error."""

    __tablename__ = "vendor_fetch"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    etag: Mapped[str | None] = mapped_column(Text)
    last_modified: Mapped[str | None] = mapped_column(Text)
    cursor: Mapped[str | None] = mapped_column(Text)
    last_fetch_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_ok_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    next_fetch_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    items: Mapped[int] = mapped_column(Integer, default=0)
    full_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # NVD: the last full fetch (not only what changed)


class VendorKev(Base):
    """CISA's catalogue of known exploited vulnerabilities, whole (the news keep only the newest entries)."""

    __tablename__ = "vendor_kev"

    cve: Mapped[str] = mapped_column(Text, primary_key=True)
    vendor: Mapped[str] = mapped_column(Text, default="")
    product: Mapped[str] = mapped_column(Text, default="")
    name: Mapped[str] = mapped_column(Text, default="")
    date_added: Mapped[str] = mapped_column(Text, default="")
    due: Mapped[str] = mapped_column(Text, default="")
    ransomware: Mapped[bool] = mapped_column(Boolean, default=False)


class VendorEvent(Base):
    """Something to notify about, once: a vulnerability affecting a followed version (key vuln:<product>:<version>:<id>),
    a newer version in its line, an EOL coming or reached. `baseline`: found in the first evaluation – shown, not sent."""

    __tablename__ = "vendor_events"
    __table_args__ = (Index("ix_vendor_events_created", "created_at"), Index("ix_vendor_events_scope", "scope"))

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(Text, unique=True)
    kind: Mapped[str] = mapped_column(Text)  # vuln | version | eol
    product: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text, default="info")
    data: Mapped[dict] = mapped_column(Json, default=dict)  # what the message says (rendered per language when sent)
    baseline: Mapped[bool] = mapped_column(Boolean, default=False)
    # a vulnerability's product and version, "vuln:<product>:<version or *>": the CVEs notified there are looked up by it
    # (once per CVE, also when NVD and the vendor both report it), and its events go when the version does
    scope: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # grows with every event (SQLite's rowid up to 0.1.15): the notification round sees "something new" by its maximum,
    # also when one event went and another came in between (notify._marks)
    n: Mapped[int] = mapped_column(BigInteger, Identity(), unique=True)


class VendorDelivery(Base):
    """Each event at most once per channel."""

    __tablename__ = "vendor_deliveries"

    channel_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notify_channels.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vendor_events.id", ondelete="CASCADE"), primary_key=True, index=True)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    sent_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class VendorAdvisoryState(Base):
    """What an advisory said last, as far as it counts (app/advisory_changes.py): fixed versions, affected ranges and
    products, severity and CVSS, CVEs – normalised, so a reformatted source is no change. `facts` carries the extractor
    and parser version it was made with (another one: recomputed or set anew, silently). `revision` counts the content
    changes (1: as first stored), `changed_at` the last one. A table of its own (not columns of vendor_advisories): the
    one-off SQLite import of 0.1.15 checks those columns."""

    __tablename__ = "vendor_advisory_state"

    advisory_id: Mapped[str] = mapped_column(ForeignKey("vendor_advisories.id", ondelete="CASCADE"), primary_key=True)
    facts: Mapped[dict] = mapped_column(Json, default=dict)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class VendorAdvisoryChange(Base):
    """One content change of an advisory (a revision): when, by which source, what changed (`diff`: fixed versions,
    affected ranges, products, severity, CVSS, CVEs, KEV, withdrawn) and what that means for the versions entered
    (`impact`). No foreign key: a withdrawn advisory goes, its last changes stay (kept KEEP, PER_ADVISORY at most)."""

    __tablename__ = "vendor_advisory_changes"
    __table_args__ = (Index("ix_vendor_advisory_changes_advisory", "advisory_id", "revision"), Index("ix_vendor_advisory_changes_at", "at"))

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    advisory_id: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text)
    ident: Mapped[str] = mapped_column(Text, default="")
    title: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(Text, default="")
    revision: Mapped[int] = mapped_column(Integer)
    doc_rev: Mapped[str] = mapped_column(Text, default="")  # the vendor's own revision of the document, if it names one
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    diff: Mapped[list] = mapped_column(Json, default=list)
    impact: Mapped[list] = mapped_column(Json, default=list)
    products: Mapped[list] = mapped_column(Json, default=list)  # the catalogue products linked then


class StoryDetail(Base):
    """Details aus der Quelle of one story (app/story_details.py): the structured advisory behind it – affected products
    and ranges, fixed versions, CVSS, CVEs, exploited, mitigation, revision. `kind`: bsi | siemens | cisco | fortinet |
    paloalto | kev | euvd | nvd | none. `next_try_at`: asked again then (young stories daily; None: never again unless
    the story's title changes, e.g. an "[UPDATE]")."""

    __tablename__ = "story_details"

    item_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("news_items.id", ondelete="CASCADE"), primary_key=True)
    kind: Mapped[str] = mapped_column(Text, default="none")
    ident: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(Text, default="pending")  # pending | ok | none | error
    data: Mapped[dict | None] = mapped_column(Json)
    fetched_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    next_try_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)


class EpssScore(Base):
    """FIRST's EPSS for one CVE of a finding or a story (app/epss.py): the probability of exploitation in the next 30
    days and its percentile, as of `day`. `fetched_at`: when it was asked (also when FIRST did not know the CVE yet –
    score None) – asked again a day later at the earliest."""

    __tablename__ = "epss_scores"
    __table_args__ = (Index("ix_epss_scores_fetched", "fetched_at"),)

    cve: Mapped[str] = mapped_column(Text, primary_key=True)
    score: Mapped[float | None] = mapped_column(Float)
    percentile: Mapped[float | None] = mapped_column(Float)
    day: Mapped[str] = mapped_column(Text, default="")
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class ExploitRef(Base):
    """A source that lists public exploit code or a ready-made check for one CVE (app/exploits.py): Metasploit module,
    Exploit-DB entry, nuclei template – the CVE, the source, a link to the entry, when Cobe News first saw it. No code.
    `baseline`: brought by the source's first import – shown, never notified."""

    __tablename__ = "exploit_refs"

    cve: Mapped[str] = mapped_column(Text, primary_key=True)
    source: Mapped[str] = mapped_column(Text, primary_key=True)  # nuclei | metasploit | exploitdb
    url: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    baseline: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))


class UpdateDismissal(Base):
    """The release whose update notice an admin closed (app/update_check.py): a newer one shows it again."""

    __tablename__ = "update_dismissals"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    version: Mapped[str] = mapped_column(Text)
    dismissed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


# ---------------------------------------------------------------- source health (app/source_health.py)


class SourceFetchStat(Base):
    """One fetch of a source (a news feed by its key, a Vendor News query by its vendor_fetch key): when, whether it
    worked, the HTTP status, the error in one of a few categories (source_health.CATEGORIES), how long the requests took,
    how much came back, how many new items it brought, whether it was a 304 and how many entries were unreadable. One
    row per fetch, kept SOURCE_STATS_DAYS (pruned hourly) – what the health page and its sparkline are computed from."""

    __tablename__ = "source_fetch_stats"
    __table_args__ = (
        Index("ix_source_fetch_stats_source", "kind", "key", "at"),  # one source's history, newest first
        Index("ix_source_fetch_stats_at", "at"),  # the retention
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    kind: Mapped[str] = mapped_column(Text)  # news | vendor | structured (CSAF providers, cvelistV5, EPSS, OSV)
    key: Mapped[str] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    ok: Mapped[bool] = mapped_column(Boolean)
    status: Mapped[int | None] = mapped_column(Integer)  # the last HTTP answer (None: none came – timeout, DNS …)
    error: Mapped[str | None] = mapped_column(Text)  # timeout | connection | tls | http_4xx | http_5xx | rate_limited | blocked | parse | too_large | other
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)  # all requests of the fetch together
    requests: Mapped[int] = mapped_column(Integer, default=0)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    items: Mapped[int] = mapped_column(Integer, default=0)  # new (news) / new or changed (Vendor News) items
    not_modified: Mapped[bool] = mapped_column(Boolean, default=False)  # 304: unchanged since the last fetch
    parse_errors: Mapped[int] = mapped_column(Integer, default=0)  # entries that could not be read (1: the whole answer)


class SourceHealthEvent(Base):
    """A source's (news) or source family's (Vendor News: nvd, paloalto …) health state changed. The newest per source
    is its last known state – kept past the retention, so a restart never announces the same change again. `notify`:
    worth a message (into disturbed / dead, or back from there); the first state of a source is its baseline (not)."""

    __tablename__ = "source_health_events"
    __table_args__ = (Index("ix_source_health_events_source", "kind", "key", "n"), Index("ix_source_health_events_created", "created_at"))

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    n: Mapped[int] = mapped_column(BigInteger, Identity(), unique=True)  # the order (and "something new" for the notification round)
    kind: Mapped[str] = mapped_column(Text)
    key: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text, default="")
    state: Mapped[str] = mapped_column(Text)  # healthy | slow | disturbed | dead | off | never
    prev: Mapped[str | None] = mapped_column(Text)
    reasons: Mapped[list] = mapped_column(Json, default=list)
    notify: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class SourceHealthDelivery(Base):
    """Each state change at most once per channel."""

    __tablename__ = "source_health_deliveries"

    channel_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notify_channels.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("source_health_events.id", ondelete="CASCADE"), primary_key=True, index=True)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    sent_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


# ---------------------------------------------------------------- catalogue self-test (app/catalog_check.py)


class CatalogCpeCheck(Base):
    """What the NVD said about one CPE of the catalogue: in the CPE dictionary at all (deprecated, and by what), how many
    CVEs name it and when the newest was published. `source`: nvd (asked) or local (a followed product's own NVD data)."""

    __tablename__ = "catalog_cpe_checks"

    cpe: Mapped[str] = mapped_column(Text, primary_key=True)  # part:vendor:product
    tried_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # the last attempt (what "due" goes by)
    checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # the last good answer
    exists: Mapped[bool | None] = mapped_column(Boolean)
    deprecated_by: Mapped[str | None] = mapped_column(Text)  # all dictionary entries deprecated: the first successor
    cve_total: Mapped[int | None] = mapped_column(Integer)
    newest_cve: Mapped[str | None] = mapped_column(Text)
    newest_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    source: Mapped[str] = mapped_column(Text, default="nvd")
    error: Mapped[str | None] = mapped_column(Text)  # the last attempt failed (kept apart from the last good answer)


class CatalogCheck(Base):
    """The self-test's verdict on one catalogue product: ok | warn | error | unchecked, with the reasons
    ([{"code", "level", …params}] – the UI words them) and when; `followed` at that time."""

    __tablename__ = "catalog_checks"

    product: Mapped[str] = mapped_column(Text, primary_key=True)
    status: Mapped[str] = mapped_column(Text, default="unchecked")
    reasons: Mapped[list] = mapped_column(Json, default=list)
    followed: Mapped[bool] = mapped_column(Boolean, default=False)
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    catalog_version: Mapped[str] = mapped_column(Text, default="")


# ---------------------------------------------------------------- Teams (0.1.28, app/teams.py)


class Team(Base):
    """A team (switched on in the settings, off by default): bound to directory groups – their members (nested ones too)
    are loaded and kept in step – plus local accounts an admin adds by hand; it owns followed products (TeamProduct)
    and a notification rule can be limited to them (NotifyRuleTeam)."""

    __tablename__ = "teams"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")  # optimistic concurrency, as users
    # "An mein Team weiterleiten" (app/forward.py): the channel a member's forward goes to – chosen by an admin, never
    # by the reader; none: the button is off. A deleted channel leaves the team without one.
    forward_channel_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("notify_channels.id", ondelete="SET NULL"))


class TeamGroup(Base):
    """A directory group bound to a team: AD by its full DN, Entra by its object id. Its members (nested ones too) are
    members of the team – loaded when the group is bound, then by the hourly sync. `state`: how the last load went."""

    __tablename__ = "team_groups"
    __table_args__ = (Index("ux_team_groups", "team_id", "source", "group_id", unique=True), Index("ix_team_groups_group", "source", "group_id"))

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(Text)  # ldap | entra
    group_id: Mapped[str] = mapped_column(Text)
    group_name: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    state: Mapped[str] = mapped_column(Text, default="loading")  # loading | ok | error
    error: Mapped[str | None] = mapped_column(Text)  # the category of the last failed load (forbidden, connection …)
    members: Mapped[int] = mapped_column(Integer, default=0)  # people found at the last good load
    synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # the last good load


class TeamMember(Base):
    """A person in a team: `origin` group (a bound group brought them – the sync adds and removes these) or manual (a
    local account an admin added). Only `group` gives the reader role (directory accounts, while Teams is on)."""

    __tablename__ = "team_members"

    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    origin: Mapped[str] = mapped_column(Text, default="group")  # group | manual
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class TeamProduct(Base):
    """A followed product belongs to a team (a product to none, one or several). `added_at`: a rule limited to the team
    sends the product's Vendor News events from then on – not its older ones. `all_members` False (later, per-person
    routing): only the members in TeamProductMember get it – today always True, no UI sets it."""

    __tablename__ = "team_products"
    __table_args__ = (Index("ux_team_products", "team_id", "follow_id", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    follow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vendor_follows.id", ondelete="CASCADE"), index=True)
    all_members: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class TeamProductMember(Base):
    """Per-person routing (prepared, not used by the UI yet): the members of the team who get this product when its
    assignment is not for all members (A and B get Palo Alto, A and C Cisco)."""

    __tablename__ = "team_product_members"

    team_product_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("team_products.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)


class TeamWelcome(Base):
    """The welcome e-mail of a person a team loaded (switch "Willkommens-Mail", off by default) – one row per directory
    account (by its id, not the users row: an account deleted and loaded again gets no second mail): pending → sending
    (claimed) → sent; no_address (no e-mail in the directory) or failed. A row left at "sending" (the process stopped
    mid-way) is never sent again – never twice is worth more than once for sure."""

    __tablename__ = "team_welcome"

    source: Mapped[str] = mapped_column(Text, primary_key=True)  # ldap | entra
    external_id: Mapped[str] = mapped_column(Text, primary_key=True)
    status: Mapped[str] = mapped_column(Text, default="pending")  # pending | sending | sent | no_address | failed
    tries: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class NotifyRuleTeam(Base):
    """A notification rule limited to teams: its Vendor News events only for the products of these teams (news stories
    and source health have no product – the filter leaves them alone)."""

    __tablename__ = "notify_rule_teams"

    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notify_rules.id", ondelete="CASCADE"), primary_key=True)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True, index=True)


# ---------------------------------------------------------------- personal notifications (0.1.30, app/personal.py)


class PersonRoute(Base):
    """Since when a person gets a team product by its routing: written when a person is added to the chosen ones of a
    product, or when "Alle im Team" is switched on for those who did not get it before. A person's Vendor News events
    of the product count from then on (and from the product's assignment and the person's joining of the team) – never
    the older ones. Goes with the person (users), the assignment (team_products) and – app/teams.py – leaving the team."""

    __tablename__ = "person_routes"

    team_product_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("team_products.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    since: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class PersonNotify(Base):
    """A person's own notifications about the Vendor News of their products ("Hersteller-News meiner Produkte"): per way
    (e-mail, desktop push, a Microsoft Teams Workflows webhook) on/off and since when – only events created after that
    are sent –, what (kinds) and from which severity on (vulnerabilities). The Teams URL is encrypted (crypto) and never
    sent to the browser; `teams_host` is what the UI shows of it. `state_<way>`: the last delivery – ok or the error."""

    __tablename__ = "person_notify"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    lang: Mapped[str] = mapped_column(Text, default="de")
    kinds: Mapped[list] = mapped_column(Json, default=lambda: ["vendor_vuln", "vendor_version"])
    min_severity: Mapped[str] = mapped_column(Text, default="info")
    email_on: Mapped[bool] = mapped_column(Boolean, default=False)
    email_since: Mapped[datetime | None] = mapped_column(UTCDateTime)
    desktop_on: Mapped[bool] = mapped_column(Boolean, default=False)
    desktop_since: Mapped[datetime | None] = mapped_column(UTCDateTime)
    teams_on: Mapped[bool] = mapped_column(Boolean, default=False)
    teams_since: Mapped[datetime | None] = mapped_column(UTCDateTime)
    teams_url_enc: Mapped[str | None] = mapped_column(Text)
    teams_host: Mapped[str | None] = mapped_column(Text)
    # {failures, next_try_at, last_ok_at, last_error, last_error_at} – written by the delivery round (app/personal.py)
    state_email: Mapped[dict] = mapped_column(Json, default=dict)
    state_desktop: Mapped[dict] = mapped_column(Json, default=dict)
    state_teams: Mapped[dict] = mapped_column(Json, default=dict)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # quiet hours, what is urgent, per way "at once" or "collected at HH:MM" (app/quiet.py) – {} : as before 0.1.35
    schedule: Mapped[dict] = mapped_column(Json, default=dict)
    # the weekly review of the own teams by e-mail (app/weekly.py) – off by default; only weeks after `weekly_since`
    weekly_on: Mapped[bool] = mapped_column(Boolean, default=False)
    weekly_since: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # the person's last visit of their watched CVEs (/watch, app/watch_api.py): what happened after it is "new" there
    watch_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # only the Vendor News of these systems ([{"vendor"} | {"product"}], app/concerns.py) – empty: every product of the
    # person's teams; never the watched CVEs (migration 0040)
    systems: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))


class PersonNews(Base):
    """A person's own security stories by e-mail or their Microsoft Teams Workflows webhook (app/personal_news.py):
    the filter (as a channel rule's: severities, sources, topics, systems, words, exclusions – empty: all) and when it
    was last saved (`filter_seq` / `filter_at`: an older story counts only through a change after it – no flood after
    widening); per way on/off and from which arrival on (`<way>_on_seq`: the newest when switched on), the message
    being sent (`<way>_claim_at`, committed before sending), the last message (`<way>_sent_at` – one per GAP), the
    pause after a failure (`<way>_next_at`), when a round last looked (`<way>_seen_at` – the fair order), up to which
    arrival and time it judged the stories (`<way>_checked_seq` / `_at` – only what arrived or changed since is judged
    again) and the last delivery for the UI (`state_<way>`). What went out: person_news_sent. The Teams URL is the person's one of
    person_notify. Migration 0042."""

    __tablename__ = "person_news"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    lang: Mapped[str] = mapped_column(Text, default="de", server_default="de")
    severities: Mapped[list] = mapped_column(Json, default=lambda: ["critical", "high"], server_default=text("'[\"critical\", \"high\"]'::jsonb"))
    sources: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    topics: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    systems: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    keywords: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    exclude: Mapped[list] = mapped_column(Json, default=list, server_default=text("'[]'::jsonb"))
    filter_seq: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    filter_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    email_on: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    email_on_seq: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    email_claim_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    email_sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    email_next_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    email_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    email_checked_seq: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    email_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    state_email: Mapped[dict] = mapped_column(Json, default=dict, server_default=text("'{}'::jsonb"))
    teams_on: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    teams_on_seq: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    teams_claim_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    teams_sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    teams_next_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    teams_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    teams_checked_seq: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    teams_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    state_teams: Mapped[dict] = mapped_column(Json, default=dict, server_default=text("'{}'::jsonb"))
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, server_default=text("now()"))


class PersonNewsSent(Base):
    """A story that went to a person on a way (app/personal_news.py) – at most once; written with the claim, before
    anything is sent (taken back only after a failure that certainly delivered nothing). Kept personal.MAX_AGE plus a
    day: an older story is never sent."""

    __tablename__ = "person_news_sent"
    __table_args__ = (Index("ix_person_news_sent_at", "sent_at"), Index("ix_person_news_sent_item", "item_id"))

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    way: Mapped[str] = mapped_column(Text, primary_key=True)
    item_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("news_items.id", ondelete="CASCADE"), primary_key=True)
    sent_at: Mapped[datetime] = mapped_column(UTCDateTime)


class PersonDelivery(Base):
    """One Vendor News event for one person on one way – at most once (the key). pending → sending (claimed and
    committed before anything is sent: a crash or restart in between never sends it twice) → sent; back to pending
    after a failure that certainly delivered nothing (a growing pause), failed after one that may have (a timeout) or
    after too many tries; skipped: decided not to send (filtered out, the way switched off, no address, no browser)."""

    __tablename__ = "person_deliveries"
    __table_args__ = (Index("ix_person_deliveries_open", "status", "user_id", "way"), Index("ix_person_deliveries_created", "created_at"))

    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vendor_events.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    way: Mapped[str] = mapped_column(Text, primary_key=True)  # email | desktop | teams
    status: Mapped[str] = mapped_column(Text, default="pending")  # pending | sending | sent | failed | skipped
    tries: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    claimed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # what makes the event urgent (app/quiet.py BITS: critical, KEV, own version affected now, watched CVE) – it passes
    # the recipient's quiet hours when one of these is among the person's urgent ones
    marks: Mapped[int] = mapped_column(SmallInteger, default=0)


# ---------------------------------------------------------------- CVE beobachten, Kalender-Feed (app/cve_watch.py, app/calendar_feed.py)


class CveWatch(Base):
    """A person follows one CVE ("CVE beobachten"), independent of teams and products: what happens to it from
    `created_at` on – a fix, CISA KEV, a jump of its EPSS, an advisory withdrawn – comes on the person's own ways
    (app/personal.py). Only the own rows are read or written (no id in any path but the CVE)."""

    __tablename__ = "cve_watches"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    cve: Mapped[str] = mapped_column(Text, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # where it was watched from (0.1.42, the list's groups): "story" (ref: its id), "finding" (product, ref: the advisory
    # id) or "manual" – with the title as it was then (from the database, never from the client). NULL: watched before
    # 0.1.42 (unknown – shown with the manual ones). The first origin stays: watching it again elsewhere changes nothing.
    origin_kind: Mapped[str | None] = mapped_column(Text)
    origin_ref: Mapped[str | None] = mapped_column(Text)
    origin_product: Mapped[str | None] = mapped_column(Text)
    origin_title: Mapped[str | None] = mapped_column(Text)


class CveWatchState(Base):
    """What a watched CVE looked like at its last check (one row per CVE, whoever watches it): in KEV, the fixed versions
    known, its EPSS reference. A difference to the current data is an event (VendorEvent kind "watch"); the first row is
    made from the data at the moment of the first watch – the baseline, never notified. Goes when nobody watches it."""

    __tablename__ = "cve_watch_state"

    cve: Mapped[str] = mapped_column(Text, primary_key=True)
    state: Mapped[dict] = mapped_column(Json, default=dict)
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class CalendarFeed(Base):
    """A person's secret calendar address (iCal: the EOL dates of their products' versions). The token is shown once;
    only its keyed hash is stored. One per person: a new one replaces it, deleting it ends the address."""

    __tablename__ = "calendar_feeds"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


# ---------------------------------------------------------------- absence and weekly review (app/absence.py, app/weekly.py)


class PersonAbsence(Base):
    """A person away from `starts_at` to `ends_at`: the Vendor News of their routed products created meanwhile go to the
    deputy's ways (and to the person too with `also_me`). A row is never changed for time that has passed – a running
    absence is ended (ends_at = now) or split, never moved – so who got an event stays who gets it. Only one row per
    person ends in the future (the API keeps it so)."""

    __tablename__ = "person_absences"
    __table_args__ = (Index("ix_person_absences_user", "user_id", "ends_at"), Index("ix_person_absences_deputy", "deputy_id", "ends_at"))

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    deputy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    starts_at: Mapped[datetime] = mapped_column(UTCDateTime)
    ends_at: Mapped[datetime] = mapped_column(UTCDateTime)
    also_me: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class TeamWeekly(Base):
    """A team's weekly review by e-mail (off by default): weekday (0 Monday) and time in its time zone. `since`: switched
    on or its time changed – only a week whose time comes after it is sent; `last_week`: the newest week queued."""

    __tablename__ = "team_weekly"

    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    weekday: Mapped[int] = mapped_column(SmallInteger, default=0)
    at: Mapped[str] = mapped_column(Text, default="08:00")
    tz: Mapped[str] = mapped_column(Text, default="Europe/Berlin")
    since: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_week: Mapped[str | None] = mapped_column(Text)


class TeamWeeklySend(Base):
    """One weekly review for one person of one team, once per week (the key, ISO week "2026-W45"): pending → sending
    (claimed and committed before the mail goes out) → sent; failed (may have arrived, or too many tries); skipped (a
    newer week came first – no catching up on old weeks)."""

    __tablename__ = "team_weekly_sends"
    __table_args__ = (Index("ix_team_weekly_sends_open", "status", "created_at"),)

    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    week: Mapped[str] = mapped_column(Text, primary_key=True)
    status: Mapped[str] = mapped_column(Text, default="pending")  # pending | sending | sent | failed | skipped
    tries: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    claimed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


# ---------------------------------------------------------------- API tokens (app/api_tokens.py)


class ApiToken(Base):
    """A named token for the read-only API (/api/v1) or the metrics (/metrics), made by an admin: shown once, only its
    keyed hash is stored (crypto.token_hash). Works only while it is neither revoked nor expired and the admin who made
    it is still an active admin. No writing scope exists."""

    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    prefix: Mapped[str] = mapped_column(Text)  # the first characters ("cnt_AbC123") – recognisable in the list, no secret
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    scopes: Mapped[list] = mapped_column(Json, default=list)  # read | metrics
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # always set since 0.1.42 (at most api_tokens.MAX_DAYS) – None only on a row older than migration 0023
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # made with "never expires" before 0.1.42: migration 0023 gave it an expiry (the list says "Ablauf ergänzt")
    expiry_added: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))


# ---------------------------------------------------------------- audit log (app/audit.py)


class AuditEntry(Base):
    """One security-relevant admin or account action (the Protokoll): who (an account – id and name as they were then –,
    or the system, the directory sync, the command line), what (an action key of audit.ACTIONS), on what (type, id and
    label as they were then), from where (the client address) and the changed fields before/after – never a secret value
    (audit.scrub). Written in the transaction of the change itself; append-only (no API edits or deletes one), kept
    `keep_days` (settings section "audit", pruned hourly). No foreign key: an entry outlives the account it names."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_at", "at", "id"),  # the list, newest first (keyset), and the retention
        Index("ix_audit_log_actor", "actor_id", "at"),
        Index("ix_audit_log_action", "action", "at"),
        Index("ix_audit_log_target", "target_type", "target_id", "at"),
        # migration 0032: the filters of the second step and the chain
        Index("ix_audit_log_kind", "actor_kind", "at", postgresql_where=text("actor_kind <> 'user'")),
        Index("ix_audit_log_ip", "ip", "at", postgresql_where=text("ip IS NOT NULL")),
        Index("ix_audit_log_session", "session_ref", "at", postgresql_where=text("session_ref IS NOT NULL")),
        Index("ix_audit_log_notable", "at", "id", postgresql_where=text("notable")),
        Index("ux_audit_log_seq", "seq", unique=True, postgresql_where=text("seq IS NOT NULL")),
        Index("ix_audit_log_unsealed", "id", postgresql_where=text("seq IS NULL")),
        # migration 0033: the search over one expression (audit.SEARCH_TEXT), trigram
        Index(
            "ix_audit_log_search",
            text(
                "lower(actor_name || ' ' || actor_display || ' ' || action || ' ' || coalesce(target_label, '') || ' ' || "
                "coalesce(target_id, '') || ' ' || coalesce(ip, '')) gin_trgm_ops"
            ),
            postgresql_using="gin",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    actor_kind: Mapped[str] = mapped_column(Text)  # user | system | sync | cli
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_name: Mapped[str] = mapped_column(Text, default="")  # the username then (user), else the kind
    actor_display: Mapped[str] = mapped_column(Text, default="")  # the display name then
    action: Mapped[str] = mapped_column(Text)
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[str | None] = mapped_column(Text)
    target_label: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(Json, default=dict)
    # who, more closely (0032): the role then, the emergency account, how its session was signed in, a keyed short
    # reference of that session (audit.session_ref – never its token or id)
    actor_role: Mapped[str | None] = mapped_column(Text)
    actor_emergency: Mapped[bool | None] = mapped_column(Boolean)
    auth_method: Mapped[str | None] = mapped_column(Text)
    session_ref: Mapped[str | None] = mapped_column(Text)
    # from where: browser and system coarse (never the full user agent), the request (no query string), how it arrived
    ua_family: Mapped[str | None] = mapped_column(Text)
    ua_version: Mapped[str | None] = mapped_column(Text)
    ua_os: Mapped[str | None] = mapped_column(Text)
    req_method: Mapped[str | None] = mapped_column(Text)
    req_path: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[str | None] = mapped_column(Text)
    req_via: Mapped[str | None] = mapped_column(Text)  # direct | bundled | proxy | bundled_proxy
    app_version: Mapped[str | None] = mapped_column(Text)
    notable: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))  # security-relevant or an anomaly
    # the chain (audit.seal / audit.verify): position, the previous entry's hash, the HMAC over this canonical entry
    seq: Mapped[int | None] = mapped_column(BigInteger)
    prev_hash: Mapped[str | None] = mapped_column(Text)
    hash: Mapped[str | None] = mapped_column(Text)


# ---------------------------------------------------------------- delivery log (app/delivery_log.py, migration 0018)


class DeliveryLog(Base):
    """One attempt to deliver one message: a rule's message to a channel, a team forward, a weekly review mail, a test.
    The attempts of one delivery share `ref` (the channel's automatic retries of the same message, a manual resend).
    What was sent only by reference and title (`items`) – never a message body, a webhook URL, a token, an SMTP
    credential or a response body; `detail` is short and cleaned (delivery_log.sanitize). Kept RETENTION_DAYS."""

    __tablename__ = "delivery_log"
    __table_args__ = (Index("ix_delivery_log_channel", "channel_id", "at"), Index("ix_delivery_log_ref", "ref", "channel_id"))

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    # a deleted channel leaves its entries (with the name it had) until they age out
    channel_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("notify_channels.id", ondelete="SET NULL"))
    channel_name: Mapped[str] = mapped_column(Text, default="")
    channel_type: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(Text)  # rule | forward | weekly | test
    ref: Mapped[str] = mapped_column(Text)  # the delivery: the same message keeps it across its attempts
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    manual: Mapped[bool] = mapped_column(Boolean, default=False)  # "Erneut senden" by an admin
    items: Mapped[list] = mapped_column(Json, default=list)  # [{"kind", "id", "title", "severity"}] – the listed ones (at most 10)
    total: Mapped[int] = mapped_column(Integer, default=0)
    rules: Mapped[list] = mapped_column(Json, default=list)  # [{"id", "name"}] that brought it
    refs: Mapped[list] = mapped_column(Json, default=list)  # rule messages: ["news:<id>:<rule id>", …] – what a resend sends again
    lang: Mapped[str] = mapped_column(Text, default="de")
    team_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    team_name: Mapped[str | None] = mapped_column(Text)
    # a weekly review's recipient – only admins see the log, and only the way and the person, never the mail
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    ok: Mapped[bool] = mapped_column(Boolean)
    outcome: Mapped[str] = mapped_column(Text)  # ok | http | timeout | blocked | smtp | error
    error: Mapped[str | None] = mapped_column(Text)  # the category (notify.NotifyError)
    code: Mapped[int | None] = mapped_column(Integer)  # HTTP status, or the SMTP reply code of an e-mail
    detail: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)


# ---------------------------------------------------------------- Produkt vorschlagen (app/catalog_care.py)


class ProductSuggestion(Base):
    """A reader's suggestion of a product the catalogue lacks: vendor, name, an optional address and CPE, why, and a
    team. Plain text only – never fetched, never rendered as HTML. open → accepted (`product_key`: the product added,
    None: "for the bundled catalogue") | rejected (`answer`: the optional reason) | duplicate (`product_key`: the
    product it already is). `seen_at`: the suggester saw the answer. The person deleted: the suggestion stays (who
    is unknown then)."""

    __tablename__ = "product_suggestions"
    __table_args__ = (Index("ix_product_suggestions_status", "status", "created_at"), Index("ix_product_suggestions_user", "user_id", "created_at"))

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    vendor: Mapped[str] = mapped_column(Text)
    product: Mapped[str] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    cpe: Mapped[str | None] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text, default="")
    team_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("teams.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(Text, default="open")  # open | accepted | rejected | duplicate
    answer: Mapped[str] = mapped_column(Text, default="")
    product_key: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
# ---------------------------------------------------------------- reading: read state, mutes, saved views (app/reader.py)


class ReaderState(Base):
    """A person's read watermarks: every story that arrived up to `news_seq` (arrival number; a story without one: up to
    `news_at`) and every Vendor News finding that arrived up to `vendor_at` counts as read – the sparse rows of
    news_reads / vendor_reads say the rest. No row (or None): up to the account's creation – nobody starts with
    thousands of unread stories. Written only by "Alle gelesen" without a filter."""

    __tablename__ = "reader_state"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    news_seq: Mapped[int | None] = mapped_column(BigInteger)
    news_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    vendor_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class VendorRead(Base):
    """A Vendor News finding (one advisory of one followed product) read by a person after their watermark – or marked
    unread again (`unread`). Read counts while `read_at` is not older than the finding's last arrival (a new event of it,
    e.g. "now exploited", makes it unread again). Sparse: rows older than reader.AUTO_READ go with the prune."""

    __tablename__ = "vendor_reads"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    product: Mapped[str] = mapped_column(Text, primary_key=True)
    finding: Mapped[str] = mapped_column(Text, primary_key=True)
    read_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    unread: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))


class VendorConfirm(Base):
    """"Treffer bestätigt" (app/finding_confirm.py): a Vendor News finding of a followed product assessed for everybody –
    not affected, mitigated or the risk accepted, with a reason. One row per period in which a confirmation stood: while
    it stands (`ended_at` None – at most one per finding – and `facts` still those of the finding) the finding counts as
    handled and is not notified. It ends by hand ("aufheben", `ended_reason` "undone") or by itself when the finding
    changes materially (exploited, rated higher, new CVEs, a version's verdict, withdrawn). The row stays after the end:
    the events made while it stood are never sent later (`held_from`, `held_until`) – a confirmation made again is a new
    row, so a time in between when none stood is never held."""

    __tablename__ = "vendor_confirms"
    __table_args__ = (
        Index("ix_vendor_confirms_finding", "product", "finding"),
        Index("ux_vendor_confirms_standing", "product", "finding", unique=True, postgresql_where=text("ended_at IS NULL")),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    product: Mapped[str] = mapped_column(Text)
    finding: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)  # not_affected | mitigated | accepted
    note: Mapped[str] = mapped_column(Text, default="", server_default="")
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    user_name: Mapped[str] = mapped_column(Text, default="", server_default="")  # kept for display (account deleted)
    confirmed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # the finding as it was confirmed (finding_confirm.facts_of) – with the ids of its group's records ("members")
    facts: Mapped[dict] = mapped_column(Json, default=dict)
    # its events made in [held_from, held_until) are never sent – while it stands (held_until None) none of them is
    held_from: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    held_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    ended_reason: Mapped[str | None] = mapped_column(Text)  # undone | exploited | severity | cves | verdict | withdrawn
    ended_by: Mapped[str | None] = mapped_column(Text)  # the name of who undid it (a lapse: none)


class PersonMute(Base):
    """"Stummschalten" for a while: a person silences a catalogue product or one CVE until `until` – none of their own
    deliveries (app/personal.py) for it, dimmed or hidden in their lists, left out of their unread numbers. Never anybody
    else's, never a team channel or an admin's rule. Expired rows go with the prune."""

    __tablename__ = "person_mutes"
    __table_args__ = (Index("ux_person_mutes", "user_id", "kind", "key", unique=True), Index("ix_person_mutes_until", "until"))

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(Text)  # product | cve
    key: Mapped[str] = mapped_column(Text)  # the product's catalogue key, or CVE-YYYY-N
    until: Mapped[datetime] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class SavedView(Base):
    """A person's saved filter of News or Vendor News ("Ansichten"): the page's query string as it was (unknown
    parameters are kept – a renamed parameter must not break a view). At most one default per person and page."""

    __tablename__ = "saved_views"
    __table_args__ = (
        Index("ux_saved_views_name", "user_id", "page", "name", unique=True),
        Index("ux_saved_views_default", "user_id", "page", unique=True, postgresql_where=text("is_default")),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    page: Mapped[str] = mapped_column(Text)  # news | vendor
    name: Mapped[str] = mapped_column(Text)
    query: Mapped[str] = mapped_column(Text, default="")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
