import os
import re
import secrets
import tempfile
from datetime import UTC, date, datetime, timedelta

from sqlalchemy.engine import make_url

# PostgreSQL 18 for the tests: TEST_DATABASE_URL names a server and a user that may create databases (docs/BETRIEB.md:
# Entwicklung). Each run gets a database of its own (cn_test_<random>), migrated once and dropped at the end; every
# test starts on emptied tables.
_admin_url = os.environ.get("TEST_DATABASE_URL", "")
if not _admin_url:
    raise SystemExit("TEST_DATABASE_URL is not set – e.g. postgresql://postgres:…@127.0.0.1:55433/postgres (docs/BETRIEB.md: Entwicklung / Tests)")
# one name per run, also when a test module imports this file a second time (as tests.conftest)
TEST_DB = os.environ.setdefault("CN_TEST_DB", f"cn_test_{secrets.token_hex(4)}")
DATABASE_URL = make_url(_admin_url).set(drivername="postgresql+asyncpg", database=TEST_DB)

# before the app is imported: no background loop, no static files, data and certificates in a temp folder, plain http
_tmp = tempfile.mkdtemp(prefix="cobe-news-test-")
os.environ.update(
    DATABASE_URL=DATABASE_URL.render_as_string(hide_password=False),
    NEWS_LOOP="0",
    DATA_DIR=_tmp,
    STATIC_DIR=os.path.join(_tmp, "no-static"),
    TLS_PATH=os.path.join(_tmp, "tls"),
    COOKIE_SECURE="0",
    BASE_URL="https://news.corp.example:8095",
    SECRET_KEY="test-only-secret-key-not-for-production",
    SMTP_ALLOW_INTERNAL="127.0.0.1",  # the local fake SMTP server (aiosmtpd; test_notify's smtp fixture lets loopback through)
)
for k in ("HTTPS_PROXY", "ALLOW_PRIVATE_FEEDS", "WEBHOOK_HOSTS", "TLS_MODE", "NEWS_HOSTNAME", "TLS_NAMES", "HSTS"):
    os.environ.pop(k, None)

import asyncio  # noqa: E402
import socket  # noqa: E402

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pyotp  # noqa: E402
import pytest  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app import api, db, delivery_log, delivery_log_api, news, notify  # noqa: E402
from app import calendar_feed, notify_api, passkeys_api, personal, personal_api, push_api, teams, vendor, watch_api, webpush  # noqa: E402
from app import settings as settings_store  # noqa: E402
from app.auth import bruteforce, entra, passwords, sessions  # noqa: E402
from app.crypto import encrypt_str  # noqa: E402
from app.main import app  # noqa: E402
from app.models import User  # noqa: E402

LOCAL = ("127.0.0.1", "localhost", "::1")
_real_getaddrinfo, _real_create_connection = socket.getaddrinfo, socket.create_connection
STRUCTURED_OFF = {"csaf": False, "cvelist": False, "epss": False, "osv": False, "exploit_metasploit": False, "exploit_exploitdb": False, "exploit_nuclei": False}
PASSWORD = "Ein-langes-Test-Passwort-2026"  # test fixture only


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """No real feed, Microsoft, Slack, Teams or mail server in tests: name lookups and connections fail loudly – except
    to this machine (the local fake SMTP server)."""

    def getaddrinfo(host, *a, **kw):
        if str(host) in LOCAL:
            return _real_getaddrinfo(host, *a, **kw)
        raise AssertionError(f"network access in a test: {host}")

    def create_connection(address, *a, **kw):
        if str(address[0]) in LOCAL:
            return _real_create_connection(address, *a, **kw)
        raise AssertionError(f"network access in a test: {address}")

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", create_connection)


def _admin_dsn() -> str:
    return make_url(_admin_url).set(drivername="postgresql").render_as_string(hide_password=False)


async def _create_db() -> None:
    conn = await asyncpg.connect(_admin_dsn())
    try:
        # byte order like SQLite's (and the production database's, docker-compose.yml): builtin C.UTF-8
        await conn.execute(f"CREATE DATABASE {TEST_DB} TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER builtin BUILTIN_LOCALE 'C.UTF-8'")
    finally:
        await conn.close()
    db.init(DATABASE_URL)
    await db.migrate()
    await db.dispose()


async def _drop_db() -> None:
    conn = await asyncpg.connect(_admin_dsn())
    try:
        await conn.execute(f"DROP DATABASE IF EXISTS {TEST_DB} WITH (FORCE)")
    finally:
        await conn.close()


@pytest.fixture(scope="session", autouse=True)
def test_database():
    asyncio.run(_create_db())
    yield DATABASE_URL
    if not os.environ.get("KEEP_TEST_DB"):
        asyncio.run(_drop_db())


def execute_elsewhere(sql: str, *args) -> None:  # noqa: ANN002
    """SQL on another connection, synchronously (from code the test cannot make async): as another request would –
    a thread with its own event loop and its own asyncpg connection."""
    import threading

    dsn = DATABASE_URL.set(drivername="postgresql").render_as_string(hide_password=False)
    err: list[BaseException] = []

    async def go() -> None:
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute(sql, *args)
        finally:
            await conn.close()

    def run() -> None:
        try:
            asyncio.run(go())
        except BaseException as exc:  # noqa: BLE001 - raised in the test's thread
            err.append(exc)

    t = threading.Thread(target=run)
    t.start()
    t.join(30)
    if err:
        raise err[0]


async def empty_tables() -> None:
    from app.sqlite_import import tables

    async with db.engine().begin() as conn:
        await conn.execute(text("TRUNCATE " + ", ".join(t.name for t in tables()) + " RESTART IDENTITY"))


@pytest.fixture(autouse=True)
async def fresh_db(tmp_path, monkeypatch):
    """Every test on emptied tables; in-process limits, the per-host clock and the brute-force counters reset."""
    db.init(DATABASE_URL)
    await empty_tables()
    async with db.session() as s:
        await news.ensure_sources(s)  # as at the start of the app
    news._host_last.clear()
    api.limits.manual_at = api.limits.test_at = -1e9
    notify_api._last_test.clear()
    notify_api._dry_at.clear()
    delivery_log.reset()
    delivery_log_api.reset()
    notify.reset()  # the last round's marks belong to the previous test's database
    push_api._last_test.clear()
    personal_api._last_test.clear()
    watch_api.reset()  # the bulk rate limit
    personal.reset()  # the last round's marks belong to the previous test's database
    calendar_feed.reset()  # the feed's rate limits
    webpush.reset_cache()
    vendor.reset()  # views, pauses and evaluation marks of the previous test's database
    # the structured sources (CSAF providers, cvelistV5, EPSS, OSV) stay off unless a test switches them on: they would
    # ask hosts the older tests' mocks do not serve (tests/test_structured.py switches them on and mocks them)
    monkeypatch.setitem(settings_store.DEFAULTS, "vendor", {**settings_store.DEFAULTS["vendor"], **STRUCTURED_OFF})
    bruteforce.reset()
    from app import audit

    audit.reset_floods()  # the hour's counts of locks of unknown names and address blocks
    passkeys_api.reset()  # pending WebAuthn challenges and the sign-in start counts
    monkeypatch.setattr(bruteforce, "DELAY_STEP", 0.0)
    monkeypatch.setattr(notify, "transport", None)
    monkeypatch.setattr(entra, "transport", None)
    entra._jwks_cache.clear()
    entra._app_tokens.clear()
    yield
    await teams.wait_idle()  # a load a test started in the background ends before its database goes
    await db.dispose()


class Browser(httpx.AsyncClient):
    """A browser: its own cookies, the CSRF token sent back with every write (double submit) and with a logged download
    (the page's api.getFile sends it: the audit log's CSV, the data export), and – as a browser's fetch() does –
    Sec-Fetch-Site: same-origin (a test of a cross-site request sets its own headers)."""

    async def request(self, method, url, *a, headers=None, **kw):
        headers = {"Sec-Fetch-Site": "same-origin", **(headers or {})}
        if method.upper() == "GET" and "export" in str(url) and "x-csrf-token" not in {k.lower() for k in headers}:
            if "cobe_news_csrf" not in self.cookies:
                await super().request("GET", "/api/auth/config")
            headers = {"X-CSRF-Token": self.cookies.get("cobe_news_csrf", ""), **headers}
        if method.upper() not in ("GET", "HEAD", "OPTIONS"):
            if "cobe_news_csrf" not in self.cookies:
                await super().request("GET", "/api/auth/config")
            headers = {"X-CSRF-Token": self.cookies.get("cobe_news_csrf", ""), **(headers or {})}
        return await super().request(method, url, *a, headers=headers, **kw)


def make_client(**kw) -> Browser:
    return Browser(transport=httpx.ASGITransport(app=app, **kw), base_url="http://news.test")


@pytest.fixture
async def client():
    async with make_client() as c:
        yield c


async def set_news(**value):
    async with db.session() as s:
        await news.save_config(s, {**news.DEFAULTS, **value})


def dated_back(data: bytes, made: date, days_ago: int = 1) -> bytes:
    """A fixture as if fetched now: every timestamp in it (YYYY-MM-DDT…) moves by the same number of days, so that
    `made` (the day the fixture was taken) becomes `days_ago` days before today (UTC) – order and spacing stay. For
    dates a window counts from the real now (EVENT_FRESH, the news retention): fixed ones would expire."""
    shift = datetime.now(UTC).date() - timedelta(days=days_ago) - made

    def move(m: re.Match) -> bytes:
        return (date.fromisoformat(m.group(0).decode()) + shift).isoformat().encode()

    return re.sub(rb"\b\d{4}-\d{2}-\d{2}(?=T)", move, data)


async def add_user(username: str, role: str = "reader", *, totp_secret: str | None = None, emergency: bool = False, **extra) -> User:
    async with db.session() as s:
        u = User(
            username=username,
            display_name=username.title(),
            role=role,
            auth_source="local",
            password_hash=passwords.hash_password(PASSWORD),
            totp_secret_enc=encrypt_str(totp_secret) if totp_secret else None,
            is_emergency=emergency,
            **extra,
        )
        s.add(u)
        await s.commit()
        return u


async def sign_in(c: httpx.AsyncClient, user: User) -> None:
    """A signed-in session straight away (the sign-in flows themselves are tested in test_auth.py)."""
    async with db.session() as s:
        u = await s.get(User, user.id)
        sess, _ = await sessions.create(s, u, "pre", "127.0.0.1", "pytest")
        token = await sessions.promote(s, sess, "active")
        await s.commit()
    c.cookies.set(sessions.cookie_name(), token)


@pytest.fixture
async def admin_client():
    """An admin (with TOTP, as admins must have)."""
    u = await add_user("anna", "admin", totp_secret=pyotp.random_base32())
    async with make_client() as c:
        await sign_in(c, u)
        c.user = u
        yield c


@pytest.fixture
async def reader_client():
    u = await add_user("rudi", "reader")
    async with make_client() as c:
        await sign_in(c, u)
        c.user = u
        yield c


@pytest.fixture(autouse=True)
def _no_host_networks(request, monkeypatch):  # noqa: ANN001, ANN202
    """The tests run on a host, not in the app's container: the host's own routes (a CI runner's 10.1.0.0/16) are not the
    Docker networks netaddr.stack_networks() guards – without this a runner's network would count as "own" and the
    address rules would differ by machine. A test about /proc/net/route itself is marked `host_networks`."""
    if request.node.get_closest_marker("host_networks"):
        return
    from app import netaddr

    monkeypatch.setattr(netaddr, "stack_networks", lambda: ())
    monkeypatch.setattr(netaddr, "container_gateway", lambda: None)
