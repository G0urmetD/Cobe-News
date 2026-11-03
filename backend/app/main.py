"""Cobe News: one process – the API, the built web UI (static files) and the background loops (asyncio tasks): feeds,
the source health (every 5 minutes), push notifications, the HTTPS certificate (daily), the directory sync and old
sessions (hourly); Vendor News (its own task, app/vendor.py) and its catalogue self-test (app/catalog_check.py).

In front: the bundled nginx (TLS, docker-compose.yml). Sign-in: local accounts, AD/LDAP, Entra ID (auth_api.py).
Writes need the CSRF token (double submit: cookie __Host-cobe_news_csrf – without the prefix on plain-http
development –, header X-CSRF-Token)."""

import asyncio
import contextlib
import hmac
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app import __version__, api_tokens, api_v1, audit, audit_api, bodylimit, calendar_feed, catalog_check, crypto, cve_watch, db, delivery_log, metrics, notify, passkeys_api, personal, reader, restore_test, sessions_api, source_health, sqlite_import, suspicious, teams, tls, vendor, webpush
from app import news as news_svc
from app.admin_api import router as admin_router
from app.api import router
from app.auth import bruteforce, lock_store, sessions
from app.auth import sync as directory_sync
from app.auth_api import issue_setup_token
from app.auth_api import router as auth_router
from app.changelog import router as changelog_router
from app.config import get_config
from app.deps import client_ip, via_https
from app.docs import router as docs_router
from app.delivery_log_api import router as delivery_log_router
from app.notify_api import router as notify_router
from app.personal_api import router as personal_router
from app.push_api import router as push_router
from app.reader_api import router as reader_router
from app.source_health_api import router as health_router
from app.teams_api import router as teams_router
from app.forward import router as forward_router
from app.vendor_api import router as vendor_router
from app.catalog_care_api import router as catalog_care_router
from app.watch_api import router as watch_router

log = logging.getLogger("cobe_news")
access = logging.getLogger("cobe_news.access")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

SAFE = ("GET", "HEAD", "OPTIONS")
# style-src: stylesheets of this origin only – no inline <style> element (an injected one could read the page with CSS
# selectors); style attributes stay allowed (style-src-attr: Radix positions popovers and menus with them, and an
# attribute has no selectors). The build keeps the libraries from injecting <style> elements (frontend
# src/lib/no-inline-styles.ts). The one hash is that of an empty <style> – the code input (input-otp) creates one and
# fills it through the CSS object model, which CSP does not restrict; an empty element can do nothing.
STYLE_EMPTY = "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"
CSP = (
    f"default-src 'self'; script-src 'self'; style-src 'self' {STYLE_EMPTY}; style-src-attr 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
# browser features the UI never uses – not even a page injected into it gets them (desktop notifications are not one)
PERMISSIONS = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"


def _secure_headers(request: Request, resp: Response, api: bool) -> Response:
    """The same headers on every answer of the app – also on the ones the guard refuses before any route runs."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Content-Security-Policy", CSP)
    resp.headers.setdefault("Permissions-Policy", PERMISSIONS)
    # no other site's window keeps a handle on this one (the sign-in with Entra is a redirect, not a popup)
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if tls.hsts() and via_https(request) and tls.hsts_host(request.headers.get("host", "")):
        resp.headers.setdefault("Strict-Transport-Security", tls.HSTS_HEADER)
    if api:
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


async def _step(name: str, fn) -> None:
    try:
        await fn()
    except Exception:  # noqa: BLE001 - logged, the next step and the next round go on
        log.exception("background step %s failed", name)


class FetchLoop:
    """The worker loops, in-process: due feeds every minute (each host at most once a minute, pauses after refusals),
    then the notification rules; old stories and sessions, and the directory sync once an hour; the certificate once a
    day. An asyncio lock and an event, no Redis."""

    def __init__(self) -> None:
        self.event = asyncio.Event()
        self.lock = asyncio.Lock()
        self.force_since: datetime | None = None
        self.force_until = 0.0
        self.last_hourly = 0.0
        self.last_tls = 0.0
        self.last_health = -1e9

    def wake(self) -> None:
        self.event.set()

    def force(self) -> None:
        self.force_since = datetime.now(UTC)
        self.force_until = time.monotonic() + 600
        self.event.set()

    async def round(self) -> None:
        # every step on its own: a failing feed, mail server or directory must not keep the others from running
        async with self.lock:
            if time.monotonic() - self.last_tls > 86400:
                self.last_tls = time.monotonic()
                await _step("tls", self._tls)
            await _step("news", self._news)
            await _step("topics", self._topics)
            if time.monotonic() - self.last_health > source_health.EVALUATE_EVERY_S:
                self.last_health = time.monotonic()
                await _step("source health", self._health)
            await _step("notify", self._notify)
            await _step("personal", self._personal)
            await _step("push", self._push)
            await _step("welcome", self._welcome)
            await _step("weekly", self._weekly)
            if time.monotonic() - self.last_hourly > 3600:
                self.last_hourly = time.monotonic()
                await _step("prune", self._prune)
                await _step("sessions", self._sessions)
                await _step("directory sync", self._directory)

    async def _tls(self) -> None:
        what = await asyncio.to_thread(tls.ensure)
        if what in ("created", "renewed"):
            log.info("tls: certificate %s", what)

    async def _news(self) -> None:
        since = self.force_since if time.monotonic() < self.force_until else None
        got = await news_svc.refresh_due(force=since or False)
        if got:
            log.info("news: %s", got)
        if since and not got:
            self.force_since = None  # nothing left to do for "fetch now"

    async def _topics(self) -> None:
        """The topics of every stored story, once per rule version (news.backfill_topics – after the upgrade, a rule
        change, the KEV's first fetch); nothing to do: one read of a counter."""
        async with db.session() as s:
            await news_svc.backfill_topics(s)

    async def _health(self) -> None:
        """The sources' states compared with the last known ones – a change worth a message goes out with the notify step."""
        async with db.session() as s:
            n = await source_health.evaluate(s)
        if n:
            log.info("source health: %s state changes to notify", n)

    async def _notify(self) -> None:
        async with db.session() as s:
            sent = await notify.dispatch(s)
        if sent:
            log.info("notify: %s", sent)

    async def _personal(self) -> None:
        """The Vendor News of a person's own products – e-mail, desktop push, their Teams webhook (app/personal.py)."""
        async with db.session() as s:
            sent = await personal.dispatch(s)
        if sent:
            log.info("personal: %s", sent)
        if personal.backlog():
            self.wake()  # a large team: the rest with the next round, right after this one (each round is bounded)

    async def _push(self) -> None:
        async with db.session() as s:
            sent = await webpush.dispatch(s)
        if sent:
            log.info("push: %s", sent)

    async def _prune(self) -> None:
        async with db.session() as s:
            gone = await news_svc.prune(s)
            stats = await source_health.prune(s)
            await personal.prune(s)
            await cve_watch.prune(s)
            from app import weekly

            await weekly.prune(s)
            await api_tokens.prune(s)
            logged = await audit.prune(s)
            await delivery_log.prune(s)  # the delivery log: RETENTION_DAYS
            await reader.prune(s)  # expired mutes, read marks the watermark or the age cover
            await lock_store.prune(s)  # brute-force locks that ran out
        if gone:
            log.info("news: %s old stories removed", gone)
        if stats:
            log.info("source health: %s old fetch records removed", stats)
        if logged:
            log.info("audit: %s entries past the retention removed", logged)
        bruteforce.purge()
        passkeys_api.purge()

    async def _sessions(self) -> None:
        async with db.session() as s:
            await sessions.cleanup(s)

    async def _directory(self) -> None:
        # Teams first (if switched on): who joined or left a team group counts for the roles the sync decides next
        async with db.session() as s:
            got = await teams.sync(s)
        if got:
            log.info("teams: %s", got)
        async with db.session() as s:
            changed = await directory_sync.run(s)
        if changed:
            log.info("directory sync: %s", changed)

    async def _welcome(self) -> None:
        async with db.session() as s:
            sent = await teams.send_welcome(s)
        if sent:
            log.info("teams: %s welcome e-mails sent", sent)

    async def _weekly(self) -> None:
        """A team's weekly review by e-mail (app/weekly.py) – bounded per round, once per team, person and week."""
        from app import weekly

        async with db.session() as s:
            sent = await weekly.run(s)
        if sent:
            log.info("weekly: %s reviews sent", sent)

    async def run(self) -> None:
        while True:
            self.event.clear()
            try:
                await self.round()
            except Exception:  # noqa: BLE001 - one bad round must not end the loop
                log.exception("background round failed")
            try:
                await asyncio.wait_for(self.event.wait(), 60)
            except TimeoutError:
                pass


def warn_weak_key() -> bool:
    """At the start: a short master key (crypto.key_weakness) as a warning – the app starts anyway (an existing install
    must keep running), and the key itself never goes into the log. Shown in Einstellungen → HTTPS as well."""
    weak = crypto.key_weakness()
    if weak:
        log.warning(
            "%s is short (under %d characters or only a few different ones) – a longer random key is advised (docs/BETRIEB.md, SECRET_KEY)",
            "SECRET_KEY" if weak == "env" else f"{crypto.KEY_FILE} in DATA_DIR",
            crypto.MIN_STRONG_KEY,
        )
    return bool(weak)


def create_app() -> FastAPI:
    cfg = get_config()
    loop = FetchLoop()
    vloop = vendor.VendorLoop(notify_wake=loop.wake)
    cloop = catalog_check.CheckLoop(vendor_loop=vloop)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # database, key file and certificates are for this process only (no other user on the host reads them)
        os.umask(0o077)
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            cfg.data_dir.chmod(0o700)
            for f in cfg.data_dir.glob("news.db*"):
                f.chmod(0o600)
        # the master key now, not at the first secret: an unusable secret.key stops the start (crypto.KeyFileError)
        await asyncio.to_thread(crypto.master)
        warn_weak_key()
        db.init(cfg.database_url)
        await db.wait_ready()
        await db.migrate()
        with contextlib.suppress(OSError):
            from app import backup

            backup.sweep()  # leftovers of a backup or restore that was killed (plain-text dump, the key)
        if cfg.sqlite_import:
            # up to 0.1.15 the data was in SQLite: moved once into the empty PostgreSQL, before anything else touches it
            # (a failed import raises – the app does not start rather than serve an empty database)
            await sqlite_import.on_start(cfg.sqlite_path)
        async with db.session() as s:
            await news_svc.ensure_sources(s)
            await issue_setup_token(s)
            await vendor.repair_advisory_cves(s)
        async with db.session() as s:
            await lock_store.load(s)  # the brute-force locks and blocks still running before the restart
        try:
            what = await asyncio.to_thread(tls.ensure)
            log.info("tls: mode %s – %s", cfg.tls_mode, what)
        except OSError as exc:
            log.warning("tls: cannot write the certificate to %s (%s)", cfg.tls_path, exc)
        except Exception:  # noqa: BLE001 - a bad host name in .env must not keep the app from starting
            log.exception("tls: certificate not created")
        loop.last_tls = time.monotonic()
        task = asyncio.create_task(loop.run()) if cfg.run_loop else None
        # Vendor News in a task of its own: its rate-limited requests (NVD) never hold up the news round
        vtask = asyncio.create_task(vloop.run()) if cfg.run_loop else None
        # Katalog-Pflege: the catalogue self-test, a few NVD requests an hour at most (app/catalog_check.py)
        ctask = asyncio.create_task(cloop.run()) if cfg.run_loop else None
        # the restore test's schedule (app/restore_test.py): a look every ten minutes whether one is due
        rtask = asyncio.create_task(restore_test.Loop().run()) if cfg.run_loop else None
        log.info("Cobe News %s – data in %s, %s", __version__, cfg.data_dir, cfg.base_url)
        try:
            yield
        finally:
            if task:
                task.cancel()
            if vtask:
                vtask.cancel()
            if ctask:
                ctask.cancel()
            if rtask:
                rtask.cancel()
            for t in list(teams._tasks):
                t.cancel()
            await db.dispose()

    app = FastAPI(title="Cobe News", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.wake = loop.wake
    app.state.force = loop.force
    app.state.loop = loop
    app.state.vendor_wake = vloop.wake
    app.state.vendor_force = vloop.force
    app.state.vendor_catalog = vloop.refresh_catalog
    app.state.catalog_check = cloop
    app.state.vendor_loop = vloop
    app.include_router(auth_router)
    # passkeys (WebAuthn) and "Meine Sitzungen" – the own ones and the admins' view of an account's
    app.include_router(passkeys_api.router)
    app.include_router(passkeys_api.admin_router)
    app.include_router(sessions_api.router)
    app.include_router(sessions_api.admin_router)
    app.include_router(admin_router)
    app.include_router(notify_router)
    app.include_router(delivery_log_router)
    app.include_router(push_router)
    app.include_router(health_router)
    app.include_router(teams_router)
    app.include_router(forward_router)
    app.include_router(personal_router)
    app.include_router(watch_router)
    app.include_router(reader_router)
    app.include_router(calendar_feed.api)
    # the calendar feed: outside /api/ (no cookie, no CSRF – a GET with a token of its own, app/calendar_feed.py)
    app.include_router(calendar_feed.router)
    app.include_router(vendor_router)
    app.include_router(catalog_care_router)
    app.include_router(changelog_router)
    # API tokens: the admins' list, the documented read-only API (/api/v1) and /metrics – a bearer token reaches only
    # these two (api_tokens.precheck below), never the UI's endpoints; the restore test's page (app/restore_test.py)
    app.include_router(api_tokens.router)
    app.include_router(restore_test.router)
    app.include_router(audit_api.router)
    app.include_router(api_v1.router)
    app.include_router(metrics.router)
    app.include_router(docs_router)
    app.include_router(router)

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": {"code": "invalid", "errors": str(exc.errors())[:500]}}, status_code=422)

    @app.exception_handler(api_tokens.TokenError)
    async def _token_refused(request: Request, exc: api_tokens.TokenError) -> JSONResponse:
        return exc.response

    # the request body limit – inside the guard below (added first: Starlette's last added middleware is the outermost),
    # so its 413 gets the security headers and the access log line like every answer
    app.add_middleware(bodylimit.BodyLimit, limit=cfg.max_body_bytes)

    @app.middleware("http")
    async def _guard(request: Request, call_next):
        api = request.url.path.startswith("/api/")
        if api and ("%00" in request.url.query or "\x00" in request.url.path):
            # a NUL in a query parameter (?q=%00): PostgreSQL cannot compare text with it – refused like a bad body
            return _secure_headers(request, JSONResponse({"detail": {"code": "invalid", "errors": "NUL character (U+0000) not allowed"}}, status_code=422), api)
        # an API token (Authorization: Bearer): only GET, only /api/v1/… and /metrics, never with a session cookie
        token = api_tokens.bearer(request) is not None
        if token and (refused := api_tokens.precheck(request)) is not None:
            return _secure_headers(request, refused, api)
        csrf_name = sessions.csrf_cookie_name()
        csrf = request.cookies.get(csrf_name) or ""
        if api and request.method not in SAFE:
            sent = request.headers.get("x-csrf-token") or ""
            if not csrf or not sent or not hmac.compare_digest(csrf, sent):
                suspicious.csrf_failed(request.method, request.url.path, client_ip(request), cookie=bool(csrf), header=bool(sent))  # throttled
                return _secure_headers(request, JSONResponse({"detail": {"code": "csrf_failed"}}, status_code=403), api)
        t0 = time.monotonic()
        # the client address for the audit log (app/audit.py) – an account's actions record where they came from
        ip_token = audit.set_ip(client_ip(request)) if api else None
        try:
            resp = await call_next(request)
        finally:
            if ip_token is not None:
                audit.reset_ip(ip_token)
        if api and not csrf and not token:
            # double submit: readable by the page (it sends it back as X-CSRF-Token), useless to another site
            resp.set_cookie(csrf_name, secrets.token_urlsafe(32), httponly=False, secure=cfg.cookie_secure, samesite="strict", path="/")
            if csrf_name != sessions.CSRF_COOKIE and sessions.CSRF_COOKIE in request.cookies:
                resp.delete_cookie(sessions.CSRF_COOKIE, path="/")  # the unprefixed one of older versions
        _secure_headers(request, resp, api)
        if api and request.url.path != "/api/health":
            access.info("%s %s %s %s %.0fms", client_ip(request), request.method, request.url.path, resp.status_code, (time.monotonic() - t0) * 1000)
        return resp

    static = cfg.static_dir
    if (static / "index.html").is_file():
        if (static / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=static / "assets"), name="assets")
        root = static.resolve()

        @app.get("/{path:path}", include_in_schema=False)
        async def spa(path: str):
            # a NUL: Path.resolve() cannot take one (a 500) – nginx refuses it already, the app's own port does not
            if path.startswith("api/") or path == "api" or "\x00" in path:
                return JSONResponse({"detail": {"code": "not_found"}}, status_code=404)
            f = (root / path).resolve()
            if path and f.is_file() and f.is_relative_to(root):
                # the service worker (Web Push): always the current one – the browser checks it on every visit
                return FileResponse(f, headers={"Cache-Control": "no-cache"} if path == "sw.js" else None)
            return FileResponse(root / "index.html", headers={"Cache-Control": "no-cache"})

    return app


app = create_app()
