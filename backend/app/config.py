"""Settings from the environment (docker-compose.yml / .env) – everything else is set in the web UI and kept in PostgreSQL."""

import ipaddress
import os
import ssl
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy.engine import URL, make_url

# TRUSTED_PROXIES=none: trust no proxy of your own – also not the Docker gateway with PROXY_ENABLED=0
NO_PROXIES = "none"

# Teams (Workflows / Power Automate, classic Incoming Webhook) and Slack – the hosts their webhook URLs live on
DEFAULT_WEBHOOK_HOSTS = ("hooks.slack.com", "*.webhook.office.com", "*.logic.azure.com", "*.powerplatform.com")


def _flag(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    return default if v is None or not v.strip() else v.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int, low: int, high: int) -> int:
    """A whole number from the environment – empty, not a number or out of range: the default."""
    try:
        v = int((os.environ.get(name) or "").strip().replace("_", ""))
    except ValueError:
        return default
    return v if low <= v <= high else default


def _list(name: str) -> tuple[str, ...]:
    return tuple(x.strip().lower() for x in (os.environ.get(name) or "").split(",") if x.strip())


@dataclass(frozen=True)
class Config:
    data_dir: Path
    static_dir: Path
    # outbound proxy (feeds, Teams, Slack) – may carry user:password; with a proxy only addresses written in the URL are checked
    proxy: str | None = field(repr=False)
    ca_file: str | None  # own CA bundle (e.g. a TLS-inspecting proxy)
    allow_private: bool  # feeds in private networks (10/8, 192.168/16 …) – off: only public addresses
    cookie_secure: bool  # cookies only over https (default; COOKIE_SECURE=0 for plain-http development)
    run_loop: bool  # background fetching in this process (off in tests)
    # HTTPS (services/tls.py)
    tls_mode: str = "selfsigned"  # selfsigned | own | external
    tls_path: Path = Path("/tls")
    hostname: str = ""
    tls_names: tuple[str, ...] = ()
    base_url: str = "https://localhost:8095"
    hsts: bool = False  # also with the self-signed certificate (once it is trusted everywhere)
    # who may set X-Forwarded-For: the bundled nginx (fixed address) and/or own proxies – see trusted_networks
    proxy_enabled: bool = True
    proxy_ip: str = "172.31.250.10"
    trusted_proxies: tuple[str, ...] = ()  # TRUSTED_PROXIES; ("none",): nobody (not even the Docker gateway)
    # addresses that stand for many people (never blocked, see netaddr.shared_address) besides the Docker gateway
    shared_addresses: tuple[str, ...] = ()
    # SMTP server addresses allowed although internal (loopback, link-local, this container's Docker networks), e.g. a
    # relay on the Docker host behind the gateway – addresses or networks
    smtp_allow_internal: tuple[str, ...] = ()
    # private addresses (company network, the Docker host) a notification channel may post to – e.g. an n8n next door.
    # Empty: channels reach public addresses only (docs/BETRIEB.md: Benachrichtigungen → Ziele)
    webhook_private_nets: tuple[str, ...] = ()
    # optional: writes to settings, sources and notification rules need this password
    secret_key: str = field(default="", repr=False)  # encrypts webhook URLs and the SMTP password; empty: a key file in DATA_DIR
    webhook_hosts: tuple[str, ...] = field(default=DEFAULT_WEBHOOK_HOSTS)
    # Web Push (desktop notifications with every tab closed): the server sends to the browser vendors' push services
    web_push: bool = True
    push_contact: str = ""  # VAPID "sub" – a mailto: or https: address the push services may contact; empty: BASE_URL
    # PostgreSQL: DATABASE_URL, or its parts (docker-compose.yml: host "db", the password from .env)
    db_url: str = field(default="", repr=False)  # DATABASE_URL – may hold the password
    db_host: str = "db"
    db_port: int = 5432
    db_name: str = "cobe_news"
    db_user: str = "cobe_news"
    db_password: str = field(default="", repr=False)
    # up to 0.1.15: the SQLite file – moved into an empty PostgreSQL once at the start (app/sqlite_import.py), never changed
    sqlite_import: bool = True
    # backups (app/backup.py): where they go, and the passphrase that encrypts them (with it, the key goes along)
    backup_dir: Path = Path("/data/backups")
    backup_passphrase: str = field(default="", repr=False)
    # the restore test (app/restore_test.py): a throwaway database with a role of its own that has no right on the app's
    # database (db-init makes both when POSTGRES_RESTORE_PASSWORD is set) – RESTORE_TEST_DATABASE_URL instead (tests)
    restore_db_url: str = field(default="", repr=False)
    restore_db_name: str = "cobe_news_restore_test"
    restore_db_user: str = "cobe_news_restore"
    restore_db_password: str = field(default="", repr=False)
    # the largest request body the app takes (app/bodylimit.py) – behind nginx's 1 MB; MAX_BODY_BYTES
    max_body_bytes: int = 1024 * 1024

    @property
    def restore_url(self) -> URL | None:
        """Where the restore test restores to – None: not set up (the test is not offered)."""
        if self.restore_db_url:
            url = make_url(self.restore_db_url)
            return url.set(drivername="postgresql+asyncpg") if url.drivername in ("postgresql", "postgres") else url
        if not self.restore_db_password:
            return None
        return self.database_url.set(username=self.restore_db_user, password=self.restore_db_password, database=self.restore_db_name)

    @property
    def database_url(self) -> URL:
        if self.db_url:
            url = make_url(self.db_url)
            return url.set(drivername="postgresql+asyncpg") if url.drivername in ("postgresql", "postgres") else url
        return URL.create("postgresql+asyncpg", username=self.db_user, password=self.db_password or None, host=self.db_host, port=self.db_port, database=self.db_name)

    @property
    def sqlite_path(self) -> Path:
        return self.data_dir / "news.db"

    @property
    def base_host(self) -> str:
        return (urlsplit(self.base_url).hostname or "").lower()

    @staticmethod
    def networks(items) -> tuple:  # noqa: ANN001
        out = []
        for n in items:
            try:
                out.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                continue
        return tuple(out)

    @property
    def trusted_networks(self) -> tuple:
        """Whose X-Forwarded-For / X-Forwarded-Proto the app believes: the bundled nginx at its fixed address
        (PROXY_ENABLED=1) and TRUSTED_PROXIES. Without the bundled nginx and without TRUSTED_PROXIES (PROXY_ENABLED=0
        alone): this container's default gateway – the Docker host, where a reverse proxy of your own reaches the app's
        port. Safe on a Linux Docker Engine because both compose files publish that port on the host's 127.0.0.1 only:
        what comes from the gateway comes from the host itself (Docker's forwarding of the 127.0.0.1 port, or a process
        of the host straight to the container) – another container comes from its own address, another machine never
        from the gateway. Not on a desktop Docker (netaddr.desktop_docker): there every container reaches the host's
        127.0.0.1 port by host.docker.internal and comes from the gateway, too – nobody is trusted then. TRUSTED_PROXIES
        replaces the gateway; "none" trusts no proxy of your own (docs/BETRIEB.md: HTTPS, 3)."""
        nets = [p for p in self.trusted_proxies if p != NO_PROXIES]
        if self.proxy_enabled and self.proxy_ip:
            nets.append(f"{self.proxy_ip}/32")
        elif not self.trusted_proxies:
            gateway = self.host_proxy_gateway()
            if gateway:
                nets.append(f"{gateway}/32")
        return self.networks(nets)

    @staticmethod
    def host_proxy_gateway() -> str | None:
        """The gateway trusted for PROXY_ENABLED=0 without TRUSTED_PROXIES – None without one or on a desktop Docker."""
        from app import netaddr  # noqa: PLC0415 - netaddr imports this module

        gateway = netaddr.container_gateway()
        return gateway if gateway and not netaddr.desktop_docker() else None

    def proxy_trust(self) -> str:
        """For the log at the start: whose X-Forwarded-For counts, and why. Blocking (DNS, once): call in a thread."""
        from app import netaddr  # noqa: PLC0415 - netaddr imports this module

        nets = ", ".join(str(n.network_address) if n.num_addresses == 1 else str(n) for n in self.trusted_networks) or "nobody"
        own = bool(self.trusted_proxies) and self.trusted_proxies != (NO_PROXIES,)
        if self.proxy_enabled:
            return f"X-Forwarded-For trusted from {nets} (the bundled nginx{' and TRUSTED_PROXIES' if own else ''})"
        if self.trusted_proxies:
            return f"PROXY_ENABLED=0 – X-Forwarded-For trusted from {nets} (TRUSTED_PROXIES)"
        gateway, desktop = netaddr.container_gateway(), netaddr.desktop_docker()
        if gateway and desktop:
            return (
                f"PROXY_ENABLED=0 – {desktop} resolves (a desktop Docker: every container reaches the app's port through the gateway"
                f" {gateway}), so X-Forwarded-For is trusted from nobody; TRUSTED_PROXIES={gateway}/32 trusts the gateway anyway"
            )
        if gateway:
            return f"PROXY_ENABLED=0 – X-Forwarded-For trusted from {nets} (the Docker gateway: a reverse proxy on this host)"
        return "PROXY_ENABLED=0 – no Docker gateway found, X-Forwarded-For trusted from nobody: set TRUSTED_PROXIES to your proxy's address"


@lru_cache
def get_config() -> Config:
    data = Path(os.environ.get("DATA_DIR", "./data")).resolve()
    static = Path(os.environ.get("STATIC_DIR", Path(__file__).resolve().parent.parent / "static"))
    proxy_enabled = _flag("PROXY_ENABLED", True)
    # TLS_MODE empty (or unknown): selfsigned with the bundled nginx, external without it (your own proxy ends TLS)
    mode = (os.environ.get("TLS_MODE") or "").strip().lower()
    if mode not in ("selfsigned", "own", "external"):
        mode = "selfsigned" if proxy_enabled else "external"
    return Config(
        data_dir=data,
        static_dir=static,
        proxy=(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "").strip() or None,
        ca_file=(os.environ.get("CA_FILE") or "").strip() or None,
        allow_private=_flag("ALLOW_PRIVATE_FEEDS"),
        cookie_secure=_flag("COOKIE_SECURE", True),
        run_loop=_flag("NEWS_LOOP", True),
        tls_mode=mode,
        tls_path=Path(os.environ.get("TLS_PATH") or (data / "tls")),
        hostname=(os.environ.get("NEWS_HOSTNAME") or "").strip().lower(),
        tls_names=_list("TLS_NAMES"),
        base_url=(os.environ.get("BASE_URL") or "https://localhost:8095").strip().rstrip("/"),
        hsts=_flag("HSTS"),
        proxy_enabled=proxy_enabled,
        proxy_ip=(os.environ.get("PROXY_IP") or "172.31.250.10").strip(),
        trusted_proxies=_list("TRUSTED_PROXIES"),
        shared_addresses=_list("SHARED_ADDRESSES"),
        smtp_allow_internal=_list("SMTP_ALLOW_INTERNAL"),
        webhook_private_nets=_list("WEBHOOK_PRIVATE_NETS"),
        secret_key=os.environ.get("SECRET_KEY") or "",
        webhook_hosts=DEFAULT_WEBHOOK_HOSTS + _list("WEBHOOK_HOSTS"),
        web_push=_flag("WEB_PUSH", True),
        push_contact=(os.environ.get("PUSH_CONTACT") or "").strip(),
        db_url=(os.environ.get("DATABASE_URL") or "").strip(),
        db_host=(os.environ.get("POSTGRES_HOST") or "db").strip(),
        db_port=int(os.environ.get("POSTGRES_PORT") or 5432),
        db_name=(os.environ.get("POSTGRES_DB") or "cobe_news").strip(),
        db_user=(os.environ.get("POSTGRES_USER") or "cobe_news").strip(),
        db_password=os.environ.get("POSTGRES_PASSWORD") or "",
        sqlite_import=_flag("SQLITE_IMPORT", True),
        backup_dir=Path(os.environ.get("BACKUP_DIR") or (data / "backups")),
        backup_passphrase=os.environ.get("BACKUP_PASSPHRASE") or "",
        restore_db_url=(os.environ.get("RESTORE_TEST_DATABASE_URL") or "").strip(),
        restore_db_name=(os.environ.get("POSTGRES_RESTORE_DB") or "cobe_news_restore_test").strip(),
        restore_db_user=(os.environ.get("POSTGRES_RESTORE_USER") or "cobe_news_restore").strip(),
        restore_db_password=os.environ.get("POSTGRES_RESTORE_PASSWORD") or "",
        max_body_bytes=_int("MAX_BODY_BYTES", 1024 * 1024, 16 * 1024, 64 * 1024 * 1024),
    )


@lru_cache
def tls_verify() -> ssl.SSLContext | bool:
    """TLS is always checked; with CA_FILE also against that bundle (in addition to the system CAs)."""
    cfg = get_config()
    if not cfg.ca_file:
        return True
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cfg.ca_file)
    return ctx
