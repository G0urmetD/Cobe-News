"""Outgoing requests to configured URLs (feeds, notification channels): URL
check, address blocklist, and a transport that connects to exactly the addresses it checked (no DNS rebinding).

Policies:
- feeds (`private_ok=None`): only public addresses unless ALLOW_PRIVATE_FEEDS is set,
- notification channels (`channel_policy()`): public addresses; private ones (an n8n next door) only inside
  WEBHOOK_PRIVATE_NETS,
- the SMTP server and the LDAP directory (`private_ok=True`): private company networks are fine (a relay, the DCs).
Never, for all of them: loopback, link-local, "any", multicast – also not hidden in NAT64 / 6to4 / IPv4-mapped /
IPv4-compatible / IPv4-translated addresses –, the Docker networks this container sits in (the app itself, the bundled
nginx), and the Docker host: the container's default gateway, Docker Desktop's host network 192.168.65.0/24 and names
like host.docker.internal – behind them are services bound to the host's own 127.0.0.1 (other apps, dev servers), which
would see the request as coming from localhost. An address an operator lists explicitly (WEBHOOK_PRIVATE_NETS,
SMTP_ALLOW_INTERNAL) is allowed anyway – a private one, the own Docker networks (a receiver next door in `edge`), the
Docker host –, never loopback, link-local / cloud metadata, "any" or multicast (0.1.26: listing them used to allow them)."""

import asyncio
import ipaddress
import re
import socket
import ssl
from functools import lru_cache
from urllib.parse import urlsplit

import httpcore
import httpx

from app.config import get_config

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")  # local-use NAT64 (RFC 8215): the IPv4 address in the last 32 bits
_6TO4 = ipaddress.ip_network("2002::/16")
_V4_COMPAT = ipaddress.ip_network("::/96")  # deprecated IPv4-compatible ::a.b.c.d (also ::7f00:1)
_V4_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")  # IPv4-translated ::ffff:0:a.b.c.d (SIIT)
# Docker Desktop's host networking: host.docker.internal is 192.168.65.254, gateway.docker.internal 192.168.65.1 – a
# request there reaches whatever listens on the Mac's (or Windows host's) loopback
_THIS_NET = ipaddress.ip_network("0.0.0.0/8")  # "this network": 0.x.y.z reaches the local host on Linux
DOCKER_HOST_NETS = (ipaddress.ip_network("192.168.65.0/24"),)
# names that stand for the Docker host (Docker Desktop, Colima/Lima, OrbStack) – refused as written, whatever they resolve to
_HOST_DOMAINS = ("docker.internal", "lima.internal", "orb.internal")

_HOSTNAME = re.compile(r"^(?=.{1,253}\.?$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")


def valid_url(url: str, *, https_only: bool = False) -> bool:
    """An outgoing URL someone configured: scheme, a real host name or IP (IPv6 in brackets), a port in range – and one
    that the HTTP client parses the same way. The patterns in the models allow too much on their own ("https://0[x:3/")."""
    try:
        parts = urlsplit(url)
        port = parts.port
        httpx.URL(url)
    except (ValueError, httpx.InvalidURL, UnicodeError):
        return False
    if parts.scheme not in (("https",) if https_only else ("http", "https")) or parts.username or parts.password:
        return False
    host = parts.hostname or ""
    if port is not None and not 0 < port < 65536:
        return False
    if parts.netloc.startswith("[") or ":" in host:
        try:
            return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address) and "%" not in host
        except ValueError:
            return False
    return bool(_HOSTNAME.match(host))


def host_name(host: str) -> bool:
    """A name that stands for the Docker host (host.docker.internal, gateway.docker.internal, host.lima.internal …)."""
    h = host.strip("[]").lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in _HOST_DOMAINS)


def channel_policy() -> dict:
    """The target policy of notification channels: public addresses, private ones only inside WEBHOOK_PRIVATE_NETS."""
    cfg = get_config()
    return {"private_ok": False, "allow": cfg.networks(cfg.webhook_private_nets)}


# an IPv4 address in the old inet_aton forms – 2130706433, 0x7f000001, 127.1, 0x7f.1: not an address for the ipaddress
# module, but one for every resolver and proxy (they never ask DNS for it)
_NUMERIC_V4 = re.compile(r"(?:0x[0-9a-f]*|[0-9]+)(?:\.(?:0x[0-9a-f]*|[0-9]+)){0,3}\.?", re.I)


def _literal_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address written as the host – also in an inet_aton form – or None (a name). No DNS lookup."""
    try:
        return ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        pass
    if _NUMERIC_V4.fullmatch(host):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(host.rstrip(".")))
        except OSError:
            return None
    return None


def loopback_name(host: str) -> bool:
    """localhost and every name below it (RFC 6761): the loopback of whoever resolves it – a proxy too."""
    h = host.strip("[]").lower().rstrip(".")
    return h == "localhost" or h.endswith(".localhost")


def forbidden_literal(url: str, *, private_ok: bool | None = None, allow: tuple[Network, ...] = ()) -> bool:
    """With a proxy in between: the proxy resolves names (this server may not even be able to) – only an address written in
    the URL itself (also as 2130706433, 0x7f000001 or 127.1), a name of the Docker host or localhost is checked here,
    without any DNS lookup."""
    try:
        host = httpx.URL(url).host
    except (httpx.InvalidURL, ValueError, UnicodeError):
        return False
    if host_name(host) or loopback_name(host):
        return True
    a = _literal_ip(host)
    if a is None:
        return False
    return _forbidden_ip(a, private_ok, allow)


def forbidden_target(url: str, *, private_ok: bool | None = None, allow: tuple[Network, ...] = ()) -> bool:
    """Outgoing requests to configured URLs: see _forbidden_ip. Blocking (DNS); call in a thread."""
    try:
        host = httpx.URL(url).host
    except (httpx.InvalidURL, ValueError, UnicodeError):
        return True  # no URL a client could send: not a target either
    if host_name(host):
        return True
    try:
        addrs = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addrs = {ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in socket.getaddrinfo(host, None)}
        except (OSError, UnicodeError):  # UnicodeError: empty or overlong labels ("http://.") – no name the client can resolve
            return False  # not resolvable: the request fails anyway (or a proxy resolves it)
    return any(_forbidden_ip(a, private_ok, allow) for a in addrs)


@lru_cache
def stack_networks() -> tuple[Network, ...]:
    """The Docker networks this container is attached to (its directly connected routes, /proc/net/route): the app and
    the bundled nginx live there – never a target of a webhook or a feed. Empty outside Linux/containers."""
    nets: list[Network] = []
    try:
        with open("/proc/net/route") as f:  # noqa: PTH123 - tiny procfs read, once per process
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 8 or parts[1] == "00000000" or parts[7] == "00000000":
                    continue
                dest = ipaddress.IPv4Address(bytes.fromhex(parts[1])[::-1])
                mask = ipaddress.IPv4Address(bytes.fromhex(parts[7])[::-1])
                net = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
                if net.prefixlen >= 12:  # a Docker bridge network, not a route to half the world
                    nets.append(net)
    except (OSError, ValueError):
        pass
    return tuple(nets)


@lru_cache
def container_gateway() -> str | None:
    """This container's default gateway (/proc/net/route). Behind Docker's port publishing – always under Docker Desktop
    and Colima on a Mac, where the real addresses are lost before nginx sees them – every request arrives from here."""
    try:
        with open("/proc/net/route") as f:  # noqa: PTH123 - tiny procfs read, once per process
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    return str(ipaddress.IPv4Address(bytes.fromhex(parts[2])[::-1]))
    except (OSError, ValueError):
        pass
    return None


def shared_address(ip: str) -> bool:
    """An address that stands for many people: the Docker gateway, a trusted proxy itself (a request without a usable
    X-Forwarded-For) or one of SHARED_ADDRESSES (an office NAT). Never blocked automatically – that would lock everyone
    out; failures through it are slowed down instead (auth/bruteforce.py). Only configuration decides, never a header."""
    try:
        a = _embedded(ipaddress.ip_address(ip))
    except ValueError:
        return False
    cfg = get_config()
    if str(a) == container_gateway():
        return True
    return any(a in n for n in (*cfg.trusted_networks, *cfg.networks(cfg.shared_addresses)))


def _embedded(a: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """The IPv4 address an IPv6 address carries: ::ffff:127.0.0.1 (mapped), ::ffff:0:127.0.0.1 (translated), ::127.0.0.1
    (compatible, also ::7f00:1), 64:ff9b::7f00:1 and 64:ff9b:1::/48 (NAT64), 2002:7f00:1::/48 (6to4)."""
    if isinstance(a, ipaddress.IPv6Address):
        if a.ipv4_mapped:
            return a.ipv4_mapped
        if a in _NAT64 or a in _NAT64_LOCAL or a in _V4_TRANSLATED:
            return ipaddress.IPv4Address(int(a) & 0xFFFFFFFF)
        if a in _V4_COMPAT and int(a) > 1:  # not :: and ::1 themselves (unspecified, loopback – refused as they are)
            return ipaddress.IPv4Address(int(a) & 0xFFFFFFFF)
        if a in _6TO4:
            return ipaddress.IPv4Address((int(a) >> 80) & 0xFFFFFFFF)
    return a


def docker_host(a: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """The Docker host as seen from this container: Docker Desktop's host network or the container's default gateway."""
    a = _embedded(a)
    return any(a in n for n in DOCKER_HOST_NETS) or str(a) == container_gateway()


# cloud metadata services outside link-local: AWS's IPv6 address (a ULA – would count as merely private otherwise)
_METADATA = (ipaddress.ip_network("fd00:ec2::254/128"),)


def never(a: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Never a target, whatever is listed (WEBHOOK_PRIVATE_NETS, SMTP_ALLOW_INTERNAL): loopback, link-local (the cloud
    metadata service 169.254.169.254), fd00:ec2::254, "any" / "this network", multicast – also hidden in an IPv6 form
    (IPv4-mapped, NAT64, 6to4 …: _embedded)."""
    for x in {a, _embedded(a)}:
        if x.is_loopback or x.is_link_local or x.is_unspecified or x.is_multicast or x in _THIS_NET or any(x in n for n in _METADATA):
            return True
    return False


def _forbidden_ip(a: ipaddress.IPv4Address | ipaddress.IPv6Address, private_ok: bool | None = None, allow: tuple[Network, ...] = ()) -> bool:
    """Never, not even when listed (`never`): loopback, link-local (cloud metadata 169.254.169.254, fd00:ec2::254), "any",
    multicast. Unless listed in `allow` (networks an operator named explicitly: WEBHOOK_PRIVATE_NETS,
    SMTP_ALLOW_INTERNAL): this container's own Docker networks, the Docker host (docker_host). Private, shared and
    reserved addresses: allowed with `private_ok=True` (SMTP, LDAP) or when listed; for feeds only with
    ALLOW_PRIVATE_FEEDS – a feed URL is fetched every few minutes and its content shown to every reader. An IPv6 address
    that is not global (ULA, site-local, documentation …) counts as private, too."""
    a = _embedded(a)
    if never(a):
        return True  # also when listed: no list makes loopback or the metadata service a target
    if any(a in n for n in allow):
        return False
    if any(a in n for n in stack_networks()) or docker_host(a):
        return True
    if private_ok is None:
        private_ok = get_config().allow_private
    return not private_ok and not a.is_global


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """Resolves a name once, checks every address it got and connects to exactly those – the check and the connection
    use the same answer. Without this a server could answer the check with a harmless address and the connection a
    moment later with 127.0.0.1 or 169.254.169.254 (DNS rebinding). TLS still checks the name (SNI and certificate
    come from the URL, not from the address)."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend, private_ok: bool | None = None, allow: tuple[Network, ...] = ()) -> None:
        self._inner = inner
        self._private_ok = private_ok
        self._allow = allow

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # noqa: ASYNC109 - httpcore's interface
        if host_name(host):
            raise httpcore.ConnectError("forbidden target")
        try:
            addrs = [ipaddress.ip_address(host.strip("[]").split("%")[0])]
        except ValueError:
            try:
                infos = await asyncio.to_thread(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
            except (OSError, UnicodeError) as exc:
                raise httpcore.ConnectError(f"cannot resolve {host}") from exc
            addrs = list(dict.fromkeys(ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos))
        if not addrs:
            raise httpcore.ConnectError(f"cannot resolve {host}")
        if any(_forbidden_ip(a, self._private_ok, self._allow) for a in addrs):  # one bad answer among good ones is reason enough
            raise httpcore.ConnectError("forbidden target")
        last: Exception | None = None
        for a in addrs:
            try:
                return await self._inner.connect_tcp(str(a), port, timeout=timeout, local_address=local_address, socket_options=socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        raise last or httpcore.ConnectError(f"cannot connect to {host}")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # noqa: ASYNC109, ARG002 - httpcore's interface
        raise httpcore.ConnectError("unix sockets are not a target")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def pinned_transport(verify: ssl.SSLContext | bool = True, *, private_ok: bool | None = None, allow: tuple[Network, ...] = ()) -> httpx.AsyncHTTPTransport:
    """Transport for requests to admin-configured URLs without a proxy (with a proxy, the proxy connects – then only
    addresses written in the URL are checked, see forbidden_literal)."""
    t = httpx.AsyncHTTPTransport(verify=verify, trust_env=False)
    t._pool._network_backend = _PinnedBackend(t._pool._network_backend, private_ok, allow)  # noqa: SLF001 - httpx has no public hook for this
    return t


class ForbiddenTarget(OSError):
    pass


async def mail_socket(host: str, port: int, timeout: float) -> socket.socket:
    """A connected socket to the SMTP server – private company networks fine; never loopback, link-local / cloud
    metadata, "any", multicast, this container's Docker networks or the Docker host, except for addresses in
    SMTP_ALLOW_INTERNAL (a name of the Docker host only when all its addresses are listed there). The name is resolved
    once, every address checked and exactly a checked one connected to (no DNS rebinding); TLS still checks the name
    (aiosmtplib gets it as the hostname). ForbiddenTarget or OSError."""
    allow = get_config().networks(get_config().smtp_allow_internal)
    if host_name(host) and not allow:
        raise ForbiddenTarget("forbidden target")
    try:
        addrs = [ipaddress.ip_address(host.strip("[]").split("%")[0])]
    except ValueError:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
        addrs = list(dict.fromkeys(ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos))
    if not addrs:
        raise socket.gaierror(f"cannot resolve {host}")
    if any(_forbidden_ip(a, True, allow) for a in addrs):
        raise ForbiddenTarget("forbidden target")
    if host_name(host) and not all(any(_embedded(a) in n for n in allow) for a in addrs):
        raise ForbiddenTarget("forbidden target")
    loop = asyncio.get_running_loop()
    last: OSError | None = None
    for a in addrs:
        sock = socket.socket(socket.AF_INET6 if a.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (str(a), port)), timeout)
            return sock
        except OSError as exc:  # TimeoutError included
            sock.close()
            last = exc
    raise last or OSError(f"cannot connect to {host}")


def check_host(host: str) -> None:
    """A directory server (LDAP) by name or address: private company networks fine (the DCs), the rest as for SMTP –
    ForbiddenTarget. Blocking (DNS); a name that does not resolve is left to the connection (it fails there)."""
    if host_name(host):
        raise ForbiddenTarget("forbidden target")
    try:
        addrs = {ipaddress.ip_address(host.strip("[]").split("%")[0])}
    except ValueError:
        try:
            addrs = {ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in socket.getaddrinfo(host, None)}
        except (OSError, UnicodeError):
            return
    if any(_forbidden_ip(a, True) for a in addrs):
        raise ForbiddenTarget("forbidden target")


def target_of(url: str) -> str | None:
    """scheme://host:port of a URL – what a stored secret is bound to (another target: enter the secret again)."""
    try:
        u = httpx.URL(url)
    except (httpx.InvalidURL, ValueError, UnicodeError):
        return None
    if not u.host:
        return None
    port = u.port or (443 if u.scheme == "https" else 80)
    return f"{u.scheme}://{u.host.lower()}:{port}"
