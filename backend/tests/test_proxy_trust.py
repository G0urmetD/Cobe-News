"""Behind your own reverse proxy with one switch: PROXY_ENABLED=0 alone makes TLS external (unless TLS_MODE says
otherwise – HSTS only when TLS_MODE=external is written down) and trusts X-Forwarded-For / -Proto from the container's
default gateway – the Docker host, where the proxy reaches the app's port (published on 127.0.0.1 only). Fails closed:
only a gateway inside EDGE_SUBNET, only on a Linux Docker Engine for sure – never on a desktop Docker (kernel or a host
name that resolves: every container reaches that port, from the gateway too), never when the resolver gives no clear
answer, never while the bundled nginx runs. TRUSTED_PROXIES replaces the gateway, "none" trusts nobody; an entry in the
network edge that misses its gateway (the old advice 172.31.250.1) is warned about. Another container in the network
comes from its own address: its header never counts."""

import dataclasses
import logging
import socket
import threading
import time

import pytest
from conftest import make_client

from app import config, deps, netaddr, tls

GATEWAY = "172.31.250.128"  # what Docker gives the network edge by default: the first address of EDGE_RANGE
EDGE = "172.31.250.0/24"
ENGINE = netaddr.HostKind("engine", "none of the host names exists")


@pytest.fixture
def use(monkeypatch):
    """A config of our own for the client address (deps), the shared addresses (netaddr) and HSTS (tls); a gateway in
    the network edge on a Linux Docker Engine."""
    monkeypatch.setattr(netaddr, "container_gateway", lambda: GATEWAY)
    monkeypatch.setattr(netaddr, "host_kind", lambda: ENGINE)
    monkeypatch.setattr(netaddr, "check_host_kind", lambda budget=netaddr.DNS_BUDGET_S: ENGINE)

    def set_(**kw) -> config.Config:
        c = dataclasses.replace(config.get_config(), **{"edge_subnet": EDGE, **kw})
        monkeypatch.setattr(deps, "get_config", lambda: c)
        monkeypatch.setattr(netaddr, "get_config", lambda: c)
        monkeypatch.setattr(tls, "get_config", lambda: c)
        return c

    return set_


@pytest.fixture
def fresh_kind(monkeypatch):
    """The real check_host_kind / host_kind with a kernel and a resolver of the test's choice."""
    netaddr.reset_host_kind()
    monkeypatch.setattr(netaddr, "_kernel_release", lambda: "6.8.0-48-generic")
    yield monkeypatch
    netaddr.reset_host_kind()


def _gaierror(code: int) -> socket.gaierror:
    return socket.gaierror(code, "test")


def _raise(error: BaseException):  # noqa: ANN202
    def answer(name):  # noqa: ANN001, ANN202, ARG001
        raise error

    return answer


def _resolver(monkeypatch, answer):  # noqa: ANN001, ANN202
    asked: list[str] = []

    def resolve(name, *a, **kw):  # noqa: ANN001, ANN002, ANN003, ANN202, ARG001
        asked.append(name)
        return answer(name)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    return asked


def _nets(c: config.Config) -> list[str]:
    return [str(n) for n in c.trusted_networks]


@pytest.mark.parametrize(
    ("env", "mode", "explicit"),
    [
        ({}, "selfsigned", False),
        ({"PROXY_ENABLED": "0"}, "external", False),
        ({"PROXY_ENABLED": "0", "TLS_MODE": ""}, "external", False),
        ({"PROXY_ENABLED": "0", "TLS_MODE": "external"}, "external", True),
        ({"PROXY_ENABLED": "0", "TLS_MODE": "own"}, "own", True),
        ({"PROXY_ENABLED": "0", "TLS_MODE": "selfsigned"}, "selfsigned", True),
        ({"PROXY_ENABLED": "1", "TLS_MODE": "external"}, "external", True),
        ({"PROXY_ENABLED": "1", "TLS_MODE": "bogus"}, "selfsigned", False),
        ({"PROXY_ENABLED": "0", "TLS_MODE": "bogus"}, "external", False),
    ],
)
def test_tls_mode_follows_the_switch_unless_set(monkeypatch, env, mode, explicit):
    for k in ("PROXY_ENABLED", "TLS_MODE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("EDGE_SUBNET", " 172.31.251.0/24 ")
    config.get_config.cache_clear()
    try:
        c = config.get_config()
        assert (c.tls_mode, c.tls_mode_explicit, c.edge_subnet) == (mode, explicit, "172.31.251.0/24")
    finally:
        config.get_config.cache_clear()


def test_hsts_only_for_an_external_mode_written_down(use):
    """Up to 0.1.48 PROXY_ENABLED=0 without TLS_MODE was selfsigned – no HSTS. The implied external keeps it so."""
    use(tls_mode="external", tls_mode_explicit=False, hsts=False)
    assert tls.hsts() is False
    use(tls_mode="external", tls_mode_explicit=True, hsts=False)
    assert tls.hsts() is True
    use(tls_mode="external", tls_mode_explicit=False, hsts=True)  # HSTS=1 switches it on in every mode, as before
    assert tls.hsts() is True
    use(tls_mode="own", tls_mode_explicit=True, hsts=False)
    assert tls.hsts() is True
    use(tls_mode="selfsigned", tls_mode_explicit=False, hsts=False)
    assert tls.hsts() is False


def test_who_is_trusted(use):
    # the bundled nginx: its fixed address only – never the gateway (Docker Desktop: every client comes from there)
    assert _nets(use(proxy_enabled=True, trusted_proxies=())) == ["172.31.250.10/32"]
    assert _nets(use(proxy_enabled=True, trusted_proxies=("10.0.0.5/32",))) == ["10.0.0.5/32", "172.31.250.10/32"]
    assert _nets(use(proxy_enabled=True, trusted_proxies=("none",))) == ["172.31.250.10/32"]
    # PROXY_ENABLED=0 alone: the gateway
    assert _nets(use(proxy_enabled=False, trusted_proxies=())) == [f"{GATEWAY}/32"]
    # TRUSTED_PROXIES replaces it (a proxy container at a fixed address in edge); "none": nobody
    assert _nets(use(proxy_enabled=False, trusted_proxies=("172.31.250.20/32",))) == ["172.31.250.20/32"]
    assert _nets(use(proxy_enabled=False, trusted_proxies=("none",))) == []


@pytest.mark.parametrize("edge", ["", "not-a-network", "10.0.0.0/8", "172.31.251.0/24"])
def test_the_gateway_only_inside_edge_subnet(use, edge):
    """No EDGE_SUBNET, a broken one or a gateway outside it (network_mode: host – the LAN router): nobody."""
    c = use(proxy_enabled=False, trusted_proxies=(), edge_subnet=edge)
    assert _nets(c) == []
    msg = c.proxy_trust()
    assert "trusted from nobody" in msg
    assert ("EDGE_SUBNET not set" in msg) if edge in ("", "not-a-network") else (f"not in EDGE_SUBNET {edge}" in msg)


def test_no_gateway_desktop_and_unknown_trust_nobody(use, monkeypatch):
    c = use(proxy_enabled=False, trusted_proxies=())
    monkeypatch.setattr(netaddr, "container_gateway", lambda: None)
    assert _nets(c) == [] and "no Docker gateway found" in c.proxy_trust()
    monkeypatch.setattr(netaddr, "container_gateway", lambda: GATEWAY)
    for kind, said in (
        (netaddr.HostKind("desktop", "kernel 6.10.14-linuxkit"), "a desktop Docker (kernel 6.10.14-linuxkit)"),
        (netaddr.HostKind("unknown", "host.docker.internal: error: [Errno -3] Temporary failure"), "cannot tell whether this is a desktop Docker"),
    ):
        monkeypatch.setattr(netaddr, "host_kind", lambda k=kind: k)
        monkeypatch.setattr(netaddr, "check_host_kind", lambda budget=netaddr.DNS_BUDGET_S, k=kind: k)
        assert _nets(c) == []
        msg = c.proxy_trust()
        assert said in msg and f"TRUSTED_PROXIES={GATEWAY}/32" in msg and "trusted from nobody" in msg, msg
    # written explicitly, the gateway counts on a desktop as well
    assert _nets(use(proxy_enabled=False, trusted_proxies=(f"{GATEWAY}/32",))) == [f"{GATEWAY}/32"]


def test_the_log_line_says_whom_and_why(use):
    assert use(proxy_enabled=True, trusted_proxies=()).proxy_trust() == "X-Forwarded-For trusted from 172.31.250.10 (the bundled nginx)"
    assert "and TRUSTED_PROXIES" in use(proxy_enabled=True, trusted_proxies=("10.0.0.5",)).proxy_trust()
    assert use(proxy_enabled=False, trusted_proxies=()).proxy_trust() == (
        f"PROXY_ENABLED=0 – X-Forwarded-For trusted from {GATEWAY} (the Docker gateway: a reverse proxy on this host)"
    )
    assert use(proxy_enabled=False, trusted_proxies=("172.31.250.20/32",)).proxy_trust().endswith("172.31.250.20 (TRUSTED_PROXIES)")
    assert "from nobody" in use(proxy_enabled=False, trusted_proxies=("none",)).proxy_trust()


def test_a_trusted_proxy_beside_the_gateway_is_warned_about(use):
    # the advice of 0.1.48: .1 – named as such
    (w,) = use(proxy_enabled=False, trusted_proxies=("172.31.250.1/32",)).proxy_warnings()
    assert "TRUSTED_PROXIES=172.31.250.1/32" in w and f"not on its gateway {GATEWAY}" in w and "up to 0.1.48" in w and "Remove TRUSTED_PROXIES" in w
    # another address in edge (could be a proxy container – said so), without the 0.1.48 remark
    (w,) = use(proxy_enabled=False, trusted_proxies=("172.31.250.20/32",)).proxy_warnings()
    assert "172.31.250.20/32" in w and "up to 0.1.48" not in w and "proxy container" in w
    # nothing to say: the gateway covered, outside edge, "none", no TRUSTED_PROXIES, the bundled nginx, no edge subnet
    assert use(proxy_enabled=False, trusted_proxies=(f"{GATEWAY}/32",)).proxy_warnings() == []
    assert use(proxy_enabled=False, trusted_proxies=("172.31.250.0/24",)).proxy_warnings() == []
    assert use(proxy_enabled=False, trusted_proxies=("10.0.0.5/32",)).proxy_warnings() == []
    assert use(proxy_enabled=False, trusted_proxies=("none",)).proxy_warnings() == []
    assert use(proxy_enabled=False, trusted_proxies=()).proxy_warnings() == []
    assert use(proxy_enabled=True, trusted_proxies=("172.31.250.1/32",)).proxy_warnings() == []
    assert use(proxy_enabled=False, trusted_proxies=("172.31.250.1/32",), edge_subnet="").proxy_warnings() == []


def test_the_kernel_of_a_desktop_vm_needs_no_dns(fresh_kind):
    asked = _resolver(fresh_kind, lambda name: [])
    for release in ("6.10.14-linuxkit", "6.13.7-orbstack-00274-g2f2d1b0e5fd8", "5.15.167.4-microsoft-standard-WSL2"):
        netaddr.reset_host_kind()
        fresh_kind.setattr(netaddr, "_kernel_release", lambda r=release: r)
        kind = netaddr.check_host_kind()
        assert kind.kind == "desktop" and release in kind.why
    assert asked == []


def test_a_host_name_that_resolves_is_a_desktop(fresh_kind):
    def answer(name):  # noqa: ANN001, ANN202
        if name == "host.lima.internal.":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.5.2", 0))]
        raise _gaierror(socket.EAI_NONAME)

    asked = _resolver(fresh_kind, answer)
    assert netaddr.check_host_kind() == netaddr.HostKind("desktop", "host.lima.internal resolves")
    assert sorted(asked) == sorted(netaddr.DESKTOP_HOST_NAMES) and all(n.endswith(".") for n in asked)  # absolute names


@pytest.mark.parametrize("code", [socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)])
def test_only_names_that_do_not_exist_make_an_engine(fresh_kind, code):
    _resolver(fresh_kind, _raise(_gaierror(code)))
    assert netaddr.check_host_kind().kind == "engine"
    _resolver(fresh_kind, _raise(_gaierror(socket.EAI_AGAIN)))
    assert netaddr.check_host_kind().kind == "engine"  # a clear answer is kept


@pytest.mark.parametrize("error", [_gaierror(socket.EAI_AGAIN), _gaierror(socket.EAI_FAIL), OSError("network unreachable"), UnicodeError("label")])
def test_a_resolver_error_is_unknown_and_not_kept(fresh_kind, error):
    def answer(name):  # noqa: ANN001, ANN202
        if name == "host.docker.internal.":
            raise error
        raise _gaierror(socket.EAI_NONAME)

    _resolver(fresh_kind, answer)
    kind = netaddr.check_host_kind()
    assert kind.kind == "unknown" and "host.docker.internal: error" in kind.why
    # not kept: once the resolver answers clearly, the next check knows
    _resolver(fresh_kind, _raise(_gaierror(socket.EAI_NONAME)))
    assert netaddr.check_host_kind().kind == "engine"


def test_a_slow_resolver_is_cut_off_and_unknown(fresh_kind):
    release = threading.Event()

    def answer(name):  # noqa: ANN001, ANN202
        if name == "gateway.docker.internal.":
            release.wait(5)  # an unreachable DNS server: EAI_AGAIN only after seconds
        raise _gaierror(socket.EAI_NONAME)

    _resolver(fresh_kind, answer)
    t0 = time.monotonic()
    kind = netaddr.check_host_kind(budget=0.3)
    release.set()
    assert time.monotonic() - t0 < 1.5  # the start never waits for it
    assert kind.kind == "unknown" and "gateway.docker.internal: no answer within 0.3 s" in kind.why


def test_the_request_path_never_waits_and_asks_again_in_the_background(fresh_kind):
    calls: list[str] = []

    def answer(name):  # noqa: ANN001, ANN202
        calls.append(name)
        raise _gaierror(socket.EAI_AGAIN)

    _resolver(fresh_kind, answer)
    assert netaddr.host_kind() == netaddr.HostKind("unknown", "not checked yet")  # nothing kept: unknown, a check starts
    for _ in range(100):
        if len(calls) == len(netaddr.DESKTOP_HOST_NAMES) and not netaddr._host_kind_lock.locked():  # noqa: SLF001
            break
        time.sleep(0.02)
    assert len(calls) == len(netaddr.DESKTOP_HOST_NAMES)
    assert netaddr.host_kind().kind == "unknown"  # still unknown (EAI_AGAIN) – and within RECHECK_S no new check
    time.sleep(0.1)
    assert len(calls) == len(netaddr.DESKTOP_HOST_NAMES)
    # a clear answer later is kept and used without asking
    _resolver(fresh_kind, _raise(_gaierror(socket.EAI_NONAME)))
    assert netaddr.check_host_kind().kind == "engine" and netaddr.host_kind().kind == "engine"


async def test_own_proxy_on_the_host_reports_the_client_another_container_does_not(use, caplog):
    use(proxy_enabled=False, trusted_proxies=(), tls_mode="external", tls_mode_explicit=True)
    forged = {"X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https", "Host": "news.corp.example"}
    with caplog.at_level(logging.INFO, logger="cobe_news.access"):
        # the host's nginx through the published 127.0.0.1 port: arrives from the gateway – its header counts
        async with make_client(client=(GATEWAY, 40000)) as c:
            r = await c.get("/api/auth/config", headers=forged)
            assert r.status_code == 200 and r.headers.get("strict-transport-security")  # https, says the proxy
        # another container in the network edge with a forged header: its own address, no https
        async with make_client(client=("172.31.250.130", 40000)) as c:
            r = await c.get("/api/auth/config", headers={**forged, "X-Forwarded-For": "198.51.100.66"})
            assert r.status_code == 200 and "strict-transport-security" not in r.headers
    lines = [r.getMessage() for r in caplog.records if "/api/auth/config" in r.getMessage()]
    assert lines[0].startswith("203.0.113.7 ") and lines[1].startswith("172.31.250.130 "), lines
    assert not any("198.51.100.66" in x for x in lines)


async def test_implied_external_sends_no_hsts(use):
    use(proxy_enabled=False, trusted_proxies=(), tls_mode="external", tls_mode_explicit=False)
    async with make_client(client=(GATEWAY, 40000)) as c:
        r = await c.get("/api/auth/config", headers={"X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https", "Host": "news.corp.example"})
    assert r.status_code == 200 and "strict-transport-security" not in r.headers


async def test_with_the_bundled_nginx_the_gateway_is_never_trusted(use, caplog):
    use(proxy_enabled=True, trusted_proxies=())
    with caplog.at_level(logging.INFO, logger="cobe_news.access"):
        async with make_client(client=(GATEWAY, 40000)) as c:
            await c.get("/api/auth/config", headers={"X-Forwarded-For": "203.0.113.9"})
    lines = [r.getMessage() for r in caplog.records if "/api/auth/config" in r.getMessage()]
    assert lines and lines[0].startswith(f"{GATEWAY} ")
    assert netaddr.shared_address(GATEWAY)  # still a shared address: never blocked
