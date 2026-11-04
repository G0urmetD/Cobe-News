"""Behind your own reverse proxy with one switch: PROXY_ENABLED=0 alone makes TLS external (unless TLS_MODE says
otherwise) and trusts X-Forwarded-For / -Proto from the container's default gateway – the Docker host, where the proxy
reaches the app's port (published on 127.0.0.1 only). Never on a desktop Docker (every container reaches that port by
host.docker.internal, from the gateway too), never while the bundled nginx runs; TRUSTED_PROXIES replaces the gateway,
"none" trusts nobody. Another container in the network comes from its own address: its header never counts."""

import dataclasses
import logging
import socket

import pytest
from conftest import make_client

from app import config, deps, netaddr, tls

GATEWAY = "172.31.250.128"  # what Docker gives the network edge by default: the first address of EDGE_RANGE


@pytest.fixture
def use(monkeypatch):
    """A config of our own for the client address (deps) and the shared addresses (netaddr); a gateway, no desktop."""
    monkeypatch.setattr(netaddr, "container_gateway", lambda: GATEWAY)
    monkeypatch.setattr(netaddr, "desktop_docker", lambda: None)

    def set_(**kw) -> config.Config:
        c = dataclasses.replace(config.get_config(), **kw)
        monkeypatch.setattr(deps, "get_config", lambda: c)
        monkeypatch.setattr(netaddr, "get_config", lambda: c)
        monkeypatch.setattr(tls, "get_config", lambda: c)
        return c

    return set_


def _nets(c: config.Config) -> list[str]:
    return [str(n) for n in c.trusted_networks]


@pytest.mark.parametrize(
    ("env", "mode"),
    [
        ({}, "selfsigned"),
        ({"PROXY_ENABLED": "0"}, "external"),
        ({"PROXY_ENABLED": "0", "TLS_MODE": ""}, "external"),
        ({"PROXY_ENABLED": "0", "TLS_MODE": "own"}, "own"),
        ({"PROXY_ENABLED": "0", "TLS_MODE": "selfsigned"}, "selfsigned"),
        ({"PROXY_ENABLED": "1", "TLS_MODE": "external"}, "external"),
        ({"PROXY_ENABLED": "1", "TLS_MODE": "bogus"}, "selfsigned"),
        ({"PROXY_ENABLED": "0", "TLS_MODE": "bogus"}, "external"),
    ],
)
def test_tls_mode_follows_the_switch_unless_set(monkeypatch, env, mode):
    for k in ("PROXY_ENABLED", "TLS_MODE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    config.get_config.cache_clear()
    try:
        assert config.get_config().tls_mode == mode
    finally:
        config.get_config.cache_clear()


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


def test_no_gateway_and_desktop_docker_trust_nobody(use, monkeypatch):
    c = use(proxy_enabled=False, trusted_proxies=())
    monkeypatch.setattr(netaddr, "container_gateway", lambda: None)
    assert _nets(c) == []
    assert "no Docker gateway found" in c.proxy_trust()
    monkeypatch.setattr(netaddr, "container_gateway", lambda: GATEWAY)
    monkeypatch.setattr(netaddr, "desktop_docker", lambda: "host.docker.internal")
    assert _nets(c) == []
    msg = c.proxy_trust()
    assert "host.docker.internal resolves" in msg and f"TRUSTED_PROXIES={GATEWAY}/32" in msg and "trusted from nobody" in msg
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


def test_desktop_docker_is_a_name_of_the_host_that_resolves(monkeypatch):
    asked: list[str] = []

    def resolve(name, *a, **kw):  # noqa: ANN001, ANN002, ANN003, ANN202
        asked.append(name)
        if name == "host.lima.internal.":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.5.2", 0))]
        raise socket.gaierror("no such name")

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    netaddr.desktop_docker.cache_clear()
    try:
        assert netaddr.desktop_docker() == "host.lima.internal"
        assert all(n.endswith(".") for n in asked)  # absolute: no search domain of the host appended
        asked.clear()
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: (_ for _ in ()).throw(socket.gaierror("nx")))
        netaddr.desktop_docker.cache_clear()
        assert netaddr.desktop_docker() is None  # a Linux Docker Engine: none of the names exists
    finally:
        netaddr.desktop_docker.cache_clear()


async def test_own_proxy_on_the_host_reports_the_client_another_container_does_not(use, caplog):
    use(proxy_enabled=False, trusted_proxies=(), tls_mode="external")
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


async def test_with_the_bundled_nginx_the_gateway_is_never_trusted(use, caplog):
    use(proxy_enabled=True, trusted_proxies=())
    with caplog.at_level(logging.INFO, logger="cobe_news.access"):
        async with make_client(client=(GATEWAY, 40000)) as c:
            await c.get("/api/auth/config", headers={"X-Forwarded-For": "203.0.113.9"})
    lines = [r.getMessage() for r in caplog.records if "/api/auth/config" in r.getMessage()]
    assert lines and lines[0].startswith(f"{GATEWAY} ")
    assert netaddr.shared_address(GATEWAY)  # still a shared address: never blocked
