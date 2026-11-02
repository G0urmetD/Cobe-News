"""The egress guard (app/netaddr.py) and the Docker host: security review 0.1.16 M3 and L9.

Under Docker Desktop host.docker.internal (192.168.65.254) and the container's gateway reach services that listen only
on the host's 127.0.0.1 – a webhook, SMTP or LDAP test there arrived as "localhost". Notification channels reach
private addresses only when WEBHOOK_PRIVATE_NETS lists them; IPv6 forms that carry an IPv4 address are decoded."""

import asyncio
import dataclasses
import ipaddress
import socket

import httpcore
import httpx
import pytest

from app import config, netaddr, news, notify
from app.auth import ldap_dir

ip = ipaddress.ip_address


@pytest.fixture
def cfg(monkeypatch):
    """A config of our own for netaddr (frozen dataclass: replaced, not changed)."""

    def use(**kw):
        c = dataclasses.replace(config.get_config(), **kw)
        monkeypatch.setattr(netaddr, "get_config", lambda: c)
        return c

    use(smtp_allow_internal=(), webhook_private_nets=())
    return use


@pytest.mark.parametrize(
    "url",
    [
        "http://host.docker.internal:18099/internal-admin-api",  # the PoC
        "http://gateway.docker.internal/x",
        "http://HOST.DOCKER.INTERNAL./x",
        "http://host.lima.internal/x",  # Colima
        "http://192.168.65.254:18099/x",  # what host.docker.internal resolves to
        "http://192.168.65.1/x",
        "http://[::ffff:192.168.65.254]/x",
    ],
)
async def test_webhook_never_targets_the_docker_host(admin_client, cfg, url):
    cfg(webhook_private_nets=("10.0.0.0/8",))  # private targets allowed – the Docker host still is not
    r = await admin_client.post("/api/admin/notify/channels", json={"name": "bad", "type": "webhook", "url": url, "allow_http": True})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "url_forbidden_target", url
    with pytest.raises(notify.NotifyError) as e:
        notify.check_url("webhook", url, allow_http=True)
    assert e.value.category == "forbidden_target"


async def test_a_name_resolving_to_the_docker_host_is_not_connected(cfg, monkeypatch):
    """The pinned transport: a harmless-looking name answering with Docker Desktop's host address is refused at connect."""
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.65.254", port))])
    connected = []

    class Inner(httpcore.AsyncNetworkBackend):
        async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # noqa: ASYNC109
            connected.append(host)
            raise httpcore.ConnectError("test: not really connecting")

    backend = netaddr._PinnedBackend(Inner(), **netaddr.channel_policy())
    for host in ("hooks.corp.example", "host.docker.internal"):
        with pytest.raises(httpcore.ConnectError, match="forbidden target"):
            await backend.connect_tcp(host, 443)
    assert connected == []
    with pytest.raises(notify.NotifyError) as e:
        await notify._post_once("https://hooks.corp.example/x", b"{}", {"X-Foo": "x"}, use_proxy=False)
    assert e.value.category == "forbidden_target"


def test_the_container_gateway_is_never_a_target(cfg, monkeypatch):
    monkeypatch.setattr(netaddr, "container_gateway", lambda: "10.99.0.1")
    assert netaddr._forbidden_ip(ip("10.99.0.1"), True)  # also where private targets are fine (SMTP, LDAP)
    assert not netaddr._forbidden_ip(ip("10.99.0.2"), True)


def test_channels_reach_private_addresses_only_when_listed(cfg):
    assert netaddr.forbidden_literal("https://10.20.30.40/x", **netaddr.channel_policy())
    assert netaddr.forbidden_literal("https://[fd00::1]/x", **netaddr.channel_policy())  # ULA: not global
    assert not netaddr.forbidden_literal("https://93.184.216.34/x", **netaddr.channel_policy())
    cfg(webhook_private_nets=("10.20.0.0/16",))
    assert not netaddr.forbidden_literal("https://10.20.30.40/x", **netaddr.channel_policy())
    assert netaddr.forbidden_literal("https://10.21.0.1/x", **netaddr.channel_policy())
    # an operator may list the Docker host deliberately (an n8n there) – by address, never by the host.docker.internal name
    cfg(webhook_private_nets=("192.168.65.254",))
    assert not netaddr.forbidden_literal("http://192.168.65.254/x", **netaddr.channel_policy())
    assert netaddr.forbidden_literal("http://host.docker.internal/x", **netaddr.channel_policy())


@pytest.mark.parametrize(
    "a",
    [
        "::7f00:1",  # IPv4-compatible ::127.0.0.1
        "::127.0.0.1",
        "::ffff:0:7f00:1",  # IPv4-translated
        "64:ff9b:1::7f00:1",  # local-use NAT64 (RFC 8215)
        "::a9fe:a9fe",  # IPv4-compatible 169.254.169.254
        "::ffff:0:a9fe:a9fe",
        "::c0a8:41fe",  # IPv4-compatible 192.168.65.254 (the Docker host)
        "0.1.2.3",  # "this network"
    ],
)
def test_ipv6_forms_carrying_an_internal_ipv4_address(a):
    assert netaddr._forbidden_ip(ip(a), True), a


async def test_smtp_test_never_reaches_the_docker_host_and_shows_no_server_text(cfg, admin_client, monkeypatch):
    with pytest.raises(netaddr.ForbiddenTarget):
        await netaddr.mail_socket("host.docker.internal", 25, 1)
    with pytest.raises(netaddr.ForbiddenTarget):
        await netaddr.mail_socket("192.168.65.254", 25, 1)
    # a relay on the Docker host, deliberately: its address in SMTP_ALLOW_INTERNAL (then also by name)
    cfg(smtp_allow_internal=("192.168.65.254",))
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.65.254", port))])
    tried = []

    async def connect(_sock, addr):
        tried.append(addr[0])
        raise ConnectionRefusedError("220 internal-relay.corp.example ESMTP Postfix (Debian)")

    monkeypatch.setattr(asyncio.get_running_loop(), "sock_connect", connect)
    with pytest.raises(ConnectionRefusedError):
        await netaddr.mail_socket("host.docker.internal", 25, 1)
    assert tried == ["192.168.65.254"]
    # the test endpoint answers with the category only – never the server's text (banner, internal host names)
    body = {"host": "smtp.corp.example", "port": 25, "from_addr": "news@corp.example", "encryption": "none", "to": "soc@corp.example"}
    r = await admin_client.post("/api/admin/notify/smtp/test", json=body)
    assert r.status_code == 200 and r.json()["ok"] is False and r.json()["error"] == "refused"
    assert "Postfix" not in r.text and "internal-relay" not in r.text


@pytest.mark.parametrize("host", ["host.docker.internal", "192.168.65.254:389", "127.0.0.1", "[::1]:636", "169.254.169.254"])
def test_ldap_never_reaches_internal_targets(cfg, host):
    with pytest.raises(ldap_dir.LdapError) as e:
        ldap_dir._server({"encryption": "ldaps"}, host)
    assert e.value.category == "forbidden_target"


def test_ldap_reaches_the_company_network(cfg):
    assert ldap_dir._server({"encryption": "ldaps"}, "10.1.2.3:636") is not None


@pytest.mark.parametrize(
    "a",
    [
        "127.0.0.1",
        "::1",
        "169.254.169.254",  # cloud metadata
        "fd00:ec2::254",  # AWS's IPv6 metadata (a ULA)
        "fe80::1",
        "0.0.0.0",
        "0.1.2.3",
        "::",
        "224.0.0.1",
        "ff02::1",
        "::ffff:127.0.0.1",  # hidden in IPv6 forms
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",
        "2002:7f00:1::1",
    ],
)
def test_listing_never_allows_loopback_link_local_any_or_multicast(cfg, a):
    """0.1.26: WEBHOOK_PRIVATE_NETS / SMTP_ALLOW_INTERNAL were checked before the never-list – listing 127.0.0.1 or the
    metadata address made it a target. Now these stay forbidden whatever is listed."""
    every = (ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0"), ipaddress.ip_network(f"{a}/{32 if ip(a).version == 4 else 128}"))
    assert netaddr._forbidden_ip(ip(a), True, every), a
    assert netaddr._forbidden_ip(ip(a), False, every), a
    cfg(webhook_private_nets=(a,), smtp_allow_internal=(a,))
    host = f"[{a}]" if ip(a).version == 6 else a
    assert netaddr.forbidden_literal(f"https://{host}/x", **netaddr.channel_policy()), a


async def test_smtp_allow_internal_never_allows_loopback(cfg):
    cfg(smtp_allow_internal=("127.0.0.1", "169.254.169.254"))
    for host in ("127.0.0.1", "169.254.169.254"):
        with pytest.raises(netaddr.ForbiddenTarget):
            await netaddr.mail_socket(host, 25, 1)


def test_listed_private_own_network_and_docker_host_stay_allowed(cfg, monkeypatch):
    """What listing is for: a private receiver, one in the container's own Docker network (a webhook tester next door in
    `edge`, WEBHOOK_PRIVATE_NETS=172.31.250.50) and the Docker host by address."""
    monkeypatch.setattr(netaddr, "stack_networks", lambda: (ipaddress.ip_network("172.31.250.0/24"),))
    monkeypatch.setattr(netaddr, "container_gateway", lambda: "172.31.250.1")
    assert netaddr.forbidden_literal("http://172.31.250.50:8080/hook", **netaddr.channel_policy())
    cfg(webhook_private_nets=("172.31.250.50", "10.20.0.0/16", "192.168.65.254", "172.31.250.1"))
    for url in ("http://172.31.250.50:8080/hook", "https://10.20.30.40/x", "http://192.168.65.254/x", "http://172.31.250.1/x", "http://[::ffff:172.31.250.50]/x"):
        assert not netaddr.forbidden_literal(url, **netaddr.channel_policy()), url
    assert netaddr.forbidden_literal("http://172.31.250.10/x", **netaddr.channel_policy())  # the bundled nginx: not listed


# ---------------------------------------------------------------- security review 0.1.31: inet_aton forms behind a proxy


@pytest.mark.parametrize(
    "url",
    [
        "http://2852039166/latest/meta-data/",  # 169.254.169.254 as one decimal number
        "http://0xa9fea9fe/",  # … in hex
        "http://169.254.43518/",  # … with the last two parts as one
        "http://127.1/",  # 127.0.0.1, short form
        "http://0x7f000001/",
        "https://0x7f.1./x",
        "http://localhost:8000/api/admin/users",  # the proxy's own loopback
        "http://admin.localhost/x",
    ],
)
async def test_literal_check_reads_every_address_form(admin_client, cfg, url):
    """With HTTPS_PROXY only what is written in the URL is checked – the proxy resolves and connects. 2130706433,
    0x7f000001 or 127.1 were no address for the check (ipaddress refuses them) but are one for every proxy: the never-list
    (loopback, cloud metadata) could be reached through it. Now they are read as the address they are."""
    assert netaddr.forbidden_literal(url, **netaddr.channel_policy()), url
    assert netaddr.forbidden_literal(url), url  # feeds
    r = await admin_client.post("/api/admin/notify/channels", json={"name": "bad", "type": "webhook", "url": url, "allow_http": True, "use_proxy": True})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "url_forbidden_target", url


async def test_no_request_through_the_proxy_to_an_address_in_another_form(cfg, monkeypatch):
    """The send itself (a stored channel, a feed redirect) refuses before anything is handed to the proxy."""
    c = dataclasses.replace(config.get_config(), proxy="http://proxy.corp.example:3128")
    monkeypatch.setattr(notify, "get_config", lambda: c)
    with pytest.raises(notify.NotifyError) as e:
        await notify._post_once("http://2852039166/latest/", b"{}", {}, use_proxy=True)
    assert e.value.category == "forbidden_target"
    guard = news._guard("http://proxy.corp.example:3128", resolve=False)
    with pytest.raises(news.NewsError):
        await guard(httpx.Request("GET", "https://0x7f000001/feed"))
    await guard(httpx.Request("GET", "https://134744072/feed"))  # a public address in that form stays one


@pytest.mark.parametrize("host", ["example.com", "deadbeef.example", "cafe", "1.2.3.4.example.com", "0x"])
def test_names_are_not_read_as_addresses(host):
    assert netaddr._literal_ip(host) is None
