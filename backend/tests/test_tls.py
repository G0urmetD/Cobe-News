"""HTTPS certificate of the bundled proxy: made by the app (180 days, renewed 30
days before the end and at once when the names change), an own one only watched, a hand-placed file never overwritten,
the download is the public part only, no HSTS with a self-signed certificate."""

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509

from app import config, tls


@pytest.fixture
def tls_env(tmp_path, monkeypatch):
    cfg = dataclasses.replace(
        config.get_config(), tls_path=tmp_path, tls_mode="selfsigned", hostname="news.corp.example", base_url="https://news.corp.example:8095", tls_names=("10.0.0.5",)
    )
    monkeypatch.setattr(tls, "get_config", lambda: cfg)
    return tmp_path, cfg, monkeypatch


def _set(env, **kw):
    d, cfg, mp = env
    new = dataclasses.replace(cfg, **kw)
    mp.setattr(tls, "get_config", lambda: new)


def _cert(d) -> x509.Certificate:
    return x509.load_pem_x509_certificate((d / tls.CERT).read_bytes())


def test_made_renewed_and_left_alone(tls_env):
    d = tls_env[0]
    assert tls.ensure() == "created"
    c = _cert(d)
    assert c.issuer == c.subject and c.not_valid_after_utc - c.not_valid_before_utc > timedelta(days=179)
    sans = tls._sans(c)
    assert sans[0] == "news.corp.example" and {"localhost", "127.0.0.1", "10.0.0.5"} <= set(sans)
    assert (d / tls.KEY).stat().st_mode & 0o077 == 0  # the key is for the owner only
    first = c.fingerprint(tls.hashes.SHA256())
    assert tls.ensure() == "ok" and _cert(d).fingerprint(tls.hashes.SHA256()) == first
    end = c.not_valid_after_utc
    assert tls.ensure(now=end - timedelta(days=31)) == "ok"
    assert tls.ensure(now=end - timedelta(days=29)) == "renewed"
    assert _cert(d).fingerprint(tls.hashes.SHA256()) != first
    # a new name: renewed at once
    _set(tls_env, hostname="news2.corp.example")
    assert tls.ensure() == "renewed" and "news2.corp.example" in tls._sans(_cert(d))


def test_a_file_put_there_by_hand_is_never_replaced(tls_env):
    d = tls_env[0]
    cert, key = tls.make(["intern.corp.example"], datetime.now(UTC) - timedelta(days=179))  # nearly over, no marker
    (d / tls.CERT).write_bytes(cert)
    (d / tls.KEY).write_bytes(key)
    assert tls.ensure() == "foreign" and (d / tls.CERT).read_bytes() == cert
    assert {"foreign", "name_mismatch", "expiring"} <= set(tls.status()["problems"])


def test_own_certificate_only_watched(tls_env):
    d = tls_env[0]
    _set(tls_env, tls_mode="own")
    assert tls.ensure() == "own" and not (d / tls.CERT).exists()
    assert tls.status()["problems"] == ["missing"]
    cert, key = tls.make(["*.corp.example"], datetime.now(UTC) - timedelta(days=170))
    # someone put the key into the same file: the download still carries only the certificate
    (d / tls.CERT).write_bytes(cert + key)
    st = tls.status()
    assert tls.covers(_cert(d), "news.corp.example") and not tls.covers(_cert(d), "a.b.corp.example")
    assert st["days_left"] <= 10 and "expiring" in st["problems"] and "own_is_self_signed" in st["problems"] and st["hsts"]
    assert b"PRIVATE" not in tls.pem() and tls.pem().startswith(b"-----BEGIN CERTIFICATE-----")
    _set(tls_env, tls_mode="external")
    assert tls.ensure() == "external" and tls.status()["problems"] == []


async def test_status_page_download_and_hsts(admin_client, reader_client, tls_env):
    tls.ensure()
    st = (await admin_client.get("/api/admin/tls")).json()
    assert st["mode"] == "selfsigned" and st["ours"] and st["problems"] == [] and st["renews_at"] and st["hsts"] is False
    pem = await admin_client.get("/api/admin/tls/cobe.crt")
    assert pem.status_code == 200 and pem.content.startswith(b"-----BEGIN CERTIFICATE-----") and b"PRIVATE" not in pem.content
    assert (await reader_client.get("/api/admin/tls")).status_code == 403
    # self-signed: no HSTS (browsers would refuse "continue anyway" for a year) – with an own certificate: HSTS on https
    proxied = {"X-Forwarded-Proto": "https"}
    assert "strict-transport-security" not in (await admin_client.get("/api/me", headers=proxied)).headers
    _set(tls_env, tls_mode="own")
    from app import main

    async with __import__("conftest").make_client(client=("172.31.250.10", 4000)) as c:
        assert "strict-transport-security" in (await c.get("/api/auth/config", headers=proxied)).headers
        assert "strict-transport-security" not in (await c.get("/api/auth/config")).headers  # plain http: never
    assert main


def test_hsts_only_for_host_names():
    """HSTS holds for a host over all ports: never for localhost (the emergency access http://localhost:8096 would turn
    into https) or an IP address – only for a real name."""
    for host in ("news.corp.example", "news.corp.example:8095", "NEWS.corp.example.", "news", "xn--bcher-kva.example:443"):
        assert tls.hsts_host(host), host
    for host in (
        "",
        "localhost",
        "localhost:8095",
        "LOCALHOST.",
        "news.localhost:8095",
        "127.0.0.1:8095",
        "10.0.0.5",
        "[::1]:8095",
        "[2001:db8::1]",
        "::1",
        "127.1",
        "0x7f.1",
        "2130706433:8095",
        "a@news.corp.example",
    ):
        assert not tls.hsts_host(host), host


async def test_hsts_header_by_host(tls_env):
    _set(tls_env, tls_mode="own")
    proxied = {"X-Forwarded-Proto": "https"}
    async with __import__("conftest").make_client(client=("172.31.250.10", 4000)) as c:
        r = await c.get("/api/auth/config", headers={**proxied, "Host": "news.corp.example:8095"})
        assert r.headers["strict-transport-security"] == "max-age=31536000"  # no includeSubDomains, no preload
        for host in ("localhost:8095", "127.0.0.1:8095", "[::1]:8095", "app.localhost:8095"):
            assert "strict-transport-security" not in (await c.get("/api/auth/config", headers={**proxied, "Host": host})).headers, host
        # the emergency access: plain http straight to the app – never
        assert "strict-transport-security" not in (await c.get("/api/auth/config", headers={"Host": "news.corp.example"})).headers
    # self-signed (the default): still off, also for a real name – HSTS=1 switches it on
    _set(tls_env, tls_mode="selfsigned")
    async with __import__("conftest").make_client(client=("172.31.250.10", 4000)) as c:
        assert "strict-transport-security" not in (await c.get("/api/auth/config", headers={**proxied, "Host": "news.corp.example"})).headers
    _set(tls_env, tls_mode="selfsigned", hsts=True)
    async with __import__("conftest").make_client(client=("172.31.250.10", 4000)) as c:
        assert "strict-transport-security" in (await c.get("/api/auth/config", headers={**proxied, "Host": "news.corp.example"})).headers
        assert "strict-transport-security" not in (await c.get("/api/auth/config", headers={**proxied, "Host": "localhost:8095"})).headers
