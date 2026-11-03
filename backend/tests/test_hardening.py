"""The fixes of the review of 0d72793: hostile feeds (DTD in any encoding, overflowing dates, quadratic HTML), a round
that never ends early, the directory sync, secrets bound to their server, stateless Entra start, the brute-force rules,
TOTP replay and re-authentication, the setup race, certificates, chat markup, the backlog, the paging of the API."""

import asyncio
import json
import time
import unicodedata
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import ANY

import httpx
import pyotp
import pytest
from conftest import PASSWORD, add_user, make_client, set_news, sign_in
from sqlalchemy import select, update

from app import auth_api, db, news, notify, tls
from app import settings as settings_store
from app.auth import bruteforce, ldap_dir
from app.auth import sync as directory_sync
from app.auth_api import issue_setup_token
from app.models import NewsItem, NewsRead, NewsSource, User

ENTITIES = '<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><rss version="2.0"><channel><item><title>&b;</title></item></channel></rss>'


# ---------------------------------------------------------------- H1: DTD and entities, whatever the encoding or position


@pytest.mark.parametrize(
    "data",
    [
        ('<?xml version="1.0" encoding="UTF-16"?>' + ENTITIES).encode("utf-16"),  # a byte search for "<!doctype" misses this
        b'<?xml version="1.0"?><!--' + b"x" * 70_000 + b"-->" + ENTITIES.encode(),  # the DTD after a 70 KB comment
        ENTITIES.encode("utf-16-be").replace(b"\x00<", b"\x00<", 1),
    ],
)
def test_dtd_refused_in_any_encoding_and_position(data):
    with pytest.raises(news.NewsError, match="format"):
        news.parse_feed(data)


def test_unknown_encoding_is_a_format_error_not_a_crash():
    with pytest.raises(news.NewsError, match="format"):
        news.parse_feed(b'<?xml version="1.0" encoding="x-no-such-charset"?><rss/>')


# ---------------------------------------------------------------- H2: dates and Retry-After that overflow


def test_dates_out_of_range_are_no_date():
    assert news._date("0001-01-01T00:00:00Z") is None  # .NET's DateTime.MinValue
    assert news._date("9999-12-31T23:59:59+14:00") is None
    assert news._date("2026-10-28T08:00:00Z") == datetime(2026, 10, 28, 8, tzinfo=UTC)
    s = news.story({"link": "https://n.example.com/a", "title": "Old", "date": news._date("0001-01-01T00:00:00Z")}, datetime.now(UTC))
    assert s is not None and s["published_at"].year >= 2026  # no date: now


def test_huge_retry_after_is_clamped():
    assert news._retry_after(httpx.Headers({"retry-after": "9" * 40})) == news.MAX_BACKOFF


async def test_one_broken_source_never_ends_the_round(monkeypatch):
    """An unexpected error in one feed (here: in storing) pauses that source – the others are still fetched."""
    await set_news(enabled=True)
    async with db.session() as s:
        await s.execute(update(NewsSource).values(enabled=False))
        for k in ("bad", "good"):
            s.add(NewsSource(key=k, name=k, url=f"https://{k}.example.org/f.xml", site="", builtin=False, enabled=True, failures=0))
        await s.commit()
    rss = b'<rss version="2.0"><channel><item><title>Hello</title><link>https://good.example.org/1</link></item></channel></rss>'
    transport = httpx.MockTransport(lambda req: httpx.Response(200, content=rss if req.url.host == "good.example.org" else b"<rss><channel><item><title>x</title><link>https://bad.example.org/1</link></item></channel></rss>"))
    real = news.story

    def story(entry, now):
        if "bad.example.org" in entry.get("link", ""):
            raise OverflowError("date value out of range")
        return real(entry, now)

    monkeypatch.setattr(news, "story", story)
    got = await news.refresh_due(transport=transport)
    assert got.get("good") == 1
    async with db.session() as s:
        bad = await s.scalar(select(NewsSource).where(NewsSource.key == "bad"))
        assert bad.next_fetch_at is not None  # paused, not asked again every round


async def test_next_fetch_is_stored_before_the_download():
    """Should a feed bring the process down, the source pauses after the restart instead of being fetched at once."""
    await set_news(enabled=True)
    async with db.session() as s:
        await s.execute(update(NewsSource).values(enabled=False))
        src = NewsSource(key="slow", name="slow", url="https://slow.example.org/f.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.commit()
        sid = src.id
    seen: dict = {}

    class Peek(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            async with db.session() as s2:
                seen["next"] = (await s2.get(NewsSource, sid)).next_fetch_at
            return httpx.Response(500)

    await news.refresh_due(transport=Peek())
    assert seen["next"] is not None and seen["next"] > datetime.now(UTC)


# ---------------------------------------------------------------- H3: linear text, cleaned links


def test_html_to_text_is_linear_on_hostile_input():
    t0 = time.monotonic()
    news.html_to_text("<script>" * 50_000)  # 400 KB: the regex before took over a minute
    news.html_to_text("<style>" + "a" * 1_000_000)
    assert time.monotonic() - t0 < 2
    assert news.html_to_text("<p>a<script>alert(1)</script>b</p><style>x{}</style><br>c &amp; d") == "ab\nc & d"


def test_article_links_only_absolute_and_in_a_new_tab():
    out = news.clean_html('<a href="/settings">in</a> <a href="//evil.example/x">proto</a> <a href="https://ok.example/y">ok</a> <a href="javascript:x()">js</a>')
    assert 'href="/settings"' not in out and "//evil.example" not in out and "javascript" not in out
    assert 'href="https://ok.example/y"' in out and 'target="_blank"' in out and "noopener" in out


def test_deeply_nested_html_is_no_cpu_trap():
    """Security review 0.1.16 M4: nh3 is quadratic in the nesting depth – 20 000 nested <ul><li> took 1.7 s per pass,
    a 5 MB feed of such entries minutes of CPU while the news round held its lock. Too deep: plain text instead."""
    for unit in ("<ul><li>", "<div>", "<blockquote>", "<table><tr><td>"):
        blob = unit * (news.TEXT_SRC_MAX // len(unit) - 1) + "Text"
        t0 = time.monotonic()
        assert news.html_to_text(blob) == "Text"
        assert news.clean_html(blob) == "<p>Text</p>"
        assert time.monotonic() - t0 < 0.5, unit
    # the whole feed as the round reads it: parse + story() of every entry (5 MB, 26 such entries)
    blob = "<ul><li>" * (news.TEXT_SRC_MAX // 8)
    items = "".join(f"<item><title>t{i}</title><link>https://e.example/{i}</link><description><![CDATA[{blob}]]></description></item>" for i in range(26))
    t0 = time.monotonic()
    entries, _ = news.parse_feed(f"<rss><channel>{items}</channel></rss>".encode())
    assert all(news.story(e, datetime.now(UTC)) for e in entries)
    assert time.monotonic() - t0 < 5  # before: over 200 s
    # an article of normal depth keeps its structure and links
    assert news.clean_html("<div><div><ul><li><a href='https://e.example/'>x</a></li></ul></div></div>").startswith("<ul><li><a href=")


def test_clean_html_is_idempotent_and_never_ends_inside_a_tag():
    """Security review 0.1.16 L11: the cut came after cleaning (27 % of long outputs ended inside a tag) and cleaning the
    output again changed it (7.7 %)."""
    import random

    rnd = random.Random(16)
    parts = ["<p>", "</p>", "<a href='https://e.example/x?a=1&b=2'>", "</a>", "<a href='/rel'>", "<b>", "</b>", "<ul>", "<li>", "</li>", "</ul>", "<br>",
             "<img src=x>", "<script>x</script>", "&amp;", "&lt;", " ", "Wort", "<h2>", "</h2>", "<code>", "</code>", "<!-- c -->", "\n", "<pre>", "</pre>", "<a>", "<p></p>"]  # fmt: skip
    for n in range(400):
        size = rnd.choice((5, 50, 400, 30_000))
        html = "".join(rnd.choice(parts) for _ in range(size))
        out = news.clean_html(html)
        assert news.clean_html(out) == out, (n, html[:200])
        assert out.rfind("<") <= out.rfind(">"), n
        assert len(out) <= news.CONTENT_MAX + 200
    long = "<p>" + "<a href='https://e.example/'>link</a> word " * 5000 + "</p>"
    out = news.clean_html(long)
    assert len(out) > news.CONTENT_MAX * 0.9 and out.endswith("</p>") and news.clean_html(out) == out


# ---------------------------------------------------------------- M5: nothing older than the retention comes back


async def test_stories_older_than_the_retention_are_not_stored_again():
    async with db.session() as s:
        src = NewsSource(key="k", name="k", url="https://k.example.org/f.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.commit()
        now = datetime.now(UTC)
        added = await news.store(
            s,
            src,
            [
                {"link": "https://k.example.org/old", "title": "Old one", "date": now - timedelta(days=120)},
                {"link": "https://k.example.org/new", "title": "New one", "date": now - timedelta(days=1)},
            ],
            timedelta(days=90),
        )
        assert added == 1
        titles = list(await s.scalars(select(NewsItem.title)))
    assert titles == ["New one"]


# ---------------------------------------------------------------- M1/M2/M7: the directory


class _FakeSvc:
    def __init__(self, result: int, entries=()):
        self.result = {"result": result}
        self.response = list(entries)

    def search(self, *a, **kw):
        return self.result["result"] == 0 and bool(self.response)


def test_a_failed_ldap_search_is_never_read_as_gone(monkeypatch):
    cfg = {"base_dn": "DC=corp,DC=example"}
    gid = str(uuid.uuid4())
    # busy / unavailable / size limit …: an error, never "the account is gone"
    for code in (1, 51, 52, 80):
        with pytest.raises(ldap_dir.LdapError):
            ldap_dir._lookup(cfg, _FakeSvc(code), gid)
    # a clean empty answer, or noSuchObject: gone
    assert ldap_dir._lookup(cfg, _FakeSvc(0), gid) is None
    assert ldap_dir._lookup(cfg, _FakeSvc(32), gid) is None


def test_ldap_does_not_follow_referrals(monkeypatch):
    made = {}

    class Conn:
        def __init__(self, server, **kw):
            made.update(kw)
            self.bound = False

        def open(self):
            pass

        def bind(self):
            return False

        def unbind(self):
            pass

    monkeypatch.setattr(ldap_dir, "Connection", Conn)
    monkeypatch.setattr(ldap_dir, "_pool", lambda cfg: object())
    ldap_dir.connection({"servers": ["dc01.corp.example"], "encryption": "ldaps"}, "cn=x", "y")
    assert made["auto_referrals"] is False


async def test_sync_asks_first_writes_after_one_bind(monkeypatch):
    """No transaction is open while the directory is asked (no row lock held meanwhile); one bind for all accounts."""
    async with db.session() as s:
        for n in range(3):
            # signed in once (accounts a team loaded and that never signed in are the team sync's – app/teams.py)
            s.add(User(username=f"ad{n}", display_name=f"Ad {n}", role="reader", auth_source="ldap", external_id=str(uuid.uuid4()), is_active=True, last_login_at=datetime.now(UTC)))
        await settings_store.put(s, "ldap", {**settings_store.DEFAULTS["ldap"], "enabled": True, "servers": ["dc"], "base_dn": "DC=x", "bind_dn": "cn=s", "bind_password_enc": "x"})
        await s.commit()
    calls: list[int] = []
    in_tx: list[bool] = []

    def lookup_many(cfg, ids):
        calls.append(len(ids))
        return {i: None for i in ids}  # all gone

    sess = db.session()
    real_run = ldap_dir.run

    async def run(fn, *args):
        in_tx.append(sess.in_transaction())
        return await real_run(fn, *args)

    monkeypatch.setattr(ldap_dir, "lookup_many", lookup_many)
    monkeypatch.setattr(ldap_dir, "run", run)
    async with sess:
        out = await directory_sync.run(sess)
    assert calls == [3] and in_tx == [False] and out == {"deactivated": 3}


async def test_sync_error_switches_nobody_off(monkeypatch):
    async with db.session() as s:
        s.add(User(username="ad", display_name="Ad", role="reader", auth_source="ldap", external_id=str(uuid.uuid4()), is_active=True))
        await settings_store.put(s, "ldap", {**settings_store.DEFAULTS["ldap"], "enabled": True, "servers": ["dc"], "base_dn": "DC=x", "bind_dn": "cn=s", "bind_password_enc": "x"})
        await s.commit()

    def broken(cfg, ids):
        raise ldap_dir.LdapError("search")

    monkeypatch.setattr(ldap_dir, "lookup_many", broken)
    async with db.session() as s:
        assert await directory_sync.run(s) == {}
        assert (await s.scalar(select(User).where(User.username == "ad"))).is_active


# ---------------------------------------------------------------- M3: a stored secret only for its own server


async def test_ldap_password_not_reused_for_another_server(admin_client):
    base = {"enabled": True, "servers": ["dc01.corp.example"], "base_dn": "DC=corp,DC=example", "bind_dn": "CN=svc,DC=corp,DC=example"}
    assert (await admin_client.put("/api/admin/auth/ldap", json={**base, "bind_password": "geheim-123"})).status_code == 200
    # same server, no password: kept
    assert (await admin_client.put("/api/admin/auth/ldap", json=base)).status_code == 200
    for change in ({"servers": ["dc.evil.example"]}, {"bind_dn": "CN=other,DC=corp,DC=example"}, {"verify_cert": False}, {"encryption": "starttls"}):
        for path, method in (("/api/admin/auth/ldap", "put"), ("/api/admin/auth/ldap/test", "post")):
            r = await getattr(admin_client, method)(path, json={**base, **change})
            assert r.status_code == 422 and r.json()["detail"]["code"] == "secret_required", (change, path)
    # with the password typed again: fine
    assert (await admin_client.put("/api/admin/auth/ldap", json={**base, "servers": ["dc02.corp.example"], "bind_password": "geheim-456"})).status_code == 200


# ---------------------------------------------------------------- M4: Entra start without server state, per address


async def test_entra_start_keeps_nothing_on_the_server_and_is_capped(admin_client, monkeypatch):
    await admin_client.put(
        "/api/admin/auth/entra",
        json={"enabled": True, "tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "AAAAAAAA-2222-3333-4444-555555555555", "client_secret": "s3cr3t"},
    )
    auth_api._oidc_starts.clear()
    async with make_client() as c:
        for n in range(auth_api.OIDC_PER_IP):
            r = await c.get("/api/auth/oidc/start", params={"next": "/?story=abc"})
            assert r.status_code == 302 and r.headers["location"].startswith("https://login.microsoftonline.com/")
            if n == 0:
                blob = c.cookies.get(auth_api.OIDC_COOKIE)
        assert "entra_busy" in (await c.get("/api/auth/oidc/start")).headers["location"]
    assert not hasattr(auth_api, "_oidc_states")
    # the cookie is encrypted (no state, nonce or verifier readable), and the landing page is only a local path
    assert "abc" not in blob
    assert auth_api._safe_next("//evil.example/x") == "/" and auth_api._safe_next("https://evil.example") == "/" and auth_api._safe_next("/?story=1") == "/?story=1"
    # another address is not affected
    async with make_client(client=("203.0.113.9", 5000)) as other:
        assert (await other.get("/api/auth/oidc/start")).headers["location"].startswith("https://login.microsoftonline.com/")
    # a tampered cookie: no sign-in
    async with make_client() as c:
        c.cookies.set(auth_api.OIDC_COOKIE, "x" * 40)
        assert "entra_state" in (await c.get("/api/auth/oidc/callback", params={"code": "c", "state": "s"})).headers["location"]


# ---------------------------------------------------------------- M6/L5: brute force


def test_names_compared_normalised():
    assert bruteforce._key("ＡＮＮＡ") == bruteforce._key("anna") == bruteforce._key("Anna ")
    assert bruteforce._key("Straße") == bruteforce._key("STRASSE")
    assert unicodedata.normalize("NFKC", "ﬁ") == "fi" and bruteforce._key("ﬁona") == bruteforce._key("fiona")


def test_one_person_mistyping_never_blocks_the_shared_address():
    for _ in range(60):
        bruteforce.register_failure("anna", "172.17.0.1")
    assert not bruteforce.ip_blocked("172.17.0.1")  # only the account locks
    for n in range(30):
        bruteforce.register_failure(f"user{n}", "172.17.0.2")  # spraying over many names
    assert bruteforce.ip_blocked("172.17.0.2")


async def test_a_flood_on_a_locked_account_costs_constant_time(client):
    """Attempts on a locked account are answered at once (no password check, no delay) – before, each one appended to a
    list under the empty name that every such attempt from everywhere shared (and to the address's list), and each
    further attempt copied the whole list: a flood slowed every request of the app down, ever more for 15 minutes."""
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    await add_user("victim", "reader")
    for _ in range(bruteforce.ACCOUNT_MAX):
        await client.post("/api/auth/login", json={"username": "victim", "password": "wrong-password-123"})
    for _ in range(20):
        r = await client.post("/api/auth/login", json={"username": "victim", "password": "wrong-password-123"})
        assert r.status_code == 423
    assert "" not in bruteforce._acct_fail and not any(k.endswith("|") for k in bruteforce._pair_fail)
    # straight on the counters: however many, each list stays at most KEEP long – and the limits still hold
    for _ in range(3 * bruteforce.KEEP):
        bruteforce.register_failure("", "198.51.100.7", lock_account=False)
        bruteforce.register_failure("anna", "198.51.100.8", lock_account=False)
    assert len(bruteforce._ip_fail["198.51.100.7"]) == bruteforce.KEEP
    assert len(bruteforce._acct_fail[bruteforce._key("anna")]) == len(bruteforce._pair_fail[f"198.51.100.8|{bruteforce._key('anna')}"]) == bruteforce.KEEP
    assert not bruteforce.ip_blocked("198.51.100.7") and not bruteforce.ip_blocked("198.51.100.8")  # one name each
    for n in range(bruteforce.IP_MIN_NAMES):
        bruteforce.register_failure(f"user{n}", "198.51.100.7")
    assert bruteforce.ip_blocked("198.51.100.7")  # spraying is still seen among the newest failures
    for _ in range(bruteforce.ACCOUNT_MAX):
        f = bruteforce.register_failure("bert", "198.51.100.9")
    assert f.locked_for and bruteforce.locked_for("bert")


def test_purge_forgets_old_entries(monkeypatch):
    bruteforce.register_failure("x", "198.51.100.1")
    real = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real() + 10 * 3600)
    bruteforce.purge()
    assert not bruteforce._acct_fail and not bruteforce._ip_fail and not bruteforce._pair_fail


def _shared_v6(monkeypatch, *addrs: str) -> None:
    import dataclasses

    from app import config, netaddr

    cfg = dataclasses.replace(config.get_config(), shared_addresses=addrs)
    monkeypatch.setattr(netaddr, "get_config", lambda: cfg)
    monkeypatch.setattr(netaddr, "container_gateway", lambda: None)


def test_ipv6_counts_per_64_ipv4_per_address(monkeypatch):
    _shared_v6(monkeypatch, "2001:db8:5::1")
    k = bruteforce.source_key
    assert k("198.51.100.7") == "198.51.100.7" and k("198.51.100.8") == "198.51.100.8"
    assert k("::ffff:198.51.100.7") == "198.51.100.7"  # IPv4-mapped: the IPv4 address
    assert k("2001:db8:1:2::1") == k("2001:db8:1:2:ffff:ffff:ffff:ffff") == "2001:db8:1:2::/64"
    assert k("2001:db8:1:3::1") == "2001:db8:1:3::/64"
    assert k("fe80::1%eth0") == "fe80::/64"
    assert k("2001:db8:5::1") == "2001:db8:5::1" and k("2001:db8:5::2") == "2001:db8:5::/64"  # a shared one keeps its own
    assert k("garbage") == "garbage"


def test_spraying_from_many_ipv6_addresses_blocks_their_64(monkeypatch):
    """One /64 is one attacker: a fresh address per guess does not get past the address limit."""
    _shared_v6(monkeypatch, "2001:db8:1:2::53")
    for n in range(bruteforce.IP_MAX):
        bruteforce.register_failure(f"user{n}", f"2001:db8:1:2::{n + 1:x}")
    assert bruteforce.ip_blocked("2001:db8:1:2::abcd")  # every address of the /64
    assert not bruteforce.ip_blocked("2001:db8:1:3::1")  # the next /64 is someone else
    assert not bruteforce.ip_blocked("2001:db8:1:2::53")  # a shared address in it is never blocked
    for n in range(bruteforce.IP_MAX):
        bruteforce.register_failure(f"user{n}", f"198.51.100.{n + 1}")
    assert not bruteforce.ip_blocked("198.51.100.200")  # IPv4 still per address
    for n in range(bruteforce.IP_MAX):
        bruteforce.register_failure(f"user{n}", "::ffff:198.51.100.9")
    assert bruteforce.ip_blocked("198.51.100.9") and bruteforce.ip_blocked("::ffff:198.51.100.9")


async def test_the_gate_and_the_sign_in_starts_count_per_64(monkeypatch):
    async with bruteforce.gate("anna", "2001:db8:1:2::1") as free:
        assert free and list(bruteforce._gates) == [f"{bruteforce._key('anna')}|2001:db8:1:2::/64"]
    monkeypatch.setattr(auth_api, "_oidc_starts", {})
    for n in range(auth_api.OIDC_PER_IP):
        assert auth_api._oidc_rate_ok(f"2001:db8:9:9::{n + 1:x}")
    assert not auth_api._oidc_rate_ok("2001:db8:9:9::beef") and auth_api._oidc_rate_ok("2001:db8:9:a::1")


async def test_sign_in_blocked_for_the_whole_64(monkeypatch):
    """Through the bundled proxy: guesses from changing IPv6 addresses of one /64 block the whole /64 – another /64 and
    IPv4 clients still get in."""
    await add_user("rudi")
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    async with make_client(client=("172.31.250.10", 5000)) as c:
        for i in range(bruteforce.IP_MAX):
            await c.post("/api/auth/login", json={"username": f"u{i}", "password": "x"}, headers={"X-Forwarded-For": f"2001:db8:7:7::{i + 1:x}"})
        r = await c.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD}, headers={"X-Forwarded-For": "2001:db8:7:7:1:2:3:4"})
        assert r.status_code == 403 and r.json()["detail"]["code"] == "ip_blocked"
        ok = await c.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD}, headers={"X-Forwarded-For": "2001:db8:7:8::1"})
        assert ok.json()["next"] == "done"
        ok = await c.post("/api/auth/login", json={"username": "rudi", "password": PASSWORD}, headers={"X-Forwarded-For": "203.0.113.5"})
        assert ok.json()["next"] == "done"


async def test_ldap_failures_count_per_account_however_typed(monkeypatch, client):
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await settings_store.put(s, "ldap", {**settings_store.DEFAULTS["ldap"], "enabled": True, "servers": ["dc"], "base_dn": "DC=x", "bind_dn": "cn=s", "bind_password_enc": "x"})
        await s.commit()

    def authenticate(cfg, username, password, seen=None, locked=None):
        seen.append("guid-of-anna")  # sAMAccountName, UPN, DOMAIN\\name: one account
        if locked is not None and locked("guid-of-anna"):
            raise ldap_dir.AccountLocked("locked")  # as the real one: checked between search and bind
        return None

    monkeypatch.setattr(ldap_dir, "authenticate", authenticate)
    codes = []
    for name in ("a.weber", "a.weber@corp.example", "A.WEBER", "a.weber", "a.weber@corp.example", "a.weber"):
        r = await client.post("/api/auth/login", json={"username": name, "password": "x", "source": "ldap"})
        codes.append(r.status_code)
    assert codes[:4] == [401, 401, 401, 401] and 423 in codes[4:]


# ---------------------------------------------------------------- L1: setup only once, also when raced


async def test_setup_race_creates_one_emergency_admin():
    async with db.session() as s:
        token = await issue_setup_token(s)
    body = {"token": token, "username": "notfall", "display_name": "", "password": PASSWORD}
    async with make_client() as a, make_client() as b:
        r1, r2 = await asyncio.gather(a.post("/api/setup", json=body), b.post("/api/setup", json={**body, "username": "notfall2"}))
    assert sorted([r1.status_code, r2.status_code]) == [200, 404]
    async with db.session() as s:
        assert len(list(await s.scalars(select(User).where(User.is_emergency.is_(True))))) == 1


# ---------------------------------------------------------------- L6: the last admin


async def test_last_admin_checked_before_writing(admin_client):
    other = await add_user("ben", "admin", totp_secret=pyotp.random_base32())
    async with db.session() as s:
        await s.execute(update(User).where(User.id == admin_client.user.id).values(is_active=True))
        await s.commit()
    assert (await admin_client.patch(f"/api/admin/users/{other.id}", json={"role": "reader"})).status_code == 200
    # anna is now the only admin – she cannot change herself (protected), and nobody can demote her via another path
    assert (await admin_client.patch(f"/api/admin/users/{admin_client.user.id}", json={"role": "reader"})).status_code == 409
    async with db.session() as s:
        assert (await s.get(User, admin_client.user.id)).role == "admin"
    # e-mail checked
    assert (await admin_client.patch(f"/api/admin/users/{other.id}", json={"email": "no-mail"})).status_code == 422
    assert (await admin_client.patch(f"/api/admin/users/{other.id}", json={"email": "ben@corp.example"})).json()["email"] == "ben@corp.example"
    assert (await admin_client.patch(f"/api/admin/users/{other.id}", json={"email": ""})).json()["email"] is None


# ---------------------------------------------------------------- L8: one TOTP code once, also in parallel


async def test_totp_code_counts_once_across_addresses():
    secret = pyotp.random_base32()
    await add_user("tina", "reader", totp_secret=secret)
    async with db.session() as s:
        await settings_store.put(s, "setup", {"completed": True})
        await s.commit()
    code = pyotp.TOTP(secret).now()
    clients = [make_client(client=(f"198.51.100.{n}", 5000)) for n in (1, 2)]
    try:
        for c in clients:
            assert (await c.post("/api/auth/login", json={"username": "tina", "password": PASSWORD})).json() == {"next": "mfa"}
        r = await asyncio.gather(*(c.post("/api/auth/mfa", json={"code": code}) for c in clients))
        assert sorted(x.status_code for x in r) == [200, 401]
    finally:
        for c in clients:
            await c.aclose()


# ---------------------------------------------------------------- L2/L3: certificates


def test_non_ascii_host_name_and_a_half_written_pair(tmp_path, monkeypatch):
    monkeypatch.setenv("TLS_PATH", str(tmp_path / "tls"))
    monkeypatch.setenv("TLS_MODE", "selfsigned")
    monkeypatch.setenv("NEWS_HOSTNAME", "nachrichten.bücher.example")
    from app.config import get_config

    get_config.cache_clear()
    try:
        assert tls.ensure() == "created"
        assert "xn--bcher-kva.example" in " ".join(tls._sans(tls._load(tmp_path / "tls" / tls.CERT)))
        assert tls.ensure() == "ok"
        # a crash after the new key, before the new certificate: noticed and made again
        key2, _ = tls.make(["localhost"])[1], None
        (tmp_path / "tls" / tls.KEY).write_bytes(key2)
        assert tls.ensure() == "renewed"
        assert tls.ensure() == "ok"
    finally:
        get_config.cache_clear()


# ---------------------------------------------------------------- L4: chat markup from a story link


def test_story_links_cannot_break_chat_markup():
    s = notify.Story(str(uuid.uuid4()), "Title", "Sum", "https://x.example/a|<!channel>(b)[c]", "high", "Src", datetime.now(UTC))
    slack = json.dumps(notify.render_slack("R", [s], 1, "de"))
    assert "<!channel>" not in slack and "a%7C%3C!channel%3E%28b%29%5Bc%5D" in slack
    teams = json.dumps(notify.render_teams("R", [s], 1, "de"))
    assert "(https://x.example/a%7C%3C!channel%3E%28b%29%5Bc%5D)" in teams
    bad = notify.Story(str(uuid.uuid4()), "T", "", "javascript:alert(1)", "high", "Src", datetime.now(UTC))
    assert "javascript" not in json.dumps(notify.render_slack("R", [bad], 1, "de"))


# ---------------------------------------------------------------- L9: no backlog flood


async def test_backlog_of_a_new_source_is_not_sent(admin_client):
    hooks: list = []
    notify.transport = httpx.MockTransport(lambda req: (hooks.append(req), httpx.Response(200))[1])
    try:
        ch = (await admin_client.post("/api/admin/notify/channels", json={"name": "Slack", "type": "slack", "url": "https://hooks.slack.com/services/T0/B0/X"})).json()
        await admin_client.post("/api/admin/notify/rules", json={"name": "All", "channels": [ch["id"]], "severities": []})
        async with db.session() as s:
            src = NewsSource(key="n", name="n", url="https://n.example.org/f.xml", site="", builtin=False, enabled=True, failures=0)
            s.add(src)
            await s.commit()
            now = datetime.now(UTC) + timedelta(seconds=1)
            for n, age in enumerate((timedelta(days=30), timedelta(days=3), timedelta(hours=2))):
                s.add(NewsItem(source_id=src.id, url=f"https://n.example.org/{n}", url_key=f"k{n}", title=f"T{n}", title_key=f"t{n}", published_at=now - age, fetched_at=now, severity="high"))
            await s.commit()
            rule = (await s.scalars(select(notify.NotifyRule))).first()
            pending = await notify.pending(s, rule, uuid.UUID(ch["id"]), rule.active_since)
        assert [i.title for i, _ in pending] == ["T2"]
    finally:
        notify.transport = None


# ---------------------------------------------------------------- L7: TOTP needs the current factor; API paging


async def test_paging_by_cursor_neither_repeats_nor_skips(reader_client):
    await set_news(enabled=True)
    async with db.session() as s:
        src = NewsSource(key="p", name="p", url="https://p.example.org/f.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.commit()
        now = datetime.now(UTC)
        for n in range(25):
            s.add(NewsItem(source_id=src.id, url=f"https://p.example.org/{n}", url_key=f"p{n}", title=f"Story {n}", title_key=f"p{n}", summary="Lücke", published_at=now - timedelta(minutes=n), fetched_at=now, severity="low", search=news.search_text(f"Story {n}", "Lücke", [])))
        await s.commit()
    first = (await reader_client.get("/api/news", params={"limit": 10})).json()
    assert first["counts"] == {"new": 25, "read": 0, "topics": ANY, "ours": 0} and first["more"] and first["next"]
    # meanwhile: a new story arrives and two of the first page are read
    async with db.session() as s:
        s.add(NewsItem(source_id=src.id, url="https://p.example.org/x", url_key="px", title="Fresh", title_key="px", published_at=datetime.now(UTC), fetched_at=datetime.now(UTC), severity="low", search="fresh"))
        await s.commit()
    for it in first["items"][:2]:
        await reader_client.post(f"/api/news/{it['id']}/read")
    seen = [i["title"] for i in first["items"]]
    cursor = first["next"]
    while cursor:
        page = (await reader_client.get("/api/news", params={"limit": 10, "before": cursor, "counts": "false"})).json()
        assert "counts" not in page
        seen += [i["title"] for i in page["items"]]
        cursor = page["next"]
    assert seen == [f"Story {n}" for n in range(25)]  # each once, in order, "Fresh" not pushed in between
    # the search on the folded column: case and accents ignored
    assert (await reader_client.get("/api/news", params={"q": "LUCKE"})).json()["counts"]["new"] == 23
    assert (await reader_client.get("/api/news", params={"before": "garbage"})).status_code == 422
    # the read tab pages by read time
    read = (await reader_client.get("/api/news", params={"state": "read"})).json()
    assert [i["title"] for i in read["items"]] == ["Story 1", "Story 0"] or [i["title"] for i in read["items"]] == ["Story 0", "Story 1"]


async def test_read_all_marks_everything(reader_client):
    await set_news(enabled=True)
    async with db.session() as s:
        src = NewsSource(key="r", name="r", url="https://r.example.org/f.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.commit()
        now = datetime.now(UTC)
        await s.execute(
            NewsItem.__table__.insert(),
            [dict(id=uuid.uuid4(), source_id=src.id, url=f"https://r.example.org/{n}", url_key=f"r{n}", title=f"S{n}", title_key=f"r{n}", summary="", content_html="", published_at=now - timedelta(seconds=n), fetched_at=now, severity="low", reasons=[], cves=[], also_in=[], search="") for n in range(5200)],
        )
        await s.commit()
    assert (await reader_client.post("/api/news/read-all", json={})).json() == {"marked": 5200}
    assert (await reader_client.get("/api/news")).json()["counts"] == {"new": 0, "read": 5200, "topics": ANY, "ours": 0}
    assert (await reader_client.post("/api/news/read-all", json={})).json() == {"marked": 0}  # idempotent
    async with db.session() as s:
        # the watermark moved – no mark per story (app/reader.py)
        assert list(await s.scalars(select(NewsRead.item_id).where(NewsRead.user_id == reader_client.user.id))) == []
    _ = sign_in


async def test_recent_counts_all_and_follows_my_desktop_choice(reader_client):
    await set_news(enabled=True)
    async with db.session() as s:
        src = NewsSource(key="d", name="d", url="https://d.example.org/f.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(src)
        await s.commit()
    since = (await reader_client.get("/api/news/recent")).json()["now"]
    async with db.session() as s:
        now = datetime.now(UTC)
        for n in range(60):  # one big round: more than the list holds
            s.add(NewsItem(source_id=src.id, url=f"https://d.example.org/{n}", url_key=f"d{n}", title=f"D{n}", title_key=f"d{n}", published_at=now, fetched_at=now, severity="critical" if n < 5 else "low"))
        await s.commit()
    got = (await reader_client.get("/api/news/recent", params={"since": since})).json()
    assert len(got["items"]) == 10 and got["total"] == 60  # nothing lost: the rest is counted
    await reader_client.put("/api/me/desktop", json={"enabled": True, "severities": ["critical"], "sources": []})
    mine = (await reader_client.get("/api/news/recent", params={"since": since, "mine": "true"})).json()
    assert mine["total"] == 5 and {i["severity"] for i in mine["items"]} == {"critical"}


# ---------------------------------------------------------------- a NUL in a request: 422, never a database error (500)


async def test_a_nul_anywhere_in_a_request_is_refused_with_422(admin_client, reader_client):
    """Security review 0.1.16 M1 (Schemathesis) and bug hunt L1: a U+0000 in a body or a query reached PostgreSQL (500)."""
    ep = "https://fcm.googleapis.com/fcm/send/abc\u0000def"
    calls = [
        (reader_client, "post", "/api/me/push/state", {"endpoint": ep}),
        (reader_client, "post", "/api/me/push/remove", {"endpoint": ep}),
        (reader_client, "put", "/api/me/desktop", {"enabled": True, "severities": ["high"], "sources": ["a\u0000"]}),
        (reader_client, "post", "/api/news/read-all", {"q": "a\u0000b"}),
        (admin_client, "post", "/api/admin/users", {"username": "neu", "email": "a\u0000@corp.example", "role": "reader"}),
        (admin_client, "put", "/api/vendor/follows/nginx", {"enabled": True, "note": "a\u0000b", "tags": []}),
        (admin_client, "post", "/api/vendor/follows/nginx/versions", {"version": "1.25.3", "label": "x\u0000"}),
        (admin_client, "post", "/api/vendor/custom", {"cpe": "a:acme:widget", "label": "Wid\u0000get"}),
        (admin_client, "post", "/api/admin/news/sources", {"name": "N\u0000", "url": "https://feed.example.org/rss"}),
        (admin_client, "put", "/api/admin/settings/news", {"enabled": False, "nested": {"k\u0000": 1}}),
    ]
    for c, method, url, body in calls:
        r = await getattr(c, method)(url, json=body)
        assert r.status_code == 422, (url, r.status_code, r.text[:200])
    for url in ("/api/news?q=%00", "/api/news?q=a%00b", "/api/news/recent?since=%00"):
        r = await reader_client.get(url)
        assert r.status_code == 422 and r.json()["detail"]["code"] == "invalid", (url, r.status_code)


async def test_a_deeply_nested_body_is_a_422_not_a_500(client, admin_client):
    """The NUL check walked a body recursively: "[" a few thousand times (json.loads takes it) was a RecursionError –
    a 500 with a thousand-frame traceback in the log, before any sign-in."""
    deep = "[" * 5000 + "]" * 5000
    for c, url, body in (
        (client, "/api/auth/login", deep),
        (client, "/api/auth/login", '{"username": "a", "password": "b", "x": ' + deep + "}"),
        (admin_client, "/api/admin/users", '{"username": "neu", "display_name": ' + deep + "}"),
    ):
        r = await c.post(url, content=body.encode(), headers={"content-type": "application/json"})
        assert r.status_code == 422, (url, r.status_code, r.text[:200])
    nested: list = ["a\u0000"]
    for _ in range(100_000):
        nested = [nested]
    assert db.has_nul(nested) and not db.has_nul([[[["ok", {"k": ["v"]}]]]])


async def test_read_all_up_to_a_number_beyond_the_column_is_a_422(reader_client):
    """`upto` without an upper bound reached PostgreSQL as a number out of int32 range – a 500 for any reader."""
    r = await reader_client.post("/api/news/read-all", json={"upto": 10**30})
    assert r.status_code == 422
    assert (await reader_client.post("/api/news/read-all", json={"upto": 2**31 - 1})).status_code == 200


def test_no_secret_of_the_environment_in_the_config_repr(monkeypatch):
    """repr(Config) – a log line, a debugger, an error report – showed SECRET_KEY, the password in DATABASE_URL and the
    proxy's credentials (the other secrets were already left out)."""
    from app.config import get_config

    monkeypatch.setenv("SECRET_KEY", "k-SECRET-1")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:db-SECRET-2@db/cobe_news")
    monkeypatch.setenv("HTTPS_PROXY", "http://p:proxy-SECRET-3@proxy.corp.example:3128")
    monkeypatch.setenv("BACKUP_PASSPHRASE", "bk-SECRET-4-long-enough")
    monkeypatch.setenv("POSTGRES_RESTORE_PASSWORD", "rs-SECRET-5")
    get_config.cache_clear()
    try:
        c = get_config()
        assert "SECRET" not in repr(c)
        assert c.secret_key == "k-SECRET-1" and c.proxy.startswith("http://p:proxy-SECRET-3@")
    finally:
        get_config.cache_clear()


async def test_the_database_drops_a_nul_that_slipped_through():
    """Defence in depth: text and JSON columns drop U+0000 on the way in (db.SafeText / db.SafeJson)."""
    async with db.session() as s:
        u = User(username="nul\u0000user", display_name="A\u0000B", role="reader", auth_source="local", desktop={"k\u0000": ["v\u0000"]})
        s.add(u)
        await s.commit()
        await s.refresh(u)
        assert u.username == "nuluser" and u.display_name == "AB" and u.desktop == {"k": ["v"]}


async def test_a_failed_statement_does_not_carry_its_values_into_the_log():
    """Security review 0.1.16 L2: a failed INSERT logged the whole row – a password hash, encrypted secrets, e-mail.
    The engine hides the parameters (hide_parameters=True)."""
    from sqlalchemy.exc import IntegrityError

    secret = "argon2-hash-that-must-not-be-logged"
    async with db.session() as s:
        s.add(User(username="dup", display_name="A", role="reader", auth_source="local", password_hash=secret))
        await s.commit()
    with pytest.raises(IntegrityError) as err:
        async with db.session() as s:
            s.add(User(username="dup", display_name="B", role="reader", auth_source="local", password_hash=secret))
            await s.commit()
    assert secret not in str(err.value) and "hidden" in str(err.value)


async def test_desktop_choice_takes_short_source_ids_only(reader_client):
    """Security review 0.1.31: the desktop choice is stored on the account and read by every push round – 50 entries of
    any length let one reader keep up to the body limit (a megabyte) in their row. Each entry is a source id now."""
    long = {"enabled": True, "severities": ["high"], "sources": ["x" * 20_000] * 50}
    r = await reader_client.put("/api/me/desktop", json=long)
    assert r.status_code == 422
    ok = {"enabled": True, "severities": ["high"], "sources": ["0b3a6d2e-7c1f-4f7e-9d8a-2b9f0c1d2e3f"]}
    assert (await reader_client.put("/api/me/desktop", json=ok)).status_code == 200
