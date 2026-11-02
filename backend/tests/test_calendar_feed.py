"""The calendar feed (app/calendar_feed.py): a secret address per person (≥ 128 bit, only its keyed hash stored, shown
once, a new one ends the old one, deletable, dead with the account), the content fresh per request (role and teams:
an admin every followed product, a reader the products of their team routing), RFC 5545 as a calendar client reads it
(CRLF, lines folded at 75 octets, TEXT escaped – a product name cannot inject a property or an event –, a stable UID
per version, DTSTAMP, two reminders) and its limits. A small parser below checks the format – no new dependency."""

import re
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select

from app import calendar_feed, db
from app import vendor_catalog as catalog
from app.crypto import token_hash
from app.models import CalendarFeed, User, VendorFollow, VendorVersion
from conftest import make_client, sign_in
from test_personal import _person, _switch, _team

PAST = datetime.now(UTC) - timedelta(days=30)
EOL = (datetime.now(UTC).date() + timedelta(days=200)).isoformat()


# ---------------------------------------------------------------- a small RFC 5545 reader


def parse(body: bytes) -> list[dict]:
    """The calendar as a list of components {"name", "props": [(name, params, value)], "subs": [...]} – after checking
    the physical format: every line ends with CRLF, none longer than 75 octets, continuation lines start with one space,
    nothing but CRLF ends a line. Raises AssertionError on anything a strict client would refuse."""
    assert body.endswith(b"\r\n")
    physical = body[:-2].split(b"\r\n")
    for ln in physical:
        assert len(ln) <= 75, ln
        assert b"\r" not in ln and b"\n" not in ln, ln
        ln.decode("utf-8")  # never a broken UTF-8 character (folding inside one)
    logical: list[bytes] = []
    for ln in physical:
        if ln.startswith((b" ", b"\t")):
            assert logical, "a continuation without a line"
            logical[-1] += ln[1:]
        else:
            logical.append(ln)
    root: list[dict] = []
    stack: list[dict] = []
    prop = re.compile(r"^([A-Z][A-Z0-9-]*)((?:;[A-Z-]+=[^;:]*)*):(.*)$", re.S)
    for raw in logical:
        text = raw.decode("utf-8")
        m = prop.match(text)
        assert m, text
        name, params, value = m.group(1), m.group(2), m.group(3)
        if name == "BEGIN":
            comp = {"name": value, "props": [], "subs": []}
            (stack[-1]["subs"] if stack else root).append(comp)
            stack.append(comp)
        elif name == "END":
            assert stack and stack[-1]["name"] == value, f"END:{value} without BEGIN"
            stack.pop()
        else:
            assert stack, f"{name} outside a component"
            stack[-1]["props"].append((name, params, value))
    assert not stack, "a component not ended"
    return root


def unescape(v: str) -> str:
    out, i = [], 0
    while i < len(v):
        c = v[i]
        if c == "\\":
            nxt = v[i + 1]
            out.append("\n" if nxt in "nN" else nxt)
            assert nxt in "nN\\;,", f"bad escape \\{nxt}"
            i += 2
            continue
        assert c not in ";,", f"unescaped {c!r}"  # a raw ; or , would split the value for a client
        out.append(c)
        i += 1
    return "".join(out)


def props(comp: dict, name: str) -> list[str]:
    return [v for n, _p, v in comp["props"] if n == name]


def events(body: bytes) -> list[dict]:
    (cal,) = parse(body)
    assert cal["name"] == "VCALENDAR" and props(cal, "VERSION") == ["2.0"] and props(cal, "PRODID")
    return [c for c in cal["subs"] if c["name"] == "VEVENT"]


# ---------------------------------------------------------------- the format


def _entry(**kw) -> dict:
    return {"id": "2b9c0f0e-8f3a-4c41-9d52-1b6f7f6b9e01", "product": "PAN-OS", "version": "11.1.2", "line": "11.1", "date": date(2027, 1, 31), "url": "https://news.corp.example/vendor?product=panos&view=versions", "stamp": datetime(2026, 10, 1, 8, 0, tzinfo=UTC)} | kw


def test_rfc5545_format_and_reminders():
    body = calendar_feed.render([_entry()], "de", "news.corp.example")
    assert body.startswith(b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\n")
    (ev,) = events(body)
    assert props(ev, "UID") == ["eol-2b9c0f0e-8f3a-4c41-9d52-1b6f7f6b9e01@news.corp.example"]
    assert props(ev, "DTSTAMP") == ["20261001T080000Z"]
    assert [(p, v) for n, p, v in ev["props"] if n == "DTSTART"] == [(";VALUE=DATE", "20270131")]
    assert [(p, v) for n, p, v in ev["props"] if n == "DTEND"] == [(";VALUE=DATE", "20270201")]
    assert unescape(props(ev, "SUMMARY")[0]) == "Support-Ende: PAN-OS 11.1.2"
    desc = unescape(props(ev, "DESCRIPTION")[0])
    assert "Support-Ende: 2027-01-31" in desc and "https://news.corp.example/vendor?product=panos&view=versions" in desc
    alarms = [s for s in ev["subs"] if s["name"] == "VALARM"]
    assert [props(a, "TRIGGER") for a in alarms] == [["-P90D"], ["-P30D"]] and all(props(a, "ACTION") == ["DISPLAY"] and props(a, "DESCRIPTION") for a in alarms)
    # the same data, the same calendar: stable UID and DTSTAMP (no "changed" every poll)
    assert calendar_feed.render([_entry()], "de", "news.corp.example") == body
    assert b"END:VCALENDAR\r\n" == body[-15:]


@pytest.mark.parametrize(
    "name",
    [
        "Evil\r\nBEGIN:VEVENT\r\nSUMMARY:pwned",
        "Evil\nEND:VCALENDAR",
        "Semi;colon,comma\\backslash",
        "DESCRIPTION:fake;X-ALT-DESC=1",
        "Ünïcödé – 🚀 " * 12,
        "tab\tand\x00nul\x1b[2Jescape sep",
    ],
)
def test_no_injection_through_names(name):
    body = calendar_feed.render([_entry(product=name, version="1;2,3\n4")], "en", "news.corp.example")
    evs = events(body)
    assert len(evs) == 1  # still one event – nothing began or ended in between
    (ev,) = evs
    assert len(props(ev, "SUMMARY")) == 1 and len(props(ev, "DESCRIPTION")) == 1 and len(props(ev, "UID")) == 1
    summary = unescape(props(ev, "SUMMARY")[0])
    clean = re.sub(r"[\x00-\x08\x0b-\x1f\x7f  ]", "", name.replace("\r\n", "\n").replace("\r", "\n"))
    assert summary == f"End of support: {clean} 1;2,3\n4"
    # nothing of it stands at the start of a line
    for ln in body.split(b"\r\n"):
        assert not ln.startswith((b"BEGIN:VEVENT", b"SUMMARY:pwned", b"END:VCALENDAR")) or ln in (b"BEGIN:VEVENT", b"END:VCALENDAR")


def test_folding_never_splits_a_character():
    long = "ä" * 100 + "🚀" * 30
    folded = calendar_feed.fold("SUMMARY:" + long)
    for ln in folded[:-2].split(b"\r\n"):
        assert len(ln) <= 75
        ln.decode("utf-8")
    assert folded.replace(b"\r\n ", b"").decode() == "SUMMARY:" + long + "\r\n"


# ---------------------------------------------------------------- the address


@pytest.fixture
def eol(monkeypatch):
    rel = [{"name": "11.1", "label": "11.1", "releaseDate": "2023-06-01", "latest": "11.1.4", "eolFrom": EOL, "isMaintained": True}]
    monkeypatch.setattr(catalog, "releases", lambda key: rel if key == "panos" else [])


async def _follow(product: str, *versions: str) -> None:
    async with db.session() as s:
        f = await s.scalar(select(VendorFollow).where(VendorFollow.product == product))
        if f is None:
            f = VendorFollow(product=product, baseline_at=PAST)
            s.add(f)
            await s.flush()
        for v in versions:
            s.add(VendorVersion(follow_id=f.id, version=v, label="Rechenzentrum von Max Muster", baseline_at=PAST))
        await s.commit()


def _token(url: str) -> str:
    m = re.fullmatch(r"https://news\.corp\.example:8095/cal/([A-Za-z0-9_-]{43})\.ics", url)
    assert m, url
    return m.group(1)


async def _get(token: str, client=None):  # noqa: ANN001
    async with make_client() as anon:  # a calendar client: no cookie, no CSRF token
        return await (client or anon).get(f"/cal/{token}.ics")


async def test_token_shown_once_hash_only_rotate_delete(reader_client, eol):
    assert (await reader_client.get("/api/me/calendar")).json()["active"] is False
    r = await reader_client.post("/api/me/calendar")
    assert r.status_code == 200
    token = _token(r.json()["url"])
    assert len(token) * 6 >= 256  # 32 random bytes (≥ 128 bit asked)
    async with db.session() as s:
        row = await s.get(CalendarFeed, reader_client.user.id)
        assert row.token_hash == token_hash(token) and token not in row.token_hash
    me = await reader_client.get("/api/me/calendar")
    assert me.json()["active"] is True and token not in me.text  # never shown again
    got = await _get(token)
    assert got.status_code == 200 and got.headers["content-type"].startswith("text/calendar")
    assert got.headers["cache-control"] == "no-store, private" and "set-cookie" not in got.headers
    assert events(got.content) == []  # a reader in no team: no products
    # a new address ends the old one
    token2 = _token((await reader_client.post("/api/me/calendar")).json()["url"])
    assert (await _get(token)).status_code == 404 and (await _get(token2)).status_code == 200
    assert (await reader_client.delete("/api/me/calendar")).json() == {"removed": True}
    assert (await _get(token2)).status_code == 404
    # writes need the session and CSRF as every API write
    async with make_client() as anon:
        assert (await anon.post("/api/me/calendar")).status_code in (401, 403)


async def test_content_follows_role_and_teams_fresh(admin_client, eol):
    await _follow("panos", "11.1.2", "11.1.3")
    await _follow("fortios", "7.4.8")  # no release data: no date, not in the calendar
    u = await _person("rita")
    async with make_client() as c:
        await sign_in(c, u)
        token = _token((await c.post("/api/me/calendar")).json()["url"])
    assert events((await _get(token)).content) == []  # Teams off: a reader has no products
    await _switch()
    await _team([u], products=("panos",))
    evs = events((await _get(token)).content)
    assert sorted(unescape(props(e, "SUMMARY")[0]) for e in evs) == ["Support-Ende: PAN-OS (Firewalls) 11.1.2", "Support-Ende: PAN-OS (Firewalls) 11.1.3"]
    body = (await _get(token)).text
    assert "Max Muster" not in body and "Rechenzentrum" not in body and "rita" not in body.lower() and "CVE" not in body
    # promoted to admin: every followed product (read fresh, no new address needed)
    async with db.session() as s:
        (await s.get(User, u.id)).role = "admin"
        await s.commit()
    assert len(events((await _get(token)).content)) == 2
    # switched off: 404 – and the address is gone for good
    async with db.session() as s:
        (await s.get(User, u.id)).is_active = False
        await s.commit()
    assert (await _get(token)).status_code == 404
    async with db.session() as s:
        assert await s.get(CalendarFeed, u.id) is None
        (await s.get(User, u.id)).is_active = True
        await s.commit()
    assert (await _get(token)).status_code == 404


async def test_unknown_tokens_and_rate_limits(reader_client, monkeypatch):
    for bad in ("x.ics", "a" * 43, "a" * 43 + ".ics", "../../etc/passwd", "%00" + "a" * 40 + ".ics"):
        assert (await _get(bad.removesuffix(".ics"))).status_code == 404
    monkeypatch.setattr(calendar_feed, "FAIL_MAX", 8)
    calendar_feed.reset()
    for _ in range(8):
        assert (await _get("b" * 43)).status_code == 404
    r = await _get("c" * 43)
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    # a valid token from the same address is held back too (guessing must not go on with a real one in between)
    token = _token((await reader_client.post("/api/me/calendar")).json()["url"])
    assert (await _get(token)).status_code == 429
    calendar_feed.reset()
    monkeypatch.setattr(calendar_feed, "TOKEN_MAX", 2)
    assert [(await _get(token)).status_code for _ in range(3)] == [200, 200, 429]


async def test_feed_route_is_no_api_and_needs_no_csrf(reader_client):
    token = _token((await reader_client.post("/api/me/calendar")).json()["url"])
    async with make_client() as anon:
        r = await anon.get(f"/cal/{token}.ics", headers={"Origin": "https://evil.example"})
    assert r.status_code == 200 and "content-security-policy" in r.headers and r.headers["x-robots-tag"].startswith("noindex")
    async with make_client() as anon:
        assert (await anon.post(f"/cal/{token}.ics")).status_code == 405
