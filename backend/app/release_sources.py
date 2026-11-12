"""Release data for products endoflife.date does not know – the catalogue's `releases` field (app/catalog_data.py
ReleaseSource) names a source per product, as data:

- GitHub releases: `releases: {github: owner/repo, tag: <regex with a group 'version'>, lts: <regex on the title>}` –
  the repository's public Atom feed (https://github.com/<owner>/<repo>/releases.atom: no token, not GitHub's API and
  its rate limit). The feed lists the newest 10 releases only (no paging; tags.atom lists the same 10) – so what was
  seen is kept and the history grows with every fetch. The version is read from the tag (from the release's link),
  never from the free-text title; "v" is dropped.
- A vendor's release notes page: `releases: {page: https://…, pattern: <regex with 'version' and optionally 'date'>}` –
  the HTML read as text (no JavaScript, bounded size), the pattern searched in it (Passwork: "Aug 03, 2026 — Passwork
  7.7.0" counts, "Desktop app 1.4.1" not).
Pre-releases (rc, beta, alpha, preview, dev …, in the tag or the title) are left out unless `prerelease: true`.

From the versions: release lines (the first `lines` parts, default 2 – 7.6.2 → 7.6; a line is LTS when one of its
releases' titles matches `lts`), the newest version per line, the date the line was first seen – in endoflife.date's
shape (vendor_catalog.product_releases), so "neue Version verfügbar", "Neuere Linie" and the target versions work as
with endoflife.date. These sources have no support or EOL dates: isEol stays unknown ("Support-Ende unbekannt") and no
EOL event is ever made from them. endoflife.date comes first: a product with lines there never reads these.

Fetched in the Vendor News round with endoflife.date's cadence (`eol_every_h`, default 24 h) – for followed products
only (no request without a followed product), one vendor_fetch row per product (releases:<key> – conditional requests,
backoff after errors, source health family "releases"), through vendor.get (the news fetcher's hardened download:
https only, no internal targets, DNS pinned, size and time limits; redirects stay on the source's host). Kept in
DATA_DIR/vendor_releases.json next to the refreshed catalogue (vendor_catalog.json), written atomically (0600) and read
again when it changes. A lost file is filled again by the next fetch (the conditional headers are only sent while
the file still has the product's data).

Baseline: the versions of a product's first fetch (and of a source changed in the catalogue) are marked `base` – a
"neue Version" event for one of them is silent (vendor._evaluate_product via vendor_catalog.release_baseline): when
Passwork first gets release data, 7.7.0 being out is shown, not notified; 7.7.1 appearing later is news.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import os
import re
import threading
import xml.etree.ElementTree as ET
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from urllib.parse import unquote, urlsplit

log = logging.getLogger("cobe_news.vendor")

FORMAT = 1
KEY_PREFIX = "releases:"
ATOM = "{http://www.w3.org/2005/Atom}"
ATOM_LIMIT = 4 * 1024 * 1024  # wazuh/wazuh's feed with its release notes: 0.7 MB
PAGE_LIMIT = 3 * 1024 * 1024  # Passwork's release notes: 0.5 MB
TEXT_MAX = 2_000_000  # characters of a page's text the pattern is searched in
KEEP_VERSIONS = 300  # per product (the oldest by version go first)
LINES_MAX = 30
DEFAULT_TAG = r"^v?(?P<version>\d+(?:\.\d+){1,3})$"
PRERELEASE = re.compile(r"(?i)(?:^|[^a-z])(?:rc|beta|alpha|preview|pre-?release|dev|nightly|snapshot|test|canary|insider)(?:[^a-z]|$)")
VERSION = re.compile(r"^\d+(?:\.\d+){0,5}$")
DATE_FORMATS = ("%Y-%m-%d", "%b %d, %Y", "%B %d, %Y", "%d %B %Y", "%d %b %Y", "%d.%m.%Y", "%b %d %Y", "%B %d %Y")


class _Cache:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.stamp: float | None = None
        self.data: dict = {"format": FORMAT, "products": {}}
        self.lines: dict[str, list[dict]] = {}


_cache = _Cache()


def _data_file() -> Path:
    from app.config import get_config

    return get_config().data_dir / "vendor_releases.json"


def reset() -> None:
    """Tests: read the file again."""
    with _cache.lock:
        _cache.stamp, _cache.data, _cache.lines = None, {"format": FORMAT, "products": {}}, {}


# ---------------------------------------------------------------- the source of a product


def config(product: dict | None) -> dict | None:
    cfg = (product or {}).get("releases")
    return cfg if isinstance(cfg, dict) and (cfg.get("github") or cfg.get("page")) else None


def signature(cfg: dict) -> str:
    """What the stored data were read with – another source or rule in the catalogue starts over (a new baseline)."""
    return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()[:16]


def url_of(cfg: dict) -> str:
    return f"https://github.com/{cfg['github']}/releases.atom" if cfg.get("github") else str(cfg["page"])


def describe(cfg: dict) -> dict:
    """What the drawer says about the source: {"kind": github|page, "ref": owner/repo or host, "url": human page}."""
    if cfg.get("github"):
        return {"kind": "github", "ref": cfg["github"], "url": f"https://github.com/{cfg['github']}/releases"}
    u = urlsplit(str(cfg["page"]))
    return {"kind": "page", "ref": u.hostname or "", "url": str(cfg["page"])}


# ---------------------------------------------------------------- parsers (pure – tested with saved real answers)


def _norm(v: str) -> str | None:
    v = (v or "").strip()
    v = v[1:] if v[:1] in ("v", "V") else v
    return v if VERSION.fullmatch(v) and len(v) <= 40 else None


def _day(text: str | None) -> str | None:
    t = re.sub(r"\s+", " ", (text or "").strip())
    if not t:
        return None
    if re.match(r"^\d{4}-\d{2}-\d{2}", t):
        t = t[:10]
    for f in DATE_FORMATS:
        try:
            return datetime.strptime(t, f).date().isoformat()  # noqa: DTZ007 - a calendar day
        except ValueError:
            continue
    return None


def _pre(*texts: str) -> bool:
    return any(PRERELEASE.search(t or "") for t in texts)


def parse_github_atom(body: bytes, cfg: dict) -> list[dict]:
    """The releases of a GitHub releases.atom: [{"v", "date", "lts"}] – tags the `tag` rule does not take and (unless
    configured) pre-releases left out. The tag comes from the entry's link (…/releases/tag/<tag>), else its id."""
    from app.news import _refuse_dtd

    _refuse_dtd(body)
    root = ET.fromstring(body)  # noqa: S314 - no DTD (refused above), no external entities in ElementTree
    if root.tag != f"{ATOM}feed":
        raise ValueError("not an Atom feed")
    tag_rx = re.compile(cfg.get("tag") or DEFAULT_TAG)
    lts_rx = re.compile(cfg["lts"]) if cfg.get("lts") else None
    out: dict[str, dict] = {}
    for e in root.findall(f"{ATOM}entry"):
        tag = ""
        for link in e.findall(f"{ATOM}link"):
            href = link.get("href") or ""
            if "/releases/tag/" in href:
                tag = unquote(href.split("/releases/tag/", 1)[1])
                break
        if not tag:
            tag = (e.findtext(f"{ATOM}id") or "").rsplit("/", 1)[-1]
        title = (e.findtext(f"{ATOM}title") or "").strip()[:200]
        m = tag_rx.fullmatch(tag.strip()[:120])
        if m is None or not m.groupdict().get("version"):
            continue
        if not cfg.get("prerelease") and _pre(tag, title):
            continue
        v = _norm(m.group("version"))
        if v is None:
            continue
        day = _day(e.findtext(f"{ATOM}updated") or e.findtext(f"{ATOM}published"))
        row = {"v": v, "date": day, "lts": bool(lts_rx and lts_rx.search(title))}
        old = out.get(v)
        if old is None or (day or "") > (old.get("date") or ""):
            out[v] = row | {"lts": row["lts"] or bool(old and old["lts"])}
    return list(out.values())


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _drop_blocks(src: str) -> str:
    """The HTML without the content of <script> and <style> elements – linear: str.find from a position that only moves
    forward (each tag name's next opening is searched again only once it lies behind), an unclosed element drops the
    rest of the page as a browser would. A regular expression over unclosed tags backtracks quadratically (a hostile
    3 MB page of "<script" took minutes – and re holds the GIL, so to_thread would not spare the event loop)."""
    low = src.translate(_ASCII_LOWER)  # same length as src (str.lower() may not be: "İ" → "i̇")
    out: list[str] = []
    pos = 0
    nxt = {name: low.find(f"<{name}", 0) for name in ("script", "style")}
    while True:
        for name, at in nxt.items():
            if 0 <= at < pos:
                nxt[name] = low.find(f"<{name}", pos)
        live = [(at, name) for name, at in nxt.items() if at >= 0]
        if not live:
            out.append(src[pos:])
            break
        at, name = min(live)
        after = at + 1 + len(name)
        if after < len(low) and low[after] not in " \t\r\n\f/>":
            out.append(src[pos:after])  # <scripts>, <styles…>: another tag, kept
            pos = after
            continue
        out.append(src[pos:at])
        end = low.find(f"</{name}", after)
        if end < 0:
            break  # unclosed: the rest is the element's content
        close = low.find(">", end)
        pos = len(low) if close < 0 else close + 1
        out.append(" ")
    return "".join(out)


def page_text(body: bytes) -> str:
    """A page's HTML as plain text – linear (no regex over unclosed tags), script and style left out, bounded."""
    import nh3

    from app import news

    src = body[:PAGE_LIMIT].decode("utf-8", "replace")
    if news._tame(src):
        text = html.unescape(nh3.clean(news._BREAKS.sub("\n", src), tags=set()))
    else:
        text = news._plain(_drop_blocks(src))
    return re.sub(r"[ \t\r\f\v\xa0]+", " ", text)[:TEXT_MAX]


def parse_page(body: bytes, cfg: dict) -> list[dict]:
    """The releases a vendor's page names: every match of `pattern` in its text ({"v", "date"}); pre-releases left out
    unless configured, each version once (the first – newest – mention)."""
    rx = re.compile(cfg["pattern"])
    out: dict[str, dict] = {}
    for m in rx.finditer(page_text(body)):
        g = m.groupdict()
        v = _norm(g.get("version") or "")
        if v is None or v in out:
            continue
        if not cfg.get("prerelease") and _pre(m.group(0)):
            continue
        out[v] = {"v": v, "date": _day(g.get("date")), "lts": False}
        if len(out) >= KEEP_VERSIONS:
            break
    return list(out.values())


def parse(body: bytes, cfg: dict) -> list[dict]:
    return parse_github_atom(body, cfg) if cfg.get("github") else parse_page(body, cfg)


# ---------------------------------------------------------------- versions → lines


def _key(v: str) -> tuple[int, ...]:
    k = [int(x) for x in v.split(".")]
    while len(k) > 1 and k[-1] == 0:
        k.pop()
    return tuple(k)


def lines_of(versions: list[dict], depth: int = 2) -> list[dict]:
    """endoflife.date-shaped release lines, newest first: name (the first `depth` parts as written – "26.09"), latest
    (the highest version of the line) and its date, releaseDate (the earliest date seen in the line), isLts. No
    support fields – unknown."""
    by: dict[str, list[dict]] = {}
    for r in versions:
        v = str(r.get("v") or "")
        if not VERSION.fullmatch(v):
            continue
        by.setdefault(".".join(v.split(".")[:depth]), []).append(r)
    out = []
    for name, rows in by.items():
        top = max(rows, key=lambda r: (_key(r["v"]), len(r["v"])))
        days = [r["date"] for r in rows if r.get("date")]
        line = {"name": name, "latest": top["v"], "isLts": any(r.get("lts") for r in rows), "_k": _key(name)}
        if top.get("date"):
            line["latestDate"] = top["date"]
        if days:
            line["releaseDate"] = min(days)
        out.append(line)
    out.sort(key=lambda r: r["_k"], reverse=True)
    for r in out:
        del r["_k"]
    return out[:LINES_MAX]


def merge(old: dict | None, found: list[dict], cfg: dict, now: datetime) -> tuple[dict, int]:
    """The stored entry with a fetch's versions added: (entry, how many versions are new). The first fetch of a source
    (or one changed in the catalogue) is the baseline – its versions are marked `base`."""
    sig = signature(cfg)
    fresh = old is None or old.get("sig") != sig or not old.get("versions")
    have = {} if fresh else {r["v"]: dict(r) for r in old.get("versions") or [] if isinstance(r, dict) and r.get("v")}
    new = 0
    for r in found:
        cur = have.get(r["v"])
        if cur is None:
            have[r["v"]] = {"v": r["v"], "date": r.get("date"), "lts": bool(r.get("lts")), "base": fresh}
            new += 1
        else:
            if r.get("date") and not cur.get("date"):
                cur["date"] = r["date"]
            cur["lts"] = bool(cur.get("lts") or r.get("lts"))
    rows = sorted(have.values(), key=lambda r: _key(r["v"]), reverse=True)[:KEEP_VERSIONS]
    at = now.replace(microsecond=0).isoformat()
    entry = {"sig": sig, "source": describe(cfg), "since": at if fresh else (old or {}).get("since") or at, "fetched_at": at, "found": len(found), "versions": rows}
    return entry, (0 if fresh else new)


# ---------------------------------------------------------------- stored data


def _read() -> dict:
    path = _data_file()
    try:
        stamp = path.stat().st_mtime
    except OSError:
        stamp = 0.0
    with _cache.lock:
        if _cache.stamp == stamp:
            return _cache.data
        data: dict = {"format": FORMAT, "products": {}}
        if stamp:
            try:
                d = json.loads(path.read_text())
                if isinstance(d, dict) and d.get("format") == FORMAT and isinstance(d.get("products"), dict):
                    data = d
            except (OSError, ValueError):
                log.warning("release data: %s unreadable – fetched again", path)
        _cache.stamp, _cache.data, _cache.lines = stamp, data, {}
        return data


def entry(key: str) -> dict | None:
    e = _read()["products"].get(key)
    return e if isinstance(e, dict) else None


def _write(products: dict) -> None:
    path = _data_file()
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"format": FORMAT, "products": products}, f, separators=(",", ":"))
    tmp.replace(path)
    with _cache.lock:
        _cache.stamp = None


def store(key: str, e: dict) -> None:
    products = dict(_read()["products"])
    products[key] = e
    _write(products)


def lines(product: dict) -> list[dict]:
    """The release lines of a product with a release source (endoflife.date's shape) – [] without data, or when the
    stored data were read from another source than the catalogue names now."""
    cfg = config(product)
    if cfg is None:
        return []
    key = str(product.get("key") or "")
    data = _read()
    with _cache.lock:
        got = _cache.lines.get(key)
    if got is not None:
        return list(got)
    e = data["products"].get(key)
    rows = lines_of(e.get("versions") or [], int(cfg.get("lines") or 2)) if isinstance(e, dict) and e.get("sig") == signature(cfg) else []
    with _cache.lock:
        if _cache.data is data:
            _cache.lines[key] = rows
    return list(rows)


def info(product: dict) -> dict | None:
    """The source for the drawer: kind, ref, url, when it was fetched last (None: not yet)."""
    cfg = config(product)
    if cfg is None:
        return None
    e = entry(str(product.get("key") or ""))
    ok = isinstance(e, dict) and e.get("sig") == signature(cfg)
    return describe(cfg) | {"fetched_at": e.get("fetched_at") if ok else None}


def is_base(product: dict, version: str | None) -> bool:
    """A version of the product's first fetch (the baseline): "neue Version" for it is shown, not notified."""
    if not version or config(product) is None:
        return False
    e = entry(str(product.get("key") or ""))
    if not isinstance(e, dict):
        return False
    return any(r.get("v") == version and r.get("base") for r in e.get("versions") or [])


def newest_day(key: str) -> date | None:
    e = entry(key)
    days = [r["date"] for r in (e or {}).get("versions") or [] if r.get("date")]
    try:
        return date.fromisoformat(max(days)) if days else None
    except ValueError:
        return None


# ---------------------------------------------------------------- fetching (the Vendor News round)


def wanted(products: list[dict]) -> list[dict]:
    """The followed products that read a release source (endoflife.date first: a product with lines there does not)."""
    from app import vendor_catalog

    return [p for p in products if config(p) is not None and not vendor_catalog.releases(p.get("eol"))]


def fetch_key(product: dict) -> str:
    return f"{KEY_PREFIX}{product['key']}"[:300]


async def sync(db, products: list[dict], every: timedelta, force: bool) -> dict[str, int]:  # noqa: ANN001
    """The due release sources of these (followed) products – one request each (a feed two products share is asked
    once per round). Returns {fetch key: new versions}."""
    from app import source_health
    from app import vendor as svc
    from app.news import NewsError

    out: dict[str, int] = {}
    bodies: dict[str, bytes] = {}
    for p in wanted(products):
        cfg = config(p)
        assert cfg is not None
        key = fetch_key(p)
        st = await svc._state(db, key)
        if not svc._due(st, datetime.now(UTC), force):
            continue
        url = url_of(cfg)
        host = urlsplit(url).hostname or ""
        old = entry(p["key"])
        have = isinstance(old, dict) and old.get("sig") == signature(cfg) and bool(old.get("versions"))
        meter = source_health.start()
        try:
            body = bodies.get(url)
            if not have:  # nothing stored (first fetch, a lost file, another source): asked in full – a 304 would leave it empty
                st.etag = st.last_modified = None
            if body is None:
                accept = "application/atom+xml, application/xml;q=0.9, */*;q=0.1" if cfg.get("github") else "text/html, application/xhtml+xml;q=0.9, */*;q=0.1"
                body = await svc.get(
                    url, db=db, st=st, headers={"Accept": accept}, limit=ATOM_LIMIT if cfg.get("github") else PAGE_LIMIT, only=lambda u, h=host: urlsplit(u).hostname == h
                )
                if body is not None:
                    bodies[url] = body
            if body is None:  # 304: unchanged
                svc._ok(st, every)
                svc._record(db, st, meter)
                await db.commit()
                continue
            found = await asyncio.to_thread(parse, body, cfg)
            if not found:
                raise NewsError("parse", "no version found")
            e, new = merge(old if have else None, found, cfg, datetime.now(UTC))
            await asyncio.to_thread(store, p["key"], e)
            svc._ok(st, every, len(e["versions"]))
            svc._record(db, st, meter, items=new)
            await db.commit()
            out[key] = new
            if new or not have:  # an unchanged list (a 200 without validators) changes nothing that is shown
                changed(p["key"])
        except Exception as exc:  # noqa: BLE001 - one source, not the round
            await db.rollback()
            if not isinstance(exc, NewsError) and isinstance(exc, ET.ParseError | ValueError | re.error):
                exc = NewsError("parse", type(exc).__name__)
            st = await svc._state(db, key)
            svc._record(db, st, meter, exc=svc._fail(st, exc, every))
            await db.commit()
    return out


def changed(key: str) -> None:
    """New release data for a product: its views, depth and the plausibility caches are computed again."""
    from app import vendor as svc
    from app import vendor_catalog, version_input

    vendor_catalog._depths.pop(f"{KEY_PREFIX}{key}", None)
    version_input.clear()
    svc.bump([key])
