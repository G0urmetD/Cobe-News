"""Release data for products endoflife.date does not know – the catalogue's `releases` field (app/catalog_data.py
ReleaseSource) names a source per product, as data:

- GitHub releases: `releases: {github: owner/repo, tag: <regex with a group 'version'>, lts: <regex on the title>}` –
  the repository's public Atom feed (https://github.com/<owner>/<repo>/releases.atom: no token, not GitHub's API and
  its rate limit). The feed lists the newest 10 releases only (no paging; tags.atom lists the same 10): an older line
  with a late backport (Wazuh 4.10.5) is there, the lines in between (4.11–4.13) are not. So the whole history comes
  from the repository's tags – git's own smart-HTTP ref advertisement
  (https://github.com/<owner>/<repo>.git/info/refs?service=git-upload-pack, what every `git clone` asks first: no token,
  no API, one request; it lists every branch, pull request and tag – n8n's 2.7 MB – so it is read bounded, see
  git_tags). Tags have no date and no title: their versions are kept without a date ("unbekannt") and LTS comes from
  the feed's titles only. The tags are read on the first fetch and then weekly (HISTORY_EVERY); the feed in between
  keeps the newest releases and their dates. A tag is not a release: one ahead of its line's newest release in the
  feed (tagged, the release not published yet) waits for the feed. The version is read from the tag (from the release's link), never from
  the free-text title; "v" is dropped.
- A vendor's release notes page: `releases: {page: https://…, pattern: <regex with 'version' and optionally 'date'>}` –
  the HTML read as text (no JavaScript, bounded size), the pattern searched in it (Passwork: "Aug 03, 2026 — Passwork
  7.7.0" counts, "Desktop app 1.4.1" not).
Pre-releases (rc, beta, alpha, preview, dev …, in the tag or the title) are left out unless `prerelease: true`.

From the versions: release lines (the first `lines` parts, default 2 – 7.6.2 → 7.6; a line is LTS when one of its
releases' titles matches `lts`; a product of the build scheme – ManageEngine's builds 14600, 16040 – has its major as
the line, as vendor._line_name), the newest version per line, the date of the line's first release where it is known –
in endoflife.date's shape (vendor_catalog.product_releases), so "neue Version verfügbar", "Neuere Linie" and the target
versions work as with endoflife.date. Lines are ordered by version, never by date: a date here is when a release was
published (or only seen), and an older line's backport is younger than a newer line's start. These sources have no
support or EOL dates: isEol stays unknown ("Support-Ende unbekannt") and no EOL event is ever made from them.
endoflife.date comes first: a product with lines there never reads these.

Fetched in the Vendor News round with endoflife.date's cadence (`eol_every_h`, default 24 h) – for followed products
only (no request without a followed product), one vendor_fetch row per product (releases:<key> – conditional requests,
backoff after errors, source health family "releases"), through vendor.get (the news fetcher's hardened download:
https only, no internal targets, DNS pinned, size and time limits; redirects stay on the source's host). Kept in
DATA_DIR/vendor_releases.json next to the refreshed catalogue (vendor_catalog.json), written atomically (0600) and read
again when it changes. A lost file is filled again by the next fetch (the conditional headers are only sent while
the file still has the product's data).

Baseline: the versions of a product's first fetch (and of a source changed in the catalogue) are marked `base` – a
"neue Version" event for one of them is silent (vendor._evaluate_product via vendor_catalog.release_baseline): when
Passwork first gets release data, 7.7.0 being out is shown, not notified; 7.7.1 appearing later is news. The first
complete history read from the tags is a baseline as well (an installation that had only the feed's 10 gets the old
lines filled in, silently); a version a later tags refresh finds that was never seen is news like one of the feed.
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
REFS_LIMIT = 16 * 1024 * 1024  # a ref advertisement: n8n-io/n8n's 2.7 MB (34 872 pull requests, 2 281 tags), wazuh's 0.9 MB
REFS_PKTS = 500_000  # pkt-lines read at most (n8n: 39 500)
PKT_MAX = 65520  # git's largest pkt-line
TAGS_MAX = 20_000  # tag names kept from one advertisement
HISTORY_EVERY = timedelta(days=7)  # the tags again – the feed keeps the newest releases in between
HISTORY_RETRY = timedelta(days=1)  # after a failed read of the tags (too large: HISTORY_EVERY)
KEEP_VERSIONS = 300  # per product (the oldest by version go first)
LINES_MAX = 30
DEFAULT_TAG = r"^v?(?P<version>\d+(?:\.\d+){1,3})$"
PRERELEASE = re.compile(r"(?i)(?:^|[^a-z])(?:rc|beta|alpha|preview|pre-?release|dev|nightly|snapshot|test|canary|insider)(?:[^a-z]|$)")
VERSION = re.compile(r"^\d+(?:\.\d+){0,5}$")
DATE_FORMATS = ("%Y-%m-%d", "%b %d, %Y", "%B %d, %Y", "%d %B %Y", "%d %b %Y", "%d %B, %Y", "%d %b, %Y", "%d.%m.%Y", "%b %d %Y", "%B %d %Y")
OID = re.compile(rb"[0-9a-f]{40}(?:[0-9a-f]{24})?")  # SHA-1 or SHA-256 object names
PKT_LEN = re.compile(rb"[0-9a-fA-F]{4}")


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


def refs_url(cfg: dict) -> str:
    """git's smart-HTTP ref advertisement of the repository – every tag (GitHub: no token, no API rate limit)."""
    return f"https://github.com/{cfg['github']}.git/info/refs?service=git-upload-pack"


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


def is_prerelease(text: str | None) -> bool:
    """A version that names itself a pre-release ("5.0.0-beta3", "7.4.0-alpha", "1.6.0-RC3") – never a target to
    recommend (vendor.target_versions), said as "Vorabversion" where a record names it as the fix."""
    return bool(text) and _pre(str(text)[:80])


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


def git_tags(body: bytes) -> list[str]:
    """The tag names of a git smart-HTTP ref advertisement, in its order (each once – an annotated tag's peeled
    "<tag>^{}" is the same tag). The format (gitprotocol-http, gitprotocol-pack): pkt-lines – four hex digits giving
    the length including themselves, then the payload; 0000 flushes. First "# service=git-upload-pack", a flush, then
    one line per ref: "<object name> <ref name>" (the first with NUL and the capabilities). Read strictly and bounded:
    a length that is no hex number, below 4 or beyond PKT_MAX or the body, a ref line without an object name, no
    service line – ValueError (a page in between, a cut answer); at most REFS_PKTS lines, TAGS_MAX tags. Linear: one
    pass, no regular expression over the body (each pkt-line is sliced, not searched)."""
    size, pos, n = len(body), 0, 0
    service = False
    tags: dict[str, None] = {}
    while pos < size:
        n += 1
        if n > REFS_PKTS:
            raise ValueError("too many pkt-lines")
        head = body[pos : pos + 4]
        if not PKT_LEN.fullmatch(head):
            raise ValueError("not a pkt-line")
        ln = int(head, 16)
        if ln < 4:  # 0000 flush, 0001 delimiter, 0002 end of response
            if ln == 3:
                raise ValueError("bad pkt-line length")
            pos += 4
            continue
        if ln > PKT_MAX or pos + ln > size:
            raise ValueError("bad pkt-line length")
        line = body[pos + 4 : pos + ln].split(b"\0", 1)[0].rstrip(b"\n")
        pos += ln
        if not service:
            if line != b"# service=git-upload-pack":
                raise ValueError("not a git ref advertisement")
            service = True
            continue
        if line.startswith(b"version "):  # protocol v1 says so first
            continue
        oid, _, ref = line.partition(b" ")
        if not OID.fullmatch(oid) or not ref:
            raise ValueError("not a ref line")
        if not ref.startswith(b"refs/tags/"):
            continue
        name = ref[10:].removesuffix(b"^{}")
        if 0 < len(name) <= 200:
            tags.setdefault(name.decode("utf-8", "replace"))
            if len(tags) >= TAGS_MAX:
                break
    if not service:
        raise ValueError("not a git ref advertisement")
    return list(tags)


def parse_tags(body: bytes, cfg: dict) -> list[dict]:
    """The versions of a GitHub repository's tags (git_tags): [{"v", "date": None, "lts": False}] – the catalogue's `tag`
    rule and the pre-release filter as for the feed (only the tag is known here, no title)."""
    tag_rx = re.compile(cfg.get("tag") or DEFAULT_TAG)
    out: dict[str, dict] = {}
    for tag in git_tags(body):
        m = tag_rx.fullmatch(tag.strip()[:120])
        if m is None or not m.groupdict().get("version"):
            continue
        if not cfg.get("prerelease") and _pre(tag):
            continue
        v = _norm(m.group("version"))
        if v is not None and v not in out:
            out[v] = {"v": v, "date": None, "lts": False}
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


def shown(v: str, scheme: str = "generic") -> str:
    """A stored version as the drawer and the matching write it: a build of the build scheme with its line
    ("16040" → "16.0 Build 16040", vendor_versions.build_v), any other as it is."""
    if scheme == "build" and v.isdigit():
        from app.vendor_versions import BUILD_MIN, build_v

        if int(v) >= BUILD_MIN:
            return build_v(int(v)).text
    return v


def _line_name(v: str, depth: int, scheme: str) -> str | None:
    if scheme == "build":
        from app.vendor_versions import BUILD_MIN, build_line

        # the builds are one sequence – the major is the line (vendor._line_name): 14600 and 14990 are line 14
        return str(build_line(int(v))[0]) if v.isdigit() and int(v) >= BUILD_MIN else None
    return ".".join(v.split(".")[:depth])


def lines_of(versions: list[dict], depth: int = 2, scheme: str = "generic", complete: bool = False) -> list[dict]:
    """endoflife.date-shaped release lines, newest (by version) first: name (the first `depth` parts as written –
    "26.09"; the build scheme: the major), latest (the highest version of the line) and its date, isLts, and
    releaseDate – the date of the line's first release, only where it is known: the line's lowest version has a date
    and it is the line's start (x.y or x.y.0), or the source lists every release (`complete`, a vendor's page). The
    earliest date merely seen in a line (the feed's newest 10 had 4.14.7, not 4.14.0) is no release date of the line.
    No support fields – unknown."""
    by: dict[str, list[dict]] = {}
    for r in versions:
        v = str(r.get("v") or "")
        if not VERSION.fullmatch(v) or (name := _line_name(v, depth, scheme)) is None:
            continue
        by.setdefault(name, []).append(r)
    out = []
    for name, rows in by.items():
        top = max(rows, key=lambda r: (_key(r["v"]), len(r["v"])))
        first = min(rows, key=lambda r: (_key(r["v"]), len(r["v"])))
        line = {"name": name, "latest": shown(top["v"], scheme), "isLts": any(r.get("lts") for r in rows), "_k": _key(name)}
        if top.get("date"):
            line["latestDate"] = top["date"]
        if first.get("date") and (complete or (scheme != "build" and _key(first["v"]) == _key(name))):
            line["releaseDate"] = first["date"]
        out.append(line)
    out.sort(key=lambda r: r["_k"], reverse=True)
    for r in out:
        del r["_k"]
    return out[:LINES_MAX]


def history_due(e: dict | None, now: datetime) -> bool:
    """The tags of a GitHub source are read again: never read (or for another source), weekly after a success, a day
    after a failure (a week when the advertisement was too large – it will be next time, too)."""
    h = (e or {}).get("history")
    if not isinstance(h, dict) or not h.get("tried_at"):
        return True
    try:
        tried = datetime.fromisoformat(str(h["tried_at"]))
    except ValueError:
        return True
    err = str(h.get("error") or "")
    wait = HISTORY_RETRY if err and not err.startswith("too_large") else HISTORY_EVERY
    return tried + wait <= now


def merge(old: dict | None, found: list[dict], cfg: dict, now: datetime, tags: list[dict] | None = None, history_error: str | None = None) -> tuple[dict, int]:
    """The stored entry with a fetch's versions added: (entry, how many versions are new). The first fetch of a source
    (or one changed in the catalogue) is the baseline – its versions are marked `base`. `tags`: the versions of the
    repository's tags (parse_tags) when they were read this time – the first complete history is a baseline too; a tag
    newer than the newest release the feed named in its line (v4.14.11 tagged, its release not published yet) waits for
    the feed – a line the feed never named comes from the tags alone. `history_error`: why they could not be read (the
    history stays as it was). New: versions that are news – kept (not trimmed away again: an old tag below the
    KEEP_VERSIONS newest is no news) and not of a baseline."""
    sig = signature(cfg)
    fresh = old is None or old.get("sig") != sig or not old.get("versions")
    have = {} if fresh else {r["v"]: dict(r) for r in old.get("versions") or [] if isinstance(r, dict) and r.get("v")}
    hist = {} if fresh else dict((old or {}).get("history") or {})
    added: set[str] = set()
    for r in found:
        cur = have.get(r["v"])
        if cur is None:
            have[r["v"]] = {"v": r["v"], "date": r.get("date"), "lts": bool(r.get("lts")), "base": fresh}
            added.add(r["v"])
        else:
            if r.get("date") and not cur.get("date"):
                cur["date"] = r["date"]
            cur["lts"] = bool(cur.get("lts") or r.get("lts"))
    at = now.replace(microsecond=0).isoformat()
    if tags is not None:
        first = fresh or not hist.get("ok_at")  # the first complete history: what it fills in was out before
        depth = int(cfg.get("lines") or 2)
        released: dict[str, tuple[int, ...]] = {}  # line → the newest version the feed named (only the feed has dates)
        for r in have.values():
            if r.get("date") and VERSION.fullmatch(r["v"]):
                ln = ".".join(r["v"].split(".")[:depth])
                released[ln] = max(released.get(ln, ()), _key(r["v"]))
        for r in tags:
            if r["v"] in have:
                continue
            ln = ".".join(r["v"].split(".")[:depth])
            if ln in released and _key(r["v"]) > released[ln]:
                continue  # tagged ahead of its line's newest release (the release not published yet): the feed brings it
            have[r["v"]] = {"v": r["v"], "date": None, "lts": False, "base": first}
            added.add(r["v"])
        hist = {"ok_at": at, "tried_at": at, "error": None, "tags": len(tags)}
    elif history_error:
        hist = hist | {"tried_at": at, "error": history_error[:120]}
    rows = sorted(have.values(), key=lambda r: _key(r["v"]), reverse=True)[:KEEP_VERSIONS]
    new = 0 if fresh else sum(1 for r in rows if r["v"] in added and not r.get("base"))
    entry = {"sig": sig, "source": describe(cfg), "since": at if fresh else (old or {}).get("since") or at, "fetched_at": at, "found": len(found), "versions": rows}
    if hist:
        entry["history"] = hist
    return entry, new


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
    ok = isinstance(e, dict) and e.get("sig") == signature(cfg)
    rows = lines_of(e.get("versions") or [], int(cfg.get("lines") or 2), product.get("scheme") or "generic", complete=bool(cfg.get("page"))) if ok else []
    with _cache.lock:
        if _cache.data is data:
            _cache.lines[key] = rows
    return list(rows)


def info(product: dict) -> dict | None:
    """The source for the drawer: kind, ref, url, when it was fetched last (None: not yet), and how complete the
    history is – `complete` (GitHub: True once the tags were read – every version, dates only for the newest releases;
    False: only the feed's newest releases are known; a page: None – what the page lists) and `known` (versions)."""
    cfg = config(product)
    if cfg is None:
        return None
    e = entry(str(product.get("key") or ""))
    ok = isinstance(e, dict) and e.get("sig") == signature(cfg)
    out = describe(cfg) | {"fetched_at": e.get("fetched_at") if ok else None}
    if ok:
        out["known"] = len(e.get("versions") or [])
        out["complete"] = bool((e.get("history") or {}).get("ok_at")) if cfg.get("github") else None
    return out


def is_base(product: dict, version: str | None) -> bool:
    """A version of the product's first fetch (the baseline): "neue Version" for it is shown, not notified. `version`
    as the lines show it (a build: "16.0 Build 16040")."""
    if not version or config(product) is None:
        return False
    e = entry(str(product.get("key") or ""))
    if not isinstance(e, dict):
        return False
    scheme = product.get("scheme") or "generic"
    return any(r.get("base") and shown(str(r.get("v") or ""), scheme) == version for r in e.get("versions") or [])


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


async def _history(db, cfg: dict, memo: dict[str, bytes | str]) -> tuple[list[dict] | None, str | None]:  # noqa: ANN001
    """The versions of a GitHub source's tags (git_tags through vendor.get: https only, github.com only, REFS_LIMIT) –
    (versions, None), or (None, why not). A failure costs the feed nothing: it is kept, the tags are asked again later.
    `memo`: the round's answers (or errors) per URL – a repository two products share is asked once."""
    from app import vendor as svc
    from app.news import NewsError

    url = refs_url(cfg)
    got = memo.get(url)
    if isinstance(got, str):
        return None, got
    try:
        if got is None:
            got = await svc.get(
                url,
                db=db,
                headers={"Accept": "application/x-git-upload-pack-advertisement, */*;q=0.1"},
                limit=REFS_LIMIT,
                conditional=False,
                only=lambda u: urlsplit(u).hostname == "github.com",
            )
            if got is None:
                raise NewsError("http", "no answer")
            memo[url] = got
        return await asyncio.to_thread(parse_tags, got, cfg), None
    except NewsError as exc:
        err = f"{exc.category}: {exc.detail}" if exc.detail else exc.category
    except (ValueError, UnicodeError, re.error) as exc:
        err = f"parse: {exc}"[:120]
    memo[url] = err
    return None, err


async def sync(db, products: list[dict], every: timedelta, force: bool) -> dict[str, int]:  # noqa: ANN001
    """The due release sources of these (followed) products – one request each (a feed two products share is asked
    once per round), and for a GitHub source whose history is due (history_due) its tags. Returns {fetch key: new
    versions}."""
    from app import source_health
    from app import vendor as svc
    from app.news import NewsError

    out: dict[str, int] = {}
    bodies: dict[str, bytes] = {}
    refs: dict[str, bytes | str] = {}
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
            found: list[dict] = []
            if body is not None:
                found = await asyncio.to_thread(parse, body, cfg)
                if not found and not cfg.get("github"):
                    raise NewsError("parse", "no version found")
            tags, hist_err = None, None
            if cfg.get("github") and history_due(old if have else None, datetime.now(UTC)):
                tags, hist_err = await _history(db, cfg, refs)
                if hist_err:
                    log.info("release data %s: tags of %s not read (%s) – the feed's newest releases only", p["key"], cfg["github"], hist_err)
            if body is not None and not found and not tags and not have:
                # a feed whose newest 10 are all pre-releases (DFIR-IRIS: v3.0.0-beta.N) is fine while the tags or
                # the stored history know versions – with neither the rule finds nothing: the source is broken
                raise NewsError("parse", "no version found")
            if body is None and tags is None and hist_err is None:  # 304: unchanged
                svc._ok(st, every)
                svc._record(db, st, meter)
                await db.commit()
                continue
            e, new = merge(old if have else None, found, cfg, datetime.now(UTC), tags=tags, history_error=hist_err)
            if body is None and have:
                e["found"] = old.get("found", 0)  # the feed was unchanged (304): what it listed last time
            await asyncio.to_thread(store, p["key"], e)
            svc._ok(st, every, len(e["versions"]))
            svc._record(db, st, meter, items=new)
            await db.commit()
            out[key] = new
            if new or not have or tags is not None:  # an unchanged list (a 200 without validators) changes nothing that is shown
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
