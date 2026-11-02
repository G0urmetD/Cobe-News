"""CSAF 2.0 providers (catalog/csaf.yaml): the advisories of the vendors whose products are followed, read from the
vendor's own CSAF distribution – not only those a news story points at (story_details).

- Discovery: the provider-metadata.json – the address in the CSAF aggregator of the BSI (AGGREGATOR, read daily while a
  provider is needed) whose host is the provider's domain, else https://<domain>/.well-known/csaf/provider-metadata.json,
  or the address csaf.yaml names. Its distributions: ROLIE feeds (only those labelled TLP:WHITE or TLP:CLEAR) or
  directories (their changes.csv: "<path>,<time>" – newest first).
- Incremental: per provider a watermark (time and address of the last document read, in that order) – each round reads
  the feed or changes.csv (conditional where the server allows it), then the documents changed after the watermark,
  oldest first, DOCS_PER_ROUND at most (a backlog continues BACKLOG_AGAIN later). The first fill goes back INITIAL.
- Each document: its hash file (.sha512, else .sha256 – where the provider offers one) must match, its TLP label must be
  WHITE or CLEAR (a document without a label only from a distribution not labelled otherwise), its publisher namespace
  must be on the provider's domain; then parsed like the details of a story (story_details.parse_csaf) and stored as
  `csaf:<tracking id>` for Siemens and Cisco – the same record their stories store, so an advisory is never there (or
  notified) twice – and as `csaf:<provider>:<tracking id>` for the others. A record of another publisher is never
  replaced (vendor.store). OpenPGP signatures (.asc) are not checked: the key comes from the same server as the
  document and would need an OpenPGP implementation (see docs/BETRIEB.md).
- A provider's document speaks only for the products of the vendors csaf.yaml maps it to, and only through the
  product's own vendor branch (vendor_match.csaf_speaks_for / entries_for).
- What the first fill of a provider brings and is older than FRESH_FILL is marked `initial`: shown, never notified
  (vendor.findings "quiet"); a younger document is notified as any other.
- Only the provider's public addresses are asked; hosts outside the provider's domain are refused – on every redirect
  too, and the advisory link points there or to the document itself.
"""

import asyncio
import csv
import hashlib
import io
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin, urlsplit

from sqlalchemy.ext.asyncio import AsyncSession

from app import source_health
from app import story_details as details
from app import vendor_catalog as catalog
from app import vendor_sources as src
from app.news import NewsError, _date

log = logging.getLogger("cobe_news.csaf")

AGGREGATOR = "https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json"
AGGREGATOR_KEY = "csaf:aggregator"
AGG_EVERY = timedelta(hours=24)
DOCS_PER_ROUND = 25
INITIAL = timedelta(days=90)
BACKLOG_AGAIN = timedelta(minutes=20)
META_LIMIT = 1024 * 1024
LIST_LIMIT = 16 * 1024 * 1024  # a ROLIE feed of all advisories (Siemens: ~1.2 MB) or a changes.csv
DOC_LIMIT = 8 * 1024 * 1024
HASH_LIMIT = 4096
OPEN_TLP = ("WHITE", "CLEAR")
KIND = {"siemens": "siemens", "cisco": "cisco"}  # the kinds story_details uses for the same publishers (same record)
HEX = re.compile(r"^[0-9a-fA-F]{64}(?:[0-9a-fA-F]{64})?$")
# the providers whose records the stories share (KIND): only their own kind of tracking id – never a BSI WID-SEC or
# another vendor's id under the same record
TRACKING = {"siemens": re.compile(r"^SSA-\d{6}$", re.I), "cisco": re.compile(r"^cisco-sa-[A-Za-z0-9_-]{4,80}$", re.I)}
FUTURE = timedelta(days=1)  # a listed time further ahead is a typo or a trap: such an entry is left out (M1)
FRESH_FILL = timedelta(days=7)  # the first fill: documents older than this are "initial" (shown, never notified)
RETRY_MAX = 5  # a document failing for a passing reason: tried again in later rounds, at most this often …
RETRY_FOR = timedelta(hours=24)  # … and this long – then skipped, the provider is never stalled by one document (M2)
RETRY_KEEP = 100  # documents waiting for another try, at most
STOP_AFTER = 3  # passing failures in a row: the round stops (the provider is down) – the rest next time
HASH_AGAIN = timedelta(days=7)  # a provider without hash files is asked for them again after this


def providers() -> list[dict]:
    return list(catalog.CSAF_PROVIDERS)


def providers_for(product: dict) -> list[dict]:
    """The providers that speak for the product's vendor (catalogue vendor, case-insensitive)."""
    v = str(product.get("vendor") or "").strip().lower()
    return [p for p in catalog.CSAF_PROVIDERS if v and v in {x.lower() for x in p["vendors"]}] if v else []


def needed(products: list[dict]) -> list[dict]:
    keys = {x["key"] for p in products for x in providers_for(p)}
    return [p for p in catalog.CSAF_PROVIDERS if p["key"] in keys]


def allowed(provider: dict, url: str) -> bool:
    """https on the provider's own hosts (`hosts`, else the domain's last two labels and below)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host or parts.username or parts.password:
        return False
    bases = provider.get("hosts") or [".".join(provider["domain"].split(".")[-2:])]
    return any(host == b or host.endswith("." + b) for b in bases)


# ---------------------------------------------------------------- parsers (pure)


@src._shaped
def parse_aggregator(data: bytes) -> dict[str, str]:
    """The aggregator's list: host of each provider-metadata.json → its address (providers and publishers)."""
    doc = src._json(data)
    if not isinstance(doc, dict) or not isinstance(doc.get("csaf_providers"), list):
        raise NewsError("format", "no CSAF aggregator")
    out: dict[str, str] = {}
    for x in [*src._l(doc.get("csaf_providers")), *src._l(doc.get("csaf_publishers"))]:
        u = src._s(src._d(src._d(x).get("metadata")).get("url"), 400)
        host = (urlsplit(u).hostname or "").lower()
        if u.startswith("https://") and host:
            out.setdefault(host, u)
    return out


@src._shaped
def parse_metadata(data: bytes, provider: dict) -> dict:
    """provider-metadata.json: the ROLIE feeds labelled TLP:WHITE/CLEAR and the directories – each on the provider's
    hosts. {feeds: [{url, tlp}], directories: [url], publisher}"""
    doc = src._json(data)
    if not isinstance(doc, dict) or not isinstance(doc.get("distributions"), list):
        raise NewsError("format", "no CSAF provider-metadata")
    feeds, dirs = [], []
    for d in doc["distributions"]:
        d = src._d(d)
        for f in src._l(src._d(d.get("rolie")).get("feeds")):
            f = src._d(f)
            u, tlp = src._s(f.get("url"), 400), src._s(f.get("tlp_label"), 20).upper()
            if tlp in OPEN_TLP and allowed(provider, u):
                feeds.append({"url": u, "tlp": tlp})
        u = src._s(d.get("directory_url"), 400)
        if u and allowed(provider, u):
            dirs.append(u if u.endswith("/") else u + "/")
    pub = src._d(doc.get("publisher"))
    return {"feeds": feeds[:6], "directories": dirs[:6], "publisher": src._s(pub.get("name"), 120), "role": src._s(doc.get("role"), 40)}


def _ts(text: str) -> str | None:
    d = _date(text or "")
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


@src._shaped
def parse_rolie(data: bytes, provider: dict, tlp: str) -> list[dict]:
    """A ROLIE feed: per entry the document's address, its time (updated) and its hash file."""
    doc = src._json(data)
    entries = src._l(src._d(src._d(doc).get("feed")).get("entry")) if isinstance(doc, dict) else None
    if entries is None or not isinstance(src._d(doc).get("feed"), dict):
        raise NewsError("format", "no ROLIE feed")
    out = []
    for e in entries:
        e = src._d(e)
        links = [src._d(x) for x in src._l(e.get("link"))]
        self_ = next((src._s(x.get("href"), 400) for x in links if x.get("rel") == "self"), "") or src._s(src._d(e.get("content")).get("src"), 400)
        hashes = [src._s(x.get("href"), 400) for x in links if x.get("rel") == "hash"]
        ts = _ts(src._s(e.get("updated"), 40) or src._s(e.get("published"), 40))
        if not ts or not allowed(provider, self_):
            continue
        h = next((x for x in hashes if x.endswith(".sha512")), None) or next((x for x in hashes if x.endswith(".sha256")), None)
        out.append({"url": self_, "ts": ts, "hash": h if h and allowed(provider, h) else None, "tlp": tlp})
    return out


def parse_changes(data: bytes, base: str, provider: dict) -> list[dict]:
    """changes.csv of a directory distribution: "<path relative to the directory>,<time>" per line (quoted or not). A
    line the csv module cannot read (a field beyond its limit, a stray quote) is left out – never the whole list."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    out = []
    for line in text.splitlines():  # also splits at a lone CR – a line of its own, not a csv.Error
        if not line.strip() or len(line) > 2000:
            continue
        try:
            row = next(csv.reader([line]), [])
        except csv.Error:
            continue
        if len(row) < 2:
            continue
        path, ts = row[0].strip(), _ts(row[1].strip())
        if not ts or not path.endswith(".json") or path.startswith(("/", "\\")) or ".." in path.split("/") or "://" in path:
            continue
        u = urljoin(base, path)
        if allowed(provider, u) and u.startswith(base):
            out.append({"url": u, "ts": ts, "hash": None, "tlp": ""})
    return out


def check_hash(body: bytes, text: bytes) -> bool | None:
    """The document against its hash file ("<hex>  <name>"): True / False; None when the file holds no hash."""
    first = (text.decode("ascii", "replace").split() or [""])[0]
    if not HEX.match(first):
        return None
    algo = hashlib.sha512 if len(first) == 128 else hashlib.sha256
    return algo(body).hexdigest().lower() == first.lower()


def tlp_ok(doc_label: str, dist_label: str) -> bool:
    """Only TLP:WHITE/CLEAR: a labelled document must be, an unlabelled one only from an unlabelled or open distribution."""
    if doc_label:
        return doc_label.upper() in OPEN_TLP
    return not dist_label or dist_label.upper() in OPEN_TLP


def own_host(provider: dict, url: str) -> bool:
    """A host of the provider (as `allowed`, whatever the scheme) – the publisher namespace of its documents."""
    host = (urlsplit(url).hostname or "").lower()
    bases = provider.get("hosts") or [".".join(provider["domain"].split(".")[-2:])]
    return bool(host) and any(host == b or host.endswith("." + b) for b in bases)


def advisory(body: bytes, provider: dict, entry: dict) -> dict | None:
    """One document as an advisory (or None: nothing affected). Raises NewsError: "format" when unreadable, "blocked"
    when not public (TLP) or not the provider's own (its publisher namespace is another domain, a tracking id of a kind
    the provider does not issue). The record: `csaf:<tracking id>` for the providers whose advisories also come with
    stories (Siemens, Cisco – one record however it came), `csaf:<provider>:<tracking id>` for the others – a provider
    never writes another's record (security review 0.1.26 H2; vendor.store also refuses another publisher)."""
    d = details.parse_csaf(body, KIND.get(provider["key"], "csaf"), details.STORE_PRODUCTS)
    if not tlp_ok(d.get("tlp") or "", entry.get("tlp") or ""):
        raise NewsError("blocked", f"TLP:{d.get('tlp')}")
    if not own_host(provider, d.get("namespace") or ""):
        raise NewsError("blocked", f"publisher namespace {str(d.get('namespace'))[:80]!r} is not the provider's")
    pattern = TRACKING.get(provider["key"])
    if pattern is not None and d.get("id") and not pattern.match(d["id"]):
        raise NewsError("blocked", f"tracking id {d['id'][:60]!r} not one of {provider['key']}")
    if KIND.get(provider["key"]) is None:
        d["publisher"] = d["publisher"] or provider["name"]
        if d.get("id"):
            d["id"] = f"{provider['key']}:{d['id']}"
    page = d.get("page") or ""
    # the advisory's own page only on the provider's hosts – else the document itself (security review L7)
    adv = details.csaf_advisory(d, page if page and allowed(provider, page) else entry["url"])
    if adv is not None:
        adv["ident"] = adv["ident"].removeprefix(f"{provider['key']}:")
        adv["data"]["provider"] = provider["key"]
        adv["data"]["feed"] = True  # from the provider's own feed (switched with "csaf" – vendor.switched_off)
    return adv


# ---------------------------------------------------------------- fetching


def _cursor(st) -> dict:  # noqa: ANN001
    try:
        c = json.loads(st.cursor or "{}")
    except ValueError:
        c = {}
    return c if isinstance(c, dict) else {}


async def sync_aggregator(db: AsyncSession, force: bool) -> dict[str, str]:
    """The BSI aggregator's provider list (daily, conditional) – host → provider-metadata address."""
    from app import vendor

    st = await vendor._state(db, AGGREGATOR_KEY)
    known = _cursor(st).get("hosts") or {}
    if not vendor._due(st, datetime.now(UTC), force):
        return known
    meter = source_health.start()
    try:
        body = await vendor.get(AGGREGATOR, db=db, st=st, limit=META_LIMIT)
        if body is not None:
            known = await asyncio.to_thread(parse_aggregator, body)
            st.cursor = json.dumps({"hosts": known})
        vendor._ok(st, AGG_EVERY, len(known))
        vendor._record(db, st, meter)
    except Exception as exc:  # noqa: BLE001 - the well-known addresses still work
        await db.rollback()
        st = await vendor._state(db, AGGREGATOR_KEY)
        vendor._record(db, st, meter, exc=vendor._fail(st, exc, AGG_EVERY))
    await db.commit()
    return known


async def _metadata_url(provider: dict, hosts: dict[str, str]) -> str:
    if provider.get("metadata"):
        return provider["metadata"]
    return hosts.get(provider["domain"]) or f"https://{provider['domain']}/.well-known/csaf/provider-metadata.json"


def _only(provider: dict):  # noqa: ANN202
    """The check every request of a provider passes – redirects included (security review L6)."""
    return lambda u: allowed(provider, u)


async def _listing(db: AsyncSession, provider: dict, meta: dict, st) -> list[dict] | None:  # noqa: ANN001
    """Every document the distributions list (None: unchanged since the last complete round – 304)."""
    from app import vendor

    out: list[dict] = []
    first = True
    sources = [("rolie", f["url"], f["tlp"]) for f in meta["feeds"]] or [("dir", d + "changes.csv", "") for d in meta["directories"]]
    if not sources:
        raise NewsError("format", "no TLP:WHITE/CLEAR distribution")
    for kind, u, tlp in sources:
        # the first list conditional (one validator pair per query): unchanged → nothing to do
        body = await vendor.get(
            u, db=db, st=st if first else None, conditional=first, limit=LIST_LIMIT, headers={"Accept": "application/json, text/csv;q=0.9, */*;q=0.1"}, only=_only(provider)
        )
        if body is None and first and len(sources) == 1:
            return None
        first = False
        if body is None:
            continue
        if kind == "rolie":
            out += await asyncio.to_thread(parse_rolie, body, provider, tlp)
        else:
            out += await asyncio.to_thread(parse_changes, body, u.removesuffix("changes.csv"), provider)
    return out


class _Again(NewsError):
    """A document not taken this round for a passing reason – tried again later (retry list)."""


def _passing(exc: NewsError) -> bool:
    return isinstance(exc, _Again) or exc.category in ("rate_limited", "timeout", "connection") or (exc.category == "http" and bool(re.search(r"HTTP 5\d\d", exc.detail or "")))


async def _document(db: AsyncSession, provider: dict, entry: dict, cur: dict) -> tuple[bytes, bool | None]:
    """The document and whether its hash matched (None: the provider offers no hash files). A hash the feed lists must
    be there: a listed one that cannot be fetched means the document is not taken this round (_Again) – as one missing
    at a provider known to offer them. Guessed hash files (.sha512/.sha256 next to the document) that do not exist mark
    the provider as one without – asked again after HASH_AGAIN (security review L5)."""
    from app import vendor

    only = _only(provider)
    body = await vendor.get(entry["url"], db=db, conditional=False, limit=DOC_LIMIT, only=only)
    if not body:
        raise NewsError("format", "empty document")
    if entry.get("hash"):
        try:
            text = await vendor.get(entry["hash"], db=db, conditional=False, limit=HASH_LIMIT, only=only)
        except NewsError as exc:
            if _passing(exc):
                raise
            raise _Again("http", f"listed hash file not available ({exc.detail or exc.category})") from exc
        ok = check_hash(body, text or b"")
        if ok is None:
            raise NewsError("format", "listed hash file holds no hash")
        return body, ok
    now = datetime.now(UTC)
    known = cur.get("hash") in (".sha512", ".sha256")
    if cur.get("hash") == "none":
        at = _date(cur.get("hash_at") or "")
        if at is not None and now - at < HASH_AGAIN:
            return body, None
    order = [".sha256", ".sha512"] if cur.get("hash") == ".sha256" else [".sha512", ".sha256"]
    for ext in order:
        try:
            text = await vendor.get(entry["url"] + ext, db=db, conditional=False, limit=HASH_LIMIT, only=only)
        except NewsError as exc:
            if exc.category in ("http", "blocked") and re.search(r"HTTP 40[34]", exc.detail or ""):
                continue
            raise
        ok = check_hash(body, text or b"")
        if ok is not None:
            cur["hash"] = ext
            cur.pop("hash_at", None)
            return body, ok
    if known:
        raise _Again("http", "hash file missing (the provider offers them)")
    cur["hash"] = "none"  # the provider has no hash files: asked again after HASH_AGAIN, not for each document
    cur["hash_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return body, None


def _retry_list(cur: dict) -> dict[str, dict]:
    r = cur.get("retry")
    return {k: v for k, v in r.items() if isinstance(v, dict) and isinstance(k, str)} if isinstance(r, dict) else {}


async def sync_provider(db: AsyncSession, provider: dict, hosts: dict[str, str], every: timedelta, ix, force: bool) -> int | None:  # noqa: ANN001
    """One provider: its metadata, its list of documents, the documents changed after the watermark (oldest first) and
    those waiting for another try. A document failing for a passing reason (5xx, timeout, a listed hash not there) goes
    on the retry list and the watermark moves on – it is tried again in the next rounds, skipped after RETRY_MAX tries or
    RETRY_FOR; STOP_AFTER such failures in a row end the round (the provider is down: the rest after the backoff)."""
    from app import vendor

    key = f"csaf:{provider['key']}"
    st = await vendor._state(db, key)
    now = datetime.now(UTC)
    if not vendor._due(st, now, force):
        return None
    cur = _cursor(st)
    first_fill = not cur.get("w") or cur.get("initial", False)
    w = cur.get("w") or f"{(now - INITIAL).strftime('%Y-%m-%dT%H:%M:%SZ')}|"
    retry = _retry_list(cur)
    changed = bad = taken = 0
    failed: NewsError | None = None
    complete = True
    meter = source_health.start()
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    horizon = (now + FUTURE).strftime("%Y-%m-%dT%H:%M:%SZ")

    async def one(e: dict) -> NewsError | None:
        """One document: stored, skipped for good (bad) or – returned – a passing failure."""
        nonlocal changed, bad, taken
        try:
            body, ok = await _document(db, provider, e, cur)
            if ok is False:
                raise NewsError("format", "hash mismatch")
            adv = await asyncio.to_thread(advisory, body, provider, e)
            if adv is not None:
                # the first fill: what is older than FRESH_FILL is shown, never notified; a fresh one is (M7)
                if first_fill and e["ts"] < (now - FRESH_FILL).strftime("%Y-%m-%dT%H:%M:%SZ"):
                    adv["data"]["initial"] = True
                skipped: list[str] = []
                changed += await vendor.store(db, [adv], ix, skipped)
                if skipped:
                    bad += 1
            taken += 1
        except NewsError as exc:
            if _passing(exc):
                return exc
            bad += 1  # gone, unreadable, wrong hash, not public or not the provider's own: skipped for good
            log.info("csaf %s %s: %s", provider["key"], e["url"][-80:], f"{exc.category}: {exc.detail}")
        return None

    def again(e: dict, exc: NewsError) -> None:
        nonlocal bad
        r = retry.get(e["url"]) or {"ts": e["ts"], "hash": e.get("hash"), "tlp": e.get("tlp") or "", "n": 0, "since": stamp}
        r["n"] = int(r.get("n") or 0) + 1
        since = _date(str(r.get("since") or "")) or now
        if r["n"] >= RETRY_MAX or now - since >= RETRY_FOR:
            retry.pop(e["url"], None)
            bad += 1
            log.info("csaf %s %s: given up after %s tries: %s", provider["key"], e["url"][-80:], r["n"], f"{exc.category}: {exc.detail}")
        else:
            retry[e["url"]] = r

    try:
        meta_url = await _metadata_url(provider, hosts)
        if not allowed(provider, meta_url):
            raise NewsError("blocked", "metadata outside the provider's domain")
        meta = await asyncio.to_thread(parse_metadata, await vendor.get(meta_url, db=db, conditional=False, limit=META_LIMIT, only=_only(provider)) or b"{}", provider)
        listed = await _listing(db, provider, meta, st)
        budget = DOCS_PER_ROUND
        in_row = 0
        # first the documents waiting for another try (oldest first)
        for u, r in sorted(retry.items(), key=lambda x: (str(x[1].get("ts")), x[0])):
            if budget <= 0 or in_row >= STOP_AFTER:
                complete = False
                break
            if not allowed(provider, u):
                retry.pop(u, None)
                continue
            budget -= 1
            e = {"url": u, "ts": str(r.get("ts") or stamp), "hash": r.get("hash"), "tlp": r.get("tlp") or ""}
            if (exc := await one(e)) is not None:
                again(e, exc)
                failed, in_row = exc, in_row + 1
            else:
                retry.pop(u, None)
                in_row = 0
        if listed is not None:
            # a time in the future (beyond FUTURE) would move the watermark past every later document: left out
            todo = sorted(
                {e["url"]: e for e in listed if f"{e['ts']}|{e['url']}" > w and e["ts"] <= horizon and e["url"] not in retry}.values(), key=lambda e: (e["ts"], e["url"])
            )
            for e in todo:
                if budget <= 0 or in_row >= STOP_AFTER:
                    complete = False
                    break
                budget -= 1
                if (exc := await one(e)) is not None:
                    again(e, exc)
                    failed, in_row = exc, in_row + 1
                else:
                    in_row = 0
                w = f"{e['ts']}|{e['url']}"
        if len(retry) > RETRY_KEEP:
            for u in sorted(retry, key=lambda x: (str(retry[x].get("ts")), x))[: len(retry) - RETRY_KEEP]:
                retry.pop(u)
                bad += 1
        st = await vendor._state(db, key)
        if listed is not None or retry != _retry_list(cur):
            st.cursor = json.dumps({**cur, "w": w, "initial": first_fill and not complete, "retry": retry})
        if failed is not None and taken == 0:
            # every document asked failed for a passing reason: the provider's error (backoff), what was read stays read
            vendor._record(db, st, meter, exc=vendor._fail(st, failed, every))
        else:
            # a backlog: again soon; documents waiting for another try: within the hour (RETRY_FOR is a day)
            vendor._ok(st, BACKLOG_AGAIN if not complete else min(every, timedelta(hours=1)) if retry else every, changed, complete=complete)
            if not complete:
                st.next_fetch_at = datetime.now(UTC) + BACKLOG_AGAIN
            vendor._record(db, st, meter, items=changed, parse_errors=bad)
    except Exception as exc:  # noqa: BLE001 - this provider pauses, the others go on
        await db.rollback()
        st = await vendor._state(db, key)
        if w != (cur.get("w") or "") or retry != _retry_list(cur):
            st.cursor = json.dumps({**cur, "w": w, "initial": first_fill, "retry": retry})  # what was read stays read
        vendor._record(db, st, meter, exc=vendor._fail(st, exc, every))
    await db.commit()
    return changed


async def sync_all(db: AsyncSession, products: list[dict], every: timedelta, ix, force: bool) -> dict[str, int]:  # noqa: ANN001
    """The providers of the followed products' vendors – the aggregator first (daily)."""
    want = needed(products)
    if not want:
        return {}
    hosts = await sync_aggregator(db, force)
    out: dict[str, int] = {}
    for p in want:
        if (r := await sync_provider(db, p, hosts, every, ix, force)) is not None:
            out[f"csaf:{p['key']}"] = r
    return out
