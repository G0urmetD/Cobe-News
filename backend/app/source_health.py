"""Quellen-Gesundheit: how well every source is fetched – the news feeds (news_sources), the queries of Vendor News
(vendor_fetch, grouped by family: nvd, paloalto, fortinet, veeam, kev, eol) and the structured sources (kind
"structured", also in vendor_fetch: csaf – one query per CSAF provider and the BSI aggregator –, cvelist, epss, osv,
exploit – one query per exploit list, app/exploits.py).

Recording (the hot path, kept cheap): a fetcher calls `start()` before its requests and `record(db, kind, key, …)` when
the fetch is decided – one row in source_fetch_stats, written with the commit the fetcher makes anyway. The requests
themselves are measured in news.download() (every fetcher downloads through it): count, time, bytes, the last HTTP
status – into the Meter of the running task (a context variable, so the news round, the Vendor News round and a
request handler never mix). A fetch that never asked the network (paused, not due) records nothing. Any later fetcher
(CSAF feeds, cvelistV5, EPSS, OSV) only needs these two calls and a kind of its own.

Errors are kept in a few categories (CATEGORIES), normalised from the fetchers' own (news.NewsError) and the HTTP status.

States (classify(), thresholds below; precedence top down):
- off – switched off (the news as a whole, the source, Vendor News, or no followed product needs the query);
- never – switched on, not fetched yet;
- dead (tot) – refused for good (HTTP 401/403/410 at least BLOCKED_FAILURES times in a row, 404 NOT_FOUND_FAILURES
  times), no success for DEAD_NO_SUCCESS while failing, or (news only) no new story for STALE although fetched fine
  for that long – judged only once the stories and the stats cover the whole time;
- disturbed (gestört) – DISTURBED_FAILURES failures in a row, a current failure that is no passing one (anything but
  a timeout, a lost connection, HTTP 5xx or "too many requests" – the source pauses until its next try), or an
  unreadable answer within PARSE_WINDOW;
- slow (langsam) – answers take more than SLOW_MS on average (last WINDOW, at least SLOW_MIN_REQUESTS requests; big
  downloads of more than BIG_BYTES a request – a first full NVD fetch, a whole list – are left out, they take long by
  nature), many
  timeouts (TIMEOUTS_MIN and TIMEOUT_SHARE of the fetches), or a passing failure being retried;
- healthy (gesund) – everything else.
A Vendor News family takes the worst state of its queries (the drawer lists them one by one).

Notifications (rule kind source_health): evaluate() writes a source_health_events row whenever a state changes; one
into disturbed or dead (or worse within them) and one back from there is sent once per channel (notify.py). The first
state of a source is its baseline – nothing is sent; the newest event per source stays past the retention, so a restart
never sends a change again.

Retention: KEEP (60 days) for the stats and for older events, pruned hourly in batches."""

import contextvars
import logging
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import func, or_, select, text
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import load_only

from app.db import utcnow
from app.models import NewsSource, SourceFetchStat, SourceHealthEvent, VendorFetch

log = logging.getLogger("cobe_news.health")

NEWS, VENDOR, STRUCTURED = "news", "vendor", "structured"
KINDS = (NEWS, VENDOR, STRUCTURED)
KEEP = timedelta(days=60)
PRUNE_BATCH = 5000
EVALUATE_EVERY_S = 300.0  # the background loop compares the states at most this often

CATEGORIES = ("timeout", "connection", "tls", "http_4xx", "http_5xx", "rate_limited", "blocked", "parse", "too_large", "other")
# a failure that says little about the source itself (the way there, the site busy for a moment): retried soon
PASSING = frozenset({"timeout", "connection", "http_5xx", "rate_limited"})

STATES = ("healthy", "slow", "disturbed", "dead", "off", "never")
RANK = {"off": 0, "never": 1, "healthy": 2, "slow": 3, "disturbed": 4, "dead": 5}
BAD = frozenset({"disturbed", "dead"})

DEAD_NO_SUCCESS = timedelta(days=14)
STALE = timedelta(days=60)
BLOCKED_FAILURES = 2  # 401/403/410 – one refusal can be a hiccup of a bot protection, two in a row are a decision
NOT_FOUND_FAILURES = 3
DISTURBED_FAILURES = 3
PARSE_WINDOW = timedelta(hours=24)
WINDOW = timedelta(days=7)  # averages, timeouts, parse errors
WEEKS = 4
SLOW_MS = 5000
SLOW_MIN_REQUESTS = 3
BIG_BYTES = 1_000_000  # per request on average: a fetch this big does not count for "slow"
TIMEOUTS_MIN = 3
TIMEOUT_SHARE = 0.25

# Vendor News: the families of vendor_fetch keys (<family>:<query>); nvdkw (NVD's keyword search) belongs to NVD – same
# host, same limits. nvdcve:<CVE> are single lookups of the story details, no source.
FAMILY_OF = {"nvdkw": "nvd"}
FAMILY_NAMES = {
    "nvd": "NVD",
    "paloalto": "Palo Alto Networks",
    "fortinet": "Fortinet PSIRT",
    "veeam": "Veeam KB",
    "kev": "CISA KEV",
    "eol": "endoflife.date",
    "csaf": "CSAF-Anbieter",
    "cvelist": "cvelistV5 (CVE-Liste)",
    "epss": "FIRST EPSS",
    "osv": "OSV.dev",
    "exploit": "Exploit-Hinweise",
}
STRUCTURED_FAMILIES = frozenset({"csaf", "cvelist", "epss", "osv", "exploit"})  # their own kind on the health page
NOT_SOURCES = ("nvdcve:", "cvelistcve:", "osvcve:")  # single lookups of one CVE each – no source


def family(key: str) -> str:
    head = key.split(":", 1)[0]
    return FAMILY_OF.get(head, head)


def kind_of(key: str) -> str:
    """The kind a vendor_fetch query is recorded and shown under: structured for the structured sources."""
    return STRUCTURED if family(key) in STRUCTURED_FAMILIES else VENDOR


def family_prefixes(fam: str) -> list[str]:
    return [fam, *(k for k, v in FAMILY_OF.items() if v == fam)]


# ---------------------------------------------------------------- recording


@dataclass
class Meter:
    """The requests of one fetch (news.download() adds each): how many, how long together, how many bytes, the last status."""

    requests: int = 0
    duration_ms: int = 0
    bytes: int = 0
    status: int | None = None


_meter: contextvars.ContextVar[Meter | None] = contextvars.ContextVar("source_health_meter", default=None)


def start() -> Meter:
    """Before a fetch's first request: what news.download() measures in this task from now on goes into this meter."""
    m = Meter()
    _meter.set(m)
    return m


def measure(seconds: float, status: int | None, size: int) -> None:
    """One request done (news.download()): status None – no answer came (timeout, DNS, TLS …)."""
    m = _meter.get()
    if m is None:
        return
    m.requests += 1
    m.duration_ms += max(0, int(seconds * 1000))
    m.bytes += max(0, size)
    m.status = status


def _tls(exc: BaseException | None) -> bool:
    for _ in range(6):
        if exc is None:
            return False
        if isinstance(exc, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(exc) or "[SSL" in str(exc):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def _by_status(status: int | None) -> str | None:
    if status is None:
        return None
    if status == 403:
        return "blocked"
    if status == 429:
        return "rate_limited"
    if 400 <= status < 500:
        return "http_4xx"
    if status >= 500:
        return "http_5xx"
    return None


def status_of(detail: str) -> int | None:
    m = re.search(r"HTTP (\d{3})", detail or "")
    return int(m.group(1)) if m else None


def category(exc: object, status: int | None = None) -> str:
    """A fetcher's error (news.NewsError: category + detail, or anything else) in one of CATEGORIES."""
    cat = str(getattr(exc, "category", "") or "")
    status = status or status_of(str(getattr(exc, "detail", "") or ""))
    if cat == "connection":
        return "tls" if isinstance(exc, BaseException) and _tls(exc) else "connection"
    if cat in ("timeout", "rate_limited", "too_large"):
        return cat
    if cat in ("parse", "format", "empty"):
        return "parse"
    if cat in ("blocked", "http"):
        return _by_status(status) or ("blocked" if cat == "blocked" else "other")
    return "other"


def category_of_text(error: str | None) -> tuple[str | None, int | None]:
    """The error a source row keeps ("blocked: HTTP 403", "timeout") as (category, HTTP status)."""
    if not error:
        return None, None
    cat, _, detail = error.partition(":")
    status = status_of(detail)
    return category(SimpleNamespace(category=cat.strip(), detail=detail.strip()), status), status


def record(
    db: AsyncSession,
    kind: str,
    key: str,
    *,
    ok: bool,
    meter: Meter | None = None,
    exc: object = None,
    items: int = 0,
    parse_errors: int = 0,
    at: datetime | None = None,
) -> SourceFetchStat | None:
    """One fetch decided: its row is added to the session (written with the fetcher's next commit – no query of its own).
    Nothing when no request was made (a pause, a host still blocked)."""
    m = meter or _meter.get() or Meter()
    _meter.set(None)
    if m.requests == 0:
        return None
    err = None if ok else category(exc, m.status)
    if err == "parse" and not parse_errors:
        parse_errors = 1  # the whole answer unreadable
    row = SourceFetchStat(
        kind=kind,
        key=key[:300],
        at=at or utcnow(),
        ok=ok,
        status=m.status,
        error=err,
        duration_ms=min(m.duration_ms, 2**31 - 1),
        requests=m.requests,
        bytes=m.bytes,
        items=max(0, int(items or 0)),
        not_modified=ok and m.status == 304,
        parse_errors=max(0, int(parse_errors or 0)),
    )
    db.add(row)
    return row


# ---------------------------------------------------------------- classification


@dataclass
class Facts:
    """What the state of one source is decided on (the source's row and its stats)."""

    active: bool = True
    last_fetch_at: datetime | None = None
    last_ok_at: datetime | None = None
    since: datetime | None = None  # meant to be fetched since (switched on, added, first fetch seen)
    failures: int = 0
    error: str | None = None  # category of the current failure (None: the last fetch went fine)
    status: int | None = None
    stale_check: bool = False  # news: "no new story for STALE" applies
    last_item_at: datetime | None = None
    items_known_since: datetime | None = None  # from then on a missing story would be seen (retention of stories and stats)
    avg_ms: int | None = None
    measured: int = 0  # requests behind avg_ms
    fetches: int = 0  # in WINDOW
    timeouts: int = 0  # in WINDOW
    parse_fails: int = 0  # in PARSE_WINDOW


def classify(f: Facts, now: datetime) -> tuple[str, list[str]]:
    """(state, reasons) – see the module doc. Reasons: blocked, not_found, no_success, stale | failing, error, parse |
    slow, timeouts, retrying."""
    if not f.active:
        return "off", []
    if f.last_fetch_at is None and f.last_ok_at is None and f.fetches == 0:
        return "never", []
    failing = f.failures > 0 and f.error is not None
    dead: list[str] = []
    if failing and (f.error == "blocked" or f.status in (401, 403, 410)) and f.failures >= BLOCKED_FAILURES:
        dead.append("blocked")
    elif failing and f.status == 404 and f.failures >= NOT_FOUND_FAILURES:
        dead.append("not_found")
    ref = max((x for x in (f.last_ok_at, f.since) if x is not None), default=None)
    if f.failures > 0 and ref is not None and now - ref >= DEAD_NO_SUCCESS:
        dead.append("no_success")
    if (
        f.stale_check
        and f.last_ok_at is not None
        and f.since is not None
        and now - f.since >= STALE
        and f.items_known_since is not None
        and now - f.items_known_since >= STALE
        and (f.last_item_at is None or now - f.last_item_at >= STALE)
    ):
        dead.append("stale")
    if dead:
        return "dead", dead
    disturbed: list[str] = []
    if f.failures >= DISTURBED_FAILURES:
        disturbed.append("failing")
    elif failing and f.error not in PASSING:
        disturbed.append("error")
    if f.parse_fails > 0 and "error" not in disturbed:
        disturbed.append("parse")
    if disturbed:
        return "disturbed", disturbed
    slow: list[str] = []
    if f.avg_ms is not None and f.measured >= SLOW_MIN_REQUESTS and f.avg_ms > SLOW_MS:
        slow.append("slow")
    if f.timeouts >= TIMEOUTS_MIN and f.timeouts >= TIMEOUT_SHARE * max(1, f.fetches):
        slow.append("timeouts")
    if failing:
        slow.append("retrying")  # a passing failure (1–2 in a row): tried again soon
    if slow:
        return "slow", slow
    return "healthy", []


def worst(states: list[str]) -> str:
    """A family's state: its worst switched-on query (off only when all are)."""
    return max(states, key=lambda s: RANK[s], default="off")


def worth_sending(prev: str | None, new: str) -> bool:
    """A change worth a message: into disturbed or dead (or from disturbed to dead), or back from there. Not the
    baseline (prev None), not being switched off."""
    if prev is None or prev == new:
        return False
    if new in BAD:
        return prev not in BAD or RANK[new] > RANK[prev]
    return prev in BAD and new in ("healthy", "slow")


# ---------------------------------------------------------------- aggregation (one query for all stats)

_STATS_SQL = text(
    """
SELECT kind, key,
  min(at) AS first_at,
  count(*) FILTER (WHERE at >= :w1) AS fetches,
  coalesce(sum(duration_ms) FILTER (WHERE at >= :w1 AND ok), 0) AS ms,
  coalesce(sum(requests) FILTER (WHERE at >= :w1 AND ok), 0) AS requests,
  coalesce(sum(duration_ms) FILTER (WHERE at >= :w1 AND ok AND bytes <= :big * greatest(requests, 1)), 0) AS ms_paced,
  coalesce(sum(requests) FILTER (WHERE at >= :w1 AND ok AND bytes <= :big * greatest(requests, 1)), 0) AS requests_paced,
  coalesce(sum(bytes) FILTER (WHERE at >= :w1 AND ok AND NOT not_modified), 0) AS bytes,
  count(*) FILTER (WHERE at >= :w1 AND ok AND NOT not_modified) AS bodies,
  count(*) FILTER (WHERE at >= :w1 AND not_modified) AS not_modified,
  count(*) FILTER (WHERE not_modified) AS not_modified_all,
  count(*) FILTER (WHERE at >= :w1 AND error = 'timeout') AS timeouts,
  coalesce(sum(parse_errors) FILTER (WHERE at >= :w1), 0) AS parse_errors,
  count(*) FILTER (WHERE at >= :p AND error = 'parse') AS parse_fails,
  max(at) FILTER (WHERE items > 0) AS last_item_at,
  max(at) FILTER (WHERE NOT ok) AS last_error_at,
  (array_agg(error ORDER BY at DESC) FILTER (WHERE NOT ok))[1] AS last_error,
  (array_agg(status ORDER BY at DESC) FILTER (WHERE NOT ok))[1] AS last_error_status,
  (array_agg(ok ORDER BY at DESC))[1] AS last_ok,
  coalesce(sum(items) FILTER (WHERE at >= :w4 AND at < :w3), 0) AS i0, count(*) FILTER (WHERE at >= :w4 AND at < :w3) AS f0,
  coalesce(sum(items) FILTER (WHERE at >= :w3 AND at < :w2), 0) AS i1, count(*) FILTER (WHERE at >= :w3 AND at < :w2) AS f1,
  coalesce(sum(items) FILTER (WHERE at >= :w2 AND at < :w1), 0) AS i2, count(*) FILTER (WHERE at >= :w2 AND at < :w1) AS f2,
  coalesce(sum(items) FILTER (WHERE at >= :w1), 0) AS i3, count(*) FILTER (WHERE at >= :w1) AS f3
FROM source_fetch_stats
WHERE at >= :keep
GROUP BY kind, key
"""
)

# the newest story per source – its own and the ones it carries as a further source ("also in")
_LAST_ITEM_SQL = text(
    """
SELECT source_id, max(fetched_at) AS at FROM (
  SELECT source_id, fetched_at FROM news_items
  UNION ALL
  SELECT s.source_id, i.fetched_at FROM news_item_sources s JOIN news_items i ON i.id = s.item_id
) x GROUP BY source_id
"""
)


async def _stats(db: AsyncSession, now: datetime) -> dict[tuple[str, str], dict]:
    w = {f"w{i}": now - WINDOW * i for i in range(1, WEEKS + 1)}
    rows = (await db.execute(_STATS_SQL, {**w, "p": now - PARSE_WINDOW, "keep": now - KEEP, "big": BIG_BYTES})).mappings().all()
    return {(r["kind"], r["key"]): dict(r) for r in rows}


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


@dataclass
class Row:
    """One line of the health table (a news source, or a Vendor News family with its queries as members)."""

    kind: str
    key: str
    name: str
    group: str
    host: str
    facts: Facts
    stats: dict
    enabled: bool
    next_fetch_at: datetime | None
    conditional: bool
    state: str = "never"
    reasons: list[str] = field(default_factory=list)
    members: list["Row"] = field(default_factory=list)
    url: str = ""


def _weeks(st: dict | None) -> list[int | None]:
    """Items per week, oldest first; None: no fetch that week (nothing known)."""
    if not st:
        return [None] * WEEKS
    return [int(st[f"i{i}"]) if st[f"f{i}"] else None for i in range(WEEKS)]


def _error_out(cat: str | None, status: int | None, at: datetime | None) -> dict | None:
    return {"category": cat, "status": status, "at": _iso(at)} if cat else None


def _facts(*, active: bool, last_fetch_at, last_ok_at, since, failures: int, error_text: str | None, st: dict | None) -> Facts:  # noqa: ANN001
    cat, status = category_of_text(error_text)
    if st and failures and st.get("last_ok") is False and st.get("last_error"):
        cat, status = st["last_error"], st["last_error_status"]  # the stats know it better (tls, the exact status)
    f = Facts(active=active, last_fetch_at=last_fetch_at, last_ok_at=last_ok_at, since=since, failures=int(failures or 0), error=cat if failures else None, status=status if failures else None)
    if st:
        f.fetches, f.timeouts, f.parse_fails = int(st["fetches"]), int(st["timeouts"]), int(st["parse_fails"])
        # "slow" is judged without the big downloads (the shown average keeps them: ms / requests)
        f.measured = int(st["requests_paced"])
        f.avg_ms = int(st["ms_paced"]) // f.measured if f.measured else None
    return f


async def _news_rows(db: AsyncSession, now: datetime, stats: dict) -> list[Row]:
    from app import news as news_svc

    cfg = await news_svc.config(db)
    on = bool(cfg.get("enabled"))
    keep_days = max(7, int(cfg.get("keep_days") or 90))
    cols = (
        NewsSource.id,
        NewsSource.key,
        NewsSource.name,
        NewsSource.url,
        NewsSource.builtin,
        NewsSource.enabled,
        NewsSource.switched_at,
        NewsSource.created_at,
        NewsSource.etag,
        NewsSource.last_modified,
        NewsSource.last_fetch_at,
        NewsSource.last_ok_at,
        NewsSource.next_fetch_at,
        NewsSource.failures,
        NewsSource.error,
    )
    sources = list(await db.scalars(select(NewsSource).options(load_only(*cols)).order_by(NewsSource.name)))
    last_item = {r.source_id: r.at for r in (await db.execute(_LAST_ITEM_SQL)).all()}
    out = []
    for s in sources:
        st = stats.get((NEWS, s.key))
        f = _facts(active=on and s.enabled, last_fetch_at=s.last_fetch_at, last_ok_at=s.last_ok_at, since=s.switched_at or s.created_at, failures=s.failures, error_text=s.error, st=st)
        f.stale_check = True
        stats_item = st["last_item_at"] if st else None
        f.last_item_at = max((x for x in (last_item.get(s.id), stats_item) if x is not None), default=None)
        # a story is kept keep_days (missing ones would show there), the stats since their first row
        f.items_known_since = min(x for x in (now - timedelta(days=keep_days), st["first_at"] if st else None) if x is not None)
        b = news_svc.BUILTIN_BY_KEY.get(s.key)
        host = s.url.split("/")[2] if "://" in s.url else ""
        row = Row(NEWS, s.key, s.name, b.category if b else "custom", host, f, st or {}, on and s.enabled, s.next_fetch_at, bool(s.etag or s.last_modified), url=s.url)
        row.state, row.reasons = classify(f, now)
        out.append(row)
    return out


async def _vendor_rows(db: AsyncSession, now: datetime, stats: dict) -> list[Row]:
    from app import vendor as vendor_svc

    active = await vendor_svc.active_keys(db)
    fetches = list(await db.scalars(select(VendorFetch).where(*(~VendorFetch.key.startswith(p, autoescape=True) for p in NOT_SOURCES))))
    by_family: dict[str, list[Row]] = {}
    for s in fetches:
        st = stats.get((kind_of(s.key), s.key))
        since = st["first_at"] if st else None
        f = _facts(active=s.key in active, last_fetch_at=s.last_fetch_at, last_ok_at=s.last_ok_at, since=since or s.last_fetch_at, failures=s.failures, error_text=s.error, st=st)
        if s.error and s.error.startswith("rate_limited: paused") and not s.failures:
            f.error = None  # not asked at all – another query's 429 paused the host
        fam = family(s.key)
        m = Row(kind_of(s.key), s.key, s.key.split(":", 1)[1] if ":" in s.key else s.key, fam, "", f, st or {}, s.key in active, s.next_fetch_at, bool(s.etag or s.last_modified))
        m.state, m.reasons = classify(f, now)
        by_family.setdefault(fam, []).append(m)
    # a family needed but not fetched yet (a product just followed) still gets its line
    known = {s.key for s in fetches}
    for key in sorted(active - known):
        m = Row(kind_of(key), key, key.split(":", 1)[1] if ":" in key else key, family(key), "", Facts(active=True), {}, True, None, False, state="never")
        by_family.setdefault(family(key), []).append(m)
    out = []
    for fam, members in sorted(by_family.items(), key=lambda x: (FAMILY_NAMES.get(x[0], x[0]).lower())):
        on = [m for m in members if m.enabled]
        state = worst([m.state for m in on]) if on else "off"
        reasons = list(dict.fromkeys(r for m in on if m.state == state for r in m.reasons))
        members.sort(key=lambda m: (-RANK[m.state] if m.enabled else 1, m.key))
        kind = STRUCTURED if fam in STRUCTURED_FAMILIES else VENDOR
        out.append(Row(kind, fam, FAMILY_NAMES.get(fam, fam), fam, "", Facts(active=bool(on)), {}, bool(on), None, any(m.conditional for m in on), state, reasons, members))
    return out


async def latest_events(db: AsyncSession) -> dict[tuple[str, str], SourceHealthEvent]:
    """The newest event per source: its last known state (and since when)."""
    stmt = (
        select(SourceHealthEvent)
        .ext(distinct_on(SourceHealthEvent.kind, SourceHealthEvent.key))
        .order_by(SourceHealthEvent.kind, SourceHealthEvent.key, SourceHealthEvent.n.desc())
    )
    return {(e.kind, e.key): e for e in await db.scalars(stmt)}


async def collect(db: AsyncSession, now: datetime | None = None) -> list[Row]:
    """Every source with its state: a constant number of queries, however many sources and fetches there are."""
    now = now or utcnow()
    stats = await _stats(db, now)
    return [*await _news_rows(db, now, stats), *await _vendor_rows(db, now, stats)]


# ---------------------------------------------------------------- API shapes


def _sum(rows: list[Row], name: str) -> int:
    return sum(int(r.stats.get(name) or 0) for r in rows)


def row_out(r: Row, now: datetime, since: datetime | None = None) -> dict:
    parts = r.members or [r]
    on = [m for m in parts if m.enabled] or parts
    f = r.facts
    req, ms = _sum(on, "requests"), _sum(on, "ms")
    bodies, size = _sum(on, "bodies"), _sum(on, "bytes")
    weeks = [None] * WEEKS
    for m in on:
        for i, n in enumerate(_weeks(m.stats)):
            if n is not None:
                weeks[i] = (weeks[i] or 0) + n
    last_errors = [(m.stats.get("last_error_at"), m.stats.get("last_error"), m.stats.get("last_error_status")) for m in on if m.stats.get("last_error_at")]
    last_error = max(last_errors, key=lambda x: x[0], default=None)
    failing = [m for m in on if m.facts.failures and m.facts.error]
    cur = max(failing, key=lambda m: (RANK[m.state], m.facts.failures), default=None)
    next_try = [m.next_fetch_at for m in failing if m.next_fetch_at and m.next_fetch_at > now]
    return {
        "kind": r.kind,
        "key": r.key,
        "name": r.name,
        "group": r.group,
        "host": r.host,
        "url": r.url,
        "enabled": r.enabled,
        "state": r.state,
        "reasons": r.reasons,
        "since": _iso(since),
        "last_ok_at": _iso(max((m.facts.last_ok_at for m in on if m.facts.last_ok_at), default=None)),
        "last_fetch_at": _iso(max((m.facts.last_fetch_at for m in on if m.facts.last_fetch_at), default=None)),
        "next_fetch_at": _iso(r.next_fetch_at if not r.members else min(next_try, default=None)),
        "paused": bool(next_try) if r.members else bool(f.failures and r.next_fetch_at and r.next_fetch_at > now),
        "failures": max((m.facts.failures for m in on), default=0),
        "error": _error_out(cur.facts.error, cur.facts.status, cur.facts.last_fetch_at) if cur else None,
        "last_error": _error_out(last_error[1], last_error[2], last_error[0]) if last_error else None,
        "weeks": weeks,
        "avg_ms": ms // req if req else None,
        "avg_bytes": size // bodies if bodies else None,
        "fetches_7d": _sum(on, "fetches"),
        "timeouts_7d": _sum(on, "timeouts"),
        "parse_errors_7d": _sum(on, "parse_errors"),
        "not_modified_7d": _sum(on, "not_modified"),
        "conditional": r.conditional or any(int(m.stats.get("not_modified_all") or 0) for m in on),
        "members": {"total": len(r.members), "active": sum(1 for m in r.members if m.enabled), "problems": sum(1 for m in r.members if m.enabled and m.state in BAD)}
        if r.members
        else None,
    }


def counts(rows: list[Row]) -> dict[str, int]:
    out = {s: 0 for s in STATES}
    for r in rows:
        out[r.state] += 1
    return out


async def overview(db: AsyncSession) -> dict:
    now = utcnow()
    rows = await collect(db, now)
    last = await latest_events(db)

    def since(r: Row) -> datetime | None:
        e = last.get((r.kind, r.key))
        return e.created_at if e is not None and e.state == r.state else None

    return {"at": now.isoformat(), "counts": counts(rows), "items": [row_out(r, now, since(r)) for r in rows]}


async def detail(db: AsyncSession, kind: str, key: str) -> dict | None:
    """One line with its history: the recent fetches (of all its queries, for a Vendor News family), the recent errors,
    its state changes and – for a family – its queries one by one."""
    now = utcnow()
    rows = await collect(db, now)
    r = next((x for x in rows if x.kind == kind and x.key == key), None)
    if r is None:
        return None
    if r.members:
        prefixes = family_prefixes(key)
        where = [SourceFetchStat.kind == kind, or_(*(SourceFetchStat.key == p for p in prefixes), *(SourceFetchStat.key.startswith(p + ":", autoescape=True) for p in prefixes))]
    else:
        where = [SourceFetchStat.kind == kind, SourceFetchStat.key == key]

    def fetch_out(x: SourceFetchStat) -> dict:
        return {
            "key": x.key,
            "at": x.at.isoformat(),
            "ok": x.ok,
            "status": x.status,
            "error": x.error,
            "duration_ms": x.duration_ms,
            "requests": x.requests,
            "bytes": x.bytes,
            "items": x.items,
            "not_modified": x.not_modified,
            "parse_errors": x.parse_errors,
        }

    recent = list(await db.scalars(select(SourceFetchStat).where(*where).order_by(SourceFetchStat.at.desc()).limit(50)))
    errors = list(await db.scalars(select(SourceFetchStat).where(*where, SourceFetchStat.ok.is_(False)).order_by(SourceFetchStat.at.desc()).limit(20)))
    events = list(
        await db.scalars(select(SourceHealthEvent).where(SourceHealthEvent.kind == kind, SourceHealthEvent.key == key).order_by(SourceHealthEvent.n.desc()).limit(10))
    )
    current = events[0] if events and events[0].state == r.state else None
    return {
        "item": row_out(r, now, current.created_at if current else None),
        "fetches": [fetch_out(x) for x in recent],
        "errors": [fetch_out(x) for x in errors],
        "events": [{"at": e.created_at.isoformat(), "state": e.state, "prev": e.prev, "reasons": list(e.reasons or [])} for e in events],
        "members": [row_out(m, now) for m in r.members],
    }


# ---------------------------------------------------------------- state changes, retention


async def evaluate(db: AsyncSession, now: datetime | None = None) -> int:
    """Compares every source's state with its last known one: a change is written as an event (one worth a message is
    marked `notify`). Returns how many changes are worth a message."""
    now = now or utcnow()
    rows = await collect(db, now)
    last = await latest_events(db)
    worth = 0
    for r in rows:
        prev = last.get((r.kind, r.key))
        if prev is not None and prev.state == r.state:
            continue
        send = worth_sending(prev.state if prev else None, r.state)
        db.add(SourceHealthEvent(kind=r.kind, key=r.key, name=r.name, state=r.state, prev=prev.state if prev else None, reasons=list(r.reasons), notify=send, created_at=now))
        worth += send
    await db.commit()
    return worth


async def prune(db: AsyncSession, now: datetime | None = None) -> int:
    """Stats older than KEEP, in short transactions of PRUNE_BATCH rows; events older than KEEP except each source's
    newest (its last known state)."""
    from app.db import delete_batched

    cut = (now or utcnow()) - KEEP
    gone = await delete_batched(db, SourceFetchStat, SourceFetchStat.at < cut, batch=PRUNE_BATCH)
    newest = select(func.max(SourceHealthEvent.n)).group_by(SourceHealthEvent.kind, SourceHealthEvent.key).scalar_subquery()
    await delete_batched(db, SourceHealthEvent, SourceHealthEvent.created_at < cut, SourceHealthEvent.n.not_in(newest), batch=PRUNE_BATCH)
    return gone
