"""Katalog-Pflege: a self-test of the Vendor News catalogue – which entries need care.

Per catalogue product (results in catalog_checks, what the NVD said per CPE in catalog_cpe_checks):
- each CPE is in the NVD CPE dictionary (cpeMatchString) and not only as deprecated entries,
- the NVD has CVEs for it, and a recent one (within NO_CVE_MONTHS),
- the endoflife.date key exists (in the latest endoflife.date list the catalogue was built from – no request of its own)
  and its CPEs still name the same vendor as ours,
- products with the vendor's own advisories (paloalto, fortinet, veeam): when the last advisory for it was seen,
- a followed product without any CPE gets a hint (its vulnerabilities come only from advisories and news) – unless the
  catalogue names it in CNA data (cna): then NVD's keyword search and cvelistV5 bring its CVEs (BloodHound CE, whose
  CVEs have no CPE in the NVD),
- a product with a release source (releases: GitHub, a vendor's page – app/release_sources.py, fetched for followed
  products): the last fetch failed, the pattern found no version, or the newest release is older than
  RELEASE_STALE_MONTHS (the source or its pattern may have changed) – no request of its own.
Status per product: error (a CPE that does not exist, an endoflife.date key that is gone), warn (deprecated CPE, no or
only old CVEs, no advisory for long, followed without CPE), ok, unchecked (no answer for its CPEs yet). Reasons are codes
with parameters ({"code", "level", …}) – the UI words them in German and English.

Requests – NVD only, through the same gate as the Vendor News round (vendor.get: 6.5 s between requests without a key,
the host-wide pause after a 429 is respected – nothing is asked while it lasts):
- followed products: every FOLLOWED_EVERY (weekly) one dictionary request per CPE; their CVE facts come from the NVD
  data Vendor News already fetched for them (no extra request);
- the whole catalogue: every ALL_EVERY (monthly) per CPE one dictionary request and, if it exists, two CVE requests
  (the count, then the newest – NVD lists oldest first);
- at most BUDGET_PER_HOUR requests per hour, only while the Vendor News round is not running – kept in the settings
  (a restart does not give a fresh hour), and spread over the hour: one step (every LOOP_EVERY_S) asks at most its share
  (step_share), not the whole hour's budget at once. Every request sent counts – a failed one too – and an outage (the
  NVD unreachable, refusing or answering 5xx) ends the step at the first failure: it never runs through the due CPEs.
Budget: about 770 distinct CPEs in the catalogue → at most ~2 300 requests per month (≈ 3 per hour on average); the cap of
20 per hour (≈ 3 % of the NVD's public limit of 5 per 30 s) spreads them out – the first full pass takes about five days,
after that each CPE comes up again 30 days after its last check. "Jetzt prüfen" (admins) checks the followed products at
once (at most MANUAL_MAX requests) and everything local.
Nothing is asked while Vendor News is switched off or nothing is followed (the promise in docs/BETRIEB.md: no request without a
followed product) – the local checks still run.
"""

import asyncio
import json
import logging
import math
import time
from collections import Counter, deque
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as dbm
from app import settings as settings_store
from app import vendor as svc
from app import vendor_catalog as catalog
from app import vendor_sources as src
from app.models import CatalogCheck, CatalogCpeCheck, VendorAdvisory, VendorAdvisoryProduct, VendorFetch
from app.news import NewsError

log = logging.getLogger("cobe_news.catalog_check")

FOLLOWED_EVERY = timedelta(days=7)
ALL_EVERY = timedelta(days=30)
BUDGET_PER_HOUR = 20
MANUAL_MAX = 60
NO_CVE_MONTHS = 36  # "any CVE in the last 3 years" – fewer CVEs than that is normal for small products, not a sign of a stale CPE
ADV_MONTHS = 24
RELEASE_STALE_MONTHS = 18  # no release for this long: the tag or page pattern probably no longer matches what the vendor writes
LOOP_EVERY_S = 600.0
RETRY_AFTER_ERROR = timedelta(hours=6)
NVD_HOST = "services.nvd.nist.gov"
SETTING = "catalog_check"

_sent: deque[float] = deque()  # when the self-test's requests went out (epoch seconds; the hourly budget, see run())
_asked = [0]  # every request sent since the process started – failed ones too (a step's budget counts attempts)
# the stored "sent" list's form: 2 (0.1.51) – milliseconds, each request once. Up to 0.1.50 a list in tenths of a second
# where every request stood twice (memory and the stored copy were merged as a set of different roundings)
SENT_V = 2


def _months_ago(now: datetime, months: int) -> datetime:
    return now - timedelta(days=round(months * 30.44))


def budget_left(now: float | None = None) -> int:
    now = time.time() if now is None else now
    while _sent and now - _sent[0] > 3600:
        _sent.popleft()
    return max(0, BUDGET_PER_HOUR - len(_sent))


def step_share() -> int:
    """What one step may ask: the hour's budget spread over the steps of an hour (20 per hour, a step every 10 minutes:
    4) – at least what one CPE needs (3)."""
    return max(3, math.ceil(BUDGET_PER_HOUR * LOOP_EVERY_S / 3600))


# ---------------------------------------------------------------- the NVD's answers


def cpe_url(cpe: str) -> str:
    return f"{src.NVD_CPES}?{urlencode({'cpeMatchString': f'cpe:2.3:{cpe}', 'resultsPerPage': 20}, safe=':*')}"


def cves_url(cpe: str, start: int = 0) -> str:
    return src.nvd_url(virtualMatchString=f"cpe:2.3:{cpe}", resultsPerPage=1, startIndex=start)


def _short(name: str) -> str:
    import re

    parts = re.split(r"(?<!\\):", name)
    return ":".join(parts[2:5]) if name.startswith("cpe:2.3:") and len(parts) >= 5 else name


def parse_dictionary(data: bytes) -> tuple[bool, str | None]:
    """(in the dictionary, the successor when every entry returned is deprecated)."""
    doc = src.clean(json.loads(data or b"{}"))
    total = int(doc.get("totalResults") or 0) if isinstance(doc, dict) else 0
    cpes = [(p or {}).get("cpe") or {} for p in (doc.get("products") or []) if isinstance(p, dict)] if isinstance(doc, dict) else []
    if total == 0 or not cpes:
        return False, None
    if all(c.get("deprecated") for c in cpes):
        by = next((_short(str(d.get("cpeName") or "")) for c in cpes for d in c.get("deprecatedBy") or [] if isinstance(d, dict) and d.get("cpeName")), None)
        return True, by or "?"
    return True, None


def parse_cve_page(data: bytes) -> tuple[int, str | None, datetime | None]:
    """(how many CVEs, the id and publication of the one on this page)."""
    doc = src.clean(json.loads(data or b"{}"))
    total = int(doc.get("totalResults") or 0) if isinstance(doc, dict) else 0
    for v in (doc.get("vulnerabilities") or []) if isinstance(doc, dict) else []:
        cve = (v or {}).get("cve") or {}
        pub = cve.get("published")
        try:
            at = datetime.fromisoformat(str(pub)).replace(tzinfo=UTC) if pub else None
        except ValueError:
            at = None
        return total, (str(cve.get("id") or "") or None), at
    return total, None, None


def outage(exc: NewsError) -> bool:
    """The NVD is not answering as it should – refused (rate limit, 403), unreachable (connection, timeout, DNS, TLS) or
    failing on its side (5xx): the step ends, every further CPE would meet the same. A 4xx about one CPE does not."""
    if exc.category in ("rate_limited", "blocked", "connection", "timeout", "dns", "tls"):
        return True
    return exc.category == "http" and str(exc.detail or "").startswith("HTTP 5")


async def _ask(db: AsyncSession, url: str, key: str) -> bytes:
    # counted before it goes out: a request that fails was sent all the same (the budget counts attempts, not answers)
    _sent.append(round(time.time(), 3))
    _asked[0] += 1
    # db: what the session holds is committed first – no transaction stays open while the gate and the download wait
    body = await svc.get(url, db=db, headers={"apiKey": key} if key else {}, has_key=bool(key), conditional=False, limit=4 * 1024 * 1024)
    return body or b"{}"


async def check_cpe(db: AsyncSession, cpe: str, key: str, local: dict | None) -> int:
    """Ask the NVD about one CPE (local: the CVE facts of a followed product's own NVD data – only the dictionary is
    asked). Returns the number of answered requests; the NewsError of an outage (outage(): 429, 403, unreachable, 5xx –
    the step ends, the CPE is due again after RETRY_AFTER_ERROR) propagates."""
    row = await db.get(CatalogCpeCheck, cpe)
    if row is None:
        row = CatalogCpeCheck(cpe=cpe, source="nvd")
        db.add(row)
    row.tried_at = datetime.now(UTC)
    asked = 0
    try:
        exists, by = parse_dictionary(await _ask(db, cpe_url(cpe), key))
        asked += 1
        total, newest, newest_at = None, None, None
        if exists and local is not None:
            total, newest, newest_at = local["total"], local.get("newest"), local.get("newest_at")
        elif exists:
            total, newest, newest_at = parse_cve_page(await _ask(db, cves_url(cpe), key))
            asked += 1
            if total > 1:
                _, newest, newest_at = parse_cve_page(await _ask(db, cves_url(cpe, total - 1), key))
                asked += 1
    except NewsError as exc:
        row.error = (f"{exc.category}: {exc.detail}" if exc.detail else exc.category)[:200]
        await db.commit()  # the last good answer (checked_at, …) stays; due again after RETRY_AFTER_ERROR
        if outage(exc):
            raise
        log.info("catalogue check %s: %s", cpe, row.error)
        return asked
    except (ValueError, TypeError) as exc:
        row.error = f"format: {type(exc).__name__}"
        await db.commit()
        return asked
    row.exists, row.deprecated_by = exists, by
    row.cve_total, row.newest_cve, row.newest_at = total, newest, newest_at
    row.source = "local" if local is not None and exists else "nvd"
    row.error = None
    row.checked_at = datetime.now(UTC)
    await db.commit()
    return asked


# ---------------------------------------------------------------- what is known locally


async def followed_keys(db: AsyncSession) -> set[str]:
    return {f.product for f in await svc.follows(db)}


async def local_cve_facts(db: AsyncSession, products: list[dict]) -> dict[str, dict]:
    """Per CPE of the followed products: the CVE count of its last full NVD fetch and the newest CVE the product has."""
    keys = [p["key"] for p in products]
    if not keys:
        return {}
    newest = {
        prod: (ident, at)
        for prod, ident, at in (
            await db.execute(
                select(VendorAdvisoryProduct.product, VendorAdvisory.ident, VendorAdvisory.published_at)
                .join(VendorAdvisory, VendorAdvisory.id == VendorAdvisoryProduct.advisory_id)
                .where(VendorAdvisoryProduct.product.in_(keys), VendorAdvisory.source == "nvd", VendorAdvisory.published_at.is_not(None))
                .ext(distinct_on(VendorAdvisoryProduct.product))
                .order_by(VendorAdvisoryProduct.product, VendorAdvisory.published_at.desc())
            )
        ).all()
    }
    cpes = {c for p in products for c in p.get("cpes") or []}
    states = {s.key[4:]: s for s in await db.scalars(select(VendorFetch).where(VendorFetch.key.in_([f"nvd:{c}" for c in cpes])))}
    out: dict[str, dict] = {}
    for p in products:
        n = newest.get(p["key"])
        for c in p.get("cpes") or []:
            st = states.get(c)
            if st is None or st.full_at is None or st.last_ok_at is None:
                continue  # not fetched completely yet: the NVD is asked instead
            cur = out.setdefault(c, {"total": int(st.items or 0), "newest": None, "newest_at": None})
            if n and (cur["newest_at"] is None or (n[1] and n[1] > cur["newest_at"])):
                cur["newest"], cur["newest_at"] = n
    return out


async def last_advisories(db: AsyncSession, products: list[dict]) -> dict[str, datetime | None]:
    """The newest advisory of the vendor's own source per product (adv) – for followed products only (fetched only then)."""
    keys = [p["key"] for p in products if p.get("adv")]
    if not keys:
        return {}
    rows = await db.execute(
        select(VendorAdvisoryProduct.product, VendorAdvisory.source, func.max(func.coalesce(VendorAdvisory.published_at, VendorAdvisory.fetched_at)))
        .join(VendorAdvisory, VendorAdvisory.id == VendorAdvisoryProduct.advisory_id)
        .where(VendorAdvisoryProduct.product.in_(keys))
        .group_by(VendorAdvisoryProduct.product, VendorAdvisory.source)
    )
    adv_of = {p["key"]: p.get("adv") for p in products}
    return {prod: at for prod, source, at in rows.all() if source == adv_of.get(prod)}


async def adv_fetched(db: AsyncSession) -> dict[str, datetime | None]:
    """Since when each advisory source has been fetched successfully (its first good fetch is not kept: the last one)."""
    out: dict[str, datetime | None] = {}
    for st in await db.scalars(select(VendorFetch).where(VendorFetch.key.like("paloalto:%") | VendorFetch.key.in_(["fortinet:rss", "veeam:feed"]))):
        fam = st.key.split(":", 1)[0]
        if st.last_ok_at and (out.get(fam) is None or st.last_ok_at > out[fam]):
            out[fam] = st.last_ok_at
    return out


# ---------------------------------------------------------------- the verdict per product


def _r(code: str, level: str, **params) -> dict:
    return {"code": code, "level": level, **{k: v for k, v in params.items() if v is not None}}


def _day(d: datetime | None) -> str | None:
    return d.date().isoformat() if d else None


def release_facts(states: dict[str, VendorFetch], p: dict) -> dict | None:
    """What is known of a product's release source: its last error, how many versions it found, the newest release day
    (None: the product reads none – endoflife.date's lines come first – or it was never fetched)."""
    from app import release_sources

    cfg = release_sources.config(p)
    if cfg is None or catalog.releases(p.get("eol")):
        return None
    st = states.get(release_sources.fetch_key(p))
    if st is None or (st.last_ok_at is None and not st.error):
        return None
    src_ = release_sources.describe(cfg)
    return {"source": f"{'GitHub ' if src_['kind'] == 'github' else ''}{src_['ref']}", "error": st.error, "newest": release_sources.newest_day(p["key"])}


def verdict(
    p: dict, cpes: dict[str, CatalogCpeCheck], eol: dict[str, dict], followed: bool, last_adv: datetime | None, adv_ok: bool, now: datetime, rel: dict | None = None
) -> tuple[str, list[dict]]:
    """ok | warn | error | unchecked and the reasons, from what is known (no I/O). `rel`: release_facts()."""
    reasons: list[dict] = []
    checked = True
    own = list(p.get("cpes") or [])
    asks_nvd = p.get("scheme") != "distro"
    if asks_nvd and own:
        found = []
        for c in own:
            row = cpes.get(c)
            if row is None or row.checked_at is None:
                checked = False
                continue
            if row.exists is False:
                reasons.append(_r("cpe_missing", "error", cpe=c))
                continue
            # deprecated, and its successor not listed as well (old CVEs may still name the old one: both may stay)
            if row.deprecated_by and row.deprecated_by not in own:
                reasons.append(_r("cpe_deprecated", "warn", cpe=c, by=row.deprecated_by))
            found.append(row)
        if found and checked and not p.get("cloud") and not p.get("filter"):
            total = sum(r.cve_total or 0 for r in found)
            newest = max((r.newest_at for r in found if r.newest_at), default=None)
            if total == 0:
                reasons.append(_r("no_cves", "warn"))
            elif newest and newest < _months_ago(now, NO_CVE_MONTHS):
                months = max(NO_CVE_MONTHS, int((now - newest).days / 30.44))
                cve = next((r.newest_cve for r in found if r.newest_at == newest), None)
                reasons.append(_r("stale_cves", "warn", months=months, newest=_day(newest), cve=cve))
    elif followed and not own and not p.get("cloud") and not p.get("cna"):
        reasons.append(_r("nocpe_followed", "warn"))
    key = p.get("eol")
    if key:
        e = eol.get(key)
        if e is None:
            reasons.append(_r("eol_missing", "error", key=key))
        elif e.get("cpes") and own and p.get("source") != "eol":
            ours, theirs = {c.split(":")[1] for c in own}, {c.split(":")[1] for c in e["cpes"]}
            if not ours & theirs:
                reasons.append(_r("eol_mismatch", "warn", key=key, theirs=", ".join(sorted(theirs))[:120]))
    if rel is not None:
        err = str(rel.get("error") or "")
        if err.startswith("parse: no version"):
            reasons.append(_r("releases_none", "warn", source=rel["source"]))
        elif err and not err.startswith("rate_limited"):
            reasons.append(_r("releases_failed", "warn", source=rel["source"], error=err[:120]))
        elif (newest := rel.get("newest")) is not None:
            at = datetime(newest.year, newest.month, newest.day, tzinfo=UTC)
            if at < _months_ago(now, RELEASE_STALE_MONTHS):
                reasons.append(_r("releases_stale", "warn", source=rel["source"], months=int((now - at).days / 30.44), last=newest.isoformat()))
    if followed and p.get("adv") and adv_ok:
        if last_adv is None:
            reasons.append(_r("adv_none", "info", source=p["adv"]))
        elif last_adv < _months_ago(now, ADV_MONTHS):
            reasons.append(_r("adv_stale", "warn", source=p["adv"], last=_day(last_adv), months=int((now - last_adv).days / 30.44)))
        else:
            reasons.append(_r("adv_last", "info", source=p["adv"], last=_day(last_adv)))
    levels = {r["level"] for r in reasons}
    if "error" in levels:
        return "error", reasons
    if "warn" in levels:
        return "warn", reasons
    if asks_nvd and own and not checked:
        return "unchecked", reasons
    return "ok", reasons


def gone_patches(eol: dict[str, dict]) -> list[dict]:
    """Entries of the catalogue data that only patch an endoflife.date product endoflife.date no longer has – they are
    silently missing from the catalogue (vendor_catalog.apply_overlay skips them)."""
    return [o for o in catalog.OVERLAY if o.get("label") is None and o["key"] not in eol]


async def evaluate(db: AsyncSession, now: datetime | None = None) -> int:
    """The verdicts of all catalogue products from what is known – written where they changed. Returns that number."""
    now = now or datetime.now(UTC)
    cat = catalog.load()
    eol = {r["key"]: r for r in cat.get("eol_products") or []}
    fol = await followed_keys(db)
    products = list(cat["products"])
    cpes = {r.cpe: r for r in await db.scalars(select(CatalogCpeCheck))}
    followed = [p for p in products if p["key"] in fol]
    last_adv = await last_advisories(db, followed)
    fetched = await adv_fetched(db)
    old = {c.product: c for c in await db.scalars(select(CatalogCheck))}
    rel_states = {s.key: s for s in await db.scalars(select(VendorFetch).where(VendorFetch.key.startswith("releases:", autoescape=True)))}
    seen: set[str] = set()
    changed = 0
    version = catalog.catalog_version()

    def put(key: str, status: str, reasons: list[dict], is_followed: bool) -> None:
        nonlocal changed
        seen.add(key)
        row = old.get(key)
        if row is not None and row.status == status and row.reasons == reasons and row.followed == is_followed and row.catalog_version == version:
            return
        if row is None:
            row = CatalogCheck(product=key)
            db.add(row)
        row.status, row.reasons, row.followed, row.checked_at, row.catalog_version = status, reasons, is_followed, now, version
        changed += 1

    for p in products:
        is_f = p["key"] in fol
        status, reasons = verdict(p, cpes, eol, is_f, last_adv.get(p["key"]), bool(fetched.get(p.get("adv") or "")), now, release_facts(rel_states, p) if is_f else None)
        put(p["key"], status, reasons, is_f)
    for o in gone_patches(eol):
        put(o["key"], "error", [_r("eol_missing", "error", key=o["key"])], o["key"] in fol)
    for key, row in old.items():
        if key not in seen:
            await db.delete(row)  # no longer in the catalogue
            changed += 1
    await db.commit()
    return changed


# ---------------------------------------------------------------- the round


def due(cpes: dict[str, CatalogCpeCheck], followed_cpes: set[str], all_cpes: list[str], now: datetime) -> list[str]:
    """The CPEs to ask about, most urgent first: followed ones not asked for a week, then never asked, then the oldest
    not asked for a month. After a failed attempt a CPE is due again after RETRY_AFTER_ERROR."""

    def interval(c: str, r: CatalogCpeCheck) -> timedelta:
        every = FOLLOWED_EVERY if c in followed_cpes else ALL_EVERY
        return min(every, RETRY_AFTER_ERROR) if r.error else every

    def is_due(c: str) -> bool:
        r = cpes.get(c)
        return r is None or r.tried_at is None or now - r.tried_at >= interval(c, r)

    def tried(c: str) -> datetime | None:
        r = cpes.get(c)
        return r.tried_at if r else None

    todo = [c for c in all_cpes if is_due(c)]
    todo.sort(key=lambda c: (c not in followed_cpes, tried(c) is not None, tried(c) or now))
    return todo


async def run(*, manual: bool = False, vendor_busy: bool = False) -> dict:
    """One step: ask the NVD about due CPEs within the budget (manual: the followed ones now), then the verdicts."""
    checked = 0
    stopped = None
    start = _asked[0]

    def asked() -> int:  # the requests of this step – failed ones included
        return _asked[0] - start

    async with dbm.session() as db:
        # the hour's requests as stored (a restart must not start a fresh hour); memory may know some more
        merge_sent((await settings_store.get(db, SETTING)))
        cfg = await svc.config(db)
        cat = catalog.load()
        fol = await followed_keys(db)
        may_ask = bool(cfg.get("enabled", True)) and bool(fol) and not vendor_busy
        if may_ask:
            products = [p for p in cat["products"] if p.get("scheme") != "distro"]
            all_cpes = list(dict.fromkeys(c for p in products for c in p.get("cpes") or []))
            fprods = [p for p in products if p["key"] in fol]
            fcpes = {c for p in fprods for c in p.get("cpes") or []}
            rows = {r.cpe: r for r in await db.scalars(select(CatalogCpeCheck))}
            now = datetime.now(UTC)
            if manual:
                todo = [c for c in all_cpes if c in fcpes]
                allowance = MANUAL_MAX
            else:
                todo = due(rows, fcpes, all_cpes, now)
                allowance = min(budget_left(), step_share())
            local = await local_cve_facts(db, fprods)
            key = svc.nvd_key(cfg)
            for c in todo:
                if svc.blocked_for(NVD_HOST) > 0:
                    stopped = "paused"
                    break
                need = 1 if c in local else 3
                if asked() + need > allowance:
                    stopped = "budget"
                    break
                try:
                    await check_cpe(db, c, key, local.get(c))
                    checked += 1
                except NewsError as exc:
                    # rate limited: the host pauses (svc.blocked_for); unreachable or failing: this step ends – an
                    # outage never runs through the list of due CPEs
                    stopped = "paused" if exc.category == "rate_limited" else "unreachable"
                    break
                if not (await svc.config(db)).get("enabled", True):
                    break
        else:
            stopped = "off" if not cfg.get("enabled", True) else "nothing_followed" if not fol else "vendor_busy"
        changed = await evaluate(db)
        state = await settings_store.get(db, SETTING)
        budget_left()  # drops what is older than an hour
        state = {**state, "last_run_at": datetime.now(UTC).isoformat(), "last_stop": stopped, "sent": list(_sent), "sent_v": SENT_V}
        if manual:
            state["last_manual_at"] = state["last_run_at"]
        if checked:
            state["last_asked_at"] = state["last_run_at"]
        await settings_store.put(db, SETTING, state)
        await db.commit()
    if checked or changed:
        log.info("catalogue check: %s CPEs (%s requests), %s verdicts changed%s", checked, asked(), changed, f", stopped: {stopped}" if stopped else "")
    return {"cpes": checked, "requests": asked(), "changed": changed, "stopped": stopped}


def merge_sent(state: dict) -> None:
    """The hour's requests: what memory knows and what was stored (a restart). Both hold the same request with the same
    value (milliseconds) – merged as a multiset (the larger count of each value), so a request stored by the last step
    counts once, and two requests in the same millisecond still count twice. A list of 0.1.50 or older (tenths of a
    second, every request twice): each value once."""
    stored = [round(float(x), 3) for x in state.get("sent") or [] if isinstance(x, int | float) and not isinstance(x, bool)]
    if state.get("sent_v") != SENT_V:
        stored = sorted(set(stored))
    merged = Counter(round(x, 3) for x in _sent) | Counter(stored)
    _sent.clear()
    _sent.extend(sorted(merged.elements()))


class CheckLoop:
    """Its own small task: every LOOP_EVERY_S one step (nothing is asked while the Vendor News round runs);
    `now()` – the admin's "Jetzt prüfen"."""

    def __init__(self, vendor_loop=None) -> None:  # noqa: ANN001
        self.event = asyncio.Event()
        self.manual = False
        self.running = False
        self.vendor_loop = vendor_loop

    def now(self) -> None:
        self.manual = True
        self.event.set()

    async def step(self) -> dict:
        manual, self.manual = self.manual, False
        self.running = True
        try:
            busy = bool(self.vendor_loop and self.vendor_loop.running) and not manual
            return await run(manual=manual, vendor_busy=busy)
        finally:
            self.running = False

    async def run(self) -> None:
        await asyncio.sleep(120)  # after the start: the Vendor News round goes first
        while True:
            self.event.clear()
            try:
                await self.step()
            except Exception:  # noqa: BLE001 - one bad step must not end the loop
                log.exception("catalogue check failed")
            try:
                await asyncio.wait_for(self.event.wait(), LOOP_EVERY_S)
            except TimeoutError:
                pass


# ---------------------------------------------------------------- what the API shows


async def overview(db: AsyncSession, *, running: bool = False) -> dict:
    cat = catalog.load()
    by = {p["key"]: p for p in cat["products"]}
    labels = {o["key"]: o for o in catalog.OVERLAY}
    rows = list(await db.scalars(select(CatalogCheck)))
    counts = {s: 0 for s in ("error", "warn", "ok", "unchecked")}
    fcounts = dict(counts)
    items = []
    for r in rows:
        counts[r.status] = counts.get(r.status, 0) + 1
        if r.followed:
            fcounts[r.status] = fcounts.get(r.status, 0) + 1
        if r.status not in ("error", "warn"):
            continue
        p = by.get(r.product) or labels.get(r.product) or {}
        items.append(
            {
                "product": r.product,
                "label": p.get("label") or r.product,
                "vendor": p.get("vendor") or "",
                "category": p.get("category") or "other",
                "cpes": list(p.get("cpes") or []),
                "status": r.status,
                "followed": r.followed,
                "reasons": [x for x in r.reasons if x.get("level") != "info"],
                "checked_at": r.checked_at.isoformat() if r.checked_at else None,
                "in_catalog": r.product in by,
            }
        )
    items.sort(key=lambda x: (x["status"] != "error", not x["followed"], x["label"].lower()))
    cpe_rows = list(await db.scalars(select(CatalogCpeCheck)))
    all_cpes = {c for p in cat["products"] if p.get("scheme") != "distro" for c in p.get("cpes") or []}
    state = await settings_store.get(db, SETTING)
    return {
        "catalog_version": catalog.catalog_version(),
        "eol_generated_at": cat.get("eol_generated_at"),
        "counts": counts,
        "followed_counts": fcounts,
        "cpes": {"total": len(all_cpes), "checked": sum(1 for r in cpe_rows if r.cpe in all_cpes and r.checked_at)},
        "items": items,
        "last_run_at": state.get("last_run_at"),
        "last_asked_at": state.get("last_asked_at"),
        "last_manual_at": state.get("last_manual_at"),
        "last_stop": state.get("last_stop"),
        "running": running,
        "budget_per_hour": BUDGET_PER_HOUR,
        "followed_every_days": FOLLOWED_EVERY.days,
        "all_every_days": ALL_EVERY.days,
    }


async def of_product(db: AsyncSession, key: str) -> dict | None:
    """A product's verdict for its drawer – only when something needs care."""
    row = await db.get(CatalogCheck, key)
    if row is None or row.status not in ("error", "warn"):
        return None
    return {"status": row.status, "reasons": [x for x in row.reasons if x.get("level") != "info"], "checked_at": row.checked_at.isoformat() if row.checked_at else None}
