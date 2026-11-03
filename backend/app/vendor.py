"""Vendor News: followed products and their versions → vulnerabilities that affect exactly them, newer versions and
EOL dates, related stories – and notifications about what is new.

Background (its own asyncio task, `VendorLoop`, so slow rate-limited requests never hold up the news round): every
minute it looks what is due – advisories and NVD every `every_h` hours (default 6), endoflife.date and the CISA KEV
every `eol_every_h` hours (default 24) – one request after the other, each host with its own minimum gap (NVD: 6.5 s
without an API key, i.e. at most 5 requests per 30 s; 0.8 s with one), conditional requests where the source supports
them, growing pauses after errors (Retry-After respected, at least an hour after 429/503). Nothing is requested while
the feature is switched off or nothing is followed.

The structured sources run in the same task (sync_structured, after_round – each switchable): the CSAF providers of the
followed vendors (csaf_providers), cvelistV5's hourly delta and single records (cvelist), OSV and EPSS for the CVEs of
the findings (osv, epss). Verdict order per vulnerability: the vendor's own advisory first, then per CVE the NVD where
it analysed the CVE, cvelistV5 where it did not, OSV where those leave it open (cve_verdict).

After a round (and right after a version is added or changed) every followed product is evaluated; what is new becomes
a VendorEvent (once per product, version and finding). The first evaluation of a new product or version is the
baseline: shown on the page, not notified – as the news rules send no backlog either.
"""

import asyncio
import bisect
import json
import logging
import re
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import Text, and_, cast, delete, literal, or_, select, update
from sqlalchemy.dialects.postgresql import JSONPATH
from sqlalchemy.dialects.postgresql import array as pg_array
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app import advisory_changes as changes_svc
from app import cve_watch
from app import db as dbm
from app import news as news_svc
from app import settings as settings_store
from app import source_health
from app import vendor_catalog as catalog
from app import vendor_sources as src
from app import vendor_titles as titles
from app import version_input
from app.config import get_config, tls_verify
from app.crypto import decrypt_str
from app.models import NewsItem, NewsItemSource, NewsSource, VendorAdvisory, VendorAdvisoryProduct, VendorAdvisoryState, VendorEvent, VendorFetch, VendorFollow, VendorKev, VendorVersion
from app.news import NewsError
from app.vendor_match import ORDER, Verdict, evaluate, name_matches, name_words
from app.vendor_match import _cna_names as cna_names
from app.vendor_versions import VEEAM_BUILD_DEPTH, V, parse

log = logging.getLogger("cobe_news.vendor")

DEFAULTS = settings_store.DEFAULTS["vendor"]
MAX_BACKOFF = timedelta(hours=24)
NVD_MAX_RESULTS = 2000  # per CPE: the newest 2000 CVEs (Linux kernel, Chrome, Windows have more)
NVD_LIMIT = 24 * 1024 * 1024  # one page of 500 records with their configurations
PAN_MAX_PAGES = 60  # 25 advisories a page – the whole history of a product line on the first run
FORTI_MAX_CSAF = 60
EVENT_FRESH = timedelta(days=30)  # older advisories (a backfill, NVD analysing an old CVE): shown, not notified
# "Support endet bald": less than half a year left – what an upgrade needs to be planned. The same number on both sides:
# the drawer computes it in the browser (frontend lib/vendor-api.ts SUPPORT_SOON_DAYS – vendor-api.test.ts pins both).
EOL_SOON_DAYS = 183
EOL_SOON = timedelta(days=EOL_SOON_DAYS)
# the pre-warnings per version entered (0.1.34): 90 and 30 days before its support ends, and when it has ended – each
# stage once per version and date (eol_stage, _eol_stages). Kind "eol" like "Support endet bald" – the rules and the
# personal ways with "Versionen & EOL" get them.
EOL_STAGES = ((30, "30"), (90, "90"))
EOL_STAGE_RANK = {"90": 1, "30": 2, "past": 3}
STORE_BATCH = 500  # advisories per write transaction (an NVD backfill brings up to NVD_MAX_RESULTS at once)
KEYWORD_DAYS = 30  # NVD keyword search for CVEs not analysed yet (no CPEs): the last days only
transport = None  # tests: an httpx.MockTransport – never the real vendors
# records about one CVE (not a vendor's advisory): grouped under the vendor advisory naming their CVE, judged after it
CVE_SOURCES = ("nvd", "cvelist", "osv")
# vendor_fetch rows of single lookups (one per CVE: when it was asked) – no sources of their own
PER_CVE = ("nvdcve:", "cvelistcve:", "osvcve:")
GAPS = {
    "services.nvd.nist.gov": 6.5,
    "security.paloaltonetworks.com": 3.0,
    "filestore.fortinet.com": 2.0,
    "endoflife.date": 5.0,
    "www.cisa.gov": 60.0,
    "www.veeam.com": 60.0,
    # the structured sources (csaf_providers, cvelist, epss, osv)
    "api.github.com": 5.0,  # unauthenticated: 60 requests an hour – cvelistV5 asks about one an hour
    "github.com": 2.0,
    "raw.githubusercontent.com": 1.0,
    "api.first.org": 2.0,
    "api.osv.dev": 1.0,
    "wid.cert-bund.de": 1.0,
    "cert-portal.siemens.com": 1.0,
    "www.cisco.com": 1.0,
    "www.se.com": 1.0,
}
# hosts the news fetch asks too: one shared minimum gap (one request per site and minute, as the news promise)
SHARED_HOSTS = ("www.cisa.gov", "www.veeam.com")
NVD_GAP_KEY = 0.8
_last: dict[str, float] = {}


class _Gen:
    """Bumped on every write (stored advisories, edited follows): the cached evaluations are recomputed."""

    value = 0  # any change (the news hints use it)
    epoch = 0  # a change for every product (KEV, catalogue)


gen = _Gen()
_pgen: dict[str, int] = {}  # per product: its advisories or its follow changed


def bump(products: "list[str] | set[str] | None" = None) -> None:
    """Cached views recomputed: of these products only (an advisory stored for them, their follow or versions edited) –
    or of all (None: the KEV, the catalogue)."""
    gen.value += 1
    if products is None:
        gen.epoch += 1
        _views.clear()
        from app import epss

        epss.invalidate()  # the stored scores are read again with the views
        return
    for k in products:
        _pgen[k] = _pgen.get(k, 0) + 1
        _views.pop(k, None)


def reset() -> None:
    """In-process state back to the start (tests: every test has its own database)."""
    _last.clear()
    _blocked.clear()
    _locks.clear()
    _evaluated.clear()
    _last_full[0] = None
    _flight.clear()
    _related.clear()
    _pruned[0] = None
    cve_watch.reset()
    bump()


# ---------------------------------------------------------------- settings


async def config(db: AsyncSession) -> dict:
    return await settings_store.get(db, "vendor")


def nvd_key(cfg: dict) -> str:
    enc = cfg.get("nvd_key_enc") or ""
    if not enc:
        return ""
    try:
        return decrypt_str(enc)
    except Exception:  # noqa: BLE001 - key changed: like no key (the settings say "set", a test shows it fails)
        return ""


# ---------------------------------------------------------------- products


async def follows(db: AsyncSession, *, enabled_only: bool = True) -> list[VendorFollow]:
    stmt = select(VendorFollow).order_by(VendorFollow.created_at)
    if enabled_only:
        stmt = stmt.where(VendorFollow.enabled.is_(True))
    return list(await db.scalars(stmt))


def product_of(f: VendorFollow) -> dict | None:
    if f.custom:
        return catalog.custom_product({**f.custom, "key": f.product})
    return catalog.product(f.product)


async def versions_of(db: AsyncSession, follow_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[VendorVersion]]:
    out: dict[uuid.UUID, list[VendorVersion]] = {}
    if not follow_ids:
        return out
    for v in await db.scalars(select(VendorVersion).where(VendorVersion.follow_id.in_(follow_ids)).order_by(VendorVersion.created_at)):
        out.setdefault(v.follow_id, []).append(v)
    return out


# ---------------------------------------------------------------- linking advisories to products


@dataclass
class Index:
    products: list[dict]
    by_cpe: dict[str, list[dict]]
    by_name: dict[str, dict[str, list[dict]]]  # source → lower name → products
    with_cna: list[dict]
    by_osv: dict[tuple[str, str], list[dict]] = field(default_factory=dict)  # (ecosystem, package), lower → products


def index_of(prods: list[dict]) -> Index:
    """The lookups link() needs for these products."""
    by_cpe: dict[str, list[dict]] = {}
    by_name: dict[str, dict[str, list[dict]]] = {"paloalto": {}, "fortinet": {}}
    by_osv: dict[tuple[str, str], list[dict]] = {}
    for p in prods:
        for c in p.get("cpes") or []:
            by_cpe.setdefault(cpe_key(c), []).append(p)
        if p.get("adv") in by_name:
            for n in p.get("names") or []:
                by_name[p["adv"]].setdefault(n.lower(), []).append(p)
        for eco, name in p.get("osv") or []:
            by_osv.setdefault((str(eco).lower(), str(name).lower()), []).append(p)
    return Index(prods, by_cpe, by_name, [p for p in prods if p.get("cna") or p.get("cpes")], by_osv)


def build_index(extra: list[dict] | None = None) -> Index:
    return index_of(list(catalog.load()["products"]) + list(extra or []))


async def current_index(db: AsyncSession) -> Index:
    """The catalogue with the products added by CPE – what every store() needs, also the story details': a record they
    store first would otherwise never be linked to a custom product (store skips unchanged records later)."""
    customs = [p for f in await follows(db, enabled_only=False) if f.custom and (p := product_of(f))]
    return build_index(customs)


def link(adv: dict, ix: Index) -> set[str]:
    """The catalogue products an advisory concerns – each candidate checked by the matching itself."""
    cands: dict[str, dict] = {}
    s = adv["source"]
    if s == "csaf":
        from app.vendor_match import entries_for

        for p in ix.products:
            if entries_for(p, adv["data"]):
                cands[p["key"]] = p
    elif s == "veeam":
        cands = {p["key"]: p for p in ix.products if p.get("adv") == "veeam"}  # a handful – the matching decides by name
    elif s in ("paloalto", "fortinet"):
        for n in adv.get("names") or []:
            low = n.lower()
            for name, ps in ix.by_name[s].items():
                if low == name or low.startswith(name + " "):
                    for p in ps:
                        cands[p["key"]] = p
    elif s == "osv":
        for pkg in adv["data"].get("packages") or []:
            if isinstance(pkg, dict):
                for p in ix.by_osv.get((str(pkg.get("ecosystem") or "").split(":")[0].lower(), str(pkg.get("name") or "").lower()), []):
                    cands[p["key"]] = p
    else:  # nvd, cvelist: CPE configurations, the CNA's affected data (cvelist: also CISA's ADP rows with their CPEs)
        data = adv["data"]
        for x in data.get("adp") or []:
            for a in x.get("affectedData") or [] if isinstance(x, dict) else []:
                for c in a.get("cpes") or [] if isinstance(a, dict) else []:
                    parts = re.split(r"(?<!\\):", str(c))
                    if len(parts) > 4:
                        for p in ix.by_cpe.get(f"{parts[3]}:{parts[4]}".replace("\\", ""), []):
                            cands[p["key"]] = p
        for cfg in data.get("configs") or []:
            for node in cfg.get("nodes") or []:
                for m in node.get("cpeMatch") or []:
                    parts = re.split(r"(?<!\\):", m.get("criteria") or "")
                    if len(parts) > 4:
                        for p in ix.by_cpe.get(f"{parts[3]}:{parts[4]}".replace("\\", ""), []):
                            cands[p["key"]] = p
        rows = [(str(a.get("vendor") or ""), str(a.get("product") or "")) for x in data.get("cna") or [] for a in x.get("affectedData") or []]
        if rows:
            for p in ix.with_cna:
                # NVD: the names the catalogue gives (its CPE configurations find the rest); cvelistV5 has no
                # configurations – there the CPE's names count too, as the matching itself judges them (eval_cna)
                for wv, want in (p.get("cna") or []) if s == "nvd" else cna_names(p):
                    if any(name_matches(prod, want, vendor) for vendor, prod in rows):
                        cands[p["key"]] = p
                        break
    return {k for k, p in cands.items() if evaluate(p, s, adv["data"], None) is not None}


def _same(old: VendorAdvisory | None, a: dict) -> bool:
    return old is not None and old.updated_at == a.get("updated_at") and old.data == a.get("data") and old.cves == a.get("cves") and old.title == a.get("title")


def _same_owner(old: VendorAdvisory | None, a: dict) -> bool:
    """Whether `a` may replace the stored record: always, except a CSAF record of another publisher (another name or
    another publisher namespace) – a CSAF provider or a story never overwrites the advisory of someone else."""
    if old is None or old.source != "csaf" or a.get("source") != "csaf":
        return True
    od, nd = old.data or {}, a.get("data") or {}
    if (od.get("publisher") or "") != (nd.get("publisher") or ""):
        return False
    return not (od.get("provider") and nd.get("provider") and od["provider"] != nd["provider"])


async def store(db: AsyncSession, advs: list[dict], ix: Index, skipped: list[str] | None = None) -> int:
    """Advisories as they are now (insert or replace) and their products; returns how many changed. Batches of
    STORE_BATCH: what changed is found by reading and linked off the event loop first, then written in one short
    transaction each – the database is never held while products are matched. Each advisory is written under a
    savepoint of its own: one the database refuses is left out (logged, its id added to `skipped`) instead of taking
    the batch – and the source's cursor – down with it. An advisory stored before whose content changed becomes a
    revision (app/advisory_changes.py) – with events for the followed products it concerns."""
    await dbm.release(db)  # the caller's pending state goes first, on its own
    changed = 0
    touched: set[str] = set()  # the products whose view changes (linked before or now)
    known_keys = [p["key"] for p in ix.products]
    targets: dict[str, dict] | None = None  # the followed products and versions – read once, when a stored one comes again
    for i in range(0, len(advs), STORE_BATCH):
        part = list({a["id"]: a for a in advs[i : i + STORE_BATCH]}.values())
        ids = [a["id"] for a in part]
        olds = {o.id: o for o in await db.scalars(select(VendorAdvisory).where(VendorAdvisory.id.in_(ids)).execution_options(populate_existing=True))}
        todo = [a for a in part if not _same(olds.get(a["id"]), a)]
        for a in [a for a in todo if not _same_owner(olds.get(a["id"]), a)]:
            # a CSAF record is replaced only by its own publisher (security review 0.1.26 H2)
            log.warning("vendor: advisory %s not replaced: another publisher (%s)", str(a["id"])[:120], str((a.get("data") or {}).get("publisher"))[:60])
            if skipped is not None:
                skipped.append(str(a["id"]))
            todo.remove(a)
        if not todo:
            continue
        linked: dict[str, set[str]] = {}
        for prod, aid in (await db.execute(select(VendorAdvisoryProduct.product, VendorAdvisoryProduct.advisory_id).where(VendorAdvisoryProduct.advisory_id.in_([a["id"] for a in todo])))).all():
            linked.setdefault(aid, set()).add(prod)
            touched.add(prod)
        again = [a["id"] for a in todo if a["id"] in olds]
        prev: dict[str, tuple] = {}
        if again:
            if targets is None:
                targets = await change_targets(db)
            states = {s.advisory_id: s for s in await db.scalars(select(VendorAdvisoryState).where(VendorAdvisoryState.advisory_id.in_(again)))}
            for aid in again:
                o, s_ = olds[aid], states.get(aid)
                prev[aid] = (o.source, o.severity, o.cvss, list(o.cves or []), o.data, (s_.facts, s_.revision) if s_ is not None else None)
        # control characters out of everything written (the parsers clean already – this also covers other callers)
        links = await asyncio.to_thread(lambda todo=todo: [(src.clean(a), link(a, ix)) for a in todo])
        plans = await asyncio.to_thread(_change_plans, links, prev, linked, targets or {}) if prev else {}
        for _, keys in links:
            touched.update(keys)
        now = datetime.now(UTC)
        for a, keys in links:
            row = {k: a.get(k) for k in ("id", "source", "ident", "title", "summary", "url", "cves", "cvss", "severity", "published_at", "updated_at", "data")}
            row["exploited"] = bool(a.get("exploited"))
            row["fetched_at"] = now
            plan = plans.get(a["id"])
            try:
                async with db.begin_nested():
                    stmt = pg_insert(VendorAdvisory).values(**row)
                    await db.execute(stmt.on_conflict_do_update(index_elements=["id"], set_={k: v for k, v in row.items() if k != "id"}))
                    # only the links of the products this index knows: a product added (by CPE) after the index was
                    # built keeps what its relink found – the round's next store() must not take it away again
                    await db.execute(delete(VendorAdvisoryProduct).where(VendorAdvisoryProduct.advisory_id == a["id"], VendorAdvisoryProduct.product.in_(known_keys)))
                    if keys:
                        await db.execute(pg_insert(VendorAdvisoryProduct).on_conflict_do_nothing(), [{"product": k, "advisory_id": a["id"]} for k in keys])
                    if plan is not None:
                        await _write_plan(db, a, plan, now)
            except DBAPIError as exc:
                log.warning("vendor: advisory %s not stored: %s", str(a.get("id"))[:120], str(exc.orig if exc.orig is not None else exc).splitlines()[0][:160])
                if skipped is not None:
                    skipped.append(str(a.get("id")))
                continue
            changed += 1
        await db.commit()
    if changed:
        bump(touched)
    return changed


async def change_targets(db: AsyncSession) -> dict[str, dict]:
    """The followed products (switched on) with their versions – what a revision is judged against (advisory_changes)."""
    fs = await follows(db)
    vers = await versions_of(db, [f.id for f in fs])
    out: dict[str, dict] = {}
    for f in fs:
        p = product_of(f)
        if p is not None:
            vs = [{"id": str(v.id), "version": v.version, "label": v.label or ""} for v in vers.get(f.id, [])]
            out[f.product] = {"key": f.product, "label": p.get("label") or f.product, "product": p, "versions": vs, "baseline": f.baseline_at is None}
    return out


def _stamped(facts: dict, source: str) -> dict:
    return {**facts, "v": changes_svc.EXTRACT_V, "p": changes_svc.PARSER_V.get(source, 1)}


def _change_plans(links: list[tuple[dict, set[str]]], prev: dict[str, tuple], linked: dict[str, set[str]], targets: dict[str, dict]) -> dict[str, dict]:
    """(Off the event loop) per advisory stored before: its facts now and – when the content changed – the revision
    (diff, impact, the followed products it concerns). Silent (facts set anew, no revision): another parser version of
    the source, a CSAF provider's first fill, a batch where most known advisories changed at once (a reformat)."""
    plans: dict[str, dict] = {}
    for a, keys in links:
        if a["id"] not in prev:
            continue
        source, sev, cvss, cves, data, state = prev[a["id"]]
        new = changes_svc.facts_of(source, a.get("severity"), a.get("cvss"), a.get("cves"), a.get("data"))
        stored = state[0] if state is not None else None
        if stored and stored.get("v") == changes_svc.EXTRACT_V:
            before = stored
        else:  # no state yet (stored before 0.1.32) or another extractor: the stored record, read as now
            before = changes_svc.facts_of(source, sev, cvss, cves, data)
        silent = bool(stored and stored.get("p", 1) != changes_svc.PARSER_V.get(source, 1)) or bool((a.get("data") or {}).get("initial"))
        merged = new if silent else changes_svc.merge(before, new)  # silent: as the source says now, nothing kept
        facts = _stamped(merged, source)
        plan = {"facts": facts, "revision": state[1] if state is not None else 1, "change": None, "write": stored != facts}
        if not silent:
            diff = changes_svc.diff(before, merged)
            tg = [targets[k] for k in sorted((linked.get(a["id"]) or set()) | keys) if k in targets]
            impact, relevant = changes_svc.impacts(tg, source, data, a.get("data")) if tg else ([], set())
            if diff or impact:
                plan["change"] = {"diff": diff, "impact": impact, "relevant": relevant, "targets": tg, "products": sorted((linked.get(a["id"]) or set()) | keys)}
        plans[a["id"]] = plan
    n = sum(1 for p in plans.values() if p["change"])
    if n >= changes_svc.MASS_MIN and n >= changes_svc.MASS_SHARE * len(plans):
        log.warning("vendor: %d of %d known advisories changed at once – taken as a reformatted source, no revisions", n, len(plans))
        for p in plans.values():
            p["change"] = None
    return plans


async def _write_plan(db: AsyncSession, a: dict, plan: dict, now: datetime) -> None:
    """The advisory's facts (and, with a change, its revision and events) – inside the advisory's savepoint."""
    revision, changed_at = plan["revision"], None
    if plan["change"]:
        c = plan["change"]
        revision += 1
        changed_at = now
        await changes_svc.record(db, a, revision=revision, changes=c["diff"], impact=c["impact"], products=c["products"], targets=c["targets"], relevant=c["relevant"], now=now)
    elif not plan["write"]:
        return
    values = {"advisory_id": a["id"], "facts": plan["facts"], "revision": revision, "changed_at": changed_at}
    set_ = {"facts": plan["facts"], "revision": revision, **({"changed_at": changed_at} if changed_at else {})}
    await db.execute(pg_insert(VendorAdvisoryState).values(**values).on_conflict_do_update(index_elements=["advisory_id"], set_=set_))


def _skipped_note(st: VendorFetch, skipped: list[str]) -> None:
    """After a fetch that worked: records the database refused show as the query's error (Quellen mit Fehlern) – the
    others are stored and the cursor moved on."""
    if skipped:
        st.error = f"format: {len(skipped)} record(s) not stored, e.g. {skipped[0]}"[:200]


RELINK_BATCH = 2000


def _jp_string(text: str) -> str:
    """A string literal for a SQL/JSON path expression."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _relink_candidates(product: dict):  # noqa: ANN202
    """Which stored advisories can concern the product at all – decided by PostgreSQL on the JSONB, so only those are
    shipped and matched in Python (not 60k NVD records as JSON text: following a product took ~1 s). Every advisory of
    the vendors' own sources (a few hundred); NVD records only where a configuration names one of its CPEs (as written
    in the catalogue and without CPE escapes) or the CNA data names a word of its CNA product names. link() decides."""
    paths = []
    for c in product.get("cpes") or []:
        for form in dict.fromkeys((c, c.replace("\\", ""))):
            paths.append(f"$.configs[*].nodes[*].cpeMatch[*].criteria ? (@ starts with {_jp_string(f'cpe:2.3:{form}:')})")
            paths.append(f"$.adp[*].affectedData[*].cpes[*] ? (@ starts with {_jp_string(f'cpe:2.3:{form}:')})")  # cvelist: CISA's ADP

    def word_of(want: str) -> str | None:
        words = [w for w in name_words(want) if w != "and"]
        return max(words, key=len) if words else None  # name_matches needs every word of the wanted name: the longest is the rarest

    for _vendor, want in product.get("cna") or []:
        if word := word_of(want):
            paths.append(f"$.cna[*].affectedData[*].product ? (@ like_regex {_jp_string(re.escape(word))} flag \"i\")")
    conds = [VendorAdvisory.data.op("@?")(cast(literal(pth), JSONPATH)) for pth in paths]
    if not product.get("cna"):
        # cvelistV5 records have no CPE configurations: the CNA's names are judged by the CPE's names (link()) – only
        # for them (a word of a CPE name like "server" is in thousands of NVD records)
        for _vendor, want in cna_names(product):
            if word := word_of(want):
                conds.append(and_(VendorAdvisory.source == "cvelist", VendorAdvisory.data.op("@?")(cast(literal(f"$.cna[*].affectedData[*].product ? (@ like_regex {_jp_string(re.escape(word))} flag \"i\")"), JSONPATH))))
    for _eco, name in product.get("osv") or []:
        conds.append(VendorAdvisory.data.op("@?")(cast(literal(f"$.packages[*].name ? (@ == {_jp_string(str(name))})"), JSONPATH)))  # OSV: its packages
    return or_(VendorAdvisory.source.not_in(CVE_SOURCES), *conds)


async def relink(db: AsyncSession, product: dict, *, quiet: bool = False) -> int:
    """A product followed later (or added by CPE, or given more CPEs or names by a catalogue change): the stored
    advisories that concern it are linked now – the queries of other products may have brought them already. Only the
    candidates (_relink_candidates) are read, in batches as raw JSON text, decoded and matched off the event loop: a
    database with 60k NVD records never stalls the requests. `quiet`: the links it adds are quiet – a finding that
    exists only through them is shown, never notified (a catalogue change is no news, relink_catalog)."""
    one = index_of([product])
    have = set(await db.scalars(select(VendorAdvisoryProduct.advisory_id).where(VendorAdvisoryProduct.product == product["key"])))

    def match(rows: list) -> list[str]:
        hits = []
        for aid, source, raw in rows:
            if aid in have:
                continue
            data = json.loads(raw) if raw else {}
            data = data if isinstance(data, dict) else {}
            if source == "fortinet":
                names = list((data.get("products") or {}).keys())
            else:
                names = list(data.get("products") or []) + [x.get("name", "") for x in data.get("lines") or [] if isinstance(x, dict)]
            if product["key"] in link({"id": aid, "source": source, "data": data, "names": names}, one):
                hits.append(aid)
        return hits

    hits: list[str] = []
    # the candidates' ids in one pass over the table (PostgreSQL checks the JSONB), then their data in batches by id
    ids = [x for x in await db.scalars(select(VendorAdvisory.id).where(_relink_candidates(product)).order_by(VendorAdvisory.id)) if x not in have]
    await dbm.release(db)
    for i in range(0, len(ids), RELINK_BATCH):
        rows = (await db.execute(select(VendorAdvisory.id, VendorAdvisory.source, cast(VendorAdvisory.data, Text)).where(VendorAdvisory.id.in_(ids[i : i + RELINK_BATCH])))).all()
        hits += await asyncio.to_thread(match, rows)
        await dbm.release(db)  # the read transaction ends between batches
    if hits:
        await db.execute(pg_insert(VendorAdvisoryProduct).on_conflict_do_nothing(), [{"product": product["key"], "advisory_id": x, "quiet": quiet} for x in hits])
    await db.commit()
    added = len(hits)
    if added:
        bump([product["key"]])
    return added


RELINK_STATE = "catalog_relink"  # settings row: {version, done: [product keys], complete}
RELINK_PRODUCTS = 10  # followed products relinked per round – a database with many products is done over a few rounds


async def relink_catalog(db: AsyncSession) -> int | None:
    """Once per catalogue version (catalog.yaml catalog_version): the followed products linked again against the stored
    advisories – a new catalogue can give a product names (CNA names, CPEs) its stored advisories carry, which only
    new or updated advisories would get linked by otherwise. RELINK_PRODUCTS a round; where it got to is kept (settings
    row RELINK_STATE), so a restart goes on, nothing is done twice; a product relinked already finds nothing new
    (relink skips links that are there). The links it adds are quiet: what appears only through them is the baseline
    – shown, not sent – as a catalogue rollout is no news, and an advisory linked this way is an old one (the round
    links new and updated advisories with the current catalogue anyway). None: nothing (left) to do."""
    version = catalog.catalog_version()
    state = await settings_store.get(db, RELINK_STATE)
    if state.get("version") == version and state.get("complete"):
        return None
    if state.get("version") != version:
        state = {"version": version, "done": [], "complete": False}
    done = set(state.get("done") or [])
    keys = sorted({f.product for f in await follows(db, enabled_only=False) if not f.custom})
    todo = [k for k in keys if k not in done]
    added = 0
    for k in todo[:RELINK_PRODUCTS]:
        if (p := catalog.product(k)) is not None:
            added += await relink(db, p, quiet=True)
        done.add(k)
    state = {"version": version, "done": sorted(done & set(keys)), "complete": len(todo) <= RELINK_PRODUCTS}
    await settings_store.put(db, RELINK_STATE, state)
    await db.commit()
    if added:
        log.info("vendor: catalogue %s – %d stored advisories linked to followed products (quiet)", version, added)
    return added


async def repair_advisory_cves(db: AsyncSession) -> int:
    """Palo Alto advisories stored before 0.1.4 kept only the CVE of their ID, not the others their title names – the
    NVD records of those were judged on their own (an advisory about two PHP CVEs, the second one shown as "possibly
    affected" although the vendor's fixed versions decide it). Run at start; changes nothing once repaired."""
    fixed = 0
    for a in await db.scalars(select(VendorAdvisory).where(VendorAdvisory.source == "paloalto")):
        want = src.pan_cves(a.ident, a.title or "", a.summary or "")
        if want != list(a.cves or []):
            a.cves = want
            fixed += 1
            # its facts are made again from the repaired record (advisory_changes) – the repair is no revision
            await db.execute(delete(VendorAdvisoryState).where(VendorAdvisoryState.advisory_id == a.id))
    if fixed:
        await db.commit()
        bump()
        log.info("vendor: %d Palo Alto advisories now list all their CVEs", fixed)
    return fixed


# ---------------------------------------------------------------- requests


_locks: dict[str, asyncio.Lock] = {}
# a host that answered 429/503 (NVD also 403): no request at all until then – for every caller (the round's other CPEs,
# the story details, the CPE search), not only the query that met it
_blocked: dict[str, float] = {}
BLOCK_DEFAULT = 600.0  # without Retry-After
BLOCK_MAX = 3600.0


def blocked_for(host: str) -> float:
    """Seconds this host is paused for (0: not paused)."""
    return max(0.0, _blocked.get(host, 0.0) - time.monotonic())


async def _gate(host: str, has_key: bool) -> None:
    """The host's minimum gap – one caller at a time (a CPE search during the round waits its turn instead of sending a
    second request into the same gap)."""
    lock = _locks.setdefault(host, asyncio.Lock())
    async with lock:
        if (left := blocked_for(host)) > 0:
            raise NewsError("rate_limited", "paused", timedelta(seconds=left))
        gap = NVD_GAP_KEY if host == "services.nvd.nist.gov" and has_key else GAPS.get(host, 2.0)
        last = max(news_svc._host_last.get(host, -1e9), _last.get(host, -1e9)) if host in SHARED_HOSTS else _last.get(host, -1e9)
        wait = gap - (time.monotonic() - last)
        if wait > 0 and transport is None:
            await asyncio.sleep(wait)
        _last[host] = time.monotonic()
        if host in SHARED_HOSTS:
            news_svc._host_last[host] = time.monotonic()


async def _state(db: AsyncSession, key: str) -> VendorFetch:
    """A query's state; a new one is pending (written with the next release/commit – not flushed into a transaction
    that would then wait on the network)."""
    st = await db.get(VendorFetch, key)
    if st is None:
        st = VendorFetch(key=key[:300], failures=0, items=0)
        db.add(st)
    return st


def _due(st: VendorFetch, now: datetime, force: bool) -> bool:
    if force and not (st.error or "").startswith("rate_limited"):
        return True
    return st.next_fetch_at is None or st.next_fetch_at <= now


def _ok(st: VendorFetch, every: timedelta, items: int | None = None, *, complete: bool = True) -> None:
    """The query worked. The validators of its answer (ETag / Last-Modified, held back by get()) are kept only when
    everything it lists was fetched: written earlier, a later failure or a cap left the rest behind a 304 until the
    feed itself changed (bug hunt 0.1.16 M8)."""
    now = datetime.now(UTC)
    st.failures, st.error, st.last_ok_at, st.next_fetch_at = 0, None, now, now + every
    if items is not None:
        st.items = items
    pending = st.__dict__.pop("_validators", None)
    if pending is not None and complete:
        st.etag, st.last_modified = pending


def _fail(st: VendorFetch, exc: Exception, every: timedelta) -> NewsError:
    if not isinstance(exc, NewsError):
        exc = NewsError("format", type(exc).__name__)
    if exc.category == "rate_limited" and exc.detail == "paused":
        # not asked at all – the host pauses after another query's 429: no failure of this one, just later
        st.next_fetch_at = datetime.now(UTC) + (exc.wait or timedelta(minutes=10))
        st.error = "rate_limited: paused"
        return exc
    st.failures = (st.failures or 0) + 1
    pause = min(every, timedelta(hours=1)) * (2 ** min(st.failures, 6))
    if exc.category == "rate_limited":
        pause = max(pause, exc.wait or timedelta(hours=1))
    st.next_fetch_at = datetime.now(UTC) + min(pause, MAX_BACKOFF)
    st.error = (f"{exc.category}: {exc.detail}" if exc.detail else exc.category)[:200]
    log.info("vendor %s: %s", st.key, st.error)
    return exc


def _record(db: AsyncSession, st: VendorFetch, meter: source_health.Meter, *, exc: Exception | None = None, items: int = 0, parse_errors: int = 0) -> None:
    """The fetch's row for the source health (nothing when it never asked the network – e.g. the host paused)."""
    source_health.record(db, source_health.kind_of(st.key), st.key, ok=exc is None, meter=meter, exc=exc, items=items, parse_errors=parse_errors)


async def get(
    url: str,
    *,
    db: AsyncSession | None = None,
    st: VendorFetch | None = None,
    headers: dict | None = None,
    limit: int = news_svc.MAX_FEED_BYTES,
    has_key: bool = False,
    conditional: bool = True,
    only=None,  # noqa: ANN001
) -> bytes | None:
    """One GET through the news fetcher's hardened download. None: 304 (unchanged). Errors as NewsError. `only`: a check
    of the URL every request – redirects included – must pass (a CSAF provider's own hosts).
    `db`: the caller's session – what it has pending is written first (`release`), so no write transaction waits on
    this host's gap or the download. `st` is updated only after the answer."""
    if db is not None:
        await dbm.release(db)
    host = urlsplit(url).hostname or ""
    await _gate(host, has_key)
    h = {"Accept": "application/json, application/xml;q=0.9, */*;q=0.1", **(headers or {})}
    if st is not None and conditional:
        if st.etag:
            h["If-None-Match"] = st.etag
        if st.last_modified:
            h["If-Modified-Since"] = st.last_modified
    asked = datetime.now(UTC)
    try:
        # a request with the NVD API key follows no redirect: httpx would send the apiKey header to any other host
        # (it strips only Authorization) – NVD's API answers directly (security review 0.1.16 L5)
        keyed = any(k.lower() == "apikey" for k in h)
        got = await news_svc.download(url, proxy=get_config().proxy, verify=tls_verify(), headers=h, limit=limit, transport=transport, follow_redirects=not keyed, only=only)
    finally:
        if st is not None:
            st.last_fetch_at = asked
    if got.status == 304:
        return None
    if got.status in (429, 503) or (got.status == 403 and host == "services.nvd.nist.gov"):
        wait = news_svc._retry_after(got.headers)
        _blocked[host] = time.monotonic() + min(BLOCK_MAX, max(30.0, wait.total_seconds() if wait else BLOCK_DEFAULT))
        raise NewsError("rate_limited", f"HTTP {got.status}", wait)
    if got.status >= 400 or (keyed and 300 <= got.status < 400):
        raise NewsError("http", f"HTTP {got.status}")
    if st is not None and conditional:
        # held back – _ok() writes them when the whole query worked (a store() in between commits the session)
        st.__dict__["_validators"] = ((got.headers.get("etag") or "")[:300] or None, (got.headers.get("last-modified") or "")[:100] or None)
    return got.body


# ---------------------------------------------------------------- one source each


async def sync_paloalto(db: AsyncSession, name: str, every: timedelta, ix: Index, force: bool) -> int | None:
    """Palo Alto's advisories of one product name, newest updated first, until the ones known from the last run."""
    st = await _state(db, f"paloalto:{name}")
    if not _due(st, datetime.now(UTC), force):
        return None
    changed, newest = 0, st.cursor
    skipped: list[str] = []
    meter = source_health.start()
    try:
        for page in range(1, PAN_MAX_PAGES + 1):
            body = await get(src.pan_url(name, page), db=db, st=st if page == 1 else None, conditional=page == 1)
            if body is None:
                break  # 304: nothing changed since the last run
            advs = src.parse_pan(body)
            if not advs:
                break
            newest = max([newest or "", *(a["updated_at"].isoformat() for a in advs if a["updated_at"])]) or newest
            changed += await store(db, advs, ix, skipped)
            if st.cursor and all(a["updated_at"] and a["updated_at"].isoformat() <= st.cursor for a in advs):
                break  # older than what the last run saw – the rest is known
            if len(advs) < 25:
                break
        st.cursor = newest
        _ok(st, every, changed)
        _skipped_note(st, skipped)
        _record(db, st, meter, items=changed)
    except Exception as exc:  # noqa: BLE001 - this source pauses, the others go on
        await db.rollback()
        st = await _state(db, f"paloalto:{name}")
        _record(db, st, meter, exc=_fail(st, exc, every))
    await db.commit()
    return changed


async def sync_fortinet(db: AsyncSession, every: timedelta, ix: Index, force: bool) -> int | None:
    """Fortinet's PSIRT RSS and the CSAF file of every advisory not stored yet (or updated since)."""
    st = await _state(db, "fortinet:rss")
    if not _due(st, datetime.now(UTC), force):
        return None
    changed = 0
    skipped: list[str] = []
    meter = source_health.start()
    try:
        body = await get(src.FORTI_RSS, db=db, st=st)
        if body is not None:
            items = src.parse_forti_rss(body)
            done, complete = 0, True
            for it in items:
                if not it["csaf"]:
                    continue
                known = await db.get(VendorAdvisory, f"fortinet:{it['ident']}")
                if known is not None and it["date"] and known.updated_at and known.updated_at >= it["date"]:
                    continue
                if done >= FORTI_MAX_CSAF:
                    complete = False  # the rest next round – the feed must not answer 304 then
                    continue
                done += 1
                try:
                    raw = await get(it["csaf"], db=db, conditional=False, limit=2 * 1024 * 1024)
                    if raw:
                        changed += await store(db, [src.parse_forti_csaf(raw, it)], ix, skipped)
                except NewsError as exc:
                    if exc.category == "rate_limited":
                        raise  # the whole source pauses – not one refused file after the other
                    complete = False
                    log.info("vendor fortinet %s: %s", it["ident"], exc.category)
            _ok(st, every, changed, complete=complete)
        else:
            _ok(st, every, changed)
        _skipped_note(st, skipped)
        _record(db, st, meter, items=changed)
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        st = await _state(db, "fortinet:rss")
        _record(db, st, meter, exc=_fail(st, exc, every))
    await db.commit()
    return changed


async def sync_veeam(db: AsyncSession, every: timedelta, ix: Index, force: bool) -> int | None:
    """Veeam's security KB feed (one request, conditional when the server sends ETag / Last-Modified): every KB
    article with its affected and fixed builds. Only articles that changed are written (store compares)."""
    st = await _state(db, "veeam:feed")
    if not _due(st, datetime.now(UTC), force):
        return None
    changed = 0
    meter = source_health.start()
    try:
        body = await get(src.VEEAM_FEED, db=db, st=st, headers={"Accept": "application/atom+xml, application/xml;q=0.9, */*;q=0.1"})
        if body is not None:
            advs = await asyncio.to_thread(src.parse_veeam, body)
            skipped: list[str] = []
            changed = await store(db, advs, ix, skipped)
            _ok(st, every, len(advs))
            _skipped_note(st, skipped)
        else:
            _ok(st, every)
        _record(db, st, meter, items=changed)
    except Exception as exc:  # noqa: BLE001 - this source pauses, the others go on
        await db.rollback()
        st = await _state(db, "veeam:feed")
        _record(db, st, meter, exc=_fail(st, exc, every))
    await db.commit()
    return changed


NVD_WINDOW_MAX = 20000  # records changed in one window: paged through completely up to this, else a full fetch next time
NVD_FULL_EVERY = timedelta(days=7)  # a full fetch: what NVD no longer lists for the CPE (rejected, CPE removed) goes


async def drop_advisories(db: AsyncSession, ids: list[str], *, withdrawn: bool = True) -> int:
    """Records NVD rejected (cvelistV5 too, OSV withdrew): no advisory any more – removed with their links. `withdrawn`:
    the source took it back – a last revision says so (advisory_changes; False: it only no longer says anything we can
    use)."""
    if not ids:
        return 0
    links = (await db.execute(select(VendorAdvisoryProduct.product, VendorAdvisoryProduct.advisory_id).where(VendorAdvisoryProduct.advisory_id.in_(ids)))).all()
    touched = {p for p, _ in links}
    if withdrawn:
        # a watched CVE (CVE beobachten): its advisory withdrawn – said before the record goes
        gone = (await db.execute(select(VendorAdvisory.id, VendorAdvisory.source, VendorAdvisory.ident, VendorAdvisory.title, VendorAdvisory.cves).where(VendorAdvisory.id.in_(ids)))).all()
        await cve_watch.withdrawn(db, [tuple(r) for r in gone])
    if withdrawn and links:
        linked: dict[str, set[str]] = {}
        for p, aid in links:
            linked.setdefault(aid, set()).add(p)
        await _side_changes(db, list(linked), linked, lambda a: [{"f": "withdrawn"}], gone=True)
    await db.execute(delete(VendorAdvisoryProduct).where(VendorAdvisoryProduct.advisory_id.in_(ids)))
    n = (await db.execute(delete(VendorAdvisory).where(VendorAdvisory.id.in_(ids)))).rowcount or 0
    await db.commit()
    if touched:
        bump(touched)
    return int(n)


async def _side_changes(db: AsyncSession, ids: list[str], linked: dict[str, set[str]], what, *, gone: bool = False) -> int:  # noqa: ANN001
    """A revision of stored advisories that does not come with a new record: withdrawn (`gone` – no data afterwards) or
    listed in CISA's KEV. `what(advisory)` → its diff entries (none: no revision). Written with the caller's transaction."""
    targets = await change_targets(db)
    advs = list(await db.scalars(select(VendorAdvisory).where(VendorAdvisory.id.in_(ids))))
    states = {s.advisory_id: s for s in await db.scalars(select(VendorAdvisoryState).where(VendorAdvisoryState.advisory_id.in_(ids)))}
    now = datetime.now(UTC)
    n = 0
    for a in advs:
        entries = what(a)
        if not entries:
            continue
        keys = sorted(linked.get(a.id) or set())
        tg = [targets[k] for k in keys if k in targets]
        impact, relevant = await asyncio.to_thread(changes_svc.impacts, tg, a.source, a.data or {}, None if gone else a.data or {}) if tg else ([], set())
        st = states.get(a.id)
        revision = (st.revision if st is not None else 1) + 1
        row = {"id": a.id, "source": a.source, "ident": a.ident, "title": a.title, "url": a.url, "severity": a.severity, "cves": a.cves or [], "data": a.data or {}}
        await changes_svc.record(db, row, revision=revision, changes=entries, impact=impact, products=keys, targets=tg, relevant=relevant, now=now)
        if not gone:
            facts = st.facts if st is not None and st.facts.get("v") == changes_svc.EXTRACT_V else _stamped(changes_svc.facts_of(a.source, a.severity, a.cvss, a.cves, a.data), a.source)
            values = {"advisory_id": a.id, "facts": facts, "revision": revision, "changed_at": now}
            await db.execute(pg_insert(VendorAdvisoryState).values(**values).on_conflict_do_update(index_elements=["advisory_id"], set_={"revision": revision, "changed_at": now}))
        n += 1
    return n


KEV_CHANGES_MAX = 300  # more new KEV entries at once: the catalogue was reloaded (not news) – no revisions


async def _kev_changes(db: AsyncSession, added: list[dict]) -> int:
    """New entries in CISA's KEV: a revision of each stored advisory naming one of their CVEs."""
    by_cve = {r["cve"]: r for r in added}
    rows = (
        await db.execute(
            select(VendorAdvisory.id, VendorAdvisory.cves)
            .where(VendorAdvisory.cves.op("?|")(pg_array(list(by_cve))))
            .where(VendorAdvisory.id.in_(select(VendorAdvisoryProduct.advisory_id)))
        )
    ).all()
    if not rows:
        return 0
    ids = [aid for aid, _ in rows]
    linked: dict[str, set[str]] = {}
    for p, aid in (await db.execute(select(VendorAdvisoryProduct.product, VendorAdvisoryProduct.advisory_id).where(VendorAdvisoryProduct.advisory_id.in_(ids)))).all():
        linked.setdefault(aid, set()).add(p)

    def what(a: VendorAdvisory) -> list[dict]:
        return [{"f": "kev", "cve": c, "added": by_cve[c].get("date_added") or "", "ransomware": bool(by_cve[c].get("ransomware"))} for c in a.cves or [] if c in by_cve][:5]

    return await _side_changes(db, ids, linked, what)


def cpe_key(cpe: str) -> str:
    """vendor:product of a catalogue CPE (part:vendor:product) without NVD's escapes – an escaped colon stays inside its
    field (a:mailcow:mailcow\\:_dockerized → mailcow:mailcow:_dockerized), the way the advisories' CPEs are read."""
    return ":".join(re.split(r"(?<!\\):", cpe)[1:3]).replace("\\", "")


async def _unlisted(db: AsyncSession, cpe: str, ix: Index, got: list[dict], complete: bool) -> int:
    """After a full fetch: stored NVD records of this CPE that NVD no longer lists for it (its configuration changed, the
    CPE was removed) – within the time the fetch covers – lose the links of the products that have this CPE. A record
    linked to nothing else goes. Never more than a tenth of what came back (an odd answer must not empty a product)."""
    plain = cpe.replace("\\", "")
    keys = [p["key"] for p in ix.by_cpe.get(cpe_key(cpe), [])]
    if not keys or not got:
        return 0
    seen = {a["id"] for a in got}
    oldest = None if complete else min((a["published_at"] for a in got if a.get("published_at")), default=None)
    stmt = (
        select(VendorAdvisory.id, cast(VendorAdvisory.data, Text))
        .join(VendorAdvisoryProduct, VendorAdvisoryProduct.advisory_id == VendorAdvisory.id)
        .where(VendorAdvisory.source == "nvd", VendorAdvisoryProduct.product.in_(keys))
        .distinct()
    )
    if oldest is not None:
        stmt = stmt.where(VendorAdvisory.published_at >= oldest)
    pattern = f"cpe:2.3:{plain}:"
    gone = [aid for aid, raw in (await db.execute(stmt)).all() if aid not in seen and pattern in (raw or "").replace("\\", "")]
    if not gone:
        return 0
    if len(gone) > max(20, len(seen) // 10):
        log.warning("vendor nvd:%s: %d stored records not listed any more – too many, left as they are", cpe, len(gone))
        return 0
    for i in range(0, len(gone), 500):
        part = gone[i : i + 500]
        await db.execute(delete(VendorAdvisoryProduct).where(VendorAdvisoryProduct.advisory_id.in_(part), VendorAdvisoryProduct.product.in_(keys)))
    orphans = [aid for aid in gone if not await db.scalar(select(VendorAdvisoryProduct.advisory_id).where(VendorAdvisoryProduct.advisory_id == aid).limit(1))]
    if orphans:
        await db.execute(delete(VendorAdvisory).where(VendorAdvisory.id.in_(orphans)))
    await db.commit()
    bump(set(keys))
    log.info("vendor nvd:%s: %d records no longer listed by NVD – unlinked", cpe, len(gone))
    return len(gone)


async def sync_nvd_cpe(db: AsyncSession, cpe: str, every: timedelta, ix: Index, key: str, force: bool) -> int | None:
    """All CVEs of one CPE (part:vendor:product): the first time (and weekly) the newest NVD_MAX_RESULTS, in between
    every record NVD changed since the last run (lastModStartDate, all pages of the window – none left out). Rejected
    records are removed; after a full fetch, records NVD no longer lists for the CPE are unlinked."""
    st = await _state(db, f"nvd:{cpe}")
    now = datetime.now(UTC)
    if not _due(st, now, force):
        return None
    match = f"cpe:2.3:{cpe}"
    has_key = bool(key)
    headers = {"apiKey": key} if key else {}
    changed = 0
    meter = source_health.start()

    async def page(start: int, window: dict, rejected: list[str]) -> tuple[int, list[dict]]:
        body = await get(src.nvd_url(virtualMatchString=match, resultsPerPage=src.NVD_PAGE, startIndex=start, **window), db=db, headers=headers, limit=NVD_LIMIT, has_key=has_key, conditional=False)
        return await asyncio.to_thread(src.parse_nvd, body or b'{"vulnerabilities": []}', rejected)

    try:
        since = datetime.fromisoformat(st.cursor) if st.cursor else None
        full = since is None or now - since >= timedelta(days=119) or st.full_at is None or now - st.full_at >= NVD_FULL_EVERY
        window = {} if full else {"lastModStartDate": src.nvd_time(since - timedelta(minutes=5)), "lastModEndDate": src.nvd_time(now)}
        rejected: list[str] = []
        total, advs = await page(0, window, rejected)
        complete = total <= len(advs)
        if window and total > NVD_WINDOW_MAX:
            full, window, complete = True, {}, False  # more than a window should ever hold: the newest records instead
            total, advs = await page(0, {}, rejected)
        if total > len(advs):
            if window:
                # changed records: every page – none is thrown away, none left out (the cursor moves on only after all)
                for s in range(len(advs), total, src.NVD_PAGE):
                    advs += (await page(s, window, rejected))[1]
                complete = True
            else:
                # newest first: NVD lists oldest first – take the last pages, at most NVD_MAX_RESULTS records
                starts = list(range(max(0, total - NVD_MAX_RESULTS), total, src.NVD_PAGE))
                starts = [s for s in starts if s != 0][-((NVD_MAX_RESULTS // src.NVD_PAGE)) :]
                if total > NVD_MAX_RESULTS:
                    advs = []  # the first page holds the oldest ones – not kept when there are more than the cap
                complete = total <= NVD_MAX_RESULTS
                for s in reversed(starts):
                    advs += (await page(s, {}, rejected))[1]
        listed = advs  # what the full fetch listed – the base for _unlisted
        if full and not complete and since is not None and now - since < timedelta(days=119):
            # the full fetch holds only the newest NVD_MAX_RESULTS: what NVD changed since the last run among the older
            # records comes from the window as usual – else the cursor moved past those changes (bug hunt 0.1.16 M9)
            win = {"lastModStartDate": src.nvd_time(since - timedelta(minutes=5)), "lastModEndDate": src.nvd_time(now)}
            wtotal, wadvs = await page(0, win, rejected)
            for s in range(len(wadvs), min(wtotal, NVD_WINDOW_MAX), src.NVD_PAGE):
                wadvs += (await page(s, win, rejected))[1]
            advs = list({a["id"]: a for a in [*advs, *wadvs]}.values())
        known = set(await db.scalars(select(VendorAdvisory.id).where(VendorAdvisory.id.in_([a["id"] for a in advs])))) if window and advs else set()
        skipped: list[str] = []
        changed = await store(db, advs, ix, skipped)
        await drop_advisories(db, rejected)
        if full and st.full_at is not None:
            await _unlisted(db, cpe, ix, listed, complete)  # not on the very first fetch: nothing stored to compare yet
        st = await _state(db, f"nvd:{cpe}")
        st.cursor = now.isoformat()
        if full:
            st.full_at = now
        # records of the CPE: all on a full fetch, plus the new ones of a window (not the changed ones again)
        _ok(st, every, total if full else (st.items or 0) + len([a for a in advs if a["id"] not in known]))
        _skipped_note(st, skipped)
        _record(db, st, meter, items=changed)
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        st = await _state(db, f"nvd:{cpe}")
        _record(db, st, meter, exc=_fail(st, exc, every))
    await db.commit()
    return changed


async def sync_nvd_keyword(db: AsyncSession, product: dict, every: timedelta, ix: Index, key: str, force: bool) -> int | None:
    """New CVEs NVD has not analysed yet (no CPEs – a growing backlog): a keyword search of the last days, kept only
    where the CNA's affected data names the product."""
    words = _keyword_words(product)
    if not words:
        return None
    st = await _state(db, f"nvdkw:{product['key']}")
    now = datetime.now(UTC)
    if not _due(st, now, force):
        return None
    meter = source_health.start()
    try:
        body = await get(
            src.nvd_url(keywordSearch=words, pubStartDate=src.nvd_time(now - timedelta(days=KEYWORD_DAYS)), pubEndDate=src.nvd_time(now), resultsPerPage=src.NVD_PAGE),
            db=db,
            headers={"apiKey": key} if key else {},
            limit=NVD_LIMIT,
            has_key=bool(key),
            conditional=False,
        )
        _, advs = await asyncio.to_thread(src.parse_nvd, body or b'{"vulnerabilities": []}')
        # only records that concern a catalogue product (the CNA names it) – "PHP" finds every WordPress plugin too
        keep = await asyncio.to_thread(lambda: [a for a in advs if link(a, ix)])
        skipped: list[str] = []
        changed = await store(db, keep, ix, skipped)
        _ok(st, every, len(keep))
        _skipped_note(st, skipped)
        _record(db, st, meter, items=changed)
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        st = await _state(db, f"nvdkw:{product['key']}")
        _record(db, st, meter, exc=_fail(st, exc, every))
        changed = 0
    await db.commit()
    return changed


async def kev_every(db: AsyncSession) -> timedelta:
    cfg = await config(db)
    return timedelta(hours=max(6, int(cfg.get("eol_every_h") or 24)))


async def kev_wanted(db: AsyncSession) -> bool:
    """Whether the KEV catalogue is fetched: for Vendor News' findings (switched on, something followed) – and for the
    news' topics ("Aktiv ausgenutzt" by CVE) while the news are switched on, also with nothing followed."""
    cfg = await config(db)
    if cfg.get("enabled", True) and await db.scalar(select(VendorFollow.product).where(VendorFollow.enabled.is_(True)).limit(1)) is not None:
        return True
    return bool((await news_svc.config(db)).get("enabled"))


async def _kev_by_news(db: AsyncSession) -> bool:
    """The news fetch the KEV (source cisa-kev switched on and healthy): one download feeds both (news.fetch_source →
    kev_received) – this fetch waits. A failing source (refused, the mirror too): Vendor News asks itself, daily."""
    if not (await news_svc.config(db)).get("enabled"):
        return False
    s = await db.scalar(select(NewsSource).where(NewsSource.key == news_svc.KEV_KEY))
    return s is not None and s.enabled and not s.failures


async def kev_store(db: AsyncSession, body: bytes) -> tuple[int, list[dict], bool]:
    """The whole catalogue from one KEV download: vendor_kev replaced; newly listed CVEs → a revision of the advisories
    naming them (not on the first fetch – the whole catalogue) and the topics of the stories naming them (on the first
    fetch: every story again, by the background job). (entries, newly listed, first fetch) – in the caller's transaction."""
    rows = await asyncio.to_thread(src.parse_kev, body)
    known = set(await db.scalars(select(VendorKev.cve)))
    await db.execute(delete(VendorKev))
    if rows:
        await db.execute(pg_insert(VendorKev).on_conflict_do_nothing(), rows)
    added = [r for r in rows if r["cve"] not in known] if known else []
    if 0 < len(added) <= KEV_CHANGES_MAX:
        await _kev_changes(db, added)
    if not known and rows:
        await news_svc.topics_again(db)
    elif added:
        await news_svc.retopic_cves(db, [r["cve"] for r in added])
    return len(rows), added, not known


async def kev_received(db: AsyncSession, body: bytes) -> int:
    """The news fetched the KEV (200): the same body is Vendor News' catalogue – no second download. Its state counts as
    fetched (the daily fetch of its own waits a day)."""
    st = await _state(db, "kev")
    before = st.items or 0
    n, _, _ = await kev_store(db, body)
    _ok(st, await kev_every(db), n)
    st.last_fetch_at = datetime.now(UTC)
    st.error = None
    await db.commit()
    bump()
    log.debug("vendor kev: %d entries from the news fetch (%+d)", n, n - before)
    return n


async def kev_checked(db: AsyncSession) -> None:
    """The news' KEV fetch answered 304: the catalogue is current – the state says so, the own fetch waits."""
    st = await _state(db, "kev")
    _ok(st, await kev_every(db))
    st.last_fetch_at = datetime.now(UTC)
    await db.commit()


async def sync_kev(db: AsyncSession, every: timedelta, force: bool) -> int | None:
    """CISA's KEV, daily – unless the news fetch it already (source cisa-kev on and healthy, see _kev_by_news). After
    a 403 of www.cisa.gov (bot protection) the same JSON from CISA's mirror on GitHub."""
    st = await _state(db, "kev")
    if not _due(st, datetime.now(UTC), force) or await _kev_by_news(db):
        return None
    meter = source_health.start()
    try:
        before = st.items or 0
        try:
            body = await get(src.KEV_URL, db=db, st=st, limit=news_svc.KEV_LIMIT)
        except NewsError as exc:
            if exc.detail != "HTTP 403":
                raise
            log.info("vendor kev: www.cisa.gov refused (403) – the catalogue from CISA's mirror on GitHub")
            body = await get(news_svc.KEV_MIRROR, db=db, st=st, limit=news_svc.KEV_LIMIT)
        if body is not None:
            n, _, _ = await kev_store(db, body)
            _ok(st, every, n)
            _record(db, st, meter, items=max(0, n - before) if before else 0)  # new entries (not the whole catalogue the first time)
            bump()
        else:
            _ok(st, every)
            _record(db, st, meter)
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        st = await _state(db, "kev")
        _record(db, st, meter, exc=_fail(st, exc, every))
    await db.commit()
    return 0


async def sync_eol(db: AsyncSession, every: timedelta, force: bool) -> int | None:
    """endoflife.date's full product list (one request, ~3 MB): the catalogue with fresh release lines and dates."""
    st = await _state(db, "eol")
    if not _due(st, datetime.now(UTC), force):
        return None
    meter = source_health.start()
    try:
        had = st.items or 0
        body = await get(src.EOL_FULL, db=db, st=st, limit=16 * 1024 * 1024)
        if body is not None:
            eol = await asyncio.to_thread(src.parse_eol, body)
            cat = await asyncio.to_thread(catalog.build, eol)
            before = {f.product: _match_sig(p) for f in await follows(db, enabled_only=False) if not f.custom and (p := catalog.product(f.product))}
            await asyncio.to_thread(catalog.save_refreshed, cat)
            _ok(st, every, len(cat["products"]))
            _record(db, st, meter, items=max(0, len(cat["products"]) - had) if had else 0)
            await db.commit()
            bump()
            # a followed product with new CPEs or names: the stored advisories that concern it now are linked –
            # quietly, as after a catalogue update (relink_catalog): old advisories found anew are no news
            for key, sig in before.items():
                if (p := catalog.product(key)) is not None and _match_sig(p) != sig:
                    await relink(db, p, quiet=True)
        else:
            _ok(st, every)
            _record(db, st, meter)
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        st = await _state(db, "eol")
        _record(db, st, meter, exc=_fail(st, exc, every))
    await db.commit()
    return 0


def _match_sig(p: dict) -> tuple:
    """What linking a product depends on (a catalogue refresh may change it)."""
    return (tuple(p.get("cpes") or []), tuple(p.get("names") or []), tuple(map(tuple, p.get("cna") or [])), p.get("adv"))


def fetch_keys(product: dict, cfg: dict | None = None) -> list[str]:
    """The queries a followed product needs – their state says whether it was fetched once (baseline). `cfg`: the
    settings (the CSAF providers of its vendor only while they are switched on)."""
    keys = []
    if cfg is None or cfg.get("csaf", True):
        from app import csaf_providers

        keys += [f"csaf:{x['key']}" for x in csaf_providers.providers_for(product)]
    if product.get("adv") == "paloalto":
        keys += [f"paloalto:{n}" for n in product.get("names") or []]
    if product.get("adv") == "fortinet":
        keys.append("fortinet:rss")
    if product.get("adv") == "veeam":
        keys.append("veeam:feed")
    if product.get("scheme") not in ("distro",):
        keys += [f"nvd:{c}" for c in product.get("cpes") or []]
    return keys


def _keyword_words(product: dict) -> str | None:
    return (product.get("kw") or [product.get("label")])[0]


def _keyword_search(product: dict) -> bool:
    """Whether the round asks NVD's keyword search for the product (CVEs not analysed yet)."""
    return product.get("scheme") not in ("distro", "cloud") and bool(product.get("cna") or product.get("cpes")) and bool(_keyword_words(product))


async def active_keys(db: AsyncSession) -> set[str]:
    """The queries the round asks now (the source health: anything else in vendor_fetch is switched off – a product no
    longer followed, Vendor News off). As run_round: nothing at all while nothing is followed."""
    cfg = await config(db)
    kev = {"kev"} if await kev_wanted(db) else set()
    if not cfg.get("enabled", True):
        return kev
    from app import epss

    products = [p for f in await follows(db) if (p := product_of(f))]
    # EPSS: for the findings – and the CVEs of the stories, while their details are fetched (epss.wanted)
    extra = {epss.KEY} if cfg.get("epss", True) and (products or await epss.stories_on(db)) else set()
    if not products:
        return extra | kev
    keys = {"kev", "eol"}
    for p in products:
        keys.update(k[:300] for k in fetch_keys(p, cfg))
        if _keyword_search(p):
            keys.add(f"nvdkw:{p['key']}"[:300])
    from app import csaf_providers, cvelist, osv

    if cfg.get("csaf", True) and any(k.startswith("csaf:") for k in keys):
        keys.add(csaf_providers.AGGREGATOR_KEY)
    if cfg.get("cvelist", True):
        keys |= {cvelist.DELTA_KEY, cvelist.SINGLE_KEY}
    if cfg.get("osv", True) and any(p.get("osv") for p in products):
        keys.add(osv.KEY)
    return keys | extra


async def run_round(*, force: bool = False, only: str | None = None) -> dict:
    """What is due: KEV and endoflife.date daily, then per followed product its advisories and CVEs. `only`: the
    catalogue alone (admin's "Katalog aktualisieren")."""
    out: dict[str, int] = {}
    async with dbm.session() as db:
        cfg = await config(db)
        every = timedelta(hours=max(1, int(cfg.get("every_h") or 6)))
        eol_every = timedelta(hours=max(6, int(cfg.get("eol_every_h") or 24)))
        if only == "catalog":
            # the admin's "Katalog aktualisieren": also while Vendor News is switched off (the API said "ok")
            await sync_eol(db, eol_every, True)
            return {"catalog": 1}
        # the KEV also with nothing followed (or Vendor News off) while the news are on: their topics need it
        if await kev_wanted(db):
            await sync_kev(db, eol_every, force)
        if not cfg.get("enabled", True):
            return out
        fs = await follows(db)
        if not fs:
            return out  # nothing followed: no other request
        products = [p for f in fs if (p := product_of(f))]
        # every query's state in one read, held for the round: _state() then finds it in the session instead of asking
        # the database once per query (the session keeps loaded rows only while somebody holds them)
        held = list(await db.scalars(select(VendorFetch)))
        ix = await current_index(db)
        key = nvd_key(cfg)
        await sync_eol(db, eol_every, False)
        try:
            if (r := await relink_catalog(db)) is not None:
                out["relink:catalog"] = r
        except Exception:  # noqa: BLE001 - the relink never stops the round; it goes on next round
            await db.rollback()
            log.exception("vendor: relinking after the catalogue change failed")
        names = list(dict.fromkeys(n for p in products if p.get("adv") == "paloalto" for n in p.get("names") or []))
        for n in names:
            if (r := await sync_paloalto(db, n, every, ix, force)) is not None:
                out[f"paloalto:{n}"] = r
        if any(p.get("adv") == "fortinet" for p in products):
            if (r := await sync_fortinet(db, every, ix, force)) is not None:
                out["fortinet"] = r
        if any(p.get("adv") == "veeam" for p in products):  # only with a Veeam product followed
            if (r := await sync_veeam(db, every, ix, force)) is not None:
                out["veeam"] = r
        cpes = list(dict.fromkeys(c for p in products if p.get("scheme") not in ("distro",) for c in p.get("cpes") or []))
        for c in cpes:
            if blocked_for("services.nvd.nist.gov"):
                break  # NVD refused (429): the other CPEs wait for the next round instead of asking into the pause
            if (r := await sync_nvd_cpe(db, c, every, ix, key, force)) is not None:
                out[f"nvd:{c}"] = r
                if not (await config(db)).get("enabled", True):
                    break  # switched off while that one was fetched
        for p in products:
            if not _keyword_search(p):
                continue
            if blocked_for("services.nvd.nist.gov"):
                break
            await sync_nvd_keyword(db, p, every, ix, key, force)
        out |= await sync_structured(db, cfg, products, every, ix, force)
        del held
    return out


async def sync_structured(db: AsyncSession, cfg: dict, products: list[dict], every: timedelta, ix: Index, force: bool) -> dict[str, int]:
    """The structured sources of the round (each switchable in the settings): the CSAF providers of the followed vendors,
    cvelistV5's hourly delta and the CVE records findings still lack (the NVD has not analysed them). EPSS and OSV come
    after the round (VendorLoop.round): they need the findings."""
    from app import csaf_providers, cvelist

    out: dict[str, int] = {}
    green = csaf_providers.green_allowed(cfg)
    try:
        # TLP:GREEN of a provider no longer allowed to bring it: gone before anything else is read (also with CSAF off)
        if n := await csaf_providers.purge_green(db, green):
            out["csaf:tlp_green_removed"] = n
    except Exception:  # noqa: BLE001 - tried again next round
        await db.rollback()
        log.exception("vendor: removing TLP:GREEN advisories failed")
    if cfg.get("csaf", True):
        for k, n in (await csaf_providers.sync_all(db, products, every, ix, force, green)).items():
            out[k] = n
    if cfg.get("cvelist", True):
        if (r := await cvelist.sync_delta(db, products, ix, force)) is not None:
            out[cvelist.DELTA_KEY] = r
        if (r := await cvelist.backfill(db, products, ix, force)) is not None:
            out[cvelist.SINGLE_KEY] = r
    return out


# ---------------------------------------------------------------- evaluation


SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


async def kev_index(db: AsyncSession) -> dict[str, VendorKev]:
    return {k.cve: k for k in await db.scalars(select(VendorKev))}


async def euvd_cves(db: AsyncSession) -> set[str]:
    """CVEs ENISA's EUVD lists as exploited – from the news (source enisa-euvd, if switched on): its own stories and
    those of the CISA KEV it carries too (the same CVE is one story, "also in")."""
    out: set[str] = set()
    euvd = await db.scalar(select(NewsSource.id).where(NewsSource.key == "enisa-euvd"))
    if euvd is None:
        return out
    # its own stories and those it carries: two index lookups (an OR of both would read every story)
    own = select(NewsItem.cves).where(NewsItem.source_id == euvd)
    carried = select(NewsItem.cves).join(NewsItemSource, NewsItemSource.item_id == NewsItem.id).where(NewsItemSource.source_id == euvd)
    for cves in await db.scalars(own.union_all(carried)):
        out.update(str(c).upper() for c in cves or [])
    return out


def stored_v(product: dict, text: str | None) -> V | None:
    """A stored version as the evaluation compares it (app/version_input.effective: "2019 CU15" for Exchange is
    15.2.1748; a version the product's rules refuse is None)."""
    eff = version_input.effective(product, text) if text else None
    return parse(product.get("scheme") or "generic", eff) if eff else None


# "unklare Altdaten": a "possible" whose reason is unclear data (no version bound, a list without the version, a line the
# data does not name, a version text of the source we cannot compare) – not one about the installed version itself –
# for a CVE published at least STALE_MARGIN before the installed release line came out (CVE-2009-3631 for TYPO3 13.4.37).
# Shown folded in the drawer, never counted, never notified. Exploited CVEs are never folded.
STALE_MARGIN = timedelta(days=365)
UNCLEAR = frozenset({"all_versions", "no_version", "not_listed", "line_not_listed", "unparsed_data"})


_SLOT = {"nvd": "nvd", "cvelist": "cve", "osv": "osv"}


def groups_of(advs: list[VendorAdvisory]) -> list[dict]:
    """One group per vulnerability: a vendor advisory with the CVE records of its CVEs (NVD, cvelistV5, OSV), or the
    CVE records of one CVE alone (NVD first, else cvelistV5)."""
    vendor = [a for a in advs if a.source not in CVE_SOURCES]
    groups: list[dict] = []
    by_cve: dict[str, dict] = {}
    for a in sorted(vendor, key=lambda x: x.published_at or datetime.min.replace(tzinfo=UTC)):
        g = {"primary": a, "nvd": [], "cve": [], "osv": []}
        groups.append(g)
        for c in a.cves or []:
            by_cve.setdefault(c, g)
    for src_ in CVE_SOURCES:  # NVD before cvelistV5 before OSV: the first record of a CVE without vendor advisory leads
        for a in advs:
            if a.source != src_:
                continue
            g = by_cve.get(a.ident)
            if g is None:
                g = by_cve[a.ident] = {"primary": a, "nvd": [], "cve": [], "osv": []}
                groups.append(g)
            elif g["primary"] is not a:
                g[_SLOT[src_]].append(a)
    return groups


def _first(xs: list, ident: str):  # noqa: ANN202
    return next((x for x in xs if x.ident == ident), None)


def cve_verdict(product: dict, nvd, cvl, osv, text: str | None) -> Verdict | None:  # noqa: ANN001
    """One CVE judged by its CVE records: the NVD where it analysed the CVE (CPE configurations); cvelistV5 (the CNA's
    current data, else CISA's ADP) where the NVD has no configuration or no record; the NVD's copy of the CNA data last.
    OSV (open-source packages) where these leave it open: it decides a "possibly" and names a missing fixed version."""
    r = None
    analysed = nvd is not None and bool((nvd.data or {}).get("configs"))
    if analysed:
        r = evaluate(product, "nvd", nvd.data or {}, text)
    if r is None and cvl is not None:
        r = evaluate(product, "cvelist", cvl.data or {}, text)
    if r is None and nvd is not None and not analysed:
        r = evaluate(product, "nvd", nvd.data or {}, text)
    if osv is not None and (r is None or r.status == "possible" or (r.status == "affected" and not r.fixed)):
        o = evaluate(product, "osv", osv.data or {}, text)
        if o is not None:
            if r is None or (r.status == "possible" and o.status in ("affected", "not_affected")):
                r = o
            elif r.status == "affected" and o.status == "affected" and o.fixed:
                r = Verdict(r.status, r.reason, o.fixed, r.detail)
    return r


def _cve_records(g: dict) -> dict[str, tuple]:
    """Per CVE of a group its records (NVD, cvelistV5, OSV) – computed once per group."""
    if (hit := g.get("_recs")) is not None:
        return hit
    out: dict[str, tuple] = {}
    for c in dict.fromkeys(x.ident for k in ("nvd", "cve", "osv") for x in g[k]):
        out[c] = (_first(g["nvd"], c), _first(g["cve"], c), _first(g["osv"], c))
    g["_recs"] = out
    return out


def group_verdict(product: dict, g: dict, text: str | None) -> Verdict | None:
    """The verdict of one vulnerability for one version: the vendor decides; its CVE records (cve_verdict) only where the
    vendor's data does not. (Called very often by target_versions: the common groups – an NVD record alone, a vendor
    advisory with NVD records only – take the short way they always took.)"""
    a: VendorAdvisory = g["primary"]
    if not (g["cve"] or g["osv"]):
        verdict = evaluate(product, a.source, a.data or {}, text)
        if a.source == "nvd" or not g["nvd"]:
            return verdict
        extra = None
        for n in g["nvd"]:
            r = evaluate(product, "nvd", n.data or {}, text)
            extra = r if extra is None or (r and ORDER[r.status] > ORDER[extra.status]) else extra
        if verdict is None or (verdict.status not in ("affected", "not_affected") and extra is not None and ORDER[extra.status] > ORDER[verdict.status]):
            verdict = extra or verdict
        return verdict
    if a.source in CVE_SOURCES:
        nvd = a if a.source == "nvd" else None
        cvl = a if a.source == "cvelist" else _first(g["cve"], a.ident)
        osv = a if a.source == "osv" else _first(g["osv"], a.ident)
        return cve_verdict(product, nvd, cvl, osv, text)
    verdict = evaluate(product, a.source, a.data or {}, text)
    extra = None
    for n, c, o in _cve_records(g).values():
        r = cve_verdict(product, n, c, o, text)
        extra = r if extra is None or (r and ORDER[r.status] > ORDER[extra.status]) else extra
    if verdict is None or (verdict.status not in ("affected", "not_affected") and extra is not None and ORDER[extra.status] > ORDER[verdict.status]):
        verdict = extra or verdict
    return verdict


def _day(text: str | None) -> date | None:
    try:
        return date.fromisoformat(str(text or "")[:10])
    except ValueError:
        return None


def findings(
    product: dict, advs: list[VendorAdvisory], versions: list[VendorVersion], kev: dict, euvd: set[str], groups: list[dict] | None = None, epss: dict | None = None
) -> list[dict]:
    """One row per vulnerability (a vendor advisory with the CVE records of its CVEs, or the records of one CVE alone),
    with a verdict per followed version – or "unversioned" when the product has no version. `epss`: CVE → score row."""
    groups = groups if groups is not None else groups_of(advs)
    epss = epss or {}
    out = []
    targets: list[tuple[VendorVersion | None, str | None]] = [(v, v.version) for v in versions] or [(None, None)]
    lines = {text: line_of(product, text) for _, text in targets if text}
    for g in groups:
        a: VendorAdvisory = g["primary"]
        others = [*g["nvd"], *g["cve"], *g["osv"]] if g["cve"] or g["osv"] else g["nvd"]
        cves = list(dict.fromkeys([*(a.cves or []), *(c for n in others for c in n.cves or [])])) if others else list(dict.fromkeys(a.cves or []))
        all_advs = [a, *others]
        k = next((kev[c] for c in cves if c in kev), None)
        exploited = bool(k) or any(x.exploited for x in all_advs) or any(c in euvd for c in cves)
        first_pub = min((x.published_at for x in all_advs if x.published_at), default=None)
        rows = []
        for ver, text in targets:
            verdict = group_verdict(product, g, text)
            if verdict is None:
                continue
            if verdict.status == "possible" and verdict.reason in UNCLEAR and not exploited and text and first_pub is not None:
                line = lines.get(text)
                released = _day(line.get("releaseDate")) if line else None
                if released is not None and first_pub.date() <= released - STALE_MARGIN:
                    verdict = Verdict("stale", "predates_line", verdict.fixed, {"line": str(line["name"]), "released": released.isoformat()})
            rows.append((ver, text, verdict))
        if not rows:
            continue
        cvss = max((x.cvss for x in all_advs if x.cvss is not None), default=None)
        sev = max((x.severity for x in all_advs), key=lambda s: SEV_RANK.get(s, 0))
        if exploited and SEV_RANK.get(sev, 0) < SEV_RANK["high"]:
            sev = "high"
        worst = max((r[2] for r in rows), key=lambda v: ORDER[v.status])
        data = a.data or {}
        top = max((epss[c] for c in cves if c in epss and epss[c].get("score") is not None), key=lambda e: e["score"], default=None) if epss else None
        ssvc = next(((x.data or {}).get("ssvc") for x in (a, *g["cve"]) if x.source == "cvelist" and (x.data or {}).get("ssvc")), None) if g["cve"] or a.source == "cvelist" else None
        out.append(
            {
                "id": a.id,
                "source": a.source,
                "ident": a.ident,
                "title": a.title,
                "headline": titles.headline(a.source, a.title or "", data.get("desc") or a.summary or "", data.get("cwe"), product.get("label") or ""),
                "summary": a.summary,
                "url": a.url,
                "also": [{"source": n.source, "ident": n.ident, "url": n.url} for n in others][:6],
                "cves": cves[:30],
                "cvss": cvss,
                "severity": sev,
                "exploited": exploited,
                "kev": {"added": k.date_added, "due": k.due, "ransomware": k.ransomware} if k else None,
                "euvd": any(c in euvd for c in cves),
                # FIRST EPSS: the CVE of the group most likely to be exploited in the next 30 days (epss.py)
                "epss": {"cve": top["cve"], "score": top["score"], "percentile": top["percentile"], "date": top["date"]} if top else None,
                "ssvc": ssvc,  # CISA's SSVC decision points (cvelistV5 ADP): exploitation, automatable, technical impact
                # an advisory a CSAF provider brought with its first fill: shown, never notified (csaf_providers) –
                # as a finding only links of the relink after a catalogue change make (relink_catalog)
                "quiet": bool(data.get("initial")) or all(getattr(x, "quiet", False) for x in all_advs),
                # from a CSAF provider's TLP:GREEN document (allowed per provider): labelled wherever it is shown or sent
                "tlp": "GREEN" if any((x.data or {}).get("tlp") == "GREEN" for x in all_advs) else None,
                "published_at": (a.published_at or a.updated_at).isoformat() if (a.published_at or a.updated_at) else None,
                "status": worst.status,
                "versions": [
                    {"id": str(ver.id) if ver else None, "version": text, "status": vd.status, "reason": vd.reason, "fixed": vd.fixed, "detail": vd.detail}
                    for ver, text, vd in rows
                ],
            }
        )
    # the most relevant first; within the same status, exploitation and CVSS the newest first
    out.sort(key=lambda f: f["published_at"] or "", reverse=True)
    out.sort(key=lambda f: (-ORDER[f["status"]], not f["exploited"], -(f["cvss"] or 0)))
    return out


# ---------------------------------------------------------------- the version to go to




def _fix_v(scheme: str, text: str | None) -> V | None:
    if not text:
        return None
    v = parse(scheme, text)
    if v is None and scheme != "veeam":  # "13.1 Patch 2" is no Veeam build – never read as one
        v = parse("generic", text) or _lead_v(text)
    return v


def _lead_v(text: str | None) -> V | None:
    """A release with a suffix the schemes do not read ("16.0.4305.5 CU27+GDR"): its numeric start."""
    t = catalog.lead(text or "")
    return parse("generic", t) if t else None


def _line_name(rels: list[dict], scheme: str, v: V) -> str:
    """The release line of a version: endoflife.date's line, else its first two parts (Windows: three)."""
    r = _line(rels, v) if rels else None
    if r is not None:
        return str(r["name"])
    return ".".join(str(x) for x in v.key[: 3 if scheme == "windows" else 2])


def target_versions(product: dict, groups: list[dict], found: list[dict], versions: list[VendorVersion]) -> dict[str, dict]:
    """Per installed version the version to go to: the smallest version of its own release line that fixes the most of
    the vulnerabilities affecting it (each candidate checked with the same matching as the version itself – a PAN-OS
    hotfix branch fixes only its own base, a Veeam build only its line). Candidates: the fixed versions the findings
    name, the latest release of the line and of the newest line (endoflife.date). Kinds: none (nothing affects it) |
    update (`to` in the own line; `open` remain – `newer` a newer line that fixes some of them) | newer_line (only a
    newer line fixes anything) | no_fix."""
    scheme = product.get("scheme") or "generic"
    rels = catalog.releases(product.get("eol"))
    by_id = {g["primary"].id: g for g in groups}
    maintained = [r for r in rels if r.get("isMaintained") or not r.get("isEol")]
    newest = max(maintained or rels, key=lambda r: r.get("releaseDate") or "") if rels else None
    out: dict[str, dict] = {}
    for ver in versions:
        vid = str(ver.id)
        rows = [(f, r) for f in found for r in f["versions"] if r["id"] == vid]
        aff = [(f, r) for f, r in rows if r["status"] == "affected"]
        t: dict = {"kind": "none", "to": None, "line": None, "fixes": 0, "total": len(aff), "open": 0, "possible": sum(1 for _, r in rows if r["status"] == "possible"), "newer": None}
        out[vid] = t
        if not aff:
            continue
        t |= {"kind": "no_fix", "open": len(aff)}
        v = stored_v(product, ver.version)
        if v is None:
            continue
        cands: dict[V, None] = {}
        for _, r in aff:
            if (c := _fix_v(scheme, r["fixed"])) is not None and c > v:
                cands.setdefault(c)
        own = _line(rels, v) if rels else None
        for r in (own, newest):
            if r is not None and (c := _fix_v(scheme, r.get("latest"))) is not None and c > v:
                cands.setdefault(c)
        per_line: dict[str, list[V]] = {}
        for c in sorted(cands):
            per_line.setdefault(_line_name(rels, scheme, c), []).append(c)
        mine = _line_name(rels, scheme, v)
        ids = {f["id"] for f, _ in aff}
        fixed_by: dict[V, set[str]] = {}

        def fixes(c: V, want: set[str]) -> set[str]:
            # which of `want` this candidate fixes – each (candidate, finding) checked once
            got = fixed_by.setdefault(c, set())
            for fid in want - got - checked.setdefault(c, set()):
                checked[c].add(fid)
                vd = group_verdict(product, by_id[fid], c.text)
                if vd is None or vd.status == "not_affected":
                    got.add(fid)
            return got & want

        checked: dict[V, set[str]] = {}
        hint = {f["id"]: _fix_v(scheme, r["fixed"]) for f, r in aff}

        def fixes_all(c: V, want: list[str]) -> bool:
            # stops at the first one it does not fix (the likeliest first: the highest fixed version)
            got = fixed_by.setdefault(c, set())
            for fid in want:
                if fid in got:
                    continue
                if fid in checked.setdefault(c, set()):
                    return False
                checked[c].add(fid)
                vd = group_verdict(product, by_id[fid], c.text)
                if vd is None or vd.status == "not_affected":
                    got.add(fid)
                else:
                    return False
            return True

        def best_in(cs: list[V], want: set[str]) -> V | None:
            """The smallest candidate of one line that fixes everything its largest one fixes: a later release of a
            line fixes what an earlier one did. Searched from the highest fixed version the findings name (below it a
            release is still affected) – a few checks per finding instead of one per candidate and finding."""
            if not cs:
                return None
            top = fixes(cs[-1], want)
            if not top:
                return None
            order = sorted(top, key=lambda fid: hint.get(fid) or V((), ""), reverse=True)
            floor = max((h for fid in top if (h := hint.get(fid)) is not None and h <= cs[-1]), default=None)
            lo, hi = (bisect.bisect_left(cs, floor) if floor is not None else 0), len(cs) - 1
            lo = min(lo, hi)
            while lo < hi:
                mid = (lo + hi) // 2
                if fixes_all(cs[mid], order):
                    hi = mid
                else:
                    lo = mid + 1
            if not fixes_all(cs[lo], order):  # the floor guessed wrong (a fix outside the line): the largest is sure
                return cs[-1]
            return cs[lo]

        def best_other(want: set[str]) -> V | None:
            # newer lines: the nearest few and the newest – the one that fixes the most, the nearer one on a tie
            names = [ln for ln in per_line if ln != mine]
            names = list(dict.fromkeys(names[:3] + names[-1:]))
            got = [(c, len(fixes(c, want))) for ln in names if (c := best_in(per_line[ln], want)) is not None]
            return max(got, key=lambda x: (x[1], -names.index(_line_name(rels, scheme, x[0]))))[0] if got else None

        others = [gid for gid in by_id if gid not in ids]

        def introduced(c: V) -> dict[str, Verdict]:
            # vulnerabilities that do not affect the installed version but the candidate (a regression of a later
            # release): a target must not trade the known holes for new ones
            return {gid: vd for gid in others if (vd := group_verdict(product, by_id[gid], c.text)) is not None and vd.status == "affected"}

        def settle(c: V) -> tuple[V, int]:
            """`c`, or a later release of its line that fixes what `c` fixes and is not affected by anything new – found
            through the fixed versions the new ones name. Else `c` with the number of new ones."""
            want = fixes(c, ids)
            for _ in range(4):
                bad = introduced(c)
                if not bad:
                    return c, 0
                nxt = [h for vd in bad.values() if (h := _fix_v(scheme, vd.fixed)) is not None and h > c]
                c2 = max(nxt) if nxt else None
                if c2 is None or _line_name(rels, scheme, c2) != _line_name(rels, scheme, c) or not want <= fixes(c2, want):
                    return c, len(bad)
                c = c2
            return c, len(introduced(c))

        c = best_in(per_line.get(mine, []), ids)
        if c is not None:
            c, new = settle(c)
            t |= {"kind": "update", "to": c.text, "line": mine, "fixes": len(fixes(c, ids)), "open": len(ids - fixes(c, ids))}
            rest = ids - fixes(c, ids)
            if rest and (n := best_other(rest)) is not None:
                t["newer"] = {"to": n.text, "line": _line_name(rels, scheme, n), "fixes": len(fixes(n, rest))}
        elif (c := best_other(ids)) is not None:
            c, new = settle(c)
            t |= {"kind": "newer_line", "to": c.text, "line": _line_name(rels, scheme, c), "fixes": len(fixes(c, ids)), "open": len(ids - fixes(c, ids))}
        else:
            new = 0
        if new:
            t["introduces"] = new  # the target is itself affected by these (no release of its line avoids them yet)
    return out


def urgency(counts: dict, releases: list[dict]) -> str:
    """How urgent a followed product is, for the order of the overview: exploited (an actively exploited vulnerability
    affects a version) → critical → affected (also: a version without support) → possible (also: no version given,
    support ends soon) → info (a cloud service the vendor fixes) → ok."""
    if counts.get("exploited_affected"):
        return "exploited"
    if counts.get("critical_affected"):
        return "critical"
    if counts.get("affected") or any(r.get("eol_state") == "past" for r in releases):
        return "affected"
    if counts.get("possible") or counts.get("unversioned") or any(r.get("eol_state") == "soon" for r in releases):
        return "possible"
    if counts.get("service"):
        return "info"
    return "ok"


def _line(rels: list[dict], v: V) -> dict | None:
    """The release line of a parsed version: the deepest line name it starts with – or (Windows / Exchange) the line
    whose latest release has its build (10.0.20348 ↔ 2022)."""
    cands = [(r, k) for r in rels if (k := parse("generic", r["name"])) is not None and v.startswith(k)]
    if cands:
        return max(cands, key=lambda x: x[1].depth)[0]
    for r in rels:
        lat = parse("generic", r.get("latest") or "") or _lead_v(r.get("latest"))
        if lat is not None and lat.depth >= 3 and v.key[:3] == lat.key[:3]:
            return r
    return None


def line_of(product: dict, version: str | None) -> dict | None:
    """The release line (endoflife.date) an installed version belongs to, with its release date."""
    rels = catalog.releases(product.get("eol"))
    v = stored_v(product, version) if version and rels else None
    return _line(rels, v) if v is not None else None


def release_info(product: dict, version: str | None, today: date | None = None) -> dict | None:
    """Release line of a version (endoflife.date): latest in the line, a newer line, support and EOL dates."""
    rels = catalog.releases(product.get("eol"))
    if not rels:
        return None
    today = today or datetime.now(UTC).date()
    scheme = product.get("scheme") or "generic"
    v = stored_v(product, version) if version else None
    line = _line(rels, v) if v is not None else None

    def state(d: str | None) -> str:
        if not d:
            return "unknown"
        try:
            at = date.fromisoformat(d[:10])
        except ValueError:
            return "unknown"
        return "past" if at <= today else "soon" if at - today < EOL_SOON else "ok"

    maintained = [r for r in rels if r.get("isMaintained") or not r.get("isEol")]
    newest = max(maintained or rels, key=lambda r: r.get("releaseDate") or "")
    out: dict = {"lines": [{k: r.get(k) for k in ("name", "label", "latest", "latestDate", "releaseDate", "eolFrom", "eoasFrom", "isEol", "isLts", "isMaintained")} | {"eol_state": state(r.get("eolFrom")) if r.get("eolFrom") else ("past" if r.get("isEol") else "unknown")} for r in rels[:30]]}
    if v is None:
        return out
    if line is None:
        out["line"] = None
        return out
    latest = parse(scheme, line.get("latest") or "") or parse("generic", line.get("latest") or "") or _lead_v(line.get("latest"))
    update = bool(latest is not None and latest > v and not v.startswith(latest))
    # "12.3.2" without its build (or "1.27" for nginx 1.27.3) may be the latest already – or not: neither "update" nor
    # "current"
    unknown = bool(update and short_version(product, v.text) and latest.startswith(v))
    eol_state = state(line.get("eolFrom")) if line.get("eolFrom") else ("past" if line.get("isEol") else "unknown")
    newer = None
    if newest is not line and (newest.get("releaseDate") or "") > (line.get("releaseDate") or "") and newest.get("name") != line.get("name"):
        newer = {"name": newest["name"], "label": newest.get("label"), "latest": newest.get("latest")}
    out |= {
        "line": {"name": line["name"], "label": line.get("label"), "latest": line.get("latest"), "latest_date": line.get("latestDate"), "release_date": line.get("releaseDate"), "eol_from": line.get("eolFrom"), "eoas_from": line.get("eoasFrom"), "lts": line.get("isLts")},
        "update_available": update and not unknown,
        "update_unknown": unknown,
        "eol_state": eol_state,
        "newer_line": newer,
    }
    return out


@dataclass(slots=True)
class Adv:
    """What the evaluation needs of a stored advisory – read as plain columns (no ORM objects kept in a session), the
    JSON decoded off the event loop."""

    id: str
    source: str
    ident: str
    title: str
    summary: str
    url: str
    cves: list
    cvss: float | None
    severity: str
    exploited: bool
    published_at: datetime | None
    updated_at: datetime | None
    data: dict
    quiet: bool = False  # its link to the product is quiet (relink_catalog)


_ADV_COLS = (
    VendorAdvisory.id,
    VendorAdvisory.source,
    VendorAdvisory.ident,
    VendorAdvisory.title,
    VendorAdvisory.summary,
    VendorAdvisory.url,
    cast(VendorAdvisory.cves, Text),
    VendorAdvisory.cvss,
    VendorAdvisory.severity,
    VendorAdvisory.exploited,
    VendorAdvisory.published_at,
    VendorAdvisory.updated_at,
    cast(VendorAdvisory.data, Text),
)


def _advs(rows: list) -> list[Adv]:
    out = []
    for r in rows:
        data = json.loads(r[12]) if r[12] else {}
        quiet = bool(r[13]) if len(r) > 13 else False
        out.append(Adv(r[0], r[1], r[2] or "", r[3] or "", r[4] or "", r[5] or "", json.loads(r[6]) if r[6] else [], r[7], r[8] or "info", bool(r[9]), r[10], r[11], data if isinstance(data, dict) else {}, quiet))
    return out


async def load_advs(db: AsyncSession, product: str) -> list[Adv]:
    rows = (
        await db.execute(
            select(*_ADV_COLS, VendorAdvisoryProduct.quiet).join(VendorAdvisoryProduct, VendorAdvisoryProduct.advisory_id == VendorAdvisory.id).where(VendorAdvisoryProduct.product == product)
        )
    ).all()
    return await asyncio.to_thread(_advs, rows)


_views: dict[str, tuple[tuple, dict]] = {}  # product → (what it was computed from, the view)
_flight: dict[str, tuple[tuple, asyncio.Task]] = {}  # product → the computation running now (single flight)
_stamp = [0]


async def product_view(db: AsyncSession, f: VendorFollow, vers: list[VendorVersion], *, kev: dict | None = None, euvd: set[str] | None = None) -> dict:
    """Everything the page shows of one followed product – cached until its advisories, its follow or versions, the
    KEV or the EUVD list change. Computed once at a time per product (concurrent requests wait for the same result)."""
    kev = kev if kev is not None else await kev_index(db)
    euvd = euvd if euvd is not None else await euvd_cves(db)
    ck = (gen.epoch, _pgen.get(f.product, 0), f.updated_at, tuple((v.id, v.version, v.updated_at) for v in vers), len(kev), hash(frozenset(euvd)))
    hit = _views.get(f.product)
    if hit and hit[0] == ck:
        return hit[1]
    run = _flight.get(f.product)
    if run is None or run[0] != ck:
        run = (ck, asyncio.ensure_future(_compute_view(f, vers, kev, euvd)))
        _flight[f.product] = run
    try:
        view = await asyncio.shield(run[1])
    finally:
        if _flight.get(f.product) is run and run[1].done():
            _flight.pop(f.product, None)
    if (gen.epoch, _pgen.get(f.product, 0)) == ck[:2]:
        _views[f.product] = (ck, view)  # not when something changed while it was computed
    return view


STRUCTURED = ("csaf", "cvelist", "epss", "osv")  # the structured sources, each switched on its own (settings)


def switched_off(cfg: dict) -> frozenset[str]:
    return frozenset(k for k in STRUCTURED if not cfg.get(k, True))


def counts(a: VendorAdvisory | Adv, off: frozenset[str]) -> bool:
    """Whether a stored record takes part in the verdicts: not one of a structured source switched off – it stays
    stored, switching the source on again uses it at once (security review 0.1.26 L9). CSAF: only what a provider's
    own feed brought (the stories' CSAF is part of the news, not of this switch)."""
    if not off:
        return True
    if a.source in ("cvelist", "osv"):
        return a.source not in off
    return not (a.source == "csaf" and "csaf" in off and (a.data or {}).get("feed"))


async def _compute_view(f: VendorFollow, vers: list[VendorVersion], kev: dict, euvd: set[str]) -> dict:
    p = product_of(f) or {"key": f.product, "label": f.product, "vendor": "", "category": "other", "scheme": "generic"}
    async with dbm.session() as db:  # its own session: a request that waits for it may end first
        advs = await load_advs(db, f.product)
        off = switched_off(await config(db))
    if off:
        advs = [a for a in advs if counts(a, off)]

    def evaluate_all() -> tuple[list[dict], dict[str, dict]]:
        groups = groups_of(advs)
        found = findings(p, advs, vers, kev, euvd, groups)
        return found, target_versions(p, groups, found, vers)

    found, targets = await asyncio.to_thread(evaluate_all)
    if "epss" not in off:
        await _add_epss(found)
    _stamp[0] += 1
    return {"product": p, "findings": found, "targets": targets, "stamp": _stamp[0]}


async def _add_epss(found: list[dict]) -> None:
    """FIRST EPSS on the findings that concern a version (the not affected ones need none): one query for their CVEs."""
    from app import epss as epss_svc

    hits = [x for x in found if x["status"] != "not_affected" and x["cves"]]
    if not hits:
        return
    async with dbm.session() as db:
        scores = await epss_svc.scores(db, {c for x in hits for c in x["cves"]})
    if not scores:
        return
    for x in hits:
        top = max((scores[c] for c in x["cves"] if c in scores), key=lambda e: e["score"], default=None)
        if top is not None:
            x["epss"] = top


def summary(view: dict, vers: list[VendorVersion]) -> dict:
    """The card: per version how many vulnerabilities affect it (critical / exploited ones apart; "unklare Altdaten"
    apart and not counted), the version to go to, the worst state."""
    if (hit := view.get("_summary")) is not None:
        return hit  # computed once per view (the overview asks for it on every load)
    fs = view["findings"]

    def blank() -> dict:
        return {"affected": 0, "possible": 0, "critical": 0, "exploited": 0, "service": 0, "unversioned": 0, "stale": 0}

    per: dict[str | None, dict] = {str(v.id): blank() for v in vers}
    for f in fs:
        for r in f["versions"]:
            s = per.get(r["id"])
            if s is None:
                s = per[r["id"]] = blank()
            if r["status"] in s:
                s[r["status"]] += 1
            if r["status"] in ("affected", "possible"):
                s["critical"] += f["severity"] == "critical"
                s["exploited"] += bool(f["exploited"])
    for vid, t in (view.get("targets") or {}).items():
        if vid in per:
            per[vid]["target"] = t
    worst = "none"
    for f in fs:
        if f["status"] not in ("not_affected", "stale") and (worst == "none" or ORDER[f["status"]] > ORDER.get(worst, -1)):
            worst = f["status"]
    view["_summary"] = out = {"per_version": per, "worst": worst}
    return out


# ---------------------------------------------------------------- related stories


def _kw_regex(words: list[str]) -> re.Pattern | None:
    ws = [re.escape(w.strip()) for w in words if w and len(w.strip()) >= 3]
    return re.compile(r"(?<![\w-])(?:" + "|".join(ws) + r")(?![\w-])", re.I) if ws else None


_related: "OrderedDict[tuple, tuple[float, list[dict]]]" = OrderedDict()
RELATED_TTL = 600.0
RELATED_CACHE = 200  # least recently used out first – a reader paging through many products never clears the rest


def _pg_word(w: str) -> str:
    """`w` as a whole word for PostgreSQL's case-insensitive regex (~*): not inside another word ("Git" in "GitHub",
    "digital") – as _kw_regex. Every character that is not a letter, digit or space is escaped (a literal in ARE)."""
    body = re.sub(r"([^\w\s])", r"\\\1", w.strip())
    return f"(^|[^[:alnum:]_-])({body})($|[^[:alnum:]_-])"


async def related_news(db: AsyncSession, product: dict, cves: list[str], limit: int = 30) -> list[dict]:
    """Stories of the news feed about the product: one of its CVEs, or its name as a word in title or summary. Cached per
    product and CVE list until a story arrives (the arrival number) or for 10 minutes (stories read, hidden, pruned) –
    the search over every story costs up to a few hundred ms for a product with many CVEs."""
    ck = (product.get("key"), tuple(cves[:40]), limit, await news_svc.last_seq(db))
    hit = _related.get(ck)
    if hit and time.monotonic() - hit[0] < RELATED_TTL:
        _related.move_to_end(ck)
        return hit[1]
    out = await _related_news(db, product, cves, limit)
    _related[ck] = (time.monotonic(), out)
    _related.move_to_end(ck)
    while len(_related) > RELATED_CACHE:
        _related.popitem(last=False)
    return out


async def _related_news(db: AsyncSession, product: dict, cves: list[str], limit: int) -> list[dict]:
    """Two queries, each with its own limit: the stories that list one of the CVEs, and the stories naming the product
    as a word – a short name ("Git", "Bun", "Lua") is part of many other words, and hundreds of such stories must not push
    a story with the product's CVE out of the list (bug hunt 0.1.16 M7)."""
    words = [w for w in dict.fromkeys([*(product.get("kw") or []), product.get("label") or ""]) if w and len(w.strip()) >= 3][:6]
    rx = _kw_regex(words)
    wanted = list(dict.fromkeys(c.upper() for c in cves[:40]))
    base = select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).where(news_svc.visible())
    rows: dict = {}
    if wanted:
        # the trigram index finds the candidates (the CVE in the folded text), the list of the story's CVEs decides
        by_cve = base.where(or_(*[NewsItem.search.like(dbm.contains(c)) for c in wanted]), NewsItem.cves.op("?|")(pg_array(wanted)))
        for i, s in (await db.execute(by_cve.order_by(NewsItem.published_at.desc()).limit(limit))).all():
            rows[i.id] = (i, s)
    if words:
        text_ = NewsItem.title + "\n" + NewsItem.summary
        by_name = base.where(or_(*[and_(NewsItem.search.like(dbm.contains(w)), text_.op("~*")(_pg_word(w))) for w in words]))
        for i, s in (await db.execute(by_name.order_by(NewsItem.published_at.desc()).limit(limit))).all():
            rows.setdefault(i.id, (i, s))
    cset = set(wanted)
    out = []
    for i, s in sorted(rows.values(), key=lambda r: r[0].published_at, reverse=True):
        hit_cves = sorted(cset.intersection(c.upper() for c in i.cves or []))
        if not hit_cves and not (rx and rx.search(f"{i.title}\n{i.summary}")):
            continue
        out.append(
            {
                "id": str(i.id),
                "title": i.title,
                "summary": i.summary[:300],
                "url": i.url,
                "source": {"id": str(s.id), "name": s.name, "logo": bool(s.logo)},
                "published_at": i.published_at.isoformat(),
                "severity": i.severity,
                "cves": hit_cves[:5],
                "by": "cve" if hit_cves else "name",
            }
        )
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- events (notifications)


READY_AFTER_FAILURES = 3


async def _answered(db: AsyncSession) -> set[str]:
    """The queries that answered once – or failed again and again (a feed that refuses us, 403): that one source must
    not hold back the events of all the others for good. One read for all products."""
    return set(await db.scalars(select(VendorFetch.key).where(or_(VendorFetch.last_ok_at.is_not(None), VendorFetch.failures >= READY_AFTER_FAILURES))))


def _ready(product: dict, answered: set[str]) -> bool:
    """Every query of the product has answered once – before that a "new" finding is only data not fetched yet."""
    return set(fetch_keys(product)) <= answered


def _fresh(f: dict, now: datetime) -> bool:
    pub = datetime.fromisoformat(f["published_at"]) if f.get("published_at") else None
    kev_added = f.get("kev") and f["kev"].get("added")
    if kev_added:
        try:
            if now - datetime.fromisoformat(kev_added).replace(tzinfo=UTC) <= EVENT_FRESH:
                return True
        except ValueError:
            pass
    return pub is not None and now - pub <= EVENT_FRESH


EVAL_FULL = timedelta(hours=1)  # also without a change: dates move on (EOL "soon", a KEV listing becomes old)
_evaluated: dict[str, tuple] = {}  # product → what its events were last evaluated from
_last_full: list[datetime | None] = [None]


def _fresh_exploit(f: dict, now: datetime) -> bool:
    """"Now actively exploited" is news when the KEV listed it recently – or, without a KEV date (EUVD, the vendor), when
    the vulnerability itself is recent."""
    added = f.get("kev") and f["kev"].get("added")
    if added:
        try:
            return now - datetime.fromisoformat(added).replace(tzinfo=UTC) <= EVENT_FRESH
        except ValueError:
            pass
    return _fresh(f, now)


def _no_cve(finding_id: str) -> str:
    """The stand-in for the CVE of a finding without one (a vendor advisory naming none): its record – so it, too, is
    notified once and can become "jetzt aktiv ausgenutzt" later."""
    return f"#{finding_id}"


async def _known(db: AsyncSession, scopes: list[str]) -> tuple[set[str], dict[str, set[str]], dict[str, set[str]]]:
    """The vulnerability events of these scopes (product + version): their keys, the CVEs notified per scope, and the
    CVEs already said to be exploited per scope – read by the scope's index, not the whole table."""
    keys: set[str] = set()
    cves: dict[str, set[str]] = {s: set() for s in scopes}
    exploited: dict[str, set[str]] = {s: set() for s in scopes}
    if not scopes:
        return keys, cves, exploited
    stmt = select(VendorEvent.key, VendorEvent.scope, VendorEvent.data["cves"], VendorEvent.data["exploited"].as_boolean()).where(VendorEvent.scope.in_(scopes))
    for key, scope, raw, expl in (await db.execute(stmt)).all():
        keys.add(key)
        got = {str(c) for c in raw} if isinstance(raw, list) else set()
        if not got and scope and (rest := key.removeprefix("exploited:")).startswith(scope + ":"):
            got = {_no_cve(rest[len(scope) + 1 :])}  # a finding without CVE: known by its record
        cves.setdefault(scope, set()).update(got)
        if expl:
            exploited.setdefault(scope, set()).update(got)
    return keys, cves, exploited


def eol_stage(eol_from: str | None, today: date) -> tuple[str, date, int] | None:
    """The pre-warning stage of a support end: "past" (ended – on the day itself, as release_info), "30" (30 days or
    less left), "90" (90 or less) – or None (further off, or no date). With the date and the days left."""
    if not eol_from:
        return None
    try:
        at = date.fromisoformat(str(eol_from)[:10])
    except ValueError:
        return None
    days = (at - today).days
    if days <= 0:
        return "past", at, days
    for limit, stage in EOL_STAGES:
        if days <= limit:
            return stage, at, days
    return None


async def _eol_known(db: AsyncSession, scopes: list[str]) -> dict[str, list[tuple[str, str, datetime]]]:
    """The pre-warnings written so far per version (scope eol:<product>:<version>): (date, stage, when)."""
    out: dict[str, list[tuple[str, str, datetime]]] = {}
    if not scopes:
        return out
    stmt = select(VendorEvent.scope, VendorEvent.data["eol_from"].as_string(), VendorEvent.data["stage"].as_string(), VendorEvent.created_at).where(VendorEvent.kind == "eol", VendorEvent.scope.in_(scopes))
    for sc, at, st, created in (await db.execute(stmt)).all():
        if at and st:
            out.setdefault(sc, []).append((at, st, created))
    return out


async def _eol_stage_silent(db: AsyncSession, product: str, line: dict, stage: str, at: date, had: list[tuple[str, str, datetime]], now: datetime) -> bool:
    """Whether this version's pre-warning comes silently (shown, not sent): no catch-up and no second message.
    - "past" of a date long gone (more than EVENT_FRESH ago), or one the line's "Support beendet" of 0.1.33 and before
      said already (the first round after the update: only the state of now, no flood of old ends);
    - the vendor moved the date: the stage of the new date is news only when it is more urgent than what was said of
      the date before (30 days before, now 90 days before a later date: silent – the 30 days of the new date come);
    - a stage that is less urgent than one said of the same date (the clock never goes back – a safeguard)."""
    rank = EOL_STAGE_RANK[stage]
    iso = at.isoformat()
    same = [EOL_STAGE_RANK.get(s, 0) for d, s, _ in had if d == iso]
    if same and max(same) >= rank:
        return True
    if not same:
        other = [(c, d) for d, _s, c in had if d != iso]
        if other:
            last_date = max(other)[1]
            said = max(EOL_STAGE_RANK.get(s, 0) for d, s, _ in had if d == last_date)
            if rank <= said:
                return True
    if stage == "past":
        if now.date() - at > EVENT_FRESH:
            return True
        legacy = await db.scalar(select(VendorEvent.data["eol_from"].as_string()).where(VendorEvent.key == f"eol:{product}:{line['name']}:past"[:400]))
        if legacy is not None and str(legacy)[:10] == iso:
            return True
    return False


async def prune_events(db: AsyncSession, fs: list[VendorFollow], vers: dict) -> int:
    """Events of products no longer followed and of versions no longer entered (an edited version is a new one): they
    only served to notify each finding once – a version entered again starts with a new, silent baseline. Keeps the
    table as big as what is followed now instead of growing with every edit."""
    keep = {f"vuln:{f.product}:{v.version}" for f in fs for v in vers.get(f.id, [])} | {f"vuln:{f.product}:*" for f in fs if not vers.get(f.id)}
    keep_eol = {f"eol:{f.product}:{v.version}" for f in fs for v in vers.get(f.id, [])}
    products = {f.product for f in fs}
    # the events of a watched CVE (kind "watch") belong to no product – they go with cve_watch.prune
    stale = and_(
        VendorEvent.kind != "watch",
        or_(
            VendorEvent.product.not_in(products),
            (VendorEvent.kind == "vuln") & VendorEvent.scope.is_not(None) & VendorEvent.scope.not_in(keep),
            (VendorEvent.kind == "eol") & VendorEvent.scope.is_not(None) & VendorEvent.scope.not_in(keep_eol),
        ),
    )
    gone = list(await db.scalars(select(VendorEvent.id).where(stale)))  # only what goes – not every event, hourly
    for i in range(0, len(gone), 500):
        await db.execute(delete(VendorEvent).where(VendorEvent.id.in_(gone[i : i + 500])))
        await db.commit()
    return len(gone)


async def evaluate_events(db: AsyncSession, *, full: bool = False) -> int:
    """New findings, newer versions and EOL dates of the followed products as events – each once – and "now actively
    exploited" for a finding notified before without it. Returns how many events (not baseline) were created. Only
    products whose view or versions changed since the last evaluation are looked at (all of them hourly); each
    product's events are read by their scope and written in a short transaction of its own."""
    now = datetime.now(UTC)
    fs = await follows(db)
    vers = await versions_of(db, [f.id for f in fs])
    kev, euvd = await kev_index(db), await euvd_cves(db)
    if full or _last_full[0] is None or now - _last_full[0] >= EVAL_FULL:
        full = True
        _last_full[0] = now
        await prune_events(db, fs, vers)
    created = 0
    answered = await _answered(db)
    if not (await config(db)).get("csaf", True):
        from app import csaf_providers

        answered |= {f"csaf:{x['key']}" for x in csaf_providers.providers()}  # switched off: nothing to wait for
    for f in fs:
        p = product_of(f)
        if p is None or not _ready(p, answered):
            continue
        vs = vers.get(f.id, [])
        view = await product_view(db, f, vs, kev=kev, euvd=euvd)
        sig = (view["stamp"], f.baseline_at is None, tuple((v.id, v.version, v.baseline_at is None) for v in vs))
        if not full and _evaluated.get(f.product) == sig:
            continue  # nothing new for this product
        try:
            n = await _evaluate_product(db, f, p, vs, view, now)
        except Exception:  # noqa: BLE001 - logged; this product (not marked evaluated) and the rest come next round
            await db.rollback()  # expires every loaded object – the loop cannot go on with them
            log.exception("vendor: evaluating %s failed", f.product)
            break
        created += n
        _evaluated[f.product] = (view["stamp"], False, tuple((v.id, v.version, False) for v in vs))
    return created


async def _evaluate_product(db: AsyncSession, f: VendorFollow, p: dict, vs: list[VendorVersion], view: dict, now: datetime) -> int:
    created = 0
    targets = [(v.version, v) for v in vs] or [("*", None)]
    scopes = [f"vuln:{f.product}:{text}" for text, _ in targets]
    known, known_cves, known_exploited = await _known(db, scopes)
    other_keys: list[str] = []
    for text, ver in targets:
        if ver is not None:
            info = release_info(p, ver.version)
            if info and info.get("line"):
                line = info["line"]
                if info.get("update_available") and line.get("latest"):
                    other_keys.append(f"version:{f.product}:{ver.version}:{line['latest']}"[:400])
                if info.get("eol_state") in ("soon", "past"):
                    other_keys.append(f"eol:{f.product}:{line['name']}:{info['eol_state']}"[:400])
    if other_keys:
        known |= set(await db.scalars(select(VendorEvent.key).where(VendorEvent.key.in_(other_keys))))
    staged = await _eol_known(db, [f"eol:{f.product}:{v.version}" for v in vs]) if vs else {}
    for text, ver in targets:
        # a follow without baseline (new, or switched on again) makes all its versions a baseline, too
        base = f.baseline_at is None or (ver is not None and ver.baseline_at is None)
        scope = f"vuln:{f.product}:{text}"
        for fd in view["findings"]:
            row = next((r for r in fd["versions"] if r["version"] == (None if text == "*" else text)), None)
            if row is None or row["status"] not in ("affected", "possible", "unversioned", "service"):
                continue
            cves = set(fd["cves"]) or {_no_cve(fd["id"])}
            data = {
                "product": p.get("label"),
                "product_key": f.product,
                "version": None if text == "*" else text,
                "label": ver.label if ver else "",
                "status": row["status"],
                "reason": row["reason"],
                "fixed": row["fixed"],
                "title": fd["title"],
                "headline": fd.get("headline") or "",
                "summary": (fd["summary"] or "")[:400],
                "url": fd["url"],
                "ident": fd["ident"],
                "cves": fd["cves"],
                "cvss": fd["cvss"],
                "exploited": fd["exploited"],
                "published_at": fd["published_at"],
                **({"tlp": fd["tlp"]} if fd.get("tlp") else {}),
            }
            key = f"{scope}:{fd['id']}"[:400]
            if key not in known and not (cves & known_cves[scope]):
                silent = base or not _fresh(fd, now) or bool(fd.get("quiet"))
                db.add(VendorEvent(key=key, kind="vuln", product=f.product, severity=fd["severity"], data=data, baseline=silent, created_at=now, scope=scope))
                known.add(key)
                known_cves[scope] |= cves
                if fd["exploited"]:
                    known_exploited[scope] |= cves
                created += 0 if silent else 1
                continue
            # notified before (by this record or another one of the same CVE) – but not as exploited: now it is
            ekey = f"exploited:{scope}:{fd['id']}"[:400]
            if fd["exploited"] and cves and not (cves & known_exploited[scope]) and ekey not in known:
                silent = base or not _fresh_exploit(fd, now)
                sev = fd["severity"] if SEV_RANK.get(fd["severity"], 0) >= SEV_RANK["high"] else "high"
                db.add(VendorEvent(key=ekey, kind="vuln", product=f.product, severity=sev, data=data | {"now_exploited": True, "kev": fd.get("kev")}, baseline=silent, created_at=now, scope=scope))
                known.add(ekey)
                known_exploited[scope] |= cves
                created += 0 if silent else 1
        if ver is not None:
            info = release_info(p, ver.version)
            if info and info.get("line"):
                line = info["line"]
                evs = []
                if info.get("update_available") and line.get("latest"):
                    evs.append(("version", f"version:{f.product}:{ver.version}:{line['latest']}", "low", {"latest": line["latest"]}, base, None))
                stage = eol_stage(line.get("eol_from"), now.date())
                if stage is not None:
                    # the pre-warning of this version (90, 30 days, ended) – it says more than "Support endet bald" of
                    # its line, which then comes silently (no second message of the same date)
                    st, at, days = stage
                    had = staged.get(f"eol:{f.product}:{ver.version}", [])
                    key = f"eolw:{f.product}:{ver.version}:{at.isoformat()}:{st}"
                    if key[:400] not in known and not any(d == at.isoformat() and x == st for d, x, _c in had):
                        silent = base or await _eol_stage_silent(db, f.product, line, st, at, had, now)
                        state = "past" if st == "past" else "soon"
                        evs.append(("eol", key, "medium" if st == "90" else "high", {"eol_state": state, "eol_from": at.isoformat(), "stage": st, "days": max(0, days)}, silent, f"eol:{f.product}:{ver.version}"))
                        staged.setdefault(f"eol:{f.product}:{ver.version}", []).append((at.isoformat(), st, now))
                    if info.get("eol_state") == "soon":
                        evs.append(("eol", f"eol:{f.product}:{line['name']}:soon", "medium", {"eol_state": "soon", "eol_from": line.get("eol_from")}, True, None))
                elif info.get("eol_state") == "soon" or (info.get("eol_state") == "past" and not line.get("eol_from")):
                    # "Support endet bald" (EOL_SOON) of the line – and an end without a date (isEol only): as before
                    evs.append(("eol", f"eol:{f.product}:{line['name']}:{info['eol_state']}", "high" if info["eol_state"] == "past" else "medium", {"eol_state": info["eol_state"], "eol_from": line.get("eol_from")}, base, None))
                for kind, key, sev, extra, silent, ev_scope in evs:
                    if key[:400] in known:
                        continue
                    data = {"product": p.get("label"), "product_key": f.product, "version": ver.version, "label": ver.label, "line": line.get("label") or line["name"], **extra}
                    db.add(VendorEvent(key=key[:400], kind=kind, product=f.product, severity=sev, data=data, baseline=silent, created_at=now, scope=ev_scope))
                    known.add(key[:400])
                    created += 0 if silent else 1
            if ver.baseline_at is None:
                # only the version evaluated here, and only while nobody set it anew meanwhile: an admin who corrects the
                # version during the round makes it a new baseline – an ORM write of this (stale) object would overwrite
                # that and turn the new version's findings into notifications; a deleted version is simply no row
                res = await db.execute(
                    update(VendorVersion)
                    .where(VendorVersion.id == ver.id, VendorVersion.version == ver.version, VendorVersion.baseline_at.is_(None))
                    .values(baseline_at=now)
                    .execution_options(synchronize_session=False)
                )
                if res.rowcount:
                    set_committed_value(ver, "baseline_at", now)
    if f.baseline_at is None:
        res = await db.execute(update(VendorFollow).where(VendorFollow.id == f.id, VendorFollow.baseline_at.is_(None)).values(baseline_at=now).execution_options(synchronize_session=False))
        if res.rowcount:
            set_committed_value(f, "baseline_at", now)
    await db.commit()
    return created


# ---------------------------------------------------------------- the background loop


LOOKUP_KEEP = timedelta(days=30)  # a single lookup's row (nvdcve:, cvelistcve:, osvcve:) older than this goes
PRUNE_EVERY = timedelta(hours=24)
_pruned: list[datetime | None] = [None]


async def prune_lookups(db: AsyncSession, now: datetime | None = None) -> int:
    """The rows of single CVE lookups (when one CVE was asked: story details, cvelistV5, OSV) older than LOOKUP_KEEP –
    each is asked again after at most a week anyway, so an old row only grows the table (security review L8)."""
    now = now or datetime.now(UTC)
    old = or_(VendorFetch.last_fetch_at.is_(None), VendorFetch.last_fetch_at < now - LOOKUP_KEEP)
    n = (await db.execute(delete(VendorFetch).where(or_(*(VendorFetch.key.startswith(p, autoescape=True) for p in PER_CVE)), old))).rowcount or 0
    await db.commit()
    return int(n)


async def after_round(db: AsyncSession, cfg: dict, force: bool = False) -> None:
    """OSV and EPSS: they look at the findings (and EPSS at the stories) – after the round's records are stored. Each
    one's failure is its own (logged, its state pauses), never the round's. Once a day the old single lookups go."""
    from app import epss, osv

    now = datetime.now(UTC)
    if _pruned[0] is None or now - _pruned[0] >= PRUNE_EVERY:
        _pruned[0] = now
        try:
            if n := await prune_lookups(db, now):
                log.info("vendor: %d old single lookups removed", n)
            if n := await changes_svc.prune(db, now):
                log.info("vendor: %d old advisory revisions and change events removed", n)
        except Exception:  # noqa: BLE001
            await db.rollback()
            log.exception("pruning the single lookups failed")

    if cfg.get("osv", True):
        try:
            await osv.refresh(db, force=force)
        except Exception:  # noqa: BLE001
            await db.rollback()
            log.exception("osv round failed")
    if cfg.get("epss", True):
        try:
            await epss.refresh(db, force=force)
        except Exception:  # noqa: BLE001
            await db.rollback()
            log.exception("epss round failed")


class VendorLoop:
    """Its own task: a slow, rate-limited NVD round never delays the news. `wake()` after an edit evaluates at once;
    `force()` ("Jetzt abrufen") fetches every source not pausing after a refusal."""

    def __init__(self, notify_wake=None) -> None:  # noqa: ANN001
        self.event = asyncio.Event()
        self.lock = asyncio.Lock()
        self.forced = False
        self.catalog = False
        self.notify_wake = notify_wake
        self.running = False
        self.last_round_at: datetime | None = None

    def wake(self) -> None:
        self.event.set()

    def force(self) -> None:
        self.forced = True
        self.event.set()

    def refresh_catalog(self) -> None:
        self.catalog = True
        self.event.set()

    async def round(self) -> None:
        async with self.lock:
            self.running = True
            try:
                if self.catalog:
                    self.catalog = False
                    await run_round(only="catalog")
                force, self.forced = self.forced, False
                got = await run_round(force=force)
                if got:
                    log.info("vendor: %s", {k: v for k, v in got.items() if v})
                async with dbm.session() as db:
                    from app import story_details

                    # Details aus der Quelle for the news (CSAF, NVD) – the same rate-limited request path
                    try:
                        await story_details.enrich_round(db)
                    except Exception:  # noqa: BLE001 - the details never stop Vendor News
                        log.exception("story details round failed")
                    cfg = await config(db)
                    if cfg.get("enabled", True):
                        await after_round(db, cfg, force)
                        n = await evaluate_events(db)
                        try:
                            # CVE beobachten: what changed for a watched CVE since the last check (stored data only)
                            n += await cve_watch.evaluate_due(db, (gen.value, gen.epoch))
                        except Exception:  # noqa: BLE001 - the watch never stops Vendor News
                            await db.rollback()
                            log.exception("cve watch round failed")
                        if n and self.notify_wake:
                            self.notify_wake()  # the news loop sends them with its next notify step
                self.last_round_at = datetime.now(UTC)
            finally:
                self.running = False

    async def run(self) -> None:
        while True:
            self.event.clear()
            try:
                await self.round()
            except Exception:  # noqa: BLE001 - one bad round must not end the loop
                log.exception("vendor round failed")
            try:
                await asyncio.wait_for(self.event.wait(), 60)
            except TimeoutError:
                pass


def validate_version(product: dict, text: str) -> tuple[bool, str, str]:
    """(ok, normalised, reason) of a version typed for a product (app/version_input.py): vCenter and ESXi also take what
    their consoles show (8.0.3.00400, builds), Exchange and SQL Server the names of their updates (2019 CU15 Apr25HU,
    2022 CU16), VMware Tools its code (12416), GlobalProtect its build (6.2.8-c948) – looked up in the build tables
    (app/build_maps.py) and stored as what advisories compare; a version far beyond every release line of the product
    ("2019 CU15" for Exchange, 15.x) is refused."""
    c = version_input.check(product, text)
    return c.ok, c.value, c.reason


def version_mapped(product: dict, text: str) -> bool:
    """Whether a typed version was looked up or normalised (8.0.3.00400 → 8.0 U3d, 2019 CU15 → 15.2.1748)."""
    return version_input.check(product, text).mapped


def short_version(product: dict, text: str) -> bool:
    """A version with fewer parts than the product's releases ("7.4" for FortiOS 7.4.8, "1.25" for nginx 1.25.5): it
    stands for several releases – "möglicherweise betroffen" wherever they differ. The form says so."""
    scheme = product.get("scheme") or "generic"
    if scheme in ("panos", "windows", "ivanti", "cloud", "distro", "sap"):
        return False
    v = stored_v(product, text)
    # without release data nothing says how long a complete version is (7-Zip 24.09, KeePass 2.59): never short
    want = VEEAM_BUILD_DEPTH if scheme == "veeam" else catalog.want_depth(product)
    return v is not None and want is not None and v.depth < want


def verdict_dict(v: Verdict | None) -> dict | None:
    return None if v is None else {"status": v.status, "reason": v.reason, "fixed": v.fixed, "detail": v.detail}
