"""Vendor News advisories nobody needs any more (0.1.51): the records of products no longer followed (or switched off),
of lookups for stories long gone – removed after KEEP, with their product links and state (ON DELETE CASCADE); their
revisions (no foreign key) age out on their own (advisory_changes.KEEP).

An advisory goes only when **all** of these hold (prune):
- it is linked to no product that is followed and switched on;
- it was stored or changed (`fetched_at`) longer than KEEP ago;
- none of its CVEs (nor its own ident) is watched by anybody (CVE beobachten reads the advisories by CVE);
- no stored story names one of its CVEs, and no story's details point at it (story_details.advisory_ids – the drawer
  shows its revisions; the topic "Exploit veröffentlicht" reads cvelistV5 records by CVE);
- it has no revision within KEEP (the history of a change stays explainable);
- no query that is still asked would list it (0.1.51 review H2: such a query is never reset, so a product followed
  later on the same CPE fetches only what changed – a record deleted under it would never come back): an NVD record
  carrying a CPE (vendor:product) one asked nvd:<cpe> query names; a Palo Alto record while a paloalto: query is asked;
  a Veeam record while veeam:feed is asked. This keeps everything of a shared CPE (the Windows Server roles, firefox and
  its ESR, panos and panorama …) while any product of it is followed – link() links against the whole catalogue, so
  such a record often links only to products nobody follows;
- its source can bring it back: never a CSAF document (one watermark per provider, the first fill reaches back only
  csaf_providers.INITIAL – a deleted document of an older date would never come again, and resetting a provider's
  watermark would read the provider's whole history for all its products) and never a Fortinet advisory (the PSIRT
  feed lists only the newest ones). Except (0.1.51) a BSI document linked to no product at all: it came with a story
  only (no provider), the story is gone (else it is kept, see above), no product of the catalogue concerns it – nobody
  can ever see it; a new story about it fetches it again. An NVD or cvelistV5 record without any CPE that names a
  catalogue product stays as well (only the keyword search of the last days or the delta feed brought it – neither
  lists an old record again). NVD (a full fetch per CPE), Palo Alto (per product name, page by page), Veeam (the whole
  KB feed) and OSV (looked up per CVE of a finding) bring theirs back; a record linked to no product at all (a story's
  lookup) is needed by nobody once its story is gone.

Bringing them back: a deleted record's query is no longer asked (no switched-on product needs it) – after a cleanup
that deleted something, every such query (nvd:<cpe>, paloalto:<name>, veeam:feed, nvdkw:<product>) is reset
(reset_queries: no cursor, no full fetch, no ETag, never answered). Whatever later needs it again – the product
followed or switched on again, another product or a catalogue change (relink_catalog) bringing the same CPE – starts
with a full fetch; until it answered, the product's events wait (vendor._ready; its keyword search: waiting()), so the baseline of the re-follow is
taken with the records back, nothing old is sent. on_follow() does the same for the queries of a product followed (or
switched on) now that no other switched-on product asks.

Deleted in short batches (db.delete_batched: FOR UPDATE SKIP LOCKED – a record a round is storing right now stays),
daily (vendor.daily_prunes, its own step)."""

import logging
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import Text, and_, exists, func, literal, literal_column, or_, select, update
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as dbm
from app.models import CveWatch, NewsItem, StoryDetail, VendorAdvisory, VendorAdvisoryChange, VendorAdvisoryProduct, VendorFetch, VendorFollow

log = logging.getLogger("cobe_news.vendor")

KEEP = timedelta(days=365)
KEPT_SOURCES = ("csaf", "fortinet")  # their records could not be fetched again (see the module text)
SCAN = 5000  # candidates read per step (keyset by id)
# the queries whose records the cleanup may delete – reset when no switched-on product asks them (never csaf:<provider>,
# fortinet:rss: their documents are kept; never kev, eol, the lists or the single lookups)
RESET_PREFIXES = ("nvd:", "nvdkw:", "paloalto:", "veeam:")


def _cheap(cut: datetime) -> list:
    """The SQL part of the rule – checked again in the DELETE itself (a link or a store meanwhile keeps the record)."""
    enabled_link = (
        exists()
        .where(VendorAdvisoryProduct.advisory_id == VendorAdvisory.id, VendorFollow.product == VendorAdvisoryProduct.product, VendorFollow.enabled.is_(True))
        .correlate(VendorAdvisory)
    )
    recent_revision = exists().where(VendorAdvisoryChange.advisory_id == VendorAdvisory.id, VendorAdvisoryChange.at >= cut).correlate(VendorAdvisory)
    any_link = exists().where(VendorAdvisoryProduct.advisory_id == VendorAdvisory.id).correlate(VendorAdvisory)
    # a story's BSI document no product concerns (no provider: only a story brings it; the story keeps it while it exists)
    lone_bsi = and_(
        VendorAdvisory.source == "csaf",
        VendorAdvisory.data["provider"].as_string().is_(None),
        VendorAdvisory.data["publisher"].as_string().startswith("BSI", autoescape=True),
        ~any_link,
    )
    return [or_(VendorAdvisory.source.not_in(KEPT_SOURCES), lone_bsi), VendorAdvisory.fetched_at < cut, ~enabled_link, ~recent_revision]


async def protected(db: AsyncSession) -> tuple[set[str], set[str], list[str]]:
    """(CVEs of stories and watches, advisory ids behind stories' details, the watched CVEs) – what keeps a record."""
    from app import story_details

    watched = sorted({str(c).upper() for c in await db.scalars(select(CveWatch.cve).distinct())})
    cves = set(watched)
    cves.update(str(c).upper() for c in await db.scalars(select(func.jsonb_array_elements_text(NewsItem.cves)).distinct()))
    ids: set[str] = set()
    rows = await db.execute(select(StoryDetail.kind, StoryDetail.ident, NewsItem.cves).join(NewsItem, NewsItem.id == StoryDetail.item_id))
    for kind, ident, item_cves in rows.all():
        ids.update(story_details.advisory_ids(kind or "", ident or "", [str(c) for c in item_cves or []]))
    return cves, ids, watched


# every CPE string anywhere in a record (NVD configurations, the CNA's and CISA's ADP data): one array per row
CPES = func.jsonb_path_query_array(VendorAdvisory.data, literal_column("""'strict $.** ? (@.type() == "string" && @ starts with "cpe:2.3:")'::jsonpath"""))
_FIELD = re.compile(r"(?<!\\):")


def cpe_product(cpe: str) -> str:
    """part:vendor:product of a CPE string or a query key's CPE, without NVD's escapes (as vendor.cpe_key reads them)."""
    parts = _FIELD.split(cpe.removeprefix("cpe:2.3:"))
    return ":".join(parts[:3]).replace("\\", "").lower()


def _kept(row, keep_cves: set[str], keep_ids: set[str], asked: set[str]) -> bool:  # noqa: ANN001 - a result row
    aid, ident, cves, source, cpes, linked = row
    if aid in keep_ids or str(ident or "").upper() in keep_cves:
        return True
    if any(isinstance(c, str) and c.upper() in keep_cves for c in cves or []):
        return True
    cpes = [cpe_product(c) for c in cpes or [] if isinstance(c, str)]
    if source in ("nvd", "cvelist"):
        if not cpes:
            return bool(linked)  # no CPE query could bring it back – kept while it names a catalogue product
        return any(c in asked for c in cpes)  # an asked query lists it: deleted, it would never come back
    if source == "paloalto":
        return any(k.startswith("paloalto:") for k in asked)
    if source == "veeam":
        return "veeam:feed" in asked
    return False


async def prune(db: AsyncSession, now: datetime | None = None) -> int:
    """The advisories the rule above lets go, in batches; afterwards the queries no switched-on product asks are reset.
    Returns how many advisories went."""
    now = now or datetime.now(UTC)
    cut = now - KEEP
    keep_cves, keep_ids, watched = await protected(db)
    keys = await _asked(db)
    asked = {cpe_product(k.removeprefix("nvd:")) for k in keys if k.startswith("nvd:")} | {k for k in keys if not k.startswith("nvd:")}
    await dbm.release(db)
    linked = exists().where(VendorAdvisoryProduct.advisory_id == VendorAdvisory.id).correlate(VendorAdvisory)
    gone, last = 0, ""
    while True:
        cols = (VendorAdvisory.id, VendorAdvisory.ident, VendorAdvisory.cves, VendorAdvisory.source, CPES, linked)
        rows = (await db.execute(select(*cols).where(VendorAdvisory.id > last, *_cheap(cut)).order_by(VendorAdvisory.id).limit(SCAN))).all()
        await dbm.release(db)
        if not rows:
            break
        last = rows[-1][0]
        doomed = [r[0] for r in rows if not _kept(r, keep_cves, keep_ids, asked)]
        if doomed:
            again = list(_cheap(cut))
            if watched:  # a watch made meanwhile still keeps it
                arr = literal(watched, ARRAY(Text))
                again += [~VendorAdvisory.cves.op("?|", is_comparison=True)(arr), VendorAdvisory.ident.not_in(watched)]
            gone += await dbm.delete_batched(db, VendorAdvisory, VendorAdvisory.id.in_(doomed), *again, batch=len(doomed))
        if len(rows) < SCAN:
            break
    if gone:
        n = await reset_queries(db, await _inactive(db))
        log.info("vendor: %d advisories of products no longer followed removed (retention), %d queries reset for a full fetch", gone, n)
    return gone


async def _asked(db: AsyncSession, *, besides: str | None = None) -> set[str]:
    """The queries the switched-on followed products need (whether Vendor News runs right now or not) – `besides`: all
    but this product's own."""
    from app import vendor

    cfg = await vendor.config(db)
    out: set[str] = set()
    for f in await vendor.follows(db):
        if f.product != besides and (p := vendor.product_of(f)) is not None:
            out.update(k[:300] for k in vendor.fetch_keys(p, cfg))
            out.add(f"nvdkw:{p['key']}"[:300])
    return out


async def _inactive(db: AsyncSession) -> list[str]:
    asked = await _asked(db)
    keys = await db.scalars(select(VendorFetch.key).where(or_(*(VendorFetch.key.startswith(p, autoescape=True) for p in RESET_PREFIXES))))
    return [k for k in keys if k not in asked]


KW_RESET = "reset"  # the cursor of an nvdkw: query the cleanup reset (the keyword search has no cursor of its own)


async def reset_queries(db: AsyncSession, keys: list[str], *, unanswered: bool = True) -> int:
    """These queries start again: the next round fetches them in full (no cursor, no full fetch done, no ETag) and –
    `unanswered` – until they answered, a product needing them is not evaluated (vendor._ready; its keyword search
    nvdkw:<product> through waiting()). Only rows not reset already."""
    keys = [k for k in keys if k.startswith(RESET_PREFIXES)]
    n = 0
    for kw in (False, True):
        part = [k for k in keys if k.startswith("nvdkw:") == kw]
        if kw:
            # a keyword search of the last days: nothing to fetch in full – asked again soon, and marked for waiting()
            values = {"next_fetch_at": None} | ({"last_ok_at": None, "failures": 0, "error": None, "cursor": KW_RESET} if unanswered else {})
            pending = [VendorFetch.last_ok_at.is_not(None), VendorFetch.next_fetch_at.is_not(None)] if unanswered else [VendorFetch.next_fetch_at.is_not(None)]
        else:
            values = {"cursor": None, "full_at": None, "etag": None, "last_modified": None, "next_fetch_at": None} | ({"last_ok_at": None, "failures": 0, "error": None} if unanswered else {})
            pending = [VendorFetch.cursor.is_not(None), VendorFetch.full_at.is_not(None), VendorFetch.etag.is_not(None), VendorFetch.last_modified.is_not(None), *([VendorFetch.last_ok_at.is_not(None)] if unanswered else [])]
        for i in range(0, len(part), 1000):
            res = await db.execute(update(VendorFetch).where(VendorFetch.key.in_(part[i : i + 1000]), or_(*pending)).values(**values).execution_options(synchronize_session=False))
            n += res.rowcount or 0
    await db.commit()
    return n


async def waiting(db: AsyncSession) -> set[str]:
    """The products whose keyword search the cleanup reset and that has not answered since (nor failed again and
    again): their evaluation waits for it like for their other queries (vendor._ready) – review 0.1.51 L3."""
    from app import vendor

    rows = await db.scalars(
        select(VendorFetch.key).where(VendorFetch.key.startswith("nvdkw:"), VendorFetch.cursor == KW_RESET, VendorFetch.last_ok_at.is_(None), VendorFetch.failures < vendor.READY_AFTER_FAILURES)
    )
    return {k.removeprefix("nvdkw:") for k in rows}


async def on_follow(db: AsyncSession, product: dict) -> int:
    """A product followed (or switched on) now: its queries that no other switched-on product asks start with a full
    fetch. Whether its evaluation waits for them: when the cleanup removed records while nobody asked, it reset the
    query to "never answered" already – the baseline is taken with the records back; otherwise its records are all
    still there and it is evaluated at once (as before). A query another product asks right now keeps its state (its
    records are linked to that product, never removed)."""
    from app import vendor

    cfg = await vendor.config(db)
    mine = {k[:300] for k in vendor.fetch_keys(product, cfg)} | {f"nvdkw:{product['key']}"[:300]}
    return await reset_queries(db, sorted(mine - await _asked(db, besides=product["key"])), unanswered=False)
