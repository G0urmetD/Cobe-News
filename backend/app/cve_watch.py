"""CVE beobachten: a person follows one CVE – independent of teams and followed products – and hears on their own ways
(app/personal.py: e-mail, desktop push, their Teams webhook) when something important happens to it:

- **Fix**: a fixed version appears in an advisory naming the CVE (a vendor's advisory, the NVD's, cvelistV5, OSV, CSAF –
  whatever Vendor News stores anyway; a revised advisory with a new fixed version counts the same).
- **KEV**: CISA lists it as exploited (vendor_kev, the whole catalogue – fetched anyway).
- **EPSS**: its EPSS percentile reaches EPSS_PCT (0.9: among the 10 % likeliest to be exploited) – or its probability
  rose by EPSS_JUMP (0.1, absolute) since the last notice (or since the watch began). A percentile that fell below
  EPSS_PCT_RESET (0.85) may reach EPSS_PCT again later; between the two nothing flaps. At most one EPSS notice a day.
- **Withdrawn**: an advisory naming it was withdrawn (NVD rejected the CVE, OSV withdrew its record …).
- **Exploit** (0.1.47): a switched-on exploit list (app/exploits.py: Metasploit, Exploit-DB, nuclei) names it for the
  first time – once per CVE (key watch:<CVE>:exploit). What a list brought with its first import (its baseline) is
  shown, never notified; a state from before this check knows no exploit yet and takes the current one silently.

Nothing old, exactly once: per CVE one state row (cve_watch_state) holds what was seen at the last check – made from
the data at the moment of the first watch (the baseline, never notified). A difference becomes one VendorEvent (kind
"watch", key unique: watch:<CVE>:kev | fix:<hash> | epss:<day> | withdrawn:<advisory>) – the person gets the events
created after their watch began, through the personal round with all its guarantees (claimed once, digest, bounded
rounds, retries). A person who starts watching a CVE someone else watches already gets a check of it first: what is
true then is not news for them.

No new data flow: only what Vendor News fetches anyway is read (stored advisories, the KEV, the EPSS scores of the CVEs
of findings and stories). A watched CVE is never asked of any outside service by itself – an unknown CVE is kept and
counts as soon as a source brings it. EPSS is only there for CVEs of findings and recent stories (app/epss.py).

Where from (0.1.42): every watch remembers its origin – a story (id and title as they were then), a Vendor News finding
(product, advisory id, title) or "manual" (typed on the list) – for the list's groups and "Gruppe nicht mehr
beobachten". The origin is resolved by the server (app/watch_api.py), never taken from the client. A CVE watched again
from somewhere else keeps its first origin (and its start): the row is not touched. Watches from before 0.1.42 have no
origin (NULL) and count as manual.
"""

import hashlib
import logging
import re
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, func, or_, select, text
from sqlalchemy.dialects.postgresql import array as pg_array
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import advisory_changes as changes_svc
from app import watch_product
from app.models import CveWatch, CveWatchState, EpssScore, VendorAdvisory, VendorAdvisoryState, VendorEvent, VendorKev

log = logging.getLogger("cobe_news.cve_watch")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,12}$")
MAX_PER_PERSON = 500
BULK_MAX = 500  # CVEs in one "Alle beobachten"
ORIGIN_KINDS = ("story", "finding", "manual")
ORIGIN_TITLE = 300  # characters of the title snapshot
WATCH_LOCK = 0x636E_7763  # pg_advisory_xact_lock(WATCH_LOCK, hashtext(person)): one add of a person at a time (the limit)
EPSS_PCT = 0.9  # percentile reached: a notice (once, until it fell below EPSS_PCT_RESET)
EPSS_PCT_RESET = 0.85
EPSS_JUMP = 0.1  # probability up by this (absolute) since the last notice or the start: a notice
FIXED_MAX = 2000  # fixed versions remembered per CVE
FIX_LIST = 12  # fixed versions named in one event
CHUNK = 500  # CVEs read at once
EVERY = 600.0  # s: a check without a change of the advisories or the KEV (EPSS comes once a day)
KEEP = timedelta(days=90)  # watch events are kept this long (they are sent within personal.MAX_AGE or never)
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
FIX_BY = 5  # advisories named as where a new fixed version appeared (the list's timeline)
TIMELINE = 50  # events of one CVE in the list's timeline
# the advisory the list opens for a CVE: the vendor's own first, then CSAF, the NVD, OSV, cvelistV5
LINK_RANK = {"cvelist": 0, "osv": 1, "nvd": 2, "csaf": 3}


def normalize(cve: str | None) -> str | None:
    """The CVE id as stored (upper case) – or None: not one."""
    c = (cve or "").strip().upper()
    return c if CVE_RE.fullmatch(c) else None


def scope(cve: str) -> str:
    return f"watch:{cve}"


# ---------------------------------------------------------------- what is known about a CVE now


async def facts(db: AsyncSession, cves: list[str]) -> dict[str, dict]:
    """Per CVE what the stored data says now: kev (and its entry), the fixed versions of every advisory naming it, the
    highest severity, a title, the EPSS (score, percentile, day), which advisory first named each fixed version
    (`fixed_in`) and the advisory to open (`link`). Only the own database – nothing is fetched."""
    from app import exploits, vendor

    out: dict[str, dict] = {c: {"kev": None, "fixed": [], "fixed_in": {}, "severity": "info", "title": "", "epss": None, "advisories": [], "link": None, "exploits": []} for c in cves}
    xcfg = await vendor.config(db)
    for i in range(0, len(cves), CHUNK):
        part = cves[i : i + CHUNK]
        for c, hits in (await exploits.of_cves(db, part, xcfg)).items():
            if c in out:
                out[c]["exploits"] = [{"source": e["source"], "url": e["url"], "first_seen": e["first_seen"], "baseline": e["baseline"]} for e in hits]
        for k in await db.scalars(select(VendorKev).where(VendorKev.cve.in_(part))):
            out[k.cve]["kev"] = {"added": k.date_added, "due": k.due, "ransomware": bool(k.ransomware), "name": k.name[:200]}
        for e in await db.scalars(select(EpssScore).where(EpssScore.cve.in_(part), EpssScore.score.is_not(None))):
            out[e.cve]["epss"] = {"score": float(e.score), "percentile": None if e.percentile is None else float(e.percentile), "day": e.day or ""}
        rows = (
            await db.execute(
                select(VendorAdvisory.id, VendorAdvisory.source, VendorAdvisory.ident, VendorAdvisory.title, VendorAdvisory.severity, VendorAdvisory.cves, VendorAdvisoryState.facts, VendorAdvisory.url)
                .outerjoin(VendorAdvisoryState, VendorAdvisoryState.advisory_id == VendorAdvisory.id)
                .where(or_(VendorAdvisory.cves.op("?|")(pg_array(part)), VendorAdvisory.ident.in_(part)))
                # a CSAF provider's TLP:GREEN document stays with the product's findings, where it is labelled –
                # the watch's messages (fix, title, link) never draw on it
                .where(func.coalesce(VendorAdvisory.data["tlp"].as_string(), "") != "GREEN")
                .order_by(VendorAdvisory.id)
            )
        ).all()
        missing = [r[0] for r in rows if not isinstance(r[6], dict)]
        data: dict[str, tuple] = {}
        if missing:
            # advisories stored before 0.1.33 have no facts yet: made from the record, as advisory_changes does
            q = select(VendorAdvisory.id, VendorAdvisory.source, VendorAdvisory.severity, VendorAdvisory.cvss, VendorAdvisory.cves, VendorAdvisory.data).where(VendorAdvisory.id.in_(missing))
            data = {r[0]: r for r in (await db.execute(q)).all()}
        for aid, source, ident, title, sev, acves, fx, url in rows:
            if not isinstance(fx, dict):
                r = data.get(aid)
                fx = changes_svc.facts_of(r[1], r[2], r[3], r[4], r[5]) if r is not None else {}
            named = {str(c).upper() for c in (acves or []) if isinstance(c, str)} | {str(ident or "").upper()}
            fixed = [str(x) for x in fx.get("fixed") or [] if isinstance(x, str)]
            for c in named & set(part):
                o = out[c]
                o["advisories"].append(aid)
                o["fixed"] += fixed
                for x in fixed:
                    o["fixed_in"].setdefault(x.casefold(), (source, str(ident or "")[:200]))
                link = _link(source, ident, url, sev, bool(fixed))
                if link is not None and (o["link"] is None or link[0] > o["link"][0]):
                    o["link"] = link
                if SEV_RANK.get(sev or "info", 0) > SEV_RANK.get(o["severity"], 0):
                    o["severity"] = sev
                if title and not o["title"]:
                    o["title"] = str(title)[:200]
    for o in out.values():
        o["fixed"] = changes_svc._uniq(o["fixed"])[:FIXED_MAX]
        o["advisories"] = sorted(set(o["advisories"]))
        o["link"] = o["link"][1] if o["link"] else None
    return out


def _link(source: str, ident: str | None, url: str | None, sev: str | None, fixed: bool) -> tuple | None:
    """(its rank, {source, ident, url}) – an advisory the list may open: a web address only (http/https)."""
    u = str(url or "").strip()
    if not u.lower().startswith(("https://", "http://")) or len(u) > 2000:
        return None
    return ((LINK_RANK.get(source, 4), fixed, SEV_RANK.get(sev or "info", 0)), {"source": source, "ident": str(ident or "")[:200], "url": u})


def baseline(f: dict) -> dict:
    """The state of a CVE as first seen – nothing of it is notified."""
    e = f.get("epss") or {}
    pct = e.get("percentile")
    return {
        "kev": f.get("kev") is not None,
        "fixed": list(f.get("fixed") or []),
        "epss_base": e.get("score"),
        "epss_high": pct is not None and pct >= EPSS_PCT,
        "exploit": bool(f.get("exploits")),
    }


def compare(cve: str, st: dict, f: dict) -> tuple[dict, list[dict]]:
    """(the new state, the events) – what changed from the state `st` to the facts `f`. Pure: the tests drive it."""
    new = dict(st)
    events: list[dict] = []
    title = f.get("title") or ""
    sev = f.get("severity") or "info"
    if f.get("kev") is not None and not st.get("kev"):
        k = f["kev"]
        events.append({"what": "kev", "key": f"watch:{cve}:kev", "severity": sev if SEV_RANK.get(sev, 0) >= SEV_RANK["high"] else "high", "data": {"kev": k}})
        new["kev"] = True
    seen = {x.casefold() for x in st.get("fixed") or []}
    added = [x for x in f.get("fixed") or [] if x.casefold() not in seen]
    if added:
        digest = hashlib.sha256("\n".join(sorted(x.casefold() for x in added)).encode()).hexdigest()[:16]
        by = list(dict.fromkeys(tuple(w) for x in added if (w := (f.get("fixed_in") or {}).get(x.casefold()))))[:FIX_BY]
        fix = {"fixed": added[:FIX_LIST], "more": max(0, len(added) - FIX_LIST)}
        if by:
            fix["by"] = [{"source": a, "ident": b} for a, b in by]
        events.append({"what": "fix", "key": f"watch:{cve}:fix:{digest}", "severity": sev if sev != "info" else "medium", "data": fix})
        new["fixed"] = changes_svc._uniq([*(st.get("fixed") or []), *added])[:FIXED_MAX]
    e = f.get("epss")
    if e and e.get("score") is not None:
        score, pct = float(e["score"]), e.get("percentile")
        base = st.get("epss_base")
        reasons = []
        if pct is not None and pct >= EPSS_PCT and not st.get("epss_high"):
            reasons.append("high")
        if base is not None and score - float(base) >= EPSS_JUMP - 1e-9:
            reasons.append("jump")
        if reasons:
            events.append(
                {
                    "what": "epss",
                    "key": f"watch:{cve}:epss:{e.get('day') or datetime.now(UTC).date().isoformat()}",
                    "severity": "high" if pct is not None and pct >= EPSS_PCT else "medium",
                    "data": {"score": score, "percentile": pct, "from": base, "day": e.get("day") or "", "reasons": reasons},
                }
            )
            new["epss_base"] = score
        elif base is None or score < float(base):
            new["epss_base"] = score  # a jump counts from the lowest value since the last notice
        if pct is not None and pct >= EPSS_PCT:
            new["epss_high"] = True
        elif pct is not None and pct < EPSS_PCT_RESET:
            new["epss_high"] = False
    ex = [x for x in f.get("exploits") or [] if isinstance(x, dict)]
    if "exploit" not in st:
        new["exploit"] = bool(ex)  # a state from before 0.1.47: what is listed now is its baseline
    elif ex and not st.get("exploit"):
        fresh = [x for x in ex if not x.get("baseline")]
        if fresh:
            events.append(
                {
                    "what": "exploit",
                    "key": f"watch:{cve}:exploit",
                    "severity": sev if SEV_RANK.get(sev, 0) >= SEV_RANK["high"] else "high",
                    "data": {"exploits": [{"source": str(x.get("source") or ""), "url": str(x.get("url") or "")} for x in fresh][:3]},
                }
            )
        new["exploit"] = True
    for ev in events:
        ev["data"] = {"cve": cve, "what": ev["what"], "title": title, **ev["data"]}
    return new, events


def _row(cve: str, ev: dict, now: datetime) -> dict:
    return {"key": ev["key"][:400], "kind": "watch", "product": "", "severity": ev["severity"], "data": ev["data"], "baseline": False, "scope": scope(cve), "created_at": now}


async def _write(db: AsyncSession, rows: list[dict]) -> int:
    if not rows:
        return 0
    res = await db.execute(pg_insert(VendorEvent).on_conflict_do_nothing(index_elements=["key"]).returning(VendorEvent.id), rows)
    return len(res.all())


# ---------------------------------------------------------------- the check


class _Marks:
    marks: tuple | None = None
    at: float = -1e9


_marks = _Marks()


def reset() -> None:
    _marks.marks, _marks.at = None, -1e9


async def evaluate(db: AsyncSession, cves: list[str] | None = None, *, now: datetime | None = None) -> int:
    """Compare the watched CVEs (or these) with what is stored now: a new state per CVE, an event per change. A CVE
    without a state gets its baseline (silent). Committed per chunk. Returns the events written."""
    now = now or datetime.now(UTC)
    if cves is None:
        cves = sorted(set(await db.scalars(select(CveWatch.cve).distinct())))
    else:
        cves = sorted({c for c in cves if normalize(c)})
    created = 0
    for i in range(0, len(cves), CHUNK):
        part = cves[i : i + CHUNK]
        states = {s.cve: dict(s.state or {}) for s in await db.scalars(select(CveWatchState).where(CveWatchState.cve.in_(part)))}
        got = await facts(db, part)
        rows, upserts = [], []
        for c in part:
            if c not in states:
                upserts.append({"cve": c, "state": baseline(got[c]), "checked_at": now})
                continue
            new, events = compare(c, states[c], got[c])
            rows += [_row(c, ev, now) for ev in events]
            upserts.append({"cve": c, "state": new, "checked_at": now})
        created += await _write(db, rows)
        if upserts:
            stmt = pg_insert(CveWatchState)
            await db.execute(stmt.on_conflict_do_update(index_elements=["cve"], set_={"state": stmt.excluded.state, "checked_at": stmt.excluded.checked_at}), upserts)
        await db.commit()
    return created


async def evaluate_due(db: AsyncSession, generation: tuple) -> int:
    """The background check (Vendor News' loop): when the stored data changed (`generation`: vendor.gen, the KEV, the
    EPSS) – or every EVERY seconds –, and only while somebody watches a CVE."""
    if not await db.scalar(select(CveWatch.cve).limit(1)):
        await db.commit()
        return 0
    newest_epss = await db.scalar(select(func.max(EpssScore.fetched_at)))
    marks = (*generation, newest_epss)
    if marks == _marks.marks and time.monotonic() - _marks.at < EVERY:
        await db.commit()
        return 0
    n = await evaluate(db)
    _marks.marks, _marks.at = marks, time.monotonic()
    return n


async def withdrawn(db: AsyncSession, advisories: list[tuple[str, str, str, str, list]]) -> int:
    """Advisories withdrawn (vendor.drop_advisories, before they go): (id, source, ident, title, cves) – an event for
    each watched CVE one of them named. Written with the caller's transaction."""
    named: dict[str, list[tuple]] = {}
    for aid, source, ident, title, cves in advisories:
        for c in {str(x).upper() for x in (cves or []) if isinstance(x, str)} | {str(ident or "").upper()}:
            if CVE_RE.fullmatch(c):
                named.setdefault(c, []).append((aid, source, ident, title))
    if not named:
        return 0
    watched = set(await db.scalars(select(CveWatch.cve).where(CveWatch.cve.in_(sorted(named))).distinct()))
    now = datetime.now(UTC)
    rows = []
    for c in sorted(watched):
        for aid, source, ident, title in named[c]:
            data = {"cve": c, "what": "withdrawn", "title": str(title or "")[:200], "advisory": aid, "source": source, "ident": str(ident or "")[:200]}
            rows.append(_row(c, {"key": f"watch:{c}:withdrawn:{aid}", "severity": "info", "data": data}, now))
    return await _write(db, rows)


async def prune(db: AsyncSession, now: datetime | None = None) -> int:
    """States nobody watches any more (a new watch is a new baseline) and watch events older than KEEP."""
    now = now or datetime.now(UTC)
    n = (await db.execute(delete(CveWatchState).where(CveWatchState.cve.not_in(select(CveWatch.cve))))).rowcount or 0
    n += (await db.execute(delete(VendorEvent).where(VendorEvent.kind == "watch", VendorEvent.created_at < now - KEEP))).rowcount or 0
    await db.commit()
    return int(n)


# ---------------------------------------------------------------- the person's list


class LimitReached(Exception):  # noqa: N818 - a refusal, not a failure
    """More new CVEs than fit: `free` places left of MAX_PER_PERSON, `wanted` new ones asked for."""

    def __init__(self, free: int, wanted: int) -> None:
        super().__init__(f"{wanted} wanted, {free} free")
        self.free, self.wanted = free, wanted


def origin_columns(origin: dict | None) -> dict:
    """The row's origin columns from a resolved origin ({kind, ref, product, title}) – all None without one."""
    o = origin or {}
    kind = o.get("kind") if o.get("kind") in ORIGIN_KINDS else None
    return {
        "origin_kind": kind,
        "origin_ref": (str(o.get("ref") or "")[:300] or None) if kind in ("story", "finding") else None,
        "origin_product": (str(o.get("product") or "")[:200] or None) if kind == "finding" else None,
        "origin_title": (str(o.get("title") or "")[:ORIGIN_TITLE] or None) if kind in ("story", "finding") else None,
    }


def origin_out(r: CveWatch) -> dict | None:
    """The origin as the list shows it – and as POST …/bulk takes it back (undo): None for a watch from before 0.1.42."""
    if r.origin_kind == "story":
        return {"kind": "story", "id": r.origin_ref or "", "title": r.origin_title or ""}
    if r.origin_kind == "finding":
        return {"kind": "finding", "product": r.origin_product or "", "advisory": r.origin_ref or "", "title": r.origin_title or ""}
    if r.origin_kind == "manual":
        return {"kind": "manual"}
    return None


def group_where(user_id, group: dict) -> list:  # noqa: ANN001
    """The rows of one group of the person's list: a story, a finding, or the manual ones (with those of unknown origin)."""
    where = [CveWatch.user_id == user_id]
    kind = group.get("kind")
    if kind == "story":
        where += [CveWatch.origin_kind == "story", CveWatch.origin_ref == str(group.get("id") or "")]
    elif kind == "finding":
        where += [CveWatch.origin_kind == "finding", CveWatch.origin_product == str(group.get("product") or ""), CveWatch.origin_ref == str(group.get("advisory") or "")]
    else:
        where.append(or_(CveWatch.origin_kind.is_(None), CveWatch.origin_kind == "manual"))
    return where


async def _count(db: AsyncSession, user_id) -> int:  # noqa: ANN001
    return int(await db.scalar(select(func.count()).select_from(CveWatch).where(CveWatch.user_id == user_id)) or 0)


async def add_many(db: AsyncSession, user_id, cves: list[str], origin: dict | None = None, *, partial: bool = False) -> dict:  # noqa: ANN001
    """Watch these CVEs (normalised ids, in the caller's order) from now on, all with `origin` (resolved by the caller).
    Already watched ones stay as they are (their first origin, their start). More new ones than places left:
    LimitReached – unless `partial`: then the first that fit are watched and the rest is `skipped`. Each new CVE is
    checked first (as add() – its baseline; watched by others: what changed until now is not this person's news), then
    the rows are written under a lock of the person (two requests at once cannot pass the limit). Committed.
    Returns {added, already, skipped} (lists of CVE ids)."""
    want = list(dict.fromkeys(cves))
    have = set(await db.scalars(select(CveWatch.cve).where(CveWatch.user_id == user_id, CveWatch.cve.in_(want)))) if want else set()
    new = [c for c in want if c not in have]
    already = [c for c in want if c in have]
    if not new:
        await db.commit()
        return {"added": [], "already": already, "skipped": []}
    free = MAX_PER_PERSON - await _count(db, user_id)
    if len(new) > free and (not partial or free <= 0):
        await db.commit()
        raise LimitReached(max(0, free), len(new))
    take = new[: max(0, free)]
    await evaluate(db, take)  # committed per chunk – before the lock: no lock is held while the facts are read
    await db.execute(text("SELECT pg_advisory_xact_lock(:k, hashtext(:u))"), {"k": WATCH_LOCK, "u": str(user_id)})
    free = MAX_PER_PERSON - await _count(db, user_id)  # again, under the lock: another request may have added meanwhile
    if len(take) > free and not partial:
        await db.commit()
        raise LimitReached(max(0, free), len(new))
    fits = take[: max(0, free)]
    added: list[str] = []
    if fits:
        now = datetime.now(UTC)
        cols = origin_columns(origin)
        res = await db.execute(pg_insert(CveWatch).on_conflict_do_nothing().returning(CveWatch.cve), [{"user_id": user_id, "cve": c, "created_at": now, **cols} for c in fits])
        got = set(res.scalars().all())
        added = [c for c in fits if c in got]
        already += [c for c in fits if c not in got]  # another request of the person added it meanwhile
    await db.commit()
    return {"added": added, "already": already, "skipped": [c for c in new if c not in fits]}


async def add(db: AsyncSession, user_id, cve: str, origin: dict | None = None) -> bool:  # noqa: ANN001
    """Watch one CVE from now on (add_many for one, without the limit – the API checks it). False: the person watched it
    already (the start and the origin stay as they were)."""
    await evaluate(db, [cve])
    cols = origin_columns(origin)
    res = await db.execute(pg_insert(CveWatch).values(user_id=user_id, cve=cve, created_at=datetime.now(UTC), **cols).on_conflict_do_nothing().returning(CveWatch.cve))
    added = res.first() is not None
    await db.commit()
    return added


async def remove_many(db: AsyncSession, user_id, *, cves: list[str] | None = None, group: dict | None = None) -> list[dict]:  # noqa: ANN001
    """Stop watching these CVEs – or one group of the list (group_where). Returns what went, each with its origin (the
    page's undo watches them again with it). Committed."""
    if cves is not None:
        where = [CveWatch.user_id == user_id, CveWatch.cve.in_(list(dict.fromkeys(cves)))]
    else:
        where = group_where(user_id, group or {})
    gone = list(await db.scalars(select(CveWatch).where(and_(*where)).order_by(CveWatch.created_at.desc(), CveWatch.cve)))
    if gone:
        await db.execute(delete(CveWatch).where(CveWatch.user_id == user_id, CveWatch.cve.in_([r.cve for r in gone])))
    out = [{"cve": r.cve, "origin": origin_out(r)} for r in gone]
    await db.commit()
    return out


async def listing(db: AsyncSession, user_id) -> list[dict]:  # noqa: ANN001
    """The person's watched CVEs, newest first, with what is known of each now (KEV, EPSS, fixed versions, advisories),
    the last event of each and its product (app/watch_product.py – worked out now, never stored: the list's groups by
    product follow what is linked later)."""
    rows = list(await db.scalars(select(CveWatch).where(CveWatch.user_id == user_id).order_by(CveWatch.created_at.desc(), CveWatch.cve)))
    if not rows:
        return []
    cves = [r.cve for r in rows]
    got = await facts(db, cves)
    products = await watch_product.resolve(db, {c: got[c]["advisories"] for c in cves})
    last: dict[str, dict] = {}
    q = (
        select(VendorEvent.scope, VendorEvent.data, VendorEvent.created_at)
        .where(VendorEvent.kind == "watch", VendorEvent.scope.in_([scope(c) for c in cves]))
        .order_by(VendorEvent.scope, VendorEvent.created_at.desc())
        .ext(distinct_on(VendorEvent.scope))
    )
    since = {r.cve: r.created_at for r in rows}
    for sc, data, at in (await db.execute(q)).all():
        c = sc.removeprefix("watch:")
        if c in since and at >= since[c]:  # the newest is older than the watch: nothing happened since (for this person)
            last[c] = {"what": (data or {}).get("what"), "at": at.isoformat()}
    out = []
    for r in rows:
        f = got[r.cve]
        out.append(
            {
                "cve": r.cve,
                "since": r.created_at.isoformat(),
                "known": bool(f["advisories"] or f["kev"] or f["epss"] or f["exploits"]),
                "title": f["title"],
                "severity": f["severity"],
                "kev": f["kev"],
                "epss": f["epss"],
                "fixed": f["fixed"][:FIX_LIST],
                "fixed_count": len(f["fixed"]),
                "exploits": [{"source": x["source"], "url": x["url"], "first_seen": x["first_seen"]} for x in f["exploits"]],
                "advisories": len(f["advisories"]),
                "advisory": f["link"],
                "last_event": last.get(r.cve),
                "origin": origin_out(r),
                "product": products[r.cve],
            }
        )
    return out


def _event_out(at: datetime, d: dict) -> dict:
    """One event of the timeline – only what the list shows (no ids, no keys)."""
    what = d.get("what")
    out: dict = {"what": what, "at": at.isoformat()}
    if what == "fix":
        out |= {"fixed": [str(x) for x in d.get("fixed") or []][:FIX_LIST], "more": int(d.get("more") or 0), "by": [{"source": str(b.get("source") or ""), "ident": str(b.get("ident") or "")} for b in d.get("by") or [] if isinstance(b, dict)][:FIX_BY]}
    elif what == "kev":
        k = d.get("kev") or {}
        out |= {"added": k.get("added") or "", "due": k.get("due") or "", "ransomware": bool(k.get("ransomware"))}
    elif what == "epss":
        out |= {"score": d.get("score"), "percentile": d.get("percentile"), "from": d.get("from"), "reasons": [str(x) for x in d.get("reasons") or []]}
    elif what == "withdrawn":
        out |= {"source": str(d.get("source") or ""), "ident": str(d.get("ident") or "")}
    elif what == "exploit":
        out |= {"exploits": [{"source": str(x.get("source") or ""), "url": str(x.get("url") or "")} for x in d.get("exploits") or [] if isinstance(x, dict)][:3]}
    return out


async def timeline(db: AsyncSession, user_id, cve: str) -> dict | None:  # noqa: ANN001
    """What happened to a CVE the person watches since they began (newest first, at most TIMELINE) – None: they do not
    watch it. Nothing older: what others watching it saw before is not this person's history."""
    row = await db.get(CveWatch, (user_id, cve))
    if row is None:
        return None
    q = (
        select(VendorEvent.created_at, VendorEvent.data)
        .where(VendorEvent.kind == "watch", VendorEvent.scope == scope(cve), VendorEvent.created_at >= row.created_at)
        .order_by(VendorEvent.created_at.desc(), VendorEvent.n.desc())
        .limit(TIMELINE)
    )
    events = [_event_out(at, data or {}) for at, data in (await db.execute(q)).all()]
    return {"cve": cve, "since": row.created_at.isoformat(), "events": events}
