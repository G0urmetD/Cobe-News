"""Advisory changes: vendors revise their advisories – a new fixed version, another severity, a wider affected range,
the advisory withdrawn, the CVE added to CISA's KEV. Vendor News keeps what an advisory said last (its "facts",
vendor_advisory_state) and, when a stored advisory comes again with other facts, a revision (vendor_advisory_changes)
with the structured difference and what it means for the versions entered (the impact – the most important part).

What counts (content only – facts_of): fixed versions, affected ranges, affected products, severity and CVSS, the CVEs,
KEV listed (sync_kev), withdrawn (drop_advisories). Never: whitespace, case, order, time stamps, the description's
text, the vendor's revision number alone (shown with a change, no change by itself).

No noise:
- the first time an advisory is stored there is nothing to compare (no revision) – also on a source's first fetch;
- facts are normalised (whitespace, case, order, duplicates) – a reformatted source is no change;
- a value that disappears (no CVSS any more, an empty list) is a gap of the source, not a change: the last one stays
  (merge) – two writers of the same record (a story and a CSAF provider) never make a change of each other;
- the extractor's own version (EXTRACT_V) is in the stored facts: another one recomputes the old facts from the stored
  record with the new extractor before comparing – a better extractor is never a change;
- a parser of a source changed (PARSER_V[source], raised with such a change): the facts are set anew, silently;
- a CSAF provider's first fill (data.initial) sets them silently as well;
- a batch where most known advisories changed at once (MASS_MIN, MASS_SHARE) is a source that reformatted: silent.

Kept: PER_ADVISORY revisions per advisory, none older than KEEP (prune, daily). Events (kind "change") only for
followed products the advisory concerns – without versions every change, with versions when a version is (or was)
concerned or the impact names one; a rule sends them only when it chose the kind "vendor_change".
"""

import logging
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import VendorAdvisoryChange, VendorEvent
from app.vendor_match import evaluate

log = logging.getLogger("cobe_news.vendor")

# the extractor below: raised when facts_of changes what it takes (the old facts are then recomputed, never a change)
EXTRACT_V = 1
# per source the parser its records come from (vendor_sources, csaf_providers/story_details, cvelist, osv): raised with
# a change of a parser that alters what it reads – the next record of that source sets its facts anew, silently
PARSER_V = {"nvd": 1, "paloalto": 1, "fortinet": 1, "veeam": 1, "csaf": 1, "cvelist": 1, "osv": 1}
KEEP = timedelta(days=365)
PER_ADVISORY = 20
RECENT = timedelta(days=30)  # "Geändert" in the lists: a change within this time
MASS_MIN = 40  # a batch with at least this many changed known advisories …
MASS_SHARE = 0.8  # … that are at least this share of the known ones: a reformatted source, not news
LIST_MAX = 600
DIFF_ITEMS = 12
LISTS = ("fixed", "affected", "products", "cves")
CONCERNS = frozenset({"affected", "possible", "service", "unversioned"})
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_VER = re.compile(r"\d+(?:\.\d+)+(?:-h\d+|-[0-9A-Za-z]+(?:\.\d+)*|[a-z]+\d*)?")
_NONE = frozenset({"", "none", "n/a", "na", "-", "unaffected", "not affected", "not applicable", "all"})


# ---------------------------------------------------------------- facts


def _n(v) -> str:  # noqa: ANN001
    return " ".join(str(v or "").split())


def _uniq(items: list[str]) -> list[str]:
    """Normalised (whitespace), without duplicates by case, sorted – the same set in another order or case is the same."""
    seen: dict[str, str] = {}
    for x in items:
        t = _n(x)
        if t:
            seen.setdefault(t.casefold(), t)
    return [seen[k] for k in sorted(seen)][:LIST_MAX]


def _l(v) -> list:  # noqa: ANN001
    return v if isinstance(v, list) else []


def _d(v) -> dict:  # noqa: ANN001
    return v if isinstance(v, dict) else {}


def _pan(data: dict, out: dict) -> None:
    for ln in _l(data.get("lines")):
        ln = _d(ln)
        name = _n(ln.get("name"))
        aff = re.sub(r"\s*\*+\s*$", "", _n(ln.get("affected")))
        if not name or aff.casefold() in _NONE:
            continue
        out["affected"].append(f"{name}: {aff}")
        out["fixed"] += [f"{name}: {v}" for v in _VER.findall(_n(ln.get("fixed")))]
    out["products"] += [str(p) for p in _l(data.get("products")) if isinstance(p, str)]


def _fortinet(data: dict, out: dict) -> None:
    for fam, v in _d(data.get("products")).items():
        out["products"].append(str(fam))
        out["affected"] += [str(x) for x in _l(_d(v).get("affected")) if isinstance(x, str)]
    for line in str(data.get("remediation") or "").splitlines():
        name, sep, rest = line.partition(":")
        if sep:
            out["fixed"] += [f"{_n(name)}: {v}" for v in _VER.findall(rest)]


def _veeam(data: dict, out: dict) -> None:
    for issue in _l(data.get("issues")):
        for r in _l(_d(issue).get("affected")):
            r = _d(r)
            lines = [str(x) for x in _l(r.get("lines"))]
            out["affected"].append(f"{_n(r.get('product'))}: ≤ {_n(r.get('upto'))}" + (f" ({', '.join(lines)})" if lines else ""))
        for r in _l(_d(issue).get("fixed")):
            r = _d(r)
            name, build = _n(r.get("name")), _n(r.get("build"))
            out["fixed"].append(f"{_n(r.get('product'))}: {name}" + (f" ({build})" if build and build != name else ""))
    out["products"] += [str(p) for p in _l(data.get("products")) if isinstance(p, str)]


_CPE_OPS = (("versionStartIncluding", ">="), ("versionStartExcluding", ">"), ("versionEndIncluding", "<="), ("versionEndExcluding", "<"))


def _configs(configs: list, out: dict) -> None:
    for cfg in _l(configs):
        for node in _l(_d(cfg).get("nodes")):
            for m in _l(_d(node).get("cpeMatch")):
                m = _d(m)
                parts = str(m.get("criteria") or "").split(":")
                if len(parts) < 6:
                    continue
                vp = f"{parts[3]}:{parts[4]}"
                spec = [parts[5]] if parts[5] not in ("*", "-", "") else []
                spec += [f"{op}{m[k]}" for k, op in _CPE_OPS if m.get(k)]
                out["products"].append(vp)
                out["affected"].append(f"{vp}: {' '.join(spec) or '*'}")
                if m.get("versionEndExcluding"):
                    out["fixed"].append(f"{vp}: {m['versionEndExcluding']}")


def _cna(blocks: list, out: dict) -> None:
    for b in _l(blocks):
        for row in _l(_d(b).get("affectedData")):
            row = _d(row)
            name = _n(f"{row.get('vendor') or ''} {row.get('product') or ''}")
            if not name:
                continue
            out["products"].append(name)
            for v in _l(row.get("versions")):
                v = _d(v)
                if v.get("status") != "affected":
                    continue
                lo = _n(v.get("version"))
                lo = "" if lo in ("0", "*") else lo
                if v.get("lessThan") and v["lessThan"] != "*":
                    spec = f"{lo} <{v['lessThan']}".strip()
                    out["fixed"].append(f"{name}: {v['lessThan']}")
                elif v.get("lessThanOrEqual") and v["lessThanOrEqual"] != "*":
                    spec = f"{lo} <={v['lessThanOrEqual']}".strip()
                else:
                    spec = lo or "*"
                out["affected"].append(f"{name}: {spec}")
                out["fixed"] += [f"{name}: {c['at']}" for c in _l(v.get("changes")) if isinstance(c, dict) and c.get("status") == "unaffected" and c.get("at")]


def _osv(data: dict, out: dict) -> None:
    for p in _l(data.get("packages")):
        p = _d(p)
        name = f"{p.get('ecosystem') or ''}/{p.get('name') or ''}"
        out["products"].append(name)
        for r in _l(p.get("ranges")):
            r = _d(r)
            end = f"<{r['fixed']}" if r.get("fixed") else f"<={r['last_affected']}" if r.get("last_affected") else ""
            out["affected"].append(f"{name}: {r.get('introduced') or '0'}..{end}")
            if r.get("fixed"):
                out["fixed"].append(f"{name}: {r['fixed']}")


def _csaf(data: dict, out: dict) -> None:
    for p in _l(data.get("products")):
        p = _d(p)
        name = _n(p.get("name"))
        if not name:
            continue
        out["products"].append(name)
        for r in _l(p.get("affected")):
            r = _d(r)
            out["affected"].append(f"{name}: {'*' if r.get('all') else _n(r.get('text'))}")
        out["fixed"] += [f"{name}: {v}" for v in _l(p.get("fixed")) if isinstance(v, str)]


def facts_of(source: str, severity: str | None, cvss: float | None, cves: list | None, data: dict | None) -> dict:
    """What counts of one advisory, normalised: severity, CVSS, CVEs, fixed versions, affected ranges, products – and
    the vendor's own revision of the document (`rev`: shown, never a change by itself)."""
    data = data if isinstance(data, dict) else {}
    out: dict = {"fixed": [], "affected": [], "products": [], "cves": [str(c) for c in cves or [] if isinstance(c, str)]}
    if source == "paloalto":
        _pan(data, out)
    elif source == "fortinet":
        _fortinet(data, out)
    elif source == "veeam":
        _veeam(data, out)
    elif source == "nvd":
        # the NVD's own analysis (CPE configurations); the CNA's data it copies only while it has none – the CNA's
        # changes are cvelistV5's (else every CNA edit came twice)
        if data.get("configs"):
            _configs(data["configs"], out)
        else:
            _cna(data.get("cna"), out)
            _cna(data.get("adp"), out)  # kept apart since 0.1.47 – the same facts as before
    elif source == "cvelist":
        _cna(data.get("cna"), out)
        _cna(data.get("adp"), out)
    elif source == "osv":
        _osv(data, out)
    elif source == "csaf":
        _csaf(data, out)
    score = round(float(cvss), 1) if isinstance(cvss, int | float) else None
    return {"sev": str(severity or "info"), "cvss": score, **{k: _uniq(out[k]) for k in LISTS}, "rev": _n(data.get("rev"))[:40]}


def _unknown_sev(f: dict) -> bool:
    return f.get("cvss") is None and f.get("sev") in ("info", "", None)


def merge(prev: dict, new: dict) -> dict:
    """The facts after `new` came: what `new` lacks (no CVSS, no severity, an empty list, no revision) stays as it was –
    a gap of the source (or another writer of the same record) is no change."""
    out = dict(new)
    if new.get("cvss") is None and prev.get("cvss") is not None:
        out["cvss"] = prev["cvss"]
        if new.get("sev") in ("info", "", None):
            out["sev"] = prev.get("sev")
    elif _unknown_sev(new) and not _unknown_sev(prev):
        out["sev"] = prev.get("sev")
    for k in LISTS:
        if not new.get(k) and prev.get(k):
            out[k] = prev[k]
    if not new.get("rev") and prev.get("rev"):
        out["rev"] = prev["rev"]
    return out


def diff(prev: dict, cur: dict) -> list[dict]:
    """The content changes from `prev` to `cur` (both facts): fixed versions, severity or CVSS, affected ranges,
    products, CVEs – each list as added / removed (DIFF_ITEMS of each, `more`: how many beyond)."""
    out: list[dict] = []

    def lists(k: str) -> None:
        a = {x.casefold(): x for x in prev.get(k) or []}
        b = {x.casefold(): x for x in cur.get(k) or []}
        add = [b[x] for x in sorted(b) if x not in a]
        rem = [a[x] for x in sorted(a) if x not in b]
        if add or rem:
            more = max(0, len(add) - DIFF_ITEMS) + max(0, len(rem) - DIFF_ITEMS)
            out.append({"f": k, "add": add[:DIFF_ITEMS], "del": rem[:DIFF_ITEMS], **({"more": more} if more else {})})

    lists("fixed")
    ps, cs = prev.get("sev") or "info", cur.get("sev") or "info"
    pc, cc = prev.get("cvss"), cur.get("cvss")
    if ps != cs:
        out.append({"f": "severity", "from": ps, "to": cs, "cvss_from": pc, "cvss_to": cc})
    elif cc is not None and (pc is None or abs(cc - pc) >= 0.05):
        out.append({"f": "cvss", "from": pc, "to": cc})
    for k in ("affected", "products", "cves"):
        lists(k)
    return out


# ---------------------------------------------------------------- what it means for the versions entered


def verdicts(targets: list[dict], source: str, data: dict | None) -> dict[tuple[str, str | None], tuple[str | None, str | None]]:
    """(product key, version text or None) → (status, fixed) of one record for each followed product and version."""
    out: dict = {}
    for t in targets:
        for v in t["versions"] or [{"version": None}]:
            r = evaluate(t["product"], source, data, v["version"]) if data is not None else None
            out[(t["key"], v["version"])] = (r.status, r.fixed) if r is not None else (None, None)
    return out


def impacts(targets: list[dict], source: str, old: dict | None, new: dict | None) -> tuple[list[dict], set[str]]:
    """What the change means for the versions entered: per version whose status (affected, not affected …) or fixed
    version changed – and the followed products the advisory concerns (without versions: always; with versions: one
    of them is or was concerned, or named in the impact). `old` / `new`: the record's data before and after (None:
    there is none – withdrawn)."""
    before, after = verdicts(targets, source, old), verdicts(targets, source, new)
    out: list[dict] = []
    relevant: set[str] = set()
    for t in targets:
        if not t["versions"]:
            relevant.add(t["key"])
            continue
        for v in t["versions"]:
            (s0, f0), (s1, f1) = before[(t["key"], v["version"])], after[(t["key"], v["version"])]
            if s0 in CONCERNS or s1 in CONCERNS:
                relevant.add(t["key"])
            n0, n1 = (s0 if s0 != "not_affected" else None), (s1 if s1 != "not_affected" else None)
            if n0 != n1 or (s1 in CONCERNS and f1 and f0 != f1):
                out.append({"product": t["key"], "label": t["label"], "version": v["version"], "vlabel": v.get("label") or "", "from": s0, "to": s1, "fixed_from": f0, "fixed_to": f1})
                relevant.add(t["key"])
    return out, relevant


def worse(item: dict) -> bool:
    """An impact that makes things worse: a version concerned now that was not, or "possibly" became "affected"."""
    order = {None: 0, "not_affected": 0, "stale": 0, "unversioned": 1, "service": 1, "possible": 2, "affected": 3}
    return order.get(item.get("to"), 0) > order.get(item.get("from"), 0)


# ---------------------------------------------------------------- writing


async def record(
    db: AsyncSession,
    adv: dict,
    *,
    revision: int,
    changes: list[dict],
    impact: list[dict],
    products: list[str],
    targets: list[dict],
    relevant: set[str],
    now: datetime,
) -> int:
    """One revision of an advisory and its events (kind "change", once per followed product it concerns); the oldest
    revisions beyond PER_ADVISORY go. Returns how many events were written (also the silent ones of a new product)."""
    db.add(
        VendorAdvisoryChange(
            advisory_id=adv["id"],
            source=adv.get("source") or "",
            ident=str(adv.get("ident") or "")[:200],
            title=str(adv.get("title") or "")[:400],
            url=str(adv.get("url") or "")[:2000],
            revision=revision,
            doc_rev=str(((adv.get("data") or {}).get("rev")) or "")[:40],
            at=now,
            diff=changes,
            impact=impact,
            products=sorted(products)[:60],
        )
    )
    await db.flush()
    keep = select(VendorAdvisoryChange.id).where(VendorAdvisoryChange.advisory_id == adv["id"]).order_by(VendorAdvisoryChange.revision.desc(), VendorAdvisoryChange.id.desc()).limit(PER_ADVISORY)
    await db.execute(delete(VendorAdvisoryChange).where(VendorAdvisoryChange.advisory_id == adv["id"], VendorAdvisoryChange.id.not_in(keep)))
    rows = []
    for t in targets:
        if t["key"] not in relevant:
            continue
        mine = [x for x in impact if x["product"] == t["key"]]
        sev = str(adv.get("severity") or "info")
        if any(worse(x) and x.get("to") == "affected" for x in mine) and SEV_RANK.get(sev, 0) < SEV_RANK["high"]:
            sev = "high"  # a version entered is affected now – as important as a new vulnerability of it
        rows.append(
            {
                "key": f"change:{t['key']}:{adv['id']}:{revision}"[:400],
                "kind": "change",
                "product": t["key"],
                "severity": sev,
                "baseline": bool(t.get("baseline")),
                "created_at": now,
                "data": {
                    "product": t["label"],
                    "product_key": t["key"],
                    "advisory": adv["id"],
                    "source": adv.get("source") or "",
                    "ident": str(adv.get("ident") or "")[:200],
                    "title": str(adv.get("title") or "")[:400],
                    "url": str(adv.get("url") or "")[:2000],
                    "cves": list(adv.get("cves") or [])[:30],
                    "revision": revision,
                    "doc_rev": str(((adv.get("data") or {}).get("rev")) or "")[:40],
                    # a CSAF provider's TLP:GREEN document (csaf_providers): sent with its label
                    **({"tlp": "GREEN"} if (adv.get("data") or {}).get("tlp") == "GREEN" else {}),
                    "diff": changes,
                    "impact": mine,
                },
            }
        )
    if rows:
        await db.execute(pg_insert(VendorEvent).on_conflict_do_nothing(index_elements=["key"]), rows)
    return len(rows)


async def prune(db: AsyncSession, now: datetime | None = None) -> int:
    """Revisions and change events older than KEEP go (daily, with the single lookups)."""
    cut = (now or datetime.now(UTC)) - KEEP
    n = (await db.execute(delete(VendorAdvisoryChange).where(VendorAdvisoryChange.at < cut))).rowcount or 0
    n += (await db.execute(delete(VendorEvent).where(VendorEvent.kind == "change", VendorEvent.created_at < cut))).rowcount or 0
    await db.commit()
    return int(n)


# ---------------------------------------------------------------- reading


def change_out(c: VendorAdvisoryChange) -> dict:
    return {
        "advisory": c.advisory_id,
        "source": c.source,
        "ident": c.ident,
        "title": c.title,
        "url": c.url,
        "revision": c.revision,
        "doc_rev": c.doc_rev or None,
        "at": c.at.isoformat(),
        "diff": c.diff or [],
        "impact": c.impact or [],
    }


async def of_advisories(db: AsyncSession, ids: list[str], limit: int = 50) -> list[dict]:
    """The revisions of these advisories, newest first."""
    if not ids:
        return []
    stmt = select(VendorAdvisoryChange).where(VendorAdvisoryChange.advisory_id.in_(ids[:60])).order_by(VendorAdvisoryChange.at.desc(), VendorAdvisoryChange.id.desc()).limit(limit)
    return [change_out(c) for c in await db.scalars(stmt)]


async def latest(db: AsyncSession, ids: list[str], since: datetime | None = None) -> dict[str, dict]:
    """Per advisory its newest revision within RECENT (the lists' "Geändert")."""
    if not ids:
        return {}
    since = since or datetime.now(UTC) - RECENT
    stmt = (
        select(VendorAdvisoryChange)
        .where(VendorAdvisoryChange.advisory_id.in_(ids), VendorAdvisoryChange.at >= since)
        .order_by(VendorAdvisoryChange.advisory_id, VendorAdvisoryChange.at.desc(), VendorAdvisoryChange.id.desc())
        .ext(distinct_on(VendorAdvisoryChange.advisory_id))
    )
    return {c.advisory_id: change_out(c) for c in await db.scalars(stmt)}


async def of_product(db: AsyncSession, key: str, limit: int = 100) -> list[dict]:
    """The change events of one followed product, newest first – what the drawer's "Änderungen" lists."""
    stmt = select(VendorEvent).where(VendorEvent.kind == "change", VendorEvent.product == key).order_by(VendorEvent.created_at.desc()).limit(limit)
    out = []
    for ev in await db.scalars(stmt):
        d = ev.data or {}
        out.append(
            {
                "advisory": d.get("advisory"),
                "source": d.get("source"),
                "ident": d.get("ident"),
                "title": d.get("title"),
                "url": d.get("url"),
                "revision": d.get("revision"),
                "doc_rev": d.get("doc_rev") or None,
                "at": ev.created_at.isoformat(),
                "diff": d.get("diff") or [],
                "impact": d.get("impact") or [],
                "severity": ev.severity,
            }
        )
    return out


async def recent_by_product(db: AsyncSession, keys: list[str], since: datetime | None = None) -> dict[str, dict]:
    """Per followed product: its change events within RECENT – how many, the newest, and whether one changed the
    verdict of a version entered (the overview's "Geändert")."""
    if not keys:
        return {}
    since = since or datetime.now(UTC) - RECENT
    impact = func.bool_or(func.jsonb_array_length(VendorEvent.data["impact"]) > 0)
    stmt = (
        select(VendorEvent.product, func.count(), func.max(VendorEvent.created_at), impact)
        .where(VendorEvent.kind == "change", VendorEvent.product.in_(keys), VendorEvent.created_at >= since)
        .group_by(VendorEvent.product)
    )
    return {p: {"count": int(n), "at": at.isoformat(), "impact": bool(imp)} for p, n, at, imp in (await db.execute(stmt)).all()}


# ---------------------------------------------------------------- text (the channels' messages)

TEXT = {
    "de": {
        "sev": {"critical": "Kritisch", "high": "Hoch", "medium": "Mittel", "low": "Niedrig", "info": "Info"},
        "status": {
            "affected": "betroffen",
            "possible": "möglicherweise betroffen",
            "service": "Cloud-Dienst betroffen",
            "unversioned": "betrifft das Produkt",
            "not_affected": "nicht betroffen",
            "stale": "unklare Altdaten",
            None: "nicht betroffen",
        },
        "now": "{where}: jetzt {to} (vorher {frm})",
        "fix_now": "{where}: Fix-Version jetzt {fixed}",
        "fix_in": " – Fix {fixed}",
        "fixed_add": "neue Fix-Version {items}",
        "fixed_del": "Fix-Version entfernt: {items}",
        "severity": "Schwere von {frm} auf {to}",
        "severity_new": "Schwere neu bewertet: {to}",
        "cvss": "CVSS {frm} → {to}",
        "cvss_new": "CVSS neu: {to}",
        "affected_add": "betroffener Bereich erweitert: {items}",
        "affected_del": "betroffener Bereich verkleinert: {items}",
        "products_add": "weitere Produkte: {items}",
        "products_del": "Produkte entfernt: {items}",
        "cves_add": "weitere CVEs: {items}",
        "cves_del": "CVEs entfernt: {items}",
        "kev": "in CISA KEV aufgenommen ({cve})",
        "withdrawn": "Advisory zurückgezogen",
        "revision": "Revision {n}",
        "title": "Advisory geändert",
        "more": " (+{n})",
    },
    "en": {
        "sev": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
        "status": {
            "affected": "affected",
            "possible": "possibly affected",
            "service": "cloud service affected",
            "unversioned": "concerns the product",
            "not_affected": "not affected",
            "stale": "unclear old data",
            None: "not affected",
        },
        "now": "{where}: now {to} (before: {frm})",
        "fix_now": "{where}: fixed version now {fixed}",
        "fix_in": " – fix {fixed}",
        "fixed_add": "new fixed version {items}",
        "fixed_del": "fixed version removed: {items}",
        "severity": "severity from {frm} to {to}",
        "severity_new": "severity newly rated: {to}",
        "cvss": "CVSS {frm} → {to}",
        "cvss_new": "new CVSS: {to}",
        "affected_add": "affected range widened: {items}",
        "affected_del": "affected range narrowed: {items}",
        "products_add": "more products: {items}",
        "products_del": "products removed: {items}",
        "cves_add": "more CVEs: {items}",
        "cves_del": "CVEs removed: {items}",
        "kev": "added to CISA KEV ({cve})",
        "withdrawn": "advisory withdrawn",
        "revision": "Revision {n}",
        "title": "Advisory changed",
        "more": " (+{n})",
    },
}


def _items(xs: list[str], lb: dict, extra: int = 0, shown: int = 3) -> str:
    left = len(xs) - shown + extra
    return ", ".join(xs[:shown]) + (lb["more"].format(n=left) if left > 0 else "")


def describe(changes: list[dict], impact: list[dict], lang: str = "de") -> list[str]:
    """The change in short lines, the impact on the versions entered first (plain text – the channels escape it)."""
    lb = TEXT.get(lang, TEXT["de"])
    st = lb["status"]
    out: list[str] = []
    for x in impact:
        where = f"{x.get('label') or x.get('product')} {x.get('version') or ''}".strip()
        if x.get("from") != x.get("to") and not ({x.get("from"), x.get("to")} <= {None, "not_affected"}):
            line = lb["now"].format(where=where, to=st.get(x.get("to"), x.get("to")), frm=st.get(x.get("from"), x.get("from")))
            if x.get("fixed_to") and x.get("to") in CONCERNS:
                line += lb["fix_in"].format(fixed=x["fixed_to"])
            out.append(line)
        elif x.get("fixed_to"):
            out.append(lb["fix_now"].format(where=where, fixed=x["fixed_to"]))
    for c in changes:
        f = c.get("f")
        more = int(c.get("more") or 0)
        if f in LISTS:
            if c.get("add"):
                out.append(lb[f"{f}_add"].format(items=_items(c["add"], lb, more if not c.get("del") else 0)))
            if c.get("del"):
                out.append(lb[f"{f}_del"].format(items=_items(c["del"], lb)))
        elif f == "severity":
            sev = lb["sev"]
            text = lb["severity_new"].format(to=sev.get(c["to"], c["to"])) if c.get("from") == "info" and c.get("cvss_from") is None else lb["severity"].format(frm=sev.get(c["from"], c["from"]), to=sev.get(c["to"], c["to"]))
            if c.get("cvss_to") is not None and c.get("cvss_from") is not None and c["cvss_to"] != c["cvss_from"]:
                text += f" (CVSS {c['cvss_from']:.1f} → {c['cvss_to']:.1f})"
            out.append(text)
        elif f == "cvss":
            out.append(lb["cvss_new"].format(to=f"{c['to']:.1f}") if c.get("from") is None else lb["cvss"].format(frm=f"{c['from']:.1f}", to=f"{c['to']:.1f}"))
        elif f == "kev":
            out.append(lb["kev"].format(cve=c.get("cve") or ""))
        elif f == "withdrawn":
            out.append(lb["withdrawn"])
    return out
